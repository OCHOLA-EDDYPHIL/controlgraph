import {
  ContractCodecError,
  canonicalSha256,
  canonicalJson,
  decodeVersionedCanonicalJson,
} from "../contracts/canonical";
import {
  TIMELINE_PAGE_LIMIT,
  decodeTimelinePage,
  targetEquals,
  type TargetBinding,
  type TimelinePage,
  type TimelineQuery,
} from "../contracts/timeline";

const OPERATOR_TIMELINE_PATH = "/v1/operator/timeline";
const OPERATOR_COMMAND_PATH = "/v1/operator/commands";
const AUTHORIZATION_HEADER = "X-ControlGraph-Authorization";
const SERVERLESS_AUTHORIZATION_HEADER = "X-Serverless-Authorization";
const CSRF_HEADER = "X-ControlGraph-CSRF";
const MAX_RESPONSE_BYTES = 65_536;
const TIMELINE_DEADLINE_MS = 10_000;
const MUTATION_DEADLINE_MS = 60_000;
const REVOCATION_REQUEST_DIGEST_DOMAIN =
  "controlgraph.epoch-revocation-request-sha256/v1\0";
const REVOCATION_EVIDENCE_ID_DOMAIN =
  "controlgraph.epoch-revocation-evidence-id/v1\0";
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const sha256 = /^[0-9a-f]{64}$/;
const csrfToken = /^[A-Za-z0-9_-]{43}$/;
const jwt = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const googleSubject = /^[1-9][0-9]{5,31}$/;
const humanEmail = /^[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;

export type OperatorApiErrorKind =
  | "AUTHENTICATION_REQUIRED"
  | "ACCESS_DENIED"
  | "CURSOR_INVALID"
  | "STALE_AUTHORITY"
  | "CONFLICT"
  | "RESPONSE_INVALID"
  | "UNAVAILABLE";

export class OperatorApiError extends Error {
  constructor(
    readonly kind: OperatorApiErrorKind,
    readonly stableCode?: string,
  ) {
    super(kind);
    this.name = "OperatorApiError";
  }
}

export interface OperatorIdentity {
  readonly principal: string;
  readonly subject: string;
  readonly expiresAtEpochSeconds: number;
}

export interface OperatorCredential extends OperatorIdentity {
  readonly idToken: string;
  readonly csrfToken: string;
}

export interface OperatorCredentialProvider {
  getCredential(options: {
    readonly fresh: boolean;
    readonly signal?: AbortSignal;
  }): Promise<OperatorCredential>;
}

export interface RevocationCommand {
  readonly rootId: string;
  readonly rootSha256: string;
  readonly expectedEpoch: number;
  readonly reason: string;
  readonly requestId: string;
  readonly idempotencyKey: string;
  readonly expectedTarget: TargetBinding;
  readonly operatorPrincipal: string;
  readonly operatorSubject: string;
}

export interface RevocationResult {
  readonly resultId: string;
  readonly previousEpoch: number;
  readonly newEpoch: number;
  readonly evidenceId: string;
  readonly evidenceSha256: string;
  readonly committedAt: string;
}

export interface OperatorApi {
  authenticate(options?: {
    readonly fresh?: boolean;
    readonly signal?: AbortSignal;
  }): Promise<OperatorIdentity>;
  readTimeline(query: TimelineQuery, signal?: AbortSignal): Promise<TimelinePage>;
  revoke(command: RevocationCommand, signal?: AbortSignal): Promise<RevocationResult>;
}

export interface ControlGraphOperatorIdentityBridge {
  getCredential(options: {
    readonly fresh: boolean;
    readonly signal?: AbortSignal;
  }): Promise<OperatorCredential>;
}

declare global {
  interface Window {
    controlGraphOperatorIdentity?: ControlGraphOperatorIdentityBridge;
  }
}

class BrowserCredentialProvider implements OperatorCredentialProvider {
  async getCredential(options: {
    readonly fresh: boolean;
    readonly signal?: AbortSignal;
  }): Promise<OperatorCredential> {
    const bridge = window.controlGraphOperatorIdentity;
    if (bridge === undefined) {
      throw new OperatorApiError("AUTHENTICATION_REQUIRED");
    }
    return bridge.getCredential(options);
  }
}

function validCredential(value: OperatorCredential): OperatorCredential {
  const now = Math.floor(Date.now() / 1000);
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.principal !== "string" ||
    !humanEmail.test(value.principal) ||
    value.principal.endsWith(".iam.gserviceaccount.com") ||
    typeof value.subject !== "string" ||
    !googleSubject.test(value.subject) ||
    !Number.isSafeInteger(value.expiresAtEpochSeconds) ||
    value.expiresAtEpochSeconds <= now + 15 ||
    typeof value.idToken !== "string" ||
    value.idToken.length > 6_144 ||
    !jwt.test(value.idToken) ||
    typeof value.csrfToken !== "string" ||
    !csrfToken.test(value.csrfToken)
  ) {
    throw new OperatorApiError("AUTHENTICATION_REQUIRED");
  }
  return value;
}

function safeApiUrl(origin: string, path: string): URL {
  const url = new URL(path, origin);
  const expected = new URL(origin);
  const localDevelopmentOrigin =
    url.protocol === "http:" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]");
  if (
    url.origin !== expected.origin ||
    (url.protocol !== "https:" && !localDevelopmentOrigin)
  ) {
    throw new OperatorApiError("UNAVAILABLE");
  }
  return url;
}

interface DeadlineSignal {
  readonly signal: AbortSignal;
  readonly timedOut: () => boolean;
  readonly dispose: () => void;
}

function withDeadline(parent: AbortSignal | undefined, milliseconds: number): DeadlineSignal {
  const controller = new AbortController();
  let didTimeOut = false;
  const abortFromParent = (): void => controller.abort(parent?.reason);
  if (parent?.aborted) {
    abortFromParent();
  } else {
    parent?.addEventListener("abort", abortFromParent, { once: true });
  }
  const timer = globalThis.setTimeout(() => {
    didTimeOut = true;
    controller.abort();
  }, milliseconds);
  return {
    signal: controller.signal,
    timedOut: () => didTimeOut,
    dispose: () => {
      globalThis.clearTimeout(timer);
      parent?.removeEventListener("abort", abortFromParent);
    },
  };
}

function unavailableOnDeadline(error: unknown, deadline: DeadlineSignal): never {
  if (deadline.timedOut()) {
    throw new OperatorApiError("UNAVAILABLE", "OPERATOR_API_DEADLINE_EXCEEDED");
  }
  if (error instanceof DOMException && error.name === "AbortError") {
    throw error;
  }
  throw new OperatorApiError("UNAVAILABLE");
}

async function obtainCredential(
  provider: OperatorCredentialProvider,
  fresh: boolean,
  deadline: DeadlineSignal,
): Promise<OperatorCredential> {
  try {
    return validCredential(
      await provider.getCredential({ fresh, signal: deadline.signal }),
    );
  } catch (error) {
    if (error instanceof OperatorApiError) {
      throw error;
    }
    unavailableOnDeadline(error, deadline);
  }
}

async function boundedText(response: Response, maximum = MAX_RESPONSE_BYTES): Promise<string> {
  const declared = response.headers.get("Content-Length");
  if (declared !== null) {
    if (!/^[0-9]{1,8}$/.test(declared) || Number(declared) > maximum) {
      throw new OperatorApiError("RESPONSE_INVALID");
    }
  }
  if (response.body === null) {
    const text = await response.text();
    if (new TextEncoder().encode(text).length > maximum) {
      throw new OperatorApiError("RESPONSE_INVALID");
    }
    return text;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    size += value.byteLength;
    if (size > maximum) {
      await reader.cancel();
      throw new OperatorApiError("RESPONSE_INVALID");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
}

async function responseCode(response: Response): Promise<string | undefined> {
  try {
    const text = await boundedText(response, 4_096);
    const parsed: unknown = JSON.parse(text);
    if (
      parsed !== null &&
      !Array.isArray(parsed) &&
      typeof parsed === "object" &&
      "code" in parsed &&
      typeof parsed.code === "string" &&
      /^[A-Z0-9_]{1,96}$/.test(parsed.code)
    ) {
      return parsed.code;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

async function apiFailure(response: Response): Promise<OperatorApiError> {
  const code = await responseCode(response);
  if (response.status === 401) {
    return new OperatorApiError("AUTHENTICATION_REQUIRED", code);
  }
  if (response.status === 403) {
    return new OperatorApiError("ACCESS_DENIED", code);
  }
  if (
    code === "TIMELINE_READ_CURSOR_INVALID" ||
    code === "TIMELINE_CURSOR_INVALID"
  ) {
    return new OperatorApiError("CURSOR_INVALID", code);
  }
  if (code === "REVOCATION_EPOCH_MISMATCH" || code === "REVOCATION_ROOT_MISMATCH") {
    return new OperatorApiError("STALE_AUTHORITY", code);
  }
  if (response.status === 409) {
    return new OperatorApiError("CONFLICT", code);
  }
  if (response.status >= 500) {
    return new OperatorApiError("UNAVAILABLE", code);
  }
  return new OperatorApiError("RESPONSE_INVALID", code);
}

async function assertTimelineCommandDigest(text: string): Promise<void> {
  let page: Record<string, unknown>;
  try {
    page = decodeVersionedCanonicalJson(text, "controlgraph.timeline-page/v1");
  } catch (error) {
    if (error instanceof ContractCodecError) {
      throw new OperatorApiError("RESPONSE_INVALID");
    }
    throw error;
  }
  if (
    page.command === null ||
    Array.isArray(page.command) ||
    typeof page.command !== "object" ||
    typeof page.command_sha256 !== "string" ||
    !sha256.test(page.command_sha256)
  ) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  const command = page.command as Record<string, unknown>;
  if (
    command.schema_version !== "controlgraph.timeline-page-command/v1" ||
    page.command_sha256 !==
      (await canonicalSha256("controlgraph.timeline-page-command/v1", command))
  ) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
}

function requestInit(
  credential: OperatorCredential,
  signal: AbortSignal | undefined,
  mutation: boolean,
): RequestInit {
  const headers: Record<string, string> = {
    Accept: "application/json",
    [AUTHORIZATION_HEADER]: `Bearer ${credential.idToken}`,
    [SERVERLESS_AUTHORIZATION_HEADER]: `Bearer ${credential.idToken}`,
  };
  if (mutation) {
    headers["Content-Type"] = "application/json";
    headers[CSRF_HEADER] = credential.csrfToken;
  }
  return {
    method: mutation ? "POST" : "GET",
    headers,
    signal,
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
  };
}

function requireJsonResponse(response: Response): void {
  const contentType = response.headers.get("Content-Type");
  if (contentType === null || contentType.split(";", 1)[0]?.trim() !== "application/json") {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
}

function assertIdentifier(value: string, name: string): void {
  if (!identifier.test(value)) {
    throw new OperatorApiError("RESPONSE_INVALID", `${name.toUpperCase()}_INVALID`);
  }
}

function assertDigest(value: string, name: string): void {
  if (!sha256.test(value)) {
    throw new OperatorApiError("RESPONSE_INVALID", `${name.toUpperCase()}_INVALID`);
  }
}

function exactResponseRecord(
  value: unknown,
  allowed: readonly string[],
): Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  const result = value as Record<string, unknown>;
  const allowlist = new Set(allowed);
  if (Object.keys(result).some((key) => !allowlist.has(key))) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  return result;
}

async function sha256Material(...parts: readonly string[]): Promise<string> {
  const encoder = new TextEncoder();
  const encoded = parts.map((part) => encoder.encode(part));
  const size = encoded.reduce((total, part) => total + part.byteLength, 0);
  const material = new Uint8Array(size);
  let offset = 0;
  for (const part of encoded) {
    material.set(part, offset);
    offset += part.byteLength;
  }
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", material),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function revocationRequestSha256(
  command: RevocationCommand,
  identity: OperatorIdentity,
): Promise<string> {
  return sha256Material(
    REVOCATION_REQUEST_DIGEST_DOMAIN,
    canonicalJson({
      confirmation: "REVOKE",
      expected_epoch: command.expectedEpoch,
      expected_root_sha256: command.rootSha256,
      idempotency_key: command.idempotencyKey,
      operator_identity: identity.principal,
      operator_subject: identity.subject,
      reason: command.reason,
      request_id: command.requestId,
      root_id: command.rootId,
      schema_version: "controlgraph.epoch-revocation-request/v1",
    }),
  );
}

function parseResponseTarget(value: unknown): TargetBinding {
  const target = exactResponseRecord(value, [
    "schema_version",
    "project_id",
    "region",
    "environment",
    "service_name",
  ]);
  if (
    target.schema_version !== "controlgraph.target-binding/v1" ||
    typeof target.project_id !== "string" ||
    typeof target.region !== "string" ||
    typeof target.environment !== "string" ||
    typeof target.service_name !== "string"
  ) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  return target as unknown as TargetBinding;
}

async function parseRevocationResult(
  text: string,
  command: RevocationCommand,
  credential: OperatorCredential,
): Promise<RevocationResult> {
  let response: Record<string, unknown>;
  try {
    response = decodeVersionedCanonicalJson(
      text,
      "controlgraph.epoch-revocation-call-outcome/v1",
    );
  } catch (error) {
    if (error instanceof ContractCodecError) {
      throw new OperatorApiError("RESPONSE_INVALID");
    }
    throw error;
  }
  const envelope = exactResponseRecord(response, [
    "schema_version",
    "attempt_id",
    "audit_id",
    "result",
  ]);
  if (
    typeof envelope.attempt_id !== "string" ||
    typeof envelope.audit_id !== "string" ||
    envelope.attempt_id !== envelope.audit_id
  ) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  assertIdentifier(envelope.attempt_id, "attempt");
  const value = exactResponseRecord(envelope.result, [
    "schema_version",
    "result_id",
    "request_sha256",
    "request_id",
    "idempotency_key",
    "root_id",
    "root_sha256",
    "target",
    "operator_identity",
    "operator_subject",
    "reason",
    "previous_epoch",
    "new_epoch",
    "evidence_id",
    "evidence_sha256",
    "evidence_subject",
    "committed_at",
  ]);
  const resultId = value.result_id;
  const requestSha256 = value.request_sha256;
  const evidenceId = value.evidence_id;
  const evidenceSha256 = value.evidence_sha256;
  const committedAt = value.committed_at;
  const target = parseResponseTarget(value.target);
  if (
    typeof resultId !== "string" ||
    typeof requestSha256 !== "string" ||
    typeof evidenceId !== "string" ||
    typeof evidenceSha256 !== "string" ||
    typeof committedAt !== "string" ||
    value.schema_version !== "controlgraph.epoch-revocation-result/v1" ||
    value.root_id !== command.rootId ||
    value.root_sha256 !== command.rootSha256 ||
    value.previous_epoch !== command.expectedEpoch ||
    value.new_epoch !== command.expectedEpoch + 1 ||
    value.reason !== command.reason ||
    value.request_id !== command.requestId ||
    value.idempotency_key !== command.idempotencyKey ||
    value.operator_identity !== credential.principal ||
    value.operator_subject !== credential.subject ||
    !targetEquals(target, command.expectedTarget)
  ) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  assertIdentifier(resultId, "result");
  assertIdentifier(evidenceId, "evidence");
  assertDigest(requestSha256, "request digest");
  assertDigest(evidenceSha256, "evidence digest");
  try {
    const parsed = new Date(committedAt);
    if (parsed.toISOString().replace(".000Z", "Z") !== committedAt) {
      throw new Error("invalid");
    }
  } catch {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  const expectedRequestSha256 = await revocationRequestSha256(command, credential);
  const expectedEvidenceId = `cgevidence:${await sha256Material(
    REVOCATION_EVIDENCE_ID_DOMAIN,
    `${expectedRequestSha256}\0${command.rootSha256}\0${command.expectedEpoch + 1}`,
  )}`;
  if (
    requestSha256 !== expectedRequestSha256 ||
    resultId !== `cgrevoke:${expectedRequestSha256}` ||
    evidenceId !== expectedEvidenceId
  ) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  const evidenceSubject = exactResponseRecord(value.evidence_subject, [
    "schema_version",
    "root_id",
    "root_sha256",
    "request_sha256",
    "request_id",
    "idempotency_key",
    "operator_identity",
    "operator_subject",
    "reason",
    "service_claim_sha256",
    "previous_authority_sha256",
    "replacement_authority_sha256",
    "previous_epoch",
    "new_epoch",
    "evidence_id",
    "committed_at",
  ]);
  if (
    evidenceSubject.schema_version !==
      "controlgraph.epoch-revocation-evidence-subject/v1" ||
    evidenceSubject.root_id !== command.rootId ||
    evidenceSubject.root_sha256 !== command.rootSha256 ||
    evidenceSubject.request_sha256 !== expectedRequestSha256 ||
    evidenceSubject.request_id !== command.requestId ||
    evidenceSubject.idempotency_key !== command.idempotencyKey ||
    evidenceSubject.operator_identity !== credential.principal ||
    evidenceSubject.operator_subject !== credential.subject ||
    evidenceSubject.reason !== command.reason ||
    evidenceSubject.previous_epoch !== command.expectedEpoch ||
    evidenceSubject.new_epoch !== command.expectedEpoch + 1 ||
    evidenceSubject.evidence_id !== expectedEvidenceId ||
    evidenceSubject.committed_at !== committedAt ||
    typeof evidenceSubject.service_claim_sha256 !== "string" ||
    typeof evidenceSubject.previous_authority_sha256 !== "string" ||
    typeof evidenceSubject.replacement_authority_sha256 !== "string"
  ) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  assertDigest(evidenceSubject.service_claim_sha256, "service claim digest");
  assertDigest(evidenceSubject.previous_authority_sha256, "previous authority digest");
  assertDigest(
    evidenceSubject.replacement_authority_sha256,
    "replacement authority digest",
  );
  if (
    evidenceSha256 !==
    (await canonicalSha256(
      "controlgraph.epoch-revocation-evidence-subject/v1",
      evidenceSubject,
    ))
  ) {
    throw new OperatorApiError("RESPONSE_INVALID");
  }
  return {
    resultId,
    previousEpoch: command.expectedEpoch,
    newEpoch: command.expectedEpoch + 1,
    evidenceId,
    evidenceSha256,
    committedAt,
  };
}

export class FetchOperatorApi implements OperatorApi {
  private readonly origin: string;
  private authenticatedIdentity: OperatorIdentity | null = null;

  constructor(
    private readonly credentials: OperatorCredentialProvider,
    origin: string,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    const parsed = new URL(origin);
    const localDevelopmentOrigin =
      parsed.protocol === "http:" &&
      (parsed.hostname === "localhost" ||
        parsed.hostname === "127.0.0.1" ||
        parsed.hostname === "[::1]");
    if (
      (parsed.protocol !== "https:" && !localDevelopmentOrigin) ||
      parsed.origin !== origin
    ) {
      throw new OperatorApiError("UNAVAILABLE");
    }
    this.origin = origin;
  }

  async authenticate(options: {
    readonly fresh?: boolean;
    readonly signal?: AbortSignal;
  } = {}): Promise<OperatorIdentity> {
    const deadline = withDeadline(options.signal, TIMELINE_DEADLINE_MS);
    try {
      const credential = await obtainCredential(
        this.credentials,
        options.fresh ?? false,
        deadline,
      );
      const identity = {
        principal: credential.principal,
        subject: credential.subject,
        expiresAtEpochSeconds: credential.expiresAtEpochSeconds,
      };
      this.authenticatedIdentity = identity;
      return identity;
    } finally {
      deadline.dispose();
    }
  }

  async readTimeline(
    query: TimelineQuery,
    signal?: AbortSignal,
  ): Promise<TimelinePage> {
    const deadline = withDeadline(signal, TIMELINE_DEADLINE_MS);
    try {
      const credential = await obtainCredential(this.credentials, false, deadline);
      if (
        this.authenticatedIdentity !== null &&
        (credential.principal !== this.authenticatedIdentity.principal ||
          credential.subject !== this.authenticatedIdentity.subject)
      ) {
        throw new OperatorApiError(
          "AUTHENTICATION_REQUIRED",
          "OPERATOR_IDENTITY_CHANGED",
        );
      }
      const url = safeApiUrl(this.origin, OPERATOR_TIMELINE_PATH);
      url.searchParams.set("after_sequence", String(query.afterSequence));
      if (query.afterEntrySha256 !== null) {
        url.searchParams.set("after_entry_sha256", query.afterEntrySha256);
      }
      url.searchParams.set("limit", String(query.limit));
      url.searchParams.set("audience", query.audience);
      let response: Response;
      try {
        response = await this.fetcher(
          url,
          requestInit(credential, deadline.signal, false),
        );
      } catch (error) {
        unavailableOnDeadline(error, deadline);
      }
      if (!response.ok) {
        throw await apiFailure(response);
      }
      requireJsonResponse(response);
      try {
        const text = await boundedText(response);
        await assertTimelineCommandDigest(text);
        return decodeTimelinePage(text, query);
      } catch (error) {
        if (error instanceof OperatorApiError) {
          throw error;
        }
        throw new OperatorApiError("RESPONSE_INVALID");
      }
    } finally {
      deadline.dispose();
    }
  }

  async revoke(
    command: RevocationCommand,
    signal?: AbortSignal,
  ): Promise<RevocationResult> {
    const deadline = withDeadline(signal, MUTATION_DEADLINE_MS);
    try {
      const credential = await obtainCredential(this.credentials, true, deadline);
      if (
        credential.principal !== command.operatorPrincipal ||
        credential.subject !== command.operatorSubject
      ) {
        throw new OperatorApiError(
          "AUTHENTICATION_REQUIRED",
          "REVOCATION_OPERATOR_CHANGED",
        );
      }
      const body = canonicalJson({
        confirmation: "REVOKE",
        expected_epoch: command.expectedEpoch,
        expected_root_sha256: command.rootSha256,
        idempotency_key: command.idempotencyKey,
        reason: command.reason,
        request_id: command.requestId,
        root_id: command.rootId,
        schema_version: "controlgraph.epoch-revocation-command/v1",
      });
      let response: Response;
      try {
        response = await this.fetcher(
          safeApiUrl(this.origin, OPERATOR_COMMAND_PATH),
          { ...requestInit(credential, deadline.signal, true), body },
        );
      } catch (error) {
        unavailableOnDeadline(error, deadline);
      }
      if (!response.ok) {
        throw await apiFailure(response);
      }
      requireJsonResponse(response);
      return await parseRevocationResult(
        await boundedText(response),
        command,
        credential,
      );
    } finally {
      deadline.dispose();
    }
  }
}

export function createBrowserOperatorApi(): OperatorApi {
  return new FetchOperatorApi(
    new BrowserCredentialProvider(),
    window.location.origin,
  );
}

export function newRevocationIdentity(): {
  readonly requestId: string;
  readonly idempotencyKey: string;
} {
  if (typeof globalThis.crypto?.randomUUID !== "function") {
    throw new OperatorApiError("UNAVAILABLE");
  }
  const identity = globalThis.crypto.randomUUID();
  return {
    requestId: `console-revoke-${identity}`,
    idempotencyKey: `console-revoke-${identity}`,
  };
}

export const DEFAULT_TIMELINE_QUERY = Object.freeze({
  audience: "OPERATOR" as const,
  limit: TIMELINE_PAGE_LIMIT,
});
