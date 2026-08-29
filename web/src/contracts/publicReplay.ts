import {
  assertUtcSecondTimestamp,
  canonicalSha256,
  decodeVersionedCanonicalJson,
} from "./canonical";

export const PUBLIC_REPLAY_ENVELOPE_VERSION = "controlgraph.public-replay-envelope/v1";
export const PUBLIC_REPLAY_PAYLOAD_VERSION = "controlgraph.public-replay-payload/v1";
export const PUBLIC_REPLAY_EVENT_VERSION = "controlgraph.public-replay-event/v1";
export const MAX_PUBLIC_REPLAY_JSON_BYTES = 65_536;

const sha256 = /^[0-9a-f]{64}$/;
const commit = /^[0-9a-f]{40}$/;
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const unsafeRenderingControl = /[\p{C}\p{Zl}\p{Zp}]/u;
const imageReference =
  /^us-central1-docker\.pkg\.dev\/(controlgraph-canary-[a-z0-9]{6,10})\/controlgraph-canary\/([a-z][a-z0-9-]*)@sha256:([0-9a-f]{64})$/;

const imageComponents = [
  "controller",
  "advisor",
  "console",
  "reference-stable",
  "reference-candidate",
] as const;

const eventKinds = [
  "AUTHORITY_ADVANCED",
  "STALE_WORK_DENIED",
  "TARGET_UNCHANGED",
  "ADVISOR_VALIDATED",
  "RECOVERY_VERIFIED",
  "TIMELINE_COMMITTED",
] as const;

const caseKinds = [
  "TARGET_RESET",
  "HEALTHY_PROMOTION",
  "UNHEALTHY_STABLE_RECOVERY",
  "REVOCATION_STALE_DENIAL",
  "INDEPENDENT_VERIFIER_PROBE",
  "AMBIGUITY_CLASSIFICATION",
  "TIMELINE_CONSOLE_READ",
  "BOUNDED_ADVISOR",
] as const;

const advisorToolIds = [
  "read_root_summary",
  "read_target_summary",
  "read_health_summary",
  "read_receipt_summary",
  "read_timeline_summary",
  "read_verifier_summary",
] as const;

const requestedOperatorActions = [
  "wait",
  "collect_approved_diagnostics",
  "request_revocation",
  "request_captured_stable_recovery",
  "request_new_operator_approved_rollout",
  "manual_review",
] as const;

const timelineEventTypes = [
  "AUTHORITY_EPOCH_ADVANCED",
  "MUTATION_APPLIED",
  "MUTATION_DENIED",
  "MODEL_ASSISTANCE_RECORDED",
] as const;

type ImageComponent = (typeof imageComponents)[number];
type PublicReplayCaseKind = (typeof caseKinds)[number];
export type PublicReplayEventKind = (typeof eventKinds)[number];

export interface PublicReplayTraffic {
  readonly schema_version: "controlgraph.public-replay-traffic/v1";
  readonly stable_percent: number;
  readonly candidate_percent: number;
  readonly target_configuration_sha256: string;
}

export interface PublicReplayCitation {
  readonly schema_version: "controlgraph.public-replay-citation/v1";
  readonly evidence_kind: "root" | "target" | "health" | "receipt" | "timeline" | "verifier";
  readonly evidence_id: string;
  readonly source_sha256: string;
}

export interface PublicReplayFinding {
  readonly schema_version: "controlgraph.public-replay-finding/v1";
  readonly statement: string;
  readonly citations: readonly PublicReplayCitation[];
}

export interface PublicReplayAdvisor {
  readonly schema_version: "controlgraph.public-replay-advisor/v1";
  readonly model_id: "gemini-3.5-flash";
  readonly model_location: "global";
  readonly prompt_version: "controlgraph.rollout-advisor-prompt/v2";
  readonly response_sha256: string;
  readonly audit_sha256: string;
  readonly registry_sha256: string;
  readonly snapshot_sha256: string;
  readonly structured_output_sha256: string;
  readonly validation: "accepted";
  readonly authority_effect: "none";
  readonly deterministic_health_override: false;
  readonly operator_review_required: true;
  readonly requested_operator_action: (typeof requestedOperatorActions)[number];
  readonly confidence_basis_points: number;
  readonly findings: readonly PublicReplayFinding[];
  readonly tool_calls: readonly Record<string, unknown>[];
  readonly replayed_without_model_call: true;
}

export interface PublicReplayEvent {
  readonly schema_version: "controlgraph.public-replay-event/v1";
  readonly sequence: number;
  readonly kind: PublicReplayEventKind;
  readonly occurred_at: string;
  readonly previous_event_sha256: string | null;
  readonly details: Record<string, unknown>;
}

export interface PublicReplayEventEnvelope {
  readonly schema_version: "controlgraph.public-replay-event-envelope/v1";
  readonly event: PublicReplayEvent;
  readonly event_sha256: string;
}

export interface PublicReplayPayload {
  readonly schema_version: "controlgraph.public-replay-payload/v1";
  readonly source_commit: string;
  readonly acceptance_manifest_sha256: string;
  readonly acceptance_run_id: string;
  readonly acceptance_status: "PASSED";
  readonly evidence_binding_complete: true;
  readonly accepted_at: string;
  readonly images: readonly {
    readonly schema_version: "controlgraph.public-replay-image/v1";
    readonly component: ImageComponent;
    readonly reference: string;
  }[];
  readonly cases: readonly {
    readonly schema_version: "controlgraph.public-replay-case/v1";
    readonly sequence: number;
    readonly kind: PublicReplayCaseKind;
    readonly case_sha256: string;
  }[];
  readonly events: readonly PublicReplayEventEnvelope[];
  readonly event_chain_head_sha256: string;
}

export interface PublicReplayEnvelope {
  readonly schema_version: "controlgraph.public-replay-envelope/v1";
  readonly payload: PublicReplayPayload;
  readonly payload_sha256: string;
}

declare global {
  interface Window {
    controlGraphPublicReplayConfig?: Readonly<{
      available: boolean;
      sha256: string | null;
    }>;
  }
}

function invalid(): never {
  throw new Error("PUBLIC_REPLAY_INVALID");
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    return invalid();
  }
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    invalid();
  }
}

function stringValue(value: unknown, pattern?: RegExp): string {
  if (typeof value !== "string" || (pattern !== undefined && !pattern.test(value))) {
    return invalid();
  }
  return value;
}

function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    return invalid();
  }
  return value as number;
}

function timestamp(value: unknown): string {
  const result = stringValue(value);
  try {
    assertUtcSecondTimestamp(result);
  } catch {
    return invalid();
  }
  return result;
}

function oneOf<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== "string" || !values.includes(value as T)) {
    return invalid();
  }
  return value as T;
}

function array(value: unknown, minimum: number, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    return invalid();
  }
  return value;
}

function traffic(value: unknown): PublicReplayTraffic {
  const item = record(value);
  exact(item, [
    "candidate_percent",
    "schema_version",
    "stable_percent",
    "target_configuration_sha256",
  ]);
  if (item.schema_version !== "controlgraph.public-replay-traffic/v1") {
    invalid();
  }
  const stable = integer(item.stable_percent, 0, 100);
  const candidate = integer(item.candidate_percent, 0, 100);
  if (stable + candidate !== 100) {
    invalid();
  }
  stringValue(item.target_configuration_sha256, sha256);
  return item as unknown as PublicReplayTraffic;
}

function authorityDetails(value: unknown): void {
  const item = record(value);
  exact(item, ["cause", "new_epoch", "previous_epoch", "schema_version", "transition_sha256"]);
  if (
    item.schema_version !== "controlgraph.public-replay-authority-advanced/v1" ||
    item.cause !== "OPERATOR_REVOCATION"
  ) {
    invalid();
  }
  const previous = integer(item.previous_epoch, 1);
  if (integer(item.new_epoch, 1) !== previous + 1) {
    invalid();
  }
  stringValue(item.transition_sha256, sha256);
}

function denialDetails(value: unknown): void {
  const item = record(value);
  exact(item, [
    "current_authority_epoch",
    "outcome",
    "reason_code",
    "receipt_sha256",
    "schema_version",
    "work_epoch",
  ]);
  if (
    item.schema_version !== "controlgraph.public-replay-stale-denial/v1" ||
    item.outcome !== "DENIED" ||
    item.reason_code !== "EPOCH_MISMATCH"
  ) {
    invalid();
  }
  const work = integer(item.work_epoch, 1);
  if (integer(item.current_authority_epoch, 1) !== work + 1) {
    invalid();
  }
  stringValue(item.receipt_sha256, sha256);
}

function unchangedDetails(value: unknown): void {
  const item = record(value);
  exact(item, ["after_denial", "before_denial", "schema_version"]);
  if (item.schema_version !== "controlgraph.public-replay-target-unchanged/v1") {
    invalid();
  }
  const before = traffic(item.before_denial);
  const after = traffic(item.after_denial);
  if (
    before.stable_percent !== 90 ||
    before.candidate_percent !== 10 ||
    JSON.stringify(before) !== JSON.stringify(after)
  ) {
    invalid();
  }
}

function citation(value: unknown): PublicReplayCitation {
  const item = record(value);
  exact(item, ["evidence_id", "evidence_kind", "schema_version", "source_sha256"]);
  if (item.schema_version !== "controlgraph.public-replay-citation/v1") {
    invalid();
  }
  oneOf(item.evidence_kind, ["root", "target", "health", "receipt", "timeline", "verifier"]);
  stringValue(item.evidence_id, identifier);
  stringValue(item.source_sha256, sha256);
  return item as unknown as PublicReplayCitation;
}

function finding(value: unknown): PublicReplayFinding {
  const item = record(value);
  exact(item, ["citations", "schema_version", "statement"]);
  if (item.schema_version !== "controlgraph.public-replay-finding/v1") {
    invalid();
  }
  const statement = stringValue(item.statement);
  if (
    Array.from(statement).length < 1 ||
    Array.from(statement).length > 512 ||
    unsafeRenderingControl.test(statement)
  ) {
    invalid();
  }
  const citations = array(item.citations, 1, 8).map(citation);
  const keys = citations.map((entry) =>
    `${entry.evidence_kind}\0${entry.evidence_id}\0${entry.source_sha256}`
  );
  if (new Set(keys).size !== keys.length) {
    invalid();
  }
  return item as unknown as PublicReplayFinding;
}

function advisorDetails(value: unknown): void {
  const outer = record(value);
  exact(outer, ["advisor", "schema_version"]);
  if (outer.schema_version !== "controlgraph.public-replay-advisor-validated/v1") {
    invalid();
  }
  const item = record(outer.advisor);
  exact(item, [
    "audit_sha256",
    "authority_effect",
    "confidence_basis_points",
    "deterministic_health_override",
    "findings",
    "model_id",
    "model_location",
    "operator_review_required",
    "prompt_version",
    "registry_sha256",
    "replayed_without_model_call",
    "requested_operator_action",
    "response_sha256",
    "schema_version",
    "snapshot_sha256",
    "structured_output_sha256",
    "tool_calls",
    "validation",
  ]);
  if (
    item.schema_version !== "controlgraph.public-replay-advisor/v1" ||
    item.model_id !== "gemini-3.5-flash" ||
    item.model_location !== "global" ||
    item.prompt_version !== "controlgraph.rollout-advisor-prompt/v2" ||
    item.validation !== "accepted" ||
    item.authority_effect !== "none" ||
    item.deterministic_health_override !== false ||
    item.operator_review_required !== true ||
    item.replayed_without_model_call !== true
  ) {
    invalid();
  }
  for (const name of [
    "audit_sha256",
    "registry_sha256",
    "response_sha256",
    "snapshot_sha256",
    "structured_output_sha256",
  ]) {
    stringValue(item[name], sha256);
  }
  oneOf(item.requested_operator_action, requestedOperatorActions);
  integer(item.confidence_basis_points, 0, 10_000);
  const findings = array(item.findings, 1, 8).map(finding);
  const citationKinds = new Set(
    findings.flatMap((entry) => entry.citations.map((entryCitation) => entryCitation.evidence_kind)),
  );
  if (
    !citationKinds.has("receipt") ||
    !citationKinds.has("timeline") ||
    (!citationKinds.has("target") && !citationKinds.has("verifier"))
  ) {
    invalid();
  }
  const toolCalls = array(item.tool_calls, 6, 6);
  const observedTools = new Set<string>();
  toolCalls.forEach((value, index) => {
    const call = record(value);
    exact(call, [
      "input_sha256",
      "output_sha256",
      "schema_version",
      "sequence",
      "status",
      "tool_id",
    ]);
    if (
      call.schema_version !== "controlgraph.public-replay-tool-call/v1" ||
      call.sequence !== index + 1 ||
      call.status !== "succeeded"
    ) {
      invalid();
    }
    observedTools.add(oneOf(call.tool_id, advisorToolIds));
    stringValue(call.input_sha256, sha256);
    stringValue(call.output_sha256, sha256);
  });
  if (
    observedTools.size !== advisorToolIds.length ||
    advisorToolIds.some((toolId) => !observedTools.has(toolId))
  ) {
    invalid();
  }
}

function recoveryDetails(value: unknown): void {
  const item = record(value);
  exact(item, ["outcome", "receipt_sha256", "schema_version", "traffic"]);
  if (
    item.schema_version !== "controlgraph.public-replay-recovery-verified/v1" ||
    item.outcome !== "VERIFIED"
  ) {
    invalid();
  }
  stringValue(item.receipt_sha256, sha256);
  const state = traffic(item.traffic);
  if (state.stable_percent !== 100 || state.candidate_percent !== 0) {
    invalid();
  }
}

function timelineDetails(value: unknown): void {
  const outer = record(value);
  exact(outer, ["schema_version", "timeline"]);
  if (outer.schema_version !== "controlgraph.public-replay-timeline-committed/v1") {
    invalid();
  }
  const item = record(outer.timeline);
  exact(item, [
    "entries",
    "entry_count",
    "head_entry_sha256",
    "head_sequence",
    "page_count",
    "page_set_sha256",
    "schema_version",
  ]);
  if (item.schema_version !== "controlgraph.public-replay-timeline/v1") {
    invalid();
  }
  const head = integer(item.head_sequence, 1);
  const count = integer(item.entry_count, 1, head);
  integer(item.page_count, 1);
  stringValue(item.head_entry_sha256, sha256);
  stringValue(item.page_set_sha256, sha256);
  const entries = array(item.entries, 4, 8);
  let previousSequence = 0;
  const kinds = new Set<string>();
  const digests = new Set<string>();
  entries.forEach((value) => {
    const entry = record(value);
    exact(entry, [
      "entry_sha256",
      "event_type",
      "occurred_at",
      "schema_version",
      "sequence",
      "verification_status",
    ]);
    if (entry.schema_version !== "controlgraph.public-replay-timeline-entry/v1") {
      invalid();
    }
    const sequence = integer(entry.sequence, previousSequence + 1, head);
    if (sequence <= previousSequence) {
      invalid();
    }
    previousSequence = sequence;
    const digest = stringValue(entry.entry_sha256, sha256);
    digests.add(digest);
    kinds.add(oneOf(entry.event_type, timelineEventTypes));
    timestamp(entry.occurred_at);
    oneOf(entry.verification_status, ["NOT_APPLICABLE", "VERIFIED"]);
  });
  if (
    count > head ||
    entries.length > count ||
    digests.size !== entries.length ||
    kinds.size !== timelineEventTypes.length
  ) {
    invalid();
  }
  timelineEventTypes.forEach((kind) => {
    if (!kinds.has(kind)) {
      invalid();
    }
  });
}

function validateDetails(kind: PublicReplayEventKind, value: unknown): void {
  const validators: Record<PublicReplayEventKind, (candidate: unknown) => void> = {
    AUTHORITY_ADVANCED: authorityDetails,
    STALE_WORK_DENIED: denialDetails,
    TARGET_UNCHANGED: unchangedDetails,
    ADVISOR_VALIDATED: advisorDetails,
    RECOVERY_VERIFIED: recoveryDetails,
    TIMELINE_COMMITTED: timelineDetails,
  };
  validators[kind](value);
}

async function validatePayload(value: unknown): Promise<PublicReplayPayload> {
  const item = record(value);
  exact(item, [
    "acceptance_manifest_sha256",
    "acceptance_run_id",
    "acceptance_status",
    "accepted_at",
    "cases",
    "event_chain_head_sha256",
    "events",
    "evidence_binding_complete",
    "images",
    "schema_version",
    "source_commit",
  ]);
  if (
    item.schema_version !== PUBLIC_REPLAY_PAYLOAD_VERSION ||
    item.acceptance_status !== "PASSED" ||
    item.evidence_binding_complete !== true
  ) {
    invalid();
  }
  stringValue(item.source_commit, commit);
  stringValue(item.acceptance_manifest_sha256, sha256);
  stringValue(item.acceptance_run_id, identifier);
  const acceptedAt = timestamp(item.accepted_at);
  const images = array(item.images, 5, 5);
  const projects = new Set<string>();
  const digests = new Set<string>();
  images.forEach((value, index) => {
    const image = record(value);
    exact(image, ["component", "reference", "schema_version"]);
    if (
      image.schema_version !== "controlgraph.public-replay-image/v1" ||
      image.component !== imageComponents[index]
    ) {
      invalid();
    }
    const match = imageReference.exec(stringValue(image.reference));
    if (match === null || match[2] !== image.component) {
      invalid();
    }
    projects.add(match[1]);
    digests.add(match[3]);
  });
  if (projects.size !== 1 || digests.size !== 5) {
    invalid();
  }

  const cases = array(item.cases, 8, 8);
  const caseDigests = new Set<string>();
  cases.forEach((value, index) => {
    const replayCase = record(value);
    exact(replayCase, ["case_sha256", "kind", "schema_version", "sequence"]);
    if (
      replayCase.schema_version !== "controlgraph.public-replay-case/v1" ||
      replayCase.sequence !== index + 1 ||
      replayCase.kind !== caseKinds[index]
    ) {
      invalid();
    }
    caseDigests.add(stringValue(replayCase.case_sha256, sha256));
  });
  if (caseDigests.size !== caseKinds.length) {
    invalid();
  }

  const events = array(item.events, 6, 6);
  let predecessor: string | null = null;
  let previousTime = "";
  for (const [index, value] of events.entries()) {
    const envelope = record(value);
    exact(envelope, ["event", "event_sha256", "schema_version"]);
    if (envelope.schema_version !== "controlgraph.public-replay-event-envelope/v1") {
      invalid();
    }
    const event = record(envelope.event);
    exact(event, [
      "details",
      "kind",
      "occurred_at",
      "previous_event_sha256",
      "schema_version",
      "sequence",
    ]);
    const kind = oneOf(event.kind, eventKinds);
    const occurredAt = timestamp(event.occurred_at);
    if (
      event.schema_version !== PUBLIC_REPLAY_EVENT_VERSION ||
      event.sequence !== index + 1 ||
      kind !== eventKinds[index] ||
      event.previous_event_sha256 !== predecessor ||
      (previousTime !== "" && occurredAt < previousTime) ||
      occurredAt > acceptedAt
    ) {
      invalid();
    }
    validateDetails(kind, event.details);
    const observed = await canonicalSha256(PUBLIC_REPLAY_EVENT_VERSION, event);
    if (envelope.event_sha256 !== observed) {
      invalid();
    }
    predecessor = observed;
    previousTime = occurredAt;
  }
  if (predecessor === null || item.event_chain_head_sha256 !== predecessor) {
    invalid();
  }
  const authority = record(record(record(events[0]).event).details);
  const denial = record(record(record(events[1]).event).details);
  if (
    authority.previous_epoch !== denial.work_epoch ||
    authority.new_epoch !== denial.current_authority_epoch
  ) {
    invalid();
  }
  return item as unknown as PublicReplayPayload;
}

export async function validatePublicReplayEnvelope(
  value: Record<string, unknown>,
): Promise<PublicReplayEnvelope> {
  exact(value, ["payload", "payload_sha256", "schema_version"]);
  if (value.schema_version !== PUBLIC_REPLAY_ENVELOPE_VERSION) {
    invalid();
  }
  const payload = await validatePayload(value.payload);
  if (
    stringValue(value.payload_sha256, sha256) !==
    await canonicalSha256(PUBLIC_REPLAY_PAYLOAD_VERSION, payload)
  ) {
    invalid();
  }
  return value as unknown as PublicReplayEnvelope;
}

async function digest(value: Uint8Array): Promise<string> {
  const material = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
  const result = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", material));
  return Array.from(result, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function boundedResponse(response: Response): Promise<Uint8Array> {
  if (response.body === null) {
    return invalid();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    size += value.byteLength;
    if (size > MAX_PUBLIC_REPLAY_JSON_BYTES) {
      await reader.cancel();
      return invalid();
    }
    chunks.push(value);
  }
  if (size === 0) {
    return invalid();
  }
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

export async function loadPublicReplay(
  fetcher: typeof fetch = globalThis.fetch,
): Promise<PublicReplayEnvelope | null> {
  const config = window.controlGraphPublicReplayConfig;
  if (
    config === undefined ||
    typeof config.available !== "boolean" ||
    (config.available
      ? typeof config.sha256 !== "string" || !sha256.test(config.sha256)
      : config.sha256 !== null)
  ) {
    return invalid();
  }
  if (!config.available) {
    return null;
  }
  const expectedSha256 = config.sha256 as string;
  const response = await fetcher(`/replays/${expectedSha256}.json`, {
    method: "GET",
    credentials: "omit",
    redirect: "error",
    headers: { Accept: "application/json" },
  });
  if (
    !response.ok ||
    response.headers.get("content-type")?.split(";", 1)[0] !== "application/json"
  ) {
    return invalid();
  }
  const bytes = await boundedResponse(response);
  if (await digest(bytes) !== expectedSha256) {
    return invalid();
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return invalid();
  }
  const value = decodeVersionedCanonicalJson(text, PUBLIC_REPLAY_ENVELOPE_VERSION);
  return validatePublicReplayEnvelope(value);
}
