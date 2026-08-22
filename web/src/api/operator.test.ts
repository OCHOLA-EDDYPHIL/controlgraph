import { describe, expect, it, vi } from "vitest";

import { canonicalJson, canonicalSha256 } from "../contracts/canonical";
import type { TimelineQuery } from "../contracts/timeline";
import {
  ROOT_ID,
  ROOT_SHA256,
  TARGET,
  field,
  timelineEntry,
  timelinePageBody,
} from "../test/timelineFixtures";
import {
  FetchOperatorApi,
  OperatorApiError,
  type OperatorCredential,
  type OperatorCredentialProvider,
  type RevocationCommand,
} from "./operator";

class CredentialProvider implements OperatorCredentialProvider {
  readonly calls: boolean[] = [];

  constructor(readonly credential: OperatorCredential) {}

  async getCredential(options: { readonly fresh: boolean }): Promise<OperatorCredential> {
    this.calls.push(options.fresh);
    return this.credential;
  }
}

function credential(overrides: Partial<OperatorCredential> = {}): OperatorCredential {
  return {
    principal: "operator@example.com",
    subject: "123456789012345678901",
    expiresAtEpochSeconds: Math.floor(Date.now() / 1000) + 600,
    idToken: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.synthetic-signature",
    csrfToken: "c".repeat(43),
    ...overrides,
  } as OperatorCredential;
}

async function pageBody(query: TimelineQuery): Promise<string> {
  const raw = JSON.parse(timelinePageBody(
    [
      timelineEntry(1, "MUTATION_APPLIED", {
        fields: [field("ACTION", "APPLY_CANARY")],
      }),
    ],
    query,
  )) as Record<string, unknown>;
  raw.command_sha256 = await canonicalSha256(
    "controlgraph.timeline-page-command/v1",
    raw.command,
  );
  return canonicalJson(raw);
}

async function sha256Material(...parts: readonly string[]): Promise<string> {
  const bytes = new TextEncoder().encode(parts.join(""));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function revocationBody(
  command: RevocationCommand,
  operator: OperatorCredential,
): Promise<string> {
  const requestSha256 = await sha256Material(
    "controlgraph.epoch-revocation-request-sha256/v1\0",
    canonicalJson({
      confirmation: "REVOKE",
      expected_epoch: command.expectedEpoch,
      expected_root_sha256: command.rootSha256,
      idempotency_key: command.idempotencyKey,
      operator_identity: operator.principal,
      operator_subject: operator.subject,
      reason: command.reason,
      request_id: command.requestId,
      root_id: command.rootId,
      schema_version: "controlgraph.epoch-revocation-request/v1",
    }),
  );
  const evidenceId = `cgevidence:${await sha256Material(
    "controlgraph.epoch-revocation-evidence-id/v1\0",
    `${requestSha256}\0${command.rootSha256}\0${command.expectedEpoch + 1}`,
  )}`;
  const evidenceSubject = {
    committed_at: "2026-08-21T12:30:00Z",
    evidence_id: evidenceId,
    idempotency_key: command.idempotencyKey,
    new_epoch: command.expectedEpoch + 1,
    operator_identity: operator.principal,
    operator_subject: operator.subject,
    previous_authority_sha256: "2".repeat(64),
    previous_epoch: command.expectedEpoch,
    reason: command.reason,
    replacement_authority_sha256: "3".repeat(64),
    request_id: command.requestId,
    request_sha256: requestSha256,
    root_id: command.rootId,
    root_sha256: command.rootSha256,
    schema_version: "controlgraph.epoch-revocation-evidence-subject/v1",
    service_claim_sha256: "1".repeat(64),
  };
  return canonicalJson({
    attempt_id: "attempt:revocation-1",
    audit_id: "attempt:revocation-1",
    result: {
      committed_at: "2026-08-21T12:30:00Z",
      evidence_id: evidenceId,
      evidence_sha256: await canonicalSha256(
        "controlgraph.epoch-revocation-evidence-subject/v1",
        evidenceSubject,
      ),
      evidence_subject: evidenceSubject,
      idempotency_key: command.idempotencyKey,
      new_epoch: command.expectedEpoch + 1,
      operator_identity: operator.principal,
      operator_subject: operator.subject,
      previous_epoch: command.expectedEpoch,
      reason: command.reason,
      request_id: command.requestId,
      request_sha256: requestSha256,
      result_id: `cgrevoke:${requestSha256}`,
      root_id: command.rootId,
      root_sha256: command.rootSha256,
      schema_version: "controlgraph.epoch-revocation-result/v1",
      target: TARGET,
    },
    schema_version: "controlgraph.epoch-revocation-call-outcome/v1",
  });
}

function revocationCommand(): RevocationCommand {
  return {
    rootId: ROOT_ID,
    rootSha256: ROOT_SHA256,
    expectedEpoch: 1,
    reason: "Operator observed unexpected rollout drift",
    requestId: "console-revoke-request-1",
    idempotencyKey: "console-revoke-request-1",
    expectedTarget: TARGET,
    operatorPrincipal: "operator@example.com",
    operatorSubject: "123456789012345678901",
  };
}

describe("authenticated operator API", () => {
  it("reads only the configured timeline endpoint with non-ambient bearer auth", async () => {
    const provider = new CredentialProvider(credential());
    const query: TimelineQuery = {
      afterSequence: 0,
      afterEntrySha256: null,
      audience: "OPERATOR",
      limit: 25,
    };
    const fetcher = vi.fn(async () =>
      new Response(await pageBody(query), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const api = new FetchOperatorApi(provider, "https://console.example", fetcher);

    const page = await api.readTimeline(query);

    expect(page.entries).toHaveLength(1);
    expect(page.nextCursor.afterSequence).toBe(1);
    expect(provider.calls).toEqual([false]);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = vi.mocked(fetcher).mock.calls[0]!;
    expect(String(url)).toBe(
      "https://console.example/v1/operator/timeline?after_sequence=0&limit=25&audience=OPERATOR",
    );
    const headers = new Headers(init?.headers);
    expect(headers.get("X-ControlGraph-Authorization")).toBe(
      `Bearer ${provider.credential.idToken}`,
    );
    expect(headers.get("X-Serverless-Authorization")).toBe(
      `Bearer ${provider.credential.idToken}`,
    );
    expect(headers.get("X-ControlGraph-CSRF")).toBeNull();
    expect(init).toMatchObject({
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
  });

  it("sends a fresh credential and anti-CSRF token for the exact revocation command", async () => {
    const provider = new CredentialProvider(credential());
    const command = revocationCommand();
    const fetcher = vi.fn(async () =>
      new Response(await revocationBody(command, provider.credential), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const api = new FetchOperatorApi(provider, "https://console.example", fetcher);

    const result = await api.revoke(command);

    expect(result).toMatchObject({
      previousEpoch: 1,
      newEpoch: 2,
      evidenceId: expect.stringMatching(/^cgevidence:[0-9a-f]{64}$/),
    });
    expect(provider.calls).toEqual([true]);
    const [url, init] = vi.mocked(fetcher).mock.calls[0]!;
    expect(String(url)).toBe("https://console.example/v1/operator/commands");
    const headers = new Headers(init?.headers);
    expect(headers.get("X-ControlGraph-CSRF")).toBe(provider.credential.csrfToken);
    expect(headers.get("X-ControlGraph-Authorization")).toBe(
      `Bearer ${provider.credential.idToken}`,
    );
    expect(headers.get("X-Serverless-Authorization")).toBe(
      `Bearer ${provider.credential.idToken}`,
    );
    expect(JSON.parse(String(init?.body))).toEqual({
      confirmation: "REVOKE",
      expected_epoch: 1,
      expected_root_sha256: ROOT_SHA256,
      idempotency_key: command.idempotencyKey,
      reason: command.reason,
      request_id: command.requestId,
      root_id: ROOT_ID,
      schema_version: "controlgraph.epoch-revocation-command/v1",
    });
    expect(init?.credentials).toBe("omit");
    expect(storageSpy).not.toHaveBeenCalled();
    storageSpy.mockRestore();
  });

  it("rejects a timeline page whose command digest was substituted", async () => {
    const provider = new CredentialProvider(credential());
    const query: TimelineQuery = {
      afterSequence: 0,
      afterEntrySha256: null,
      audience: "OPERATOR",
      limit: 25,
    };
    const body = JSON.parse(await pageBody(query)) as Record<string, unknown>;
    body.command_sha256 = "0".repeat(64);
    const fetcher = vi.fn(async () =>
      new Response(canonicalJson(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const api = new FetchOperatorApi(provider, "https://console.example", fetcher);

    await expect(api.readTimeline(query)).rejects.toMatchObject({
      kind: "RESPONSE_INVALID",
    });
  });

  it("refuses a mutation when the identity bridge omits anti-CSRF state", async () => {
    const provider = new CredentialProvider(credential({ csrfToken: "too-short" }));
    const fetcher = vi.fn() as unknown as typeof fetch;
    const api = new FetchOperatorApi(provider, "https://console.example", fetcher);

    await expect(
      api.revoke(revocationCommand()),
    ).rejects.toMatchObject({ kind: "AUTHENTICATION_REQUIRED" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("maps server epoch conflicts to a stale-authority failure without response text", async () => {
    const provider = new CredentialProvider(credential());
    const fetcher = vi.fn(async () =>
      new Response(
        JSON.stringify({
          code: "REVOCATION_EPOCH_MISMATCH",
          correlation_id: "a".repeat(32),
        }),
        { status: 409 },
      ),
    ) as unknown as typeof fetch;
    const api = new FetchOperatorApi(provider, "https://console.example", fetcher);

    await expect(
      api.revoke(revocationCommand()),
    ).rejects.toEqual(
      new OperatorApiError("STALE_AUTHORITY", "REVOCATION_EPOCH_MISMATCH"),
    );
  });

  it("rejects a successful response that is not bound to the reviewed target", async () => {
    const provider = new CredentialProvider(credential());
    const command = revocationCommand();
    const body = JSON.parse(
      await revocationBody(command, provider.credential),
    ) as Record<string, unknown>;
    const result = body.result as Record<string, unknown>;
    result.target = { ...TARGET, service_name: "different-reference-target" };
    const fetcher = vi.fn(async () =>
      new Response(canonicalJson(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const api = new FetchOperatorApi(provider, "https://console.example", fetcher);

    await expect(api.revoke(command)).rejects.toMatchObject({
      kind: "RESPONSE_INVALID",
    });
  });

  it("fails a dispatched revocation closed when its deadline expires", async () => {
    vi.useFakeTimers();
    try {
      const provider = new CredentialProvider(credential());
      const fetcher = vi.fn(
        async (_url: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener(
              "abort",
              () => reject(new DOMException("aborted", "AbortError")),
              { once: true },
            );
          }),
      ) as unknown as typeof fetch;
      const api = new FetchOperatorApi(provider, "https://console.example", fetcher);
      const assertion = expect(api.revoke(revocationCommand())).rejects.toEqual(
        new OperatorApiError("UNAVAILABLE", "OPERATOR_API_DEADLINE_EXCEEDED"),
      );

      await vi.advanceTimersByTimeAsync(60_000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });
});
