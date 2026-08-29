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
  type AdvisorCommand,
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

function advisorCommand(): AdvisorCommand {
  return {
    rootId: ROOT_ID,
    rootSha256: ROOT_SHA256,
    expectedEpoch: 2,
    requestId: "console-advisor-request-1",
    idempotencyKey: "console-advisor-request-1",
    requestedAt: "2026-08-28T20:00:00Z",
    expectedTarget: TARGET,
  };
}

function advisorCommandWire(command: AdvisorCommand): Record<string, unknown> {
  return {
    schema_version: "controlgraph.advisor-operator-command/v1",
    request_id: command.requestId,
    idempotency_key: command.idempotencyKey,
    target: command.expectedTarget,
    root_id: command.rootId,
    expected_root_sha256: command.rootSha256,
    expected_epoch: command.expectedEpoch,
    requested_at: command.requestedAt,
  };
}

async function advisorBody(command: AdvisorCommand): Promise<string> {
  const snapshotSha256 = "4".repeat(64);
  const recommendation = {
    assumptions: [],
    authority_effect: "none",
    confidence_basis_points: 9_100,
    current_epoch: command.expectedEpoch,
    deterministic_health_override: false,
    findings: [
      {
        citations: [
          {
            evidence_id: "evidence:denied-receipt",
            evidence_kind: "receipt",
            source_sha256: "5".repeat(64),
          },
          {
            evidence_id: "evidence:epoch-transition",
            evidence_kind: "timeline",
            source_sha256: "6".repeat(64),
          },
        ],
        statement: "The work epoch preceded the current authority epoch.",
      },
    ],
    manual_review_reason: null,
    operator_review_required: true,
    recommendation_id: "advisor-recommendation-1",
    requested_operator_action: "request_new_operator_approved_rollout",
    root_id: command.rootId,
    schema_version: "controlgraph.advisor-recommendation/v1",
    snapshot_sha256: snapshotSha256,
    target: command.expectedTarget,
    uncertainties: ["No unstated provider state was inferred."],
  };
  const interactionId = "advisor-interaction-1";
  return canonicalJson({
    command_sha256: await canonicalSha256(
      "controlgraph.advisor-operator-command/v1",
      advisorCommandWire(command),
    ),
    epoch: command.expectedEpoch,
    interaction_id: interactionId,
    replayed: false,
    response: {
      audit: {
        cited_evidence_ids: ["evidence:denied-receipt", "evidence:epoch-transition"],
        correlation_id: command.requestId,
        fallback_code: null,
        interaction_id: interactionId,
        model_id: "gemini-3.5-flash",
        model_location: "global",
        operator_disposition: "pending_review",
        prompt_version: "controlgraph.rollout-advisor-prompt/v2",
        registry_sha256: "7".repeat(64),
        schema_version: "controlgraph.advisor-interaction-audit/v1",
        snapshot_sha256: snapshotSha256,
        structured_output_sha256: await canonicalSha256(
          "controlgraph.advisor-recommendation/v1",
          recommendation,
        ),
        tool_calls: [
          "read_root_summary",
          "read_target_summary",
          "read_health_summary",
          "read_receipt_summary",
          "read_timeline_summary",
          "read_verifier_summary",
        ].map((toolId, index) => ({
          input_sha256: (index + 10).toString(16).repeat(64).slice(0, 64),
          output_sha256: (index + 20).toString(16).repeat(64).slice(0, 64),
          schema_version: "controlgraph.advisor-tool-call-audit/v1",
          sequence: index + 1,
          status: "succeeded",
          tool_id: toolId,
        })),
        validation: {
          accepted: true,
          codes: ["accepted"],
          schema_version: "controlgraph.advisor-validation/v1",
        },
      },
      manual_next_step:
        "review_named_evidence_and_use_deterministic_operator_commands_only",
      recommendation,
      request_sha256: "8".repeat(64),
      schema_version: "controlgraph.advisor-response/v1",
    },
    root_id: command.rootId,
    root_sha256: command.rootSha256,
    schema_version: "controlgraph.advisor-operator-result/v1",
    target: command.expectedTarget,
  });
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

  it("sends the bounded advisor command and verifies its model, tool, and citation bindings", async () => {
    const provider = new CredentialProvider(credential());
    const command = advisorCommand();
    const fetcher = vi.fn(async () =>
      new Response(await advisorBody(command), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const api = new FetchOperatorApi(provider, "https://console.example", fetcher);

    const result = await api.advise(command);

    expect(result.response.recommendation?.findings[0]?.citations).toHaveLength(2);
    expect(result.response.audit).toMatchObject({
      model_id: "gemini-3.5-flash",
      prompt_version: "controlgraph.rollout-advisor-prompt/v2",
      fallback_code: null,
      validation: { accepted: true, codes: ["accepted"] },
    });
    expect(result.response.audit.tool_calls).toHaveLength(6);
    expect(provider.calls).toEqual([true]);
    const [url, init] = vi.mocked(fetcher).mock.calls[0]!;
    expect(String(url)).toBe("https://console.example/v1/operator/commands");
    expect(JSON.parse(String(init?.body))).toEqual(advisorCommandWire(command));
    const headers = new Headers(init?.headers);
    expect(headers.get("X-ControlGraph-CSRF")).toBe(provider.credential.csrfToken);
    expect(headers.get("X-ControlGraph-Authorization")).toBe(
      `Bearer ${provider.credential.idToken}`,
    );
  });

  it("rejects an advisor audit correlated to a different operator request", async () => {
    const provider = new CredentialProvider(credential());
    const command = advisorCommand();
    const body = JSON.parse(await advisorBody(command)) as Record<string, unknown>;
    const response = body.response as Record<string, unknown>;
    const audit = response.audit as Record<string, unknown>;
    audit.correlation_id = "console-advisor-substituted-request";
    const fetcher = vi.fn(async () =>
      new Response(canonicalJson(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const api = new FetchOperatorApi(provider, "https://console.example", fetcher);

    await expect(api.advise(command)).rejects.toEqual(
      new OperatorApiError("RESPONSE_INVALID", "ADVISOR_RESPONSE_INVALID"),
    );
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
