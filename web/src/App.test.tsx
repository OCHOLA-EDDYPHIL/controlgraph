import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import {
  OperatorApiError,
  type AdvisorCommand,
  type OperatorApi,
  type OperatorIdentity,
  type RevocationCommand,
  type RevocationResult,
} from "./api/operator";
import type { AdvisorOperatorResult } from "./contracts/modelAssistance";
import type { TimelinePage, TimelineQuery } from "./contracts/timeline";
import {
  ROOT_ID,
  ROOT_SHA256,
  field,
  timelineEntry,
  timelinePage,
} from "./test/timelineFixtures";

const IDENTITY: OperatorIdentity = {
  principal: "operator@example.com",
  subject: "123456789012345678901",
  expiresAtEpochSeconds: 9_000_000_000,
};

class FakeOperatorApi implements OperatorApi {
  entries = [timelineEntry(1, "AUTHORITY_ROOT_CREATED")];
  pageSize = 25;
  authenticateError: unknown = null;
  nextReadError: unknown = null;
  revokeError: unknown = null;
  adviseError: unknown = null;
  nextPageTransform: ((page: TimelinePage) => TimelinePage) | null = null;
  readonly queries: TimelineQuery[] = [];
  readonly authenticationFreshness: boolean[] = [];
  readonly revocations: RevocationCommand[] = [];
  readonly advisorCommands: AdvisorCommand[] = [];

  async authenticate(options?: { readonly fresh?: boolean }): Promise<OperatorIdentity> {
    this.authenticationFreshness.push(options?.fresh ?? false);
    if (this.authenticateError !== null) {
      throw this.authenticateError;
    }
    return IDENTITY;
  }

  async readTimeline(query: TimelineQuery): Promise<ReturnType<typeof timelinePage>> {
    this.queries.push(query);
    if (this.nextReadError !== null) {
      const error = this.nextReadError;
      this.nextReadError = null;
      throw error;
    }
    const expectedDigest =
      query.afterSequence === 0
        ? null
        : this.entries[query.afterSequence - 1]?.entrySha256 ?? null;
    if (expectedDigest !== query.afterEntrySha256) {
      throw new OperatorApiError("CURSOR_INVALID", "TIMELINE_READ_CURSOR_INVALID");
    }
    const page = timelinePage(this.entries, query.afterSequence, this.pageSize);
    if (this.nextPageTransform === null) {
      return page;
    }
    const transform = this.nextPageTransform;
    this.nextPageTransform = null;
    return transform(page);
  }

  async revoke(command: RevocationCommand): Promise<RevocationResult> {
    this.revocations.push(command);
    if (this.revokeError !== null) {
      throw this.revokeError;
    }
    return {
      resultId: `cgrevoke:${"c".repeat(64)}`,
      previousEpoch: command.expectedEpoch,
      newEpoch: command.expectedEpoch + 1,
      evidenceId: "evidence:revocation-1",
      evidenceSha256: "d".repeat(64),
      committedAt: "2026-08-21T12:30:00Z",
    };
  }

  async advise(command: AdvisorCommand): Promise<AdvisorOperatorResult> {
    this.advisorCommands.push(command);
    if (this.adviseError !== null) {
      throw this.adviseError;
    }
    return advisorResult(command);
  }
}

function advisorResult(command: AdvisorCommand): AdvisorOperatorResult {
  const snapshotSha256 = "7".repeat(64);
  const recommendation = {
    schema_version: "controlgraph.advisor-recommendation/v1" as const,
    recommendation_id: "advisor-recommendation-1",
    snapshot_sha256: snapshotSha256,
    target: command.expectedTarget,
    root_id: command.rootId,
    current_epoch: command.expectedEpoch,
    findings: [
      {
        statement: "The denied work was bound to the preceding authority epoch.",
        citations: [
          {
            evidence_kind: "receipt" as const,
            evidence_id: "evidence:denied-receipt",
            source_sha256: "8".repeat(64),
          },
          {
            evidence_kind: "timeline" as const,
            evidence_id: "evidence:epoch-transition",
            source_sha256: "9".repeat(64),
          },
          {
            evidence_kind: "target" as const,
            evidence_id: "evidence:unchanged-target",
            source_sha256: "6".repeat(64),
          },
        ],
      },
    ],
    assumptions: [],
    uncertainties: ["No cause beyond the named evidence was inferred."],
    confidence_basis_points: 9_200,
    requested_operator_action: "request_captured_stable_recovery" as const,
    manual_review_reason: null,
    operator_review_required: true as const,
    authority_effect: "none" as const,
    deterministic_health_override: false as const,
  };
  return {
    schema_version: "controlgraph.advisor-operator-result/v1",
    command_sha256: "1".repeat(64),
    interaction_id: "advisor-interaction-1",
    target: command.expectedTarget,
    root_id: command.rootId,
    root_sha256: command.rootSha256,
    epoch: command.expectedEpoch,
    replayed: false,
    response: {
      schema_version: "controlgraph.advisor-response/v1",
      request_sha256: "2".repeat(64),
      recommendation,
      manual_next_step:
        "review_named_evidence_and_use_deterministic_operator_commands_only",
      audit: {
        schema_version: "controlgraph.advisor-interaction-audit/v1",
        interaction_id: "advisor-interaction-1",
        correlation_id: command.requestId,
        model_id: "gemini-3.5-flash",
        model_location: "global",
        prompt_version: "controlgraph.rollout-advisor-prompt/v2",
        registry_sha256: "3".repeat(64),
        snapshot_sha256: snapshotSha256,
        tool_calls: [
          "read_root_summary",
          "read_target_summary",
          "read_health_summary",
          "read_receipt_summary",
          "read_timeline_summary",
          "read_verifier_summary",
        ].map((toolId, index) => ({
          schema_version: "controlgraph.advisor-tool-call-audit/v1" as const,
          sequence: index + 1,
          tool_id: toolId as
            | "read_root_summary"
            | "read_target_summary"
            | "read_health_summary"
            | "read_receipt_summary"
            | "read_timeline_summary"
            | "read_verifier_summary",
          input_sha256: (index + 10).toString(16).repeat(64).slice(0, 64),
          output_sha256: (index + 20).toString(16).repeat(64).slice(0, 64),
          status: "succeeded" as const,
        })),
        cited_evidence_ids: [
          "evidence:denied-receipt",
          "evidence:epoch-transition",
          "evidence:unchanged-target",
        ],
        structured_output_sha256: "4".repeat(64),
        validation: {
          schema_version: "controlgraph.advisor-validation/v1",
          accepted: true,
          codes: ["accepted"],
        },
        operator_disposition: "pending_review",
        fallback_code: null,
      },
    },
  };
}

function staleDenialTimeline(denialOccurredAt: string) {
  const revocationCorrelations = [
    { kind: "EVIDENCE" as const, correlationId: "evidence:revocation-1" },
    { kind: "REQUEST" as const, correlationId: "request:revocation-1" },
  ];
  return [
    timelineEntry(1, "AUTHORITY_ROOT_CREATED", { epoch: 1 }),
    timelineEntry(2, "AUTHORITY_EPOCH_ADVANCED", {
      epoch: 2,
      occurredAt: denialOccurredAt,
      actorRole: "OPERATOR",
      correlations: revocationCorrelations,
      verificationStatus: "VERIFIED",
    }),
    timelineEntry(3, "OPERATOR_ACTION_RECORDED", {
      epoch: 2,
      occurredAt: denialOccurredAt,
      actorRole: "OPERATOR",
      correlations: revocationCorrelations,
      fields: [field("ACTION", "REVOKE_EPOCH")],
      signature: null,
      verificationStatus: "NOT_APPLICABLE",
    }),
    timelineEntry(4, "MUTATION_DENIED", {
      epoch: 1,
      occurredAt: denialOccurredAt,
      fields: [
        field("OUTCOME", "DENIED"),
        field("REASON_CODE", "EPOCH_MISMATCH"),
      ],
    }),
  ];
}

function completeTimeline() {
  return [
    timelineEntry(1, "AUTHORITY_ROOT_CREATED", {
      fields: [field("SUMMARY", "Root admitted for the reference target")],
    }),
    timelineEntry(2, "MUTATION_APPLIED", {
      fields: [field("ACTION", "APPLY_CANARY"), field("STATE", "90/10")],
    }),
    timelineEntry(3, "HEALTH_OBSERVED", {
      fields: [field("OBSERVATION", "100 candidate requests"), field("WINDOW", "1 of 2")],
    }),
    timelineEntry(4, "HEALTH_DECIDED", {
      fields: [field("STATE", "HEALTHY")],
    }),
    timelineEntry(5, "MUTATION_APPLIED", {
      fields: [field("ACTION", "PROMOTE_CANDIDATE")],
    }),
    timelineEntry(6, "RECOVERY_INTENT_CREATED", {
      fields: [field("SUMMARY", "One stable-only recovery intent")],
    }),
    timelineEntry(7, "RECOVERY_APPLIED", {
      fields: [field("OUTCOME", "Captured stable at 100%")],
    }),
    timelineEntry(8, "VERIFICATION_RECORDED", {
      fields: [field("SUMMARY", "Configuration and probe agree")],
      verificationStatus: "VERIFIED",
    }),
    timelineEntry(9, "MUTATION_DENIED", {
      fields: [field("REASON_CODE", "EPOCH_STALE")],
    }),
    timelineEntry(10, "MUTATION_AMBIGUOUS", {
      fields: [field("NEXT_ACTION", "Independent readback required")],
      verificationStatus: "AMBIGUOUS",
    }),
    timelineEntry(11, "MODEL_ASSISTANCE_RECORDED", {
      fields: [field("SUMMARY", "Review the contradictory observations")],
    }),
    timelineEntry(12, "TERMINAL_CLASSIFIED", {
      fields: [field("OUTCOME", "AMBIGUOUS")],
      verificationStatus: "AMBIGUOUS",
      terminalClassification: "AMBIGUOUS",
    }),
  ];
}

describe("operator console", () => {
  it("offers a fresh stale-epoch investigation and renders validated Gemini citations", async () => {
    const api = new FakeOperatorApi();
    const occurredAt = new Date(Math.floor(Date.now() / 1_000) * 1_000)
      .toISOString()
      .replace(".000Z", "Z");
    api.entries = staleDenialTimeline(occurredAt);
    render(<App api={api} pollIntervalMs={0} />);

    expect(await screen.findByText("DENIED · EPOCH_MISMATCH")).toBeTruthy();
    expect(screen.getByText(/Work bound to epoch 1 reached authority at epoch 2/)).toBeTruthy();
    fireEvent.click(
      screen.getByRole("button", { name: "Analyze current rollout evidence" }),
    );

    expect(
      await screen.findByRole("article", { name: "Validated Gemini evidence analysis" }),
    ).toBeTruthy();
    expect(
      screen.getByText("The denied work was bound to the preceding authority epoch."),
    ).toBeTruthy();
    expect(screen.getByText("evidence:denied-receipt")).toBeTruthy();
    expect(screen.getByText("gemini-3.5-flash")).toBeTruthy();
    expect(screen.getByText("controlgraph.rollout-advisor-prompt/v2")).toBeTruthy();
    expect(screen.getByText(/Authority effect:/).textContent).toContain("none");
    expect(api.advisorCommands).toHaveLength(1);
    expect(api.advisorCommands[0]).toMatchObject({
      rootId: ROOT_ID,
      rootSha256: ROOT_SHA256,
      expectedEpoch: 2,
    });
    expect(api.advisorCommands[0]?.requestId).toMatch(/^console-advisor-/);
    expect(api.advisorCommands[0]?.requestedAt).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/,
    );
    expect(api.advisorCommands[0]?.idempotencyKey).toBe(
      api.advisorCommands[0]?.requestId,
    );
  });

  it("does not offer model analysis for stale or non-epoch denial evidence", async () => {
    const api = new FakeOperatorApi();
    const occurredAt = new Date(Date.now() - 241_000)
      .toISOString()
      .replace(/\.\d{3}Z$/, "Z");
    api.entries = staleDenialTimeline(occurredAt);
    render(<App api={api} pollIntervalMs={0} />);

    await screen.findByText("operator@example.com");
    expect(
      screen.queryByRole("button", { name: "Analyze current rollout evidence" }),
    ).toBeNull();
    expect(api.advisorCommands).toHaveLength(0);
  });

  it("does not offer analysis when the verified revocation transition follows the denial", async () => {
    const api = new FakeOperatorApi();
    const occurredAt = new Date(Math.floor(Date.now() / 1_000) * 1_000)
      .toISOString()
      .replace(".000Z", "Z");
    const revocationCorrelations = [
      { kind: "EVIDENCE" as const, correlationId: "evidence:revocation-1" },
      { kind: "REQUEST" as const, correlationId: "request:revocation-1" },
    ];
    api.entries = [
      timelineEntry(1, "AUTHORITY_ROOT_CREATED", { epoch: 1 }),
      timelineEntry(2, "MUTATION_DENIED", {
        epoch: 1,
        occurredAt,
        fields: [
          field("OUTCOME", "DENIED"),
          field("REASON_CODE", "EPOCH_MISMATCH"),
        ],
      }),
      timelineEntry(3, "AUTHORITY_EPOCH_ADVANCED", {
        epoch: 2,
        occurredAt,
        actorRole: "OPERATOR",
        correlations: revocationCorrelations,
        verificationStatus: "VERIFIED",
      }),
      timelineEntry(4, "OPERATOR_ACTION_RECORDED", {
        epoch: 2,
        occurredAt,
        actorRole: "OPERATOR",
        correlations: revocationCorrelations,
        fields: [field("ACTION", "REVOKE_EPOCH")],
        signature: null,
        verificationStatus: "NOT_APPLICABLE",
      }),
    ];
    render(<App api={api} pollIntervalMs={0} />);

    await screen.findByText("operator@example.com");
    expect(
      screen.queryByRole("button", { name: "Analyze current rollout evidence" }),
    ).toBeNull();
  });

  it("does not treat an uncorrelated operator action as proof of revocation", async () => {
    const api = new FakeOperatorApi();
    const occurredAt = new Date(Math.floor(Date.now() / 1_000) * 1_000)
      .toISOString()
      .replace(".000Z", "Z");
    api.entries = staleDenialTimeline(occurredAt).map((entry) =>
      entry.eventType === "OPERATOR_ACTION_RECORDED"
        ? {
            ...entry,
            correlations: [
              { kind: "EVIDENCE" as const, correlationId: "evidence:different" },
              { kind: "REQUEST" as const, correlationId: "request:different" },
            ],
          }
        : entry,
    );
    render(<App api={api} pollIntervalMs={0} />);

    await screen.findByText("operator@example.com");
    expect(
      screen.queryByRole("button", { name: "Analyze current rollout evidence" }),
    ).toBeNull();
  });

  it("hides completed advice when the timeline head advances with a new mutation", async () => {
    const api = new FakeOperatorApi();
    const occurredAt = new Date(Math.floor(Date.now() / 1_000) * 1_000)
      .toISOString()
      .replace(".000Z", "Z");
    api.entries = staleDenialTimeline(occurredAt);
    render(<App api={api} pollIntervalMs={15} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Analyze current rollout evidence" }),
    );
    expect(
      await screen.findByRole("article", { name: "Validated Gemini evidence analysis" }),
    ).toBeTruthy();

    api.entries = [
      ...api.entries,
      timelineEntry(5, "MUTATION_APPLIED", {
        epoch: 2,
        occurredAt,
        fields: [field("OUTCOME", "APPLIED")],
      }),
    ];

    expect(
      await screen.findByText(
        "The authority or latest mutation receipt changed. The prior analysis was hidden.",
      ),
    ).toBeTruthy();
    expect(
      screen.queryByRole("article", { name: "Validated Gemini evidence analysis" }),
    ).toBeNull();
  });

  it("renders every rollout and evidence state from omission-free pages", async () => {
    const api = new FakeOperatorApi();
    api.entries = completeTimeline();
    api.pageSize = 4;
    render(<App api={api} pollIntervalMs={0} />);

    expect(
      await screen.findByRole("heading", { name: "Authority you can inspect." }),
    ).toBeTruthy();
    expect(await screen.findByText("operator@example.com")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "controlgraph-reference-target" })).toBeTruthy();
    expect(screen.getAllByText("Epoch 1").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "90/10 canary applied" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Health policy: healthy" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Candidate promoted" })).toBeTruthy();
    expect(
      screen.getByRole("heading", { name: "Captured stable revision restored" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("heading", { name: "Independent verification matched" }),
    ).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Stale authority denied" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Mutation outcome ambiguous" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Model advisory recorded" })).toBeTruthy();
    expect(screen.getByText(/Advisory only\. This event cannot authorize/)).toBeTruthy();
    expect(screen.getByText(/Partial or contradictory evidence is present/)).toBeTruthy();
    expect(api.queries.map((query) => query.afterSequence)).toEqual([0, 4, 8]);
    expect(api.queries[1]?.afterEntrySha256).toBe(api.entries[3]?.entrySha256);
  });

  it("requires fresh root and epoch review, a typed reason, and explicit confirmation", async () => {
    const api = new FakeOperatorApi();
    render(<App api={api} pollIntervalMs={0} />);
    await screen.findByText("operator@example.com");

    fireEvent.click(screen.getByRole("button", { name: "Review revocation" }));
    const dialog = await screen.findByRole("dialog", { name: "Review epoch revocation" });
    expect(dialog.textContent).toContain(ROOT_ID);
    expect(dialog.textContent).toContain("1 → 2");
    const submit = screen.getByRole("button", { name: "Revoke epoch 1" });
    expect((submit as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByLabelText("Reason for revocation"), {
      target: { value: "Operator observed unexpected rollout drift" },
    });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(
      screen.getByLabelText(/I reviewed root .* and confirm revocation of expected epoch 1/),
    );
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(submit);

    expect(await screen.findByText("Authority revoked at epoch 2")).toBeTruthy();
    expect(screen.getByText("evidence:revocation-1")).toBeTruthy();
    expect(api.revocations).toHaveLength(1);
    expect(api.revocations[0]).toMatchObject({
      rootId: ROOT_ID,
      rootSha256: ROOT_SHA256,
      expectedEpoch: 1,
      reason: "Operator observed unexpected rollout drift",
    });
    expect(api.revocations[0]?.requestId).toMatch(/^console-revoke-/);
    expect(api.revocations[0]?.requestId).toBe(api.revocations[0]?.idempotencyKey);
    expect(api.authenticationFreshness.filter(Boolean)).toHaveLength(2);
  });

  it("blocks a reviewed revocation when the epoch changes before submission", async () => {
    const api = new FakeOperatorApi();
    render(<App api={api} pollIntervalMs={0} />);
    await screen.findByText("operator@example.com");
    fireEvent.click(screen.getByRole("button", { name: "Review revocation" }));
    await screen.findByRole("dialog", { name: "Review epoch revocation" });
    fireEvent.change(screen.getByLabelText("Reason for revocation"), {
      target: { value: "Operator revocation after safety review" },
    });
    fireEvent.click(screen.getByLabelText(/I reviewed root/));

    api.entries = [
      ...api.entries,
      timelineEntry(2, "AUTHORITY_EPOCH_ADVANCED", {
        epoch: 2,
        fields: [field("SUMMARY", "A different request advanced authority")],
      }),
    ];
    fireEvent.click(screen.getByRole("button", { name: "Revoke epoch 1" }));

    expect(await screen.findByText("Revocation review expired")).toBeTruthy();
    expect(screen.getByText(/No stale command was sent/)).toBeTruthy();
    expect(api.revocations).toHaveLength(0);
  });

  it("keeps an unknown mutation outcome explicit and never offers a blind retry", async () => {
    const api = new FakeOperatorApi();
    api.revokeError = new OperatorApiError("UNAVAILABLE", "REVOCATION_OUTCOME_UNKNOWN");
    render(<App api={api} pollIntervalMs={0} />);
    await screen.findByText("operator@example.com");
    fireEvent.click(screen.getByRole("button", { name: "Review revocation" }));
    await screen.findByRole("dialog");
    fireEvent.change(screen.getByLabelText("Reason for revocation"), {
      target: { value: "Operator cannot establish safe rollout state" },
    });
    fireEvent.click(screen.getByLabelText(/I reviewed root/));
    fireEvent.click(screen.getByRole("button", { name: "Revoke epoch 1" }));

    expect(await screen.findByText("Revocation outcome is unknown")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Check timeline" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Revoke epoch/ })).toBeNull();
    expect(
      (screen.getByRole("button", { name: "Review revocation" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(api.revocations).toHaveLength(1);

    const requestId = api.revocations[0]!.requestId;
    api.entries = [
      ...api.entries,
      timelineEntry(2, "AUTHORITY_EPOCH_ADVANCED", { epoch: 2 }),
      timelineEntry(3, "OPERATOR_ACTION_RECORDED", {
        epoch: 2,
        fields: [field("ACTION", "REVOKE_EPOCH")],
        correlations: [
          { kind: "EVIDENCE", correlationId: "evidence:confirmed-revocation" },
          { kind: "REQUEST", correlationId: requestId },
        ],
      }),
    ];
    fireEvent.click(screen.getByRole("button", { name: "Check timeline" }));

    expect(await screen.findByText("Revocation confirmed by timeline at epoch 2")).toBeTruthy();
    expect(screen.getByText("evidence:confirmed-revocation")).toBeTruthy();
  });

  it("traps dialog focus, closes on Escape, and restores the review trigger", async () => {
    const api = new FakeOperatorApi();
    render(<App api={api} pollIntervalMs={0} />);
    await screen.findByText("operator@example.com");
    const trigger = screen.getByRole("button", { name: "Review revocation" });
    fireEvent.click(trigger);
    const dialog = await screen.findByRole("dialog", { name: "Review epoch revocation" });

    fireEvent.keyDown(dialog, { key: "Escape" });

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.activeElement).toBe(trigger);
  });

  it("continues reconnect from the last cursor without replacing admitted events", async () => {
    const api = new FakeOperatorApi();
    render(<App api={api} pollIntervalMs={15} />);
    await screen.findByText("operator@example.com");
    api.nextReadError = new OperatorApiError("UNAVAILABLE");

    expect(await screen.findByText(/Connection interrupted/)).toBeTruthy();
    const previousHead = api.entries.at(-1)!;
    api.entries = [
      ...api.entries,
      timelineEntry(2, "HEALTH_OBSERVED", {
        fields: [field("WINDOW", "1 of 2")],
      }),
    ];
    const reconnectQueryIndex = api.queries.length;
    fireEvent.click(screen.getByRole("button", { name: "Reconnect" }));

    expect(await screen.findByRole("heading", { name: "Health window 1 of 2" })).toBeTruthy();
    expect(api.queries[reconnectQueryIndex]).toMatchObject({
      afterSequence: 1,
      afterEntrySha256: previousHead.entrySha256,
    });
    expect(screen.getAllByRole("heading", { name: "Rollout root established" })).toHaveLength(1);
  });

  it("fails closed for a denied operator and exposes no mutation surface", async () => {
    const api = new FakeOperatorApi();
    api.authenticateError = new OperatorApiError("ACCESS_DENIED", "AUTH_CALLER_DENIED");
    render(<App api={api} pollIntervalMs={0} />);

    expect(await screen.findByText(/Access denied/)).toBeTruthy();
    expect(screen.getByText("AUTH_CALLER_DENIED")).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Review revocation" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(screen.queryByText(/Deploy|Delete|Scale service/)).toBeNull();
  });

  it("makes an initial operator API failure explicit", async () => {
    const api = new FakeOperatorApi();
    api.nextReadError = new OperatorApiError("UNAVAILABLE");
    render(<App api={api} pollIntervalMs={0} />);

    expect(await screen.findByText(/operator API is unavailable/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reload timeline" })).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Review revocation" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it("renders untrusted timeline text as text rather than markup", async () => {
    const api = new FakeOperatorApi();
    api.entries = [
      timelineEntry(1, "AUTHORITY_ROOT_CREATED", {
        fields: [field("SUMMARY", '<img src=x onerror="globalThis.compromised=true">')],
      }),
    ];
    render(<App api={api} pollIntervalMs={0} />);

    expect((await screen.findAllByText(/<img src=x onerror=/)).length).toBeGreaterThan(0);
    expect(document.querySelector("img")).toBeNull();
    expect((globalThis as typeof globalThis & { compromised?: boolean }).compromised).toBeUndefined();
  });

  it("requires manual reload when the server rejects a cursor", async () => {
    const api = new FakeOperatorApi();
    render(<App api={api} pollIntervalMs={15} />);
    await screen.findByText("operator@example.com");
    api.nextReadError = new OperatorApiError(
      "CURSOR_INVALID",
      "TIMELINE_READ_CURSOR_INVALID",
    );

    expect(await screen.findByText(/This view is stale/)).toBeTruthy();
    expect(screen.getByText("TIMELINE_READ_CURSOR_INVALID")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reload timeline" }));
    await waitFor(() => expect(screen.queryByText(/This view is stale/)).toBeNull());
    expect(api.queries.at(-1)?.afterSequence).toBe(0);
  });

  it("rejects a regressed timeline head instead of replacing admitted evidence", async () => {
    const api = new FakeOperatorApi();
    render(<App api={api} pollIntervalMs={15} />);
    await screen.findByText("operator@example.com");
    api.nextPageTransform = (page) => ({
      ...page,
      head: { afterSequence: 0, afterEntrySha256: null },
    });

    expect(await screen.findByText(/Timeline evidence is partial/)).toBeTruthy();
    expect(screen.getByText("TIMELINE_HEAD_REGRESSED")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Rollout root established" })).toBeTruthy();
  });
});
