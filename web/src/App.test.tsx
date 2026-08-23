import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import {
  OperatorApiError,
  type OperatorApi,
  type OperatorIdentity,
  type RevocationCommand,
  type RevocationResult,
} from "./api/operator";
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
  nextPageTransform: ((page: TimelinePage) => TimelinePage) | null = null;
  readonly queries: TimelineQuery[] = [];
  readonly authenticationFreshness: boolean[] = [];
  readonly revocations: RevocationCommand[] = [];

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
