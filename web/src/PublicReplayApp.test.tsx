import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  PublicReplayEnvelope,
  PublicReplayEventEnvelope,
  PublicReplayEventKind,
} from "./contracts/publicReplay";

const loadPublicReplayMock = vi.hoisted(() => vi.fn());

vi.mock("./contracts/publicReplay", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./contracts/publicReplay")>()),
  loadPublicReplay: loadPublicReplayMock,
}));

import { PublicReplayApp } from "./PublicReplayApp";

const REPLAY_SHA256 = "f".repeat(64);
const FINDING = "Stale work was denied and the target remained unchanged.";
const CASE_KINDS = [
  "TARGET_RESET",
  "HEALTHY_PROMOTION",
  "UNHEALTHY_STABLE_RECOVERY",
  "REVOCATION_STALE_DENIAL",
  "INDEPENDENT_VERIFIER_PROBE",
  "AMBIGUITY_CLASSIFICATION",
  "TIMELINE_CONSOLE_READ",
  "BOUNDED_ADVISOR",
] as const;
const IMAGE_COMPONENTS = [
  "controller",
  "advisor",
  "console",
  "reference-stable",
  "reference-candidate",
] as const;
const TOOL_IDS = [
  "read_root_summary",
  "read_target_summary",
  "read_health_summary",
  "read_receipt_summary",
  "read_timeline_summary",
  "read_verifier_summary",
] as const;

function digest(value: number): string {
  return value.toString(16).padStart(64, "0");
}

function eventDigest(sequence: number): string {
  return sequence.toString(16).padStart(2, "0").repeat(32);
}

function replayEvent(
  kind: PublicReplayEventKind,
  sequence: number,
  details: Record<string, unknown>,
): PublicReplayEventEnvelope {
  return {
    schema_version: "controlgraph.public-replay-event-envelope/v1",
    event_sha256: eventDigest(sequence),
    event: {
      schema_version: "controlgraph.public-replay-event/v1",
      sequence,
      kind,
      occurred_at: `2026-08-24T00:00:0${sequence - 1}Z`,
      previous_event_sha256: sequence === 1 ? null : eventDigest(sequence - 1),
      details,
    },
  };
}

function validReplay(): PublicReplayEnvelope {
  const canary = {
    candidate_percent: 10,
    schema_version: "controlgraph.public-replay-traffic/v1",
    stable_percent: 90,
    target_configuration_sha256: digest(80),
  };
  const timelineEventTypes = [
    "AUTHORITY_EPOCH_ADVANCED",
    "MUTATION_APPLIED",
    "MUTATION_DENIED",
    "MODEL_ASSISTANCE_RECORDED",
  ] as const;
  return {
    schema_version: "controlgraph.public-replay-envelope/v1",
    payload_sha256: REPLAY_SHA256,
    payload: {
      schema_version: "controlgraph.public-replay-payload/v1",
      source_commit: "a".repeat(40),
      acceptance_manifest_sha256: digest(120),
      acceptance_run_id: `cgacceptance:${digest(121)}`,
      acceptance_status: "PASSED",
      evidence_binding_complete: true,
      accepted_at: "2026-08-24T00:00:06Z",
      images: IMAGE_COMPONENTS.map((component, index) => ({
        schema_version: "controlgraph.public-replay-image/v1" as const,
        component,
        reference: (
          "us-central1-docker.pkg.dev/controlgraph-canary-abc123/" +
          `controlgraph-canary/${component}@sha256:${digest(90 + index)}`
        ),
      })),
      cases: CASE_KINDS.map((kind, index) => ({
        schema_version: "controlgraph.public-replay-case/v1" as const,
        sequence: index + 1,
        kind,
        case_sha256: digest(100 + index),
      })),
      events: [
        replayEvent("AUTHORITY_ADVANCED", 1, {
          schema_version: "controlgraph.public-replay-authority-advanced/v1",
          previous_epoch: 7,
          new_epoch: 8,
          cause: "OPERATOR_REVOCATION",
          transition_sha256: digest(81),
        }),
        replayEvent("STALE_WORK_DENIED", 2, {
          schema_version: "controlgraph.public-replay-stale-denial/v1",
          work_epoch: 7,
          current_authority_epoch: 8,
          outcome: "DENIED",
          reason_code: "EPOCH_MISMATCH",
          receipt_sha256: digest(82),
        }),
        replayEvent("TARGET_UNCHANGED", 3, {
          schema_version: "controlgraph.public-replay-target-unchanged/v1",
          before_denial: canary,
          after_denial: canary,
        }),
        replayEvent("ADVISOR_VALIDATED", 4, {
          schema_version: "controlgraph.public-replay-advisor-validated/v1",
          advisor: {
            schema_version: "controlgraph.public-replay-advisor/v1",
            model_id: "gemini-3.5-flash",
            model_location: "global",
            prompt_version: "controlgraph.rollout-advisor-prompt/v2",
            response_sha256: digest(30),
            audit_sha256: digest(31),
            registry_sha256: digest(32),
            snapshot_sha256: digest(33),
            structured_output_sha256: digest(34),
            validation: "accepted",
            authority_effect: "none",
            deterministic_health_override: false,
            operator_review_required: true,
            requested_operator_action: "manual_review",
            confidence_basis_points: 8400,
            findings: [
              {
                schema_version: "controlgraph.public-replay-finding/v1",
                statement: FINDING,
                citations: ["receipt", "timeline", "target"].map((evidenceKind, index) => ({
                  schema_version: "controlgraph.public-replay-citation/v1",
                  evidence_kind: evidenceKind,
                  evidence_id: `evidence-${evidenceKind}`,
                  source_sha256: digest(20 + index),
                })),
              },
            ],
            tool_calls: TOOL_IDS.map((toolId, index) => ({
              schema_version: "controlgraph.public-replay-tool-call/v1",
              sequence: index + 1,
              tool_id: toolId,
              input_sha256: digest(40 + index),
              output_sha256: digest(50 + index),
              status: "succeeded",
            })),
            replayed_without_model_call: true,
          },
        }),
        replayEvent("RECOVERY_VERIFIED", 5, {
          schema_version: "controlgraph.public-replay-recovery-verified/v1",
          outcome: "VERIFIED",
          receipt_sha256: digest(83),
          traffic: {
            candidate_percent: 0,
            schema_version: "controlgraph.public-replay-traffic/v1",
            stable_percent: 100,
            target_configuration_sha256: digest(84),
          },
        }),
        replayEvent("TIMELINE_COMMITTED", 6, {
          schema_version: "controlgraph.public-replay-timeline-committed/v1",
          timeline: {
            schema_version: "controlgraph.public-replay-timeline/v1",
            entries: timelineEventTypes.map((eventType, index) => ({
              schema_version: "controlgraph.public-replay-timeline-entry/v1",
              sequence: 21 + index,
              entry_sha256: digest(60 + index),
              event_type: eventType,
              occurred_at: `2026-08-24T00:00:0${index}Z`,
              verification_status: eventType === "MUTATION_APPLIED" ? "VERIFIED" : "NOT_APPLICABLE",
            })),
            entry_count: 24,
            head_entry_sha256: digest(63),
            head_sequence: 24,
            page_count: 3,
            page_set_sha256: digest(70),
          },
        }),
      ],
      event_chain_head_sha256: eventDigest(6),
    },
  };
}

function configureLoader(result: PublicReplayEnvelope | null | Error): void {
  loadPublicReplayMock.mockImplementation(async () => {
    const config = window.controlGraphPublicReplayConfig;
    if (config?.available !== true) {
      return null;
    }
    await fetch(`/replays/${config.sha256}.json`, {
      credentials: "omit",
      headers: { Accept: "application/json" },
    });
    if (result instanceof Error) {
      throw result;
    }
    return result;
  });
}

describe("PublicReplayApp", () => {
  beforeEach(() => {
    loadPublicReplayMock.mockReset();
    window.controlGraphPublicReplayConfig = { available: false, sha256: null };
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    delete window.controlGraphPublicReplayConfig;
  });

  it("announces verification while the replay is loading", () => {
    loadPublicReplayMock.mockReturnValue(new Promise(() => undefined));

    const { container } = render(<PublicReplayApp />);

    expect(screen.getByRole("status").textContent).toContain("Verifying public replay");
    expect(screen.getByText(/before showing evidence/)).toBeTruthy();
    expect(container.querySelector("main")?.getAttribute("aria-busy")).toBe("true");
  });

  it("renders the unavailable state without requesting an artifact", async () => {
    configureLoader(null);

    render(<PublicReplayApp />);

    expect(await screen.findByRole("heading", { name: "No public replay available" }))
      .toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain(
      "No accepted replay is currently published",
    );
    expect(screen.getByRole("link", { name: "Check again" }).getAttribute("href"))
      .toBe("/replay");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("uses neutral fail-closed copy when the configured replay cannot be loaded", async () => {
    window.controlGraphPublicReplayConfig = { available: true, sha256: REPLAY_SHA256 };
    vi.mocked(fetch).mockRejectedValue(new Error("synthetic replay failure"));
    configureLoader(new Error("invalid replay"));

    render(<PublicReplayApp />);

    expect((await screen.findByRole("alert")).textContent).toContain(
      "Replay could not be verified",
    );
    expect(screen.getByText(/could not be loaded and verified, so it remains hidden/))
      .toBeTruthy();
    expect(screen.getByRole("link", { name: "Retry replay" }).getAttribute("href"))
      .toBe("/replay");
    expect(screen.queryByRole("heading", { name: "Stale promotion blocked" })).toBeNull();
  });

  it("leads with the human outcome and preserves the complete six-event proof", async () => {
    window.controlGraphPublicReplayConfig = { available: true, sha256: REPLAY_SHA256 };
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
    configureLoader(validReplay());

    const { container } = render(<PublicReplayApp />);

    expect(await screen.findByRole("heading", { name: "Stale promotion blocked" }))
      .toBeTruthy();
    expect(screen.getByText(/target remained at 90\/10/)).toBeTruthy();
    const outcomeSummary = screen.getByRole("region", { name: "Outcome summary" });
    expect(within(outcomeSummary).getByText("Queued promotion").closest("article")?.textContent)
      .toContain("BlockedDENIED / EPOCH_MISMATCH");
    expect(within(outcomeSummary).getByText("Traffic after denial").closest("article")?.textContent)
      .toContain("90 / 10Stable / candidate · unchanged");
    expect(within(outcomeSummary).getByText("Verified recovery").closest("article")?.textContent)
      .toContain("100% stable0% candidate");
    expect(screen.getByText("Browser verification passed")).toBeTruthy();

    const sequence = screen.getByRole("region", {
      name: "From revoked approval to stable recovery",
    });
    expect(within(sequence).getByRole("list")).toBeTruthy();
    expect(within(sequence).getAllByRole("listitem")).toHaveLength(6);
    for (const heading of [
      "Approval was withdrawn",
      "Stale promotion was blocked",
      "Traffic stayed at 90/10",
      "Advisor explained the evidence",
      "Recovery reached 100% stable",
      "Evidence chain was verified",
    ]) {
      expect(screen.getByRole("heading", { name: heading })).toBeTruthy();
    }
    expect(
      screen.getByRole("heading", { name: "Approval was withdrawn" }).closest("article")
        ?.textContent,
    ).toContain("from epoch 7 to epoch 8");
    expect(
      screen.getByRole("heading", { name: "Stale promotion was blocked" }).closest("article")
        ?.textContent,
    ).toContain("DENIED / EPOCH_MISMATCH");
    expect(
      screen.getByRole("heading", { name: "Traffic stayed at 90/10" }).closest("article")
        ?.textContent,
    ).toContain(
      "Verified independent readback found 90% stable / 10% candidate before the denial and 90% stable / 10% candidate after it",
    );
    expect(
      screen.getByRole("heading", { name: "Recovery reached 100% stable" }).closest("article")
        ?.textContent,
    ).toContain("VERIFIED at 100% stable / 0% candidate");

    const advisorEvent = screen.getByRole("heading", {
      name: "Advisor explained the evidence",
    }).closest("article");
    expect(advisorEvent?.textContent).toContain("A read-only advisor explained");
    expect(advisorEvent?.textContent).toContain("authority_effect=none");
    expect(advisorEvent?.textContent).not.toContain(FINDING);
    expect(advisorEvent?.textContent).not.toContain("gemini-3.5-flash");

    expect(container.querySelectorAll(".event-index[aria-hidden='true']")).toHaveLength(6);
    expect(container.querySelector("time[datetime='2026-08-24T00:00:01Z']")?.textContent)
      .toBe("2026-08-24T00:00:01Z");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(`/replays/${REPLAY_SHA256}.json`, {
      credentials: "omit",
      headers: { Accept: "application/json" },
    });
  });

  it("keeps exact evidence and advisor metadata in one closed verification disclosure", async () => {
    window.controlGraphPublicReplayConfig = { available: true, sha256: REPLAY_SHA256 };
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
    const replay = validReplay();
    configureLoader(replay);

    const { container } = render(<PublicReplayApp />);
    await screen.findByRole("heading", { name: "Stale promotion blocked" });

    const details = container.querySelector("details.verification-details");
    expect(container.querySelectorAll("details")).toHaveLength(1);
    expect(details).toBeTruthy();
    expect((details as HTMLDetailsElement).open).toBe(false);
    expect(within(details as HTMLElement).getByText("Verification details")).toBeTruthy();

    const exactEvidence = details?.textContent ?? "";
    expect(exactEvidence).toContain(replay.payload.source_commit);
    expect(exactEvidence).toContain(replay.payload_sha256);
    expect(exactEvidence).toContain(replay.payload.acceptance_manifest_sha256);
    expect(exactEvidence).toContain(replay.payload.acceptance_run_id);
    expect(exactEvidence).toContain(replay.payload.event_chain_head_sha256);
    expect(exactEvidence).toContain(eventDigest(2));
    expect(exactEvidence).toContain(digest(20));
    expect(exactEvidence).toContain("evidence-receipt");
    expect(exactEvidence).toContain(FINDING);
    expect(exactEvidence).toContain("gemini-3.5-flash");
    expect(exactEvidence).toContain("controlgraph.rollout-advisor-prompt/v2");
    expect(exactEvidence).toContain("manual_review");
    expect(exactEvidence).toContain("8400");
    for (const toolId of TOOL_IDS) {
      expect(exactEvidence).toContain(toolId);
    }
    for (const image of replay.payload.images) {
      expect(exactEvidence).toContain(image.reference);
      expect(exactEvidence).toContain(image.reference.split("@sha256:")[1]);
    }
    expect(details?.querySelectorAll(".raw-value").length).toBeGreaterThan(40);
  });
});
