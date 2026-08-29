import { cleanup, render, screen } from "@testing-library/react";
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

function replayEvent(
  kind: PublicReplayEventKind,
  sequence: number,
  details: Record<string, unknown>,
): PublicReplayEventEnvelope {
  return {
    schema_version: "controlgraph.public-replay-event-envelope/v1",
    event_sha256: sequence.toString(16).padStart(2, "0").repeat(32),
    event: {
      schema_version: "controlgraph.public-replay-event/v1",
      sequence,
      kind,
      occurred_at: `2026-08-24T00:00:0${sequence - 1}Z`,
      previous_event_sha256: sequence === 1 ? null : "a".repeat(64),
      details,
    },
  };
}

function validReplay(): PublicReplayEnvelope {
  const canary = {
    candidate_percent: 10,
    schema_version: "controlgraph.public-replay-traffic/v1",
    stable_percent: 90,
    target_configuration_sha256: "b".repeat(64),
  };
  return {
    schema_version: "controlgraph.public-replay-envelope/v1",
    payload_sha256: REPLAY_SHA256,
    payload: {
      schema_version: "controlgraph.public-replay-payload/v1",
      source_commit: "a".repeat(40),
      acceptance_manifest_sha256: "c".repeat(64),
      acceptance_run_id: `cgacceptance:${"d".repeat(64)}`,
      acceptance_status: "PASSED",
      evidence_binding_complete: true,
      accepted_at: "2026-08-24T00:00:06Z",
      images: IMAGE_COMPONENTS.map((component, index) => ({
        schema_version: "controlgraph.public-replay-image/v1" as const,
        component,
        reference: (
          "us-central1-docker.pkg.dev/controlgraph-canary-abc123/" +
          `controlgraph-canary/${component}@sha256:${String(index + 1).repeat(64)}`
        ),
      })),
      cases: CASE_KINDS.map((kind, index) => ({
        schema_version: "controlgraph.public-replay-case/v1" as const,
        sequence: index + 1,
        kind,
        case_sha256: String(index + 1).repeat(64),
      })),
      events: [
        replayEvent("AUTHORITY_ADVANCED", 1, {
          previous_epoch: 7,
          new_epoch: 8,
        }),
        replayEvent("STALE_WORK_DENIED", 2, {
          work_epoch: 7,
          current_authority_epoch: 8,
        }),
        replayEvent("TARGET_UNCHANGED", 3, {
          before_denial: canary,
          after_denial: canary,
        }),
        replayEvent("ADVISOR_VALIDATED", 4, {
          advisor: {
            model_id: "gemini-3.5-flash",
            findings: [
              {
                statement: "Stale work was denied and the target remained unchanged.",
                citations: [
                  { evidence_kind: "receipt" },
                  { evidence_kind: "timeline" },
                  { evidence_kind: "target" },
                ],
              },
            ],
            tool_calls: Array.from({ length: 6 }, (_, index) => ({ sequence: index + 1 })),
          },
        }),
        replayEvent("RECOVERY_VERIFIED", 5, {
          traffic: {
            candidate_percent: 0,
            schema_version: "controlgraph.public-replay-traffic/v1",
            stable_percent: 100,
            target_configuration_sha256: "e".repeat(64),
          },
        }),
        replayEvent("TIMELINE_COMMITTED", 6, {
          timeline: {
            entries: Array.from({ length: 8 }, (_, index) => ({ sequence: index + 1 })),
            head_entry_sha256: "9".repeat(64),
            head_sequence: 24,
          },
        }),
      ],
      event_chain_head_sha256: "9".repeat(64),
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

  it("renders the unavailable state without requesting an artifact", async () => {
    configureLoader(null);

    render(<PublicReplayApp />);

    expect(await screen.findByRole("heading", { name: "Public replay" })).toBeTruthy();
    expect(screen.getByText("No accepted replay is currently published.")).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("fails closed when the configured replay cannot be loaded", async () => {
    window.controlGraphPublicReplayConfig = { available: true, sha256: REPLAY_SHA256 };
    vi.mocked(fetch).mockRejectedValue(new Error("synthetic replay failure"));
    configureLoader(new Error("invalid replay"));

    render(<PublicReplayApp />);

    expect((await screen.findByRole("alert")).textContent).toContain(
      "Replay verification failed",
    );
    expect(screen.getByText(/not rendered because its immutable validation did not pass/))
      .toBeTruthy();
  });

  it("renders the complete six-event recorded evidence boundary", async () => {
    window.controlGraphPublicReplayConfig = { available: true, sha256: REPLAY_SHA256 };
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
    configureLoader(validReplay());

    const { container } = render(<PublicReplayApp />);

    expect(await screen.findByRole("heading", { name: "Stale-authority replay" }))
      .toBeTruthy();
    expect(screen.getByText("Cases: 8 / 8 passed")).toBeTruthy();
    expect(screen.getByText("Recorded hosted evidence — no live connection or credentials."))
      .toBeTruthy();
    expect(screen.getByText(/6 \/ 6 read-only tools succeeded/)).toBeTruthy();
    expect(container.querySelectorAll(".replay-event")).toHaveLength(6);
    for (const heading of [
      "Authority advanced",
      "Queued work denied",
      "Target stayed unchanged",
      "Advisory analysis validated",
      "Captured stable restored",
      "Timeline commitments verified",
    ]) {
      expect(screen.getByRole("heading", { name: heading })).toBeTruthy();
    }
    expect(
      screen.getByRole("heading", { name: "Queued work denied" }).closest("article")
        ?.textContent,
    ).toContain("DENIED with EPOCH_MISMATCH against current epoch 8");
    expect(screen.getByText("90% stable / 10% candidate before and after the denial."))
      .toBeTruthy();
    expect(
      screen.getByRole("heading", { name: "Captured stable restored" }).closest("article")
        ?.textContent,
    ).toContain("VERIFIED at 100% stable / 0% candidate");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(`/replays/${REPLAY_SHA256}.json`, {
      credentials: "omit",
      headers: { Accept: "application/json" },
    });
  });
});
