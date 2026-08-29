import { describe, expect, it, vi } from "vitest";

import { canonicalJsonBytes, canonicalSha256 } from "./canonical";
import {
  loadPublicReplay,
  validatePublicReplayEnvelope,
} from "./publicReplay";

type JsonObject = Record<string, unknown>;

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

const EVENT_KINDS = [
  "AUTHORITY_ADVANCED",
  "STALE_WORK_DENIED",
  "TARGET_UNCHANGED",
  "ADVISOR_VALIDATED",
  "RECOVERY_VERIFIED",
  "TIMELINE_COMMITTED",
] as const;

const TOOL_IDS = [
  "read_root_summary",
  "read_target_summary",
  "read_health_summary",
  "read_receipt_summary",
  "read_timeline_summary",
  "read_verifier_summary",
] as const;

function sha(value: number): string {
  return value.toString(16).padStart(2, "0").repeat(32);
}

function traffic(stable: number, candidate: number, digest: string): JsonObject {
  return {
    candidate_percent: candidate,
    schema_version: "controlgraph.public-replay-traffic/v1",
    stable_percent: stable,
    target_configuration_sha256: digest,
  };
}

function eventDetails(): JsonObject[] {
  const canary = traffic(90, 10, sha(20));
  return [
    {
      cause: "OPERATOR_REVOCATION",
      new_epoch: 8,
      previous_epoch: 7,
      schema_version: "controlgraph.public-replay-authority-advanced/v1",
      transition_sha256: sha(21),
    },
    {
      current_authority_epoch: 8,
      outcome: "DENIED",
      reason_code: "EPOCH_MISMATCH",
      receipt_sha256: sha(22),
      schema_version: "controlgraph.public-replay-stale-denial/v1",
      work_epoch: 7,
    },
    {
      after_denial: canary,
      before_denial: canary,
      schema_version: "controlgraph.public-replay-target-unchanged/v1",
    },
    {
      advisor: {
        audit_sha256: sha(23),
        authority_effect: "none",
        confidence_basis_points: 8_500,
        deterministic_health_override: false,
        findings: [{
          citations: ["receipt", "timeline", "target"].map((kind, index) => ({
            evidence_id: `evidence-${kind}`,
            evidence_kind: kind,
            schema_version: "controlgraph.public-replay-citation/v1",
            source_sha256: sha(30 + index),
          })),
          schema_version: "controlgraph.public-replay-finding/v1",
          statement: "Stale work was denied and the target remained unchanged.",
        }],
        model_id: "gemini-3.5-flash",
        model_location: "global",
        operator_review_required: true,
        prompt_version: "controlgraph.rollout-advisor-prompt/v2",
        registry_sha256: sha(24),
        replayed_without_model_call: true,
        requested_operator_action: "wait",
        response_sha256: sha(25),
        schema_version: "controlgraph.public-replay-advisor/v1",
        snapshot_sha256: sha(26),
        structured_output_sha256: sha(27),
        tool_calls: TOOL_IDS.map((toolId, index) => ({
          input_sha256: sha(40 + index),
          output_sha256: sha(50 + index),
          schema_version: "controlgraph.public-replay-tool-call/v1",
          sequence: index + 1,
          status: "succeeded",
          tool_id: toolId,
        })),
        validation: "accepted",
      },
      schema_version: "controlgraph.public-replay-advisor-validated/v1",
    },
    {
      outcome: "VERIFIED",
      receipt_sha256: sha(28),
      schema_version: "controlgraph.public-replay-recovery-verified/v1",
      traffic: traffic(100, 0, sha(29)),
    },
    {
      schema_version: "controlgraph.public-replay-timeline-committed/v1",
      timeline: {
        entries: [
          "AUTHORITY_EPOCH_ADVANCED",
          "MUTATION_DENIED",
          "MUTATION_APPLIED",
          "MODEL_ASSISTANCE_RECORDED",
        ].map((eventType, index) => ({
          entry_sha256: sha(60 + index),
          event_type: eventType,
          occurred_at: `2026-08-24T00:00:0${index}Z`,
          schema_version: "controlgraph.public-replay-timeline-entry/v1",
          sequence: index + 1,
          verification_status: index === 0 ? "NOT_APPLICABLE" : "VERIFIED",
        })),
        entry_count: 4,
        head_entry_sha256: sha(63),
        head_sequence: 4,
        page_count: 1,
        page_set_sha256: sha(64),
        schema_version: "controlgraph.public-replay-timeline/v1",
      },
    },
  ];
}

async function seal(payload: JsonObject): Promise<JsonObject> {
  let predecessor: string | null = null;
  const events = payload.events as JsonObject[];
  for (const envelope of events) {
    const event = envelope.event as JsonObject;
    event.previous_event_sha256 = predecessor;
    predecessor = await canonicalSha256(
      "controlgraph.public-replay-event/v1",
      event,
    );
    envelope.event_sha256 = predecessor;
  }
  payload.event_chain_head_sha256 = predecessor;
  return {
    payload,
    payload_sha256: await canonicalSha256(
      "controlgraph.public-replay-payload/v1",
      payload,
    ),
    schema_version: "controlgraph.public-replay-envelope/v1",
  };
}

async function fixture(): Promise<JsonObject> {
  const details = eventDetails();
  const payload: JsonObject = {
    acceptance_manifest_sha256: sha(70),
    acceptance_run_id: `cgacceptance:${sha(71)}`,
    acceptance_status: "PASSED",
    accepted_at: "2026-08-24T00:00:06Z",
    cases: CASE_KINDS.map((kind, index) => ({
      case_sha256: sha(80 + index),
      kind,
      schema_version: "controlgraph.public-replay-case/v1",
      sequence: index + 1,
    })),
    event_chain_head_sha256: sha(89),
    events: EVENT_KINDS.map((kind, index) => ({
      event: {
        details: details[index],
        kind,
        occurred_at: `2026-08-24T00:00:0${index}Z`,
        previous_event_sha256: null,
        schema_version: "controlgraph.public-replay-event/v1",
        sequence: index + 1,
      },
      event_sha256: sha(90 + index),
      schema_version: "controlgraph.public-replay-event-envelope/v1",
    })),
    evidence_binding_complete: true,
    images: IMAGE_COMPONENTS.map((component, index) => ({
      component,
      reference: (
        "us-central1-docker.pkg.dev/controlgraph-canary-abc123/" +
        `controlgraph-canary/${component}@sha256:${sha(100 + index)}`
      ),
      schema_version: "controlgraph.public-replay-image/v1",
    })),
    schema_version: "controlgraph.public-replay-payload/v1",
    source_commit: "a".repeat(40),
  };
  return seal(payload);
}

async function rawSha256(value: Uint8Array): Promise<string> {
  const material = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("public replay browser verifier", () => {
  it("accepts one complete immutable replay", async () => {
    const envelope = await fixture();

    const decoded = await validatePublicReplayEnvelope(envelope);

    expect(decoded.payload.cases.map((item) => item.kind)).toEqual(CASE_KINDS);
    expect(decoded.payload.events.map((item) => item.event.kind)).toEqual(EVENT_KINDS);
  });

  it("allows append-ordered timeline replay with an earlier source timestamp", async () => {
    const envelope = await fixture();
    const payload = envelope.payload as JsonObject;
    const events = payload.events as JsonObject[];
    const committed = (events[5]!.event as JsonObject).details as JsonObject;
    const timeline = committed.timeline as JsonObject;
    const entries = timeline.entries as JsonObject[];
    entries.push({
      ...entries[2]!,
      entry_sha256: "e".repeat(64),
      occurred_at: "2026-08-24T00:00:04Z",
      sequence: 5,
    });
    entries.push({
      ...entries[3]!,
      entry_sha256: "f".repeat(64),
      occurred_at: "2026-08-24T00:00:03Z",
      sequence: 6,
    });
    timeline.entry_count = 6;
    timeline.head_entry_sha256 = "f".repeat(64);
    timeline.head_sequence = 6;

    await expect(validatePublicReplayEnvelope(await seal(payload))).resolves.toBeDefined();
  });

  it("rejects semantic tampering even after all hashes are recomputed", async () => {
    const duplicateCase = await fixture();
    const duplicatePayload = duplicateCase.payload as JsonObject;
    const cases = duplicatePayload.cases as JsonObject[];
    cases[1]!.case_sha256 = cases[0]!.case_sha256;
    await expect(validatePublicReplayEnvelope(await seal(duplicatePayload))).rejects.toThrow(
      "PUBLIC_REPLAY_INVALID",
    );

    const duplicateTool = await fixture();
    const toolPayload = duplicateTool.payload as JsonObject;
    const events = toolPayload.events as JsonObject[];
    const advisorDetails = ((events[3]!.event as JsonObject).details as JsonObject)
      .advisor as JsonObject;
    const calls = advisorDetails.tool_calls as JsonObject[];
    calls[1]!.tool_id = calls[0]!.tool_id;
    await expect(validatePublicReplayEnvelope(await seal(toolPayload))).rejects.toThrow(
      "PUBLIC_REPLAY_INVALID",
    );

    const crossEpoch = await fixture();
    const epochPayload = crossEpoch.payload as JsonObject;
    const epochEvents = epochPayload.events as JsonObject[];
    const denial = (epochEvents[1]!.event as JsonObject).details as JsonObject;
    denial.work_epoch = 9;
    denial.current_authority_epoch = 10;
    await expect(validatePublicReplayEnvelope(await seal(epochPayload))).rejects.toThrow(
      "PUBLIC_REPLAY_INVALID",
    );
  });

  it("fetches only the immutable credential-free route and rejects BOM bytes", async () => {
    const envelope = await fixture();
    const bytes = canonicalJsonBytes(envelope);
    const replaySha256 = await rawSha256(bytes);
    window.controlGraphPublicReplayConfig = { available: true, sha256: replaySha256 };
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(input).toBe(`/replays/${replaySha256}.json`);
      expect(init?.credentials).toBe("omit");
      expect(new Headers(init?.headers).has("Authorization")).toBe(false);
      return new Response(bytes, { headers: { "Content-Type": "application/json" } });
    }) as unknown as typeof fetch;

    await expect(loadPublicReplay(fetcher)).resolves.toEqual(
      await validatePublicReplayEnvelope(envelope),
    );
    expect(fetcher).toHaveBeenCalledTimes(1);

    const bom = new Uint8Array(bytes.length + 3);
    bom.set([0xef, 0xbb, 0xbf]);
    bom.set(bytes, 3);
    window.controlGraphPublicReplayConfig = {
      available: true,
      sha256: await rawSha256(bom),
    };
    const bomFetcher = vi.fn(async () => new Response(bom, {
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof fetch;
    await expect(loadPublicReplay(bomFetcher)).rejects.toThrow("not valid JSON");
  });
});
