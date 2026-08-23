import { describe, expect, it } from "vitest";

import { canonicalJson } from "./canonical";
import {
  REDACTED_DISPLAY_VALUE,
  decodeTimelinePage,
  type TimelineQuery,
} from "./timeline";
import {
  TARGET,
  field,
  timelineEntry,
  timelineEntryWire,
  timelinePageBody,
} from "../test/timelineFixtures";
import operatorTimelinePageV1 from "../test/operatorTimelinePageV1.json?raw";

const QUERY: TimelineQuery = {
  afterSequence: 0,
  afterEntrySha256: null,
  audience: "OPERATOR",
  limit: 25,
};

describe("timeline projection decoder", () => {
  it("decodes the Python-produced operator timeline golden fixture", () => {
    const page = decodeTimelinePage(operatorTimelinePageV1.trim(), QUERY);

    expect(page.entries).toHaveLength(10);
    expect(page.entries.map((entry) => entry.eventType)).toEqual([
      "TASK_CREATED",
      "MUTATION_APPLIED",
      "HEALTH_OBSERVED",
      "HEALTH_DECIDED",
      "TASK_CREATED",
      "TERMINAL_CLASSIFIED",
      "RECOVERY_TASK_CREATED",
      "OPERATOR_ACTION_RECORDED",
      "VERIFICATION_RECORDED",
      "MODEL_ASSISTANCE_RECORDED",
    ]);
    expect(page.entries[2]?.signature?.purpose).toBe("HEALTH_ATTESTATION");
    expect(page.nextCursor).toEqual(page.head);
  });

  it("accepts the backend's independent-verification signature purpose", () => {
    const entry = timelineEntry(1, "VERIFICATION_RECORDED", {
      verificationStatus: "VERIFIED",
    });
    const wireEntry = timelineEntryWire(entry);
    const signature = wireEntry.signature as Record<string, unknown>;
    signature.purpose = "INDEPENDENT_VERIFICATION";
    const body = JSON.parse(timelinePageBody([entry], QUERY)) as Record<
      string,
      unknown
    >;
    body.entries = [wireEntry];

    const page = decodeTimelinePage(canonicalJson(body), QUERY);

    expect(page.entries[0]?.signature?.purpose).toBe("INDEPENDENT_VERIFICATION");
  });

  it("accepts one exact contiguous operator projection", () => {
    const entries = [
      timelineEntry(1, "AUTHORITY_ROOT_CREATED"),
      timelineEntry(2, "MUTATION_APPLIED", {
        fields: [field("ACTION", "APPLY_CANARY")],
      }),
    ];

    const page = decodeTimelinePage(timelinePageBody(entries, QUERY), QUERY);

    expect(page.entries.map((entry) => entry.sequence)).toEqual([1, 2]);
    expect(page.target).toEqual(TARGET);
    expect(page.nextCursor).toEqual({
      afterSequence: 2,
      afterEntrySha256: entries[1]?.entrySha256,
    });
  });

  it("redacts secret-shaped display values even when a server projection misses them", () => {
    const entry = timelineEntry(1, "OPERATOR_ACTION_RECORDED", {
      fields: [
        field(
          "SUMMARY",
          "authorization: Bearer synthetic-token-value-that-must-not-render",
        ),
      ],
    });

    const page = decodeTimelinePage(timelinePageBody([entry], QUERY), QUERY);

    expect(page.entries[0]?.displayFields[0]?.value).toBe(REDACTED_DISPLAY_VALUE);
  });

  it("rejects unknown fields, gaps, and query substitution", () => {
    const first = timelineEntry(1, "AUTHORITY_ROOT_CREATED");
    expect(() =>
      decodeTimelinePage(
        timelinePageBody([first], QUERY, { unexpected: "field" }),
        QUERY,
      ),
    ).toThrow(/unknown field/);

    expect(() =>
      decodeTimelinePage(timelinePageBody([timelineEntry(2, "TASK_CREATED")], QUERY), QUERY),
    ).toThrow(/contiguous/);

    const raw = JSON.parse(timelinePageBody([first], QUERY)) as Record<string, unknown>;
    const command = raw.command as Record<string, unknown>;
    command.after_sequence = 1;
    command.after_entry_sha256 = first.entrySha256;
    expect(() => decodeTimelinePage(canonicalJson(raw), QUERY)).toThrow(/bind its query/);
  });

  it("rejects cross-target entries and unbound signature metadata", () => {
    const first = timelineEntry(1, "AUTHORITY_ROOT_CREATED");
    const crossTarget = {
      ...timelineEntryWire(first),
      target: { ...TARGET, service_name: "other-reference-target" },
    };
    const crossTargetBody = JSON.parse(timelinePageBody([first], QUERY)) as Record<
      string,
      unknown
    >;
    crossTargetBody.entries = [crossTarget];
    expect(() => decodeTimelinePage(canonicalJson(crossTargetBody), QUERY)).toThrow(
      /target sequence/,
    );

    const signatureBody = JSON.parse(timelinePageBody([first], QUERY)) as Record<
      string,
      unknown
    >;
    const wireEntry = (signatureBody.entries as Record<string, unknown>[])[0]!;
    const signature = wireEntry.signature as Record<string, unknown>;
    signature.payload_sha256 = "9".repeat(64);
    expect(() => decodeTimelinePage(canonicalJson(signatureBody), QUERY)).toThrow(
      /payload-bound/,
    );
  });

  it("rejects rendering controls in display text", () => {
    const entry = timelineEntry(1, "OPERATOR_ACTION_RECORDED", {
      fields: [field("SUMMARY", "hidden\u0000text")],
    });
    expect(() => decodeTimelinePage(timelinePageBody([entry], QUERY), QUERY)).toThrow(
      /rendering control/,
    );
  });
});
