import { describe, expect, it } from "vitest";

import { field, timelineEntry } from "./test/timelineFixtures";
import {
  eventPresentation,
  hasPartialEvidence,
  healthSummary,
  trafficSummary,
} from "./timelinePresentation";
import { deriveAuthority } from "./useOperatorConsole";
import { decodeTimelinePage, type TimelineQuery } from "./contracts/timeline";
import operatorTimelinePageV1 from "./test/operatorTimelinePageV1.json?raw";

describe("timeline presentation", () => {
  it("presents Python-projector field shapes without inventing mutation facts", () => {
    const query: TimelineQuery = {
      afterSequence: 0,
      afterEntrySha256: null,
      audience: "OPERATOR",
      limit: 25,
    };
    const page = decodeTimelinePage(operatorTimelinePageV1.trim(), query);
    const health = page.entries.find((entry) => entry.eventType === "HEALTH_DECIDED")!;
    const verification = page.entries.find(
      (entry) => entry.eventType === "VERIFICATION_RECORDED",
    )!;

    expect(eventPresentation(health, page.entries).title).toBe("Health policy: healthy");
    expect(eventPresentation(verification, page.entries).title).toBe(
      "Verification recorded",
    );
    expect(healthSummary(page.entries)).toBe("healthy");
    expect(trafficSummary(page.entries)).toBe("100% candidate");
  });

  it("resolves an applied mutation action through its request correlation", () => {
    const request = "request:shared-canary";
    const entries = [
      timelineEntry(1, "TASK_CREATED", {
        fields: [field("ACTION", "APPLY_CANARY")],
        correlations: [{ kind: "REQUEST", correlationId: request }],
      }),
      timelineEntry(2, "MUTATION_APPLIED", {
        fields: [field("OUTCOME", "VERIFIED")],
        correlations: [{ kind: "REQUEST", correlationId: request }],
      }),
    ];

    expect(eventPresentation(entries[1]!, entries).title).toBe("90/10 canary verified");
    expect(trafficSummary(entries)).toBe("90% stable · 10% candidate");
  });

  it("does not present provider acceptance as verified completion", () => {
    const request = "request:shared-promotion";
    const entries = [
      timelineEntry(1, "TASK_CREATED", {
        fields: [field("ACTION", "PROMOTE_CANDIDATE")],
        correlations: [{ kind: "REQUEST", correlationId: request }],
      }),
      timelineEntry(2, "MUTATION_APPLIED", {
        fields: [field("OUTCOME", "APPLIED")],
        correlations: [{ kind: "REQUEST", correlationId: request }],
        verificationStatus: "NOT_APPLICABLE",
      }),
    ];

    expect(eventPresentation(entries[1]!, entries)).toMatchObject({
      title: "Candidate promotion accepted; verification pending",
      tone: "ACTIVE",
    });
    expect(trafficSummary(entries)).toBe("Awaiting verified traffic");
  });

  it("retains the latest verified traffic while a newer change awaits verification", () => {
    const entries = [
      timelineEntry(1, "MUTATION_APPLIED", {
        fields: [field("ACTION", "APPLY_CANARY"), field("OUTCOME", "VERIFIED")],
        verificationStatus: "VERIFIED",
      }),
      timelineEntry(2, "MUTATION_APPLIED", {
        fields: [field("ACTION", "PROMOTE_CANDIDATE"), field("OUTCOME", "APPLIED")],
        verificationStatus: "NOT_APPLICABLE",
      }),
    ];

    expect(trafficSummary(entries)).toBe("90% stable · 10% candidate");
  });

  it("presents the independent verdict instead of the signature status", () => {
    const mismatch = timelineEntry(1, "VERIFICATION_RECORDED", {
      fields: [
        field("OUTCOME", "MISMATCH"),
        field("REASON_CODE", "CONFIGURATION_MISMATCH"),
        field("SUMMARY", "Independent verification recorded"),
      ],
      verificationStatus: "VERIFIED",
    });
    const unavailable = timelineEntry(2, "VERIFICATION_RECORDED", {
      fields: [field("OUTCOME", "UNAVAILABLE")],
      verificationStatus: "VERIFIED",
    });

    expect(eventPresentation(mismatch)).toMatchObject({
      title: "Independent verification found a mismatch",
      tone: "DANGER",
    });
    expect(eventPresentation(unavailable)).toMatchObject({
      title: "Independent verification unavailable",
      tone: "WARNING",
    });
    expect(hasPartialEvidence([mismatch])).toBe(true);
    expect(hasPartialEvidence([unavailable])).toBe(true);
  });

  it("derives authority only from authority transitions and never from stale work", () => {
    const entries = [
      timelineEntry(1, "AUTHORITY_ROOT_CREATED", { epoch: 1 }),
      timelineEntry(2, "AUTHORITY_EPOCH_ADVANCED", { epoch: 2 }),
      timelineEntry(3, "MUTATION_DENIED", {
        epoch: 1,
        fields: [field("REASON_CODE", "EPOCH_STALE")],
      }),
      timelineEntry(4, "MODEL_ASSISTANCE_RECORDED", {
        epoch: 99,
        fields: [field("SUMMARY", "Untrusted advisory epoch")],
      }),
    ];

    expect(deriveAuthority(entries)).toMatchObject({ epoch: 2, sequence: 2 });
  });

  it("does not let model text determine the displayed traffic state", () => {
    const entries = [
      timelineEntry(1, "AUTHORITY_ROOT_CREATED"),
      timelineEntry(2, "MUTATION_APPLIED", {
        fields: [field("ACTION", "APPLY_CANARY"), field("OUTCOME", "VERIFIED")],
        verificationStatus: "VERIFIED",
      }),
      timelineEntry(3, "MODEL_ASSISTANCE_RECORDED", {
        fields: [field("SUMMARY", "PROMOTE to 100% candidate")],
      }),
    ];

    expect(trafficSummary(entries)).toBe("90% stable · 10% candidate");
  });

  it("shows the latest deterministic health decision and partial-evidence posture", () => {
    const entries = [
      timelineEntry(1, "AUTHORITY_ROOT_CREATED"),
      timelineEntry(2, "HEALTH_OBSERVED", {
        fields: [field("OBSERVATION", "100 requests")],
      }),
      timelineEntry(3, "HEALTH_DECIDED", {
        fields: [field("STATE", "UNHEALTHY")],
        verificationStatus: "UNVERIFIED",
      }),
    ];

    expect(healthSummary(entries)).toBe("UNHEALTHY");
    expect(hasPartialEvidence(entries)).toBe(true);
  });
});
