import type {
  TargetBinding,
  TimelineDisplayField,
  TimelineEntry,
  TimelineEventType,
  TimelineEvidenceClass,
  TimelineCorrelation,
  TimelinePage,
  TimelineTerminalClassification,
  TimelineVerificationStatus,
} from "../contracts/timeline";
import { canonicalJson } from "../contracts/canonical";

export const TARGET: TargetBinding = {
  schema_version: "controlgraph.target-binding/v1",
  project_id: "controlgraph-canary-abc123",
  region: "us-central1",
  environment: "nonprod",
  service_name: "controlgraph-reference-target",
};

export const ROOT_SHA256 = "a".repeat(64);
export const ROOT_ID = `cgroot:${ROOT_SHA256}`;

export function digest(sequence: number): string {
  return sequence.toString(16).padStart(8, "0").repeat(8);
}

function evidenceClass(eventType: TimelineEventType): TimelineEvidenceClass {
  if (eventType.startsWith("AUTHORITY_")) return "AUTHORITY";
  if (eventType === "CAPABILITY_ISSUED") return "CAPABILITY";
  if (eventType.startsWith("TASK_")) return "TASK";
  if (eventType === "HEALTH_OBSERVED") return "HEALTH";
  if (eventType === "HEALTH_DECIDED") return "DECISION";
  if (eventType.startsWith("MUTATION_")) return "MUTATION";
  if (eventType.startsWith("RECOVERY_")) return "RECOVERY";
  if (eventType === "MODEL_ASSISTANCE_RECORDED") return "MODEL_ASSISTANCE";
  if (eventType === "OPERATOR_ACTION_RECORDED") return "OPERATOR_ACTION";
  return "VERIFICATION";
}

export function field(
  name: TimelineDisplayField["name"],
  value: string,
): TimelineDisplayField {
  return { name, value };
}

export function timelineEntry(
  sequence: number,
  eventType: TimelineEventType,
  options: {
    readonly epoch?: number;
    readonly fields?: readonly TimelineDisplayField[];
    readonly verificationStatus?: TimelineVerificationStatus;
    readonly terminalClassification?: TimelineTerminalClassification;
    readonly rootSha256?: string;
    readonly correlations?: readonly TimelineCorrelation[];
  } = {},
): TimelineEntry {
  const entrySha256 = digest(sequence);
  const rootSha256 = options.rootSha256 ?? ROOT_SHA256;
  return {
    entryId: `cgtimeline:${entrySha256}`,
    entrySha256,
    sequence,
    previousEntrySha256: sequence === 1 ? null : digest(sequence - 1),
    target: TARGET,
    sourceSchemaVersion: "controlgraph.synthetic-evidence/v1",
    eventType,
    evidenceClass: evidenceClass(eventType),
    actorRole:
      eventType === "MODEL_ASSISTANCE_RECORDED"
        ? "ADVISOR"
        : eventType.startsWith("VERIFICATION") || eventType === "TERMINAL_CLASSIFIED"
          ? "VERIFIER"
          : "COORDINATOR",
    actorId: null,
    rootId: `cgroot:${rootSha256}`,
    rootSha256,
    epoch: options.epoch ?? 1,
    occurredAt: `2026-08-21T12:${String(sequence).padStart(2, "0")}:00Z`,
    recordedAt: `2026-08-21T12:${String(sequence).padStart(2, "0")}:01Z`,
    correlations: options.correlations ?? [
      { kind: "EVIDENCE", correlationId: `evidence:${sequence}` },
    ],
    payloadSha256: digest(sequence + 100),
    policySha256: "b".repeat(64),
    signature: {
      purpose: "EVIDENCE",
      signingKeyVersion:
        "projects/controlgraph-canary-abc123/locations/us-central1/keyRings/controlgraph-signing/cryptoKeys/evidence-signing/cryptoKeyVersions/1",
      signingAlgorithm: "EC_SIGN_P256_SHA256",
      payloadSha256: digest(sequence + 100),
      signingInputSha256: digest(sequence + 200),
      signatureSha256: digest(sequence + 300),
    },
    verificationStatus: options.verificationStatus ?? "NOT_APPLICABLE",
    terminalClassification: options.terminalClassification ?? "NONE",
    displayFields: options.fields ?? [field("SUMMARY", `Event ${sequence}`)],
  };
}

export function timelinePage(
  allEntries: readonly TimelineEntry[],
  afterSequence: number,
  maximumEntries = 25,
): TimelinePage {
  const entries = allEntries.slice(afterSequence, afterSequence + maximumEntries);
  const headEntry = allEntries.at(-1);
  const nextEntry = entries.at(-1);
  return {
    target: TARGET,
    entries,
    nextCursor: {
      afterSequence: nextEntry?.sequence ?? afterSequence,
      afterEntrySha256:
        nextEntry?.entrySha256 ??
        (afterSequence === 0 ? null : allEntries[afterSequence - 1]?.entrySha256 ?? null),
    },
    head: {
      afterSequence: headEntry?.sequence ?? 0,
      afterEntrySha256: headEntry?.entrySha256 ?? null,
    },
    hasMore: (nextEntry?.sequence ?? afterSequence) < (headEntry?.sequence ?? 0),
  };
}

export function timelineEntryWire(entry: TimelineEntry): Record<string, unknown> {
  return {
    actor_data_class: "OPERATOR",
    actor_id: entry.actorId,
    actor_role: entry.actorRole,
    audience: "OPERATOR",
    correlations: entry.correlations.map((correlation) => ({
      correlation_id: correlation.correlationId,
      data_class: "OPERATOR",
      kind: correlation.kind,
      schema_version: "controlgraph.timeline-correlation/v1",
    })),
    display_fields: entry.displayFields.map((display) => ({
      data_class: "OPERATOR",
      name: display.name,
      schema_version: "controlgraph.timeline-display-field/v1",
      value: display.value,
    })),
    entry_id: entry.entryId,
    entry_sha256: entry.entrySha256,
    epoch: entry.epoch,
    event_type: entry.eventType,
    evidence_class: entry.evidenceClass,
    occurred_at: entry.occurredAt,
    payload_sha256: entry.payloadSha256,
    policy_sha256: entry.policySha256,
    previous_entry_sha256: entry.previousEntrySha256,
    raw_retention_days: 30,
    recorded_at: entry.recordedAt,
    root_id: entry.rootId,
    root_sha256: entry.rootSha256,
    schema_version: "controlgraph.timeline-entry-projection/v1",
    sequence: entry.sequence,
    signature:
      entry.signature === null
        ? null
        : {
            payload_sha256: entry.signature.payloadSha256,
            purpose: entry.signature.purpose,
            schema_version: "controlgraph.timeline-signature-metadata/v1",
            signature_sha256: entry.signature.signatureSha256,
            signing_algorithm: entry.signature.signingAlgorithm,
            signing_input_sha256: entry.signature.signingInputSha256,
            signing_key_version: entry.signature.signingKeyVersion,
          },
    source_schema_version: entry.sourceSchemaVersion,
    target: entry.target,
    terminal_classification: entry.terminalClassification,
    verification_status: entry.verificationStatus,
  };
}

export function timelinePageBody(
  entries: readonly TimelineEntry[],
  query: {
    readonly afterSequence: number;
    readonly afterEntrySha256: string | null;
    readonly audience: "OPERATOR";
    readonly limit: number;
  },
  overrides: Record<string, unknown> = {},
): string {
  const last = entries.at(-1);
  return canonicalJson({
    command: {
      after_entry_sha256: query.afterEntrySha256,
      after_sequence: query.afterSequence,
      audience: query.audience,
      limit: query.limit,
      schema_version: "controlgraph.timeline-page-command/v1",
      target: TARGET,
    },
    command_sha256: "f".repeat(64),
    entries: entries.map(timelineEntryWire),
    has_more: false,
    head_entry_sha256: last?.entrySha256 ?? query.afterEntrySha256,
    head_sequence: last?.sequence ?? query.afterSequence,
    next_after_entry_sha256: last?.entrySha256 ?? query.afterEntrySha256,
    next_after_sequence: last?.sequence ?? query.afterSequence,
    schema_version: "controlgraph.timeline-page/v1",
    ...overrides,
  });
}
