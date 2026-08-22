import {
  ContractCodecError,
  assertUtcSecondTimestamp,
  decodeVersionedCanonicalJson,
} from "./canonical";

export const TIMELINE_PAGE_VERSION = "controlgraph.timeline-page/v1";
export const REDACTED_DISPLAY_VALUE = "[REDACTED]";
export const TIMELINE_PAGE_LIMIT = 25;

const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const projectId = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const region = /^[a-z]+-[a-z]+[0-9]+$/;
const cloudRunName = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const sha256 = /^[0-9a-f]{64}$/;
const contractVersion = /^controlgraph\.[a-z0-9-]+\/v[1-9][0-9]*$/;
const keyVersion = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+\/cryptoKeyVersions\/[1-9][0-9]*$/;
const unsafeRenderingControl = /[\p{C}\p{Zl}\p{Zp}]/u;

const secretPatterns = [
  /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/i,
  /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{30,}\b/,
  /\bya29\.[A-Za-z0-9_-]{20,}\b/,
  /["']?(?:authorization|cookie|set-cookie|password|private[_-]?key|client[_-]?secret|access[_-]?token|identity[_-]?token|signature|capability|x-goog-iap-jwt-assertion)["']?\s*[:=]/i,
] as const;

const timelineAudiences = [
  "PUBLIC_DEMO",
  "OPERATOR",
  "SECURITY_AUDIT",
  "RESTRICTED",
] as const;
const evidenceClasses = [
  "AUTHORITY",
  "CAPABILITY",
  "TASK",
  "HEALTH",
  "DECISION",
  "MUTATION",
  "RECOVERY",
  "VERIFICATION",
  "MODEL_ASSISTANCE",
  "OPERATOR_ACTION",
] as const;
const eventTypes = [
  "AUTHORITY_ROOT_CREATED",
  "AUTHORITY_EPOCH_ADVANCED",
  "CAPABILITY_ISSUED",
  "TASK_CREATED",
  "TASK_DELIVERED",
  "HEALTH_OBSERVED",
  "HEALTH_DECIDED",
  "MUTATION_REQUESTED",
  "MUTATION_APPLIED",
  "MUTATION_DENIED",
  "MUTATION_AMBIGUOUS",
  "RECOVERY_INTENT_CREATED",
  "RECOVERY_TASK_CREATED",
  "RECOVERY_APPLIED",
  "VERIFICATION_RECORDED",
  "TERMINAL_CLASSIFIED",
  "MODEL_ASSISTANCE_RECORDED",
  "OPERATOR_ACTION_RECORDED",
] as const;
const actorRoles = [
  "OPERATOR",
  "API",
  "COORDINATOR",
  "ISSUER",
  "EXECUTOR",
  "RECOVERY",
  "VERIFIER",
  "EVIDENCE_WRITER",
  "ADVISOR",
  "TARGET",
  "SYSTEM",
] as const;
const correlationKinds = [
  "REQUEST",
  "RECEIPT",
  "EVIDENCE",
  "CAPABILITY",
  "TASK",
  "DECISION",
  "MUTATION",
  "RECOVERY",
  "VERIFICATION",
  "MODEL",
  "OPERATOR_ACTION",
] as const;
const displayFieldNames = [
  "SUMMARY",
  "ACTION",
  "STATE",
  "OUTCOME",
  "REASON_CODE",
  "REVISION",
  "OBSERVATION",
  "WINDOW",
  "NEXT_ACTION",
] as const;
const verificationStatuses = [
  "NOT_APPLICABLE",
  "UNVERIFIED",
  "VERIFIED",
  "FAILED",
  "AMBIGUOUS",
] as const;
const terminalClassifications = [
  "NONE",
  "PROMOTED",
  "RECOVERED",
  "REVOKED",
  "DENIED",
  "FAILED_SAFE",
  "AMBIGUOUS",
] as const;
const signaturePurposes = [
  "CAPABILITY",
  "EVIDENCE",
  "HEALTH_ATTESTATION",
  "INDEPENDENT_VERIFICATION",
  "RECOVERY_PRESTATE",
  "CLASSIFICATION_EVIDENCE",
] as const;

const audienceRank: Record<TimelineAudience, number> = {
  PUBLIC_DEMO: 0,
  OPERATOR: 1,
  SECURITY_AUDIT: 2,
  RESTRICTED: 3,
};

const eventEvidenceClass: Record<TimelineEventType, TimelineEvidenceClass> = {
  AUTHORITY_ROOT_CREATED: "AUTHORITY",
  AUTHORITY_EPOCH_ADVANCED: "AUTHORITY",
  CAPABILITY_ISSUED: "CAPABILITY",
  TASK_CREATED: "TASK",
  TASK_DELIVERED: "TASK",
  HEALTH_OBSERVED: "HEALTH",
  HEALTH_DECIDED: "DECISION",
  MUTATION_REQUESTED: "MUTATION",
  MUTATION_APPLIED: "MUTATION",
  MUTATION_DENIED: "MUTATION",
  MUTATION_AMBIGUOUS: "MUTATION",
  RECOVERY_INTENT_CREATED: "RECOVERY",
  RECOVERY_TASK_CREATED: "RECOVERY",
  RECOVERY_APPLIED: "RECOVERY",
  VERIFICATION_RECORDED: "VERIFICATION",
  TERMINAL_CLASSIFIED: "VERIFICATION",
  MODEL_ASSISTANCE_RECORDED: "MODEL_ASSISTANCE",
  OPERATOR_ACTION_RECORDED: "OPERATOR_ACTION",
};

export type TimelineAudience = (typeof timelineAudiences)[number];
export type TimelineEvidenceClass = (typeof evidenceClasses)[number];
export type TimelineEventType = (typeof eventTypes)[number];
export type TimelineActorRole = (typeof actorRoles)[number];
export type TimelineCorrelationKind = (typeof correlationKinds)[number];
export type TimelineDisplayFieldName = (typeof displayFieldNames)[number];
export type TimelineVerificationStatus = (typeof verificationStatuses)[number];
export type TimelineTerminalClassification =
  (typeof terminalClassifications)[number];
export type TimelineSignaturePurpose = (typeof signaturePurposes)[number];

export interface TargetBinding {
  readonly schema_version: "controlgraph.target-binding/v1";
  readonly project_id: string;
  readonly region: string;
  readonly environment: string;
  readonly service_name: string;
}

export interface TimelineCursor {
  readonly afterSequence: number;
  readonly afterEntrySha256: string | null;
}

export interface TimelineQuery extends TimelineCursor {
  readonly audience: "OPERATOR";
  readonly limit: number;
}

export interface TimelineCorrelation {
  readonly kind: TimelineCorrelationKind;
  readonly correlationId: string;
}

export interface TimelineDisplayField {
  readonly name: TimelineDisplayFieldName;
  readonly value: string;
}

export interface TimelineSignatureMetadata {
  readonly purpose: TimelineSignaturePurpose;
  readonly signingKeyVersion: string;
  readonly signingAlgorithm: "EC_SIGN_P256_SHA256";
  readonly payloadSha256: string;
  readonly signingInputSha256: string;
  readonly signatureSha256: string;
}

export interface TimelineEntry {
  readonly entryId: string;
  readonly entrySha256: string;
  readonly sequence: number;
  readonly previousEntrySha256: string | null;
  readonly target: TargetBinding;
  readonly sourceSchemaVersion: string;
  readonly eventType: TimelineEventType;
  readonly evidenceClass: TimelineEvidenceClass;
  readonly actorRole: TimelineActorRole;
  readonly actorId: string | null;
  readonly rootId: string;
  readonly rootSha256: string;
  readonly epoch: number;
  readonly occurredAt: string;
  readonly recordedAt: string;
  readonly correlations: readonly TimelineCorrelation[];
  readonly payloadSha256: string;
  readonly policySha256: string;
  readonly signature: TimelineSignatureMetadata | null;
  readonly verificationStatus: TimelineVerificationStatus;
  readonly terminalClassification: TimelineTerminalClassification;
  readonly displayFields: readonly TimelineDisplayField[];
}

export interface TimelinePage {
  readonly target: TargetBinding;
  readonly entries: readonly TimelineEntry[];
  readonly nextCursor: TimelineCursor;
  readonly head: TimelineCursor;
  readonly hasMore: boolean;
}

export const INITIAL_TIMELINE_CURSOR: TimelineCursor = Object.freeze({
  afterSequence: 0,
  afterEntrySha256: null,
});

function record(
  value: unknown,
  name: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new ContractCodecError(`${name} must be an object`);
  }
  const result = value as Record<string, unknown>;
  const allowlist = new Set(allowed);
  if (Object.keys(result).some((key) => !allowlist.has(key))) {
    throw new ContractCodecError(`${name} contains an unknown field`);
  }
  return result;
}

function array(value: unknown, name: string, maximum: number): readonly unknown[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new ContractCodecError(`${name} is outside its bounds`);
  }
  return value;
}

function string(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): string {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    value.normalize("NFC") !== value
  ) {
    throw new ContractCodecError(`${name} is invalid`);
  }
  return value;
}

function safeText(value: unknown, name: string, maximum = 512): string {
  const text = string(value, name, 1, maximum);
  if (unsafeRenderingControl.test(text)) {
    throw new ContractCodecError(`${name} contains a rendering control`);
  }
  return text;
}

function matchingString(
  value: unknown,
  name: string,
  pattern: RegExp,
  maximum = 512,
): string {
  const text = string(value, name, 1, maximum);
  if (!pattern.test(text)) {
    throw new ContractCodecError(`${name} is invalid`);
  }
  return text;
}

function integer(value: unknown, name: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new ContractCodecError(`${name} is invalid`);
  }
  return value as number;
}

function enumeration<const T extends readonly string[]>(
  value: unknown,
  name: string,
  values: T,
): T[number] {
  if (typeof value !== "string" || !values.includes(value)) {
    throw new ContractCodecError(`${name} is unsupported`);
  }
  return value as T[number];
}

function nullableDigest(value: unknown, name: string): string | null {
  return value === null ? null : matchingString(value, name, sha256, 64);
}

function utcSecond(value: unknown, name: string): string {
  const timestamp = string(value, name, 20, 20);
  assertUtcSecondTimestamp(timestamp);
  return timestamp;
}

function isSecretShaped(value: string): boolean {
  return secretPatterns.some((pattern) => pattern.test(value));
}

export function redactDisplayValue(value: string): string {
  return isSecretShaped(value) ? REDACTED_DISPLAY_VALUE : value;
}

function parseTarget(value: unknown): TargetBinding {
  const item = record(value, "timeline target", [
    "schema_version",
    "project_id",
    "region",
    "environment",
    "service_name",
  ]);
  if (item.schema_version !== "controlgraph.target-binding/v1") {
    throw new ContractCodecError("timeline target version is unsupported");
  }
  return {
    schema_version: item.schema_version,
    project_id: matchingString(item.project_id, "target project", projectId, 30),
    region: matchingString(item.region, "target region", region, 32),
    environment: matchingString(item.environment, "target environment", identifier, 128),
    service_name: matchingString(item.service_name, "target service", cloudRunName, 63),
  };
}

function sameTarget(left: TargetBinding, right: TargetBinding): boolean {
  return (
    left.project_id === right.project_id &&
    left.region === right.region &&
    left.environment === right.environment &&
    left.service_name === right.service_name
  );
}

function parseCorrelation(value: unknown): TimelineCorrelation | null {
  const item = record(value, "timeline correlation", [
    "schema_version",
    "kind",
    "correlation_id",
    "data_class",
  ]);
  if (item.schema_version !== "controlgraph.timeline-correlation/v1") {
    throw new ContractCodecError("timeline correlation version is unsupported");
  }
  const dataClass = enumeration(
    item.data_class,
    "correlation audience",
    timelineAudiences,
  );
  if (audienceRank[dataClass] > audienceRank.OPERATOR) {
    throw new ContractCodecError("timeline correlation exceeds the operator audience");
  }
  const correlationId = matchingString(
    item.correlation_id,
    "correlation identity",
    identifier,
    128,
  );
  if (isSecretShaped(correlationId)) {
    return null;
  }
  return {
    kind: enumeration(item.kind, "correlation kind", correlationKinds),
    correlationId,
  };
}

function parseDisplayField(value: unknown): TimelineDisplayField {
  const item = record(value, "timeline display field", [
    "schema_version",
    "name",
    "value",
    "data_class",
  ]);
  if (item.schema_version !== "controlgraph.timeline-display-field/v1") {
    throw new ContractCodecError("timeline display field version is unsupported");
  }
  const dataClass = enumeration(
    item.data_class,
    "display field audience",
    timelineAudiences,
  );
  if (audienceRank[dataClass] > audienceRank.OPERATOR) {
    throw new ContractCodecError("timeline display field exceeds the operator audience");
  }
  return {
    name: enumeration(item.name, "display field name", displayFieldNames),
    value: redactDisplayValue(safeText(item.value, "display field value")),
  };
}

function parseSignature(value: unknown): TimelineSignatureMetadata | null {
  if (value === null) {
    return null;
  }
  const item = record(value, "timeline signature metadata", [
    "schema_version",
    "purpose",
    "signing_key_version",
    "signing_algorithm",
    "payload_sha256",
    "signing_input_sha256",
    "signature_sha256",
  ]);
  if (
    item.schema_version !== "controlgraph.timeline-signature-metadata/v1" ||
    item.signing_algorithm !== "EC_SIGN_P256_SHA256"
  ) {
    throw new ContractCodecError("timeline signature metadata is unsupported");
  }
  return {
    purpose: enumeration(item.purpose, "timeline signature purpose", signaturePurposes),
    signingKeyVersion: matchingString(
      item.signing_key_version,
      "timeline signing key",
      keyVersion,
    ),
    signingAlgorithm: item.signing_algorithm,
    payloadSha256: matchingString(item.payload_sha256, "payload digest", sha256, 64),
    signingInputSha256: matchingString(
      item.signing_input_sha256,
      "signing input digest",
      sha256,
      64,
    ),
    signatureSha256: matchingString(
      item.signature_sha256,
      "signature digest",
      sha256,
      64,
    ),
  };
}

function parseEntry(value: unknown): TimelineEntry {
  const item = record(value, "timeline entry", [
    "schema_version",
    "audience",
    "entry_id",
    "entry_sha256",
    "sequence",
    "previous_entry_sha256",
    "target",
    "source_schema_version",
    "event_type",
    "evidence_class",
    "actor_role",
    "actor_id",
    "actor_data_class",
    "root_id",
    "root_sha256",
    "epoch",
    "occurred_at",
    "recorded_at",
    "correlations",
    "payload_sha256",
    "policy_sha256",
    "raw_retention_days",
    "signature",
    "verification_status",
    "terminal_classification",
    "display_fields",
  ]);
  if (
    item.schema_version !== "controlgraph.timeline-entry-projection/v1" ||
    item.audience !== "OPERATOR"
  ) {
    throw new ContractCodecError("timeline entry projection is unsupported");
  }
  const actorDataClass = enumeration(
    item.actor_data_class,
    "actor audience",
    timelineAudiences,
  );
  const rawRetentionDays = integer(item.raw_retention_days, "raw retention days", 1);
  if (rawRetentionDays > 3_650) {
    throw new ContractCodecError("raw retention days is invalid");
  }
  const entrySha256 = matchingString(item.entry_sha256, "entry digest", sha256, 64);
  const entryId = matchingString(item.entry_id, "entry identity", identifier, 128);
  if (entryId !== `cgtimeline:${entrySha256}`) {
    throw new ContractCodecError("timeline entry identity is invalid");
  }
  const sequence = integer(item.sequence, "timeline sequence", 1);
  const previousEntrySha256 = nullableDigest(
    item.previous_entry_sha256,
    "previous entry digest",
  );
  if ((sequence === 1) !== (previousEntrySha256 === null)) {
    throw new ContractCodecError("timeline entry predecessor is invalid");
  }
  const actorId =
    item.actor_id === null
      ? null
      : matchingString(item.actor_id, "actor identity", identifier, 128);
  if (actorId !== null && audienceRank[actorDataClass] > audienceRank.OPERATOR) {
    throw new ContractCodecError("timeline projection exposes a restricted actor");
  }
  const correlations = array(item.correlations, "timeline correlations", 16)
    .map(parseCorrelation)
    .filter((entry): entry is TimelineCorrelation => entry !== null);
  const displayFields = array(item.display_fields, "timeline display fields", 16).map(
    parseDisplayField,
  );
  const correlationKeys = correlations.map(
    (entry) => `${entry.kind}\u0000${entry.correlationId}`,
  );
  const displayKeys = displayFields.map((entry) => entry.name);
  if (
    new Set(correlationKeys).size !== correlationKeys.length ||
    correlationKeys.join("\u0000") !== [...correlationKeys].sort().join("\u0000") ||
    new Set(displayKeys).size !== displayKeys.length ||
    displayKeys.join("\u0000") !== [...displayKeys].sort().join("\u0000")
  ) {
    throw new ContractCodecError("timeline projection contains duplicate display data");
  }
  const rootSha256 = matchingString(item.root_sha256, "root digest", sha256, 64);
  const rootId = matchingString(item.root_id, "root identity", identifier, 128);
  if (rootId !== `cgroot:${rootSha256}`) {
    throw new ContractCodecError("timeline root identity is invalid");
  }
  const signature = parseSignature(item.signature);
  const payloadSha256 = matchingString(item.payload_sha256, "payload digest", sha256, 64);
  if (signature !== null && signature.payloadSha256 !== payloadSha256) {
    throw new ContractCodecError("timeline signature metadata is not payload-bound");
  }
  const eventType = enumeration(item.event_type, "timeline event type", eventTypes);
  const evidenceClass = enumeration(
    item.evidence_class,
    "timeline evidence class",
    evidenceClasses,
  );
  const terminalClassification = enumeration(
    item.terminal_classification,
    "terminal classification",
    terminalClassifications,
  );
  if (
    eventEvidenceClass[eventType] !== evidenceClass ||
    (eventType === "TERMINAL_CLASSIFIED") !== (terminalClassification !== "NONE")
  ) {
    throw new ContractCodecError("timeline event classification is invalid");
  }
  return {
    entryId,
    entrySha256,
    sequence,
    previousEntrySha256,
    target: parseTarget(item.target),
    sourceSchemaVersion: matchingString(
      item.source_schema_version,
      "source schema version",
      contractVersion,
      128,
    ),
    eventType,
    evidenceClass,
    actorRole: enumeration(item.actor_role, "timeline actor role", actorRoles),
    actorId: actorId !== null && isSecretShaped(actorId) ? null : actorId,
    rootId,
    rootSha256,
    epoch: integer(item.epoch, "timeline epoch", 1),
    occurredAt: utcSecond(item.occurred_at, "event time"),
    recordedAt: utcSecond(item.recorded_at, "recorded time"),
    correlations,
    payloadSha256,
    policySha256: matchingString(item.policy_sha256, "policy digest", sha256, 64),
    signature,
    verificationStatus: enumeration(
      item.verification_status,
      "verification status",
      verificationStatuses,
    ),
    terminalClassification,
    displayFields,
  };
}

export function decodeTimelinePage(text: string, query: TimelineQuery): TimelinePage {
  const value = decodeVersionedCanonicalJson(text, TIMELINE_PAGE_VERSION);
  const page = record(value, "timeline page", [
    "schema_version",
    "command",
    "command_sha256",
    "entries",
    "next_after_sequence",
    "next_after_entry_sha256",
    "head_sequence",
    "head_entry_sha256",
    "has_more",
  ]);
  const command = record(page.command, "timeline command", [
    "schema_version",
    "target",
    "after_sequence",
    "after_entry_sha256",
    "limit",
    "audience",
  ]);
  if (
    command.schema_version !== "controlgraph.timeline-page-command/v1" ||
    command.audience !== query.audience ||
    command.after_sequence !== query.afterSequence ||
    command.after_entry_sha256 !== query.afterEntrySha256 ||
    command.limit !== query.limit
  ) {
    throw new ContractCodecError("timeline response does not bind its query");
  }
  matchingString(page.command_sha256, "timeline command digest", sha256, 64);
  const target = parseTarget(command.target);
  const entries = array(page.entries, "timeline page entries", query.limit).map(parseEntry);
  let expectedSequence = query.afterSequence + 1;
  let predecessor = query.afterEntrySha256;
  for (const entry of entries) {
    if (
      !sameTarget(entry.target, target) ||
      entry.sequence !== expectedSequence ||
      entry.previousEntrySha256 !== predecessor
    ) {
      throw new ContractCodecError("timeline page is not one contiguous target sequence");
    }
    expectedSequence += 1;
    predecessor = entry.entrySha256;
  }
  const nextCursor: TimelineCursor = {
    afterSequence: integer(page.next_after_sequence, "next sequence"),
    afterEntrySha256: nullableDigest(page.next_after_entry_sha256, "next entry digest"),
  };
  const head: TimelineCursor = {
    afterSequence: integer(page.head_sequence, "head sequence"),
    afterEntrySha256: nullableDigest(page.head_entry_sha256, "head entry digest"),
  };
  if (
    (nextCursor.afterSequence === 0) !== (nextCursor.afterEntrySha256 === null) ||
    (head.afterSequence === 0) !== (head.afterEntrySha256 === null) ||
    nextCursor.afterSequence !== (entries.at(-1)?.sequence ?? query.afterSequence) ||
    nextCursor.afterEntrySha256 !==
      (entries.at(-1)?.entrySha256 ?? query.afterEntrySha256) ||
    nextCursor.afterSequence > head.afterSequence ||
    typeof page.has_more !== "boolean" ||
    page.has_more !== (nextCursor.afterSequence < head.afterSequence) ||
    (head.afterSequence > query.afterSequence && entries.length === 0) ||
    (nextCursor.afterSequence === head.afterSequence &&
      nextCursor.afterEntrySha256 !== head.afterEntrySha256)
  ) {
    throw new ContractCodecError("timeline response cursor is invalid");
  }
  return {
    target,
    entries,
    nextCursor,
    head,
    hasMore: page.has_more,
  };
}

export function targetEquals(left: TargetBinding, right: TargetBinding): boolean {
  return sameTarget(left, right);
}
