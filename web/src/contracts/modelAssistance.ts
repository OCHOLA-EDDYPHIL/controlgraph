import {
  ContractCodecError,
  canonicalSha256,
  decodeVersionedCanonicalJson,
} from "./canonical";
import { targetEquals, type TargetBinding } from "./timeline";

export const ADVISOR_OPERATOR_COMMAND_VERSION =
  "controlgraph.advisor-operator-command/v1" as const;
export const ADVISOR_OPERATOR_RESULT_VERSION =
  "controlgraph.advisor-operator-result/v1" as const;

const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const sha256 = /^[0-9a-f]{64}$/;
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

const evidenceKinds = ["root", "target", "health", "receipt", "timeline", "verifier"] as const;
const requestedActions = [
  "wait",
  "collect_approved_diagnostics",
  "request_revocation",
  "request_captured_stable_recovery",
  "request_new_operator_approved_rollout",
  "manual_review",
] as const;
const toolIds = [
  "read_root_summary",
  "read_target_summary",
  "read_health_summary",
  "read_receipt_summary",
  "read_timeline_summary",
  "read_verifier_summary",
] as const;
const toolStatuses = ["succeeded", "denied", "failed"] as const;
const validationCodes = [
  "accepted",
  "snapshot_digest_mismatch",
  "target_mismatch",
  "root_mismatch",
  "epoch_mismatch",
  "evidence_stale",
  "evidence_incomplete",
  "evidence_conflict",
  "citation_invalid",
  "low_confidence",
  "action_not_allowed",
  "model_response_invalid",
  "tool_call_invalid",
] as const;
const fallbackCodes = [
  "timeout",
  "quota",
  "malformed_output",
  "model_unavailable",
  "unsafe_recommendation",
  "tool_error",
] as const;
const dispositions = [
  "pending_review",
  "accepted_for_consideration",
  "rejected",
  "expired",
] as const;
const promptVersions = [
  "controlgraph.rollout-advisor-prompt/v1",
  "controlgraph.rollout-advisor-prompt/v2",
] as const;

export type DiagnosticEvidenceKind = (typeof evidenceKinds)[number];
export type RequestedOperatorAction = (typeof requestedActions)[number];
export type DiagnosticToolId = (typeof toolIds)[number];
export type ToolCallStatus = (typeof toolStatuses)[number];
export type RecommendationValidationCode = (typeof validationCodes)[number];
export type AdvisorFallbackCode = (typeof fallbackCodes)[number];
export type OperatorDisposition = (typeof dispositions)[number];
export type AdvisorPromptVersion = (typeof promptVersions)[number];

export interface AdvisorOperatorCommandWire {
  readonly schema_version: typeof ADVISOR_OPERATOR_COMMAND_VERSION;
  readonly request_id: string;
  readonly idempotency_key: string;
  readonly target: TargetBinding;
  readonly root_id: string;
  readonly expected_root_sha256: string;
  readonly expected_epoch: number;
  readonly requested_at: string;
}

export interface EvidenceCitation {
  readonly evidence_kind: DiagnosticEvidenceKind;
  readonly evidence_id: string;
  readonly source_sha256: string;
}

export interface DiagnosticFinding {
  readonly statement: string;
  readonly citations: readonly EvidenceCitation[];
}

export interface AdvisorRecommendation {
  readonly schema_version: "controlgraph.advisor-recommendation/v1";
  readonly recommendation_id: string;
  readonly snapshot_sha256: string;
  readonly target: TargetBinding;
  readonly root_id: string;
  readonly current_epoch: number;
  readonly findings: readonly DiagnosticFinding[];
  readonly assumptions: readonly string[];
  readonly uncertainties: readonly string[];
  readonly confidence_basis_points: number;
  readonly requested_operator_action: RequestedOperatorAction;
  readonly manual_review_reason: string | null;
  readonly operator_review_required: true;
  readonly authority_effect: "none";
  readonly deterministic_health_override: false;
}

export interface AdvisorToolCallAudit {
  readonly schema_version: "controlgraph.advisor-tool-call-audit/v1";
  readonly sequence: number;
  readonly tool_id: DiagnosticToolId;
  readonly input_sha256: string;
  readonly output_sha256: string | null;
  readonly status: ToolCallStatus;
}

export interface AdvisorValidation {
  readonly schema_version: "controlgraph.advisor-validation/v1";
  readonly accepted: boolean;
  readonly codes: readonly RecommendationValidationCode[];
}

export interface AdvisorInteractionAudit {
  readonly schema_version: "controlgraph.advisor-interaction-audit/v1";
  readonly interaction_id: string;
  readonly correlation_id: string;
  readonly model_id: "gemini-3.5-flash";
  readonly model_location: "global";
  readonly prompt_version: AdvisorPromptVersion;
  readonly registry_sha256: string;
  readonly snapshot_sha256: string;
  readonly tool_calls: readonly AdvisorToolCallAudit[];
  readonly cited_evidence_ids: readonly string[];
  readonly structured_output_sha256: string | null;
  readonly validation: AdvisorValidation;
  readonly operator_disposition: OperatorDisposition;
  readonly fallback_code: AdvisorFallbackCode | null;
}

export interface AdvisorResponse {
  readonly schema_version: "controlgraph.advisor-response/v1";
  readonly request_sha256: string;
  readonly recommendation: AdvisorRecommendation | null;
  readonly audit: AdvisorInteractionAudit;
  readonly manual_next_step:
    "review_named_evidence_and_use_deterministic_operator_commands_only";
}

export interface AdvisorOperatorResult {
  readonly schema_version: typeof ADVISOR_OPERATOR_RESULT_VERSION;
  readonly command_sha256: string;
  readonly interaction_id: string;
  readonly target: TargetBinding;
  readonly root_id: string;
  readonly root_sha256: string;
  readonly epoch: number;
  readonly response: AdvisorResponse;
  readonly replayed: boolean;
}

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
  const output = value as Record<string, unknown>;
  const allowlist = new Set(allowed);
  if (Object.keys(output).some((key) => !allowlist.has(key))) {
    throw new ContractCodecError(`${name} contains an unknown field`);
  }
  return output;
}

function array(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): readonly unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
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
  const output = string(value, name, 1, maximum);
  if (
    unsafeRenderingControl.test(output) ||
    secretPatterns.some((pattern) => pattern.test(output))
  ) {
    throw new ContractCodecError(`${name} is unsafe to render`);
  }
  return output;
}

function matchingString(
  value: unknown,
  name: string,
  pattern: RegExp,
  maximum = 512,
): string {
  const output = string(value, name, 1, maximum);
  if (!pattern.test(output)) {
    throw new ContractCodecError(`${name} is invalid`);
  }
  return output;
}

function integer(value: unknown, name: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
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

function parseTarget(value: unknown): TargetBinding {
  const item = record(value, "advisor target", [
    "schema_version",
    "project_id",
    "region",
    "environment",
    "service_name",
  ]);
  if (item.schema_version !== "controlgraph.target-binding/v1") {
    throw new ContractCodecError("advisor target version is unsupported");
  }
  return {
    schema_version: "controlgraph.target-binding/v1",
    project_id: matchingString(item.project_id, "advisor target project", /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/, 30),
    region: matchingString(item.region, "advisor target region", /^[a-z]+-[a-z]+[0-9]+$/, 32),
    environment: matchingString(item.environment, "advisor target environment", identifier, 128),
    service_name: matchingString(item.service_name, "advisor target service", /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/, 63),
  };
}

function parseCitation(value: unknown): EvidenceCitation {
  const item = record(value, "advisor citation", [
    "evidence_kind",
    "evidence_id",
    "source_sha256",
  ]);
  return {
    evidence_kind: enumeration(item.evidence_kind, "advisor citation kind", evidenceKinds),
    evidence_id: matchingString(item.evidence_id, "advisor citation evidence", identifier, 128),
    source_sha256: matchingString(item.source_sha256, "advisor citation source", sha256, 64),
  };
}

function parseFinding(value: unknown): DiagnosticFinding {
  const item = record(value, "advisor finding", ["statement", "citations"]);
  const citations = array(item.citations, "advisor finding citations", 1, 8).map(parseCitation);
  const unique = new Set(
    citations.map((citation) =>
      `${citation.evidence_kind}\0${citation.evidence_id}\0${citation.source_sha256}`,
    ),
  );
  if (unique.size !== citations.length) {
    throw new ContractCodecError("advisor finding citations are duplicated");
  }
  return {
    statement: safeText(item.statement, "advisor finding"),
    citations,
  };
}

function parseRecommendation(value: unknown): AdvisorRecommendation {
  const item = record(value, "advisor recommendation", [
    "schema_version",
    "recommendation_id",
    "snapshot_sha256",
    "target",
    "root_id",
    "current_epoch",
    "findings",
    "assumptions",
    "uncertainties",
    "confidence_basis_points",
    "requested_operator_action",
    "manual_review_reason",
    "operator_review_required",
    "authority_effect",
    "deterministic_health_override",
  ]);
  const action = enumeration(
    item.requested_operator_action,
    "advisor requested action",
    requestedActions,
  );
  const manualReviewReason =
    item.manual_review_reason === null
      ? null
      : safeText(item.manual_review_reason, "advisor manual review reason");
  const confidence = integer(
    item.confidence_basis_points,
    "advisor confidence",
    0,
    10_000,
  );
  if (
    item.schema_version !== "controlgraph.advisor-recommendation/v1" ||
    item.operator_review_required !== true ||
    item.authority_effect !== "none" ||
    item.deterministic_health_override !== false ||
    (action === "manual_review") !== (manualReviewReason !== null) ||
    (confidence < 7_000 && action !== "manual_review")
  ) {
    throw new ContractCodecError("advisor recommendation violates its authority boundary");
  }
  return {
    schema_version: "controlgraph.advisor-recommendation/v1",
    recommendation_id: matchingString(item.recommendation_id, "advisor recommendation id", identifier, 128),
    snapshot_sha256: matchingString(item.snapshot_sha256, "advisor snapshot digest", sha256, 64),
    target: parseTarget(item.target),
    root_id: matchingString(item.root_id, "advisor root id", identifier, 128),
    current_epoch: integer(item.current_epoch, "advisor current epoch", 1),
    findings: array(item.findings, "advisor findings", 1, 8).map(parseFinding),
    assumptions: array(item.assumptions, "advisor assumptions", 0, 8).map((entry) =>
      safeText(entry, "advisor assumption"),
    ),
    uncertainties: array(item.uncertainties, "advisor uncertainties", 1, 8).map((entry) =>
      safeText(entry, "advisor uncertainty"),
    ),
    confidence_basis_points: confidence,
    requested_operator_action: action,
    manual_review_reason: manualReviewReason,
    operator_review_required: true,
    authority_effect: "none",
    deterministic_health_override: false,
  };
}

function parseToolCall(value: unknown, expectedSequence: number): AdvisorToolCallAudit {
  const item = record(value, "advisor tool audit", [
    "schema_version",
    "sequence",
    "tool_id",
    "input_sha256",
    "output_sha256",
    "status",
  ]);
  const status = enumeration(item.status, "advisor tool status", toolStatuses);
  const output = nullableDigest(item.output_sha256, "advisor tool output digest");
  if (
    item.schema_version !== "controlgraph.advisor-tool-call-audit/v1" ||
    integer(item.sequence, "advisor tool sequence", 1, 6) !== expectedSequence ||
    (status === "succeeded") !== (output !== null)
  ) {
    throw new ContractCodecError("advisor tool audit is inconsistent");
  }
  return {
    schema_version: "controlgraph.advisor-tool-call-audit/v1",
    sequence: expectedSequence,
    tool_id: enumeration(item.tool_id, "advisor tool id", toolIds),
    input_sha256: matchingString(item.input_sha256, "advisor tool input digest", sha256, 64),
    output_sha256: output,
    status,
  };
}

function parseValidation(value: unknown): AdvisorValidation {
  const item = record(value, "advisor validation", ["schema_version", "accepted", "codes"]);
  const codes = array(item.codes, "advisor validation codes", 1, 8).map((entry) =>
    enumeration(entry, "advisor validation code", validationCodes),
  );
  if (
    item.schema_version !== "controlgraph.advisor-validation/v1" ||
    typeof item.accepted !== "boolean" ||
    new Set(codes).size !== codes.length ||
    item.accepted !== (codes.length === 1 && codes[0] === "accepted")
  ) {
    throw new ContractCodecError("advisor validation is inconsistent");
  }
  return {
    schema_version: "controlgraph.advisor-validation/v1",
    accepted: item.accepted,
    codes,
  };
}

function parseAudit(value: unknown): AdvisorInteractionAudit {
  const item = record(value, "advisor audit", [
    "schema_version",
    "interaction_id",
    "correlation_id",
    "model_id",
    "model_location",
    "prompt_version",
    "registry_sha256",
    "snapshot_sha256",
    "tool_calls",
    "cited_evidence_ids",
    "structured_output_sha256",
    "validation",
    "operator_disposition",
    "fallback_code",
  ]);
  const toolCalls = array(item.tool_calls, "advisor tool calls", 0, 6).map((entry, index) =>
    parseToolCall(entry, index + 1),
  );
  const citedEvidenceIds = array(
    item.cited_evidence_ids,
    "advisor cited evidence",
    0,
    64,
  ).map((entry) => matchingString(entry, "advisor cited evidence id", identifier, 128));
  const validation = parseValidation(item.validation);
  const structuredOutput = nullableDigest(
    item.structured_output_sha256,
    "advisor structured output digest",
  );
  const fallback =
    item.fallback_code === null
      ? null
      : enumeration(item.fallback_code, "advisor fallback", fallbackCodes);
  const successfulToolIds = new Set(
    toolCalls
      .filter((tool) => tool.status === "succeeded")
      .map((tool) => tool.tool_id),
  );
  if (
    item.schema_version !== "controlgraph.advisor-interaction-audit/v1" ||
    item.model_id !== "gemini-3.5-flash" ||
    item.model_location !== "global" ||
    new Set(citedEvidenceIds).size !== citedEvidenceIds.length ||
    (validation.accepted && (structuredOutput === null || fallback !== null)) ||
    (!validation.accepted && fallback === null) ||
    (validation.accepted &&
      (toolCalls.length !== toolIds.length ||
        successfulToolIds.size !== toolIds.length ||
        toolIds.some((toolId) => !successfulToolIds.has(toolId))))
  ) {
    throw new ContractCodecError("advisor audit is inconsistent");
  }
  return {
    schema_version: "controlgraph.advisor-interaction-audit/v1",
    interaction_id: matchingString(item.interaction_id, "advisor interaction id", identifier, 128),
    correlation_id: matchingString(item.correlation_id, "advisor correlation id", identifier, 128),
    model_id: "gemini-3.5-flash",
    model_location: "global",
    prompt_version: enumeration(item.prompt_version, "advisor prompt version", promptVersions),
    registry_sha256: matchingString(item.registry_sha256, "advisor registry digest", sha256, 64),
    snapshot_sha256: matchingString(item.snapshot_sha256, "advisor audit snapshot digest", sha256, 64),
    tool_calls: toolCalls,
    cited_evidence_ids: citedEvidenceIds,
    structured_output_sha256: structuredOutput,
    validation,
    operator_disposition: enumeration(item.operator_disposition, "advisor disposition", dispositions),
    fallback_code: fallback,
  };
}

function parseResponse(value: unknown): AdvisorResponse {
  const item = record(value, "advisor response", [
    "schema_version",
    "request_sha256",
    "recommendation",
    "audit",
    "manual_next_step",
  ]);
  if (
    item.schema_version !== "controlgraph.advisor-response/v1" ||
    item.manual_next_step !==
      "review_named_evidence_and_use_deterministic_operator_commands_only"
  ) {
    throw new ContractCodecError("advisor response is unsupported");
  }
  const recommendation =
    item.recommendation === null ? null : parseRecommendation(item.recommendation);
  const audit = parseAudit(item.audit);
  if (audit.validation.accepted !== (recommendation !== null)) {
    throw new ContractCodecError("advisor response does not match validation");
  }
  return {
    schema_version: "controlgraph.advisor-response/v1",
    request_sha256: matchingString(item.request_sha256, "advisor request digest", sha256, 64),
    recommendation,
    audit,
    manual_next_step:
      "review_named_evidence_and_use_deterministic_operator_commands_only",
  };
}

export async function decodeAdvisorOperatorResult(
  text: string,
  command: AdvisorOperatorCommandWire,
): Promise<AdvisorOperatorResult> {
  const decoded = decodeVersionedCanonicalJson(text, ADVISOR_OPERATOR_RESULT_VERSION);
  const item = record(decoded, "advisor result", [
    "schema_version",
    "command_sha256",
    "interaction_id",
    "target",
    "root_id",
    "root_sha256",
    "epoch",
    "response",
    "replayed",
  ]);
  const response = parseResponse(item.response);
  const target = parseTarget(item.target);
  const rootId = matchingString(item.root_id, "advisor result root id", identifier, 128);
  const rootSha256 = matchingString(item.root_sha256, "advisor result root digest", sha256, 64);
  const epoch = integer(item.epoch, "advisor result epoch", 1);
  const interactionId = matchingString(
    item.interaction_id,
    "advisor result interaction id",
    identifier,
    128,
  );
  const commandSha256 = matchingString(
    item.command_sha256,
    "advisor command digest",
    sha256,
    64,
  );
  const recommendation = response.recommendation;
  if (
    typeof item.replayed !== "boolean" ||
    commandSha256 !== await canonicalSha256(ADVISOR_OPERATOR_COMMAND_VERSION, command) ||
    !targetEquals(target, command.target) ||
    rootId !== command.root_id ||
    rootSha256 !== command.expected_root_sha256 ||
    epoch !== command.expected_epoch ||
    rootId !== `cgroot:${rootSha256}` ||
    interactionId !== response.audit.interaction_id ||
    response.audit.correlation_id !== command.request_id ||
    (recommendation !== null &&
      (!targetEquals(recommendation.target, target) ||
        recommendation.root_id !== rootId ||
        recommendation.current_epoch !== epoch ||
        recommendation.snapshot_sha256 !== response.audit.snapshot_sha256 ||
        response.audit.structured_output_sha256 !==
          await canonicalSha256(recommendation.schema_version, recommendation)))
  ) {
    throw new ContractCodecError("advisor result binding is invalid");
  }
  const recommendationCitations = new Set(
    recommendation?.findings.flatMap((finding) =>
      finding.citations.map((citation) => citation.evidence_id),
    ) ?? [],
  );
  if (
    recommendationCitations.size !== response.audit.cited_evidence_ids.length ||
    response.audit.cited_evidence_ids.some(
      (evidenceId) => !recommendationCitations.has(evidenceId),
    )
  ) {
    throw new ContractCodecError("advisor result citations are not audit-bound");
  }
  return {
    schema_version: ADVISOR_OPERATOR_RESULT_VERSION,
    command_sha256: commandSha256,
    interaction_id: interactionId,
    target,
    root_id: rootId,
    root_sha256: rootSha256,
    epoch,
    response,
    replayed: item.replayed,
  };
}
