"""Closed contracts for bounded, read-only model assistance."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    CloudRunName,
    Identifier,
    Percent,
    PositiveSafeInteger,
    Sha256Digest,
    ShortText,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import TargetBinding

DIAGNOSTIC_EVIDENCE_SUMMARY_V1: Final = "controlgraph.diagnostic-evidence-summary/v1"
DIAGNOSTIC_EVIDENCE_FACT_V1: Final = "controlgraph.diagnostic-evidence-fact/v1"
DIAGNOSTIC_SNAPSHOT_V1: Final = "controlgraph.diagnostic-snapshot/v1"
DIAGNOSTIC_TOOL_INPUT_V1: Final = "controlgraph.diagnostic-tool-input/v1"
DIAGNOSTIC_TOOL_RESULT_V1: Final = "controlgraph.diagnostic-tool-result/v1"
DIAGNOSTIC_TOOL_DEFINITION_V1: Final = "controlgraph.diagnostic-tool-definition/v1"
DIAGNOSTIC_REGISTRY_V1: Final = "controlgraph.diagnostic-registry/v1"
ADVISOR_INVOCATION_REQUEST_V1: Final = "controlgraph.advisor-invocation-request/v1"
ADVISOR_RECOMMENDATION_V1: Final = "controlgraph.advisor-recommendation/v1"
ADVISOR_VALIDATION_V1: Final = "controlgraph.advisor-validation/v1"
ADVISOR_TOOL_CALL_AUDIT_V1: Final = "controlgraph.advisor-tool-call-audit/v1"
ADVISOR_INTERACTION_AUDIT_V1: Final = "controlgraph.advisor-interaction-audit/v1"
ADVISOR_RESPONSE_V1: Final = "controlgraph.advisor-response/v1"
ADVISOR_OPERATOR_COMMAND_V1: Final = "controlgraph.advisor-operator-command/v1"
ADVISOR_OPERATOR_INVOCATION_V1: Final = "controlgraph.advisor-operator-invocation/v1"
ADVISOR_OPERATOR_RESULT_V1: Final = "controlgraph.advisor-operator-result/v1"
ADVISOR_DISPOSITION_COMMAND_V1: Final = "controlgraph.advisor-disposition-command/v1"
ADVISOR_DISPOSITION_INVOCATION_V1: Final = (
    "controlgraph.advisor-disposition-invocation/v1"
)
ADVISOR_DISPOSITION_RESULT_V1: Final = "controlgraph.advisor-disposition-result/v1"
MODEL_ASSISTANCE_TIMELINE_AUDIT_V1: Final = (
    "controlgraph.model-assistance-timeline-audit/v1"
)

MODEL_ID: Final = "gemini-3.5-flash"
MODEL_LOCATION: Final = "global"
PROMPT_VERSION: Final = "controlgraph.rollout-advisor-prompt/v1"

MAX_EVIDENCE_AGE_SECONDS: Final = 300
MAX_SNAPSHOT_LIFETIME_SECONDS: Final = 300
MAX_TOOL_RESPONSE_BYTES: Final = 4_096
MAX_TOOL_CALLS: Final = 6
MAX_LLM_CALLS: Final = 4
MAX_MODEL_OUTPUT_BYTES: Final = 16_384
MAX_MODEL_OUTPUT_TOKENS: Final = 2_048
MIN_ACTION_CONFIDENCE_BASIS_POINTS: Final = 7_000

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(
    r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)
_MAX_ID_TOKEN_LIFETIME_SECONDS: Final = 3_660

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


class DiagnosticEvidenceKind(StrEnum):
    """The complete evidence classes exposed to the model."""

    ROOT = "root"
    TARGET = "target"
    HEALTH = "health"
    RECEIPT = "receipt"
    TIMELINE = "timeline"
    VERIFIER = "verifier"


class DiagnosticEvidenceSummaryCode(StrEnum):
    """Closed model-visible descriptions of validated M6 record families."""

    ROOT_RECORD_VERIFIED = "root_record_verified"
    TARGET_OBSERVATION_VERIFIED = "target_observation_verified"
    HEALTH_EVIDENCE_VERIFIED = "health_evidence_verified"
    RECEIPT_RECORD_VERIFIED = "receipt_record_verified"
    TIMELINE_PROJECTION_VERIFIED = "timeline_projection_verified"
    VERIFIER_EVIDENCE_VERIFIED = "verifier_evidence_verified"


class DiagnosticEvidenceFactName(StrEnum):
    """Closed fact names that may be exposed from verified M6 records."""

    STABLE_REVISION = "stable_revision"
    CANDIDATE_REVISION = "candidate_revision"
    INITIAL_EPOCH = "initial_epoch"
    VERIFICATION_KIND = "verification_kind"
    VERIFICATION_VERDICT = "verification_verdict"
    MONITORING_COMPLETENESS = "monitoring_completeness"
    MONITORING_WINDOW = "monitoring_window"
    HEALTH_STATUS = "health_status"
    RECEIPT_OUTCOME = "receipt_outcome"
    TIMELINE_HEAD_SEQUENCE = "timeline_head_sequence"
    TIMELINE_LATEST_EVENT = "timeline_latest_event"
    TERMINAL_CLASSIFICATION = "terminal_classification"


class DiagnosticToolId(StrEnum):
    """The complete read-only diagnostic tool allowlist."""

    READ_ROOT_SUMMARY = "read_root_summary"
    READ_TARGET_SUMMARY = "read_target_summary"
    READ_HEALTH_SUMMARY = "read_health_summary"
    READ_RECEIPT_SUMMARY = "read_receipt_summary"
    READ_TIMELINE_SUMMARY = "read_timeline_summary"
    READ_VERIFIER_SUMMARY = "read_verifier_summary"


class EvidenceConsistency(StrEnum):
    """Coordinator assessment of whether the assembled evidence agrees."""

    CONSISTENT = "consistent"
    CONFLICTING = "conflicting"
    INCOMPLETE = "incomplete"


class RolloutPhase(StrEnum):
    """Closed rollout phases used only to constrain advisory actions."""

    STABLE = "stable"
    CANARY = "canary"
    PROMOTED = "promoted"
    RECOVERY_PENDING = "recovery_pending"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class AdvisoryHealth(StrEnum):
    """Imported deterministic health state; the model cannot alter it."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


class RequestedOperatorAction(StrEnum):
    """The only actions a recommendation may ask an operator to consider."""

    WAIT = "wait"
    COLLECT_APPROVED_DIAGNOSTICS = "collect_approved_diagnostics"
    REQUEST_REVOCATION = "request_revocation"
    REQUEST_CAPTURED_STABLE_RECOVERY = "request_captured_stable_recovery"
    REQUEST_NEW_OPERATOR_APPROVED_ROLLOUT = "request_new_operator_approved_rollout"
    MANUAL_REVIEW = "manual_review"


class RecommendationValidationCode(StrEnum):
    """Stable deterministic validation results without model text."""

    ACCEPTED = "accepted"
    SNAPSHOT_DIGEST_MISMATCH = "snapshot_digest_mismatch"
    TARGET_MISMATCH = "target_mismatch"
    ROOT_MISMATCH = "root_mismatch"
    EPOCH_MISMATCH = "epoch_mismatch"
    EVIDENCE_STALE = "evidence_stale"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    EVIDENCE_CONFLICT = "evidence_conflict"
    CITATION_INVALID = "citation_invalid"
    LOW_CONFIDENCE = "low_confidence"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    MODEL_RESPONSE_INVALID = "model_response_invalid"
    TOOL_CALL_INVALID = "tool_call_invalid"


class AdvisorFallbackCode(StrEnum):
    """Side-effect-free outcomes for unavailable or unsafe assistance."""

    TIMEOUT = "timeout"
    QUOTA = "quota"
    MALFORMED_OUTPUT = "malformed_output"
    MODEL_UNAVAILABLE = "model_unavailable"
    UNSAFE_RECOMMENDATION = "unsafe_recommendation"
    TOOL_ERROR = "tool_error"


class OperatorDisposition(StrEnum):
    """Review state recorded separately from any authority-bearing command."""

    PENDING_REVIEW = "pending_review"
    ACCEPTED_FOR_CONSIDERATION = "accepted_for_consideration"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ModelAssistanceLifecycle(StrEnum):
    """Append-only lifecycle stages projected into the M6 timeline."""

    COMPLETED = "completed"
    FALLBACK = "fallback"
    REPLAYED = "replayed"
    DISPOSITION_RECORDED = "disposition_recorded"
    DISPOSITION_REPLAYED = "disposition_replayed"


class ModelAssistanceActorRole(StrEnum):
    """Authenticated actor class responsible for one audit lifecycle event."""

    ADVISOR = "advisor"
    OPERATOR = "operator"


class ToolCallStatus(StrEnum):
    """Sanitized outcome of one allowlisted tool call."""

    SUCCEEDED = "succeeded"
    DENIED = "denied"
    FAILED = "failed"


class DiagnosticEvidenceFactV1(StrictContractModel):
    """One bounded fact copied from an identified M6 record."""

    schema_version: Literal["controlgraph.diagnostic-evidence-fact/v1"]
    evidence_id: Identifier
    name: DiagnosticEvidenceFactName
    value: ShortText

    @model_validator(mode="after")
    def validate_value(self) -> Self:
        closed_values = {
            DiagnosticEvidenceFactName.VERIFICATION_KIND: {
                "CONFIGURATION",
                "PROBE",
            },
            DiagnosticEvidenceFactName.VERIFICATION_VERDICT: {
                "MATCH",
                "MISMATCH",
                "UNAVAILABLE",
                "INCONCLUSIVE",
            },
            DiagnosticEvidenceFactName.MONITORING_COMPLETENESS: {
                "COMPLETE",
                "PARTIAL",
                "MISSING",
            },
            DiagnosticEvidenceFactName.HEALTH_STATUS: {
                "healthy",
                "unhealthy",
                "wait",
                "insufficient-evidence",
            },
            DiagnosticEvidenceFactName.RECEIPT_OUTCOME: {
                "CLAIMED",
                "DENIED",
                "APPLIED",
                "VERIFIED",
                "FAILED_SAFE",
                "AMBIGUOUS",
            },
            DiagnosticEvidenceFactName.TIMELINE_LATEST_EVENT: {
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
            },
            DiagnosticEvidenceFactName.TERMINAL_CLASSIFICATION: {
                "NONE",
                "PROMOTED",
                "RECOVERED",
                "REVOKED",
                "DENIED",
                "FAILED_SAFE",
                "AMBIGUOUS",
            },
        }
        if self.name in closed_values and self.value not in closed_values[self.name]:
            raise ValueError("diagnostic evidence fact value is outside its domain")
        if self.name in {
            DiagnosticEvidenceFactName.INITIAL_EPOCH,
            DiagnosticEvidenceFactName.MONITORING_WINDOW,
            DiagnosticEvidenceFactName.TIMELINE_HEAD_SEQUENCE,
        } and (not self.value.isascii() or not self.value.isdigit()):
            raise ValueError("diagnostic evidence numeric fact is invalid")
        if (
            self.name
            in {
                DiagnosticEvidenceFactName.STABLE_REVISION,
                DiagnosticEvidenceFactName.CANDIDATE_REVISION,
            }
            and re.fullmatch(
                r"controlgraph-reference-target-(?:stable|candidate)(?:-v[1-9][0-9]*)?",
                self.value,
            )
            is None
        ):
            raise ValueError("diagnostic evidence revision fact is invalid")
        return self


class DiagnosticEvidenceSummaryV1(StrictContractModel):
    """Bounded facts and citations from one validated M6 evidence class."""

    schema_version: Literal["controlgraph.diagnostic-evidence-summary/v1"]
    evidence_kind: DiagnosticEvidenceKind
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=16)]
    source_sha256: Sha256Digest
    observed_at: UtcSecond
    fresh_until: UtcSecond
    summary_code: DiagnosticEvidenceSummaryCode
    facts: Annotated[tuple[DiagnosticEvidenceFactV1, ...], Field(min_length=1, max_length=16)]
    redacted: Literal[True]
    untrusted_model_context: Literal[True]

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence identifiers must be unique")
        if _utc(self.observed_at) >= _utc(self.fresh_until):
            raise ValueError("evidence freshness interval is invalid")
        expected_code = dict(
            zip(
                tuple(DiagnosticEvidenceKind),
                tuple(DiagnosticEvidenceSummaryCode),
                strict=True,
            )
        )[self.evidence_kind]
        if self.summary_code is not expected_code:
            raise ValueError("diagnostic summary code does not match its evidence class")
        fact_keys = tuple((fact.evidence_id, fact.name.value) for fact in self.facts)
        if (
            any(fact.evidence_id not in self.evidence_ids for fact in self.facts)
            or len(set(fact_keys)) != len(fact_keys)
            or fact_keys != tuple(sorted(fact_keys))
        ):
            raise ValueError("diagnostic evidence facts are not canonically bound")
        required = {
            DiagnosticEvidenceKind.ROOT: {
                DiagnosticEvidenceFactName.STABLE_REVISION,
                DiagnosticEvidenceFactName.CANDIDATE_REVISION,
                DiagnosticEvidenceFactName.INITIAL_EPOCH,
            },
            DiagnosticEvidenceKind.TARGET: {
                DiagnosticEvidenceFactName.VERIFICATION_KIND,
                DiagnosticEvidenceFactName.VERIFICATION_VERDICT,
            },
            DiagnosticEvidenceKind.HEALTH: {
                DiagnosticEvidenceFactName.MONITORING_COMPLETENESS,
                DiagnosticEvidenceFactName.MONITORING_WINDOW,
                DiagnosticEvidenceFactName.HEALTH_STATUS,
            },
            DiagnosticEvidenceKind.RECEIPT: {
                DiagnosticEvidenceFactName.RECEIPT_OUTCOME,
            },
            DiagnosticEvidenceKind.TIMELINE: {
                DiagnosticEvidenceFactName.TIMELINE_HEAD_SEQUENCE,
                DiagnosticEvidenceFactName.TIMELINE_LATEST_EVENT,
                DiagnosticEvidenceFactName.TERMINAL_CLASSIFICATION,
            },
            DiagnosticEvidenceKind.VERIFIER: {
                DiagnosticEvidenceFactName.VERIFICATION_KIND,
                DiagnosticEvidenceFactName.VERIFICATION_VERDICT,
            },
        }[self.evidence_kind]
        if not required.issubset({fact.name for fact in self.facts}):
            raise ValueError("diagnostic evidence facts are incomplete")
        return self


class DiagnosticSnapshotV1(StrictContractModel):
    """Coordinator-assembled immutable input for one advisory invocation."""

    schema_version: Literal["controlgraph.diagnostic-snapshot/v1"]
    snapshot_id: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    current_epoch: PositiveSafeInteger
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    recovery_revision: CloudRunName
    stable_percent: Percent
    candidate_percent: Percent
    rollout_phase: RolloutPhase
    authority_revoked: bool
    health: AdvisoryHealth
    terminal_health: bool
    health_policy_sha256: Sha256Digest
    evidence_consistency: EvidenceConsistency
    assembled_at: UtcSecond
    expires_at: UtcSecond
    root_summary: DiagnosticEvidenceSummaryV1
    target_summary: DiagnosticEvidenceSummaryV1
    health_summary: DiagnosticEvidenceSummaryV1
    receipt_summary: DiagnosticEvidenceSummaryV1
    timeline_summary: DiagnosticEvidenceSummaryV1
    verifier_summary: DiagnosticEvidenceSummaryV1

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        expected_kinds = (
            DiagnosticEvidenceKind.ROOT,
            DiagnosticEvidenceKind.TARGET,
            DiagnosticEvidenceKind.HEALTH,
            DiagnosticEvidenceKind.RECEIPT,
            DiagnosticEvidenceKind.TIMELINE,
            DiagnosticEvidenceKind.VERIFIER,
        )
        summaries = self.evidence_summaries
        assembled_at = _utc(self.assembled_at)
        expires_at = _utc(self.expires_at)
        prefix = f"{self.target.service_name}-"
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(self.target.project_id) is None
            or "reconcile" in self.target.project_id.lower()
            or self.target.region != "us-central1"
            or self.target.environment != "nonprod"
            or self.target.service_name != "controlgraph-reference-target"
        ):
            raise ValueError("diagnostic target is outside ControlGraph")
        if self.root_id != f"cgroot:{self.root_sha256}":
            raise ValueError("diagnostic root binding is invalid")
        if (
            self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(prefix)
            or not self.candidate_revision.startswith(prefix)
            or self.recovery_revision != self.stable_revision
        ):
            raise ValueError("diagnostic revision binding is invalid")
        if (self.stable_percent, self.candidate_percent) not in {
            (100, 0),
            (90, 10),
            (0, 100),
        }:
            raise ValueError("diagnostic traffic is outside the closed rollout policy")
        traffic = (self.stable_percent, self.candidate_percent)
        expected_traffic = {
            RolloutPhase.STABLE: (100, 0),
            RolloutPhase.CANARY: (90, 10),
            RolloutPhase.PROMOTED: (0, 100),
            RolloutPhase.RECOVERY_PENDING: (90, 10),
            RolloutPhase.REVOKED: (90, 10),
        }
        if (
            self.rollout_phase is not RolloutPhase.UNKNOWN
            and traffic != expected_traffic[self.rollout_phase]
        ):
            raise ValueError("diagnostic rollout phase and traffic disagree")
        if expires_at <= assembled_at or int((expires_at - assembled_at).total_seconds()) > (
            MAX_SNAPSHOT_LIFETIME_SECONDS
        ):
            raise ValueError("diagnostic snapshot lifetime is invalid")
        all_ids: list[str] = []
        for expected_kind, summary in zip(expected_kinds, summaries, strict=True):
            if summary.evidence_kind is not expected_kind:
                raise ValueError("diagnostic evidence class is misplaced")
            observed_at = _utc(summary.observed_at)
            fresh_until = _utc(summary.fresh_until)
            if observed_at > assembled_at or fresh_until < expires_at:
                raise ValueError("diagnostic evidence is stale or future-dated")
            if (
                expected_kind is not DiagnosticEvidenceKind.ROOT
                and int((assembled_at - observed_at).total_seconds()) > MAX_EVIDENCE_AGE_SECONDS
            ):
                raise ValueError("diagnostic evidence is stale or future-dated")
            all_ids.extend(summary.evidence_ids)
        if len(set(all_ids)) != len(all_ids):
            raise ValueError("evidence identifiers must be unique across the snapshot")
        if self.terminal_health and self.health not in {
            AdvisoryHealth.HEALTHY,
            AdvisoryHealth.UNHEALTHY,
        }:
            raise ValueError("terminal health must contain a deterministic result")
        return self

    @property
    def evidence_summaries(self) -> tuple[DiagnosticEvidenceSummaryV1, ...]:
        return (
            self.root_summary,
            self.target_summary,
            self.health_summary,
            self.receipt_summary,
            self.timeline_summary,
            self.verifier_summary,
        )


class DiagnosticModelContextV1(StrictContractModel):
    """Closed rollout facts exposed by every diagnostic tool result."""

    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    current_epoch: PositiveSafeInteger
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    recovery_revision: CloudRunName
    stable_percent: Percent
    candidate_percent: Percent
    rollout_phase: RolloutPhase
    authority_revoked: bool
    health: AdvisoryHealth
    terminal_health: bool
    health_policy_sha256: Sha256Digest
    evidence_consistency: EvidenceConsistency
    assembled_at: UtcSecond
    expires_at: UtcSecond

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        prefix = f"{self.target.service_name}-"
        expected_traffic = {
            RolloutPhase.STABLE: (100, 0),
            RolloutPhase.CANARY: (90, 10),
            RolloutPhase.PROMOTED: (0, 100),
            RolloutPhase.RECOVERY_PENDING: (90, 10),
            RolloutPhase.REVOKED: (90, 10),
        }
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(self.target.project_id) is None
            or "reconcile" in self.target.project_id.lower()
            or self.target.region != "us-central1"
            or self.target.environment != "nonprod"
            or self.target.service_name != "controlgraph-reference-target"
            or self.root_id != f"cgroot:{self.root_sha256}"
            or self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(prefix)
            or not self.candidate_revision.startswith(prefix)
            or self.recovery_revision != self.stable_revision
            or (self.stable_percent, self.candidate_percent)
            not in {(100, 0), (90, 10), (0, 100)}
            or (
                self.rollout_phase is not RolloutPhase.UNKNOWN
                and (self.stable_percent, self.candidate_percent)
                != expected_traffic[self.rollout_phase]
            )
            or _utc(self.expires_at) <= _utc(self.assembled_at)
            or (
                self.terminal_health
                and self.health not in {AdvisoryHealth.HEALTHY, AdvisoryHealth.UNHEALTHY}
            )
        ):
            raise ValueError("diagnostic model context is invalid")
        return self


class DiagnosticToolInputV1(StrictContractModel):
    """The only model-controlled input accepted by a diagnostic tool."""

    schema_version: Literal["controlgraph.diagnostic-tool-input/v1"]
    snapshot_sha256: Sha256Digest


class DiagnosticToolResultV1(StrictContractModel):
    """One bounded tool result drawn from the invocation-bound snapshot."""

    schema_version: Literal["controlgraph.diagnostic-tool-result/v1"]
    tool_id: DiagnosticToolId
    snapshot_sha256: Sha256Digest
    evidence: DiagnosticEvidenceSummaryV1
    context: DiagnosticModelContextV1


class DiagnosticToolDefinitionV1(StrictContractModel):
    """Inspectable contract for one model-visible read-only operation."""

    schema_version: Literal["controlgraph.diagnostic-tool-definition/v1"]
    tool_id: DiagnosticToolId
    input_schema: Literal["controlgraph.diagnostic-tool-input/v1"]
    output_schema: Literal["controlgraph.diagnostic-tool-result/v1"]
    execution_identity: Literal["controlgraph-advisor"]
    timeout_ms: Annotated[int, Field(ge=1, le=1_000)]
    max_response_bytes: Annotated[int, Field(ge=1, le=MAX_TOOL_RESPONSE_BYTES)]
    target_scope: Literal["invocation_snapshot"]
    evidence_source: DiagnosticEvidenceKind
    read_only: Literal[True]
    redaction_required: Literal[True]


class DiagnosticRegistryV1(StrictContractModel):
    """The exact registry made visible to the ADK coordinator."""

    schema_version: Literal["controlgraph.diagnostic-registry/v1"]
    tools: Annotated[
        tuple[DiagnosticToolDefinitionV1, ...],
        Field(min_length=MAX_TOOL_CALLS, max_length=MAX_TOOL_CALLS),
    ]

    @model_validator(mode="after")
    def validate_registry(self) -> Self:
        expected = tuple(DiagnosticToolId)
        if tuple(tool.tool_id for tool in self.tools) != expected:
            raise ValueError("diagnostic registry is not the exact allowlist")
        if tuple(tool.evidence_source for tool in self.tools) != tuple(
            DiagnosticEvidenceKind
        ):
            raise ValueError("diagnostic registry evidence sources are invalid")
        return self


class AdvisorInvocationRequestV1(StrictContractModel):
    """One coordinator-authenticated, side-effect-free advisory request."""

    schema_version: Literal["controlgraph.advisor-invocation-request/v1"]
    correlation_id: Identifier
    requested_at: UtcSecond
    snapshot: DiagnosticSnapshotV1
    snapshot_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if self.snapshot_sha256 != canonical_sha256(self.snapshot):
            raise ValueError("advisor request is not bound to its exact snapshot")
        return self


class EvidenceCitationV1(StrictContractModel):
    """A named evidence record and its immutable summary source."""

    evidence_kind: DiagnosticEvidenceKind
    evidence_id: Identifier
    source_sha256: Sha256Digest


class DiagnosticFindingV1(StrictContractModel):
    """One concise factual finding with at least one named citation."""

    statement: ShortText
    citations: Annotated[tuple[EvidenceCitationV1, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def validate_citations(self) -> Self:
        keys = tuple(
            (item.evidence_kind, item.evidence_id, item.source_sha256)
            for item in self.citations
        )
        if len(set(keys)) != len(keys):
            raise ValueError("finding citations must be unique")
        return self


class AdvisorRecommendationV1(StrictContractModel):
    """Closed model output with no authority-bearing fields."""

    schema_version: Literal["controlgraph.advisor-recommendation/v1"]
    recommendation_id: Identifier
    snapshot_sha256: Sha256Digest
    target: TargetBinding
    root_id: Identifier
    current_epoch: PositiveSafeInteger
    findings: Annotated[tuple[DiagnosticFindingV1, ...], Field(min_length=1, max_length=8)]
    assumptions: Annotated[tuple[ShortText, ...], Field(max_length=8)]
    uncertainties: Annotated[tuple[ShortText, ...], Field(min_length=1, max_length=8)]
    confidence_basis_points: Annotated[int, Field(ge=0, le=10_000)]
    requested_operator_action: RequestedOperatorAction
    manual_review_reason: ShortText | None
    operator_review_required: bool
    authority_effect: Literal["none"]
    deterministic_health_override: bool

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        manual = self.requested_operator_action is RequestedOperatorAction.MANUAL_REVIEW
        if (
            self.operator_review_required is not True
            or self.deterministic_health_override is not False
        ):
            raise ValueError("recommendation cannot alter the advisory authority boundary")
        if manual != (self.manual_review_reason is not None):
            raise ValueError("manual review reason does not match the requested action")
        if self.confidence_basis_points < MIN_ACTION_CONFIDENCE_BASIS_POINTS and not manual:
            raise ValueError("low-confidence recommendations must request manual review")
        return self


class AdvisorValidationV1(StrictContractModel):
    """Deterministic recommendation validation result."""

    schema_version: Literal["controlgraph.advisor-validation/v1"]
    accepted: bool
    codes: Annotated[
        tuple[RecommendationValidationCode, ...],
        Field(min_length=1, max_length=8),
    ]

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.accepted != (self.codes == (RecommendationValidationCode.ACCEPTED,)):
            raise ValueError("recommendation validation result is inconsistent")
        if len(set(self.codes)) != len(self.codes):
            raise ValueError("recommendation validation codes must be unique")
        return self


class AdvisorToolCallAuditV1(StrictContractModel):
    """Content-free audit facts for one tool call."""

    schema_version: Literal["controlgraph.advisor-tool-call-audit/v1"]
    sequence: PositiveSafeInteger
    tool_id: DiagnosticToolId
    input_sha256: Sha256Digest
    output_sha256: Sha256Digest | None
    status: ToolCallStatus

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if (self.status is ToolCallStatus.SUCCEEDED) != (self.output_sha256 is not None):
            raise ValueError("tool audit output does not match its status")
        return self


class AdvisorInteractionAuditV1(StrictContractModel):
    """Redacted model boundary audit without prompts, credentials, or thoughts."""

    schema_version: Literal["controlgraph.advisor-interaction-audit/v1"]
    interaction_id: Identifier
    correlation_id: Identifier
    model_id: Literal["gemini-3.5-flash"]
    model_location: Literal["global"]
    prompt_version: Literal["controlgraph.rollout-advisor-prompt/v1"]
    registry_sha256: Sha256Digest
    snapshot_sha256: Sha256Digest
    tool_calls: Annotated[
        tuple[AdvisorToolCallAuditV1, ...],
        Field(max_length=MAX_TOOL_CALLS),
    ]
    cited_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=64)]
    structured_output_sha256: Sha256Digest | None
    validation: AdvisorValidationV1
    operator_disposition: OperatorDisposition
    fallback_code: AdvisorFallbackCode | None

    @model_validator(mode="after")
    def validate_audit(self) -> Self:
        if len(set(self.cited_evidence_ids)) != len(self.cited_evidence_ids):
            raise ValueError("audit citations must be unique")
        if tuple(call.sequence for call in self.tool_calls) != tuple(
            range(1, len(self.tool_calls) + 1)
        ):
            raise ValueError("tool audit sequence is invalid")
        if self.validation.accepted:
            if self.structured_output_sha256 is None or self.fallback_code is not None:
                raise ValueError("accepted interaction audit is inconsistent")
        elif self.fallback_code is None:
            raise ValueError("denied interaction audit requires a fallback")
        return self


class AdvisorResponseV1(StrictContractModel):
    """Validated proposal or deterministic side-effect-free fallback."""

    schema_version: Literal["controlgraph.advisor-response/v1"]
    request_sha256: Sha256Digest
    recommendation: AdvisorRecommendationV1 | None
    audit: AdvisorInteractionAuditV1
    manual_next_step: Literal[
        "review_named_evidence_and_use_deterministic_operator_commands_only"
    ]

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        if self.audit.validation.accepted != (self.recommendation is not None):
            raise ValueError("advisor response does not match validation")
        if self.recommendation is not None and (
            self.audit.structured_output_sha256 != canonical_sha256(self.recommendation)
            or self.audit.snapshot_sha256 != self.recommendation.snapshot_sha256
        ):
            raise ValueError("advisor audit does not bind its recommendation")
        return self


class AdvisorOperatorCommandV1(StrictContractModel):
    """Operator request for advice about one exact root and epoch."""

    schema_version: Literal["controlgraph.advisor-operator-command/v1"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    requested_at: UtcSecond

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(self.target.project_id) is None
            or "reconcile" in self.target.project_id.lower()
            or self.target.region != "us-central1"
            or self.target.environment != "nonprod"
            or self.target.service_name != "controlgraph-reference-target"
            or self.root_id != f"cgroot:{self.expected_root_sha256}"
        ):
            raise ValueError("advisor operator scope is invalid")
        return self


class AdvisorOperatorInvocationV1(StrictContractModel):
    """Advice command plus operator identity facts authenticated by the API."""

    schema_version: Literal["controlgraph.advisor-operator-invocation/v1"]
    command: AdvisorOperatorCommandV1
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        if (
            _HUMAN_EMAIL.fullmatch(self.operator_identity) is None
            or self.operator_identity.endswith(".iam.gserviceaccount.com")
            or _API_AUDIENCE.fullmatch(self.operator_audience) is None
            or self.operator_issued_at >= self.operator_expires_at
            or self.operator_expires_at - self.operator_issued_at
            > _MAX_ID_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError("advisor operator invocation is invalid")
        return self


class AdvisorOperatorResultV1(StrictContractModel):
    """One persisted advisor response or its exact idempotent replay."""

    schema_version: Literal["controlgraph.advisor-operator-result/v1"]
    command_sha256: Sha256Digest
    interaction_id: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    response: AdvisorResponseV1
    replayed: bool

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        recommendation = self.response.recommendation
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.interaction_id != self.response.audit.interaction_id
            or (
                recommendation is not None
                and (
                    recommendation.target != self.target
                    or recommendation.root_id != self.root_id
                    or recommendation.current_epoch != self.epoch
                )
            )
        ):
            raise ValueError("advisor operator result binding is invalid")
        return self


class AdvisorDispositionCommandV1(StrictContractModel):
    """Deliberate operator disposition of one persisted advisory interaction."""

    schema_version: Literal["controlgraph.advisor-disposition-command/v1"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    interaction_id: Identifier
    expected_response_sha256: Sha256Digest
    disposition: Literal[
        OperatorDisposition.ACCEPTED_FOR_CONSIDERATION,
        OperatorDisposition.REJECTED,
    ]
    recorded_at: UtcSecond

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(self.target.project_id) is None
            or "reconcile" in self.target.project_id.lower()
            or self.target.region != "us-central1"
            or self.target.environment != "nonprod"
            or self.target.service_name != "controlgraph-reference-target"
            or self.root_id != f"cgroot:{self.expected_root_sha256}"
        ):
            raise ValueError("advisor disposition scope is invalid")
        return self


class AdvisorDispositionInvocationV1(StrictContractModel):
    """Disposition command plus operator identity facts authenticated by the API."""

    schema_version: Literal["controlgraph.advisor-disposition-invocation/v1"]
    command: AdvisorDispositionCommandV1
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        if (
            _HUMAN_EMAIL.fullmatch(self.operator_identity) is None
            or self.operator_identity.endswith(".iam.gserviceaccount.com")
            or _API_AUDIENCE.fullmatch(self.operator_audience) is None
            or self.operator_issued_at >= self.operator_expires_at
            or self.operator_expires_at - self.operator_issued_at
            > _MAX_ID_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError("advisor disposition invocation is invalid")
        return self


class AdvisorDispositionResultV1(StrictContractModel):
    """Persisted disposition result with explicit idempotent replay state."""

    schema_version: Literal["controlgraph.advisor-disposition-result/v1"]
    command_sha256: Sha256Digest
    interaction_id: Identifier
    response_sha256: Sha256Digest
    disposition: Literal[
        OperatorDisposition.ACCEPTED_FOR_CONSIDERATION,
        OperatorDisposition.REJECTED,
    ]
    replayed: bool


class ModelAssistanceTimelineAuditV1(StrictContractModel):
    """Redacted append-only M6 timeline input for model-assistance lifecycle events."""

    schema_version: Literal["controlgraph.model-assistance-timeline-audit/v1"]
    event_id: Identifier
    lifecycle: ModelAssistanceLifecycle
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    request_id: Identifier
    interaction_id: Identifier
    actor_role: ModelAssistanceActorRole
    actor_id: Identifier
    occurred_at: UtcSecond
    command_sha256: Sha256Digest
    response_sha256: Sha256Digest
    audit: AdvisorInteractionAuditV1
    disposition: OperatorDisposition

    @model_validator(mode="after")
    def validate_event(self) -> Self:
        completed = self.audit.validation.accepted
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.interaction_id != self.audit.interaction_id
            or self.epoch <= 0
            or re.fullmatch(r"actor:[0-9a-f]{64}", self.actor_id) is None
            or (
                self.lifecycle
                in {
                    ModelAssistanceLifecycle.DISPOSITION_RECORDED,
                    ModelAssistanceLifecycle.DISPOSITION_REPLAYED,
                }
            )
            != (self.actor_role is ModelAssistanceActorRole.OPERATOR)
            or (
                self.lifecycle is ModelAssistanceLifecycle.COMPLETED
                and (not completed or self.disposition is not OperatorDisposition.PENDING_REVIEW)
            )
            or (
                self.lifecycle is ModelAssistanceLifecycle.FALLBACK
                and (completed or self.disposition is not OperatorDisposition.PENDING_REVIEW)
            )
            or (
                self.lifecycle
                in {
                    ModelAssistanceLifecycle.DISPOSITION_RECORDED,
                    ModelAssistanceLifecycle.DISPOSITION_REPLAYED,
                }
                and self.disposition
                not in {
                    OperatorDisposition.ACCEPTED_FOR_CONSIDERATION,
                    OperatorDisposition.REJECTED,
                }
            )
        ):
            raise ValueError("model-assistance timeline audit binding is invalid")
        return self


def diagnostic_registry_v1() -> DiagnosticRegistryV1:
    """Build the one ordered registry accepted by the advisor runtime."""

    tools = tuple(
        DiagnosticToolDefinitionV1(
            schema_version=DIAGNOSTIC_TOOL_DEFINITION_V1,
            tool_id=tool_id,
            input_schema=DIAGNOSTIC_TOOL_INPUT_V1,
            output_schema=DIAGNOSTIC_TOOL_RESULT_V1,
            execution_identity="controlgraph-advisor",
            timeout_ms=250,
            max_response_bytes=MAX_TOOL_RESPONSE_BYTES,
            target_scope="invocation_snapshot",
            evidence_source=evidence_kind,
            read_only=True,
            redaction_required=True,
        )
        for tool_id, evidence_kind in zip(
            tuple(DiagnosticToolId), tuple(DiagnosticEvidenceKind), strict=True
        )
    )
    return DiagnosticRegistryV1(schema_version=DIAGNOSTIC_REGISTRY_V1, tools=tools)


def diagnostic_model_context(snapshot: DiagnosticSnapshotV1) -> DiagnosticModelContextV1:
    """Project only closed, non-secret rollout facts for a model-visible tool result."""

    if type(snapshot) is not DiagnosticSnapshotV1:
        raise TypeError("an exact diagnostic snapshot is required")
    return DiagnosticModelContextV1(
        target=snapshot.target,
        root_id=snapshot.root_id,
        root_sha256=snapshot.root_sha256,
        current_epoch=snapshot.current_epoch,
        stable_revision=snapshot.stable_revision,
        candidate_revision=snapshot.candidate_revision,
        recovery_revision=snapshot.recovery_revision,
        stable_percent=snapshot.stable_percent,
        candidate_percent=snapshot.candidate_percent,
        rollout_phase=snapshot.rollout_phase,
        authority_revoked=snapshot.authority_revoked,
        health=snapshot.health,
        terminal_health=snapshot.terminal_health,
        health_policy_sha256=snapshot.health_policy_sha256,
        evidence_consistency=snapshot.evidence_consistency,
        assembled_at=snapshot.assembled_at,
        expires_at=snapshot.expires_at,
    )


def _utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "ADVISOR_DISPOSITION_COMMAND_V1",
    "ADVISOR_DISPOSITION_INVOCATION_V1",
    "ADVISOR_DISPOSITION_RESULT_V1",
    "ADVISOR_INTERACTION_AUDIT_V1",
    "ADVISOR_INVOCATION_REQUEST_V1",
    "ADVISOR_OPERATOR_COMMAND_V1",
    "ADVISOR_OPERATOR_INVOCATION_V1",
    "ADVISOR_OPERATOR_RESULT_V1",
    "ADVISOR_RECOMMENDATION_V1",
    "ADVISOR_RESPONSE_V1",
    "ADVISOR_TOOL_CALL_AUDIT_V1",
    "ADVISOR_VALIDATION_V1",
    "DIAGNOSTIC_EVIDENCE_FACT_V1",
    "DIAGNOSTIC_EVIDENCE_SUMMARY_V1",
    "DIAGNOSTIC_REGISTRY_V1",
    "DIAGNOSTIC_SNAPSHOT_V1",
    "DIAGNOSTIC_TOOL_DEFINITION_V1",
    "DIAGNOSTIC_TOOL_INPUT_V1",
    "DIAGNOSTIC_TOOL_RESULT_V1",
    "MAX_LLM_CALLS",
    "MAX_MODEL_OUTPUT_BYTES",
    "MAX_MODEL_OUTPUT_TOKENS",
    "MAX_TOOL_CALLS",
    "MAX_TOOL_RESPONSE_BYTES",
    "MODEL_ASSISTANCE_TIMELINE_AUDIT_V1",
    "MODEL_ID",
    "MODEL_LOCATION",
    "PROMPT_VERSION",
    "AdvisorDispositionCommandV1",
    "AdvisorDispositionInvocationV1",
    "AdvisorDispositionResultV1",
    "AdvisorFallbackCode",
    "AdvisorInteractionAuditV1",
    "AdvisorInvocationRequestV1",
    "AdvisorOperatorCommandV1",
    "AdvisorOperatorInvocationV1",
    "AdvisorOperatorResultV1",
    "AdvisorRecommendationV1",
    "AdvisorResponseV1",
    "AdvisorToolCallAuditV1",
    "AdvisorValidationV1",
    "AdvisoryHealth",
    "DiagnosticEvidenceFactName",
    "DiagnosticEvidenceFactV1",
    "DiagnosticEvidenceKind",
    "DiagnosticEvidenceSummaryCode",
    "DiagnosticEvidenceSummaryV1",
    "DiagnosticFindingV1",
    "DiagnosticModelContextV1",
    "DiagnosticRegistryV1",
    "DiagnosticSnapshotV1",
    "DiagnosticToolDefinitionV1",
    "DiagnosticToolId",
    "DiagnosticToolInputV1",
    "DiagnosticToolResultV1",
    "EvidenceCitationV1",
    "EvidenceConsistency",
    "ModelAssistanceActorRole",
    "ModelAssistanceLifecycle",
    "ModelAssistanceTimelineAuditV1",
    "OperatorDisposition",
    "RecommendationValidationCode",
    "RequestedOperatorAction",
    "RolloutPhase",
    "ToolCallStatus",
    "diagnostic_model_context",
    "diagnostic_registry_v1",
]
