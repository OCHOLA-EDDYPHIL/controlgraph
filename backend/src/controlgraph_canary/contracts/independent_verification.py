"""Closed contracts for independent configuration and data-plane verification."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, cast
from urllib.parse import urlsplit

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    Base64Url,
    BoundedText,
    CloudRunName,
    Identifier,
    KeyVersionResource,
    NonNegativeSafeInteger,
    OpaqueToken,
    Percent,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import (
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    canonical_sha256,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
    TrafficAllocation,
)

VERIFICATION_REQUEST_V1: Final = "controlgraph.verification-request/v1"
INDEPENDENT_VERIFICATION_INVOCATION_V1: Final = (
    "controlgraph.independent-verification-invocation/v1"
)
CONFIGURATION_OBSERVATION_FACTS_V1: Final = (
    "controlgraph.configuration-observation-facts/v1"
)
CONFIGURATION_OBSERVATION_V1: Final = "controlgraph.configuration-observation/v1"
CONFIGURATION_ATTESTATION_V1: Final = "controlgraph.configuration-attestation/v1"
PROBE_POLICY_V1: Final = "controlgraph.probe-policy/v1"
PROBE_REQUEST_V1: Final = "controlgraph.probe-request/v1"
SEALED_REFERENCE_PROBE_V1: Final = "controlgraph.sealed-reference-probe/v1"
PROBE_SAMPLE_OBSERVATION_V1: Final = "controlgraph.probe-sample-observation/v1"
PROBE_OBSERVATION_V1: Final = "controlgraph.probe-observation/v1"
PROBE_ATTESTATION_V1: Final = "controlgraph.probe-attestation/v1"
INDEPENDENT_VERIFICATION_EVIDENCE_V1: Final = (
    "controlgraph.independent-verification-evidence/v1"
)
INDEPENDENT_VERIFICATION_SIGNING_REQUEST_V1: Final = (
    "controlgraph.independent-verification-signing-request/v1"
)
SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1: Final = (
    "controlgraph.signed-independent-verification-evidence/v1"
)
INDEPENDENT_VERIFICATION_ATTESTATION_V1: Final = (
    "controlgraph.independent-verification-attestation/v1"
)
VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1: Final = (
    "controlgraph.verified-independent-verification-evidence/v1"
)
EXECUTION_COMPLETION_EVIDENCE_V1: Final = (
    "controlgraph.execution-completion-evidence/v1"
)
AUTHORITY_COMPLETION_EVIDENCE_V1: Final = (
    "controlgraph.authority-completion-evidence/v1"
)
COMPLETION_ASSESSMENT_REQUEST_V1: Final = (
    "controlgraph.completion-assessment-request/v1"
)
COMPLETION_EVIDENCE_BUNDLE_V1: Final = "controlgraph.completion-evidence-bundle/v1"
COMPLETION_CLASSIFICATION_V1: Final = "controlgraph.completion-classification/v1"

INDEPENDENT_VERIFICATION_PURPOSE: Final = "INDEPENDENT_VERIFICATION"
P256_SIGNING_ALGORITHM: Final = "EC_SIGN_P256_SHA256"

_SIGNING_INPUT_DOMAIN: Final = b"controlgraph.independent-verification-evidence/v1\0"
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
_VERIFIER_PREFIX: Final = "controlgraph-verifier@"

ProbeNonce = Annotated[
    str,
    StringConstraints(min_length=32, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
]


class ConfigurationAttestationStatus(StrEnum):
    """Closed outcomes from the read-only Cloud Run configuration read."""

    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"


class ConfigurationAttestationReason(StrEnum):
    """Stable, payload-free configuration observation reasons."""

    MATCH = "CONFIGURATION_MATCH"
    READ_UNAVAILABLE = "CONFIGURATION_READ_UNAVAILABLE"
    RECONCILING = "CONFIGURATION_RECONCILING"
    NOT_READY = "CONFIGURATION_NOT_READY"
    GENERATION_MISMATCH = "CONFIGURATION_GENERATION_MISMATCH"
    REVISION_MAPPING_MISMATCH = "CONFIGURATION_REVISION_MAPPING_MISMATCH"
    TRAFFIC_MISMATCH = "CONFIGURATION_TRAFFIC_MISMATCH"
    CONCURRENCY_MISMATCH = "CONFIGURATION_CONCURRENCY_MISMATCH"
    DIGEST_MISMATCH = "CONFIGURATION_DIGEST_MISMATCH"


class ConfigurationReadyState(StrEnum):
    """Provider readiness reduced to the facts needed by verification."""

    READY = "READY"
    NOT_READY = "NOT_READY"
    UNKNOWN = "UNKNOWN"


class ProbeSampleOutcome(StrEnum):
    """One bounded harmless request outcome."""

    STABLE = "STABLE"
    CANDIDATE = "CANDIDATE"
    RESPONSE_INVALID = "RESPONSE_INVALID"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"


class ProbeAttestationStatus(StrEnum):
    """A probe never turns uncertain data into success."""

    MATCH = "MATCH"
    INCONCLUSIVE = "INCONCLUSIVE"


class ProbeAttestationReason(StrEnum):
    """Stable, payload-free data-plane probe reasons."""

    MATCH = "PROBE_MATCH"
    TRANSPORT_UNAVAILABLE = "PROBE_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "PROBE_RESPONSE_INVALID"
    DISTRIBUTION_MISMATCH = "PROBE_DISTRIBUTION_MISMATCH"


class IndependentVerificationKind(StrEnum):
    """Purpose-separated verifier evidence subjects."""

    CONFIGURATION = "CONFIGURATION"
    PROBE = "PROBE"


class IndependentVerificationVerdict(StrEnum):
    """Common signed verdict vocabulary."""

    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class CompletionKind(StrEnum):
    """Terminal claims classified from required evidence."""

    PROMOTION = "PROMOTION"
    RECOVERY = "RECOVERY"
    REVOCATION = "REVOCATION"
    STALE_CAPABILITY_DENIAL = "STALE_CAPABILITY_DENIAL"


class CompletionStatus(StrEnum):
    """Completion is binary; every unresolved state is ambiguous."""

    COMPLETE = "COMPLETE"
    AMBIGUOUS = "AMBIGUOUS"


class AuthorityCompletionKind(StrEnum):
    """Authority facts admitted for non-target terminal claims."""

    REVOCATION = "REVOCATION"
    EPOCH_ADVANCEMENT = "EPOCH_ADVANCEMENT"


class CompletionReason(StrEnum):
    """Stable terminal classifier reasons in deterministic priority order."""

    PROMOTION_COMPLETE = "PROMOTION_COMPLETE"
    RECOVERY_COMPLETE = "RECOVERY_COMPLETE"
    REVOCATION_COMPLETE = "REVOCATION_COMPLETE"
    STALE_CAPABILITY_DENIAL_COMPLETE = "STALE_CAPABILITY_DENIAL_COMPLETE"
    UNCERTAIN_WRITE = "UNCERTAIN_WRITE"
    EXECUTION_PROOF_ABSENT = "EXECUTION_PROOF_ABSENT"
    EXECUTION_EVIDENCE_CONTRADICTORY = "EXECUTION_EVIDENCE_CONTRADICTORY"
    AUTHORITY_PROOF_ABSENT = "AUTHORITY_PROOF_ABSENT"
    CONFIGURATION_PROOF_ABSENT = "CONFIGURATION_PROOF_ABSENT"
    CONFIGURATION_MISMATCH = "CONFIGURATION_MISMATCH"
    CONFIGURATION_UNAVAILABLE = "CONFIGURATION_UNAVAILABLE"
    PROBE_PROOF_ABSENT = "PROBE_PROOF_ABSENT"
    PROBE_INCONCLUSIVE = "PROBE_INCONCLUSIVE"
    CONFIGURATION_DATA_DISAGREEMENT = "CONFIGURATION_DATA_DISAGREEMENT"
    EVIDENCE_BINDING_MISMATCH = "EVIDENCE_BINDING_MISMATCH"
    EVIDENCE_STALE = "EVIDENCE_STALE"


class VerificationRequestV1(StrictContractModel):
    """One root-, epoch-, target-, plan-, and window-bound verification request."""

    schema_version: Literal["controlgraph.verification-request/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    target: TargetBinding
    plan_sha256: Sha256Digest
    signed_intent_sha256: Sha256Digest
    action: CapabilityAction
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    stable_percent: Percent
    candidate_percent: Percent
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    expected_stable_revision_configuration_sha256: Sha256Digest
    expected_candidate_revision_configuration_sha256: Sha256Digest
    expected_target_configuration_sha256: Sha256Digest
    observation_window_started_at: UtcSecond
    observation_window_ends_at: UtcSecond
    request_id: Identifier
    correlation_id: Identifier

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        prefix = f"{self.target.service_name}-"
        expected_traffic = {
            CapabilityAction.APPLY_CANARY: (90, 10),
            CapabilityAction.PROMOTE_CANDIDATE: (0, 100),
            CapabilityAction.RECOVER_STABLE: (100, 0),
        }[self.action]
        start = _parse_utc(self.observation_window_started_at)
        end = _parse_utc(self.observation_window_ends_at)
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.target.service_name != _REFERENCE_SERVICE
            or self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(prefix)
            or not self.candidate_revision.startswith(prefix)
            or (self.stable_percent, self.candidate_percent) != expected_traffic
            or not start < end
            or (end - start).total_seconds() > 300
        ):
            raise ValueError("verification request bindings are invalid")
        return self


class IndependentVerificationInvocationV1(StrictContractModel):
    """Select one read-only verifier operation without changing its evidence root."""

    schema_version: Literal[
        "controlgraph.independent-verification-invocation/v1"
    ]
    kind: IndependentVerificationKind
    verification: VerificationRequestV1


class ConfigurationObservationFactsV1(StrictContractModel):
    """Canonical provider facts captured by the independent verifier."""

    schema_version: Literal["controlgraph.configuration-observation-facts/v1"]
    target: TargetBinding
    source_generation: PositiveSafeInteger
    observed_generation: NonNegativeSafeInteger
    provider_etag: OpaqueToken
    reconciling: bool
    ready_state: ConfigurationReadyState
    template_revision: CloudRunName
    latest_created_revision: CloudRunName
    latest_ready_revision: CloudRunName
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    traffic: Annotated[tuple[TrafficAllocation, ...], Field(min_length=1, max_length=2)]
    traffic_statuses: Annotated[
        tuple[TrafficAllocation, ...],
        Field(min_length=1, max_length=2),
    ]
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision_configuration_sha256: Sha256Digest
    target_configuration_sha256: Sha256Digest
    retrieved_by: BoundedText
    retrieved_at: UtcSecond

    @model_validator(mode="after")
    def validate_facts(self) -> Self:
        if (
            len({item.revision for item in self.traffic}) != len(self.traffic)
            or len({item.revision for item in self.traffic_statuses})
            != len(self.traffic_statuses)
            or sum(item.percent for item in self.traffic) != 100
            or sum(item.percent for item in self.traffic_statuses) != 100
        ):
            raise ValueError("configuration observation traffic is invalid")
        return self


class ConfigurationObservationV1(StrictContractModel):
    """Provider facts plus their canonical observation digest."""

    schema_version: Literal["controlgraph.configuration-observation/v1"]
    facts: ConfigurationObservationFactsV1
    observation_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.observation_sha256 != canonical_sha256(self.facts):
            raise ValueError("configuration observation digest is invalid")
        return self


class ConfigurationAttestationV1(StrictContractModel):
    """Match, mismatch, or unavailable result; never an executor receipt."""

    schema_version: Literal["controlgraph.configuration-attestation/v1"]
    request: VerificationRequestV1
    request_sha256: Sha256Digest
    status: ConfigurationAttestationStatus
    reason: ConfigurationAttestationReason
    observation: ConfigurationObservationV1 | None
    attested_by: BoundedText
    attested_at: UtcSecond

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        expected_verifier = _verifier_identity(self.request.target)
        if (
            self.request_sha256 != canonical_sha256(self.request)
            or self.attested_by != expected_verifier
            or not _timestamp_in_window(self.attested_at, self.request)
        ):
            raise ValueError("configuration attestation binding is invalid")
        if self.observation is None:
            if (
                self.status is not ConfigurationAttestationStatus.UNAVAILABLE
                or self.reason is not ConfigurationAttestationReason.READ_UNAVAILABLE
            ):
                raise ValueError("missing configuration observation must be unavailable")
            return self
        facts = self.observation.facts
        reason = configuration_attestation_reason(self.request, facts)
        expected_status = (
            ConfigurationAttestationStatus.MATCH
            if reason is ConfigurationAttestationReason.MATCH
            else ConfigurationAttestationStatus.MISMATCH
        )
        if (
            facts.target != self.request.target
            or facts.retrieved_by != expected_verifier
            or not _timestamp_in_window(facts.retrieved_at, self.request)
            or self.reason is not reason
            or self.status is not expected_status
        ):
            raise ValueError("configuration attestation result is inconsistent")
        return self


class ProbePolicyV1(StrictContractModel):
    """Fixed, bounded sampling and retry policy committed by the rollout."""

    schema_version: Literal["controlgraph.probe-policy/v1"]
    sample_count: Literal[20]
    timeout_milliseconds: Literal[2_000]
    max_attempts_per_sample: Literal[1]
    response_limit_bytes: Literal[1_024]
    stable_minimum: Annotated[int, Field(ge=0, le=20)]
    stable_maximum: Annotated[int, Field(ge=0, le=20)]
    candidate_minimum: Annotated[int, Field(ge=0, le=20)]
    candidate_maximum: Annotated[int, Field(ge=0, le=20)]

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        if (
            self.stable_minimum > self.stable_maximum
            or self.candidate_minimum > self.candidate_maximum
            or self.stable_minimum + self.candidate_minimum > self.sample_count
            or self.stable_maximum + self.candidate_maximum < self.sample_count
        ):
            raise ValueError("probe distribution bounds are invalid")
        return self


class ProbeRequestV1(StrictContractModel):
    """A harmless nonce/correlation probe sealed to one allowlisted endpoint."""

    schema_version: Literal["controlgraph.probe-request/v1"]
    verification: VerificationRequestV1
    policy: ProbePolicyV1
    endpoint: Audience
    nonce: ProbeNonce
    started_at: UtcSecond

    @model_validator(mode="after")
    def validate_probe(self) -> Self:
        parsed = urlsplit(self.endpoint)
        expected_bounds = probe_distribution_bounds(
            self.verification.stable_percent,
            self.verification.candidate_percent,
        )
        actual_bounds = (
            self.policy.stable_minimum,
            self.policy.stable_maximum,
            self.policy.candidate_minimum,
            self.policy.candidate_maximum,
        )
        if (
            parsed.path != "/v1/probe"
            or parsed.query
            or parsed.fragment
            or actual_bounds != expected_bounds
            or not _timestamp_in_window(self.started_at, self.verification)
        ):
            raise ValueError("probe request bindings are invalid")
        return self


class SealedReferenceProbeV1(StrictContractModel):
    """Marker-only reference-target response echoing harmless request seals."""

    schema_version: Literal["controlgraph.sealed-reference-probe/v1"]
    revision: CloudRunName
    marker: Identifier
    nonce: ProbeNonce
    correlation_id: Identifier


class ProbeSampleObservationV1(StrictContractModel):
    """One redacted sample retaining only immutable marker facts and a digest."""

    schema_version: Literal["controlgraph.probe-sample-observation/v1"]
    sample_index: Annotated[int, Field(ge=1, le=20)]
    correlation_id: Identifier
    requested_at: UtcSecond
    completed_at: UtcSecond
    outcome: ProbeSampleOutcome
    revision: CloudRunName | None
    marker: Identifier | None
    response_sha256: Sha256Digest | None

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        successful = self.outcome in {
            ProbeSampleOutcome.STABLE,
            ProbeSampleOutcome.CANDIDATE,
        }
        if (
            _parse_utc(self.requested_at) > _parse_utc(self.completed_at)
            or successful
            != (
                self.revision is not None
                and self.marker is not None
                and self.response_sha256 is not None
            )
            or (
                self.outcome is ProbeSampleOutcome.TRANSPORT_UNAVAILABLE
                and self.response_sha256 is not None
            )
        ):
            raise ValueError("probe sample observation shape is invalid")
        return self


class ProbeObservationV1(StrictContractModel):
    """Exactly twenty bounded attempts with immutable aggregate counts."""

    schema_version: Literal["controlgraph.probe-observation/v1"]
    samples: Annotated[tuple[ProbeSampleObservationV1, ...], Field(min_length=20, max_length=20)]
    stable_count: Annotated[int, Field(ge=0, le=20)]
    candidate_count: Annotated[int, Field(ge=0, le=20)]
    invalid_count: Annotated[int, Field(ge=0, le=20)]
    unavailable_count: Annotated[int, Field(ge=0, le=20)]
    observation_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        outcomes = [sample.outcome for sample in self.samples]
        expected_counts = (
            outcomes.count(ProbeSampleOutcome.STABLE),
            outcomes.count(ProbeSampleOutcome.CANDIDATE),
            outcomes.count(ProbeSampleOutcome.RESPONSE_INVALID),
            outcomes.count(ProbeSampleOutcome.TRANSPORT_UNAVAILABLE),
        )
        actual_counts = (
            self.stable_count,
            self.candidate_count,
            self.invalid_count,
            self.unavailable_count,
        )
        expected_correlations = [sample.correlation_id for sample in self.samples]
        if (
            actual_counts != expected_counts
            or sum(actual_counts) != 20
            or [sample.sample_index for sample in self.samples] != list(range(1, 21))
            or len(set(expected_correlations)) != 20
            or self.observation_sha256 != probe_observation_sha256(self.samples)
        ):
            raise ValueError("probe observation is inconsistent")
        return self


class ProbeAttestationV1(StrictContractModel):
    """Request-bound synthetic data-plane observation."""

    schema_version: Literal["controlgraph.probe-attestation/v1"]
    request: ProbeRequestV1
    request_sha256: Sha256Digest
    status: ProbeAttestationStatus
    reason: ProbeAttestationReason
    observation: ProbeObservationV1
    attested_by: BoundedText
    completed_at: UtcSecond

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        reason = probe_attestation_reason(self.request.policy, self.observation)
        expected_status = (
            ProbeAttestationStatus.MATCH
            if reason is ProbeAttestationReason.MATCH
            else ProbeAttestationStatus.INCONCLUSIVE
        )
        verification = self.request.verification
        prefix = f"{verification.correlation_id}:"
        if (
            self.request_sha256 != canonical_sha256(self.request)
            or self.attested_by != _verifier_identity(verification.target)
            or self.reason is not reason
            or self.status is not expected_status
            or not _timestamp_in_window(self.completed_at, verification)
            or any(
                sample.correlation_id != f"{prefix}{sample.sample_index}"
                or not _timestamp_in_window(sample.requested_at, verification)
                or not _timestamp_in_window(sample.completed_at, verification)
                for sample in self.observation.samples
            )
        ):
            raise ValueError("probe attestation binding is invalid")
        return self


class IndependentVerificationEvidenceV1(StrictContractModel):
    """Purpose-separated signed digest of one independent verifier result."""

    schema_version: Literal["controlgraph.independent-verification-evidence/v1"]
    kind: IndependentVerificationKind
    verification_request_sha256: Sha256Digest
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    target: TargetBinding
    plan_sha256: Sha256Digest
    signed_intent_sha256: Sha256Digest
    action: CapabilityAction
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    stable_percent: Percent
    candidate_percent: Percent
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    request_id: Identifier
    correlation_id: Identifier
    observation_window_started_at: UtcSecond
    observation_window_ends_at: UtcSecond
    subject_sha256: Sha256Digest
    verdict: IndependentVerificationVerdict
    reason_code: BoundedText
    verifier_identity: BoundedText
    occurred_at: UtcSecond


class IndependentVerificationSigningRequestV1(StrictContractModel):
    """Exact result bundle admitted to the verifier-only signing route."""

    schema_version: Literal[
        "controlgraph.independent-verification-signing-request/v1"
    ]
    configuration: ConfigurationAttestationV1 | None = None
    probe: ProbeAttestationV1 | None = None
    evidence: IndependentVerificationEvidenceV1

    @model_validator(mode="after")
    def validate_signing_request(self) -> Self:
        if (self.configuration is None) == (self.probe is None):
            raise ValueError("exactly one independent verification result is required")
        if self.configuration is not None:
            configuration = self.configuration
            verification: VerificationRequestV1 = configuration.request
            kind = IndependentVerificationKind.CONFIGURATION
            verdict = {
                ConfigurationAttestationStatus.MATCH: IndependentVerificationVerdict.MATCH,
                ConfigurationAttestationStatus.MISMATCH: IndependentVerificationVerdict.MISMATCH,
                ConfigurationAttestationStatus.UNAVAILABLE: (
                    IndependentVerificationVerdict.UNAVAILABLE
                ),
            }[configuration.status]
            reason = configuration.reason.value
            occurred_at = configuration.attested_at
            subject_sha256 = canonical_sha256(configuration)
        else:
            assert self.probe is not None
            probe = self.probe
            verification = probe.request.verification
            kind = IndependentVerificationKind.PROBE
            verdict = (
                IndependentVerificationVerdict.MATCH
                if probe.status is ProbeAttestationStatus.MATCH
                else IndependentVerificationVerdict.INCONCLUSIVE
            )
            reason = probe.reason.value
            occurred_at = probe.completed_at
            subject_sha256 = canonical_sha256(probe)
        evidence = self.evidence
        if (
            evidence.kind is not kind
            or evidence.verification_request_sha256 != canonical_sha256(verification)
            or evidence.root_id != verification.root_id
            or evidence.root_sha256 != verification.root_sha256
            or evidence.epoch != verification.epoch
            or evidence.target != verification.target
            or evidence.plan_sha256 != verification.plan_sha256
            or evidence.signed_intent_sha256 != verification.signed_intent_sha256
            or evidence.action is not verification.action
            or evidence.stable_revision != verification.stable_revision
            or evidence.candidate_revision != verification.candidate_revision
            or evidence.stable_percent != verification.stable_percent
            or evidence.candidate_percent != verification.candidate_percent
            or evidence.concurrency != verification.concurrency
            or evidence.request_id != verification.request_id
            or evidence.correlation_id != verification.correlation_id
            or evidence.observation_window_started_at
            != verification.observation_window_started_at
            or evidence.observation_window_ends_at != verification.observation_window_ends_at
            or evidence.subject_sha256 != subject_sha256
            or evidence.verdict is not verdict
            or evidence.reason_code != reason
            or evidence.verifier_identity != _verifier_identity(verification.target)
            or evidence.occurred_at != occurred_at
        ):
            raise ValueError("independent verification evidence is not result-bound")
        return self


class SignedIndependentVerificationEvidenceV1(StrictContractModel):
    """Evidence-writer signature over one verifier-owned evidence payload."""

    schema_version: Literal[
        "controlgraph.signed-independent-verification-evidence/v1"
    ]
    evidence: IndependentVerificationEvidenceV1
    purpose: Literal["INDEPENDENT_VERIFICATION"]
    signing_key_version: KeyVersionResource
    signing_algorithm: Literal["EC_SIGN_P256_SHA256"]
    payload_sha256: Sha256Digest
    signing_input_sha256: Sha256Digest
    signature: Base64Url

    @model_validator(mode="after")
    def validate_signature_bindings(self) -> Self:
        if (
            self.payload_sha256 != canonical_sha256(self.evidence)
            or self.signing_input_sha256
            != independent_verification_signing_input_sha256(
                self.evidence,
                self.signing_key_version,
            )
        ):
            raise ValueError("independent verification signature binding is invalid")
        return self


class IndependentVerificationAttestationV1(StrictContractModel):
    """One verifier result and the evidence-writer signature that binds it."""

    schema_version: Literal[
        "controlgraph.independent-verification-attestation/v1"
    ]
    signing_request: IndependentVerificationSigningRequestV1
    signed_evidence: SignedIndependentVerificationEvidenceV1

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        if self.signed_evidence.evidence != self.signing_request.evidence:
            raise ValueError("signed independent attestation is substituted")
        return self


class VerifiedIndependentVerificationEvidenceV1(StrictContractModel):
    """A signature-verified result retained for the pure terminal classifier."""

    schema_version: Literal[
        "controlgraph.verified-independent-verification-evidence/v1"
    ]
    signing_request: IndependentVerificationSigningRequestV1
    signed_evidence: SignedIndependentVerificationEvidenceV1
    verified_at: UtcSecond

    @model_validator(mode="after")
    def validate_verified_evidence(self) -> Self:
        if (
            self.signed_evidence.evidence != self.signing_request.evidence
            or _parse_utc(self.verified_at)
            < _parse_utc(self.signing_request.evidence.occurred_at)
        ):
            raise ValueError("verified independent evidence binding is invalid")
        return self


class ExecutionCompletionEvidenceV1(StrictContractModel):
    """Prevalidated durable receipt facts; never a target observation."""

    schema_version: Literal["controlgraph.execution-completion-evidence/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    target: TargetBinding
    plan_sha256: Sha256Digest
    signed_intent_sha256: Sha256Digest
    intent_signature_verified: Literal[True]
    request_id: Identifier
    correlation_id: Identifier
    observation_window_started_at: UtcSecond
    observation_window_ends_at: UtcSecond
    action: CapabilityAction
    outcome: ReceiptOutcome
    reason_code: ReasonCode | None
    receipt_sha256: Sha256Digest
    receipt_persisted: Literal[True]
    write_outcome_known: bool

    @model_validator(mode="after")
    def validate_receipt_facts(self) -> Self:
        needs_reason = self.outcome in {
            ReceiptOutcome.DENIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.AMBIGUOUS,
        }
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or _parse_utc(self.observation_window_started_at)
            >= _parse_utc(self.observation_window_ends_at)
            or needs_reason != (self.reason_code is not None)
            or (self.outcome is ReceiptOutcome.AMBIGUOUS)
            != (not self.write_outcome_known)
            or (
                self.outcome is ReceiptOutcome.AMBIGUOUS
                and self.reason_code is not ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS
            )
        ):
            raise ValueError("execution completion evidence is inconsistent")
        return self


class AuthorityCompletionEvidenceV1(StrictContractModel):
    """Signature-verified authority fact bound to one completion assessment."""

    schema_version: Literal["controlgraph.authority-completion-evidence/v1"]
    kind: AuthorityCompletionKind
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    target: TargetBinding
    plan_sha256: Sha256Digest
    request_id: Identifier
    correlation_id: Identifier
    observation_window_started_at: UtcSecond
    observation_window_ends_at: UtcSecond
    authority_evidence_sha256: Sha256Digest
    signature_verified: Literal[True]
    occurred_at: UtcSecond

    @model_validator(mode="after")
    def validate_authority_fact(self) -> Self:
        occurred = _parse_utc(self.occurred_at)
        start = _parse_utc(self.observation_window_started_at)
        end = _parse_utc(self.observation_window_ends_at)
        if self.root_id != f"cgroot:{self.root_sha256}" or not start <= occurred <= end:
            raise ValueError("authority completion evidence is inconsistent")
        return self


class CompletionAssessmentRequestV1(StrictContractModel):
    """Exact terminal claim to be classified from a closed evidence bundle."""

    schema_version: Literal["controlgraph.completion-assessment-request/v1"]
    kind: CompletionKind
    verification: VerificationRequestV1
    assessed_at: UtcSecond

    @model_validator(mode="after")
    def validate_assessment(self) -> Self:
        expected_action = {
            CompletionKind.PROMOTION: CapabilityAction.PROMOTE_CANDIDATE,
            CompletionKind.RECOVERY: CapabilityAction.RECOVER_STABLE,
        }.get(self.kind)
        if (
            (expected_action is not None and self.verification.action is not expected_action)
            or _parse_utc(self.assessed_at)
            < _parse_utc(self.verification.observation_window_ends_at)
        ):
            raise ValueError("completion assessment request is invalid")
        return self


class CompletionEvidenceBundleV1(StrictContractModel):
    """All evidence made available to the deterministic completion classifier."""

    schema_version: Literal["controlgraph.completion-evidence-bundle/v1"]
    request: CompletionAssessmentRequestV1
    execution: ExecutionCompletionEvidenceV1 | None = None
    configuration: VerifiedIndependentVerificationEvidenceV1 | None = None
    probe: VerifiedIndependentVerificationEvidenceV1 | None = None
    authority: AuthorityCompletionEvidenceV1 | None = None

    @model_validator(mode="after")
    def validate_evidence_kinds(self) -> Self:
        if (
            self.configuration is not None
            and self.configuration.signing_request.evidence.kind
            is not IndependentVerificationKind.CONFIGURATION
        ) or (
            self.probe is not None
            and self.probe.signing_request.evidence.kind
            is not IndependentVerificationKind.PROBE
        ):
            raise ValueError("completion evidence occupies the wrong slot")
        return self


class CompletionClassificationV1(StrictContractModel):
    """Stable terminal result from the pure fail-closed classifier."""

    schema_version: Literal["controlgraph.completion-classification/v1"]
    request: CompletionAssessmentRequestV1
    bundle_sha256: Sha256Digest
    status: CompletionStatus
    reason: CompletionReason
    follow_up_required: bool
    follow_up_after_seconds: Literal[5] | None
    follow_up_attempt_limit: Literal[3] | None
    classified_at: UtcSecond

    @model_validator(mode="after")
    def validate_terminal_shape(self) -> Self:
        complete_reason = {
            CompletionKind.PROMOTION: CompletionReason.PROMOTION_COMPLETE,
            CompletionKind.RECOVERY: CompletionReason.RECOVERY_COMPLETE,
            CompletionKind.REVOCATION: CompletionReason.REVOCATION_COMPLETE,
            CompletionKind.STALE_CAPABILITY_DENIAL: (
                CompletionReason.STALE_CAPABILITY_DENIAL_COMPLETE
            ),
        }[self.request.kind]
        if (
            self.classified_at != self.request.assessed_at
            or (self.status is CompletionStatus.AMBIGUOUS) != self.follow_up_required
            or self.follow_up_required
            != (
                self.follow_up_after_seconds == 5
                and self.follow_up_attempt_limit == 3
            )
            or (self.status is CompletionStatus.COMPLETE)
            != (self.reason is complete_reason)
        ):
            raise ValueError("completion classification shape is invalid")
        return self


def configuration_attestation_reason(
    request: VerificationRequestV1,
    facts: ConfigurationObservationFactsV1,
) -> ConfigurationAttestationReason:
    """Return the first stable mismatch reason in a deterministic order."""

    if facts.reconciling:
        return ConfigurationAttestationReason.RECONCILING
    if facts.ready_state is not ConfigurationReadyState.READY:
        return ConfigurationAttestationReason.NOT_READY
    if facts.source_generation != facts.observed_generation:
        return ConfigurationAttestationReason.GENERATION_MISMATCH
    if (
        facts.template_revision != request.candidate_revision
        or facts.latest_created_revision != request.candidate_revision
        or facts.latest_ready_revision != request.candidate_revision
        or facts.stable_revision != request.stable_revision
        or facts.candidate_revision != request.candidate_revision
    ):
        return ConfigurationAttestationReason.REVISION_MAPPING_MISMATCH
    expected = {
        request.stable_revision: request.stable_percent,
        request.candidate_revision: request.candidate_percent,
    }
    if (
        not _traffic_matches_expected(facts.traffic, expected)
        or not _traffic_matches_expected(facts.traffic_statuses, expected)
    ):
        return ConfigurationAttestationReason.TRAFFIC_MISMATCH
    if facts.concurrency != request.concurrency:
        return ConfigurationAttestationReason.CONCURRENCY_MISMATCH
    if (
        facts.stable_revision_configuration_sha256
        != request.expected_stable_revision_configuration_sha256
        or facts.candidate_revision_configuration_sha256
        != request.expected_candidate_revision_configuration_sha256
        or facts.target_configuration_sha256
        != request.expected_target_configuration_sha256
    ):
        return ConfigurationAttestationReason.DIGEST_MISMATCH
    return ConfigurationAttestationReason.MATCH


def _traffic_matches_expected(
    allocations: tuple[TrafficAllocation, ...],
    expected: dict[str, int],
) -> bool:
    """Normalize a provider-omitted zero allocation without admitting another revision."""

    observed = {item.revision: item.percent for item in allocations}
    return set(observed).issubset(expected) and all(
        observed.get(revision, 0) == percent
        for revision, percent in expected.items()
    )


def probe_distribution_bounds(
    stable_percent: int,
    candidate_percent: int,
) -> tuple[int, int, int, int]:
    """Return the sole accepted bounds for the fixed twenty-sample probe."""

    if (stable_percent, candidate_percent) == (100, 0):
        return 20, 20, 0, 0
    if (stable_percent, candidate_percent) == (90, 10):
        return 14, 19, 1, 6
    if (stable_percent, candidate_percent) == (0, 100):
        return 0, 0, 20, 20
    raise ValueError("unsupported probe traffic distribution")


def probe_attestation_reason(
    policy: ProbePolicyV1,
    observation: ProbeObservationV1,
) -> ProbeAttestationReason:
    """Reduce bounded sample outcomes without treating uncertainty as success."""

    if observation.unavailable_count:
        return ProbeAttestationReason.TRANSPORT_UNAVAILABLE
    if observation.invalid_count:
        return ProbeAttestationReason.RESPONSE_INVALID
    if not (
        policy.stable_minimum <= observation.stable_count <= policy.stable_maximum
        and policy.candidate_minimum
        <= observation.candidate_count
        <= policy.candidate_maximum
    ):
        return ProbeAttestationReason.DISTRIBUTION_MISMATCH
    return ProbeAttestationReason.MATCH


def probe_observation_sha256(
    samples: tuple[ProbeSampleObservationV1, ...],
) -> str:
    """Hash the complete ordered, redacted sample sequence."""

    value = [sample.model_dump(mode="json") for sample in samples]
    return hashlib.sha256(
        b"controlgraph.probe-observation/v1\0"
        + canonical_json_value_bytes(cast(RestrictedJson, value))
    ).hexdigest()


def independent_verification_signing_input_sha256(
    evidence: IndependentVerificationEvidenceV1,
    signing_key_version: str,
) -> str:
    """Domain-separate an independent verifier evidence signature."""

    payload = canonical_json_bytes(evidence)
    framed = (
        _SIGNING_INPUT_DOMAIN
        + len(signing_key_version.encode("utf-8")).to_bytes(4, "big")
        + signing_key_version.encode("utf-8")
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return hashlib.sha256(framed).hexdigest()


def _verifier_identity(target: TargetBinding) -> str:
    return f"{_VERIFIER_PREFIX}{target.project_id}.iam.gserviceaccount.com"


def _timestamp_in_window(value: str, request: VerificationRequestV1) -> bool:
    timestamp = _parse_utc(value)
    return (
        _parse_utc(request.observation_window_started_at)
        <= timestamp
        <= _parse_utc(request.observation_window_ends_at)
    )


def _parse_utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "AUTHORITY_COMPLETION_EVIDENCE_V1",
    "COMPLETION_ASSESSMENT_REQUEST_V1",
    "COMPLETION_CLASSIFICATION_V1",
    "COMPLETION_EVIDENCE_BUNDLE_V1",
    "CONFIGURATION_ATTESTATION_V1",
    "CONFIGURATION_OBSERVATION_FACTS_V1",
    "CONFIGURATION_OBSERVATION_V1",
    "EXECUTION_COMPLETION_EVIDENCE_V1",
    "INDEPENDENT_VERIFICATION_ATTESTATION_V1",
    "INDEPENDENT_VERIFICATION_EVIDENCE_V1",
    "INDEPENDENT_VERIFICATION_INVOCATION_V1",
    "INDEPENDENT_VERIFICATION_PURPOSE",
    "INDEPENDENT_VERIFICATION_SIGNING_REQUEST_V1",
    "P256_SIGNING_ALGORITHM",
    "PROBE_ATTESTATION_V1",
    "PROBE_OBSERVATION_V1",
    "PROBE_POLICY_V1",
    "PROBE_REQUEST_V1",
    "PROBE_SAMPLE_OBSERVATION_V1",
    "SEALED_REFERENCE_PROBE_V1",
    "SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1",
    "VERIFICATION_REQUEST_V1",
    "VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1",
    "AuthorityCompletionEvidenceV1",
    "AuthorityCompletionKind",
    "CompletionAssessmentRequestV1",
    "CompletionClassificationV1",
    "CompletionEvidenceBundleV1",
    "CompletionKind",
    "CompletionReason",
    "CompletionStatus",
    "ConfigurationAttestationReason",
    "ConfigurationAttestationStatus",
    "ConfigurationAttestationV1",
    "ConfigurationObservationFactsV1",
    "ConfigurationObservationV1",
    "ConfigurationReadyState",
    "ExecutionCompletionEvidenceV1",
    "IndependentVerificationAttestationV1",
    "IndependentVerificationEvidenceV1",
    "IndependentVerificationInvocationV1",
    "IndependentVerificationKind",
    "IndependentVerificationSigningRequestV1",
    "IndependentVerificationVerdict",
    "ProbeAttestationReason",
    "ProbeAttestationStatus",
    "ProbeAttestationV1",
    "ProbeObservationV1",
    "ProbePolicyV1",
    "ProbeRequestV1",
    "ProbeSampleObservationV1",
    "ProbeSampleOutcome",
    "SealedReferenceProbeV1",
    "SignedIndependentVerificationEvidenceV1",
    "VerificationRequestV1",
    "VerifiedIndependentVerificationEvidenceV1",
    "configuration_attestation_reason",
    "independent_verification_signing_input_sha256",
    "probe_attestation_reason",
    "probe_distribution_bounds",
    "probe_observation_sha256",
]
