"""Versioned contracts for abandoning an expired ambiguous recovery dispatch."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    CloudRunName,
    Identifier,
    NonNegativeSafeInteger,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import (
    RestrictedJson,
    canonical_json_value_bytes,
    canonical_sha256,
)
from controlgraph_canary.contracts.evidence import EvidenceChainHeadV1
from controlgraph_canary.contracts.models import EpochAuthorityRecord, EvidenceEvent, TargetBinding
from controlgraph_canary.contracts.recovery_execution import RecoveryDispatchRecordV2
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1
from controlgraph_canary.contracts.service_claim_release import ServiceClaimReleaseEvidenceSubjectV1
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecordV3,
    ServiceClaimStableBaselineProofV1,
)

RECOVERY_ABANDONMENT_COMMAND_V1: Final = "controlgraph.recovery-abandonment-command/v1"
RECOVERY_ABANDONMENT_INVOCATION_V1: Final = "controlgraph.recovery-abandonment-invocation/v1"
RECOVERY_ABANDONMENT_EVIDENCE_SUBJECT_V1: Final = (
    "controlgraph.recovery-abandonment-evidence-subject/v1"
)
RECOVERY_ABANDONMENT_FENCE_SUBJECT_V1: Final = "controlgraph.recovery-abandonment-fence-subject/v1"
RECOVERY_ABANDONMENT_IDENTITY_V1: Final = "controlgraph.recovery-abandonment-identity/v1"
RECOVERY_ABANDONMENT_PROGRESS_V1: Final = "controlgraph.recovery-abandonment-progress/v1"
RECOVERY_ABANDONMENT_RESULT_V1: Final = "controlgraph.recovery-abandonment-result/v1"
RECOVERY_ABANDONMENT_RELAY_RESPONSE_V1: Final = (
    "controlgraph.recovery-abandonment-relay-response/v1"
)
RECOVERY_ABANDONMENT_CLASSIFICATION_REQUEST_V1: Final = (
    "controlgraph.recovery-abandonment-classification-request/v1"
)
RECOVERY_ABANDONMENT_CLASSIFICATION_RESULT_V1: Final = (
    "controlgraph.recovery-abandonment-classification-result/v1"
)
RECOVERY_ABANDONMENT_CLASSIFICATION_SUBJECT_V1: Final = (
    "controlgraph.recovery-abandonment-classification-subject/v1"
)
RECOVERY_ABANDONMENT_CLASSIFICATION_SIGNING_REQUEST_V1: Final = (
    "controlgraph.recovery-abandonment-classification-signing-request/v1"
)
RECOVERY_ABANDONMENT_CLASSIFICATION_ATTESTATION_V1: Final = (
    "controlgraph.recovery-abandonment-classification-attestation/v1"
)

_REQUEST_DIGEST_DOMAIN: Final = b"controlgraph.recovery-abandonment-request/v1\0"
_CLASSIFICATION_DIGEST_DOMAIN: Final = (
    b"controlgraph.recovery-abandonment-classification-request/v1\0"
)
_EVIDENCE_ID_DOMAIN: Final = b"controlgraph.recovery-abandonment-evidence-id/v1\0"
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$")

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


class RecoveryAbandonmentIdentityKind(StrEnum):
    REQUEST = "REQUEST"
    IDEMPOTENCY = "IDEMPOTENCY"


class RecoveryAbandonmentPhase(StrEnum):
    FENCED_RESET_REQUIRED = "FENCED_RESET_REQUIRED"
    RELEASED = "RELEASED"


class RecoveryAbandonmentFailureCode(StrEnum):
    CALLER_DENIED = "RECOVERY_ABANDONMENT_CALLER_DENIED"
    COMMAND_DENIED = "RECOVERY_ABANDONMENT_COMMAND_DENIED"
    ROOT_NOT_FOUND = "RECOVERY_ABANDONMENT_ROOT_NOT_FOUND"
    ROOT_MISMATCH = "RECOVERY_ABANDONMENT_ROOT_MISMATCH"
    CLAIM_NOT_ACTIVE = "RECOVERY_ABANDONMENT_CLAIM_NOT_ACTIVE"
    EPOCH_MISMATCH = "RECOVERY_ABANDONMENT_EPOCH_MISMATCH"
    INTENT_INVALID = "RECOVERY_ABANDONMENT_INTENT_INVALID"
    DISPATCH_INVALID = "RECOVERY_ABANDONMENT_DISPATCH_INVALID"
    DISPATCH_NOT_EXPIRED = "RECOVERY_ABANDONMENT_DISPATCH_NOT_EXPIRED"
    RECEIPT_EXISTS = "RECOVERY_ABANDONMENT_RECEIPT_EXISTS"
    IDENTITY_CONFLICT = "RECOVERY_ABANDONMENT_IDENTITY_CONFLICT"
    CLASSIFICATION_DENIED = "RECOVERY_ABANDONMENT_CLASSIFICATION_DENIED"
    EVIDENCE_DENIED = "RECOVERY_ABANDONMENT_EVIDENCE_DENIED"
    TRUSTED_STATE_INVALID = "RECOVERY_ABANDONMENT_TRUSTED_STATE_INVALID"
    STORE_UNAVAILABLE = "RECOVERY_ABANDONMENT_STORE_UNAVAILABLE"
    OUTCOME_UNKNOWN = "RECOVERY_ABANDONMENT_OUTCOME_UNKNOWN"


class RecoveryAbandonmentCommandV1(StrictContractModel):
    """Operator request bound to one exact stranded recovery dispatch."""

    schema_version: Literal["controlgraph.recovery-abandonment-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    recovery_dispatch_id: Identifier
    expected_dispatch_sha256: Sha256Digest
    reason: BoundedText
    request_id: Identifier
    idempotency_key: Identifier
    confirmation: Literal["ABANDON_AMBIGUOUS_RECOVERY"]

    @model_validator(mode="after")
    def validate_root_identity(self) -> Self:
        if self.root_id != f"cgroot:{self.expected_root_sha256}":
            raise ValueError("abandonment root identifier and digest do not match")
        return self


class RecoveryAbandonmentInvocationV1(StrictContractModel):
    """An abandonment command plus operator facts authenticated by the API."""

    schema_version: Literal["controlgraph.recovery-abandonment-invocation/v1"]
    command: RecoveryAbandonmentCommandV1
    attempt_id: Identifier
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_operator(self) -> Self:
        if (
            _HUMAN_EMAIL.fullmatch(self.operator_identity) is None
            or self.operator_identity.endswith(".iam.gserviceaccount.com")
            or _API_AUDIENCE.fullmatch(self.operator_audience) is None
            or self.operator_issued_at >= self.operator_expires_at
            or self.operator_expires_at - self.operator_issued_at > 3_660
        ):
            raise ValueError("abandonment invocation operator binding is invalid")
        return self


class RecoveryAbandonmentEvidenceSubjectV1(StrictContractModel):
    """Facts atomically established when an expired enqueue outcome is abandoned."""

    schema_version: Literal["controlgraph.recovery-abandonment-evidence-subject/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    recovery_dispatch_id: Identifier
    previous_dispatch_sha256: Sha256Digest
    ambiguous_dispatch_sha256: Sha256Digest
    previous_dispatch_revision: Annotated[int, Field(ge=0, le=2)]
    ambiguous_dispatch_revision: Annotated[int, Field(ge=1, le=3)]
    task_id: Identifier
    task_name: BoundedText
    task_sha256: Sha256Digest
    capability_id: Identifier
    capability_sha256: Sha256Digest
    task_expires_at: UtcSecond
    recovery_receipt_id: Identifier
    receipt_absent_at_fence: Literal[True]
    reason: BoundedText
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    evidence_id: Identifier
    abandoned_at: UtcSecond

    @model_validator(mode="after")
    def validate_subject(self) -> Self:
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.previous_dispatch_revision + 1 != self.ambiguous_dispatch_revision
            or self.task_expires_at > self.abandoned_at
        ):
            raise ValueError("recovery abandonment evidence is invalid")
        return self


class RecoveryAbandonmentFenceSubjectV1(StrictContractModel):
    """Exact claim-version and authority transition coupled to abandonment."""

    schema_version: Literal["controlgraph.recovery-abandonment-fence-subject/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    abandonment_evidence_id: Identifier
    abandonment_evidence_sha256: Sha256Digest
    previous_claim_sha256: Sha256Digest
    replacement_claim_sha256: Sha256Digest
    previous_authority_sha256: Sha256Digest
    replacement_authority_sha256: Sha256Digest
    previous_epoch: PositiveSafeInteger
    new_epoch: PositiveSafeInteger
    evidence_id: Identifier
    fenced_at: UtcSecond

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        if self.new_epoch != self.previous_epoch + 1:
            raise ValueError("abandonment fence must advance exactly one epoch")
        return self


class RecoveryAbandonmentClassificationRequestV1(StrictContractModel):
    """Expected stable-only state sent to the independent verifier."""

    schema_version: Literal["controlgraph.recovery-abandonment-classification-request/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    abandonment_request_sha256: Sha256Digest
    classification_evidence_id: Identifier
    previous_evidence_sequence: NonNegativeSafeInteger
    previous_event_sha256: Sha256Digest
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    concurrency: PositiveSafeInteger
    expected_classification: Literal["STABLE_BASELINE_CONFIRMED"]
    expected_target_configuration_sha256: Sha256Digest
    minimum_service_generation_exclusive: NonNegativeSafeInteger
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    request_id: Identifier

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        prefix = f"{self.target.service_name}-"
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.classification_evidence_id
            != recovery_abandonment_evidence_id(
                self.abandonment_request_sha256,
                "classification",
            )
            or self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(prefix)
            or not self.candidate_revision.startswith(prefix)
            or not 1 <= self.concurrency <= 1_000
            or self.fenced_authority_revision != self.fenced_epoch - 1
        ):
            raise ValueError("abandonment classification request is invalid")
        return self


class RecoveryAbandonmentClassificationResultV1(StrictContractModel):
    schema_version: Literal["controlgraph.recovery-abandonment-classification-result/v1"]
    request: RecoveryAbandonmentClassificationRequestV1
    request_sha256: Sha256Digest
    classification: Literal["STABLE_BASELINE_CONFIRMED"]
    service_generation: PositiveSafeInteger
    provider_etag: BoundedText
    target_configuration_sha256: Sha256Digest
    classified_by: BoundedText
    classified_at: UtcSecond

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        request = self.request
        if (
            self.request_sha256 != recovery_abandonment_classification_request_sha256(request)
            or self.classification != request.expected_classification
            or self.service_generation <= request.minimum_service_generation_exclusive
            or request.fenced_authority_revision != request.fenced_epoch - 1
            or self.target_configuration_sha256 != request.expected_target_configuration_sha256
            or self.classified_by
            != f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        ):
            raise ValueError("abandonment classification result is not request-bound")
        return self


class RecoveryAbandonmentClassificationSubjectV1(StrictContractModel):
    schema_version: Literal["controlgraph.recovery-abandonment-classification-subject/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    classification_request_sha256: Sha256Digest
    classification: Literal["STABLE_BASELINE_CONFIRMED"]
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    service_generation: PositiveSafeInteger
    provider_etag: BoundedText
    target_configuration_sha256: Sha256Digest
    evidence_id: Identifier
    classified_by: BoundedText
    classified_at: UtcSecond


class RecoveryAbandonmentClassificationSigningRequestV1(StrictContractModel):
    schema_version: Literal["controlgraph.recovery-abandonment-classification-signing-request/v1"]
    result: RecoveryAbandonmentClassificationResultV1
    subject: RecoveryAbandonmentClassificationSubjectV1
    event: EvidenceEvent

    @model_validator(mode="after")
    def validate_signing_request(self) -> Self:
        result = self.result
        request = result.request
        subject = self.subject
        event = self.event
        if (
            subject.target != request.target
            or subject.root_id != request.root_id
            or subject.root_sha256 != request.root_sha256
            or subject.request_sha256 != request.abandonment_request_sha256
            or subject.classification_request_sha256 != result.request_sha256
            or subject.classification != result.classification
            or subject.fenced_epoch != request.fenced_epoch
            or subject.fenced_authority_revision != request.fenced_authority_revision
            or subject.service_generation != result.service_generation
            or subject.provider_etag != result.provider_etag
            or subject.target_configuration_sha256 != result.target_configuration_sha256
            or subject.evidence_id != request.classification_evidence_id
            or subject.classified_by != result.classified_by
            or subject.classified_at != result.classified_at
            or event.evidence_id != request.classification_evidence_id
            or event.sequence != request.previous_evidence_sequence + 1
            or event.root_id != request.root_id
            or event.root_sha256 != request.root_sha256
            or event.target != request.target
            or event.epoch != request.fenced_epoch
            or event.kind.value != "TARGET_VERIFIED"
            or event.actor != result.classified_by
            or event.request_id != request.request_id
            or event.receipt_id is not None
            or event.occurred_at != result.classified_at
            or event.subject_sha256 != canonical_sha256(subject)
            or event.previous_event_sha256 != request.previous_event_sha256
            or event.reason_code is not None
            or event.provider_operation is not None
            or event.target_configuration_sha256 != result.target_configuration_sha256
        ):
            raise ValueError("abandonment classification signing request is invalid")
        return self


class RecoveryAbandonmentClassificationAttestationV1(StrictContractModel):
    schema_version: Literal["controlgraph.recovery-abandonment-classification-attestation/v1"]
    signing_request: RecoveryAbandonmentClassificationSigningRequestV1
    signed_evidence: SignedEvidenceEventV1

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        if self.signed_evidence.event != self.signing_request.event:
            raise ValueError("abandonment classification signature payload differs")
        return self


class RecoveryAbandonmentIdentityV1(StrictContractModel):
    schema_version: Literal["controlgraph.recovery-abandonment-identity/v1"]
    identity_kind: RecoveryAbandonmentIdentityKind
    identity_value: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    result_id: Identifier
    claimed_at: UtcSecond

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.result_id != f"cgabandon:{self.request_sha256}"
        ):
            raise ValueError("recovery abandonment identity is invalid")
        return self


class RecoveryAbandonmentProgressV1(StrictContractModel):
    """Immutable winner for the atomic dispatch-abandonment and epoch fence."""

    schema_version: Literal["controlgraph.recovery-abandonment-progress/v1"]
    result_id: Identifier
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    recovery_dispatch_id: Identifier
    previous_dispatch_sha256: Sha256Digest
    ambiguous_dispatch_sha256: Sha256Digest
    recovery_receipt_id: Identifier
    abandonment_evidence_id: Identifier
    abandonment_evidence_sha256: Sha256Digest
    abandonment_subject: RecoveryAbandonmentEvidenceSubjectV1
    fence_evidence_id: Identifier
    fence_evidence_sha256: Sha256Digest
    fence_subject: RecoveryAbandonmentFenceSubjectV1
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    fenced_at: UtcSecond

    @model_validator(mode="after")
    def validate_progress(self) -> Self:
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.result_id != f"cgabandon:{self.request_sha256}"
            or self.abandonment_evidence_id == self.fence_evidence_id
            or self.abandonment_evidence_sha256 == self.fence_evidence_sha256
            or self.abandonment_subject.target != self.target
            or self.abandonment_subject.root_id != self.root_id
            or self.abandonment_subject.root_sha256 != self.root_sha256
            or self.abandonment_subject.request_sha256 != self.request_sha256
            or self.abandonment_subject.recovery_dispatch_id != self.recovery_dispatch_id
            or self.abandonment_subject.previous_dispatch_sha256 != self.previous_dispatch_sha256
            or self.abandonment_subject.ambiguous_dispatch_sha256 != self.ambiguous_dispatch_sha256
            or self.abandonment_subject.recovery_receipt_id != self.recovery_receipt_id
            or self.abandonment_subject.evidence_id != self.abandonment_evidence_id
            or self.abandonment_subject.abandoned_at != self.fenced_at
            or self.fence_subject.target != self.target
            or self.fence_subject.root_id != self.root_id
            or self.fence_subject.root_sha256 != self.root_sha256
            or self.fence_subject.request_sha256 != self.request_sha256
            or self.fence_subject.request_id != self.request_id
            or self.fence_subject.idempotency_key != self.idempotency_key
            or self.fence_subject.operator_identity != self.abandonment_subject.operator_identity
            or self.fence_subject.operator_subject != self.abandonment_subject.operator_subject
            or self.fence_subject.abandonment_evidence_id != self.abandonment_evidence_id
            or self.fence_subject.abandonment_evidence_sha256 != self.abandonment_evidence_sha256
            or self.fence_subject.evidence_id != self.fence_evidence_id
            or self.fence_subject.new_epoch != self.fenced_epoch
            or self.fence_subject.previous_epoch + 1 != self.fenced_epoch
            or self.fenced_authority_revision != self.fenced_epoch - 1
            or self.fenced_at != self.fence_subject.fenced_at
        ):
            raise ValueError("recovery abandonment progress bindings are invalid")
        return self


class RecoveryAbandonmentResultV1(StrictContractModel):
    """Resumable operator result: fenced/reset-required or finally released."""

    schema_version: Literal["controlgraph.recovery-abandonment-result/v1"]
    result_id: Identifier
    phase: RecoveryAbandonmentPhase
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    recovery_dispatch_id: Identifier
    ambiguous_dispatch_sha256: Sha256Digest
    recovery_receipt_id: Identifier
    abandonment_evidence_id: Identifier
    abandonment_evidence_sha256: Sha256Digest
    fence_evidence_id: Identifier
    fence_evidence_sha256: Sha256Digest
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    fenced_at: UtcSecond
    classification_evidence_id: Identifier | None
    classification_evidence_sha256: Sha256Digest | None
    classification_subject: RecoveryAbandonmentClassificationSubjectV1 | None
    release_evidence_id: Identifier | None
    release_evidence_sha256: Sha256Digest | None
    release_subject: ServiceClaimReleaseEvidenceSubjectV1 | None
    stable_baseline_proof: ServiceClaimStableBaselineProofV1 | None
    released_at: UtcSecond | None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if (
            self.result_id != f"cgabandon:{self.request_sha256}"
            or self.root_id != f"cgroot:{self.root_sha256}"
            or self.fenced_authority_revision != self.fenced_epoch - 1
        ):
            raise ValueError("recovery abandonment result identity is invalid")
        final_values = (
            self.classification_evidence_id,
            self.classification_evidence_sha256,
            self.classification_subject,
            self.release_evidence_id,
            self.release_evidence_sha256,
            self.release_subject,
            self.stable_baseline_proof,
            self.released_at,
        )
        if self.phase is RecoveryAbandonmentPhase.FENCED_RESET_REQUIRED:
            if any(value is not None for value in final_values):
                raise ValueError("reset-required result cannot contain final proof")
            return self
        if any(value is None for value in final_values):
            raise ValueError("released abandonment result requires final proof")
        proof = self.stable_baseline_proof
        subject = self.classification_subject
        release = self.release_subject
        assert proof is not None and subject is not None and release is not None
        if (
            proof.root_id != self.root_id
            or proof.root_sha256 != self.root_sha256
            or proof.target != self.target
            or proof.classification != "STABLE_BASELINE_CONFIRMED"
            or proof.fenced_epoch != self.fenced_epoch
            or proof.fenced_authority_revision != self.fenced_authority_revision
            or proof.evidence_id != self.classification_evidence_id
            or proof.evidence_sha256 != self.classification_evidence_sha256
            or proof.target_configuration_sha256 != subject.target_configuration_sha256
            or proof.service_generation != subject.service_generation
            or proof.provider_etag != subject.provider_etag
            or proof.classified_by != subject.classified_by
            or proof.classified_at != subject.classified_at
            or subject.target != self.target
            or subject.root_id != self.root_id
            or subject.root_sha256 != self.root_sha256
            or subject.request_sha256 != self.request_sha256
            or subject.classification != "STABLE_BASELINE_CONFIRMED"
            or subject.fenced_epoch != self.fenced_epoch
            or subject.fenced_authority_revision != self.fenced_authority_revision
            or subject.evidence_id != self.classification_evidence_id
            or release.target != self.target
            or release.root_id != self.root_id
            or release.root_sha256 != self.root_sha256
            or release.request_sha256 != self.request_sha256
            or release.request_id != self.request_id
            or release.idempotency_key != self.idempotency_key
            or release.operator_identity != self.operator_identity
            or release.operator_subject != self.operator_subject
            or release.classification_evidence_id != self.classification_evidence_id
            or release.classification_evidence_sha256 != self.classification_evidence_sha256
            or release.fenced_epoch != self.fenced_epoch
            or release.fenced_authority_revision != self.fenced_authority_revision
            or release.evidence_id != self.release_evidence_id
            or release.released_at != self.released_at
            or not self.fenced_at <= proof.classified_at <= release.released_at
            or len(
                {
                    self.abandonment_evidence_id,
                    self.fence_evidence_id,
                    proof.evidence_id,
                    release.evidence_id,
                }
            )
            != 4
            or len(
                {
                    self.abandonment_evidence_sha256,
                    self.fence_evidence_sha256,
                    proof.evidence_sha256,
                    cast(str, self.release_evidence_sha256),
                }
            )
            != 4
        ):
            raise ValueError("released abandonment result bindings are invalid")
        return self


class RecoveryAbandonmentRelayResponseV1(StrictContractModel):
    schema_version: Literal["controlgraph.recovery-abandonment-relay-response/v1"]
    result: RecoveryAbandonmentResultV1 | None
    failure_code: RecoveryAbandonmentFailureCode | None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (self.result is None) == (self.failure_code is None):
            raise ValueError("abandonment relay response must contain one outcome")
        return self


class RecoveryAbandonmentFenceCommitV1(StrictContractModel):
    replacement_dispatch: RecoveryDispatchRecordV2
    replacement_claim: ServiceClaimRecordV3
    replacement_authority: EpochAuthorityRecord
    abandonment_subject: RecoveryAbandonmentEvidenceSubjectV1
    abandonment_evidence: SignedEvidenceEventV1
    fence_subject: RecoveryAbandonmentFenceSubjectV1
    fence_evidence: SignedEvidenceEventV1
    chain_head: EvidenceChainHeadV1
    progress: RecoveryAbandonmentProgressV1
    request_identity: RecoveryAbandonmentIdentityV1
    idempotency_identity: RecoveryAbandonmentIdentityV1


class RecoveryAbandonmentFinalizeCommitV1(StrictContractModel):
    replacement_claim: ServiceClaimRecordV3
    classification_subject: RecoveryAbandonmentClassificationSubjectV1
    classification_evidence: SignedEvidenceEventV1
    release_subject: ServiceClaimReleaseEvidenceSubjectV1
    release_evidence: SignedEvidenceEventV1
    chain_head: EvidenceChainHeadV1
    result: RecoveryAbandonmentResultV1


def recovery_abandonment_request_sha256(
    invocation: RecoveryAbandonmentInvocationV1,
) -> str:
    if type(invocation) is not RecoveryAbandonmentInvocationV1:
        raise TypeError("abandonment request hashing requires an exact invocation")
    command = invocation.command
    value: RestrictedJson = {
        "confirmation": command.confirmation,
        "expected_dispatch_sha256": command.expected_dispatch_sha256,
        "expected_epoch": command.expected_epoch,
        "expected_root_sha256": command.expected_root_sha256,
        "idempotency_key": command.idempotency_key,
        "operator_identity": invocation.operator_identity,
        "operator_subject": invocation.operator_subject,
        "reason": command.reason,
        "recovery_dispatch_id": command.recovery_dispatch_id,
        "request_id": command.request_id,
        "root_id": command.root_id,
        "schema_version": "controlgraph.recovery-abandonment-request/v1",
    }
    return hashlib.sha256(_REQUEST_DIGEST_DOMAIN + canonical_json_value_bytes(value)).hexdigest()


def recovery_abandonment_classification_request_sha256(
    request: RecoveryAbandonmentClassificationRequestV1,
) -> str:
    if type(request) is not RecoveryAbandonmentClassificationRequestV1:
        raise TypeError("abandonment classification hashing requires an exact request")
    return hashlib.sha256(
        _CLASSIFICATION_DIGEST_DOMAIN + canonical_json_value_bytes(request.model_dump(mode="json"))
    ).hexdigest()


def recovery_abandonment_evidence_id(
    request_sha256: str,
    stage: Literal["ambiguity", "fence", "classification", "release"],
) -> str:
    if (
        type(request_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", request_sha256) is None
        or stage not in {"ambiguity", "fence", "classification", "release"}
    ):
        raise ValueError("abandonment evidence identity input is invalid")
    digest = hashlib.sha256(
        _EVIDENCE_ID_DOMAIN + stage.encode("ascii") + b"\0" + request_sha256.encode("ascii")
    ).hexdigest()
    return f"cgevidence:{digest}"


__all__ = [name for name in globals() if name.startswith("RECOVERY_ABANDONMENT_")] + [
    "RecoveryAbandonmentClassificationAttestationV1",
    "RecoveryAbandonmentClassificationRequestV1",
    "RecoveryAbandonmentClassificationResultV1",
    "RecoveryAbandonmentClassificationSigningRequestV1",
    "RecoveryAbandonmentClassificationSubjectV1",
    "RecoveryAbandonmentCommandV1",
    "RecoveryAbandonmentEvidenceSubjectV1",
    "RecoveryAbandonmentFailureCode",
    "RecoveryAbandonmentFenceCommitV1",
    "RecoveryAbandonmentFenceSubjectV1",
    "RecoveryAbandonmentFinalizeCommitV1",
    "RecoveryAbandonmentIdentityKind",
    "RecoveryAbandonmentIdentityV1",
    "RecoveryAbandonmentInvocationV1",
    "RecoveryAbandonmentPhase",
    "RecoveryAbandonmentProgressV1",
    "RecoveryAbandonmentRelayResponseV1",
    "RecoveryAbandonmentResultV1",
    "recovery_abandonment_classification_request_sha256",
    "recovery_abandonment_evidence_id",
    "recovery_abandonment_request_sha256",
]
