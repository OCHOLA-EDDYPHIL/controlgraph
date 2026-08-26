"""Strict contracts for explicit, evidence-backed service-claim release."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import StringConstraints, model_validator

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
from controlgraph_canary.contracts.models import (
    EVIDENCE_EVENT_V1,
    CapabilityAction,
    EpochAuthorityRecord,
    EvidenceEvent,
    EvidenceKind,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryApplyReceiptLocatorV1,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    ServiceClaimTargetClassification,
    ServiceClaimTargetClassificationProof,
    ServiceClaimTerminalRootState,
)

SERVICE_CLAIM_RELEASE_COMMAND_V1: Final = (
    "controlgraph.service-claim-release-command/v1"
)
STRANDED_STABLE_CLAIM_RELEASE_COMMAND_V1: Final = (
    "controlgraph.stranded-stable-claim-release-command/v1"
)
SERVICE_CLAIM_RELEASE_INVOCATION_V1: Final = (
    "controlgraph.service-claim-release-invocation/v1"
)
SERVICE_CLAIM_CLASSIFICATION_REQUEST_V1: Final = (
    "controlgraph.service-claim-classification-request/v1"
)
SERVICE_CLAIM_CLASSIFICATION_RESULT_V1: Final = (
    "controlgraph.service-claim-classification-result/v1"
)
SERVICE_CLAIM_CLASSIFICATION_SIGNING_REQUEST_V1: Final = (
    "controlgraph.service-claim-classification-signing-request/v1"
)
SERVICE_CLAIM_CLASSIFICATION_ATTESTATION_V1: Final = (
    "controlgraph.service-claim-classification-attestation/v1"
)
SERVICE_CLAIM_TERMINAL_EVIDENCE_SUBJECT_V1: Final = (
    "controlgraph.service-claim-terminal-evidence-subject/v1"
)
STRANDED_STABLE_CLAIM_EVIDENCE_SUBJECT_V1: Final = (
    "controlgraph.stranded-stable-claim-evidence-subject/v1"
)
SERVICE_CLAIM_FENCE_EVIDENCE_SUBJECT_V1: Final = (
    "controlgraph.service-claim-fence-evidence-subject/v1"
)
SERVICE_CLAIM_TARGET_CLASSIFICATION_EVIDENCE_SUBJECT_V1: Final = (
    "controlgraph.service-claim-target-classification-evidence-subject/v1"
)
SERVICE_CLAIM_RELEASE_EVIDENCE_SUBJECT_V1: Final = (
    "controlgraph.service-claim-release-evidence-subject/v1"
)
SERVICE_CLAIM_RELEASE_IDENTITY_V1: Final = (
    "controlgraph.service-claim-release-identity/v1"
)
SERVICE_CLAIM_RELEASE_PROGRESS_V1: Final = (
    "controlgraph.service-claim-release-progress/v1"
)
SERVICE_CLAIM_RELEASE_RESULT_V1: Final = (
    "controlgraph.service-claim-release-result/v1"
)
SERVICE_CLAIM_RELEASE_RELAY_RESPONSE_V1: Final = (
    "controlgraph.service-claim-release-relay-response/v1"
)

_REQUEST_DIGEST_DOMAIN: Final = b"controlgraph.service-claim-release-request/v1\0"
_STRANDED_REQUEST_DIGEST_DOMAIN: Final = (
    b"controlgraph.stranded-stable-claim-release-request/v1\0"
)
_CLASSIFICATION_DIGEST_DOMAIN: Final = (
    b"controlgraph.service-claim-classification-request/v1\0"
)
_EVIDENCE_ID_DOMAIN: Final = b"controlgraph.service-claim-release-evidence-id/v1\0"
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(
    r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


class ServiceClaimReleaseIdentityKind(StrEnum):
    """Independent public identities reserved by one release request."""

    REQUEST = "REQUEST"
    IDEMPOTENCY = "IDEMPOTENCY"


class ServiceClaimReleaseFailureCode(StrEnum):
    """Closed payload-free release failure classes."""

    CALLER_DENIED = "SERVICE_CLAIM_RELEASE_CALLER_DENIED"
    COMMAND_DENIED = "SERVICE_CLAIM_RELEASE_COMMAND_DENIED"
    ROOT_NOT_FOUND = "SERVICE_CLAIM_RELEASE_ROOT_NOT_FOUND"
    ROOT_MISMATCH = "SERVICE_CLAIM_RELEASE_ROOT_MISMATCH"
    CLAIM_NOT_ACTIVE = "SERVICE_CLAIM_RELEASE_CLAIM_NOT_ACTIVE"
    EPOCH_MISMATCH = "SERVICE_CLAIM_RELEASE_EPOCH_MISMATCH"
    TERMINAL_RECEIPT_INVALID = "SERVICE_CLAIM_RELEASE_TERMINAL_RECEIPT_INVALID"
    IDENTITY_CONFLICT = "SERVICE_CLAIM_RELEASE_IDENTITY_CONFLICT"
    CLASSIFICATION_DENIED = "SERVICE_CLAIM_RELEASE_CLASSIFICATION_DENIED"
    EVIDENCE_DENIED = "SERVICE_CLAIM_RELEASE_EVIDENCE_DENIED"
    TRUSTED_STATE_INVALID = "SERVICE_CLAIM_RELEASE_TRUSTED_STATE_INVALID"
    STORE_UNAVAILABLE = "SERVICE_CLAIM_RELEASE_STORE_UNAVAILABLE"
    OUTCOME_UNKNOWN = "SERVICE_CLAIM_RELEASE_OUTCOME_UNKNOWN"


class ServiceClaimReleaseCommandV1(StrictContractModel):
    """An explicit operator request containing no claimed proof facts."""

    schema_version: Literal["controlgraph.service-claim-release-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    terminal_receipt_idempotency_key: Identifier
    request_id: Identifier
    idempotency_key: Identifier
    confirmation: Literal["RELEASE"]

    @model_validator(mode="after")
    def validate_root_identity(self) -> Self:
        if self.root_id != f"cgroot:{self.expected_root_sha256}":
            raise ValueError("release root identifier and digest do not match")
        return self


class StrandedStableClaimReleaseCommandV1(StrictContractModel):
    """Explicit break-glass request for one stranded synthetic APPLY claim."""

    schema_version: Literal[
        "controlgraph.stranded-stable-claim-release-command/v1"
    ]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    expected_service_claim_sha256: Sha256Digest
    expected_service_claim_revision: NonNegativeSafeInteger
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1
    reason: BoundedText
    request_id: Identifier
    idempotency_key: Identifier
    confirmation: Literal["RELEASE_STRANDED_STABLE_CLAIM"]

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        receipt = self.verified_apply_receipt
        if (
            self.root_id != f"cgroot:{self.expected_root_sha256}"
            or receipt.root_id != self.root_id
            or receipt.root_sha256 != self.expected_root_sha256
            or receipt.epoch != self.expected_epoch
        ):
            raise ValueError("stranded claim release bindings are invalid")
        return self


class ServiceClaimReleaseInvocationV1(StrictContractModel):
    """A release command plus operator facts authenticated by the API."""

    schema_version: Literal["controlgraph.service-claim-release-invocation/v1"]
    command: ServiceClaimReleaseCommandV1 | StrandedStableClaimReleaseCommandV1
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
            raise ValueError("release invocation operator binding is invalid")
        return self


class ServiceClaimClassificationRequestV1(StrictContractModel):
    """Coordinator-derived expectation sent to the fixed read-only verifier."""

    schema_version: Literal["controlgraph.service-claim-classification-request/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    release_request_sha256: Sha256Digest
    classification_evidence_id: Identifier
    previous_evidence_sequence: NonNegativeSafeInteger
    previous_event_sha256: Sha256Digest
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    concurrency: PositiveSafeInteger
    expected_classification: ServiceClaimTargetClassification
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
            != service_claim_release_evidence_id(
                self.release_request_sha256,
                "classification",
            )
            or self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(prefix)
            or not self.candidate_revision.startswith(prefix)
            or not 1 <= self.concurrency <= 1_000
        ):
            raise ValueError("classification request bindings are invalid")
        return self


class ServiceClaimClassificationResultV1(StrictContractModel):
    """Canonical facts observed by the authenticated verifier read boundary."""

    schema_version: Literal["controlgraph.service-claim-classification-result/v1"]
    request: ServiceClaimClassificationRequestV1
    request_sha256: Sha256Digest
    classification: ServiceClaimTargetClassification
    service_generation: PositiveSafeInteger
    provider_etag: BoundedText
    target_configuration_sha256: Sha256Digest
    classified_by: BoundedText
    classified_at: UtcSecond

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        request = self.request
        expected_reader = (
            f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        )
        if (
            self.request_sha256 != service_claim_classification_request_sha256(request)
            or self.classification is not request.expected_classification
            or self.service_generation <= request.minimum_service_generation_exclusive
            or self.target_configuration_sha256
            != request.expected_target_configuration_sha256
            or self.classified_by != expected_reader
            or len(self.provider_etag) > 512
        ):
            raise ValueError("classification result is not exactly request-bound")
        return self


class ServiceClaimTerminalEvidenceSubjectV1(StrictContractModel):
    """Terminal state derived from one exact durable verified receipt."""

    schema_version: Literal["controlgraph.service-claim-terminal-evidence-subject/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    state: ServiceClaimTerminalRootState
    target_configuration_sha256: Sha256Digest
    receipt_id: Identifier
    receipt_sha256: Sha256Digest
    receipt_revision: NonNegativeSafeInteger
    receipt_epoch: PositiveSafeInteger
    receipt_action: CapabilityAction
    receipt_outcome: Literal[ReceiptOutcome.VERIFIED]
    evidence_id: Identifier
    confirmed_by: Literal["controlgraph.coordinator/v1"]
    confirmed_at: UtcSecond


class StrandedStableClaimEvidenceSubjectV1(StrictContractModel):
    """Auditable pre-classification basis for fencing one exact stranded claim."""

    schema_version: Literal[
        "controlgraph.stranded-stable-claim-evidence-subject/v1"
    ]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    state: Literal[ServiceClaimTerminalRootState.STRANDED_STABLE]
    expected_stable_target_configuration_sha256: Sha256Digest
    expected_service_claim_sha256: Sha256Digest
    expected_service_claim_revision: NonNegativeSafeInteger
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1
    reason: BoundedText
    confirmation: Literal["RELEASE_STRANDED_STABLE_CLAIM"]
    classification_pending: Literal[True]
    evidence_id: Identifier
    confirmed_by: Literal["controlgraph.coordinator/v1"]
    confirmed_at: UtcSecond

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        locator = self.verified_apply_receipt
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or locator.target != self.target
            or locator.root_id != self.root_id
            or locator.root_sha256 != self.root_sha256
        ):
            raise ValueError("stranded claim evidence bindings are invalid")
        return self


class ServiceClaimFenceEvidenceSubjectV1(StrictContractModel):
    """Exact claim fence and authority transition committed as one mutation."""

    schema_version: Literal["controlgraph.service-claim-fence-evidence-subject/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    terminal_evidence_id: Identifier
    terminal_evidence_sha256: Sha256Digest
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
            raise ValueError("claim fence must advance exactly one epoch")
        return self


class ServiceClaimTargetClassificationEvidenceSubjectV1(StrictContractModel):
    """Authenticated verifier result committed by signed evidence."""

    schema_version: Literal[
        "controlgraph.service-claim-target-classification-evidence-subject/v1"
    ]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    classification_request_sha256: Sha256Digest
    classification: ServiceClaimTargetClassification
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    service_generation: PositiveSafeInteger
    provider_etag: BoundedText
    target_configuration_sha256: Sha256Digest
    evidence_id: Identifier
    classified_by: BoundedText
    classified_at: UtcSecond


class ServiceClaimReleaseEvidenceSubjectV1(StrictContractModel):
    """Exact final claim replacement following authenticated classification."""

    schema_version: Literal["controlgraph.service-claim-release-evidence-subject/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    classification_evidence_id: Identifier
    classification_evidence_sha256: Sha256Digest
    fenced_claim_sha256: Sha256Digest
    released_claim_sha256: Sha256Digest
    fenced_authority_sha256: Sha256Digest
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    evidence_id: Identifier
    released_at: UtcSecond


class ServiceClaimClassificationSigningRequestV1(StrictContractModel):
    """Exact verifier-derived classification bundle admitted for signing."""

    schema_version: Literal[
        "controlgraph.service-claim-classification-signing-request/v1"
    ]
    result: ServiceClaimClassificationResultV1
    subject: ServiceClaimTargetClassificationEvidenceSubjectV1
    event: EvidenceEvent

    @model_validator(mode="after")
    def validate_signing_request(self) -> Self:
        result = self.result
        request = result.request
        subject = self.subject
        event = self.event
        reader = f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        if (
            subject.target != request.target
            or subject.root_id != request.root_id
            or subject.root_sha256 != request.root_sha256
            or subject.request_sha256 != request.release_request_sha256
            or subject.classification_request_sha256 != result.request_sha256
            or subject.classification is not result.classification
            or subject.fenced_epoch != request.fenced_epoch
            or subject.fenced_authority_revision
            != request.fenced_authority_revision
            or subject.service_generation != result.service_generation
            or subject.provider_etag != result.provider_etag
            or subject.target_configuration_sha256
            != result.target_configuration_sha256
            or subject.evidence_id != request.classification_evidence_id
            or subject.classified_by != reader
            or subject.classified_at != result.classified_at
            or event.schema_version != EVIDENCE_EVENT_V1
            or event.evidence_id != request.classification_evidence_id
            or event.sequence != request.previous_evidence_sequence + 1
            or event.root_id != request.root_id
            or event.root_sha256 != request.root_sha256
            or event.target != request.target
            or event.epoch != request.fenced_epoch
            or event.kind is not EvidenceKind.TARGET_VERIFIED
            or event.actor != reader
            or event.request_id != request.request_id
            or event.receipt_id is not None
            or event.occurred_at != result.classified_at
            or event.subject_sha256 != canonical_sha256(subject)
            or event.previous_event_sha256 != request.previous_event_sha256
            or event.reason_code is not None
            or event.provider_operation is not None
            or event.target_configuration_sha256
            != result.target_configuration_sha256
        ):
            raise ValueError("classification signing request is not exactly bound")
        return self


class ServiceClaimClassificationAttestationV1(StrictContractModel):
    """Verifier-authenticated signed classification returned to the coordinator."""

    schema_version: Literal[
        "controlgraph.service-claim-classification-attestation/v1"
    ]
    signing_request: ServiceClaimClassificationSigningRequestV1
    signed_evidence: SignedEvidenceEventV1

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        if self.signed_evidence.event != self.signing_request.event:
            raise ValueError("classification attestation signature payload differs")
        return self


class ServiceClaimReleaseIdentityV1(StrictContractModel):
    """Immutable ownership of one request or idempotency identity."""

    schema_version: Literal["controlgraph.service-claim-release-identity/v1"]
    identity_kind: ServiceClaimReleaseIdentityKind
    identity_value: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    result_id: Identifier
    claimed_at: UtcSecond


class ServiceClaimReleaseProgressV1(StrictContractModel):
    """Immutable exact winner for the atomic claim-fence stage."""

    schema_version: Literal["controlgraph.service-claim-release-progress/v1"]
    result_id: Identifier
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    terminal_receipt_id: Identifier
    terminal_receipt_sha256: Sha256Digest
    terminal_evidence_id: Identifier
    terminal_evidence_sha256: Sha256Digest
    terminal_subject: (
        ServiceClaimTerminalEvidenceSubjectV1
        | StrandedStableClaimEvidenceSubjectV1
    )
    fence_evidence_id: Identifier
    fence_evidence_sha256: Sha256Digest
    fence_subject: ServiceClaimFenceEvidenceSubjectV1
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    fenced_at: UtcSecond

    @model_validator(mode="after")
    def validate_progress(self) -> Self:
        if type(self.terminal_subject) is ServiceClaimTerminalEvidenceSubjectV1:
            receipt_binding_is_exact = (
                self.terminal_subject.receipt_id == self.terminal_receipt_id
                and self.terminal_subject.receipt_sha256
                == self.terminal_receipt_sha256
            )
        elif type(self.terminal_subject) is StrandedStableClaimEvidenceSubjectV1:
            receipt_binding_is_exact = (
                self.terminal_subject.verified_apply_receipt.receipt_id
                == self.terminal_receipt_id
                and self.terminal_subject.verified_apply_receipt.receipt_sha256
                == self.terminal_receipt_sha256
            )
        else:
            receipt_binding_is_exact = False
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.result_id != f"cgrelease:{self.request_sha256}"
            or self.terminal_evidence_id == self.fence_evidence_id
            or self.terminal_evidence_sha256 == self.fence_evidence_sha256
            or self.terminal_subject.root_id != self.root_id
            or self.terminal_subject.root_sha256 != self.root_sha256
            or self.terminal_subject.target != self.target
            or not receipt_binding_is_exact
            or self.terminal_subject.evidence_id != self.terminal_evidence_id
            or self.fence_subject.root_id != self.root_id
            or self.fence_subject.root_sha256 != self.root_sha256
            or self.fence_subject.target != self.target
            or self.fence_subject.request_sha256 != self.request_sha256
            or self.fence_subject.request_id != self.request_id
            or self.fence_subject.idempotency_key != self.idempotency_key
            or self.fence_subject.terminal_evidence_id != self.terminal_evidence_id
            or self.fence_subject.terminal_evidence_sha256
            != self.terminal_evidence_sha256
            or self.fence_subject.evidence_id != self.fence_evidence_id
            or self.fence_subject.new_epoch != self.fenced_epoch
            or self.fenced_at != self.fence_subject.fenced_at
        ):
            raise ValueError("claim release progress bindings are invalid")
        return self


class ServiceClaimReleaseResultV1(StrictContractModel):
    """Immutable exact winner returned after final claim release."""

    schema_version: Literal["controlgraph.service-claim-release-result/v1"]
    result_id: Identifier
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    terminal_receipt_id: Identifier
    terminal_receipt_sha256: Sha256Digest
    terminal_evidence_id: Identifier
    terminal_evidence_sha256: Sha256Digest
    fence_evidence_id: Identifier
    fence_evidence_sha256: Sha256Digest
    classification_evidence_id: Identifier
    classification_evidence_sha256: Sha256Digest
    classification_subject: ServiceClaimTargetClassificationEvidenceSubjectV1
    release_evidence_id: Identifier
    release_evidence_sha256: Sha256Digest
    release_subject: ServiceClaimReleaseEvidenceSubjectV1
    classification_proof: ServiceClaimTargetClassificationProof
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    released_at: UtcSecond

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        proof = self.classification_proof
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.result_id != f"cgrelease:{self.request_sha256}"
            or proof.target != self.target
            or proof.root_id != self.root_id
            or proof.root_sha256 != self.root_sha256
            or proof.fenced_epoch != self.fenced_epoch
            or proof.fenced_authority_revision != self.fenced_authority_revision
            or proof.evidence_id != self.classification_evidence_id
            or proof.evidence_sha256 != self.classification_evidence_sha256
            or self.classification_subject.root_id != self.root_id
            or self.classification_subject.root_sha256 != self.root_sha256
            or self.classification_subject.target != self.target
            or self.classification_subject.request_sha256 != self.request_sha256
            or self.classification_subject.evidence_id
            != self.classification_evidence_id
            or self.classification_subject.fenced_epoch != self.fenced_epoch
            or self.classification_subject.fenced_authority_revision
            != self.fenced_authority_revision
            or self.release_subject.root_id != self.root_id
            or self.release_subject.root_sha256 != self.root_sha256
            or self.release_subject.target != self.target
            or self.release_subject.request_sha256 != self.request_sha256
            or self.release_subject.request_id != self.request_id
            or self.release_subject.idempotency_key != self.idempotency_key
            or self.release_subject.classification_evidence_id
            != self.classification_evidence_id
            or self.release_subject.classification_evidence_sha256
            != self.classification_evidence_sha256
            or self.release_subject.evidence_id != self.release_evidence_id
            or self.release_subject.released_at != self.released_at
            or len(
                {
                    self.terminal_evidence_id,
                    self.fence_evidence_id,
                    self.classification_evidence_id,
                    self.release_evidence_id,
                }
            )
            != 4
            or len(
                {
                    self.terminal_evidence_sha256,
                    self.fence_evidence_sha256,
                    self.classification_evidence_sha256,
                    self.release_evidence_sha256,
                }
            )
            != 4
        ):
            raise ValueError("claim release result bindings are invalid")
        return self


class ServiceClaimReleaseRelayResponseV1(StrictContractModel):
    """Closed coordinator response preserving one exact failure or result."""

    schema_version: Literal[
        "controlgraph.service-claim-release-relay-response/v1"
    ]
    result: ServiceClaimReleaseResultV1 | None
    failure_code: ServiceClaimReleaseFailureCode | None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (self.result is None) == (self.failure_code is None):
            raise ValueError("release relay response must contain one outcome")
        return self


class ServiceClaimReleaseFenceCommitV1(StrictContractModel):
    """Complete atomic fence bundle passed to the coordinator store."""

    replacement_claim: ServiceClaimRecord
    replacement_authority: EpochAuthorityRecord
    terminal_subject: (
        ServiceClaimTerminalEvidenceSubjectV1
        | StrandedStableClaimEvidenceSubjectV1
    )
    terminal_evidence: SignedEvidenceEventV1
    fence_subject: ServiceClaimFenceEvidenceSubjectV1
    fence_evidence: SignedEvidenceEventV1
    chain_head: EvidenceChainHeadV1
    progress: ServiceClaimReleaseProgressV1
    request_identity: ServiceClaimReleaseIdentityV1
    idempotency_identity: ServiceClaimReleaseIdentityV1


class ServiceClaimReleaseFinalizeCommitV1(StrictContractModel):
    """Complete atomic final release bundle passed to the coordinator store."""

    replacement_claim: ServiceClaimRecord
    classification_subject: ServiceClaimTargetClassificationEvidenceSubjectV1
    classification_evidence: SignedEvidenceEventV1
    release_subject: ServiceClaimReleaseEvidenceSubjectV1
    release_evidence: SignedEvidenceEventV1
    chain_head: EvidenceChainHeadV1
    result: ServiceClaimReleaseResultV1


def service_claim_release_request_sha256(
    invocation: ServiceClaimReleaseInvocationV1,
) -> str:
    """Hash every operator-controlled and authenticated release binding."""

    if type(invocation) is not ServiceClaimReleaseInvocationV1:
        raise TypeError("release request hashing requires an exact invocation")
    command = invocation.command
    if type(command) is ServiceClaimReleaseCommandV1:
        value: RestrictedJson = {
            "confirmation": command.confirmation,
            "expected_epoch": command.expected_epoch,
            "expected_root_sha256": command.expected_root_sha256,
            "idempotency_key": command.idempotency_key,
            "operator_identity": invocation.operator_identity,
            "operator_subject": invocation.operator_subject,
            "request_id": command.request_id,
            "root_id": command.root_id,
            "schema_version": "controlgraph.service-claim-release-request/v1",
            "terminal_receipt_idempotency_key": (
                command.terminal_receipt_idempotency_key
            ),
        }
        domain = _REQUEST_DIGEST_DOMAIN
    elif type(command) is StrandedStableClaimReleaseCommandV1:
        value = {
            "confirmation": command.confirmation,
            "expected_epoch": command.expected_epoch,
            "expected_root_sha256": command.expected_root_sha256,
            "expected_service_claim_revision": (
                command.expected_service_claim_revision
            ),
            "expected_service_claim_sha256": command.expected_service_claim_sha256,
            "idempotency_key": command.idempotency_key,
            "operator_identity": invocation.operator_identity,
            "operator_subject": invocation.operator_subject,
            "reason": command.reason,
            "request_id": command.request_id,
            "root_id": command.root_id,
            "schema_version": (
                "controlgraph.stranded-stable-claim-release-request/v1"
            ),
            "verified_apply_receipt": command.verified_apply_receipt.model_dump(
                mode="json"
            ),
        }
        domain = _STRANDED_REQUEST_DIGEST_DOMAIN
    else:
        raise TypeError("release request contains an unsupported command")
    return hashlib.sha256(domain + canonical_json_value_bytes(value)).hexdigest()


def service_claim_classification_request_sha256(
    request: ServiceClaimClassificationRequestV1,
) -> str:
    """Hash one complete coordinator-to-verifier classification request."""

    if type(request) is not ServiceClaimClassificationRequestV1:
        raise TypeError("classification hashing requires an exact request")
    return hashlib.sha256(
        _CLASSIFICATION_DIGEST_DOMAIN
        + canonical_json_value_bytes(request.model_dump(mode="json"))
    ).hexdigest()


def service_claim_release_evidence_id(
    request_sha256: str,
    stage: Literal["terminal", "fence", "classification", "release"],
) -> str:
    """Return one deterministic stage-separated evidence identity."""

    if (
        type(request_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", request_sha256) is None
        or stage not in {"terminal", "fence", "classification", "release"}
    ):
        raise ValueError("release evidence identity input is invalid")
    digest = hashlib.sha256(
        _EVIDENCE_ID_DOMAIN
        + stage.encode("ascii")
        + b"\0"
        + request_sha256.encode("ascii")
    ).hexdigest()
    return f"cgrevidence:{digest}"


__all__ = [
    "SERVICE_CLAIM_CLASSIFICATION_ATTESTATION_V1",
    "SERVICE_CLAIM_CLASSIFICATION_REQUEST_V1",
    "SERVICE_CLAIM_CLASSIFICATION_RESULT_V1",
    "SERVICE_CLAIM_CLASSIFICATION_SIGNING_REQUEST_V1",
    "SERVICE_CLAIM_FENCE_EVIDENCE_SUBJECT_V1",
    "SERVICE_CLAIM_RELEASE_COMMAND_V1",
    "SERVICE_CLAIM_RELEASE_EVIDENCE_SUBJECT_V1",
    "SERVICE_CLAIM_RELEASE_IDENTITY_V1",
    "SERVICE_CLAIM_RELEASE_INVOCATION_V1",
    "SERVICE_CLAIM_RELEASE_PROGRESS_V1",
    "SERVICE_CLAIM_RELEASE_RELAY_RESPONSE_V1",
    "SERVICE_CLAIM_RELEASE_RESULT_V1",
    "SERVICE_CLAIM_TARGET_CLASSIFICATION_EVIDENCE_SUBJECT_V1",
    "SERVICE_CLAIM_TERMINAL_EVIDENCE_SUBJECT_V1",
    "STRANDED_STABLE_CLAIM_EVIDENCE_SUBJECT_V1",
    "STRANDED_STABLE_CLAIM_RELEASE_COMMAND_V1",
    "ServiceClaimClassificationAttestationV1",
    "ServiceClaimClassificationRequestV1",
    "ServiceClaimClassificationResultV1",
    "ServiceClaimClassificationSigningRequestV1",
    "ServiceClaimFenceEvidenceSubjectV1",
    "ServiceClaimReleaseCommandV1",
    "ServiceClaimReleaseEvidenceSubjectV1",
    "ServiceClaimReleaseFailureCode",
    "ServiceClaimReleaseFenceCommitV1",
    "ServiceClaimReleaseFinalizeCommitV1",
    "ServiceClaimReleaseIdentityKind",
    "ServiceClaimReleaseIdentityV1",
    "ServiceClaimReleaseInvocationV1",
    "ServiceClaimReleaseProgressV1",
    "ServiceClaimReleaseRelayResponseV1",
    "ServiceClaimReleaseResultV1",
    "ServiceClaimTargetClassificationEvidenceSubjectV1",
    "ServiceClaimTerminalEvidenceSubjectV1",
    "StrandedStableClaimEvidenceSubjectV1",
    "StrandedStableClaimReleaseCommandV1",
    "service_claim_classification_request_sha256",
    "service_claim_release_evidence_id",
    "service_claim_release_request_sha256",
]
