"""Strict contracts for authenticated manual epoch revocation."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import StringConstraints, field_validator, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    Identifier,
    PositiveSafeInteger,
    Sha256Digest,
    ShortText,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import RestrictedJson, canonical_json_value_bytes
from controlgraph_canary.contracts.evidence import EvidenceChainHeadV1
from controlgraph_canary.contracts.models import (
    EpochAuthorityRecord,
    TargetBinding,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1

EPOCH_REVOCATION_COMMAND_V1: Final = "controlgraph.epoch-revocation-command/v1"
EPOCH_REVOCATION_INVOCATION_V1: Final = "controlgraph.epoch-revocation-invocation/v1"
EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1: Final = (
    "controlgraph.epoch-revocation-evidence-subject/v1"
)
EPOCH_REVOCATION_IDENTITY_V1: Final = "controlgraph.epoch-revocation-identity/v1"
EPOCH_REVOCATION_RESULT_V1: Final = "controlgraph.epoch-revocation-result/v1"
EPOCH_REVOCATION_AUDIT_V1: Final = "controlgraph.epoch-revocation-audit/v1"
EPOCH_REVOCATION_RELAY_RESPONSE_V1: Final = (
    "controlgraph.epoch-revocation-relay-response/v1"
)

_REQUEST_DIGEST_DOMAIN: Final = b"controlgraph.epoch-revocation-request-sha256/v1\0"
_EVIDENCE_ID_DOMAIN: Final = b"controlgraph.epoch-revocation-evidence-id/v1\0"
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


class EpochRevocationIdentityKind(StrEnum):
    """Independent identifiers reserved by one canonical revocation request."""

    REQUEST = "REQUEST"
    IDEMPOTENCY = "IDEMPOTENCY"


class EpochRevocationAuditOutcome(StrEnum):
    """Durable disposition of one authenticated canonical API attempt."""

    COMMITTED = "COMMITTED"
    ADOPTED = "ADOPTED"
    DENIED = "DENIED"


class EpochRevocationFailureCode(StrEnum):
    """Closed payload-free denial classes for the revocation boundary."""

    CALLER_DENIED = "REVOCATION_CALLER_DENIED"
    COMMAND_DENIED = "REVOCATION_COMMAND_DENIED"
    ROOT_NOT_FOUND = "REVOCATION_ROOT_NOT_FOUND"
    ROOT_MISMATCH = "REVOCATION_ROOT_MISMATCH"
    ACTIVE_CLAIM_REQUIRED = "REVOCATION_ACTIVE_CLAIM_REQUIRED"
    EPOCH_MISMATCH = "REVOCATION_EPOCH_MISMATCH"
    IDENTITY_CONFLICT = "REVOCATION_IDENTITY_CONFLICT"
    TRUSTED_STATE_INVALID = "REVOCATION_TRUSTED_STATE_INVALID"
    EVIDENCE_DENIED = "REVOCATION_EVIDENCE_DENIED"
    STORE_UNAVAILABLE = "REVOCATION_STORE_UNAVAILABLE"
    OUTCOME_UNKNOWN = "REVOCATION_OUTCOME_UNKNOWN"


class EpochRevocationCommandV1(StrictContractModel):
    """One explicit operator request to advance an exact root epoch."""

    schema_version: Literal["controlgraph.epoch-revocation-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    reason: ShortText
    request_id: Identifier
    idempotency_key: Identifier
    confirmation: Literal["REVOKE"]

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("revocation reason must be exact non-whitespace text")
        return value

    @model_validator(mode="after")
    def validate_root_identity(self) -> Self:
        if self.root_id != f"cgroot:{self.expected_root_sha256}":
            raise ValueError("revocation root identifier and digest do not match")
        return self


class EpochRevocationInvocationV1(StrictContractModel):
    """A command plus the operator facts verified by the public API."""

    schema_version: Literal["controlgraph.epoch-revocation-invocation/v1"]
    command: EpochRevocationCommandV1
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
            raise ValueError("revocation invocation operator binding is invalid")
        return self


class EpochRevocationEvidenceSubjectV1(StrictContractModel):
    """The complete authority transition bound by EPOCH_ADVANCED evidence."""

    schema_version: Literal["controlgraph.epoch-revocation-evidence-subject/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    reason: ShortText
    service_claim_sha256: Sha256Digest
    previous_authority_sha256: Sha256Digest
    replacement_authority_sha256: Sha256Digest
    previous_epoch: PositiveSafeInteger
    new_epoch: PositiveSafeInteger
    evidence_id: Identifier
    committed_at: UtcSecond

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        if self.new_epoch != self.previous_epoch + 1:
            raise ValueError("revocation evidence must advance exactly one epoch")
        return self


class EpochRevocationIdentityV1(StrictContractModel):
    """Immutable ownership of one request or idempotency identity."""

    schema_version: Literal["controlgraph.epoch-revocation-identity/v1"]
    identity_kind: EpochRevocationIdentityKind
    identity_value: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    result_id: Identifier
    claimed_at: UtcSecond


class EpochRevocationResultV1(StrictContractModel):
    """Immutable committed result returned by direct and replayed requests."""

    schema_version: Literal["controlgraph.epoch-revocation-result/v1"]
    result_id: Identifier
    request_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    reason: ShortText
    previous_epoch: PositiveSafeInteger
    new_epoch: PositiveSafeInteger
    evidence_id: Identifier
    evidence_sha256: Sha256Digest
    evidence_subject: EpochRevocationEvidenceSubjectV1
    committed_at: UtcSecond

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or self.new_epoch != self.previous_epoch + 1
            or self.result_id != f"cgrevoke:{self.request_sha256}"
            or self.evidence_id
            != epoch_revocation_evidence_id(
                self.request_sha256,
                self.root_sha256,
                self.new_epoch,
            )
            or self.evidence_subject.root_id != self.root_id
            or self.evidence_subject.root_sha256 != self.root_sha256
            or self.evidence_subject.request_sha256 != self.request_sha256
            or self.evidence_subject.request_id != self.request_id
            or self.evidence_subject.idempotency_key != self.idempotency_key
            or self.evidence_subject.operator_identity != self.operator_identity
            or self.evidence_subject.operator_subject != self.operator_subject
            or self.evidence_subject.reason != self.reason
            or self.evidence_subject.previous_epoch != self.previous_epoch
            or self.evidence_subject.new_epoch != self.new_epoch
            or self.evidence_subject.evidence_id != self.evidence_id
            or self.evidence_subject.committed_at != self.committed_at
        ):
            raise ValueError("revocation result identity or transition is invalid")
        return self


class EpochRevocationAuditV1(StrictContractModel):
    """Immutable audit entry for one canonical authenticated attempt."""

    schema_version: Literal["controlgraph.epoch-revocation-audit/v1"]
    audit_id: Identifier
    attempt_id: Identifier
    request_sha256: Sha256Digest
    root_id: Identifier
    root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    outcome: EpochRevocationAuditOutcome
    failure_code: EpochRevocationFailureCode | None
    result_id: Identifier | None
    evidence_id: Identifier | None
    new_epoch: PositiveSafeInteger | None
    recorded_at: UtcSecond

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        committed_values = (self.result_id, self.evidence_id, self.new_epoch)
        if self.outcome is EpochRevocationAuditOutcome.DENIED:
            if self.failure_code is None or any(value is not None for value in committed_values):
                raise ValueError("denied revocation audit shape is invalid")
        elif self.failure_code is not None or any(value is None for value in committed_values):
            raise ValueError("successful revocation audit shape is invalid")
        return self


class EpochRevocationRelayResponseV1(StrictContractModel):
    """Sanitized coordinator outcome carried over the authenticated relay."""

    schema_version: Literal["controlgraph.epoch-revocation-relay-response/v1"]
    result: EpochRevocationResultV1 | None
    failure_code: EpochRevocationFailureCode | None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (self.result is None) == (self.failure_code is None):
            raise ValueError("revocation relay response must contain one outcome")
        return self


class EpochRevocationCommitV1(StrictContractModel):
    """Complete validated bundle committed atomically by the coordinator store."""

    replacement_authority: EpochAuthorityRecord
    evidence_subject: EpochRevocationEvidenceSubjectV1
    signed_evidence: SignedEvidenceEventV1
    chain_head: EvidenceChainHeadV1
    result: EpochRevocationResultV1
    request_identity: EpochRevocationIdentityV1
    idempotency_identity: EpochRevocationIdentityV1
    audit: EpochRevocationAuditV1


def epoch_revocation_request_sha256(invocation: EpochRevocationInvocationV1) -> str:
    """Hash every operator-controlled and authenticated revocation binding."""

    if type(invocation) is not EpochRevocationInvocationV1:
        raise TypeError("revocation request hashing requires an exact invocation")
    command = invocation.command
    value: RestrictedJson = {
        "confirmation": command.confirmation,
        "expected_epoch": command.expected_epoch,
        "expected_root_sha256": command.expected_root_sha256,
        "idempotency_key": command.idempotency_key,
        "operator_identity": invocation.operator_identity,
        "operator_subject": invocation.operator_subject,
        "reason": command.reason,
        "request_id": command.request_id,
        "root_id": command.root_id,
        "schema_version": "controlgraph.epoch-revocation-request/v1",
    }
    return hashlib.sha256(
        _REQUEST_DIGEST_DOMAIN + canonical_json_value_bytes(value)
    ).hexdigest()


def epoch_revocation_evidence_id(
    request_sha256: str,
    root_sha256: str,
    new_epoch: int,
) -> str:
    """Derive the unique evidence identity for one exact epoch transition."""

    if (
        type(request_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", request_sha256) is None
        or type(root_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", root_sha256) is None
        or type(new_epoch) is not int
        or not 1 <= new_epoch <= 2**53 - 1
    ):
        raise ValueError("revocation evidence identity input is invalid")
    material = f"{request_sha256}\0{root_sha256}\0{new_epoch}".encode("ascii")
    return f"cgevidence:{hashlib.sha256(_EVIDENCE_ID_DOMAIN + material).hexdigest()}"


__all__ = [
    "EPOCH_REVOCATION_AUDIT_V1",
    "EPOCH_REVOCATION_COMMAND_V1",
    "EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1",
    "EPOCH_REVOCATION_IDENTITY_V1",
    "EPOCH_REVOCATION_INVOCATION_V1",
    "EPOCH_REVOCATION_RELAY_RESPONSE_V1",
    "EPOCH_REVOCATION_RESULT_V1",
    "EpochRevocationAuditOutcome",
    "EpochRevocationAuditV1",
    "EpochRevocationCommandV1",
    "EpochRevocationCommitV1",
    "EpochRevocationEvidenceSubjectV1",
    "EpochRevocationFailureCode",
    "EpochRevocationIdentityKind",
    "EpochRevocationIdentityV1",
    "EpochRevocationInvocationV1",
    "EpochRevocationRelayResponseV1",
    "EpochRevocationResultV1",
    "epoch_revocation_evidence_id",
    "epoch_revocation_request_sha256",
]
