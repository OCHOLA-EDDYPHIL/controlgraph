"""Canonical records and deterministic identities for authority persistence."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, ValidationError, model_validator

from controlgraph_canary.authority.replay import MutationTargetKey, receipt_claim_identity
from controlgraph_canary.contracts.base import (
    MAX_CONTRACT_BYTES,
    BoundedText,
    Identifier,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import (
    EpochAuthorityRecord,
    ExecutionReceipt,
    RolloutRoot,
    TargetBinding,
)

SERVICE_CLAIM_V1: Final = "controlgraph.service-claim/v1"
AUTHORITY_STORAGE_DOCUMENT_V1: Final = "controlgraph.authority-storage-document/v1"
FIRESTORE_DOCUMENT_ID_DOMAIN: Final = b"controlgraph.firestore-document-id/v1\0"


class ServiceClaimStatus(StrEnum):
    """Closed lifecycle for the single active-root claim on one service."""

    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"


class ServiceClaimRecord(StrictContractModel):
    """One service's ownership by an immutable rollout root."""

    schema_version: Literal["controlgraph.service-claim/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    status: ServiceClaimStatus
    claimed_by: BoundedText
    claim_request_id: Identifier
    claim_evidence_id: Identifier
    claimed_at: UtcSecond
    released_by: BoundedText | None
    release_request_id: Identifier | None
    release_evidence_id: Identifier | None
    released_at: UtcSecond | None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        release_values = (
            self.released_by,
            self.release_request_id,
            self.release_evidence_id,
            self.released_at,
        )
        if self.status is ServiceClaimStatus.ACTIVE:
            if any(value is not None for value in release_values):
                raise ValueError("active service claim cannot contain release metadata")
        elif any(value is None for value in release_values):
            raise ValueError("released service claim requires complete release metadata")
        elif self.released_at is not None and self.released_at < self.claimed_at:
            raise ValueError("service claim release predates its creation")
        return self


class AuthorityStorageKind(StrEnum):
    """Closed Firestore record families used by the authority database."""

    ROLLOUT_ROOT = "controlgraph-rollout-roots-v1"
    SERVICE_CLAIM = "controlgraph-service-claims-v1"
    EPOCH_AUTHORITY = "controlgraph-epoch-authorities-v1"
    EXECUTION_RECEIPT = "controlgraph-execution-receipts-v1"


class AuthorityStorageDocument(StrictContractModel):
    """Exact canonical payload wrapper stored at one fixed Firestore identity."""

    schema_version: Literal["controlgraph.authority-storage-document/v1"]
    record_kind: AuthorityStorageKind
    logical_id: Identifier
    revision: Annotated[int, Field(ge=0, le=2**53 - 1)]
    mutation_id: Identifier
    canonical_payload: Annotated[str, Field(min_length=2, max_length=MAX_CONTRACT_BYTES)]
    payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        model_type: type[RolloutRoot | ServiceClaimRecord | EpochAuthorityRecord | ExecutionReceipt]
        if self.record_kind is AuthorityStorageKind.ROLLOUT_ROOT:
            model_type = RolloutRoot
        elif self.record_kind is AuthorityStorageKind.SERVICE_CLAIM:
            model_type = ServiceClaimRecord
        elif self.record_kind is AuthorityStorageKind.EPOCH_AUTHORITY:
            model_type = EpochAuthorityRecord
        else:
            model_type = ExecutionReceipt
        try:
            payload = decode_contract(self.canonical_payload, model_type)
        except ContractError as error:
            raise ValueError("authority storage payload is invalid") from error
        if canonical_sha256(payload) != self.payload_sha256:
            raise ValueError("authority storage payload digest does not match")
        if self.record_kind is AuthorityStorageKind.ROLLOUT_ROOT and self.revision != 0:
            raise ValueError("immutable rollout root must remain at revision zero")
        if (
            self.record_kind is AuthorityStorageKind.EPOCH_AUTHORITY
            and self.revision != cast(EpochAuthorityRecord, payload).revision
        ):
            raise ValueError("authority storage and payload revisions do not match")
        if self.record_kind is AuthorityStorageKind.SERVICE_CLAIM:
            expected_logical_id = canonical_sha256(payload.target)
        elif self.record_kind is AuthorityStorageKind.EXECUTION_RECEIPT:
            receipt = cast(ExecutionReceipt, payload)
            expected_logical_id = execution_receipt_logical_id(
                receipt.target,
                receipt.idempotency_key,
            )
            if receipt.receipt_id != expected_logical_id:
                raise ValueError("execution receipt identity does not match its claim key")
        else:
            expected_logical_id = payload.root_id
        if self.logical_id != expected_logical_id:
            raise ValueError("authority storage payload identity does not match")
        return self


class _LogicalIdentity(StrictContractModel):
    value: Identifier


def _document_id(kind: AuthorityStorageKind, logical_id: str) -> str:
    if type(kind) is not AuthorityStorageKind:
        raise TypeError("authority storage kind must be exact")
    try:
        identity = _LogicalIdentity(value=logical_id).value
        encoded_identity = identity.encode("ascii")
    except (TypeError, UnicodeEncodeError, ValueError, ValidationError) as error:
        raise ValueError("authority storage logical identifier is invalid") from error
    material = FIRESTORE_DOCUMENT_ID_DOMAIN + kind.value.encode("ascii") + b"\0"
    return hashlib.sha256(material + encoded_identity).hexdigest()


def rollout_root_document_id(root_id: str) -> str:
    """Return the domain-separated document ID for one rollout root."""

    return _document_id(AuthorityStorageKind.ROLLOUT_ROOT, root_id)


def service_claim_logical_id(target: TargetBinding) -> str:
    """Return the canonical service identity without exposing a Firestore path."""

    if type(target) is not TargetBinding:
        raise TypeError("service claim target must be exact")
    return canonical_sha256(target)


def service_claim_document_id(target: TargetBinding) -> str:
    """Return the domain-separated document ID for one configured service."""

    return _document_id(AuthorityStorageKind.SERVICE_CLAIM, service_claim_logical_id(target))


def epoch_authority_document_id(root_id: str) -> str:
    """Return the domain-separated document ID for one root's authority."""

    return _document_id(AuthorityStorageKind.EPOCH_AUTHORITY, root_id)


def execution_receipt_logical_id(target: TargetBinding, idempotency_key: str) -> str:
    """Return one target-bound claim identity for an idempotency key."""

    if type(target) is not TargetBinding:
        raise TypeError("execution receipt target must be exact")
    return receipt_claim_identity(
        MutationTargetKey(
            project_id=target.project_id,
            region=target.region,
            environment=target.environment,
            service_name=target.service_name,
        ),
        idempotency_key,
    )


def execution_receipt_document_id(target: TargetBinding, idempotency_key: str) -> str:
    """Return the document ID for one target-bound idempotency claim."""

    return _document_id(
        AuthorityStorageKind.EXECUTION_RECEIPT,
        execution_receipt_logical_id(target, idempotency_key),
    )


__all__ = [
    "AUTHORITY_STORAGE_DOCUMENT_V1",
    "FIRESTORE_DOCUMENT_ID_DOMAIN",
    "SERVICE_CLAIM_V1",
    "AuthorityStorageDocument",
    "AuthorityStorageKind",
    "ServiceClaimRecord",
    "ServiceClaimStatus",
    "epoch_authority_document_id",
    "execution_receipt_document_id",
    "execution_receipt_logical_id",
    "rollout_root_document_id",
    "service_claim_document_id",
    "service_claim_logical_id",
]
