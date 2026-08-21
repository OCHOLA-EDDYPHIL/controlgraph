"""Canonical contracts for the narrow coordinator receipt-authority facade."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal, Self

from pydantic import model_validator

from controlgraph_canary.contracts.base import (
    Identifier,
    NonNegativeSafeInteger,
    OpaqueToken,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.storage import ServiceClaimRecord, ServiceClaimStatus

_READBACK_RESOLUTION_MARKER = re.compile(r"^cgrrb:[0-9a-f]{64}$")


class ReceiptAuthorityOperation(StrEnum):
    """The only receipt operations exposed by the coordinator facade."""

    CLAIM = "CLAIM"
    READ = "READ"
    COMPARE_AND_SET = "COMPARE_AND_SET"
    RESOLVE_AMBIGUOUS = "RESOLVE_AMBIGUOUS"


class ReceiptAuthorityDisposition(StrEnum):
    """Closed canonical outcomes from one receipt-authority request."""

    CLAIM_CREATED = "CLAIM_CREATED"
    CLAIM_ADOPTED = "CLAIM_ADOPTED"
    CLAIM_CONFLICT = "CLAIM_CONFLICT"
    RECEIPT_FOUND = "RECEIPT_FOUND"
    RECEIPT_NOT_FOUND = "RECEIPT_NOT_FOUND"
    RECEIPT_UPDATED = "RECEIPT_UPDATED"
    AMBIGUOUS_RECEIPT_RESOLVED = "AMBIGUOUS_RECEIPT_RESOLVED"


class ReceiptMutationBindingV1(StrictContractModel):
    """Wire projection of one complete immutable mutation binding."""

    schema_version: Literal["controlgraph.receipt-mutation-binding/v1"]
    idempotency_key: Identifier
    request_id: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    action: CapabilityAction
    target: TargetBinding
    provider_precondition: OpaqueToken
    plan_sha256: Sha256Digest
    capability_sha256: Sha256Digest
    payload_sha256: Sha256Digest
    expected_poststate_sha256: Sha256Digest


class StoredExecutionReceiptV1(StrictContractModel):
    """One execution receipt and its monotonic authority-store revision."""

    schema_version: Literal["controlgraph.stored-execution-receipt/v1"]
    receipt: ExecutionReceipt
    storage_revision: NonNegativeSafeInteger


class StoredEpochAuthorityV1(StrictContractModel):
    """One exact epoch-authority record and its storage revision."""

    schema_version: Literal["controlgraph.stored-epoch-authority/v1"]
    authority: EpochAuthorityRecord
    storage_revision: NonNegativeSafeInteger

    @model_validator(mode="after")
    def validate_revision(self) -> Self:
        if self.storage_revision != self.authority.revision:
            raise ValueError("stored epoch authority revisions do not match")
        return self


class StoredServiceClaimV1(StrictContractModel):
    """One exact active service claim and its storage revision."""

    schema_version: Literal["controlgraph.stored-service-claim/v1"]
    service_claim: ServiceClaimRecord
    storage_revision: NonNegativeSafeInteger

    @model_validator(mode="after")
    def validate_active_revision(self) -> Self:
        if (
            self.service_claim.status is not ServiceClaimStatus.ACTIVE
            or self.storage_revision % 3 != 0
        ):
            raise ValueError("stored service claim is not at one active revision")
        return self


class ReceiptAuthorityClaimV1(StrictContractModel):
    """Exact initial receipt and mutation binding submitted for claim."""

    schema_version: Literal["controlgraph.receipt-authority-claim/v1"]
    receipt: ExecutionReceipt
    binding: ReceiptMutationBindingV1

    @model_validator(mode="after")
    def validate_target_and_identity(self) -> Self:
        if (
            self.receipt.target != self.binding.target
            or self.receipt.idempotency_key != self.binding.idempotency_key
            or self.receipt.request_id != self.binding.request_id
        ):
            raise ValueError("receipt claim does not match its wire binding")
        return self


class ReceiptAuthorityReadV1(StrictContractModel):
    """Target-bound lookup for one receipt idempotency identity."""

    schema_version: Literal["controlgraph.receipt-authority-read/v1"]
    idempotency_key: Identifier


class ReceiptAuthorityCompareAndSetV1(StrictContractModel):
    """Exact expected receipt revision and monotonic replacement."""

    schema_version: Literal["controlgraph.receipt-authority-compare-and-set/v1"]
    expected: StoredExecutionReceiptV1
    replacement: ExecutionReceipt

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        before = self.expected.receipt
        after = self.replacement
        immutable_identity = (
            "receipt_id",
            "request_id",
            "idempotency_key",
            "capability_sha256",
            "mutation_sha256",
            "plan_sha256",
            "expected_poststate_sha256",
            "target",
            "root_id",
            "root_sha256",
            "epoch",
            "action",
            "provider_etag",
            "dispatch_not_after",
            "created_at",
        )
        if any(getattr(before, field) != getattr(after, field) for field in immutable_identity):
            raise ValueError("receipt compare-and-set changes immutable identity")
        if any(evidence_id.startswith("cgrrb:") for evidence_id in after.evidence_ids):
            raise ValueError("readback resolution evidence requires its dedicated operation")
        return self


class ReceiptAuthorityResolveAmbiguousV1(StrictContractModel):
    """Exact AMBIGUOUS-to-VERIFIED transition fenced by active root authority."""

    schema_version: Literal["controlgraph.receipt-authority-resolve-ambiguous/v1"]
    expected: StoredExecutionReceiptV1
    replacement: ExecutionReceipt
    expected_authority: StoredEpochAuthorityV1
    expected_service_claim: StoredServiceClaimV1

    @model_validator(mode="after")
    def validate_resolution_fence(self) -> Self:
        before = self.expected.receipt
        after = self.replacement
        authority = self.expected_authority.authority
        claim = self.expected_service_claim.service_claim
        immutable_fields = {
            "schema_version",
            "receipt_id",
            "request_id",
            "idempotency_key",
            "capability_sha256",
            "mutation_sha256",
            "plan_sha256",
            "expected_poststate_sha256",
            "target",
            "root_id",
            "root_sha256",
            "epoch",
            "action",
            "provider_etag",
            "dispatch_not_after",
            "provider_operation",
            "observed_authority_epoch",
            "created_at",
        }
        if (
            before.outcome is not ReceiptOutcome.AMBIGUOUS
            or before.reason_code is not ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS
            or before.provider_operation is None
            or before.observed_etag is None
            or before.observed_authority_epoch != before.epoch
            or after.outcome is not ReceiptOutcome.VERIFIED
            or after.reason_code is not None
            or after.observed_etag is None
            or any(
                getattr(before, field) != getattr(after, field)
                for field in immutable_fields
            )
            or after.updated_at < before.updated_at
            or len(after.evidence_ids) != len(before.evidence_ids) + 1
            or after.evidence_ids[:-1] != before.evidence_ids
            or _READBACK_RESOLUTION_MARKER.fullmatch(after.evidence_ids[-1]) is None
            or authority.target != before.target
            or authority.root_id != before.root_id
            or authority.root_sha256 != before.root_sha256
            or authority.current_epoch != before.epoch
            or claim.target != before.target
            or claim.root_id != before.root_id
            or claim.root_sha256 != before.root_sha256
        ):
            raise ValueError("ambiguous receipt resolution fence is invalid")
        return self


class ReceiptAuthorityRequestV1(StrictContractModel):
    """One attempt-bound request to the fixed coordinator receipt facade."""

    schema_version: Literal["controlgraph.receipt-authority-request/v1"]
    operation: ReceiptAuthorityOperation
    attempt_id: Identifier
    target: TargetBinding
    claim: ReceiptAuthorityClaimV1 | None = None
    read: ReceiptAuthorityReadV1 | None = None
    compare_and_set: ReceiptAuthorityCompareAndSetV1 | None = None
    resolve_ambiguous: ReceiptAuthorityResolveAmbiguousV1 | None = None

    @model_validator(mode="after")
    def validate_operation_shape(self) -> Self:
        populated = {
            ReceiptAuthorityOperation.CLAIM: self.claim is not None,
            ReceiptAuthorityOperation.READ: self.read is not None,
            ReceiptAuthorityOperation.COMPARE_AND_SET: self.compare_and_set is not None,
            ReceiptAuthorityOperation.RESOLVE_AMBIGUOUS: (
                self.resolve_ambiguous is not None
            ),
        }
        if not populated[self.operation] or sum(populated.values()) != 1:
            raise ValueError("receipt authority request operation shape is invalid")
        if self.claim is not None and self.claim.receipt.target != self.target:
            raise ValueError("receipt claim target does not match the facade target")
        if self.compare_and_set is not None and (
            self.compare_and_set.expected.receipt.target != self.target
            or self.compare_and_set.replacement.target != self.target
        ):
            raise ValueError("receipt compare-and-set target does not match the facade target")
        if self.resolve_ambiguous is not None and (
            self.resolve_ambiguous.expected.receipt.target != self.target
            or self.resolve_ambiguous.replacement.target != self.target
            or self.resolve_ambiguous.expected_authority.authority.target != self.target
            or self.resolve_ambiguous.expected_service_claim.service_claim.target
            != self.target
        ):
            raise ValueError("ambiguous receipt resolution target is invalid")
        return self


class DirectReceiptCreateConfirmationV1(StrictContractModel):
    """Ephemeral response binding for one directly confirmed create attempt."""

    schema_version: Literal["controlgraph.direct-receipt-create-confirmation/v1"]
    attempt_id: Identifier
    request_sha256: Sha256Digest
    receipt_sha256: Sha256Digest
    mutation_sha256: Sha256Digest


class ReceiptAuthorityResponseV1(StrictContractModel):
    """Canonical response bound to one exact request and transport attempt."""

    schema_version: Literal["controlgraph.receipt-authority-response/v1"]
    operation: ReceiptAuthorityOperation
    disposition: ReceiptAuthorityDisposition
    attempt_id: Identifier
    request_sha256: Sha256Digest
    target: TargetBinding
    stored_receipt: StoredExecutionReceiptV1 | None = None
    direct_create_confirmation: DirectReceiptCreateConfirmationV1 | None = None

    @model_validator(mode="after")
    def validate_response_shape(self) -> Self:
        allowed = {
            ReceiptAuthorityOperation.CLAIM: {
                ReceiptAuthorityDisposition.CLAIM_CREATED,
                ReceiptAuthorityDisposition.CLAIM_ADOPTED,
                ReceiptAuthorityDisposition.CLAIM_CONFLICT,
            },
            ReceiptAuthorityOperation.READ: {
                ReceiptAuthorityDisposition.RECEIPT_FOUND,
                ReceiptAuthorityDisposition.RECEIPT_NOT_FOUND,
            },
            ReceiptAuthorityOperation.COMPARE_AND_SET: {
                ReceiptAuthorityDisposition.RECEIPT_UPDATED,
            },
            ReceiptAuthorityOperation.RESOLVE_AMBIGUOUS: {
                ReceiptAuthorityDisposition.AMBIGUOUS_RECEIPT_RESOLVED,
            },
        }
        if self.disposition not in allowed[self.operation]:
            raise ValueError("receipt authority response disposition is invalid")

        requires_stored = self.disposition in {
            ReceiptAuthorityDisposition.CLAIM_CREATED,
            ReceiptAuthorityDisposition.CLAIM_ADOPTED,
            ReceiptAuthorityDisposition.RECEIPT_FOUND,
            ReceiptAuthorityDisposition.RECEIPT_UPDATED,
            ReceiptAuthorityDisposition.AMBIGUOUS_RECEIPT_RESOLVED,
        }
        if requires_stored != (self.stored_receipt is not None):
            raise ValueError("receipt authority response stored-record shape is invalid")
        if self.stored_receipt is not None and self.stored_receipt.receipt.target != self.target:
            raise ValueError("receipt authority response target is invalid")

        if self.disposition is ReceiptAuthorityDisposition.CLAIM_CREATED:
            stored = self.stored_receipt
            confirmation = self.direct_create_confirmation
            if (
                stored is None
                or stored.storage_revision != 0
                or stored.receipt.outcome is not ReceiptOutcome.CLAIMED
                or confirmation is None
                or confirmation.attempt_id != self.attempt_id
                or confirmation.request_sha256 != self.request_sha256
                or confirmation.receipt_sha256 != canonical_sha256(stored.receipt)
                or confirmation.mutation_sha256 != stored.receipt.mutation_sha256
            ):
                raise ValueError("direct receipt-create confirmation is invalid")
        elif self.direct_create_confirmation is not None:
            raise ValueError("only a direct create may carry dispatch confirmation")
        return self


__all__ = [
    "DirectReceiptCreateConfirmationV1",
    "ReceiptAuthorityClaimV1",
    "ReceiptAuthorityCompareAndSetV1",
    "ReceiptAuthorityDisposition",
    "ReceiptAuthorityOperation",
    "ReceiptAuthorityReadV1",
    "ReceiptAuthorityRequestV1",
    "ReceiptAuthorityResolveAmbiguousV1",
    "ReceiptAuthorityResponseV1",
    "ReceiptMutationBindingV1",
    "StoredEpochAuthorityV1",
    "StoredExecutionReceiptV1",
    "StoredServiceClaimV1",
]
