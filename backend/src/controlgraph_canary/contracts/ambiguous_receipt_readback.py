"""Closed contracts for readback-only resolution of one ambiguous receipt."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Final, Literal, Self

from pydantic import model_validator

from controlgraph_canary.contracts.base import (
    Identifier,
    NonNegativeSafeInteger,
    OpaqueToken,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
)
from controlgraph_canary.contracts.receipt_authority import StoredExecutionReceiptV1

AMBIGUOUS_RECEIPT_READBACK_COMMAND_V1: Final = (
    "controlgraph.ambiguous-receipt-readback-command/v1"
)
AMBIGUOUS_RECEIPT_READBACK_RESULT_V1: Final = (
    "controlgraph.ambiguous-receipt-readback-result/v1"
)
READBACK_ONLY_CONFIRMATION: Final = "READBACK_ONLY"
_RESOLUTION_EVIDENCE_DOMAIN: Final = (
    b"controlgraph.ambiguous-receipt-readback-resolution-evidence/v1\0"
)


class AmbiguousReceiptReadbackDisposition(StrEnum):
    """Closed successful classifications for one readback-only run."""

    RESOLVED = "RESOLVED"
    ADOPTED = "ADOPTED"


class AmbiguousReceiptReadbackCommandV1(StrictContractModel):
    """Exact locator for one supported already-stored ambiguous receipt."""

    schema_version: Literal[
        "controlgraph.ambiguous-receipt-readback-command/v1"
    ]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    action: Literal[
        CapabilityAction.APPLY_CANARY,
        CapabilityAction.RECOVER_STABLE,
    ]
    request_id: Identifier
    idempotency_key: Identifier
    capability_sha256: Sha256Digest
    expected_receipt_sha256: Sha256Digest
    expected_storage_revision: NonNegativeSafeInteger
    expected_ambiguous_observed_etag: OpaqueToken
    expected_ambiguous_updated_at: UtcSecond
    confirmation: Literal["READBACK_ONLY"]


def ambiguous_receipt_resolution_evidence_id(
    command: AmbiguousReceiptReadbackCommandV1,
) -> str:
    """Derive the replay marker from the complete exact command locator."""

    if type(command) is not AmbiguousReceiptReadbackCommandV1:
        raise TypeError("an exact ambiguous receipt readback command is required")
    digest = hashlib.sha256(
        _RESOLUTION_EVIDENCE_DOMAIN + canonical_json_bytes(command)
    ).hexdigest()
    return f"cgrrb:{digest}"


def reconstruct_ambiguous_receipt_predecessor(
    command: AmbiguousReceiptReadbackCommandV1,
    verified: ExecutionReceipt,
) -> ExecutionReceipt:
    """Reconstruct the exact pinned predecessor from one marked verified receipt."""

    if type(command) is not AmbiguousReceiptReadbackCommandV1:
        raise TypeError("an exact ambiguous receipt readback command is required")
    if type(verified) is not ExecutionReceipt:
        raise TypeError("an exact verified execution receipt is required")
    marker = ambiguous_receipt_resolution_evidence_id(command)
    if (
        verified.outcome is not ReceiptOutcome.VERIFIED
        or not verified.evidence_ids
        or verified.evidence_ids[-1] != marker
        or verified.evidence_ids.count(marker) != 1
    ):
        raise ValueError("verified receipt does not contain one resolution marker")
    return ExecutionReceipt(
        **{
            **verified.model_dump(mode="python"),
            "outcome": ReceiptOutcome.AMBIGUOUS,
            "reason_code": ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
            "observed_etag": command.expected_ambiguous_observed_etag,
            "updated_at": command.expected_ambiguous_updated_at,
            "evidence_ids": verified.evidence_ids[:-1],
        }
    )


class AmbiguousReceiptReadbackResultV1(StrictContractModel):
    """Canonical verified receipt returned by a readback-only run."""

    schema_version: Literal[
        "controlgraph.ambiguous-receipt-readback-result/v1"
    ]
    disposition: AmbiguousReceiptReadbackDisposition
    command: AmbiguousReceiptReadbackCommandV1
    command_sha256: Sha256Digest
    resolution_evidence_id: Identifier
    stored_receipt: StoredExecutionReceiptV1

    @model_validator(mode="after")
    def validate_result_bindings(self) -> Self:
        receipt = self.stored_receipt.receipt
        try:
            predecessor = reconstruct_ambiguous_receipt_predecessor(
                self.command,
                receipt,
            )
        except (TypeError, ValueError):
            raise ValueError(
                "readback result does not reconstruct its pinned predecessor"
            ) from None
        if (
            self.command_sha256 != canonical_sha256(self.command)
            or self.resolution_evidence_id
            != ambiguous_receipt_resolution_evidence_id(self.command)
            or self.stored_receipt.storage_revision
            != self.command.expected_storage_revision + 1
            or receipt.root_id != self.command.root_id
            or receipt.root_sha256 != self.command.expected_root_sha256
            or receipt.epoch != self.command.expected_epoch
            or receipt.action is not self.command.action
            or receipt.request_id != self.command.request_id
            or receipt.idempotency_key != self.command.idempotency_key
            or receipt.capability_sha256 != self.command.capability_sha256
            or receipt.outcome is not ReceiptOutcome.VERIFIED
            or receipt.reason_code is not None
            or receipt.observed_etag is None
            or receipt.provider_operation is None
            or receipt.observed_authority_epoch != self.command.expected_epoch
            or receipt.updated_at < self.command.expected_ambiguous_updated_at
            or not receipt.evidence_ids
            or receipt.evidence_ids[-1] != self.resolution_evidence_id
            or receipt.evidence_ids.count(self.resolution_evidence_id) != 1
            or canonical_sha256(predecessor) != self.command.expected_receipt_sha256
        ):
            raise ValueError("readback result does not contain one marked verified receipt")
        return self


def ambiguous_receipt_readback_result(
    *,
    command: AmbiguousReceiptReadbackCommandV1,
    disposition: AmbiguousReceiptReadbackDisposition,
    stored_receipt: StoredExecutionReceiptV1,
) -> AmbiguousReceiptReadbackResultV1:
    """Construct one result while binding its deterministic command marker."""

    if type(command) is not AmbiguousReceiptReadbackCommandV1:
        raise TypeError("an exact ambiguous receipt readback command is required")
    if type(disposition) is not AmbiguousReceiptReadbackDisposition:
        raise TypeError("an exact ambiguous receipt readback disposition is required")
    return AmbiguousReceiptReadbackResultV1(
        schema_version=AMBIGUOUS_RECEIPT_READBACK_RESULT_V1,
        disposition=disposition,
        command=command,
        command_sha256=canonical_sha256(command),
        resolution_evidence_id=ambiguous_receipt_resolution_evidence_id(command),
        stored_receipt=stored_receipt,
    )


__all__ = [
    "AMBIGUOUS_RECEIPT_READBACK_COMMAND_V1",
    "AMBIGUOUS_RECEIPT_READBACK_RESULT_V1",
    "READBACK_ONLY_CONFIRMATION",
    "AmbiguousReceiptReadbackCommandV1",
    "AmbiguousReceiptReadbackDisposition",
    "AmbiguousReceiptReadbackResultV1",
    "ambiguous_receipt_readback_result",
    "ambiguous_receipt_resolution_evidence_id",
    "reconstruct_ambiguous_receipt_predecessor",
]
