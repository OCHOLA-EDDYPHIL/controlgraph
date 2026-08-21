"""Readback-only resolution for one exact ambiguous execution receipt."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.receipt_execution import (
    ReceiptReadbackResult,
    TargetBoundReceiptReadback,
)
from controlgraph_canary.application.root_authority import (
    RootAuthorityBundleReader,
    inspect_root_authority_bundle,
)
from controlgraph_canary.contracts.ambiguous_receipt_readback import (
    AmbiguousReceiptReadbackCommandV1,
    AmbiguousReceiptReadbackDisposition,
    AmbiguousReceiptReadbackResultV1,
    ambiguous_receipt_readback_result,
    ambiguous_receipt_resolution_evidence_id,
    reconstruct_ambiguous_receipt_predecessor,
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
from controlgraph_canary.contracts.receipt_authority import StoredExecutionReceiptV1
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    ServiceClaimStatus,
    execution_receipt_logical_id,
)


class AmbiguousReceiptReadbackErrorCode(StrEnum):
    """Stable fail-closed result classes from one resolution attempt."""

    RECEIPT_UNAVAILABLE = "AMBIGUOUS_RECEIPT_READBACK_RECEIPT_UNAVAILABLE"
    RECEIPT_MISSING = "AMBIGUOUS_RECEIPT_READBACK_RECEIPT_MISSING"
    RECEIPT_CONFLICT = "AMBIGUOUS_RECEIPT_READBACK_RECEIPT_CONFLICT"
    RECEIPT_STATE_DENIED = "AMBIGUOUS_RECEIPT_READBACK_RECEIPT_STATE_DENIED"
    ROOT_UNAVAILABLE = "AMBIGUOUS_RECEIPT_READBACK_ROOT_UNAVAILABLE"
    ROOT_BINDING_MISMATCH = "AMBIGUOUS_RECEIPT_READBACK_ROOT_BINDING_MISMATCH"
    AUTHORITY_STALE = "AMBIGUOUS_RECEIPT_READBACK_AUTHORITY_STALE"
    OPERATION_UNVERIFIED = "AMBIGUOUS_RECEIPT_READBACK_OPERATION_UNVERIFIED"
    POSTSTATE_UNVERIFIED = "AMBIGUOUS_RECEIPT_READBACK_POSTSTATE_UNVERIFIED"
    COMPARE_AND_SET_UNCONFIRMED = (
        "AMBIGUOUS_RECEIPT_READBACK_COMPARE_AND_SET_UNCONFIRMED"
    )


class AmbiguousReceiptReadbackError(RuntimeError):
    """Sanitized readback-only failure with no provider or record payload."""

    def __init__(self, code: AmbiguousReceiptReadbackErrorCode) -> None:
        if type(code) is not AmbiguousReceiptReadbackErrorCode:
            raise TypeError("an exact ambiguous receipt readback error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class TargetBoundProviderOperationReadback(Protocol):
    """Confirm one exact provider operation without carrying mutation authority."""

    @property
    def target(self) -> TargetBinding: ...

    async def terminal_success(self, operation_name: str) -> bool: ...


@runtime_checkable
class AmbiguousReceiptResolutionStore(Protocol):
    """Read and atomically resolve only one authority-fenced ambiguous receipt."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...

    async def resolve_ambiguous_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        expected_service_claim: StoredRecord[ServiceClaimRecord],
    ) -> StoredRecord[ExecutionReceipt]: ...


@dataclass(frozen=True, slots=True)
class _ResolvedBoundary:
    expected_poststate: TargetConfigurationProjection
    receipt: StoredRecord[ExecutionReceipt]
    authority: StoredRecord[EpochAuthorityRecord]
    service_claim: StoredRecord[ServiceClaimRecord]


class AmbiguousReceiptReadbackResolver:
    """Classify one stored ambiguous receipt using only independent reads and CAS."""

    def __init__(
        self,
        *,
        root_reader: RootAuthorityBundleReader,
        receipt_store: AmbiguousReceiptResolutionStore,
        operation_readback: TargetBoundProviderOperationReadback,
        target_readback: TargetBoundReceiptReadback,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        try:
            targets = (
                root_reader.target,
                receipt_store.target,
                operation_readback.target,
                target_readback.target,
            )
        except Exception:
            raise TypeError("readback-only resolver dependencies must be target-bound") from None
        if any(type(target) is not TargetBinding for target in targets):
            raise TypeError("readback-only resolver dependencies must use exact targets")
        if len(set(target.model_dump_json() for target in targets)) != 1:
            raise ValueError("readback-only resolver dependencies do not share one target")
        if clock is not None and not callable(clock):
            raise TypeError("readback-only resolver clock must be callable")
        self._root_reader = root_reader
        self._receipt_store = receipt_store
        self._operation_readback = operation_readback
        self._target_readback = target_readback
        self._target = targets[0]
        self._clock = clock or _now_utc_second

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def resolve(
        self,
        command: AmbiguousReceiptReadbackCommandV1,
    ) -> AmbiguousReceiptReadbackResultV1:
        """Resolve or safely adopt only the command's exact stored receipt."""

        if type(command) is not AmbiguousReceiptReadbackCommandV1:
            raise TypeError("an exact ambiguous receipt readback command is required")
        stored = await self._read_receipt(command)
        adoption_candidate = self._adoption_candidate(command, stored)
        if adoption_candidate:
            if not _is_exact_adopted_receipt(command, stored):
                raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_STATE_DENIED)
            return _result(
                command,
                AmbiguousReceiptReadbackDisposition.ADOPTED,
                stored,
            )
        self._require_exact_ambiguous(command, stored)

        boundary = await self._read_and_validate_boundary(command, stored)
        receipt = boundary.receipt.value
        operation_name = receipt.provider_operation
        if operation_name is None:
            raise _error(AmbiguousReceiptReadbackErrorCode.OPERATION_UNVERIFIED)
        try:
            operation_verified = await self._operation_readback.terminal_success(
                operation_name
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            operation_verified = False
        if operation_verified is not True:
            raise _error(AmbiguousReceiptReadbackErrorCode.OPERATION_UNVERIFIED)

        try:
            observed = await self._target_readback.readback(boundary.expected_poststate)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _error(AmbiguousReceiptReadbackErrorCode.POSTSTATE_UNVERIFIED) from None
        if (
            type(observed) is not ReceiptReadbackResult
            or observed.state != boundary.expected_poststate
            or observed.observed_etag is None
        ):
            raise _error(AmbiguousReceiptReadbackErrorCode.POSTSTATE_UNVERIFIED)

        refreshed_boundary = await self._read_and_validate_boundary(command, stored)
        if refreshed_boundary.expected_poststate != boundary.expected_poststate:
            raise _error(AmbiguousReceiptReadbackErrorCode.ROOT_BINDING_MISMATCH)

        marker = ambiguous_receipt_resolution_evidence_id(command)
        if marker in receipt.evidence_ids or len(receipt.evidence_ids) >= 64:
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_CONFLICT)
        now = _require_utc_second(self._clock())
        if _utc_second(receipt.updated_at) > now:
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_CONFLICT)
        replacement = ExecutionReceipt(
            **{
                **receipt.model_dump(mode="python"),
                "outcome": ReceiptOutcome.VERIFIED,
                "reason_code": None,
                "observed_etag": observed.observed_etag,
                "updated_at": _utc_second_text(now),
                "evidence_ids": (*receipt.evidence_ids, marker),
            }
        )
        if not _is_exact_resolution_replacement(
            receipt,
            replacement,
            marker=marker,
            observed_etag=observed.observed_etag,
        ):
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_CONFLICT)
        try:
            updated = await self._receipt_store.resolve_ambiguous_receipt(
                stored,
                replacement,
                refreshed_boundary.authority,
                refreshed_boundary.service_claim,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            readback = await self._read_after_unknown(command)
            if readback is None or not _is_exact_adopted_receipt(command, readback):
                raise _error(
                    AmbiguousReceiptReadbackErrorCode.COMPARE_AND_SET_UNCONFIRMED
                ) from None
            return _result(
                command,
                AmbiguousReceiptReadbackDisposition.ADOPTED,
                readback,
            )
        if updated != StoredRecord(replacement, stored.revision + 1):
            raise _error(AmbiguousReceiptReadbackErrorCode.COMPARE_AND_SET_UNCONFIRMED)
        return _result(
            command,
            AmbiguousReceiptReadbackDisposition.RESOLVED,
            updated,
        )

    async def _read_receipt(
        self,
        command: AmbiguousReceiptReadbackCommandV1,
    ) -> StoredRecord[ExecutionReceipt]:
        try:
            stored = await self._receipt_store.read_receipt(command.idempotency_key)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_UNAVAILABLE) from None
        if stored is None:
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_MISSING)
        if type(stored) is not StoredRecord or type(stored.value) is not ExecutionReceipt:
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_CONFLICT)
        return stored

    async def _read_after_unknown(
        self,
        command: AmbiguousReceiptReadbackCommandV1,
    ) -> StoredRecord[ExecutionReceipt] | None:
        try:
            current = await self._receipt_store.read_receipt(command.idempotency_key)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None
        if type(current) is not StoredRecord or type(current.value) is not ExecutionReceipt:
            return None
        return current

    def _adoption_candidate(
        self,
        command: AmbiguousReceiptReadbackCommandV1,
        stored: StoredRecord[ExecutionReceipt],
    ) -> bool:
        receipt = stored.value
        marker = ambiguous_receipt_resolution_evidence_id(command)
        return (
            receipt.outcome is ReceiptOutcome.VERIFIED
            and stored.revision == command.expected_storage_revision + 1
            and bool(receipt.evidence_ids)
            and receipt.evidence_ids[-1] == marker
            and receipt.evidence_ids.count(marker) == 1
        )

    def _require_exact_ambiguous(
        self,
        command: AmbiguousReceiptReadbackCommandV1,
        stored: StoredRecord[ExecutionReceipt],
    ) -> None:
        if not _receipt_matches_locator(command, stored, target=self._target):
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_CONFLICT)
        if (
            stored.revision != command.expected_storage_revision
            or canonical_sha256(stored.value) != command.expected_receipt_sha256
        ):
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_CONFLICT)
        receipt = stored.value
        if (
            receipt.outcome is not ReceiptOutcome.AMBIGUOUS
            or receipt.reason_code is not ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS
            or receipt.provider_operation is None
            or receipt.observed_etag is None
            or receipt.observed_etag != command.expected_ambiguous_observed_etag
            or receipt.updated_at != command.expected_ambiguous_updated_at
        ):
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_STATE_DENIED)

    async def _read_and_validate_boundary(
        self,
        command: AmbiguousReceiptReadbackCommandV1,
        stored: StoredRecord[ExecutionReceipt],
    ) -> _ResolvedBoundary:
        if not _receipt_matches_locator(command, stored, target=self._target):
            raise _error(AmbiguousReceiptReadbackErrorCode.RECEIPT_CONFLICT)
        try:
            bundle = await self._root_reader.read_root_creation_bundle(command.root_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _error(AmbiguousReceiptReadbackErrorCode.ROOT_UNAVAILABLE) from None
        if bundle is None:
            raise _error(AmbiguousReceiptReadbackErrorCode.ROOT_UNAVAILABLE)
        trusted = inspect_root_authority_bundle(bundle, target=self._target)
        if trusted is None:
            raise _error(AmbiguousReceiptReadbackErrorCode.ROOT_BINDING_MISMATCH)
        receipt = stored.value
        root = trusted.root
        plan = root.content.rollout_plan
        expected = TargetConfigurationProjection(
            target=self._target,
            stable_revision=plan.stable_revision,
            candidate_revision=plan.candidate_revision,
            stable_percent=plan.stable_percent,
            candidate_percent=plan.candidate_percent,
            concurrency=plan.concurrency,
        )
        if (
            root.root_id != command.root_id
            or root.root_sha256 != command.expected_root_sha256
            or receipt.root_id != root.root_id
            or receipt.root_sha256 != root.root_sha256
            or receipt.target != root.content.target
            or receipt.action is not CapabilityAction.APPLY_CANARY
            or receipt.plan_sha256 != canonical_sha256(plan)
            or receipt.provider_etag != root.content.stable_snapshot.provider_etag
            or receipt.expected_poststate_sha256
            != target_configuration_projection_sha256(expected)
        ):
            raise _error(AmbiguousReceiptReadbackErrorCode.ROOT_BINDING_MISMATCH)
        if (
            trusted.service_claim.status is not ServiceClaimStatus.ACTIVE
            or trusted.authority.current_epoch != command.expected_epoch
            or receipt.epoch != trusted.authority.current_epoch
            or receipt.observed_authority_epoch != trusted.authority.current_epoch
        ):
            raise _error(AmbiguousReceiptReadbackErrorCode.AUTHORITY_STALE)
        return _ResolvedBoundary(
            expected_poststate=expected,
            receipt=stored,
            authority=StoredRecord(
                trusted.authority,
                trusted.authority_revision,
            ),
            service_claim=StoredRecord(
                trusted.service_claim,
                trusted.service_claim_revision,
            ),
        )


def _receipt_matches_locator(
    command: AmbiguousReceiptReadbackCommandV1,
    stored: StoredRecord[ExecutionReceipt],
    *,
    target: TargetBinding,
) -> bool:
    receipt = stored.value
    return (
        receipt.receipt_id == execution_receipt_logical_id(target, command.idempotency_key)
        and receipt.target == target
        and receipt.root_id == command.root_id
        and receipt.root_sha256 == command.expected_root_sha256
        and receipt.epoch == command.expected_epoch
        and receipt.action is command.action
        and receipt.request_id == command.request_id
        and receipt.idempotency_key == command.idempotency_key
        and receipt.capability_sha256 == command.capability_sha256
    )


def _is_exact_adopted_receipt(
    command: AmbiguousReceiptReadbackCommandV1,
    stored: StoredRecord[ExecutionReceipt],
) -> bool:
    receipt = stored.value
    marker = ambiguous_receipt_resolution_evidence_id(command)
    shape_is_exact = (
        stored.revision == command.expected_storage_revision + 1
        and receipt.outcome is ReceiptOutcome.VERIFIED
        and receipt.reason_code is None
        and receipt.observed_etag is not None
        and receipt.provider_operation is not None
        and receipt.observed_authority_epoch == command.expected_epoch
        and bool(receipt.evidence_ids)
        and receipt.evidence_ids[-1] == marker
        and receipt.evidence_ids.count(marker) == 1
        and receipt.updated_at >= command.expected_ambiguous_updated_at
    )
    if not shape_is_exact:
        return False
    try:
        reconstructed = reconstruct_ambiguous_receipt_predecessor(command, receipt)
    except (TypeError, ValueError):
        return False
    return canonical_sha256(reconstructed) == command.expected_receipt_sha256


def _is_exact_resolution_replacement(
    before: ExecutionReceipt,
    after: ExecutionReceipt,
    *,
    marker: str,
    observed_etag: str,
) -> bool:
    mutable_fields = {
        "outcome",
        "reason_code",
        "observed_etag",
        "updated_at",
        "evidence_ids",
    }
    return (
        all(
            getattr(before, field) == getattr(after, field)
            for field in ExecutionReceipt.model_fields
            if field not in mutable_fields
        )
        and after.outcome is ReceiptOutcome.VERIFIED
        and after.reason_code is None
        and after.observed_etag == observed_etag
        and after.updated_at >= before.updated_at
        and after.evidence_ids == (*before.evidence_ids, marker)
    )


def _result(
    command: AmbiguousReceiptReadbackCommandV1,
    disposition: AmbiguousReceiptReadbackDisposition,
    stored: StoredRecord[ExecutionReceipt],
) -> AmbiguousReceiptReadbackResultV1:
    return ambiguous_receipt_readback_result(
        command=command,
        disposition=disposition,
        stored_receipt=StoredExecutionReceiptV1(
            schema_version="controlgraph.stored-execution-receipt/v1",
            receipt=stored.value,
            storage_revision=stored.revision,
        ),
    )


def _error(code: AmbiguousReceiptReadbackErrorCode) -> AmbiguousReceiptReadbackError:
    return AmbiguousReceiptReadbackError(code)


def _require_utc_second(value: datetime) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond
    ):
        raise ValueError("readback-only resolver clock is invalid")
    return value


def _utc_second(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _utc_second_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "AmbiguousReceiptReadbackError",
    "AmbiguousReceiptReadbackErrorCode",
    "AmbiguousReceiptReadbackResolver",
    "AmbiguousReceiptResolutionStore",
    "TargetBoundProviderOperationReadback",
]
