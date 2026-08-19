"""Cloud-independent port for durable rollout authority and receipts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.contracts.models import (
    EpochAuthorityRecord,
    ExecutionReceipt,
    RolloutRoot,
    TargetBinding,
)
from controlgraph_canary.contracts.storage import ServiceClaimRecord


class AuthorityStoreErrorCode(StrEnum):
    """Stable, provider-independent persistence failure classes."""

    CONFLICT = "AUTHORITY_STORE_CONFLICT"
    CORRUPT_RECORD = "AUTHORITY_STORE_CORRUPT_RECORD"
    OUTCOME_UNKNOWN = "AUTHORITY_STORE_OUTCOME_UNKNOWN"
    UNAVAILABLE = "AUTHORITY_STORE_UNAVAILABLE"


class AuthorityStoreError(RuntimeError):
    """Sanitized persistence failure that carries no provider response material."""

    def __init__(self, code: AuthorityStoreErrorCode) -> None:
        if type(code) is not AuthorityStoreErrorCode:
            raise TypeError("an exact authority store error code is required")
        self.code = code
        super().__init__(code.value)


class AuthorityStoreConflict(AuthorityStoreError):
    def __init__(self) -> None:
        super().__init__(AuthorityStoreErrorCode.CONFLICT)


class AuthorityStoreCorruptRecord(AuthorityStoreError):
    def __init__(self) -> None:
        super().__init__(AuthorityStoreErrorCode.CORRUPT_RECORD)


class AuthorityStoreOutcomeUnknown(AuthorityStoreError):
    def __init__(self) -> None:
        super().__init__(AuthorityStoreErrorCode.OUTCOME_UNKNOWN)


class AuthorityStoreUnavailable(AuthorityStoreError):
    def __init__(self) -> None:
        super().__init__(AuthorityStoreErrorCode.UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class StoredRecord[RecordT]:
    """Provider-neutral record plus its monotonic persistence revision."""

    value: RecordT
    revision: int

    def __post_init__(self) -> None:
        if type(self.revision) is not int or not 0 <= self.revision <= 2**53 - 1:
            raise ValueError("stored record revision is invalid")


@dataclass(frozen=True, slots=True)
class CreatedRollout:
    """The three records committed atomically for a new rollout."""

    root: StoredRecord[RolloutRoot]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]


@dataclass(frozen=True, slots=True)
class IssuanceStateSnapshot:
    """One transactionally consistent view of issuance-bearing authority state."""

    root: StoredRecord[RolloutRoot]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]


@dataclass(frozen=True, slots=True)
class ReleasedServiceClaim:
    """The claim release and epoch advance committed by one transaction."""

    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]


@runtime_checkable
class AuthorityStore(Protocol):
    """Narrow persistence operations required by ControlGraph authority flows."""

    @property
    def target(self) -> TargetBinding: ...

    async def create_rollout(
        self,
        root: RolloutRoot,
        service_claim: ServiceClaimRecord,
        authority: EpochAuthorityRecord,
    ) -> CreatedRollout: ...

    async def read_rollout_root(self, root_id: str) -> StoredRecord[RolloutRoot] | None: ...

    async def read_service_claim(self) -> StoredRecord[ServiceClaimRecord] | None: ...

    async def read_authority(
        self,
        root_id: str,
    ) -> StoredRecord[EpochAuthorityRecord] | None: ...

    async def read_issuance_state(
        self,
        root_id: str,
    ) -> IssuanceStateSnapshot | None: ...

    async def advance_authority(
        self,
        expected: StoredRecord[EpochAuthorityRecord],
        replacement: EpochAuthorityRecord,
    ) -> StoredRecord[EpochAuthorityRecord]: ...

    async def release_service_claim(
        self,
        expected_claim: StoredRecord[ServiceClaimRecord],
        replacement_claim: ServiceClaimRecord,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        replacement_authority: EpochAuthorityRecord,
    ) -> ReleasedServiceClaim: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...

    async def claim_receipt(
        self,
        receipt: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]: ...

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]: ...


__all__ = [
    "AuthorityStore",
    "AuthorityStoreConflict",
    "AuthorityStoreCorruptRecord",
    "AuthorityStoreError",
    "AuthorityStoreErrorCode",
    "AuthorityStoreOutcomeUnknown",
    "AuthorityStoreUnavailable",
    "CreatedRollout",
    "IssuanceStateSnapshot",
    "ReleasedServiceClaim",
    "StoredRecord",
]
