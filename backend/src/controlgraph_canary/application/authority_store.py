"""Cloud-independent port for durable rollout authority and receipts."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Protocol, runtime_checkable

from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    EpochAuthorityRecord,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    RolloutRoot,
    TargetBinding,
)
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV2,
    RolloutRootV3,
    RootCreationResultV1,
    RootCreationResultV2,
    SignedEvidenceEventV1,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    execution_receipt_logical_id,
)


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


class _DirectReceiptCreateKey:
    pass


_DIRECT_RECEIPT_CREATE_KEY = _DirectReceiptCreateKey()


class DirectReceiptCreate:
    """One-use proof of an uninterrupted, directly confirmed receipt create."""

    __slots__ = (
        "_attempt_id",
        "_available",
        "_binding",
        "_claimed_receipt",
        "_lock",
        "_request_sha256",
    )

    def __init__(
        self,
        key: _DirectReceiptCreateKey,
        claimed_receipt: StoredRecord[ExecutionReceipt],
        binding: MutationBinding,
        *,
        attempt_id: str | None = None,
        request_sha256: str | None = None,
    ) -> None:
        if key is not _DIRECT_RECEIPT_CREATE_KEY:
            raise TypeError("direct receipt-create proof is authority-issued")
        _validate_initial_receipt_claim(claimed_receipt)
        if type(binding) is not MutationBinding or not _receipt_matches_binding(
            claimed_receipt.value,
            binding,
        ):
            raise ValueError("direct receipt create does not match its mutation binding")
        if (attempt_id is None) != (request_sha256 is None):
            raise ValueError("direct receipt-create transport binding is incomplete")
        if attempt_id is not None and (
            type(attempt_id) is not str
            or not attempt_id
            or attempt_id != attempt_id.strip()
            or len(attempt_id) > 128
        ):
            raise ValueError("direct receipt-create attempt binding is invalid")
        if request_sha256 is not None and (
            type(request_sha256) is not str
            or len(request_sha256) != 64
            or any(character not in "0123456789abcdef" for character in request_sha256)
        ):
            raise ValueError("direct receipt-create request binding is invalid")
        self._claimed_receipt = claimed_receipt
        self._binding = binding
        self._attempt_id = attempt_id
        self._request_sha256 = request_sha256
        self._available = True
        self._lock = Lock()

    @classmethod
    def _from_direct_store_create(
        cls,
        claimed_receipt: StoredRecord[ExecutionReceipt],
        binding: MutationBinding,
    ) -> DirectReceiptCreate:
        """Issue only after a store directly confirms its initial create."""

        return cls(_DIRECT_RECEIPT_CREATE_KEY, claimed_receipt, binding)

    @classmethod
    def _from_direct_authority_confirmation(
        cls,
        claimed_receipt: StoredRecord[ExecutionReceipt],
        binding: MutationBinding,
        *,
        attempt_id: str,
        request_sha256: str,
        confirmed_attempt_id: str,
        confirmed_request_sha256: str,
        confirmed_receipt_sha256: str,
        confirmed_mutation_sha256: str,
    ) -> DirectReceiptCreate:
        """Issue only for a response bound to the exact one-shot facade request."""

        values = (
            attempt_id,
            request_sha256,
            confirmed_attempt_id,
            confirmed_request_sha256,
            confirmed_receipt_sha256,
            confirmed_mutation_sha256,
        )
        if any(type(value) is not str for value in values):
            raise TypeError("direct receipt-create confirmation binding is invalid")
        if (
            not hmac.compare_digest(attempt_id, confirmed_attempt_id)
            or not hmac.compare_digest(request_sha256, confirmed_request_sha256)
            or not hmac.compare_digest(
                canonical_sha256(claimed_receipt.value),
                confirmed_receipt_sha256,
            )
            or not hmac.compare_digest(
                mutation_identity(binding),
                confirmed_mutation_sha256,
            )
        ):
            raise ValueError("direct receipt-create confirmation does not match its request")
        return cls(
            _DIRECT_RECEIPT_CREATE_KEY,
            claimed_receipt,
            binding,
            attempt_id=attempt_id,
            request_sha256=request_sha256,
        )

    def _take_claim(
        self,
    ) -> tuple[StoredRecord[ExecutionReceipt], MutationBinding]:
        with self._lock:
            if not self._available:
                raise ValueError("direct receipt-create proof is already consumed")
            self._available = False
            return self._claimed_receipt, self._binding


@dataclass(frozen=True, slots=True)
class ReceiptClaimCreated:
    """A fresh claim with the only proof permitted to mint dispatch ownership."""

    receipt: StoredRecord[ExecutionReceipt]
    direct_create: DirectReceiptCreate

    def __post_init__(self) -> None:
        _validate_initial_receipt_claim(self.receipt)
        if type(self.direct_create) is not DirectReceiptCreate:
            raise TypeError("a direct receipt-create proof is required")


@dataclass(frozen=True, slots=True)
class ReceiptClaimAdopted:
    """An exact existing receipt that never carries dispatch authority."""

    receipt: StoredRecord[ExecutionReceipt]

    def __post_init__(self) -> None:
        if (
            type(self.receipt) is not StoredRecord
            or type(self.receipt.value) is not ExecutionReceipt
        ):
            raise TypeError("an exact stored receipt is required")


@dataclass(frozen=True, slots=True)
class ReceiptClaimConflict:
    """Stable denial for target-bound idempotency reuse with different work."""

    reason_code: ReasonCode = ReasonCode.IDEMPOTENCY_CONFLICT

    def __post_init__(self) -> None:
        if self.reason_code is not ReasonCode.IDEMPOTENCY_CONFLICT:
            raise ValueError("receipt claim conflict reason is fixed")


type ReceiptClaimResult = ReceiptClaimCreated | ReceiptClaimAdopted | ReceiptClaimConflict


def _validate_initial_receipt_claim(claimed: object) -> None:
    if type(claimed) is not StoredRecord:
        raise TypeError("an exact stored receipt is required")
    receipt = claimed.value
    if type(receipt) is not ExecutionReceipt:
        raise TypeError("an exact claimed receipt is required")
    if (
        claimed.revision != 0
        or receipt.outcome is not ReceiptOutcome.CLAIMED
        or receipt.receipt_id
        != execution_receipt_logical_id(receipt.target, receipt.idempotency_key)
    ):
        raise ValueError("receipt is not one initial claim")


def _receipt_matches_binding(
    receipt: ExecutionReceipt,
    binding: MutationBinding,
) -> bool:
    target = binding.target
    return (
        type(binding.action) is MutationAction
        and type(target) is MutationTargetKey
        and receipt.idempotency_key == binding.idempotency_key
        and receipt.request_id == binding.request_id
        and receipt.root_id == binding.root_id
        and receipt.root_sha256 == binding.root_sha256
        and receipt.epoch == binding.epoch
        and receipt.action.value == binding.action.value
        and receipt.target.project_id == target.project_id
        and receipt.target.region == target.region
        and receipt.target.environment == target.environment
        and receipt.target.service_name == target.service_name
        and receipt.provider_etag == binding.provider_precondition
        and receipt.plan_sha256 == binding.plan_sha256
        and receipt.capability_sha256 == binding.capability_sha256
        and receipt.mutation_sha256 == mutation_identity(binding)
        and receipt.expected_poststate_sha256 == binding.expected_poststate_sha256
    )


def validate_receipt_claim_binding(
    receipt: ExecutionReceipt,
    binding: MutationBinding,
) -> None:
    """Reject a claimed receipt that is not the exact canonical mutation binding."""

    claimed = StoredRecord(receipt, 0)
    _validate_initial_receipt_claim(claimed)
    if type(binding) is not MutationBinding or not _receipt_matches_binding(receipt, binding):
        raise ValueError("receipt claim does not match its mutation binding")


@dataclass(frozen=True, slots=True)
class CreatedRollout:
    """The three records committed atomically for a new rollout."""

    root: StoredRecord[RolloutRoot]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]


@dataclass(frozen=True, slots=True)
class RootCreationBundle:
    """One coherent view of six exact V2-era or V3-era root records."""

    root: StoredRecord[RolloutRootV2 | RolloutRootV3]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]
    lineage_anchor: StoredRecord[CapabilityLineageAnchorV1]
    signed_evidence: StoredRecord[SignedEvidenceEventV1]
    creation_result: StoredRecord[RootCreationResultV1 | RootCreationResultV2]

    def __post_init__(self) -> None:
        expected_types = (
            (self.service_claim, ServiceClaimRecord),
            (self.authority, EpochAuthorityRecord),
            (self.lineage_anchor, CapabilityLineageAnchorV1),
            (self.signed_evidence, SignedEvidenceEventV1),
        )
        if any(
            type(record) is not StoredRecord or type(record.value) is not model_type
            for record, model_type in expected_types
        ) or type(self.root) is not StoredRecord or type(self.creation_result) is not StoredRecord:
            raise TypeError("root creation bundle requires exact stored records")
        pair = (type(self.root.value), type(self.creation_result.value))
        if pair not in (
            (RolloutRootV2, RootCreationResultV1),
            (RolloutRootV3, RootCreationResultV2),
        ):
            raise TypeError("root creation bundle versions do not match")


@dataclass(frozen=True, slots=True)
class RootCreationWriteResult:
    """Direct creation or exact replay adoption with its coherent stored winner."""

    result: RootCreationResultV1 | RootCreationResultV2
    bundle: RootCreationBundle

    def __post_init__(self) -> None:
        if type(self.result) not in (RootCreationResultV1, RootCreationResultV2):
            raise TypeError("root creation write requires an exact result")
        persisted = self.bundle.creation_result.value
        normalized: RootCreationResultV1 | RootCreationResultV2
        if type(self.result) is RootCreationResultV1:
            normalized = RootCreationResultV1.model_validate(
                {**self.result.model_dump(mode="python"), "outcome": "CREATED"}
            )
        else:
            normalized = RootCreationResultV2.model_validate(
                {**self.result.model_dump(mode="python"), "outcome": "CREATED"}
            )
        if persisted != normalized:
            raise ValueError("root creation write result does not match its stored winner")


@dataclass(frozen=True, slots=True)
class IssuanceStateSnapshot:
    """One transactionally consistent view of issuance-bearing authority state."""

    root: StoredRecord[RolloutRoot]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]


@dataclass(frozen=True, slots=True)
class FinalAuthoritySnapshot:
    """One atomic view used immediately before a protected mutation."""

    root: StoredRecord[RolloutRoot]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]


@dataclass(frozen=True, slots=True)
class FencedServiceClaim:
    """The non-issuing claim fence and epoch advance committed atomically."""

    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]


@dataclass(frozen=True, slots=True)
class ReleasedServiceClaim:
    """The final claim release and unchanged fenced authority."""

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
        *,
        verified_candidate_revision_configuration_sha256: str,
    ) -> CreatedRollout: ...

    async def create_rollout_after_release(
        self,
        expected_released_claim: StoredRecord[ServiceClaimRecord],
        root: RolloutRoot,
        service_claim: ServiceClaimRecord,
        authority: EpochAuthorityRecord,
        *,
        verified_candidate_revision_configuration_sha256: str,
    ) -> CreatedRollout: ...

    async def create_or_adopt_root_creation_bundle(
        self,
        root: RolloutRootV3,
        service_claim: ServiceClaimRecord,
        authority: EpochAuthorityRecord,
        lineage_anchor: CapabilityLineageAnchorV1,
        signed_evidence: SignedEvidenceEventV1,
        creation_result: RootCreationResultV2,
        *,
        expected_released_claim: StoredRecord[ServiceClaimRecord] | None = None,
    ) -> RootCreationWriteResult: ...

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootCreationBundle | None: ...

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

    async def read_final_authority_snapshot(
        self,
        root_id: str,
    ) -> FinalAuthoritySnapshot | None: ...

    async def advance_authority(
        self,
        expected: StoredRecord[EpochAuthorityRecord],
        replacement: EpochAuthorityRecord,
    ) -> StoredRecord[EpochAuthorityRecord]: ...

    async def fence_service_claim(
        self,
        expected_claim: StoredRecord[ServiceClaimRecord],
        replacement_claim: ServiceClaimRecord,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        replacement_authority: EpochAuthorityRecord,
    ) -> FencedServiceClaim: ...

    async def release_service_claim(
        self,
        expected_claim: StoredRecord[ServiceClaimRecord],
        replacement_claim: ServiceClaimRecord,
        expected_authority: StoredRecord[EpochAuthorityRecord],
    ) -> ReleasedServiceClaim: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult: ...

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
    "DirectReceiptCreate",
    "FencedServiceClaim",
    "FinalAuthoritySnapshot",
    "IssuanceStateSnapshot",
    "ReceiptClaimAdopted",
    "ReceiptClaimConflict",
    "ReceiptClaimCreated",
    "ReceiptClaimResult",
    "ReleasedServiceClaim",
    "RootCreationBundle",
    "RootCreationWriteResult",
    "StoredRecord",
    "validate_receipt_claim_binding",
]
