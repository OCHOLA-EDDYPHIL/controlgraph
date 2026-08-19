"""Final epoch fencing and capability-sealed mutation dispatch."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from threading import Lock
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import (
    AuthorityStoreError,
    DirectReceiptCreate,
    FinalAuthoritySnapshot,
    StoredRecord,
)
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.cloud_run import (
    rollout_root_target_configuration_sha256,
)
from controlgraph_canary.application.identity import AuthenticationContext, ServiceRole
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    RolloutRoot,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    ServiceClaimStatus,
    execution_receipt_logical_id,
    service_claim_matches_root,
)


@runtime_checkable
class FinalAuthorityReader(Protocol):
    """Narrow reader required by the final mutation fence."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_final_authority_snapshot(
        self,
        root_id: str,
    ) -> FinalAuthoritySnapshot | None: ...


@runtime_checkable
class TargetBoundMutationAdapter[ResultT](Protocol):
    """A target-bound adapter that admits only an internal mutation permit."""

    @property
    def target(self) -> TargetBinding: ...

    @property
    def service_role(self) -> ServiceRole: ...

    async def mutate(self, permit: MutationPermit) -> ResultT: ...


@dataclass(frozen=True, slots=True)
class FinalAuthorityDenial:
    """Stable pre-dispatch denial retaining the receipt that must be closed."""

    reason_code: ReasonCode
    claimed_receipt: StoredRecord[ExecutionReceipt]
    observed_authority_epoch: int | None = None

    def __post_init__(self) -> None:
        if type(self.reason_code) is not ReasonCode:
            raise TypeError("an exact final-authority denial reason is required")
        if self.observed_authority_epoch is not None and (
            type(self.observed_authority_epoch) is not int
            or self.observed_authority_epoch < 1
        ):
            raise ValueError("observed authority epoch is invalid")
        _validate_claimed_record(self.claimed_receipt)


@dataclass(frozen=True, slots=True)
class FinalMutationResult[ResultT]:
    """Adapter result bound to the authoritative epoch read immediately before it."""

    result: ResultT
    observed_authority_epoch: int

    def __post_init__(self) -> None:
        if (
            type(self.observed_authority_epoch) is not int
            or self.observed_authority_epoch < 1
        ):
            raise ValueError("observed authority epoch is invalid")


class _LeaseKey:
    pass


_LEASE_KEY = _LeaseKey()


class _LeaseState(StrEnum):
    FRESH = "FRESH"
    ENTERED = "ENTERED"
    CLOSED = "CLOSED"


class ReceiptDispatchLease:
    """Exact one-use ownership of a definitively fresh receipt claim."""

    __slots__ = ("_binding", "_claimed_receipt", "_lock", "_state")

    def __init__(
        self,
        key: _LeaseKey,
        claimed_receipt: StoredRecord[ExecutionReceipt],
        binding: MutationBinding,
    ) -> None:
        if key is not _LEASE_KEY:
            raise TypeError("receipt dispatch leases are factory-issued")
        _validate_claimed_record(claimed_receipt)
        if type(binding) is not MutationBinding or not _receipt_matches_binding(
            claimed_receipt,
            binding,
        ):
            raise ValueError("receipt dispatch lease binding is invalid")
        self._claimed_receipt = claimed_receipt
        self._binding = binding
        self._lock = Lock()
        self._state = _LeaseState.FRESH

    def _enter(self, verified: VerifiedMutation) -> ReasonCode | None:
        with self._lock:
            if self._state is not _LeaseState.FRESH:
                return ReasonCode.RECEIPT_IN_PROGRESS
            self._state = _LeaseState.ENTERED
            if not _binding_matches_verified(self._binding, verified):
                self._state = _LeaseState.CLOSED
                return ReasonCode.IDEMPOTENCY_CONFLICT
            return None

    def _denial(
        self,
        reason_code: ReasonCode,
        observed_authority_epoch: int | None = None,
    ) -> FinalAuthorityDenial:
        return FinalAuthorityDenial(
            reason_code=reason_code,
            claimed_receipt=self._claimed_receipt,
            observed_authority_epoch=observed_authority_epoch,
        )

    def _close_with_denial(
        self,
        reason_code: ReasonCode,
        observed_authority_epoch: int | None = None,
    ) -> FinalAuthorityDenial:
        with self._lock:
            if self._state is _LeaseState.ENTERED:
                self._state = _LeaseState.CLOSED
        return self._denial(reason_code, observed_authority_epoch)

    def _authorize(
        self,
        verified: VerifiedMutation,
        target: TargetBinding,
        service_role: ServiceRole,
    ) -> MutationPermit:
        with self._lock:
            if self._state is not _LeaseState.ENTERED:
                raise RuntimeError("receipt dispatch lease is not active")
            self._state = _LeaseState.CLOSED
            return MutationPermit(
                _PERMIT_KEY,
                target=target,
                service_role=service_role,
                intent=verified.request.intent,
                receipt_id=self._claimed_receipt.value.receipt_id,
                binding=self._binding,
            )


class DefinitiveFreshClaimLeaseFactory:
    """Mint dispatch ownership only from definitive receipt-create proof."""

    @staticmethod
    def mint(created: DirectReceiptCreate) -> ReceiptDispatchLease:
        if type(created) is not DirectReceiptCreate:
            raise TypeError("a direct receipt-create proof is required")
        claimed_receipt, binding = created._take_claim()
        return ReceiptDispatchLease(
            _LEASE_KEY,
            claimed_receipt,
            binding,
        )


class _PermitKey:
    pass


_PERMIT_KEY = _PermitKey()


class MutationPermit:
    """Opaque, target-bound permission for one already-fenced mutation intent."""

    __slots__ = (
        "_available",
        "_binding",
        "_intent",
        "_lock",
        "_receipt_id",
        "_service_role",
        "_target",
    )

    def __init__(
        self,
        key: _PermitKey,
        *,
        target: TargetBinding,
        service_role: ServiceRole,
        intent: MutationIntent,
        receipt_id: str,
        binding: MutationBinding,
    ) -> None:
        if key is not _PERMIT_KEY:
            raise TypeError("mutation permits are final-gate issued")
        if (
            type(target) is not TargetBinding
            or type(service_role) is not ServiceRole
            or type(intent) is not MutationIntent
            or type(receipt_id) is not str
            or type(binding) is not MutationBinding
            or intent.target != target
        ):
            raise TypeError("mutation permit binding is invalid")
        self._target = target
        self._service_role = service_role
        self._intent = intent
        self._receipt_id = receipt_id
        self._binding = binding
        self._available = True
        self._lock = Lock()

    @property
    def intent(self) -> MutationIntent:
        """Consume and return the immutable command sealed into this permit."""

        with self._lock:
            if not self._available:
                raise RuntimeError("mutation permit is already consumed or closed")
            self._available = False
            return self._intent

    def _close(self) -> None:
        with self._lock:
            self._available = False


class FinalMutationGate[ResultT]:
    """Perform the sole final authority await and immediately dispatch its permit."""

    def __init__(
        self,
        *,
        authority_reader: FinalAuthorityReader,
        adapter: TargetBoundMutationAdapter[ResultT],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        try:
            reader_target = authority_reader.target
            adapter_target = adapter.target
            service_role = adapter.service_role
        except Exception:
            raise TypeError("final mutation dependencies must be target-bound") from None
        if (
            type(reader_target) is not TargetBinding
            or type(adapter_target) is not TargetBinding
            or reader_target != adapter_target
        ):
            raise ValueError("final mutation dependencies do not share one exact target")
        if type(service_role) is not ServiceRole or service_role not in {
            ServiceRole.EXECUTOR,
            ServiceRole.RECOVERY,
        }:
            raise ValueError("final mutation adapter must use an execution role")
        if clock is not None and not callable(clock):
            raise TypeError("final mutation clock must be callable")
        self._authority_reader = authority_reader
        self._adapter = adapter
        self._target = reader_target
        self._service_role = service_role
        self._clock = clock or _now_utc_second

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def execute(
        self,
        lease: ReceiptDispatchLease,
        verified: VerifiedMutation,
    ) -> FinalMutationResult[ResultT] | FinalAuthorityDenial:
        """Consume one lease, recheck authority, and dispatch without another await."""

        if type(lease) is not ReceiptDispatchLease or type(verified) is not VerifiedMutation:
            raise TypeError("exact final mutation inputs are required")
        entry_denial = lease._enter(verified)
        if entry_denial is not None:
            return lease._denial(entry_denial)
        try:
            snapshot = await self._authority_reader.read_final_authority_snapshot(
                verified.request.intent.root_id
            )
        except asyncio.CancelledError:
            lease._close_with_denial(ReasonCode.AUTHORITY_UNAVAILABLE)
            raise
        except AuthorityStoreError:
            return lease._close_with_denial(ReasonCode.AUTHORITY_UNAVAILABLE)
        except Exception:
            return lease._close_with_denial(ReasonCode.AUTHORITY_UNAVAILABLE)
        try:
            now_second = _require_utc_second(self._clock())
        except Exception:
            return lease._close_with_denial(ReasonCode.AUTHORITY_UNAVAILABLE)
        denial = _final_authority_denial(
            snapshot,
            verified=verified,
            target=self._target,
            service_role=self._service_role,
            now_second=now_second,
        )
        observed_authority_epoch = _observed_authority_epoch(
            snapshot,
            verified=verified,
            target=self._target,
        )
        if denial is not None:
            return lease._close_with_denial(denial, observed_authority_epoch)
        if observed_authority_epoch is None:
            return lease._close_with_denial(ReasonCode.AUTHORITY_UNAVAILABLE)
        permit = lease._authorize(verified, self._target, self._service_role)
        try:
            result = await self._adapter.mutate(permit)
            return FinalMutationResult(
                result=result,
                observed_authority_epoch=observed_authority_epoch,
            )
        finally:
            permit._close()


def _validate_claimed_record(claimed: object) -> None:
    if type(claimed) is not StoredRecord:
        raise TypeError("an exact stored receipt is required")
    record = claimed.value
    if type(record) is not ExecutionReceipt:
        raise TypeError("an exact claimed receipt is required")
    if (
        claimed.revision != 0
        or record.outcome is not ReceiptOutcome.CLAIMED
        or record.receipt_id
        != execution_receipt_logical_id(record.target, record.idempotency_key)
    ):
        raise ValueError("receipt is not one initial claim")


def _receipt_matches_binding(
    claimed: StoredRecord[ExecutionReceipt],
    binding: MutationBinding,
) -> bool:
    receipt = claimed.value
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


def _binding_matches_verified(
    binding: MutationBinding,
    verified: VerifiedMutation,
) -> bool:
    if (
        type(verified.request) is not TaskRequest
        or type(verified.root) is not RolloutRoot
        or type(verified.caller) is not AuthenticationContext
    ):
        return False
    intent = verified.request.intent
    return (
        binding.idempotency_key == intent.idempotency_key
        and binding.request_id == intent.request_id
        and binding.root_id == intent.root_id
        and binding.root_sha256 == intent.root_sha256
        and binding.epoch == intent.epoch
        and binding.action.value == intent.action.value
        and binding.target
        == MutationTargetKey(
            project_id=intent.target.project_id,
            region=intent.target.region,
            environment=intent.target.environment,
            service_name=intent.target.service_name,
        )
        and binding.provider_precondition == intent.provider_etag
        and binding.plan_sha256 == intent.plan_sha256
        and binding.capability_sha256 == verified.capability_sha256
        and binding.payload_sha256 == canonical_sha256(verified.request)
    )


def _final_authority_denial(
    snapshot: FinalAuthoritySnapshot | None,
    *,
    verified: VerifiedMutation,
    target: TargetBinding,
    service_role: ServiceRole,
    now_second: int,
) -> ReasonCode | None:
    if snapshot is None or type(snapshot) is not FinalAuthoritySnapshot:
        return ReasonCode.AUTHORITY_UNAVAILABLE
    if any(
        type(record) is not StoredRecord
        for record in (snapshot.root, snapshot.service_claim, snapshot.authority)
    ):
        return ReasonCode.AUTHORITY_UNAVAILABLE
    root = snapshot.root.value
    claim = snapshot.service_claim.value
    authority = snapshot.authority.value
    if (
        type(root) is not RolloutRoot
        or type(claim) is not ServiceClaimRecord
        or type(authority) is not EpochAuthorityRecord
    ):
        return ReasonCode.AUTHORITY_UNAVAILABLE
    intent = verified.request.intent
    if type(verified.earliest_lineage_issued_at) is not int:
        return ReasonCode.AUTHORITY_UNAVAILABLE
    observed_authority_epoch = _coherent_authority_epoch(
        snapshot,
        verified=verified,
        target=target,
    )
    if observed_authority_epoch is None:
        return ReasonCode.AUTHORITY_UNAVAILABLE
    if observed_authority_epoch != intent.epoch:
        return ReasonCode.EPOCH_MISMATCH
    if (
        snapshot.service_claim.revision % 3 != 0
        or claim.status is not ServiceClaimStatus.ACTIVE
        or verified.earliest_lineage_issued_at
        < _parse_utc_second(authority.changed_at)
    ):
        return ReasonCode.AUTHORITY_UNAVAILABLE
    claims = verified.request.capability.claims
    if now_second < _parse_utc_second(claims.not_before) or now_second < _parse_utc_second(
        verified.request.scheduled_at
    ):
        return ReasonCode.CAPABILITY_NOT_YET_VALID
    if now_second >= _parse_utc_second(claims.expires_at) or now_second >= _parse_utc_second(
        verified.request.expires_at
    ):
        return ReasonCode.CAPABILITY_EXPIRED
    if not _role_admits(service_role, intent.action):
        return ReasonCode.CLAIM_BINDING_MISMATCH
    return None


def _observed_authority_epoch(
    snapshot: FinalAuthoritySnapshot | None,
    *,
    verified: VerifiedMutation,
    target: TargetBinding,
) -> int | None:
    return _coherent_authority_epoch(snapshot, verified=verified, target=target)


def _coherent_authority_epoch(
    snapshot: FinalAuthoritySnapshot | None,
    *,
    verified: VerifiedMutation,
    target: TargetBinding,
) -> int | None:
    if snapshot is None or type(snapshot) is not FinalAuthoritySnapshot:
        return None
    if any(
        type(record) is not StoredRecord
        for record in (snapshot.root, snapshot.service_claim, snapshot.authority)
    ):
        return None
    root = snapshot.root.value
    claim = snapshot.service_claim.value
    authority_record = snapshot.authority
    authority = authority_record.value
    if (
        type(root) is not RolloutRoot
        or type(claim) is not ServiceClaimRecord
        or type(authority) is not EpochAuthorityRecord
    ):
        return None
    intent = verified.request.intent
    try:
        stable_target_configuration_sha256 = (
            rollout_root_target_configuration_sha256(
                root,
                stable_percent=100,
                candidate_percent=0,
            )
        )
        candidate_target_configuration_sha256 = (
            rollout_root_target_configuration_sha256(
                root,
                stable_percent=0,
                candidate_percent=100,
            )
        )
    except (TypeError, ValueError):
        return None
    claim_lifecycle_matches = (
        claim.status is ServiceClaimStatus.ACTIVE
        and snapshot.service_claim.revision % 3 == 0
    ) or (
        claim.status is ServiceClaimStatus.RELEASING
        and snapshot.service_claim.revision % 3 == 1
    ) or (
        claim.status is ServiceClaimStatus.RELEASED
        and snapshot.service_claim.revision % 3 == 2
    )
    claim_fence_matches = claim.status is ServiceClaimStatus.ACTIVE or (
        authority.revision >= 1
        and authority.cause is EpochChangeCause.OPERATOR_REVOCATION
        and claim.release_fence_epoch == authority.current_epoch
        and claim.release_fence_authority_revision == authority.revision
        and claim.release_fenced_by == authority.changed_by
        and claim.release_fence_request_id == authority.request_id
        and claim.release_fence_evidence_id == authority.evidence_id
        and claim.release_fenced_at == authority.changed_at
    )
    if (
        snapshot.root.revision != 0
        or root != verified.root
        or root.target != target
        or intent.target != target
        or root.root_id != intent.root_id
        or canonical_sha256(root) != intent.root_sha256
        or claim.target != target
        or claim.root_id != intent.root_id
        or claim.root_sha256 != intent.root_sha256
        or not service_claim_matches_root(
            claim,
            root,
            stable_target_configuration_sha256=(
                stable_target_configuration_sha256
            ),
            candidate_target_configuration_sha256=(
                candidate_target_configuration_sha256
            ),
        )
        or not claim_lifecycle_matches
        or not claim_fence_matches
        or authority.target != target
        or authority.root_id != intent.root_id
        or authority.root_sha256 != intent.root_sha256
        or type(authority.current_epoch) is not int
        or authority.current_epoch < 1
        or authority_record.revision != authority.revision
        or authority.current_epoch != authority.revision + 1
    ):
        return None
    return authority.current_epoch


def _role_admits(service_role: ServiceRole, action: CapabilityAction) -> bool:
    if service_role is ServiceRole.RECOVERY:
        return action is CapabilityAction.RECOVER_STABLE
    return service_role is ServiceRole.EXECUTOR and action in {
        CapabilityAction.APPLY_CANARY,
        CapabilityAction.PROMOTE_CANDIDATE,
    }


def _parse_utc_second(value: str) -> int:
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def _require_utc_second(value: datetime) -> int:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond
    ):
        raise ValueError("final mutation clock is invalid")
    return int(value.timestamp())


def _now_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "DefinitiveFreshClaimLeaseFactory",
    "FinalAuthorityDenial",
    "FinalAuthorityReader",
    "FinalMutationGate",
    "FinalMutationResult",
    "MutationPermit",
    "ReceiptDispatchLease",
    "TargetBoundMutationAdapter",
]
