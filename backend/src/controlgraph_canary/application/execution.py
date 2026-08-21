"""Final epoch fencing and capability-sealed mutation dispatch."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from threading import Lock
from typing import Protocol, cast, runtime_checkable

from controlgraph_canary.application.authority_store import (
    AuthorityStoreError,
    DirectReceiptCreate,
    StoredRecord,
)
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.cloud_run import (
    rollout_root_v3_target_configuration_sha256,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.root_authority import (
    RootAuthorityBundle,
    inspect_root_authority_bundle,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochChangeCause,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.promotion_execution import (
    PromotionAuthorizationV1,
    PromotionMutationIntentV2,
    PromotionTaskRequestV2,
    create_verified_apply_receipt_locator,
    promotion_capability_id,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV2, RolloutRootV3
from controlgraph_canary.contracts.storage import (
    ServiceClaimStatus,
    execution_receipt_logical_id,
)


@runtime_checkable
class FinalAuthorityReader(Protocol):
    """Narrow reader required by the final mutation fence."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootAuthorityBundle | None: ...


@runtime_checkable
class PreparedTargetMutation[ResultT](Protocol):
    """One fully prepared provider call awaiting only a final-gate permit."""

    @property
    def target(self) -> TargetBinding: ...

    @property
    def service_role(self) -> ServiceRole: ...

    @property
    def intent(self) -> MutationIntent | PromotionMutationIntentV2: ...

    async def mutate(self, permit: MutationPermit) -> ResultT: ...


@runtime_checkable
class TargetBoundMutationAdapter[ResultT](Protocol):
    """Prepare one target-bound provider call before the final authority read."""

    @property
    def target(self) -> TargetBinding: ...

    @property
    def service_role(self) -> ServiceRole: ...

    async def prepare(
        self,
        intent: MutationIntent | PromotionMutationIntentV2,
    ) -> PreparedTargetMutation[ResultT]: ...


@runtime_checkable
class PromotionSourceReceiptReader(Protocol):
    """Strongly read the durable APPLY_CANARY receipt named by a promotion."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...


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
        intent: MutationIntent | PromotionMutationIntentV2,
        receipt_id: str,
        binding: MutationBinding,
    ) -> None:
        if key is not _PERMIT_KEY:
            raise TypeError("mutation permits are final-gate issued")
        if (
            type(target) is not TargetBinding
            or type(service_role) is not ServiceRole
            or type(intent) not in (MutationIntent, PromotionMutationIntentV2)
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
    def intent(self) -> MutationIntent | PromotionMutationIntentV2:
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
        route_policy: RouteAuthenticationPolicy,
        source_receipt_reader: PromotionSourceReceiptReader | None = None,
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
        if type(route_policy) is not RouteAuthenticationPolicy:
            raise TypeError("final mutation gate requires an exact route policy")
        if (
            route_policy.service_role is not service_role
            or route_policy.project_id != reader_target.project_id
        ):
            raise ValueError("final mutation route policy does not match the adapter")
        if source_receipt_reader is not None:
            try:
                receipt_target = source_receipt_reader.target
            except Exception:
                raise TypeError(
                    "promotion source receipt reader must be target-bound"
                ) from None
            if type(receipt_target) is not TargetBinding or receipt_target != reader_target:
                raise ValueError(
                    "promotion source receipt reader does not share the exact target"
                )
        if clock is not None and not callable(clock):
            raise TypeError("final mutation clock must be callable")
        self._authority_reader = authority_reader
        self._adapter = adapter
        self._route_policy = route_policy
        self._source_receipt_reader = source_receipt_reader
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
            prepared = await self._adapter.prepare(verified.request.intent)
        except asyncio.CancelledError:
            lease._close_with_denial(ReasonCode.AUTHORITY_UNAVAILABLE)
            raise
        except Exception:
            return lease._close_with_denial(ReasonCode.AUTHORITY_UNAVAILABLE)
        if not _prepared_mutation_matches(
            prepared,
            verified=verified,
            target=self._target,
            service_role=self._service_role,
        ):
            return lease._close_with_denial(ReasonCode.CLAIM_BINDING_MISMATCH)
        if type(verified.request) is PromotionTaskRequestV2:
            try:
                receipt_denial = await self._revalidate_promotion_source_receipt(verified)
            except asyncio.CancelledError:
                lease._close_with_denial(ReasonCode.AUTHORITY_UNAVAILABLE)
                raise
            if receipt_denial is not None:
                return lease._close_with_denial(receipt_denial)
        try:
            snapshot = await self._authority_reader.read_root_creation_bundle(
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
            route_policy=self._route_policy,
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
            result = await prepared.mutate(permit)
            return FinalMutationResult(
                result=result,
                observed_authority_epoch=observed_authority_epoch,
            )
        finally:
            permit._close()

    async def _revalidate_promotion_source_receipt(
        self,
        verified: VerifiedMutation,
    ) -> ReasonCode | None:
        request = verified.request
        if type(request) is not PromotionTaskRequestV2:
            return None
        reader = self._source_receipt_reader
        if reader is None:
            return ReasonCode.AUTHORITY_UNAVAILABLE
        locator = request.intent.authorization.verified_apply_receipt
        try:
            stored = await reader.read_receipt(locator.idempotency_key)
        except asyncio.CancelledError:
            raise
        except Exception:
            return ReasonCode.AUTHORITY_UNAVAILABLE
        if (
            type(stored) is not StoredRecord
            or type(stored.value) is not ExecutionReceipt
            or stored.revision < 2
        ):
            return ReasonCode.AUTHORITY_UNAVAILABLE
        receipt = stored.value
        try:
            observed_locator = create_verified_apply_receipt_locator(receipt)
        except (TypeError, ValueError):
            return ReasonCode.AUTHORITY_UNAVAILABLE
        intent = request.intent
        authorization = intent.authorization
        if (
            observed_locator != locator
            or canonical_sha256(receipt) != authorization.source_receipt_sha256
            or receipt.target != intent.target
            or receipt.root_id != intent.root_id
            or receipt.root_sha256 != intent.root_sha256
            or receipt.epoch != intent.epoch
            or receipt.action is not CapabilityAction.APPLY_CANARY
            or receipt.outcome is not ReceiptOutcome.VERIFIED
            or receipt.expected_poststate_sha256 != intent.expected_prestate_sha256
            or receipt.observed_etag != authorization.provider_etag
            or receipt.observed_authority_epoch != intent.epoch
        ):
            return ReasonCode.CLAIM_BINDING_MISMATCH
        return None


def _prepared_mutation_matches(
    prepared: object,
    *,
    verified: VerifiedMutation,
    target: TargetBinding,
    service_role: ServiceRole,
) -> bool:
    if not isinstance(prepared, PreparedTargetMutation):
        return False
    try:
        prepared_target = prepared.target
        prepared_role = prepared.service_role
        prepared_intent = prepared.intent
        mutate = prepared.mutate
    except Exception:
        return False
    return (
        type(prepared_target) is TargetBinding
        and prepared_target == target
        and type(prepared_role) is ServiceRole
        and prepared_role is service_role
        and type(prepared_intent) in (MutationIntent, PromotionMutationIntentV2)
        and prepared_intent == verified.request.intent
        and callable(mutate)
    )


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
    request = verified.request
    if (
        type(request) not in (TaskRequest, PromotionTaskRequestV2)
        or type(verified.root) not in (RolloutRootV2, RolloutRootV3)
        or type(verified.caller) is not AuthenticationContext
    ):
        return False
    intent = request.intent
    common_matches = (
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
        and binding.payload_sha256 == canonical_sha256(request)
        and verified.capability_sha256 == canonical_sha256(request.capability)
        and verified.claims_sha256 == request.capability.claims_sha256
    )
    if not common_matches:
        return False
    if type(request) is TaskRequest:
        return type(intent) is MutationIntent
    promotion_request = cast(PromotionTaskRequestV2, request)
    return (
        type(intent) is PromotionMutationIntentV2
        and type(verified.root) is RolloutRootV3
        and binding.expected_poststate_sha256 == intent.desired_poststate_sha256
        and _promotion_request_matches_root(promotion_request, verified.root)
    )


def _final_authority_denial(
    snapshot: RootAuthorityBundle | None,
    *,
    verified: VerifiedMutation,
    target: TargetBinding,
    service_role: ServiceRole,
    route_policy: RouteAuthenticationPolicy,
    now_second: int,
) -> ReasonCode | None:
    if snapshot is None:
        return ReasonCode.AUTHORITY_UNAVAILABLE
    state = inspect_root_authority_bundle(snapshot, target=target)
    if state is None:
        return ReasonCode.AUTHORITY_UNAVAILABLE
    claim = state.service_claim
    authority = state.authority
    intent = verified.request.intent
    if type(verified.earliest_lineage_issued_at) is not int:
        return ReasonCode.AUTHORITY_UNAVAILABLE
    caller_denial = _final_caller_denial(
        verified,
        route_policy=route_policy,
        now_second=now_second,
    )
    if caller_denial is not None:
        return caller_denial
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
        state.service_claim_revision % 3 != 0
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
    if type(verified.request) is PromotionTaskRequestV2:
        if type(verified.root) is not RolloutRootV3 or not _promotion_request_matches_root(
            verified.request,
            verified.root,
        ):
            return ReasonCode.CLAIM_BINDING_MISMATCH
        if now_second >= _parse_utc_second(verified.request.intent.proof_valid_until):
            return ReasonCode.CAPABILITY_EXPIRED
    if not _role_admits(service_role, intent.action):
        return ReasonCode.CLAIM_BINDING_MISMATCH
    return None


def _final_caller_denial(
    verified: VerifiedMutation,
    *,
    route_policy: RouteAuthenticationPolicy,
    now_second: int,
) -> ReasonCode | None:
    caller = verified.caller
    request = verified.request
    if type(caller) is not AuthenticationContext:
        return ReasonCode.CALLER_UNAUTHENTICATED
    if (
        caller.role is not route_policy.caller.role
        or caller.email != route_policy.caller.email
        or caller.subject != route_policy.caller.subject
        or caller.audience != route_policy.audience
        or request.handler_audience != route_policy.audience
        or caller.issuer not in {"accounts.google.com", "https://accounts.google.com"}
        or type(caller.issued_at) is not int
        or type(caller.expires_at) is not int
        or not caller.issued_at <= now_second < caller.expires_at
        or caller.expires_at - caller.issued_at > 3_660
    ):
        return ReasonCode.CALLER_UNAUTHORIZED
    return None


def _promotion_request_matches_root(
    request: PromotionTaskRequestV2,
    root: RolloutRootV3,
) -> bool:
    """Recheck all compact promotion authority bindings without an external read."""

    if type(request) is not PromotionTaskRequestV2 or type(root) is not RolloutRootV3:
        return False
    intent = request.intent
    authorization = intent.authorization
    claims = request.capability.claims
    content = root.content
    plan = content.rollout_plan
    bounds = content.authority_bounds
    if type(authorization) is not PromotionAuthorizationV1:
        return False
    try:
        capability_id = promotion_capability_id(authorization)
        expected_prestate_sha256 = rollout_root_v3_target_configuration_sha256(
            root,
            stable_percent=90,
            candidate_percent=10,
        )
        desired_poststate_sha256 = rollout_root_v3_target_configuration_sha256(
            root,
            stable_percent=0,
            candidate_percent=100,
        )
    except (TypeError, ValueError):
        return False
    return (
        authorization.root_schema_version == root.schema_version
        and authorization.root_id == root.root_id
        and authorization.root_sha256 == root.root_sha256
        and authorization.target == content.target
        and authorization.epoch == claims.epoch == intent.epoch
        and authorization.request_id == claims.request_id == intent.request_id
        and authorization.idempotency_key
        == claims.idempotency_key
        == intent.idempotency_key
        and authorization.scheduled_at == request.scheduled_at == claims.not_before
        and authorization.plan_sha256 == canonical_sha256(plan)
        and authorization.policy_schema_version == content.health_policy.schema_version
        and authorization.policy_sha256 == canonical_sha256(content.health_policy)
        and authorization.stable_snapshot_sha256
        == canonical_sha256(content.stable_snapshot)
        and authorization.stable_revision == plan.stable_revision
        and authorization.stable_revision_configuration_sha256
        == plan.stable_revision_configuration_sha256
        and authorization.candidate_revision == plan.candidate_revision
        and authorization.candidate_revision_configuration_sha256
        == plan.candidate_revision_configuration_sha256
        and authorization.concurrency == plan.concurrency
        and authorization.evidence_signing_key_version
        == content.evidence_signing_key_version
        and authorization.capability_signing_key_version
        == bounds.capability_signing_key_version
        and authorization.issuer_identity == bounds.issuer_identity
        and authorization.executor_identity == bounds.executor_identity
        and authorization.executor_audience == bounds.executor_audience
        and authorization.expected_prestate_sha256 == expected_prestate_sha256
        and authorization.desired_poststate_sha256 == desired_poststate_sha256
        and authorization.expected_stable_percent == 90
        and authorization.expected_candidate_percent == 10
        and authorization.stable_percent == 0
        and authorization.candidate_percent == 100
        and authorization.provider_etag == claims.provider_etag == intent.provider_etag
        and authorization.capability_id == capability_id
        and intent.capability_id == capability_id
        and claims.capability_id == capability_id
        and intent.promotion_authorization_sha256 == canonical_sha256(authorization)
        and intent.target == authorization.target
        and intent.root_id == authorization.root_id
        and intent.root_sha256 == authorization.root_sha256
        and intent.action is CapabilityAction.PROMOTE_CANDIDATE
        and intent.stable_revision == authorization.stable_revision
        and intent.candidate_revision == authorization.candidate_revision
        and intent.stable_percent == 0
        and intent.candidate_percent == 100
        and intent.concurrency is None
        and intent.plan_sha256 == authorization.plan_sha256
        and intent.expected_prestate_sha256 == authorization.expected_prestate_sha256
        and intent.terminal_health_decision_sha256
        == authorization.terminal_health_decision_sha256
        and intent.health_chain_sha256
        == authorization.health_chain_locator.health_chain_sha256
        and intent.desired_poststate_sha256 == authorization.desired_poststate_sha256
        and intent.proof_valid_until == authorization.proof_valid_until
        and claims.issuer == authorization.issuer_identity
        and claims.subject == authorization.executor_identity
        and claims.audience == authorization.executor_audience
        and claims.target == authorization.target
        and claims.root_id == authorization.root_id
        and claims.root_sha256 == authorization.root_sha256
        and claims.action is CapabilityAction.PROMOTE_CANDIDATE
        and claims.stable_revision == authorization.stable_revision
        and claims.candidate_revision == authorization.candidate_revision
        and claims.stable_percent == 0
        and claims.candidate_percent == 100
        and claims.concurrency is None
        and claims.plan_sha256 == authorization.plan_sha256
        and claims.signing_key_version
        == authorization.capability_signing_key_version
        and request.handler_audience == authorization.executor_audience
        and request.expires_at <= authorization.proof_valid_until
    )


def _observed_authority_epoch(
    snapshot: RootAuthorityBundle | None,
    *,
    verified: VerifiedMutation,
    target: TargetBinding,
) -> int | None:
    return _coherent_authority_epoch(snapshot, verified=verified, target=target)


def _coherent_authority_epoch(
    snapshot: RootAuthorityBundle | None,
    *,
    verified: VerifiedMutation,
    target: TargetBinding,
) -> int | None:
    if snapshot is None:
        return None
    state = inspect_root_authority_bundle(snapshot, target=target)
    if state is None:
        return None
    root = state.root
    anchor = state.lineage_anchor
    claim = state.service_claim
    authority = state.authority
    intent = verified.request.intent
    claim_lifecycle_matches = (
        claim.status is ServiceClaimStatus.ACTIVE
        and state.service_claim_revision % 3 == 0
    ) or (
        claim.status is ServiceClaimStatus.RELEASING
        and state.service_claim_revision % 3 == 1
    ) or (
        claim.status is ServiceClaimStatus.RELEASED
        and state.service_claim_revision % 3 == 2
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
        root != verified.root
        or anchor != verified.lineage_anchor
        or root.content.target != target
        or intent.target != target
        or root.root_id != intent.root_id
        or root.root_sha256 != intent.root_sha256
        or claim.target != target
        or claim.root_id != intent.root_id
        or claim.root_sha256 != intent.root_sha256
        or not claim_lifecycle_matches
        or not claim_fence_matches
        or authority.target != target
        or authority.root_id != intent.root_id
        or authority.root_sha256 != intent.root_sha256
        or type(authority.current_epoch) is not int
        or authority.current_epoch < 1
        or state.authority_revision != authority.revision
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
    "PreparedTargetMutation",
    "PromotionSourceReceiptReader",
    "ReceiptDispatchLease",
    "TargetBoundMutationAdapter",
]
