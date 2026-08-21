"""Receipt-backed at-most-once execution for already verified mutations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import (
    AuthorityStoreError,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    ReceiptClaimResult,
    StoredRecord,
)
from controlgraph_canary.application.capability_verification import (
    CapabilityVerificationError,
    CapabilityVerifier,
    VerifiedMutation,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunMutationOutcome,
    CloudRunMutationPurpose,
    CloudRunMutationReason,
    CloudRunMutationResult,
    TargetConfigurationProjection,
    rollout_root_v3_target_configuration_sha256,
    target_configuration_projection,
    target_configuration_sha256,
)
from controlgraph_canary.application.execution import (
    DefinitiveFreshClaimLeaseFactory,
    FinalAuthorityDenial,
    FinalMutationGate,
    FinalMutationResult,
    MutationPermit,
    PreparedTargetMutation,
    TargetBoundMutationAdapter,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.promotion_execution import (
    PromotionMutationIntentV2,
    PromotionTaskRequestV2,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryMutationIntentV2,
    RecoveryTaskRequestV2,
    recovery_target_configuration_sha256,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV2, RolloutRootV3
from controlgraph_canary.contracts.storage import execution_receipt_logical_id

RECEIPT_ORPHAN_GRACE_SECONDS: Final = 60
# A new claim needs the orphan grace plus the queue's 30-second maximum
# backoff so a later delivery can reach readback before task expiry.
RECEIPT_NEW_CLAIM_RECOVERY_WINDOW_SECONDS: Final = 90


class ReceiptMutationStatus(StrEnum):
    """Closed result classes from the sole admitted mutation adapter call."""

    APPLIED = "APPLIED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class ReceiptMutationResult:
    """Sanitized provider result ready for durable receipt classification."""

    status: ReceiptMutationStatus
    provider_operation: str | None
    reason_code: ReasonCode | None

    def __post_init__(self) -> None:
        if type(self.status) is not ReceiptMutationStatus:
            raise TypeError("an exact mutation result status is required")
        if self.provider_operation is not None and (
            type(self.provider_operation) is not str
            or not self.provider_operation
            or self.provider_operation != self.provider_operation.strip()
            or len(self.provider_operation) > 512
        ):
            raise ValueError("provider operation is invalid")
        if self.status is ReceiptMutationStatus.APPLIED:
            if self.reason_code is not None or self.provider_operation is None:
                raise ValueError("applied mutation result shape is invalid")
        elif self.status is ReceiptMutationStatus.FAILED_SAFE:
            if self.provider_operation is not None or self.reason_code not in {
                ReasonCode.PROVIDER_PRECONDITION_FAILED,
                ReasonCode.TARGET_BINDING_MISMATCH,
                ReasonCode.PROVIDER_REQUEST_REJECTED,
            }:
                raise ValueError("failed-safe mutation result shape is invalid")
        elif self.reason_code is not ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS:
            raise ValueError("ambiguous mutation result shape is invalid")


def map_cloud_run_mutation_result(
    result: CloudRunMutationResult,
) -> ReceiptMutationResult:
    """Map one sanitized Cloud Run outcome without losing its stable classification."""

    if type(result) is not CloudRunMutationResult:
        raise TypeError("an exact Cloud Run mutation result is required")
    if result.outcome is CloudRunMutationOutcome.APPLIED:
        return ReceiptMutationResult(
            status=ReceiptMutationStatus.APPLIED,
            provider_operation=result.operation_name,
            reason_code=None,
        )
    if result.outcome is CloudRunMutationOutcome.AMBIGUOUS:
        return ReceiptMutationResult(
            status=ReceiptMutationStatus.AMBIGUOUS,
            provider_operation=result.operation_name,
            reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
        )
    reason_codes = {
        CloudRunMutationReason.PRECONDITION_FAILED: (
            ReasonCode.PROVIDER_PRECONDITION_FAILED
        ),
        CloudRunMutationReason.DECLARATION_MISMATCH: ReasonCode.TARGET_BINDING_MISMATCH,
        CloudRunMutationReason.PROVIDER_REJECTED: ReasonCode.PROVIDER_REQUEST_REJECTED,
    }
    if result.reason is None:
        raise ValueError("failed-safe Cloud Run mutation reason is invalid")
    reason_code = reason_codes.get(result.reason)
    if reason_code is None:
        raise ValueError("failed-safe Cloud Run mutation reason is invalid")
    return ReceiptMutationResult(
        status=ReceiptMutationStatus.FAILED_SAFE,
        provider_operation=None,
        reason_code=reason_code,
    )


class _ReceiptClassifyingPreparedMutation:
    """Map one already-prepared Cloud Run call without adding a pre-call await."""

    def __init__(
        self,
        delegate: PreparedTargetMutation[CloudRunMutationResult],
    ) -> None:
        self._delegate = delegate
        self._target = delegate.target
        self._service_role = delegate.service_role
        self._intent = delegate.intent

    @property
    def target(self) -> TargetBinding:
        return self._target

    @property
    def service_role(self) -> ServiceRole:
        return self._service_role

    @property
    def intent(
        self,
    ) -> MutationIntent | PromotionMutationIntentV2 | RecoveryMutationIntentV2:
        return self._intent

    async def mutate(self, permit: MutationPermit) -> ReceiptMutationResult:
        result = await self._delegate.mutate(permit)
        return map_cloud_run_mutation_result(result)


class ReceiptClassifyingMutationAdapter:
    """Prepare a Cloud Run call and preserve its target, role, and classification."""

    def __init__(
        self,
        delegate: TargetBoundMutationAdapter[CloudRunMutationResult],
    ) -> None:
        try:
            target = delegate.target
            service_role = delegate.service_role
        except Exception:
            raise TypeError("receipt mutation delegate must be target-bound") from None
        if type(target) is not TargetBinding or type(service_role) is not ServiceRole:
            raise TypeError("receipt mutation delegate binding is invalid")
        self._delegate = delegate
        self._target = target
        self._service_role = service_role
        purpose = getattr(
            delegate,
            "mutation_purpose",
            CloudRunMutationPurpose.STANDARD_EXECUTION,
        )
        if type(purpose) is not CloudRunMutationPurpose:
            raise TypeError("receipt mutation delegate purpose is invalid")
        self._mutation_purpose = purpose

    @property
    def target(self) -> TargetBinding:
        return self._target

    @property
    def service_role(self) -> ServiceRole:
        return self._service_role

    @property
    def mutation_purpose(self) -> CloudRunMutationPurpose:
        return self._mutation_purpose

    async def prepare(
        self,
        intent: MutationIntent | PromotionMutationIntentV2 | RecoveryMutationIntentV2,
    ) -> PreparedTargetMutation[ReceiptMutationResult]:
        prepared = await self._delegate.prepare(intent)
        return _ReceiptClassifyingPreparedMutation(prepared)


@dataclass(frozen=True, slots=True)
class ReceiptReadbackResult:
    """One independent observation of the target-bound provider state."""

    state: TargetConfigurationProjection | None
    observed_etag: str | None

    def __post_init__(self) -> None:
        if self.state is not None and type(self.state) is not TargetConfigurationProjection:
            raise TypeError("readback state must be exact")
        if self.observed_etag is not None and (
            type(self.observed_etag) is not str
            or not self.observed_etag
            or self.observed_etag != self.observed_etag.strip()
            or len(self.observed_etag) > 512
        ):
            raise ValueError("readback etag is invalid")


@runtime_checkable
class TargetBoundReceiptReadback(Protocol):
    """Read one fixed target without carrying mutation authority."""

    @property
    def target(self) -> TargetBinding: ...

    async def readback(
        self,
        expected: TargetConfigurationProjection,
    ) -> ReceiptReadbackResult: ...


@runtime_checkable
class ReceiptStore(Protocol):
    """Narrow durable operations required by receipt execution."""

    @property
    def target(self) -> TargetBinding: ...

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]: ...


@dataclass(frozen=True, slots=True)
class ReceiptExecutionStored:
    """A durable exact receipt returned to the protected handler."""

    receipt: StoredRecord[ExecutionReceipt]
    reason_code: ReasonCode | None = None

    def __post_init__(self) -> None:
        if (
            type(self.receipt) is not StoredRecord
            or type(self.receipt.value) is not ExecutionReceipt
        ):
            raise TypeError("an exact stored execution receipt is required")
        if self.reason_code is not None and type(self.reason_code) is not ReasonCode:
            raise TypeError("an exact receipt response reason is required")
        if self.receipt.value.outcome is ReceiptOutcome.CLAIMED:
            if self.reason_code is not ReasonCode.RECEIPT_IN_PROGRESS:
                raise ValueError("claimed receipt response must be in progress")
        elif self.reason_code is not self.receipt.value.reason_code:
            raise ValueError("receipt response reason does not match durable state")


@dataclass(frozen=True, slots=True)
class ReceiptExecutionDenied:
    """A stable denial that does not expose or overwrite another receipt."""

    reason_code: ReasonCode

    def __post_init__(self) -> None:
        if self.reason_code not in {
            ReasonCode.IDEMPOTENCY_CONFLICT,
            ReasonCode.AUTHORITY_UNAVAILABLE,
            ReasonCode.CAPABILITY_EXPIRED,
            ReasonCode.TARGET_BINDING_MISMATCH,
        }:
            raise ValueError("receipt execution denial reason is invalid")


type ReceiptExecutionResponse = ReceiptExecutionStored | ReceiptExecutionDenied


@runtime_checkable
class OneShotRecoveryExecutorClient(Protocol):
    """Forward one canonical recovery task to the executor-hosted facade."""

    @property
    def target(self) -> TargetBinding: ...

    async def execute(self, payload: bytes) -> ReceiptExecutionResponse: ...


class RecoveryTaskForwarder:
    """Forward only a task already verified at the recovery worker boundary."""

    def __init__(
        self,
        *,
        client: OneShotRecoveryExecutorClient,
        route_policy: RouteAuthenticationPolicy,
    ) -> None:
        if not isinstance(client, OneShotRecoveryExecutorClient):
            raise TypeError("an exact recovery executor client is required")
        if (
            type(route_policy) is not RouteAuthenticationPolicy
            or route_policy.service_role is not ServiceRole.RECOVERY
            or route_policy.caller.role is not CallerRole.RECOVERY_TASK_CALLER
            or client.target.project_id != route_policy.project_id
        ):
            raise ValueError("recovery forwarding route is invalid")
        self._client = client
        self._route_policy = route_policy
        self._target = client.target

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def forward(self, verified: VerifiedMutation) -> ReceiptExecutionResponse:
        if type(verified) is not VerifiedMutation:
            raise TypeError("recovery forwarding requires an exact verified mutation")
        request = verified.request
        caller = verified.caller
        policy = self._route_policy
        if (
            type(request) is not RecoveryTaskRequestV2
            or request.intent.target != self._target
            or request.handler_audience != policy.audience
            or type(caller) is not AuthenticationContext
            or caller.role is not policy.caller.role
            or caller.email != policy.caller.email
            or caller.subject != policy.caller.subject
            or caller.audience != policy.audience
        ):
            raise CapabilityVerificationError(ReasonCode.CLAIM_BINDING_MISMATCH)
        result = await self._client.execute(canonical_json_bytes(request))
        if type(result) not in (ReceiptExecutionStored, ReceiptExecutionDenied):
            raise RuntimeError("recovery executor returned an invalid response")
        return result


class RecoveryExecutorFacade:
    """Independently reverify and execute recovery inside the executor service."""

    def __init__(
        self,
        *,
        verifier: CapabilityVerifier,
        coordinator: ReceiptExecutionCoordinator,
    ) -> None:
        if type(verifier) is not CapabilityVerifier:
            raise TypeError("an exact recovery facade verifier is required")
        if type(coordinator) is not ReceiptExecutionCoordinator:
            raise TypeError("an exact recovery receipt coordinator is required")
        if (
            not verifier.recovery_executor_facade
            or verifier.target != coordinator.target
        ):
            raise ValueError("recovery executor facade dependencies are invalid")
        self._verifier = verifier
        self._coordinator = coordinator
        self._target = verifier.target

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def execute(
        self,
        payload: bytes,
        caller: AuthenticationContext,
    ) -> ReceiptExecutionResponse:
        verified = await self._verifier.verify(payload, caller)
        if type(verified.request) is not RecoveryTaskRequestV2:
            raise CapabilityVerificationError(ReasonCode.CLAIM_BINDING_MISMATCH)
        return await self._coordinator.execute(verified)


class ReceiptExecutionCoordinator:
    """Claim once, run the final gate once, and recover only through readback."""

    def __init__(
        self,
        *,
        store: ReceiptStore,
        final_gate: FinalMutationGate[ReceiptMutationResult],
        readback: TargetBoundReceiptReadback,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        try:
            store_target = store.target
            gate_target = final_gate.target
            readback_target = readback.target
        except Exception:
            raise TypeError("receipt execution dependencies must be target-bound") from None
        if (
            type(store_target) is not TargetBinding
            or type(gate_target) is not TargetBinding
            or type(readback_target) is not TargetBinding
            or store_target != gate_target
            or store_target != readback_target
        ):
            raise ValueError("receipt execution dependencies do not share one exact target")
        if clock is not None and not callable(clock):
            raise TypeError("receipt execution clock must be callable")
        self._store = store
        self._final_gate = final_gate
        self._readback = readback
        self._target = store_target
        self._clock = clock or _now_utc_second

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def execute(self, verified: VerifiedMutation) -> ReceiptExecutionResponse:
        """Execute one already verified mutation without granting replay dispatch."""

        if type(verified) is not VerifiedMutation:
            raise TypeError("receipt execution requires one verified mutation")
        try:
            expected_state = _expected_target_state(verified)
            binding = _mutation_binding(verified, expected_state)
        except (TypeError, ValueError):
            return ReceiptExecutionDenied(ReasonCode.TARGET_BINDING_MISMATCH)
        now = _require_utc_second(self._clock())
        expires_at = _utc_second_datetime(verified.request.expires_at)
        if now + timedelta(
            seconds=RECEIPT_NEW_CLAIM_RECOVERY_WINDOW_SECONDS
        ) >= expires_at:
            return await self._adopt_without_new_claim(
                verified,
                expected_state,
                binding,
            )
        claimed = _claimed_receipt(verified, binding, now)
        try:
            claim = await self._store.claim_or_adopt_receipt(claimed, binding)
        except AuthorityStoreError:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        except Exception:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)

        if type(claim) is ReceiptClaimConflict:
            return ReceiptExecutionDenied(ReasonCode.IDEMPOTENCY_CONFLICT)
        if type(claim) is ReceiptClaimAdopted:
            if not _valid_adopted_receipt(claim.receipt, binding, verified):
                return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
            return await self._handle_existing(
                claim.receipt,
                expected_state,
                binding,
                verified,
            )
        if type(claim) is not ReceiptClaimCreated:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        if not _valid_adopted_receipt(claim.receipt, binding, verified):
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)

        lease = DefinitiveFreshClaimLeaseFactory.mint(claim.direct_create)
        try:
            gated = await self._final_gate.execute(lease, verified)
        except Exception:
            ambiguous = _provider_result_receipt(
                claim.receipt.value,
                ReceiptMutationResult(
                    status=ReceiptMutationStatus.AMBIGUOUS,
                    provider_operation=None,
                    reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
                ),
                observed_authority_epoch=None,
                updated_at=_utc_second_text(_require_utc_second(self._clock())),
            )
            persisted = await self._persist_or_read(
                claim.receipt,
                ambiguous,
                binding,
                verified,
            )
            if persisted is None:
                return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
            return await self._handle_after_provider(
                persisted,
                expected_state,
                binding,
                verified,
            )

        if type(gated) is FinalAuthorityDenial:
            denied = _denied_receipt(
                gated,
                updated_at=_utc_second_text(_require_utc_second(self._clock())),
            )
            persisted = await self._persist_or_read(
                claim.receipt,
                denied,
                binding,
                verified,
            )
            provider_attempted = False
        elif type(gated) is FinalMutationResult and type(gated.result) is ReceiptMutationResult:
            result = _provider_result_receipt(
                claim.receipt.value,
                gated.result,
                observed_authority_epoch=gated.observed_authority_epoch,
                updated_at=_utc_second_text(_require_utc_second(self._clock())),
            )
            persisted = await self._persist_or_read(
                claim.receipt,
                result,
                binding,
                verified,
            )
            provider_attempted = True
        else:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        if persisted is None:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        if provider_attempted:
            return await self._handle_after_provider(
                persisted,
                expected_state,
                binding,
                verified,
            )
        return await self._handle_existing(
            persisted,
            expected_state,
            binding,
            verified,
        )

    async def recover_orphaned(
        self,
        verified: VerifiedMutation,
    ) -> ReceiptExecutionResponse:
        """Classify previously claimed exact work through readback, never dispatch."""

        if type(verified) is not VerifiedMutation:
            raise TypeError("orphan recovery requires one previously verified mutation")
        try:
            expected_state = _expected_target_state(verified)
            binding = _mutation_binding(verified, expected_state)
        except (TypeError, ValueError):
            return ReceiptExecutionDenied(ReasonCode.TARGET_BINDING_MISMATCH)
        try:
            stored = await self._store.read_receipt(
                verified.request.intent.idempotency_key
            )
        except Exception:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        if stored is None:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        if not _valid_adopted_receipt(stored, binding, verified):
            return ReceiptExecutionDenied(ReasonCode.IDEMPOTENCY_CONFLICT)
        return await self._handle_existing(
            stored,
            expected_state,
            binding,
            verified,
        )

    async def _adopt_without_new_claim(
        self,
        verified: VerifiedMutation,
        expected_state: TargetConfigurationProjection,
        binding: MutationBinding,
    ) -> ReceiptExecutionResponse:
        try:
            stored = await self._store.read_receipt(
                verified.request.intent.idempotency_key
            )
        except Exception:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        if stored is None:
            return ReceiptExecutionDenied(ReasonCode.CAPABILITY_EXPIRED)
        if not _valid_adopted_receipt(stored, binding, verified):
            return ReceiptExecutionDenied(ReasonCode.IDEMPOTENCY_CONFLICT)
        return await self._handle_existing(
            stored,
            expected_state,
            binding,
            verified,
        )

    async def _handle_existing(
        self,
        stored: StoredRecord[ExecutionReceipt],
        expected_state: TargetConfigurationProjection,
        binding: MutationBinding,
        verified: VerifiedMutation,
    ) -> ReceiptExecutionResponse:
        receipt = stored.value
        if receipt.outcome in {
            ReceiptOutcome.DENIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.VERIFIED,
        }:
            return ReceiptExecutionStored(stored, receipt.reason_code)
        if receipt.outcome is ReceiptOutcome.CLAIMED:
            now = _require_utc_second(self._clock())
            if now < _orphan_recovery_at(receipt):
                return ReceiptExecutionStored(stored, ReasonCode.RECEIPT_IN_PROGRESS)
        return await self._readback_only(
            stored,
            expected_state,
            binding,
            verified,
        )

    async def _handle_after_provider(
        self,
        stored: StoredRecord[ExecutionReceipt],
        expected_state: TargetConfigurationProjection,
        binding: MutationBinding,
        verified: VerifiedMutation,
    ) -> ReceiptExecutionResponse:
        if stored.value.outcome is ReceiptOutcome.CLAIMED:
            return await self._readback_only(
                stored,
                expected_state,
                binding,
                verified,
            )
        return await self._handle_existing(
            stored,
            expected_state,
            binding,
            verified,
        )

    async def _readback_only(
        self,
        stored: StoredRecord[ExecutionReceipt],
        expected_state: TargetConfigurationProjection,
        binding: MutationBinding,
        verified: VerifiedMutation,
    ) -> ReceiptExecutionResponse:
        try:
            observation = await self._readback.readback(expected_state)
        except Exception:
            observation = ReceiptReadbackResult(state=None, observed_etag=None)
        if type(observation) is not ReceiptReadbackResult:
            observation = ReceiptReadbackResult(state=None, observed_etag=None)

        current = stored
        if current.value.outcome is ReceiptOutcome.CLAIMED:
            ambiguous = _ambiguous_readback_receipt(
                current.value,
                observation,
                updated_at=_utc_second_text(_require_utc_second(self._clock())),
            )
            persisted = await self._persist_or_read(
                current,
                ambiguous,
                binding,
                verified,
            )
            if persisted is None:
                return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
            current = persisted

        if current.value.outcome in {
            ReceiptOutcome.DENIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.VERIFIED,
        }:
            return ReceiptExecutionStored(current, current.value.reason_code)
        if current.value.outcome not in {
            ReceiptOutcome.APPLIED,
            ReceiptOutcome.AMBIGUOUS,
        }:
            return ReceiptExecutionStored(current, ReasonCode.RECEIPT_IN_PROGRESS)

        exact = (
            observation.state == expected_state
            and observation.observed_etag is not None
            and target_configuration_sha256(
                verified.request.intent,
                expected_concurrency=expected_state.concurrency,
            )
            == current.value.expected_poststate_sha256
        )
        if exact:
            observed_etag = observation.observed_etag
            if observed_etag is None:
                return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
            replacement = _verified_readback_receipt(
                current.value,
                observed_etag,
                updated_at=_utc_second_text(_require_utc_second(self._clock())),
            )
        else:
            replacement = _ambiguous_readback_receipt(
                current.value,
                observation,
                updated_at=_utc_second_text(_require_utc_second(self._clock())),
            )
            if (
                current.value.outcome is ReceiptOutcome.AMBIGUOUS
                and observation.observed_etag == current.value.observed_etag
            ):
                return ReceiptExecutionStored(current, current.value.reason_code)
        persisted = await self._persist_or_read(
            current,
            replacement,
            binding,
            verified,
        )
        if persisted is None:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        return ReceiptExecutionStored(persisted, persisted.value.reason_code)

    async def _persist_or_read(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
        binding: MutationBinding,
        verified: VerifiedMutation,
    ) -> StoredRecord[ExecutionReceipt] | None:
        replacement_record = StoredRecord(replacement, expected.revision + 1)
        if (
            not _valid_adopted_receipt(expected, binding, verified)
            or not _valid_adopted_receipt(replacement_record, binding, verified)
            or not _valid_monotonic_resolution(expected, replacement_record)
        ):
            return None
        for attempt in range(2):
            try:
                committed = await self._store.compare_and_set_receipt(
                    expected,
                    replacement,
                )
                if committed != replacement_record:
                    return None
                return committed
            except AuthorityStoreError:
                pass
            except Exception:
                pass
            try:
                current = await self._store.read_receipt(
                    expected.value.idempotency_key
                )
            except Exception:
                return None
            if type(current) is not StoredRecord or type(current.value) is not ExecutionReceipt:
                return None
            if (
                not _valid_adopted_receipt(current, binding, verified)
                or not _valid_monotonic_resolution(expected, current)
            ):
                return None
            if current != expected:
                return current
            if attempt == 1:
                return None
        return None


def _expected_target_state(verified: VerifiedMutation) -> TargetConfigurationProjection:
    intent = verified.request.intent
    root = verified.root
    if type(verified.request) is PromotionTaskRequestV2:
        if type(intent) is not PromotionMutationIntentV2 or type(root) is not RolloutRootV3:
            raise TypeError("V2 promotion receipt execution requires an exact V3 root")
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
        if (
            intent.expected_prestate_sha256 != expected_prestate_sha256
            or intent.desired_poststate_sha256 != desired_poststate_sha256
        ):
            raise ValueError("V2 promotion receipt state is outside the V3 root")
    elif type(verified.request) is RecoveryTaskRequestV2:
        if type(intent) is not RecoveryMutationIntentV2 or type(root) not in (
            RolloutRootV3,
            RolloutRootV2,
        ):
            raise TypeError("V2 recovery receipt execution requires an exact root")
        expected_prestate_sha256 = recovery_target_configuration_sha256(
            root,
            stable_percent=90,
            candidate_percent=10,
        )
        desired_poststate_sha256 = recovery_target_configuration_sha256(
            root,
            stable_percent=100,
            candidate_percent=0,
        )
        if (
            intent.expected_prestate_sha256 != expected_prestate_sha256
            or intent.desired_poststate_sha256 != desired_poststate_sha256
        ):
            raise ValueError("V2 recovery receipt state is outside its root")
    elif type(intent) is PromotionMutationIntentV2:
        raise TypeError("V2 promotion intent requires the exact V2 task request")
    elif (
        type(intent) is RecoveryMutationIntentV2
        or intent.action is CapabilityAction.RECOVER_STABLE
    ):
        raise TypeError("recovery requires the exact V2 recovery task request")
    projected = target_configuration_projection(
        intent,
        expected_concurrency=root.content.authority_bounds.concurrency,
    )
    if (
        type(intent) is PromotionMutationIntentV2
        and target_configuration_sha256(
            intent,
            expected_concurrency=projected.concurrency,
        )
        != intent.desired_poststate_sha256
    ):
        raise ValueError("V2 promotion receipt poststate is not authorized")
    if (
        type(intent) is RecoveryMutationIntentV2
        and target_configuration_sha256(
            intent,
            expected_concurrency=projected.concurrency,
        )
        != intent.desired_poststate_sha256
    ):
        raise ValueError("V2 recovery receipt poststate is not authorized")
    return projected


def _mutation_binding(
    verified: VerifiedMutation,
    expected_state: TargetConfigurationProjection,
) -> MutationBinding:
    intent = verified.request.intent
    return MutationBinding(
        idempotency_key=intent.idempotency_key,
        request_id=intent.request_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=MutationAction(intent.action.value),
        target=MutationTargetKey(
            project_id=intent.target.project_id,
            region=intent.target.region,
            environment=intent.target.environment,
            service_name=intent.target.service_name,
        ),
        provider_precondition=intent.provider_etag,
        plan_sha256=intent.plan_sha256,
        capability_sha256=verified.capability_sha256,
        payload_sha256=canonical_sha256(verified.request),
        expected_poststate_sha256=target_configuration_sha256(
            intent,
            expected_concurrency=expected_state.concurrency,
        ),
    )


def _claimed_receipt(
    verified: VerifiedMutation,
    binding: MutationBinding,
    created_at: datetime,
) -> ExecutionReceipt:
    intent = verified.request.intent
    timestamp = _utc_second_text(created_at)
    return ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(intent.target, intent.idempotency_key),
        request_id=intent.request_id,
        idempotency_key=intent.idempotency_key,
        capability_sha256=verified.capability_sha256,
        mutation_sha256=mutation_identity(binding),
        plan_sha256=intent.plan_sha256,
        expected_poststate_sha256=binding.expected_poststate_sha256,
        target=intent.target,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=intent.action,
        provider_etag=intent.provider_etag,
        dispatch_not_after=verified.request.expires_at,
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=None,
        created_at=timestamp,
        updated_at=timestamp,
        evidence_ids=(),
    )


def _receipt_matches_binding(
    receipt: ExecutionReceipt,
    binding: MutationBinding,
) -> bool:
    target = binding.target
    return (
        receipt.idempotency_key == binding.idempotency_key
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


def _valid_adopted_receipt(
    stored: StoredRecord[ExecutionReceipt],
    binding: MutationBinding,
    verified: VerifiedMutation,
) -> bool:
    if type(stored) is not StoredRecord or type(stored.value) is not ExecutionReceipt:
        return False
    receipt = stored.value
    expected_receipt_id = execution_receipt_logical_id(
        verified.request.intent.target,
        verified.request.intent.idempotency_key,
    )
    if (
        receipt.receipt_id != expected_receipt_id
        or receipt.dispatch_not_after != verified.request.expires_at
        or not _receipt_matches_binding(receipt, binding)
    ):
        return False
    if receipt.outcome is ReceiptOutcome.CLAIMED:
        return stored.revision == 0
    return stored.revision >= 1


def _receipt_cas_identity(receipt: ExecutionReceipt) -> tuple[object, ...]:
    return (
        receipt.receipt_id,
        receipt.request_id,
        receipt.idempotency_key,
        receipt.capability_sha256,
        receipt.mutation_sha256,
        receipt.plan_sha256,
        receipt.expected_poststate_sha256,
        receipt.target,
        receipt.root_id,
        receipt.root_sha256,
        receipt.epoch,
        receipt.action,
        receipt.provider_etag,
        receipt.dispatch_not_after,
        receipt.created_at,
    )


def _valid_monotonic_resolution(
    expected: StoredRecord[ExecutionReceipt],
    current: StoredRecord[ExecutionReceipt],
) -> bool:
    if current.revision < expected.revision:
        return False
    if current.revision == expected.revision:
        return current == expected
    before = expected.value
    after = current.value
    if (
        _receipt_cas_identity(before) != _receipt_cas_identity(after)
        or after.updated_at < before.updated_at
        or after.evidence_ids[: len(before.evidence_ids)] != before.evidence_ids
    ):
        return False
    if before.observed_authority_epoch is not None:
        if after.observed_authority_epoch != before.observed_authority_epoch:
            return False
    elif (
        before.outcome is not ReceiptOutcome.CLAIMED
        and after.observed_authority_epoch is not None
    ):
        return False
    if before.provider_operation is not None:
        if after.provider_operation != before.provider_operation:
            return False
    elif (
        before.outcome is not ReceiptOutcome.CLAIMED
        and after.provider_operation is not None
    ):
        return False
    reachable = {
        ReceiptOutcome.CLAIMED: {
            ReceiptOutcome.DENIED,
            ReceiptOutcome.APPLIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.AMBIGUOUS,
            ReceiptOutcome.VERIFIED,
        },
        ReceiptOutcome.APPLIED: {
            ReceiptOutcome.AMBIGUOUS,
            ReceiptOutcome.VERIFIED,
        },
        ReceiptOutcome.AMBIGUOUS: {
            ReceiptOutcome.AMBIGUOUS,
            ReceiptOutcome.VERIFIED,
        },
    }
    if after.outcome not in reachable.get(before.outcome, set()):
        return False
    return not (
        before.outcome is ReceiptOutcome.CLAIMED
        and after.outcome is ReceiptOutcome.VERIFIED
        and current.revision < expected.revision + 2
    )


def _denied_receipt(
    denial: FinalAuthorityDenial,
    *,
    updated_at: str,
) -> ExecutionReceipt:
    claimed = denial.claimed_receipt.value
    return _replace_receipt(
        claimed,
        outcome=ReceiptOutcome.DENIED,
        reason_code=denial.reason_code,
        observed_authority_epoch=denial.observed_authority_epoch,
        updated_at=updated_at,
    )


def _provider_result_receipt(
    claimed: ExecutionReceipt,
    result: ReceiptMutationResult,
    *,
    observed_authority_epoch: int | None,
    updated_at: str,
) -> ExecutionReceipt:
    outcome = ReceiptOutcome(result.status.value)
    return _replace_receipt(
        claimed,
        outcome=outcome,
        reason_code=result.reason_code,
        provider_operation=result.provider_operation,
        observed_authority_epoch=observed_authority_epoch,
        updated_at=updated_at,
    )


def _verified_readback_receipt(
    current: ExecutionReceipt,
    observed_etag: str,
    *,
    updated_at: str,
) -> ExecutionReceipt:
    return _replace_receipt(
        current,
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        observed_etag=observed_etag,
        updated_at=updated_at,
    )


def _ambiguous_readback_receipt(
    current: ExecutionReceipt,
    observation: ReceiptReadbackResult,
    *,
    updated_at: str,
) -> ExecutionReceipt:
    return _replace_receipt(
        current,
        outcome=ReceiptOutcome.AMBIGUOUS,
        reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
        observed_etag=observation.observed_etag,
        updated_at=updated_at,
    )


def _replace_receipt(
    current: ExecutionReceipt,
    **changes: object,
) -> ExecutionReceipt:
    return ExecutionReceipt(
        **{
            **current.model_dump(mode="python"),
            **changes,
        }
    )


def _require_utc_second(value: datetime) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond
    ):
        raise ValueError("receipt execution clock is invalid")
    return value


def _utc_second_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _orphan_recovery_at(receipt: ExecutionReceipt) -> datetime:
    created = _utc_second_datetime(receipt.created_at)
    deadline = _utc_second_datetime(receipt.dispatch_not_after)
    latest_reachable = max(created, deadline - timedelta(seconds=1))
    return min(
        created + timedelta(seconds=RECEIPT_ORPHAN_GRACE_SECONDS),
        latest_reachable,
    )


def _utc_second_datetime(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _now_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "RECEIPT_NEW_CLAIM_RECOVERY_WINDOW_SECONDS",
    "RECEIPT_ORPHAN_GRACE_SECONDS",
    "OneShotRecoveryExecutorClient",
    "ReceiptClassifyingMutationAdapter",
    "ReceiptExecutionCoordinator",
    "ReceiptExecutionDenied",
    "ReceiptExecutionResponse",
    "ReceiptExecutionStored",
    "ReceiptMutationResult",
    "ReceiptMutationStatus",
    "ReceiptReadbackResult",
    "ReceiptStore",
    "RecoveryExecutorFacade",
    "RecoveryTaskForwarder",
    "TargetBoundReceiptReadback",
    "map_cloud_run_mutation_result",
]
