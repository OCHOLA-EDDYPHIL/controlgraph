"""Authenticated orchestration for one verified-canary candidate promotion."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal, Protocol, cast, runtime_checkable

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreError,
    AuthorityStoreOutcomeUnknown,
    StoredRecord,
)
from controlgraph_canary.application.canary_execution import (
    CanaryExecutionError,
    CanaryExecutionErrorCode,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.promotion_store import PromotionDispatchStore
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.application.tasks import (
    TaskDispatcher,
    TaskEnqueueDisposition,
    TaskEnqueueResult,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    MutationIntent,
    SignedCapability,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.promotion_execution import (
    PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V1,
    PROMOTION_DISPATCH_RECORD_V1,
    PROMOTION_DISPATCH_RESULT_V1,
    PROMOTION_INVOCATION_V1,
    PromotionCapabilityIssuanceCommandV1,
    PromotionCommandV1,
    PromotionDispatchRecordV1,
    PromotionDispatchResultV1,
    PromotionDispatchState,
    PromotionInvocationV1,
    promotion_command_sha256,
    promotion_dispatch_id,
)


@runtime_checkable
class PromotionCapabilityClient(Protocol):
    """Issue only a receipt-derived root capability for candidate promotion."""

    async def issue(self, command: PromotionCommandV1) -> SignedCapability: ...


@runtime_checkable
class PromotionCoordinator(Protocol):
    """Dispatch one authenticated candidate-promotion command."""

    async def dispatch(
        self,
        command: PromotionCommandV1,
    ) -> PromotionDispatchResultV1: ...


class CoordinatorPromotionCapabilityClient:
    """Request one promotion capability from the fixed issuer without retries."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.ISSUER
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._transport = transport

    async def issue(self, command: PromotionCommandV1) -> SignedCapability:
        if type(command) is not PromotionCommandV1:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        issuance = PromotionCapabilityIssuanceCommandV1(
            schema_version=PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V1,
            root_id=command.root_id,
            expected_root_sha256=command.expected_root_sha256,
            expected_epoch=command.expected_epoch,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            verified_apply_receipt=command.verified_apply_receipt,
        )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(issuance),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRANSPORT_UNAVAILABLE) from None
        try:
            capability = decode_contract(body, SignedCapability)
        except (ContractError, TypeError, ValueError):
            raise CanaryExecutionError(CanaryExecutionErrorCode.RESPONSE_INVALID) from None
        if not _capability_matches_command(
            capability,
            command,
            project_id=self._route.project_id,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.RESPONSE_INVALID)
        return capability


class PromotionRolloutCoordinator:
    """Issue, address, and enqueue one exact candidate-promotion task."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        capability_client: PromotionCapabilityClient,
        dispatch_store: PromotionDispatchStore,
        task_dispatcher: TaskDispatcher,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or target.region != "us-central1"
            or target.environment != "nonprod"
            or target.service_name != "controlgraph-reference-target"
            or "reconcile" in target.project_id.lower()
            or not isinstance(capability_client, PromotionCapabilityClient)
            or not isinstance(dispatch_store, PromotionDispatchStore)
            or type(dispatch_store.target) is not TargetBinding
            or dispatch_store.target != target
            or type(task_dispatcher) is not TaskDispatcher
            or (clock is not None and not callable(clock))
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._capability_client = capability_client
        self._dispatch_store = dispatch_store
        self._task_dispatcher = task_dispatcher
        self._clock = clock or _now_utc_second

    async def dispatch(
        self,
        command: PromotionCommandV1,
    ) -> PromotionDispatchResultV1:
        if type(command) is not PromotionCommandV1:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        existing = await self._read_dispatch(command)
        if existing is not None:
            result = self._adopt_existing(existing, command)
            if result is not None:
                return result
            prepared = existing
        else:
            prepared = await self._prepare(command)
            result = self._adopt_existing(prepared, command)
            if result is not None:
                return result

        dispatch_time = _require_utc_second(self._clock())
        try:
            addressed = self._task_dispatcher.prepare(
                prepared.value.task,
                now=dispatch_time,
            )
            if addressed.name != prepared.value.task_name:
                raise ValueError("prepared promotion task address changed")
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID) from None

        try:
            started_value = PromotionDispatchRecordV1.model_validate(
                {
                    **prepared.value.model_dump(mode="python"),
                    "state": PromotionDispatchState.ENQUEUE_STARTED,
                    "enqueue_started_at": _utc_second(dispatch_time),
                }
            )
        except Exception:
            raise CanaryExecutionError(
                CanaryExecutionErrorCode.TRUSTED_STATE_INVALID
            ) from None
        try:
            direct_start = await self._dispatch_store.begin_promotion_enqueue(
                prepared,
                started_value,
            )
            started = direct_start.dispatch
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raced = await self._read_after_transition(command)
            result = self._adopt_existing(raced, command)
            if result is not None:
                return result
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreCorruptRecord:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreOutcomeUnknown:
            raced = await self._read_after_transition(command)
            result = self._adopt_existing(raced, command)
            if result is not None:
                return result
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreError:
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None

        try:
            dispatched = self._task_dispatcher.dispatch_prepared(
                addressed,
                permit=direct_start.permit,
                now=dispatch_time,
            )
        except Exception:
            dispatched = TaskEnqueueResult(
                task_name=started.value.task_name,
                disposition=TaskEnqueueDisposition.AMBIGUOUS,
            )
        if (
            type(dispatched) is not TaskEnqueueResult
            or type(dispatched.disposition) is not TaskEnqueueDisposition
            or dispatched.task_name != started.value.task_name
        ):
            dispatched = TaskEnqueueResult(
                task_name=started.value.task_name,
                disposition=TaskEnqueueDisposition.AMBIGUOUS,
            )
        try:
            result = _dispatch_result(started.value, dispatched)
            terminal_value = PromotionDispatchRecordV1.model_validate(
                {
                    **started.value.model_dump(mode="python"),
                    "state": PromotionDispatchState(dispatched.disposition.value),
                    "terminal_at": started.value.enqueue_started_at,
                    "result": result,
                }
            )
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        try:
            terminal = await self._dispatch_store.compare_and_set_promotion_dispatch(
                started,
                terminal_value,
            )
        except asyncio.CancelledError:
            raise
        except (AuthorityStoreConflict, AuthorityStoreOutcomeUnknown):
            raced = await self._read_after_transition(command)
            replay = self._adopt_existing(raced, command)
            if replay is not None:
                return replay
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreCorruptRecord:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreError:
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        replay = self._adopt_existing(terminal, command)
        if replay is None:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID)
        return replay

    async def _prepare(
        self,
        command: PromotionCommandV1,
    ) -> StoredRecord[PromotionDispatchRecordV1]:
        capability = await self._capability_client.issue(command)
        if (
            not _capability_matches_command(
                capability,
                command,
                project_id=self._target.project_id,
            )
            or capability.claims.target != self._target
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.ISSUANCE_DENIED)
        claims = capability.claims
        try:
            intent = MutationIntent(
                schema_version="controlgraph.mutation-intent/v1",
                request_id=claims.request_id,
                idempotency_key=claims.idempotency_key,
                target=claims.target,
                root_id=claims.root_id,
                root_sha256=claims.root_sha256,
                epoch=claims.epoch,
                action=claims.action,
                stable_revision=claims.stable_revision,
                candidate_revision=claims.candidate_revision,
                stable_percent=claims.stable_percent,
                candidate_percent=claims.candidate_percent,
                concurrency=claims.concurrency,
                plan_sha256=claims.plan_sha256,
                provider_etag=claims.provider_etag,
            )
            request = TaskRequest(
                schema_version="controlgraph.task-request/v1",
                task_id=f"task-{capability.claims_sha256}",
                queue_region="us-central1",
                handler_audience=claims.audience,
                scheduled_at=claims.not_before,
                expires_at=claims.expires_at,
                capability=capability,
                intent=intent,
            )
            prepared_time = _require_utc_second(self._clock())
            addressed = self._task_dispatcher.prepare(request, now=prepared_time)
            command_sha256 = promotion_command_sha256(command)
            prepared_value = PromotionDispatchRecordV1(
                schema_version=PROMOTION_DISPATCH_RECORD_V1,
                dispatch_id=promotion_dispatch_id(command_sha256),
                command_sha256=command_sha256,
                request_id=command.request_id,
                idempotency_key=command.idempotency_key,
                target=self._target,
                root_id=command.root_id,
                root_sha256=command.expected_root_sha256,
                epoch=command.expected_epoch,
                verified_apply_receipt=command.verified_apply_receipt,
                source_receipt_sha256=(command.verified_apply_receipt.receipt_sha256),
                task_sha256=canonical_sha256(request),
                task_name=addressed.name,
                task=request,
                state=PromotionDispatchState.PREPARED,
                prepared_at=_utc_second(prepared_time),
                enqueue_started_at=None,
                terminal_at=None,
                result=None,
            )
        except asyncio.CancelledError:
            raise
        except CanaryExecutionError:
            raise
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.ISSUANCE_DENIED) from None
        try:
            return await self._dispatch_store.prepare_or_adopt_promotion_dispatch(
                command,
                prepared_value,
            )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raise CanaryExecutionError(CanaryExecutionErrorCode.IDENTITY_CONFLICT) from None
        except AuthorityStoreCorruptRecord:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreOutcomeUnknown:
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreError:
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None

    async def _read_dispatch(
        self,
        command: PromotionCommandV1,
    ) -> StoredRecord[PromotionDispatchRecordV1] | None:
        try:
            return await self._dispatch_store.read_promotion_dispatch(command)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raise CanaryExecutionError(CanaryExecutionErrorCode.IDENTITY_CONFLICT) from None
        except AuthorityStoreCorruptRecord:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreOutcomeUnknown:
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreError:
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None

    async def _require_owned_dispatch(
        self,
        command: PromotionCommandV1,
    ) -> StoredRecord[PromotionDispatchRecordV1]:
        current = await self._read_dispatch(command)
        if current is None:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID)
        return current

    async def _read_after_transition(
        self,
        command: PromotionCommandV1,
    ) -> StoredRecord[PromotionDispatchRecordV1]:
        try:
            return await self._require_owned_dispatch(command)
        except CanaryExecutionError as error:
            if error.code in {
                CanaryExecutionErrorCode.TRUSTED_STATE_INVALID,
                CanaryExecutionErrorCode.IDENTITY_CONFLICT,
            }:
                raise
            raise CanaryExecutionError(
                CanaryExecutionErrorCode.OUTCOME_UNKNOWN
            ) from None

    def _adopt_existing(
        self,
        stored: StoredRecord[PromotionDispatchRecordV1],
        command: PromotionCommandV1,
    ) -> PromotionDispatchResultV1 | None:
        expected_revisions = {
            PromotionDispatchState.PREPARED: 0,
            PromotionDispatchState.ENQUEUE_STARTED: 1,
            PromotionDispatchState.CREATED: 2,
            PromotionDispatchState.DUPLICATE: 2,
            PromotionDispatchState.AMBIGUOUS: 2,
        }
        if (
            type(stored) is not StoredRecord
            or type(stored.value) is not PromotionDispatchRecordV1
            or stored.value.target != self._target
            or stored.revision != expected_revisions.get(stored.value.state)
            or stored.value.command_sha256 != promotion_command_sha256(command)
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID)
        if stored.value.state is PromotionDispatchState.PREPARED:
            return None
        if stored.value.state is PromotionDispatchState.ENQUEUE_STARTED:
            raise CanaryExecutionError(CanaryExecutionErrorCode.OUTCOME_UNKNOWN)
        result = stored.value.result
        if not _result_matches_command(
            result,
            command,
            project_id=self._target.project_id,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID)
        return cast(PromotionDispatchResultV1, result)


class ApiPromotionClient:
    """Forward an authenticated operator command only to the fixed coordinator."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        authentication_policy: RouteAuthenticationPolicy,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.API
            or route.service_role is not ServiceRole.COORDINATOR
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.API
            or authentication_policy.caller.role is not CallerRole.OPERATOR
            or authentication_policy.project_id != route.project_id
            or authentication_policy.project_number != route.project_number
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._authentication_policy = authentication_policy
        self._transport = transport

    async def dispatch(
        self,
        command: PromotionCommandV1,
        principal: AuthenticationContext,
    ) -> PromotionDispatchResultV1:
        if type(command) is not PromotionCommandV1:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        if not _context_matches_policy(
            principal,
            self._authentication_policy,
            role=CallerRole.OPERATOR,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.OPERATOR_DENIED)
        invocation = PromotionInvocationV1(
            schema_version=PROMOTION_INVOCATION_V1,
            command=command,
            operator_identity=principal.email,
            operator_subject=principal.subject,
            operator_issuer=cast(
                Literal["accounts.google.com", "https://accounts.google.com"],
                principal.issuer,
            ),
            operator_audience=principal.audience,
            operator_issued_at=principal.issued_at,
            operator_expires_at=principal.expires_at,
        )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRANSPORT_UNAVAILABLE) from None
        try:
            result = decode_contract(body, PromotionDispatchResultV1)
        except (ContractError, TypeError, ValueError):
            raise CanaryExecutionError(CanaryExecutionErrorCode.RESPONSE_INVALID) from None
        if not _result_matches_command(
            result,
            command,
            project_id=self._route.project_id,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.RESPONSE_INVALID)
        return result


class CoordinatorPromotionRelay:
    """Authenticate API and propagated operator identity before promotion dispatch."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        coordinator: PromotionCoordinator,
    ) -> None:
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.COORDINATOR
            or authentication_policy.caller.role is not CallerRole.API
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.project_id != authentication_policy.project_id
            or operator_policy.project_number != authentication_policy.project_number
            or not isinstance(coordinator, PromotionCoordinator)
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._coordinator = coordinator

    async def dispatch(
        self,
        invocation: PromotionInvocationV1,
        caller: AuthenticationContext,
    ) -> PromotionDispatchResultV1:
        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CALLER_DENIED)
        if type(invocation) is not PromotionInvocationV1:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        expected_operator = self._operator_policy.caller
        if (
            invocation.operator_identity != expected_operator.email
            or invocation.operator_subject != expected_operator.subject
            or invocation.operator_audience != self._operator_policy.audience
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.OPERATOR_DENIED)
        try:
            result = await self._coordinator.dispatch(invocation.command)
        except asyncio.CancelledError:
            raise
        except CanaryExecutionError:
            raise
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        if not _result_matches_command(
            result,
            invocation.command,
            project_id=self._authentication_policy.project_id,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE)
        return result


def _dispatch_result(
    record: PromotionDispatchRecordV1,
    dispatched: TaskEnqueueResult,
) -> PromotionDispatchResultV1:
    task = record.task
    claims = task.capability.claims
    return PromotionDispatchResultV1(
        schema_version=PROMOTION_DISPATCH_RESULT_V1,
        request_id=claims.request_id,
        idempotency_key=claims.idempotency_key,
        target=claims.target,
        root_id=claims.root_id,
        root_sha256=claims.root_sha256,
        epoch=claims.epoch,
        stable_revision=claims.stable_revision,
        candidate_revision=claims.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        provider_etag=claims.provider_etag,
        verified_apply_receipt=record.verified_apply_receipt,
        capability_id=claims.capability_id,
        capability_sha256=canonical_sha256(task.capability),
        task_id=task.task_id,
        task_name=dispatched.task_name,
        enqueue_disposition=dispatched.disposition.value,
        scheduled_at=task.scheduled_at,
        expires_at=task.expires_at,
    )


def _capability_matches_command(
    capability: object,
    command: PromotionCommandV1,
    *,
    project_id: str,
) -> bool:
    if type(capability) is not SignedCapability:
        return False
    claims = capability.claims
    return (
        claims.target.project_id == project_id
        and claims.root_id == command.root_id
        and claims.root_sha256 == command.expected_root_sha256
        and claims.epoch == command.expected_epoch
        and claims.request_id == command.request_id
        and claims.idempotency_key == command.idempotency_key
        and claims.action is CapabilityAction.PROMOTE_CANDIDATE
        and claims.concurrency is None
        and claims.stable_percent == 0
        and claims.candidate_percent == 100
        and claims.parent_capability_sha256 is None
    )


def _result_matches_command(
    result: object,
    command: PromotionCommandV1,
    *,
    project_id: str,
) -> bool:
    return (
        type(result) is PromotionDispatchResultV1
        and result.request_id == command.request_id
        and result.idempotency_key == command.idempotency_key
        and result.root_id == command.root_id
        and result.root_sha256 == command.expected_root_sha256
        and result.epoch == command.expected_epoch
        and result.target.project_id == project_id
        and result.stable_percent == 0
        and result.candidate_percent == 100
        and result.verified_apply_receipt == command.verified_apply_receipt
    )


def _context_matches_policy(
    context: object,
    policy: RouteAuthenticationPolicy,
    *,
    role: CallerRole,
) -> bool:
    return (
        type(context) is AuthenticationContext
        and context.role is role
        and context.role is policy.caller.role
        and context.email == policy.caller.email
        and context.subject == policy.caller.subject
        and context.issuer in {"accounts.google.com", "https://accounts.google.com"}
        and context.audience == policy.audience
        and type(context.issued_at) is int
        and type(context.expires_at) is int
        and context.issued_at < context.expires_at
        and context.expires_at - context.issued_at <= 3_660
    )


def _require_utc_second(value: datetime) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond
    ):
        raise ValueError("promotion execution clock is invalid")
    return value


def _now_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _utc_second(value: datetime) -> str:
    return _require_utc_second(value).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "ApiPromotionClient",
    "CoordinatorPromotionCapabilityClient",
    "CoordinatorPromotionRelay",
    "PromotionCapabilityClient",
    "PromotionCoordinator",
    "PromotionRolloutCoordinator",
]
