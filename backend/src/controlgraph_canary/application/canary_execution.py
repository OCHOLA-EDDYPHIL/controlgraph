"""Authenticated orchestration for one immutable-root-derived 90/10 canary."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Protocol, cast, runtime_checkable

from controlgraph_canary.application.capability_issuance import (
    AuthenticatedIssuancePrincipal,
    CapabilityIssuanceRequest,
    CapabilityIssuer,
    PromotionCapabilityIssuanceRequestV2,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.application.tasks import TaskDispatcher
from controlgraph_canary.contracts.canary_execution import (
    APPLY_CANARY_INVOCATION_V1,
    CANARY_DISPATCH_RESULT_V1,
    CAPABILITY_ISSUANCE_COMMAND_V1,
    ApplyCanaryCommandV1,
    ApplyCanaryInvocationV1,
    CanaryDispatchResultV1,
    CapabilityIssuanceCommandV1,
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
    PromotionCapabilityIssuanceCommandV2,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryCapabilityIssuanceCommandV2,
    RecoveryCapabilityIssuanceResultV2,
)


class CanaryExecutionErrorCode(StrEnum):
    """Stable failures that contain no credential, capability, or provider payload."""

    CONFIGURATION_INVALID = "CANARY_CONFIGURATION_INVALID"
    CALLER_DENIED = "CANARY_CALLER_DENIED"
    OPERATOR_DENIED = "CANARY_OPERATOR_DENIED"
    COMMAND_DENIED = "CANARY_COMMAND_DENIED"
    ISSUANCE_DENIED = "CANARY_ISSUANCE_DENIED"
    TRANSPORT_UNAVAILABLE = "CANARY_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "CANARY_RESPONSE_INVALID"
    DISPATCH_UNAVAILABLE = "CANARY_DISPATCH_UNAVAILABLE"
    IDENTITY_CONFLICT = "CANARY_IDENTITY_CONFLICT"
    TRUSTED_STATE_INVALID = "CANARY_TRUSTED_STATE_INVALID"
    OUTCOME_UNKNOWN = "CANARY_OUTCOME_UNKNOWN"


class CanaryExecutionError(RuntimeError):
    """One sanitized canary orchestration failure."""

    def __init__(self, code: CanaryExecutionErrorCode) -> None:
        if type(code) is not CanaryExecutionErrorCode:
            raise TypeError("an exact canary execution error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class ApplyCanaryCapabilityClient(Protocol):
    """Issue only the root-derived capability needed by an apply-canary task."""

    async def issue(self, command: ApplyCanaryCommandV1) -> SignedCapability: ...


@runtime_checkable
class ApplyCanaryCoordinator(Protocol):
    """Dispatch one authenticated apply-canary command."""

    async def dispatch(
        self,
        command: ApplyCanaryCommandV1,
    ) -> CanaryDispatchResultV1: ...


@runtime_checkable
class CapabilityTimelineRecorder(Protocol):
    """Record an issuer-authenticated capability without claiming signature verification."""

    @property
    def target(self) -> TargetBinding: ...

    async def record_signed_capability(
        self,
        signed: SignedCapability,
        *,
        signature_verified: bool,
    ) -> None: ...


class CapabilityIssuanceService:
    """Authenticate the coordinator and invoke the root-derived capability issuer."""

    def __init__(
        self,
        *,
        issuer: CapabilityIssuer,
        authentication_policy: RouteAuthenticationPolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(issuer) is not CapabilityIssuer
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.ISSUER
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or (clock is not None and not callable(clock))
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._issuer = issuer
        self._authentication_policy = authentication_policy
        self._clock = clock or _now_utc_second

    async def issue(
        self,
        command: CapabilityIssuanceCommandV1
        | PromotionCapabilityIssuanceCommandV2
        | RecoveryCapabilityIssuanceCommandV2,
        caller: AuthenticationContext,
    ) -> SignedCapability | RecoveryCapabilityIssuanceResultV2:
        """Return one signed envelope only to the configured coordinator."""

        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.COORDINATOR,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CALLER_DENIED)
        if type(command) not in {
            CapabilityIssuanceCommandV1,
            PromotionCapabilityIssuanceCommandV2,
            RecoveryCapabilityIssuanceCommandV2,
        }:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        try:
            principal = AuthenticatedIssuancePrincipal(identity=caller.email)
            now = _require_utc_second(self._clock())
            if type(command) is CapabilityIssuanceCommandV1:
                issued = await self._issuer.issue(
                    CapabilityIssuanceRequest(
                        root_id=command.root_id,
                        expected_root_sha256=command.expected_root_sha256,
                        expected_epoch=command.expected_epoch,
                        request_id=command.request_id,
                        idempotency_key=command.idempotency_key,
                    ),
                    principal=principal,
                    now=now,
                )
            elif type(command) is PromotionCapabilityIssuanceCommandV2:
                issued = await self._issuer.issue_promotion(
                    PromotionCapabilityIssuanceRequestV2(
                        root_id=command.root_id,
                        expected_root_sha256=command.expected_root_sha256,
                        expected_epoch=command.expected_epoch,
                        request_id=command.request_id,
                        idempotency_key=command.idempotency_key,
                        scheduled_at=command.scheduled_at,
                        verified_apply_receipt=command.verified_apply_receipt,
                        authorization=command.authorization,
                    ),
                    principal=principal,
                    now=now,
                )
            elif type(command) is RecoveryCapabilityIssuanceCommandV2:
                recovery_result = await self._issuer.issue_recovery(
                    command,
                    principal=principal,
                    now=now,
                )
                claims = recovery_result.capability.claims
                if (
                    recovery_result.issuance_command != command
                    or claims.root_id != command.root_id
                    or claims.root_sha256 != command.expected_root_sha256
                    or claims.epoch != command.expected_epoch
                    or claims.request_id != command.request_id
                    or claims.idempotency_key != command.idempotency_key
                    or claims.action is not CapabilityAction.RECOVER_STABLE
                    or claims.subject != command.authorization.recovery_identity
                    or claims.audience != command.authorization.recovery_audience
                    or claims.concurrency != command.authorization.concurrency
                    or claims.stable_percent != 100
                    or claims.candidate_percent != 0
                    or claims.parent_capability_sha256 is not None
                    or claims.not_before != command.scheduled_at
                ):
                    raise CanaryExecutionError(
                        CanaryExecutionErrorCode.ISSUANCE_DENIED
                    )
                return recovery_result
            else:
                raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.ISSUANCE_DENIED) from None
        claims = issued.claims
        expected_action = (
            CapabilityAction.APPLY_CANARY
            if type(command) is CapabilityIssuanceCommandV1
            else CapabilityAction.PROMOTE_CANDIDATE
        )
        expected_traffic = (
            (90, 10) if expected_action is CapabilityAction.APPLY_CANARY else (0, 100)
        )
        if (
            claims.root_id != command.root_id
            or claims.root_sha256 != command.expected_root_sha256
            or claims.epoch != command.expected_epoch
            or claims.request_id != command.request_id
            or claims.idempotency_key != command.idempotency_key
            or claims.action is not expected_action
            or claims.concurrency is not None
            or claims.stable_percent != expected_traffic[0]
            or claims.candidate_percent != expected_traffic[1]
            or (
                type(command) is PromotionCapabilityIssuanceCommandV2
                and (
                    claims.parent_capability_sha256 is not None
                    or claims.not_before != command.scheduled_at
                )
            )
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.ISSUANCE_DENIED)
        return issued


class CoordinatorCapabilityClient:
    """Request one capability from the fixed issuer route without retries."""

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

    async def issue(self, command: ApplyCanaryCommandV1) -> SignedCapability:
        if type(command) is not ApplyCanaryCommandV1:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        issuance = CapabilityIssuanceCommandV1(
            schema_version=CAPABILITY_ISSUANCE_COMMAND_V1,
            root_id=command.root_id,
            expected_root_sha256=command.expected_root_sha256,
            expected_epoch=command.expected_epoch,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
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
        claims = capability.claims
        if (
            claims.target.project_id != self._route.project_id
            or claims.root_id != command.root_id
            or claims.root_sha256 != command.expected_root_sha256
            or claims.epoch != command.expected_epoch
            or claims.request_id != command.request_id
            or claims.idempotency_key != command.idempotency_key
            or claims.action is not CapabilityAction.APPLY_CANARY
            or claims.concurrency is not None
            or claims.stable_percent != 90
            or claims.candidate_percent != 10
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.RESPONSE_INVALID)
        return capability


class CanaryRolloutCoordinator:
    """Issue, derive, address, and enqueue one exact apply-canary task."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        capability_client: ApplyCanaryCapabilityClient,
        task_dispatcher: TaskDispatcher,
        clock: Callable[[], datetime] | None = None,
        timeline_recorder: CapabilityTimelineRecorder | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or target.region != "us-central1"
            or target.environment != "nonprod"
            or target.service_name != "controlgraph-reference-target"
            or "reconcile" in target.project_id.lower()
            or not isinstance(capability_client, ApplyCanaryCapabilityClient)
            or type(task_dispatcher) is not TaskDispatcher
            or (clock is not None and not callable(clock))
            or (
                timeline_recorder is not None
                and (
                    not isinstance(timeline_recorder, CapabilityTimelineRecorder)
                    or timeline_recorder.target != target
                )
            )
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._capability_client = capability_client
        self._task_dispatcher = task_dispatcher
        self._clock = clock or _now_utc_second
        self._timeline_recorder = timeline_recorder

    async def dispatch(
        self,
        command: ApplyCanaryCommandV1,
    ) -> CanaryDispatchResultV1:
        if type(command) is not ApplyCanaryCommandV1:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        capability = await self._capability_client.issue(command)
        claims = capability.claims
        if (
            claims.target != self._target
            or claims.root_id != command.root_id
            or claims.root_sha256 != command.expected_root_sha256
            or claims.epoch != command.expected_epoch
            or claims.request_id != command.request_id
            or claims.idempotency_key != command.idempotency_key
            or claims.action is not CapabilityAction.APPLY_CANARY
            or claims.concurrency is not None
            or claims.stable_percent != 90
            or claims.candidate_percent != 10
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.ISSUANCE_DENIED)
        try:
            if self._timeline_recorder is not None:
                await self._timeline_recorder.record_signed_capability(
                    capability,
                    signature_verified=False,
                )
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
            dispatch_time = _require_utc_second(self._clock())
            dispatched = await self._task_dispatcher.dispatch(
                request,
                now=dispatch_time,
            )
            capability_sha256 = canonical_sha256(capability)
            return CanaryDispatchResultV1(
                schema_version=CANARY_DISPATCH_RESULT_V1,
                request_id=claims.request_id,
                idempotency_key=claims.idempotency_key,
                target=claims.target,
                root_id=claims.root_id,
                root_sha256=claims.root_sha256,
                epoch=claims.epoch,
                stable_revision=claims.stable_revision,
                candidate_revision=claims.candidate_revision,
                stable_percent=90,
                candidate_percent=10,
                capability_id=claims.capability_id,
                capability_sha256=capability_sha256,
                task_id=request.task_id,
                task_name=dispatched.task_name,
                enqueue_disposition=dispatched.disposition.value,
                scheduled_at=request.scheduled_at,
                expires_at=request.expires_at,
            )
        except asyncio.CancelledError:
            raise
        except CanaryExecutionError:
            raise
        except Exception:
            raise CanaryExecutionError(CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None


class ApiCanaryClient:
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
        command: ApplyCanaryCommandV1,
        principal: AuthenticationContext,
    ) -> CanaryDispatchResultV1:
        if type(command) is not ApplyCanaryCommandV1:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        if not _context_matches_policy(
            principal,
            self._authentication_policy,
            role=CallerRole.OPERATOR,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.OPERATOR_DENIED)
        invocation = ApplyCanaryInvocationV1(
            schema_version=APPLY_CANARY_INVOCATION_V1,
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
            result = decode_contract(body, CanaryDispatchResultV1)
        except (ContractError, TypeError, ValueError):
            raise CanaryExecutionError(CanaryExecutionErrorCode.RESPONSE_INVALID) from None
        if not _result_matches_command(
            result,
            command,
            project_id=self._route.project_id,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.RESPONSE_INVALID)
        return result


class CoordinatorCanaryRelay:
    """Authenticate API and propagated operator identity before task dispatch."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        coordinator: ApplyCanaryCoordinator,
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
            or not isinstance(coordinator, ApplyCanaryCoordinator)
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._coordinator = coordinator

    async def dispatch(
        self,
        invocation: ApplyCanaryInvocationV1,
        caller: AuthenticationContext,
    ) -> CanaryDispatchResultV1:
        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CALLER_DENIED)
        if type(invocation) is not ApplyCanaryInvocationV1:
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


def _result_matches_command(
    result: object,
    command: ApplyCanaryCommandV1,
    *,
    project_id: str,
) -> bool:
    return (
        type(result) is CanaryDispatchResultV1
        and result.request_id == command.request_id
        and result.idempotency_key == command.idempotency_key
        and result.root_id == command.root_id
        and result.root_sha256 == command.expected_root_sha256
        and result.epoch == command.expected_epoch
        and result.target.project_id == project_id
        and result.stable_percent == 90
        and result.candidate_percent == 10
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
        raise ValueError("canary execution clock is invalid")
    return value


def _now_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "ApiCanaryClient",
    "ApplyCanaryCapabilityClient",
    "ApplyCanaryCoordinator",
    "CanaryExecutionError",
    "CanaryExecutionErrorCode",
    "CanaryRolloutCoordinator",
    "CapabilityIssuanceService",
    "CapabilityTimelineRecorder",
    "CoordinatorCanaryRelay",
    "CoordinatorCapabilityClient",
]
