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
from controlgraph_canary.application.health_orchestration import (
    HealthAttestationVerifier,
    verify_healthy_promotion_chain,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.promotion_store import (
    PromotionDispatchStoreV2,
    PromotionHealthChainReader,
)
from controlgraph_canary.application.root_authority import (
    RootAuthorityBundleReader,
    inspect_root_authority_bundle,
)
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
    SignedCapability,
    TargetBinding,
)
from controlgraph_canary.contracts.promotion_execution import (
    PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V2,
    PROMOTION_DISPATCH_RECORD_V2,
    PROMOTION_DISPATCH_RESULT_V2,
    PROMOTION_INVOCATION_V2,
    PROMOTION_MUTATION_INTENT_V2,
    PROMOTION_TASK_REQUEST_V2,
    PromotionAuthorizationV1,
    PromotionCapabilityIssuanceCommandV2,
    PromotionCommandV2,
    PromotionDispatchRecordV2,
    PromotionDispatchResultV2,
    PromotionDispatchState,
    PromotionInvocationV2,
    PromotionMutationIntentV2,
    PromotionTaskRequestV2,
    create_promotion_authorization,
    create_promotion_health_chain_locator,
    promotion_capability_id,
    promotion_command_v2_sha256,
    promotion_dispatch_v2_id,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV3
from controlgraph_canary.contracts.storage import ServiceClaimStatus


@runtime_checkable
class PromotionCapabilityClient(Protocol):
    """Issue only a receipt-derived root capability for candidate promotion."""

    async def issue(
        self,
        command: PromotionCommandV2,
        authorization: PromotionAuthorizationV1,
    ) -> SignedCapability: ...


@runtime_checkable
class PromotionAuthorizationResolver(Protocol):
    """Resolve verifier-owned health and root state into one compact authorization."""

    async def resolve(
        self,
        command: PromotionCommandV2,
        *,
        now: datetime,
    ) -> PromotionAuthorizationV1: ...


@runtime_checkable
class PromotionCoordinator(Protocol):
    """Dispatch one authenticated candidate-promotion command."""

    async def dispatch(
        self,
        command: PromotionCommandV2,
    ) -> PromotionDispatchResultV2: ...


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

    async def issue(
        self,
        command: PromotionCommandV2,
        authorization: PromotionAuthorizationV1,
    ) -> SignedCapability:
        if (
            type(command) is not PromotionCommandV2
            or type(authorization) is not PromotionAuthorizationV1
            or authorization.health_chain_locator != command.health_chain_locator
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        issuance = PromotionCapabilityIssuanceCommandV2(
            schema_version=PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V2,
            root_id=command.root_id,
            expected_root_sha256=command.expected_root_sha256,
            expected_epoch=command.expected_epoch,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            scheduled_at=command.scheduled_at,
            verified_apply_receipt=command.verified_apply_receipt,
            authorization=authorization,
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
            authorization=authorization,
            project_id=self._route.project_id,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.RESPONSE_INVALID)
        return capability


class StoredPromotionAuthorizationResolver:
    """Derive authorization only from coherent root state and a signed durable chain."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        root_reader: RootAuthorityBundleReader,
        health_chain_reader: PromotionHealthChainReader,
        health_signature_verifier: HealthAttestationVerifier,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or not isinstance(root_reader, RootAuthorityBundleReader)
            or root_reader.target != target
            or not isinstance(health_chain_reader, PromotionHealthChainReader)
            or health_chain_reader.target != target
            or not isinstance(health_signature_verifier, HealthAttestationVerifier)
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._root_reader = root_reader
        self._health_chain_reader = health_chain_reader
        self._health_signature_verifier = health_signature_verifier

    async def resolve(
        self,
        command: PromotionCommandV2,
        *,
        now: datetime,
    ) -> PromotionAuthorizationV1:
        if type(command) is not PromotionCommandV2:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        evaluation_time = _require_utc_second(now)
        try:
            bundle = await self._root_reader.read_root_creation_bundle(command.root_id)
            trusted = inspect_root_authority_bundle(bundle, target=self._target)
            chain = await self._health_chain_reader.read_promotion_health_chain(
                command.health_chain_locator
            )
        except asyncio.CancelledError:
            raise
        except (AuthorityStoreCorruptRecord, ContractError, TypeError, ValueError):
            raise CanaryExecutionError(
                CanaryExecutionErrorCode.TRUSTED_STATE_INVALID
            ) from None
        except Exception:
            raise CanaryExecutionError(
                CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE
            ) from None
        if (
            trusted is None
            or type(trusted.root) is not RolloutRootV3
            or trusted.root.root_id != command.root_id
            or trusted.root.root_sha256 != command.expected_root_sha256
            or trusted.authority.current_epoch != command.expected_epoch
            or trusted.service_claim.status is not ServiceClaimStatus.ACTIVE
            or chain is None
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID)
        try:
            compact = await verify_healthy_promotion_chain(
                chain=chain,
                signature_verifier=self._health_signature_verifier,
                now=evaluation_time,
            )
            authorization = create_promotion_authorization(
                root=trusted.root,
                signed_health_chain=chain,
                request_id=command.request_id,
                idempotency_key=command.idempotency_key,
                scheduled_at=command.scheduled_at,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CanaryExecutionError(
                CanaryExecutionErrorCode.TRUSTED_STATE_INVALID
            ) from None
        if (
            compact != authorization.healthy_promotion_proof
            or create_promotion_health_chain_locator(chain)
            != command.health_chain_locator
            or authorization.verified_apply_receipt
            != command.verified_apply_receipt
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID)
        return authorization


class PromotionRolloutCoordinator:
    """Issue, address, and enqueue one exact candidate-promotion task."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authorization_resolver: PromotionAuthorizationResolver,
        capability_client: PromotionCapabilityClient,
        dispatch_store: PromotionDispatchStoreV2,
        task_dispatcher: TaskDispatcher,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or target.region != "us-central1"
            or target.environment != "nonprod"
            or target.service_name != "controlgraph-reference-target"
            or "reconcile" in target.project_id.lower()
            or not isinstance(authorization_resolver, PromotionAuthorizationResolver)
            or not isinstance(capability_client, PromotionCapabilityClient)
            or not isinstance(dispatch_store, PromotionDispatchStoreV2)
            or type(dispatch_store.target) is not TargetBinding
            or dispatch_store.target != target
            or type(task_dispatcher) is not TaskDispatcher
            or (clock is not None and not callable(clock))
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._authorization_resolver = authorization_resolver
        self._capability_client = capability_client
        self._dispatch_store = dispatch_store
        self._task_dispatcher = task_dispatcher
        self._clock = clock or _now_utc_second

    async def dispatch(
        self,
        command: PromotionCommandV2,
    ) -> PromotionDispatchResultV2:
        if type(command) is not PromotionCommandV2:
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
            started_value = PromotionDispatchRecordV2.model_validate(
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
            direct_start = await self._dispatch_store.begin_promotion_enqueue_v2(
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
            dispatched = self._task_dispatcher.dispatch_prepared_v2(
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
            terminal_value = PromotionDispatchRecordV2.model_validate(
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
            terminal = await self._dispatch_store.compare_and_set_promotion_dispatch_v2(
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
        command: PromotionCommandV2,
    ) -> StoredRecord[PromotionDispatchRecordV2]:
        prepared_time = _require_utc_second(self._clock())
        authorization = await self._authorization_resolver.resolve(
            command,
            now=prepared_time,
        )
        capability = await self._capability_client.issue(command, authorization)
        if (
            not _capability_matches_command(
                capability,
                command,
                authorization=authorization,
                project_id=self._target.project_id,
            )
            or capability.claims.target != self._target
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.ISSUANCE_DENIED)
        claims = capability.claims
        try:
            intent = PromotionMutationIntentV2(
                schema_version=PROMOTION_MUTATION_INTENT_V2,
                request_id=authorization.request_id,
                idempotency_key=authorization.idempotency_key,
                target=authorization.target,
                root_id=authorization.root_id,
                root_sha256=authorization.root_sha256,
                epoch=authorization.epoch,
                action=CapabilityAction.PROMOTE_CANDIDATE,
                stable_revision=authorization.stable_revision,
                candidate_revision=authorization.candidate_revision,
                stable_percent=authorization.stable_percent,
                candidate_percent=authorization.candidate_percent,
                concurrency=None,
                plan_sha256=authorization.plan_sha256,
                provider_etag=authorization.provider_etag,
                capability_id=promotion_capability_id(authorization),
                promotion_authorization_sha256=canonical_sha256(authorization),
                expected_prestate_sha256=authorization.expected_prestate_sha256,
                terminal_health_decision_sha256=(
                    authorization.terminal_health_decision_sha256
                ),
                health_chain_sha256=(
                    authorization.health_chain_locator.health_chain_sha256
                ),
                desired_poststate_sha256=authorization.desired_poststate_sha256,
                proof_valid_until=authorization.proof_valid_until,
                authorization=authorization,
            )
            request = PromotionTaskRequestV2(
                schema_version=PROMOTION_TASK_REQUEST_V2,
                task_id=f"task-{capability.claims_sha256}",
                queue_region="us-central1",
                handler_audience=claims.audience,
                scheduled_at=claims.not_before,
                expires_at=claims.expires_at,
                capability=capability,
                intent=intent,
            )
            addressed = self._task_dispatcher.prepare(request, now=prepared_time)
            command_sha256 = promotion_command_v2_sha256(command)
            prepared_value = PromotionDispatchRecordV2(
                schema_version=PROMOTION_DISPATCH_RECORD_V2,
                dispatch_id=promotion_dispatch_v2_id(command_sha256),
                command_sha256=command_sha256,
                promotion_authorization_sha256=canonical_sha256(authorization),
                capability_id=promotion_capability_id(authorization),
                request_id=authorization.request_id,
                idempotency_key=authorization.idempotency_key,
                target=authorization.target,
                root_id=authorization.root_id,
                root_sha256=authorization.root_sha256,
                epoch=authorization.epoch,
                scheduled_at=authorization.scheduled_at,
                source_receipt_sha256=authorization.source_receipt_sha256,
                health_chain_sha256=(
                    authorization.health_chain_locator.health_chain_sha256
                ),
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
            return await self._dispatch_store.prepare_or_adopt_promotion_dispatch_v2(
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
        command: PromotionCommandV2,
    ) -> StoredRecord[PromotionDispatchRecordV2] | None:
        try:
            return await self._dispatch_store.read_promotion_dispatch_v2(command)
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
        command: PromotionCommandV2,
    ) -> StoredRecord[PromotionDispatchRecordV2]:
        current = await self._read_dispatch(command)
        if current is None:
            raise CanaryExecutionError(CanaryExecutionErrorCode.TRUSTED_STATE_INVALID)
        return current

    async def _read_after_transition(
        self,
        command: PromotionCommandV2,
    ) -> StoredRecord[PromotionDispatchRecordV2]:
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
        stored: StoredRecord[PromotionDispatchRecordV2],
        command: PromotionCommandV2,
    ) -> PromotionDispatchResultV2 | None:
        expected_revisions = {
            PromotionDispatchState.PREPARED: 0,
            PromotionDispatchState.ENQUEUE_STARTED: 1,
            PromotionDispatchState.CREATED: 2,
            PromotionDispatchState.DUPLICATE: 2,
            PromotionDispatchState.AMBIGUOUS: 2,
        }
        if (
            type(stored) is not StoredRecord
            or type(stored.value) is not PromotionDispatchRecordV2
            or stored.value.target != self._target
            or stored.revision != expected_revisions.get(stored.value.state)
            or stored.value.command_sha256 != promotion_command_v2_sha256(command)
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
        return cast(PromotionDispatchResultV2, result)


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
        command: PromotionCommandV2,
        principal: AuthenticationContext,
    ) -> PromotionDispatchResultV2:
        if type(command) is not PromotionCommandV2:
            raise CanaryExecutionError(CanaryExecutionErrorCode.COMMAND_DENIED)
        if not _context_matches_policy(
            principal,
            self._authentication_policy,
            role=CallerRole.OPERATOR,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.OPERATOR_DENIED)
        invocation = PromotionInvocationV2(
            schema_version=PROMOTION_INVOCATION_V2,
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
            result = decode_contract(body, PromotionDispatchResultV2)
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
        invocation: PromotionInvocationV2,
        caller: AuthenticationContext,
    ) -> PromotionDispatchResultV2:
        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise CanaryExecutionError(CanaryExecutionErrorCode.CALLER_DENIED)
        if type(invocation) is not PromotionInvocationV2:
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
    record: PromotionDispatchRecordV2,
    dispatched: TaskEnqueueResult,
) -> PromotionDispatchResultV2:
    task = record.task
    claims = task.capability.claims
    authorization = task.intent.authorization
    return PromotionDispatchResultV2(
        schema_version=PROMOTION_DISPATCH_RESULT_V2,
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
        verified_apply_receipt=authorization.verified_apply_receipt,
        source_receipt_sha256=authorization.source_receipt_sha256,
        expected_prestate_sha256=authorization.expected_prestate_sha256,
        terminal_health_decision_sha256=(
            authorization.terminal_health_decision_sha256
        ),
        health_chain_sha256=authorization.health_chain_locator.health_chain_sha256,
        health_chain_locator=authorization.health_chain_locator,
        healthy_promotion_proof_sha256=(
            authorization.healthy_promotion_proof_sha256
        ),
        desired_poststate_sha256=authorization.desired_poststate_sha256,
        proof_valid_until=authorization.proof_valid_until,
        promotion_authorization_sha256=canonical_sha256(authorization),
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
    command: PromotionCommandV2,
    *,
    authorization: PromotionAuthorizationV1,
    project_id: str,
) -> bool:
    if (
        type(capability) is not SignedCapability
        or type(authorization) is not PromotionAuthorizationV1
    ):
        return False
    claims = capability.claims
    return (
        claims.target.project_id == project_id
        and authorization.root_id == command.root_id
        and authorization.root_sha256 == command.expected_root_sha256
        and authorization.epoch == command.expected_epoch
        and authorization.request_id == command.request_id
        and authorization.idempotency_key == command.idempotency_key
        and authorization.scheduled_at == command.scheduled_at
        and authorization.verified_apply_receipt == command.verified_apply_receipt
        and authorization.health_chain_locator == command.health_chain_locator
        and claims.capability_id == promotion_capability_id(authorization)
        and claims.issuer == authorization.issuer_identity
        and claims.subject == authorization.executor_identity
        and claims.audience == authorization.executor_audience
        and claims.signing_key_version
        == authorization.capability_signing_key_version
        and claims.target == authorization.target
        and claims.root_id == authorization.root_id
        and claims.root_sha256 == authorization.root_sha256
        and claims.epoch == authorization.epoch
        and claims.request_id == authorization.request_id
        and claims.idempotency_key == authorization.idempotency_key
        and claims.not_before == authorization.scheduled_at
        and authorization.healthy_promotion_proof.issued_at
        <= claims.issued_at
        <= claims.not_before
        < claims.expires_at
        <= authorization.proof_valid_until
        and claims.action is CapabilityAction.PROMOTE_CANDIDATE
        and claims.concurrency is None
        and claims.stable_revision == authorization.stable_revision
        and claims.candidate_revision == authorization.candidate_revision
        and claims.stable_percent == authorization.stable_percent
        and claims.candidate_percent == authorization.candidate_percent
        and claims.plan_sha256 == authorization.plan_sha256
        and claims.provider_etag == authorization.provider_etag
        and claims.parent_capability_sha256 is None
    )


def _result_matches_command(
    result: object,
    command: PromotionCommandV2,
    *,
    project_id: str,
) -> bool:
    return (
        type(result) is PromotionDispatchResultV2
        and result.request_id == command.request_id
        and result.idempotency_key == command.idempotency_key
        and result.root_id == command.root_id
        and result.root_sha256 == command.expected_root_sha256
        and result.epoch == command.expected_epoch
        and result.scheduled_at == command.scheduled_at
        and result.target.project_id == project_id
        and result.stable_percent == 0
        and result.candidate_percent == 100
        and result.verified_apply_receipt == command.verified_apply_receipt
        and result.source_receipt_sha256
        == command.verified_apply_receipt.receipt_sha256
        and result.health_chain_sha256
        == command.health_chain_locator.health_chain_sha256
        and result.health_chain_locator == command.health_chain_locator
        and result.scheduled_at < result.expires_at <= result.proof_valid_until
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
    "PromotionAuthorizationResolver",
    "PromotionCapabilityClient",
    "PromotionCoordinator",
    "PromotionRolloutCoordinator",
    "StoredPromotionAuthorizationResolver",
]
