"""Narrow Cloud Run v2 adapter sealed to one declared canary target."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from typing import Final, Protocol, cast

from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2

from controlgraph_canary.application.cloud_run import (
    CloudRunMutationOutcome,
    CloudRunMutationReason,
    CloudRunMutationResult,
    CloudRunReadError,
    CloudRunReadErrorCode,
    CloudRunRevisionState,
    CloudRunServiceState,
    CloudRunTargetConfiguration,
    CloudRunTargetState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
    DeclaredRevision,
)
from controlgraph_canary.application.execution import MutationPermit
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.contracts.models import CapabilityAction, MutationIntent, TargetBinding

CLOUD_RUN_REGION: Final = "us-central1"
CLOUD_RUN_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
CLOUD_RUN_RPC_TIMEOUT_SECONDS: Final = 5.0
CLOUD_RUN_OPERATION_TIMEOUT_SECONDS: Final = 30.0

_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_REVISION_ALLOCATION: Final = (
    run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION
)
_KNOWN_PRECONDITION_FAILURES: Final = (
    api_exceptions.Aborted,
    api_exceptions.Conflict,
    api_exceptions.FailedPrecondition,
)
_KNOWN_SAFE_REJECTIONS: Final = (
    api_exceptions.BadRequest,
    api_exceptions.Forbidden,
    api_exceptions.InvalidArgument,
    api_exceptions.NotFound,
    api_exceptions.PermissionDenied,
    api_exceptions.Unauthenticated,
    api_exceptions.Unauthorized,
)


class _ProviderOperationPort(Protocol):
    name: str


class _AsyncOperationPort(Protocol):
    @property
    def operation(self) -> _ProviderOperationPort: ...

    async def result(self, timeout: float | None = None) -> object: ...


class _ServicesClientPort(Protocol):
    async def get_service(
        self,
        request: run_v2.GetServiceRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> run_v2.Service: ...

    async def update_service(
        self,
        request: run_v2.UpdateServiceRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> _AsyncOperationPort: ...


class _RevisionsClientPort(Protocol):
    async def get_revision(
        self,
        request: run_v2.GetRevisionRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> run_v2.Revision: ...


type ServicesClientFactory = Callable[[], _ServicesClientPort]
type RevisionsClientFactory = Callable[[], _RevisionsClientPort]


def _default_services_client_factory() -> _ServicesClientPort:
    return cast(_ServicesClientPort, run_v2.ServicesAsyncClient())


def _default_revisions_client_factory() -> _RevisionsClientPort:
    return cast(_RevisionsClientPort, run_v2.RevisionsAsyncClient())


class CloudRunV2Adapter:
    """Read and conditionally route traffic for one fixed reference service."""

    def __init__(
        self,
        *,
        configuration: CloudRunTargetConfiguration,
        service_role: ServiceRole,
        configured_project_id: str,
        services_client_factory: ServicesClientFactory | None = None,
        revisions_client_factory: RevisionsClientFactory | None = None,
    ) -> None:
        if type(configuration) is not CloudRunTargetConfiguration:
            raise TypeError("an exact Cloud Run target configuration is required")
        if type(service_role) is not ServiceRole or service_role not in {
            ServiceRole.EXECUTOR,
            ServiceRole.RECOVERY,
        }:
            raise ValueError("Cloud Run mutation role must be executor or recovery")
        target = configuration.target
        if (
            type(configured_project_id) is not str
            or _CONTROLGRAPH_PROJECT_ID.fullmatch(configured_project_id) is None
            or target.project_id != configured_project_id
        ):
            raise ValueError("Cloud Run project is not the configured ControlGraph project")
        if target.region != CLOUD_RUN_REGION:
            raise ValueError("Cloud Run target must use us-central1")
        if target.service_name != CLOUD_RUN_REFERENCE_SERVICE:
            raise ValueError("Cloud Run adapter is sealed to the reference service")
        if configuration.stable_concurrency != configuration.candidate_concurrency:
            raise ValueError("declared revisions must share the approved concurrency")
        if services_client_factory is not None and not callable(services_client_factory):
            raise TypeError("Cloud Run services client factory must be callable")
        if revisions_client_factory is not None and not callable(revisions_client_factory):
            raise TypeError("Cloud Run revisions client factory must be callable")
        self._configuration = configuration
        self._service_role = service_role
        self._services_client_factory = services_client_factory or _default_services_client_factory
        self._revisions_client_factory = (
            revisions_client_factory or _default_revisions_client_factory
        )
        self._services: _ServicesClientPort | None = None
        self._revisions: _RevisionsClientPort | None = None
        self._services_lock = asyncio.Lock()
        self._revisions_lock = asyncio.Lock()

    @property
    def target(self) -> TargetBinding:
        return self._configuration.target

    @property
    def service_role(self) -> ServiceRole:
        return self._service_role

    async def read_service(self) -> CloudRunServiceState:
        """Read only the exact configured service resource."""

        request = run_v2.GetServiceRequest(name=self._configuration.service_resource)
        try:
            client = await self._services_client()
            async with asyncio.timeout(CLOUD_RUN_RPC_TIMEOUT_SECONDS):
                service = await client.get_service(
                    request,
                    retry=None,
                    timeout=CLOUD_RUN_RPC_TIMEOUT_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except api_exceptions.NotFound:
            raise CloudRunReadError(CloudRunReadErrorCode.NOT_FOUND) from None
        except CloudRunReadError:
            raise
        except Exception:
            raise CloudRunReadError(CloudRunReadErrorCode.UNAVAILABLE) from None
        try:
            return self._decode_service(service)
        except (TypeError, ValueError):
            raise CloudRunReadError(CloudRunReadErrorCode.CORRUPT_RESPONSE) from None

    async def read_revision(self, declared: DeclaredRevision) -> CloudRunRevisionState:
        """Read one of the two constructor-declared immutable revisions."""

        revision_name = self._configuration.revision(declared)
        request = run_v2.GetRevisionRequest(name=self._configuration.revision_resource(declared))
        try:
            client = await self._revisions_client()
            async with asyncio.timeout(CLOUD_RUN_RPC_TIMEOUT_SECONDS):
                revision = await client.get_revision(
                    request,
                    retry=None,
                    timeout=CLOUD_RUN_RPC_TIMEOUT_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except api_exceptions.NotFound:
            raise CloudRunReadError(CloudRunReadErrorCode.NOT_FOUND) from None
        except CloudRunReadError:
            raise
        except Exception:
            raise CloudRunReadError(CloudRunReadErrorCode.UNAVAILABLE) from None
        try:
            return self._decode_revision(revision, expected_revision=revision_name)
        except (TypeError, ValueError):
            raise CloudRunReadError(CloudRunReadErrorCode.CORRUPT_RESPONSE) from None

    async def read_target(self) -> CloudRunTargetState:
        """Read the fixed service and both declared revisions without a list surface."""

        service, stable, candidate = await asyncio.gather(
            self.read_service(),
            self.read_revision(DeclaredRevision.STABLE),
            self.read_revision(DeclaredRevision.CANDIDATE),
        )
        if (
            stable.revision != self._configuration.stable_revision
            or stable.concurrency != self._configuration.stable_concurrency
            or candidate.revision != self._configuration.candidate_revision
            or candidate.concurrency != self._configuration.candidate_concurrency
        ):
            raise CloudRunReadError(CloudRunReadErrorCode.CORRUPT_RESPONSE)
        return CloudRunTargetState(
            service=service,
            stable_revision=stable,
            candidate_revision=candidate,
        )

    async def mutate(self, permit: MutationPermit) -> CloudRunMutationResult:
        """Consume one final-gate permit and make one conditional traffic request."""

        if type(permit) is not MutationPermit:
            raise TypeError("Cloud Run mutation requires an exact one-use permit")
        intent = permit.intent
        requested, expected_concurrency, rejection = self._admit_intent(intent)
        if rejection is not None:
            return _failed_safe(requested, expected_concurrency, rejection)
        request = self._update_request(intent, requested)
        try:
            client = await self._services_client()
        except asyncio.CancelledError:
            raise
        except Exception:
            return _failed_safe(
                requested,
                expected_concurrency,
                CloudRunMutationReason.PROVIDER_REJECTED,
            )
        try:
            async with asyncio.timeout(CLOUD_RUN_RPC_TIMEOUT_SECONDS):
                operation = await client.update_service(
                    request,
                    retry=None,
                    timeout=CLOUD_RUN_RPC_TIMEOUT_SECONDS,
                )
        except _KNOWN_PRECONDITION_FAILURES:
            return _failed_safe(
                requested,
                expected_concurrency,
                CloudRunMutationReason.PRECONDITION_FAILED,
            )
        except _KNOWN_SAFE_REJECTIONS:
            return _failed_safe(
                requested,
                expected_concurrency,
                CloudRunMutationReason.PROVIDER_REJECTED,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return _ambiguous(requested, expected_concurrency, operation_name=None)
        operation_name = _operation_name(operation)
        if operation_name is None:
            return _ambiguous(requested, expected_concurrency, operation_name=None)
        try:
            async with asyncio.timeout(CLOUD_RUN_OPERATION_TIMEOUT_SECONDS):
                response = await operation.result(timeout=CLOUD_RUN_OPERATION_TIMEOUT_SECONDS)
            service = self._decode_service(response)
            if service.traffic != requested:
                return _ambiguous(
                    requested,
                    expected_concurrency,
                    operation_name=operation_name,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            return _ambiguous(
                requested,
                expected_concurrency,
                operation_name=operation_name,
            )
        return CloudRunMutationResult(
            outcome=CloudRunMutationOutcome.APPLIED,
            requested_traffic=requested,
            expected_concurrency=expected_concurrency,
            operation_name=operation_name,
            service=service,
            reason=None,
        )

    def _admit_intent(
        self,
        intent: MutationIntent,
    ) -> tuple[
        tuple[CloudRunTrafficAllocation, ...],
        int,
        CloudRunMutationReason | None,
    ]:
        configuration = self._configuration
        requested = (
            CloudRunTrafficAllocation(
                revision=configuration.stable_revision,
                percent=intent.stable_percent,
                tag="stable",
            ),
            CloudRunTrafficAllocation(
                revision=configuration.candidate_revision,
                percent=intent.candidate_percent,
                tag="candidate",
            ),
        )
        expected_concurrency = configuration.stable_concurrency
        exact_target = (
            intent.target == configuration.target
            and intent.stable_revision == configuration.stable_revision
            and intent.candidate_revision == configuration.candidate_revision
        )
        role_admits = (
            self._service_role is ServiceRole.EXECUTOR
            and intent.action in {CapabilityAction.APPLY_CANARY, CapabilityAction.PROMOTE_CANDIDATE}
        ) or (
            self._service_role is ServiceRole.RECOVERY
            and intent.action is CapabilityAction.RECOVER_STABLE
        )
        concurrency_is_exact = (
            intent.concurrency == expected_concurrency
            if intent.action is CapabilityAction.RECOVER_STABLE
            else intent.concurrency is None
        )
        if not exact_target or not role_admits or not concurrency_is_exact:
            return (
                requested,
                expected_concurrency,
                CloudRunMutationReason.DECLARATION_MISMATCH,
            )
        return requested, expected_concurrency, None

    def _update_request(
        self,
        intent: MutationIntent,
        traffic: tuple[CloudRunTrafficAllocation, ...],
    ) -> run_v2.UpdateServiceRequest:
        service = run_v2.Service(
            name=self._configuration.service_resource,
            etag=intent.provider_etag,
            traffic=[
                run_v2.TrafficTarget(
                    type_=_REVISION_ALLOCATION,
                    revision=item.revision,
                    percent=item.percent,
                    tag=item.tag,
                )
                for item in traffic
            ],
        )
        return run_v2.UpdateServiceRequest(
            service=service,
            update_mask={"paths": ["traffic"]},
            validate_only=False,
            allow_missing=False,
        )

    async def _services_client(self) -> _ServicesClientPort:
        if self._services is not None:
            return self._services
        async with self._services_lock:
            if self._services is None:
                try:
                    client = self._services_client_factory()
                    if not all(
                        callable(getattr(client, name, None))
                        for name in ("get_service", "update_service")
                    ):
                        raise TypeError("Cloud Run services client is incomplete")
                except Exception:
                    raise CloudRunReadError(CloudRunReadErrorCode.UNAVAILABLE) from None
                self._services = client
        return self._services

    async def _revisions_client(self) -> _RevisionsClientPort:
        if self._revisions is not None:
            return self._revisions
        async with self._revisions_lock:
            if self._revisions is None:
                try:
                    client = self._revisions_client_factory()
                    if not callable(getattr(client, "get_revision", None)):
                        raise TypeError("Cloud Run revisions client is incomplete")
                except Exception:
                    raise CloudRunReadError(CloudRunReadErrorCode.UNAVAILABLE) from None
                self._revisions = client
        return self._revisions

    def _decode_service(self, value: object) -> CloudRunServiceState:
        if type(value) is not run_v2.Service:
            raise TypeError("Cloud Run service response type is invalid")
        configuration = self._configuration
        declared = {
            configuration.stable_revision: "stable",
            configuration.candidate_revision: "candidate",
        }
        revision_order = {
            configuration.stable_revision: 0,
            configuration.candidate_revision: 1,
        }
        traffic = tuple(
            sorted(
                (_decode_traffic(item, declared=declared) for item in value.traffic),
                key=lambda item: revision_order[item.revision],
            )
        )
        traffic_statuses = tuple(
            sorted(
                (
                    _decode_traffic_status(item, declared=declared)
                    for item in value.traffic_statuses
                ),
                key=lambda item: revision_order[item.revision],
            )
        )
        state = CloudRunServiceState(
            target=configuration.target,
            resource_name=value.name,
            uid=value.uid,
            etag=value.etag,
            generation=value.generation,
            observed_generation=value.observed_generation,
            reconciling=value.reconciling,
            latest_ready_revision=value.latest_ready_revision,
            latest_created_revision=value.latest_created_revision,
            template_revision=value.template.revision,
            template_concurrency=value.template.max_instance_request_concurrency,
            traffic=traffic,
            traffic_statuses=traffic_statuses,
            uri=value.uri,
        )
        if any(
            revision not in {configuration.stable_revision, configuration.candidate_revision}
            for revision in (
                state.latest_ready_revision,
                state.latest_created_revision,
                state.template_revision,
            )
        ):
            raise ValueError("Cloud Run service references an undeclared revision")
        expected_template_concurrency = (
            configuration.stable_concurrency
            if state.template_revision == configuration.stable_revision
            else configuration.candidate_concurrency
        )
        if state.template_concurrency != expected_template_concurrency:
            raise ValueError("Cloud Run service template concurrency is not declared")
        return state

    def _decode_revision(
        self,
        value: object,
        *,
        expected_revision: str,
    ) -> CloudRunRevisionState:
        if type(value) is not run_v2.Revision:
            raise TypeError("Cloud Run revision response type is invalid")
        configuration = self._configuration
        state = CloudRunRevisionState(
            target=configuration.target,
            revision=expected_revision,
            resource_name=value.name,
            service_resource=value.service,
            uid=value.uid,
            etag=value.etag,
            generation=value.generation,
            observed_generation=value.observed_generation,
            reconciling=value.reconciling,
            concurrency=value.max_instance_request_concurrency,
        )
        expected_concurrency = (
            configuration.stable_concurrency
            if expected_revision == configuration.stable_revision
            else configuration.candidate_concurrency
        )
        if state.concurrency != expected_concurrency:
            raise ValueError("Cloud Run revision concurrency is not declared")
        return state


def _decode_traffic(
    value: run_v2.TrafficTarget,
    *,
    declared: dict[str, str],
) -> CloudRunTrafficAllocation:
    if type(value) is not run_v2.TrafficTarget or value.type_ != _REVISION_ALLOCATION:
        raise ValueError("Cloud Run traffic target is not revision-bound")
    expected_tag = declared.get(value.revision)
    if expected_tag is None or value.tag != expected_tag:
        raise ValueError("Cloud Run traffic target is not declared")
    return CloudRunTrafficAllocation(
        revision=value.revision,
        percent=value.percent,
        tag=value.tag,
    )


def _decode_traffic_status(
    value: run_v2.TrafficTargetStatus,
    *,
    declared: dict[str, str],
) -> CloudRunTrafficStatus:
    if type(value) is not run_v2.TrafficTargetStatus or value.type_ != _REVISION_ALLOCATION:
        raise ValueError("Cloud Run traffic status is not revision-bound")
    expected_tag = declared.get(value.revision)
    if expected_tag is None or value.tag != expected_tag:
        raise ValueError("Cloud Run traffic status is not declared")
    return CloudRunTrafficStatus(
        revision=value.revision,
        percent=value.percent,
        tag=value.tag,
        uri=value.uri,
    )


def _operation_name(operation: object) -> str | None:
    try:
        provider_operation = cast(_AsyncOperationPort, operation).operation
        name = provider_operation.name
    except Exception:
        return None
    if type(name) is not str or not name or len(name) > 512 or name != name.strip():
        return None
    return name


def _failed_safe(
    requested: tuple[CloudRunTrafficAllocation, ...],
    expected_concurrency: int,
    reason: CloudRunMutationReason,
) -> CloudRunMutationResult:
    return CloudRunMutationResult(
        outcome=CloudRunMutationOutcome.FAILED_SAFE,
        requested_traffic=requested,
        expected_concurrency=expected_concurrency,
        operation_name=None,
        service=None,
        reason=reason,
    )


def _ambiguous(
    requested: tuple[CloudRunTrafficAllocation, ...],
    expected_concurrency: int,
    *,
    operation_name: str | None,
) -> CloudRunMutationResult:
    return CloudRunMutationResult(
        outcome=CloudRunMutationOutcome.AMBIGUOUS,
        requested_traffic=requested,
        expected_concurrency=expected_concurrency,
        operation_name=operation_name,
        service=None,
        reason=CloudRunMutationReason.OUTCOME_UNKNOWN,
    )


__all__ = [
    "CLOUD_RUN_OPERATION_TIMEOUT_SECONDS",
    "CLOUD_RUN_REFERENCE_SERVICE",
    "CLOUD_RUN_REGION",
    "CLOUD_RUN_RPC_TIMEOUT_SECONDS",
    "CloudRunV2Adapter",
    "RevisionsClientFactory",
    "ServicesClientFactory",
]
