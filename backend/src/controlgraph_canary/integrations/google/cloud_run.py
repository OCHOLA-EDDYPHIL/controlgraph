"""Narrow Cloud Run v2 adapter sealed to one declared canary target."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Sequence
from typing import Final, Protocol, cast

from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2

from controlgraph_canary.application.cloud_run import (
    CloudRunExecutionEnvironment,
    CloudRunHttpProbe,
    CloudRunMutationOutcome,
    CloudRunMutationReason,
    CloudRunMutationResult,
    CloudRunNetworkInterface,
    CloudRunReadError,
    CloudRunReadErrorCode,
    CloudRunReadyState,
    CloudRunRevisionConfiguration,
    CloudRunRevisionState,
    CloudRunServiceState,
    CloudRunTargetConfiguration,
    CloudRunTargetState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
    CloudRunVpcEgress,
    TargetConfigurationProjection,
)
from controlgraph_canary.application.execution import MutationPermit
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.application.receipt_execution import ReceiptReadbackResult
from controlgraph_canary.application.reference_target_reset import (
    REFERENCE_TARGET_CANDIDATE_REVISION,
    REFERENCE_TARGET_CONCURRENCY,
    REFERENCE_TARGET_STABLE_REVISION,
    ReferenceTargetResetConfiguration,
    ReferenceTargetResetError,
    ReferenceTargetResetErrorCode,
    ReferenceTargetResetOutcome,
    ReferenceTargetResetRequest,
    ReferenceTargetResetResult,
)
from controlgraph_canary.contracts.models import CapabilityAction, MutationIntent, TargetBinding

CLOUD_RUN_REGION: Final = "us-central1"
CLOUD_RUN_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
CLOUD_RUN_RPC_TIMEOUT_SECONDS: Final = 5.0
_CLOUD_RUN_MUTATION_RPC_TIMEOUT_SECONDS: Final = 15.0
CLOUD_RUN_OPERATION_TIMEOUT_SECONDS: Final = 30.0

_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_REVISION_ALLOCATION: Final = (
    run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION
)
_PREVIOUS_REFERENCE_TARGET_STABLE_REVISION: Final = (
    "controlgraph-reference-target-stable-v1"
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


class _ReadOnlyServicesClientPort(Protocol):
    async def get_service(
        self,
        request: run_v2.GetServiceRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> run_v2.Service: ...


class _RevisionsClientPort(Protocol):
    async def get_revision(
        self,
        request: run_v2.GetRevisionRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> run_v2.Revision: ...


type ServicesClientFactory = Callable[[], _ServicesClientPort]
type ReadOnlyServicesClientFactory = Callable[[], _ReadOnlyServicesClientPort]
type RevisionsClientFactory = Callable[[], _RevisionsClientPort]


def _default_services_client_factory() -> _ServicesClientPort:
    return cast(_ServicesClientPort, run_v2.ServicesAsyncClient())


def _default_read_only_services_client_factory() -> _ReadOnlyServicesClientPort:
    return cast(_ReadOnlyServicesClientPort, run_v2.ServicesAsyncClient())


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

    async def read_revision(self, revision_name: str) -> CloudRunRevisionState:
        """Read one exact service-owned immutable revision by name."""

        request = run_v2.GetRevisionRequest(
            name=self._configuration.revision_resource_name(revision_name)
        )
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
            self.read_revision(self._configuration.stable_revision),
            self.read_revision(self._configuration.candidate_revision),
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
            async with asyncio.timeout(_CLOUD_RUN_MUTATION_RPC_TIMEOUT_SECONDS):
                operation = await client.update_service(
                    request,
                    retry=None,
                    timeout=_CLOUD_RUN_MUTATION_RPC_TIMEOUT_SECONDS,
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
        return _decode_service(value, configuration=self._configuration)

    def _decode_revision(
        self,
        value: object,
        *,
        expected_revision: str,
    ) -> CloudRunRevisionState:
        return _decode_revision(
            value,
            configuration=self._configuration,
            expected_revision=expected_revision,
        )


class CloudRunV2ReferenceTargetResetter:
    """Explicitly restore the configured disposable target before an acceptance run."""

    def __init__(
        self,
        *,
        configuration: ReferenceTargetResetConfiguration,
        services_client_factory: ServicesClientFactory | None = None,
        revisions_client_factory: RevisionsClientFactory | None = None,
    ) -> None:
        if type(configuration) is not ReferenceTargetResetConfiguration:
            raise TypeError("an exact reference-target reset configuration is required")
        if services_client_factory is not None and not callable(services_client_factory):
            raise TypeError("Cloud Run services client factory must be callable")
        if revisions_client_factory is not None and not callable(revisions_client_factory):
            raise TypeError("Cloud Run revisions client factory must be callable")
        self._reset_configuration = configuration
        self._target_configuration = configuration.target_configuration
        self._services_client_factory = services_client_factory or _default_services_client_factory
        self._revisions_client_factory = (
            revisions_client_factory or _default_revisions_client_factory
        )
        self._services: _ServicesClientPort | None = None
        self._revisions: _RevisionsClientPort | None = None
        self._services_lock = asyncio.Lock()
        self._revisions_lock = asyncio.Lock()

    @property
    def configuration(self) -> ReferenceTargetResetConfiguration:
        return self._reset_configuration

    async def reset(
        self,
        request: ReferenceTargetResetRequest,
    ) -> ReferenceTargetResetResult:
        """Make at most one conditional update and require a fresh exact readback."""

        if type(request) is not ReferenceTargetResetRequest:
            raise TypeError("an exact reference-target reset request is required")
        before = await self._read_target()
        before_traffic = self._admit_target(
            before,
            allow_reset_precursor=True,
        )
        if before.service.etag != request.expected_etag:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.PRECONDITION_FAILED
            )
        if before_traffic == (100, 0):
            confirmed = await self._read_target()
            if (
                self._admit_target(confirmed) != (100, 0)
                or confirmed.service.etag != before.service.etag
                or confirmed.service.generation != before.service.generation
            ):
                raise ReferenceTargetResetError(
                    ReferenceTargetResetErrorCode.PRECONDITION_FAILED
                )
            return ReferenceTargetResetResult(
                configuration=self.configuration,
                request=request,
                outcome=ReferenceTargetResetOutcome.ALREADY_BASELINE,
                previous_generation=before.service.generation,
                observed_generation=confirmed.service.generation,
                observed_etag=confirmed.service.etag,
                operation_name=None,
            )

        acknowledged, operation_name = await self._update_baseline(before.service.etag)
        try:
            observed = await self._read_target()
            observed_traffic = self._admit_target(observed)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.OUTCOME_UNKNOWN
            ) from None
        if (
            observed_traffic != (100, 0)
            or observed.service.generation <= before.service.generation
            or observed.service.etag == before.service.etag
        ):
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.OUTCOME_UNKNOWN
            )
        outcome = (
            ReferenceTargetResetOutcome.RESET_APPLIED
            if acknowledged
            else ReferenceTargetResetOutcome.RESET_CONFIRMED_AFTER_UNKNOWN
        )
        return ReferenceTargetResetResult(
            configuration=self.configuration,
            request=request,
            outcome=outcome,
            previous_generation=before.service.generation,
            observed_generation=observed.service.generation,
            observed_etag=observed.service.etag,
            operation_name=operation_name,
        )

    async def _read_target(self) -> CloudRunTargetState:
        try:
            service, stable, candidate = await asyncio.gather(
                self._read_service(),
                self._read_revision(REFERENCE_TARGET_STABLE_REVISION),
                self._read_revision(REFERENCE_TARGET_CANDIDATE_REVISION),
            )
            return CloudRunTargetState(
                service=service,
                stable_revision=stable,
                candidate_revision=candidate,
            )
        except asyncio.CancelledError:
            raise
        except ReferenceTargetResetError:
            raise
        except Exception:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
            ) from None

    async def _read_service(self) -> CloudRunServiceState:
        request = run_v2.GetServiceRequest(name=self._target_configuration.service_resource)
        try:
            client = await self._services_client()
            async with asyncio.timeout(CLOUD_RUN_RPC_TIMEOUT_SECONDS):
                response = await client.get_service(
                    request,
                    retry=None,
                    timeout=CLOUD_RUN_RPC_TIMEOUT_SECONDS,
                )
            return _decode_service(response, configuration=self._target_configuration)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
            ) from None

    async def _read_revision(self, revision_name: str) -> CloudRunRevisionState:
        request = run_v2.GetRevisionRequest(
            name=self._target_configuration.revision_resource_name(revision_name)
        )
        try:
            client = await self._revisions_client()
            async with asyncio.timeout(CLOUD_RUN_RPC_TIMEOUT_SECONDS):
                response = await client.get_revision(
                    request,
                    retry=None,
                    timeout=CLOUD_RUN_RPC_TIMEOUT_SECONDS,
                )
            return _decode_revision(
                response,
                configuration=self._target_configuration,
                expected_revision=revision_name,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
            ) from None

    def _admit_target(
        self,
        state: CloudRunTargetState,
        *,
        allow_reset_precursor: bool = False,
    ) -> tuple[int, int] | None:
        if type(state) is not CloudRunTargetState:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
            )
        service = state.service
        stable = state.stable_revision
        candidate = state.candidate_revision
        if (
            service.target != self.configuration.target
            or stable.revision != REFERENCE_TARGET_STABLE_REVISION
            or candidate.revision != REFERENCE_TARGET_CANDIDATE_REVISION
            or stable.configuration
            != self._expected_revision_configuration(self.configuration.stable_image)
            or candidate.configuration
            != self._expected_revision_configuration(self.configuration.candidate_image)
            or service.reconciling
            or service.ready_state is not CloudRunReadyState.READY
            or service.generation != service.observed_generation
            or service.template_revision != REFERENCE_TARGET_CANDIDATE_REVISION
            or service.latest_created_revision != REFERENCE_TARGET_CANDIDATE_REVISION
            or service.latest_ready_revision
            not in {
                _PREVIOUS_REFERENCE_TARGET_STABLE_REVISION,
                REFERENCE_TARGET_STABLE_REVISION,
                REFERENCE_TARGET_CANDIDATE_REVISION,
            }
            or stable.reconciling
            or stable.ready_state is not CloudRunReadyState.READY
            or stable.generation != stable.observed_generation
            or candidate.reconciling
            or candidate.ready_state is not CloudRunReadyState.READY
            or candidate.generation != candidate.observed_generation
        ):
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
            )
        if allow_reset_precursor and any(
            self._is_stable_only_baseline(
                service.traffic,
                revision=revision,
            )
            and self._is_stable_only_baseline(
                service.traffic_statuses,
                revision=revision,
            )
            for revision in (
                _PREVIOUS_REFERENCE_TARGET_STABLE_REVISION,
                REFERENCE_TARGET_STABLE_REVISION,
            )
        ):
            return None
        traffic = self._traffic_pair(service.traffic)
        statuses = self._traffic_pair(service.traffic_statuses)
        if traffic != statuses or traffic not in {(100, 0), (90, 10), (0, 100)}:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
            )
        if traffic == (100, 0) and (
            len(service.traffic) != 2
            or len(service.traffic_statuses) != 2
            or service.latest_ready_revision != REFERENCE_TARGET_CANDIDATE_REVISION
        ):
            if allow_reset_precursor and (
                len(service.traffic) == 2 and len(service.traffic_statuses) == 2
            ):
                return None
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
            )
        return traffic

    def _is_stable_only_baseline(
        self,
        allocations: Sequence[CloudRunTrafficAllocation | CloudRunTrafficStatus],
        *,
        revision: str,
    ) -> bool:
        return len(allocations) == 1 and (
            allocations[0].revision == revision
            and allocations[0].percent == 100
            and allocations[0].tag == "stable"
        )

    def _expected_revision_configuration(
        self,
        image: str,
    ) -> CloudRunRevisionConfiguration:
        return CloudRunRevisionConfiguration(
            image=image,
            service_account=(
                f"controlgraph-reference@{self.configuration.project_id}.iam.gserviceaccount.com"
            ),
            execution_environment=CloudRunExecutionEnvironment.GEN2,
            timeout_seconds=5,
            concurrency=REFERENCE_TARGET_CONCURRENCY,
            min_instance_count=0,
            max_instance_count=1,
            container_name="reference-target",
            command=(),
            args=(),
            working_dir=None,
            port_name="http1",
            container_port=8080,
            cpu_limit="1",
            memory_limit="512Mi",
            cpu_idle=True,
            startup_cpu_boost=False,
            startup_probe=CloudRunHttpProbe(
                path="/healthz",
                port=8080,
                initial_delay_seconds=0,
                timeout_seconds=2,
                period_seconds=5,
                failure_threshold=12,
            ),
            liveness_probe=CloudRunHttpProbe(
                path="/healthz",
                port=8080,
                initial_delay_seconds=5,
                timeout_seconds=2,
                period_seconds=10,
                failure_threshold=3,
            ),
            vpc_connector=None,
            vpc_egress=CloudRunVpcEgress.ALL_TRAFFIC,
            network_interfaces=(
                CloudRunNetworkInterface(
                    network=self.configuration.network_resource,
                    subnetwork=self.configuration.subnetwork_resource,
                    tags=(),
                ),
            ),
        )

    def _traffic_pair(
        self,
        allocations: Sequence[CloudRunTrafficAllocation | CloudRunTrafficStatus],
    ) -> tuple[int, int]:
        expected_tags = {
            REFERENCE_TARGET_STABLE_REVISION: "stable",
            REFERENCE_TARGET_CANDIDATE_REVISION: "candidate",
        }
        observed: dict[str, int] = {}
        for allocation in allocations:
            if (
                allocation.revision not in expected_tags
                or allocation.tag != expected_tags[allocation.revision]
            ):
                raise ReferenceTargetResetError(
                    ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
                )
            observed[allocation.revision] = allocation.percent
        return (
            observed.get(REFERENCE_TARGET_STABLE_REVISION, 0),
            observed.get(REFERENCE_TARGET_CANDIDATE_REVISION, 0),
        )

    async def _update_baseline(self, etag: str) -> tuple[bool, str | None]:
        request = run_v2.UpdateServiceRequest(
            service=run_v2.Service(
                name=self._target_configuration.service_resource,
                etag=etag,
                traffic=[
                    run_v2.TrafficTarget(
                        type_=_REVISION_ALLOCATION,
                        revision=REFERENCE_TARGET_STABLE_REVISION,
                        percent=100,
                        tag="stable",
                    ),
                    run_v2.TrafficTarget(
                        type_=_REVISION_ALLOCATION,
                        revision=REFERENCE_TARGET_CANDIDATE_REVISION,
                        percent=0,
                        tag="candidate",
                    ),
                ],
            ),
            update_mask={"paths": ["traffic"]},
            validate_only=False,
            allow_missing=False,
        )
        try:
            client = await self._services_client()
            async with asyncio.timeout(CLOUD_RUN_RPC_TIMEOUT_SECONDS):
                operation = await client.update_service(
                    request,
                    retry=None,
                    timeout=CLOUD_RUN_RPC_TIMEOUT_SECONDS,
                )
        except _KNOWN_PRECONDITION_FAILURES:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.PRECONDITION_FAILED
            ) from None
        except _KNOWN_SAFE_REJECTIONS:
            raise ReferenceTargetResetError(
                ReferenceTargetResetErrorCode.PROVIDER_REJECTED
            ) from None
        except asyncio.CancelledError:
            raise
        except Exception:
            return False, None
        operation_name = _operation_name(operation)
        if operation_name is None:
            return False, None
        try:
            async with asyncio.timeout(CLOUD_RUN_OPERATION_TIMEOUT_SECONDS):
                response = await operation.result(timeout=CLOUD_RUN_OPERATION_TIMEOUT_SECONDS)
            service = _decode_service(response, configuration=self._target_configuration)
            if self._traffic_pair(service.traffic) != (100, 0):
                return False, operation_name
        except asyncio.CancelledError:
            raise
        except Exception:
            return False, operation_name
        return True, operation_name

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
                    raise ReferenceTargetResetError(
                        ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
                    ) from None
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
                    raise ReferenceTargetResetError(
                        ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
                    ) from None
                self._revisions = client
        return self._revisions


class CloudRunV2ReceiptReadback:
    """Fresh read-only receipt observation for one fixed reference service."""

    def __init__(
        self,
        *,
        configuration: CloudRunTargetConfiguration,
        configured_project_id: str,
        services_client_factory: ReadOnlyServicesClientFactory | None = None,
    ) -> None:
        if type(configuration) is not CloudRunTargetConfiguration:
            raise TypeError("an exact Cloud Run target configuration is required")
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
            raise ValueError("Cloud Run receipt readback is sealed to the reference service")
        if configuration.stable_concurrency != configuration.candidate_concurrency:
            raise ValueError("declared revisions must share the approved concurrency")
        if services_client_factory is not None and not callable(services_client_factory):
            raise TypeError("Cloud Run services client factory must be callable")
        self._configuration = configuration
        self._services_client_factory = (
            services_client_factory or _default_read_only_services_client_factory
        )
        self._services: _ReadOnlyServicesClientPort | None = None
        self._services_lock = asyncio.Lock()

    @property
    def target(self) -> TargetBinding:
        return self._configuration.target

    async def readback(
        self,
        expected: TargetConfigurationProjection,
    ) -> ReceiptReadbackResult:
        """Read a fresh provider configuration without carrying mutation authority."""

        if type(expected) is not TargetConfigurationProjection:
            raise TypeError("Cloud Run receipt readback requires an exact expectation")
        configuration = self._configuration
        if (
            expected.target != configuration.target
            or expected.stable_revision != configuration.stable_revision
            or expected.candidate_revision != configuration.candidate_revision
            or expected.concurrency != configuration.stable_concurrency
        ):
            return _closed_readback()

        request = run_v2.GetServiceRequest(name=configuration.service_resource)
        try:
            client = await self._services_client()
            async with asyncio.timeout(CLOUD_RUN_RPC_TIMEOUT_SECONDS):
                provider_service = await client.get_service(
                    request,
                    retry=None,
                    timeout=CLOUD_RUN_RPC_TIMEOUT_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            return _closed_readback()

        try:
            service = _decode_service(provider_service, configuration=configuration)
        except (TypeError, ValueError):
            return _closed_readback()
        if (
            service.reconciling
            or service.ready_state is not CloudRunReadyState.READY
            or service.generation != service.observed_generation
            or service.template_revision != configuration.candidate_revision
            or service.latest_created_revision != configuration.candidate_revision
            or service.latest_ready_revision != configuration.candidate_revision
        ):
            return _closed_readback(service.etag)

        traffic = {item.revision: item.percent for item in service.traffic}
        observed_traffic = {
            item.revision: item.percent for item in service.traffic_statuses
        }
        if traffic != observed_traffic or set(traffic) != {
            configuration.stable_revision,
            configuration.candidate_revision,
        }:
            return _closed_readback(service.etag)
        try:
            observed = TargetConfigurationProjection(
                target=configuration.target,
                stable_revision=configuration.stable_revision,
                candidate_revision=configuration.candidate_revision,
                stable_percent=traffic[configuration.stable_revision],
                candidate_percent=traffic[configuration.candidate_revision],
                concurrency=service.template_concurrency,
            )
        except (TypeError, ValueError):
            return _closed_readback(service.etag)
        return ReceiptReadbackResult(
            state=observed,
            observed_etag=service.etag,
        )

    async def _services_client(self) -> _ReadOnlyServicesClientPort:
        if self._services is not None:
            return self._services
        async with self._services_lock:
            if self._services is None:
                try:
                    client = self._services_client_factory()
                    if not callable(getattr(client, "get_service", None)):
                        raise TypeError("Cloud Run services client is incomplete")
                except Exception:
                    raise CloudRunReadError(CloudRunReadErrorCode.UNAVAILABLE) from None
                self._services = client
        return self._services


class CloudRunV2SnapshotReader:
    """Verifier-only read surface for one fixed reference target."""

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
        if service_role is not ServiceRole.VERIFIER:
            raise ValueError("Cloud Run snapshot reads require the verifier role")
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
            raise ValueError("Cloud Run snapshot reader is sealed to the reference service")
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

    @property
    def reader_identity(self) -> str:
        return f"controlgraph-verifier@{self.target.project_id}.iam.gserviceaccount.com"

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
            return _decode_service(service, configuration=self._configuration)
        except (TypeError, ValueError):
            raise CloudRunReadError(CloudRunReadErrorCode.CORRUPT_RESPONSE) from None

    async def read_revision(self, revision_name: str) -> CloudRunRevisionState:
        """Read one traffic-selected revision under the configured service."""

        request = run_v2.GetRevisionRequest(
            name=self._configuration.revision_resource_name(revision_name)
        )
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
            return _decode_revision(
                revision,
                configuration=self._configuration,
                expected_revision=revision_name,
            )
        except (TypeError, ValueError):
            raise CloudRunReadError(CloudRunReadErrorCode.CORRUPT_RESPONSE) from None

    async def read_target(self) -> CloudRunTargetState:
        """Read the fixed service and both configured revisions without listing."""

        service, stable, candidate = await asyncio.gather(
            self.read_service(),
            self.read_revision(self._configuration.stable_revision),
            self.read_revision(self._configuration.candidate_revision),
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

    async def _services_client(self) -> _ServicesClientPort:
        if self._services is not None:
            return self._services
        async with self._services_lock:
            if self._services is None:
                try:
                    client = self._services_client_factory()
                    if not callable(getattr(client, "get_service", None)):
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


def _decode_service(
    value: object,
    *,
    configuration: CloudRunTargetConfiguration,
) -> CloudRunServiceState:
    if type(value) is not run_v2.Service:
        raise TypeError("Cloud Run service response type is invalid")
    prefix = f"{configuration.target.service_name}-"
    declared_order = {
        configuration.stable_revision: 0,
        configuration.candidate_revision: 1,
    }
    traffic = tuple(
        sorted(
            (_decode_traffic(item, revision_prefix=prefix) for item in value.traffic),
            key=lambda item: (declared_order.get(item.revision, 2), item.revision),
        )
    )
    traffic_statuses = tuple(
        sorted(
            (
                _decode_traffic_status(item, revision_prefix=prefix)
                for item in value.traffic_statuses
            ),
            key=lambda item: (declared_order.get(item.revision, 2), item.revision),
        )
    )
    return CloudRunServiceState(
        target=configuration.target,
        resource_name=value.name,
        uid=value.uid,
        etag=value.etag,
        generation=value.generation,
        observed_generation=value.observed_generation,
        reconciling=value.reconciling,
        ready_state=_decode_ready_condition(value.terminal_condition),
        latest_ready_revision=_decode_provider_revision_name(
            value.latest_ready_revision,
            configuration=configuration,
        ),
        latest_created_revision=_decode_provider_revision_name(
            value.latest_created_revision,
            configuration=configuration,
        ),
        template_revision=_decode_provider_revision_name(
            value.template.revision,
            configuration=configuration,
        ),
        template_concurrency=value.template.max_instance_request_concurrency,
        traffic=traffic,
        traffic_statuses=traffic_statuses,
        uri=value.uri,
    )


def _decode_revision(
    value: object,
    *,
    configuration: CloudRunTargetConfiguration,
    expected_revision: str,
) -> CloudRunRevisionState:
    if type(value) is not run_v2.Revision:
        raise TypeError("Cloud Run revision response type is invalid")
    ready_conditions = tuple(
        condition for condition in value.conditions if condition.type_ == "Ready"
    )
    if len(ready_conditions) != 1:
        raise ValueError("Cloud Run revision does not have one authoritative Ready condition")
    immutable_configuration = _decode_revision_configuration(value)
    configuration.validate_revision_configuration(immutable_configuration)
    service_resource = value.service
    if service_resource == configuration.target.service_name:
        service_resource = configuration.service_resource
    if service_resource != configuration.service_resource:
        raise ValueError("Cloud Run revision service is outside the configured target")
    return CloudRunRevisionState(
        target=configuration.target,
        revision=expected_revision,
        resource_name=value.name,
        service_resource=service_resource,
        uid=value.uid,
        etag=value.etag,
        generation=value.generation,
        observed_generation=value.observed_generation,
        reconciling=value.reconciling,
        ready_state=_decode_ready_condition(ready_conditions[0]),
        concurrency=value.max_instance_request_concurrency,
        configuration=immutable_configuration,
    )


def _decode_provider_revision_name(
    value: object,
    *,
    configuration: CloudRunTargetConfiguration,
) -> str:
    if type(value) is not str:
        raise TypeError("Cloud Run revision name is invalid")
    resource_prefix = f"{configuration.service_resource}/revisions/"
    revision = value.removeprefix(resource_prefix) if value.startswith(resource_prefix) else value
    if value != revision and "/" in revision:
        raise ValueError("Cloud Run revision resource is invalid")
    if configuration.revision_resource_name(revision) != f"{resource_prefix}{revision}":
        raise ValueError("Cloud Run revision is outside the configured service")
    return revision


def _decode_ready_condition(value: object) -> CloudRunReadyState:
    if type(value) is not run_v2.Condition or value.type_ != "Ready":
        raise ValueError("Cloud Run Ready condition is missing")
    if value.state == run_v2.Condition.State.CONDITION_SUCCEEDED:
        return CloudRunReadyState.READY
    if value.state in {
        run_v2.Condition.State.CONDITION_PENDING,
        run_v2.Condition.State.CONDITION_RECONCILING,
    }:
        return CloudRunReadyState.NOT_READY
    if value.state == run_v2.Condition.State.CONDITION_FAILED:
        return CloudRunReadyState.FAILED
    raise ValueError("Cloud Run Ready condition state is unknown")


def _decode_revision_configuration(
    value: run_v2.Revision,
) -> CloudRunRevisionConfiguration:
    provider = run_v2.Revision.pb(value)
    if (
        value.volumes
        or len(value.containers) != 1
        or not provider.HasField("scaling")
        or not provider.HasField("vpc_access")
        or not provider.HasField("timeout")
        or value.encryption_key
        or provider.HasField("service_mesh")
        or value.encryption_key_revocation_action
        or value.encryption_key_shutdown_duration.total_seconds() != 0
        or value.session_affinity
        or provider.HasField("node_selector")
        or value.gpu_zonal_redundancy_disabled
    ):
        raise ValueError("Cloud Run revision contains unsupported execution configuration")
    container = value.containers[0]
    container_provider = run_v2.Container.pb(container)
    if (
        container_provider.HasField("source_code")
        or container.env
        or container.volume_mounts
        or len(container.ports) != 1
        or container_provider.HasField("readiness_probe")
        or container.depends_on
        or container.base_image_uri
        or container_provider.HasField("build_info")
    ):
        raise ValueError("Cloud Run container contains unsupported execution configuration")
    limits = dict(container.resources.limits)
    if set(limits) != {"cpu", "memory"}:
        raise ValueError("Cloud Run container resources are not the closed supported set")
    timeout_seconds = value.timeout.total_seconds()
    if not timeout_seconds.is_integer():
        raise ValueError("Cloud Run revision timeout must use whole seconds")
    execution_environment = {
        run_v2.ExecutionEnvironment.EXECUTION_ENVIRONMENT_GEN1: (
            CloudRunExecutionEnvironment.GEN1
        ),
        run_v2.ExecutionEnvironment.EXECUTION_ENVIRONMENT_GEN2: (
            CloudRunExecutionEnvironment.GEN2
        ),
    }.get(value.execution_environment)
    if execution_environment is None:
        raise ValueError("Cloud Run revision execution environment is unknown")
    vpc_egress = {
        run_v2.VpcAccess.VpcEgress.ALL_TRAFFIC: CloudRunVpcEgress.ALL_TRAFFIC,
        run_v2.VpcAccess.VpcEgress.PRIVATE_RANGES_ONLY: (
            CloudRunVpcEgress.PRIVATE_RANGES_ONLY
        ),
    }.get(value.vpc_access.egress)
    if vpc_egress is None:
        raise ValueError("Cloud Run revision VPC egress is unknown")
    network_interfaces = tuple(
        CloudRunNetworkInterface(
            network=interface.network,
            subnetwork=interface.subnetwork,
            tags=tuple(sorted(set(interface.tags))),
        )
        for interface in value.vpc_access.network_interfaces
    )
    working_dir = container.working_dir or None
    connector = value.vpc_access.connector or None
    port = container.ports[0]
    return CloudRunRevisionConfiguration(
        image=container.image,
        service_account=value.service_account,
        execution_environment=execution_environment,
        timeout_seconds=int(timeout_seconds),
        concurrency=value.max_instance_request_concurrency,
        min_instance_count=value.scaling.min_instance_count,
        max_instance_count=value.scaling.max_instance_count,
        container_name=container.name,
        command=tuple(container.command),
        args=tuple(container.args),
        working_dir=working_dir,
        port_name=port.name,
        container_port=port.container_port,
        cpu_limit=limits["cpu"],
        memory_limit=limits["memory"],
        cpu_idle=container.resources.cpu_idle,
        startup_cpu_boost=container.resources.startup_cpu_boost,
        startup_probe=_decode_http_probe(container.startup_probe),
        liveness_probe=_decode_http_probe(container.liveness_probe),
        vpc_connector=connector,
        vpc_egress=vpc_egress,
        network_interfaces=network_interfaces,
    )


def _decode_http_probe(value: object) -> CloudRunHttpProbe:
    if type(value) is not run_v2.Probe:
        raise TypeError("Cloud Run probe response type is invalid")
    provider = run_v2.Probe.pb(value)
    if provider.WhichOneof("probe_type") != "http_get" or value.http_get.http_headers:
        raise ValueError("Cloud Run probe is not one header-free HTTP probe")
    return CloudRunHttpProbe(
        path=value.http_get.path,
        port=value.http_get.port,
        initial_delay_seconds=value.initial_delay_seconds,
        timeout_seconds=value.timeout_seconds,
        period_seconds=value.period_seconds,
        failure_threshold=value.failure_threshold,
    )


def _decode_traffic(
    value: run_v2.TrafficTarget,
    *,
    revision_prefix: str,
) -> CloudRunTrafficAllocation:
    if type(value) is not run_v2.TrafficTarget or value.type_ != _REVISION_ALLOCATION:
        raise ValueError("Cloud Run traffic target is not revision-bound")
    if not value.revision.startswith(revision_prefix):
        raise ValueError("Cloud Run traffic revision is outside the configured service")
    return CloudRunTrafficAllocation(
        revision=value.revision,
        percent=value.percent,
        tag=value.tag or None,
    )


def _decode_traffic_status(
    value: run_v2.TrafficTargetStatus,
    *,
    revision_prefix: str,
) -> CloudRunTrafficStatus:
    if type(value) is not run_v2.TrafficTargetStatus or value.type_ != _REVISION_ALLOCATION:
        raise ValueError("Cloud Run traffic status is not revision-bound")
    if not value.revision.startswith(revision_prefix):
        raise ValueError("Cloud Run traffic status revision is outside the configured service")
    return CloudRunTrafficStatus(
        revision=value.revision,
        percent=value.percent,
        tag=value.tag or None,
        uri=value.uri or None,
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


def _closed_readback(observed_etag: str | None = None) -> ReceiptReadbackResult:
    return ReceiptReadbackResult(state=None, observed_etag=observed_etag)


__all__ = [
    "CLOUD_RUN_OPERATION_TIMEOUT_SECONDS",
    "CLOUD_RUN_REFERENCE_SERVICE",
    "CLOUD_RUN_REGION",
    "CLOUD_RUN_RPC_TIMEOUT_SECONDS",
    "CloudRunV2Adapter",
    "CloudRunV2ReceiptReadback",
    "CloudRunV2SnapshotReader",
    "ReadOnlyServicesClientFactory",
    "RevisionsClientFactory",
    "ServicesClientFactory",
]
