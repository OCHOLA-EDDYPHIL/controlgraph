from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from functools import wraps
from threading import Event, Thread
from typing import Any, cast

import pytest
from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2
from root_v2_support import RootBundle, root_bundle, root_records

from controlgraph_canary.application.authority_store import (
    DirectReceiptCreate,
    StoredRecord,
)
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.cloud_run import (
    CLOUD_RUN_REVISION_CONFIGURATION_DOMAIN,
    CLOUD_RUN_REVISION_CONFIGURATION_V1,
    TARGET_CONFIGURATION_DOMAIN,
    TARGET_CONFIGURATION_V1,
    CloudRunExecutionEnvironment,
    CloudRunMutationOutcome,
    CloudRunMutationReason,
    CloudRunMutationResult,
    CloudRunReadError,
    CloudRunReadErrorCode,
    CloudRunReadyState,
    CloudRunTargetConfiguration,
    DeclaredRevision,
    TargetConfigurationProjection,
    cloud_run_revision_configuration_sha256,
    target_configuration_projection,
    target_configuration_sha256,
)
from controlgraph_canary.application.execution import (
    DefinitiveFreshClaimLeaseFactory,
    FinalAuthorityDenial,
    FinalMutationGate,
    FinalMutationResult,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.receipt_execution import (
    ReceiptMutationResult,
    ReceiptMutationStatus,
    ReceiptReadbackResult,
    map_cloud_run_mutation_result,
)
from controlgraph_canary.application.reference_target_reset import (
    REFERENCE_TARGET_RESET_CONFIRMATION,
    ReferenceTargetResetConfiguration,
    ReferenceTargetResetError,
    ReferenceTargetResetErrorCode,
    ReferenceTargetResetOutcome,
    ReferenceTargetResetRequest,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import (
    canonical_sha256,
    encode_base64url,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    CapabilityClaims,
    EpochChangeCause,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV2
from controlgraph_canary.contracts.storage import execution_receipt_logical_id
from controlgraph_canary.integrations.google.cloud_run import (
    CloudRunV2Adapter,
    CloudRunV2ReceiptReadback,
    CloudRunV2ReferenceTargetResetter,
    CloudRunV2SnapshotReader,
)

PROJECT_ID = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
SERVICE = "controlgraph-reference-target"
STABLE = f"{SERVICE}-stable-v9"
CANDIDATE = f"{SERVICE}-candidate-v9"
SERVICE_RESOURCE = f"projects/{PROJECT_ID}/locations/us-central1/services/{SERVICE}"
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
THREE_DIGEST = "3" * 64
KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)


def _route_policy(role: ServiceRole) -> RouteAuthenticationPolicy:
    caller_role = (
        CallerRole.RECOVERY_TASK_CALLER
        if role is ServiceRole.RECOVERY
        else CallerRole.EXECUTION_TASK_CALLER
    )
    account = (
        "cg-recovery-task-caller"
        if role is ServiceRole.RECOVERY
        else "cg-execution-task-caller"
    )
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=role,
        path=protected_path(role),
        audience=(
            f"https://controlgraph-{role.value}-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        caller=CallerBinding(
            role=caller_role,
            email=f"{account}@{PROJECT_ID}.iam.gserviceaccount.com",
            subject=SUBJECT,
        ),
    )
NOW = datetime(2026, 8, 19, 12, 3, tzinfo=UTC)
REFERENCE_IMAGE = (
    f"us-central1-docker.pkg.dev/{PROJECT_ID}/controlgraph-images/reference-target"
    f"@sha256:{'1' * 64}"
)
RESET_STABLE_IMAGE = (
    f"us-central1-docker.pkg.dev/{PROJECT_ID}/controlgraph-canary/reference-stable"
    f"@sha256:{'4' * 64}"
)
RESET_CANDIDATE_IMAGE = (
    f"us-central1-docker.pkg.dev/{PROJECT_ID}/controlgraph-canary/reference-candidate"
    f"@sha256:{'5' * 64}"
)
RESET_CANDIDATE_SAME_DIGEST = (
    f"us-central1-docker.pkg.dev/{PROJECT_ID}/controlgraph-canary/reference-candidate"
    f"@sha256:{'4' * 64}"
)
NETWORK_RESOURCE = f"projects/{PROJECT_ID}/global/networks/controlgraph"
SUBNETWORK_RESOURCE = (
    f"projects/{PROJECT_ID}/regions/us-central1/subnetworks/controlgraph"
)


def _async_test[**P](
    function: Callable[P, Coroutine[Any, Any, None]],
) -> Callable[P, None]:
    @wraps(function)
    def run(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(function(*args, **kwargs))

    return run


def _provider_error(error_type: type[Exception], detail: str) -> Exception:
    return error_type(detail)


def _target(**changes: str) -> TargetBinding:
    values = {
        "schema_version": "controlgraph.target-binding/v1",
        "project_id": PROJECT_ID,
        "region": "us-central1",
        "environment": "nonprod",
        "service_name": SERVICE,
    }
    values.update(changes)
    return TargetBinding(**values)  # type: ignore[arg-type]


def _configuration(
    *,
    target: TargetBinding | None = None,
    stable_revision: str = STABLE,
    candidate_revision: str = CANDIDATE,
    stable_concurrency: int = 8,
    candidate_concurrency: int = 8,
    network_resource: str | None = None,
    subnetwork_resource: str | None = None,
) -> CloudRunTargetConfiguration:
    configured_target = target or _target()
    return CloudRunTargetConfiguration(
        target=configured_target,
        stable_revision=stable_revision,
        candidate_revision=candidate_revision,
        stable_concurrency=stable_concurrency,
        candidate_concurrency=candidate_concurrency,
        network_resource=network_resource
        or (
            f"projects/{configured_target.project_id}/global/networks/controlgraph"
        ),
        subnetwork_resource=subnetwork_resource
        or (
            f"projects/{configured_target.project_id}/regions/{configured_target.region}/"
            "subnetworks/controlgraph"
        ),
    )


def _root(
    *,
    concurrency: int = 8,
    candidate_revision: str = CANDIDATE,
) -> RolloutRootV2:
    root, _, _, _ = root_records(
        target=_target(),
        stable_revision=STABLE,
        candidate_revision=candidate_revision,
        concurrency=concurrency,
        provider_etag="etag-before-7",
        candidate_revision_configuration_sha256=THREE_DIGEST,
    )
    return root


def _action_shape(action: CapabilityAction, concurrency: int) -> tuple[int, int, int | None]:
    if action is CapabilityAction.APPLY_CANARY:
        return 90, 10, None
    if action is CapabilityAction.PROMOTE_CANDIDATE:
        return 0, 100, None
    return 100, 0, concurrency


def _verified(
    *,
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
    root_concurrency: int = 8,
    candidate_revision: str = CANDIDATE,
) -> VerifiedMutation:
    root = _root(
        concurrency=root_concurrency,
        candidate_revision=candidate_revision,
    )
    role = (
        ServiceRole.RECOVERY if action is CapabilityAction.RECOVER_STABLE else ServiceRole.EXECUTOR
    )
    stable_percent, candidate_percent, concurrency = _action_shape(
        action,
        root_concurrency,
    )
    audience = f"https://controlgraph-{role.value}-123456789012.us-central1.run.app"
    claims = CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id=f"capability-{action.value.lower()}",
        issuer=f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com",
        subject=f"controlgraph-{role.value}@{PROJECT_ID}.iam.gserviceaccount.com",
        audience=audience,
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=action,
        stable_revision=root.content.rollout_plan.stable_revision,
        candidate_revision=root.content.rollout_plan.candidate_revision,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=concurrency,
        plan_sha256=canonical_sha256(root.content.rollout_plan),
        provider_etag=root.content.stable_snapshot.provider_etag,
        request_id=f"request-{action.value.lower()}",
        idempotency_key=f"intent-{action.value.lower()}",
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:02:00Z",
        not_before="2026-08-19T12:02:00Z",
        expires_at="2026-08-19T12:07:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=KEY_VERSION,
    )
    capability = SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-cloud-run-adapter-signature"),
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
        task_id=f"task-{action.value.lower()}",
        queue_region=root.content.target.region,
        handler_audience=audience,
        scheduled_at=claims.not_before,
        expires_at=claims.expires_at,
        capability=capability,
        intent=intent,
    )
    caller_role = (
        CallerRole.RECOVERY_TASK_CALLER
        if role is ServiceRole.RECOVERY
        else CallerRole.EXECUTION_TASK_CALLER
    )
    caller = AuthenticationContext(
        role=caller_role,
        email=(
            f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
            if role is ServiceRole.RECOVERY
            else f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
        subject="123456789012345678901",
        issuer="https://accounts.google.com",
        audience=audience,
        issued_at=int(datetime(2026, 8, 19, 12, 0, tzinfo=UTC).timestamp()),
        expires_at=int(datetime(2026, 8, 19, 13, 0, tzinfo=UTC).timestamp()),
    )
    return VerifiedMutation(
        request=request,
        root=root,
        lineage_anchor=root_records(
            target=_target(),
            stable_revision=STABLE,
            candidate_revision=candidate_revision,
            concurrency=root_concurrency,
            provider_etag="etag-before-7",
            candidate_revision_configuration_sha256=THREE_DIGEST,
        )[1],
        caller=caller,
        capability_sha256=canonical_sha256(capability),
        claims_sha256=capability.claims_sha256,
        earliest_lineage_issued_at=int(datetime(2026, 8, 19, 12, 2, tzinfo=UTC).timestamp()),
    )


def _binding(verified: VerifiedMutation) -> MutationBinding:
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
        expected_poststate_sha256=THREE_DIGEST,
    )


def _claimed(verified: VerifiedMutation) -> StoredRecord[ExecutionReceipt]:
    intent = verified.request.intent
    binding = _binding(verified)
    receipt = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(intent.target, intent.idempotency_key),
        request_id=intent.request_id,
        idempotency_key=intent.idempotency_key,
        capability_sha256=verified.capability_sha256,
        mutation_sha256=mutation_identity(binding),
        plan_sha256=intent.plan_sha256,
        expected_poststate_sha256=THREE_DIGEST,
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
        created_at="2026-08-19T12:02:01Z",
        updated_at="2026-08-19T12:02:01Z",
        evidence_ids=(),
    )
    return StoredRecord(receipt, 0)


def _snapshot(root: RolloutRootV2) -> RootBundle:
    generated_root, anchor, claim, authority = root_records(
        target=root.content.target,
        stable_revision=root.content.rollout_plan.stable_revision,
        candidate_revision=root.content.rollout_plan.candidate_revision,
        concurrency=root.content.rollout_plan.concurrency,
        service_generation=root.content.stable_snapshot.service_generation,
        provider_etag=root.content.stable_snapshot.provider_etag,
        baseline_configuration_sha256=(
            root.content.stable_snapshot.configuration_sha256
        ),
        stable_revision_configuration_sha256=(
            root.content.rollout_plan.stable_revision_configuration_sha256
        ),
        candidate_revision_configuration_sha256=(
            root.content.rollout_plan.candidate_revision_configuration_sha256
        ),
    )
    assert generated_root == root
    return root_bundle(
        root=root,
        anchor=anchor,
        claim=claim,
        authority=authority,
    )


def _revoked_snapshot(root: RolloutRootV2) -> RootBundle:
    snapshot = _snapshot(root)
    authority = snapshot.authority.value.model_copy(
        update={
            "current_epoch": 2,
            "previous_epoch": 1,
            "revision": 1,
            "cause": EpochChangeCause.OPERATOR_REVOCATION,
            "changed_by": "operator@example.test",
            "request_id": "request-revoke-during-client-init",
            "evidence_id": "evidence-revoke-during-client-init",
            "changed_at": "2026-08-19T12:02:30Z",
        }
    )
    return replace(snapshot, authority=StoredRecord(authority, 1))


class _Reader:
    def __init__(self, root: RolloutRootV2) -> None:
        self.target = root.content.target
        self.snapshot = _snapshot(root)

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootBundle | None:
        assert root_id == self.snapshot.root.value.root_id
        return self.snapshot


@dataclass
class _ProviderOperation:
    name: str


class _FakeOperation:
    def __init__(self, result: object, *, name: str = "operations/update-traffic-1") -> None:
        self.operation = _ProviderOperation(name)
        self.result_value = result
        self.calls: list[float | None] = []

    async def result(self, timeout: float | None = None) -> object:
        self.calls.append(timeout)
        if isinstance(self.result_value, BaseException):
            raise self.result_value
        return self.result_value


class _FakeServicesClient:
    def __init__(
        self,
        *,
        service: object | None = None,
        update: object | None = None,
    ) -> None:
        self.service = service if service is not None else _service()
        self.update = update if update is not None else _FakeOperation(_service())
        self.get_calls: list[tuple[run_v2.GetServiceRequest, object | None, float]] = []
        self.update_calls: list[tuple[run_v2.UpdateServiceRequest, object | None, float]] = []

    async def get_service(
        self,
        request: run_v2.GetServiceRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> run_v2.Service:
        self.get_calls.append((request, retry, timeout))
        if isinstance(self.service, BaseException):
            raise self.service
        return cast(run_v2.Service, self.service)

    async def update_service(
        self,
        request: run_v2.UpdateServiceRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> _FakeOperation:
        self.update_calls.append((request, retry, timeout))
        if isinstance(self.update, BaseException):
            raise self.update
        return cast(_FakeOperation, self.update)


class _GetOnlyServicesClient:
    def __init__(self, *services: object) -> None:
        self.services = list(services) or [_service()]
        self.get_calls: list[tuple[run_v2.GetServiceRequest, object | None, float]] = []

    async def get_service(
        self,
        request: run_v2.GetServiceRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> run_v2.Service:
        self.get_calls.append((request, retry, timeout))
        response = self.services.pop(0) if len(self.services) > 1 else self.services[0]
        if isinstance(response, BaseException):
            raise response
        return cast(run_v2.Service, response)


class _ResetServicesClient:
    def __init__(self, services: list[object], *, update: object) -> None:
        self.services = services
        self.update = update
        self.get_calls: list[tuple[run_v2.GetServiceRequest, object | None, float]] = []
        self.update_calls: list[tuple[run_v2.UpdateServiceRequest, object | None, float]] = []

    async def get_service(
        self,
        request: run_v2.GetServiceRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> run_v2.Service:
        self.get_calls.append((request, retry, timeout))
        if not self.services:
            raise AssertionError("unexpected reset service read")
        response = self.services.pop(0)
        if isinstance(response, BaseException):
            raise response
        return cast(run_v2.Service, response)

    async def update_service(
        self,
        request: run_v2.UpdateServiceRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> _FakeOperation:
        self.update_calls.append((request, retry, timeout))
        if isinstance(self.update, BaseException):
            raise self.update
        return cast(_FakeOperation, self.update)


class _FakeRevisionsClient:
    def __init__(
        self,
        *,
        concurrency: int = 8,
        stable_image: str = REFERENCE_IMAGE,
        candidate_image: str = REFERENCE_IMAGE,
        memory_limit: str = "512Mi",
    ) -> None:
        self.responses = {
            f"{SERVICE_RESOURCE}/revisions/{STABLE}": _revision(
                STABLE,
                concurrency,
                image=stable_image,
                memory_limit=memory_limit,
            ),
            f"{SERVICE_RESOURCE}/revisions/{CANDIDATE}": _revision(
                CANDIDATE,
                concurrency,
                image=candidate_image,
                memory_limit=memory_limit,
            ),
        }
        self.calls: list[tuple[run_v2.GetRevisionRequest, object | None, float]] = []

    async def get_revision(
        self,
        request: run_v2.GetRevisionRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> run_v2.Revision:
        self.calls.append((request, retry, timeout))
        result = self.responses[request.name]
        if isinstance(result, BaseException):
            raise result
        return result


def _service(
    stable_percent: int = 90,
    candidate_percent: int = 10,
    *,
    resource_name: str = SERVICE_RESOURCE,
    stable_revision: str = STABLE,
    candidate_revision: str = CANDIDATE,
    template_revision: str = CANDIDATE,
    latest_created_revision: str | None = None,
    latest_ready_revision: str | None = None,
    concurrency: int = 8,
    etag: str = "etag-after-8",
    ready_state: run_v2.Condition.State = run_v2.Condition.State.CONDITION_SUCCEEDED,
    traffic_tags: tuple[str, str] = ("stable", "candidate"),
    status_tags: tuple[str, str] = ("stable", "candidate"),
    status_stable_percent: int | None = None,
    status_candidate_percent: int | None = None,
    generation: int = 8,
    observed_generation: int | None = None,
) -> run_v2.Service:
    return run_v2.Service(
        name=resource_name,
        uid="synthetic-service-uid",
        generation=generation,
        observed_generation=(
            generation if observed_generation is None else observed_generation
        ),
        etag=etag,
        reconciling=False,
        terminal_condition=run_v2.Condition(type_="Ready", state=ready_state),
        conditions=[run_v2.Condition(type_="Ready", state=ready_state)],
        latest_ready_revision=latest_ready_revision or candidate_revision,
        latest_created_revision=latest_created_revision or candidate_revision,
        template=run_v2.RevisionTemplate(
            revision=template_revision,
            max_instance_request_concurrency=concurrency,
        ),
        traffic=[
            run_v2.TrafficTarget(
                type_=(run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION),
                revision=stable_revision,
                percent=(
                    stable_percent
                    if status_stable_percent is None
                    else status_stable_percent
                ),
                tag=traffic_tags[0],
            ),
            run_v2.TrafficTarget(
                type_=(run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION),
                revision=candidate_revision,
                percent=(
                    candidate_percent
                    if status_candidate_percent is None
                    else status_candidate_percent
                ),
                tag=traffic_tags[1],
            ),
        ],
        traffic_statuses=[
            run_v2.TrafficTargetStatus(
                type_=(run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION),
                revision=stable_revision,
                percent=stable_percent,
                tag=status_tags[0],
                uri=(
                    "https://stable.example.test" if status_tags[0] else ""
                ),
            ),
            run_v2.TrafficTargetStatus(
                type_=(run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION),
                revision=candidate_revision,
                percent=candidate_percent,
                tag=status_tags[1],
                uri=(
                    "https://candidate.example.test" if status_tags[1] else ""
                ),
            ),
        ],
        uri="https://service.example.test",
    )


def _revision(
    revision: str,
    concurrency: int = 8,
    *,
    ready_state: run_v2.Condition.State = run_v2.Condition.State.CONDITION_SUCCEEDED,
    image: str = REFERENCE_IMAGE,
    env: list[run_v2.EnvVar] | None = None,
    volumes: list[run_v2.Volume] | None = None,
    containers: list[run_v2.Container] | None = None,
    service_account: str | None = None,
    memory_limit: str = "512Mi",
    network_resource: str = NETWORK_RESOURCE,
    subnetwork_resource: str = SUBNETWORK_RESOURCE,
    labels: dict[str, str] | None = None,
    annotations: dict[str, str] | None = None,
) -> run_v2.Revision:
    container = run_v2.Container(
        name="reference-target",
        image=image,
        env=[] if env is None else env,
        ports=[run_v2.ContainerPort(name="http1", container_port=8080)],
        resources=run_v2.ResourceRequirements(
            limits={"cpu": "1", "memory": memory_limit},
            cpu_idle=True,
            startup_cpu_boost=False,
        ),
        startup_probe=run_v2.Probe(
            initial_delay_seconds=0,
            timeout_seconds=2,
            period_seconds=5,
            failure_threshold=12,
            http_get=run_v2.HTTPGetAction(path="/healthz", port=8080),
        ),
        liveness_probe=run_v2.Probe(
            initial_delay_seconds=5,
            timeout_seconds=2,
            period_seconds=10,
            failure_threshold=3,
            http_get=run_v2.HTTPGetAction(path="/healthz", port=8080),
        ),
    )
    return run_v2.Revision(
        name=f"{SERVICE_RESOURCE}/revisions/{revision}",
        service=SERVICE_RESOURCE,
        uid=f"synthetic-{revision}-uid",
        labels={} if labels is None else labels,
        annotations={} if annotations is None else annotations,
        etag=f"etag-{revision}",
        generation=1,
        observed_generation=1,
        reconciling=False,
        conditions=[run_v2.Condition(type_="Ready", state=ready_state)],
        max_instance_request_concurrency=concurrency,
        service_account=service_account
        or f"controlgraph-reference@{PROJECT_ID}.iam.gserviceaccount.com",
        execution_environment=run_v2.ExecutionEnvironment.EXECUTION_ENVIRONMENT_GEN2,
        timeout="5s",
        scaling=run_v2.RevisionScaling(min_instance_count=0, max_instance_count=1),
        containers=[container] if containers is None else containers,
        volumes=[] if volumes is None else volumes,
        vpc_access=run_v2.VpcAccess(
            egress=run_v2.VpcAccess.VpcEgress.ALL_TRAFFIC,
            network_interfaces=[
                run_v2.VpcAccess.NetworkInterface(
                    network=network_resource,
                    subnetwork=subnetwork_resource,
                )
            ],
        ),
    )


def _adapter(
    services: _FakeServicesClient,
    *,
    revisions: _FakeRevisionsClient | None = None,
    role: ServiceRole = ServiceRole.EXECUTOR,
    configuration: CloudRunTargetConfiguration | None = None,
) -> CloudRunV2Adapter:
    revision_client = revisions or _FakeRevisionsClient()
    return CloudRunV2Adapter(
        configuration=configuration or _configuration(),
        service_role=role,
        configured_project_id=PROJECT_ID,
        services_client_factory=lambda: services,
        revisions_client_factory=lambda: revision_client,
    )


def _snapshot_reader(
    services: _FakeServicesClient,
    *,
    revisions: _FakeRevisionsClient | None = None,
    role: ServiceRole = ServiceRole.VERIFIER,
) -> CloudRunV2SnapshotReader:
    revision_client = revisions or _FakeRevisionsClient()
    return CloudRunV2SnapshotReader(
        configuration=_configuration(),
        service_role=role,
        configured_project_id=PROJECT_ID,
        services_client_factory=lambda: services,
        revisions_client_factory=lambda: revision_client,
    )


def _receipt_readback(
    services: _GetOnlyServicesClient,
    *,
    configuration: CloudRunTargetConfiguration | None = None,
) -> CloudRunV2ReceiptReadback:
    return CloudRunV2ReceiptReadback(
        configuration=configuration or _configuration(),
        configured_project_id=PROJECT_ID,
        services_client_factory=lambda: services,
    )


def _reset_configuration(**changes: str) -> ReferenceTargetResetConfiguration:
    values = {
        "project_id": PROJECT_ID,
        "stable_image": RESET_STABLE_IMAGE,
        "candidate_image": RESET_CANDIDATE_IMAGE,
        "network_resource": NETWORK_RESOURCE,
        "subnetwork_resource": SUBNETWORK_RESOURCE,
    }
    values.update(changes)
    return ReferenceTargetResetConfiguration(**values)


def _resetter(
    services: _ResetServicesClient,
    *,
    revisions: _FakeRevisionsClient | None = None,
    configuration: ReferenceTargetResetConfiguration | None = None,
) -> CloudRunV2ReferenceTargetResetter:
    revision_client = revisions or _FakeRevisionsClient(
        stable_image=RESET_STABLE_IMAGE,
        candidate_image=RESET_CANDIDATE_IMAGE,
    )
    return CloudRunV2ReferenceTargetResetter(
        configuration=configuration or _reset_configuration(),
        services_client_factory=lambda: services,
        revisions_client_factory=lambda: revision_client,
    )


def _reset_request(etag: str = "etag-before-reset") -> ReferenceTargetResetRequest:
    return ReferenceTargetResetRequest(
        expected_etag=etag,
        confirmation=REFERENCE_TARGET_RESET_CONFIRMATION,
    )


async def _execute(
    adapter: CloudRunV2Adapter,
    *,
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
    root_concurrency: int = 8,
    candidate_revision: str = CANDIDATE,
) -> CloudRunMutationResult:
    verified = _verified(
        action=action,
        root_concurrency=root_concurrency,
        candidate_revision=candidate_revision,
    )
    proof = DirectReceiptCreate._from_direct_store_create(
        _claimed(verified),
        _binding(verified),
    )
    lease = DefinitiveFreshClaimLeaseFactory.mint(proof)
    result = await FinalMutationGate(
        authority_reader=_Reader(verified.root),
        adapter=adapter,
        route_policy=_route_policy(adapter.service_role),
        clock=lambda: NOW,
    ).execute(lease, verified)
    assert type(result) is FinalMutationResult
    assert type(result.result) is CloudRunMutationResult
    return result.result


@pytest.mark.parametrize(
    ("target", "configured_project", "message"),
    [
        (_target(project_id="other-project"), PROJECT_ID, "configured ControlGraph project"),
        (_target(region="europe-west1"), PROJECT_ID, "must use us-central1"),
        (
            _target(service_name="other-reference-target"),
            PROJECT_ID,
            "belong to the configured service",
        ),
        (_target(), "shared-project", "configured ControlGraph project"),
    ],
)
def test_constructor_rejects_unbound_coordinates(
    target: TargetBinding,
    configured_project: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CloudRunV2Adapter(
            configuration=_configuration(target=target),
            service_role=ServiceRole.EXECUTOR,
            configured_project_id=configured_project,
            services_client_factory=lambda: _FakeServicesClient(),
            revisions_client_factory=lambda: _FakeRevisionsClient(),
        )


def test_constructor_rejects_undeclared_revision_or_concurrency_shapes() -> None:
    with pytest.raises(ValueError, match="belong to the configured service"):
        _configuration(stable_revision="other-stable")
    with pytest.raises(ValueError, match="share the approved concurrency"):
        _adapter(
            _FakeServicesClient(),
            configuration=_configuration(candidate_concurrency=9),
        )
    other_target = _target(service_name="other-reference-target")
    with pytest.raises(ValueError, match="reference service"):
        _adapter(
            _FakeServicesClient(),
            configuration=_configuration(
                target=other_target,
                stable_revision="other-reference-target-stable-v1",
                candidate_revision="other-reference-target-candidate-v1",
            ),
        )


@_async_test
async def test_exact_service_and_revision_reads_use_only_fixed_resources() -> None:
    services = _FakeServicesClient()
    revisions = _FakeRevisionsClient()
    adapter = _adapter(services, revisions=revisions)

    target = await adapter.read_target()

    assert target.service.resource_name == SERVICE_RESOURCE
    assert target.service.etag == "etag-after-8"
    assert target.service.generation == 8
    assert target.service.observed_generation == 8
    assert target.service.ready_state is CloudRunReadyState.READY
    assert [(item.revision, item.percent) for item in target.service.traffic] == [
        (STABLE, 90),
        (CANDIDATE, 10),
    ]
    assert target.stable_revision.revision == STABLE
    assert target.candidate_revision.revision == CANDIDATE
    assert target.stable_revision.concurrency == 8
    assert target.candidate_revision.concurrency == 8
    assert target.stable_revision.ready_state is CloudRunReadyState.READY
    assert target.stable_revision.configuration.image == REFERENCE_IMAGE
    assert (
        target.stable_revision.configuration.execution_environment
        is CloudRunExecutionEnvironment.GEN2
    )
    assert (
        CLOUD_RUN_REVISION_CONFIGURATION_V1
        == "controlgraph.cloud-run-revision-configuration/v1"
    )
    assert CLOUD_RUN_REVISION_CONFIGURATION_DOMAIN == (
        b"controlgraph.cloud-run-revision-configuration-sha256/v1\0"
    )
    assert [(call[0].name, call[1]) for call in services.get_calls] == [(SERVICE_RESOURCE, None)]
    assert {call[0].name for call in revisions.calls} == {
        f"{SERVICE_RESOURCE}/revisions/{STABLE}",
        f"{SERVICE_RESOURCE}/revisions/{CANDIDATE}",
    }
    with pytest.raises(ValueError, match="configured service"):
        await adapter.read_revision("stable")
    assert len(revisions.calls) == 2


@_async_test
async def test_service_read_preserves_a_provider_quoted_etag() -> None:
    quoted_etag = '"' + "A" * 151 + '"'
    service = _service(
        etag=quoted_etag,
        latest_ready_revision=(
            f"{SERVICE_RESOURCE}/revisions/controlgraph-reference-target-stable-v1"
        ),
        latest_created_revision=f"{SERVICE_RESOURCE}/revisions/{CANDIDATE}",
    )
    revisions = _FakeRevisionsClient()
    for response in revisions.responses.values():
        response.service = SERVICE
        response.etag = quoted_etag

    state = await _adapter(
        _FakeServicesClient(service=service),
        revisions=revisions,
    ).read_target()

    assert state.service.etag == quoted_etag
    assert state.service.latest_ready_revision == (
        "controlgraph-reference-target-stable-v1"
    )
    assert state.service.latest_created_revision == CANDIDATE
    assert state.stable_revision.service_resource == SERVICE_RESOURCE
    assert state.stable_revision.etag == quoted_etag
    assert state.candidate_revision.service_resource == SERVICE_RESOURCE
    assert state.candidate_revision.etag == quoted_etag


@_async_test
async def test_verifier_snapshot_reader_has_only_exact_read_operations() -> None:
    services = _FakeServicesClient(service=_service(100, 0))
    revisions = _FakeRevisionsClient()
    reader = _snapshot_reader(services, revisions=revisions)

    service = await reader.read_service()
    revision = await reader.read_revision(STABLE)

    assert reader.service_role is ServiceRole.VERIFIER
    assert reader.reader_identity == (
        f"controlgraph-verifier@{PROJECT_ID}.iam.gserviceaccount.com"
    )
    assert service.target == _target()
    assert revision.revision == STABLE
    assert services.update_calls == []
    public_callables = {
        name
        for name in dir(reader)
        if not name.startswith("_") and callable(getattr(reader, name))
    }
    assert public_callables == {"read_revision", "read_service", "read_target"}
    assert not hasattr(reader, "mutate")


@_async_test
async def test_snapshot_reader_gets_the_exact_positive_traffic_revision() -> None:
    traffic_revision = f"{SERVICE}-retained-v0"
    services = _FakeServicesClient(
        service=_service(100, 0, stable_revision=traffic_revision)
    )
    revisions = _FakeRevisionsClient()
    resource = f"{SERVICE_RESOURCE}/revisions/{traffic_revision}"
    revisions.responses[resource] = _revision(traffic_revision)
    reader = _snapshot_reader(services, revisions=revisions)

    service = await reader.read_service()
    positive = next(allocation for allocation in service.traffic if allocation.percent > 0)
    revision = await reader.read_revision(positive.revision)

    assert positive.revision == traffic_revision
    assert revision.revision == traffic_revision
    assert [call[0].name for call in revisions.calls] == [resource]


@_async_test
async def test_receipt_readback_uses_a_fresh_exact_get_and_provider_state() -> None:
    services = _GetOnlyServicesClient(
        _service(90, 10, concurrency=8, etag="etag-readback-1"),
        _service(80, 20, concurrency=9, etag="etag-readback-2"),
    )
    readback = _receipt_readback(services)
    expected = target_configuration_projection(
        _verified().request.intent,
        expected_concurrency=8,
    )

    first = await readback.readback(expected)
    second = await readback.readback(expected)

    assert first == ReceiptReadbackResult(
        state=expected,
        observed_etag="etag-readback-1",
    )
    assert second == ReceiptReadbackResult(
        state=replace(
            expected,
            stable_percent=80,
            candidate_percent=20,
            concurrency=9,
        ),
        observed_etag="etag-readback-2",
    )
    assert second.state != expected
    assert [(call[0].name, call[1], call[2]) for call in services.get_calls] == [
        (SERVICE_RESOURCE, None, 5.0),
        (SERVICE_RESOURCE, None, 5.0),
    ]
    public_callables = {
        name
        for name in dir(readback)
        if not name.startswith("_") and callable(getattr(readback, name))
    }
    assert public_callables == {"readback"}
    assert not hasattr(readback, "mutate")
    assert not hasattr(readback, "update_service")


@pytest.mark.parametrize(
    "expected",
    [
        replace(
            target_configuration_projection(
                _verified().request.intent,
                expected_concurrency=8,
            ),
            target=_target(project_id="controlgraph-canary-d4e5f6"),
        ),
        replace(
            target_configuration_projection(
                _verified().request.intent,
                expected_concurrency=8,
            ),
            stable_revision=f"{SERVICE}-stable-v10",
        ),
        replace(
            target_configuration_projection(
                _verified().request.intent,
                expected_concurrency=8,
            ),
            candidate_revision=f"{SERVICE}-candidate-v10",
        ),
        replace(
            target_configuration_projection(
                _verified().request.intent,
                expected_concurrency=8,
            ),
            concurrency=9,
        ),
    ],
)
@_async_test
async def test_receipt_readback_rejects_unbound_expectations_without_provider_access(
    expected: TargetConfigurationProjection,
) -> None:
    services = _GetOnlyServicesClient()

    observation = await _receipt_readback(services).readback(expected)

    assert observation == ReceiptReadbackResult(state=None, observed_etag=None)
    assert services.get_calls == []


@pytest.mark.parametrize(
    ("provider_response", "observed_etag"),
    [
        (RuntimeError("synthetic unavailable detail"), None),
        (object(), None),
        (
            _service(
                ready_state=cast(
                    run_v2.Condition.State,
                    run_v2.Condition.State.CONDITION_PENDING,
                )
            ),
            "etag-after-8",
        ),
        (
            _service(stable_revision=f"{SERVICE}-unapproved-v2"),
            "etag-after-8",
        ),
        (
            _service(status_stable_percent=100, status_candidate_percent=0),
            "etag-after-8",
        ),
        (
            _service(template_revision=f"{SERVICE}-unapproved-v2"),
            "etag-after-8",
        ),
        (
            _service(latest_created_revision=f"{SERVICE}-unapproved-v2"),
            "etag-after-8",
        ),
        (
            _service(latest_ready_revision=f"{SERVICE}-unapproved-v2"),
            "etag-after-8",
        ),
    ],
)
@_async_test
async def test_receipt_readback_fails_closed_on_unavailable_or_unsettled_state(
    provider_response: object,
    observed_etag: str | None,
) -> None:
    services = _GetOnlyServicesClient(provider_response)
    expected = target_configuration_projection(
        _verified().request.intent,
        expected_concurrency=8,
    )

    observation = await _receipt_readback(services).readback(expected)

    assert observation == ReceiptReadbackResult(
        state=None,
        observed_etag=observed_etag,
    )
    assert len(services.get_calls) == 1


@_async_test
async def test_receipt_readback_propagates_cancellation() -> None:
    services = _GetOnlyServicesClient(asyncio.CancelledError())
    expected = target_configuration_projection(
        _verified().request.intent,
        expected_concurrency=8,
    )

    with pytest.raises(asyncio.CancelledError):
        await _receipt_readback(services).readback(expected)

    assert len(services.get_calls) == 1


@pytest.mark.parametrize(
    ("target", "configured_project", "message"),
    [
        (_target(project_id="other-project"), PROJECT_ID, "configured ControlGraph project"),
        (_target(region="europe-west1"), PROJECT_ID, "must use us-central1"),
        (
            _target(service_name="other-reference-target"),
            PROJECT_ID,
            "belong to the configured service",
        ),
        (_target(), "shared-project", "configured ControlGraph project"),
    ],
)
def test_receipt_readback_constructor_rejects_unbound_coordinates(
    target: TargetBinding,
    configured_project: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CloudRunV2ReceiptReadback(
            configuration=_configuration(target=target),
            configured_project_id=configured_project,
            services_client_factory=lambda: _GetOnlyServicesClient(),
        )


def test_receipt_readback_requires_one_approved_concurrency() -> None:
    with pytest.raises(ValueError, match="share the approved concurrency"):
        _receipt_readback(
            _GetOnlyServicesClient(),
            configuration=_configuration(candidate_concurrency=9),
        )


@pytest.mark.parametrize("role", [ServiceRole.EXECUTOR, ServiceRole.RECOVERY])
def test_snapshot_reader_rejects_mutation_roles(role: ServiceRole) -> None:
    with pytest.raises(ValueError, match="verifier role"):
        _snapshot_reader(_FakeServicesClient(), role=role)


@_async_test
async def test_read_failures_are_sanitized_and_corrupt_state_is_rejected() -> None:
    raw = "synthetic raw provider detail that must not escape"
    missing = _adapter(_FakeServicesClient(service=_provider_error(api_exceptions.NotFound, raw)))
    with pytest.raises(CloudRunReadError) as missing_error:
        await missing.read_service()
    assert missing_error.value.code is CloudRunReadErrorCode.NOT_FOUND
    assert raw not in str(missing_error.value)

    unavailable = _adapter(_FakeServicesClient(service=RuntimeError(raw)))
    with pytest.raises(CloudRunReadError) as unavailable_error:
        await unavailable.read_service()
    assert unavailable_error.value.code is CloudRunReadErrorCode.UNAVAILABLE
    assert raw not in str(unavailable_error.value)

    corrupt = _adapter(
        _FakeServicesClient(
            service=_service(resource_name=SERVICE_RESOURCE.replace(SERVICE, "other"))
        )
    )
    with pytest.raises(CloudRunReadError) as corrupt_error:
        await corrupt.read_service()
    assert corrupt_error.value.code is CloudRunReadErrorCode.CORRUPT_RESPONSE


@pytest.mark.parametrize(
    ("ready_state", "expected"),
    [
        (run_v2.Condition.State.CONDITION_PENDING, CloudRunReadyState.NOT_READY),
        (run_v2.Condition.State.CONDITION_RECONCILING, CloudRunReadyState.NOT_READY),
        (run_v2.Condition.State.CONDITION_FAILED, CloudRunReadyState.FAILED),
    ],
)
@_async_test
async def test_revision_read_decodes_authoritative_ready_condition(
    ready_state: run_v2.Condition.State,
    expected: CloudRunReadyState,
) -> None:
    revisions = _FakeRevisionsClient()
    revisions.responses[f"{SERVICE_RESOURCE}/revisions/{STABLE}"] = _revision(
        STABLE,
        ready_state=ready_state,
    )

    state = await _adapter(_FakeServicesClient(), revisions=revisions).read_revision(STABLE)

    assert state.ready_state is expected


@pytest.mark.parametrize(
    "revision",
    [
        _revision(STABLE, ready_state=run_v2.Condition.State.STATE_UNSPECIFIED),
        _revision(STABLE, image="example.test/reference-target:latest"),
        _revision(STABLE, env=[run_v2.EnvVar(name="PLAIN", value="unsupported")]),
        _revision(
            STABLE,
            env=[
                run_v2.EnvVar(
                    name="SECRET",
                    value_source=run_v2.EnvVarSource(
                        secret_key_ref=run_v2.SecretKeySelector(
                            secret="synthetic-secret",
                            version="1",
                        )
                    ),
                )
            ],
        ),
        _revision(STABLE, volumes=[run_v2.Volume(name="unsupported-volume")]),
        _revision(
            STABLE,
            containers=[
                run_v2.Container(name="first", image=REFERENCE_IMAGE),
                run_v2.Container(name="second", image=REFERENCE_IMAGE),
            ],
        ),
        _revision(
            STABLE,
            service_account=(
                f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"
            ),
        ),
        _revision(
            STABLE,
            network_resource=(
                "projects/controlgraph-canary-b2c3d4/global/networks/controlgraph"
            ),
        ),
        _revision(
            STABLE,
            subnetwork_resource=(
                "projects/controlgraph-canary-b2c3d4/regions/us-central1/"
                "subnetworks/controlgraph"
            ),
        ),
    ],
)
@_async_test
async def test_revision_read_rejects_unknown_readiness_or_unsupported_configuration(
    revision: run_v2.Revision,
) -> None:
    revisions = _FakeRevisionsClient()
    revisions.responses[f"{SERVICE_RESOURCE}/revisions/{STABLE}"] = revision

    with pytest.raises(CloudRunReadError) as failure:
        await _adapter(_FakeServicesClient(), revisions=revisions).read_revision(STABLE)

    assert failure.value.code is CloudRunReadErrorCode.CORRUPT_RESPONSE


@_async_test
async def test_revision_configuration_digest_excludes_provider_display_metadata() -> None:
    first_revisions = _FakeRevisionsClient()
    second_revisions = _FakeRevisionsClient()
    first_provider_revision = _revision(
        STABLE,
        labels={"display": "first"},
        annotations={"display.example/annotation": "first"},
    )
    first_provider_revision.create_time = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
    first_provider_revision.update_time = datetime(2026, 8, 19, 12, 1, tzinfo=UTC)
    first_provider_revision.log_uri = "https://console.example.test/first"
    first_provider_revision.creator = "first@example.test"
    second_provider_revision = _revision(
        STABLE,
        labels={"display": "second"},
        annotations={"display.example/annotation": "second"},
    )
    second_provider_revision.create_time = datetime(2026, 8, 19, 13, 0, tzinfo=UTC)
    second_provider_revision.update_time = datetime(2026, 8, 19, 13, 1, tzinfo=UTC)
    second_provider_revision.log_uri = "https://console.example.test/second"
    second_provider_revision.creator = "second@example.test"
    first_revisions.responses[
        f"{SERVICE_RESOURCE}/revisions/{STABLE}"
    ] = first_provider_revision
    second_revisions.responses[
        f"{SERVICE_RESOURCE}/revisions/{STABLE}"
    ] = second_provider_revision

    first = await _adapter(
        _FakeServicesClient(), revisions=first_revisions
    ).read_revision(STABLE)
    second = await _adapter(
        _FakeServicesClient(), revisions=second_revisions
    ).read_revision(STABLE)

    assert first.configuration == second.configuration
    assert cloud_run_revision_configuration_sha256(first.configuration) == (
        cloud_run_revision_configuration_sha256(second.configuration)
    )


@pytest.mark.parametrize(
    "service",
    [
        _service(candidate_revision="unrelated-service-candidate-v1"),
        _service(stable_percent=80, candidate_percent=10),
        _service(ready_state=run_v2.Condition.State.STATE_UNSPECIFIED),
    ],
)
@_async_test
async def test_read_rejects_unbound_traffic_or_unknown_readiness(
    service: run_v2.Service,
) -> None:
    adapter = _adapter(_FakeServicesClient(service=service))
    with pytest.raises(CloudRunReadError) as error:
        await adapter.read_service()
    assert error.value.code is CloudRunReadErrorCode.CORRUPT_RESPONSE


@_async_test
async def test_service_read_ignores_display_aliases_and_decodes_not_ready_states() -> None:
    services = _FakeServicesClient(
        service=_service(
            candidate_revision=f"{SERVICE}-new-display-v2",
            template_revision=f"{SERVICE}-template-display-v3",
            concurrency=99,
            traffic_tags=("", "renamed"),
            status_tags=("different", ""),
            ready_state=run_v2.Condition.State.CONDITION_FAILED,
        )
    )

    state = await _adapter(services).read_service()

    assert state.ready_state is CloudRunReadyState.FAILED
    assert state.template_concurrency == 99
    assert {allocation.revision: allocation.tag for allocation in state.traffic} == {
        STABLE: None,
        f"{SERVICE}-new-display-v2": "renamed",
    }
    assert {
        allocation.revision: allocation.tag for allocation in state.traffic_statuses
    } == {
        STABLE: "different",
        f"{SERVICE}-new-display-v2": None,
    }


@pytest.mark.parametrize(
    ("action", "role", "stable_percent", "candidate_percent"),
    [
        (CapabilityAction.APPLY_CANARY, ServiceRole.EXECUTOR, 90, 10),
        (CapabilityAction.PROMOTE_CANDIDATE, ServiceRole.EXECUTOR, 0, 100),
    ],
)
@_async_test
async def test_mutation_uses_one_traffic_only_conditional_request(
    action: CapabilityAction,
    role: ServiceRole,
    stable_percent: int,
    candidate_percent: int,
) -> None:
    response = _service(stable_percent, candidate_percent)
    operation = _FakeOperation(response)
    services = _FakeServicesClient(update=operation)
    adapter = _adapter(services, role=role)

    result = await _execute(adapter, action=action)

    assert result.outcome is CloudRunMutationOutcome.APPLIED
    assert result.operation_name == "operations/update-traffic-1"
    assert result.service is not None
    assert result.service.etag == "etag-after-8"
    assert result.expected_concurrency == 8
    assert map_cloud_run_mutation_result(result) == ReceiptMutationResult(
        status=ReceiptMutationStatus.APPLIED,
        provider_operation="operations/update-traffic-1",
        reason_code=None,
    )
    assert [(item.revision, item.percent, item.tag) for item in result.requested_traffic] == [
        (STABLE, stable_percent, "stable"),
        (CANDIDATE, candidate_percent, "candidate"),
    ]
    assert len(services.update_calls) == 1
    request, retry, timeout = services.update_calls[0]
    assert retry is None
    assert timeout == 15.0
    assert request.service.name == SERVICE_RESOURCE
    assert request.service.etag == "etag-before-7"
    assert request.update_mask.paths == ["traffic"]
    assert request.allow_missing is False
    assert request.validate_only is False
    assert request.service.template == run_v2.RevisionTemplate()
    provider_fields = {
        descriptor.name for descriptor, _value in run_v2.Service.pb(request.service).ListFields()
    }
    assert provider_fields == {"name", "traffic", "etag"}
    assert operation.calls == [30.0]


def test_recovery_identity_cannot_construct_a_cloud_run_mutation_adapter() -> None:
    services = _FakeServicesClient()

    with pytest.raises(ValueError, match="executor identity"):
        _adapter(services, role=ServiceRole.RECOVERY)

    assert services.update_calls == []


@_async_test
async def test_undeclared_revision_is_denied_without_provider_call() -> None:
    services = _FakeServicesClient()
    adapter = _adapter(services)

    result = await _execute(
        adapter,
        candidate_revision=f"{SERVICE}-other-v1",
    )

    assert result.outcome is CloudRunMutationOutcome.FAILED_SAFE
    assert result.reason is CloudRunMutationReason.DECLARATION_MISMATCH
    assert services.update_calls == []


@pytest.mark.parametrize(
    ("provider_error", "reason"),
    [
        (
            _provider_error(
                api_exceptions.FailedPrecondition,
                "synthetic etag mismatch",
            ),
            CloudRunMutationReason.PRECONDITION_FAILED,
        ),
        (
            _provider_error(api_exceptions.PermissionDenied, "synthetic denied"),
            CloudRunMutationReason.PROVIDER_REJECTED,
        ),
    ],
)
@_async_test
async def test_known_rejections_are_failed_safe_without_retry(
    provider_error: Exception,
    reason: CloudRunMutationReason,
) -> None:
    services = _FakeServicesClient(update=provider_error)
    result = await _execute(_adapter(services))

    assert result.outcome is CloudRunMutationOutcome.FAILED_SAFE
    assert result.reason is reason
    assert result.operation_name is None
    assert len(services.update_calls) == 1
    with pytest.raises(ValueError, match="failed-safe mutation result"):
        replace(result, operation_name="operations/forbidden")
    expected_reason = {
        CloudRunMutationReason.PRECONDITION_FAILED: (
            ReasonCode.PROVIDER_PRECONDITION_FAILED
        ),
        CloudRunMutationReason.PROVIDER_REJECTED: ReasonCode.PROVIDER_REQUEST_REJECTED,
    }[reason]
    assert map_cloud_run_mutation_result(result) == ReceiptMutationResult(
        status=ReceiptMutationStatus.FAILED_SAFE,
        provider_operation=None,
        reason_code=expected_reason,
    )


@pytest.mark.parametrize(
    "provider_error",
    [
        TimeoutError(),
        _provider_error(api_exceptions.DeadlineExceeded, "synthetic deadline"),
        _provider_error(api_exceptions.ServiceUnavailable, "synthetic unavailable"),
        RuntimeError("synthetic unknown"),
    ],
)
@_async_test
async def test_unknown_initial_provider_outcome_is_ambiguous_without_retry(
    provider_error: Exception,
) -> None:
    services = _FakeServicesClient(update=provider_error)
    result = await _execute(_adapter(services))

    assert result.outcome is CloudRunMutationOutcome.AMBIGUOUS
    assert result.reason is CloudRunMutationReason.OUTCOME_UNKNOWN
    assert result.operation_name is None
    assert len(services.update_calls) == 1
    assert map_cloud_run_mutation_result(result) == ReceiptMutationResult(
        status=ReceiptMutationStatus.AMBIGUOUS,
        provider_operation=None,
        reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
    )


@_async_test
async def test_cancellation_during_update_propagates_after_one_attempt() -> None:
    services = _FakeServicesClient(update=asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        await _execute(_adapter(services))

    assert len(services.update_calls) == 1


@pytest.mark.parametrize(
    "operation_result",
    [
        TimeoutError(),
        _provider_error(
            api_exceptions.FailedPrecondition,
            "synthetic operation failure",
        ),
        RuntimeError("synthetic malformed operation"),
        object(),
        _service(100, 0),
    ],
)
@_async_test
async def test_unknown_or_mismatched_operation_result_preserves_ambiguity(
    operation_result: object,
) -> None:
    operation = _FakeOperation(operation_result)
    services = _FakeServicesClient(update=operation)
    result = await _execute(_adapter(services))

    assert result.outcome is CloudRunMutationOutcome.AMBIGUOUS
    assert result.reason is CloudRunMutationReason.OUTCOME_UNKNOWN
    assert result.operation_name == "operations/update-traffic-1"
    assert len(services.update_calls) == 1
    assert operation.calls == [30.0]
    assert map_cloud_run_mutation_result(result) == ReceiptMutationResult(
        status=ReceiptMutationStatus.AMBIGUOUS,
        provider_operation="operations/update-traffic-1",
        reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
    )


@_async_test
async def test_cancellation_while_polling_operation_propagates() -> None:
    operation = _FakeOperation(asyncio.CancelledError())
    services = _FakeServicesClient(update=operation)

    with pytest.raises(asyncio.CancelledError):
        await _execute(_adapter(services))

    assert len(services.update_calls) == 1
    assert operation.calls == [30.0]


@_async_test
async def test_missing_operation_identity_is_ambiguous_without_polling() -> None:
    operation = _FakeOperation(_service(), name="")
    services = _FakeServicesClient(update=operation)

    result = await _execute(_adapter(services))

    assert result.outcome is CloudRunMutationOutcome.AMBIGUOUS
    assert result.operation_name is None
    assert operation.calls == []


def test_adapter_exposes_no_general_cloud_run_mutation_surface() -> None:
    adapter = _adapter(_FakeServicesClient())
    public_callables = {
        name
        for name in dir(adapter)
        if not name.startswith("_") and callable(getattr(adapter, name))
    }
    assert public_callables == {
        "mutate",
        "prepare",
        "read_revision",
        "read_service",
        "read_target",
    }
    assert not hasattr(adapter, "deploy")
    assert not hasattr(adapter, "update_service")
    assert not hasattr(adapter, "delete_revision")


@_async_test
async def test_adapter_rejects_any_input_other_than_a_final_gate_permit() -> None:
    services = _FakeServicesClient()
    adapter = _adapter(services)

    with pytest.raises(TypeError, match="one-use permit"):
        await adapter.mutate(_verified().request.intent)  # type: ignore[arg-type]

    assert services.update_calls == []


@_async_test
async def test_client_initialization_completes_before_final_epoch_read() -> None:
    services = _FakeServicesClient()
    initialization_started = Event()
    release_initialization = Event()

    def client_factory() -> _FakeServicesClient:
        initialization_started.set()
        if not release_initialization.wait(2):
            raise RuntimeError("synthetic client initialization timeout")
        return services

    adapter = CloudRunV2Adapter(
        configuration=_configuration(),
        service_role=ServiceRole.EXECUTOR,
        configured_project_id=PROJECT_ID,
        services_client_factory=client_factory,
    )
    verified = _verified()
    reader = _Reader(verified.root)

    def revoke_before_release() -> None:
        assert initialization_started.wait(2)
        reader.snapshot = _revoked_snapshot(verified.root)
        release_initialization.set()

    revoker = Thread(target=revoke_before_release)
    revoker.start()
    try:
        proof = DirectReceiptCreate._from_direct_store_create(
            _claimed(verified),
            _binding(verified),
        )
        result = await FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            route_policy=_route_policy(ServiceRole.EXECUTOR),
            clock=lambda: NOW,
        ).execute(DefinitiveFreshClaimLeaseFactory.mint(proof), verified)
    finally:
        release_initialization.set()
        revoker.join(timeout=2)

    assert isinstance(result, FinalAuthorityDenial)
    assert result.reason_code is ReasonCode.EPOCH_MISMATCH
    assert result.observed_authority_epoch == 2
    assert services.update_calls == []


def test_target_configuration_is_immutable_and_exact() -> None:
    configuration = _configuration()
    with pytest.raises(AttributeError):
        configuration.stable_revision = "changed"  # type: ignore[misc]
    assert configuration.revision(DeclaredRevision.STABLE) == STABLE
    assert configuration.revision(DeclaredRevision.CANDIDATE) == CANDIDATE
    assert configuration.service_resource == SERVICE_RESOURCE
    assert replace(configuration) == configuration


def test_target_configuration_projection_and_digest_are_stable() -> None:
    intent = _verified().request.intent

    projection = target_configuration_projection(intent, expected_concurrency=8)

    assert projection == TargetConfigurationProjection(
        target=_target(),
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
        stable_percent=90,
        candidate_percent=10,
        concurrency=8,
    )
    assert TARGET_CONFIGURATION_V1 == "controlgraph.target-configuration/v1"
    assert TARGET_CONFIGURATION_DOMAIN == b"controlgraph.target-configuration-sha256/v1\0"
    assert target_configuration_sha256(intent, expected_concurrency=8) == (
        "a8a4957e0f4caa86ec1ca1fb80a744a2c3276f21867004e315f47ea5c84edb44"
    )


def test_target_configuration_digest_excludes_non_poststate_fields() -> None:
    intent = _verified().request.intent
    same_poststate = intent.model_copy(
        update={
            "request_id": "request-other",
            "idempotency_key": "intent-other",
            "root_id": "root-other",
            "root_sha256": "4" * 64,
            "epoch": 2,
            "action": CapabilityAction.PROMOTE_CANDIDATE,
            "plan_sha256": "5" * 64,
            "provider_etag": "etag-other",
        }
    )

    assert target_configuration_sha256(same_poststate, expected_concurrency=8) == (
        target_configuration_sha256(intent, expected_concurrency=8)
    )


@pytest.mark.parametrize(
    ("changes", "expected_concurrency"),
    [
        ({"target": _target(project_id="controlgraph-canary-d4e5f6")}, 8),
        ({"stable_revision": f"{SERVICE}-stable-v10"}, 8),
        ({"candidate_revision": f"{SERVICE}-candidate-v10"}, 8),
        ({"stable_percent": 80, "candidate_percent": 20}, 8),
        ({}, 9),
    ],
)
def test_target_configuration_digest_binds_every_poststate_field(
    changes: dict[str, object],
    expected_concurrency: int,
) -> None:
    intent = _verified().request.intent
    changed = intent.model_copy(update=changes)

    assert target_configuration_sha256(changed, expected_concurrency=expected_concurrency) != (
        target_configuration_sha256(intent, expected_concurrency=8)
    )


def test_target_configuration_projection_rejects_legacy_recovery_intent() -> None:
    recovery = _verified(action=CapabilityAction.RECOVER_STABLE).request.intent
    with pytest.raises(ValueError, match="legacy recovery intent"):
        target_configuration_projection(recovery, expected_concurrency=9)


def test_reference_target_reset_configuration_is_exact_and_immutable() -> None:
    configuration = _reset_configuration()

    assert configuration.target == _target()
    assert configuration.target_configuration == _configuration()
    with pytest.raises(AttributeError):
        configuration.project_id = "controlgraph-canary-other1"  # type: ignore[misc]


@pytest.mark.parametrize(
    "changes",
    [
        {"project_id": "shared-project"},
        {"project_id": "controlgraph-canary-reconcile"},
        {"stable_image": "reference-stable:latest"},
        {
            "stable_image": (
                f"us-central1-docker.pkg.dev/{PROJECT_ID}/other/reference-stable"
                f"@sha256:{'4' * 64}"
            )
        },
        {"candidate_image": RESET_STABLE_IMAGE},
        {"candidate_image": RESET_CANDIDATE_SAME_DIGEST},
        {"network_resource": "projects/shared/global/networks/controlgraph"},
        {"subnetwork_resource": "projects/shared/regions/us-central1/subnets/controlgraph"},
    ],
)
def test_reference_target_reset_configuration_rejects_substitution(
    changes: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        _reset_configuration(**changes)


@_async_test
async def test_reference_target_reset_uses_one_conditional_traffic_update_and_readback() -> None:
    before = _service(0, 100, etag="etag-before-reset", generation=8)
    after = _service(100, 0, etag="etag-after-reset", generation=9)
    operation = _FakeOperation(after, name="operations/reference-target-reset-1")
    services = _ResetServicesClient([before, after], update=operation)
    revisions = _FakeRevisionsClient(
        stable_image=RESET_STABLE_IMAGE,
        candidate_image=RESET_CANDIDATE_IMAGE,
    )

    result = await _resetter(services, revisions=revisions).reset(_reset_request())

    assert result.outcome is ReferenceTargetResetOutcome.RESET_APPLIED
    assert result.previous_generation == 8
    assert result.observed_generation == 9
    assert result.observed_etag == "etag-after-reset"
    assert result.operation_name == "operations/reference-target-reset-1"
    assert len(services.get_calls) == 2
    assert len(revisions.calls) == 4
    assert len(services.update_calls) == 1
    request, retry, timeout = services.update_calls[0]
    assert retry is None
    assert timeout == 5.0
    assert request.service.name == SERVICE_RESOURCE
    assert request.service.etag == "etag-before-reset"
    assert request.update_mask.paths == ["traffic"]
    assert request.allow_missing is False
    assert request.validate_only is False
    assert [(item.revision, item.percent, item.tag) for item in request.service.traffic] == [
        (STABLE, 100, "stable"),
        (CANDIDATE, 0, "candidate"),
    ]
    provider_fields = {
        descriptor.name for descriptor, _value in run_v2.Service.pb(request.service).ListFields()
    }
    assert provider_fields == {"name", "traffic", "etag"}
    assert operation.calls == [30.0]


@_async_test
async def test_reference_target_reset_migrates_the_exact_v8_baseline_to_v9() -> None:
    before = _service(
        100,
        0,
        stable_revision="controlgraph-reference-target-stable-v8",
        candidate_revision="controlgraph-reference-target-candidate-v8",
        etag="etag-before-migration",
        generation=8,
        latest_ready_revision=(
            f"{SERVICE_RESOURCE}/revisions/controlgraph-reference-target-candidate-v8"
        ),
        latest_created_revision=f"{SERVICE_RESOURCE}/revisions/{CANDIDATE}",
    )
    after = _service(100, 0, etag="etag-after-migration", generation=9)
    operation = _FakeOperation(after, name="operations/reference-target-migration-1")
    services = _ResetServicesClient([before, after], update=operation)

    result = await _resetter(services).reset(_reset_request("etag-before-migration"))

    assert result.outcome is ReferenceTargetResetOutcome.RESET_APPLIED
    assert result.previous_generation == 8
    assert result.observed_generation == 9
    assert len(services.update_calls) == 1
    request, _, _ = services.update_calls[0]
    assert [(item.revision, item.percent, item.tag) for item in request.service.traffic] == [
        (STABLE, 100, "stable"),
        (CANDIDATE, 0, "candidate"),
    ]


@_async_test
async def test_reference_target_reset_rewrites_a_stable_only_current_baseline() -> None:
    before = _service(
        100,
        0,
        etag="etag-before-reset",
        generation=8,
        latest_ready_revision=STABLE,
    )
    del before.traffic[1:]
    del before.traffic_statuses[1:]
    after = _service(100, 0, etag="etag-after-reset", generation=9)
    operation = _FakeOperation(after, name="operations/reference-target-reset-1")
    services = _ResetServicesClient([before, after], update=operation)

    result = await _resetter(services).reset(_reset_request())

    assert result.outcome is ReferenceTargetResetOutcome.RESET_APPLIED
    assert result.previous_generation == 8
    assert result.observed_generation == 9
    assert len(services.update_calls) == 1
    request, retry, _ = services.update_calls[0]
    assert retry is None
    assert [(item.revision, item.percent, item.tag) for item in request.service.traffic] == [
        (STABLE, 100, "stable"),
        (CANDIDATE, 0, "candidate"),
    ]


@_async_test
async def test_reference_target_reset_rewrites_when_candidate_is_not_latest_ready() -> None:
    before = _service(
        100,
        0,
        etag="etag-before-reset",
        generation=8,
        latest_ready_revision=STABLE,
    )
    after = _service(100, 0, etag="etag-after-reset", generation=9)
    operation = _FakeOperation(after, name="operations/reference-target-reset-1")
    services = _ResetServicesClient([before, after], update=operation)

    result = await _resetter(services).reset(_reset_request())

    assert result.outcome is ReferenceTargetResetOutcome.RESET_APPLIED
    assert len(services.update_calls) == 1


@_async_test
async def test_reference_target_reset_denies_stable_only_baseline_readback() -> None:
    before = _service(90, 10, etag="etag-before-reset", generation=8)
    incomplete = _service(
        100,
        0,
        etag="etag-after-reset",
        generation=9,
        latest_ready_revision=CANDIDATE,
    )
    del incomplete.traffic[1:]
    del incomplete.traffic_statuses[1:]
    operation = _FakeOperation(incomplete, name="operations/reference-target-reset-1")
    services = _ResetServicesClient([before, incomplete], update=operation)

    with pytest.raises(ReferenceTargetResetError) as raised:
        await _resetter(services).reset(_reset_request())

    assert raised.value.code is ReferenceTargetResetErrorCode.OUTCOME_UNKNOWN
    assert len(services.update_calls) == 1
    assert len(services.get_calls) == 2
    assert operation.calls == [30.0]


@_async_test
async def test_reference_target_reset_denies_non_candidate_latest_ready_readback() -> None:
    before = _service(90, 10, etag="etag-before-reset", generation=8)
    incomplete = _service(
        100,
        0,
        etag="etag-after-reset",
        generation=9,
        latest_ready_revision=STABLE,
    )
    operation = _FakeOperation(incomplete, name="operations/reference-target-reset-1")
    services = _ResetServicesClient([before, incomplete], update=operation)

    with pytest.raises(ReferenceTargetResetError) as raised:
        await _resetter(services).reset(_reset_request())

    assert raised.value.code is ReferenceTargetResetErrorCode.OUTCOME_UNKNOWN
    assert len(services.update_calls) == 1
    assert len(services.get_calls) == 2
    assert operation.calls == [30.0]


@pytest.mark.parametrize(
    "case",
    ["wrong-tag", "wrong-percent", "extra-allocation", "status-mismatch"],
)
@_async_test
async def test_reference_target_reset_rejects_any_other_v8_traffic_shape(
    case: str,
) -> None:
    before = _service(
        100,
        0,
        stable_revision="controlgraph-reference-target-stable-v8",
        candidate_revision="controlgraph-reference-target-candidate-v8",
        etag="etag-before-migration",
        generation=8,
        latest_ready_revision=(
            f"{SERVICE_RESOURCE}/revisions/controlgraph-reference-target-candidate-v8"
        ),
        latest_created_revision=f"{SERVICE_RESOURCE}/revisions/{CANDIDATE}",
    )
    if case == "wrong-tag":
        before.traffic[0].tag = "candidate"
        before.traffic_statuses[0].tag = "candidate"
    elif case == "wrong-percent":
        before.traffic[0].percent = 99
        before.traffic[1].percent = 1
        before.traffic_statuses[0].percent = 99
        before.traffic_statuses[1].percent = 1
    elif case == "extra-allocation":
        before.traffic.append(
            run_v2.TrafficTarget(
                type_=(
                    run_v2.TrafficTargetAllocationType
                    .TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION
                ),
                revision=CANDIDATE,
                percent=0,
                tag="candidate",
            )
        )
    else:
        before.traffic_statuses[1].percent = 1
    services = _ResetServicesClient(
        [before],
        update=AssertionError("invalid retained traffic must not update"),
    )

    with pytest.raises(ReferenceTargetResetError) as raised:
        await _resetter(services).reset(_reset_request("etag-before-migration"))

    assert raised.value.code is ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
    assert services.update_calls == []


@_async_test
async def test_reference_target_reset_confirms_an_existing_baseline_without_update() -> None:
    first = _service(100, 0, etag="etag-baseline", generation=8)
    confirmed = _service(100, 0, etag="etag-baseline", generation=8)
    services = _ResetServicesClient(
        [first, confirmed],
        update=AssertionError("baseline must not be rewritten"),
    )

    result = await _resetter(services).reset(_reset_request("etag-baseline"))

    assert result.outcome is ReferenceTargetResetOutcome.ALREADY_BASELINE
    assert result.operation_name is None
    assert result.previous_generation == result.observed_generation == 8
    assert services.update_calls == []
    assert len(services.get_calls) == 2


@_async_test
async def test_reference_target_reset_denies_stale_etag_before_provider_update() -> None:
    services = _ResetServicesClient(
        [_service(0, 100, etag="etag-current")],
        update=AssertionError("stale reset must not update"),
    )

    with pytest.raises(ReferenceTargetResetError) as raised:
        await _resetter(services).reset(_reset_request("etag-stale"))

    assert raised.value.code is ReferenceTargetResetErrorCode.PRECONDITION_FAILED
    assert services.update_calls == []
    assert len(services.get_calls) == 1


@_async_test
async def test_reference_target_reset_denies_an_unexpected_immutable_image() -> None:
    services = _ResetServicesClient(
        [_service(0, 100, etag="etag-before-reset")],
        update=AssertionError("image mismatch must not update"),
    )
    revisions = _FakeRevisionsClient(
        stable_image=REFERENCE_IMAGE,
        candidate_image=RESET_CANDIDATE_IMAGE,
    )

    with pytest.raises(ReferenceTargetResetError) as raised:
        await _resetter(services, revisions=revisions).reset(_reset_request())

    assert raised.value.code is ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
    assert services.update_calls == []


@_async_test
async def test_reference_target_reset_denies_an_unexpected_memory_limit() -> None:
    services = _ResetServicesClient(
        [_service(0, 100, etag="etag-before-reset")],
        update=AssertionError("memory mismatch must not update"),
    )
    revisions = _FakeRevisionsClient(
        stable_image=RESET_STABLE_IMAGE,
        candidate_image=RESET_CANDIDATE_IMAGE,
        memory_limit="256Mi",
    )

    with pytest.raises(ReferenceTargetResetError) as raised:
        await _resetter(services, revisions=revisions).reset(_reset_request())

    assert raised.value.code is ReferenceTargetResetErrorCode.TARGET_STATE_DENIED
    assert services.update_calls == []


@_async_test
async def test_reference_target_reset_resolves_unknown_outcome_only_by_exact_readback() -> None:
    before = _service(90, 10, etag="etag-before-reset", generation=8)
    after = _service(100, 0, etag="etag-after-reset", generation=9)
    services = _ResetServicesClient(
        [before, after],
        update=RuntimeError("synthetic unknown provider outcome"),
    )

    result = await _resetter(services).reset(_reset_request())

    assert result.outcome is ReferenceTargetResetOutcome.RESET_CONFIRMED_AFTER_UNKNOWN
    assert result.operation_name is None
    assert len(services.update_calls) == 1
    assert len(services.get_calls) == 2


@_async_test
async def test_reference_target_reset_preserves_unknown_when_readback_is_not_baseline() -> None:
    before = _service(90, 10, etag="etag-before-reset", generation=8)
    unchanged = _service(90, 10, etag="etag-before-reset", generation=8)
    services = _ResetServicesClient(
        [before, unchanged],
        update=RuntimeError("synthetic unknown provider outcome"),
    )

    with pytest.raises(ReferenceTargetResetError) as raised:
        await _resetter(services).reset(_reset_request())

    assert raised.value.code is ReferenceTargetResetErrorCode.OUTCOME_UNKNOWN
    assert len(services.update_calls) == 1
    assert len(services.get_calls) == 2


@_async_test
async def test_reference_target_reset_maps_known_rejection_without_retry() -> None:
    services = _ResetServicesClient(
        [_service(0, 100, etag="etag-before-reset")],
        update=_provider_error(api_exceptions.FailedPrecondition, "synthetic etag race"),
    )

    with pytest.raises(ReferenceTargetResetError) as raised:
        await _resetter(services).reset(_reset_request())

    assert raised.value.code is ReferenceTargetResetErrorCode.PRECONDITION_FAILED
    assert len(services.update_calls) == 1
    assert len(services.get_calls) == 1


def test_reference_target_resetter_exposes_no_general_cloud_run_surface() -> None:
    services = _ResetServicesClient(
        [_service(100, 0, etag="etag-baseline")],
        update=AssertionError("not called"),
    )
    resetter = _resetter(services)

    public_callables = {
        name
        for name in dir(resetter)
        if not name.startswith("_") and callable(getattr(resetter, name))
    }
    assert public_callables == {"reset"}
    assert not hasattr(resetter, "update_service")
    assert not hasattr(resetter, "delete")
