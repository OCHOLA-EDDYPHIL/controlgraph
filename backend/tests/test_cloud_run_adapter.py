from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from functools import wraps
from typing import Any, cast

import pytest
from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2

from controlgraph_canary.application.authority_store import (
    DirectReceiptCreate,
    FinalAuthoritySnapshot,
    StoredRecord,
)
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.cloud_run import (
    TARGET_CONFIGURATION_DOMAIN,
    TARGET_CONFIGURATION_V1,
    CloudRunMutationOutcome,
    CloudRunMutationReason,
    CloudRunMutationResult,
    CloudRunReadError,
    CloudRunReadErrorCode,
    CloudRunTargetConfiguration,
    DeclaredRevision,
    TargetConfigurationProjection,
    target_configuration_projection,
    target_configuration_sha256,
)
from controlgraph_canary.application.execution import (
    DefinitiveFreshClaimLeaseFactory,
    FinalMutationGate,
    FinalMutationResult,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    ServiceRole,
)
from controlgraph_canary.application.receipt_execution import (
    ReceiptMutationResult,
    ReceiptMutationStatus,
    map_cloud_run_mutation_result,
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
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    RolloutRoot,
    SignedCapability,
    StableSnapshot,
    TargetBinding,
    TaskRequest,
    TrafficAllocation,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    ServiceClaimStatus,
    execution_receipt_logical_id,
)
from controlgraph_canary.integrations.google.cloud_run import CloudRunV2Adapter

PROJECT_ID = "controlgraph-canary-a1b2c3"
SERVICE = "controlgraph-reference-target"
STABLE = f"{SERVICE}-stable-v1"
CANDIDATE = f"{SERVICE}-candidate-v1"
SERVICE_RESOURCE = f"projects/{PROJECT_ID}/locations/us-central1/services/{SERVICE}"
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
THREE_DIGEST = "3" * 64
KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)
NOW = datetime(2026, 8, 19, 12, 3, tzinfo=UTC)


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
        "environment": "acceptance",
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
) -> CloudRunTargetConfiguration:
    return CloudRunTargetConfiguration(
        target=target or _target(),
        stable_revision=stable_revision,
        candidate_revision=candidate_revision,
        stable_concurrency=stable_concurrency,
        candidate_concurrency=candidate_concurrency,
    )


def _root(
    *,
    concurrency: int = 8,
    candidate_revision: str = CANDIDATE,
) -> RolloutRoot:
    target = _target()
    stable = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=target,
        stable_revision=STABLE,
        traffic=(TrafficAllocation(revision=STABLE, percent=100),),
        concurrency=concurrency,
        service_generation=7,
        provider_etag="etag-before-7",
        configuration_sha256=ZERO_DIGEST,
        captured_at="2026-08-19T12:00:00Z",
        captured_by="controlgraph.operator/v1",
    )
    return RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id="root-cloud-run-adapter",
        target=target,
        stable_snapshot=stable,
        candidate_revision=candidate_revision,
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=ONE_DIGEST,
        maximum_recovery_attempts=1,
        initial_epoch=1,
        plan_sha256=TWO_DIGEST,
        approved_by="controlgraph.operator/v1",
        approved_at="2026-08-19T12:01:00Z",
    )


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
        target=root.target,
        root_id=root.root_id,
        root_sha256=canonical_sha256(root),
        epoch=1,
        action=action,
        stable_revision=root.stable_snapshot.stable_revision,
        candidate_revision=root.candidate_revision,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=concurrency,
        plan_sha256=root.plan_sha256,
        provider_etag=root.stable_snapshot.provider_etag,
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
        queue_region=root.target.region,
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
        email=f"caller@{PROJECT_ID}.iam.gserviceaccount.com",
        subject="123456789012345678901",
        issuer="https://accounts.google.com",
        audience=audience,
        issued_at=1,
        expires_at=2,
    )
    return VerifiedMutation(
        request=request,
        root=root,
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


def _snapshot(root: RolloutRoot) -> FinalAuthoritySnapshot:
    root_sha256 = canonical_sha256(root)
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root_sha256,
        target=root.target,
        current_epoch=1,
        previous_epoch=None,
        revision=0,
        cause=EpochChangeCause.ROOT_CREATED,
        changed_by="controlgraph.operator/v1",
        request_id="request-authority-1",
        evidence_id="evidence-authority-1",
        changed_at="2026-08-19T12:01:00Z",
    )
    claim = ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v1",
        target=root.target,
        root_id=root.root_id,
        root_sha256=root_sha256,
        status=ServiceClaimStatus.ACTIVE,
        claimed_by="controlgraph.api/v1",
        claim_request_id="request-claim",
        claim_evidence_id="evidence-claim",
        claimed_at="2026-08-19T12:01:01Z",
        released_by=None,
        release_request_id=None,
        release_evidence_id=None,
        released_at=None,
    )
    return FinalAuthoritySnapshot(
        root=StoredRecord(root, 0),
        service_claim=StoredRecord(claim, 0),
        authority=StoredRecord(authority, 0),
    )


class _Reader:
    def __init__(self, root: RolloutRoot) -> None:
        self.target = root.target
        self.snapshot = _snapshot(root)

    async def read_final_authority_snapshot(
        self,
        root_id: str,
    ) -> FinalAuthoritySnapshot | None:
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


class _FakeRevisionsClient:
    def __init__(self, *, concurrency: int = 8) -> None:
        self.responses = {
            f"{SERVICE_RESOURCE}/revisions/{STABLE}": _revision(STABLE, concurrency),
            f"{SERVICE_RESOURCE}/revisions/{CANDIDATE}": _revision(
                CANDIDATE,
                concurrency,
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
    concurrency: int = 8,
    etag: str = "etag-after-8",
) -> run_v2.Service:
    return run_v2.Service(
        name=resource_name,
        uid="synthetic-service-uid",
        generation=8,
        observed_generation=8,
        etag=etag,
        reconciling=False,
        latest_ready_revision=candidate_revision,
        latest_created_revision=candidate_revision,
        template=run_v2.RevisionTemplate(
            revision=template_revision,
            max_instance_request_concurrency=concurrency,
        ),
        traffic=[
            run_v2.TrafficTarget(
                type_=(run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION),
                revision=stable_revision,
                percent=stable_percent,
                tag="stable",
            ),
            run_v2.TrafficTarget(
                type_=(run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION),
                revision=candidate_revision,
                percent=candidate_percent,
                tag="candidate",
            ),
        ],
        traffic_statuses=[
            run_v2.TrafficTargetStatus(
                type_=(run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION),
                revision=stable_revision,
                percent=stable_percent,
                tag="stable",
                uri="https://stable.example.test",
            ),
            run_v2.TrafficTargetStatus(
                type_=(run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION),
                revision=candidate_revision,
                percent=candidate_percent,
                tag="candidate",
                uri="https://candidate.example.test",
            ),
        ],
        uri="https://service.example.test",
    )


def _revision(revision: str, concurrency: int = 8) -> run_v2.Revision:
    return run_v2.Revision(
        name=f"{SERVICE_RESOURCE}/revisions/{revision}",
        service=SERVICE_RESOURCE,
        uid=f"synthetic-{revision}-uid",
        etag=f"etag-{revision}",
        generation=1,
        observed_generation=1,
        reconciling=False,
        max_instance_request_concurrency=concurrency,
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
    assert [(item.revision, item.percent) for item in target.service.traffic] == [
        (STABLE, 90),
        (CANDIDATE, 10),
    ]
    assert target.stable_revision.revision == STABLE
    assert target.candidate_revision.revision == CANDIDATE
    assert target.stable_revision.concurrency == 8
    assert target.candidate_revision.concurrency == 8
    assert [(call[0].name, call[1]) for call in services.get_calls] == [(SERVICE_RESOURCE, None)]
    assert {call[0].name for call in revisions.calls} == {
        f"{SERVICE_RESOURCE}/revisions/{STABLE}",
        f"{SERVICE_RESOURCE}/revisions/{CANDIDATE}",
    }
    with pytest.raises(TypeError, match="declared revision selector"):
        await adapter.read_revision("stable")  # type: ignore[arg-type]
    assert len(revisions.calls) == 2


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
    "service",
    [
        _service(candidate_revision=f"{SERVICE}-undeclared-v1"),
        _service(concurrency=9),
        _service(stable_percent=80, candidate_percent=10),
    ],
)
@_async_test
async def test_read_rejects_undeclared_revision_concurrency_and_traffic(
    service: run_v2.Service,
) -> None:
    adapter = _adapter(_FakeServicesClient(service=service))
    with pytest.raises(CloudRunReadError) as error:
        await adapter.read_service()
    assert error.value.code is CloudRunReadErrorCode.CORRUPT_RESPONSE


@pytest.mark.parametrize(
    ("action", "role", "stable_percent", "candidate_percent"),
    [
        (CapabilityAction.APPLY_CANARY, ServiceRole.EXECUTOR, 90, 10),
        (CapabilityAction.PROMOTE_CANDIDATE, ServiceRole.EXECUTOR, 0, 100),
        (CapabilityAction.RECOVER_STABLE, ServiceRole.RECOVERY, 100, 0),
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
    request, retry, _timeout = services.update_calls[0]
    assert retry is None
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


@_async_test
async def test_concurrency_change_intent_is_denied_without_provider_call() -> None:
    services = _FakeServicesClient()
    adapter = _adapter(services, role=ServiceRole.RECOVERY)

    result = await _execute(
        adapter,
        action=CapabilityAction.RECOVER_STABLE,
        root_concurrency=9,
    )

    assert result.outcome is CloudRunMutationOutcome.FAILED_SAFE
    assert result.reason is CloudRunMutationReason.DECLARATION_MISMATCH
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
    assert public_callables == {"mutate", "read_revision", "read_service", "read_target"}
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
        "9859ee2f9e9a8a78518a97457e075856990ec8e7ea8c9e0b5ca898e7d8b05c8e"
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
        ({"stable_revision": f"{SERVICE}-stable-v2"}, 8),
        ({"candidate_revision": f"{SERVICE}-candidate-v2"}, 8),
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


def test_target_configuration_projection_rejects_mismatched_declared_state() -> None:
    recovery = _verified(action=CapabilityAction.RECOVER_STABLE).request.intent
    with pytest.raises(ValueError, match="expected concurrency"):
        target_configuration_projection(recovery, expected_concurrency=9)

    mismatched_revision = recovery.model_copy(update={"candidate_revision": "other-candidate-v1"})
    with pytest.raises(ValueError, match="target service"):
        target_configuration_projection(mismatched_revision, expected_concurrency=8)
