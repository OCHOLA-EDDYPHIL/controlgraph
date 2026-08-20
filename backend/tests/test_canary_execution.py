from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from controlgraph_canary.application.canary_execution import (
    ApiCanaryClient,
    CanaryExecutionError,
    CanaryExecutionErrorCode,
    CanaryRolloutCoordinator,
    CoordinatorCanaryRelay,
    CoordinatorCapabilityClient,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    runtime_route_policy,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.tasks import (
    EXECUTION_HANDLER_PATH,
    AddressedTask,
    TaskAddressor,
    TaskDeliverySettings,
    TaskDispatcher,
    TaskEnqueueDisposition,
    TaskEnqueueResult,
)
from controlgraph_canary.contracts.canary_execution import (
    APPLY_CANARY_COMMAND_V1,
    APPLY_CANARY_INVOCATION_V1,
    CANARY_DISPATCH_RESULT_V1,
    CAPABILITY_ISSUANCE_COMMAND_V1,
    ApplyCanaryCommandV1,
    ApplyCanaryInvocationV1,
    CanaryDispatchResultV1,
    CapabilityIssuanceCommandV1,
)
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
    encode_base64url,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    CapabilityClaims,
    SignedCapability,
    TargetBinding,
    TaskRequest,
)

PROJECT_ID = "controlgraph-canary-abc123"
OTHER_PROJECT_ID = "controlgraph-canary-def456"
PROJECT_NUMBER = "123456789012"
OPERATOR_EMAIL = "operator@example.test"
OPERATOR_SUBJECT = "123456789012345678901"
API_SUBJECT = "234567890123456789012"
COORDINATOR_SUBJECT = "345678901234567890123"
ROOT_SHA256 = "a" * 64
PLAN_SHA256 = "b" * 64
NOW = datetime(2026, 8, 19, 12, 1, tzinfo=UTC)
ISSUED_AT = 1_776_236_400
EXPIRES_AT = ISSUED_AT + 600


def _origin(role: ServiceRole) -> str:
    return (
        f"https://controlgraph-{role.value.replace('_', '-')}-{PROJECT_NUMBER}"
        ".us-central1.run.app"
    )


def _target(project_id: str = PROJECT_ID) -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=project_id,
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )


def _command(**changes: object) -> ApplyCanaryCommandV1:
    values: dict[str, object] = {
        "schema_version": APPLY_CANARY_COMMAND_V1,
        "root_id": "root-001",
        "expected_root_sha256": ROOT_SHA256,
        "expected_epoch": 7,
        "request_id": "request-apply-001",
        "idempotency_key": "intent-apply-001",
    }
    values.update(changes)
    return ApplyCanaryCommandV1.model_validate(values)


def _capability(
    *,
    target: TargetBinding | None = None,
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
    **changes: object,
) -> SignedCapability:
    stable_percent, candidate_percent = {
        CapabilityAction.APPLY_CANARY: (90, 10),
        CapabilityAction.PROMOTE_CANDIDATE: (0, 100),
        CapabilityAction.RECOVER_STABLE: (100, 0),
    }[action]
    values: dict[str, object] = {
        "schema_version": "controlgraph.capability-claims/v1",
        "capability_id": "capability-apply-001",
        "issuer": f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com",
        "subject": f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com",
        "audience": _origin(ServiceRole.EXECUTOR),
        "target": target or _target(),
        "root_id": "root-001",
        "root_sha256": ROOT_SHA256,
        "epoch": 7,
        "action": action,
        "stable_revision": "controlgraph-reference-target-stable",
        "candidate_revision": "controlgraph-reference-target-candidate",
        "stable_percent": stable_percent,
        "candidate_percent": candidate_percent,
        "concurrency": None,
        "plan_sha256": PLAN_SHA256,
        "provider_etag": "etag-root-001",
        "request_id": "request-apply-001",
        "idempotency_key": "intent-apply-001",
        "parent_capability_sha256": None,
        "issued_at": "2026-08-19T12:00:00Z",
        "not_before": "2026-08-19T12:02:00Z",
        "expires_at": "2026-08-19T12:10:00Z",
        "signing_algorithm": "EC_SIGN_P256_SHA256",
        "signing_key_version": (
            f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
            "cryptoKeys/capability-signing/cryptoKeyVersions/1"
        ),
    }
    values.update(changes)
    claims = CapabilityClaims.model_validate(values)
    return SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-signature"),
    )


def _result(
    *,
    command: ApplyCanaryCommandV1 | None = None,
    capability: SignedCapability | None = None,
    target: TargetBinding | None = None,
    disposition: TaskEnqueueDisposition = TaskEnqueueDisposition.CREATED,
) -> CanaryDispatchResultV1:
    selected_command = command or _command()
    selected_capability = capability or _capability(target=target)
    selected_target = target or selected_capability.claims.target
    return CanaryDispatchResultV1(
        schema_version=CANARY_DISPATCH_RESULT_V1,
        request_id=selected_command.request_id,
        idempotency_key=selected_command.idempotency_key,
        target=selected_target,
        root_id=selected_command.root_id,
        root_sha256=selected_command.expected_root_sha256,
        epoch=selected_command.expected_epoch,
        stable_revision=selected_capability.claims.stable_revision,
        candidate_revision=selected_capability.claims.candidate_revision,
        stable_percent=90,
        candidate_percent=10,
        capability_id=selected_capability.claims.capability_id,
        capability_sha256=canonical_sha256(selected_capability),
        task_id=f"task-{selected_capability.claims_sha256}",
        task_name=(
            f"projects/{selected_target.project_id}/locations/us-central1/"
            f"queues/controlgraph-execution/tasks/cg-{canonical_sha256(selected_capability)}"
        ),
        enqueue_disposition=disposition.value,
        scheduled_at=selected_capability.claims.not_before,
        expires_at=selected_capability.claims.expires_at,
    )


def _policy(service_role: ServiceRole) -> RouteAuthenticationPolicy:
    caller_role, caller_email, caller_subject = {
        ServiceRole.API: (
            CallerRole.OPERATOR,
            OPERATOR_EMAIL,
            OPERATOR_SUBJECT,
        ),
        ServiceRole.COORDINATOR: (
            CallerRole.API,
            f"controlgraph-api@{PROJECT_ID}.iam.gserviceaccount.com",
            API_SUBJECT,
        ),
        ServiceRole.ISSUER: (
            CallerRole.COORDINATOR,
            f"controlgraph-coordinator@{PROJECT_ID}.iam.gserviceaccount.com",
            COORDINATOR_SUBJECT,
        ),
    }[service_role]
    return runtime_route_policy(
        service_role,
        {
            "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
            "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
            "CONTROLGRAPH_REGION": "us-central1",
            "CONTROLGRAPH_ROLE": service_role.value,
            "CONTROLGRAPH_AUTH_AUDIENCE": _origin(service_role),
            "CONTROLGRAPH_AUTH_CALLER_ROLE": caller_role.value,
            "CONTROLGRAPH_AUTH_CALLER_EMAIL": caller_email,
            "CONTROLGRAPH_AUTH_CALLER_SUBJECT": caller_subject,
        },
    )


def _context(role: CallerRole, **changes: object) -> AuthenticationContext:
    values: dict[str, object] = {
        "role": role,
        "issuer": "https://accounts.google.com",
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
    }
    if role is CallerRole.OPERATOR:
        values.update(
            email=OPERATOR_EMAIL,
            subject=OPERATOR_SUBJECT,
            audience=_origin(ServiceRole.API),
        )
    elif role is CallerRole.API:
        values.update(
            email=f"controlgraph-api@{PROJECT_ID}.iam.gserviceaccount.com",
            subject=API_SUBJECT,
            audience=_origin(ServiceRole.COORDINATOR),
        )
    else:
        raise AssertionError("test context role is unsupported")
    values.update(changes)
    return AuthenticationContext(**values)  # type: ignore[arg-type]


def _api_route() -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.API,
        service_role=ServiceRole.COORDINATOR,
        audience=_origin(ServiceRole.COORDINATOR),
    )


def _issuer_route() -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.COORDINATOR,
        service_role=ServiceRole.ISSUER,
        audience=_origin(ServiceRole.ISSUER),
    )


def _delivery_settings() -> TaskDeliverySettings:
    return TaskDeliverySettings(
        project_id=PROJECT_ID,
        execution_queue_id="controlgraph-execution",
        recovery_queue_id="controlgraph-recovery",
        executor_service_url=_origin(ServiceRole.EXECUTOR),
        recovery_service_url=_origin(ServiceRole.RECOVERY),
        execution_oidc_service_account=(
            f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
        recovery_oidc_service_account=(
            f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
    )


class _Transport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.error: BaseException | None = None
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        if self.error is not None:
            raise self.error
        return self.response


class _CapabilityClient:
    def __init__(self, capability: SignedCapability) -> None:
        self.capability = capability
        self.calls: list[ApplyCanaryCommandV1] = []

    async def issue(self, command: ApplyCanaryCommandV1) -> SignedCapability:
        self.calls.append(command)
        return self.capability


class _Coordinator:
    def __init__(self, result: CanaryDispatchResultV1) -> None:
        self.result = result
        self.calls: list[ApplyCanaryCommandV1] = []

    async def dispatch(
        self,
        command: ApplyCanaryCommandV1,
    ) -> CanaryDispatchResultV1:
        self.calls.append(command)
        return self.result


class _RecordingEnqueuer:
    def __init__(
        self,
        disposition: TaskEnqueueDisposition = TaskEnqueueDisposition.CREATED,
    ) -> None:
        self.disposition = disposition
        self.error: BaseException | None = None
        self.calls: list[tuple[AddressedTask, datetime]] = []

    def enqueue(self, task: AddressedTask, *, now: datetime) -> TaskEnqueueResult:
        self.calls.append((task, now))
        if self.error is not None:
            raise self.error
        return TaskEnqueueResult(
            task_name=task.name,
            disposition=self.disposition,
        )


def _rollout_coordinator(
    capability_client: _CapabilityClient,
    enqueuer: _RecordingEnqueuer,
) -> CanaryRolloutCoordinator:
    return CanaryRolloutCoordinator(
        target=_target(),
        capability_client=capability_client,
        task_dispatcher=TaskDispatcher(
            TaskAddressor(_delivery_settings()),
            enqueuer,
        ),
        clock=lambda: NOW,
    )


def _invocation(**changes: object) -> ApplyCanaryInvocationV1:
    values: dict[str, object] = {
        "schema_version": APPLY_CANARY_INVOCATION_V1,
        "command": _command(),
        "operator_identity": OPERATOR_EMAIL,
        "operator_subject": OPERATOR_SUBJECT,
        "operator_issuer": "https://accounts.google.com",
        "operator_audience": _origin(ServiceRole.API),
        "operator_issued_at": ISSUED_AT,
        "operator_expires_at": EXPIRES_AT,
    }
    values.update(changes)
    return ApplyCanaryInvocationV1.model_validate(values)


def test_apply_command_surface_contains_no_target_or_action_selector() -> None:
    command = _command()

    assert tuple(ApplyCanaryCommandV1.model_fields) == (
        "schema_version",
        "root_id",
        "expected_root_sha256",
        "expected_epoch",
        "request_id",
        "idempotency_key",
    )
    assert tuple(CapabilityIssuanceCommandV1.model_fields) == tuple(
        ApplyCanaryCommandV1.model_fields
    )
    assert decode_contract(canonical_json_bytes(command), ApplyCanaryCommandV1) == command

    for injected in (
        {"target": _target().model_dump(mode="json")},
        {"action": CapabilityAction.PROMOTE_CANDIDATE.value},
        {"stable_percent": 0, "candidate_percent": 100},
    ):
        with pytest.raises(ValidationError):
            ApplyCanaryCommandV1.model_validate(
                {**command.model_dump(mode="python"), **injected}
            )


def test_api_client_propagates_only_authenticated_operator_facts() -> None:
    transport = _Transport(canonical_json_bytes(_result()))
    client = ApiCanaryClient(
        route=_api_route(),
        authentication_policy=_policy(ServiceRole.API),
        transport=transport,
    )

    assert asyncio.run(client.dispatch(_command(), _context(CallerRole.OPERATOR))) == _result()
    assert len(transport.calls) == 1
    route, body = transport.calls[0]
    assert route == _api_route()
    invocation = decode_contract(body, ApplyCanaryInvocationV1)
    assert invocation.command == _command()
    assert invocation.operator_identity == OPERATOR_EMAIL
    assert invocation.operator_subject == OPERATOR_SUBJECT
    assert invocation.operator_issuer == "https://accounts.google.com"
    assert invocation.operator_audience == _origin(ServiceRole.API)
    assert invocation.operator_issued_at == ISSUED_AT
    assert invocation.operator_expires_at == EXPIRES_AT

    with pytest.raises(CanaryExecutionError) as denied:
        asyncio.run(
            client.dispatch(
                _command(),
                _context(CallerRole.OPERATOR, email="other.operator@example.test"),
            )
        )
    assert denied.value.code is CanaryExecutionErrorCode.OPERATOR_DENIED
    assert len(transport.calls) == 1


def test_coordinator_reauthenticates_api_and_propagated_operator() -> None:
    coordinator = _Coordinator(_result())
    relay = CoordinatorCanaryRelay(
        authentication_policy=_policy(ServiceRole.COORDINATOR),
        operator_policy=_policy(ServiceRole.API),
        coordinator=coordinator,
    )

    assert asyncio.run(relay.dispatch(_invocation(), _context(CallerRole.API))) == _result()
    assert coordinator.calls == [_command()]

    with pytest.raises(CanaryExecutionError) as wrong_operator:
        asyncio.run(
            relay.dispatch(
                _invocation(operator_subject="999999999999999999999"),
                _context(CallerRole.API),
            )
        )
    assert wrong_operator.value.code is CanaryExecutionErrorCode.OPERATOR_DENIED
    assert coordinator.calls == [_command()]

    with pytest.raises(CanaryExecutionError) as wrong_api:
        asyncio.run(
            relay.dispatch(
                _invocation(),
                _context(CallerRole.API, subject="999999999999999999999"),
            )
        )
    assert wrong_api.value.code is CanaryExecutionErrorCode.CALLER_DENIED
    assert coordinator.calls == [_command()]


def test_capability_client_sends_only_command_preconditions_to_fixed_issuer() -> None:
    capability = _capability()
    transport = _Transport(canonical_json_bytes(capability))
    client = CoordinatorCapabilityClient(
        route=_issuer_route(),
        transport=transport,
    )

    assert asyncio.run(client.issue(_command())) == capability
    assert len(transport.calls) == 1
    route, body = transport.calls[0]
    assert route == _issuer_route()
    issuance = decode_contract(body, CapabilityIssuanceCommandV1)
    assert issuance == CapabilityIssuanceCommandV1(
        schema_version=CAPABILITY_ISSUANCE_COMMAND_V1,
        root_id=_command().root_id,
        expected_root_sha256=_command().expected_root_sha256,
        expected_epoch=_command().expected_epoch,
        request_id=_command().request_id,
        idempotency_key=_command().idempotency_key,
    )
    assert "target" not in CapabilityIssuanceCommandV1.model_fields
    assert "action" not in CapabilityIssuanceCommandV1.model_fields


def test_capability_client_rejects_mismatch_and_transport_failure_without_retry() -> None:
    mismatch_transport = _Transport(
        canonical_json_bytes(_capability(request_id="request-substituted"))
    )
    mismatch_client = CoordinatorCapabilityClient(
        route=_issuer_route(),
        transport=mismatch_transport,
    )

    with pytest.raises(CanaryExecutionError) as mismatch:
        asyncio.run(mismatch_client.issue(_command()))
    assert mismatch.value.code is CanaryExecutionErrorCode.RESPONSE_INVALID
    assert len(mismatch_transport.calls) == 1

    marker = "unmistakably-synthetic-private-transport-detail"
    failed_transport = _Transport(b"")
    failed_transport.error = RuntimeError(marker)
    failed_client = CoordinatorCapabilityClient(
        route=_issuer_route(),
        transport=failed_transport,
    )
    with pytest.raises(CanaryExecutionError) as unavailable:
        asyncio.run(failed_client.issue(_command()))
    assert unavailable.value.code is CanaryExecutionErrorCode.TRANSPORT_UNAVAILABLE
    assert marker not in str(unavailable.value)
    assert len(failed_transport.calls) == 1


def test_coordinator_derives_exact_task_only_from_signed_claims() -> None:
    capability = _capability()
    capability_client = _CapabilityClient(capability)
    enqueuer = _RecordingEnqueuer()
    coordinator = _rollout_coordinator(capability_client, enqueuer)

    result = asyncio.run(coordinator.dispatch(_command()))

    assert capability_client.calls == [_command()]
    assert len(enqueuer.calls) == 1
    addressed, dispatch_time = enqueuer.calls[0]
    assert dispatch_time == NOW
    assert addressed.parent == (
        f"projects/{PROJECT_ID}/locations/us-central1/queues/controlgraph-execution"
    )
    assert addressed.handler_url == f"{_origin(ServiceRole.EXECUTOR)}{EXECUTION_HANDLER_PATH}"
    assert addressed.audience == _origin(ServiceRole.EXECUTOR)
    assert addressed.oidc_service_account == (
        f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
    )
    request = decode_contract(addressed.body, TaskRequest)
    claims = capability.claims
    assert request.capability == capability
    assert request.task_id == f"task-{capability.claims_sha256}"
    assert request.queue_region == "us-central1"
    assert request.handler_audience == claims.audience
    assert request.scheduled_at == claims.not_before
    assert request.expires_at == claims.expires_at
    assert request.intent.model_dump(mode="python") == {
        "schema_version": "controlgraph.mutation-intent/v1",
        "request_id": claims.request_id,
        "idempotency_key": claims.idempotency_key,
        "target": claims.target.model_dump(mode="python"),
        "root_id": claims.root_id,
        "root_sha256": claims.root_sha256,
        "epoch": claims.epoch,
        "action": claims.action,
        "stable_revision": claims.stable_revision,
        "candidate_revision": claims.candidate_revision,
        "stable_percent": claims.stable_percent,
        "candidate_percent": claims.candidate_percent,
        "concurrency": claims.concurrency,
        "plan_sha256": claims.plan_sha256,
        "provider_etag": claims.provider_etag,
    }
    assert result.target == claims.target
    assert result.root_sha256 == claims.root_sha256
    assert result.epoch == claims.epoch
    assert result.stable_percent == 90
    assert result.candidate_percent == 10
    assert result.task_name == addressed.name
    assert result.enqueue_disposition == TaskEnqueueDisposition.CREATED.value


@pytest.mark.parametrize(
    "capability",
    [
        _capability(root_sha256="c" * 64),
        _capability(epoch=8),
        _capability(request_id="request-substituted"),
        _capability(idempotency_key="intent-substituted"),
        _capability(action=CapabilityAction.PROMOTE_CANDIDATE),
        _capability(concurrency=40),
    ],
)
def test_coordinator_denies_mismatched_or_non_canary_capability_before_enqueue(
    capability: SignedCapability,
) -> None:
    enqueuer = _RecordingEnqueuer()
    coordinator = _rollout_coordinator(_CapabilityClient(capability), enqueuer)

    with pytest.raises(CanaryExecutionError) as denied:
        asyncio.run(coordinator.dispatch(_command()))
    assert denied.value.code is CanaryExecutionErrorCode.ISSUANCE_DENIED
    assert enqueuer.calls == []


def test_ambiguous_enqueue_is_reported_once_without_blind_retry() -> None:
    enqueuer = _RecordingEnqueuer(TaskEnqueueDisposition.AMBIGUOUS)
    coordinator = _rollout_coordinator(_CapabilityClient(_capability()), enqueuer)

    result = asyncio.run(coordinator.dispatch(_command()))

    assert len(enqueuer.calls) == 1
    assert result.enqueue_disposition == TaskEnqueueDisposition.AMBIGUOUS.value


def test_dispatch_failure_is_sanitized_and_not_retried() -> None:
    marker = "unmistakably-synthetic-private-enqueue-detail"
    enqueuer = _RecordingEnqueuer()
    enqueuer.error = RuntimeError(marker)
    coordinator = _rollout_coordinator(_CapabilityClient(_capability()), enqueuer)

    with pytest.raises(CanaryExecutionError) as unavailable:
        asyncio.run(coordinator.dispatch(_command()))
    assert unavailable.value.code is CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE
    assert marker not in str(unavailable.value)
    assert len(enqueuer.calls) == 1


def test_api_client_rejects_cross_project_or_command_mismatched_result() -> None:
    other_target = _target(OTHER_PROJECT_ID)
    cross_project = _result(
        target=other_target,
        capability=_capability(target=other_target),
    )
    cross_project_transport = _Transport(canonical_json_bytes(cross_project))
    cross_project_client = ApiCanaryClient(
        route=_api_route(),
        authentication_policy=_policy(ServiceRole.API),
        transport=cross_project_transport,
    )

    with pytest.raises(CanaryExecutionError) as wrong_project:
        asyncio.run(
            cross_project_client.dispatch(_command(), _context(CallerRole.OPERATOR))
        )
    assert wrong_project.value.code is CanaryExecutionErrorCode.RESPONSE_INVALID
    assert len(cross_project_transport.calls) == 1

    wrong_command = _command(request_id="request-substituted")
    mismatch_transport = _Transport(
        canonical_json_bytes(_result(command=wrong_command))
    )
    mismatch_client = ApiCanaryClient(
        route=_api_route(),
        authentication_policy=_policy(ServiceRole.API),
        transport=mismatch_transport,
    )
    with pytest.raises(CanaryExecutionError) as mismatch:
        asyncio.run(mismatch_client.dispatch(_command(), _context(CallerRole.OPERATOR)))
    assert mismatch.value.code is CanaryExecutionErrorCode.RESPONSE_INVALID
    assert len(mismatch_transport.calls) == 1
