from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest
from google.api_core.exceptions import AlreadyExists, DeadlineExceeded
from google.cloud import tasks_v2

from controlgraph_canary.application.tasks import (
    EXECUTION_HANDLER_PATH,
    MAX_SCHEDULE_DELAY_SECONDS,
    MAX_TASK_AGE_SECONDS,
    RECOVERY_HANDLER_PATH,
    TASK_DISPATCH_DEADLINE_SECONDS,
    TASK_REGION,
    TaskAddressingError,
    TaskAddressor,
    TaskDeliverySettings,
    TaskDispatcher,
    TaskEnqueueDisposition,
    TaskRoute,
)
from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityClaims,
    MutationIntent,
    SignedCapability,
    TargetBinding,
    TaskRequest,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
    encode_base64url,
)
from controlgraph_canary.integrations.google.tasks import GoogleCloudTasksEnqueuer

PROJECT_ID = "controlgraph-canary-abc123"
EXECUTOR_ORIGIN = "https://controlgraph-executor-abc-uc.a.run.app"
RECOVERY_ORIGIN = "https://controlgraph-recovery-abc-uc.a.run.app"
EXECUTION_CALLER = f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
RECOVERY_CALLER = f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
ROOT_DIGEST = "a" * 64
PLAN_DIGEST = "b" * 64


def delivery_settings() -> TaskDeliverySettings:
    return TaskDeliverySettings(
        project_id=PROJECT_ID,
        execution_queue_id="controlgraph-execution",
        recovery_queue_id="controlgraph-recovery",
        executor_service_url=EXECUTOR_ORIGIN,
        recovery_service_url=RECOVERY_ORIGIN,
        execution_oidc_service_account=EXECUTION_CALLER,
        recovery_oidc_service_account=RECOVERY_CALLER,
    )


@pytest.mark.parametrize("project_id", ["shared-project", "reconcile-production"])
def test_delivery_settings_reject_projects_outside_controlgraph(project_id: str) -> None:
    with pytest.raises(ValueError, match="project_id"):
        replace(delivery_settings(), project_id=project_id)


@pytest.mark.parametrize(
    ("field_name", "substitute"),
    [
        ("execution_queue_id", "controlgraph-execution-alt"),
        ("recovery_queue_id", "controlgraph-recovery-alt"),
        ("execution_queue_id", "controlgraph-recovery"),
        ("recovery_queue_id", "controlgraph-execution"),
        (
            "execution_oidc_service_account",
            f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com",
        ),
        (
            "recovery_oidc_service_account",
            f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com",
        ),
        (
            "execution_oidc_service_account",
            "cg-execution-task-caller@controlgraph-canary-def456.iam.gserviceaccount.com",
        ),
        (
            "recovery_oidc_service_account",
            f"alternate-recovery-caller@{PROJECT_ID}.iam.gserviceaccount.com",
        ),
        ("executor_service_url", RECOVERY_ORIGIN),
        ("recovery_service_url", EXECUTOR_ORIGIN),
        (
            "executor_service_url",
            "https://reconcile-executor-abc-uc.a.run.app",
        ),
        (
            "recovery_service_url",
            "https://controlgraph-recovery-shadow-abc-uc.a.run.app",
        ),
    ],
)
def test_delivery_settings_rejects_coordinate_substitution(
    field_name: str,
    substitute: str,
) -> None:
    with pytest.raises(ValueError):
        replace(delivery_settings(), **{field_name: substitute})


def task_request(
    *,
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
    scheduled_at: str = "2026-08-19T12:02:00Z",
    expires_at: str = "2026-08-19T12:10:00Z",
    audience: str | None = None,
    queue_region: str = TASK_REGION,
) -> TaskRequest:
    is_recovery = action is CapabilityAction.RECOVER_STABLE
    target = TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT_ID,
        region=TASK_REGION,
        environment="acceptance",
        service_name="reference-target",
    )
    service_audience = audience or (RECOVERY_ORIGIN if is_recovery else EXECUTOR_ORIGIN)
    stable_percent, candidate_percent = (100, 0) if is_recovery else (90, 10)
    if action is CapabilityAction.PROMOTE_CANDIDATE:
        stable_percent, candidate_percent = 0, 100
    request_id = f"request-{action.value.lower()}"
    idempotency_key = f"intent-{action.value.lower()}"
    claims = CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id=f"capability-{action.value.lower()}",
        issuer=f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com",
        subject=(
            f"controlgraph-recovery@{PROJECT_ID}.iam.gserviceaccount.com"
            if is_recovery
            else f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
        audience=service_audience,
        target=target,
        root_id="root-001",
        root_sha256=ROOT_DIGEST,
        epoch=7,
        action=action,
        stable_revision="reference-target-stable",
        candidate_revision="reference-target-candidate",
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=40 if is_recovery else None,
        plan_sha256=PLAN_DIGEST,
        provider_etag="etag-7",
        request_id=request_id,
        idempotency_key=idempotency_key,
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:00:00Z",
        not_before="2026-08-19T12:00:00Z",
        expires_at="2026-08-19T12:15:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=(
            f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph/"
            "cryptoKeys/capabilities/cryptoKeyVersions/1"
        ),
    )
    capability = SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-signature"),
    )
    intent = MutationIntent(
        schema_version="controlgraph.mutation-intent/v1",
        request_id=request_id,
        idempotency_key=idempotency_key,
        target=target,
        root_id="root-001",
        root_sha256=ROOT_DIGEST,
        epoch=7,
        action=action,
        stable_revision="reference-target-stable",
        candidate_revision="reference-target-candidate",
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=40 if is_recovery else None,
        plan_sha256=PLAN_DIGEST,
        provider_etag="etag-7",
    )
    return TaskRequest(
        schema_version="controlgraph.task-request/v1",
        task_id=f"task-{action.value.lower()}",
        queue_region=queue_region,
        handler_audience=service_audience,
        scheduled_at=scheduled_at,
        expires_at=expires_at,
        capability=capability,
        intent=intent,
    )


class _Response:
    def __init__(self, name: str) -> None:
        self.name = name


class _CapturingClient:
    def __init__(self, *, duplicate_after_first: bool = False) -> None:
        self.requests: list[dict[str, object]] = []
        self.duplicate_after_first = duplicate_after_first

    def create_task(self, *, request: dict[str, object]) -> object:
        self.requests.append(request)
        task = cast(dict[str, object], request["task"])
        if self.duplicate_after_first and len(self.requests) > 1:
            raise AlreadyExists("synthetic duplicate")
        return _Response(cast(str, task["name"]))


class _DeadlineExceededClient:
    def __init__(self) -> None:
        self.calls = 0

    def create_task(self, *, request: dict[str, object]) -> object:
        self.calls += 1
        raise DeadlineExceeded("synthetic deadline")


class _UnexpectedResponseClient:
    def __init__(self) -> None:
        self.calls = 0

    def create_task(self, *, request: dict[str, object]) -> object:
        self.calls += 1
        return _Response("projects/other/locations/us-central1/queues/other/tasks/other")


class _RaisingNameResponse:
    @property
    def name(self) -> str:
        raise RuntimeError("synthetic provider response detail")


class _RaisingNameClient:
    def __init__(self) -> None:
        self.calls = 0

    def create_task(self, *, request: dict[str, object]) -> object:
        self.calls += 1
        return _RaisingNameResponse()


class _RaisingEquality:
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("synthetic provider response detail")


class _NonStringNameResponse:
    def __init__(self) -> None:
        self.name = _RaisingEquality()


class _RaisingEqualityClient:
    def __init__(self) -> None:
        self.calls = 0

    def create_task(self, *, request: dict[str, object]) -> object:
        self.calls += 1
        return _NonStringNameResponse()


@pytest.mark.parametrize(
    ("action", "route", "queue", "origin", "path", "caller"),
    [
        (
            CapabilityAction.APPLY_CANARY,
            TaskRoute.EXECUTION,
            "controlgraph-execution",
            EXECUTOR_ORIGIN,
            EXECUTION_HANDLER_PATH,
            EXECUTION_CALLER,
        ),
        (
            CapabilityAction.PROMOTE_CANDIDATE,
            TaskRoute.EXECUTION,
            "controlgraph-execution",
            EXECUTOR_ORIGIN,
            EXECUTION_HANDLER_PATH,
            EXECUTION_CALLER,
        ),
        (
            CapabilityAction.RECOVER_STABLE,
            TaskRoute.RECOVERY,
            "controlgraph-recovery",
            RECOVERY_ORIGIN,
            RECOVERY_HANDLER_PATH,
            RECOVERY_CALLER,
        ),
    ],
)
def test_actions_are_sealed_to_exact_addressed_routes(
    action: CapabilityAction,
    route: TaskRoute,
    queue: str,
    origin: str,
    path: str,
    caller: str,
) -> None:
    request = task_request(action=action)
    addressed = TaskAddressor(delivery_settings()).seal(
        request,
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )

    assert addressed.route is route
    assert addressed.parent == f"projects/{PROJECT_ID}/locations/us-central1/queues/{queue}"
    assert addressed.name.startswith(f"{addressed.parent}/tasks/cg-")
    assert addressed.handler_url == f"{origin}{path}"
    assert addressed.audience == origin
    assert addressed.oidc_service_account == caller
    assert decode_contract(addressed.body, TaskRequest) == request


@pytest.mark.parametrize(
    "altered_handler_url",
    [
        "https://other-executor-abc-uc.a.run.app/v1/internal/tasks/execute",
        f"{EXECUTOR_ORIGIN}/attacker-path",
        f"{EXECUTOR_ORIGIN}{EXECUTION_HANDLER_PATH}?next=/attacker-path",
    ],
)
def test_provider_adapter_rechecks_the_seal_before_create_task(
    altered_handler_url: str,
) -> None:
    addressor = TaskAddressor(delivery_settings())
    addressed = addressor.seal(
        task_request(),
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )
    altered = replace(
        addressed,
        handler_url=altered_handler_url,
    )
    client = _CapturingClient()

    with pytest.raises(TaskAddressingError, match="seal"):
        GoogleCloudTasksEnqueuer(client, addressor).enqueue(
            altered,
            now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
        )

    assert client.requests == []


def test_delayed_task_keeps_canonical_body_and_only_fixed_http_fields() -> None:
    request = task_request(
        scheduled_at="2026-08-19T12:11:00Z",
        expires_at="2026-08-19T12:14:00Z",
    )
    client = _CapturingClient()
    addressor = TaskAddressor(delivery_settings())
    dispatcher = TaskDispatcher(
        addressor,
        GoogleCloudTasksEnqueuer(client, addressor),
    )

    result = dispatcher.dispatch(
        request,
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )

    assert MAX_SCHEDULE_DELAY_SECONDS == 600
    assert MAX_TASK_AGE_SECONDS == 900
    assert result.disposition is TaskEnqueueDisposition.CREATED
    provider_request = client.requests[0]
    assert set(provider_request) == {"parent", "task"}
    task = cast(dict[str, object], provider_request["task"])
    assert set(task) == {"name", "http_request", "schedule_time", "dispatch_deadline"}
    http_request = cast(dict[str, object], task["http_request"])
    assert set(http_request) == {"http_method", "url", "headers", "body", "oidc_token"}
    assert http_request["url"] == f"{EXECUTOR_ORIGIN}{EXECUTION_HANDLER_PATH}"
    assert http_request["headers"] == {"Content-Type": "application/json"}
    assert http_request["body"] == canonical_json_bytes(request)
    assert http_request["oidc_token"] == {
        "service_account_email": EXECUTION_CALLER,
        "audience": EXECUTOR_ORIGIN,
    }
    assert task["schedule_time"] == datetime(2026, 8, 19, 12, 11, tzinfo=UTC)
    assert task["dispatch_deadline"] == {"seconds": TASK_DISPATCH_DEADLINE_SECONDS}
    provider_model = tasks_v2.CreateTaskRequest(provider_request)
    assert provider_model.task.http_request.oidc_token.audience == EXECUTOR_ORIGIN
    assert provider_model.task.schedule_time == datetime(2026, 8, 19, 12, 11, tzinfo=UTC)


def test_duplicate_enqueue_uses_one_deterministic_identity() -> None:
    request = task_request()
    client = _CapturingClient(duplicate_after_first=True)
    addressor = TaskAddressor(delivery_settings())
    dispatcher = TaskDispatcher(
        addressor,
        GoogleCloudTasksEnqueuer(client, addressor),
    )
    now = datetime(2026, 8, 19, 12, 1, tzinfo=UTC)

    first = dispatcher.dispatch(request, now=now)
    duplicate = dispatcher.dispatch(request, now=now)

    assert first.disposition is TaskEnqueueDisposition.CREATED
    assert duplicate.disposition is TaskEnqueueDisposition.DUPLICATE
    assert duplicate.task_name == first.task_name
    assert client.requests[0] == client.requests[1]


def test_expired_task_is_rejected_before_provider_call() -> None:
    client = _CapturingClient()
    addressor = TaskAddressor(delivery_settings())
    dispatcher = TaskDispatcher(
        addressor,
        GoogleCloudTasksEnqueuer(client, addressor),
    )

    with pytest.raises(TaskAddressingError, match="expired"):
        dispatcher.dispatch(
            task_request(),
            now=datetime(2026, 8, 19, 12, 10, tzinfo=UTC),
        )

    assert client.requests == []


def test_create_task_timeout_is_explicitly_ambiguous_and_not_retried() -> None:
    client = _DeadlineExceededClient()
    addressor = TaskAddressor(delivery_settings())
    dispatcher = TaskDispatcher(
        addressor,
        GoogleCloudTasksEnqueuer(client, addressor),
    )

    result = dispatcher.dispatch(
        task_request(),
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )

    assert client.calls == 1
    assert result.disposition is TaskEnqueueDisposition.AMBIGUOUS
    assert result.task_name.startswith(
        f"projects/{PROJECT_ID}/locations/us-central1/queues/controlgraph-execution/tasks/cg-"
    )


def test_default_task_client_is_deferred_and_unavailable_is_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def unavailable_client() -> object:
        nonlocal calls
        calls += 1
        raise RuntimeError("synthetic credentials detail")

    monkeypatch.setattr(tasks_v2, "CloudTasksClient", unavailable_client)
    addressor = TaskAddressor(delivery_settings())
    enqueuer = GoogleCloudTasksEnqueuer.from_default_credentials(addressor)

    assert calls == 0
    result = TaskDispatcher(addressor, enqueuer).dispatch(
        task_request(),
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )

    assert calls == 1
    assert result.disposition is TaskEnqueueDisposition.AMBIGUOUS


def test_unexpected_provider_response_is_ambiguous_and_not_retried() -> None:
    client = _UnexpectedResponseClient()
    addressor = TaskAddressor(delivery_settings())
    dispatcher = TaskDispatcher(
        addressor,
        GoogleCloudTasksEnqueuer(client, addressor),
    )

    result = dispatcher.dispatch(
        task_request(),
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )

    assert client.calls == 1
    assert result.disposition is TaskEnqueueDisposition.AMBIGUOUS


def test_raising_provider_response_name_is_ambiguous_and_not_retried() -> None:
    client = _RaisingNameClient()
    addressor = TaskAddressor(delivery_settings())
    dispatcher = TaskDispatcher(
        addressor,
        GoogleCloudTasksEnqueuer(client, addressor),
    )

    result = dispatcher.dispatch(
        task_request(),
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )

    assert client.calls == 1
    assert result.disposition is TaskEnqueueDisposition.AMBIGUOUS


def test_non_string_provider_response_name_is_ambiguous_without_comparison() -> None:
    client = _RaisingEqualityClient()
    addressor = TaskAddressor(delivery_settings())
    dispatcher = TaskDispatcher(
        addressor,
        GoogleCloudTasksEnqueuer(client, addressor),
    )

    result = dispatcher.dispatch(
        task_request(),
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )

    assert client.calls == 1
    assert result.disposition is TaskEnqueueDisposition.AMBIGUOUS


def test_provider_adapter_rechecks_expiry_immediately_before_create_task() -> None:
    addressor = TaskAddressor(delivery_settings())
    addressed = addressor.seal(
        task_request(),
        now=datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
    )
    client = _CapturingClient()

    with pytest.raises(TaskAddressingError, match="expired"):
        GoogleCloudTasksEnqueuer(client, addressor).enqueue(
            addressed,
            now=datetime(2026, 8, 19, 12, 10, tzinfo=UTC),
        )

    assert client.requests == []


def test_configuration_rejects_cross_region_and_handler_path_injection() -> None:
    with pytest.raises(ValueError):
        replace(delivery_settings(), region="europe-west1")
    with pytest.raises(ValueError):
        replace(
            delivery_settings(),
            executor_service_url=f"{EXECUTOR_ORIGIN}/attacker-path",
        )
    with pytest.raises(ValueError):
        replace(
            delivery_settings(),
            executor_service_url=f"{EXECUTOR_ORIGIN}?next=/attacker-path",
        )


def test_request_cannot_override_region_or_base_service_audience() -> None:
    addressor = TaskAddressor(delivery_settings())
    now = datetime(2026, 8, 19, 12, 1, tzinfo=UTC)

    with pytest.raises(TaskAddressingError, match="region"):
        addressor.seal(task_request(queue_region="europe-west1"), now=now)
    with pytest.raises(TaskAddressingError, match="audience"):
        addressor.seal(
            task_request(audience="https://other-executor-abc-uc.a.run.app"),
            now=now,
        )
