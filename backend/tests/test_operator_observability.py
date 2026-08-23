from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_root_trust import (
    CANDIDATE,
    CANDIDATE_CONFIGURATION,
    NOW,
    PROJECT,
    PROJECT_NUMBER,
    STABLE,
    STABLE_CONFIGURATION,
    _revision,
    _service,
    _target,
)

from controlgraph_canary.application.authority_store import AuthorityStore, StoredRecord
from controlgraph_canary.application.cloud_run import (
    CloudRunReadyState,
    CloudRunTargetState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.completion_classification import (
    CoordinatorCompletionClassificationService,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    runtime_route_policy,
)
from controlgraph_canary.application.independent_verification import (
    IndependentVerificationService,
)
from controlgraph_canary.application.independent_verification_signing import (
    CoordinatorIndependentVerificationClient,
)
from controlgraph_canary.application.operator_observability import (
    ApiOperatorObservationClient,
    CoordinatorOperatorObservationRelay,
    CoordinatorStableSnapshotClient,
    CoordinatorTargetTrafficClient,
    OperatorObservationError,
    OperatorObservationErrorCode,
    StableSnapshotCaptureService,
    TargetTrafficObservationService,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.tasks import TaskEnqueuer
from controlgraph_canary.application.timeline_relay import (
    ApiTimelineClient,
    CoordinatorTimelineRelay,
)
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.operator_observability import (
    EXECUTION_RECEIPT_READ_COMMAND_V1,
    EXECUTION_RECEIPT_READ_INVOCATION_V1,
    STABLE_SNAPSHOT_CAPTURE_COMMAND_V1,
    STABLE_SNAPSHOT_CAPTURE_INVOCATION_V1,
    STABLE_SNAPSHOT_CAPTURE_REQUEST_V1,
    TARGET_TRAFFIC_READ_COMMAND_V1,
    TARGET_TRAFFIC_READ_INVOCATION_V1,
    TARGET_TRAFFIC_READ_REQUEST_V1,
    ExecutionReceiptReadCommandV1,
    ExecutionReceiptReadInvocationV1,
    ExecutionReceiptReadResultV1,
    StableSnapshotCaptureCommandV1,
    StableSnapshotCaptureInvocationV1,
    StableSnapshotCaptureRequestV1,
    StableSnapshotCaptureResultV1,
    TargetTrafficReadCommandV1,
    TargetTrafficReadInvocationV1,
    TargetTrafficReadRequestV1,
    TargetTrafficReadResultV1,
)
from controlgraph_canary.contracts.storage import execution_receipt_logical_id
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.http.service import create_service_app
from controlgraph_canary.services.runtime import create_runtime_service_app

OPERATOR_EMAIL = "operator@example.test"
OPERATOR_SUBJECT = "123456789012345678901"
API_SUBJECT = "234567890123456789012"
COORDINATOR_SUBJECT = "345678901234567890123"
API_IDENTITY = f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com"
COORDINATOR_IDENTITY = (
    f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com"
)
VERIFIER_IDENTITY = f"controlgraph-verifier@{PROJECT}.iam.gserviceaccount.com"
API_AUDIENCE = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
COORDINATOR_AUDIENCE = (
    f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
)
VERIFIER_AUDIENCE = (
    f"https://controlgraph-verifier-{PROJECT_NUMBER}.us-central1.run.app"
)
ISSUED_AT = 1_776_236_400
EXPIRES_AT = ISSUED_AT + 600
EVIDENCE_WRITER_AUDIENCE = (
    f"https://controlgraph-evidence-writer-{PROJECT_NUMBER}.us-central1.run.app"
)
ISSUER_AUDIENCE = (
    f"https://controlgraph-issuer-{PROJECT_NUMBER}.us-central1.run.app"
)
EXECUTOR_AUDIENCE = (
    f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
)
RECOVERY_AUDIENCE = (
    f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
)


def _identity_environment(role: ServiceRole) -> dict[str, str]:
    if role is ServiceRole.API:
        caller_role = CallerRole.OPERATOR
        caller_email = OPERATOR_EMAIL
        caller_subject = OPERATOR_SUBJECT
        audience = API_AUDIENCE
    elif role is ServiceRole.COORDINATOR:
        caller_role = CallerRole.API
        caller_email = API_IDENTITY
        caller_subject = API_SUBJECT
        audience = COORDINATOR_AUDIENCE
    else:
        caller_role = CallerRole.COORDINATOR
        caller_email = COORDINATOR_IDENTITY
        caller_subject = COORDINATOR_SUBJECT
        audience = VERIFIER_AUDIENCE
    return {
        "CONTROLGRAPH_PROJECT_ID": PROJECT,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_ROLE": role.value,
        "CONTROLGRAPH_AUTH_AUDIENCE": audience,
        "CONTROLGRAPH_AUTH_CALLER_ROLE": caller_role.value,
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": caller_email,
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": caller_subject,
    }


def _runtime_environment(role: ServiceRole) -> dict[str, str]:
    environment = _identity_environment(role)
    environment.update(
        {
            "CONTROLGRAPH_SERVICE_NAME": f"controlgraph-{role.value.replace('_', '-')}",
            "CONTROLGRAPH_CONTROLLER_ID": f"{PROJECT}:us-central1:{role.value}",
            "CONTROLGRAPH_BUILD_DIGEST": f"sha256:{'a' * 64}",
            "CONTROLGRAPH_CONTRACT_VERSION": "controlgraph.contract/v1",
            "CONTROLGRAPH_FIRESTORE_DATABASE": "controlgraph-authority",
            "CONTROLGRAPH_MUTATIONS_ENABLED": "false",
            "CONTROLGRAPH_ENVIRONMENT": "nonprod",
        }
    )
    if role is ServiceRole.API:
        environment.update(
            {
                "CONTROLGRAPH_COORDINATOR_URL": COORDINATOR_AUDIENCE,
                "CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE": (
                    "32555940559.apps.googleusercontent.com"
                ),
                "CONTROLGRAPH_OPERATOR_CONSOLE_ORIGIN": (
                    f"https://controlgraph-console-{PROJECT_NUMBER}.us-central1.run.app"
                ),
                "CONTROLGRAPH_SECURITY_AUDITOR_EMAIL": "security@example.com",
                "CONTROLGRAPH_SECURITY_AUDITOR_SUBJECT": "223456789012345678901",
                "CONTROLGRAPH_RESTRICTED_EXPORTER_EMAIL": "exporter@example.com",
                "CONTROLGRAPH_RESTRICTED_EXPORTER_SUBJECT": "323456789012345678901",
            }
        )
    elif role is ServiceRole.VERIFIER:
        environment.update(
            {
                "CONTROLGRAPH_TARGET_NETWORK_RESOURCE": (
                    f"projects/{PROJECT}/global/networks/controlgraph-network"
                ),
                "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE": (
                    f"projects/{PROJECT}/regions/us-central1/"
                    "subnetworks/controlgraph-runtime"
                ),
                "CONTROLGRAPH_EVIDENCE_WRITER_URL": EVIDENCE_WRITER_AUDIENCE,
                "CONTROLGRAPH_REFERENCE_TARGET_URL": (
                    f"https://controlgraph-reference-target-{PROJECT_NUMBER}"
                    ".us-central1.run.app"
                ),
                "CONTROLGRAPH_EVIDENCE_KEY_VERSION": _evidence_key_version(),
            }
        )
    elif role is ServiceRole.COORDINATOR:
        environment.update(
            {
                "CONTROLGRAPH_ISSUER_URL": ISSUER_AUDIENCE,
                "CONTROLGRAPH_VERIFIER_URL": VERIFIER_AUDIENCE,
                "CONTROLGRAPH_EVIDENCE_WRITER_URL": EVIDENCE_WRITER_AUDIENCE,
                "CONTROLGRAPH_CAPABILITY_KEY_VERSION": _capability_key_version(),
                "CONTROLGRAPH_EVIDENCE_KEY_VERSION": _evidence_key_version(),
                "CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256": "b" * 64,
                "CONTROLGRAPH_OPERATOR_EMAIL": OPERATOR_EMAIL,
                "CONTROLGRAPH_OPERATOR_SUBJECT": OPERATOR_SUBJECT,
                "CONTROLGRAPH_SECURITY_AUDITOR_EMAIL": "security@example.com",
                "CONTROLGRAPH_SECURITY_AUDITOR_SUBJECT": "223456789012345678901",
                "CONTROLGRAPH_RESTRICTED_EXPORTER_EMAIL": "exporter@example.com",
                "CONTROLGRAPH_RESTRICTED_EXPORTER_SUBJECT": "323456789012345678901",
                "CONTROLGRAPH_EXECUTOR_URL": EXECUTOR_AUDIENCE,
                "CONTROLGRAPH_RECOVERY_URL": RECOVERY_AUDIENCE,
                "CONTROLGRAPH_EXECUTION_QUEUE": "controlgraph-execution",
                "CONTROLGRAPH_RECOVERY_QUEUE": "controlgraph-recovery",
                "CONTROLGRAPH_EXECUTION_TASK_CALLER": (
                    f"cg-execution-task-caller@{PROJECT}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_RECOVERY_TASK_CALLER": (
                    f"cg-recovery-task-caller@{PROJECT}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_RECEIPT_AUTH_CALLER_EMAIL": (
                    f"controlgraph-executor@{PROJECT}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_RECEIPT_AUTH_CALLER_SUBJECT": "456789012345678901234",
                "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_EMAIL": (
                    f"controlgraph-executor@{PROJECT}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_SUBJECT": (
                    "456789012345678901234"
                ),
                "CONTROLGRAPH_TIMELINE_RETENTION_CALLER_EMAIL": (
                    f"cg-retention-sweeper@{PROJECT}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_TIMELINE_RETENTION_CALLER_SUBJECT": (
                    "556789012345678901234"
                ),
            }
        )
    return environment


def _capability_key_version() -> str:
    return (
        f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
        "cryptoKeys/capability-signing/cryptoKeyVersions/1"
    )


def _evidence_key_version() -> str:
    return (
        f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
        "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
    )


def _policy(role: ServiceRole) -> RouteAuthenticationPolicy:
    return runtime_route_policy(role, _identity_environment(role))


def _context(role: CallerRole, **changes: object) -> AuthenticationContext:
    values: dict[str, object] = {
        "role": role,
        "email": {
            CallerRole.OPERATOR: OPERATOR_EMAIL,
            CallerRole.API: API_IDENTITY,
            CallerRole.COORDINATOR: COORDINATOR_IDENTITY,
        }[role],
        "subject": {
            CallerRole.OPERATOR: OPERATOR_SUBJECT,
            CallerRole.API: API_SUBJECT,
            CallerRole.COORDINATOR: COORDINATOR_SUBJECT,
        }[role],
        "issuer": "https://accounts.google.com",
        "audience": {
            CallerRole.OPERATOR: API_AUDIENCE,
            CallerRole.API: COORDINATOR_AUDIENCE,
            CallerRole.COORDINATOR: VERIFIER_AUDIENCE,
        }[role],
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
    }
    values.update(changes)
    return AuthenticationContext(**values)  # type: ignore[arg-type]


def _route(caller: CallerRole, service: ServiceRole) -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        caller_role=caller,
        service_role=service,
        audience={
            ServiceRole.COORDINATOR: COORDINATOR_AUDIENCE,
            ServiceRole.VERIFIER: VERIFIER_AUDIENCE,
        }[service],
    )


def _snapshot_command() -> StableSnapshotCaptureCommandV1:
    return StableSnapshotCaptureCommandV1(
        schema_version=STABLE_SNAPSHOT_CAPTURE_COMMAND_V1,
        request_id="snapshot-read-001",
    )


def _snapshot_request() -> StableSnapshotCaptureRequestV1:
    return StableSnapshotCaptureRequestV1(
        schema_version=STABLE_SNAPSHOT_CAPTURE_REQUEST_V1,
        request_id=_snapshot_command().request_id,
        target=_target(),
    )


def _traffic_command() -> TargetTrafficReadCommandV1:
    return TargetTrafficReadCommandV1(
        schema_version=TARGET_TRAFFIC_READ_COMMAND_V1,
        request_id="traffic-read-001",
    )


def _traffic_request() -> TargetTrafficReadRequestV1:
    return TargetTrafficReadRequestV1(
        schema_version=TARGET_TRAFFIC_READ_REQUEST_V1,
        request_id=_traffic_command().request_id,
        target=_target(),
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
        concurrency=8,
    )


def _receipt(
    *,
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
    outcome: ReceiptOutcome = ReceiptOutcome.VERIFIED,
    reason_code: ReasonCode | None = None,
    observed_epoch: int | None = 1,
    receipt_id: str | None = None,
) -> ExecutionReceipt:
    request_id = (
        "apply-request-001"
        if action is CapabilityAction.APPLY_CANARY
        else "promote-request-001"
    )
    idempotency_key = (
        "apply-idempotency-001"
        if action is CapabilityAction.APPLY_CANARY
        else "promote-idempotency-001"
    )
    return ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=(
            receipt_id
            if receipt_id is not None
            else execution_receipt_logical_id(_target(), idempotency_key)
        ),
        request_id=request_id,
        idempotency_key=idempotency_key,
        capability_sha256="1" * 64,
        mutation_sha256="2" * 64,
        plan_sha256="3" * 64,
        expected_poststate_sha256="4" * 64,
        target=_target(),
        root_id="root-observation-001",
        root_sha256="5" * 64,
        epoch=1,
        action=action,
        provider_etag="service-etag-7",
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=outcome,
        reason_code=reason_code,
        provider_operation=(
            "operations/apply-001" if outcome is ReceiptOutcome.VERIFIED else None
        ),
        observed_etag=(
            "service-etag-8" if outcome is ReceiptOutcome.VERIFIED else None
        ),
        observed_authority_epoch=observed_epoch,
        created_at="2026-08-19T12:01:00Z",
        updated_at="2026-08-19T12:02:00Z",
        evidence_ids=("evidence-execution-001",),
    )


def _receipt_command(receipt: ExecutionReceipt) -> ExecutionReceiptReadCommandV1:
    return ExecutionReceiptReadCommandV1(
        schema_version=EXECUTION_RECEIPT_READ_COMMAND_V1,
        root_id=receipt.root_id,
        expected_root_sha256=receipt.root_sha256,
        expected_epoch=receipt.epoch,
        action=receipt.action,
        request_id=receipt.request_id,
        idempotency_key=receipt.idempotency_key,
        capability_sha256=receipt.capability_sha256,
    )


def _invocation(
    command: StableSnapshotCaptureCommandV1
    | ExecutionReceiptReadCommandV1
    | TargetTrafficReadCommandV1,
) -> (
    StableSnapshotCaptureInvocationV1
    | ExecutionReceiptReadInvocationV1
    | TargetTrafficReadInvocationV1
):
    values = {
        "command": command,
        "operator_identity": OPERATOR_EMAIL,
        "operator_subject": OPERATOR_SUBJECT,
        "operator_issuer": "https://accounts.google.com",
        "operator_audience": API_AUDIENCE,
        "operator_issued_at": ISSUED_AT,
        "operator_expires_at": EXPIRES_AT,
    }
    if type(command) is StableSnapshotCaptureCommandV1:
        return StableSnapshotCaptureInvocationV1(
            schema_version=STABLE_SNAPSHOT_CAPTURE_INVOCATION_V1,
            **values,  # type: ignore[arg-type]
        )
    if type(command) is ExecutionReceiptReadCommandV1:
        return ExecutionReceiptReadInvocationV1(
            schema_version=EXECUTION_RECEIPT_READ_INVOCATION_V1,
            **values,  # type: ignore[arg-type]
        )
    return TargetTrafficReadInvocationV1(
        schema_version=TARGET_TRAFFIC_READ_INVOCATION_V1,
        **values,  # type: ignore[arg-type]
    )


class _Reader:
    def __init__(self, state: CloudRunTargetState) -> None:
        self.state = state
        self.services = [state.service, state.service]
        self.calls: list[str] = []

    @property
    def target(self) -> TargetBinding:
        return _target()

    @property
    def service_role(self) -> ServiceRole:
        return ServiceRole.VERIFIER

    @property
    def reader_identity(self) -> str:
        return VERIFIER_IDENTITY

    async def read_service(self) -> object:
        self.calls.append("service")
        return self.services.pop(0)

    async def read_revision(self, revision_name: str) -> object:
        self.calls.append(f"revision:{revision_name}")
        if revision_name == STABLE:
            return self.state.stable_revision
        if revision_name == CANDIDATE:
            return self.state.candidate_revision
        raise AssertionError("unexpected revision")

    async def read_target(self) -> CloudRunTargetState:
        self.calls.append("target")
        return self.state


def _state(
    stable_percent: int = 90,
    candidate_percent: int = 10,
    *,
    include_zero: bool = True,
) -> CloudRunTargetState:
    allocations = []
    statuses = []
    for revision, percent in (
        (STABLE, stable_percent),
        (CANDIDATE, candidate_percent),
    ):
        if percent == 0 and not include_zero:
            continue
        allocations.append(
            CloudRunTrafficAllocation(revision=revision, percent=percent, tag=None)
        )
        statuses.append(
            CloudRunTrafficStatus(
                revision=revision,
                percent=percent,
                tag=None,
                uri=None,
            )
        )
    service = replace(
        _service(),
        traffic=tuple(allocations),
        traffic_statuses=tuple(statuses),
    )
    return CloudRunTargetState(
        service=service,
        stable_revision=_revision(STABLE, configuration=STABLE_CONFIGURATION),
        candidate_revision=_revision(CANDIDATE, configuration=CANDIDATE_CONFIGURATION),
    )


class _Transport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        return self.response


class _Authenticator:
    def __init__(
        self,
        policy: RouteAuthenticationPolicy,
        context: AuthenticationContext,
    ) -> None:
        self.policy = policy
        self.context = context

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        assert authorization_header == "Bearer synthetic.observation.token"
        assert policy == self.policy
        return self.context


class _Store:
    def __init__(self, stored: StoredRecord[ExecutionReceipt] | None) -> None:
        self.stored = stored
        self.calls: list[str] = []

    @property
    def target(self) -> TargetBinding:
        return _target()

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        self.calls.append(idempotency_key)
        return self.stored


class _RuntimeStore(_Store):
    async def _unreachable(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("runtime composition must not access authority storage")

    create_rollout = _unreachable
    create_rollout_after_release = _unreachable
    create_or_adopt_root_creation_bundle = _unreachable
    read_root_creation_bundle = _unreachable
    read_rollout_root = _unreachable
    read_service_claim = _unreachable
    read_authority = _unreachable
    read_issuance_state = _unreachable
    read_final_authority_snapshot = _unreachable
    advance_authority = _unreachable
    fence_service_claim = _unreachable
    release_service_claim = _unreachable
    claim_or_adopt_receipt = _unreachable
    compare_and_set_receipt = _unreachable
    read_epoch_revocation_state = _unreachable
    read_epoch_revocation_proof = _unreachable
    commit_epoch_revocation = _unreachable
    record_epoch_revocation_audit = _unreachable
    read_service_claim_release_state = _unreachable
    commit_service_claim_fence = _unreachable
    commit_service_claim_release = _unreachable
    read_promotion_dispatch = _unreachable
    prepare_or_adopt_promotion_dispatch = _unreachable
    compare_and_set_promotion_dispatch = _unreachable
    begin_promotion_enqueue = _unreachable
    read_promotion_dispatch_v2 = _unreachable
    prepare_or_adopt_promotion_dispatch_v2 = _unreachable
    compare_and_set_promotion_dispatch_v2 = _unreachable
    begin_promotion_enqueue_v2 = _unreachable


class _NeverTaskEnqueuer:
    async def enqueue(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("runtime composition must not enqueue a task")


def _snapshot_service(reader: _Reader) -> StableSnapshotCaptureService:
    return StableSnapshotCaptureService(
        target=_target(),
        authentication_policy=_policy(ServiceRole.VERIFIER),
        reader_factory=lambda request: reader,
        clock=lambda: NOW,
    )


def _traffic_service(reader: _Reader) -> TargetTrafficObservationService:
    return TargetTrafficObservationService(
        target=_target(),
        authentication_policy=_policy(ServiceRole.VERIFIER),
        reader_factory=lambda request: reader,
        clock=lambda: NOW,
    )


def _relay(store: _Store) -> CoordinatorOperatorObservationRelay:
    return CoordinatorOperatorObservationRelay(
        authentication_policy=_policy(ServiceRole.COORDINATOR),
        operator_policy=_policy(ServiceRole.API),
        snapshot_client=CoordinatorStableSnapshotClient(
            target=_target(),
            route=_route(CallerRole.COORDINATOR, ServiceRole.VERIFIER),
            transport=_Transport(b"unused"),
        ),
        traffic_client=CoordinatorTargetTrafficClient(
            target=_target(),
            stable_revision=STABLE,
            candidate_revision=CANDIDATE,
            concurrency=8,
            route=_route(CallerRole.COORDINATOR, ServiceRole.VERIFIER),
            transport=_Transport(b"unused"),
        ),
        receipt_store=store,
    )


def test_snapshot_capture_is_two_read_canonical_and_root_creation_ready() -> None:
    reader = _Reader(_state(100, 0, include_zero=False))

    result = asyncio.run(
        _snapshot_service(reader).capture(
            _snapshot_request(),
            _context(CallerRole.COORDINATOR),
        )
    )

    assert reader.calls == ["service", f"revision:{STABLE}", "service"]
    assert result.snapshot.target == _target()
    assert result.snapshot.stable_revision == STABLE
    assert result.snapshot.captured_by == VERIFIER_IDENTITY
    assert result.request_sha256 == canonical_sha256(result.request)
    assert (
        decode_contract(
            canonical_json_bytes(result),
            StableSnapshotCaptureResultV1,
        )
        == result
    )


def test_snapshot_capture_rejects_caller_and_out_of_boundary_configuration() -> None:
    reader = _Reader(_state(100, 0, include_zero=False))
    with pytest.raises(OperatorObservationError) as denied:
        asyncio.run(
            _snapshot_service(reader).capture(
                _snapshot_request(),
                _context(CallerRole.COORDINATOR, subject="999999999999999999999"),
            )
        )
    assert denied.value.code is OperatorObservationErrorCode.CALLER_DENIED

    with pytest.raises(OperatorObservationError) as invalid:
        StableSnapshotCaptureService(
            target=_target(environment="acceptance"),
            authentication_policy=_policy(ServiceRole.VERIFIER),
            reader_factory=lambda request: reader,
        )
    assert invalid.value.code is OperatorObservationErrorCode.CONFIGURATION_INVALID


@pytest.mark.parametrize(
    ("stable_percent", "candidate_percent", "include_zero"),
    [(100, 0, False), (90, 10, True), (0, 100, False)],
)
def test_target_traffic_observation_supports_only_rollout_states(
    stable_percent: int,
    candidate_percent: int,
    include_zero: bool,
) -> None:
    reader = _Reader(
        _state(stable_percent, candidate_percent, include_zero=include_zero)
    )

    result = asyncio.run(
        _traffic_service(reader).observe(
            _traffic_request(),
            _context(CallerRole.COORDINATOR),
        )
    )

    traffic = {item.revision: item.percent for item in result.traffic}
    assert traffic.get(STABLE, 0) == stable_percent
    assert traffic.get(CANDIDATE, 0) == candidate_percent
    assert result.traffic == result.traffic_statuses
    assert result.service_generation == 7
    assert result.provider_etag == "service-etag-7"
    assert result.observed_by == VERIFIER_IDENTITY
    projection = TargetConfigurationProjection(
        target=_target(),
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=8,
    )
    assert result.target_configuration_sha256 == (
        target_configuration_projection_sha256(projection)
    )
    assert reader.calls == ["target"]


@pytest.mark.parametrize(
    "failure",
    [
        "reconciling",
        "unready",
        "status",
        "extra",
        "revision_unready",
        "revision_concurrency",
    ],
)
def test_target_traffic_observation_rejects_unsafe_or_ambiguous_state(
    failure: str,
) -> None:
    state = _state()
    service = state.service
    if failure == "reconciling":
        service = replace(service, reconciling=True)
    elif failure == "unready":
        service = replace(service, ready_state=CloudRunReadyState.NOT_READY)
    elif failure == "status":
        service = replace(
            service,
            traffic_statuses=(
                CloudRunTrafficStatus(
                    revision=STABLE,
                    percent=100,
                    tag=None,
                    uri=None,
                ),
            ),
        )
    elif failure == "extra":
        service = replace(
            service,
            traffic=(
                service.traffic[0],
                CloudRunTrafficAllocation(
                    revision="controlgraph-reference-target-rogue-v1",
                    percent=10,
                    tag=None,
                ),
            ),
            traffic_statuses=(
                service.traffic_statuses[0],
                CloudRunTrafficStatus(
                    revision="controlgraph-reference-target-rogue-v1",
                    percent=10,
                    tag=None,
                    uri=None,
                ),
            ),
        )
    stable_revision = state.stable_revision
    if failure == "revision_unready":
        stable_revision = replace(
            stable_revision,
            ready_state=CloudRunReadyState.NOT_READY,
        )
    elif failure == "revision_concurrency":
        stable_revision = replace(
            stable_revision,
            concurrency=9,
            configuration=replace(stable_revision.configuration, concurrency=9),
        )
    reader = _Reader(
        replace(state, service=service, stable_revision=stable_revision)
    )

    with pytest.raises(OperatorObservationError) as denied:
        asyncio.run(
            _traffic_service(reader).observe(
                _traffic_request(),
                _context(CallerRole.COORDINATOR),
            )
        )
    assert denied.value.code is OperatorObservationErrorCode.TARGET_STATE_DENIED


def test_verified_apply_receipt_returns_exact_promotion_locator() -> None:
    receipt = _receipt()
    store = _Store(StoredRecord(receipt, 2))
    invocation = _invocation(_receipt_command(receipt))
    assert type(invocation) is ExecutionReceiptReadInvocationV1

    result = asyncio.run(
        _relay(store).read_receipt(invocation, _context(CallerRole.API))
    )

    assert result.receipt == receipt
    assert result.receipt_sha256 == canonical_sha256(receipt)
    assert result.verified_apply_receipt is not None
    assert result.verified_apply_receipt.receipt_id == receipt.receipt_id
    assert result.verified_apply_receipt.receipt_sha256 == canonical_sha256(receipt)
    assert (
        decode_contract(canonical_json_bytes(result), ExecutionReceiptReadResultV1)
        == result
    )


def test_stale_promotion_denial_is_readable_without_promotion_locator() -> None:
    receipt = _receipt(
        action=CapabilityAction.PROMOTE_CANDIDATE,
        outcome=ReceiptOutcome.DENIED,
        reason_code=ReasonCode.EPOCH_MISMATCH,
        observed_epoch=2,
    )
    invocation = _invocation(_receipt_command(receipt))
    assert type(invocation) is ExecutionReceiptReadInvocationV1

    result = asyncio.run(
        _relay(_Store(StoredRecord(receipt, 1))).read_receipt(
            invocation,
            _context(CallerRole.API),
        )
    )

    assert result.receipt.reason_code is ReasonCode.EPOCH_MISMATCH
    assert result.receipt.observed_authority_epoch == 2
    assert result.receipt.evidence_ids == ("evidence-execution-001",)
    assert result.verified_apply_receipt is None


@pytest.mark.parametrize("case", ["missing", "binding", "receipt_id"])
def test_receipt_absence_and_every_exact_binding_mismatch_share_one_denial(
    case: str,
) -> None:
    receipt = _receipt(
        receipt_id=("misidentified-receipt" if case == "receipt_id" else None)
    )
    command = _receipt_command(receipt)
    if case == "binding":
        command = command.model_copy(update={"capability_sha256": "9" * 64})
    stored = None if case == "missing" else StoredRecord(receipt, 2)
    invocation = _invocation(command)
    assert type(invocation) is ExecutionReceiptReadInvocationV1

    with pytest.raises(OperatorObservationError) as denied:
        asyncio.run(
            _relay(_Store(stored)).read_receipt(
                invocation,
                _context(CallerRole.API),
            )
        )
    assert denied.value.code is OperatorObservationErrorCode.RECEIPT_NOT_FOUND


def test_receipt_contract_admits_recovery_and_rejects_misidentified_result() -> None:
    receipt = _receipt()
    recovery_command = ExecutionReceiptReadCommandV1(
        **{
            **_receipt_command(receipt).model_dump(mode="python"),
            "action": CapabilityAction.RECOVER_STABLE,
        }
    )
    assert recovery_command.action is CapabilityAction.RECOVER_STABLE

    result = asyncio.run(
        _relay(_Store(StoredRecord(receipt, 2))).read_receipt(
            _invocation(_receipt_command(receipt)),  # type: ignore[arg-type]
            _context(CallerRole.API),
        )
    )
    values = result.model_dump(mode="json")
    values["receipt"]["receipt_id"] = "misidentified-receipt"
    values["verified_apply_receipt"]["receipt_id"] = "misidentified-receipt"
    with pytest.raises(ValidationError):
        ExecutionReceiptReadResultV1.model_validate(values)


def test_clients_forward_only_canonical_invocations_and_reject_digest_substitution() -> None:
    snapshot_result = asyncio.run(
        _snapshot_service(_Reader(_state(100, 0, include_zero=False))).capture(
            _snapshot_request(),
            _context(CallerRole.COORDINATOR),
        )
    )
    snapshot_transport = _Transport(canonical_json_bytes(snapshot_result))
    api = ApiOperatorObservationClient(
        route=_route(CallerRole.API, ServiceRole.COORDINATOR),
        authentication_policy=_policy(ServiceRole.API),
        transport=snapshot_transport,
    )

    assert (
        asyncio.run(
            api.capture_snapshot(_snapshot_command(), _context(CallerRole.OPERATOR))
        )
        == snapshot_result
    )
    forwarded = decode_contract(
        snapshot_transport.calls[0][1],
        StableSnapshotCaptureInvocationV1,
    )
    assert forwarded.operator_identity == OPERATOR_EMAIL

    traffic_result = asyncio.run(
        _traffic_service(_Reader(_state())).observe(
            _traffic_request(),
            _context(CallerRole.COORDINATOR),
        )
    )
    traffic_transport = _Transport(
        canonical_json_bytes(
            traffic_result.model_copy(
                update={"target_configuration_sha256": "f" * 64}
            )
        )
    )
    traffic_client = CoordinatorTargetTrafficClient(
        target=_target(),
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
        concurrency=8,
        route=_route(CallerRole.COORDINATOR, ServiceRole.VERIFIER),
        transport=traffic_transport,
    )
    with pytest.raises(OperatorObservationError) as invalid:
        asyncio.run(traffic_client.observe(_traffic_command()))
    assert invalid.value.code is OperatorObservationErrorCode.RESPONSE_INVALID


def test_api_http_route_authenticates_and_returns_canonical_traffic_observation() -> None:
    result = asyncio.run(
        _traffic_service(_Reader(_state())).observe(
            _traffic_request(),
            _context(CallerRole.COORDINATOR),
        )
    )
    client = ApiOperatorObservationClient(
        route=_route(CallerRole.API, ServiceRole.COORDINATOR),
        authentication_policy=_policy(ServiceRole.API),
        transport=_Transport(canonical_json_bytes(result)),
    )
    app = create_service_app(
        ServiceRole.API,
        authenticator=_Authenticator(
            _policy(ServiceRole.API),
            _context(CallerRole.OPERATOR),
        ),
        authentication_policy=_policy(ServiceRole.API),
        api_operator_observation_client=client,
    )

    response = TestClient(app).post(
        "/v1/operator/commands",
        headers={
            CONTROLGRAPH_AUTHORIZATION_HEADER: "Bearer synthetic.observation.token",
            SERVERLESS_AUTHORIZATION_HEADER: (
                "bearer synthetic.observation.SIGNATURE_REMOVED_BY_GOOGLE"
            ),
        },
        content=canonical_json_bytes(_traffic_command()),
    )

    assert response.status_code == 200
    assert decode_contract(response.content, TargetTrafficReadResultV1) == result


def test_coordinator_http_receipt_mismatch_is_one_payload_free_not_found() -> None:
    receipt = _receipt()
    relay = _relay(_Store(None))
    invocation = _invocation(_receipt_command(receipt))
    assert type(invocation) is ExecutionReceiptReadInvocationV1
    app = create_service_app(
        ServiceRole.COORDINATOR,
        authenticator=_Authenticator(
            _policy(ServiceRole.COORDINATOR),
            _context(CallerRole.API),
        ),
        authentication_policy=_policy(ServiceRole.COORDINATOR),
        coordinator_operator_observation_relay=relay,
    )

    response = TestClient(app).post(
        "/v1/internal/coordinate",
        headers={"Authorization": "Bearer synthetic.observation.token"},
        content=canonical_json_bytes(invocation),
    )

    assert response.status_code == 404
    assert response.json()["code"] == (
        OperatorObservationErrorCode.RECEIPT_NOT_FOUND.value
    )
    assert set(response.json()) == {"code", "correlation_id"}


def test_verifier_http_route_returns_two_read_snapshot_without_provider_details() -> None:
    reader = _Reader(_state(100, 0, include_zero=False))
    app = create_service_app(
        ServiceRole.VERIFIER,
        authenticator=_Authenticator(
            _policy(ServiceRole.VERIFIER),
            _context(CallerRole.COORDINATOR),
        ),
        authentication_policy=_policy(ServiceRole.VERIFIER),
        stable_snapshot_capture_service=_snapshot_service(reader),
    )

    response = TestClient(app).post(
        "/v1/internal/verify",
        headers={"Authorization": "Bearer synthetic.observation.token"},
        content=canonical_json_bytes(_snapshot_request()),
    )

    assert response.status_code == 200
    result = decode_contract(response.content, StableSnapshotCaptureResultV1)
    assert result.snapshot.captured_by == VERIFIER_IDENTITY
    assert reader.calls == ["service", f"revision:{STABLE}", "service"]


def test_runtime_composes_observation_components_for_all_three_roles() -> None:
    api = create_runtime_service_app(
        ServiceRole.API,
        environment=_runtime_environment(ServiceRole.API),
        internal_transport=_Transport(b"unused"),
    )
    verifier = create_runtime_service_app(
        ServiceRole.VERIFIER,
        environment=_runtime_environment(ServiceRole.VERIFIER),
        internal_transport=_Transport(b"unused"),
    )
    coordinator = create_runtime_service_app(
        ServiceRole.COORDINATOR,
        environment=_runtime_environment(ServiceRole.COORDINATOR),
        internal_transport=_Transport(b"unused"),
        kms_client=object(),
        authority_store=cast(AuthorityStore, _RuntimeStore(None)),
        task_enqueuer=cast(TaskEnqueuer, _NeverTaskEnqueuer()),
    )

    assert isinstance(
        api.state.controlgraph_operator_observation_client,
        ApiOperatorObservationClient,
    )
    assert isinstance(api.state.controlgraph_timeline_read, ApiTimelineClient)
    assert api.state.controlgraph_timeline_raw_export is api.state.controlgraph_timeline_read
    assert isinstance(
        verifier.state.controlgraph_stable_snapshot_capture,
        StableSnapshotCaptureService,
    )
    assert isinstance(
        verifier.state.controlgraph_target_traffic_observation,
        TargetTrafficObservationService,
    )
    assert isinstance(
        verifier.state.controlgraph_independent_verification,
        IndependentVerificationService,
    )
    assert isinstance(
        coordinator.state.controlgraph_independent_verification_client,
        CoordinatorIndependentVerificationClient,
    )
    assert isinstance(
        coordinator.state.controlgraph_completion_classification,
        CoordinatorCompletionClassificationService,
    )
    assert (
        coordinator.state.controlgraph_independent_verification_client._timeline_recorder
        is None
    )
    assert (
        coordinator.state.controlgraph_completion_classification._timeline_recorder
        is None
    )
    assert (
        coordinator.state.controlgraph_completion_workflow._timeline_recorder
        is coordinator.state.controlgraph_timeline_recorder
    )
    assert isinstance(
        coordinator.state.controlgraph_operator_observation_relay,
        CoordinatorOperatorObservationRelay,
    )
    assert isinstance(
        coordinator.state.controlgraph_timeline_relay,
        CoordinatorTimelineRelay,
    )
