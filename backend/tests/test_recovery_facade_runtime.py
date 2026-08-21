from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from recovery_v2_test_data import RecoveryV2Bundle, make_unhealthy_v3_recovery_bundle
from test_recovery_worker_boundary import (
    _PrestateVerifier,
    _RootReader,
    _signed_task,
    _source_receipt,
    _trust_verifier,
)

from controlgraph_canary.application.authority_store import (
    ReceiptClaimConflict,
    ReceiptClaimResult,
    StoredRecord,
)
from controlgraph_canary.application.identity import (
    RECEIPT_AUTHORITY_PATH,
    RECOVERY_EXECUTION_FACADE_PATH,
    RECOVERY_RECEIPT_AUTHORITY_PATH,
    AuthenticationContext,
    CallerRole,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.receipt_authority import ReceiptAuthorityService
from controlgraph_canary.application.receipt_execution import (
    ReceiptExecutionDenied,
    ReceiptExecutionStored,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.receipt_authority import (
    ReceiptAuthorityOperation,
    ReceiptAuthorityRequestV1,
)
from controlgraph_canary.contracts.recovery_execution import RecoveryTaskRequestV2
from controlgraph_canary.contracts.storage import execution_receipt_logical_id
from controlgraph_canary.http.receipt import (
    DeniedReceiptTaskResponse,
    RecoveryExecutorClient,
    StoredReceiptTaskResponse,
)
from controlgraph_canary.integrations.google import cloud_run as cloud_run_integration
from controlgraph_canary.services import runtime

PROJECT_ID = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
EXECUTOR_AUDIENCE = (
    f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
)
RECOVERY_AUDIENCE = (
    f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
)
COORDINATOR_AUDIENCE = (
    f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
)


def _utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _environment(role: ServiceRole, bundle: RecoveryV2Bundle) -> dict[str, str]:
    common = {
        "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_SERVICE_NAME": f"controlgraph-{role.value}",
        "CONTROLGRAPH_CONTROLLER_ID": f"{PROJECT_ID}:us-central1:{role.value}",
        "CONTROLGRAPH_ROLE": role.value,
        "CONTROLGRAPH_BUILD_DIGEST": f"sha256:{'a' * 64}",
        "CONTROLGRAPH_CONTRACT_VERSION": "controlgraph.contract/v1",
        "CONTROLGRAPH_FIRESTORE_DATABASE": "controlgraph-authority",
        "CONTROLGRAPH_MUTATIONS_ENABLED": "true",
        "CONTROLGRAPH_ENVIRONMENT": "nonprod",
        "CONTROLGRAPH_CAPABILITY_KEY_VERSION": (
            bundle.task.capability.claims.signing_key_version
        ),
        "CONTROLGRAPH_EVIDENCE_KEY_VERSION": (
            bundle.prestate_attestation.signing_key_version
        ),
    }
    if role is ServiceRole.RECOVERY:
        common.update(
            {
                "CONTROLGRAPH_AUTH_AUDIENCE": RECOVERY_AUDIENCE,
                "CONTROLGRAPH_AUTH_CALLER_ROLE": "recovery_task_caller",
                "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
                    f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_AUTH_CALLER_SUBJECT": SUBJECT,
                "CONTROLGRAPH_EXECUTOR_URL": EXECUTOR_AUDIENCE,
            }
        )
        return common
    if role is not ServiceRole.EXECUTOR:
        raise AssertionError("test environment only supports recovery composition")
    common.update(
        {
            "CONTROLGRAPH_AUTH_AUDIENCE": EXECUTOR_AUDIENCE,
            "CONTROLGRAPH_AUTH_CALLER_ROLE": "execution_task_caller",
            "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
                f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_AUTH_CALLER_SUBJECT": SUBJECT,
            "CONTROLGRAPH_COORDINATOR_URL": COORDINATOR_AUDIENCE,
            "CONTROLGRAPH_TARGET_NETWORK_RESOURCE": (
                f"projects/{PROJECT_ID}/global/networks/controlgraph-network"
            ),
            "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE": (
                f"projects/{PROJECT_ID}/regions/us-central1/"
                "subnetworks/controlgraph-runtime"
            ),
            "CONTROLGRAPH_RECOVERY_FACADE_CALLER_EMAIL": (
                f"controlgraph-recovery@{PROJECT_ID}.iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_RECOVERY_FACADE_CALLER_SUBJECT": SUBJECT,
        }
    )
    return common


def _install_recovery_verifiers(
    monkeypatch: pytest.MonkeyPatch,
    bundle: RecoveryV2Bundle,
    private_key: ec.EllipticCurvePrivateKey,
) -> _PrestateVerifier:
    trust = _trust_verifier(
        private_key,
        bundle.task.capability.claims.signing_key_version,
    )
    prestate = _PrestateVerifier(bundle.prestate_attestation)

    class _TrustLoader:
        def __init__(self, **_: object) -> None:
            pass

        def load(self):  # type: ignore[no-untyped-def]
            return trust

    def prestate_verifier(**_: object) -> _PrestateVerifier:
        return prestate

    monkeypatch.setattr(runtime, "GoogleKmsCapabilityTrustLoader", _TrustLoader)
    monkeypatch.setattr(
        runtime,
        "GoogleKmsRecoveryPrestateAttestationVerifier",
        prestate_verifier,
    )
    return prestate


def _identity_claims(*, audience: str, email: str, now: datetime) -> dict[str, object]:
    return {
        "iss": "https://accounts.google.com",
        "aud": audience,
        "email": email,
        "email_verified": True,
        "sub": SUBJECT,
        "iat": int((now - timedelta(minutes=1)).timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }


class _StaticTransport:
    def __init__(self, response: bytes | Exception) -> None:
        self._response = response
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


class _ConflictReceiptStore:
    def __init__(self, target: TargetBinding) -> None:
        self.target = target
        self.claims = 0

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        del receipt, binding
        self.claims += 1
        return ReceiptClaimConflict()

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        del idempotency_key
        raise AssertionError("claim conflict must stop before receipt reads")

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        del expected, replacement
        raise AssertionError("claim conflict must stop before receipt updates")


class _RecoveryReceiptTransport:
    def __init__(self, service: ReceiptAuthorityService, now: datetime) -> None:
        self._service = service
        self._caller = AuthenticationContext(
            role=CallerRole.EXECUTOR,
            email=f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com",
            subject=SUBJECT,
            issuer="https://accounts.google.com",
            audience=COORDINATOR_AUDIENCE,
            issued_at=int((now - timedelta(minutes=1)).timestamp()),
            expires_at=int((now + timedelta(minutes=5)).timestamp()),
        )
        self.calls: list[tuple[CoordinatorInternalRoute, ReceiptAuthorityRequestV1]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        request = ReceiptAuthorityRequestV1.model_validate_json(body)
        self.calls.append((route, request))
        if (
            route.path != RECOVERY_RECEIPT_AUTHORITY_PATH
            or route.path == RECEIPT_AUTHORITY_PATH
            or route.caller_role is not CallerRole.EXECUTOR
            or route.service_role is not ServiceRole.COORDINATOR
        ):
            raise AssertionError("recovery execution used the wrong receipt authority route")
        return await self._service.handle_recovery_authenticated(body, self._caller)


def _facade_route(target: TargetBinding) -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=target.project_id,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.RECOVERY,
        service_role=ServiceRole.EXECUTOR,
        audience=EXECUTOR_AUDIENCE,
        override_path=RECOVERY_EXECUTION_FACADE_PATH,
    )


def _recovery_receipt(
    task: RecoveryTaskRequestV2,
    *,
    outcome: ReceiptOutcome = ReceiptOutcome.VERIFIED,
) -> ExecutionReceipt:
    intent = task.intent
    binding = MutationBinding(
        idempotency_key=intent.idempotency_key,
        request_id=intent.request_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=MutationAction.RECOVER_STABLE,
        target=MutationTargetKey(
            project_id=intent.target.project_id,
            region=intent.target.region,
            environment=intent.target.environment,
            service_name=intent.target.service_name,
        ),
        provider_precondition=intent.provider_etag,
        plan_sha256=intent.plan_sha256,
        capability_sha256=canonical_sha256(task.capability),
        payload_sha256=canonical_sha256(task),
        expected_poststate_sha256=intent.desired_poststate_sha256,
    )
    return ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(intent.target, intent.idempotency_key),
        request_id=intent.request_id,
        idempotency_key=intent.idempotency_key,
        capability_sha256=binding.capability_sha256,
        mutation_sha256=mutation_identity(binding),
        plan_sha256=intent.plan_sha256,
        expected_poststate_sha256=intent.desired_poststate_sha256,
        target=intent.target,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=CapabilityAction.RECOVER_STABLE,
        provider_etag=intent.provider_etag,
        dispatch_not_after=task.expires_at,
        outcome=outcome,
        reason_code=None,
        provider_operation=(
            "operations/recover-stable" if outcome is ReceiptOutcome.APPLIED else None
        ),
        observed_etag=("etag-recovered" if outcome is ReceiptOutcome.VERIFIED else None),
        observed_authority_epoch=(
            intent.epoch
            if outcome in {ReceiptOutcome.APPLIED, ReceiptOutcome.VERIFIED}
            else None
        ),
        created_at=task.scheduled_at,
        updated_at=task.scheduled_at,
        evidence_ids=(),
    )


def _replace_receipt(
    receipt: ExecutionReceipt,
    **changes: object,
) -> ExecutionReceipt:
    return ExecutionReceipt.model_validate(
        {
            **receipt.model_dump(mode="python"),
            **changes,
        }
    )


def test_recovery_runtime_only_forwards_to_the_exact_executor_facade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    private_key = ec.generate_private_key(ec.SECP256R1())
    task = _signed_task(bundle, private_key)
    now = _utc(task.scheduled_at) + timedelta(seconds=1)
    reader = _RootReader(bundle)
    prestate = _install_recovery_verifiers(monkeypatch, bundle, private_key)
    response_body = canonical_json_bytes(
        DeniedReceiptTaskResponse(code=ReasonCode.IDEMPOTENCY_CONFLICT)
    )
    transport = _StaticTransport(response_body)
    cloud_run_constructions: list[str] = []

    def forbidden_cloud_run(*_: object, **__: object) -> None:
        cloud_run_constructions.append("constructed")
        raise AssertionError("the recovery worker must not compose Cloud Run dependencies")

    monkeypatch.setattr(
        cloud_run_integration,
        "CloudRunV2Adapter",
        forbidden_cloud_run,
    )
    monkeypatch.setattr(
        cloud_run_integration,
        "CloudRunV2ReceiptReadback",
        forbidden_cloud_run,
    )

    def verify_token(token: str, audience: str) -> dict[str, object]:
        assert token == "recovery.task.token"
        assert audience == RECOVERY_AUDIENCE
        return _identity_claims(
            audience=audience,
            email=f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com",
            now=now,
        )

    app = runtime.create_runtime_service_app(
        ServiceRole.RECOVERY,
        environment=_environment(ServiceRole.RECOVERY, bundle),
        token_verifier=verify_token,
        clock=lambda: now.timestamp(),
        kms_client=object(),
        internal_transport=transport,
        authority_store=reader,
        capability_verification_clock=lambda: now,
    )

    with TestClient(app) as client:
        response = client.post(
            protected_path(ServiceRole.RECOVERY),
            content=canonical_json_bytes(task),
            headers={
                "Authorization": "Bearer recovery.task.token",
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 409
    assert response.json() == {
        "schema_version": "controlgraph.receipt-task-denial/v1",
        "code": ReasonCode.IDEMPOTENCY_CONFLICT.value,
    }
    assert reader.reads == [bundle.root.root_id]
    assert prestate.calls == [bundle.prestate_attestation]
    assert cloud_run_constructions == []
    assert not hasattr(app.state, "controlgraph_recovery_executor_facade")
    assert len(transport.calls) == 1
    route, body = transport.calls[0]
    assert route == _facade_route(bundle.root.content.target)
    assert body == canonical_json_bytes(task)


def test_executor_facade_uses_recovery_policy_and_recovery_receipt_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    private_key = ec.generate_private_key(ec.SECP256R1())
    task = _signed_task(bundle, private_key)
    now = _utc(task.scheduled_at) + timedelta(seconds=1)
    reader = _RootReader(bundle)
    prestate = _install_recovery_verifiers(monkeypatch, bundle, private_key)
    backing = _ConflictReceiptStore(bundle.root.content.target)
    transport = _RecoveryReceiptTransport(ReceiptAuthorityService(backing), now)
    provider_calls: list[str] = []

    def forbidden_provider() -> None:
        provider_calls.append("called")
        raise AssertionError("claim conflict must stop before Cloud Run")

    def verify_token(token: str, audience: str) -> dict[str, object]:
        assert token == "recovery.facade.token"
        assert audience == EXECUTOR_AUDIENCE
        return _identity_claims(
            audience=audience,
            email=f"controlgraph-recovery@{PROJECT_ID}.iam.gserviceaccount.com",
            now=now,
        )

    app = runtime.create_runtime_service_app(
        ServiceRole.EXECUTOR,
        environment=_environment(ServiceRole.EXECUTOR, bundle),
        token_verifier=verify_token,
        clock=lambda: now.timestamp(),
        kms_client=object(),
        internal_transport=transport,
        services_client_factory=forbidden_provider,
        revisions_client_factory=forbidden_provider,
        readback_services_client_factory=forbidden_provider,
        authority_store=reader,
        final_authority_clock=lambda: now,
        receipt_clock=lambda: now,
        capability_verification_clock=lambda: now,
    )
    payload = canonical_json_bytes(task)
    headers = {
        "Authorization": "Bearer recovery.facade.token",
        "Content-Type": "application/json",
    }

    with TestClient(app) as client:
        direct = client.post(
            protected_path(ServiceRole.EXECUTOR),
            content=payload,
            headers=headers,
        )
        facade = client.post(
            RECOVERY_EXECUTION_FACADE_PATH,
            content=payload,
            headers=headers,
        )

    assert direct.status_code == 403
    assert direct.json()["code"] == "AUTH_CALLER_DENIED"
    assert facade.status_code == 200
    assert facade.json()["code"] == ReasonCode.IDEMPOTENCY_CONFLICT.value
    assert callable(app.state.controlgraph_recovery_executor_facade)
    assert reader.reads == [bundle.root.root_id]
    assert prestate.calls == [bundle.prestate_attestation]
    assert backing.claims == 1
    assert provider_calls == []
    assert len(transport.calls) == 1
    route, request = transport.calls[0]
    assert route.path == RECOVERY_RECEIPT_AUTHORITY_PATH
    assert route.path != RECEIPT_AUTHORITY_PATH
    assert route.caller_role is CallerRole.EXECUTOR
    assert request.operation is ReceiptAuthorityOperation.CLAIM
    assert request.claim is not None
    assert request.claim.receipt.action is CapabilityAction.RECOVER_STABLE


def test_recovery_executor_client_decodes_only_canonical_facade_responses() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    target = bundle.root.content.target
    payload = canonical_json_bytes(bundle.task)
    recovery_receipt = _recovery_receipt(bundle.task)
    stored_body = canonical_json_bytes(
        StoredReceiptTaskResponse(receipt=recovery_receipt, storage_revision=2)
    )
    denied_body = canonical_json_bytes(
        DeniedReceiptTaskResponse(code=ReasonCode.IDEMPOTENCY_CONFLICT)
    )
    stored_transport = _StaticTransport(stored_body)
    denied_transport = _StaticTransport(denied_body)

    stored = asyncio.run(
        RecoveryExecutorClient(
            target=target,
            route=_facade_route(target),
            transport=stored_transport,
        ).execute(payload)
    )
    denied = asyncio.run(
        RecoveryExecutorClient(
            target=target,
            route=_facade_route(target),
            transport=denied_transport,
        ).execute(payload)
    )

    assert stored == ReceiptExecutionStored(
        receipt=StoredRecord(recovery_receipt, 2),
        reason_code=None,
    )
    assert denied == ReceiptExecutionDenied(ReasonCode.IDEMPOTENCY_CONFLICT)
    assert stored_transport.calls == [(_facade_route(target), payload)]
    assert denied_transport.calls == [(_facade_route(target), payload)]


def test_recovery_executor_client_fails_closed_on_transport_or_invalid_response() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    target = bundle.root.content.target
    payload = canonical_json_bytes(bundle.task)
    failed_transport = _StaticTransport(RuntimeError("sensitive transport detail"))
    invalid_transport = _StaticTransport(b'{"schema_version":"unknown/v1"}')

    failed = asyncio.run(
        RecoveryExecutorClient(
            target=target,
            route=_facade_route(target),
            transport=failed_transport,
        ).execute(payload)
    )
    invalid = asyncio.run(
        RecoveryExecutorClient(
            target=target,
            route=_facade_route(target),
            transport=invalid_transport,
        ).execute(payload)
    )

    assert failed == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
    assert invalid == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
    assert len(failed_transport.calls) == 1
    assert len(invalid_transport.calls) == 1


def test_recovery_executor_client_rejects_a_substituted_apply_receipt() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    target = bundle.root.content.target
    payload = canonical_json_bytes(bundle.task)
    response = canonical_json_bytes(
        StoredReceiptTaskResponse(
            receipt=_source_receipt(bundle),
            storage_revision=2,
        )
    )
    transport = _StaticTransport(response)

    result = asyncio.run(
        RecoveryExecutorClient(
            target=target,
            route=_facade_route(target),
            transport=transport,
        ).execute(payload)
    )

    assert result == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
    assert transport.calls == [(_facade_route(target), payload)]


def test_recovery_executor_client_rejects_every_mismatched_receipt_binding() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    task = bundle.task
    target = bundle.root.content.target
    payload = canonical_json_bytes(task)
    receipt = _recovery_receipt(task)
    other_target = target.model_copy(update={"service_name": "other-service"})
    substitutions: tuple[dict[str, object], ...] = (
        {"receipt_id": "cgreceipt:substituted"},
        {"request_id": "substituted-request"},
        {"idempotency_key": "substituted-idempotency"},
        {"capability_sha256": "1" * 64},
        {"mutation_sha256": "2" * 64},
        {"plan_sha256": "3" * 64},
        {"expected_poststate_sha256": "4" * 64},
        {"target": other_target},
        {"root_id": "cgroot:substituted"},
        {"root_sha256": "5" * 64},
        {"epoch": task.intent.epoch + 1},
        {"action": CapabilityAction.APPLY_CANARY},
        {"provider_etag": "substituted-etag"},
        {"dispatch_not_after": task.intent.proof_valid_until},
    )

    for substitution in substitutions:
        substituted = _replace_receipt(receipt, **substitution)
        transport = _StaticTransport(
            canonical_json_bytes(
                StoredReceiptTaskResponse(
                    receipt=substituted,
                    storage_revision=2,
                )
            )
        )
        result = asyncio.run(
            RecoveryExecutorClient(
                target=target,
                route=_facade_route(target),
                transport=transport,
            ).execute(payload)
        )

        assert result == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        assert transport.calls == [(_facade_route(target), payload)]


def test_recovery_executor_client_rejects_invalid_storage_outcome_pairs() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    task = bundle.task
    target = bundle.root.content.target
    payload = canonical_json_bytes(task)
    invalid_pairs = (
        (_recovery_receipt(task), 1),
        (_recovery_receipt(task, outcome=ReceiptOutcome.CLAIMED), 1),
        (_recovery_receipt(task, outcome=ReceiptOutcome.APPLIED), 1),
    )

    for receipt, storage_revision in invalid_pairs:
        transport = _StaticTransport(
            canonical_json_bytes(
                StoredReceiptTaskResponse(
                    receipt=receipt,
                    storage_revision=storage_revision,
                )
            )
        )
        result = asyncio.run(
            RecoveryExecutorClient(
                target=target,
                route=_facade_route(target),
                transport=transport,
            ).execute(payload)
        )

        assert result == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        assert transport.calls == [(_facade_route(target), payload)]


def test_recovery_runtime_maps_a_substituted_receipt_to_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    private_key = ec.generate_private_key(ec.SECP256R1())
    task = _signed_task(bundle, private_key)
    now = _utc(task.scheduled_at) + timedelta(seconds=1)
    reader = _RootReader(bundle)
    _install_recovery_verifiers(monkeypatch, bundle, private_key)
    transport = _StaticTransport(
        canonical_json_bytes(
            StoredReceiptTaskResponse(
                receipt=_source_receipt(bundle),
                storage_revision=2,
            )
        )
    )

    def verify_token(token: str, audience: str) -> dict[str, object]:
        assert token == "recovery.task.token"
        assert audience == RECOVERY_AUDIENCE
        return _identity_claims(
            audience=audience,
            email=f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com",
            now=now,
        )

    app = runtime.create_runtime_service_app(
        ServiceRole.RECOVERY,
        environment=_environment(ServiceRole.RECOVERY, bundle),
        token_verifier=verify_token,
        clock=lambda: now.timestamp(),
        kms_client=object(),
        internal_transport=transport,
        authority_store=reader,
        capability_verification_clock=lambda: now,
    )

    with TestClient(app) as client:
        response = client.post(
            protected_path(ServiceRole.RECOVERY),
            content=canonical_json_bytes(task),
            headers={
                "Authorization": "Bearer recovery.task.token",
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 503
    assert response.json() == {
        "schema_version": "controlgraph.receipt-task-denial/v1",
        "code": ReasonCode.AUTHORITY_UNAVAILABLE.value,
    }
    assert transport.calls == [
        (_facade_route(bundle.root.content.target), canonical_json_bytes(task))
    ]
