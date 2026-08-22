from __future__ import annotations

import argparse
import asyncio
import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from root_v2_test_data import make_root_v3_records
from test_evidence_writer import _FakeKmsClient
from test_m2_firestore_authority_store import (
    _FakeClient,
    _FakeTransactionRunner,
    _Reference,
    _StoredDocument,
)
from test_operator_cli import _Poster, _Runner
from test_operator_observability import (
    _NeverTaskEnqueuer,
    _runtime_environment,
    _RuntimeStore,
    _Transport,
)
from test_recovery_abandonment import (
    _coordinator_policy,
    _late_epoch_denial,
    _operator_policy,
    _principal,
    _run_first_stage,
    _run_released_stage,
    _signed_event,
    _Store,
)
from test_service_claim_classification import (
    _classification_policy,
    _DigestBackend,
    _service_state,
)
from test_service_claim_classification import _context as _classification_context
from test_service_claim_classification import (
    _coordinator_policy as _verifier_policy,
)

from controlgraph_canary.application.authority_store import (
    AuthorityStore,
    AuthorityStoreConflict,
    AuthorityStoreUnavailable,
    StoredRecord,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
)
from controlgraph_canary.application.identity import (
    CLASSIFICATION_EVIDENCE_PATH,
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.recovery_abandonment import RecoveryAbandoner
from controlgraph_canary.application.recovery_abandonment_relay import (
    ApiRecoveryAbandonmentClient,
    CoordinatorRecoveryAbandonmentRelay,
)
from controlgraph_canary.application.recovery_abandonment_store import (
    RecoveryAbandonmentState,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.service_claim_classification import (
    ServiceClaimClassificationService,
)
from controlgraph_canary.application.service_claim_classification_signing import (
    ClassificationEvidenceSigningService,
)
from controlgraph_canary.application.signing import AsyncPurposeSealedSigner
from controlgraph_canary.application.tasks import TaskEnqueuer
from controlgraph_canary.cli import _run_recovery_abandonment
from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.health_storage import (
    HealthStorageKind,
    create_recovery_dispatch_storage_record,
    recovery_dispatch_document_id,
    recovery_dispatch_identity_document_id,
    recovery_dispatch_identity_logical_id,
    recovery_intent_document_id,
)
from controlgraph_canary.contracts.models import ReasonCode, TargetBinding
from controlgraph_canary.contracts.recovery_abandonment import (
    RECOVERY_ABANDONMENT_RELAY_RESPONSE_V1,
    RecoveryAbandonmentClassificationAttestationV1,
    RecoveryAbandonmentClassificationRequestV1,
    RecoveryAbandonmentClassificationSigningRequestV1,
    RecoveryAbandonmentFailureCode,
    RecoveryAbandonmentInvocationV1,
    RecoveryAbandonmentRelayResponseV1,
    RecoveryAbandonmentResultV1,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryDispatchIdentityKind,
    RecoveryDispatchRecordV2,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1
from controlgraph_canary.contracts.storage import (
    AuthorityStorageKind,
    capability_lineage_anchor_document_id,
    capability_lineage_anchor_logical_id,
    epoch_authority_document_id,
    evidence_chain_head_document_id,
    execution_receipt_document_id,
    execution_receipt_logical_id,
    recovery_abandonment_identity_document_id,
    recovery_abandonment_identity_logical_id,
    recovery_abandonment_progress_document_id,
    recovery_abandonment_result_document_id,
    rollout_root_v3_document_id,
    root_creation_result_v2_document_id,
    service_claim_document_id,
    service_claim_logical_id,
    signed_evidence_event_document_id,
)
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.http.service import create_service_app
from controlgraph_canary.integrations.google import firestore as firestore_integration
from controlgraph_canary.integrations.google import (
    firestore_recovery_abandonment as abandonment_integration,
)
from controlgraph_canary.integrations.google.firestore import (
    _document_data,
    _prepared_document,
)
from controlgraph_canary.integrations.google.firestore_health import (
    _recovery_dispatch_identity,
)
from controlgraph_canary.integrations.google.firestore_recovery_abandonment import (
    FirestoreRecoveryAbandonmentStore,
    _health_document_data,
    _prepared_health_document,
)
from controlgraph_canary.integrations.google.internal_transport import InternalHttpResponse
from controlgraph_canary.services.runtime import create_runtime_service_app

_TOKEN = "Bearer synthetic.abandonment.token"


class _Authenticator:
    def __init__(self, context: AuthenticationContext) -> None:
        self.context = context

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        del policy
        assert authorization_header == _TOKEN
        return self.context


def _headers(role: ServiceRole) -> dict[str, str]:
    if role is ServiceRole.API:
        return {
            CONTROLGRAPH_AUTHORIZATION_HEADER: _TOKEN,
            SERVERLESS_AUTHORIZATION_HEADER: (
                "bearer synthetic.abandonment.SIGNATURE_REMOVED_BY_GOOGLE"
            ),
        }
    return {"Authorization": _TOKEN}


def _unsupported(contract: Any) -> bytes:
    values = contract.model_dump(mode="json")
    values["schema_version"] = f"{values['schema_version']}-unsupported"
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _api_context() -> AuthenticationContext:
    policy = _coordinator_policy()
    return AuthenticationContext(
        role=CallerRole.API,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=_principal().issued_at,
        expires_at=_principal().expires_at,
    )


class _AbandonmentTransport:
    def __init__(self, result: RecoveryAbandonmentResultV1) -> None:
        self.result = result
        self.calls: list[tuple[CoordinatorInternalRoute, RecoveryAbandonmentInvocationV1]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        invocation = decode_contract(body, RecoveryAbandonmentInvocationV1)
        self.calls.append((route, invocation))
        return canonical_json_bytes(
            RecoveryAbandonmentRelayResponseV1(
                schema_version=RECOVERY_ABANDONMENT_RELAY_RESPONSE_V1,
                result=self.result,
                failure_code=None,
            )
        )


class _ReturningAbandoner:
    def __init__(self, result: RecoveryAbandonmentResultV1) -> None:
        self.result = result
        self.calls: list[tuple[RecoveryAbandonmentInvocationV1, AuthenticationContext | None]] = []

    async def abandon(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> RecoveryAbandonmentResultV1:
        self.calls.append((invocation, principal))
        return self.result


def test_api_and_coordinator_http_routes_are_exact_and_fail_closed() -> None:
    model_store, _, _, _, result = _run_first_stage()
    command = model_store.state.invocation.command
    transport = _AbandonmentTransport(result)
    route = CoordinatorInternalRoute(
        project_id=_operator_policy().project_id,
        project_number=_operator_policy().project_number,
        caller_role=CallerRole.API,
        service_role=ServiceRole.COORDINATOR,
        audience=_coordinator_policy().audience,
    )
    api_relay = ApiRecoveryAbandonmentClient(
        route=route,
        authentication_policy=_operator_policy(),
        transport=transport,
    )
    api = TestClient(
        create_service_app(
            ServiceRole.API,
            authenticator=_Authenticator(_principal()),
            authentication_policy=_operator_policy(),
            api_recovery_abandonment_client=api_relay,
        )
    )

    response = api.post(
        protected_path(ServiceRole.API),
        headers=_headers(ServiceRole.API),
        content=canonical_json_bytes(command),
    )

    assert response.status_code == 200
    assert decode_contract(response.content, RecoveryAbandonmentResultV1) == result
    assert len(transport.calls) == 1

    wrong_role = TestClient(
        create_service_app(
            ServiceRole.API,
            authenticator=_Authenticator(replace(_principal(), role=CallerRole.API)),
            authentication_policy=_operator_policy(),
            api_recovery_abandonment_client=api_relay,
        )
    ).post(
        protected_path(ServiceRole.API),
        headers=_headers(ServiceRole.API),
        content=canonical_json_bytes(command),
    )
    unsupported = api.post(
        protected_path(ServiceRole.API),
        headers=_headers(ServiceRole.API),
        content=_unsupported(command),
    )

    assert wrong_role.status_code == 403
    assert wrong_role.json()["code"] == RecoveryAbandonmentFailureCode.CALLER_DENIED.value
    assert unsupported.status_code == 400
    assert unsupported.json()["code"] == "CONTRACT_VERSION_UNSUPPORTED"
    assert len(transport.calls) == 1

    application = _ReturningAbandoner(result)
    coordinator_relay = CoordinatorRecoveryAbandonmentRelay(
        authentication_policy=_coordinator_policy(),
        operator_policy=_operator_policy(),
        abandoner=application,
    )
    invocation = model_store.state.invocation
    coordinator = TestClient(
        create_service_app(
            ServiceRole.COORDINATOR,
            authenticator=_Authenticator(_api_context()),
            authentication_policy=_coordinator_policy(),
            coordinator_recovery_abandonment_relay=coordinator_relay,
        )
    )
    accepted = coordinator.post(
        protected_path(ServiceRole.COORDINATOR),
        headers=_headers(ServiceRole.COORDINATOR),
        content=canonical_json_bytes(invocation),
    )

    assert accepted.status_code == 200
    accepted_outcome = decode_contract(accepted.content, RecoveryAbandonmentRelayResponseV1)
    assert accepted_outcome.result == result
    assert accepted_outcome.failure_code is None
    assert len(application.calls) == 1

    wrong_role = TestClient(
        create_service_app(
            ServiceRole.COORDINATOR,
            authenticator=_Authenticator(replace(_api_context(), role=CallerRole.ISSUER)),
            authentication_policy=_coordinator_policy(),
            coordinator_recovery_abandonment_relay=coordinator_relay,
        )
    ).post(
        protected_path(ServiceRole.COORDINATOR),
        headers=_headers(ServiceRole.COORDINATOR),
        content=canonical_json_bytes(invocation),
    )
    unsupported = coordinator.post(
        protected_path(ServiceRole.COORDINATOR),
        headers=_headers(ServiceRole.COORDINATOR),
        content=_unsupported(invocation),
    )

    assert wrong_role.status_code == 200
    denied = decode_contract(wrong_role.content, RecoveryAbandonmentRelayResponseV1)
    assert denied.result is None
    assert denied.failure_code is RecoveryAbandonmentFailureCode.CALLER_DENIED
    assert unsupported.status_code == 400
    assert unsupported.json()["code"] == "CONTRACT_VERSION_UNSUPPORTED"
    assert len(application.calls) == 1


def test_operator_cli_posts_exact_abandonment_and_rejects_bad_responses(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    model_store, _, _, _, result = _run_first_stage()
    command = model_store.state.invocation.command
    command_file = tmp_path / "abandonment-command.json"
    command_file.write_bytes(canonical_json_bytes(command))
    args = argparse.Namespace(
        project_number=_operator_policy().project_number,
        command_file=str(command_file),
    )
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(result),
        )
    )

    assert (
        _run_recovery_abandonment(
            args,
            command_runner=_Runner(),
            http_poster=poster,
        )
        == 0
    )
    assert poster.calls[0]["body"] == canonical_json_bytes(command)
    assert capsys.readouterr().out.strip() == canonical_json_bytes(result).decode()

    for body in (
        b"{}",
        canonical_json_bytes(result.model_copy(update={"request_id": "request-other"})),
    ):
        assert (
            _run_recovery_abandonment(
                args,
                command_runner=_Runner(),
                http_poster=_Poster(
                    InternalHttpResponse(
                        status_code=200,
                        content_type="application/json",
                        body=body,
                    )
                ),
            )
            == 6
        )
        assert capsys.readouterr().out.strip() == (
            '{"code": "RECOVERY_ABANDONMENT_RESPONSE_INVALID"}'
        )


def _classification_request() -> RecoveryAbandonmentClassificationRequestV1:
    store, abandoner, _, classification, _ = _run_first_stage()
    asyncio.run(abandoner.abandon(store.state.invocation, principal=_principal()))
    return classification.calls[0]


class _ClassificationEvidenceClient:
    def __init__(self) -> None:
        self.requests: list[RecoveryAbandonmentClassificationSigningRequestV1] = []
        self.key_version = make_root_v3_records().root.content.evidence_signing_key_version

    async def sign(
        self,
        request: RecoveryAbandonmentClassificationSigningRequestV1,
    ) -> SignedEvidenceEventV1:
        self.requests.append(request)
        return _signed_event(
            request.event,
            self.key_version,
            b"classification-integration-evidence",
        )


def _stable_reader(request: RecoveryAbandonmentClassificationRequestV1) -> Any:
    from test_service_claim_classification import _Reader

    reader = _Reader(request)  # type: ignore[arg-type]
    reader.state = _service_state(
        request,  # type: ignore[arg-type]
        traffic=(
            CloudRunTrafficAllocation(
                revision=request.stable_revision,
                percent=100,
                tag="stable",
            ),
        ),
        traffic_statuses=(
            CloudRunTrafficStatus(
                revision=request.stable_revision,
                percent=100,
                tag="stable",
                uri="https://stable.example.test",
            ),
        ),
    )
    return reader


def test_verifier_and_evidence_writer_http_routes_accept_only_new_exact_contracts() -> None:
    request = _classification_request()
    evidence = _ClassificationEvidenceClient()
    verifier_policy = _verifier_policy()
    verifier_context = _classification_context(CallerRole.COORDINATOR)
    classification_service = ServiceClaimClassificationService(
        authentication_policy=verifier_policy,
        reader_factory=_stable_reader,
        evidence_client=evidence,
        clock=lambda: datetime.fromtimestamp(_principal().issued_at + 62, tz=UTC),
    )
    verifier = TestClient(
        create_service_app(
            ServiceRole.VERIFIER,
            authenticator=_Authenticator(verifier_context),
            authentication_policy=verifier_policy,
            service_claim_classification_service=classification_service,
        )
    )

    response = verifier.post(
        protected_path(ServiceRole.VERIFIER),
        headers=_headers(ServiceRole.VERIFIER),
        content=canonical_json_bytes(request),
    )

    assert response.status_code == 200
    attestation = decode_contract(
        response.content,
        RecoveryAbandonmentClassificationAttestationV1,
    )
    assert attestation.signing_request.result.request == request
    assert evidence.requests == [attestation.signing_request]

    wrong_role = TestClient(
        create_service_app(
            ServiceRole.VERIFIER,
            authenticator=_Authenticator(replace(verifier_context, role=CallerRole.API)),
            authentication_policy=verifier_policy,
            service_claim_classification_service=classification_service,
        )
    ).post(
        protected_path(ServiceRole.VERIFIER),
        headers=_headers(ServiceRole.VERIFIER),
        content=canonical_json_bytes(request),
    )
    unsupported = verifier.post(
        protected_path(ServiceRole.VERIFIER),
        headers=_headers(ServiceRole.VERIFIER),
        content=_unsupported(request),
    )
    assert wrong_role.status_code == 403
    assert wrong_role.json()["code"] == "SERVICE_CLAIM_CLASSIFICATION_CALLER_DENIED"
    assert unsupported.status_code == 400
    assert unsupported.json()["code"] == "CONTRACT_VERSION_UNSUPPORTED"
    assert len(evidence.requests) == 1

    backend = _DigestBackend()
    writer_policy = _classification_policy()
    signer = ClassificationEvidenceSigningService(
        project_id=writer_policy.project_id,
        authentication_policy=writer_policy,
        signer=AsyncPurposeSealedSigner(backend),
    )
    writer_context = _classification_context(CallerRole.VERIFIER)
    writer = TestClient(
        create_service_app(
            ServiceRole.EVIDENCE_WRITER,
            authenticator=_Authenticator(writer_context),
            authentication_policy=writer_policy,
            classification_evidence_signing_service=signer,
            classification_evidence_authentication_policy=writer_policy,
        )
    )
    signed_response = writer.post(
        CLASSIFICATION_EVIDENCE_PATH,
        headers=_headers(ServiceRole.EVIDENCE_WRITER),
        content=canonical_json_bytes(attestation.signing_request),
    )
    assert signed_response.status_code == 200
    signed = decode_contract(signed_response.content, SignedEvidenceEventV1)
    assert signed.event == attestation.signing_request.event
    assert len(backend.calls) == 1

    wrong_role = TestClient(
        create_service_app(
            ServiceRole.EVIDENCE_WRITER,
            authenticator=_Authenticator(replace(writer_context, role=CallerRole.COORDINATOR)),
            authentication_policy=writer_policy,
            classification_evidence_signing_service=signer,
            classification_evidence_authentication_policy=writer_policy,
        )
    ).post(
        CLASSIFICATION_EVIDENCE_PATH,
        headers=_headers(ServiceRole.EVIDENCE_WRITER),
        content=canonical_json_bytes(attestation.signing_request),
    )
    unsupported = writer.post(
        CLASSIFICATION_EVIDENCE_PATH,
        headers=_headers(ServiceRole.EVIDENCE_WRITER),
        content=_unsupported(attestation.signing_request),
    )
    assert wrong_role.status_code == 403
    assert wrong_role.json()["code"] == "AUTH_CALLER_DENIED"
    assert unsupported.status_code == 400
    assert unsupported.json()["code"] == "CONTRACT_VERSION_UNSUPPORTED"
    assert len(backend.calls) == 1


class _RuntimeAbandonmentStore(_RuntimeStore):
    read_recovery_abandonment_state = _RuntimeStore._unreachable
    commit_recovery_abandonment_fence = _RuntimeStore._unreachable
    commit_recovery_abandonment_release = _RuntimeStore._unreachable


def test_runtime_composes_abandonment_across_all_four_service_roles() -> None:
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
    writer_environment = _runtime_environment(ServiceRole.EVIDENCE_WRITER)
    writer_environment.update(
        {
            "CONTROLGRAPH_AUTH_AUDIENCE": (
                f"https://controlgraph-evidence-writer-"
                f"{writer_environment['CONTROLGRAPH_PROJECT_NUMBER']}.us-central1.run.app"
            ),
            "CONTROLGRAPH_AUTH_CALLER_ROLE": CallerRole.COORDINATOR.value,
            "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
                f"controlgraph-coordinator@{writer_environment['CONTROLGRAPH_PROJECT_ID']}"
                ".iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_EVIDENCE_KEY_VERSION": (
                f"projects/{writer_environment['CONTROLGRAPH_PROJECT_ID']}/locations/"
                "us-central1/keyRings/controlgraph-signing/cryptoKeys/evidence-signing/"
                "cryptoKeyVersions/1"
            ),
            "CONTROLGRAPH_SIGNING_ALGORITHM": "EC_SIGN_P256_SHA256",
            "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_EMAIL": (
                f"controlgraph-verifier@{writer_environment['CONTROLGRAPH_PROJECT_ID']}"
                ".iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_SUBJECT": (
                writer_environment["CONTROLGRAPH_AUTH_CALLER_SUBJECT"]
            ),
        }
    )
    writer = create_runtime_service_app(
        ServiceRole.EVIDENCE_WRITER,
        environment=writer_environment,
        kms_client=_FakeKmsClient(),
    )
    coordinator = create_runtime_service_app(
        ServiceRole.COORDINATOR,
        environment=_runtime_environment(ServiceRole.COORDINATOR),
        internal_transport=_Transport(b"unused"),
        kms_client=object(),
        authority_store=cast(AuthorityStore, _RuntimeAbandonmentStore(None)),
        task_enqueuer=cast(TaskEnqueuer, _NeverTaskEnqueuer()),
    )

    assert isinstance(
        api.state.controlgraph_recovery_abandonment_client,
        ApiRecoveryAbandonmentClient,
    )
    assert isinstance(
        coordinator.state.controlgraph_recovery_abandoner,
        RecoveryAbandoner,
    )
    assert isinstance(
        coordinator.state.controlgraph_recovery_abandonment_relay,
        CoordinatorRecoveryAbandonmentRelay,
    )
    assert isinstance(
        verifier.state.controlgraph_service_claim_classification,
        ServiceClaimClassificationService,
    )
    assert isinstance(
        writer.state.controlgraph_classification_evidence_signing,
        ClassificationEvidenceSigningService,
    )


def _put_authority(
    client: _FakeClient,
    *,
    kind: AuthorityStorageKind,
    logical_id: str,
    document_id: str,
    stored: StoredRecord[Any],
) -> None:
    document = _prepared_document(
        kind=kind,
        logical_id=logical_id,
        document_id=document_id,
        revision=stored.revision,
        value=stored.value,
    )
    client.clock += timedelta(microseconds=1)
    client.documents[f"{kind.value}/{document_id}"] = _StoredDocument(
        _document_data(document.wrapper),
        client.clock,
    )


def _put_health(
    client: _FakeClient,
    *,
    kind: HealthStorageKind,
    logical_id: str,
    document_id: str,
    target: TargetBinding,
    stored: StoredRecord[Any],
) -> None:
    document = _prepared_health_document(
        kind=kind,
        logical_id=logical_id,
        document_id=document_id,
        revision=stored.revision,
        target=target,
        value=stored.value,
    )
    client.clock += timedelta(microseconds=1)
    client.documents[f"{kind.value}/{document_id}"] = _StoredDocument(
        _health_document_data(document[0]),
        client.clock,
    )


def _seed_state(client: _FakeClient, state: RecoveryAbandonmentState) -> None:
    bundle = state.root_bundle
    intent = state.recovery_intent
    dispatch = state.recovery_dispatch
    assert bundle is not None and intent is not None and dispatch is not None
    target = bundle.root.value.content.target
    root_id = bundle.root.value.root_id
    authority_documents = (
        (
            AuthorityStorageKind.ROLLOUT_ROOT_V3,
            root_id,
            rollout_root_v3_document_id(root_id),
            bundle.root,
        ),
        (
            AuthorityStorageKind.SERVICE_CLAIM,
            service_claim_logical_id(target),
            service_claim_document_id(target),
            bundle.service_claim,
        ),
        (
            AuthorityStorageKind.EPOCH_AUTHORITY,
            root_id,
            epoch_authority_document_id(root_id),
            bundle.authority,
        ),
        (
            AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
            capability_lineage_anchor_logical_id(bundle.lineage_anchor.value),
            capability_lineage_anchor_document_id(bundle.lineage_anchor.value),
            bundle.lineage_anchor,
        ),
        (
            AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            bundle.signed_evidence.value.event.evidence_id,
            signed_evidence_event_document_id(bundle.signed_evidence.value.event.evidence_id),
            bundle.signed_evidence,
        ),
        (
            AuthorityStorageKind.ROOT_CREATION_RESULT_V2,
            root_id,
            root_creation_result_v2_document_id(root_id),
            bundle.creation_result,
        ),
    )
    for kind, logical_id, document_id, stored in authority_documents:
        _put_authority(
            client,
            kind=kind,
            logical_id=logical_id,
            document_id=document_id,
            stored=stored,
        )

    _put_health(
        client,
        kind=HealthStorageKind.RECOVERY_INTENT,
        logical_id=intent.value.intent_id,
        document_id=recovery_intent_document_id(target, intent.value.root_sha256),
        target=target,
        stored=intent,
    )
    for identity_kind in (
        RecoveryDispatchIdentityKind.REQUEST,
        RecoveryDispatchIdentityKind.IDEMPOTENCY,
    ):
        identity = _recovery_dispatch_identity(dispatch.value, identity_kind)
        identity_value = identity.identity_value
        _put_health(
            client,
            kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
            logical_id=recovery_dispatch_identity_logical_id(
                identity_kind.value,
                identity_value,
            ),
            document_id=recovery_dispatch_identity_document_id(
                target,
                identity_kind.value,
                identity_value,
            ),
            target=target,
            stored=StoredRecord(identity, 0),
        )
    dispatch_storage = create_recovery_dispatch_storage_record(dispatch.value)
    _put_health(
        client,
        kind=HealthStorageKind.RECOVERY_DISPATCH,
        logical_id=dispatch.value.dispatch_id,
        document_id=recovery_dispatch_document_id(target, dispatch.value.dispatch_id),
        target=target,
        stored=StoredRecord(dispatch_storage, dispatch.revision),
    )

    if state.recovery_receipt is not None:
        _put_authority(
            client,
            kind=AuthorityStorageKind.EXECUTION_RECEIPT,
            logical_id=execution_receipt_logical_id(target, dispatch.value.idempotency_key),
            document_id=execution_receipt_document_id(
                target,
                dispatch.value.idempotency_key,
            ),
            stored=state.recovery_receipt,
        )
    if state.chain_head is not None:
        _put_authority(
            client,
            kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
            logical_id=root_id,
            document_id=evidence_chain_head_document_id(root_id),
            stored=state.chain_head,
        )
    evidence = (
        state.head_evidence,
        state.abandonment_evidence,
        state.fence_evidence,
        state.classification_evidence,
        state.release_evidence,
    )
    for stored in evidence:
        if stored is None:
            continue
        evidence_id = stored.value.event.evidence_id
        _put_authority(
            client,
            kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            logical_id=evidence_id,
            document_id=signed_evidence_event_document_id(evidence_id),
            stored=stored,
        )
    for stored in (state.request_identity, state.idempotency_identity):
        if stored is None:
            continue
        value = stored.value
        _put_authority(
            client,
            kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY,
            logical_id=recovery_abandonment_identity_logical_id(
                value.identity_kind.value,
                value.identity_value,
            ),
            document_id=recovery_abandonment_identity_document_id(
                value.identity_kind.value,
                value.identity_value,
            ),
            stored=stored,
        )
    if state.progress is not None:
        _put_authority(
            client,
            kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS,
            logical_id=state.progress.value.result_id,
            document_id=recovery_abandonment_progress_document_id(state.progress.value.result_id),
            stored=state.progress,
        )
    if state.result is not None:
        _put_authority(
            client,
            kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
            logical_id=state.result.value.result_id,
            document_id=recovery_abandonment_result_document_id(state.result.value.result_id),
            stored=state.result,
        )


def _firestore_store(
    client: _FakeClient,
    runner: _FakeTransactionRunner,
    target: TargetBinding,
) -> FirestoreRecoveryAbandonmentStore:
    return FirestoreRecoveryAbandonmentStore.for_test(
        target=target,
        configured_project_id=target.project_id,
        client_factory=lambda: client,
        transaction_runner=runner,
    )


def _changed_dispatch(dispatch: RecoveryDispatchRecordV2) -> RecoveryDispatchRecordV2:
    prepared_at = datetime.strptime(dispatch.prepared_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return RecoveryDispatchRecordV2.model_validate(
        {
            **dispatch.model_dump(mode="python"),
            "prepared_at": (prepared_at - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )


def test_firestore_abandonment_read_has_dedicated_total_and_rpc_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    memory, _, _, _, _ = _run_first_stage()
    expected, _ = memory.fence_commits[0]
    rpc_timeouts: list[float | None] = []
    original_get = _Reference.get
    delay_reads = True

    async def recording_get(
        reference: _Reference,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        timeout = kwargs.get("timeout")
        should_delay = delay_reads and not rpc_timeouts
        rpc_timeouts.append(timeout)
        if should_delay:
            assert type(timeout) is float
            async with asyncio.timeout(timeout):
                await asyncio.sleep(0.01)
        return await original_get(reference, *args, **kwargs)

    monkeypatch.setattr(_Reference, "get", recording_get)

    async def scenario() -> None:
        nonlocal delay_reads
        client = _FakeClient()
        runner = _FakeTransactionRunner()

        async def delayed_runner(
            delayed_client: _FakeClient,
            maximum_attempts: int,
            expected_writes: int,
            body: Any,
        ) -> None:
            await asyncio.sleep(0.03)
            await runner(delayed_client, maximum_attempts, expected_writes, body)

        assert expected.root_bundle is not None
        store = FirestoreRecoveryAbandonmentStore.for_test(
            target=expected.root_bundle.root.value.content.target,
            configured_project_id=expected.root_bundle.root.value.content.target.project_id,
            client_factory=lambda: client,
            transaction_runner=delayed_runner,
        )
        _seed_state(client, expected)

        observed = await store.read_recovery_abandonment_state(expected.invocation)

        assert observed == expected
        assert runner.expected_writes == [0]
        assert len(rpc_timeouts) >= 20
        assert set(rpc_timeouts) == {0.1}

        delay_reads = False
        rpc_timeouts.clear()
        assert await store.read_service_claim() == expected.root_bundle.service_claim
        assert rpc_timeouts == [0.005]

    monkeypatch.setattr(
        firestore_integration,
        "FIRESTORE_OPERATION_TIMEOUT_SECONDS",
        0.005,
    )

    monkeypatch.setattr(
        abandonment_integration,
        "_RECOVERY_ABANDONMENT_OPERATION_TIMEOUT_SECONDS",
        15.0,
    )
    monkeypatch.setattr(
        abandonment_integration,
        "_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS",
        0.1,
    )
    asyncio.run(scenario())


def test_firestore_abandonment_write_has_a_dedicated_total_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    memory, _, _, _, _ = _run_first_stage()
    expected, commit = memory.fence_commits[0]
    rpc_timeouts: list[float | None] = []
    original_get = _Reference.get

    async def recording_get(
        reference: _Reference,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        rpc_timeouts.append(kwargs.get("timeout"))
        return await original_get(reference, *args, **kwargs)

    monkeypatch.setattr(_Reference, "get", recording_get)

    async def scenario() -> None:
        client = _FakeClient()
        runner = _FakeTransactionRunner()

        async def delayed_runner(
            delayed_client: _FakeClient,
            maximum_attempts: int,
            expected_writes: int,
            body: Any,
        ) -> None:
            await asyncio.sleep(0.03)
            await runner(delayed_client, maximum_attempts, expected_writes, body)

        store = FirestoreRecoveryAbandonmentStore.for_test(
            target=commit.replacement_dispatch.target,
            configured_project_id=commit.replacement_dispatch.target.project_id,
            client_factory=lambda: client,
            transaction_runner=delayed_runner,
        )
        _seed_state(client, expected)

        written = await store.commit_recovery_abandonment_fence(expected, commit)

        assert written.recovery_dispatch.value == commit.replacement_dispatch
        assert runner.expected_writes == [9]
        assert rpc_timeouts
        assert set(rpc_timeouts) == {0.1}

    monkeypatch.setattr(
        firestore_integration,
        "FIRESTORE_OPERATION_TIMEOUT_SECONDS",
        0.005,
    )
    monkeypatch.setattr(
        abandonment_integration,
        "_RECOVERY_ABANDONMENT_OPERATION_TIMEOUT_SECONDS",
        15.0,
    )
    monkeypatch.setattr(
        abandonment_integration,
        "_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS",
        0.1,
    )
    asyncio.run(scenario())


def test_firestore_abandonment_read_remains_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    memory, _, _, _, _ = _run_first_stage()
    expected, _ = memory.fence_commits[0]

    async def scenario() -> None:
        client = _FakeClient()
        runner_started = asyncio.Event()

        async def blocked_runner(
            delayed_client: _FakeClient,
            maximum_attempts: int,
            expected_writes: int,
            body: Any,
        ) -> None:
            del delayed_client, maximum_attempts, expected_writes, body
            runner_started.set()
            await asyncio.Event().wait()

        assert expected.root_bundle is not None
        store = FirestoreRecoveryAbandonmentStore.for_test(
            target=expected.root_bundle.root.value.content.target,
            configured_project_id=expected.root_bundle.root.value.content.target.project_id,
            client_factory=lambda: client,
            transaction_runner=blocked_runner,
        )
        _seed_state(client, expected)

        with pytest.raises(AuthorityStoreUnavailable):
            await asyncio.wait_for(
                store.read_recovery_abandonment_state(expected.invocation),
                timeout=0.5,
            )
        assert runner_started.is_set()

    monkeypatch.setattr(
        abandonment_integration,
        "_RECOVERY_ABANDONMENT_OPERATION_TIMEOUT_SECONDS",
        0.01,
    )
    asyncio.run(scenario())


def test_firestore_fence_rereads_receipt_absence_and_commits_one_cas() -> None:
    memory, _, _, _, _ = _run_first_stage()
    expected, commit = memory.fence_commits[0]

    async def scenario() -> None:
        client = _FakeClient()
        runner = _FakeTransactionRunner()
        store = _firestore_store(client, runner, commit.replacement_dispatch.target)
        _seed_state(client, expected)

        observed = await store.read_recovery_abandonment_state(expected.invocation)
        written = await store.commit_recovery_abandonment_fence(observed, commit)

        assert written.recovery_dispatch.value == commit.replacement_dispatch
        assert written.recovery_dispatch.revision == 2
        assert written.progress.value.abandonment_subject.receipt_absent_at_fence is True
        assert runner.expected_writes[-1] == 9
        persisted = await store.read_recovery_abandonment_state(expected.invocation)
        assert persisted.recovery_receipt is None
        assert persisted.recovery_dispatch == written.recovery_dispatch
        assert persisted.progress == written.progress

    asyncio.run(scenario())


@pytest.mark.parametrize("changed", ["receipt", "dispatch", "claim"])
def test_firestore_fence_rejects_state_changed_after_read(changed: str) -> None:
    memory, _, _, _, _ = _run_first_stage()
    expected, commit = memory.fence_commits[0]
    fenced = memory.state

    async def scenario() -> None:
        client = _FakeClient()
        runner = _FakeTransactionRunner()
        store = _firestore_store(client, runner, commit.replacement_dispatch.target)
        _seed_state(client, expected)
        observed = await store.read_recovery_abandonment_state(expected.invocation)

        if changed == "receipt":
            assert fenced.recovery_dispatch is not None
            late = _late_epoch_denial(memory)
            _put_authority(
                client,
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=late.value.receipt_id,
                document_id=execution_receipt_document_id(
                    store.target,
                    fenced.recovery_dispatch.value.idempotency_key,
                ),
                stored=late,
            )
        elif changed == "dispatch":
            assert expected.recovery_dispatch is not None
            changed_dispatch = StoredRecord(
                _changed_dispatch(expected.recovery_dispatch.value),
                expected.recovery_dispatch.revision,
            )
            _put_health(
                client,
                kind=HealthStorageKind.RECOVERY_DISPATCH,
                logical_id=changed_dispatch.value.dispatch_id,
                document_id=recovery_dispatch_document_id(
                    store.target,
                    changed_dispatch.value.dispatch_id,
                ),
                target=store.target,
                stored=StoredRecord(
                    create_recovery_dispatch_storage_record(changed_dispatch.value),
                    changed_dispatch.revision,
                ),
            )
        else:
            assert expected.root_bundle is not None
            replacement_claim = StoredRecord(
                commit.replacement_claim,
                expected.root_bundle.service_claim.revision + 1,
            )
            _put_authority(
                client,
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=service_claim_logical_id(store.target),
                document_id=service_claim_document_id(store.target),
                stored=replacement_claim,
            )
        before = deepcopy(client.documents)
        completed_transactions = len(runner.write_result_counts)

        with pytest.raises(AuthorityStoreConflict):
            await store.commit_recovery_abandonment_fence(observed, commit)

        assert client.documents == before
        assert len(runner.write_result_counts) == completed_transactions

    asyncio.run(scenario())


def _finalize_fixture() -> tuple[
    _Store,
    RecoveryAbandonmentState,
    Any,
    StoredRecord[Any],
]:
    memory, _, _, _ = _run_released_stage()
    fenced, commit = memory.finalize_commits[0]
    late = _late_epoch_denial(memory)
    return memory, replace(fenced, recovery_receipt=late), commit, late


def test_firestore_finalize_accepts_only_exact_late_epoch_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, expected, commit, late = _finalize_fixture()
    rpc_timeouts: list[float | None] = []
    original_get = _Reference.get

    async def recording_get(
        reference: _Reference,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        rpc_timeouts.append(kwargs.get("timeout"))
        return await original_get(reference, *args, **kwargs)

    monkeypatch.setattr(_Reference, "get", recording_get)
    monkeypatch.setattr(
        abandonment_integration,
        "_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS",
        0.1,
    )

    async def scenario() -> None:
        client = _FakeClient()
        runner = _FakeTransactionRunner()
        assert expected.root_bundle is not None
        store = _firestore_store(
            client,
            runner,
            expected.root_bundle.root.value.content.target,
        )
        _seed_state(client, expected)

        observed = await store.read_recovery_abandonment_state(expected.invocation)
        assert observed.recovery_receipt == late
        written = await store.commit_recovery_abandonment_release(observed, commit)

        assert written.result.value == commit.result
        assert written.service_claim.value.status.value == "RELEASED"
        persisted = await store.read_recovery_abandonment_state(expected.invocation)
        assert persisted.recovery_receipt == late
        assert persisted.result == written.result
        assert rpc_timeouts
        assert set(rpc_timeouts) == {0.1}

    asyncio.run(scenario())


@pytest.mark.parametrize("changed", ["near-miss-receipt", "dispatch"])
def test_firestore_finalize_rejects_changed_dispatch_or_receipt(changed: str) -> None:
    memory, expected, commit, _ = _finalize_fixture()

    async def scenario() -> None:
        client = _FakeClient()
        runner = _FakeTransactionRunner()
        assert expected.root_bundle is not None
        store = _firestore_store(
            client,
            runner,
            expected.root_bundle.root.value.content.target,
        )
        _seed_state(client, expected)
        observed = await store.read_recovery_abandonment_state(expected.invocation)
        dispatch = cast(StoredRecord[RecoveryDispatchRecordV2], expected.recovery_dispatch)

        if changed == "near-miss-receipt":
            near_miss = _late_epoch_denial(
                memory,
                reason_code=ReasonCode.CALLER_UNAUTHORIZED,
            )
            _put_authority(
                client,
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=near_miss.value.receipt_id,
                document_id=execution_receipt_document_id(
                    store.target,
                    dispatch.value.idempotency_key,
                ),
                stored=near_miss,
            )
        else:
            changed_dispatch = _changed_dispatch(dispatch.value)
            _put_health(
                client,
                kind=HealthStorageKind.RECOVERY_DISPATCH,
                logical_id=dispatch.value.dispatch_id,
                document_id=recovery_dispatch_document_id(
                    store.target,
                    dispatch.value.dispatch_id,
                ),
                target=store.target,
                stored=StoredRecord(
                    create_recovery_dispatch_storage_record(changed_dispatch),
                    dispatch.revision,
                ),
            )
        before = deepcopy(client.documents)
        completed_transactions = len(runner.write_result_counts)

        with pytest.raises(AuthorityStoreConflict):
            await store.commit_recovery_abandonment_release(observed, commit)

        assert client.documents == before
        assert len(runner.write_result_counts) == completed_transactions

    asyncio.run(scenario())
