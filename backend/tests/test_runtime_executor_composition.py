from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import google_crc32c
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi.testclient import TestClient
from google.cloud import run_v2
from root_v2_support import RootBundle, root_bundle, root_records

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    DirectReceiptCreate,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    ReceiptClaimResult,
    StoredRecord,
    validate_receipt_claim_binding,
)
from controlgraph_canary.application.identity import (
    RECEIPT_AUTHORITY_PATH,
    CallerRole,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.receipt_authority import ReceiptAuthorityService
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.signing import (
    DigestSigningBackend,
    PurposeSealedSigner,
    SigningProfile,
)
from controlgraph_canary.authority.replay import MutationBinding
from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityClaims,
    ExecutionReceipt,
    MutationIntent,
    ReceiptOutcome,
    SignedCapability,
    TaskRequest,
    canonical_json_bytes,
    canonical_sha256,
)
from controlgraph_canary.contracts.receipt_authority import (
    ReceiptAuthorityOperation,
    ReceiptAuthorityRequestV1,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV2
from controlgraph_canary.services.runtime import create_runtime_service_app

PROJECT_ID = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
SERVICE = "controlgraph-reference-target"
STABLE = f"{SERVICE}-stable-v1"
CANDIDATE = f"{SERVICE}-candidate-v1"
SERVICE_RESOURCE = f"projects/{PROJECT_ID}/locations/us-central1/services/{SERVICE}"
CAPABILITY_KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)
EXECUTOR_AUDIENCE = (
    f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
)
COORDINATOR_AUDIENCE = (
    f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
)
NOW = datetime(2026, 8, 19, 12, 3, tzinfo=UTC)


def _environment() -> dict[str, str]:
    return {
        "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_SERVICE_NAME": "controlgraph-executor",
        "CONTROLGRAPH_CONTROLLER_ID": f"{PROJECT_ID}:us-central1:executor",
        "CONTROLGRAPH_ROLE": "executor",
        "CONTROLGRAPH_BUILD_DIGEST": f"sha256:{'a' * 64}",
        "CONTROLGRAPH_CONTRACT_VERSION": "controlgraph.contract/v1",
        "CONTROLGRAPH_FIRESTORE_DATABASE": "controlgraph-authority",
        "CONTROLGRAPH_MUTATIONS_ENABLED": "true",
        "CONTROLGRAPH_ENVIRONMENT": "nonprod",
        "CONTROLGRAPH_AUTH_AUDIENCE": EXECUTOR_AUDIENCE,
        "CONTROLGRAPH_AUTH_CALLER_ROLE": "execution_task_caller",
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
            f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": SUBJECT,
        "CONTROLGRAPH_CAPABILITY_KEY_VERSION": CAPABILITY_KEY_VERSION,
        "CONTROLGRAPH_COORDINATOR_URL": COORDINATOR_AUDIENCE,
        "CONTROLGRAPH_TARGET_NETWORK_RESOURCE": (
            f"projects/{PROJECT_ID}/global/networks/controlgraph-network"
        ),
        "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE": (
            f"projects/{PROJECT_ID}/regions/us-central1/"
            "subnetworks/controlgraph-runtime"
        ),
    }


class _LocalSigningBackend:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self.profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_KEY_VERSION)
        self._private_key = private_key

    def sign_digest(self, digest: bytes) -> bytes:
        return self._private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )


def _task(
    root: RolloutRootV2,
    private_key: ec.EllipticCurvePrivateKey,
) -> TaskRequest:
    plan = root.content.rollout_plan
    claims = CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id="capability-runtime-executor-001",
        issuer=f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com",
        subject=f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com",
        audience=EXECUTOR_AUDIENCE,
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=90,
        candidate_percent=10,
        concurrency=None,
        plan_sha256=canonical_sha256(plan),
        provider_etag=root.content.stable_snapshot.provider_etag,
        request_id="request-runtime-executor-001",
        idempotency_key="intent-runtime-executor-001",
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:02:00Z",
        not_before="2026-08-19T12:02:00Z",
        expires_at="2026-08-19T12:07:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=CAPABILITY_KEY_VERSION,
    )
    detached = PurposeSealedSigner(
        cast(DigestSigningBackend, _LocalSigningBackend(private_key))
    ).sign(claims)
    capability = SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=detached.signature,
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
    return TaskRequest(
        schema_version="controlgraph.task-request/v1",
        task_id="task-runtime-executor-001",
        queue_region="us-central1",
        handler_audience=EXECUTOR_AUDIENCE,
        scheduled_at=claims.not_before,
        expires_at=claims.expires_at,
        capability=capability,
        intent=intent,
    )


class _KmsClient:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._private_key = private_key
        self.version_requests: list[dict[str, object]] = []
        self.public_key_requests: list[dict[str, object]] = []

    def get_crypto_key_version(self, request: dict[str, object]) -> object:
        self.version_requests.append(request)
        return SimpleNamespace(
            name=CAPABILITY_KEY_VERSION,
            state="ENABLED",
            algorithm="EC_SIGN_P256_SHA256",
        )

    def get_public_key(self, request: dict[str, object]) -> object:
        self.public_key_requests.append(request)
        pem = (
            self._private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )
        return SimpleNamespace(
            name=CAPABILITY_KEY_VERSION,
            algorithm="EC_SIGN_P256_SHA256",
            pem=pem,
            pem_crc32c=google_crc32c.value(pem.encode("ascii")),
        )


class _AuthorityStore:
    def __init__(self, bundle: RootBundle, events: list[str]) -> None:
        self.target = bundle.root.value.content.target
        self._bundle = bundle
        self.events = events
        self.reads: list[str] = []

    async def read_root_creation_bundle(self, root_id: str) -> RootBundle | None:
        self.events.append("root-read")
        self.reads.append(root_id)
        if root_id != self._bundle.root.value.root_id:
            return None
        return self._bundle


class _ReceiptBackingStore:
    def __init__(self, bundle: RootBundle, events: list[str]) -> None:
        self.target = bundle.root.value.content.target
        self.events = events
        self.stored: StoredRecord[ExecutionReceipt] | None = None

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        self.events.append("receipt-claim")
        validate_receipt_claim_binding(receipt, binding)
        if self.stored is None:
            self.stored = StoredRecord(receipt, 0)
            return ReceiptClaimCreated(
                self.stored,
                DirectReceiptCreate._from_direct_store_create(
                    self.stored,
                    binding,
                ),
            )
        if self.stored.value.mutation_sha256 != receipt.mutation_sha256:
            return ReceiptClaimConflict()
        return ReceiptClaimAdopted(self.stored)

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        self.events.append("receipt-read")
        if self.stored is None or self.stored.value.idempotency_key != idempotency_key:
            return None
        return self.stored

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        self.events.append("receipt-cas")
        if self.stored != expected:
            raise AuthorityStoreConflict()
        self.stored = StoredRecord(replacement, expected.revision + 1)
        return self.stored


class _ReceiptLoopbackTransport:
    def __init__(
        self,
        service: ReceiptAuthorityService,
        events: list[str],
    ) -> None:
        self._service = service
        self.events = events
        self.routes: list[CoordinatorInternalRoute] = []
        self.operations: list[ReceiptAuthorityOperation] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        request = ReceiptAuthorityRequestV1.model_validate_json(body)
        self.events.append(f"receipt-route-{request.operation.value}")
        self.routes.append(route)
        self.operations.append(request.operation)
        return await self._service.handle(body)


class _Operation:
    def __init__(self, service: run_v2.Service) -> None:
        self.operation = SimpleNamespace(name="operations/runtime-executor-001")
        self._service = service
        self.timeouts: list[float | None] = []

    async def result(self, timeout: float | None = None) -> run_v2.Service:
        self.timeouts.append(timeout)
        return self._service


class _MutationServicesClient:
    def __init__(self, service: run_v2.Service, events: list[str]) -> None:
        self._operation = _Operation(service)
        self.events = events
        self.get_calls: list[run_v2.GetServiceRequest] = []
        self.update_calls: list[run_v2.UpdateServiceRequest] = []

    async def get_service(
        self,
        request: run_v2.GetServiceRequest,
        *,
        retry: object,
        timeout: float,
    ) -> run_v2.Service:
        del retry, timeout
        self.get_calls.append(request)
        raise AssertionError("the mutation path must not substitute a preparatory service read")

    async def update_service(
        self,
        request: run_v2.UpdateServiceRequest,
        *,
        retry: object,
        timeout: float,
    ) -> _Operation:
        assert retry is None
        assert timeout == 5.0
        self.events.append("cloud-run-update")
        self.update_calls.append(request)
        return self._operation


class _ReadbackServicesClient:
    def __init__(self, service: run_v2.Service, events: list[str]) -> None:
        self._service = service
        self.events = events
        self.get_calls: list[run_v2.GetServiceRequest] = []

    async def get_service(
        self,
        request: run_v2.GetServiceRequest,
        *,
        retry: object,
        timeout: float,
    ) -> run_v2.Service:
        assert retry is None
        assert timeout == 5.0
        self.events.append("cloud-run-readback")
        self.get_calls.append(request)
        return self._service


class _RevisionsClient:
    def __init__(self) -> None:
        self.calls: list[run_v2.GetRevisionRequest] = []

    async def get_revision(
        self,
        request: run_v2.GetRevisionRequest,
        *,
        retry: object,
        timeout: float,
    ) -> run_v2.Revision:
        del retry, timeout
        self.calls.append(request)
        raise AssertionError("the closed traffic command must not inspect another revision")


def _settled_canary_service() -> run_v2.Service:
    ready = run_v2.Condition.State.CONDITION_SUCCEEDED
    return run_v2.Service(
        name=SERVICE_RESOURCE,
        uid="synthetic-runtime-service-uid",
        generation=8,
        observed_generation=8,
        etag="etag-canary-8",
        reconciling=False,
        terminal_condition=run_v2.Condition(type_="Ready", state=ready),
        conditions=[run_v2.Condition(type_="Ready", state=ready)],
        latest_ready_revision=CANDIDATE,
        latest_created_revision=CANDIDATE,
        template=run_v2.RevisionTemplate(
            revision=CANDIDATE,
            max_instance_request_concurrency=8,
        ),
        traffic=[
            run_v2.TrafficTarget(
                type_=(
                    run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION
                ),
                revision=STABLE,
                percent=90,
                tag="stable",
            ),
            run_v2.TrafficTarget(
                type_=(
                    run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION
                ),
                revision=CANDIDATE,
                percent=10,
                tag="candidate",
            ),
        ],
        traffic_statuses=[
            run_v2.TrafficTargetStatus(
                type_=(
                    run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION
                ),
                revision=STABLE,
                percent=90,
                tag="stable",
                uri="https://stable.example.test",
            ),
            run_v2.TrafficTargetStatus(
                type_=(
                    run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION
                ),
                revision=CANDIDATE,
                percent=10,
                tag="candidate",
                uri="https://candidate.example.test",
            ),
        ],
        uri="https://service.example.test",
    )


def test_enabled_executor_runtime_composes_exact_production_execution_path() -> None:
    events: list[str] = []
    private_key = ec.generate_private_key(ec.SECP256R1())
    root, anchor, claim, authority = root_records(
        concurrency=8,
        provider_etag="etag-stable-7",
    )
    bundle = root_bundle(
        root=root,
        anchor=anchor,
        claim=claim,
        authority=authority,
    )
    authority_store = _AuthorityStore(bundle, events)
    receipt_store = _ReceiptBackingStore(bundle, events)
    receipt_transport = _ReceiptLoopbackTransport(
        ReceiptAuthorityService(receipt_store),
        events,
    )
    kms = _KmsClient(private_key)
    provider_service = _settled_canary_service()
    mutation_services = _MutationServicesClient(provider_service, events)
    readback_services = _ReadbackServicesClient(provider_service, events)
    revisions = _RevisionsClient()

    def verify_token(token: str, audience: str) -> dict[str, object]:
        events.append("caller-admission")
        assert token == "aaa.bbb.ccc"
        assert audience == EXECUTOR_AUDIENCE
        return {
            "iss": "https://accounts.google.com",
            "aud": EXECUTOR_AUDIENCE,
            "email": (
                f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
            ),
            "email_verified": True,
            "sub": SUBJECT,
            "iat": int(NOW.timestamp()) - 60,
            "exp": int(NOW.timestamp()) + 300,
        }

    def mutation_client_factory() -> _MutationServicesClient:
        events.append("mutation-client")
        return mutation_services

    def readback_client_factory() -> _ReadbackServicesClient:
        events.append("readback-client")
        return readback_services

    app = create_runtime_service_app(
        ServiceRole.EXECUTOR,
        environment=_environment(),
        token_verifier=verify_token,
        clock=lambda: NOW.timestamp(),
        kms_client=kms,
        internal_transport=receipt_transport,
        services_client_factory=mutation_client_factory,
        revisions_client_factory=lambda: revisions,
        readback_services_client_factory=readback_client_factory,
        authority_store=authority_store,
        final_authority_clock=lambda: NOW,
        receipt_clock=lambda: NOW,
        capability_verification_clock=lambda: NOW,
    )

    with TestClient(app) as client:
        metadata = client.get("/v1/metadata")
        response = client.post(
            protected_path(ServiceRole.EXECUTOR),
            content=canonical_json_bytes(_task(root, private_key)),
            headers={
                "Authorization": "Bearer aaa.bbb.ccc",
                "Content-Type": "application/json",
            },
        )

    assert metadata.status_code == 200
    assert metadata.json()["mutation_enabled"] is True
    assert response.status_code == 200
    assert response.json()["receipt"]["outcome"] == ReceiptOutcome.VERIFIED.value
    assert response.json()["receipt"]["observed_etag"] == "etag-canary-8"
    assert response.json()["storage_revision"] == 2
    assert callable(app.state.controlgraph_receipt_execution)

    assert kms.version_requests == [{"name": CAPABILITY_KEY_VERSION}]
    assert kms.public_key_requests == [{"name": CAPABILITY_KEY_VERSION}]
    assert authority_store.reads == [root.root_id, root.root_id]
    assert events == [
        "caller-admission",
        "root-read",
        "receipt-route-CLAIM",
        "receipt-claim",
        "root-read",
        "mutation-client",
        "cloud-run-update",
        "receipt-route-COMPARE_AND_SET",
        "receipt-cas",
        "readback-client",
        "cloud-run-readback",
        "receipt-route-COMPARE_AND_SET",
        "receipt-cas",
    ]

    assert receipt_transport.operations == [
        ReceiptAuthorityOperation.CLAIM,
        ReceiptAuthorityOperation.COMPARE_AND_SET,
        ReceiptAuthorityOperation.COMPARE_AND_SET,
    ]
    assert all(
        route.project_id == PROJECT_ID
        and route.project_number == PROJECT_NUMBER
        and route.caller_role is CallerRole.EXECUTOR
        and route.service_role is ServiceRole.COORDINATOR
        and route.audience == COORDINATOR_AUDIENCE
        and route.path == RECEIPT_AUTHORITY_PATH
        for route in receipt_transport.routes
    )

    assert len(mutation_services.update_calls) == 1
    update = mutation_services.update_calls[0]
    assert update.service.name == SERVICE_RESOURCE
    assert update.service.etag == "etag-stable-7"
    assert list(update.update_mask.paths) == ["traffic"]
    assert [
        (allocation.revision, allocation.percent, allocation.tag)
        for allocation in update.service.traffic
    ] == [(STABLE, 90, "stable"), (CANDIDATE, 10, "candidate")]
    assert mutation_services.get_calls == []
    assert revisions.calls == []
    assert [request.name for request in readback_services.get_calls] == [
        SERVICE_RESOURCE
    ]
