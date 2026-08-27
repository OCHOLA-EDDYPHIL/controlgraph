from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from types import SimpleNamespace

import google_crc32c
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi.testclient import TestClient
from pydantic import ValidationError

from controlgraph_canary.application.candidate_revision import (
    CandidateRevisionAttestation,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunExecutionEnvironment,
    CloudRunHttpProbe,
    CloudRunNetworkInterface,
    CloudRunReadyState,
    CloudRunRevisionConfiguration,
    CloudRunRevisionState,
    CloudRunServiceState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
    CloudRunVpcEgress,
    cloud_run_revision_configuration_sha256,
)
from controlgraph_canary.application.identity import (
    HEALTH_ATTESTATION_PATH,
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    runtime_route_policy,
)
from controlgraph_canary.application.model_assistance import CoordinatorAdvisorClient
from controlgraph_canary.application.root_relay import CoordinatorRootCreationRelay
from controlgraph_canary.application.root_trust import (
    CoordinatorEvidenceClient,
    CoordinatorInternalRoute,
    CoordinatorRootPreflightClient,
    RootPreflightError,
    RootPreflightErrorCode,
    RootPreflightService,
    RootTrustClientError,
    RootTrustClientErrorCode,
)
from controlgraph_canary.application.service_claim_release import ServiceClaimReleaser
from controlgraph_canary.application.signing import (
    SigningProfile,
    build_signing_input,
)
from controlgraph_canary.application.stable_snapshot import stable_configuration_sha256
from controlgraph_canary.application.tasks import AddressedTask, TaskEnqueueResult
from controlgraph_canary.contracts import (
    EvidenceEvent,
    EvidenceKind,
    SignedEvidenceEventV1,
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.root_creation import SIGNED_EVIDENCE_EVENT_V1
from controlgraph_canary.contracts.root_trust import (
    ROOT_CANDIDATE_ATTESTATION_V1,
    ROOT_PREFLIGHT_REQUEST_V1,
    ROOT_PREFLIGHT_RESULT_V1,
    RootCandidateAttestationV1,
    RootPreflightRequestV1,
    RootPreflightResultV1,
    root_preflight_request_sha256,
)
from controlgraph_canary.http.service import create_service_app, protected_paths
from controlgraph_canary.integrations.google.internal_transport import (
    GoogleOneShotOidcTransport,
    InternalHttpResponse,
    InternalTransportError,
)
from controlgraph_canary.integrations.google.kms import (
    GoogleKmsEvidenceSignatureVerifier,
)
from controlgraph_canary.services.runtime import (
    CoordinatorTrustClients,
    create_runtime_service_app,
)
from controlgraph_canary.settings import ControllerSettings

PROJECT = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
SERVICE = "controlgraph-reference-target"
STABLE = f"{SERVICE}-stable-v14"
CANDIDATE = f"{SERVICE}-candidate-v14"
VERIFIER_IDENTITY = f"controlgraph-verifier@{PROJECT}.iam.gserviceaccount.com"
COORDINATOR_IDENTITY = f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com"
SUBJECT = "123456789012345678901"
VERIFIER_AUDIENCE = (
    f"https://controlgraph-verifier-{PROJECT_NUMBER}.us-central1.run.app"
)
EVIDENCE_AUDIENCE = (
    f"https://controlgraph-evidence-writer-{PROJECT_NUMBER}.us-central1.run.app"
)
EVIDENCE_KEY_VERSION = (
    f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
)
CAPABILITY_KEY_VERSION = (
    f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)
OLD = datetime(2026, 8, 19, 11, 55, tzinfo=UTC)
NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)


def _target(**changes: str) -> TargetBinding:
    values = {
        "schema_version": "controlgraph.target-binding/v1",
        "project_id": PROJECT,
        "region": "us-central1",
        "environment": "nonprod",
        "service_name": SERVICE,
    }
    values.update(changes)
    return TargetBinding.model_validate(values)


def _revision_configuration(*, digest: str) -> CloudRunRevisionConfiguration:
    return CloudRunRevisionConfiguration(
        image=(
            f"us-central1-docker.pkg.dev/{PROJECT}/controlgraph-images/reference-target"
            f"@sha256:{digest}"
        ),
        service_account=f"controlgraph-reference@{PROJECT}.iam.gserviceaccount.com",
        execution_environment=CloudRunExecutionEnvironment.GEN2,
        timeout_seconds=5,
        concurrency=8,
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
                network=f"projects/{PROJECT}/global/networks/controlgraph",
                subnetwork=(
                    f"projects/{PROJECT}/regions/us-central1/subnetworks/controlgraph"
                ),
                tags=(),
            ),
        ),
    )


STABLE_CONFIGURATION = _revision_configuration(digest="1" * 64)
CANDIDATE_CONFIGURATION = _revision_configuration(digest="2" * 64)


def _service(*, generation: int = 7, etag: str = "service-etag-7") -> CloudRunServiceState:
    target = _target()
    return CloudRunServiceState(
        target=target,
        resource_name=(
            f"projects/{PROJECT}/locations/us-central1/services/{SERVICE}"
        ),
        uid="service-uid-1",
        etag=etag,
        generation=generation,
        observed_generation=generation,
        reconciling=False,
        ready_state=CloudRunReadyState.READY,
        latest_ready_revision=CANDIDATE,
        latest_created_revision=CANDIDATE,
        template_revision=CANDIDATE,
        template_concurrency=8,
        traffic=(
            CloudRunTrafficAllocation(revision=STABLE, percent=100, tag="stable"),
        ),
        traffic_statuses=(
            CloudRunTrafficStatus(
                revision=STABLE,
                percent=100,
                tag="stable",
                uri="https://stable.example.test",
            ),
        ),
        uri="https://reference.example.test",
    )


def _revision(
    revision: str,
    *,
    configuration: CloudRunRevisionConfiguration,
) -> CloudRunRevisionState:
    service_resource = f"projects/{PROJECT}/locations/us-central1/services/{SERVICE}"
    return CloudRunRevisionState(
        target=_target(),
        revision=revision,
        resource_name=f"{service_resource}/revisions/{revision}",
        service_resource=service_resource,
        uid=f"{revision}-uid",
        etag=f"{revision}-etag",
        generation=1,
        observed_generation=1,
        reconciling=False,
        ready_state=CloudRunReadyState.READY,
        concurrency=8,
        configuration=configuration,
    )


def _snapshot(*, captured_at: str = "2026-08-19T11:55:00Z") -> StableSnapshot:
    service = _service()
    revision = _revision(STABLE, configuration=STABLE_CONFIGURATION)
    traffic = (TrafficAllocation(revision=STABLE, percent=100),)
    return StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=_target(),
        stable_revision=STABLE,
        traffic=traffic,
        concurrency=8,
        service_generation=service.generation,
        provider_etag=service.etag,
        configuration_sha256=stable_configuration_sha256(service, revision, traffic),
        stable_revision_configuration_sha256=(
            cloud_run_revision_configuration_sha256(STABLE_CONFIGURATION)
        ),
        captured_at=captured_at,
        captured_by=VERIFIER_IDENTITY,
    )


def _request(**changes: object) -> RootPreflightRequestV1:
    values: dict[str, object] = {
        "schema_version": ROOT_PREFLIGHT_REQUEST_V1,
        "target": _target(),
        "expected_stable_snapshot": _snapshot(),
        "candidate_revision": CANDIDATE,
        "candidate_revision_configuration_sha256": (
            cloud_run_revision_configuration_sha256(CANDIDATE_CONFIGURATION)
        ),
        "concurrency": 8,
    }
    values.update(changes)
    return RootPreflightRequestV1.model_validate(values)


def _candidate_contract(*, captured_at: str = "2026-08-19T12:00:00Z") -> RootCandidateAttestationV1:
    return RootCandidateAttestationV1(
        schema_version=ROOT_CANDIDATE_ATTESTATION_V1,
        target=_target(),
        candidate_revision=CANDIDATE,
        configuration_sha256=(
            cloud_run_revision_configuration_sha256(CANDIDATE_CONFIGURATION)
        ),
        generation=1,
        etag=f"{CANDIDATE}-etag",
        concurrency=8,
        reader_identity=VERIFIER_IDENTITY,
        captured_at=captured_at,
    )


def _result(request: RootPreflightRequestV1 | None = None) -> RootPreflightResultV1:
    selected = request or _request()
    return RootPreflightResultV1(
        schema_version=ROOT_PREFLIGHT_RESULT_V1,
        request=selected,
        request_sha256=root_preflight_request_sha256(selected),
        stable_snapshot=_snapshot(captured_at="2026-08-19T12:00:00Z"),
        candidate_revision=_candidate_contract(),
    )


def _identity_environment(role: ServiceRole) -> dict[str, str]:
    audience = VERIFIER_AUDIENCE if role is ServiceRole.VERIFIER else EVIDENCE_AUDIENCE
    return {
        "CONTROLGRAPH_PROJECT_ID": PROJECT,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_ROLE": role.value,
        "CONTROLGRAPH_AUTH_AUDIENCE": audience,
        "CONTROLGRAPH_AUTH_CALLER_ROLE": "coordinator",
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": COORDINATOR_IDENTITY,
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": SUBJECT,
    }


def _policy() -> RouteAuthenticationPolicy:
    return runtime_route_policy(ServiceRole.VERIFIER, _identity_environment(ServiceRole.VERIFIER))


def _context(**changes: object) -> AuthenticationContext:
    values: dict[str, object] = {
        "role": CallerRole.COORDINATOR,
        "email": COORDINATOR_IDENTITY,
        "subject": SUBJECT,
        "issuer": "https://accounts.google.com",
        "audience": VERIFIER_AUDIENCE,
        "issued_at": 1_776_236_340,
        "expires_at": 1_776_239_400,
    }
    values.update(changes)
    return AuthenticationContext(**values)  # type: ignore[arg-type]


class _Reader:
    def __init__(
        self,
        *,
        service: CloudRunServiceState | None = None,
        services: list[CloudRunServiceState] | None = None,
    ) -> None:
        selected = service or _service()
        self._services = list(services or [selected, selected, selected, selected])
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

    async def read_service(self) -> CloudRunServiceState:
        self.calls.append("service")
        return self._services.pop(0)

    async def read_revision(self, revision_name: str) -> CloudRunRevisionState:
        self.calls.append(f"revision:{revision_name}")
        if revision_name == STABLE:
            return _revision(STABLE, configuration=STABLE_CONFIGURATION)
        if revision_name == CANDIDATE:
            return _revision(CANDIDATE, configuration=CANDIDATE_CONFIGURATION)
        raise AssertionError("unexpected revision")


class _Authenticator:
    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        assert authorization_header == "Bearer synthetic.test.token"
        assert policy == _policy()
        return _context()


class _Transport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        return self.response


def _route(role: ServiceRole) -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.COORDINATOR,
        service_role=role,
        audience=(VERIFIER_AUDIENCE if role is ServiceRole.VERIFIER else EVIDENCE_AUDIENCE),
    )


def test_health_attestation_route_is_sealed_to_verifier_evidence_writer() -> None:
    route = CoordinatorInternalRoute(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.VERIFIER,
        service_role=ServiceRole.EVIDENCE_WRITER,
        audience=EVIDENCE_AUDIENCE,
        override_path=HEALTH_ATTESTATION_PATH,
    )

    assert route.path == HEALTH_ATTESTATION_PATH
    assert route.url == f"{EVIDENCE_AUDIENCE}{HEALTH_ATTESTATION_PATH}"

    with pytest.raises(ValueError, match="route coordinates are invalid"):
        CoordinatorInternalRoute(
            project_id=PROJECT,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.COORDINATOR,
            service_role=ServiceRole.EVIDENCE_WRITER,
            audience=EVIDENCE_AUDIENCE,
            override_path=HEALTH_ATTESTATION_PATH,
        )


def _preflight_service(reader: _Reader) -> RootPreflightService:
    return RootPreflightService(
        target=_target(),
        authentication_policy=_policy(),
        reader_factory=lambda request: reader,
        clock=lambda: NOW,
    )


def _event() -> EvidenceEvent:
    return EvidenceEvent(
        schema_version="controlgraph.evidence-event/v1",
        evidence_id="evidence:root:1",
        sequence=0,
        root_id=f"cgroot:{'a' * 64}",
        root_sha256="a" * 64,
        target=_target(),
        epoch=1,
        kind=EvidenceKind.ROOT_CREATED,
        actor="operator@example.com",
        request_id="request:root:1",
        receipt_id=None,
        occurred_at="2026-08-19T12:00:00Z",
        subject_sha256="b" * 64,
        previous_event_sha256=None,
        reason_code=None,
        provider_operation=None,
        target_configuration_sha256="c" * 64,
    )


def _signed_event(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    event: EvidenceEvent | None = None,
) -> SignedEvidenceEventV1:
    selected = event or _event()
    signing_input = build_signing_input(
        SigningProfile.evidence(PROJECT, EVIDENCE_KEY_VERSION),
        selected,
    )
    signature = private_key.sign(
        signing_input.digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    from controlgraph_canary.contracts.codec import encode_base64url

    return SignedEvidenceEventV1(
        schema_version=SIGNED_EVIDENCE_EVENT_V1,
        event=selected,
        purpose="EVIDENCE",
        signing_key_version=EVIDENCE_KEY_VERSION,
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=signing_input.payload_sha256,
        signing_input_sha256=signing_input.digest_sha256,
        signature=encode_base64url(signature),
    )


class _KmsClient:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self.version_calls: list[tuple[dict[str, object], object, float]] = []
        self.public_calls: list[tuple[dict[str, object], object, float]] = []
        self.version_name = EVIDENCE_KEY_VERSION
        self.version_state = "ENABLED"
        self.version_algorithm = "EC_SIGN_P256_SHA256"
        self.public_name = EVIDENCE_KEY_VERSION
        self.public_algorithm = "EC_SIGN_P256_SHA256"
        self.pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    async def get_crypto_key_version(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object:
        self.version_calls.append((request, retry, timeout))
        return SimpleNamespace(
            name=self.version_name,
            state=self.version_state,
            algorithm=self.version_algorithm,
        )

    async def get_public_key(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object:
        self.public_calls.append((request, retry, timeout))
        return SimpleNamespace(
            name=self.public_name,
            algorithm=self.public_algorithm,
            pem=self.pem,
            pem_crc32c=google_crc32c.value(self.pem.encode("ascii")),
        )


class _CapabilityKmsClient:
    def __init__(self) -> None:
        self.version_requests: list[dict[str, object]] = []
        self.public_key_requests: list[dict[str, object]] = []
        private_key = ec.generate_private_key(ec.SECP256R1())
        self.pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def get_crypto_key_version(self, request: dict[str, object]) -> object:
        self.version_requests.append(request)
        return SimpleNamespace(
            name=CAPABILITY_KEY_VERSION,
            state="ENABLED",
            algorithm="EC_SIGN_P256_SHA256",
        )

    def get_public_key(self, request: dict[str, object]) -> object:
        self.public_key_requests.append(request)
        return SimpleNamespace(
            name=CAPABILITY_KEY_VERSION,
            algorithm="EC_SIGN_P256_SHA256",
            pem=self.pem,
            pem_crc32c=google_crc32c.value(self.pem.encode("ascii")),
        )


def test_preflight_contract_is_canonical_self_binding_and_rejects_substitution() -> None:
    request = _request()
    result = _result(request)

    assert decode_contract(canonical_json_bytes(request), RootPreflightRequestV1) == request
    assert decode_contract(canonical_json_bytes(result), RootPreflightResultV1) == result
    assert result.request_sha256 == root_preflight_request_sha256(request)

    values = result.model_dump(mode="json")
    values["candidate_revision"]["configuration_sha256"] = "f" * 64
    with pytest.raises(ValidationError):
        RootPreflightResultV1.model_validate(values)

    with pytest.raises(ValidationError):
        _request(candidate_revision=STABLE)
    with pytest.raises(ValidationError):
        _request(target=_target(project_id="controlgraph-canary-reconcile"))


def test_verifier_recaptures_exact_stable_and_validates_candidate() -> None:
    reader = _Reader()
    result = asyncio.run(_preflight_service(reader).preflight(_request(), _context()))

    assert result == _result()
    assert reader.calls == [
        "service",
        f"revision:{STABLE}",
        "service",
        f"revision:{CANDIDATE}",
        "service",
        f"revision:{STABLE}",
        "service",
    ]


def test_verifier_denies_drift_and_wrong_caller_without_candidate_read() -> None:
    drifted = _Reader(service=_service(generation=8, etag="service-etag-8"))
    with pytest.raises(RootPreflightError) as mismatch:
        asyncio.run(_preflight_service(drifted).preflight(_request(), _context()))
    assert mismatch.value.code is RootPreflightErrorCode.STABLE_MISMATCH
    assert f"revision:{CANDIDATE}" not in drifted.calls

    reader = _Reader()
    with pytest.raises(RootPreflightError) as denied:
        asyncio.run(
            _preflight_service(reader).preflight(
                _request(),
                _context(email=f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com"),
            )
        )
    assert denied.value.code is RootPreflightErrorCode.CALLER_DENIED
    assert reader.calls == []

    baseline = _service()
    final_drift = _service(generation=8, etag="service-etag-8")
    changed_after_candidate = _Reader(
        services=[baseline, baseline, final_drift, final_drift]
    )
    with pytest.raises(RootPreflightError) as final_mismatch:
        asyncio.run(
            _preflight_service(changed_after_candidate).preflight(
                _request(),
                _context(),
            )
        )
    assert final_mismatch.value.code is RootPreflightErrorCode.STABLE_MISMATCH
    assert changed_after_candidate.calls[-3:] == [
        "service",
        f"revision:{STABLE}",
        "service",
    ]


def test_authenticated_verifier_route_returns_only_canonical_result() -> None:
    reader = _Reader()
    app = create_service_app(
        ServiceRole.VERIFIER,
        authenticator=_Authenticator(),
        authentication_policy=_policy(),
        root_preflight_service=_preflight_service(reader),
    )
    response = TestClient(app).post(
        protected_paths(ServiceRole.VERIFIER)[0],
        content=canonical_json_bytes(_request()),
        headers={"Authorization": "Bearer synthetic.test.token"},
    )

    assert response.status_code == 200
    assert response.content == canonical_json_bytes(_result())
    assert decode_contract(response.content, RootPreflightResultV1) == _result()

    invalid = TestClient(app).post(
        protected_paths(ServiceRole.VERIFIER)[0],
        content=b" " + canonical_json_bytes(_request()),
        headers={"Authorization": "Bearer synthetic.test.token"},
    )
    assert invalid.status_code == 400
    assert invalid.json()["code"] == "CONTRACT_INVALID"


def test_coordinator_preflight_client_binds_request_and_converts_trusted_result() -> None:
    request = _request()
    transport = _Transport(canonical_json_bytes(_result(request)))
    client = CoordinatorRootPreflightClient(
        route=_route(ServiceRole.VERIFIER),
        transport=transport,
    )

    trusted = asyncio.run(client.preflight(request))

    assert trusted.stable_snapshot == _snapshot(captured_at="2026-08-19T12:00:00Z")
    assert trusted.candidate_revision == CandidateRevisionAttestation(
        target=_target(),
        candidate_revision=CANDIDATE,
        configuration_sha256=(
            cloud_run_revision_configuration_sha256(CANDIDATE_CONFIGURATION)
        ),
        generation=1,
        etag=f"{CANDIDATE}-etag",
        concurrency=8,
        reader_identity=VERIFIER_IDENTITY,
        captured_at="2026-08-19T12:00:00Z",
    )
    assert transport.calls == [
        (_route(ServiceRole.VERIFIER), canonical_json_bytes(request))
    ]

    other = _request(candidate_revision=f"{SERVICE}-candidate-v15")
    substituted = _Transport(canonical_json_bytes(_result()))
    with pytest.raises(RootTrustClientError) as failure:
        asyncio.run(
            CoordinatorRootPreflightClient(
                route=_route(ServiceRole.VERIFIER),
                transport=substituted,
            ).preflight(other)
        )
    assert failure.value.code is RootTrustClientErrorCode.RESPONSE_INVALID


def test_one_shot_oidc_transport_uses_exact_audience_url_and_never_retries() -> None:
    class TokenProvider:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def token(self, audience: str) -> str:
            self.calls.append(audience)
            return "synthetic.oidc.token"

    class Poster:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []
            self.status = 200

        def post(self, **request: object) -> InternalHttpResponse:
            self.calls.append(request)
            return InternalHttpResponse(
                status_code=self.status,
                content_type="application/json",
                body=b"{}",
            )

    tokens = TokenProvider()
    poster = Poster()
    route = _route(ServiceRole.VERIFIER)
    transport = GoogleOneShotOidcTransport(
        project_id=PROJECT,
        caller_role=CallerRole.COORDINATOR,
        token_provider=tokens,
        http_poster=poster,
        timeout_seconds=30.0,
    )

    assert asyncio.run(transport.post(route, b"{}")) == b"{}"
    assert tokens.calls == [VERIFIER_AUDIENCE]
    assert len(poster.calls) == 1
    assert poster.calls[0]["url"] == f"{VERIFIER_AUDIENCE}/v1/internal/verify"
    headers = poster.calls[0]["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer synthetic.oidc.token"
    assert poster.calls[0]["timeout"] == 30.0

    poster.status = 307
    with pytest.raises(InternalTransportError):
        asyncio.run(transport.post(route, b"{}"))
    assert len(poster.calls) == 2


def test_one_shot_oidc_transport_does_not_serialize_blocking_token_fetches() -> None:
    concurrent_calls = 4
    rendezvous = threading.Barrier(concurrent_calls)

    class TokenProvider:
        def token(self, audience: str) -> str:
            assert audience == VERIFIER_AUDIENCE
            rendezvous.wait(timeout=5)
            return "synthetic.oidc.token"

    class Poster:
        def post(self, **request: object) -> InternalHttpResponse:
            return InternalHttpResponse(
                status_code=200,
                content_type="application/json",
                body=b"{}",
            )

    route = _route(ServiceRole.VERIFIER)
    transport = GoogleOneShotOidcTransport(
        project_id=PROJECT,
        caller_role=CallerRole.COORDINATOR,
        token_provider=TokenProvider(),
        http_poster=Poster(),
        timeout_seconds=30.0,
    )

    async def post_concurrently() -> tuple[bytes, ...]:
        return tuple(
            await asyncio.gather(
                *(transport.post(route, b"{}") for _ in range(concurrent_calls))
            )
        )

    assert asyncio.run(post_concurrently()) == (b"{}",) * concurrent_calls


@pytest.mark.parametrize(
    "service_role",
    [ServiceRole.COORDINATOR, ServiceRole.VERIFIER, ServiceRole.ISSUER],
)
def test_evidence_client_verifies_exact_ecdsa_signature_and_key_version(
    service_role: ServiceRole,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    signed = _signed_event(private_key)
    kms = _KmsClient(private_key)
    verifier = GoogleKmsEvidenceSignatureVerifier(
        project_id=PROJECT,
        service_role=service_role,
        key_version=EVIDENCE_KEY_VERSION,
        client=kms,
    )
    transport = _Transport(canonical_json_bytes(signed))
    client = CoordinatorEvidenceClient(
        route=_route(ServiceRole.EVIDENCE_WRITER),
        evidence_key_version=EVIDENCE_KEY_VERSION,
        transport=transport,
        signature_verifier=verifier,
    )

    assert asyncio.run(client.sign(_event())) == signed
    assert kms.version_calls == [
        ({"name": EVIDENCE_KEY_VERSION}, None, 5.0)
    ]
    assert kms.public_calls == [
        ({"name": EVIDENCE_KEY_VERSION}, None, 5.0)
    ]

    forged = SignedEvidenceEventV1(
        schema_version=signed.schema_version,
        event=signed.event,
        purpose=signed.purpose,
        signing_key_version=signed.signing_key_version,
        signing_algorithm=signed.signing_algorithm,
        payload_sha256=signed.payload_sha256,
        signing_input_sha256=signed.signing_input_sha256,
        signature="c3ludGhldGljLWludmFsaWQtc2lnbmF0dXJl",
    )
    with pytest.raises(RootTrustClientError) as invalid:
        asyncio.run(
            CoordinatorEvidenceClient(
                route=_route(ServiceRole.EVIDENCE_WRITER),
                evidence_key_version=EVIDENCE_KEY_VERSION,
                transport=_Transport(canonical_json_bytes(forged)),
                signature_verifier=verifier,
            ).sign(_event())
        )
    assert invalid.value.code is RootTrustClientErrorCode.EVIDENCE_INVALID


@pytest.mark.parametrize(
    "service_role",
    [
        ServiceRole.API,
        ServiceRole.EVIDENCE_WRITER,
        ServiceRole.EXECUTOR,
        ServiceRole.RECOVERY,
    ],
)
def test_evidence_verifier_rejects_roles_outside_read_only_trust_boundary(
    service_role: ServiceRole,
) -> None:
    with pytest.raises(Exception) as failure:
        GoogleKmsEvidenceSignatureVerifier(
            project_id=PROJECT,
            service_role=service_role,
            key_version=EVIDENCE_KEY_VERSION,
            client=_KmsClient(ec.generate_private_key(ec.SECP256R1())),
        )

    assert "evidence verification role is invalid" in str(failure.value)


def test_evidence_verifier_rejects_kms_response_substitution() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    kms = _KmsClient(private_key)
    kms.public_name = EVIDENCE_KEY_VERSION.replace("/1", "/2")
    verifier = GoogleKmsEvidenceSignatureVerifier(
        project_id=PROJECT,
        service_role=ServiceRole.COORDINATOR,
        key_version=EVIDENCE_KEY_VERSION,
        client=kms,
    )

    with pytest.raises(Exception) as failure:
        asyncio.run(verifier.verify(_signed_event(private_key)))
    assert "another public key version" in str(failure.value)
    assert len(kms.public_calls) == 1


def _coordinator_environment() -> dict[str, str]:
    return {
        "CONTROLGRAPH_PROJECT_ID": PROJECT,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_SERVICE_NAME": "controlgraph-coordinator",
        "CONTROLGRAPH_CONTROLLER_ID": f"{PROJECT}:us-central1:coordinator",
        "CONTROLGRAPH_ROLE": "coordinator",
        "CONTROLGRAPH_BUILD_DIGEST": f"sha256:{'d' * 64}",
        "CONTROLGRAPH_CONTRACT_VERSION": "controlgraph.contract/v1",
        "CONTROLGRAPH_FIRESTORE_DATABASE": "controlgraph-authority",
        "CONTROLGRAPH_MUTATIONS_ENABLED": "false",
        "CONTROLGRAPH_ENVIRONMENT": "nonprod",
        "CONTROLGRAPH_AUTH_AUDIENCE": (
            f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "CONTROLGRAPH_AUTH_CALLER_ROLE": "api",
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
            f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": SUBJECT,
        "CONTROLGRAPH_ISSUER_URL": (
            f"https://controlgraph-issuer-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "CONTROLGRAPH_VERIFIER_URL": VERIFIER_AUDIENCE,
        "CONTROLGRAPH_EVIDENCE_WRITER_URL": EVIDENCE_AUDIENCE,
        "CONTROLGRAPH_CAPABILITY_KEY_VERSION": CAPABILITY_KEY_VERSION,
        "CONTROLGRAPH_EVIDENCE_KEY_VERSION": EVIDENCE_KEY_VERSION,
        "CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256": "b" * 64,
        "CONTROLGRAPH_OPERATOR_EMAIL": "operator@example.com",
        "CONTROLGRAPH_OPERATOR_SUBJECT": SUBJECT,
        "CONTROLGRAPH_SECURITY_AUDITOR_EMAIL": (
            f"cg-security-auditor@{PROJECT}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_SECURITY_AUDITOR_SUBJECT": "223456789012345678901",
        "CONTROLGRAPH_RESTRICTED_EXPORTER_EMAIL": (
            f"cg-restricted-exporter@{PROJECT}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_RESTRICTED_EXPORTER_SUBJECT": "323456789012345678901",
        "CONTROLGRAPH_EXECUTOR_URL": (
            f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "CONTROLGRAPH_RECOVERY_URL": (
            f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
        ),
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
        "CONTROLGRAPH_RECEIPT_AUTH_CALLER_SUBJECT": SUBJECT,
        "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_EMAIL": (
            f"controlgraph-executor@{PROJECT}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_SUBJECT": SUBJECT,
        "CONTROLGRAPH_TIMELINE_RETENTION_CALLER_EMAIL": (
            f"cg-retention-sweeper@{PROJECT}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_TIMELINE_RETENTION_CALLER_SUBJECT": SUBJECT,
        "CONTROLGRAPH_ADVISOR_URL": (
            f"https://controlgraph-advisor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
    }


class _UnusedTaskEnqueuer:
    async def enqueue(
        self,
        task: AddressedTask,
        *,
        now: datetime,
    ) -> TaskEnqueueResult:
        del task, now
        raise AssertionError("settings composition must not enqueue a task")


def test_coordinator_runtime_composes_exact_release_gate_with_mutations_disabled() -> None:
    environment = _coordinator_environment()
    settings = ControllerSettings.from_environment(environment)
    assert settings.verifier_url == VERIFIER_AUDIENCE
    assert settings.evidence_writer_url == EVIDENCE_AUDIENCE
    assert settings.evidence_key_version == EVIDENCE_KEY_VERSION

    transport = _Transport(b"{}")
    kms = _CapabilityKmsClient()
    app = create_runtime_service_app(
        ServiceRole.COORDINATOR,
        environment=environment,
        internal_transport=transport,
        kms_client=kms,
        task_enqueuer=_UnusedTaskEnqueuer(),
    )
    assert isinstance(app.state.controlgraph_trust_clients, CoordinatorTrustClients)
    assert not settings.mutations_enabled
    completion_workflow = app.state.controlgraph_completion_workflow
    assert completion_workflow._signed_intent_reader is not None
    assert completion_workflow._signed_intent_verifier is not None
    assert kms.version_requests == [{"name": CAPABILITY_KEY_VERSION}]
    assert kms.public_key_requests == [{"name": CAPABILITY_KEY_VERSION}]
    assert isinstance(app.state.controlgraph_advisor_client, CoordinatorAdvisorClient)
    assert isinstance(
        app.state.controlgraph_root_creation_relay,
        CoordinatorRootCreationRelay,
    )
    releaser = app.state.controlgraph_service_claim_releaser
    assert isinstance(releaser, ServiceClaimReleaser)
    assert releaser.target == _target()
    assert releaser.evidence_key_version == EVIDENCE_KEY_VERSION
    assert not any("release" in route.path for route in app.routes)

    substituted = dict(environment)
    substituted["CONTROLGRAPH_VERIFIER_URL"] = EVIDENCE_AUDIENCE
    with pytest.raises(ValueError):
        ControllerSettings.from_environment(substituted)


def test_preflight_contract_rejects_result_time_reversal() -> None:
    values = _result().model_dump(mode="json")
    values["candidate_revision"]["captured_at"] = "2026-08-19T12:00:01Z"
    with pytest.raises(ValidationError):
        RootPreflightResultV1.model_validate(values)


def test_client_sanitizes_transport_and_malformed_response_failures() -> None:
    class BrokenTransport:
        async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
            del route, body
            raise RuntimeError("unmistakably-synthetic-private-response")

    with pytest.raises(RootTrustClientError) as unavailable:
        asyncio.run(
            CoordinatorRootPreflightClient(
                route=_route(ServiceRole.VERIFIER),
                transport=BrokenTransport(),
            ).preflight(_request())
        )
    assert unavailable.value.code is RootTrustClientErrorCode.TRANSPORT_UNAVAILABLE
    assert "private-response" not in str(unavailable.value)

    malformed = _Transport(b'{"schema_version":"controlgraph.root-preflight-result/v1"}')
    with pytest.raises(RootTrustClientError) as invalid:
        asyncio.run(
            CoordinatorRootPreflightClient(
                route=_route(ServiceRole.VERIFIER),
                transport=malformed,
            ).preflight(_request())
        )
    assert invalid.value.code is RootTrustClientErrorCode.RESPONSE_INVALID
