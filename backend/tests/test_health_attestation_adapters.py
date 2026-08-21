from __future__ import annotations

import asyncio
from types import SimpleNamespace

import google_crc32c
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi.testclient import TestClient
from health_execution_test_data import make_healthy_chain
from recovery_v2_test_data import make_unhealthy_v3_recovery_bundle

from controlgraph_canary.application.health_attestation import (
    HealthAttestationError,
    HealthAttestationErrorCode,
    HealthAttestationSigningService,
    VerifierHealthAttestationClient,
)
from controlgraph_canary.application.identity import (
    HEALTH_ATTESTATION_PATH,
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.signing import SigningProfile
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    encode_base64url,
)
from controlgraph_canary.contracts.health_execution import (
    HEALTH_ATTESTATION_PURPOSE,
    P256_SIGNING_ALGORITHM,
    SIGNED_HEALTH_DECISION_PROOF_V1,
    HealthAttestationSigningRequestV1,
    SignedHealthDecisionProofV1,
    create_health_attestation_signing_request,
    create_health_decision_proof,
    health_attestation_signing_input_sha256,
)
from controlgraph_canary.contracts.recovery_execution import (
    create_recovery_prestate_attestation,
    recovery_prestate_signing_input_sha256,
)
from controlgraph_canary.http.service import create_service_app
from controlgraph_canary.integrations.google.kms import (
    GoogleKmsHealthAttestationVerifier,
    GoogleKmsRecoveryPrestateAttestationVerifier,
)

PROJECT = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
KEY_VERSION = (
    f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
)
AUDIENCE = (
    f"https://controlgraph-evidence-writer-{PROJECT_NUMBER}.us-central1.run.app"
)
VERIFIER_EMAIL = f"controlgraph-verifier@{PROJECT}.iam.gserviceaccount.com"


def _request(
    private_key: ec.EllipticCurvePrivateKey,
) -> HealthAttestationSigningRequestV1:
    chain = make_healthy_chain()
    first, second = chain.signed_proofs
    signing_input = health_attestation_signing_input_sha256(
        first.proof,
        KEY_VERSION,
    )
    signed_first = SignedHealthDecisionProofV1(
        schema_version=SIGNED_HEALTH_DECISION_PROOF_V1,
        proof=first.proof,
        purpose=HEALTH_ATTESTATION_PURPOSE,
        signing_key_version=KEY_VERSION,
        signing_algorithm=P256_SIGNING_ALGORITHM,
        payload_sha256=canonical_sha256(first.proof),
        signing_input_sha256=signing_input,
        signature=encode_base64url(
            private_key.sign(
                bytes.fromhex(signing_input),
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        ),
    )
    pending = create_health_decision_proof(
        anchor=chain.anchor,
        sequence=second.proof.sequence,
        previous_signed_proof_sha256=canonical_sha256(signed_first),
        prior_state=second.proof.prior_state,
        observation=second.proof.observation,
        decision=second.proof.decision,
    )
    return create_health_attestation_signing_request(
        anchor=chain.anchor,
        prior_signed_proof=signed_first,
        pending_proof=pending,
    )


def _policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EVIDENCE_WRITER,
        path=HEALTH_ATTESTATION_PATH,
        audience=AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.VERIFIER,
            email=VERIFIER_EMAIL,
            subject=SUBJECT,
        ),
    )


def _caller(**changes: object) -> AuthenticationContext:
    values: dict[str, object] = {
        "role": CallerRole.VERIFIER,
        "email": VERIFIER_EMAIL,
        "subject": SUBJECT,
        "issuer": "https://accounts.google.com",
        "audience": AUDIENCE,
        "issued_at": 1_776_942_000,
        "expires_at": 1_776_942_600,
    }
    values.update(changes)
    return AuthenticationContext(**values)  # type: ignore[arg-type]


class _DigestBackend:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self.profile = SigningProfile.evidence(PROJECT, KEY_VERSION)
        self.private_key = private_key
        self.calls: list[bytes] = []

    async def sign_digest(self, digest: bytes) -> bytes:
        self.calls.append(digest)
        return self.private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )


class _KmsClient:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self.version_calls = 0
        self.public_calls = 0
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
        self.version_calls += 1
        assert request == {"name": KEY_VERSION}
        assert retry is None
        assert timeout == 5.0
        return SimpleNamespace(
            name=KEY_VERSION,
            state="ENABLED",
            algorithm="EC_SIGN_P256_SHA256",
        )

    async def get_public_key(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object:
        self.public_calls += 1
        assert request == {"name": KEY_VERSION}
        assert retry is None
        assert timeout == 5.0
        return SimpleNamespace(
            name=KEY_VERSION,
            algorithm="EC_SIGN_P256_SHA256",
            pem=self.pem,
            pem_crc32c=google_crc32c.value(self.pem.encode("ascii")),
        )


def _signing_service(
    private_key: ec.EllipticCurvePrivateKey,
) -> tuple[HealthAttestationSigningService, _DigestBackend]:
    backend = _DigestBackend(private_key)
    verifier = GoogleKmsHealthAttestationVerifier(
        project_id=PROJECT,
        service_role=ServiceRole.EVIDENCE_WRITER,
        key_version=KEY_VERSION,
        client=_KmsClient(private_key),
    )
    return (
        HealthAttestationSigningService(
            project_id=PROJECT,
            authentication_policy=_policy(),
            signer=backend,
            signature_verifier=verifier,
        ),
        backend,
    )


class _Transport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        return self.response


class _Authenticator:
    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        if authorization_header != "Bearer exact.health.token":
            raise AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)
        if policy != _policy():
            raise AuthenticationError(AuthenticationDenialCode.CALLER_DENIED)
        return _caller()


def _route() -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.VERIFIER,
        service_role=ServiceRole.EVIDENCE_WRITER,
        audience=AUDIENCE,
        override_path=HEALTH_ATTESTATION_PATH,
    )


def _base_writer_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EVIDENCE_WRITER,
        path=protected_path(ServiceRole.EVIDENCE_WRITER),
        audience=AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.COORDINATOR,
            email=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com",
            subject=SUBJECT,
        ),
    )


def test_writer_replays_then_signs_and_read_only_roles_verify_exact_digest() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    request = _request(private_key)
    service, backend = _signing_service(private_key)

    signed = asyncio.run(service.attest(request, _caller()))

    assert signed.proof == request.pending_proof
    assert backend.calls == [
        bytes.fromhex(
            health_attestation_signing_input_sha256(
                request.pending_proof,
                KEY_VERSION,
            )
        )
    ]
    for role in (
        ServiceRole.VERIFIER,
        ServiceRole.ISSUER,
        ServiceRole.COORDINATOR,
        ServiceRole.EVIDENCE_WRITER,
    ):
        kms = _KmsClient(private_key)
        verifier = GoogleKmsHealthAttestationVerifier(
            project_id=PROJECT,
            service_role=role,
            key_version=KEY_VERSION,
            client=kms,
        )
        asyncio.run(verifier.verify(signed))
        assert (kms.version_calls, kms.public_calls) == (1, 1)


def test_writer_denies_identity_or_root_key_substitution_before_kms() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    request = _request(private_key)
    service, backend = _signing_service(private_key)

    with pytest.raises(HealthAttestationError) as denied:
        asyncio.run(service.attest(request, _caller(subject="999999")))
    assert denied.value.code is HealthAttestationErrorCode.CALLER_DENIED
    assert backend.calls == []

    substituted = request.model_copy(
        update={
            "anchor": request.anchor.model_copy(
                update={
                    "evidence_signing_key_version": KEY_VERSION.replace("/1", "/2")
                }
            )
        }
    )
    with pytest.raises(HealthAttestationError) as invalid:
        asyncio.run(service.attest(substituted, _caller()))
    assert invalid.value.code is HealthAttestationErrorCode.REQUEST_DENIED
    assert backend.calls == []


def test_verifier_client_posts_once_and_rejects_response_substitution() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    request = _request(private_key)
    service, _ = _signing_service(private_key)
    signed = asyncio.run(service.attest(request, _caller()))
    transport = _Transport(canonical_json_bytes(signed))
    client = VerifierHealthAttestationClient(
        route=_route(),
        transport=transport,
        signing_key_version=KEY_VERSION,
    )

    assert asyncio.run(client.attest(request)) == signed
    assert transport.calls == [(_route(), canonical_json_bytes(request))]

    transport.response = b'{"schema_version":"controlgraph.health-decision-proof/v1"}'
    with pytest.raises(HealthAttestationError) as invalid:
        asyncio.run(client.attest(request))
    assert invalid.value.code is HealthAttestationErrorCode.RESPONSE_INVALID
    assert len(transport.calls) == 2


def test_health_attestation_http_route_is_verifier_only_and_canonical() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    service, _ = _signing_service(private_key)
    client = TestClient(
        create_service_app(
            ServiceRole.EVIDENCE_WRITER,
            authenticator=_Authenticator(),
            authentication_policy=_base_writer_policy(),
            health_attestation_signing_service=service,
            health_attestation_authentication_policy=_policy(),
        )
    )
    request = _request(private_key)

    response = client.post(
        HEALTH_ATTESTATION_PATH,
        content=canonical_json_bytes(request),
        headers={"Authorization": "Bearer exact.health.token"},
    )
    assert response.status_code == 200

    denied = client.post(
        HEALTH_ATTESTATION_PATH,
        content=canonical_json_bytes(request),
        headers={"Authorization": "Bearer substituted.token"},
    )
    assert denied.status_code == 401
    assert denied.json()["code"] == "AUTH_CREDENTIAL_INVALID"

    malformed = client.post(
        HEALTH_ATTESTATION_PATH,
        content=b'{"schema_version":"unsupported"}',
        headers={"Authorization": "Bearer exact.health.token"},
    )
    assert malformed.status_code == 400
    assert malformed.json()["code"] == "CONTRACT_VERSION_UNSUPPORTED"


def test_health_verifier_rejects_a_forged_signature() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    request = _request(private_key)
    service, _ = _signing_service(private_key)
    signed = asyncio.run(service.attest(request, _caller()))
    forged = signed.model_copy(update={"signature": encode_base64url(b"forged")})
    verifier = GoogleKmsHealthAttestationVerifier(
        project_id=PROJECT,
        service_role=ServiceRole.ISSUER,
        key_version=KEY_VERSION,
        client=_KmsClient(private_key),
    )

    with pytest.raises(Exception, match="signature verification failed"):
        asyncio.run(verifier.verify(forged))


@pytest.mark.parametrize(
    "role",
    [ServiceRole.API, ServiceRole.EXECUTOR, ServiceRole.RECOVERY],
)
def test_health_verifier_rejects_roles_outside_read_only_trust_boundary(
    role: ServiceRole,
) -> None:
    with pytest.raises(Exception, match="verification role is invalid"):
        GoogleKmsHealthAttestationVerifier(
            project_id=PROJECT,
            service_role=role,
            key_version=KEY_VERSION,
            client=object(),
        )


def test_recovery_prestate_verifier_accepts_only_exact_digest_signature() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    result = make_unhealthy_v3_recovery_bundle().prestate_result
    digest = recovery_prestate_signing_input_sha256(result, KEY_VERSION)
    attestation = create_recovery_prestate_attestation(
        result=result,
        signature=encode_base64url(
            private_key.sign(
                bytes.fromhex(digest),
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        ),
    )
    kms = _KmsClient(private_key)
    verifier = GoogleKmsRecoveryPrestateAttestationVerifier(
        project_id=PROJECT,
        service_role=ServiceRole.RECOVERY,
        key_version=KEY_VERSION,
        client=kms,
    )

    asyncio.run(verifier.verify(attestation))
    assert (kms.version_calls, kms.public_calls) == (1, 1)

    forged = attestation.model_copy(
        update={"signature": encode_base64url(b"forged")}
    )
    with pytest.raises(Exception, match="signature verification failed"):
        asyncio.run(verifier.verify(forged))


@pytest.mark.parametrize(
    "role",
    [ServiceRole.API, ServiceRole.EVIDENCE_WRITER],
)
def test_recovery_prestate_verifier_rejects_unneeded_roles(
    role: ServiceRole,
) -> None:
    with pytest.raises(Exception, match="verification role is invalid"):
        GoogleKmsRecoveryPrestateAttestationVerifier(
            project_id=PROJECT,
            service_role=role,
            key_version=KEY_VERSION,
            client=object(),
        )
