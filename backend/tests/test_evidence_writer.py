from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from types import SimpleNamespace
from typing import cast

import google_crc32c
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from controlgraph_canary.application.evidence_signing import (
    EvidenceSigningError,
    EvidenceSigningErrorCode,
    EvidenceSigningService,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    runtime_route_policy,
)
from controlgraph_canary.application.signing import (
    AsyncPurposeSealedSigner,
    SigningError,
    SigningErrorCode,
    SigningProfile,
)
from controlgraph_canary.contracts import (
    EvidenceEvent,
    EvidenceKind,
    SignedEvidenceEventV1,
    TargetBinding,
    canonical_json_bytes,
    decode_contract,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.http.service import create_service_app, protected_paths
from controlgraph_canary.integrations.google.kms import GoogleKmsAsyncDigestSigner
from controlgraph_canary.services.runtime import create_runtime_service_app
from controlgraph_canary.settings import ControllerSettings

PROJECT_ID = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
)
AUDIENCE = (
    f"https://controlgraph-evidence-writer-{PROJECT_NUMBER}.us-central1.run.app"
)
AUTHORIZATION = "Bearer aaa.bbb.ccc"


def _target(**changes: str) -> TargetBinding:
    values = {
        "schema_version": "controlgraph.target-binding/v1",
        "project_id": PROJECT_ID,
        "region": "us-central1",
        "environment": "nonprod",
        "service_name": "controlgraph-reference-target",
    }
    values.update(changes)
    return TargetBinding.model_validate(values)


def _event(*, target: TargetBinding | None = None) -> EvidenceEvent:
    return EvidenceEvent(
        schema_version="controlgraph.evidence-event/v1",
        evidence_id="evidence:root:1",
        sequence=0,
        root_id=f"cgroot:{'a' * 64}",
        root_sha256="a" * 64,
        target=target or _target(),
        epoch=1,
        kind=EvidenceKind.ROOT_CREATED,
        actor="operator@example.com",
        request_id="request:root:1",
        receipt_id=None,
        occurred_at="2026-08-19T19:00:00Z",
        subject_sha256="b" * 64,
        previous_event_sha256=None,
        reason_code=None,
        provider_operation=None,
        target_configuration_sha256="c" * 64,
    )


def _event_with_extra_field(name: str, value: str) -> bytes:
    return canonical_json_bytes(_event())[:-1] + f',"{name}":"{value}"}}'.encode()


def _identity_environment() -> dict[str, str]:
    return {
        "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_ROLE": "evidence_writer",
        "CONTROLGRAPH_AUTH_AUDIENCE": AUDIENCE,
        "CONTROLGRAPH_AUTH_CALLER_ROLE": "coordinator",
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
            f"controlgraph-coordinator@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": SUBJECT,
    }


def _runtime_environment() -> dict[str, str]:
    return {
        **_identity_environment(),
        "CONTROLGRAPH_SERVICE_NAME": "controlgraph-evidence-writer",
        "CONTROLGRAPH_CONTROLLER_ID": f"{PROJECT_ID}:us-central1:evidence_writer",
        "CONTROLGRAPH_BUILD_DIGEST": f"sha256:{'d' * 64}",
        "CONTROLGRAPH_CONTRACT_VERSION": "controlgraph.contract/v1",
        "CONTROLGRAPH_FIRESTORE_DATABASE": "controlgraph-authority",
        "CONTROLGRAPH_MUTATIONS_ENABLED": "false",
        "CONTROLGRAPH_ENVIRONMENT": "nonprod",
        "CONTROLGRAPH_EVIDENCE_KEY_VERSION": KEY_VERSION,
        "CONTROLGRAPH_SIGNING_ALGORITHM": "EC_SIGN_P256_SHA256",
        "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_EMAIL": (
            f"controlgraph-verifier@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_SUBJECT": SUBJECT,
    }


def _policy() -> RouteAuthenticationPolicy:
    return runtime_route_policy(ServiceRole.EVIDENCE_WRITER, _identity_environment())


def _context(**changes: object) -> AuthenticationContext:
    values: dict[str, object] = {
        "role": CallerRole.COORDINATOR,
        "email": f"controlgraph-coordinator@{PROJECT_ID}.iam.gserviceaccount.com",
        "subject": SUBJECT,
        "issuer": "https://accounts.google.com",
        "audience": AUDIENCE,
        "issued_at": 1_776_236_340,
        "expires_at": 1_776_239_400,
    }
    values.update(changes)
    return AuthenticationContext(**values)  # type: ignore[arg-type]


class _DigestBackend:
    def __init__(self, profile: SigningProfile) -> None:
        self.profile = profile
        self.calls: list[bytes] = []
        self.error: BaseException | None = None
        self.signature = b"synthetic-evidence-signature"

    async def sign_digest(self, digest: bytes) -> bytes:
        self.calls.append(digest)
        if self.error is not None:
            raise self.error
        return self.signature


def _service(
    backend: _DigestBackend | None = None,
) -> tuple[EvidenceSigningService, _DigestBackend]:
    selected = backend or _DigestBackend(SigningProfile.evidence(PROJECT_ID, KEY_VERSION))
    return (
        EvidenceSigningService(
            project_id=PROJECT_ID,
            authentication_policy=_policy(),
            signer=AsyncPurposeSealedSigner(selected),
        ),
        selected,
    )


def _sign(
    service: EvidenceSigningService,
    event: EvidenceEvent,
    context: AuthenticationContext,
) -> SignedEvidenceEventV1:
    return asyncio.run(service.sign(event, context))


class _Authenticator:
    def __init__(self, context: AuthenticationContext | None = None) -> None:
        self.context = context or _context()
        self.calls: list[str | None] = []
        self.error: AuthenticationError | None = None

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        self.calls.append(authorization_header)
        if self.error is not None:
            raise self.error
        if authorization_header != AUTHORIZATION or policy != _policy():
            raise AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)
        return self.context


def _client(
    service: EvidenceSigningService,
    authenticator: _Authenticator | None = None,
) -> TestClient:
    return TestClient(
        create_service_app(
            ServiceRole.EVIDENCE_WRITER,
            authenticator=authenticator or _Authenticator(),
            authentication_policy=_policy(),
            evidence_signing_service=service,
        )
    )


def test_application_signs_with_exact_detached_signature_bindings() -> None:
    service, backend = _service()
    event = _event()

    signed = _sign(service, event, _context())

    assert signed.event == event
    assert signed.purpose == "EVIDENCE"
    assert signed.signing_key_version == KEY_VERSION
    assert signed.signing_algorithm == "EC_SIGN_P256_SHA256"
    assert signed.payload_sha256 == evidence_payload_sha256(event)
    assert signed.signing_input_sha256 == evidence_signing_input_sha256(event, KEY_VERSION)
    assert backend.calls == [bytes.fromhex(signed.signing_input_sha256)]


def test_generic_coordinator_route_cannot_sign_verifier_actor_provenance() -> None:
    service, backend = _service()
    event = _event().model_copy(
        update={
            "actor": (
                f"controlgraph-verifier@{PROJECT_ID}.iam.gserviceaccount.com"
            )
        }
    )

    with pytest.raises(EvidenceSigningError) as failure:
        _sign(service, event, _context())

    assert failure.value.code is EvidenceSigningErrorCode.ACTOR_DENIED
    assert backend.calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"role": CallerRole.API},
        {"email": f"controlgraph-api@{PROJECT_ID}.iam.gserviceaccount.com"},
        {"subject": "999999999999999999999"},
        {"issuer": cast(str, [])},
        {"issuer": "https://issuer.example"},
        {"audience": f"https://controlgraph-verifier-{PROJECT_NUMBER}.us-central1.run.app"},
    ],
)
def test_application_rechecks_the_exact_coordinator(changes: dict[str, object]) -> None:
    service, backend = _service()

    with pytest.raises(EvidenceSigningError) as failure:
        _sign(service, _event(), _context(**changes))

    assert failure.value.code is EvidenceSigningErrorCode.CALLER_DENIED
    assert backend.calls == []


@pytest.mark.parametrize(
    "target",
    [
        _target(project_id="controlgraph-canary-def456"),
        _target(region="europe-west1"),
        _target(environment="prod"),
        _target(service_name="controlgraph-other-target"),
    ],
)
def test_application_denies_every_target_substitution_before_signing(
    target: TargetBinding,
) -> None:
    service, backend = _service()

    with pytest.raises(EvidenceSigningError) as failure:
        _sign(service, _event(target=target), _context())

    assert failure.value.code is EvidenceSigningErrorCode.TARGET_DENIED
    assert backend.calls == []


def test_application_rejects_capability_signer_and_forbidden_project_configuration() -> None:
    capability_key = KEY_VERSION.replace("evidence-signing", "capability-signing")
    capability_backend = _DigestBackend(SigningProfile.capability(PROJECT_ID, capability_key))
    with pytest.raises(EvidenceSigningError) as wrong_purpose:
        EvidenceSigningService(
            project_id=PROJECT_ID,
            authentication_policy=_policy(),
            signer=AsyncPurposeSealedSigner(capability_backend),
        )
    assert wrong_purpose.value.code is EvidenceSigningErrorCode.CONFIGURATION_INVALID

    forbidden_project = "controlgraph-canary-reconcile"
    forbidden_key = KEY_VERSION.replace(PROJECT_ID, forbidden_project)
    forbidden_policy_values = _identity_environment()
    forbidden_policy_values["CONTROLGRAPH_PROJECT_ID"] = forbidden_project
    forbidden_policy_values["CONTROLGRAPH_AUTH_CALLER_EMAIL"] = (
        f"controlgraph-coordinator@{forbidden_project}.iam.gserviceaccount.com"
    )
    with pytest.raises(EvidenceSigningError) as forbidden:
        EvidenceSigningService(
            project_id=forbidden_project,
            authentication_policy=runtime_route_policy(
                ServiceRole.EVIDENCE_WRITER,
                forbidden_policy_values,
            ),
            signer=AsyncPurposeSealedSigner(
                _DigestBackend(SigningProfile.evidence(forbidden_project, forbidden_key))
            ),
        )
    assert forbidden.value.code is EvidenceSigningErrorCode.CONFIGURATION_INVALID


def test_application_sanitizes_signer_failures_and_propagates_cancellation() -> None:
    service, backend = _service()
    backend.error = SigningError(
        SigningErrorCode.PROVIDER_FAILURE,
        "unmistakably-synthetic-provider-diagnostic",
    )
    with pytest.raises(EvidenceSigningError) as failure:
        _sign(service, _event(), _context())
    assert failure.value.code is EvidenceSigningErrorCode.UNAVAILABLE
    assert "provider" not in str(failure.value)

    backend.error = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        _sign(service, _event(), _context())


def test_application_cancellation_reaches_the_active_signing_backend() -> None:
    profile = SigningProfile.evidence(PROJECT_ID, KEY_VERSION)

    class BlockingBackend:
        def __init__(self) -> None:
            self.profile = profile
            self.started = asyncio.Event()
            self.cancelled = False

        async def sign_digest(self, digest: bytes) -> bytes:
            assert len(digest) == 32
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise

    backend = BlockingBackend()
    service = EvidenceSigningService(
        project_id=PROJECT_ID,
        authentication_policy=_policy(),
        signer=AsyncPurposeSealedSigner(backend),
    )

    async def cancel_active_signing() -> None:
        task = asyncio.create_task(service.sign(_event(), _context()))
        await backend.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_active_signing())
    assert backend.cancelled is True


def test_authenticated_handler_returns_only_the_canonical_signed_contract() -> None:
    service, backend = _service()
    event = _event()
    response = _client(service).post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=canonical_json_bytes(event),
        headers={"Authorization": AUTHORIZATION, "Content-Type": "application/json"},
    )

    assert response.status_code == 200
    signed = decode_contract(response.content, SignedEvidenceEventV1)
    assert signed.event == event
    assert response.content == canonical_json_bytes(signed)
    assert len(backend.calls) == 1
    metadata = _client(service).get("/v1/metadata")
    assert metadata.json()["mutation_enabled"] is False


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"{}", "CONTRACT_INVALID"),
        (b'{"schema_version":"controlgraph.evidence-event/v2"}', "CONTRACT_VERSION_UNSUPPORTED"),
        (
            b'{"schema_version":"controlgraph.evidence-event/v1","schema_version":"x"}',
            "CONTRACT_INVALID",
        ),
        (b" " + canonical_json_bytes(_event()), "CONTRACT_INVALID"),
        (
            _event_with_extra_field("signing_key_version", "caller-key"),
            "CONTRACT_INVALID",
        ),
        (
            _event_with_extra_field("signing_algorithm", "caller-algorithm"),
            "CONTRACT_INVALID",
        ),
        (
            _event_with_extra_field("signing_url", "https://attacker.invalid"),
            "CONTRACT_INVALID",
        ),
        (b"x" * (MAX_CONTRACT_BYTES + 1), "CONTRACT_INVALID"),
    ],
)
def test_handler_rejects_noncanonical_or_signer_selecting_bodies(
    body: bytes,
    code: str,
) -> None:
    service, backend = _service()
    response = _client(service).post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=body,
        headers={"Authorization": AUTHORIZATION},
    )

    assert response.status_code == 400
    assert response.json()["code"] == code
    assert backend.calls == []


def test_authentication_precedes_body_parsing_and_never_reflects_body_or_token() -> None:
    service, backend = _service()
    authenticator = _Authenticator()
    authenticator.error = AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)
    marker = "unmistakably-synthetic-private-payload"
    response = _client(service, authenticator).post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=(b"x" * (MAX_CONTRACT_BYTES + 1)) + marker.encode(),
        headers={"Authorization": "Bearer private.synthetic.token"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_CREDENTIAL_INVALID"
    assert marker not in response.text
    assert "private.synthetic.token" not in response.text
    assert backend.calls == []


def test_handler_denies_wrong_target_and_sanitizes_provider_failure(
    capsys: pytest.CaptureFixture[str],
) -> None:
    service, backend = _service()
    client = _client(service)
    target_denial = client.post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=canonical_json_bytes(_event(target=_target(environment="prod"))),
        headers={"Authorization": AUTHORIZATION},
    )
    assert target_denial.status_code == 403
    assert target_denial.json()["code"] == "EVIDENCE_SIGNING_TARGET_DENIED"
    assert backend.calls == []

    marker = "unmistakably-synthetic-kms-diagnostic"
    backend.error = RuntimeError(marker)
    unavailable = client.post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=canonical_json_bytes(_event()),
        headers={"Authorization": AUTHORIZATION},
    )
    assert unavailable.status_code == 503
    assert unavailable.json()["code"] == "EVIDENCE_SIGNING_UNAVAILABLE"
    assert marker not in unavailable.text
    assert marker not in capsys.readouterr().err


def test_handler_rechecks_authenticator_output_before_signing() -> None:
    service, backend = _service()
    authenticator = _Authenticator(
        _context(email=f"controlgraph-api@{PROJECT_ID}.iam.gserviceaccount.com")
    )

    response = _client(service, authenticator).post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=canonical_json_bytes(_event()),
        headers={"Authorization": AUTHORIZATION},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "EVIDENCE_SIGNING_CALLER_DENIED"
    assert backend.calls == []


def test_signed_contract_rejects_event_and_signature_binding_tampering() -> None:
    service, _ = _service()
    signed = _sign(service, _event(), _context())
    values = signed.model_dump(mode="json")

    tampered_event = json.loads(json.dumps(values))
    tampered_event["event"]["actor"] = "substituted@example.com"
    with pytest.raises(ValidationError):
        SignedEvidenceEventV1.model_validate(tampered_event)

    tampered_digest = json.loads(json.dumps(values))
    tampered_digest["signing_input_sha256"] = "f" * 64
    with pytest.raises(ValidationError):
        SignedEvidenceEventV1.model_validate(tampered_digest)


class _FakeKmsClient:
    def __init__(self) -> None:
        self.version_requests: list[dict[str, object]] = []
        self.sign_requests: list[dict[str, object]] = []
        self.failure: BaseException | None = None
        self.sign_failure: BaseException | None = None
        self.version_name = KEY_VERSION
        self.version_state = "ENABLED"
        self.version_algorithm = "EC_SIGN_P256_SHA256"
        self.sign_name = KEY_VERSION
        self.signature = b"synthetic-runtime-evidence-signature"
        self.signature_crc32c: int | None = None
        self.verified_digest_crc32c = True

    async def get_crypto_key_version(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object:
        assert retry is None
        assert timeout == 5.0
        self.version_requests.append(request)
        if self.failure is not None:
            raise self.failure
        return SimpleNamespace(
            name=self.version_name,
            state=self.version_state,
            algorithm=self.version_algorithm,
        )

    async def asymmetric_sign(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object:
        assert retry is None
        assert timeout == 5.0
        self.sign_requests.append(request)
        if self.failure is not None:
            raise self.failure
        if self.sign_failure is not None:
            raise self.sign_failure
        return SimpleNamespace(
            name=self.sign_name,
            signature=self.signature,
            signature_crc32c=(
                google_crc32c.value(self.signature)
                if self.signature_crc32c is None
                else self.signature_crc32c
            ),
            verified_digest_crc32c=self.verified_digest_crc32c,
        )


def _token_verifier(token: str, audience: str) -> dict[str, object]:
    assert token == "aaa.bbb.ccc"
    assert audience == AUDIENCE
    return {
        "iss": "https://accounts.google.com",
        "aud": AUDIENCE,
        "email": f"controlgraph-coordinator@{PROJECT_ID}.iam.gserviceaccount.com",
        "email_verified": True,
        "sub": SUBJECT,
        "iat": 1_776_236_340,
        "exp": 1_776_239_400,
    }


def test_runtime_composes_one_exact_evidence_kms_request_without_body_selection() -> None:
    kms = _FakeKmsClient()
    app = create_runtime_service_app(
        ServiceRole.EVIDENCE_WRITER,
        environment=_runtime_environment(),
        token_verifier=_token_verifier,
        clock=lambda: 1_776_236_400.0,
        kms_client=kms,
    )
    response = TestClient(app).post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=canonical_json_bytes(_event()),
        headers={"Authorization": AUTHORIZATION},
    )

    assert response.status_code == 200
    assert kms.version_requests == [{"name": KEY_VERSION}]
    assert len(kms.sign_requests) == 1
    assert kms.sign_requests[0]["name"] == KEY_VERSION
    assert set(kms.sign_requests[0]) == {"name", "digest", "digest_crc32c"}


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("version_name", KEY_VERSION.replace("/1", "/2"), SigningErrorCode.KEY_VERSION_MISMATCH),
        ("version_state", "DISABLED", SigningErrorCode.KEY_VERSION_DISABLED),
        ("version_algorithm", "EC_SIGN_P384_SHA384", SigningErrorCode.ALGORITHM_MISMATCH),
    ],
)
def test_async_kms_rejects_substituted_or_disabled_version_metadata(
    field: str,
    value: str,
    code: SigningErrorCode,
) -> None:
    kms = _FakeKmsClient()
    setattr(kms, field, value)
    signer = GoogleKmsAsyncDigestSigner(
        SigningProfile.evidence(PROJECT_ID, KEY_VERSION),
        client=kms,
    )

    with pytest.raises(SigningError) as failure:
        asyncio.run(signer.sign_digest(b"d" * 32))

    assert failure.value.code is code
    assert len(kms.version_requests) == 1
    assert kms.sign_requests == []


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("sign_name", KEY_VERSION.replace("/1", "/2"), SigningErrorCode.KEY_VERSION_MISMATCH),
        ("verified_digest_crc32c", False, SigningErrorCode.CRC_MISMATCH),
        ("signature", b"", SigningErrorCode.SIGNATURE_INVALID),
        ("signature_crc32c", 0, SigningErrorCode.CRC_MISMATCH),
    ],
)
def test_async_kms_rejects_invalid_signing_responses(
    field: str,
    value: object,
    code: SigningErrorCode,
) -> None:
    kms = _FakeKmsClient()
    setattr(kms, field, value)
    signer = GoogleKmsAsyncDigestSigner(
        SigningProfile.evidence(PROJECT_ID, KEY_VERSION),
        client=kms,
    )

    with pytest.raises(SigningError) as failure:
        asyncio.run(signer.sign_digest(b"d" * 32))

    assert failure.value.code is code
    assert len(kms.version_requests) == 1
    assert len(kms.sign_requests) == 1


def test_async_kms_sanitizes_sign_stage_failures_and_propagates_cancellation() -> None:
    kms = _FakeKmsClient()
    signer = GoogleKmsAsyncDigestSigner(
        SigningProfile.evidence(PROJECT_ID, KEY_VERSION),
        client=kms,
    )
    kms.sign_failure = RuntimeError("unmistakably-synthetic-sign-stage-diagnostic")

    with pytest.raises(SigningError) as failure:
        asyncio.run(signer.sign_digest(b"d" * 32))

    assert failure.value.code is SigningErrorCode.PROVIDER_FAILURE
    assert "diagnostic" not in str(failure.value)
    assert len(kms.version_requests) == 1
    assert len(kms.sign_requests) == 1

    kms.sign_failure = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(signer.sign_digest(b"d" * 32))


@pytest.mark.parametrize(
    "missing",
    [
        "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
        "CONTROLGRAPH_SIGNING_ALGORITHM",
        "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_EMAIL",
        "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_SUBJECT",
    ],
)
def test_evidence_writer_settings_require_every_signing_binding(missing: str) -> None:
    environment = _runtime_environment()
    environment.pop(missing)

    with pytest.raises(ValueError, match=missing):
        ControllerSettings.from_environment(environment)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        (
            "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
            KEY_VERSION.replace(PROJECT_ID, "controlgraph-canary-def456"),
        ),
        (
            "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
            KEY_VERSION.replace("evidence-signing", "capability-signing"),
        ),
        ("CONTROLGRAPH_SIGNING_ALGORITHM", "EC_SIGN_P384_SHA384"),
        ("CONTROLGRAPH_SERVICE_NAME", "controlgraph-evidence_writer"),
        ("CONTROLGRAPH_AUTH_CALLER_ROLE", "api"),
    ],
)
def test_runtime_rejects_signing_and_identity_configuration_substitution(
    key: str,
    value: str,
) -> None:
    environment = _runtime_environment()
    environment[key] = value

    with pytest.raises((EvidenceSigningError, SigningError, ValueError)):
        create_runtime_service_app(
            ServiceRole.EVIDENCE_WRITER,
            environment=environment,
            token_verifier=_token_verifier,
            kms_client=_FakeKmsClient(),
        )


def test_runtime_provider_failure_is_stable_payload_free_and_not_retried() -> None:
    kms = _FakeKmsClient()
    marker = "unmistakably-synthetic-provider-private-text"
    kms.failure = RuntimeError(marker)
    app = create_runtime_service_app(
        ServiceRole.EVIDENCE_WRITER,
        environment=_runtime_environment(),
        token_verifier=_token_verifier,
        clock=lambda: 1_776_236_400.0,
        kms_client=kms,
    )
    response = TestClient(app).post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=canonical_json_bytes(_event()),
        headers={"Authorization": AUTHORIZATION},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "EVIDENCE_SIGNING_UNAVAILABLE"
    assert marker not in response.text
    assert len(kms.version_requests) == 1
    assert kms.sign_requests == []


def test_runtime_defers_kms_client_creation_until_an_authenticated_sign_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import controlgraph_canary.integrations.google.kms as kms_module

    kms = _FakeKmsClient()
    creations: list[bool] = []

    def create_client() -> _FakeKmsClient:
        creations.append(True)
        return kms

    monkeypatch.setattr(kms_module, "_default_async_client", create_client)
    app = create_runtime_service_app(
        ServiceRole.EVIDENCE_WRITER,
        environment=_runtime_environment(),
        token_verifier=_token_verifier,
        clock=lambda: 1_776_236_400.0,
    )
    client = TestClient(app)

    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/metadata").status_code == 200
    assert creations == []

    response = client.post(
        protected_paths(ServiceRole.EVIDENCE_WRITER)[0],
        content=canonical_json_bytes(_event()),
        headers={"Authorization": AUTHORIZATION},
    )
    assert response.status_code == 200
    assert creations == [True]


def test_runtime_service_has_no_firestore_or_cloud_run_adapter_dependency() -> None:
    environment = {**os.environ, **_runtime_environment()}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, sys; "
                "import controlgraph_canary.services.evidence_writer.app; "
                "print(json.dumps(sorted(name for name in sys.modules "
                "if name.startswith('controlgraph_canary.integrations.google.') "
                "and (name.endswith('.firestore') or name.endswith('.cloud_run')))))"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert json.loads(result.stdout) == []
