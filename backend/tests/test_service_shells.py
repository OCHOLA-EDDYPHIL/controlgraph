from __future__ import annotations

import importlib
import json
import re
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
    RouteAuthenticationPolicy,
    runtime_route_policy,
    runtime_service_name,
)
from controlgraph_canary.application.promotion_execution import (
    ApiPromotionClient,
    CoordinatorPromotionRelay,
)
from controlgraph_canary.application.revocation_relay import (
    ApiEpochRevocationClient,
    CoordinatorEpochRevocationRelay,
)
from controlgraph_canary.application.root_relay import (
    ApiRootCreationClient,
    CoordinatorRootCreationRelay,
)
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.http.service import (
    PRODUCT_CONTRACT_VERSION,
    SERVICE_SHELL_VERSION,
    ServiceRole,
    create_service_app,
    protected_paths,
)
from controlgraph_canary.integrations.google.identity import GoogleIdentityVerifier
from controlgraph_canary.services.runtime import create_runtime_service_app

ROLE_MODULES = (
    (ServiceRole.API, "controlgraph_canary.services.api.app"),
    (ServiceRole.COORDINATOR, "controlgraph_canary.services.coordinator.app"),
    (ServiceRole.ISSUER, "controlgraph_canary.services.issuer.app"),
    (ServiceRole.EXECUTOR, "controlgraph_canary.services.executor.app"),
    (ServiceRole.RECOVERY, "controlgraph_canary.services.recovery.app"),
    (ServiceRole.VERIFIER, "controlgraph_canary.services.verifier.app"),
    (ServiceRole.EVIDENCE_WRITER, "controlgraph_canary.services.evidence_writer.app"),
)

PROJECT_ID = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
CALLER_ROLES = {
    ServiceRole.API: CallerRole.OPERATOR,
    ServiceRole.COORDINATOR: CallerRole.API,
    ServiceRole.ISSUER: CallerRole.COORDINATOR,
    ServiceRole.EXECUTOR: CallerRole.EXECUTION_TASK_CALLER,
    ServiceRole.RECOVERY: CallerRole.RECOVERY_TASK_CALLER,
    ServiceRole.VERIFIER: CallerRole.COORDINATOR,
    ServiceRole.EVIDENCE_WRITER: CallerRole.COORDINATOR,
}
CALLER_ACCOUNT_IDS = {
    CallerRole.API: "controlgraph-api",
    CallerRole.COORDINATOR: "controlgraph-coordinator",
    CallerRole.EXECUTION_TASK_CALLER: "cg-execution-task-caller",
    CallerRole.RECOVERY_TASK_CALLER: "cg-recovery-task-caller",
}


def _credential_headers(role: ServiceRole, value: str) -> dict[str, str]:
    if role is ServiceRole.API:
        prefix, separator, signature = value.removeprefix("Bearer ").rpartition(".")
        assert prefix and separator and signature
        return {
            CONTROLGRAPH_AUTHORIZATION_HEADER: value,
            SERVERLESS_AUTHORIZATION_HEADER: (
                f"bearer {prefix}.SIGNATURE_REMOVED_BY_GOOGLE"
            ),
        }
    return {"Authorization": value}


def _caller_email(role: CallerRole) -> str:
    if role is CallerRole.OPERATOR:
        return "operator@example.com"
    return f"{CALLER_ACCOUNT_IDS[role]}@{PROJECT_ID}.iam.gserviceaccount.com"


def _environment(role: ServiceRole) -> dict[str, str]:
    caller_role = CALLER_ROLES[role]
    environment = {
        "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_SERVICE_NAME": runtime_service_name(role),
        "CONTROLGRAPH_CONTROLLER_ID": f"{PROJECT_ID}:us-central1:{role.value}",
        "CONTROLGRAPH_ROLE": role.value,
        "CONTROLGRAPH_BUILD_DIGEST": f"sha256:{'a' * 64}",
        "CONTROLGRAPH_CONTRACT_VERSION": PRODUCT_CONTRACT_VERSION,
        "CONTROLGRAPH_FIRESTORE_DATABASE": "controlgraph-authority",
        "CONTROLGRAPH_MUTATIONS_ENABLED": "false",
        "CONTROLGRAPH_ENVIRONMENT": "nonprod",
        "CONTROLGRAPH_AUTH_AUDIENCE": (
            f"https://{runtime_service_name(role)}-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "CONTROLGRAPH_AUTH_CALLER_ROLE": caller_role.value,
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": _caller_email(caller_role),
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": SUBJECT,
    }
    if role is ServiceRole.EVIDENCE_WRITER:
        environment.update(
            {
                "CONTROLGRAPH_EVIDENCE_KEY_VERSION": (
                    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
                    "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
                ),
                "CONTROLGRAPH_SIGNING_ALGORITHM": "EC_SIGN_P256_SHA256",
                "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_EMAIL": (
                    f"controlgraph-verifier@{PROJECT_ID}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_SUBJECT": SUBJECT,
            }
        )
    if role is ServiceRole.ISSUER:
        environment.update(
            {
                "CONTROLGRAPH_CAPABILITY_KEY_VERSION": (
                    f"projects/{PROJECT_ID}/locations/us-central1/"
                    "keyRings/controlgraph-signing/cryptoKeys/capability-signing/"
                    "cryptoKeyVersions/1"
                ),
                "CONTROLGRAPH_EVIDENCE_KEY_VERSION": (
                    f"projects/{PROJECT_ID}/locations/us-central1/"
                    "keyRings/controlgraph-signing/cryptoKeys/evidence-signing/"
                    "cryptoKeyVersions/1"
                ),
                "CONTROLGRAPH_SIGNING_ALGORITHM": "EC_SIGN_P256_SHA256",
                "CONTROLGRAPH_RECOVERY_URL": (
                    f"https://controlgraph-recovery-{PROJECT_NUMBER}."
                    "us-central1.run.app"
                ),
            }
        )
    if role is ServiceRole.API:
        environment.update(
            {
                "CONTROLGRAPH_COORDINATOR_URL": (
                    f"https://controlgraph-coordinator-{PROJECT_NUMBER}."
                    "us-central1.run.app"
                ),
                "CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE": (
                    "32555940559.apps.googleusercontent.com"
                ),
            }
        )
    if role is ServiceRole.COORDINATOR:
        environment.update(
            {
                "CONTROLGRAPH_ISSUER_URL": (
                    f"https://controlgraph-issuer-{PROJECT_NUMBER}."
                    "us-central1.run.app"
                ),
                "CONTROLGRAPH_VERIFIER_URL": (
                    f"https://controlgraph-verifier-{PROJECT_NUMBER}.us-central1.run.app"
                ),
                "CONTROLGRAPH_EVIDENCE_WRITER_URL": (
                    "https://controlgraph-evidence-writer-"
                    f"{PROJECT_NUMBER}.us-central1.run.app"
                ),
                "CONTROLGRAPH_EVIDENCE_KEY_VERSION": (
                    f"projects/{PROJECT_ID}/locations/us-central1/"
                    "keyRings/controlgraph-signing/cryptoKeys/evidence-signing/"
                    "cryptoKeyVersions/1"
                ),
                "CONTROLGRAPH_CAPABILITY_KEY_VERSION": (
                    f"projects/{PROJECT_ID}/locations/us-central1/"
                    "keyRings/controlgraph-signing/cryptoKeys/capability-signing/"
                    "cryptoKeyVersions/1"
                ),
                "CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256": "b" * 64,
                "CONTROLGRAPH_OPERATOR_EMAIL": "operator@example.com",
                "CONTROLGRAPH_OPERATOR_SUBJECT": SUBJECT,
                "CONTROLGRAPH_EXECUTOR_URL": (
                    f"https://controlgraph-executor-{PROJECT_NUMBER}."
                    "us-central1.run.app"
                ),
                "CONTROLGRAPH_RECOVERY_URL": (
                    f"https://controlgraph-recovery-{PROJECT_NUMBER}."
                    "us-central1.run.app"
                ),
                "CONTROLGRAPH_EXECUTION_QUEUE": "controlgraph-execution",
                "CONTROLGRAPH_RECOVERY_QUEUE": "controlgraph-recovery",
                "CONTROLGRAPH_EXECUTION_TASK_CALLER": (
                    f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_RECOVERY_TASK_CALLER": (
                    f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_RECEIPT_AUTH_CALLER_EMAIL": (
                    f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_RECEIPT_AUTH_CALLER_SUBJECT": SUBJECT,
                "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_EMAIL": (
                    f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"
                ),
                "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_SUBJECT": SUBJECT,
            }
        )
    if role is ServiceRole.VERIFIER:
        environment.update(
            {
                "CONTROLGRAPH_TARGET_NETWORK_RESOURCE": (
                    f"projects/{PROJECT_ID}/global/networks/controlgraph"
                ),
                "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE": (
                    f"projects/{PROJECT_ID}/regions/us-central1/"
                    "subnetworks/controlgraph"
                ),
                "CONTROLGRAPH_EVIDENCE_WRITER_URL": (
                    "https://controlgraph-evidence-writer-"
                    f"{PROJECT_NUMBER}.us-central1.run.app"
                ),
                "CONTROLGRAPH_EVIDENCE_KEY_VERSION": (
                    f"projects/{PROJECT_ID}/locations/us-central1/"
                    "keyRings/controlgraph-signing/cryptoKeys/evidence-signing/"
                    "cryptoKeyVersions/1"
                ),
            }
        )
    return environment


class _ExactTestAuthenticator:
    def __init__(self, expected_header: str) -> None:
        self.expected_header = expected_header
        self.calls: list[tuple[str | None, RouteAuthenticationPolicy]] = []

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        self.calls.append((authorization_header, policy))
        if authorization_header is None:
            raise AuthenticationError(AuthenticationDenialCode.CREDENTIAL_MISSING)
        if authorization_header != self.expected_header:
            raise AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)
        return AuthenticationContext(
            role=policy.caller.role,
            email=policy.caller.email,
            subject=policy.caller.subject,
            issuer="https://accounts.google.com",
            audience=policy.audience,
            issued_at=1_776_236_340,
            expires_at=1_776_239_400,
        )


@pytest.mark.parametrize(("role", "module_name"), ROLE_MODULES)
def test_each_service_role_has_identity_safe_health_and_metadata(
    role: ServiceRole,
    module_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key, value in _environment(role).items():
        monkeypatch.setenv(key, value)
    module = importlib.import_module(module_name)
    client = TestClient(module.app)

    if role is ServiceRole.API:
        assert isinstance(
            module.app.state.controlgraph_root_creation_client,
            ApiRootCreationClient,
        )
        assert isinstance(
            module.app.state.controlgraph_epoch_revocation_client,
            ApiEpochRevocationClient,
        )
        assert isinstance(
            module.app.state.controlgraph_promotion_client,
            ApiPromotionClient,
        )
    if role is ServiceRole.COORDINATOR:
        assert isinstance(
            module.app.state.controlgraph_root_creation_relay,
            CoordinatorRootCreationRelay,
        )
        assert isinstance(
            module.app.state.controlgraph_epoch_revocation_relay,
            CoordinatorEpochRevocationRelay,
        )
        assert isinstance(
            module.app.state.controlgraph_promotion_relay,
            CoordinatorPromotionRelay,
        )

    health = client.get("/healthz")
    metadata = client.get("/v1/metadata")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["service_role"] == role.value
    assert re.fullmatch(r"[0-9a-f]{32}", health.json()["correlation_id"])
    assert health.headers["x-controlgraph-correlation-id"] == health.json()["correlation_id"]
    assert metadata.status_code == 200
    assert metadata.json()["contract_version"] == PRODUCT_CONTRACT_VERSION
    assert metadata.json()["service_shell_version"] == SERVICE_SHELL_VERSION
    assert metadata.json()["service_role"] == role.value
    assert metadata.json()["mutation_enabled"] is False
    assert metadata.json()["build_digest"] == _environment(role)["CONTROLGRAPH_BUILD_DIGEST"]
    assert re.fullmatch(r"[0-9a-f]{32}", metadata.json()["correlation_id"])
    assert metadata.headers["x-controlgraph-correlation-id"] == metadata.json()["correlation_id"]
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@pytest.mark.parametrize("role", tuple(ServiceRole))
def test_every_protected_route_remains_disabled_without_reading_sensitive_body(
    role: ServiceRole,
    caplog: pytest.LogCaptureFixture,
) -> None:
    digest = f"sha256:{'c' * 64}"
    policy = runtime_route_policy(role, _environment(role))
    sensitive_marker = "unmistakably-synthetic-capability"
    token_marker = "unmistakably-synthetic-token"
    authorization = f"Bearer header.payload.{token_marker}"
    authenticator = _ExactTestAuthenticator(authorization)
    client = TestClient(
        create_service_app(
            role,
            build_digest=digest,
            authenticator=authenticator,
            authentication_policy=policy,
        )
    )

    for path in protected_paths(role):
        response = client.post(
            path,
            content=f'{{"capability":"{sensitive_marker}"}}',
            headers={
                "Content-Type": "application/json",
                **_credential_headers(role, authorization),
            },
        )
        assert response.status_code == 503
        expected_code = (
            "EVIDENCE_SIGNING_CONFIGURATION_INVALID"
            if role is ServiceRole.EVIDENCE_WRITER
            else "MUTATION_DISABLED"
        )
        assert response.json()["code"] == expected_code
        assert re.fullmatch(r"[0-9a-f]{32}", response.json()["correlation_id"])
        assert (
            response.headers["x-controlgraph-correlation-id"] == response.json()["correlation_id"]
        )
        assert sensitive_marker not in response.text
        assert token_marker not in response.text

        missing = client.post(path, content=f'{{"capability":"{sensitive_marker}"}}')
        assert missing.status_code == 401
        assert missing.json()["code"] == "AUTH_CREDENTIAL_MISSING"

    metadata = client.get("/v1/metadata")
    assert metadata.json()["build_digest"] == digest
    assert metadata.json()["mutation_enabled"] is False
    assert sensitive_marker not in caplog.text
    assert token_marker not in caplog.text
    assert authenticator.calls


def test_valid_identity_without_capability_cannot_enable_mutation() -> None:
    role = ServiceRole.EXECUTOR
    policy = runtime_route_policy(role, _environment(role))
    authorization = "Bearer exact.test.credential"
    authenticator = _ExactTestAuthenticator(authorization)
    client = TestClient(
        create_service_app(
            role,
            authenticator=authenticator,
            authentication_policy=policy,
        )
    )

    response = client.post(
        protected_paths(role)[0],
        headers={"Authorization": authorization},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_DISABLED"
    assert authenticator.calls == [(authorization, policy)]


def test_retried_delivery_reenters_the_same_authentication_gate() -> None:
    role = ServiceRole.RECOVERY
    policy = runtime_route_policy(role, _environment(role))
    authorization = "Bearer exact.retry.credential"
    authenticator = _ExactTestAuthenticator(authorization)
    client = TestClient(
        create_service_app(
            role,
            authenticator=authenticator,
            authentication_policy=policy,
        )
    )

    first = client.post(protected_paths(role)[0], headers={"Authorization": authorization})
    retry = client.post(protected_paths(role)[0], headers={"Authorization": authorization})

    assert first.status_code == 503
    assert retry.status_code == 503
    assert first.json()["code"] == "MUTATION_DISABLED"
    assert retry.json()["code"] == "MUTATION_DISABLED"
    assert authenticator.calls == [(authorization, policy), (authorization, policy)]


def test_missing_authentication_configuration_and_duplicate_headers_fail_closed() -> None:
    role = ServiceRole.EXECUTOR
    path = protected_paths(role)[0]
    unconfigured = TestClient(create_service_app(role)).post(path)
    assert unconfigured.status_code == 503
    assert unconfigured.json()["code"] == "AUTH_CONFIGURATION_INVALID"

    policy = runtime_route_policy(role, _environment(role))
    authenticator = _ExactTestAuthenticator("Bearer exact.test.credential")
    configured = TestClient(
        create_service_app(
            role,
            authenticator=authenticator,
            authentication_policy=policy,
        )
    )
    duplicate = configured.post(
        path,
        headers=[
            ("Authorization", "Bearer exact.test.credential"),
            ("Authorization", "Bearer substituted.test.credential"),
        ],
    )

    assert duplicate.status_code == 401
    assert duplicate.json()["code"] == "AUTH_CREDENTIAL_MALFORMED"
    assert authenticator.calls == []


def test_runtime_composition_uses_startup_policy_for_google_verification() -> None:
    role = ServiceRole.ISSUER
    environment = _environment(role)
    expected_audience = environment["CONTROLGRAPH_AUTH_AUDIENCE"]
    calls: list[tuple[str, str]] = []

    def verify_token(token: str, audience: str) -> dict[str, object]:
        calls.append((token, audience))
        return {
            "iss": "https://accounts.google.com",
            "aud": expected_audience,
            "email": environment["CONTROLGRAPH_AUTH_CALLER_EMAIL"],
            "email_verified": True,
            "sub": SUBJECT,
            "iat": 1_776_236_340,
            "exp": 1_776_239_400,
        }

    client = TestClient(
        create_runtime_service_app(
            role,
            environment=environment,
            token_verifier=verify_token,
            clock=lambda: 1_776_236_400.0,
            kms_client=object(),
        )
    )
    response = client.post(
        protected_paths(role)[0],
        content=b"{}",
        headers={"Authorization": "Bearer exact.test.credential"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "CONTRACT_INVALID"
    assert calls == [("exact.test.credential", expected_audience)]


def test_api_runtime_verifies_operator_token_against_oauth_client_audience() -> None:
    environment = _environment(ServiceRole.API)
    oauth_audience = environment["CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE"]
    calls: list[tuple[str, str]] = []

    def verify_token(token: str, audience: str) -> dict[str, object]:
        calls.append((token, audience))
        return {
            "iss": "https://accounts.google.com",
            "aud": oauth_audience,
            "email": environment["CONTROLGRAPH_AUTH_CALLER_EMAIL"],
            "email_verified": True,
            "sub": SUBJECT,
            "iat": 1_776_236_340,
            "exp": 1_776_239_400,
        }

    client = TestClient(
        create_runtime_service_app(
            ServiceRole.API,
            environment=environment,
            token_verifier=verify_token,
            clock=lambda: 1_776_236_400.0,
        )
    )
    response = client.post(
        protected_paths(ServiceRole.API)[0],
        content=b"{}",
        headers=_credential_headers(
            ServiceRole.API,
            "Bearer exact.test.credential",
        ),
    )

    assert response.status_code == 400
    assert response.json()["code"] == "CONTRACT_INVALID"
    assert calls == [("exact.test.credential", oauth_audience)]


@pytest.mark.parametrize(
    "headers",
    [
        [("Authorization", "Bearer header.payload.signature")],
        [(CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature")],
        [(SERVERLESS_AUTHORIZATION_HEADER, "Bearer header.payload.signature")],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (SERVERLESS_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            ("Authorization", "Bearer header.payload.signature"),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (SERVERLESS_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (SERVERLESS_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (SERVERLESS_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (SERVERLESS_AUTHORIZATION_HEADER, "Bearer other.payload.signature"),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (SERVERLESS_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "Bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "header.payload.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "bearer other.payload.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "bearer header.payload.extra.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.signature"),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "bearer header.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer one.two.three.signature"),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "bearer one.two.three.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer .payload.signature"),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "bearer .payload.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header..signature"),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "bearer header..SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
        [
            (CONTROLGRAPH_AUTHORIZATION_HEADER, "Bearer header.payload.signature"),
            (SERVERLESS_AUTHORIZATION_HEADER, "bearer header.payload.signature"),
        ],
        [
            (
                CONTROLGRAPH_AUTHORIZATION_HEADER,
                "Bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
            (
                SERVERLESS_AUTHORIZATION_HEADER,
                "bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE",
            ),
        ],
    ],
)
def test_operator_route_rejects_incomplete_duplicate_or_ambiguous_envelopes(
    headers: list[tuple[str, str]],
) -> None:
    role = ServiceRole.API
    policy = runtime_route_policy(role, _environment(role))
    authenticator = _ExactTestAuthenticator("Bearer header.payload.signature")
    response = TestClient(
        create_service_app(
            role,
            authenticator=authenticator,
            authentication_policy=policy,
        )
    ).post(protected_paths(role)[0], headers=headers)

    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_CREDENTIAL_MALFORMED"
    assert authenticator.calls == []


def test_operator_envelope_admits_cloud_run_signature_removal() -> None:
    role = ServiceRole.API
    policy = runtime_route_policy(role, _environment(role))
    credential = "Bearer header.payload.signature"
    authenticator = _ExactTestAuthenticator(credential)
    response = TestClient(
        create_service_app(
            role,
            authenticator=authenticator,
            authentication_policy=policy,
        )
    ).post(
        protected_paths(role)[0],
        headers={
            CONTROLGRAPH_AUTHORIZATION_HEADER: credential,
            SERVERLESS_AUTHORIZATION_HEADER: (
                "bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE"
            ),
        },
    )

    assert response.status_code == 503
    assert authenticator.calls == [(credential, policy)]


@pytest.mark.parametrize(
    "header",
    [CONTROLGRAPH_AUTHORIZATION_HEADER, SERVERLESS_AUTHORIZATION_HEADER],
)
def test_non_operator_routes_reject_operator_transport_headers(header: str) -> None:
    role = ServiceRole.EXECUTOR
    policy = runtime_route_policy(role, _environment(role))
    authenticator = _ExactTestAuthenticator("Bearer header.payload.signature")
    response = TestClient(
        create_service_app(
            role,
            authenticator=authenticator,
            authentication_policy=policy,
        )
    ).post(
        protected_paths(role)[0],
        headers={header: "Bearer header.payload.signature"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_CREDENTIAL_MALFORMED"
    assert authenticator.calls == []


def test_cloud_tasks_authorization_fallback_is_signature_verified() -> None:
    role = ServiceRole.EXECUTOR
    environment = _environment(role)
    policy = runtime_route_policy(role, environment)
    expected_audience = environment["CONTROLGRAPH_AUTH_AUDIENCE"]
    calls: list[tuple[str, str]] = []

    def verify_token(token: str, audience: str) -> dict[str, object]:
        calls.append((token, audience))
        return {
            "iss": "https://accounts.google.com",
            "aud": expected_audience,
            "email": environment["CONTROLGRAPH_AUTH_CALLER_EMAIL"],
            "email_verified": True,
            "sub": SUBJECT,
            "iat": 1_776_236_340,
            "exp": 1_776_239_400,
        }

    response = TestClient(
        create_service_app(
            role,
            authenticator=GoogleIdentityVerifier(
                verify_token,
                clock=lambda: 1_776_236_400.0,
            ),
            authentication_policy=policy,
        )
    ).post(
        protected_paths(role)[0],
        headers={"Authorization": "Bearer header.payload.signature"},
    )

    assert response.status_code == 503
    assert calls == [("header.payload.signature", expected_audience)]


def test_unexpected_verifier_failure_is_sanitized_and_fails_closed() -> None:
    role = ServiceRole.EXECUTOR
    policy = runtime_route_policy(role, _environment(role))
    sensitive_marker = "unmistakably-synthetic-token"

    class BrokenAuthenticator:
        def authenticate(
            self,
            authorization_header: str | None,
            route_policy: RouteAuthenticationPolicy,
        ) -> AuthenticationContext:
            raise RuntimeError(f"provider diagnostic contained {sensitive_marker}")

    client = TestClient(
        create_service_app(
            role,
            authenticator=BrokenAuthenticator(),
            authentication_policy=policy,
        )
    )
    response = client.post(
        protected_paths(role)[0],
        headers={"Authorization": f"Bearer {sensitive_marker}"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "AUTH_VERIFICATION_UNAVAILABLE"
    assert sensitive_marker not in response.text


def test_service_app_rejects_a_policy_for_another_role() -> None:
    policy = runtime_route_policy(ServiceRole.RECOVERY, _environment(ServiceRole.RECOVERY))

    with pytest.raises(ValueError, match="service role"):
        create_service_app(
            ServiceRole.EXECUTOR,
            authenticator=_ExactTestAuthenticator("Bearer exact.test.credential"),
            authentication_policy=policy,
        )


@pytest.mark.parametrize(
    "role",
    tuple(
        role
        for role in ServiceRole
        if role
        not in {
            ServiceRole.COORDINATOR,
            ServiceRole.EVIDENCE_WRITER,
            ServiceRole.ISSUER,
            ServiceRole.EXECUTOR,
            ServiceRole.RECOVERY,
            ServiceRole.VERIFIER,
        }
    ),
)
def test_runtime_rejects_kms_clients_outside_evidence_trust_roles(
    role: ServiceRole,
) -> None:
    with pytest.raises(ValueError, match="KMS dependencies"):
        create_runtime_service_app(
            role,
            environment=_environment(role),
            kms_client=object(),
        )


def test_runtime_limits_revocation_injected_dependencies_to_their_roles() -> None:
    with pytest.raises(ValueError, match="revocation clocks"):
        create_runtime_service_app(
            ServiceRole.API,
            environment=_environment(ServiceRole.API),
            revocation_clock=lambda: datetime(2026, 8, 20, tzinfo=UTC),
        )
    with pytest.raises(ValueError, match="attempt identities"):
        create_runtime_service_app(
            ServiceRole.RECOVERY,
            environment=_environment(ServiceRole.RECOVERY),
            revocation_attempt_id_factory=lambda: "attempt-id",
        )


def test_service_claim_release_clock_is_coordinator_limited() -> None:
    with pytest.raises(ValueError, match="service-claim release clocks"):
        create_runtime_service_app(
            ServiceRole.RECOVERY,
            environment=_environment(ServiceRole.RECOVERY),
            service_claim_release_clock=lambda: datetime.now(UTC),
        )


@pytest.mark.parametrize(
    "digest",
    ["latest", "sha256:abc", f"sha256:{'A' * 64}", f"md5:{'0' * 64}"],
)
def test_service_shell_rejects_mutable_or_malformed_build_identifiers(digest: str) -> None:
    with pytest.raises(ValueError, match="immutable sha256"):
        create_service_app(ServiceRole.EXECUTOR, build_digest=digest)


def test_service_shell_rejects_an_unsupported_configured_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROLGRAPH_CONTRACT_VERSION", "controlgraph.contract/v2")

    with pytest.raises(ValueError, match="CONTRACT_VERSION"):
        create_service_app(ServiceRole.EXECUTOR, build_digest=f"sha256:{'d' * 64}")


def test_service_shell_emits_payload_free_structured_correlation_event(
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy = runtime_route_policy(ServiceRole.EXECUTOR, _environment(ServiceRole.EXECUTOR))
    sensitive_marker = "unmistakably-synthetic-capability-and-token"
    authorization = f"Bearer {sensitive_marker}"
    client = TestClient(
        create_service_app(
            ServiceRole.EXECUTOR,
            authenticator=_ExactTestAuthenticator(authorization),
            authentication_policy=policy,
        )
    )

    response = client.post(
        protected_paths(ServiceRole.EXECUTOR)[0],
        content=f'{{"capability":"{sensitive_marker}"}}',
        headers={"Authorization": authorization},
    )

    emitted = capsys.readouterr().err.strip().splitlines()
    event = json.loads(emitted[-1])
    assert event == {
        "correlation_id": response.headers["x-controlgraph-correlation-id"],
        "event": "controlgraph.service.request",
        "service_role": "executor",
        "status_code": 503,
    }
    assert sensitive_marker not in "\n".join(emitted)
