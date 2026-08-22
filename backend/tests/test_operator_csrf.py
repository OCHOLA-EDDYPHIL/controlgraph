from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import Headers

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.http.operator_csrf import (
    CSRF_HEADER,
    CSRF_SHA256_DOMAIN,
    validate_operator_csrf,
)
from controlgraph_canary.http.service import create_service_app

PROJECT_ID = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
API_ORIGIN = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
CONSOLE_ORIGIN = f"https://controlgraph-console-{PROJECT_NUMBER}.us-central1.run.app"
OPERATOR_EMAIL = "operator@example.com"
OPERATOR_SUBJECT = "123456789012345678901"
FULL_TOKEN = "header.payload.synthetic-signature"
CSRF_TOKEN = "a" * 43


def _csrf_nonce(token: str = CSRF_TOKEN) -> str:
    return (
        base64.urlsafe_b64encode(
            hashlib.sha256(CSRF_SHA256_DOMAIN + token.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )


def _context(*, nonce: str | None) -> AuthenticationContext:
    return AuthenticationContext(
        role=CallerRole.OPERATOR,
        email=OPERATOR_EMAIL,
        subject=OPERATOR_SUBJECT,
        issuer="https://accounts.google.com",
        audience=API_ORIGIN,
        issued_at=1_776_236_340,
        expires_at=1_776_237_000,
        operator_session_nonce=nonce,
    )


def _browser_headers(*, csrf: str = CSRF_TOKEN) -> list[tuple[str, str]]:
    return [
        ("Origin", CONSOLE_ORIGIN),
        ("Sec-Fetch-Site", "same-origin"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Dest", "empty"),
        (CSRF_HEADER, csrf),
    ]


def _policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.API,
        path="/v1/operator/commands",
        audience=API_ORIGIN,
        caller=CallerBinding(
            role=CallerRole.OPERATOR,
            email=OPERATOR_EMAIL,
            subject=OPERATOR_SUBJECT,
        ),
    )


def _headers(values: list[tuple[str, str]]) -> Headers:
    return Headers(
        raw=[(name.lower().encode("ascii"), value.encode("ascii")) for name, value in values]
    )


class _Authenticator:
    def __init__(self, context: AuthenticationContext) -> None:
        self.context = context
        self.calls = 0

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        self.calls += 1
        assert authorization_header == f"Bearer {FULL_TOKEN}"
        assert policy == _policy()
        return self.context


def _identity_headers() -> list[tuple[str, str]]:
    return [
        (CONTROLGRAPH_AUTHORIZATION_HEADER, f"Bearer {FULL_TOKEN}"),
        (
            SERVERLESS_AUTHORIZATION_HEADER,
            "bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE",
        ),
    ]


def test_browser_csrf_accepts_only_exact_nonce_bound_same_origin_request() -> None:
    validate_operator_csrf(
        _headers(_browser_headers()),
        _context(nonce=_csrf_nonce()),
        expected_origin=CONSOLE_ORIGIN,
    )


def test_non_browser_cli_has_one_metadata_free_path() -> None:
    validate_operator_csrf(
        Headers(),
        _context(nonce=None),
        expected_origin=CONSOLE_ORIGIN,
    )


@pytest.mark.parametrize(
    ("headers", "nonce", "code"),
    [
        (
            [("Origin", CONSOLE_ORIGIN)],
            None,
            AuthenticationDenialCode.BROWSER_ORIGIN_DENIED,
        ),
        (
            [("Sec-Fetch-Site", "same-origin")],
            None,
            AuthenticationDenialCode.BROWSER_ORIGIN_DENIED,
        ),
        (
            [("Sec-Fetch-Mode", "cors")],
            None,
            AuthenticationDenialCode.BROWSER_ORIGIN_DENIED,
        ),
        (
            [("Sec-Fetch-Dest", "empty")],
            None,
            AuthenticationDenialCode.BROWSER_ORIGIN_DENIED,
        ),
        (
            [("Sec-Fetch-User", "?1")],
            None,
            AuthenticationDenialCode.BROWSER_ORIGIN_DENIED,
        ),
        ([(CSRF_HEADER, CSRF_TOKEN)], None, AuthenticationDenialCode.BROWSER_ORIGIN_DENIED),
        ([], _csrf_nonce(), AuthenticationDenialCode.BROWSER_ORIGIN_DENIED),
        (
            _browser_headers()[:-1],
            _csrf_nonce(),
            AuthenticationDenialCode.CSRF_MISSING,
        ),
        (
            _browser_headers(),
            None,
            AuthenticationDenialCode.CSRF_INVALID,
        ),
        (
            [
                (name, "cross-site") if name == "Sec-Fetch-Site" else (name, value)
                for name, value in _browser_headers()
            ],
            _csrf_nonce(),
            AuthenticationDenialCode.BROWSER_ORIGIN_DENIED,
        ),
        (
            _browser_headers(csrf="b" * 43),
            _csrf_nonce(),
            AuthenticationDenialCode.CSRF_INVALID,
        ),
    ],
)
def test_partial_or_substituted_browser_state_never_falls_back_to_cli(
    headers: list[tuple[str, str]],
    nonce: str | None,
    code: AuthenticationDenialCode,
) -> None:
    with pytest.raises(AuthenticationError) as failure:
        validate_operator_csrf(
            _headers(headers),
            _context(nonce=nonce),
            expected_origin=CONSOLE_ORIGIN,
        )

    assert failure.value.code is code
    assert CSRF_TOKEN not in str(failure.value)


def test_operator_post_validates_csrf_after_identity_without_logging_secrets(
    capsys: pytest.CaptureFixture[str],
) -> None:
    authenticator = _Authenticator(_context(nonce=_csrf_nonce()))
    app = create_service_app(
        ServiceRole.API,
        authenticator=authenticator,
        authentication_policy=_policy(),
        operator_console_origin=CONSOLE_ORIGIN,
    )
    headers = [*_identity_headers(), *_browser_headers(csrf="b" * 43)]

    response = TestClient(app).post(
        "/v1/operator/commands",
        headers=headers,
        content=b"{}",
    )

    assert authenticator.calls == 1
    assert response.status_code == 403
    assert response.json()["code"] == AuthenticationDenialCode.CSRF_INVALID.value
    emitted = capsys.readouterr()
    assert FULL_TOKEN not in emitted.out + emitted.err
    assert CSRF_TOKEN not in emitted.out + emitted.err
    assert "b" * 43 not in emitted.out + emitted.err
    assert FULL_TOKEN not in repr(authenticator.context)
    assert CSRF_TOKEN not in repr(authenticator.context)


def test_operator_post_accepts_complete_browser_envelope_before_route_dispatch() -> None:
    authenticator = _Authenticator(_context(nonce=_csrf_nonce()))
    app = create_service_app(
        ServiceRole.API,
        authenticator=authenticator,
        authentication_policy=_policy(),
        operator_console_origin=CONSOLE_ORIGIN,
    )

    response = TestClient(app).post(
        "/v1/operator/commands",
        headers=[*_identity_headers(), *_browser_headers()],
        content=b"{}",
    )

    assert authenticator.calls == 1
    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_DISABLED"
