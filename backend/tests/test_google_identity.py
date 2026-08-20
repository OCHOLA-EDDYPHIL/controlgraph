from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from controlgraph_canary.application.identity import (
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
    ServiceRole,
    runtime_route_policy,
)
from controlgraph_canary.integrations.google.identity import GoogleIdentityVerifier

PROJECT_ID = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
CALLER_EMAIL = f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
CALLER_SUBJECT = "123456789012345678901"
AUDIENCE = f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
API_AUDIENCE = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
OPERATOR_EMAIL = "operator@example.com"
OPERATOR_SUBJECT = "223456789012345678901"
OPERATOR_OAUTH_CLIENT_AUDIENCE = "32555940559.apps.googleusercontent.com"
TOKEN = "synthetic_header.synthetic_payload.synthetic_signature"
NOW = 1_776_236_400.0


def policy():
    return runtime_route_policy(
        ServiceRole.EXECUTOR,
        {
            "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
            "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
            "CONTROLGRAPH_REGION": "us-central1",
            "CONTROLGRAPH_ROLE": "executor",
            "CONTROLGRAPH_AUTH_AUDIENCE": AUDIENCE,
            "CONTROLGRAPH_AUTH_CALLER_ROLE": "execution_task_caller",
            "CONTROLGRAPH_AUTH_CALLER_EMAIL": CALLER_EMAIL,
            "CONTROLGRAPH_AUTH_CALLER_SUBJECT": CALLER_SUBJECT,
        },
    )


def operator_policy():
    return runtime_route_policy(
        ServiceRole.API,
        {
            "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
            "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
            "CONTROLGRAPH_REGION": "us-central1",
            "CONTROLGRAPH_ROLE": "api",
            "CONTROLGRAPH_AUTH_AUDIENCE": API_AUDIENCE,
            "CONTROLGRAPH_AUTH_CALLER_ROLE": "operator",
            "CONTROLGRAPH_AUTH_CALLER_EMAIL": OPERATOR_EMAIL,
            "CONTROLGRAPH_AUTH_CALLER_SUBJECT": OPERATOR_SUBJECT,
        },
    )


def claims(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "iss": "https://accounts.google.com",
        "aud": AUDIENCE,
        "email": CALLER_EMAIL,
        "email_verified": True,
        "sub": CALLER_SUBJECT,
        "iat": int(NOW) - 60,
        "nbf": int(NOW) - 60,
        "exp": int(NOW) + 3_000,
    }
    values.update(changes)
    return values


def operator_claims(**changes: object) -> dict[str, object]:
    values = claims(
        aud=OPERATOR_OAUTH_CLIENT_AUDIENCE,
        email=OPERATOR_EMAIL,
        sub=OPERATOR_SUBJECT,
    )
    values.update(changes)
    return values


class CapturingVerifier:
    def __init__(self, result: Mapping[str, Any]) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def __call__(self, token: str, audience: str) -> Mapping[str, Any]:
        self.calls.append((token, audience))
        return self.result


@pytest.mark.parametrize("issuer", ["accounts.google.com", "https://accounts.google.com"])
def test_google_identity_verifier_returns_bounded_context_for_exact_caller(
    issuer: str,
) -> None:
    backend = CapturingVerifier(claims(iss=issuer))
    verifier = GoogleIdentityVerifier(backend, clock=lambda: NOW)

    context = verifier.authenticate(f"Bearer {TOKEN}", policy())

    assert context.role is CallerRole.EXECUTION_TASK_CALLER
    assert context.email == CALLER_EMAIL
    assert context.subject == CALLER_SUBJECT
    assert context.issuer == issuer
    assert context.audience == AUDIENCE
    assert context.issued_at == int(NOW) - 60
    assert context.expires_at == int(NOW) + 3_000
    assert backend.calls == [(TOKEN, AUDIENCE)]
    assert not hasattr(context, "token")


def test_operator_token_uses_oauth_audience_and_seals_route_context() -> None:
    backend = CapturingVerifier(operator_claims())
    verifier = GoogleIdentityVerifier(
        backend,
        clock=lambda: NOW,
        operator_oauth_client_audience=OPERATOR_OAUTH_CLIENT_AUDIENCE,
    )

    context = verifier.authenticate(f"Bearer {TOKEN}", operator_policy())

    assert context.role is CallerRole.OPERATOR
    assert context.email == OPERATOR_EMAIL
    assert context.subject == OPERATOR_SUBJECT
    assert context.audience == API_AUDIENCE
    assert backend.calls == [(TOKEN, OPERATOR_OAUTH_CLIENT_AUDIENCE)]


@pytest.mark.parametrize(
    "configured_audience",
    [
        None,
        "",
        API_AUDIENCE,
        "32555940559.apps.googleusercontent.com ",
        "client.apps.googleusercontent.com",
    ],
)
def test_operator_verification_fails_closed_without_exact_oauth_audience(
    configured_audience: str | None,
) -> None:
    backend = CapturingVerifier(operator_claims())

    with pytest.raises(AuthenticationError) as failure:
        GoogleIdentityVerifier(
            backend,
            clock=lambda: NOW,
            operator_oauth_client_audience=configured_audience,
        ).authenticate(f"Bearer {TOKEN}", operator_policy())

    assert failure.value.code is AuthenticationDenialCode.CONFIGURATION_INVALID
    assert backend.calls == []


def test_operator_token_cannot_substitute_route_audience_for_oauth_audience() -> None:
    backend = CapturingVerifier(operator_claims(aud=API_AUDIENCE))

    with pytest.raises(AuthenticationError) as failure:
        GoogleIdentityVerifier(
            backend,
            clock=lambda: NOW,
            operator_oauth_client_audience=OPERATOR_OAUTH_CLIENT_AUDIENCE,
        ).authenticate(f"Bearer {TOKEN}", operator_policy())

    assert failure.value.code is AuthenticationDenialCode.AUDIENCE_DENIED
    assert backend.calls == [(TOKEN, OPERATOR_OAUTH_CLIENT_AUDIENCE)]


@pytest.mark.parametrize(
    ("authorization", "code"),
    [
        (None, AuthenticationDenialCode.CREDENTIAL_MISSING),
        ("", AuthenticationDenialCode.CREDENTIAL_MISSING),
        (TOKEN, AuthenticationDenialCode.CREDENTIAL_MALFORMED),
        (f"bearer {TOKEN}", AuthenticationDenialCode.CREDENTIAL_MALFORMED),
        ("Bearer one.two", AuthenticationDenialCode.CREDENTIAL_MALFORMED),
        ("Bearer one.two.", AuthenticationDenialCode.CREDENTIAL_MALFORMED),
        ("Bearer one.two.three.extra", AuthenticationDenialCode.CREDENTIAL_MALFORMED),
        ("Bearer one.two.three\n", AuthenticationDenialCode.CREDENTIAL_MALFORMED),
        ("Bearer one.two.thr=ee", AuthenticationDenialCode.CREDENTIAL_MALFORMED),
    ],
)
def test_bearer_envelope_failures_are_stable_and_skip_signature_verification(
    authorization: str | None,
    code: AuthenticationDenialCode,
) -> None:
    backend = CapturingVerifier(claims())

    with pytest.raises(AuthenticationError) as failure:
        GoogleIdentityVerifier(backend, clock=lambda: NOW).authenticate(authorization, policy())

    assert failure.value.code is code
    assert backend.calls == []


@pytest.mark.parametrize(
    "authorization",
    [
        "Bearer " + ("a" * 8_192),
        "Bearer " + ("a" * 6_141) + ".b.c",
    ],
)
def test_oversized_authorization_and_token_are_rejected_before_verification(
    authorization: str,
) -> None:
    backend = CapturingVerifier(claims())

    with pytest.raises(AuthenticationError) as failure:
        GoogleIdentityVerifier(backend, clock=lambda: NOW).authenticate(
            authorization,
            policy(),
        )

    assert failure.value.code is AuthenticationDenialCode.CREDENTIAL_MALFORMED
    assert backend.calls == []


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"iss": "https://issuer.example.test"}, AuthenticationDenialCode.ISSUER_DENIED),
        (
            {"aud": (f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app")},
            AuthenticationDenialCode.AUDIENCE_DENIED,
        ),
        (
            {"email": (f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com")},
            AuthenticationDenialCode.CALLER_DENIED,
        ),
        ({"sub": "223456789012345678901"}, AuthenticationDenialCode.CALLER_DENIED),
        ({"email_verified": False}, AuthenticationDenialCode.CALLER_DENIED),
        ({"exp": int(NOW)}, AuthenticationDenialCode.TOKEN_EXPIRED),
        ({"iat": int(NOW) + 61}, AuthenticationDenialCode.TOKEN_NOT_YET_VALID),
        ({"nbf": int(NOW) + 61}, AuthenticationDenialCode.TOKEN_NOT_YET_VALID),
        ({"exp": int(NOW) + 4_000}, AuthenticationDenialCode.TOKEN_LIFETIME_DENIED),
        (
            {"iat": int(NOW) - 4_000, "exp": int(NOW) + 1},
            AuthenticationDenialCode.TOKEN_LIFETIME_DENIED,
        ),
        ({"exp": True}, AuthenticationDenialCode.CREDENTIAL_INVALID),
        ({"iat": "1776230000"}, AuthenticationDenialCode.CREDENTIAL_INVALID),
        ({"nbf": "1776230000"}, AuthenticationDenialCode.CREDENTIAL_INVALID),
    ],
)
def test_claim_substitution_and_replay_inappropriate_times_fail_closed(
    changes: dict[str, object],
    code: AuthenticationDenialCode,
) -> None:
    backend = CapturingVerifier(claims(**changes))

    with pytest.raises(AuthenticationError) as failure:
        GoogleIdentityVerifier(backend, clock=lambda: NOW).authenticate(
            f"Bearer {TOKEN}",
            policy(),
        )

    assert failure.value.code is code


def test_a_valid_token_for_another_route_cannot_be_replayed() -> None:
    recovery_audience = f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
    recovery_caller = f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
    backend = CapturingVerifier(
        claims(
            aud=recovery_audience,
            email=recovery_caller,
            sub="223456789012345678901",
        )
    )

    with pytest.raises(AuthenticationError) as failure:
        GoogleIdentityVerifier(backend, clock=lambda: NOW).authenticate(
            f"Bearer {TOKEN}",
            policy(),
        )

    assert failure.value.code is AuthenticationDenialCode.AUDIENCE_DENIED


def test_signature_backend_failure_never_discloses_token_or_provider_text() -> None:
    sensitive_marker = TOKEN

    def invalid_signature(token: str, audience: str) -> Mapping[str, Any]:
        raise RuntimeError(f"provider rejected {token} for {audience}")

    with pytest.raises(AuthenticationError) as failure:
        GoogleIdentityVerifier(invalid_signature, clock=lambda: NOW).authenticate(
            f"Bearer {TOKEN}",
            policy(),
        )

    assert failure.value.code is AuthenticationDenialCode.CREDENTIAL_INVALID
    assert failure.value.__cause__ is None
    assert failure.value.__suppress_context__ is True
    assert sensitive_marker not in str(failure.value)
    assert "provider rejected" not in str(failure.value)


def test_nonfinite_clock_and_nonmapping_claims_fail_with_sanitized_errors() -> None:
    backend = CapturingVerifier(claims())
    with pytest.raises(AuthenticationError) as bad_clock:
        GoogleIdentityVerifier(backend, clock=lambda: float("nan")).authenticate(
            f"Bearer {TOKEN}",
            policy(),
        )
    assert bad_clock.value.code is AuthenticationDenialCode.CREDENTIAL_INVALID

    def nonmapping(token: str, audience: str) -> Mapping[str, Any]:
        return []  # type: ignore[return-value]

    with pytest.raises(AuthenticationError) as bad_claims:
        GoogleIdentityVerifier(nonmapping, clock=lambda: NOW).authenticate(
            f"Bearer {TOKEN}",
            policy(),
        )
    assert bad_claims.value.code is AuthenticationDenialCode.CREDENTIAL_INVALID
