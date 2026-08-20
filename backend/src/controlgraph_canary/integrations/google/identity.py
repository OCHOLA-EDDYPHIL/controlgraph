"""Bounded Google OIDC verification for exact ControlGraph route policies."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
    RouteAuthenticationPolicy,
)

_GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})
_MAX_AUTHORIZATION_HEADER_BYTES = 8_192
_MAX_ID_TOKEN_BYTES = 6_144
_MAX_AUDIENCE_BYTES = 2_048
_MAX_EMAIL_BYTES = 320
_MAX_SUBJECT_BYTES = 255
_MAX_CLOCK_SKEW_SECONDS = 60
_MAX_TOKEN_LIFETIME_SECONDS = 3_660
_GOOGLE_REQUEST_TIMEOUT_SECONDS = 5.0
_JWT_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_GOOGLE_OAUTH_CLIENT_AUDIENCE = re.compile(
    r"^[0-9]{6,32}(?:-[a-z0-9]{6,128})?\.apps\.googleusercontent\.com$"
)


class IdentityTokenVerifier(Protocol):
    """Narrow signature-verification callable used by the Google adapter."""

    def __call__(self, token: str, audience: str) -> Mapping[str, Any]: ...


def _denied(code: AuthenticationDenialCode) -> AuthenticationError:
    return AuthenticationError(code)


def _bounded_ascii(value: object, *, maximum: int) -> str:
    if type(value) is not str or not value:
        raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID) from None
    if (
        len(encoded) > maximum
        or any(character.isspace() for character in value)
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID)
    return value


def _extract_bearer_token(authorization_header: str | None) -> str:
    if authorization_header is None or authorization_header == "":
        raise _denied(AuthenticationDenialCode.CREDENTIAL_MISSING)
    if type(authorization_header) is not str:
        raise _denied(AuthenticationDenialCode.CREDENTIAL_MALFORMED)
    try:
        encoded_header = authorization_header.encode("ascii")
    except UnicodeEncodeError:
        raise _denied(AuthenticationDenialCode.CREDENTIAL_MALFORMED) from None
    if (
        len(encoded_header) > _MAX_AUTHORIZATION_HEADER_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in authorization_header)
        or not authorization_header.startswith("Bearer ")
    ):
        raise _denied(AuthenticationDenialCode.CREDENTIAL_MALFORMED)

    token = authorization_header.removeprefix("Bearer ")
    try:
        token_bytes = token.encode("ascii")
    except UnicodeEncodeError:
        raise _denied(AuthenticationDenialCode.CREDENTIAL_MALFORMED) from None
    segments = token.split(".")
    if (
        not token
        or len(token_bytes) > _MAX_ID_TOKEN_BYTES
        or len(segments) != 3
        or any(not segment or _JWT_SEGMENT.fullmatch(segment) is None for segment in segments)
    ):
        raise _denied(AuthenticationDenialCode.CREDENTIAL_MALFORMED)
    return token


def _default_google_verifier(token: str, audience: str) -> Mapping[str, Any]:
    try:
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token

        request = Request()
        request.session.trust_env = False

        def bounded_request(
            url: str,
            method: str = "GET",
            body: bytes | None = None,
            headers: Mapping[str, str] | None = None,
            **kwargs: Any,
        ) -> Any:
            kwargs.pop("timeout", None)
            return request(
                url,
                method=method,
                body=body,
                headers=headers,
                timeout=_GOOGLE_REQUEST_TIMEOUT_SECONDS,
                **kwargs,
            )

        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            token,
            bounded_request,
            audience=audience,
        )
    except Exception:
        raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID) from None
    if not isinstance(claims, Mapping):
        raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID)
    return claims


class GoogleIdentityVerifier:
    """Verify one Google-signed credential against one route-bound caller."""

    def __init__(
        self,
        verifier: IdentityTokenVerifier | None = None,
        clock: Callable[[], float] | None = None,
        *,
        operator_oauth_client_audience: str | None = None,
    ) -> None:
        self._verifier = verifier or _default_google_verifier
        self._clock = clock or time.time
        self._operator_oauth_client_audience = operator_oauth_client_audience

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        """Return bounded caller context or fail with a credential-free denial."""

        try:
            if type(policy) is not RouteAuthenticationPolicy:
                raise _denied(AuthenticationDenialCode.CONFIGURATION_INVALID)
            route_audience = _bounded_ascii(
                policy.audience,
                maximum=_MAX_AUDIENCE_BYTES,
            )
            verification_audience = route_audience
            if policy.caller.role is CallerRole.OPERATOR:
                configured_audience = self._operator_oauth_client_audience
                if (
                    type(configured_audience) is not str
                    or _GOOGLE_OAUTH_CLIENT_AUDIENCE.fullmatch(configured_audience)
                    is None
                ):
                    raise _denied(AuthenticationDenialCode.CONFIGURATION_INVALID)
                verification_audience = configured_audience
            token = _extract_bearer_token(authorization_header)
            try:
                claims = self._verifier(token, verification_audience)
            except AuthenticationError:
                raise
            except Exception:
                raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID) from None
            if not isinstance(claims, Mapping):
                raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID)

            issuer = claims.get("iss")
            if issuer not in _GOOGLE_ISSUERS:
                raise _denied(AuthenticationDenialCode.ISSUER_DENIED)
            if claims.get("aud") != verification_audience:
                raise _denied(AuthenticationDenialCode.AUDIENCE_DENIED)

            email = claims.get("email")
            subject = claims.get("sub")
            if (
                claims.get("email_verified") is not True
                or email != policy.caller.email
                or subject != policy.caller.subject
            ):
                raise _denied(AuthenticationDenialCode.CALLER_DENIED)
            verified_email = _bounded_ascii(email, maximum=_MAX_EMAIL_BYTES)
            verified_subject = _bounded_ascii(subject, maximum=_MAX_SUBJECT_BYTES)

            expires_at = claims.get("exp")
            issued_at = claims.get("iat")
            not_before = claims.get("nbf")
            now = self._clock()
            if (
                type(expires_at) is not int
                or type(issued_at) is not int
                or isinstance(now, bool)
                or not isinstance(now, (int, float))
                or not math.isfinite(now)
            ):
                raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID)
            if expires_at <= now:
                raise _denied(AuthenticationDenialCode.TOKEN_EXPIRED)
            if issued_at > now + _MAX_CLOCK_SKEW_SECONDS:
                raise _denied(AuthenticationDenialCode.TOKEN_NOT_YET_VALID)
            if not_before is not None:
                if type(not_before) is not int:
                    raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID)
                if not_before > now + _MAX_CLOCK_SKEW_SECONDS:
                    raise _denied(AuthenticationDenialCode.TOKEN_NOT_YET_VALID)
            if (
                issued_at >= expires_at
                or expires_at - issued_at > _MAX_TOKEN_LIFETIME_SECONDS
                or now - issued_at > _MAX_TOKEN_LIFETIME_SECONDS
            ):
                raise _denied(AuthenticationDenialCode.TOKEN_LIFETIME_DENIED)

            return AuthenticationContext(
                role=policy.caller.role,
                email=verified_email,
                subject=verified_subject,
                issuer=issuer,
                audience=route_audience,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        except AuthenticationError:
            raise
        except Exception:
            raise _denied(AuthenticationDenialCode.CREDENTIAL_INVALID) from None


__all__ = [
    "GoogleIdentityVerifier",
    "IdentityTokenVerifier",
]
