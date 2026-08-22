"""Validate nonce-bound anti-CSRF state for browser operator mutations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

from starlette.datastructures import Headers

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
)

CSRF_HEADER = "X-ControlGraph-CSRF"
CSRF_SHA256_DOMAIN = b"controlgraph.operator-csrf-sha256/v1\x00"

_CSRF_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SESSION_NONCE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def validate_operator_csrf(
    headers: Headers,
    context: AuthenticationContext,
    *,
    expected_origin: str,
) -> None:
    """Accept a non-browser CLI or one complete nonce-bound same-origin request."""

    if type(context) is not AuthenticationContext:
        raise AuthenticationError(AuthenticationDenialCode.CONFIGURATION_INVALID)

    origins = headers.getlist("origin")
    csrf_values = headers.getlist(CSRF_HEADER)
    fetch_headers_present = any(name.lower().startswith("sec-fetch-") for name in headers)
    nonce = context.operator_session_nonce

    browser_signal_present = bool(
        origins or csrf_values or fetch_headers_present or nonce is not None
    )
    if not browser_signal_present:
        return

    if context.role is not CallerRole.OPERATOR:
        raise AuthenticationError(AuthenticationDenialCode.CALLER_DENIED)

    if origins != [expected_origin]:
        raise AuthenticationError(AuthenticationDenialCode.BROWSER_ORIGIN_DENIED)
    if headers.getlist("sec-fetch-site") != ["same-origin"]:
        raise AuthenticationError(AuthenticationDenialCode.BROWSER_ORIGIN_DENIED)
    if headers.getlist("sec-fetch-mode") != ["cors"]:
        raise AuthenticationError(AuthenticationDenialCode.BROWSER_ORIGIN_DENIED)
    if headers.getlist("sec-fetch-dest") != ["empty"]:
        raise AuthenticationError(AuthenticationDenialCode.BROWSER_ORIGIN_DENIED)
    if not csrf_values:
        raise AuthenticationError(AuthenticationDenialCode.CSRF_MISSING)
    if (
        len(csrf_values) != 1
        or _CSRF_TOKEN.fullmatch(csrf_values[0]) is None
        or type(nonce) is not str
        or _SESSION_NONCE.fullmatch(nonce) is None
    ):
        raise AuthenticationError(AuthenticationDenialCode.CSRF_INVALID)

    calculated = (
        base64.urlsafe_b64encode(
            hashlib.sha256(CSRF_SHA256_DOMAIN + csrf_values[0].encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    if not hmac.compare_digest(calculated, nonce):
        raise AuthenticationError(AuthenticationDenialCode.CSRF_INVALID)


__all__ = ["CSRF_HEADER", "CSRF_SHA256_DOMAIN", "validate_operator_csrf"]
