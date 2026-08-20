"""Select one signed Google credential from a policy-specific HTTP envelope."""

from __future__ import annotations

from starlette.datastructures import Headers

from controlgraph_canary.application.identity import (
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
    RouteAuthenticationPolicy,
)

CONTROLGRAPH_AUTHORIZATION_HEADER = "X-ControlGraph-Authorization"
SERVERLESS_AUTHORIZATION_HEADER = "X-Serverless-Authorization"
_MAX_HEADER_BYTES = 8_192
_REMOVED_SIGNATURE = "SIGNATURE_REMOVED_BY_GOOGLE"


def authentication_header(
    headers: Headers,
    policy: RouteAuthenticationPolicy,
) -> str | None:
    """Return the sole app-verifiable credential or fail closed on ambiguity."""

    standard = _single(headers, "authorization")
    controlgraph = _single(headers, CONTROLGRAPH_AUTHORIZATION_HEADER)
    serverless = _single(headers, SERVERLESS_AUTHORIZATION_HEADER)
    if policy.caller.role is CallerRole.OPERATOR:
        if standard is not None:
            _malformed()
        if controlgraph is None and serverless is None:
            return None
        if (
            controlgraph is None
            or serverless is None
            or not _same_identity_envelope(controlgraph, serverless)
        ):
            _malformed()
        return controlgraph
    if controlgraph is not None or serverless is not None:
        _malformed()
    return standard


def _single(headers: Headers, name: str) -> str | None:
    values = headers.getlist(name)
    if len(values) > 1:
        _malformed()
    return values[0] if values else None


def _same_identity_envelope(controlgraph: str, serverless: str) -> bool:
    if not _bounded_ascii(controlgraph) or not _bounded_ascii(serverless):
        return False
    if not controlgraph.startswith("Bearer ") or not serverless.startswith("bearer "):
        return False
    controlgraph_parts = controlgraph.removeprefix("Bearer ").split(".")
    serverless_parts = serverless.removeprefix("bearer ").split(".")
    return (
        len(controlgraph_parts) == 3
        and len(serverless_parts) == 3
        and all(controlgraph_parts)
        and all(serverless_parts[:2])
        and controlgraph_parts[2] != _REMOVED_SIGNATURE
        and serverless_parts[2] == _REMOVED_SIGNATURE
        and controlgraph_parts[:2] == serverless_parts[:2]
    )


def _bounded_ascii(value: str) -> bool:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return bool(
        encoded
        and len(encoded) <= _MAX_HEADER_BYTES
        and not any(character < 32 or character == 127 for character in encoded)
    )


def _malformed() -> None:
    raise AuthenticationError(AuthenticationDenialCode.CREDENTIAL_MALFORMED)


__all__ = [
    "CONTROLGRAPH_AUTHORIZATION_HEADER",
    "SERVERLESS_AUTHORIZATION_HEADER",
    "authentication_header",
]
