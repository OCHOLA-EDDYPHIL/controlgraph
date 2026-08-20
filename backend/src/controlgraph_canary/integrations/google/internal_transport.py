"""One-shot Google OIDC transport for fixed coordinator service calls."""

from __future__ import annotations

import asyncio
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from controlgraph_canary.application.identity import CallerRole
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_OIDC_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{16,16384}$")
_REQUEST_TIMEOUT_SECONDS = 10.0


class InternalTransportError(RuntimeError):
    """Sanitized failure from one fixed internal request attempt."""


class IdTokenProvider(Protocol):
    """Mint a Google identity token for one exact configured audience."""

    def token(self, audience: str) -> str: ...


@dataclass(frozen=True, slots=True)
class InternalHttpResponse:
    """Bounded response facts retained without arbitrary headers."""

    status_code: int
    content_type: str | None
    body: bytes


class OneShotHttpPoster(Protocol):
    """Make exactly one POST without redirect or retry handling."""

    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> InternalHttpResponse: ...


class GoogleIdTokenProvider:
    """Use application default identity without retaining credential material."""

    def token(self, audience: str) -> str:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import id_token

            value = id_token.fetch_id_token(Request(), audience)  # type: ignore[no-untyped-call]
        except Exception:
            raise InternalTransportError("identity token acquisition failed") from None
        if type(value) is not str or _OIDC_TOKEN.fullmatch(value) is None:
            raise InternalTransportError("identity token acquisition failed")
        return value


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class UrllibOneShotHttpPoster:
    """Standard-library POST backend with redirects disabled."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> InternalHttpResponse:
        request = urllib.request.Request(
            url=url,
            data=body,
            headers=dict(headers),
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                status = response.status
                content_types = response.headers.get_all("Content-Type") or []
                response_body = response.read(MAX_CONTRACT_BYTES + 1)
        except urllib.error.HTTPError as error:
            return InternalHttpResponse(
                status_code=error.code,
                content_type=None,
                body=b"",
            )
        except Exception:
            raise InternalTransportError("internal request failed") from None
        if type(status) is not int or len(content_types) != 1:
            raise InternalTransportError("internal response is invalid")
        content_type = content_types[0]
        if type(content_type) is not str:
            raise InternalTransportError("internal response is invalid")
        return InternalHttpResponse(
            status_code=status,
            content_type=content_type,
            body=response_body,
        )


class GoogleOneShotOidcTransport:
    """Seal one canonical POST to its configured audience and internal caller role."""

    def __init__(
        self,
        *,
        project_id: str,
        caller_role: CallerRole,
        token_provider: IdTokenProvider | None = None,
        http_poster: OneShotHttpPoster | None = None,
    ) -> None:
        if (
            type(project_id) is not str
            or _PROJECT_ID.fullmatch(project_id) is None
            or "reconcile" in project_id
            or caller_role
            not in {CallerRole.API, CallerRole.COORDINATOR, CallerRole.EXECUTOR}
        ):
            raise InternalTransportError("internal transport configuration is invalid")
        self._project_id = project_id
        self._caller_role = caller_role
        self._token_provider = token_provider or GoogleIdTokenProvider()
        self._http_poster = http_poster or UrllibOneShotHttpPoster()

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        """Make one authenticated attempt and admit only one canonical JSON response."""

        if (
            type(route) is not CoordinatorInternalRoute
            or route.project_id != self._project_id
            or route.caller_role is not self._caller_role
            or type(body) is not bytes
            or not body
            or len(body) > MAX_CONTRACT_BYTES
        ):
            raise InternalTransportError("internal request is outside its configured route")
        try:
            token = self._token_provider.token(route.audience)
        except InternalTransportError:
            raise
        except Exception:
            raise InternalTransportError("identity token acquisition failed") from None
        if type(token) is not str or _OIDC_TOKEN.fullmatch(token) is None:
            raise InternalTransportError("identity token acquisition failed")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        try:
            response = await asyncio.to_thread(
                self._http_poster.post,
                url=route.url,
                headers=headers,
                body=body,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            raise
        except InternalTransportError:
            raise
        except Exception:
            raise InternalTransportError("internal request failed") from None
        if type(response) is not InternalHttpResponse:
            raise InternalTransportError("internal response is invalid")
        if (
            response.status_code != 200
            or response.content_type
            not in {"application/json", "application/json; charset=utf-8"}
            or not response.body
            or len(response.body) > MAX_CONTRACT_BYTES
        ):
            raise InternalTransportError("internal response is invalid")
        return response.body


__all__ = [
    "GoogleIdTokenProvider",
    "GoogleOneShotOidcTransport",
    "IdTokenProvider",
    "InternalHttpResponse",
    "InternalTransportError",
    "OneShotHttpPoster",
    "UrllibOneShotHttpPoster",
]
