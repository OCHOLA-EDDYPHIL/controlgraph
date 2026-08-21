"""One-shot authenticated GET transport for the fixed reference probe."""

from __future__ import annotations

import asyncio
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from controlgraph_canary.application.independent_verification import ProbeHttpResponse
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.integrations.google.internal_transport import (
    GoogleIdTokenProvider,
    IdTokenProvider,
)

_HOSTNAME = re.compile(
    r"^controlgraph-reference-target-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_CORRELATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OIDC_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{16,16384}$")


class ProbeTransportError(OSError):
    """Sanitized network/token failure classified as unavailable by the verifier."""


@dataclass(frozen=True, slots=True)
class ProbeRawHttpResponse:
    """Bounded raw response from a single non-redirecting GET."""

    status_code: int
    content_type: str
    body: bytes


class OneShotHttpGetter(Protocol):
    """Make exactly one GET with redirects and retries disabled."""

    def get(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        response_limit_bytes: int,
    ) -> ProbeRawHttpResponse: ...


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


class UrllibOneShotHttpGetter:
    """Standard-library GET backend with no redirect or retry behavior."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def get(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        response_limit_bytes: int,
    ) -> ProbeRawHttpResponse:
        request = urllib.request.Request(
            url=url,
            headers=dict(headers),
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                status = response.status
                content_types = response.headers.get_all("Content-Type") or []
                body = response.read(response_limit_bytes + 1)
        except urllib.error.HTTPError as error:
            return ProbeRawHttpResponse(
                status_code=error.code,
                content_type="",
                body=b"",
            )
        except Exception:
            raise ProbeTransportError("reference probe request failed") from None
        if (
            type(status) is not int
            or len(content_types) != 1
            or type(content_types[0]) is not str
            or len(body) > response_limit_bytes
        ):
            raise ValueError("reference probe response is invalid")
        return ProbeRawHttpResponse(
            status_code=status,
            content_type=content_types[0],
            body=body,
        )


class GoogleSealedProbeTransport:
    """GET-only OIDC client sealed to one exact HTTPS target and path."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        endpoint: str,
        token_provider: IdTokenProvider | None = None,
        http_getter: OneShotHttpGetter | None = None,
    ) -> None:
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError:
            raise ValueError("probe transport endpoint is invalid") from None
        if (
            type(target) is not TargetBinding
            or target.region != "us-central1"
            or target.environment != "nonprod"
            or target.service_name != "controlgraph-reference-target"
            or type(endpoint) is not str
            or parsed.scheme != "https"
            or parsed.hostname is None
            or _HOSTNAME.fullmatch(parsed.hostname) is None
            or parsed.netloc != parsed.hostname
            or parsed.path != "/v1/probe"
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or endpoint != f"https://{parsed.hostname}/v1/probe"
        ):
            raise ValueError("probe transport endpoint is outside the target allowlist")
        self._endpoint = endpoint
        self._audience = f"https://{parsed.hostname}"
        self._token_provider = token_provider or GoogleIdTokenProvider()
        self._http_getter = http_getter or UrllibOneShotHttpGetter()

    @property
    def endpoint(self) -> str:
        """Return the sole allowlisted destination including immutable path."""

        return self._endpoint

    async def get(
        self,
        *,
        nonce: str,
        correlation_id: str,
        timeout_milliseconds: int,
        response_limit_bytes: int,
    ) -> ProbeHttpResponse:
        """Make one bounded request; credentials and bodies never enter errors."""

        if (
            type(nonce) is not str
            or _NONCE.fullmatch(nonce) is None
            or type(correlation_id) is not str
            or _CORRELATION.fullmatch(correlation_id) is None
            or timeout_milliseconds != 2_000
            or response_limit_bytes != 1_024
        ):
            raise ValueError("probe request is outside the sealed transport policy")
        try:
            token = await asyncio.to_thread(
                self._token_provider.token,
                self._audience,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ProbeTransportError("reference probe identity unavailable") from None
        if type(token) is not str or _OIDC_TOKEN.fullmatch(token) is None:
            raise ProbeTransportError("reference probe identity unavailable")
        query = urllib.parse.urlencode(
            {"correlation_id": correlation_id, "nonce": nonce},
            quote_via=urllib.parse.quote,
            safe="",
        )
        url = f"{self._endpoint}?{query}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Cache-Control": "no-store",
        }
        try:
            raw = await asyncio.to_thread(
                self._http_getter.get,
                url=url,
                headers=headers,
                timeout=timeout_milliseconds / 1_000,
                response_limit_bytes=response_limit_bytes,
            )
        except asyncio.CancelledError:
            raise
        except ProbeTransportError:
            raise
        except ValueError:
            raise
        except Exception:
            raise ProbeTransportError("reference probe request failed") from None
        if type(raw) is not ProbeRawHttpResponse:
            raise ValueError("reference probe response is invalid")
        return ProbeHttpResponse(
            status_code=raw.status_code,
            content_type=raw.content_type,
            body=raw.body,
        )


__all__ = [
    "GoogleSealedProbeTransport",
    "OneShotHttpGetter",
    "ProbeRawHttpResponse",
    "ProbeTransportError",
    "UrllibOneShotHttpGetter",
]
