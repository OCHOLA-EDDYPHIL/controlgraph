from __future__ import annotations

import asyncio

import pytest

from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.integrations.google.probe_transport import (
    GoogleSealedProbeTransport,
    ProbeRawHttpResponse,
    ProbeTransportError,
)

PROJECT = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
ENDPOINT = (
    f"https://controlgraph-reference-target-{PROJECT_NUMBER}.us-central1.run.app"
    "/v1/probe"
)


def _target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT,
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )


class _TokenProvider:
    def __init__(self, token: str = "header.payload.signature") -> None:
        self.value = token
        self.audiences: list[str] = []

    def token(self, audience: str) -> str:
        self.audiences.append(audience)
        return self.value


class _Getter:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def get(self, **values: object) -> ProbeRawHttpResponse:
        self.calls.append(values)
        return ProbeRawHttpResponse(
            status_code=200,
            content_type="application/json",
            body=b"{}",
        )


def test_transport_is_sealed_to_exact_origin_path_and_bounded_get() -> None:
    tokens = _TokenProvider()
    getter = _Getter()
    transport = GoogleSealedProbeTransport(
        target=_target(),
        endpoint=ENDPOINT,
        token_provider=tokens,
        http_getter=getter,
    )

    response = asyncio.run(
        transport.get(
            nonce="n" * 32,
            correlation_id="probe-001:1",
            timeout_milliseconds=2_000,
            response_limit_bytes=1_024,
        )
    )

    assert response.status_code == 200
    assert tokens.audiences == [ENDPOINT.removesuffix("/v1/probe")]
    assert getter.calls == [
        {
            "url": f"{ENDPOINT}?correlation_id=probe-001%3A1&nonce={'n' * 32}",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer header.payload.signature",
                "Cache-Control": "no-store",
            },
            "timeout": 2.0,
            "response_limit_bytes": 1_024,
        }
    ]


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://controlgraph-reference-target-123456789012.us-central1.run.app/v1/probe",
        "https://127.0.0.1/v1/probe",
        "https://controlgraph-reference-target-123456789012.us-central1.run.app/",
        (
            "https://controlgraph-reference-target-123456789012.us-central1.run.app"
            "/v1/probe?url=https://example.test"
        ),
        "https://example.test/v1/probe",
        (
            "https://controlgraph-reference-target-123456789012.us-central1.run.app"
            "/v1/probe#fragment"
        ),
    ],
)
def test_transport_rejects_ssrf_and_destination_substitution(endpoint: str) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        GoogleSealedProbeTransport(target=_target(), endpoint=endpoint)


def test_transport_rejects_credential_and_policy_substitution_before_http() -> None:
    getter = _Getter()
    transport = GoogleSealedProbeTransport(
        target=_target(),
        endpoint=ENDPOINT,
        token_provider=_TokenProvider("credential\nsubstitution"),
        http_getter=getter,
    )

    with pytest.raises(ProbeTransportError, match="identity unavailable"):
        asyncio.run(
            transport.get(
                nonce="n" * 32,
                correlation_id="probe-001:1",
                timeout_milliseconds=2_000,
                response_limit_bytes=1_024,
            )
        )
    with pytest.raises(ValueError, match="sealed transport policy"):
        asyncio.run(
            GoogleSealedProbeTransport(
                target=_target(),
                endpoint=ENDPOINT,
                token_provider=_TokenProvider(),
                http_getter=getter,
            ).get(
                nonce="n" * 32,
                correlation_id="probe-001:1",
                timeout_milliseconds=2_001,
                response_limit_bytes=1_024,
            )
        )
    assert getter.calls == []
