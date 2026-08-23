from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi.testclient import TestClient
from model_assistance_test_data import (
    authentication_context,
    authentication_policy,
    invocation,
    recommendation,
    verified_evidence_reader,
)

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
)
from controlgraph_canary.application.model_assistance import (
    InvocationDiagnosticRegistry,
    ReadOnlyAdvisorService,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.model_assistance import (
    AdvisorInvocationRequestV1,
    AdvisorRecommendationV1,
    AdvisorResponseV1,
)
from controlgraph_canary.http.advisor import create_advisor_app


class _Authenticator:
    def authenticate(
        self,
        authorization_header: str | None,
        policy: object,
    ) -> AuthenticationContext:
        del policy
        if authorization_header != "Bearer valid-synthetic-token":
            raise AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)
        return authentication_context()


class _Model:
    @property
    def model_id(self) -> Literal["gemini-3.5-flash"]:
        return "gemini-3.5-flash"

    @property
    def model_location(self) -> Literal["global"]:
        return "global"

    @property
    def prompt_version(self) -> Literal["controlgraph.rollout-advisor-prompt/v1"]:
        return "controlgraph.rollout-advisor-prompt/v1"

    async def recommend(
        self,
        request: AdvisorInvocationRequestV1,
        tools: InvocationDiagnosticRegistry,
    ) -> AdvisorRecommendationV1:
        for tool_id in tools.registry.tools:
            await tools.read(tool_id.tool_id, request.snapshot_sha256)
        return recommendation(request)


def _client() -> TestClient:
    policy = authentication_policy()
    service = ReadOnlyAdvisorService(
        authentication_policy=policy,
        model=_Model(),
        evidence_reader=verified_evidence_reader(),
        clock=lambda: datetime(2026, 8, 22, 10, 1, tzinfo=UTC),
    )
    return TestClient(
        create_advisor_app(
            authenticator=_Authenticator(),
            authentication_policy=policy,
            advisor_service=service,
            build_digest=f"sha256:{'a' * 64}",
        )
    )


def test_advisor_http_route_requires_coordinator_identity() -> None:
    response = _client().post(
        "/v1/internal/advise",
        content=canonical_json_bytes(invocation()),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == AuthenticationDenialCode.CREDENTIAL_INVALID.value
    assert "valid-synthetic-token" not in response.text


def test_advisor_http_route_returns_only_canonical_validated_response() -> None:
    request = invocation()

    response = _client().post(
        "/v1/internal/advise",
        content=canonical_json_bytes(request),
        headers={
            "Authorization": "Bearer valid-synthetic-token",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = decode_contract(response.content, AdvisorResponseV1)
    assert result.request_sha256
    assert result.recommendation is not None
    assert result.audit.validation.accepted is True
    assert response.content == canonical_json_bytes(result)


def test_advisor_http_route_rejects_noncanonical_or_unknown_fields() -> None:
    request = invocation().model_dump(mode="json")
    request["unexpected"] = True

    response = _client().post(
        "/v1/internal/advise",
        json=request,
        headers={"Authorization": "Bearer valid-synthetic-token"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "ADVISOR_REQUEST_INVALID"


def test_advisor_metadata_never_advertises_mutation_authority() -> None:
    response = _client().get("/v1/metadata")

    assert response.status_code == 200
    assert response.json()["service_role"] == "advisor"
    assert response.json()["mutation_enabled"] is False
