from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from health_execution_test_data import make_anchor
from pydantic import BaseModel
from test_health_pipeline import (
    _Clock,
    _command,
    _context,
    _invocation,
    _pipeline,
    _policy,
)

from controlgraph_canary.application.health_pipeline import (
    ApiHealthEvaluationClient,
    CoordinatorHealthEvaluationService,
    VerifierHealthEvaluationService,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.health_pipeline import (
    HealthEvaluationCommandV1,
    HealthEvaluationInvocationV1,
    HealthEvaluationResultV2,
    VerifierHealthEvaluationRequestV1,
    VerifierHealthEvaluationResultV1,
    create_verifier_health_evaluation_request,
)
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.http.service import create_service_app

_CREDENTIAL = "Bearer header.payload.signature"


class _Authenticator:
    def __init__(
        self,
        policy: RouteAuthenticationPolicy,
        context: AuthenticationContext,
    ) -> None:
        self.policy = policy
        self.context = context
        self.calls: list[tuple[str | None, RouteAuthenticationPolicy]] = []

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        self.calls.append((authorization_header, policy))
        assert authorization_header == _CREDENTIAL
        assert policy == self.policy
        return self.context


class _CapturingApiClient:
    def __init__(self, delegate: ApiHealthEvaluationClient) -> None:
        self.delegate = delegate
        self.calls: list[tuple[HealthEvaluationCommandV1, AuthenticationContext]] = []
        self.results: list[HealthEvaluationResultV2] = []

    async def evaluate(
        self,
        command: HealthEvaluationCommandV1,
        caller: AuthenticationContext,
    ) -> HealthEvaluationResultV2:
        self.calls.append((command, caller))
        result = await self.delegate.evaluate(command, caller)
        self.results.append(result)
        return result


class _CapturingCoordinatorService:
    def __init__(self, delegate: CoordinatorHealthEvaluationService) -> None:
        self.delegate = delegate
        self.calls: list[
            tuple[HealthEvaluationInvocationV1, AuthenticationContext]
        ] = []
        self.results: list[HealthEvaluationResultV2] = []

    async def evaluate(
        self,
        invocation: HealthEvaluationInvocationV1,
        caller: AuthenticationContext,
    ) -> HealthEvaluationResultV2:
        self.calls.append((invocation, caller))
        result = await self.delegate.evaluate(invocation, caller)
        self.results.append(result)
        return result


class _CapturingVerifierService:
    def __init__(self, delegate: VerifierHealthEvaluationService) -> None:
        self.delegate = delegate
        self.calls: list[
            tuple[VerifierHealthEvaluationRequestV1, AuthenticationContext]
        ] = []
        self.results: list[VerifierHealthEvaluationResultV1] = []

    async def evaluate(
        self,
        request: VerifierHealthEvaluationRequestV1,
        caller: AuthenticationContext,
    ) -> VerifierHealthEvaluationResultV1:
        self.calls.append((request, caller))
        result = await self.delegate.evaluate(request, caller)
        self.results.append(result)
        return result


def _headers(role: ServiceRole) -> dict[str, str]:
    if role is ServiceRole.API:
        return {
            CONTROLGRAPH_AUTHORIZATION_HEADER: _CREDENTIAL,
            SERVERLESS_AUTHORIZATION_HEADER: (
                "bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE"
            ),
        }
    return {"Authorization": _CREDENTIAL}


def _altered_payload(contract: BaseModel, **updates: object) -> bytes:
    values = contract.model_dump(mode="json")
    values.update(updates)
    return json.dumps(
        values,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _assert_schema_variants_fail_closed(
    client: TestClient,
    *,
    role: ServiceRole,
    contract: BaseModel,
) -> None:
    for payload, expected_code in (
        (
            _altered_payload(
                contract,
                schema_version=f"{contract.model_dump()['schema_version']}-legacy",
            ),
            "CONTRACT_VERSION_UNSUPPORTED",
        ),
        (_altered_payload(contract, unexpected_field=True), "CONTRACT_INVALID"),
    ):
        response = client.post(
            protected_path(role),
            headers=_headers(role),
            content=payload,
        )

        assert response.status_code == 400
        assert response.json()["code"] == expected_code
        assert set(response.json()) == {"code", "correlation_id"}


def test_api_health_route_decodes_and_dispatches_only_the_exact_command() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    api, transport, _, _, command, operator, _, _ = _pipeline(clock=clock)
    policy = _policy(ServiceRole.API, CallerRole.OPERATOR)
    authenticator = _Authenticator(policy, operator)
    capturing = _CapturingApiClient(api)
    client = TestClient(
        create_service_app(
            ServiceRole.API,
            authenticator=authenticator,
            authentication_policy=policy,
            api_health_evaluation_client=capturing,  # type: ignore[arg-type]
        )
    )

    response = client.post(
        protected_path(ServiceRole.API),
        headers=_headers(ServiceRole.API),
        content=canonical_json_bytes(command),
    )

    assert response.status_code == 200
    result = decode_contract(response.content, HealthEvaluationResultV2)
    assert result == capturing.results[0]
    assert response.content == canonical_json_bytes(result)
    assert capturing.calls == [(command, operator)]
    assert len(transport.calls) == 2

    _assert_schema_variants_fail_closed(
        client,
        role=ServiceRole.API,
        contract=command,
    )
    assert capturing.calls == [(command, operator)]
    assert len(transport.calls) == 2


def test_coordinator_health_route_decodes_and_dispatches_only_exact_invocation() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    _, transport, _, _, command, operator, coordinator, _ = _pipeline(clock=clock)
    invocation = _invocation(command, operator)
    policy = _policy(ServiceRole.COORDINATOR, CallerRole.API)
    caller = _context(policy)
    authenticator = _Authenticator(policy, caller)
    capturing = _CapturingCoordinatorService(coordinator)
    client = TestClient(
        create_service_app(
            ServiceRole.COORDINATOR,
            authenticator=authenticator,
            authentication_policy=policy,
            coordinator_health_evaluation_service=capturing,  # type: ignore[arg-type]
        )
    )

    response = client.post(
        protected_path(ServiceRole.COORDINATOR),
        headers=_headers(ServiceRole.COORDINATOR),
        content=canonical_json_bytes(invocation),
    )

    assert response.status_code == 200
    result = decode_contract(response.content, HealthEvaluationResultV2)
    assert result == capturing.results[0]
    assert response.content == canonical_json_bytes(result)
    assert capturing.calls == [(invocation, caller)]
    assert len(transport.verifier_requests) == 1

    _assert_schema_variants_fail_closed(
        client,
        role=ServiceRole.COORDINATOR,
        contract=invocation,
    )
    assert capturing.calls == [(invocation, caller)]
    assert len(transport.verifier_requests) == 1


def test_verifier_health_route_decodes_and_dispatches_only_the_exact_request() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    _, transport, _, _, _, _, _, _ = _pipeline(clock=clock)
    verifier = transport.verifier_service
    assert verifier is not None
    root, anchor = make_anchor()
    command = _command(root, anchor.apply_receipt)
    request = create_verifier_health_evaluation_request(
        command=command,
        root=root,
        anchor=anchor,
        prior_signed_proof=None,
    )
    policy = _policy(ServiceRole.VERIFIER, CallerRole.COORDINATOR)
    caller = _context(policy)
    authenticator = _Authenticator(policy, caller)
    capturing = _CapturingVerifierService(verifier)
    client = TestClient(
        create_service_app(
            ServiceRole.VERIFIER,
            authenticator=authenticator,
            authentication_policy=policy,
            verifier_health_evaluation_service=capturing,  # type: ignore[arg-type]
        )
    )

    response = client.post(
        protected_path(ServiceRole.VERIFIER),
        headers=_headers(ServiceRole.VERIFIER),
        content=canonical_json_bytes(request),
    )

    assert response.status_code == 200
    result = decode_contract(response.content, VerifierHealthEvaluationResultV1)
    assert result == capturing.results[0]
    assert response.content == canonical_json_bytes(result)
    assert result.request_sha256 == request.request_sha256
    assert result.signed_proof.proof.sequence == 1
    assert capturing.calls == [(request, caller)]

    _assert_schema_variants_fail_closed(
        client,
        role=ServiceRole.VERIFIER,
        contract=request,
    )
    assert capturing.calls == [(request, caller)]
