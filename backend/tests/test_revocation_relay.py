from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from root_v2_test_data import PROJECT, PROJECT_NUMBER, make_root_v2_records

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.revocation import EpochRevocationError
from controlgraph_canary.application.revocation_relay import (
    ApiEpochRevocationClient,
    CoordinatorEpochRevocationRelay,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_COMMAND_V1,
    EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1,
    EPOCH_REVOCATION_RELAY_RESPONSE_V1,
    EPOCH_REVOCATION_RESULT_V1,
    EpochRevocationCommandV1,
    EpochRevocationEvidenceSubjectV1,
    EpochRevocationFailureCode,
    EpochRevocationInvocationV1,
    EpochRevocationRelayResponseV1,
    EpochRevocationResultV1,
    epoch_revocation_evidence_id,
    epoch_revocation_request_sha256,
)
from controlgraph_canary.http.service import create_service_app

OPERATOR = "operator@example.test"
OPERATOR_SUBJECT = "123456789012345678901"
API_SUBJECT = "234567890123456789012"
API_AUDIENCE = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
COORDINATOR_AUDIENCE = (
    f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
)
ISSUED_AT = 1_787_140_000
EXPIRES_AT = ISSUED_AT + 600


def _operator_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.API,
        path=protected_path(ServiceRole.API),
        audience=API_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.OPERATOR,
            email=OPERATOR,
            subject=OPERATOR_SUBJECT,
        ),
    )


def _coordinator_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.COORDINATOR,
        path=protected_path(ServiceRole.COORDINATOR),
        audience=COORDINATOR_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.API,
            email=f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com",
            subject=API_SUBJECT,
        ),
    )


def _operator() -> AuthenticationContext:
    return AuthenticationContext(
        role=CallerRole.OPERATOR,
        email=OPERATOR,
        subject=OPERATOR_SUBJECT,
        issuer="https://accounts.google.com",
        audience=API_AUDIENCE,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )


def _api() -> AuthenticationContext:
    return AuthenticationContext(
        role=CallerRole.API,
        email=f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com",
        subject=API_SUBJECT,
        issuer="https://accounts.google.com",
        audience=COORDINATOR_AUDIENCE,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )


def _command() -> EpochRevocationCommandV1:
    records = make_root_v2_records()
    return EpochRevocationCommandV1(
        schema_version=EPOCH_REVOCATION_COMMAND_V1,
        root_id=records.root.root_id,
        expected_root_sha256=records.root.root_sha256,
        expected_epoch=1,
        reason="Stop the canary before delayed work executes.",
        request_id="request-revoke-relay-001",
        idempotency_key="revoke-relay-001",
        confirmation="REVOKE",
    )


def _result(invocation: EpochRevocationInvocationV1) -> EpochRevocationResultV1:
    records = make_root_v2_records()
    digest = epoch_revocation_request_sha256(invocation)
    command = invocation.command
    evidence_id = epoch_revocation_evidence_id(
        digest,
        command.expected_root_sha256,
        command.expected_epoch + 1,
    )
    committed_at = "2026-08-19T12:05:00Z"
    subject = EpochRevocationEvidenceSubjectV1(
        schema_version=EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1,
        root_id=command.root_id,
        root_sha256=command.expected_root_sha256,
        request_sha256=digest,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        operator_identity=invocation.operator_identity,
        operator_subject=invocation.operator_subject,
        reason=command.reason,
        service_claim_sha256="b" * 64,
        previous_authority_sha256="c" * 64,
        replacement_authority_sha256="d" * 64,
        previous_epoch=command.expected_epoch,
        new_epoch=command.expected_epoch + 1,
        evidence_id=evidence_id,
        committed_at=committed_at,
    )
    return EpochRevocationResultV1(
        schema_version=EPOCH_REVOCATION_RESULT_V1,
        result_id=f"cgrevoke:{digest}",
        request_sha256=digest,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        root_id=command.root_id,
        root_sha256=command.expected_root_sha256,
        target=records.root.content.target,
        operator_identity=invocation.operator_identity,
        operator_subject=invocation.operator_subject,
        reason=command.reason,
        previous_epoch=command.expected_epoch,
        new_epoch=command.expected_epoch + 1,
        evidence_id=evidence_id,
        evidence_sha256="a" * 64,
        evidence_subject=subject,
        committed_at=committed_at,
    )


def _route() -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.API,
        service_role=ServiceRole.COORDINATOR,
        audience=COORDINATOR_AUDIENCE,
    )


class _Transport:
    def __init__(self) -> None:
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        invocation = decode_contract(body, EpochRevocationInvocationV1)
        return canonical_json_bytes(
            EpochRevocationRelayResponseV1(
                schema_version=EPOCH_REVOCATION_RELAY_RESPONSE_V1,
                result=_result(invocation),
                failure_code=None,
            )
        )


class _OutcomeTransport:
    def __init__(self, body: bytes | None) -> None:
        self.body = body

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        del route, body
        if self.body is None:
            raise TimeoutError("synthetic response loss")
        return self.body


class _TamperedTargetTransport:
    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        del route
        invocation = decode_contract(body, EpochRevocationInvocationV1)
        result = _result(invocation)
        altered = result.model_copy(
            update={
                "target": result.target.model_copy(
                    update={"project_id": "controlgraph-canary-z9y8x7"}
                )
            }
        )
        return canonical_json_bytes(
            EpochRevocationRelayResponseV1(
                schema_version=EPOCH_REVOCATION_RELAY_RESPONSE_V1,
                result=altered,
                failure_code=None,
            )
        )


class _Revoker:
    def __init__(self) -> None:
        self.calls: list[
            tuple[EpochRevocationInvocationV1, AuthenticationContext | None]
        ] = []
        self.denials: list[tuple[EpochRevocationInvocationV1, EpochRevocationFailureCode]] = []

    async def revoke(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> EpochRevocationResultV1:
        self.calls.append((invocation, principal))
        return _result(invocation)

    async def record_authenticated_denial(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        code: EpochRevocationFailureCode,
    ) -> None:
        self.denials.append((invocation, code))


class _Authenticator:
    def __init__(self, principal: AuthenticationContext) -> None:
        self.principal = principal

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        assert authorization_header == "Bearer exact-token"
        assert policy.caller.role is self.principal.role
        return self.principal


def test_api_relay_binds_verified_operator_and_one_unique_attempt() -> None:
    async def scenario() -> None:
        transport = _Transport()
        client = ApiEpochRevocationClient(
            route=_route(),
            authentication_policy=_operator_policy(),
            transport=transport,
            attempt_id_factory=lambda: "cgrevoke-attempt-relay-001",
        )

        result = await client.revoke(_command(), _operator())

        assert result.new_epoch == 2
        assert len(transport.calls) == 1
        route, body = transport.calls[0]
        assert route == _route()
        invocation = decode_contract(body, EpochRevocationInvocationV1)
        assert invocation.attempt_id == "cgrevoke-attempt-relay-001"
        assert invocation.operator_identity == OPERATOR
        assert invocation.operator_subject == OPERATOR_SUBJECT

    asyncio.run(scenario())


def test_coordinator_relay_preserves_operator_identity_without_an_api_store() -> None:
    async def scenario() -> None:
        revoker = _Revoker()
        relay = CoordinatorEpochRevocationRelay(
            authentication_policy=_coordinator_policy(),
            operator_policy=_operator_policy(),
            revoker=revoker,
        )
        operator = _operator()
        invocation = EpochRevocationInvocationV1(
            schema_version="controlgraph.epoch-revocation-invocation/v1",
            command=_command(),
            attempt_id="cgrevoke-attempt-relay-002",
            operator_identity=operator.email,
            operator_subject=operator.subject,
            operator_issuer="https://accounts.google.com",
            operator_audience=operator.audience,
            operator_issued_at=operator.issued_at,
            operator_expires_at=operator.expires_at,
        )

        result = await relay.revoke(invocation, _api())

        assert result.new_epoch == 2
        assert revoker.calls == [(invocation, operator)]

    asyncio.run(scenario())


def test_api_http_route_accepts_the_strict_revocation_command() -> None:
    transport = _Transport()
    relay = ApiEpochRevocationClient(
        route=_route(),
        authentication_policy=_operator_policy(),
        transport=transport,
        attempt_id_factory=lambda: "cgrevoke-attempt-http-001",
    )
    client = TestClient(
        create_service_app(
            ServiceRole.API,
            authenticator=_Authenticator(_operator()),
            authentication_policy=_operator_policy(),
            api_epoch_revocation_client=relay,
        )
    )

    response = client.post(
        protected_path(ServiceRole.API),
        content=canonical_json_bytes(_command()),
        headers={"Authorization": "Bearer exact-token"},
    )

    assert response.status_code == 200
    result = decode_contract(response.content, EpochRevocationResultV1)
    assert result.new_epoch == 2
    assert len(transport.calls) == 1


def test_coordinator_http_route_accepts_only_the_bound_invocation() -> None:
    revoker = _Revoker()
    relay = CoordinatorEpochRevocationRelay(
        authentication_policy=_coordinator_policy(),
        operator_policy=_operator_policy(),
        revoker=revoker,
    )
    operator = _operator()
    invocation = EpochRevocationInvocationV1(
        schema_version="controlgraph.epoch-revocation-invocation/v1",
        command=_command(),
        attempt_id="cgrevoke-attempt-http-002",
        operator_identity=operator.email,
        operator_subject=operator.subject,
        operator_issuer="https://accounts.google.com",
        operator_audience=operator.audience,
        operator_issued_at=operator.issued_at,
        operator_expires_at=operator.expires_at,
    )
    client = TestClient(
        create_service_app(
            ServiceRole.COORDINATOR,
            authenticator=_Authenticator(_api()),
            authentication_policy=_coordinator_policy(),
            coordinator_epoch_revocation_relay=relay,
        )
    )

    response = client.post(
        protected_path(ServiceRole.COORDINATOR),
        content=canonical_json_bytes(invocation),
        headers={"Authorization": "Bearer exact-token"},
    )

    assert response.status_code == 200
    outcome = decode_contract(response.content, EpochRevocationRelayResponseV1)
    assert outcome.result is not None and outcome.result.new_epoch == 2
    assert outcome.failure_code is None
    assert revoker.calls == [(invocation, operator)]


def test_api_relay_preserves_sanitized_coordinator_denials() -> None:
    async def scenario() -> None:
        client = ApiEpochRevocationClient(
            route=_route(),
            authentication_policy=_operator_policy(),
            transport=_OutcomeTransport(
                canonical_json_bytes(
                    EpochRevocationRelayResponseV1(
                        schema_version=EPOCH_REVOCATION_RELAY_RESPONSE_V1,
                        result=None,
                        failure_code=EpochRevocationFailureCode.EPOCH_MISMATCH,
                    )
                )
            ),
            attempt_id_factory=lambda: "cgrevoke-attempt-denied",
        )

        with pytest.raises(EpochRevocationError) as captured:
            await client.revoke(_command(), _operator())

        assert captured.value.code is EpochRevocationFailureCode.EPOCH_MISMATCH

    asyncio.run(scenario())


def test_api_relay_classifies_response_loss_as_outcome_unknown() -> None:
    async def scenario() -> None:
        client = ApiEpochRevocationClient(
            route=_route(),
            authentication_policy=_operator_policy(),
            transport=_OutcomeTransport(None),
            attempt_id_factory=lambda: "cgrevoke-attempt-ambiguous",
        )

        with pytest.raises(EpochRevocationError) as captured:
            await client.revoke(_command(), _operator())

        assert captured.value.code is EpochRevocationFailureCode.OUTCOME_UNKNOWN

    asyncio.run(scenario())


def test_coordinator_relay_rejects_forged_operator_facts_before_revoker() -> None:
    async def scenario() -> None:
        revoker = _Revoker()
        relay = CoordinatorEpochRevocationRelay(
            authentication_policy=_coordinator_policy(),
            operator_policy=_operator_policy(),
            revoker=revoker,
        )
        operator = _operator()
        forged = EpochRevocationInvocationV1(
            schema_version="controlgraph.epoch-revocation-invocation/v1",
            command=_command(),
            attempt_id="cgrevoke-attempt-forged-operator",
            operator_identity="attacker@example.test",
            operator_subject=operator.subject,
            operator_issuer="https://accounts.google.com",
            operator_audience=operator.audience,
            operator_issued_at=operator.issued_at,
            operator_expires_at=operator.expires_at,
        )

        with pytest.raises(EpochRevocationError) as captured:
            await relay.revoke(forged, _api())

        assert captured.value.code is EpochRevocationFailureCode.CALLER_DENIED
        assert revoker.calls == []
        assert revoker.denials == [
            (forged, EpochRevocationFailureCode.CALLER_DENIED)
        ]

    asyncio.run(scenario())


def test_api_relay_rejects_a_result_for_another_target() -> None:
    async def scenario() -> None:
        client = ApiEpochRevocationClient(
            route=_route(),
            authentication_policy=_operator_policy(),
            transport=_TamperedTargetTransport(),
            attempt_id_factory=lambda: "cgrevoke-attempt-target-tamper",
        )

        with pytest.raises(EpochRevocationError) as captured:
            await client.revoke(_command(), _operator())

        assert captured.value.code is EpochRevocationFailureCode.OUTCOME_UNKNOWN

    asyncio.run(scenario())
