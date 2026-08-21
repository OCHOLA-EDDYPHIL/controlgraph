from __future__ import annotations

import asyncio
from typing import cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_root_creation_application import (
    PROJECT,
    PROJECT_NUMBER,
    _command,
    _signed,
    _unsigned,
)
from test_root_creation_service import _bundle

from controlgraph_canary.application.authority_store import RootCreationWriteResult
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    runtime_route_policy,
)
from controlgraph_canary.application.root_creation import complete_root_creation
from controlgraph_canary.application.root_creation_service import (
    RootCreationError,
    RootCreationErrorCode,
)
from controlgraph_canary.application.root_relay import (
    ApiRootCreationClient,
    CoordinatorRootCreationRelay,
    RootRelayError,
    RootRelayErrorCode,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.contracts import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.codec import encode_base64url
from controlgraph_canary.contracts.root_creation import (
    RootCreationCommandV1,
    decode_root_creation_result,
)
from controlgraph_canary.contracts.root_relay import (
    ROOT_CREATION_INVOCATION_V1,
    RootCreationInvocationV1,
)
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.http.service import create_service_app, protected_paths
from controlgraph_canary.integrations.google.internal_transport import (
    GoogleOneShotOidcTransport,
    InternalHttpResponse,
    InternalTransportError,
)

OPERATOR_EMAIL = "operator@example.test"
OPERATOR_SUBJECT = "123456789012345678901"
API_SUBJECT = "234567890123456789012"
OPERATOR_AUDIENCE = (
    f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
)
COORDINATOR_AUDIENCE = (
    f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
)
API_IDENTITY = f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com"
ISSUED_AT = 1_776_236_400
EXPIRES_AT = ISSUED_AT + 600
AUTHORIZATION = "Bearer aaa.bbb.ccc"
OPERATOR_HEADERS = {
    CONTROLGRAPH_AUTHORIZATION_HEADER: AUTHORIZATION,
    SERVERLESS_AUTHORIZATION_HEADER: "bearer aaa.bbb.SIGNATURE_REMOVED_BY_GOOGLE",
}


def _identity_environment(role: ServiceRole) -> dict[str, str]:
    if role is ServiceRole.API:
        caller_role = "operator"
        caller_email = OPERATOR_EMAIL
        caller_subject = OPERATOR_SUBJECT
        audience = OPERATOR_AUDIENCE
    else:
        caller_role = "api"
        caller_email = API_IDENTITY
        caller_subject = API_SUBJECT
        audience = COORDINATOR_AUDIENCE
    return {
        "CONTROLGRAPH_PROJECT_ID": PROJECT,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_ROLE": role.value,
        "CONTROLGRAPH_AUTH_AUDIENCE": audience,
        "CONTROLGRAPH_AUTH_CALLER_ROLE": caller_role,
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": caller_email,
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": caller_subject,
    }


def _policy(role: ServiceRole) -> RouteAuthenticationPolicy:
    return runtime_route_policy(role, _identity_environment(role))


def _operator(**changes: object) -> AuthenticationContext:
    values: dict[str, object] = {
        "role": CallerRole.OPERATOR,
        "email": OPERATOR_EMAIL,
        "subject": OPERATOR_SUBJECT,
        "issuer": "https://accounts.google.com",
        "audience": OPERATOR_AUDIENCE,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
    }
    values.update(changes)
    return AuthenticationContext(**values)  # type: ignore[arg-type]


def _api_caller(**changes: object) -> AuthenticationContext:
    values: dict[str, object] = {
        "role": CallerRole.API,
        "email": API_IDENTITY,
        "subject": API_SUBJECT,
        "issuer": "https://accounts.google.com",
        "audience": COORDINATOR_AUDIENCE,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
    }
    values.update(changes)
    return AuthenticationContext(**values)  # type: ignore[arg-type]


def _invocation(
    *,
    command: RootCreationCommandV1 | None = None,
    operator_identity: str = OPERATOR_EMAIL,
    operator_subject: str = OPERATOR_SUBJECT,
) -> RootCreationInvocationV1:
    return RootCreationInvocationV1(
        schema_version=ROOT_CREATION_INVOCATION_V1,
        command=command or _command(),
        operator_identity=operator_identity,
        operator_subject=operator_subject,
        operator_issuer="https://accounts.google.com",
        operator_audience=OPERATOR_AUDIENCE,
        operator_issued_at=ISSUED_AT,
        operator_expires_at=EXPIRES_AT,
    )


def _write_result(
    *,
    command: RootCreationCommandV1 | None = None,
) -> RootCreationWriteResult:
    unsigned = _unsigned(command=command or _command())
    artifacts = complete_root_creation(unsigned, _signed(unsigned))
    return RootCreationWriteResult(
        result=artifacts.creation_result,
        bundle=_bundle(artifacts),
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
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.error: BaseException | None = None
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        if self.error is not None:
            raise self.error
        return self.response


class _Creator:
    def __init__(self, result: RootCreationWriteResult | None = None) -> None:
        self.result = result or _write_result()
        self.error: BaseException | None = None
        self.calls: list[tuple[RootCreationCommandV1, AuthenticationContext | None]] = []

    async def create(
        self,
        command: RootCreationCommandV1,
        *,
        principal: AuthenticationContext | None,
    ) -> RootCreationWriteResult:
        self.calls.append((command, principal))
        if self.error is not None:
            raise self.error
        return self.result


class _Authenticator:
    def __init__(
        self,
        policy: RouteAuthenticationPolicy,
        context: AuthenticationContext,
    ) -> None:
        self.policy = policy
        self.context = context
        self.error: AuthenticationError | None = None
        self.calls: list[str | None] = []

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        self.calls.append(authorization_header)
        if self.error is not None:
            raise self.error
        if authorization_header != AUTHORIZATION or policy != self.policy:
            raise AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)
        return self.context


def _api_client(transport: _Transport) -> ApiRootCreationClient:
    return ApiRootCreationClient(
        route=_route(),
        authentication_policy=_policy(ServiceRole.API),
        transport=transport,
    )


def _coordinator(creator: _Creator) -> CoordinatorRootCreationRelay:
    return CoordinatorRootCreationRelay(
        authentication_policy=_policy(ServiceRole.COORDINATOR),
        operator_policy=_policy(ServiceRole.API),
        creator=creator,
    )


def test_invocation_is_strict_canonical_and_bounds_forwarded_identity() -> None:
    invocation = _invocation()

    assert (
        decode_contract(canonical_json_bytes(invocation), RootCreationInvocationV1)
        == invocation
    )

    with pytest.raises(ValidationError):
        _invocation(operator_identity=API_IDENTITY)
    with pytest.raises(ValidationError):
        RootCreationInvocationV1.model_validate(
            {
                **invocation.model_dump(mode="python"),
                "operator_expires_at": invocation.operator_issued_at + 3_661,
            }
        )


def test_api_client_derives_operator_only_from_authentication_context() -> None:
    expected = _write_result().result
    transport = _Transport(canonical_json_bytes(expected))
    client = _api_client(transport)

    result = asyncio.run(client.create(_command(), _operator()))

    assert result == expected
    assert len(transport.calls) == 1
    route, body = transport.calls[0]
    assert route == _route()
    invocation = decode_contract(body, RootCreationInvocationV1)
    assert invocation.command == _command()
    assert invocation.operator_identity == OPERATOR_EMAIL
    assert invocation.operator_subject == OPERATOR_SUBJECT

    with pytest.raises(RootRelayError) as denied:
        asyncio.run(
            client.create(
                _command(),
                _operator(email="other.operator@example.test"),
            )
        )
    assert denied.value.code is RootRelayErrorCode.OPERATOR_DENIED
    assert len(transport.calls) == 1


def test_api_client_rejects_substituted_or_malformed_coordinator_result() -> None:
    substituted_command = _command(request_id="request-root-substituted")
    substituted = _Transport(
        canonical_json_bytes(_write_result(command=substituted_command).result)
    )
    with pytest.raises(RootRelayError) as wrong_winner:
        asyncio.run(_api_client(substituted).create(_command(), _operator()))
    assert wrong_winner.value.code is RootRelayErrorCode.RESPONSE_INVALID

    malformed = _Transport(b'{"schema_version":"controlgraph.root-creation-result/v1"}')
    with pytest.raises(RootRelayError) as invalid:
        asyncio.run(_api_client(malformed).create(_command(), _operator()))
    assert invalid.value.code is RootRelayErrorCode.RESPONSE_INVALID


def test_coordinator_reauthenticates_api_and_reconstructs_exact_operator() -> None:
    creator = _Creator()
    relay = _coordinator(creator)

    result = asyncio.run(relay.create(_invocation(), _api_caller()))

    assert result == creator.result.result
    assert creator.calls == [(_command(), _operator())]

    with pytest.raises(RootRelayError) as wrong_api:
        asyncio.run(
            relay.create(
                _invocation(),
                _api_caller(subject="999999999999999999999"),
            )
        )
    assert wrong_api.value.code is RootRelayErrorCode.CALLER_DENIED
    assert len(creator.calls) == 1

    with pytest.raises(RootRelayError) as wrong_operator:
        asyncio.run(
            relay.create(
                _invocation(operator_identity="other.operator@example.test"),
                _api_caller(),
            )
        )
    assert wrong_operator.value.code is RootRelayErrorCode.OPERATOR_DENIED
    assert len(creator.calls) == 1


def test_coordinator_maps_creator_failures_without_reflecting_details() -> None:
    creator = _Creator()
    relay = _coordinator(creator)
    creator.error = RootCreationError(RootCreationErrorCode.ACTIVE_CLAIM_CONFLICT)
    with pytest.raises(RootRelayError) as conflict:
        asyncio.run(relay.create(_invocation(), _api_caller()))
    assert conflict.value.code is RootRelayErrorCode.CREATION_CONFLICT

    marker = "unmistakably-synthetic-private-store-detail"
    creator.error = RuntimeError(marker)
    with pytest.raises(RootRelayError) as unavailable:
        asyncio.run(relay.create(_invocation(), _api_caller()))
    assert unavailable.value.code is RootRelayErrorCode.CREATION_UNAVAILABLE
    assert marker not in str(unavailable.value)


def test_api_http_route_accepts_only_public_command_fields() -> None:
    transport = _Transport(canonical_json_bytes(_write_result().result))
    policy = _policy(ServiceRole.API)
    authenticator = _Authenticator(policy, _operator())
    client = TestClient(
        create_service_app(
            ServiceRole.API,
            authenticator=authenticator,
            authentication_policy=policy,
            api_root_creation_client=_api_client(transport),
        )
    )

    response = client.post(
        protected_paths(ServiceRole.API)[0],
        content=canonical_json_bytes(_command()),
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 200
    assert decode_root_creation_result(response.content) == _write_result().result

    body = canonical_json_bytes(_command())[:-1] + (
        b',"operator_identity":"attacker@example.test"}'
    )
    denied = client.post(
        protected_paths(ServiceRole.API)[0],
        content=body,
        headers=OPERATOR_HEADERS,
    )
    assert denied.status_code == 400
    assert denied.json()["code"] == "CONTRACT_INVALID"
    assert len(transport.calls) == 1


def test_coordinator_http_route_returns_canonical_result_and_sanitized_denial() -> None:
    creator = _Creator()
    policy = _policy(ServiceRole.COORDINATOR)
    authenticator = _Authenticator(policy, _api_caller())
    client = TestClient(
        create_service_app(
            ServiceRole.COORDINATOR,
            authenticator=authenticator,
            authentication_policy=policy,
            coordinator_root_creation_relay=_coordinator(creator),
        )
    )

    response = client.post(
        protected_paths(ServiceRole.COORDINATOR)[0],
        content=canonical_json_bytes(_invocation()),
        headers={"Authorization": AUTHORIZATION},
    )
    assert response.status_code == 200
    assert response.content == canonical_json_bytes(creator.result.result)

    marker = "unmistakably-synthetic-private-creator-detail"
    creator.error = RuntimeError(marker)
    denied = client.post(
        protected_paths(ServiceRole.COORDINATOR)[0],
        content=canonical_json_bytes(_invocation()),
        headers={"Authorization": AUTHORIZATION},
    )
    assert denied.status_code == 503
    assert denied.json()["code"] == "ROOT_RELAY_CREATION_UNAVAILABLE"
    assert marker not in denied.text


def test_http_authentication_precedes_root_body_parsing() -> None:
    transport = _Transport(canonical_json_bytes(_write_result().result))
    policy = _policy(ServiceRole.API)
    authenticator = _Authenticator(policy, _operator())
    authenticator.error = AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)
    client = TestClient(
        create_service_app(
            ServiceRole.API,
            authenticator=authenticator,
            authentication_policy=policy,
            api_root_creation_client=_api_client(transport),
        )
    )

    marker = "unmistakably-synthetic-private-command"
    response = client.post(
        protected_paths(ServiceRole.API)[0],
        content=f'{{"payload":"{marker}"}}',
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_CREDENTIAL_INVALID"
    assert marker not in response.text
    assert transport.calls == []


def test_one_shot_transport_supports_only_exact_api_to_coordinator_route() -> None:
    class Tokens:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def token(self, audience: str) -> str:
            self.calls.append(audience)
            return "synthetic.oidc.token"

    class Poster:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []
            self.status = 200

        def post(self, **request: object) -> InternalHttpResponse:
            self.calls.append(request)
            return InternalHttpResponse(
                status_code=self.status,
                content_type="application/json",
                body=b"{}",
            )

    tokens = Tokens()
    poster = Poster()
    transport = GoogleOneShotOidcTransport(
        project_id=PROJECT,
        caller_role=CallerRole.API,
        token_provider=tokens,
        http_poster=poster,
        timeout_seconds=45.0,
    )

    assert asyncio.run(transport.post(_route(), b"{}")) == b"{}"
    assert tokens.calls == [COORDINATOR_AUDIENCE]
    assert len(poster.calls) == 1
    assert poster.calls[0]["url"] == (
        f"{COORDINATOR_AUDIENCE}/v1/internal/coordinate"
    )
    headers = cast(dict[str, str], poster.calls[0]["headers"])
    assert headers["Authorization"] == "Bearer synthetic.oidc.token"
    assert poster.calls[0]["timeout"] == 45.0

    poster.status = 307
    with pytest.raises(InternalTransportError):
        asyncio.run(transport.post(_route(), b"{}"))
    assert len(poster.calls) == 2

    with pytest.raises(ValueError):
        CoordinatorInternalRoute(
            project_id=PROJECT,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.API,
            service_role=ServiceRole.VERIFIER,
            audience=(
                f"https://controlgraph-verifier-{PROJECT_NUMBER}.us-central1.run.app"
            ),
        )


@pytest.mark.parametrize("timeout_seconds", [0.0, 45.1, float("inf"), float("nan")])
def test_one_shot_transport_rejects_unbounded_timeout(timeout_seconds: float) -> None:
    with pytest.raises(InternalTransportError):
        GoogleOneShotOidcTransport(
            project_id=PROJECT,
            caller_role=CallerRole.API,
            timeout_seconds=timeout_seconds,
        )


def test_relay_cancellation_propagates_without_a_second_attempt() -> None:
    transport = _Transport(canonical_json_bytes(_write_result().result))
    transport.error = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_api_client(transport).create(_command(), _operator()))
    assert len(transport.calls) == 1

    creator = _Creator()
    creator.error = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_coordinator(creator).create(_invocation(), _api_caller()))
    assert len(creator.calls) == 1


def test_invocation_signature_field_cannot_be_smuggled_into_public_command() -> None:
    encoded = encode_base64url(b"synthetic-signature")
    body = canonical_json_bytes(_command())[:-1] + (
        f',"signature":"{encoded}"}}'.encode()
    )
    with pytest.raises(ContractError):
        decode_contract(body, RootCreationCommandV1)
