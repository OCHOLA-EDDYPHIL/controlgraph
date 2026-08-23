from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

from fastapi.testclient import TestClient
from model_assistance_test_data import (
    ADVISOR_AUDIENCE,
    PROJECT_ID,
    PROJECT_NUMBER,
    SUBJECT,
    authentication_context,
    authentication_policy,
    invocation,
    recommendation,
    target,
    verified_evidence_reader,
)

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.model_assistance import (
    AdvisorAuditWriteResult,
    AdvisorDispositionWriteResult,
    ApiAdvisorClient,
    CoordinatorAdvisorClient,
    CoordinatorAdvisorWorkflow,
    InvocationDiagnosticRegistry,
    ReadOnlyAdvisorService,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.timeline_projectors import project_model_assistance
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.model_assistance import (
    ADVISOR_DISPOSITION_COMMAND_V1,
    ADVISOR_DISPOSITION_INVOCATION_V1,
    ADVISOR_DISPOSITION_RESULT_V1,
    ADVISOR_OPERATOR_COMMAND_V1,
    ADVISOR_OPERATOR_INVOCATION_V1,
    AdvisorDispositionCommandV1,
    AdvisorDispositionInvocationV1,
    AdvisorDispositionResultV1,
    AdvisorInvocationRequestV1,
    AdvisorOperatorCommandV1,
    AdvisorOperatorInvocationV1,
    AdvisorOperatorResultV1,
    AdvisorRecommendationV1,
    AdvisorResponseV1,
    ModelAssistanceLifecycle,
    ModelAssistanceTimelineAuditV1,
    OperatorDisposition,
)
from controlgraph_canary.contracts.timeline import (
    TimelineActorRole,
    TimelineEventType,
    standard_timeline_evidence_policy_set,
)
from controlgraph_canary.http.service import create_service_app

NOW = datetime(2026, 8, 22, 10, 1, tzinfo=UTC)
API_AUDIENCE = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
COORDINATOR_AUDIENCE = (
    f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
)


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
        for definition in tools.registry.tools:
            await tools.read(definition.tool_id, request.snapshot_sha256)
        return recommendation(request)


class _AdvisorTransport:
    def __init__(self, response: AdvisorResponseV1) -> None:
        self.response = response
        self.calls = 0

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        del route, body
        self.calls += 1
        return canonical_json_bytes(self.response)


class _Assembler:
    async def assemble(self, command: AdvisorOperatorCommandV1) -> AdvisorInvocationRequestV1:
        result = invocation()
        assert result.correlation_id == command.request_id
        assert result.requested_at == command.requested_at
        return result


class _AuditStore:
    def __init__(self) -> None:
        self.responses: dict[str, AdvisorOperatorResultV1] = {}
        self.dispositions: dict[str, OperatorDisposition] = {}

    async def read_response(self, idempotency_key: str) -> AdvisorOperatorResultV1 | None:
        return self.responses.get(idempotency_key)

    async def write_response_if_absent(
        self,
        idempotency_key: str,
        result: AdvisorOperatorResultV1,
    ) -> AdvisorAuditWriteResult:
        winner = self.responses.setdefault(idempotency_key, result)
        return AdvisorAuditWriteResult(result=winner, created=winner is result)

    async def write_disposition(
        self,
        command: AdvisorDispositionCommandV1,
    ) -> AdvisorDispositionWriteResult:
        interaction = next(
            value
            for value in self.responses.values()
            if value.interaction_id == command.interaction_id
        )
        assert canonical_sha256(interaction.response) == command.expected_response_sha256
        created = command.interaction_id not in self.dispositions
        previous = self.dispositions.setdefault(command.interaction_id, command.disposition)
        if previous is not command.disposition:
            raise ValueError("conflicting disposition")
        result = AdvisorDispositionResultV1(
            schema_version=ADVISOR_DISPOSITION_RESULT_V1,
            command_sha256=canonical_sha256(command),
            interaction_id=interaction.interaction_id,
            response_sha256=canonical_sha256(interaction.response),
            disposition=previous,
            replayed=not created,
        )
        return AdvisorDispositionWriteResult(
            interaction=interaction,
            result=result,
            created=created,
        )


class _Timeline:
    def __init__(self) -> None:
        self.events: list[ModelAssistanceTimelineAuditV1] = []

    async def record_model_assistance(
        self,
        event: ModelAssistanceTimelineAuditV1,
    ) -> None:
        self.events.append(event)


class _Authenticator:
    def __init__(self, context: AuthenticationContext) -> None:
        self.context = context

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        del policy
        if authorization_header not in {
            "Bearer valid-synthetic-token",
            "Bearer synthetic.header.signature",
        }:
            raise AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)
        return self.context


class _CoordinatorTransport:
    def __init__(
        self,
        workflow: CoordinatorAdvisorWorkflow,
        caller: AuthenticationContext,
    ) -> None:
        self.workflow = workflow
        self.caller = caller

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        del route
        request = decode_contract(body, AdvisorOperatorInvocationV1)
        result = await self.workflow.advise(request, self.caller)
        return canonical_json_bytes(result)


def _operator_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.API,
        path=protected_path(ServiceRole.API),
        audience=API_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.OPERATOR,
            email="operator@example.com",
            subject=SUBJECT,
        ),
    )


def _coordinator_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.COORDINATOR,
        path=protected_path(ServiceRole.COORDINATOR),
        audience=COORDINATOR_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.API,
            email=f"controlgraph-api@{PROJECT_ID}.iam.gserviceaccount.com",
            subject=SUBJECT,
        ),
    )


def _operator_context() -> AuthenticationContext:
    policy = _operator_policy()
    return AuthenticationContext(
        role=CallerRole.OPERATOR,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=1_776_500_000,
        expires_at=1_776_500_600,
    )


def _api_context() -> AuthenticationContext:
    policy = _coordinator_policy()
    return AuthenticationContext(
        role=CallerRole.API,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=1_776_500_000,
        expires_at=1_776_500_600,
    )


def _command() -> AdvisorOperatorCommandV1:
    request = invocation()
    return AdvisorOperatorCommandV1(
        schema_version=ADVISOR_OPERATOR_COMMAND_V1,
        request_id=request.correlation_id,
        idempotency_key="advisor-request-1",
        target=target(),
        root_id=request.snapshot.root_id,
        expected_root_sha256=request.snapshot.root_sha256,
        expected_epoch=request.snapshot.current_epoch,
        requested_at=request.requested_at,
    )


def _workflow() -> tuple[CoordinatorAdvisorWorkflow, _AuditStore, _Timeline, _AdvisorTransport]:
    request = invocation()
    response = asyncio.run(
        ReadOnlyAdvisorService(
            authentication_policy=authentication_policy(),
            model=_Model(),
            evidence_reader=verified_evidence_reader(),
            clock=lambda: NOW,
        ).advise(request, authentication_context())
    )
    advisor_transport = _AdvisorTransport(response)
    advisor_client = CoordinatorAdvisorClient(
        route=CoordinatorInternalRoute(
            project_id=PROJECT_ID,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.COORDINATOR,
            service_role=ServiceRole.ADVISOR,
            audience=ADVISOR_AUDIENCE,
        ),
        transport=advisor_transport,
    )
    store = _AuditStore()
    timeline = _Timeline()
    workflow = CoordinatorAdvisorWorkflow(
        authentication_policy=_coordinator_policy(),
        operator_policy=_operator_policy(),
        assembler=_Assembler(),
        advisor=advisor_client,
        audit_store=store,
        timeline=timeline,
    )
    return workflow, store, timeline, advisor_transport


def _operator_invocation(command: AdvisorOperatorCommandV1) -> AdvisorOperatorInvocationV1:
    principal = _operator_context()
    return AdvisorOperatorInvocationV1(
        schema_version=ADVISOR_OPERATOR_INVOCATION_V1,
        command=command,
        operator_identity=principal.email,
        operator_subject=principal.subject,
        operator_issuer="https://accounts.google.com",
        operator_audience=principal.audience,
        operator_issued_at=principal.issued_at,
        operator_expires_at=principal.expires_at,
    )


def test_coordinator_persists_redacted_interaction_and_replays_without_model_call() -> None:
    workflow, _, timeline, advisor_transport = _workflow()
    request = _operator_invocation(_command())

    first = asyncio.run(workflow.advise(request, _api_context()))
    replay = asyncio.run(workflow.advise(request, _api_context()))

    assert first.replayed is False
    assert replay.replayed is True
    assert first.response == replay.response
    assert advisor_transport.calls == 1
    assert tuple(event.lifecycle for event in timeline.events) == (
        ModelAssistanceLifecycle.COMPLETED,
        ModelAssistanceLifecycle.COMPLETED,
        ModelAssistanceLifecycle.REPLAYED,
    )
    assert timeline.events[0].event_id == timeline.events[1].event_id
    serialized = "".join(event.model_dump_json() for event in timeline.events)
    assert "capability" not in serialized.lower()
    assert "Bearer" not in serialized
    assert "operator@example.com" not in serialized
    projected = project_model_assistance(
        timeline.events[0],
        policy_set=standard_timeline_evidence_policy_set(first.target),
    )
    assert projected.event.event_type is TimelineEventType.MODEL_ASSISTANCE_RECORDED
    assert projected.event.actor_role is TimelineActorRole.ADVISOR


def test_disposition_is_compare_and_set_and_audits_replay() -> None:
    workflow, _, timeline, _ = _workflow()
    interaction = asyncio.run(
        workflow.advise(_operator_invocation(_command()), _api_context())
    )
    command = AdvisorDispositionCommandV1(
        schema_version=ADVISOR_DISPOSITION_COMMAND_V1,
        request_id="disposition-request-1",
        idempotency_key="disposition-1",
        target=interaction.target,
        root_id=interaction.root_id,
        expected_root_sha256=interaction.root_sha256,
        expected_epoch=interaction.epoch,
        interaction_id=interaction.interaction_id,
        expected_response_sha256=canonical_sha256(interaction.response),
        disposition=OperatorDisposition.REJECTED,
        recorded_at="2026-08-22T10:02:00Z",
    )
    principal = _operator_context()
    invocation_value = AdvisorDispositionInvocationV1(
        schema_version=ADVISOR_DISPOSITION_INVOCATION_V1,
        command=command,
        operator_identity=principal.email,
        operator_subject=principal.subject,
        operator_issuer="https://accounts.google.com",
        operator_audience=principal.audience,
        operator_issued_at=principal.issued_at,
        operator_expires_at=principal.expires_at,
    )

    first = asyncio.run(workflow.record_disposition(invocation_value, _api_context()))
    replay = asyncio.run(workflow.record_disposition(invocation_value, _api_context()))

    assert first.replayed is False
    assert replay.replayed is True
    assert tuple(event.lifecycle for event in timeline.events[-2:]) == (
        ModelAssistanceLifecycle.DISPOSITION_RECORDED,
        ModelAssistanceLifecycle.DISPOSITION_REPLAYED,
    )


def test_authenticated_operator_route_invokes_the_coordinator_workflow() -> None:
    workflow, _, _, _ = _workflow()
    api_client = ApiAdvisorClient(
        route=CoordinatorInternalRoute(
            project_id=PROJECT_ID,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.API,
            service_role=ServiceRole.COORDINATOR,
            audience=COORDINATOR_AUDIENCE,
        ),
        authentication_policy=_operator_policy(),
        transport=_CoordinatorTransport(workflow, _api_context()),
    )
    app = create_service_app(
        ServiceRole.API,
        authenticator=_Authenticator(_operator_context()),
        authentication_policy=_operator_policy(),
        api_advisor_client=api_client,
    )

    response = TestClient(app).post(
        protected_path(ServiceRole.API),
        content=canonical_json_bytes(_command()),
        headers={
            "X-ControlGraph-Authorization": "Bearer synthetic.header.signature",
            "X-Serverless-Authorization": (
                "bearer synthetic.header.SIGNATURE_REMOVED_BY_GOOGLE"
            ),
        },
    )

    assert response.status_code == 200
    result = decode_contract(response.content, AdvisorOperatorResultV1)
    assert result.response.audit.validation.accepted is True


def test_authenticated_coordinator_route_invokes_the_workflow_service() -> None:
    workflow, _, _, _ = _workflow()
    app = create_service_app(
        ServiceRole.COORDINATOR,
        authenticator=_Authenticator(_api_context()),
        authentication_policy=_coordinator_policy(),
        coordinator_advisor_workflow=workflow,
    )

    response = TestClient(app).post(
        protected_path(ServiceRole.COORDINATOR),
        content=canonical_json_bytes(_operator_invocation(_command())),
        headers={"Authorization": "Bearer valid-synthetic-token"},
    )

    assert response.status_code == 200
    assert decode_contract(response.content, AdvisorOperatorResultV1).replayed is False
