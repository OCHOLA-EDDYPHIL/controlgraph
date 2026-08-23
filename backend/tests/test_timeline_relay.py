from __future__ import annotations

import asyncio

import pytest

from controlgraph_canary.application.identity import (
    TIMELINE_RAW_EXPORT_PATH,
    TIMELINE_READ_PATH,
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.timeline import (
    TimelineRawExportError,
    TimelineRawExportService,
    TimelineRawReadSlice,
    TimelineReadError,
    TimelineReadService,
    TimelineReadSlice,
)
from controlgraph_canary.application.timeline_relay import (
    ApiTimelineClient,
    CoordinatorTimelineRelay,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.timeline import (
    TIMELINE_PAGE_COMMAND_V1,
    TIMELINE_PAGE_V1,
    TIMELINE_RAW_EXPORT_COMMAND_V1,
    TIMELINE_RAW_EXPORT_V1,
    TimelineAudience,
    TimelinePageCommandV1,
    TimelinePageV1,
    TimelineRawExportCommandV1,
    TimelineRawExportV1,
)
from controlgraph_canary.contracts.timeline_relay import (
    TimelineRawExportInvocationV1,
    TimelineReadInvocationV1,
)

PROJECT_NUMBER = "123456789012"
TARGET = TargetBinding(
    schema_version="controlgraph.target-binding/v1",
    project_id="controlgraph-canary-a1b2c3",
    region="us-central1",
    environment="nonprod",
    service_name="controlgraph-reference-target",
)
API_AUDIENCE = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
COORDINATOR_AUDIENCE = (
    f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
)


def _policy(
    path: str,
    email: str,
    subject: str,
    role: CallerRole,
) -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=TARGET.project_id,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.API,
        path=path,
        audience=API_AUDIENCE,
        caller=CallerBinding(
            role=role,
            email=email,
            subject=subject,
        ),
    )


OPERATOR_POLICY = _policy(
    TIMELINE_READ_PATH,
    "operator@example.com",
    "123456789012",
    CallerRole.OPERATOR,
)
SECURITY_POLICY = _policy(
    TIMELINE_READ_PATH,
    f"cg-security-auditor@{TARGET.project_id}.iam.gserviceaccount.com",
    "223456789012",
    CallerRole.SECURITY_AUDITOR,
)
EXPORT_POLICY = _policy(
    TIMELINE_RAW_EXPORT_PATH,
    f"cg-restricted-exporter@{TARGET.project_id}.iam.gserviceaccount.com",
    "323456789012",
    CallerRole.RESTRICTED_EXPORTER,
)


def _context(policy: RouteAuthenticationPolicy) -> AuthenticationContext:
    return AuthenticationContext(
        role=policy.caller.role,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=1_776_236_400,
        expires_at=1_776_237_000,
    )


def _page_command(audience: TimelineAudience) -> TimelinePageCommandV1:
    return TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=10,
        audience=audience,
    )


def _raw_command() -> TimelineRawExportCommandV1:
    return TimelineRawExportCommandV1(
        schema_version=TIMELINE_RAW_EXPORT_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=10,
    )


def _page(command: TimelinePageCommandV1) -> TimelinePageV1:
    from controlgraph_canary.contracts.codec import canonical_sha256

    return TimelinePageV1(
        schema_version=TIMELINE_PAGE_V1,
        command=command,
        command_sha256=canonical_sha256(command),
        entries=(),
        next_after_sequence=0,
        next_after_entry_sha256=None,
        head_sequence=0,
        head_entry_sha256=None,
        has_more=False,
    )


def _export(command: TimelineRawExportCommandV1) -> TimelineRawExportV1:
    from controlgraph_canary.contracts.codec import canonical_sha256

    return TimelineRawExportV1(
        schema_version=TIMELINE_RAW_EXPORT_V1,
        command=command,
        command_sha256=canonical_sha256(command),
        evaluated_at="2026-08-21T12:00:00Z",
        entries=(),
        next_after_sequence=0,
        next_after_entry_sha256=None,
        head_sequence=0,
        head_entry_sha256=None,
        has_more=False,
    )


class _Transport:
    def __init__(self, response: TimelinePageV1 | TimelineRawExportV1) -> None:
        self.response = response
        self.calls: list[bytes] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        assert route.service_role is ServiceRole.COORDINATOR
        self.calls.append(body)
        return canonical_json_bytes(self.response)


def _api_client(transport: _Transport) -> ApiTimelineClient:
    return ApiTimelineClient(
        target=TARGET,
        route=CoordinatorInternalRoute(
            project_id=TARGET.project_id,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.API,
            service_role=ServiceRole.COORDINATOR,
            audience=COORDINATOR_AUDIENCE,
        ),
        operator_policy=OPERATOR_POLICY,
        security_audit_policy=SECURITY_POLICY,
        restricted_export_policy=EXPORT_POLICY,
        transport=transport,
    )


def test_api_relay_separates_operator_audit_and_export_identities() -> None:
    security_command = _page_command(TimelineAudience.SECURITY_AUDIT)
    transport = _Transport(_page(security_command))
    client = _api_client(transport)

    with pytest.raises(TimelineReadError):
        asyncio.run(client.read(security_command, _context(OPERATOR_POLICY)))
    page = asyncio.run(client.read(security_command, _context(SECURITY_POLICY)))

    assert page.command == security_command
    invocation = decode_contract(transport.calls[0], TimelineReadInvocationV1)
    assert invocation.reader.email == SECURITY_POLICY.caller.email

    raw_command = _raw_command()
    raw_transport = _Transport(_export(raw_command))
    raw_client = _api_client(raw_transport)
    with pytest.raises(TimelineRawExportError):
        asyncio.run(raw_client.export(raw_command, _context(OPERATOR_POLICY)))
    exported = asyncio.run(raw_client.export(raw_command, _context(EXPORT_POLICY)))

    assert exported.command == raw_command
    raw_invocation = decode_contract(
        raw_transport.calls[0],
        TimelineRawExportInvocationV1,
    )
    assert raw_invocation.reader.email == EXPORT_POLICY.caller.email


class _Store:
    @property
    def target(self):  # type: ignore[no-untyped-def]
        return TARGET

    async def append(self, event):  # type: ignore[no-untyped-def]
        raise AssertionError(event)

    async def append_with_raw(self, event, raw_source):  # type: ignore[no-untyped-def]
        raise AssertionError((event, raw_source))

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice:
        return TimelineReadSlice(command=command, head=None, entries=())

    async def read_raw_export(
        self,
        command: TimelineRawExportCommandV1,
    ) -> TimelineRawReadSlice:
        return TimelineRawReadSlice(
            command=command,
            head=None,
            entries=(),
            raw_evidence=(),
            deletion_receipts=(),
            evaluated_at="2026-08-21T12:00:00Z",
        )


def _api_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=TARGET.project_id,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.COORDINATOR,
        path=protected_path(ServiceRole.COORDINATOR),
        audience=COORDINATOR_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.API,
            email=f"controlgraph-api@{TARGET.project_id}.iam.gserviceaccount.com",
            subject="423456789012",
        ),
    )


def _api_context() -> AuthenticationContext:
    policy = _api_policy()
    return AuthenticationContext(
        role=CallerRole.API,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=1_776_236_400,
        expires_at=1_776_237_000,
    )


def test_coordinator_reauthorizes_forwarded_reader_before_store_access() -> None:
    store = _Store()
    relay = CoordinatorTimelineRelay(
        authentication_policy=_api_policy(),
        operator_policy=OPERATOR_POLICY,
        security_audit_policy=SECURITY_POLICY,
        restricted_export_policy=EXPORT_POLICY,
        read_service=TimelineReadService(target=TARGET, store=store),
        raw_export_service=TimelineRawExportService(target=TARGET, store=store),
    )
    command = _page_command(TimelineAudience.SECURITY_AUDIT)
    denied = TimelineReadInvocationV1.model_validate(
        {
            "schema_version": "controlgraph.timeline-read-invocation/v1",
            "command": command,
            "reader": {
                "email": OPERATOR_POLICY.caller.email,
                "subject": OPERATOR_POLICY.caller.subject,
                "issuer": "accounts.google.com",
                "audience": API_AUDIENCE,
                "issued_at": 1_776_236_400,
                "expires_at": 1_776_237_000,
            },
        }
    )

    with pytest.raises(TimelineReadError):
        asyncio.run(relay.read(denied, _api_context()))
