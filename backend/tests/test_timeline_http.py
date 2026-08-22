from __future__ import annotations

from fastapi.testclient import TestClient
from timeline_test_data import TARGET

from controlgraph_canary.application.identity import (
    TIMELINE_RAW_EXPORT_PATH,
    TIMELINE_READ_PATH,
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.timeline import (
    TimelineRawExportService,
    TimelineRawReadSlice,
    TimelineReadService,
    TimelineReadSlice,
)
from controlgraph_canary.contracts.timeline import (
    TimelineEventV1,
    TimelinePageCommandV1,
    TimelineRawExportCommandV1,
    TimelineRawSourceV1,
)
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.http.service import create_service_app

PROJECT_NUMBER = "123456789012"
OPERATOR_EMAIL = "operator@example.com"
OPERATOR_SUBJECT = "123456789012345678901"
SECURITY_EMAIL = "security@example.com"
SECURITY_SUBJECT = "223456789012345678901"
EXPORTER_EMAIL = "exporter@example.com"
EXPORTER_SUBJECT = "323456789012345678901"
AUDIENCE = (
    f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
)
FULL_TOKEN = "Bearer header.payload.signature"
OPERATOR_HEADERS = {
    CONTROLGRAPH_AUTHORIZATION_HEADER: FULL_TOKEN,
    SERVERLESS_AUTHORIZATION_HEADER: (
        "bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE"
    ),
}
SECURITY_TOKEN = "Bearer security.payload.signature"
SECURITY_HEADERS = {
    CONTROLGRAPH_AUTHORIZATION_HEADER: SECURITY_TOKEN,
    SERVERLESS_AUTHORIZATION_HEADER: (
        "bearer security.payload.SIGNATURE_REMOVED_BY_GOOGLE"
    ),
}
EXPORT_TOKEN = "Bearer exporter.payload.signature"
EXPORT_HEADERS = {
    CONTROLGRAPH_AUTHORIZATION_HEADER: EXPORT_TOKEN,
    SERVERLESS_AUTHORIZATION_HEADER: (
        "bearer exporter.payload.SIGNATURE_REMOVED_BY_GOOGLE"
    ),
}


def _policy(
    path: str,
    *,
    email: str = OPERATOR_EMAIL,
    subject: str = OPERATOR_SUBJECT,
) -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=TARGET.project_id,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.API,
        path=path,
        audience=AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.OPERATOR,
            email=email,
            subject=subject,
        ),
    )


class _Authenticator:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        identities = {
            FULL_TOKEN: (OPERATOR_EMAIL, OPERATOR_SUBJECT),
            SECURITY_TOKEN: (SECURITY_EMAIL, SECURITY_SUBJECT),
            EXPORT_TOKEN: (EXPORTER_EMAIL, EXPORTER_SUBJECT),
        }
        identity = identities.get(authorization_header or "")
        if identity != (policy.caller.email, policy.caller.subject):
            raise AuthenticationError(AuthenticationDenialCode.CALLER_DENIED)
        self.paths.append(policy.path)
        return AuthenticationContext(
            role=CallerRole.OPERATOR,
            email=identity[0],
            subject=identity[1],
            issuer="accounts.google.com",
            audience=AUDIENCE,
            issued_at=1_700_000_000,
            expires_at=1_700_003_600,
        )


class _TimelineStore:
    def __init__(self) -> None:
        self.page_commands: list[TimelinePageCommandV1] = []
        self.raw_commands: list[TimelineRawExportCommandV1] = []

    @property
    def target(self):  # type: ignore[no-untyped-def]
        return TARGET

    async def append(self, event: TimelineEventV1):  # type: ignore[no-untyped-def]
        del event
        raise AssertionError("timeline GET must not append")

    async def append_with_raw(
        self,
        event: TimelineEventV1,
        raw_source: TimelineRawSourceV1,
    ):  # type: ignore[no-untyped-def]
        del event, raw_source
        raise AssertionError("timeline GET must not append")

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice:
        self.page_commands.append(command)
        return TimelineReadSlice(command=command, head=None, entries=())

    async def read_raw_export(
        self,
        command: TimelineRawExportCommandV1,
    ) -> TimelineRawReadSlice:
        self.raw_commands.append(command)
        return TimelineRawReadSlice(
            command=command,
            head=None,
            entries=(),
            raw_evidence=(),
            deletion_receipts=(),
            evaluated_at="2026-08-21T12:00:00Z",
        )


def _client() -> tuple[TestClient, _Authenticator, _TimelineStore]:
    authenticator = _Authenticator()
    store = _TimelineStore()
    app = create_service_app(
        ServiceRole.API,
        authenticator=authenticator,
        authentication_policy=_policy(protected_path(ServiceRole.API)),
        timeline_read_service=TimelineReadService(target=TARGET, store=store),
        timeline_read_authentication_policy=_policy(TIMELINE_READ_PATH),
        timeline_security_read_authentication_policy=_policy(
            TIMELINE_READ_PATH,
            email=SECURITY_EMAIL,
            subject=SECURITY_SUBJECT,
        ),
        timeline_raw_export_service=TimelineRawExportService(target=TARGET, store=store),
        timeline_raw_export_authentication_policy=_policy(
            TIMELINE_RAW_EXPORT_PATH,
            email=EXPORTER_EMAIL,
            subject=EXPORTER_SUBJECT,
        ),
    )
    return TestClient(app), authenticator, store


def test_timeline_get_authenticates_dual_header_and_injects_exact_target() -> None:
    client, authenticator, store = _client()

    response = client.get(
        f"{TIMELINE_READ_PATH}?limit=7&audience=PUBLIC_DEMO",
        headers=OPERATOR_HEADERS,
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["command"]["target"] == TARGET.model_dump(mode="json")
    assert response.json()["command"]["audience"] == "PUBLIC_DEMO"
    assert store.page_commands[0].target == TARGET
    assert store.page_commands[0].limit == 7
    assert authenticator.paths == [TIMELINE_READ_PATH]


def test_timeline_get_rejects_target_override_ambiguous_cursor_and_elevation() -> None:
    client, _, store = _client()

    target_override = client.get(
        f"{TIMELINE_READ_PATH}?target=another",
        headers=OPERATOR_HEADERS,
    )
    duplicate = client.get(
        f"{TIMELINE_READ_PATH}?limit=1&limit=2",
        headers=OPERATOR_HEADERS,
    )
    incomplete_cursor = client.get(
        f"{TIMELINE_READ_PATH}?after_sequence=1",
        headers=OPERATOR_HEADERS,
    )
    elevated = client.get(
        f"{TIMELINE_READ_PATH}?audience=RESTRICTED",
        headers=OPERATOR_HEADERS,
    )
    audit_denied = client.get(
        f"{TIMELINE_READ_PATH}?audience=SECURITY_AUDIT",
        headers=OPERATOR_HEADERS,
    )
    audit_accepted = client.get(
        f"{TIMELINE_READ_PATH}?audience=SECURITY_AUDIT",
        headers=SECURITY_HEADERS,
    )

    assert target_override.status_code == 400
    assert duplicate.status_code == 400
    assert incomplete_cursor.status_code == 400
    assert elevated.status_code == 403
    assert audit_denied.status_code == 403
    assert audit_accepted.status_code == 200
    assert [item.audience.value for item in store.page_commands] == ["SECURITY_AUDIT"]


def test_timeline_get_rejects_incomplete_operator_identity_envelope() -> None:
    client, _, store = _client()

    response = client.get(
        TIMELINE_READ_PATH,
        headers={CONTROLGRAPH_AUTHORIZATION_HEADER: FULL_TOKEN},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_CREDENTIAL_MALFORMED"
    assert store.page_commands == []


def test_raw_export_requires_separate_confirmation_and_is_no_store() -> None:
    client, authenticator, store = _client()

    denied = client.get(
        TIMELINE_RAW_EXPORT_PATH,
        headers={
            **OPERATOR_HEADERS,
            "X-ControlGraph-Raw-Export": "EXPORT_RESTRICTED_EVIDENCE_V1",
        },
    )
    unconfirmed = client.get(TIMELINE_RAW_EXPORT_PATH, headers=EXPORT_HEADERS)
    accepted = client.get(
        TIMELINE_RAW_EXPORT_PATH,
        headers={
            **EXPORT_HEADERS,
            "X-ControlGraph-Raw-Export": "EXPORT_RESTRICTED_EVIDENCE_V1",
        },
    )

    assert denied.status_code == 403
    assert denied.json()["code"] == "AUTH_CALLER_DENIED"
    assert unconfirmed.status_code == 403
    assert unconfirmed.json()["code"] == "TIMELINE_RAW_EXPORT_ACCESS_DENIED"
    assert accepted.status_code == 200
    assert accepted.headers["cache-control"] == "no-store"
    assert accepted.json()["command"]["target"] == TARGET.model_dump(mode="json")
    assert len(store.raw_commands) == 1
    assert store.raw_commands[0].target == TARGET
    assert authenticator.paths == [TIMELINE_RAW_EXPORT_PATH, TIMELINE_RAW_EXPORT_PATH]
