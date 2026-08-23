from __future__ import annotations

from dataclasses import replace

import pytest

from controlgraph_canary.application.identity import (
    RECEIPT_AUTHORITY_PATH,
    RECOVERY_EXECUTION_FACADE_PATH,
    RECOVERY_RECEIPT_AUTHORITY_PATH,
    TIMELINE_RETENTION_PATH,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    expected_route_caller_role,
    protected_path,
    runtime_caller_emails,
    runtime_route_policy,
    runtime_service_name,
)

PROJECT_ID = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
OPERATOR_EMAIL = "operator@example.com"

EXPECTED_CALLERS = {
    CallerRole.OPERATOR: OPERATOR_EMAIL,
    CallerRole.API: f"controlgraph-api@{PROJECT_ID}.iam.gserviceaccount.com",
    CallerRole.COORDINATOR: f"controlgraph-coordinator@{PROJECT_ID}.iam.gserviceaccount.com",
    CallerRole.ISSUER: f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com",
    CallerRole.EXECUTOR: f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com",
    CallerRole.RECOVERY: f"controlgraph-recovery@{PROJECT_ID}.iam.gserviceaccount.com",
    CallerRole.VERIFIER: f"controlgraph-verifier@{PROJECT_ID}.iam.gserviceaccount.com",
    CallerRole.EVIDENCE_WRITER: f"cg-evidence-writer@{PROJECT_ID}.iam.gserviceaccount.com",
    CallerRole.EXECUTION_TASK_CALLER: (
        f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
    ),
    CallerRole.RECOVERY_TASK_CALLER: (
        f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
    ),
    CallerRole.RETENTION_SWEEPER: (f"cg-retention-sweeper@{PROJECT_ID}.iam.gserviceaccount.com"),
}

ROUTE_CALLERS = {
    ServiceRole.API: CallerRole.OPERATOR,
    ServiceRole.COORDINATOR: CallerRole.API,
    ServiceRole.ISSUER: CallerRole.COORDINATOR,
    ServiceRole.EXECUTOR: CallerRole.EXECUTION_TASK_CALLER,
    ServiceRole.RECOVERY: CallerRole.RECOVERY_TASK_CALLER,
    ServiceRole.VERIFIER: CallerRole.COORDINATOR,
    ServiceRole.EVIDENCE_WRITER: CallerRole.COORDINATOR,
}


def identity_environment(role: ServiceRole) -> dict[str, str]:
    caller_role = ROUTE_CALLERS[role]
    return {
        "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_ROLE": role.value,
        "CONTROLGRAPH_AUTH_AUDIENCE": (
            f"https://{runtime_service_name(role)}-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "CONTROLGRAPH_AUTH_CALLER_ROLE": caller_role.value,
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": EXPECTED_CALLERS[caller_role],
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": SUBJECT,
    }


def test_runtime_identity_map_is_exact_and_complete() -> None:
    assert runtime_caller_emails(PROJECT_ID, OPERATOR_EMAIL) == EXPECTED_CALLERS
    assert set(EXPECTED_CALLERS) == set(CallerRole)


@pytest.mark.parametrize("service_role", tuple(ServiceRole))
def test_each_protected_route_has_one_exact_caller_and_audience(
    service_role: ServiceRole,
) -> None:
    policy = runtime_route_policy(service_role, identity_environment(service_role))

    assert policy.service_role is service_role
    assert policy.path == protected_path(service_role)
    assert policy.audience == (
        f"https://{runtime_service_name(service_role)}-{PROJECT_NUMBER}.us-central1.run.app"
    )
    assert policy.caller.role is ROUTE_CALLERS[service_role]
    assert policy.caller.email == EXPECTED_CALLERS[ROUTE_CALLERS[service_role]]
    assert policy.caller.subject == SUBJECT
    assert expected_route_caller_role(service_role) is ROUTE_CALLERS[service_role]


def test_evidence_writer_identity_and_route_are_exact() -> None:
    assert runtime_service_name(ServiceRole.EVIDENCE_WRITER) == "controlgraph-evidence-writer"
    assert protected_path(ServiceRole.EVIDENCE_WRITER) == "/v1/internal/evidence/sign"
    assert (
        EXPECTED_CALLERS[CallerRole.EVIDENCE_WRITER]
        == f"cg-evidence-writer@{PROJECT_ID}.iam.gserviceaccount.com"
    )


@pytest.mark.parametrize(
    ("field", "substitute"),
    [
        ("CONTROLGRAPH_PROJECT_ID", "shared-project"),
        ("CONTROLGRAPH_PROJECT_ID", "reconcile-production"),
        ("CONTROLGRAPH_PROJECT_NUMBER", "012345678901"),
        ("CONTROLGRAPH_PROJECT_NUMBER", "project-number"),
        ("CONTROLGRAPH_REGION", "europe-west1"),
        ("CONTROLGRAPH_ROLE", "recovery"),
        (
            "CONTROLGRAPH_AUTH_AUDIENCE",
            f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app",
        ),
        (
            "CONTROLGRAPH_AUTH_AUDIENCE",
            "https://controlgraph-executor-999999999999.us-central1.run.app",
        ),
        ("CONTROLGRAPH_AUTH_CALLER_ROLE", "recovery_task_caller"),
        (
            "CONTROLGRAPH_AUTH_CALLER_EMAIL",
            f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com",
        ),
        ("CONTROLGRAPH_AUTH_CALLER_SUBJECT", "subject-selected-by-caller"),
    ],
)
def test_runtime_route_policy_rejects_coordinate_substitution(
    field: str,
    substitute: str,
) -> None:
    environment = identity_environment(ServiceRole.EXECUTOR)
    environment[field] = substitute

    with pytest.raises(ValueError):
        runtime_route_policy(ServiceRole.EXECUTOR, environment)


def test_route_policy_rejects_service_name_and_path_substitution() -> None:
    policy = runtime_route_policy(ServiceRole.EXECUTOR, identity_environment(ServiceRole.EXECUTOR))

    with pytest.raises(ValueError, match="path"):
        replace(policy, path="/v1/internal/tasks/recover")
    with pytest.raises(ValueError, match="audience"):
        replace(
            policy,
            audience=("https://controlgraph-executor-shadow-123456789012.us-central1.run.app"),
        )


@pytest.mark.parametrize(
    ("path", "caller_role"),
    [
        (RECEIPT_AUTHORITY_PATH, CallerRole.EXECUTOR),
        (RECOVERY_RECEIPT_AUTHORITY_PATH, CallerRole.EXECUTOR),
    ],
)
def test_receipt_authority_routes_bind_distinct_execution_callers(
    path: str,
    caller_role: CallerRole,
) -> None:
    policy = RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.COORDINATOR,
        path=path,
        audience=(f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"),
        caller=CallerBinding(
            role=caller_role,
            email=EXPECTED_CALLERS[caller_role],
            subject=SUBJECT,
        ),
    )

    assert policy.path == path
    assert policy.caller.role is caller_role


def test_timeline_retention_route_binds_only_the_sweeper_identity() -> None:
    policy = RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.COORDINATOR,
        path=TIMELINE_RETENTION_PATH,
        audience=(f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"),
        caller=CallerBinding(
            role=CallerRole.RETENTION_SWEEPER,
            email=EXPECTED_CALLERS[CallerRole.RETENTION_SWEEPER],
            subject=SUBJECT,
        ),
    )

    assert policy.path == TIMELINE_RETENTION_PATH
    with pytest.raises(ValueError, match="caller role"):
        replace(
            policy,
            caller=CallerBinding(
                role=CallerRole.API,
                email=EXPECTED_CALLERS[CallerRole.API],
                subject=SUBJECT,
            ),
        )


def test_recovery_cannot_use_either_executor_receipt_authority_route() -> None:
    with pytest.raises(ValueError, match="caller role"):
        RouteAuthenticationPolicy(
            project_id=PROJECT_ID,
            project_number=PROJECT_NUMBER,
            service_role=ServiceRole.COORDINATOR,
            path=RECEIPT_AUTHORITY_PATH,
            audience=(f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"),
            caller=CallerBinding(
                role=CallerRole.RECOVERY,
                email=EXPECTED_CALLERS[CallerRole.RECOVERY],
                subject=SUBJECT,
            ),
        )

    with pytest.raises(ValueError, match="caller role"):
        RouteAuthenticationPolicy(
            project_id=PROJECT_ID,
            project_number=PROJECT_NUMBER,
            service_role=ServiceRole.COORDINATOR,
            path=RECOVERY_RECEIPT_AUTHORITY_PATH,
            audience=(f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"),
            caller=CallerBinding(
                role=CallerRole.RECOVERY,
                email=EXPECTED_CALLERS[CallerRole.RECOVERY],
                subject=SUBJECT,
            ),
        )


def test_recovery_executor_facade_has_one_exact_caller_and_path() -> None:
    policy = RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EXECUTOR,
        path=RECOVERY_EXECUTION_FACADE_PATH,
        audience=(f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"),
        caller=CallerBinding(
            role=CallerRole.RECOVERY,
            email=EXPECTED_CALLERS[CallerRole.RECOVERY],
            subject=SUBJECT,
        ),
    )

    assert policy.path == RECOVERY_EXECUTION_FACADE_PATH
    assert policy.caller.role is CallerRole.RECOVERY

    with pytest.raises(ValueError, match="caller role"):
        replace(
            policy,
            caller=CallerBinding(
                role=CallerRole.EXECUTION_TASK_CALLER,
                email=EXPECTED_CALLERS[CallerRole.EXECUTION_TASK_CALLER],
                subject=SUBJECT,
            ),
        )


@pytest.mark.parametrize(
    ("project_id", "operator_email"),
    [
        ("shared-project", OPERATOR_EMAIL),
        (PROJECT_ID, f"controlgraph-api@{PROJECT_ID}.iam.gserviceaccount.com"),
        (PROJECT_ID, "Operator@Example.com"),
    ],
)
def test_runtime_caller_map_rejects_unbounded_identity_configuration(
    project_id: str,
    operator_email: str,
) -> None:
    with pytest.raises(ValueError):
        runtime_caller_emails(project_id, operator_email)


def test_authentication_errors_expose_only_the_stable_denial_code() -> None:
    sensitive_marker = "unmistakably-synthetic-bearer-token"
    error = AuthenticationError(AuthenticationDenialCode.CREDENTIAL_INVALID)

    assert str(error) == "AUTH_CREDENTIAL_INVALID"
    assert sensitive_marker not in str(error)
    assert sensitive_marker not in repr(error)


def test_caller_binding_rejects_non_google_subjects() -> None:
    with pytest.raises(ValueError, match="subject"):
        CallerBinding(
            role=CallerRole.COORDINATOR,
            email=EXPECTED_CALLERS[CallerRole.COORDINATOR],
            subject="caller-chosen-subject",
        )


def test_route_policy_rejects_an_unrelated_cloud_run_origin() -> None:
    with pytest.raises(ValueError, match="audience"):
        RouteAuthenticationPolicy(
            project_id=PROJECT_ID,
            project_number=PROJECT_NUMBER,
            service_role=ServiceRole.ISSUER,
            path=protected_path(ServiceRole.ISSUER),
            audience="https://reconcile-issuer-123456789012.us-central1.run.app",
            caller=CallerBinding(
                role=CallerRole.COORDINATOR,
                email=EXPECTED_CALLERS[CallerRole.COORDINATOR],
                subject=SUBJECT,
            ),
        )
