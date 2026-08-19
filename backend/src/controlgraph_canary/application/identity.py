"""Exact workload identity policy for protected ControlGraph routes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from controlgraph_canary.application.tasks import (
    EXECUTION_HANDLER_PATH,
    RECOVERY_HANDLER_PATH,
)

IDENTITY_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_AUTH_AUDIENCE",
    "CONTROLGRAPH_AUTH_CALLER_EMAIL",
    "CONTROLGRAPH_AUTH_CALLER_ROLE",
    "CONTROLGRAPH_AUTH_CALLER_SUBJECT",
)

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_PROJECT_NUMBER = re.compile(r"^[1-9][0-9]{5,31}$")
_GOOGLE_SUBJECT = re.compile(r"^[1-9][0-9]{5,31}$")
_EMAIL = re.compile(r"^[a-z0-9][a-z0-9._%+\-]{0,63}@[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$")


class ServiceRole(StrEnum):
    """Private services with one closed protected route each."""

    API = "api"
    COORDINATOR = "coordinator"
    ISSUER = "issuer"
    EXECUTOR = "executor"
    RECOVERY = "recovery"
    VERIFIER = "verifier"
    EVIDENCE_WRITER = "evidence_writer"


class CallerRole(StrEnum):
    """Every identity that may participate in the runtime control path."""

    OPERATOR = "operator"
    API = "api"
    COORDINATOR = "coordinator"
    ISSUER = "issuer"
    EXECUTOR = "executor"
    RECOVERY = "recovery"
    VERIFIER = "verifier"
    EVIDENCE_WRITER = "evidence_writer"
    EXECUTION_TASK_CALLER = "execution_task_caller"
    RECOVERY_TASK_CALLER = "recovery_task_caller"


class AuthenticationDenialCode(StrEnum):
    """Stable denial reasons that never contain credential material."""

    CONFIGURATION_INVALID = "AUTH_CONFIGURATION_INVALID"
    CREDENTIAL_MISSING = "AUTH_CREDENTIAL_MISSING"
    CREDENTIAL_MALFORMED = "AUTH_CREDENTIAL_MALFORMED"
    CREDENTIAL_INVALID = "AUTH_CREDENTIAL_INVALID"
    ISSUER_DENIED = "AUTH_ISSUER_DENIED"
    AUDIENCE_DENIED = "AUTH_AUDIENCE_DENIED"
    CALLER_DENIED = "AUTH_CALLER_DENIED"
    TOKEN_EXPIRED = "AUTH_TOKEN_EXPIRED"
    TOKEN_NOT_YET_VALID = "AUTH_TOKEN_NOT_YET_VALID"
    TOKEN_LIFETIME_DENIED = "AUTH_TOKEN_LIFETIME_DENIED"
    VERIFICATION_UNAVAILABLE = "AUTH_VERIFICATION_UNAVAILABLE"


class AuthenticationError(Exception):
    """A sanitized authentication failure with one stable denial code."""

    def __init__(self, code: AuthenticationDenialCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class CallerBinding:
    """One exact Google identity and the ControlGraph role it may assume."""

    role: CallerRole
    email: str
    subject: str

    def __post_init__(self) -> None:
        if type(self.role) is not CallerRole:
            raise ValueError("caller role is invalid")
        _validate_email(self.email)
        _validate_subject(self.subject)


@dataclass(frozen=True, slots=True)
class RouteAuthenticationPolicy:
    """Exact audience and caller policy for one protected service route."""

    project_id: str
    project_number: str
    service_role: ServiceRole
    path: str
    audience: str
    caller: CallerBinding

    def __post_init__(self) -> None:
        _validate_project_id(self.project_id)
        _validate_project_number(self.project_number)
        if type(self.service_role) is not ServiceRole:
            raise ValueError("service role is invalid")
        if self.path != protected_path(self.service_role):
            raise ValueError("protected path does not match the service role")
        _validate_audience(self.audience, self.service_role)
        expected_audience = (
            f"https://{runtime_service_name(self.service_role)}-{self.project_number}"
            ".us-central1.run.app"
        )
        if self.audience != expected_audience:
            raise ValueError("route audience does not match its project coordinates")
        expected_caller_role = expected_route_caller_role(self.service_role)
        if self.caller.role is not expected_caller_role:
            raise ValueError("caller role does not match the protected route")
        if self.caller.role is CallerRole.OPERATOR:
            _validate_operator_email(self.caller.email)
        elif self.caller.email != _service_account_email(self.caller.role, self.project_id):
            raise ValueError("caller email does not match its project role")


@dataclass(frozen=True, slots=True)
class AuthenticationContext:
    """Bounded verified caller data retained without the bearer credential."""

    role: CallerRole
    email: str
    subject: str
    issuer: str
    audience: str
    issued_at: int
    expires_at: int


class IdentityAuthenticator(Protocol):
    """Port for authenticating one request against one exact route policy."""

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext: ...


_SERVICE_ACCOUNT_IDS: dict[CallerRole, str] = {
    CallerRole.API: "controlgraph-api",
    CallerRole.COORDINATOR: "controlgraph-coordinator",
    CallerRole.ISSUER: "controlgraph-issuer",
    CallerRole.EXECUTOR: "controlgraph-executor",
    CallerRole.RECOVERY: "controlgraph-recovery",
    CallerRole.VERIFIER: "controlgraph-verifier",
    CallerRole.EVIDENCE_WRITER: "cg-evidence-writer",
    CallerRole.EXECUTION_TASK_CALLER: "cg-execution-task-caller",
    CallerRole.RECOVERY_TASK_CALLER: "cg-recovery-task-caller",
}

_SERVICE_NAMES: dict[ServiceRole, str] = {
    ServiceRole.API: "controlgraph-api",
    ServiceRole.COORDINATOR: "controlgraph-coordinator",
    ServiceRole.ISSUER: "controlgraph-issuer",
    ServiceRole.EXECUTOR: "controlgraph-executor",
    ServiceRole.RECOVERY: "controlgraph-recovery",
    ServiceRole.VERIFIER: "controlgraph-verifier",
    ServiceRole.EVIDENCE_WRITER: "controlgraph-evidence-writer",
}

_PROTECTED_PATHS: dict[ServiceRole, str] = {
    ServiceRole.API: "/v1/operator/commands",
    ServiceRole.COORDINATOR: "/v1/internal/coordinate",
    ServiceRole.ISSUER: "/v1/internal/issue",
    ServiceRole.EXECUTOR: EXECUTION_HANDLER_PATH,
    ServiceRole.RECOVERY: RECOVERY_HANDLER_PATH,
    ServiceRole.VERIFIER: "/v1/internal/verify",
    ServiceRole.EVIDENCE_WRITER: "/v1/internal/evidence/sign",
}

_ROUTE_CALLER_ROLES: dict[ServiceRole, CallerRole] = {
    ServiceRole.API: CallerRole.OPERATOR,
    ServiceRole.COORDINATOR: CallerRole.API,
    ServiceRole.ISSUER: CallerRole.COORDINATOR,
    ServiceRole.EXECUTOR: CallerRole.EXECUTION_TASK_CALLER,
    ServiceRole.RECOVERY: CallerRole.RECOVERY_TASK_CALLER,
    ServiceRole.VERIFIER: CallerRole.COORDINATOR,
    ServiceRole.EVIDENCE_WRITER: CallerRole.COORDINATOR,
}


def runtime_service_name(role: ServiceRole) -> str:
    """Return the exact Cloud Run service name bound to a runtime role."""

    if type(role) is not ServiceRole:
        raise ValueError("service role is invalid")
    return _SERVICE_NAMES[role]


def protected_path(role: ServiceRole) -> str:
    """Return the sole protected path admitted by a service role."""

    if type(role) is not ServiceRole:
        raise ValueError("service role is invalid")
    return _PROTECTED_PATHS[role]


def runtime_caller_emails(project_id: str, operator_email: str) -> dict[CallerRole, str]:
    """Derive the complete runtime identity map from one project and operator."""

    _validate_project_id(project_id)
    _validate_operator_email(operator_email)
    result = {
        role: f"{account_id}@{project_id}.iam.gserviceaccount.com"
        for role, account_id in _SERVICE_ACCOUNT_IDS.items()
    }
    result[CallerRole.OPERATOR] = operator_email
    return result


def expected_route_caller_role(service_role: ServiceRole) -> CallerRole:
    """Return the only caller role accepted by a protected service route."""

    if type(service_role) is not ServiceRole:
        raise ValueError("service role is invalid")
    return _ROUTE_CALLER_ROLES[service_role]


def runtime_route_policy(
    service_role: ServiceRole,
    environment: Mapping[str, str],
) -> RouteAuthenticationPolicy:
    """Build and cross-check one route policy from bounded startup configuration."""

    if type(service_role) is not ServiceRole:
        raise ValueError("service role is invalid")
    missing = [
        key
        for key in (
            "CONTROLGRAPH_PROJECT_ID",
            "CONTROLGRAPH_PROJECT_NUMBER",
            "CONTROLGRAPH_REGION",
            "CONTROLGRAPH_ROLE",
            *IDENTITY_ENVIRONMENT_KEYS,
        )
        if not _environment_value(environment, key)
    ]
    if missing:
        raise ValueError("identity environment is incomplete")

    project_id = _environment_value(environment, "CONTROLGRAPH_PROJECT_ID")
    project_number = _environment_value(environment, "CONTROLGRAPH_PROJECT_NUMBER")
    region = _environment_value(environment, "CONTROLGRAPH_REGION")
    configured_role = _environment_value(environment, "CONTROLGRAPH_ROLE")
    audience = _environment_value(environment, "CONTROLGRAPH_AUTH_AUDIENCE")
    caller_email = _environment_value(environment, "CONTROLGRAPH_AUTH_CALLER_EMAIL")
    caller_subject = _environment_value(environment, "CONTROLGRAPH_AUTH_CALLER_SUBJECT")
    raw_caller_role = _environment_value(environment, "CONTROLGRAPH_AUTH_CALLER_ROLE")

    _validate_project_id(project_id)
    _validate_project_number(project_number)
    if region != "us-central1" or configured_role != service_role.value:
        raise ValueError("identity service coordinates are invalid")
    try:
        caller_role = CallerRole(raw_caller_role)
    except ValueError:
        raise ValueError("identity caller role is invalid") from None

    expected_caller_role = expected_route_caller_role(service_role)
    if caller_role is not expected_caller_role:
        raise ValueError("identity caller role does not match the protected route")

    if caller_role is CallerRole.OPERATOR:
        _validate_operator_email(caller_email)
        expected_email = caller_email
    else:
        expected_email = _service_account_email(caller_role, project_id)
    if caller_email != expected_email:
        raise ValueError("identity caller email does not match the protected route")

    expected_audience = (
        f"https://{runtime_service_name(service_role)}-{project_number}.{region}.run.app"
    )
    if audience != expected_audience:
        raise ValueError("identity audience does not match the service coordinates")

    return RouteAuthenticationPolicy(
        project_id=project_id,
        project_number=project_number,
        service_role=service_role,
        path=protected_path(service_role),
        audience=audience,
        caller=CallerBinding(
            role=caller_role,
            email=caller_email,
            subject=caller_subject,
        ),
    )


def _environment_value(environment: Mapping[str, str], key: str) -> str:
    value = environment.get(key)
    if type(value) is not str:
        return ""
    return value.strip()


def _validate_project_id(value: str) -> None:
    if type(value) is not str or _PROJECT_ID.fullmatch(value) is None:
        raise ValueError("project identity is invalid")


def _validate_project_number(value: str) -> None:
    if type(value) is not str or _PROJECT_NUMBER.fullmatch(value) is None:
        raise ValueError("project number is invalid")


def _validate_operator_email(value: str) -> None:
    _validate_email(value)
    if value.endswith(".iam.gserviceaccount.com"):
        raise ValueError("operator identity must be a human email")


def _service_account_email(role: CallerRole, project_id: str) -> str:
    account_id = _SERVICE_ACCOUNT_IDS.get(role)
    if account_id is None:
        raise ValueError("caller role is not a workload identity")
    return f"{account_id}@{project_id}.iam.gserviceaccount.com"


def _validate_email(value: str) -> None:
    if type(value) is not str or len(value.encode("utf-8")) > 320:
        raise ValueError("caller email is invalid")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("caller email is invalid") from None
    if _EMAIL.fullmatch(value) is None:
        raise ValueError("caller email is invalid")


def _validate_subject(value: str) -> None:
    if type(value) is not str or _GOOGLE_SUBJECT.fullmatch(value) is None:
        raise ValueError("caller subject is invalid")


def _validate_audience(value: str, service_role: ServiceRole) -> None:
    if type(value) is not str or len(value.encode("utf-8")) > 2_048:
        raise ValueError("route audience is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("route audience is invalid") from None
    hostname = parsed.hostname
    expected_hostname = re.compile(
        rf"^{re.escape(runtime_service_name(service_role))}-[1-9][0-9]{{5,31}}"
        r"\.us-central1\.run\.app$"
    )
    if (
        parsed.scheme != "https"
        or hostname is None
        or expected_hostname.fullmatch(hostname) is None
        or parsed.netloc != hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is not None
        or value.endswith("/")
        or value != f"https://{hostname}"
    ):
        raise ValueError("route audience is invalid")


__all__ = [
    "IDENTITY_ENVIRONMENT_KEYS",
    "AuthenticationContext",
    "AuthenticationDenialCode",
    "AuthenticationError",
    "CallerBinding",
    "CallerRole",
    "IdentityAuthenticator",
    "RouteAuthenticationPolicy",
    "ServiceRole",
    "expected_route_caller_role",
    "protected_path",
    "runtime_caller_emails",
    "runtime_route_policy",
    "runtime_service_name",
]
