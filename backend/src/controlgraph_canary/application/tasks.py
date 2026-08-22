"""Closed application boundary for addressed Cloud Tasks delivery."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Protocol
from urllib.parse import urlsplit

from controlgraph_canary.application.promotion_store import (
    PromotionEnqueuePermit,
    PromotionEnqueuePermitV2,
)
from controlgraph_canary.application.recovery_store import RecoveryEnqueuePermit
from controlgraph_canary.contracts.codec import (
    ContractError,
    ContractErrorCode,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import CapabilityAction, TaskRequest
from controlgraph_canary.contracts.promotion_execution import PromotionTaskRequestV2
from controlgraph_canary.contracts.recovery_execution import RecoveryTaskRequestV2

TASK_REGION: Final = "us-central1"
EXECUTION_QUEUE_ID: Final = "controlgraph-execution"
RECOVERY_QUEUE_ID: Final = "controlgraph-recovery"
EXECUTION_TASK_CALLER_ACCOUNT_ID: Final = "cg-execution-task-caller"
RECOVERY_TASK_CALLER_ACCOUNT_ID: Final = "cg-recovery-task-caller"
EXECUTOR_SERVICE_NAME: Final = "controlgraph-executor"
RECOVERY_SERVICE_NAME: Final = "controlgraph-recovery"
EXECUTION_HANDLER_PATH: Final = "/v1/internal/tasks/execute"
RECOVERY_HANDLER_PATH: Final = "/v1/internal/tasks/recover"
MAX_SCHEDULE_DELAY_SECONDS: Final = 600
MAX_TASK_AGE_SECONDS: Final = 900
TASK_DISPATCH_DEADLINE_SECONDS: Final = 60
MIN_RECOVERY_DELIVERY_MARGIN_SECONDS: Final = 120

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_TASK_ID = re.compile(r"^[A-Za-z0-9_-]{1,500}$")

type AddressableTaskRequest = (
    TaskRequest | PromotionTaskRequestV2 | RecoveryTaskRequestV2
)


class TaskRoute(StrEnum):
    """The only task destinations in the first ControlGraph vertical."""

    EXECUTION = "execution"
    RECOVERY = "recovery"


class TaskEnqueueDisposition(StrEnum):
    """Safe outcomes from creating one deterministic task."""

    CREATED = "CREATED"
    DUPLICATE = "DUPLICATE"
    AMBIGUOUS = "AMBIGUOUS"


class TaskAddressingError(ValueError):
    """A task cannot be sealed to the configured delivery boundary."""


@dataclass(frozen=True, slots=True)
class TaskDeliverySettings:
    """Startup-bound queue, handler, audience, and delivery identities."""

    project_id: str
    execution_queue_id: str
    recovery_queue_id: str
    executor_service_url: str
    recovery_service_url: str
    execution_oidc_service_account: str
    recovery_oidc_service_account: str
    region: str = TASK_REGION

    def __post_init__(self) -> None:
        if type(self.project_id) is not str or _PROJECT_ID.fullmatch(self.project_id) is None:
            raise ValueError("project_id is invalid")
        if self.region != TASK_REGION:
            raise ValueError("task delivery is pinned to us-central1")
        if self.execution_queue_id != EXECUTION_QUEUE_ID:
            raise ValueError("execution queue does not match the fixed queue")
        if self.recovery_queue_id != RECOVERY_QUEUE_ID:
            raise ValueError("recovery queue does not match the fixed queue")
        _validate_service_origin(self.executor_service_url, EXECUTOR_SERVICE_NAME)
        _validate_service_origin(self.recovery_service_url, RECOVERY_SERVICE_NAME)
        _validate_service_account(
            self.execution_oidc_service_account,
            self.project_id,
            EXECUTION_TASK_CALLER_ACCOUNT_ID,
        )
        _validate_service_account(
            self.recovery_oidc_service_account,
            self.project_id,
            RECOVERY_TASK_CALLER_ACCOUNT_ID,
        )


@dataclass(frozen=True, slots=True)
class AddressedTask:
    """A canonical command sealed to one configured Cloud Tasks destination."""

    route: TaskRoute
    parent: str
    name: str
    handler_url: str
    audience: str
    oidc_service_account: str
    scheduled_for: datetime
    expires_at: datetime
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class TaskEnqueueResult:
    """The result of one create-task call without exposing provider content."""

    task_name: str
    disposition: TaskEnqueueDisposition


class TaskEnqueuer(Protocol):
    """Port for exactly one provider create-task attempt."""

    async def enqueue(
        self,
        task: AddressedTask,
        *,
        now: datetime,
    ) -> TaskEnqueueResult:
        """Attempt to create the addressed task once."""


class TaskAddressor:
    """Seal canonical task requests to startup-bound destinations."""

    def __init__(self, settings: TaskDeliverySettings) -> None:
        self._settings = settings

    def seal(self, request: AddressableTaskRequest, *, now: datetime) -> AddressedTask:
        """Validate bounds and derive every provider coordinate from configuration."""

        evaluation_time = _require_utc_second(now)
        scheduled_for = _parse_utc_second(request.scheduled_at)
        expires_at = _parse_utc_second(request.expires_at)
        route = _route_for_action(request.intent.action)
        if request.queue_region != self._settings.region:
            raise TaskAddressingError("task queue region does not match configuration")
        if (
            request.intent.target.project_id != self._settings.project_id
            or request.intent.target.region != self._settings.region
        ):
            raise TaskAddressingError("task target does not match delivery configuration")
        if expires_at <= evaluation_time:
            raise TaskAddressingError("task is expired")
        if (scheduled_for - evaluation_time).total_seconds() > MAX_SCHEDULE_DELAY_SECONDS:
            raise TaskAddressingError("task schedule exceeds the delay bound")
        if (expires_at - scheduled_for).total_seconds() > MAX_TASK_AGE_SECONDS:
            raise TaskAddressingError("task lifetime exceeds the age bound")
        if (
            route is TaskRoute.RECOVERY
            and (
                expires_at - max(evaluation_time, scheduled_for)
            ).total_seconds()
            < MIN_RECOVERY_DELIVERY_MARGIN_SECONDS
        ):
            raise TaskAddressingError("recovery task delivery margin is exhausted")

        queue_id, service_url, caller, handler_path = self._route_configuration(route)
        if request.handler_audience != service_url:
            raise TaskAddressingError("task audience does not match the service audience")

        canonical_body = canonical_json_bytes(request)
        deterministic_id = _deterministic_task_id(request)
        parent = (
            f"projects/{self._settings.project_id}/locations/{self._settings.region}"
            f"/queues/{queue_id}"
        )
        name = f"{parent}/tasks/{deterministic_id}"
        if _TASK_ID.fullmatch(deterministic_id) is None:
            raise AssertionError("derived task identifier is invalid")
        return AddressedTask(
            route=route,
            parent=parent,
            name=name,
            handler_url=f"{service_url}{handler_path}",
            audience=service_url,
            oidc_service_account=caller,
            scheduled_for=scheduled_for,
            expires_at=expires_at,
            body=canonical_body,
        )

    def validate_seal(self, task: AddressedTask, *, now: datetime) -> None:
        """Rebuild a task at dispatch time and require an exact sealed match."""

        try:
            request = _decode_addressed_task(task.body)
        except ContractError as error:
            raise TaskAddressingError("addressed task body is not canonical") from error
        expected = self.seal(request, now=now)
        if task != expected:
            raise TaskAddressingError("addressed task seal does not match configuration")

    def _route_configuration(self, route: TaskRoute) -> tuple[str, str, str, str]:
        if route is TaskRoute.EXECUTION:
            return (
                self._settings.execution_queue_id,
                self._settings.executor_service_url,
                self._settings.execution_oidc_service_account,
                EXECUTION_HANDLER_PATH,
            )
        return (
            self._settings.recovery_queue_id,
            self._settings.recovery_service_url,
            self._settings.recovery_oidc_service_account,
            RECOVERY_HANDLER_PATH,
        )


class TaskDispatcher:
    """Perform one bounded enqueue attempt; callers decide any later new action."""

    def __init__(self, addressor: TaskAddressor, enqueuer: TaskEnqueuer) -> None:
        self._addressor = addressor
        self._enqueuer = enqueuer

    async def dispatch(
        self,
        request: TaskRequest,
        *,
        now: datetime,
    ) -> TaskEnqueueResult:
        if request.intent.action in {
            CapabilityAction.PROMOTE_CANDIDATE,
            CapabilityAction.RECOVER_STABLE,
        }:
            raise TaskAddressingError(
                "terminal dispatch requires a directly confirmed enqueue permit"
            )
        evaluation_time = _require_utc_second(now)
        addressed = self.prepare(request, now=evaluation_time)
        return await self._enqueuer.enqueue(addressed, now=evaluation_time)

    def prepare(self, request: AddressableTaskRequest, *, now: datetime) -> AddressedTask:
        """Seal an exact task before durable enqueue ownership begins."""

        return self._addressor.seal(request, now=_require_utc_second(now))

    async def dispatch_prepared(
        self,
        task: AddressedTask,
        *,
        permit: PromotionEnqueuePermit,
        now: datetime,
    ) -> TaskEnqueueResult:
        """Validate and submit one already sealed task exactly once."""

        evaluation_time = _require_utc_second(now)
        self._addressor.validate_seal(task, now=evaluation_time)
        try:
            request = decode_contract(task.body, TaskRequest)
        except ContractError as error:
            raise TaskAddressingError("promotion task body is not canonical") from error
        if (
            type(permit) is not PromotionEnqueuePermit
            or request.intent.action is not CapabilityAction.PROMOTE_CANDIDATE
        ):
            raise TaskAddressingError("promotion enqueue permit is required")
        try:
            permit._take(
                task_name=task.name,
                task_sha256=canonical_sha256(request),
            )
        except (TypeError, ValueError) as error:
            raise TaskAddressingError("promotion enqueue permit is invalid") from error
        return await self._enqueuer.enqueue(task, now=evaluation_time)

    async def dispatch_prepared_v2(
        self,
        task: AddressedTask,
        *,
        permit: PromotionEnqueuePermitV2,
        now: datetime,
    ) -> TaskEnqueueResult:
        """Submit one exactly sealed V2 promotion task with direct store authority."""

        evaluation_time = _require_utc_second(now)
        self._addressor.validate_seal(task, now=evaluation_time)
        try:
            request = decode_contract(task.body, PromotionTaskRequestV2)
        except ContractError as error:
            raise TaskAddressingError("V2 promotion task body is not canonical") from error
        if (
            type(permit) is not PromotionEnqueuePermitV2
            or request.intent.action is not CapabilityAction.PROMOTE_CANDIDATE
        ):
            raise TaskAddressingError("V2 promotion enqueue permit is required")
        try:
            permit._take(
                task_name=task.name,
                task_sha256=canonical_sha256(request),
            )
        except (TypeError, ValueError) as error:
            raise TaskAddressingError("V2 promotion enqueue permit is invalid") from error
        return await self._enqueuer.enqueue(task, now=evaluation_time)

    async def dispatch_prepared_recovery(
        self,
        task: AddressedTask,
        *,
        permit: RecoveryEnqueuePermit,
        now: datetime,
    ) -> TaskEnqueueResult:
        """Submit one exactly sealed stable-recovery task with direct store authority."""

        evaluation_time = _require_utc_second(now)
        self._addressor.validate_seal(task, now=evaluation_time)
        try:
            request = decode_contract(task.body, RecoveryTaskRequestV2)
        except ContractError as error:
            raise TaskAddressingError("recovery task body is not canonical") from error
        if (
            type(permit) is not RecoveryEnqueuePermit
            or request.intent.action is not CapabilityAction.RECOVER_STABLE
        ):
            raise TaskAddressingError("recovery enqueue permit is required")
        try:
            permit._take(
                task_name=task.name,
                task_sha256=canonical_sha256(request),
            )
        except (TypeError, ValueError) as error:
            raise TaskAddressingError("recovery enqueue permit is invalid") from error
        return await self._enqueuer.enqueue(task, now=evaluation_time)


def _route_for_action(action: CapabilityAction) -> TaskRoute:
    if action is CapabilityAction.RECOVER_STABLE:
        return TaskRoute.RECOVERY
    if action in {CapabilityAction.APPLY_CANARY, CapabilityAction.PROMOTE_CANDIDATE}:
        return TaskRoute.EXECUTION
    raise TaskAddressingError("task action has no configured route")


def _deterministic_task_id(request: AddressableTaskRequest) -> str:
    return f"cg-{canonical_sha256(request)}"


def _decode_addressed_task(body: bytes) -> AddressableTaskRequest:
    try:
        return decode_contract(body, RecoveryTaskRequestV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, PromotionTaskRequestV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    return decode_contract(body, TaskRequest)


def _validate_service_origin(value: str, service_name: str) -> None:
    if type(value) is not str:
        raise ValueError("service URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("service URL is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not _is_service_hostname(parsed.hostname, service_name)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is not None
        or value.endswith("/")
        or value != f"https://{parsed.hostname}"
    ):
        raise ValueError("service URL must match the fixed Cloud Run service")


def _is_service_hostname(hostname: str, service_name: str) -> bool:
    legacy = re.compile(rf"^{re.escape(service_name)}-[a-z0-9]+-[a-z0-9]+\.a\.run\.app$")
    deterministic = re.compile(rf"^{re.escape(service_name)}-[1-9][0-9]*\.{TASK_REGION}\.run\.app$")
    return legacy.fullmatch(hostname) is not None or deterministic.fullmatch(hostname) is not None


def _validate_service_account(value: str, project_id: str, account_id: str) -> None:
    expected = f"{account_id}@{project_id}.iam.gserviceaccount.com"
    if value != expected:
        raise ValueError("OIDC service account does not match the fixed delivery caller")


def _parse_utc_second(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _require_utc_second(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value) or value.microsecond:
        raise ValueError("now must be an exact UTC second")
    return value


__all__ = [
    "EXECUTION_HANDLER_PATH",
    "EXECUTION_QUEUE_ID",
    "EXECUTION_TASK_CALLER_ACCOUNT_ID",
    "EXECUTOR_SERVICE_NAME",
    "MAX_SCHEDULE_DELAY_SECONDS",
    "MAX_TASK_AGE_SECONDS",
    "MIN_RECOVERY_DELIVERY_MARGIN_SECONDS",
    "RECOVERY_HANDLER_PATH",
    "RECOVERY_QUEUE_ID",
    "RECOVERY_SERVICE_NAME",
    "RECOVERY_TASK_CALLER_ACCOUNT_ID",
    "TASK_DISPATCH_DEADLINE_SECONDS",
    "TASK_REGION",
    "AddressableTaskRequest",
    "AddressedTask",
    "TaskAddressingError",
    "TaskAddressor",
    "TaskDeliverySettings",
    "TaskDispatcher",
    "TaskEnqueueDisposition",
    "TaskEnqueueResult",
    "TaskEnqueuer",
    "TaskRoute",
]
