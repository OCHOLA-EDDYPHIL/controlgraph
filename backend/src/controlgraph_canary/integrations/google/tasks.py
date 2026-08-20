"""One-shot Google Cloud Tasks adapter for sealed addressed commands."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from threading import Lock
from typing import Protocol, cast

from google.api_core.exceptions import AlreadyExists
from google.cloud import tasks_v2

from controlgraph_canary.application.tasks import (
    TASK_DISPATCH_DEADLINE_SECONDS,
    AddressedTask,
    TaskAddressor,
    TaskEnqueueDisposition,
    TaskEnqueueResult,
)


class CloudTasksCreateClient(Protocol):
    """Narrow client surface used by the task adapter."""

    def create_task(self, *, request: Mapping[str, object]) -> object:
        """Create one addressed task."""


class GoogleCloudTasksEnqueuer:
    """Submit one sealed HTTP task without application retries or redirects."""

    def __init__(
        self,
        client: CloudTasksCreateClient | None,
        addressor: TaskAddressor,
    ) -> None:
        self._client = client
        self._addressor = addressor
        self._client_lock = Lock()

    @classmethod
    def from_default_credentials(cls, addressor: TaskAddressor) -> GoogleCloudTasksEnqueuer:
        """Construct the runtime client without exposing credential material."""

        return cls(None, addressor)

    def enqueue(self, task: AddressedTask, *, now: datetime) -> TaskEnqueueResult:
        self._addressor.validate_seal(task, now=now)
        provider_request: dict[str, object] = {
            "parent": task.parent,
            "task": {
                "name": task.name,
                "http_request": {
                    "http_method": tasks_v2.HttpMethod.POST,
                    "url": task.handler_url,
                    "headers": {"Content-Type": "application/json"},
                    "body": task.body,
                    "oidc_token": {
                        "service_account_email": task.oidc_service_account,
                        "audience": task.audience,
                    },
                },
                "schedule_time": task.scheduled_for,
                "dispatch_deadline": {"seconds": TASK_DISPATCH_DEADLINE_SECONDS},
            },
        }
        try:
            response = self._get_client().create_task(request=provider_request)
            response_name = getattr(response, "name", None)
        except AlreadyExists:
            return TaskEnqueueResult(
                task_name=task.name,
                disposition=TaskEnqueueDisposition.DUPLICATE,
            )
        except Exception:
            return TaskEnqueueResult(
                task_name=task.name,
                disposition=TaskEnqueueDisposition.AMBIGUOUS,
            )
        if type(response_name) is not str or response_name != task.name:
            return TaskEnqueueResult(
                task_name=task.name,
                disposition=TaskEnqueueDisposition.AMBIGUOUS,
            )
        return TaskEnqueueResult(
            task_name=task.name,
            disposition=TaskEnqueueDisposition.CREATED,
        )

    def _get_client(self) -> CloudTasksCreateClient:
        client = self._client
        if client is not None:
            return client
        with self._client_lock:
            client = self._client
            if client is None:
                client = cast(CloudTasksCreateClient, tasks_v2.CloudTasksClient())
                self._client = client
        return client


__all__ = ["CloudTasksCreateClient", "GoogleCloudTasksEnqueuer"]
