"""One-shot Google Cloud Tasks adapter for sealed addressed commands."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import datetime
from typing import Final, Protocol, cast

import google.auth
from google.api_core.exceptions import AlreadyExists
from google.auth.credentials import Credentials
from google.cloud import tasks_v2

from controlgraph_canary.application.tasks import (
    TASK_DISPATCH_DEADLINE_SECONDS,
    AddressedTask,
    TaskAddressor,
    TaskEnqueueDisposition,
    TaskEnqueueResult,
)

CLOUD_TASKS_CREATE_RPC_TIMEOUT_SECONDS: Final = 10.0
CLOUD_TASKS_ENQUEUE_WALL_TIMEOUT_SECONDS: Final = 15.0
_CLOUD_TASKS_AUTH_SCOPES: Final = (
    "https://www.googleapis.com/auth/cloud-platform",
)


class CloudTasksCreateClient(Protocol):
    """Narrow client surface used by the task adapter."""

    async def create_task(
        self,
        *,
        request: Mapping[str, object],
        retry: None,
        timeout: float,
    ) -> object:
        """Create one addressed task."""


class GoogleCloudTasksEnqueuer:
    """Submit one sealed HTTP task without application retries or redirects."""

    def __init__(
        self,
        client: CloudTasksCreateClient | None,
        addressor: TaskAddressor,
        *,
        credentials: Credentials | None = None,
    ) -> None:
        if client is None and credentials is None:
            raise ValueError("a Cloud Tasks client or credentials are required")
        self._client = client
        self._credentials = credentials
        self._addressor = addressor

    @classmethod
    def from_default_credentials(cls, addressor: TaskAddressor) -> GoogleCloudTasksEnqueuer:
        """Construct the runtime client without exposing credential material."""

        credentials, _ = google.auth.default(
            default_scopes=_CLOUD_TASKS_AUTH_SCOPES,
        )
        return cls(None, addressor, credentials=credentials)

    async def enqueue(
        self,
        task: AddressedTask,
        *,
        now: datetime,
    ) -> TaskEnqueueResult:
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
            async with asyncio.timeout(CLOUD_TASKS_ENQUEUE_WALL_TIMEOUT_SECONDS):
                client = self._get_client()
                response = await client.create_task(
                    request=provider_request,
                    retry=None,
                    timeout=CLOUD_TASKS_CREATE_RPC_TIMEOUT_SECONDS,
                )
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
        credentials = self._credentials
        if credentials is None:
            raise RuntimeError("Cloud Tasks credentials are unavailable")
        client = cast(
            CloudTasksCreateClient,
            tasks_v2.CloudTasksAsyncClient(credentials=credentials),
        )
        self._client = client
        return client


__all__ = [
    "CLOUD_TASKS_CREATE_RPC_TIMEOUT_SECONDS",
    "CLOUD_TASKS_ENQUEUE_WALL_TIMEOUT_SECONDS",
    "CloudTasksCreateClient",
    "GoogleCloudTasksEnqueuer",
]
