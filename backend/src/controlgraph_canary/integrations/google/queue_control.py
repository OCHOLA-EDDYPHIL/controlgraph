"""One-RPC Google Cloud Tasks control for the fixed execution queue."""

from __future__ import annotations

from typing import Protocol

from google.cloud import tasks_v2

from controlgraph_canary.application.queue_control import (
    ExecutionQueueObservation,
    ExecutionQueueState,
    ExecutionQueueTarget,
)

_RPC_TIMEOUT_SECONDS = 20.0


class _CloudTasksQueueClient(Protocol):
    def get_queue(
        self,
        *,
        name: str,
        retry: None,
        timeout: float,
    ) -> tasks_v2.Queue: ...

    def pause_queue(
        self,
        *,
        name: str,
        retry: None,
        timeout: float,
    ) -> tasks_v2.Queue: ...

    def resume_queue(
        self,
        *,
        name: str,
        retry: None,
        timeout: float,
    ) -> tasks_v2.Queue: ...


class GoogleCloudTasksExecutionQueueController:
    """Control one sealed queue without SDK retries or caller-selected coordinates."""

    def __init__(
        self,
        target: ExecutionQueueTarget,
        client: _CloudTasksQueueClient,
    ) -> None:
        if type(target) is not ExecutionQueueTarget:
            raise TypeError("an exact execution queue target is required")
        self._target = target
        self._client = client

    @classmethod
    def from_default_credentials(
        cls,
        target: ExecutionQueueTarget,
    ) -> GoogleCloudTasksExecutionQueueController:
        return cls(target, tasks_v2.CloudTasksClient())

    def describe(self) -> ExecutionQueueObservation:
        return self._observation(
            self._client.get_queue(
                name=self._target.resource_name,
                retry=None,
                timeout=_RPC_TIMEOUT_SECONDS,
            )
        )

    def hold(self) -> ExecutionQueueObservation:
        return self._observation(
            self._client.pause_queue(
                name=self._target.resource_name,
                retry=None,
                timeout=_RPC_TIMEOUT_SECONDS,
            )
        )

    def release(self) -> ExecutionQueueObservation:
        return self._observation(
            self._client.resume_queue(
                name=self._target.resource_name,
                retry=None,
                timeout=_RPC_TIMEOUT_SECONDS,
            )
        )

    def _observation(self, queue: tasks_v2.Queue) -> ExecutionQueueObservation:
        if type(queue) is not tasks_v2.Queue or queue.name != self._target.resource_name:
            raise ValueError("Cloud Tasks returned an unexpected queue")
        try:
            state = ExecutionQueueState(tasks_v2.Queue.State(queue.state).name)
        except (TypeError, ValueError) as error:
            raise ValueError("Cloud Tasks returned an unsupported queue state") from error
        return ExecutionQueueObservation(resource_name=queue.name, state=state)


__all__ = ["GoogleCloudTasksExecutionQueueController"]
