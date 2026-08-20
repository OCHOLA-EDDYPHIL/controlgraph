"""Closed operator boundary for the fixed execution queue."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

EXECUTION_QUEUE_ID = "controlgraph-execution"
EXECUTION_QUEUE_REGION = "us-central1"
_CONTROLGRAPH_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_EXECUTION_QUEUE_RESOURCE = re.compile(
    r"^projects/controlgraph-canary-[a-z0-9]{6,10}/locations/us-central1/"
    r"queues/controlgraph-execution$"
)


class ExecutionQueueState(StrEnum):
    """Provider states admitted by the bounded operator surface."""

    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    DISABLED = "DISABLED"


@dataclass(frozen=True, slots=True)
class ExecutionQueueTarget:
    """The sole operator-controlled queue in one isolated project."""

    project_id: str

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not str
            or _CONTROLGRAPH_PROJECT_ID.fullmatch(self.project_id) is None
            or "reconcile" in self.project_id
        ):
            raise ValueError("execution queue project is invalid")

    @property
    def resource_name(self) -> str:
        return (
            f"projects/{self.project_id}/locations/{EXECUTION_QUEUE_REGION}"
            f"/queues/{EXECUTION_QUEUE_ID}"
        )


@dataclass(frozen=True, slots=True)
class ExecutionQueueObservation:
    """Sanitized exact queue identity and provider state."""

    resource_name: str
    state: ExecutionQueueState

    def __post_init__(self) -> None:
        if (
            type(self.resource_name) is not str
            or _EXECUTION_QUEUE_RESOURCE.fullmatch(self.resource_name) is None
            or "reconcile" in self.resource_name
        ):
            raise ValueError("execution queue observation resource is invalid")
        if type(self.state) is not ExecutionQueueState:
            raise TypeError("execution queue observation state is invalid")


class ExecutionQueueController(Protocol):
    """One-RPC operations for only the configured execution queue."""

    def describe(self) -> ExecutionQueueObservation: ...

    def hold(self) -> ExecutionQueueObservation: ...

    def release(self) -> ExecutionQueueObservation: ...


__all__ = [
    "EXECUTION_QUEUE_ID",
    "EXECUTION_QUEUE_REGION",
    "ExecutionQueueController",
    "ExecutionQueueObservation",
    "ExecutionQueueState",
    "ExecutionQueueTarget",
]
