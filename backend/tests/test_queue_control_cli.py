from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field

import pytest
from google.cloud import tasks_v2

from controlgraph_canary.application.queue_control import (
    ExecutionQueueObservation,
    ExecutionQueueState,
    ExecutionQueueTarget,
)
from controlgraph_canary.cli import _build_parser, _run_execution_queue_command
from controlgraph_canary.integrations.google.queue_control import (
    GoogleCloudTasksExecutionQueueController,
)

PROJECT_ID = "controlgraph-canary-a1b2c3"
TARGET = ExecutionQueueTarget(project_id=PROJECT_ID)


@dataclass
class _Controller:
    observation: object
    error: Exception | None = None
    calls: list[str] = field(default_factory=list)

    def _call(self, action: str) -> object:
        self.calls.append(action)
        if self.error is not None:
            raise self.error
        return self.observation

    def describe(self) -> object:
        return self._call("describe")

    def hold(self) -> object:
        return self._call("hold")

    def release(self) -> object:
        return self._call("release")


class _Factory:
    def __init__(self, controller: _Controller) -> None:
        self.controller = controller
        self.calls: list[ExecutionQueueTarget] = []

    def __call__(self, target: ExecutionQueueTarget) -> object:
        self.calls.append(target)
        return self.controller


class _Client:
    def __init__(self, queue: tasks_v2.Queue) -> None:
        self.queue = queue
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _call(self, action: str, **options: object) -> tasks_v2.Queue:
        self.calls.append((action, options))
        return self.queue

    def get_queue(self, **options: object) -> tasks_v2.Queue:
        return self._call("get", **options)

    def pause_queue(self, **options: object) -> tasks_v2.Queue:
        return self._call("pause", **options)

    def resume_queue(self, **options: object) -> tasks_v2.Queue:
        return self._call("resume", **options)


def _args(action: str, *, project_id: object = PROJECT_ID) -> argparse.Namespace:
    confirmations = {
        "describe": None,
        "hold": "HOLD_EXECUTION_QUEUE",
        "release": "RELEASE_EXECUTION_QUEUE",
    }
    return argparse.Namespace(
        queue_action=action,
        project_id=project_id,
        confirm=confirmations.get(action),
    )


def _observation(state: ExecutionQueueState) -> ExecutionQueueObservation:
    return ExecutionQueueObservation(resource_name=TARGET.resource_name, state=state)


@pytest.mark.parametrize("state", list(ExecutionQueueState))
def test_describe_uses_one_sealed_controller_call_and_sanitizes_output(
    state: ExecutionQueueState,
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller = _Controller(_observation(state))
    factory = _Factory(controller)

    status = _run_execution_queue_command(
        _args("describe"),
        controller_factory=factory,  # type: ignore[arg-type]
    )

    assert status == 0
    assert factory.calls == [TARGET]
    assert controller.calls == ["describe"]
    assert json.loads(capsys.readouterr().out) == {
        "action": "describe",
        "location": "us-central1",
        "project_id": PROJECT_ID,
        "queue_id": "controlgraph-execution",
        "state": state.value,
    }


@pytest.mark.parametrize(
    ("action", "confirmation", "state"),
    [
        ("hold", "HOLD_EXECUTION_QUEUE", ExecutionQueueState.PAUSED),
        ("release", "RELEASE_EXECUTION_QUEUE", ExecutionQueueState.RUNNING),
    ],
)
def test_queue_mutation_requires_confirmation_and_observes_the_requested_state(
    action: str,
    confirmation: str,
    state: ExecutionQueueState,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = _args(action)
    assert args.confirm == confirmation
    controller = _Controller(_observation(state))
    factory = _Factory(controller)

    status = _run_execution_queue_command(
        args,
        controller_factory=factory,  # type: ignore[arg-type]
    )

    assert status == 0
    assert factory.calls == [TARGET]
    assert controller.calls == [action]
    assert json.loads(capsys.readouterr().out) == {
        "action": action,
        "location": "us-central1",
        "project_id": PROJECT_ID,
        "queue_id": "controlgraph-execution",
        "state": state.value,
    }


@pytest.mark.parametrize(
    "project_id",
    [
        None,
        "controlgraph-canary-short",
        "controlgraph-canary-reconcile",
        "controlgraph-canary-UPPER1",
        "controlgraph-canary-a1b2c3 --location=europe-west1",
        "reconcile-production",
    ],
)
def test_queue_control_rejects_unsealed_projects_before_client_construction(
    project_id: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller = _Controller(_observation(ExecutionQueueState.PAUSED))
    factory = _Factory(controller)

    status = _run_execution_queue_command(
        _args("hold", project_id=project_id),
        controller_factory=factory,  # type: ignore[arg-type]
    )

    assert status == 2
    assert factory.calls == []
    assert controller.calls == []
    assert json.loads(capsys.readouterr().out) == {
        "code": "QUEUE_CONTROL_COMMAND_INVALID"
    }


@pytest.mark.parametrize(
    ("action", "observation", "expected_status", "expected_code"),
    [
        (
            "describe",
            object(),
            5,
            "QUEUE_CONTROL_RESPONSE_INVALID",
        ),
        (
            "hold",
            _observation(ExecutionQueueState.RUNNING),
            4,
            "QUEUE_CONTROL_OUTCOME_UNKNOWN",
        ),
        (
            "release",
            _observation(ExecutionQueueState.PAUSED),
            4,
            "QUEUE_CONTROL_OUTCOME_UNKNOWN",
        ),
    ],
)
def test_queue_control_fails_closed_on_unbound_or_wrong_state_results(
    action: str,
    observation: object,
    expected_status: int,
    expected_code: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller = _Controller(observation)

    status = _run_execution_queue_command(
        _args(action),
        controller_factory=_Factory(controller),  # type: ignore[arg-type]
    )

    assert status == expected_status
    assert controller.calls == [action]
    assert json.loads(capsys.readouterr().out) == {"code": expected_code}


@pytest.mark.parametrize(
    ("action", "expected_status", "expected_code"),
    [
        ("describe", 3, "QUEUE_CONTROL_PROVIDER_UNAVAILABLE"),
        ("hold", 4, "QUEUE_CONTROL_OUTCOME_UNKNOWN"),
        ("release", 4, "QUEUE_CONTROL_OUTCOME_UNKNOWN"),
    ],
)
def test_queue_control_sanitizes_provider_failures(
    action: str,
    expected_status: int,
    expected_code: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller = _Controller(
        _observation(ExecutionQueueState.RUNNING),
        error=TimeoutError("provider-diagnostic-that-must-not-escape"),
    )

    status = _run_execution_queue_command(
        _args(action),
        controller_factory=_Factory(controller),  # type: ignore[arg-type]
    )

    assert status == expected_status
    assert controller.calls == [action]
    assert json.loads(capsys.readouterr().out) == {"code": expected_code}


@pytest.mark.parametrize(
    ("action", "method", "provider_state", "expected_state"),
    [
        ("describe", "get", tasks_v2.Queue.State.DISABLED, ExecutionQueueState.DISABLED),
        ("hold", "pause", tasks_v2.Queue.State.PAUSED, ExecutionQueueState.PAUSED),
        ("release", "resume", tasks_v2.Queue.State.RUNNING, ExecutionQueueState.RUNNING),
    ],
)
def test_google_adapter_makes_one_non_retrying_bounded_rpc(
    action: str,
    method: str,
    provider_state: tasks_v2.Queue.State,
    expected_state: ExecutionQueueState,
) -> None:
    client = _Client(tasks_v2.Queue(name=TARGET.resource_name, state=provider_state))
    controller = GoogleCloudTasksExecutionQueueController(
        TARGET,
        client,  # type: ignore[arg-type]
    )

    observed = getattr(controller, action)()

    assert observed == _observation(expected_state)
    assert client.calls == [
        (
            method,
            {
                "name": TARGET.resource_name,
                "retry": None,
                "timeout": 20.0,
            },
        )
    ]


@pytest.mark.parametrize(
    "queue",
    [
        tasks_v2.Queue(
            name=TARGET.resource_name.replace("controlgraph-execution", "other"),
            state=tasks_v2.Queue.State.PAUSED,
        ),
        tasks_v2.Queue(name=TARGET.resource_name, state=tasks_v2.Queue.State.STATE_UNSPECIFIED),
    ],
)
def test_google_adapter_rejects_unbound_or_unknown_provider_results(
    queue: tasks_v2.Queue,
) -> None:
    controller = GoogleCloudTasksExecutionQueueController(
        TARGET,
        _Client(queue),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError):
        controller.hold()


@pytest.mark.parametrize(
    ("resource_name", "state", "error_type"),
    [
        (
            TARGET.resource_name.replace("controlgraph-execution", "other"),
            ExecutionQueueState.RUNNING,
            ValueError,
        ),
        (TARGET.resource_name, "RUNNING", TypeError),
    ],
)
def test_queue_observation_rejects_unbound_resources_and_untyped_states(
    resource_name: str,
    state: object,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        ExecutionQueueObservation(
            resource_name=resource_name,
            state=state,  # type: ignore[arg-type]
        )


def test_parser_exposes_no_queue_region_or_arbitrary_provider_command() -> None:
    parser = _build_parser()
    parsed = parser.parse_args(
        [
            "execution-queue",
            "hold",
            "--project-id",
            PROJECT_ID,
            "--confirm",
            "HOLD_EXECUTION_QUEUE",
        ]
    )
    assert parsed.queue_action == "hold"
    assert not hasattr(parsed, "queue")
    assert not hasattr(parsed, "location")

    for arguments in (
        ["execution-queue", "delete", "--project-id", PROJECT_ID],
        [
            "execution-queue",
            "hold",
            "--project-id",
            PROJECT_ID,
            "--confirm",
            "RELEASE_EXECUTION_QUEUE",
        ],
        [
            "execution-queue",
            "release",
            "--project-id",
            PROJECT_ID,
            "--queue",
            "other",
            "--confirm",
            "RELEASE_EXECUTION_QUEUE",
        ],
    ):
        with pytest.raises(SystemExit):
            parser.parse_args(arguments)
