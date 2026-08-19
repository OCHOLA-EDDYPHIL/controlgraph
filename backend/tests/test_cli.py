import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from controlgraph_canary.cli import _doctor_report, main
from controlgraph_canary.settings import REQUIRED_ENVIRONMENT_KEYS, ControllerSettings


def test_doctor_reports_missing_configuration() -> None:
    report = _doctor_report({})

    assert report == {
        "configured": False,
        "missing": list(REQUIRED_ENVIRONMENT_KEYS),
        "cloud_calls_performed": False,
    }


def test_fence_check_emits_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(
            [
                "fence-check",
                "--token-epoch",
                "7",
                "--current-epoch",
                "7",
                "--controller-id",
                "controller-a",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert json.loads(output) == {
        "authorized": True,
        "controller_id": "controller-a",
        "epoch": 7,
    }


def test_serve_disables_uvicorn_access_log(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    observed: dict[str, object] = {}

    def run(app: str, **options: object) -> None:
        observed["app"] = app
        observed.update(options)

    monkeypatch.setattr(
        ControllerSettings,
        "from_environment",
        lambda: SimpleNamespace(role="api"),
    )
    monkeypatch.setattr(uvicorn, "run", run)

    assert main(["serve", "--host", "127.0.0.1", "--port", "8765"]) == 0
    assert observed == {
        "access_log": False,
        "app": "controlgraph_canary.services.api.app:app",
        "host": "127.0.0.1",
        "port": 8765,
    }


@pytest.mark.parametrize(
    ("command", "revision", "marker"),
    [
        (
            "serve-reference-stable",
            "controlgraph-reference-target-stable-v1",
            "controlgraph-stable-v1",
        ),
        (
            "serve-reference-candidate",
            "controlgraph-reference-target-candidate-v1",
            "controlgraph-candidate-v1",
        ),
    ],
)
def test_reference_entrypoints_are_fixed_and_disable_access_logs(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    revision: str,
    marker: str,
) -> None:
    import uvicorn

    observed: dict[str, object] = {}

    def run(app: object, **options: object) -> None:
        observed["probe"] = TestClient(app).get("/v1/probe").json()
        observed.update(options)

    monkeypatch.setenv("K_REVISION", revision)
    monkeypatch.setattr(uvicorn, "run", run)

    assert main([command, "--host", "127.0.0.1", "--port", "8766"]) == 0
    assert observed == {
        "access_log": False,
        "host": "127.0.0.1",
        "port": 8766,
        "probe": {
            "marker": marker,
            "revision": revision,
            "schema_version": "controlgraph.reference-probe/v1",
        },
    }
