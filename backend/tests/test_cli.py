import json
from types import SimpleNamespace

import pytest

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
