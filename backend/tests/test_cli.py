import json

import pytest

from controlgraph_canary.cli import _doctor_report, main
from controlgraph_canary.settings import REQUIRED_ENVIRONMENT_KEYS


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
