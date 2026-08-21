from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from root_v2_test_data import PROJECT_NUMBER
from test_health_pipeline import _Clock, _pipeline

from controlgraph_canary.cli import _build_parser, _run_health_evaluation
from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.health_pipeline import (
    HealthEvaluationCommandV1,
    HealthEvaluationResultV1,
)
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.integrations.google.internal_transport import (
    InternalHttpResponse,
)

_TOKEN = "header.payload.signature"


class _Runner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        capture_output: bool,
        text: bool,
        check: bool,
        timeout: float,
        shell: bool,
    ) -> subprocess.CompletedProcess[str]:
        options = {
            "capture_output": capture_output,
            "text": text,
            "check": check,
            "timeout": timeout,
            "shell": shell,
        }
        self.calls.append((tuple(argv), options))
        return subprocess.CompletedProcess(
            tuple(argv),
            0,
            stdout=f"{_TOKEN}\n",
            stderr="",
        )


class _Poster:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls: list[dict[str, object]] = []

    def post(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> InternalHttpResponse:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        return InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=self.body,
        )


def _health_fixture(
    tmp_path: Path,
) -> tuple[Path, HealthEvaluationCommandV1, HealthEvaluationResultV1]:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    api, _, _, _, command, operator, _, _ = _pipeline(clock=clock)
    result = asyncio.run(api.evaluate(command, operator))
    command_file = tmp_path / "health-evaluation-command.json"
    command_file.write_bytes(canonical_json_bytes(command))
    return command_file, command, result


def _args(command_file: Path) -> argparse.Namespace:
    return argparse.Namespace(
        project_number=PROJECT_NUMBER,
        command_file=str(command_file),
    )


def _altered_payload(command: HealthEvaluationCommandV1, **updates: object) -> bytes:
    values = command.model_dump(mode="json")
    values.update(updates)
    return json.dumps(
        values,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _different_digest(value: str) -> str:
    return "0" * 64 if value != "0" * 64 else "1" * 64


def _validated_result(
    result: HealthEvaluationResultV1,
    **updates: object,
) -> HealthEvaluationResultV1:
    changed = result.model_copy(update=updates)
    return HealthEvaluationResultV1.model_validate(changed.model_dump(mode="python"))


def test_evaluate_health_parser_requires_the_exact_command_source() -> None:
    args = _build_parser().parse_args(
        [
            "evaluate-health",
            "--project-number",
            PROJECT_NUMBER,
            "--command-file",
            "health.json",
        ]
    )

    assert args.command == "evaluate-health"
    assert args.project_number == PROJECT_NUMBER
    assert args.command_file == "health.json"


def test_evaluate_health_posts_and_prints_the_exact_bound_result(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    command_file, command, result = _health_fixture(tmp_path)
    runner = _Runner()
    poster = _Poster(canonical_json_bytes(result))

    status = _run_health_evaluation(
        _args(command_file),
        command_runner=runner,
        http_poster=poster,
    )

    assert status == 0
    assert runner.calls == [
        (
            ("gcloud", "auth", "print-identity-token"),
            {
                "capture_output": True,
                "text": True,
                "check": False,
                "timeout": 10.0,
                "shell": False,
            },
        )
    ]
    assert poster.calls == [
        {
            "url": (
                f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app/"
                "v1/operator/commands"
            ),
            "headers": {
                "Accept": "application/json",
                "Content-Type": "application/json",
                CONTROLGRAPH_AUTHORIZATION_HEADER: f"Bearer {_TOKEN}",
                SERVERLESS_AUTHORIZATION_HEADER: f"Bearer {_TOKEN}",
            },
            "body": canonical_json_bytes(command),
            "timeout": 30.0,
        }
    ]
    assert decode_contract(
        poster.calls[0]["body"],  # type: ignore[arg-type]
        HealthEvaluationCommandV1,
    ) == command
    assert capsys.readouterr().out.strip() == canonical_json_bytes(result).decode()


@pytest.mark.parametrize(
    "updates",
    [
        {"schema_version": "controlgraph.health-evaluation-command/v0"},
        {"unexpected_field": True},
    ],
)
def test_evaluate_health_rejects_legacy_or_invalid_command_before_auth(
    updates: dict[str, object],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, command, result = _health_fixture(tmp_path)
    command_file = tmp_path / "invalid-health-evaluation-command.json"
    command_file.write_bytes(_altered_payload(command, **updates))
    runner = _Runner()
    poster = _Poster(canonical_json_bytes(result))

    status = _run_health_evaluation(
        _args(command_file),
        command_runner=runner,
        http_poster=poster,
    )

    assert status == 2
    assert runner.calls == []
    assert poster.calls == []
    assert (
        capsys.readouterr().out.strip()
        == '{"code": "HEALTH_EVALUATION_COMMAND_INVALID"}'
    )


def test_evaluate_health_rejects_every_mismatched_result_binding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    command_file, command, result = _health_fixture(tmp_path)
    other_root_sha256 = _different_digest(result.root_sha256)
    other_target = result.target.model_copy(
        update={"project_id": "controlgraph-canary-z9y8x7"}
    )
    other_receipt = result.verified_apply_receipt.model_copy(
        update={
            "receipt_sha256": _different_digest(
                result.verified_apply_receipt.receipt_sha256
            )
        }
    )
    mismatches = (
        _validated_result(result, request_id="other-health-request"),
        _validated_result(result, idempotency_key="other-health-idempotency"),
        _validated_result(
            result,
            command_sha256=_different_digest(result.command_sha256),
        ),
        _validated_result(result, target=other_target),
        _validated_result(
            result,
            root_id=f"cgroot:{other_root_sha256}",
            root_sha256=other_root_sha256,
        ),
        _validated_result(result, epoch=result.epoch + 1),
        _validated_result(result, verified_apply_receipt=other_receipt),
        _validated_result(
            result,
            expected_sequence=1,
            expected_chain_head_sha256="e" * 64,
            terminal_sequence=2,
        ),
    )

    for mismatch in mismatches:
        runner = _Runner()
        poster = _Poster(canonical_json_bytes(mismatch))

        status = _run_health_evaluation(
            _args(command_file),
            command_runner=runner,
            http_poster=poster,
        )

        assert status == 6
        assert len(runner.calls) == 1
        assert len(poster.calls) == 1
        assert poster.calls[0]["body"] == canonical_json_bytes(command)
        assert (
            capsys.readouterr().out.strip()
            == '{"code": "HEALTH_EVALUATION_RESPONSE_INVALID"}'
        )
