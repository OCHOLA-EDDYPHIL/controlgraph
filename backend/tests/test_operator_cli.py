from __future__ import annotations

import argparse
import inspect
import io
import subprocess
from pathlib import Path
from typing import Any

import pytest
from health_execution_test_data import make_health_root, make_healthy_chain
from recovery_v2_test_data import make_revoked_v2_recovery_bundle
from root_v2_test_data import PROJECT_NUMBER, make_root_v2_records
from test_service_claim_release import _released_store

import controlgraph_canary.cli as cli_module
from controlgraph_canary.cli import (
    _build_parser,
    _run_apply_canary,
    _run_execution_receipt_read,
    _run_promotion,
    _run_recovery,
    _run_root_creation,
    _run_service_claim_release,
    _run_stable_snapshot_capture,
    _run_target_traffic_read,
)
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.canary_execution import (
    APPLY_CANARY_COMMAND_V1,
    CANARY_DISPATCH_RESULT_V1,
    ApplyCanaryCommandV1,
    CanaryDispatchResultV1,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    TrafficAllocation,
)
from controlgraph_canary.contracts.operator_observability import (
    EXECUTION_RECEIPT_READ_COMMAND_V1,
    EXECUTION_RECEIPT_READ_RESULT_V1,
    STABLE_SNAPSHOT_CAPTURE_COMMAND_V1,
    STABLE_SNAPSHOT_CAPTURE_REQUEST_V1,
    STABLE_SNAPSHOT_CAPTURE_RESULT_V1,
    TARGET_TRAFFIC_READ_COMMAND_V1,
    TARGET_TRAFFIC_READ_REQUEST_V1,
    TARGET_TRAFFIC_READ_RESULT_V1,
    ExecutionReceiptReadCommandV1,
    ExecutionReceiptReadResultV1,
    StableSnapshotCaptureCommandV1,
    StableSnapshotCaptureRequestV1,
    StableSnapshotCaptureResultV1,
    TargetTrafficReadCommandV1,
    TargetTrafficReadRequestV1,
    TargetTrafficReadResultV1,
)
from controlgraph_canary.contracts.promotion_execution import (
    PROMOTION_COMMAND_V2,
    PROMOTION_DISPATCH_RESULT_V2,
    PromotionCommandV2,
    PromotionDispatchResultV2,
    create_promotion_authorization,
)
from controlgraph_canary.contracts.recovery_execution import (
    RECOVERY_DISPATCH_RESULT_V2,
    RecoveryDispatchResultV2,
)
from controlgraph_canary.contracts.root_creation import (
    ROOT_CREATION_COMMAND_V1,
    RootCreationCommandV1,
)
from controlgraph_canary.contracts.service_claim_release import (
    ServiceClaimReleaseCommandV1,
)
from controlgraph_canary.contracts.storage import execution_receipt_logical_id
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.integrations.google.internal_transport import InternalHttpResponse


class _Poster:
    def __init__(self, response: InternalHttpResponse) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def post(self, **values: object) -> InternalHttpResponse:
        self.calls.append(values)
        return self.response


class _Runner:
    def __init__(self, *, returncode: int = 0, stderr: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def __call__(self, argv: object, **options: object) -> subprocess.CompletedProcess[str]:
        arguments = tuple(argv)  # type: ignore[arg-type]
        self.calls.append((arguments, options))
        return subprocess.CompletedProcess(
            arguments,
            self.returncode,
            stdout="header.payload.signature\n" if self.returncode == 0 else "",
            stderr=self.stderr,
        )


class _ExplodingRunner:
    def __call__(self, argv: object, **options: object) -> subprocess.CompletedProcess[str]:
        del argv, options
        raise RuntimeError("provider-secret-diagnostic")


class _BinaryStdin:
    def __init__(self, payload: bytes) -> None:
        self.buffer = io.BytesIO(payload)


def _success_fixtures(tmp_path: Path) -> list[tuple[Any, argparse.Namespace, object, object]]:
    records = make_root_v2_records()
    target = records.root.content.target
    plan = records.root.content.rollout_plan

    snapshot_command = StableSnapshotCaptureCommandV1(
        schema_version=STABLE_SNAPSHOT_CAPTURE_COMMAND_V1,
        request_id="snapshot-cli-001",
    )
    snapshot_request = StableSnapshotCaptureRequestV1(
        schema_version=STABLE_SNAPSHOT_CAPTURE_REQUEST_V1,
        request_id=snapshot_command.request_id,
        target=target,
    )
    snapshot_result = StableSnapshotCaptureResultV1(
        schema_version=STABLE_SNAPSHOT_CAPTURE_RESULT_V1,
        request=snapshot_request,
        request_sha256=canonical_sha256(snapshot_request),
        snapshot=records.root.content.stable_snapshot,
    )

    root_command = RootCreationCommandV1(
        schema_version=ROOT_CREATION_COMMAND_V1,
        request_id=records.creation_result.request_id,
        idempotency_key=records.creation_result.idempotency_key,
        expected_stable_snapshot=records.root.content.stable_snapshot,
    )
    root_file = tmp_path / "root-command.json"
    root_file.write_bytes(canonical_json_bytes(root_command))

    canary_command = ApplyCanaryCommandV1(
        schema_version=APPLY_CANARY_COMMAND_V1,
        root_id=records.root.root_id,
        expected_root_sha256=records.root.root_sha256,
        expected_epoch=1,
        request_id="apply-cli-001",
        idempotency_key="apply-cli-intent-001",
    )
    canary_result = CanaryDispatchResultV1(
        schema_version=CANARY_DISPATCH_RESULT_V1,
        request_id=canary_command.request_id,
        idempotency_key=canary_command.idempotency_key,
        target=target,
        root_id=canary_command.root_id,
        root_sha256=canary_command.expected_root_sha256,
        epoch=canary_command.expected_epoch,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=90,
        candidate_percent=10,
        capability_id="capability-apply-cli-001",
        capability_sha256="a" * 64,
        task_id="task-apply-cli-001",
        task_name=(
            f"projects/{target.project_id}/locations/us-central1/"
            f"queues/controlgraph-execution/tasks/cg-{'a' * 64}"
        ),
        enqueue_disposition="CREATED",
        scheduled_at="2026-08-19T12:02:00Z",
        expires_at="2026-08-19T12:10:00Z",
    )

    receipt = _denied_receipt(records.root.root_id, records.root.root_sha256)
    receipt_command = ExecutionReceiptReadCommandV1(
        schema_version=EXECUTION_RECEIPT_READ_COMMAND_V1,
        root_id=receipt.root_id,
        expected_root_sha256=receipt.root_sha256,
        expected_epoch=receipt.epoch,
        action=receipt.action,
        request_id=receipt.request_id,
        idempotency_key=receipt.idempotency_key,
        capability_sha256=receipt.capability_sha256,
    )
    receipt_result = ExecutionReceiptReadResultV1(
        schema_version=EXECUTION_RECEIPT_READ_RESULT_V1,
        command=receipt_command,
        command_sha256=canonical_sha256(receipt_command),
        receipt=receipt,
        storage_revision=1,
        receipt_sha256=canonical_sha256(receipt),
        verified_apply_receipt=None,
    )

    traffic_command = TargetTrafficReadCommandV1(
        schema_version=TARGET_TRAFFIC_READ_COMMAND_V1,
        request_id="traffic-cli-001",
    )
    traffic_request = TargetTrafficReadRequestV1(
        schema_version=TARGET_TRAFFIC_READ_REQUEST_V1,
        request_id=traffic_command.request_id,
        target=target,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        concurrency=8,
    )
    traffic = (TrafficAllocation(revision=plan.stable_revision, percent=100),)
    traffic_result = TargetTrafficReadResultV1(
        schema_version=TARGET_TRAFFIC_READ_RESULT_V1,
        request=traffic_request,
        request_sha256=canonical_sha256(traffic_request),
        traffic=traffic,
        traffic_statuses=traffic,
        service_generation=7,
        provider_etag="etag-traffic-cli-001",
        concurrency=traffic_request.concurrency,
        stable_revision_configuration_sha256="b" * 64,
        candidate_revision_configuration_sha256="c" * 64,
        target_configuration_sha256="d" * 64,
        observed_by=(f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"),
        observed_at="2026-08-19T12:05:00Z",
    )

    promotion_chain = make_healthy_chain()
    promotion_proof = promotion_chain.healthy_promotion_proof
    assert promotion_proof is not None
    promotion_authorization = create_promotion_authorization(
        root=make_health_root(),
        signed_health_chain=promotion_chain,
        request_id="promote-cli-001",
        idempotency_key="promote-cli-intent-001",
        scheduled_at=promotion_proof.issued_at,
    )
    promotion_command = PromotionCommandV2(
        schema_version=PROMOTION_COMMAND_V2,
        root_id=promotion_authorization.root_id,
        expected_root_sha256=promotion_authorization.root_sha256,
        expected_epoch=1,
        request_id="promote-cli-001",
        idempotency_key="promote-cli-intent-001",
        scheduled_at=promotion_authorization.scheduled_at,
        verified_apply_receipt=promotion_authorization.verified_apply_receipt,
        health_chain_locator=promotion_authorization.health_chain_locator,
    )
    promotion_file = tmp_path / "promotion-command.json"
    promotion_file.write_bytes(canonical_json_bytes(promotion_command))
    promotion_result = PromotionDispatchResultV2(
        schema_version=PROMOTION_DISPATCH_RESULT_V2,
        request_id=promotion_command.request_id,
        idempotency_key=promotion_command.idempotency_key,
        target=promotion_authorization.target,
        root_id=promotion_command.root_id,
        root_sha256=promotion_command.expected_root_sha256,
        epoch=promotion_command.expected_epoch,
        stable_revision=promotion_authorization.stable_revision,
        candidate_revision=promotion_authorization.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        provider_etag=promotion_authorization.provider_etag,
        verified_apply_receipt=promotion_authorization.verified_apply_receipt,
        source_receipt_sha256=promotion_authorization.source_receipt_sha256,
        expected_prestate_sha256=promotion_authorization.expected_prestate_sha256,
        terminal_health_decision_sha256=(
            promotion_authorization.terminal_health_decision_sha256
        ),
        health_chain_sha256=(
            promotion_authorization.health_chain_locator.health_chain_sha256
        ),
        health_chain_locator=promotion_authorization.health_chain_locator,
        healthy_promotion_proof_sha256=(
            promotion_authorization.healthy_promotion_proof_sha256
        ),
        desired_poststate_sha256=promotion_authorization.desired_poststate_sha256,
        proof_valid_until=promotion_authorization.proof_valid_until,
        promotion_authorization_sha256=canonical_sha256(promotion_authorization),
        capability_id=promotion_authorization.capability_id,
        capability_sha256="e" * 64,
        task_id="task-promote-cli-001",
        task_name=(
            f"projects/{promotion_authorization.target.project_id}/locations/us-central1/"
            f"queues/controlgraph-execution/tasks/cg-{'e' * 64}"
        ),
        enqueue_disposition="CREATED",
        scheduled_at=promotion_authorization.scheduled_at,
        expires_at="2026-08-21T12:10:00Z",
    )

    release_invocation, _release_store, release_result = _released_store()
    release_command = release_invocation.command
    release_file = tmp_path / "service-claim-release-command.json"
    release_file.write_bytes(canonical_json_bytes(release_command))

    return [
        (
            _run_stable_snapshot_capture,
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                request_id=snapshot_command.request_id,
            ),
            snapshot_command,
            snapshot_result,
        ),
        (
            _run_root_creation,
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(root_file),
            ),
            root_command,
            records.creation_result,
        ),
        (
            _run_apply_canary,
            _authority_args(canary_command),
            canary_command,
            canary_result,
        ),
        (
            _run_execution_receipt_read,
            argparse.Namespace(
                **vars(_authority_args(receipt_command)),
                action=receipt_command.action,
                capability_sha256=receipt_command.capability_sha256,
            ),
            receipt_command,
            receipt_result,
        ),
        (
            _run_target_traffic_read,
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                request_id=traffic_command.request_id,
            ),
            traffic_command,
            traffic_result,
        ),
        (
            _run_promotion,
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(promotion_file),
            ),
            promotion_command,
            promotion_result,
        ),
        (
            _run_service_claim_release,
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(release_file),
            ),
            release_command,
            release_result,
        ),
    ]


def _authority_args(
    command: ApplyCanaryCommandV1 | ExecutionReceiptReadCommandV1,
) -> argparse.Namespace:
    return argparse.Namespace(
        project_number=PROJECT_NUMBER,
        root_id=command.root_id,
        expected_root_sha256=command.expected_root_sha256,
        expected_epoch=command.expected_epoch,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
    )


def _denied_receipt(
    root_id: str,
    root_sha256: str,
    *,
    suffix: str = "001",
) -> ExecutionReceipt:
    records = make_root_v2_records()
    idempotency_key = f"promote-denied-cli-intent-{suffix}"
    return ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(
            records.root.content.target,
            idempotency_key,
        ),
        request_id=f"promote-denied-cli-{suffix}",
        idempotency_key=idempotency_key,
        capability_sha256="5" * 64,
        mutation_sha256="6" * 64,
        plan_sha256="7" * 64,
        expected_poststate_sha256="8" * 64,
        target=records.root.content.target,
        root_id=root_id,
        root_sha256=root_sha256,
        epoch=1,
        action=CapabilityAction.PROMOTE_CANDIDATE,
        provider_etag="etag-canary-cli-001",
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.DENIED,
        reason_code=ReasonCode.EPOCH_MISMATCH,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=2,
        created_at="2026-08-19T12:01:00Z",
        updated_at="2026-08-19T12:02:00Z",
        evidence_ids=(f"evidence-promote-denied-cli-{suffix}",),
    )


def test_parser_exposes_only_named_operator_commands_and_typed_fields() -> None:
    parser = _build_parser()
    parsed = parser.parse_args(
        [
            "read-execution-receipt",
            "--project-number",
            PROJECT_NUMBER,
            "--root-id",
            "root-cli-001",
            "--expected-root-sha256",
            "a" * 64,
            "--expected-epoch",
            "1",
            "--action",
            CapabilityAction.APPLY_CANARY.value,
            "--request-id",
            "request-cli-001",
            "--idempotency-key",
            "intent-cli-001",
            "--capability-sha256",
            "b" * 64,
        ]
    )
    assert parsed.action is CapabilityAction.APPLY_CANARY

    recovery_receipt = parser.parse_args(
        [
            "read-execution-receipt",
            "--project-number",
            PROJECT_NUMBER,
            "--root-id",
            "root-cli-recovery-001",
            "--expected-root-sha256",
            "c" * 64,
            "--expected-epoch",
            "2",
            "--action",
            CapabilityAction.RECOVER_STABLE.value,
            "--request-id",
            "request-cli-recovery-001",
            "--idempotency-key",
            "intent-cli-recovery-001",
            "--capability-sha256",
            "d" * 64,
        ]
    )
    assert recovery_receipt.action is CapabilityAction.RECOVER_STABLE

    release = parser.parse_args(
        [
            "release-service-claim",
            "--project-number",
            PROJECT_NUMBER,
            "--command-file",
            "release.json",
        ]
    )
    assert release.command_file == "release.json"

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "capture-stable-snapshot",
                "--project-number",
                PROJECT_NUMBER,
                "--request-id",
                "request-cli-001",
                "--url",
                "https://example.invalid",
            ]
        )
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "read-target-traffic",
                "--project-number",
                PROJECT_NUMBER,
                "--request-id",
                "request-cli-001",
                "--endpoint",
                "other-service",
            ]
        )


def test_main_routes_service_claim_release_to_the_typed_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[argparse.Namespace] = []

    def run(args: argparse.Namespace) -> int:
        observed.append(args)
        return 17

    monkeypatch.setattr(cli_module, "_run_service_claim_release", run)

    assert (
        cli_module.main(
            [
                "release-service-claim",
                "--project-number",
                PROJECT_NUMBER,
                "--command-file",
                "release.json",
            ]
        )
        == 17
    )
    assert len(observed) == 1
    assert observed[0].project_number == PROJECT_NUMBER
    assert observed[0].command_file == "release.json"


def test_all_operator_commands_use_one_fixed_shell_free_api_post(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    origin = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
    for run, args, command, result in _success_fixtures(tmp_path):
        runner = _Runner()
        poster = _Poster(
            InternalHttpResponse(
                status_code=200,
                content_type="application/json",
                body=canonical_json_bytes(result),  # type: ignore[arg-type]
            )
        )

        status = run(args, command_runner=runner, http_poster=poster)

        assert status == 0
        assert runner.calls == [
            (
                (
                    "gcloud",
                    "auth",
                    "print-identity-token",
                ),
                {
                    "capture_output": True,
                    "text": True,
                    "check": False,
                    "timeout": 10.0,
                    "shell": False,
                },
            )
        ]
        assert len(poster.calls) == 1
        call = poster.calls[0]
        assert call["url"] == f"{origin}/v1/operator/commands"
        assert call["body"] == canonical_json_bytes(command)  # type: ignore[arg-type]
        assert call["timeout"] == 30.0
        assert call["headers"] == {
            "Accept": "application/json",
            "Content-Type": "application/json",
            CONTROLGRAPH_AUTHORIZATION_HEADER: "Bearer header.payload.signature",
            SERVERLESS_AUTHORIZATION_HEADER: "Bearer header.payload.signature",
        }
        output = capsys.readouterr().out
        assert "header.payload.signature" not in output
        assert output.strip() == canonical_json_bytes(result).decode("utf-8")  # type: ignore[arg-type]


def test_complex_commands_decode_exact_type_before_token_acquisition(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixtures = _success_fixtures(tmp_path)
    root_command = fixtures[1][2]
    promotion_command = fixtures[5][2]
    release_command = fixtures[6][2]
    root_file = tmp_path / "root-substitution.json"
    promotion_file = tmp_path / "promotion-substitution.json"
    release_file = tmp_path / "release-substitution.json"
    root_file.write_bytes(canonical_json_bytes(promotion_command))  # type: ignore[arg-type]
    promotion_file.write_bytes(canonical_json_bytes(root_command))  # type: ignore[arg-type]
    release_file.write_bytes(canonical_json_bytes(promotion_command))  # type: ignore[arg-type]

    for run, args, code in (
        (
            _run_root_creation,
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(root_file),
            ),
            "ROOT_CREATION_COMMAND_INVALID",
        ),
        (
            _run_promotion,
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(promotion_file),
            ),
            "PROMOTION_COMMAND_INVALID",
        ),
        (
            _run_service_claim_release,
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(release_file),
            ),
            "SERVICE_CLAIM_RELEASE_COMMAND_INVALID",
        ),
    ):
        runner = _Runner()
        poster = _Poster(InternalHttpResponse(status_code=500, content_type=None, body=b""))
        assert run(args, command_runner=runner, http_poster=poster) == 2
        assert runner.calls == []
        assert poster.calls == []
        assert capsys.readouterr().out.strip() == f'{{"code": "{code}"}}'

    assert type(release_command) is ServiceClaimReleaseCommandV1


def test_canonical_stdin_is_decoded_before_root_creation_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, _args, command, result = _success_fixtures(tmp_path)[1]
    monkeypatch.setattr(cli_module.sys, "stdin", _BinaryStdin(canonical_json_bytes(command)))
    args = argparse.Namespace(project_number=PROJECT_NUMBER, command_file="-")
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(result),  # type: ignore[arg-type]
        )
    )

    assert run(args, command_runner=_Runner(), http_poster=poster) == 0
    assert len(poster.calls) == 1


def test_noncanonical_complex_command_is_rejected_before_auth(
    tmp_path: Path,
) -> None:
    _run, _args, command, _result = _success_fixtures(tmp_path)[1]
    command_file = tmp_path / "noncanonical-root-command.json"
    command_file.write_bytes(canonical_json_bytes(command) + b"\n")  # type: ignore[arg-type]
    runner = _Runner()
    poster = _Poster(InternalHttpResponse(status_code=500, content_type=None, body=b""))

    assert (
        _run_root_creation(
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(command_file),
            ),
            command_runner=runner,
            http_poster=poster,
        )
        == 2
    )
    assert runner.calls == []
    assert poster.calls == []


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"schema_version":"controlgraph.service-claim-release-command/v1"}',
        b"[]",
    ],
)
def test_invalid_service_claim_release_is_rejected_before_auth(
    payload: bytes,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    command_file = tmp_path / "invalid-release-command.json"
    command_file.write_bytes(payload)
    runner = _Runner()
    poster = _Poster(InternalHttpResponse(status_code=500, content_type=None, body=b""))

    assert (
        _run_service_claim_release(
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(command_file),
            ),
            command_runner=runner,
            http_poster=poster,
        )
        == 2
    )
    assert runner.calls == []
    assert poster.calls == []
    assert (
        capsys.readouterr().out.strip()
        == '{"code": "SERVICE_CLAIM_RELEASE_COMMAND_INVALID"}'
    )


def test_noncanonical_service_claim_release_is_rejected_before_auth(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _run, _args, command, _result = _success_fixtures(tmp_path)[6]
    command_file = tmp_path / "noncanonical-release-command.json"
    command_file.write_bytes(canonical_json_bytes(command) + b"\n")  # type: ignore[arg-type]
    runner = _Runner()
    poster = _Poster(InternalHttpResponse(status_code=500, content_type=None, body=b""))

    assert (
        _run_service_claim_release(
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(command_file),
            ),
            command_runner=runner,
            http_poster=poster,
        )
        == 2
    )
    assert runner.calls == []
    assert poster.calls == []
    assert (
        capsys.readouterr().out.strip()
        == '{"code": "SERVICE_CLAIM_RELEASE_COMMAND_INVALID"}'
    )


@pytest.mark.parametrize(
    ("update", "filename"),
    [
        ({"request_id": "other-release-request"}, "request-mismatch.json"),
        (
            {"terminal_receipt_idempotency_key": "other-terminal-receipt"},
            "terminal-mismatch.json",
        ),
    ],
)
def test_service_claim_release_result_must_match_the_exact_command(
    update: dict[str, str],
    filename: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _run, _args, command, result = _success_fixtures(tmp_path)[6]
    assert type(command) is ServiceClaimReleaseCommandV1
    mismatched_command = command.model_copy(update=update)
    command_file = tmp_path / filename
    command_file.write_bytes(canonical_json_bytes(mismatched_command))
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(result),  # type: ignore[arg-type]
        )
    )

    assert (
        _run_service_claim_release(
            argparse.Namespace(
                project_number=PROJECT_NUMBER,
                command_file=str(command_file),
            ),
            command_runner=_Runner(),
            http_poster=poster,
        )
        == 6
    )
    assert len(poster.calls) == 1
    assert (
        capsys.readouterr().out.strip()
        == '{"code": "SERVICE_CLAIM_RELEASE_RESPONSE_INVALID"}'
    )


def test_service_claim_release_rejects_another_valid_result_contract(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixtures = _success_fixtures(tmp_path)
    run, args, _command, _result = fixtures[6]
    promotion_result = fixtures[5][3]

    assert (
        run(
            args,
            command_runner=_Runner(),
            http_poster=_Poster(
                InternalHttpResponse(
                    status_code=200,
                    content_type="application/json",
                    body=canonical_json_bytes(promotion_result),  # type: ignore[arg-type]
                )
            ),
        )
        == 6
    )
    assert (
        capsys.readouterr().out.strip()
        == '{"code": "SERVICE_CLAIM_RELEASE_RESPONSE_INVALID"}'
    )


def test_every_result_is_bound_to_the_exact_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixtures = _success_fixtures(tmp_path)
    snapshot_result = fixtures[0][3]
    other_snapshot_request = snapshot_result.request.model_copy(  # type: ignore[union-attr]
        update={"request_id": "other-snapshot-request"}
    )
    other_snapshot_result = snapshot_result.model_copy(  # type: ignore[union-attr]
        update={
            "request": other_snapshot_request,
            "request_sha256": canonical_sha256(other_snapshot_request),
        }
    )

    canary_result = fixtures[2][3]
    other_canary_result = canary_result.model_copy(  # type: ignore[union-attr]
        update={"request_id": "other-canary-request"}
    )

    records = make_root_v2_records()
    other_receipt = _denied_receipt(
        records.root.root_id,
        records.root.root_sha256,
        suffix="002",
    )
    other_receipt_command = ExecutionReceiptReadCommandV1(
        schema_version=EXECUTION_RECEIPT_READ_COMMAND_V1,
        root_id=other_receipt.root_id,
        expected_root_sha256=other_receipt.root_sha256,
        expected_epoch=other_receipt.epoch,
        action=other_receipt.action,
        request_id=other_receipt.request_id,
        idempotency_key=other_receipt.idempotency_key,
        capability_sha256=other_receipt.capability_sha256,
    )
    other_receipt_result = ExecutionReceiptReadResultV1(
        schema_version=EXECUTION_RECEIPT_READ_RESULT_V1,
        command=other_receipt_command,
        command_sha256=canonical_sha256(other_receipt_command),
        receipt=other_receipt,
        storage_revision=1,
        receipt_sha256=canonical_sha256(other_receipt),
        verified_apply_receipt=None,
    )

    traffic_result = fixtures[4][3]
    other_traffic_request = traffic_result.request.model_copy(  # type: ignore[union-attr]
        update={"request_id": "other-traffic-request"}
    )
    other_traffic_result = traffic_result.model_copy(  # type: ignore[union-attr]
        update={
            "request": other_traffic_request,
            "request_sha256": canonical_sha256(other_traffic_request),
        }
    )

    promotion_result = fixtures[5][3]
    other_promotion_result = promotion_result.model_copy(  # type: ignore[union-attr]
        update={
            "request_id": "other-promotion-request",
            "idempotency_key": "other-promotion-intent",
        }
    )
    other_promotion_schedule = promotion_result.model_copy(  # type: ignore[union-attr]
        update={"scheduled_at": "2026-08-19T12:06:01Z"}
    )

    substitutions = (
        (*fixtures[0][:2], other_snapshot_result, "SNAPSHOT_RESPONSE_INVALID"),
        (
            *fixtures[1][:2],
            make_root_v2_records(variant=2).creation_result,
            "ROOT_CREATION_RESPONSE_INVALID",
        ),
        (*fixtures[2][:2], other_canary_result, "CANARY_RESPONSE_INVALID"),
        (*fixtures[3][:2], other_receipt_result, "RECEIPT_READ_RESPONSE_INVALID"),
        (*fixtures[4][:2], other_traffic_result, "TRAFFIC_READ_RESPONSE_INVALID"),
        (*fixtures[5][:2], other_promotion_result, "PROMOTION_RESPONSE_INVALID"),
        (*fixtures[5][:2], other_promotion_schedule, "PROMOTION_RESPONSE_INVALID"),
    )
    for run, args, result, code in substitutions:
        status = run(
            args,
            command_runner=_Runner(),
            http_poster=_Poster(
                InternalHttpResponse(
                    status_code=200,
                    content_type="application/json",
                    body=canonical_json_bytes(result),  # type: ignore[arg-type]
                )
            ),
        )

        assert status == 6
        assert capsys.readouterr().out.strip() == f'{{"code": "{code}"}}'


def test_result_contract_version_substitution_is_rejected(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixtures = _success_fixtures(tmp_path)
    run, args, _command, _snapshot_result = fixtures[0]
    traffic_result = fixtures[4][3]

    assert (
        run(
            args,
            command_runner=_Runner(),
            http_poster=_Poster(
                InternalHttpResponse(
                    status_code=200,
                    content_type="application/json",
                    body=canonical_json_bytes(traffic_result),  # type: ignore[arg-type]
                )
            ),
        )
        == 6
    )
    assert capsys.readouterr().out.strip() == '{"code": "SNAPSHOT_RESPONSE_INVALID"}'


@pytest.mark.parametrize(
    ("response", "expected_status", "expected_code"),
    [
        (
            InternalHttpResponse(  # type: ignore[arg-type]
                status_code="500",
                content_type="application/json",
                body=b"{}",
            ),
            4,
            "SNAPSHOT_OUTCOME_UNKNOWN",
        ),
        (
            InternalHttpResponse(
                status_code=999,
                content_type="application/json",
                body=b"{}",
            ),
            4,
            "SNAPSHOT_OUTCOME_UNKNOWN",
        ),
        (
            InternalHttpResponse(  # type: ignore[arg-type]
                status_code=200,
                content_type=["application/json"],
                body=b"{}",
            ),
            4,
            "SNAPSHOT_OUTCOME_UNKNOWN",
        ),
        (
            InternalHttpResponse(  # type: ignore[arg-type]
                status_code=200,
                content_type="application/json",
                body="{}",
            ),
            4,
            "SNAPSHOT_OUTCOME_UNKNOWN",
        ),
        (
            InternalHttpResponse(
                status_code=200,
                content_type="application/json",
                body=b"",
            ),
            4,
            "SNAPSHOT_OUTCOME_UNKNOWN",
        ),
        (
            InternalHttpResponse(
                status_code=200,
                content_type="application/json",
                body=b"x" * (MAX_CONTRACT_BYTES + 1),
            ),
            4,
            "SNAPSHOT_OUTCOME_UNKNOWN",
        ),
        (
            InternalHttpResponse(
                status_code=200,
                content_type="text/plain",
                body=b"{}",
            ),
            4,
            "SNAPSHOT_OUTCOME_UNKNOWN",
        ),
        (
            InternalHttpResponse(
                status_code=204,
                content_type=None,
                body=b"",
            ),
            4,
            "SNAPSHOT_OUTCOME_UNKNOWN",
        ),
        (
            InternalHttpResponse(
                status_code=403,
                content_type=None,
                body=b"",
            ),
            5,
            "SNAPSHOT_API_DENIED",
        ),
    ],
)
def test_malformed_post_responses_never_become_command_errors(
    response: InternalHttpResponse,
    expected_status: int,
    expected_code: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run, args, _command, _result = _success_fixtures(tmp_path)[0]
    poster = _Poster(response)

    assert run(args, command_runner=_Runner(), http_poster=poster) == expected_status
    assert len(poster.calls) == 1
    assert capsys.readouterr().out.strip() == f'{{"code": "{expected_code}"}}'


@pytest.mark.parametrize("runner", [_Runner(returncode=1, stderr="secret"), _ExplodingRunner()])
def test_auth_failures_never_expose_provider_diagnostics(
    runner: object,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run, args, _command, _result = _success_fixtures(tmp_path)[0]
    poster = _Poster(
        InternalHttpResponse(status_code=200, content_type="application/json", body=b"{}")
    )

    assert run(args, command_runner=runner, http_poster=poster) == 3
    assert poster.calls == []
    output = capsys.readouterr().out
    assert output.strip() == '{"code": "SNAPSHOT_AUTH_UNAVAILABLE"}'
    assert "secret" not in output
    assert "provider" not in output


def test_invalid_project_is_rejected_before_auth_or_post(tmp_path: Path) -> None:
    run, args, _command, _result = _success_fixtures(tmp_path)[0]
    args.project_number = "projects/arbitrary/locations/global"
    runner = _Runner()
    poster = _Poster(InternalHttpResponse(status_code=500, content_type=None, body=b""))

    assert run(args, command_runner=runner, http_poster=poster) == 2
    assert runner.calls == []
    assert poster.calls == []


def test_cli_has_no_direct_cloud_store_kms_run_or_raw_http_paths() -> None:
    source = inspect.getsource(cli_module)

    assert "google.cloud.firestore" not in source
    assert "integrations.google.firestore" not in source
    assert "integrations.google.kms" not in source
    assert "integrations.google.cloud_run" not in source
    assert "import urllib" not in source
    assert "from urllib" not in source
    assert "import requests" not in source
    assert "from requests" not in source


def _recovery_cli_fixture(
    tmp_path: Path,
) -> tuple[argparse.Namespace, object, RecoveryDispatchResultV2]:
    bundle = make_revoked_v2_recovery_bundle()
    command_file = tmp_path / "recovery-command.json"
    command_file.write_bytes(canonical_json_bytes(bundle.command))
    authorization = bundle.authorization
    task = bundle.task
    result = RecoveryDispatchResultV2(
        schema_version=RECOVERY_DISPATCH_RESULT_V2,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_schema_version=authorization.root_schema_version,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        stable_revision=authorization.stable_revision,
        stable_revision_configuration_sha256=(
            authorization.stable_revision_configuration_sha256
        ),
        candidate_revision=authorization.candidate_revision,
        candidate_revision_configuration_sha256=(
            authorization.candidate_revision_configuration_sha256
        ),
        stable_percent=100,
        candidate_percent=0,
        concurrency=authorization.concurrency,
        provider_etag=authorization.current_provider_etag,
        verified_apply_receipt=authorization.verified_apply_receipt,
        source_receipt_sha256=authorization.source_receipt_sha256,
        trigger_basis=authorization.source.basis,
        trigger_proof_sha256=authorization.trigger_proof_sha256,
        prestate_attestation_sha256=authorization.prestate_attestation_sha256,
        expected_prestate_sha256=authorization.expected_prestate_sha256,
        desired_poststate_sha256=authorization.desired_poststate_sha256,
        proof_valid_until=authorization.proof_valid_until,
        recovery_authorization_sha256=canonical_sha256(authorization),
        capability_id=authorization.capability_id,
        capability_sha256=canonical_sha256(task.capability),
        task_id=task.task_id,
        task_name=(
            f"projects/{authorization.target.project_id}/locations/us-central1/"
            f"queues/controlgraph-recovery/tasks/cg-{canonical_sha256(task)}"
        ),
        enqueue_disposition="CREATED",
        scheduled_at=task.scheduled_at,
        expires_at=task.expires_at,
    )
    return (
        argparse.Namespace(
            project_number=PROJECT_NUMBER,
            command_file=str(command_file),
        ),
        bundle.command,
        result,
    )


def test_recovery_cli_posts_one_exact_revoked_v2_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args, command, result = _recovery_cli_fixture(tmp_path)
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(result),
        )
    )

    assert _run_recovery(args, command_runner=_Runner(), http_poster=poster) == 0
    assert len(poster.calls) == 1
    assert poster.calls[0]["body"] == canonical_json_bytes(command)  # type: ignore[arg-type]
    assert capsys.readouterr().out.strip() == canonical_json_bytes(result).decode()


def test_recovery_cli_rejects_substituted_result(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args, _command, result = _recovery_cli_fixture(tmp_path)
    substituted = result.model_copy(update={"request_id": "other-recovery-request"})
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(substituted),
        )
    )

    assert _run_recovery(args, command_runner=_Runner(), http_poster=poster) == 6
    assert capsys.readouterr().out.strip() == '{"code": "RECOVERY_RESPONSE_INVALID"}'
