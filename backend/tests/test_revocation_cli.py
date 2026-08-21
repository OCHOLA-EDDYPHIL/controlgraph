from __future__ import annotations

import argparse
import inspect
import subprocess

from revocation_proof_test_data import make_revocation_proof_records
from root_v2_test_data import PROJECT_NUMBER, make_root_v2_records

import controlgraph_canary.cli as cli_module
from controlgraph_canary.cli import _run_epoch_revocation, _run_revocation_proof
from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_CALL_OUTCOME_V1,
    EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1,
    EPOCH_REVOCATION_RESULT_V1,
    EpochRevocationCallOutcomeV1,
    EpochRevocationCommandV1,
    EpochRevocationEvidenceSubjectV1,
    EpochRevocationProofCommandV1,
    EpochRevocationResultV1,
    epoch_revocation_evidence_id,
)
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
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def __call__(self, argv: object, **options: object) -> subprocess.CompletedProcess[str]:
        arguments = tuple(argv)  # type: ignore[arg-type]
        self.calls.append((arguments, options))
        return subprocess.CompletedProcess(arguments, 0, stdout="header.payload.signature\n")


class _LostResponsePoster:
    def post(self, **values: object) -> InternalHttpResponse:
        del values
        raise TimeoutError("synthetic response loss")


def _args() -> argparse.Namespace:
    records = make_root_v2_records()
    return argparse.Namespace(
        project_number=PROJECT_NUMBER,
        root_id=records.root.root_id,
        expected_root_sha256=records.root.root_sha256,
        expected_epoch=1,
        reason="Stop the canary before delayed work executes.",
        request_id="request-revoke-cli-001",
        idempotency_key="revoke-cli-001",
        confirm="REVOKE",
    )


def _result(args: argparse.Namespace) -> EpochRevocationResultV1:
    records = make_root_v2_records()
    request_sha256 = "a" * 64
    evidence_id = epoch_revocation_evidence_id(
        request_sha256,
        args.expected_root_sha256,
        args.expected_epoch + 1,
    )
    committed_at = "2026-08-19T12:05:00Z"
    subject = EpochRevocationEvidenceSubjectV1(
        schema_version=EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1,
        root_id=args.root_id,
        root_sha256=args.expected_root_sha256,
        request_sha256=request_sha256,
        request_id=args.request_id,
        idempotency_key=args.idempotency_key,
        operator_identity="operator@example.test",
        operator_subject="123456789012345678901",
        reason=args.reason,
        service_claim_sha256="c" * 64,
        previous_authority_sha256="d" * 64,
        replacement_authority_sha256="e" * 64,
        previous_epoch=args.expected_epoch,
        new_epoch=args.expected_epoch + 1,
        evidence_id=evidence_id,
        committed_at=committed_at,
    )
    return EpochRevocationResultV1(
        schema_version=EPOCH_REVOCATION_RESULT_V1,
        result_id=f"cgrevoke:{request_sha256}",
        request_sha256=request_sha256,
        request_id=args.request_id,
        idempotency_key=args.idempotency_key,
        root_id=args.root_id,
        root_sha256=args.expected_root_sha256,
        target=records.root.content.target,
        operator_identity="operator@example.test",
        operator_subject="123456789012345678901",
        reason=args.reason,
        previous_epoch=args.expected_epoch,
        new_epoch=args.expected_epoch + 1,
        evidence_id=evidence_id,
        evidence_sha256="b" * 64,
        evidence_subject=subject,
        committed_at=committed_at,
    )


def _proof_args() -> argparse.Namespace:
    command = make_revocation_proof_records().proof_command
    return argparse.Namespace(
        project_number=PROJECT_NUMBER,
        root_id=command.root_id,
        root_sha256=command.root_sha256,
        previous_epoch=command.previous_epoch,
        new_epoch=command.new_epoch,
        reason=command.reason,
        request_sha256=command.request_sha256,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        result_id=command.result_id,
        evidence_id=command.evidence_id,
        evidence_sha256=command.evidence_sha256,
        attempt_id=command.attempt_id,
        audit_id=command.audit_id,
    )


def test_cli_uses_human_identity_token_and_one_shell_free_api_post(
    capsys: object,
) -> None:
    args = _args()
    result = _result(args)
    outcome = EpochRevocationCallOutcomeV1(
        schema_version=EPOCH_REVOCATION_CALL_OUTCOME_V1,
        attempt_id="cgrevoke-attempt-cli-001",
        audit_id="cgrevoke-attempt-cli-001",
        result=result,
    )
    runner = _Runner()
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(outcome),
        )
    )

    status = _run_epoch_revocation(
        args,
        command_runner=runner,
        http_poster=poster,
    )

    assert status == 0
    origin = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
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
    assert call["timeout"] == 60.0
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert "Authorization" not in headers
    assert headers[CONTROLGRAPH_AUTHORIZATION_HEADER] == "Bearer header.payload.signature"
    assert headers[SERVERLESS_AUTHORIZATION_HEADER] == "Bearer header.payload.signature"
    command = decode_contract(call["body"], EpochRevocationCommandV1)
    assert command.confirmation == "REVOKE"
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "header.payload.signature" not in output
    assert output.strip() == canonical_json_bytes(outcome).decode("utf-8")


def test_cli_rejects_unsealed_project_coordinates_without_auth_or_http() -> None:
    args = _args()
    args.project_number = "not-a-project-number"
    runner = _Runner()
    poster = _Poster(
        InternalHttpResponse(status_code=500, content_type=None, body=b"")
    )

    status = _run_epoch_revocation(
        args,
        command_runner=runner,
        http_poster=poster,
    )

    assert status == 2
    assert runner.calls == []
    assert poster.calls == []


def test_cli_rejects_a_response_not_bound_to_the_exact_reason(
    capsys: object,
) -> None:
    args = _args()
    original = _result(args)
    altered = original.model_copy(
        update={
            "reason": "Different operator reason.",
            "evidence_subject": original.evidence_subject.model_copy(
                update={"reason": "Different operator reason."}
            ),
        }
    )
    outcome = EpochRevocationCallOutcomeV1(
        schema_version=EPOCH_REVOCATION_CALL_OUTCOME_V1,
        attempt_id="cgrevoke-attempt-cli-altered",
        audit_id="cgrevoke-attempt-cli-altered",
        result=altered,
    )
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(outcome),
        )
    )

    status = _run_epoch_revocation(
        args,
        command_runner=_Runner(),
        http_poster=poster,
    )

    assert status == 6
    assert capsys.readouterr().out.strip() == '{"code": "REVOCATION_RESPONSE_INVALID"}'  # type: ignore[attr-defined]


def test_cli_has_no_direct_authority_or_provider_mutation_imports() -> None:
    source = inspect.getsource(cli_module)

    assert "google.cloud.firestore" not in source
    assert "integrations.google.firestore" not in source
    assert "integrations.google.kms" not in source
    assert "integrations.google.cloud_run" not in source


def test_cli_keeps_post_response_loss_and_server_failure_ambiguous(
    capsys: object,
) -> None:
    for poster in (
        _LostResponsePoster(),
        _Poster(
            InternalHttpResponse(
                status_code=503,
                content_type="application/json",
                body=b"",
            )
        ),
    ):
        status = _run_epoch_revocation(
            _args(),
            command_runner=_Runner(),
            http_poster=poster,
        )

        assert status == 4
        assert (  # type: ignore[attr-defined]
            capsys.readouterr().out.strip()
            == '{"code": "REVOCATION_OUTCOME_UNKNOWN"}'
        )


def test_proof_cli_uses_one_exact_authenticated_api_post(capsys: object) -> None:
    records = make_revocation_proof_records()
    runner = _Runner()
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(records.proof),
        )
    )

    status = _run_revocation_proof(
        _proof_args(),
        command_runner=runner,
        http_poster=poster,
    )

    assert status == 0
    origin = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
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
    assert call["timeout"] == 60.0
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert "Authorization" not in headers
    assert headers[CONTROLGRAPH_AUTHORIZATION_HEADER] == "Bearer header.payload.signature"
    assert headers[SERVERLESS_AUTHORIZATION_HEADER] == "Bearer header.payload.signature"
    command = decode_contract(call["body"], EpochRevocationProofCommandV1)
    assert command == records.proof_command
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "header.payload.signature" not in output
    assert output.strip() == canonical_json_bytes(records.proof).decode("utf-8")


def test_proof_cli_collapses_api_denial_without_echoing_payload(
    capsys: object,
) -> None:
    poster = _Poster(
        InternalHttpResponse(
            status_code=403,
            content_type="application/json",
            body=b'{"provider_diagnostic":"must-not-escape"}',
        )
    )

    status = _run_revocation_proof(
        _proof_args(),
        command_runner=_Runner(),
        http_poster=poster,
    )

    assert status == 5
    assert (  # type: ignore[attr-defined]
        capsys.readouterr().out.strip()
        == '{"code": "REVOCATION_PROOF_DENIED"}'
    )


def test_proof_cli_rejects_a_substituted_attempt(capsys: object) -> None:
    substituted = make_revocation_proof_records(
        attempt_id="cgrevoke-attempt-proof-substituted"
    )
    poster = _Poster(
        InternalHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(substituted.proof),
        )
    )

    status = _run_revocation_proof(
        _proof_args(),
        command_runner=_Runner(),
        http_poster=poster,
    )

    assert status == 6
    assert (  # type: ignore[attr-defined]
        capsys.readouterr().out.strip()
        == '{"code": "REVOCATION_PROOF_RESPONSE_INVALID"}'
    )
