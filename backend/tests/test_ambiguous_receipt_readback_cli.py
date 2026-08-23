from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from controlgraph_canary.ambiguous_receipt_readback_cli import (
    AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV,
    main,
)
from controlgraph_canary.application.ambiguous_receipt_readback import (
    AmbiguousReceiptReadbackError,
    AmbiguousReceiptReadbackErrorCode,
)
from controlgraph_canary.contracts.ambiguous_receipt_readback import (
    AMBIGUOUS_RECEIPT_READBACK_COMMAND_V1,
    AmbiguousReceiptReadbackCommandV1,
    AmbiguousReceiptReadbackDisposition,
    AmbiguousReceiptReadbackResultV1,
    ambiguous_receipt_readback_result,
    ambiguous_receipt_resolution_evidence_id,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.receipt_authority import StoredExecutionReceiptV1
from controlgraph_canary.contracts.storage import execution_receipt_logical_id


def _command(
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
) -> AmbiguousReceiptReadbackCommandV1:
    return AmbiguousReceiptReadbackCommandV1(
        schema_version=AMBIGUOUS_RECEIPT_READBACK_COMMAND_V1,
        root_id=f"cgroot:{'1' * 64}",
        expected_root_sha256="1" * 64,
        expected_epoch=1,
        action=action,
        request_id="request-001",
        idempotency_key="idempotency-001",
        capability_sha256="2" * 64,
        expected_receipt_sha256="3" * 64,
        expected_storage_revision=2,
        expected_ambiguous_observed_etag="etag-ambiguous-7",
        expected_ambiguous_updated_at="2026-08-19T12:03:00Z",
        confirmation="READBACK_ONLY",
    )


def _successful_contracts() -> tuple[
    AmbiguousReceiptReadbackCommandV1,
    AmbiguousReceiptReadbackResultV1,
]:
    target = TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id="controlgraph-canary-abc123",
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )
    ambiguous = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(target, "idempotency-001"),
        request_id="request-001",
        idempotency_key="idempotency-001",
        capability_sha256="2" * 64,
        mutation_sha256="4" * 64,
        plan_sha256="5" * 64,
        expected_poststate_sha256="6" * 64,
        target=target,
        root_id=f"cgroot:{'1' * 64}",
        root_sha256="1" * 64,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag="etag-stable-6",
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.AMBIGUOUS,
        reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
        provider_operation=(
            "projects/controlgraph-canary-abc123/locations/us-central1/"
            "operations/readback-001"
        ),
        observed_etag="etag-ambiguous-7",
        observed_authority_epoch=1,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:03:00Z",
        evidence_ids=("evidence-readback-001",),
    )
    command = _command().model_copy(
        update={"expected_receipt_sha256": canonical_sha256(ambiguous)}
    )
    verified = ExecutionReceipt(
        **{
            **ambiguous.model_dump(mode="python"),
            "outcome": ReceiptOutcome.VERIFIED,
            "reason_code": None,
            "observed_etag": "etag-verified-8",
            "updated_at": "2026-08-19T12:04:00Z",
            "evidence_ids": (
                *ambiguous.evidence_ids,
                ambiguous_receipt_resolution_evidence_id(command),
            ),
        }
    )
    result = ambiguous_receipt_readback_result(
        command=command,
        disposition=AmbiguousReceiptReadbackDisposition.RESOLVED,
        stored_receipt=StoredExecutionReceiptV1(
            schema_version="controlgraph.stored-execution-receipt/v1",
            receipt=verified,
            storage_revision=3,
        ),
    )
    return command, result


class _DeniedResolver:
    async def resolve(self, command: AmbiguousReceiptReadbackCommandV1) -> None:
        del command
        raise AmbiguousReceiptReadbackError(
            AmbiguousReceiptReadbackErrorCode.AUTHORITY_STALE
        )


class _DeniedFactory:
    def __init__(self) -> None:
        self.actions: list[CapabilityAction] = []

    def __call__(
        self,
        *,
        action: CapabilityAction,
        environment: Mapping[str, str] | None = None,
    ) -> _DeniedResolver:
        del environment
        self.actions.append(action)
        return _DeniedResolver()


class _SuccessfulResolver:
    def __init__(self, result: AmbiguousReceiptReadbackResultV1) -> None:
        self.result = result

    async def resolve(
        self,
        command: AmbiguousReceiptReadbackCommandV1,
    ) -> AmbiguousReceiptReadbackResultV1:
        assert command == self.result.command
        return self.result


class _SuccessfulFactory:
    def __init__(self, result: AmbiguousReceiptReadbackResultV1) -> None:
        self.result = result

    def __call__(
        self,
        *,
        action: CapabilityAction,
        environment: Mapping[str, str] | None = None,
    ) -> _SuccessfulResolver:
        del environment
        assert action is self.result.command.action
        return _SuccessfulResolver(self.result)


def test_cli_rejects_noncanonical_command_before_runtime_composition(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    command_file = tmp_path / "invalid.json"
    command_file.write_text('{"schema_version":"wrong"}', encoding="utf-8")

    assert main(["--command-file", str(command_file)]) == 2
    output = capsys.readouterr().out
    assert json.loads(output) == {"code": "AMBIGUOUS_RECEIPT_READBACK_COMMAND_INVALID"}


def test_cli_runs_one_resolver_attempt_and_emits_only_stable_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    command_file = tmp_path / "command.json"
    command_file.write_bytes(canonical_json_bytes(_command()))

    assert (
        main(
            ["--command-file", str(command_file)],
            environment={},
            resolver_factory=_DeniedFactory(),
        )
        == 4
    )
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "code": AmbiguousReceiptReadbackErrorCode.AUTHORITY_STALE.value
    }


def test_cli_reads_the_fixed_bounded_environment_source(
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = {
        AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV: canonical_json_bytes(_command()).decode(
            "utf-8"
        )
    }

    assert (
        main(
            ["--command-environment"],
            environment=environment,
            resolver_factory=_DeniedFactory(),
        )
        == 4
    )
    assert json.loads(capsys.readouterr().out) == {
        "code": AmbiguousReceiptReadbackErrorCode.AUTHORITY_STALE.value
    }


def test_cli_passes_recovery_action_to_runtime_composition(
    capsys: pytest.CaptureFixture[str],
) -> None:
    command = _command(CapabilityAction.RECOVER_STABLE)
    factory = _DeniedFactory()

    assert (
        main(
            ["--command-environment"],
            environment={
                AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV: canonical_json_bytes(
                    command
                ).decode("utf-8")
            },
            resolver_factory=factory,
        )
        == 4
    )
    assert factory.actions == [CapabilityAction.RECOVER_STABLE]
    assert json.loads(capsys.readouterr().out) == {
        "code": AmbiguousReceiptReadbackErrorCode.AUTHORITY_STALE.value
    }


def test_cli_emits_one_canonical_success_result(
    capsys: pytest.CaptureFixture[str],
) -> None:
    command, result = _successful_contracts()

    assert (
        main(
            ["--command-environment"],
            environment={
                AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV: canonical_json_bytes(
                    command
                ).decode("utf-8")
            },
            resolver_factory=_SuccessfulFactory(result),
        )
        == 0
    )
    assert capsys.readouterr().out == canonical_json_bytes(result).decode("utf-8") + "\n"


def test_cli_rejects_semantically_valid_noncanonical_environment_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    noncanonical = json.dumps(
        json.loads(canonical_json_bytes(_command())),
        indent=2,
        sort_keys=False,
    )

    assert (
        main(
            ["--command-environment"],
            environment={AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV: noncanonical},
            resolver_factory=_DeniedFactory(),
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out) == {
        "code": "AMBIGUOUS_RECEIPT_READBACK_COMMAND_INVALID"
    }


@pytest.mark.parametrize(
    "payload",
    [
        "{not-json}",
        "x" * 65_537,
        "",
    ],
)
def test_cli_rejects_invalid_or_oversized_environment_commands(
    payload: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            ["--command-environment"],
            environment={AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV: payload},
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out) == {
        "code": "AMBIGUOUS_RECEIPT_READBACK_COMMAND_INVALID"
    }


def test_cli_command_sources_are_mutually_exclusive(tmp_path: Path) -> None:
    command_file = tmp_path / "command.json"
    command_file.write_bytes(canonical_json_bytes(_command()))

    with pytest.raises(SystemExit) as captured:
        main(
            [
                "--command-file",
                str(command_file),
                "--command-environment",
            ],
            environment={
                AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV: canonical_json_bytes(
                    _command()
                ).decode("utf-8")
            },
        )
    assert captured.value.code == 2
