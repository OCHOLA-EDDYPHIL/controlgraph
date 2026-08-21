from __future__ import annotations

import pytest
from pydantic import ValidationError
from root_v2_support import root_records

from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.contracts.ambiguous_receipt_readback import (
    AMBIGUOUS_RECEIPT_READBACK_COMMAND_V1,
    AmbiguousReceiptReadbackCommandV1,
    AmbiguousReceiptReadbackDisposition,
    ambiguous_receipt_readback_result,
    ambiguous_receipt_resolution_evidence_id,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
)
from controlgraph_canary.contracts.receipt_authority import StoredExecutionReceiptV1
from controlgraph_canary.contracts.storage import execution_receipt_logical_id


def _replace_receipt(
    receipt: ExecutionReceipt,
    **changes: object,
) -> ExecutionReceipt:
    return ExecutionReceipt(
        **{
            **receipt.model_dump(mode="python"),
            **changes,
        }
    )


def _receipt() -> ExecutionReceipt:
    root, _, _, _ = root_records(concurrency=8)
    plan = root.content.rollout_plan
    expected = TargetConfigurationProjection(
        target=root.content.target,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=plan.stable_percent,
        candidate_percent=plan.candidate_percent,
        concurrency=plan.concurrency,
    )
    return ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(root.content.target, "idempotency-001"),
        request_id="request-001",
        idempotency_key="idempotency-001",
        capability_sha256="3" * 64,
        mutation_sha256="4" * 64,
        plan_sha256=canonical_sha256(plan),
        expected_poststate_sha256=target_configuration_projection_sha256(expected),
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag=root.content.stable_snapshot.provider_etag,
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.AMBIGUOUS,
        reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
        provider_operation=(
            f"projects/{root.content.target.project_id}/locations/us-central1/"
            "operations/apply-001"
        ),
        observed_etag="etag-ambiguous-7",
        observed_authority_epoch=1,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:03:00Z",
        evidence_ids=(),
    )


def _command(receipt: ExecutionReceipt) -> AmbiguousReceiptReadbackCommandV1:
    return AmbiguousReceiptReadbackCommandV1(
        schema_version=AMBIGUOUS_RECEIPT_READBACK_COMMAND_V1,
        root_id=receipt.root_id,
        expected_root_sha256=receipt.root_sha256,
        expected_epoch=receipt.epoch,
        action=CapabilityAction.APPLY_CANARY,
        request_id=receipt.request_id,
        idempotency_key=receipt.idempotency_key,
        capability_sha256=receipt.capability_sha256,
        expected_receipt_sha256=canonical_sha256(receipt),
        expected_storage_revision=2,
        expected_ambiguous_observed_etag=receipt.observed_etag or "missing",
        expected_ambiguous_updated_at=receipt.updated_at,
        confirmation="READBACK_ONLY",
    )


def test_command_is_strict_versioned_apply_only_and_requires_confirmation() -> None:
    command = _command(_receipt())
    payload = command.model_dump(mode="python")

    for changes in (
        {"confirmation": "APPLY"},
        {"action": CapabilityAction.PROMOTE_CANDIDATE},
        {"schema_version": "controlgraph.ambiguous-receipt-readback-command/v2"},
        {"unexpected": "field"},
        {"expected_epoch": 0},
    ):
        with pytest.raises(ValidationError):
            AmbiguousReceiptReadbackCommandV1.model_validate({**payload, **changes})

    with pytest.raises(ValidationError, match="ambiguous receipt reason"):
        _replace_receipt(
            _receipt(),
            reason_code=ReasonCode.AUTHORITY_UNAVAILABLE,
        )


def test_resolution_marker_is_deterministic_and_bound_to_every_locator_field() -> None:
    command = _command(_receipt())
    marker = ambiguous_receipt_resolution_evidence_id(command)

    assert marker == ambiguous_receipt_resolution_evidence_id(command)
    assert marker.startswith("cgrrb:")
    for field, changed in (
        ("request_id", "request-002"),
        ("idempotency_key", "idempotency-002"),
        ("capability_sha256", "5" * 64),
        ("expected_receipt_sha256", "6" * 64),
        ("expected_storage_revision", 3),
        ("expected_ambiguous_observed_etag", "etag-ambiguous-8"),
        ("expected_ambiguous_updated_at", "2026-08-19T12:04:00Z"),
    ):
        modified = command.model_copy(update={field: changed})
        assert ambiguous_receipt_resolution_evidence_id(modified) != marker


def test_result_contract_binds_command_revision_marker_and_verified_receipt() -> None:
    ambiguous = _receipt()
    command = _command(ambiguous)
    marker = ambiguous_receipt_resolution_evidence_id(command)
    verified = _replace_receipt(
        ambiguous,
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        observed_etag="etag-canary-8",
        updated_at="2026-08-19T12:04:00Z",
        evidence_ids=(marker,),
    )
    stored = StoredExecutionReceiptV1(
        schema_version="controlgraph.stored-execution-receipt/v1",
        receipt=verified,
        storage_revision=3,
    )

    result = ambiguous_receipt_readback_result(
        command=command,
        disposition=AmbiguousReceiptReadbackDisposition.RESOLVED,
        stored_receipt=stored,
    )

    assert result.command == command
    assert result.command_sha256 == canonical_sha256(command)
    assert canonical_json_bytes(result)
    invalid = result.model_dump(mode="python")
    invalid["stored_receipt"]["storage_revision"] = 4
    with pytest.raises(ValidationError):
        type(result).model_validate(invalid)
