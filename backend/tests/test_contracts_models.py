import json
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityClaims,
    ContractError,
    ContractErrorCode,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    ExecutionReceipt,
    HealthInput,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    RecoveryPlan,
    RolloutRoot,
    SignedCapability,
    StableSnapshot,
    TargetBinding,
    TaskRequest,
    TrafficAllocation,
    canonical_json_bytes,
    canonical_sha256,
    decode_base64url,
    decode_contract,
    encode_base64url,
)
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES, MAX_SAFE_INTEGER

ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64


def target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id="demo-project-123",
        region="us-central1",
        environment="acceptance",
        service_name="canary-target",
    )


def snapshot() -> StableSnapshot:
    return StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=target(),
        stable_revision="canary-target-stable",
        traffic=(
            TrafficAllocation(revision="canary-target-stable", percent=100),
        ),
        concurrency=40,
        service_generation=7,
        provider_etag="etag-stable-7",
        configuration_sha256=ZERO_DIGEST,
        captured_at="2026-08-19T12:00:00Z",
        captured_by="operator@example.com",
    )


def root() -> RolloutRoot:
    return RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id="root-001",
        target=target(),
        stable_snapshot=snapshot(),
        candidate_revision="canary-target-candidate",
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=ONE_DIGEST,
        maximum_recovery_attempts=1,
        initial_epoch=1,
        plan_sha256=TWO_DIGEST,
        approved_by="operator@example.com",
        approved_at="2026-08-19T12:01:00Z",
    )


def root_digest() -> str:
    return canonical_sha256(root())


def claims() -> CapabilityClaims:
    return CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id="capability-001",
        issuer="issuer@demo-project-123.iam.gserviceaccount.com",
        subject="executor@demo-project-123.iam.gserviceaccount.com",
        audience="https://executor.example.test/internal/v1/execute",
        target=target(),
        root_id="root-001",
        root_sha256=root_digest(),
        epoch=7,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision="canary-target-stable",
        candidate_revision="canary-target-candidate",
        stable_percent=90,
        candidate_percent=10,
        concurrency=None,
        plan_sha256=TWO_DIGEST,
        provider_etag="etag-stable-7",
        request_id="request-001",
        idempotency_key="intent-001",
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:01:00Z",
        not_before="2026-08-19T12:01:00Z",
        expires_at="2026-08-19T12:06:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=(
            "projects/demo-project-123/locations/us-central1/keyRings/controlgraph/"
            "cryptoKeys/capabilities/cryptoKeyVersions/1"
        ),
    )


def signed_capability() -> SignedCapability:
    value = claims()
    return SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=value,
        claims_sha256=canonical_sha256(value),
        signature=encode_base64url(b"synthetic-signature"),
    )


def intent() -> MutationIntent:
    return MutationIntent(
        schema_version="controlgraph.mutation-intent/v1",
        request_id="request-001",
        idempotency_key="intent-001",
        target=target(),
        root_id="root-001",
        root_sha256=root_digest(),
        epoch=7,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision="canary-target-stable",
        candidate_revision="canary-target-candidate",
        stable_percent=90,
        candidate_percent=10,
        concurrency=None,
        plan_sha256=TWO_DIGEST,
        provider_etag="etag-stable-7",
    )


def all_contracts() -> tuple[object, ...]:
    return (
        target(),
        snapshot(),
        root(),
        EpochAuthorityRecord(
            schema_version="controlgraph.epoch-authority/v1",
            root_id="root-001",
            root_sha256=root_digest(),
            target=target(),
            current_epoch=1,
            previous_epoch=None,
            revision=0,
            cause=EpochChangeCause.ROOT_CREATED,
            changed_by="operator@example.com",
            request_id="request-root-001",
            evidence_id="evidence-root-001",
            changed_at="2026-08-19T12:01:00Z",
        ),
        claims(),
        signed_capability(),
        intent(),
        TaskRequest(
            schema_version="controlgraph.task-request/v1",
            task_id="task-001",
            queue_region="us-central1",
            handler_audience="https://executor.example.test/internal/v1/execute",
            scheduled_at="2026-08-19T12:02:00Z",
            expires_at="2026-08-19T12:05:00Z",
            capability=signed_capability(),
            intent=intent(),
        ),
        ExecutionReceipt(
            schema_version="controlgraph.execution-receipt/v1",
            receipt_id="receipt-001",
            request_id="request-001",
            idempotency_key="intent-001",
            capability_sha256=ZERO_DIGEST,
            mutation_sha256=ONE_DIGEST,
            plan_sha256=TWO_DIGEST,
            expected_poststate_sha256=ZERO_DIGEST,
            target=target(),
            root_id="root-001",
            root_sha256=root_digest(),
            epoch=7,
            action=CapabilityAction.APPLY_CANARY,
            provider_etag="etag-stable-7",
            dispatch_not_after="2026-08-19T12:10:00Z",
            outcome=ReceiptOutcome.DENIED,
            reason_code=ReasonCode.EPOCH_MISMATCH,
            provider_operation=None,
            observed_etag=None,
            observed_authority_epoch=8,
            created_at="2026-08-19T12:03:00Z",
            updated_at="2026-08-19T12:03:00Z",
            evidence_ids=("evidence-denial-001",),
        ),
        HealthInput(
            schema_version="controlgraph.health-input/v1",
            root_id="root-001",
            root_sha256=root_digest(),
            target=target(),
            epoch=7,
            window_started_at="2026-08-19T12:02:00Z",
            window_ended_at="2026-08-19T12:03:00Z",
            request_count=100,
            error_count=1,
            p95_latency_ms=120,
            probe_successes=9,
            probe_failures=1,
            metrics_sha256=TWO_DIGEST,
            observed_by="verifier@demo-project-123.iam.gserviceaccount.com",
            evidence_ids=("evidence-health-001",),
        ),
        RecoveryPlan(
            schema_version="controlgraph.recovery-plan/v1",
            request_id="request-recovery-001",
            root_id="root-001",
            root_sha256=root_digest(),
            target=target(),
            epoch=7,
            stable_revision="canary-target-stable",
            candidate_revision="canary-target-candidate",
            stable_percent=100,
            candidate_percent=0,
            concurrency=40,
            provider_etag="etag-canary-8",
            stable_snapshot_sha256=ZERO_DIGEST,
            plan_sha256=ONE_DIGEST,
            maximum_attempts=1,
            approved_by="operator@example.com",
            approved_at="2026-08-19T12:04:00Z",
        ),
        EvidenceEvent(
            schema_version="controlgraph.evidence-event/v1",
            evidence_id="evidence-root-001",
            sequence=0,
            root_id="root-001",
            root_sha256=root_digest(),
            target=target(),
            epoch=7,
            kind=EvidenceKind.ROOT_CREATED,
            actor="api@demo-project-123.iam.gserviceaccount.com",
            request_id="request-root-001",
            receipt_id=None,
            occurred_at="2026-08-19T12:01:00Z",
            subject_sha256=ZERO_DIGEST,
            previous_event_sha256=None,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=None,
        ),
    )


def test_every_contract_round_trips_canonical_bytes() -> None:
    assert claims().root_sha256 == canonical_sha256(root())
    for value in all_contracts():
        assert hasattr(value, "schema_version")
        encoded = canonical_json_bytes(value)  # type: ignore[arg-type]
        assert encoded == canonical_json_bytes(
            decode_contract(encoded, type(value))  # type: ignore[arg-type]
        )
        assert b" " not in encoded and b"\n" not in encoded


def test_models_are_frozen_and_unknown_fields_fail_closed() -> None:
    with pytest.raises(ValidationError):
        target().service_name = "other"  # type: ignore[misc]

    value = json.loads(canonical_json_bytes(target()))
    value["unexpected"] = "value"
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    with pytest.raises(ContractError) as error:
        decode_contract(payload, TargetBinding)
    assert error.value.code is ContractErrorCode.INVALID


@pytest.mark.parametrize(
    "payload",
    [
        '{"schema_version":"controlgraph.target-binding/v1",'
        '"schema_version":"controlgraph.target-binding/v1"}',
        '{"schema_version":"controlgraph.target-binding/v1","value":1.0}',
        (
            '{"schema_version":"controlgraph.target-binding/v1","value":'
            f"{MAX_SAFE_INTEGER + 1}" + "}"
        ),
        '{ "schema_version":"controlgraph.target-binding/v1"}',
    ],
)
def test_ambiguous_or_noncanonical_json_is_rejected(payload: str) -> None:
    with pytest.raises(ContractError) as error:
        decode_contract(payload, TargetBinding)
    assert error.value.code is ContractErrorCode.INVALID


def test_unsupported_version_has_a_stable_code() -> None:
    value = json.loads(canonical_json_bytes(target()))
    value["schema_version"] = "controlgraph.target-binding/v2"
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    with pytest.raises(ContractError) as error:
        decode_contract(payload, TargetBinding)
    assert error.value.code is ContractErrorCode.VERSION_UNSUPPORTED


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update(captured_at="2026-08-19T12:00:00.000Z"),
        lambda data: data.update(captured_at="2026-08-19T12:00:00+00:00"),
        lambda data: data.update(captured_at="2026-02-30T12:00:00Z"),
        lambda data: data.update(captured_by="Cafe\u0301"),
    ],
)
def test_invalid_timestamp_and_non_nfc_text_are_rejected(
    mutation: Callable[[dict[str, object]], None],
) -> None:
    data = snapshot().model_dump(mode="python")
    mutation(data)
    with pytest.raises(ValidationError):
        StableSnapshot.model_validate(data)


def test_cross_field_inconsistencies_are_rejected() -> None:
    snapshot_data = snapshot().model_dump(mode="python")
    snapshot_data["traffic"] = (
        TrafficAllocation(revision="canary-target-candidate", percent=100),
    )
    with pytest.raises(ValidationError):
        StableSnapshot.model_validate(snapshot_data)

    claim_data = claims().model_dump(mode="python")
    claim_data["candidate_percent"] = 11
    with pytest.raises(ValidationError):
        CapabilityClaims.model_validate(claim_data)

    claim_data = claims().model_dump(mode="python")
    claim_data["epoch"] = 0
    with pytest.raises(ValidationError):
        CapabilityClaims.model_validate(claim_data)

    authority_data = all_contracts()[3].model_dump(mode="python")  # type: ignore[union-attr]
    authority_data["current_epoch"] = 2
    with pytest.raises(ValidationError):
        EpochAuthorityRecord.model_validate(authority_data)

    authority_data = all_contracts()[3].model_dump(mode="python")  # type: ignore[union-attr]
    authority_data.update(
        current_epoch=3,
        previous_epoch=2,
        revision=1,
        cause=EpochChangeCause.OPERATOR_REVOCATION,
    )
    with pytest.raises(ValidationError, match="epoch and revision"):
        EpochAuthorityRecord.model_validate(authority_data)

    receipt_data = all_contracts()[8].model_dump(mode="python")  # type: ignore[union-attr]
    del receipt_data["plan_sha256"]
    with pytest.raises(ValidationError):
        ExecutionReceipt.model_validate(receipt_data)

    receipt_data = all_contracts()[8].model_dump(mode="python")  # type: ignore[union-attr]
    del receipt_data["expected_poststate_sha256"]
    with pytest.raises(ValidationError):
        ExecutionReceipt.model_validate(receipt_data)

    task_data = all_contracts()[7].model_dump(mode="python")  # type: ignore[union-attr]
    task_data["handler_audience"] = "https://other.example.test/internal/v1/execute"
    with pytest.raises(ValidationError):
        TaskRequest.model_validate(task_data)

    task_data = all_contracts()[7].model_dump(mode="python")  # type: ignore[union-attr]
    task_data["intent"]["root_sha256"] = ZERO_DIGEST  # type: ignore[index]
    with pytest.raises(ValidationError):
        TaskRequest.model_validate(task_data)


@pytest.mark.parametrize(
    "reason",
    [
        ReasonCode.PROVIDER_PRECONDITION_FAILED,
        ReasonCode.TARGET_BINDING_MISMATCH,
        ReasonCode.PROVIDER_REQUEST_REJECTED,
    ],
)
def test_failed_safe_receipt_accepts_only_stable_sanitized_reasons(
    reason: ReasonCode,
) -> None:
    receipt_data = all_contracts()[8].model_dump(mode="python")  # type: ignore[union-attr]
    receipt_data.update(
        outcome=ReceiptOutcome.FAILED_SAFE,
        reason_code=reason,
        observed_authority_epoch=None,
    )

    receipt = ExecutionReceipt.model_validate(receipt_data)

    assert receipt.reason_code is reason


def test_failed_safe_receipt_rejects_unrelated_reason() -> None:
    receipt_data = all_contracts()[8].model_dump(mode="python")  # type: ignore[union-attr]
    receipt_data.update(
        outcome=ReceiptOutcome.FAILED_SAFE,
        reason_code=ReasonCode.AUTHORITY_UNAVAILABLE,
        observed_authority_epoch=None,
    )

    with pytest.raises(ValidationError, match="failed-safe receipt reason"):
        ExecutionReceipt.model_validate(receipt_data)


@pytest.mark.parametrize(
    ("outcome", "changes", "message"),
    [
        (
            ReceiptOutcome.DENIED,
            {"provider_operation": "operations/forbidden"},
            "denied receipt",
        ),
        (
            ReceiptOutcome.DENIED,
            {"observed_etag": "etag-forbidden"},
            "denied receipt",
        ),
        (
            ReceiptOutcome.APPLIED,
            {
                "reason_code": None,
                "provider_operation": None,
                "observed_authority_epoch": 7,
            },
            "applied receipt",
        ),
        (
            ReceiptOutcome.FAILED_SAFE,
            {
                "reason_code": ReasonCode.PROVIDER_REQUEST_REJECTED,
                "provider_operation": "operations/forbidden",
                "observed_authority_epoch": 7,
            },
            "failed-safe receipt",
        ),
    ],
)
def test_receipt_outcomes_reject_impossible_provider_result_shapes(
    outcome: ReceiptOutcome,
    changes: dict[str, object],
    message: str,
) -> None:
    receipt_data = all_contracts()[8].model_dump(mode="python")  # type: ignore[union-attr]
    receipt_data.update(outcome=outcome, **changes)

    with pytest.raises(ValidationError, match=message):
        ExecutionReceipt.model_validate(receipt_data)


def test_oversized_input_is_rejected_before_schema_validation() -> None:
    payload = b"{" + b" " * MAX_CONTRACT_BYTES + b"}"
    with pytest.raises(ContractError) as error:
        decode_contract(payload, TargetBinding)
    assert error.value.code is ContractErrorCode.INVALID


@pytest.mark.parametrize("value", [b"", b"\x00\xffsynthetic", bytes(range(32))])
def test_base64url_has_one_unpadded_spelling(value: bytes) -> None:
    encoded = encode_base64url(value)
    assert "=" not in encoded and "+" not in encoded and "/" not in encoded
    assert decode_base64url(encoded) == value


@pytest.mark.parametrize("value", ["A=", "+w", "/w", "A"])
def test_noncanonical_base64url_is_rejected(value: str) -> None:
    with pytest.raises(ContractError):
        decode_base64url(value)
