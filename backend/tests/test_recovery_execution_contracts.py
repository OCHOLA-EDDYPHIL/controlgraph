from __future__ import annotations

from typing import Any, Literal

import pytest
from health_execution_test_data import make_health_root, make_healthy_chain
from pydantic import ValidationError
from recovery_v2_test_data import (
    RecoveryV2Bundle,
    make_revoked_v2_recovery_bundle,
    make_unhealthy_recovery_chain,
    make_unhealthy_v3_recovery_bundle,
)

from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES, StrictContractModel
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.health import HealthDecisionStatus
from controlgraph_canary.contracts.health_storage import (
    RecoveryDispatchStorageRecordV2,
    create_recovery_dispatch_storage_record,
    health_storage_payload_fits,
    recovery_dispatch_storage_record_value,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReceiptOutcome,
)
from controlgraph_canary.contracts.recovery_execution import (
    MAX_RECOVERY_TASK_CANONICAL_BYTES,
    RECOVER_CAPTURED_STABLE,
    RECOVERY_DISPATCH_IDENTITY_V2,
    RECOVERY_DISPATCH_RECORD_V2,
    RECOVERY_DISPATCH_RESULT_V2,
    RECOVERY_INVOCATION_V2,
    RecoveryCapabilityIssuanceResultV2,
    RecoveryCommandV2,
    RecoveryDispatchIdentityKind,
    RecoveryDispatchIdentityV2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchResultV2,
    RecoveryDispatchState,
    RecoveryInvocationV2,
    RecoveryMutationIntentV2,
    RecoveryPrestateRequestV1,
    RecoveryTaskRequestV2,
    RecoveryTriggerBasis,
    RevokedV2RecoverySourceV1,
    UnhealthyRecoverySourceV1,
    create_recovery_apply_receipt_locator,
    create_recovery_authorization,
    create_recovery_health_chain_locator,
    create_recovery_intent,
    create_recovery_prestate_result,
    create_recovery_receipt_locator,
    create_revoked_v2_recovery_source,
    recovery_capability_id,
    recovery_command_sha256,
    recovery_dispatch_id,
    recovery_intent_id,
    recovery_prestate_signing_input_sha256,
    recovery_target_configuration_sha256,
    recovery_trigger_proof_sha256,
)
from controlgraph_canary.contracts.root_creation import create_rollout_root_v3


def _replace[ModelT: StrictContractModel](model: ModelT, **updates: Any) -> ModelT:
    values = model.model_dump(mode="python")
    values.update(updates)
    return type(model).model_validate(values)


def _dispatch_result(
    bundle: RecoveryV2Bundle,
    *,
    disposition: Literal["CREATED", "DUPLICATE", "AMBIGUOUS"] = "CREATED",
) -> RecoveryDispatchResultV2:
    authorization = bundle.authorization
    task = bundle.task
    task_sha256 = canonical_sha256(task)
    return RecoveryDispatchResultV2(
        schema_version=RECOVERY_DISPATCH_RESULT_V2,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_schema_version=authorization.root_schema_version,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        stable_revision=authorization.stable_revision,
        stable_revision_configuration_sha256=(authorization.stable_revision_configuration_sha256),
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
            f"projects/{authorization.target.project_id}/locations/us-central1/queues/"
            f"controlgraph-recovery/tasks/cg-{task_sha256}"
        ),
        enqueue_disposition=disposition,
        scheduled_at=task.scheduled_at,
        expires_at=task.expires_at,
    )


def _dispatch_record(
    bundle: RecoveryV2Bundle,
    *,
    state: RecoveryDispatchState = RecoveryDispatchState.CREATED,
) -> RecoveryDispatchRecordV2:
    command_sha256 = recovery_command_sha256(bundle.command)
    task_sha256 = canonical_sha256(bundle.task)
    task_name = (
        f"projects/{bundle.authorization.target.project_id}/locations/us-central1/queues/"
        f"controlgraph-recovery/tasks/cg-{task_sha256}"
    )
    terminal = state in {
        RecoveryDispatchState.CREATED,
        RecoveryDispatchState.DUPLICATE,
        RecoveryDispatchState.AMBIGUOUS,
    }
    return RecoveryDispatchRecordV2(
        schema_version=RECOVERY_DISPATCH_RECORD_V2,
        dispatch_id=recovery_dispatch_id(command_sha256),
        command_sha256=command_sha256,
        recovery_authorization_sha256=canonical_sha256(bundle.authorization),
        capability_id=bundle.authorization.capability_id,
        request_id=bundle.authorization.request_id,
        idempotency_key=bundle.authorization.idempotency_key,
        target=bundle.authorization.target,
        root_id=bundle.authorization.root_id,
        root_sha256=bundle.authorization.root_sha256,
        epoch=bundle.authorization.epoch,
        scheduled_at=bundle.authorization.scheduled_at,
        source_receipt_sha256=bundle.authorization.source_receipt_sha256,
        trigger_proof_sha256=bundle.authorization.trigger_proof_sha256,
        prestate_attestation_sha256=(bundle.authorization.prestate_attestation_sha256),
        task_sha256=task_sha256,
        task_name=task_name,
        task=bundle.task,
        state=state,
        prepared_at=bundle.authorization.issued_at,
        enqueue_started_at=(
            bundle.authorization.scheduled_at
            if state is not RecoveryDispatchState.PREPARED
            else None
        ),
        terminal_at=(bundle.task.expires_at if terminal else None),
        result=(_dispatch_result(bundle, disposition=state.value) if terminal else None),
    )


@pytest.mark.parametrize(
    "factory,root_version,basis",
    [
        (
            make_unhealthy_v3_recovery_bundle,
            "controlgraph.rollout-root/v3",
            RecoveryTriggerBasis.TERMINAL_UNHEALTHY_V3,
        ),
        (
            make_revoked_v2_recovery_bundle,
            "controlgraph.rollout-root/v2",
            RecoveryTriggerBasis.OPERATOR_CONFIRMED_REVOKED_V2,
        ),
    ],
)
def test_complete_recovery_contract_is_canonical_and_stable_only(
    factory: Any,
    root_version: str,
    basis: RecoveryTriggerBasis,
) -> None:
    first = factory()
    second = factory()
    authorization = first.authorization

    assert first == second
    assert authorization.root_schema_version == root_version
    assert authorization.source.basis is basis
    assert authorization.capability_id == recovery_capability_id(authorization)
    assert (authorization.expected_stable_percent, authorization.expected_candidate_percent) == (
        90,
        10,
    )
    assert (authorization.stable_percent, authorization.candidate_percent) == (100, 0)
    assert authorization.concurrency == first.root.content.rollout_plan.concurrency
    assert authorization.stable_revision == first.root.content.stable_snapshot.stable_revision
    assert authorization.desired_poststate_sha256 == recovery_target_configuration_sha256(
        first.root,
        stable_percent=100,
        candidate_percent=0,
    )
    assert authorization.current_provider_etag == (first.prestate_result.current_provider_etag)
    assert authorization.trigger_proof_sha256 == recovery_trigger_proof_sha256(authorization.source)
    assert first.mutation_intent.action is CapabilityAction.RECOVER_STABLE
    assert first.task.capability.claims.subject == authorization.recovery_identity
    assert first.task.capability.claims.concurrency == authorization.concurrency

    for model in (
        first.command,
        first.prestate_request,
        first.prestate_result,
        first.prestate_attestation,
        first.authorization,
        first.issuance_command,
        first.issuance_result,
        first.mutation_intent,
        first.task,
    ):
        encoded = canonical_json_bytes(model)
        assert len(encoded) <= MAX_CONTRACT_BYTES
        assert decode_contract(encoded, type(model)) == model
    assert len(canonical_json_bytes(first.task)) <= MAX_RECOVERY_TASK_CANONICAL_BYTES


def test_public_command_has_no_mutation_coordinate_or_provider_prestate() -> None:
    command = make_unhealthy_v3_recovery_bundle().command
    assert set(command.model_dump(mode="json")) == {
        "schema_version",
        "root_id",
        "expected_root_sha256",
        "expected_epoch",
        "request_id",
        "idempotency_key",
        "scheduled_at",
        "verified_apply_receipt",
        "source",
    }
    forbidden = {
        "stable_revision",
        "candidate_revision",
        "concurrency",
        "stable_percent",
        "candidate_percent",
        "provider_etag",
        "target",
    }
    assert forbidden.isdisjoint(type(command).model_fields)


def test_terminal_unhealthy_locator_rejects_healthy_and_tampered_chains() -> None:
    chain = make_unhealthy_recovery_chain()
    locator = create_recovery_health_chain_locator(chain)

    assert locator.terminal_status is HealthDecisionStatus.UNHEALTHY
    assert locator.terminal_sequence == 2
    assert locator.chain_head_sha256 == locator.terminal_signed_proof_sha256
    with pytest.raises(ValueError, match="terminal unhealthy"):
        create_recovery_health_chain_locator(make_healthy_chain())
    with pytest.raises(ValidationError, match="locator"):
        _replace(locator, terminal_health_decision_sha256="f" * 64, chain_head_sha256="e" * 64)


def test_root_unique_intent_owns_exactly_one_command_independent_of_epoch() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    intent = create_recovery_intent(
        bundle.command,
        created_at="2026-08-21T12:09:20Z",
    )
    changed_command = _replace(
        bundle.command,
        request_id="request-unhealthy-recovery-002",
        idempotency_key="unhealthy-recovery-002",
    )

    assert intent.intent_id == recovery_intent_id(bundle.root.root_sha256)
    assert intent.command_sha256 != recovery_command_sha256(changed_command)
    assert recovery_intent_id(bundle.root.root_sha256) == intent.intent_id
    with pytest.raises(ValidationError, match="intent"):
        _replace(intent, command=changed_command)


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_root_sha256", "f" * 64),
        ("expected_epoch", 2),
        ("scheduled_at", "2026-08-21T12:08:59Z"),
    ],
)
def test_unhealthy_command_rejects_each_altered_binding(field: str, value: object) -> None:
    command = make_unhealthy_v3_recovery_bundle().command
    with pytest.raises(ValidationError):
        _replace(command, **{field: value})


def test_v2_compatibility_is_structurally_operator_confirmed_and_v2_only() -> None:
    bundle = make_revoked_v2_recovery_bundle()
    source = bundle.command.source
    assert type(source) is RevokedV2RecoverySourceV1
    proof = source.revocation_proof
    invocation = RecoveryInvocationV2(
        schema_version=RECOVERY_INVOCATION_V2,
        command=bundle.command,
        operator_identity=proof.result.operator_identity,
        operator_subject=proof.result.operator_subject,
        operator_issuer="https://accounts.google.com",
        operator_audience="https://controlgraph-api-123456789012.us-central1.run.app",
        operator_issued_at=1_787_140_000,
        operator_expires_at=1_787_140_600,
    )
    assert type(invocation.command.source) is RevokedV2RecoverySourceV1
    assert invocation.command.source.confirmation == RECOVER_CAPTURED_STABLE

    unhealthy = make_unhealthy_v3_recovery_bundle()
    with pytest.raises(ValidationError, match="invocation"):
        RecoveryInvocationV2(
            **{
                **invocation.model_dump(mode="python"),
                "command": unhealthy.command,
            }
        )
    with pytest.raises(TypeError, match="RolloutRootV2"):
        create_revoked_v2_recovery_source(
            root=make_health_root(),  # type: ignore[arg-type]
            revocation_proof=proof,
            confirmation=RECOVER_CAPTURED_STABLE,
        )
    with pytest.raises(ValueError, match="confirmation"):
        create_revoked_v2_recovery_source(
            root=bundle.root,  # type: ignore[arg-type]
            revocation_proof=proof,
            confirmation="RECOVER_LATEST",  # type: ignore[arg-type]
        )


def test_unhealthy_source_is_v3_only_and_cannot_cross_into_v2() -> None:
    v3 = make_unhealthy_v3_recovery_bundle()
    v2 = make_revoked_v2_recovery_bundle()
    assert type(v3.command.source) is UnhealthyRecoverySourceV1
    with pytest.raises(ValidationError):
        RecoveryPrestateRequestV1.model_validate(
            {
                **v3.prestate_request.model_dump(mode="python"),
                "root": v2.root,
                "root_schema_version": v2.root.schema_version,
                "root_id": v2.root.root_id,
                "root_sha256": v2.root.root_sha256,
                "target": v2.root.content.target,
            }
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("stable_revision", "controlgraph-reference-target-latest"),
        ("candidate_revision", "controlgraph-reference-target-other"),
        ("concurrency", 999),
        ("expected_prestate_sha256", "f" * 64),
        ("trigger_proof_sha256", "e" * 64),
        ("source_receipt_storage_revision", 3),
        (
            "evidence_signing_key_version",
            "projects/controlgraph-canary-a1b2c3/locations/us-central1/"
            "keyRings/controlgraph-signing/cryptoKeys/capability-signing/"
            "cryptoKeyVersions/1",
        ),
    ],
)
def test_prestate_request_rejects_tampering(field: str, value: object) -> None:
    request = make_unhealthy_v3_recovery_bundle().prestate_request
    with pytest.raises(ValidationError, match="prestate request"):
        _replace(request, **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("observed_prestate_sha256", "f" * 64),
        ("stable_percent", 100),
        ("candidate_percent", 0),
        ("concurrency", 9),
        ("service_generation", 0),
        ("retrieved_at", "2026-08-21T12:14:10Z"),
        (
            "verifier_identity",
            "controlgraph-recovery@controlgraph-canary-a1b2c3.iam.gserviceaccount.com",
        ),
    ],
)
def test_prestate_result_rejects_nonexact_readback(field: str, value: object) -> None:
    result = make_unhealthy_v3_recovery_bundle().prestate_result
    with pytest.raises(ValidationError):
        _replace(result, **{field: value})


def test_prestate_attestation_binds_result_key_purpose_and_signature() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    attestation = bundle.prestate_attestation
    assert attestation.signing_input_sha256 == recovery_prestate_signing_input_sha256(
        bundle.prestate_result,
        attestation.signing_key_version,
    )
    for updates in (
        {"result_sha256": "f" * 64},
        {"payload_sha256": "f" * 64},
        {"signing_request_sha256": "f" * 64},
        {"signing_input_sha256": "f" * 64},
        {"signature": "%%%"},
    ):
        with pytest.raises(ValidationError):
            _replace(attestation, **updates)

    changed = create_recovery_prestate_result(
        request=bundle.prestate_request,
        current_provider_etag="different-current-etag",
        service_generation=10,
        retrieved_at=bundle.prestate_result.retrieved_at,
    )
    with pytest.raises(ValidationError, match="attestation"):
        _replace(attestation, result=changed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("stable_revision", "controlgraph-reference-target-latest"),
        ("candidate_revision", "controlgraph-reference-target-other"),
        ("concurrency", 1000),
        ("stable_revision_configuration_sha256", "f" * 64),
        ("candidate_revision_configuration_sha256", "e" * 64),
        ("stable_snapshot_sha256", "d" * 64),
        ("current_provider_etag", "forged-etag"),
        ("expected_prestate_sha256", "c" * 64),
        ("desired_poststate_sha256", "b" * 64),
        ("trigger_proof_sha256", "a" * 64),
        ("stable_percent", 90),
        ("candidate_percent", 10),
        ("maximum_capability_lifetime_seconds", 599),
        ("maximum_attempts", 2),
    ],
)
def test_authorization_rejects_stable_target_or_proof_tampering(
    field: str,
    value: object,
) -> None:
    authorization = make_unhealthy_v3_recovery_bundle().authorization
    with pytest.raises(ValidationError):
        _replace(authorization, **{field: value})


def test_authorization_allows_independent_capability_key_rotation() -> None:
    root = make_health_root()
    project_id = root.content.target.project_id
    bounds_values = root.content.authority_bounds.model_dump(mode="python")
    bounds_values["capability_signing_key_version"] = (
        f"projects/{project_id}/locations/us-central1/keyRings/controlgraph-signing/"
        "cryptoKeys/capability-signing/cryptoKeyVersions/2"
    )
    rotated_bounds = type(root.content.authority_bounds).model_validate(bounds_values)
    content_values = root.content.model_dump(mode="python")
    content_values["authority_bounds"] = rotated_bounds
    rotated_root = create_rollout_root_v3(type(root.content).model_validate(content_values))

    bundle = make_unhealthy_v3_recovery_bundle(rotated_root)

    assert bundle.authorization.evidence_signing_key_version.endswith(
        "evidence-signing/cryptoKeyVersions/1"
    )
    assert bundle.authorization.capability_signing_key_version.endswith(
        "capability-signing/cryptoKeyVersions/2"
    )


def test_authorization_requires_attestation_for_same_command_root_and_mode() -> None:
    v3 = make_unhealthy_v3_recovery_bundle()
    v2 = make_revoked_v2_recovery_bundle()
    with pytest.raises(ValidationError):
        _replace(v3.authorization, prestate_attestation=v2.prestate_attestation)
    with pytest.raises(ValueError):
        create_recovery_authorization(
            root=v3.root,
            command=v3.command,
            prestate_attestation=v2.prestate_attestation,
        )


def test_capability_issuance_rejects_wrong_identity_action_scope_and_etag() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    result = bundle.issuance_result
    claims = result.capability.claims
    for updates in (
        {
            "subject": (
                "controlgraph-executor@"
                f"{bundle.authorization.target.project_id}.iam.gserviceaccount.com"
            )
        },
        {"provider_etag": "forged-etag"},
        {"concurrency": bundle.authorization.concurrency + 1},
        {"parent_capability_sha256": "f" * 64},
    ):
        changed_claims = claims.model_copy(update=updates)
        changed_capability = result.capability.model_copy(
            update={
                "claims": changed_claims,
                "claims_sha256": canonical_sha256(changed_claims),
            }
        )
        with pytest.raises(ValidationError, match="issuance result"):
            RecoveryCapabilityIssuanceResultV2.model_validate(
                {
                    **result.model_dump(mode="python"),
                    "capability": changed_capability,
                    "capability_sha256": canonical_sha256(changed_capability),
                }
            )


@pytest.mark.parametrize(
    "field,value",
    [
        ("stable_revision", "controlgraph-reference-target-latest"),
        ("candidate_revision", "controlgraph-reference-target-other"),
        ("stable_percent", 90),
        ("candidate_percent", 10),
        ("concurrency", 999),
        ("provider_etag", "forged-etag"),
        ("desired_poststate_sha256", "f" * 64),
        ("prestate_attestation_sha256", "e" * 64),
    ],
)
def test_recovery_intent_rejects_arbitrary_mutation_fields(
    field: str,
    value: object,
) -> None:
    intent = make_unhealthy_v3_recovery_bundle().mutation_intent
    with pytest.raises(ValidationError):
        _replace(intent, **{field: value})


def test_task_rejects_promotion_identity_audience_and_expired_prestate() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    task = bundle.task
    for updates in (
        {"handler_audience": "https://controlgraph-executor-123456789012.us-central1.run.app"},
        {"expires_at": bundle.authorization.proof_valid_until},
        {"scheduled_at": "2026-08-21T12:09:31Z"},
    ):
        with pytest.raises(ValidationError, match="task"):
            _replace(task, **updates)


def test_dispatch_identity_record_and_terminal_result_are_exact() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    command_sha256 = recovery_command_sha256(bundle.command)
    identity = RecoveryDispatchIdentityV2(
        schema_version=RECOVERY_DISPATCH_IDENTITY_V2,
        identity_kind=RecoveryDispatchIdentityKind.REQUEST,
        identity_value=bundle.command.request_id,
        dispatch_id=recovery_dispatch_id(command_sha256),
        command_sha256=command_sha256,
        recovery_authorization_sha256=canonical_sha256(bundle.authorization),
        capability_id=bundle.authorization.capability_id,
        target=bundle.authorization.target,
        root_id=bundle.authorization.root_id,
        root_sha256=bundle.authorization.root_sha256,
        epoch=bundle.authorization.epoch,
        scheduled_at=bundle.authorization.scheduled_at,
        source_receipt_sha256=bundle.authorization.source_receipt_sha256,
        trigger_proof_sha256=bundle.authorization.trigger_proof_sha256,
        prestate_attestation_sha256=(bundle.authorization.prestate_attestation_sha256),
        claimed_at=bundle.authorization.issued_at,
    )
    record = _dispatch_record(bundle)

    assert identity.dispatch_id == record.dispatch_id
    assert record.result is not None
    assert record.result.stable_percent == 100
    assert record.result.candidate_percent == 0
    storage_record = create_recovery_dispatch_storage_record(record)
    encoded = canonical_json_bytes(storage_record)
    decoded = decode_contract(encoded, RecoveryDispatchStorageRecordV2)
    assert len(encoded) <= MAX_CONTRACT_BYTES
    assert health_storage_payload_fits(storage_record)
    assert recovery_dispatch_storage_record_value(decoded) == record
    assert "task" not in RecoveryDispatchStorageRecordV2.model_fields
    assert decoded.task_sha256 == canonical_sha256(record.task)
    with pytest.raises(ValidationError, match="dispatch identity"):
        _replace(identity, dispatch_id=f"cgrecover:{'f' * 64}")
    with pytest.raises(ValidationError):
        _replace(record, result=_replace(record.result, provider_etag="forged-etag"))

    with pytest.raises(ValidationError, match="storage bindings"):
        _replace(storage_record, request_id="other-recovery-request")
    with pytest.raises(ValidationError, match="storage bindings"):
        _replace(storage_record, task_sha256="f" * 64)


def test_revoked_v2_dispatch_storage_projection_is_bounded_and_lossless() -> None:
    bundle = make_revoked_v2_recovery_bundle()
    record = _dispatch_record(bundle)
    storage_record = create_recovery_dispatch_storage_record(record)
    encoded = canonical_json_bytes(storage_record)

    assert not health_storage_payload_fits(record)
    assert len(encoded) <= MAX_CONTRACT_BYTES
    assert health_storage_payload_fits(storage_record)
    assert recovery_dispatch_storage_record_value(
        decode_contract(encoded, RecoveryDispatchStorageRecordV2)
    ) == record

    tampered_payload = storage_record.task_canonical_payload.replace(
        bundle.command.request_id,
        "request-revoked-v2-recovery-002",
    )
    with pytest.raises(ValidationError, match="storage bindings"):
        _replace(storage_record, task_canonical_payload=tampered_payload)


def test_dispatch_state_machine_does_not_reconstruct_enqueue_authority() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    prepared = _dispatch_record(bundle, state=RecoveryDispatchState.PREPARED)
    started = _dispatch_record(bundle, state=RecoveryDispatchState.ENQUEUE_STARTED)
    assert prepared.enqueue_started_at is None and prepared.result is None
    assert started.enqueue_started_at is not None and started.result is None
    with pytest.raises(ValidationError, match="prepared"):
        _replace(prepared, enqueue_started_at=prepared.prepared_at)
    with pytest.raises(ValidationError, match="started"):
        _replace(started, result=_dispatch_result(bundle))


def test_apply_and_recovery_receipt_locators_bind_revision_and_terminal_state() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    apply_receipt = bundle.command.source.health_chain_locator  # type: ignore[union-attr]
    assert apply_receipt.source_receipt_sha256 == (
        bundle.command.verified_apply_receipt.receipt_sha256
    )
    with pytest.raises(TypeError, match="exact execution receipt"):
        create_recovery_apply_receipt_locator(
            bundle.prestate_request.root.content.stable_snapshot,  # type: ignore[arg-type]
            storage_revision=2,
        )

    authorization = bundle.authorization
    receipt = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id="cgreceipt:recovery-terminal-001",
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        capability_sha256=canonical_sha256(bundle.task.capability),
        mutation_sha256=canonical_sha256(bundle.mutation_intent),
        plan_sha256=authorization.plan_sha256,
        expected_poststate_sha256=authorization.desired_poststate_sha256,
        target=authorization.target,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        action=CapabilityAction.RECOVER_STABLE,
        provider_etag=authorization.current_provider_etag,
        dispatch_not_after=bundle.task.expires_at,
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        provider_operation="operations/recovery-terminal-001",
        observed_etag="stable-restored-etag-10",
        observed_authority_epoch=authorization.epoch,
        created_at=bundle.task.scheduled_at,
        updated_at=bundle.task.expires_at,
        evidence_ids=("evidence-recovery-terminal-001",),
    )
    locator = create_recovery_receipt_locator(receipt, storage_revision=4)
    assert locator.receipt_sha256 == canonical_sha256(receipt)
    assert locator.outcome is ReceiptOutcome.VERIFIED
    claimed = receipt.model_copy(
        update={
            "outcome": ReceiptOutcome.CLAIMED,
            "provider_operation": None,
            "observed_etag": None,
            "observed_authority_epoch": None,
        }
    )
    with pytest.raises(ValueError, match="terminal"):
        create_recovery_receipt_locator(claimed, storage_revision=1)


def test_unknown_fields_and_cross_action_shapes_fail_closed() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    command_values = bundle.command.model_dump(mode="python")
    command_values["candidate_revision"] = bundle.authorization.candidate_revision
    with pytest.raises(ValidationError, match="Extra inputs"):
        RecoveryCommandV2.model_validate(command_values)

    intent_values = bundle.mutation_intent.model_dump(mode="python")
    intent_values["action"] = CapabilityAction.PROMOTE_CANDIDATE
    with pytest.raises(ValidationError):
        RecoveryMutationIntentV2.model_validate(intent_values)

    task_values = bundle.task.model_dump(mode="python")
    task_values["intent"] = bundle.task.intent.model_copy(
        update={"stable_percent": 0, "candidate_percent": 100}
    )
    with pytest.raises(ValidationError):
        RecoveryTaskRequestV2.model_validate(task_values)
