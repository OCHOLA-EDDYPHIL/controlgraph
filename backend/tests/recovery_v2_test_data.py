from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from health_execution_test_data import (
    make_anchor,
    make_health_root,
    make_observation,
    make_signed_proof,
    make_verified_apply_receipt,
)
from revocation_proof_test_data import make_revocation_proof_records
from root_v2_test_data import make_root_v2_records, make_root_v3_records

from controlgraph_canary.application.health_evaluation import (
    derive_next_health_evaluation_state,
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.health import MonitoringWindowObservationV1
from controlgraph_canary.contracts.health_execution import (
    SignedHealthDecisionChainV1,
    create_health_decision_proof,
    create_post_apply_health_anchor,
    create_signed_health_decision_chain,
)
from controlgraph_canary.contracts.models import (
    CAPABILITY_CLAIMS_V1,
    EXECUTION_RECEIPT_V1,
    SIGNED_CAPABILITY_V1,
    CapabilityAction,
    CapabilityClaims,
    ExecutionReceipt,
    ReceiptOutcome,
    SignedCapability,
)
from controlgraph_canary.contracts.recovery_execution import (
    RECOVER_CAPTURED_STABLE,
    RECOVERY_CAPABILITY_ISSUANCE_COMMAND_V2,
    RECOVERY_CAPABILITY_ISSUANCE_RESULT_V2,
    RECOVERY_MUTATION_INTENT_V2,
    RECOVERY_TASK_REQUEST_V2,
    RecoveryAuthorizationV1,
    RecoveryCapabilityIssuanceCommandV2,
    RecoveryCapabilityIssuanceResultV2,
    RecoveryCommandV2,
    RecoveryMutationIntentV2,
    RecoveryPrestateAttestationV1,
    RecoveryPrestateRequestV1,
    RecoveryPrestateResultV1,
    RecoveryTaskRequestV2,
    create_recovery_apply_receipt_locator,
    create_recovery_authorization,
    create_recovery_prestate_attestation,
    create_recovery_prestate_request,
    create_recovery_prestate_result,
    create_revoked_v2_recovery_command,
    create_revoked_v3_recovery_command,
    create_unhealthy_recovery_command,
    recovery_capability_id,
    recovery_capability_issuance_command_sha256,
    recovery_target_configuration_sha256,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV2, RolloutRootV3


@dataclass(frozen=True, slots=True)
class RecoveryV2Bundle:
    root: RolloutRootV2 | RolloutRootV3
    command: RecoveryCommandV2
    prestate_request: RecoveryPrestateRequestV1
    prestate_result: RecoveryPrestateResultV1
    prestate_attestation: RecoveryPrestateAttestationV1
    authorization: RecoveryAuthorizationV1
    issuance_command: RecoveryCapabilityIssuanceCommandV2
    issuance_result: RecoveryCapabilityIssuanceResultV2
    mutation_intent: RecoveryMutationIntentV2
    task: RecoveryTaskRequestV2


def _unhealthy_observation(
    observation: MonitoringWindowObservationV1,
) -> MonitoringWindowObservationV1:
    samples = list(observation.samples)
    samples[0] = samples[0].model_copy(update={"int64_value": 946})
    samples[3] = samples[3].model_copy(update={"int64_value": 50})
    sample_tuple = tuple(samples)
    sample_sha256s = tuple(canonical_sha256(sample) for sample in sample_tuple)
    values = observation.model_dump(mode="python")
    values.update(
        samples=sample_tuple,
        sample_sha256s=sample_sha256s,
        source_sample_sha256s=tuple(sorted(sample_sha256s)),
        successful_request_count=946,
        server_error_count=50,
    )
    return MonitoringWindowObservationV1.model_validate(values)


def make_unhealthy_recovery_chain(
    root: RolloutRootV3 | None = None,
) -> SignedHealthDecisionChainV1:
    anchor = (
        make_anchor()[1]
        if root is None
        else create_post_apply_health_anchor(
            root=root,
            apply_receipt=make_verified_apply_receipt(root),
        )
    )
    first_state = initial_health_evaluation_state(
        policy=anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
    )
    first_observation = _unhealthy_observation(make_observation(anchor, window_index=1))
    first_decision = evaluate_health_observation(
        policy=anchor.policy,
        prior_state=first_state,
        observation=first_observation,
        evaluated_at=first_observation.observed_at,
    )
    first_proof = create_health_decision_proof(
        anchor=anchor,
        sequence=1,
        previous_signed_proof_sha256=None,
        prior_state=first_state,
        observation=first_observation,
        decision=first_decision,
    )
    first_signed = make_signed_proof(
        first_proof,
        anchor,
        marker=b"first-unhealthy-recovery-proof",
    )
    second_state = derive_next_health_evaluation_state(
        policy=anchor.policy,
        predecessor_decision=first_decision,
    )
    second_observation = _unhealthy_observation(make_observation(anchor, window_index=2))
    second_decision = evaluate_health_observation(
        policy=anchor.policy,
        prior_state=second_state,
        predecessor_decision=first_decision,
        observation=second_observation,
        evaluated_at=second_observation.observed_at,
    )
    second_proof = create_health_decision_proof(
        anchor=anchor,
        sequence=2,
        previous_signed_proof_sha256=canonical_sha256(first_signed),
        prior_state=second_state,
        observation=second_observation,
        decision=second_decision,
    )
    second_signed = make_signed_proof(
        second_proof,
        anchor,
        marker=b"second-unhealthy-recovery-proof",
    )
    return create_signed_health_decision_chain(
        anchor=anchor,
        signed_proofs=(first_signed, second_signed),
    )


def make_v2_verified_apply_receipt(root: RolloutRootV2) -> ExecutionReceipt:
    return ExecutionReceipt(
        schema_version=EXECUTION_RECEIPT_V1,
        receipt_id="cgreceipt:v2-recovery-apply-001",
        request_id="request-v2-recovery-apply-001",
        idempotency_key="v2-recovery-apply-001",
        capability_sha256="1" * 64,
        mutation_sha256="2" * 64,
        plan_sha256=canonical_sha256(root.content.rollout_plan),
        expected_poststate_sha256=recovery_target_configuration_sha256(
            root,
            stable_percent=90,
            candidate_percent=10,
        ),
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag=root.content.stable_snapshot.provider_etag,
        dispatch_not_after="2026-08-19T12:04:00Z",
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        provider_operation="operations/v2-recovery-apply-001",
        observed_etag="v2-canary-etag-8",
        observed_authority_epoch=1,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:03:00Z",
        evidence_ids=("evidence-v2-recovery-apply-001",),
    )


def _capability(authorization: RecoveryAuthorizationV1) -> SignedCapability:
    claims = CapabilityClaims(
        schema_version=CAPABILITY_CLAIMS_V1,
        capability_id=recovery_capability_id(authorization),
        issuer=authorization.issuer_identity,
        subject=authorization.recovery_identity,
        audience=authorization.recovery_audience,
        target=authorization.target,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        action=CapabilityAction.RECOVER_STABLE,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        stable_percent=100,
        candidate_percent=0,
        concurrency=authorization.concurrency,
        plan_sha256=authorization.plan_sha256,
        provider_etag=authorization.current_provider_etag,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        parent_capability_sha256=None,
        issued_at=authorization.issued_at,
        not_before=authorization.scheduled_at,
        expires_at=(
            "2026-08-19T12:07:30Z"
            if authorization.root_schema_version == "controlgraph.rollout-root/v2"
            else "2026-08-21T12:11:30Z"
        ),
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=authorization.capability_signing_key_version,
    )
    return SignedCapability(
        schema_version=SIGNED_CAPABILITY_V1,
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-recovery-capability"),
    )


def _mutation_intent(
    authorization: RecoveryAuthorizationV1,
) -> RecoveryMutationIntentV2:
    return RecoveryMutationIntentV2(
        schema_version=RECOVERY_MUTATION_INTENT_V2,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_schema_version=authorization.root_schema_version,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        action=CapabilityAction.RECOVER_STABLE,
        stable_revision=authorization.stable_revision,
        stable_revision_configuration_sha256=(authorization.stable_revision_configuration_sha256),
        candidate_revision=authorization.candidate_revision,
        candidate_revision_configuration_sha256=(
            authorization.candidate_revision_configuration_sha256
        ),
        stable_percent=100,
        candidate_percent=0,
        concurrency=authorization.concurrency,
        plan_sha256=authorization.plan_sha256,
        stable_snapshot_sha256=authorization.stable_snapshot_sha256,
        provider_etag=authorization.current_provider_etag,
        capability_id=authorization.capability_id,
        recovery_authorization_sha256=canonical_sha256(authorization),
        verified_apply_receipt=authorization.verified_apply_receipt,
        source_receipt_sha256=authorization.source_receipt_sha256,
        source_receipt_storage_revision=authorization.source_receipt_storage_revision,
        source=authorization.source,
        trigger_proof_sha256=authorization.trigger_proof_sha256,
        prestate_attestation_sha256=authorization.prestate_attestation_sha256,
        expected_prestate_sha256=authorization.expected_prestate_sha256,
        desired_poststate_sha256=authorization.desired_poststate_sha256,
        proof_valid_until=authorization.proof_valid_until,
        authorization=authorization,
    )


def _finish_bundle(
    *,
    root: RolloutRootV2 | RolloutRootV3,
    command: RecoveryCommandV2,
    requested_at: str,
    retrieved_at: str,
    valid_until: str,
    current_provider_etag: str,
    service_generation: int,
    task_expires_at: str,
) -> RecoveryV2Bundle:
    prestate_request = create_recovery_prestate_request(
        command=command,
        root=root,
        requested_at=requested_at,
        valid_until=valid_until,
    )
    prestate_result = create_recovery_prestate_result(
        request=prestate_request,
        current_provider_etag=current_provider_etag,
        service_generation=service_generation,
        retrieved_at=retrieved_at,
    )
    prestate_attestation = create_recovery_prestate_attestation(
        result=prestate_result,
        signature=encode_base64url(b"synthetic-recovery-prestate-attestation"),
    )
    authorization = create_recovery_authorization(
        root=root,
        command=command,
        prestate_attestation=prestate_attestation,
    )
    issuance_command = RecoveryCapabilityIssuanceCommandV2(
        schema_version=RECOVERY_CAPABILITY_ISSUANCE_COMMAND_V2,
        root_id=authorization.root_id,
        expected_root_sha256=authorization.root_sha256,
        expected_epoch=authorization.epoch,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        scheduled_at=authorization.scheduled_at,
        authorization=authorization,
        authorization_sha256=canonical_sha256(authorization),
    )
    capability = _capability(authorization)
    issuance_result = RecoveryCapabilityIssuanceResultV2(
        schema_version=RECOVERY_CAPABILITY_ISSUANCE_RESULT_V2,
        issuance_command=issuance_command,
        issuance_command_sha256=recovery_capability_issuance_command_sha256(issuance_command),
        authorization_sha256=canonical_sha256(authorization),
        capability_id=authorization.capability_id,
        capability=capability,
        capability_sha256=canonical_sha256(capability),
        issued_at=capability.claims.issued_at,
        expires_at=capability.claims.expires_at,
    )
    mutation_intent = _mutation_intent(authorization)
    task = RecoveryTaskRequestV2(
        schema_version=RECOVERY_TASK_REQUEST_V2,
        task_id=f"task-{capability.claims_sha256}",
        queue_region="us-central1",
        handler_audience=authorization.recovery_audience,
        scheduled_at=authorization.scheduled_at,
        expires_at=task_expires_at,
        capability=capability,
        intent=mutation_intent,
    )
    return RecoveryV2Bundle(
        root=root,
        command=command,
        prestate_request=prestate_request,
        prestate_result=prestate_result,
        prestate_attestation=prestate_attestation,
        authorization=authorization,
        issuance_command=issuance_command,
        issuance_result=issuance_result,
        mutation_intent=mutation_intent,
        task=task,
    )


def make_unhealthy_v3_recovery_bundle(
    root: RolloutRootV3 | None = None,
) -> RecoveryV2Bundle:
    if root is None:
        return _make_default_unhealthy_v3_recovery_bundle()

    rollout_root = root
    chain = make_unhealthy_recovery_chain(rollout_root)
    anchor = chain.anchor
    apply_locator = create_recovery_apply_receipt_locator(
        anchor.apply_receipt,
        storage_revision=2,
    )
    command = create_unhealthy_recovery_command(
        signed_health_chain=chain,
        verified_apply_receipt=apply_locator,
        request_id="request-unhealthy-recovery-001",
        idempotency_key="unhealthy-recovery-001",
        scheduled_at="2026-08-21T12:09:30Z",
    )
    return _finish_bundle(
        root=rollout_root,
        command=command,
        requested_at="2026-08-21T12:09:10Z",
        retrieved_at="2026-08-21T12:09:11Z",
        valid_until="2026-08-21T12:14:10Z",
        current_provider_etag="recovery-canary-etag-9",
        service_generation=9,
        task_expires_at="2026-08-21T12:11:30Z",
    )


@lru_cache(maxsize=1)
def _make_default_unhealthy_v3_recovery_bundle() -> RecoveryV2Bundle:
    return make_unhealthy_v3_recovery_bundle(make_health_root())


@lru_cache(maxsize=1)
def make_revoked_v2_recovery_bundle() -> RecoveryV2Bundle:
    root = make_root_v2_records().root
    proof = make_revocation_proof_records().proof
    apply_locator = create_recovery_apply_receipt_locator(
        make_v2_verified_apply_receipt(root),
        storage_revision=2,
    )
    command = create_revoked_v2_recovery_command(
        root=root,
        revocation_proof=proof,
        verified_apply_receipt=apply_locator,
        request_id="request-revoked-v2-recovery-001",
        idempotency_key="revoked-v2-recovery-001",
        scheduled_at="2026-08-19T12:05:30Z",
        confirmation=RECOVER_CAPTURED_STABLE,
    )
    return _finish_bundle(
        root=root,
        command=command,
        requested_at="2026-08-19T12:05:10Z",
        retrieved_at="2026-08-19T12:05:11Z",
        valid_until="2026-08-19T12:10:10Z",
        current_provider_etag="revoked-v2-canary-etag-9",
        service_generation=9,
        task_expires_at="2026-08-19T12:07:30Z",
    )


@lru_cache(maxsize=1)
def make_revoked_v3_recovery_bundle() -> RecoveryV2Bundle:
    records = make_root_v3_records()
    root = records.root
    proof = make_revocation_proof_records(
        root_records=records,
        committed_at="2026-08-21T12:05:00Z",
    ).proof
    apply_locator = create_recovery_apply_receipt_locator(
        make_verified_apply_receipt(root),
        storage_revision=2,
    )
    command = create_revoked_v3_recovery_command(
        root=root,
        revocation_proof=proof,
        verified_apply_receipt=apply_locator,
        request_id="request-revoked-v3-recovery-001",
        idempotency_key="revoked-v3-recovery-001",
        scheduled_at="2026-08-21T12:09:30Z",
        confirmation=RECOVER_CAPTURED_STABLE,
    )
    return _finish_bundle(
        root=root,
        command=command,
        requested_at="2026-08-21T12:09:10Z",
        retrieved_at="2026-08-21T12:09:11Z",
        valid_until="2026-08-21T12:14:10Z",
        current_provider_etag="revoked-v3-canary-etag-9",
        service_generation=9,
        task_expires_at="2026-08-21T12:11:30Z",
    )


__all__ = [
    "RecoveryV2Bundle",
    "make_revoked_v2_recovery_bundle",
    "make_revoked_v3_recovery_bundle",
    "make_unhealthy_recovery_chain",
    "make_unhealthy_v3_recovery_bundle",
    "make_v2_verified_apply_receipt",
]
