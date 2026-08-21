from __future__ import annotations

from datetime import UTC, datetime, timedelta

from root_v2_test_data import make_root_v2_records
from test_health_contracts import _distribution, _policy, _samples

from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.health_evaluation import (
    derive_next_health_evaluation_state,
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.contracts.codec import (
    canonical_sha256,
    encode_base64url,
)
from controlgraph_canary.contracts.health import (
    HealthSignal,
    MonitoringDistributionV1,
    MonitoringObservationCompleteness,
    MonitoringObservationTiming,
    MonitoringWindowObservationV1,
    derive_monitoring_metric_queries,
)
from controlgraph_canary.contracts.health_execution import (
    HEALTH_ATTESTATION_PURPOSE,
    HEALTH_DECISION_PROOF_V1,
    P256_SIGNING_ALGORITHM,
    SIGNED_HEALTH_DECISION_PROOF_V1,
    HealthDecisionProofV1,
    PostApplyHealthAnchorV1,
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    create_health_decision_proof,
    create_post_apply_health_anchor,
    create_signed_health_decision_chain,
    health_attestation_signing_input_sha256,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReceiptOutcome,
)
from controlgraph_canary.contracts.root_creation import (
    ROLLOUT_ROOT_CONTENT_V3,
    RolloutRootContentV3,
    RolloutRootV3,
    create_rollout_root_v3,
)
from controlgraph_canary.contracts.storage import execution_receipt_logical_id


def make_health_root() -> RolloutRootV3:
    prior = make_root_v2_records().root
    policy = _policy()
    plan = prior.content.rollout_plan.model_copy(
        update={"health_policy_sha256": canonical_sha256(policy)}
    )
    bounds = prior.content.authority_bounds.model_copy(
        update={"plan_sha256": canonical_sha256(plan)}
    )
    return create_rollout_root_v3(
        RolloutRootContentV3(
            schema_version=ROLLOUT_ROOT_CONTENT_V3,
            target=prior.content.target,
            stable_snapshot=prior.content.stable_snapshot,
            health_policy=policy,
            rollout_plan=plan,
            authority_bounds=bounds,
            evidence_signing_key_version=prior.content.evidence_signing_key_version,
            approved_by=prior.content.approved_by,
            approved_by_subject=prior.content.approved_by_subject,
            approved_at=prior.content.approved_at,
        )
    )


def target_state_sha256(
    root: RolloutRootV3,
    *,
    stable_percent: int,
    candidate_percent: int,
) -> str:
    plan = root.content.rollout_plan
    return target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=root.content.target,
            stable_revision=plan.stable_revision,
            candidate_revision=plan.candidate_revision,
            stable_percent=stable_percent,
            candidate_percent=candidate_percent,
            concurrency=plan.concurrency,
        )
    )


def make_verified_apply_receipt(
    root: RolloutRootV3,
    *,
    updated_at: str = "2026-08-21T12:03:00Z",
) -> ExecutionReceipt:
    target = root.content.target
    return ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(target, "apply-health-001"),
        request_id="request-apply-health-001",
        idempotency_key="apply-health-001",
        capability_sha256="1" * 64,
        mutation_sha256="2" * 64,
        plan_sha256=canonical_sha256(root.content.rollout_plan),
        expected_poststate_sha256=target_state_sha256(
            root,
            stable_percent=90,
            candidate_percent=10,
        ),
        target=target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag=root.content.stable_snapshot.provider_etag,
        dispatch_not_after="2026-08-21T12:10:00Z",
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        provider_operation="operations/apply-health-001",
        observed_etag="canary-etag-8",
        observed_authority_epoch=1,
        created_at="2026-08-21T12:02:00Z",
        updated_at=updated_at,
        evidence_ids=("evidence-apply-health-001",),
    )


def make_anchor() -> tuple[RolloutRootV3, PostApplyHealthAnchorV1]:
    root = make_health_root()
    return root, create_post_apply_health_anchor(
        root=root,
        apply_receipt=make_verified_apply_receipt(root),
    )


def _utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _utc_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_observation(
    anchor: PostApplyHealthAnchorV1,
    *,
    window_index: int,
    observed_at: str | None = None,
) -> MonitoringWindowObservationV1:
    started = _utc(anchor.observation_started_at) + timedelta(
        seconds=(window_index - 1) * anchor.policy.window_seconds
    )
    ended = started + timedelta(seconds=anchor.policy.window_seconds)
    observed = observed_at or _utc_text(
        ended + timedelta(seconds=anchor.policy.observation_delay_seconds)
    )
    queries = derive_monitoring_metric_queries(
        anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        window_started_at=_utc_text(started),
        window_ended_at=_utc_text(ended),
    )
    samples = _samples(queries)
    sample_sha256s = tuple(canonical_sha256(sample) for sample in samples)
    distribution = _distribution(samples[-1])
    assert type(distribution) is MonitoringDistributionV1
    return MonitoringWindowObservationV1(
        schema_version="controlgraph.monitoring-window-observation/v1",
        observation_id=f"health-anchor-window-{window_index:02d}",
        policy_schema_version=anchor.policy.schema_version,
        policy_sha256=anchor.policy_sha256,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
        window_index=window_index,
        window_started_at=_utc_text(started),
        window_ended_at=_utc_text(ended),
        observed_at=observed,
        queries=queries,
        query_sha256s=tuple(canonical_sha256(query) for query in queries),
        samples=samples,
        sample_sha256s=sample_sha256s,
        source_sample_sha256s=tuple(sorted(sample_sha256s)),
        completeness=MonitoringObservationCompleteness.COMPLETE,
        timing=MonitoringObservationTiming.READY,
        missing_signals=(),
        duplicate_count=0,
        conflicting_duplicate=False,
        request_count=1_000,
        response_1xx_count=0,
        successful_request_count=995,
        response_3xx_count=2,
        response_4xx_count=2,
        server_error_count=1,
        latency_distribution=distribution,
    )


def make_missing_observation(
    anchor: PostApplyHealthAnchorV1,
    *,
    window_index: int,
    observed_at: str,
) -> MonitoringWindowObservationV1:
    complete = make_observation(
        anchor,
        window_index=window_index,
        observed_at=observed_at,
    )
    elapsed = int((_utc(observed_at) - _utc(complete.window_ended_at)).total_seconds())
    timing = (
        MonitoringObservationTiming.READY
        if elapsed <= anchor.policy.maximum_observation_delay_seconds
        else MonitoringObservationTiming.LATE
    )
    return MonitoringWindowObservationV1(
        schema_version=complete.schema_version,
        observation_id=f"health-anchor-window-{window_index:02d}-missing-{elapsed}",
        policy_schema_version=complete.policy_schema_version,
        policy_sha256=complete.policy_sha256,
        target=complete.target,
        root_id=complete.root_id,
        root_sha256=complete.root_sha256,
        epoch=complete.epoch,
        candidate_revision=complete.candidate_revision,
        observation_started_at=complete.observation_started_at,
        window_index=complete.window_index,
        window_started_at=complete.window_started_at,
        window_ended_at=complete.window_ended_at,
        observed_at=observed_at,
        queries=complete.queries,
        query_sha256s=complete.query_sha256s,
        samples=(),
        sample_sha256s=(),
        source_sample_sha256s=(),
        completeness=MonitoringObservationCompleteness.MISSING,
        timing=timing,
        missing_signals=tuple(HealthSignal),
        duplicate_count=0,
        conflicting_duplicate=False,
        request_count=None,
        response_1xx_count=None,
        successful_request_count=None,
        response_3xx_count=None,
        response_4xx_count=None,
        server_error_count=None,
        latency_distribution=None,
    )


def make_signed_proof(
    proof: HealthDecisionProofV1,
    anchor: PostApplyHealthAnchorV1,
    *,
    marker: bytes = b"synthetic-health-attestation",
) -> SignedHealthDecisionProofV1:
    return SignedHealthDecisionProofV1(
        schema_version=SIGNED_HEALTH_DECISION_PROOF_V1,
        proof=proof,
        purpose=HEALTH_ATTESTATION_PURPOSE,
        signing_key_version=anchor.evidence_signing_key_version,
        signing_algorithm=P256_SIGNING_ALGORITHM,
        payload_sha256=canonical_sha256(proof),
        signing_input_sha256=health_attestation_signing_input_sha256(
            proof,
            anchor.evidence_signing_key_version,
        ),
        signature=encode_base64url(marker),
    )


def make_healthy_chain() -> SignedHealthDecisionChainV1:
    _, anchor = make_anchor()
    first_state = initial_health_evaluation_state(
        policy=anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
    )
    first_observation = make_observation(anchor, window_index=1)
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
    first_signed = make_signed_proof(first_proof, anchor, marker=b"first-health-proof")
    linked_state = derive_next_health_evaluation_state(
        policy=anchor.policy,
        predecessor_decision=first_decision,
    )
    second_observation = make_observation(anchor, window_index=2)
    second_decision = evaluate_health_observation(
        policy=anchor.policy,
        prior_state=linked_state,
        predecessor_decision=first_decision,
        observation=second_observation,
        evaluated_at=second_observation.observed_at,
    )
    second_proof = create_health_decision_proof(
        anchor=anchor,
        sequence=2,
        previous_signed_proof_sha256=canonical_sha256(first_signed),
        prior_state=linked_state,
        observation=second_observation,
        decision=second_decision,
    )
    second_signed = make_signed_proof(second_proof, anchor, marker=b"second-health-proof")
    return create_signed_health_decision_chain(
        anchor=anchor,
        signed_proofs=(first_signed, second_signed),
    )


__all__ = [
    "HEALTH_DECISION_PROOF_V1",
    "make_anchor",
    "make_health_root",
    "make_healthy_chain",
    "make_missing_observation",
    "make_observation",
    "make_signed_proof",
    "make_verified_apply_receipt",
    "target_state_sha256",
]
