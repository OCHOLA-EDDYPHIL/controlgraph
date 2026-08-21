"""Canonical boundary adapter for the pure deterministic health evaluator."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import cast

from controlgraph_canary.authority.health import (
    HealthEvaluationState,
    HealthPolicy,
    HealthWindowSample,
    evaluate_health,
)
from controlgraph_canary.contracts.codec import (
    RestrictedJson,
    canonical_json_value_bytes,
    canonical_sha256,
)
from controlgraph_canary.contracts.health import (
    HEALTH_DECISION_V1,
    HEALTH_EVALUATION_STATE_V1,
    HealthDecisionStatus,
    HealthDecisionV1,
    HealthEvaluationStateV1,
    HealthReasonCode,
    MonitoringObservationCompleteness,
    MonitoringWindowObservationV1,
    RolloutHealthPolicyV2,
)
from controlgraph_canary.contracts.models import TargetBinding

_DECISION_ID_DOMAIN = b"controlgraph.health-decision-id/v1\0"
_MAX_UTC_EPOCH_SECOND = 253_402_300_799


def _epoch_seconds(value: str) -> int:
    result = int(
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=UTC)
        .timestamp()
    )
    if result < 0:
        raise ValueError("health timestamps must not precede the Unix epoch")
    return result


def _utc_second(value: int) -> str:
    if value < 0 or value > _MAX_UTC_EPOCH_SECOND:
        raise ValueError("health timestamp exceeds the UTC calendar range")
    return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def initial_health_evaluation_state(
    *,
    policy: RolloutHealthPolicyV2,
    target: TargetBinding,
    root_id: str,
    root_sha256: str,
    epoch: int,
    candidate_revision: str,
    observation_started_at: str,
) -> HealthEvaluationStateV1:
    """Create the only valid empty state for a root-bound policy evaluation."""

    if type(policy) is not RolloutHealthPolicyV2:
        raise TypeError("policy must be an exact RolloutHealthPolicyV2")
    if type(target) is not TargetBinding:
        raise TypeError("target must be an exact TargetBinding")
    return HealthEvaluationStateV1(
        schema_version=HEALTH_EVALUATION_STATE_V1,
        policy_schema_version=policy.schema_version,
        policy_sha256=canonical_sha256(policy),
        target=target,
        root_id=root_id,
        root_sha256=root_sha256,
        epoch=epoch,
        candidate_revision=candidate_revision,
        observation_started_at=observation_started_at,
        last_window_ended_at=None,
        consecutive_healthy_windows=0,
        consecutive_unhealthy_windows=0,
        evaluated_windows=0,
        last_observation_sha256=None,
        consumed_sample_set_sha256s=(),
        prior_decision_sha256=None,
    )


def _authority_policy(
    policy: RolloutHealthPolicyV2,
    state: HealthEvaluationStateV1,
) -> HealthPolicy:
    policy_sha256 = canonical_sha256(policy)
    if state.policy_schema_version != policy.schema_version:
        raise ValueError("health state policy version does not match the supplied policy")
    if state.policy_sha256 != policy_sha256:
        raise ValueError("health state policy digest does not match the supplied policy")
    observation_started_at = _epoch_seconds(state.observation_started_at)
    if (
        observation_started_at
        + policy.maximum_windows * policy.window_seconds
        + policy.maximum_observation_delay_seconds
        > _MAX_UTC_EPOCH_SECOND
    ):
        raise ValueError("health policy horizon exceeds the UTC calendar range")
    return HealthPolicy(
        policy_version=policy.schema_version,
        policy_sha256=policy_sha256,
        project_id=state.target.project_id,
        region=state.target.region,
        environment=state.target.environment,
        service_name=state.target.service_name,
        root_id=state.root_id,
        root_sha256=state.root_sha256,
        epoch=state.epoch,
        candidate_revision=state.candidate_revision,
        observation_started_at=observation_started_at,
        window_seconds=policy.window_seconds,
        observation_delay_seconds=policy.observation_delay_seconds,
        maximum_observation_delay_seconds=policy.maximum_observation_delay_seconds,
        minimum_request_count=policy.minimum_request_count,
        healthy_maximum_error_rate_basis_points=(
            policy.healthy_maximum_error_rate_basis_points
        ),
        unhealthy_minimum_error_rate_basis_points=(
            policy.unhealthy_minimum_error_rate_basis_points
        ),
        healthy_maximum_p95_latency_ms=policy.healthy_maximum_p95_latency_ms,
        unhealthy_minimum_p95_latency_ms=policy.unhealthy_minimum_p95_latency_ms,
        healthy_minimum_availability_basis_points=(
            policy.healthy_minimum_availability_basis_points
        ),
        unhealthy_maximum_availability_basis_points=(
            policy.unhealthy_maximum_availability_basis_points
        ),
        healthy_consecutive_windows=policy.healthy_consecutive_windows,
        unhealthy_consecutive_windows=policy.unhealthy_consecutive_windows,
        maximum_windows=policy.maximum_windows,
    )


def _authority_state(state: HealthEvaluationStateV1) -> HealthEvaluationState:
    return HealthEvaluationState(
        policy_version=state.policy_schema_version,
        policy_sha256=state.policy_sha256,
        project_id=state.target.project_id,
        region=state.target.region,
        environment=state.target.environment,
        service_name=state.target.service_name,
        root_id=state.root_id,
        root_sha256=state.root_sha256,
        epoch=state.epoch,
        candidate_revision=state.candidate_revision,
        observation_started_at=_epoch_seconds(state.observation_started_at),
        last_window_ended_at=(
            _epoch_seconds(state.last_window_ended_at)
            if state.last_window_ended_at is not None
            else None
        ),
        consecutive_healthy_windows=state.consecutive_healthy_windows,
        consecutive_unhealthy_windows=state.consecutive_unhealthy_windows,
        evaluated_windows=state.evaluated_windows,
        last_observation_sha256=state.last_observation_sha256,
        consumed_sample_set_sha256s=state.consumed_sample_set_sha256s,
        prior_decision_sha256=state.prior_decision_sha256,
    )


def _authority_sample(
    observation: MonitoringWindowObservationV1,
) -> HealthWindowSample:
    distribution = observation.latency_distribution
    return HealthWindowSample(
        observation_sha256=canonical_sha256(observation),
        query_sha256s=observation.query_sha256s,
        sample_sha256s=observation.sample_sha256s,
        policy_sha256=observation.policy_sha256,
        project_id=observation.target.project_id,
        region=observation.target.region,
        environment=observation.target.environment,
        service_name=observation.target.service_name,
        root_id=observation.root_id,
        root_sha256=observation.root_sha256,
        epoch=observation.epoch,
        candidate_revision=observation.candidate_revision,
        observation_started_at=_epoch_seconds(observation.observation_started_at),
        window_index=observation.window_index,
        window_started_at=_epoch_seconds(observation.window_started_at),
        window_ended_at=_epoch_seconds(observation.window_ended_at),
        observed_at=_epoch_seconds(observation.observed_at),
        request_count=observation.request_count or 0,
        response_1xx_count=observation.response_1xx_count or 0,
        successful_request_count=observation.successful_request_count or 0,
        response_3xx_count=observation.response_3xx_count or 0,
        response_4xx_count=observation.response_4xx_count or 0,
        server_error_count=observation.server_error_count or 0,
        p95_latency_ms=distribution.p95_latency_ms if distribution is not None else 0,
        complete=(
            observation.completeness is MonitoringObservationCompleteness.COMPLETE
        ),
        missing=(
            observation.completeness is MonitoringObservationCompleteness.MISSING
        ),
        duplicate_count=observation.duplicate_count,
        conflicting_duplicate=observation.conflicting_duplicate,
    )


def _contract_state(
    state: HealthEvaluationState,
    target: TargetBinding,
) -> HealthEvaluationStateV1:
    return HealthEvaluationStateV1(
        schema_version=HEALTH_EVALUATION_STATE_V1,
        policy_schema_version="controlgraph.rollout-health-policy/v2",
        policy_sha256=state.policy_sha256,
        target=target,
        root_id=state.root_id,
        root_sha256=state.root_sha256,
        epoch=state.epoch,
        candidate_revision=state.candidate_revision,
        observation_started_at=_utc_second(state.observation_started_at),
        last_window_ended_at=(
            _utc_second(state.last_window_ended_at)
            if state.last_window_ended_at is not None
            else None
        ),
        consecutive_healthy_windows=state.consecutive_healthy_windows,
        consecutive_unhealthy_windows=state.consecutive_unhealthy_windows,
        evaluated_windows=state.evaluated_windows,
        last_observation_sha256=state.last_observation_sha256,
        consumed_sample_set_sha256s=state.consumed_sample_set_sha256s,
        prior_decision_sha256=state.prior_decision_sha256,
    )


def _decision_id(decision: HealthDecisionV1) -> str:
    projection = cast(
        RestrictedJson,
        decision.model_dump(mode="json", exclude={"decision_id"}),
    )
    digest = hashlib.sha256(
        _DECISION_ID_DOMAIN + canonical_json_value_bytes(projection)
    ).hexdigest()
    return f"cghealth:{digest}"


def evaluate_health_observation(
    *,
    policy: RolloutHealthPolicyV2,
    prior_state: HealthEvaluationStateV1,
    observation: MonitoringWindowObservationV1 | None,
    evaluated_at: str,
) -> HealthDecisionV1:
    """Validate canonical inputs, evaluate once, and return a canonical decision."""

    if type(policy) is not RolloutHealthPolicyV2:
        raise TypeError("policy must be an exact RolloutHealthPolicyV2")
    if type(prior_state) is not HealthEvaluationStateV1:
        raise TypeError("prior_state must be an exact HealthEvaluationStateV1")
    if observation is not None and type(observation) is not MonitoringWindowObservationV1:
        raise TypeError("observation must be an exact MonitoringWindowObservationV1")

    authority_policy = _authority_policy(policy, prior_state)
    authority_state = _authority_state(prior_state)
    samples = (() if observation is None else (_authority_sample(observation),))
    result = evaluate_health(
        authority_policy,
        samples,
        authority_state,
        evaluated_at=_epoch_seconds(evaluated_at),
    )
    next_state = _contract_state(result.state, prior_state.target)
    decision = HealthDecisionV1(
        schema_version=HEALTH_DECISION_V1,
        decision_id="health-decision-pending",
        status=HealthDecisionStatus(result.decision.value),
        reason_codes=tuple(HealthReasonCode(reason.value) for reason in result.reasons),
        policy_schema_version=policy.schema_version,
        policy_sha256=canonical_sha256(policy),
        target=prior_state.target,
        root_id=prior_state.root_id,
        root_sha256=prior_state.root_sha256,
        epoch=prior_state.epoch,
        candidate_revision=prior_state.candidate_revision,
        prior_state_sha256=canonical_sha256(prior_state),
        next_state=next_state,
        observation_sha256=result.observation_sha256,
        query_sha256s=result.query_sha256s,
        sample_sha256s=result.sample_sha256s,
        window_started_at=(
            _utc_second(result.window_started_at)
            if result.window_started_at is not None
            else None
        ),
        window_ended_at=(
            _utc_second(result.window_ended_at)
            if result.window_ended_at is not None
            else None
        ),
        request_count=result.request_count,
        successful_request_count=result.successful_request_count,
        server_error_count=result.server_error_count,
        error_rate_basis_points=result.error_rate_basis_points,
        availability_basis_points=result.availability_basis_points,
        p95_latency_ms=result.p95_latency_ms,
        evaluated_at=evaluated_at,
        next_evaluation_at=(
            _utc_second(result.next_evaluation_at)
            if result.next_evaluation_at is not None
            else None
        ),
    )
    final_value = decision.model_dump(mode="python")
    final_value["decision_id"] = _decision_id(decision)
    return HealthDecisionV1.model_validate(final_value)


__all__ = [
    "evaluate_health_observation",
    "initial_health_evaluation_state",
]
