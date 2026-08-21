from __future__ import annotations

import pytest
from test_health_contracts import (
    _distribution,
    _observation,
    _policy,
    _query,
    _samples,
    _target,
)

from controlgraph_canary.application.health_evaluation import (
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.contracts import (
    ContractError,
    HealthDecisionStatus,
    HealthReasonCode,
    MonitoringObservationTiming,
    MonitoringQueryKind,
    canonical_json_bytes,
    canonical_sha256,
    monitoring_sample_set_sha256,
)


def _initial_state():  # type: ignore[no-untyped-def]
    return initial_health_evaluation_state(
        policy=_policy(),
        target=_target(),
        root_id="cgroot:" + "1" * 64,
        root_sha256="1" * 64,
        epoch=1,
        candidate_revision="controlgraph-reference-target-candidate-v3",
        observation_started_at="2026-08-21T12:00:00Z",
    )


def _second_observation():  # type: ignore[no-untyped-def]
    queries = tuple(
        _query(
            kind,
            window_started_at="2026-08-21T12:01:00Z",
            window_ended_at="2026-08-21T12:02:00Z",
        )
        for kind in MonitoringQueryKind
    )
    samples = _samples(queries)
    return _observation(
        observation_id="health-window-002",
        window_index=2,
        window_started_at="2026-08-21T12:01:00Z",
        window_ended_at="2026-08-21T12:02:00Z",
        observed_at="2026-08-21T12:05:00Z",
        queries=queries,
        query_sha256s=tuple(canonical_sha256(query) for query in queries),
        samples=samples,
        sample_sha256s=tuple(canonical_sha256(sample) for sample in samples),
        latency_distribution=_distribution(samples[-1]),
    )


def test_initial_state_recomputes_the_canonical_policy_digest() -> None:
    policy = _policy()

    state = initial_health_evaluation_state(
        policy=policy,
        target=_target(),
        root_id="cgroot:" + "1" * 64,
        root_sha256="1" * 64,
        epoch=1,
        candidate_revision="controlgraph-reference-target-candidate-v3",
        observation_started_at="2026-08-21T12:00:00Z",
    )

    assert state.policy_sha256 == canonical_sha256(policy)
    assert state.evaluated_windows == 0


def test_canonical_observations_produce_a_terminal_healthy_streak() -> None:
    policy = _policy()
    initial = _initial_state()

    first = evaluate_health_observation(
        policy=policy,
        prior_state=initial,
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    second = evaluate_health_observation(
        policy=policy,
        prior_state=first.next_state,
        observation=_second_observation(),
        evaluated_at="2026-08-21T12:05:00Z",
    )

    assert first.status is HealthDecisionStatus.WAIT
    assert first.reason_codes == (
        HealthReasonCode.HEALTHY_THRESHOLDS_MET,
        HealthReasonCode.HEALTHY_STREAK_PENDING,
    )
    assert first.next_state.consecutive_healthy_windows == 1
    assert first.next_state.consumed_sample_set_sha256s == (
        monitoring_sample_set_sha256(_observation().sample_sha256s),
    )
    assert second.status is HealthDecisionStatus.HEALTHY
    assert second.reason_codes[-1] is HealthReasonCode.HEALTHY_STREAK_MET
    assert second.next_evaluation_at is None
    assert second.observation_sha256 == canonical_sha256(_second_observation())


def test_cross_call_observation_replay_preserves_the_healthy_streak() -> None:
    policy = _policy()
    observation = _observation()
    recollected = _observation(observed_at="2026-08-21T12:04:01Z")
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=observation,
        evaluated_at="2026-08-21T12:04:00Z",
    )

    replayed = evaluate_health_observation(
        policy=policy,
        prior_state=first.next_state,
        observation=recollected,
        evaluated_at="2026-08-21T12:04:01Z",
    )
    terminal = evaluate_health_observation(
        policy=policy,
        prior_state=replayed.next_state,
        observation=_second_observation(),
        evaluated_at="2026-08-21T12:05:00Z",
    )

    assert replayed.status is HealthDecisionStatus.WAIT
    assert replayed.reason_codes == (HealthReasonCode.WINDOW_DUPLICATE,)
    assert replayed.next_state == first.next_state
    assert canonical_sha256(recollected) != canonical_sha256(observation)
    assert replayed.next_evaluation_at == "2026-08-21T12:05:00Z"
    assert terminal.status is HealthDecisionStatus.HEALTHY


def test_conflict_metadata_takes_precedence_over_adapter_replay_deduplication() -> None:
    policy = _policy()
    observation = _observation()
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=observation,
        evaluated_at="2026-08-21T12:04:00Z",
    )
    selected = observation.sample_sha256s
    conflict = _observation(
        observation_id="health-window-001-conflict",
        observed_at="2026-08-21T12:04:01Z",
        source_sample_sha256s=tuple(sorted((*selected, "f" * 64))),
        duplicate_count=1,
        conflicting_duplicate=True,
    )

    replayed = evaluate_health_observation(
        policy=policy,
        prior_state=first.next_state,
        observation=conflict,
        evaluated_at="2026-08-21T12:04:01Z",
    )

    assert replayed.status is HealthDecisionStatus.INSUFFICIENT_EVIDENCE
    assert replayed.reason_codes == (HealthReasonCode.SAMPLE_CONFLICTING_DUPLICATE,)
    assert replayed.next_state.consecutive_healthy_windows == 0


def test_evaluator_adapter_binds_distinct_conflict_sets_to_distinct_observations() -> None:
    selected = _observation().sample_sha256s
    first_conflict = _observation(
        observation_id="health-window-001-conflict",
        source_sample_sha256s=tuple(sorted((*selected, "e" * 64))),
        duplicate_count=1,
        conflicting_duplicate=True,
    )
    second_conflict = _observation(
        observation_id="health-window-001-conflict",
        source_sample_sha256s=tuple(sorted((*selected, "f" * 64))),
        duplicate_count=1,
        conflicting_duplicate=True,
    )

    first = evaluate_health_observation(
        policy=_policy(),
        prior_state=_initial_state(),
        observation=first_conflict,
        evaluated_at="2026-08-21T12:04:00Z",
    )
    second = evaluate_health_observation(
        policy=_policy(),
        prior_state=_initial_state(),
        observation=second_conflict,
        evaluated_at="2026-08-21T12:04:00Z",
    )

    assert first.observation_sha256 == canonical_sha256(first_conflict)
    assert second.observation_sha256 == canonical_sha256(second_conflict)
    assert first.observation_sha256 != second.observation_sha256
    assert canonical_sha256(first) != canonical_sha256(second)


def test_identical_canonical_inputs_produce_identical_decision_bytes() -> None:
    inputs = {
        "policy": _policy(),
        "prior_state": _initial_state(),
        "observation": _observation(),
        "evaluated_at": "2026-08-21T12:04:00Z",
    }

    first = evaluate_health_observation(**inputs)
    second = evaluate_health_observation(**inputs)

    assert first == second
    assert first.decision_id.startswith("cghealth:")
    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_mapper_rejects_a_state_with_a_caller_asserted_policy_digest() -> None:
    state = _initial_state().model_copy(update={"policy_sha256": "f" * 64})

    with pytest.raises(ValueError, match="policy digest"):
        evaluate_health_observation(
            policy=_policy(),
            prior_state=state,
            observation=_observation(),
            evaluated_at="2026-08-21T12:04:00Z",
        )


@pytest.mark.parametrize(
    "observation_started_at",
    ("1969-12-31T23:59:59Z", "9999-12-31T23:59:00Z"),
)
def test_mapper_rejects_timestamps_outside_the_evaluator_horizon(
    observation_started_at: str,
) -> None:
    state = initial_health_evaluation_state(
        policy=_policy(),
        target=_target(),
        root_id="cgroot:" + "1" * 64,
        root_sha256="1" * 64,
        epoch=1,
        candidate_revision="controlgraph-reference-target-candidate-v3",
        observation_started_at=observation_started_at,
    )

    with pytest.raises(ValueError, match=r"epoch|calendar range"):
        evaluate_health_observation(
            policy=_policy(),
            prior_state=state,
            observation=None,
            evaluated_at=observation_started_at,
        )


def test_early_observation_waits_without_advancing_state() -> None:
    early = _observation(
        observed_at="2026-08-21T12:03:59Z",
        timing=MonitoringObservationTiming.EARLY,
    )
    initial = _initial_state()

    decision = evaluate_health_observation(
        policy=_policy(),
        prior_state=initial,
        observation=early,
        evaluated_at="2026-08-21T12:04:00Z",
    )

    assert decision.status is HealthDecisionStatus.WAIT
    assert decision.reason_codes == (HealthReasonCode.SAMPLE_EARLY,)
    assert decision.next_state == initial
    assert decision.next_evaluation_at == "2026-08-21T12:04:00Z"


def test_invalid_canonical_scope_is_rejected_before_it_can_claim_health() -> None:
    mismatched = _observation().model_copy(update={"root_id": "cgroot:" + "9" * 64})

    with pytest.raises(ContractError):
        evaluate_health_observation(
            policy=_policy(),
            prior_state=_initial_state(),
            observation=mismatched,
            evaluated_at="2026-08-21T12:04:00Z",
        )


def test_terminal_state_cannot_be_reused() -> None:
    policy = _policy()
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    terminal = evaluate_health_observation(
        policy=policy,
        prior_state=first.next_state,
        observation=_second_observation(),
        evaluated_at="2026-08-21T12:05:00Z",
    )

    reused = evaluate_health_observation(
        policy=policy,
        prior_state=terminal.next_state,
        observation=None,
        evaluated_at="2026-08-21T12:06:00Z",
    )

    assert reused.status is HealthDecisionStatus.INSUFFICIENT_EVIDENCE
    assert reused.reason_codes == (HealthReasonCode.STATE_TERMINAL,)
    assert reused.next_evaluation_at is None
