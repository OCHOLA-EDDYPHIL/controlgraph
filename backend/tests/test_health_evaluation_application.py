from __future__ import annotations

import pytest
from test_health_contracts import (
    _distribution,
    _observation,
    _policy,
    _query,
    _samples,
    _target,
    _window_observation,
)

from controlgraph_canary.application.health_evaluation import (
    derive_next_health_evaluation_state,
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.contracts import (
    ContractError,
    HealthDecisionStatus,
    HealthEvaluationStateV1,
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
        candidate_revision="controlgraph-reference-target-candidate-v4",
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


def _next_state(decision):  # type: ignore[no-untyped-def]
    return derive_next_health_evaluation_state(
        policy=_policy(),
        predecessor_decision=decision,
    )


def test_initial_state_recomputes_the_canonical_policy_digest() -> None:
    policy = _policy()

    state = initial_health_evaluation_state(
        policy=policy,
        target=_target(),
        root_id="cgroot:" + "1" * 64,
        root_sha256="1" * 64,
        epoch=1,
        candidate_revision="controlgraph-reference-target-candidate-v4",
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
        prior_state=_next_state(first),
        predecessor_decision=first,
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
        prior_state=_next_state(first),
        predecessor_decision=first,
        observation=recollected,
        evaluated_at="2026-08-21T12:04:01Z",
    )
    terminal = evaluate_health_observation(
        policy=policy,
        prior_state=_next_state(replayed),
        predecessor_decision=replayed,
        observation=_second_observation(),
        evaluated_at="2026-08-21T12:05:00Z",
    )

    assert replayed.status is HealthDecisionStatus.WAIT
    assert replayed.reason_codes == (HealthReasonCode.WINDOW_DUPLICATE,)
    assert replayed.next_state == _next_state(first)
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
        prior_state=_next_state(first),
        predecessor_decision=first,
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
        candidate_revision="controlgraph-reference-target-candidate-v4",
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

    linked_state = _next_state(decision)
    resumed = evaluate_health_observation(
        policy=_policy(),
        prior_state=linked_state,
        predecessor_decision=decision,
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )

    assert linked_state.evaluated_windows == 0
    assert linked_state.prior_decision_sha256 == canonical_sha256(decision)
    assert resumed.reason_codes == (
        HealthReasonCode.HEALTHY_THRESHOLDS_MET,
        HealthReasonCode.HEALTHY_STREAK_PENDING,
    )


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
        prior_state=_next_state(first),
        predecessor_decision=first,
        observation=_second_observation(),
        evaluated_at="2026-08-21T12:05:00Z",
    )

    with pytest.raises(ValueError, match="terminal health decision"):
        derive_next_health_evaluation_state(
            policy=policy,
            predecessor_decision=terminal,
        )


def test_non_initial_state_requires_its_exact_canonical_predecessor() -> None:
    policy = _policy()
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    linked_state = _next_state(first)

    assert linked_state.prior_decision_sha256 == canonical_sha256(first)
    with pytest.raises(ValueError, match="predecessor decision is required"):
        evaluate_health_observation(
            policy=policy,
            prior_state=linked_state,
            observation=_second_observation(),
            evaluated_at="2026-08-21T12:05:00Z",
        )


def test_forged_streak_state_cannot_be_advanced() -> None:
    policy = _policy()
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    forged_values = _next_state(first).model_dump(mode="python")
    forged_values["consecutive_healthy_windows"] = 0
    forged_state = HealthEvaluationStateV1.model_validate(forged_values)

    with pytest.raises(ValueError, match="exact predecessor decision"):
        evaluate_health_observation(
            policy=policy,
            prior_state=forged_state,
            predecessor_decision=first,
            observation=_second_observation(),
            evaluated_at="2026-08-21T12:05:00Z",
        )


def test_predecessor_replay_is_idempotent_and_cannot_extend_the_streak() -> None:
    policy = _policy()
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    linked_state = _next_state(first)
    inputs = {
        "policy": policy,
        "prior_state": linked_state,
        "predecessor_decision": first,
        "observation": _second_observation(),
        "evaluated_at": "2026-08-21T12:05:00Z",
    }

    first_replay = evaluate_health_observation(**inputs)
    second_replay = evaluate_health_observation(**inputs)

    assert first_replay == second_replay
    assert canonical_sha256(first_replay) == canonical_sha256(second_replay)
    assert first_replay.next_state.consecutive_healthy_windows == 2


def test_noncanonical_predecessor_decision_id_is_rejected() -> None:
    first = evaluate_health_observation(
        policy=_policy(),
        prior_state=_initial_state(),
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    forged_predecessor = first.model_copy(update={"decision_id": "forged-decision"})

    with pytest.raises(ValueError, match="decision id is not canonical"):
        derive_next_health_evaluation_state(
            policy=_policy(),
            predecessor_decision=forged_predecessor,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("epoch", 2),
        ("candidate_revision", "controlgraph-reference-target-forged"),
        ("target", _target().model_copy(update={"environment": "other"})),
        ("root_id", "cgroot:" + "2" * 64),
    ),
)
def test_predecessor_rejects_scope_forgery(field: str, value: object) -> None:
    policy = _policy()
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    state_values = _next_state(first).model_dump(mode="python")
    state_values[field] = value
    if field == "root_id":
        state_values["root_sha256"] = "2" * 64
    forged_state = HealthEvaluationStateV1.model_validate(state_values)

    with pytest.raises(ValueError, match="exact predecessor decision"):
        evaluate_health_observation(
            policy=policy,
            prior_state=forged_state,
            predecessor_decision=first,
            observation=_second_observation(),
            evaluated_at="2026-08-21T12:05:00Z",
        )


def test_branch_state_cannot_be_paired_with_another_predecessor() -> None:
    policy = _policy()
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    linked_state = _next_state(first)
    recollected = _observation(observed_at="2026-08-21T12:04:01Z")
    replay_decision = evaluate_health_observation(
        policy=policy,
        prior_state=linked_state,
        predecessor_decision=first,
        observation=recollected,
        evaluated_at="2026-08-21T12:04:01Z",
    )

    with pytest.raises(ValueError, match="exact predecessor decision"):
        evaluate_health_observation(
            policy=policy,
            prior_state=_next_state(replay_decision),
            predecessor_decision=first,
            observation=_second_observation(),
            evaluated_at="2026-08-21T12:05:00Z",
        )


def test_gap_and_out_of_order_windows_cannot_build_a_healthy_streak() -> None:
    policy = _policy()
    first = evaluate_health_observation(
        policy=policy,
        prior_state=_initial_state(),
        observation=_observation(),
        evaluated_at="2026-08-21T12:04:00Z",
    )
    gap = evaluate_health_observation(
        policy=policy,
        prior_state=_next_state(first),
        predecessor_decision=first,
        observation=_window_observation(3),
        evaluated_at="2026-08-21T12:06:00Z",
    )
    out_of_order = evaluate_health_observation(
        policy=policy,
        prior_state=_next_state(gap),
        predecessor_decision=gap,
        observation=_window_observation(2),
        evaluated_at="2026-08-21T12:06:00Z",
    )

    assert gap.status is HealthDecisionStatus.INSUFFICIENT_EVIDENCE
    assert gap.reason_codes == (HealthReasonCode.WINDOW_GAP,)
    assert gap.next_state.consecutive_healthy_windows == 0
    assert out_of_order.status is HealthDecisionStatus.INSUFFICIENT_EVIDENCE
    assert out_of_order.reason_codes == (HealthReasonCode.WINDOW_OUT_OF_ORDER,)
    assert out_of_order.next_state.consecutive_healthy_windows == 0
