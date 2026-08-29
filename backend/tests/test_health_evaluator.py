from dataclasses import FrozenInstanceError, replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from controlgraph_canary.authority import (
    HealthDecisionKind,
    HealthEvaluationState,
    HealthPolicy,
    HealthReason,
    HealthWindowSample,
    evaluate_health,
)

PROPERTY_SETTINGS = settings(
    max_examples=100,
    derandomize=True,
    deadline=None,
    database=None,
    print_blob=True,
)

ROOT_DIGEST = "0" * 64
POLICY_DIGEST = "1" * 64


def _policy(**changes: object) -> HealthPolicy:
    values: dict[str, object] = {
        "policy_version": "controlgraph.rollout-health-policy/v2",
        "policy_sha256": POLICY_DIGEST,
        "project_id": "controlgraph-project",
        "region": "us-central1",
        "environment": "acceptance",
        "service_name": "canary-target",
        "root_id": f"cgroot:{ROOT_DIGEST}",
        "root_sha256": ROOT_DIGEST,
        "epoch": 7,
        "candidate_revision": "canary-target-candidate-00002",
        "observation_started_at": 0,
        "window_seconds": 60,
        "observation_delay_seconds": 180,
        "maximum_observation_delay_seconds": 360,
        "minimum_request_count": 100,
        "healthy_maximum_error_rate_basis_points": 100,
        "unhealthy_minimum_error_rate_basis_points": 500,
        "healthy_maximum_p95_latency_ms": 500,
        "unhealthy_minimum_p95_latency_ms": 1_000,
        "healthy_minimum_availability_basis_points": 9_900,
        "unhealthy_maximum_availability_basis_points": 9_500,
        "healthy_consecutive_windows": 2,
        "unhealthy_consecutive_windows": 2,
        "maximum_windows": 10,
    }
    values.update(changes)
    return HealthPolicy(**values)  # type: ignore[arg-type]


def _state(policy: HealthPolicy | None = None, **changes: object) -> HealthEvaluationState:
    bound_policy = policy or _policy()
    values: dict[str, object] = {
        "policy_version": bound_policy.policy_version,
        "policy_sha256": bound_policy.policy_sha256,
        "project_id": bound_policy.project_id,
        "region": bound_policy.region,
        "environment": bound_policy.environment,
        "service_name": bound_policy.service_name,
        "root_id": bound_policy.root_id,
        "root_sha256": bound_policy.root_sha256,
        "epoch": bound_policy.epoch,
        "candidate_revision": bound_policy.candidate_revision,
        "observation_started_at": bound_policy.observation_started_at,
        "last_window_ended_at": None,
        "consecutive_healthy_windows": 0,
        "consecutive_unhealthy_windows": 0,
        "evaluated_windows": 0,
        "last_observation_sha256": None,
        "consumed_sample_set_sha256s": (),
        "prior_decision_sha256": None,
    }
    values.update(changes)
    if values["evaluated_windows"] and "last_observation_sha256" not in changes:
        values["last_observation_sha256"] = "f" * 64
    return HealthEvaluationState(**values)  # type: ignore[arg-type]


def _sample(
    window: int,
    policy: HealthPolicy | None = None,
    **changes: object,
) -> HealthWindowSample:
    bound_policy = policy or _policy()
    window_started_at = (
        bound_policy.observation_started_at + (window - 1) * bound_policy.window_seconds
    )
    window_ended_at = window_started_at + bound_policy.window_seconds
    values: dict[str, object] = {
        "observation_sha256": f"{window:064x}",
        "query_sha256s": (f"{100 + window:064x}", f"{110 + window:064x}"),
        "sample_sha256s": (
            f"{200 + window:064x}",
            f"{300 + window:064x}",
        ),
        "policy_sha256": bound_policy.policy_sha256,
        "project_id": bound_policy.project_id,
        "region": bound_policy.region,
        "environment": bound_policy.environment,
        "service_name": bound_policy.service_name,
        "root_id": bound_policy.root_id,
        "root_sha256": bound_policy.root_sha256,
        "epoch": bound_policy.epoch,
        "candidate_revision": bound_policy.candidate_revision,
        "observation_started_at": bound_policy.observation_started_at,
        "window_index": window,
        "window_started_at": window_started_at,
        "window_ended_at": window_ended_at,
        "observed_at": window_ended_at + bound_policy.observation_delay_seconds,
        "request_count": 100,
        "response_1xx_count": 0,
        "successful_request_count": 99,
        "response_3xx_count": 0,
        "response_4xx_count": 0,
        "server_error_count": 1,
        "p95_latency_ms": 500,
        "complete": True,
        "missing": False,
        "duplicate_count": 0,
        "conflicting_duplicate": False,
    }
    values.update(changes)
    if "response_4xx_count" not in changes:
        values["response_4xx_count"] = (
            int(values["request_count"])
            - int(values["response_1xx_count"])
            - int(values["successful_request_count"])
            - int(values["response_3xx_count"])
            - int(values["server_error_count"])
        )
    return HealthWindowSample(**values)  # type: ignore[arg-type]


def test_closed_decisions_and_frozen_inputs() -> None:
    policy = _policy()

    assert {decision.value for decision in HealthDecisionKind} == {
        "healthy",
        "unhealthy",
        "wait",
        "insufficient-evidence",
    }
    with pytest.raises(FrozenInstanceError):
        policy.window_seconds = 30  # type: ignore[misc]
    with pytest.raises(ValueError, match="bind root_sha256"):
        _policy(root_id=f"cgroot:{'2' * 64}")
    with pytest.raises(ValueError, match="request and latency sample digests"):
        _sample(1, policy, sample_sha256s=("a" * 64,))


def test_exact_healthy_boundaries_wait_for_required_streak() -> None:
    policy = _policy()
    prior_state = _state(policy)
    sample = _sample(1, policy)

    result = evaluate_health(policy, (sample,), prior_state, evaluated_at=240)

    assert result.decision is HealthDecisionKind.WAIT
    assert result.reasons == (
        HealthReason.HEALTHY_THRESHOLDS_MET,
        HealthReason.HEALTHY_STREAK_PENDING,
    )
    assert result.prior_state is prior_state
    assert replace(result.state, consumed_sample_set_sha256s=()) == replace(
        prior_state,
        last_window_ended_at=60,
        consecutive_healthy_windows=1,
        evaluated_windows=1,
        last_observation_sha256=sample.observation_sha256,
    )
    assert len(result.state.consumed_sample_set_sha256s) == 1
    assert result.window_started_at == 0
    assert result.window_ended_at == 60
    assert result.request_count == 100
    assert result.successful_request_count == 99
    assert result.server_error_count == 1
    assert result.error_rate_basis_points == 100
    assert result.availability_basis_points == 9_900
    assert result.p95_latency_ms == 500
    assert result.observation_digests == (sample.observation_sha256,)
    assert result.observation_sha256 == sample.observation_sha256
    assert result.query_sha256s == sample.query_sha256s
    assert result.sample_sha256s == sample.sample_sha256s
    assert result.duplicate_count == 0
    assert result.policy_version == policy.policy_version
    assert result.policy_sha256 == policy.policy_sha256
    assert result.next_evaluation_at == 300


def test_two_ordered_healthy_windows_emit_healthy_with_complete_citations() -> None:
    policy = _policy()
    samples = (_sample(1, policy), _sample(2, policy))

    result = evaluate_health(policy, samples, _state(policy), evaluated_at=300)

    assert result.decision is HealthDecisionKind.HEALTHY
    assert result.reasons == (
        HealthReason.HEALTHY_THRESHOLDS_MET,
        HealthReason.HEALTHY_STREAK_MET,
    )
    assert result.state.last_window_ended_at == 120
    assert result.state.consecutive_healthy_windows == 2
    assert result.state.consecutive_unhealthy_windows == 0
    assert result.state.evaluated_windows == 2
    assert result.observation_digests == tuple(
        sample.observation_sha256 for sample in samples
    )
    assert result.next_evaluation_at is None


@pytest.mark.parametrize(
    ("changes", "expected_reason"),
    [
        (
            {"successful_request_count": 95, "server_error_count": 5},
            HealthReason.UNHEALTHY_ERROR_RATE,
        ),
        ({"p95_latency_ms": 1_000}, HealthReason.UNHEALTHY_LATENCY),
        (
            {"successful_request_count": 95, "server_error_count": 1},
            HealthReason.UNHEALTHY_AVAILABILITY,
        ),
    ],
)
def test_exact_unhealthy_boundaries_require_two_windows(
    changes: dict[str, object],
    expected_reason: HealthReason,
) -> None:
    policy = _policy()
    samples = (_sample(1, policy, **changes), _sample(2, policy, **changes))

    first = evaluate_health(policy, samples[:1], _state(policy), evaluated_at=240)
    result = evaluate_health(policy, samples, _state(policy), evaluated_at=300)

    assert first.decision is HealthDecisionKind.WAIT
    assert first.reasons[-1] is HealthReason.UNHEALTHY_STREAK_PENDING
    assert result.decision is HealthDecisionKind.UNHEALTHY
    assert expected_reason in result.reasons
    assert result.reasons[-1] is HealthReason.UNHEALTHY_STREAK_MET
    assert result.state.consecutive_unhealthy_windows == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"successful_request_count": 98, "server_error_count": 2},
        {"p95_latency_ms": 501},
        {"successful_request_count": 98, "server_error_count": 1},
    ],
)
def test_values_between_healthy_and_unhealthy_thresholds_wait(
    changes: dict[str, object],
) -> None:
    policy = _policy()
    prior_state = _state(
        policy,
        last_window_ended_at=60,
        consecutive_healthy_windows=1,
        evaluated_windows=1,
    )

    result = evaluate_health(
        policy,
        (_sample(2, policy, **changes),),
        prior_state,
        evaluated_at=300,
    )

    assert result.decision is HealthDecisionKind.WAIT
    assert result.reasons == (HealthReason.THRESHOLD_INCONCLUSIVE,)
    assert result.state.last_window_ended_at == 120
    assert result.state.consecutive_healthy_windows == 0
    assert result.state.consecutive_unhealthy_windows == 0


@pytest.mark.parametrize(
    ("sample_changes", "reason"),
    [
        ({"complete": False}, HealthReason.SAMPLE_PARTIAL),
        (
            {"duplicate_count": 1, "conflicting_duplicate": True},
            HealthReason.SAMPLE_CONFLICTING_DUPLICATE,
        ),
        (
            {
                "request_count": 99,
                "successful_request_count": 98,
                "server_error_count": 1,
            },
            HealthReason.MINIMUM_REQUESTS_NOT_MET,
        ),
        ({"observed_at": 481}, HealthReason.SAMPLE_LATE),
        ({"service_name": "different-service"}, HealthReason.SAMPLE_SCOPE_MISMATCH),
    ],
)
def test_partial_duplicate_late_small_and_out_of_scope_samples_fail_safe(
    sample_changes: dict[str, object],
    reason: HealthReason,
) -> None:
    policy = _policy()
    prior_state = _state(
        policy,
        last_window_ended_at=60,
        consecutive_healthy_windows=1,
        evaluated_windows=1,
    )
    sample = _sample(2, policy, **sample_changes)

    result = evaluate_health(policy, (sample,), prior_state, evaluated_at=481)

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (reason,)
    assert result.state.consecutive_healthy_windows == 0
    assert result.state.consecutive_unhealthy_windows == 0
    assert result.observation_digests == (sample.observation_sha256,)


def test_early_observation_waits_without_changing_state() -> None:
    policy = _policy()
    prior_state = _state(
        policy,
        last_window_ended_at=60,
        consecutive_healthy_windows=1,
        evaluated_windows=1,
    )
    sample = _sample(2, policy, observed_at=299)

    result = evaluate_health(policy, (sample,), prior_state, evaluated_at=300)

    assert result.decision is HealthDecisionKind.WAIT
    assert result.reasons == (HealthReason.SAMPLE_EARLY,)
    assert result.state == prior_state
    assert result.next_evaluation_at == 300


def test_future_gap_sample_cannot_consume_windows() -> None:
    policy = _policy()
    prior_state = _state(policy)
    future_gap = _sample(2, policy, observed_at=350)

    result = evaluate_health(policy, (future_gap,), prior_state, evaluated_at=300)

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (HealthReason.SAMPLE_LATE,)
    assert result.state == prior_state
    assert result.next_evaluation_at == 350


def test_not_ready_gap_sample_cannot_consume_windows() -> None:
    policy = _policy()
    prior_state = _state(policy)
    future_gap = _sample(2, policy)

    result = evaluate_health(policy, (future_gap,), prior_state, evaluated_at=299)

    assert result.decision is HealthDecisionKind.WAIT
    assert result.reasons == (HealthReason.WINDOW_NOT_READY,)
    assert result.state == prior_state
    assert result.next_evaluation_at == 300


def test_identical_collector_duplicates_are_deduplicated() -> None:
    policy = _policy()
    sample = _sample(1, policy, duplicate_count=3)

    once = evaluate_health(policy, (sample,), _state(policy), evaluated_at=240)
    repeated = evaluate_health(policy, (sample,) * 11, _state(policy), evaluated_at=240)

    assert repeated == once
    assert repeated.observation_digests == (sample.observation_sha256,)
    assert repeated.duplicate_count == 3


def test_identical_cross_call_replay_preserves_the_active_streak() -> None:
    policy = _policy()
    sample = _sample(1, policy)
    first = evaluate_health(policy, (sample,), _state(policy), evaluated_at=240)

    replayed = evaluate_health(policy, (sample,), first.state, evaluated_at=241)

    assert replayed.decision is HealthDecisionKind.WAIT
    assert replayed.reasons == (HealthReason.WINDOW_DUPLICATE,)
    assert replayed.state == first.state
    assert replayed.observation_sha256 == sample.observation_sha256
    assert replayed.next_evaluation_at == 300


def test_recollected_sample_set_preserves_the_active_streak() -> None:
    policy = _policy()
    sample = _sample(1, policy)
    first = evaluate_health(policy, (sample,), _state(policy), evaluated_at=240)
    recollected = _sample(
        1,
        policy,
        observation_sha256="b" * 64,
        observed_at=241,
    )

    replayed = evaluate_health(policy, (recollected,), first.state, evaluated_at=241)

    assert replayed.decision is HealthDecisionKind.WAIT
    assert replayed.reasons == (HealthReason.WINDOW_DUPLICATE,)
    assert replayed.state == first.state


def test_conflicting_cross_call_replay_resets_the_active_streak() -> None:
    policy = _policy()
    sample = _sample(1, policy)
    first = evaluate_health(policy, (sample,), _state(policy), evaluated_at=240)
    conflict = _sample(
        1,
        policy,
        observation_sha256="a" * 64,
        sample_sha256s=("b" * 64, "c" * 64),
        p95_latency_ms=499,
    )

    replayed = evaluate_health(policy, (conflict,), first.state, evaluated_at=241)

    assert replayed.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert replayed.reasons == (HealthReason.SAMPLE_CONFLICTING_DUPLICATE,)
    assert replayed.state.consecutive_healthy_windows == 0
    assert replayed.next_evaluation_at == 300


def test_conflict_metadata_takes_precedence_over_cross_call_deduplication() -> None:
    policy = _policy()
    sample = _sample(1, policy)
    first = evaluate_health(policy, (sample,), _state(policy), evaluated_at=240)
    conflict = _sample(
        1,
        policy,
        observation_sha256="a" * 64,
        observed_at=241,
        duplicate_count=1,
        conflicting_duplicate=True,
    )

    replayed = evaluate_health(policy, (conflict,), first.state, evaluated_at=241)

    assert replayed.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert replayed.reasons == (HealthReason.SAMPLE_CONFLICTING_DUPLICATE,)
    assert replayed.state.consecutive_healthy_windows == 0


def test_missing_observation_is_retryable_then_consumes_at_deadline() -> None:
    policy = _policy()
    missing = _sample(
        1,
        policy,
        sample_sha256s=(),
        request_count=0,
        successful_request_count=0,
        server_error_count=0,
        p95_latency_ms=0,
        complete=False,
        missing=True,
    )

    retryable = evaluate_health(policy, (missing,), _state(policy), evaluated_at=240)
    expired = evaluate_health(policy, (missing,), _state(policy), evaluated_at=420)

    assert retryable.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert retryable.reasons == (HealthReason.SAMPLE_MISSING,)
    assert retryable.state == _state(policy)
    assert retryable.next_evaluation_at == 420
    assert expired.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert expired.reasons == (HealthReason.SAMPLE_MISSING,)
    assert expired.state.last_window_ended_at == 60
    assert expired.state.evaluated_windows == 1
    assert expired.state.last_observation_sha256 == missing.observation_sha256
    assert expired.next_evaluation_at == 420


def test_error_rate_uses_ceiling_and_availability_uses_floor_basis_points() -> None:
    policy = _policy()
    sample = _sample(
        1,
        policy,
        request_count=199,
        successful_request_count=197,
        server_error_count=2,
    )

    result = evaluate_health(policy, (sample,), _state(policy), evaluated_at=240)

    assert result.error_rate_basis_points == 101
    assert result.availability_basis_points == 9_899


@pytest.mark.parametrize(
    ("evaluated_at", "consumed", "next_evaluation_at"),
    [(240, False, 420), (420, True, 420), (460, True, 460)],
)
def test_complete_zero_request_window_suppresses_the_entire_aggregate_tuple(
    evaluated_at: int,
    consumed: bool,
    next_evaluation_at: int,
) -> None:
    policy = _policy()
    sample = _sample(
        1,
        policy,
        request_count=0,
        successful_request_count=0,
        server_error_count=0,
        p95_latency_ms=0,
    )
    prior_state = _state(policy)

    result = evaluate_health(policy, (sample,), prior_state, evaluated_at=evaluated_at)

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (HealthReason.MINIMUM_REQUESTS_NOT_MET,)
    assert (
        result.request_count,
        result.successful_request_count,
        result.server_error_count,
        result.error_rate_basis_points,
        result.availability_basis_points,
        result.p95_latency_ms,
    ) == (None, None, None, None, None, None)
    assert result.next_evaluation_at == next_evaluation_at
    if consumed:
        assert result.state.last_window_ended_at == sample.window_ended_at
        assert result.state.last_observation_sha256 == sample.observation_sha256
    else:
        assert result.state is prior_state


def test_no_samples_and_mismatched_prior_state_are_insufficient() -> None:
    policy = _policy()
    state = _state(
        policy,
        last_window_ended_at=60,
        consecutive_unhealthy_windows=1,
        evaluated_windows=1,
    )

    missing = evaluate_health(policy, (), state, evaluated_at=480)
    mismatched = evaluate_health(
        policy,
        (_sample(2, policy),),
        replace(state, environment="different-environment"),
        evaluated_at=300,
    )

    assert missing.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert missing.reasons == (HealthReason.NO_SAMPLES,)
    assert missing.state.consecutive_unhealthy_windows == 0
    assert mismatched.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert mismatched.reasons == (HealthReason.STATE_SCOPE_MISMATCH,)


def test_inconsistent_prior_state_window_is_insufficient() -> None:
    policy = _policy()
    state = _state(
        policy,
        last_window_ended_at=120,
        evaluated_windows=1,
    )

    result = evaluate_health(policy, (), state, evaluated_at=360)

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (HealthReason.STATE_SCOPE_MISMATCH,)
    assert result.next_evaluation_at is None


def test_missing_or_partial_data_is_retryable_until_the_collection_deadline() -> None:
    policy = _policy()
    state = _state(
        policy,
        last_window_ended_at=60,
        consecutive_healthy_windows=1,
        evaluated_windows=1,
    )

    missing = evaluate_health(policy, (), state, evaluated_at=300)
    partial = evaluate_health(
        policy,
        (_sample(2, policy, complete=False),),
        state,
        evaluated_at=300,
    )

    assert missing.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert missing.reasons == (HealthReason.NO_SAMPLES,)
    assert missing.next_evaluation_at == 480
    assert missing.state == state
    assert partial.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert partial.reasons == (HealthReason.SAMPLE_PARTIAL,)
    assert partial.next_evaluation_at == 480
    assert partial.state == state


def test_window_not_ready_waits_without_changing_state() -> None:
    policy = _policy()
    prior_state = _state(
        policy,
        last_window_ended_at=60,
        consecutive_healthy_windows=1,
        evaluated_windows=1,
    )
    sample = _sample(2, policy, observed_at=120)

    result = evaluate_health(policy, (sample,), prior_state, evaluated_at=299)

    assert result.decision is HealthDecisionKind.WAIT
    assert result.reasons == (HealthReason.WINDOW_NOT_READY,)
    assert result.state.last_window_ended_at == 60
    assert result.state == prior_state
    assert result.next_evaluation_at == 300


@pytest.mark.parametrize(
    ("samples", "state", "reason"),
    [
        (
            (_sample(1, window_ended_at=59, observed_at=239),),
            _state(),
            HealthReason.WINDOW_BOUNDARY_INVALID,
        ),
        ((_sample(2),), _state(), HealthReason.WINDOW_GAP),
        (
            (_sample(1),),
            _state(last_window_ended_at=120, evaluated_windows=2),
            HealthReason.WINDOW_OUT_OF_ORDER,
        ),
        (
            (
                _sample(1),
                _sample(
                    1,
                    observation_sha256="a" * 64,
                    sample_sha256s=("b" * 64, "c" * 64),
                    p95_latency_ms=499,
                ),
            ),
            _state(),
            HealthReason.SAMPLE_CONFLICTING_DUPLICATE,
        ),
    ],
)
def test_boundary_gap_order_and_duplicate_windows_fail_safe(
    samples: tuple[HealthWindowSample, ...],
    state: HealthEvaluationState,
    reason: HealthReason,
) -> None:
    result = evaluate_health(_policy(), samples, state, evaluated_at=300)

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (reason,)
    assert result.state.consecutive_healthy_windows == 0
    assert result.state.consecutive_unhealthy_windows == 0


def test_conflict_metadata_takes_precedence_over_within_call_deduplication() -> None:
    policy = _policy()
    first = _sample(1, policy)
    conflict = _sample(
        1,
        policy,
        observation_sha256="a" * 64,
        duplicate_count=1,
        conflicting_duplicate=True,
    )

    result = evaluate_health(policy, (first, conflict), _state(policy), evaluated_at=240)

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (HealthReason.SAMPLE_CONFLICTING_DUPLICATE,)


def test_more_than_ten_windows_is_insufficient_without_evaluation() -> None:
    policy = _policy()
    samples = tuple(_sample(index, policy) for index in range(1, 12))

    result = evaluate_health(policy, samples, _state(policy), evaluated_at=840)

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (HealthReason.TOO_MANY_WINDOWS,)
    assert result.observation_digests == tuple(
        sample.observation_sha256 for sample in samples
    )


def test_tenth_nonterminal_window_exhausts_the_cumulative_budget() -> None:
    policy = _policy()
    prior_state = _state(
        policy,
        last_window_ended_at=540,
        evaluated_windows=9,
    )

    result = evaluate_health(
        policy,
        (_sample(10, policy),),
        prior_state,
        evaluated_at=780,
    )

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (
        HealthReason.HEALTHY_THRESHOLDS_MET,
        HealthReason.MAXIMUM_WINDOWS_EXHAUSTED,
    )
    assert result.state.last_window_ended_at == 600
    assert result.state.evaluated_windows == 10
    assert result.state.consecutive_healthy_windows == 0


def test_tenth_window_can_emit_a_terminal_health_decision() -> None:
    policy = _policy()
    prior_state = _state(
        policy,
        last_window_ended_at=540,
        consecutive_healthy_windows=1,
        evaluated_windows=9,
    )

    result = evaluate_health(
        policy,
        (_sample(10, policy),),
        prior_state,
        evaluated_at=780,
    )

    assert result.decision is HealthDecisionKind.HEALTHY
    assert result.reasons[-1] is HealthReason.HEALTHY_STREAK_MET
    assert result.state.evaluated_windows == 10


def test_opposite_classification_breaks_an_active_streak() -> None:
    policy = _policy()
    prior_state = _state(
        policy,
        last_window_ended_at=60,
        consecutive_healthy_windows=1,
        evaluated_windows=1,
    )
    unhealthy = _sample(2, policy, p95_latency_ms=1_000)

    result = evaluate_health(policy, (unhealthy,), prior_state, evaluated_at=300)

    assert result.decision is HealthDecisionKind.WAIT
    assert result.reasons[-1] is HealthReason.UNHEALTHY_STREAK_PENDING
    assert result.state.consecutive_healthy_windows == 0
    assert result.state.consecutive_unhealthy_windows == 1


def test_healthy_classification_breaks_an_active_unhealthy_streak() -> None:
    policy = _policy()
    prior_state = _state(
        policy,
        last_window_ended_at=60,
        consecutive_unhealthy_windows=1,
        evaluated_windows=1,
    )

    result = evaluate_health(
        policy,
        (_sample(2, policy),),
        prior_state,
        evaluated_at=300,
    )

    assert result.decision is HealthDecisionKind.WAIT
    assert result.reasons[-1] is HealthReason.HEALTHY_STREAK_PENDING
    assert result.state.consecutive_healthy_windows == 1
    assert result.state.consecutive_unhealthy_windows == 0


def test_terminal_decision_ignores_later_batch_windows() -> None:
    policy = _policy()
    samples = (
        _sample(1, policy),
        _sample(2, policy),
        _sample(3, policy, p95_latency_ms=1_000),
    )

    result = evaluate_health(policy, samples, _state(policy), evaluated_at=360)

    assert result.decision is HealthDecisionKind.HEALTHY
    assert result.window_ended_at == 120
    assert result.observation_digests == tuple(
        sample.observation_sha256 for sample in samples[:2]
    )
    assert result.next_evaluation_at is None


@pytest.mark.parametrize(
    ("healthy_streak", "unhealthy_streak", "evaluated_windows"),
    [(2, 0, 2), (0, 2, 2), (3, 0, 3), (2, 0, 10)],
)
def test_terminal_state_cannot_be_reused_for_another_evaluation(
    healthy_streak: int,
    unhealthy_streak: int,
    evaluated_windows: int,
) -> None:
    policy = _policy()
    terminal_state = _state(
        policy,
        last_window_ended_at=evaluated_windows * policy.window_seconds,
        consecutive_healthy_windows=healthy_streak,
        consecutive_unhealthy_windows=unhealthy_streak,
        evaluated_windows=evaluated_windows,
    )
    next_window = evaluated_windows + 1

    result = evaluate_health(
        policy,
        (_sample(next_window, policy),),
        terminal_state,
        evaluated_at=(next_window * policy.window_seconds) + policy.observation_delay_seconds,
    )

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (HealthReason.STATE_TERMINAL,)
    assert result.state is terminal_state
    assert result.observation_sha256 is None
    assert result.query_sha256s == ()
    assert result.sample_sha256s == ()
    assert result.next_evaluation_at is None


def test_nonterminal_next_evaluation_never_precedes_evaluation_time() -> None:
    policy = _policy()
    sample = _sample(1, policy)

    result = evaluate_health(policy, (sample,), _state(policy), evaluated_at=400)

    assert result.decision is HealthDecisionKind.WAIT
    assert result.next_evaluation_at == 400


@pytest.mark.parametrize(
    ("evaluated_at", "expected_next_evaluation_at"),
    [(420, 420), (460, 460)],
)
def test_future_observation_never_schedules_in_the_past(
    evaluated_at: int,
    expected_next_evaluation_at: int,
) -> None:
    policy = _policy()
    sample = _sample(1, policy, observed_at=500)

    result = evaluate_health(policy, (sample,), _state(policy), evaluated_at=evaluated_at)

    assert result.decision is HealthDecisionKind.INSUFFICIENT_EVIDENCE
    assert result.reasons == (HealthReason.SAMPLE_LATE,)
    assert result.state == _state(policy)
    assert result.next_evaluation_at == expected_next_evaluation_at


@PROPERTY_SETTINGS
@given(
    request_count=st.integers(min_value=100, max_value=10_000),
    successful_request_count=st.integers(min_value=0, max_value=10_000),
    server_error_count=st.integers(min_value=0, max_value=10_000),
    p95_latency_ms=st.integers(min_value=0, max_value=2_000),
)
def test_identical_inputs_produce_identical_results(
    request_count: int,
    successful_request_count: int,
    server_error_count: int,
    p95_latency_ms: int,
) -> None:
    successful_request_count %= request_count + 1
    server_error_count %= request_count - successful_request_count + 1
    policy = _policy()
    sample = _sample(
        1,
        policy,
        request_count=request_count,
        successful_request_count=successful_request_count,
        server_error_count=server_error_count,
        p95_latency_ms=p95_latency_ms,
    )
    state = _state(policy)

    first = evaluate_health(policy, (sample,), state, evaluated_at=240)
    second = evaluate_health(policy, (sample,), state, evaluated_at=240)

    assert first == second


@PROPERTY_SETTINGS
@given(
    request_count=st.integers(min_value=100, max_value=10_000),
    p95_latency_ms=st.integers(min_value=1_000, max_value=100_000),
)
def test_two_high_latency_windows_are_always_unhealthy(
    request_count: int,
    p95_latency_ms: int,
) -> None:
    policy = _policy()
    successful_request_count = request_count * 99 // 100
    server_error_count = request_count - successful_request_count
    samples = tuple(
        _sample(
            index,
            policy,
            request_count=request_count,
            successful_request_count=successful_request_count,
            server_error_count=server_error_count,
            p95_latency_ms=p95_latency_ms,
        )
        for index in (1, 2)
    )

    result = evaluate_health(policy, samples, _state(policy), evaluated_at=300)

    assert result.decision is HealthDecisionKind.UNHEALTHY
    assert HealthReason.UNHEALTHY_LATENCY in result.reasons
