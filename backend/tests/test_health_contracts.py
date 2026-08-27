from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from controlgraph_canary.contracts import (
    ContractError,
    HealthDecisionStatus,
    HealthDecisionV1,
    HealthEvaluationStateV1,
    HealthReasonCode,
    HealthSignal,
    MonitoringDistributionV1,
    MonitoringMetricQueryV1,
    MonitoringObservationCompleteness,
    MonitoringObservationTiming,
    MonitoringQueryKind,
    MonitoringSampleV1,
    MonitoringWindowObservationV1,
    RolloutHealthPolicyV1,
    RolloutHealthPolicyV2,
    StrictContractModel,
    TargetBinding,
    binary64_milliseconds_to_microseconds,
    canonical_json_bytes,
    canonical_sha256,
    create_rollout_health_policy_v2,
    decode_contract,
    monitoring_query_id,
    monitoring_sample_set_sha256,
)

PROJECT = "controlgraph-canary-a1b2c3"
SERVICE = "controlgraph-reference-target"
CANDIDATE = f"{SERVICE}-candidate-v11"
ROOT_ID = "cgroot:" + "1" * 64
ROOT_SHA256 = "1" * 64


def _target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT,
        region="us-central1",
        environment="nonprod",
        service_name=SERVICE,
    )


def _policy(**changes: object) -> RolloutHealthPolicyV2:
    values: dict[str, object] = {
        "schema_version": "controlgraph.rollout-health-policy/v2",
        "observation_schema_version": "controlgraph.monitoring-window-observation/v1",
        "decision_schema_version": "controlgraph.health-decision/v1",
        "monitored_resource_type": "cloud_run_revision",
        "request_count_metric_type": "run.googleapis.com/request_count",
        "successful_response_code_class": "2xx",
        "server_error_response_code_class": "5xx",
        "latency_metric_type": "run.googleapis.com/request_latencies",
        "request_unit": "1",
        "latency_unit": "ms",
        "latency_source_conversion": (
            "IEEE_754_BINARY64_MILLISECONDS_TO_INTEGER_MICROSECONDS_TIES_TO_EVEN"
        ),
        "alignment_period_seconds": 60,
        "request_per_series_aligner": "ALIGN_SUM",
        "request_cross_series_reducer": "REDUCE_SUM",
        "request_group_by_field": "metric.labels.response_code_class",
        "total_request_definition": "SUM_1XX_2XX_3XX_4XX_5XX",
        "availability_definition": "SUCCESSFUL_2XX_OVER_TOTAL_REQUESTS",
        "server_error_rate_definition": "SERVER_ERROR_5XX_OVER_TOTAL_REQUESTS",
        "latency_definition": "MERGED_DISTRIBUTION_PERCENTILE_95",
        "latency_primary_per_series_aligner": "ALIGN_SUM",
        "latency_primary_cross_series_reducer": "REDUCE_SUM",
        "latency_secondary_per_series_aligner": "ALIGN_PERCENTILE_95",
        "latency_secondary_cross_series_reducer": "REDUCE_NONE",
        "latency_secondary_output_metric_kind": "GAUGE",
        "latency_secondary_output_value_type": "DOUBLE",
        "latency_rounding": "CEILING_TO_INTEGER_MILLISECOND",
        "configuration_name_source": "TARGET_SERVICE_NAME",
        "route_filter": "",
        "provider_interval_semantics": "START_EXCLUSIVE_END_INCLUSIVE",
        "page_size": 1_000,
        "view": "FULL",
        "order_by": None,
        "window_seconds": 60,
        "window_semantics": "HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE",
        "observation_delay_seconds": 180,
        "maximum_observation_delay_seconds": 300,
        "minimum_request_count": 100,
        "healthy_maximum_error_rate_basis_points": 100,
        "unhealthy_minimum_error_rate_basis_points": 500,
        "healthy_maximum_p95_latency_ms": 500,
        "unhealthy_minimum_p95_latency_ms": 1_000,
        "healthy_minimum_availability_basis_points": 9_900,
        "unhealthy_maximum_availability_basis_points": 9_500,
        "error_rate_rounding": "CEILING_BASIS_POINTS",
        "availability_rate_rounding": "FLOOR_BASIS_POINTS",
        "healthy_consecutive_windows": 2,
        "unhealthy_consecutive_windows": 2,
        "maximum_windows": 10,
        "early_observation_action": "WAIT",
        "missing_observation_action": "INSUFFICIENT_EVIDENCE",
        "partial_observation_action": "INSUFFICIENT_EVIDENCE",
        "late_observation_action": "INSUFFICIENT_EVIDENCE",
        "malformed_observation_action": "INSUFFICIENT_EVIDENCE",
        "unknown_response_code_class_action": "INSUFFICIENT_EVIDENCE",
        "identical_duplicate_action": "DEDUPLICATE_BY_SAMPLE_SHA256",
        "conflicting_duplicate_action": "INSUFFICIENT_EVIDENCE",
        "sample_set_digest_domain": "controlgraph.monitoring-sample-set/v1",
        "sample_set_digest_algorithm": ("SHA256_DOMAIN_NUL_UINT16_COUNT_ORDERED_32_BYTE_DIGESTS"),
        "out_of_order_action": "INSUFFICIENT_EVIDENCE",
        "boundary_sample_action": "INCLUDE_START_EXCLUDE_END",
    }
    values.update(changes)
    return RolloutHealthPolicyV2.model_validate(values)


def _policy_sha256() -> str:
    return canonical_sha256(_policy())


def _filter(
    metric_type: str,
) -> str:
    clauses = [
        f'metric.type="{metric_type}"',
        'resource.type="cloud_run_revision"',
        f'resource.labels.project_id="{PROJECT}"',
        'resource.labels.location="us-central1"',
        f'resource.labels.service_name="{SERVICE}"',
        f'resource.labels.configuration_name="{SERVICE}"',
        f'resource.labels.revision_name="{CANDIDATE}"',
        'metric.labels.route=""',
    ]
    return " AND ".join(clauses)


def _query(query_kind: MonitoringQueryKind, **changes: object) -> MonitoringMetricQueryV1:
    is_latency = query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
    metric_type = (
        "run.googleapis.com/request_latencies" if is_latency else "run.googleapis.com/request_count"
    )
    values: dict[str, object] = {
        "schema_version": "controlgraph.monitoring-metric-query/v1",
        "query_id": "pending",
        "query_kind": query_kind,
        "policy_sha256": _policy_sha256(),
        "target": _target(),
        "root_id": ROOT_ID,
        "root_sha256": ROOT_SHA256,
        "epoch": 1,
        "candidate_revision": CANDIDATE,
        "configuration_name": SERVICE,
        "window_started_at": "2026-08-21T12:00:00Z",
        "window_ended_at": "2026-08-21T12:01:00Z",
        "window_semantics": "HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE",
        "provider_interval_semantics": "START_EXCLUSIVE_END_INCLUSIVE",
        "metric_type": metric_type,
        "monitored_resource_type": "cloud_run_revision",
        "unit": "ms" if is_latency else "1",
        "metric_kind": "DELTA",
        "value_type": "DISTRIBUTION" if is_latency else "INT64",
        "alignment_period_seconds": 60,
        "primary_per_series_aligner": "ALIGN_SUM",
        "primary_cross_series_reducer": "REDUCE_SUM",
        "secondary_per_series_aligner": "ALIGN_PERCENTILE_95" if is_latency else None,
        "secondary_cross_series_reducer": "REDUCE_NONE" if is_latency else None,
        "secondary_output_metric_kind": "GAUGE" if is_latency else None,
        "secondary_output_value_type": "DOUBLE" if is_latency else None,
        "group_by_fields": () if is_latency else ("metric.labels.response_code_class",),
        "page_size": 1_000,
        "view": "FULL",
        "order_by": None,
        "metric_filter": _filter(metric_type),
    }
    values.update(changes)
    if "query_id" not in changes:
        values["query_id"] = monitoring_query_id(
            policy_sha256=cast(str, values["policy_sha256"]),
            target=cast(TargetBinding, values["target"]),
            root_sha256=cast(str, values["root_sha256"]),
            epoch=cast(int, values["epoch"]),
            candidate_revision=cast(str, values["candidate_revision"]),
            window_started_at=cast(str, values["window_started_at"]),
            window_ended_at=cast(str, values["window_ended_at"]),
            query_kind=cast(MonitoringQueryKind, values["query_kind"]),
        )
    return MonitoringMetricQueryV1.model_validate(values)


def _queries() -> tuple[MonitoringMetricQueryV1, ...]:
    return tuple(_query(query_kind) for query_kind in MonitoringQueryKind)


def _sample(
    query: MonitoringMetricQueryV1,
    *,
    response_code_class: str | None = None,
    int64_value: int | None = None,
    latency_microseconds: int | None = None,
    **changes: object,
) -> MonitoringSampleV1:
    is_latency = query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
    values: dict[str, object] = {
        "schema_version": "controlgraph.monitoring-sample/v1",
        "query_sha256": canonical_sha256(query),
        "query_kind": query.query_kind,
        "window_started_at": query.window_started_at,
        "window_ended_at": query.window_ended_at,
        "response_code_class": None if is_latency else response_code_class,
        "provider_value_type": "DOUBLE" if is_latency else "INT64",
        "provider_double_bits": (
            struct.pack(">d", (latency_microseconds or 0) / 1_000).hex() if is_latency else None
        ),
        "unit": "us" if is_latency else "1",
        "int64_value": None if is_latency else int64_value,
        "latency_microseconds": latency_microseconds if is_latency else None,
    }
    values.update(changes)
    return MonitoringSampleV1.model_validate(values)


def _samples(
    queries: tuple[MonitoringMetricQueryV1, ...] | None = None,
) -> tuple[MonitoringSampleV1, ...]:
    request_query, latency_query = queries or _queries()
    return (
        _sample(request_query, response_code_class="2xx", int64_value=995),
        _sample(request_query, response_code_class="3xx", int64_value=2),
        _sample(request_query, response_code_class="4xx", int64_value=2),
        _sample(request_query, response_code_class="5xx", int64_value=1),
        _sample(latency_query, latency_microseconds=400_000),
    )


def _distribution(
    latency_sample: MonitoringSampleV1 | None = None,
    **changes: object,
) -> MonitoringDistributionV1:
    source = latency_sample or _samples()[-1]
    values: dict[str, object] = {
        "schema_version": "controlgraph.monitoring-distribution/v1",
        "sample_count": 1,
        "p95_latency_ms": 400,
        "percentile_basis_points": 9_500,
        "unit": "ms",
        "rounding": "CEILING_TO_INTEGER_MILLISECOND",
        "source_sample_sha256s": (canonical_sha256(source),),
    }
    values.update(changes)
    return MonitoringDistributionV1.model_validate(values)


def _observation(**changes: object) -> MonitoringWindowObservationV1:
    queries = _queries()
    samples = _samples(queries)
    values: dict[str, object] = {
        "schema_version": "controlgraph.monitoring-window-observation/v1",
        "observation_id": "health-window-001",
        "policy_schema_version": "controlgraph.rollout-health-policy/v2",
        "policy_sha256": _policy_sha256(),
        "target": _target(),
        "root_id": ROOT_ID,
        "root_sha256": ROOT_SHA256,
        "epoch": 1,
        "candidate_revision": CANDIDATE,
        "observation_started_at": "2026-08-21T12:00:00Z",
        "window_index": 1,
        "window_started_at": "2026-08-21T12:00:00Z",
        "window_ended_at": "2026-08-21T12:01:00Z",
        "observed_at": "2026-08-21T12:04:00Z",
        "queries": queries,
        "query_sha256s": tuple(canonical_sha256(query) for query in queries),
        "samples": samples,
        "sample_sha256s": tuple(canonical_sha256(sample) for sample in samples),
        "source_sample_sha256s": tuple(sorted(canonical_sha256(sample) for sample in samples)),
        "completeness": MonitoringObservationCompleteness.COMPLETE,
        "timing": MonitoringObservationTiming.READY,
        "missing_signals": (),
        "duplicate_count": 0,
        "conflicting_duplicate": False,
        "request_count": 1_000,
        "response_1xx_count": 0,
        "successful_request_count": 995,
        "response_3xx_count": 2,
        "response_4xx_count": 2,
        "server_error_count": 1,
        "latency_distribution": _distribution(samples[-1]),
    }
    values.update(changes)
    if "samples" in changes and "sample_sha256s" not in changes:
        changed_samples = cast(tuple[MonitoringSampleV1, ...], changes["samples"])
        values["sample_sha256s"] = tuple(canonical_sha256(sample) for sample in changed_samples)
    if "source_sample_sha256s" not in changes and (
        "samples" in changes or "sample_sha256s" in changes
    ):
        values["source_sample_sha256s"] = tuple(
            sorted(cast(tuple[str, ...], values["sample_sha256s"]))
        )
    return MonitoringWindowObservationV1.model_validate(values)


def _window_observation(window_index: int) -> MonitoringWindowObservationV1:
    window_started_at = f"2026-08-21T12:{window_index - 1:02d}:00Z"
    window_ended_at = f"2026-08-21T12:{window_index:02d}:00Z"
    observed_at = f"2026-08-21T12:{window_index + 3:02d}:00Z"
    queries = tuple(
        _query(
            query_kind,
            window_started_at=window_started_at,
            window_ended_at=window_ended_at,
        )
        for query_kind in MonitoringQueryKind
    )
    samples = _samples(queries)
    return _observation(
        observation_id=f"health-window-{window_index:03d}",
        window_index=window_index,
        window_started_at=window_started_at,
        window_ended_at=window_ended_at,
        observed_at=observed_at,
        queries=queries,
        query_sha256s=tuple(canonical_sha256(query) for query in queries),
        samples=samples,
        sample_sha256s=tuple(canonical_sha256(sample) for sample in samples),
        latency_distribution=_distribution(samples[-1]),
    )


def _state(*, evaluated: bool = False, **changes: object) -> HealthEvaluationStateV1:
    values: dict[str, object] = {
        "schema_version": "controlgraph.health-evaluation-state/v1",
        "policy_schema_version": "controlgraph.rollout-health-policy/v2",
        "policy_sha256": _policy_sha256(),
        "target": _target(),
        "root_id": ROOT_ID,
        "root_sha256": ROOT_SHA256,
        "epoch": 1,
        "candidate_revision": CANDIDATE,
        "observation_started_at": "2026-08-21T12:00:00Z",
        "last_window_ended_at": "2026-08-21T12:01:00Z" if evaluated else None,
        "consecutive_healthy_windows": 1 if evaluated else 0,
        "consecutive_unhealthy_windows": 0,
        "evaluated_windows": 1 if evaluated else 0,
        "last_observation_sha256": canonical_sha256(_observation()) if evaluated else None,
        "consumed_sample_set_sha256s": (
            (monitoring_sample_set_sha256(_observation().sample_sha256s),) if evaluated else ()
        ),
        "prior_decision_sha256": None,
    }
    values.update(changes)
    if "evaluated_windows" in changes and "last_window_ended_at" not in changes:
        evaluated_windows = cast(int, changes["evaluated_windows"])
        values["last_window_ended_at"] = (
            f"2026-08-21T12:{evaluated_windows:02d}:00Z" if evaluated_windows else None
        )
        values["last_observation_sha256"] = (
            canonical_sha256(_window_observation(evaluated_windows)) if evaluated_windows else None
        )
        sample_set_sha256 = (
            monitoring_sample_set_sha256(_window_observation(evaluated_windows).sample_sha256s)
            if evaluated_windows
            else None
        )
        values["consumed_sample_set_sha256s"] = (
            (sample_set_sha256,) if sample_set_sha256 is not None else ()
        )
    return HealthEvaluationStateV1.model_validate(values)


def _decision(**changes: object) -> HealthDecisionV1:
    next_state = changes.get("next_state")
    observation = (
        _window_observation(next_state.evaluated_windows)
        if isinstance(next_state, HealthEvaluationStateV1) and next_state.evaluated_windows > 0
        else _observation()
    )
    values: dict[str, object] = {
        "schema_version": "controlgraph.health-decision/v1",
        "decision_id": "health-decision-001",
        "status": HealthDecisionStatus.WAIT,
        "reason_codes": (
            HealthReasonCode.HEALTHY_THRESHOLDS_MET,
            HealthReasonCode.HEALTHY_STREAK_PENDING,
        ),
        "policy_schema_version": "controlgraph.rollout-health-policy/v2",
        "policy_sha256": _policy_sha256(),
        "target": _target(),
        "root_id": ROOT_ID,
        "root_sha256": ROOT_SHA256,
        "epoch": 1,
        "candidate_revision": CANDIDATE,
        "prior_state_sha256": canonical_sha256(_state()),
        "next_state": _state(evaluated=True),
        "observation_sha256": canonical_sha256(observation),
        "query_sha256s": observation.query_sha256s,
        "sample_sha256s": observation.sample_sha256s,
        "window_started_at": observation.window_started_at,
        "window_ended_at": observation.window_ended_at,
        "request_count": 1_000,
        "successful_request_count": 995,
        "server_error_count": 1,
        "error_rate_basis_points": 10,
        "availability_basis_points": 9_950,
        "p95_latency_ms": 400,
        "evaluated_at": "2026-08-21T12:04:00Z",
        "next_evaluation_at": "2026-08-21T12:05:00Z",
    }
    values.update(changes)
    return HealthDecisionV1.model_validate(values)


def test_v2_policy_is_frozen_and_canonical() -> None:
    policy = _policy()
    encoded = canonical_json_bytes(policy)

    assert decode_contract(encoded, RolloutHealthPolicyV2) == policy
    assert canonical_sha256(decode_contract(encoded, RolloutHealthPolicyV2)) == canonical_sha256(
        policy
    )
    assert policy.window_seconds == 60
    assert policy.observation_delay_seconds == 180
    assert policy.maximum_observation_delay_seconds == 300
    assert policy.maximum_windows == 10
    assert policy.latency_source_conversion.endswith("TIES_TO_EVEN")
    assert create_rollout_health_policy_v2() == policy
    assert create_rollout_health_policy_v2() is not create_rollout_health_policy_v2()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("window_seconds", 61),
        ("minimum_request_count", 99),
        ("healthy_maximum_error_rate_basis_points", 101),
        ("unhealthy_minimum_error_rate_basis_points", 499),
        ("healthy_maximum_p95_latency_ms", 501),
        ("unhealthy_minimum_p95_latency_ms", 999),
        ("healthy_minimum_availability_basis_points", 9_899),
        ("unhealthy_maximum_availability_basis_points", 9_501),
        ("healthy_consecutive_windows", 1),
        ("maximum_windows", 11),
        ("missing_observation_action", "HEALTHY"),
    ],
)
def test_v2_policy_rejects_semantic_drift(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        _policy(**{field: value})


def test_monitoring_queries_freeze_signal_semantics_and_exact_filter() -> None:
    queries = _queries()

    assert tuple(query.query_kind for query in queries) == tuple(MonitoringQueryKind)
    assert queries[0].metric_type == "run.googleapis.com/request_count"
    assert queries[0].group_by_fields == ("metric.labels.response_code_class",)
    assert queries[1].metric_type == "run.googleapis.com/request_latencies"
    assert queries[1].secondary_per_series_aligner == "ALIGN_PERCENTILE_95"
    assert f'resource.labels.project_id="{PROJECT}"' in queries[0].metric_filter
    assert f'resource.labels.revision_name="{CANDIDATE}"' in queries[0].metric_filter


@pytest.mark.parametrize(
    "changes",
    [
        {"window_ended_at": "2026-08-21T12:01:01Z"},
        {"metric_type": "run.googleapis.com/request_latencies"},
        {"group_by_fields": ()},
        {"metric_filter": 'metric.type="run.googleapis.com/request_count"'},
        {"root_id": "cgroot:" + "2" * 64},
    ],
)
def test_monitoring_query_rejects_changed_window_signal_or_filter(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _query(MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS, **changes)


def test_monitoring_query_rejects_a_caller_asserted_query_id() -> None:
    with pytest.raises(ValidationError, match="query id does not match"):
        _query(
            MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS,
            query_id="cgmonq:" + "f" * 64,
        )


def test_monitoring_samples_have_strict_query_specific_shapes() -> None:
    request_query, latency_query = _queries()
    request_sample = _sample(
        request_query,
        response_code_class="2xx",
        int64_value=995,
    )
    latency_sample = _sample(latency_query, latency_microseconds=400_000)

    assert (
        decode_contract(canonical_json_bytes(request_sample), MonitoringSampleV1) == request_sample
    )
    assert latency_sample.provider_value_type == "DOUBLE"
    with pytest.raises(ValidationError, match="request-count sample shape"):
        _sample(
            request_query,
            response_code_class="2xx",
            int64_value=995,
            provider_value_type="DOUBLE",
        )
    with pytest.raises(ValidationError, match="latency sample shape"):
        _sample(
            latency_query,
            latency_microseconds=400_000,
            provider_value_type="INT64",
        )
    with pytest.raises(ValidationError, match="canonical binary64 conversion"):
        _sample(
            latency_query,
            latency_microseconds=400_000,
            provider_double_bits=struct.pack(">d", 400.001).hex(),
        )


@pytest.mark.parametrize(
    ("provider_double_bits", "expected_microseconds"),
    [
        ("0000000000000000", 0),
        ("3f40624dd2f1a9fc", 1),
        ("3f589374bc6a7efa", 2),
        ("3ff001a36e2eb1c4", 1_000),
        ("3ff0020c49ba5e35", 1_000),
        ("3ff0027525460aa6", 1_001),
        ("4079000000000001", 400_000),
    ],
)
def test_binary64_latency_conversion_has_frozen_boundary_vectors(
    provider_double_bits: str,
    expected_microseconds: int,
) -> None:
    assert binary64_milliseconds_to_microseconds(provider_double_bits) == expected_microseconds


@pytest.mark.parametrize("provider_double_bits", ["fff0000000000000", "7ff0000000000000"])
def test_binary64_latency_conversion_rejects_negative_or_nonfinite_values(
    provider_double_bits: str,
) -> None:
    with pytest.raises(ValueError, match="finite non-negative"):
        binary64_milliseconds_to_microseconds(provider_double_bits)


def test_sample_set_identity_is_ordered_domain_separated_and_bounded() -> None:
    first = "1" * 64
    second = "2" * 64

    assert monitoring_sample_set_sha256(()) is None
    assert monitoring_sample_set_sha256((first, second)) == (
        "3b5ad76eb4c9fea9ec1458869d9c06db638014ba9842b0e549905aa79477dad6"
    )
    assert monitoring_sample_set_sha256((first, second)) != (
        monitoring_sample_set_sha256((second, first))
    )
    with pytest.raises(ValueError, match="invalid SHA-256"):
        monitoring_sample_set_sha256(("not-a-digest",))


def test_complete_observation_binds_queries_samples_and_distribution() -> None:
    observation = _observation()
    encoded = canonical_json_bytes(observation)

    assert decode_contract(encoded, MonitoringWindowObservationV1) == observation
    assert observation.query_sha256s == tuple(
        canonical_sha256(query) for query in observation.queries
    )
    assert observation.latency_distribution is not None
    assert set(observation.latency_distribution.source_sample_sha256s).issubset(
        observation.sample_sha256s
    )


def test_observation_recomputes_sample_digests_and_aggregates() -> None:
    observation = _observation()
    request_query = observation.queries[0]
    altered = (
        _sample(request_query, response_code_class="2xx", int64_value=994),
        *observation.samples[1:],
    )

    with pytest.raises(ValidationError, match="sample digests"):
        _observation(samples=altered, sample_sha256s=observation.sample_sha256s)
    with pytest.raises(ValidationError, match="request aggregates"):
        _observation(request_count=999)
    with pytest.raises(ValidationError, match="latency aggregate"):
        _observation(latency_distribution=_distribution(p95_latency_ms=401))


def test_observation_binds_every_retrieved_source_sample_digest() -> None:
    observation = _observation()
    selected = observation.sample_sha256s
    identical_sources = tuple(sorted((*selected, selected[0])))
    conflict_sources = tuple(sorted((*selected, "f" * 64)))

    identical = _observation(
        source_sample_sha256s=identical_sources,
        duplicate_count=1,
    )
    conflict = _observation(
        source_sample_sha256s=conflict_sources,
        duplicate_count=1,
        conflicting_duplicate=True,
    )

    assert identical.source_sample_sha256s.count(selected[0]) == 2
    assert conflict.conflicting_duplicate is True
    assert canonical_sha256(identical) != canonical_sha256(conflict)

    with pytest.raises(ValidationError, match="not canonical"):
        _observation(source_sample_sha256s=tuple(reversed(identical_sources)))
    with pytest.raises(ValidationError, match="omit a selected sample"):
        _observation(source_sample_sha256s=tuple(sorted(selected[:-1])))
    with pytest.raises(ValidationError, match="duplicate count"):
        _observation(duplicate_count=1)
    with pytest.raises(ValidationError, match="conflict classification"):
        _observation(
            source_sample_sha256s=conflict_sources,
            duplicate_count=1,
        )


def test_observation_requires_canonical_complete_request_samples() -> None:
    samples = _samples()

    with pytest.raises(ValidationError, match="response-code class sample"):
        _observation(samples=(samples[-1],))
    with pytest.raises(ValidationError, match="canonical order"):
        _observation(samples=(samples[1], samples[0], *samples[2:]))
    with pytest.raises(ValidationError, match=r"must be unique|canonical order"):
        _observation(samples=(samples[0], samples[0], *samples[1:]))


def test_observation_rejects_sample_outside_its_exact_query() -> None:
    samples = _samples()
    foreign = samples[0].model_copy(update={"query_sha256": "f" * 64})

    with pytest.raises(ValidationError, match="does not match an observation query"):
        _observation(samples=(foreign, *samples[1:]))


@pytest.mark.parametrize(
    ("changes", "expected_completeness", "expected_timing"),
    [
        (
            {
                "samples": (),
                "sample_sha256s": (),
                "completeness": MonitoringObservationCompleteness.MISSING,
                "missing_signals": tuple(HealthSignal),
                "request_count": None,
                "response_1xx_count": None,
                "successful_request_count": None,
                "response_3xx_count": None,
                "response_4xx_count": None,
                "server_error_count": None,
                "latency_distribution": None,
            },
            MonitoringObservationCompleteness.MISSING,
            MonitoringObservationTiming.READY,
        ),
        (
            {
                "samples": _samples()[:-1],
                "completeness": MonitoringObservationCompleteness.PARTIAL,
                "missing_signals": (HealthSignal.REQUEST_LATENCY_P95,),
                "latency_distribution": None,
            },
            MonitoringObservationCompleteness.PARTIAL,
            MonitoringObservationTiming.READY,
        ),
        (
            {
                "observed_at": "2026-08-21T12:03:59Z",
                "timing": MonitoringObservationTiming.EARLY,
            },
            MonitoringObservationCompleteness.COMPLETE,
            MonitoringObservationTiming.EARLY,
        ),
        (
            {
                "observed_at": "2026-08-21T12:06:01Z",
                "timing": MonitoringObservationTiming.LATE,
            },
            MonitoringObservationCompleteness.COMPLETE,
            MonitoringObservationTiming.LATE,
        ),
        (
            {
                "source_sample_sha256s": tuple(
                    sorted(
                        (
                            *(canonical_sha256(sample) for sample in _samples()),
                            "f" * 64,
                        )
                    )
                ),
                "duplicate_count": 1,
                "conflicting_duplicate": True,
            },
            MonitoringObservationCompleteness.COMPLETE,
            MonitoringObservationTiming.READY,
        ),
    ],
)
def test_observation_explicitly_classifies_fail_safe_sample_states(
    changes: dict[str, object],
    expected_completeness: MonitoringObservationCompleteness,
    expected_timing: MonitoringObservationTiming,
) -> None:
    observation = _observation(**changes)

    assert observation.completeness is expected_completeness
    assert observation.timing is expected_timing


@pytest.mark.parametrize(
    "changes",
    [
        {"query_sha256s": ("f" * 64,) * 2},
        {"window_started_at": "2026-08-21T12:00:01Z"},
        {"successful_request_count": 1_001},
        {"duplicate_count": 0, "conflicting_duplicate": True},
        {"missing_signals": (HealthSignal.TOTAL_REQUESTS,)},
        {"timing": MonitoringObservationTiming.LATE},
        {"observed_at": "2026-08-21T12:00:59Z", "timing": MonitoringObservationTiming.EARLY},
        {"root_id": "cgroot:" + "2" * 64},
    ],
)
def test_observation_rejects_scope_digest_or_classification_drift(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _observation(**changes)


def test_state_enforces_streak_and_window_continuity() -> None:
    state = _state(evaluated=True)
    linked_wait_state = _state(prior_decision_sha256="f" * 64)

    assert decode_contract(canonical_json_bytes(state), HealthEvaluationStateV1) == state
    assert linked_wait_state.evaluated_windows == 0
    assert linked_wait_state.prior_decision_sha256 == "f" * 64
    with pytest.raises(ValidationError, match="both be active"):
        _state(
            evaluated=True,
            consecutive_healthy_windows=1,
            consecutive_unhealthy_windows=1,
        )
    with pytest.raises(ValidationError, match="initial health state"):
        _state(last_window_ended_at="2026-08-21T12:01:00Z")
    with pytest.raises(ValidationError, match="not contiguous"):
        _state(
            evaluated=True,
            last_window_ended_at="2026-08-21T12:02:00Z",
        )
    with pytest.raises(ValidationError, match="root binding"):
        _state(root_id="cgroot:" + "2" * 64)


def test_state_rejects_calendar_overflow_as_a_contract_error() -> None:
    values = _state().model_dump(mode="python")
    values.update(
        {
            "observation_started_at": "9999-12-31T23:59:59Z",
            "last_window_ended_at": "9999-12-31T23:59:59Z",
            "evaluated_windows": 1,
            "last_observation_sha256": "f" * 64,
        }
    )

    with pytest.raises(ValidationError, match="calendar range"):
        HealthEvaluationStateV1.model_validate(values)
    with pytest.raises(ContractError):
        decode_contract(
            json.dumps(values, separators=(",", ":")).encode("utf-8"),
            HealthEvaluationStateV1,
        )


def test_decision_cites_exact_inputs_and_canonical_integer_aggregates() -> None:
    decision = _decision()
    encoded = canonical_json_bytes(decision)

    assert decode_contract(encoded, HealthDecisionV1) == decision
    assert decision.availability_basis_points == 9_950
    assert decision.error_rate_basis_points == 10
    assert len(decision.query_sha256s) == 2

    with pytest.raises(ValidationError, match="availability aggregate"):
        _decision(availability_basis_points=9_949)
    with pytest.raises(ValidationError, match="outside its exact scope"):
        _decision(
            next_state=_state(
                evaluated=True, target=_target().model_copy(update={"environment": "other"})
            )
        )
    with pytest.raises(ValidationError, match="root binding"):
        _decision(root_id="cgroot:" + "2" * 64)


def test_decision_enforces_status_reason_and_streak_consistency() -> None:
    healthy_state = _state(
        evaluated=True,
        consecutive_healthy_windows=2,
        evaluated_windows=2,
    )
    healthy = _decision(
        status=HealthDecisionStatus.HEALTHY,
        reason_codes=(
            HealthReasonCode.HEALTHY_THRESHOLDS_MET,
            HealthReasonCode.HEALTHY_STREAK_MET,
        ),
        next_state=healthy_state,
        next_evaluation_at=None,
    )
    assert healthy.status is HealthDecisionStatus.HEALTHY

    with pytest.raises(ValidationError, match="terminal reasons"):
        _decision(status=HealthDecisionStatus.HEALTHY, next_evaluation_at=None)
    with pytest.raises(ValidationError, match="healthy streak"):
        _decision(
            status=HealthDecisionStatus.HEALTHY,
            reason_codes=(
                HealthReasonCode.HEALTHY_THRESHOLDS_MET,
                HealthReasonCode.HEALTHY_STREAK_MET,
            ),
            next_evaluation_at=None,
        )
    with pytest.raises(ValidationError, match="minimum request count"):
        _decision(
            status=HealthDecisionStatus.HEALTHY,
            reason_codes=(
                HealthReasonCode.HEALTHY_THRESHOLDS_MET,
                HealthReasonCode.HEALTHY_STREAK_MET,
            ),
            next_state=healthy_state,
            request_count=1,
            successful_request_count=1,
            server_error_count=0,
            error_rate_basis_points=0,
            availability_basis_points=10_000,
            next_evaluation_at=None,
        )
    with pytest.raises(ValidationError, match="request and latency sample citations"):
        _decision(
            status=HealthDecisionStatus.HEALTHY,
            reason_codes=(
                HealthReasonCode.HEALTHY_THRESHOLDS_MET,
                HealthReasonCode.HEALTHY_STREAK_MET,
            ),
            next_state=healthy_state,
            sample_sha256s=(),
            next_evaluation_at=None,
        )
    with pytest.raises(ValidationError, match="request and latency sample citations"):
        _decision(
            status=HealthDecisionStatus.HEALTHY,
            reason_codes=(
                HealthReasonCode.HEALTHY_THRESHOLDS_MET,
                HealthReasonCode.HEALTHY_STREAK_MET,
            ),
            next_state=healthy_state,
            sample_sha256s=("f" * 64,),
            next_evaluation_at=None,
        )
    with pytest.raises(ValidationError, match="exact 60-second window"):
        _decision(
            status=HealthDecisionStatus.HEALTHY,
            reason_codes=(
                HealthReasonCode.HEALTHY_THRESHOLDS_MET,
                HealthReasonCode.HEALTHY_STREAK_MET,
            ),
            next_state=healthy_state,
            window_started_at="2026-08-21T12:02:00Z",
            next_evaluation_at=None,
        )
    with pytest.raises(ValidationError, match="terminal streak reason"):
        _decision(
            reason_codes=(
                HealthReasonCode.HEALTHY_THRESHOLDS_MET,
                HealthReasonCode.HEALTHY_STREAK_MET,
            )
        )
    with pytest.raises(ValidationError, match="terminal streak reason"):
        _decision(
            status=HealthDecisionStatus.INSUFFICIENT_EVIDENCE,
            reason_codes=(HealthReasonCode.HEALTHY_STREAK_MET,),
        )


def test_unhealthy_and_non_consuming_wait_decisions_are_canonical() -> None:
    unhealthy = _decision(
        status=HealthDecisionStatus.UNHEALTHY,
        reason_codes=(
            HealthReasonCode.UNHEALTHY_ERROR_RATE,
            HealthReasonCode.UNHEALTHY_LATENCY,
            HealthReasonCode.UNHEALTHY_AVAILABILITY,
            HealthReasonCode.UNHEALTHY_STREAK_MET,
        ),
        next_state=_state(
            evaluated=True,
            consecutive_healthy_windows=0,
            consecutive_unhealthy_windows=2,
            evaluated_windows=2,
        ),
        request_count=100,
        successful_request_count=90,
        server_error_count=5,
        error_rate_basis_points=500,
        availability_basis_points=9_000,
        p95_latency_ms=1_000,
        next_evaluation_at=None,
    )
    early = _decision(
        reason_codes=(HealthReasonCode.SAMPLE_EARLY,),
        next_state=_state(),
    )
    duplicate = _decision(reason_codes=(HealthReasonCode.WINDOW_DUPLICATE,))

    assert unhealthy.status is HealthDecisionStatus.UNHEALTHY
    assert early.status is HealthDecisionStatus.WAIT
    assert early.next_state.last_observation_sha256 is None
    assert duplicate.status is HealthDecisionStatus.WAIT


def test_missing_decision_cannot_claim_observation_data_or_health() -> None:
    initial = _state()
    missing = _decision(
        status=HealthDecisionStatus.INSUFFICIENT_EVIDENCE,
        reason_codes=(HealthReasonCode.NO_SAMPLES,),
        next_state=initial,
        observation_sha256=None,
        query_sha256s=(),
        sample_sha256s=(),
        window_started_at=None,
        window_ended_at=None,
        request_count=None,
        successful_request_count=None,
        server_error_count=None,
        error_rate_basis_points=None,
        availability_basis_points=None,
        p95_latency_ms=None,
    )

    assert missing.status is HealthDecisionStatus.INSUFFICIENT_EVIDENCE
    terminal_state = _decision(
        status=HealthDecisionStatus.INSUFFICIENT_EVIDENCE,
        reason_codes=(HealthReasonCode.STATE_TERMINAL,),
        next_state=_state(
            evaluated=True,
            consecutive_healthy_windows=2,
            evaluated_windows=2,
        ),
        observation_sha256=None,
        query_sha256s=(),
        sample_sha256s=(),
        window_started_at=None,
        window_ended_at=None,
        request_count=None,
        successful_request_count=None,
        server_error_count=None,
        error_rate_basis_points=None,
        availability_basis_points=None,
        p95_latency_ms=None,
        next_evaluation_at=None,
    )
    assert terminal_state.reason_codes == (HealthReasonCode.STATE_TERMINAL,)
    with pytest.raises(ValidationError, match="requires a terminal streak"):
        _decision(
            status=HealthDecisionStatus.INSUFFICIENT_EVIDENCE,
            reason_codes=(HealthReasonCode.STATE_TERMINAL,),
            next_state=_state(),
            observation_sha256=None,
            query_sha256s=(),
            sample_sha256s=(),
            window_started_at=None,
            window_ended_at=None,
            request_count=None,
            successful_request_count=None,
            server_error_count=None,
            error_rate_basis_points=None,
            availability_basis_points=None,
            p95_latency_ms=None,
            next_evaluation_at=None,
        )
    with pytest.raises(ValidationError, match="cannot cite a current observation"):
        _decision(
            status=HealthDecisionStatus.INSUFFICIENT_EVIDENCE,
            reason_codes=(HealthReasonCode.STATE_TERMINAL,),
            next_state=_state(
                evaluated=True,
                consecutive_healthy_windows=2,
                evaluated_windows=2,
            ),
            next_evaluation_at=None,
        )
    with pytest.raises(ValidationError, match="cannot schedule another evaluation"):
        _decision(
            status=HealthDecisionStatus.INSUFFICIENT_EVIDENCE,
            reason_codes=(HealthReasonCode.STATE_TERMINAL,),
            next_state=_state(
                evaluated=True,
                consecutive_healthy_windows=2,
                evaluated_windows=2,
            ),
            observation_sha256=None,
            query_sha256s=(),
            sample_sha256s=(),
            window_started_at=None,
            window_ended_at=None,
            request_count=None,
            successful_request_count=None,
            server_error_count=None,
            error_rate_basis_points=None,
            availability_basis_points=None,
            p95_latency_ms=None,
            next_evaluation_at="2026-08-21T12:05:00Z",
        )
    with pytest.raises(ValidationError, match="healthy decision requires"):
        _decision(
            status=HealthDecisionStatus.HEALTHY,
            reason_codes=(
                HealthReasonCode.HEALTHY_THRESHOLDS_MET,
                HealthReasonCode.HEALTHY_STREAK_MET,
            ),
            observation_sha256=None,
            query_sha256s=(),
            sample_sha256s=(),
            window_started_at=None,
            window_ended_at=None,
            request_count=None,
            successful_request_count=None,
            server_error_count=None,
            error_rate_basis_points=None,
            availability_basis_points=None,
            p95_latency_ms=None,
            next_evaluation_at=None,
        )


def test_existing_v1_policy_still_decodes_without_v2_fields() -> None:
    policy = RolloutHealthPolicyV1(
        schema_version="controlgraph.rollout-health-policy/v1",
        input_schema_version="controlgraph.health-input/v1",
        evaluation_window_seconds=60,
        minimum_request_count=100,
        maximum_error_rate_basis_points=100,
        maximum_p95_latency_ms=500,
        minimum_probe_count=10,
        minimum_probe_success_basis_points=9_900,
        healthy_consecutive_windows=2,
        unhealthy_consecutive_windows=2,
        window_semantics="HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE",
        incomplete_data_action="INDETERMINATE_NO_MUTATION",
        late_data_action="INDETERMINATE_NO_MUTATION",
        duplicate_data_action="REJECT",
    )

    encoded = canonical_json_bytes(policy)
    assert decode_contract(encoded, RolloutHealthPolicyV1) == policy
    with pytest.raises(ContractError):
        decode_contract(encoded, RolloutHealthPolicyV2)


def test_health_golden_vectors_freeze_canonical_bytes_and_digests() -> None:
    fixture_path = Path(__file__).parents[2] / "contract-fixtures/health-v1/golden.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected = (
        (_policy(), RolloutHealthPolicyV2),
        (_observation(), MonitoringWindowObservationV1),
        (_decision(), HealthDecisionV1),
    )
    vectors = fixture["vectors"]
    decoded_values = (
        decode_contract(vectors[0]["canonical"].encode("utf-8"), RolloutHealthPolicyV2),
        decode_contract(vectors[1]["canonical"].encode("utf-8"), MonitoringWindowObservationV1),
        decode_contract(vectors[2]["canonical"].encode("utf-8"), HealthDecisionV1),
    )

    assert fixture["canonical_encoding"] == "controlgraph.canonical-json/v1"
    for vector, (value, _model_type), decoded in zip(
        vectors, expected, decoded_values, strict=True
    ):
        canonical = vector["canonical"].encode("utf-8")
        assert canonical == canonical_json_bytes(value)
        assert decoded == value
        assert vector["sha256"] == canonical_sha256(decoded)


@pytest.mark.parametrize(
    ("value", "model_type"),
    [
        (_policy(), RolloutHealthPolicyV2),
        (
            _query(MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS),
            MonitoringMetricQueryV1,
        ),
        (_distribution(), MonitoringDistributionV1),
        (_samples()[0], MonitoringSampleV1),
        (_observation(), MonitoringWindowObservationV1),
        (_state(), HealthEvaluationStateV1),
        (_decision(), HealthDecisionV1),
    ],
)
def test_health_contracts_reject_unknown_fields(
    value: object,
    model_type: type[StrictContractModel],
) -> None:
    raw = json.loads(canonical_json_bytes(value))  # type: ignore[arg-type]
    raw["unexpected"] = "rejected"
    with pytest.raises(ValidationError):
        model_type.model_validate(raw)
