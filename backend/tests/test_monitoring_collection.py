from __future__ import annotations

import asyncio
import json
import struct
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from controlgraph_canary.application.monitoring import (
    MonitoringCollectedPoint,
    MonitoringCollectionError,
    MonitoringCollectionErrorCode,
    MonitoringCollectionScope,
    MonitoringQueryCollection,
    MonitoringWindowCollector,
    _issue_monitoring_collection_scope,
)
from controlgraph_canary.contracts import (
    HealthSignal,
    MonitoringMetricQueryV1,
    MonitoringObservationCompleteness,
    MonitoringObservationTiming,
    MonitoringQueryKind,
    RolloutHealthPolicyV2,
    TargetBinding,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
    derive_monitoring_metric_queries,
)

PROJECT = "controlgraph-canary-a1b2c3"
SERVICE = "controlgraph-reference-target"
CANDIDATE = f"{SERVICE}-candidate-v17"
ROOT_SHA256 = "1" * 64
ROOT_ID = f"cgroot:{ROOT_SHA256}"


def _policy() -> RolloutHealthPolicyV2:
    fixture_path = Path(__file__).parents[2] / "contract-fixtures" / "health-v1" / "golden.json"
    fixture = cast(dict[str, object], json.loads(fixture_path.read_text(encoding="utf-8")))
    vectors = cast(list[dict[str, object]], fixture["vectors"])
    vector = next(item for item in vectors if item["model"] == "RolloutHealthPolicyV2")
    return decode_contract(cast(str, vector["canonical"]), RolloutHealthPolicyV2)


def _target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT,
        region="us-central1",
        environment="nonprod",
        service_name=SERVICE,
    )


def _scope(**changes: object) -> MonitoringCollectionScope:
    values: dict[str, object] = {
        "policy": _policy(),
        "target": _target(),
        "root_id": ROOT_ID,
        "root_sha256": ROOT_SHA256,
        "epoch": 1,
        "candidate_revision": CANDIDATE,
        "observation_started_at": "2026-08-21T12:00:00Z",
    }
    values.update(changes)
    return _issue_monitoring_collection_scope(  # type: ignore[arg-type]
        **values,
    )


def _clock(minute: int = 4, second: int = 0) -> Callable[[], datetime]:
    return lambda: datetime(2026, 8, 21, 12, minute, second, tzinfo=UTC)


def _point(
    query: MonitoringMetricQueryV1,
    *,
    response_code_class: str | None = None,
    int64_value: int | None = None,
    latency_ms: float | None = None,
) -> MonitoringCollectedPoint:
    is_latency = query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
    return MonitoringCollectedPoint(
        query_sha256=canonical_sha256(query),
        query_kind=query.query_kind,
        interval_started_at=query.window_started_at,
        interval_ended_at=query.window_ended_at,
        response_code_class=(None if is_latency else response_code_class),  # type: ignore[arg-type]
        provider_value_type="DOUBLE" if is_latency else "INT64",
        int64_value=None if is_latency else int64_value,
        provider_double_bits=(
            struct.pack(">d", latency_ms if latency_ms is not None else 0.0).hex()
            if is_latency
            else None
        ),
    )


class FakeQueryCollector:
    def __init__(
        self,
        points: Callable[[MonitoringMetricQueryV1], tuple[MonitoringCollectedPoint, ...]],
    ) -> None:
        self._points = points
        self.calls: list[tuple[MonitoringMetricQueryV1, float]] = []

    async def collect(
        self,
        query: MonitoringMetricQueryV1,
        *,
        timeout_seconds: float,
    ) -> MonitoringQueryCollection:
        self.calls.append((query, timeout_seconds))
        return MonitoringQueryCollection(
            query_sha256=canonical_sha256(query),
            query_kind=query.query_kind,
            points=self._points(query),
        )


def _complete_points(
    query: MonitoringMetricQueryV1,
) -> tuple[MonitoringCollectedPoint, ...]:
    if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
        return (_point(query, latency_ms=400.0),)
    return (
        _point(query, response_code_class="5xx", int64_value=1),
        _point(query, response_code_class="4xx", int64_value=2),
        _point(query, response_code_class="2xx", int64_value=995),
        _point(query, response_code_class="3xx", int64_value=2),
    )


def test_query_derivation_is_closed_target_bound_and_deterministic() -> None:
    arguments = {
        "target": _target(),
        "root_id": ROOT_ID,
        "root_sha256": ROOT_SHA256,
        "epoch": 1,
        "candidate_revision": CANDIDATE,
        "window_started_at": "2026-08-21T12:00:00Z",
        "window_ended_at": "2026-08-21T12:01:00Z",
    }

    queries = derive_monitoring_metric_queries(_policy(), **arguments)  # type: ignore[arg-type]

    assert queries == derive_monitoring_metric_queries(  # type: ignore[arg-type]
        _policy(),
        **arguments,
    )
    assert tuple(query.query_kind for query in queries) == tuple(MonitoringQueryKind)
    assert queries[0].group_by_fields == ("metric.labels.response_code_class",)
    assert queries[1].secondary_per_series_aligner == "ALIGN_PERCENTILE_95"
    assert queries[0].query_id != queries[1].query_id
    for query in queries:
        assert query.policy_sha256 == canonical_sha256(_policy())
        assert query.target == _target()
        assert query.root_id == ROOT_ID
        assert f'resource.labels.project_id="{PROJECT}"' in query.metric_filter
        assert f'resource.labels.revision_name="{CANDIDATE}"' in query.metric_filter
        assert 'metric.labels.route=""' in query.metric_filter
    other_environment = derive_monitoring_metric_queries(
        _policy(),
        **{
            **arguments,
            "target": _target().model_copy(update={"environment": "staging"}),
        },  # type: ignore[arg-type]
    )
    assert {query.query_id for query in queries}.isdisjoint(
        query.query_id for query in other_environment
    )


def test_derived_query_id_and_digest_regression_vector() -> None:
    queries = derive_monitoring_metric_queries(
        _policy(),
        target=_target(),
        root_id=ROOT_ID,
        root_sha256=ROOT_SHA256,
        epoch=1,
        candidate_revision=CANDIDATE,
        window_started_at="2026-08-21T12:00:00Z",
        window_ended_at="2026-08-21T12:01:00Z",
    )

    assert tuple((query.query_id, canonical_sha256(query)) for query in queries) == (
        (
            "cgmonq:774043f796437810da447d70f72b6d6c10b8ace8f1d8a76d1696075a72ba994b",
            "3c6b10b36969ddb15e246c35fb1bf4e7c1db6376dc34f1edf19138c402e547d3",
        ),
        (
            "cgmonq:acc9b5af5f79643f2051a11adcb91ee3be25d8dffa2a1678c9673587b589ca46",
            "120a82a526a7678364f8c03d311734a6966e3fa3b6b2ec7582c84b781dccb0e3",
        ),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"root_id": f"cgroot:{'2' * 64}"},
        {"candidate_revision": "UPPERCASE"},
        {"candidate_revision": "different-service-candidate-v1"},
        {"window_ended_at": "2026-08-21T12:01:01Z"},
        {
            "window_started_at": "2026-08-21T12:00:01Z",
            "window_ended_at": "2026-08-21T12:01:01Z",
        },
        {"epoch": True},
    ],
)
def test_query_derivation_rejects_invalid_scope_or_window(changes: dict[str, object]) -> None:
    arguments: dict[str, object] = {
        "target": _target(),
        "root_id": ROOT_ID,
        "root_sha256": ROOT_SHA256,
        "epoch": 1,
        "candidate_revision": CANDIDATE,
        "window_started_at": "2026-08-21T12:00:00Z",
        "window_ended_at": "2026-08-21T12:01:00Z",
    }
    arguments.update(changes)

    with pytest.raises((TypeError, ValueError)):
        derive_monitoring_metric_queries(_policy(), **arguments)  # type: ignore[arg-type]


def test_direct_query_contract_rejects_off_minute_and_cross_service_revision() -> None:
    query = derive_monitoring_metric_queries(
        _policy(),
        target=_target(),
        root_id=ROOT_ID,
        root_sha256=ROOT_SHA256,
        epoch=1,
        candidate_revision=CANDIDATE,
        window_started_at="2026-08-21T12:00:00Z",
        window_ended_at="2026-08-21T12:01:00Z",
    )[0]
    values = query.model_dump(mode="python")
    values.update(
        window_started_at="2026-08-21T12:00:01Z",
        window_ended_at="2026-08-21T12:01:01Z",
    )
    with pytest.raises(ValidationError, match="align to UTC minutes"):
        MonitoringMetricQueryV1.model_validate(values)

    other_revision = "different-service-candidate-v1"
    values = query.model_dump(mode="python")
    values["candidate_revision"] = other_revision
    values["metric_filter"] = query.metric_filter.replace(CANDIDATE, other_revision)
    with pytest.raises(ValidationError, match="outside the target service"):
        MonitoringMetricQueryV1.model_validate(values)

    values = query.model_dump(mode="python")
    values["query_id"] = "cgmonq:" + "f" * 64
    with pytest.raises(ValidationError, match="query id does not match"):
        MonitoringMetricQueryV1.model_validate(values)

    values = query.model_dump(mode="python")
    values["target"] = query.target.model_copy(update={"environment": "staging"})
    with pytest.raises(ValidationError, match="query id does not match"):
        MonitoringMetricQueryV1.model_validate(values)


def test_collector_builds_stable_canonical_complete_observation() -> None:
    provider = FakeQueryCollector(_complete_points)
    collector = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=provider,
        clock=_clock(),
    )

    result = asyncio.run(collector.collect(1))
    repeated = asyncio.run(collector.collect(1))
    observation = result.observation

    assert result == repeated
    assert result.observation_sha256 == canonical_sha256(observation)
    assert canonical_json_bytes(observation) == canonical_json_bytes(repeated.observation)
    assert [query.query_kind for query, _timeout in provider.calls[:2]] == list(MonitoringQueryKind)
    assert all(timeout == 10.0 for _query, timeout in provider.calls)
    assert observation.completeness is MonitoringObservationCompleteness.COMPLETE
    assert observation.timing is MonitoringObservationTiming.READY
    assert observation.missing_signals == ()
    assert observation.request_count == 1_000
    assert observation.response_1xx_count == 0
    assert observation.successful_request_count == 995
    assert observation.response_3xx_count == 2
    assert observation.response_4xx_count == 2
    assert observation.server_error_count == 1
    assert observation.latency_distribution is not None
    assert observation.latency_distribution.p95_latency_ms == 400
    assert observation.source_sample_sha256s == tuple(
        sorted(canonical_sha256(sample) for sample in observation.samples)
    )
    assert [sample.response_code_class for sample in observation.samples] == [
        "2xx",
        "3xx",
        "4xx",
        "5xx",
        None,
    ]


def test_duplicate_and_conflict_resolution_is_order_independent() -> None:
    def duplicate_points(
        query: MonitoringMetricQueryV1,
    ) -> tuple[MonitoringCollectedPoint, ...]:
        if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
            latency = _point(query, latency_ms=400.0)
            return latency, latency
        healthy = _point(query, response_code_class="2xx", int64_value=995)
        conflicting = _point(query, response_code_class="2xx", int64_value=994)
        return healthy, conflicting, healthy

    forward = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(duplicate_points),
        clock=_clock(),
    )
    reverse = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(lambda query: tuple(reversed(duplicate_points(query)))),
        clock=_clock(),
    )

    forward_result = asyncio.run(forward.collect(1))
    reverse_result = asyncio.run(reverse.collect(1))

    assert forward_result == reverse_result
    assert forward_result.observation.duplicate_count == 3
    assert forward_result.observation.conflicting_duplicate is True
    assert len(forward_result.observation.samples) == 2
    assert len(forward_result.observation.source_sample_sha256s) == 5
    assert forward_result.observation.successful_request_count == 994


def test_identical_duplicates_are_deduplicated_without_conflict() -> None:
    def identical_points(
        query: MonitoringMetricQueryV1,
    ) -> tuple[MonitoringCollectedPoint, ...]:
        point = (
            _point(query, latency_ms=400.0)
            if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
            else _point(query, response_code_class="2xx", int64_value=100)
        )
        return point, point

    observation = asyncio.run(
        MonitoringWindowCollector(
            scope=_scope(),
            query_collector=FakeQueryCollector(identical_points),
            clock=_clock(),
        ).collect(1)
    ).observation

    assert observation.duplicate_count == 2
    assert observation.conflicting_duplicate is False
    assert len(observation.samples) == 2
    assert len(observation.source_sample_sha256s) == 4
    assert len(set(observation.source_sample_sha256s)) == 2


def test_observation_identity_binds_discarded_conflicts_and_duplicate_multiplicity() -> None:
    def points_with_conflict(
        conflicting_count: int,
    ) -> Callable[[MonitoringMetricQueryV1], tuple[MonitoringCollectedPoint, ...]]:
        def points(
            query: MonitoringMetricQueryV1,
        ) -> tuple[MonitoringCollectedPoint, ...]:
            if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
                return (_point(query, latency_ms=400.0),)
            return (
                _point(query, response_code_class="2xx", int64_value=990),
                _point(
                    query,
                    response_code_class="2xx",
                    int64_value=conflicting_count,
                ),
            )

        return points

    first = asyncio.run(
        MonitoringWindowCollector(
            scope=_scope(),
            query_collector=FakeQueryCollector(points_with_conflict(994)),
            clock=_clock(),
        ).collect(1)
    )
    second = asyncio.run(
        MonitoringWindowCollector(
            scope=_scope(),
            query_collector=FakeQueryCollector(points_with_conflict(995)),
            clock=_clock(),
        ).collect(1)
    )

    assert first.observation.samples == second.observation.samples
    assert first.observation.duplicate_count == second.observation.duplicate_count == 1
    assert first.observation.source_sample_sha256s != (second.observation.source_sample_sha256s)
    assert first.observation.observation_id != second.observation.observation_id
    assert first.observation_sha256 != second.observation_sha256

    def one_or_two_identical(
        duplicate: bool,
    ) -> Callable[[MonitoringMetricQueryV1], tuple[MonitoringCollectedPoint, ...]]:
        def points(
            query: MonitoringMetricQueryV1,
        ) -> tuple[MonitoringCollectedPoint, ...]:
            point = (
                _point(query, latency_ms=400.0)
                if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
                else _point(query, response_code_class="2xx", int64_value=990)
            )
            return (point, point) if duplicate else (point,)

        return points

    single = asyncio.run(
        MonitoringWindowCollector(
            scope=_scope(),
            query_collector=FakeQueryCollector(one_or_two_identical(False)),
            clock=_clock(),
        ).collect(1)
    )
    repeated = asyncio.run(
        MonitoringWindowCollector(
            scope=_scope(),
            query_collector=FakeQueryCollector(one_or_two_identical(True)),
            clock=_clock(),
        ).collect(1)
    )

    assert single.observation.samples == repeated.observation.samples
    assert repeated.observation.duplicate_count == 2
    assert single.observation_sha256 != repeated.observation_sha256


def test_provider_neutral_points_reject_malformed_values() -> None:
    request_query, latency_query = derive_monitoring_metric_queries(
        _policy(),
        target=_target(),
        root_id=ROOT_ID,
        root_sha256=ROOT_SHA256,
        epoch=1,
        candidate_revision=CANDIDATE,
        window_started_at="2026-08-21T12:00:00Z",
        window_ended_at="2026-08-21T12:01:00Z",
    )

    with pytest.raises(ValueError, match="request point"):
        _point(request_query, response_code_class="9xx", int64_value=1)
    with pytest.raises(ValueError, match="request point"):
        _point(request_query, response_code_class="2xx", int64_value=-1)
    with pytest.raises(ValueError, match="latency point"):
        MonitoringCollectedPoint(
            query_sha256=canonical_sha256(latency_query),
            query_kind=latency_query.query_kind,
            interval_started_at=latency_query.window_started_at,
            interval_ended_at=latency_query.window_ended_at,
            response_code_class=None,
            provider_value_type="DOUBLE",
            int64_value=None,
            provider_double_bits="8000000000000000",
        )


@pytest.mark.parametrize(
    ("points", "completeness", "missing_signals"),
    [
        (
            lambda _query: (),
            MonitoringObservationCompleteness.MISSING,
            tuple(HealthSignal),
        ),
        (
            lambda query: (
                ()
                if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
                else (_point(query, response_code_class="2xx", int64_value=100),)
            ),
            MonitoringObservationCompleteness.PARTIAL,
            (HealthSignal.REQUEST_LATENCY_P95,),
        ),
        (
            lambda query: (
                (_point(query, latency_ms=250.0),)
                if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
                else ()
            ),
            MonitoringObservationCompleteness.PARTIAL,
            (
                HealthSignal.TOTAL_REQUESTS,
                HealthSignal.SUCCESSFUL_2XX_REQUESTS,
                HealthSignal.SERVER_ERROR_5XX_REQUESTS,
            ),
        ),
    ],
)
def test_missing_series_produce_canonical_missing_or_partial_observations(
    points: Callable[[MonitoringMetricQueryV1], tuple[MonitoringCollectedPoint, ...]],
    completeness: MonitoringObservationCompleteness,
    missing_signals: tuple[HealthSignal, ...],
) -> None:
    collector = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(points),
        clock=_clock(),
    )

    observation = asyncio.run(collector.collect(1)).observation

    assert observation.completeness is completeness
    assert observation.missing_signals == missing_signals
    if observation.request_count is not None:
        assert observation.request_count == 100
        assert observation.server_error_count == 0


def test_window_index_derives_contiguous_query_interval_and_timing() -> None:
    collector = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(lambda _query: ()),
        clock=_clock(minute=5),
    )

    observation = asyncio.run(collector.collect(2)).observation

    assert observation.window_started_at == "2026-08-21T12:01:00Z"
    assert observation.window_ended_at == "2026-08-21T12:02:00Z"
    assert observation.timing is MonitoringObservationTiming.READY


@pytest.mark.parametrize(
    ("minute", "second", "expected"),
    [
        (3, 59, MonitoringObservationTiming.EARLY),
        (4, 0, MonitoringObservationTiming.READY),
        (6, 0, MonitoringObservationTiming.READY),
        (6, 1, MonitoringObservationTiming.LATE),
    ],
)
def test_collection_classifies_delayed_availability(
    minute: int,
    second: int,
    expected: MonitoringObservationTiming,
) -> None:
    collector = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(lambda _query: ()),
        clock=_clock(minute, second),
    )

    assert asyncio.run(collector.collect(1)).observation.timing is expected


def test_provider_errors_are_sanitized_and_cancellation_propagates() -> None:
    class FailingCollector:
        async def collect(
            self,
            query: MonitoringMetricQueryV1,
            *,
            timeout_seconds: float,
        ) -> MonitoringQueryCollection:
            del query, timeout_seconds
            raise RuntimeError("synthetic-secret-provider-payload")

    collector = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FailingCollector(),
        clock=_clock(),
    )

    with pytest.raises(MonitoringCollectionError) as raised:
        asyncio.run(collector.collect(1))

    assert raised.value.code is MonitoringCollectionErrorCode.QUERY_UNAVAILABLE
    assert str(raised.value) == MonitoringCollectionErrorCode.QUERY_UNAVAILABLE.value
    assert "synthetic-secret" not in str(raised.value)

    class CancelledCollector:
        async def collect(
            self,
            query: MonitoringMetricQueryV1,
            *,
            timeout_seconds: float,
        ) -> MonitoringQueryCollection:
            del query, timeout_seconds
            raise asyncio.CancelledError

    cancelled = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=CancelledCollector(),
        clock=_clock(),
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancelled.collect(1))


def test_timeout_invalid_results_windows_and_clock_have_closed_errors() -> None:
    class SlowCollector:
        async def collect(
            self,
            query: MonitoringMetricQueryV1,
            *,
            timeout_seconds: float,
        ) -> MonitoringQueryCollection:
            del query, timeout_seconds
            await asyncio.sleep(1)
            raise AssertionError("unreachable")

    timeout_collector = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=SlowCollector(),
        query_timeout_seconds=0.001,
        clock=_clock(),
    )
    with pytest.raises(MonitoringCollectionError) as timeout:
        asyncio.run(timeout_collector.collect(1))
    assert timeout.value.code is MonitoringCollectionErrorCode.QUERY_TIMEOUT

    class WrongQueryCollector:
        async def collect(
            self,
            query: MonitoringMetricQueryV1,
            *,
            timeout_seconds: float,
        ) -> MonitoringQueryCollection:
            del query, timeout_seconds
            return MonitoringQueryCollection(
                query_sha256="0" * 64,
                query_kind=MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS,
                points=(),
            )

    invalid = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=WrongQueryCollector(),
        clock=_clock(),
    )
    with pytest.raises(MonitoringCollectionError) as invalid_result:
        asyncio.run(invalid.collect(1))
    assert invalid_result.value.code is MonitoringCollectionErrorCode.RESULT_INVALID

    valid = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(lambda _query: ()),
        clock=_clock(),
    )
    for invalid_window in (True, 0, 11):
        with pytest.raises(MonitoringCollectionError) as window:
            asyncio.run(valid.collect(invalid_window))
        assert window.value.code is MonitoringCollectionErrorCode.WINDOW_INVALID

    early_clock = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(lambda _query: ()),
        clock=lambda: datetime(2026, 8, 21, 12, 0, tzinfo=UTC),
    )
    with pytest.raises(MonitoringCollectionError) as clock_error:
        asyncio.run(early_clock.collect(1))
    assert clock_error.value.code is MonitoringCollectionErrorCode.CLOCK_INVALID


def test_cross_query_point_bound_and_aggregate_overflow_fail_closed() -> None:
    def too_many_points(
        query: MonitoringMetricQueryV1,
    ) -> tuple[MonitoringCollectedPoint, ...]:
        point = (
            _point(query, latency_ms=1.0)
            if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
            else _point(query, response_code_class="2xx", int64_value=1)
        )
        count = 32 if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION else 33
        return (point,) * count

    bounded = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(too_many_points),
        clock=_clock(),
    )
    with pytest.raises(MonitoringCollectionError) as point_bound:
        asyncio.run(bounded.collect(1))
    assert point_bound.value.code is MonitoringCollectionErrorCode.RESULT_INVALID

    def overflowing_counts(
        query: MonitoringMetricQueryV1,
    ) -> tuple[MonitoringCollectedPoint, ...]:
        if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
            return (_point(query, latency_ms=1.0),)
        return tuple(
            _point(
                query,
                response_code_class=response_code_class,
                int64_value=2**53 - 1,
            )
            for response_code_class in ("1xx", "2xx", "3xx", "4xx", "5xx")
        )

    overflowing = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(overflowing_counts),
        clock=_clock(),
    )
    with pytest.raises(MonitoringCollectionError) as aggregate:
        asyncio.run(overflowing.collect(1))
    assert aggregate.value.code is MonitoringCollectionErrorCode.RESULT_INVALID


def test_query_bound_point_from_another_window_fails_closed() -> None:
    def wrong_window(
        query: MonitoringMetricQueryV1,
    ) -> tuple[MonitoringCollectedPoint, ...]:
        if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
            return ()
        return (
            MonitoringCollectedPoint(
                query_sha256=canonical_sha256(query),
                query_kind=query.query_kind,
                interval_started_at="2026-08-21T12:01:00Z",
                interval_ended_at="2026-08-21T12:02:00Z",
                response_code_class="2xx",
                provider_value_type="INT64",
                int64_value=1,
                provider_double_bits=None,
            ),
        )

    collector = MonitoringWindowCollector(
        scope=_scope(),
        query_collector=FakeQueryCollector(wrong_window),
        clock=_clock(),
    )

    with pytest.raises(MonitoringCollectionError) as failure:
        asyncio.run(collector.collect(1))

    assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID


@pytest.mark.parametrize(
    "changes",
    [
        {"root_id": f"cgroot:{'2' * 64}"},
        {"epoch": True},
        {"candidate_revision": "UPPERCASE"},
        {"candidate_revision": "different-service-candidate-v1"},
        {"observation_started_at": "2026-08-21T12:00:00+00:00"},
        {"observation_started_at": "2026-08-21T12:00:01Z"},
    ],
)
def test_collection_scope_rejects_invalid_bindings(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="monitoring collection scope is invalid"):
        _scope(**changes)


def test_monitoring_application_module_has_no_provider_sdk_import() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "controlgraph_canary" / "application" / "monitoring.py"
    ).read_text(encoding="utf-8")

    assert "google.cloud" not in source
    assert "monitoring_v3" not in source
