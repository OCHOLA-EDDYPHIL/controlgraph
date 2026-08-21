from __future__ import annotations

import asyncio
import json
import struct
from collections.abc import AsyncIterator, Callable, Coroutine, Sequence
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any

import pytest
from google.api import metric_pb2
from google.cloud import monitoring_v3

from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.application.monitoring import (
    MonitoringCollectionError,
    MonitoringCollectionErrorCode,
)
from controlgraph_canary.contracts.codec import decode_contract
from controlgraph_canary.contracts.health import (
    MonitoringMetricQueryV1,
    MonitoringWindowObservationV1,
)
from controlgraph_canary.integrations.google.monitoring import (
    MONITORING_MAXIMUM_PAGES,
    MONITORING_MAXIMUM_POINTS,
    GoogleCloudMonitoringCollector,
)

_FIXTURE = Path(__file__).parents[2] / "contract-fixtures" / "health-v1" / "golden.json"


def _async_test[**P](
    function: Callable[P, Coroutine[Any, Any, None]],
) -> Callable[P, None]:
    @wraps(function)
    def run(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(function(*args, **kwargs))

    return run


def _queries() -> tuple[MonitoringMetricQueryV1, MonitoringMetricQueryV1]:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    observation = decode_contract(
        fixture["vectors"][1]["canonical"].encode("utf-8"),
        MonitoringWindowObservationV1,
    )
    return observation.queries


def _timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _request_series(
    query: MonitoringMetricQueryV1,
    *,
    response_code_class: str = "2xx",
    value: int = 100,
    resource_labels: dict[str, str] | None = None,
    metric_labels: dict[str, str] | None = None,
    points: Sequence[monitoring_v3.Point] | None = None,
    metric_kind: int = metric_pb2.MetricDescriptor.MetricKind.DELTA,
    value_type: int = metric_pb2.MetricDescriptor.ValueType.INT64,
    unit: str = "1",
) -> monitoring_v3.TimeSeries:
    labels = {
        "response_code_class": response_code_class,
        "route": "",
    }
    if metric_labels is not None:
        labels = metric_labels
    target_labels = {
        "project_id": query.target.project_id,
        "location": query.target.region,
        "service_name": query.target.service_name,
        "configuration_name": query.configuration_name,
        "revision_name": query.candidate_revision,
    }
    if resource_labels is not None:
        target_labels = resource_labels
    provider_points = (
        points
        if points is not None
        else (
            monitoring_v3.Point(
                interval=monitoring_v3.TimeInterval(
                    start_time=_timestamp(query.window_started_at),
                    end_time=_timestamp(query.window_ended_at),
                ),
                value=monitoring_v3.TypedValue(int64_value=value),
            ),
        )
    )
    return monitoring_v3.TimeSeries(
        metric={"type": query.metric_type, "labels": labels},
        resource={"type": query.monitored_resource_type, "labels": target_labels},
        metric_kind=metric_kind,
        value_type=value_type,
        points=provider_points,
        unit=unit,
    )


def _latency_series(
    query: MonitoringMetricQueryV1,
    *,
    value: float = 400.125,
    include_start: bool = False,
    resource_labels: dict[str, str] | None = None,
    metric_labels: dict[str, str] | None = None,
    metric_kind: int = metric_pb2.MetricDescriptor.MetricKind.GAUGE,
    value_type: int = metric_pb2.MetricDescriptor.ValueType.DOUBLE,
    unit: str = "ms",
) -> monitoring_v3.TimeSeries:
    interval: dict[str, datetime] = {"end_time": _timestamp(query.window_ended_at)}
    if include_start:
        interval["start_time"] = _timestamp(query.window_ended_at)
    return monitoring_v3.TimeSeries(
        metric={
            "type": query.metric_type,
            "labels": metric_labels if metric_labels is not None else {"route": ""},
        },
        resource={
            "type": query.monitored_resource_type,
            "labels": resource_labels if resource_labels is not None else {},
        },
        metric_kind=metric_kind,
        value_type=value_type,
        points=(
            monitoring_v3.Point(
                interval=interval,
                value=monitoring_v3.TypedValue(double_value=value),
            ),
        ),
        unit=unit,
    )


def _page(
    query: MonitoringMetricQueryV1,
    *series: monitoring_v3.TimeSeries,
    next_page_token: str = "",
    execution_errors: Sequence[object] = (),
    unit: str | None = None,
) -> monitoring_v3.ListTimeSeriesResponse:
    return monitoring_v3.ListTimeSeriesResponse(
        time_series=series,
        next_page_token=next_page_token,
        execution_errors=execution_errors,
        unit=query.unit if unit is None else unit,
    )


class FakePager:
    def __init__(
        self,
        pages: Sequence[monitoring_v3.ListTimeSeriesResponse],
        *,
        terminal_error: Exception | None = None,
        delay_seconds: float = 0,
    ) -> None:
        self._pages = tuple(pages)
        self._terminal_error = terminal_error
        self._delay_seconds = delay_seconds
        self.yielded = 0

    @property
    def pages(self) -> AsyncIterator[monitoring_v3.ListTimeSeriesResponse]:
        async def iterate() -> AsyncIterator[monitoring_v3.ListTimeSeriesResponse]:
            for page in self._pages:
                if self._delay_seconds:
                    await asyncio.sleep(self._delay_seconds)
                self.yielded += 1
                yield page
            if self._terminal_error is not None:
                raise self._terminal_error

        return iterate()


class FakeMetricServiceClient:
    def __init__(
        self,
        pager: FakePager | None = None,
        *,
        error: BaseException | None = None,
        delay_seconds: float = 0,
    ) -> None:
        self.pager = pager or FakePager(())
        self.error = error
        self.delay_seconds = delay_seconds
        self.calls: list[tuple[monitoring_v3.ListTimeSeriesRequest, object, float]] = []

    async def list_time_series(
        self,
        request: monitoring_v3.ListTimeSeriesRequest,
        *,
        retry: object,
        timeout: float,
    ) -> FakePager:
        self.calls.append((request, retry, timeout))
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.error is not None:
            raise self.error
        return self.pager


def _collector(
    client: FakeMetricServiceClient,
    query: MonitoringMetricQueryV1 | None = None,
) -> GoogleCloudMonitoringCollector:
    bound_query = query or _queries()[0]
    return GoogleCloudMonitoringCollector(
        target=bound_query.target,
        service_role=ServiceRole.VERIFIER,
        configured_project_id=bound_query.target.project_id,
        client_factory=lambda: client,
    )


@_async_test
async def test_request_query_is_exact_bounded_retry_free_and_canonical() -> None:
    query = _queries()[0]
    first_page = _page(
        query,
        _request_series(query, response_code_class="5xx", value=3),
        _request_series(query, response_code_class="2xx", value=97),
        next_page_token="next-page",
    )
    second_page = _page(
        query,
        _request_series(query, response_code_class="2xx", value=97),
    )
    client = FakeMetricServiceClient(FakePager((first_page, second_page)))

    result = await _collector(client, query).collect(query, timeout_seconds=12.0)

    assert [point.response_code_class for point in result.points] == ["2xx", "2xx", "5xx"]
    assert [point.int64_value for point in result.points] == [97, 97, 3]
    assert all(point.interval_started_at == query.window_started_at for point in result.points)
    assert all(point.interval_ended_at == query.window_ended_at for point in result.points)
    assert len(client.calls) == 1
    request, retry, timeout = client.calls[0]
    assert retry is None
    assert timeout == 5.0
    assert request.name == f"projects/{query.target.project_id}"
    assert request.filter == query.metric_filter
    assert request.page_size == 1_000
    assert request.view == monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL
    assert request.order_by == ""
    assert request.page_token == ""
    assert request.aggregation.alignment_period.total_seconds() == 60
    assert request.aggregation.per_series_aligner == monitoring_v3.Aggregation.Aligner.ALIGN_SUM
    assert request.aggregation.cross_series_reducer == monitoring_v3.Aggregation.Reducer.REDUCE_SUM
    assert tuple(request.aggregation.group_by_fields) == (
        "metric.labels.response_code_class",
    )
    provider_request = monitoring_v3.ListTimeSeriesRequest.pb(request)
    assert not provider_request.HasField("secondary_aggregation")
    assert provider_request.interval.start_time.nanos == 0
    assert provider_request.interval.end_time.nanos == 0
    assert provider_request.interval.start_time.ToDatetime(tzinfo=UTC) == _timestamp(
        query.window_started_at
    )
    assert provider_request.interval.end_time.ToDatetime(tzinfo=UTC) == _timestamp(
        query.window_ended_at
    )


@_async_test
async def test_latency_query_uses_frozen_secondary_aggregation_and_preserves_bits() -> None:
    query = _queries()[1]
    client = FakeMetricServiceClient(
        FakePager(
            (
                _page(query, _latency_series(query, value=400.125)),
            )
        )
    )

    result = await _collector(client, query).collect(query, timeout_seconds=10.0)

    assert len(result.points) == 1
    assert result.points[0].provider_double_bits == struct.pack(">d", 400.125).hex()
    request = client.calls[0][0]
    assert request.aggregation.per_series_aligner == monitoring_v3.Aggregation.Aligner.ALIGN_SUM
    assert request.aggregation.cross_series_reducer == monitoring_v3.Aggregation.Reducer.REDUCE_SUM
    assert tuple(request.aggregation.group_by_fields) == ()
    assert request.secondary_aggregation.alignment_period.total_seconds() == 60
    assert (
        request.secondary_aggregation.per_series_aligner
        == monitoring_v3.Aggregation.Aligner.ALIGN_PERCENTILE_95
    )
    assert (
        request.secondary_aggregation.cross_series_reducer
        == monitoring_v3.Aggregation.Reducer.REDUCE_NONE
    )


@pytest.mark.parametrize("include_start", [False, True])
def test_latency_accepts_only_canonical_gauge_interval_forms(include_start: bool) -> None:
    async def run() -> None:
        query = _queries()[1]
        response = _page(
            query,
            _latency_series(query, include_start=include_start),
        )

        result = await _collector(
            FakeMetricServiceClient(FakePager((response,))),
            query,
        ).collect(query, timeout_seconds=10.0)

        assert result.points[0].interval_started_at == query.window_started_at
        assert result.points[0].interval_ended_at == query.window_ended_at

    asyncio.run(run())


@_async_test
async def test_empty_reduced_series_remains_missing_instead_of_becoming_zero() -> None:
    query = _queries()[0]
    for unit in (query.unit, ""):
        client = FakeMetricServiceClient(
            FakePager((_page(query, unit=unit),))
        )

        result = await _collector(client, query).collect(query, timeout_seconds=10.0)

        assert result.points == ()


@_async_test
async def test_reduced_series_may_omit_target_labels_but_cannot_echo_another_target() -> None:
    query = _queries()[0]
    accepted = _page(
        query,
        _request_series(
            query,
            resource_labels={},
            metric_labels={"response_code_class": "2xx"},
        ),
    )
    result = await _collector(
        FakeMetricServiceClient(FakePager((accepted,))),
        query,
    ).collect(query, timeout_seconds=10.0)
    assert result.points[0].int64_value == 100

    rejected = _page(
        query,
        _request_series(
            query,
            resource_labels={"service_name": "unrelated-service"},
        ),
    )
    with pytest.raises(MonitoringCollectionError) as failure:
        await _collector(
            FakeMetricServiceClient(FakePager((rejected,))),
            query,
        ).collect(query, timeout_seconds=10.0)
    assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID


@_async_test
async def test_query_substitution_is_denied_before_provider_access() -> None:
    query = _queries()[0]
    client = FakeMetricServiceClient()
    altered = query.model_copy(
        update={"metric_filter": 'metric.type="run.googleapis.com/request_count"'}
    )

    with pytest.raises(MonitoringCollectionError) as failure:
        await _collector(client, query).collect(altered, timeout_seconds=10.0)

    assert failure.value.code is MonitoringCollectionErrorCode.CONFIGURATION_INVALID
    assert client.calls == []


def test_collector_is_explicitly_verifier_only_and_target_bound() -> None:
    query = _queries()[0]
    client = FakeMetricServiceClient()
    for role in ServiceRole:
        if role is ServiceRole.VERIFIER:
            continue
        with pytest.raises(MonitoringCollectionError) as failure:
            GoogleCloudMonitoringCollector(
                target=query.target,
                service_role=role,
                configured_project_id=query.target.project_id,
                client_factory=lambda: client,
            )
        assert failure.value.code is MonitoringCollectionErrorCode.CONFIGURATION_INVALID

    invalid_configurations = (
        (query.target, "unsealed-project"),
        (query.target, "controlgraph-canary-zzzzzz"),
        (
            query.target.model_copy(update={"region": "europe-west1"}),
            query.target.project_id,
        ),
        (
            query.target.model_copy(update={"environment": "prod"}),
            query.target.project_id,
        ),
        (
            query.target.model_copy(update={"service_name": "other-service"}),
            query.target.project_id,
        ),
    )
    for target, configured_project_id in invalid_configurations:
        with pytest.raises(MonitoringCollectionError) as failure:
            GoogleCloudMonitoringCollector(
                target=target,
                service_role=ServiceRole.VERIFIER,
                configured_project_id=configured_project_id,
                client_factory=lambda: client,
            )
        assert failure.value.code is MonitoringCollectionErrorCode.CONFIGURATION_INVALID
    assert client.calls == []


@pytest.mark.parametrize(
    "response_code_class",
    ["", "200", "6xx", "2XX"],
)
def test_unknown_response_code_classes_fail_closed(response_code_class: str) -> None:
    async def run() -> None:
        query = _queries()[0]
        response = _page(
            query,
            _request_series(query, response_code_class=response_code_class),
        )
        with pytest.raises(MonitoringCollectionError) as failure:
            await _collector(
                FakeMetricServiceClient(FakePager((response,))),
                query,
            ).collect(query, timeout_seconds=10.0)
        assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID

    asyncio.run(run())


@pytest.mark.parametrize("value", [-1, 2**53])
def test_request_values_must_be_nonnegative_safe_int64(value: int) -> None:
    async def run() -> None:
        query = _queries()[0]
        response = _page(
            query,
            _request_series(query, value=value),
        )
        with pytest.raises(MonitoringCollectionError) as failure:
            await _collector(
                FakeMetricServiceClient(FakePager((response,))),
                query,
            ).collect(query, timeout_seconds=10.0)
        assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID

    asyncio.run(run())


@pytest.mark.parametrize("value", [-1.0, -0.0, float("inf"), float("-inf"), float("nan")])
def test_latency_values_must_be_finite_nonnegative_and_not_negative_zero(
    value: float,
) -> None:
    async def run() -> None:
        query = _queries()[1]
        response = _page(
            query,
            _latency_series(query, value=value),
        )
        with pytest.raises(MonitoringCollectionError) as failure:
            await _collector(
                FakeMetricServiceClient(FakePager((response,))),
                query,
            ).collect(query, timeout_seconds=10.0)
        assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID

    asyncio.run(run())


@_async_test
async def test_wrong_point_interval_type_and_cardinality_fail_closed() -> None:
    request_query, latency_query = _queries()
    wrong_end = monitoring_v3.Point(
        interval={
            "start_time": _timestamp(request_query.window_started_at),
            "end_time": _timestamp(request_query.window_started_at),
        },
        value={"int64_value": 1},
    )
    nanos = monitoring_v3.Point(
        interval={
            "start_time": {
                "seconds": int(_timestamp(request_query.window_started_at).timestamp()),
                "nanos": 1,
            },
            "end_time": _timestamp(request_query.window_ended_at),
        },
        value={"int64_value": 1},
    )
    wrong_latency_interval = _latency_series(latency_query, include_start=True)
    wrong_latency_interval.points[0].interval = monitoring_v3.TimeInterval(
        start_time=_timestamp(latency_query.window_started_at),
        end_time=_timestamp(latency_query.window_ended_at),
    )
    malformed = (
        _request_series(request_query, points=(wrong_end,)),
        _request_series(request_query, points=(nanos,)),
        _request_series(request_query, points=()),
        _request_series(
            request_query,
            metric_kind=metric_pb2.MetricDescriptor.MetricKind.GAUGE,
        ),
        _request_series(
            request_query,
            value_type=metric_pb2.MetricDescriptor.ValueType.DOUBLE,
        ),
        _latency_series(
            latency_query,
            metric_kind=metric_pb2.MetricDescriptor.MetricKind.DELTA,
        ),
        _latency_series(
            latency_query,
            value_type=metric_pb2.MetricDescriptor.ValueType.DISTRIBUTION,
        ),
        wrong_latency_interval,
    )
    for series in malformed:
        query = (
            latency_query
            if series.metric.type == latency_query.metric_type
            else request_query
        )
        response = _page(query, series)
        with pytest.raises(MonitoringCollectionError) as failure:
            await _collector(
                FakeMetricServiceClient(FakePager((response,))),
                query,
            ).collect(query, timeout_seconds=10.0)
        assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID


@pytest.mark.parametrize("unit", ["", "ms"])
def test_nonempty_page_unit_must_match_the_exact_query_unit(unit: str) -> None:
    async def run() -> None:
        query = _queries()[0]
        response = _page(
            query,
            _request_series(query),
            unit=unit,
        )

        with pytest.raises(MonitoringCollectionError) as failure:
            await _collector(
                FakeMetricServiceClient(FakePager((response,))),
                query,
            ).collect(query, timeout_seconds=10.0)

        assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID

    asyncio.run(run())


@_async_test
async def test_execution_errors_and_provider_failures_are_sanitized() -> None:
    query = _queries()[0]
    provider_detail = "private-provider-detail"
    execution_error = _page(
        query,
        execution_errors=({"code": 13, "message": provider_detail},),
    )
    for client in (
        FakeMetricServiceClient(FakePager((execution_error,))),
        FakeMetricServiceClient(error=RuntimeError(provider_detail)),
        FakeMetricServiceClient(
            FakePager((), terminal_error=RuntimeError(provider_detail))
        ),
    ):
        with pytest.raises(MonitoringCollectionError) as failure:
            await _collector(client, query).collect(query, timeout_seconds=10.0)
        assert failure.value.code is MonitoringCollectionErrorCode.QUERY_UNAVAILABLE
        assert provider_detail not in str(failure.value)


@_async_test
async def test_outer_timeout_is_sanitized_and_cancellation_propagates() -> None:
    query = _queries()[0]
    with pytest.raises(MonitoringCollectionError) as timeout_failure:
        await _collector(
            FakeMetricServiceClient(delay_seconds=0.05),
            query,
        ).collect(query, timeout_seconds=0.001)
    assert timeout_failure.value.code is MonitoringCollectionErrorCode.QUERY_TIMEOUT

    with pytest.raises(asyncio.CancelledError):
        await _collector(
            FakeMetricServiceClient(error=asyncio.CancelledError()),
            query,
        ).collect(query, timeout_seconds=10.0)


@_async_test
async def test_page_point_and_token_bounds_prevent_unbounded_collection() -> None:
    query = _queries()[0]
    too_many_pages = tuple(_page(query) for _ in range(MONITORING_MAXIMUM_PAGES + 1))
    too_many_points = _page(
        query,
        *(
            _request_series(query, value=index)
            for index in range(MONITORING_MAXIMUM_POINTS + 1)
        ),
    )
    token_cycle = (
        _page(query, next_page_token="page-a"),
        _page(query, next_page_token="page-b"),
        _page(query, next_page_token="page-a"),
    )
    page_after_terminal = (
        _page(query),
        _page(query),
    )
    truncated_pager = (_page(query, next_page_token="not-consumed"),)
    for pages in (
        (),
        too_many_pages,
        (too_many_points,),
        token_cycle,
        page_after_terminal,
        truncated_pager,
    ):
        with pytest.raises(MonitoringCollectionError) as failure:
            await _collector(
                FakeMetricServiceClient(FakePager(pages)),
                query,
            ).collect(query, timeout_seconds=10.0)
        assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID

    maximum_page_sequence = tuple(
        _page(query, next_page_token=f"page-{index + 1}")
        for index in range(MONITORING_MAXIMUM_PAGES + 1)
    )
    bounded_pager = FakePager(maximum_page_sequence)
    with pytest.raises(MonitoringCollectionError) as failure:
        await _collector(
            FakeMetricServiceClient(bounded_pager),
            query,
        ).collect(query, timeout_seconds=10.0)
    assert failure.value.code is MonitoringCollectionErrorCode.RESULT_INVALID
    assert bounded_pager.yielded == MONITORING_MAXIMUM_PAGES
