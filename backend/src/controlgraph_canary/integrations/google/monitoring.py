"""Read-only Cloud Monitoring collection for one verifier-bound rollout target."""

from __future__ import annotations

import asyncio
import math
import re
import struct
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Final, Literal, Protocol, cast

from google.api import metric_pb2  # type: ignore[import-untyped]
from google.cloud import monitoring_v3

from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.application.monitoring import (
    MonitoringCollectedPoint,
    MonitoringCollectionError,
    MonitoringCollectionErrorCode,
    MonitoringQueryCollection,
)
from controlgraph_canary.contracts.base import MAX_SAFE_INTEGER
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.health import (
    MonitoringMetricQueryV1,
    MonitoringQueryKind,
)
from controlgraph_canary.contracts.models import TargetBinding

MONITORING_RPC_TIMEOUT_SECONDS: Final = 5.0
MONITORING_MAXIMUM_TOTAL_TIMEOUT_SECONDS: Final = 30.0
MONITORING_MAXIMUM_PAGES: Final = 8
MONITORING_MAXIMUM_POINTS: Final = 64

_RESOURCE_TYPE: Final = "cloud_run_revision"
_MONITORING_REGION: Final = "us-central1"
_MONITORING_ENVIRONMENT: Final = "nonprod"
_MONITORING_SERVICE: Final = "controlgraph-reference-target"
_CONTROLGRAPH_PROJECT_ID: Final = re.compile(
    r"^controlgraph-canary-[a-z0-9]{6,10}$"
)
_RESPONSE_CODE_CLASSES: Final = frozenset({"1xx", "2xx", "3xx", "4xx", "5xx"})
_RESPONSE_CODE_ORDER: Final = {
    "1xx": 0,
    "2xx": 1,
    "3xx": 2,
    "4xx": 3,
    "5xx": 4,
}
_RESOURCE_LABELS: Final = frozenset(
    {"project_id", "location", "service_name", "configuration_name", "revision_name"}
)
_REQUEST_METRIC_LABELS: Final = frozenset({"response_code_class", "route"})
_LATENCY_METRIC_LABELS: Final = frozenset({"route"})
_NEGATIVE_ZERO_BINARY64: Final = "8000000000000000"

type _ResponseCodeClass = Literal["1xx", "2xx", "3xx", "4xx", "5xx"]


class _ListTimeSeriesPagerPort(Protocol):
    @property
    def pages(self) -> AsyncIterator[monitoring_v3.ListTimeSeriesResponse]: ...


class _MetricServiceClientPort(Protocol):
    async def list_time_series(
        self,
        request: monitoring_v3.ListTimeSeriesRequest,
        *,
        retry: None,
        timeout: float,
    ) -> _ListTimeSeriesPagerPort: ...


type MetricServiceClientFactory = Callable[[], _MetricServiceClientPort]


def _default_client_factory() -> _MetricServiceClientPort:
    return cast(_MetricServiceClientPort, monitoring_v3.MetricServiceAsyncClient())


class GoogleCloudMonitoringCollector:
    """List only the fixed health series admitted for the verifier target."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        service_role: ServiceRole,
        configured_project_id: str,
        client_factory: MetricServiceClientFactory | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or type(service_role) is not ServiceRole
            or service_role is not ServiceRole.VERIFIER
            or type(configured_project_id) is not str
            or _CONTROLGRAPH_PROJECT_ID.fullmatch(configured_project_id) is None
            or target.project_id != configured_project_id
            or target.region != _MONITORING_REGION
            or target.environment != _MONITORING_ENVIRONMENT
            or target.service_name != _MONITORING_SERVICE
            or (client_factory is not None and not callable(client_factory))
        ):
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.CONFIGURATION_INVALID
            )
        self._target = target
        self._client_factory = client_factory or _default_client_factory
        self._client: _MetricServiceClientPort | None = None
        self._client_lock = asyncio.Lock()

    @property
    def target(self) -> TargetBinding:
        return self._target

    @property
    def service_role(self) -> ServiceRole:
        return ServiceRole.VERIFIER

    async def collect(
        self,
        query: MonitoringMetricQueryV1,
        *,
        timeout_seconds: float,
    ) -> MonitoringQueryCollection:
        """Collect one exact query with bounded, retry-free provider reads."""

        admitted_query = self._admit_query(query)
        total_timeout = _admit_timeout(timeout_seconds)
        request = _list_time_series_request(admitted_query)
        try:
            async with asyncio.timeout(total_timeout):
                client = await self._metric_service_client()
                pager = await client.list_time_series(
                    request,
                    retry=None,
                    timeout=min(MONITORING_RPC_TIMEOUT_SECONDS, total_timeout),
                )
                points = await self._collect_pages(pager, admitted_query)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.QUERY_TIMEOUT
            ) from None
        except MonitoringCollectionError:
            raise
        except Exception:
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.QUERY_UNAVAILABLE
            ) from None
        return MonitoringQueryCollection(
            query_sha256=canonical_sha256(admitted_query),
            query_kind=admitted_query.query_kind,
            points=tuple(sorted(points, key=_point_order)),
        )

    async def _metric_service_client(self) -> _MetricServiceClientPort:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                self._client = self._client_factory()
            return self._client

    def _admit_query(self, query: MonitoringMetricQueryV1) -> MonitoringMetricQueryV1:
        if type(query) is not MonitoringMetricQueryV1:
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.CONFIGURATION_INVALID
            )
        try:
            validated = MonitoringMetricQueryV1.model_validate(
                query.model_dump(mode="python")
            )
        except (TypeError, ValueError):
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.CONFIGURATION_INVALID
            ) from None
        if (
            validated != query
            or validated.target != self._target
            or validated.configuration_name != self._target.service_name
            or validated.metric_filter != _metric_filter(validated)
        ):
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.CONFIGURATION_INVALID
            )
        return validated

    async def _collect_pages(
        self,
        pager: _ListTimeSeriesPagerPort,
        query: MonitoringMetricQueryV1,
    ) -> list[MonitoringCollectedPoint]:
        points: list[MonitoringCollectedPoint] = []
        seen_page_tokens: set[str] = set()
        page_count = 0
        last_next_page_token = ""
        try:
            pages = pager.pages
        except Exception:
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.QUERY_UNAVAILABLE
            ) from None
        async for page in pages:
            page_count += 1
            if page_count > MONITORING_MAXIMUM_PAGES:
                raise MonitoringCollectionError(
                    MonitoringCollectionErrorCode.RESULT_INVALID
                )
            if page_count > 1 and not last_next_page_token:
                raise MonitoringCollectionError(
                    MonitoringCollectionErrorCode.RESULT_INVALID
                )
            if type(page) is not monitoring_v3.ListTimeSeriesResponse:
                raise MonitoringCollectionError(
                    MonitoringCollectionErrorCode.RESULT_INVALID
                )
            if page.execution_errors:
                raise MonitoringCollectionError(
                    MonitoringCollectionErrorCode.QUERY_UNAVAILABLE
                )
            if page.unit != query.unit and (page.unit != "" or page.time_series):
                raise MonitoringCollectionError(
                    MonitoringCollectionErrorCode.RESULT_INVALID
                )
            next_page_token = page.next_page_token
            if type(next_page_token) is not str:
                raise MonitoringCollectionError(
                    MonitoringCollectionErrorCode.RESULT_INVALID
                )
            if next_page_token:
                if page_count == MONITORING_MAXIMUM_PAGES:
                    raise MonitoringCollectionError(
                        MonitoringCollectionErrorCode.RESULT_INVALID
                    )
                if next_page_token in seen_page_tokens:
                    raise MonitoringCollectionError(
                        MonitoringCollectionErrorCode.RESULT_INVALID
                    )
                seen_page_tokens.add(next_page_token)
            last_next_page_token = next_page_token
            if len(points) + len(page.time_series) > MONITORING_MAXIMUM_POINTS:
                raise MonitoringCollectionError(
                    MonitoringCollectionErrorCode.RESULT_INVALID
                )
            for series in page.time_series:
                points.append(_decode_time_series(series, query))
        if page_count == 0 or last_next_page_token:
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.RESULT_INVALID
            )
        return points


def _admit_timeout(timeout_seconds: float) -> float:
    if (
        type(timeout_seconds) not in {int, float}
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= MONITORING_MAXIMUM_TOTAL_TIMEOUT_SECONDS
    ):
        raise MonitoringCollectionError(
            MonitoringCollectionErrorCode.CONFIGURATION_INVALID
        )
    return float(timeout_seconds)


def _list_time_series_request(
    query: MonitoringMetricQueryV1,
) -> monitoring_v3.ListTimeSeriesRequest:
    aggregation = monitoring_v3.Aggregation(
        alignment_period={"seconds": query.alignment_period_seconds},
        per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
        cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
        group_by_fields=list(query.group_by_fields),
    )
    values: dict[str, object] = {
        "name": f"projects/{query.target.project_id}",
        "filter": _metric_filter(query),
        "interval": monitoring_v3.TimeInterval(
            start_time=_utc_datetime(query.window_started_at),
            end_time=_utc_datetime(query.window_ended_at),
        ),
        "aggregation": aggregation,
        "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        "page_size": query.page_size,
    }
    if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
        values["secondary_aggregation"] = monitoring_v3.Aggregation(
            alignment_period={"seconds": query.alignment_period_seconds},
            per_series_aligner=(
                monitoring_v3.Aggregation.Aligner.ALIGN_PERCENTILE_95
            ),
            cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_NONE,
        )
    return monitoring_v3.ListTimeSeriesRequest(values)


def _metric_filter(query: MonitoringMetricQueryV1) -> str:
    clauses = (
        f'metric.type="{query.metric_type}"',
        f'resource.type="{_RESOURCE_TYPE}"',
        f'resource.labels.project_id="{query.target.project_id}"',
        f'resource.labels.location="{query.target.region}"',
        f'resource.labels.service_name="{query.target.service_name}"',
        f'resource.labels.configuration_name="{query.configuration_name}"',
        f'resource.labels.revision_name="{query.candidate_revision}"',
        'metric.labels.route=""',
    )
    return " AND ".join(clauses)


def _decode_time_series(
    series: monitoring_v3.TimeSeries,
    query: MonitoringMetricQueryV1,
) -> MonitoringCollectedPoint:
    if type(series) is not monitoring_v3.TimeSeries or len(series.points) != 1:
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    if series.unit not in {"", query.unit}:
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    _validate_series_labels(series, query)
    point = series.points[0]
    if type(point) is not monitoring_v3.Point:
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    _validate_provider_interval(point, query)
    value = monitoring_v3.TypedValue.pb(point.value)
    value_kind = value.WhichOneof("value")
    query_sha256 = canonical_sha256(query)
    if query.query_kind is MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS:
        if (
            series.metric_kind != metric_pb2.MetricDescriptor.MetricKind.DELTA
            or series.value_type != metric_pb2.MetricDescriptor.ValueType.INT64
            or value_kind != "int64_value"
        ):
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.RESULT_INVALID
            )
        int64_value = value.int64_value
        if type(int64_value) is not int or not 0 <= int64_value <= MAX_SAFE_INTEGER:
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.RESULT_INVALID
            )
        response_code_class = cast(
            _ResponseCodeClass,
            series.metric.labels["response_code_class"],
        )
        return MonitoringCollectedPoint(
            query_sha256=query_sha256,
            query_kind=query.query_kind,
            interval_started_at=query.window_started_at,
            interval_ended_at=query.window_ended_at,
            response_code_class=response_code_class,
            provider_value_type="INT64",
            int64_value=int64_value,
            provider_double_bits=None,
        )
    if (
        series.metric_kind != metric_pb2.MetricDescriptor.MetricKind.GAUGE
        or series.value_type != metric_pb2.MetricDescriptor.ValueType.DOUBLE
        or value_kind != "double_value"
    ):
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    double_value = value.double_value
    provider_double_bits = struct.pack(">d", double_value).hex()
    if (
        type(double_value) is not float
        or not math.isfinite(double_value)
        or double_value < 0
        or provider_double_bits == _NEGATIVE_ZERO_BINARY64
    ):
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    try:
        return MonitoringCollectedPoint(
            query_sha256=query_sha256,
            query_kind=query.query_kind,
            interval_started_at=query.window_started_at,
            interval_ended_at=query.window_ended_at,
            response_code_class=None,
            provider_value_type="DOUBLE",
            int64_value=None,
            provider_double_bits=provider_double_bits,
        )
    except (TypeError, ValueError):
        raise MonitoringCollectionError(
            MonitoringCollectionErrorCode.RESULT_INVALID
        ) from None


def _validate_series_labels(
    series: monitoring_v3.TimeSeries,
    query: MonitoringMetricQueryV1,
) -> None:
    if series.metric.type != query.metric_type or series.resource.type != _RESOURCE_TYPE:
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    resource_labels = dict(series.resource.labels)
    metric_labels = dict(series.metric.labels)
    if not set(resource_labels).issubset(_RESOURCE_LABELS):
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    expected_resource_labels = {
        "project_id": query.target.project_id,
        "location": query.target.region,
        "service_name": query.target.service_name,
        "configuration_name": query.configuration_name,
        "revision_name": query.candidate_revision,
    }
    if any(
        resource_labels[label] != expected_resource_labels[label]
        for label in resource_labels
    ):
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    if query.query_kind is MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS:
        if (
            not set(metric_labels).issubset(_REQUEST_METRIC_LABELS)
            or metric_labels.get("response_code_class") not in _RESPONSE_CODE_CLASSES
            or ("route" in metric_labels and metric_labels["route"] != "")
        ):
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.RESULT_INVALID
            )
        return
    if not set(metric_labels).issubset(_LATENCY_METRIC_LABELS) or (
        "route" in metric_labels and metric_labels["route"] != ""
    ):
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)


def _validate_provider_interval(
    point: monitoring_v3.Point,
    query: MonitoringMetricQueryV1,
) -> None:
    interval = monitoring_v3.TimeInterval.pb(point.interval)
    if (
        not interval.HasField("end_time")
        or interval.end_time.nanos != 0
        or interval.end_time.seconds != _epoch_seconds(query.window_ended_at)
    ):
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
    if query.query_kind is MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS:
        if (
            not interval.HasField("start_time")
            or interval.start_time.nanos != 0
            or interval.start_time.seconds != _epoch_seconds(query.window_started_at)
        ):
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.RESULT_INVALID
            )
        return
    if interval.HasField("start_time") and (
        interval.start_time.nanos != 0
        or interval.start_time.seconds != interval.end_time.seconds
    ):
        raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)


def _utc_datetime(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _epoch_seconds(value: str) -> int:
    delta = _utc_datetime(value) - datetime(1970, 1, 1, tzinfo=UTC)
    return delta.days * 86_400 + delta.seconds


def _point_order(point: MonitoringCollectedPoint) -> tuple[int, int, str]:
    response_order = (
        _RESPONSE_CODE_ORDER[point.response_code_class]
        if point.response_code_class is not None
        else len(_RESPONSE_CODE_ORDER)
    )
    return (
        response_order,
        point.int64_value if point.int64_value is not None else -1,
        point.provider_double_bits or "",
    )


__all__ = [
    "GoogleCloudMonitoringCollector",
    "MetricServiceClientFactory",
]
