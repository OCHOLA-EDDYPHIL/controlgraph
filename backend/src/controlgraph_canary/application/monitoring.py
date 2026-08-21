"""Provider-neutral collection of canonical rollout health observations."""

from __future__ import annotations

import asyncio
import hashlib
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from controlgraph_canary.contracts.base import MAX_SAFE_INTEGER, validate_utc_second
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.health import (
    MONITORING_DISTRIBUTION_V1,
    MONITORING_SAMPLE_V1,
    MONITORING_WINDOW_OBSERVATION_V1,
    HealthSignal,
    MonitoringDistributionV1,
    MonitoringMetricQueryV1,
    MonitoringObservationCompleteness,
    MonitoringObservationTiming,
    MonitoringQueryKind,
    MonitoringSampleV1,
    MonitoringWindowObservationV1,
    RolloutHealthPolicyV2,
    binary64_milliseconds_to_microseconds,
    derive_monitoring_metric_queries,
)
from controlgraph_canary.contracts.models import TargetBinding

type ResponseCodeClass = Literal["1xx", "2xx", "3xx", "4xx", "5xx"]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BINARY64 = re.compile(r"^[0-9a-f]{16}$")
_WINDOW_SECONDS = 60
_MAXIMUM_POINTS = 64
_OBSERVATION_ID_DOMAIN = b"controlgraph.monitoring-observation-id/v1\0"
_RESPONSE_CODE_ORDER: tuple[ResponseCodeClass, ...] = (
    "1xx",
    "2xx",
    "3xx",
    "4xx",
    "5xx",
)


class MonitoringCollectionErrorCode(StrEnum):
    """Stable, payload-free monitoring collection failures."""

    CONFIGURATION_INVALID = "MONITORING_COLLECTION_CONFIGURATION_INVALID"
    WINDOW_INVALID = "MONITORING_COLLECTION_WINDOW_INVALID"
    QUERY_TIMEOUT = "MONITORING_COLLECTION_QUERY_TIMEOUT"
    QUERY_UNAVAILABLE = "MONITORING_COLLECTION_QUERY_UNAVAILABLE"
    RESULT_INVALID = "MONITORING_COLLECTION_RESULT_INVALID"
    CLOCK_INVALID = "MONITORING_COLLECTION_CLOCK_INVALID"


class MonitoringCollectionError(RuntimeError):
    """One sanitized failure containing no provider response material."""

    def __init__(self, code: MonitoringCollectionErrorCode) -> None:
        if type(code) is not MonitoringCollectionErrorCode:
            raise TypeError("an exact monitoring collection error code is required")
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class MonitoringCollectionScope:
    """Immutable root, policy, target, and interval binding for health collection."""

    policy: RolloutHealthPolicyV2
    target: TargetBinding
    root_id: str
    root_sha256: str
    epoch: int
    candidate_revision: str
    observation_started_at: str

    def __post_init__(self) -> None:
        if type(self.policy) is not RolloutHealthPolicyV2 or type(self.target) is not TargetBinding:
            raise ValueError("monitoring collection scope is invalid")
        try:
            window_started_at, window_ended_at = _window_bounds(
                self.observation_started_at,
                1,
            )
            derive_monitoring_metric_queries(
                self.policy,
                target=self.target,
                root_id=self.root_id,
                root_sha256=self.root_sha256,
                epoch=self.epoch,
                candidate_revision=self.candidate_revision,
                window_started_at=window_started_at,
                window_ended_at=window_ended_at,
            )
        except (TypeError, ValueError):
            raise ValueError("monitoring collection scope is invalid") from None


@dataclass(frozen=True, slots=True)
class MonitoringCollectedPoint:
    """One SDK-free aggregate point returned for an exact derived query."""

    query_sha256: str
    query_kind: MonitoringQueryKind
    interval_started_at: str
    interval_ended_at: str
    response_code_class: ResponseCodeClass | None
    provider_value_type: Literal["INT64", "DOUBLE"]
    int64_value: int | None
    provider_double_bits: str | None

    def __post_init__(self) -> None:
        if type(self.interval_started_at) is not str or type(self.interval_ended_at) is not str:
            raise ValueError("monitoring point interval is invalid")
        try:
            validate_utc_second(self.interval_started_at)
            validate_utc_second(self.interval_ended_at)
        except (TypeError, ValueError):
            raise ValueError("monitoring point interval is invalid") from None
        if (
            type(self.query_sha256) is not str
            or _SHA256.fullmatch(self.query_sha256) is None
            or type(self.query_kind) is not MonitoringQueryKind
            or _seconds_between(self.interval_started_at, self.interval_ended_at) != _WINDOW_SECONDS
        ):
            raise ValueError("monitoring point query binding is invalid")
        if self.query_kind is MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS:
            if (
                type(self.response_code_class) is not str
                or self.response_code_class not in _RESPONSE_CODE_ORDER
                or type(self.provider_value_type) is not str
                or self.provider_value_type != "INT64"
                or type(self.int64_value) is not int
                or not 0 <= self.int64_value <= MAX_SAFE_INTEGER
                or self.provider_double_bits is not None
            ):
                raise ValueError("monitoring request point is invalid")
            return
        if (
            self.response_code_class is not None
            or type(self.provider_value_type) is not str
            or self.provider_value_type != "DOUBLE"
            or self.int64_value is not None
            or type(self.provider_double_bits) is not str
            or _BINARY64.fullmatch(self.provider_double_bits) is None
        ):
            raise ValueError("monitoring latency point is invalid")
        try:
            binary64_milliseconds_to_microseconds(self.provider_double_bits)
        except ValueError:
            raise ValueError("monitoring latency point is invalid") from None


@dataclass(frozen=True, slots=True)
class MonitoringQueryCollection:
    """Bounded point sequence returned for one exact Monitoring query."""

    query_sha256: str
    query_kind: MonitoringQueryKind
    points: tuple[MonitoringCollectedPoint, ...]

    def __post_init__(self) -> None:
        if (
            type(self.query_sha256) is not str
            or _SHA256.fullmatch(self.query_sha256) is None
            or type(self.query_kind) is not MonitoringQueryKind
            or type(self.points) is not tuple
            or len(self.points) > _MAXIMUM_POINTS
        ):
            raise ValueError("monitoring query collection is invalid")
        if any(
            type(point) is not MonitoringCollectedPoint
            or point.query_sha256 != self.query_sha256
            or point.query_kind is not self.query_kind
            for point in self.points
        ):
            raise ValueError("monitoring query collection point binding is invalid")


@runtime_checkable
class MonitoringQueryCollector(Protocol):
    """Read-only provider port for one already-derived metric query."""

    async def collect(
        self,
        query: MonitoringMetricQueryV1,
        *,
        timeout_seconds: float,
    ) -> MonitoringQueryCollection: ...


@dataclass(frozen=True, slots=True)
class MonitoringCollectionResult:
    """Canonical observation plus its cross-boundary content digest."""

    observation: MonitoringWindowObservationV1
    observation_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.observation) is not MonitoringWindowObservationV1
            or type(self.observation_sha256) is not str
            or _SHA256.fullmatch(self.observation_sha256) is None
            or canonical_sha256(self.observation) != self.observation_sha256
        ):
            raise ValueError("monitoring collection result is invalid")


class MonitoringWindowCollector:
    """Collect and canonicalize one closed window without deriving a health decision."""

    def __init__(
        self,
        *,
        scope: MonitoringCollectionScope,
        query_collector: MonitoringQueryCollector,
        query_timeout_seconds: float = 10.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(scope) is not MonitoringCollectionScope:
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.CONFIGURATION_INVALID)
        try:
            collect = query_collector.collect
        except Exception:
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.CONFIGURATION_INVALID
            ) from None
        if not callable(collect) or (
            type(query_timeout_seconds) not in {int, float}
            or not math.isfinite(query_timeout_seconds)
            or not 0 < query_timeout_seconds <= 30
        ):
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.CONFIGURATION_INVALID)
        if clock is not None and not callable(clock):
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.CONFIGURATION_INVALID)
        self._scope = scope
        self._query_collector = query_collector
        self._query_timeout_seconds = float(query_timeout_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))

    async def collect(self, window_index: int) -> MonitoringCollectionResult:
        """Return one deterministic observation or a stable sanitized failure."""

        if (
            type(window_index) is not int
            or not 1 <= window_index <= self._scope.policy.maximum_windows
        ):
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.WINDOW_INVALID)
        try:
            window_started_at, window_ended_at = _window_bounds(
                self._scope.observation_started_at,
                window_index,
            )
            queries = derive_monitoring_metric_queries(
                self._scope.policy,
                target=self._scope.target,
                root_id=self._scope.root_id,
                root_sha256=self._scope.root_sha256,
                epoch=self._scope.epoch,
                candidate_revision=self._scope.candidate_revision,
                window_started_at=window_started_at,
                window_ended_at=window_ended_at,
            )
        except (TypeError, ValueError):
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.WINDOW_INVALID) from None

        collections: list[MonitoringQueryCollection] = []
        for query in queries:
            collections.append(await self._collect_query(query))
        if sum(len(collection.points) for collection in collections) > _MAXIMUM_POINTS:
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)

        try:
            observed_at = _clock_utc_second(self._clock)
        except Exception:
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.CLOCK_INVALID) from None
        if _seconds_between(window_ended_at, observed_at) < 0:
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.CLOCK_INVALID)

        try:
            (
                samples,
                source_sample_sha256s,
                duplicate_count,
                conflicting_duplicate,
            ) = _canonical_samples(queries, (collections[0], collections[1]))
            observation = _build_observation(
                scope=self._scope,
                window_index=window_index,
                window_started_at=window_started_at,
                window_ended_at=window_ended_at,
                observed_at=observed_at,
                queries=queries,
                samples=samples,
                source_sample_sha256s=source_sample_sha256s,
                duplicate_count=duplicate_count,
                conflicting_duplicate=conflicting_duplicate,
            )
            return MonitoringCollectionResult(
                observation=observation,
                observation_sha256=canonical_sha256(observation),
            )
        except (TypeError, ValueError):
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID) from None

    async def _collect_query(
        self,
        query: MonitoringMetricQueryV1,
    ) -> MonitoringQueryCollection:
        try:
            async with asyncio.timeout(self._query_timeout_seconds):
                result = await self._query_collector.collect(
                    query,
                    timeout_seconds=self._query_timeout_seconds,
                )
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.QUERY_TIMEOUT) from None
        except MonitoringCollectionError:
            raise
        except Exception:
            raise MonitoringCollectionError(
                MonitoringCollectionErrorCode.QUERY_UNAVAILABLE
            ) from None
        if (
            type(result) is not MonitoringQueryCollection
            or result.query_sha256 != canonical_sha256(query)
            or result.query_kind is not query.query_kind
            or any(
                point.interval_started_at != query.window_started_at
                or point.interval_ended_at != query.window_ended_at
                for point in result.points
            )
        ):
            raise MonitoringCollectionError(MonitoringCollectionErrorCode.RESULT_INVALID)
        return result


def _canonical_samples(
    queries: tuple[MonitoringMetricQueryV1, MonitoringMetricQueryV1],
    collections: tuple[MonitoringQueryCollection, MonitoringQueryCollection],
) -> tuple[tuple[MonitoringSampleV1, ...], tuple[str, ...], int, bool]:
    sample_groups: dict[
        tuple[MonitoringQueryKind, ResponseCodeClass | None],
        list[MonitoringSampleV1],
    ] = {}
    source_sample_sha256s: list[str] = []
    for query, collection in zip(queries, collections, strict=True):
        for point in collection.points:
            sample = _canonical_sample(query, point)
            source_sample_sha256s.append(canonical_sha256(sample))
            slot = (sample.query_kind, sample.response_code_class)
            sample_groups.setdefault(slot, []).append(sample)

    selected: list[MonitoringSampleV1] = []
    duplicate_count = 0
    conflicting_duplicate = False
    canonical_slots = (
        *(
            (MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS, response_code_class)
            for response_code_class in _RESPONSE_CODE_ORDER
        ),
        (MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION, None),
    )
    for slot in canonical_slots:
        slot_samples = sample_groups.get(slot, [])
        if not slot_samples:
            continue
        duplicate_count += len(slot_samples) - 1
        samples_by_digest: dict[str, MonitoringSampleV1] = {}
        for sample in slot_samples:
            sample_sha256 = canonical_sha256(sample)
            previous = samples_by_digest.get(sample_sha256)
            if previous is None or canonical_json_bytes(sample) < canonical_json_bytes(previous):
                samples_by_digest[sample_sha256] = sample
        if len(samples_by_digest) > 1:
            conflicting_duplicate = True
        selected.append(
            min(
                samples_by_digest.values(),
                key=canonical_json_bytes,
            )
        )
    return (
        tuple(selected),
        tuple(sorted(source_sample_sha256s)),
        duplicate_count,
        conflicting_duplicate,
    )


def _canonical_sample(
    query: MonitoringMetricQueryV1,
    point: MonitoringCollectedPoint,
) -> MonitoringSampleV1:
    is_latency = query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
    provider_double_bits = point.provider_double_bits if is_latency else None
    return MonitoringSampleV1(
        schema_version=MONITORING_SAMPLE_V1,
        query_sha256=canonical_sha256(query),
        query_kind=query.query_kind,
        window_started_at=query.window_started_at,
        window_ended_at=query.window_ended_at,
        response_code_class=None if is_latency else point.response_code_class,
        provider_value_type="DOUBLE" if is_latency else "INT64",
        provider_double_bits=provider_double_bits,
        unit="us" if is_latency else "1",
        int64_value=None if is_latency else point.int64_value,
        latency_microseconds=(
            binary64_milliseconds_to_microseconds(provider_double_bits)
            if provider_double_bits is not None
            else None
        ),
    )


def _build_observation(
    *,
    scope: MonitoringCollectionScope,
    window_index: int,
    window_started_at: str,
    window_ended_at: str,
    observed_at: str,
    queries: tuple[MonitoringMetricQueryV1, MonitoringMetricQueryV1],
    samples: tuple[MonitoringSampleV1, ...],
    source_sample_sha256s: tuple[str, ...],
    duplicate_count: int,
    conflicting_duplicate: bool,
) -> MonitoringWindowObservationV1:
    query_sha256s = tuple(canonical_sha256(query) for query in queries)
    sample_sha256s = tuple(canonical_sha256(sample) for sample in samples)
    request_samples = {
        sample.response_code_class: sample
        for sample in samples
        if sample.query_kind is MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS
    }
    latency_sample = next(
        (
            sample
            for sample in samples
            if sample.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
        ),
        None,
    )
    request_present = bool(request_samples)
    counts: dict[ResponseCodeClass, int] = {
        response_code_class: _request_sample_count(request_samples.get(response_code_class))
        for response_code_class in _RESPONSE_CODE_ORDER
    }
    request_count = sum(counts.values()) if request_present else None
    latency_distribution = _latency_distribution(latency_sample)
    signal_values = (
        request_count,
        counts["2xx"] if request_present else None,
        counts["5xx"] if request_present else None,
        latency_distribution,
    )
    missing_signals = tuple(
        signal
        for signal, value in zip(tuple(HealthSignal), signal_values, strict=True)
        if value is None
    )
    completeness = (
        MonitoringObservationCompleteness.COMPLETE
        if not missing_signals
        else (
            MonitoringObservationCompleteness.MISSING
            if len(missing_signals) == len(tuple(HealthSignal))
            else MonitoringObservationCompleteness.PARTIAL
        )
    )
    timing = _observation_timing(scope.policy, window_ended_at, observed_at)
    observation_id = _observation_id(
        scope=scope,
        window_index=window_index,
        window_started_at=window_started_at,
        window_ended_at=window_ended_at,
        observed_at=observed_at,
        query_sha256s=query_sha256s,
        sample_sha256s=sample_sha256s,
        source_sample_sha256s=source_sample_sha256s,
        duplicate_count=duplicate_count,
        conflicting_duplicate=conflicting_duplicate,
    )
    return MonitoringWindowObservationV1(
        schema_version=MONITORING_WINDOW_OBSERVATION_V1,
        observation_id=observation_id,
        policy_schema_version=scope.policy.schema_version,
        policy_sha256=canonical_sha256(scope.policy),
        target=scope.target,
        root_id=scope.root_id,
        root_sha256=scope.root_sha256,
        epoch=scope.epoch,
        candidate_revision=scope.candidate_revision,
        observation_started_at=scope.observation_started_at,
        window_index=window_index,
        window_started_at=window_started_at,
        window_ended_at=window_ended_at,
        observed_at=observed_at,
        queries=queries,
        query_sha256s=query_sha256s,
        samples=samples,
        sample_sha256s=sample_sha256s,
        source_sample_sha256s=source_sample_sha256s,
        completeness=completeness,
        timing=timing,
        missing_signals=missing_signals,
        duplicate_count=duplicate_count,
        conflicting_duplicate=conflicting_duplicate,
        request_count=request_count,
        response_1xx_count=counts["1xx"] if request_present else None,
        successful_request_count=counts["2xx"] if request_present else None,
        response_3xx_count=counts["3xx"] if request_present else None,
        response_4xx_count=counts["4xx"] if request_present else None,
        server_error_count=counts["5xx"] if request_present else None,
        latency_distribution=latency_distribution,
    )


def _latency_distribution(
    sample: MonitoringSampleV1 | None,
) -> MonitoringDistributionV1 | None:
    if sample is None:
        return None
    latency_microseconds = sample.latency_microseconds
    if latency_microseconds is None:
        raise ValueError("monitoring latency sample is invalid")
    return MonitoringDistributionV1(
        schema_version=MONITORING_DISTRIBUTION_V1,
        sample_count=1,
        p95_latency_ms=(latency_microseconds + 999) // 1_000,
        percentile_basis_points=9_500,
        unit="ms",
        rounding="CEILING_TO_INTEGER_MILLISECOND",
        source_sample_sha256s=(canonical_sha256(sample),),
    )


def _request_sample_count(sample: MonitoringSampleV1 | None) -> int:
    if sample is None:
        return 0
    if sample.int64_value is None:
        raise ValueError("monitoring request sample is invalid")
    return sample.int64_value


def _observation_timing(
    policy: RolloutHealthPolicyV2,
    window_ended_at: str,
    observed_at: str,
) -> MonitoringObservationTiming:
    elapsed = _seconds_between(window_ended_at, observed_at)
    if elapsed < policy.observation_delay_seconds:
        return MonitoringObservationTiming.EARLY
    if elapsed > policy.maximum_observation_delay_seconds:
        return MonitoringObservationTiming.LATE
    return MonitoringObservationTiming.READY


def _observation_id(
    *,
    scope: MonitoringCollectionScope,
    window_index: int,
    window_started_at: str,
    window_ended_at: str,
    observed_at: str,
    query_sha256s: tuple[str, ...],
    sample_sha256s: tuple[str, ...],
    source_sample_sha256s: tuple[str, ...],
    duplicate_count: int,
    conflicting_duplicate: bool,
) -> str:
    digest = hashlib.sha256()
    digest.update(_OBSERVATION_ID_DOMAIN)
    components = (
        canonical_sha256(scope.policy),
        scope.root_sha256,
        str(scope.epoch),
        scope.candidate_revision,
        scope.observation_started_at,
        str(window_index),
        window_started_at,
        window_ended_at,
        observed_at,
        *query_sha256s,
        *sample_sha256s,
        *source_sample_sha256s,
        str(duplicate_count),
        "true" if conflicting_duplicate else "false",
    )
    for component in components:
        encoded = component.encode("utf-8")
        digest.update(len(encoded).to_bytes(2, "big"))
        digest.update(encoded)
    return f"cgobs:{digest.hexdigest()}"


def _window_bounds(observation_started_at: str, window_index: int) -> tuple[str, str]:
    if type(observation_started_at) is not str:
        raise ValueError("monitoring interval start is invalid")
    validate_utc_second(observation_started_at)
    started = datetime.strptime(observation_started_at, "%Y-%m-%dT%H:%M:%SZ")
    try:
        window_started = started + timedelta(seconds=(window_index - 1) * _WINDOW_SECONDS)
        window_ended = window_started + timedelta(seconds=_WINDOW_SECONDS)
    except OverflowError as error:
        raise ValueError("monitoring window exceeds the UTC calendar range") from error
    return (
        window_started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        window_ended.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _clock_utc_second(clock: Callable[[], datetime]) -> str:
    value = clock()
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("monitoring clock is invalid")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seconds_between(start: str, end: str) -> int:
    return int(
        (
            datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
            - datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
        ).total_seconds()
    )


__all__ = [
    "MonitoringCollectedPoint",
    "MonitoringCollectionError",
    "MonitoringCollectionErrorCode",
    "MonitoringCollectionResult",
    "MonitoringCollectionScope",
    "MonitoringQueryCollection",
    "MonitoringQueryCollector",
    "MonitoringWindowCollector",
]
