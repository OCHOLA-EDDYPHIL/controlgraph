"""Strict contracts for deterministic Cloud Run health evaluation."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import Field, model_validator

from controlgraph_canary.contracts.base import (
    CloudRunName,
    Identifier,
    NonNegativeSafeInteger,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
    validate_utc_second,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import TargetBinding

ROLLOUT_HEALTH_POLICY_V2: Final = "controlgraph.rollout-health-policy/v2"
MONITORING_METRIC_QUERY_V1: Final = "controlgraph.monitoring-metric-query/v1"
MONITORING_SAMPLE_V1: Final = "controlgraph.monitoring-sample/v1"
MONITORING_DISTRIBUTION_V1: Final = "controlgraph.monitoring-distribution/v1"
MONITORING_WINDOW_OBSERVATION_V1: Final = "controlgraph.monitoring-window-observation/v1"
HEALTH_EVALUATION_STATE_V1: Final = "controlgraph.health-evaluation-state/v1"
HEALTH_DECISION_V1: Final = "controlgraph.health-decision/v1"

_REQUEST_COUNT_METRIC: Final = "run.googleapis.com/request_count"
_REQUEST_LATENCY_METRIC: Final = "run.googleapis.com/request_latencies"
_RESOURCE_TYPE: Final = "cloud_run_revision"
_WINDOW_SECONDS: Final = 60
_OBSERVATION_DELAY_SECONDS: Final = 180
_MAXIMUM_OBSERVATION_DELAY_SECONDS: Final = 300
_MAXIMUM_WINDOWS: Final = 10
_BASIS_POINTS: Final = 10_000
_SAMPLE_SET_DIGEST_DOMAIN: Final = b"controlgraph.monitoring-sample-set/v1\0"
_QUERY_ID_DOMAIN: Final = b"controlgraph.monitoring-query-id/v1\0"
_BINARY64_HEX: Final = re.compile(r"^[0-9a-f]{16}$")
_SHA256_HEX: Final = re.compile(r"^[0-9a-f]{64}$")
_CLOUD_RUN_NAME: Final = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_SAFE_INTEGER: Final = 2**53 - 1


def _validate_root_binding(root_id: str, root_sha256: str) -> None:
    if root_id != f"cgroot:{root_sha256}":
        raise ValueError("health contract root binding is inconsistent")


def monitoring_sample_set_sha256(sample_sha256s: tuple[str, ...]) -> str | None:
    """Return the domain-separated identity of a non-empty canonical sample sequence."""

    if type(sample_sha256s) is not tuple or len(sample_sha256s) > 64:
        raise ValueError("sample digest sequence must be an exact tuple of at most 64 values")
    if any(
        type(sample_sha256) is not str or _SHA256_HEX.fullmatch(sample_sha256) is None
        for sample_sha256 in sample_sha256s
    ):
        raise ValueError("sample digest sequence contains an invalid SHA-256 digest")
    if not sample_sha256s:
        return None
    digest = hashlib.sha256()
    digest.update(_SAMPLE_SET_DIGEST_DOMAIN)
    digest.update(len(sample_sha256s).to_bytes(2, "big"))
    for sample_sha256 in sample_sha256s:
        digest.update(bytes.fromhex(sample_sha256))
    return digest.hexdigest()


def binary64_milliseconds_to_microseconds(provider_double_bits: str) -> int:
    """Convert a non-negative IEEE-754 binary64 millisecond value exactly."""

    if (
        type(provider_double_bits) is not str
        or _BINARY64_HEX.fullmatch(provider_double_bits) is None
    ):
        raise ValueError("provider double bits must be 16 lowercase hexadecimal characters")
    raw = int(provider_double_bits, 16)
    sign = raw >> 63
    exponent = (raw >> 52) & 0x7FF
    fraction = raw & ((1 << 52) - 1)
    if sign or exponent == 0x7FF:
        raise ValueError("provider latency must be a finite non-negative binary64 value")
    if exponent == 0:
        significand = fraction
        exponent_two = -1074
    else:
        significand = (1 << 52) | fraction
        exponent_two = exponent - 1023 - 52
    numerator = significand * 1_000
    denominator = 1
    if exponent_two >= 0:
        numerator <<= exponent_two
    else:
        denominator <<= -exponent_two
    microseconds, remainder = divmod(numerator, denominator)
    doubled_remainder = remainder * 2
    if doubled_remainder > denominator or (
        doubled_remainder == denominator and microseconds % 2 == 1
    ):
        microseconds += 1
    if microseconds > _MAX_SAFE_INTEGER:
        raise ValueError("canonical latency exceeds the safe integer range")
    return microseconds


def derive_monitoring_metric_queries(
    policy: RolloutHealthPolicyV2,
    *,
    target: TargetBinding,
    root_id: str,
    root_sha256: str,
    epoch: int,
    candidate_revision: str,
    window_started_at: str,
    window_ended_at: str,
) -> tuple[MonitoringMetricQueryV1, MonitoringMetricQueryV1]:
    """Derive the two closed Monitoring queries for one bound health window."""

    if type(policy) is not RolloutHealthPolicyV2:
        raise TypeError("an exact rollout health policy is required")
    if type(target) is not TargetBinding:
        raise TypeError("an exact target binding is required")
    if (
        type(root_id) is not str
        or type(root_sha256) is not str
        or _SHA256_HEX.fullmatch(root_sha256) is None
        or root_id != f"cgroot:{root_sha256}"
        or type(epoch) is not int
        or not 1 <= epoch <= _MAX_SAFE_INTEGER
        or type(candidate_revision) is not str
        or _CLOUD_RUN_NAME.fullmatch(candidate_revision) is None
        or type(window_started_at) is not str
        or type(window_ended_at) is not str
    ):
        raise ValueError("monitoring query scope is invalid")
    try:
        validate_utc_second(window_started_at)
        validate_utc_second(window_ended_at)
    except (TypeError, ValueError):
        raise ValueError("monitoring query window is invalid") from None
    if _seconds_between(window_started_at, window_ended_at) != _WINDOW_SECONDS:
        raise ValueError("monitoring query window is invalid")
    if not _is_utc_minute(window_started_at) or not _is_utc_minute(window_ended_at):
        raise ValueError("monitoring query window must align to UTC minutes")
    if not candidate_revision.startswith(f"{target.service_name}-"):
        raise ValueError("monitoring candidate revision is outside the target service")
    validated_policy = RolloutHealthPolicyV2.model_validate(policy)
    policy_sha256 = canonical_sha256(validated_policy)
    query_values: list[MonitoringMetricQueryV1] = []
    for query_kind in MonitoringQueryKind:
        is_latency = query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION
        metric_type = (
            validated_policy.latency_metric_type
            if is_latency
            else validated_policy.request_count_metric_type
        )
        query_values.append(
            MonitoringMetricQueryV1(
                schema_version=MONITORING_METRIC_QUERY_V1,
                query_id=monitoring_query_id(
                    policy_sha256=policy_sha256,
                    target=target,
                    root_sha256=root_sha256,
                    epoch=epoch,
                    candidate_revision=candidate_revision,
                    window_started_at=window_started_at,
                    window_ended_at=window_ended_at,
                    query_kind=query_kind,
                ),
                query_kind=query_kind,
                policy_sha256=policy_sha256,
                target=target,
                root_id=root_id,
                root_sha256=root_sha256,
                epoch=epoch,
                candidate_revision=candidate_revision,
                configuration_name=target.service_name,
                window_started_at=window_started_at,
                window_ended_at=window_ended_at,
                window_semantics=validated_policy.window_semantics,
                provider_interval_semantics=validated_policy.provider_interval_semantics,
                metric_type=metric_type,
                monitored_resource_type=validated_policy.monitored_resource_type,
                unit=(
                    validated_policy.latency_unit if is_latency else validated_policy.request_unit
                ),
                metric_kind="DELTA",
                value_type="DISTRIBUTION" if is_latency else "INT64",
                alignment_period_seconds=validated_policy.alignment_period_seconds,
                primary_per_series_aligner=(
                    validated_policy.latency_primary_per_series_aligner
                    if is_latency
                    else validated_policy.request_per_series_aligner
                ),
                primary_cross_series_reducer=(
                    validated_policy.latency_primary_cross_series_reducer
                    if is_latency
                    else validated_policy.request_cross_series_reducer
                ),
                secondary_per_series_aligner=(
                    validated_policy.latency_secondary_per_series_aligner if is_latency else None
                ),
                secondary_cross_series_reducer=(
                    validated_policy.latency_secondary_cross_series_reducer if is_latency else None
                ),
                secondary_output_metric_kind=(
                    validated_policy.latency_secondary_output_metric_kind if is_latency else None
                ),
                secondary_output_value_type=(
                    validated_policy.latency_secondary_output_value_type if is_latency else None
                ),
                group_by_fields=(() if is_latency else (validated_policy.request_group_by_field,)),
                page_size=validated_policy.page_size,
                view=validated_policy.view,
                order_by=validated_policy.order_by,
                metric_filter=_metric_filter_values(
                    metric_type=metric_type,
                    target=target,
                    configuration_name=target.service_name,
                    candidate_revision=candidate_revision,
                    route_filter=validated_policy.route_filter,
                ),
            )
        )
    return query_values[0], query_values[1]


class HealthSignal(StrEnum):
    """Closed Cloud Monitoring signals admitted by the health policy."""

    TOTAL_REQUESTS = "TOTAL_REQUESTS"
    SUCCESSFUL_2XX_REQUESTS = "SUCCESSFUL_2XX_REQUESTS"
    SERVER_ERROR_5XX_REQUESTS = "SERVER_ERROR_5XX_REQUESTS"
    REQUEST_LATENCY_P95 = "REQUEST_LATENCY_P95"


class MonitoringQueryKind(StrEnum):
    """Closed Monitoring API query profiles used to derive the health signals."""

    REQUEST_COUNT_BY_RESPONSE_CODE_CLASS = "REQUEST_COUNT_BY_RESPONSE_CODE_CLASS"
    REQUEST_LATENCY_DISTRIBUTION = "REQUEST_LATENCY_DISTRIBUTION"


class MonitoringObservationCompleteness(StrEnum):
    """Presence classification for one complete evaluation window."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"


class MonitoringObservationTiming(StrEnum):
    """Retrieval classification relative to the policy's ready and late bounds."""

    EARLY = "EARLY"
    READY = "READY"
    LATE = "LATE"


class HealthDecisionStatus(StrEnum):
    """Closed terminal and non-terminal health decisions."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    WAIT = "wait"
    INSUFFICIENT_EVIDENCE = "insufficient-evidence"


class HealthReasonCode(StrEnum):
    """Stable reasons that a deterministic decision may cite."""

    NO_SAMPLES = "NO_SAMPLES"
    TOO_MANY_WINDOWS = "TOO_MANY_WINDOWS"
    STATE_TERMINAL = "STATE_TERMINAL"
    STATE_SCOPE_MISMATCH = "STATE_SCOPE_MISMATCH"
    SAMPLE_SCOPE_MISMATCH = "SAMPLE_SCOPE_MISMATCH"
    WINDOW_BOUNDARY_INVALID = "WINDOW_BOUNDARY_INVALID"
    WINDOW_OUT_OF_ORDER = "WINDOW_OUT_OF_ORDER"
    WINDOW_DUPLICATE = "WINDOW_DUPLICATE"
    WINDOW_GAP = "WINDOW_GAP"
    WINDOW_NOT_READY = "WINDOW_NOT_READY"
    SAMPLE_EARLY = "SAMPLE_EARLY"
    SAMPLE_LATE = "SAMPLE_LATE"
    SAMPLE_MISSING = "SAMPLE_MISSING"
    SAMPLE_PARTIAL = "SAMPLE_PARTIAL"
    SAMPLE_CONFLICTING_DUPLICATE = "SAMPLE_CONFLICTING_DUPLICATE"
    MINIMUM_REQUESTS_NOT_MET = "MINIMUM_REQUESTS_NOT_MET"
    HEALTHY_THRESHOLDS_MET = "HEALTHY_THRESHOLDS_MET"
    UNHEALTHY_ERROR_RATE = "UNHEALTHY_ERROR_RATE"
    UNHEALTHY_LATENCY = "UNHEALTHY_LATENCY"
    UNHEALTHY_AVAILABILITY = "UNHEALTHY_AVAILABILITY"
    THRESHOLD_INCONCLUSIVE = "THRESHOLD_INCONCLUSIVE"
    HEALTHY_STREAK_PENDING = "HEALTHY_STREAK_PENDING"
    UNHEALTHY_STREAK_PENDING = "UNHEALTHY_STREAK_PENDING"
    HEALTHY_STREAK_MET = "HEALTHY_STREAK_MET"
    UNHEALTHY_STREAK_MET = "UNHEALTHY_STREAK_MET"
    MAXIMUM_WINDOWS_EXHAUSTED = "MAXIMUM_WINDOWS_EXHAUSTED"


_INSUFFICIENT_REASONS: Final = frozenset(
    {
        HealthReasonCode.NO_SAMPLES,
        HealthReasonCode.TOO_MANY_WINDOWS,
        HealthReasonCode.STATE_TERMINAL,
        HealthReasonCode.STATE_SCOPE_MISMATCH,
        HealthReasonCode.SAMPLE_SCOPE_MISMATCH,
        HealthReasonCode.WINDOW_BOUNDARY_INVALID,
        HealthReasonCode.WINDOW_OUT_OF_ORDER,
        HealthReasonCode.WINDOW_GAP,
        HealthReasonCode.SAMPLE_LATE,
        HealthReasonCode.SAMPLE_MISSING,
        HealthReasonCode.SAMPLE_PARTIAL,
        HealthReasonCode.SAMPLE_CONFLICTING_DUPLICATE,
        HealthReasonCode.MINIMUM_REQUESTS_NOT_MET,
    }
)


class RolloutHealthPolicyV2(StrictContractModel):
    """Frozen metrics, windows, thresholds, hysteresis, and fail-safe actions."""

    schema_version: Literal["controlgraph.rollout-health-policy/v2"]
    observation_schema_version: Literal["controlgraph.monitoring-window-observation/v1"]
    decision_schema_version: Literal["controlgraph.health-decision/v1"]
    monitored_resource_type: Literal["cloud_run_revision"]
    request_count_metric_type: Literal["run.googleapis.com/request_count"]
    successful_response_code_class: Literal["2xx"]
    server_error_response_code_class: Literal["5xx"]
    latency_metric_type: Literal["run.googleapis.com/request_latencies"]
    request_unit: Literal["1"]
    latency_unit: Literal["ms"]
    latency_source_conversion: Literal[
        "IEEE_754_BINARY64_MILLISECONDS_TO_INTEGER_MICROSECONDS_TIES_TO_EVEN"
    ]
    alignment_period_seconds: Literal[60]
    request_per_series_aligner: Literal["ALIGN_SUM"]
    request_cross_series_reducer: Literal["REDUCE_SUM"]
    request_group_by_field: Literal["metric.labels.response_code_class"]
    total_request_definition: Literal["SUM_1XX_2XX_3XX_4XX_5XX"]
    availability_definition: Literal["SUCCESSFUL_2XX_OVER_TOTAL_REQUESTS"]
    server_error_rate_definition: Literal["SERVER_ERROR_5XX_OVER_TOTAL_REQUESTS"]
    latency_definition: Literal["MERGED_DISTRIBUTION_PERCENTILE_95"]
    latency_primary_per_series_aligner: Literal["ALIGN_SUM"]
    latency_primary_cross_series_reducer: Literal["REDUCE_SUM"]
    latency_secondary_per_series_aligner: Literal["ALIGN_PERCENTILE_95"]
    latency_secondary_cross_series_reducer: Literal["REDUCE_NONE"]
    latency_secondary_output_metric_kind: Literal["GAUGE"]
    latency_secondary_output_value_type: Literal["DOUBLE"]
    latency_rounding: Literal["CEILING_TO_INTEGER_MILLISECOND"]
    configuration_name_source: Literal["TARGET_SERVICE_NAME"]
    route_filter: Literal[""]
    provider_interval_semantics: Literal["START_EXCLUSIVE_END_INCLUSIVE"]
    page_size: Literal[1_000]
    view: Literal["FULL"]
    order_by: None
    window_seconds: Literal[60]
    window_semantics: Literal["HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE"]
    observation_delay_seconds: Literal[180]
    maximum_observation_delay_seconds: Literal[300]
    minimum_request_count: Literal[100]
    healthy_maximum_error_rate_basis_points: Literal[100]
    unhealthy_minimum_error_rate_basis_points: Literal[500]
    healthy_maximum_p95_latency_ms: Literal[500]
    unhealthy_minimum_p95_latency_ms: Literal[1_000]
    healthy_minimum_availability_basis_points: Literal[9_900]
    unhealthy_maximum_availability_basis_points: Literal[9_500]
    error_rate_rounding: Literal["CEILING_BASIS_POINTS"]
    availability_rate_rounding: Literal["FLOOR_BASIS_POINTS"]
    healthy_consecutive_windows: Literal[2]
    unhealthy_consecutive_windows: Literal[2]
    maximum_windows: Literal[10]
    early_observation_action: Literal["WAIT"]
    missing_observation_action: Literal["INSUFFICIENT_EVIDENCE"]
    partial_observation_action: Literal["INSUFFICIENT_EVIDENCE"]
    late_observation_action: Literal["INSUFFICIENT_EVIDENCE"]
    malformed_observation_action: Literal["INSUFFICIENT_EVIDENCE"]
    unknown_response_code_class_action: Literal["INSUFFICIENT_EVIDENCE"]
    identical_duplicate_action: Literal["DEDUPLICATE_BY_SAMPLE_SHA256"]
    conflicting_duplicate_action: Literal["INSUFFICIENT_EVIDENCE"]
    sample_set_digest_domain: Literal["controlgraph.monitoring-sample-set/v1"]
    sample_set_digest_algorithm: Literal["SHA256_DOMAIN_NUL_UINT16_COUNT_ORDERED_32_BYTE_DIGESTS"]
    out_of_order_action: Literal["INSUFFICIENT_EVIDENCE"]
    boundary_sample_action: Literal["INCLUDE_START_EXCLUDE_END"]


def create_rollout_health_policy_v2() -> RolloutHealthPolicyV2:
    """Return the one frozen V2 policy admitted for newly created rollout roots."""

    return RolloutHealthPolicyV2(
        schema_version=ROLLOUT_HEALTH_POLICY_V2,
        observation_schema_version=MONITORING_WINDOW_OBSERVATION_V1,
        decision_schema_version=HEALTH_DECISION_V1,
        monitored_resource_type=_RESOURCE_TYPE,
        request_count_metric_type=_REQUEST_COUNT_METRIC,
        successful_response_code_class="2xx",
        server_error_response_code_class="5xx",
        latency_metric_type=_REQUEST_LATENCY_METRIC,
        request_unit="1",
        latency_unit="ms",
        latency_source_conversion=(
            "IEEE_754_BINARY64_MILLISECONDS_TO_INTEGER_MICROSECONDS_TIES_TO_EVEN"
        ),
        alignment_period_seconds=_WINDOW_SECONDS,
        request_per_series_aligner="ALIGN_SUM",
        request_cross_series_reducer="REDUCE_SUM",
        request_group_by_field="metric.labels.response_code_class",
        total_request_definition="SUM_1XX_2XX_3XX_4XX_5XX",
        availability_definition="SUCCESSFUL_2XX_OVER_TOTAL_REQUESTS",
        server_error_rate_definition="SERVER_ERROR_5XX_OVER_TOTAL_REQUESTS",
        latency_definition="MERGED_DISTRIBUTION_PERCENTILE_95",
        latency_primary_per_series_aligner="ALIGN_SUM",
        latency_primary_cross_series_reducer="REDUCE_SUM",
        latency_secondary_per_series_aligner="ALIGN_PERCENTILE_95",
        latency_secondary_cross_series_reducer="REDUCE_NONE",
        latency_secondary_output_metric_kind="GAUGE",
        latency_secondary_output_value_type="DOUBLE",
        latency_rounding="CEILING_TO_INTEGER_MILLISECOND",
        configuration_name_source="TARGET_SERVICE_NAME",
        route_filter="",
        provider_interval_semantics="START_EXCLUSIVE_END_INCLUSIVE",
        page_size=1_000,
        view="FULL",
        order_by=None,
        window_seconds=_WINDOW_SECONDS,
        window_semantics="HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE",
        observation_delay_seconds=_OBSERVATION_DELAY_SECONDS,
        maximum_observation_delay_seconds=_MAXIMUM_OBSERVATION_DELAY_SECONDS,
        minimum_request_count=100,
        healthy_maximum_error_rate_basis_points=100,
        unhealthy_minimum_error_rate_basis_points=500,
        healthy_maximum_p95_latency_ms=500,
        unhealthy_minimum_p95_latency_ms=1_000,
        healthy_minimum_availability_basis_points=9_900,
        unhealthy_maximum_availability_basis_points=9_500,
        error_rate_rounding="CEILING_BASIS_POINTS",
        availability_rate_rounding="FLOOR_BASIS_POINTS",
        healthy_consecutive_windows=2,
        unhealthy_consecutive_windows=2,
        maximum_windows=_MAXIMUM_WINDOWS,
        early_observation_action="WAIT",
        missing_observation_action="INSUFFICIENT_EVIDENCE",
        partial_observation_action="INSUFFICIENT_EVIDENCE",
        late_observation_action="INSUFFICIENT_EVIDENCE",
        malformed_observation_action="INSUFFICIENT_EVIDENCE",
        unknown_response_code_class_action="INSUFFICIENT_EVIDENCE",
        identical_duplicate_action="DEDUPLICATE_BY_SAMPLE_SHA256",
        conflicting_duplicate_action="INSUFFICIENT_EVIDENCE",
        sample_set_digest_domain="controlgraph.monitoring-sample-set/v1",
        sample_set_digest_algorithm=(
            "SHA256_DOMAIN_NUL_UINT16_COUNT_ORDERED_32_BYTE_DIGESTS"
        ),
        out_of_order_action="INSUFFICIENT_EVIDENCE",
        boundary_sample_action="INCLUDE_START_EXCLUDE_END",
    )


class MonitoringMetricQueryV1(StrictContractModel):
    """One exact, target-bound Cloud Monitoring query for a health window."""

    schema_version: Literal["controlgraph.monitoring-metric-query/v1"]
    query_id: Identifier
    query_kind: MonitoringQueryKind
    policy_sha256: Sha256Digest
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    candidate_revision: CloudRunName
    configuration_name: CloudRunName
    window_started_at: UtcSecond
    window_ended_at: UtcSecond
    window_semantics: Literal["HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE"]
    provider_interval_semantics: Literal["START_EXCLUSIVE_END_INCLUSIVE"]
    metric_type: Literal[
        "run.googleapis.com/request_count",
        "run.googleapis.com/request_latencies",
    ]
    monitored_resource_type: Literal["cloud_run_revision"]
    unit: Literal["1", "ms"]
    metric_kind: Literal["DELTA"]
    value_type: Literal["INT64", "DISTRIBUTION"]
    alignment_period_seconds: Literal[60]
    primary_per_series_aligner: Literal["ALIGN_SUM"]
    primary_cross_series_reducer: Literal["REDUCE_SUM"]
    secondary_per_series_aligner: Literal["ALIGN_PERCENTILE_95"] | None
    secondary_cross_series_reducer: Literal["REDUCE_NONE"] | None
    secondary_output_metric_kind: Literal["GAUGE"] | None
    secondary_output_value_type: Literal["DOUBLE"] | None
    group_by_fields: Annotated[tuple[str, ...], Field(max_length=1)]
    page_size: Literal[1_000]
    view: Literal["FULL"]
    order_by: None
    metric_filter: Annotated[str, Field(min_length=1, max_length=2_048)]

    @model_validator(mode="after")
    def validate_query(self) -> Self:
        _validate_root_binding(self.root_id, self.root_sha256)
        if _seconds_between(self.window_started_at, self.window_ended_at) != _WINDOW_SECONDS:
            raise ValueError("monitoring query must cover one exact 60-second window")
        if not _is_utc_minute(self.window_started_at) or not _is_utc_minute(self.window_ended_at):
            raise ValueError("monitoring query window must align to UTC minutes")
        expected = _query_semantics(self.query_kind)
        actual = (
            self.metric_type,
            self.unit,
            self.value_type,
            self.primary_per_series_aligner,
            self.primary_cross_series_reducer,
            self.secondary_per_series_aligner,
            self.secondary_cross_series_reducer,
            self.secondary_output_metric_kind,
            self.secondary_output_value_type,
            self.group_by_fields,
        )
        if actual != expected:
            raise ValueError("monitoring query semantics do not match its signal")
        if self.metric_filter != _metric_filter(self):
            raise ValueError("monitoring metric filter is not the exact target-bound filter")
        if self.configuration_name != self.target.service_name:
            raise ValueError("monitoring configuration name must match the target service")
        if not self.candidate_revision.startswith(f"{self.target.service_name}-"):
            raise ValueError("monitoring candidate revision is outside the target service")
        expected_query_id = monitoring_query_id(
            policy_sha256=self.policy_sha256,
            target=self.target,
            root_sha256=self.root_sha256,
            epoch=self.epoch,
            candidate_revision=self.candidate_revision,
            window_started_at=self.window_started_at,
            window_ended_at=self.window_ended_at,
            query_kind=self.query_kind,
        )
        if self.query_id != expected_query_id:
            raise ValueError("monitoring query id does not match its canonical scope")
        return self


class MonitoringSampleV1(StrictContractModel):
    """One canonical value returned by an exact Monitoring query."""

    schema_version: Literal["controlgraph.monitoring-sample/v1"]
    query_sha256: Sha256Digest
    query_kind: MonitoringQueryKind
    window_started_at: UtcSecond
    window_ended_at: UtcSecond
    response_code_class: Literal["1xx", "2xx", "3xx", "4xx", "5xx"] | None
    provider_value_type: Literal["INT64", "DOUBLE"]
    provider_double_bits: Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")] | None
    unit: Literal["1", "us"]
    int64_value: NonNegativeSafeInteger | None
    latency_microseconds: NonNegativeSafeInteger | None

    @model_validator(mode="after")
    def validate_sample(self) -> Self:
        if _seconds_between(self.window_started_at, self.window_ended_at) != _WINDOW_SECONDS:
            raise ValueError("monitoring sample must cover one exact 60-second window")
        if self.query_kind is MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS:
            if (
                self.response_code_class is None
                or self.provider_value_type != "INT64"
                or self.unit != "1"
                or self.provider_double_bits is not None
                or self.int64_value is None
                or self.latency_microseconds is not None
            ):
                raise ValueError("request-count sample shape is invalid")
        elif (
            self.response_code_class is not None
            or self.provider_value_type != "DOUBLE"
            or self.provider_double_bits is None
            or self.unit != "us"
            or self.int64_value is not None
            or self.latency_microseconds is None
        ):
            raise ValueError("latency sample shape is invalid")
        if (
            self.provider_double_bits is not None
            and self.latency_microseconds
            != binary64_milliseconds_to_microseconds(self.provider_double_bits)
        ):
            raise ValueError("latency sample is not the canonical binary64 conversion")
        return self


class MonitoringDistributionV1(StrictContractModel):
    """Canonical percentile projection of one Monitoring latency distribution."""

    schema_version: Literal["controlgraph.monitoring-distribution/v1"]
    sample_count: NonNegativeSafeInteger
    p95_latency_ms: NonNegativeSafeInteger
    percentile_basis_points: Literal[9_500]
    unit: Literal["ms"]
    rounding: Literal["CEILING_TO_INTEGER_MILLISECOND"]
    source_sample_sha256s: Annotated[tuple[Sha256Digest, ...], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def validate_distribution(self) -> Self:
        if len(set(self.source_sample_sha256s)) != len(self.source_sample_sha256s):
            raise ValueError("latency source sample digests must be unique")
        if self.sample_count == 0 and self.p95_latency_ms != 0:
            raise ValueError("an empty latency distribution cannot have a percentile")
        return self


class MonitoringWindowObservationV1(StrictContractModel):
    """Canonical four-signal observation for one target-bound health window."""

    schema_version: Literal["controlgraph.monitoring-window-observation/v1"]
    observation_id: Identifier
    policy_schema_version: Literal["controlgraph.rollout-health-policy/v2"]
    policy_sha256: Sha256Digest
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    candidate_revision: CloudRunName
    observation_started_at: UtcSecond
    window_index: Annotated[int, Field(ge=1, le=10)]
    window_started_at: UtcSecond
    window_ended_at: UtcSecond
    observed_at: UtcSecond
    queries: Annotated[tuple[MonitoringMetricQueryV1, ...], Field(min_length=2, max_length=2)]
    query_sha256s: Annotated[tuple[Sha256Digest, ...], Field(min_length=2, max_length=2)]
    samples: Annotated[tuple[MonitoringSampleV1, ...], Field(max_length=64)]
    sample_sha256s: Annotated[tuple[Sha256Digest, ...], Field(max_length=64)]
    source_sample_sha256s: Annotated[tuple[Sha256Digest, ...], Field(max_length=64)]
    completeness: MonitoringObservationCompleteness
    timing: MonitoringObservationTiming
    missing_signals: Annotated[tuple[HealthSignal, ...], Field(max_length=4)]
    duplicate_count: Annotated[int, Field(ge=0, le=64)]
    conflicting_duplicate: bool
    request_count: NonNegativeSafeInteger | None
    response_1xx_count: NonNegativeSafeInteger | None
    successful_request_count: NonNegativeSafeInteger | None
    response_3xx_count: NonNegativeSafeInteger | None
    response_4xx_count: NonNegativeSafeInteger | None
    server_error_count: NonNegativeSafeInteger | None
    latency_distribution: MonitoringDistributionV1 | None

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        _validate_root_binding(self.root_id, self.root_sha256)
        if _seconds_between(self.window_started_at, self.window_ended_at) != _WINDOW_SECONDS:
            raise ValueError("health observation must cover one exact 60-second window")
        if _seconds_between(self.window_ended_at, self.observed_at) < 0:
            raise ValueError("health observation cannot precede its window end")
        expected_start = _add_seconds(
            self.observation_started_at,
            (self.window_index - 1) * _WINDOW_SECONDS,
        )
        if self.window_started_at != expected_start:
            raise ValueError("health observation window is not contiguous with its root interval")
        expected_query_kinds = tuple(MonitoringQueryKind)
        if tuple(query.query_kind for query in self.queries) != expected_query_kinds:
            raise ValueError("health observation queries must use the closed query order")
        expected_digests = tuple(canonical_sha256(query) for query in self.queries)
        if self.query_sha256s != expected_digests:
            raise ValueError("health observation query digests do not match its queries")
        if len(set(self.query_sha256s)) != len(self.query_sha256s):
            raise ValueError("health observation query digests must be unique")
        for query in self.queries:
            if (
                query.policy_sha256 != self.policy_sha256
                or query.target != self.target
                or query.root_id != self.root_id
                or query.root_sha256 != self.root_sha256
                or query.epoch != self.epoch
                or query.candidate_revision != self.candidate_revision
                or query.window_started_at != self.window_started_at
                or query.window_ended_at != self.window_ended_at
            ):
                raise ValueError("health observation query is outside its exact scope")
        expected_timing = _observation_timing(self.window_ended_at, self.observed_at)
        if self.timing is not expected_timing:
            raise ValueError("health observation timing classification is incorrect")
        expected_signals = tuple(HealthSignal)
        signal_values = (
            self.request_count,
            self.successful_request_count,
            self.server_error_count,
            self.latency_distribution,
        )
        absent = tuple(
            signal
            for signal, value in zip(expected_signals, signal_values, strict=True)
            if value is None
        )
        expected_completeness = (
            MonitoringObservationCompleteness.COMPLETE
            if not absent
            else (
                MonitoringObservationCompleteness.MISSING
                if len(absent) == len(expected_signals)
                else MonitoringObservationCompleteness.PARTIAL
            )
        )
        if self.completeness is not expected_completeness or self.missing_signals != absent:
            raise ValueError("health observation completeness classification is incorrect")
        expected_sample_digests = tuple(canonical_sha256(sample) for sample in self.samples)
        if self.sample_sha256s != expected_sample_digests:
            raise ValueError("health observation sample digests do not match its samples")
        if len(set(self.sample_sha256s)) != len(self.sample_sha256s):
            raise ValueError("health observation sample digests must be unique")
        if self.source_sample_sha256s != tuple(sorted(self.source_sample_sha256s)):
            raise ValueError("health observation source sample digests are not canonical")
        selected_sample_digests = set(self.sample_sha256s)
        source_sample_digests = set(self.source_sample_sha256s)
        if not selected_sample_digests.issubset(source_sample_digests):
            raise ValueError("health observation source samples omit a selected sample")
        if self.duplicate_count != len(self.source_sample_sha256s) - len(self.sample_sha256s):
            raise ValueError("health observation duplicate count does not match its sources")
        if self.conflicting_duplicate != (source_sample_digests != selected_sample_digests):
            raise ValueError("health observation conflict classification is incorrect")
        self._validate_samples_and_aggregates()
        return self

    def _validate_samples_and_aggregates(self) -> None:
        query_by_digest = {
            digest: query for digest, query in zip(self.query_sha256s, self.queries, strict=True)
        }
        request_samples: dict[str, MonitoringSampleV1] = {}
        latency_samples: list[MonitoringSampleV1] = []
        previous_order = -1
        response_order = {"1xx": 0, "2xx": 1, "3xx": 2, "4xx": 3, "5xx": 4}
        for sample in self.samples:
            query = query_by_digest.get(sample.query_sha256)
            if query is None or query.query_kind is not sample.query_kind:
                raise ValueError("monitoring sample does not match an observation query")
            if (
                sample.window_started_at != self.window_started_at
                or sample.window_ended_at != self.window_ended_at
            ):
                raise ValueError("monitoring sample is outside its observation window")
            if sample.query_kind is MonitoringQueryKind.REQUEST_COUNT_BY_RESPONSE_CODE_CLASS:
                response_code_class = sample.response_code_class
                assert response_code_class is not None
                order = response_order[response_code_class]
                if response_code_class in request_samples:
                    raise ValueError("response-code class samples must be unique")
                request_samples[response_code_class] = sample
            else:
                order = len(response_order)
                latency_samples.append(sample)
            if order <= previous_order:
                raise ValueError("monitoring samples are not in canonical order")
            previous_order = order

        request_missing = {
            HealthSignal.TOTAL_REQUESTS,
            HealthSignal.SUCCESSFUL_2XX_REQUESTS,
            HealthSignal.SERVER_ERROR_5XX_REQUESTS,
        }.issubset(self.missing_signals)
        if (
            any(
                signal in self.missing_signals
                for signal in (
                    HealthSignal.TOTAL_REQUESTS,
                    HealthSignal.SUCCESSFUL_2XX_REQUESTS,
                    HealthSignal.SERVER_ERROR_5XX_REQUESTS,
                )
            )
            != request_missing
        ):
            raise ValueError("grouped request signals must be missing together")
        latency_missing = HealthSignal.REQUEST_LATENCY_P95 in self.missing_signals

        if request_missing:
            if request_samples or any(
                value is not None
                for value in (
                    self.request_count,
                    self.response_1xx_count,
                    self.successful_request_count,
                    self.response_3xx_count,
                    self.response_4xx_count,
                    self.server_error_count,
                )
            ):
                raise ValueError("missing request query cannot contain request aggregates")
        else:
            if not request_samples:
                raise ValueError("complete request query requires a response-code class sample")
            counts = {
                response_class: _request_sample_value(sample)
                for response_class in response_order
                for sample in (request_samples.get(response_class),)
            }
            expected_request_aggregates = (
                sum(counts.values()),
                counts["1xx"],
                counts["2xx"],
                counts["3xx"],
                counts["4xx"],
                counts["5xx"],
            )
            if (
                self.request_count,
                self.response_1xx_count,
                self.successful_request_count,
                self.response_3xx_count,
                self.response_4xx_count,
                self.server_error_count,
            ) != expected_request_aggregates:
                raise ValueError("request aggregates do not match canonical request samples")

        if latency_missing:
            if latency_samples or self.latency_distribution is not None:
                raise ValueError("missing latency query cannot contain a latency aggregate")
        else:
            if len(latency_samples) != 1:
                raise ValueError("latency query requires one canonical percentile sample")
            latency_sample = latency_samples[0]
            assert latency_sample.latency_microseconds is not None
            latency_digest = canonical_sha256(latency_sample)
            expected_distribution = MonitoringDistributionV1(
                schema_version=MONITORING_DISTRIBUTION_V1,
                sample_count=1,
                p95_latency_ms=(latency_sample.latency_microseconds + 999) // 1_000,
                percentile_basis_points=9_500,
                unit="ms",
                rounding="CEILING_TO_INTEGER_MILLISECOND",
                source_sample_sha256s=(latency_digest,),
            )
            if self.latency_distribution != expected_distribution:
                raise ValueError("latency aggregate does not match its canonical sample")


def _request_sample_value(sample: MonitoringSampleV1 | None) -> int:
    if sample is None:
        return 0
    assert sample.int64_value is not None
    return sample.int64_value


class HealthEvaluationStateV1(StrictContractModel):
    """Root-bound hysteresis and window-continuity state."""

    schema_version: Literal["controlgraph.health-evaluation-state/v1"]
    policy_schema_version: Literal["controlgraph.rollout-health-policy/v2"]
    policy_sha256: Sha256Digest
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    candidate_revision: CloudRunName
    observation_started_at: UtcSecond
    last_window_ended_at: UtcSecond | None
    consecutive_healthy_windows: Annotated[int, Field(ge=0, le=10)]
    consecutive_unhealthy_windows: Annotated[int, Field(ge=0, le=10)]
    evaluated_windows: Annotated[int, Field(ge=0, le=10)]
    last_observation_sha256: Sha256Digest | None
    consumed_sample_set_sha256s: Annotated[tuple[Sha256Digest, ...], Field(max_length=10)]
    prior_decision_sha256: Sha256Digest | None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        _validate_root_binding(self.root_id, self.root_sha256)
        if self.consecutive_healthy_windows and self.consecutive_unhealthy_windows:
            raise ValueError("healthy and unhealthy streaks cannot both be active")
        if len(set(self.consumed_sample_set_sha256s)) != len(self.consumed_sample_set_sha256s):
            raise ValueError("consumed sample-set digests must be unique")
        if len(self.consumed_sample_set_sha256s) > self.evaluated_windows:
            raise ValueError("consumed sample-set digests cannot exceed evaluated windows")
        if (
            max(
                self.consecutive_healthy_windows,
                self.consecutive_unhealthy_windows,
            )
            > self.evaluated_windows
        ):
            raise ValueError("health streak cannot exceed evaluated windows")
        if self.evaluated_windows == 0:
            if (
                self.last_window_ended_at is not None
                or self.last_observation_sha256 is not None
                or self.consumed_sample_set_sha256s
            ):
                raise ValueError("initial health state cannot cite a prior evaluation")
        elif self.last_window_ended_at is None or self.last_observation_sha256 is None:
            raise ValueError("evaluated health state requires its last window and observation")
        elif self.last_window_ended_at != _add_seconds(
            self.observation_started_at,
            self.evaluated_windows * _WINDOW_SECONDS,
        ):
            raise ValueError("evaluated health state is not contiguous with its root interval")
        return self


class HealthDecisionV1(StrictContractModel):
    """Canonical decision with complete policy, sample, aggregate, and state citations."""

    schema_version: Literal["controlgraph.health-decision/v1"]
    decision_id: Identifier
    status: HealthDecisionStatus
    reason_codes: Annotated[tuple[HealthReasonCode, ...], Field(min_length=1, max_length=16)]
    policy_schema_version: Literal["controlgraph.rollout-health-policy/v2"]
    policy_sha256: Sha256Digest
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    candidate_revision: CloudRunName
    prior_state_sha256: Sha256Digest
    next_state: HealthEvaluationStateV1
    observation_sha256: Sha256Digest | None
    query_sha256s: Annotated[tuple[Sha256Digest, ...], Field(max_length=2)]
    sample_sha256s: Annotated[tuple[Sha256Digest, ...], Field(max_length=64)]
    window_started_at: UtcSecond | None
    window_ended_at: UtcSecond | None
    request_count: NonNegativeSafeInteger | None
    successful_request_count: NonNegativeSafeInteger | None
    server_error_count: NonNegativeSafeInteger | None
    error_rate_basis_points: Annotated[int, Field(ge=0, le=10_000)] | None
    availability_basis_points: Annotated[int, Field(ge=0, le=10_000)] | None
    p95_latency_ms: NonNegativeSafeInteger | None
    evaluated_at: UtcSecond
    next_evaluation_at: UtcSecond | None

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        _validate_root_binding(self.root_id, self.root_sha256)
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("health decision reason codes must be unique")
        if len(set(self.query_sha256s)) != len(self.query_sha256s):
            raise ValueError("health decision query digests must be unique")
        if len(set(self.sample_sha256s)) != len(self.sample_sha256s):
            raise ValueError("health decision sample digests must be unique")
        if (
            self.next_evaluation_at is not None
            and _seconds_between(self.evaluated_at, self.next_evaluation_at) < 0
        ):
            raise ValueError("next health evaluation cannot precede this decision")
        state = self.next_state
        if (
            state.policy_sha256 != self.policy_sha256
            or state.target != self.target
            or state.root_id != self.root_id
            or state.root_sha256 != self.root_sha256
            or state.epoch != self.epoch
            or state.candidate_revision != self.candidate_revision
        ):
            raise ValueError("health decision state is outside its exact scope")
        window_values = (self.window_started_at, self.window_ended_at)
        if (window_values[0] is None) != (window_values[1] is None):
            raise ValueError("health decision window bounds must be present together")
        aggregate_values = (
            self.request_count,
            self.successful_request_count,
            self.server_error_count,
            self.error_rate_basis_points,
            self.availability_basis_points,
            self.p95_latency_ms,
        )
        aggregate_present = tuple(value is not None for value in aggregate_values)
        if any(aggregate_present) and not all(aggregate_present):
            raise ValueError("health decision aggregates must be present together")
        if all(aggregate_present):
            request_count = self.request_count
            successful_count = self.successful_request_count
            server_error_count = self.server_error_count
            assert request_count is not None
            assert successful_count is not None
            assert server_error_count is not None
            if request_count == 0:
                raise ValueError("health decision rates require at least one request")
            if successful_count + server_error_count > request_count:
                raise ValueError("health decision request classes cannot overlap")
            if self.availability_basis_points != successful_count * _BASIS_POINTS // request_count:
                raise ValueError("health decision availability aggregate is not canonical")
            expected_error_rate = (
                server_error_count * _BASIS_POINTS + request_count - 1
            ) // request_count
            if self.error_rate_basis_points != expected_error_rate:
                raise ValueError("health decision error-rate aggregate is not canonical")
        if self.observation_sha256 is None:
            if (
                self.query_sha256s
                or self.sample_sha256s
                or any(aggregate_present)
                or any(value is not None for value in window_values)
            ):
                raise ValueError("uncited health decision cannot contain observation data")
        else:
            if len(self.query_sha256s) != len(tuple(MonitoringQueryKind)):
                raise ValueError("cited health decision requires all query digests")
            if any(value is None for value in window_values):
                raise ValueError("cited health decision requires its observation window")
            if (
                state.last_observation_sha256 == self.observation_sha256
                and state.last_window_ended_at != self.window_ended_at
            ):
                raise ValueError("health decision state cites an inconsistent observation window")
        self._validate_status_semantics(all(aggregate_present))
        return self

    def _validate_status_semantics(self, aggregates_present: bool) -> None:
        healthy_reasons = (
            HealthReasonCode.HEALTHY_THRESHOLDS_MET,
            HealthReasonCode.HEALTHY_STREAK_MET,
        )
        healthy_pending_reasons = (
            HealthReasonCode.HEALTHY_THRESHOLDS_MET,
            HealthReasonCode.HEALTHY_STREAK_PENDING,
        )
        derived_unhealthy = self._derived_unhealthy_reasons() if aggregates_present else ()
        unhealthy_reasons = (*derived_unhealthy, HealthReasonCode.UNHEALTHY_STREAK_MET)
        unhealthy_pending_reasons = (
            *derived_unhealthy,
            HealthReasonCode.UNHEALTHY_STREAK_PENDING,
        )
        consumed = (
            self.observation_sha256 is not None
            and self.next_state.last_observation_sha256 == self.observation_sha256
            and self.next_state.last_window_ended_at == self.window_ended_at
        )

        if self.status is HealthDecisionStatus.HEALTHY:
            if self.reason_codes != healthy_reasons:
                raise ValueError("healthy decision requires canonical healthy terminal reasons")
            if not aggregates_present or self.observation_sha256 is None or not consumed:
                raise ValueError("healthy decision requires consumed cited aggregates")
            self._validate_threshold_evidence()
            if not self._healthy_thresholds_met():
                raise ValueError("healthy decision aggregates do not meet healthy thresholds")
            if (
                self.next_state.consecutive_healthy_windows < 2
                or self.next_state.consecutive_unhealthy_windows != 0
            ):
                raise ValueError("healthy decision requires its healthy streak")
            if self.next_evaluation_at is not None:
                raise ValueError("terminal health decision cannot schedule another evaluation")
            return

        if self.status is HealthDecisionStatus.UNHEALTHY:
            if not derived_unhealthy or self.reason_codes != unhealthy_reasons:
                raise ValueError("unhealthy decision requires canonical unhealthy terminal reasons")
            if not aggregates_present or self.observation_sha256 is None or not consumed:
                raise ValueError("unhealthy decision requires consumed cited aggregates")
            self._validate_threshold_evidence()
            if (
                self.next_state.consecutive_unhealthy_windows < 2
                or self.next_state.consecutive_healthy_windows != 0
            ):
                raise ValueError("unhealthy decision requires its unhealthy streak")
            if self.next_evaluation_at is not None:
                raise ValueError("terminal health decision cannot schedule another evaluation")
            return

        terminal_streak_reasons = {
            HealthReasonCode.HEALTHY_STREAK_MET,
            HealthReasonCode.UNHEALTHY_STREAK_MET,
        }
        if terminal_streak_reasons.intersection(self.reason_codes):
            raise ValueError("non-terminal decision cannot cite a terminal streak reason")

        if self.status is HealthDecisionStatus.WAIT:
            if self.next_evaluation_at is None:
                raise ValueError("wait decision must schedule another evaluation")
            if self.reason_codes in (
                (HealthReasonCode.WINDOW_NOT_READY,),
                (HealthReasonCode.SAMPLE_EARLY,),
            ):
                return
            if self.reason_codes == (HealthReasonCode.WINDOW_DUPLICATE,):
                sample_set_sha256 = monitoring_sample_set_sha256(self.sample_sha256s)
                if self.observation_sha256 is None or not (
                    consumed
                    or (
                        sample_set_sha256 is not None
                        and sample_set_sha256 in self.next_state.consumed_sample_set_sha256s
                    )
                ):
                    raise ValueError(
                        "duplicate-window decision requires its prior observation citation"
                    )
                return
            if self.reason_codes == healthy_pending_reasons:
                if not aggregates_present or not consumed or not self._healthy_thresholds_met():
                    raise ValueError(
                        "healthy pending decision requires consumed healthy aggregates"
                    )
                self._validate_threshold_evidence()
                if (
                    self.next_state.consecutive_healthy_windows != 1
                    or self.next_state.consecutive_unhealthy_windows != 0
                ):
                    raise ValueError("healthy pending decision requires its pending streak")
                return
            if derived_unhealthy and self.reason_codes == unhealthy_pending_reasons:
                if not aggregates_present or not consumed:
                    raise ValueError("unhealthy pending decision requires consumed aggregates")
                self._validate_threshold_evidence()
                if (
                    self.next_state.consecutive_unhealthy_windows != 1
                    or self.next_state.consecutive_healthy_windows != 0
                ):
                    raise ValueError("unhealthy pending decision requires its pending streak")
                return
            if self.reason_codes == (HealthReasonCode.THRESHOLD_INCONCLUSIVE,):
                if (
                    not aggregates_present
                    or not consumed
                    or self._healthy_thresholds_met()
                    or derived_unhealthy
                ):
                    raise ValueError("inconclusive decision requires consumed wait-band aggregates")
                self._validate_threshold_evidence()
                if (
                    self.next_state.consecutive_healthy_windows != 0
                    or self.next_state.consecutive_unhealthy_windows != 0
                ):
                    raise ValueError("inconclusive decision must reset health streaks")
                return
            raise ValueError("wait decision reasons are not canonical")

        if self.reason_codes == (HealthReasonCode.STATE_TERMINAL,):
            if (
                self.next_state.consecutive_healthy_windows < 2
                and self.next_state.consecutive_unhealthy_windows < 2
            ):
                raise ValueError("terminal-state decision requires a terminal streak")
            if self.observation_sha256 is not None:
                raise ValueError("terminal-state decision cannot cite a current observation")
            if self.next_evaluation_at is not None:
                raise ValueError("terminal-state decision cannot schedule another evaluation")
            return

        if self.reason_codes[-1] is HealthReasonCode.MAXIMUM_WINDOWS_EXHAUSTED:
            if self.next_evaluation_at is not None:
                raise ValueError("maximum-windows decision cannot schedule another evaluation")
            if self.next_state.evaluated_windows != _MAXIMUM_WINDOWS:
                raise ValueError("maximum-windows decision requires an exhausted state")
            threshold_reasons = self.reason_codes[:-1]
            valid_threshold_reasons = (
                (HealthReasonCode.HEALTHY_THRESHOLDS_MET,)
                if aggregates_present and self._healthy_thresholds_met()
                else derived_unhealthy
                if aggregates_present and derived_unhealthy
                else (HealthReasonCode.THRESHOLD_INCONCLUSIVE,)
                if aggregates_present
                else ()
            )
            if threshold_reasons and threshold_reasons != valid_threshold_reasons:
                raise ValueError("maximum-windows threshold reasons are not canonical")
            if threshold_reasons and not consumed:
                raise ValueError("maximum-windows threshold decision must consume its observation")
            if threshold_reasons:
                self._validate_threshold_evidence()
        elif len(self.reason_codes) != 1 or self.reason_codes[0] not in _INSUFFICIENT_REASONS:
            raise ValueError("insufficient-evidence decision reasons are not canonical")

    def _validate_threshold_evidence(self) -> None:
        assert self.request_count is not None
        assert self.window_started_at is not None
        assert self.window_ended_at is not None
        if self.request_count < 100:
            raise ValueError("threshold decision requires the policy minimum request count")
        if len(self.sample_sha256s) < 2:
            raise ValueError("threshold decision requires request and latency sample citations")
        if _seconds_between(self.window_started_at, self.window_ended_at) != _WINDOW_SECONDS:
            raise ValueError("threshold decision requires one exact 60-second window")

    def _healthy_thresholds_met(self) -> bool:
        assert self.request_count is not None
        assert self.successful_request_count is not None
        assert self.server_error_count is not None
        assert self.p95_latency_ms is not None
        return (
            self.server_error_count * _BASIS_POINTS <= 100 * self.request_count
            and self.p95_latency_ms <= 500
            and self.successful_request_count * _BASIS_POINTS >= 9_900 * self.request_count
        )

    def _derived_unhealthy_reasons(self) -> tuple[HealthReasonCode, ...]:
        assert self.request_count is not None
        assert self.successful_request_count is not None
        assert self.server_error_count is not None
        assert self.p95_latency_ms is not None
        reasons: list[HealthReasonCode] = []
        if self.server_error_count * _BASIS_POINTS >= 500 * self.request_count:
            reasons.append(HealthReasonCode.UNHEALTHY_ERROR_RATE)
        if self.p95_latency_ms >= 1_000:
            reasons.append(HealthReasonCode.UNHEALTHY_LATENCY)
        if self.successful_request_count * _BASIS_POINTS <= 9_500 * self.request_count:
            reasons.append(HealthReasonCode.UNHEALTHY_AVAILABILITY)
        return tuple(reasons)


def _seconds_between(start: str, end: str) -> int:
    return int(
        (
            datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
            - datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
        ).total_seconds()
    )


def _is_utc_minute(value: str) -> bool:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").second == 0


def _add_seconds(value: str, seconds: int) -> str:
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ") + timedelta(seconds=seconds)
    except OverflowError as exc:
        raise ValueError("health timestamp exceeds the UTC calendar range") from exc
    return result.strftime("%Y-%m-%dT%H:%M:%SZ")


def _query_semantics(
    query_kind: MonitoringQueryKind,
) -> tuple[
    str,
    str,
    str,
    str,
    str,
    str | None,
    str | None,
    str | None,
    str | None,
    tuple[str, ...],
]:
    if query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
        return (
            _REQUEST_LATENCY_METRIC,
            "ms",
            "DISTRIBUTION",
            "ALIGN_SUM",
            "REDUCE_SUM",
            "ALIGN_PERCENTILE_95",
            "REDUCE_NONE",
            "GAUGE",
            "DOUBLE",
            (),
        )
    return (
        _REQUEST_COUNT_METRIC,
        "1",
        "INT64",
        "ALIGN_SUM",
        "REDUCE_SUM",
        None,
        None,
        None,
        None,
        ("metric.labels.response_code_class",),
    )


def _metric_filter_values(
    *,
    metric_type: str,
    target: TargetBinding,
    configuration_name: str,
    candidate_revision: str,
    route_filter: str,
) -> str:
    clauses = [
        f'metric.type="{metric_type}"',
        f'resource.type="{_RESOURCE_TYPE}"',
        f'resource.labels.project_id="{target.project_id}"',
        f'resource.labels.location="{target.region}"',
        f'resource.labels.service_name="{target.service_name}"',
        f'resource.labels.configuration_name="{configuration_name}"',
        f'resource.labels.revision_name="{candidate_revision}"',
        f'metric.labels.route="{route_filter}"',
    ]
    return " AND ".join(clauses)


def _metric_filter(query: MonitoringMetricQueryV1) -> str:
    return _metric_filter_values(
        metric_type=query.metric_type,
        target=query.target,
        configuration_name=query.configuration_name,
        candidate_revision=query.candidate_revision,
        route_filter="",
    )


def monitoring_query_id(
    *,
    policy_sha256: str,
    target: TargetBinding,
    root_sha256: str,
    epoch: int,
    candidate_revision: str,
    window_started_at: str,
    window_ended_at: str,
    query_kind: MonitoringQueryKind,
) -> str:
    digest = hashlib.sha256()
    digest.update(_QUERY_ID_DOMAIN)
    components = (
        policy_sha256,
        target.project_id,
        target.region,
        target.environment,
        target.service_name,
        root_sha256,
        str(epoch),
        candidate_revision,
        window_started_at,
        window_ended_at,
        query_kind.value,
    )
    for component in components:
        encoded = component.encode("utf-8")
        digest.update(len(encoded).to_bytes(2, "big"))
        digest.update(encoded)
    return f"cgmonq:{digest.hexdigest()}"


def _observation_timing(window_ended_at: str, observed_at: str) -> MonitoringObservationTiming:
    ready_at = _add_seconds(window_ended_at, _OBSERVATION_DELAY_SECONDS)
    late_after = _add_seconds(window_ended_at, _MAXIMUM_OBSERVATION_DELAY_SECONDS)
    if observed_at < ready_at:
        return MonitoringObservationTiming.EARLY
    if observed_at > late_after:
        return MonitoringObservationTiming.LATE
    return MonitoringObservationTiming.READY


__all__ = [
    "HEALTH_DECISION_V1",
    "HEALTH_EVALUATION_STATE_V1",
    "MONITORING_DISTRIBUTION_V1",
    "MONITORING_METRIC_QUERY_V1",
    "MONITORING_SAMPLE_V1",
    "MONITORING_WINDOW_OBSERVATION_V1",
    "ROLLOUT_HEALTH_POLICY_V2",
    "HealthDecisionStatus",
    "HealthDecisionV1",
    "HealthEvaluationStateV1",
    "HealthReasonCode",
    "HealthSignal",
    "MonitoringDistributionV1",
    "MonitoringMetricQueryV1",
    "MonitoringObservationCompleteness",
    "MonitoringObservationTiming",
    "MonitoringQueryKind",
    "MonitoringSampleV1",
    "MonitoringWindowObservationV1",
    "RolloutHealthPolicyV2",
    "binary64_milliseconds_to_microseconds",
    "create_rollout_health_policy_v2",
    "derive_monitoring_metric_queries",
    "monitoring_query_id",
    "monitoring_sample_set_sha256",
]
