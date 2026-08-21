"""Pure deterministic evaluation of canonical canary health windows."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from enum import StrEnum

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WILDCARD_CHARACTERS = frozenset("*?[]")
_BASIS_POINTS = 10_000
_MAX_WINDOWS = 10
_MAX_SAFE_INTEGER = 2**53 - 1
_SAMPLE_SET_DIGEST_DOMAIN = b"controlgraph.monitoring-sample-set/v1\0"


class HealthDecisionKind(StrEnum):
    """Closed outcomes emitted by the health evaluator."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    WAIT = "wait"
    INSUFFICIENT_EVIDENCE = "insufficient-evidence"


class HealthReason(StrEnum):
    """Stable reasons for one deterministic health decision."""

    NO_SAMPLES = "NO_SAMPLES"
    TOO_MANY_WINDOWS = "TOO_MANY_WINDOWS"
    STATE_SCOPE_MISMATCH = "STATE_SCOPE_MISMATCH"
    STATE_TERMINAL = "STATE_TERMINAL"
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


def _require_identifier(name: str, value: object) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must not be blank")
    if any(character in value for character in _WILDCARD_CHARACTERS):
        raise ValueError(f"{name} must not contain wildcards")


def _require_digest(name: str, value: object) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _require_int(name: str, value: object, *, minimum: int, maximum: int) -> None:
    if type(value) is not int or value < minimum or value > maximum:
        raise ValueError(f"{name} must be an integer from {minimum} through {maximum}")


def _require_bool(name: str, value: object) -> None:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a bool")


def _require_root_binding(root_id: str, root_sha256: str) -> None:
    if root_id != f"cgroot:{root_sha256}":
        raise ValueError("root_id must bind root_sha256")


def _sample_set_sha256(sample_sha256s: tuple[str, ...]) -> str | None:
    if not sample_sha256s:
        return None
    digest = hashlib.sha256()
    digest.update(_SAMPLE_SET_DIGEST_DOMAIN)
    digest.update(len(sample_sha256s).to_bytes(2, "big"))
    for sample_sha256 in sample_sha256s:
        digest.update(bytes.fromhex(sample_sha256))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class HealthPolicy:
    """Frozen target binding, window rules, thresholds, and hysteresis."""

    policy_version: str
    policy_sha256: str
    project_id: str
    region: str
    environment: str
    service_name: str
    root_id: str
    root_sha256: str
    epoch: int
    candidate_revision: str
    observation_started_at: int
    window_seconds: int
    observation_delay_seconds: int
    maximum_observation_delay_seconds: int
    minimum_request_count: int
    healthy_maximum_error_rate_basis_points: int
    unhealthy_minimum_error_rate_basis_points: int
    healthy_maximum_p95_latency_ms: int
    unhealthy_minimum_p95_latency_ms: int
    healthy_minimum_availability_basis_points: int
    unhealthy_maximum_availability_basis_points: int
    healthy_consecutive_windows: int
    unhealthy_consecutive_windows: int
    maximum_windows: int = _MAX_WINDOWS

    def __post_init__(self) -> None:
        for name in (
            "policy_version",
            "project_id",
            "region",
            "environment",
            "service_name",
            "root_id",
            "candidate_revision",
        ):
            _require_identifier(name, getattr(self, name))
        _require_digest("policy_sha256", self.policy_sha256)
        _require_digest("root_sha256", self.root_sha256)
        _require_root_binding(self.root_id, self.root_sha256)
        _require_int("epoch", self.epoch, minimum=1, maximum=_MAX_SAFE_INTEGER)
        _require_int(
            "observation_started_at",
            self.observation_started_at,
            minimum=0,
            maximum=_MAX_SAFE_INTEGER,
        )
        _require_int("window_seconds", self.window_seconds, minimum=1, maximum=86_400)
        _require_int(
            "observation_delay_seconds",
            self.observation_delay_seconds,
            minimum=0,
            maximum=86_400,
        )
        _require_int(
            "maximum_observation_delay_seconds",
            self.maximum_observation_delay_seconds,
            minimum=0,
            maximum=86_400,
        )
        if self.maximum_observation_delay_seconds < self.observation_delay_seconds:
            raise ValueError("maximum observation delay cannot precede the earliest observation")
        _require_int(
            "minimum_request_count",
            self.minimum_request_count,
            minimum=1,
            maximum=_MAX_SAFE_INTEGER,
        )
        for name in (
            "healthy_maximum_error_rate_basis_points",
            "unhealthy_minimum_error_rate_basis_points",
            "healthy_minimum_availability_basis_points",
            "unhealthy_maximum_availability_basis_points",
        ):
            _require_int(name, getattr(self, name), minimum=0, maximum=_BASIS_POINTS)
        _require_int(
            "healthy_maximum_p95_latency_ms",
            self.healthy_maximum_p95_latency_ms,
            minimum=0,
            maximum=_MAX_SAFE_INTEGER,
        )
        _require_int(
            "unhealthy_minimum_p95_latency_ms",
            self.unhealthy_minimum_p95_latency_ms,
            minimum=0,
            maximum=_MAX_SAFE_INTEGER,
        )
        for name in ("healthy_consecutive_windows", "unhealthy_consecutive_windows"):
            _require_int(name, getattr(self, name), minimum=1, maximum=64)
        _require_int("maximum_windows", self.maximum_windows, minimum=1, maximum=_MAX_WINDOWS)
        if (
            self.observation_started_at
            + self.maximum_windows * self.window_seconds
            + self.maximum_observation_delay_seconds
            > _MAX_SAFE_INTEGER
        ):
            raise ValueError("health policy window horizon exceeds the safe timestamp range")
        if (
            self.healthy_consecutive_windows > self.maximum_windows
            or self.unhealthy_consecutive_windows > self.maximum_windows
        ):
            raise ValueError("health streak requirements cannot exceed maximum windows")
        if (
            self.healthy_maximum_error_rate_basis_points
            >= self.unhealthy_minimum_error_rate_basis_points
        ):
            raise ValueError("healthy and unhealthy error thresholds must leave a wait band")
        if self.healthy_maximum_p95_latency_ms >= self.unhealthy_minimum_p95_latency_ms:
            raise ValueError("healthy and unhealthy latency thresholds must leave a wait band")
        if (
            self.unhealthy_maximum_availability_basis_points
            >= self.healthy_minimum_availability_basis_points
        ):
            raise ValueError("healthy and unhealthy availability thresholds must leave a wait band")


@dataclass(frozen=True, slots=True)
class HealthWindowSample:
    """One canonical aggregate for a target-bound half-open window."""

    observation_sha256: str
    query_sha256s: tuple[str, ...]
    sample_sha256s: tuple[str, ...]
    policy_sha256: str
    project_id: str
    region: str
    environment: str
    service_name: str
    root_id: str
    root_sha256: str
    epoch: int
    candidate_revision: str
    observation_started_at: int
    window_index: int
    window_started_at: int
    window_ended_at: int
    observed_at: int
    request_count: int
    response_1xx_count: int
    successful_request_count: int
    response_3xx_count: int
    response_4xx_count: int
    server_error_count: int
    p95_latency_ms: int
    complete: bool
    missing: bool
    duplicate_count: int
    conflicting_duplicate: bool

    def __post_init__(self) -> None:
        _require_digest("observation_sha256", self.observation_sha256)
        if type(self.query_sha256s) is not tuple or len(self.query_sha256s) != 2:
            raise ValueError("query_sha256s must contain the two policy query digests")
        if type(self.sample_sha256s) is not tuple or len(self.sample_sha256s) > 64:
            raise ValueError("sample_sha256s must contain at most 64 source digests")
        for digest in self.query_sha256s:
            _require_digest("query_sha256s", digest)
        for digest in self.sample_sha256s:
            _require_digest("sample_sha256s", digest)
        if len(set(self.query_sha256s)) != len(self.query_sha256s):
            raise ValueError("query digests must be unique")
        if len(set(self.sample_sha256s)) != len(self.sample_sha256s):
            raise ValueError("sample digests must be unique")
        _require_digest("policy_sha256", self.policy_sha256)
        for name in (
            "project_id",
            "region",
            "environment",
            "service_name",
            "root_id",
            "candidate_revision",
        ):
            _require_identifier(name, getattr(self, name))
        _require_digest("root_sha256", self.root_sha256)
        _require_root_binding(self.root_id, self.root_sha256)
        _require_int("epoch", self.epoch, minimum=1, maximum=_MAX_SAFE_INTEGER)
        for name in (
            "observation_started_at",
            "window_started_at",
            "window_ended_at",
            "observed_at",
        ):
            _require_int(name, getattr(self, name), minimum=0, maximum=_MAX_SAFE_INTEGER)
        _require_int("window_index", self.window_index, minimum=1, maximum=_MAX_SAFE_INTEGER)
        for name in (
            "request_count",
            "response_1xx_count",
            "successful_request_count",
            "response_3xx_count",
            "response_4xx_count",
            "server_error_count",
            "p95_latency_ms",
            "duplicate_count",
        ):
            _require_int(name, getattr(self, name), minimum=0, maximum=_MAX_SAFE_INTEGER)
        _require_bool("complete", self.complete)
        _require_bool("missing", self.missing)
        _require_bool("conflicting_duplicate", self.conflicting_duplicate)
        if self.complete and self.missing:
            raise ValueError("a complete health sample cannot be missing")
        if self.complete and len(self.sample_sha256s) < 2:
            raise ValueError(
                "complete health sample requires request and latency sample digests"
            )
        if self.conflicting_duplicate and self.duplicate_count == 0:
            raise ValueError("a conflicting duplicate requires a positive duplicate count")
        if self.missing and (
            self.sample_sha256s
            or self.request_count
            or self.response_1xx_count
            or self.successful_request_count
            or self.response_3xx_count
            or self.response_4xx_count
            or self.server_error_count
            or self.p95_latency_ms
        ):
            raise ValueError("a missing health sample cannot contain aggregates")
        if self.window_ended_at <= self.window_started_at:
            raise ValueError("health window must have positive duration")
        if self.observed_at < self.window_ended_at:
            raise ValueError("health sample cannot be observed before its window ends")
        response_total = (
            self.response_1xx_count
            + self.successful_request_count
            + self.response_3xx_count
            + self.response_4xx_count
            + self.server_error_count
        )
        if self.complete and response_total != self.request_count:
            raise ValueError("total requests must equal the five known response-code classes")
        if response_total > self.request_count:
            raise ValueError("known response-code classes cannot exceed total requests")


@dataclass(frozen=True, slots=True)
class HealthEvaluationState:
    """Root-bound anti-flap state carried between pure evaluations."""

    policy_version: str
    policy_sha256: str
    project_id: str
    region: str
    environment: str
    service_name: str
    root_id: str
    root_sha256: str
    epoch: int
    candidate_revision: str
    observation_started_at: int
    last_window_ended_at: int | None = None
    consecutive_healthy_windows: int = 0
    consecutive_unhealthy_windows: int = 0
    evaluated_windows: int = 0
    last_observation_sha256: str | None = None
    consumed_sample_set_sha256s: tuple[str, ...] = ()
    prior_decision_sha256: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "policy_version",
            "project_id",
            "region",
            "environment",
            "service_name",
            "root_id",
            "candidate_revision",
        ):
            _require_identifier(name, getattr(self, name))
        _require_digest("policy_sha256", self.policy_sha256)
        _require_digest("root_sha256", self.root_sha256)
        _require_root_binding(self.root_id, self.root_sha256)
        _require_int("epoch", self.epoch, minimum=1, maximum=_MAX_SAFE_INTEGER)
        _require_int(
            "observation_started_at",
            self.observation_started_at,
            minimum=0,
            maximum=_MAX_SAFE_INTEGER,
        )
        if self.last_window_ended_at is not None:
            _require_int(
                "last_window_ended_at",
                self.last_window_ended_at,
                minimum=0,
                maximum=_MAX_SAFE_INTEGER,
            )
        if self.last_observation_sha256 is not None:
            _require_digest("last_observation_sha256", self.last_observation_sha256)
        if (
            type(self.consumed_sample_set_sha256s) is not tuple
            or len(self.consumed_sample_set_sha256s) > _MAX_WINDOWS
        ):
            raise ValueError("consumed_sample_set_sha256s must contain at most 10 digests")
        for digest in self.consumed_sample_set_sha256s:
            _require_digest("consumed_sample_set_sha256s", digest)
        if len(set(self.consumed_sample_set_sha256s)) != len(
            self.consumed_sample_set_sha256s
        ):
            raise ValueError("consumed sample-set digests must be unique")
        if self.prior_decision_sha256 is not None:
            _require_digest("prior_decision_sha256", self.prior_decision_sha256)
        for name in ("consecutive_healthy_windows", "consecutive_unhealthy_windows"):
            _require_int(name, getattr(self, name), minimum=0, maximum=64)
        _require_int("evaluated_windows", self.evaluated_windows, minimum=0, maximum=_MAX_WINDOWS)
        if self.consecutive_healthy_windows and self.consecutive_unhealthy_windows:
            raise ValueError("healthy and unhealthy streaks cannot both be active")
        if self.last_window_ended_at is None and (
            self.consecutive_healthy_windows
            or self.consecutive_unhealthy_windows
            or self.evaluated_windows
            or self.last_observation_sha256 is not None
            or self.consumed_sample_set_sha256s
            or self.prior_decision_sha256 is not None
        ):
            raise ValueError("evaluated health state requires a prior window")
        if self.evaluated_windows == 0 and self.last_window_ended_at is not None:
            raise ValueError("initial health state cannot cite a prior window")
        if max(
            self.consecutive_healthy_windows,
            self.consecutive_unhealthy_windows,
        ) > self.evaluated_windows:
            raise ValueError("a health streak cannot exceed evaluated windows")
        if self.evaluated_windows and self.last_observation_sha256 is None:
            raise ValueError("evaluated health state requires its last observation digest")
        if len(self.consumed_sample_set_sha256s) > self.evaluated_windows:
            raise ValueError("consumed sample-set digests cannot exceed evaluated windows")


@dataclass(frozen=True, slots=True)
class HealthEvaluationResult:
    """Complete deterministic decision record returned by the evaluator."""

    decision: HealthDecisionKind
    reasons: tuple[HealthReason, ...]
    policy_version: str
    policy_sha256: str
    prior_state: HealthEvaluationState
    state: HealthEvaluationState
    window_started_at: int | None
    window_ended_at: int | None
    request_count: int | None
    successful_request_count: int | None
    server_error_count: int | None
    error_rate_basis_points: int | None
    availability_basis_points: int | None
    p95_latency_ms: int | None
    observation_digests: tuple[str, ...]
    observation_sha256: str | None
    query_sha256s: tuple[str, ...]
    sample_sha256s: tuple[str, ...]
    duplicate_count: int | None
    evaluated_at: int
    next_evaluation_at: int | None


def _scope(
    policy: HealthPolicy | HealthEvaluationState | HealthWindowSample,
) -> tuple[str | int, ...]:
    return (
        policy.project_id,
        policy.region,
        policy.environment,
        policy.service_name,
        policy.root_id,
        policy.root_sha256,
        policy.epoch,
        policy.candidate_revision,
    )


def _state_matches(policy: HealthPolicy, state: HealthEvaluationState) -> bool:
    expected_last_window_ended_at = (
        None
        if state.evaluated_windows == 0
        else state.observation_started_at + state.evaluated_windows * policy.window_seconds
    )
    return (
        state.policy_version == policy.policy_version
        and state.policy_sha256 == policy.policy_sha256
        and state.observation_started_at == policy.observation_started_at
        and state.last_window_ended_at == expected_last_window_ended_at
        and _scope(state) == _scope(policy)
    )


def _sample_matches(policy: HealthPolicy, sample: HealthWindowSample) -> bool:
    return (
        sample.policy_sha256 == policy.policy_sha256
        and sample.observation_started_at == policy.observation_started_at
        and _scope(sample) == _scope(policy)
    )


def _reset(
    state: HealthEvaluationState,
    *,
    last_window_ended_at: int | None = None,
) -> HealthEvaluationState:
    return replace(
        state,
        last_window_ended_at=(
            state.last_window_ended_at if last_window_ended_at is None else last_window_ended_at
        ),
        consecutive_healthy_windows=0,
        consecutive_unhealthy_windows=0,
    )


def _advance(
    state: HealthEvaluationState,
    *,
    last_window_ended_at: int,
    last_observation_sha256: str | None,
    sample_sha256s: tuple[str, ...],
    windows: int = 1,
) -> HealthEvaluationState:
    sample_set_sha256 = _sample_set_sha256(sample_sha256s)
    consumed_sample_set_sha256s = state.consumed_sample_set_sha256s
    if (
        sample_set_sha256 is not None
        and sample_set_sha256 not in consumed_sample_set_sha256s
    ):
        consumed_sample_set_sha256s = (
            *consumed_sample_set_sha256s,
            sample_set_sha256,
        )
    return replace(
        state,
        last_window_ended_at=last_window_ended_at,
        evaluated_windows=min(state.evaluated_windows + windows, _MAX_WINDOWS),
        last_observation_sha256=last_observation_sha256,
        consumed_sample_set_sha256s=consumed_sample_set_sha256s,
    )


def _floor_basis_points(numerator: int, denominator: int) -> int:
    return numerator * _BASIS_POINTS // denominator


def _ceiling_basis_points(numerator: int, denominator: int) -> int:
    scaled = numerator * _BASIS_POINTS
    return (scaled + denominator - 1) // denominator


def _next_window_ready(policy: HealthPolicy, window_ended_at: int) -> int:
    return window_ended_at + policy.window_seconds + policy.observation_delay_seconds


def _next_after_consumed(
    policy: HealthPolicy,
    state: HealthEvaluationState,
    *,
    evaluated_at: int,
    window_ended_at: int,
) -> int | None:
    if state.evaluated_windows >= policy.maximum_windows:
        return None
    return max(evaluated_at, _next_window_ready(policy, window_ended_at))


def _result(
    *,
    decision: HealthDecisionKind,
    reasons: tuple[HealthReason, ...],
    policy: HealthPolicy,
    prior_state: HealthEvaluationState,
    state: HealthEvaluationState,
    evaluated_at: int,
    samples: tuple[HealthWindowSample, ...] = (),
    sample: HealthWindowSample | None = None,
    next_evaluation_at: int | None = None,
) -> HealthEvaluationResult:
    if sample is None or not sample.complete or sample.request_count == 0:
        request_count = None
        successful_request_count = None
        server_error_count = None
        error_rate_basis_points = None
        availability_basis_points = None
        p95_latency_ms = None
    else:
        request_count = sample.request_count
        successful_request_count = sample.successful_request_count
        server_error_count = sample.server_error_count
        error_rate_basis_points = (
            _ceiling_basis_points(server_error_count, request_count)
            if request_count > 0
            else None
        )
        availability_basis_points = (
            _floor_basis_points(successful_request_count, request_count)
            if request_count > 0
            else None
        )
        p95_latency_ms = sample.p95_latency_ms
    return HealthEvaluationResult(
        decision=decision,
        reasons=reasons,
        policy_version=policy.policy_version,
        policy_sha256=policy.policy_sha256,
        prior_state=prior_state,
        state=state,
        window_started_at=sample.window_started_at if sample is not None else None,
        window_ended_at=sample.window_ended_at if sample is not None else None,
        request_count=request_count,
        successful_request_count=successful_request_count,
        server_error_count=server_error_count,
        error_rate_basis_points=error_rate_basis_points,
        availability_basis_points=availability_basis_points,
        p95_latency_ms=p95_latency_ms,
        observation_digests=tuple(item.observation_sha256 for item in samples),
        observation_sha256=sample.observation_sha256 if sample is not None else None,
        query_sha256s=sample.query_sha256s if sample is not None else (),
        sample_sha256s=sample.sample_sha256s if sample is not None else (),
        duplicate_count=sample.duplicate_count if sample is not None else None,
        evaluated_at=evaluated_at,
        next_evaluation_at=(
            max(evaluated_at, next_evaluation_at)
            if next_evaluation_at is not None
            else None
        ),
    )


def _insufficient(
    *,
    reason: HealthReason,
    policy: HealthPolicy,
    prior_state: HealthEvaluationState,
    state: HealthEvaluationState,
    evaluated_at: int,
    samples: tuple[HealthWindowSample, ...],
    sample: HealthWindowSample | None = None,
    reset_streaks: bool = True,
    next_evaluation_at: int | None = None,
) -> HealthEvaluationResult:
    next_state = _reset(state) if reset_streaks else state
    return _result(
        decision=HealthDecisionKind.INSUFFICIENT_EVIDENCE,
        reasons=(reason,),
        policy=policy,
        prior_state=prior_state,
        state=next_state,
        evaluated_at=evaluated_at,
        samples=samples,
        sample=sample,
        next_evaluation_at=next_evaluation_at,
    )


def _classify_window(
    policy: HealthPolicy,
    sample: HealthWindowSample,
) -> tuple[str, tuple[HealthReason, ...]]:
    denominator = sample.request_count
    error_numerator = sample.server_error_count * _BASIS_POINTS
    availability_numerator = sample.successful_request_count * _BASIS_POINTS

    unhealthy_reasons: list[HealthReason] = []
    if error_numerator >= policy.unhealthy_minimum_error_rate_basis_points * denominator:
        unhealthy_reasons.append(HealthReason.UNHEALTHY_ERROR_RATE)
    if sample.p95_latency_ms >= policy.unhealthy_minimum_p95_latency_ms:
        unhealthy_reasons.append(HealthReason.UNHEALTHY_LATENCY)
    if availability_numerator <= policy.unhealthy_maximum_availability_basis_points * denominator:
        unhealthy_reasons.append(HealthReason.UNHEALTHY_AVAILABILITY)
    if unhealthy_reasons:
        return "unhealthy", tuple(unhealthy_reasons)

    healthy = (
        error_numerator <= policy.healthy_maximum_error_rate_basis_points * denominator
        and sample.p95_latency_ms <= policy.healthy_maximum_p95_latency_ms
        and availability_numerator
        >= policy.healthy_minimum_availability_basis_points * denominator
    )
    if healthy:
        return "healthy", (HealthReason.HEALTHY_THRESHOLDS_MET,)
    return "wait", (HealthReason.THRESHOLD_INCONCLUSIVE,)


def evaluate_health(
    policy: HealthPolicy,
    samples: tuple[HealthWindowSample, ...],
    prior_state: HealthEvaluationState,
    *,
    evaluated_at: int,
) -> HealthEvaluationResult:
    """Evaluate ordered canonical windows without clock, network, or storage access."""

    if type(policy) is not HealthPolicy:
        raise TypeError("policy must be an exact HealthPolicy")
    if type(prior_state) is not HealthEvaluationState:
        raise TypeError("prior_state must be an exact HealthEvaluationState")
    if type(samples) is not tuple or any(
        type(sample) is not HealthWindowSample for sample in samples
    ):
        raise TypeError("samples must be a tuple of exact HealthWindowSample values")
    samples = tuple(dict.fromkeys(samples))
    _require_int("evaluated_at", evaluated_at, minimum=0, maximum=_MAX_SAFE_INTEGER)

    if not _state_matches(policy, prior_state):
        return _insufficient(
            reason=HealthReason.STATE_SCOPE_MISMATCH,
            policy=policy,
            prior_state=prior_state,
            state=prior_state,
            evaluated_at=evaluated_at,
            samples=samples,
        )
    if (
        prior_state.consecutive_healthy_windows >= policy.healthy_consecutive_windows
        or prior_state.consecutive_unhealthy_windows >= policy.unhealthy_consecutive_windows
    ):
        return _insufficient(
            reason=HealthReason.STATE_TERMINAL,
            policy=policy,
            prior_state=prior_state,
            state=prior_state,
            evaluated_at=evaluated_at,
            samples=samples,
            reset_streaks=False,
        )
    if prior_state.evaluated_windows >= policy.maximum_windows:
        return _insufficient(
            reason=HealthReason.MAXIMUM_WINDOWS_EXHAUSTED,
            policy=policy,
            prior_state=prior_state,
            state=prior_state,
            evaluated_at=evaluated_at,
            samples=samples,
        )
    if not samples:
        expected_start = (
            prior_state.last_window_ended_at
            if prior_state.last_window_ended_at is not None
            else policy.observation_started_at
        )
        expected_end = expected_start + policy.window_seconds
        ready_at = expected_end + policy.observation_delay_seconds
        collection_deadline = expected_end + policy.maximum_observation_delay_seconds
        if evaluated_at < ready_at:
            return _result(
                decision=HealthDecisionKind.WAIT,
                reasons=(HealthReason.WINDOW_NOT_READY,),
                policy=policy,
                prior_state=prior_state,
                state=prior_state,
                evaluated_at=evaluated_at,
                samples=samples,
                next_evaluation_at=ready_at,
            )
        if evaluated_at < collection_deadline:
            return _insufficient(
                reason=HealthReason.NO_SAMPLES,
                policy=policy,
                prior_state=prior_state,
                state=prior_state,
                evaluated_at=evaluated_at,
                samples=samples,
                reset_streaks=False,
                next_evaluation_at=collection_deadline,
            )
        return _insufficient(
            reason=HealthReason.NO_SAMPLES,
            policy=policy,
            prior_state=prior_state,
            state=_reset(prior_state),
            evaluated_at=evaluated_at,
            samples=samples,
        )
    if len(samples) > policy.maximum_windows:
        return _insufficient(
            reason=HealthReason.TOO_MANY_WINDOWS,
            policy=policy,
            prior_state=prior_state,
            state=prior_state,
            evaluated_at=evaluated_at,
            samples=samples,
        )

    state = prior_state
    seen_windows: dict[tuple[int, int], HealthWindowSample] = {}
    seen_digests: dict[str, HealthWindowSample] = {}
    seen_sample_sets: dict[str, HealthWindowSample] = {}
    accepted: list[HealthWindowSample] = []
    last_result: HealthEvaluationResult | None = None

    for sample in samples:
        window = (sample.window_started_at, sample.window_ended_at)
        sample_set_sha256 = _sample_set_sha256(sample.sample_sha256s)
        prior_window_sample = seen_windows.get(window)
        prior_digest_sample = seen_digests.get(sample.observation_sha256)
        prior_sample_set_sample = (
            seen_sample_sets.get(sample_set_sha256)
            if sample_set_sha256 is not None
            else None
        )
        if (
            prior_window_sample is not None
            and not prior_window_sample.conflicting_duplicate
            and not sample.conflicting_duplicate
            and (
                prior_window_sample.observation_sha256 == sample.observation_sha256
                or (
                    sample_set_sha256 is not None
                    and _sample_set_sha256(prior_window_sample.sample_sha256s)
                    == sample_set_sha256
                )
            )
        ):
            continue
        accepted.append(sample)
        cited = tuple(accepted)
        if (
            prior_window_sample is not None
            or prior_digest_sample is not None
            or prior_sample_set_sample is not None
        ):
            conflict_state = _reset(state)
            return _insufficient(
                reason=HealthReason.SAMPLE_CONFLICTING_DUPLICATE,
                policy=policy,
                prior_state=prior_state,
                state=conflict_state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    conflict_state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )
        seen_windows[window] = sample
        seen_digests[sample.observation_sha256] = sample
        if sample_set_sha256 is not None:
            seen_sample_sets[sample_set_sha256] = sample

        if state.evaluated_windows >= policy.maximum_windows:
            return _insufficient(
                reason=HealthReason.MAXIMUM_WINDOWS_EXHAUSTED,
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
            )
        if not _sample_matches(policy, sample):
            return _insufficient(
                reason=HealthReason.SAMPLE_SCOPE_MISMATCH,
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
            )

        boundary_valid = (
            sample.window_ended_at - sample.window_started_at == policy.window_seconds
            and sample.window_index
            == (
                (sample.window_started_at - policy.observation_started_at)
                // policy.window_seconds
            )
            + 1
            and sample.window_started_at >= policy.observation_started_at
            and (sample.window_started_at - policy.observation_started_at)
            % policy.window_seconds
            == 0
        )
        if not boundary_valid:
            return _insufficient(
                reason=HealthReason.WINDOW_BOUNDARY_INVALID,
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
            )

        identical_replay = not sample.conflicting_duplicate and (
            sample.observation_sha256 == state.last_observation_sha256
            or (
                sample_set_sha256 is not None
                and sample_set_sha256 in state.consumed_sample_set_sha256s
            )
        )
        if identical_replay:
            next_window_base = state.last_window_ended_at
            assert next_window_base is not None
            return _result(
                decision=HealthDecisionKind.WAIT,
                reasons=(HealthReason.WINDOW_DUPLICATE,),
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    state,
                    evaluated_at=evaluated_at,
                    window_ended_at=next_window_base,
                ),
            )
        if sample.window_ended_at == state.last_window_ended_at:
            conflict_state = _reset(state)
            return _insufficient(
                reason=HealthReason.SAMPLE_CONFLICTING_DUPLICATE,
                policy=policy,
                prior_state=prior_state,
                state=conflict_state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    conflict_state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )

        expected_start = (
            state.last_window_ended_at
            if state.last_window_ended_at is not None
            else policy.observation_started_at
        )
        if sample.window_started_at < expected_start:
            return _insufficient(
                reason=HealthReason.WINDOW_OUT_OF_ORDER,
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
            )
        elapsed_windows = (
            sample.window_ended_at - expected_start
        ) // policy.window_seconds
        has_gap = sample.window_started_at > expected_start
        ready_at = sample.window_ended_at + policy.observation_delay_seconds
        if evaluated_at < ready_at:
            return _result(
                decision=HealthDecisionKind.WAIT,
                reasons=(HealthReason.WINDOW_NOT_READY,),
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=ready_at,
            )
        collection_deadline = (
            sample.window_ended_at + policy.maximum_observation_delay_seconds
        )
        if sample.observed_at > evaluated_at:
            return _insufficient(
                reason=HealthReason.SAMPLE_LATE,
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                reset_streaks=False,
                next_evaluation_at=min(sample.observed_at, collection_deadline),
            )
        if sample.observed_at < ready_at:
            return _result(
                decision=HealthDecisionKind.WAIT,
                reasons=(HealthReason.SAMPLE_EARLY,),
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=max(evaluated_at, ready_at),
            )
        advanced_state = _advance(
            state,
            last_window_ended_at=sample.window_ended_at,
            last_observation_sha256=sample.observation_sha256,
            sample_sha256s=sample.sample_sha256s,
            windows=elapsed_windows,
        )
        if sample.observed_at > collection_deadline:
            return _insufficient(
                reason=HealthReason.SAMPLE_LATE,
                policy=policy,
                prior_state=prior_state,
                state=advanced_state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    advanced_state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )
        if has_gap:
            return _insufficient(
                reason=HealthReason.WINDOW_GAP,
                policy=policy,
                prior_state=prior_state,
                state=advanced_state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    advanced_state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )
        if sample.missing or not sample.complete:
            reason = (
                HealthReason.SAMPLE_MISSING
                if sample.missing
                else HealthReason.SAMPLE_PARTIAL
            )
            if evaluated_at < collection_deadline:
                return _insufficient(
                    reason=reason,
                    policy=policy,
                    prior_state=prior_state,
                    state=state,
                    evaluated_at=evaluated_at,
                    samples=cited,
                    sample=sample,
                    reset_streaks=False,
                    next_evaluation_at=collection_deadline,
                )
            return _insufficient(
                reason=reason,
                policy=policy,
                prior_state=prior_state,
                state=advanced_state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    advanced_state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )
        if sample.conflicting_duplicate:
            return _insufficient(
                reason=HealthReason.SAMPLE_CONFLICTING_DUPLICATE,
                policy=policy,
                prior_state=prior_state,
                state=advanced_state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    advanced_state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )
        if sample.request_count < policy.minimum_request_count:
            if evaluated_at < collection_deadline:
                return _insufficient(
                    reason=HealthReason.MINIMUM_REQUESTS_NOT_MET,
                    policy=policy,
                    prior_state=prior_state,
                    state=state,
                    evaluated_at=evaluated_at,
                    samples=cited,
                    sample=sample,
                    reset_streaks=False,
                    next_evaluation_at=collection_deadline,
                )
            return _insufficient(
                reason=HealthReason.MINIMUM_REQUESTS_NOT_MET,
                policy=policy,
                prior_state=prior_state,
                state=advanced_state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    advanced_state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )

        classification, threshold_reasons = _classify_window(policy, sample)
        if classification == "healthy":
            state = replace(
                advanced_state,
                consecutive_healthy_windows=min(
                    state.consecutive_healthy_windows + 1,
                    policy.healthy_consecutive_windows,
                ),
                consecutive_unhealthy_windows=0,
            )
            streak_met = (
                state.consecutive_healthy_windows >= policy.healthy_consecutive_windows
            )
            if streak_met:
                return _result(
                    decision=HealthDecisionKind.HEALTHY,
                    reasons=(*threshold_reasons, HealthReason.HEALTHY_STREAK_MET),
                    policy=policy,
                    prior_state=prior_state,
                    state=state,
                    evaluated_at=evaluated_at,
                    samples=cited,
                    sample=sample,
                )
            if state.evaluated_windows >= policy.maximum_windows:
                return _result(
                    decision=HealthDecisionKind.INSUFFICIENT_EVIDENCE,
                    reasons=(*threshold_reasons, HealthReason.MAXIMUM_WINDOWS_EXHAUSTED),
                    policy=policy,
                    prior_state=prior_state,
                    state=_reset(state),
                    evaluated_at=evaluated_at,
                    samples=cited,
                    sample=sample,
                )
            last_result = _result(
                decision=HealthDecisionKind.WAIT,
                reasons=(*threshold_reasons, HealthReason.HEALTHY_STREAK_PENDING),
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )
        elif classification == "unhealthy":
            state = replace(
                advanced_state,
                consecutive_healthy_windows=0,
                consecutive_unhealthy_windows=min(
                    state.consecutive_unhealthy_windows + 1,
                    policy.unhealthy_consecutive_windows,
                ),
            )
            streak_met = (
                state.consecutive_unhealthy_windows >= policy.unhealthy_consecutive_windows
            )
            if streak_met:
                return _result(
                    decision=HealthDecisionKind.UNHEALTHY,
                    reasons=(*threshold_reasons, HealthReason.UNHEALTHY_STREAK_MET),
                    policy=policy,
                    prior_state=prior_state,
                    state=state,
                    evaluated_at=evaluated_at,
                    samples=cited,
                    sample=sample,
                )
            if state.evaluated_windows >= policy.maximum_windows:
                return _result(
                    decision=HealthDecisionKind.INSUFFICIENT_EVIDENCE,
                    reasons=(*threshold_reasons, HealthReason.MAXIMUM_WINDOWS_EXHAUSTED),
                    policy=policy,
                    prior_state=prior_state,
                    state=_reset(state),
                    evaluated_at=evaluated_at,
                    samples=cited,
                    sample=sample,
                )
            last_result = _result(
                decision=HealthDecisionKind.WAIT,
                reasons=(*threshold_reasons, HealthReason.UNHEALTHY_STREAK_PENDING),
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )
        else:
            state = _reset(advanced_state)
            if state.evaluated_windows >= policy.maximum_windows:
                return _result(
                    decision=HealthDecisionKind.INSUFFICIENT_EVIDENCE,
                    reasons=(*threshold_reasons, HealthReason.MAXIMUM_WINDOWS_EXHAUSTED),
                    policy=policy,
                    prior_state=prior_state,
                    state=state,
                    evaluated_at=evaluated_at,
                    samples=cited,
                    sample=sample,
                )
            last_result = _result(
                decision=HealthDecisionKind.WAIT,
                reasons=threshold_reasons,
                policy=policy,
                prior_state=prior_state,
                state=state,
                evaluated_at=evaluated_at,
                samples=cited,
                sample=sample,
                next_evaluation_at=_next_after_consumed(
                    policy,
                    state,
                    evaluated_at=evaluated_at,
                    window_ended_at=sample.window_ended_at,
                ),
            )

    if last_result is None:  # pragma: no cover - non-empty input always assigns or returns
        raise AssertionError("health evaluation produced no result")
    return last_result


__all__ = [
    "HealthDecisionKind",
    "HealthEvaluationResult",
    "HealthEvaluationState",
    "HealthPolicy",
    "HealthReason",
    "HealthWindowSample",
    "evaluate_health",
]
