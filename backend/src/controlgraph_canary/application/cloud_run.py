"""Provider-neutral state and outcomes for the bound Cloud Run target."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from controlgraph_canary.contracts.base import MAX_SAFE_INTEGER
from controlgraph_canary.contracts.codec import RestrictedJson, canonical_json_value_bytes
from controlgraph_canary.contracts.models import MutationIntent, TargetBinding

TARGET_CONFIGURATION_DOMAIN: Final = b"controlgraph.target-configuration-sha256/v1\0"
TARGET_CONFIGURATION_V1: Final = "controlgraph.target-configuration/v1"
_CLOUD_RUN_NAME: Final = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_OPAQUE_TOKEN: Final = re.compile(r"^[A-Za-z0-9._~:/+=-]+$")


def _require_name(name: str, value: object) -> None:
    if type(value) is not str or _CLOUD_RUN_NAME.fullmatch(value) is None:
        raise ValueError(f"{name} is not an exact Cloud Run name")


def _require_bounded_text(name: str, value: object, *, maximum: int = 2_048) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} is not bounded text")


def _require_token(name: str, value: object) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or _OPAQUE_TOKEN.fullmatch(value) is None
    ):
        raise ValueError(f"{name} is not an opaque provider token")


def _require_generation(name: str, value: object) -> None:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"{name} is not a positive safe integer")


def _service_resource(target: TargetBinding) -> str:
    return f"projects/{target.project_id}/locations/{target.region}/services/{target.service_name}"


def _revision_resource(target: TargetBinding, revision: str) -> str:
    return f"{_service_resource(target)}/revisions/{revision}"


class DeclaredRevision(StrEnum):
    """Closed selector for the two revisions admitted by one rollout root."""

    STABLE = "STABLE"
    CANDIDATE = "CANDIDATE"


@dataclass(frozen=True, slots=True)
class CloudRunTargetConfiguration:
    """Trusted constructor binding for one service and two immutable revisions."""

    target: TargetBinding
    stable_revision: str
    candidate_revision: str
    stable_concurrency: int
    candidate_concurrency: int

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("Cloud Run target configuration requires an exact target")
        _require_name("stable_revision", self.stable_revision)
        _require_name("candidate_revision", self.candidate_revision)
        if self.stable_revision == self.candidate_revision:
            raise ValueError("declared Cloud Run revisions must differ")
        prefix = f"{self.target.service_name}-"
        if not self.stable_revision.startswith(prefix) or not self.candidate_revision.startswith(
            prefix
        ):
            raise ValueError("declared revisions do not belong to the configured service")
        for name, value in (
            ("stable_concurrency", self.stable_concurrency),
            ("candidate_concurrency", self.candidate_concurrency),
        ):
            if type(value) is not int or not 1 <= value <= 1_000:
                raise ValueError(f"{name} is outside the approved bound")

    @property
    def service_resource(self) -> str:
        return _service_resource(self.target)

    def revision(self, declared: DeclaredRevision) -> str:
        if type(declared) is not DeclaredRevision:
            raise TypeError("an exact declared revision selector is required")
        if declared is DeclaredRevision.STABLE:
            return self.stable_revision
        return self.candidate_revision

    def revision_resource(self, declared: DeclaredRevision) -> str:
        return _revision_resource(self.target, self.revision(declared))


@dataclass(frozen=True, slots=True)
class TargetConfigurationProjection:
    """Provider-neutral canonical poststate admitted by one mutation intent."""

    target: TargetBinding
    stable_revision: str
    candidate_revision: str
    stable_percent: int
    candidate_percent: int
    concurrency: int

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("target configuration requires an exact target")
        _require_name("stable_revision", self.stable_revision)
        _require_name("candidate_revision", self.candidate_revision)
        if self.stable_revision == self.candidate_revision:
            raise ValueError("target configuration revisions must differ")
        prefix = f"{self.target.service_name}-"
        if not self.stable_revision.startswith(prefix) or not self.candidate_revision.startswith(
            prefix
        ):
            raise ValueError("target configuration revisions do not belong to the target service")
        if (
            type(self.stable_percent) is not int
            or type(self.candidate_percent) is not int
            or not 0 <= self.stable_percent <= 100
            or not 0 <= self.candidate_percent <= 100
            or self.stable_percent + self.candidate_percent != 100
        ):
            raise ValueError("target configuration traffic is invalid")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 1_000:
            raise ValueError("target configuration concurrency is invalid")


def target_configuration_projection(
    intent: MutationIntent,
    *,
    expected_concurrency: int,
) -> TargetConfigurationProjection:
    """Project only the exact poststate fields shared by receipts and readback."""

    if type(intent) is not MutationIntent:
        raise TypeError("an exact mutation intent is required")
    if intent.concurrency is not None and intent.concurrency != expected_concurrency:
        raise ValueError("mutation intent concurrency does not match the expected concurrency")
    return TargetConfigurationProjection(
        target=intent.target,
        stable_revision=intent.stable_revision,
        candidate_revision=intent.candidate_revision,
        stable_percent=intent.stable_percent,
        candidate_percent=intent.candidate_percent,
        concurrency=expected_concurrency,
    )


def target_configuration_sha256(
    intent: MutationIntent,
    *,
    expected_concurrency: int,
) -> str:
    """Hash the provider-neutral target poststate under one explicit domain."""

    projected = target_configuration_projection(
        intent,
        expected_concurrency=expected_concurrency,
    )
    value: RestrictedJson = {
        "candidate_percent": projected.candidate_percent,
        "candidate_revision": projected.candidate_revision,
        "concurrency": projected.concurrency,
        "schema_version": TARGET_CONFIGURATION_V1,
        "stable_percent": projected.stable_percent,
        "stable_revision": projected.stable_revision,
        "target": projected.target.model_dump(mode="json"),
    }
    return hashlib.sha256(
        TARGET_CONFIGURATION_DOMAIN + canonical_json_value_bytes(value)
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class CloudRunTrafficAllocation:
    """Exact desired traffic mapping for one declared revision."""

    revision: str
    percent: int
    tag: str

    def __post_init__(self) -> None:
        _require_name("traffic revision", self.revision)
        if type(self.percent) is not int or not 0 <= self.percent <= 100:
            raise ValueError("traffic percent is outside zero to one hundred")
        _require_name("traffic tag", self.tag)


@dataclass(frozen=True, slots=True)
class CloudRunTrafficStatus:
    """Provider-observed URL mapping for one traffic target."""

    revision: str
    percent: int
    tag: str
    uri: str

    def __post_init__(self) -> None:
        _require_name("traffic status revision", self.revision)
        if type(self.percent) is not int or not 0 <= self.percent <= 100:
            raise ValueError("traffic status percent is outside zero to one hundred")
        _require_name("traffic status tag", self.tag)
        _require_bounded_text("traffic status URI", self.uri)


@dataclass(frozen=True, slots=True)
class CloudRunServiceState:
    """Bounded provider state returned by one exact service read or operation."""

    target: TargetBinding
    resource_name: str
    uid: str
    etag: str
    generation: int
    observed_generation: int
    reconciling: bool
    latest_ready_revision: str
    latest_created_revision: str
    template_revision: str
    template_concurrency: int
    traffic: tuple[CloudRunTrafficAllocation, ...]
    traffic_statuses: tuple[CloudRunTrafficStatus, ...]
    uri: str

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("Cloud Run service state requires an exact target")
        if self.resource_name != _service_resource(self.target):
            raise ValueError("Cloud Run service state does not match its target")
        _require_bounded_text("service uid", self.uid, maximum=128)
        _require_token("service etag", self.etag)
        _require_generation("service generation", self.generation)
        _require_generation("service observed generation", self.observed_generation)
        if type(self.reconciling) is not bool:
            raise ValueError("service reconciling flag is invalid")
        for name, value in (
            ("latest_ready_revision", self.latest_ready_revision),
            ("latest_created_revision", self.latest_created_revision),
            ("template_revision", self.template_revision),
        ):
            _require_name(name, value)
        if (
            type(self.template_concurrency) is not int
            or not 1 <= self.template_concurrency <= 1_000
        ):
            raise ValueError("service template concurrency is outside the approved bound")
        if not 1 <= len(self.traffic) <= 2:
            raise ValueError("service traffic mapping is not bounded")
        if len({item.revision for item in self.traffic}) != len(self.traffic):
            raise ValueError("service traffic contains a duplicate revision")
        if len({item.tag for item in self.traffic}) != len(self.traffic):
            raise ValueError("service traffic contains a duplicate tag")
        if sum(item.percent for item in self.traffic) != 100:
            raise ValueError("service traffic does not total one hundred percent")
        if not 1 <= len(self.traffic_statuses) <= 2:
            raise ValueError("service traffic status mapping is not bounded")
        if len({item.revision for item in self.traffic_statuses}) != len(self.traffic_statuses):
            raise ValueError("service traffic status contains a duplicate revision")
        if sum(item.percent for item in self.traffic_statuses) != 100:
            raise ValueError("service traffic statuses do not total one hundred percent")
        _require_bounded_text("service URI", self.uri)


@dataclass(frozen=True, slots=True)
class CloudRunRevisionState:
    """Exact immutable state for one declared Cloud Run revision."""

    target: TargetBinding
    revision: str
    resource_name: str
    service_resource: str
    uid: str
    etag: str
    generation: int
    observed_generation: int
    reconciling: bool
    concurrency: int

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("Cloud Run revision state requires an exact target")
        _require_name("revision", self.revision)
        if self.resource_name != _revision_resource(self.target, self.revision):
            raise ValueError("Cloud Run revision state does not match its target")
        if self.service_resource != _service_resource(self.target):
            raise ValueError("Cloud Run revision service does not match its target")
        _require_bounded_text("revision uid", self.uid, maximum=128)
        _require_token("revision etag", self.etag)
        _require_generation("revision generation", self.generation)
        _require_generation("revision observed generation", self.observed_generation)
        if type(self.reconciling) is not bool:
            raise ValueError("revision reconciling flag is invalid")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 1_000:
            raise ValueError("revision concurrency is outside the approved bound")


@dataclass(frozen=True, slots=True)
class CloudRunTargetState:
    """One bounded service view plus both exact declared revision reads."""

    service: CloudRunServiceState
    stable_revision: CloudRunRevisionState
    candidate_revision: CloudRunRevisionState

    def __post_init__(self) -> None:
        target = self.service.target
        if (
            self.stable_revision.target != target
            or self.candidate_revision.target != target
            or self.stable_revision.revision == self.candidate_revision.revision
        ):
            raise ValueError("Cloud Run target state is not one exact declared target")


class CloudRunMutationOutcome(StrEnum):
    """Closed provider classifications after one admitted mutation call."""

    APPLIED = "APPLIED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"


class CloudRunMutationReason(StrEnum):
    """Sanitized reason retained without raw provider response material."""

    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    DECLARATION_MISMATCH = "DECLARATION_MISMATCH"
    PROVIDER_REJECTED = "PROVIDER_REJECTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


@dataclass(frozen=True, slots=True)
class CloudRunMutationResult:
    """One mutation attempt with its request mapping and bounded provider result."""

    outcome: CloudRunMutationOutcome
    requested_traffic: tuple[CloudRunTrafficAllocation, ...]
    expected_concurrency: int
    operation_name: str | None
    service: CloudRunServiceState | None
    reason: CloudRunMutationReason | None

    def __post_init__(self) -> None:
        if type(self.outcome) is not CloudRunMutationOutcome:
            raise TypeError("an exact Cloud Run mutation outcome is required")
        if len(self.requested_traffic) != 2:
            raise ValueError("a mutation must bind both declared revisions")
        if len({item.revision for item in self.requested_traffic}) != 2:
            raise ValueError("mutation traffic revisions must be distinct")
        if sum(item.percent for item in self.requested_traffic) != 100:
            raise ValueError("mutation traffic does not total one hundred percent")
        if (
            type(self.expected_concurrency) is not int
            or not 1 <= self.expected_concurrency <= 1_000
        ):
            raise ValueError("mutation concurrency is outside the approved bound")
        if self.operation_name is not None:
            _require_bounded_text("operation name", self.operation_name, maximum=512)
        if self.outcome is CloudRunMutationOutcome.APPLIED:
            if self.operation_name is None or self.service is None or self.reason is not None:
                raise ValueError("applied mutation result shape is invalid")
            return
        if self.service is not None or type(self.reason) is not CloudRunMutationReason:
            raise ValueError("non-applied mutation result shape is invalid")
        if (
            self.outcome is CloudRunMutationOutcome.AMBIGUOUS
            and self.reason is not CloudRunMutationReason.OUTCOME_UNKNOWN
        ):
            raise ValueError("ambiguous mutation requires an unknown-outcome reason")
        if (
            self.outcome is CloudRunMutationOutcome.FAILED_SAFE
            and self.reason is CloudRunMutationReason.OUTCOME_UNKNOWN
        ):
            raise ValueError("failed-safe mutation cannot retain an unknown outcome")


class CloudRunReadErrorCode(StrEnum):
    """Stable failure classes for exact target reads."""

    NOT_FOUND = "CLOUD_RUN_NOT_FOUND"
    UNAVAILABLE = "CLOUD_RUN_UNAVAILABLE"
    CORRUPT_RESPONSE = "CLOUD_RUN_CORRUPT_RESPONSE"


class CloudRunReadError(RuntimeError):
    """Sanitized read failure that retains no raw provider response material."""

    def __init__(self, code: CloudRunReadErrorCode) -> None:
        if type(code) is not CloudRunReadErrorCode:
            raise TypeError("an exact Cloud Run read error code is required")
        self.code = code
        super().__init__(code.value)


__all__ = [
    "TARGET_CONFIGURATION_DOMAIN",
    "TARGET_CONFIGURATION_V1",
    "CloudRunMutationOutcome",
    "CloudRunMutationReason",
    "CloudRunMutationResult",
    "CloudRunReadError",
    "CloudRunReadErrorCode",
    "CloudRunRevisionState",
    "CloudRunServiceState",
    "CloudRunTargetConfiguration",
    "CloudRunTargetState",
    "CloudRunTrafficAllocation",
    "CloudRunTrafficStatus",
    "DeclaredRevision",
    "TargetConfigurationProjection",
    "target_configuration_projection",
    "target_configuration_sha256",
]
