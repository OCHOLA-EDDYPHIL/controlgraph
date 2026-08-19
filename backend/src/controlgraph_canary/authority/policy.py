"""Closed capability attenuation and lineage policy for Cloud Run canaries."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from controlgraph_canary.authority.reducer import DenialReason

MAX_LINEAGE_DEPTH = 16
_WILDCARD_CHARACTERS = frozenset("*?[]")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CanaryAction(StrEnum):
    """Closed actions that a ControlGraph capability may authorize."""

    APPLY_CANARY = "APPLY_CANARY_V1"
    PROMOTE_CANDIDATE = "PROMOTE_CANDIDATE_V1"
    REVOKE_EPOCH = "REVOKE_EPOCH_V1"
    RECOVER_STABLE = "RECOVER_STABLE_V1"
    READBACK_TARGET = "VERIFY_TARGET_V1"
    PROBE_DATA_PATH = "PROBE_DATA_PATH_V1"


class AttenuationFailure(StrEnum):
    """Deterministic field classification for an attenuation denial."""

    TARGET = "TARGET"
    ROOT = "ROOT"
    ROOT_DIGEST = "ROOT_DIGEST"
    EPOCH = "EPOCH"
    PLAN = "PLAN"
    PRECONDITION = "PRECONDITION"
    REQUEST = "REQUEST"
    IDEMPOTENCY = "IDEMPOTENCY"
    CALLERS = "CALLERS"
    AUDIENCES = "AUDIENCES"
    REVISIONS = "REVISIONS"
    STABLE_REVISION = "STABLE_REVISION"
    CANDIDATE_REVISION = "CANDIDATE_REVISION"
    ACTIONS = "ACTIONS"
    TRAFFIC = "TRAFFIC"
    CONCURRENCY = "CONCURRENCY"
    TIME = "TIME"


class LineageFailure(StrEnum):
    """Deterministic structural classification for a lineage denial."""

    MISSING = "MISSING"
    CYCLIC = "CYCLIC"
    DUPLICATE = "DUPLICATE"
    WRONG_PARENT = "WRONG_PARENT"
    WIDENED = "WIDENED"
    MAX_DEPTH_EXCEEDED = "MAX_DEPTH_EXCEEDED"
    INVALID_MAX_DEPTH = "INVALID_MAX_DEPTH"


def _validate_identifier(name: str, value: object) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must not be blank")
    if any(character in value for character in _WILDCARD_CHARACTERS):
        raise ValueError(f"{name} must not contain wildcards")


def _validate_string_set(name: str, values: object) -> None:
    if not isinstance(values, frozenset) or not values:
        raise ValueError(f"{name} must be a non-empty frozenset")
    for value in values:
        _validate_identifier(name, value)


def _validate_sha256(name: str, value: object) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class IntegerBounds:
    """Inclusive integer range that can only be narrowed by a child."""

    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if type(self.minimum) is not int or type(self.maximum) is not int:
            raise ValueError("bounds must use integers")
        if self.minimum < 0 or self.maximum < self.minimum:
            raise ValueError("bounds must be non-negative and ordered")

    def is_within(self, parent: IntegerBounds) -> bool:
        return self.minimum >= parent.minimum and self.maximum <= parent.maximum


@dataclass(frozen=True, slots=True)
class TimeBounds:
    """Inclusive validity start and exclusive expiry supplied by the caller."""

    not_before: int
    expires_at: int

    def __post_init__(self) -> None:
        if type(self.not_before) is not int or type(self.expires_at) is not int:
            raise ValueError("time bounds must use integers")
        if self.not_before < 0 or self.expires_at <= self.not_before:
            raise ValueError("time bounds must define a positive non-negative interval")

    def is_within(self, parent: TimeBounds) -> bool:
        return self.not_before >= parent.not_before and self.expires_at <= parent.expires_at


@dataclass(frozen=True, slots=True)
class CapabilityScope:
    """Maximum authority carried by one canary capability."""

    project_id: str
    region: str
    environment: str
    service_name: str
    root_id: str
    root_sha256: str
    epoch: int
    plan_sha256: str
    provider_precondition: str
    request_id: str
    idempotency_key: str
    callers: frozenset[str]
    audiences: frozenset[str]
    stable_revision: str
    candidate_revision: str
    revisions: frozenset[str]
    actions: frozenset[CanaryAction]
    traffic_percent: IntegerBounds
    concurrency: IntegerBounds
    validity: TimeBounds

    def __post_init__(self) -> None:
        for name in ("project_id", "region", "environment", "service_name", "root_id"):
            _validate_identifier(name, getattr(self, name))
        _validate_sha256("root_sha256", self.root_sha256)
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("epoch must be an integer at least one")
        _validate_sha256("plan_sha256", self.plan_sha256)
        _validate_identifier("provider_precondition", self.provider_precondition)
        _validate_identifier("request_id", self.request_id)
        _validate_identifier("idempotency_key", self.idempotency_key)
        _validate_string_set("callers", self.callers)
        _validate_string_set("audiences", self.audiences)
        _validate_identifier("stable_revision", self.stable_revision)
        _validate_identifier("candidate_revision", self.candidate_revision)
        if self.stable_revision == self.candidate_revision:
            raise ValueError("stable and candidate revisions must differ")
        _validate_string_set("revisions", self.revisions)
        if not self.revisions.issubset({self.stable_revision, self.candidate_revision}):
            raise ValueError("revisions must be bound to the stable or candidate role")
        if not isinstance(self.actions, frozenset) or not self.actions:
            raise ValueError("actions must be a non-empty frozenset")
        if any(not isinstance(action, CanaryAction) for action in self.actions):
            raise ValueError("actions must contain only CanaryAction values")
        if not isinstance(self.traffic_percent, IntegerBounds):
            raise ValueError("traffic_percent must be IntegerBounds")
        if self.traffic_percent.maximum > 100:
            raise ValueError("traffic bounds must remain between zero and one hundred")
        if not isinstance(self.concurrency, IntegerBounds):
            raise ValueError("concurrency must be IntegerBounds")
        if self.concurrency.minimum < 1 or self.concurrency.maximum > 1_000:
            raise ValueError("concurrency bounds must remain between one and one thousand")
        if not isinstance(self.validity, TimeBounds):
            raise ValueError("validity must be TimeBounds")


@dataclass(frozen=True, slots=True)
class AttenuationResult:
    """Result of proving that one child scope is no wider than its parent."""

    allowed: bool
    reason: DenialReason | None
    failure: AttenuationFailure | None


@dataclass(frozen=True, slots=True)
class OperatorRootAnchor:
    """Expected operator-approved root at which lineage must terminate."""

    root_sha256: str
    scope: CapabilityScope

    def __post_init__(self) -> None:
        _validate_sha256("root_sha256", self.root_sha256)
        if not isinstance(self.scope, CapabilityScope):
            raise ValueError("scope must be CapabilityScope")
        if self.root_sha256 != self.scope.root_sha256:
            raise ValueError("anchor digest must match the approved root scope")


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    """One capability and its exact parent in an ordered lineage."""

    capability_sha256: str
    parent_capability_sha256: str | None
    scope: CapabilityScope

    def __post_init__(self) -> None:
        _validate_sha256("capability_sha256", self.capability_sha256)
        if self.parent_capability_sha256 is not None:
            _validate_sha256("parent_capability_sha256", self.parent_capability_sha256)
        if not isinstance(self.scope, CapabilityScope):
            raise ValueError("scope must be CapabilityScope")


@dataclass(frozen=True, slots=True)
class LineageResult:
    """Result of validating an ordered capability chain from an expected anchor."""

    allowed: bool
    reason: DenialReason | None
    failure: LineageFailure | None
    depth: int
    failed_capability_sha256: str | None = None
    attenuation_failure: AttenuationFailure | None = None


def _attenuation_denial(
    reason: DenialReason,
    failure: AttenuationFailure,
) -> AttenuationResult:
    return AttenuationResult(allowed=False, reason=reason, failure=failure)


def check_attenuation(parent: CapabilityScope, child: CapabilityScope) -> AttenuationResult:
    """Prove field-by-field that ``child`` is equal to or narrower than ``parent``."""

    if (
        child.project_id != parent.project_id
        or child.region != parent.region
        or child.environment != parent.environment
        or child.service_name != parent.service_name
    ):
        return _attenuation_denial(
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.TARGET,
        )
    if child.root_id != parent.root_id:
        return _attenuation_denial(DenialReason.LINEAGE_INVALID, AttenuationFailure.ROOT)
    if child.root_sha256 != parent.root_sha256:
        return _attenuation_denial(
            DenialReason.LINEAGE_INVALID,
            AttenuationFailure.ROOT_DIGEST,
        )
    if child.epoch != parent.epoch:
        return _attenuation_denial(DenialReason.EPOCH_MISMATCH, AttenuationFailure.EPOCH)
    if child.plan_sha256 != parent.plan_sha256:
        return _attenuation_denial(
            DenialReason.CLAIM_BINDING_MISMATCH,
            AttenuationFailure.PLAN,
        )
    if child.provider_precondition != parent.provider_precondition:
        return _attenuation_denial(
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.PRECONDITION,
        )
    if child.request_id != parent.request_id:
        return _attenuation_denial(
            DenialReason.CLAIM_BINDING_MISMATCH,
            AttenuationFailure.REQUEST,
        )
    if child.idempotency_key != parent.idempotency_key:
        return _attenuation_denial(
            DenialReason.CLAIM_BINDING_MISMATCH,
            AttenuationFailure.IDEMPOTENCY,
        )
    if not child.callers.issubset(parent.callers):
        return _attenuation_denial(DenialReason.SCOPE_AMPLIFICATION, AttenuationFailure.CALLERS)
    if not child.audiences.issubset(parent.audiences):
        return _attenuation_denial(
            DenialReason.SCOPE_AMPLIFICATION,
            AttenuationFailure.AUDIENCES,
        )
    if child.stable_revision != parent.stable_revision:
        return _attenuation_denial(
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.STABLE_REVISION,
        )
    if child.candidate_revision != parent.candidate_revision:
        return _attenuation_denial(
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.CANDIDATE_REVISION,
        )
    if not child.revisions.issubset(parent.revisions):
        return _attenuation_denial(
            DenialReason.SCOPE_AMPLIFICATION,
            AttenuationFailure.REVISIONS,
        )
    if not child.actions.issubset(parent.actions):
        return _attenuation_denial(DenialReason.SCOPE_AMPLIFICATION, AttenuationFailure.ACTIONS)
    if not child.traffic_percent.is_within(parent.traffic_percent):
        return _attenuation_denial(DenialReason.SCOPE_AMPLIFICATION, AttenuationFailure.TRAFFIC)
    if not child.concurrency.is_within(parent.concurrency):
        return _attenuation_denial(
            DenialReason.SCOPE_AMPLIFICATION,
            AttenuationFailure.CONCURRENCY,
        )
    if not child.validity.is_within(parent.validity):
        return _attenuation_denial(DenialReason.SCOPE_AMPLIFICATION, AttenuationFailure.TIME)
    return AttenuationResult(allowed=True, reason=None, failure=None)


def _lineage_denial(
    failure: LineageFailure,
    *,
    depth: int,
    failed_capability_sha256: str | None = None,
    reason: DenialReason = DenialReason.LINEAGE_INVALID,
    attenuation_failure: AttenuationFailure | None = None,
) -> LineageResult:
    return LineageResult(
        allowed=False,
        reason=reason,
        failure=failure,
        depth=depth,
        failed_capability_sha256=failed_capability_sha256,
        attenuation_failure=attenuation_failure,
    )


def _contains_cycle(
    grants_by_id: dict[str, CapabilityGrant],
) -> bool:
    for starting_id in grants_by_id:
        current_id = starting_id
        visited: set[str] = set()
        while current_id in grants_by_id:
            if current_id in visited:
                return True
            visited.add(current_id)
            parent_id = grants_by_id[current_id].parent_capability_sha256
            if parent_id is None:
                break
            current_id = parent_id
    return False


def validate_lineage(
    anchor: OperatorRootAnchor,
    grants: tuple[CapabilityGrant, ...],
    *,
    max_depth: int = MAX_LINEAGE_DEPTH,
) -> LineageResult:
    """Validate one ordered anchor-to-leaf chain and every attenuation hop."""

    if type(max_depth) is not int or not 1 <= max_depth <= MAX_LINEAGE_DEPTH:
        return _lineage_denial(
            LineageFailure.INVALID_MAX_DEPTH,
            depth=0,
            reason=DenialReason.CONTRACT_INVALID,
        )
    if not grants:
        return _lineage_denial(LineageFailure.MISSING, depth=0)
    if len(grants) > max_depth:
        return _lineage_denial(LineageFailure.MAX_DEPTH_EXCEEDED, depth=max_depth)

    grants_by_id: dict[str, CapabilityGrant] = {}
    for grant in grants:
        if grant.capability_sha256 in grants_by_id:
            return _lineage_denial(
                LineageFailure.DUPLICATE,
                depth=len(grants_by_id),
                failed_capability_sha256=grant.capability_sha256,
            )
        grants_by_id[grant.capability_sha256] = grant

    if _contains_cycle(grants_by_id):
        return _lineage_denial(LineageFailure.CYCLIC, depth=0)

    known_ids = frozenset(grants_by_id)
    for index, grant in enumerate(grants):
        if (
            grant.parent_capability_sha256 is not None
            and grant.parent_capability_sha256 not in known_ids
        ):
            return _lineage_denial(
                LineageFailure.MISSING,
                depth=index,
                failed_capability_sha256=grant.capability_sha256,
            )

    expected_parent_id: str | None = None
    parent_scope = anchor.scope
    for depth, grant in enumerate(grants, start=1):
        if grant.parent_capability_sha256 != expected_parent_id:
            return _lineage_denial(
                LineageFailure.WRONG_PARENT,
                depth=depth - 1,
                failed_capability_sha256=grant.capability_sha256,
            )
        attenuation = check_attenuation(parent_scope, grant.scope)
        if not attenuation.allowed:
            return _lineage_denial(
                LineageFailure.WIDENED,
                depth=depth,
                failed_capability_sha256=grant.capability_sha256,
                reason=attenuation.reason or DenialReason.SCOPE_AMPLIFICATION,
                attenuation_failure=attenuation.failure,
            )
        expected_parent_id = grant.capability_sha256
        parent_scope = grant.scope

    return LineageResult(
        allowed=True,
        reason=None,
        failure=None,
        depth=len(grants),
    )


__all__ = [
    "MAX_LINEAGE_DEPTH",
    "AttenuationFailure",
    "AttenuationResult",
    "CanaryAction",
    "CapabilityGrant",
    "CapabilityScope",
    "IntegerBounds",
    "LineageFailure",
    "LineageResult",
    "OperatorRootAnchor",
    "TimeBounds",
    "check_attenuation",
    "validate_lineage",
]
