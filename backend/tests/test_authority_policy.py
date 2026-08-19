import hashlib
from dataclasses import FrozenInstanceError, replace

import pytest

from controlgraph_canary.authority import (
    MAX_LINEAGE_DEPTH,
    AttenuationFailure,
    CanaryAction,
    CapabilityGrant,
    CapabilityScope,
    DenialReason,
    IntegerBounds,
    LineageFailure,
    OperatorRootAnchor,
    TimeBounds,
    check_attenuation,
    validate_lineage,
)

ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64


def scope(**overrides: object) -> CapabilityScope:
    values: dict[str, object] = {
        "project_id": "controlgraph-project",
        "region": "us-central1",
        "environment": "acceptance",
        "service_name": "canary-target",
        "root_id": "root-a",
        "root_sha256": ZERO_DIGEST,
        "epoch": 7,
        "plan_sha256": ONE_DIGEST,
        "provider_precondition": "etag-stable-7",
        "request_id": "request-001",
        "idempotency_key": "intent-001",
        "callers": frozenset({"issuer", "executor", "recovery", "verifier"}),
        "audiences": frozenset({"executor-audience", "recovery-audience"}),
        "stable_revision": "stable-00001",
        "candidate_revision": "candidate-00002",
        "revisions": frozenset({"stable-00001", "candidate-00002"}),
        "actions": frozenset(CanaryAction),
        "traffic_percent": IntegerBounds(0, 100),
        "concurrency": IntegerBounds(1, 1_000),
        "validity": TimeBounds(100, 500),
    }
    values.update(overrides)
    return CapabilityScope(**values)  # type: ignore[arg-type]


def narrowed_scope(**overrides: object) -> CapabilityScope:
    values: dict[str, object] = {
        "callers": frozenset({"executor"}),
        "audiences": frozenset({"executor-audience"}),
        "revisions": frozenset({"candidate-00002"}),
        "actions": frozenset({CanaryAction.APPLY_CANARY}),
        "traffic_percent": IntegerBounds(10, 10),
        "concurrency": IntegerBounds(40, 80),
        "validity": TimeBounds(120, 300),
    }
    values.update(overrides)
    return scope(**values)


def grant(
    capability_id: str,
    parent_id: str | None,
    capability_scope: CapabilityScope,
) -> CapabilityGrant:
    return CapabilityGrant(
        capability_sha256=hashlib.sha256(capability_id.encode()).hexdigest(),
        parent_capability_sha256=(
            hashlib.sha256(parent_id.encode()).hexdigest() if parent_id is not None else None
        ),
        scope=capability_scope,
    )


def root_anchor(capability_scope: CapabilityScope) -> OperatorRootAnchor:
    return OperatorRootAnchor(
        root_sha256=capability_scope.root_sha256,
        scope=capability_scope,
    )


def test_scope_is_frozen_and_uses_closed_canary_actions() -> None:
    capability_scope = scope()

    assert {action.value for action in CanaryAction} == {
        "APPLY_CANARY_V1",
        "PROMOTE_CANDIDATE_V1",
        "REVOKE_EPOCH_V1",
        "RECOVER_STABLE_V1",
        "VERIFY_TARGET_V1",
        "PROBE_DATA_PATH_V1",
    }
    with pytest.raises(FrozenInstanceError):
        capability_scope.epoch = 8  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("project_id", ""),
        ("region", "*"),
        ("environment", "prod?"),
        ("service_name", "service[0]"),
        ("root_id", "root-*"),
        ("provider_precondition", "etag-*"),
        ("request_id", "request-*"),
        ("idempotency_key", "intent-*"),
    ],
)
def test_scope_rejects_blank_and_wildcard_exact_bindings(field: str, value: str) -> None:
    with pytest.raises(ValueError):
        scope(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("callers", frozenset()),
        ("callers", frozenset({"executor*"})),
        ("audiences", frozenset({""})),
        ("revisions", frozenset({"candidate?"})),
        ("actions", frozenset()),
        ("actions", frozenset({"APPLY_CANARY_V1"})),
    ],
)
def test_scope_rejects_empty_wildcard_and_open_ended_sets(
    field: str,
    value: frozenset[object],
) -> None:
    with pytest.raises(ValueError):
        scope(**{field: value})


@pytest.mark.parametrize(
    "bounds",
    [IntegerBounds(0, 101), IntegerBounds(1, 100)],
)
def test_scope_enforces_traffic_and_concurrency_limits(bounds: IntegerBounds) -> None:
    if bounds.maximum == 101:
        with pytest.raises(ValueError):
            scope(traffic_percent=bounds)
    else:
        with pytest.raises(ValueError):
            scope(concurrency=IntegerBounds(0, bounds.maximum))


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: IntegerBounds(-1, 1),
        lambda: IntegerBounds(2, 1),
        lambda: IntegerBounds(True, 1),
        lambda: TimeBounds(-1, 1),
        lambda: TimeBounds(2, 2),
        lambda: TimeBounds(2, True),
    ],
)
def test_bounds_reject_malformed_intervals(constructor: object) -> None:
    with pytest.raises(ValueError):
        constructor()  # type: ignore[operator]


def test_equal_and_narrower_scopes_are_allowed() -> None:
    parent = scope()
    child = narrowed_scope()

    assert check_attenuation(parent, parent).allowed is True
    result = check_attenuation(parent, child)
    assert result.allowed is True
    assert result.reason is None
    assert result.failure is None


@pytest.mark.parametrize(
    ("field", "value", "reason", "failure"),
    [
        (
            "project_id",
            "other-project",
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.TARGET,
        ),
        (
            "region",
            "europe-west1",
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.TARGET,
        ),
        (
            "environment",
            "production",
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.TARGET,
        ),
        (
            "service_name",
            "other-service",
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.TARGET,
        ),
        ("root_id", "root-b", DenialReason.LINEAGE_INVALID, AttenuationFailure.ROOT),
        (
            "root_sha256",
            ONE_DIGEST,
            DenialReason.LINEAGE_INVALID,
            AttenuationFailure.ROOT_DIGEST,
        ),
        ("epoch", 8, DenialReason.EPOCH_MISMATCH, AttenuationFailure.EPOCH),
        (
            "plan_sha256",
            ZERO_DIGEST,
            DenialReason.CLAIM_BINDING_MISMATCH,
            AttenuationFailure.PLAN,
        ),
        (
            "provider_precondition",
            "etag-stable-8",
            DenialReason.TARGET_BINDING_MISMATCH,
            AttenuationFailure.PRECONDITION,
        ),
        (
            "request_id",
            "request-002",
            DenialReason.CLAIM_BINDING_MISMATCH,
            AttenuationFailure.REQUEST,
        ),
        (
            "idempotency_key",
            "intent-002",
            DenialReason.CLAIM_BINDING_MISMATCH,
            AttenuationFailure.IDEMPOTENCY,
        ),
    ],
)
def test_exact_target_root_and_epoch_cannot_change(
    field: str,
    value: object,
    reason: DenialReason,
    failure: AttenuationFailure,
) -> None:
    result = check_attenuation(scope(), replace(narrowed_scope(), **{field: value}))

    assert result.allowed is False
    assert result.reason is reason
    assert result.failure is failure


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        (
            "callers",
            frozenset({"executor", "unknown-caller"}),
            AttenuationFailure.CALLERS,
        ),
        (
            "audiences",
            frozenset({"executor-audience", "unknown-audience"}),
            AttenuationFailure.AUDIENCES,
        ),
        (
            "revisions",
            frozenset({"stable-00001", "candidate-00002"}),
            AttenuationFailure.REVISIONS,
        ),
        (
            "actions",
            frozenset({CanaryAction.APPLY_CANARY, CanaryAction.PROMOTE_CANDIDATE}),
            AttenuationFailure.ACTIONS,
        ),
        ("traffic_percent", IntegerBounds(9, 10), AttenuationFailure.TRAFFIC),
        ("traffic_percent", IntegerBounds(10, 11), AttenuationFailure.TRAFFIC),
        ("concurrency", IntegerBounds(39, 80), AttenuationFailure.CONCURRENCY),
        ("concurrency", IntegerBounds(40, 81), AttenuationFailure.CONCURRENCY),
        ("validity", TimeBounds(99, 300), AttenuationFailure.TIME),
        ("validity", TimeBounds(120, 301), AttenuationFailure.TIME),
    ],
)
def test_child_cannot_widen_sets_ranges_or_lifetime(
    field: str,
    value: object,
    failure: AttenuationFailure,
) -> None:
    parent = narrowed_scope()
    child = replace(parent, **{field: value})

    result = check_attenuation(parent, child)

    assert result.allowed is False
    assert result.reason is DenialReason.SCOPE_AMPLIFICATION
    assert result.failure is failure


@pytest.mark.parametrize(
    ("changes", "failure"),
    [
        (
            {
                "stable_revision": "stable-00003",
                "revisions": frozenset({"stable-00003", "candidate-00002"}),
            },
            AttenuationFailure.STABLE_REVISION,
        ),
        (
            {
                "candidate_revision": "candidate-00003",
                "revisions": frozenset({"stable-00001", "candidate-00003"}),
            },
            AttenuationFailure.CANDIDATE_REVISION,
        ),
        (
            {
                "stable_revision": "candidate-00002",
                "candidate_revision": "stable-00001",
            },
            AttenuationFailure.STABLE_REVISION,
        ),
    ],
)
def test_revision_roles_cannot_be_substituted(
    changes: dict[str, object],
    failure: AttenuationFailure,
) -> None:
    result = check_attenuation(scope(), replace(narrowed_scope(), **changes))

    assert result.allowed is False
    assert result.reason is DenialReason.TARGET_BINDING_MISMATCH
    assert result.failure is failure


def test_valid_lineage_terminates_at_expected_operator_root() -> None:
    anchor = root_anchor(scope())
    first_scope = scope(
        callers=frozenset({"executor", "recovery"}),
        audiences=frozenset({"executor-audience", "recovery-audience"}),
        actions=frozenset({CanaryAction.APPLY_CANARY, CanaryAction.RECOVER_STABLE}),
        traffic_percent=IntegerBounds(0, 90),
        concurrency=IntegerBounds(20, 100),
        validity=TimeBounds(110, 400),
    )
    second_scope = narrowed_scope(validity=TimeBounds(150, 250))
    grants = (
        grant("capability-1", None, first_scope),
        grant("capability-2", "capability-1", second_scope),
    )

    result = validate_lineage(anchor, grants)

    assert result.allowed is True
    assert result.reason is None
    assert result.failure is None
    assert result.depth == 2


def test_missing_lineage_is_denied() -> None:
    anchor = root_anchor(scope())

    result = validate_lineage(anchor, ())

    assert result.allowed is False
    assert result.reason is DenialReason.LINEAGE_INVALID
    assert result.failure is LineageFailure.MISSING


def test_duplicate_capability_id_is_denied() -> None:
    anchor = root_anchor(scope())
    first = grant("duplicate", None, narrowed_scope())
    duplicate = grant("duplicate", "duplicate", narrowed_scope())

    result = validate_lineage(anchor, (first, duplicate))

    assert result.reason is DenialReason.LINEAGE_INVALID
    assert result.failure is LineageFailure.DUPLICATE
    assert result.failed_capability_sha256 == hashlib.sha256(b"duplicate").hexdigest()


def test_cyclic_lineage_is_denied() -> None:
    anchor = root_anchor(scope())
    first = grant("capability-1", "capability-2", narrowed_scope())
    second = grant("capability-2", "capability-1", narrowed_scope())

    result = validate_lineage(anchor, (first, second))

    assert result.reason is DenialReason.LINEAGE_INVALID
    assert result.failure is LineageFailure.CYCLIC


def test_missing_parent_is_denied() -> None:
    anchor = root_anchor(scope())
    orphan = grant("capability-1", "missing-parent", narrowed_scope())

    result = validate_lineage(anchor, (orphan,))

    assert result.reason is DenialReason.LINEAGE_INVALID
    assert result.failure is LineageFailure.MISSING
    assert result.failed_capability_sha256 == hashlib.sha256(b"capability-1").hexdigest()


def test_wrong_parent_in_ordered_chain_is_denied() -> None:
    anchor = root_anchor(scope())
    first = grant("capability-1", None, narrowed_scope())
    third = grant("capability-3", "capability-1", narrowed_scope())
    second = grant("capability-2", "capability-3", narrowed_scope())

    result = validate_lineage(anchor, (first, second, third))

    assert result.reason is DenialReason.LINEAGE_INVALID
    assert result.failure is LineageFailure.WRONG_PARENT
    assert result.failed_capability_sha256 == hashlib.sha256(b"capability-2").hexdigest()


def test_widened_lineage_hop_returns_stable_policy_reason() -> None:
    parent_scope = narrowed_scope()
    anchor = root_anchor(parent_scope)
    widened = replace(
        parent_scope,
        actions=frozenset({CanaryAction.APPLY_CANARY, CanaryAction.PROMOTE_CANDIDATE}),
    )

    result = validate_lineage(
        anchor,
        (grant("capability-1", None, widened),),
    )

    assert result.reason is DenialReason.SCOPE_AMPLIFICATION
    assert result.failure is LineageFailure.WIDENED
    assert result.attenuation_failure is AttenuationFailure.ACTIONS


def test_wrong_epoch_in_lineage_preserves_epoch_reason() -> None:
    anchor = root_anchor(scope())
    wrong_epoch = replace(narrowed_scope(), epoch=8)

    result = validate_lineage(
        anchor,
        (grant("capability-1", None, wrong_epoch),),
    )

    assert result.reason is DenialReason.EPOCH_MISMATCH
    assert result.failure is LineageFailure.WIDENED
    assert result.attenuation_failure is AttenuationFailure.EPOCH


def test_lineage_enforces_configured_and_system_maximum_depth() -> None:
    anchor = root_anchor(scope())
    grants = (
        grant("capability-1", None, narrowed_scope()),
        grant("capability-2", "capability-1", narrowed_scope()),
        grant("capability-3", "capability-2", narrowed_scope()),
    )

    too_deep = validate_lineage(anchor, grants, max_depth=2)
    invalid_limit = validate_lineage(anchor, grants, max_depth=MAX_LINEAGE_DEPTH + 1)

    assert too_deep.reason is DenialReason.LINEAGE_INVALID
    assert too_deep.failure is LineageFailure.MAX_DEPTH_EXCEEDED
    assert invalid_limit.reason is DenialReason.CONTRACT_INVALID
    assert invalid_limit.failure is LineageFailure.INVALID_MAX_DEPTH
