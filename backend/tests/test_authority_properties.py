import hashlib
import json
import string
from dataclasses import dataclass, replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from controlgraph_canary.authority import (
    MAX_LINEAGE_DEPTH,
    AttenuationFailure,
    CanaryAction,
    CapabilityGrant,
    CapabilityScope,
    DenialReason,
    EpochAdvanceCause,
    EpochAdvanceOutcome,
    EpochAdvanceRequest,
    EpochAuthority,
    EpochCheckOutcome,
    FactStatus,
    IntegerBounds,
    LineageFailure,
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    OperatorRootAnchor,
    ProviderAttemptResult,
    ProviderOutcome,
    ReducerFacts,
    ReducerInput,
    ReducerOutput,
    ReplayAction,
    ReplayReceipt,
    ReplayReceiptOutcome,
    RolloutEvent,
    RolloutState,
    TimeBounds,
    TransportAction,
    TransportFailure,
    check_attenuation,
    check_epoch,
    claim_receipt,
    compare_and_advance,
    decide_replay,
    decide_transport_failure,
    mark_provider_attempted,
    mutation_identity,
    record_pre_dispatch_failure,
    record_provider_result,
    record_readback,
    reduce_rollout,
    validate_lineage,
)
from controlgraph_canary.contracts import (
    ContractError,
    TargetBinding,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)

PROPERTY_SETTINGS = settings(
    max_examples=100,
    derandomize=True,
    deadline=None,
    database=None,
    print_blob=True,
)

_LOWER_ALPHANUMERIC = string.ascii_lowercase + string.digits
_IDENTIFIER_SUFFIX = st.text(alphabet=_LOWER_ALPHANUMERIC, min_size=1, max_size=12)
_DIGESTS = st.binary(min_size=32, max_size=32).map(bytes.hex)
_OPTIONAL_DENIAL_REASONS = st.one_of(st.none(), st.sampled_from(tuple(DenialReason)))


def _identifier(prefix: str) -> st.SearchStrategy[str]:
    return _IDENTIFIER_SUFFIX.map(lambda suffix: f"{prefix}-{suffix}")


def _label_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@st.composite
def _target_bindings(draw: st.DrawFn) -> TargetBinding:
    project_middle = draw(
        st.text(
            alphabet=string.ascii_lowercase + string.digits + "-",
            min_size=4,
            max_size=20,
        )
    )
    service_suffix = draw(st.text(alphabet=_LOWER_ALPHANUMERIC, max_size=30))
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=f"p{project_middle}0",
        region=draw(st.sampled_from(("us-central1", "europe-west1", "asia-east1"))),
        environment=draw(_identifier("environment")),
        service_name=f"s{service_suffix}",
    )


@st.composite
def _reducer_facts(draw: st.DrawFn) -> ReducerFacts:
    return ReducerFacts(
        authorization=draw(st.sampled_from(tuple(FactStatus))),
        authority=draw(st.sampled_from(tuple(FactStatus))),
        time_window=draw(st.sampled_from(tuple(FactStatus))),
        observation=draw(st.sampled_from(tuple(FactStatus))),
        provider_outcome=draw(st.sampled_from(tuple(ProviderOutcome))),
    )


def _reduce_history(
    initial_state: RolloutState,
    steps: tuple[tuple[RolloutEvent, ReducerFacts, DenialReason | None], ...],
) -> tuple[ReducerOutput, ...]:
    state = initial_state
    ambiguity_origin: RolloutState | None = None
    outputs: list[ReducerOutput] = []
    for event, facts, denial_reason in steps:
        result = reduce_rollout(
            ReducerInput(
                state=state,
                event=event,
                facts=facts,
                denial_reason=denial_reason,
                ambiguity_origin=ambiguity_origin,
            )
        )
        outputs.append(result)
        state = result.state
        ambiguity_origin = result.ambiguity_origin
    return tuple(outputs)


@st.composite
def _capability_scopes(draw: st.DrawFn) -> CapabilityScope:
    traffic_minimum = draw(st.integers(min_value=0, max_value=100))
    traffic_maximum = draw(st.integers(min_value=traffic_minimum, max_value=100))
    concurrency_minimum = draw(st.integers(min_value=1, max_value=1_000))
    concurrency_maximum = draw(st.integers(min_value=concurrency_minimum, max_value=1_000))
    not_before = draw(st.integers(min_value=0, max_value=1_000_000))
    expires_at = draw(st.integers(min_value=not_before + 1, max_value=not_before + 10_000))
    stable_revision = draw(_identifier("stable"))
    candidate_revision = draw(_identifier("candidate"))
    return CapabilityScope(
        project_id=draw(_identifier("project")),
        region=draw(st.sampled_from(("us-central1", "europe-west1", "asia-east1"))),
        environment=draw(_identifier("environment")),
        service_name=draw(_identifier("service")),
        root_id=draw(_identifier("root")),
        root_sha256=draw(_DIGESTS),
        epoch=draw(st.integers(min_value=1, max_value=1_000_000)),
        plan_sha256=draw(_DIGESTS),
        provider_precondition=draw(_identifier("etag")),
        request_id=draw(_identifier("request")),
        idempotency_key=draw(_identifier("idempotency")),
        callers=draw(
            st.sets(
                st.sampled_from(("caller-a", "caller-b", "caller-c", "caller-d")),
                min_size=1,
                max_size=4,
            ).map(frozenset)
        ),
        audiences=draw(
            st.sets(
                st.sampled_from(("audience-a", "audience-b", "audience-c")),
                min_size=1,
                max_size=3,
            ).map(frozenset)
        ),
        stable_revision=stable_revision,
        candidate_revision=candidate_revision,
        revisions=frozenset({stable_revision, candidate_revision}),
        actions=draw(
            st.sets(
                st.sampled_from(tuple(CanaryAction)),
                min_size=1,
                max_size=len(CanaryAction),
            ).map(frozenset)
        ),
        traffic_percent=IntegerBounds(traffic_minimum, traffic_maximum),
        concurrency=IntegerBounds(concurrency_minimum, concurrency_maximum),
        validity=TimeBounds(not_before, expires_at),
    )


def _nonempty_subset(values: frozenset[object]) -> st.SearchStrategy[frozenset[object]]:
    ordered = sorted(values, key=str)
    return st.sets(
        st.sampled_from(ordered),
        min_size=1,
        max_size=len(ordered),
    ).map(frozenset)


@st.composite
def _narrowed_scope(draw: st.DrawFn, parent: CapabilityScope) -> CapabilityScope:
    traffic_minimum = draw(
        st.integers(
            min_value=parent.traffic_percent.minimum,
            max_value=parent.traffic_percent.maximum,
        )
    )
    traffic_maximum = draw(
        st.integers(
            min_value=traffic_minimum,
            max_value=parent.traffic_percent.maximum,
        )
    )
    concurrency_minimum = draw(
        st.integers(
            min_value=parent.concurrency.minimum,
            max_value=parent.concurrency.maximum,
        )
    )
    concurrency_maximum = draw(
        st.integers(
            min_value=concurrency_minimum,
            max_value=parent.concurrency.maximum,
        )
    )
    not_before = draw(
        st.integers(
            min_value=parent.validity.not_before,
            max_value=parent.validity.expires_at - 1,
        )
    )
    expires_at = draw(st.integers(min_value=not_before + 1, max_value=parent.validity.expires_at))
    return replace(
        parent,
        callers=draw(_nonempty_subset(parent.callers)),
        audiences=draw(_nonempty_subset(parent.audiences)),
        revisions=draw(_nonempty_subset(parent.revisions)),
        actions=draw(_nonempty_subset(parent.actions)),
        traffic_percent=IntegerBounds(traffic_minimum, traffic_maximum),
        concurrency=IntegerBounds(concurrency_minimum, concurrency_maximum),
        validity=TimeBounds(not_before, expires_at),
    )


@st.composite
def _lineage_cases(
    draw: st.DrawFn,
) -> tuple[OperatorRootAnchor, tuple[CapabilityGrant, ...]]:
    scope = draw(_capability_scopes())
    anchor = OperatorRootAnchor(root_sha256=scope.root_sha256, scope=scope)
    depth = draw(st.integers(min_value=2, max_value=6))
    grants: list[CapabilityGrant] = []
    parent_sha256: str | None = None
    for index in range(1, depth + 1):
        scope = draw(_narrowed_scope(scope))
        capability_sha256 = _label_digest(f"capability-{index}")
        grants.append(
            CapabilityGrant(
                capability_sha256=capability_sha256,
                parent_capability_sha256=parent_sha256,
                scope=scope,
            )
        )
        parent_sha256 = capability_sha256
    return anchor, tuple(grants)


@st.composite
def _mutation_bindings(draw: st.DrawFn) -> MutationBinding:
    return MutationBinding(
        idempotency_key=draw(_identifier("idempotency")),
        request_id=draw(_identifier("request")),
        root_id=draw(_identifier("root")),
        root_sha256=draw(_DIGESTS),
        epoch=draw(st.integers(min_value=1, max_value=1_000_000)),
        action=draw(st.sampled_from(tuple(MutationAction))),
        target=MutationTargetKey(
            project_id=draw(_identifier("project")),
            region=draw(st.sampled_from(("us-central1", "europe-west1", "asia-east1"))),
            environment=draw(_identifier("environment")),
            service_name=draw(_identifier("service")),
        ),
        provider_precondition=draw(_identifier("etag")),
        plan_sha256=draw(_DIGESTS),
        capability_sha256=draw(_DIGESTS),
        payload_sha256=draw(_DIGESTS),
        expected_poststate_sha256=draw(_DIGESTS),
    )


def _different_text(value: str, replacement: str) -> str:
    return replacement if value != replacement else f"{replacement}-other"


def _different_digest(value: str) -> str:
    first = "0" if value[0] != "0" else "1"
    return first + value[1:]


def _different_action(value: MutationAction) -> MutationAction:
    actions = tuple(MutationAction)
    return actions[(actions.index(value) + 1) % len(actions)]


def _alter_binding(value: MutationBinding, field: str) -> MutationBinding:
    if field == "idempotency_key":
        return replace(
            value,
            idempotency_key=_different_text(value.idempotency_key, "idempotency-other"),
        )
    if field == "request_id":
        return replace(
            value,
            request_id=_different_text(value.request_id, "request-other"),
        )
    if field == "root_id":
        return replace(value, root_id=_different_text(value.root_id, "root-other"))
    if field == "root_sha256":
        return replace(value, root_sha256=_different_digest(value.root_sha256))
    if field == "epoch":
        return replace(value, epoch=value.epoch + 1)
    if field == "action":
        return replace(value, action=_different_action(value.action))
    if field in {"project_id", "region", "environment", "service_name"}:
        changed = _different_text(getattr(value.target, field), f"{field}-other")
        return replace(value, target=replace(value.target, **{field: changed}))
    if field == "provider_precondition":
        return replace(
            value,
            provider_precondition=_different_text(
                value.provider_precondition,
                "etag-other",
            ),
        )
    if field == "plan_sha256":
        return replace(value, plan_sha256=_different_digest(value.plan_sha256))
    if field == "capability_sha256":
        return replace(
            value,
            capability_sha256=_different_digest(value.capability_sha256),
        )
    if field == "payload_sha256":
        return replace(value, payload_sha256=_different_digest(value.payload_sha256))
    if field == "expected_poststate_sha256":
        return replace(
            value,
            expected_poststate_sha256=_different_digest(value.expected_poststate_sha256),
        )
    raise AssertionError(f"unknown mutation binding field: {field}")


_MUTATION_FIELDS = (
    "idempotency_key",
    "request_id",
    "root_id",
    "root_sha256",
    "epoch",
    "action",
    "project_id",
    "region",
    "environment",
    "service_name",
    "provider_precondition",
    "plan_sha256",
    "capability_sha256",
    "payload_sha256",
    "expected_poststate_sha256",
)


@dataclass(frozen=True, slots=True)
class _ReceiptClaimStore:
    revision: int
    receipt: ReplayReceipt | None
    owner: str | None


@dataclass(frozen=True, slots=True)
class _EpochAuthorityStore:
    revision: int
    authority: EpochAuthority
    owner: str | None


def _commit_epoch_advance(
    store: _EpochAuthorityStore,
    *,
    snapshot_revision: int,
    owner: str,
    request: EpochAdvanceRequest,
) -> tuple[_EpochAuthorityStore, bool]:
    if store.revision != snapshot_revision:
        return store, False
    result = compare_and_advance(store.authority, request)
    if not result.advanced:
        return store, False
    return (
        _EpochAuthorityStore(
            revision=store.revision + 1,
            authority=result.authority,
            owner=owner,
        ),
        True,
    )


def _commit_initial_claim(
    store: _ReceiptClaimStore,
    *,
    snapshot_revision: int,
    owner: str,
    binding: MutationBinding,
) -> tuple[_ReceiptClaimStore, bool]:
    if store.revision != snapshot_revision:
        return store, False
    decision = decide_replay(binding, store.receipt)
    if decision.action is not ReplayAction.CLAIM_NEW or decision.receipt is None:
        return store, False
    return (
        _ReceiptClaimStore(
            revision=store.revision + 1,
            receipt=decision.receipt,
            owner=owner,
        ),
        True,
    )


def _commit_provider_attempt(
    store: _ReceiptClaimStore,
    *,
    snapshot_revision: int,
    owner: str,
    binding: MutationBinding,
) -> tuple[_ReceiptClaimStore, bool]:
    if store.revision != snapshot_revision:
        return store, False
    decision = decide_replay(binding, store.receipt)
    if decision.action is not ReplayAction.RESUME_PRE_DISPATCH or decision.receipt is None:
        return store, False
    return (
        _ReceiptClaimStore(
            revision=store.revision + 1,
            receipt=mark_provider_attempted(decision.receipt),
            owner=owner,
        ),
        True,
    )


@PROPERTY_SETTINGS
@given(target=_target_bindings())
def test_contract_canonical_round_trip_and_order_rejection(target: TargetBinding) -> None:
    encoded = canonical_json_bytes(target)

    assert decode_contract(encoded, TargetBinding) == target
    assert canonical_json_bytes(target) == encoded
    assert canonical_sha256(target) == canonical_sha256(target)

    value = target.model_dump(mode="json")
    reordered = {key: value[key] for key in reversed(value)}
    noncanonical = json.dumps(reordered, separators=(",", ":")).encode()
    assert noncanonical != encoded
    with pytest.raises(ContractError):
        decode_contract(noncanonical, TargetBinding)


@PROPERTY_SETTINGS
@given(
    initial_state=st.sampled_from(tuple(RolloutState)),
    steps=st.lists(
        st.tuples(
            st.sampled_from(tuple(RolloutEvent)),
            _reducer_facts(),
            _OPTIONAL_DENIAL_REASONS,
        ),
        min_size=1,
        max_size=24,
    ).map(tuple),
)
def test_generated_rollout_histories_are_deterministic(
    initial_state: RolloutState,
    steps: tuple[tuple[RolloutEvent, ReducerFacts, DenialReason | None], ...],
) -> None:
    first = _reduce_history(initial_state, steps)
    second = _reduce_history(initial_state, steps)

    assert first == second
    for result in first:
        if not result.transition_valid:
            assert result.commands == ()
        if result.state is RolloutState.DENIED:
            assert result.commands == ()


@PROPERTY_SETTINGS
@given(
    root_id=_identifier("root"),
    epoch=st.integers(min_value=2, max_value=1_000_000),
)
def test_epoch_checks_require_exact_root_scoped_equality(root_id: str, epoch: int) -> None:
    current = check_epoch(
        token_root_id=root_id,
        token_epoch=epoch,
        authority_root_id=root_id,
        current_epoch=epoch,
    )
    stale = check_epoch(
        token_root_id=root_id,
        token_epoch=epoch - 1,
        authority_root_id=root_id,
        current_epoch=epoch,
    )
    future = check_epoch(
        token_root_id=root_id,
        token_epoch=epoch + 1,
        authority_root_id=root_id,
        current_epoch=epoch,
    )
    wrong_root = check_epoch(
        token_root_id=f"{root_id}-other",
        token_epoch=epoch,
        authority_root_id=root_id,
        current_epoch=epoch,
    )

    assert current.outcome is EpochCheckOutcome.CURRENT
    assert current.authorized is True
    assert stale.outcome is EpochCheckOutcome.STALE
    assert future.outcome is EpochCheckOutcome.FUTURE
    assert wrong_root.outcome is EpochCheckOutcome.ROOT_MISMATCH
    assert all(not result.authorized for result in (stale, future, wrong_root))


@PROPERTY_SETTINGS
@given(
    root_id=_identifier("root"),
    epoch=st.integers(min_value=1, max_value=1_000_000),
    cause=st.sampled_from(tuple(EpochAdvanceCause)),
)
def test_epoch_advance_is_monotonic_and_rejects_reused_authority(
    root_id: str,
    epoch: int,
    cause: EpochAdvanceCause,
) -> None:
    authority = EpochAuthority(root_id=root_id, epoch=epoch)
    request = EpochAdvanceRequest(
        root_id=root_id,
        expected_epoch=epoch,
        requested_epoch=epoch + 1,
        actor_id="operator",
        cause=cause,
        request_id="request-1",
        evidence_id="evidence-1",
    )

    winner = compare_and_advance(authority, request)
    loser = compare_and_advance(winner.authority, request)
    skipped = compare_and_advance(
        authority,
        replace(request, requested_epoch=epoch + 2),
    )
    wrong_root = compare_and_advance(
        authority,
        replace(request, root_id=f"{root_id}-other"),
    )

    assert winner.outcome is EpochAdvanceOutcome.ADVANCED
    assert winner.authority == EpochAuthority(root_id=root_id, epoch=epoch + 1)
    assert winner.transition is not None
    assert (winner.transition.prior_epoch, winner.transition.new_epoch) == (epoch, epoch + 1)
    assert loser.outcome is EpochAdvanceOutcome.STALE
    assert loser.authority == winner.authority
    assert skipped.outcome is EpochAdvanceOutcome.INVALID
    assert skipped.authority == authority
    assert wrong_root.outcome is EpochAdvanceOutcome.ROOT_MISMATCH
    assert wrong_root.authority == authority


@PROPERTY_SETTINGS
@given(
    root_id=_identifier("root"),
    epoch=st.integers(min_value=1, max_value=1_000_000),
    cause=st.sampled_from(tuple(EpochAdvanceCause)),
    contender_order=st.lists(
        _identifier("contender"),
        min_size=2,
        max_size=16,
        unique=True,
    ),
    initial_revision=st.integers(min_value=0, max_value=1_000_000),
)
def test_transactional_epoch_race_has_one_cas_winner(
    root_id: str,
    epoch: int,
    cause: EpochAdvanceCause,
    contender_order: list[str],
    initial_revision: int,
) -> None:
    store = _EpochAuthorityStore(
        revision=initial_revision,
        authority=EpochAuthority(root_id=root_id, epoch=epoch),
        owner=None,
    )
    winners: list[str] = []

    for contender in contender_order:
        request = EpochAdvanceRequest(
            root_id=root_id,
            expected_epoch=epoch,
            requested_epoch=epoch + 1,
            actor_id=contender,
            cause=cause,
            request_id=f"request-{contender}",
            evidence_id=f"evidence-{contender}",
        )
        store, committed = _commit_epoch_advance(
            store,
            snapshot_revision=initial_revision,
            owner=contender,
            request=request,
        )
        if committed:
            winners.append(contender)

    assert winners == contender_order[:1]
    assert store.revision == initial_revision + 1
    assert store.authority == EpochAuthority(root_id=root_id, epoch=epoch + 1)
    assert store.owner == contender_order[0]


@PROPERTY_SETTINGS
@given(parent=_capability_scopes(), data=st.data())
def test_attenuation_is_reflexive_and_transitive(
    parent: CapabilityScope,
    data: st.DataObject,
) -> None:
    child = data.draw(_narrowed_scope(parent), label="child")
    grandchild = data.draw(_narrowed_scope(child), label="grandchild")

    assert check_attenuation(parent, parent).allowed is True
    assert check_attenuation(parent, child).allowed is True
    assert check_attenuation(child, grandchild).allowed is True
    assert check_attenuation(parent, grandchild).allowed is True


@PROPERTY_SETTINGS
@given(
    parent=_capability_scopes(),
    field=st.sampled_from(
        (
            "callers",
            "audiences",
            "revisions",
            "actions",
            "traffic_percent",
            "concurrency",
            "validity",
        )
    ),
)
def test_generated_scope_widening_is_rejected(
    parent: CapabilityScope,
    field: str,
) -> None:
    expected: AttenuationFailure
    if field == "callers":
        child = replace(parent, callers=parent.callers | {"caller-outside"})
        expected = AttenuationFailure.CALLERS
    elif field == "audiences":
        child = replace(parent, audiences=parent.audiences | {"audience-outside"})
        expected = AttenuationFailure.AUDIENCES
    elif field == "revisions":
        parent = replace(parent, revisions=frozenset({parent.candidate_revision}))
        child = replace(
            parent,
            revisions=frozenset({parent.stable_revision, parent.candidate_revision}),
        )
        expected = AttenuationFailure.REVISIONS
    elif field == "actions":
        parent = replace(parent, actions=frozenset({CanaryAction.APPLY_CANARY}))
        child = replace(
            parent,
            actions=frozenset({CanaryAction.APPLY_CANARY, CanaryAction.PROMOTE_CANDIDATE}),
        )
        expected = AttenuationFailure.ACTIONS
    elif field == "traffic_percent":
        parent = replace(parent, traffic_percent=IntegerBounds(10, 90))
        child = replace(parent, traffic_percent=IntegerBounds(9, 90))
        expected = AttenuationFailure.TRAFFIC
    elif field == "concurrency":
        parent = replace(parent, concurrency=IntegerBounds(10, 900))
        child = replace(parent, concurrency=IntegerBounds(9, 900))
        expected = AttenuationFailure.CONCURRENCY
    else:
        parent = replace(parent, validity=TimeBounds(10, 100))
        child = replace(parent, validity=TimeBounds(9, 100))
        expected = AttenuationFailure.TIME

    result = check_attenuation(parent, child)

    assert result.allowed is False
    assert result.reason is DenialReason.SCOPE_AMPLIFICATION
    assert result.failure is expected


@PROPERTY_SETTINGS
@given(
    parent=_capability_scopes(),
    field=st.sampled_from(
        (
            "root_sha256",
            "plan_sha256",
            "provider_precondition",
            "request_id",
            "idempotency_key",
            "stable_revision",
            "candidate_revision",
        )
    ),
)
def test_immutable_scope_bindings_cannot_change(
    parent: CapabilityScope,
    field: str,
) -> None:
    if field == "root_sha256":
        child = replace(parent, root_sha256=_different_digest(parent.root_sha256))
        expected_reason = DenialReason.LINEAGE_INVALID
        expected_failure = AttenuationFailure.ROOT_DIGEST
    elif field == "plan_sha256":
        child = replace(parent, plan_sha256=_different_digest(parent.plan_sha256))
        expected_reason = DenialReason.CLAIM_BINDING_MISMATCH
        expected_failure = AttenuationFailure.PLAN
    elif field == "provider_precondition":
        child = replace(
            parent,
            provider_precondition=_different_text(
                parent.provider_precondition,
                "etag-other",
            ),
        )
        expected_reason = DenialReason.TARGET_BINDING_MISMATCH
        expected_failure = AttenuationFailure.PRECONDITION
    elif field == "request_id":
        child = replace(
            parent,
            request_id=_different_text(parent.request_id, "request-other"),
        )
        expected_reason = DenialReason.CLAIM_BINDING_MISMATCH
        expected_failure = AttenuationFailure.REQUEST
    elif field == "idempotency_key":
        child = replace(
            parent,
            idempotency_key=_different_text(
                parent.idempotency_key,
                "idempotency-other",
            ),
        )
        expected_reason = DenialReason.CLAIM_BINDING_MISMATCH
        expected_failure = AttenuationFailure.IDEMPOTENCY
    elif field == "stable_revision":
        changed = _different_text(parent.stable_revision, "stable-other")
        child = replace(
            parent,
            stable_revision=changed,
            revisions=frozenset({changed, parent.candidate_revision}),
        )
        expected_reason = DenialReason.TARGET_BINDING_MISMATCH
        expected_failure = AttenuationFailure.STABLE_REVISION
    else:
        changed = _different_text(parent.candidate_revision, "candidate-other")
        child = replace(
            parent,
            candidate_revision=changed,
            revisions=frozenset({parent.stable_revision, changed}),
        )
        expected_reason = DenialReason.TARGET_BINDING_MISMATCH
        expected_failure = AttenuationFailure.CANDIDATE_REVISION

    result = check_attenuation(parent, child)

    assert result.allowed is False
    assert result.reason is expected_reason
    assert result.failure is expected_failure


@PROPERTY_SETTINGS
@given(parent=_capability_scopes())
def test_lineage_accepts_minimum_and_maximum_depth(parent: CapabilityScope) -> None:
    anchor = OperatorRootAnchor(root_sha256=parent.root_sha256, scope=parent)
    grants = tuple(
        CapabilityGrant(
            capability_sha256=_label_digest(f"capability-{index}"),
            parent_capability_sha256=(
                None if index == 1 else _label_digest(f"capability-{index - 1}")
            ),
            scope=parent,
        )
        for index in range(1, MAX_LINEAGE_DEPTH + 1)
    )

    minimum = validate_lineage(anchor, grants[:1])
    maximum = validate_lineage(anchor, grants)
    too_deep_for_limit = validate_lineage(
        anchor,
        grants,
        max_depth=MAX_LINEAGE_DEPTH - 1,
    )

    assert minimum.allowed is True
    assert minimum.depth == 1
    assert maximum.allowed is True
    assert maximum.depth == MAX_LINEAGE_DEPTH
    assert too_deep_for_limit.allowed is False
    assert too_deep_for_limit.failure is LineageFailure.MAX_DEPTH_EXCEEDED


@PROPERTY_SETTINGS
@given(case=_lineage_cases())
def test_generated_lineage_reordering_fails_closed(
    case: tuple[OperatorRootAnchor, tuple[CapabilityGrant, ...]],
) -> None:
    anchor, grants = case

    valid = validate_lineage(anchor, grants)
    reordered = validate_lineage(anchor, grants[1:] + grants[:1])

    assert valid.allowed is True
    assert valid.depth == len(grants)
    assert reordered.allowed is False
    assert reordered.reason is DenialReason.LINEAGE_INVALID
    assert reordered.failure is LineageFailure.WRONG_PARENT


@PROPERTY_SETTINGS
@given(
    case=_lineage_cases(),
    malformed=st.sampled_from(
        ("missing", "unknown", "cyclic", "duplicate", "reordered", "max_depth")
    ),
)
def test_generated_malformed_lineage_is_denied(
    case: tuple[OperatorRootAnchor, tuple[CapabilityGrant, ...]],
    malformed: str,
) -> None:
    anchor, grants = case
    max_depth = MAX_LINEAGE_DEPTH
    if malformed == "missing":
        candidate: tuple[CapabilityGrant, ...] = ()
        expected = LineageFailure.MISSING
    elif malformed == "unknown":
        candidate = (
            replace(
                grants[0],
                parent_capability_sha256=_label_digest("unknown-parent"),
            ),
            *grants[1:],
        )
        expected = LineageFailure.MISSING
    elif malformed == "cyclic":
        candidate = (
            replace(
                grants[0],
                parent_capability_sha256=grants[1].capability_sha256,
            ),
            replace(
                grants[1],
                parent_capability_sha256=grants[0].capability_sha256,
            ),
            *grants[2:],
        )
        expected = LineageFailure.CYCLIC
    elif malformed == "duplicate":
        candidate = (
            grants[0],
            replace(
                grants[1],
                capability_sha256=grants[0].capability_sha256,
            ),
            *grants[2:],
        )
        expected = LineageFailure.DUPLICATE
    elif malformed == "reordered":
        candidate = grants[1:] + grants[:1]
        expected = LineageFailure.WRONG_PARENT
    else:
        candidate = grants
        max_depth = len(grants) - 1
        expected = LineageFailure.MAX_DEPTH_EXCEEDED

    result = validate_lineage(anchor, candidate, max_depth=max_depth)

    assert result.allowed is False
    assert result.failure is expected


@PROPERTY_SETTINGS
@given(
    binding=_mutation_bindings(),
    field=st.sampled_from(_MUTATION_FIELDS),
)
def test_mutation_identity_binds_every_exact_field(
    binding: MutationBinding,
    field: str,
) -> None:
    identity = mutation_identity(binding)
    altered = _alter_binding(binding, field)

    assert mutation_identity(binding) == identity
    assert len(identity) == 64
    assert mutation_identity(altered) != identity


@PROPERTY_SETTINGS
@given(
    binding=_mutation_bindings(),
    field=st.sampled_from(_MUTATION_FIELDS[1:]),
)
def test_exact_duplicate_resumes_but_altered_replay_conflicts(
    binding: MutationBinding,
    field: str,
) -> None:
    stored = claim_receipt(binding)

    exact = decide_replay(binding, stored)
    conflict = decide_replay(_alter_binding(binding, field), stored)

    assert exact.action is ReplayAction.RESUME_PRE_DISPATCH
    assert exact.may_enter_dispatch is True
    assert conflict.action is ReplayAction.DENY_CONFLICT
    assert conflict.reason is DenialReason.IDEMPOTENCY_CONFLICT
    assert conflict.may_enter_dispatch is False


@PROPERTY_SETTINGS
@given(
    binding=_mutation_bindings(),
    contender_order=st.lists(
        _identifier("contender"),
        min_size=2,
        max_size=16,
        unique=True,
    ),
)
def test_transactional_claim_race_has_one_initial_winner(
    binding: MutationBinding,
    contender_order: list[str],
) -> None:
    store = _ReceiptClaimStore(revision=0, receipt=None, owner=None)
    winners: list[str] = []

    for contender in contender_order:
        store, committed = _commit_initial_claim(
            store,
            snapshot_revision=0,
            owner=contender,
            binding=binding,
        )
        if committed:
            winners.append(contender)

    assert winners == contender_order[:1]
    assert store.revision == 1
    assert store.owner == contender_order[0]
    assert store.receipt == claim_receipt(binding)


@PROPERTY_SETTINGS
@given(
    binding=_mutation_bindings(),
    contender_order=st.lists(
        _identifier("contender"),
        min_size=2,
        max_size=16,
        unique=True,
    ),
    claimed_revision=st.integers(min_value=0, max_value=1_000_000),
)
def test_transactional_provider_attempt_yields_one_dispatch_permit(
    binding: MutationBinding,
    contender_order: list[str],
    claimed_revision: int,
) -> None:
    store = _ReceiptClaimStore(
        revision=claimed_revision,
        receipt=claim_receipt(binding),
        owner=None,
    )
    dispatch_permits: list[str] = []

    for contender in contender_order:
        store, committed = _commit_provider_attempt(
            store,
            snapshot_revision=claimed_revision,
            owner=contender,
            binding=binding,
        )
        if committed:
            dispatch_permits.append(contender)

    assert dispatch_permits == contender_order[:1]
    assert store.revision == claimed_revision + 1
    assert store.owner == contender_order[0]
    assert store.receipt is not None
    assert store.receipt.outcome is ReplayReceiptOutcome.AMBIGUOUS
    after_commit = decide_replay(binding, store.receipt)
    assert after_commit.action is ReplayAction.REQUIRE_READBACK
    assert after_commit.may_enter_dispatch is False


@PROPERTY_SETTINGS
@given(binding=_mutation_bindings())
def test_readback_success_uses_only_the_bound_expectation(
    binding: MutationBinding,
) -> None:
    attempted = mark_provider_attempted(claim_receipt(binding))
    uncertain = record_provider_result(attempted, ProviderAttemptResult.TIMEOUT)
    caller_selected = _different_digest(binding.expected_poststate_sha256)

    rejected = record_readback(
        uncertain,
        observed_poststate_sha256=caller_selected,
    )
    verified = record_readback(
        uncertain,
        observed_poststate_sha256=binding.expected_poststate_sha256,
    )

    assert rejected.outcome is ReplayReceiptOutcome.AMBIGUOUS
    assert rejected.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
    assert verified.outcome is ReplayReceiptOutcome.VERIFIED
    assert verified.result_sha256 == binding.expected_poststate_sha256
    with pytest.raises(TypeError):
        record_readback(
            uncertain,
            expected_poststate_sha256=caller_selected,
            observed_poststate_sha256=caller_selected,
        )


@PROPERTY_SETTINGS
@given(
    binding=_mutation_bindings(),
    result=st.sampled_from(tuple(ProviderAttemptResult)),
    observed=st.one_of(st.none(), _DIGESTS),
)
def test_provider_attempts_and_uncertain_outcomes_never_redispatch(
    binding: MutationBinding,
    result: ProviderAttemptResult,
    observed: str | None,
) -> None:
    attempted = mark_provider_attempted(claim_receipt(binding))

    duplicate = decide_replay(binding, attempted)
    assert duplicate.action is ReplayAction.REQUIRE_READBACK
    assert duplicate.may_enter_dispatch is False

    classified = record_provider_result(attempted, result)
    after_result = decide_replay(binding, classified)
    assert after_result.may_enter_dispatch is False

    if result not in {
        ProviderAttemptResult.ACCEPTED,
        ProviderAttemptResult.PRECONDITION_REJECTED,
    }:
        assert classified.outcome is ReplayReceiptOutcome.AMBIGUOUS
        assert classified.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS

    if classified.awaits_readback:
        readback = record_readback(
            classified,
            observed_poststate_sha256=observed,
        )
        after_readback = decide_replay(binding, readback)
        assert after_readback.may_enter_dispatch is False
        if observed != binding.expected_poststate_sha256:
            assert readback.outcome is ReplayReceiptOutcome.AMBIGUOUS
            assert readback.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS


@PROPERTY_SETTINGS
@given(
    failure=st.sampled_from(tuple(TransportFailure)),
    maximum_attempts=st.integers(min_value=1, max_value=3),
    data=st.data(),
)
def test_transport_retry_is_bounded_to_known_pre_dispatch_failures(
    failure: TransportFailure,
    maximum_attempts: int,
    data: st.DataObject,
) -> None:
    attempt_number = data.draw(
        st.integers(min_value=1, max_value=maximum_attempts),
        label="attempt_number",
    )
    decision = decide_transport_failure(
        failure,
        attempt_number=attempt_number,
        maximum_attempts=maximum_attempts,
    )

    if failure is TransportFailure.BEFORE_DISPATCH:
        expected = (
            TransportAction.RETRY_BEFORE_DISPATCH
            if attempt_number < maximum_attempts
            else TransportAction.STOP_BEFORE_DISPATCH
        )
        assert decision.action is expected
        assert decision.requires_readback is False
    else:
        assert decision.action is TransportAction.REQUIRE_READBACK
        assert decision.retry_permitted is False
        assert decision.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS


@PROPERTY_SETTINGS
@given(
    binding=_mutation_bindings(),
    maximum_attempts=st.integers(min_value=1, max_value=3),
)
def test_pre_dispatch_retry_exhaustion_is_durable(
    binding: MutationBinding,
    maximum_attempts: int,
) -> None:
    receipt = claim_receipt(binding)

    for expected_attempt in range(1, maximum_attempts + 1):
        receipt = record_pre_dispatch_failure(
            receipt,
            maximum_attempts=maximum_attempts,
        )
        assert receipt.pre_dispatch_attempts == expected_attempt

    assert receipt.terminal is True
    assert receipt.outcome is ReplayReceiptOutcome.FAILED_SAFE
    assert receipt.reason is DenialReason.TRANSPORT_UNAVAILABLE
    duplicate = decide_replay(binding, receipt)
    assert duplicate.action is ReplayAction.RETURN_STORED
    assert duplicate.may_enter_dispatch is False


@PROPERTY_SETTINGS
@given(
    root_id=_identifier("root"),
    current_epoch=st.integers(min_value=2, max_value=1_000_000),
    stale=st.booleans(),
)
def test_stale_or_future_epoch_denial_emits_no_mutation_command(
    root_id: str,
    current_epoch: int,
    stale: bool,
) -> None:
    token_epoch = current_epoch - 1 if stale else current_epoch + 1
    check = check_epoch(
        token_root_id=root_id,
        token_epoch=token_epoch,
        authority_root_id=root_id,
        current_epoch=current_epoch,
    )
    result = reduce_rollout(
        ReducerInput(
            state=RolloutState.ROOT_ACTIVE,
            event=RolloutEvent.CANARY_REQUESTED,
            facts=ReducerFacts(
                authorization=FactStatus.CONFIRMED,
                authority=FactStatus.REJECTED,
                time_window=FactStatus.CONFIRMED,
            ),
        )
    )

    expected = EpochCheckOutcome.STALE if stale else EpochCheckOutcome.FUTURE
    assert check.outcome is expected
    assert check.authorized is False
    assert result.state is RolloutState.DENIED
    assert result.reason is DenialReason.EPOCH_MISMATCH
    assert result.commands == ()
