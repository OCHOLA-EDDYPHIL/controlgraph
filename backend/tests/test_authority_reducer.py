from dataclasses import FrozenInstanceError

import pytest

from controlgraph_canary.authority import (
    DenialReason,
    FactStatus,
    ProviderOutcome,
    ReducerFacts,
    ReducerInput,
    RolloutCommand,
    RolloutEvent,
    RolloutState,
    reduce_rollout,
)

CONFIRMED_FACTS = ReducerFacts(
    authorization=FactStatus.CONFIRMED,
    authority=FactStatus.CONFIRMED,
    time_window=FactStatus.CONFIRMED,
    observation=FactStatus.CONFIRMED,
    provider_outcome=ProviderOutcome.APPLIED,
)


@pytest.mark.parametrize(
    ("state", "event", "next_state", "commands", "terminal"),
    [
        (
            RolloutState.ROOT_PENDING,
            RolloutEvent.STABLE_CAPTURE_REQUESTED,
            RolloutState.ROOT_PENDING,
            (RolloutCommand.CAPTURE_STABLE_V1,),
            False,
        ),
        (
            RolloutState.ROOT_PENDING,
            RolloutEvent.STABLE_CAPTURED,
            RolloutState.ROOT_PENDING,
            (RolloutCommand.CREATE_ROLLOUT_ROOT_V1,),
            False,
        ),
        (
            RolloutState.ROOT_PENDING,
            RolloutEvent.ROOT_CREATED,
            RolloutState.ROOT_ACTIVE,
            (),
            False,
        ),
        (
            RolloutState.ROOT_ACTIVE,
            RolloutEvent.CANARY_REQUESTED,
            RolloutState.CANARY_PENDING,
            (RolloutCommand.APPLY_CANARY_V1,),
            False,
        ),
        (
            RolloutState.CANARY_PENDING,
            RolloutEvent.CANARY_APPLIED,
            RolloutState.CANARY_PENDING,
            (RolloutCommand.VERIFY_TARGET_V1,),
            False,
        ),
        (
            RolloutState.CANARY_PENDING,
            RolloutEvent.CANARY_VERIFIED,
            RolloutState.CANARY_OBSERVING,
            (RolloutCommand.EVALUATE_HEALTH_V1,),
            False,
        ),
        (
            RolloutState.CANARY_OBSERVING,
            RolloutEvent.HEALTHY,
            RolloutState.PROMOTION_PENDING,
            (RolloutCommand.PROMOTE_CANDIDATE_V1,),
            False,
        ),
        (
            RolloutState.CANARY_OBSERVING,
            RolloutEvent.UNHEALTHY,
            RolloutState.RECOVERY_PENDING,
            (RolloutCommand.RECOVER_STABLE_V1,),
            False,
        ),
        (
            RolloutState.PROMOTION_PENDING,
            RolloutEvent.PROMOTION_APPLIED,
            RolloutState.PROMOTION_PENDING,
            (RolloutCommand.VERIFY_TARGET_V1,),
            False,
        ),
        (
            RolloutState.PROMOTION_PENDING,
            RolloutEvent.PROMOTION_VERIFIED,
            RolloutState.PROMOTED,
            (),
            False,
        ),
        (
            RolloutState.RECOVERY_PENDING,
            RolloutEvent.RECOVERY_APPLIED,
            RolloutState.RECOVERY_PENDING,
            (RolloutCommand.VERIFY_TARGET_V1,),
            False,
        ),
        (
            RolloutState.RECOVERY_PENDING,
            RolloutEvent.RECOVERY_VERIFIED,
            RolloutState.RECOVERED,
            (),
            False,
        ),
        (
            RolloutState.PROMOTED,
            RolloutEvent.COMPLETION_CONFIRMED,
            RolloutState.PROMOTED,
            (),
            True,
        ),
        (
            RolloutState.RECOVERED,
            RolloutEvent.COMPLETION_CONFIRMED,
            RolloutState.RECOVERED,
            (),
            True,
        ),
    ],
)
def test_legal_journey_transitions_are_deterministic(
    state: RolloutState,
    event: RolloutEvent,
    next_state: RolloutState,
    commands: tuple[RolloutCommand, ...],
    terminal: bool,
) -> None:
    request = ReducerInput(state=state, event=event, facts=CONFIRMED_FACTS)

    first = reduce_rollout(request)
    second = reduce_rollout(request)

    assert first == second
    assert first.previous_state is state
    assert first.state is next_state
    assert first.commands == commands
    assert first.reason is None
    assert first.transition_valid is True
    assert first.terminal is terminal


@pytest.mark.parametrize(
    "state",
    [
        RolloutState.ROOT_ACTIVE,
        RolloutState.CANARY_PENDING,
        RolloutState.CANARY_OBSERVING,
        RolloutState.PROMOTION_PENDING,
        RolloutState.RECOVERY_PENDING,
    ],
)
def test_revocation_is_requested_then_confirmed(state: RolloutState) -> None:
    request = reduce_rollout(
        ReducerInput(
            state=state,
            event=RolloutEvent.REVOCATION_REQUESTED,
            facts=CONFIRMED_FACTS,
        )
    )
    revoked = reduce_rollout(
        ReducerInput(
            state=state,
            event=RolloutEvent.EPOCH_REVOKED,
            facts=CONFIRMED_FACTS,
        )
    )

    assert request.state is state
    assert request.commands == (RolloutCommand.REVOKE_EPOCH_V1,)
    assert revoked.state is RolloutState.REVOKED
    assert revoked.commands == ()
    assert revoked.terminal is True


@pytest.mark.parametrize(
    "state",
    [
        RolloutState.ROOT_PENDING,
        RolloutState.CANARY_PENDING,
        RolloutState.PROMOTION_PENDING,
        RolloutState.RECOVERY_PENDING,
    ],
)
def test_explicit_denial_is_terminal_and_emits_no_command(state: RolloutState) -> None:
    result = reduce_rollout(
        ReducerInput(
            state=state,
            event=RolloutEvent.AUTHORITY_DENIED,
            denial_reason=DenialReason.EPOCH_MISMATCH,
        )
    )

    assert result.state is RolloutState.DENIED
    assert result.reason is DenialReason.EPOCH_MISMATCH
    assert result.commands == ()
    assert result.terminal is True


@pytest.mark.parametrize(
    "state",
    [
        RolloutState.ROOT_PENDING,
        RolloutState.CANARY_PENDING,
        RolloutState.PROMOTION_PENDING,
        RolloutState.RECOVERY_PENDING,
    ],
)
def test_failed_safe_is_terminal_and_emits_no_command(state: RolloutState) -> None:
    facts = ReducerFacts(provider_outcome=ProviderOutcome.FAILED_SAFE)
    result = reduce_rollout(
        ReducerInput(
            state=state,
            event=RolloutEvent.OPERATION_FAILED_SAFE,
            facts=facts,
        )
    )

    assert result.state is RolloutState.FAILED_SAFE
    assert result.reason is DenialReason.PROVIDER_PRECONDITION_FAILED
    assert result.commands == ()
    assert result.terminal is True


@pytest.mark.parametrize(
    "state",
    [
        RolloutState.CANARY_PENDING,
        RolloutState.PROMOTION_PENDING,
        RolloutState.RECOVERY_PENDING,
    ],
)
def test_ambiguous_provider_outcome_preserves_its_origin(state: RolloutState) -> None:
    facts = ReducerFacts(provider_outcome=ProviderOutcome.AMBIGUOUS)
    result = reduce_rollout(
        ReducerInput(
            state=state,
            event=RolloutEvent.PROVIDER_OUTCOME_AMBIGUOUS,
            facts=facts,
        )
    )

    assert result.state is RolloutState.AMBIGUOUS
    assert result.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
    assert result.commands == ()
    assert result.ambiguity_origin is state


@pytest.mark.parametrize(
    ("origin", "event", "next_state", "commands"),
    [
        (
            RolloutState.CANARY_PENDING,
            RolloutEvent.AMBIGUITY_RESOLVED_CANARY,
            RolloutState.CANARY_OBSERVING,
            (RolloutCommand.EVALUATE_HEALTH_V1,),
        ),
        (
            RolloutState.PROMOTION_PENDING,
            RolloutEvent.AMBIGUITY_RESOLVED_PROMOTION,
            RolloutState.PROMOTED,
            (),
        ),
        (
            RolloutState.RECOVERY_PENDING,
            RolloutEvent.AMBIGUITY_RESOLVED_RECOVERY,
            RolloutState.RECOVERED,
            (),
        ),
    ],
)
def test_exact_readback_resolves_only_the_matching_ambiguous_action(
    origin: RolloutState,
    event: RolloutEvent,
    next_state: RolloutState,
    commands: tuple[RolloutCommand, ...],
) -> None:
    result = reduce_rollout(
        ReducerInput(
            state=RolloutState.AMBIGUOUS,
            event=event,
            facts=CONFIRMED_FACTS,
            ambiguity_origin=origin,
        )
    )

    assert result.state is next_state
    assert result.commands == commands
    assert result.reason is None
    assert result.ambiguity_origin is None


def test_mismatched_ambiguity_resolution_is_invalid() -> None:
    result = reduce_rollout(
        ReducerInput(
            state=RolloutState.AMBIGUOUS,
            event=RolloutEvent.AMBIGUITY_RESOLVED_PROMOTION,
            facts=CONFIRMED_FACTS,
            ambiguity_origin=RolloutState.CANARY_PENDING,
        )
    )

    assert result.state is RolloutState.AMBIGUOUS
    assert result.reason is DenialReason.TRANSITION_INVALID
    assert result.transition_valid is False
    assert result.commands == ()


def test_unresolved_ambiguity_has_an_explicit_terminal_classification() -> None:
    result = reduce_rollout(
        ReducerInput(
            state=RolloutState.AMBIGUOUS,
            event=RolloutEvent.AMBIGUITY_UNRESOLVED,
            ambiguity_origin=RolloutState.CANARY_PENDING,
        )
    )

    assert result.state is RolloutState.AMBIGUOUS
    assert result.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
    assert result.terminal is True
    assert result.commands == ()


def test_illegal_transition_fails_closed_without_changing_state() -> None:
    result = reduce_rollout(
        ReducerInput(
            state=RolloutState.ROOT_ACTIVE,
            event=RolloutEvent.PROMOTION_VERIFIED,
            facts=CONFIRMED_FACTS,
        )
    )

    assert result.state is RolloutState.ROOT_ACTIVE
    assert result.reason is DenialReason.TRANSITION_INVALID
    assert result.transition_valid is False
    assert result.commands == ()


@pytest.mark.parametrize(
    ("facts", "reason"),
    [
        (
            ReducerFacts(),
            DenialReason.CALLER_UNAUTHENTICATED,
        ),
        (
            ReducerFacts(
                authorization=FactStatus.CONFIRMED,
                authority=FactStatus.UNKNOWN,
                time_window=FactStatus.CONFIRMED,
            ),
            DenialReason.AUTHORITY_UNAVAILABLE,
        ),
        (
            ReducerFacts(
                authorization=FactStatus.CONFIRMED,
                authority=FactStatus.REJECTED,
                time_window=FactStatus.CONFIRMED,
            ),
            DenialReason.EPOCH_MISMATCH,
        ),
        (
            ReducerFacts(
                authorization=FactStatus.CONFIRMED,
                authority=FactStatus.CONFIRMED,
                time_window=FactStatus.REJECTED,
            ),
            DenialReason.CAPABILITY_EXPIRED,
        ),
    ],
)
def test_missing_or_rejected_control_facts_deny_without_a_command(
    facts: ReducerFacts,
    reason: DenialReason,
) -> None:
    result = reduce_rollout(
        ReducerInput(
            state=RolloutState.ROOT_ACTIVE,
            event=RolloutEvent.CANARY_REQUESTED,
            facts=facts,
        )
    )

    assert result.state is RolloutState.DENIED
    assert result.reason is reason
    assert result.commands == ()
    assert result.terminal is True


def test_missing_provider_outcome_remains_ambiguous_without_retry_command() -> None:
    result = reduce_rollout(
        ReducerInput(
            state=RolloutState.CANARY_PENDING,
            event=RolloutEvent.CANARY_APPLIED,
        )
    )

    assert result.state is RolloutState.AMBIGUOUS
    assert result.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
    assert result.commands == ()
    assert result.ambiguity_origin is RolloutState.CANARY_PENDING


def test_missing_verification_observation_remains_ambiguous() -> None:
    result = reduce_rollout(
        ReducerInput(
            state=RolloutState.PROMOTION_PENDING,
            event=RolloutEvent.PROMOTION_VERIFIED,
        )
    )

    assert result.state is RolloutState.AMBIGUOUS
    assert result.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
    assert result.commands == ()


def test_public_types_are_frozen_and_commands_are_closed() -> None:
    request = ReducerInput(
        state=RolloutState.ROOT_ACTIVE,
        event=RolloutEvent.CANARY_REQUESTED,
        facts=CONFIRMED_FACTS,
    )
    result = reduce_rollout(request)

    assert {command.value for command in RolloutCommand} == {
        "CAPTURE_STABLE_V1",
        "CREATE_ROLLOUT_ROOT_V1",
        "APPLY_CANARY_V1",
        "EVALUATE_HEALTH_V1",
        "PROMOTE_CANDIDATE_V1",
        "RECOVER_STABLE_V1",
        "REVOKE_EPOCH_V1",
        "VERIFY_TARGET_V1",
    }
    with pytest.raises(FrozenInstanceError):
        result.state = RolloutState.DENIED  # type: ignore[misc]
