"""Pure rollout reducer for the closed ControlGraph Canary state machine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RolloutState(StrEnum):
    """Version-one rollout states from the product contract."""

    ROOT_PENDING = "ROOT_PENDING"
    ROOT_ACTIVE = "ROOT_ACTIVE"
    CANARY_PENDING = "CANARY_PENDING"
    CANARY_OBSERVING = "CANARY_OBSERVING"
    PROMOTION_PENDING = "PROMOTION_PENDING"
    RECOVERY_PENDING = "RECOVERY_PENDING"
    PROMOTED = "PROMOTED"
    RECOVERED = "RECOVERED"
    REVOKED = "REVOKED"
    DENIED = "DENIED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"


class RolloutCommand(StrEnum):
    """Closed commands that may be emitted by the reducer."""

    CAPTURE_STABLE_V1 = "CAPTURE_STABLE_V1"
    CREATE_ROLLOUT_ROOT_V1 = "CREATE_ROLLOUT_ROOT_V1"
    APPLY_CANARY_V1 = "APPLY_CANARY_V1"
    EVALUATE_HEALTH_V1 = "EVALUATE_HEALTH_V1"
    PROMOTE_CANDIDATE_V1 = "PROMOTE_CANDIDATE_V1"
    RECOVER_STABLE_V1 = "RECOVER_STABLE_V1"
    REVOKE_EPOCH_V1 = "REVOKE_EPOCH_V1"
    VERIFY_TARGET_V1 = "VERIFY_TARGET_V1"


class RolloutEvent(StrEnum):
    """Closed facts that may be supplied to the reducer."""

    STABLE_CAPTURE_REQUESTED = "STABLE_CAPTURE_REQUESTED"
    STABLE_CAPTURED = "STABLE_CAPTURED"
    ROOT_CREATED = "ROOT_CREATED"
    CANARY_REQUESTED = "CANARY_REQUESTED"
    CANARY_APPLIED = "CANARY_APPLIED"
    CANARY_VERIFIED = "CANARY_VERIFIED"
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    PROMOTION_APPLIED = "PROMOTION_APPLIED"
    PROMOTION_VERIFIED = "PROMOTION_VERIFIED"
    RECOVERY_APPLIED = "RECOVERY_APPLIED"
    RECOVERY_VERIFIED = "RECOVERY_VERIFIED"
    REVOCATION_REQUESTED = "REVOCATION_REQUESTED"
    EPOCH_REVOKED = "EPOCH_REVOKED"
    COMPLETION_CONFIRMED = "COMPLETION_CONFIRMED"
    AUTHORITY_DENIED = "AUTHORITY_DENIED"
    OPERATION_FAILED_SAFE = "OPERATION_FAILED_SAFE"
    PROVIDER_OUTCOME_AMBIGUOUS = "PROVIDER_OUTCOME_AMBIGUOUS"
    AMBIGUITY_RESOLVED_CANARY = "AMBIGUITY_RESOLVED_CANARY"
    AMBIGUITY_RESOLVED_PROMOTION = "AMBIGUITY_RESOLVED_PROMOTION"
    AMBIGUITY_RESOLVED_RECOVERY = "AMBIGUITY_RESOLVED_RECOVERY"
    AMBIGUITY_UNRESOLVED = "AMBIGUITY_UNRESOLVED"


class DenialReason(StrEnum):
    """Stable public reason codes accepted by the product contract."""

    CONTRACT_INVALID = "CONTRACT_INVALID"
    CONTRACT_VERSION_UNSUPPORTED = "CONTRACT_VERSION_UNSUPPORTED"
    CALLER_UNAUTHENTICATED = "CALLER_UNAUTHENTICATED"
    CALLER_UNAUTHORIZED = "CALLER_UNAUTHORIZED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    KEY_VERSION_UNTRUSTED = "KEY_VERSION_UNTRUSTED"
    CAPABILITY_EXPIRED = "CAPABILITY_EXPIRED"
    CAPABILITY_NOT_YET_VALID = "CAPABILITY_NOT_YET_VALID"
    CLAIM_BINDING_MISMATCH = "CLAIM_BINDING_MISMATCH"
    TARGET_BINDING_MISMATCH = "TARGET_BINDING_MISMATCH"
    LINEAGE_INVALID = "LINEAGE_INVALID"
    SCOPE_AMPLIFICATION = "SCOPE_AMPLIFICATION"
    AUTHORITY_UNAVAILABLE = "AUTHORITY_UNAVAILABLE"
    EPOCH_MISMATCH = "EPOCH_MISMATCH"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    RECEIPT_IN_PROGRESS = "RECEIPT_IN_PROGRESS"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
    PROVIDER_PRECONDITION_FAILED = "PROVIDER_PRECONDITION_FAILED"
    PROVIDER_REQUEST_REJECTED = "PROVIDER_REQUEST_REJECTED"
    PROVIDER_OUTCOME_AMBIGUOUS = "PROVIDER_OUTCOME_AMBIGUOUS"
    TRANSITION_INVALID = "TRANSITION_INVALID"
    POLICY_UNHEALTHY = "POLICY_UNHEALTHY"


class FactStatus(StrEnum):
    """Status of a fact supplied by a boundary outside the pure reducer."""

    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ProviderOutcome(StrEnum):
    """Known classification of a provider or authority-store operation."""

    APPLIED = "APPLIED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True, slots=True)
class ReducerFacts:
    """Explicit facts consumed without performing side effects."""

    authorization: FactStatus = FactStatus.NOT_APPLICABLE
    authority: FactStatus = FactStatus.NOT_APPLICABLE
    time_window: FactStatus = FactStatus.NOT_APPLICABLE
    observation: FactStatus = FactStatus.NOT_APPLICABLE
    provider_outcome: ProviderOutcome = ProviderOutcome.NOT_APPLICABLE


@dataclass(frozen=True, slots=True)
class ReducerInput:
    """One state and ordered event presented to the reducer."""

    state: RolloutState
    event: RolloutEvent
    facts: ReducerFacts = field(default_factory=ReducerFacts)
    denial_reason: DenialReason | None = None
    ambiguity_origin: RolloutState | None = None


@dataclass(frozen=True, slots=True)
class ReducerOutput:
    """Deterministic result of reducing one event."""

    previous_state: RolloutState
    state: RolloutState
    event: RolloutEvent
    commands: tuple[RolloutCommand, ...]
    reason: DenialReason | None
    transition_valid: bool
    terminal: bool
    ambiguity_origin: RolloutState | None = None


@dataclass(frozen=True, slots=True)
class _Transition:
    state: RolloutState
    commands: tuple[RolloutCommand, ...] = ()
    requires_authorization: bool = False
    requires_authority: bool = False
    requires_time: bool = False
    requires_observation: bool = False
    provider_outcome: ProviderOutcome | None = None
    ambiguity_origin: RolloutState | None = None
    terminal: bool = False


def _command(command: RolloutCommand) -> tuple[RolloutCommand, ...]:
    return (command,)


_TRANSITIONS: dict[tuple[RolloutState, RolloutEvent], _Transition] = {
    (RolloutState.ROOT_PENDING, RolloutEvent.STABLE_CAPTURE_REQUESTED): _Transition(
        RolloutState.ROOT_PENDING,
        _command(RolloutCommand.CAPTURE_STABLE_V1),
        requires_authorization=True,
        requires_time=True,
    ),
    (RolloutState.ROOT_PENDING, RolloutEvent.STABLE_CAPTURED): _Transition(
        RolloutState.ROOT_PENDING,
        _command(RolloutCommand.CREATE_ROLLOUT_ROOT_V1),
        requires_authorization=True,
        requires_time=True,
        requires_observation=True,
    ),
    (RolloutState.ROOT_PENDING, RolloutEvent.ROOT_CREATED): _Transition(
        RolloutState.ROOT_ACTIVE,
        provider_outcome=ProviderOutcome.APPLIED,
    ),
    (RolloutState.ROOT_ACTIVE, RolloutEvent.CANARY_REQUESTED): _Transition(
        RolloutState.CANARY_PENDING,
        _command(RolloutCommand.APPLY_CANARY_V1),
        requires_authorization=True,
        requires_authority=True,
        requires_time=True,
    ),
    (RolloutState.CANARY_PENDING, RolloutEvent.CANARY_APPLIED): _Transition(
        RolloutState.CANARY_PENDING,
        _command(RolloutCommand.VERIFY_TARGET_V1),
        provider_outcome=ProviderOutcome.APPLIED,
    ),
    (RolloutState.CANARY_PENDING, RolloutEvent.CANARY_VERIFIED): _Transition(
        RolloutState.CANARY_OBSERVING,
        _command(RolloutCommand.EVALUATE_HEALTH_V1),
        requires_observation=True,
    ),
    (RolloutState.CANARY_OBSERVING, RolloutEvent.HEALTHY): _Transition(
        RolloutState.PROMOTION_PENDING,
        _command(RolloutCommand.PROMOTE_CANDIDATE_V1),
        requires_authorization=True,
        requires_authority=True,
        requires_time=True,
        requires_observation=True,
    ),
    (RolloutState.CANARY_OBSERVING, RolloutEvent.UNHEALTHY): _Transition(
        RolloutState.RECOVERY_PENDING,
        _command(RolloutCommand.RECOVER_STABLE_V1),
        requires_authorization=True,
        requires_authority=True,
        requires_time=True,
        requires_observation=True,
    ),
    (RolloutState.PROMOTION_PENDING, RolloutEvent.PROMOTION_APPLIED): _Transition(
        RolloutState.PROMOTION_PENDING,
        _command(RolloutCommand.VERIFY_TARGET_V1),
        provider_outcome=ProviderOutcome.APPLIED,
    ),
    (RolloutState.PROMOTION_PENDING, RolloutEvent.PROMOTION_VERIFIED): _Transition(
        RolloutState.PROMOTED,
        requires_observation=True,
    ),
    (RolloutState.RECOVERY_PENDING, RolloutEvent.RECOVERY_APPLIED): _Transition(
        RolloutState.RECOVERY_PENDING,
        _command(RolloutCommand.VERIFY_TARGET_V1),
        provider_outcome=ProviderOutcome.APPLIED,
    ),
    (RolloutState.RECOVERY_PENDING, RolloutEvent.RECOVERY_VERIFIED): _Transition(
        RolloutState.RECOVERED,
        requires_observation=True,
    ),
    (RolloutState.PROMOTED, RolloutEvent.COMPLETION_CONFIRMED): _Transition(
        RolloutState.PROMOTED,
        requires_observation=True,
        terminal=True,
    ),
    (RolloutState.RECOVERED, RolloutEvent.COMPLETION_CONFIRMED): _Transition(
        RolloutState.RECOVERED,
        requires_observation=True,
        terminal=True,
    ),
    (RolloutState.AMBIGUOUS, RolloutEvent.AMBIGUITY_RESOLVED_CANARY): _Transition(
        RolloutState.CANARY_OBSERVING,
        _command(RolloutCommand.EVALUATE_HEALTH_V1),
        requires_observation=True,
        ambiguity_origin=RolloutState.CANARY_PENDING,
    ),
    (RolloutState.AMBIGUOUS, RolloutEvent.AMBIGUITY_RESOLVED_PROMOTION): _Transition(
        RolloutState.PROMOTED,
        requires_observation=True,
        ambiguity_origin=RolloutState.PROMOTION_PENDING,
    ),
    (RolloutState.AMBIGUOUS, RolloutEvent.AMBIGUITY_RESOLVED_RECOVERY): _Transition(
        RolloutState.RECOVERED,
        requires_observation=True,
        ambiguity_origin=RolloutState.RECOVERY_PENDING,
    ),
    (RolloutState.AMBIGUOUS, RolloutEvent.AMBIGUITY_UNRESOLVED): _Transition(
        RolloutState.AMBIGUOUS,
        terminal=True,
    ),
}

_REVOCABLE_STATES = (
    RolloutState.ROOT_ACTIVE,
    RolloutState.CANARY_PENDING,
    RolloutState.CANARY_OBSERVING,
    RolloutState.PROMOTION_PENDING,
    RolloutState.RECOVERY_PENDING,
)
for _state in _REVOCABLE_STATES:
    _TRANSITIONS[(_state, RolloutEvent.REVOCATION_REQUESTED)] = _Transition(
        _state,
        _command(RolloutCommand.REVOKE_EPOCH_V1),
        requires_authorization=True,
        requires_authority=True,
        requires_time=True,
    )
    _TRANSITIONS[(_state, RolloutEvent.EPOCH_REVOKED)] = _Transition(
        RolloutState.REVOKED,
        provider_outcome=ProviderOutcome.APPLIED,
        terminal=True,
    )

_COMMAND_STATES = (
    RolloutState.ROOT_PENDING,
    RolloutState.CANARY_PENDING,
    RolloutState.PROMOTION_PENDING,
    RolloutState.RECOVERY_PENDING,
)
for _state in _COMMAND_STATES:
    _TRANSITIONS[(_state, RolloutEvent.AUTHORITY_DENIED)] = _Transition(
        RolloutState.DENIED,
        terminal=True,
    )
    _TRANSITIONS[(_state, RolloutEvent.OPERATION_FAILED_SAFE)] = _Transition(
        RolloutState.FAILED_SAFE,
        provider_outcome=ProviderOutcome.FAILED_SAFE,
        terminal=True,
    )

_MUTATION_STATES = (
    RolloutState.CANARY_PENDING,
    RolloutState.PROMOTION_PENDING,
    RolloutState.RECOVERY_PENDING,
)
for _state in _MUTATION_STATES:
    _TRANSITIONS[(_state, RolloutEvent.PROVIDER_OUTCOME_AMBIGUOUS)] = _Transition(
        RolloutState.AMBIGUOUS,
        provider_outcome=ProviderOutcome.AMBIGUOUS,
    )


def _result(
    request: ReducerInput,
    state: RolloutState,
    *,
    commands: tuple[RolloutCommand, ...] = (),
    reason: DenialReason | None = None,
    transition_valid: bool = True,
    terminal: bool = False,
    ambiguity_origin: RolloutState | None = None,
) -> ReducerOutput:
    return ReducerOutput(
        previous_state=request.state,
        state=state,
        event=request.event,
        commands=commands,
        reason=reason,
        transition_valid=transition_valid,
        terminal=terminal,
        ambiguity_origin=ambiguity_origin,
    )


def _deny(request: ReducerInput, reason: DenialReason) -> ReducerOutput:
    return _result(
        request,
        RolloutState.DENIED,
        reason=request.denial_reason or reason,
        terminal=True,
    )


def _ambiguity(request: ReducerInput) -> ReducerOutput:
    origin = request.ambiguity_origin or request.state
    return _result(
        request,
        RolloutState.AMBIGUOUS,
        reason=DenialReason.PROVIDER_OUTCOME_AMBIGUOUS,
        ambiguity_origin=origin,
    )


def _check_required_facts(
    request: ReducerInput, transition: _Transition
) -> ReducerOutput | None:
    facts = request.facts
    if transition.requires_authorization and facts.authorization is not FactStatus.CONFIRMED:
        reason = (
            DenialReason.CALLER_UNAUTHORIZED
            if facts.authorization is FactStatus.REJECTED
            else DenialReason.CALLER_UNAUTHENTICATED
        )
        return _deny(request, reason)
    if transition.requires_authority and facts.authority is not FactStatus.CONFIRMED:
        reason = (
            DenialReason.EPOCH_MISMATCH
            if facts.authority is FactStatus.REJECTED
            else DenialReason.AUTHORITY_UNAVAILABLE
        )
        return _deny(request, reason)
    if transition.requires_time and facts.time_window is not FactStatus.CONFIRMED:
        reason = (
            DenialReason.CAPABILITY_EXPIRED
            if facts.time_window is FactStatus.REJECTED
            else DenialReason.CONTRACT_INVALID
        )
        return _deny(request, reason)
    if transition.requires_observation and facts.observation is not FactStatus.CONFIRMED:
        return _ambiguity(request)
    if transition.provider_outcome is not None:
        if facts.provider_outcome is ProviderOutcome.FAILED_SAFE:
            return _result(
                request,
                RolloutState.FAILED_SAFE,
                reason=request.denial_reason or DenialReason.PROVIDER_PRECONDITION_FAILED,
                terminal=True,
            )
        if facts.provider_outcome is not transition.provider_outcome:
            return _ambiguity(request)
    return None


def reduce_rollout(request: ReducerInput) -> ReducerOutput:
    """Reduce one explicit event without consulting any external state."""

    transition = _TRANSITIONS.get((request.state, request.event))
    if transition is None:
        return _result(
            request,
            request.state,
            reason=DenialReason.TRANSITION_INVALID,
            transition_valid=False,
            terminal=request.state
            in {RolloutState.REVOKED, RolloutState.DENIED, RolloutState.FAILED_SAFE},
            ambiguity_origin=request.ambiguity_origin,
        )

    if (
        transition.ambiguity_origin is not None
        and request.ambiguity_origin is not transition.ambiguity_origin
    ):
        return _result(
            request,
            request.state,
            reason=DenialReason.TRANSITION_INVALID,
            transition_valid=False,
            ambiguity_origin=request.ambiguity_origin,
        )

    fact_result = _check_required_facts(request, transition)
    if fact_result is not None:
        return fact_result

    reason = request.denial_reason if transition.state is RolloutState.DENIED else None
    if transition.state is RolloutState.DENIED and reason is None:
        reason = DenialReason.AUTHORITY_UNAVAILABLE
    if transition.state is RolloutState.FAILED_SAFE:
        reason = request.denial_reason or DenialReason.PROVIDER_PRECONDITION_FAILED
    if transition.state is RolloutState.AMBIGUOUS:
        reason = DenialReason.PROVIDER_OUTCOME_AMBIGUOUS

    ambiguity_origin = request.ambiguity_origin
    if transition.state is RolloutState.AMBIGUOUS and request.state is not RolloutState.AMBIGUOUS:
        ambiguity_origin = request.state
    elif request.state is RolloutState.AMBIGUOUS and transition.state is not RolloutState.AMBIGUOUS:
        ambiguity_origin = None

    return _result(
        request,
        transition.state,
        commands=transition.commands,
        reason=reason,
        terminal=transition.terminal,
        ambiguity_origin=ambiguity_origin,
    )
