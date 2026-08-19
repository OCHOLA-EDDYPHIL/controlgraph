"""Root-scoped epoch fencing and pure monotonic advance primitives."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from controlgraph_canary.authority.reducer import DenialReason

INITIAL_EPOCH = 1
LOCAL_ROOT_ID = "local-scaffold"


def _is_nonblank(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


class EpochCheckOutcome(StrEnum):
    """Deterministic classification of an exact-match epoch check."""

    CURRENT = "CURRENT"
    STALE = "STALE"
    FUTURE = "FUTURE"
    ROOT_MISMATCH = "ROOT_MISMATCH"
    INVALID = "INVALID"


class EpochAdvanceCause(StrEnum):
    """Closed causes that may advance root authority."""

    REVOCATION = "REVOCATION"
    SUPERSESSION = "SUPERSESSION"
    RECOVERY = "RECOVERY"


class EpochAdvanceOutcome(StrEnum):
    """Deterministic result of a pure compare-and-advance request."""

    ADVANCED = "ADVANCED"
    STALE = "STALE"
    FUTURE = "FUTURE"
    ROOT_MISMATCH = "ROOT_MISMATCH"
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class EpochAuthority:
    """Current authority for one immutable rollout root."""

    root_id: str
    epoch: int = INITIAL_EPOCH

    def __post_init__(self) -> None:
        if not _is_nonblank(self.root_id):
            raise ValueError("root_id must not be blank")
        if type(self.epoch) is not int or self.epoch < INITIAL_EPOCH:
            raise ValueError(f"epoch must be an integer at least {INITIAL_EPOCH}")


@dataclass(frozen=True, slots=True)
class EpochCheckResult:
    """Result of checking a token against current root authority."""

    outcome: EpochCheckOutcome
    token_root_id: str
    authority_root_id: str
    token_epoch: int
    current_epoch: int
    reason: DenialReason | None

    @property
    def authorized(self) -> bool:
        return self.outcome is EpochCheckOutcome.CURRENT


@dataclass(frozen=True, slots=True)
class EpochAdvanceRequest:
    """Explicit proposal to advance one root from N to N+1."""

    root_id: str
    expected_epoch: int
    requested_epoch: int
    actor_id: str
    cause: EpochAdvanceCause
    request_id: str
    evidence_id: str


@dataclass(frozen=True, slots=True)
class EpochTransition:
    """Immutable metadata produced for a valid advance proposal."""

    root_id: str
    actor_id: str
    cause: EpochAdvanceCause
    request_id: str
    evidence_id: str
    prior_epoch: int
    new_epoch: int


@dataclass(frozen=True, slots=True)
class EpochAdvanceResult:
    """Pure result; persistence later decides which proposal commits."""

    outcome: EpochAdvanceOutcome
    authority: EpochAuthority
    transition: EpochTransition | None
    reason: DenialReason | None

    @property
    def advanced(self) -> bool:
        return self.outcome is EpochAdvanceOutcome.ADVANCED


class EpochMismatchError(PermissionError):
    """Raised by the compatibility guard when epoch authority is not current."""

    def __init__(self, result: EpochCheckResult) -> None:
        self.result = result
        self.token_epoch = result.token_epoch
        self.current_epoch = result.current_epoch
        self.token_root_id = result.token_root_id
        self.authority_root_id = result.authority_root_id
        super().__init__(
            "epoch authority mismatch: "
            f"outcome={result.outcome.value}, token_root={result.token_root_id}, "
            f"authority_root={result.authority_root_id}, token={result.token_epoch}, "
            f"authoritative={result.current_epoch}"
        )


@dataclass(frozen=True, slots=True)
class EpochFence:
    """An authority token scoped to one controller, rollout root, and epoch."""

    epoch: int
    controller_id: str
    root_id: str = LOCAL_ROOT_ID

    def __post_init__(self) -> None:
        if type(self.epoch) is not int or self.epoch < INITIAL_EPOCH:
            raise ValueError(f"epoch must be an integer at least {INITIAL_EPOCH}")
        if not _is_nonblank(self.controller_id):
            raise ValueError("controller_id must not be blank")
        if not _is_nonblank(self.root_id):
            raise ValueError("root_id must not be blank")

    def check(self, authority: EpochAuthority) -> EpochCheckResult:
        """Classify this token against an explicit authority record."""

        return check_epoch(
            token_root_id=self.root_id,
            token_epoch=self.epoch,
            authority_root_id=authority.root_id,
            current_epoch=authority.epoch,
        )

    def require_current(
        self,
        authority: EpochAuthority | int,
        *,
        root_id: str | None = None,
    ) -> None:
        """Raise unless this token exactly matches explicit current authority.

        An integer remains accepted for the local fence-check CLI. Authority-bearing
        application paths should pass an ``EpochAuthority`` record.
        """

        result = (
            self.check(authority)
            if isinstance(authority, EpochAuthority)
            else check_epoch(
                token_root_id=self.root_id,
                token_epoch=self.epoch,
                authority_root_id=self.root_id if root_id is None else root_id,
                current_epoch=authority,
            )
        )
        if result.outcome is EpochCheckOutcome.INVALID:
            raise ValueError("current epoch authority is invalid")
        if not result.authorized:
            raise EpochMismatchError(result)


def check_epoch(
    *,
    token_root_id: str,
    token_epoch: int,
    authority_root_id: str,
    current_epoch: int,
) -> EpochCheckResult:
    """Classify root and epoch equality without raising or reading external state."""

    if (
        not _is_nonblank(token_root_id)
        or not _is_nonblank(authority_root_id)
        or type(token_epoch) is not int
        or type(current_epoch) is not int
        or token_epoch < INITIAL_EPOCH
        or current_epoch < INITIAL_EPOCH
    ):
        return EpochCheckResult(
            outcome=EpochCheckOutcome.INVALID,
            token_root_id=token_root_id,
            authority_root_id=authority_root_id,
            token_epoch=token_epoch,
            current_epoch=current_epoch,
            reason=DenialReason.CONTRACT_INVALID,
        )
    if token_root_id != authority_root_id:
        return EpochCheckResult(
            outcome=EpochCheckOutcome.ROOT_MISMATCH,
            token_root_id=token_root_id,
            authority_root_id=authority_root_id,
            token_epoch=token_epoch,
            current_epoch=current_epoch,
            reason=DenialReason.TARGET_BINDING_MISMATCH,
        )
    if token_epoch < current_epoch:
        outcome = EpochCheckOutcome.STALE
    elif token_epoch > current_epoch:
        outcome = EpochCheckOutcome.FUTURE
    else:
        outcome = EpochCheckOutcome.CURRENT
    return EpochCheckResult(
        outcome=outcome,
        token_root_id=token_root_id,
        authority_root_id=authority_root_id,
        token_epoch=token_epoch,
        current_epoch=current_epoch,
        reason=None if outcome is EpochCheckOutcome.CURRENT else DenialReason.EPOCH_MISMATCH,
    )


def initial_authority(root_id: str) -> EpochAuthority:
    """Create the initial epoch-one authority for one rollout root."""

    return EpochAuthority(root_id=root_id, epoch=INITIAL_EPOCH)


def _invalid_advance(
    authority: EpochAuthority,
    outcome: EpochAdvanceOutcome,
    reason: DenialReason,
) -> EpochAdvanceResult:
    return EpochAdvanceResult(
        outcome=outcome,
        authority=authority,
        transition=None,
        reason=reason,
    )


def compare_and_advance(
    authority: EpochAuthority,
    request: EpochAdvanceRequest,
) -> EpochAdvanceResult:
    """Purely compare N and propose N+1 without claiming a committed winner."""

    if (
        not _is_nonblank(request.root_id)
        or not _is_nonblank(request.actor_id)
        or not _is_nonblank(request.request_id)
        or not _is_nonblank(request.evidence_id)
        or not isinstance(request.cause, EpochAdvanceCause)
        or type(request.expected_epoch) is not int
        or type(request.requested_epoch) is not int
        or request.expected_epoch < INITIAL_EPOCH
        or request.requested_epoch < INITIAL_EPOCH
    ):
        return _invalid_advance(
            authority,
            EpochAdvanceOutcome.INVALID,
            DenialReason.CONTRACT_INVALID,
        )
    if request.root_id != authority.root_id:
        return _invalid_advance(
            authority,
            EpochAdvanceOutcome.ROOT_MISMATCH,
            DenialReason.TARGET_BINDING_MISMATCH,
        )
    if request.expected_epoch < authority.epoch:
        return _invalid_advance(
            authority,
            EpochAdvanceOutcome.STALE,
            DenialReason.EPOCH_MISMATCH,
        )
    if request.expected_epoch > authority.epoch:
        return _invalid_advance(
            authority,
            EpochAdvanceOutcome.FUTURE,
            DenialReason.EPOCH_MISMATCH,
        )
    if request.requested_epoch != authority.epoch + 1:
        return _invalid_advance(
            authority,
            EpochAdvanceOutcome.INVALID,
            DenialReason.CONTRACT_INVALID,
        )

    next_authority = EpochAuthority(
        root_id=authority.root_id,
        epoch=authority.epoch + 1,
    )
    transition = EpochTransition(
        root_id=authority.root_id,
        actor_id=request.actor_id,
        cause=request.cause,
        request_id=request.request_id,
        evidence_id=request.evidence_id,
        prior_epoch=authority.epoch,
        new_epoch=next_authority.epoch,
    )
    return EpochAdvanceResult(
        outcome=EpochAdvanceOutcome.ADVANCED,
        authority=next_authority,
        transition=transition,
        reason=None,
    )
