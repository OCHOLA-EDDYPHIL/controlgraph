from dataclasses import FrozenInstanceError

import pytest

from controlgraph_canary.authority import (
    INITIAL_EPOCH,
    DenialReason,
    EpochAdvanceCause,
    EpochAdvanceOutcome,
    EpochAdvanceRequest,
    EpochAuthority,
    EpochCheckOutcome,
    EpochFence,
    EpochMismatchError,
    check_epoch,
    compare_and_advance,
    initial_authority,
)


def advance_request(
    *,
    root_id: str = "root-a",
    expected_epoch: int = 1,
    requested_epoch: int = 2,
    actor_id: str = "operator-a",
    cause: EpochAdvanceCause = EpochAdvanceCause.REVOCATION,
    request_id: str = "request-a",
    evidence_id: str = "evidence-a",
) -> EpochAdvanceRequest:
    return EpochAdvanceRequest(
        root_id=root_id,
        expected_epoch=expected_epoch,
        requested_epoch=requested_epoch,
        actor_id=actor_id,
        cause=cause,
        request_id=request_id,
        evidence_id=evidence_id,
    )


def test_initial_authority_is_root_scoped_at_epoch_one() -> None:
    authority = initial_authority("root-a")

    assert authority == EpochAuthority(root_id="root-a", epoch=INITIAL_EPOCH)


@pytest.mark.parametrize(
    ("root_id", "epoch"),
    [("", 1), ("   ", 1), ("root-a", 0), ("root-a", -1), ("root-a", True)],
)
def test_invalid_authority_is_rejected(root_id: str, epoch: int) -> None:
    with pytest.raises(ValueError):
        EpochAuthority(root_id=root_id, epoch=epoch)


def test_exact_root_and_epoch_are_current() -> None:
    fence = EpochFence(epoch=12, controller_id="controller-a", root_id="root-a")

    result = fence.check(EpochAuthority(root_id="root-a", epoch=12))

    assert result.authorized is True
    assert result.outcome is EpochCheckOutcome.CURRENT
    assert result.reason is None


@pytest.mark.parametrize(
    ("token_root", "token_epoch", "authority_root", "current_epoch", "outcome", "reason"),
    [
        ("root-a", 11, "root-a", 12, EpochCheckOutcome.STALE, DenialReason.EPOCH_MISMATCH),
        ("root-a", 13, "root-a", 12, EpochCheckOutcome.FUTURE, DenialReason.EPOCH_MISMATCH),
        (
            "root-a",
            12,
            "root-b",
            12,
            EpochCheckOutcome.ROOT_MISMATCH,
            DenialReason.TARGET_BINDING_MISMATCH,
        ),
        ("", 12, "root-a", 12, EpochCheckOutcome.INVALID, DenialReason.CONTRACT_INVALID),
        ("root-a", 0, "root-a", 12, EpochCheckOutcome.INVALID, DenialReason.CONTRACT_INVALID),
    ],
)
def test_epoch_checks_have_deterministic_denial_outcomes(
    token_root: str,
    token_epoch: int,
    authority_root: str,
    current_epoch: int,
    outcome: EpochCheckOutcome,
    reason: DenialReason,
) -> None:
    result = check_epoch(
        token_root_id=token_root,
        token_epoch=token_epoch,
        authority_root_id=authority_root,
        current_epoch=current_epoch,
    )

    assert result.authorized is False
    assert result.outcome is outcome
    assert result.reason is reason


@pytest.mark.parametrize("authoritative_epoch", [11, 13])
def test_require_current_fails_closed_for_stale_and_future_epoch(
    authoritative_epoch: int,
) -> None:
    fence = EpochFence(epoch=12, controller_id="controller-a", root_id="root-a")

    with pytest.raises(EpochMismatchError) as caught:
        fence.require_current(EpochAuthority(root_id="root-a", epoch=authoritative_epoch))

    assert caught.value.result.reason is DenialReason.EPOCH_MISMATCH


def test_require_current_keeps_local_integer_guard_compatible() -> None:
    fence = EpochFence(epoch=7, controller_id="controller-a")

    fence.require_current(7)


@pytest.mark.parametrize(
    ("epoch", "controller_id", "root_id"),
    [(0, "controller-a", "root-a"), (1, "", "root-a"), (1, "controller-a", "")],
)
def test_invalid_fence_is_rejected(epoch: int, controller_id: str, root_id: str) -> None:
    with pytest.raises(ValueError):
        EpochFence(epoch=epoch, controller_id=controller_id, root_id=root_id)


@pytest.mark.parametrize("cause", list(EpochAdvanceCause))
def test_compare_and_advance_proposes_exactly_one_epoch_with_metadata(
    cause: EpochAdvanceCause,
) -> None:
    authority = initial_authority("root-a")
    request = advance_request(cause=cause)

    result = compare_and_advance(authority, request)

    assert result.advanced is True
    assert result.outcome is EpochAdvanceOutcome.ADVANCED
    assert result.authority == EpochAuthority(root_id="root-a", epoch=2)
    assert result.reason is None
    assert result.transition is not None
    assert result.transition.root_id == "root-a"
    assert result.transition.actor_id == "operator-a"
    assert result.transition.cause is cause
    assert result.transition.request_id == "request-a"
    assert result.transition.evidence_id == "evidence-a"
    assert result.transition.prior_epoch == 1
    assert result.transition.new_epoch == 2
    assert authority.epoch == 1


@pytest.mark.parametrize(
    ("proposal", "outcome", "reason"),
    [
        (
            advance_request(expected_epoch=1, requested_epoch=2),
            EpochAdvanceOutcome.STALE,
            DenialReason.EPOCH_MISMATCH,
        ),
        (
            advance_request(expected_epoch=3, requested_epoch=4),
            EpochAdvanceOutcome.FUTURE,
            DenialReason.EPOCH_MISMATCH,
        ),
        (
            advance_request(root_id="root-b", expected_epoch=2, requested_epoch=3),
            EpochAdvanceOutcome.ROOT_MISMATCH,
            DenialReason.TARGET_BINDING_MISMATCH,
        ),
        (
            advance_request(expected_epoch=2, requested_epoch=2),
            EpochAdvanceOutcome.INVALID,
            DenialReason.CONTRACT_INVALID,
        ),
        (
            advance_request(expected_epoch=2, requested_epoch=4),
            EpochAdvanceOutcome.INVALID,
            DenialReason.CONTRACT_INVALID,
        ),
        (
            advance_request(expected_epoch=2, requested_epoch=3, actor_id=""),
            EpochAdvanceOutcome.INVALID,
            DenialReason.CONTRACT_INVALID,
        ),
    ],
)
def test_compare_and_advance_rejects_stale_future_cross_root_and_invalid_requests(
    proposal: EpochAdvanceRequest,
    outcome: EpochAdvanceOutcome,
    reason: DenialReason,
) -> None:
    authority = EpochAuthority(root_id="root-a", epoch=2)

    result = compare_and_advance(authority, proposal)

    assert result.advanced is False
    assert result.outcome is outcome
    assert result.authority is authority
    assert result.transition is None
    assert result.reason is reason


def test_compare_and_advance_is_deterministic_and_results_are_frozen() -> None:
    authority = initial_authority("root-a")
    request = advance_request()

    first = compare_and_advance(authority, request)
    second = compare_and_advance(authority, request)

    assert first == second
    with pytest.raises(FrozenInstanceError):
        first.authority.epoch = 9  # type: ignore[misc]
