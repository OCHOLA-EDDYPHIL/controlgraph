import pytest

from controlgraph_canary.authority import EpochFence, EpochMismatchError


def test_exact_epoch_is_current() -> None:
    fence = EpochFence(epoch=12, controller_id="controller-a")

    fence.require_current(12)


@pytest.mark.parametrize("authoritative_epoch", [11, 13])
def test_non_matching_epoch_fails_closed(authoritative_epoch: int) -> None:
    fence = EpochFence(epoch=12, controller_id="controller-a")

    with pytest.raises(EpochMismatchError):
        fence.require_current(authoritative_epoch)


@pytest.mark.parametrize(
    ("epoch", "controller_id"),
    [(-1, "controller-a"), (0, ""), (0, "   ")],
)
def test_invalid_token_is_rejected(epoch: int, controller_id: str) -> None:
    with pytest.raises(ValueError):
        EpochFence(epoch=epoch, controller_id=controller_id)
