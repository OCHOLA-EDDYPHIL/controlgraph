"""Epoch fencing primitives with no infrastructure dependencies."""

from dataclasses import dataclass


class EpochMismatchError(PermissionError):
    """Raised when a token is not valid for the authoritative epoch."""

    def __init__(self, token_epoch: int, current_epoch: int) -> None:
        self.token_epoch = token_epoch
        self.current_epoch = current_epoch
        super().__init__(
            f"epoch mismatch: token={token_epoch}, authoritative={current_epoch}"
        )


@dataclass(frozen=True, slots=True)
class EpochFence:
    """An authority token scoped to one controller and one exact epoch."""

    epoch: int
    controller_id: str

    def __post_init__(self) -> None:
        if self.epoch < 0:
            raise ValueError("epoch must be non-negative")
        if not self.controller_id.strip():
            raise ValueError("controller_id must not be blank")

    def require_current(self, current_epoch: int) -> None:
        """Fail closed unless this token exactly matches the current epoch."""

        if current_epoch < 0:
            raise ValueError("current_epoch must be non-negative")
        if self.epoch != current_epoch:
            raise EpochMismatchError(self.epoch, current_epoch)
