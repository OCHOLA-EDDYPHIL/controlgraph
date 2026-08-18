"""Dependency-free authority primitives."""

from controlgraph_canary.authority.epoch import EpochFence, EpochMismatchError

__all__ = ["EpochFence", "EpochMismatchError"]
