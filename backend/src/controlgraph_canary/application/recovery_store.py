"""Cloud-independent durable ownership for one captured-stable recovery."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from threading import Lock
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryCommandV2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchState,
    RecoveryIntentV1,
)


class _RecoveryEnqueuePermitKey:
    pass


_RECOVERY_ENQUEUE_PERMIT_KEY = _RecoveryEnqueuePermitKey()


class RecoveryEnqueuePermit:
    """One-use authority minted only by a directly confirmed enqueue start."""

    __slots__ = (
        "_available",
        "_dispatch_id",
        "_lock",
        "_revision",
        "_task_name",
        "_task_sha256",
    )

    def __init__(
        self,
        key: _RecoveryEnqueuePermitKey,
        started: StoredRecord[RecoveryDispatchRecordV2],
    ) -> None:
        if key is not _RECOVERY_ENQUEUE_PERMIT_KEY:
            raise TypeError("recovery enqueue permits are store-issued")
        if (
            type(started) is not StoredRecord
            or type(started.value) is not RecoveryDispatchRecordV2
            or started.revision != 1
            or started.value.state is not RecoveryDispatchState.ENQUEUE_STARTED
            or started.value.result is not None
        ):
            raise ValueError("recovery enqueue permit requires one exact started task")
        self._dispatch_id = started.value.dispatch_id
        self._revision = started.revision
        self._task_name = started.value.task_name
        self._task_sha256 = started.value.task_sha256
        self._available = True
        self._lock = Lock()

    @classmethod
    def _from_direct_store_start(
        cls,
        started: StoredRecord[RecoveryDispatchRecordV2],
    ) -> RecoveryEnqueuePermit:
        return cls(_RECOVERY_ENQUEUE_PERMIT_KEY, started)

    def _take(self, *, task_name: str, task_sha256: str) -> None:
        with self._lock:
            if not self._available:
                raise ValueError("recovery enqueue permit is already consumed")
            if (
                self._revision != 1
                or type(task_name) is not str
                or type(task_sha256) is not str
                or not hmac.compare_digest(task_name, self._task_name)
                or not hmac.compare_digest(task_sha256, self._task_sha256)
            ):
                raise ValueError("recovery enqueue permit does not match the sealed task")
            self._available = False

    def _matches(self, started: StoredRecord[RecoveryDispatchRecordV2]) -> bool:
        return (
            type(started) is StoredRecord
            and type(started.value) is RecoveryDispatchRecordV2
            and started.revision == self._revision == 1
            and hmac.compare_digest(started.value.dispatch_id, self._dispatch_id)
            and hmac.compare_digest(started.value.task_name, self._task_name)
            and hmac.compare_digest(started.value.task_sha256, self._task_sha256)
        )


@dataclass(frozen=True, slots=True)
class DirectRecoveryEnqueueStart:
    """One directly confirmed started record and its process-local permit."""

    dispatch: StoredRecord[RecoveryDispatchRecordV2]
    permit: RecoveryEnqueuePermit

    def __post_init__(self) -> None:
        if (
            type(self.dispatch) is not StoredRecord
            or type(self.dispatch.value) is not RecoveryDispatchRecordV2
            or self.dispatch.revision != 1
            or self.dispatch.value.state is not RecoveryDispatchState.ENQUEUE_STARTED
            or type(self.permit) is not RecoveryEnqueuePermit
            or not self.permit._matches(self.dispatch)
        ):
            raise ValueError("direct recovery enqueue start is invalid")


@runtime_checkable
class RecoveryIntentReader(Protocol):
    """Read the root-unique recovery intent without mutation authority."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_recovery_intent(
        self,
        root_sha256: str,
    ) -> StoredRecord[RecoveryIntentV1] | None: ...


@runtime_checkable
class RecoveryDispatchStore(RecoveryIntentReader, Protocol):
    """Own one root intent and one monotonic recovery enqueue attempt."""

    async def create_or_adopt_recovery_intent(
        self,
        intent: RecoveryIntentV1,
    ) -> StoredRecord[RecoveryIntentV1]: ...

    async def read_recovery_dispatch(
        self,
        command: RecoveryCommandV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2] | None: ...

    async def prepare_or_adopt_recovery_dispatch(
        self,
        intent: StoredRecord[RecoveryIntentV1],
        prepared: RecoveryDispatchRecordV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2]: ...

    async def compare_and_set_recovery_dispatch(
        self,
        expected: StoredRecord[RecoveryDispatchRecordV2],
        replacement: RecoveryDispatchRecordV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2]: ...

    async def begin_recovery_enqueue(
        self,
        expected: StoredRecord[RecoveryDispatchRecordV2],
        replacement: RecoveryDispatchRecordV2,
    ) -> DirectRecoveryEnqueueStart: ...


__all__ = [
    "DirectRecoveryEnqueueStart",
    "RecoveryDispatchStore",
    "RecoveryEnqueuePermit",
    "RecoveryIntentReader",
]
