"""Cloud-independent durable ownership port for candidate promotion dispatch."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from threading import Lock
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.contracts.health_execution import SignedHealthDecisionChainV1
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.promotion_execution import (
    PromotionCommandV1,
    PromotionCommandV2,
    PromotionDispatchRecordV1,
    PromotionDispatchRecordV2,
    PromotionDispatchState,
    PromotionHealthChainLocatorV1,
)


class _PromotionEnqueuePermitKey:
    pass


_PROMOTION_ENQUEUE_PERMIT_KEY = _PromotionEnqueuePermitKey()


class PromotionEnqueuePermit:
    """One-use authority to enqueue one directly confirmed stored task."""

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
        key: _PromotionEnqueuePermitKey,
        started: StoredRecord[PromotionDispatchRecordV1],
    ) -> None:
        if key is not _PROMOTION_ENQUEUE_PERMIT_KEY:
            raise TypeError("promotion enqueue permits are store-issued")
        if (
            type(started) is not StoredRecord
            or type(started.value) is not PromotionDispatchRecordV1
            or started.revision != 1
            or started.value.state is not PromotionDispatchState.ENQUEUE_STARTED
            or started.value.result is not None
        ):
            raise ValueError("promotion enqueue permit requires one exact started task")
        self._dispatch_id = started.value.dispatch_id
        self._revision = started.revision
        self._task_name = started.value.task_name
        self._task_sha256 = started.value.task_sha256
        self._available = True
        self._lock = Lock()

    @classmethod
    def _from_direct_store_start(
        cls,
        started: StoredRecord[PromotionDispatchRecordV1],
    ) -> PromotionEnqueuePermit:
        """Issue only after the store directly confirms the start transition."""

        return cls(_PROMOTION_ENQUEUE_PERMIT_KEY, started)

    def _take(self, *, task_name: str, task_sha256: str) -> None:
        with self._lock:
            if not self._available:
                raise ValueError("promotion enqueue permit is already consumed")
            if (
                self._revision != 1
                or type(task_name) is not str
                or type(task_sha256) is not str
                or not hmac.compare_digest(task_name, self._task_name)
                or not hmac.compare_digest(task_sha256, self._task_sha256)
            ):
                raise ValueError("promotion enqueue permit does not match the sealed task")
            self._available = False

    def _matches(
        self,
        started: StoredRecord[PromotionDispatchRecordV1],
    ) -> bool:
        return (
            type(started) is StoredRecord
            and type(started.value) is PromotionDispatchRecordV1
            and started.revision == self._revision == 1
            and hmac.compare_digest(started.value.dispatch_id, self._dispatch_id)
            and hmac.compare_digest(started.value.task_name, self._task_name)
            and hmac.compare_digest(started.value.task_sha256, self._task_sha256)
        )


@dataclass(frozen=True, slots=True)
class DirectPromotionEnqueueStart:
    """A directly confirmed started record and its one enqueue permit."""

    dispatch: StoredRecord[PromotionDispatchRecordV1]
    permit: PromotionEnqueuePermit

    def __post_init__(self) -> None:
        if (
            type(self.dispatch) is not StoredRecord
            or type(self.dispatch.value) is not PromotionDispatchRecordV1
            or self.dispatch.revision != 1
            or self.dispatch.value.state is not PromotionDispatchState.ENQUEUE_STARTED
            or type(self.permit) is not PromotionEnqueuePermit
            or not self.permit._matches(self.dispatch)
        ):
            raise ValueError("direct promotion enqueue start is invalid")


class _PromotionEnqueuePermitV2Key:
    pass


_PROMOTION_ENQUEUE_PERMIT_V2_KEY = _PromotionEnqueuePermitV2Key()


class PromotionEnqueuePermitV2:
    """One-use authority to enqueue one directly confirmed V2 promotion task."""

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
        key: _PromotionEnqueuePermitV2Key,
        started: StoredRecord[PromotionDispatchRecordV2],
    ) -> None:
        if key is not _PROMOTION_ENQUEUE_PERMIT_V2_KEY:
            raise TypeError("V2 promotion enqueue permits are store-issued")
        if (
            type(started) is not StoredRecord
            or type(started.value) is not PromotionDispatchRecordV2
            or started.revision != 1
            or started.value.state is not PromotionDispatchState.ENQUEUE_STARTED
            or started.value.result is not None
        ):
            raise ValueError("V2 promotion enqueue permit requires one exact started task")
        self._dispatch_id = started.value.dispatch_id
        self._revision = started.revision
        self._task_name = started.value.task_name
        self._task_sha256 = started.value.task_sha256
        self._available = True
        self._lock = Lock()

    @classmethod
    def _from_direct_store_start(
        cls,
        started: StoredRecord[PromotionDispatchRecordV2],
    ) -> PromotionEnqueuePermitV2:
        """Issue only after the V2 store directly confirms the start transition."""

        return cls(_PROMOTION_ENQUEUE_PERMIT_V2_KEY, started)

    def _take(self, *, task_name: str, task_sha256: str) -> None:
        with self._lock:
            if not self._available:
                raise ValueError("V2 promotion enqueue permit is already consumed")
            if (
                self._revision != 1
                or type(task_name) is not str
                or type(task_sha256) is not str
                or not hmac.compare_digest(task_name, self._task_name)
                or not hmac.compare_digest(task_sha256, self._task_sha256)
            ):
                raise ValueError("V2 promotion enqueue permit does not match the sealed task")
            self._available = False

    def _matches(
        self,
        started: StoredRecord[PromotionDispatchRecordV2],
    ) -> bool:
        return (
            type(started) is StoredRecord
            and type(started.value) is PromotionDispatchRecordV2
            and started.revision == self._revision == 1
            and hmac.compare_digest(started.value.dispatch_id, self._dispatch_id)
            and hmac.compare_digest(started.value.task_name, self._task_name)
            and hmac.compare_digest(started.value.task_sha256, self._task_sha256)
        )


@dataclass(frozen=True, slots=True)
class DirectPromotionEnqueueStartV2:
    """A directly confirmed V2 started record and its one enqueue permit."""

    dispatch: StoredRecord[PromotionDispatchRecordV2]
    permit: PromotionEnqueuePermitV2

    def __post_init__(self) -> None:
        if (
            type(self.dispatch) is not StoredRecord
            or type(self.dispatch.value) is not PromotionDispatchRecordV2
            or self.dispatch.revision != 1
            or self.dispatch.value.state is not PromotionDispatchState.ENQUEUE_STARTED
            or type(self.permit) is not PromotionEnqueuePermitV2
            or not self.permit._matches(self.dispatch)
        ):
            raise ValueError("direct V2 promotion enqueue start is invalid")


@runtime_checkable
class PromotionDispatchStore(Protocol):
    """Reserve promotion identities and advance one exact task with CAS."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_promotion_dispatch(
        self,
        command: PromotionCommandV1,
    ) -> StoredRecord[PromotionDispatchRecordV1] | None: ...

    async def prepare_or_adopt_promotion_dispatch(
        self,
        command: PromotionCommandV1,
        prepared: PromotionDispatchRecordV1,
    ) -> StoredRecord[PromotionDispatchRecordV1]: ...

    async def compare_and_set_promotion_dispatch(
        self,
        expected: StoredRecord[PromotionDispatchRecordV1],
        replacement: PromotionDispatchRecordV1,
    ) -> StoredRecord[PromotionDispatchRecordV1]: ...

    async def begin_promotion_enqueue(
        self,
        expected: StoredRecord[PromotionDispatchRecordV1],
        replacement: PromotionDispatchRecordV1,
    ) -> DirectPromotionEnqueueStart: ...


@runtime_checkable
class PromotionDispatchStoreV2(Protocol):
    """Reserve V2 promotion identities and advance one exact task with CAS."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_promotion_dispatch_v2(
        self,
        command: PromotionCommandV2,
    ) -> StoredRecord[PromotionDispatchRecordV2] | None: ...

    async def prepare_or_adopt_promotion_dispatch_v2(
        self,
        command: PromotionCommandV2,
        prepared: PromotionDispatchRecordV2,
    ) -> StoredRecord[PromotionDispatchRecordV2]: ...

    async def compare_and_set_promotion_dispatch_v2(
        self,
        expected: StoredRecord[PromotionDispatchRecordV2],
        replacement: PromotionDispatchRecordV2,
    ) -> StoredRecord[PromotionDispatchRecordV2]: ...

    async def begin_promotion_enqueue_v2(
        self,
        expected: StoredRecord[PromotionDispatchRecordV2],
        replacement: PromotionDispatchRecordV2,
    ) -> DirectPromotionEnqueueStartV2: ...


@runtime_checkable
class PromotionHealthChainReader(Protocol):
    """Load one full durable chain only through every compact locator binding."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_promotion_health_chain(
        self,
        locator: PromotionHealthChainLocatorV1,
    ) -> SignedHealthDecisionChainV1 | None: ...


__all__ = [
    "DirectPromotionEnqueueStart",
    "DirectPromotionEnqueueStartV2",
    "PromotionDispatchStore",
    "PromotionDispatchStoreV2",
    "PromotionEnqueuePermit",
    "PromotionEnqueuePermitV2",
    "PromotionHealthChainReader",
]
