"""Two-read capture of one exact stable Cloud Run baseline."""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

from controlgraph_canary.application.cloud_run import (
    CloudRunReadError,
    CloudRunReadErrorCode,
    CloudRunRevisionState,
    CloudRunServiceState,
    DeclaredRevision,
)
from controlgraph_canary.contracts.codec import RestrictedJson, canonical_json_value_bytes
from controlgraph_canary.contracts.models import (
    STABLE_SNAPSHOT_V1,
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
)

STABLE_CONFIGURATION_V1: Final = "controlgraph.stable-configuration/v1"
STABLE_CONFIGURATION_DOMAIN: Final = b"controlgraph.stable-configuration-sha256/v1\0"
MAX_STABLE_CAPTURE_ATTEMPTS: Final = 3

_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"


class StableCaptureReason(StrEnum):
    """Closed, provider-independent stable-capture failures."""

    SERVICE_MISSING = "STABLE_CAPTURE_SERVICE_MISSING"
    REVISION_MISSING = "STABLE_CAPTURE_REVISION_MISSING"
    SOURCE_UNAVAILABLE = "STABLE_CAPTURE_SOURCE_UNAVAILABLE"
    SOURCE_INVALID = "STABLE_CAPTURE_SOURCE_INVALID"
    TARGET_MISMATCH = "STABLE_CAPTURE_TARGET_MISMATCH"
    SERVICE_NOT_READY = "STABLE_CAPTURE_SERVICE_NOT_READY"
    TRAFFIC_UNRESOLVED = "STABLE_CAPTURE_TRAFFIC_UNRESOLVED"
    BASELINE_NOT_STABLE = "STABLE_CAPTURE_BASELINE_NOT_STABLE"
    TRAFFIC_UNSUPPORTED = "STABLE_CAPTURE_TRAFFIC_UNSUPPORTED"
    REVISION_NOT_READY = "STABLE_CAPTURE_REVISION_NOT_READY"
    SOURCE_CHANGED = "STABLE_CAPTURE_SOURCE_CHANGED"


class StableCaptureError(RuntimeError):
    """Sanitized stable-capture failure with no provider response material."""

    def __init__(self, reason: StableCaptureReason) -> None:
        if type(reason) is not StableCaptureReason:
            raise TypeError("an exact stable-capture reason is required")
        self.reason = reason
        super().__init__(reason.value)


class _SourceChanged(RuntimeError):
    pass


@runtime_checkable
class StableSnapshotReader(Protocol):
    """Read-only target port required by stable snapshot capture."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_service(self) -> CloudRunServiceState: ...

    async def read_revision(self, declared: DeclaredRevision) -> CloudRunRevisionState: ...


@dataclass(frozen=True, slots=True)
class StableSnapshotCaptureConfiguration:
    """Trusted target and authenticated reader binding for one capture use case."""

    target: TargetBinding
    reader_identity: str

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("stable capture requires an exact configured target")
        if (
            _CONTROLGRAPH_PROJECT_ID.fullmatch(self.target.project_id) is None
            or self.target.region != "us-central1"
            or self.target.service_name != _REFERENCE_SERVICE
            or "reconcile" in self.target.environment.lower()
        ):
            raise ValueError("stable capture target is outside the ControlGraph boundary")
        expected_reader = (
            f"controlgraph-verifier@{self.target.project_id}.iam.gserviceaccount.com"
        )
        if type(self.reader_identity) is not str or self.reader_identity != expected_reader:
            raise ValueError("stable capture reader is not the configured verifier identity")


def stable_configuration_sha256(
    service: CloudRunServiceState,
    revision: CloudRunRevisionState,
    traffic: tuple[TrafficAllocation, ...],
) -> str:
    """Hash only the exact serving configuration needed to classify the baseline."""

    if type(service) is not CloudRunServiceState or type(revision) is not CloudRunRevisionState:
        raise TypeError("stable configuration requires exact Cloud Run state")
    observed_traffic = {
        (allocation.revision, allocation.percent) for allocation in service.traffic
    }
    observed_statuses = {
        (allocation.revision, allocation.percent) for allocation in service.traffic_statuses
    }
    projected_traffic = {(allocation.revision, allocation.percent) for allocation in traffic}
    if (
        service.target != revision.target
        or not traffic
        or len(traffic) > 2
        or any(type(item) is not TrafficAllocation for item in traffic)
        or observed_traffic != projected_traffic
        or observed_statuses != projected_traffic
        or traffic[0].revision != revision.revision
        or traffic[0].percent != 100
        or (
            len(traffic) == 2
            and (traffic[1].revision == revision.revision or traffic[1].percent != 0)
        )
    ):
        raise ValueError("stable configuration state is not one exact baseline")
    traffic_value: list[RestrictedJson] = [
        {
            "percent": allocation.percent,
            "revision": allocation.revision,
        }
        for allocation in traffic
    ]
    value: RestrictedJson = {
        "concurrency": revision.concurrency,
        "schema_version": STABLE_CONFIGURATION_V1,
        "service_uid": service.uid,
        "stable_revision": revision.revision,
        "stable_revision_etag": revision.etag,
        "stable_revision_generation": revision.generation,
        "stable_revision_uid": revision.uid,
        "target": service.target.model_dump(mode="json"),
        "traffic": traffic_value,
    }
    return hashlib.sha256(
        STABLE_CONFIGURATION_DOMAIN + canonical_json_value_bytes(value)
    ).hexdigest()


class StableSnapshotCapturer:
    """Capture a stable baseline only after two matching service reads."""

    def __init__(
        self,
        *,
        reader: StableSnapshotReader,
        configuration: StableSnapshotCaptureConfiguration,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(configuration) is not StableSnapshotCaptureConfiguration:
            raise TypeError("an exact stable-capture configuration is required")
        try:
            reader_target = reader.target
            read_service = reader.read_service
            read_revision = reader.read_revision
        except Exception:
            raise TypeError("a target-bound stable snapshot reader is required") from None
        if (
            type(reader_target) is not TargetBinding
            or reader_target != configuration.target
            or not callable(read_service)
            or not callable(read_revision)
        ):
            raise ValueError("stable snapshot reader does not match its configured target")
        if clock is not None and not callable(clock):
            raise TypeError("stable snapshot clock must be callable")
        self._reader = reader
        self._configuration = configuration
        self._clock = clock or _now_utc_second

    @property
    def target(self) -> TargetBinding:
        return self._configuration.target

    async def capture(self) -> StableSnapshot:
        """Return one canonical snapshot or a stable, payload-free failure."""

        for attempt in range(MAX_STABLE_CAPTURE_ATTEMPTS):
            try:
                return await self._capture_once()
            except _SourceChanged:
                if attempt + 1 == MAX_STABLE_CAPTURE_ATTEMPTS:
                    raise StableCaptureError(StableCaptureReason.SOURCE_CHANGED) from None
        raise StableCaptureError(StableCaptureReason.SOURCE_CHANGED)

    async def _capture_once(self) -> StableSnapshot:
        first = await self._read_service()
        first_traffic = self._stable_traffic(first)
        stable_revision = await self._read_stable_revision()
        if stable_revision.target != self.target:
            raise StableCaptureError(StableCaptureReason.TARGET_MISMATCH)
        if stable_revision.revision != first_traffic[0].revision:
            raise StableCaptureError(StableCaptureReason.TRAFFIC_UNRESOLVED)
        if (
            stable_revision.reconciling
            or stable_revision.observed_generation != stable_revision.generation
        ):
            raise StableCaptureError(StableCaptureReason.REVISION_NOT_READY)

        second = await self._read_service()
        if second.target != self.target:
            raise StableCaptureError(StableCaptureReason.TARGET_MISMATCH)
        if (
            second.uid != first.uid
            or second.generation != first.generation
            or second.etag != first.etag
        ):
            raise _SourceChanged
        try:
            second_traffic = self._stable_traffic(second)
        except StableCaptureError as error:
            if error.reason is StableCaptureReason.TARGET_MISMATCH:
                raise
            raise _SourceChanged from None
        if second_traffic != first_traffic:
            raise _SourceChanged

        captured_at = _utc_second(self._clock())
        configuration_sha256 = stable_configuration_sha256(
            second,
            stable_revision,
            second_traffic,
        )
        return StableSnapshot(
            schema_version=STABLE_SNAPSHOT_V1,
            target=self.target,
            stable_revision=stable_revision.revision,
            traffic=second_traffic,
            concurrency=stable_revision.concurrency,
            service_generation=second.generation,
            provider_etag=second.etag,
            configuration_sha256=configuration_sha256,
            captured_at=captured_at,
            captured_by=self._configuration.reader_identity,
        )

    async def _read_service(self) -> CloudRunServiceState:
        try:
            value = await self._reader.read_service()
        except asyncio.CancelledError:
            raise
        except CloudRunReadError as error:
            if error.code is CloudRunReadErrorCode.NOT_FOUND:
                raise StableCaptureError(StableCaptureReason.SERVICE_MISSING) from None
            if error.code is CloudRunReadErrorCode.CORRUPT_RESPONSE:
                raise StableCaptureError(StableCaptureReason.SOURCE_INVALID) from None
            raise StableCaptureError(StableCaptureReason.SOURCE_UNAVAILABLE) from None
        except Exception:
            raise StableCaptureError(StableCaptureReason.SOURCE_UNAVAILABLE) from None
        if type(value) is not CloudRunServiceState:
            raise StableCaptureError(StableCaptureReason.SOURCE_INVALID)
        return value

    async def _read_stable_revision(self) -> CloudRunRevisionState:
        try:
            value = await self._reader.read_revision(DeclaredRevision.STABLE)
        except asyncio.CancelledError:
            raise
        except CloudRunReadError as error:
            if error.code is CloudRunReadErrorCode.NOT_FOUND:
                raise StableCaptureError(StableCaptureReason.REVISION_MISSING) from None
            if error.code is CloudRunReadErrorCode.CORRUPT_RESPONSE:
                raise StableCaptureError(StableCaptureReason.SOURCE_INVALID) from None
            raise StableCaptureError(StableCaptureReason.SOURCE_UNAVAILABLE) from None
        except Exception:
            raise StableCaptureError(StableCaptureReason.SOURCE_UNAVAILABLE) from None
        if type(value) is not CloudRunRevisionState:
            raise StableCaptureError(StableCaptureReason.SOURCE_INVALID)
        return value

    def _stable_traffic(
        self,
        service: CloudRunServiceState,
    ) -> tuple[TrafficAllocation, ...]:
        if service.target != self.target:
            raise StableCaptureError(StableCaptureReason.TARGET_MISMATCH)
        if service.reconciling or service.observed_generation != service.generation:
            raise StableCaptureError(StableCaptureReason.SERVICE_NOT_READY)
        traffic_resolution = {
            (allocation.revision, allocation.percent, allocation.tag)
            for allocation in service.traffic
        }
        status_resolution = {
            (allocation.revision, allocation.percent, allocation.tag)
            for allocation in service.traffic_statuses
        }
        if traffic_resolution != status_resolution:
            raise StableCaptureError(StableCaptureReason.TRAFFIC_UNRESOLVED)
        prefix = f"{self.target.service_name}-"
        if any(not allocation.revision.startswith(prefix) for allocation in service.traffic):
            raise StableCaptureError(StableCaptureReason.TRAFFIC_UNSUPPORTED)
        positive = tuple(allocation for allocation in service.traffic if allocation.percent > 0)
        if len(positive) != 1 or positive[0].percent != 100:
            raise StableCaptureError(StableCaptureReason.BASELINE_NOT_STABLE)
        zero = tuple(allocation for allocation in service.traffic if allocation.percent == 0)
        if len(zero) > 1:
            raise StableCaptureError(StableCaptureReason.TRAFFIC_UNSUPPORTED)
        stable = TrafficAllocation(revision=positive[0].revision, percent=100)
        if not zero:
            return (stable,)
        unserved = TrafficAllocation(revision=zero[0].revision, percent=0)
        if unserved.revision == stable.revision:
            raise StableCaptureError(StableCaptureReason.TRAFFIC_UNSUPPORTED)
        return stable, unserved


def _now_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _utc_second(value: datetime) -> str:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.microsecond != 0
    ):
        raise ValueError("stable snapshot clock must return an exact aware second")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "MAX_STABLE_CAPTURE_ATTEMPTS",
    "STABLE_CONFIGURATION_DOMAIN",
    "STABLE_CONFIGURATION_V1",
    "StableCaptureError",
    "StableCaptureReason",
    "StableSnapshotCaptureConfiguration",
    "StableSnapshotCapturer",
    "StableSnapshotReader",
    "stable_configuration_sha256",
]
