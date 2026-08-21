"""Target-sealed timeline ports, authorization, and deterministic projections."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.timeline import (
    TIMELINE_CORRELATION_V1,
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_ENTRY_PROJECTION_V1,
    TIMELINE_PAGE_V1,
    TimelineActorRole,
    TimelineAudience,
    TimelineCorrelationV1,
    TimelineDisplayFieldV1,
    TimelineEntryProjectionV1,
    TimelineEntryV1,
    TimelineEventV1,
    TimelineEvidencePolicySetV1,
    TimelineHeadV1,
    TimelinePageCommandV1,
    TimelinePageV1,
)

REDACTED_DISPLAY_VALUE = "[REDACTED]"

_AUDIENCE_RANK = {
    TimelineAudience.PUBLIC_DEMO: 0,
    TimelineAudience.OPERATOR: 1,
    TimelineAudience.SECURITY_AUDIT: 2,
    TimelineAudience.RESTRICTED: 3,
}
_SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(
        r"(?i)[\"']?(?:authorization|cookie|set-cookie|password|private[_-]?key|"
        r"client[_-]?secret|access[_-]?token|identity[_-]?token|signature|"
        r"capability|x-goog-iap-jwt-assertion)[\"']?\s*[:=]"
    ),
)


class TimelineStoreErrorCode(StrEnum):
    CONFLICT = "TIMELINE_STORE_CONFLICT"
    CORRUPT_RECORD = "TIMELINE_STORE_CORRUPT_RECORD"
    OUTCOME_UNKNOWN = "TIMELINE_STORE_OUTCOME_UNKNOWN"
    UNAVAILABLE = "TIMELINE_STORE_UNAVAILABLE"
    CURSOR_INVALID = "TIMELINE_CURSOR_INVALID"


class TimelineStoreError(RuntimeError):
    """Sanitized storage failure with no provider or source payload."""

    def __init__(self, code: TimelineStoreErrorCode) -> None:
        if type(code) is not TimelineStoreErrorCode:
            raise TypeError("an exact timeline store error code is required")
        self.code = code
        super().__init__(code.value)


class TimelineStoreConflict(TimelineStoreError):
    def __init__(self) -> None:
        super().__init__(TimelineStoreErrorCode.CONFLICT)


class TimelineStoreCorruptRecord(TimelineStoreError):
    def __init__(self) -> None:
        super().__init__(TimelineStoreErrorCode.CORRUPT_RECORD)


class TimelineStoreOutcomeUnknown(TimelineStoreError):
    def __init__(self) -> None:
        super().__init__(TimelineStoreErrorCode.OUTCOME_UNKNOWN)


class TimelineStoreUnavailable(TimelineStoreError):
    def __init__(self) -> None:
        super().__init__(TimelineStoreErrorCode.UNAVAILABLE)


class TimelineCursorInvalid(TimelineStoreError):
    def __init__(self) -> None:
        super().__init__(TimelineStoreErrorCode.CURSOR_INVALID)


class TimelineReadErrorCode(StrEnum):
    CONFIGURATION_INVALID = "TIMELINE_READ_CONFIGURATION_INVALID"
    ACCESS_DENIED = "TIMELINE_READ_ACCESS_DENIED"
    TARGET_DENIED = "TIMELINE_READ_TARGET_DENIED"
    CURSOR_INVALID = "TIMELINE_READ_CURSOR_INVALID"
    STORE_UNAVAILABLE = "TIMELINE_READ_STORE_UNAVAILABLE"
    RESPONSE_INVALID = "TIMELINE_READ_RESPONSE_INVALID"


class TimelineReadError(RuntimeError):
    """Bounded application failure for an audience-scoped read."""

    def __init__(self, code: TimelineReadErrorCode) -> None:
        if type(code) is not TimelineReadErrorCode:
            raise TypeError("an exact timeline read error code is required")
        self.code = code
        super().__init__(code.value)


class TimelineWriteErrorCode(StrEnum):
    CONFIGURATION_INVALID = "TIMELINE_WRITE_CONFIGURATION_INVALID"
    ACCESS_DENIED = "TIMELINE_WRITE_ACCESS_DENIED"
    TARGET_DENIED = "TIMELINE_WRITE_TARGET_DENIED"
    POLICY_DENIED = "TIMELINE_WRITE_POLICY_DENIED"
    CONFLICT = "TIMELINE_WRITE_CONFLICT"
    STORE_UNAVAILABLE = "TIMELINE_WRITE_STORE_UNAVAILABLE"


class TimelineWriteError(RuntimeError):
    """Bounded application failure for target-scoped projection writes."""

    def __init__(self, code: TimelineWriteErrorCode) -> None:
        if type(code) is not TimelineWriteErrorCode:
            raise TypeError("an exact timeline write error code is required")
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class TimelineAppendCreated:
    entry: TimelineEntryV1

    def __post_init__(self) -> None:
        if type(self.entry) is not TimelineEntryV1:
            raise TypeError("timeline append result requires an exact entry")


@dataclass(frozen=True, slots=True)
class TimelineAppendAdopted:
    entry: TimelineEntryV1

    def __post_init__(self) -> None:
        if type(self.entry) is not TimelineEntryV1:
            raise TypeError("timeline append result requires an exact entry")


type TimelineAppendResult = TimelineAppendCreated | TimelineAppendAdopted


@dataclass(frozen=True, slots=True)
class TimelineReadSlice:
    """Full immutable entries behind one strongly observed head."""

    command: TimelinePageCommandV1
    head: TimelineHeadV1 | None
    entries: tuple[TimelineEntryV1, ...]

    def __post_init__(self) -> None:
        if type(self.command) is not TimelinePageCommandV1:
            raise TypeError("timeline read slice requires an exact command")
        if self.head is None:
            if self.command.after_sequence != 0 or self.entries:
                raise ValueError("an empty timeline cannot satisfy a nonzero cursor")
            return
        if type(self.head) is not TimelineHeadV1 or self.head.target != self.command.target:
            raise ValueError("timeline head does not match the read target")
        command = self.command
        if command.after_sequence > self.head.sequence:
            raise ValueError("timeline cursor is beyond the observed head")
        expected_count = min(command.limit, self.head.sequence - command.after_sequence)
        if len(self.entries) != expected_count:
            raise ValueError("timeline read slice is not omission-free")
        predecessor = command.after_entry_sha256
        sequence = command.after_sequence + 1
        for entry in self.entries:
            if (
                type(entry) is not TimelineEntryV1
                or entry.content.target != command.target
                or entry.content.sequence != sequence
                or entry.content.previous_entry_sha256 != predecessor
            ):
                raise ValueError("timeline read slice is not contiguous")
            predecessor = entry.entry_sha256
            sequence += 1
        if command.after_sequence == self.head.sequence:
            if command.after_entry_sha256 != self.head.entry_sha256:
                raise ValueError("timeline cursor does not identify the observed head")
        elif (
            self.entries[-1].content.sequence == self.head.sequence
            and self.entries[-1].entry_sha256 != self.head.entry_sha256
        ):
            raise ValueError("timeline entries do not terminate at the observed head")


@dataclass(frozen=True, slots=True)
class TimelineReadGrant:
    """Audience ceiling derived by a trusted authenticated composition boundary."""

    target: TargetBinding
    maximum_audience: TimelineAudience
    principal_id: str

    def __post_init__(self) -> None:
        if (
            type(self.target) is not TargetBinding
            or type(self.maximum_audience) is not TimelineAudience
            or type(self.principal_id) is not str
            or not self.principal_id
            or len(self.principal_id) > 128
        ):
            raise ValueError("timeline read grant is invalid")


@dataclass(frozen=True, slots=True)
class TimelineWriteGrant:
    """Writer role derived by a trusted workload-authentication boundary."""

    target: TargetBinding
    writer_role: TimelineActorRole
    principal_id: str

    def __post_init__(self) -> None:
        if (
            type(self.target) is not TargetBinding
            or type(self.writer_role) is not TimelineActorRole
            or type(self.principal_id) is not str
            or not self.principal_id
            or len(self.principal_id) > 128
        ):
            raise ValueError("timeline write grant is invalid")


@runtime_checkable
class TimelineStore(Protocol):
    """Exact get/create/update surface; no list, query, delete, or raw export."""

    @property
    def target(self) -> TargetBinding: ...

    async def append(self, event: TimelineEventV1) -> TimelineAppendResult: ...

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice: ...


def _is_visible(data_class: TimelineAudience, audience: TimelineAudience) -> bool:
    return _AUDIENCE_RANK[data_class] <= _AUDIENCE_RANK[audience]


def _is_secret_shaped(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in _SECRET_PATTERNS)


def project_timeline_entry(
    entry: TimelineEntryV1,
    audience: TimelineAudience,
) -> TimelineEntryProjectionV1:
    """Return one deterministic allowlist projection without raw source material."""

    if type(entry) is not TimelineEntryV1 or type(audience) is not TimelineAudience:
        raise TypeError("timeline projection requires exact inputs")
    content = entry.content
    event = content.event
    actor_id = (
        event.actor_id
        if _is_visible(event.actor_data_class, audience)
        and not _is_secret_shaped(event.actor_id)
        else None
    )
    correlations = tuple(
        TimelineCorrelationV1(
            schema_version=TIMELINE_CORRELATION_V1,
            kind=item.kind,
            correlation_id=item.correlation_id,
            data_class=item.data_class,
        )
        for item in event.correlations
        if _is_visible(item.data_class, audience)
        and not _is_secret_shaped(item.correlation_id)
    )
    display_fields = tuple(
        TimelineDisplayFieldV1(
            schema_version=TIMELINE_DISPLAY_FIELD_V1,
            name=item.name,
            value=(
                REDACTED_DISPLAY_VALUE
                if _is_secret_shaped(item.value)
                else item.value
            ),
            data_class=item.data_class,
        )
        for item in event.display_fields
        if _is_visible(item.data_class, audience)
    )
    return TimelineEntryProjectionV1(
        schema_version=TIMELINE_ENTRY_PROJECTION_V1,
        audience=audience,
        entry_id=entry.entry_id,
        entry_sha256=entry.entry_sha256,
        sequence=content.sequence,
        previous_entry_sha256=content.previous_entry_sha256,
        target=content.target,
        source_schema_version=event.source_schema_version,
        event_type=event.event_type,
        evidence_class=event.evidence_class,
        actor_role=event.actor_role,
        actor_id=actor_id,
        actor_data_class=event.actor_data_class,
        root_id=event.root_id,
        root_sha256=event.root_sha256,
        epoch=event.epoch,
        occurred_at=event.occurred_at,
        recorded_at=content.recorded_at,
        correlations=correlations,
        payload_sha256=event.payload_sha256,
        policy_sha256=event.policy_sha256,
        raw_retention_days=event.raw_retention_days,
        signature=event.signature,
        verification_status=event.verification_status,
        terminal_classification=event.terminal_classification,
        display_fields=display_fields,
    )


def project_timeline_page(read: TimelineReadSlice) -> TimelinePageV1:
    """Project a validated full slice into one audience-specific page."""

    if type(read) is not TimelineReadSlice:
        raise TypeError("timeline page projection requires an exact read slice")
    command = read.command
    entries = tuple(project_timeline_entry(item, command.audience) for item in read.entries)
    head_sequence = 0 if read.head is None else read.head.sequence
    head_sha256 = None if read.head is None else read.head.entry_sha256
    next_sha256: str | None
    if entries:
        next_sequence = entries[-1].sequence
        next_sha256 = entries[-1].entry_sha256
    else:
        next_sequence = command.after_sequence
        next_sha256 = command.after_entry_sha256
    return TimelinePageV1(
        schema_version=TIMELINE_PAGE_V1,
        command=command,
        command_sha256=canonical_sha256(command),
        entries=entries,
        next_after_sequence=next_sequence,
        next_after_entry_sha256=next_sha256,
        head_sequence=head_sequence,
        head_entry_sha256=head_sha256,
        has_more=next_sequence < head_sequence,
    )


class TimelineReadService:
    """Enforce target and audience scope before returning a projection."""

    def __init__(self, *, target: TargetBinding, store: TimelineStore) -> None:
        if (
            type(target) is not TargetBinding
            or not isinstance(store, TimelineStore)
            or store.target != target
        ):
            raise TimelineReadError(TimelineReadErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._store = store

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def read(
        self,
        command: TimelinePageCommandV1,
        grant: TimelineReadGrant,
    ) -> TimelinePageV1:
        if type(command) is not TimelinePageCommandV1 or type(grant) is not TimelineReadGrant:
            raise TimelineReadError(TimelineReadErrorCode.ACCESS_DENIED)
        if command.target != self._target or grant.target != self._target:
            raise TimelineReadError(TimelineReadErrorCode.TARGET_DENIED)
        if _AUDIENCE_RANK[command.audience] > _AUDIENCE_RANK[grant.maximum_audience]:
            raise TimelineReadError(TimelineReadErrorCode.ACCESS_DENIED)
        try:
            read = await self._store.read_page(command)
            return project_timeline_page(read)
        except asyncio.CancelledError:
            raise
        except TimelineCursorInvalid:
            raise TimelineReadError(TimelineReadErrorCode.CURSOR_INVALID) from None
        except TimelineStoreError:
            raise TimelineReadError(TimelineReadErrorCode.STORE_UNAVAILABLE) from None
        except (TypeError, ValueError):
            raise TimelineReadError(TimelineReadErrorCode.RESPONSE_INVALID) from None


class TimelineWriteService:
    """Bind writes to the configured target, policy digest, and workload role."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        policy_set: TimelineEvidencePolicySetV1,
        store: TimelineStore,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or type(policy_set) is not TimelineEvidencePolicySetV1
            or policy_set.target != target
            or not isinstance(store, TimelineStore)
            or store.target != target
        ):
            raise TimelineWriteError(TimelineWriteErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._policy_set = policy_set
        self._policy_sha256 = canonical_sha256(policy_set)
        self._policies = {
            policy.evidence_class: policy for policy in policy_set.policies
        }
        self._store = store

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def append(
        self,
        event: TimelineEventV1,
        grant: TimelineWriteGrant,
    ) -> TimelineAppendResult:
        if type(event) is not TimelineEventV1 or type(grant) is not TimelineWriteGrant:
            raise TimelineWriteError(TimelineWriteErrorCode.ACCESS_DENIED)
        if event.target != self._target or grant.target != self._target:
            raise TimelineWriteError(TimelineWriteErrorCode.TARGET_DENIED)
        policy = self._policies[event.evidence_class]
        if grant.writer_role not in policy.writer_roles:
            raise TimelineWriteError(TimelineWriteErrorCode.ACCESS_DENIED)
        if (
            event.policy_sha256 != self._policy_sha256
            or event.raw_retention_days != policy.raw_retention_days
        ):
            raise TimelineWriteError(TimelineWriteErrorCode.POLICY_DENIED)
        try:
            return await self._store.append(event)
        except asyncio.CancelledError:
            raise
        except TimelineStoreConflict:
            raise TimelineWriteError(TimelineWriteErrorCode.CONFLICT) from None
        except TimelineStoreError:
            raise TimelineWriteError(TimelineWriteErrorCode.STORE_UNAVAILABLE) from None


__all__ = [
    "REDACTED_DISPLAY_VALUE",
    "TimelineAppendAdopted",
    "TimelineAppendCreated",
    "TimelineAppendResult",
    "TimelineCursorInvalid",
    "TimelineReadError",
    "TimelineReadErrorCode",
    "TimelineReadGrant",
    "TimelineReadService",
    "TimelineReadSlice",
    "TimelineStore",
    "TimelineStoreConflict",
    "TimelineStoreCorruptRecord",
    "TimelineStoreError",
    "TimelineStoreErrorCode",
    "TimelineStoreOutcomeUnknown",
    "TimelineStoreUnavailable",
    "TimelineWriteError",
    "TimelineWriteErrorCode",
    "TimelineWriteGrant",
    "TimelineWriteService",
    "project_timeline_entry",
    "project_timeline_page",
]
