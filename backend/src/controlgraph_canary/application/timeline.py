"""Target-sealed timeline ports, authorization, and deterministic projections."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.timeline import (
    TIMELINE_CORRELATION_V1,
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_ENTRY_PROJECTION_V1,
    TIMELINE_PAGE_V1,
    TIMELINE_RAW_EXPORT_ITEM_V1,
    TIMELINE_RAW_EXPORT_V1,
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
    TimelineRawDeletionReceiptV1,
    TimelineRawEvidenceV1,
    TimelineRawExportCommandV1,
    TimelineRawExportItemV1,
    TimelineRawExportV1,
    TimelineRawLifecycleStatus,
    TimelineRawSourceV1,
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


class TimelineRawExportErrorCode(StrEnum):
    CONFIGURATION_INVALID = "TIMELINE_RAW_EXPORT_CONFIGURATION_INVALID"
    ACCESS_DENIED = "TIMELINE_RAW_EXPORT_ACCESS_DENIED"
    TARGET_DENIED = "TIMELINE_RAW_EXPORT_TARGET_DENIED"
    CURSOR_INVALID = "TIMELINE_RAW_EXPORT_CURSOR_INVALID"
    STORE_UNAVAILABLE = "TIMELINE_RAW_EXPORT_STORE_UNAVAILABLE"
    RESPONSE_INVALID = "TIMELINE_RAW_EXPORT_RESPONSE_INVALID"


class TimelineRawExportError(RuntimeError):
    """Bounded failure for the separately gated raw-record surface."""

    def __init__(self, code: TimelineRawExportErrorCode) -> None:
        if type(code) is not TimelineRawExportErrorCode:
            raise TypeError("an exact timeline raw export error code is required")
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
class TimelineRawReadSlice:
    """Full entries and exact-ID raw records behind one strongly observed head."""

    command: TimelineRawExportCommandV1
    head: TimelineHeadV1 | None
    entries: tuple[TimelineEntryV1, ...]
    raw_evidence: tuple[TimelineRawEvidenceV1 | None, ...]
    deletion_receipts: tuple[TimelineRawDeletionReceiptV1 | None, ...]
    evaluated_at: str

    def __post_init__(self) -> None:
        if type(self.command) is not TimelineRawExportCommandV1:
            raise TypeError("timeline raw read slice requires an exact command")
        try:
            evaluated = datetime.strptime(self.evaluated_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            )
        except (TypeError, ValueError) as error:
            raise ValueError("timeline raw read evaluation time is invalid") from error
        if self.head is None:
            if (
                self.command.after_sequence != 0
                or self.entries
                or self.raw_evidence
                or self.deletion_receipts
            ):
                raise ValueError("an empty timeline cannot satisfy a raw export cursor")
            return
        if (
            type(self.head) is not TimelineHeadV1
            or self.head.target != self.command.target
            or len(self.raw_evidence) != len(self.entries)
            or len(self.deletion_receipts) != len(self.entries)
        ):
            raise ValueError("timeline raw read head or record count is invalid")
        expected_count = min(
            self.command.limit,
            self.head.sequence - self.command.after_sequence,
        )
        if expected_count < 0 or len(self.entries) != expected_count:
            raise ValueError("timeline raw read slice is not omission-free")
        sequence = self.command.after_sequence + 1
        predecessor = self.command.after_entry_sha256
        for entry, raw, receipt in zip(
            self.entries,
            self.raw_evidence,
            self.deletion_receipts,
            strict=True,
        ):
            if (
                type(entry) is not TimelineEntryV1
                or entry.content.target != self.command.target
                or entry.content.sequence != sequence
                or entry.content.previous_entry_sha256 != predecessor
            ):
                raise ValueError("timeline raw read slice is not contiguous")
            expires = _raw_expires_at(entry)
            if raw is None and (
                evaluated < expires
                or receipt is None
                or not _deletion_receipt_matches_entry(receipt, entry)
            ):
                raise ValueError("timeline raw deletion evidence is absent")
            if raw is not None and (
                evaluated >= expires
                or receipt is not None
                or not _raw_matches_entry(raw, entry, expires_at=_utc_second(expires))
            ):
                raise ValueError("timeline raw evidence does not match its entry")
            sequence += 1
            predecessor = entry.entry_sha256
        if self.command.after_sequence == self.head.sequence:
            if self.command.after_entry_sha256 != self.head.entry_sha256:
                raise ValueError("timeline raw cursor does not identify the observed head")
        elif (
            self.entries[-1].content.sequence == self.head.sequence
            and self.entries[-1].entry_sha256 != self.head.entry_sha256
        ):
            raise ValueError("timeline raw entries do not terminate at the observed head")


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


@dataclass(frozen=True, slots=True)
class TimelineRawExportGrant:
    """Separate restricted-export authority derived at an authenticated route."""

    target: TargetBinding
    principal_id: str

    def __post_init__(self) -> None:
        if (
            type(self.target) is not TargetBinding
            or type(self.principal_id) is not str
            or not self.principal_id
            or len(self.principal_id) > 128
        ):
            raise ValueError("timeline raw export grant is invalid")


@runtime_checkable
class TimelineStore(Protocol):
    """Exact get/create/update surface; no list, query, delete, or raw export."""

    @property
    def target(self) -> TargetBinding: ...

    async def append(self, event: TimelineEventV1) -> TimelineAppendResult: ...

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice: ...


@runtime_checkable
class TimelineRawStore(Protocol):
    """Atomic raw append plus exact-ID export and policy-bound expiry deletion."""

    @property
    def target(self) -> TargetBinding: ...

    async def append_with_raw(
        self,
        event: TimelineEventV1,
        raw_source: TimelineRawSourceV1,
    ) -> TimelineAppendResult: ...

    async def read_raw_export(
        self,
        command: TimelineRawExportCommandV1,
    ) -> TimelineRawReadSlice: ...


@runtime_checkable
class TimelineRawBatchStore(Protocol):
    """Atomic ordered append surface for one causally related projection group."""

    @property
    def target(self) -> TargetBinding: ...

    async def append_many_with_raw(
        self,
        items: tuple[tuple[TimelineEventV1, TimelineRawSourceV1], ...],
    ) -> tuple[TimelineAppendResult, ...]: ...


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


def _parse_utc_second(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _utc_second(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _raw_expires_at(entry: TimelineEntryV1) -> datetime:
    return _parse_utc_second(entry.content.recorded_at) + timedelta(
        days=entry.content.event.raw_retention_days
    )


def _raw_matches_entry(
    raw: TimelineRawEvidenceV1,
    entry: TimelineEntryV1,
    *,
    expires_at: str,
) -> bool:
    event = entry.content.event
    source = raw.raw_source
    signature_sha256 = None if event.signature is None else event.signature.signature_sha256
    return (
        raw.target == entry.content.target
        and raw.sequence == entry.content.sequence
        and raw.entry_id == entry.entry_id
        and raw.entry_sha256 == entry.entry_sha256
        and raw.source_id == event.source_id
        and raw.recorded_at == entry.content.recorded_at
        and raw.expires_at == expires_at
        and source.raw_source_id == event.raw_source_id
        and source.source_schema_version == event.source_schema_version
        and source.target == event.target
        and source.evidence_class is event.evidence_class
        and source.payload_sha256 == event.payload_sha256
        and source.record_sha256 == event.raw_record_sha256
        and source.signature_sha256 == signature_sha256
    )


def _deletion_receipt_matches_entry(
    receipt: TimelineRawDeletionReceiptV1,
    entry: TimelineEntryV1,
) -> bool:
    event = entry.content.event
    return (
        receipt.target == entry.content.target
        and receipt.sequence == entry.content.sequence
        and receipt.entry_id == entry.entry_id
        and receipt.entry_sha256 == entry.entry_sha256
        and receipt.source_id == event.source_id
        and receipt.raw_source_id == event.raw_source_id
        and receipt.record_sha256 == event.raw_record_sha256
        and receipt.expires_at == _utc_second(_raw_expires_at(entry))
    )


def project_timeline_raw_export(read: TimelineRawReadSlice) -> TimelineRawExportV1:
    """Project a validated raw slice while honoring expiration before TTL cleanup."""

    if type(read) is not TimelineRawReadSlice:
        raise TypeError("timeline raw export projection requires an exact read slice")
    evaluated = _parse_utc_second(read.evaluated_at)
    items: list[TimelineRawExportItemV1] = []
    for entry, raw, receipt in zip(
        read.entries,
        read.raw_evidence,
        read.deletion_receipts,
        strict=True,
    ):
        content = entry.content
        event = content.event
        expires = _raw_expires_at(entry)
        deleted = evaluated >= expires
        if (raw is None) != deleted or (receipt is not None) != deleted:
            raise ValueError("timeline raw lifecycle evidence is inconsistent")
        source = None if raw is None else raw.raw_source
        items.append(
            TimelineRawExportItemV1(
                schema_version=TIMELINE_RAW_EXPORT_ITEM_V1,
                sequence=content.sequence,
                entry_id=entry.entry_id,
                entry_sha256=entry.entry_sha256,
                previous_entry_sha256=content.previous_entry_sha256,
                source_id=event.source_id,
                raw_source_id=event.raw_source_id,
                source_schema_version=event.source_schema_version,
                event_type=event.event_type,
                evidence_class=event.evidence_class,
                payload_sha256=event.payload_sha256,
                record_sha256=event.raw_record_sha256,
                signature_sha256=(
                    None if event.signature is None else event.signature.signature_sha256
                ),
                recorded_at=content.recorded_at,
                expires_at=_utc_second(expires),
                lifecycle_status=(
                    TimelineRawLifecycleStatus.DELETED
                    if deleted
                    else TimelineRawLifecycleStatus.AVAILABLE
                ),
                canonical_record=(
                    None
                    if deleted
                    else source.canonical_record
                    if source is not None
                    else None
                ),
                deletion_receipt_id=(
                    receipt.receipt_id if receipt is not None else None
                ),
                deletion_receipt_sha256=(
                    canonical_sha256(receipt) if receipt is not None else None
                ),
                deletion_confirmed_at=(
                    receipt.deletion_confirmed_at if receipt is not None else None
                ),
                deletion_policy="EXPIRE_RAW_PRESERVE_DIGEST_V1",
            )
        )
    head_sequence = 0 if read.head is None else read.head.sequence
    head_digest = None if read.head is None else read.head.entry_sha256
    next_digest: str | None
    if items:
        next_sequence = items[-1].sequence
        next_digest = items[-1].entry_sha256
    else:
        next_sequence = read.command.after_sequence
        next_digest = read.command.after_entry_sha256
    return TimelineRawExportV1(
        schema_version=TIMELINE_RAW_EXPORT_V1,
        command=read.command,
        command_sha256=canonical_sha256(read.command),
        evaluated_at=read.evaluated_at,
        entries=tuple(items),
        next_after_sequence=next_sequence,
        next_after_entry_sha256=next_digest,
        head_sequence=head_sequence,
        head_entry_sha256=head_digest,
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


class TimelineRawExportService:
    """Enforce the separate restricted-export grant before exact-ID raw reads."""

    def __init__(self, *, target: TargetBinding, store: TimelineRawStore) -> None:
        if (
            type(target) is not TargetBinding
            or not isinstance(store, TimelineRawStore)
            or store.target != target
        ):
            raise TimelineRawExportError(
                TimelineRawExportErrorCode.CONFIGURATION_INVALID
            )
        self._target = target
        self._store = store

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def export(
        self,
        command: TimelineRawExportCommandV1,
        grant: TimelineRawExportGrant,
    ) -> TimelineRawExportV1:
        if (
            type(command) is not TimelineRawExportCommandV1
            or type(grant) is not TimelineRawExportGrant
        ):
            raise TimelineRawExportError(TimelineRawExportErrorCode.ACCESS_DENIED)
        if command.target != self._target or grant.target != self._target:
            raise TimelineRawExportError(TimelineRawExportErrorCode.TARGET_DENIED)
        try:
            read = await self._store.read_raw_export(command)
            return project_timeline_raw_export(read)
        except asyncio.CancelledError:
            raise
        except TimelineCursorInvalid:
            raise TimelineRawExportError(TimelineRawExportErrorCode.CURSOR_INVALID) from None
        except TimelineStoreError:
            raise TimelineRawExportError(
                TimelineRawExportErrorCode.STORE_UNAVAILABLE
            ) from None
        except (TypeError, ValueError):
            raise TimelineRawExportError(
                TimelineRawExportErrorCode.RESPONSE_INVALID
            ) from None


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

    async def append_with_raw(
        self,
        event: TimelineEventV1,
        raw_source: TimelineRawSourceV1,
        grant: TimelineWriteGrant,
    ) -> TimelineAppendResult:
        if (
            type(event) is not TimelineEventV1
            or type(raw_source) is not TimelineRawSourceV1
            or type(grant) is not TimelineWriteGrant
        ):
            raise TimelineWriteError(TimelineWriteErrorCode.ACCESS_DENIED)
        if (
            event.target != self._target
            or raw_source.target != self._target
            or grant.target != self._target
        ):
            raise TimelineWriteError(TimelineWriteErrorCode.TARGET_DENIED)
        policy = self._policies[event.evidence_class]
        signature_sha256 = (
            None if event.signature is None else event.signature.signature_sha256
        )
        if grant.writer_role not in policy.writer_roles:
            raise TimelineWriteError(TimelineWriteErrorCode.ACCESS_DENIED)
        if (
            event.policy_sha256 != self._policy_sha256
            or event.raw_retention_days != policy.raw_retention_days
            or raw_source.raw_source_id != event.raw_source_id
            or raw_source.source_schema_version != event.source_schema_version
            or raw_source.evidence_class is not event.evidence_class
            or raw_source.payload_sha256 != event.payload_sha256
            or raw_source.record_sha256 != event.raw_record_sha256
            or raw_source.signature_sha256 != signature_sha256
            or not isinstance(self._store, TimelineRawStore)
        ):
            raise TimelineWriteError(TimelineWriteErrorCode.POLICY_DENIED)
        try:
            return await self._store.append_with_raw(event, raw_source)
        except asyncio.CancelledError:
            raise
        except TimelineStoreConflict:
            raise TimelineWriteError(TimelineWriteErrorCode.CONFLICT) from None
        except TimelineStoreError:
            raise TimelineWriteError(TimelineWriteErrorCode.STORE_UNAVAILABLE) from None

    async def append_many_with_raw(
        self,
        items: tuple[tuple[TimelineEventV1, TimelineRawSourceV1], ...],
        grant: TimelineWriteGrant,
    ) -> tuple[TimelineAppendResult, ...]:
        """Atomically append one nonempty, ordered group of summary and raw records."""

        if (
            type(items) is not tuple
            or not items
            or len(items) > 32
            or type(grant) is not TimelineWriteGrant
            or not isinstance(self._store, TimelineRawBatchStore)
        ):
            raise TimelineWriteError(TimelineWriteErrorCode.ACCESS_DENIED)
        source_ids: set[str] = set()
        for item in items:
            if type(item) is not tuple or len(item) != 2:
                raise TimelineWriteError(TimelineWriteErrorCode.ACCESS_DENIED)
            event, raw_source = item
            if type(event) is not TimelineEventV1 or type(raw_source) is not TimelineRawSourceV1:
                raise TimelineWriteError(TimelineWriteErrorCode.ACCESS_DENIED)
            if (
                event.target != self._target
                or raw_source.target != self._target
                or grant.target != self._target
            ):
                raise TimelineWriteError(TimelineWriteErrorCode.TARGET_DENIED)
            policy = self._policies[event.evidence_class]
            signature_sha256 = (
                None if event.signature is None else event.signature.signature_sha256
            )
            if grant.writer_role not in policy.writer_roles:
                raise TimelineWriteError(TimelineWriteErrorCode.ACCESS_DENIED)
            if (
                event.source_id in source_ids
                or event.policy_sha256 != self._policy_sha256
                or event.raw_retention_days != policy.raw_retention_days
                or raw_source.raw_source_id != event.raw_source_id
                or raw_source.source_schema_version != event.source_schema_version
                or raw_source.evidence_class is not event.evidence_class
                or raw_source.payload_sha256 != event.payload_sha256
                or raw_source.record_sha256 != event.raw_record_sha256
                or raw_source.signature_sha256 != signature_sha256
            ):
                raise TimelineWriteError(TimelineWriteErrorCode.POLICY_DENIED)
            source_ids.add(event.source_id)
        try:
            return await self._store.append_many_with_raw(items)
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
    "TimelineRawBatchStore",
    "TimelineRawExportError",
    "TimelineRawExportErrorCode",
    "TimelineRawExportGrant",
    "TimelineRawExportService",
    "TimelineRawReadSlice",
    "TimelineRawStore",
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
    "project_timeline_raw_export",
]
