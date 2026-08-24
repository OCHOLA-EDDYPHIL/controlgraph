"""Small adapter from durable M6 records to one bounded advisor snapshot."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import RootCreationBundle
from controlgraph_canary.application.timeline import TimelineReadSlice
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.model_assistance import (
    ADVISOR_INVOCATION_REQUEST_V1,
    DIAGNOSTIC_EVIDENCE_FACT_V1,
    DIAGNOSTIC_EVIDENCE_SUMMARY_V1,
    DIAGNOSTIC_SNAPSHOT_V1,
    AdvisorInvocationRequestV1,
    AdvisorOperatorCommandV1,
    AdvisoryHealth,
    DiagnosticEvidenceFactName,
    DiagnosticEvidenceFactV1,
    DiagnosticEvidenceKind,
    DiagnosticEvidenceSummaryCode,
    DiagnosticEvidenceSummaryV1,
    DiagnosticSnapshotV1,
    EvidenceConsistency,
    RolloutPhase,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.root_creation import RolloutRootV3
from controlgraph_canary.contracts.timeline import (
    TIMELINE_PAGE_COMMAND_V1,
    TimelineAudience,
    TimelineEntryV1,
    TimelineEventType,
    TimelineHeadV1,
    TimelinePageCommandV1,
    TimelineTerminalClassification,
    TimelineVerificationStatus,
)

_TIMELINE_PAGE_SIZE = 100
_MAX_TIMELINE_ENTRIES = 1_000
_SNAPSHOT_LIFETIME_SECONDS = 240


@runtime_checkable
class M6AuthorityReader(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootCreationBundle | None: ...


@runtime_checkable
class M6TimelineReader(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice: ...


class M6DiagnosticSnapshotAssembler:
    """Project one current root from the M6 authority and chained timeline stores."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authority: M6AuthorityReader,
        timeline: M6TimelineReader,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or not isinstance(authority, M6AuthorityReader)
            or authority.target != target
            or not isinstance(timeline, M6TimelineReader)
            or timeline.target != target
            or (clock is not None and not callable(clock))
        ):
            raise ValueError("M6 diagnostic snapshot configuration is invalid")
        self._target = target
        self._authority = authority
        self._timeline = timeline
        self._clock = clock or (lambda: datetime.now(UTC))

    async def assemble(
        self,
        command: AdvisorOperatorCommandV1,
    ) -> AdvisorInvocationRequestV1:
        if type(command) is not AdvisorOperatorCommandV1 or command.target != self._target:
            raise ValueError("advisor command target is invalid")
        bundle = await self._authority.read_root_creation_bundle(command.root_id)
        if bundle is None or type(bundle.root.value) is not RolloutRootV3:
            raise ValueError("advisor root evidence is unavailable")
        root = bundle.root.value
        authority = bundle.authority.value
        if (
            root.root_sha256 != command.expected_root_sha256
            or authority.root_id != root.root_id
            or authority.root_sha256 != root.root_sha256
            or authority.current_epoch != command.expected_epoch
            or authority.target != self._target
        ):
            raise ValueError("advisor authority evidence is stale")

        timeline_head, timeline_entries = await _read_timeline(
            target=self._target,
            timeline=self._timeline,
        )
        entries = tuple(
            entry
            for entry in timeline_entries
            if entry.content.event.root_id == root.root_id
            and entry.content.event.root_sha256 == root.root_sha256
        )
        if not entries or any(
            entry.content.event.epoch > authority.current_epoch for entry in entries
        ):
            raise ValueError("advisor timeline evidence is inconsistent")

        root_entries = _verified_entries(entries, TimelineEventType.AUTHORITY_ROOT_CREATED)
        monitoring_entries = _verified_entries(entries, TimelineEventType.HEALTH_OBSERVED)
        health_entries = _verified_entries(entries, TimelineEventType.HEALTH_DECIDED)
        verifier_entries = _verified_entries(entries, TimelineEventType.VERIFICATION_RECORDED)
        receipt_entries = tuple(
            entry
            for entry in entries
            if entry.content.event.event_type
            in {
                TimelineEventType.MUTATION_APPLIED,
                TimelineEventType.MUTATION_DENIED,
                TimelineEventType.MUTATION_AMBIGUOUS,
            }
            and entry.content.event.verification_status
            in {
                TimelineVerificationStatus.VERIFIED,
                TimelineVerificationStatus.AMBIGUOUS,
                TimelineVerificationStatus.NOT_APPLICABLE,
            }
        )
        if (
            not root_entries
            or not monitoring_entries
            or not health_entries
            or not verifier_entries
            or not receipt_entries
        ):
            raise ValueError("advisor evidence set is incomplete")

        plan = root.content.rollout_plan
        health_entry = health_entries[-1]
        health_value = _display_value(health_entry, "OUTCOME")
        health = {
            "healthy": AdvisoryHealth.HEALTHY,
            "unhealthy": AdvisoryHealth.UNHEALTHY,
            "wait": AdvisoryHealth.UNKNOWN,
            "insufficient-evidence": AdvisoryHealth.AMBIGUOUS,
        }.get(health_value or "", AdvisoryHealth.UNKNOWN)
        terminal_health = health in {AdvisoryHealth.HEALTHY, AdvisoryHealth.UNHEALTHY}
        phase, stable_percent, candidate_percent = _rollout_state(
            entries,
            authority_revoked=authority.current_epoch > plan.initial_epoch,
            health=health,
        )
        assembly_time = self._clock()
        assembled_at = _utc_text(assembly_time)
        fresh_until = _utc_text(
            assembly_time.astimezone(UTC) + timedelta(seconds=_SNAPSHOT_LIFETIME_SECONDS)
        )
        target_entries = _latest_verification_entries(verifier_entries)
        receipt_entry = receipt_entries[-1]
        monitoring_entry = monitoring_entries[-1]
        if (
            monitoring_entry.content.event.payload_sha256
            != health_entry.content.event.payload_sha256
        ):
            raise ValueError("advisor health evidence is inconsistent")
        health_evidence = (monitoring_entry, health_entry)
        terminal_entry = _latest_terminal_entry(entries)
        timeline_entries = tuple(
            sorted(
                {item.entry_id: item for item in (terminal_entry, entries[-1])}.values(),
                key=lambda item: item.content.sequence,
            )
        )
        consistency = _evidence_consistency(
            target_entries,
            terminal_entry=terminal_entry,
            health=health,
        )
        snapshot = DiagnosticSnapshotV1(
            schema_version=DIAGNOSTIC_SNAPSHOT_V1,
            snapshot_id=_snapshot_id(
                root.root_sha256,
                authority.current_epoch,
                timeline_head.entry_sha256,
                command.request_id,
            ),
            target=self._target,
            root_id=root.root_id,
            root_sha256=root.root_sha256,
            current_epoch=authority.current_epoch,
            stable_revision=plan.stable_revision,
            candidate_revision=plan.candidate_revision,
            recovery_revision=plan.stable_revision,
            stable_percent=stable_percent,
            candidate_percent=candidate_percent,
            rollout_phase=phase,
            authority_revoked=authority.current_epoch > plan.initial_epoch,
            health=health,
            terminal_health=terminal_health,
            health_policy_sha256=plan.health_policy_sha256,
            evidence_consistency=consistency,
            assembled_at=assembled_at,
            expires_at=fresh_until,
            root_summary=_summary(
                DiagnosticEvidenceKind.ROOT,
                root_entries[-1:],
                source_sha256=root.root_sha256,
                fresh_until=fresh_until,
                facts=(
                    (
                        root_entries[-1],
                        DiagnosticEvidenceFactName.CANDIDATE_REVISION,
                        plan.candidate_revision,
                    ),
                    (
                        root_entries[-1],
                        DiagnosticEvidenceFactName.INITIAL_EPOCH,
                        str(plan.initial_epoch),
                    ),
                    (
                        root_entries[-1],
                        DiagnosticEvidenceFactName.STABLE_REVISION,
                        plan.stable_revision,
                    ),
                ),
            ),
            target_summary=_summary(
                DiagnosticEvidenceKind.TARGET,
                target_entries,
                source_sha256=_entry_set_sha256(target_entries),
                fresh_until=fresh_until,
                facts=_verification_facts(target_entries),
            ),
            health_summary=_summary(
                DiagnosticEvidenceKind.HEALTH,
                health_evidence,
                source_sha256=_entry_set_sha256(health_evidence),
                fresh_until=fresh_until,
                facts=(
                    (
                        health_entry,
                        DiagnosticEvidenceFactName.HEALTH_STATUS,
                        _required_display_value(health_entry, "OUTCOME"),
                    ),
                    (
                        monitoring_entry,
                        DiagnosticEvidenceFactName.MONITORING_COMPLETENESS,
                        _required_display_value(monitoring_entry, "OBSERVATION"),
                    ),
                    (
                        monitoring_entry,
                        DiagnosticEvidenceFactName.MONITORING_WINDOW,
                        _required_display_value(monitoring_entry, "WINDOW"),
                    ),
                ),
            ),
            receipt_summary=_summary(
                DiagnosticEvidenceKind.RECEIPT,
                receipt_entries[-1:],
                source_sha256=receipt_entry.content.event.payload_sha256,
                fresh_until=fresh_until,
                facts=_receipt_facts(receipt_entry),
            ),
            timeline_summary=_summary(
                DiagnosticEvidenceKind.TIMELINE,
                timeline_entries,
                source_sha256=timeline_head.entry_sha256,
                fresh_until=fresh_until,
                facts=(
                    (
                        entries[-1],
                        DiagnosticEvidenceFactName.TIMELINE_HEAD_SEQUENCE,
                        str(timeline_head.sequence),
                    ),
                    (
                        entries[-1],
                        DiagnosticEvidenceFactName.TIMELINE_LATEST_EVENT,
                        entries[-1].content.event.event_type.value,
                    ),
                    (
                        terminal_entry,
                        DiagnosticEvidenceFactName.TERMINAL_CLASSIFICATION,
                        terminal_entry.content.event.terminal_classification.value,
                    ),
                ),
            ),
            verifier_summary=_summary(
                DiagnosticEvidenceKind.VERIFIER,
                target_entries,
                source_sha256=_entry_set_sha256(target_entries),
                fresh_until=fresh_until,
                facts=_verification_facts(target_entries),
            ),
        )
        return AdvisorInvocationRequestV1(
            schema_version=ADVISOR_INVOCATION_REQUEST_V1,
            correlation_id=command.request_id,
            requested_at=command.requested_at,
            snapshot=snapshot,
            snapshot_sha256=canonical_sha256(snapshot),
        )


async def _read_timeline(
    *,
    target: TargetBinding,
    timeline: M6TimelineReader,
) -> tuple[TimelineHeadV1, tuple[TimelineEntryV1, ...]]:
    entries: list[TimelineEntryV1] = []
    after_sequence = 0
    after_entry_sha256: str | None = None
    captured_head: TimelineHeadV1 | None = None
    expected_head: tuple[int, str] | None = None

    while True:
        page = await timeline.read_page(
            TimelinePageCommandV1(
                schema_version=TIMELINE_PAGE_COMMAND_V1,
                target=target,
                after_sequence=after_sequence,
                after_entry_sha256=after_entry_sha256,
                limit=_TIMELINE_PAGE_SIZE,
                audience=TimelineAudience.OPERATOR,
            )
        )
        if page.head is None:
            raise ValueError("advisor timeline evidence is unavailable")
        observed_head = (page.head.sequence, page.head.entry_sha256)
        if expected_head is None:
            captured_head = page.head
            expected_head = observed_head
            if page.head.sequence > _MAX_TIMELINE_ENTRIES:
                raise ValueError("advisor timeline evidence is unavailable")
        elif observed_head != expected_head:
            raise ValueError("advisor timeline evidence is unavailable")
        if not page.entries:
            raise ValueError("advisor timeline evidence is unavailable")

        entries.extend(page.entries)
        final_entry = page.entries[-1]
        if final_entry.content.sequence <= after_sequence:
            raise ValueError("advisor timeline evidence is unavailable")
        after_sequence = final_entry.content.sequence
        after_entry_sha256 = final_entry.entry_sha256
        if after_sequence == expected_head[0]:
            if after_entry_sha256 != expected_head[1] or captured_head is None:
                raise ValueError("advisor timeline evidence is unavailable")
            return captured_head, tuple(entries)
        if after_sequence > expected_head[0]:
            raise ValueError("advisor timeline evidence is unavailable")


def _verified_entries(
    entries: tuple[TimelineEntryV1, ...],
    event_type: TimelineEventType,
) -> tuple[TimelineEntryV1, ...]:
    return tuple(
        entry
        for entry in entries
        if entry.content.event.event_type is event_type
        and entry.content.event.signature is not None
        and entry.content.event.verification_status is TimelineVerificationStatus.VERIFIED
    )


def _rollout_state(
    entries: tuple[TimelineEntryV1, ...],
    *,
    authority_revoked: bool,
    health: AdvisoryHealth,
) -> tuple[RolloutPhase, int, int]:
    terminal = next(
        (
            entry.content.event.terminal_classification
            for entry in reversed(entries)
            if entry.content.event.event_type is TimelineEventType.TERMINAL_CLASSIFIED
        ),
        TimelineTerminalClassification.NONE,
    )
    if terminal is TimelineTerminalClassification.PROMOTED:
        return RolloutPhase.PROMOTED, 0, 100
    if terminal is TimelineTerminalClassification.RECOVERED:
        return RolloutPhase.STABLE, 100, 0
    if terminal is TimelineTerminalClassification.AMBIGUOUS:
        return RolloutPhase.UNKNOWN, 90, 10
    if authority_revoked:
        return RolloutPhase.REVOKED, 90, 10
    if health is AdvisoryHealth.UNHEALTHY:
        return RolloutPhase.RECOVERY_PENDING, 90, 10
    return RolloutPhase.CANARY, 90, 10


def _summary(
    kind: DiagnosticEvidenceKind,
    entries: tuple[TimelineEntryV1, ...],
    *,
    source_sha256: str,
    fresh_until: str,
    facts: tuple[tuple[TimelineEntryV1, DiagnosticEvidenceFactName, str], ...],
) -> DiagnosticEvidenceSummaryV1:
    if not entries:
        raise ValueError("diagnostic summary source is empty")
    summary_code = dict(
        zip(
            tuple(DiagnosticEvidenceKind),
            tuple(DiagnosticEvidenceSummaryCode),
            strict=True,
        )
    )[kind]
    evidence_ids = {entry.entry_id: _evidence_id(kind, entry) for entry in entries}
    return DiagnosticEvidenceSummaryV1(
        schema_version=DIAGNOSTIC_EVIDENCE_SUMMARY_V1,
        evidence_kind=kind,
        evidence_ids=tuple(evidence_ids[entry.entry_id] for entry in entries),
        source_sha256=source_sha256,
        observed_at=min(
            (entry.content.event.occurred_at for entry in entries),
            key=_utc,
        ),
        fresh_until=fresh_until,
        summary_code=summary_code,
        facts=tuple(
            sorted(
                (
                    DiagnosticEvidenceFactV1(
                        schema_version=DIAGNOSTIC_EVIDENCE_FACT_V1,
                        evidence_id=evidence_ids[entry.entry_id],
                        name=name,
                        value=value,
                    )
                    for entry, name, value in facts
                ),
                key=lambda item: (item.evidence_id, item.name.value),
            )
        ),
        redacted=True,
        untrusted_model_context=True,
    )


def _entry_set_sha256(entries: tuple[TimelineEntryV1, ...]) -> str:
    digest = hashlib.sha256(b"controlgraph.diagnostic-entry-set/v1\0")
    for entry in entries:
        digest.update(bytes.fromhex(entry.entry_sha256))
    return digest.hexdigest()


def _evidence_id(kind: DiagnosticEvidenceKind, entry: TimelineEntryV1) -> str:
    return f"cgdiag:{kind.value}:{entry.entry_sha256[:24]}"


def _verification_facts(
    entries: tuple[TimelineEntryV1, ...],
) -> tuple[tuple[TimelineEntryV1, DiagnosticEvidenceFactName, str], ...]:
    facts: list[tuple[TimelineEntryV1, DiagnosticEvidenceFactName, str]] = []
    for entry in entries:
        facts.extend(
            (
                (
                    entry,
                    DiagnosticEvidenceFactName.VERIFICATION_KIND,
                    _required_display_value(entry, "OBSERVATION"),
                ),
                (
                    entry,
                    DiagnosticEvidenceFactName.VERIFICATION_VERDICT,
                    _required_display_value(entry, "OUTCOME"),
                ),
            )
        )
    return tuple(facts)


def _receipt_facts(
    entry: TimelineEntryV1,
) -> tuple[tuple[TimelineEntryV1, DiagnosticEvidenceFactName, str], ...]:
    return (
        (
            entry,
            DiagnosticEvidenceFactName.RECEIPT_OUTCOME,
            _required_display_value(entry, "OUTCOME"),
        ),
    )


def _latest_verification_entries(
    entries: tuple[TimelineEntryV1, ...],
) -> tuple[TimelineEntryV1, ...]:
    selected: dict[str, TimelineEntryV1] = {}
    for entry in entries:
        kind = _display_value(entry, "OBSERVATION")
        if kind in {"CONFIGURATION", "PROBE"}:
            selected[kind] = entry
    if set(selected) != {"CONFIGURATION", "PROBE"}:
        raise ValueError("advisor target evidence is incomplete")
    return tuple(sorted(selected.values(), key=lambda item: item.content.sequence))


def _latest_terminal_entry(entries: tuple[TimelineEntryV1, ...]) -> TimelineEntryV1:
    return next(
        (
            entry
            for entry in reversed(entries)
            if entry.content.event.event_type is TimelineEventType.TERMINAL_CLASSIFIED
        ),
        entries[-1],
    )


def _evidence_consistency(
    verifier_entries: tuple[TimelineEntryV1, ...],
    *,
    terminal_entry: TimelineEntryV1,
    health: AdvisoryHealth,
) -> EvidenceConsistency:
    terminal = terminal_entry.content.event.terminal_classification
    verdicts = {_required_display_value(entry, "OUTCOME") for entry in verifier_entries}
    if "MISMATCH" in verdicts:
        return EvidenceConsistency.CONFLICTING
    if (
        terminal is TimelineTerminalClassification.AMBIGUOUS
        or terminal is TimelineTerminalClassification.NONE
        or health in {AdvisoryHealth.UNKNOWN, AdvisoryHealth.AMBIGUOUS}
        or verdicts.intersection({"UNAVAILABLE", "INCONCLUSIVE"})
    ):
        return EvidenceConsistency.INCOMPLETE
    return EvidenceConsistency.CONSISTENT


def _snapshot_id(root_sha256: str, epoch: int, head_sha256: str, request_id: str) -> str:
    digest = hashlib.sha256(
        b"controlgraph.diagnostic-snapshot-id/v1\0"
        + bytes.fromhex(root_sha256)
        + b"\0"
        + str(epoch).encode("ascii")
        + b"\0"
        + bytes.fromhex(head_sha256)
        + b"\0"
        + request_id.encode("utf-8")
    ).hexdigest()
    return f"cgsnapshot:{digest}"


def _display_value(entry: TimelineEntryV1, name: str) -> str | None:
    return next(
        (
            field.value
            for field in entry.content.event.display_fields
            if field.name.value == name
        ),
        None,
    )


def _required_display_value(entry: TimelineEntryV1, name: str) -> str:
    value = _display_value(entry, name)
    if value is None:
        raise ValueError("advisor evidence field is unavailable")
    return value


def _utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("advisor assembly clock must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = ["M6DiagnosticSnapshotAssembler"]
