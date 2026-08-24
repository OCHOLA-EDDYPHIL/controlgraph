from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from root_v2_test_data import make_root_v3_records
from timeline_test_data import timeline_event

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.application.model_assistance_m6 import (
    M6DiagnosticSnapshotAssembler,
    _read_timeline,
)
from controlgraph_canary.application.timeline import TimelineReadSlice
from controlgraph_canary.contracts.model_assistance import (
    ADVISOR_OPERATOR_COMMAND_V1,
    AdvisorOperatorCommandV1,
    AdvisoryHealth,
    RolloutPhase,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.timeline import (
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_HEAD_V1,
    TimelineAudience,
    TimelineDisplayFieldName,
    TimelineDisplayFieldV1,
    TimelineEntryV1,
    TimelineEventType,
    TimelineEventV1,
    TimelineHeadV1,
    TimelinePageCommandV1,
    TimelineVerificationStatus,
    timeline_entry,
)


class _Authority:
    def __init__(self, bundle: RootCreationBundle) -> None:
        self.target = bundle.authority.value.target
        self._bundle = bundle

    async def read_root_creation_bundle(self, root_id: str) -> RootCreationBundle | None:
        return self._bundle if root_id == self._bundle.root.value.root_id else None


class _Timeline:
    def __init__(
        self,
        head: TimelineHeadV1,
        entries: tuple[TimelineEntryV1, ...],
        *,
        later_heads: tuple[TimelineHeadV1, ...] = (),
    ) -> None:
        self.target = head.target
        self._heads = (head, *later_heads)
        self._entries = entries
        self.commands: list[TimelinePageCommandV1] = []

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice:
        head = self._heads[min(len(self.commands), len(self._heads) - 1)]
        self.commands.append(command)
        end = min(head.sequence, command.after_sequence + command.limit)
        return TimelineReadSlice(
            command=command,
            head=head,
            entries=self._entries[command.after_sequence : end],
        )


def _synthetic_entries(
    target: TargetBinding,
    count: int,
) -> tuple[TimelineEntryV1, ...]:
    entries: list[TimelineEntryV1] = []
    predecessor = None
    for sequence in range(1, count + 1):
        event = timeline_event(sequence, target=target)
        entry = timeline_entry(
            event,
            sequence=sequence,
            previous_entry_sha256=predecessor,
            recorded_at=event.occurred_at,
        )
        entries.append(entry)
        predecessor = entry.entry_sha256
    return tuple(entries)


def _head(
    entries: tuple[TimelineEntryV1, ...],
    *,
    sequence: int | None = None,
    entry_sha256: str | None = None,
) -> TimelineHeadV1:
    last = entries[-1]
    digest = entry_sha256 or last.entry_sha256
    return TimelineHeadV1(
        schema_version=TIMELINE_HEAD_V1,
        target=last.content.target,
        sequence=last.content.sequence if sequence is None else sequence,
        entry_id=f"cgtimeline:{digest}",
        entry_sha256=digest,
        updated_at=last.content.recorded_at,
    )


def test_timeline_read_paginates_with_exact_cursor_beyond_one_page() -> None:
    target = make_root_v3_records().root.content.target
    entries = _synthetic_entries(target, 106)
    expected_head = _head(entries)
    timeline = _Timeline(expected_head, entries)

    head, observed = asyncio.run(_read_timeline(target=target, timeline=timeline))

    assert head == expected_head
    assert observed == entries
    assert len(timeline.commands) == 2
    assert timeline.commands[0].after_sequence == 0
    assert timeline.commands[0].after_entry_sha256 is None
    assert timeline.commands[1].after_sequence == 100
    assert timeline.commands[1].after_entry_sha256 == entries[99].entry_sha256


def test_timeline_read_rejects_head_drift_between_pages() -> None:
    target = make_root_v3_records().root.content.target
    entries = _synthetic_entries(target, 107)
    timeline = _Timeline(
        _head(entries[:106]),
        entries,
        later_heads=(_head(entries),),
    )

    with pytest.raises(ValueError, match="timeline evidence is unavailable"):
        asyncio.run(_read_timeline(target=target, timeline=timeline))

    assert len(timeline.commands) == 2


def test_timeline_read_rejects_a_head_beyond_the_total_entry_cap() -> None:
    target = make_root_v3_records().root.content.target
    entries = _synthetic_entries(target, 100)
    timeline = _Timeline(
        _head(entries, sequence=1_001, entry_sha256="f" * 64),
        entries,
    )

    with pytest.raises(ValueError, match="timeline evidence is unavailable"):
        asyncio.run(_read_timeline(target=target, timeline=timeline))

    assert len(timeline.commands) == 1


def _field(name: TimelineDisplayFieldName, value: str) -> TimelineDisplayFieldV1:
    return TimelineDisplayFieldV1(
        schema_version=TIMELINE_DISPLAY_FIELD_V1,
        name=name,
        value=value,
        data_class=TimelineAudience.PUBLIC_DEMO,
    )


def test_assembler_projects_one_current_m6_root_and_timeline() -> None:
    records = make_root_v3_records()
    root = records.root
    target = root.content.target
    bundle = RootCreationBundle(
        root=StoredRecord(root, 0),
        service_claim=StoredRecord(records.service_claim, 0),
        authority=StoredRecord(records.authority, 0),
        lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        signed_evidence=StoredRecord(records.signed_evidence, 0),
        creation_result=StoredRecord(records.creation_result, 0),
    )
    shapes = (
        (
            TimelineEventType.AUTHORITY_ROOT_CREATED,
            "EVIDENCE",
            (_field(TimelineDisplayFieldName.OUTCOME, "created"),),
        ),
        (
            TimelineEventType.MUTATION_APPLIED,
            None,
            (_field(TimelineDisplayFieldName.OUTCOME, "VERIFIED"),),
        ),
        (
            TimelineEventType.HEALTH_OBSERVED,
            "HEALTH_ATTESTATION",
            (
                _field(TimelineDisplayFieldName.OBSERVATION, "COMPLETE"),
                _field(TimelineDisplayFieldName.WINDOW, "1"),
            ),
        ),
        (
            TimelineEventType.HEALTH_DECIDED,
            "HEALTH_ATTESTATION",
            (_field(TimelineDisplayFieldName.OUTCOME, "healthy"),),
        ),
        (
            TimelineEventType.VERIFICATION_RECORDED,
            "INDEPENDENT_VERIFICATION",
            (
                _field(TimelineDisplayFieldName.OBSERVATION, "CONFIGURATION"),
                _field(TimelineDisplayFieldName.OUTCOME, "MATCH"),
            ),
        ),
        (
            TimelineEventType.VERIFICATION_RECORDED,
            "INDEPENDENT_VERIFICATION",
            (
                _field(TimelineDisplayFieldName.OBSERVATION, "PROBE"),
                _field(TimelineDisplayFieldName.OUTCOME, "MATCH"),
            ),
        ),
    )
    entries = []
    predecessor = None
    health_payload_sha256 = None
    for sequence, (event_type, purpose, fields) in enumerate(shapes, start=1):
        base = timeline_event(
            sequence,
            target=target,
            event_type=event_type,
            display_fields=tuple(
                sorted(
                    (
                        *fields,
                        _field(TimelineDisplayFieldName.SUMMARY, "Bound M6 evidence"),
                    ),
                    key=lambda field: field.name.value,
                )
            ),
        )
        signature = base.signature
        if signature is not None and purpose is not None:
            signature = signature.model_copy(update={"purpose": purpose})
        if purpose is None:
            signature = None
        payload_sha256 = base.payload_sha256
        if event_type is TimelineEventType.HEALTH_OBSERVED:
            health_payload_sha256 = payload_sha256
        elif event_type is TimelineEventType.HEALTH_DECIDED:
            assert health_payload_sha256 is not None
            payload_sha256 = health_payload_sha256
            assert signature is not None
            signature = signature.model_copy(update={"payload_sha256": payload_sha256})
        event = TimelineEventV1.model_validate(
            {
                **base.model_dump(mode="python"),
                "root_id": root.root_id,
                "root_sha256": root.root_sha256,
                "epoch": records.authority.current_epoch,
                "occurred_at": f"2026-08-22T09:59:{sequence:02d}Z",
                "payload_sha256": payload_sha256,
                "signature": signature,
                "verification_status": TimelineVerificationStatus.VERIFIED,
            }
        )
        entry = timeline_entry(
            event,
            sequence=sequence,
            previous_entry_sha256=predecessor,
            recorded_at=f"2026-08-22T09:59:{sequence:02d}Z",
        )
        entries.append(entry)
        predecessor = entry.entry_sha256
    assert predecessor is not None
    head = TimelineHeadV1(
        schema_version=TIMELINE_HEAD_V1,
        target=target,
        sequence=len(entries),
        entry_id=entries[-1].entry_id,
        entry_sha256=predecessor,
        updated_at=entries[-1].content.recorded_at,
    )
    command = AdvisorOperatorCommandV1(
        schema_version=ADVISOR_OPERATOR_COMMAND_V1,
        request_id="advisor-request-1",
        idempotency_key="advisor-idempotency-1",
        target=target,
        root_id=root.root_id,
        expected_root_sha256=root.root_sha256,
        expected_epoch=records.authority.current_epoch,
        requested_at="2026-08-22T09:58:00Z",
    )

    request = asyncio.run(
        M6DiagnosticSnapshotAssembler(
            target=target,
            authority=_Authority(bundle),
            timeline=_Timeline(head, tuple(entries)),
            clock=lambda: datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
        ).assemble(command)
    )

    assert request.snapshot.root_sha256 == root.root_sha256
    assert request.snapshot.health is AdvisoryHealth.HEALTHY
    assert request.snapshot.rollout_phase is RolloutPhase.CANARY
    assert request.snapshot.evidence_consistency.value == "incomplete"
    assert len(request.snapshot.evidence_summaries) == 6
    assert request.snapshot.assembled_at == "2026-08-22T10:00:00Z"
    assert request.requested_at == "2026-08-22T09:58:00Z"
    assert request.snapshot.health_summary.observed_at == "2026-08-22T09:59:03Z"
    assert request.snapshot.target_summary.observed_at == "2026-08-22T09:59:05Z"
    assert {
        (fact.name.value, fact.value) for fact in request.snapshot.target_summary.facts
    } == {
        ("verification_kind", "CONFIGURATION"),
        ("verification_kind", "PROBE"),
        ("verification_verdict", "MATCH"),
    }
    assert {
        (fact.name.value, fact.value) for fact in request.snapshot.health_summary.facts
    } == {
        ("health_status", "healthy"),
        ("monitoring_completeness", "COMPLETE"),
        ("monitoring_window", "1"),
    }

    stale_events = [entry.content.event for entry in entries]
    stale_events[-2] = stale_events[-2].model_copy(
        update={"occurred_at": "2026-08-22T09:54:59Z"}
    )
    stale_entries = []
    stale_predecessor = None
    for sequence, event in enumerate(stale_events, start=1):
        entry = timeline_entry(
            event,
            sequence=sequence,
            previous_entry_sha256=stale_predecessor,
            recorded_at=f"2026-08-22T09:59:{sequence:02d}Z",
        )
        stale_entries.append(entry)
        stale_predecessor = entry.entry_sha256
    assert stale_predecessor is not None
    stale_head = head.model_copy(
        update={
            "entry_id": stale_entries[-1].entry_id,
            "entry_sha256": stale_predecessor,
        }
    )

    with pytest.raises(ValueError, match="stale or future-dated"):
        asyncio.run(
            M6DiagnosticSnapshotAssembler(
                target=target,
                authority=_Authority(bundle),
                timeline=_Timeline(stale_head, tuple(stale_entries)),
                clock=lambda: datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            ).assemble(command)
        )
