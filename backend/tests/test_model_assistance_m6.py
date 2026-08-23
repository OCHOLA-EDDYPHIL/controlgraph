from __future__ import annotations

import asyncio

from root_v2_test_data import make_root_v3_records
from timeline_test_data import timeline_event

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.application.model_assistance_m6 import (
    M6DiagnosticSnapshotAssembler,
)
from controlgraph_canary.application.timeline import TimelineReadSlice
from controlgraph_canary.contracts.model_assistance import (
    ADVISOR_OPERATOR_COMMAND_V1,
    AdvisorOperatorCommandV1,
    AdvisoryHealth,
    RolloutPhase,
)
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
    ) -> None:
        self.target = head.target
        self._head = head
        self._entries = entries

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice:
        return TimelineReadSlice(command=command, head=self._head, entries=self._entries)


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
        (TimelineEventType.AUTHORITY_ROOT_CREATED, "EVIDENCE", "created"),
        (TimelineEventType.MUTATION_APPLIED, None, "VERIFIED"),
        (TimelineEventType.HEALTH_DECIDED, "HEALTH_ATTESTATION", "healthy"),
        (
            TimelineEventType.VERIFICATION_RECORDED,
            "INDEPENDENT_VERIFICATION",
            "VERIFIED",
        ),
    )
    entries = []
    predecessor = None
    for sequence, (event_type, purpose, outcome) in enumerate(shapes, start=1):
        base = timeline_event(
            sequence,
            target=target,
            event_type=event_type,
            display_fields=(
                _field(TimelineDisplayFieldName.OUTCOME, outcome),
                _field(TimelineDisplayFieldName.SUMMARY, "Bound M6 evidence"),
            ),
        )
        signature = base.signature
        if signature is not None and purpose is not None:
            signature = signature.model_copy(update={"purpose": purpose})
        if purpose is None:
            signature = None
        event = TimelineEventV1.model_validate(
            {
                **base.model_dump(mode="python"),
                "root_id": root.root_id,
                "root_sha256": root.root_sha256,
                "epoch": records.authority.current_epoch,
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
        requested_at="2026-08-22T10:00:00Z",
    )

    request = asyncio.run(
        M6DiagnosticSnapshotAssembler(
            target=target,
            authority=_Authority(bundle),
            timeline=_Timeline(head, tuple(entries)),
        ).assemble(command)
    )

    assert request.snapshot.root_sha256 == root.root_sha256
    assert request.snapshot.health is AdvisoryHealth.HEALTHY
    assert request.snapshot.rollout_phase is RolloutPhase.CANARY
    assert request.snapshot.evidence_consistency.value == "consistent"
    assert len(request.snapshot.evidence_summaries) == 6
