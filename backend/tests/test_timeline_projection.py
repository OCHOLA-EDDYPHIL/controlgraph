from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Coroutine
from functools import wraps
from types import SimpleNamespace
from typing import Any

import pytest
from timeline_test_data import OTHER_TARGET, TARGET, timeline_event

from controlgraph_canary.application import timeline_recording
from controlgraph_canary.application.timeline import (
    REDACTED_DISPLAY_VALUE,
    TimelineAppendCreated,
    TimelineReadError,
    TimelineReadErrorCode,
    TimelineReadGrant,
    TimelineReadService,
    TimelineReadSlice,
    TimelineWriteError,
    TimelineWriteErrorCode,
    TimelineWriteGrant,
    TimelineWriteService,
    project_timeline_entry,
)
from controlgraph_canary.application.timeline_recording import (
    _emit_operational_signals,
    _operational_signals,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes
from controlgraph_canary.contracts.timeline import (
    TIMELINE_CORRELATION_V1,
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_HEAD_V1,
    TIMELINE_PAGE_COMMAND_V1,
    TimelineActorRole,
    TimelineAudience,
    TimelineCorrelationKind,
    TimelineCorrelationV1,
    TimelineDisplayFieldName,
    TimelineDisplayFieldV1,
    TimelineEntryV1,
    TimelineEventType,
    TimelineEventV1,
    TimelineHeadV1,
    TimelinePageCommandV1,
    TimelineTerminalClassification,
    TimelineVerificationStatus,
    standard_timeline_evidence_policy_set,
    timeline_entry,
)


def _async_test[**P](
    function: Callable[P, Coroutine[Any, Any, None]],
) -> Callable[P, None]:
    @wraps(function)
    def run(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(function(*args, **kwargs))

    return run


def _classified_entry() -> TimelineEntryV1:
    correlations = (
        TimelineCorrelationV1(
            schema_version=TIMELINE_CORRELATION_V1,
            kind=TimelineCorrelationKind.EVIDENCE,
            correlation_id="evidence:public",
            data_class=TimelineAudience.PUBLIC_DEMO,
        ),
        TimelineCorrelationV1(
            schema_version=TIMELINE_CORRELATION_V1,
            kind=TimelineCorrelationKind.MODEL,
            correlation_id="ya29.synthetic_identity_token_value",
            data_class=TimelineAudience.RESTRICTED,
        ),
        TimelineCorrelationV1(
            schema_version=TIMELINE_CORRELATION_V1,
            kind=TimelineCorrelationKind.REQUEST,
            correlation_id="eyJaaaa.bbbbb.ccccc",
            data_class=TimelineAudience.OPERATOR,
        ),
        TimelineCorrelationV1(
            schema_version=TIMELINE_CORRELATION_V1,
            kind=TimelineCorrelationKind.VERIFICATION,
            correlation_id="verification:security",
            data_class=TimelineAudience.SECURITY_AUDIT,
        ),
    )
    fields = (
        TimelineDisplayFieldV1(
            schema_version=TIMELINE_DISPLAY_FIELD_V1,
            name=TimelineDisplayFieldName.ACTION,
            value="Bearer synthetic-secret-token-value",
            data_class=TimelineAudience.OPERATOR,
        ),
        TimelineDisplayFieldV1(
            schema_version=TIMELINE_DISPLAY_FIELD_V1,
            name=TimelineDisplayFieldName.NEXT_ACTION,
            value="restricted-export-review",
            data_class=TimelineAudience.RESTRICTED,
        ),
        TimelineDisplayFieldV1(
            schema_version=TIMELINE_DISPLAY_FIELD_V1,
            name=TimelineDisplayFieldName.OBSERVATION,
            value='{"capability":"synthetic-capability-value"}',
            data_class=TimelineAudience.SECURITY_AUDIT,
        ),
        TimelineDisplayFieldV1(
            schema_version=TIMELINE_DISPLAY_FIELD_V1,
            name=TimelineDisplayFieldName.SUMMARY,
            value="Canary health evidence recorded",
            data_class=TimelineAudience.PUBLIC_DEMO,
        ),
    )
    event = timeline_event(
        10,
        correlations=correlations,
        display_fields=fields,
        actor_data_class=TimelineAudience.SECURITY_AUDIT,
    )
    return timeline_entry(
        event,
        sequence=1,
        previous_entry_sha256=None,
        recorded_at="2026-08-21T00:04:00Z",
    )


def test_operational_signal_log_is_closed_and_excludes_source_content(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sensitive_marker = "unmistakably-synthetic-sensitive-source"
    event = timeline_event(
        9,
        event_type=TimelineEventType.TERMINAL_CLASSIFIED,
        display_fields=(
            TimelineDisplayFieldV1(
                schema_version=TIMELINE_DISPLAY_FIELD_V1,
                name=TimelineDisplayFieldName.ACTION,
                value="RECOVERY",
                data_class=TimelineAudience.PUBLIC_DEMO,
            ),
            TimelineDisplayFieldV1(
                schema_version=TIMELINE_DISPLAY_FIELD_V1,
                name=TimelineDisplayFieldName.OUTCOME,
                value="AMBIGUOUS",
                data_class=TimelineAudience.PUBLIC_DEMO,
            ),
            TimelineDisplayFieldV1(
                schema_version=TIMELINE_DISPLAY_FIELD_V1,
                name=TimelineDisplayFieldName.REASON_CODE,
                value="EVIDENCE_STALE",
                data_class=TimelineAudience.OPERATOR,
            ),
            TimelineDisplayFieldV1(
                schema_version=TIMELINE_DISPLAY_FIELD_V1,
                name=TimelineDisplayFieldName.SUMMARY,
                value=sensitive_marker,
                data_class=TimelineAudience.RESTRICTED,
            ),
        ),
    ).model_copy(
        update={
            "terminal_classification": TimelineTerminalClassification.AMBIGUOUS,
            "verification_status": TimelineVerificationStatus.AMBIGUOUS,
        }
    )

    assert _operational_signals(event) == ("failed_recovery", "evidence_failure")
    _emit_operational_signals(event)

    records = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert [record["signal"] for record in records] == [
        "failed_recovery",
        "evidence_failure",
    ]
    assert all(
        set(record)
        == {"epoch", "event", "event_type", "root_sha256", "signal"}
        for record in records
    )
    assert sensitive_marker not in json.dumps(records)
    assert "request:9" not in json.dumps(records)


def test_operational_signal_output_failure_does_not_change_the_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingStream:
        def write(self, _value: str) -> None:
            raise OSError("synthetic closed stream")

        def flush(self) -> None:
            raise AssertionError("flush must not follow a failed write")

    event = timeline_event(
        9,
        event_type=TimelineEventType.MUTATION_AMBIGUOUS,
    )
    monkeypatch.setattr(
        timeline_recording,
        "sys",
        SimpleNamespace(stderr=FailingStream()),
    )

    _emit_operational_signals(event)


def test_audience_projections_are_nested_and_secret_safe() -> None:
    entry = _classified_entry()
    projections = {
        audience: project_timeline_entry(entry, audience)
        for audience in TimelineAudience
    }

    field_names = {
        audience: {field.name for field in projection.display_fields}
        for audience, projection in projections.items()
    }
    assert field_names[TimelineAudience.PUBLIC_DEMO] < field_names[TimelineAudience.OPERATOR]
    assert field_names[TimelineAudience.OPERATOR] < field_names[TimelineAudience.SECURITY_AUDIT]
    assert field_names[TimelineAudience.SECURITY_AUDIT] < field_names[TimelineAudience.RESTRICTED]

    assert projections[TimelineAudience.PUBLIC_DEMO].actor_id is None
    assert projections[TimelineAudience.OPERATOR].actor_id is None
    assert projections[TimelineAudience.SECURITY_AUDIT].actor_id == "actor:10"
    operator_fields = {
        field.name: field.value
        for field in projections[TimelineAudience.OPERATOR].display_fields
    }
    assert operator_fields[TimelineDisplayFieldName.ACTION] == REDACTED_DISPLAY_VALUE

    for projection in projections.values():
        encoded = canonical_json_bytes(projection)
        assert b"synthetic-secret-token-value" not in encoded
        assert b"synthetic-capability-value" not in encoded
        assert b"eyJaaaa.bbbbb.ccccc" not in encoded
        assert b"synthetic_identity_token_value" not in encoded
        assert b"raw-source:10" not in encoded


class _MemoryTimelineStore:
    def __init__(self, entries: tuple[TimelineEntryV1, ...]) -> None:
        self._target = TARGET
        self.entries = entries
        self.read_count = 0
        last = entries[-1]
        self.head = TimelineHeadV1(
            schema_version=TIMELINE_HEAD_V1,
            target=TARGET,
            sequence=last.content.sequence,
            entry_id=last.entry_id,
            entry_sha256=last.entry_sha256,
            updated_at=last.content.recorded_at,
        )

    @property
    def target(self):  # type: ignore[no-untyped-def]
        return self._target

    async def append(self, event):  # type: ignore[no-untyped-def]
        raise AssertionError("read service must not append")

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice:
        self.read_count += 1
        selected = tuple(
            entry
            for entry in self.entries
            if command.after_sequence
            < entry.content.sequence
            <= command.after_sequence + command.limit
        )
        return TimelineReadSlice(command=command, head=self.head, entries=selected)


def _entries() -> tuple[TimelineEntryV1, ...]:
    result: list[TimelineEntryV1] = []
    predecessor = None
    for sequence in range(1, 4):
        entry = timeline_entry(
            timeline_event(sequence + 10),
            sequence=sequence,
            previous_entry_sha256=predecessor,
            recorded_at=f"2026-08-21T00:05:0{sequence}Z",
        )
        result.append(entry)
        predecessor = entry.entry_sha256
    return tuple(result)


@_async_test
async def test_read_service_enforces_target_audience_and_omission_free_reconnect() -> None:
    entries = _entries()
    store = _MemoryTimelineStore(entries)
    service = TimelineReadService(target=TARGET, store=store)
    grant = TimelineReadGrant(
        target=TARGET,
        maximum_audience=TimelineAudience.OPERATOR,
        principal_id="operator:synthetic",
    )
    first_command = TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=2,
        audience=TimelineAudience.OPERATOR,
    )
    first = await service.read(first_command, grant)
    assert [item.sequence for item in first.entries] == [1, 2]
    assert first.has_more is True

    second_command = TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=TARGET,
        after_sequence=first.next_after_sequence,
        after_entry_sha256=first.next_after_entry_sha256,
        limit=2,
        audience=TimelineAudience.OPERATOR,
    )
    second = await service.read(second_command, grant)
    repeated = await service.read(second_command, grant)
    assert [item.sequence for item in second.entries] == [3]
    assert canonical_json_bytes(second) == canonical_json_bytes(repeated)
    assert store.read_count == 3

    elevated = TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=2,
        audience=TimelineAudience.SECURITY_AUDIT,
    )
    with pytest.raises(TimelineReadError) as denied:
        await service.read(elevated, grant)
    assert denied.value.code is TimelineReadErrorCode.ACCESS_DENIED

    other_target = TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=OTHER_TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=2,
        audience=TimelineAudience.OPERATOR,
    )
    with pytest.raises(TimelineReadError) as denied_target:
        await service.read(other_target, grant)
    assert denied_target.value.code is TimelineReadErrorCode.TARGET_DENIED


class _MemoryTimelineWriteStore:
    def __init__(self) -> None:
        self._target = TARGET
        self.events: list[TimelineEventV1] = []

    @property
    def target(self):  # type: ignore[no-untyped-def]
        return self._target

    async def append(self, event: TimelineEventV1):  # type: ignore[no-untyped-def]
        self.events.append(event)
        entry = timeline_entry(
            event,
            sequence=len(self.events),
            previous_entry_sha256=None,
            recorded_at="2026-08-21T00:06:00Z",
        )
        return TimelineAppendCreated(entry)

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice:
        raise AssertionError("write service must not read")


@_async_test
async def test_write_service_enforces_target_role_and_bound_retention_policy() -> None:
    store = _MemoryTimelineWriteStore()
    policy_set = standard_timeline_evidence_policy_set(TARGET)
    service = TimelineWriteService(target=TARGET, policy_set=policy_set, store=store)
    coordinator = TimelineWriteGrant(
        target=TARGET,
        writer_role=TimelineActorRole.COORDINATOR,
        principal_id="coordinator:synthetic",
    )
    event = timeline_event(40)

    result = await service.append(event, coordinator)
    assert isinstance(result, TimelineAppendCreated)
    assert store.events == [event]

    executor = TimelineWriteGrant(
        target=TARGET,
        writer_role=TimelineActorRole.EXECUTOR,
        principal_id="executor:synthetic",
    )
    with pytest.raises(TimelineWriteError) as denied_role:
        await service.append(timeline_event(41), executor)
    assert denied_role.value.code is TimelineWriteErrorCode.ACCESS_DENIED

    wrong_retention = type(event).model_validate(
        {**event.model_dump(mode="python"), "raw_retention_days": 31}
    )
    with pytest.raises(TimelineWriteError) as denied_policy:
        await service.append(wrong_retention, coordinator)
    assert denied_policy.value.code is TimelineWriteErrorCode.POLICY_DENIED
