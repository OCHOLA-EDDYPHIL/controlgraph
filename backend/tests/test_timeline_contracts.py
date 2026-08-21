from copy import deepcopy

import pytest
from pydantic import ValidationError
from timeline_test_data import OTHER_TARGET, TARGET, timeline_event

from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.timeline import (
    TIMELINE_ENTRY_CONTENT_V1,
    TIMELINE_ENTRY_PROJECTION_V1,
    TIMELINE_ENTRY_V1,
    TIMELINE_EVIDENCE_POLICY_SET_V1,
    TIMELINE_PAGE_COMMAND_V1,
    TIMELINE_PAGE_V1,
    TimelineAudience,
    TimelineEntryContentV1,
    TimelineEntryProjectionV1,
    TimelineEntryV1,
    TimelineEventType,
    TimelineEvidenceClass,
    TimelineEvidencePolicySetV1,
    TimelinePageCommandV1,
    TimelinePageV1,
    TimelineTerminalClassification,
    standard_timeline_evidence_policy_set,
    timeline_entry,
    timeline_entry_document_id,
    timeline_head_document_id,
    timeline_identity_document_id,
)


def _projection(entry: TimelineEntryV1) -> TimelineEntryProjectionV1:
    event = entry.content.event
    return TimelineEntryProjectionV1(
        schema_version=TIMELINE_ENTRY_PROJECTION_V1,
        audience=TimelineAudience.OPERATOR,
        entry_id=entry.entry_id,
        entry_sha256=entry.entry_sha256,
        sequence=entry.content.sequence,
        previous_entry_sha256=entry.content.previous_entry_sha256,
        target=entry.content.target,
        source_schema_version=event.source_schema_version,
        event_type=event.event_type,
        evidence_class=event.evidence_class,
        actor_role=event.actor_role,
        actor_id=event.actor_id,
        actor_data_class=event.actor_data_class,
        root_id=event.root_id,
        root_sha256=event.root_sha256,
        epoch=event.epoch,
        occurred_at=event.occurred_at,
        recorded_at=entry.content.recorded_at,
        correlations=event.correlations,
        payload_sha256=event.payload_sha256,
        policy_sha256=event.policy_sha256,
        raw_retention_days=event.raw_retention_days,
        signature=event.signature,
        verification_status=event.verification_status,
        terminal_classification=event.terminal_classification,
        display_fields=event.display_fields,
    )


def test_timeline_event_is_strict_ordered_and_class_bound() -> None:
    event = timeline_event(1)

    with pytest.raises(ValidationError):
        type(event).model_validate({**event.model_dump(mode="python"), "unexpected": True})

    with pytest.raises(ValidationError):
        type(event).model_validate(
            {
                **event.model_dump(mode="python"),
                "evidence_class": TimelineEvidenceClass.MUTATION,
            }
        )

    with pytest.raises(ValidationError):
        type(event).model_validate(
            {
                **event.model_dump(mode="python"),
                "correlations": tuple(reversed(event.correlations)),
            }
        )


def test_terminal_classification_requires_dedicated_event() -> None:
    event = timeline_event(2)
    with pytest.raises(ValidationError):
        type(event).model_validate(
            {
                **event.model_dump(mode="python"),
                "terminal_classification": TimelineTerminalClassification.DENIED,
            }
        )

    terminal = timeline_event(3, event_type=TimelineEventType.TERMINAL_CLASSIFIED)
    assert terminal.terminal_classification is TimelineTerminalClassification.PROMOTED


def test_timeline_entry_is_content_addressed_and_chained() -> None:
    first = timeline_entry(
        timeline_event(4),
        sequence=1,
        previous_entry_sha256=None,
        recorded_at="2026-08-21T00:01:00Z",
    )
    second = timeline_entry(
        timeline_event(5),
        sequence=2,
        previous_entry_sha256=first.entry_sha256,
        recorded_at="2026-08-21T00:01:01Z",
    )

    assert first.entry_sha256 == canonical_sha256(first.content)
    assert second.content.previous_entry_sha256 == first.entry_sha256

    tampered = deepcopy(second.model_dump(mode="python"))
    tampered["content"]["recorded_at"] = "2026-08-21T00:01:02Z"
    with pytest.raises(ValidationError):
        TimelineEntryV1.model_validate(tampered)

    with pytest.raises(ValidationError):
        TimelineEntryContentV1(
            schema_version=TIMELINE_ENTRY_CONTENT_V1,
            target=TARGET,
            sequence=2,
            previous_entry_sha256=None,
            recorded_at="2026-08-21T00:01:01Z",
            event=timeline_event(5),
        )


def test_timeline_cursor_requires_exact_predecessor_digest() -> None:
    with pytest.raises(ValidationError):
        TimelinePageCommandV1(
            schema_version=TIMELINE_PAGE_COMMAND_V1,
            target=TARGET,
            after_sequence=1,
            after_entry_sha256=None,
            limit=10,
            audience=TimelineAudience.OPERATOR,
        )
    with pytest.raises(ValidationError):
        TimelinePageCommandV1(
            schema_version=TIMELINE_PAGE_COMMAND_V1,
            target=TARGET,
            after_sequence=0,
            after_entry_sha256="d" * 64,
            limit=10,
            audience=TimelineAudience.OPERATOR,
        )
    with pytest.raises(ValidationError):
        TimelinePageCommandV1(
            schema_version=TIMELINE_PAGE_COMMAND_V1,
            target=TARGET,
            after_sequence=0,
            after_entry_sha256=None,
            limit=101,
            audience=TimelineAudience.OPERATOR,
        )


def test_page_contract_rejects_omission_reordering_and_wrong_target() -> None:
    first = timeline_entry(
        timeline_event(6),
        sequence=1,
        previous_entry_sha256=None,
        recorded_at="2026-08-21T00:02:00Z",
    )
    second = timeline_entry(
        timeline_event(7),
        sequence=2,
        previous_entry_sha256=first.entry_sha256,
        recorded_at="2026-08-21T00:02:01Z",
    )
    command = TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=2,
        audience=TimelineAudience.OPERATOR,
    )
    projections = (_projection(first), _projection(second))
    page = TimelinePageV1(
        schema_version=TIMELINE_PAGE_V1,
        command=command,
        command_sha256=canonical_sha256(command),
        entries=projections,
        next_after_sequence=2,
        next_after_entry_sha256=second.entry_sha256,
        head_sequence=2,
        head_entry_sha256=second.entry_sha256,
        has_more=False,
    )
    assert [entry.sequence for entry in page.entries] == [1, 2]

    page_data = page.model_dump(mode="python")
    with pytest.raises(ValidationError):
        TimelinePageV1.model_validate({**page_data, "entries": tuple(reversed(projections))})

    wrong_target = _projection(
        timeline_entry(
            timeline_event(8, target=OTHER_TARGET),
            sequence=1,
            previous_entry_sha256=None,
            recorded_at="2026-08-21T00:02:02Z",
        )
    )
    with pytest.raises(ValidationError):
        TimelinePageV1.model_validate({**page_data, "entries": (wrong_target,)})

    with pytest.raises(ValidationError):
        TimelinePageV1.model_validate({**page_data, "entries": ()})


def test_target_scoped_document_ids_are_deterministic_and_disjoint() -> None:
    assert timeline_head_document_id(TARGET) == timeline_head_document_id(TARGET)
    assert timeline_head_document_id(TARGET) != timeline_head_document_id(OTHER_TARGET)
    assert timeline_entry_document_id(TARGET, 1) != timeline_entry_document_id(TARGET, 2)
    assert timeline_identity_document_id(TARGET, "source:1") != timeline_identity_document_id(
        TARGET,
        "source:2",
    )
    assert len(timeline_entry_document_id(TARGET, 1)) == 64


def test_evidence_policy_registry_is_complete_restricted_and_finite() -> None:
    policy_set = standard_timeline_evidence_policy_set(TARGET)

    assert (
        decode_contract(canonical_json_bytes(policy_set), TimelineEvidencePolicySetV1)
        == policy_set
    )
    assert {policy.evidence_class for policy in policy_set.policies} == set(
        TimelineEvidenceClass
    )
    assert all(policy.raw_retention_days == 30 for policy in policy_set.policies)
    assert all(
        policy.raw_read_audience is TimelineAudience.RESTRICTED
        for policy in policy_set.policies
    )
    assert all(
        policy.raw_export_audience is TimelineAudience.RESTRICTED
        and policy.deletion_evidence_required is True
        and policy.deletion_policy == "EXPIRE_RAW_PRESERVE_DIGEST_V1"
        for policy in policy_set.policies
    )

    with pytest.raises(ValidationError):
        TimelineEvidencePolicySetV1(
            schema_version=TIMELINE_EVIDENCE_POLICY_SET_V1,
            target=TARGET,
            policies=policy_set.policies[:-1],
        )
    with pytest.raises(ValidationError):
        standard_timeline_evidence_policy_set(TARGET, raw_retention_days=0)


def test_entry_contract_rejects_wrong_self_address() -> None:
    entry = timeline_entry(
        timeline_event(9),
        sequence=1,
        previous_entry_sha256=None,
        recorded_at="2026-08-21T00:03:00Z",
    )
    with pytest.raises(ValidationError):
        TimelineEntryV1(
            schema_version=TIMELINE_ENTRY_V1,
            entry_id=entry.entry_id,
            entry_sha256="f" * 64,
            content=entry.content,
        )
