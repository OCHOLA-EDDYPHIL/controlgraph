from __future__ import annotations

from timeline_test_data import TARGET, timeline_event

from controlgraph_canary.application.timeline import TimelineReadSlice, project_timeline_page
from controlgraph_canary.contracts.timeline import (
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_HEAD_V1,
    TIMELINE_PAGE_COMMAND_V1,
    TimelineActorRole,
    TimelineAudience,
    TimelineDisplayFieldName,
    TimelineDisplayFieldV1,
    TimelineEventType,
    TimelineHeadV1,
    TimelinePageCommandV1,
    TimelinePageV1,
    TimelineSignatureMetadataV1,
    TimelineTerminalClassification,
    TimelineVerificationStatus,
    timeline_entry,
)


def _field(
    name: TimelineDisplayFieldName,
    value: str,
    *,
    audience: TimelineAudience = TimelineAudience.PUBLIC_DEMO,
) -> TimelineDisplayFieldV1:
    return TimelineDisplayFieldV1(
        schema_version=TIMELINE_DISPLAY_FIELD_V1,
        name=name,
        value=value,
        data_class=audience,
    )


def operator_timeline_page() -> TimelinePageV1:
    """Build the canonical cross-surface fixture consumed by backend and console tests."""

    shapes = (
        (
            TimelineEventType.TASK_CREATED,
            TimelineActorRole.COORDINATOR,
            (
                _field(TimelineDisplayFieldName.ACTION, "APPLY_CANARY"),
                _field(TimelineDisplayFieldName.OUTCOME, "CREATED"),
                _field(TimelineDisplayFieldName.SUMMARY, "Canary task created"),
            ),
            TimelineVerificationStatus.NOT_APPLICABLE,
            TimelineTerminalClassification.NONE,
        ),
        (
            TimelineEventType.MUTATION_APPLIED,
            TimelineActorRole.EXECUTOR,
            (
                _field(TimelineDisplayFieldName.OUTCOME, "VERIFIED"),
                _field(TimelineDisplayFieldName.SUMMARY, "Canary mutation applied"),
            ),
            TimelineVerificationStatus.VERIFIED,
            TimelineTerminalClassification.NONE,
        ),
        (
            TimelineEventType.HEALTH_OBSERVED,
            TimelineActorRole.VERIFIER,
            (
                _field(TimelineDisplayFieldName.OBSERVATION, "COMPLETE"),
                _field(TimelineDisplayFieldName.SUMMARY, "Health window observed"),
                _field(TimelineDisplayFieldName.WINDOW, "1"),
            ),
            TimelineVerificationStatus.VERIFIED,
            TimelineTerminalClassification.NONE,
        ),
        (
            TimelineEventType.HEALTH_DECIDED,
            TimelineActorRole.VERIFIER,
            (
                _field(TimelineDisplayFieldName.OUTCOME, "healthy"),
                _field(TimelineDisplayFieldName.SUMMARY, "Health decision recorded"),
            ),
            TimelineVerificationStatus.VERIFIED,
            TimelineTerminalClassification.NONE,
        ),
        (
            TimelineEventType.TASK_CREATED,
            TimelineActorRole.COORDINATOR,
            (
                _field(TimelineDisplayFieldName.ACTION, "PROMOTE_CANDIDATE"),
                _field(TimelineDisplayFieldName.OUTCOME, "CREATED"),
                _field(TimelineDisplayFieldName.SUMMARY, "Promotion task created"),
            ),
            TimelineVerificationStatus.NOT_APPLICABLE,
            TimelineTerminalClassification.NONE,
        ),
        (
            TimelineEventType.TERMINAL_CLASSIFIED,
            TimelineActorRole.VERIFIER,
            (
                _field(TimelineDisplayFieldName.OUTCOME, "PROMOTED"),
                _field(TimelineDisplayFieldName.SUMMARY, "Terminal state classified"),
            ),
            TimelineVerificationStatus.VERIFIED,
            TimelineTerminalClassification.PROMOTED,
        ),
        (
            TimelineEventType.RECOVERY_TASK_CREATED,
            TimelineActorRole.COORDINATOR,
            (
                _field(TimelineDisplayFieldName.ACTION, "RECOVER_STABLE"),
                _field(TimelineDisplayFieldName.OUTCOME, "CREATED"),
                _field(TimelineDisplayFieldName.SUMMARY, "Recovery task addressed"),
            ),
            TimelineVerificationStatus.NOT_APPLICABLE,
            TimelineTerminalClassification.NONE,
        ),
        (
            TimelineEventType.OPERATOR_ACTION_RECORDED,
            TimelineActorRole.OPERATOR,
            (
                _field(TimelineDisplayFieldName.ACTION, "REVOKE_EPOCH"),
                _field(
                    TimelineDisplayFieldName.REASON_CODE,
                    "OPERATOR_REQUESTED",
                    audience=TimelineAudience.OPERATOR,
                ),
                _field(TimelineDisplayFieldName.SUMMARY, "Epoch revocation recorded"),
            ),
            TimelineVerificationStatus.VERIFIED,
            TimelineTerminalClassification.NONE,
        ),
        (
            TimelineEventType.VERIFICATION_RECORDED,
            TimelineActorRole.VERIFIER,
            (
                _field(TimelineDisplayFieldName.OUTCOME, "VERIFIED"),
                _field(TimelineDisplayFieldName.SUMMARY, "Target verification recorded"),
            ),
            TimelineVerificationStatus.VERIFIED,
            TimelineTerminalClassification.NONE,
        ),
        (
            TimelineEventType.MODEL_ASSISTANCE_RECORDED,
            TimelineActorRole.ADVISOR,
            (
                _field(TimelineDisplayFieldName.ACTION, "ADVISORY_ONLY"),
                _field(TimelineDisplayFieldName.OUTCOME, "NON_AUTHORITATIVE"),
                _field(TimelineDisplayFieldName.SUMMARY, "Model assistance recorded"),
            ),
            TimelineVerificationStatus.NOT_APPLICABLE,
            TimelineTerminalClassification.NONE,
        ),
    )
    entries = []
    predecessor = None
    for sequence, (event_type, actor_role, fields, verification, terminal) in enumerate(
        shapes,
        start=1,
    ):
        event = timeline_event(
            100 + sequence,
            event_type=event_type,
            display_fields=fields,
        )
        signature: TimelineSignatureMetadataV1 | None = event.signature
        if event_type in {
            TimelineEventType.TASK_CREATED,
            TimelineEventType.MUTATION_APPLIED,
            TimelineEventType.RECOVERY_TASK_CREATED,
            TimelineEventType.TERMINAL_CLASSIFIED,
            TimelineEventType.MODEL_ASSISTANCE_RECORDED,
            TimelineEventType.OPERATOR_ACTION_RECORDED,
        }:
            signature = None
        elif event_type in {
            TimelineEventType.HEALTH_OBSERVED,
            TimelineEventType.HEALTH_DECIDED,
        }:
            assert signature is not None
            signature = signature.model_copy(update={"purpose": "HEALTH_ATTESTATION"})
        event = event.model_copy(
            update={
                "actor_role": actor_role,
                "signature": signature,
                "verification_status": verification,
                "terminal_classification": terminal,
            }
        )
        entry = timeline_entry(
            event,
            sequence=sequence,
            previous_entry_sha256=predecessor,
            recorded_at=f"2026-08-21T12:00:{sequence:02d}Z",
        )
        entries.append(entry)
        predecessor = entry.entry_sha256
    assert predecessor is not None
    head = TimelineHeadV1(
        schema_version=TIMELINE_HEAD_V1,
        target=TARGET,
        sequence=len(entries),
        entry_id=entries[-1].entry_id,
        entry_sha256=predecessor,
        updated_at=entries[-1].content.recorded_at,
    )
    command = TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=25,
        audience=TimelineAudience.OPERATOR,
    )
    return project_timeline_page(
        TimelineReadSlice(command=command, head=head, entries=tuple(entries))
    )


__all__ = ["operator_timeline_page"]
