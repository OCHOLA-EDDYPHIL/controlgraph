import hashlib

from controlgraph_canary.contracts.codec import canonical_json_value_bytes, canonical_sha256
from controlgraph_canary.contracts.models import TARGET_BINDING_V1, TargetBinding
from controlgraph_canary.contracts.timeline import (
    TIMELINE_CORRELATION_V1,
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_EVENT_V1,
    TIMELINE_RAW_SOURCE_V1,
    TIMELINE_SIGNATURE_METADATA_V1,
    TimelineActorRole,
    TimelineAudience,
    TimelineCorrelationKind,
    TimelineCorrelationV1,
    TimelineDisplayFieldName,
    TimelineDisplayFieldV1,
    TimelineEventType,
    TimelineEventV1,
    TimelineEvidenceClass,
    TimelineRawSourceV1,
    TimelineSignatureMetadataV1,
    TimelineTerminalClassification,
    TimelineVerificationStatus,
    standard_timeline_evidence_policy_set,
)

TARGET = TargetBinding(
    schema_version=TARGET_BINDING_V1,
    project_id="controlgraph-canary-a1b2c3",
    region="us-central1",
    environment="acceptance",
    service_name="controlgraph-reference-target",
)
OTHER_TARGET = TargetBinding(
    schema_version=TARGET_BINDING_V1,
    project_id="controlgraph-canary-d4e5f6",
    region="us-central1",
    environment="acceptance",
    service_name="controlgraph-reference-target",
)

_EVENT_CLASSES = {
    TimelineEventType.AUTHORITY_ROOT_CREATED: TimelineEvidenceClass.AUTHORITY,
    TimelineEventType.AUTHORITY_EPOCH_ADVANCED: TimelineEvidenceClass.AUTHORITY,
    TimelineEventType.CAPABILITY_ISSUED: TimelineEvidenceClass.CAPABILITY,
    TimelineEventType.TASK_CREATED: TimelineEvidenceClass.TASK,
    TimelineEventType.TASK_DELIVERED: TimelineEvidenceClass.TASK,
    TimelineEventType.HEALTH_OBSERVED: TimelineEvidenceClass.HEALTH,
    TimelineEventType.HEALTH_DECIDED: TimelineEvidenceClass.DECISION,
    TimelineEventType.MUTATION_REQUESTED: TimelineEvidenceClass.MUTATION,
    TimelineEventType.MUTATION_APPLIED: TimelineEvidenceClass.MUTATION,
    TimelineEventType.MUTATION_DENIED: TimelineEvidenceClass.MUTATION,
    TimelineEventType.MUTATION_AMBIGUOUS: TimelineEvidenceClass.MUTATION,
    TimelineEventType.RECOVERY_INTENT_CREATED: TimelineEvidenceClass.RECOVERY,
    TimelineEventType.RECOVERY_TASK_CREATED: TimelineEvidenceClass.RECOVERY,
    TimelineEventType.RECOVERY_APPLIED: TimelineEvidenceClass.RECOVERY,
    TimelineEventType.VERIFICATION_RECORDED: TimelineEvidenceClass.VERIFICATION,
    TimelineEventType.TERMINAL_CLASSIFIED: TimelineEvidenceClass.VERIFICATION,
    TimelineEventType.MODEL_ASSISTANCE_RECORDED: TimelineEvidenceClass.MODEL_ASSISTANCE,
    TimelineEventType.OPERATOR_ACTION_RECORDED: TimelineEvidenceClass.OPERATOR_ACTION,
}


def timeline_event(
    index: int,
    *,
    target: TargetBinding = TARGET,
    event_type: TimelineEventType = TimelineEventType.HEALTH_OBSERVED,
    display_fields: tuple[TimelineDisplayFieldV1, ...] | None = None,
    correlations: tuple[TimelineCorrelationV1, ...] | None = None,
    actor_data_class: TimelineAudience = TimelineAudience.OPERATOR,
) -> TimelineEventV1:
    digit = format(index % 16, "x")
    payload_sha256 = digit * 64
    signature = TimelineSignatureMetadataV1(
        schema_version=TIMELINE_SIGNATURE_METADATA_V1,
        purpose="EVIDENCE",
        signing_key_version=(
            f"projects/{target.project_id}/locations/us-central1/keyRings/"
            "controlgraph-signing/cryptoKeys/evidence-signing/cryptoKeyVersions/1"
        ),
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=payload_sha256,
        signing_input_sha256="a" * 64,
        signature_sha256="b" * 64,
    )
    if correlations is None:
        correlations = (
            TimelineCorrelationV1(
                schema_version=TIMELINE_CORRELATION_V1,
                kind=TimelineCorrelationKind.EVIDENCE,
                correlation_id=f"evidence:{index}",
                data_class=TimelineAudience.PUBLIC_DEMO,
            ),
            TimelineCorrelationV1(
                schema_version=TIMELINE_CORRELATION_V1,
                kind=TimelineCorrelationKind.REQUEST,
                correlation_id=f"request:{index}",
                data_class=TimelineAudience.OPERATOR,
            ),
        )
    if display_fields is None:
        display_fields = (
            TimelineDisplayFieldV1(
                schema_version=TIMELINE_DISPLAY_FIELD_V1,
                name=TimelineDisplayFieldName.OUTCOME,
                value="observation-recorded",
                data_class=TimelineAudience.PUBLIC_DEMO,
            ),
            TimelineDisplayFieldV1(
                schema_version=TIMELINE_DISPLAY_FIELD_V1,
                name=TimelineDisplayFieldName.SUMMARY,
                value=f"Synthetic event {index}",
                data_class=TimelineAudience.PUBLIC_DEMO,
            ),
        )
    terminal = (
        TimelineTerminalClassification.PROMOTED
        if event_type is TimelineEventType.TERMINAL_CLASSIFIED
        else TimelineTerminalClassification.NONE
    )
    policy_set = standard_timeline_evidence_policy_set(target)
    return TimelineEventV1(
        schema_version=TIMELINE_EVENT_V1,
        source_id=f"source:{index}",
        source_schema_version="controlgraph.signed-evidence-event/v1",
        raw_source_id=f"raw-source:{index}",
        event_type=event_type,
        evidence_class=_EVENT_CLASSES[event_type],
        target=target,
        actor_role=TimelineActorRole.VERIFIER,
        actor_id=f"actor:{index}",
        actor_data_class=actor_data_class,
        root_id=f"cgroot:{'c' * 64}",
        root_sha256="c" * 64,
        epoch=1,
        occurred_at=f"2026-08-21T00:00:{index % 60:02d}Z",
        correlations=correlations,
        payload_sha256=payload_sha256,
        raw_record_sha256="d" * 64,
        policy_sha256=canonical_sha256(policy_set),
        raw_retention_days=30,
        signature=signature,
        verification_status=TimelineVerificationStatus.VERIFIED,
        terminal_classification=terminal,
        display_fields=display_fields,
    )


def timeline_event_with_raw(
    index: int,
    *,
    target: TargetBinding = TARGET,
    event_type: TimelineEventType = TimelineEventType.HEALTH_OBSERVED,
) -> tuple[TimelineEventV1, TimelineRawSourceV1]:
    canonical_record = canonical_json_value_bytes(
        {
            "schema_version": "controlgraph.synthetic-timeline-source/v1",
            "source_id": f"source:{index}",
            "target": target.model_dump(mode="json"),
        }
    ).decode("utf-8")
    record_sha256 = hashlib.sha256(canonical_record.encode("utf-8")).hexdigest()
    event = timeline_event(index, target=target, event_type=event_type).model_copy(
        update={
            "source_schema_version": "controlgraph.synthetic-timeline-source/v1",
            "raw_source_id": f"cgraw:{record_sha256}",
            "raw_record_sha256": record_sha256,
        }
    )
    raw_source = TimelineRawSourceV1(
        schema_version=TIMELINE_RAW_SOURCE_V1,
        raw_source_id=event.raw_source_id,
        source_schema_version=event.source_schema_version,
        target=target,
        evidence_class=event.evidence_class,
        payload_sha256=event.payload_sha256,
        record_sha256=record_sha256,
        canonical_record=canonical_record,
        signature_sha256=(
            None if event.signature is None else event.signature.signature_sha256
        ),
    )
    return event, raw_source
