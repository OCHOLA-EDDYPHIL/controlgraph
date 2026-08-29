"""Closed source-record projectors for append-only operator timeline evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from controlgraph_canary.application.signing import SigningProfile, build_signing_input
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.canary_execution import CanaryDispatchResultV1
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_base64url,
)
from controlgraph_canary.contracts.health_execution import SignedHealthDecisionProofV1
from controlgraph_canary.contracts.independent_verification import (
    CompletionClassificationV1,
    CompletionKind,
    CompletionStatus,
    SignedIndependentVerificationEvidenceV1,
    VerifiedIndependentVerificationEvidenceV1,
)
from controlgraph_canary.contracts.model_assistance import (
    ModelAssistanceActorRole,
    ModelAssistanceTimelineAuditV1,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceKind,
    ExecutionReceipt,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.promotion_execution import PromotionDispatchResultV2
from controlgraph_canary.contracts.recovery_abandonment import (
    RecoveryAbandonmentPhase,
    RecoveryAbandonmentResultV1,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryDispatchResultV2,
    RecoveryIntentV1,
)
from controlgraph_canary.contracts.revocation import EpochRevocationCallOutcomeV1
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1
from controlgraph_canary.contracts.service_claim_release import ServiceClaimReleaseResultV1
from controlgraph_canary.contracts.storage import ServiceClaimTargetClassification
from controlgraph_canary.contracts.timeline import (
    TIMELINE_CORRELATION_V1,
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_EVENT_V1,
    TIMELINE_RAW_SOURCE_V1,
    TIMELINE_REDACTED_SOURCE_V1,
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
    TimelineEvidencePolicySetV1,
    TimelineRawSourceV1,
    TimelineRedactedSourceV1,
    TimelineSignatureMetadataV1,
    TimelineTerminalClassification,
    TimelineVerificationStatus,
    timeline_capability_source_id,
)


@dataclass(frozen=True, slots=True)
class TimelineProjection:
    """One exact summary event and the separately retained source record."""

    event: TimelineEventV1
    raw_source: TimelineRawSourceV1

    def __post_init__(self) -> None:
        if (
            type(self.event) is not TimelineEventV1
            or type(self.raw_source) is not TimelineRawSourceV1
        ):
            raise TypeError("timeline projection requires exact contracts")


_EVIDENCE_KIND_EVENT: dict[EvidenceKind, TimelineEventType] = {
    EvidenceKind.ROOT_CREATED: TimelineEventType.AUTHORITY_ROOT_CREATED,
    EvidenceKind.CAPABILITY_ISSUED: TimelineEventType.CAPABILITY_ISSUED,
    EvidenceKind.EPOCH_ADVANCED: TimelineEventType.AUTHORITY_EPOCH_ADVANCED,
    EvidenceKind.DELIVERY_AUTHENTICATED: TimelineEventType.TASK_DELIVERED,
    EvidenceKind.CAPABILITY_VERIFIED: TimelineEventType.VERIFICATION_RECORDED,
    EvidenceKind.RECEIPT_CLAIMED: TimelineEventType.MUTATION_REQUESTED,
    EvidenceKind.MUTATION_APPLIED: TimelineEventType.MUTATION_APPLIED,
    EvidenceKind.TARGET_VERIFIED: TimelineEventType.VERIFICATION_RECORDED,
    EvidenceKind.EXECUTION_DENIED: TimelineEventType.MUTATION_DENIED,
    EvidenceKind.OUTCOME_AMBIGUOUS: TimelineEventType.MUTATION_AMBIGUOUS,
}

_EVENT_CLASS: dict[TimelineEventType, TimelineEvidenceClass] = {
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


def timeline_actor_id(value: str) -> str:
    """Return the stable pseudonymous actor identifier used by timeline events."""

    if type(value) is not str or not value:
        raise TypeError("timeline actor source must be nonempty text")
    return f"actor:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _correlations(
    values: tuple[tuple[TimelineCorrelationKind, str, TimelineAudience], ...],
) -> tuple[TimelineCorrelationV1, ...]:
    return tuple(
        TimelineCorrelationV1(
            schema_version=TIMELINE_CORRELATION_V1,
            kind=kind,
            correlation_id=value,
            data_class=data_class,
        )
        for kind, value, data_class in sorted(values, key=lambda item: (item[0].value, item[1]))
    )


def _display(
    values: tuple[tuple[TimelineDisplayFieldName, str, TimelineAudience], ...],
) -> tuple[TimelineDisplayFieldV1, ...]:
    return tuple(
        TimelineDisplayFieldV1(
            schema_version=TIMELINE_DISPLAY_FIELD_V1,
            name=name,
            value=value,
            data_class=data_class,
        )
        for name, value, data_class in sorted(values, key=lambda item: item[0].value)
    )


def _policy(
    policy_set: TimelineEvidencePolicySetV1,
    evidence_class: TimelineEvidenceClass,
) -> tuple[str, int]:
    if type(policy_set) is not TimelineEvidencePolicySetV1:
        raise TypeError("timeline policy set must be exact")
    selected = next(
        item for item in policy_set.policies if item.evidence_class is evidence_class
    )
    return canonical_sha256(policy_set), selected.raw_retention_days


def _raw_source(
    source: StrictContractModel,
    *,
    retained_source: StrictContractModel | None = None,
    target: TargetBinding,
    evidence_class: TimelineEvidenceClass,
    payload_sha256: str,
    signature_sha256: str | None,
) -> TimelineRawSourceV1:
    canonical = canonical_json_bytes(retained_source or source)
    record_sha256 = hashlib.sha256(canonical).hexdigest()
    source_schema_version = getattr(source, "schema_version", None)
    if type(source_schema_version) is not str:
        raise TypeError("timeline source schema version is absent")
    return TimelineRawSourceV1(
        schema_version=TIMELINE_RAW_SOURCE_V1,
        raw_source_id=f"cgraw:{record_sha256}",
        source_schema_version=source_schema_version,
        target=target,
        evidence_class=evidence_class,
        payload_sha256=payload_sha256,
        record_sha256=record_sha256,
        canonical_record=canonical.decode("utf-8"),
        signature_sha256=signature_sha256,
    )


def _redacted_source(source: StrictContractModel) -> TimelineRedactedSourceV1:
    source_schema_version = getattr(source, "schema_version", None)
    if type(source_schema_version) is not str:
        raise TypeError("timeline source schema version is absent")
    return TimelineRedactedSourceV1(
        schema_version=TIMELINE_REDACTED_SOURCE_V1,
        source_schema_version=source_schema_version,
        source_sha256=canonical_sha256(source),
        redaction_policy="EXCLUDE_CAPABILITY_AND_CREDENTIAL_MATERIAL_V1",
    )


def _projection(
    *,
    source: StrictContractModel,
    source_id: str,
    event_type: TimelineEventType,
    target: TargetBinding,
    actor_role: TimelineActorRole,
    actor: str,
    root_id: str,
    root_sha256: str,
    epoch: int,
    occurred_at: str,
    correlations: tuple[TimelineCorrelationV1, ...],
    payload_sha256: str,
    signature: TimelineSignatureMetadataV1 | None,
    verification_status: TimelineVerificationStatus,
    terminal_classification: TimelineTerminalClassification,
    display_fields: tuple[TimelineDisplayFieldV1, ...],
    policy_set: TimelineEvidencePolicySetV1,
    retained_source: StrictContractModel | None = None,
    actor_id: str | None = None,
) -> TimelineProjection:
    evidence_class = _EVENT_CLASS[event_type]
    if target != policy_set.target:
        raise ValueError("timeline source target is outside its policy")
    policy_sha256, retention_days = _policy(policy_set, evidence_class)
    source_schema_version = getattr(source, "schema_version", None)
    if type(source_schema_version) is not str:
        raise TypeError("timeline source schema version is absent")
    signature_sha256 = None if signature is None else signature.signature_sha256
    raw = _raw_source(
        source,
        retained_source=retained_source,
        target=target,
        evidence_class=evidence_class,
        payload_sha256=payload_sha256,
        signature_sha256=signature_sha256,
    )
    event = TimelineEventV1(
        schema_version=TIMELINE_EVENT_V1,
        source_id=source_id,
        source_schema_version=source_schema_version,
        raw_source_id=raw.raw_source_id,
        event_type=event_type,
        evidence_class=evidence_class,
        target=target,
        actor_role=actor_role,
        actor_id=actor_id or timeline_actor_id(actor),
        actor_data_class=TimelineAudience.SECURITY_AUDIT,
        root_id=root_id,
        root_sha256=root_sha256,
        epoch=epoch,
        occurred_at=occurred_at,
        correlations=correlations,
        payload_sha256=payload_sha256,
        raw_record_sha256=raw.record_sha256,
        policy_sha256=policy_sha256,
        raw_retention_days=retention_days,
        signature=signature,
        verification_status=verification_status,
        terminal_classification=terminal_classification,
        display_fields=display_fields,
    )
    return TimelineProjection(event=event, raw_source=raw)


def _signature_metadata(
    signed: (
        SignedEvidenceEventV1
        | SignedHealthDecisionProofV1
        | SignedIndependentVerificationEvidenceV1
    ),
) -> TimelineSignatureMetadataV1:
    raw_signature = decode_base64url(signed.signature, maximum_bytes=256)
    return TimelineSignatureMetadataV1(
        schema_version=TIMELINE_SIGNATURE_METADATA_V1,
        purpose=signed.purpose,
        signing_key_version=signed.signing_key_version,
        signing_algorithm=signed.signing_algorithm,
        payload_sha256=signed.payload_sha256,
        signing_input_sha256=signed.signing_input_sha256,
        signature_sha256=hashlib.sha256(raw_signature).hexdigest(),
    )


def project_signed_evidence_event(
    signed: SignedEvidenceEventV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
    signature_verified: bool,
) -> TimelineProjection:
    """Project one signed evidence record without implying unperformed verification."""

    if type(signed) is not SignedEvidenceEventV1 or type(signature_verified) is not bool:
        raise TypeError("signed evidence projection inputs must be exact")
    source = signed.event
    event_type = _EVIDENCE_KIND_EVENT[source.kind]
    actor_role = {
        EvidenceKind.ROOT_CREATED: TimelineActorRole.OPERATOR,
        EvidenceKind.CAPABILITY_ISSUED: TimelineActorRole.ISSUER,
        EvidenceKind.EPOCH_ADVANCED: TimelineActorRole.OPERATOR,
        EvidenceKind.DELIVERY_AUTHENTICATED: TimelineActorRole.EXECUTOR,
        EvidenceKind.CAPABILITY_VERIFIED: TimelineActorRole.EXECUTOR,
        EvidenceKind.RECEIPT_CLAIMED: TimelineActorRole.EXECUTOR,
        EvidenceKind.MUTATION_APPLIED: TimelineActorRole.EXECUTOR,
        EvidenceKind.TARGET_VERIFIED: TimelineActorRole.VERIFIER,
        EvidenceKind.EXECUTION_DENIED: TimelineActorRole.EXECUTOR,
        EvidenceKind.OUTCOME_AMBIGUOUS: TimelineActorRole.EXECUTOR,
    }[source.kind]
    correlation_values = [
        (TimelineCorrelationKind.EVIDENCE, source.evidence_id, TimelineAudience.OPERATOR)
    ]
    if source.receipt_id is not None:
        correlation_values.append(
            (TimelineCorrelationKind.RECEIPT, source.receipt_id, TimelineAudience.OPERATOR)
        )
    if source.request_id is not None:
        correlation_values.append(
            (TimelineCorrelationKind.REQUEST, source.request_id, TimelineAudience.OPERATOR)
        )
    display_values = [
        (
            TimelineDisplayFieldName.SUMMARY,
            source.kind.value.replace("_", " ").title(),
            TimelineAudience.PUBLIC_DEMO,
        )
    ]
    if source.reason_code is not None:
        display_values.append(
            (
                TimelineDisplayFieldName.REASON_CODE,
                source.reason_code.value,
                TimelineAudience.OPERATOR,
            )
        )
    if source.provider_operation is not None:
        display_values.append(
            (
                TimelineDisplayFieldName.OUTCOME,
                "provider-operation-recorded",
                TimelineAudience.PUBLIC_DEMO,
            )
        )
    return _projection(
        source=signed,
        source_id=source.evidence_id,
        event_type=event_type,
        target=source.target,
        actor_role=actor_role,
        actor=source.actor,
        root_id=source.root_id,
        root_sha256=source.root_sha256,
        epoch=source.epoch,
        occurred_at=source.occurred_at,
        correlations=_correlations(tuple(correlation_values)),
        payload_sha256=signed.payload_sha256,
        signature=_signature_metadata(signed),
        verification_status=(
            TimelineVerificationStatus.VERIFIED
            if signature_verified
            else TimelineVerificationStatus.UNVERIFIED
        ),
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(tuple(display_values)),
        policy_set=policy_set,
    )


def project_signed_capability(
    signed: SignedCapability,
    *,
    policy_set: TimelineEvidencePolicySetV1,
    signature_verified: bool,
) -> TimelineProjection:
    """Project a capability while keeping its token and identifiers out of summaries."""

    if type(signed) is not SignedCapability or type(signature_verified) is not bool:
        raise TypeError("signed capability projection inputs must be exact")
    claims = signed.claims
    signing = build_signing_input(
        SigningProfile.capability(claims.target.project_id, claims.signing_key_version),
        claims,
    )
    signature_sha256 = hashlib.sha256(
        decode_base64url(signed.signature, maximum_bytes=256)
    ).hexdigest()
    signature = TimelineSignatureMetadataV1(
        schema_version=TIMELINE_SIGNATURE_METADATA_V1,
        purpose="CAPABILITY",
        signing_key_version=claims.signing_key_version,
        signing_algorithm=claims.signing_algorithm,
        payload_sha256=signing.payload_sha256,
        signing_input_sha256=signing.digest_sha256,
        signature_sha256=signature_sha256,
    )
    return _projection(
        source=signed,
        retained_source=_redacted_source(signed),
        source_id=timeline_capability_source_id(canonical_sha256(signed)),
        event_type=TimelineEventType.CAPABILITY_ISSUED,
        target=claims.target,
        actor_role=TimelineActorRole.ISSUER,
        actor=claims.issuer,
        root_id=claims.root_id,
        root_sha256=claims.root_sha256,
        epoch=claims.epoch,
        occurred_at=claims.issued_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.CAPABILITY,
                    claims.capability_id,
                    TimelineAudience.RESTRICTED,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    claims.request_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=signing.payload_sha256,
        signature=signature,
        verification_status=(
            TimelineVerificationStatus.VERIFIED
            if signature_verified
            else TimelineVerificationStatus.UNVERIFIED
        ),
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.ACTION,
                    claims.action.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Capability issued",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_task_request(
    task: TaskRequest,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project an addressed task without displaying its embedded capability."""

    if type(task) is not TaskRequest:
        raise TypeError("task projection input must be exact")
    intent = task.intent
    return _projection(
        source=task,
        retained_source=_redacted_source(task),
        source_id=task.task_id,
        event_type=TimelineEventType.TASK_CREATED,
        target=intent.target,
        actor_role=TimelineActorRole.COORDINATOR,
        actor=intent.target.project_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        occurred_at=task.scheduled_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.REQUEST,
                    intent.request_id,
                    TimelineAudience.OPERATOR,
                ),
                (TimelineCorrelationKind.TASK, task.task_id, TimelineAudience.OPERATOR),
            )
        ),
        payload_sha256=canonical_sha256(task),
        signature=None,
        verification_status=TimelineVerificationStatus.NOT_APPLICABLE,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.ACTION,
                    intent.action.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Addressed task created",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_canary_dispatch(
    result: CanaryDispatchResultV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project the exact addressed canary task result returned by coordination."""

    if type(result) is not CanaryDispatchResultV1:
        raise TypeError("canary dispatch projection input must be exact")
    return _project_dispatch_result(
        source=result,
        source_id=result.task_id,
        target=result.target,
        root_id=result.root_id,
        root_sha256=result.root_sha256,
        epoch=result.epoch,
        request_id=result.request_id,
        task_id=result.task_id,
        action=CapabilityAction.APPLY_CANARY.value,
        disposition=result.enqueue_disposition,
        occurred_at=result.scheduled_at,
        policy_set=policy_set,
    )


def project_promotion_dispatch(
    result: PromotionDispatchResultV2,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project the exact addressed promotion task result returned by coordination."""

    if type(result) is not PromotionDispatchResultV2:
        raise TypeError("promotion dispatch projection input must be exact")
    return _project_dispatch_result(
        source=result,
        source_id=result.task_id,
        target=result.target,
        root_id=result.root_id,
        root_sha256=result.root_sha256,
        epoch=result.epoch,
        request_id=result.request_id,
        task_id=result.task_id,
        action=CapabilityAction.PROMOTE_CANDIDATE.value,
        disposition=result.enqueue_disposition,
        occurred_at=result.scheduled_at,
        policy_set=policy_set,
    )


def _project_dispatch_result(
    *,
    source: StrictContractModel,
    source_id: str,
    target: TargetBinding,
    root_id: str,
    root_sha256: str,
    epoch: int,
    request_id: str,
    task_id: str,
    action: str,
    disposition: str,
    occurred_at: str,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    normalized_source = source
    normalized_disposition = disposition
    if disposition in {"CREATED", "DUPLICATE"}:
        normalized_source = type(source).model_validate(
            {**source.model_dump(mode="python"), "enqueue_disposition": "CREATED"}
        )
        normalized_disposition = "CREATED"
    return _projection(
        source=normalized_source,
        source_id=source_id,
        event_type=TimelineEventType.TASK_CREATED,
        target=target,
        actor_role=TimelineActorRole.COORDINATOR,
        actor=target.project_id,
        root_id=root_id,
        root_sha256=root_sha256,
        epoch=epoch,
        occurred_at=occurred_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.REQUEST,
                    request_id,
                    TimelineAudience.OPERATOR,
                ),
                (TimelineCorrelationKind.TASK, task_id, TimelineAudience.OPERATOR),
            )
        ),
        payload_sha256=canonical_sha256(normalized_source),
        signature=None,
        verification_status=TimelineVerificationStatus.NOT_APPLICABLE,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.ACTION,
                    action,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.OUTCOME,
                    normalized_disposition,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Addressed rollout task recorded",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_epoch_authority(
    authority: EpochAuthorityRecord,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project an initial or advanced exact-match epoch authority record."""

    if type(authority) is not EpochAuthorityRecord:
        raise TypeError("authority projection input must be exact")
    event_type = (
        TimelineEventType.AUTHORITY_ROOT_CREATED
        if authority.cause is EpochChangeCause.ROOT_CREATED
        else TimelineEventType.AUTHORITY_EPOCH_ADVANCED
    )
    return _projection(
        source=authority,
        source_id=f"authority:{canonical_sha256(authority)}",
        event_type=event_type,
        target=authority.target,
        actor_role=(
            TimelineActorRole.OPERATOR
            if authority.cause is EpochChangeCause.OPERATOR_REVOCATION
            else TimelineActorRole.COORDINATOR
        ),
        actor=authority.changed_by,
        root_id=authority.root_id,
        root_sha256=authority.root_sha256,
        epoch=authority.current_epoch,
        occurred_at=authority.changed_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.EVIDENCE,
                    authority.evidence_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    authority.request_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=canonical_sha256(authority),
        signature=None,
        verification_status=TimelineVerificationStatus.NOT_APPLICABLE,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.OUTCOME,
                    authority.cause.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Epoch authority recorded",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_execution_receipt(
    receipt: ExecutionReceipt,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project one durable receipt state without inventing a terminal classification."""

    if type(receipt) is not ExecutionReceipt:
        raise TypeError("receipt projection input must be exact")
    event_type = {
        ReceiptOutcome.CLAIMED: TimelineEventType.MUTATION_REQUESTED,
        ReceiptOutcome.DENIED: TimelineEventType.MUTATION_DENIED,
        ReceiptOutcome.APPLIED: TimelineEventType.MUTATION_APPLIED,
        ReceiptOutcome.VERIFIED: TimelineEventType.MUTATION_APPLIED,
        ReceiptOutcome.FAILED_SAFE: TimelineEventType.MUTATION_DENIED,
        ReceiptOutcome.AMBIGUOUS: TimelineEventType.MUTATION_AMBIGUOUS,
    }[receipt.outcome]
    fields = [
        (
            TimelineDisplayFieldName.OUTCOME,
            receipt.outcome.value,
            TimelineAudience.PUBLIC_DEMO,
        ),
        (
            TimelineDisplayFieldName.SUMMARY,
            "Mutation receipt recorded",
            TimelineAudience.PUBLIC_DEMO,
        ),
    ]
    if receipt.reason_code is not None:
        fields.append(
            (
                TimelineDisplayFieldName.REASON_CODE,
                receipt.reason_code.value,
                TimelineAudience.OPERATOR,
            )
        )
    return _projection(
        source=receipt,
        source_id=f"receipt-state:{canonical_sha256(receipt)}",
        event_type=event_type,
        target=receipt.target,
        actor_role=TimelineActorRole.EXECUTOR,
        actor=receipt.target.project_id,
        root_id=receipt.root_id,
        root_sha256=receipt.root_sha256,
        epoch=receipt.epoch,
        occurred_at=receipt.updated_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.RECEIPT,
                    receipt.receipt_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    receipt.request_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=canonical_sha256(receipt),
        signature=None,
        verification_status=(
            TimelineVerificationStatus.VERIFIED
            if receipt.outcome is ReceiptOutcome.VERIFIED
            else TimelineVerificationStatus.AMBIGUOUS
            if receipt.outcome is ReceiptOutcome.AMBIGUOUS
            else TimelineVerificationStatus.NOT_APPLICABLE
        ),
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(tuple(fields)),
        policy_set=policy_set,
    )


def project_signed_health_proof(
    signed: SignedHealthDecisionProofV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
    signature_verified: bool,
) -> tuple[TimelineProjection, TimelineProjection]:
    """Project the observation and decision contained in one signed health proof."""

    if type(signed) is not SignedHealthDecisionProofV1 or type(signature_verified) is not bool:
        raise TypeError("health projection inputs must be exact")
    proof = signed.proof
    observation = proof.observation
    decision = proof.decision
    signature = _signature_metadata(signed)
    verification = (
        TimelineVerificationStatus.VERIFIED
        if signature_verified
        else TimelineVerificationStatus.UNVERIFIED
    )
    common_correlations = (
        (
            TimelineCorrelationKind.DECISION,
            decision.decision_id,
            TimelineAudience.OPERATOR,
        ),
        (
            TimelineCorrelationKind.EVIDENCE,
            proof.proof_id,
            TimelineAudience.OPERATOR,
        ),
    )
    observed = _projection(
        source=signed,
        source_id=f"{proof.proof_id}:observation",
        event_type=TimelineEventType.HEALTH_OBSERVED,
        target=observation.target,
        actor_role=TimelineActorRole.VERIFIER,
        actor=proof.verifier_identity,
        root_id=observation.root_id,
        root_sha256=observation.root_sha256,
        epoch=observation.epoch,
        occurred_at=observation.observed_at,
        correlations=_correlations(common_correlations),
        payload_sha256=signed.payload_sha256,
        signature=signature,
        verification_status=verification,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.OBSERVATION,
                    observation.completeness.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Health window observed",
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.WINDOW,
                    str(observation.window_index),
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )
    decided = _projection(
        source=signed,
        source_id=f"{proof.proof_id}:decision",
        event_type=TimelineEventType.HEALTH_DECIDED,
        target=decision.target,
        actor_role=TimelineActorRole.VERIFIER,
        actor=proof.verifier_identity,
        root_id=decision.root_id,
        root_sha256=decision.root_sha256,
        epoch=decision.epoch,
        occurred_at=decision.evaluated_at,
        correlations=_correlations(common_correlations),
        payload_sha256=signed.payload_sha256,
        signature=signature,
        verification_status=verification,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.OUTCOME,
                    decision.status.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Health decision recorded",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )
    return observed, decided


def project_independent_verification(
    verified: VerifiedIndependentVerificationEvidenceV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project only coordinator-verified, independently signed target evidence."""

    if type(verified) is not VerifiedIndependentVerificationEvidenceV1:
        raise TypeError("independent verification projection input must be exact")
    signed = verified.signed_evidence
    evidence = signed.evidence
    source_sha256 = canonical_sha256(verified)
    fields = [
        (
            TimelineDisplayFieldName.ACTION,
            evidence.action.value,
            TimelineAudience.OPERATOR,
        ),
        (
            TimelineDisplayFieldName.OBSERVATION,
            evidence.kind.value,
            TimelineAudience.PUBLIC_DEMO,
        ),
        (
            TimelineDisplayFieldName.OUTCOME,
            evidence.verdict.value,
            TimelineAudience.PUBLIC_DEMO,
        ),
        (
            TimelineDisplayFieldName.REASON_CODE,
            evidence.reason_code,
            TimelineAudience.OPERATOR,
        ),
        (
            TimelineDisplayFieldName.SUMMARY,
            "Independent verification recorded",
            TimelineAudience.PUBLIC_DEMO,
        ),
    ]
    configuration = verified.signing_request.configuration
    if configuration is not None and configuration.observation is not None:
        facts = configuration.observation.facts
        traffic = {item.revision: item.percent for item in facts.traffic_statuses}
        fields.append(
            (
                TimelineDisplayFieldName.STATE,
                (
                    f"stable_percent={traffic.get(facts.stable_revision, 0)};"
                    f"candidate_percent={traffic.get(facts.candidate_revision, 0)};"
                    "target_configuration_sha256="
                    f"{facts.target_configuration_sha256}"
                ),
                TimelineAudience.OPERATOR,
            )
        )
    return _projection(
        source=verified,
        source_id=f"verification:{source_sha256}",
        event_type=TimelineEventType.VERIFICATION_RECORDED,
        target=evidence.target,
        actor_role=TimelineActorRole.VERIFIER,
        actor=evidence.verifier_identity,
        root_id=evidence.root_id,
        root_sha256=evidence.root_sha256,
        epoch=evidence.epoch,
        occurred_at=evidence.occurred_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.EVIDENCE,
                    f"verification-evidence:{signed.payload_sha256}",
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    evidence.request_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.VERIFICATION,
                    evidence.correlation_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=signed.payload_sha256,
        signature=_signature_metadata(signed),
        verification_status=TimelineVerificationStatus.VERIFIED,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(tuple(fields)),
        policy_set=policy_set,
    )


def project_completion_classification(
    classification: CompletionClassificationV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project the pure classifier result without inventing a signature."""

    if type(classification) is not CompletionClassificationV1:
        raise TypeError("completion classification projection input must be exact")
    request = classification.request
    verification = request.verification
    terminal = (
        TimelineTerminalClassification.AMBIGUOUS
        if classification.status is CompletionStatus.AMBIGUOUS
        else {
            CompletionKind.PROMOTION: TimelineTerminalClassification.PROMOTED,
            CompletionKind.RECOVERY: TimelineTerminalClassification.RECOVERED,
            CompletionKind.REVOCATION: TimelineTerminalClassification.REVOKED,
            CompletionKind.STALE_CAPABILITY_DENIAL: (
                TimelineTerminalClassification.DENIED
            ),
        }[request.kind]
    )
    source_sha256 = canonical_sha256(classification)
    return _projection(
        source=classification,
        source_id=f"classification:{source_sha256}",
        event_type=TimelineEventType.TERMINAL_CLASSIFIED,
        target=verification.target,
        actor_role=TimelineActorRole.COORDINATOR,
        actor=(
            f"controlgraph-coordinator@{verification.target.project_id}"
            ".iam.gserviceaccount.com"
        ),
        root_id=verification.root_id,
        root_sha256=verification.root_sha256,
        epoch=verification.epoch,
        occurred_at=classification.classified_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.DECISION,
                    f"completion:{source_sha256}",
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.EVIDENCE,
                    f"completion-bundle:{classification.bundle_sha256}",
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    verification.request_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.VERIFICATION,
                    verification.correlation_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=source_sha256,
        signature=None,
        verification_status=(
            TimelineVerificationStatus.VERIFIED
            if classification.status is CompletionStatus.COMPLETE
            else TimelineVerificationStatus.AMBIGUOUS
        ),
        terminal_classification=terminal,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.ACTION,
                    request.kind.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.OUTCOME,
                    classification.status.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.REASON_CODE,
                    classification.reason.value,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Completion classified",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_epoch_revocation(
    outcome: EpochRevocationCallOutcomeV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> tuple[TimelineProjection]:
    """Project an authenticated operator revocation without inventing classification."""

    if type(outcome) is not EpochRevocationCallOutcomeV1:
        raise TypeError("epoch revocation projection input must be exact")
    result = outcome.result
    correlations = _correlations(
        (
            (
                TimelineCorrelationKind.EVIDENCE,
                result.evidence_id,
                TimelineAudience.OPERATOR,
            ),
            (
                TimelineCorrelationKind.OPERATOR_ACTION,
                outcome.attempt_id,
                TimelineAudience.OPERATOR,
            ),
            (
                TimelineCorrelationKind.REQUEST,
                result.request_id,
                TimelineAudience.OPERATOR,
            ),
        )
    )
    action = _projection(
        source=outcome,
        source_id=f"{outcome.attempt_id}:operator",
        event_type=TimelineEventType.OPERATOR_ACTION_RECORDED,
        target=result.target,
        actor_role=TimelineActorRole.OPERATOR,
        actor=result.operator_identity,
        root_id=result.root_id,
        root_sha256=result.root_sha256,
        epoch=result.new_epoch,
        occurred_at=result.committed_at,
        correlations=correlations,
        payload_sha256=canonical_sha256(outcome),
        signature=None,
        verification_status=TimelineVerificationStatus.NOT_APPLICABLE,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.ACTION,
                    "REVOKE_EPOCH",
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.REASON_CODE,
                    "OPERATOR_REQUESTED",
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Operator revoked rollout authority",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )
    return (action,)


def project_service_claim_release(
    result: ServiceClaimReleaseResultV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project independently verified terminal state used to release a service claim."""

    if type(result) is not ServiceClaimReleaseResultV1:
        raise TypeError("service claim release projection input must be exact")
    classification = {
        ServiceClaimTargetClassification.CANDIDATE_PROMOTED: (
            TimelineTerminalClassification.PROMOTED
        ),
        ServiceClaimTargetClassification.STABLE_RESTORED: (
            TimelineTerminalClassification.RECOVERED
        ),
    }[result.classification_proof.classification]
    return _projection(
        source=result,
        source_id=f"{result.result_id}:terminal",
        event_type=TimelineEventType.TERMINAL_CLASSIFIED,
        target=result.target,
        actor_role=TimelineActorRole.VERIFIER,
        actor=result.classification_proof.classified_by,
        root_id=result.root_id,
        root_sha256=result.root_sha256,
        epoch=result.fenced_epoch,
        occurred_at=result.released_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.EVIDENCE,
                    result.classification_evidence_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    result.request_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.VERIFICATION,
                    result.classification_proof.evidence_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=canonical_sha256(result),
        signature=None,
        verification_status=TimelineVerificationStatus.VERIFIED,
        terminal_classification=classification,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.OUTCOME,
                    classification.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Terminal rollout independently classified",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_recovery_abandonment(
    result: RecoveryAbandonmentResultV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project each durable phase of an operator-approved recovery abandonment."""

    if type(result) is not RecoveryAbandonmentResultV1:
        raise TypeError("recovery abandonment projection input must be exact")
    released = result.phase is RecoveryAbandonmentPhase.RELEASED
    return _projection(
        source=result,
        source_id=f"{result.result_id}:{result.phase.value.lower()}",
        event_type=TimelineEventType.OPERATOR_ACTION_RECORDED,
        target=result.target,
        actor_role=TimelineActorRole.OPERATOR,
        actor=result.operator_identity,
        root_id=result.root_id,
        root_sha256=result.root_sha256,
        epoch=result.fenced_epoch,
        occurred_at=(
            result.released_at
            if released and result.released_at is not None
            else result.fenced_at
        ),
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.EVIDENCE,
                    result.fence_evidence_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.RECOVERY,
                    result.recovery_dispatch_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    result.request_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=canonical_sha256(result),
        signature=None,
        verification_status=(
            TimelineVerificationStatus.VERIFIED
            if released
            else TimelineVerificationStatus.AMBIGUOUS
        ),
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.ACTION,
                    "ABANDON_AMBIGUOUS_RECOVERY",
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.OUTCOME,
                    result.phase.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    (
                        "Ambiguous recovery claim released"
                        if released
                        else "Ambiguous recovery fenced for reset"
                    ),
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_recovery_intent(
    intent: RecoveryIntentV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project the root-owned exactly-once recovery intent."""

    if type(intent) is not RecoveryIntentV1:
        raise TypeError("recovery intent projection input must be exact")
    return _projection(
        source=intent,
        source_id=intent.intent_id,
        event_type=TimelineEventType.RECOVERY_INTENT_CREATED,
        target=intent.command.source.target,
        actor_role=TimelineActorRole.COORDINATOR,
        actor=intent.command.source.target.project_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        occurred_at=intent.created_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.RECOVERY,
                    intent.intent_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    intent.request_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=canonical_sha256(intent),
        signature=None,
        verification_status=TimelineVerificationStatus.NOT_APPLICABLE,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.OUTCOME,
                    intent.trigger_basis.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Recovery intent created",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_recovery_dispatch(
    result: RecoveryDispatchResultV2,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project the one addressed recovery task result."""

    if type(result) is not RecoveryDispatchResultV2:
        raise TypeError("recovery dispatch projection input must be exact")
    normalized = result
    if result.enqueue_disposition in {"CREATED", "DUPLICATE"}:
        normalized = RecoveryDispatchResultV2.model_validate(
            {**result.model_dump(mode="python"), "enqueue_disposition": "CREATED"}
        )
    return _projection(
        source=normalized,
        source_id=result.task_id,
        event_type=TimelineEventType.RECOVERY_TASK_CREATED,
        target=result.target,
        actor_role=TimelineActorRole.COORDINATOR,
        actor=result.target.project_id,
        root_id=result.root_id,
        root_sha256=result.root_sha256,
        epoch=result.epoch,
        occurred_at=result.scheduled_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.RECOVERY,
                    result.task_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    result.request_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.TASK,
                    result.task_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=canonical_sha256(normalized),
        signature=None,
        verification_status=TimelineVerificationStatus.NOT_APPLICABLE,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.ACTION,
                    CapabilityAction.RECOVER_STABLE.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.OUTCOME,
                    normalized.enqueue_disposition,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Recovery task addressed",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
    )


def project_model_assistance(
    audit: ModelAssistanceTimelineAuditV1,
    *,
    policy_set: TimelineEvidencePolicySetV1,
) -> TimelineProjection:
    """Project one already-redacted advisor lifecycle record."""

    if type(audit) is not ModelAssistanceTimelineAuditV1:
        raise TypeError("model assistance projection input must be exact")
    return _projection(
        source=audit,
        source_id=audit.event_id,
        event_type=TimelineEventType.MODEL_ASSISTANCE_RECORDED,
        target=audit.target,
        actor_role=(
            TimelineActorRole.OPERATOR
            if audit.actor_role is ModelAssistanceActorRole.OPERATOR
            else TimelineActorRole.ADVISOR
        ),
        actor=audit.actor_id,
        root_id=audit.root_id,
        root_sha256=audit.root_sha256,
        epoch=audit.epoch,
        occurred_at=audit.occurred_at,
        correlations=_correlations(
            (
                (
                    TimelineCorrelationKind.MODEL,
                    audit.interaction_id,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineCorrelationKind.REQUEST,
                    audit.request_id,
                    TimelineAudience.OPERATOR,
                ),
            )
        ),
        payload_sha256=canonical_sha256(audit),
        signature=None,
        verification_status=TimelineVerificationStatus.NOT_APPLICABLE,
        terminal_classification=TimelineTerminalClassification.NONE,
        display_fields=_display(
            (
                (
                    TimelineDisplayFieldName.OUTCOME,
                    audit.disposition.value,
                    TimelineAudience.OPERATOR,
                ),
                (
                    TimelineDisplayFieldName.STATE,
                    audit.lifecycle.value,
                    TimelineAudience.PUBLIC_DEMO,
                ),
                (
                    TimelineDisplayFieldName.SUMMARY,
                    "Read-only rollout advice recorded",
                    TimelineAudience.PUBLIC_DEMO,
                ),
            )
        ),
        policy_set=policy_set,
        actor_id=audit.actor_id,
    )


__all__ = [
    "TimelineProjection",
    "project_canary_dispatch",
    "project_completion_classification",
    "project_epoch_authority",
    "project_epoch_revocation",
    "project_execution_receipt",
    "project_independent_verification",
    "project_model_assistance",
    "project_promotion_dispatch",
    "project_recovery_abandonment",
    "project_recovery_dispatch",
    "project_recovery_intent",
    "project_service_claim_release",
    "project_signed_capability",
    "project_signed_evidence_event",
    "project_signed_health_proof",
    "project_task_request",
    "timeline_actor_id",
]
