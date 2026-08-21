"""Strict contracts for the target-scoped append-only operator timeline."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Identifier,
    KeyVersionResource,
    NonNegativeSafeInteger,
    PositiveSafeInteger,
    Sha256Digest,
    ShortText,
    StrictContractModel,
    UtcSecond,
    validate_nfc_text,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import TargetBinding

TIMELINE_SIGNATURE_METADATA_V1: Final = "controlgraph.timeline-signature-metadata/v1"
TIMELINE_CORRELATION_V1: Final = "controlgraph.timeline-correlation/v1"
TIMELINE_DISPLAY_FIELD_V1: Final = "controlgraph.timeline-display-field/v1"
TIMELINE_EVIDENCE_POLICY_V1: Final = "controlgraph.timeline-evidence-policy/v1"
TIMELINE_EVIDENCE_POLICY_SET_V1: Final = "controlgraph.timeline-evidence-policy-set/v1"
TIMELINE_EVENT_V1: Final = "controlgraph.timeline-event/v1"
TIMELINE_ENTRY_CONTENT_V1: Final = "controlgraph.timeline-entry-content/v1"
TIMELINE_ENTRY_V1: Final = "controlgraph.timeline-entry/v1"
TIMELINE_IDENTITY_V1: Final = "controlgraph.timeline-identity/v1"
TIMELINE_HEAD_V1: Final = "controlgraph.timeline-head/v1"
TIMELINE_PAGE_COMMAND_V1: Final = "controlgraph.timeline-page-command/v1"
TIMELINE_ENTRY_PROJECTION_V1: Final = "controlgraph.timeline-entry-projection/v1"
TIMELINE_PAGE_V1: Final = "controlgraph.timeline-page/v1"
TIMELINE_RAW_SOURCE_V1: Final = "controlgraph.timeline-raw-source/v1"
TIMELINE_RAW_EVIDENCE_V1: Final = "controlgraph.timeline-raw-evidence/v1"
TIMELINE_RAW_EXPORT_COMMAND_V1: Final = "controlgraph.timeline-raw-export-command/v1"
TIMELINE_RAW_EXPORT_ITEM_V1: Final = "controlgraph.timeline-raw-export-item/v1"
TIMELINE_RAW_EXPORT_V1: Final = "controlgraph.timeline-raw-export/v1"
TIMELINE_STORAGE_DOCUMENT_V1: Final = "controlgraph.timeline-storage-document/v1"

TIMELINE_HEAD_COLLECTION: Final = "controlgraph_timeline_heads"
TIMELINE_IDENTITY_COLLECTION: Final = "controlgraph_timeline_identities"
TIMELINE_ENTRY_COLLECTION: Final = "controlgraph_timeline_entries"
TIMELINE_RAW_COLLECTION: Final = "controlgraph_timeline_raw"
TIMELINE_MAX_PAGE_SIZE: Final = 100
TIMELINE_MAX_RAW_EXPORT_SIZE: Final = 25
TIMELINE_DEFAULT_RAW_RETENTION_DAYS: Final = 30

ContractVersion = Annotated[
    str,
    StringConstraints(
        min_length=20,
        max_length=128,
        pattern=r"^controlgraph\.[a-z0-9-]+/v[1-9][0-9]*$",
    ),
    AfterValidator(validate_nfc_text),
]
CanonicalPayload = Annotated[
    str,
    StringConstraints(min_length=2, max_length=65_536),
    AfterValidator(validate_nfc_text),
]


class TimelineAudience(StrEnum):
    """Closed evidence views from least to most privileged."""

    PUBLIC_DEMO = "PUBLIC_DEMO"
    OPERATOR = "OPERATOR"
    SECURITY_AUDIT = "SECURITY_AUDIT"
    RESTRICTED = "RESTRICTED"


class TimelineEvidenceClass(StrEnum):
    """Stable source families represented by the timeline."""

    AUTHORITY = "AUTHORITY"
    CAPABILITY = "CAPABILITY"
    TASK = "TASK"
    HEALTH = "HEALTH"
    DECISION = "DECISION"
    MUTATION = "MUTATION"
    RECOVERY = "RECOVERY"
    VERIFICATION = "VERIFICATION"
    MODEL_ASSISTANCE = "MODEL_ASSISTANCE"
    OPERATOR_ACTION = "OPERATOR_ACTION"


class TimelineEventType(StrEnum):
    """Closed, stable event types for target history."""

    AUTHORITY_ROOT_CREATED = "AUTHORITY_ROOT_CREATED"
    AUTHORITY_EPOCH_ADVANCED = "AUTHORITY_EPOCH_ADVANCED"
    CAPABILITY_ISSUED = "CAPABILITY_ISSUED"
    TASK_CREATED = "TASK_CREATED"
    TASK_DELIVERED = "TASK_DELIVERED"
    HEALTH_OBSERVED = "HEALTH_OBSERVED"
    HEALTH_DECIDED = "HEALTH_DECIDED"
    MUTATION_REQUESTED = "MUTATION_REQUESTED"
    MUTATION_APPLIED = "MUTATION_APPLIED"
    MUTATION_DENIED = "MUTATION_DENIED"
    MUTATION_AMBIGUOUS = "MUTATION_AMBIGUOUS"
    RECOVERY_INTENT_CREATED = "RECOVERY_INTENT_CREATED"
    RECOVERY_TASK_CREATED = "RECOVERY_TASK_CREATED"
    RECOVERY_APPLIED = "RECOVERY_APPLIED"
    VERIFICATION_RECORDED = "VERIFICATION_RECORDED"
    TERMINAL_CLASSIFIED = "TERMINAL_CLASSIFIED"
    MODEL_ASSISTANCE_RECORDED = "MODEL_ASSISTANCE_RECORDED"
    OPERATOR_ACTION_RECORDED = "OPERATOR_ACTION_RECORDED"


class TimelineActorRole(StrEnum):
    OPERATOR = "OPERATOR"
    API = "API"
    COORDINATOR = "COORDINATOR"
    ISSUER = "ISSUER"
    EXECUTOR = "EXECUTOR"
    RECOVERY = "RECOVERY"
    VERIFIER = "VERIFIER"
    EVIDENCE_WRITER = "EVIDENCE_WRITER"
    ADVISOR = "ADVISOR"
    TARGET = "TARGET"
    SYSTEM = "SYSTEM"


class TimelineCorrelationKind(StrEnum):
    REQUEST = "REQUEST"
    RECEIPT = "RECEIPT"
    EVIDENCE = "EVIDENCE"
    CAPABILITY = "CAPABILITY"
    TASK = "TASK"
    DECISION = "DECISION"
    MUTATION = "MUTATION"
    RECOVERY = "RECOVERY"
    VERIFICATION = "VERIFICATION"
    MODEL = "MODEL"
    OPERATOR_ACTION = "OPERATOR_ACTION"


class TimelineVerificationStatus(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    AMBIGUOUS = "AMBIGUOUS"


class TimelineTerminalClassification(StrEnum):
    NONE = "NONE"
    PROMOTED = "PROMOTED"
    RECOVERED = "RECOVERED"
    REVOKED = "REVOKED"
    DENIED = "DENIED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"


class TimelineDisplayFieldName(StrEnum):
    SUMMARY = "SUMMARY"
    ACTION = "ACTION"
    STATE = "STATE"
    OUTCOME = "OUTCOME"
    REASON_CODE = "REASON_CODE"
    REVISION = "REVISION"
    OBSERVATION = "OBSERVATION"
    WINDOW = "WINDOW"
    NEXT_ACTION = "NEXT_ACTION"


class TimelineStorageKind(StrEnum):
    HEAD = "HEAD"
    IDENTITY = "IDENTITY"
    ENTRY = "ENTRY"


class TimelineRawLifecycleStatus(StrEnum):
    """Honest raw-record availability at one export evaluation instant."""

    AVAILABLE = "AVAILABLE"
    EXPIRED_BY_POLICY = "EXPIRED_BY_POLICY"


_AUDIENCE_ORDER: Final[dict[TimelineAudience, int]] = {
    TimelineAudience.PUBLIC_DEMO: 0,
    TimelineAudience.OPERATOR: 1,
    TimelineAudience.SECURITY_AUDIT: 2,
    TimelineAudience.RESTRICTED: 3,
}


class TimelineEvidencePolicyV1(StrictContractModel):
    """Access and finite raw-lifecycle policy for one evidence class."""

    schema_version: Literal["controlgraph.timeline-evidence-policy/v1"]
    evidence_class: TimelineEvidenceClass
    writer_roles: Annotated[tuple[TimelineActorRole, ...], Field(min_length=1, max_length=4)]
    summary_audiences: Annotated[
        tuple[TimelineAudience, ...],
        Field(min_length=1, max_length=4),
    ]
    raw_read_audience: Literal[TimelineAudience.RESTRICTED]
    raw_export_audience: Literal[TimelineAudience.RESTRICTED]
    redaction_policy: Literal["ALLOWLIST_AND_SECRET_SCAN_V1"]
    raw_retention_days: Annotated[int, Field(ge=1, le=3_650)]
    deletion_policy: Literal["EXPIRE_RAW_PRESERVE_DIGEST_V1"]
    deletion_evidence_required: Literal[True]

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        writer_values = tuple(role.value for role in self.writer_roles)
        if len(set(writer_values)) != len(writer_values) or writer_values != tuple(
            sorted(writer_values)
        ):
            raise ValueError("timeline writer roles must be unique and ordered")
        if self.summary_audiences != tuple(TimelineAudience):
            raise ValueError("timeline summary audiences must preserve sequence visibility")
        return self


class TimelineEvidencePolicySetV1(StrictContractModel):
    """Complete policy registry bound to one configured target."""

    schema_version: Literal["controlgraph.timeline-evidence-policy-set/v1"]
    target: TargetBinding
    policies: Annotated[
        tuple[TimelineEvidencePolicyV1, ...],
        Field(min_length=len(TimelineEvidenceClass), max_length=len(TimelineEvidenceClass)),
    ]

    @model_validator(mode="after")
    def validate_complete_registry(self) -> Self:
        classes = tuple(policy.evidence_class for policy in self.policies)
        expected = tuple(sorted(TimelineEvidenceClass, key=lambda item: item.value))
        if classes != expected:
            raise ValueError("timeline evidence policies must cover every class in order")
        return self


_EVENT_CLASS: Final[dict[TimelineEventType, TimelineEvidenceClass]] = {
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


class TimelineSignatureMetadataV1(StrictContractModel):
    """Non-secret signature bindings retained in every audience projection."""

    schema_version: Literal["controlgraph.timeline-signature-metadata/v1"]
    purpose: Literal[
        "CAPABILITY",
        "EVIDENCE",
        "HEALTH_ATTESTATION",
        "INDEPENDENT_VERIFICATION",
        "RECOVERY_PRESTATE",
        "CLASSIFICATION_EVIDENCE",
    ]
    signing_key_version: KeyVersionResource
    signing_algorithm: Literal["EC_SIGN_P256_SHA256"]
    payload_sha256: Sha256Digest
    signing_input_sha256: Sha256Digest
    signature_sha256: Sha256Digest


class TimelineCorrelationV1(StrictContractModel):
    schema_version: Literal["controlgraph.timeline-correlation/v1"]
    kind: TimelineCorrelationKind
    correlation_id: Identifier
    data_class: TimelineAudience


class TimelineDisplayFieldV1(StrictContractModel):
    schema_version: Literal["controlgraph.timeline-display-field/v1"]
    name: TimelineDisplayFieldName
    value: ShortText
    data_class: TimelineAudience


class TimelineEventV1(StrictContractModel):
    """One immutable source-derived event before target sequence allocation."""

    schema_version: Literal["controlgraph.timeline-event/v1"]
    source_id: Identifier
    source_schema_version: ContractVersion
    raw_source_id: Identifier
    event_type: TimelineEventType
    evidence_class: TimelineEvidenceClass
    target: TargetBinding
    actor_role: TimelineActorRole
    actor_id: Identifier
    actor_data_class: TimelineAudience
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    occurred_at: UtcSecond
    correlations: Annotated[tuple[TimelineCorrelationV1, ...], Field(min_length=1, max_length=16)]
    payload_sha256: Sha256Digest
    raw_record_sha256: Sha256Digest
    policy_sha256: Sha256Digest
    raw_retention_days: Annotated[int, Field(ge=1, le=3_650)]
    signature: TimelineSignatureMetadataV1 | None
    verification_status: TimelineVerificationStatus
    terminal_classification: TimelineTerminalClassification
    display_fields: Annotated[
        tuple[TimelineDisplayFieldV1, ...],
        Field(min_length=1, max_length=16),
    ]

    @model_validator(mode="after")
    def validate_event(self) -> Self:
        if self.evidence_class is not _EVENT_CLASS[self.event_type]:
            raise ValueError("timeline event type does not match its evidence class")
        correlation_keys = tuple(
            (item.kind.value, item.correlation_id) for item in self.correlations
        )
        if len(set(correlation_keys)) != len(correlation_keys):
            raise ValueError("timeline correlations must be unique")
        if correlation_keys != tuple(sorted(correlation_keys)):
            raise ValueError("timeline correlations must use canonical order")
        display_names = tuple(item.name.value for item in self.display_fields)
        if len(set(display_names)) != len(display_names):
            raise ValueError("timeline display fields must be unique")
        if display_names != tuple(sorted(display_names)):
            raise ValueError("timeline display fields must use canonical order")
        is_terminal = self.event_type is TimelineEventType.TERMINAL_CLASSIFIED
        if is_terminal != (
            self.terminal_classification is not TimelineTerminalClassification.NONE
        ):
            raise ValueError("terminal classification requires its dedicated event type")
        if self.signature is not None and self.signature.payload_sha256 != self.payload_sha256:
            raise ValueError("timeline signature does not bind the source payload")
        return self


class TimelineEntryContentV1(StrictContractModel):
    schema_version: Literal["controlgraph.timeline-entry-content/v1"]
    target: TargetBinding
    sequence: PositiveSafeInteger
    previous_entry_sha256: Sha256Digest | None
    recorded_at: UtcSecond
    event: TimelineEventV1

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        if self.target != self.event.target:
            raise ValueError("timeline entry target does not match its event")
        if (self.sequence == 1) != (self.previous_entry_sha256 is None):
            raise ValueError("timeline entry predecessor does not match its sequence")
        return self


class TimelineEntryV1(StrictContractModel):
    schema_version: Literal["controlgraph.timeline-entry/v1"]
    entry_id: Identifier
    entry_sha256: Sha256Digest
    content: TimelineEntryContentV1

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        expected = canonical_sha256(self.content)
        if self.entry_sha256 != expected or self.entry_id != f"cgtimeline:{expected}":
            raise ValueError("timeline entry identity does not match its canonical content")
        return self


class TimelineIdentityV1(StrictContractModel):
    """Immutable source identity that makes append replay deterministic."""

    schema_version: Literal["controlgraph.timeline-identity/v1"]
    target: TargetBinding
    source_id: Identifier
    source_schema_version: ContractVersion
    event_sha256: Sha256Digest
    sequence: PositiveSafeInteger
    entry_id: Identifier
    entry_sha256: Sha256Digest
    recorded_at: UtcSecond

    @model_validator(mode="after")
    def validate_entry_identity(self) -> Self:
        if self.entry_id != f"cgtimeline:{self.entry_sha256}":
            raise ValueError("timeline identity does not bind its entry digest")
        return self


class TimelineHeadV1(StrictContractModel):
    """Mutable pointer to the last immutable target-scoped entry."""

    schema_version: Literal["controlgraph.timeline-head/v1"]
    target: TargetBinding
    sequence: PositiveSafeInteger
    entry_id: Identifier
    entry_sha256: Sha256Digest
    updated_at: UtcSecond

    @model_validator(mode="after")
    def validate_entry_identity(self) -> Self:
        if self.entry_id != f"cgtimeline:{self.entry_sha256}":
            raise ValueError("timeline head does not bind its entry digest")
        return self


class TimelinePageCommandV1(StrictContractModel):
    """Exclusive exact cursor for one configured target and audience."""

    schema_version: Literal["controlgraph.timeline-page-command/v1"]
    target: TargetBinding
    after_sequence: NonNegativeSafeInteger
    after_entry_sha256: Sha256Digest | None
    limit: Annotated[int, Field(ge=1, le=TIMELINE_MAX_PAGE_SIZE)]
    audience: TimelineAudience

    @model_validator(mode="after")
    def validate_cursor(self) -> Self:
        if (self.after_sequence == 0) != (self.after_entry_sha256 is None):
            raise ValueError("timeline cursor digest does not match its sequence")
        return self


class TimelineEntryProjectionV1(StrictContractModel):
    """Audience-filtered entry with no raw source record or signature bytes."""

    schema_version: Literal["controlgraph.timeline-entry-projection/v1"]
    audience: TimelineAudience
    entry_id: Identifier
    entry_sha256: Sha256Digest
    sequence: PositiveSafeInteger
    previous_entry_sha256: Sha256Digest | None
    target: TargetBinding
    source_schema_version: ContractVersion
    event_type: TimelineEventType
    evidence_class: TimelineEvidenceClass
    actor_role: TimelineActorRole
    actor_id: Identifier | None
    actor_data_class: TimelineAudience
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    occurred_at: UtcSecond
    recorded_at: UtcSecond
    correlations: Annotated[tuple[TimelineCorrelationV1, ...], Field(max_length=16)]
    payload_sha256: Sha256Digest
    policy_sha256: Sha256Digest
    raw_retention_days: Annotated[int, Field(ge=1, le=3_650)]
    signature: TimelineSignatureMetadataV1 | None
    verification_status: TimelineVerificationStatus
    terminal_classification: TimelineTerminalClassification
    display_fields: Annotated[tuple[TimelineDisplayFieldV1, ...], Field(max_length=16)]

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if self.entry_id != f"cgtimeline:{self.entry_sha256}":
            raise ValueError("timeline projection does not bind its entry digest")
        if (self.sequence == 1) != (self.previous_entry_sha256 is None):
            raise ValueError("timeline projection predecessor does not match its sequence")
        if self.actor_id is not None and (
            _AUDIENCE_ORDER[self.actor_data_class] > _AUDIENCE_ORDER[self.audience]
        ):
            raise ValueError("timeline projection exposes a restricted actor")
        correlation_keys = tuple(
            (item.kind.value, item.correlation_id) for item in self.correlations
        )
        display_names = tuple(item.name.value for item in self.display_fields)
        if (
            len(set(correlation_keys)) != len(correlation_keys)
            or correlation_keys != tuple(sorted(correlation_keys))
            or any(
                _AUDIENCE_ORDER[item.data_class] > _AUDIENCE_ORDER[self.audience]
                for item in self.correlations
            )
            or len(set(display_names)) != len(display_names)
            or display_names != tuple(sorted(display_names))
            or any(
                _AUDIENCE_ORDER[item.data_class] > _AUDIENCE_ORDER[self.audience]
                for item in self.display_fields
            )
        ):
            raise ValueError("timeline projection fields are not canonical for its audience")
        return self


class TimelinePageV1(StrictContractModel):
    """One omission-free page tied to a strongly read target head."""

    schema_version: Literal["controlgraph.timeline-page/v1"]
    command: TimelinePageCommandV1
    command_sha256: Sha256Digest
    entries: Annotated[
        tuple[TimelineEntryProjectionV1, ...],
        Field(max_length=TIMELINE_MAX_PAGE_SIZE),
    ]
    next_after_sequence: NonNegativeSafeInteger
    next_after_entry_sha256: Sha256Digest | None
    head_sequence: NonNegativeSafeInteger
    head_entry_sha256: Sha256Digest | None
    has_more: bool

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        command = self.command
        if self.command_sha256 != canonical_sha256(command):
            raise ValueError("timeline page does not bind its command")
        if len(self.entries) > command.limit or self.head_sequence < command.after_sequence:
            raise ValueError("timeline page bounds are invalid")
        if (self.head_sequence == 0) != (self.head_entry_sha256 is None):
            raise ValueError("timeline head digest does not match its sequence")
        expected_sequence = command.after_sequence + 1
        predecessor = command.after_entry_sha256
        for entry in self.entries:
            if (
                entry.audience is not command.audience
                or entry.target != command.target
                or entry.sequence != expected_sequence
                or entry.previous_entry_sha256 != predecessor
            ):
                raise ValueError("timeline page entries are not one contiguous target sequence")
            expected_sequence += 1
            predecessor = entry.entry_sha256
        expected_next_sha256: str | None
        if self.entries:
            expected_next_sequence = self.entries[-1].sequence
            expected_next_sha256 = self.entries[-1].entry_sha256
        else:
            expected_next_sequence = command.after_sequence
            expected_next_sha256 = command.after_entry_sha256
        if (
            self.next_after_sequence != expected_next_sequence
            or self.next_after_entry_sha256 != expected_next_sha256
            or self.next_after_sequence > self.head_sequence
            or self.has_more != (self.next_after_sequence < self.head_sequence)
        ):
            raise ValueError("timeline page next cursor is invalid")
        if self.head_sequence > command.after_sequence and not self.entries:
            raise ValueError("timeline page omitted an available entry")
        if (
            self.next_after_sequence == self.head_sequence
            and self.next_after_entry_sha256 != self.head_entry_sha256
        ):
            raise ValueError("timeline page does not terminate at the observed head")
        return self


class TimelineRawSourceV1(StrictContractModel):
    """A bounded canonical source record supplied with one timeline event."""

    schema_version: Literal["controlgraph.timeline-raw-source/v1"]
    raw_source_id: Identifier
    source_schema_version: ContractVersion
    target: TargetBinding
    evidence_class: TimelineEvidenceClass
    payload_sha256: Sha256Digest
    record_sha256: Sha256Digest
    canonical_record: CanonicalPayload
    signature_sha256: Sha256Digest | None

    @model_validator(mode="after")
    def validate_record_digest(self) -> Self:
        try:
            encoded = self.canonical_record.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("timeline raw source is not UTF-8") from error
        if hashlib.sha256(encoded).hexdigest() != self.record_sha256:
            raise ValueError("timeline raw source digest is invalid")
        return self


class TimelineRawEvidenceV1(StrictContractModel):
    """Immutable raw source plus its exact timeline and lifecycle bindings."""

    schema_version: Literal["controlgraph.timeline-raw-evidence/v1"]
    target: TargetBinding
    sequence: PositiveSafeInteger
    entry_id: Identifier
    entry_sha256: Sha256Digest
    source_id: Identifier
    raw_source: TimelineRawSourceV1
    recorded_at: UtcSecond
    expires_at: UtcSecond
    deletion_policy: Literal["EXPIRE_RAW_PRESERVE_DIGEST_V1"]

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if (
            self.entry_id != f"cgtimeline:{self.entry_sha256}"
            or self.target != self.raw_source.target
            or self.recorded_at >= self.expires_at
        ):
            raise ValueError("timeline raw evidence bindings are invalid")
        return self


class TimelineRawExportCommandV1(StrictContractModel):
    """Exclusive exact cursor for a separately authorized raw export."""

    schema_version: Literal["controlgraph.timeline-raw-export-command/v1"]
    target: TargetBinding
    after_sequence: NonNegativeSafeInteger
    after_entry_sha256: Sha256Digest | None
    limit: Annotated[int, Field(ge=1, le=TIMELINE_MAX_RAW_EXPORT_SIZE)]

    @model_validator(mode="after")
    def validate_cursor(self) -> Self:
        if (self.after_sequence == 0) != (self.after_entry_sha256 is None):
            raise ValueError("timeline raw export cursor digest does not match its sequence")
        return self


class TimelineRawExportItemV1(StrictContractModel):
    """One bounded raw record or its preserved policy-expiration evidence."""

    schema_version: Literal["controlgraph.timeline-raw-export-item/v1"]
    sequence: PositiveSafeInteger
    entry_id: Identifier
    entry_sha256: Sha256Digest
    previous_entry_sha256: Sha256Digest | None
    source_id: Identifier
    raw_source_id: Identifier
    source_schema_version: ContractVersion
    event_type: TimelineEventType
    evidence_class: TimelineEvidenceClass
    payload_sha256: Sha256Digest
    record_sha256: Sha256Digest
    signature_sha256: Sha256Digest | None
    recorded_at: UtcSecond
    expires_at: UtcSecond
    lifecycle_status: TimelineRawLifecycleStatus
    canonical_record: CanonicalPayload | None
    deletion_policy: Literal["EXPIRE_RAW_PRESERVE_DIGEST_V1"]

    @model_validator(mode="after")
    def validate_item(self) -> Self:
        if (
            self.entry_id != f"cgtimeline:{self.entry_sha256}"
            or (self.sequence == 1) != (self.previous_entry_sha256 is None)
            or (self.lifecycle_status is TimelineRawLifecycleStatus.AVAILABLE)
            != (self.canonical_record is not None)
        ):
            raise ValueError("timeline raw export item is invalid")
        if self.canonical_record is not None:
            try:
                encoded = self.canonical_record.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError("timeline raw export is not UTF-8") from error
            if hashlib.sha256(encoded).hexdigest() != self.record_sha256:
                raise ValueError("timeline raw export record digest is invalid")
        return self


class TimelineRawExportV1(StrictContractModel):
    """Omission-free raw export bound to one target, cursor, and evaluation time."""

    schema_version: Literal["controlgraph.timeline-raw-export/v1"]
    command: TimelineRawExportCommandV1
    command_sha256: Sha256Digest
    evaluated_at: UtcSecond
    entries: Annotated[
        tuple[TimelineRawExportItemV1, ...],
        Field(max_length=TIMELINE_MAX_RAW_EXPORT_SIZE),
    ]
    next_after_sequence: NonNegativeSafeInteger
    next_after_entry_sha256: Sha256Digest | None
    head_sequence: NonNegativeSafeInteger
    head_entry_sha256: Sha256Digest | None
    has_more: bool

    @model_validator(mode="after")
    def validate_export(self) -> Self:
        command = self.command
        if self.command_sha256 != canonical_sha256(command):
            raise ValueError("timeline raw export does not bind its command")
        if len(self.entries) > command.limit or self.head_sequence < command.after_sequence:
            raise ValueError("timeline raw export bounds are invalid")
        if (self.head_sequence == 0) != (self.head_entry_sha256 is None):
            raise ValueError("timeline raw export head digest is invalid")
        expected_sequence = command.after_sequence + 1
        predecessor = command.after_entry_sha256
        for item in self.entries:
            if item.sequence != expected_sequence or item.previous_entry_sha256 != predecessor:
                raise ValueError("timeline raw export is not contiguous")
            if (
                item.lifecycle_status is TimelineRawLifecycleStatus.AVAILABLE
                and self.evaluated_at >= item.expires_at
            ) or (
                item.lifecycle_status is TimelineRawLifecycleStatus.EXPIRED_BY_POLICY
                and self.evaluated_at < item.expires_at
            ):
                raise ValueError("timeline raw lifecycle status is invalid")
            expected_sequence += 1
            predecessor = item.entry_sha256
        next_digest: str | None
        if self.entries:
            next_sequence = self.entries[-1].sequence
            next_digest = self.entries[-1].entry_sha256
        else:
            next_sequence = command.after_sequence
            next_digest = command.after_entry_sha256
        if (
            self.next_after_sequence != next_sequence
            or self.next_after_entry_sha256 != next_digest
            or self.has_more != (next_sequence < self.head_sequence)
            or (self.head_sequence > command.after_sequence and not self.entries)
            or (
                next_sequence == self.head_sequence
                and next_digest != self.head_entry_sha256
            )
        ):
            raise ValueError("timeline raw export cursor is invalid")
        return self


class TimelineStorageDocumentV1(StrictContractModel):
    """Canonical Firestore wrapper for timeline records."""

    schema_version: Literal["controlgraph.timeline-storage-document/v1"]
    record_kind: TimelineStorageKind
    logical_id: Identifier
    revision: NonNegativeSafeInteger
    mutation_id: Identifier
    canonical_payload: CanonicalPayload
    payload_sha256: Sha256Digest


def _document_digest(domain: str, *parts: str) -> str:
    material = "\0".join((domain, *parts)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def timeline_target_sha256(target: TargetBinding) -> str:
    if type(target) is not TargetBinding:
        raise TypeError("timeline target must be exact")
    return canonical_sha256(target)


def standard_timeline_evidence_policy_set(
    target: TargetBinding,
    *,
    raw_retention_days: int = TIMELINE_DEFAULT_RAW_RETENTION_DAYS,
) -> TimelineEvidencePolicySetV1:
    """Build the closed policy registry used by the timeline application boundary."""

    if type(target) is not TargetBinding or type(raw_retention_days) is not int:
        raise TypeError("timeline evidence policy configuration must be exact")
    audiences = tuple(TimelineAudience)
    policies = tuple(
        TimelineEvidencePolicyV1(
            schema_version=TIMELINE_EVIDENCE_POLICY_V1,
            evidence_class=evidence_class,
            writer_roles=(TimelineActorRole.COORDINATOR,),
            summary_audiences=audiences,
            raw_read_audience=TimelineAudience.RESTRICTED,
            raw_export_audience=TimelineAudience.RESTRICTED,
            redaction_policy="ALLOWLIST_AND_SECRET_SCAN_V1",
            raw_retention_days=raw_retention_days,
            deletion_policy="EXPIRE_RAW_PRESERVE_DIGEST_V1",
            deletion_evidence_required=True,
        )
        for evidence_class in sorted(TimelineEvidenceClass, key=lambda item: item.value)
    )
    return TimelineEvidencePolicySetV1(
        schema_version=TIMELINE_EVIDENCE_POLICY_SET_V1,
        target=target,
        policies=policies,
    )


def timeline_head_logical_id(target: TargetBinding) -> str:
    return f"cgtimeline-head:{timeline_target_sha256(target)}"


def timeline_head_document_id(target: TargetBinding) -> str:
    return _document_digest(
        "controlgraph.timeline-head-document/v1",
        timeline_target_sha256(target),
    )


def timeline_identity_logical_id(target: TargetBinding, source_id: str) -> str:
    if type(source_id) is not str or not source_id:
        raise TypeError("timeline source identity must be exact")
    digest = _document_digest(
        "controlgraph.timeline-source-logical/v1",
        timeline_target_sha256(target),
        source_id,
    )
    return f"cgtimeline-source:{digest}"


def timeline_identity_document_id(target: TargetBinding, source_id: str) -> str:
    return _document_digest(
        "controlgraph.timeline-identity-document/v1",
        timeline_target_sha256(target),
        timeline_identity_logical_id(target, source_id),
    )


def timeline_entry_logical_id(target: TargetBinding, sequence: int) -> str:
    if type(sequence) is not int or not 1 <= sequence <= 2**53 - 1:
        raise ValueError("timeline sequence is invalid")
    digest = _document_digest(
        "controlgraph.timeline-entry-logical/v1",
        timeline_target_sha256(target),
        str(sequence),
    )
    return f"cgtimeline-sequence:{digest}"


def timeline_entry_document_id(target: TargetBinding, sequence: int) -> str:
    return _document_digest(
        "controlgraph.timeline-entry-document/v1",
        timeline_target_sha256(target),
        timeline_entry_logical_id(target, sequence),
    )


def timeline_raw_document_id(target: TargetBinding, source_id: str) -> str:
    if type(source_id) is not str or not source_id:
        raise TypeError("timeline raw source identity must be exact")
    return _document_digest(
        "controlgraph.timeline-raw-document/v1",
        timeline_target_sha256(target),
        source_id,
    )


def timeline_entry(
    event: TimelineEventV1,
    *,
    sequence: int,
    previous_entry_sha256: str | None,
    recorded_at: str,
) -> TimelineEntryV1:
    if type(event) is not TimelineEventV1:
        raise TypeError("timeline event must be exact")
    content = TimelineEntryContentV1(
        schema_version=TIMELINE_ENTRY_CONTENT_V1,
        target=event.target,
        sequence=sequence,
        previous_entry_sha256=previous_entry_sha256,
        recorded_at=recorded_at,
        event=event,
    )
    digest = canonical_sha256(content)
    return TimelineEntryV1(
        schema_version=TIMELINE_ENTRY_V1,
        entry_id=f"cgtimeline:{digest}",
        entry_sha256=digest,
        content=content,
    )


__all__ = [
    "TIMELINE_CORRELATION_V1",
    "TIMELINE_DEFAULT_RAW_RETENTION_DAYS",
    "TIMELINE_DISPLAY_FIELD_V1",
    "TIMELINE_ENTRY_COLLECTION",
    "TIMELINE_ENTRY_CONTENT_V1",
    "TIMELINE_ENTRY_PROJECTION_V1",
    "TIMELINE_ENTRY_V1",
    "TIMELINE_EVENT_V1",
    "TIMELINE_EVIDENCE_POLICY_SET_V1",
    "TIMELINE_EVIDENCE_POLICY_V1",
    "TIMELINE_HEAD_COLLECTION",
    "TIMELINE_HEAD_V1",
    "TIMELINE_IDENTITY_COLLECTION",
    "TIMELINE_IDENTITY_V1",
    "TIMELINE_MAX_PAGE_SIZE",
    "TIMELINE_MAX_RAW_EXPORT_SIZE",
    "TIMELINE_PAGE_COMMAND_V1",
    "TIMELINE_PAGE_V1",
    "TIMELINE_RAW_COLLECTION",
    "TIMELINE_RAW_EVIDENCE_V1",
    "TIMELINE_RAW_EXPORT_COMMAND_V1",
    "TIMELINE_RAW_EXPORT_ITEM_V1",
    "TIMELINE_RAW_EXPORT_V1",
    "TIMELINE_RAW_SOURCE_V1",
    "TIMELINE_SIGNATURE_METADATA_V1",
    "TIMELINE_STORAGE_DOCUMENT_V1",
    "TimelineActorRole",
    "TimelineAudience",
    "TimelineCorrelationKind",
    "TimelineCorrelationV1",
    "TimelineDisplayFieldName",
    "TimelineDisplayFieldV1",
    "TimelineEntryContentV1",
    "TimelineEntryProjectionV1",
    "TimelineEntryV1",
    "TimelineEventType",
    "TimelineEventV1",
    "TimelineEvidenceClass",
    "TimelineEvidencePolicySetV1",
    "TimelineEvidencePolicyV1",
    "TimelineHeadV1",
    "TimelineIdentityV1",
    "TimelinePageCommandV1",
    "TimelinePageV1",
    "TimelineRawEvidenceV1",
    "TimelineRawExportCommandV1",
    "TimelineRawExportItemV1",
    "TimelineRawExportV1",
    "TimelineRawLifecycleStatus",
    "TimelineRawSourceV1",
    "TimelineSignatureMetadataV1",
    "TimelineStorageDocumentV1",
    "TimelineStorageKind",
    "TimelineTerminalClassification",
    "TimelineVerificationStatus",
    "standard_timeline_evidence_policy_set",
    "timeline_entry",
    "timeline_entry_document_id",
    "timeline_entry_logical_id",
    "timeline_head_document_id",
    "timeline_head_logical_id",
    "timeline_identity_document_id",
    "timeline_identity_logical_id",
    "timeline_raw_document_id",
    "timeline_target_sha256",
]
