"""Bounded, redacted contracts for one immutable public acceptance replay."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Identifier,
    Percent,
    PositiveSafeInteger,
    Sha256Digest,
    ShortText,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import canonical_sha256

PUBLIC_REPLAY_SEED_V1: Final = "controlgraph.public-replay-seed/v1"
PUBLIC_REPLAY_IMAGE_V1: Final = "controlgraph.public-replay-image/v1"
PUBLIC_REPLAY_CASE_V1: Final = "controlgraph.public-replay-case/v1"
PUBLIC_REPLAY_TRAFFIC_V1: Final = "controlgraph.public-replay-traffic/v1"
PUBLIC_REPLAY_CITATION_V1: Final = "controlgraph.public-replay-citation/v1"
PUBLIC_REPLAY_FINDING_V1: Final = "controlgraph.public-replay-finding/v1"
PUBLIC_REPLAY_TOOL_CALL_V1: Final = "controlgraph.public-replay-tool-call/v1"
PUBLIC_REPLAY_ADVISOR_V1: Final = "controlgraph.public-replay-advisor/v1"
PUBLIC_REPLAY_TIMELINE_ENTRY_V1: Final = "controlgraph.public-replay-timeline-entry/v1"
PUBLIC_REPLAY_TIMELINE_V1: Final = "controlgraph.public-replay-timeline/v1"
PUBLIC_REPLAY_AUTHORITY_ADVANCED_V1: Final = (
    "controlgraph.public-replay-authority-advanced/v1"
)
PUBLIC_REPLAY_STALE_DENIAL_V1: Final = "controlgraph.public-replay-stale-denial/v1"
PUBLIC_REPLAY_TARGET_UNCHANGED_V1: Final = "controlgraph.public-replay-target-unchanged/v1"
PUBLIC_REPLAY_ADVISOR_VALIDATED_V1: Final = "controlgraph.public-replay-advisor-validated/v1"
PUBLIC_REPLAY_RECOVERY_VERIFIED_V1: Final = "controlgraph.public-replay-recovery-verified/v1"
PUBLIC_REPLAY_TIMELINE_COMMITTED_V1: Final = "controlgraph.public-replay-timeline-committed/v1"
PUBLIC_REPLAY_EVENT_V1: Final = "controlgraph.public-replay-event/v1"
PUBLIC_REPLAY_EVENT_ENVELOPE_V1: Final = "controlgraph.public-replay-event-envelope/v1"
PUBLIC_REPLAY_PAYLOAD_V1: Final = "controlgraph.public-replay-payload/v1"
PUBLIC_REPLAY_ENVELOPE_V1: Final = "controlgraph.public-replay-envelope/v1"

MAX_PUBLIC_REPLAY_JSON_BYTES: Final = 65_536
MAX_PUBLIC_REPLAY_GZIP_BYTES: Final = 18_432
MAX_PUBLIC_REPLAY_BASE64_BYTES: Final = 24_576

GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
ImageReference = Annotated[
    str,
    StringConstraints(
        min_length=100,
        max_length=512,
        pattern=(
            r"^us-central1-docker\.pkg\.dev/controlgraph-canary-[a-z0-9]{6,10}/"
            r"controlgraph-canary/[a-z][a-z0-9-]*@sha256:[0-9a-f]{64}$"
        ),
    ),
]

_IMAGE_REFERENCE = re.compile(
    r"^us-central1-docker\.pkg\.dev/(?P<project>controlgraph-canary-[a-z0-9]{6,10})/"
    r"controlgraph-canary/(?P<component>[a-z][a-z0-9-]*)@sha256:"
    r"(?P<digest>[0-9a-f]{64})$"
)


class PublicReplayImageComponent(StrEnum):
    CONTROLLER = "controller"
    ADVISOR = "advisor"
    CONSOLE = "console"
    REFERENCE_STABLE = "reference-stable"
    REFERENCE_CANDIDATE = "reference-candidate"


class PublicReplayEventKind(StrEnum):
    AUTHORITY_ADVANCED = "AUTHORITY_ADVANCED"
    STALE_WORK_DENIED = "STALE_WORK_DENIED"
    TARGET_UNCHANGED = "TARGET_UNCHANGED"
    ADVISOR_VALIDATED = "ADVISOR_VALIDATED"
    RECOVERY_VERIFIED = "RECOVERY_VERIFIED"
    TIMELINE_COMMITTED = "TIMELINE_COMMITTED"


class PublicReplayCaseKind(StrEnum):
    TARGET_RESET = "TARGET_RESET"
    HEALTHY_PROMOTION = "HEALTHY_PROMOTION"
    UNHEALTHY_STABLE_RECOVERY = "UNHEALTHY_STABLE_RECOVERY"
    REVOCATION_STALE_DENIAL = "REVOCATION_STALE_DENIAL"
    INDEPENDENT_VERIFIER_PROBE = "INDEPENDENT_VERIFIER_PROBE"
    AMBIGUITY_CLASSIFICATION = "AMBIGUITY_CLASSIFICATION"
    TIMELINE_CONSOLE_READ = "TIMELINE_CONSOLE_READ"
    BOUNDED_ADVISOR = "BOUNDED_ADVISOR"


class PublicReplayTimelineEventType(StrEnum):
    AUTHORITY_EPOCH_ADVANCED = "AUTHORITY_EPOCH_ADVANCED"
    MUTATION_APPLIED = "MUTATION_APPLIED"
    MUTATION_DENIED = "MUTATION_DENIED"
    MODEL_ASSISTANCE_RECORDED = "MODEL_ASSISTANCE_RECORDED"


class PublicReplayImageV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-image/v1"]
    component: PublicReplayImageComponent
    reference: ImageReference

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        match = _IMAGE_REFERENCE.fullmatch(self.reference)
        if match is None or match.group("component") != self.component.value:
            raise ValueError("public replay image component is not bound to its reference")
        return self


class PublicReplayCaseV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-case/v1"]
    sequence: PositiveSafeInteger
    kind: PublicReplayCaseKind
    case_sha256: Sha256Digest


class PublicReplayTrafficV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-traffic/v1"]
    stable_percent: Percent
    candidate_percent: Percent
    target_configuration_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_total(self) -> Self:
        if self.stable_percent + self.candidate_percent != 100:
            raise ValueError("public replay traffic must total 100 percent")
        return self


class PublicReplayCitationV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-citation/v1"]
    evidence_kind: Literal["root", "target", "health", "receipt", "timeline", "verifier"]
    evidence_id: Identifier
    source_sha256: Sha256Digest


class PublicReplayFindingV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-finding/v1"]
    statement: ShortText
    citations: Annotated[
        tuple[PublicReplayCitationV1, ...],
        Field(min_length=1, max_length=8),
    ]

    @model_validator(mode="after")
    def validate_citations(self) -> Self:
        values = tuple(
            (item.evidence_kind, item.evidence_id, item.source_sha256)
            for item in self.citations
        )
        if len(set(values)) != len(values):
            raise ValueError("public replay finding citations must be unique")
        return self


class PublicReplayToolCallV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-tool-call/v1"]
    sequence: PositiveSafeInteger
    tool_id: Literal[
        "read_root_summary",
        "read_target_summary",
        "read_health_summary",
        "read_receipt_summary",
        "read_timeline_summary",
        "read_verifier_summary",
    ]
    input_sha256: Sha256Digest
    output_sha256: Sha256Digest
    status: Literal["succeeded"]


class PublicReplayAdvisorV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-advisor/v1"]
    model_id: Literal["gemini-3.5-flash"]
    model_location: Literal["global"]
    prompt_version: Literal["controlgraph.rollout-advisor-prompt/v2"]
    response_sha256: Sha256Digest
    audit_sha256: Sha256Digest
    registry_sha256: Sha256Digest
    snapshot_sha256: Sha256Digest
    structured_output_sha256: Sha256Digest
    validation: Literal["accepted"]
    authority_effect: Literal["none"]
    deterministic_health_override: Literal[False]
    operator_review_required: Literal[True]
    requested_operator_action: Literal[
        "wait",
        "collect_approved_diagnostics",
        "request_revocation",
        "request_captured_stable_recovery",
        "request_new_operator_approved_rollout",
        "manual_review",
    ]
    confidence_basis_points: Annotated[int, Field(ge=0, le=10_000)]
    findings: Annotated[tuple[PublicReplayFindingV1, ...], Field(min_length=1, max_length=8)]
    tool_calls: Annotated[
        tuple[PublicReplayToolCallV1, ...],
        Field(min_length=6, max_length=6),
    ]
    replayed_without_model_call: Literal[True]

    @model_validator(mode="after")
    def validate_advisory_only_result(self) -> Self:
        if tuple(item.sequence for item in self.tool_calls) != tuple(
            range(1, len(self.tool_calls) + 1)
        ) or {item.tool_id for item in self.tool_calls} != {
            "read_root_summary",
            "read_target_summary",
            "read_health_summary",
            "read_receipt_summary",
            "read_timeline_summary",
            "read_verifier_summary",
        }:
            raise ValueError("public replay advisor tool calls are not contiguous")
        citation_kinds = {
            citation.evidence_kind
            for finding in self.findings
            for citation in finding.citations
        }
        if not {"receipt", "timeline"}.issubset(citation_kinds) or not citation_kinds.intersection(
            {"target", "verifier"}
        ):
            raise ValueError("public replay advisor citations are incomplete")
        return self


class PublicReplayTimelineEntryV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-timeline-entry/v1"]
    sequence: PositiveSafeInteger
    entry_sha256: Sha256Digest
    event_type: PublicReplayTimelineEventType
    occurred_at: UtcSecond
    verification_status: Literal["NOT_APPLICABLE", "VERIFIED"]


class PublicReplayTimelineV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-timeline/v1"]
    head_sequence: PositiveSafeInteger
    head_entry_sha256: Sha256Digest
    entry_count: PositiveSafeInteger
    page_count: PositiveSafeInteger
    page_set_sha256: Sha256Digest
    entries: Annotated[
        tuple[PublicReplayTimelineEntryV1, ...],
        Field(min_length=4, max_length=8),
    ]

    @model_validator(mode="after")
    def validate_commitments(self) -> Self:
        sequences = tuple(item.sequence for item in self.entries)
        if (
            self.entry_count > self.head_sequence
            or len(self.entries) > self.entry_count
            or sequences != tuple(sorted(set(sequences)))
            or sequences[-1] > self.head_sequence
            or len({item.entry_sha256 for item in self.entries}) != len(self.entries)
        ):
            raise ValueError("public replay timeline commitments are invalid")
        kinds = {item.event_type for item in self.entries}
        if set(PublicReplayTimelineEventType) != kinds:
            raise ValueError("public replay timeline commitments are incomplete")
        return self


class PublicReplayAuthorityAdvancedV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-authority-advanced/v1"]
    previous_epoch: PositiveSafeInteger
    new_epoch: PositiveSafeInteger
    cause: Literal["OPERATOR_REVOCATION"]
    transition_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        if self.new_epoch != self.previous_epoch + 1:
            raise ValueError("public replay authority transition must advance once")
        return self


class PublicReplayStaleDenialV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-stale-denial/v1"]
    work_epoch: PositiveSafeInteger
    current_authority_epoch: PositiveSafeInteger
    outcome: Literal["DENIED"]
    reason_code: Literal["EPOCH_MISMATCH"]
    receipt_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_epoch(self) -> Self:
        if self.current_authority_epoch != self.work_epoch + 1:
            raise ValueError("public replay stale denial is not an N to N+1 denial")
        return self


class PublicReplayTargetUnchangedV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-target-unchanged/v1"]
    before_denial: PublicReplayTrafficV1
    after_denial: PublicReplayTrafficV1

    @model_validator(mode="after")
    def validate_unchanged_canary(self) -> Self:
        if (
            self.before_denial != self.after_denial
            or self.before_denial.stable_percent != 90
            or self.before_denial.candidate_percent != 10
        ):
            raise ValueError("public replay denial target must remain at exact 90/10")
        return self


class PublicReplayAdvisorValidatedV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-advisor-validated/v1"]
    advisor: PublicReplayAdvisorV1


class PublicReplayRecoveryVerifiedV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-recovery-verified/v1"]
    outcome: Literal["VERIFIED"]
    receipt_sha256: Sha256Digest
    traffic: PublicReplayTrafficV1

    @model_validator(mode="after")
    def validate_stable_recovery(self) -> Self:
        if self.traffic.stable_percent != 100 or self.traffic.candidate_percent != 0:
            raise ValueError("public replay recovery must restore exact 100/0 traffic")
        return self


class PublicReplayTimelineCommittedV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-timeline-committed/v1"]
    timeline: PublicReplayTimelineV1


type PublicReplayEventDetailsV1 = (
    PublicReplayAuthorityAdvancedV1
    | PublicReplayStaleDenialV1
    | PublicReplayTargetUnchangedV1
    | PublicReplayAdvisorValidatedV1
    | PublicReplayRecoveryVerifiedV1
    | PublicReplayTimelineCommittedV1
)


class PublicReplaySeedV1(StrictContractModel):
    """Safe accepted observations retained for deterministic public export."""

    schema_version: Literal["controlgraph.public-replay-seed/v1"]
    authority_occurred_at: UtcSecond
    denial_occurred_at: UtcSecond
    unchanged_observed_at: UtcSecond
    advisor_requested_at: UtcSecond
    recovery_occurred_at: UtcSecond
    timeline_observed_at: UtcSecond
    authority: PublicReplayAuthorityAdvancedV1
    denial: PublicReplayStaleDenialV1
    unchanged: PublicReplayTargetUnchangedV1
    advisor: PublicReplayAdvisorValidatedV1
    recovery: PublicReplayRecoveryVerifiedV1
    timeline: PublicReplayTimelineCommittedV1

    @model_validator(mode="after")
    def validate_flow(self) -> Self:
        if (
            self.authority.previous_epoch != self.denial.work_epoch
            or self.authority.new_epoch != self.denial.current_authority_epoch
            or not (
                self.authority_occurred_at
                <= self.denial_occurred_at
                <= self.unchanged_observed_at
                <= self.advisor_requested_at
                <= self.recovery_occurred_at
                <= self.timeline_observed_at
            )
        ):
            raise ValueError("public replay seed flow is inconsistent")
        return self


class PublicReplayEventV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-event/v1"]
    sequence: PositiveSafeInteger
    kind: PublicReplayEventKind
    occurred_at: UtcSecond
    previous_event_sha256: Sha256Digest | None
    details: PublicReplayEventDetailsV1

    @model_validator(mode="after")
    def validate_details(self) -> Self:
        expected = {
            PublicReplayEventKind.AUTHORITY_ADVANCED: PublicReplayAuthorityAdvancedV1,
            PublicReplayEventKind.STALE_WORK_DENIED: PublicReplayStaleDenialV1,
            PublicReplayEventKind.TARGET_UNCHANGED: PublicReplayTargetUnchangedV1,
            PublicReplayEventKind.ADVISOR_VALIDATED: PublicReplayAdvisorValidatedV1,
            PublicReplayEventKind.RECOVERY_VERIFIED: PublicReplayRecoveryVerifiedV1,
            PublicReplayEventKind.TIMELINE_COMMITTED: PublicReplayTimelineCommittedV1,
        }
        if type(self.details) is not expected[self.kind]:
            raise ValueError("public replay event kind does not match its details")
        if (self.sequence == 1) != (self.previous_event_sha256 is None):
            raise ValueError("public replay event predecessor is invalid")
        return self


class PublicReplayEventEnvelopeV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-event-envelope/v1"]
    event: PublicReplayEventV1
    event_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.event_sha256 != canonical_sha256(self.event):
            raise ValueError("public replay event digest is invalid")
        return self


class PublicReplayPayloadV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-payload/v1"]
    source_commit: GitCommit
    acceptance_manifest_sha256: Sha256Digest
    acceptance_run_id: Identifier
    acceptance_status: Literal["PASSED"]
    evidence_binding_complete: Literal[True]
    accepted_at: UtcSecond
    images: Annotated[tuple[PublicReplayImageV1, ...], Field(min_length=5, max_length=5)]
    cases: Annotated[tuple[PublicReplayCaseV1, ...], Field(min_length=8, max_length=8)]
    events: Annotated[
        tuple[PublicReplayEventEnvelopeV1, ...],
        Field(min_length=6, max_length=6),
    ]
    event_chain_head_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        if tuple(item.component for item in self.images) != tuple(PublicReplayImageComponent):
            raise ValueError("public replay images are not in canonical component order")
        image_matches = [_IMAGE_REFERENCE.fullmatch(item.reference) for item in self.images]
        if (
            any(match is None for match in image_matches)
            or len({item.reference for item in self.images}) != len(self.images)
            or len({match.group("project") for match in image_matches if match is not None}) != 1
            or len({match.group("digest") for match in image_matches if match is not None}) != 5
        ):
            raise ValueError("public replay image bindings are invalid")
        if (
            tuple(item.sequence for item in self.cases) != tuple(range(1, 9))
            or tuple(item.kind for item in self.cases) != tuple(PublicReplayCaseKind)
            or len({item.case_sha256 for item in self.cases}) != len(self.cases)
        ):
            raise ValueError("public replay case commitments are invalid")
        if tuple(item.event.kind for item in self.events) != tuple(PublicReplayEventKind):
            raise ValueError("public replay events are not in canonical order")
        predecessor: str | None = None
        previous_occurred_at: str | None = None
        for sequence, item in enumerate(self.events, start=1):
            if (
                item.event.sequence != sequence
                or item.event.previous_event_sha256 != predecessor
                or (
                    previous_occurred_at is not None
                    and item.event.occurred_at < previous_occurred_at
                )
                or item.event.occurred_at > self.accepted_at
            ):
                raise ValueError("public replay event chain is invalid")
            predecessor = item.event_sha256
            previous_occurred_at = item.event.occurred_at
        if predecessor != self.event_chain_head_sha256:
            raise ValueError("public replay chain head is invalid")
        authority = self.events[0].event.details
        denial = self.events[1].event.details
        if (
            not isinstance(authority, PublicReplayAuthorityAdvancedV1)
            or not isinstance(denial, PublicReplayStaleDenialV1)
            or authority.previous_epoch != denial.work_epoch
            or authority.new_epoch != denial.current_authority_epoch
        ):
            raise ValueError("public replay authority and denial are inconsistent")
        return self


class PublicReplayEnvelopeV1(StrictContractModel):
    schema_version: Literal["controlgraph.public-replay-envelope/v1"]
    payload: PublicReplayPayloadV1
    payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_payload_digest(self) -> Self:
        if self.payload_sha256 != canonical_sha256(self.payload):
            raise ValueError("public replay payload digest is invalid")
        return self


def create_public_replay_payload(
    *,
    source_commit: str,
    acceptance_manifest_sha256: str,
    acceptance_run_id: str,
    accepted_at: str,
    images: tuple[PublicReplayImageV1, ...],
    cases: tuple[PublicReplayCaseV1, ...],
    seed: PublicReplaySeedV1,
) -> PublicReplayPayloadV1:
    """Create the only supported chronological event chain from one safe seed."""

    event_values: tuple[tuple[PublicReplayEventKind, str, PublicReplayEventDetailsV1], ...] = (
        (PublicReplayEventKind.AUTHORITY_ADVANCED, seed.authority_occurred_at, seed.authority),
        (PublicReplayEventKind.STALE_WORK_DENIED, seed.denial_occurred_at, seed.denial),
        (PublicReplayEventKind.TARGET_UNCHANGED, seed.unchanged_observed_at, seed.unchanged),
        (PublicReplayEventKind.ADVISOR_VALIDATED, seed.advisor_requested_at, seed.advisor),
        (PublicReplayEventKind.RECOVERY_VERIFIED, seed.recovery_occurred_at, seed.recovery),
        (PublicReplayEventKind.TIMELINE_COMMITTED, seed.timeline_observed_at, seed.timeline),
    )
    predecessor: str | None = None
    events: list[PublicReplayEventEnvelopeV1] = []
    for sequence, (kind, occurred_at, details) in enumerate(event_values, start=1):
        event = PublicReplayEventV1(
            schema_version=PUBLIC_REPLAY_EVENT_V1,
            sequence=sequence,
            kind=kind,
            occurred_at=occurred_at,
            previous_event_sha256=predecessor,
            details=details,
        )
        predecessor = canonical_sha256(event)
        events.append(
            PublicReplayEventEnvelopeV1(
                schema_version=PUBLIC_REPLAY_EVENT_ENVELOPE_V1,
                event=event,
                event_sha256=predecessor,
            )
        )
    assert predecessor is not None
    return PublicReplayPayloadV1(
        schema_version=PUBLIC_REPLAY_PAYLOAD_V1,
        source_commit=source_commit,
        acceptance_manifest_sha256=acceptance_manifest_sha256,
        acceptance_run_id=acceptance_run_id,
        acceptance_status="PASSED",
        evidence_binding_complete=True,
        accepted_at=accepted_at,
        images=images,
        cases=cases,
        events=tuple(events),
        event_chain_head_sha256=predecessor,
    )


def create_public_replay_envelope(payload: PublicReplayPayloadV1) -> PublicReplayEnvelopeV1:
    """Bind one validated replay payload to its canonical content digest."""

    return PublicReplayEnvelopeV1(
        schema_version=PUBLIC_REPLAY_ENVELOPE_V1,
        payload=payload,
        payload_sha256=canonical_sha256(payload),
    )


__all__ = [
    "MAX_PUBLIC_REPLAY_BASE64_BYTES",
    "MAX_PUBLIC_REPLAY_GZIP_BYTES",
    "MAX_PUBLIC_REPLAY_JSON_BYTES",
    "PUBLIC_REPLAY_ENVELOPE_V1",
    "PUBLIC_REPLAY_EVENT_ENVELOPE_V1",
    "PUBLIC_REPLAY_EVENT_V1",
    "PUBLIC_REPLAY_PAYLOAD_V1",
    "PUBLIC_REPLAY_SEED_V1",
    "PublicReplayAdvisorV1",
    "PublicReplayAdvisorValidatedV1",
    "PublicReplayAuthorityAdvancedV1",
    "PublicReplayCaseKind",
    "PublicReplayCaseV1",
    "PublicReplayCitationV1",
    "PublicReplayEnvelopeV1",
    "PublicReplayEventEnvelopeV1",
    "PublicReplayEventKind",
    "PublicReplayEventV1",
    "PublicReplayFindingV1",
    "PublicReplayImageComponent",
    "PublicReplayImageV1",
    "PublicReplayPayloadV1",
    "PublicReplayRecoveryVerifiedV1",
    "PublicReplaySeedV1",
    "PublicReplayStaleDenialV1",
    "PublicReplayTargetUnchangedV1",
    "PublicReplayTimelineCommittedV1",
    "PublicReplayTimelineEntryV1",
    "PublicReplayTimelineEventType",
    "PublicReplayTimelineV1",
    "PublicReplayToolCallV1",
    "PublicReplayTrafficV1",
    "create_public_replay_envelope",
    "create_public_replay_payload",
]
