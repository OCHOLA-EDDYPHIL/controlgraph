"""Closed version 1 contracts for the Cloud Run canary domain."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import Field, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    Base64Url,
    BoundedText,
    CloudRunName,
    Identifier,
    KeyVersionResource,
    NonNegativeSafeInteger,
    OpaqueToken,
    Percent,
    PositiveSafeInteger,
    ProjectId,
    Region,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)

TARGET_BINDING_V1: Final = "controlgraph.target-binding/v1"
STABLE_SNAPSHOT_V1: Final = "controlgraph.stable-snapshot/v1"
ROLLOUT_ROOT_V1: Final = "controlgraph.rollout-root/v1"
EPOCH_AUTHORITY_V1: Final = "controlgraph.epoch-authority/v1"
CAPABILITY_CLAIMS_V1: Final = "controlgraph.capability-claims/v1"
SIGNED_CAPABILITY_V1: Final = "controlgraph.signed-capability/v1"
MUTATION_INTENT_V1: Final = "controlgraph.mutation-intent/v1"
TASK_REQUEST_V1: Final = "controlgraph.task-request/v1"
EXECUTION_RECEIPT_V1: Final = "controlgraph.execution-receipt/v1"
HEALTH_INPUT_V1: Final = "controlgraph.health-input/v1"
RECOVERY_PLAN_V1: Final = "controlgraph.recovery-plan/v1"
EVIDENCE_EVENT_V1: Final = "controlgraph.evidence-event/v1"


class CapabilityAction(StrEnum):
    APPLY_CANARY = "APPLY_CANARY_V1"
    PROMOTE_CANDIDATE = "PROMOTE_CANDIDATE_V1"
    RECOVER_STABLE = "RECOVER_STABLE_V1"


class EpochChangeCause(StrEnum):
    ROOT_CREATED = "ROOT_CREATED"
    OPERATOR_REVOCATION = "OPERATOR_REVOCATION"
    SUPERSESSION = "SUPERSESSION"
    RECOVERY = "RECOVERY"


class ReceiptOutcome(StrEnum):
    CLAIMED = "CLAIMED"
    DENIED = "DENIED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"


class ReasonCode(StrEnum):
    CONTRACT_INVALID = "CONTRACT_INVALID"
    CONTRACT_VERSION_UNSUPPORTED = "CONTRACT_VERSION_UNSUPPORTED"
    CALLER_UNAUTHENTICATED = "CALLER_UNAUTHENTICATED"
    CALLER_UNAUTHORIZED = "CALLER_UNAUTHORIZED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    KEY_VERSION_UNTRUSTED = "KEY_VERSION_UNTRUSTED"
    CAPABILITY_EXPIRED = "CAPABILITY_EXPIRED"
    CAPABILITY_NOT_YET_VALID = "CAPABILITY_NOT_YET_VALID"
    CLAIM_BINDING_MISMATCH = "CLAIM_BINDING_MISMATCH"
    TARGET_BINDING_MISMATCH = "TARGET_BINDING_MISMATCH"
    LINEAGE_INVALID = "LINEAGE_INVALID"
    SCOPE_AMPLIFICATION = "SCOPE_AMPLIFICATION"
    AUTHORITY_UNAVAILABLE = "AUTHORITY_UNAVAILABLE"
    EPOCH_MISMATCH = "EPOCH_MISMATCH"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    RECEIPT_IN_PROGRESS = "RECEIPT_IN_PROGRESS"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
    PROVIDER_PRECONDITION_FAILED = "PROVIDER_PRECONDITION_FAILED"
    PROVIDER_REQUEST_REJECTED = "PROVIDER_REQUEST_REJECTED"
    PROVIDER_OUTCOME_AMBIGUOUS = "PROVIDER_OUTCOME_AMBIGUOUS"
    TRANSITION_INVALID = "TRANSITION_INVALID"
    POLICY_UNHEALTHY = "POLICY_UNHEALTHY"


class EvidenceKind(StrEnum):
    ROOT_CREATED = "ROOT_CREATED"
    CAPABILITY_ISSUED = "CAPABILITY_ISSUED"
    EPOCH_ADVANCED = "EPOCH_ADVANCED"
    DELIVERY_AUTHENTICATED = "DELIVERY_AUTHENTICATED"
    CAPABILITY_VERIFIED = "CAPABILITY_VERIFIED"
    RECEIPT_CLAIMED = "RECEIPT_CLAIMED"
    MUTATION_APPLIED = "MUTATION_APPLIED"
    TARGET_VERIFIED = "TARGET_VERIFIED"
    EXECUTION_DENIED = "EXECUTION_DENIED"
    OUTCOME_AMBIGUOUS = "OUTCOME_AMBIGUOUS"


class TargetBinding(StrictContractModel):
    schema_version: Literal["controlgraph.target-binding/v1"]
    project_id: ProjectId
    region: Region
    environment: Identifier
    service_name: CloudRunName


class TrafficAllocation(StrictContractModel):
    revision: CloudRunName
    percent: Percent


class StableSnapshot(StrictContractModel):
    schema_version: Literal["controlgraph.stable-snapshot/v1"]
    target: TargetBinding
    stable_revision: CloudRunName
    traffic: Annotated[tuple[TrafficAllocation, ...], Field(min_length=1, max_length=2)]
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    service_generation: NonNegativeSafeInteger
    provider_etag: OpaqueToken
    configuration_sha256: Sha256Digest
    captured_at: UtcSecond
    captured_by: BoundedText

    @model_validator(mode="after")
    def validate_stable_baseline(self) -> Self:
        if len(self.traffic) != 1:
            raise ValueError("stable snapshot must have one traffic allocation")
        allocation = self.traffic[0]
        if allocation.revision != self.stable_revision or allocation.percent != 100:
            raise ValueError("stable snapshot must route 100 percent to the stable revision")
        return self


class RolloutRoot(StrictContractModel):
    schema_version: Literal["controlgraph.rollout-root/v1"]
    root_id: Identifier
    target: TargetBinding
    stable_snapshot: StableSnapshot
    candidate_revision: CloudRunName
    stable_percent: Literal[90]
    candidate_percent: Literal[10]
    health_policy_sha256: Sha256Digest
    maximum_recovery_attempts: Annotated[int, Field(ge=1, le=3)]
    initial_epoch: Literal[1]
    plan_sha256: Sha256Digest
    approved_by: BoundedText
    approved_at: UtcSecond

    @model_validator(mode="after")
    def validate_root_bindings(self) -> Self:
        if self.target != self.stable_snapshot.target:
            raise ValueError("rollout root target does not match its snapshot")
        if self.candidate_revision == self.stable_snapshot.stable_revision:
            raise ValueError("candidate revision must differ from the stable revision")
        return self


class EpochAuthorityRecord(StrictContractModel):
    schema_version: Literal["controlgraph.epoch-authority/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    current_epoch: PositiveSafeInteger
    previous_epoch: PositiveSafeInteger | None
    revision: NonNegativeSafeInteger
    cause: EpochChangeCause
    changed_by: BoundedText
    request_id: Identifier
    evidence_id: Identifier
    changed_at: UtcSecond

    @model_validator(mode="after")
    def validate_transition_shape(self) -> Self:
        if self.cause is EpochChangeCause.ROOT_CREATED:
            if self.current_epoch != 1 or self.previous_epoch is not None or self.revision != 0:
                raise ValueError(
                    "initial authority must use epoch one, no previous epoch, and revision zero"
                )
        elif (
            self.previous_epoch is None
            or self.current_epoch != self.previous_epoch + 1
            or self.revision < 1
        ):
            raise ValueError("authority transition must advance exactly one epoch")
        if self.current_epoch != self.revision + 1:
            raise ValueError("authority epoch and revision must advance together")
        return self


def _expected_traffic(action: CapabilityAction) -> tuple[int, int]:
    if action is CapabilityAction.APPLY_CANARY:
        return 90, 10
    if action is CapabilityAction.PROMOTE_CANDIDATE:
        return 0, 100
    return 100, 0


class CapabilityClaims(StrictContractModel):
    schema_version: Literal["controlgraph.capability-claims/v1"]
    capability_id: Identifier
    issuer: BoundedText
    subject: BoundedText
    audience: Audience
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    action: CapabilityAction
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    stable_percent: Percent
    candidate_percent: Percent
    concurrency: Annotated[int, Field(ge=1, le=1_000)] | None
    plan_sha256: Sha256Digest
    provider_etag: OpaqueToken
    request_id: Identifier
    idempotency_key: Identifier
    parent_capability_sha256: Sha256Digest | None
    issued_at: UtcSecond
    not_before: UtcSecond
    expires_at: UtcSecond
    signing_algorithm: Literal["EC_SIGN_P256_SHA256"]
    signing_key_version: KeyVersionResource

    @model_validator(mode="after")
    def validate_claim_bindings(self) -> Self:
        if self.stable_revision == self.candidate_revision:
            raise ValueError("stable and candidate revisions must differ")
        if (self.stable_percent, self.candidate_percent) != _expected_traffic(self.action):
            raise ValueError("traffic does not match the capability action")
        issued = self.issued_at
        not_before = self.not_before
        expires = self.expires_at
        if not issued <= not_before < expires:
            raise ValueError("capability timestamps are not ordered")
        from datetime import datetime

        issued_time = datetime.strptime(issued, "%Y-%m-%dT%H:%M:%SZ")
        expires_time = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ")
        if (expires_time - issued_time).total_seconds() > 900:
            raise ValueError("capability lifetime exceeds 900 seconds")
        return self


class SignedCapability(StrictContractModel):
    schema_version: Literal["controlgraph.signed-capability/v1"]
    claims: CapabilityClaims
    claims_sha256: Sha256Digest
    signature: Base64Url

    @model_validator(mode="after")
    def validate_claims_digest(self) -> Self:
        from controlgraph_canary.contracts.codec import canonical_sha256

        if canonical_sha256(self.claims) != self.claims_sha256:
            raise ValueError("claims digest does not match canonical claims")
        return self


class MutationIntent(StrictContractModel):
    schema_version: Literal["controlgraph.mutation-intent/v1"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    action: CapabilityAction
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    stable_percent: Percent
    candidate_percent: Percent
    concurrency: Annotated[int, Field(ge=1, le=1_000)] | None
    plan_sha256: Sha256Digest
    provider_etag: OpaqueToken

    @model_validator(mode="after")
    def validate_intent(self) -> Self:
        if self.stable_revision == self.candidate_revision:
            raise ValueError("stable and candidate revisions must differ")
        if (self.stable_percent, self.candidate_percent) != _expected_traffic(self.action):
            raise ValueError("traffic does not match the mutation action")
        return self


class TaskRequest(StrictContractModel):
    schema_version: Literal["controlgraph.task-request/v1"]
    task_id: Identifier
    queue_region: Region
    handler_audience: Audience
    scheduled_at: UtcSecond
    expires_at: UtcSecond
    capability: SignedCapability
    intent: MutationIntent

    @model_validator(mode="after")
    def validate_task_bindings(self) -> Self:
        claims = self.capability.claims
        intent = self.intent
        if self.handler_audience != claims.audience:
            raise ValueError("task audience does not match capability audience")
        if not claims.not_before <= self.scheduled_at < self.expires_at <= claims.expires_at:
            raise ValueError("task timestamps exceed the capability window")
        if (
            claims.target != intent.target
            or claims.root_id != intent.root_id
            or claims.root_sha256 != intent.root_sha256
            or claims.epoch != intent.epoch
            or claims.action is not intent.action
            or claims.stable_revision != intent.stable_revision
            or claims.candidate_revision != intent.candidate_revision
            or claims.stable_percent != intent.stable_percent
            or claims.candidate_percent != intent.candidate_percent
            or claims.concurrency != intent.concurrency
            or claims.plan_sha256 != intent.plan_sha256
            or claims.provider_etag != intent.provider_etag
            or claims.request_id != intent.request_id
            or claims.idempotency_key != intent.idempotency_key
        ):
            raise ValueError("task intent does not match capability claims")
        return self


class ExecutionReceipt(StrictContractModel):
    schema_version: Literal["controlgraph.execution-receipt/v1"]
    receipt_id: Identifier
    request_id: Identifier
    idempotency_key: Identifier
    capability_sha256: Sha256Digest
    mutation_sha256: Sha256Digest
    plan_sha256: Sha256Digest
    expected_poststate_sha256: Sha256Digest
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    action: CapabilityAction
    provider_etag: OpaqueToken
    dispatch_not_after: UtcSecond
    outcome: ReceiptOutcome
    reason_code: ReasonCode | None
    provider_operation: BoundedText | None
    observed_etag: OpaqueToken | None
    observed_authority_epoch: PositiveSafeInteger | None
    created_at: UtcSecond
    updated_at: UtcSecond
    evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=64)]

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("receipt timestamps are not ordered")
        if self.dispatch_not_after < self.created_at:
            raise ValueError("receipt dispatch deadline precedes its claim")
        needs_reason = self.outcome in {
            ReceiptOutcome.DENIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.AMBIGUOUS,
        }
        if needs_reason != (self.reason_code is not None):
            raise ValueError("receipt reason does not match its outcome")
        if self.outcome is ReceiptOutcome.FAILED_SAFE and self.reason_code not in {
            ReasonCode.PROVIDER_PRECONDITION_FAILED,
            ReasonCode.TARGET_BINDING_MISMATCH,
            ReasonCode.PROVIDER_REQUEST_REJECTED,
        }:
            raise ValueError("failed-safe receipt reason is invalid")
        if (
            self.outcome is ReceiptOutcome.AMBIGUOUS
            and self.reason_code is not ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS
        ):
            raise ValueError("ambiguous receipt reason is invalid")
        if self.outcome is ReceiptOutcome.CLAIMED and (
            self.provider_operation is not None
            or self.observed_etag is not None
            or self.observed_authority_epoch is not None
        ):
            raise ValueError("claimed receipt cannot contain a provider result")
        if self.outcome is ReceiptOutcome.DENIED and (
            self.provider_operation is not None or self.observed_etag is not None
        ):
            raise ValueError("denied receipt cannot contain a provider result")
        if self.outcome is ReceiptOutcome.APPLIED and (
            self.provider_operation is None or self.observed_etag is not None
        ):
            raise ValueError("applied receipt result shape is invalid")
        if self.outcome is ReceiptOutcome.FAILED_SAFE and (
            self.provider_operation is not None or self.observed_etag is not None
        ):
            raise ValueError("failed-safe receipt cannot contain a provider result")
        if (
            self.reason_code is ReasonCode.EPOCH_MISMATCH
            and (
                self.observed_authority_epoch is None
                or self.observed_authority_epoch == self.epoch
            )
        ):
            raise ValueError("epoch mismatch receipt requires a different observed authority epoch")
        if self.outcome is ReceiptOutcome.VERIFIED and self.observed_etag is None:
            raise ValueError("verified receipt requires an observed etag")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("receipt evidence identifiers must be unique")
        return self


class HealthInput(StrictContractModel):
    schema_version: Literal["controlgraph.health-input/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    window_started_at: UtcSecond
    window_ended_at: UtcSecond
    request_count: NonNegativeSafeInteger
    error_count: NonNegativeSafeInteger
    p95_latency_ms: NonNegativeSafeInteger
    probe_successes: NonNegativeSafeInteger
    probe_failures: NonNegativeSafeInteger
    metrics_sha256: Sha256Digest
    observed_by: BoundedText
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def validate_health_window(self) -> Self:
        if self.window_ended_at < self.window_started_at:
            raise ValueError("health window timestamps are not ordered")
        if self.error_count > self.request_count:
            raise ValueError("error count cannot exceed request count")
        if self.probe_successes + self.probe_failures < 1:
            raise ValueError("health input requires at least one probe")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("health evidence identifiers must be unique")
        return self


class RecoveryPlan(StrictContractModel):
    schema_version: Literal["controlgraph.recovery-plan/v1"]
    request_id: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    stable_percent: Literal[100]
    candidate_percent: Literal[0]
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    provider_etag: OpaqueToken
    stable_snapshot_sha256: Sha256Digest
    plan_sha256: Sha256Digest
    maximum_attempts: Annotated[int, Field(ge=1, le=3)]
    approved_by: BoundedText
    approved_at: UtcSecond

    @model_validator(mode="after")
    def validate_recovery_target(self) -> Self:
        if self.stable_revision == self.candidate_revision:
            raise ValueError("recovery stable and candidate revisions must differ")
        return self


class EvidenceEvent(StrictContractModel):
    schema_version: Literal["controlgraph.evidence-event/v1"]
    evidence_id: Identifier
    sequence: NonNegativeSafeInteger
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    kind: EvidenceKind
    actor: BoundedText
    request_id: Identifier | None
    receipt_id: Identifier | None
    occurred_at: UtcSecond
    subject_sha256: Sha256Digest
    previous_event_sha256: Sha256Digest | None
    reason_code: ReasonCode | None
    provider_operation: BoundedText | None
    target_configuration_sha256: Sha256Digest | None

    @model_validator(mode="after")
    def validate_event_shape(self) -> Self:
        if (self.sequence == 0) != (self.previous_event_sha256 is None):
            raise ValueError("evidence chain predecessor does not match sequence")
        if self.kind is EvidenceKind.EXECUTION_DENIED and self.reason_code is None:
            raise ValueError("denial evidence requires a reason")
        if self.kind is not EvidenceKind.EXECUTION_DENIED and self.reason_code is not None:
            raise ValueError("non-denial evidence cannot carry a denial reason")
        if self.kind is EvidenceKind.MUTATION_APPLIED and self.provider_operation is None:
            raise ValueError("mutation evidence requires a provider operation")
        if self.kind is EvidenceKind.TARGET_VERIFIED and self.target_configuration_sha256 is None:
            raise ValueError("verification evidence requires a target configuration digest")
        return self


__all__ = [
    "CAPABILITY_CLAIMS_V1",
    "EPOCH_AUTHORITY_V1",
    "EVIDENCE_EVENT_V1",
    "EXECUTION_RECEIPT_V1",
    "HEALTH_INPUT_V1",
    "MUTATION_INTENT_V1",
    "RECOVERY_PLAN_V1",
    "ROLLOUT_ROOT_V1",
    "SIGNED_CAPABILITY_V1",
    "STABLE_SNAPSHOT_V1",
    "TARGET_BINDING_V1",
    "TASK_REQUEST_V1",
    "CapabilityAction",
    "CapabilityClaims",
    "EpochAuthorityRecord",
    "EpochChangeCause",
    "EvidenceEvent",
    "EvidenceKind",
    "ExecutionReceipt",
    "HealthInput",
    "MutationIntent",
    "ReasonCode",
    "ReceiptOutcome",
    "RecoveryPlan",
    "RolloutRoot",
    "SignedCapability",
    "StableSnapshot",
    "TargetBinding",
    "TaskRequest",
    "TrafficAllocation",
]
