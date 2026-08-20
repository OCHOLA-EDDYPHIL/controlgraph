"""Canonical contracts for bounded operator observations."""

from __future__ import annotations

import re
from typing import Annotated, Final, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    CloudRunName,
    Identifier,
    NonNegativeSafeInteger,
    OpaqueToken,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReceiptOutcome,
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
)
from controlgraph_canary.contracts.promotion_execution import (
    VERIFIED_APPLY_RECEIPT_LOCATOR_V1,
    VerifiedApplyReceiptLocatorV1,
)
from controlgraph_canary.contracts.storage import execution_receipt_logical_id

STABLE_SNAPSHOT_CAPTURE_COMMAND_V1: Final = (
    "controlgraph.stable-snapshot-capture-command/v1"
)
STABLE_SNAPSHOT_CAPTURE_INVOCATION_V1: Final = (
    "controlgraph.stable-snapshot-capture-invocation/v1"
)
STABLE_SNAPSHOT_CAPTURE_REQUEST_V1: Final = (
    "controlgraph.stable-snapshot-capture-request/v1"
)
STABLE_SNAPSHOT_CAPTURE_RESULT_V1: Final = (
    "controlgraph.stable-snapshot-capture-result/v1"
)
EXECUTION_RECEIPT_READ_COMMAND_V1: Final = (
    "controlgraph.execution-receipt-read-command/v1"
)
EXECUTION_RECEIPT_READ_INVOCATION_V1: Final = (
    "controlgraph.execution-receipt-read-invocation/v1"
)
EXECUTION_RECEIPT_READ_RESULT_V1: Final = (
    "controlgraph.execution-receipt-read-result/v1"
)
TARGET_TRAFFIC_READ_COMMAND_V1: Final = "controlgraph.target-traffic-read-command/v1"
TARGET_TRAFFIC_READ_INVOCATION_V1: Final = (
    "controlgraph.target-traffic-read-invocation/v1"
)
TARGET_TRAFFIC_READ_REQUEST_V1: Final = "controlgraph.target-traffic-read-request/v1"
TARGET_TRAFFIC_READ_RESULT_V1: Final = "controlgraph.target-traffic-read-result/v1"

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(
    r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
_MAX_ID_TOKEN_LIFETIME_SECONDS: Final = 3_660

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


class StableSnapshotCaptureCommandV1(StrictContractModel):
    """Request one fresh configured-target snapshot without cloud coordinates."""

    schema_version: Literal["controlgraph.stable-snapshot-capture-command/v1"]
    request_id: Identifier


class StableSnapshotCaptureInvocationV1(StrictContractModel):
    """Snapshot command plus identity facts authenticated by the operator API."""

    schema_version: Literal["controlgraph.stable-snapshot-capture-invocation/v1"]
    command: StableSnapshotCaptureCommandV1
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        _validate_operator_invocation(self)
        return self


class StableSnapshotCaptureRequestV1(StrictContractModel):
    """Coordinator-selected target for one verifier snapshot capture."""

    schema_version: Literal["controlgraph.stable-snapshot-capture-request/v1"]
    request_id: Identifier
    target: TargetBinding

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        _validate_target(self.target)
        return self


class StableSnapshotCaptureResultV1(StrictContractModel):
    """Self-binding two-read stable snapshot returned by the verifier."""

    schema_version: Literal["controlgraph.stable-snapshot-capture-result/v1"]
    request: StableSnapshotCaptureRequestV1
    request_sha256: Sha256Digest
    snapshot: StableSnapshot

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        expected_reader = (
            f"controlgraph-verifier@{self.request.target.project_id}.iam.gserviceaccount.com"
        )
        if (
            self.request_sha256 != canonical_sha256(self.request)
            or self.snapshot.target != self.request.target
            or self.snapshot.captured_by != expected_reader
        ):
            raise ValueError("stable snapshot result is not bound to its exact request")
        return self


class ExecutionReceiptReadCommandV1(StrictContractModel):
    """Full known dispatch identity required to read one exact receipt."""

    schema_version: Literal["controlgraph.execution-receipt-read-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    action: CapabilityAction
    request_id: Identifier
    idempotency_key: Identifier
    capability_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_action(self) -> Self:
        if self.action not in {
            CapabilityAction.APPLY_CANARY,
            CapabilityAction.PROMOTE_CANDIDATE,
        }:
            raise ValueError("receipt observation action is not operator-readable")
        return self


class ExecutionReceiptReadInvocationV1(StrictContractModel):
    """Exact receipt command plus identity facts authenticated by the API."""

    schema_version: Literal["controlgraph.execution-receipt-read-invocation/v1"]
    command: ExecutionReceiptReadCommandV1
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        _validate_operator_invocation(self)
        return self


class ExecutionReceiptReadResultV1(StrictContractModel):
    """One exact target-bound receipt with a promotion locator when eligible."""

    schema_version: Literal["controlgraph.execution-receipt-read-result/v1"]
    command: ExecutionReceiptReadCommandV1
    command_sha256: Sha256Digest
    receipt: ExecutionReceipt
    storage_revision: NonNegativeSafeInteger
    receipt_sha256: Sha256Digest
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1 | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        command = self.command
        receipt = self.receipt
        _validate_target(receipt.target)
        if (
            self.command_sha256 != canonical_sha256(command)
            or self.receipt_sha256 != canonical_sha256(receipt)
            or receipt.root_id != command.root_id
            or receipt.root_sha256 != command.expected_root_sha256
            or receipt.epoch != command.expected_epoch
            or receipt.action is not command.action
            or receipt.request_id != command.request_id
            or receipt.idempotency_key != command.idempotency_key
            or receipt.capability_sha256 != command.capability_sha256
            or receipt.receipt_id
            != execution_receipt_logical_id(receipt.target, command.idempotency_key)
        ):
            raise ValueError("receipt observation does not match its exact command")

        locator_required = (
            receipt.action is CapabilityAction.APPLY_CANARY
            and receipt.outcome is ReceiptOutcome.VERIFIED
            and receipt.provider_operation is not None
            and self.storage_revision >= 2
        )
        if locator_required != (self.verified_apply_receipt is not None):
            raise ValueError("receipt observation locator shape is invalid")
        locator = self.verified_apply_receipt
        if locator is not None and (
            locator.schema_version != VERIFIED_APPLY_RECEIPT_LOCATOR_V1
            or locator.receipt_id != receipt.receipt_id
            or locator.request_id != receipt.request_id
            or locator.idempotency_key != receipt.idempotency_key
            or locator.capability_sha256 != receipt.capability_sha256
            or locator.mutation_sha256 != receipt.mutation_sha256
            or locator.expected_poststate_sha256 != receipt.expected_poststate_sha256
            or locator.provider_operation != receipt.provider_operation
            or locator.receipt_sha256 != self.receipt_sha256
        ):
            raise ValueError("verified apply locator does not match the exact receipt")
        return self


class TargetTrafficReadCommandV1(StrictContractModel):
    """Request fresh traffic facts for only the configured reference target."""

    schema_version: Literal["controlgraph.target-traffic-read-command/v1"]
    request_id: Identifier


class TargetTrafficReadInvocationV1(StrictContractModel):
    """Traffic-read command plus identity facts authenticated by the API."""

    schema_version: Literal["controlgraph.target-traffic-read-invocation/v1"]
    command: TargetTrafficReadCommandV1
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        _validate_operator_invocation(self)
        return self


class TargetTrafficReadRequestV1(StrictContractModel):
    """Coordinator-selected fixed target and revision pair for verifier readback."""

    schema_version: Literal["controlgraph.target-traffic-read-request/v1"]
    request_id: Identifier
    target: TargetBinding
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    concurrency: Annotated[int, Field(ge=1, le=1_000)]

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        _validate_target(self.target)
        prefix = f"{self.target.service_name}-"
        if (
            self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(prefix)
            or not self.candidate_revision.startswith(prefix)
        ):
            raise ValueError("target traffic revisions are not target-bound")
        return self


class TargetTrafficReadResultV1(StrictContractModel):
    """Canonical verifier observation of one supported target traffic state."""

    schema_version: Literal["controlgraph.target-traffic-read-result/v1"]
    request: TargetTrafficReadRequestV1
    request_sha256: Sha256Digest
    traffic: Annotated[tuple[TrafficAllocation, ...], Field(min_length=1, max_length=2)]
    traffic_statuses: Annotated[
        tuple[TrafficAllocation, ...],
        Field(min_length=1, max_length=2),
    ]
    service_generation: PositiveSafeInteger
    provider_etag: OpaqueToken
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision_configuration_sha256: Sha256Digest
    target_configuration_sha256: Sha256Digest
    observed_by: BoundedText
    observed_at: UtcSecond

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        request = self.request
        expected_reader = (
            f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        )
        traffic = tuple((item.revision, item.percent) for item in self.traffic)
        statuses = tuple((item.revision, item.percent) for item in self.traffic_statuses)
        allowed_revisions = {request.stable_revision, request.candidate_revision}
        traffic_map = dict(traffic)
        if (
            self.request_sha256 != canonical_sha256(request)
            or self.concurrency != request.concurrency
            or self.observed_by != expected_reader
            or traffic != statuses
            or len(traffic_map) != len(traffic)
            or not set(traffic_map).issubset(allowed_revisions)
            or sum(traffic_map.values()) != 100
            or (
                traffic_map.get(request.stable_revision, 0),
                traffic_map.get(request.candidate_revision, 0),
            )
            not in {(100, 0), (90, 10), (0, 100)}
        ):
            raise ValueError("target traffic result is not one supported exact observation")
        return self


def _validate_operator_invocation(value: object) -> None:
    operator_identity = getattr(value, "operator_identity", None)
    operator_audience = getattr(value, "operator_audience", None)
    issued_at = getattr(value, "operator_issued_at", None)
    expires_at = getattr(value, "operator_expires_at", None)
    if (
        type(operator_identity) is not str
        or _HUMAN_EMAIL.fullmatch(operator_identity) is None
        or operator_identity.endswith(".iam.gserviceaccount.com")
        or type(operator_audience) is not str
        or _API_AUDIENCE.fullmatch(operator_audience) is None
        or type(issued_at) is not int
        or type(expires_at) is not int
        or issued_at >= expires_at
        or expires_at - issued_at > _MAX_ID_TOKEN_LIFETIME_SECONDS
    ):
        raise ValueError("operator observation invocation bindings are invalid")


def _validate_target(target: TargetBinding) -> None:
    if (
        type(target) is not TargetBinding
        or _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is None
        or "reconcile" in target.project_id.lower()
        or target.region != "us-central1"
        or target.environment != "nonprod"
        or target.service_name != _REFERENCE_SERVICE
    ):
        raise ValueError("operator observation target is outside ControlGraph")


__all__ = [
    "EXECUTION_RECEIPT_READ_COMMAND_V1",
    "EXECUTION_RECEIPT_READ_INVOCATION_V1",
    "EXECUTION_RECEIPT_READ_RESULT_V1",
    "STABLE_SNAPSHOT_CAPTURE_COMMAND_V1",
    "STABLE_SNAPSHOT_CAPTURE_INVOCATION_V1",
    "STABLE_SNAPSHOT_CAPTURE_REQUEST_V1",
    "STABLE_SNAPSHOT_CAPTURE_RESULT_V1",
    "TARGET_TRAFFIC_READ_COMMAND_V1",
    "TARGET_TRAFFIC_READ_INVOCATION_V1",
    "TARGET_TRAFFIC_READ_REQUEST_V1",
    "TARGET_TRAFFIC_READ_RESULT_V1",
    "ExecutionReceiptReadCommandV1",
    "ExecutionReceiptReadInvocationV1",
    "ExecutionReceiptReadResultV1",
    "StableSnapshotCaptureCommandV1",
    "StableSnapshotCaptureInvocationV1",
    "StableSnapshotCaptureRequestV1",
    "StableSnapshotCaptureResultV1",
    "TargetTrafficReadCommandV1",
    "TargetTrafficReadInvocationV1",
    "TargetTrafficReadRequestV1",
    "TargetTrafficReadResultV1",
]
