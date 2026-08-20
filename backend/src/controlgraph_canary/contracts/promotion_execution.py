"""Canonical contracts for issuing and dispatching a candidate promotion."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    CloudRunName,
    Identifier,
    OpaqueToken,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    TargetBinding,
    TaskRequest,
)

VERIFIED_APPLY_RECEIPT_LOCATOR_V1: Final = "controlgraph.verified-apply-receipt-locator/v1"
PROMOTION_COMMAND_V1: Final = "controlgraph.promotion-command/v1"
PROMOTION_INVOCATION_V1: Final = "controlgraph.promotion-invocation/v1"
PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V1: Final = (
    "controlgraph.promotion-capability-issuance-command/v1"
)
PROMOTION_DISPATCH_RESULT_V1: Final = "controlgraph.promotion-dispatch-result/v1"
PROMOTION_DISPATCH_IDENTITY_V1: Final = "controlgraph.promotion-dispatch-identity/v1"
PROMOTION_DISPATCH_RECORD_V1: Final = "controlgraph.promotion-dispatch-record/v1"

_PROMOTION_COMMAND_DIGEST_DOMAIN: Final = b"controlgraph.promotion-command-sha256/v1\0"

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$")
_TASK_NAME = re.compile(
    r"^projects/(controlgraph-canary-[a-z0-9]{6,10})/locations/us-central1/"
    r"queues/controlgraph-execution/tasks/cg-[0-9a-f]{64}$"
)
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
_MAX_ID_TOKEN_LIFETIME_SECONDS: Final = 3_660

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


class VerifiedApplyReceiptLocatorV1(StrictContractModel):
    """Exact durable receipt and mutation identity selected as promotion input."""

    schema_version: Literal["controlgraph.verified-apply-receipt-locator/v1"]
    receipt_id: Identifier
    request_id: Identifier
    idempotency_key: Identifier
    capability_sha256: Sha256Digest
    mutation_sha256: Sha256Digest
    expected_poststate_sha256: Sha256Digest
    provider_operation: BoundedText
    receipt_sha256: Sha256Digest


class PromotionCommandV1(StrictContractModel):
    """Operator-selected authority and trusted receipt locator, without a target."""

    schema_version: Literal["controlgraph.promotion-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1


class PromotionInvocationV1(StrictContractModel):
    """One promotion command plus operator identity facts authenticated by the API."""

    schema_version: Literal["controlgraph.promotion-invocation/v1"]
    command: PromotionCommandV1
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        if (
            _HUMAN_EMAIL.fullmatch(self.operator_identity) is None
            or self.operator_identity.endswith(".iam.gserviceaccount.com")
            or _API_AUDIENCE.fullmatch(self.operator_audience) is None
            or self.operator_issued_at >= self.operator_expires_at
            or self.operator_expires_at - self.operator_issued_at > _MAX_ID_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError("promotion invocation bindings are invalid")
        return self


class PromotionCapabilityIssuanceCommandV1(StrictContractModel):
    """Coordinator preconditions for one receipt-derived promotion capability."""

    schema_version: Literal["controlgraph.promotion-capability-issuance-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1


class PromotionDispatchIdentityKind(StrEnum):
    """Independent caller identities owned by one canonical promotion."""

    REQUEST = "REQUEST"
    IDEMPOTENCY = "IDEMPOTENCY"


class PromotionDispatchState(StrEnum):
    """Monotonic durable states around the one permitted enqueue attempt."""

    PREPARED = "PREPARED"
    ENQUEUE_STARTED = "ENQUEUE_STARTED"
    CREATED = "CREATED"
    DUPLICATE = "DUPLICATE"
    AMBIGUOUS = "AMBIGUOUS"


class PromotionDispatchIdentityV1(StrictContractModel):
    """Immutable ownership of one request or idempotency identity."""

    schema_version: Literal["controlgraph.promotion-dispatch-identity/v1"]
    identity_kind: PromotionDispatchIdentityKind
    identity_value: Identifier
    dispatch_id: Identifier
    command_sha256: Sha256Digest
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    source_receipt_sha256: Sha256Digest
    claimed_at: UtcSecond

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.dispatch_id != promotion_dispatch_id(self.command_sha256):
            raise ValueError("promotion dispatch identity is invalid")
        return self


class PromotionDispatchResultV1(StrictContractModel):
    """Bounded result of issuing and addressing one promotion task."""

    schema_version: Literal["controlgraph.promotion-dispatch-result/v1"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    stable_percent: Literal[0]
    candidate_percent: Literal[100]
    provider_etag: OpaqueToken
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1
    capability_id: Identifier
    capability_sha256: Sha256Digest
    task_id: Identifier
    task_name: BoundedText
    enqueue_disposition: Literal["CREATED", "DUPLICATE", "AMBIGUOUS"]
    scheduled_at: UtcSecond
    expires_at: UtcSecond

    @model_validator(mode="after")
    def validate_dispatch(self) -> Self:
        task_match = _TASK_NAME.fullmatch(self.task_name)
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(self.target.project_id) is None
            or "reconcile" in self.target.project_id.lower()
            or self.target.region != "us-central1"
            or self.target.environment != "nonprod"
            or self.target.service_name != _REFERENCE_SERVICE
            or task_match is None
            or task_match.group(1) != self.target.project_id
            or self.scheduled_at >= self.expires_at
        ):
            raise ValueError("promotion dispatch result bindings are invalid")
        return self


class PromotionDispatchRecordV1(StrictContractModel):
    """Durable exact task and monotonic outcome for one promotion command."""

    schema_version: Literal["controlgraph.promotion-dispatch-record/v1"]
    dispatch_id: Identifier
    command_sha256: Sha256Digest
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1
    source_receipt_sha256: Sha256Digest
    task_sha256: Sha256Digest
    task_name: BoundedText
    task: TaskRequest
    state: PromotionDispatchState
    prepared_at: UtcSecond
    enqueue_started_at: UtcSecond | None
    terminal_at: UtcSecond | None
    result: PromotionDispatchResultV1 | None

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        command = PromotionCommandV1(
            schema_version=PROMOTION_COMMAND_V1,
            root_id=self.root_id,
            expected_root_sha256=self.root_sha256,
            expected_epoch=self.epoch,
            request_id=self.request_id,
            idempotency_key=self.idempotency_key,
            verified_apply_receipt=self.verified_apply_receipt,
        )
        claims = self.task.capability.claims
        intent = self.task.intent
        expected_task_name = (
            f"projects/{self.target.project_id}/locations/us-central1/queues/"
            f"controlgraph-execution/tasks/cg-{self.task_sha256}"
        )
        terminal = self.state in {
            PromotionDispatchState.CREATED,
            PromotionDispatchState.DUPLICATE,
            PromotionDispatchState.AMBIGUOUS,
        }
        if (
            self.command_sha256 != promotion_command_sha256(command)
            or self.dispatch_id != promotion_dispatch_id(self.command_sha256)
            or self.source_receipt_sha256 != self.verified_apply_receipt.receipt_sha256
            or self.task_sha256 != canonical_sha256(self.task)
            or self.task_name != expected_task_name
            or self.task.task_id != f"task-{self.task.capability.claims_sha256}"
            or self.task.queue_region != "us-central1"
            or claims.target != self.target
            or claims.root_id != self.root_id
            or claims.root_sha256 != self.root_sha256
            or claims.epoch != self.epoch
            or claims.request_id != self.request_id
            or claims.idempotency_key != self.idempotency_key
            or claims.action is not CapabilityAction.PROMOTE_CANDIDATE
            or claims.stable_percent != 0
            or claims.candidate_percent != 100
            or claims.concurrency is not None
            or claims.parent_capability_sha256 is not None
            or intent.action is not CapabilityAction.PROMOTE_CANDIDATE
        ):
            raise ValueError("promotion dispatch task binding is invalid")
        if self.state is PromotionDispatchState.PREPARED:
            if any(
                value is not None
                for value in (self.enqueue_started_at, self.terminal_at, self.result)
            ):
                raise ValueError("prepared promotion dispatch shape is invalid")
            return self
        if self.enqueue_started_at is None or self.enqueue_started_at < self.prepared_at:
            raise ValueError("promotion enqueue start is invalid")
        if self.state is PromotionDispatchState.ENQUEUE_STARTED:
            if self.terminal_at is not None or self.result is not None:
                raise ValueError("started promotion dispatch shape is invalid")
            return self
        if (
            not terminal
            or self.terminal_at is None
            or self.terminal_at < self.enqueue_started_at
            or self.result is None
            or self.result.enqueue_disposition != self.state.value
            or self.result.request_id != self.request_id
            or self.result.idempotency_key != self.idempotency_key
            or self.result.target != self.target
            or self.result.root_id != self.root_id
            or self.result.root_sha256 != self.root_sha256
            or self.result.epoch != self.epoch
            or self.result.stable_revision != claims.stable_revision
            or self.result.candidate_revision != claims.candidate_revision
            or self.result.provider_etag != claims.provider_etag
            or self.result.verified_apply_receipt != self.verified_apply_receipt
            or self.result.capability_id != claims.capability_id
            or self.result.capability_sha256 != canonical_sha256(self.task.capability)
            or self.result.task_id != self.task.task_id
            or self.result.task_name != self.task_name
            or self.result.scheduled_at != self.task.scheduled_at
            or self.result.expires_at != self.task.expires_at
        ):
            raise ValueError("terminal promotion dispatch shape is invalid")
        return self


def promotion_command_sha256(command: PromotionCommandV1) -> str:
    """Hash every caller-selected promotion binding under a fixed domain."""

    if type(command) is not PromotionCommandV1:
        raise TypeError("promotion hashing requires an exact command")
    return hashlib.sha256(
        _PROMOTION_COMMAND_DIGEST_DOMAIN + canonical_json_bytes(command)
    ).hexdigest()


def promotion_dispatch_id(command_sha256: str) -> str:
    """Return the immutable dispatch identity for one command digest."""

    if re.fullmatch(r"[0-9a-f]{64}", command_sha256) is None:
        raise ValueError("promotion command digest is invalid")
    return f"cgpromote:{command_sha256}"


__all__ = [
    "PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V1",
    "PROMOTION_COMMAND_V1",
    "PROMOTION_DISPATCH_IDENTITY_V1",
    "PROMOTION_DISPATCH_RECORD_V1",
    "PROMOTION_DISPATCH_RESULT_V1",
    "PROMOTION_INVOCATION_V1",
    "VERIFIED_APPLY_RECEIPT_LOCATOR_V1",
    "PromotionCapabilityIssuanceCommandV1",
    "PromotionCommandV1",
    "PromotionDispatchIdentityKind",
    "PromotionDispatchIdentityV1",
    "PromotionDispatchRecordV1",
    "PromotionDispatchResultV1",
    "PromotionDispatchState",
    "PromotionInvocationV1",
    "VerifiedApplyReceiptLocatorV1",
    "promotion_command_sha256",
    "promotion_dispatch_id",
]
