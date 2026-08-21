"""Canonical contracts for issuing and dispatching a candidate promotion."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    CloudRunName,
    Identifier,
    KeyVersionResource,
    OpaqueToken,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    canonical_sha256,
)
from controlgraph_canary.contracts.health import HealthDecisionStatus
from controlgraph_canary.contracts.health_execution import (
    HealthyPromotionProofV1,
    SignedHealthDecisionChainV1,
    create_post_apply_health_anchor,
    health_chain_manifest_sha256,
    signed_health_decision_chain_sha256,
    signed_health_proof_chain_sha256,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV3

VERIFIED_APPLY_RECEIPT_LOCATOR_V1: Final = "controlgraph.verified-apply-receipt-locator/v1"
PROMOTION_COMMAND_V1: Final = "controlgraph.promotion-command/v1"
PROMOTION_INVOCATION_V1: Final = "controlgraph.promotion-invocation/v1"
PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V1: Final = (
    "controlgraph.promotion-capability-issuance-command/v1"
)
PROMOTION_DISPATCH_RESULT_V1: Final = "controlgraph.promotion-dispatch-result/v1"
PROMOTION_DISPATCH_IDENTITY_V1: Final = "controlgraph.promotion-dispatch-identity/v1"
PROMOTION_DISPATCH_RECORD_V1: Final = "controlgraph.promotion-dispatch-record/v1"
PROMOTION_AUTHORIZATION_V1: Final = "controlgraph.promotion-authorization/v1"
PROMOTION_HEALTH_CHAIN_LOCATOR_V1: Final = (
    "controlgraph.promotion-health-chain-locator/v1"
)
PROMOTION_COMMAND_V2: Final = "controlgraph.promotion-command/v2"
PROMOTION_INVOCATION_V2: Final = "controlgraph.promotion-invocation/v2"
PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V2: Final = (
    "controlgraph.promotion-capability-issuance-command/v2"
)
PROMOTION_MUTATION_INTENT_V2: Final = "controlgraph.promotion-mutation-intent/v2"
PROMOTION_TASK_REQUEST_V2: Final = "controlgraph.promotion-task-request/v2"
PROMOTION_DISPATCH_RESULT_V2: Final = "controlgraph.promotion-dispatch-result/v2"
PROMOTION_DISPATCH_IDENTITY_V2: Final = "controlgraph.promotion-dispatch-identity/v2"
PROMOTION_DISPATCH_RECORD_V2: Final = "controlgraph.promotion-dispatch-record/v2"

_PROMOTION_COMMAND_DIGEST_DOMAIN: Final = b"controlgraph.promotion-command-sha256/v1\0"
_PROMOTION_COMMAND_V2_DIGEST_DOMAIN: Final = b"controlgraph.promotion-command-sha256/v2\0"
_PROMOTION_CAPABILITY_ID_DOMAIN: Final = b"controlgraph.promotion-capability-id/v1\0"
MAX_PROMOTION_TASK_CANONICAL_BYTES: Final = 64_000

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$")
_EXECUTOR_AUDIENCE = re.compile(
    r"^https://controlgraph-executor-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)
_TASK_NAME = re.compile(
    r"^projects/(controlgraph-canary-[a-z0-9]{6,10})/locations/us-central1/"
    r"queues/controlgraph-execution/tasks/cg-[0-9a-f]{64}$"
)
_EVIDENCE_KEY = re.compile(
    r"^projects/(?P<project>controlgraph-canary-[a-z0-9]{6,10})/"
    r"locations/us-central1/keyRings/controlgraph-signing/"
    r"cryptoKeys/evidence-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
_MAX_ID_TOKEN_LIFETIME_SECONDS: Final = 3_660

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


def _require_canonical_size(
    value: StrictContractModel,
    *,
    maximum_bytes: int,
    boundary: str,
) -> None:
    projection = cast(RestrictedJson, value.model_dump(mode="json"))
    try:
        encoded = canonical_json_value_bytes(projection)
    except ContractError:
        raise ValueError(f"{boundary} exceeds the canonical byte bound") from None
    if len(encoded) > maximum_bytes:
        raise ValueError(f"{boundary} exceeds the canonical byte bound")


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
    """Operator-selected authority, schedule, and trusted receipt locator."""

    schema_version: Literal["controlgraph.promotion-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    scheduled_at: UtcSecond
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
    scheduled_at: UtcSecond
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
    scheduled_at: UtcSecond
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
    scheduled_at: UtcSecond
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
            scheduled_at=self.scheduled_at,
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
            or claims.not_before != self.scheduled_at
            or self.task.scheduled_at != self.scheduled_at
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
            or self.result.scheduled_at != self.scheduled_at
            or self.result.expires_at != self.task.expires_at
        ):
            raise ValueError("terminal promotion dispatch shape is invalid")
        return self


class PromotionHealthChainLocatorV1(StrictContractModel):
    """Exact durable lookup and manifest bindings for one signed health chain."""

    schema_version: Literal["controlgraph.promotion-health-chain-locator/v1"]
    anchor_id: Identifier
    anchor_sha256: Sha256Digest
    chain_id: Identifier
    health_chain_sha256: Sha256Digest
    chain_head_sha256: Sha256Digest
    ordered_proof_chain_sha256: Sha256Digest
    terminal_sequence: Annotated[int, Field(ge=1, le=20)]

    @model_validator(mode="after")
    def validate_locator(self) -> Self:
        if (
            not self.anchor_id.startswith("cghealthanchor:")
            or self.chain_id != f"cghealthchain:{self.health_chain_sha256}"
        ):
            raise ValueError("promotion health-chain locator is invalid")
        return self


class PromotionAuthorizationV1(StrictContractModel):
    """Compact root and healthy-chain bindings for one promotion capability."""

    schema_version: Literal["controlgraph.promotion-authorization/v1"]
    capability_id: Identifier
    request_id: Identifier
    idempotency_key: Identifier
    scheduled_at: UtcSecond
    root_schema_version: Literal["controlgraph.rollout-root/v3"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    plan_sha256: Sha256Digest
    policy_schema_version: Literal["controlgraph.rollout-health-policy/v2"]
    policy_sha256: Sha256Digest
    stable_snapshot_sha256: Sha256Digest
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    evidence_signing_key_version: KeyVersionResource
    capability_signing_key_version: KeyVersionResource
    issuer_identity: BoundedText
    executor_identity: BoundedText
    executor_audience: Audience
    expected_stable_percent: Literal[90]
    expected_candidate_percent: Literal[10]
    expected_prestate_sha256: Sha256Digest
    provider_etag: OpaqueToken
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1
    source_receipt_sha256: Sha256Digest
    health_chain_locator: PromotionHealthChainLocatorV1
    terminal_health_decision_sha256: Sha256Digest
    healthy_promotion_proof_sha256: Sha256Digest
    healthy_promotion_proof: HealthyPromotionProofV1
    stable_percent: Literal[0]
    candidate_percent: Literal[100]
    desired_poststate_sha256: Sha256Digest
    proof_valid_until: UtcSecond

    @model_validator(mode="after")
    def validate_authorization(self) -> Self:
        compact = self.healthy_promotion_proof
        chain = self.health_chain_locator
        key_match = _EVIDENCE_KEY.fullmatch(self.evidence_signing_key_version)
        capability_key = self.evidence_signing_key_version.replace(
            "evidence-signing",
            "capability-signing",
        )
        revision_prefix = f"{self.target.service_name}-"
        if (
            self.root_id != f"cgroot:{self.root_sha256}"
            or _CONTROLGRAPH_PROJECT.fullmatch(self.target.project_id) is None
            or "reconcile" in self.target.project_id.lower()
            or self.target.region != "us-central1"
            or self.target.environment != "nonprod"
            or self.target.service_name != _REFERENCE_SERVICE
            or self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(revision_prefix)
            or not self.candidate_revision.startswith(revision_prefix)
            or key_match is None
            or key_match.group("project") != self.target.project_id
            or self.capability_signing_key_version != capability_key
            or self.issuer_identity
            != f"controlgraph-issuer@{self.target.project_id}.iam.gserviceaccount.com"
            or self.executor_identity
            != f"controlgraph-executor@{self.target.project_id}.iam.gserviceaccount.com"
            or _EXECUTOR_AUDIENCE.fullmatch(self.executor_audience) is None
        ):
            raise ValueError("promotion authorization root binding is invalid")
        if (
            self.verified_apply_receipt.expected_poststate_sha256
            != self.expected_prestate_sha256
            or self.source_receipt_sha256
            != self.verified_apply_receipt.receipt_sha256
        ):
            raise ValueError("promotion authorization receipt binding is invalid")
        if (
            type(compact) is not HealthyPromotionProofV1
            or type(chain) is not PromotionHealthChainLocatorV1
            or compact.anchor_id != chain.anchor_id
            or compact.anchor_sha256 != chain.anchor_sha256
            or compact.root_id != self.root_id
            or compact.root_sha256 != self.root_sha256
            or compact.target != self.target
            or compact.epoch != self.epoch
            or compact.policy_sha256 != self.policy_sha256
            or compact.candidate_revision != self.candidate_revision
            or compact.terminal_sequence != chain.terminal_sequence
            or compact.source_receipt_sha256 != self.source_receipt_sha256
            or compact.expected_prestate_sha256 != self.expected_prestate_sha256
            or compact.terminal_health_decision_sha256
            != self.terminal_health_decision_sha256
            or compact.signed_health_chain_sha256
            != chain.ordered_proof_chain_sha256
            or self.healthy_promotion_proof_sha256 != canonical_sha256(compact)
            or chain.health_chain_sha256
            != health_chain_manifest_sha256(
                anchor_sha256=chain.anchor_sha256,
                ordered_proof_chain_sha256=chain.ordered_proof_chain_sha256,
                chain_head_sha256=chain.chain_head_sha256,
                healthy_promotion_proof_sha256=self.healthy_promotion_proof_sha256,
            )
            or compact.stable_percent != self.stable_percent
            or compact.candidate_percent != self.candidate_percent
            or compact.desired_poststate_sha256 != self.desired_poststate_sha256
            or compact.valid_until != self.proof_valid_until
            or not compact.issued_at <= self.scheduled_at < self.proof_valid_until
        ):
            raise ValueError("promotion authorization does not bind its healthy proof")
        if self.capability_id != promotion_capability_id(self):
            raise ValueError("promotion authorization capability identifier is not canonical")
        return self


class PromotionCommandV2(StrictContractModel):
    """Operator-selected root and verifier-owned health-chain locator."""

    schema_version: Literal["controlgraph.promotion-command/v2"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    scheduled_at: UtcSecond
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1
    health_chain_locator: PromotionHealthChainLocatorV1

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        if self.root_id != f"cgroot:{self.expected_root_sha256}":
            raise ValueError("promotion command bindings are invalid")
        return self


class PromotionInvocationV2(StrictContractModel):
    """Authenticated operator identity paired with a V2 promotion command."""

    schema_version: Literal["controlgraph.promotion-invocation/v2"]
    command: PromotionCommandV2
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        if (
            type(self.command) is not PromotionCommandV2
            or _HUMAN_EMAIL.fullmatch(self.operator_identity) is None
            or self.operator_identity.endswith(".iam.gserviceaccount.com")
            or _API_AUDIENCE.fullmatch(self.operator_audience) is None
            or self.operator_issued_at >= self.operator_expires_at
            or self.operator_expires_at - self.operator_issued_at
            > _MAX_ID_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError("promotion invocation bindings are invalid")
        return self


class PromotionCapabilityIssuanceCommandV2(StrictContractModel):
    """Coordinator preconditions for one health-authorized promotion capability."""

    schema_version: Literal["controlgraph.promotion-capability-issuance-command/v2"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    scheduled_at: UtcSecond
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1
    authorization: PromotionAuthorizationV1

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        authorization = self.authorization
        if (
            type(authorization) is not PromotionAuthorizationV1
            or self.root_id != authorization.root_id
            or self.expected_root_sha256 != authorization.root_sha256
            or self.expected_epoch != authorization.epoch
            or self.request_id != authorization.request_id
            or self.idempotency_key != authorization.idempotency_key
            or self.scheduled_at != authorization.scheduled_at
            or self.verified_apply_receipt != authorization.verified_apply_receipt
        ):
            raise ValueError("promotion issuance command does not match its authorization")
        return self


class PromotionMutationIntentV2(StrictContractModel):
    """Promotion-only mutation intent carrying the authorization used for issuance."""

    schema_version: Literal["controlgraph.promotion-mutation-intent/v2"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    action: Literal[CapabilityAction.PROMOTE_CANDIDATE]
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    stable_percent: Literal[0]
    candidate_percent: Literal[100]
    concurrency: None
    plan_sha256: Sha256Digest
    provider_etag: OpaqueToken
    capability_id: Identifier
    promotion_authorization_sha256: Sha256Digest
    expected_prestate_sha256: Sha256Digest
    terminal_health_decision_sha256: Sha256Digest
    health_chain_sha256: Sha256Digest
    desired_poststate_sha256: Sha256Digest
    proof_valid_until: UtcSecond
    authorization: PromotionAuthorizationV1

    @model_validator(mode="after")
    def validate_intent(self) -> Self:
        authorization = self.authorization
        if (
            type(authorization) is not PromotionAuthorizationV1
            or self.request_id != authorization.request_id
            or self.idempotency_key != authorization.idempotency_key
            or self.target != authorization.target
            or self.root_id != authorization.root_id
            or self.root_sha256 != authorization.root_sha256
            or self.epoch != authorization.epoch
            or self.stable_revision != authorization.stable_revision
            or self.candidate_revision != authorization.candidate_revision
            or self.stable_percent != authorization.stable_percent
            or self.candidate_percent != authorization.candidate_percent
            or self.plan_sha256 != authorization.plan_sha256
            or self.provider_etag != authorization.provider_etag
            or self.capability_id != promotion_capability_id(authorization)
            or self.promotion_authorization_sha256 != canonical_sha256(authorization)
            or self.expected_prestate_sha256 != authorization.expected_prestate_sha256
            or self.terminal_health_decision_sha256
            != authorization.terminal_health_decision_sha256
            or self.health_chain_sha256
            != authorization.health_chain_locator.health_chain_sha256
            or self.desired_poststate_sha256 != authorization.desired_poststate_sha256
            or self.proof_valid_until != authorization.proof_valid_until
        ):
            raise ValueError("promotion mutation intent does not match its authorization")
        return self


class PromotionTaskRequestV2(StrictContractModel):
    """Addressed promotion task that cannot represent another mutation action."""

    schema_version: Literal["controlgraph.promotion-task-request/v2"]
    task_id: Identifier
    queue_region: Literal["us-central1"]
    handler_audience: Audience
    scheduled_at: UtcSecond
    expires_at: UtcSecond
    capability: SignedCapability
    intent: PromotionMutationIntentV2

    @model_validator(mode="after")
    def validate_task_bindings(self) -> Self:
        capability = self.capability
        intent = self.intent
        authorization = intent.authorization
        claims = capability.claims
        if (
            type(capability) is not SignedCapability
            or type(intent) is not PromotionMutationIntentV2
            or claims.action is not CapabilityAction.PROMOTE_CANDIDATE
            or claims.capability_id != promotion_capability_id(authorization)
            or claims.capability_id != intent.capability_id
            or self.task_id != f"task-{capability.claims_sha256}"
            or self.handler_audience != claims.audience
            or claims.issuer != authorization.issuer_identity
            or claims.subject != authorization.executor_identity
            or claims.audience != authorization.executor_audience
            or claims.signing_key_version
            != authorization.capability_signing_key_version
            or claims.parent_capability_sha256 is not None
            or claims.target != intent.target
            or claims.root_id != intent.root_id
            or claims.root_sha256 != intent.root_sha256
            or claims.epoch != intent.epoch
            or claims.stable_revision != intent.stable_revision
            or claims.candidate_revision != intent.candidate_revision
            or claims.stable_percent != intent.stable_percent
            or claims.candidate_percent != intent.candidate_percent
            or claims.concurrency is not None
            or claims.plan_sha256 != intent.plan_sha256
            or claims.provider_etag != intent.provider_etag
            or claims.request_id != intent.request_id
            or claims.idempotency_key != intent.idempotency_key
            or claims.not_before != authorization.scheduled_at
            or self.scheduled_at != authorization.scheduled_at
            or not authorization.healthy_promotion_proof.issued_at
            <= claims.issued_at
            <= claims.not_before
            or not claims.not_before
            <= self.scheduled_at
            < self.expires_at
            <= claims.expires_at
            <= authorization.proof_valid_until
        ):
            raise ValueError("promotion task does not match its capability and authorization")
        _require_canonical_size(
            self,
            maximum_bytes=MAX_PROMOTION_TASK_CANONICAL_BYTES,
            boundary="promotion task",
        )
        return self


class PromotionDispatchIdentityV2(StrictContractModel):
    """Immutable request ownership for a V2 health-authorized promotion."""

    schema_version: Literal["controlgraph.promotion-dispatch-identity/v2"]
    identity_kind: PromotionDispatchIdentityKind
    identity_value: Identifier
    dispatch_id: Identifier
    command_sha256: Sha256Digest
    promotion_authorization_sha256: Sha256Digest
    capability_id: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    scheduled_at: UtcSecond
    source_receipt_sha256: Sha256Digest
    health_chain_sha256: Sha256Digest
    claimed_at: UtcSecond

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if (
            self.dispatch_id != promotion_dispatch_v2_id(self.command_sha256)
            or re.fullmatch(r"cgcap-[0-9a-f]{64}", self.capability_id) is None
        ):
            raise ValueError("V2 promotion dispatch identity is invalid")
        return self


class PromotionDispatchResultV2(StrictContractModel):
    """Compact result bound to the complete authorization carried by its command."""

    schema_version: Literal["controlgraph.promotion-dispatch-result/v2"]
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
    source_receipt_sha256: Sha256Digest
    expected_prestate_sha256: Sha256Digest
    terminal_health_decision_sha256: Sha256Digest
    health_chain_sha256: Sha256Digest
    health_chain_locator: PromotionHealthChainLocatorV1
    healthy_promotion_proof_sha256: Sha256Digest
    desired_poststate_sha256: Sha256Digest
    proof_valid_until: UtcSecond
    promotion_authorization_sha256: Sha256Digest
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
            or self.source_receipt_sha256 != self.verified_apply_receipt.receipt_sha256
            or self.health_chain_sha256 != self.health_chain_locator.health_chain_sha256
            or re.fullmatch(r"cgcap-[0-9a-f]{64}", self.capability_id) is None
            or not self.scheduled_at < self.expires_at <= self.proof_valid_until
        ):
            raise ValueError("V2 promotion dispatch result bindings are invalid")
        return self


class PromotionDispatchRecordV2(StrictContractModel):
    """Durable exact V2 promotion task and monotonic enqueue outcome."""

    schema_version: Literal["controlgraph.promotion-dispatch-record/v2"]
    dispatch_id: Identifier
    command_sha256: Sha256Digest
    promotion_authorization_sha256: Sha256Digest
    capability_id: Identifier
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    scheduled_at: UtcSecond
    source_receipt_sha256: Sha256Digest
    health_chain_sha256: Sha256Digest
    task_sha256: Sha256Digest
    task_name: BoundedText
    task: PromotionTaskRequestV2
    state: PromotionDispatchState
    prepared_at: UtcSecond
    enqueue_started_at: UtcSecond | None
    terminal_at: UtcSecond | None
    result: PromotionDispatchResultV2 | None

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        task = self.task
        intent = task.intent
        authorization = intent.authorization
        command = PromotionCommandV2(
            schema_version=PROMOTION_COMMAND_V2,
            root_id=authorization.root_id,
            expected_root_sha256=authorization.root_sha256,
            expected_epoch=authorization.epoch,
            request_id=authorization.request_id,
            idempotency_key=authorization.idempotency_key,
            scheduled_at=authorization.scheduled_at,
            verified_apply_receipt=authorization.verified_apply_receipt,
            health_chain_locator=authorization.health_chain_locator,
        )
        claims = task.capability.claims
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
            type(task) is not PromotionTaskRequestV2
            or self.command_sha256 != promotion_command_v2_sha256(command)
            or self.dispatch_id != promotion_dispatch_v2_id(self.command_sha256)
            or self.promotion_authorization_sha256 != canonical_sha256(authorization)
            or self.capability_id != promotion_capability_id(authorization)
            or self.request_id != authorization.request_id
            or self.idempotency_key != authorization.idempotency_key
            or self.target != authorization.target
            or self.root_id != authorization.root_id
            or self.root_sha256 != authorization.root_sha256
            or self.epoch != authorization.epoch
            or self.scheduled_at != authorization.scheduled_at
            or self.source_receipt_sha256 != authorization.source_receipt_sha256
            or self.health_chain_sha256
            != authorization.health_chain_locator.health_chain_sha256
            or self.task_sha256 != canonical_sha256(task)
            or self.task_name != expected_task_name
            or claims.capability_id != self.capability_id
        ):
            raise ValueError("V2 promotion dispatch task binding is invalid")
        if self.state is PromotionDispatchState.PREPARED:
            if any(
                value is not None
                for value in (self.enqueue_started_at, self.terminal_at, self.result)
            ):
                raise ValueError("prepared V2 promotion dispatch shape is invalid")
            return self
        if self.enqueue_started_at is None or self.enqueue_started_at < self.prepared_at:
            raise ValueError("V2 promotion enqueue start is invalid")
        if self.state is PromotionDispatchState.ENQUEUE_STARTED:
            if self.terminal_at is not None or self.result is not None:
                raise ValueError("started V2 promotion dispatch shape is invalid")
            return self
        result = self.result
        if (
            not terminal
            or self.terminal_at is None
            or self.terminal_at < self.enqueue_started_at
            or result is None
            or result.enqueue_disposition != self.state.value
            or result.request_id != self.request_id
            or result.idempotency_key != self.idempotency_key
            or result.target != self.target
            or result.root_id != self.root_id
            or result.root_sha256 != self.root_sha256
            or result.epoch != self.epoch
            or result.stable_revision != authorization.stable_revision
            or result.candidate_revision != authorization.candidate_revision
            or result.provider_etag != authorization.provider_etag
            or result.verified_apply_receipt != authorization.verified_apply_receipt
            or result.source_receipt_sha256 != authorization.source_receipt_sha256
            or result.expected_prestate_sha256 != authorization.expected_prestate_sha256
            or result.terminal_health_decision_sha256
            != authorization.terminal_health_decision_sha256
            or result.health_chain_sha256
            != authorization.health_chain_locator.health_chain_sha256
            or result.health_chain_locator != authorization.health_chain_locator
            or result.healthy_promotion_proof_sha256
            != authorization.healthy_promotion_proof_sha256
            or result.desired_poststate_sha256 != authorization.desired_poststate_sha256
            or result.proof_valid_until != authorization.proof_valid_until
            or result.promotion_authorization_sha256
            != self.promotion_authorization_sha256
            or result.capability_id != self.capability_id
            or result.capability_sha256 != canonical_sha256(task.capability)
            or result.task_id != task.task_id
            or result.task_name != self.task_name
            or result.scheduled_at != self.scheduled_at
            or result.expires_at != task.expires_at
        ):
            raise ValueError("terminal V2 promotion dispatch shape is invalid")
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


def create_verified_apply_receipt_locator(
    receipt: ExecutionReceipt,
) -> VerifiedApplyReceiptLocatorV1:
    """Project the exact immutable identity of one verified apply receipt."""

    if type(receipt) is not ExecutionReceipt:
        raise TypeError("promotion receipt projection requires an exact execution receipt")
    validated = ExecutionReceipt.model_validate(receipt)
    if (
        validated.action is not CapabilityAction.APPLY_CANARY
        or validated.outcome is not ReceiptOutcome.VERIFIED
        or validated.provider_operation is None
    ):
        raise ValueError("promotion requires a provider-confirmed verified apply receipt")
    return VerifiedApplyReceiptLocatorV1(
        schema_version=VERIFIED_APPLY_RECEIPT_LOCATOR_V1,
        receipt_id=validated.receipt_id,
        request_id=validated.request_id,
        idempotency_key=validated.idempotency_key,
        capability_sha256=validated.capability_sha256,
        mutation_sha256=validated.mutation_sha256,
        expected_poststate_sha256=validated.expected_poststate_sha256,
        provider_operation=validated.provider_operation,
        receipt_sha256=canonical_sha256(validated),
    )


def promotion_capability_id(authorization: PromotionAuthorizationV1) -> str:
    """Recompute the sole capability identifier for a complete authorization."""

    if type(authorization) is not PromotionAuthorizationV1:
        raise TypeError("promotion capability identity requires an exact authorization")
    projection = cast(
        RestrictedJson,
        authorization.model_dump(mode="json", exclude={"capability_id"}),
    )
    digest = hashlib.sha256(
        _PROMOTION_CAPABILITY_ID_DOMAIN + canonical_json_value_bytes(projection)
    ).hexdigest()
    return f"cgcap-{digest}"


def create_promotion_health_chain_locator(
    signed_health_chain: SignedHealthDecisionChainV1,
) -> PromotionHealthChainLocatorV1:
    """Project one full durable chain into its exact compact lookup manifest."""

    if type(signed_health_chain) is not SignedHealthDecisionChainV1:
        raise TypeError("promotion locator requires an exact signed health chain")
    validated_chain = SignedHealthDecisionChainV1.model_validate(signed_health_chain)
    compact = validated_chain.healthy_promotion_proof
    if compact is None:
        raise ValueError("promotion locator requires a terminal healthy chain")
    return PromotionHealthChainLocatorV1(
        schema_version=PROMOTION_HEALTH_CHAIN_LOCATOR_V1,
        anchor_id=validated_chain.anchor.anchor_id,
        anchor_sha256=validated_chain.anchor_sha256,
        chain_id=validated_chain.chain_id,
        health_chain_sha256=signed_health_decision_chain_sha256(validated_chain),
        chain_head_sha256=validated_chain.chain_head_sha256,
        ordered_proof_chain_sha256=signed_health_proof_chain_sha256(
            validated_chain.signed_proofs
        ),
        terminal_sequence=compact.terminal_sequence,
    )


def create_promotion_authorization(
    *,
    root: RolloutRootV3,
    signed_health_chain: SignedHealthDecisionChainV1,
    request_id: str,
    idempotency_key: str,
    scheduled_at: str,
) -> PromotionAuthorizationV1:
    """Derive one self-identifying authorization from an exact healthy V3 chain."""

    if type(root) is not RolloutRootV3:
        raise TypeError("promotion authorization requires an exact RolloutRootV3")
    if type(signed_health_chain) is not SignedHealthDecisionChainV1:
        raise TypeError("promotion authorization requires an exact signed health chain")
    validated_root = RolloutRootV3.model_validate(root)
    validated_chain = SignedHealthDecisionChainV1.model_validate(signed_health_chain)
    compact = validated_chain.healthy_promotion_proof
    anchor = validated_chain.anchor
    if (
        compact is None
        or validated_chain.signed_proofs[-1].proof.decision.status
        is not HealthDecisionStatus.HEALTHY
    ):
        raise ValueError("promotion authorization requires a terminal healthy proof")
    try:
        expected_anchor = create_post_apply_health_anchor(
            root=validated_root,
            apply_receipt=anchor.apply_receipt,
        )
    except (TypeError, ValueError):
        raise ValueError("promotion authorization chain is outside its V3 root") from None
    if expected_anchor != anchor:
        raise ValueError("promotion authorization chain is outside its V3 root")
    plan = validated_root.content.rollout_plan
    bounds = validated_root.content.authority_bounds
    locator = create_verified_apply_receipt_locator(anchor.apply_receipt)
    chain_locator = create_promotion_health_chain_locator(validated_chain)
    values: dict[str, object] = {
        "schema_version": PROMOTION_AUTHORIZATION_V1,
        "capability_id": "pending",
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "scheduled_at": scheduled_at,
        "root_schema_version": validated_root.schema_version,
        "root_id": validated_root.root_id,
        "root_sha256": validated_root.root_sha256,
        "target": validated_root.content.target,
        "epoch": anchor.epoch,
        "plan_sha256": canonical_sha256(plan),
        "policy_schema_version": validated_root.content.health_policy.schema_version,
        "policy_sha256": canonical_sha256(validated_root.content.health_policy),
        "stable_snapshot_sha256": canonical_sha256(validated_root.content.stable_snapshot),
        "stable_revision": plan.stable_revision,
        "stable_revision_configuration_sha256": (
            plan.stable_revision_configuration_sha256
        ),
        "candidate_revision": plan.candidate_revision,
        "candidate_revision_configuration_sha256": (
            plan.candidate_revision_configuration_sha256
        ),
        "concurrency": plan.concurrency,
        "evidence_signing_key_version": (
            validated_root.content.evidence_signing_key_version
        ),
        "capability_signing_key_version": bounds.capability_signing_key_version,
        "issuer_identity": bounds.issuer_identity,
        "executor_identity": bounds.executor_identity,
        "executor_audience": bounds.executor_audience,
        "expected_stable_percent": 90,
        "expected_candidate_percent": 10,
        "expected_prestate_sha256": compact.expected_prestate_sha256,
        "provider_etag": anchor.provider_etag,
        "verified_apply_receipt": locator,
        "source_receipt_sha256": compact.source_receipt_sha256,
        "health_chain_locator": chain_locator,
        "terminal_health_decision_sha256": compact.terminal_health_decision_sha256,
        "healthy_promotion_proof_sha256": canonical_sha256(compact),
        "healthy_promotion_proof": compact,
        "stable_percent": 0,
        "candidate_percent": 100,
        "desired_poststate_sha256": compact.desired_poststate_sha256,
        "proof_valid_until": compact.valid_until,
    }
    draft = PromotionAuthorizationV1.model_construct(_fields_set=None, **values)
    values["capability_id"] = promotion_capability_id(draft)
    return PromotionAuthorizationV1.model_validate(values)


def promotion_command_v2_sha256(command: PromotionCommandV2) -> str:
    """Hash every V2 command binding under a version-separated domain."""

    if type(command) is not PromotionCommandV2:
        raise TypeError("V2 promotion hashing requires an exact command")
    return hashlib.sha256(
        _PROMOTION_COMMAND_V2_DIGEST_DOMAIN + canonical_json_bytes(command)
    ).hexdigest()


def promotion_dispatch_v2_id(command_sha256: str) -> str:
    """Return the immutable V2 dispatch identity for one command digest."""

    if re.fullmatch(r"[0-9a-f]{64}", command_sha256) is None:
        raise ValueError("V2 promotion command digest is invalid")
    return f"cgpromotev2:{command_sha256}"


__all__ = [
    "MAX_PROMOTION_TASK_CANONICAL_BYTES",
    "PROMOTION_AUTHORIZATION_V1",
    "PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V1",
    "PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V2",
    "PROMOTION_COMMAND_V1",
    "PROMOTION_COMMAND_V2",
    "PROMOTION_DISPATCH_IDENTITY_V1",
    "PROMOTION_DISPATCH_IDENTITY_V2",
    "PROMOTION_DISPATCH_RECORD_V1",
    "PROMOTION_DISPATCH_RECORD_V2",
    "PROMOTION_DISPATCH_RESULT_V1",
    "PROMOTION_DISPATCH_RESULT_V2",
    "PROMOTION_HEALTH_CHAIN_LOCATOR_V1",
    "PROMOTION_INVOCATION_V1",
    "PROMOTION_INVOCATION_V2",
    "PROMOTION_MUTATION_INTENT_V2",
    "PROMOTION_TASK_REQUEST_V2",
    "VERIFIED_APPLY_RECEIPT_LOCATOR_V1",
    "PromotionAuthorizationV1",
    "PromotionCapabilityIssuanceCommandV1",
    "PromotionCapabilityIssuanceCommandV2",
    "PromotionCommandV1",
    "PromotionCommandV2",
    "PromotionDispatchIdentityKind",
    "PromotionDispatchIdentityV1",
    "PromotionDispatchIdentityV2",
    "PromotionDispatchRecordV1",
    "PromotionDispatchRecordV2",
    "PromotionDispatchResultV1",
    "PromotionDispatchResultV2",
    "PromotionDispatchState",
    "PromotionHealthChainLocatorV1",
    "PromotionInvocationV1",
    "PromotionInvocationV2",
    "PromotionMutationIntentV2",
    "PromotionTaskRequestV2",
    "VerifiedApplyReceiptLocatorV1",
    "create_promotion_authorization",
    "create_promotion_health_chain_locator",
    "create_verified_apply_receipt_locator",
    "promotion_capability_id",
    "promotion_command_sha256",
    "promotion_command_v2_sha256",
    "promotion_dispatch_id",
    "promotion_dispatch_v2_id",
]
