"""Canonical contracts for stable-only recovery orchestration and execution."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    Base64Url,
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
    DIGEST_DOMAIN,
    ContractError,
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    canonical_sha256,
    decode_base64url,
    encode_base64url,
)
from controlgraph_canary.contracts.health import HealthDecisionStatus
from controlgraph_canary.contracts.health_execution import (
    SignedHealthDecisionChainV1,
    health_chain_manifest_sha256,
    signed_health_decision_chain_sha256,
    signed_health_proof_chain_sha256,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
)
from controlgraph_canary.contracts.revocation import EpochRevocationProofV1
from controlgraph_canary.contracts.root_creation import RolloutRootV2, RolloutRootV3

RECOVERY_HEALTH_CHAIN_LOCATOR_V1: Final = "controlgraph.recovery-health-chain-locator/v1"
RECOVERY_APPLY_RECEIPT_LOCATOR_V1: Final = "controlgraph.recovery-apply-receipt-locator/v1"
UNHEALTHY_RECOVERY_SOURCE_V1: Final = "controlgraph.unhealthy-recovery-source/v1"
REVOKED_V2_RECOVERY_SOURCE_V1: Final = "controlgraph.revoked-v2-recovery-source/v1"
REVOKED_V3_RECOVERY_SOURCE_V1: Final = "controlgraph.revoked-v3-recovery-source/v1"
RECOVERY_COMMAND_V2: Final = "controlgraph.recovery-command/v2"
RECOVERY_INVOCATION_V2: Final = "controlgraph.recovery-invocation/v2"
RECOVERY_INTENT_V1: Final = "controlgraph.recovery-intent/v1"
RECOVERY_PRESTATE_REQUEST_V1: Final = "controlgraph.recovery-prestate-request/v1"
RECOVERY_PRESTATE_RESULT_V1: Final = "controlgraph.recovery-prestate-result/v1"
RECOVERY_PRESTATE_SIGNING_REQUEST_V1: Final = "controlgraph.recovery-prestate-signing-request/v1"
RECOVERY_PRESTATE_ATTESTATION_V1: Final = "controlgraph.recovery-prestate-attestation/v1"
RECOVERY_AUTHORIZATION_V1: Final = "controlgraph.recovery-authorization/v1"
RECOVERY_CAPABILITY_ISSUANCE_COMMAND_V2: Final = (
    "controlgraph.recovery-capability-issuance-command/v2"
)
RECOVERY_CAPABILITY_ISSUANCE_RESULT_V2: Final = (
    "controlgraph.recovery-capability-issuance-result/v2"
)
RECOVERY_MUTATION_INTENT_V2: Final = "controlgraph.recovery-mutation-intent/v2"
RECOVERY_TASK_REQUEST_V2: Final = "controlgraph.recovery-task-request/v2"
RECOVERY_DISPATCH_IDENTITY_V2: Final = "controlgraph.recovery-dispatch-identity/v2"
RECOVERY_DISPATCH_RESULT_V2: Final = "controlgraph.recovery-dispatch-result/v2"
RECOVERY_DISPATCH_RECORD_V2: Final = "controlgraph.recovery-dispatch-record/v2"
RECOVERY_RECEIPT_LOCATOR_V1: Final = "controlgraph.recovery-receipt-locator/v1"

RECOVER_CAPTURED_STABLE: Final = "RECOVER_CAPTURED_STABLE"
RECOVERY_PRESTATE_ATTESTATION_PURPOSE: Final = "RECOVERY_PRESTATE_ATTESTATION"
P256_SIGNING_ALGORITHM: Final = "EC_SIGN_P256_SHA256"
MAX_RECOVERY_TASK_CANONICAL_BYTES: Final = 64_000

_COMMAND_DIGEST_DOMAIN: Final = b"controlgraph.recovery-command-sha256/v2\0"
_INTENT_DIGEST_DOMAIN: Final = b"controlgraph.recovery-intent-id/v1\0"
_TRIGGER_DIGEST_DOMAIN: Final = b"controlgraph.recovery-trigger-proof-sha256/v1\0"
_PRESTATE_REQUEST_ID_DOMAIN: Final = b"controlgraph.recovery-prestate-request-id/v1\0"
_PRESTATE_RESULT_ID_DOMAIN: Final = b"controlgraph.recovery-prestate-result-id/v1\0"
_PRESTATE_SIGNING_REQUEST_ID_DOMAIN: Final = (
    b"controlgraph.recovery-prestate-signing-request-id/v1\0"
)
_PRESTATE_SIGNING_INPUT_DOMAIN: Final = b"controlgraph.recovery-prestate-signature-input/v1\0"
_CAPABILITY_ID_DOMAIN: Final = b"controlgraph.recovery-capability-id/v1\0"
_ISSUANCE_COMMAND_DIGEST_DOMAIN: Final = (
    b"controlgraph.recovery-capability-issuance-command-sha256/v2\0"
)
_DISPATCH_ID_DOMAIN: Final = b"controlgraph.recovery-dispatch-id/v2\0"
_TARGET_CONFIGURATION_DOMAIN: Final = b"controlgraph.target-configuration-sha256/v1\0"
_TARGET_CONFIGURATION_V1: Final = "controlgraph.target-configuration/v1"

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$")
_RECOVERY_AUDIENCE = re.compile(
    r"^https://controlgraph-recovery-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)
_RECOVERY_TASK_NAME = re.compile(
    r"^projects/(controlgraph-canary-[a-z0-9]{6,10})/locations/us-central1/"
    r"queues/controlgraph-recovery/tasks/cg-[0-9a-f]{64}$"
)
_EVIDENCE_KEY = re.compile(
    r"^projects/(?P<project>controlgraph-canary-[a-z0-9]{6,10})/"
    r"locations/us-central1/keyRings/controlgraph-signing/"
    r"cryptoKeys/evidence-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
_CAPABILITY_KEY = re.compile(
    r"^projects/(?P<project>controlgraph-canary-[a-z0-9]{6,10})/"
    r"locations/us-central1/keyRings/controlgraph-signing/"
    r"cryptoKeys/capability-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
_MAX_ID_TOKEN_LIFETIME_SECONDS: Final = 3_660
_MAX_PRESTATE_LIFETIME_SECONDS: Final = 300

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


class RecoveryTriggerBasis(StrEnum):
    """Closed sources that may authorize captured-stable recovery."""

    TERMINAL_UNHEALTHY_V3 = "TERMINAL_UNHEALTHY_V3"
    OPERATOR_CONFIRMED_REVOKED_V2 = "OPERATOR_CONFIRMED_REVOKED_V2"
    OPERATOR_CONFIRMED_REVOKED_V3 = "OPERATOR_CONFIRMED_REVOKED_V3"


class RecoveryDispatchIdentityKind(StrEnum):
    """Independent identities reserved for one canonical recovery."""

    REQUEST = "REQUEST"
    IDEMPOTENCY = "IDEMPOTENCY"


class RecoveryDispatchState(StrEnum):
    """Monotonic states around the sole permitted recovery enqueue attempt."""

    PREPARED = "PREPARED"
    ENQUEUE_STARTED = "ENQUEUE_STARTED"
    CREATED = "CREATED"
    DUPLICATE = "DUPLICATE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class _RootBindings:
    schema_version: str
    root_id: str
    root_sha256: str
    target: TargetBinding
    plan_sha256: str
    stable_snapshot_sha256: str
    stable_revision: str
    stable_revision_configuration_sha256: str
    candidate_revision: str
    candidate_revision_configuration_sha256: str
    concurrency: int
    evidence_signing_key_version: str
    capability_signing_key_version: str
    issuer_identity: str
    recovery_identity: str
    recovery_audience: str
    maximum_capability_lifetime_seconds: int


def _seconds(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _target_is_exact(target: TargetBinding) -> bool:
    return (
        type(target) is TargetBinding
        and _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is not None
        and "reconcile" not in target.project_id.lower()
        and target.region == "us-central1"
        and target.environment == "nonprod"
        and target.service_name == _REFERENCE_SERVICE
    )


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


def _content_id(
    value: StrictContractModel,
    *,
    id_field: str,
    prefix: str,
    domain: bytes,
) -> str:
    projection = cast(
        RestrictedJson,
        value.model_dump(mode="json", exclude={id_field}),
    )
    return f"{prefix}{hashlib.sha256(domain + canonical_json_value_bytes(projection)).hexdigest()}"


def _validated_contract_sha256(value: StrictContractModel) -> str:
    """Hash a nested model already revalidated by its containing contract."""

    projection = cast(RestrictedJson, value.model_dump(mode="json"))
    if type(projection) is not dict:
        raise TypeError("contract projection must be an object")
    schema_version = projection.get("schema_version")
    if type(schema_version) is not str:
        raise ValueError("contract projection lacks a schema version")
    return hashlib.sha256(
        DIGEST_DOMAIN
        + schema_version.encode("ascii")
        + b"\0"
        + canonical_json_value_bytes(projection)
    ).hexdigest()


def _root_bindings(root: RolloutRootV2 | RolloutRootV3) -> _RootBindings:
    if type(root) not in (RolloutRootV2, RolloutRootV3):
        raise TypeError("recovery requires an exact RolloutRootV2 or RolloutRootV3")
    validated = type(root).model_validate(root)
    content = validated.content
    plan = content.rollout_plan
    bounds = content.authority_bounds
    return _RootBindings(
        schema_version=validated.schema_version,
        root_id=validated.root_id,
        root_sha256=validated.root_sha256,
        target=content.target,
        plan_sha256=canonical_sha256(plan),
        stable_snapshot_sha256=canonical_sha256(content.stable_snapshot),
        stable_revision=plan.stable_revision,
        stable_revision_configuration_sha256=(plan.stable_revision_configuration_sha256),
        candidate_revision=plan.candidate_revision,
        candidate_revision_configuration_sha256=(plan.candidate_revision_configuration_sha256),
        concurrency=plan.concurrency,
        evidence_signing_key_version=content.evidence_signing_key_version,
        capability_signing_key_version=bounds.capability_signing_key_version,
        issuer_identity=bounds.issuer_identity,
        recovery_identity=bounds.recovery_identity,
        recovery_audience=bounds.recovery_audience,
        maximum_capability_lifetime_seconds=bounds.maximum_capability_lifetime_seconds,
    )


def recovery_target_configuration_sha256(
    root: RolloutRootV2 | RolloutRootV3,
    *,
    stable_percent: Literal[90, 100],
    candidate_percent: Literal[10, 0],
) -> str:
    """Hash one exact root-derived recovery prestate or poststate."""

    bindings = _root_bindings(root)
    if (stable_percent, candidate_percent) not in {(90, 10), (100, 0)}:
        raise ValueError("recovery target configuration must be exact 90/10 or 100/0")
    value: RestrictedJson = {
        "candidate_percent": candidate_percent,
        "candidate_revision": bindings.candidate_revision,
        "concurrency": bindings.concurrency,
        "schema_version": _TARGET_CONFIGURATION_V1,
        "stable_percent": stable_percent,
        "stable_revision": bindings.stable_revision,
        "target": bindings.target.model_dump(mode="json"),
    }
    return hashlib.sha256(
        _TARGET_CONFIGURATION_DOMAIN + canonical_json_value_bytes(value)
    ).hexdigest()


class RecoveryApplyReceiptLocatorV1(StrictContractModel):
    """Exact durable verified APPLY receipt, including its storage revision."""

    schema_version: Literal["controlgraph.recovery-apply-receipt-locator/v1"]
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
    action: Literal[CapabilityAction.APPLY_CANARY]
    provider_etag: OpaqueToken
    provider_operation: BoundedText
    observed_etag: OpaqueToken
    observed_authority_epoch: PositiveSafeInteger
    receipt_sha256: Sha256Digest
    storage_revision: Annotated[int, Field(ge=2, le=9_007_199_254_740_991)]

    @model_validator(mode="after")
    def validate_locator(self) -> Self:
        if (
            not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.root_sha256}"
            or self.observed_authority_epoch != self.epoch
        ):
            raise ValueError("recovery apply receipt locator bindings are invalid")
        return self


class RecoveryHealthChainLocatorV1(StrictContractModel):
    """Exact durable lookup for one terminal-unhealthy signed health chain."""

    schema_version: Literal["controlgraph.recovery-health-chain-locator/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    anchor_id: Identifier
    anchor_sha256: Sha256Digest
    chain_id: Identifier
    health_chain_sha256: Sha256Digest
    chain_head_sha256: Sha256Digest
    ordered_proof_chain_sha256: Sha256Digest
    terminal_sequence: Annotated[int, Field(ge=1, le=20)]
    terminal_status: Literal[HealthDecisionStatus.UNHEALTHY]
    terminal_signed_proof_sha256: Sha256Digest
    terminal_health_decision_sha256: Sha256Digest
    source_receipt_sha256: Sha256Digest
    expected_prestate_sha256: Sha256Digest
    terminal_decided_at: UtcSecond

    @model_validator(mode="after")
    def validate_locator(self) -> Self:
        if (
            not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.root_sha256}"
            or not self.anchor_id.startswith("cghealthanchor:")
            or self.chain_id != f"cghealthchain:{self.health_chain_sha256}"
            or self.health_chain_sha256
            != health_chain_manifest_sha256(
                anchor_sha256=self.anchor_sha256,
                ordered_proof_chain_sha256=self.ordered_proof_chain_sha256,
                chain_head_sha256=self.chain_head_sha256,
                healthy_promotion_proof_sha256=None,
            )
            or self.chain_head_sha256 != self.terminal_signed_proof_sha256
        ):
            raise ValueError("recovery health-chain locator bindings are invalid")
        return self


class UnhealthyRecoverySourceV1(StrictContractModel):
    """A V3 recovery trigger selected only by a terminal unhealthy chain."""

    schema_version: Literal["controlgraph.unhealthy-recovery-source/v1"]
    basis: Literal[RecoveryTriggerBasis.TERMINAL_UNHEALTHY_V3]
    root_schema_version: Literal["controlgraph.rollout-root/v3"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    health_chain_locator: RecoveryHealthChainLocatorV1
    triggered_at: UtcSecond

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        locator = self.health_chain_locator
        if (
            self.root_id != locator.root_id
            or self.root_sha256 != locator.root_sha256
            or self.target != locator.target
            or self.epoch != locator.epoch
            or self.triggered_at != locator.terminal_decided_at
        ):
            raise ValueError("unhealthy recovery source is outside its terminal chain")
        return self


class RevokedV2RecoverySourceV1(StrictContractModel):
    """Explicit compatibility trigger for a revoked legacy V2 rollout root."""

    schema_version: Literal["controlgraph.revoked-v2-recovery-source/v1"]
    basis: Literal[RecoveryTriggerBasis.OPERATOR_CONFIRMED_REVOKED_V2]
    root_schema_version: Literal["controlgraph.rollout-root/v2"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    confirmation: Literal["RECOVER_CAPTURED_STABLE"]
    revocation_proof: EpochRevocationProofV1
    revocation_proof_sha256: Sha256Digest
    triggered_at: UtcSecond

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        proof = self.revocation_proof
        result = proof.result
        if (
            not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.root_sha256}"
            or result.root_id != self.root_id
            or result.root_sha256 != self.root_sha256
            or result.target != self.target
            or result.new_epoch != self.epoch
            or proof.authority.current_epoch != self.epoch
            or proof.authority.previous_epoch != result.previous_epoch
            or self.revocation_proof_sha256 != canonical_sha256(proof)
            or self.triggered_at != result.committed_at
        ):
            raise ValueError("revoked V2 recovery source proof is invalid")
        return self


class RevokedV3RecoverySourceV1(StrictContractModel):
    """Explicit operator trigger for a revoked current V3 rollout root."""

    schema_version: Literal["controlgraph.revoked-v3-recovery-source/v1"]
    basis: Literal[RecoveryTriggerBasis.OPERATOR_CONFIRMED_REVOKED_V3]
    root_schema_version: Literal["controlgraph.rollout-root/v3"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    confirmation: Literal["RECOVER_CAPTURED_STABLE"]
    revocation_proof: EpochRevocationProofV1
    revocation_proof_sha256: Sha256Digest
    triggered_at: UtcSecond

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        proof = self.revocation_proof
        result = proof.result
        if (
            not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.root_sha256}"
            or result.root_id != self.root_id
            or result.root_sha256 != self.root_sha256
            or result.target != self.target
            or result.new_epoch != self.epoch
            or proof.authority.current_epoch != self.epoch
            or proof.authority.previous_epoch != result.previous_epoch
            or self.revocation_proof_sha256 != canonical_sha256(proof)
            or self.triggered_at != result.committed_at
        ):
            raise ValueError("revoked V3 recovery source proof is invalid")
        return self


type RecoverySourceV1 = Annotated[
    UnhealthyRecoverySourceV1 | RevokedV2RecoverySourceV1 | RevokedV3RecoverySourceV1,
    Field(discriminator="basis"),
]
type RecoveryRolloutRoot = Annotated[
    RolloutRootV2 | RolloutRootV3,
    Field(discriminator="schema_version"),
]


class RecoveryCommandV2(StrictContractModel):
    """One recovery request with no caller-selectable mutation coordinates."""

    schema_version: Literal["controlgraph.recovery-command/v2"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    scheduled_at: UtcSecond
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1
    source: RecoverySourceV1

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        receipt = self.verified_apply_receipt
        source = self.source
        if (
            self.root_id != f"cgroot:{self.expected_root_sha256}"
            or self.root_id != source.root_id
            or self.expected_root_sha256 != source.root_sha256
            or self.expected_epoch != source.epoch
            or receipt.root_id != self.root_id
            or receipt.root_sha256 != self.expected_root_sha256
            or receipt.target != source.target
            or receipt.plan_sha256 == "0" * 64
            or self.scheduled_at < source.triggered_at
        ):
            raise ValueError("recovery command bindings are invalid")
        if type(source) is UnhealthyRecoverySourceV1:
            if (
                receipt.epoch != self.expected_epoch
                or receipt.receipt_sha256 != source.health_chain_locator.source_receipt_sha256
                or receipt.expected_poststate_sha256
                != source.health_chain_locator.expected_prestate_sha256
            ):
                raise ValueError("unhealthy recovery command receipt is invalid")
        elif type(source) is RevokedV2RecoverySourceV1:
            if receipt.epoch != source.revocation_proof.result.previous_epoch:
                raise ValueError("revoked V2 recovery command receipt is invalid")
        elif type(source) is RevokedV3RecoverySourceV1:
            if receipt.epoch != source.revocation_proof.result.previous_epoch:
                raise ValueError("revoked V3 recovery command receipt is invalid")
        else:
            raise ValueError("recovery command source is invalid")
        return self


class RecoveryIntentV1(StrictContractModel):
    """Root-unique ownership of the command selected for stable recovery."""

    schema_version: Literal["controlgraph.recovery-intent/v1"]
    intent_id: Identifier
    command: RecoveryCommandV2
    command_sha256: Sha256Digest
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    source_receipt_sha256: Sha256Digest
    trigger_basis: RecoveryTriggerBasis
    trigger_proof_sha256: Sha256Digest
    created_at: UtcSecond

    @model_validator(mode="after")
    def validate_intent(self) -> Self:
        command = self.command
        if (
            self.intent_id != recovery_intent_id(self.root_sha256)
            or self.command_sha256 != recovery_command_sha256(command)
            or self.root_id != command.root_id
            or self.root_sha256 != command.expected_root_sha256
            or self.epoch != command.expected_epoch
            or self.request_id != command.request_id
            or self.idempotency_key != command.idempotency_key
            or self.source_receipt_sha256 != command.verified_apply_receipt.receipt_sha256
            or self.trigger_basis is not command.source.basis
            or self.trigger_proof_sha256 != recovery_trigger_proof_sha256(command.source)
            or self.created_at < command.source.triggered_at
            or self.created_at > command.scheduled_at
        ):
            raise ValueError("recovery intent bindings are invalid")
        return self


class RecoveryInvocationV2(StrictContractModel):
    """Authenticated operator invocation for explicit revoked-root recovery."""

    schema_version: Literal["controlgraph.recovery-invocation/v2"]
    command: RecoveryCommandV2
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        source = self.command.source
        if type(source) not in (RevokedV2RecoverySourceV1, RevokedV3RecoverySourceV1):
            raise ValueError("recovery invocation bindings are invalid")
        revoked_source = cast(
            RevokedV2RecoverySourceV1 | RevokedV3RecoverySourceV1,
            source,
        )
        if (
            revoked_source.confirmation != RECOVER_CAPTURED_STABLE
            or self.operator_identity
            != revoked_source.revocation_proof.result.operator_identity
            or self.operator_subject
            != revoked_source.revocation_proof.result.operator_subject
            or _HUMAN_EMAIL.fullmatch(self.operator_identity) is None
            or self.operator_identity.endswith(".iam.gserviceaccount.com")
            or _API_AUDIENCE.fullmatch(self.operator_audience) is None
            or self.operator_issued_at >= self.operator_expires_at
            or self.operator_expires_at - self.operator_issued_at > _MAX_ID_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError("recovery invocation bindings are invalid")
        return self


class RecoveryPrestateRequestV1(StrictContractModel):
    """Verifier request derived from a root for an exact current 90/10 read."""

    schema_version: Literal["controlgraph.recovery-prestate-request/v1"]
    prestate_request_id: Identifier
    command: RecoveryCommandV2
    command_sha256: Sha256Digest
    root: RecoveryRolloutRoot
    root_schema_version: Literal["controlgraph.rollout-root/v2", "controlgraph.rollout-root/v3"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    plan_sha256: Sha256Digest
    stable_snapshot_sha256: Sha256Digest
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    stable_percent: Literal[90]
    candidate_percent: Literal[10]
    expected_prestate_sha256: Sha256Digest
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1
    source_receipt_sha256: Sha256Digest
    source_receipt_storage_revision: Annotated[int, Field(ge=2, le=9_007_199_254_740_991)]
    source: RecoverySourceV1
    trigger_proof_sha256: Sha256Digest
    verifier_identity: BoundedText
    evidence_signing_key_version: KeyVersionResource
    requested_at: UtcSecond
    valid_until: UtcSecond

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        bindings = _root_bindings(self.root)
        expected_prestate = recovery_target_configuration_sha256(
            self.root,
            stable_percent=90,
            candidate_percent=10,
        )
        duration = (_seconds(self.valid_until) - _seconds(self.requested_at)).total_seconds()
        if (
            self.command_sha256 != recovery_command_sha256(self.command)
            or self.root_schema_version != bindings.schema_version
            or self.root_id != bindings.root_id
            or self.root_sha256 != bindings.root_sha256
            or self.target != bindings.target
            or self.epoch != self.command.expected_epoch
            or self.plan_sha256 != bindings.plan_sha256
            or self.stable_snapshot_sha256 != bindings.stable_snapshot_sha256
            or self.stable_revision != bindings.stable_revision
            or self.stable_revision_configuration_sha256
            != bindings.stable_revision_configuration_sha256
            or self.candidate_revision != bindings.candidate_revision
            or self.candidate_revision_configuration_sha256
            != bindings.candidate_revision_configuration_sha256
            or self.concurrency != bindings.concurrency
            or self.expected_prestate_sha256 != expected_prestate
            or self.verified_apply_receipt != self.command.verified_apply_receipt
            or self.source_receipt_sha256 != self.verified_apply_receipt.receipt_sha256
            or self.source_receipt_storage_revision != self.verified_apply_receipt.storage_revision
            or self.source != self.command.source
            or self.trigger_proof_sha256 != recovery_trigger_proof_sha256(self.source)
            or self.verifier_identity
            != f"controlgraph-verifier@{self.target.project_id}.iam.gserviceaccount.com"
            or self.evidence_signing_key_version != bindings.evidence_signing_key_version
            or not self.source.triggered_at <= self.requested_at <= self.command.scheduled_at
            or not self.requested_at < self.valid_until
            or not self.command.scheduled_at < self.valid_until
            or not 1 <= duration <= _MAX_PRESTATE_LIFETIME_SECONDS
        ):
            raise ValueError("recovery prestate request bindings are invalid")
        if (
            type(self.root) is RolloutRootV3
            and type(self.source)
            not in (UnhealthyRecoverySourceV1, RevokedV3RecoverySourceV1)
        ) or (
            type(self.root) is RolloutRootV2 and type(self.source) is not RevokedV2RecoverySourceV1
        ):
            raise ValueError("recovery prestate request root mode is invalid")
        if self.prestate_request_id != recovery_prestate_request_id(self):
            raise ValueError("recovery prestate request identifier is not canonical")
        return self


class RecoveryPrestateResultV1(StrictContractModel):
    """Verifier-owned affirmative observation of the exact root-derived 90/10 state."""

    schema_version: Literal["controlgraph.recovery-prestate-result/v1"]
    result_id: Identifier
    prestate_request_id: Identifier
    request_sha256: Sha256Digest
    request: RecoveryPrestateRequestV1
    classification: Literal["MATCH"]
    target: TargetBinding
    root_schema_version: Literal["controlgraph.rollout-root/v2", "controlgraph.rollout-root/v3"]
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    stable_percent: Literal[90]
    candidate_percent: Literal[10]
    expected_prestate_sha256: Sha256Digest
    observed_prestate_sha256: Sha256Digest
    current_provider_etag: OpaqueToken
    service_generation: PositiveSafeInteger
    verifier_identity: BoundedText
    retrieved_at: UtcSecond

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        request = self.request
        if (
            self.prestate_request_id != request.prestate_request_id
            or self.request_sha256 != canonical_sha256(request)
            or self.target != request.target
            or self.root_schema_version != request.root_schema_version
            or self.root_id != request.root_id
            or self.root_sha256 != request.root_sha256
            or self.epoch != request.epoch
            or self.stable_revision != request.stable_revision
            or self.stable_revision_configuration_sha256
            != request.stable_revision_configuration_sha256
            or self.candidate_revision != request.candidate_revision
            or self.candidate_revision_configuration_sha256
            != request.candidate_revision_configuration_sha256
            or self.concurrency != request.concurrency
            or self.expected_prestate_sha256 != request.expected_prestate_sha256
            or self.observed_prestate_sha256 != self.expected_prestate_sha256
            or self.verifier_identity != request.verifier_identity
            or not request.requested_at
            <= self.retrieved_at
            <= request.command.scheduled_at
            < request.valid_until
        ):
            raise ValueError("recovery prestate result is not an exact 90/10 match")
        if self.result_id != recovery_prestate_result_id(self):
            raise ValueError("recovery prestate result identifier is not canonical")
        return self


class RecoveryPrestateSigningRequestV1(StrictContractModel):
    """Exact verifier result submitted for purpose-separated evidence signing."""

    schema_version: Literal["controlgraph.recovery-prestate-signing-request/v1"]
    signing_request_id: Identifier
    result: RecoveryPrestateResultV1
    result_sha256: Sha256Digest
    purpose: Literal["RECOVERY_PRESTATE_ATTESTATION"]
    signing_key_version: KeyVersionResource

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if (
            self.result_sha256 != canonical_sha256(self.result)
            or self.signing_key_version != self.result.request.evidence_signing_key_version
            or self.signing_request_id != recovery_prestate_signing_request_id(self)
        ):
            raise ValueError("recovery prestate signing request bindings are invalid")
        return self


class RecoveryPrestateAttestationV1(StrictContractModel):
    """An exact 90/10 result signed under the evidence key's recovery purpose."""

    schema_version: Literal["controlgraph.recovery-prestate-attestation/v1"]
    attestation_id: Identifier
    result: RecoveryPrestateResultV1
    result_sha256: Sha256Digest
    signing_request_sha256: Sha256Digest
    purpose: Literal["RECOVERY_PRESTATE_ATTESTATION"]
    signing_key_version: KeyVersionResource
    signing_algorithm: Literal["EC_SIGN_P256_SHA256"]
    payload_sha256: Sha256Digest
    signing_input_sha256: Sha256Digest
    signature: Base64Url

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        matched = _EVIDENCE_KEY.fullmatch(self.signing_key_version)
        expected_request = create_recovery_prestate_signing_request(self.result)
        try:
            raw_signature = decode_base64url(self.signature, maximum_bytes=256)
        except ValueError:
            raise ValueError("recovery prestate attestation signature is invalid") from None
        if (
            matched is None
            or matched.group("project") != self.result.target.project_id
            or self.result_sha256 != canonical_sha256(self.result)
            or self.payload_sha256 != self.result_sha256
            or self.signing_request_sha256 != canonical_sha256(expected_request)
            or self.signing_key_version != expected_request.signing_key_version
            or self.signing_input_sha256
            != recovery_prestate_signing_input_sha256(
                self.result,
                self.signing_key_version,
            )
            or not raw_signature
            or encode_base64url(raw_signature) != self.signature
            or self.attestation_id != f"cgrecoveryprestate:{self.signing_input_sha256}"
        ):
            raise ValueError("recovery prestate attestation bindings are invalid")
        return self


class RecoveryAuthorizationV1(StrictContractModel):
    """Complete root, trigger, receipt, and fresh-prestate recovery authority."""

    schema_version: Literal["controlgraph.recovery-authorization/v1"]
    capability_id: Identifier
    request_id: Identifier
    idempotency_key: Identifier
    scheduled_at: UtcSecond
    root_schema_version: Literal["controlgraph.rollout-root/v2", "controlgraph.rollout-root/v3"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    plan_sha256: Sha256Digest
    stable_snapshot_sha256: Sha256Digest
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    evidence_signing_key_version: KeyVersionResource
    capability_signing_key_version: KeyVersionResource
    issuer_identity: BoundedText
    recovery_identity: BoundedText
    recovery_audience: Audience
    maximum_capability_lifetime_seconds: Annotated[int, Field(ge=1, le=900)]
    maximum_attempts: Literal[1]
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1
    source_receipt_sha256: Sha256Digest
    source_receipt_storage_revision: Annotated[int, Field(ge=2, le=9_007_199_254_740_991)]
    source: RecoverySourceV1
    trigger_proof_sha256: Sha256Digest
    prestate_attestation: RecoveryPrestateAttestationV1
    prestate_attestation_sha256: Sha256Digest
    expected_stable_percent: Literal[90]
    expected_candidate_percent: Literal[10]
    expected_prestate_sha256: Sha256Digest
    current_provider_etag: OpaqueToken
    stable_percent: Literal[100]
    candidate_percent: Literal[0]
    desired_poststate_sha256: Sha256Digest
    issued_at: UtcSecond
    proof_valid_until: UtcSecond

    @model_validator(mode="after")
    def validate_authorization(self) -> Self:
        attestation = self.prestate_attestation
        result = attestation.result
        request = result.request
        root = request.root
        bindings = _root_bindings(root)
        evidence_key_match = _EVIDENCE_KEY.fullmatch(self.evidence_signing_key_version)
        capability_key_match = _CAPABILITY_KEY.fullmatch(
            self.capability_signing_key_version
        )
        if (
            not _target_is_exact(self.target)
            or self.root_schema_version != bindings.schema_version
            or self.root_id != bindings.root_id
            or self.root_sha256 != bindings.root_sha256
            or self.target != bindings.target
            or self.epoch != request.epoch
            or self.plan_sha256 != bindings.plan_sha256
            or self.stable_snapshot_sha256 != bindings.stable_snapshot_sha256
            or self.stable_revision != bindings.stable_revision
            or self.stable_revision_configuration_sha256
            != bindings.stable_revision_configuration_sha256
            or self.candidate_revision != bindings.candidate_revision
            or self.candidate_revision_configuration_sha256
            != bindings.candidate_revision_configuration_sha256
            or self.concurrency != bindings.concurrency
            or self.evidence_signing_key_version != bindings.evidence_signing_key_version
            or evidence_key_match is None
            or evidence_key_match.group("project") != self.target.project_id
            or self.capability_signing_key_version != bindings.capability_signing_key_version
            or capability_key_match is None
            or capability_key_match.group("project") != self.target.project_id
            or self.issuer_identity != bindings.issuer_identity
            or self.issuer_identity
            != f"controlgraph-issuer@{self.target.project_id}.iam.gserviceaccount.com"
            or self.recovery_identity != bindings.recovery_identity
            or self.recovery_identity
            != f"controlgraph-recovery@{self.target.project_id}.iam.gserviceaccount.com"
            or self.recovery_audience != bindings.recovery_audience
            or _RECOVERY_AUDIENCE.fullmatch(self.recovery_audience) is None
            or self.maximum_capability_lifetime_seconds
            != bindings.maximum_capability_lifetime_seconds
        ):
            raise ValueError("recovery authorization root binding is invalid")
        if (
            self.request_id != request.command.request_id
            or self.idempotency_key != request.command.idempotency_key
            or self.scheduled_at != request.command.scheduled_at
            or self.verified_apply_receipt != request.verified_apply_receipt
            or self.source_receipt_sha256 != request.source_receipt_sha256
            or self.source_receipt_storage_revision != request.source_receipt_storage_revision
            or self.source != request.source
            or self.trigger_proof_sha256 != request.trigger_proof_sha256
            or self.prestate_attestation_sha256 != canonical_sha256(attestation)
            or self.evidence_signing_key_version != attestation.signing_key_version
            or self.expected_prestate_sha256 != request.expected_prestate_sha256
            or self.expected_prestate_sha256 != result.observed_prestate_sha256
            or self.current_provider_etag != result.current_provider_etag
            or self.desired_poststate_sha256
            != recovery_target_configuration_sha256(
                root,
                stable_percent=100,
                candidate_percent=0,
            )
            or self.issued_at != result.retrieved_at
            or self.proof_valid_until != request.valid_until
            or not self.issued_at <= self.scheduled_at < self.proof_valid_until
        ):
            raise ValueError("recovery authorization proof binding is invalid")
        if self.capability_id != recovery_capability_id(self):
            raise ValueError("recovery authorization capability identifier is not canonical")
        return self


class RecoveryCapabilityIssuanceCommandV2(StrictContractModel):
    """Coordinator request for one root-derived recovery capability."""

    schema_version: Literal["controlgraph.recovery-capability-issuance-command/v2"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier
    scheduled_at: UtcSecond
    authorization: RecoveryAuthorizationV1
    authorization_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        authorization = self.authorization
        if (
            self.root_id != authorization.root_id
            or self.expected_root_sha256 != authorization.root_sha256
            or self.expected_epoch != authorization.epoch
            or self.request_id != authorization.request_id
            or self.idempotency_key != authorization.idempotency_key
            or self.scheduled_at != authorization.scheduled_at
            or self.authorization_sha256 != canonical_sha256(authorization)
        ):
            raise ValueError("recovery issuance command bindings are invalid")
        return self


class RecoveryCapabilityIssuanceResultV2(StrictContractModel):
    """A signed recovery capability bound to its exact issuance request."""

    schema_version: Literal["controlgraph.recovery-capability-issuance-result/v2"]
    issuance_command: RecoveryCapabilityIssuanceCommandV2
    issuance_command_sha256: Sha256Digest
    authorization_sha256: Sha256Digest
    capability_id: Identifier
    capability: SignedCapability
    capability_sha256: Sha256Digest
    issued_at: UtcSecond
    expires_at: UtcSecond

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        authorization = self.issuance_command.authorization
        claims = self.capability.claims
        if (
            self.issuance_command_sha256
            != recovery_capability_issuance_command_sha256(self.issuance_command)
            or self.authorization_sha256 != canonical_sha256(authorization)
            or self.capability_id != recovery_capability_id(authorization)
            or self.capability_sha256 != canonical_sha256(self.capability)
            or claims.capability_id != self.capability_id
            or claims.issuer != authorization.issuer_identity
            or claims.subject != authorization.recovery_identity
            or claims.audience != authorization.recovery_audience
            or claims.target != authorization.target
            or claims.root_id != authorization.root_id
            or claims.root_sha256 != authorization.root_sha256
            or claims.epoch != authorization.epoch
            or claims.action is not CapabilityAction.RECOVER_STABLE
            or claims.stable_revision != authorization.stable_revision
            or claims.candidate_revision != authorization.candidate_revision
            or claims.stable_percent != 100
            or claims.candidate_percent != 0
            or claims.concurrency != authorization.concurrency
            or claims.plan_sha256 != authorization.plan_sha256
            or claims.provider_etag != authorization.current_provider_etag
            or claims.request_id != authorization.request_id
            or claims.idempotency_key != authorization.idempotency_key
            or claims.parent_capability_sha256 is not None
            or claims.signing_key_version != authorization.capability_signing_key_version
            or claims.issued_at != authorization.issued_at
            or claims.not_before != authorization.scheduled_at
            or self.issued_at != claims.issued_at
            or self.expires_at != claims.expires_at
            or not claims.not_before < claims.expires_at <= authorization.proof_valid_until
            or (_seconds(claims.expires_at) - _seconds(claims.issued_at)).total_seconds()
            > authorization.maximum_capability_lifetime_seconds
        ):
            raise ValueError("recovery issuance result bindings are invalid")
        return self


class RecoveryMutationIntentV2(StrictContractModel):
    """Recovery-only mutation derived entirely from its sealed authorization."""

    schema_version: Literal["controlgraph.recovery-mutation-intent/v2"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_schema_version: Literal["controlgraph.rollout-root/v2", "controlgraph.rollout-root/v3"]
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    action: Literal[CapabilityAction.RECOVER_STABLE]
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    stable_percent: Literal[100]
    candidate_percent: Literal[0]
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    plan_sha256: Sha256Digest
    stable_snapshot_sha256: Sha256Digest
    provider_etag: OpaqueToken
    capability_id: Identifier
    recovery_authorization_sha256: Sha256Digest
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1
    source_receipt_sha256: Sha256Digest
    source_receipt_storage_revision: Annotated[int, Field(ge=2, le=9_007_199_254_740_991)]
    source: RecoverySourceV1
    trigger_proof_sha256: Sha256Digest
    prestate_attestation_sha256: Sha256Digest
    expected_prestate_sha256: Sha256Digest
    desired_poststate_sha256: Sha256Digest
    proof_valid_until: UtcSecond
    authorization: RecoveryAuthorizationV1

    @model_validator(mode="after")
    def validate_intent(self) -> Self:
        authorization = self.authorization
        if (
            self.request_id != authorization.request_id
            or self.idempotency_key != authorization.idempotency_key
            or self.target != authorization.target
            or self.root_schema_version != authorization.root_schema_version
            or self.root_id != authorization.root_id
            or self.root_sha256 != authorization.root_sha256
            or self.epoch != authorization.epoch
            or self.stable_revision != authorization.stable_revision
            or self.stable_revision_configuration_sha256
            != authorization.stable_revision_configuration_sha256
            or self.candidate_revision != authorization.candidate_revision
            or self.candidate_revision_configuration_sha256
            != authorization.candidate_revision_configuration_sha256
            or self.concurrency != authorization.concurrency
            or self.plan_sha256 != authorization.plan_sha256
            or self.stable_snapshot_sha256 != authorization.stable_snapshot_sha256
            or self.provider_etag != authorization.current_provider_etag
            or self.capability_id != authorization.capability_id
            or self.recovery_authorization_sha256 != canonical_sha256(authorization)
            or self.verified_apply_receipt != authorization.verified_apply_receipt
            or self.source_receipt_sha256 != authorization.source_receipt_sha256
            or self.source_receipt_storage_revision != authorization.source_receipt_storage_revision
            or self.source != authorization.source
            or self.trigger_proof_sha256 != authorization.trigger_proof_sha256
            or self.prestate_attestation_sha256 != authorization.prestate_attestation_sha256
            or self.expected_prestate_sha256 != authorization.expected_prestate_sha256
            or self.desired_poststate_sha256 != authorization.desired_poststate_sha256
            or self.proof_valid_until != authorization.proof_valid_until
        ):
            raise ValueError("recovery mutation intent does not match its authorization")
        return self


class RecoveryTaskRequestV2(StrictContractModel):
    """Addressed recovery task that cannot represent promotion or arbitrary mutation."""

    schema_version: Literal["controlgraph.recovery-task-request/v2"]
    task_id: Identifier
    queue_region: Literal["us-central1"]
    handler_audience: Audience
    scheduled_at: UtcSecond
    expires_at: UtcSecond
    capability: SignedCapability
    intent: RecoveryMutationIntentV2

    @model_validator(mode="after")
    def validate_task(self) -> Self:
        claims = self.capability.claims
        intent = self.intent
        authorization = intent.authorization
        if (
            claims.action is not CapabilityAction.RECOVER_STABLE
            or claims.capability_id != recovery_capability_id(authorization)
            or claims.capability_id != intent.capability_id
            or self.task_id != f"task-{self.capability.claims_sha256}"
            or self.handler_audience != authorization.recovery_audience
            or self.handler_audience != claims.audience
            or claims.issuer != authorization.issuer_identity
            or claims.subject != authorization.recovery_identity
            or claims.signing_key_version != authorization.capability_signing_key_version
            or claims.parent_capability_sha256 is not None
            or claims.target != intent.target
            or claims.root_id != intent.root_id
            or claims.root_sha256 != intent.root_sha256
            or claims.epoch != intent.epoch
            or claims.stable_revision != intent.stable_revision
            or claims.candidate_revision != intent.candidate_revision
            or claims.stable_percent != 100
            or claims.candidate_percent != 0
            or claims.concurrency != intent.concurrency
            or claims.plan_sha256 != intent.plan_sha256
            or claims.provider_etag != intent.provider_etag
            or claims.request_id != intent.request_id
            or claims.idempotency_key != intent.idempotency_key
            or claims.issued_at != authorization.issued_at
            or claims.not_before != authorization.scheduled_at
            or self.scheduled_at != authorization.scheduled_at
            or not claims.not_before
            <= self.scheduled_at
            < self.expires_at
            <= claims.expires_at
            <= authorization.proof_valid_until
        ):
            raise ValueError("recovery task bindings are invalid")
        _require_canonical_size(
            self,
            maximum_bytes=MAX_RECOVERY_TASK_CANONICAL_BYTES,
            boundary="recovery task",
        )
        return self


class RecoveryDispatchIdentityV2(StrictContractModel):
    """Immutable request ownership for one canonical stable recovery."""

    schema_version: Literal["controlgraph.recovery-dispatch-identity/v2"]
    identity_kind: RecoveryDispatchIdentityKind
    identity_value: Identifier
    dispatch_id: Identifier
    command_sha256: Sha256Digest
    recovery_authorization_sha256: Sha256Digest
    capability_id: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    scheduled_at: UtcSecond
    source_receipt_sha256: Sha256Digest
    trigger_proof_sha256: Sha256Digest
    prestate_attestation_sha256: Sha256Digest
    claimed_at: UtcSecond

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if (
            self.dispatch_id != recovery_dispatch_id(self.command_sha256)
            or re.fullmatch(r"cgcap-[0-9a-f]{64}", self.capability_id) is None
            or not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.root_sha256}"
        ):
            raise ValueError("recovery dispatch identity is invalid")
        return self


class RecoveryDispatchResultV2(StrictContractModel):
    """Bounded result of issuing and addressing one captured-stable task."""

    schema_version: Literal["controlgraph.recovery-dispatch-result/v2"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_schema_version: Literal["controlgraph.rollout-root/v2", "controlgraph.rollout-root/v3"]
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    stable_percent: Literal[100]
    candidate_percent: Literal[0]
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    provider_etag: OpaqueToken
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1
    source_receipt_sha256: Sha256Digest
    trigger_basis: RecoveryTriggerBasis
    trigger_proof_sha256: Sha256Digest
    prestate_attestation_sha256: Sha256Digest
    expected_prestate_sha256: Sha256Digest
    desired_poststate_sha256: Sha256Digest
    proof_valid_until: UtcSecond
    recovery_authorization_sha256: Sha256Digest
    capability_id: Identifier
    capability_sha256: Sha256Digest
    task_id: Identifier
    task_name: BoundedText
    enqueue_disposition: Literal["CREATED", "DUPLICATE", "AMBIGUOUS"]
    scheduled_at: UtcSecond
    expires_at: UtcSecond

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        task_match = _RECOVERY_TASK_NAME.fullmatch(self.task_name)
        if (
            not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.root_sha256}"
            or task_match is None
            or task_match.group(1) != self.target.project_id
            or self.source_receipt_sha256 != self.verified_apply_receipt.receipt_sha256
            or re.fullmatch(r"cgcap-[0-9a-f]{64}", self.capability_id) is None
            or not self.scheduled_at < self.expires_at <= self.proof_valid_until
            or (
                self.root_schema_version == "controlgraph.rollout-root/v3"
                and self.trigger_basis
                not in {
                    RecoveryTriggerBasis.TERMINAL_UNHEALTHY_V3,
                    RecoveryTriggerBasis.OPERATOR_CONFIRMED_REVOKED_V3,
                }
            )
            or (
                self.root_schema_version == "controlgraph.rollout-root/v2"
                and self.trigger_basis is not RecoveryTriggerBasis.OPERATOR_CONFIRMED_REVOKED_V2
            )
        ):
            raise ValueError("recovery dispatch result bindings are invalid")
        return self


class RecoveryDispatchRecordV2(StrictContractModel):
    """Full exact recovery task and monotonic enqueue outcome."""

    schema_version: Literal["controlgraph.recovery-dispatch-record/v2"]
    dispatch_id: Identifier
    command_sha256: Sha256Digest
    recovery_authorization_sha256: Sha256Digest
    capability_id: Identifier
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    scheduled_at: UtcSecond
    source_receipt_sha256: Sha256Digest
    trigger_proof_sha256: Sha256Digest
    prestate_attestation_sha256: Sha256Digest
    task_sha256: Sha256Digest
    task_name: BoundedText
    task: RecoveryTaskRequestV2
    state: RecoveryDispatchState
    prepared_at: UtcSecond
    enqueue_started_at: UtcSecond | None
    terminal_at: UtcSecond | None
    result: RecoveryDispatchResultV2 | None

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        task = self.task
        intent = task.intent
        authorization = task.intent.authorization
        prestate_request = authorization.prestate_attestation.result.request
        expected_task_name = (
            f"projects/{self.target.project_id}/locations/us-central1/queues/"
            f"controlgraph-recovery/tasks/cg-{self.task_sha256}"
        )
        terminal = self.state in {
            RecoveryDispatchState.CREATED,
            RecoveryDispatchState.DUPLICATE,
            RecoveryDispatchState.AMBIGUOUS,
        }
        if (
            self.command_sha256 != prestate_request.command_sha256
            or self.dispatch_id != recovery_dispatch_id(self.command_sha256)
            or self.recovery_authorization_sha256
            != intent.recovery_authorization_sha256
            or self.capability_id != intent.capability_id
            or self.request_id != authorization.request_id
            or self.idempotency_key != authorization.idempotency_key
            or self.target != authorization.target
            or self.root_id != authorization.root_id
            or self.root_sha256 != authorization.root_sha256
            or self.epoch != authorization.epoch
            or self.scheduled_at != authorization.scheduled_at
            or self.source_receipt_sha256 != authorization.source_receipt_sha256
            or self.trigger_proof_sha256 != authorization.trigger_proof_sha256
            or self.prestate_attestation_sha256 != authorization.prestate_attestation_sha256
            or self.task_sha256 != _validated_contract_sha256(task)
            or self.task_name != expected_task_name
            or task.capability.claims.capability_id != self.capability_id
        ):
            raise ValueError("recovery dispatch task binding is invalid")
        if self.state is RecoveryDispatchState.PREPARED:
            if any(
                value is not None
                for value in (self.enqueue_started_at, self.terminal_at, self.result)
            ):
                raise ValueError("prepared recovery dispatch shape is invalid")
            return self
        if self.enqueue_started_at is None or self.enqueue_started_at < self.prepared_at:
            raise ValueError("recovery enqueue start is invalid")
        if self.state is RecoveryDispatchState.ENQUEUE_STARTED:
            if self.terminal_at is not None or self.result is not None:
                raise ValueError("started recovery dispatch shape is invalid")
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
            or result.root_schema_version != authorization.root_schema_version
            or result.root_id != self.root_id
            or result.root_sha256 != self.root_sha256
            or result.epoch != self.epoch
            or result.stable_revision != authorization.stable_revision
            or result.stable_revision_configuration_sha256
            != authorization.stable_revision_configuration_sha256
            or result.candidate_revision != authorization.candidate_revision
            or result.candidate_revision_configuration_sha256
            != authorization.candidate_revision_configuration_sha256
            or result.concurrency != authorization.concurrency
            or result.provider_etag != authorization.current_provider_etag
            or result.verified_apply_receipt != authorization.verified_apply_receipt
            or result.source_receipt_sha256 != authorization.source_receipt_sha256
            or result.trigger_basis is not authorization.source.basis
            or result.trigger_proof_sha256 != authorization.trigger_proof_sha256
            or result.prestate_attestation_sha256 != authorization.prestate_attestation_sha256
            or result.expected_prestate_sha256 != authorization.expected_prestate_sha256
            or result.desired_poststate_sha256 != authorization.desired_poststate_sha256
            or result.proof_valid_until != authorization.proof_valid_until
            or result.recovery_authorization_sha256 != self.recovery_authorization_sha256
            or result.capability_id != self.capability_id
            or result.capability_sha256
            != _validated_contract_sha256(task.capability)
            or result.task_id != task.task_id
            or result.task_name != self.task_name
            or result.scheduled_at != self.scheduled_at
            or result.expires_at != task.expires_at
        ):
            raise ValueError("terminal recovery dispatch shape is invalid")
        return self


class RecoveryReceiptLocatorV1(StrictContractModel):
    """Exact durable locator for one terminal recovery execution receipt."""

    schema_version: Literal["controlgraph.recovery-receipt-locator/v1"]
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
    action: Literal[CapabilityAction.RECOVER_STABLE]
    provider_etag: OpaqueToken
    outcome: Literal[
        ReceiptOutcome.DENIED,
        ReceiptOutcome.APPLIED,
        ReceiptOutcome.VERIFIED,
        ReceiptOutcome.FAILED_SAFE,
        ReceiptOutcome.AMBIGUOUS,
    ]
    reason_code: ReasonCode | None
    provider_operation: BoundedText | None
    observed_etag: OpaqueToken | None
    observed_authority_epoch: PositiveSafeInteger | None
    receipt_sha256: Sha256Digest
    storage_revision: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_locator(self) -> Self:
        if not _target_is_exact(self.target) or self.root_id != f"cgroot:{self.root_sha256}":
            raise ValueError("recovery receipt locator bindings are invalid")
        needs_reason = self.outcome in {
            ReceiptOutcome.DENIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.AMBIGUOUS,
        }
        if needs_reason != (self.reason_code is not None):
            raise ValueError("recovery receipt locator outcome is invalid")
        if self.outcome is ReceiptOutcome.AMBIGUOUS and (
            self.reason_code is not ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS
        ):
            raise ValueError("recovery receipt locator ambiguity is invalid")
        if self.outcome is ReceiptOutcome.VERIFIED and (
            self.provider_operation is None
            or self.observed_etag is None
            or self.observed_authority_epoch != self.epoch
        ):
            raise ValueError("verified recovery receipt locator is incomplete")
        return self


def recovery_trigger_proof_sha256(source: RecoverySourceV1) -> str:
    """Hash one mode-separated recovery source under a fixed domain."""

    if type(source) not in (
        UnhealthyRecoverySourceV1,
        RevokedV2RecoverySourceV1,
        RevokedV3RecoverySourceV1,
    ):
        raise TypeError("recovery trigger hashing requires an exact recovery source")
    return hashlib.sha256(_TRIGGER_DIGEST_DOMAIN + canonical_json_bytes(source)).hexdigest()


def recovery_command_sha256(command: RecoveryCommandV2) -> str:
    """Hash every caller-visible recovery command binding."""

    if type(command) is not RecoveryCommandV2:
        raise TypeError("recovery command hashing requires an exact command")
    return hashlib.sha256(_COMMAND_DIGEST_DOMAIN + canonical_json_bytes(command)).hexdigest()


def recovery_intent_id(root_sha256: str) -> str:
    """Return the one recovery-intent identity reserved for a rollout root."""

    if type(root_sha256) is not str or _SHA256.fullmatch(root_sha256) is None:
        raise ValueError("recovery intent root digest is invalid")
    digest = hashlib.sha256(_INTENT_DIGEST_DOMAIN + bytes.fromhex(root_sha256)).hexdigest()
    return f"cgrecoveryintent:{digest}"


def recovery_prestate_request_id(request: RecoveryPrestateRequestV1) -> str:
    """Return the deterministic identity for one recovery prestate request."""

    if type(request) is not RecoveryPrestateRequestV1:
        raise TypeError("recovery prestate identity requires an exact request")
    return _content_id(
        request,
        id_field="prestate_request_id",
        prefix="cgrecoveryread:",
        domain=_PRESTATE_REQUEST_ID_DOMAIN,
    )


def recovery_prestate_result_id(result: RecoveryPrestateResultV1) -> str:
    """Return the deterministic identity for one exact prestate observation."""

    if type(result) is not RecoveryPrestateResultV1:
        raise TypeError("recovery prestate result identity requires an exact result")
    return _content_id(
        result,
        id_field="result_id",
        prefix="cgrecoveryresult:",
        domain=_PRESTATE_RESULT_ID_DOMAIN,
    )


def recovery_prestate_signing_request_id(
    request: RecoveryPrestateSigningRequestV1,
) -> str:
    """Return the deterministic identity for one prestate signing request."""

    if type(request) is not RecoveryPrestateSigningRequestV1:
        raise TypeError("prestate signing identity requires an exact request")
    return _content_id(
        request,
        id_field="signing_request_id",
        prefix="cgrecoverysign:",
        domain=_PRESTATE_SIGNING_REQUEST_ID_DOMAIN,
    )


def recovery_prestate_signing_input_sha256(
    result: RecoveryPrestateResultV1,
    signing_key_version: str,
) -> str:
    """Hash an exact prestate result under its fixed purpose and evidence key."""

    if type(result) is not RecoveryPrestateResultV1:
        raise TypeError("prestate signing requires an exact result")
    if type(signing_key_version) is not str or _EVIDENCE_KEY.fullmatch(signing_key_version) is None:
        raise ValueError("recovery prestate signing key is invalid")
    header: RestrictedJson = {
        "algorithm": P256_SIGNING_ALGORITHM,
        "key_version": signing_key_version,
        "payload_version": result.schema_version,
        "purpose": RECOVERY_PRESTATE_ATTESTATION_PURPOSE,
        "schema_version": "controlgraph.recovery-prestate-signature-input/v1",
    }
    return hashlib.sha256(
        _PRESTATE_SIGNING_INPUT_DOMAIN
        + canonical_json_value_bytes(header)
        + b"\0"
        + canonical_json_bytes(result)
    ).hexdigest()


def recovery_capability_id(authorization: RecoveryAuthorizationV1) -> str:
    """Recompute the sole capability identifier for a recovery authorization."""

    if type(authorization) is not RecoveryAuthorizationV1:
        raise TypeError("recovery capability identity requires an exact authorization")
    projection = cast(
        RestrictedJson,
        authorization.model_dump(mode="json", exclude={"capability_id"}),
    )
    digest = hashlib.sha256(
        _CAPABILITY_ID_DOMAIN + canonical_json_value_bytes(projection)
    ).hexdigest()
    return f"cgcap-{digest}"


def recovery_capability_issuance_command_sha256(
    command: RecoveryCapabilityIssuanceCommandV2,
) -> str:
    """Hash one exact recovery capability issuance command."""

    if type(command) is not RecoveryCapabilityIssuanceCommandV2:
        raise TypeError("recovery issuance hashing requires an exact command")
    return hashlib.sha256(
        _ISSUANCE_COMMAND_DIGEST_DOMAIN + canonical_json_bytes(command)
    ).hexdigest()


def recovery_dispatch_id(command_sha256: str) -> str:
    """Return the immutable dispatch identity for one recovery command digest."""

    if type(command_sha256) is not str or _SHA256.fullmatch(command_sha256) is None:
        raise ValueError("recovery command digest is invalid")
    digest = hashlib.sha256(_DISPATCH_ID_DOMAIN + bytes.fromhex(command_sha256)).hexdigest()
    return f"cgrecover:{digest}"


def create_recovery_apply_receipt_locator(
    receipt: ExecutionReceipt,
    *,
    storage_revision: int,
) -> RecoveryApplyReceiptLocatorV1:
    """Project one verified APPLY receipt into an exact durable locator."""

    if type(receipt) is not ExecutionReceipt:
        raise TypeError("recovery APPLY locator requires an exact execution receipt")
    validated = ExecutionReceipt.model_validate(receipt)
    if (
        validated.action is not CapabilityAction.APPLY_CANARY
        or validated.outcome is not ReceiptOutcome.VERIFIED
        or validated.reason_code is not None
        or validated.provider_operation is None
        or validated.observed_etag is None
        or validated.observed_authority_epoch != validated.epoch
        or storage_revision < 2
    ):
        raise ValueError("recovery requires a durable verified APPLY receipt")
    return RecoveryApplyReceiptLocatorV1(
        schema_version=RECOVERY_APPLY_RECEIPT_LOCATOR_V1,
        receipt_id=validated.receipt_id,
        request_id=validated.request_id,
        idempotency_key=validated.idempotency_key,
        capability_sha256=validated.capability_sha256,
        mutation_sha256=validated.mutation_sha256,
        plan_sha256=validated.plan_sha256,
        expected_poststate_sha256=validated.expected_poststate_sha256,
        target=validated.target,
        root_id=validated.root_id,
        root_sha256=validated.root_sha256,
        epoch=validated.epoch,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag=validated.provider_etag,
        provider_operation=validated.provider_operation,
        observed_etag=validated.observed_etag,
        observed_authority_epoch=validated.observed_authority_epoch,
        receipt_sha256=canonical_sha256(validated),
        storage_revision=storage_revision,
    )


def create_recovery_health_chain_locator(
    signed_health_chain: SignedHealthDecisionChainV1,
) -> RecoveryHealthChainLocatorV1:
    """Project a terminal unhealthy signed chain into its exact durable locator."""

    if type(signed_health_chain) is not SignedHealthDecisionChainV1:
        raise TypeError("recovery locator requires an exact signed health chain")
    chain = SignedHealthDecisionChainV1.model_validate(signed_health_chain)
    terminal = chain.signed_proofs[-1]
    if (
        terminal.proof.decision.status is not HealthDecisionStatus.UNHEALTHY
        or terminal.proof.decision.next_evaluation_at is not None
        or chain.healthy_promotion_proof is not None
    ):
        raise ValueError("recovery locator requires a terminal unhealthy chain")
    anchor = chain.anchor
    return RecoveryHealthChainLocatorV1(
        schema_version=RECOVERY_HEALTH_CHAIN_LOCATOR_V1,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        target=anchor.target,
        epoch=anchor.epoch,
        anchor_id=anchor.anchor_id,
        anchor_sha256=chain.anchor_sha256,
        chain_id=chain.chain_id,
        health_chain_sha256=signed_health_decision_chain_sha256(chain),
        chain_head_sha256=chain.chain_head_sha256,
        ordered_proof_chain_sha256=signed_health_proof_chain_sha256(chain.signed_proofs),
        terminal_sequence=terminal.proof.sequence,
        terminal_status=HealthDecisionStatus.UNHEALTHY,
        terminal_signed_proof_sha256=canonical_sha256(terminal),
        terminal_health_decision_sha256=terminal.proof.decision_sha256,
        source_receipt_sha256=anchor.source_receipt_sha256,
        expected_prestate_sha256=anchor.expected_prestate_sha256,
        terminal_decided_at=terminal.proof.decision.evaluated_at,
    )


def create_unhealthy_recovery_source(
    signed_health_chain: SignedHealthDecisionChainV1,
) -> UnhealthyRecoverySourceV1:
    """Create the only normal V3 recovery source from a terminal unhealthy chain."""

    locator = create_recovery_health_chain_locator(signed_health_chain)
    return UnhealthyRecoverySourceV1(
        schema_version=UNHEALTHY_RECOVERY_SOURCE_V1,
        basis=RecoveryTriggerBasis.TERMINAL_UNHEALTHY_V3,
        root_schema_version="controlgraph.rollout-root/v3",
        root_id=locator.root_id,
        root_sha256=locator.root_sha256,
        target=locator.target,
        epoch=locator.epoch,
        health_chain_locator=locator,
        triggered_at=locator.terminal_decided_at,
    )


def create_unhealthy_recovery_command(
    *,
    signed_health_chain: SignedHealthDecisionChainV1,
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1,
    request_id: str,
    idempotency_key: str,
    scheduled_at: str,
) -> RecoveryCommandV2:
    """Derive the normal recovery command from one terminal unhealthy chain."""

    if type(verified_apply_receipt) is not RecoveryApplyReceiptLocatorV1:
        raise TypeError("unhealthy recovery requires an exact APPLY receipt locator")
    source = create_unhealthy_recovery_source(signed_health_chain)
    return RecoveryCommandV2(
        schema_version=RECOVERY_COMMAND_V2,
        root_id=source.root_id,
        expected_root_sha256=source.root_sha256,
        expected_epoch=source.epoch,
        request_id=request_id,
        idempotency_key=idempotency_key,
        scheduled_at=scheduled_at,
        verified_apply_receipt=verified_apply_receipt,
        source=source,
    )


def create_revoked_v2_recovery_source(
    *,
    root: RolloutRootV2,
    revocation_proof: EpochRevocationProofV1,
    confirmation: Literal["RECOVER_CAPTURED_STABLE"],
) -> RevokedV2RecoverySourceV1:
    """Create the explicit operator-confirmed compatibility source for a V2 root."""

    if type(root) is not RolloutRootV2:
        raise TypeError("revoked compatibility recovery requires an exact RolloutRootV2")
    if type(revocation_proof) is not EpochRevocationProofV1:
        raise TypeError("revoked compatibility recovery requires an exact revocation proof")
    if confirmation != RECOVER_CAPTURED_STABLE:
        raise ValueError("revoked compatibility recovery requires explicit confirmation")
    validated_root = RolloutRootV2.model_validate(root)
    proof = EpochRevocationProofV1.model_validate(revocation_proof)
    return RevokedV2RecoverySourceV1(
        schema_version=REVOKED_V2_RECOVERY_SOURCE_V1,
        basis=RecoveryTriggerBasis.OPERATOR_CONFIRMED_REVOKED_V2,
        root_schema_version="controlgraph.rollout-root/v2",
        root_id=validated_root.root_id,
        root_sha256=validated_root.root_sha256,
        target=validated_root.content.target,
        epoch=proof.authority.current_epoch,
        confirmation=confirmation,
        revocation_proof=proof,
        revocation_proof_sha256=canonical_sha256(proof),
        triggered_at=proof.result.committed_at,
    )


def create_revoked_v2_recovery_command(
    *,
    root: RolloutRootV2,
    revocation_proof: EpochRevocationProofV1,
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1,
    request_id: str,
    idempotency_key: str,
    scheduled_at: str,
    confirmation: Literal["RECOVER_CAPTURED_STABLE"],
) -> RecoveryCommandV2:
    """Derive the explicitly confirmed compatibility command for a revoked V2 root."""

    if type(verified_apply_receipt) is not RecoveryApplyReceiptLocatorV1:
        raise TypeError("revoked V2 recovery requires an exact APPLY receipt locator")
    source = create_revoked_v2_recovery_source(
        root=root,
        revocation_proof=revocation_proof,
        confirmation=confirmation,
    )
    return RecoveryCommandV2(
        schema_version=RECOVERY_COMMAND_V2,
        root_id=source.root_id,
        expected_root_sha256=source.root_sha256,
        expected_epoch=source.epoch,
        request_id=request_id,
        idempotency_key=idempotency_key,
        scheduled_at=scheduled_at,
        verified_apply_receipt=verified_apply_receipt,
        source=source,
    )


def create_revoked_v3_recovery_source(
    *,
    root: RolloutRootV3,
    revocation_proof: EpochRevocationProofV1,
    confirmation: Literal["RECOVER_CAPTURED_STABLE"],
) -> RevokedV3RecoverySourceV1:
    """Create an explicit operator-confirmed recovery source for a revoked V3 root."""

    if type(root) is not RolloutRootV3:
        raise TypeError("revoked V3 recovery requires an exact RolloutRootV3")
    if type(revocation_proof) is not EpochRevocationProofV1:
        raise TypeError("revoked V3 recovery requires an exact revocation proof")
    if confirmation != RECOVER_CAPTURED_STABLE:
        raise ValueError("revoked V3 recovery requires explicit confirmation")
    validated_root = RolloutRootV3.model_validate(root)
    proof = EpochRevocationProofV1.model_validate(revocation_proof)
    return RevokedV3RecoverySourceV1(
        schema_version=REVOKED_V3_RECOVERY_SOURCE_V1,
        basis=RecoveryTriggerBasis.OPERATOR_CONFIRMED_REVOKED_V3,
        root_schema_version="controlgraph.rollout-root/v3",
        root_id=validated_root.root_id,
        root_sha256=validated_root.root_sha256,
        target=validated_root.content.target,
        epoch=proof.authority.current_epoch,
        confirmation=confirmation,
        revocation_proof=proof,
        revocation_proof_sha256=canonical_sha256(proof),
        triggered_at=proof.result.committed_at,
    )


def create_revoked_v3_recovery_command(
    *,
    root: RolloutRootV3,
    revocation_proof: EpochRevocationProofV1,
    verified_apply_receipt: RecoveryApplyReceiptLocatorV1,
    request_id: str,
    idempotency_key: str,
    scheduled_at: str,
    confirmation: Literal["RECOVER_CAPTURED_STABLE"],
) -> RecoveryCommandV2:
    """Derive an explicitly confirmed captured-stable command for a revoked V3 root."""

    if type(verified_apply_receipt) is not RecoveryApplyReceiptLocatorV1:
        raise TypeError("revoked V3 recovery requires an exact APPLY receipt locator")
    source = create_revoked_v3_recovery_source(
        root=root,
        revocation_proof=revocation_proof,
        confirmation=confirmation,
    )
    return RecoveryCommandV2(
        schema_version=RECOVERY_COMMAND_V2,
        root_id=source.root_id,
        expected_root_sha256=source.root_sha256,
        expected_epoch=source.epoch,
        request_id=request_id,
        idempotency_key=idempotency_key,
        scheduled_at=scheduled_at,
        verified_apply_receipt=verified_apply_receipt,
        source=source,
    )


def create_recovery_intent(
    command: RecoveryCommandV2,
    *,
    created_at: str,
) -> RecoveryIntentV1:
    """Create the root-unique durable intent used by atomic orchestration."""

    if type(command) is not RecoveryCommandV2:
        raise TypeError("recovery intent creation requires an exact command")
    return RecoveryIntentV1(
        schema_version=RECOVERY_INTENT_V1,
        intent_id=recovery_intent_id(command.expected_root_sha256),
        command=command,
        command_sha256=recovery_command_sha256(command),
        root_id=command.root_id,
        root_sha256=command.expected_root_sha256,
        epoch=command.expected_epoch,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        source_receipt_sha256=command.verified_apply_receipt.receipt_sha256,
        trigger_basis=command.source.basis,
        trigger_proof_sha256=recovery_trigger_proof_sha256(command.source),
        created_at=created_at,
    )


def create_recovery_prestate_request(
    *,
    command: RecoveryCommandV2,
    root: RolloutRootV2 | RolloutRootV3,
    requested_at: str,
    valid_until: str,
) -> RecoveryPrestateRequestV1:
    """Derive the sole exact 90/10 verifier request for a recovery command."""

    if type(command) is not RecoveryCommandV2:
        raise TypeError("recovery prestate creation requires an exact command")
    bindings = _root_bindings(root)
    values: dict[str, object] = {
        "schema_version": RECOVERY_PRESTATE_REQUEST_V1,
        "prestate_request_id": "pending",
        "command": command,
        "command_sha256": recovery_command_sha256(command),
        "root": root,
        "root_schema_version": bindings.schema_version,
        "root_id": bindings.root_id,
        "root_sha256": bindings.root_sha256,
        "target": bindings.target,
        "epoch": command.expected_epoch,
        "plan_sha256": bindings.plan_sha256,
        "stable_snapshot_sha256": bindings.stable_snapshot_sha256,
        "stable_revision": bindings.stable_revision,
        "stable_revision_configuration_sha256": (bindings.stable_revision_configuration_sha256),
        "candidate_revision": bindings.candidate_revision,
        "candidate_revision_configuration_sha256": (
            bindings.candidate_revision_configuration_sha256
        ),
        "concurrency": bindings.concurrency,
        "stable_percent": 90,
        "candidate_percent": 10,
        "expected_prestate_sha256": recovery_target_configuration_sha256(
            root,
            stable_percent=90,
            candidate_percent=10,
        ),
        "verified_apply_receipt": command.verified_apply_receipt,
        "source_receipt_sha256": command.verified_apply_receipt.receipt_sha256,
        "source_receipt_storage_revision": (command.verified_apply_receipt.storage_revision),
        "source": command.source,
        "trigger_proof_sha256": recovery_trigger_proof_sha256(command.source),
        "verifier_identity": (
            f"controlgraph-verifier@{bindings.target.project_id}.iam.gserviceaccount.com"
        ),
        "evidence_signing_key_version": bindings.evidence_signing_key_version,
        "requested_at": requested_at,
        "valid_until": valid_until,
    }
    draft = RecoveryPrestateRequestV1.model_construct(_fields_set=None, **values)
    values["prestate_request_id"] = recovery_prestate_request_id(draft)
    return RecoveryPrestateRequestV1.model_validate(values)


def create_recovery_prestate_result(
    *,
    request: RecoveryPrestateRequestV1,
    current_provider_etag: str,
    service_generation: int,
    retrieved_at: str,
) -> RecoveryPrestateResultV1:
    """Create one affirmative exact-match prestate result from verifier readback."""

    if type(request) is not RecoveryPrestateRequestV1:
        raise TypeError("recovery prestate result requires an exact request")
    values: dict[str, object] = {
        "schema_version": RECOVERY_PRESTATE_RESULT_V1,
        "result_id": "pending",
        "prestate_request_id": request.prestate_request_id,
        "request_sha256": canonical_sha256(request),
        "request": request,
        "classification": "MATCH",
        "target": request.target,
        "root_schema_version": request.root_schema_version,
        "root_id": request.root_id,
        "root_sha256": request.root_sha256,
        "epoch": request.epoch,
        "stable_revision": request.stable_revision,
        "stable_revision_configuration_sha256": (request.stable_revision_configuration_sha256),
        "candidate_revision": request.candidate_revision,
        "candidate_revision_configuration_sha256": (
            request.candidate_revision_configuration_sha256
        ),
        "concurrency": request.concurrency,
        "stable_percent": 90,
        "candidate_percent": 10,
        "expected_prestate_sha256": request.expected_prestate_sha256,
        "observed_prestate_sha256": request.expected_prestate_sha256,
        "current_provider_etag": current_provider_etag,
        "service_generation": service_generation,
        "verifier_identity": request.verifier_identity,
        "retrieved_at": retrieved_at,
    }
    draft = RecoveryPrestateResultV1.model_construct(_fields_set=None, **values)
    values["result_id"] = recovery_prestate_result_id(draft)
    return RecoveryPrestateResultV1.model_validate(values)


def create_recovery_prestate_signing_request(
    result: RecoveryPrestateResultV1,
) -> RecoveryPrestateSigningRequestV1:
    """Construct the exact purpose-separated request used by the evidence writer."""

    if type(result) is not RecoveryPrestateResultV1:
        raise TypeError("recovery prestate signing requires an exact result")
    values: dict[str, object] = {
        "schema_version": RECOVERY_PRESTATE_SIGNING_REQUEST_V1,
        "signing_request_id": "pending",
        "result": result,
        "result_sha256": canonical_sha256(result),
        "purpose": RECOVERY_PRESTATE_ATTESTATION_PURPOSE,
        "signing_key_version": result.request.evidence_signing_key_version,
    }
    draft = RecoveryPrestateSigningRequestV1.model_construct(
        _fields_set=None,
        **values,
    )
    values["signing_request_id"] = recovery_prestate_signing_request_id(draft)
    return RecoveryPrestateSigningRequestV1.model_validate(values)


def create_recovery_prestate_attestation(
    *,
    result: RecoveryPrestateResultV1,
    signature: str,
) -> RecoveryPrestateAttestationV1:
    """Bind an evidence-writer signature to one exact verifier prestate result."""

    signing_request = create_recovery_prestate_signing_request(result)
    signing_input_sha256 = recovery_prestate_signing_input_sha256(
        result,
        signing_request.signing_key_version,
    )
    return RecoveryPrestateAttestationV1(
        schema_version=RECOVERY_PRESTATE_ATTESTATION_V1,
        attestation_id=f"cgrecoveryprestate:{signing_input_sha256}",
        result=result,
        result_sha256=canonical_sha256(result),
        signing_request_sha256=canonical_sha256(signing_request),
        purpose=RECOVERY_PRESTATE_ATTESTATION_PURPOSE,
        signing_key_version=signing_request.signing_key_version,
        signing_algorithm=P256_SIGNING_ALGORITHM,
        payload_sha256=canonical_sha256(result),
        signing_input_sha256=signing_input_sha256,
        signature=signature,
    )


def create_recovery_authorization(
    *,
    root: RolloutRootV2 | RolloutRootV3,
    command: RecoveryCommandV2,
    prestate_attestation: RecoveryPrestateAttestationV1,
) -> RecoveryAuthorizationV1:
    """Derive one self-identifying recovery authorization from trusted inputs."""

    if type(command) is not RecoveryCommandV2:
        raise TypeError("recovery authorization requires an exact command")
    if type(prestate_attestation) is not RecoveryPrestateAttestationV1:
        raise TypeError("recovery authorization requires an exact prestate attestation")
    bindings = _root_bindings(root)
    values: dict[str, object] = {
        "schema_version": RECOVERY_AUTHORIZATION_V1,
        "capability_id": "pending",
        "request_id": command.request_id,
        "idempotency_key": command.idempotency_key,
        "scheduled_at": command.scheduled_at,
        "root_schema_version": bindings.schema_version,
        "root_id": bindings.root_id,
        "root_sha256": bindings.root_sha256,
        "target": bindings.target,
        "epoch": command.expected_epoch,
        "plan_sha256": bindings.plan_sha256,
        "stable_snapshot_sha256": bindings.stable_snapshot_sha256,
        "stable_revision": bindings.stable_revision,
        "stable_revision_configuration_sha256": (bindings.stable_revision_configuration_sha256),
        "candidate_revision": bindings.candidate_revision,
        "candidate_revision_configuration_sha256": (
            bindings.candidate_revision_configuration_sha256
        ),
        "concurrency": bindings.concurrency,
        "evidence_signing_key_version": bindings.evidence_signing_key_version,
        "capability_signing_key_version": bindings.capability_signing_key_version,
        "issuer_identity": bindings.issuer_identity,
        "recovery_identity": bindings.recovery_identity,
        "recovery_audience": bindings.recovery_audience,
        "maximum_capability_lifetime_seconds": (bindings.maximum_capability_lifetime_seconds),
        "maximum_attempts": 1,
        "verified_apply_receipt": command.verified_apply_receipt,
        "source_receipt_sha256": command.verified_apply_receipt.receipt_sha256,
        "source_receipt_storage_revision": (command.verified_apply_receipt.storage_revision),
        "source": command.source,
        "trigger_proof_sha256": recovery_trigger_proof_sha256(command.source),
        "prestate_attestation": prestate_attestation,
        "prestate_attestation_sha256": canonical_sha256(prestate_attestation),
        "expected_stable_percent": 90,
        "expected_candidate_percent": 10,
        "expected_prestate_sha256": (prestate_attestation.result.expected_prestate_sha256),
        "current_provider_etag": prestate_attestation.result.current_provider_etag,
        "stable_percent": 100,
        "candidate_percent": 0,
        "desired_poststate_sha256": recovery_target_configuration_sha256(
            root,
            stable_percent=100,
            candidate_percent=0,
        ),
        "issued_at": prestate_attestation.result.retrieved_at,
        "proof_valid_until": prestate_attestation.result.request.valid_until,
    }
    draft = RecoveryAuthorizationV1.model_construct(_fields_set=None, **values)
    values["capability_id"] = recovery_capability_id(draft)
    return RecoveryAuthorizationV1.model_validate(values)


def create_recovery_receipt_locator(
    receipt: ExecutionReceipt,
    *,
    storage_revision: int,
) -> RecoveryReceiptLocatorV1:
    """Project a terminal recovery receipt into its exact durable locator."""

    if type(receipt) is not ExecutionReceipt:
        raise TypeError("recovery receipt projection requires an exact execution receipt")
    validated = ExecutionReceipt.model_validate(receipt)
    if (
        validated.action is not CapabilityAction.RECOVER_STABLE
        or validated.outcome is ReceiptOutcome.CLAIMED
        or storage_revision < 1
    ):
        raise ValueError("recovery receipt locator requires a terminal recovery receipt")
    return RecoveryReceiptLocatorV1(
        schema_version=RECOVERY_RECEIPT_LOCATOR_V1,
        receipt_id=validated.receipt_id,
        request_id=validated.request_id,
        idempotency_key=validated.idempotency_key,
        capability_sha256=validated.capability_sha256,
        mutation_sha256=validated.mutation_sha256,
        plan_sha256=validated.plan_sha256,
        expected_poststate_sha256=validated.expected_poststate_sha256,
        target=validated.target,
        root_id=validated.root_id,
        root_sha256=validated.root_sha256,
        epoch=validated.epoch,
        action=CapabilityAction.RECOVER_STABLE,
        provider_etag=validated.provider_etag,
        outcome=validated.outcome,
        reason_code=validated.reason_code,
        provider_operation=validated.provider_operation,
        observed_etag=validated.observed_etag,
        observed_authority_epoch=validated.observed_authority_epoch,
        receipt_sha256=canonical_sha256(validated),
        storage_revision=storage_revision,
    )


__all__ = [
    "MAX_RECOVERY_TASK_CANONICAL_BYTES",
    "P256_SIGNING_ALGORITHM",
    "RECOVERY_APPLY_RECEIPT_LOCATOR_V1",
    "RECOVERY_AUTHORIZATION_V1",
    "RECOVERY_CAPABILITY_ISSUANCE_COMMAND_V2",
    "RECOVERY_CAPABILITY_ISSUANCE_RESULT_V2",
    "RECOVERY_COMMAND_V2",
    "RECOVERY_DISPATCH_IDENTITY_V2",
    "RECOVERY_DISPATCH_RECORD_V2",
    "RECOVERY_DISPATCH_RESULT_V2",
    "RECOVERY_HEALTH_CHAIN_LOCATOR_V1",
    "RECOVERY_INTENT_V1",
    "RECOVERY_INVOCATION_V2",
    "RECOVERY_MUTATION_INTENT_V2",
    "RECOVERY_PRESTATE_ATTESTATION_PURPOSE",
    "RECOVERY_PRESTATE_ATTESTATION_V1",
    "RECOVERY_PRESTATE_REQUEST_V1",
    "RECOVERY_PRESTATE_RESULT_V1",
    "RECOVERY_PRESTATE_SIGNING_REQUEST_V1",
    "RECOVERY_RECEIPT_LOCATOR_V1",
    "RECOVERY_TASK_REQUEST_V2",
    "RECOVER_CAPTURED_STABLE",
    "REVOKED_V2_RECOVERY_SOURCE_V1",
    "REVOKED_V3_RECOVERY_SOURCE_V1",
    "UNHEALTHY_RECOVERY_SOURCE_V1",
    "RecoveryApplyReceiptLocatorV1",
    "RecoveryAuthorizationV1",
    "RecoveryCapabilityIssuanceCommandV2",
    "RecoveryCapabilityIssuanceResultV2",
    "RecoveryCommandV2",
    "RecoveryDispatchIdentityKind",
    "RecoveryDispatchIdentityV2",
    "RecoveryDispatchRecordV2",
    "RecoveryDispatchResultV2",
    "RecoveryDispatchState",
    "RecoveryHealthChainLocatorV1",
    "RecoveryIntentV1",
    "RecoveryInvocationV2",
    "RecoveryMutationIntentV2",
    "RecoveryPrestateAttestationV1",
    "RecoveryPrestateRequestV1",
    "RecoveryPrestateResultV1",
    "RecoveryPrestateSigningRequestV1",
    "RecoveryReceiptLocatorV1",
    "RecoveryRolloutRoot",
    "RecoverySourceV1",
    "RecoveryTaskRequestV2",
    "RecoveryTriggerBasis",
    "RevokedV2RecoverySourceV1",
    "RevokedV3RecoverySourceV1",
    "UnhealthyRecoverySourceV1",
    "create_recovery_apply_receipt_locator",
    "create_recovery_authorization",
    "create_recovery_health_chain_locator",
    "create_recovery_intent",
    "create_recovery_prestate_attestation",
    "create_recovery_prestate_request",
    "create_recovery_prestate_result",
    "create_recovery_prestate_signing_request",
    "create_recovery_receipt_locator",
    "create_revoked_v2_recovery_command",
    "create_revoked_v2_recovery_source",
    "create_revoked_v3_recovery_command",
    "create_revoked_v3_recovery_source",
    "create_unhealthy_recovery_command",
    "create_unhealthy_recovery_source",
    "recovery_capability_id",
    "recovery_capability_issuance_command_sha256",
    "recovery_command_sha256",
    "recovery_dispatch_id",
    "recovery_intent_id",
    "recovery_prestate_request_id",
    "recovery_prestate_result_id",
    "recovery_prestate_signing_input_sha256",
    "recovery_prestate_signing_request_id",
    "recovery_target_configuration_sha256",
    "recovery_trigger_proof_sha256",
]
