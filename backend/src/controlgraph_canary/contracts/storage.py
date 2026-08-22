"""Canonical records and deterministic identities for authority persistence."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, ValidationError, model_validator

from controlgraph_canary.authority.replay import MutationTargetKey, receipt_claim_identity
from controlgraph_canary.contracts.base import (
    MAX_CONTRACT_BYTES,
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
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.evidence import EvidenceChainHeadV1
from controlgraph_canary.contracts.models import (
    EpochAuthorityRecord,
    ExecutionReceipt,
    RolloutRoot,
    TargetBinding,
)
from controlgraph_canary.contracts.promotion_execution import (
    PromotionDispatchIdentityKind,
    PromotionDispatchIdentityV1,
    PromotionDispatchIdentityV2,
    PromotionDispatchRecordV1,
    PromotionDispatchRecordV2,
    PromotionDispatchState,
)
from controlgraph_canary.contracts.revocation import (
    EpochRevocationAuditV1,
    EpochRevocationIdentityV1,
    EpochRevocationResultV1,
)
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV2,
    RolloutRootV3,
    RootCreationResultV1,
    RootCreationResultV2,
    SignedEvidenceEventV1,
)

SERVICE_CLAIM_V2: Final = "controlgraph.service-claim/v2"
SERVICE_CLAIM_V3: Final = "controlgraph.service-claim/v3"
AUTHORITY_STORAGE_DOCUMENT_V1: Final = "controlgraph.authority-storage-document/v1"
FIRESTORE_DOCUMENT_ID_DOMAIN: Final = b"controlgraph.firestore-document-id/v1\0"
_PROMOTION_IDENTITY_LOGICAL_ID_DOMAIN: Final = (
    b"controlgraph.promotion-dispatch-identity-logical-id/v1\0"
)
_PROMOTION_V2_IDENTITY_LOGICAL_ID_DOMAIN: Final = (
    b"controlgraph.promotion-dispatch-identity-logical-id/v2\0"
)
_RECOVERY_ABANDONMENT_IDENTITY_LOGICAL_ID_DOMAIN: Final = (
    b"controlgraph.recovery-abandonment-identity-logical-id/v1\0"
)
SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1: Final = "controlgraph.service-claim-terminal-root-proof/v1"
SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1: Final = (
    "controlgraph.service-claim-target-classification-proof/v1"
)
SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION: Final = (
    "FENCED_EPOCH_AND_INDEPENDENT_TARGET_CLASSIFICATION_V2"
)
SERVICE_CLAIM_ABANDONMENT_RELEASE_CONDITION: Final = (
    "FENCED_AMBIGUOUS_RECOVERY_AND_INDEPENDENT_STABLE_BASELINE_V1"
)
SERVICE_CLAIM_ABANDONMENT_PROOF_V1: Final = "controlgraph.service-claim-abandonment-proof/v1"
SERVICE_CLAIM_STABLE_BASELINE_PROOF_V1: Final = (
    "controlgraph.service-claim-stable-baseline-proof/v1"
)

_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_CONTROLGRAPH_ENVIRONMENT: Final = "nonprod"
_CONTROLGRAPH_REFERENCE_SERVICE: Final = "controlgraph-reference-target"


class ServiceClaimStatus(StrEnum):
    """Closed lifecycle for the single active-root claim on one service."""

    ACTIVE = "ACTIVE"
    RELEASING = "RELEASING"
    RELEASED = "RELEASED"


class ServiceClaimTerminalRootState(StrEnum):
    """Closed terminal root states that can participate in claim release."""

    PROMOTED = "PROMOTED"
    RECOVERED = "RECOVERED"


class ServiceClaimTargetClassification(StrEnum):
    """Independent target classifications admitted for terminal release."""

    CANDIDATE_PROMOTED = "CANDIDATE_PROMOTED"
    STABLE_RESTORED = "STABLE_RESTORED"


def _require_service_claim_target(target: TargetBinding) -> None:
    if type(target) is not TargetBinding:
        raise TypeError("service claim target must be exact")
    if (
        _CONTROLGRAPH_PROJECT_ID.fullmatch(target.project_id) is None
        or "reconcile" in target.project_id
        or target.region != "us-central1"
        or target.environment != _CONTROLGRAPH_ENVIRONMENT
        or target.service_name != _CONTROLGRAPH_REFERENCE_SERVICE
    ):
        raise ValueError("service claim target is outside the ControlGraph boundary")


class ServiceClaimTerminalRootProof(StrictContractModel):
    """Canonical reference to terminal-root evidence presented for release."""

    schema_version: Literal["controlgraph.service-claim-terminal-root-proof/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    state: ServiceClaimTerminalRootState
    target_configuration_sha256: Sha256Digest
    evidence_id: Identifier
    evidence_sha256: Sha256Digest
    confirmed_by: Literal["controlgraph.coordinator/v1"]
    confirmed_at: UtcSecond

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        _require_service_claim_target(self.target)
        return self


class ServiceClaimTargetClassificationProof(StrictContractModel):
    """Canonical reference to verifier classification evidence presented for release."""

    schema_version: Literal["controlgraph.service-claim-target-classification-proof/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    classification: ServiceClaimTargetClassification
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    service_generation: PositiveSafeInteger
    provider_etag: OpaqueToken
    target_configuration_sha256: Sha256Digest
    evidence_id: Identifier
    evidence_sha256: Sha256Digest
    classified_by: BoundedText
    classified_at: UtcSecond

    @model_validator(mode="after")
    def validate_independent_reader(self) -> Self:
        _require_service_claim_target(self.target)
        expected_reader = f"controlgraph-verifier@{self.target.project_id}.iam.gserviceaccount.com"
        if self.classified_by != expected_reader:
            raise ValueError("target classification is not bound to the verifier identity")
        return self


class ServiceClaimRecord(StrictContractModel):
    """One service's ownership by an immutable rollout root."""

    schema_version: Literal["controlgraph.service-claim/v2"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    initial_epoch: Literal[1]
    baseline_service_generation: NonNegativeSafeInteger
    baseline_configuration_sha256: Sha256Digest
    baseline_revision_configuration_sha256: Sha256Digest
    candidate_revision_configuration_sha256: Sha256Digest
    stable_target_configuration_sha256: Sha256Digest
    candidate_target_configuration_sha256: Sha256Digest
    operator_owner: BoundedText
    workload_creator: Literal["controlgraph.api/v1"]
    terminal_release_condition: Literal["FENCED_EPOCH_AND_INDEPENDENT_TARGET_CLASSIFICATION_V2"]
    status: ServiceClaimStatus
    claim_request_id: Identifier
    claim_evidence_id: Identifier
    claimed_at: UtcSecond
    release_fence_epoch: PositiveSafeInteger | None
    release_fence_authority_revision: NonNegativeSafeInteger | None
    release_fenced_by: BoundedText | None
    release_fence_request_id: Identifier | None
    release_fence_evidence_id: Identifier | None
    release_fenced_at: UtcSecond | None
    released_by: Literal["controlgraph.coordinator/v1"] | None
    release_request_id: Identifier | None
    release_evidence_id: Identifier | None
    released_at: UtcSecond | None
    terminal_root_proof: ServiceClaimTerminalRootProof | None
    target_classification_proof: ServiceClaimTargetClassificationProof | None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        _require_service_claim_target(self.target)
        if self.operator_owner == self.workload_creator:
            raise ValueError("service claim operator and workload identities must differ")
        if self.stable_revision == self.candidate_revision:
            raise ValueError("service claim revisions must differ")
        prefix = f"{self.target.service_name}-"
        if not self.stable_revision.startswith(prefix) or not self.candidate_revision.startswith(
            prefix
        ):
            raise ValueError("service claim revisions are outside the target service")
        fence_values = (
            self.release_fence_epoch,
            self.release_fence_authority_revision,
            self.release_fenced_by,
            self.release_fence_request_id,
            self.release_fence_evidence_id,
            self.release_fenced_at,
            self.terminal_root_proof,
        )
        final_release_values = (
            self.released_by,
            self.release_request_id,
            self.release_evidence_id,
            self.released_at,
            self.target_classification_proof,
        )
        if self.status is ServiceClaimStatus.ACTIVE:
            if any(value is not None for value in (*fence_values, *final_release_values)):
                raise ValueError("active service claim cannot contain release metadata")
            return self
        if any(value is None for value in fence_values):
            raise ValueError("non-active service claim requires a complete epoch fence")
        if self.status is ServiceClaimStatus.RELEASING:
            if any(value is not None for value in final_release_values):
                raise ValueError("releasing service claim cannot contain final release metadata")
        elif any(value is None for value in final_release_values):
            raise ValueError("released service claim requires complete release metadata")
        terminal = cast(ServiceClaimTerminalRootProof, self.terminal_root_proof)
        if (
            terminal.target != self.target
            or terminal.root_id != self.root_id
            or terminal.root_sha256 != self.root_sha256
        ):
            raise ValueError("service claim terminal proof does not match its root and target")
        expected_configuration = {
            ServiceClaimTerminalRootState.PROMOTED: (self.candidate_target_configuration_sha256),
            ServiceClaimTerminalRootState.RECOVERED: (self.stable_target_configuration_sha256),
        }[terminal.state]
        if terminal.target_configuration_sha256 != expected_configuration:
            raise ValueError("terminal root proof does not match the expected target state")
        release_fence_epoch = cast(int, self.release_fence_epoch)
        release_fence_revision = cast(int, self.release_fence_authority_revision)
        release_fence_evidence_id = cast(str, self.release_fence_evidence_id)
        release_fenced_at = cast(str, self.release_fenced_at)
        if (
            release_fence_epoch <= self.initial_epoch
            or release_fence_revision != release_fence_epoch - self.initial_epoch
            or not self.claimed_at <= terminal.confirmed_at <= release_fenced_at
            or terminal.evidence_id == release_fence_evidence_id
        ):
            raise ValueError("service claim epoch fence is not a later terminal transition")
        if self.status is ServiceClaimStatus.RELEASING:
            return self
        classification = cast(
            ServiceClaimTargetClassificationProof,
            self.target_classification_proof,
        )
        if (
            classification.target != self.target
            or classification.root_id != self.root_id
            or classification.root_sha256 != self.root_sha256
        ):
            raise ValueError("target classification does not match the claimed root")
        expected_classification = {
            ServiceClaimTerminalRootState.PROMOTED: (
                ServiceClaimTargetClassification.CANDIDATE_PROMOTED
            ),
            ServiceClaimTerminalRootState.RECOVERED: (
                ServiceClaimTargetClassification.STABLE_RESTORED
            ),
        }[terminal.state]
        if (
            classification.classification is not expected_classification
            or classification.target_configuration_sha256 != expected_configuration
            or classification.fenced_epoch != release_fence_epoch
            or classification.fenced_authority_revision != release_fence_revision
        ):
            raise ValueError("terminal root and target classification are incoherent")
        if classification.service_generation <= self.baseline_service_generation:
            raise ValueError("target classification predates the claimed baseline")
        release_evidence_id = cast(str, self.release_evidence_id)
        if (
            len(
                {
                    self.claim_evidence_id,
                    terminal.evidence_id,
                    release_fence_evidence_id,
                    classification.evidence_id,
                    release_evidence_id,
                }
            )
            != 5
            or len(
                {
                    terminal.evidence_sha256,
                    classification.evidence_sha256,
                }
            )
            != 2
        ):
            raise ValueError("claim transition evidence must be independent")
        released_at = cast(str, self.released_at)
        if not (release_fenced_at <= classification.classified_at <= released_at):
            raise ValueError("service claim release proof times are not ordered")
        return self


class ServiceClaimAbandonmentProofV1(StrictContractModel):
    """Proof that one expired, outcome-unknown recovery was fenced and abandoned."""

    schema_version: Literal["controlgraph.service-claim-abandonment-proof/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    state: Literal["ABANDONED"]
    required_stable_baseline_configuration_sha256: Sha256Digest
    recovery_dispatch_id: Identifier
    recovery_dispatch_sha256: Sha256Digest
    recovery_dispatch_revision: Literal[2]
    recovery_receipt_id: Identifier
    receipt_absent_at_fence: Literal[True]
    evidence_id: Identifier
    evidence_sha256: Sha256Digest
    confirmed_by: Literal["controlgraph.coordinator/v1"]
    confirmed_at: UtcSecond

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        _require_service_claim_target(self.target)
        if self.root_id != f"cgroot:{self.root_sha256}":
            raise ValueError("abandonment proof root identity is invalid")
        return self


class ServiceClaimStableBaselineProofV1(StrictContractModel):
    """Independent verifier proof of the post-abandonment stable-only baseline."""

    schema_version: Literal["controlgraph.service-claim-stable-baseline-proof/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    classification: Literal["STABLE_BASELINE_CONFIRMED"]
    fenced_epoch: PositiveSafeInteger
    fenced_authority_revision: NonNegativeSafeInteger
    service_generation: PositiveSafeInteger
    provider_etag: OpaqueToken
    target_configuration_sha256: Sha256Digest
    evidence_id: Identifier
    evidence_sha256: Sha256Digest
    classified_by: BoundedText
    classified_at: UtcSecond

    @model_validator(mode="after")
    def validate_independent_reader(self) -> Self:
        _require_service_claim_target(self.target)
        expected_reader = f"controlgraph-verifier@{self.target.project_id}.iam.gserviceaccount.com"
        if self.root_id != f"cgroot:{self.root_sha256}" or self.classified_by != expected_reader:
            raise ValueError("stable baseline proof is not verifier-bound")
        if self.fenced_authority_revision != self.fenced_epoch - 1:
            raise ValueError("stable baseline proof fence is incoherent")
        return self


class ServiceClaimRecordV3(StrictContractModel):
    """Versioned claim state for explicit abandonment of ambiguous recovery."""

    schema_version: Literal["controlgraph.service-claim/v3"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    initial_epoch: Literal[1]
    baseline_service_generation: NonNegativeSafeInteger
    baseline_configuration_sha256: Sha256Digest
    baseline_revision_configuration_sha256: Sha256Digest
    candidate_revision_configuration_sha256: Sha256Digest
    stable_target_configuration_sha256: Sha256Digest
    candidate_target_configuration_sha256: Sha256Digest
    operator_owner: BoundedText
    workload_creator: Literal["controlgraph.api/v1"]
    terminal_release_condition: Literal[
        "FENCED_AMBIGUOUS_RECOVERY_AND_INDEPENDENT_STABLE_BASELINE_V1"
    ]
    status: ServiceClaimStatus
    claim_request_id: Identifier
    claim_evidence_id: Identifier
    claimed_at: UtcSecond
    release_fence_epoch: PositiveSafeInteger | None
    release_fence_authority_revision: NonNegativeSafeInteger | None
    release_fenced_by: BoundedText | None
    release_fence_request_id: Identifier | None
    release_fence_evidence_id: Identifier | None
    release_fenced_at: UtcSecond | None
    released_by: Literal["controlgraph.coordinator/v1"] | None
    release_request_id: Identifier | None
    release_evidence_id: Identifier | None
    released_at: UtcSecond | None
    terminal_root_proof: ServiceClaimAbandonmentProofV1 | None
    target_classification_proof: ServiceClaimStableBaselineProofV1 | None

    @model_validator(mode="after")
    def validate_abandonment_lifecycle(self) -> Self:
        _require_service_claim_target(self.target)
        if self.status is ServiceClaimStatus.ACTIVE:
            raise ValueError("V3 abandonment claims cannot be active")
        if self.operator_owner == self.workload_creator:
            raise ValueError("service claim operator and workload identities must differ")
        if self.stable_revision == self.candidate_revision:
            raise ValueError("service claim revisions must differ")
        prefix = f"{self.target.service_name}-"
        if not self.stable_revision.startswith(prefix) or not self.candidate_revision.startswith(
            prefix
        ):
            raise ValueError("service claim revisions are outside the target service")
        fence_values = (
            self.release_fence_epoch,
            self.release_fence_authority_revision,
            self.release_fenced_by,
            self.release_fence_request_id,
            self.release_fence_evidence_id,
            self.release_fenced_at,
            self.terminal_root_proof,
        )
        if any(value is None for value in fence_values):
            raise ValueError("abandonment claim requires a complete epoch fence")
        final_release_values = (
            self.released_by,
            self.release_request_id,
            self.release_evidence_id,
            self.released_at,
            self.target_classification_proof,
        )
        if self.status is ServiceClaimStatus.RELEASING:
            if any(value is not None for value in final_release_values):
                raise ValueError("releasing abandonment claim cannot be final")
        elif self.status is ServiceClaimStatus.RELEASED:
            if any(value is None for value in final_release_values):
                raise ValueError("released abandonment claim requires final proof")
        else:
            raise ValueError("abandonment claim status is invalid")
        abandonment = cast(ServiceClaimAbandonmentProofV1, self.terminal_root_proof)
        if (
            abandonment.target != self.target
            or abandonment.root_id != self.root_id
            or abandonment.root_sha256 != self.root_sha256
            or abandonment.required_stable_baseline_configuration_sha256
            != self.stable_target_configuration_sha256
        ):
            raise ValueError("abandonment proof does not match the claim")
        fence_epoch = cast(int, self.release_fence_epoch)
        fence_revision = cast(int, self.release_fence_authority_revision)
        fence_evidence_id = cast(str, self.release_fence_evidence_id)
        fenced_at = cast(str, self.release_fenced_at)
        if (
            fence_epoch <= self.initial_epoch
            or fence_revision != fence_epoch - self.initial_epoch
            or not self.claimed_at <= abandonment.confirmed_at <= fenced_at
            or abandonment.evidence_id == fence_evidence_id
        ):
            raise ValueError("abandonment fence is not a later authority transition")
        if self.status is ServiceClaimStatus.RELEASING:
            return self
        classification = cast(
            ServiceClaimStableBaselineProofV1,
            self.target_classification_proof,
        )
        if (
            classification.target != self.target
            or classification.root_id != self.root_id
            or classification.root_sha256 != self.root_sha256
            or classification.target_configuration_sha256 != self.stable_target_configuration_sha256
            or classification.fenced_epoch != fence_epoch
            or classification.fenced_authority_revision != fence_revision
            or classification.service_generation <= self.baseline_service_generation
            or classification.evidence_sha256 == abandonment.evidence_sha256
            or self.release_request_id != self.release_fence_request_id
        ):
            raise ValueError("stable baseline proof does not match abandonment")
        release_evidence_id = cast(str, self.release_evidence_id)
        if (
            len(
                {
                    self.claim_evidence_id,
                    abandonment.evidence_id,
                    fence_evidence_id,
                    classification.evidence_id,
                    release_evidence_id,
                }
            )
            != 5
        ):
            raise ValueError("abandonment transition evidence must be independent")
        released_at = cast(str, self.released_at)
        if not (fenced_at <= classification.classified_at <= released_at):
            raise ValueError("abandonment release proof times are not ordered")
        return self


ServiceClaimRecordValue = ServiceClaimRecord | ServiceClaimRecordV3


def service_claim_matches_root(
    claim: ServiceClaimRecord,
    root: RolloutRoot,
    *,
    stable_target_configuration_sha256: str,
    candidate_target_configuration_sha256: str,
) -> bool:
    """Return whether one claim exactly binds an immutable rollout root."""

    if type(claim) is not ServiceClaimRecord or type(root) is not RolloutRoot:
        return False
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in (
            stable_target_configuration_sha256,
            candidate_target_configuration_sha256,
        )
    ):
        return False
    expected_reader = f"controlgraph-verifier@{root.target.project_id}.iam.gserviceaccount.com"
    return (
        claim.target == root.target
        and claim.root_id == root.root_id
        and claim.root_sha256 == canonical_sha256(root)
        and claim.stable_revision == root.stable_snapshot.stable_revision
        and claim.candidate_revision == root.candidate_revision
        and claim.initial_epoch == root.initial_epoch
        and (claim.baseline_service_generation == root.stable_snapshot.service_generation)
        and (claim.baseline_configuration_sha256 == root.stable_snapshot.configuration_sha256)
        and (
            claim.baseline_revision_configuration_sha256
            == root.stable_snapshot.stable_revision_configuration_sha256
        )
        and (claim.stable_target_configuration_sha256 == stable_target_configuration_sha256)
        and (claim.candidate_target_configuration_sha256 == candidate_target_configuration_sha256)
        and claim.operator_owner == root.approved_by
        and claim.workload_creator == "controlgraph.api/v1"
        and claim.terminal_release_condition == SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION
        and root.stable_snapshot.captured_by == expected_reader
        and root.stable_snapshot.captured_at <= root.approved_at <= claim.claimed_at
    )


def active_service_claim_matches_root(
    claim: ServiceClaimRecord,
    root: RolloutRoot,
    *,
    stable_target_configuration_sha256: str,
    candidate_target_configuration_sha256: str,
) -> bool:
    """Return whether one active claim exactly binds an immutable rollout root."""

    return (
        type(claim) is ServiceClaimRecord
        and claim.status is ServiceClaimStatus.ACTIVE
        and service_claim_matches_root(
            claim,
            root,
            stable_target_configuration_sha256=stable_target_configuration_sha256,
            candidate_target_configuration_sha256=candidate_target_configuration_sha256,
        )
    )


def service_claim_matches_root_v2(
    claim: ServiceClaimRecord,
    root: RolloutRootV2,
    *,
    stable_target_configuration_sha256: str,
    candidate_target_configuration_sha256: str,
) -> bool:
    """Return whether one claim exactly binds a content-addressed rollout root."""

    if type(claim) is not ServiceClaimRecord or type(root) is not RolloutRootV2:
        return False
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in (
            stable_target_configuration_sha256,
            candidate_target_configuration_sha256,
        )
    ):
        return False
    content = root.content
    snapshot = content.stable_snapshot
    plan = content.rollout_plan
    expected_reader = f"controlgraph-verifier@{content.target.project_id}.iam.gserviceaccount.com"
    return (
        claim.target == content.target
        and claim.root_id == root.root_id
        and claim.root_sha256 == root.root_sha256
        and claim.stable_revision == plan.stable_revision
        and claim.candidate_revision == plan.candidate_revision
        and claim.initial_epoch == plan.initial_epoch
        and claim.baseline_service_generation == snapshot.service_generation
        and claim.baseline_configuration_sha256 == snapshot.configuration_sha256
        and (
            claim.baseline_revision_configuration_sha256
            == plan.stable_revision_configuration_sha256
        )
        and (
            claim.candidate_revision_configuration_sha256
            == plan.candidate_revision_configuration_sha256
        )
        and claim.stable_target_configuration_sha256 == stable_target_configuration_sha256
        and claim.candidate_target_configuration_sha256 == candidate_target_configuration_sha256
        and claim.operator_owner == content.approved_by
        and claim.workload_creator == "controlgraph.api/v1"
        and claim.terminal_release_condition == SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION
        and snapshot.captured_by == expected_reader
        and snapshot.captured_at <= content.approved_at <= claim.claimed_at
    )


def active_service_claim_matches_root_v2(
    claim: ServiceClaimRecord,
    root: RolloutRootV2,
    *,
    stable_target_configuration_sha256: str,
    candidate_target_configuration_sha256: str,
) -> bool:
    """Return whether one active claim exactly binds a content-addressed root."""

    return (
        type(claim) is ServiceClaimRecord
        and claim.status is ServiceClaimStatus.ACTIVE
        and service_claim_matches_root_v2(
            claim,
            root,
            stable_target_configuration_sha256=stable_target_configuration_sha256,
            candidate_target_configuration_sha256=candidate_target_configuration_sha256,
        )
    )


def service_claim_matches_root_v3(
    claim: ServiceClaimRecord | ServiceClaimRecordV3,
    root: RolloutRootV3,
    *,
    stable_target_configuration_sha256: str,
    candidate_target_configuration_sha256: str,
) -> bool:
    """Return whether one claim exactly binds a V3 rollout root."""

    if (
        type(claim) not in (ServiceClaimRecord, ServiceClaimRecordV3)
        or type(root) is not RolloutRootV3
    ):
        return False
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in (
            stable_target_configuration_sha256,
            candidate_target_configuration_sha256,
        )
    ):
        return False
    content = root.content
    snapshot = content.stable_snapshot
    plan = content.rollout_plan
    expected_reader = f"controlgraph-verifier@{content.target.project_id}.iam.gserviceaccount.com"
    return (
        claim.target == content.target
        and claim.root_id == root.root_id
        and claim.root_sha256 == root.root_sha256
        and claim.stable_revision == plan.stable_revision
        and claim.candidate_revision == plan.candidate_revision
        and claim.initial_epoch == plan.initial_epoch
        and claim.baseline_service_generation == snapshot.service_generation
        and claim.baseline_configuration_sha256 == snapshot.configuration_sha256
        and claim.baseline_revision_configuration_sha256
        == plan.stable_revision_configuration_sha256
        and claim.candidate_revision_configuration_sha256
        == plan.candidate_revision_configuration_sha256
        and claim.stable_target_configuration_sha256 == stable_target_configuration_sha256
        and claim.candidate_target_configuration_sha256 == candidate_target_configuration_sha256
        and claim.operator_owner == content.approved_by
        and claim.workload_creator == "controlgraph.api/v1"
        and claim.terminal_release_condition
        == (
            SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION
            if type(claim) is ServiceClaimRecord
            else SERVICE_CLAIM_ABANDONMENT_RELEASE_CONDITION
        )
        and snapshot.captured_by == expected_reader
        and snapshot.captured_at <= content.approved_at <= claim.claimed_at
    )


def active_service_claim_matches_root_v3(
    claim: ServiceClaimRecord,
    root: RolloutRootV3,
    *,
    stable_target_configuration_sha256: str,
    candidate_target_configuration_sha256: str,
) -> bool:
    """Return whether one active claim exactly binds a V3 root."""

    return (
        type(claim) is ServiceClaimRecord
        and claim.status is ServiceClaimStatus.ACTIVE
        and service_claim_matches_root_v3(
            claim,
            root,
            stable_target_configuration_sha256=stable_target_configuration_sha256,
            candidate_target_configuration_sha256=candidate_target_configuration_sha256,
        )
    )


class AuthorityStorageKind(StrEnum):
    """Closed Firestore record families used by the authority database."""

    ROLLOUT_ROOT = "controlgraph-rollout-roots-v1"
    ROLLOUT_ROOT_V2 = "controlgraph-rollout-roots-v2"
    ROLLOUT_ROOT_V3 = "controlgraph-rollout-roots-v3"
    SERVICE_CLAIM = "controlgraph-service-claims-v1"
    EPOCH_AUTHORITY = "controlgraph-epoch-authorities-v1"
    EXECUTION_RECEIPT = "controlgraph-execution-receipts-v1"
    CAPABILITY_LINEAGE_ANCHOR = "controlgraph-capability-lineage-anchors-v1"
    SIGNED_EVIDENCE_EVENT = "controlgraph-signed-evidence-events-v1"
    ROOT_CREATION_RESULT = "controlgraph-root-creation-results-v1"
    ROOT_CREATION_RESULT_V2 = "controlgraph-root-creation-results-v2"
    EVIDENCE_CHAIN_HEAD = "controlgraph-evidence-chain-heads-v1"
    EPOCH_REVOCATION_IDENTITY = "controlgraph-epoch-revocation-identities-v1"
    EPOCH_REVOCATION_RESULT = "controlgraph-epoch-revocation-results-v1"
    EPOCH_REVOCATION_AUDIT = "controlgraph-epoch-revocation-audits-v1"
    SERVICE_CLAIM_RELEASE_IDENTITY = "controlgraph-service-claim-release-identities-v1"
    SERVICE_CLAIM_RELEASE_PROGRESS = "controlgraph-service-claim-release-progress-v1"
    SERVICE_CLAIM_RELEASE_RESULT = "controlgraph-service-claim-release-results-v1"
    RECOVERY_ABANDONMENT_IDENTITY = "controlgraph-recovery-abandonment-identities-v1"
    RECOVERY_ABANDONMENT_PROGRESS = "controlgraph-recovery-abandonment-progress-v1"
    RECOVERY_ABANDONMENT_RESULT = "controlgraph-recovery-abandonment-results-v1"
    PROMOTION_DISPATCH_IDENTITY = "controlgraph-promotion-dispatch-identities-v1"
    PROMOTION_DISPATCH = "controlgraph-promotion-dispatches-v1"
    PROMOTION_DISPATCH_IDENTITY_V2 = "controlgraph-promotion-dispatch-identities-v2"
    PROMOTION_DISPATCH_V2 = "controlgraph-promotion-dispatches-v2"


class AuthorityStorageDocument(StrictContractModel):
    """Exact canonical payload wrapper stored at one fixed Firestore identity."""

    schema_version: Literal["controlgraph.authority-storage-document/v1"]
    record_kind: AuthorityStorageKind
    logical_id: Identifier
    revision: Annotated[int, Field(ge=0, le=2**53 - 1)]
    mutation_id: Identifier
    canonical_payload: Annotated[str, Field(min_length=2, max_length=MAX_CONTRACT_BYTES)]
    payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        model_type: type[StrictContractModel]
        if self.record_kind is AuthorityStorageKind.ROLLOUT_ROOT:
            model_type = RolloutRoot
        elif self.record_kind is AuthorityStorageKind.ROLLOUT_ROOT_V2:
            model_type = RolloutRootV2
        elif self.record_kind is AuthorityStorageKind.ROLLOUT_ROOT_V3:
            model_type = RolloutRootV3
        elif self.record_kind is AuthorityStorageKind.SERVICE_CLAIM:
            try:
                raw_claim = json.loads(self.canonical_payload)
            except (TypeError, ValueError):
                raise ValueError("authority storage payload is invalid") from None
            model_type = (
                ServiceClaimRecordV3
                if type(raw_claim) is dict and raw_claim.get("schema_version") == SERVICE_CLAIM_V3
                else ServiceClaimRecord
            )
        elif self.record_kind is AuthorityStorageKind.EPOCH_AUTHORITY:
            model_type = EpochAuthorityRecord
        elif self.record_kind is AuthorityStorageKind.EXECUTION_RECEIPT:
            model_type = ExecutionReceipt
        elif self.record_kind is AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR:
            model_type = CapabilityLineageAnchorV1
        elif self.record_kind is AuthorityStorageKind.SIGNED_EVIDENCE_EVENT:
            model_type = SignedEvidenceEventV1
        elif self.record_kind is AuthorityStorageKind.ROOT_CREATION_RESULT:
            model_type = RootCreationResultV1
        elif self.record_kind is AuthorityStorageKind.ROOT_CREATION_RESULT_V2:
            model_type = RootCreationResultV2
        elif self.record_kind is AuthorityStorageKind.EVIDENCE_CHAIN_HEAD:
            model_type = EvidenceChainHeadV1
        elif self.record_kind is AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY:
            model_type = EpochRevocationIdentityV1
        elif self.record_kind is AuthorityStorageKind.EPOCH_REVOCATION_RESULT:
            model_type = EpochRevocationResultV1
        elif self.record_kind is AuthorityStorageKind.EPOCH_REVOCATION_AUDIT:
            model_type = EpochRevocationAuditV1
        elif self.record_kind is AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY:
            model_type = PromotionDispatchIdentityV1
        elif self.record_kind is AuthorityStorageKind.PROMOTION_DISPATCH:
            model_type = PromotionDispatchRecordV1
        elif self.record_kind is AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2:
            model_type = PromotionDispatchIdentityV2
        elif self.record_kind is AuthorityStorageKind.PROMOTION_DISPATCH_V2:
            model_type = PromotionDispatchRecordV2
        elif self.record_kind in {
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS,
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
        }:
            from controlgraph_canary.contracts.service_claim_release import (
                ServiceClaimReleaseIdentityV1,
                ServiceClaimReleaseProgressV1,
                ServiceClaimReleaseResultV1,
            )

            if self.record_kind is AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY:
                model_type = ServiceClaimReleaseIdentityV1
            elif self.record_kind is AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS:
                model_type = ServiceClaimReleaseProgressV1
            else:
                model_type = ServiceClaimReleaseResultV1
        else:
            from controlgraph_canary.contracts.recovery_abandonment import (
                RecoveryAbandonmentIdentityV1,
                RecoveryAbandonmentProgressV1,
                RecoveryAbandonmentResultV1,
            )

            if self.record_kind is AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY:
                model_type = RecoveryAbandonmentIdentityV1
            elif self.record_kind is AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS:
                model_type = RecoveryAbandonmentProgressV1
            else:
                model_type = RecoveryAbandonmentResultV1
        try:
            payload = decode_contract(self.canonical_payload, model_type)
        except ContractError as error:
            raise ValueError("authority storage payload is invalid") from error
        if canonical_sha256(payload) != self.payload_sha256:
            raise ValueError("authority storage payload digest does not match")
        immutable_kinds = {
            AuthorityStorageKind.ROLLOUT_ROOT,
            AuthorityStorageKind.ROLLOUT_ROOT_V2,
            AuthorityStorageKind.ROLLOUT_ROOT_V3,
            AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
            AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            AuthorityStorageKind.ROOT_CREATION_RESULT,
            AuthorityStorageKind.ROOT_CREATION_RESULT_V2,
            AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
            AuthorityStorageKind.EPOCH_REVOCATION_RESULT,
            AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS,
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
            AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY,
            AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS,
            AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
            AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
            AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
        }
        if self.record_kind in immutable_kinds and self.revision != 0:
            raise ValueError("immutable authority record must remain at revision zero")
        if (
            self.record_kind is AuthorityStorageKind.EPOCH_AUTHORITY
            and self.revision != cast(EpochAuthorityRecord, payload).revision
        ):
            raise ValueError("authority storage and payload revisions do not match")
        if (
            self.record_kind is AuthorityStorageKind.EVIDENCE_CHAIN_HEAD
            and self.revision != cast(EvidenceChainHeadV1, payload).sequence
        ):
            raise ValueError("evidence head storage and sequence revisions do not match")
        if self.record_kind is AuthorityStorageKind.SERVICE_CLAIM:
            claim = cast(ServiceClaimRecord | ServiceClaimRecordV3, payload)
            expected_revision_remainder = {
                ServiceClaimStatus.ACTIVE: 0,
                ServiceClaimStatus.RELEASING: 1,
                ServiceClaimStatus.RELEASED: 2,
            }[claim.status]
            if self.revision % 3 != expected_revision_remainder:
                raise ValueError("service claim lifecycle and storage revision do not match")
            expected_logical_id = service_claim_logical_id(claim.target)
        elif self.record_kind is AuthorityStorageKind.EXECUTION_RECEIPT:
            receipt = cast(ExecutionReceipt, payload)
            expected_logical_id = execution_receipt_logical_id(
                receipt.target,
                receipt.idempotency_key,
            )
            if receipt.receipt_id != expected_logical_id:
                raise ValueError("execution receipt identity does not match its claim key")
        elif self.record_kind is AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR:
            expected_logical_id = capability_lineage_anchor_logical_id(
                cast(CapabilityLineageAnchorV1, payload)
            )
        elif self.record_kind is AuthorityStorageKind.SIGNED_EVIDENCE_EVENT:
            expected_logical_id = cast(SignedEvidenceEventV1, payload).event.evidence_id
        elif self.record_kind in {
            AuthorityStorageKind.ROOT_CREATION_RESULT,
            AuthorityStorageKind.ROOT_CREATION_RESULT_V2,
        }:
            result = cast(RootCreationResultV1 | RootCreationResultV2, payload)
            if result.outcome != "CREATED":
                raise ValueError("persisted root creation result must identify the winner")
            expected_logical_id = result.root.root_id
        elif self.record_kind is AuthorityStorageKind.EVIDENCE_CHAIN_HEAD:
            expected_logical_id = cast(EvidenceChainHeadV1, payload).root_id
        elif self.record_kind is AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY:
            identity = cast(EpochRevocationIdentityV1, payload)
            expected_logical_id = epoch_revocation_identity_logical_id(
                identity.identity_kind.value,
                identity.identity_value,
            )
        elif self.record_kind is AuthorityStorageKind.EPOCH_REVOCATION_RESULT:
            expected_logical_id = cast(EpochRevocationResultV1, payload).result_id
        elif self.record_kind is AuthorityStorageKind.EPOCH_REVOCATION_AUDIT:
            expected_logical_id = cast(EpochRevocationAuditV1, payload).audit_id
        elif self.record_kind is AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY:
            promotion_identity = cast(PromotionDispatchIdentityV1, payload)
            expected_logical_id = promotion_dispatch_identity_logical_id(
                promotion_identity.identity_kind.value,
                promotion_identity.identity_value,
            )
        elif self.record_kind is AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2:
            promotion_identity_v2 = cast(PromotionDispatchIdentityV2, payload)
            expected_logical_id = promotion_dispatch_identity_v2_logical_id(
                promotion_identity_v2.identity_kind.value,
                promotion_identity_v2.identity_value,
            )
        elif self.record_kind is AuthorityStorageKind.PROMOTION_DISPATCH:
            dispatch = cast(PromotionDispatchRecordV1, payload)
            expected_revision = {
                PromotionDispatchState.PREPARED: 0,
                PromotionDispatchState.ENQUEUE_STARTED: 1,
                PromotionDispatchState.CREATED: 2,
                PromotionDispatchState.DUPLICATE: 2,
                PromotionDispatchState.AMBIGUOUS: 2,
            }[dispatch.state]
            if self.revision != expected_revision:
                raise ValueError("promotion dispatch state and storage revision do not match")
            expected_logical_id = dispatch.dispatch_id
        elif self.record_kind is AuthorityStorageKind.PROMOTION_DISPATCH_V2:
            dispatch_v2 = cast(PromotionDispatchRecordV2, payload)
            expected_revision = {
                PromotionDispatchState.PREPARED: 0,
                PromotionDispatchState.ENQUEUE_STARTED: 1,
                PromotionDispatchState.CREATED: 2,
                PromotionDispatchState.DUPLICATE: 2,
                PromotionDispatchState.AMBIGUOUS: 2,
            }[dispatch_v2.state]
            if self.revision != expected_revision:
                raise ValueError("V2 promotion state and storage revision do not match")
            expected_logical_id = dispatch_v2.dispatch_id
        elif self.record_kind in {
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS,
            AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
        }:
            from controlgraph_canary.contracts.service_claim_release import (
                ServiceClaimReleaseIdentityV1,
                ServiceClaimReleaseProgressV1,
                ServiceClaimReleaseResultV1,
            )

            if self.record_kind is AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY:
                release_identity = cast(ServiceClaimReleaseIdentityV1, payload)
                expected_logical_id = service_claim_release_identity_logical_id(
                    release_identity.identity_kind.value,
                    release_identity.identity_value,
                )
            elif self.record_kind is AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS:
                expected_logical_id = cast(
                    ServiceClaimReleaseProgressV1,
                    payload,
                ).result_id
            else:
                expected_logical_id = cast(
                    ServiceClaimReleaseResultV1,
                    payload,
                ).result_id
        elif self.record_kind in {
            AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY,
            AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS,
            AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
        }:
            from controlgraph_canary.contracts.recovery_abandonment import (
                RecoveryAbandonmentIdentityV1,
                RecoveryAbandonmentProgressV1,
                RecoveryAbandonmentResultV1,
            )

            if self.record_kind is AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY:
                abandonment_identity = cast(RecoveryAbandonmentIdentityV1, payload)
                expected_logical_id = recovery_abandonment_identity_logical_id(
                    abandonment_identity.identity_kind.value,
                    abandonment_identity.identity_value,
                )
            elif self.record_kind is AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS:
                expected_logical_id = cast(
                    RecoveryAbandonmentProgressV1,
                    payload,
                ).result_id
            else:
                expected_logical_id = cast(
                    RecoveryAbandonmentResultV1,
                    payload,
                ).result_id
        else:
            expected_logical_id = cast(
                RolloutRoot | RolloutRootV2 | RolloutRootV3 | EpochAuthorityRecord,
                payload,
            ).root_id
        if self.logical_id != expected_logical_id:
            raise ValueError("authority storage payload identity does not match")
        return self


class _LogicalIdentity(StrictContractModel):
    value: Identifier


def _document_id(kind: AuthorityStorageKind, logical_id: str) -> str:
    if type(kind) is not AuthorityStorageKind:
        raise TypeError("authority storage kind must be exact")
    try:
        identity = _LogicalIdentity(value=logical_id).value
        encoded_identity = identity.encode("ascii")
    except (TypeError, UnicodeEncodeError, ValueError, ValidationError) as error:
        raise ValueError("authority storage logical identifier is invalid") from error
    material = FIRESTORE_DOCUMENT_ID_DOMAIN + kind.value.encode("ascii") + b"\0"
    return hashlib.sha256(material + encoded_identity).hexdigest()


def rollout_root_document_id(root_id: str) -> str:
    """Return the domain-separated document ID for one rollout root."""

    return _document_id(AuthorityStorageKind.ROLLOUT_ROOT, root_id)


def rollout_root_v2_document_id(root_id: str) -> str:
    """Return the domain-separated document ID for one v2 rollout root."""

    return _document_id(AuthorityStorageKind.ROLLOUT_ROOT_V2, root_id)


def rollout_root_v3_document_id(root_id: str) -> str:
    """Return the domain-separated document ID for one v3 rollout root."""

    return _document_id(AuthorityStorageKind.ROLLOUT_ROOT_V3, root_id)


def service_claim_logical_id(target: TargetBinding) -> str:
    """Return the canonical service identity without exposing a Firestore path."""

    _require_service_claim_target(target)
    return canonical_sha256(target)


def service_claim_document_id(target: TargetBinding) -> str:
    """Return the schema-stable document ID for one configured service."""

    return _document_id(AuthorityStorageKind.SERVICE_CLAIM, service_claim_logical_id(target))


def epoch_authority_document_id(root_id: str) -> str:
    """Return the domain-separated document ID for one root's authority."""

    return _document_id(AuthorityStorageKind.EPOCH_AUTHORITY, root_id)


def capability_lineage_anchor_logical_id(anchor: CapabilityLineageAnchorV1) -> str:
    """Return the content-addressed identity for one lineage anchor."""

    if type(anchor) is not CapabilityLineageAnchorV1:
        raise TypeError("lineage anchor identity requires an exact anchor")
    return f"cganchor:{canonical_sha256(anchor)}"


def capability_lineage_anchor_document_id(anchor: CapabilityLineageAnchorV1) -> str:
    """Return the domain-separated document ID for one lineage anchor."""

    return _document_id(
        AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
        capability_lineage_anchor_logical_id(anchor),
    )


def signed_evidence_event_document_id(evidence_id: str) -> str:
    """Return the domain-separated document ID for one signed evidence event."""

    return _document_id(AuthorityStorageKind.SIGNED_EVIDENCE_EVENT, evidence_id)


def root_creation_result_document_id(root_id: str) -> str:
    """Return the domain-separated document ID for one root creation winner."""

    return _document_id(AuthorityStorageKind.ROOT_CREATION_RESULT, root_id)


def root_creation_result_v2_document_id(root_id: str) -> str:
    """Return the domain-separated document ID for one V2 creation result."""

    return _document_id(AuthorityStorageKind.ROOT_CREATION_RESULT_V2, root_id)


def evidence_chain_head_document_id(root_id: str) -> str:
    """Return the document ID for one root's mutable evidence-chain head."""

    return _document_id(AuthorityStorageKind.EVIDENCE_CHAIN_HEAD, root_id)


def epoch_revocation_identity_logical_id(kind: str, identity_value: str) -> str:
    """Return the collision domain for one revocation request identity."""

    if kind not in {"REQUEST", "IDEMPOTENCY"}:
        raise ValueError("revocation identity kind is invalid")
    return f"{kind}:{_LogicalIdentity(value=identity_value).value}"


def epoch_revocation_identity_document_id(kind: str, identity_value: str) -> str:
    """Return the immutable document ID for one revocation identity claim."""

    return _document_id(
        AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
        epoch_revocation_identity_logical_id(kind, identity_value),
    )


def epoch_revocation_result_document_id(result_id: str) -> str:
    """Return the immutable document ID for one committed revocation result."""

    return _document_id(AuthorityStorageKind.EPOCH_REVOCATION_RESULT, result_id)


def epoch_revocation_audit_document_id(audit_id: str) -> str:
    """Return the immutable document ID for one authenticated attempt audit."""

    return _document_id(AuthorityStorageKind.EPOCH_REVOCATION_AUDIT, audit_id)


def service_claim_release_identity_logical_id(kind: str, identity_value: str) -> str:
    """Return the collision domain for one claim-release request identity."""

    if kind not in {"REQUEST", "IDEMPOTENCY"}:
        raise ValueError("claim-release identity kind is invalid")
    return f"{kind}:{_LogicalIdentity(value=identity_value).value}"


def service_claim_release_identity_document_id(
    kind: str,
    identity_value: str,
) -> str:
    """Return the immutable document ID for one release identity claim."""

    return _document_id(
        AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
        service_claim_release_identity_logical_id(kind, identity_value),
    )


def service_claim_release_progress_document_id(result_id: str) -> str:
    """Return the immutable document ID for one committed release fence."""

    return _document_id(AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS, result_id)


def service_claim_release_result_document_id(result_id: str) -> str:
    """Return the immutable document ID for one completed claim release."""

    return _document_id(AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT, result_id)


def recovery_abandonment_identity_logical_id(kind: str, identity_value: str) -> str:
    """Return the isolated collision domain for one abandonment identity."""

    if kind not in {"REQUEST", "IDEMPOTENCY"}:
        raise ValueError("recovery abandonment identity kind is invalid")
    identity = _LogicalIdentity(value=identity_value).value
    digest = hashlib.sha256(
        _RECOVERY_ABANDONMENT_IDENTITY_LOGICAL_ID_DOMAIN
        + kind.encode("ascii")
        + b"\0"
        + identity.encode("ascii")
    ).hexdigest()
    return f"{kind}:{digest}"


def recovery_abandonment_identity_document_id(
    kind: str,
    identity_value: str,
) -> str:
    """Return the immutable document ID for one abandonment identity."""

    return _document_id(
        AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY,
        recovery_abandonment_identity_logical_id(kind, identity_value),
    )


def recovery_abandonment_progress_document_id(result_id: str) -> str:
    """Return the immutable document ID for one committed abandonment fence."""

    return _document_id(AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS, result_id)


def recovery_abandonment_result_document_id(result_id: str) -> str:
    """Return the immutable document ID for one finalized abandonment."""

    return _document_id(AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT, result_id)


def promotion_dispatch_identity_logical_id(kind: str, identity_value: str) -> str:
    """Return the collision domain for one promotion dispatch identity."""

    if kind not in {
        PromotionDispatchIdentityKind.REQUEST.value,
        PromotionDispatchIdentityKind.IDEMPOTENCY.value,
    }:
        raise ValueError("promotion dispatch identity kind is invalid")
    identity = _LogicalIdentity(value=identity_value).value
    digest = hashlib.sha256(
        _PROMOTION_IDENTITY_LOGICAL_ID_DOMAIN
        + kind.encode("ascii")
        + b"\0"
        + identity.encode("ascii")
    ).hexdigest()
    return f"{kind}:{digest}"


def promotion_dispatch_identity_document_id(kind: str, identity_value: str) -> str:
    """Return the immutable document ID for one promotion identity claim."""

    return _document_id(
        AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
        promotion_dispatch_identity_logical_id(kind, identity_value),
    )


def promotion_dispatch_document_id(dispatch_id: str) -> str:
    """Return the document ID for one monotonic promotion dispatch."""

    return _document_id(AuthorityStorageKind.PROMOTION_DISPATCH, dispatch_id)


def promotion_dispatch_identity_v2_logical_id(kind: str, identity_value: str) -> str:
    """Return the isolated collision domain for one V2 promotion identity."""

    if kind not in {
        PromotionDispatchIdentityKind.REQUEST.value,
        PromotionDispatchIdentityKind.IDEMPOTENCY.value,
    }:
        raise ValueError("V2 promotion dispatch identity kind is invalid")
    identity = _LogicalIdentity(value=identity_value).value
    digest = hashlib.sha256(
        _PROMOTION_V2_IDENTITY_LOGICAL_ID_DOMAIN
        + kind.encode("ascii")
        + b"\0"
        + identity.encode("ascii")
    ).hexdigest()
    return f"{kind}:{digest}"


def promotion_dispatch_identity_v2_document_id(kind: str, identity_value: str) -> str:
    """Return the immutable document ID for one V2 promotion identity claim."""

    return _document_id(
        AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
        promotion_dispatch_identity_v2_logical_id(kind, identity_value),
    )


def promotion_dispatch_v2_document_id(dispatch_id: str) -> str:
    """Return the document ID for one monotonic V2 promotion dispatch."""

    return _document_id(AuthorityStorageKind.PROMOTION_DISPATCH_V2, dispatch_id)


def execution_receipt_logical_id(target: TargetBinding, idempotency_key: str) -> str:
    """Return one target-bound claim identity for an idempotency key."""

    if type(target) is not TargetBinding:
        raise TypeError("execution receipt target must be exact")
    return receipt_claim_identity(
        MutationTargetKey(
            project_id=target.project_id,
            region=target.region,
            environment=target.environment,
            service_name=target.service_name,
        ),
        idempotency_key,
    )


def execution_receipt_document_id(target: TargetBinding, idempotency_key: str) -> str:
    """Return the document ID for one target-bound idempotency claim."""

    return _document_id(
        AuthorityStorageKind.EXECUTION_RECEIPT,
        execution_receipt_logical_id(target, idempotency_key),
    )


__all__ = [
    "AUTHORITY_STORAGE_DOCUMENT_V1",
    "FIRESTORE_DOCUMENT_ID_DOMAIN",
    "SERVICE_CLAIM_ABANDONMENT_PROOF_V1",
    "SERVICE_CLAIM_ABANDONMENT_RELEASE_CONDITION",
    "SERVICE_CLAIM_STABLE_BASELINE_PROOF_V1",
    "SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1",
    "SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION",
    "SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1",
    "SERVICE_CLAIM_V2",
    "SERVICE_CLAIM_V3",
    "AuthorityStorageDocument",
    "AuthorityStorageKind",
    "ServiceClaimAbandonmentProofV1",
    "ServiceClaimRecord",
    "ServiceClaimRecordV3",
    "ServiceClaimRecordValue",
    "ServiceClaimStableBaselineProofV1",
    "ServiceClaimStatus",
    "ServiceClaimTargetClassification",
    "ServiceClaimTargetClassificationProof",
    "ServiceClaimTerminalRootProof",
    "ServiceClaimTerminalRootState",
    "active_service_claim_matches_root",
    "active_service_claim_matches_root_v2",
    "active_service_claim_matches_root_v3",
    "capability_lineage_anchor_document_id",
    "capability_lineage_anchor_logical_id",
    "epoch_authority_document_id",
    "epoch_revocation_audit_document_id",
    "epoch_revocation_identity_document_id",
    "epoch_revocation_identity_logical_id",
    "epoch_revocation_result_document_id",
    "evidence_chain_head_document_id",
    "execution_receipt_document_id",
    "execution_receipt_logical_id",
    "promotion_dispatch_document_id",
    "promotion_dispatch_identity_document_id",
    "promotion_dispatch_identity_logical_id",
    "promotion_dispatch_identity_v2_document_id",
    "promotion_dispatch_identity_v2_logical_id",
    "promotion_dispatch_v2_document_id",
    "recovery_abandonment_identity_document_id",
    "recovery_abandonment_identity_logical_id",
    "recovery_abandonment_progress_document_id",
    "recovery_abandonment_result_document_id",
    "rollout_root_document_id",
    "rollout_root_v2_document_id",
    "rollout_root_v3_document_id",
    "root_creation_result_document_id",
    "root_creation_result_v2_document_id",
    "service_claim_document_id",
    "service_claim_logical_id",
    "service_claim_matches_root",
    "service_claim_matches_root_v2",
    "service_claim_matches_root_v3",
    "service_claim_release_identity_document_id",
    "service_claim_release_identity_logical_id",
    "service_claim_release_progress_document_id",
    "service_claim_release_result_document_id",
    "signed_evidence_event_document_id",
]
