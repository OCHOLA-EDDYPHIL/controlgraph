"""Compact normalized persistence contracts for signed health chains."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, ValidationError, model_validator

from controlgraph_canary.contracts.base import (
    MAX_CONTRACT_BYTES,
    Identifier,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.health import HealthDecisionStatus
from controlgraph_canary.contracts.health_execution import (
    HealthyPromotionProofV1,
    PostApplyHealthAnchorV1,
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    health_chain_manifest_sha256,
    signed_health_decision_chain_sha256,
    signed_health_proof_chain_sha256,
)
from controlgraph_canary.contracts.models import TargetBinding

HEALTH_PROOF_DOCUMENT_REFERENCE_V1: Final = (
    "controlgraph.health-proof-document-reference/v1"
)
HEALTH_CHAIN_MANIFEST_V1: Final = "controlgraph.health-chain-manifest/v1"
HEALTH_STORAGE_DOCUMENT_V1: Final = "controlgraph.health-storage-document/v1"

HEALTH_FIRESTORE_DOCUMENT_ID_DOMAIN: Final = (
    b"controlgraph.health-firestore-document-id/v1\0"
)
_SIGNED_PROOF_CHAIN_DOMAIN: Final = b"controlgraph.signed-health-proof-chain/v1\0"
_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")


class HealthStorageKind(StrEnum):
    """Closed, versioned Firestore collections for normalized health evidence."""

    POST_APPLY_HEALTH_ANCHOR = "controlgraph-post-apply-health-anchors-v1"
    SIGNED_HEALTH_DECISION_PROOF = "controlgraph-signed-health-decision-proofs-v1"
    HEALTH_CHAIN_HEAD = "controlgraph-health-chain-heads-v1"
    HEALTH_CHAIN_MANIFEST = "controlgraph-health-chain-manifests-v1"


def _require_health_target(target: TargetBinding) -> None:
    if type(target) is not TargetBinding:
        raise TypeError("health storage target must be exact")
    if (
        _CONTROLGRAPH_PROJECT_ID.fullmatch(target.project_id) is None
        or "reconcile" in target.project_id
        or target.region != "us-central1"
        or target.environment != "nonprod"
        or target.service_name != "controlgraph-reference-target"
    ):
        raise ValueError("health storage target is outside the ControlGraph boundary")


class _LogicalIdentity(StrictContractModel):
    value: Identifier


def _validated_identifier(value: str) -> str:
    try:
        return _LogicalIdentity(value=value).value
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("health storage logical identifier is invalid") from error


def _validated_digest(value: str) -> str:
    class _Digest(StrictContractModel):
        value: Sha256Digest

    try:
        return _Digest(value=value).value
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("health storage digest is invalid") from error


def _document_id(
    kind: HealthStorageKind,
    target: TargetBinding,
    *components: str,
) -> str:
    if type(kind) is not HealthStorageKind:
        raise TypeError("health storage kind must be exact")
    _require_health_target(target)
    if not components or any(
        type(component) is not str or not component for component in components
    ):
        raise ValueError("health storage document identity is invalid")
    digest = hashlib.sha256()
    digest.update(HEALTH_FIRESTORE_DOCUMENT_ID_DOMAIN)
    for component in (
        kind.value,
        canonical_sha256(target),
        *components,
    ):
        encoded = component.encode("ascii")
        digest.update(len(encoded).to_bytes(2, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def health_anchor_document_id(target: TargetBinding, anchor_id: str) -> str:
    """Return the target-scoped immutable document ID for one health anchor."""

    return _document_id(
        HealthStorageKind.POST_APPLY_HEALTH_ANCHOR,
        target,
        _validated_identifier(anchor_id),
    )


def signed_health_proof_logical_id(signed_proof_sha256: str) -> str:
    """Return the content identity for one exact signed proof wrapper."""

    return f"cgsignedhealthproof:{_validated_digest(signed_proof_sha256)}"


def signed_health_proof_document_id(
    target: TargetBinding,
    anchor_id: str,
    signed_proof_sha256: str,
) -> str:
    """Return one target- and anchor-scoped signed-proof document ID."""

    return _document_id(
        HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF,
        target,
        _validated_identifier(anchor_id),
        _validated_digest(signed_proof_sha256),
    )


def health_chain_head_document_id(target: TargetBinding, anchor_id: str) -> str:
    """Return the target-scoped CAS head document ID for one health anchor."""

    return _document_id(
        HealthStorageKind.HEALTH_CHAIN_HEAD,
        target,
        _validated_identifier(anchor_id),
    )


def health_chain_manifest_document_id(
    target: TargetBinding,
    manifest_sha256: str,
) -> str:
    """Return the target-scoped immutable lookup ID for one chain manifest."""

    return _document_id(
        HealthStorageKind.HEALTH_CHAIN_MANIFEST,
        target,
        _validated_digest(manifest_sha256),
    )


def ordered_health_proof_digests_sha256(
    signed_proof_sha256s: tuple[str, ...],
) -> str:
    """Hash an ordered sequence of signed-proof digests without an aggregate payload."""

    if (
        type(signed_proof_sha256s) is not tuple
        or not signed_proof_sha256s
        or len(signed_proof_sha256s) > 20
    ):
        raise ValueError("ordered signed-proof digest sequence is invalid")
    validated = tuple(_validated_digest(value) for value in signed_proof_sha256s)
    digest = hashlib.sha256()
    digest.update(_SIGNED_PROOF_CHAIN_DOMAIN)
    digest.update(len(validated).to_bytes(2, "big"))
    for value in validated:
        digest.update(bytes.fromhex(value))
    return digest.hexdigest()


def health_chain_manifest_components_sha256(
    *,
    anchor_sha256: str,
    ordered_proof_chain_sha256: str,
    chain_head_sha256: str,
    healthy_promotion_proof_sha256: str | None,
) -> str:
    """Recompute the health-chain helper digest from compact manifest components."""

    return health_chain_manifest_sha256(
        anchor_sha256=_validated_digest(anchor_sha256),
        ordered_proof_chain_sha256=_validated_digest(
            ordered_proof_chain_sha256
        ),
        chain_head_sha256=_validated_digest(chain_head_sha256),
        healthy_promotion_proof_sha256=(
            _validated_digest(healthy_promotion_proof_sha256)
            if healthy_promotion_proof_sha256 is not None
            else None
        ),
    )


class HealthProofDocumentReferenceV1(StrictContractModel):
    """Ordered immutable document and digest binding for one signed proof."""

    schema_version: Literal["controlgraph.health-proof-document-reference/v1"]
    sequence: Annotated[int, Field(ge=1, le=20)]
    proof_id: Identifier
    document_id: Sha256Digest
    signed_proof_sha256: Sha256Digest
    decision_sha256: Sha256Digest


class HealthChainManifestV1(StrictContractModel):
    """Compact durable chain state that never embeds the full signed proof sequence."""

    schema_version: Literal["controlgraph.health-chain-manifest/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    anchor_id: Identifier
    anchor_sha256: Sha256Digest
    chain_id: Identifier
    manifest_sha256: Sha256Digest
    ordered_proof_chain_sha256: Sha256Digest
    chain_head_sha256: Sha256Digest
    terminal_sequence: Annotated[int, Field(ge=1, le=20)]
    terminal_status: HealthDecisionStatus
    proof_documents: Annotated[
        tuple[HealthProofDocumentReferenceV1, ...],
        Field(min_length=1, max_length=20),
    ]
    healthy_promotion_proof: HealthyPromotionProofV1 | None
    healthy_promotion_proof_sha256: Sha256Digest | None

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        _require_health_target(self.target)
        if self.root_id != f"cgroot:{self.root_sha256}":
            raise ValueError("health manifest root binding is invalid")
        if len(self.proof_documents) != self.terminal_sequence:
            raise ValueError("health manifest proof count is invalid")
        signed_digests: list[str] = []
        seen_document_ids: set[str] = set()
        seen_signed_digests: set[str] = set()
        for expected_sequence, reference in enumerate(self.proof_documents, start=1):
            expected_document_id = signed_health_proof_document_id(
                self.target,
                self.anchor_id,
                reference.signed_proof_sha256,
            )
            if (
                reference.sequence != expected_sequence
                or reference.document_id != expected_document_id
                or reference.document_id in seen_document_ids
                or reference.signed_proof_sha256 in seen_signed_digests
            ):
                raise ValueError("health manifest proof reference is invalid")
            seen_document_ids.add(reference.document_id)
            seen_signed_digests.add(reference.signed_proof_sha256)
            signed_digests.append(reference.signed_proof_sha256)
        expected_ordered_digest = ordered_health_proof_digests_sha256(
            tuple(signed_digests)
        )
        compact = self.healthy_promotion_proof
        compact_sha256 = (
            canonical_sha256(compact) if compact is not None else None
        )
        if (
            self.ordered_proof_chain_sha256 != expected_ordered_digest
            or self.chain_head_sha256 != self.proof_documents[-1].signed_proof_sha256
            or self.healthy_promotion_proof_sha256 != compact_sha256
        ):
            raise ValueError("health manifest digest bindings are invalid")
        if self.terminal_status is HealthDecisionStatus.HEALTHY:
            terminal = self.proof_documents[-1]
            if (
                compact is None
                or compact.anchor_id != self.anchor_id
                or compact.anchor_sha256 != self.anchor_sha256
                or compact.root_id != self.root_id
                or compact.root_sha256 != self.root_sha256
                or compact.target != self.target
                or compact.epoch != self.epoch
                or compact.terminal_sequence != self.terminal_sequence
                or compact.terminal_health_decision_sha256
                != terminal.decision_sha256
                or compact.signed_health_chain_sha256
                != self.ordered_proof_chain_sha256
            ):
                raise ValueError("healthy manifest compact proof is invalid")
        elif compact is not None:
            raise ValueError("non-healthy manifest cannot carry a promotion proof")
        expected_manifest_sha256 = health_chain_manifest_components_sha256(
            anchor_sha256=self.anchor_sha256,
            ordered_proof_chain_sha256=self.ordered_proof_chain_sha256,
            chain_head_sha256=self.chain_head_sha256,
            healthy_promotion_proof_sha256=self.healthy_promotion_proof_sha256,
        )
        if (
            self.manifest_sha256 != expected_manifest_sha256
            or self.chain_id != f"cghealthchain:{self.manifest_sha256}"
        ):
            raise ValueError("health manifest identity is invalid")
        return self


def create_health_chain_manifest(
    chain: SignedHealthDecisionChainV1,
) -> HealthChainManifestV1:
    """Project an in-process chain into its bounded normalized manifest."""

    if type(chain) is not SignedHealthDecisionChainV1:
        raise TypeError("health manifest creation requires an exact signed chain")
    signed_digests = tuple(canonical_sha256(proof) for proof in chain.signed_proofs)
    proof_documents = tuple(
        HealthProofDocumentReferenceV1(
            schema_version=HEALTH_PROOF_DOCUMENT_REFERENCE_V1,
            sequence=signed.proof.sequence,
            proof_id=signed.proof.proof_id,
            document_id=signed_health_proof_document_id(
                chain.anchor.target,
                chain.anchor.anchor_id,
                signed_sha256,
            ),
            signed_proof_sha256=signed_sha256,
            decision_sha256=signed.proof.decision_sha256,
        )
        for signed, signed_sha256 in zip(chain.signed_proofs, signed_digests, strict=True)
    )
    compact = chain.healthy_promotion_proof
    manifest_sha256 = signed_health_decision_chain_sha256(chain)
    manifest = HealthChainManifestV1(
        schema_version=HEALTH_CHAIN_MANIFEST_V1,
        target=chain.anchor.target,
        root_id=chain.anchor.root_id,
        root_sha256=chain.anchor.root_sha256,
        epoch=chain.anchor.epoch,
        anchor_id=chain.anchor.anchor_id,
        anchor_sha256=chain.anchor_sha256,
        chain_id=chain.chain_id,
        manifest_sha256=manifest_sha256,
        ordered_proof_chain_sha256=signed_health_proof_chain_sha256(
            chain.signed_proofs
        ),
        chain_head_sha256=chain.chain_head_sha256,
        terminal_sequence=chain.signed_proofs[-1].proof.sequence,
        terminal_status=chain.signed_proofs[-1].proof.decision.status,
        proof_documents=proof_documents,
        healthy_promotion_proof=compact,
        healthy_promotion_proof_sha256=(
            canonical_sha256(compact) if compact is not None else None
        ),
    )
    if manifest.manifest_sha256 != signed_health_decision_chain_sha256(chain):
        raise ValueError("health manifest does not match the chain helper digest")
    return manifest


class HealthStorageDocumentV1(StrictContractModel):
    """Exact canonical payload wrapper for one normalized health document."""

    schema_version: Literal["controlgraph.health-storage-document/v1"]
    record_kind: HealthStorageKind
    target: TargetBinding
    logical_id: Identifier
    revision: Annotated[int, Field(ge=0, le=20)]
    mutation_id: Identifier
    canonical_payload: Annotated[str, Field(min_length=2, max_length=MAX_CONTRACT_BYTES)]
    payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        _require_health_target(self.target)
        model_type: type[StrictContractModel]
        if self.record_kind is HealthStorageKind.POST_APPLY_HEALTH_ANCHOR:
            model_type = PostApplyHealthAnchorV1
        elif self.record_kind is HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF:
            model_type = SignedHealthDecisionProofV1
        else:
            model_type = HealthChainManifestV1
        try:
            payload = decode_contract(self.canonical_payload, model_type)
        except ContractError as error:
            raise ValueError("health storage payload is invalid") from error
        if canonical_sha256(payload) != self.payload_sha256:
            raise ValueError("health storage payload digest does not match")
        if self.record_kind is HealthStorageKind.POST_APPLY_HEALTH_ANCHOR:
            anchor = cast(PostApplyHealthAnchorV1, payload)
            expected_logical_id = anchor.anchor_id
            expected_target = anchor.target
            expected_revision = 0
        elif self.record_kind is HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF:
            proof = cast(SignedHealthDecisionProofV1, payload)
            expected_logical_id = signed_health_proof_logical_id(
                canonical_sha256(proof)
            )
            expected_target = proof.proof.decision.target
            expected_revision = 0
        else:
            manifest = cast(HealthChainManifestV1, payload)
            expected_logical_id = (
                manifest.anchor_id
                if self.record_kind is HealthStorageKind.HEALTH_CHAIN_HEAD
                else manifest.chain_id
            )
            expected_target = manifest.target
            expected_revision = manifest.terminal_sequence
        if (
            self.logical_id != expected_logical_id
            or self.target != expected_target
            or self.revision != expected_revision
        ):
            raise ValueError("health storage wrapper binding is invalid")
        return self


def health_storage_document_payload(
    document: HealthStorageDocumentV1,
) -> StrictContractModel:
    """Decode one exact health storage wrapper without aggregate-chain decoding."""

    if type(document) is not HealthStorageDocumentV1:
        raise TypeError("health storage wrapper must be exact")
    model_type: type[StrictContractModel]
    if document.record_kind is HealthStorageKind.POST_APPLY_HEALTH_ANCHOR:
        model_type = PostApplyHealthAnchorV1
    elif document.record_kind is HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF:
        model_type = SignedHealthDecisionProofV1
    else:
        model_type = HealthChainManifestV1
    return decode_contract(document.canonical_payload, model_type)


def health_storage_payload_fits(value: StrictContractModel) -> bool:
    """Return whether one normalized payload fits the canonical contract bound."""

    try:
        canonical_json_bytes(value)
    except (ContractError, TypeError, ValueError):
        return False
    return True


__all__ = [
    "HEALTH_CHAIN_MANIFEST_V1",
    "HEALTH_FIRESTORE_DOCUMENT_ID_DOMAIN",
    "HEALTH_PROOF_DOCUMENT_REFERENCE_V1",
    "HEALTH_STORAGE_DOCUMENT_V1",
    "HealthChainManifestV1",
    "HealthProofDocumentReferenceV1",
    "HealthStorageDocumentV1",
    "HealthStorageKind",
    "create_health_chain_manifest",
    "health_anchor_document_id",
    "health_chain_head_document_id",
    "health_chain_manifest_components_sha256",
    "health_chain_manifest_document_id",
    "health_storage_document_payload",
    "health_storage_payload_fits",
    "ordered_health_proof_digests_sha256",
    "signed_health_proof_document_id",
    "signed_health_proof_logical_id",
]
