from __future__ import annotations

import pytest
from health_execution_test_data import make_healthy_chain
from health_storage_test_data import make_twenty_proof_chain
from pydantic import ValidationError

from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.health_execution import (
    health_chain_manifest_sha256,
    signed_health_decision_chain_sha256,
    signed_health_proof_chain_sha256,
)
from controlgraph_canary.contracts.health_storage import (
    HealthChainManifestV1,
    create_health_chain_manifest,
    health_anchor_document_id,
    health_chain_head_document_id,
    health_chain_manifest_components_sha256,
    health_chain_manifest_document_id,
    ordered_health_proof_digests_sha256,
    signed_health_proof_document_id,
)
from controlgraph_canary.contracts.models import TargetBinding


def test_manifest_matches_both_health_chain_digest_helpers_without_aggregate_payload() -> None:
    chain = make_healthy_chain()
    manifest = create_health_chain_manifest(chain)
    signed_digests = tuple(canonical_sha256(value) for value in chain.signed_proofs)

    assert manifest.chain_id == chain.chain_id
    assert manifest.anchor_id == chain.anchor.anchor_id
    assert manifest.anchor_sha256 == chain.anchor_sha256
    assert manifest.manifest_sha256 == signed_health_decision_chain_sha256(chain)
    assert manifest.ordered_proof_chain_sha256 == ordered_health_proof_digests_sha256(
        signed_digests
    )
    assert manifest.ordered_proof_chain_sha256 == signed_health_proof_chain_sha256(
        chain.signed_proofs
    )
    assert manifest.chain_head_sha256 == signed_digests[-1]
    assert manifest.healthy_promotion_proof == chain.healthy_promotion_proof
    assert "signed_proofs" not in HealthChainManifestV1.model_fields
    assert "anchor" not in HealthChainManifestV1.model_fields
    assert len(canonical_json_bytes(manifest)) < MAX_CONTRACT_BYTES


def test_manifest_component_hash_rejects_any_substituted_binding() -> None:
    manifest = create_health_chain_manifest(make_healthy_chain())
    assert manifest.manifest_sha256 == health_chain_manifest_components_sha256(
        anchor_sha256=manifest.anchor_sha256,
        ordered_proof_chain_sha256=manifest.ordered_proof_chain_sha256,
        chain_head_sha256=manifest.chain_head_sha256,
        healthy_promotion_proof_sha256=manifest.healthy_promotion_proof_sha256,
    )
    assert manifest.manifest_sha256 == health_chain_manifest_sha256(
        anchor_sha256=manifest.anchor_sha256,
        ordered_proof_chain_sha256=manifest.ordered_proof_chain_sha256,
        chain_head_sha256=manifest.chain_head_sha256,
        healthy_promotion_proof_sha256=manifest.healthy_promotion_proof_sha256,
    )

    values = manifest.model_dump(mode="python")
    values["chain_head_sha256"] = "f" * 64
    with pytest.raises(ValidationError):
        HealthChainManifestV1.model_validate(values)


def test_twenty_proof_manifest_remains_bounded_and_references_every_document() -> None:
    chain = make_twenty_proof_chain()
    manifest = create_health_chain_manifest(chain)

    assert len(chain.signed_proofs) == len(manifest.proof_documents) == 20
    assert manifest.terminal_sequence == 20
    assert len(canonical_json_bytes(manifest)) < MAX_CONTRACT_BYTES
    assert all(
        reference.sequence == index
        and reference.signed_proof_sha256 == canonical_sha256(chain.signed_proofs[index - 1])
        for index, reference in enumerate(manifest.proof_documents, start=1)
    )


def test_firestore_document_ids_are_versioned_target_and_anchor_scoped() -> None:
    chain = make_healthy_chain()
    manifest = create_health_chain_manifest(chain)
    target = chain.anchor.target
    other_target = TargetBinding(
        **{
            **target.model_dump(mode="python"),
            "project_id": "controlgraph-canary-b2c3d4",
        }
    )
    signed_digest = manifest.proof_documents[0].signed_proof_sha256

    assert health_anchor_document_id(target, manifest.anchor_id) != health_anchor_document_id(
        other_target,
        manifest.anchor_id,
    )
    assert health_chain_head_document_id(
        target,
        manifest.anchor_id,
    ) != health_chain_head_document_id(other_target, manifest.anchor_id)
    assert health_chain_manifest_document_id(
        target,
        manifest.manifest_sha256,
    ) != health_chain_manifest_document_id(
        other_target,
        manifest.manifest_sha256,
    )
    assert signed_health_proof_document_id(
        target,
        manifest.anchor_id,
        signed_digest,
    ) != signed_health_proof_document_id(
        target,
        "cghealthanchor:" + "a" * 64,
        signed_digest,
    )
