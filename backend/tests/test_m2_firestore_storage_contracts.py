import json

import pytest
from pydantic import ValidationError

from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    ReceiptOutcome,
    RolloutRoot,
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
)
from controlgraph_canary.contracts.storage import (
    AUTHORITY_STORAGE_DOCUMENT_V1,
    AuthorityStorageDocument,
    AuthorityStorageKind,
    ServiceClaimRecord,
    ServiceClaimStatus,
    epoch_authority_document_id,
    execution_receipt_document_id,
    execution_receipt_logical_id,
    rollout_root_document_id,
    service_claim_document_id,
    service_claim_logical_id,
)

ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64


def target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id="controlgraph-canary-a1b2c3",
        region="us-central1",
        environment="acceptance",
        service_name="reference-target",
    )


def root() -> RolloutRoot:
    configured_target = target()
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=configured_target,
        stable_revision="reference-stable",
        traffic=(TrafficAllocation(revision="reference-stable", percent=100),),
        concurrency=8,
        service_generation=12,
        provider_etag="etag-stable-12",
        configuration_sha256=ZERO_DIGEST,
        stable_revision_configuration_sha256=ONE_DIGEST,
        captured_at="2026-08-19T12:00:00Z",
        captured_by="controlgraph.operator/v1",
    )
    return RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id="root-storage-001",
        target=configured_target,
        stable_snapshot=snapshot,
        candidate_revision="reference-candidate",
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=ONE_DIGEST,
        maximum_recovery_attempts=1,
        initial_epoch=1,
        plan_sha256=ZERO_DIGEST,
        approved_by="controlgraph.operator/v1",
        approved_at="2026-08-19T12:01:00Z",
    )


def claimed_receipt() -> ExecutionReceipt:
    value = root()
    idempotency_key = "intent-storage-001"
    return ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(value.target, idempotency_key),
        request_id="request-storage-001",
        idempotency_key=idempotency_key,
        capability_sha256=ZERO_DIGEST,
        mutation_sha256=ONE_DIGEST,
        plan_sha256=value.plan_sha256,
        expected_poststate_sha256=ONE_DIGEST,
        target=value.target,
        root_id=value.root_id,
        root_sha256=canonical_sha256(value),
        epoch=value.initial_epoch,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag=value.stable_snapshot.provider_etag,
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=None,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:02:00Z",
        evidence_ids=("evidence-storage-001",),
    )


def active_claim() -> ServiceClaimRecord:
    value = root()
    return ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v1",
        target=value.target,
        root_id=value.root_id,
        root_sha256=canonical_sha256(value),
        status=ServiceClaimStatus.ACTIVE,
        claimed_by="controlgraph.api/v1",
        claim_request_id="request-root-001",
        claim_evidence_id="evidence-root-001",
        claimed_at="2026-08-19T12:01:01Z",
        released_by=None,
        release_request_id=None,
        release_evidence_id=None,
        released_at=None,
    )


def test_document_ids_are_deterministic_fixed_and_domain_separated() -> None:
    value = target()
    document_ids = {
        rollout_root_document_id("same-logical-id"),
        epoch_authority_document_id("same-logical-id"),
        execution_receipt_document_id(value, "same-logical-id"),
        service_claim_document_id(value),
    }

    assert len(document_ids) == 4
    assert all(len(document_id) == 64 for document_id in document_ids)
    assert rollout_root_document_id("same-logical-id") == rollout_root_document_id(
        "same-logical-id"
    )
    assert service_claim_logical_id(value) == canonical_sha256(value)
    assert execution_receipt_logical_id(value, "same-logical-id") == (
        execution_receipt_logical_id(value, "same-logical-id")
    )


@pytest.mark.parametrize("logical_id", ["", " contains-space", "bad/path", "\N{SNOWMAN}"])
def test_document_ids_reject_noncanonical_logical_identifiers(logical_id: str) -> None:
    with pytest.raises(ValueError, match="logical identifier is invalid"):
        rollout_root_document_id(logical_id)


def test_service_claim_lifecycle_is_closed_and_complete() -> None:
    claim = active_claim()

    released = ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASED,
            "released_by": "controlgraph.coordinator/v1",
            "release_request_id": "request-release-001",
            "release_evidence_id": "evidence-release-001",
            "released_at": "2026-08-19T12:05:00Z",
        }
    )

    assert released.status is ServiceClaimStatus.RELEASED
    with pytest.raises(ValidationError, match="complete release metadata"):
        ServiceClaimRecord(
            **{
                **claim.model_dump(mode="python"),
                "status": ServiceClaimStatus.RELEASED,
            }
        )
    with pytest.raises(ValidationError, match="cannot contain release metadata"):
        ServiceClaimRecord(
            **{
                **claim.model_dump(mode="python"),
                "released_by": "controlgraph.coordinator/v1",
            }
        )


def test_storage_wrapper_validates_exact_payload_digest_and_identity() -> None:
    value = root()
    payload = canonical_json_bytes(value).decode("utf-8")
    document = AuthorityStorageDocument(
        schema_version=AUTHORITY_STORAGE_DOCUMENT_V1,
        record_kind=AuthorityStorageKind.ROLLOUT_ROOT,
        logical_id=value.root_id,
        revision=0,
        mutation_id="write-00000000000000000000000000000000",
        canonical_payload=payload,
        payload_sha256=canonical_sha256(value),
    )

    assert document.canonical_payload == payload
    with pytest.raises(ValidationError, match="digest does not match"):
        AuthorityStorageDocument(
            **{
                **document.model_dump(mode="python"),
                "payload_sha256": ZERO_DIGEST,
            }
        )
    with pytest.raises(ValidationError, match="identity does not match"):
        AuthorityStorageDocument(
            **{
                **document.model_dump(mode="python"),
                "logical_id": "other-root",
            }
        )
    changed = json.loads(payload)
    changed["approved_by"] = "different-operator"
    noncanonical = json.dumps(changed)
    with pytest.raises(ValidationError, match="payload is invalid"):
        AuthorityStorageDocument(
            **{
                **document.model_dump(mode="python"),
                "canonical_payload": noncanonical,
            }
        )


def test_storage_wrapper_rejects_nonzero_immutable_root_revision() -> None:
    value = root()
    with pytest.raises(ValidationError, match="must remain at revision zero"):
        AuthorityStorageDocument(
            schema_version=AUTHORITY_STORAGE_DOCUMENT_V1,
            record_kind=AuthorityStorageKind.ROLLOUT_ROOT,
            logical_id=value.root_id,
            revision=1,
            mutation_id="write-00000000000000000000000000000000",
            canonical_payload=canonical_json_bytes(value).decode("utf-8"),
            payload_sha256=canonical_sha256(value),
        )


def test_storage_wrapper_seals_receipts_to_the_target_idempotency_claim() -> None:
    receipt = claimed_receipt()
    document = AuthorityStorageDocument(
        schema_version=AUTHORITY_STORAGE_DOCUMENT_V1,
        record_kind=AuthorityStorageKind.EXECUTION_RECEIPT,
        logical_id=receipt.receipt_id,
        revision=0,
        mutation_id="write-00000000000000000000000000000000",
        canonical_payload=canonical_json_bytes(receipt).decode("utf-8"),
        payload_sha256=canonical_sha256(receipt),
    )

    assert document.logical_id == receipt.receipt_id
    attacker_selected = receipt.model_copy(update={"receipt_id": ONE_DIGEST})
    with pytest.raises(ValidationError, match="identity does not match its claim key"):
        AuthorityStorageDocument(
            **{
                **document.model_dump(mode="python"),
                "logical_id": attacker_selected.receipt_id,
                "canonical_payload": canonical_json_bytes(attacker_selected).decode("utf-8"),
                "payload_sha256": canonical_sha256(attacker_selected),
            }
        )


def test_storage_wrapper_requires_matching_authority_revisions() -> None:
    value = root()
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=value.root_id,
        root_sha256=canonical_sha256(value),
        target=value.target,
        current_epoch=1,
        previous_epoch=None,
        revision=0,
        cause=EpochChangeCause.ROOT_CREATED,
        changed_by="controlgraph.api/v1",
        request_id="request-root-001",
        evidence_id="evidence-root-001",
        changed_at="2026-08-19T12:01:01Z",
    )
    with pytest.raises(ValidationError, match="revisions do not match"):
        AuthorityStorageDocument(
            schema_version=AUTHORITY_STORAGE_DOCUMENT_V1,
            record_kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=authority.root_id,
            revision=1,
            mutation_id="write-00000000000000000000000000000000",
            canonical_payload=canonical_json_bytes(authority).decode("utf-8"),
            payload_sha256=canonical_sha256(authority),
        )
