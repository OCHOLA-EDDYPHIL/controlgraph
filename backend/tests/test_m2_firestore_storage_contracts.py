import json

import pytest
from pydantic import ValidationError

from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
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
    SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
    SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
    SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
    AuthorityStorageDocument,
    AuthorityStorageKind,
    ServiceClaimRecord,
    ServiceClaimStatus,
    ServiceClaimTargetClassification,
    ServiceClaimTargetClassificationProof,
    ServiceClaimTerminalRootProof,
    ServiceClaimTerminalRootState,
    epoch_authority_document_id,
    execution_receipt_document_id,
    execution_receipt_logical_id,
    rollout_root_document_id,
    service_claim_document_id,
    service_claim_logical_id,
)

ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64


def target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id="controlgraph-canary-a1b2c3",
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )


def root() -> RolloutRoot:
    configured_target = target()
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=configured_target,
        stable_revision="controlgraph-reference-target-stable-v16",
        traffic=(
            TrafficAllocation(
                revision="controlgraph-reference-target-stable-v16",
                percent=100,
            ),
        ),
        concurrency=8,
        service_generation=12,
        provider_etag="etag-stable-12",
        configuration_sha256=ZERO_DIGEST,
        stable_revision_configuration_sha256=ONE_DIGEST,
        captured_at="2026-08-19T12:00:00Z",
        captured_by=(
            f"controlgraph-verifier@{configured_target.project_id}.iam.gserviceaccount.com"
        ),
    )
    return RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id="root-storage-001",
        target=configured_target,
        stable_snapshot=snapshot,
        candidate_revision="controlgraph-reference-target-candidate-v16",
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
    stable_target_configuration_sha256 = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=value.target,
            stable_revision=value.stable_snapshot.stable_revision,
            candidate_revision=value.candidate_revision,
            stable_percent=100,
            candidate_percent=0,
            concurrency=value.stable_snapshot.concurrency,
        )
    )
    candidate_target_configuration_sha256 = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=value.target,
            stable_revision=value.stable_snapshot.stable_revision,
            candidate_revision=value.candidate_revision,
            stable_percent=0,
            candidate_percent=100,
            concurrency=value.stable_snapshot.concurrency,
        )
    )
    return ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v2",
        target=value.target,
        root_id=value.root_id,
        root_sha256=canonical_sha256(value),
        stable_revision=value.stable_snapshot.stable_revision,
        candidate_revision=value.candidate_revision,
        initial_epoch=value.initial_epoch,
        baseline_service_generation=value.stable_snapshot.service_generation,
        baseline_configuration_sha256=value.stable_snapshot.configuration_sha256,
        baseline_revision_configuration_sha256=(
            value.stable_snapshot.stable_revision_configuration_sha256
        ),
        candidate_revision_configuration_sha256=TWO_DIGEST,
        stable_target_configuration_sha256=stable_target_configuration_sha256,
        candidate_target_configuration_sha256=candidate_target_configuration_sha256,
        operator_owner=value.approved_by,
        workload_creator="controlgraph.api/v1",
        terminal_release_condition=SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
        status=ServiceClaimStatus.ACTIVE,
        claim_request_id="request-root-001",
        claim_evidence_id="evidence-root-001",
        claimed_at="2026-08-19T12:01:01Z",
        release_fence_epoch=None,
        release_fence_authority_revision=None,
        release_fenced_by=None,
        release_fence_request_id=None,
        release_fence_evidence_id=None,
        release_fenced_at=None,
        released_by=None,
        release_request_id=None,
        release_evidence_id=None,
        released_at=None,
        terminal_root_proof=None,
        target_classification_proof=None,
    )


def release_proofs(
    claim: ServiceClaimRecord,
    *,
    state: ServiceClaimTerminalRootState = ServiceClaimTerminalRootState.RECOVERED,
) -> tuple[ServiceClaimTerminalRootProof, ServiceClaimTargetClassificationProof]:
    target_configuration_sha256 = (
        claim.candidate_target_configuration_sha256
        if state is ServiceClaimTerminalRootState.PROMOTED
        else claim.stable_target_configuration_sha256
    )
    classification_value = (
        ServiceClaimTargetClassification.CANDIDATE_PROMOTED
        if state is ServiceClaimTerminalRootState.PROMOTED
        else ServiceClaimTargetClassification.STABLE_RESTORED
    )
    terminal = ServiceClaimTerminalRootProof(
        schema_version=SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
        target=claim.target,
        root_id=claim.root_id,
        root_sha256=claim.root_sha256,
        state=state,
        target_configuration_sha256=target_configuration_sha256,
        evidence_id="evidence-terminal-001",
        evidence_sha256=ZERO_DIGEST,
        confirmed_by="controlgraph.coordinator/v1",
        confirmed_at="2026-08-19T12:03:00Z",
    )
    classification = ServiceClaimTargetClassificationProof(
        schema_version=SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
        target=claim.target,
        root_id=claim.root_id,
        root_sha256=claim.root_sha256,
        classification=classification_value,
        fenced_epoch=2,
        fenced_authority_revision=1,
        service_generation=14,
        provider_etag="etag-stable-14",
        target_configuration_sha256=target_configuration_sha256,
        evidence_id="evidence-target-001",
        evidence_sha256=ONE_DIGEST,
        classified_by=(
            f"controlgraph-verifier@{claim.target.project_id}.iam.gserviceaccount.com"
        ),
        classified_at="2026-08-19T12:04:00Z",
    )
    return terminal, classification


def releasing_claim() -> ServiceClaimRecord:
    claim = active_claim()
    terminal, _ = release_proofs(claim)
    return ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASING,
            "release_fence_epoch": 2,
            "release_fence_authority_revision": 1,
            "release_fenced_by": "controlgraph.operator/v1",
            "release_fence_request_id": "request-fence-001",
            "release_fence_evidence_id": "evidence-fence-001",
            "release_fenced_at": "2026-08-19T12:03:30Z",
            "terminal_root_proof": terminal,
        }
    )


def released_claim() -> ServiceClaimRecord:
    claim = releasing_claim()
    _, classification = release_proofs(claim)
    return ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASED,
            "released_by": "controlgraph.coordinator/v1",
            "release_request_id": "request-release-001",
            "release_evidence_id": "evidence-release-001",
            "released_at": "2026-08-19T12:05:00Z",
            "target_classification_proof": classification,
        }
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
    assert service_claim_logical_id(value) == (
        "586e47586241392bb56b7adf22c42b6b86c1c56043e574cf4d1bf229997393ed"
    )
    assert service_claim_document_id(value) == (
        "ecabfa5ef82a81d131906692c587615912bca8b09dcfd57b207b1c70b111275a"
    )
    assert execution_receipt_logical_id(value, "same-logical-id") == (
        execution_receipt_logical_id(value, "same-logical-id")
    )


def test_service_claim_key_binds_every_admitted_coordinate_without_aliases() -> None:
    value = target()
    other_project = value.model_copy(update={"project_id": "controlgraph-canary-d4e5f6"})

    assert service_claim_logical_id(other_project) != service_claim_logical_id(value)
    for change in (
        {"project_id": "controlgraph-canary-reconcile"},
        {"region": "us-central01"},
        {"environment": "acceptance"},
        {"service_name": "controlgraph-reference-targe"},
    ):
        alias = value.model_copy(update=change)
        with pytest.raises(ValueError, match="outside the ControlGraph boundary"):
            service_claim_logical_id(alias)


@pytest.mark.parametrize("logical_id", ["", " contains-space", "bad/path", "\N{SNOWMAN}"])
def test_document_ids_reject_noncanonical_logical_identifiers(logical_id: str) -> None:
    with pytest.raises(ValueError, match="logical identifier is invalid"):
        rollout_root_document_id(logical_id)


def test_service_claim_lifecycle_is_closed_and_complete() -> None:
    claim = active_claim()
    releasing = releasing_claim()
    released = released_claim()

    assert releasing.status is ServiceClaimStatus.RELEASING
    assert released.status is ServiceClaimStatus.RELEASED
    with pytest.raises(ValidationError, match="complete epoch fence"):
        ServiceClaimRecord(
            **{
                **claim.model_dump(mode="python"),
                "status": ServiceClaimStatus.RELEASED,
            }
        )


def test_service_claim_separates_operator_and_workload_identities() -> None:
    claim = active_claim()

    with pytest.raises(ValidationError, match="operator and workload identities"):
        ServiceClaimRecord(
            **{
                **claim.model_dump(mode="python"),
                "operator_owner": claim.workload_creator,
            }
        )


def test_released_claim_rejects_unbound_or_reused_proof_material() -> None:
    claim = active_claim()
    terminal, classification = release_proofs(claim)
    values: dict[str, object] = {
        **claim.model_dump(mode="python"),
        "status": ServiceClaimStatus.RELEASED,
        "release_fence_epoch": 2,
        "release_fence_authority_revision": 1,
        "release_fenced_by": "controlgraph.operator/v1",
        "release_fence_request_id": "request-fence-001",
        "release_fence_evidence_id": "evidence-fence-001",
        "release_fenced_at": "2026-08-19T12:03:30Z",
        "released_by": "controlgraph.coordinator/v1",
        "release_request_id": "request-release-001",
        "release_evidence_id": "evidence-release-001",
        "released_at": "2026-08-19T12:05:00Z",
        "terminal_root_proof": terminal,
        "target_classification_proof": classification,
    }

    wrong_terminal = terminal.model_copy(
        update={
            "target_configuration_sha256": claim.candidate_target_configuration_sha256,
        }
    )
    with pytest.raises(ValidationError, match="expected target state"):
        ServiceClaimRecord(  # type: ignore[arg-type]
            **{**values, "terminal_root_proof": wrong_terminal}
        )

    old_classification = classification.model_copy(
        update={"service_generation": claim.baseline_service_generation}
    )
    with pytest.raises(ValidationError, match="predates"):
        ServiceClaimRecord(  # type: ignore[arg-type]
            **{**values, "target_classification_proof": old_classification}
        )

    stale_fence = classification.model_copy(update={"fenced_epoch": 3})
    with pytest.raises(ValidationError, match="incoherent"):
        ServiceClaimRecord(  # type: ignore[arg-type]
            **{**values, "target_classification_proof": stale_fence}
        )

    with pytest.raises(ValidationError, match="independent"):
        ServiceClaimRecord(  # type: ignore[arg-type]
            **{**values, "release_evidence_id": classification.evidence_id}
        )


def test_promoted_root_and_candidate_classification_are_one_closed_pair() -> None:
    claim = active_claim()
    terminal, classification = release_proofs(
        claim,
        state=ServiceClaimTerminalRootState.PROMOTED,
    )
    values: dict[str, object] = {
        **claim.model_dump(mode="python"),
        "status": ServiceClaimStatus.RELEASED,
        "release_fence_epoch": 2,
        "release_fence_authority_revision": 1,
        "release_fenced_by": "controlgraph.operator/v1",
        "release_fence_request_id": "request-fence-promoted",
        "release_fence_evidence_id": "evidence-fence-promoted",
        "release_fenced_at": "2026-08-19T12:03:30Z",
        "released_by": "controlgraph.coordinator/v1",
        "release_request_id": "request-release-promoted",
        "release_evidence_id": "evidence-release-promoted",
        "released_at": "2026-08-19T12:05:00Z",
        "terminal_root_proof": terminal,
        "target_classification_proof": classification,
    }

    released = ServiceClaimRecord(**values)  # type: ignore[arg-type]
    assert released.terminal_root_proof == terminal
    assert released.target_classification_proof == classification

    cross_paired = classification.model_copy(
        update={
            "classification": ServiceClaimTargetClassification.STABLE_RESTORED,
            "target_configuration_sha256": claim.stable_target_configuration_sha256,
        }
    )
    with pytest.raises(ValidationError, match="incoherent"):
        ServiceClaimRecord(  # type: ignore[arg-type]
            **{**values, "target_classification_proof": cross_paired}
        )


def test_release_evidence_references_reject_forged_actor_and_root_bindings() -> None:
    claim = active_claim()
    terminal, classification = release_proofs(claim)

    with pytest.raises(ValidationError):
        ServiceClaimTerminalRootProof(
            **{
                **terminal.model_dump(mode="python"),
                "confirmed_by": "controlgraph-verifier/v1",
            }
        )
    with pytest.raises(ValidationError, match="verifier identity"):
        ServiceClaimTargetClassificationProof(
            **{
                **classification.model_dump(mode="python"),
                "classified_by": "controlgraph.coordinator/v1",
            }
        )

    wrong_root = classification.model_copy(update={"root_sha256": TWO_DIGEST})
    released = released_claim()
    with pytest.raises(ValidationError, match="claimed root"):
        ServiceClaimRecord(
            **{
                **released.model_dump(mode="python"),
                "target_classification_proof": wrong_root,
            }
        )


def test_active_claim_rejects_any_release_metadata() -> None:
    claim = active_claim()
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


@pytest.mark.parametrize(
    ("claim", "revision"),
    [
        (active_claim(), 1),
        (releasing_claim(), 2),
        (released_claim(), 3),
    ],
)
def test_storage_wrapper_binds_claim_status_to_lifecycle_revision(
    claim: ServiceClaimRecord,
    revision: int,
) -> None:
    with pytest.raises(ValidationError, match="lifecycle and storage revision"):
        AuthorityStorageDocument(
            schema_version=AUTHORITY_STORAGE_DOCUMENT_V1,
            record_kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=service_claim_logical_id(claim.target),
            revision=revision,
            mutation_id="write-00000000000000000000000000000000",
            canonical_payload=canonical_json_bytes(claim).decode("utf-8"),
            payload_sha256=canonical_sha256(claim),
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
        changed_by=value.approved_by,
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
