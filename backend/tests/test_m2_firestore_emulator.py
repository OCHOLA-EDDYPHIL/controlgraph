"""Real Firestore-emulator races for the M2 authority-store boundary."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence
from uuid import uuid4

import pytest

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    CreatedRollout,
    FinalAuthoritySnapshot,
    IssuanceStateSnapshot,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    StoredRecord,
)
from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_sha256
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
    SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
    SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
    SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
    ServiceClaimRecord,
    ServiceClaimStatus,
    ServiceClaimTargetClassification,
    ServiceClaimTargetClassificationProof,
    ServiceClaimTerminalRootProof,
    ServiceClaimTerminalRootState,
    execution_receipt_logical_id,
)
from controlgraph_canary.integrations.google.firestore import FirestoreAuthorityStore

pytestmark = pytest.mark.skipif(
    not os.environ.get("FIRESTORE_EMULATOR_HOST"),
    reason="requires a running Firestore emulator",
)

ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
THREE_DIGEST = "3" * 64
FOUR_DIGEST = "4" * 64


def _initial_records(
    *,
    target: TargetBinding,
    root_id: str,
    captured_at: str = "2026-08-19T12:00:00Z",
    approved_at: str = "2026-08-19T12:01:00Z",
    claimed_at: str = "2026-08-19T12:01:01Z",
    service_generation: int = 12,
) -> tuple[RolloutRoot, ServiceClaimRecord, EpochAuthorityRecord]:
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=target,
        stable_revision="controlgraph-reference-target-stable-v15",
        traffic=(
            TrafficAllocation(
                revision="controlgraph-reference-target-stable-v15",
                percent=100,
            ),
        ),
        concurrency=8,
        service_generation=service_generation,
        provider_etag=f"etag-stable-{service_generation}",
        configuration_sha256=ZERO_DIGEST,
        stable_revision_configuration_sha256=ONE_DIGEST,
        captured_at=captured_at,
        captured_by=f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com",
    )
    root = RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id=root_id,
        target=target,
        stable_snapshot=snapshot,
        candidate_revision="controlgraph-reference-target-candidate-v15",
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=ONE_DIGEST,
        maximum_recovery_attempts=1,
        initial_epoch=1,
        plan_sha256=TWO_DIGEST,
        approved_by="controlgraph.operator/v1",
        approved_at=approved_at,
    )
    root_sha256 = canonical_sha256(root)
    stable_target_configuration_sha256 = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=root.target,
            stable_revision=root.stable_snapshot.stable_revision,
            candidate_revision=root.candidate_revision,
            stable_percent=100,
            candidate_percent=0,
            concurrency=root.stable_snapshot.concurrency,
        )
    )
    candidate_target_configuration_sha256 = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=root.target,
            stable_revision=root.stable_snapshot.stable_revision,
            candidate_revision=root.candidate_revision,
            stable_percent=0,
            candidate_percent=100,
            concurrency=root.stable_snapshot.concurrency,
        )
    )
    claim = ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v2",
        target=target,
        root_id=root.root_id,
        root_sha256=root_sha256,
        stable_revision=root.stable_snapshot.stable_revision,
        candidate_revision=root.candidate_revision,
        initial_epoch=root.initial_epoch,
        baseline_service_generation=root.stable_snapshot.service_generation,
        baseline_configuration_sha256=root.stable_snapshot.configuration_sha256,
        baseline_revision_configuration_sha256=(
            root.stable_snapshot.stable_revision_configuration_sha256
        ),
        candidate_revision_configuration_sha256=THREE_DIGEST,
        stable_target_configuration_sha256=stable_target_configuration_sha256,
        candidate_target_configuration_sha256=candidate_target_configuration_sha256,
        operator_owner=root.approved_by,
        workload_creator="controlgraph.api/v1",
        terminal_release_condition=SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
        status=ServiceClaimStatus.ACTIVE,
        claim_request_id=f"request-{root_id}",
        claim_evidence_id=f"evidence-{root_id}",
        claimed_at=claimed_at,
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
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root_sha256,
        target=target,
        current_epoch=1,
        previous_epoch=None,
        revision=0,
        cause=EpochChangeCause.ROOT_CREATED,
        changed_by=root.approved_by,
        request_id=claim.claim_request_id,
        evidence_id=claim.claim_evidence_id,
        changed_at=claimed_at,
    )
    return root, claim, authority


def _revocation(current: EpochAuthorityRecord, *, suffix: str) -> EpochAuthorityRecord:
    return EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=current.root_id,
        root_sha256=current.root_sha256,
        target=current.target,
        current_epoch=current.current_epoch + 1,
        previous_epoch=current.current_epoch,
        revision=current.revision + 1,
        cause=EpochChangeCause.OPERATOR_REVOCATION,
        changed_by="controlgraph.operator/v1",
        request_id=f"request-revoke-{suffix}",
        evidence_id=f"evidence-revoke-{suffix}",
        changed_at="2026-08-19T12:05:00Z",
    )


def _release(
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
) -> tuple[ServiceClaimRecord, ServiceClaimRecord, EpochAuthorityRecord]:
    revoked = _revocation(authority, suffix="release")
    terminal = ServiceClaimTerminalRootProof(
        schema_version=SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
        target=claim.target,
        root_id=claim.root_id,
        root_sha256=claim.root_sha256,
        state=ServiceClaimTerminalRootState.RECOVERED,
        target_configuration_sha256=claim.stable_target_configuration_sha256,
        evidence_id="evidence-terminal-release",
        evidence_sha256=ZERO_DIGEST,
        confirmed_by="controlgraph.coordinator/v1",
        confirmed_at="2026-08-19T12:03:00Z",
    )
    classification = ServiceClaimTargetClassificationProof(
        schema_version=SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
        target=claim.target,
        root_id=claim.root_id,
        root_sha256=claim.root_sha256,
        classification=ServiceClaimTargetClassification.STABLE_RESTORED,
        fenced_epoch=revoked.current_epoch,
        fenced_authority_revision=revoked.revision,
        service_generation=14,
        provider_etag="etag-stable-14",
        target_configuration_sha256=claim.stable_target_configuration_sha256,
        evidence_id="evidence-target-release",
        evidence_sha256=ONE_DIGEST,
        classified_by=(
            f"controlgraph-verifier@{claim.target.project_id}.iam.gserviceaccount.com"
        ),
        classified_at="2026-08-19T12:06:00Z",
    )
    fenced = ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASING,
            "release_fence_epoch": revoked.current_epoch,
            "release_fence_authority_revision": revoked.revision,
            "release_fenced_by": revoked.changed_by,
            "release_fence_request_id": revoked.request_id,
            "release_fence_evidence_id": revoked.evidence_id,
            "release_fenced_at": revoked.changed_at,
            "terminal_root_proof": terminal,
        }
    )
    released = ServiceClaimRecord(
        **{
            **fenced.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASED,
            "released_by": "controlgraph.coordinator/v1",
            "release_request_id": "request-release",
            "release_evidence_id": "evidence-release",
            "released_at": "2026-08-19T12:07:00Z",
            "target_classification_proof": classification,
        }
    )
    return fenced, released, revoked


def _receipt(
    root: RolloutRoot,
    *,
    action: CapabilityAction,
    seed: str,
    idempotency_key: str | None = None,
    capability_sha256: str = ZERO_DIGEST,
) -> ExecutionReceipt:
    claim_key = idempotency_key or f"intent-{seed}"
    receipt_id = execution_receipt_logical_id(root.target, claim_key)
    initial = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=receipt_id,
        request_id=f"request-{seed}",
        idempotency_key=claim_key,
        capability_sha256=capability_sha256,
        mutation_sha256=ONE_DIGEST,
        plan_sha256=TWO_DIGEST,
        expected_poststate_sha256=THREE_DIGEST,
        target=root.target,
        root_id=root.root_id,
        root_sha256=canonical_sha256(root),
        epoch=1,
        action=action,
        provider_etag="etag-stable-12",
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=None,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:02:00Z",
        evidence_ids=(f"evidence-{seed}",),
    )
    return ExecutionReceipt(
        **{
            **initial.model_dump(mode="python"),
            "mutation_sha256": mutation_identity(_receipt_binding(initial)),
        }
    )


def _receipt_binding(receipt: ExecutionReceipt) -> MutationBinding:
    return MutationBinding(
        idempotency_key=receipt.idempotency_key,
        request_id=receipt.request_id,
        root_id=receipt.root_id,
        root_sha256=receipt.root_sha256,
        epoch=receipt.epoch,
        action=MutationAction(receipt.action.value),
        target=MutationTargetKey(
            project_id=receipt.target.project_id,
            region=receipt.target.region,
            environment=receipt.target.environment,
            service_name=receipt.target.service_name,
        ),
        provider_precondition=receipt.provider_etag,
        plan_sha256=receipt.plan_sha256,
        capability_sha256=receipt.capability_sha256,
        payload_sha256=FOUR_DIGEST,
        expected_poststate_sha256=receipt.expected_poststate_sha256,
    )


async def _claim_or_adopt(
    store: FirestoreAuthorityStore,
    receipt: ExecutionReceipt,
) -> ReceiptClaimCreated | ReceiptClaimAdopted | ReceiptClaimConflict:
    return await store.claim_or_adopt_receipt(receipt, _receipt_binding(receipt))


def _target() -> TargetBinding:
    suffix = uuid4().hex[:10]
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=f"controlgraph-canary-{suffix}",
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )


def _assert_one_conflict(results: Sequence[object]) -> object:
    winners = [result for result in results if not isinstance(result, BaseException)]
    conflicts = [result for result in results if isinstance(result, AuthorityStoreConflict)]
    assert len(winners) == 1
    assert len(conflicts) == 1
    return winners[0]


async def _create_rollout(
    authority_store: FirestoreAuthorityStore,
    root: RolloutRoot,
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
) -> CreatedRollout:
    return await authority_store.create_rollout(
        root,
        claim,
        authority,
        verified_candidate_revision_configuration_sha256=(
            claim.candidate_revision_configuration_sha256
        ),
    )


async def _create_rollout_after_release(
    authority_store: FirestoreAuthorityStore,
    expected_released_claim: StoredRecord[ServiceClaimRecord],
    root: RolloutRoot,
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
) -> CreatedRollout:
    return await authority_store.create_rollout_after_release(
        expected_released_claim,
        root,
        claim,
        authority,
        verified_candidate_revision_configuration_sha256=(
            claim.candidate_revision_configuration_sha256
        ),
    )


def test_emulator_root_creation_and_epoch_revocation_have_single_winners() -> None:
    async def scenario() -> None:
        target = _target()
        first = _initial_records(target=target, root_id=f"root-{uuid4().hex}")
        second = _initial_records(target=target, root_id=f"root-{uuid4().hex}")
        first_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        second_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )

        create_results = await asyncio.gather(
            _create_rollout(first_store, *first),
            _create_rollout(second_store, *second),
            return_exceptions=True,
        )
        created = _assert_one_conflict(create_results)
        claim = await first_store.read_service_claim()
        assert claim is not None
        assert claim.value.root_id in {first[0].root_id, second[0].root_id}

        winning_authority = await first_store.read_authority(claim.value.root_id)
        assert winning_authority is not None
        revoke_results = await asyncio.gather(
            first_store.advance_authority(
                winning_authority,
                _revocation(winning_authority.value, suffix="first"),
            ),
            second_store.advance_authority(
                winning_authority,
                _revocation(winning_authority.value, suffix="second"),
            ),
            return_exceptions=True,
        )
        revoked = _assert_one_conflict(revoke_results)
        assert isinstance(revoked, StoredRecord)
        assert revoked.revision == revoked.value.revision == 1
        assert revoked.value.current_epoch == 2
        assert created is not None

    asyncio.run(scenario())


def test_emulator_issuance_snapshot_is_coherent_across_claim_fence() -> None:
    async def scenario() -> None:
        target = _target()
        root, claim, authority = _initial_records(
            target=target,
            root_id=f"root-{uuid4().hex}",
        )
        first_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        second_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        created = await _create_rollout(first_store, root, claim, authority)
        fenced, _, revoked = _release(claim, authority)

        snapshot, fence_result = await asyncio.gather(
            first_store.read_issuance_state(root.root_id),
            second_store.fence_service_claim(
                created.service_claim,
                fenced,
                created.authority,
                revoked,
            ),
        )

        before = IssuanceStateSnapshot(
            root=created.root,
            service_claim=created.service_claim,
            authority=created.authority,
        )
        after = IssuanceStateSnapshot(
            root=created.root,
            service_claim=fence_result.service_claim,
            authority=fence_result.authority,
        )
        assert snapshot in (before, after)
        assert await first_store.read_issuance_state(root.root_id) == after
        assert after.service_claim.value.status is ServiceClaimStatus.RELEASING
        assert after.authority.value.current_epoch == 2

    asyncio.run(scenario())


def test_emulator_final_snapshot_is_coherent_across_claim_fence() -> None:
    async def scenario() -> None:
        target = _target()
        root, claim, authority = _initial_records(
            target=target,
            root_id=f"root-{uuid4().hex}",
        )
        first_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        second_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        created = await _create_rollout(first_store, root, claim, authority)
        fenced, _, revoked = _release(claim, authority)

        snapshot, fence_result = await asyncio.gather(
            first_store.read_final_authority_snapshot(root.root_id),
            second_store.fence_service_claim(
                created.service_claim,
                fenced,
                created.authority,
                revoked,
            ),
        )

        before = FinalAuthoritySnapshot(
            root=created.root,
            service_claim=created.service_claim,
            authority=created.authority,
        )
        after = FinalAuthoritySnapshot(
            root=created.root,
            service_claim=fence_result.service_claim,
            authority=fence_result.authority,
        )
        assert snapshot in (before, after)
        assert await first_store.read_final_authority_snapshot(root.root_id) == after

    asyncio.run(scenario())


def test_emulator_released_claim_takeover_has_one_transactional_winner() -> None:
    async def scenario() -> None:
        target = _target()
        root, claim, authority = _initial_records(
            target=target,
            root_id=f"root-{uuid4().hex}",
        )
        first_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        second_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        created = await _create_rollout(first_store, root, claim, authority)
        fenced, released, revoked = _release(claim, authority)
        fenced_state = await first_store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        released_state = await first_store.release_service_claim(
            fenced_state.service_claim,
            released,
            fenced_state.authority,
        )
        first = _initial_records(
            target=target,
            root_id=f"root-{uuid4().hex}",
            captured_at="2026-08-19T12:08:00Z",
            approved_at="2026-08-19T12:09:00Z",
            claimed_at="2026-08-19T12:09:01Z",
            service_generation=15,
        )
        second = _initial_records(
            target=target,
            root_id=f"root-{uuid4().hex}",
            captured_at="2026-08-19T12:08:00Z",
            approved_at="2026-08-19T12:09:00Z",
            claimed_at="2026-08-19T12:09:01Z",
            service_generation=15,
        )

        results = await asyncio.gather(
            _create_rollout_after_release(first_store,
                released_state.service_claim,
                *first,
            ),
            _create_rollout_after_release(second_store,
                released_state.service_claim,
                *second,
            ),
            return_exceptions=True,
        )

        winner = _assert_one_conflict(results)
        current = await first_store.read_service_claim()
        assert current is not None
        assert current.revision == 3
        assert current.value.status is ServiceClaimStatus.ACTIVE
        assert current.value.root_id in {first[0].root_id, second[0].root_id}
        assert winner is not None

    asyncio.run(scenario())


def test_emulator_release_race_never_ignores_a_newer_authority_epoch() -> None:
    async def scenario() -> None:
        target = _target()
        root, claim, authority = _initial_records(
            target=target,
            root_id=f"root-{uuid4().hex}",
        )
        first_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        second_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        created = await _create_rollout(first_store, root, claim, authority)
        fenced, released, revoked = _release(claim, authority)
        fenced_state = await first_store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        newer_authority = _revocation(
            fenced_state.authority.value,
            suffix="after-fence",
        ).model_copy(update={"changed_at": "2026-08-19T12:08:00Z"})

        release_result, advance_result = await asyncio.gather(
            first_store.release_service_claim(
                fenced_state.service_claim,
                released,
                fenced_state.authority,
            ),
            second_store.advance_authority(
                fenced_state.authority,
                newer_authority,
            ),
            return_exceptions=True,
        )

        assert not isinstance(advance_result, BaseException)
        current_authority = await first_store.read_authority(root.root_id)
        current_claim = await first_store.read_service_claim()
        assert current_authority == StoredRecord(newer_authority, 2)
        assert current_claim is not None
        if isinstance(release_result, AuthorityStoreConflict):
            assert current_claim == fenced_state.service_claim
        else:
            assert not isinstance(release_result, BaseException)
            assert current_claim == release_result.service_claim
            assert current_claim.value.status is ServiceClaimStatus.RELEASED

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "action",
    [CapabilityAction.APPLY_CANARY, CapabilityAction.RECOVER_STABLE],
)
def test_emulator_execute_and_recover_receipt_claims_have_single_winners(
    action: CapabilityAction,
) -> None:
    async def scenario() -> None:
        target = _target()
        root, _, _ = _initial_records(target=target, root_id=f"root-{uuid4().hex}")
        receipt = _receipt(root, action=action, seed=f"receipt-{uuid4().hex}")
        first_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        second_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )

        results = await asyncio.gather(
            _claim_or_adopt(first_store, receipt),
            _claim_or_adopt(second_store, receipt),
        )
        assert sum(type(result) is ReceiptClaimCreated for result in results) == 1
        assert sum(type(result) is ReceiptClaimAdopted for result in results) == 1
        created = next(result for result in results if type(result) is ReceiptClaimCreated)
        adopted = next(result for result in results if type(result) is ReceiptClaimAdopted)
        assert created.receipt == adopted.receipt == StoredRecord(receipt, 0)
        assert await first_store.read_receipt(receipt.idempotency_key) == created.receipt

    asyncio.run(scenario())


def test_emulator_same_receipt_key_with_changed_binding_has_one_winner() -> None:
    async def scenario() -> None:
        target = _target()
        root, _, _ = _initial_records(target=target, root_id=f"root-{uuid4().hex}")
        claim_key = f"intent-{uuid4().hex}"
        first = _receipt(
            root,
            action=CapabilityAction.APPLY_CANARY,
            seed="first",
            idempotency_key=claim_key,
        )
        second = _receipt(
            root,
            action=CapabilityAction.APPLY_CANARY,
            seed="second",
            idempotency_key=claim_key,
            capability_sha256=THREE_DIGEST,
        )
        assert first.receipt_id == second.receipt_id
        assert first != second

        first_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        second_store = FirestoreAuthorityStore.for_emulator(
            target=target,
            configured_project_id=target.project_id,
        )
        results = await asyncio.gather(
            _claim_or_adopt(first_store, first),
            _claim_or_adopt(second_store, second),
        )
        assert sum(type(result) is ReceiptClaimCreated for result in results) == 1
        assert sum(type(result) is ReceiptClaimConflict for result in results) == 1
        claimed = next(result for result in results if type(result) is ReceiptClaimCreated)
        stored = await first_store.read_receipt(claim_key)
        assert stored == claimed.receipt
        assert stored.value in (first, second)

        loser = second if stored.value == first else first
        assert type(await _claim_or_adopt(first_store, loser)) is ReceiptClaimConflict
        assert await second_store.read_receipt(claim_key) == stored

    asyncio.run(scenario())
