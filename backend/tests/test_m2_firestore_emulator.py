"""Real Firestore-emulator races for the M2 authority-store boundary."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence
from uuid import uuid4

import pytest

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    FinalAuthoritySnapshot,
    IssuanceStateSnapshot,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    StoredRecord,
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
    ServiceClaimRecord,
    ServiceClaimStatus,
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
) -> tuple[RolloutRoot, ServiceClaimRecord, EpochAuthorityRecord]:
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=target,
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
    root = RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id=root_id,
        target=target,
        stable_snapshot=snapshot,
        candidate_revision="reference-candidate",
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=ONE_DIGEST,
        maximum_recovery_attempts=1,
        initial_epoch=1,
        plan_sha256=TWO_DIGEST,
        approved_by="controlgraph.operator/v1",
        approved_at="2026-08-19T12:01:00Z",
    )
    root_sha256 = canonical_sha256(root)
    claim = ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v1",
        target=target,
        root_id=root.root_id,
        root_sha256=root_sha256,
        status=ServiceClaimStatus.ACTIVE,
        claimed_by="controlgraph.api/v1",
        claim_request_id=f"request-{root_id}",
        claim_evidence_id=f"evidence-{root_id}",
        claimed_at="2026-08-19T12:01:01Z",
        released_by=None,
        release_request_id=None,
        release_evidence_id=None,
        released_at=None,
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
        changed_by="controlgraph.api/v1",
        request_id=claim.claim_request_id,
        evidence_id=claim.claim_evidence_id,
        changed_at="2026-08-19T12:01:01Z",
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
        changed_at="2026-08-19T12:02:00Z",
    )


def _release(
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
) -> tuple[ServiceClaimRecord, EpochAuthorityRecord]:
    revoked = _revocation(authority, suffix="release")
    released = ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASED,
            "released_by": revoked.changed_by,
            "release_request_id": revoked.request_id,
            "release_evidence_id": revoked.evidence_id,
            "released_at": revoked.changed_at,
        }
    )
    return released, revoked


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
    suffix = uuid4().hex[:12]
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id="controlgraph-canary-emulator",
        region="us-central1",
        environment="emulator",
        service_name=f"reference-{suffix}",
    )


def _assert_one_conflict(results: Sequence[object]) -> object:
    winners = [result for result in results if not isinstance(result, BaseException)]
    conflicts = [result for result in results if isinstance(result, AuthorityStoreConflict)]
    assert len(winners) == 1
    assert len(conflicts) == 1
    return winners[0]


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
            first_store.create_rollout(*first),
            second_store.create_rollout(*second),
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


def test_emulator_issuance_snapshot_is_coherent_across_claim_release() -> None:
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
        created = await first_store.create_rollout(root, claim, authority)
        released, revoked = _release(claim, authority)

        snapshot, release_result = await asyncio.gather(
            first_store.read_issuance_state(root.root_id),
            second_store.release_service_claim(
                created.service_claim,
                released,
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
            service_claim=release_result.service_claim,
            authority=release_result.authority,
        )
        assert snapshot in (before, after)
        assert await first_store.read_issuance_state(root.root_id) == after
        assert after.service_claim.value.status is ServiceClaimStatus.RELEASED
        assert after.authority.value.current_epoch == 2

    asyncio.run(scenario())


def test_emulator_final_snapshot_is_coherent_across_claim_release() -> None:
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
        created = await first_store.create_rollout(root, claim, authority)
        released, revoked = _release(claim, authority)

        snapshot, release_result = await asyncio.gather(
            first_store.read_final_authority_snapshot(root.root_id),
            second_store.release_service_claim(
                created.service_claim,
                released,
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
            service_claim=release_result.service_claim,
            authority=release_result.authority,
        )
        assert snapshot in (before, after)
        assert await first_store.read_final_authority_snapshot(root.root_id) == after

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
