from __future__ import annotations

import asyncio

import pytest
from health_execution_test_data import make_healthy_chain, make_signed_proof
from health_storage_test_data import make_twenty_proof_chain
from recovery_v2_test_data import (
    RecoveryV2Bundle,
    make_revoked_v2_recovery_bundle,
    make_unhealthy_recovery_chain,
)
from test_m2_firestore_authority_store import _FakeClient, _FakeTransactionRunner

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    StoredRecord,
)
from controlgraph_canary.application.health_store import (
    HealthChainReader,
    HealthChainStore,
    HealthChainWriteDisposition,
)
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.health_storage import (
    HealthChainManifestV1,
    HealthStorageKind,
)
from controlgraph_canary.contracts.promotion_execution import (
    PROMOTION_HEALTH_CHAIN_LOCATOR_V1,
    PromotionHealthChainLocatorV1,
)
from controlgraph_canary.contracts.recovery_execution import (
    RECOVERY_DISPATCH_RECORD_V2,
    RecoveryCommandV2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchState,
    RecoveryIntentV1,
    create_recovery_apply_receipt_locator,
    create_recovery_intent,
    create_unhealthy_recovery_command,
    recovery_command_sha256,
    recovery_dispatch_id,
)
from controlgraph_canary.integrations.google.firestore_health import (
    FirestoreHealthChainReader,
    FirestoreHealthChainStore,
)


def _store() -> tuple[
    FirestoreHealthChainStore,
    _FakeClient,
    _FakeTransactionRunner,
]:
    target = make_healthy_chain().anchor.target
    client = _FakeClient(project_id=target.project_id)
    runner = _FakeTransactionRunner()
    store = FirestoreHealthChainStore.for_test(
        target=target,
        configured_project_id=target.project_id,
        service_role=ServiceRole.COORDINATOR,
        client_factory=lambda: client,
        transaction_runner=runner,
    )
    return store, client, runner


def _reader(
    client: _FakeClient,
    runner: _FakeTransactionRunner,
) -> FirestoreHealthChainReader:
    target = make_healthy_chain().anchor.target
    return FirestoreHealthChainReader.for_test(
        target=target,
        configured_project_id=target.project_id,
        service_role=ServiceRole.ISSUER,
        client_factory=lambda: client,
        transaction_runner=runner,
    )


def _locator(manifest: HealthChainManifestV1) -> PromotionHealthChainLocatorV1:
    return PromotionHealthChainLocatorV1(
        schema_version=PROMOTION_HEALTH_CHAIN_LOCATOR_V1,
        anchor_id=manifest.anchor_id,
        anchor_sha256=manifest.anchor_sha256,
        chain_id=manifest.chain_id,
        health_chain_sha256=manifest.manifest_sha256,
        chain_head_sha256=manifest.chain_head_sha256,
        ordered_proof_chain_sha256=manifest.ordered_proof_chain_sha256,
        terminal_sequence=manifest.terminal_sequence,
    )


def test_writer_and_reader_are_role_sealed_away_from_the_verifier() -> None:
    chain = make_healthy_chain()
    target = chain.anchor.target
    client = _FakeClient(project_id=target.project_id)

    coordinator = FirestoreHealthChainStore.for_test(
        target=target,
        configured_project_id=target.project_id,
        service_role=ServiceRole.COORDINATOR,
        client_factory=lambda: client,
    )
    issuer = FirestoreHealthChainReader.for_test(
        target=target,
        configured_project_id=target.project_id,
        service_role=ServiceRole.ISSUER,
        client_factory=lambda: client,
    )

    assert isinstance(coordinator, HealthChainStore)
    assert isinstance(issuer, HealthChainReader)
    assert not hasattr(issuer, "append_signed_health_proof")
    with pytest.raises(ValueError, match="role is not admitted"):
        FirestoreHealthChainStore.for_test(
            target=target,
            configured_project_id=target.project_id,
            service_role=ServiceRole.VERIFIER,
            client_factory=lambda: client,
        )
    with pytest.raises(ValueError, match="role is not admitted"):
        FirestoreHealthChainStore.for_test(
            target=target,
            configured_project_id=target.project_id,
            service_role=ServiceRole.ISSUER,
            client_factory=lambda: client,
        )
    with pytest.raises(ValueError, match="role is not admitted"):
        FirestoreHealthChainReader.for_test(
            target=target,
            configured_project_id=target.project_id,
            service_role=ServiceRole.VERIFIER,
            client_factory=lambda: client,
        )


def test_anchor_and_proofs_are_normalized_and_exact_replays_are_adopted() -> None:
    async def scenario() -> None:
        chain = make_healthy_chain()
        store, client, runner = _store()
        anchor_result = await store.create_or_adopt_health_anchor(chain.anchor)

        first = await store.append_signed_health_proof(
            anchor_result.snapshot,
            chain.signed_proofs[0],
        )
        replay = await store.append_signed_health_proof(
            anchor_result.snapshot,
            chain.signed_proofs[0],
        )
        terminal = await store.append_signed_health_proof(
            first.snapshot,
            chain.signed_proofs[1],
        )
        adopted_anchor = await store.create_or_adopt_health_anchor(chain.anchor)

        assert anchor_result.disposition is HealthChainWriteDisposition.CREATED
        assert first.disposition is HealthChainWriteDisposition.CREATED
        assert replay.disposition is HealthChainWriteDisposition.ADOPTED
        assert replay.snapshot == first.snapshot
        assert terminal.snapshot.signed_chain == chain
        assert adopted_anchor.disposition is HealthChainWriteDisposition.ADOPTED
        assert adopted_anchor.snapshot == terminal.snapshot
        assert len(client.documents) == 6
        assert [count for count in runner.write_result_counts if count] == [1, 3, 3]

        issuer = _reader(client, runner)
        manifest = terminal.snapshot.manifest
        assert manifest is not None
        assert await issuer.read_health_chain(chain.anchor.anchor_id) == terminal.snapshot
        assert (
            await issuer.read_health_chain_by_manifest(manifest.value.manifest_sha256)
            == terminal.snapshot
        )
        assert await issuer.read_promotion_health_chain(_locator(manifest.value)) == chain

    asyncio.run(scenario())


def test_concurrent_forks_have_one_winner_and_one_conflict() -> None:
    async def scenario() -> None:
        chain = make_healthy_chain()
        store, _, _ = _store()
        anchor = await store.create_or_adopt_health_anchor(chain.anchor)
        first = await store.append_signed_health_proof(
            anchor.snapshot,
            chain.signed_proofs[0],
        )
        alternate = make_signed_proof(
            chain.signed_proofs[1].proof,
            chain.anchor,
            marker=b"forked-terminal-proof",
        )

        outcomes = await asyncio.gather(
            store.append_signed_health_proof(first.snapshot, chain.signed_proofs[1]),
            store.append_signed_health_proof(first.snapshot, alternate),
            return_exceptions=True,
        )

        winners = [value for value in outcomes if not isinstance(value, Exception)]
        conflicts = [value for value in outcomes if isinstance(value, AuthorityStoreConflict)]
        assert len(winners) == len(conflicts) == 1
        current = await store.read_health_chain(chain.anchor.anchor_id)
        assert current == winners[0].snapshot

    asyncio.run(scenario())


def test_gap_and_replay_are_denied_before_any_firestore_write() -> None:
    async def scenario() -> None:
        chain = make_healthy_chain()
        store, _, runner = _store()
        anchor = await store.create_or_adopt_health_anchor(chain.anchor)

        with pytest.raises(ValueError, match="exact next chain element"):
            await store.append_signed_health_proof(
                anchor.snapshot,
                chain.signed_proofs[1],
            )
        first = await store.append_signed_health_proof(
            anchor.snapshot,
            chain.signed_proofs[0],
        )
        with pytest.raises(ValueError, match="exact next chain element"):
            await store.append_signed_health_proof(
                first.snapshot,
                chain.signed_proofs[0],
            )

        assert [count for count in runner.write_result_counts if count] == [1, 3]

    asyncio.run(scenario())


@pytest.mark.parametrize("damage", ("missing-proof", "corrupt-proof", "missing-manifest"))
def test_missing_or_corrupt_normalized_documents_fail_closed(damage: str) -> None:
    async def scenario() -> None:
        chain = make_healthy_chain()
        store, client, _ = _store()
        anchor = await store.create_or_adopt_health_anchor(chain.anchor)
        first = await store.append_signed_health_proof(
            anchor.snapshot,
            chain.signed_proofs[0],
        )
        manifest = first.snapshot.manifest
        assert manifest is not None
        proof_path = (
            f"{HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF.value}/"
            f"{manifest.value.proof_documents[0].document_id}"
        )
        immutable_paths = [
            path
            for path in client.documents
            if path.startswith(f"{HealthStorageKind.HEALTH_CHAIN_MANIFEST.value}/")
        ]
        assert len(immutable_paths) == 1
        if damage == "missing-proof":
            del client.documents[proof_path]
        elif damage == "corrupt-proof":
            client.documents[proof_path].data["payload_sha256"] = "0" * 64
        else:
            del client.documents[immutable_paths[0]]

        with pytest.raises(AuthorityStoreCorruptRecord):
            await store.read_health_chain(chain.anchor.anchor_id)

    asyncio.run(scenario())


def test_ambiguous_complete_append_is_adopted_and_partial_commit_is_not_retried() -> None:
    async def scenario() -> None:
        chain = make_healthy_chain()
        store, _, runner = _store()
        runner.mode = "commit-then-timeout"
        anchor = await store.create_or_adopt_health_anchor(chain.anchor)
        assert anchor.disposition is HealthChainWriteDisposition.ADOPTED

        runner.mode = "commit-then-timeout"
        appended = await store.append_signed_health_proof(
            anchor.snapshot,
            chain.signed_proofs[0],
        )
        assert appended.disposition is HealthChainWriteDisposition.ADOPTED

        partial_store, _, partial_runner = _store()
        partial_anchor = await partial_store.create_or_adopt_health_anchor(chain.anchor)
        partial_runner.mode = "commit-first-only-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await partial_store.append_signed_health_proof(
                partial_anchor.snapshot,
                chain.signed_proofs[0],
            )
        assert partial_runner.expected_writes.count(3) == 1

    asyncio.run(scenario())


def test_twenty_proofs_reconstruct_from_individual_bounded_documents() -> None:
    async def scenario() -> None:
        chain = make_twenty_proof_chain()
        store, client, runner = _store()
        current = (await store.create_or_adopt_health_anchor(chain.anchor)).snapshot
        for signed_proof in chain.signed_proofs:
            current = (await store.append_signed_health_proof(current, signed_proof)).snapshot

        manifest = current.manifest
        assert manifest is not None
        issuer = _reader(client, runner)
        reconstructed = await issuer.read_health_chain_by_manifest(manifest.value.manifest_sha256)

        assert reconstructed == current
        assert reconstructed.signed_chain == chain
        assert len(reconstructed.signed_proofs) == 20
        assert len(client.documents) == 42
        assert all(
            "controlgraph.signed-health-decision-chain/v1" not in stored.data["canonical_payload"]
            for stored in client.documents.values()
        )

    asyncio.run(scenario())


def _prepared_recovery_record() -> tuple[
    RecoveryV2Bundle,
    RecoveryDispatchRecordV2,
    StoredRecord[RecoveryIntentV1],
]:
    bundle = make_revoked_v2_recovery_bundle()
    intent = create_recovery_intent(
        bundle.command,
        created_at=bundle.command.source.triggered_at,
    )
    task_sha256 = canonical_sha256(bundle.task)
    task_name = (
        f"projects/{bundle.root.content.target.project_id}/locations/us-central1/"
        f"queues/controlgraph-recovery/tasks/cg-{task_sha256}"
    )
    prepared = RecoveryDispatchRecordV2(
        schema_version=RECOVERY_DISPATCH_RECORD_V2,
        dispatch_id=recovery_dispatch_id(recovery_command_sha256(bundle.command)),
        command_sha256=recovery_command_sha256(bundle.command),
        recovery_authorization_sha256=canonical_sha256(bundle.authorization),
        capability_id=bundle.authorization.capability_id,
        request_id=bundle.command.request_id,
        idempotency_key=bundle.command.idempotency_key,
        target=bundle.root.content.target,
        root_id=bundle.root.root_id,
        root_sha256=bundle.root.root_sha256,
        epoch=bundle.command.expected_epoch,
        scheduled_at=bundle.command.scheduled_at,
        source_receipt_sha256=(bundle.command.verified_apply_receipt.receipt_sha256),
        trigger_proof_sha256=bundle.authorization.trigger_proof_sha256,
        prestate_attestation_sha256=(bundle.authorization.prestate_attestation_sha256),
        task_sha256=task_sha256,
        task_name=task_name,
        task=bundle.task,
        state=RecoveryDispatchState.PREPARED,
        prepared_at=bundle.authorization.issued_at,
        enqueue_started_at=None,
        terminal_at=None,
        result=None,
    )
    return bundle, prepared, StoredRecord(intent, 0)


def test_terminal_unhealthy_append_atomically_owns_root_recovery() -> None:
    async def scenario() -> None:
        chain = make_unhealthy_recovery_chain()
        command = create_unhealthy_recovery_command(
            signed_health_chain=chain,
            verified_apply_receipt=create_recovery_apply_receipt_locator(
                chain.anchor.apply_receipt,
                storage_revision=2,
            ),
            request_id="request-unhealthy-recovery-001",
            idempotency_key="unhealthy-recovery-001",
            scheduled_at="2026-08-21T12:09:30Z",
        )
        intent = create_recovery_intent(
            command,
            created_at=command.source.triggered_at,
        )
        store, client, runner = _store()
        current = (await store.create_or_adopt_health_anchor(chain.anchor)).snapshot
        current = (
            await store.append_signed_health_proof(
                current,
                chain.signed_proofs[0],
            )
        ).snapshot
        terminal = await store.append_signed_health_proof(
            current,
            chain.signed_proofs[1],
            intent,
        )
        replay = await store.append_signed_health_proof(
            current,
            chain.signed_proofs[1],
            intent,
        )

        assert terminal.snapshot.recovery_intent == StoredRecord(intent, 0)
        assert replay.disposition is HealthChainWriteDisposition.ADOPTED
        assert await store.read_recovery_intent(command.expected_root_sha256) == (
            StoredRecord(intent, 0)
        )
        assert (
            await store.read_recovery_health_chain(
                command.source.health_chain_locator  # type: ignore[union-attr]
            )
            == chain
        )
        assert [count for count in runner.write_result_counts if count] == [1, 3, 4]
        assert len(client.documents) == 7

    asyncio.run(scenario())


def test_concurrent_terminal_unhealthy_appends_converge_on_one_recovery_intent() -> None:
    async def scenario() -> None:
        chain = make_unhealthy_recovery_chain()
        command = create_unhealthy_recovery_command(
            signed_health_chain=chain,
            verified_apply_receipt=create_recovery_apply_receipt_locator(
                chain.anchor.apply_receipt,
                storage_revision=2,
            ),
            request_id="request-concurrent-unhealthy-recovery-001",
            idempotency_key="concurrent-unhealthy-recovery-001",
            scheduled_at="2026-08-21T12:09:30Z",
        )
        intent = create_recovery_intent(
            command,
            created_at=command.source.triggered_at,
        )
        store, client, _ = _store()
        current = (await store.create_or_adopt_health_anchor(chain.anchor)).snapshot
        current = (
            await store.append_signed_health_proof(
                current,
                chain.signed_proofs[0],
            )
        ).snapshot

        outcomes = await asyncio.gather(
            store.append_signed_health_proof(
                current,
                chain.signed_proofs[1],
                intent,
            ),
            store.append_signed_health_proof(
                current,
                chain.signed_proofs[1],
                intent,
            ),
        )

        assert {outcome.disposition for outcome in outcomes} == {
            HealthChainWriteDisposition.CREATED,
            HealthChainWriteDisposition.ADOPTED,
        }
        assert outcomes[0].snapshot == outcomes[1].snapshot
        assert outcomes[0].snapshot.recovery_intent == StoredRecord(intent, 0)
        assert await store.read_recovery_intent(command.expected_root_sha256) == (
            StoredRecord(intent, 0)
        )
        intent_prefix = f"{HealthStorageKind.RECOVERY_INTENT.value}/"
        assert sum(path.startswith(intent_prefix) for path in client.documents) == 1

    asyncio.run(scenario())


def test_recovery_enqueue_start_never_reconstructs_a_permit() -> None:
    async def scenario() -> None:
        bundle, prepared, intent = _prepared_recovery_record()
        store, _, runner = _store()
        owned = await store.create_or_adopt_recovery_intent(intent.value)
        stored = await store.prepare_or_adopt_recovery_dispatch(owned, prepared)
        started_value = RecoveryDispatchRecordV2.model_validate(
            {
                **prepared.model_dump(mode="python"),
                "state": RecoveryDispatchState.ENQUEUE_STARTED,
                "enqueue_started_at": bundle.authorization.issued_at,
            }
        )

        runner.mode = "commit-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await store.begin_recovery_enqueue(stored, started_value)
        current = await store.read_recovery_dispatch(bundle.command)
        assert current == StoredRecord(started_value, 1)
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await store.begin_recovery_enqueue(stored, started_value)

    asyncio.run(scenario())


def test_recovery_enqueue_permit_is_one_use_and_root_intent_conflicts() -> None:
    async def scenario() -> None:
        bundle, prepared, intent = _prepared_recovery_record()
        store, _, _ = _store()
        owned = await store.create_or_adopt_recovery_intent(intent.value)
        assert await store.create_or_adopt_recovery_intent(intent.value) == owned
        conflicting_command = RecoveryCommandV2.model_validate(
            {
                **bundle.command.model_dump(mode="python"),
                "request_id": "different-root-owner-request",
                "idempotency_key": "different-root-owner-key",
            }
        )
        conflicting_intent = create_recovery_intent(
            conflicting_command,
            created_at=conflicting_command.source.triggered_at,
        )
        with pytest.raises(AuthorityStoreConflict):
            await store.create_or_adopt_recovery_intent(conflicting_intent)

        stored = await store.prepare_or_adopt_recovery_dispatch(owned, prepared)
        started_value = RecoveryDispatchRecordV2.model_validate(
            {
                **prepared.model_dump(mode="python"),
                "state": RecoveryDispatchState.ENQUEUE_STARTED,
                "enqueue_started_at": bundle.authorization.issued_at,
            }
        )
        direct = await store.begin_recovery_enqueue(stored, started_value)
        direct.permit._take(
            task_name=prepared.task_name,
            task_sha256=prepared.task_sha256,
        )
        with pytest.raises(ValueError, match="already consumed"):
            direct.permit._take(
                task_name=prepared.task_name,
                task_sha256=prepared.task_sha256,
            )

    asyncio.run(scenario())
