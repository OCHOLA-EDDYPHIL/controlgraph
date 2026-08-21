from __future__ import annotations

import asyncio

import pytest
from health_execution_test_data import make_healthy_chain, make_signed_proof
from health_storage_test_data import make_twenty_proof_chain
from test_m2_firestore_authority_store import _FakeClient, _FakeTransactionRunner

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
)
from controlgraph_canary.application.health_store import (
    HealthChainReader,
    HealthChainStore,
    HealthChainWriteDisposition,
)
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.contracts.health_storage import (
    HealthChainManifestV1,
    HealthStorageKind,
)
from controlgraph_canary.contracts.promotion_execution import (
    PROMOTION_HEALTH_CHAIN_LOCATOR_V1,
    PromotionHealthChainLocatorV1,
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
        assert await issuer.read_health_chain_by_manifest(
            manifest.value.manifest_sha256
        ) == terminal.snapshot
        assert await issuer.read_promotion_health_chain(
            _locator(manifest.value)
        ) == chain

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
            current = (
                await store.append_signed_health_proof(current, signed_proof)
            ).snapshot

        manifest = current.manifest
        assert manifest is not None
        issuer = _reader(client, runner)
        reconstructed = await issuer.read_health_chain_by_manifest(
            manifest.value.manifest_sha256
        )

        assert reconstructed == current
        assert reconstructed.signed_chain == chain
        assert len(reconstructed.signed_proofs) == 20
        assert len(client.documents) == 42
        assert all(
            "controlgraph.signed-health-decision-chain/v1" not in stored.data["canonical_payload"]
            for stored in client.documents.values()
        )

    asyncio.run(scenario())
