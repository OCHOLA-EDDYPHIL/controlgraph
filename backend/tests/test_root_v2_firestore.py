from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from root_v2_test_data import (
    RootV2Records,
    RootV3Records,
    make_root_v2_records,
    make_root_v3_records,
    root_v2_target,
)
from test_m2_firestore_authority_store import (
    _FakeClient,
    _FakeTransactionRunner,
    _StoredDocument,
)

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    RootCreationBundle,
    StoredRecord,
)
from controlgraph_canary.contracts.storage import (
    AuthorityStorageKind,
    capability_lineage_anchor_document_id,
    epoch_authority_document_id,
    rollout_root_v2_document_id,
    rollout_root_v3_document_id,
    root_creation_result_document_id,
    root_creation_result_v2_document_id,
    service_claim_document_id,
    signed_evidence_event_document_id,
)
from controlgraph_canary.integrations.google.firestore import (
    FirestoreAuthorityStore,
    _document_data,
    _prepared_document,
)


def _store() -> tuple[FirestoreAuthorityStore, _FakeClient, _FakeTransactionRunner]:
    client = _FakeClient()
    runner = _FakeTransactionRunner()
    target = root_v2_target()
    store = FirestoreAuthorityStore.for_test(
        target=target,
        configured_project_id=target.project_id,
        client_factory=lambda: client,
        transaction_runner=runner,
    )
    return store, client, runner


async def _create(
    store: FirestoreAuthorityStore,
    records: RootV3Records,
) -> object:
    return await store.create_or_adopt_root_creation_bundle(
        records.root,
        records.service_claim,
        records.authority,
        records.lineage_anchor,
        records.signed_evidence,
        records.creation_result,
    )


def _seed_historical_bundle(client: _FakeClient, records: RootV2Records) -> None:
    historical = records
    documents = (
        _prepared_document(
            kind=AuthorityStorageKind.ROLLOUT_ROOT_V2,
            logical_id=historical.root.root_id,
            document_id=rollout_root_v2_document_id(historical.root.root_id),
            revision=0,
            value=historical.root,
        ),
        _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=historical.creation_result.winner_service_claim_id,
            document_id=service_claim_document_id(historical.root.content.target),
            revision=0,
            value=historical.service_claim,
        ),
        _prepared_document(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=historical.root.root_id,
            document_id=epoch_authority_document_id(historical.root.root_id),
            revision=0,
            value=historical.authority,
        ),
        _prepared_document(
            kind=AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
            logical_id=historical.creation_result.winner_lineage_anchor_id,
            document_id=capability_lineage_anchor_document_id(
                historical.lineage_anchor
            ),
            revision=0,
            value=historical.lineage_anchor,
        ),
        _prepared_document(
            kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            logical_id=historical.signed_evidence.event.evidence_id,
            document_id=signed_evidence_event_document_id(
                historical.signed_evidence.event.evidence_id
            ),
            revision=0,
            value=historical.signed_evidence,
        ),
        _prepared_document(
            kind=AuthorityStorageKind.ROOT_CREATION_RESULT,
            logical_id=historical.root.root_id,
            document_id=root_creation_result_document_id(historical.root.root_id),
            revision=0,
            value=historical.creation_result,
        ),
    )
    update_time = datetime(2026, 8, 19, 12, 1, 1, tzinfo=UTC)
    for document in documents:
        path = f"{document.wrapper.record_kind.value}/{document.document_id}"
        client.documents[path] = _StoredDocument(
            data=_document_data(document.wrapper),
            update_time=update_time,
        )


def test_root_v3_bundle_is_one_six_record_commit_and_coherent_read() -> None:
    async def scenario() -> None:
        store, client, runner = _store()
        records = make_root_v3_records()

        created = await _create(store, records)
        read = await store.read_root_creation_bundle(records.root.root_id)
        signed = await store.read_signed_evidence_event(
            records.signed_evidence.event.evidence_id
        )

        assert created.result.outcome == "CREATED"
        assert signed == StoredRecord(records.signed_evidence, 0)
        assert read == created.bundle == RootCreationBundle(
            root=StoredRecord(records.root, 0),
            service_claim=StoredRecord(records.service_claim, 0),
            authority=StoredRecord(records.authority, 0),
            lineage_anchor=StoredRecord(records.lineage_anchor, 0),
            signed_evidence=StoredRecord(records.signed_evidence, 0),
            creation_result=StoredRecord(records.creation_result, 0),
        )
        assert runner.write_result_counts == [6, 0]
        assert len(client.documents) == 6
        target = records.root.content.target
        evidence_id = records.signed_evidence.event.evidence_id
        expected_paths = {
            f"{AuthorityStorageKind.ROLLOUT_ROOT_V3.value}/"
            f"{rollout_root_v3_document_id(records.root.root_id)}",
            f"{AuthorityStorageKind.SERVICE_CLAIM.value}/"
            f"{service_claim_document_id(target)}",
            f"{AuthorityStorageKind.EPOCH_AUTHORITY.value}/"
            f"{epoch_authority_document_id(records.root.root_id)}",
            f"{AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR.value}/"
            f"{capability_lineage_anchor_document_id(records.lineage_anchor)}",
            f"{AuthorityStorageKind.SIGNED_EVIDENCE_EVENT.value}/"
            f"{signed_evidence_event_document_id(evidence_id)}",
            f"{AuthorityStorageKind.ROOT_CREATION_RESULT_V2.value}/"
            f"{root_creation_result_v2_document_id(records.root.root_id)}",
        }
        assert set(client.documents) == expected_paths

        missing = await store.read_signed_evidence_event("cgev:missing-evidence")
        assert missing is None

    asyncio.run(scenario())


def test_exact_root_creation_replay_adopts_the_persisted_winner() -> None:
    async def scenario() -> None:
        store, client, runner = _store()
        records = make_root_v3_records()

        created = await _create(store, records)
        adopted = await _create(store, records)

        assert created.result.outcome == "CREATED"
        assert adopted.result.outcome == "ADOPTED"
        assert adopted.bundle == created.bundle
        assert adopted.bundle.creation_result.value.outcome == "CREATED"
        assert len(client.documents) == 6
        assert runner.write_result_counts == [6, 0]

    asyncio.run(scenario())


def test_competing_root_creation_has_one_claim_winner() -> None:
    async def scenario() -> None:
        store, client, _ = _store()
        first = make_root_v3_records(variant=1)
        second = make_root_v3_records(variant=2)

        outcomes = await asyncio.gather(
            _create(store, first),
            _create(store, second),
            return_exceptions=True,
        )

        assert sum(not isinstance(outcome, Exception) for outcome in outcomes) == 1
        assert sum(isinstance(outcome, AuthorityStoreConflict) for outcome in outcomes) == 1
        claim_paths = [
            path
            for path in client.documents
            if path.startswith(f"{AuthorityStorageKind.SERVICE_CLAIM.value}/")
        ]
        root_paths = [
            path
            for path in client.documents
            if path.startswith(f"{AuthorityStorageKind.ROLLOUT_ROOT_V3.value}/")
        ]
        assert len(claim_paths) == len(root_paths) == 1
        assert len(client.documents) == 6

    asyncio.run(scenario())


def test_ambiguous_complete_commit_adopts_but_partial_commit_fails_closed() -> None:
    async def scenario() -> None:
        store, client, runner = _store()
        records = make_root_v3_records()
        runner.mode = "commit-then-timeout"

        adopted = await _create(store, records)

        assert adopted.result.outcome == "ADOPTED"
        assert len(client.documents) == 6

        partial_store, partial_client, partial_runner = _store()
        partial_records = make_root_v3_records(variant=2)
        partial_runner.mode = "commit-first-only-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await _create(partial_store, partial_records)
        assert len(partial_client.documents) == 5
        with pytest.raises(AuthorityStoreCorruptRecord):
            await partial_store.read_root_creation_bundle(partial_records.root.root_id)

    asyncio.run(scenario())


def test_coherent_read_rejects_a_missing_or_recombined_bundle_record() -> None:
    async def scenario() -> None:
        store, client, _ = _store()
        records = make_root_v3_records()
        await _create(store, records)
        anchor_path = (
            f"{AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR.value}/"
            f"{capability_lineage_anchor_document_id(records.lineage_anchor)}"
        )
        del client.documents[anchor_path]

        with pytest.raises(AuthorityStoreCorruptRecord):
            await store.read_root_creation_bundle(records.root.root_id)

        absent = make_root_v3_records(variant=2)
        assert await store.read_root_creation_bundle(absent.root.root_id) is None

    asyncio.run(scenario())


def test_historical_v2_bundle_remains_readable_from_its_versioned_collections() -> None:
    async def scenario() -> None:
        store, client, _ = _store()
        records = make_root_v2_records()
        _seed_historical_bundle(client, records)

        assert await store.read_root_creation_bundle(records.root.root_id) == (
            RootCreationBundle(
                root=StoredRecord(records.root, 0),
                service_claim=StoredRecord(records.service_claim, 0),
                authority=StoredRecord(records.authority, 0),
                lineage_anchor=StoredRecord(records.lineage_anchor, 0),
                signed_evidence=StoredRecord(records.signed_evidence, 0),
                creation_result=StoredRecord(records.creation_result, 0),
            )
        )

    asyncio.run(scenario())


def test_cross_version_collection_alias_fails_closed() -> None:
    async def scenario() -> None:
        store, client, _ = _store()
        historical = make_root_v2_records()
        current = make_root_v3_records(variant=2)
        _seed_historical_bundle(client, historical)
        current_document = _prepared_document(
            kind=AuthorityStorageKind.ROLLOUT_ROOT_V3,
            logical_id=current.root.root_id,
            document_id=rollout_root_v3_document_id(current.root.root_id),
            revision=0,
            value=current.root,
        )
        aliased_path = (
            f"{AuthorityStorageKind.ROLLOUT_ROOT_V3.value}/"
            f"{rollout_root_v3_document_id(historical.root.root_id)}"
        )
        client.documents[aliased_path] = _StoredDocument(
            data=_document_data(current_document.wrapper),
            update_time=datetime(2026, 8, 19, 12, 1, 2, tzinfo=UTC),
        )

        with pytest.raises(AuthorityStoreCorruptRecord):
            await store.read_root_creation_bundle(historical.root.root_id)

    asyncio.run(scenario())
