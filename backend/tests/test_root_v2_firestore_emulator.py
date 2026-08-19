from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import pytest
from root_v2_test_data import RootV2Records, make_root_v2_records

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    RootCreationWriteResult,
)
from controlgraph_canary.integrations.google.firestore import FirestoreAuthorityStore

pytestmark = pytest.mark.skipif(
    not os.environ.get("FIRESTORE_EMULATOR_HOST"),
    reason="requires a running Firestore emulator",
)


async def _create(
    store: FirestoreAuthorityStore,
    records: RootV2Records,
) -> RootCreationWriteResult:
    return await store.create_or_adopt_root_creation_bundle(
        records.root,
        records.service_claim,
        records.authority,
        records.lineage_anchor,
        records.signed_evidence,
        records.creation_result,
    )


def test_emulator_root_v2_bundle_has_one_claim_winner_and_exact_replay() -> None:
    async def scenario() -> None:
        project_id = f"controlgraph-canary-{uuid4().hex[:10]}"
        first = make_root_v2_records(project_id=project_id, variant=1)
        second = make_root_v2_records(project_id=project_id, variant=2)
        first_store = FirestoreAuthorityStore.for_emulator(
            target=first.root.content.target,
            configured_project_id=project_id,
        )
        second_store = FirestoreAuthorityStore.for_emulator(
            target=first.root.content.target,
            configured_project_id=project_id,
        )

        outcomes = await asyncio.gather(
            _create(first_store, first),
            _create(second_store, second),
            return_exceptions=True,
        )

        winners = [outcome for outcome in outcomes if isinstance(outcome, RootCreationWriteResult)]
        conflicts = [outcome for outcome in outcomes if isinstance(outcome, AuthorityStoreConflict)]
        assert len(winners) == len(conflicts) == 1
        winner = winners[0]
        winning_records = first if winner.bundle.root.value == first.root else second
        winning_store = first_store if winning_records is first else second_store
        assert winner.result.outcome == "CREATED"
        assert await winning_store.read_root_creation_bundle(
            winning_records.root.root_id
        ) == winner.bundle

        replay = await _create(winning_store, winning_records)
        assert replay.result.outcome == "ADOPTED"
        assert replay.bundle == winner.bundle

        losing_records = second if winning_records is first else first
        assert await winning_store.read_root_creation_bundle(losing_records.root.root_id) is None

    asyncio.run(scenario())
