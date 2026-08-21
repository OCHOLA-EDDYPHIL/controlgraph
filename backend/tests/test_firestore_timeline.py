from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Coroutine, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from typing import Any

import pytest
from timeline_test_data import OTHER_TARGET, TARGET, timeline_event

from controlgraph_canary.application.timeline import (
    TimelineAppendAdopted,
    TimelineAppendCreated,
    TimelineCursorInvalid,
    TimelineStoreConflict,
    TimelineStoreCorruptRecord,
)
from controlgraph_canary.contracts.timeline import (
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_ENTRY_COLLECTION,
    TIMELINE_PAGE_COMMAND_V1,
    TimelineAudience,
    TimelineDisplayFieldName,
    TimelineDisplayFieldV1,
    TimelinePageCommandV1,
    standard_timeline_evidence_policy_set,
    timeline_entry_document_id,
)
from controlgraph_canary.integrations.google.firestore_timeline import (
    FIRESTORE_TIMELINE_DATABASE,
    AsyncFirestoreTimelineClientPort,
    FirestoreTimelineStore,
    TimelineDocumentReferencePort,
    TimelineTransactionBody,
)

NOW = datetime(2026, 8, 21, 0, 10, tzinfo=UTC)


def _async_test[**P](
    function: Callable[P, Coroutine[Any, Any, None]],
) -> Callable[P, None]:
    @wraps(function)
    def run(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(function(*args, **kwargs))

    return run


@dataclass(frozen=True)
class _WriteResult:
    update_time: datetime = NOW


class _Snapshot:
    def __init__(self, reference: _Reference, data: dict[str, Any] | None) -> None:
        self.reference = reference
        self._data = deepcopy(data)
        self.exists = data is not None
        self.read_time = NOW
        self.update_time = NOW if self.exists else None

    def to_dict(self) -> dict[str, Any] | None:
        return deepcopy(self._data)


class _Reference:
    def __init__(self, client: _Client, path: str) -> None:
        self.client = client
        self.path = path

    async def get(
        self,
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> object:
        del field_paths, retry, timeout, read_time
        self.client.get_calls.append(self.path)
        if isinstance(transaction, _Transaction):
            data = transaction.read(self.path)
        else:
            data = self.client.documents.get(self.path)
        return _Snapshot(self, data)


class _Transaction:
    def __init__(self, client: _Client) -> None:
        self.client = client
        self.write_results: list[object] = []
        self.writes: list[tuple[str, str, dict[str, Any]]] = []

    def read(self, path: str) -> dict[str, Any] | None:
        return self.client.documents.get(path)

    def create(
        self,
        reference: TimelineDocumentReferencePort,
        document_data: dict[str, Any],
    ) -> None:
        self.writes.append(("create", reference.path, deepcopy(document_data)))

    def update(
        self,
        reference: TimelineDocumentReferencePort,
        field_updates: dict[str, Any],
        option: object | None = None,
    ) -> None:
        del option
        self.writes.append(("update", reference.path, deepcopy(field_updates)))


class _Client:
    project = TARGET.project_id
    _database = FIRESTORE_TIMELINE_DATABASE

    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}
        self.get_calls: list[str] = []
        self.batch_calls: list[tuple[str, ...]] = []
        self.write_count = 0
        self.transaction_count = 0
        self.reverse_batch = True
        self.duplicate_batch = False
        self.lose_next_commit = False
        self.lock = asyncio.Lock()

    @property
    def _database_string(self) -> str:
        return f"projects/{self.project}/databases/{self._database}"

    def document(self, *document_path: str) -> _Reference:
        return _Reference(self, "/".join(document_path))

    def get_all(
        self,
        references: Sequence[TimelineDocumentReferencePort],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> AsyncIterator[object]:
        del field_paths, transaction, retry, timeout, read_time
        paths = tuple(reference.path for reference in references)
        self.batch_calls.append(paths)

        async def snapshots() -> AsyncIterator[object]:
            ordered = tuple(reversed(references)) if self.reverse_batch else tuple(references)
            for reference in ordered:
                yield _Snapshot(
                    self.document(*reference.path.split("/")),
                    self.documents.get(reference.path),
                )
            if self.duplicate_batch and ordered:
                reference = ordered[0]
                yield _Snapshot(
                    self.document(*reference.path.split("/")),
                    self.documents.get(reference.path),
                )

        return snapshots()

    def transaction(self, max_attempts: int = 3, read_only: bool = False) -> _Transaction:
        del max_attempts, read_only
        return _Transaction(self)


async def _run_transaction(
    client_port: AsyncFirestoreTimelineClientPort,
    maximum_attempts: int,
    expected_writes: int,
    body: TimelineTransactionBody,
) -> None:
    del maximum_attempts
    client = client_port
    assert isinstance(client, _Client)
    async with client.lock:
        client.transaction_count += 1
        transaction = _Transaction(client)
        await body(transaction)
        assert len(transaction.writes) == expected_writes
        for operation, path, data in transaction.writes:
            if operation == "create":
                if path in client.documents:
                    raise RuntimeError("synthetic create contention")
            elif path not in client.documents:
                raise RuntimeError("synthetic update contention")
            client.documents[path] = deepcopy(data)
        client.write_count += len(transaction.writes)
        transaction.write_results = [_WriteResult() for _ in transaction.writes]
        if client.lose_next_commit:
            client.lose_next_commit = False
            raise TimeoutError("synthetic lost commit response")


def _store(client: _Client) -> FirestoreTimelineStore:
    return FirestoreTimelineStore(
        target=TARGET,
        configured_project_id=TARGET.project_id,
        policy_set=standard_timeline_evidence_policy_set(TARGET),
        client_factory=lambda: client,
        transaction_runner=_run_transaction,
        clock=lambda: NOW,
    )


def _command(
    *,
    after_sequence: int = 0,
    after_entry_sha256: str | None = None,
    limit: int = 100,
) -> TimelinePageCommandV1:
    return TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=TARGET,
        after_sequence=after_sequence,
        after_entry_sha256=after_entry_sha256,
        limit=limit,
        audience=TimelineAudience.OPERATOR,
    )


@_async_test
async def test_empty_timeline_uses_only_the_exact_head_read() -> None:
    client = _Client()
    store = _store(client)

    page = await store.read_page(_command(limit=10))

    assert page.head is None
    assert page.entries == ()
    assert client.batch_calls == []
    assert client.write_count == 0


@_async_test
async def test_append_is_monotonic_replay_safe_and_source_conflict_safe() -> None:
    client = _Client()
    store = _store(client)
    event = timeline_event(20)

    first = await store.append(event)
    replay = await store.append(event)

    assert isinstance(first, TimelineAppendCreated)
    assert first.entry.content.sequence == 1
    assert isinstance(replay, TimelineAppendAdopted)
    assert replay.entry == first.entry
    assert client.write_count == 3
    assert client.transaction_count == 1

    fields = list(event.display_fields)
    fields[-1] = TimelineDisplayFieldV1(
        schema_version=TIMELINE_DISPLAY_FIELD_V1,
        name=TimelineDisplayFieldName.SUMMARY,
        value="Changed semantic event",
        data_class=TimelineAudience.PUBLIC_DEMO,
    )
    conflict = type(event).model_validate(
        {**event.model_dump(mode="python"), "display_fields": tuple(fields)}
    )
    with pytest.raises(TimelineStoreConflict):
        await store.append(conflict)
    wrong_retention = type(event).model_validate(
        {**event.model_dump(mode="python"), "raw_retention_days": 31}
    )
    with pytest.raises(ValueError):
        await store.append(wrong_retention)
    assert client.write_count == 3


@_async_test
async def test_concurrent_appends_allocate_one_contiguous_target_sequence() -> None:
    client = _Client()
    store = _store(client)

    results = await asyncio.gather(
        store.append(timeline_event(21)),
        store.append(timeline_event(22)),
        store.append(timeline_event(23)),
    )

    assert sorted(result.entry.content.sequence for result in results) == [1, 2, 3]
    assert all(isinstance(result, TimelineAppendCreated) for result in results)
    page = await store.read_page(_command())
    assert [entry.content.sequence for entry in page.entries] == [1, 2, 3]
    assert page.entries[1].content.previous_entry_sha256 == page.entries[0].entry_sha256
    assert page.entries[2].content.previous_entry_sha256 == page.entries[1].entry_sha256


@_async_test
async def test_concurrent_exact_replays_create_one_entry() -> None:
    client = _Client()
    store = _store(client)
    event = timeline_event(31)

    results = await asyncio.gather(store.append(event), store.append(event))

    assert sum(isinstance(result, TimelineAppendCreated) for result in results) == 1
    assert sum(isinstance(result, TimelineAppendAdopted) for result in results) == 1
    assert results[0].entry == results[1].entry
    assert client.write_count == 3


@_async_test
async def test_lost_commit_response_adopts_only_the_exact_persisted_event() -> None:
    client = _Client()
    client.lose_next_commit = True
    store = _store(client)

    result = await store.append(timeline_event(24))

    assert isinstance(result, TimelineAppendAdopted)
    assert result.entry.content.sequence == 1
    assert client.write_count == 3


@_async_test
async def test_exact_get_pages_are_order_independent_and_reconnect_without_omission() -> None:
    client = _Client()
    store = _store(client)
    for index in range(25, 28):
        await store.append(timeline_event(index))

    writes_before = client.write_count
    first = await store.read_page(_command(limit=2))
    assert [entry.content.sequence for entry in first.entries] == [1, 2]
    assert first.head is not None and first.head.sequence == 3
    second_command = _command(
        after_sequence=2,
        after_entry_sha256=first.entries[-1].entry_sha256,
        limit=2,
    )
    second = await store.read_page(second_command)
    repeated = await store.read_page(second_command)
    assert [entry.content.sequence for entry in second.entries] == [3]
    assert repeated == second
    assert client.write_count == writes_before
    assert all(len(paths) <= 3 for paths in client.batch_calls)
    assert not hasattr(store, "list")
    assert not hasattr(store, "query")
    assert not hasattr(store, "delete")


@_async_test
async def test_cursor_outside_head_or_with_wrong_digest_fails_closed() -> None:
    client = _Client()
    store = _store(client)
    created = await store.append(timeline_event(28))

    with pytest.raises(TimelineCursorInvalid):
        await store.read_page(
            _command(after_sequence=1, after_entry_sha256="f" * 64)
        )
    with pytest.raises(TimelineCursorInvalid):
        await store.read_page(
            _command(after_sequence=2, after_entry_sha256=created.entry.entry_sha256)
        )

    cross_target = TimelinePageCommandV1(
        schema_version=TIMELINE_PAGE_COMMAND_V1,
        target=OTHER_TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=10,
        audience=TimelineAudience.OPERATOR,
    )
    with pytest.raises(ValueError):
        await store.read_page(cross_target)


@_async_test
async def test_missing_or_duplicate_exact_get_results_are_corruption() -> None:
    client = _Client()
    store = _store(client)
    await store.append(timeline_event(29))
    await store.append(timeline_event(30))

    missing_path = (
        f"{TIMELINE_ENTRY_COLLECTION}/"
        f"{timeline_entry_document_id(TARGET, 2)}"
    )
    removed = client.documents.pop(missing_path)
    with pytest.raises(TimelineStoreCorruptRecord):
        await store.read_page(_command())
    client.documents[missing_path] = removed

    client.duplicate_batch = True
    with pytest.raises(TimelineStoreCorruptRecord):
        await store.read_page(_command())
