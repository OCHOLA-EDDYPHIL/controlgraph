from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Coroutine, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

import pytest
from timeline_test_data import (
    OTHER_TARGET,
    TARGET,
    timeline_event,
    timeline_event_with_raw,
)

from controlgraph_canary.application.timeline import (
    TimelineAppendAdopted,
    TimelineAppendCreated,
    TimelineCursorInvalid,
    TimelineRawExportGrant,
    TimelineRawExportService,
    TimelineStoreConflict,
    TimelineStoreCorruptRecord,
    TimelineWriteError,
    TimelineWriteErrorCode,
    TimelineWriteGrant,
    TimelineWriteService,
)
from controlgraph_canary.application.timeline_projectors import (
    project_signed_capability,
)
from controlgraph_canary.application.timeline_recording import TimelineRecorder
from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.models import (
    CAPABILITY_CLAIMS_V1,
    SIGNED_CAPABILITY_V1,
    CapabilityAction,
    CapabilityClaims,
    SignedCapability,
)
from controlgraph_canary.contracts.timeline import (
    TIMELINE_DISPLAY_FIELD_V1,
    TIMELINE_ENTRY_COLLECTION,
    TIMELINE_PAGE_COMMAND_V1,
    TIMELINE_RAW_COLLECTION,
    TIMELINE_RAW_EXPORT_COMMAND_V1,
    TIMELINE_RAW_TOMBSTONE_COLLECTION,
    TIMELINE_SIGNED_INTENT_COLLECTION,
    TimelineActorRole,
    TimelineAudience,
    TimelineDisplayFieldName,
    TimelineDisplayFieldV1,
    TimelinePageCommandV1,
    TimelineRawExportCommandV1,
    TimelineRawLifecycleStatus,
    standard_timeline_evidence_policy_set,
    timeline_capability_source_id,
    timeline_entry_document_id,
    timeline_raw_document_id,
    timeline_raw_tombstone_document_id,
    timeline_signed_intent_document_id,
)
from controlgraph_canary.integrations.google.firestore_timeline import (
    FIRESTORE_TIMELINE_DATABASE,
    AsyncFirestoreTimelineClientPort,
    FirestoreTimelineStore,
    FirestoreTimelineTransactionRunner,
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


class _Query:
    def __init__(self, client: _Client, collection: str) -> None:
        self.client = client
        self.collection = collection
        self.filters: list[tuple[str, str, object]] = []
        self.orders: list[str] = []
        self.maximum: int | None = None

    def where(self, *, filter: object) -> _Query:
        values = vars(filter)
        self.filters.append(
            (
                str(values["field_path"]),
                str(values["op_string"]),
                values["value"],
            )
        )
        return self

    def order_by(self, field_path: str, direction: object | None = None) -> _Query:
        del direction
        self.orders.append(field_path)
        return self

    def limit(self, count: int) -> _Query:
        self.maximum = count
        return self

    def stream(
        self,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[object]:
        del transaction, retry, timeout
        prefix = f"{self.collection}/"
        selected = [
            (path, data)
            for path, data in self.client.documents.items()
            if path.startswith(prefix) and "/" not in path[len(prefix) :]
        ]
        for field_path, operation, expected in self.filters:
            if operation == "==":
                selected = [item for item in selected if item[1].get(field_path) == expected]
            elif operation == "<=":
                selected = [
                    item
                    for item in selected
                    if item[1].get(field_path) is not None and item[1][field_path] <= expected
                ]
            else:
                raise AssertionError(operation)
        selected.sort(key=lambda item: (item[1]["expires_at"], item[0]))
        if self.maximum is not None:
            selected = selected[: self.maximum]
        if self.client.reverse_query:
            selected.reverse()
        if self.client.duplicate_query and selected:
            selected.append(selected[0])
        self.client.query_calls.append(
            (self.collection, tuple(self.filters), tuple(self.orders), self.maximum)
        )

        async def snapshots() -> AsyncIterator[object]:
            for path, data in selected:
                yield _Snapshot(self.client.document(*path.split("/")), data)

        return snapshots()


class _Transaction:
    def __init__(self, client: _Client) -> None:
        self.client = client
        self.write_results: list[object] = []
        self.writes: list[tuple[str, str, dict[str, Any] | None]] = []

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

    def delete(self, reference: TimelineDocumentReferencePort) -> None:
        self.writes.append(("delete", reference.path, None))


class _Client:
    project = TARGET.project_id
    _database = FIRESTORE_TIMELINE_DATABASE

    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}
        self.get_calls: list[str] = []
        self.batch_calls: list[tuple[str, ...]] = []
        self.query_calls: list[
            tuple[str, tuple[tuple[str, str, object], ...], tuple[str, ...], int | None]
        ] = []
        self.write_count = 0
        self.transaction_count = 0
        self.reverse_batch = True
        self.duplicate_batch = False
        self.reverse_query = False
        self.duplicate_query = False
        self.lose_next_commit = False
        self.lock = asyncio.Lock()

    @property
    def _database_string(self) -> str:
        return f"projects/{self.project}/databases/{self._database}"

    def document(self, *document_path: str) -> _Reference:
        return _Reference(self, "/".join(document_path))

    def collection(self, collection_path: str) -> _Query:
        return _Query(self, collection_path)

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
            if operation == "delete":
                client.documents.pop(path, None)
                continue
            assert data is not None
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


def _store(
    client: _Client,
    *,
    clock: Callable[[], datetime] = lambda: NOW,
    transaction_runner: FirestoreTimelineTransactionRunner | None = None,
) -> FirestoreTimelineStore:
    return FirestoreTimelineStore(
        target=TARGET,
        configured_project_id=TARGET.project_id,
        policy_set=standard_timeline_evidence_policy_set(TARGET),
        client_factory=lambda: client,
        transaction_runner=transaction_runner or _run_transaction,
        clock=clock,
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
    assert not hasattr(store, "delete_timeline_entry")


@_async_test
async def test_cursor_outside_head_or_with_wrong_digest_fails_closed() -> None:
    client = _Client()
    store = _store(client)
    created = await store.append(timeline_event(28))

    with pytest.raises(TimelineCursorInvalid):
        await store.read_page(_command(after_sequence=1, after_entry_sha256="f" * 64))
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

    missing_path = f"{TIMELINE_ENTRY_COLLECTION}/{timeline_entry_document_id(TARGET, 2)}"
    removed = client.documents.pop(missing_path)
    with pytest.raises(TimelineStoreCorruptRecord):
        await store.read_page(_command())
    client.documents[missing_path] = removed

    client.duplicate_batch = True
    with pytest.raises(TimelineStoreCorruptRecord):
        await store.read_page(_command())


@_async_test
async def test_raw_append_is_atomic_replay_safe_and_exact_id_exported() -> None:
    client = _Client()
    store = _store(client)
    event, raw_source = timeline_event_with_raw(32)

    policy_set = standard_timeline_evidence_policy_set(TARGET)
    writer = TimelineWriteService(target=TARGET, policy_set=policy_set, store=store)
    grant = TimelineWriteGrant(
        target=TARGET,
        writer_role=TimelineActorRole.COORDINATOR,
        principal_id="coordinator:synthetic",
    )
    created = await writer.append_with_raw(event, raw_source, grant)
    replay = await writer.append_with_raw(event, raw_source, grant)

    assert isinstance(created, TimelineAppendCreated)
    assert isinstance(replay, TimelineAppendAdopted)
    assert replay.entry == created.entry
    assert client.write_count == 4
    assert client.transaction_count == 1
    raw_path = f"{TIMELINE_RAW_COLLECTION}/{timeline_raw_document_id(TARGET, event.source_id)}"
    stored_raw = client.documents[raw_path]
    assert stored_raw["expires_at"] == NOW + timedelta(days=30)

    command = TimelineRawExportCommandV1(
        schema_version=TIMELINE_RAW_EXPORT_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=1,
    )
    exported = await TimelineRawExportService(target=TARGET, store=store).export(
        command,
        TimelineRawExportGrant(target=TARGET, principal_id="operator:synthetic"),
    )
    assert len(exported.entries) == 1
    assert exported.entries[0].lifecycle_status is TimelineRawLifecycleStatus.AVAILABLE
    assert exported.entries[0].canonical_record == raw_source.canonical_record
    assert client.batch_calls[-1] == (
        f"{TIMELINE_ENTRY_COLLECTION}/{timeline_entry_document_id(TARGET, 1)}",
    )
    assert raw_path in client.get_calls

    _, unrelated_raw = timeline_event_with_raw(35)
    with pytest.raises(TimelineWriteError) as denied:
        await writer.append_with_raw(event, unrelated_raw, grant)
    assert denied.value.code is TimelineWriteErrorCode.POLICY_DENIED


@_async_test
async def test_grouped_raw_append_is_one_transaction_and_replay_safe() -> None:
    client = _Client()
    store = _store(client)
    items = (timeline_event_with_raw(36), timeline_event_with_raw(37))
    writer = TimelineWriteService(
        target=TARGET,
        policy_set=standard_timeline_evidence_policy_set(TARGET),
        store=store,
    )
    grant = TimelineWriteGrant(
        target=TARGET,
        writer_role=TimelineActorRole.COORDINATOR,
        principal_id="coordinator:synthetic",
    )

    created = await writer.append_many_with_raw(items, grant)
    replay = await writer.append_many_with_raw(items, grant)

    assert all(isinstance(item, TimelineAppendCreated) for item in created)
    assert all(isinstance(item, TimelineAppendAdopted) for item in replay)
    assert tuple(item.entry for item in replay) == tuple(item.entry for item in created)
    assert [item.entry.content.sequence for item in created] == [1, 2]
    assert created[1].entry.content.previous_entry_sha256 == created[0].entry.entry_sha256
    assert client.transaction_count == 1
    assert client.write_count == 7


@_async_test
async def test_grouped_raw_append_recovers_an_exact_lost_commit_response() -> None:
    client = _Client()
    client.lose_next_commit = True
    store = _store(client)
    items = (timeline_event_with_raw(38), timeline_event_with_raw(39))

    result = await store.append_many_with_raw(items)

    assert all(isinstance(item, TimelineAppendAdopted) for item in result)
    assert [item.entry.content.sequence for item in result] == [1, 2]
    assert client.transaction_count == 1
    assert client.write_count == 7


@_async_test
async def test_grouped_raw_append_adopts_exact_prefix_and_appends_missing_suffix() -> None:
    client = _Client()
    store = _store(client)
    first = timeline_event_with_raw(40)
    second = timeline_event_with_raw(41)
    await store.append_with_raw(*first)

    result = await store.append_many_with_raw((first, second))

    assert isinstance(result[0], TimelineAppendAdopted)
    assert isinstance(result[1], TimelineAppendCreated)
    assert [item.entry.content.sequence for item in result] == [1, 2]
    assert client.transaction_count == 2
    assert client.write_count == 8


@_async_test
async def test_grouped_raw_append_adopts_a_concurrent_exact_commit() -> None:
    client = _Client()
    store = _store(client)
    concurrent_store = _store(client)
    items = (timeline_event_with_raw(42), timeline_event_with_raw(43))
    original_read = store._read_existing_append
    first_read = True

    async def racing_read(event):  # type: ignore[no-untyped-def]
        nonlocal first_read
        existing = await original_read(event)
        if first_read:
            first_read = False
            await concurrent_store.append_many_with_raw(items)
        return existing

    store._read_existing_append = racing_read  # type: ignore[method-assign]

    result = await store.append_many_with_raw(items)

    assert all(isinstance(item, TimelineAppendAdopted) for item in result)
    assert [item.entry.content.sequence for item in result] == [1, 2]
    assert client.transaction_count == 1
    assert client.write_count == 7


@_async_test
async def test_grouped_raw_append_adopts_exact_commit_after_preflight() -> None:
    client = _Client()
    concurrent_store = _store(client)
    items = (timeline_event_with_raw(44), timeline_event_with_raw(45))
    raced = False

    async def racing_runner(
        client_port: AsyncFirestoreTimelineClientPort,
        maximum_attempts: int,
        expected_writes: int,
        body: TimelineTransactionBody,
    ) -> None:
        nonlocal raced
        if not raced:
            raced = True
            await concurrent_store.append_many_with_raw(items)
        await _run_transaction(
            client_port,
            maximum_attempts,
            expected_writes,
            body,
        )

    store = _store(client, transaction_runner=racing_runner)

    result = await store.append_many_with_raw(items)

    assert all(isinstance(item, TimelineAppendAdopted) for item in result)
    assert [item.entry.content.sequence for item in result] == [1, 2]
    assert client.transaction_count == 2
    assert client.write_count == 7


@_async_test
async def test_signed_intent_is_read_by_receipt_bound_envelope_digest() -> None:
    client = _Client()
    store = _store(client)
    claims = CapabilityClaims(
        schema_version=CAPABILITY_CLAIMS_V1,
        capability_id=f"cgcap-{'c' * 64}",
        issuer=f"controlgraph-issuer@{TARGET.project_id}.iam.gserviceaccount.com",
        subject=f"controlgraph-executor@{TARGET.project_id}.iam.gserviceaccount.com",
        audience="https://controlgraph-executor.example/internal/execute",
        target=TARGET,
        root_id=f"cgroot:{'a' * 64}",
        root_sha256="a" * 64,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision="controlgraph-reference-target-stable-v1",
        candidate_revision="controlgraph-reference-target-candidate-v1",
        stable_percent=90,
        candidate_percent=10,
        concurrency=None,
        plan_sha256="b" * 64,
        provider_etag="stable-etag-1",
        request_id="request-capability-001",
        idempotency_key="capability-001",
        parent_capability_sha256=None,
        issued_at="2026-08-21T00:00:00Z",
        not_before="2026-08-21T00:00:00Z",
        expires_at="2026-08-21T00:10:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=(
            f"projects/{TARGET.project_id}/locations/us-central1/keyRings/"
            "controlgraph-signing/cryptoKeys/capability-signing/cryptoKeyVersions/1"
        ),
    )
    signed = SignedCapability(
        schema_version=SIGNED_CAPABILITY_V1,
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-capability-signature"),
    )
    digest = canonical_sha256(signed)
    projection = project_signed_capability(
        signed,
        policy_set=standard_timeline_evidence_policy_set(TARGET),
        signature_verified=False,
    )

    recorder = TimelineRecorder(
        service=TimelineWriteService(
            target=TARGET,
            policy_set=standard_timeline_evidence_policy_set(TARGET),
            store=store,
        ),
        grant=TimelineWriteGrant(
            target=TARGET,
            writer_role=TimelineActorRole.COORDINATOR,
            principal_id="coordinator:synthetic",
        ),
        policy_set=standard_timeline_evidence_policy_set(TARGET),
        signed_intent_store=store,
    )
    await recorder.record_signed_capability(signed, signature_verified=False)

    assert projection.event.source_id == timeline_capability_source_id(digest)
    intent_path = (
        f"{TIMELINE_SIGNED_INTENT_COLLECTION}/{timeline_signed_intent_document_id(TARGET, digest)}"
    )
    assert intent_path in client.documents
    assert signed.signature not in projection.raw_source.canonical_record
    assert await store.read_signed_intent(digest) == signed
    assert await store.read_signed_intent("f" * 64) is None


@_async_test
async def test_retention_sweep_retires_expired_raw_and_export_replays_without_writes() -> None:
    now = [NOW]
    client = _Client()
    store = _store(client, clock=lambda: now[0])
    event, raw_source = timeline_event_with_raw(33)
    await store.append_with_raw(event, raw_source)
    command = TimelineRawExportCommandV1(
        schema_version=TIMELINE_RAW_EXPORT_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=1,
    )

    now[0] = NOW + timedelta(days=30)
    receipts = await store.sweep_expired_raw(limit=25)
    assert len(receipts) == 1

    raw_path = f"{TIMELINE_RAW_COLLECTION}/{timeline_raw_document_id(TARGET, event.source_id)}"
    assert raw_path not in client.documents
    tombstone_path = (
        f"{TIMELINE_RAW_TOMBSTONE_COLLECTION}/"
        f"{timeline_raw_tombstone_document_id(TARGET, event.source_id)}"
    )
    assert tombstone_path in client.documents
    assert client.query_calls == [
        (
            TIMELINE_RAW_COLLECTION,
            (
                ("target_sha256", "==", canonical_sha256(TARGET)),
                ("expires_at", "<=", NOW + timedelta(days=30)),
            ),
            ("expires_at", "__name__"),
            25,
        )
    ]
    retained_write_count = client.write_count
    retained_transaction_count = client.transaction_count

    deleted = await store.read_raw_export(command)
    deleted_export = await TimelineRawExportService(target=TARGET, store=store).export(
        command,
        TimelineRawExportGrant(target=TARGET, principal_id="operator:synthetic"),
    )
    assert deleted.raw_evidence == (None,)
    assert deleted.deletion_receipts[0] is not None
    assert deleted_export.entries[0].lifecycle_status is TimelineRawLifecycleStatus.DELETED
    assert deleted_export.entries[0].canonical_record is None
    assert deleted_export.entries[0].record_sha256 == raw_source.record_sha256
    assert deleted_export.entries[0].deletion_receipt_id is not None
    assert deleted_export.entries[0].deletion_receipt_sha256 is not None
    replay = await store.read_raw_export(command)
    assert replay == deleted
    assert client.write_count == retained_write_count
    assert client.transaction_count == retained_transaction_count


@_async_test
async def test_retention_sweep_rejects_duplicate_or_unordered_query_results() -> None:
    for query_fault in ("duplicate_query", "reverse_query"):
        now = [NOW]
        client = _Client()
        store = _store(client, clock=lambda now=now: now[0])
        for ordinal in (35, 36):
            event, raw_source = timeline_event_with_raw(ordinal)
            await store.append_with_raw(event, raw_source)
        writes_before_sweep = client.write_count
        setattr(client, query_fault, True)
        now[0] = NOW + timedelta(days=30)

        with pytest.raises(TimelineStoreCorruptRecord):
            await store.sweep_expired_raw(limit=25)

        assert client.write_count == writes_before_sweep


@_async_test
async def test_raw_export_fails_closed_for_early_deletion_cursor_and_target() -> None:
    client = _Client()
    store = _store(client)
    event, raw_source = timeline_event_with_raw(34)
    created = await store.append_with_raw(event, raw_source)
    raw_path = f"{TIMELINE_RAW_COLLECTION}/{timeline_raw_document_id(TARGET, event.source_id)}"
    del client.documents[raw_path]
    initial = TimelineRawExportCommandV1(
        schema_version=TIMELINE_RAW_EXPORT_COMMAND_V1,
        target=TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=1,
    )
    with pytest.raises(TimelineStoreCorruptRecord):
        await store.read_raw_export(initial)

    bad_cursor = TimelineRawExportCommandV1(
        schema_version=TIMELINE_RAW_EXPORT_COMMAND_V1,
        target=TARGET,
        after_sequence=1,
        after_entry_sha256="f" * 64,
        limit=1,
    )
    with pytest.raises(TimelineCursorInvalid):
        await store.read_raw_export(bad_cursor)

    cross_target = TimelineRawExportCommandV1(
        schema_version=TIMELINE_RAW_EXPORT_COMMAND_V1,
        target=OTHER_TARGET,
        after_sequence=0,
        after_entry_sha256=None,
        limit=1,
    )
    with pytest.raises(ValueError):
        await store.read_raw_export(cross_target)

    assert created.entry.content.sequence == 1
