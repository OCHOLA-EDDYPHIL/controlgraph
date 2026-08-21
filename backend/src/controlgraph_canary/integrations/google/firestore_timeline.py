"""Target-sealed Firestore adapter for exact append and timeline pagination."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol, cast
from uuid import uuid4

from google.api_core import exceptions as api_exceptions
from google.cloud import firestore_v1

from controlgraph_canary.application.timeline import (
    TimelineAppendAdopted,
    TimelineAppendCreated,
    TimelineAppendResult,
    TimelineCursorInvalid,
    TimelineReadSlice,
    TimelineStoreConflict,
    TimelineStoreCorruptRecord,
    TimelineStoreOutcomeUnknown,
    TimelineStoreUnavailable,
)
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.timeline import (
    TIMELINE_ENTRY_COLLECTION,
    TIMELINE_HEAD_COLLECTION,
    TIMELINE_HEAD_V1,
    TIMELINE_IDENTITY_COLLECTION,
    TIMELINE_IDENTITY_V1,
    TIMELINE_STORAGE_DOCUMENT_V1,
    TimelineEntryV1,
    TimelineEventV1,
    TimelineEvidencePolicySetV1,
    TimelineHeadV1,
    TimelineIdentityV1,
    TimelinePageCommandV1,
    TimelineStorageDocumentV1,
    TimelineStorageKind,
    timeline_entry,
    timeline_entry_document_id,
    timeline_entry_logical_id,
    timeline_head_document_id,
    timeline_head_logical_id,
    timeline_identity_document_id,
    timeline_identity_logical_id,
)

FIRESTORE_TIMELINE_DATABASE: Final = "controlgraph-authority"
FIRESTORE_TIMELINE_REGION: Final = "us-central1"
FIRESTORE_TIMELINE_TIMEOUT_SECONDS: Final = 5.0
FIRESTORE_TIMELINE_MAX_TRANSACTION_ATTEMPTS: Final = 3

_CONTROLGRAPH_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_DOCUMENT_FIELDS = frozenset(TimelineStorageDocumentV1.model_fields)
_KNOWN_CONTENTION = (
    api_exceptions.Aborted,
    api_exceptions.AlreadyExists,
    api_exceptions.Conflict,
    api_exceptions.FailedPrecondition,
)


class TimelineDocumentReferencePort(Protocol):
    path: str

    async def get(
        self,
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> object: ...


class TimelineProviderSnapshotPort(Protocol):
    reference: TimelineDocumentReferencePort
    exists: bool
    read_time: datetime
    update_time: datetime | None

    def to_dict(self) -> dict[str, Any] | None: ...


class TimelineWriteResultPort(Protocol):
    update_time: datetime


class TimelineTransactionPort(Protocol):
    write_results: list[object]

    def create(
        self,
        reference: TimelineDocumentReferencePort,
        document_data: dict[str, Any],
    ) -> None: ...

    def update(
        self,
        reference: TimelineDocumentReferencePort,
        field_updates: dict[str, Any],
        option: object | None = None,
    ) -> None: ...


class AsyncFirestoreTimelineClientPort(Protocol):
    project: str
    _database: str

    @property
    def _database_string(self) -> str: ...

    def document(self, *document_path: str) -> TimelineDocumentReferencePort: ...

    def get_all(
        self,
        references: Sequence[TimelineDocumentReferencePort],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> AsyncIterator[object]: ...

    def transaction(
        self,
        max_attempts: int = FIRESTORE_TIMELINE_MAX_TRANSACTION_ATTEMPTS,
        read_only: bool = False,
    ) -> TimelineTransactionPort: ...


type FirestoreTimelineClientFactory = Callable[[], AsyncFirestoreTimelineClientPort]
type TimelineTransactionBody = Callable[[TimelineTransactionPort], Awaitable[None]]
type FirestoreTimelineTransactionRunner = Callable[
    [AsyncFirestoreTimelineClientPort, int, int, TimelineTransactionBody],
    Awaitable[None],
]


@dataclass(frozen=True, slots=True)
class _PreparedDocument[ModelT: StrictContractModel]:
    wrapper: TimelineStorageDocumentV1
    value: ModelT
    collection: str
    document_id: str


@dataclass(frozen=True, slots=True)
class _DecodedDocument[ModelT: StrictContractModel]:
    wrapper: TimelineStorageDocumentV1
    value: ModelT


@dataclass(frozen=True, slots=True)
class _ReadSpec:
    reference: TimelineDocumentReferencePort
    kind: TimelineStorageKind
    logical_id: str
    document_id: str
    model_type: type[StrictContractModel]


class _ReplayDetected(RuntimeError):
    def __init__(self, entry: TimelineEntryV1) -> None:
        self.entry = entry
        super().__init__("timeline replay detected")


def _default_client_factory(
    project_id: str,
    *,
    emulator: bool,
) -> FirestoreTimelineClientFactory:
    def create() -> AsyncFirestoreTimelineClientPort:
        if emulator:
            if not os.environ.get("FIRESTORE_EMULATOR_HOST"):
                raise ValueError("Firestore emulator construction requires an emulator host")
        elif "FIRESTORE_EMULATOR_HOST" in os.environ:
            raise ValueError("production Firestore construction rejects the emulator host")
        return cast(
            AsyncFirestoreTimelineClientPort,
            firestore_v1.AsyncClient(
                project=project_id,
                database=FIRESTORE_TIMELINE_DATABASE,
            ),
        )

    return create


async def _default_transaction_runner(
    client: AsyncFirestoreTimelineClientPort,
    maximum_attempts: int,
    expected_writes: int,
    body: TimelineTransactionBody,
) -> None:
    transaction = cast(
        firestore_v1.AsyncTransaction,
        client.transaction(max_attempts=maximum_attempts, read_only=False),
    )

    async def execute(value: firestore_v1.AsyncTransaction) -> None:
        await body(cast(TimelineTransactionPort, value))

    transactional = firestore_v1.async_transactional(execute)
    await transactional(transaction)
    results = transaction.write_results
    if type(results) is not list or len(results) != expected_writes:
        raise RuntimeError("ambiguous timeline transaction result")
    for result in results:
        _aware_utc(cast(TimelineWriteResultPort, result).update_time)


def _aware_utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("provider timestamp is invalid")
    return value.astimezone(UTC)


def _utc_second(value: datetime) -> str:
    return _aware_utc(value).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _system_clock() -> datetime:
    return datetime.now(UTC)


def _document_path(collection: str, document_id: str) -> str:
    return f"{collection}/{document_id}"


def _prepared_document[ModelT: StrictContractModel](
    *,
    kind: TimelineStorageKind,
    logical_id: str,
    collection: str,
    document_id: str,
    revision: int,
    value: ModelT,
) -> _PreparedDocument[ModelT]:
    wrapper = TimelineStorageDocumentV1(
        schema_version=TIMELINE_STORAGE_DOCUMENT_V1,
        record_kind=kind,
        logical_id=logical_id,
        revision=revision,
        mutation_id=f"timeline-write:{uuid4().hex}",
        canonical_payload=canonical_json_bytes(value).decode("utf-8"),
        payload_sha256=canonical_sha256(value),
    )
    if type(document_id) is not str or len(document_id) != 64:
        raise ValueError("timeline document identity is invalid")
    return _PreparedDocument(
        wrapper=wrapper,
        value=value,
        collection=collection,
        document_id=document_id,
    )


def _document_data(document: TimelineStorageDocumentV1) -> dict[str, Any]:
    data = document.model_dump(mode="json")
    if set(data) != _DOCUMENT_FIELDS:
        raise TimelineStoreCorruptRecord
    return data


def _is_contention(error: BaseException) -> bool:
    current: BaseException | None = error
    visited: set[int] = set()
    for _ in range(6):
        if current is None or id(current) in visited:
            return False
        visited.add(id(current))
        if isinstance(current, _KNOWN_CONTENTION):
            return True
        current = current.__cause__ or current.__context__
    return False


class FirestoreTimelineStore:
    """Append and page one fixed target without collection enumeration or deletion."""

    @classmethod
    def production(
        cls,
        *,
        target: TargetBinding,
        configured_project_id: str,
        policy_set: TimelineEvidencePolicySetV1,
        clock: Callable[[], datetime] | None = None,
    ) -> FirestoreTimelineStore:
        return cls(
            target=target,
            configured_project_id=configured_project_id,
            policy_set=policy_set,
            client_factory=_default_client_factory(configured_project_id, emulator=False),
            transaction_runner=_default_transaction_runner,
            clock=clock,
        )

    @classmethod
    def emulator(
        cls,
        *,
        target: TargetBinding,
        configured_project_id: str,
        policy_set: TimelineEvidencePolicySetV1,
        clock: Callable[[], datetime] | None = None,
    ) -> FirestoreTimelineStore:
        return cls(
            target=target,
            configured_project_id=configured_project_id,
            policy_set=policy_set,
            client_factory=_default_client_factory(configured_project_id, emulator=True),
            transaction_runner=_default_transaction_runner,
            clock=clock,
        )

    def __init__(
        self,
        *,
        target: TargetBinding,
        configured_project_id: str,
        policy_set: TimelineEvidencePolicySetV1,
        client_factory: FirestoreTimelineClientFactory,
        transaction_runner: FirestoreTimelineTransactionRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or type(configured_project_id) is not str
            or _CONTROLGRAPH_PROJECT_ID.fullmatch(configured_project_id) is None
            or target.project_id != configured_project_id
            or target.region != FIRESTORE_TIMELINE_REGION
            or type(policy_set) is not TimelineEvidencePolicySetV1
            or policy_set.target != target
            or not callable(client_factory)
            or not callable(transaction_runner)
            or (clock is not None and not callable(clock))
        ):
            raise ValueError("Firestore timeline configuration is invalid")
        self._target = target
        self._configured_project_id = configured_project_id
        self._policy_sha256 = canonical_sha256(policy_set)
        self._retention_by_class = {
            policy.evidence_class: policy.raw_retention_days
            for policy in policy_set.policies
        }
        self._client_factory = client_factory
        self._transaction_runner = transaction_runner
        self._clock = clock or _system_clock
        self._client_instance: AsyncFirestoreTimelineClientPort | None = None
        self._client_lock = asyncio.Lock()

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def _client(self) -> AsyncFirestoreTimelineClientPort:
        async with self._client_lock:
            if self._client_instance is None:
                try:
                    client = self._client_factory()
                    expected_database = (
                        f"projects/{self._configured_project_id}/databases/"
                        f"{FIRESTORE_TIMELINE_DATABASE}"
                    )
                    if (
                        client.project != self._configured_project_id
                        or client._database != FIRESTORE_TIMELINE_DATABASE
                        or client._database_string != expected_database
                        or any(
                            not callable(getattr(client, name, None))
                            for name in ("document", "get_all", "transaction")
                        )
                    ):
                        raise ValueError("Firestore timeline client binding is invalid")
                except Exception:
                    raise TimelineStoreUnavailable from None
                self._client_instance = client
            return self._client_instance

    def _reference(
        self,
        client: AsyncFirestoreTimelineClientPort,
        collection: str,
        document_id: str,
    ) -> TimelineDocumentReferencePort:
        expected_path = _document_path(collection, document_id)
        try:
            reference = client.document(collection, document_id)
        except Exception:
            raise TimelineStoreUnavailable from None
        if reference.path != expected_path:
            raise TimelineStoreCorruptRecord
        return reference

    async def _snapshot(
        self,
        reference: TimelineDocumentReferencePort,
        *,
        transaction: TimelineTransactionPort | None,
    ) -> object:
        try:
            async with asyncio.timeout(FIRESTORE_TIMELINE_TIMEOUT_SECONDS):
                return await reference.get(
                    field_paths=None,
                    transaction=transaction,
                    retry=None,
                    timeout=FIRESTORE_TIMELINE_TIMEOUT_SECONDS,
                    read_time=None,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise TimelineStoreUnavailable from None

    def _decode_snapshot[ModelT: StrictContractModel](
        self,
        snapshot: object,
        *,
        reference: TimelineDocumentReferencePort,
        kind: TimelineStorageKind,
        logical_id: str,
        model_type: type[ModelT],
    ) -> _DecodedDocument[ModelT] | None:
        try:
            provider = cast(TimelineProviderSnapshotPort, snapshot)
            _aware_utc(provider.read_time)
            if provider.reference.path != reference.path:
                raise ValueError("timeline snapshot path is invalid")
            if type(provider.exists) is not bool:
                raise ValueError("timeline snapshot existence flag is invalid")
            if not provider.exists:
                if provider.to_dict() is not None or provider.update_time is not None:
                    raise ValueError("missing timeline snapshot contains data")
                return None
            if provider.update_time is None:
                raise ValueError("timeline snapshot update time is absent")
            _aware_utc(provider.update_time)
            data = provider.to_dict()
            if type(data) is not dict or set(data) != _DOCUMENT_FIELDS:
                raise ValueError("timeline wrapper shape is invalid")
            if data.get("record_kind") != kind.value:
                raise ValueError("timeline wrapper kind is invalid")
            normalized = dict(data)
            normalized["record_kind"] = kind
            wrapper = TimelineStorageDocumentV1.model_validate(normalized)
            if wrapper.record_kind is not kind or wrapper.logical_id != logical_id:
                raise ValueError("timeline wrapper identity is invalid")
            value = decode_contract(wrapper.canonical_payload, model_type)
            if canonical_sha256(value) != wrapper.payload_sha256:
                raise ValueError("timeline wrapper digest is invalid")
            return _DecodedDocument(wrapper=wrapper, value=value)
        except TimelineStoreCorruptRecord:
            raise
        except Exception:
            raise TimelineStoreCorruptRecord from None

    async def _read_one[ModelT: StrictContractModel](
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        transaction: TimelineTransactionPort | None,
        collection: str,
        document_id: str,
        kind: TimelineStorageKind,
        logical_id: str,
        model_type: type[ModelT],
    ) -> _DecodedDocument[ModelT] | None:
        reference = self._reference(client, collection, document_id)
        snapshot = await self._snapshot(reference, transaction=transaction)
        return self._decode_snapshot(
            snapshot,
            reference=reference,
            kind=kind,
            logical_id=logical_id,
            model_type=model_type,
        )

    def _entry_matches_identity(
        self,
        entry: TimelineEntryV1,
        identity: TimelineIdentityV1,
        event: TimelineEventV1,
    ) -> bool:
        return (
            identity.target == self._target
            and identity.source_id == event.source_id
            and identity.source_schema_version == event.source_schema_version
            and identity.event_sha256 == canonical_sha256(event)
            and entry.content.target == self._target
            and entry.content.sequence == identity.sequence
            and entry.content.event == event
            and entry.entry_id == identity.entry_id
            and entry.entry_sha256 == identity.entry_sha256
            and entry.content.recorded_at == identity.recorded_at
        )

    async def _read_existing_append(
        self,
        event: TimelineEventV1,
    ) -> TimelineEntryV1 | None:
        client = await self._client()
        identity = await self._read_one(
            client=client,
            transaction=None,
            collection=TIMELINE_IDENTITY_COLLECTION,
            document_id=timeline_identity_document_id(self._target, event.source_id),
            kind=TimelineStorageKind.IDENTITY,
            logical_id=timeline_identity_logical_id(self._target, event.source_id),
            model_type=TimelineIdentityV1,
        )
        if identity is None:
            return None
        entry = await self._read_one(
            client=client,
            transaction=None,
            collection=TIMELINE_ENTRY_COLLECTION,
            document_id=timeline_entry_document_id(self._target, identity.value.sequence),
            kind=TimelineStorageKind.ENTRY,
            logical_id=timeline_entry_logical_id(self._target, identity.value.sequence),
            model_type=TimelineEntryV1,
        )
        if entry is None or not self._entry_matches_identity(
            entry.value,
            identity.value,
            event,
        ):
            raise TimelineStoreConflict
        head = await self._read_one(
            client=client,
            transaction=None,
            collection=TIMELINE_HEAD_COLLECTION,
            document_id=timeline_head_document_id(self._target),
            kind=TimelineStorageKind.HEAD,
            logical_id=timeline_head_logical_id(self._target),
            model_type=TimelineHeadV1,
        )
        if (
            head is None
            or head.wrapper.revision != head.value.sequence
            or head.value.target != self._target
            or head.value.sequence < identity.value.sequence
            or (
                head.value.sequence == identity.value.sequence
                and head.value.entry_sha256 != entry.value.entry_sha256
            )
        ):
            raise TimelineStoreCorruptRecord
        return entry.value

    async def append(self, event: TimelineEventV1) -> TimelineAppendResult:
        """Append once by immutable source identity or adopt an exact replay."""

        if (
            type(event) is not TimelineEventV1
            or event.target != self._target
            or event.policy_sha256 != self._policy_sha256
            or event.raw_retention_days
            != self._retention_by_class[event.evidence_class]
        ):
            raise ValueError("timeline event does not match configured target and policy")
        try:
            existing = await self._read_existing_append(event)
        except TimelineStoreConflict:
            raise
        except TimelineStoreCorruptRecord:
            raise
        except TimelineStoreUnavailable:
            existing = None
        if existing is not None:
            return TimelineAppendAdopted(existing)

        client = await self._client()
        event_sha256 = canonical_sha256(event)
        recorded_at = _utc_second(self._clock())
        created: TimelineEntryV1 | None = None

        async def write(transaction: TimelineTransactionPort) -> None:
            nonlocal created
            identity_logical_id = timeline_identity_logical_id(
                self._target,
                event.source_id,
            )
            current_identity = await self._read_one(
                client=client,
                transaction=transaction,
                collection=TIMELINE_IDENTITY_COLLECTION,
                document_id=timeline_identity_document_id(self._target, event.source_id),
                kind=TimelineStorageKind.IDENTITY,
                logical_id=identity_logical_id,
                model_type=TimelineIdentityV1,
            )
            if current_identity is not None:
                current_entry = await self._read_one(
                    client=client,
                    transaction=transaction,
                    collection=TIMELINE_ENTRY_COLLECTION,
                    document_id=timeline_entry_document_id(
                        self._target,
                        current_identity.value.sequence,
                    ),
                    kind=TimelineStorageKind.ENTRY,
                    logical_id=timeline_entry_logical_id(
                        self._target,
                        current_identity.value.sequence,
                    ),
                    model_type=TimelineEntryV1,
                )
                if current_entry is None or not self._entry_matches_identity(
                    current_entry.value,
                    current_identity.value,
                    event,
                ):
                    raise TimelineStoreConflict
                raise _ReplayDetected(current_entry.value)

            head_document_id = timeline_head_document_id(self._target)
            current_head = await self._read_one(
                client=client,
                transaction=transaction,
                collection=TIMELINE_HEAD_COLLECTION,
                document_id=head_document_id,
                kind=TimelineStorageKind.HEAD,
                logical_id=timeline_head_logical_id(self._target),
                model_type=TimelineHeadV1,
            )
            if current_head is None:
                sequence = 1
                predecessor = None
            else:
                if (
                    current_head.wrapper.revision != current_head.value.sequence
                    or current_head.value.target != self._target
                ):
                    raise TimelineStoreCorruptRecord
                sequence = current_head.value.sequence + 1
                predecessor = current_head.value.entry_sha256

            entry_logical_id = timeline_entry_logical_id(self._target, sequence)
            current_entry = await self._read_one(
                client=client,
                transaction=transaction,
                collection=TIMELINE_ENTRY_COLLECTION,
                document_id=timeline_entry_document_id(self._target, sequence),
                kind=TimelineStorageKind.ENTRY,
                logical_id=entry_logical_id,
                model_type=TimelineEntryV1,
            )
            if current_entry is not None:
                raise TimelineStoreCorruptRecord

            entry = timeline_entry(
                event,
                sequence=sequence,
                previous_entry_sha256=predecessor,
                recorded_at=recorded_at,
            )
            identity = TimelineIdentityV1(
                schema_version=TIMELINE_IDENTITY_V1,
                target=self._target,
                source_id=event.source_id,
                source_schema_version=event.source_schema_version,
                event_sha256=event_sha256,
                sequence=sequence,
                entry_id=entry.entry_id,
                entry_sha256=entry.entry_sha256,
                recorded_at=recorded_at,
            )
            head = TimelineHeadV1(
                schema_version=TIMELINE_HEAD_V1,
                target=self._target,
                sequence=sequence,
                entry_id=entry.entry_id,
                entry_sha256=entry.entry_sha256,
                updated_at=recorded_at,
            )
            prepared_identity = _prepared_document(
                kind=TimelineStorageKind.IDENTITY,
                logical_id=identity_logical_id,
                collection=TIMELINE_IDENTITY_COLLECTION,
                document_id=timeline_identity_document_id(self._target, event.source_id),
                revision=0,
                value=identity,
            )
            prepared_entry = _prepared_document(
                kind=TimelineStorageKind.ENTRY,
                logical_id=entry_logical_id,
                collection=TIMELINE_ENTRY_COLLECTION,
                document_id=timeline_entry_document_id(self._target, sequence),
                revision=0,
                value=entry,
            )
            prepared_head = _prepared_document(
                kind=TimelineStorageKind.HEAD,
                logical_id=timeline_head_logical_id(self._target),
                collection=TIMELINE_HEAD_COLLECTION,
                document_id=head_document_id,
                revision=sequence,
                value=head,
            )
            transaction.create(
                self._reference(
                    client,
                    prepared_identity.collection,
                    prepared_identity.document_id,
                ),
                _document_data(prepared_identity.wrapper),
            )
            transaction.create(
                self._reference(client, prepared_entry.collection, prepared_entry.document_id),
                _document_data(prepared_entry.wrapper),
            )
            head_reference = self._reference(
                client,
                prepared_head.collection,
                prepared_head.document_id,
            )
            if current_head is None:
                transaction.create(head_reference, _document_data(prepared_head.wrapper))
            else:
                transaction.update(head_reference, _document_data(prepared_head.wrapper))
            created = entry

        try:
            async with asyncio.timeout(FIRESTORE_TIMELINE_TIMEOUT_SECONDS):
                await self._transaction_runner(
                    client,
                    FIRESTORE_TIMELINE_MAX_TRANSACTION_ATTEMPTS,
                    3,
                    write,
                )
        except asyncio.CancelledError:
            raise
        except _ReplayDetected as replay:
            return TimelineAppendAdopted(replay.entry)
        except TimelineStoreConflict:
            raise
        except TimelineStoreCorruptRecord:
            raise
        except Exception as error:
            try:
                winner = await self._read_existing_append(event)
            except (TimelineStoreConflict, TimelineStoreCorruptRecord):
                raise
            except TimelineStoreUnavailable:
                raise TimelineStoreOutcomeUnknown from None
            if winner is not None:
                return TimelineAppendAdopted(winner)
            if _is_contention(error):
                raise TimelineStoreConflict from None
            raise TimelineStoreOutcomeUnknown from None
        if created is None:
            raise TimelineStoreOutcomeUnknown
        return TimelineAppendCreated(created)

    async def _batch_read_entries(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        sequences: tuple[int, ...],
    ) -> dict[int, TimelineEntryV1]:
        specs = tuple(
            _ReadSpec(
                reference=self._reference(
                    client,
                    TIMELINE_ENTRY_COLLECTION,
                    timeline_entry_document_id(self._target, sequence),
                ),
                kind=TimelineStorageKind.ENTRY,
                logical_id=timeline_entry_logical_id(self._target, sequence),
                document_id=timeline_entry_document_id(self._target, sequence),
                model_type=TimelineEntryV1,
            )
            for sequence in sequences
        )
        expected = {
            spec.reference.path: (sequence, spec)
            for sequence, spec in zip(sequences, specs, strict=True)
        }
        decoded: dict[int, TimelineEntryV1] = {}
        seen: set[str] = set()
        try:
            async with asyncio.timeout(FIRESTORE_TIMELINE_TIMEOUT_SECONDS):
                snapshots = client.get_all(
                    [spec.reference for spec in specs],
                    field_paths=None,
                    transaction=None,
                    retry=None,
                    timeout=FIRESTORE_TIMELINE_TIMEOUT_SECONDS,
                    read_time=None,
                )
                async for snapshot in snapshots:
                    try:
                        provider = cast(TimelineProviderSnapshotPort, snapshot)
                        path = provider.reference.path
                    except Exception:
                        raise TimelineStoreCorruptRecord from None
                    expected_item = expected.get(path)
                    if expected_item is None or path in seen:
                        raise TimelineStoreCorruptRecord
                    seen.add(path)
                    sequence, spec = expected_item
                    item = self._decode_snapshot(
                        snapshot,
                        reference=spec.reference,
                        kind=spec.kind,
                        logical_id=spec.logical_id,
                        model_type=TimelineEntryV1,
                    )
                    if item is None or item.wrapper.revision != 0:
                        raise TimelineStoreCorruptRecord
                    decoded[sequence] = item.value
        except asyncio.CancelledError:
            raise
        except TimelineStoreCorruptRecord:
            raise
        except Exception:
            raise TimelineStoreUnavailable from None
        if seen != set(expected) or set(decoded) != set(sequences):
            raise TimelineStoreCorruptRecord
        return decoded

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice:
        """Read a contiguous page using one head get and deterministic BatchGet IDs."""

        if type(command) is not TimelinePageCommandV1 or command.target != self._target:
            raise ValueError("timeline page command does not match the configured target")
        client = await self._client()
        head = await self._read_one(
            client=client,
            transaction=None,
            collection=TIMELINE_HEAD_COLLECTION,
            document_id=timeline_head_document_id(self._target),
            kind=TimelineStorageKind.HEAD,
            logical_id=timeline_head_logical_id(self._target),
            model_type=TimelineHeadV1,
        )
        if head is None:
            if command.after_sequence != 0:
                raise TimelineCursorInvalid
            return TimelineReadSlice(command=command, head=None, entries=())
        if head.wrapper.revision != head.value.sequence or head.value.target != self._target:
            raise TimelineStoreCorruptRecord
        if command.after_sequence > head.value.sequence:
            raise TimelineCursorInvalid

        first = command.after_sequence + 1
        last = min(head.value.sequence, command.after_sequence + command.limit)
        requested = tuple(range(first, last + 1))
        read_sequences = (
            (command.after_sequence, *requested)
            if command.after_sequence > 0
            else requested
        )
        decoded = await self._batch_read_entries(client=client, sequences=read_sequences)
        predecessor = command.after_entry_sha256
        if command.after_sequence > 0:
            cursor = decoded[command.after_sequence]
            if (
                cursor.content.target != self._target
                or cursor.content.sequence != command.after_sequence
                or cursor.entry_sha256 != command.after_entry_sha256
            ):
                raise TimelineCursorInvalid
            predecessor = cursor.entry_sha256
        entries: list[TimelineEntryV1] = []
        for sequence in requested:
            entry = decoded[sequence]
            if (
                entry.content.target != self._target
                or entry.content.sequence != sequence
                or entry.content.previous_entry_sha256 != predecessor
            ):
                raise TimelineStoreCorruptRecord
            entries.append(entry)
            predecessor = entry.entry_sha256
        if (
            requested
            and requested[-1] == head.value.sequence
            and entries[-1].entry_sha256 != head.value.entry_sha256
        ):
            raise TimelineStoreCorruptRecord
        if not requested and command.after_entry_sha256 != head.value.entry_sha256:
            raise TimelineCursorInvalid
        return TimelineReadSlice(
            command=command,
            head=head.value,
            entries=tuple(entries),
        )


__all__ = [
    "FIRESTORE_TIMELINE_DATABASE",
    "FIRESTORE_TIMELINE_MAX_TRANSACTION_ATTEMPTS",
    "FIRESTORE_TIMELINE_REGION",
    "FIRESTORE_TIMELINE_TIMEOUT_SECONDS",
    "AsyncFirestoreTimelineClientPort",
    "FirestoreTimelineClientFactory",
    "FirestoreTimelineStore",
    "FirestoreTimelineTransactionRunner",
    "TimelineDocumentReferencePort",
    "TimelineTransactionBody",
    "TimelineTransactionPort",
]
