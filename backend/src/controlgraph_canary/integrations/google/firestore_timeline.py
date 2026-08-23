"""Target-sealed Firestore adapter for exact append and timeline pagination."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol, cast
from uuid import uuid4

from google.api_core import exceptions as api_exceptions
from google.cloud import firestore_v1

from controlgraph_canary.application.timeline import (
    TIMELINE_RETENTION_SWEEP_LIMIT,
    TimelineAppendAdopted,
    TimelineAppendCreated,
    TimelineAppendResult,
    TimelineCursorInvalid,
    TimelineRawReadSlice,
    TimelineReadSlice,
    TimelineStoreConflict,
    TimelineStoreCorruptRecord,
    TimelineStoreError,
    TimelineStoreOutcomeUnknown,
    TimelineStoreUnavailable,
)
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import SignedCapability, TargetBinding
from controlgraph_canary.contracts.timeline import (
    TIMELINE_ENTRY_COLLECTION,
    TIMELINE_HEAD_COLLECTION,
    TIMELINE_HEAD_V1,
    TIMELINE_IDENTITY_COLLECTION,
    TIMELINE_IDENTITY_V1,
    TIMELINE_PAGE_COMMAND_V1,
    TIMELINE_RAW_COLLECTION,
    TIMELINE_RAW_DELETION_RECEIPT_V1,
    TIMELINE_RAW_EVIDENCE_V1,
    TIMELINE_RAW_TOMBSTONE_COLLECTION,
    TIMELINE_SIGNED_INTENT_COLLECTION,
    TIMELINE_STORAGE_DOCUMENT_V1,
    TimelineAudience,
    TimelineEntryV1,
    TimelineEventV1,
    TimelineEvidenceClass,
    TimelineEvidencePolicySetV1,
    TimelineHeadV1,
    TimelineIdentityV1,
    TimelinePageCommandV1,
    TimelineRawDeletionReceiptV1,
    TimelineRawEvidenceV1,
    TimelineRawExportCommandV1,
    TimelineRawSourceV1,
    TimelineStorageDocumentV1,
    TimelineStorageKind,
    timeline_entry,
    timeline_entry_document_id,
    timeline_entry_logical_id,
    timeline_head_document_id,
    timeline_head_logical_id,
    timeline_identity_document_id,
    timeline_identity_logical_id,
    timeline_raw_deletion_receipt_id,
    timeline_raw_document_id,
    timeline_raw_tombstone_document_id,
    timeline_signed_intent_document_id,
    timeline_target_sha256,
)

FIRESTORE_TIMELINE_DATABASE: Final = "controlgraph-authority"
FIRESTORE_TIMELINE_REGION: Final = "us-central1"
FIRESTORE_TIMELINE_TIMEOUT_SECONDS: Final = 5.0
FIRESTORE_TIMELINE_MAX_TRANSACTION_ATTEMPTS: Final = 3

_CONTROLGRAPH_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_DOCUMENT_FIELDS = frozenset(TimelineStorageDocumentV1.model_fields)
_RAW_STORAGE_VERSION: Final = "controlgraph.timeline-raw-storage/v1"
_SIGNED_INTENT_STORAGE_VERSION: Final = "controlgraph.signed-intent-storage/v1"
_RAW_DOCUMENT_FIELDS: Final = frozenset(
    {
        "schema_version",
        "logical_id",
        "entry_id",
        "entry_sha256",
        "sequence",
        "canonical_payload",
        "payload_sha256",
        "expires_at",
        "target_sha256",
    }
)
_SIGNED_INTENT_DOCUMENT_FIELDS: Final = frozenset(
    {
        "schema_version",
        "logical_id",
        "capability_sha256",
        "canonical_payload",
        "payload_sha256",
        "expires_at",
    }
)
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


class TimelineQueryPort(Protocol):
    def where(self, *, filter: object) -> TimelineQueryPort: ...

    def order_by(
        self,
        field_path: str,
        direction: object | None = None,
    ) -> TimelineQueryPort: ...

    def limit(self, count: int) -> TimelineQueryPort: ...

    def stream(
        self,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[object]: ...


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

    def delete(self, reference: TimelineDocumentReferencePort) -> None: ...


class AsyncFirestoreTimelineClientPort(Protocol):
    project: str
    _database: str

    @property
    def _database_string(self) -> str: ...

    def document(self, *document_path: str) -> TimelineDocumentReferencePort: ...

    def collection(self, collection_path: str) -> TimelineQueryPort: ...

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


@dataclass(frozen=True, slots=True)
class _StoredSignedIntent:
    value: SignedCapability
    expires_at: datetime


class _ReplayDetected(RuntimeError):
    def __init__(self, entry: TimelineEntryV1) -> None:
        self.entry = entry
        super().__init__("timeline replay detected")


class _SignedIntentReplay(RuntimeError):
    pass


class _RawDeletionReplay(RuntimeError):
    def __init__(self, receipt: TimelineRawDeletionReceiptV1) -> None:
        self.receipt = receipt
        super().__init__("timeline raw deletion replay detected")


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


def _raw_logical_id(target: TargetBinding, source_id: str) -> str:
    return f"cgtimeline-raw:{timeline_raw_document_id(target, source_id)}"


def _parse_utc_second(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (TypeError, ValueError) as error:
        raise TimelineStoreCorruptRecord from error


def _raw_evidence(
    *,
    entry: TimelineEntryV1,
    raw_source: TimelineRawSourceV1,
) -> TimelineRawEvidenceV1:
    recorded = _parse_utc_second(entry.content.recorded_at)
    expires = recorded + timedelta(days=entry.content.event.raw_retention_days)
    return TimelineRawEvidenceV1(
        schema_version=TIMELINE_RAW_EVIDENCE_V1,
        target=entry.content.target,
        sequence=entry.content.sequence,
        entry_id=entry.entry_id,
        entry_sha256=entry.entry_sha256,
        source_id=entry.content.event.source_id,
        raw_source=raw_source,
        recorded_at=entry.content.recorded_at,
        expires_at=_utc_second(expires),
        deletion_policy="EXPIRE_RAW_PRESERVE_DIGEST_V1",
    )


def _raw_document_data(raw: TimelineRawEvidenceV1) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": _RAW_STORAGE_VERSION,
        "logical_id": _raw_logical_id(raw.target, raw.source_id),
        "entry_id": raw.entry_id,
        "entry_sha256": raw.entry_sha256,
        "sequence": raw.sequence,
        "canonical_payload": canonical_json_bytes(raw).decode("utf-8"),
        "payload_sha256": canonical_sha256(raw),
        "expires_at": _parse_utc_second(raw.expires_at),
        "target_sha256": timeline_target_sha256(raw.target),
    }
    if set(data) != _RAW_DOCUMENT_FIELDS:
        raise TimelineStoreCorruptRecord
    return data


def _signed_intent_logical_id(target: TargetBinding, capability_sha256: str) -> str:
    return f"cgsigned-intent:{timeline_signed_intent_document_id(target, capability_sha256)}"


def _signed_intent_document_data(
    signed: SignedCapability,
    *,
    expires_at: datetime,
) -> dict[str, Any]:
    capability_sha256 = canonical_sha256(signed)
    data: dict[str, Any] = {
        "schema_version": _SIGNED_INTENT_STORAGE_VERSION,
        "logical_id": _signed_intent_logical_id(
            signed.claims.target,
            capability_sha256,
        ),
        "capability_sha256": capability_sha256,
        "canonical_payload": canonical_json_bytes(signed).decode("utf-8"),
        "payload_sha256": capability_sha256,
        "expires_at": _aware_utc(expires_at),
    }
    if set(data) != _SIGNED_INTENT_DOCUMENT_FIELDS:
        raise TimelineStoreCorruptRecord
    return data


def _raw_deletion_receipt(
    entry: TimelineEntryV1,
    *,
    confirmed_at: str,
) -> TimelineRawDeletionReceiptV1:
    event = entry.content.event
    expires_at = _utc_second(
        _parse_utc_second(entry.content.recorded_at) + timedelta(days=event.raw_retention_days)
    )
    return TimelineRawDeletionReceiptV1(
        schema_version=TIMELINE_RAW_DELETION_RECEIPT_V1,
        receipt_id=timeline_raw_deletion_receipt_id(
            entry.content.target,
            event.source_id,
            event.raw_record_sha256,
        ),
        target=entry.content.target,
        sequence=entry.content.sequence,
        entry_id=entry.entry_id,
        entry_sha256=entry.entry_sha256,
        source_id=event.source_id,
        raw_source_id=event.raw_source_id,
        record_sha256=event.raw_record_sha256,
        expires_at=expires_at,
        deletion_confirmed_at=confirmed_at,
        deletion_policy="EXPIRE_RAW_PRESERVE_DIGEST_V1",
    )


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
    """Append/page one target and retire expired raw records on write replay."""

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
            policy.evidence_class: policy.raw_retention_days for policy in policy_set.policies
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

    def _decode_raw_snapshot(
        self,
        snapshot: object,
        *,
        reference: TimelineDocumentReferencePort,
        source_id: str,
    ) -> TimelineRawEvidenceV1 | None:
        try:
            provider = cast(TimelineProviderSnapshotPort, snapshot)
            _aware_utc(provider.read_time)
            if provider.reference.path != reference.path or type(provider.exists) is not bool:
                raise ValueError("timeline raw snapshot metadata is invalid")
            if not provider.exists:
                if provider.to_dict() is not None or provider.update_time is not None:
                    raise ValueError("missing timeline raw snapshot contains data")
                return None
            if provider.update_time is None:
                raise ValueError("timeline raw snapshot update time is absent")
            _aware_utc(provider.update_time)
            data = provider.to_dict()
            if type(data) is not dict or set(data) != _RAW_DOCUMENT_FIELDS:
                raise ValueError("timeline raw wrapper shape is invalid")
            expires_at = _aware_utc(data.get("expires_at"))
            if (
                data.get("schema_version") != _RAW_STORAGE_VERSION
                or data.get("logical_id") != _raw_logical_id(self._target, source_id)
                or data.get("target_sha256") != timeline_target_sha256(self._target)
                or type(data.get("canonical_payload")) is not str
                or type(data.get("payload_sha256")) is not str
            ):
                raise ValueError("timeline raw wrapper identity is invalid")
            raw = decode_contract(data["canonical_payload"], TimelineRawEvidenceV1)
            if (
                raw.target != self._target
                or raw.source_id != source_id
                or raw.entry_id != data.get("entry_id")
                or raw.entry_sha256 != data.get("entry_sha256")
                or raw.sequence != data.get("sequence")
                or raw.expires_at != _utc_second(expires_at)
                or canonical_sha256(raw) != data["payload_sha256"]
            ):
                raise ValueError("timeline raw wrapper digest or binding is invalid")
            return raw
        except TimelineStoreCorruptRecord:
            raise
        except Exception:
            raise TimelineStoreCorruptRecord from None

    async def _read_raw_one(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        transaction: TimelineTransactionPort | None,
        source_id: str,
    ) -> TimelineRawEvidenceV1 | None:
        reference = self._reference(
            client,
            TIMELINE_RAW_COLLECTION,
            timeline_raw_document_id(self._target, source_id),
        )
        snapshot = await self._snapshot(reference, transaction=transaction)
        return self._decode_raw_snapshot(
            snapshot,
            reference=reference,
            source_id=source_id,
        )

    def _decode_raw_query_snapshot(
        self,
        snapshot: object,
        *,
        client: AsyncFirestoreTimelineClientPort,
    ) -> TimelineRawEvidenceV1:
        try:
            provider = cast(TimelineProviderSnapshotPort, snapshot)
            data = provider.to_dict()
            if type(data) is not dict or type(data.get("canonical_payload")) is not str:
                raise ValueError("timeline raw query result is invalid")
            raw = decode_contract(data["canonical_payload"], TimelineRawEvidenceV1)
            reference = self._reference(
                client,
                TIMELINE_RAW_COLLECTION,
                timeline_raw_document_id(self._target, raw.source_id),
            )
            decoded = self._decode_raw_snapshot(
                snapshot,
                reference=reference,
                source_id=raw.source_id,
            )
            if decoded is None:
                raise ValueError("timeline raw query returned a missing record")
            return decoded
        except TimelineStoreError:
            raise
        except Exception:
            raise TimelineStoreCorruptRecord from None

    async def _query_expired_raw(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        evaluated_at: datetime,
        limit: int,
    ) -> tuple[TimelineRawEvidenceV1, ...]:
        """Return only the oldest expired records for this exact target."""

        try:
            query = (
                client.collection(TIMELINE_RAW_COLLECTION)
                .where(
                    filter=firestore_v1.FieldFilter(
                        "target_sha256",
                        "==",
                        timeline_target_sha256(self._target),
                    )
                )
                .where(
                    filter=firestore_v1.FieldFilter(
                        "expires_at",
                        "<=",
                        evaluated_at,
                    )
                )
                .order_by("expires_at", direction=firestore_v1.Query.ASCENDING)
                .order_by("__name__", direction=firestore_v1.Query.ASCENDING)
                .limit(limit)
            )
            snapshots = query.stream(
                transaction=None,
                retry=None,
                timeout=FIRESTORE_TIMELINE_TIMEOUT_SECONDS,
            )
            selected: list[TimelineRawEvidenceV1] = []
            keys: list[tuple[datetime, str]] = []
            seen: set[str] = set()
            async with asyncio.timeout(FIRESTORE_TIMELINE_TIMEOUT_SECONDS):
                async for snapshot in snapshots:
                    provider = cast(TimelineProviderSnapshotPort, snapshot)
                    if provider.reference.path in seen or len(selected) >= limit:
                        raise TimelineStoreCorruptRecord
                    raw = self._decode_raw_query_snapshot(snapshot, client=client)
                    expiry = _parse_utc_second(raw.expires_at)
                    if expiry > evaluated_at:
                        raise TimelineStoreCorruptRecord
                    seen.add(provider.reference.path)
                    keys.append((expiry, provider.reference.path))
                    selected.append(raw)
            if keys != sorted(keys):
                raise TimelineStoreCorruptRecord
            return tuple(selected)
        except asyncio.CancelledError:
            raise
        except TimelineStoreError:
            raise
        except Exception:
            raise TimelineStoreUnavailable from None

    def _decode_signed_intent_snapshot(
        self,
        snapshot: object,
        *,
        reference: TimelineDocumentReferencePort,
        capability_sha256: str,
    ) -> _StoredSignedIntent | None:
        try:
            provider = cast(TimelineProviderSnapshotPort, snapshot)
            _aware_utc(provider.read_time)
            if provider.reference.path != reference.path or type(provider.exists) is not bool:
                raise ValueError("signed intent snapshot metadata is invalid")
            if not provider.exists:
                if provider.to_dict() is not None or provider.update_time is not None:
                    raise ValueError("missing signed intent snapshot contains data")
                return None
            if provider.update_time is None:
                raise ValueError("signed intent snapshot update time is absent")
            _aware_utc(provider.update_time)
            data = provider.to_dict()
            if type(data) is not dict or set(data) != _SIGNED_INTENT_DOCUMENT_FIELDS:
                raise ValueError("signed intent wrapper shape is invalid")
            expires_at = _aware_utc(data.get("expires_at"))
            if (
                data.get("schema_version") != _SIGNED_INTENT_STORAGE_VERSION
                or data.get("logical_id")
                != _signed_intent_logical_id(self._target, capability_sha256)
                or data.get("capability_sha256") != capability_sha256
                or data.get("payload_sha256") != capability_sha256
                or type(data.get("canonical_payload")) is not str
            ):
                raise ValueError("signed intent wrapper identity is invalid")
            signed = decode_contract(data["canonical_payload"], SignedCapability)
            if (
                signed.claims.target != self._target
                or canonical_sha256(signed) != capability_sha256
            ):
                raise ValueError("signed intent binding is invalid")
            return _StoredSignedIntent(value=signed, expires_at=expires_at)
        except TimelineStoreCorruptRecord:
            raise
        except Exception:
            raise TimelineStoreCorruptRecord from None

    async def _read_signed_intent_one(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        transaction: TimelineTransactionPort | None,
        capability_sha256: str,
    ) -> _StoredSignedIntent | None:
        reference = self._reference(
            client,
            TIMELINE_SIGNED_INTENT_COLLECTION,
            timeline_signed_intent_document_id(self._target, capability_sha256),
        )
        snapshot = await self._snapshot(reference, transaction=transaction)
        return self._decode_signed_intent_snapshot(
            snapshot,
            reference=reference,
            capability_sha256=capability_sha256,
        )

    async def persist_signed_intent(self, signed: SignedCapability) -> None:
        """Persist a capability in a TTL-bound, non-exportable exact-ID collection."""

        if type(signed) is not SignedCapability or signed.claims.target != self._target:
            raise ValueError("signed intent does not match the configured target")
        capability_sha256 = canonical_sha256(signed)
        client = await self._client()
        expires_at = self._clock() + timedelta(
            days=self._retention_by_class[TimelineEvidenceClass.CAPABILITY]
        )

        async def write(transaction: TimelineTransactionPort) -> None:
            current = await self._read_signed_intent_one(
                client=client,
                transaction=transaction,
                capability_sha256=capability_sha256,
            )
            if current is not None:
                if current.value != signed:
                    raise TimelineStoreCorruptRecord
                raise _SignedIntentReplay
            reference = self._reference(
                client,
                TIMELINE_SIGNED_INTENT_COLLECTION,
                timeline_signed_intent_document_id(self._target, capability_sha256),
            )
            transaction.create(
                reference,
                _signed_intent_document_data(signed, expires_at=expires_at),
            )

        try:
            async with asyncio.timeout(FIRESTORE_TIMELINE_TIMEOUT_SECONDS):
                await self._transaction_runner(
                    client,
                    FIRESTORE_TIMELINE_MAX_TRANSACTION_ATTEMPTS,
                    1,
                    write,
                )
        except asyncio.CancelledError:
            raise
        except _SignedIntentReplay:
            return
        except TimelineStoreCorruptRecord:
            raise
        except Exception:
            try:
                current = await self._read_signed_intent_one(
                    client=client,
                    transaction=None,
                    capability_sha256=capability_sha256,
                )
            except TimelineStoreError:
                raise TimelineStoreOutcomeUnknown from None
            if current is not None and current.value == signed:
                return
            raise TimelineStoreOutcomeUnknown from None

    async def read_signed_intent(
        self,
        capability_sha256: str,
    ) -> SignedCapability | None:
        """Read one unexpired signed capability by its receipt-bound digest."""

        stored = await self._read_signed_intent_one(
            client=await self._client(),
            transaction=None,
            capability_sha256=capability_sha256,
        )
        if stored is None or self._clock() >= stored.expires_at:
            return None
        return stored.value

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

    async def _require_existing_raw(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        transaction: TimelineTransactionPort | None,
        entry: TimelineEntryV1,
        raw_source: TimelineRawSourceV1,
    ) -> None:
        current = await self._read_raw_one(
            client=client,
            transaction=transaction,
            source_id=entry.content.event.source_id,
        )
        expected = _raw_evidence(entry=entry, raw_source=raw_source)
        if current is None:
            if self._clock() < _parse_utc_second(expected.expires_at):
                raise TimelineStoreCorruptRecord
            return
        if current != expected:
            raise TimelineStoreConflict

    async def _require_or_retire_existing_raw(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        entry: TimelineEntryV1,
        raw_source: TimelineRawSourceV1,
    ) -> None:
        expires_at = _parse_utc_second(_raw_evidence(entry=entry, raw_source=raw_source).expires_at)
        evaluated_at = _utc_second(self._clock())
        if _parse_utc_second(evaluated_at) < expires_at:
            await self._require_existing_raw(
                client=client,
                transaction=None,
                entry=entry,
                raw_source=raw_source,
            )
            return
        await self._delete_expired_raw(
            client=client,
            entry=entry,
            raw_source=raw_source,
            confirmed_at=evaluated_at,
        )

    async def _adopt_exact_prefix(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        existing: list[TimelineEntryV1 | None],
        items: tuple[tuple[TimelineEventV1, TimelineRawSourceV1], ...],
    ) -> tuple[TimelineAppendResult, ...]:
        first_missing = next(
            (index for index, entry in enumerate(existing) if entry is None),
            len(existing),
        )
        if any(entry is not None for entry in existing[first_missing:]):
            raise TimelineStoreConflict
        adopted: list[TimelineAppendResult] = []
        for entry, (_, raw_source) in zip(
            existing[:first_missing],
            items[:first_missing],
            strict=True,
        ):
            assert entry is not None
            await self._require_or_retire_existing_raw(
                client=client,
                entry=entry,
                raw_source=raw_source,
            )
            adopted.append(TimelineAppendAdopted(entry))
        return tuple(adopted)

    async def _read_existing_group(
        self,
        items: tuple[tuple[TimelineEventV1, TimelineRawSourceV1], ...],
    ) -> list[TimelineEntryV1 | None]:
        existing: list[TimelineEntryV1 | None] = []
        for event, _ in items:
            try:
                existing.append(await self._read_existing_append(event))
            except (TimelineStoreConflict, TimelineStoreCorruptRecord):
                raise
            except TimelineStoreUnavailable:
                existing.append(None)
        return existing

    async def _read_stable_exact_prefix(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        items: tuple[tuple[TimelineEventV1, TimelineRawSourceV1], ...],
    ) -> tuple[TimelineAppendResult, ...]:
        for attempt in range(2):
            existing = await self._read_existing_group(items)
            try:
                return await self._adopt_exact_prefix(
                    client=client,
                    existing=existing,
                    items=items,
                )
            except TimelineStoreConflict:
                if attempt:
                    raise
        raise TimelineStoreConflict

    async def append(self, event: TimelineEventV1) -> TimelineAppendResult:
        """Append once by immutable source identity or adopt an exact replay."""

        return await self._append(event, raw_source=None)

    async def append_with_raw(
        self,
        event: TimelineEventV1,
        raw_source: TimelineRawSourceV1,
    ) -> TimelineAppendResult:
        """Atomically append one summary and its finite-lifecycle raw source."""

        if type(raw_source) is not TimelineRawSourceV1:
            raise TypeError("timeline raw source must be exact")
        return await self._append(event, raw_source=raw_source)

    async def append_many_with_raw(
        self,
        items: tuple[tuple[TimelineEventV1, TimelineRawSourceV1], ...],
    ) -> tuple[TimelineAppendResult, ...]:
        """Append one causal group in a single Firestore transaction."""

        if type(items) is not tuple or not items or len(items) > 32:
            raise TypeError("timeline append group is invalid")
        source_ids: set[str] = set()
        for item in items:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError("timeline append group item is invalid")
            event, raw_source = item
            self._validate_event(event, raw_source=raw_source)
            if event.source_id in source_ids:
                raise ValueError("timeline append group source identities must be unique")
            source_ids.add(event.source_id)

        client = await self._client()
        adopted_prefix = await self._read_stable_exact_prefix(
            client=client,
            items=items,
        )
        if len(adopted_prefix) == len(items):
            return adopted_prefix
        if adopted_prefix:
            appended = await self.append_many_with_raw(items[len(adopted_prefix) :])
            return adopted_prefix + appended

        recorded_at = _utc_second(self._clock())
        created: tuple[TimelineEntryV1, ...] | None = None

        async def write(transaction: TimelineTransactionPort) -> None:
            nonlocal created
            identities: list[tuple[str, _DecodedDocument[TimelineIdentityV1] | None]] = []
            for event, _ in items:
                logical_id = timeline_identity_logical_id(self._target, event.source_id)
                identity = await self._read_one(
                    client=client,
                    transaction=transaction,
                    collection=TIMELINE_IDENTITY_COLLECTION,
                    document_id=timeline_identity_document_id(
                        self._target,
                        event.source_id,
                    ),
                    kind=TimelineStorageKind.IDENTITY,
                    logical_id=logical_id,
                    model_type=TimelineIdentityV1,
                )
                identities.append((logical_id, identity))
            if any(identity is not None for _, identity in identities):
                raise TimelineStoreConflict

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
                first_sequence = 1
                predecessor = None
            else:
                if (
                    current_head.wrapper.revision != current_head.value.sequence
                    or current_head.value.target != self._target
                ):
                    raise TimelineStoreCorruptRecord
                first_sequence = current_head.value.sequence + 1
                predecessor = current_head.value.entry_sha256

            pending: list[
                tuple[
                    _PreparedDocument[TimelineIdentityV1],
                    _PreparedDocument[TimelineEntryV1],
                    TimelineRawEvidenceV1,
                    TimelineEntryV1,
                ]
            ] = []
            for offset, ((event, raw_source), (identity_logical_id, _)) in enumerate(
                zip(items, identities, strict=True)
            ):
                sequence = first_sequence + offset
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
                current_raw = await self._read_raw_one(
                    client=client,
                    transaction=transaction,
                    source_id=event.source_id,
                )
                if current_entry is not None or current_raw is not None:
                    raise TimelineStoreCorruptRecord
                entry = timeline_entry(
                    event,
                    sequence=sequence,
                    previous_entry_sha256=predecessor,
                    recorded_at=recorded_at,
                )
                next_identity = TimelineIdentityV1(
                    schema_version=TIMELINE_IDENTITY_V1,
                    target=self._target,
                    source_id=event.source_id,
                    source_schema_version=event.source_schema_version,
                    event_sha256=canonical_sha256(event),
                    sequence=sequence,
                    entry_id=entry.entry_id,
                    entry_sha256=entry.entry_sha256,
                    recorded_at=recorded_at,
                )
                pending.append(
                    (
                        _prepared_document(
                            kind=TimelineStorageKind.IDENTITY,
                            logical_id=identity_logical_id,
                            collection=TIMELINE_IDENTITY_COLLECTION,
                            document_id=timeline_identity_document_id(
                                self._target,
                                event.source_id,
                            ),
                            revision=0,
                            value=next_identity,
                        ),
                        _prepared_document(
                            kind=TimelineStorageKind.ENTRY,
                            logical_id=entry_logical_id,
                            collection=TIMELINE_ENTRY_COLLECTION,
                            document_id=timeline_entry_document_id(
                                self._target,
                                sequence,
                            ),
                            revision=0,
                            value=entry,
                        ),
                        _raw_evidence(entry=entry, raw_source=raw_source),
                        entry,
                    )
                )
                predecessor = entry.entry_sha256

            final_entry = pending[-1][3]
            head = TimelineHeadV1(
                schema_version=TIMELINE_HEAD_V1,
                target=self._target,
                sequence=final_entry.content.sequence,
                entry_id=final_entry.entry_id,
                entry_sha256=final_entry.entry_sha256,
                updated_at=recorded_at,
            )
            prepared_head = _prepared_document(
                kind=TimelineStorageKind.HEAD,
                logical_id=timeline_head_logical_id(self._target),
                collection=TIMELINE_HEAD_COLLECTION,
                document_id=head_document_id,
                revision=head.sequence,
                value=head,
            )
            for prepared_identity, prepared_entry, raw, entry in pending:
                transaction.create(
                    self._reference(
                        client,
                        prepared_identity.collection,
                        prepared_identity.document_id,
                    ),
                    _document_data(prepared_identity.wrapper),
                )
                transaction.create(
                    self._reference(
                        client,
                        prepared_entry.collection,
                        prepared_entry.document_id,
                    ),
                    _document_data(prepared_entry.wrapper),
                )
                transaction.create(
                    self._reference(
                        client,
                        TIMELINE_RAW_COLLECTION,
                        timeline_raw_document_id(
                            self._target,
                            entry.content.event.source_id,
                        ),
                    ),
                    _raw_document_data(raw),
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
            created = tuple(item[3] for item in pending)

        try:
            async with asyncio.timeout(FIRESTORE_TIMELINE_TIMEOUT_SECONDS):
                await self._transaction_runner(
                    client,
                    FIRESTORE_TIMELINE_MAX_TRANSACTION_ATTEMPTS,
                    3 * len(items) + 1,
                    write,
                )
        except asyncio.CancelledError:
            raise
        except TimelineStoreConflict:
            try:
                adopted_prefix = await self._read_stable_exact_prefix(
                    client=client,
                    items=items,
                )
            except (TimelineStoreConflict, TimelineStoreCorruptRecord):
                raise
            except TimelineStoreUnavailable:
                raise TimelineStoreOutcomeUnknown from None
            if len(adopted_prefix) == len(items):
                return adopted_prefix
            if adopted_prefix:
                appended = await self.append_many_with_raw(items[len(adopted_prefix) :])
                return adopted_prefix + appended
            raise
        except TimelineStoreCorruptRecord:
            raise
        except Exception as error:
            try:
                adopted_prefix = await self._read_stable_exact_prefix(
                    client=client,
                    items=items,
                )
            except (TimelineStoreConflict, TimelineStoreCorruptRecord):
                raise
            except TimelineStoreUnavailable:
                raise TimelineStoreOutcomeUnknown from None
            if len(adopted_prefix) == len(items):
                return adopted_prefix
            if adopted_prefix:
                appended = await self.append_many_with_raw(items[len(adopted_prefix) :])
                return adopted_prefix + appended
            if _is_contention(error):
                raise TimelineStoreConflict from None
            raise TimelineStoreOutcomeUnknown from None
        if created is None:
            raise TimelineStoreOutcomeUnknown
        return tuple(TimelineAppendCreated(entry) for entry in created)

    def _validate_event(
        self,
        event: TimelineEventV1,
        *,
        raw_source: TimelineRawSourceV1 | None,
    ) -> None:
        if (
            type(event) is not TimelineEventV1
            or event.target != self._target
            or event.policy_sha256 != self._policy_sha256
            or event.raw_retention_days != self._retention_by_class[event.evidence_class]
        ):
            raise ValueError("timeline event does not match configured target and policy")
        signature_sha256 = None if event.signature is None else event.signature.signature_sha256
        if raw_source is not None and (
            raw_source.raw_source_id != event.raw_source_id
            or raw_source.source_schema_version != event.source_schema_version
            or raw_source.target != event.target
            or raw_source.evidence_class is not event.evidence_class
            or raw_source.payload_sha256 != event.payload_sha256
            or raw_source.record_sha256 != event.raw_record_sha256
            or raw_source.signature_sha256 != signature_sha256
        ):
            raise ValueError("timeline raw source does not match its event")

    async def _append(
        self,
        event: TimelineEventV1,
        *,
        raw_source: TimelineRawSourceV1 | None,
    ) -> TimelineAppendResult:

        self._validate_event(event, raw_source=raw_source)
        try:
            existing = await self._read_existing_append(event)
        except TimelineStoreConflict:
            raise
        except TimelineStoreCorruptRecord:
            raise
        except TimelineStoreUnavailable:
            existing = None
        if existing is not None:
            if raw_source is not None:
                await self._require_or_retire_existing_raw(
                    client=await self._client(),
                    entry=existing,
                    raw_source=raw_source,
                )
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
                if raw_source is not None:
                    await self._require_existing_raw(
                        client=client,
                        transaction=transaction,
                        entry=current_entry.value,
                        raw_source=raw_source,
                    )
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

            current_raw = await self._read_raw_one(
                client=client,
                transaction=transaction,
                source_id=event.source_id,
            )
            if current_raw is not None:
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
            if raw_source is not None:
                raw = _raw_evidence(entry=entry, raw_source=raw_source)
                transaction.create(
                    self._reference(
                        client,
                        TIMELINE_RAW_COLLECTION,
                        timeline_raw_document_id(self._target, event.source_id),
                    ),
                    _raw_document_data(raw),
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
                    4 if raw_source is not None else 3,
                    write,
                )
        except asyncio.CancelledError:
            raise
        except _ReplayDetected as replay:
            if raw_source is not None:
                await self._require_or_retire_existing_raw(
                    client=client,
                    entry=replay.entry,
                    raw_source=raw_source,
                )
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
                if raw_source is not None:
                    await self._require_or_retire_existing_raw(
                        client=await self._client(),
                        entry=winner,
                        raw_source=raw_source,
                    )
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
            (command.after_sequence, *requested) if command.after_sequence > 0 else requested
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

    def _deletion_receipt_matches_entry(
        self,
        receipt: TimelineRawDeletionReceiptV1,
        entry: TimelineEntryV1,
    ) -> bool:
        event = entry.content.event
        expected_expiry = _utc_second(
            _parse_utc_second(entry.content.recorded_at) + timedelta(days=event.raw_retention_days)
        )
        return (
            receipt.target == self._target
            and receipt.sequence == entry.content.sequence
            and receipt.entry_id == entry.entry_id
            and receipt.entry_sha256 == entry.entry_sha256
            and receipt.source_id == event.source_id
            and receipt.raw_source_id == event.raw_source_id
            and receipt.record_sha256 == event.raw_record_sha256
            and receipt.expires_at == expected_expiry
        )

    async def _read_deletion_receipt(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        transaction: TimelineTransactionPort | None,
        entry: TimelineEntryV1,
    ) -> TimelineRawDeletionReceiptV1 | None:
        event = entry.content.event
        receipt_id = timeline_raw_deletion_receipt_id(
            self._target,
            event.source_id,
            event.raw_record_sha256,
        )
        stored = await self._read_one(
            client=client,
            transaction=transaction,
            collection=TIMELINE_RAW_TOMBSTONE_COLLECTION,
            document_id=timeline_raw_tombstone_document_id(
                self._target,
                event.source_id,
            ),
            kind=TimelineStorageKind.RAW_DELETION,
            logical_id=receipt_id,
            model_type=TimelineRawDeletionReceiptV1,
        )
        if stored is None:
            return None
        if stored.wrapper.revision != 0 or not self._deletion_receipt_matches_entry(
            stored.value, entry
        ):
            raise TimelineStoreCorruptRecord
        return stored.value

    async def _delete_expired_raw(
        self,
        *,
        client: AsyncFirestoreTimelineClientPort,
        entry: TimelineEntryV1,
        raw_source: TimelineRawSourceV1,
        confirmed_at: str,
    ) -> TimelineRawDeletionReceiptV1:
        event = entry.content.event
        expected = _raw_deletion_receipt(entry, confirmed_at=confirmed_at)
        tombstone_document_id = timeline_raw_tombstone_document_id(
            self._target,
            event.source_id,
        )
        logical_id = expected.receipt_id
        selected: TimelineRawDeletionReceiptV1 | None = None

        async def write(transaction: TimelineTransactionPort) -> None:
            nonlocal selected
            current = await self._read_deletion_receipt(
                client=client,
                transaction=transaction,
                entry=entry,
            )
            raw = await self._read_raw_one(
                client=client,
                transaction=transaction,
                source_id=event.source_id,
            )
            if raw is not None and raw != _raw_evidence(
                entry=entry,
                raw_source=raw_source,
            ):
                raise TimelineStoreConflict
            if current is not None:
                if raw is not None:
                    raise TimelineStoreCorruptRecord
                raise _RawDeletionReplay(current)
            selected = expected
            prepared = _prepared_document(
                kind=TimelineStorageKind.RAW_DELETION,
                logical_id=logical_id,
                collection=TIMELINE_RAW_TOMBSTONE_COLLECTION,
                document_id=tombstone_document_id,
                revision=0,
                value=expected,
            )
            transaction.delete(
                self._reference(
                    client,
                    TIMELINE_RAW_COLLECTION,
                    timeline_raw_document_id(self._target, event.source_id),
                )
            )
            receipt_reference = self._reference(
                client,
                prepared.collection,
                prepared.document_id,
            )
            transaction.create(receipt_reference, _document_data(prepared.wrapper))

        try:
            async with asyncio.timeout(FIRESTORE_TIMELINE_TIMEOUT_SECONDS):
                await self._transaction_runner(
                    client,
                    FIRESTORE_TIMELINE_MAX_TRANSACTION_ATTEMPTS,
                    2,
                    write,
                )
        except asyncio.CancelledError:
            raise
        except _RawDeletionReplay as replay:
            return replay.receipt
        except TimelineStoreCorruptRecord:
            raise
        except TimelineStoreConflict:
            raise
        except Exception:
            adopted = await self._read_deletion_receipt(
                client=client,
                transaction=None,
                entry=entry,
            )
            remaining = await self._read_raw_one(
                client=client,
                transaction=None,
                source_id=event.source_id,
            )
            if (
                adopted is None
                or remaining is not None
                or not self._deletion_receipt_matches_entry(adopted, entry)
            ):
                raise TimelineStoreOutcomeUnknown from None
            return adopted
        if selected is None:
            raise TimelineStoreOutcomeUnknown
        return selected

    async def sweep_expired_raw(
        self,
        *,
        limit: int,
    ) -> tuple[TimelineRawDeletionReceiptV1, ...]:
        """Retire a bounded target-scoped batch and preserve deletion evidence."""

        if type(limit) is not int or not 1 <= limit <= TIMELINE_RETENTION_SWEEP_LIMIT:
            raise ValueError("timeline retention sweep limit is invalid")
        client = await self._client()
        evaluated = self._clock().astimezone(UTC).replace(microsecond=0)
        raw_records = await self._query_expired_raw(
            client=client,
            evaluated_at=evaluated,
            limit=limit,
        )
        if not raw_records:
            return ()
        sequences = tuple(raw.sequence for raw in raw_records)
        if len(set(sequences)) != len(sequences):
            raise TimelineStoreCorruptRecord
        entries = await self._batch_read_entries(client=client, sequences=sequences)
        receipts: list[TimelineRawDeletionReceiptV1] = []
        confirmed_at = _utc_second(evaluated)
        for raw in raw_records:
            entry = entries[raw.sequence]
            if raw != _raw_evidence(
                entry=entry, raw_source=raw.raw_source
            ) or evaluated < _parse_utc_second(raw.expires_at):
                raise TimelineStoreCorruptRecord
            receipts.append(
                await self._delete_expired_raw(
                    client=client,
                    entry=entry,
                    raw_source=raw.raw_source,
                    confirmed_at=confirmed_at,
                )
            )
        return tuple(receipts)

    async def read_raw_export(
        self,
        command: TimelineRawExportCommandV1,
    ) -> TimelineRawReadSlice:
        """Read a bounded raw page only by target-derived immutable document IDs."""

        if type(command) is not TimelineRawExportCommandV1 or command.target != self._target:
            raise ValueError("timeline raw export command does not match the configured target")
        summary_command = TimelinePageCommandV1(
            schema_version=TIMELINE_PAGE_COMMAND_V1,
            target=command.target,
            after_sequence=command.after_sequence,
            after_entry_sha256=command.after_entry_sha256,
            limit=command.limit,
            audience=TimelineAudience.RESTRICTED,
        )
        summary = await self.read_page(summary_command)
        client = await self._client()
        evaluated_at = _utc_second(self._clock())
        try:

            async def read_lifecycle(
                entry: TimelineEntryV1,
            ) -> tuple[TimelineRawEvidenceV1 | None, TimelineRawDeletionReceiptV1 | None]:
                raw, receipt = await asyncio.gather(
                    self._read_raw_one(
                        client=client,
                        transaction=None,
                        source_id=entry.content.event.source_id,
                    ),
                    self._read_deletion_receipt(
                        client=client,
                        transaction=None,
                        entry=entry,
                    ),
                )
                return raw, receipt

            lifecycle = await asyncio.gather(*(read_lifecycle(entry) for entry in summary.entries))
            return TimelineRawReadSlice(
                command=command,
                head=summary.head,
                entries=summary.entries,
                raw_evidence=tuple(item[0] for item in lifecycle),
                deletion_receipts=tuple(item[1] for item in lifecycle),
                evaluated_at=evaluated_at,
            )
        except asyncio.CancelledError:
            raise
        except TimelineStoreError:
            raise
        except Exception:
            raise TimelineStoreCorruptRecord from None


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
