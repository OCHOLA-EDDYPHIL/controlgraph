"""Transactional Firestore adapter sealed to ControlGraph authority state."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol, Self, cast
from uuid import uuid4

from google.api_core import exceptions as api_exceptions
from google.cloud import firestore_v1

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    CreatedRollout,
    StoredRecord,
)
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import (
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    ReceiptOutcome,
    RolloutRoot,
    TargetBinding,
)
from controlgraph_canary.contracts.storage import (
    AUTHORITY_STORAGE_DOCUMENT_V1,
    AuthorityStorageDocument,
    AuthorityStorageKind,
    ServiceClaimRecord,
    ServiceClaimStatus,
    epoch_authority_document_id,
    execution_receipt_document_id,
    execution_receipt_logical_id,
    rollout_root_document_id,
    service_claim_document_id,
    service_claim_logical_id,
)

FIRESTORE_AUTHORITY_DATABASE: Final = "controlgraph-authority"
FIRESTORE_AUTHORITY_REGION: Final = "us-central1"
FIRESTORE_OPERATION_TIMEOUT_SECONDS: Final = 5.0
FIRESTORE_MAX_TRANSACTION_ATTEMPTS: Final = 3

_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_DOCUMENT_FIELDS: Final = frozenset(AuthorityStorageDocument.model_fields)
_KNOWN_CONTENTION = (
    api_exceptions.Aborted,
    api_exceptions.AlreadyExists,
    api_exceptions.Conflict,
    api_exceptions.FailedPrecondition,
    api_exceptions.NotFound,
)


class _DocumentReferencePort(Protocol):
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


class _ProviderSnapshotPort(Protocol):
    reference: _DocumentReferencePort
    exists: bool
    read_time: datetime
    update_time: datetime | None

    def to_dict(self) -> dict[str, Any] | None: ...


class _WriteResultPort(Protocol):
    update_time: datetime


class _TransactionPort(Protocol):
    write_results: list[object]

    def create(
        self,
        reference: _DocumentReferencePort,
        document_data: dict[str, Any],
    ) -> None: ...

    def update(
        self,
        reference: _DocumentReferencePort,
        field_updates: dict[str, Any],
        option: object | None = None,
    ) -> None: ...


class AsyncFirestoreAuthorityClientPort(Protocol):
    """Narrow SDK surface used by the authority database adapter."""

    project: str
    _database: str

    @property
    def _database_string(self) -> str: ...

    def document(self, *document_path: str) -> _DocumentReferencePort: ...

    def transaction(
        self,
        max_attempts: int = FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
        read_only: bool = False,
    ) -> _TransactionPort: ...


type FirestoreAuthorityClientFactory = Callable[[], AsyncFirestoreAuthorityClientPort]
type _TransactionBody = Callable[[_TransactionPort], Awaitable[None]]
type FirestoreTransactionRunner = Callable[
    [AsyncFirestoreAuthorityClientPort, int, int, _TransactionBody],
    Awaitable[None],
]


class _ExpectedStateMismatch(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _PreparedDocument[ModelT: StrictContractModel]:
    wrapper: AuthorityStorageDocument
    value: ModelT
    document_id: str


@dataclass(frozen=True, slots=True)
class _DecodedDocument[ModelT: StrictContractModel]:
    wrapper: AuthorityStorageDocument
    value: ModelT

    @property
    def stored(self) -> StoredRecord[ModelT]:
        return StoredRecord(value=self.value, revision=self.wrapper.revision)


def _default_client_factory(
    project_id: str,
    *,
    emulator: bool,
) -> FirestoreAuthorityClientFactory:
    def create() -> AsyncFirestoreAuthorityClientPort:
        if emulator:
            _require_emulator_host()
        else:
            _reject_emulator_host()
        return cast(
            AsyncFirestoreAuthorityClientPort,
            firestore_v1.AsyncClient(
                project=project_id,
                database=FIRESTORE_AUTHORITY_DATABASE,
            ),
        )

    return create


def _validate_project_binding(target: TargetBinding, configured_project_id: str) -> None:
    if type(target) is not TargetBinding:
        raise TypeError("Firestore authority target must be exact")
    if type(configured_project_id) is not str:
        raise TypeError("Firestore authority project must be exact")
    if _CONTROLGRAPH_PROJECT_ID.fullmatch(configured_project_id) is None:
        raise ValueError("Firestore authority project must be a ControlGraph project")
    if target.project_id != configured_project_id:
        raise ValueError("Firestore authority target project does not match configuration")
    if target.region != FIRESTORE_AUTHORITY_REGION:
        raise ValueError("Firestore authority target must use us-central1")


def _reject_emulator_host() -> None:
    if "FIRESTORE_EMULATOR_HOST" in os.environ:
        raise ValueError("production Firestore construction rejects the emulator host")


def _require_emulator_host() -> None:
    if not os.environ.get("FIRESTORE_EMULATOR_HOST"):
        raise ValueError("Firestore emulator construction requires an emulator host")


def _expected_database_resource(project_id: str) -> str:
    return f"projects/{project_id}/databases/{FIRESTORE_AUTHORITY_DATABASE}"


async def _await_shielded[ResultT](
    task: asyncio.Task[ResultT],
    *,
    timeout_seconds: float,
) -> ResultT:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError
        try:
            async with asyncio.timeout(remaining):
                return await asyncio.shield(task)
        except asyncio.CancelledError:
            current_task = asyncio.current_task()
            if current_task is not None:
                current_task.uncancel()


def _consume_background_result(task: asyncio.Future[Any]) -> None:
    if task.cancelled():
        return
    try:
        task.exception()
    except BaseException:
        return


async def _default_transaction_runner(
    client: AsyncFirestoreAuthorityClientPort,
    maximum_attempts: int,
    expected_writes: int,
    body: _TransactionBody,
) -> None:
    transaction = cast(
        firestore_v1.AsyncTransaction,
        client.transaction(max_attempts=maximum_attempts),
    )

    async def execute(value: firestore_v1.AsyncTransaction) -> None:
        await body(cast(_TransactionPort, value))

    transactional = firestore_v1.async_transactional(execute)
    await transactional(transaction)
    results = transaction.write_results
    if type(results) is not list or len(results) != expected_writes:
        raise RuntimeError("ambiguous transaction result")
    for result in results:
        _aware_utc(cast(_WriteResultPort, result).update_time)


def _aware_utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("provider timestamp is invalid")
    return value.astimezone(UTC)


def _new_mutation_id() -> str:
    return f"write-{uuid4().hex}"


def _document_path(kind: AuthorityStorageKind, document_id: str) -> str:
    return f"{kind.value}/{document_id}"


def _prepared_document[ModelT: StrictContractModel](
    *,
    kind: AuthorityStorageKind,
    logical_id: str,
    document_id: str,
    revision: int,
    value: ModelT,
) -> _PreparedDocument[ModelT]:
    payload = canonical_json_bytes(value).decode("utf-8")
    wrapper = AuthorityStorageDocument(
        schema_version=AUTHORITY_STORAGE_DOCUMENT_V1,
        record_kind=kind,
        logical_id=logical_id,
        revision=revision,
        mutation_id=_new_mutation_id(),
        canonical_payload=payload,
        payload_sha256=canonical_sha256(value),
    )
    if type(document_id) is not str or len(document_id) != 64:
        raise ValueError("authority storage document identity is invalid")
    return _PreparedDocument(wrapper=wrapper, value=value, document_id=document_id)


def _document_data(document: AuthorityStorageDocument) -> dict[str, Any]:
    data = document.model_dump(mode="json")
    if set(data) != _DOCUMENT_FIELDS:
        raise AuthorityStoreCorruptRecord
    return data


def _same_prepared(
    decoded: _DecodedDocument[StrictContractModel],
    expected: _PreparedDocument[StrictContractModel],
) -> bool:
    return decoded.wrapper == expected.wrapper and decoded.value == expected.value


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


def _validate_initial_rollout(
    configured_target: TargetBinding,
    root: RolloutRoot,
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
) -> None:
    if any(value.target != configured_target for value in (root, claim, authority)):
        raise ValueError("rollout records do not match the configured target")
    root_sha256 = canonical_sha256(root)
    if (
        claim.root_id != root.root_id
        or claim.root_sha256 != root_sha256
        or claim.status is not ServiceClaimStatus.ACTIVE
        or authority.root_id != root.root_id
        or authority.root_sha256 != root_sha256
        or authority.current_epoch != root.initial_epoch
        or authority.previous_epoch is not None
        or authority.revision != 0
        or authority.cause is not EpochChangeCause.ROOT_CREATED
        or claim.claim_request_id != authority.request_id
        or claim.claim_evidence_id != authority.evidence_id
    ):
        raise ValueError("initial rollout records are not one atomic authority state")


def _validate_authority_advance(
    configured_target: TargetBinding,
    expected: StoredRecord[EpochAuthorityRecord],
    replacement: EpochAuthorityRecord,
) -> None:
    current = expected.value
    if type(current) is not EpochAuthorityRecord or type(replacement) is not EpochAuthorityRecord:
        raise TypeError("authority compare-and-set requires exact authority records")
    if expected.revision != current.revision:
        raise ValueError("authority storage and domain revisions differ")
    if current.target != configured_target or replacement.target != configured_target:
        raise ValueError("authority does not match the configured target")
    if (
        replacement.root_id != current.root_id
        or replacement.root_sha256 != current.root_sha256
        or replacement.previous_epoch != current.current_epoch
        or replacement.current_epoch != current.current_epoch + 1
        or replacement.revision != current.revision + 1
        or replacement.cause is EpochChangeCause.ROOT_CREATED
        or replacement.changed_at < current.changed_at
    ):
        raise ValueError("authority replacement is not a monotonic advance")


def _validate_claim_release(
    configured_target: TargetBinding,
    expected: StoredRecord[ServiceClaimRecord],
    replacement: ServiceClaimRecord,
) -> None:
    current = expected.value
    if type(current) is not ServiceClaimRecord or type(replacement) is not ServiceClaimRecord:
        raise TypeError("service claim compare-and-set requires exact claim records")
    if current.target != configured_target or replacement.target != configured_target:
        raise ValueError("service claim does not match the configured target")
    immutable_fields_match = (
        replacement.target == current.target
        and replacement.root_id == current.root_id
        and replacement.root_sha256 == current.root_sha256
        and replacement.claimed_by == current.claimed_by
        and replacement.claim_request_id == current.claim_request_id
        and replacement.claim_evidence_id == current.claim_evidence_id
        and replacement.claimed_at == current.claimed_at
    )
    if (
        current.status is not ServiceClaimStatus.ACTIVE
        or replacement.status is not ServiceClaimStatus.RELEASED
        or not immutable_fields_match
    ):
        raise ValueError("service claim replacement is not an exact release")


_RECEIPT_TRANSITIONS: Final = {
    ReceiptOutcome.CLAIMED: frozenset(
        {
            ReceiptOutcome.DENIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.AMBIGUOUS,
        }
    ),
    ReceiptOutcome.AMBIGUOUS: frozenset(
        {
            ReceiptOutcome.APPLIED,
            ReceiptOutcome.VERIFIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.AMBIGUOUS,
        }
    ),
    ReceiptOutcome.APPLIED: frozenset(
        {
            ReceiptOutcome.VERIFIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.AMBIGUOUS,
        }
    ),
}


def _receipt_binding(receipt: ExecutionReceipt) -> tuple[object, ...]:
    return (
        receipt.receipt_id,
        receipt.request_id,
        receipt.idempotency_key,
        receipt.capability_sha256,
        receipt.mutation_sha256,
        receipt.plan_sha256,
        receipt.expected_poststate_sha256,
        receipt.target,
        receipt.root_id,
        receipt.root_sha256,
        receipt.epoch,
        receipt.action,
        receipt.provider_etag,
        receipt.created_at,
    )


def _validate_receipt_identity(
    configured_target: TargetBinding,
    receipt: ExecutionReceipt,
) -> str:
    if receipt.target != configured_target:
        raise ValueError("receipt does not match the configured target")
    logical_id = execution_receipt_logical_id(
        configured_target,
        receipt.idempotency_key,
    )
    if receipt.receipt_id != logical_id:
        raise ValueError("receipt identifier does not match its idempotency claim")
    return logical_id


def _validate_receipt_replacement(
    configured_target: TargetBinding,
    expected: StoredRecord[ExecutionReceipt],
    replacement: ExecutionReceipt,
) -> None:
    current = expected.value
    if type(current) is not ExecutionReceipt or type(replacement) is not ExecutionReceipt:
        raise TypeError("receipt compare-and-set requires exact receipt records")
    _validate_receipt_identity(configured_target, current)
    _validate_receipt_identity(configured_target, replacement)
    if _receipt_binding(current) != _receipt_binding(replacement):
        raise ValueError("receipt replacement changes an immutable binding")
    if replacement.outcome not in _RECEIPT_TRANSITIONS.get(current.outcome, frozenset()):
        raise ValueError("receipt replacement is not a permitted forward transition")
    if replacement.updated_at < current.updated_at:
        raise ValueError("receipt replacement moves time backwards")
    if replacement.evidence_ids[: len(current.evidence_ids)] != current.evidence_ids:
        raise ValueError("receipt replacement removes existing evidence")
    if replacement == current:
        raise ValueError("receipt replacement does not change durable state")


class FirestoreAuthorityStore:
    """Authority store fixed to one ControlGraph service and named database."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        configured_project_id: str,
    ) -> None:
        _reject_emulator_host()
        self._initialize(
            target=target,
            configured_project_id=configured_project_id,
            client_factory=_default_client_factory(
                configured_project_id,
                emulator=False,
            ),
            transaction_runner=_default_transaction_runner,
        )

    @classmethod
    def for_emulator(
        cls,
        *,
        target: TargetBinding,
        configured_project_id: str,
    ) -> Self:
        _require_emulator_host()
        return cls._from_components(
            target=target,
            configured_project_id=configured_project_id,
            client_factory=_default_client_factory(
                configured_project_id,
                emulator=True,
            ),
            transaction_runner=_default_transaction_runner,
        )

    @classmethod
    def for_test(
        cls,
        *,
        target: TargetBinding,
        configured_project_id: str,
        client_factory: FirestoreAuthorityClientFactory,
        transaction_runner: FirestoreTransactionRunner | None = None,
    ) -> Self:
        selected_transaction_runner = (
            _default_transaction_runner if transaction_runner is None else transaction_runner
        )
        return cls._from_components(
            target=target,
            configured_project_id=configured_project_id,
            client_factory=client_factory,
            transaction_runner=selected_transaction_runner,
        )

    @classmethod
    def _from_components(
        cls,
        *,
        target: TargetBinding,
        configured_project_id: str,
        client_factory: FirestoreAuthorityClientFactory,
        transaction_runner: FirestoreTransactionRunner,
    ) -> Self:
        instance = cls.__new__(cls)
        instance._initialize(
            target=target,
            configured_project_id=configured_project_id,
            client_factory=client_factory,
            transaction_runner=transaction_runner,
        )
        return instance

    def _initialize(
        self,
        *,
        target: TargetBinding,
        configured_project_id: str,
        client_factory: FirestoreAuthorityClientFactory,
        transaction_runner: FirestoreTransactionRunner,
    ) -> None:
        _validate_project_binding(target, configured_project_id)
        if not callable(client_factory):
            raise TypeError("Firestore client factory must be callable")
        if not callable(transaction_runner):
            raise TypeError("Firestore transaction runner must be callable")
        self._target = target
        self._configured_project_id = configured_project_id
        self._client_factory = client_factory
        self._transaction_runner = transaction_runner
        self._client_instance: AsyncFirestoreAuthorityClientPort | None = None
        self._client_lock = asyncio.Lock()

    @property
    def target(self) -> TargetBinding:
        return self._target

    @property
    def database_id(self) -> str:
        return FIRESTORE_AUTHORITY_DATABASE

    async def _client(self) -> AsyncFirestoreAuthorityClientPort:
        if self._client_instance is not None:
            return self._client_instance
        async with self._client_lock:
            if self._client_instance is None:
                try:
                    client = self._client_factory()
                except Exception:
                    raise AuthorityStoreUnavailable from None
                if any(
                    not callable(getattr(client, name, None))
                    for name in ("document", "transaction")
                ):
                    raise AuthorityStoreUnavailable
                try:
                    project = client.project
                    database = client._database
                    database_resource = client._database_string
                except Exception:
                    raise AuthorityStoreUnavailable from None
                if (
                    type(project) is not str
                    or project != self._configured_project_id
                    or type(database) is not str
                    or database != FIRESTORE_AUTHORITY_DATABASE
                    or type(database_resource) is not str
                    or database_resource != _expected_database_resource(self._configured_project_id)
                ):
                    raise AuthorityStoreUnavailable
                self._client_instance = client
            return self._client_instance

    @staticmethod
    def _reference(
        client: AsyncFirestoreAuthorityClientPort,
        kind: AuthorityStorageKind,
        document_id: str,
    ) -> _DocumentReferencePort:
        expected_path = _document_path(kind, document_id)
        try:
            reference = client.document(kind.value, document_id)
            path = reference.path
        except Exception:
            raise AuthorityStoreUnavailable from None
        if path != expected_path:
            raise AuthorityStoreCorruptRecord
        return reference

    @staticmethod
    async def _get_snapshot(
        reference: _DocumentReferencePort,
        *,
        transaction: _TransactionPort | None,
    ) -> object:
        return await reference.get(
            field_paths=None,
            transaction=transaction,
            retry=None,
            timeout=FIRESTORE_OPERATION_TIMEOUT_SECONDS,
            read_time=None,
        )

    @staticmethod
    def _decode_snapshot[ModelT: StrictContractModel](
        snapshot: object,
        *,
        reference: _DocumentReferencePort,
        kind: AuthorityStorageKind,
        logical_id: str,
        document_id: str,
        model_type: type[ModelT],
    ) -> _DecodedDocument[ModelT] | None:
        try:
            provider_snapshot = cast(_ProviderSnapshotPort, snapshot)
            snapshot_reference = provider_snapshot.reference
            if snapshot_reference.path != reference.path:
                raise ValueError("snapshot reference does not match")
            exists = provider_snapshot.exists
            if type(exists) is not bool:
                raise ValueError("snapshot existence flag is invalid")
            _aware_utc(provider_snapshot.read_time)
            data = provider_snapshot.to_dict()
            update_time = provider_snapshot.update_time
            if not exists:
                if data is not None or update_time is not None:
                    raise ValueError("missing snapshot contains state")
                return None
            _aware_utc(update_time)
            if type(data) is not dict or set(data) != _DOCUMENT_FIELDS:
                raise ValueError("storage wrapper is not exact")
            if data.get("record_kind") != kind.value:
                raise ValueError("storage wrapper kind does not match")
            normalized = dict(data)
            normalized["record_kind"] = kind
            wrapper = AuthorityStorageDocument.model_validate(normalized)
            if wrapper.record_kind is not kind or wrapper.logical_id != logical_id:
                raise ValueError("storage wrapper identity does not match")
            if reference.path != _document_path(kind, document_id):
                raise ValueError("storage document path does not match")
            value = decode_contract(wrapper.canonical_payload, model_type)
            if canonical_sha256(value) != wrapper.payload_sha256:
                raise ValueError("storage payload digest does not match")
            return _DecodedDocument(wrapper=wrapper, value=value)
        except (AuthorityStoreCorruptRecord, asyncio.CancelledError):
            raise
        except Exception:
            raise AuthorityStoreCorruptRecord from None

    async def _strong_read[ModelT: StrictContractModel](
        self,
        *,
        kind: AuthorityStorageKind,
        logical_id: str,
        document_id: str,
        model_type: type[ModelT],
    ) -> _DecodedDocument[ModelT] | None:
        client = await self._client()
        reference = self._reference(client, kind, document_id)
        try:
            async with asyncio.timeout(FIRESTORE_OPERATION_TIMEOUT_SECONDS):
                snapshot = await self._get_snapshot(reference, transaction=None)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise
        except Exception:
            raise AuthorityStoreUnavailable from None
        return self._decode_snapshot(
            snapshot,
            reference=reference,
            kind=kind,
            logical_id=logical_id,
            document_id=document_id,
            model_type=model_type,
        )

    async def _transaction_read[ModelT: StrictContractModel](
        self,
        transaction: _TransactionPort,
        *,
        reference: _DocumentReferencePort,
        kind: AuthorityStorageKind,
        logical_id: str,
        document_id: str,
        model_type: type[ModelT],
    ) -> _DecodedDocument[ModelT] | None:
        snapshot = await self._get_snapshot(reference, transaction=transaction)
        return self._decode_snapshot(
            snapshot,
            reference=reference,
            kind=kind,
            logical_id=logical_id,
            document_id=document_id,
            model_type=model_type,
        )

    async def _resolve_ambiguous(
        self,
        documents: tuple[_PreparedDocument[StrictContractModel], ...],
    ) -> tuple[_DecodedDocument[StrictContractModel], ...]:
        resolved: list[_DecodedDocument[StrictContractModel]] = []
        competing_revision = False
        try:
            for expected in documents:
                current = await self._strong_read(
                    kind=expected.wrapper.record_kind,
                    logical_id=expected.wrapper.logical_id,
                    document_id=expected.document_id,
                    model_type=type(expected.value),
                )
                if current is not None and _same_prepared(current, expected):
                    resolved.append(current)
                elif current is not None and current.wrapper.revision == expected.wrapper.revision:
                    competing_revision = True
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AuthorityStoreOutcomeUnknown from None
        if len(resolved) == len(documents):
            return tuple(resolved)
        if competing_revision:
            raise AuthorityStoreConflict
        raise AuthorityStoreOutcomeUnknown

    async def _run_transaction(
        self,
        documents: tuple[_PreparedDocument[StrictContractModel], ...],
        body: _TransactionBody,
    ) -> tuple[_DecodedDocument[StrictContractModel], ...] | None:
        client = await self._client()

        async def execute() -> tuple[_DecodedDocument[StrictContractModel], ...] | None:
            try:
                await self._transaction_runner(
                    client,
                    FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
                    len(documents),
                    body,
                )
            except asyncio.CancelledError:
                raise
            except AuthorityStoreCorruptRecord:
                raise
            except _ExpectedStateMismatch:
                raise AuthorityStoreConflict from None
            except Exception as error:
                if _is_contention(error):
                    raise AuthorityStoreConflict from None
                return await self._resolve_ambiguous(documents)
            return None

        operation = asyncio.create_task(execute())
        try:
            return await _await_shielded(
                operation,
                timeout_seconds=FIRESTORE_OPERATION_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            operation.add_done_callback(_consume_background_result)

        classification = asyncio.create_task(self._resolve_ambiguous(documents))
        try:
            return await _await_shielded(
                classification,
                timeout_seconds=FIRESTORE_OPERATION_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            classification.add_done_callback(_consume_background_result)
            raise AuthorityStoreOutcomeUnknown from None

    async def create_rollout(
        self,
        root: RolloutRoot,
        service_claim: ServiceClaimRecord,
        authority: EpochAuthorityRecord,
    ) -> CreatedRollout:
        _validate_initial_rollout(self._target, root, service_claim, authority)
        root_document = _prepared_document(
            kind=AuthorityStorageKind.ROLLOUT_ROOT,
            logical_id=root.root_id,
            document_id=rollout_root_document_id(root.root_id),
            revision=0,
            value=root,
        )
        claim_logical_id = service_claim_logical_id(self._target)
        claim_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=claim_logical_id,
            document_id=service_claim_document_id(self._target),
            revision=0,
            value=service_claim,
        )
        authority_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=authority.root_id,
            document_id=epoch_authority_document_id(authority.root_id),
            revision=0,
            value=authority,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            root_document,
            claim_document,
            authority_document,
        )

        async def create(transaction: _TransactionPort) -> None:
            client = await self._client()
            for document in documents:
                reference = self._reference(
                    client,
                    document.wrapper.record_kind,
                    document.document_id,
                )
                transaction.create(reference, _document_data(document.wrapper))

        await self._run_transaction(documents, create)
        return CreatedRollout(
            root=_stored(root_document),
            service_claim=_stored(claim_document),
            authority=_stored(authority_document),
        )

    async def read_rollout_root(self, root_id: str) -> StoredRecord[RolloutRoot] | None:
        decoded = await self._strong_read(
            kind=AuthorityStorageKind.ROLLOUT_ROOT,
            logical_id=root_id,
            document_id=rollout_root_document_id(root_id),
            model_type=RolloutRoot,
        )
        if decoded is not None and decoded.value.target != self._target:
            raise AuthorityStoreCorruptRecord
        return None if decoded is None else decoded.stored

    async def read_service_claim(self) -> StoredRecord[ServiceClaimRecord] | None:
        logical_id = service_claim_logical_id(self._target)
        decoded = await self._strong_read(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=logical_id,
            document_id=service_claim_document_id(self._target),
            model_type=ServiceClaimRecord,
        )
        if decoded is not None and decoded.value.target != self._target:
            raise AuthorityStoreCorruptRecord
        return None if decoded is None else decoded.stored

    async def read_authority(
        self,
        root_id: str,
    ) -> StoredRecord[EpochAuthorityRecord] | None:
        decoded = await self._strong_read(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=root_id,
            document_id=epoch_authority_document_id(root_id),
            model_type=EpochAuthorityRecord,
        )
        if decoded is not None and decoded.value.target != self._target:
            raise AuthorityStoreCorruptRecord
        return None if decoded is None else decoded.stored

    async def advance_authority(
        self,
        expected: StoredRecord[EpochAuthorityRecord],
        replacement: EpochAuthorityRecord,
    ) -> StoredRecord[EpochAuthorityRecord]:
        _validate_authority_advance(self._target, expected, replacement)
        document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=replacement.root_id,
            document_id=epoch_authority_document_id(replacement.root_id),
            revision=expected.revision + 1,
            value=replacement,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (document,)

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            reference = self._reference(
                client,
                AuthorityStorageKind.EPOCH_AUTHORITY,
                epoch_authority_document_id(replacement.root_id),
            )
            current = await self._transaction_read(
                transaction,
                reference=reference,
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=replacement.root_id,
                document_id=document.document_id,
                model_type=EpochAuthorityRecord,
            )
            if current is None or current.stored != expected:
                raise _ExpectedStateMismatch
            transaction.update(reference, _document_data(document.wrapper))

        await self._run_transaction(documents, update)
        return _stored(document)

    async def release_service_claim(
        self,
        expected: StoredRecord[ServiceClaimRecord],
        replacement: ServiceClaimRecord,
    ) -> StoredRecord[ServiceClaimRecord]:
        _validate_claim_release(self._target, expected, replacement)
        logical_id = service_claim_logical_id(self._target)
        document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=logical_id,
            document_id=service_claim_document_id(self._target),
            revision=expected.revision + 1,
            value=replacement,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (document,)

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            reference = self._reference(
                client,
                AuthorityStorageKind.SERVICE_CLAIM,
                service_claim_document_id(self._target),
            )
            current = await self._transaction_read(
                transaction,
                reference=reference,
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=logical_id,
                document_id=document.document_id,
                model_type=ServiceClaimRecord,
            )
            if current is None or current.stored != expected:
                raise _ExpectedStateMismatch
            transaction.update(reference, _document_data(document.wrapper))

        await self._run_transaction(documents, update)
        return _stored(document)

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        logical_id = execution_receipt_logical_id(self._target, idempotency_key)
        decoded = await self._strong_read(
            kind=AuthorityStorageKind.EXECUTION_RECEIPT,
            logical_id=logical_id,
            document_id=execution_receipt_document_id(self._target, idempotency_key),
            model_type=ExecutionReceipt,
        )
        if decoded is not None:
            try:
                _validate_receipt_identity(self._target, decoded.value)
            except (TypeError, ValueError):
                raise AuthorityStoreCorruptRecord from None
        return None if decoded is None else decoded.stored

    async def claim_receipt(
        self,
        receipt: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        if type(receipt) is not ExecutionReceipt:
            raise TypeError("receipt claim requires an exact receipt")
        logical_id = _validate_receipt_identity(self._target, receipt)
        if receipt.outcome is not ReceiptOutcome.CLAIMED:
            raise ValueError("receipt claim is not in the claim phase")
        document = _prepared_document(
            kind=AuthorityStorageKind.EXECUTION_RECEIPT,
            logical_id=logical_id,
            document_id=execution_receipt_document_id(
                self._target,
                receipt.idempotency_key,
            ),
            revision=0,
            value=receipt,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (document,)

        async def create(transaction: _TransactionPort) -> None:
            client = await self._client()
            reference = self._reference(
                client,
                AuthorityStorageKind.EXECUTION_RECEIPT,
                execution_receipt_document_id(
                    self._target,
                    receipt.idempotency_key,
                ),
            )
            transaction.create(reference, _document_data(document.wrapper))

        await self._run_transaction(documents, create)
        return _stored(document)

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        _validate_receipt_replacement(self._target, expected, replacement)
        logical_id = execution_receipt_logical_id(
            self._target,
            replacement.idempotency_key,
        )
        document = _prepared_document(
            kind=AuthorityStorageKind.EXECUTION_RECEIPT,
            logical_id=logical_id,
            document_id=execution_receipt_document_id(
                self._target,
                replacement.idempotency_key,
            ),
            revision=expected.revision + 1,
            value=replacement,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (document,)

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            reference = self._reference(
                client,
                AuthorityStorageKind.EXECUTION_RECEIPT,
                execution_receipt_document_id(
                    self._target,
                    replacement.idempotency_key,
                ),
            )
            current = await self._transaction_read(
                transaction,
                reference=reference,
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=logical_id,
                document_id=document.document_id,
                model_type=ExecutionReceipt,
            )
            if current is None or current.stored != expected:
                raise _ExpectedStateMismatch
            transaction.update(reference, _document_data(document.wrapper))

        await self._run_transaction(documents, update)
        return _stored(document)


def _stored[ModelT: StrictContractModel](
    document: _PreparedDocument[ModelT],
) -> StoredRecord[ModelT]:
    return StoredRecord(value=document.value, revision=document.wrapper.revision)


__all__ = [
    "FIRESTORE_AUTHORITY_DATABASE",
    "FIRESTORE_AUTHORITY_REGION",
    "FIRESTORE_MAX_TRANSACTION_ATTEMPTS",
    "FIRESTORE_OPERATION_TIMEOUT_SECONDS",
    "AsyncFirestoreAuthorityClientPort",
    "FirestoreAuthorityClientFactory",
    "FirestoreAuthorityStore",
    "FirestoreTransactionRunner",
]
