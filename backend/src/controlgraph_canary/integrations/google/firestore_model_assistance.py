"""Small immutable Firestore store for advisor replay and disposition audit."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal, Protocol, cast

from google.cloud import firestore_v1

from controlgraph_canary.application.model_assistance import (
    AdvisorAuditWriteResult,
    AdvisorDispositionWriteResult,
)
from controlgraph_canary.contracts.base import Identifier, StrictContractModel
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.model_assistance import (
    ADVISOR_DISPOSITION_RESULT_V1,
    AdvisorDispositionCommandV1,
    AdvisorDispositionResultV1,
    AdvisorOperatorResultV1,
)
from controlgraph_canary.contracts.models import TargetBinding

_DATABASE = "controlgraph-authority"
_COLLECTION = "model-assistance-audit"
_TIMEOUT_SECONDS = 5.0
_MAX_TRANSACTION_ATTEMPTS = 3
_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")


class _StoredResponseV1(StrictContractModel):
    schema_version: Literal["controlgraph.model-assistance-response-storage/v1"]
    idempotency_key: Identifier
    result: AdvisorOperatorResultV1


class _StoredDispositionV1(StrictContractModel):
    schema_version: Literal["controlgraph.model-assistance-disposition-storage/v1"]
    command: AdvisorDispositionCommandV1
    result: AdvisorDispositionResultV1


class _AuditDocumentV1(StrictContractModel):
    schema_version: Literal["controlgraph.model-assistance-audit-document/v1"]
    record_kind: Literal["RESPONSE_KEY", "RESPONSE_INTERACTION", "DISPOSITION"]
    logical_id: Identifier
    target: TargetBinding
    canonical_payload: str
    payload_sha256: str


class _DocumentReference(Protocol):
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

    async def create(
        self,
        document_data: dict[str, Any],
        retry: object | None = None,
        timeout: float | None = None,
    ) -> object: ...


class _Snapshot(Protocol):
    exists: bool

    def to_dict(self) -> dict[str, Any] | None: ...


class _Transaction(Protocol):
    def create(
        self,
        reference: _DocumentReference,
        document_data: dict[str, Any],
    ) -> None: ...


class _Client(Protocol):
    project: str
    _database: str

    @property
    def _database_string(self) -> str: ...

    def document(self, *document_path: str) -> _DocumentReference: ...

    def transaction(
        self,
        max_attempts: int = ...,
        read_only: bool = ...,
    ) -> object: ...


class FirestoreModelAssistanceAuditStore:
    """Persist one immutable response and one compare-and-set disposition."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        configured_project_id: str,
        client_factory: Callable[[], _Client] | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or type(configured_project_id) is not str
            or _PROJECT_ID.fullmatch(configured_project_id) is None
            or target.project_id != configured_project_id
            or target.region != "us-central1"
            or (client_factory is not None and not callable(client_factory))
        ):
            raise ValueError("Firestore model-assistance configuration is invalid")
        if client_factory is None and "FIRESTORE_EMULATOR_HOST" in os.environ:
            raise ValueError("production Firestore construction rejects the emulator host")
        self._target = target
        self._project_id = configured_project_id
        self._client_factory = client_factory or cast(
            Callable[[], _Client],
            lambda: firestore_v1.AsyncClient(
                project=configured_project_id,
                database=_DATABASE,
            ),
        )
        self._client_instance: _Client | None = None
        self._client_lock = asyncio.Lock()

    async def read_response(self, idempotency_key: str) -> AdvisorOperatorResultV1 | None:
        stored = await self._read_response("RESPONSE_KEY", idempotency_key)
        if stored is None:
            return None
        if stored.idempotency_key != idempotency_key:
            raise RuntimeError("model-assistance audit record is corrupt")
        return stored.result

    async def write_response_if_absent(
        self,
        idempotency_key: str,
        result: AdvisorOperatorResultV1,
    ) -> AdvisorAuditWriteResult:
        candidate = _StoredResponseV1(
            schema_version="controlgraph.model-assistance-response-storage/v1",
            idempotency_key=idempotency_key,
            result=result,
        )
        if result.target != self._target or result.replayed:
            raise ValueError("model-assistance response is outside its store")
        current = await self.read_response(idempotency_key)
        if current is not None:
            return self._adopt_response(current, result)

        interaction = await self._read_response(
            "RESPONSE_INTERACTION",
            result.interaction_id,
        )
        if interaction is not None:
            raise RuntimeError("model-assistance interaction already exists")
        key_document = _document(
            "RESPONSE_KEY",
            idempotency_key,
            self._target,
            candidate,
        )
        interaction_document = _document(
            "RESPONSE_INTERACTION",
            result.interaction_id,
            self._target,
            candidate,
        )
        try:
            await self._create_pair(key_document, interaction_document)
        except asyncio.CancelledError:
            raise
        except Exception:
            current = await self.read_response(idempotency_key)
            interaction = await self._read_response(
                "RESPONSE_INTERACTION",
                result.interaction_id,
            )
            if current is None or interaction is None or current != interaction.result:
                raise RuntimeError("model-assistance audit write failed") from None
            return self._adopt_response(current, result)
        return AdvisorAuditWriteResult(result=result, created=True)

    async def write_disposition(
        self,
        command: AdvisorDispositionCommandV1,
    ) -> AdvisorDispositionWriteResult:
        if type(command) is not AdvisorDispositionCommandV1 or command.target != self._target:
            raise ValueError("model-assistance disposition is outside its store")
        interaction = await self._read_response(
            "RESPONSE_INTERACTION",
            command.interaction_id,
        )
        if interaction is None or not _command_matches_response(command, interaction.result):
            raise RuntimeError("model-assistance response binding is invalid")
        response = interaction.result
        candidate = AdvisorDispositionResultV1(
            schema_version=ADVISOR_DISPOSITION_RESULT_V1,
            command_sha256=canonical_sha256(command),
            interaction_id=command.interaction_id,
            response_sha256=canonical_sha256(response.response),
            disposition=command.disposition,
            replayed=False,
        )
        stored = _StoredDispositionV1(
            schema_version="controlgraph.model-assistance-disposition-storage/v1",
            command=command,
            result=candidate,
        )
        document = _document(
            "DISPOSITION",
            command.interaction_id,
            self._target,
            stored,
        )
        previous = await self._read_disposition(command.interaction_id)
        if previous is not None:
            return _adopt_disposition(previous, stored, response)
        try:
            reference = await self._reference(document)
            await reference.create(
                document.model_dump(mode="json"),
                timeout=_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            previous = await self._read_disposition(command.interaction_id)
            if previous is None:
                raise RuntimeError("model-assistance disposition write failed") from None
            return _adopt_disposition(previous, stored, response)
        return AdvisorDispositionWriteResult(
            interaction=response,
            result=candidate,
            created=True,
        )

    async def _client(self) -> _Client:
        async with self._client_lock:
            if self._client_instance is None:
                client = self._client_factory()
                if (
                    client.project != self._project_id
                    or client._database != _DATABASE
                    or client._database_string
                    != f"projects/{self._project_id}/databases/{_DATABASE}"
                ):
                    raise RuntimeError("model-assistance Firestore client is invalid")
                self._client_instance = client
            return self._client_instance

    async def _reference(self, document: _AuditDocumentV1) -> _DocumentReference:
        client = await self._client()
        document_id = _document_id(document.record_kind, document.logical_id, self._target)
        reference = client.document(_COLLECTION, document_id)
        if reference.path != f"{_COLLECTION}/{document_id}":
            raise RuntimeError("model-assistance Firestore reference is invalid")
        return reference

    async def _read_response(
        self,
        kind: Literal["RESPONSE_KEY", "RESPONSE_INTERACTION"],
        binding: str,
    ) -> _StoredResponseV1 | None:
        document = _empty_document(kind, binding, self._target)
        payload = await self._read(document)
        if payload is None:
            return None
        return decode_contract(payload, _StoredResponseV1)

    async def _read_disposition(self, interaction_id: str) -> _StoredDispositionV1 | None:
        document = _empty_document("DISPOSITION", interaction_id, self._target)
        payload = await self._read(document)
        if payload is None:
            return None
        return decode_contract(payload, _StoredDispositionV1)

    async def _read(self, expected: _AuditDocumentV1) -> bytes | None:
        try:
            reference = await self._reference(expected)
            snapshot = cast(_Snapshot, await reference.get(timeout=_TIMEOUT_SECONDS))
            if not snapshot.exists:
                return None
            raw = snapshot.to_dict()
            document = _AuditDocumentV1.model_validate(raw)
            if (
                document.record_kind != expected.record_kind
                or document.logical_id != expected.logical_id
                or document.target != self._target
            ):
                raise RuntimeError
            payload = document.canonical_payload.encode("utf-8")
            if hashlib.sha256(payload).hexdigest() != document.payload_sha256:
                raise RuntimeError
            return payload
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RuntimeError("model-assistance audit read failed") from None

    async def _create_pair(
        self,
        first: _AuditDocumentV1,
        second: _AuditDocumentV1,
    ) -> None:
        client = await self._client()
        first_reference = await self._reference(first)
        second_reference = await self._reference(second)
        transaction = cast(
            firestore_v1.AsyncTransaction,
            client.transaction(max_attempts=_MAX_TRANSACTION_ATTEMPTS, read_only=False),
        )

        async def create(value: firestore_v1.AsyncTransaction) -> None:
            selected = cast(_Transaction, value)
            selected.create(first_reference, first.model_dump(mode="json"))
            selected.create(second_reference, second.model_dump(mode="json"))

        async with asyncio.timeout(_TIMEOUT_SECONDS):
            await firestore_v1.async_transactional(create)(transaction)

    @staticmethod
    def _adopt_response(
        current: AdvisorOperatorResultV1,
        candidate: AdvisorOperatorResultV1,
    ) -> AdvisorAuditWriteResult:
        if current != candidate:
            raise RuntimeError("model-assistance idempotency conflict")
        return AdvisorAuditWriteResult(result=current, created=False)


def _empty_document(
    kind: Literal["RESPONSE_KEY", "RESPONSE_INTERACTION", "DISPOSITION"],
    binding: str,
    target: TargetBinding,
) -> _AuditDocumentV1:
    return _AuditDocumentV1(
        schema_version="controlgraph.model-assistance-audit-document/v1",
        record_kind=kind,
        logical_id=_logical_id(kind, binding, target),
        target=target,
        canonical_payload="",
        payload_sha256=hashlib.sha256(b"").hexdigest(),
    )


def _document(
    kind: Literal["RESPONSE_KEY", "RESPONSE_INTERACTION", "DISPOSITION"],
    binding: str,
    target: TargetBinding,
    payload: StrictContractModel,
) -> _AuditDocumentV1:
    canonical = canonical_json_bytes(payload)
    return _AuditDocumentV1(
        schema_version="controlgraph.model-assistance-audit-document/v1",
        record_kind=kind,
        logical_id=_logical_id(kind, binding, target),
        target=target,
        canonical_payload=canonical.decode("utf-8"),
        payload_sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _logical_id(kind: str, binding: str, target: TargetBinding) -> str:
    digest = hashlib.sha256(
        b"controlgraph.model-assistance-logical-id/v1\0"
        + kind.encode("ascii")
        + b"\0"
        + canonical_json_bytes(target)
        + b"\0"
        + binding.encode("utf-8")
    ).hexdigest()
    return f"cgaudit:{digest}"


def _document_id(kind: str, logical_id: str, target: TargetBinding) -> str:
    return hashlib.sha256(
        b"controlgraph.model-assistance-document-id/v1\0"
        + kind.encode("ascii")
        + b"\0"
        + logical_id.encode("ascii")
        + b"\0"
        + canonical_json_bytes(target)
    ).hexdigest()


def _command_matches_response(
    command: AdvisorDispositionCommandV1,
    response: AdvisorOperatorResultV1,
) -> bool:
    return (
        response.interaction_id == command.interaction_id
        and response.target == command.target
        and response.root_id == command.root_id
        and response.root_sha256 == command.expected_root_sha256
        and response.epoch == command.expected_epoch
        and canonical_sha256(response.response) == command.expected_response_sha256
    )


def _adopt_disposition(
    previous: _StoredDispositionV1,
    candidate: _StoredDispositionV1,
    interaction: AdvisorOperatorResultV1,
) -> AdvisorDispositionWriteResult:
    if previous != candidate:
        raise RuntimeError("model-assistance disposition conflict")
    return AdvisorDispositionWriteResult(
        interaction=interaction,
        result=previous.result.model_copy(update={"replayed": True}),
        created=False,
    )


__all__ = ["FirestoreModelAssistanceAuditStore"]
