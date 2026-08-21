"""Role-sealed Firestore persistence for normalized signed health chains."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, ClassVar, Self, cast
from uuid import uuid4

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    StoredRecord,
)
from controlgraph_canary.application.health_store import (
    HealthAnchorWriteResult,
    HealthChainAppendResult,
    HealthChainSnapshot,
    HealthChainWriteDisposition,
)
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.application.recovery_store import (
    DirectRecoveryEnqueueStart,
    RecoveryEnqueuePermit,
)
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.health_execution import (
    PostApplyHealthAnchorV1,
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    create_signed_health_decision_chain,
)
from controlgraph_canary.contracts.health_storage import (
    HEALTH_STORAGE_DOCUMENT_V1,
    HealthChainManifestV1,
    HealthStorageDocumentV1,
    HealthStorageKind,
    RecoveryDispatchStorageRecordV2,
    create_health_chain_manifest,
    create_recovery_dispatch_storage_record,
    health_anchor_document_id,
    health_chain_head_document_id,
    health_chain_manifest_document_id,
    recovery_dispatch_document_id,
    recovery_dispatch_identity_document_id,
    recovery_dispatch_identity_logical_id,
    recovery_dispatch_storage_record_value,
    recovery_intent_document_id,
    signed_health_proof_document_id,
    signed_health_proof_logical_id,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.promotion_execution import (
    PromotionHealthChainLocatorV1,
)
from controlgraph_canary.contracts.recovery_execution import (
    RECOVERY_DISPATCH_IDENTITY_V2,
    RecoveryCommandV2,
    RecoveryDispatchIdentityKind,
    RecoveryDispatchIdentityV2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchState,
    RecoveryHealthChainLocatorV1,
    RecoveryIntentV1,
    RevokedV2RecoverySourceV1,
    recovery_command_sha256,
    recovery_dispatch_id,
    recovery_intent_id,
)
from controlgraph_canary.integrations.google.firestore import (
    FIRESTORE_AUTHORITY_DATABASE,
    FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
    FIRESTORE_OPERATION_TIMEOUT_SECONDS,
    AsyncFirestoreAuthorityClientPort,
    FirestoreAuthorityClientFactory,
    FirestoreTransactionRunner,
    _await_shielded,
    _aware_utc,
    _consume_background_result,
    _default_client_factory,
    _default_transaction_runner,
    _DocumentReferencePort,
    _expected_database_resource,
    _is_contention,
    _ProviderSnapshotPort,
    _reject_emulator_host,
    _require_emulator_host,
    _TransactionPort,
    _validate_project_binding,
)

_DOCUMENT_FIELDS = frozenset(HealthStorageDocumentV1.model_fields)


class _ExpectedStateMismatch(RuntimeError):
    pass


class _ExactDuplicate(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _PreparedDocument[ModelT: StrictContractModel]:
    wrapper: HealthStorageDocumentV1
    value: ModelT
    document_id: str


@dataclass(frozen=True, slots=True)
class _DecodedDocument[ModelT: StrictContractModel]:
    wrapper: HealthStorageDocumentV1
    value: ModelT

    @property
    def stored(self) -> StoredRecord[ModelT]:
        return StoredRecord(self.value, self.wrapper.revision)


def _document_path(kind: HealthStorageKind, document_id: str) -> str:
    return f"{kind.value}/{document_id}"


def _prepared_document[ModelT: StrictContractModel](
    *,
    kind: HealthStorageKind,
    logical_id: str,
    document_id: str,
    revision: int,
    value: ModelT,
) -> _PreparedDocument[ModelT]:
    payload = canonical_json_bytes(value).decode("utf-8")
    wrapper = HealthStorageDocumentV1(
        schema_version=HEALTH_STORAGE_DOCUMENT_V1,
        record_kind=kind,
        target=_payload_target(value),
        logical_id=logical_id,
        revision=revision,
        mutation_id=f"health-write-{uuid4().hex}",
        canonical_payload=payload,
        payload_sha256=canonical_sha256(value),
    )
    if type(document_id) is not str or len(document_id) != 64:
        raise ValueError("health storage document identity is invalid")
    return _PreparedDocument(wrapper, value, document_id)


def _payload_target(value: StrictContractModel) -> TargetBinding:
    if type(value) is PostApplyHealthAnchorV1:
        return value.target
    if type(value) is SignedHealthDecisionProofV1:
        return value.proof.decision.target
    if type(value) is HealthChainManifestV1:
        return value.target
    if type(value) is RecoveryIntentV1:
        return value.command.source.target
    if type(value) is RecoveryDispatchIdentityV2:
        return value.target
    if type(value) is RecoveryDispatchStorageRecordV2:
        return value.target
    raise TypeError("health storage payload type is unsupported")


def _document_data(document: HealthStorageDocumentV1) -> dict[str, Any]:
    data = document.model_dump(mode="json")
    if set(data) != _DOCUMENT_FIELDS:
        raise AuthorityStoreCorruptRecord
    return data


def _matches_prepared_content(
    decoded: _DecodedDocument[StrictContractModel] | None,
    expected: _PreparedDocument[StrictContractModel],
) -> bool:
    if decoded is None:
        return False
    wrapper = decoded.wrapper
    prepared = expected.wrapper
    return (
        wrapper.record_kind is prepared.record_kind
        and wrapper.target == prepared.target
        and wrapper.logical_id == prepared.logical_id
        and wrapper.revision == prepared.revision
        and wrapper.canonical_payload == prepared.canonical_payload
        and wrapper.payload_sha256 == prepared.payload_sha256
        and decoded.value == expected.value
    )


def _stored[ModelT: StrictContractModel](
    document: _PreparedDocument[ModelT],
) -> StoredRecord[ModelT]:
    return StoredRecord(document.value, document.wrapper.revision)


def _recovery_dispatch_identity(
    record: RecoveryDispatchRecordV2,
    kind: RecoveryDispatchIdentityKind,
) -> RecoveryDispatchIdentityV2:
    identity_value = (
        record.request_id
        if kind is RecoveryDispatchIdentityKind.REQUEST
        else record.idempotency_key
    )
    return RecoveryDispatchIdentityV2(
        schema_version=RECOVERY_DISPATCH_IDENTITY_V2,
        identity_kind=kind,
        identity_value=identity_value,
        target=record.target,
        dispatch_id=record.dispatch_id,
        command_sha256=record.command_sha256,
        recovery_authorization_sha256=record.recovery_authorization_sha256,
        capability_id=record.capability_id,
        root_id=record.root_id,
        root_sha256=record.root_sha256,
        epoch=record.epoch,
        scheduled_at=record.scheduled_at,
        source_receipt_sha256=record.source_receipt_sha256,
        trigger_proof_sha256=record.trigger_proof_sha256,
        prestate_attestation_sha256=record.prestate_attestation_sha256,
        claimed_at=record.prepared_at,
    )


def _recovery_transition_is_exact(
    expected: StoredRecord[RecoveryDispatchRecordV2],
    replacement: RecoveryDispatchRecordV2,
) -> bool:
    if (
        type(expected) is not StoredRecord
        or type(expected.value) is not RecoveryDispatchRecordV2
        or type(replacement) is not RecoveryDispatchRecordV2
    ):
        return False
    current = expected.value
    current_projection = current.model_dump(
        mode="python",
        exclude={"state", "enqueue_started_at", "terminal_at", "result"},
    )
    replacement_projection = replacement.model_dump(
        mode="python",
        exclude={"state", "enqueue_started_at", "terminal_at", "result"},
    )
    if current_projection != replacement_projection:
        return False
    if current.state is RecoveryDispatchState.PREPARED:
        return (
            expected.revision == 0
            and replacement.state is RecoveryDispatchState.ENQUEUE_STARTED
            and replacement.enqueue_started_at is not None
            and replacement.terminal_at is None
            and replacement.result is None
        )
    if current.state is RecoveryDispatchState.ENQUEUE_STARTED:
        return (
            expected.revision == 1
            and replacement.state
            in {
                RecoveryDispatchState.CREATED,
                RecoveryDispatchState.DUPLICATE,
                RecoveryDispatchState.AMBIGUOUS,
            }
            and replacement.enqueue_started_at == current.enqueue_started_at
            and replacement.terminal_at is not None
            and replacement.result is not None
        )
    return False


class FirestoreHealthChainReader:
    """Strong normalized reads sealed to coordinator or issuer identity."""

    _ADMITTED_ROLES: ClassVar[frozenset[ServiceRole]] = frozenset(
        {ServiceRole.COORDINATOR, ServiceRole.ISSUER}
    )

    def __init__(
        self,
        *,
        target: TargetBinding,
        configured_project_id: str,
        service_role: ServiceRole,
    ) -> None:
        _reject_emulator_host()
        self._initialize(
            target=target,
            configured_project_id=configured_project_id,
            service_role=service_role,
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
        service_role: ServiceRole,
    ) -> Self:
        _require_emulator_host()
        return cls._from_components(
            target=target,
            configured_project_id=configured_project_id,
            service_role=service_role,
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
        service_role: ServiceRole,
        client_factory: FirestoreAuthorityClientFactory,
        transaction_runner: FirestoreTransactionRunner | None = None,
    ) -> Self:
        return cls._from_components(
            target=target,
            configured_project_id=configured_project_id,
            service_role=service_role,
            client_factory=client_factory,
            transaction_runner=(
                _default_transaction_runner
                if transaction_runner is None
                else transaction_runner
            ),
        )

    @classmethod
    def _from_components(
        cls,
        *,
        target: TargetBinding,
        configured_project_id: str,
        service_role: ServiceRole,
        client_factory: FirestoreAuthorityClientFactory,
        transaction_runner: FirestoreTransactionRunner,
    ) -> Self:
        instance = cls.__new__(cls)
        instance._initialize(
            target=target,
            configured_project_id=configured_project_id,
            service_role=service_role,
            client_factory=client_factory,
            transaction_runner=transaction_runner,
        )
        return instance

    def _initialize(
        self,
        *,
        target: TargetBinding,
        configured_project_id: str,
        service_role: ServiceRole,
        client_factory: FirestoreAuthorityClientFactory,
        transaction_runner: FirestoreTransactionRunner,
    ) -> None:
        _validate_project_binding(target, configured_project_id)
        if type(service_role) is not ServiceRole or service_role not in self._ADMITTED_ROLES:
            raise ValueError("health-chain persistence role is not admitted")
        if not callable(client_factory) or not callable(transaction_runner):
            raise TypeError("health-chain Firestore components must be callable")
        self._target = target
        self._configured_project_id = configured_project_id
        self._service_role = service_role
        self._client_factory = client_factory
        self._transaction_runner = transaction_runner
        self._client_instance: AsyncFirestoreAuthorityClientPort | None = None
        self._client_lock = asyncio.Lock()

    @property
    def target(self) -> TargetBinding:
        return self._target

    @property
    def service_role(self) -> ServiceRole:
        return self._service_role

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
                    project = client.project
                    database = client._database
                    database_resource = client._database_string
                except Exception:
                    raise AuthorityStoreUnavailable from None
                if (
                    any(
                        not callable(getattr(client, name, None))
                        for name in ("document", "get_all", "transaction")
                    )
                    or project != self._configured_project_id
                    or database != FIRESTORE_AUTHORITY_DATABASE
                    or database_resource
                    != _expected_database_resource(self._configured_project_id)
                ):
                    raise AuthorityStoreUnavailable
                self._client_instance = client
            return self._client_instance

    @staticmethod
    def _reference(
        client: AsyncFirestoreAuthorityClientPort,
        kind: HealthStorageKind,
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
        kind: HealthStorageKind,
        logical_id: str,
        document_id: str,
        model_type: type[ModelT],
    ) -> _DecodedDocument[ModelT] | None:
        try:
            provider_snapshot = cast(_ProviderSnapshotPort, snapshot)
            if provider_snapshot.reference.path != reference.path:
                raise ValueError("health snapshot reference does not match")
            exists = provider_snapshot.exists
            if type(exists) is not bool:
                raise ValueError("health snapshot existence flag is invalid")
            _aware_utc(provider_snapshot.read_time)
            data = provider_snapshot.to_dict()
            update_time = provider_snapshot.update_time
            if not exists:
                if data is not None or update_time is not None:
                    raise ValueError("missing health snapshot contains state")
                return None
            _aware_utc(update_time)
            if type(data) is not dict or set(data) != _DOCUMENT_FIELDS:
                raise ValueError("health storage wrapper is not exact")
            if data.get("record_kind") != kind.value:
                raise ValueError("health storage wrapper kind does not match")
            normalized = dict(data)
            normalized["record_kind"] = kind
            wrapper = HealthStorageDocumentV1.model_validate(normalized)
            if wrapper.record_kind is not kind:
                raise ValueError("health storage wrapper kind does not match")
            if (
                wrapper.logical_id != logical_id
                or reference.path != _document_path(kind, document_id)
            ):
                raise ValueError("health storage wrapper identity does not match")
            value = decode_contract(wrapper.canonical_payload, model_type)
            if canonical_sha256(value) != wrapper.payload_sha256:
                raise ValueError("health storage payload digest does not match")
            return _DecodedDocument(wrapper, value)
        except (AuthorityStoreCorruptRecord, asyncio.CancelledError):
            raise
        except Exception:
            raise AuthorityStoreCorruptRecord from None

    async def _transaction_read[ModelT: StrictContractModel](
        self,
        transaction: _TransactionPort,
        *,
        kind: HealthStorageKind,
        logical_id: str,
        document_id: str,
        model_type: type[ModelT],
    ) -> _DecodedDocument[ModelT] | None:
        client = await self._client()
        reference = self._reference(client, kind, document_id)
        snapshot = await self._get_snapshot(reference, transaction=transaction)
        decoded = self._decode_snapshot(
            snapshot,
            reference=reference,
            kind=kind,
            logical_id=logical_id,
            document_id=document_id,
            model_type=model_type,
        )
        if decoded is not None and decoded.wrapper.target != self._target:
            raise AuthorityStoreCorruptRecord
        return decoded

    async def _strong_read[ModelT: StrictContractModel](
        self,
        *,
        kind: HealthStorageKind,
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
        except (AuthorityStoreConflict, AuthorityStoreCorruptRecord):
            raise
        except Exception:
            raise AuthorityStoreUnavailable from None
        decoded = self._decode_snapshot(
            snapshot,
            reference=reference,
            kind=kind,
            logical_id=logical_id,
            document_id=document_id,
            model_type=model_type,
        )
        if decoded is not None and decoded.wrapper.target != self._target:
            raise AuthorityStoreCorruptRecord
        return decoded

    async def _run_consistent_read(self, body: Any) -> None:
        client = await self._client()
        try:
            async with asyncio.timeout(FIRESTORE_OPERATION_TIMEOUT_SECONDS):
                await self._transaction_runner(
                    client,
                    FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
                    0,
                    body,
                )
        except asyncio.CancelledError:
            raise
        except (AuthorityStoreConflict, AuthorityStoreCorruptRecord):
            raise
        except Exception:
            raise AuthorityStoreUnavailable from None

    async def _reconstruct(
        self,
        transaction: _TransactionPort,
        anchor: _DecodedDocument[PostApplyHealthAnchorV1],
        manifest: _DecodedDocument[HealthChainManifestV1],
    ) -> HealthChainSnapshot:
        value = manifest.value
        if (
            value.target != self._target
            or value.anchor_id != anchor.value.anchor_id
            or value.anchor_sha256 != canonical_sha256(anchor.value)
            or value.root_id != anchor.value.root_id
            or value.root_sha256 != anchor.value.root_sha256
            or value.epoch != anchor.value.epoch
        ):
            raise AuthorityStoreCorruptRecord
        proof_records: list[StoredRecord[SignedHealthDecisionProofV1]] = []
        for proof_reference in value.proof_documents:
            decoded = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF,
                logical_id=signed_health_proof_logical_id(
                    proof_reference.signed_proof_sha256
                ),
                document_id=proof_reference.document_id,
                model_type=SignedHealthDecisionProofV1,
            )
            if decoded is None:
                raise AuthorityStoreCorruptRecord
            proof = decoded.value
            if (
                decoded.wrapper.revision != 0
                or canonical_sha256(proof) != proof_reference.signed_proof_sha256
                or proof.proof.proof_id != proof_reference.proof_id
                or proof.proof.sequence != proof_reference.sequence
                or proof.proof.decision_sha256 != proof_reference.decision_sha256
                or proof.proof.anchor_id != value.anchor_id
                or proof.proof.anchor_sha256 != value.anchor_sha256
            ):
                raise AuthorityStoreCorruptRecord
            proof_records.append(decoded.stored)
        try:
            chain = create_signed_health_decision_chain(
                anchor=anchor.value,
                signed_proofs=tuple(record.value for record in proof_records),
            )
            expected_manifest = create_health_chain_manifest(chain)
        except (TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None
        if expected_manifest != value:
            raise AuthorityStoreCorruptRecord
        recovery_intent: _DecodedDocument[RecoveryIntentV1] | None = None
        if value.terminal_status.value == "unhealthy":
            recovery_intent = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_INTENT,
                logical_id=recovery_intent_id(value.root_sha256),
                document_id=recovery_intent_document_id(
                    self._target,
                    value.root_sha256,
                ),
                model_type=RecoveryIntentV1,
            )
            if recovery_intent is None:
                raise AuthorityStoreCorruptRecord
        try:
            return HealthChainSnapshot(
                anchor=anchor.stored,
                manifest=manifest.stored,
                signed_proofs=tuple(proof_records),
                signed_chain=chain,
                recovery_intent=(
                    recovery_intent.stored
                    if recovery_intent is not None
                    else None
                ),
            )
        except (TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None

    async def read_health_chain(
        self,
        anchor_id: str,
    ) -> HealthChainSnapshot | None:
        """Read one current chain by its exact target-scoped anchor identity."""

        anchor_document_id = health_anchor_document_id(self._target, anchor_id)
        head_document_id = health_chain_head_document_id(self._target, anchor_id)
        result: HealthChainSnapshot | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal result
            anchor = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.POST_APPLY_HEALTH_ANCHOR,
                logical_id=anchor_id,
                document_id=anchor_document_id,
                model_type=PostApplyHealthAnchorV1,
            )
            head = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.HEALTH_CHAIN_HEAD,
                logical_id=anchor_id,
                document_id=head_document_id,
                model_type=HealthChainManifestV1,
            )
            if anchor is None:
                if head is not None:
                    raise AuthorityStoreCorruptRecord
                result = None
                return
            if head is None:
                result = HealthChainSnapshot(anchor.stored, None, (), None)
                return
            manifest_document_id = health_chain_manifest_document_id(
                self._target,
                head.value.manifest_sha256,
            )
            immutable = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.HEALTH_CHAIN_MANIFEST,
                logical_id=head.value.chain_id,
                document_id=manifest_document_id,
                model_type=HealthChainManifestV1,
            )
            if immutable is None or immutable.stored != head.stored:
                raise AuthorityStoreCorruptRecord
            result = await self._reconstruct(transaction, anchor, head)

        await self._run_consistent_read(read)
        return result

    async def read_health_chain_by_manifest(
        self,
        manifest_sha256: str,
    ) -> HealthChainSnapshot | None:
        """Reconstruct one immutable historical chain by its helper manifest digest."""

        manifest_document_id = health_chain_manifest_document_id(
            self._target,
            manifest_sha256,
        )
        result: HealthChainSnapshot | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal result
            chain_id = f"cghealthchain:{manifest_sha256}"
            manifest = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.HEALTH_CHAIN_MANIFEST,
                logical_id=chain_id,
                document_id=manifest_document_id,
                model_type=HealthChainManifestV1,
            )
            if manifest is None:
                result = None
                return
            if (
                manifest.value.manifest_sha256 != manifest_sha256
                or manifest.value.chain_id != chain_id
            ):
                raise AuthorityStoreCorruptRecord
            anchor_document_id = health_anchor_document_id(
                self._target,
                manifest.value.anchor_id,
            )
            anchor = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.POST_APPLY_HEALTH_ANCHOR,
                logical_id=manifest.value.anchor_id,
                document_id=anchor_document_id,
                model_type=PostApplyHealthAnchorV1,
            )
            if anchor is None:
                raise AuthorityStoreCorruptRecord
            result = await self._reconstruct(transaction, anchor, manifest)

        await self._run_consistent_read(read)
        return result

    async def read_promotion_health_chain(
        self,
        locator: PromotionHealthChainLocatorV1,
    ) -> SignedHealthDecisionChainV1 | None:
        """Load a full chain only when every promotion locator field matches."""

        if type(locator) is not PromotionHealthChainLocatorV1:
            raise TypeError("promotion health-chain lookup requires an exact locator")
        snapshot = await self.read_health_chain_by_manifest(
            locator.health_chain_sha256
        )
        if snapshot is None:
            return None
        manifest = snapshot.manifest
        chain = snapshot.signed_chain
        if manifest is None or chain is None:
            raise AuthorityStoreCorruptRecord
        value = manifest.value
        if (
            value.anchor_id != locator.anchor_id
            or value.anchor_sha256 != locator.anchor_sha256
            or value.chain_id != locator.chain_id
            or value.manifest_sha256 != locator.health_chain_sha256
            or value.chain_head_sha256 != locator.chain_head_sha256
            or value.ordered_proof_chain_sha256
            != locator.ordered_proof_chain_sha256
            or value.terminal_sequence != locator.terminal_sequence
            or chain.healthy_promotion_proof is None
        ):
            raise AuthorityStoreCorruptRecord
        return chain

    async def read_recovery_intent(
        self,
        root_sha256: str,
    ) -> StoredRecord[RecoveryIntentV1] | None:
        """Strongly read the sole target- and root-scoped recovery intent."""

        logical_id = recovery_intent_id(root_sha256)
        decoded = await self._strong_read(
            kind=HealthStorageKind.RECOVERY_INTENT,
            logical_id=logical_id,
            document_id=recovery_intent_document_id(self._target, root_sha256),
            model_type=RecoveryIntentV1,
        )
        if decoded is None:
            return None
        if (
            decoded.wrapper.revision != 0
            or decoded.value.root_sha256 != root_sha256
            or decoded.value.intent_id != logical_id
        ):
            raise AuthorityStoreCorruptRecord
        return decoded.stored

    async def read_recovery_health_chain(
        self,
        locator: RecoveryHealthChainLocatorV1,
    ) -> SignedHealthDecisionChainV1 | None:
        """Load a full chain only through every terminal-unhealthy binding."""

        if type(locator) is not RecoveryHealthChainLocatorV1:
            raise TypeError("recovery health-chain lookup requires an exact locator")
        snapshot = await self.read_health_chain_by_manifest(
            locator.health_chain_sha256
        )
        if snapshot is None:
            return None
        manifest = snapshot.manifest
        chain = snapshot.signed_chain
        if manifest is None or chain is None:
            raise AuthorityStoreCorruptRecord
        value = manifest.value
        terminal = chain.signed_proofs[-1]
        if (
            value.root_id != locator.root_id
            or value.root_sha256 != locator.root_sha256
            or value.target != locator.target
            or value.epoch != locator.epoch
            or value.anchor_id != locator.anchor_id
            or value.anchor_sha256 != locator.anchor_sha256
            or value.chain_id != locator.chain_id
            or value.manifest_sha256 != locator.health_chain_sha256
            or value.chain_head_sha256 != locator.chain_head_sha256
            or value.ordered_proof_chain_sha256
            != locator.ordered_proof_chain_sha256
            or value.terminal_sequence != locator.terminal_sequence
            or value.terminal_status.value != "unhealthy"
            or canonical_sha256(terminal)
            != locator.terminal_signed_proof_sha256
            or terminal.proof.decision_sha256
            != locator.terminal_health_decision_sha256
            or chain.anchor.source_receipt_sha256
            != locator.source_receipt_sha256
            or chain.anchor.expected_prestate_sha256
            != locator.expected_prestate_sha256
            or terminal.proof.decision.evaluated_at != locator.terminal_decided_at
        ):
            raise AuthorityStoreCorruptRecord
        return chain


class FirestoreHealthChainStore(FirestoreHealthChainReader):
    """Coordinator-only immutable anchor writer and transactional CAS appender."""

    _ADMITTED_ROLES: ClassVar[frozenset[ServiceRole]] = frozenset(
        {ServiceRole.COORDINATOR}
    )

    async def _execute_write(self, expected_writes: int, body: Any) -> None:
        client = await self._client()
        async def execute() -> None:
            await self._transaction_runner(
                client,
                FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
                expected_writes,
                body,
            )

        operation: asyncio.Task[None] = asyncio.create_task(execute())
        try:
            await _await_shielded(
                operation,
                timeout_seconds=FIRESTORE_OPERATION_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            operation.add_done_callback(_consume_background_result)
            raise
        except TimeoutError:
            operation.add_done_callback(_consume_background_result)
            raise

    async def _resolve_anchor(
        self,
        anchor: PostApplyHealthAnchorV1,
    ) -> HealthChainSnapshot | None:
        try:
            snapshot = await self.read_health_chain(anchor.anchor_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AuthorityStoreOutcomeUnknown from None
        if snapshot is not None and snapshot.anchor.value == anchor:
            return snapshot
        return None

    async def create_or_adopt_health_anchor(
        self,
        anchor: PostApplyHealthAnchorV1,
    ) -> HealthAnchorWriteResult:
        """Create one immutable anchor or adopt only its exact durable value."""

        if type(anchor) is not PostApplyHealthAnchorV1:
            raise TypeError("health anchor persistence requires an exact anchor")
        validated = PostApplyHealthAnchorV1.model_validate(anchor)
        if validated.target != self._target:
            raise ValueError("health anchor does not match the configured target")
        document = _prepared_document(
            kind=HealthStorageKind.POST_APPLY_HEALTH_ANCHOR,
            logical_id=validated.anchor_id,
            document_id=health_anchor_document_id(
                self._target,
                validated.anchor_id,
            ),
            revision=0,
            value=validated,
        )

        async def create(transaction: _TransactionPort) -> None:
            current = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.POST_APPLY_HEALTH_ANCHOR,
                logical_id=validated.anchor_id,
                document_id=document.document_id,
                model_type=PostApplyHealthAnchorV1,
            )
            if current is not None:
                if current.stored == _stored(document):
                    raise _ExactDuplicate
                raise _ExpectedStateMismatch
            client = await self._client()
            transaction.create(
                self._reference(
                    client,
                    HealthStorageKind.POST_APPLY_HEALTH_ANCHOR,
                    document.document_id,
                ),
                _document_data(document.wrapper),
            )

        try:
            await self._execute_write(1, create)
        except asyncio.CancelledError:
            raise
        except _ExactDuplicate:
            adopted = await self._resolve_anchor(validated)
            if adopted is None:
                raise AuthorityStoreCorruptRecord from None
            return HealthAnchorWriteResult(
                HealthChainWriteDisposition.ADOPTED,
                adopted,
            )
        except _ExpectedStateMismatch:
            raise AuthorityStoreConflict from None
        except AuthorityStoreCorruptRecord:
            raise
        except Exception as error:
            adopted = await self._resolve_anchor(validated)
            if adopted is not None:
                return HealthAnchorWriteResult(
                    HealthChainWriteDisposition.ADOPTED,
                    adopted,
                )
            if _is_contention(error):
                raise AuthorityStoreConflict from None
            raise AuthorityStoreOutcomeUnknown from None
        return HealthAnchorWriteResult(
            HealthChainWriteDisposition.CREATED,
            HealthChainSnapshot(_stored(document), None, (), None),
        )

    async def _resolve_append(
        self,
        candidate: HealthChainSnapshot,
    ) -> HealthChainSnapshot:
        manifest = candidate.manifest
        if manifest is None:
            raise AuthorityStoreOutcomeUnknown
        try:
            immutable = await self.read_health_chain_by_manifest(
                manifest.value.manifest_sha256
            )
            current = await self.read_health_chain(candidate.anchor.value.anchor_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AuthorityStoreOutcomeUnknown from None
        if immutable == candidate and current == candidate:
            return candidate
        if (
            current is not None
            and current.manifest is not None
            and current.manifest.value.terminal_sequence
            >= manifest.value.terminal_sequence
        ):
            raise AuthorityStoreConflict
        raise AuthorityStoreOutcomeUnknown

    async def append_signed_health_proof(
        self,
        expected: HealthChainSnapshot,
        signed_proof: SignedHealthDecisionProofV1,
        recovery_intent: RecoveryIntentV1 | None = None,
    ) -> HealthChainAppendResult:
        """CAS-append one exact signed proof without serializing its aggregate chain."""

        if type(expected) is not HealthChainSnapshot:
            raise TypeError("health-chain append requires an exact expected snapshot")
        if type(signed_proof) is not SignedHealthDecisionProofV1:
            raise TypeError("health-chain append requires an exact signed proof")
        validated_proof = SignedHealthDecisionProofV1.model_validate(signed_proof)
        if expected.target != self._target:
            raise ValueError("expected health chain does not match the configured target")
        try:
            chain = create_signed_health_decision_chain(
                anchor=expected.anchor.value,
                signed_proofs=(
                    *(record.value for record in expected.signed_proofs),
                    validated_proof,
                ),
            )
            manifest = create_health_chain_manifest(chain)
        except (TypeError, ValueError):
            raise ValueError("signed proof is not the exact next chain element") from None
        is_unhealthy = manifest.terminal_status.value == "unhealthy"
        if is_unhealthy != (recovery_intent is not None):
            raise ValueError(
                "terminal unhealthy append requires exactly one recovery intent"
            )
        validated_intent = (
            RecoveryIntentV1.model_validate(recovery_intent)
            if recovery_intent is not None
            else None
        )
        signed_digest = canonical_sha256(validated_proof)
        proof_document = _prepared_document(
            kind=HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF,
            logical_id=signed_health_proof_logical_id(signed_digest),
            document_id=signed_health_proof_document_id(
                self._target,
                expected.anchor.value.anchor_id,
                signed_digest,
            ),
            revision=0,
            value=validated_proof,
        )
        head_document = _prepared_document(
            kind=HealthStorageKind.HEALTH_CHAIN_HEAD,
            logical_id=manifest.anchor_id,
            document_id=health_chain_head_document_id(
                self._target,
                manifest.anchor_id,
            ),
            revision=manifest.terminal_sequence,
            value=manifest,
        )
        manifest_document = _prepared_document(
            kind=HealthStorageKind.HEALTH_CHAIN_MANIFEST,
            logical_id=manifest.chain_id,
            document_id=health_chain_manifest_document_id(
                self._target,
                manifest.manifest_sha256,
            ),
            revision=manifest.terminal_sequence,
            value=manifest,
        )
        intent_document = (
            _prepared_document(
                kind=HealthStorageKind.RECOVERY_INTENT,
                logical_id=validated_intent.intent_id,
                document_id=recovery_intent_document_id(
                    self._target,
                    validated_intent.root_sha256,
                ),
                revision=0,
                value=validated_intent,
            )
            if validated_intent is not None
            else None
        )
        candidate = HealthChainSnapshot(
            anchor=expected.anchor,
            manifest=_stored(head_document),
            signed_proofs=(*expected.signed_proofs, _stored(proof_document)),
            signed_chain=chain,
            recovery_intent=(
                _stored(intent_document) if intent_document is not None else None
            ),
        )

        async def append(transaction: _TransactionPort) -> None:
            anchor_document_id = health_anchor_document_id(
                self._target,
                expected.anchor.value.anchor_id,
            )
            current_anchor = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.POST_APPLY_HEALTH_ANCHOR,
                logical_id=expected.anchor.value.anchor_id,
                document_id=anchor_document_id,
                model_type=PostApplyHealthAnchorV1,
            )
            current_head = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.HEALTH_CHAIN_HEAD,
                logical_id=manifest.anchor_id,
                document_id=head_document.document_id,
                model_type=HealthChainManifestV1,
            )
            current_proof = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF,
                logical_id=proof_document.wrapper.logical_id,
                document_id=proof_document.document_id,
                model_type=SignedHealthDecisionProofV1,
            )
            current_manifest = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.HEALTH_CHAIN_MANIFEST,
                logical_id=manifest.chain_id,
                document_id=manifest_document.document_id,
                model_type=HealthChainManifestV1,
            )
            current_intent = (
                await self._transaction_read(
                    transaction,
                    kind=HealthStorageKind.RECOVERY_INTENT,
                    logical_id=intent_document.wrapper.logical_id,
                    document_id=intent_document.document_id,
                    model_type=RecoveryIntentV1,
                )
                if intent_document is not None
                else None
            )
            if current_anchor is None or current_anchor.stored != expected.anchor:
                raise _ExpectedStateMismatch
            candidate_is_current = (
                current_head is not None
                and current_head.stored == candidate.manifest
            )
            proof_is_current = _matches_prepared_content(
                cast(_DecodedDocument[StrictContractModel] | None, current_proof),
                cast(_PreparedDocument[StrictContractModel], proof_document),
            )
            manifest_is_current = _matches_prepared_content(
                cast(_DecodedDocument[StrictContractModel] | None, current_manifest),
                cast(_PreparedDocument[StrictContractModel], manifest_document),
            )
            intent_is_current = (
                intent_document is None
                or _matches_prepared_content(
                    cast(
                        _DecodedDocument[StrictContractModel] | None,
                        current_intent,
                    ),
                    cast(_PreparedDocument[StrictContractModel], intent_document),
                )
            )
            if candidate_is_current:
                if proof_is_current and manifest_is_current and intent_is_current:
                    raise _ExactDuplicate
                raise AuthorityStoreCorruptRecord
            expected_is_current = (
                current_head is None
                if expected.manifest is None
                else current_head is not None
                and current_head.stored == expected.manifest
            )
            if not expected_is_current:
                raise _ExpectedStateMismatch
            if (
                current_proof is not None
                or current_manifest is not None
                or current_intent is not None
            ):
                raise AuthorityStoreCorruptRecord
            client = await self._client()
            transaction.create(
                self._reference(
                    client,
                    HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF,
                    proof_document.document_id,
                ),
                _document_data(proof_document.wrapper),
            )
            transaction.create(
                self._reference(
                    client,
                    HealthStorageKind.HEALTH_CHAIN_MANIFEST,
                    manifest_document.document_id,
                ),
                _document_data(manifest_document.wrapper),
            )
            if intent_document is not None:
                transaction.create(
                    self._reference(
                        client,
                        HealthStorageKind.RECOVERY_INTENT,
                        intent_document.document_id,
                    ),
                    _document_data(intent_document.wrapper),
                )
            head_reference = self._reference(
                client,
                HealthStorageKind.HEALTH_CHAIN_HEAD,
                head_document.document_id,
            )
            if current_head is None:
                transaction.create(
                    head_reference,
                    _document_data(head_document.wrapper),
                )
            else:
                transaction.update(
                    head_reference,
                    _document_data(head_document.wrapper),
                )

        try:
            await self._execute_write(4 if intent_document is not None else 3, append)
        except asyncio.CancelledError:
            raise
        except _ExactDuplicate:
            adopted = await self._resolve_append(candidate)
            return HealthChainAppendResult(
                HealthChainWriteDisposition.ADOPTED,
                adopted,
            )
        except _ExpectedStateMismatch:
            raise AuthorityStoreConflict from None
        except AuthorityStoreCorruptRecord:
            raise
        except Exception as error:
            try:
                adopted = await self._resolve_append(candidate)
            except AuthorityStoreConflict:
                raise
            except AuthorityStoreOutcomeUnknown:
                if _is_contention(error):
                    raise AuthorityStoreConflict from None
                raise
            return HealthChainAppendResult(
                HealthChainWriteDisposition.ADOPTED,
                adopted,
            )
        return HealthChainAppendResult(
            HealthChainWriteDisposition.CREATED,
            candidate,
        )

    async def create_or_adopt_recovery_intent(
        self,
        intent: RecoveryIntentV1,
    ) -> StoredRecord[RecoveryIntentV1]:
        """Reserve the sole root-level recovery command or adopt its exact value."""

        if type(intent) is not RecoveryIntentV1:
            raise TypeError("recovery intent persistence requires an exact intent")
        validated = RecoveryIntentV1.model_validate(intent)
        if (
            type(validated.command.source) is not RevokedV2RecoverySourceV1
            or validated.command.source.target != self._target
        ):
            raise ValueError("recovery intent does not match the configured target")
        document = _prepared_document(
            kind=HealthStorageKind.RECOVERY_INTENT,
            logical_id=validated.intent_id,
            document_id=recovery_intent_document_id(
                self._target,
                validated.root_sha256,
            ),
            revision=0,
            value=validated,
        )

        async def create(transaction: _TransactionPort) -> None:
            current = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_INTENT,
                logical_id=validated.intent_id,
                document_id=document.document_id,
                model_type=RecoveryIntentV1,
            )
            if current is not None:
                if current.stored == _stored(document):
                    raise _ExactDuplicate
                raise _ExpectedStateMismatch
            client = await self._client()
            transaction.create(
                self._reference(
                    client,
                    HealthStorageKind.RECOVERY_INTENT,
                    document.document_id,
                ),
                _document_data(document.wrapper),
            )

        try:
            await self._execute_write(1, create)
        except asyncio.CancelledError:
            raise
        except _ExactDuplicate:
            adopted = await self.read_recovery_intent(validated.root_sha256)
            if adopted != _stored(document):
                raise AuthorityStoreCorruptRecord from None
            return adopted
        except _ExpectedStateMismatch:
            raise AuthorityStoreConflict from None
        except AuthorityStoreCorruptRecord:
            raise
        except Exception as error:
            try:
                adopted = await self.read_recovery_intent(validated.root_sha256)
            except Exception:
                raise AuthorityStoreOutcomeUnknown from None
            if adopted == _stored(document):
                return adopted
            if adopted is not None or _is_contention(error):
                raise AuthorityStoreConflict from None
            raise AuthorityStoreOutcomeUnknown from None
        return _stored(document)

    async def read_recovery_dispatch(
        self,
        command: RecoveryCommandV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2] | None:
        """Read one dispatch only through both immutable request identities."""

        if type(command) is not RecoveryCommandV2:
            raise TypeError("recovery dispatch read requires an exact command")
        command_sha256 = recovery_command_sha256(command)
        dispatch_id = recovery_dispatch_id(command_sha256)
        request_logical_id = recovery_dispatch_identity_logical_id(
            RecoveryDispatchIdentityKind.REQUEST.value,
            command.request_id,
        )
        idempotency_logical_id = recovery_dispatch_identity_logical_id(
            RecoveryDispatchIdentityKind.IDEMPOTENCY.value,
            command.idempotency_key,
        )
        result: StoredRecord[RecoveryDispatchRecordV2] | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal result
            request = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
                logical_id=request_logical_id,
                document_id=recovery_dispatch_identity_document_id(
                    self._target,
                    RecoveryDispatchIdentityKind.REQUEST.value,
                    command.request_id,
                ),
                model_type=RecoveryDispatchIdentityV2,
            )
            idempotency = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
                logical_id=idempotency_logical_id,
                document_id=recovery_dispatch_identity_document_id(
                    self._target,
                    RecoveryDispatchIdentityKind.IDEMPOTENCY.value,
                    command.idempotency_key,
                ),
                model_type=RecoveryDispatchIdentityV2,
            )
            dispatch = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_DISPATCH,
                logical_id=dispatch_id,
                document_id=recovery_dispatch_document_id(
                    self._target,
                    dispatch_id,
                ),
                model_type=RecoveryDispatchStorageRecordV2,
            )
            if request is None and idempotency is None and dispatch is None:
                result = None
                return
            if request is None or idempotency is None or dispatch is None:
                raise AuthorityStoreCorruptRecord
            try:
                dispatch_value = recovery_dispatch_storage_record_value(
                    dispatch.value
                )
            except (TypeError, ValueError):
                raise AuthorityStoreCorruptRecord from None
            expected_request = _recovery_dispatch_identity(
                dispatch_value,
                RecoveryDispatchIdentityKind.REQUEST,
            )
            expected_idempotency = _recovery_dispatch_identity(
                dispatch_value,
                RecoveryDispatchIdentityKind.IDEMPOTENCY,
            )
            if (
                request.value != expected_request
                or idempotency.value != expected_idempotency
                or request.wrapper.revision != 0
                or idempotency.wrapper.revision != 0
                or dispatch_value.command_sha256 != command_sha256
                or dispatch_value.request_id != command.request_id
                or dispatch_value.idempotency_key != command.idempotency_key
                or dispatch_value.root_sha256 != command.expected_root_sha256
                or dispatch_value.epoch != command.expected_epoch
            ):
                raise AuthorityStoreConflict
            result = StoredRecord(dispatch_value, dispatch.wrapper.revision)

        await self._run_consistent_read(read)
        return result

    async def prepare_or_adopt_recovery_dispatch(
        self,
        intent: StoredRecord[RecoveryIntentV1],
        prepared: RecoveryDispatchRecordV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2]:
        """Create immutable dispatch ownership after exact root intent ownership."""

        if (
            type(intent) is not StoredRecord
            or type(intent.value) is not RecoveryIntentV1
            or intent.revision != 0
            or type(prepared) is not RecoveryDispatchRecordV2
            or prepared.state is not RecoveryDispatchState.PREPARED
            or prepared.command_sha256 != intent.value.command_sha256
            or prepared.root_sha256 != intent.value.root_sha256
            or prepared.epoch != intent.value.epoch
        ):
            raise ValueError("prepared recovery dispatch does not match its root intent")
        command = intent.value.command
        request_identity = _recovery_dispatch_identity(
            prepared,
            RecoveryDispatchIdentityKind.REQUEST,
        )
        idempotency_identity = _recovery_dispatch_identity(
            prepared,
            RecoveryDispatchIdentityKind.IDEMPOTENCY,
        )
        request_document = _prepared_document(
            kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
            logical_id=recovery_dispatch_identity_logical_id(
                request_identity.identity_kind.value,
                request_identity.identity_value,
            ),
            document_id=recovery_dispatch_identity_document_id(
                self._target,
                request_identity.identity_kind.value,
                request_identity.identity_value,
            ),
            revision=0,
            value=request_identity,
        )
        idempotency_document = _prepared_document(
            kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
            logical_id=recovery_dispatch_identity_logical_id(
                idempotency_identity.identity_kind.value,
                idempotency_identity.identity_value,
            ),
            document_id=recovery_dispatch_identity_document_id(
                self._target,
                idempotency_identity.identity_kind.value,
                idempotency_identity.identity_value,
            ),
            revision=0,
            value=idempotency_identity,
        )
        dispatch_storage = create_recovery_dispatch_storage_record(prepared)
        dispatch_document = _prepared_document(
            kind=HealthStorageKind.RECOVERY_DISPATCH,
            logical_id=prepared.dispatch_id,
            document_id=recovery_dispatch_document_id(
                self._target,
                prepared.dispatch_id,
            ),
            revision=0,
            value=dispatch_storage,
        )

        async def create(transaction: _TransactionPort) -> None:
            current_intent = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_INTENT,
                logical_id=intent.value.intent_id,
                document_id=recovery_intent_document_id(
                    self._target,
                    intent.value.root_sha256,
                ),
                model_type=RecoveryIntentV1,
            )
            current_request = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
                logical_id=request_document.wrapper.logical_id,
                document_id=request_document.document_id,
                model_type=RecoveryDispatchIdentityV2,
            )
            current_idempotency = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
                logical_id=idempotency_document.wrapper.logical_id,
                document_id=idempotency_document.document_id,
                model_type=RecoveryDispatchIdentityV2,
            )
            current_dispatch = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_DISPATCH,
                logical_id=prepared.dispatch_id,
                document_id=dispatch_document.document_id,
                model_type=RecoveryDispatchStorageRecordV2,
            )
            if current_intent is None or current_intent.stored != intent:
                raise _ExpectedStateMismatch
            current_values = (current_request, current_idempotency, current_dispatch)
            if all(value is None for value in current_values):
                client = await self._client()
                for document in (
                    request_document,
                    idempotency_document,
                    dispatch_document,
                ):
                    transaction.create(
                        self._reference(
                            client,
                            document.wrapper.record_kind,
                            document.document_id,
                        ),
                        _document_data(document.wrapper),
                    )
                return
            exact = (
                _matches_prepared_content(
                    cast(_DecodedDocument[StrictContractModel] | None, current_request),
                    cast(_PreparedDocument[StrictContractModel], request_document),
                )
                and _matches_prepared_content(
                    cast(
                        _DecodedDocument[StrictContractModel] | None,
                        current_idempotency,
                    ),
                    cast(_PreparedDocument[StrictContractModel], idempotency_document),
                )
                and _matches_prepared_content(
                    cast(_DecodedDocument[StrictContractModel] | None, current_dispatch),
                    cast(_PreparedDocument[StrictContractModel], dispatch_document),
                )
            )
            if exact:
                raise _ExactDuplicate
            raise _ExpectedStateMismatch

        try:
            await self._execute_write(3, create)
        except asyncio.CancelledError:
            raise
        except _ExactDuplicate:
            adopted = await self.read_recovery_dispatch(command)
            if adopted != StoredRecord(prepared, 0):
                raise AuthorityStoreCorruptRecord from None
            return adopted
        except _ExpectedStateMismatch:
            raise AuthorityStoreConflict from None
        except AuthorityStoreCorruptRecord:
            raise
        except Exception as error:
            try:
                adopted = await self.read_recovery_dispatch(command)
            except Exception:
                raise AuthorityStoreOutcomeUnknown from None
            if adopted == StoredRecord(prepared, 0):
                return adopted
            if adopted is not None or _is_contention(error):
                raise AuthorityStoreConflict from None
            raise AuthorityStoreOutcomeUnknown from None
        return StoredRecord(prepared, 0)

    async def _compare_and_set_recovery_dispatch(
        self,
        expected: StoredRecord[RecoveryDispatchRecordV2],
        replacement: RecoveryDispatchRecordV2,
        *,
        allow_enqueue_start: bool,
    ) -> tuple[StoredRecord[RecoveryDispatchRecordV2], bool]:
        if not _recovery_transition_is_exact(expected, replacement):
            raise ValueError("recovery dispatch transition is invalid")
        if (
            replacement.state is RecoveryDispatchState.ENQUEUE_STARTED
        ) != allow_enqueue_start:
            raise ValueError("recovery enqueue transition requires its sealed operation")
        next_revision = expected.revision + 1
        replacement_storage = create_recovery_dispatch_storage_record(replacement)
        replacement_document = _prepared_document(
            kind=HealthStorageKind.RECOVERY_DISPATCH,
            logical_id=replacement.dispatch_id,
            document_id=recovery_dispatch_document_id(
                self._target,
                replacement.dispatch_id,
            ),
            revision=next_revision,
            value=replacement_storage,
        )

        async def update(transaction: _TransactionPort) -> None:
            current = await self._transaction_read(
                transaction,
                kind=HealthStorageKind.RECOVERY_DISPATCH,
                logical_id=replacement.dispatch_id,
                document_id=replacement_document.document_id,
                model_type=RecoveryDispatchStorageRecordV2,
            )
            current_domain = (
                None
                if current is None
                else StoredRecord(
                    recovery_dispatch_storage_record_value(current.value),
                    current.wrapper.revision,
                )
            )
            if current_domain != expected:
                if (
                    current is not None
                    and current.stored == _stored(replacement_document)
                ):
                    raise _ExactDuplicate
                raise _ExpectedStateMismatch
            client = await self._client()
            transaction.update(
                self._reference(
                    client,
                    HealthStorageKind.RECOVERY_DISPATCH,
                    replacement_document.document_id,
                ),
                _document_data(replacement_document.wrapper),
            )

        try:
            await self._execute_write(1, update)
        except asyncio.CancelledError:
            raise
        except _ExactDuplicate:
            return StoredRecord(replacement, next_revision), False
        except _ExpectedStateMismatch:
            raise AuthorityStoreConflict from None
        except AuthorityStoreCorruptRecord:
            raise
        except Exception:
            if allow_enqueue_start:
                raise AuthorityStoreOutcomeUnknown from None
            try:
                adopted = await self.read_recovery_dispatch(
                    replacement.task.intent.authorization.prestate_attestation.result.request.command
                )
            except Exception:
                raise AuthorityStoreOutcomeUnknown from None
            if adopted == StoredRecord(replacement, next_revision):
                return adopted, False
            raise AuthorityStoreOutcomeUnknown from None
        return StoredRecord(replacement, next_revision), True

    async def compare_and_set_recovery_dispatch(
        self,
        expected: StoredRecord[RecoveryDispatchRecordV2],
        replacement: RecoveryDispatchRecordV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2]:
        """Advance a started dispatch only to its exact terminal result."""

        if replacement.state is RecoveryDispatchState.ENQUEUE_STARTED:
            raise ValueError("enqueue start requires direct permit issuance")
        stored, _ = await self._compare_and_set_recovery_dispatch(
            expected,
            replacement,
            allow_enqueue_start=False,
        )
        return stored

    async def begin_recovery_enqueue(
        self,
        expected: StoredRecord[RecoveryDispatchRecordV2],
        replacement: RecoveryDispatchRecordV2,
    ) -> DirectRecoveryEnqueueStart:
        """Mint one process-local permit only after a direct PREPARED-to-start CAS."""

        if replacement.state is not RecoveryDispatchState.ENQUEUE_STARTED:
            raise ValueError("recovery enqueue start requires ENQUEUE_STARTED")
        stored, directly_written = await self._compare_and_set_recovery_dispatch(
            expected,
            replacement,
            allow_enqueue_start=True,
        )
        if not directly_written:
            raise AuthorityStoreOutcomeUnknown
        return DirectRecoveryEnqueueStart(
            dispatch=stored,
            permit=RecoveryEnqueuePermit._from_direct_store_start(stored),
        )


__all__ = [
    "FirestoreHealthChainReader",
    "FirestoreHealthChainStore",
]
