"""Transactional Firestore adapter sealed to ControlGraph authority state."""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Literal, Protocol, Self, cast
from uuid import uuid4

from google.api_core import exceptions as api_exceptions
from google.cloud import firestore_v1

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    CreatedRollout,
    DirectReceiptCreate,
    FencedServiceClaim,
    FinalAuthoritySnapshot,
    IssuanceStateSnapshot,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    ReceiptClaimResult,
    ReleasedServiceClaim,
    RootCreationBundle,
    RootCreationWriteResult,
    StoredRecord,
    validate_receipt_claim_binding,
)
from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    rollout_root_target_configuration_sha256,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.evidence_chain import current_evidence_chain_head
from controlgraph_canary.application.promotion_store import (
    DirectPromotionEnqueueStart,
    DirectPromotionEnqueueStartV2,
    PromotionEnqueuePermit,
    PromotionEnqueuePermitV2,
)
from controlgraph_canary.application.revocation_store import (
    EpochRevocationProofState,
    EpochRevocationState,
    EpochRevocationWriteResult,
)
from controlgraph_canary.application.service_claim_release_store import (
    ServiceClaimFenceWriteResult,
    ServiceClaimFinalizeWriteResult,
    ServiceClaimReleaseState,
)
from controlgraph_canary.authority.replay import MutationBinding
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.evidence import EvidenceChainHeadV1
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceKind,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    RolloutRoot,
    TargetBinding,
)
from controlgraph_canary.contracts.promotion_execution import (
    PROMOTION_DISPATCH_IDENTITY_V1,
    PROMOTION_DISPATCH_IDENTITY_V2,
    PromotionCommandV1,
    PromotionCommandV2,
    PromotionDispatchIdentityKind,
    PromotionDispatchIdentityV1,
    PromotionDispatchIdentityV2,
    PromotionDispatchRecordV1,
    PromotionDispatchRecordV2,
    PromotionDispatchState,
    promotion_command_sha256,
    promotion_command_v2_sha256,
    promotion_dispatch_id,
    promotion_dispatch_v2_id,
)
from controlgraph_canary.contracts.revocation import (
    EpochRevocationAuditV1,
    EpochRevocationCommitV1,
    EpochRevocationIdentityKind,
    EpochRevocationIdentityV1,
    EpochRevocationInvocationV1,
    EpochRevocationProofCommandV1,
    EpochRevocationResultV1,
    epoch_revocation_request_sha256,
)
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV2,
    RolloutRootV3,
    RootCreationResultV1,
    RootCreationResultV2,
    SignedEvidenceEventV1,
    capability_lineage_anchor,
)
from controlgraph_canary.contracts.service_claim_release import (
    ServiceClaimReleaseFenceCommitV1,
    ServiceClaimReleaseFinalizeCommitV1,
    ServiceClaimReleaseIdentityKind,
    ServiceClaimReleaseIdentityV1,
    ServiceClaimReleaseInvocationV1,
    ServiceClaimReleaseProgressV1,
    ServiceClaimReleaseResultV1,
    service_claim_release_evidence_id,
    service_claim_release_request_sha256,
)
from controlgraph_canary.contracts.storage import (
    AUTHORITY_STORAGE_DOCUMENT_V1,
    AuthorityStorageDocument,
    AuthorityStorageKind,
    ServiceClaimRecord,
    ServiceClaimRecordV3,
    ServiceClaimRecordValue,
    ServiceClaimStatus,
    ServiceClaimTargetClassification,
    ServiceClaimTerminalRootState,
    active_service_claim_matches_root,
    active_service_claim_matches_root_v3,
    capability_lineage_anchor_document_id,
    capability_lineage_anchor_logical_id,
    epoch_authority_document_id,
    epoch_revocation_audit_document_id,
    epoch_revocation_identity_document_id,
    epoch_revocation_identity_logical_id,
    epoch_revocation_result_document_id,
    evidence_chain_head_document_id,
    execution_receipt_document_id,
    execution_receipt_logical_id,
    promotion_dispatch_document_id,
    promotion_dispatch_identity_document_id,
    promotion_dispatch_identity_logical_id,
    promotion_dispatch_identity_v2_document_id,
    promotion_dispatch_identity_v2_logical_id,
    promotion_dispatch_v2_document_id,
    rollout_root_document_id,
    rollout_root_v2_document_id,
    rollout_root_v3_document_id,
    root_creation_result_document_id,
    root_creation_result_v2_document_id,
    service_claim_document_id,
    service_claim_logical_id,
    service_claim_matches_root_v2,
    service_claim_matches_root_v3,
    service_claim_release_identity_document_id,
    service_claim_release_identity_logical_id,
    service_claim_release_progress_document_id,
    service_claim_release_result_document_id,
    signed_evidence_event_document_id,
)

FIRESTORE_AUTHORITY_DATABASE: Final = "controlgraph-authority"
FIRESTORE_AUTHORITY_REGION: Final = "us-central1"
FIRESTORE_OPERATION_TIMEOUT_SECONDS: Final = 5.0
FIRESTORE_MAX_TRANSACTION_ATTEMPTS: Final = 3

_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_SHA256_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
_READBACK_RESOLUTION_MARKER: Final = re.compile(r"^cgrrb:[0-9a-f]{64}$")
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

    def get_all(
        self,
        references: Sequence[_DocumentReferencePort],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> AsyncIterator[object]: ...

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


class _TransactionCommitDisposition(StrEnum):
    DIRECT_CONFIRMED = "DIRECT_CONFIRMED"
    READBACK_RESOLVED = "READBACK_RESOLVED"


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


@dataclass(frozen=True, slots=True)
class _DecodedIssuanceState:
    root: _DecodedDocument[RolloutRoot] | None
    service_claim: _DecodedDocument[ServiceClaimRecord] | None
    authority: _DecodedDocument[EpochAuthorityRecord] | None


@dataclass(frozen=True, slots=True)
class _FinalReadSpec:
    reference: _DocumentReferencePort
    kind: AuthorityStorageKind
    logical_id: str
    document_id: str
    model_type: type[StrictContractModel]


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
    service_claim_logical_id(target)


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
    cancellation_requested = False
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            if cancellation_requested:
                raise asyncio.CancelledError
            raise TimeoutError
        try:
            async with asyncio.timeout(remaining):
                result = await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancellation_requested = True
            current_task = asyncio.current_task()
            if current_task is not None:
                current_task.uncancel()
            continue
        except BaseException:
            if cancellation_requested:
                raise asyncio.CancelledError from None
            raise
        if cancellation_requested:
            raise asyncio.CancelledError
        return result


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
        client.transaction(
            max_attempts=maximum_attempts,
            read_only=expected_writes == 0,
        ),
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
    *,
    verified_candidate_revision_configuration_sha256: str,
) -> None:
    if (
        type(verified_candidate_revision_configuration_sha256) is not str
        or _SHA256_DIGEST.fullmatch(verified_candidate_revision_configuration_sha256) is None
    ):
        raise ValueError("verified candidate configuration is not a SHA-256 digest")
    if (
        claim.candidate_revision_configuration_sha256
        != verified_candidate_revision_configuration_sha256
    ):
        raise ValueError("verified candidate configuration does not match the claim")
    if any(value.target != configured_target for value in (root, claim, authority)):
        raise ValueError("rollout records do not match the configured target")
    root_sha256 = canonical_sha256(root)
    stable_configuration_sha256 = rollout_root_target_configuration_sha256(
        root,
        stable_percent=100,
        candidate_percent=0,
    )
    candidate_configuration_sha256 = rollout_root_target_configuration_sha256(
        root,
        stable_percent=0,
        candidate_percent=100,
    )
    if (
        not active_service_claim_matches_root(
            claim,
            root,
            stable_target_configuration_sha256=stable_configuration_sha256,
            candidate_target_configuration_sha256=candidate_configuration_sha256,
        )
        or authority.changed_by != claim.operator_owner
        or claim.operator_owner != root.approved_by
        or claim.operator_owner == claim.workload_creator
        or root.approved_by == claim.workload_creator
        or authority.changed_by == claim.workload_creator
        or authority.root_id != root.root_id
        or authority.root_sha256 != root_sha256
        or authority.current_epoch != root.initial_epoch
        or authority.previous_epoch is not None
        or authority.revision != 0
        or authority.cause is not EpochChangeCause.ROOT_CREATED
        or claim.claim_request_id != authority.request_id
        or claim.claim_evidence_id != authority.evidence_id
        or claim.claimed_at != authority.changed_at
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


def _validate_epoch_revocation_commit(
    configured_target: TargetBinding,
    expected: EpochRevocationState,
    commit: EpochRevocationCommitV1,
) -> None:
    if (
        type(expected) is not EpochRevocationState
        or type(commit) is not EpochRevocationCommitV1
        or expected.root_bundle is None
        or expected.request_identity is not None
        or expected.idempotency_identity is not None
        or expected.result is not None
        or expected.attempt_audit is not None
    ):
        raise TypeError("epoch revocation commit requires exact state and records")
    invocation = expected.invocation
    command = invocation.command
    request_sha256 = epoch_revocation_request_sha256(invocation)
    bundle = expected.root_bundle
    root = bundle.root.value
    claim = bundle.service_claim.value
    authority = bundle.authority
    replacement = commit.replacement_authority
    _validate_authority_advance(configured_target, authority, replacement)
    if (
        root.content.target != configured_target
        or root.root_id != command.root_id
        or root.root_sha256 != command.expected_root_sha256
        or claim.status is not ServiceClaimStatus.ACTIVE
        or bundle.service_claim.revision % 3 != 0
        or claim.root_id != root.root_id
        or claim.root_sha256 != root.root_sha256
        or authority.value.current_epoch != command.expected_epoch
        or replacement.cause is not EpochChangeCause.OPERATOR_REVOCATION
        or replacement.changed_by != invocation.operator_identity
        or replacement.request_id != command.request_id
    ):
        raise ValueError("epoch revocation does not match active root authority")
    result = commit.result
    subject = commit.evidence_subject
    signed = commit.signed_evidence
    event = signed.event
    evidence_sha256 = canonical_sha256(signed)
    if (
        result.request_sha256 != request_sha256
        or result.result_id != f"cgrevoke:{request_sha256}"
        or result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.root_id != root.root_id
        or result.root_sha256 != root.root_sha256
        or result.target != configured_target
        or result.operator_identity != invocation.operator_identity
        or result.operator_subject != invocation.operator_subject
        or result.reason != command.reason
        or result.previous_epoch != authority.value.current_epoch
        or result.new_epoch != replacement.current_epoch
        or result.evidence_id != replacement.evidence_id
        or result.evidence_sha256 != evidence_sha256
        or result.evidence_subject != subject
        or result.committed_at != replacement.changed_at
        or subject.root_id != result.root_id
        or subject.root_sha256 != result.root_sha256
        or subject.request_sha256 != request_sha256
        or subject.request_id != result.request_id
        or subject.idempotency_key != result.idempotency_key
        or subject.operator_identity != result.operator_identity
        or subject.operator_subject != result.operator_subject
        or subject.reason != result.reason
        or subject.service_claim_sha256 != canonical_sha256(claim)
        or subject.previous_authority_sha256 != canonical_sha256(authority.value)
        or subject.replacement_authority_sha256 != canonical_sha256(replacement)
        or subject.previous_epoch != result.previous_epoch
        or subject.new_epoch != result.new_epoch
        or subject.evidence_id != result.evidence_id
        or subject.committed_at != result.committed_at
        or event.evidence_id != result.evidence_id
        or event.root_id != result.root_id
        or event.root_sha256 != result.root_sha256
        or event.target != configured_target
        or event.epoch != result.new_epoch
        or event.kind is not EvidenceKind.EPOCH_ADVANCED
        or event.actor != invocation.operator_identity
        or event.request_id != command.request_id
        or event.receipt_id is not None
        or event.occurred_at != result.committed_at
        or event.subject_sha256 != canonical_sha256(subject)
        or event.reason_code is not None
        or event.provider_operation is not None
        or event.target_configuration_sha256 is not None
        or signed.signing_key_version != root.content.evidence_signing_key_version
    ):
        raise ValueError("epoch revocation result and evidence are incoherent")
    predecessor_head = current_evidence_chain_head(
        bundle,
        target=configured_target,
        stored_head=expected.chain_head,
        head_evidence=expected.head_evidence,
    )
    predecessor = (
        bundle.signed_evidence.value
        if expected.chain_head is None
        else cast(StoredRecord[SignedEvidenceEventV1], expected.head_evidence).value
    )
    predecessor_sequence = predecessor_head.sequence
    head = commit.chain_head
    if (
        event.sequence != predecessor_sequence + 1
        or event.previous_event_sha256 != canonical_sha256(predecessor)
        or event.occurred_at < predecessor_head.updated_at
        or head.root_id != result.root_id
        or head.root_sha256 != result.root_sha256
        or head.target != configured_target
        or head.sequence != event.sequence
        or head.evidence_id != event.evidence_id
        or head.evidence_sha256 != evidence_sha256
        or head.kind is not event.kind
        or head.epoch != event.epoch
        or head.updated_at != event.occurred_at
    ):
        raise ValueError("epoch revocation evidence-chain update is invalid")
    identities = (
        (
            commit.request_identity,
            EpochRevocationIdentityKind.REQUEST,
            command.request_id,
        ),
        (
            commit.idempotency_identity,
            EpochRevocationIdentityKind.IDEMPOTENCY,
            command.idempotency_key,
        ),
    )
    if any(
        identity.identity_kind is not kind
        or identity.identity_value != value
        or identity.root_id != result.root_id
        or identity.root_sha256 != result.root_sha256
        or identity.request_sha256 != request_sha256
        or identity.result_id != result.result_id
        or identity.claimed_at != result.committed_at
        for identity, kind, value in identities
    ):
        raise ValueError("epoch revocation identity claims are invalid")
    audit = commit.audit
    if (
        audit.audit_id != invocation.attempt_id
        or audit.attempt_id != invocation.attempt_id
        or audit.request_sha256 != request_sha256
        or audit.root_id != result.root_id
        or audit.root_sha256 != result.root_sha256
        or audit.expected_epoch != command.expected_epoch
        or audit.request_id != command.request_id
        or audit.idempotency_key != command.idempotency_key
        or audit.operator_identity != invocation.operator_identity
        or audit.operator_subject != invocation.operator_subject
        or audit.outcome.value != "COMMITTED"
        or audit.result_id != result.result_id
        or audit.evidence_id != result.evidence_id
        or audit.new_epoch != result.new_epoch
        or audit.recorded_at != result.committed_at
    ):
        raise ValueError("epoch revocation accepted audit is invalid")


def _claim_ownership_binding(claim: ServiceClaimRecord) -> tuple[object, ...]:
    return (
        claim.target,
        claim.root_id,
        claim.root_sha256,
        claim.stable_revision,
        claim.candidate_revision,
        claim.initial_epoch,
        claim.baseline_service_generation,
        claim.baseline_configuration_sha256,
        claim.baseline_revision_configuration_sha256,
        claim.candidate_revision_configuration_sha256,
        claim.stable_target_configuration_sha256,
        claim.candidate_target_configuration_sha256,
        claim.operator_owner,
        claim.workload_creator,
        claim.terminal_release_condition,
        claim.claim_request_id,
        claim.claim_evidence_id,
        claim.claimed_at,
    )


def _validate_claim_fence(
    configured_target: TargetBinding,
    expected: StoredRecord[ServiceClaimRecord],
    replacement: ServiceClaimRecord,
) -> None:
    current = expected.value
    if type(current) is not ServiceClaimRecord or type(replacement) is not ServiceClaimRecord:
        raise TypeError("service claim compare-and-set requires exact claim records")
    if current.target != configured_target or replacement.target != configured_target:
        raise ValueError("service claim does not match the configured target")
    if (
        current.status is not ServiceClaimStatus.ACTIVE
        or replacement.status is not ServiceClaimStatus.RELEASING
        or _claim_ownership_binding(replacement) != _claim_ownership_binding(current)
    ):
        raise ValueError("service claim replacement is not an exact epoch fence")


def _validate_claim_fence_authority(
    configured_target: TargetBinding,
    expected_claim: StoredRecord[ServiceClaimRecord],
    replacement_claim: ServiceClaimRecord,
    expected_authority: StoredRecord[EpochAuthorityRecord],
    replacement_authority: EpochAuthorityRecord,
) -> None:
    _validate_claim_fence(configured_target, expected_claim, replacement_claim)
    _validate_authority_advance(
        configured_target,
        expected_authority,
        replacement_authority,
    )
    current_claim = expected_claim.value
    current_authority = expected_authority.value
    if (
        current_claim.root_id != current_authority.root_id
        or current_claim.root_sha256 != current_authority.root_sha256
        or replacement_claim.root_id != replacement_authority.root_id
        or replacement_claim.root_sha256 != replacement_authority.root_sha256
        or replacement_claim.release_fence_epoch != replacement_authority.current_epoch
        or replacement_claim.release_fence_authority_revision != replacement_authority.revision
        or replacement_claim.release_fenced_by != replacement_authority.changed_by
        or replacement_claim.release_fence_request_id != replacement_authority.request_id
        or replacement_claim.release_fence_evidence_id != replacement_authority.evidence_id
        or replacement_claim.release_fenced_at != replacement_authority.changed_at
        or replacement_authority.cause is not EpochChangeCause.OPERATOR_REVOCATION
    ):
        raise ValueError("service claim fence and authority advance are not one transition")


def _validate_claim_release(
    configured_target: TargetBinding,
    expected_claim: StoredRecord[ServiceClaimRecord],
    replacement_claim: ServiceClaimRecord,
    expected_authority: StoredRecord[EpochAuthorityRecord],
) -> None:
    current = expected_claim.value
    authority = expected_authority.value
    if (
        type(current) is not ServiceClaimRecord
        or type(replacement_claim) is not ServiceClaimRecord
        or type(authority) is not EpochAuthorityRecord
    ):
        raise TypeError("service claim release requires exact authority records")
    if current.target != configured_target or replacement_claim.target != configured_target:
        raise ValueError("service claim does not match the configured target")
    if (
        current.status is not ServiceClaimStatus.RELEASING
        or replacement_claim.status is not ServiceClaimStatus.RELEASED
        or _claim_ownership_binding(replacement_claim) != _claim_ownership_binding(current)
        or replacement_claim.release_fence_epoch != current.release_fence_epoch
        or replacement_claim.release_fence_authority_revision
        != current.release_fence_authority_revision
        or replacement_claim.release_fenced_by != current.release_fenced_by
        or replacement_claim.release_fence_request_id != current.release_fence_request_id
        or replacement_claim.release_fence_evidence_id != current.release_fence_evidence_id
        or replacement_claim.release_fenced_at != current.release_fenced_at
        or replacement_claim.terminal_root_proof != current.terminal_root_proof
        or authority.target != current.target
        or authority.root_id != current.root_id
        or authority.root_sha256 != current.root_sha256
        or authority.current_epoch != current.release_fence_epoch
        or authority.revision != current.release_fence_authority_revision
        or expected_authority.revision != authority.revision
        or authority.cause is not EpochChangeCause.OPERATOR_REVOCATION
        or authority.changed_by != current.release_fenced_by
        or authority.request_id != current.release_fence_request_id
        or authority.evidence_id != current.release_fence_evidence_id
        or authority.changed_at != current.release_fenced_at
    ):
        raise ValueError("service claim replacement is not an exact fenced release")


def _terminal_receipt_release_mapping(
    receipt: ExecutionReceipt,
    claim: ServiceClaimRecord,
) -> tuple[
    ServiceClaimTerminalRootState,
    ServiceClaimTargetClassification,
    str,
]:
    if receipt.action is CapabilityAction.PROMOTE_CANDIDATE:
        return (
            ServiceClaimTerminalRootState.PROMOTED,
            ServiceClaimTargetClassification.CANDIDATE_PROMOTED,
            claim.candidate_target_configuration_sha256,
        )
    if receipt.action is CapabilityAction.RECOVER_STABLE:
        return (
            ServiceClaimTerminalRootState.RECOVERED,
            ServiceClaimTargetClassification.STABLE_RESTORED,
            claim.stable_target_configuration_sha256,
        )
    raise ValueError("terminal receipt action cannot release a service claim")


def _validate_service_claim_fence_commit(
    configured_target: TargetBinding,
    expected: ServiceClaimReleaseState,
    commit: ServiceClaimReleaseFenceCommitV1,
) -> None:
    if (
        type(expected) is not ServiceClaimReleaseState
        or type(commit) is not ServiceClaimReleaseFenceCommitV1
        or expected.root_bundle is None
        or type(expected.root_bundle) is not RootCreationBundle
        or expected.terminal_receipt is None
        or type(expected.terminal_receipt) is not StoredRecord
        or type(expected.terminal_receipt.value) is not ExecutionReceipt
        or any(
            value is not None
            for value in (
                expected.request_identity,
                expected.idempotency_identity,
                expected.progress,
                expected.result,
                expected.terminal_evidence,
                expected.fence_evidence,
                expected.classification_evidence,
                expected.release_evidence,
            )
        )
    ):
        raise ValueError("service claim fence state is not pristine")
    bundle = expected.root_bundle
    _validate_read_root_creation_bundle(configured_target, bundle)
    claim_value = bundle.service_claim.value
    if type(claim_value) is not ServiceClaimRecord:
        raise ValueError("normal service claim release requires a V2 claim")
    claim_record = StoredRecord(claim_value, bundle.service_claim.revision)
    _validate_claim_fence_authority(
        configured_target,
        claim_record,
        commit.replacement_claim,
        bundle.authority,
        commit.replacement_authority,
    )
    previous_head = current_evidence_chain_head(
        bundle,
        target=configured_target,
        stored_head=expected.chain_head,
        head_evidence=expected.head_evidence,
    )
    terminal = commit.terminal_evidence
    fence = commit.fence_evidence
    terminal_event = terminal.event
    fence_event = fence.event
    progress = commit.progress
    request_sha256 = service_claim_release_request_sha256(expected.invocation)
    invocation = expected.invocation
    command = expected.invocation.command
    receipt_record = expected.terminal_receipt
    receipt = receipt_record.value
    root = bundle.root.value
    claim = claim_value
    authority = bundle.authority.value
    terminal_state, _, target_configuration_sha256 = (
        _terminal_receipt_release_mapping(receipt, claim)
    )
    terminal_subject = commit.terminal_subject
    terminal_proof = commit.replacement_claim.terminal_root_proof
    fence_subject = commit.fence_subject
    replacement_authority = commit.replacement_authority
    replacement_claim = commit.replacement_claim
    if terminal_proof is None:
        raise ValueError("service claim fence lacks terminal proof")
    if (
        root.content.target != configured_target
        or root.root_id != command.root_id
        or root.root_sha256 != command.expected_root_sha256
        or claim.target != configured_target
        or claim.root_id != root.root_id
        or claim.root_sha256 != root.root_sha256
        or authority.target != configured_target
        or authority.root_id != root.root_id
        or authority.root_sha256 != root.root_sha256
        or authority.current_epoch != command.expected_epoch
        or receipt_record.revision < 1
        or receipt.receipt_id
        != execution_receipt_logical_id(
            configured_target,
            command.terminal_receipt_idempotency_key,
        )
        or receipt.idempotency_key != command.terminal_receipt_idempotency_key
        or receipt.target != configured_target
        or receipt.root_id != root.root_id
        or receipt.root_sha256 != root.root_sha256
        or receipt.outcome is not ReceiptOutcome.VERIFIED
        or receipt.reason_code is not None
        or receipt.observed_etag is None
        or receipt.expected_poststate_sha256 != target_configuration_sha256
        or receipt.epoch > authority.current_epoch
        or receipt.updated_at > progress.fenced_at
        or previous_head.updated_at > progress.fenced_at
        or replacement_authority.changed_by != invocation.operator_identity
        or replacement_authority.request_id != command.request_id
        or replacement_authority.evidence_id != fence_event.evidence_id
        or replacement_authority.changed_at != progress.fenced_at
        or replacement_claim.release_fenced_by != invocation.operator_identity
        or replacement_claim.release_fence_request_id != command.request_id
        or replacement_claim.release_fence_evidence_id != fence_event.evidence_id
        or replacement_claim.release_fenced_at != progress.fenced_at
        or terminal_subject.target != configured_target
        or terminal_subject.root_id != root.root_id
        or terminal_subject.root_sha256 != root.root_sha256
        or terminal_subject.state is not terminal_state
        or terminal_subject.target_configuration_sha256
        != target_configuration_sha256
        or terminal_subject.receipt_id != receipt.receipt_id
        or terminal_subject.receipt_sha256 != canonical_sha256(receipt)
        or terminal_subject.receipt_revision != receipt_record.revision
        or terminal_subject.receipt_epoch != receipt.epoch
        or terminal_subject.receipt_action is not receipt.action
        or terminal_subject.receipt_outcome is not ReceiptOutcome.VERIFIED
        or terminal_subject.evidence_id != terminal_event.evidence_id
        or terminal_subject.confirmed_by != "controlgraph.coordinator/v1"
        or terminal_subject.confirmed_at != progress.fenced_at
        or terminal_proof.target != terminal_subject.target
        or terminal_proof.root_id != terminal_subject.root_id
        or terminal_proof.root_sha256 != terminal_subject.root_sha256
        or terminal_proof.state is not terminal_subject.state
        or terminal_proof.target_configuration_sha256
        != terminal_subject.target_configuration_sha256
        or terminal_proof.evidence_id != terminal_event.evidence_id
        or terminal_proof.evidence_sha256 != canonical_sha256(terminal)
        or terminal_proof.confirmed_by != terminal_subject.confirmed_by
        or terminal_proof.confirmed_at != terminal_subject.confirmed_at
        or terminal_event.root_id != root.root_id
        or terminal_event.root_sha256 != root.root_sha256
        or terminal_event.target != configured_target
        or terminal_event.epoch != receipt.epoch
        or terminal_event.actor != "controlgraph.coordinator/v1"
        or terminal_event.request_id != command.request_id
        or terminal_event.occurred_at != progress.fenced_at
        or terminal_event.reason_code is not None
        or terminal_event.provider_operation is not None
        or terminal_event.target_configuration_sha256
        != target_configuration_sha256
        or fence_subject.target != configured_target
        or fence_subject.root_id != root.root_id
        or fence_subject.root_sha256 != root.root_sha256
        or fence_subject.request_sha256 != request_sha256
        or fence_subject.request_id != command.request_id
        or fence_subject.idempotency_key != command.idempotency_key
        or fence_subject.operator_identity != invocation.operator_identity
        or fence_subject.operator_subject != invocation.operator_subject
        or fence_subject.terminal_evidence_id != terminal_event.evidence_id
        or fence_subject.terminal_evidence_sha256 != canonical_sha256(terminal)
        or fence_subject.previous_claim_sha256 != canonical_sha256(claim)
        or fence_subject.replacement_claim_sha256
        != canonical_sha256(replacement_claim)
        or fence_subject.previous_authority_sha256 != canonical_sha256(authority)
        or fence_subject.replacement_authority_sha256
        != canonical_sha256(replacement_authority)
        or fence_subject.previous_epoch != authority.current_epoch
        or fence_subject.new_epoch != replacement_authority.current_epoch
        or fence_subject.evidence_id != fence_event.evidence_id
        or fence_subject.fenced_at != progress.fenced_at
        or fence_event.root_id != root.root_id
        or fence_event.root_sha256 != root.root_sha256
        or fence_event.target != configured_target
        or fence_event.actor != invocation.operator_identity
        or fence_event.receipt_id is not None
        or fence_event.occurred_at != progress.fenced_at
        or fence_event.reason_code is not None
        or fence_event.provider_operation is not None
        or fence_event.target_configuration_sha256 is not None
        or progress.request_sha256 != request_sha256
        or progress.result_id != f"cgrelease:{request_sha256}"
        or progress.request_id != command.request_id
        or progress.idempotency_key != command.idempotency_key
        or progress.root_id != root.root_id
        or progress.root_sha256 != root.root_sha256
        or progress.target != configured_target
        or progress.terminal_receipt_id != receipt.receipt_id
        or progress.terminal_receipt_sha256 != canonical_sha256(receipt)
        or progress.terminal_evidence_sha256 != canonical_sha256(terminal)
        or progress.fence_evidence_sha256 != canonical_sha256(fence)
        or progress.terminal_subject != commit.terminal_subject
        or progress.fence_subject != commit.fence_subject
        or progress.terminal_evidence_id != terminal_event.evidence_id
        or progress.fence_evidence_id != fence_event.evidence_id
        or progress.fenced_epoch != replacement_authority.current_epoch
        or progress.fenced_authority_revision != replacement_authority.revision
        or progress.fenced_at != replacement_authority.changed_at
        or terminal_event.evidence_id
        != service_claim_release_evidence_id(request_sha256, "terminal")
        or terminal_event.sequence != previous_head.sequence + 1
        or terminal_event.previous_event_sha256 != previous_head.evidence_sha256
        or terminal_event.subject_sha256 != canonical_sha256(commit.terminal_subject)
        or terminal_event.kind is not EvidenceKind.TARGET_VERIFIED
        or terminal_event.receipt_id != receipt.receipt_id
        or fence_event.evidence_id
        != service_claim_release_evidence_id(request_sha256, "fence")
        or fence_event.sequence != terminal_event.sequence + 1
        or fence_event.previous_event_sha256 != canonical_sha256(terminal)
        or fence_event.subject_sha256 != canonical_sha256(commit.fence_subject)
        or fence_event.kind is not EvidenceKind.EPOCH_ADVANCED
        or fence_event.epoch != commit.replacement_authority.current_epoch
        or fence_event.request_id != command.request_id
        or commit.chain_head.root_id != fence_event.root_id
        or commit.chain_head.root_sha256 != fence_event.root_sha256
        or commit.chain_head.target != fence_event.target
        or commit.chain_head.sequence != fence_event.sequence
        or commit.chain_head.evidence_id != fence_event.evidence_id
        or commit.chain_head.evidence_sha256 != canonical_sha256(fence)
        or commit.chain_head.kind is not fence_event.kind
        or commit.chain_head.epoch != fence_event.epoch
        or commit.chain_head.updated_at != fence_event.occurred_at
        or terminal.signing_key_version
        != bundle.root.value.content.evidence_signing_key_version
        or fence.signing_key_version
        != bundle.root.value.content.evidence_signing_key_version
        or commit.request_identity.identity_kind
        is not ServiceClaimReleaseIdentityKind.REQUEST
        or commit.request_identity.identity_value != command.request_id
        or commit.idempotency_identity.identity_kind
        is not ServiceClaimReleaseIdentityKind.IDEMPOTENCY
        or commit.idempotency_identity.identity_value != command.idempotency_key
        or commit.request_identity.request_sha256 != request_sha256
        or commit.idempotency_identity.request_sha256 != request_sha256
        or commit.request_identity.result_id != progress.result_id
        or commit.idempotency_identity.result_id != progress.result_id
        or commit.request_identity.root_id != root.root_id
        or commit.idempotency_identity.root_id != root.root_id
        or commit.request_identity.root_sha256 != root.root_sha256
        or commit.idempotency_identity.root_sha256 != root.root_sha256
        or commit.request_identity.claimed_at != progress.fenced_at
        or commit.idempotency_identity.claimed_at != progress.fenced_at
    ):
        raise ValueError("service claim fence commit is not exactly bound")


def _validate_service_claim_finalize_commit(
    configured_target: TargetBinding,
    expected: ServiceClaimReleaseState,
    commit: ServiceClaimReleaseFinalizeCommitV1,
) -> None:
    if (
        type(expected) is not ServiceClaimReleaseState
        or type(commit) is not ServiceClaimReleaseFinalizeCommitV1
        or expected.root_bundle is None
        or type(expected.root_bundle) is not RootCreationBundle
        or expected.terminal_receipt is None
        or type(expected.terminal_receipt) is not StoredRecord
        or type(expected.terminal_receipt.value) is not ExecutionReceipt
        or expected.progress is None
        or type(expected.progress) is not StoredRecord
        or type(expected.progress.value) is not ServiceClaimReleaseProgressV1
        or expected.request_identity is None
        or type(expected.request_identity) is not StoredRecord
        or type(expected.request_identity.value) is not ServiceClaimReleaseIdentityV1
        or expected.idempotency_identity is None
        or type(expected.idempotency_identity) is not StoredRecord
        or type(expected.idempotency_identity.value)
        is not ServiceClaimReleaseIdentityV1
        or expected.terminal_evidence is None
        or type(expected.terminal_evidence) is not StoredRecord
        or type(expected.terminal_evidence.value) is not SignedEvidenceEventV1
        or expected.fence_evidence is None
        or type(expected.fence_evidence) is not StoredRecord
        or type(expected.fence_evidence.value) is not SignedEvidenceEventV1
        or expected.chain_head is None
        or type(expected.chain_head) is not StoredRecord
        or type(expected.chain_head.value) is not EvidenceChainHeadV1
        or expected.head_evidence is None
        or type(expected.head_evidence) is not StoredRecord
        or type(expected.head_evidence.value) is not SignedEvidenceEventV1
        or expected.result is not None
        or expected.classification_evidence is not None
        or expected.release_evidence is not None
    ):
        raise ValueError("service claim finalize state is incomplete")
    bundle = expected.root_bundle
    _validate_read_root_creation_bundle(configured_target, bundle)
    claim_value = bundle.service_claim.value
    if type(claim_value) is not ServiceClaimRecord:
        raise ValueError("normal service claim release requires a V2 claim")
    claim_record = StoredRecord(claim_value, bundle.service_claim.revision)
    _validate_claim_release(
        configured_target,
        claim_record,
        commit.replacement_claim,
        bundle.authority,
    )
    previous_head = current_evidence_chain_head(
        bundle,
        target=configured_target,
        stored_head=expected.chain_head,
        head_evidence=expected.head_evidence,
    )
    classification = commit.classification_evidence
    release = commit.release_evidence
    classification_event = classification.event
    release_event = release.event
    result = commit.result
    progress = expected.progress.value
    request_sha256 = service_claim_release_request_sha256(expected.invocation)
    invocation = expected.invocation
    command = invocation.command
    root = bundle.root.value
    claim = claim_value
    authority = bundle.authority.value
    terminal_receipt = expected.terminal_receipt.value
    terminal_evidence = expected.terminal_evidence.value
    fence_evidence = expected.fence_evidence.value
    request_identity = expected.request_identity.value
    idempotency_identity = expected.idempotency_identity.value
    classification_subject = commit.classification_subject
    release_subject = commit.release_subject
    classification_proof = commit.replacement_claim.target_classification_proof
    terminal_proof = claim.terminal_root_proof
    expected_reader = (
        f"controlgraph-verifier@{configured_target.project_id}.iam.gserviceaccount.com"
    )
    if classification_proof is None or terminal_proof is None:
        raise ValueError("service claim release lacks verifier classification proof")
    terminal_state, expected_classification, target_configuration_sha256 = (
        _terminal_receipt_release_mapping(terminal_receipt, claim)
    )
    if (
        root.content.target != configured_target
        or root.root_id != command.root_id
        or root.root_sha256 != command.expected_root_sha256
        or claim.target != configured_target
        or claim.root_id != root.root_id
        or claim.root_sha256 != root.root_sha256
        or authority.target != configured_target
        or authority.root_id != root.root_id
        or authority.root_sha256 != root.root_sha256
        or authority.current_epoch != command.expected_epoch + 1
        or progress.request_sha256 != request_sha256
        or progress.result_id != f"cgrelease:{request_sha256}"
        or progress.request_id != command.request_id
        or progress.idempotency_key != command.idempotency_key
        or progress.root_id != root.root_id
        or progress.root_sha256 != root.root_sha256
        or progress.target != configured_target
        or progress.terminal_receipt_id != terminal_receipt.receipt_id
        or progress.terminal_receipt_sha256 != canonical_sha256(terminal_receipt)
        or progress.terminal_evidence_id
        != terminal_evidence.event.evidence_id
        or progress.terminal_evidence_sha256
        != canonical_sha256(terminal_evidence)
        or progress.fence_evidence_id != fence_evidence.event.evidence_id
        or progress.fence_evidence_sha256 != canonical_sha256(fence_evidence)
        or progress.fenced_epoch != authority.current_epoch
        or progress.fenced_authority_revision != authority.revision
        or progress.fenced_at != authority.changed_at
        or terminal_receipt.receipt_id
        != execution_receipt_logical_id(
            configured_target,
            command.terminal_receipt_idempotency_key,
        )
        or terminal_receipt.idempotency_key
        != command.terminal_receipt_idempotency_key
        or terminal_receipt.target != configured_target
        or terminal_receipt.root_id != root.root_id
        or terminal_receipt.root_sha256 != root.root_sha256
        or terminal_receipt.outcome is not ReceiptOutcome.VERIFIED
        or terminal_receipt.reason_code is not None
        or terminal_receipt.observed_etag is None
        or terminal_receipt.expected_poststate_sha256
        != target_configuration_sha256
        or terminal_receipt.epoch > command.expected_epoch
        or terminal_state is not terminal_proof.state
        or terminal_proof.target != configured_target
        or terminal_proof.root_id != root.root_id
        or terminal_proof.root_sha256 != root.root_sha256
        or terminal_proof.target_configuration_sha256
        != target_configuration_sha256
        or terminal_proof.evidence_id != progress.terminal_evidence_id
        or terminal_proof.evidence_sha256 != progress.terminal_evidence_sha256
        or terminal_proof.confirmed_by != "controlgraph.coordinator/v1"
        or terminal_proof.confirmed_at != progress.fenced_at
        or progress.terminal_subject.target != configured_target
        or progress.terminal_subject.root_id != root.root_id
        or progress.terminal_subject.root_sha256 != root.root_sha256
        or progress.terminal_subject.state is not terminal_state
        or progress.terminal_subject.target_configuration_sha256
        != target_configuration_sha256
        or progress.terminal_subject.receipt_id != terminal_receipt.receipt_id
        or progress.terminal_subject.receipt_sha256
        != canonical_sha256(terminal_receipt)
        or progress.terminal_subject.receipt_revision
        != expected.terminal_receipt.revision
        or progress.terminal_subject.receipt_epoch != terminal_receipt.epoch
        or progress.terminal_subject.receipt_action is not terminal_receipt.action
        or progress.terminal_subject.receipt_outcome is not ReceiptOutcome.VERIFIED
        or progress.terminal_subject.evidence_id
        != terminal_evidence.event.evidence_id
        or progress.terminal_subject.confirmed_by
        != "controlgraph.coordinator/v1"
        or progress.terminal_subject.confirmed_at != progress.fenced_at
        or terminal_evidence.event.root_id != root.root_id
        or terminal_evidence.event.root_sha256 != root.root_sha256
        or terminal_evidence.event.target != configured_target
        or terminal_evidence.event.epoch != terminal_receipt.epoch
        or terminal_evidence.event.kind is not EvidenceKind.TARGET_VERIFIED
        or terminal_evidence.event.actor != "controlgraph.coordinator/v1"
        or terminal_evidence.event.request_id != command.request_id
        or terminal_evidence.event.receipt_id != terminal_receipt.receipt_id
        or terminal_evidence.event.occurred_at != progress.fenced_at
        or terminal_evidence.event.subject_sha256
        != canonical_sha256(progress.terminal_subject)
        or terminal_evidence.event.target_configuration_sha256
        != target_configuration_sha256
        or terminal_evidence.signing_key_version
        != root.content.evidence_signing_key_version
        or progress.fence_subject.target != configured_target
        or progress.fence_subject.root_id != root.root_id
        or progress.fence_subject.root_sha256 != root.root_sha256
        or progress.fence_subject.request_sha256 != request_sha256
        or progress.fence_subject.request_id != command.request_id
        or progress.fence_subject.idempotency_key != command.idempotency_key
        or progress.fence_subject.operator_identity != invocation.operator_identity
        or progress.fence_subject.operator_subject != invocation.operator_subject
        or progress.fence_subject.replacement_claim_sha256 != canonical_sha256(claim)
        or progress.fence_subject.replacement_authority_sha256
        != canonical_sha256(authority)
        or progress.fence_subject.new_epoch != authority.current_epoch
        or progress.fence_subject.evidence_id != fence_evidence.event.evidence_id
        or progress.fence_subject.fenced_at != progress.fenced_at
        or fence_evidence.event.root_id != root.root_id
        or fence_evidence.event.root_sha256 != root.root_sha256
        or fence_evidence.event.target != configured_target
        or fence_evidence.event.epoch != authority.current_epoch
        or fence_evidence.event.kind is not EvidenceKind.EPOCH_ADVANCED
        or fence_evidence.event.actor != invocation.operator_identity
        or fence_evidence.event.request_id != command.request_id
        or fence_evidence.event.receipt_id is not None
        or fence_evidence.event.occurred_at != progress.fenced_at
        or fence_evidence.event.subject_sha256
        != canonical_sha256(progress.fence_subject)
        or fence_evidence.event.sequence != terminal_evidence.event.sequence + 1
        or fence_evidence.event.previous_event_sha256
        != progress.terminal_evidence_sha256
        or fence_evidence.event.reason_code is not None
        or fence_evidence.event.provider_operation is not None
        or fence_evidence.event.target_configuration_sha256 is not None
        or fence_evidence.signing_key_version
        != root.content.evidence_signing_key_version
        or request_identity.identity_kind
        is not ServiceClaimReleaseIdentityKind.REQUEST
        or request_identity.identity_value != command.request_id
        or idempotency_identity.identity_kind
        is not ServiceClaimReleaseIdentityKind.IDEMPOTENCY
        or idempotency_identity.identity_value != command.idempotency_key
        or request_identity.root_id != root.root_id
        or idempotency_identity.root_id != root.root_id
        or request_identity.root_sha256 != root.root_sha256
        or idempotency_identity.root_sha256 != root.root_sha256
        or request_identity.request_sha256 != request_sha256
        or idempotency_identity.request_sha256 != request_sha256
        or request_identity.result_id != progress.result_id
        or idempotency_identity.result_id != progress.result_id
        or request_identity.claimed_at != progress.fenced_at
        or idempotency_identity.claimed_at != progress.fenced_at
        or expected.progress.revision != 0
        or expected.request_identity.revision != 0
        or expected.idempotency_identity.revision != 0
        or expected.terminal_evidence.revision != 0
        or expected.fence_evidence.revision != 0
        or result.request_sha256 != request_sha256
        or result.result_id != progress.result_id
        or result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.root_id != root.root_id
        or result.root_sha256 != root.root_sha256
        or result.target != configured_target
        or result.operator_identity != invocation.operator_identity
        or result.operator_subject != invocation.operator_subject
        or result.terminal_receipt_id != progress.terminal_receipt_id
        or result.terminal_receipt_sha256 != progress.terminal_receipt_sha256
        or result.terminal_evidence_id != progress.terminal_evidence_id
        or result.terminal_evidence_sha256 != progress.terminal_evidence_sha256
        or result.fence_evidence_id != progress.fence_evidence_id
        or result.fence_evidence_sha256 != progress.fence_evidence_sha256
        or result.classification_subject != commit.classification_subject
        or result.release_subject != commit.release_subject
        or result.classification_evidence_id != classification_event.evidence_id
        or result.classification_evidence_sha256 != canonical_sha256(classification)
        or result.release_evidence_id != release_event.evidence_id
        or result.release_evidence_sha256 != canonical_sha256(release)
        or result.fenced_epoch != progress.fenced_epoch
        or result.fenced_authority_revision
        != progress.fenced_authority_revision
        or classification_subject.target != configured_target
        or classification_subject.root_id != root.root_id
        or classification_subject.root_sha256 != root.root_sha256
        or classification_subject.request_sha256 != request_sha256
        or classification_subject.classification is not expected_classification
        or classification_subject.fenced_epoch != progress.fenced_epoch
        or classification_subject.fenced_authority_revision
        != progress.fenced_authority_revision
        or classification_subject.target_configuration_sha256
        != target_configuration_sha256
        or classification_subject.service_generation
        <= claim.baseline_service_generation
        or classification_subject.evidence_id != classification_event.evidence_id
        or classification_subject.classified_by != expected_reader
        or classification_subject.classified_at != classification_event.occurred_at
        or classification_proof.target != configured_target
        or classification_proof.root_id != root.root_id
        or classification_proof.root_sha256 != root.root_sha256
        or classification_proof.classification is not expected_classification
        or classification_proof.fenced_epoch != progress.fenced_epoch
        or classification_proof.fenced_authority_revision
        != progress.fenced_authority_revision
        or classification_proof.service_generation
        != classification_subject.service_generation
        or classification_proof.provider_etag != classification_subject.provider_etag
        or classification_proof.target_configuration_sha256
        != target_configuration_sha256
        or classification_proof.evidence_id != classification_event.evidence_id
        or classification_proof.evidence_sha256 != canonical_sha256(classification)
        or classification_proof.classified_by != expected_reader
        or classification_proof.classified_at != classification_event.occurred_at
        or classification_event.evidence_id
        != service_claim_release_evidence_id(request_sha256, "classification")
        or classification_event.sequence != previous_head.sequence + 1
        or classification_event.previous_event_sha256
        != previous_head.evidence_sha256
        or classification_event.subject_sha256
        != canonical_sha256(commit.classification_subject)
        or classification_event.kind is not EvidenceKind.TARGET_VERIFIED
        or classification_event.root_id != root.root_id
        or classification_event.root_sha256 != root.root_sha256
        or classification_event.target != configured_target
        or classification_event.epoch != progress.fenced_epoch
        or classification_event.actor != expected_reader
        or classification_event.request_id != command.request_id
        or classification_event.receipt_id is not None
        or classification_event.occurred_at < previous_head.updated_at
        or classification_event.reason_code is not None
        or classification_event.provider_operation is not None
        or classification_event.target_configuration_sha256
        != target_configuration_sha256
        or commit.replacement_claim.released_by != "controlgraph.coordinator/v1"
        or commit.replacement_claim.release_request_id != command.request_id
        or commit.replacement_claim.target_classification_proof
        != classification_proof
        or release_subject.target != configured_target
        or release_subject.root_id != root.root_id
        or release_subject.root_sha256 != root.root_sha256
        or release_subject.request_sha256 != request_sha256
        or release_subject.request_id != command.request_id
        or release_subject.idempotency_key != command.idempotency_key
        or release_subject.operator_identity != invocation.operator_identity
        or release_subject.operator_subject != invocation.operator_subject
        or release_subject.classification_evidence_id
        != classification_event.evidence_id
        or release_subject.classification_evidence_sha256
        != canonical_sha256(classification)
        or release_subject.fenced_claim_sha256 != canonical_sha256(claim)
        or release_subject.released_claim_sha256
        != canonical_sha256(commit.replacement_claim)
        or release_subject.fenced_authority_sha256 != canonical_sha256(authority)
        or release_subject.fenced_epoch != progress.fenced_epoch
        or release_subject.fenced_authority_revision
        != progress.fenced_authority_revision
        or release_subject.evidence_id != release_event.evidence_id
        or release_subject.released_at != release_event.occurred_at
        or release_event.evidence_id
        != service_claim_release_evidence_id(request_sha256, "release")
        or release_event.sequence != classification_event.sequence + 1
        or release_event.previous_event_sha256 != canonical_sha256(classification)
        or release_event.subject_sha256 != canonical_sha256(commit.release_subject)
        or release_event.kind is not EvidenceKind.TARGET_VERIFIED
        or release_event.root_id != root.root_id
        or release_event.root_sha256 != root.root_sha256
        or release_event.target != configured_target
        or release_event.epoch != progress.fenced_epoch
        or release_event.actor != "controlgraph.coordinator/v1"
        or release_event.request_id != command.request_id
        or release_event.receipt_id is not None
        or release_event.occurred_at < classification_event.occurred_at
        or release_event.reason_code is not None
        or release_event.provider_operation is not None
        or release_event.target_configuration_sha256
        != target_configuration_sha256
        or commit.chain_head.root_id != release_event.root_id
        or commit.chain_head.root_sha256 != release_event.root_sha256
        or commit.chain_head.target != release_event.target
        or commit.chain_head.sequence != release_event.sequence
        or commit.chain_head.evidence_id != release_event.evidence_id
        or commit.chain_head.evidence_sha256 != canonical_sha256(release)
        or commit.chain_head.kind is not release_event.kind
        or commit.chain_head.epoch != release_event.epoch
        or commit.chain_head.updated_at != release_event.occurred_at
        or classification.signing_key_version
        != bundle.root.value.content.evidence_signing_key_version
        or release.signing_key_version
        != bundle.root.value.content.evidence_signing_key_version
        or result.classification_proof
        != commit.replacement_claim.target_classification_proof
        or result.release_evidence_id != commit.replacement_claim.release_evidence_id
        or result.released_at != commit.replacement_claim.released_at
        or result.released_at != release_event.occurred_at
    ):
        raise ValueError("service claim finalize commit is not exactly bound")


def _validate_released_takeover(
    configured_target: TargetBinding,
    expected_released_claim: StoredRecord[ServiceClaimRecordValue],
    root: RolloutRoot,
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
    *,
    verified_candidate_revision_configuration_sha256: str,
) -> None:
    _validate_initial_rollout(
        configured_target,
        root,
        claim,
        authority,
        verified_candidate_revision_configuration_sha256=(
            verified_candidate_revision_configuration_sha256
        ),
    )
    previous = expected_released_claim.value
    if type(previous) not in (ServiceClaimRecord, ServiceClaimRecordV3):
        raise TypeError("released claim takeover requires an exact service claim")
    if (
        previous.target != configured_target
        or previous.status is not ServiceClaimStatus.RELEASED
        or previous.root_id == root.root_id
        or previous.released_at is None
        or root.stable_snapshot.captured_at <= previous.released_at
        or claim.claimed_at < root.approved_at
    ):
        raise ValueError("new rollout does not follow one safely released claim")


def _content_addressed_root_target_configuration_sha256(
    root: RolloutRootV2 | RolloutRootV3,
    *,
    stable_percent: int,
    candidate_percent: int,
) -> str:
    if type(root) not in (RolloutRootV2, RolloutRootV3):
        raise TypeError("an exact content-addressed rollout root is required")
    plan = root.content.rollout_plan
    return target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=root.content.target,
            stable_revision=plan.stable_revision,
            candidate_revision=plan.candidate_revision,
            stable_percent=stable_percent,
            candidate_percent=candidate_percent,
            concurrency=plan.concurrency,
        )
    )


def _validate_released_takeover_content_addressed(
    configured_target: TargetBinding,
    expected_released_claim: StoredRecord[ServiceClaimRecordValue],
    root: RolloutRootV2 | RolloutRootV3,
    claim: ServiceClaimRecord,
) -> None:
    previous = expected_released_claim.value
    if type(previous) not in (ServiceClaimRecord, ServiceClaimRecordV3):
        raise TypeError("released claim takeover requires an exact service claim")
    if (
        previous.target != configured_target
        or previous.status is not ServiceClaimStatus.RELEASED
        or expected_released_claim.revision % 3 != 2
        or previous.root_id == root.root_id
        or previous.released_at is None
        or root.content.stable_snapshot.captured_at <= previous.released_at
        or claim.claimed_at < root.content.approved_at
    ):
        raise ValueError("new rollout does not follow one safely released claim")


def _validate_initial_root_creation_bundle(
    configured_target: TargetBinding,
    root: RolloutRootV3,
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
    lineage_anchor: CapabilityLineageAnchorV1,
    signed_evidence: SignedEvidenceEventV1,
    creation_result: RootCreationResultV2,
    expected_released_claim: StoredRecord[ServiceClaimRecordValue] | None,
) -> None:
    exact_records = (
        (root, RolloutRootV3),
        (claim, ServiceClaimRecord),
        (authority, EpochAuthorityRecord),
        (lineage_anchor, CapabilityLineageAnchorV1),
        (signed_evidence, SignedEvidenceEventV1),
        (creation_result, RootCreationResultV2),
    )
    if any(type(record) is not model_type for record, model_type in exact_records):
        raise TypeError("root creation requires exact bundle records")
    stable_configuration_sha256 = _content_addressed_root_target_configuration_sha256(
        root,
        stable_percent=100,
        candidate_percent=0,
    )
    candidate_configuration_sha256 = _content_addressed_root_target_configuration_sha256(
        root,
        stable_percent=0,
        candidate_percent=100,
    )
    if any(
        record_target != configured_target
        for record_target in (
            root.content.target,
            claim.target,
            authority.target,
            lineage_anchor.target,
            signed_evidence.event.target,
        )
    ):
        raise ValueError("root creation records do not match the configured target")
    if (
        creation_result.outcome != "CREATED"
        or creation_result.root != root
        or creation_result.initial_authority != authority
        or creation_result.lineage_anchor != lineage_anchor
        or creation_result.signed_evidence != signed_evidence
        or lineage_anchor != capability_lineage_anchor(root)
        or not active_service_claim_matches_root_v3(
            claim,
            root,
            stable_target_configuration_sha256=stable_configuration_sha256,
            candidate_target_configuration_sha256=candidate_configuration_sha256,
        )
        or creation_result.winner_service_claim_id != service_claim_logical_id(configured_target)
        or creation_result.winner_service_claim_sha256 != canonical_sha256(claim)
        or claim.claim_request_id != creation_result.winner_request_id
        or claim.claim_evidence_id != signed_evidence.event.evidence_id
        or claim.claimed_at != creation_result.created_at
        or authority.request_id != claim.claim_request_id
        or authority.evidence_id != claim.claim_evidence_id
        or authority.changed_at != claim.claimed_at
    ):
        raise ValueError("root creation records are not one atomic authority bundle")
    if expected_released_claim is not None:
        if type(expected_released_claim) is not StoredRecord:
            raise TypeError("released claim takeover requires an exact stored claim")
        _validate_released_takeover_content_addressed(
            configured_target,
            expected_released_claim,
            root,
            claim,
        )


def _validate_read_root_creation_bundle(
    configured_target: TargetBinding,
    bundle: RootCreationBundle,
) -> None:
    root = bundle.root.value
    claim = bundle.service_claim.value
    authority = bundle.authority.value
    anchor = bundle.lineage_anchor.value
    evidence = bundle.signed_evidence.value
    result = bundle.creation_result.value
    if any(
        record_target != configured_target
        for record_target in (
            root.content.target,
            claim.target,
            authority.target,
            anchor.target,
            evidence.event.target,
        )
    ):
        raise ValueError("root creation bundle target does not match configuration")
    if (
        bundle.root.revision != 0
        or bundle.lineage_anchor.revision != 0
        or bundle.signed_evidence.revision != 0
        or bundle.creation_result.revision != 0
        or result.outcome != "CREATED"
        or result.root != root
        or result.lineage_anchor != anchor
        or result.signed_evidence != evidence
        or anchor != capability_lineage_anchor(root)
        or authority.root_id != root.root_id
        or authority.root_sha256 != root.root_sha256
        or authority.revision != bundle.authority.revision
        or result.winner_service_claim_id != service_claim_logical_id(configured_target)
    ):
        raise ValueError("root creation bundle is incoherent")
    if claim.root_id == root.root_id:
        stable_configuration_sha256 = _content_addressed_root_target_configuration_sha256(
            root,
            stable_percent=100,
            candidate_percent=0,
        )
        candidate_configuration_sha256 = _content_addressed_root_target_configuration_sha256(
            root,
            stable_percent=0,
            candidate_percent=100,
        )
        if type(root) is RolloutRootV2:
            if type(claim) is not ServiceClaimRecord:
                raise ValueError("V2 root requires a V2 service claim")
            claim_matches = service_claim_matches_root_v2(
                claim,
                root,
                stable_target_configuration_sha256=stable_configuration_sha256,
                candidate_target_configuration_sha256=candidate_configuration_sha256,
            )
        else:
            root_v3 = cast(RolloutRootV3, root)
            claim_matches = service_claim_matches_root_v3(
                claim,
                root_v3,
                stable_target_configuration_sha256=stable_configuration_sha256,
                candidate_target_configuration_sha256=candidate_configuration_sha256,
            )
        if not claim_matches:
            raise ValueError("root creation bundle claim is incoherent")
        if bundle.service_claim.revision == 0 and (
            result.winner_service_claim_sha256 != canonical_sha256(claim)
        ):
            raise ValueError("root creation bundle initial claim digest does not match")


def _adopted_root_creation_result(
    result: RootCreationResultV1 | RootCreationResultV2,
) -> RootCreationResultV1 | RootCreationResultV2:
    if type(result) is RootCreationResultV1:
        return RootCreationResultV1.model_validate(
            {**result.model_dump(mode="python"), "outcome": "ADOPTED"}
        )
    if type(result) is RootCreationResultV2:
        return RootCreationResultV2.model_validate(
            {**result.model_dump(mode="python"), "outcome": "ADOPTED"}
        )
    raise TypeError("root creation adoption requires an exact result")


def _root_creation_bundle_matches_request(
    bundle: RootCreationBundle,
    *,
    root: RolloutRootV3,
    service_claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
    lineage_anchor: CapabilityLineageAnchorV1,
    signed_evidence: SignedEvidenceEventV1,
    creation_result: RootCreationResultV2,
) -> bool:
    return (
        bundle.root == StoredRecord(root, 0)
        and bundle.service_claim.value == service_claim
        and bundle.service_claim.revision % 3 == 0
        and bundle.authority == StoredRecord(authority, 0)
        and bundle.lineage_anchor == StoredRecord(lineage_anchor, 0)
        and bundle.signed_evidence == StoredRecord(signed_evidence, 0)
        and bundle.creation_result == StoredRecord(creation_result, 0)
    )


_RECEIPT_TRANSITIONS: Final = {
    ReceiptOutcome.CLAIMED: frozenset(
        {
            ReceiptOutcome.DENIED,
            ReceiptOutcome.APPLIED,
            ReceiptOutcome.FAILED_SAFE,
            ReceiptOutcome.AMBIGUOUS,
        }
    ),
    ReceiptOutcome.AMBIGUOUS: frozenset(
        {
            ReceiptOutcome.VERIFIED,
            ReceiptOutcome.AMBIGUOUS,
        }
    ),
    ReceiptOutcome.APPLIED: frozenset(
        {
            ReceiptOutcome.VERIFIED,
            ReceiptOutcome.AMBIGUOUS,
        }
    ),
}


def _receipt_semantic_binding(receipt: ExecutionReceipt) -> tuple[object, ...]:
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
        receipt.dispatch_not_after,
    )


def _receipt_cas_binding(receipt: ExecutionReceipt) -> tuple[object, ...]:
    return (
        *_receipt_semantic_binding(receipt),
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
    if _receipt_cas_binding(current) != _receipt_cas_binding(replacement):
        raise ValueError("receipt replacement changes an immutable binding")
    if replacement.outcome not in _RECEIPT_TRANSITIONS.get(current.outcome, frozenset()):
        raise ValueError("receipt replacement is not a permitted forward transition")
    if replacement.updated_at < current.updated_at:
        raise ValueError("receipt replacement moves time backwards")
    if replacement.evidence_ids[: len(current.evidence_ids)] != current.evidence_ids:
        raise ValueError("receipt replacement removes existing evidence")
    if (
        current.observed_authority_epoch is not None
        and replacement.observed_authority_epoch != current.observed_authority_epoch
    ) or (
        current.outcome is not ReceiptOutcome.CLAIMED
        and current.observed_authority_epoch is None
        and replacement.observed_authority_epoch is not None
    ):
        raise ValueError("receipt replacement changes its final authority observation")
    if (
        current.provider_operation is not None
        and replacement.provider_operation != current.provider_operation
    ) or (
        current.outcome is not ReceiptOutcome.CLAIMED
        and current.provider_operation is None
        and replacement.provider_operation is not None
    ):
        raise ValueError("receipt replacement changes its provider operation")
    if replacement == current:
        raise ValueError("receipt replacement does not change durable state")


def _reject_generic_readback_resolution_marker(
    replacement: ExecutionReceipt,
) -> None:
    if any(evidence_id.startswith("cgrrb:") for evidence_id in replacement.evidence_ids):
        raise ValueError("readback resolution evidence requires its dedicated operation")


def _validate_ambiguous_receipt_resolution(
    configured_target: TargetBinding,
    expected: StoredRecord[ExecutionReceipt],
    replacement: ExecutionReceipt,
    expected_authority: StoredRecord[EpochAuthorityRecord],
    expected_service_claim: StoredRecord[ServiceClaimRecord],
) -> None:
    _validate_receipt_replacement(configured_target, expected, replacement)
    before = expected.value
    authority = expected_authority.value
    claim = expected_service_claim.value
    if (
        type(authority) is not EpochAuthorityRecord
        or type(claim) is not ServiceClaimRecord
        or before.outcome is not ReceiptOutcome.AMBIGUOUS
        or before.reason_code is not ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS
        or before.provider_operation is None
        or before.observed_etag is None
        or before.observed_authority_epoch != before.epoch
        or replacement.outcome is not ReceiptOutcome.VERIFIED
        or replacement.reason_code is not None
        or replacement.observed_etag is None
        or len(replacement.evidence_ids) != len(before.evidence_ids) + 1
        or replacement.evidence_ids[:-1] != before.evidence_ids
        or _READBACK_RESOLUTION_MARKER.fullmatch(replacement.evidence_ids[-1]) is None
        or authority.target != configured_target
        or authority.root_id != before.root_id
        or authority.root_sha256 != before.root_sha256
        or authority.current_epoch != before.epoch
        or authority.revision != expected_authority.revision
        or claim.status is not ServiceClaimStatus.ACTIVE
        or expected_service_claim.revision % 3 != 0
        or claim.target != configured_target
        or claim.root_id != before.root_id
        or claim.root_sha256 != before.root_sha256
    ):
        raise ValueError("ambiguous receipt resolution fence is invalid")


def _validate_promotion_record(
    configured_target: TargetBinding,
    command: PromotionCommandV1,
    record: PromotionDispatchRecordV1,
) -> None:
    if type(command) is not PromotionCommandV1 or type(record) is not PromotionDispatchRecordV1:
        raise TypeError("promotion dispatch requires exact contracts")
    command_sha256 = promotion_command_sha256(command)
    if (
        record.target != configured_target
        or record.command_sha256 != command_sha256
        or record.dispatch_id != promotion_dispatch_id(command_sha256)
        or record.request_id != command.request_id
        or record.idempotency_key != command.idempotency_key
        or record.root_id != command.root_id
        or record.root_sha256 != command.expected_root_sha256
        or record.epoch != command.expected_epoch
        or record.scheduled_at != command.scheduled_at
        or record.verified_apply_receipt != command.verified_apply_receipt
        or record.source_receipt_sha256 != command.verified_apply_receipt.receipt_sha256
    ):
        raise ValueError("promotion dispatch does not match its command")


def _promotion_dispatch_identity(
    record: PromotionDispatchRecordV1,
    kind: PromotionDispatchIdentityKind,
) -> PromotionDispatchIdentityV1:
    identity_value = (
        record.request_id
        if kind is PromotionDispatchIdentityKind.REQUEST
        else record.idempotency_key
    )
    return PromotionDispatchIdentityV1(
        schema_version=PROMOTION_DISPATCH_IDENTITY_V1,
        identity_kind=kind,
        identity_value=identity_value,
        dispatch_id=record.dispatch_id,
        command_sha256=record.command_sha256,
        root_id=record.root_id,
        root_sha256=record.root_sha256,
        epoch=record.epoch,
        scheduled_at=record.scheduled_at,
        source_receipt_sha256=record.source_receipt_sha256,
        claimed_at=record.prepared_at,
    )


def _promotion_identity_matches_record(
    identity: PromotionDispatchIdentityV1,
    record: PromotionDispatchRecordV1,
    kind: PromotionDispatchIdentityKind,
) -> bool:
    return identity == _promotion_dispatch_identity(record, kind)


def _validate_promotion_replacement(
    configured_target: TargetBinding,
    expected: StoredRecord[PromotionDispatchRecordV1],
    replacement: PromotionDispatchRecordV1,
) -> None:
    if (
        type(expected) is not StoredRecord
        or type(expected.value) is not PromotionDispatchRecordV1
        or type(replacement) is not PromotionDispatchRecordV1
    ):
        raise TypeError("promotion compare-and-set requires exact records")
    current = expected.value
    if current.target != configured_target or replacement.target != configured_target:
        raise ValueError("promotion dispatch target does not match configuration")
    immutable_fields = (
        "schema_version",
        "dispatch_id",
        "command_sha256",
        "request_id",
        "idempotency_key",
        "target",
        "root_id",
        "root_sha256",
        "epoch",
        "scheduled_at",
        "verified_apply_receipt",
        "source_receipt_sha256",
        "task_sha256",
        "task_name",
        "task",
        "prepared_at",
    )
    if any(getattr(current, field) != getattr(replacement, field) for field in immutable_fields):
        raise ValueError("promotion replacement changes an immutable binding")
    terminal_states = {
        PromotionDispatchState.CREATED,
        PromotionDispatchState.DUPLICATE,
        PromotionDispatchState.AMBIGUOUS,
    }
    if current.state is PromotionDispatchState.PREPARED:
        valid = (
            expected.revision == 0
            and replacement.state is PromotionDispatchState.ENQUEUE_STARTED
            and replacement.enqueue_started_at is not None
            and replacement.terminal_at is None
            and replacement.result is None
        )
    elif current.state is PromotionDispatchState.ENQUEUE_STARTED:
        valid = (
            expected.revision == 1
            and replacement.state in terminal_states
            and replacement.enqueue_started_at == current.enqueue_started_at
            and replacement.terminal_at is not None
            and replacement.result is not None
        )
    else:
        valid = False
    if not valid:
        raise ValueError("promotion replacement is not a monotonic transition")


def _validate_promotion_record_v2(
    configured_target: TargetBinding,
    command: PromotionCommandV2,
    record: PromotionDispatchRecordV2,
) -> None:
    if type(command) is not PromotionCommandV2 or type(record) is not PromotionDispatchRecordV2:
        raise TypeError("V2 promotion dispatch requires exact contracts")
    command_sha256 = promotion_command_v2_sha256(command)
    if (
        record.target != configured_target
        or record.command_sha256 != command_sha256
        or record.dispatch_id != promotion_dispatch_v2_id(command_sha256)
        or record.request_id != command.request_id
        or record.idempotency_key != command.idempotency_key
        or record.root_id != command.root_id
        or record.root_sha256 != command.expected_root_sha256
        or record.epoch != command.expected_epoch
        or record.scheduled_at != command.scheduled_at
        or record.source_receipt_sha256
        != command.verified_apply_receipt.receipt_sha256
        or record.health_chain_sha256
        != command.health_chain_locator.health_chain_sha256
    ):
        raise ValueError("V2 promotion dispatch does not match its command")


def _promotion_dispatch_identity_v2(
    record: PromotionDispatchRecordV2,
    kind: PromotionDispatchIdentityKind,
) -> PromotionDispatchIdentityV2:
    identity_value = (
        record.request_id
        if kind is PromotionDispatchIdentityKind.REQUEST
        else record.idempotency_key
    )
    return PromotionDispatchIdentityV2(
        schema_version=PROMOTION_DISPATCH_IDENTITY_V2,
        identity_kind=kind,
        identity_value=identity_value,
        dispatch_id=record.dispatch_id,
        command_sha256=record.command_sha256,
        promotion_authorization_sha256=record.promotion_authorization_sha256,
        capability_id=record.capability_id,
        root_id=record.root_id,
        root_sha256=record.root_sha256,
        epoch=record.epoch,
        scheduled_at=record.scheduled_at,
        source_receipt_sha256=record.source_receipt_sha256,
        health_chain_sha256=record.health_chain_sha256,
        claimed_at=record.prepared_at,
    )


def _promotion_identity_matches_record_v2(
    identity: PromotionDispatchIdentityV2,
    record: PromotionDispatchRecordV2,
    kind: PromotionDispatchIdentityKind,
) -> bool:
    return identity == _promotion_dispatch_identity_v2(record, kind)


def _validate_promotion_replacement_v2(
    configured_target: TargetBinding,
    expected: StoredRecord[PromotionDispatchRecordV2],
    replacement: PromotionDispatchRecordV2,
) -> None:
    if (
        type(expected) is not StoredRecord
        or type(expected.value) is not PromotionDispatchRecordV2
        or type(replacement) is not PromotionDispatchRecordV2
    ):
        raise TypeError("V2 promotion compare-and-set requires exact records")
    current = expected.value
    if current.target != configured_target or replacement.target != configured_target:
        raise ValueError("V2 promotion dispatch target does not match configuration")
    immutable_fields = (
        "schema_version",
        "dispatch_id",
        "command_sha256",
        "promotion_authorization_sha256",
        "capability_id",
        "request_id",
        "idempotency_key",
        "target",
        "root_id",
        "root_sha256",
        "epoch",
        "scheduled_at",
        "source_receipt_sha256",
        "health_chain_sha256",
        "task_sha256",
        "task_name",
        "task",
        "prepared_at",
    )
    if any(getattr(current, field) != getattr(replacement, field) for field in immutable_fields):
        raise ValueError("V2 promotion replacement changes an immutable binding")
    terminal_states = {
        PromotionDispatchState.CREATED,
        PromotionDispatchState.DUPLICATE,
        PromotionDispatchState.AMBIGUOUS,
    }
    if current.state is PromotionDispatchState.PREPARED:
        valid = (
            expected.revision == 0
            and replacement.state is PromotionDispatchState.ENQUEUE_STARTED
            and replacement.enqueue_started_at is not None
            and replacement.terminal_at is None
            and replacement.result is None
        )
    elif current.state is PromotionDispatchState.ENQUEUE_STARTED:
        valid = (
            expected.revision == 1
            and replacement.state in terminal_states
            and replacement.enqueue_started_at == current.enqueue_started_at
            and replacement.terminal_at is not None
            and replacement.result is not None
        )
    else:
        valid = False
    if not valid:
        raise ValueError("V2 promotion replacement is not a monotonic transition")


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
                    for name in ("document", "get_all", "transaction")
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

    @staticmethod
    def _decode_service_claim_snapshot(
        snapshot: object,
        *,
        reference: _DocumentReferencePort,
        logical_id: str,
        document_id: str,
    ) -> _DecodedDocument[ServiceClaimRecordValue] | None:
        """Decode only the explicitly supported service-claim schema versions."""

        kind = AuthorityStorageKind.SERVICE_CLAIM
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
            try:
                raw_claim = json.loads(wrapper.canonical_payload)
            except (TypeError, ValueError):
                raise ValueError("service claim payload is invalid") from None
            if type(raw_claim) is not dict:
                raise ValueError("service claim payload is invalid")
            schema_version = raw_claim.get("schema_version")
            if schema_version == "controlgraph.service-claim/v2":
                value: ServiceClaimRecordValue = decode_contract(
                    wrapper.canonical_payload,
                    ServiceClaimRecord,
                )
            elif schema_version == "controlgraph.service-claim/v3":
                value = decode_contract(wrapper.canonical_payload, ServiceClaimRecordV3)
            else:
                raise ValueError("service claim schema version is unsupported")
            if canonical_sha256(value) != wrapper.payload_sha256:
                raise ValueError("storage payload digest does not match")
            return _DecodedDocument(wrapper=wrapper, value=value)
        except (AuthorityStoreCorruptRecord, asyncio.CancelledError):
            raise
        except Exception:
            raise AuthorityStoreCorruptRecord from None

    async def _strong_read_service_claim(
        self,
        *,
        logical_id: str,
        document_id: str,
    ) -> _DecodedDocument[ServiceClaimRecordValue] | None:
        client = await self._client()
        reference = self._reference(
            client,
            AuthorityStorageKind.SERVICE_CLAIM,
            document_id,
        )
        try:
            async with asyncio.timeout(FIRESTORE_OPERATION_TIMEOUT_SECONDS):
                snapshot = await self._get_snapshot(reference, transaction=None)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise
        except Exception:
            raise AuthorityStoreUnavailable from None
        return self._decode_service_claim_snapshot(
            snapshot,
            reference=reference,
            logical_id=logical_id,
            document_id=document_id,
        )

    async def _transaction_read_service_claim(
        self,
        transaction: _TransactionPort,
        *,
        reference: _DocumentReferencePort,
        logical_id: str,
        document_id: str,
    ) -> _DecodedDocument[ServiceClaimRecordValue] | None:
        snapshot = await self._get_snapshot(reference, transaction=transaction)
        return self._decode_service_claim_snapshot(
            snapshot,
            reference=reference,
            logical_id=logical_id,
            document_id=document_id,
        )

    async def _strong_read[ModelT: StrictContractModel](
        self,
        *,
        kind: AuthorityStorageKind,
        logical_id: str,
        document_id: str,
        model_type: type[ModelT],
    ) -> _DecodedDocument[ModelT] | None:
        decoded, _ = await self._strong_read_with_update_time(
            kind=kind,
            logical_id=logical_id,
            document_id=document_id,
            model_type=model_type,
        )
        return decoded

    async def _strong_read_with_update_time[ModelT: StrictContractModel](
        self,
        *,
        kind: AuthorityStorageKind,
        logical_id: str,
        document_id: str,
        model_type: type[ModelT],
    ) -> tuple[_DecodedDocument[ModelT] | None, datetime | None]:
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
        decoded = self._decode_snapshot(
            snapshot,
            reference=reference,
            kind=kind,
            logical_id=logical_id,
            document_id=document_id,
            model_type=model_type,
        )
        if decoded is None:
            return None, None
        try:
            update_time = _aware_utc(cast(_ProviderSnapshotPort, snapshot).update_time)
        except Exception:
            raise AuthorityStoreCorruptRecord from None
        return decoded, update_time

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

    async def _transaction_read_content_addressed_root(
        self,
        transaction: _TransactionPort,
        client: AsyncFirestoreAuthorityClientPort,
        root_id: str,
    ) -> _DecodedDocument[RolloutRootV2 | RolloutRootV3] | None:
        v2_document_id = rollout_root_v2_document_id(root_id)
        v3_document_id = rollout_root_v3_document_id(root_id)
        v2 = await self._transaction_read(
            transaction,
            reference=self._reference(
                client,
                AuthorityStorageKind.ROLLOUT_ROOT_V2,
                v2_document_id,
            ),
            kind=AuthorityStorageKind.ROLLOUT_ROOT_V2,
            logical_id=root_id,
            document_id=v2_document_id,
            model_type=RolloutRootV2,
        )
        v3 = await self._transaction_read(
            transaction,
            reference=self._reference(
                client,
                AuthorityStorageKind.ROLLOUT_ROOT_V3,
                v3_document_id,
            ),
            kind=AuthorityStorageKind.ROLLOUT_ROOT_V3,
            logical_id=root_id,
            document_id=v3_document_id,
            model_type=RolloutRootV3,
        )
        if v2 is not None and v3 is not None:
            raise AuthorityStoreCorruptRecord
        return cast(_DecodedDocument[RolloutRootV2 | RolloutRootV3] | None, v3 or v2)

    async def _transaction_read_root_creation_result(
        self,
        transaction: _TransactionPort,
        client: AsyncFirestoreAuthorityClientPort,
        root_id: str,
    ) -> _DecodedDocument[RootCreationResultV1 | RootCreationResultV2] | None:
        v1_document_id = root_creation_result_document_id(root_id)
        v2_document_id = root_creation_result_v2_document_id(root_id)
        v1 = await self._transaction_read(
            transaction,
            reference=self._reference(
                client,
                AuthorityStorageKind.ROOT_CREATION_RESULT,
                v1_document_id,
            ),
            kind=AuthorityStorageKind.ROOT_CREATION_RESULT,
            logical_id=root_id,
            document_id=v1_document_id,
            model_type=RootCreationResultV1,
        )
        v2 = await self._transaction_read(
            transaction,
            reference=self._reference(
                client,
                AuthorityStorageKind.ROOT_CREATION_RESULT_V2,
                v2_document_id,
            ),
            kind=AuthorityStorageKind.ROOT_CREATION_RESULT_V2,
            logical_id=root_id,
            document_id=v2_document_id,
            model_type=RootCreationResultV2,
        )
        if v1 is not None and v2 is not None:
            raise AuthorityStoreCorruptRecord
        return cast(
            _DecodedDocument[RootCreationResultV1 | RootCreationResultV2] | None,
            v2 or v1,
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
    ) -> _TransactionCommitDisposition:
        client = await self._client()

        async def execute() -> _TransactionCommitDisposition:
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
                await self._resolve_ambiguous(documents)
                return _TransactionCommitDisposition.READBACK_RESOLVED
            return _TransactionCommitDisposition.DIRECT_CONFIRMED

        operation = asyncio.create_task(execute())
        try:
            return await _await_shielded(
                operation,
                timeout_seconds=FIRESTORE_OPERATION_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            operation.add_done_callback(_consume_background_result)
            raise
        except TimeoutError:
            operation.add_done_callback(_consume_background_result)

        classification = asyncio.create_task(self._resolve_ambiguous(documents))
        try:
            await _await_shielded(
                classification,
                timeout_seconds=FIRESTORE_OPERATION_TIMEOUT_SECONDS,
            )
            return _TransactionCommitDisposition.READBACK_RESOLVED
        except asyncio.CancelledError:
            classification.add_done_callback(_consume_background_result)
            raise
        except TimeoutError:
            classification.add_done_callback(_consume_background_result)
            raise AuthorityStoreOutcomeUnknown from None

    async def _run_consistent_read(self, body: _TransactionBody) -> None:
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
        except AuthorityStoreCorruptRecord:
            raise
        except Exception:
            raise AuthorityStoreUnavailable from None

    async def create_rollout(
        self,
        root: RolloutRoot,
        service_claim: ServiceClaimRecord,
        authority: EpochAuthorityRecord,
        *,
        verified_candidate_revision_configuration_sha256: str,
    ) -> CreatedRollout:
        _validate_initial_rollout(
            self._target,
            root,
            service_claim,
            authority,
            verified_candidate_revision_configuration_sha256=(
                verified_candidate_revision_configuration_sha256
            ),
        )
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

    async def create_rollout_after_release(
        self,
        expected_released_claim: StoredRecord[ServiceClaimRecordValue],
        root: RolloutRoot,
        service_claim: ServiceClaimRecord,
        authority: EpochAuthorityRecord,
        *,
        verified_candidate_revision_configuration_sha256: str,
    ) -> CreatedRollout:
        _validate_released_takeover(
            self._target,
            expected_released_claim,
            root,
            service_claim,
            authority,
            verified_candidate_revision_configuration_sha256=(
                verified_candidate_revision_configuration_sha256
            ),
        )
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
            revision=expected_released_claim.revision + 1,
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

        async def replace(transaction: _TransactionPort) -> None:
            client = await self._client()
            claim_reference = self._reference(
                client,
                AuthorityStorageKind.SERVICE_CLAIM,
                claim_document.document_id,
            )
            current_claim = await self._transaction_read_service_claim(
                transaction,
                reference=claim_reference,
                logical_id=claim_logical_id,
                document_id=claim_document.document_id,
            )
            if current_claim is None or current_claim.stored != expected_released_claim:
                raise _ExpectedStateMismatch
            root_reference = self._reference(
                client,
                AuthorityStorageKind.ROLLOUT_ROOT,
                root_document.document_id,
            )
            authority_reference = self._reference(
                client,
                AuthorityStorageKind.EPOCH_AUTHORITY,
                authority_document.document_id,
            )
            transaction.create(root_reference, _document_data(root_document.wrapper))
            transaction.update(claim_reference, _document_data(claim_document.wrapper))
            transaction.create(
                authority_reference,
                _document_data(authority_document.wrapper),
            )

        await self._run_transaction(documents, replace)
        return CreatedRollout(
            root=_stored(root_document),
            service_claim=_stored(claim_document),
            authority=_stored(authority_document),
        )

    async def create_or_adopt_root_creation_bundle(
        self,
        root: RolloutRootV3,
        service_claim: ServiceClaimRecord,
        authority: EpochAuthorityRecord,
        lineage_anchor: CapabilityLineageAnchorV1,
        signed_evidence: SignedEvidenceEventV1,
        creation_result: RootCreationResultV2,
        *,
        expected_released_claim: StoredRecord[ServiceClaimRecordValue] | None = None,
    ) -> RootCreationWriteResult:
        _validate_initial_root_creation_bundle(
            self._target,
            root,
            service_claim,
            authority,
            lineage_anchor,
            signed_evidence,
            creation_result,
            expected_released_claim,
        )
        root_document = _prepared_document(
            kind=AuthorityStorageKind.ROLLOUT_ROOT_V3,
            logical_id=root.root_id,
            document_id=rollout_root_v3_document_id(root.root_id),
            revision=0,
            value=root,
        )
        claim_logical_id = service_claim_logical_id(self._target)
        claim_revision = (
            0 if expected_released_claim is None else expected_released_claim.revision + 1
        )
        claim_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=claim_logical_id,
            document_id=service_claim_document_id(self._target),
            revision=claim_revision,
            value=service_claim,
        )
        authority_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=authority.root_id,
            document_id=epoch_authority_document_id(authority.root_id),
            revision=0,
            value=authority,
        )
        anchor_logical_id = capability_lineage_anchor_logical_id(lineage_anchor)
        anchor_document = _prepared_document(
            kind=AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
            logical_id=anchor_logical_id,
            document_id=capability_lineage_anchor_document_id(lineage_anchor),
            revision=0,
            value=lineage_anchor,
        )
        evidence_logical_id = signed_evidence.event.evidence_id
        evidence_document = _prepared_document(
            kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            logical_id=evidence_logical_id,
            document_id=signed_evidence_event_document_id(evidence_logical_id),
            revision=0,
            value=signed_evidence,
        )
        result_document = _prepared_document(
            kind=AuthorityStorageKind.ROOT_CREATION_RESULT_V2,
            logical_id=root.root_id,
            document_id=root_creation_result_v2_document_id(root.root_id),
            revision=0,
            value=creation_result,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            root_document,
            claim_document,
            authority_document,
            anchor_document,
            evidence_document,
            result_document,
        )

        async def create(transaction: _TransactionPort) -> None:
            client = await self._client()
            existing_root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                root.root_id,
            )
            existing_result = await self._transaction_read_root_creation_result(
                transaction,
                client,
                root.root_id,
            )
            if (existing_root is None) != (existing_result is None):
                raise AuthorityStoreCorruptRecord
            if existing_root is not None:
                raise _ExpectedStateMismatch
            if expected_released_claim is None:
                for document in documents:
                    reference = self._reference(
                        client,
                        document.wrapper.record_kind,
                        document.document_id,
                    )
                    transaction.create(reference, _document_data(document.wrapper))
                return
            claim_reference = self._reference(
                client,
                AuthorityStorageKind.SERVICE_CLAIM,
                claim_document.document_id,
            )
            current_claim = await self._transaction_read_service_claim(
                transaction,
                reference=claim_reference,
                logical_id=claim_logical_id,
                document_id=claim_document.document_id,
            )
            if current_claim is None or current_claim.stored != expected_released_claim:
                raise _ExpectedStateMismatch
            for document in documents:
                if document is claim_document:
                    continue
                reference = self._reference(
                    client,
                    document.wrapper.record_kind,
                    document.document_id,
                )
                transaction.create(reference, _document_data(document.wrapper))
            transaction.update(claim_reference, _document_data(claim_document.wrapper))

        bundle = RootCreationBundle(
            root=_stored(root_document),
            service_claim=_stored(claim_document),
            authority=_stored(authority_document),
            lineage_anchor=_stored(anchor_document),
            signed_evidence=_stored(evidence_document),
            creation_result=_stored(result_document),
        )
        try:
            disposition = await self._run_transaction(documents, create)
        except AuthorityStoreConflict:
            existing = await self.read_root_creation_bundle(root.root_id)
            if existing is None or not _root_creation_bundle_matches_request(
                existing,
                root=root,
                service_claim=service_claim,
                authority=authority,
                lineage_anchor=lineage_anchor,
                signed_evidence=signed_evidence,
                creation_result=creation_result,
            ):
                raise
            return RootCreationWriteResult(
                result=_adopted_root_creation_result(existing.creation_result.value),
                bundle=existing,
            )
        result = (
            creation_result
            if disposition is _TransactionCommitDisposition.DIRECT_CONFIRMED
            else _adopted_root_creation_result(creation_result)
        )
        return RootCreationWriteResult(result=result, bundle=bundle)

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootCreationBundle | None:
        decoded_bundle: RootCreationBundle | None = None
        completed = False

        async def read(transaction: _TransactionPort) -> None:
            nonlocal completed, decoded_bundle
            client = await self._client()
            authority_document_id = epoch_authority_document_id(root_id)
            root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                root_id,
            )
            authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
            )
            creation_result = await self._transaction_read_root_creation_result(
                transaction,
                client,
                root_id,
            )
            root_specific = (root, authority, creation_result)
            if all(record is None for record in root_specific):
                completed = True
                return
            if any(record is None for record in root_specific):
                raise AuthorityStoreCorruptRecord
            decoded_root = cast(
                _DecodedDocument[RolloutRootV2 | RolloutRootV3],
                root,
            )
            decoded_authority = cast(_DecodedDocument[EpochAuthorityRecord], authority)
            decoded_result = cast(
                _DecodedDocument[RootCreationResultV1 | RootCreationResultV2],
                creation_result,
            )
            if (type(decoded_root.value), type(decoded_result.value)) not in (
                (RolloutRootV2, RootCreationResultV1),
                (RolloutRootV3, RootCreationResultV2),
            ):
                raise AuthorityStoreCorruptRecord
            result = decoded_result.value
            claim_logical_id = service_claim_logical_id(self._target)
            claim_document_id = service_claim_document_id(self._target)
            anchor_logical_id = result.winner_lineage_anchor_id
            anchor_document_id = capability_lineage_anchor_document_id(result.lineage_anchor)
            evidence_logical_id = result.winner_evidence_id
            evidence_document_id = signed_evidence_event_document_id(evidence_logical_id)
            claim = await self._transaction_read_service_claim(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document_id,
                ),
                logical_id=claim_logical_id,
                document_id=claim_document_id,
            )
            anchor = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
                    anchor_document_id,
                ),
                kind=AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
                logical_id=anchor_logical_id,
                document_id=anchor_document_id,
                model_type=CapabilityLineageAnchorV1,
            )
            evidence = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    evidence_document_id,
                ),
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=evidence_logical_id,
                document_id=evidence_document_id,
                model_type=SignedEvidenceEventV1,
            )
            if claim is None or anchor is None or evidence is None:
                raise AuthorityStoreCorruptRecord
            decoded_bundle = RootCreationBundle(
                root=decoded_root.stored,
                service_claim=claim.stored,
                authority=decoded_authority.stored,
                lineage_anchor=anchor.stored,
                signed_evidence=evidence.stored,
                creation_result=decoded_result.stored,
            )
            completed = True

        await self._run_consistent_read(read)
        if not completed:
            raise AuthorityStoreUnavailable
        if decoded_bundle is None:
            return None
        try:
            _validate_read_root_creation_bundle(self._target, decoded_bundle)
        except (TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None
        return decoded_bundle

    async def read_service_claim_release_state(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
    ) -> ServiceClaimReleaseState:
        """Read one complete release lifecycle view in a consistent transaction."""

        if type(invocation) is not ServiceClaimReleaseInvocationV1:
            raise TypeError("service claim release state requires an exact invocation")
        command = invocation.command
        request_sha256 = service_claim_release_request_sha256(invocation)
        result_id = f"cgrelease:{request_sha256}"
        decoded_state: ServiceClaimReleaseState | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal decoded_state
            client = await self._client()
            root_id = command.root_id
            authority_document_id = epoch_authority_document_id(root_id)
            decoded_root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                root_id,
            )
            decoded_authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
            )
            decoded_creation = await self._transaction_read_root_creation_result(
                transaction,
                client,
                root_id,
            )
            root_specific = (decoded_root, decoded_authority, decoded_creation)
            root_bundle: RootCreationBundle | None = None
            decoded_root_evidence: _DecodedDocument[SignedEvidenceEventV1] | None = None
            if any(value is not None for value in root_specific):
                if any(value is None for value in root_specific):
                    raise AuthorityStoreCorruptRecord
                root_record = cast(
                    _DecodedDocument[RolloutRootV2 | RolloutRootV3],
                    decoded_root,
                )
                authority_record = cast(
                    _DecodedDocument[EpochAuthorityRecord],
                    decoded_authority,
                )
                creation_record = cast(
                    _DecodedDocument[RootCreationResultV1 | RootCreationResultV2],
                    decoded_creation,
                )
                if (type(root_record.value), type(creation_record.value)) not in (
                    (RolloutRootV2, RootCreationResultV1),
                    (RolloutRootV3, RootCreationResultV2),
                ):
                    raise AuthorityStoreCorruptRecord
                creation = creation_record.value
                claim_logical_id = service_claim_logical_id(self._target)
                claim_document_id = service_claim_document_id(self._target)
                anchor_logical_id = creation.winner_lineage_anchor_id
                anchor_document_id = capability_lineage_anchor_document_id(
                    creation.lineage_anchor
                )
                root_evidence_id = creation.winner_evidence_id
                root_evidence_document_id = signed_evidence_event_document_id(
                    root_evidence_id
                )
                decoded_claim = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SERVICE_CLAIM,
                        claim_document_id,
                    ),
                    kind=AuthorityStorageKind.SERVICE_CLAIM,
                    logical_id=claim_logical_id,
                    document_id=claim_document_id,
                    model_type=ServiceClaimRecord,
                )
                decoded_anchor = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
                        anchor_document_id,
                    ),
                    kind=AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
                    logical_id=anchor_logical_id,
                    document_id=anchor_document_id,
                    model_type=CapabilityLineageAnchorV1,
                )
                decoded_root_evidence = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        root_evidence_document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=root_evidence_id,
                    document_id=root_evidence_document_id,
                    model_type=SignedEvidenceEventV1,
                )
                if (
                    decoded_claim is None
                    or decoded_anchor is None
                    or decoded_root_evidence is None
                ):
                    raise AuthorityStoreCorruptRecord
                root_bundle = RootCreationBundle(
                    root=root_record.stored,
                    service_claim=decoded_claim.stored,
                    authority=authority_record.stored,
                    lineage_anchor=decoded_anchor.stored,
                    signed_evidence=decoded_root_evidence.stored,
                    creation_result=creation_record.stored,
                )

            head_document_id = evidence_chain_head_document_id(root_id)
            decoded_head = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document_id,
                ),
                kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                logical_id=root_id,
                document_id=head_document_id,
                model_type=EvidenceChainHeadV1,
            )
            decoded_head_evidence: _DecodedDocument[SignedEvidenceEventV1] | None = None
            if decoded_head is not None:
                head_evidence_id = decoded_head.value.evidence_id
                if (
                    decoded_root_evidence is not None
                    and decoded_root_evidence.value.event.evidence_id == head_evidence_id
                ):
                    decoded_head_evidence = decoded_root_evidence
                else:
                    head_evidence_document_id = signed_evidence_event_document_id(
                        head_evidence_id
                    )
                    decoded_head_evidence = await self._transaction_read(
                        transaction,
                        reference=self._reference(
                            client,
                            AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                            head_evidence_document_id,
                        ),
                        kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        logical_id=head_evidence_id,
                        document_id=head_evidence_document_id,
                        model_type=SignedEvidenceEventV1,
                    )
                    if decoded_head_evidence is None:
                        raise AuthorityStoreCorruptRecord

            receipt_logical_id = execution_receipt_logical_id(
                self._target,
                command.terminal_receipt_idempotency_key,
            )
            receipt_document_id = execution_receipt_document_id(
                self._target,
                command.terminal_receipt_idempotency_key,
            )
            decoded_receipt = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EXECUTION_RECEIPT,
                    receipt_document_id,
                ),
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=receipt_logical_id,
                document_id=receipt_document_id,
                model_type=ExecutionReceipt,
            )

            async def release_evidence(
                stage: Literal["terminal", "fence", "classification", "release"],
            ) -> _DecodedDocument[SignedEvidenceEventV1] | None:
                evidence_id = service_claim_release_evidence_id(
                    request_sha256,
                    stage,
                )
                document_id = signed_evidence_event_document_id(evidence_id)
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=evidence_id,
                    document_id=document_id,
                    model_type=SignedEvidenceEventV1,
                )

            decoded_terminal_evidence = await release_evidence("terminal")
            decoded_fence_evidence = await release_evidence("fence")
            decoded_classification_evidence = await release_evidence("classification")
            decoded_release_evidence = await release_evidence("release")

            request_identity_logical_id = service_claim_release_identity_logical_id(
                ServiceClaimReleaseIdentityKind.REQUEST.value,
                command.request_id,
            )
            request_identity_document_id = service_claim_release_identity_document_id(
                ServiceClaimReleaseIdentityKind.REQUEST.value,
                command.request_id,
            )
            idempotency_identity_logical_id = (
                service_claim_release_identity_logical_id(
                    ServiceClaimReleaseIdentityKind.IDEMPOTENCY.value,
                    command.idempotency_key,
                )
            )
            idempotency_identity_document_id = (
                service_claim_release_identity_document_id(
                    ServiceClaimReleaseIdentityKind.IDEMPOTENCY.value,
                    command.idempotency_key,
                )
            )
            decoded_request_identity = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
                    request_identity_document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
                logical_id=request_identity_logical_id,
                document_id=request_identity_document_id,
                model_type=ServiceClaimReleaseIdentityV1,
            )
            decoded_idempotency_identity = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
                    idempotency_identity_document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
                logical_id=idempotency_identity_logical_id,
                document_id=idempotency_identity_document_id,
                model_type=ServiceClaimReleaseIdentityV1,
            )
            progress_document_id = service_claim_release_progress_document_id(
                result_id
            )
            decoded_progress = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS,
                    progress_document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS,
                logical_id=result_id,
                document_id=progress_document_id,
                model_type=ServiceClaimReleaseProgressV1,
            )
            result_document_id = service_claim_release_result_document_id(result_id)
            decoded_result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
                    result_document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
                logical_id=result_id,
                document_id=result_document_id,
                model_type=ServiceClaimReleaseResultV1,
            )
            decoded_state = ServiceClaimReleaseState(
                invocation=invocation,
                root_bundle=root_bundle,
                terminal_receipt=(
                    None if decoded_receipt is None else decoded_receipt.stored
                ),
                chain_head=None if decoded_head is None else decoded_head.stored,
                head_evidence=(
                    None
                    if decoded_head_evidence is None
                    else decoded_head_evidence.stored
                ),
                terminal_evidence=(
                    None
                    if decoded_terminal_evidence is None
                    else decoded_terminal_evidence.stored
                ),
                fence_evidence=(
                    None
                    if decoded_fence_evidence is None
                    else decoded_fence_evidence.stored
                ),
                classification_evidence=(
                    None
                    if decoded_classification_evidence is None
                    else decoded_classification_evidence.stored
                ),
                release_evidence=(
                    None
                    if decoded_release_evidence is None
                    else decoded_release_evidence.stored
                ),
                request_identity=(
                    None
                    if decoded_request_identity is None
                    else decoded_request_identity.stored
                ),
                idempotency_identity=(
                    None
                    if decoded_idempotency_identity is None
                    else decoded_idempotency_identity.stored
                ),
                progress=(
                    None if decoded_progress is None else decoded_progress.stored
                ),
                result=None if decoded_result is None else decoded_result.stored,
            )

        await self._run_consistent_read(read)
        if decoded_state is None:
            raise AuthorityStoreUnavailable
        if decoded_state.root_bundle is not None:
            try:
                _validate_read_root_creation_bundle(
                    self._target,
                    decoded_state.root_bundle,
                )
            except (TypeError, ValueError):
                raise AuthorityStoreCorruptRecord from None
        return decoded_state

    async def commit_service_claim_fence(
        self,
        expected: ServiceClaimReleaseState,
        commit: ServiceClaimReleaseFenceCommitV1,
    ) -> ServiceClaimFenceWriteResult:
        """Atomically append terminal/fence evidence and fence claim authority."""

        _validate_service_claim_fence_commit(self._target, expected, commit)
        root_bundle = cast(RootCreationBundle, expected.root_bundle)
        claim_logical_id = service_claim_logical_id(self._target)
        claim_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=claim_logical_id,
            document_id=service_claim_document_id(self._target),
            revision=root_bundle.service_claim.revision + 1,
            value=commit.replacement_claim,
        )
        authority_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=commit.replacement_authority.root_id,
            document_id=epoch_authority_document_id(
                commit.replacement_authority.root_id
            ),
            revision=root_bundle.authority.revision + 1,
            value=commit.replacement_authority,
        )

        def evidence_document(
            evidence: SignedEvidenceEventV1,
        ) -> _PreparedDocument[SignedEvidenceEventV1]:
            evidence_id = evidence.event.evidence_id
            return _prepared_document(
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=evidence_id,
                document_id=signed_evidence_event_document_id(evidence_id),
                revision=0,
                value=evidence,
            )

        terminal_document = evidence_document(commit.terminal_evidence)
        fence_document = evidence_document(commit.fence_evidence)
        head_document = _prepared_document(
            kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
            logical_id=commit.chain_head.root_id,
            document_id=evidence_chain_head_document_id(commit.chain_head.root_id),
            revision=commit.chain_head.sequence,
            value=commit.chain_head,
        )
        progress_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS,
            logical_id=commit.progress.result_id,
            document_id=service_claim_release_progress_document_id(
                commit.progress.result_id
            ),
            revision=0,
            value=commit.progress,
        )
        request_identity_logical_id = service_claim_release_identity_logical_id(
            commit.request_identity.identity_kind.value,
            commit.request_identity.identity_value,
        )
        request_identity_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
            logical_id=request_identity_logical_id,
            document_id=service_claim_release_identity_document_id(
                commit.request_identity.identity_kind.value,
                commit.request_identity.identity_value,
            ),
            revision=0,
            value=commit.request_identity,
        )
        idempotency_identity_logical_id = service_claim_release_identity_logical_id(
            commit.idempotency_identity.identity_kind.value,
            commit.idempotency_identity.identity_value,
        )
        idempotency_identity_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
            logical_id=idempotency_identity_logical_id,
            document_id=service_claim_release_identity_document_id(
                commit.idempotency_identity.identity_kind.value,
                commit.idempotency_identity.identity_value,
            ),
            revision=0,
            value=commit.idempotency_identity,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            claim_document,
            authority_document,
            terminal_document,
            fence_document,
            head_document,
            progress_document,
            request_identity_document,
            idempotency_identity_document,
        )

        async def write(transaction: _TransactionPort) -> None:
            client = await self._client()
            root_id = commit.progress.root_id
            current_root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                root_id,
            )
            current_claim = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document.document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=claim_logical_id,
                document_id=claim_document.document_id,
                model_type=ServiceClaimRecord,
            )
            current_authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document.document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=root_id,
                document_id=authority_document.document_id,
                model_type=EpochAuthorityRecord,
            )
            receipt = cast(StoredRecord[ExecutionReceipt], expected.terminal_receipt)
            receipt_document_id = execution_receipt_document_id(
                self._target,
                receipt.value.idempotency_key,
            )
            current_receipt = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EXECUTION_RECEIPT,
                    receipt_document_id,
                ),
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=execution_receipt_logical_id(
                    self._target,
                    receipt.value.idempotency_key,
                ),
                document_id=receipt_document_id,
                model_type=ExecutionReceipt,
            )
            current_head = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document.document_id,
                ),
                kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                logical_id=root_id,
                document_id=head_document.document_id,
                model_type=EvidenceChainHeadV1,
            )
            expected_predecessor = (
                root_bundle.signed_evidence
                if expected.chain_head is None
                else expected.head_evidence
            )
            if expected_predecessor is None:
                raise _ExpectedStateMismatch
            predecessor_id = expected_predecessor.value.event.evidence_id
            predecessor_document_id = signed_evidence_event_document_id(
                predecessor_id
            )
            current_predecessor = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    predecessor_document_id,
                ),
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=predecessor_id,
                document_id=predecessor_document_id,
                model_type=SignedEvidenceEventV1,
            )

            async def current[ModelT: StrictContractModel](
                document: _PreparedDocument[ModelT],
                model: type[ModelT],
            ) -> _DecodedDocument[ModelT] | None:
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        document.wrapper.record_kind,
                        document.document_id,
                    ),
                    kind=document.wrapper.record_kind,
                    logical_id=document.wrapper.logical_id,
                    document_id=document.document_id,
                    model_type=model,
                )

            current_terminal = await current(
                terminal_document,
                SignedEvidenceEventV1,
            )
            current_fence = await current(fence_document, SignedEvidenceEventV1)
            current_progress = await current(
                progress_document,
                ServiceClaimReleaseProgressV1,
            )
            current_request_identity = await current(
                request_identity_document,
                ServiceClaimReleaseIdentityV1,
            )
            current_idempotency_identity = await current(
                idempotency_identity_document,
                ServiceClaimReleaseIdentityV1,
            )
            request_sha256 = service_claim_release_request_sha256(
                expected.invocation
            )

            async def current_release_evidence(
                stage: Literal["classification", "release"],
            ) -> _DecodedDocument[SignedEvidenceEventV1] | None:
                evidence_id = service_claim_release_evidence_id(
                    request_sha256,
                    stage,
                )
                document_id = signed_evidence_event_document_id(evidence_id)
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=evidence_id,
                    document_id=document_id,
                    model_type=SignedEvidenceEventV1,
                )

            current_classification = await current_release_evidence(
                "classification"
            )
            current_release = await current_release_evidence("release")
            result_id = commit.progress.result_id
            result_document_id = service_claim_release_result_document_id(
                result_id
            )
            current_result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
                    result_document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
                logical_id=result_id,
                document_id=result_document_id,
                model_type=ServiceClaimReleaseResultV1,
            )
            if (
                current_root is None
                or current_root.stored != root_bundle.root
                or current_claim is None
                or current_claim.stored != root_bundle.service_claim
                or current_authority is None
                or current_authority.stored != root_bundle.authority
                or current_receipt is None
                or current_receipt.stored != receipt
                or (None if current_head is None else current_head.stored)
                != expected.chain_head
                or current_predecessor is None
                or current_predecessor.stored != expected_predecessor
                or current_terminal is not None
                or current_fence is not None
                or current_progress is not None
                or current_request_identity is not None
                or current_idempotency_identity is not None
                or current_classification is not None
                or current_release is not None
                or current_result is not None
            ):
                raise _ExpectedStateMismatch
            transaction.update(
                self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document.document_id,
                ),
                _document_data(claim_document.wrapper),
            )
            transaction.update(
                self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document.document_id,
                ),
                _document_data(authority_document.wrapper),
            )
            for evidence_document in (terminal_document, fence_document):
                transaction.create(
                    self._reference(
                        client,
                        evidence_document.wrapper.record_kind,
                        evidence_document.document_id,
                    ),
                    _document_data(evidence_document.wrapper),
                )
            head_reference = self._reference(
                client,
                AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
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
            for metadata_document in (
                progress_document,
                request_identity_document,
                idempotency_identity_document,
            ):
                transaction.create(
                    self._reference(
                        client,
                        metadata_document.wrapper.record_kind,
                        metadata_document.document_id,
                    ),
                    _document_data(metadata_document.wrapper),
                )

        await self._run_transaction(documents, write)
        return ServiceClaimFenceWriteResult(
            service_claim=_stored(claim_document),
            authority=_stored(authority_document),
            terminal_evidence=_stored(terminal_document),
            fence_evidence=_stored(fence_document),
            chain_head=_stored(head_document),
            progress=_stored(progress_document),
            request_identity=_stored(request_identity_document),
            idempotency_identity=_stored(idempotency_identity_document),
        )

    async def commit_service_claim_release(
        self,
        expected: ServiceClaimReleaseState,
        commit: ServiceClaimReleaseFinalizeCommitV1,
    ) -> ServiceClaimFinalizeWriteResult:
        """Atomically append verifier proof and finalize the fenced claim."""

        _validate_service_claim_finalize_commit(self._target, expected, commit)
        root_bundle = cast(RootCreationBundle, expected.root_bundle)
        claim_logical_id = service_claim_logical_id(self._target)
        claim_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=claim_logical_id,
            document_id=service_claim_document_id(self._target),
            revision=root_bundle.service_claim.revision + 1,
            value=commit.replacement_claim,
        )

        def evidence_document(
            evidence: SignedEvidenceEventV1,
        ) -> _PreparedDocument[SignedEvidenceEventV1]:
            evidence_id = evidence.event.evidence_id
            return _prepared_document(
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=evidence_id,
                document_id=signed_evidence_event_document_id(evidence_id),
                revision=0,
                value=evidence,
            )

        classification_document = evidence_document(commit.classification_evidence)
        release_document = evidence_document(commit.release_evidence)
        head_document = _prepared_document(
            kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
            logical_id=commit.chain_head.root_id,
            document_id=evidence_chain_head_document_id(commit.chain_head.root_id),
            revision=commit.chain_head.sequence,
            value=commit.chain_head,
        )
        result_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
            logical_id=commit.result.result_id,
            document_id=service_claim_release_result_document_id(
                commit.result.result_id
            ),
            revision=0,
            value=commit.result,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            claim_document,
            classification_document,
            release_document,
            head_document,
            result_document,
        )

        async def write(transaction: _TransactionPort) -> None:
            client = await self._client()
            root_id = commit.result.root_id
            current_root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                root_id,
            )
            current_claim = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document.document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=claim_logical_id,
                document_id=claim_document.document_id,
                model_type=ServiceClaimRecord,
            )
            authority_document_id = epoch_authority_document_id(root_id)
            current_authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
            )
            receipt = cast(
                StoredRecord[ExecutionReceipt],
                expected.terminal_receipt,
            )
            receipt_document_id = execution_receipt_document_id(
                self._target,
                receipt.value.idempotency_key,
            )
            current_receipt = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EXECUTION_RECEIPT,
                    receipt_document_id,
                ),
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=execution_receipt_logical_id(
                    self._target,
                    receipt.value.idempotency_key,
                ),
                document_id=receipt_document_id,
                model_type=ExecutionReceipt,
            )
            terminal_record = cast(
                StoredRecord[SignedEvidenceEventV1],
                expected.terminal_evidence,
            )
            terminal_document_id = signed_evidence_event_document_id(
                terminal_record.value.event.evidence_id
            )
            current_terminal = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    terminal_document_id,
                ),
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=terminal_record.value.event.evidence_id,
                document_id=terminal_document_id,
                model_type=SignedEvidenceEventV1,
            )
            current_head = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document.document_id,
                ),
                kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                logical_id=root_id,
                document_id=head_document.document_id,
                model_type=EvidenceChainHeadV1,
            )
            expected_predecessor = expected.head_evidence
            if expected_predecessor is None:
                raise _ExpectedStateMismatch
            predecessor_id = expected_predecessor.value.event.evidence_id
            predecessor_document_id = signed_evidence_event_document_id(
                predecessor_id
            )
            current_predecessor = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    predecessor_document_id,
                ),
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=predecessor_id,
                document_id=predecessor_document_id,
                model_type=SignedEvidenceEventV1,
            )
            progress = cast(
                StoredRecord[ServiceClaimReleaseProgressV1],
                expected.progress,
            )
            progress_document_id = service_claim_release_progress_document_id(
                progress.value.result_id
            )
            current_progress = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS,
                    progress_document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_PROGRESS,
                logical_id=progress.value.result_id,
                document_id=progress_document_id,
                model_type=ServiceClaimReleaseProgressV1,
            )

            async def identity(
                stored: StoredRecord[ServiceClaimReleaseIdentityV1] | None,
            ) -> _DecodedDocument[ServiceClaimReleaseIdentityV1] | None:
                if stored is None:
                    raise _ExpectedStateMismatch
                value = stored.value
                logical_id = service_claim_release_identity_logical_id(
                    value.identity_kind.value,
                    value.identity_value,
                )
                document_id = service_claim_release_identity_document_id(
                    value.identity_kind.value,
                    value.identity_value,
                )
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
                        document_id,
                    ),
                    kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_IDENTITY,
                    logical_id=logical_id,
                    document_id=document_id,
                    model_type=ServiceClaimReleaseIdentityV1,
                )

            current_request_identity = await identity(expected.request_identity)
            current_idempotency_identity = await identity(
                expected.idempotency_identity
            )

            async def evidence(
                document: _PreparedDocument[SignedEvidenceEventV1],
            ) -> _DecodedDocument[SignedEvidenceEventV1] | None:
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        document.document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=document.wrapper.logical_id,
                    document_id=document.document_id,
                    model_type=SignedEvidenceEventV1,
                )

            current_classification = await evidence(classification_document)
            current_release = await evidence(release_document)
            current_result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
                    result_document.document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
                logical_id=commit.result.result_id,
                document_id=result_document.document_id,
                model_type=ServiceClaimReleaseResultV1,
            )
            if (
                current_root is None
                or current_root.stored != root_bundle.root
                or current_claim is None
                or current_claim.stored != root_bundle.service_claim
                or current_authority is None
                or current_authority.stored != root_bundle.authority
                or current_receipt is None
                or current_receipt.stored != receipt
                or current_terminal is None
                or current_terminal.stored != terminal_record
                or current_head is None
                or current_head.stored != expected.chain_head
                or current_predecessor is None
                or current_predecessor.stored != expected_predecessor
                or current_progress is None
                or current_progress.stored != progress
                or current_request_identity is None
                or current_request_identity.stored != expected.request_identity
                or current_idempotency_identity is None
                or current_idempotency_identity.stored
                != expected.idempotency_identity
                or current_classification is not None
                or current_release is not None
                or current_result is not None
            ):
                raise _ExpectedStateMismatch
            transaction.update(
                self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document.document_id,
                ),
                _document_data(claim_document.wrapper),
            )
            for document in (classification_document, release_document):
                transaction.create(
                    self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        document.document_id,
                    ),
                    _document_data(document.wrapper),
                )
            transaction.update(
                self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document.document_id,
                ),
                _document_data(head_document.wrapper),
            )
            transaction.create(
                self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM_RELEASE_RESULT,
                    result_document.document_id,
                ),
                _document_data(result_document.wrapper),
            )

        await self._run_transaction(documents, write)
        return ServiceClaimFinalizeWriteResult(
            service_claim=_stored(claim_document),
            authority=root_bundle.authority,
            classification_evidence=_stored(classification_document),
            release_evidence=_stored(release_document),
            chain_head=_stored(head_document),
            result=_stored(result_document),
        )


    async def read_epoch_revocation_proof(
        self,
        command: EpochRevocationProofCommandV1,
    ) -> EpochRevocationProofState | None:
        """Read one authority, evidence, result, and audit by exact document keys."""

        if type(command) is not EpochRevocationProofCommandV1:
            raise TypeError("epoch revocation proof requires an exact command")
        decoded_state: EpochRevocationProofState | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal decoded_state
            client = await self._client()
            authority_document_id = epoch_authority_document_id(command.root_id)
            result_document_id = epoch_revocation_result_document_id(command.result_id)
            evidence_document_id = signed_evidence_event_document_id(command.evidence_id)
            audit_document_id = epoch_revocation_audit_document_id(command.audit_id)
            authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=command.root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
            )
            signed_evidence = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    evidence_document_id,
                ),
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=command.evidence_id,
                document_id=evidence_document_id,
                model_type=SignedEvidenceEventV1,
            )
            result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_RESULT,
                    result_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_RESULT,
                logical_id=command.result_id,
                document_id=result_document_id,
                model_type=EpochRevocationResultV1,
            )
            audit = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
                    audit_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
                logical_id=command.audit_id,
                document_id=audit_document_id,
                model_type=EpochRevocationAuditV1,
            )
            if any(value is None for value in (authority, signed_evidence, result, audit)):
                return
            decoded_state = EpochRevocationProofState(
                command=command,
                authority=cast(_DecodedDocument[EpochAuthorityRecord], authority).stored,
                signed_evidence=cast(
                    _DecodedDocument[SignedEvidenceEventV1],
                    signed_evidence,
                ).stored,
                result=cast(_DecodedDocument[EpochRevocationResultV1], result).stored,
                audit=cast(_DecodedDocument[EpochRevocationAuditV1], audit).stored,
            )

        await self._run_consistent_read(read)
        return decoded_state

    async def read_epoch_revocation_state(
        self,
        invocation: EpochRevocationInvocationV1,
    ) -> EpochRevocationState:
        """Read the exact root, chain, identities, and result in one transaction."""

        if type(invocation) is not EpochRevocationInvocationV1:
            raise TypeError("epoch revocation state requires an exact invocation")
        command = invocation.command
        request_sha256 = epoch_revocation_request_sha256(invocation)
        result_logical_id = f"cgrevoke:{request_sha256}"
        decoded_state: EpochRevocationState | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal decoded_state
            client = await self._client()
            root_id = command.root_id
            authority_document_id = epoch_authority_document_id(root_id)
            decoded_root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                root_id,
            )
            decoded_authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
            )
            decoded_creation_result = await self._transaction_read_root_creation_result(
                transaction,
                client,
                root_id,
            )
            root_specific = (
                decoded_root,
                decoded_authority,
                decoded_creation_result,
            )
            root_bundle: RootCreationBundle | None = None
            decoded_root_evidence: _DecodedDocument[SignedEvidenceEventV1] | None = None
            if any(record is not None for record in root_specific):
                if any(record is None for record in root_specific):
                    raise AuthorityStoreCorruptRecord
                root_record = cast(
                    _DecodedDocument[RolloutRootV2 | RolloutRootV3],
                    decoded_root,
                )
                authority_record = cast(
                    _DecodedDocument[EpochAuthorityRecord],
                    decoded_authority,
                )
                creation_record = cast(
                    _DecodedDocument[RootCreationResultV1 | RootCreationResultV2],
                    decoded_creation_result,
                )
                if (type(root_record.value), type(creation_record.value)) not in (
                    (RolloutRootV2, RootCreationResultV1),
                    (RolloutRootV3, RootCreationResultV2),
                ):
                    raise AuthorityStoreCorruptRecord
                creation = creation_record.value
                claim_logical_id = service_claim_logical_id(self._target)
                claim_document_id = service_claim_document_id(self._target)
                anchor_logical_id = creation.winner_lineage_anchor_id
                anchor_document_id = capability_lineage_anchor_document_id(creation.lineage_anchor)
                root_evidence_id = creation.winner_evidence_id
                root_evidence_document_id = signed_evidence_event_document_id(root_evidence_id)
                decoded_claim = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SERVICE_CLAIM,
                        claim_document_id,
                    ),
                    kind=AuthorityStorageKind.SERVICE_CLAIM,
                    logical_id=claim_logical_id,
                    document_id=claim_document_id,
                    model_type=ServiceClaimRecord,
                )
                decoded_anchor = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
                        anchor_document_id,
                    ),
                    kind=AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
                    logical_id=anchor_logical_id,
                    document_id=anchor_document_id,
                    model_type=CapabilityLineageAnchorV1,
                )
                decoded_root_evidence = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        root_evidence_document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=root_evidence_id,
                    document_id=root_evidence_document_id,
                    model_type=SignedEvidenceEventV1,
                )
                if decoded_claim is None or decoded_anchor is None or decoded_root_evidence is None:
                    raise AuthorityStoreCorruptRecord
                root_bundle = RootCreationBundle(
                    root=root_record.stored,
                    service_claim=decoded_claim.stored,
                    authority=authority_record.stored,
                    lineage_anchor=decoded_anchor.stored,
                    signed_evidence=decoded_root_evidence.stored,
                    creation_result=creation_record.stored,
                )

            head_document_id = evidence_chain_head_document_id(root_id)
            decoded_head = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document_id,
                ),
                kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                logical_id=root_id,
                document_id=head_document_id,
                model_type=EvidenceChainHeadV1,
            )
            decoded_head_evidence: _DecodedDocument[SignedEvidenceEventV1] | None = None
            if decoded_head is not None:
                if (
                    decoded_root_evidence is not None
                    and decoded_head.value.evidence_id
                    == decoded_root_evidence.value.event.evidence_id
                ):
                    decoded_head_evidence = decoded_root_evidence
                else:
                    head_evidence_id = decoded_head.value.evidence_id
                    head_evidence_document_id = signed_evidence_event_document_id(head_evidence_id)
                    decoded_head_evidence = await self._transaction_read(
                        transaction,
                        reference=self._reference(
                            client,
                            AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                            head_evidence_document_id,
                        ),
                        kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        logical_id=head_evidence_id,
                        document_id=head_evidence_document_id,
                        model_type=SignedEvidenceEventV1,
                    )
                    if decoded_head_evidence is None:
                        raise AuthorityStoreCorruptRecord

            request_identity_logical_id = epoch_revocation_identity_logical_id(
                EpochRevocationIdentityKind.REQUEST.value,
                command.request_id,
            )
            request_identity_document_id = epoch_revocation_identity_document_id(
                EpochRevocationIdentityKind.REQUEST.value,
                command.request_id,
            )
            idempotency_identity_logical_id = epoch_revocation_identity_logical_id(
                EpochRevocationIdentityKind.IDEMPOTENCY.value,
                command.idempotency_key,
            )
            idempotency_identity_document_id = epoch_revocation_identity_document_id(
                EpochRevocationIdentityKind.IDEMPOTENCY.value,
                command.idempotency_key,
            )
            decoded_request_identity = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
                    request_identity_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
                logical_id=request_identity_logical_id,
                document_id=request_identity_document_id,
                model_type=EpochRevocationIdentityV1,
            )
            decoded_idempotency_identity = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
                    idempotency_identity_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
                logical_id=idempotency_identity_logical_id,
                document_id=idempotency_identity_document_id,
                model_type=EpochRevocationIdentityV1,
            )
            result_document_id = epoch_revocation_result_document_id(result_logical_id)
            decoded_result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_RESULT,
                    result_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_RESULT,
                logical_id=result_logical_id,
                document_id=result_document_id,
                model_type=EpochRevocationResultV1,
            )
            decoded_result_evidence: _DecodedDocument[SignedEvidenceEventV1] | None = None
            if decoded_result is not None:
                result_evidence_id = decoded_result.value.evidence_id
                if (
                    decoded_head_evidence is not None
                    and decoded_head_evidence.value.event.evidence_id == result_evidence_id
                ):
                    decoded_result_evidence = decoded_head_evidence
                elif (
                    decoded_root_evidence is not None
                    and decoded_root_evidence.value.event.evidence_id == result_evidence_id
                ):
                    decoded_result_evidence = decoded_root_evidence
                else:
                    result_evidence_document_id = signed_evidence_event_document_id(
                        result_evidence_id
                    )
                    decoded_result_evidence = await self._transaction_read(
                        transaction,
                        reference=self._reference(
                            client,
                            AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                            result_evidence_document_id,
                        ),
                        kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        logical_id=result_evidence_id,
                        document_id=result_evidence_document_id,
                        model_type=SignedEvidenceEventV1,
                    )
                    if decoded_result_evidence is None:
                        raise AuthorityStoreCorruptRecord
            audit_document_id = epoch_revocation_audit_document_id(invocation.attempt_id)
            decoded_audit = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
                    audit_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
                logical_id=invocation.attempt_id,
                document_id=audit_document_id,
                model_type=EpochRevocationAuditV1,
            )
            decoded_state = EpochRevocationState(
                invocation=invocation,
                root_bundle=root_bundle,
                chain_head=None if decoded_head is None else decoded_head.stored,
                head_evidence=(
                    None if decoded_head_evidence is None else decoded_head_evidence.stored
                ),
                request_identity=(
                    None if decoded_request_identity is None else decoded_request_identity.stored
                ),
                idempotency_identity=(
                    None
                    if decoded_idempotency_identity is None
                    else decoded_idempotency_identity.stored
                ),
                result=None if decoded_result is None else decoded_result.stored,
                result_evidence=(
                    None if decoded_result_evidence is None else decoded_result_evidence.stored
                ),
                attempt_audit=(None if decoded_audit is None else decoded_audit.stored),
            )

        await self._run_consistent_read(read)
        if decoded_state is None:
            raise AuthorityStoreUnavailable
        if decoded_state.root_bundle is not None:
            try:
                _validate_read_root_creation_bundle(
                    self._target,
                    decoded_state.root_bundle,
                )
            except (TypeError, ValueError):
                raise AuthorityStoreCorruptRecord from None
        return decoded_state

    async def commit_epoch_revocation(
        self,
        expected: EpochRevocationState,
        commit: EpochRevocationCommitV1,
    ) -> EpochRevocationWriteResult:
        """Atomically advance authority and append the signed evidence bundle."""

        _validate_epoch_revocation_commit(self._target, expected, commit)
        root_bundle = cast(RootCreationBundle, expected.root_bundle)
        authority_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=commit.replacement_authority.root_id,
            document_id=epoch_authority_document_id(commit.replacement_authority.root_id),
            revision=commit.replacement_authority.revision,
            value=commit.replacement_authority,
        )
        evidence_id = commit.signed_evidence.event.evidence_id
        evidence_document = _prepared_document(
            kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            logical_id=evidence_id,
            document_id=signed_evidence_event_document_id(evidence_id),
            revision=0,
            value=commit.signed_evidence,
        )
        head_document = _prepared_document(
            kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
            logical_id=commit.chain_head.root_id,
            document_id=evidence_chain_head_document_id(commit.chain_head.root_id),
            revision=commit.chain_head.sequence,
            value=commit.chain_head,
        )
        result_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_REVOCATION_RESULT,
            logical_id=commit.result.result_id,
            document_id=epoch_revocation_result_document_id(commit.result.result_id),
            revision=0,
            value=commit.result,
        )
        request_identity_logical_id = epoch_revocation_identity_logical_id(
            commit.request_identity.identity_kind.value,
            commit.request_identity.identity_value,
        )
        request_identity_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
            logical_id=request_identity_logical_id,
            document_id=epoch_revocation_identity_document_id(
                commit.request_identity.identity_kind.value,
                commit.request_identity.identity_value,
            ),
            revision=0,
            value=commit.request_identity,
        )
        idempotency_identity_logical_id = epoch_revocation_identity_logical_id(
            commit.idempotency_identity.identity_kind.value,
            commit.idempotency_identity.identity_value,
        )
        idempotency_identity_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
            logical_id=idempotency_identity_logical_id,
            document_id=epoch_revocation_identity_document_id(
                commit.idempotency_identity.identity_kind.value,
                commit.idempotency_identity.identity_value,
            ),
            revision=0,
            value=commit.idempotency_identity,
        )
        audit_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
            logical_id=commit.audit.audit_id,
            document_id=epoch_revocation_audit_document_id(commit.audit.audit_id),
            revision=0,
            value=commit.audit,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            authority_document,
            evidence_document,
            head_document,
            result_document,
            request_identity_document,
            idempotency_identity_document,
            audit_document,
        )

        async def write(transaction: _TransactionPort) -> None:
            client = await self._client()
            root_id = commit.result.root_id
            current_root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                root_id,
            )
            claim_logical_id = service_claim_logical_id(self._target)
            claim_document_id = service_claim_document_id(self._target)
            current_claim = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=claim_logical_id,
                document_id=claim_document_id,
                model_type=ServiceClaimRecord,
            )
            current_authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document.document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=root_id,
                document_id=authority_document.document_id,
                model_type=EpochAuthorityRecord,
            )
            current_head = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document.document_id,
                ),
                kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                logical_id=root_id,
                document_id=head_document.document_id,
                model_type=EvidenceChainHeadV1,
            )
            expected_predecessor = (
                root_bundle.signed_evidence
                if expected.chain_head is None
                else expected.head_evidence
            )
            if expected_predecessor is None:
                raise _ExpectedStateMismatch
            predecessor_evidence_id = expected_predecessor.value.event.evidence_id
            predecessor_document_id = signed_evidence_event_document_id(predecessor_evidence_id)
            current_predecessor = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    predecessor_document_id,
                ),
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=predecessor_evidence_id,
                document_id=predecessor_document_id,
                model_type=SignedEvidenceEventV1,
            )
            current_request_identity = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
                    request_identity_document.document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
                logical_id=request_identity_logical_id,
                document_id=request_identity_document.document_id,
                model_type=EpochRevocationIdentityV1,
            )
            current_idempotency_identity = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
                    idempotency_identity_document.document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_IDENTITY,
                logical_id=idempotency_identity_logical_id,
                document_id=idempotency_identity_document.document_id,
                model_type=EpochRevocationIdentityV1,
            )
            current_result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_RESULT,
                    result_document.document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_RESULT,
                logical_id=commit.result.result_id,
                document_id=result_document.document_id,
                model_type=EpochRevocationResultV1,
            )
            current_audit = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
                    audit_document.document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
                logical_id=commit.audit.audit_id,
                document_id=audit_document.document_id,
                model_type=EpochRevocationAuditV1,
            )
            if (
                current_root is None
                or current_root.stored != root_bundle.root
                or current_claim is None
                or current_claim.stored != root_bundle.service_claim
                or current_authority is None
                or current_authority.stored != root_bundle.authority
                or (None if current_head is None else current_head.stored) != expected.chain_head
                or current_predecessor is None
                or current_predecessor.stored != expected_predecessor
                or (None if current_request_identity is None else current_request_identity.stored)
                != expected.request_identity
                or (
                    None
                    if current_idempotency_identity is None
                    else current_idempotency_identity.stored
                )
                != expected.idempotency_identity
                or (None if current_result is None else current_result.stored) != expected.result
                or (None if current_audit is None else current_audit.stored)
                != expected.attempt_audit
            ):
                raise _ExpectedStateMismatch
            authority_reference = self._reference(
                client,
                AuthorityStorageKind.EPOCH_AUTHORITY,
                authority_document.document_id,
            )
            head_reference = self._reference(
                client,
                AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                head_document.document_id,
            )
            transaction.update(
                authority_reference,
                _document_data(authority_document.wrapper),
            )
            transaction.create(
                self._reference(
                    client,
                    AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    evidence_document.document_id,
                ),
                _document_data(evidence_document.wrapper),
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
            for document in (
                result_document,
                request_identity_document,
                idempotency_identity_document,
                audit_document,
            ):
                transaction.create(
                    self._reference(
                        client,
                        document.wrapper.record_kind,
                        document.document_id,
                    ),
                    _document_data(document.wrapper),
                )

        await self._run_transaction(documents, write)
        return EpochRevocationWriteResult(
            authority=_stored(authority_document),
            signed_evidence=_stored(evidence_document),
            chain_head=_stored(head_document),
            result=_stored(result_document),
            request_identity=_stored(request_identity_document),
            idempotency_identity=_stored(idempotency_identity_document),
            audit=_stored(audit_document),
        )

    async def record_epoch_revocation_audit(
        self,
        audit: EpochRevocationAuditV1,
    ) -> StoredRecord[EpochRevocationAuditV1]:
        """Create or exactly adopt one immutable per-attempt audit record."""

        if type(audit) is not EpochRevocationAuditV1:
            raise TypeError("epoch revocation audit must be exact")
        document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
            logical_id=audit.audit_id,
            document_id=epoch_revocation_audit_document_id(audit.audit_id),
            revision=0,
            value=audit,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (document,)

        async def create(transaction: _TransactionPort) -> None:
            client = await self._client()
            transaction.create(
                self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
                    document.document_id,
                ),
                _document_data(document.wrapper),
            )

        try:
            await self._run_transaction(documents, create)
        except AuthorityStoreConflict:
            current = await self._strong_read(
                kind=AuthorityStorageKind.EPOCH_REVOCATION_AUDIT,
                logical_id=audit.audit_id,
                document_id=document.document_id,
                model_type=EpochRevocationAuditV1,
            )
            if current is None or current.value != audit or current.wrapper.revision != 0:
                raise
            return current.stored
        return _stored(document)

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

    async def read_service_claim(self) -> StoredRecord[ServiceClaimRecordValue] | None:
        logical_id = service_claim_logical_id(self._target)
        decoded = await self._strong_read_service_claim(
            logical_id=logical_id,
            document_id=service_claim_document_id(self._target),
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

    async def read_issuance_state(
        self,
        root_id: str,
    ) -> IssuanceStateSnapshot | None:
        decoded_state: _DecodedIssuanceState | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal decoded_state
            client = await self._client()
            root_document_id = rollout_root_document_id(root_id)
            claim_logical_id = service_claim_logical_id(self._target)
            claim_document_id = service_claim_document_id(self._target)
            authority_document_id = epoch_authority_document_id(root_id)
            root_reference = self._reference(
                client,
                AuthorityStorageKind.ROLLOUT_ROOT,
                root_document_id,
            )
            claim_reference = self._reference(
                client,
                AuthorityStorageKind.SERVICE_CLAIM,
                claim_document_id,
            )
            authority_reference = self._reference(
                client,
                AuthorityStorageKind.EPOCH_AUTHORITY,
                authority_document_id,
            )
            decoded_state = _DecodedIssuanceState(
                root=await self._transaction_read(
                    transaction,
                    reference=root_reference,
                    kind=AuthorityStorageKind.ROLLOUT_ROOT,
                    logical_id=root_id,
                    document_id=root_document_id,
                    model_type=RolloutRoot,
                ),
                service_claim=await self._transaction_read(
                    transaction,
                    reference=claim_reference,
                    kind=AuthorityStorageKind.SERVICE_CLAIM,
                    logical_id=claim_logical_id,
                    document_id=claim_document_id,
                    model_type=ServiceClaimRecord,
                ),
                authority=await self._transaction_read(
                    transaction,
                    reference=authority_reference,
                    kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                    logical_id=root_id,
                    document_id=authority_document_id,
                    model_type=EpochAuthorityRecord,
                ),
            )

        await self._run_consistent_read(read)
        if decoded_state is None:
            raise AuthorityStoreUnavailable
        present = tuple(
            value
            for value in (
                decoded_state.root,
                decoded_state.service_claim,
                decoded_state.authority,
            )
            if value is not None
        )
        if any(value.value.target != self._target for value in present):
            raise AuthorityStoreCorruptRecord
        if (
            decoded_state.root is None
            or decoded_state.service_claim is None
            or decoded_state.authority is None
        ):
            return None
        return IssuanceStateSnapshot(
            root=decoded_state.root.stored,
            service_claim=decoded_state.service_claim.stored,
            authority=decoded_state.authority.stored,
        )

    async def read_final_authority_snapshot(
        self,
        root_id: str,
    ) -> FinalAuthoritySnapshot | None:
        """Read the complete final fence with one strongly consistent BatchGet RPC."""

        client = await self._client()
        root_document_id = rollout_root_document_id(root_id)
        claim_logical_id = service_claim_logical_id(self._target)
        claim_document_id = service_claim_document_id(self._target)
        authority_document_id = epoch_authority_document_id(root_id)
        specs = (
            _FinalReadSpec(
                reference=self._reference(
                    client,
                    AuthorityStorageKind.ROLLOUT_ROOT,
                    root_document_id,
                ),
                kind=AuthorityStorageKind.ROLLOUT_ROOT,
                logical_id=root_id,
                document_id=root_document_id,
                model_type=RolloutRoot,
            ),
            _FinalReadSpec(
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document_id,
                ),
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=claim_logical_id,
                document_id=claim_document_id,
                model_type=ServiceClaimRecord,
            ),
            _FinalReadSpec(
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
            ),
        )
        expected = {spec.reference.path: spec for spec in specs}
        decoded: dict[str, _DecodedDocument[StrictContractModel] | None] = {}
        previous_read_time: datetime | None = None
        try:
            async with asyncio.timeout(FIRESTORE_OPERATION_TIMEOUT_SECONDS):
                snapshots = client.get_all(
                    [spec.reference for spec in specs],
                    field_paths=None,
                    transaction=None,
                    retry=None,
                    timeout=FIRESTORE_OPERATION_TIMEOUT_SECONDS,
                    read_time=None,
                )
                async for snapshot in snapshots:
                    try:
                        provider_snapshot = cast(_ProviderSnapshotPort, snapshot)
                        current_read_time = _aware_utc(provider_snapshot.read_time)
                        path = provider_snapshot.reference.path
                    except Exception:
                        raise AuthorityStoreCorruptRecord from None
                    if previous_read_time is not None and current_read_time < previous_read_time:
                        raise AuthorityStoreCorruptRecord
                    previous_read_time = current_read_time
                    spec = expected.get(path)
                    if spec is None or path in decoded:
                        raise AuthorityStoreCorruptRecord
                    decoded[path] = self._decode_snapshot(
                        snapshot,
                        reference=spec.reference,
                        kind=spec.kind,
                        logical_id=spec.logical_id,
                        document_id=spec.document_id,
                        model_type=spec.model_type,
                    )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise
        except Exception:
            raise AuthorityStoreUnavailable from None
        if set(decoded) != set(expected):
            raise AuthorityStoreCorruptRecord
        root = cast(
            _DecodedDocument[RolloutRoot] | None,
            decoded[specs[0].reference.path],
        )
        service_claim = cast(
            _DecodedDocument[ServiceClaimRecord] | None,
            decoded[specs[1].reference.path],
        )
        authority = cast(
            _DecodedDocument[EpochAuthorityRecord] | None,
            decoded[specs[2].reference.path],
        )
        present = tuple(value for value in (root, service_claim, authority) if value is not None)
        if any(value.value.target != self._target for value in present):
            raise AuthorityStoreCorruptRecord
        if root is None or service_claim is None or authority is None:
            return None
        return FinalAuthoritySnapshot(
            root=root.stored,
            service_claim=service_claim.stored,
            authority=authority.stored,
        )

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

        current, update_time = await self._strong_read_with_update_time(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=replacement.root_id,
            document_id=document.document_id,
            model_type=EpochAuthorityRecord,
        )
        if current is None or current.stored != expected or update_time is None:
            raise AuthorityStoreConflict
        write_option = firestore_v1.LastUpdateOption(update_time)

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            reference = self._reference(
                client,
                AuthorityStorageKind.EPOCH_AUTHORITY,
                epoch_authority_document_id(replacement.root_id),
            )
            transaction.update(
                reference,
                _document_data(document.wrapper),
                option=write_option,
            )

        await self._run_transaction(documents, update)
        return _stored(document)

    async def fence_service_claim(
        self,
        expected_claim: StoredRecord[ServiceClaimRecord],
        replacement_claim: ServiceClaimRecord,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        replacement_authority: EpochAuthorityRecord,
    ) -> FencedServiceClaim:
        _validate_claim_fence_authority(
            self._target,
            expected_claim,
            replacement_claim,
            expected_authority,
            replacement_authority,
        )
        logical_id = service_claim_logical_id(self._target)
        claim_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=logical_id,
            document_id=service_claim_document_id(self._target),
            revision=expected_claim.revision + 1,
            value=replacement_claim,
        )
        authority_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=replacement_authority.root_id,
            document_id=epoch_authority_document_id(replacement_authority.root_id),
            revision=expected_authority.revision + 1,
            value=replacement_authority,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            claim_document,
            authority_document,
        )

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            claim_reference = self._reference(
                client,
                AuthorityStorageKind.SERVICE_CLAIM,
                service_claim_document_id(self._target),
            )
            authority_reference = self._reference(
                client,
                AuthorityStorageKind.EPOCH_AUTHORITY,
                epoch_authority_document_id(replacement_authority.root_id),
            )
            current_claim = await self._transaction_read(
                transaction,
                reference=claim_reference,
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=logical_id,
                document_id=claim_document.document_id,
                model_type=ServiceClaimRecord,
            )
            current_authority = await self._transaction_read(
                transaction,
                reference=authority_reference,
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=replacement_authority.root_id,
                document_id=authority_document.document_id,
                model_type=EpochAuthorityRecord,
            )
            if (
                current_claim is None
                or current_claim.stored != expected_claim
                or current_authority is None
                or current_authority.stored != expected_authority
            ):
                raise _ExpectedStateMismatch
            transaction.update(
                claim_reference,
                _document_data(claim_document.wrapper),
            )
            transaction.update(
                authority_reference,
                _document_data(authority_document.wrapper),
            )

        await self._run_transaction(documents, update)
        return FencedServiceClaim(
            service_claim=_stored(claim_document),
            authority=_stored(authority_document),
        )

    async def release_service_claim(
        self,
        expected_claim: StoredRecord[ServiceClaimRecord],
        replacement_claim: ServiceClaimRecord,
        expected_authority: StoredRecord[EpochAuthorityRecord],
    ) -> ReleasedServiceClaim:
        _validate_claim_release(
            self._target,
            expected_claim,
            replacement_claim,
            expected_authority,
        )
        logical_id = service_claim_logical_id(self._target)
        claim_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=logical_id,
            document_id=service_claim_document_id(self._target),
            revision=expected_claim.revision + 1,
            value=replacement_claim,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (claim_document,)

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            claim_reference = self._reference(
                client,
                AuthorityStorageKind.SERVICE_CLAIM,
                claim_document.document_id,
            )
            authority_reference = self._reference(
                client,
                AuthorityStorageKind.EPOCH_AUTHORITY,
                epoch_authority_document_id(expected_authority.value.root_id),
            )
            current_claim = await self._transaction_read(
                transaction,
                reference=claim_reference,
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=logical_id,
                document_id=claim_document.document_id,
                model_type=ServiceClaimRecord,
            )
            current_authority = await self._transaction_read(
                transaction,
                reference=authority_reference,
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=expected_authority.value.root_id,
                document_id=epoch_authority_document_id(expected_authority.value.root_id),
                model_type=EpochAuthorityRecord,
            )
            if (
                current_claim is None
                or current_claim.stored != expected_claim
                or current_authority is None
                or current_authority.stored != expected_authority
            ):
                raise _ExpectedStateMismatch
            transaction.update(claim_reference, _document_data(claim_document.wrapper))

        await self._run_transaction(documents, update)
        return ReleasedServiceClaim(
            service_claim=_stored(claim_document),
            authority=expected_authority,
        )

    async def read_promotion_dispatch(
        self,
        command: PromotionCommandV1,
    ) -> StoredRecord[PromotionDispatchRecordV1] | None:
        """Read one command's identity ownership and exact dispatch atomically."""

        if type(command) is not PromotionCommandV1:
            raise TypeError("promotion dispatch read requires an exact command")
        command_sha256 = promotion_command_sha256(command)
        dispatch_id = promotion_dispatch_id(command_sha256)
        request_logical_id = promotion_dispatch_identity_logical_id(
            PromotionDispatchIdentityKind.REQUEST.value,
            command.request_id,
        )
        request_document_id = promotion_dispatch_identity_document_id(
            PromotionDispatchIdentityKind.REQUEST.value,
            command.request_id,
        )
        idempotency_logical_id = promotion_dispatch_identity_logical_id(
            PromotionDispatchIdentityKind.IDEMPOTENCY.value,
            command.idempotency_key,
        )
        idempotency_document_id = promotion_dispatch_identity_document_id(
            PromotionDispatchIdentityKind.IDEMPOTENCY.value,
            command.idempotency_key,
        )
        dispatch_document_id = promotion_dispatch_document_id(dispatch_id)
        decoded_request: _DecodedDocument[PromotionDispatchIdentityV1] | None = None
        decoded_idempotency: _DecodedDocument[PromotionDispatchIdentityV1] | None = None
        decoded_dispatch: _DecodedDocument[PromotionDispatchRecordV1] | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal decoded_request, decoded_idempotency, decoded_dispatch
            client = await self._client()
            decoded_request = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                    request_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                logical_id=request_logical_id,
                document_id=request_document_id,
                model_type=PromotionDispatchIdentityV1,
            )
            decoded_idempotency = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                    idempotency_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                logical_id=idempotency_logical_id,
                document_id=idempotency_document_id,
                model_type=PromotionDispatchIdentityV1,
            )
            decoded_dispatch = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH,
                    dispatch_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH,
                logical_id=dispatch_id,
                document_id=dispatch_document_id,
                model_type=PromotionDispatchRecordV1,
            )

        await self._run_consistent_read(read)
        source_sha256 = command.verified_apply_receipt.receipt_sha256

        def matches_command(
            decoded: _DecodedDocument[PromotionDispatchIdentityV1],
            kind: PromotionDispatchIdentityKind,
            value: str,
        ) -> bool:
            identity = decoded.value
            return (
                identity.identity_kind is kind
                and identity.identity_value == value
                and identity.dispatch_id == dispatch_id
                and identity.command_sha256 == command_sha256
                and identity.root_id == command.root_id
                and identity.root_sha256 == command.expected_root_sha256
                and identity.epoch == command.expected_epoch
                and identity.scheduled_at == command.scheduled_at
                and identity.source_receipt_sha256 == source_sha256
            )

        request_conflicts = decoded_request is not None and not matches_command(
            decoded_request,
            PromotionDispatchIdentityKind.REQUEST,
            command.request_id,
        )
        idempotency_conflicts = decoded_idempotency is not None and not matches_command(
            decoded_idempotency,
            PromotionDispatchIdentityKind.IDEMPOTENCY,
            command.idempotency_key,
        )
        if request_conflicts or idempotency_conflicts:
            if decoded_dispatch is not None:
                raise AuthorityStoreCorruptRecord
            raise AuthorityStoreConflict
        if decoded_request is None and decoded_idempotency is None and decoded_dispatch is None:
            return None
        if decoded_request is None or decoded_idempotency is None or decoded_dispatch is None:
            raise AuthorityStoreCorruptRecord
        record = decoded_dispatch.value
        try:
            _validate_promotion_record(self._target, command, record)
            if not _promotion_identity_matches_record(
                decoded_request.value,
                record,
                PromotionDispatchIdentityKind.REQUEST,
            ) or not _promotion_identity_matches_record(
                decoded_idempotency.value,
                record,
                PromotionDispatchIdentityKind.IDEMPOTENCY,
            ):
                raise ValueError("promotion ownership does not match its dispatch")
        except (TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None
        return decoded_dispatch.stored

    async def prepare_or_adopt_promotion_dispatch(
        self,
        command: PromotionCommandV1,
        prepared: PromotionDispatchRecordV1,
    ) -> StoredRecord[PromotionDispatchRecordV1]:
        """Atomically reserve both identities and persist the exact signed task."""

        _validate_promotion_record(self._target, command, prepared)
        if prepared.state is not PromotionDispatchState.PREPARED:
            raise ValueError("promotion preparation must be in PREPARED state")
        request_identity = _promotion_dispatch_identity(
            prepared,
            PromotionDispatchIdentityKind.REQUEST,
        )
        idempotency_identity = _promotion_dispatch_identity(
            prepared,
            PromotionDispatchIdentityKind.IDEMPOTENCY,
        )
        request_logical_id = promotion_dispatch_identity_logical_id(
            request_identity.identity_kind.value,
            request_identity.identity_value,
        )
        idempotency_logical_id = promotion_dispatch_identity_logical_id(
            idempotency_identity.identity_kind.value,
            idempotency_identity.identity_value,
        )
        request_document = _prepared_document(
            kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
            logical_id=request_logical_id,
            document_id=promotion_dispatch_identity_document_id(
                request_identity.identity_kind.value,
                request_identity.identity_value,
            ),
            revision=0,
            value=request_identity,
        )
        idempotency_document = _prepared_document(
            kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
            logical_id=idempotency_logical_id,
            document_id=promotion_dispatch_identity_document_id(
                idempotency_identity.identity_kind.value,
                idempotency_identity.identity_value,
            ),
            revision=0,
            value=idempotency_identity,
        )
        dispatch_document = _prepared_document(
            kind=AuthorityStorageKind.PROMOTION_DISPATCH,
            logical_id=prepared.dispatch_id,
            document_id=promotion_dispatch_document_id(prepared.dispatch_id),
            revision=0,
            value=prepared,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            request_document,
            idempotency_document,
            dispatch_document,
        )

        async def create(transaction: _TransactionPort) -> None:
            client = await self._client()
            request_reference = self._reference(
                client,
                AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                request_document.document_id,
            )
            idempotency_reference = self._reference(
                client,
                AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                idempotency_document.document_id,
            )
            dispatch_reference = self._reference(
                client,
                AuthorityStorageKind.PROMOTION_DISPATCH,
                dispatch_document.document_id,
            )
            existing_request = await self._transaction_read(
                transaction,
                reference=request_reference,
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                logical_id=request_logical_id,
                document_id=request_document.document_id,
                model_type=PromotionDispatchIdentityV1,
            )
            existing_idempotency = await self._transaction_read(
                transaction,
                reference=idempotency_reference,
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                logical_id=idempotency_logical_id,
                document_id=idempotency_document.document_id,
                model_type=PromotionDispatchIdentityV1,
            )
            existing_dispatch = await self._transaction_read(
                transaction,
                reference=dispatch_reference,
                kind=AuthorityStorageKind.PROMOTION_DISPATCH,
                logical_id=prepared.dispatch_id,
                document_id=dispatch_document.document_id,
                model_type=PromotionDispatchRecordV1,
            )
            if any(
                value is not None
                for value in (
                    existing_request,
                    existing_idempotency,
                    existing_dispatch,
                )
            ):
                raise _ExpectedStateMismatch
            transaction.create(
                request_reference,
                _document_data(request_document.wrapper),
            )
            transaction.create(
                idempotency_reference,
                _document_data(idempotency_document.wrapper),
            )
            transaction.create(
                dispatch_reference,
                _document_data(dispatch_document.wrapper),
            )

        try:
            await self._run_transaction(documents, create)
        except AuthorityStoreConflict:
            adopted = await self.read_promotion_dispatch(command)
            if adopted is None:
                raise AuthorityStoreOutcomeUnknown from None
            return adopted
        return _stored(dispatch_document)

    async def _compare_and_set_promotion_dispatch(
        self,
        expected: StoredRecord[PromotionDispatchRecordV1],
        replacement: PromotionDispatchRecordV1,
    ) -> tuple[
        StoredRecord[PromotionDispatchRecordV1],
        _TransactionCommitDisposition,
    ]:
        """Advance PREPARED to started or started to one immutable terminal state."""

        _validate_promotion_replacement(self._target, expected, replacement)
        current = expected.value
        request_identity = _promotion_dispatch_identity(
            current,
            PromotionDispatchIdentityKind.REQUEST,
        )
        idempotency_identity = _promotion_dispatch_identity(
            current,
            PromotionDispatchIdentityKind.IDEMPOTENCY,
        )
        request_logical_id = promotion_dispatch_identity_logical_id(
            request_identity.identity_kind.value,
            request_identity.identity_value,
        )
        idempotency_logical_id = promotion_dispatch_identity_logical_id(
            idempotency_identity.identity_kind.value,
            idempotency_identity.identity_value,
        )
        document = _prepared_document(
            kind=AuthorityStorageKind.PROMOTION_DISPATCH,
            logical_id=replacement.dispatch_id,
            document_id=promotion_dispatch_document_id(replacement.dispatch_id),
            revision=expected.revision + 1,
            value=replacement,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (document,)

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            request_document_id = promotion_dispatch_identity_document_id(
                request_identity.identity_kind.value,
                request_identity.identity_value,
            )
            idempotency_document_id = promotion_dispatch_identity_document_id(
                idempotency_identity.identity_kind.value,
                idempotency_identity.identity_value,
            )
            decoded_request = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                    request_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                logical_id=request_logical_id,
                document_id=request_document_id,
                model_type=PromotionDispatchIdentityV1,
            )
            decoded_idempotency = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                    idempotency_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY,
                logical_id=idempotency_logical_id,
                document_id=idempotency_document_id,
                model_type=PromotionDispatchIdentityV1,
            )
            if (
                decoded_request is None
                or decoded_idempotency is None
                or decoded_request.value != request_identity
                or decoded_idempotency.value != idempotency_identity
            ):
                raise AuthorityStoreCorruptRecord
            reference = self._reference(
                client,
                AuthorityStorageKind.PROMOTION_DISPATCH,
                document.document_id,
            )
            decoded_current = await self._transaction_read(
                transaction,
                reference=reference,
                kind=AuthorityStorageKind.PROMOTION_DISPATCH,
                logical_id=current.dispatch_id,
                document_id=document.document_id,
                model_type=PromotionDispatchRecordV1,
            )
            if decoded_current is None or decoded_current.stored != expected:
                raise _ExpectedStateMismatch
            transaction.update(reference, _document_data(document.wrapper))

        disposition = await self._run_transaction(documents, update)
        return _stored(document), disposition

    async def compare_and_set_promotion_dispatch(
        self,
        expected: StoredRecord[PromotionDispatchRecordV1],
        replacement: PromotionDispatchRecordV1,
    ) -> StoredRecord[PromotionDispatchRecordV1]:
        """Commit one non-dispatching promotion state transition."""

        if replacement.state is PromotionDispatchState.ENQUEUE_STARTED:
            raise ValueError("promotion enqueue starts require direct confirmation")
        stored, _ = await self._compare_and_set_promotion_dispatch(
            expected,
            replacement,
        )
        return stored

    async def begin_promotion_enqueue(
        self,
        expected: StoredRecord[PromotionDispatchRecordV1],
        replacement: PromotionDispatchRecordV1,
    ) -> DirectPromotionEnqueueStart:
        """Issue enqueue authority only for a directly confirmed start CAS."""

        if replacement.state is not PromotionDispatchState.ENQUEUE_STARTED:
            raise ValueError("promotion enqueue start requires ENQUEUE_STARTED")
        stored, disposition = await self._compare_and_set_promotion_dispatch(
            expected,
            replacement,
        )
        if disposition is not _TransactionCommitDisposition.DIRECT_CONFIRMED:
            raise AuthorityStoreOutcomeUnknown
        return DirectPromotionEnqueueStart(
            dispatch=stored,
            permit=PromotionEnqueuePermit._from_direct_store_start(stored),
        )

    async def read_promotion_dispatch_v2(
        self,
        command: PromotionCommandV2,
    ) -> StoredRecord[PromotionDispatchRecordV2] | None:
        """Read one V2 command's isolated identity ownership and exact dispatch."""

        if type(command) is not PromotionCommandV2:
            raise TypeError("V2 promotion dispatch read requires an exact command")
        command_sha256 = promotion_command_v2_sha256(command)
        dispatch_id = promotion_dispatch_v2_id(command_sha256)
        request_logical_id = promotion_dispatch_identity_v2_logical_id(
            PromotionDispatchIdentityKind.REQUEST.value,
            command.request_id,
        )
        request_document_id = promotion_dispatch_identity_v2_document_id(
            PromotionDispatchIdentityKind.REQUEST.value,
            command.request_id,
        )
        idempotency_logical_id = promotion_dispatch_identity_v2_logical_id(
            PromotionDispatchIdentityKind.IDEMPOTENCY.value,
            command.idempotency_key,
        )
        idempotency_document_id = promotion_dispatch_identity_v2_document_id(
            PromotionDispatchIdentityKind.IDEMPOTENCY.value,
            command.idempotency_key,
        )
        dispatch_document_id = promotion_dispatch_v2_document_id(dispatch_id)
        decoded_request: _DecodedDocument[PromotionDispatchIdentityV2] | None = None
        decoded_idempotency: _DecodedDocument[PromotionDispatchIdentityV2] | None = None
        decoded_dispatch: _DecodedDocument[PromotionDispatchRecordV2] | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal decoded_request, decoded_idempotency, decoded_dispatch
            client = await self._client()
            decoded_request = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                    request_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                logical_id=request_logical_id,
                document_id=request_document_id,
                model_type=PromotionDispatchIdentityV2,
            )
            decoded_idempotency = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                    idempotency_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                logical_id=idempotency_logical_id,
                document_id=idempotency_document_id,
                model_type=PromotionDispatchIdentityV2,
            )
            decoded_dispatch = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_V2,
                    dispatch_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_V2,
                logical_id=dispatch_id,
                document_id=dispatch_document_id,
                model_type=PromotionDispatchRecordV2,
            )

        await self._run_consistent_read(read)
        source_sha256 = command.verified_apply_receipt.receipt_sha256

        def matches_command(
            decoded: _DecodedDocument[PromotionDispatchIdentityV2],
            kind: PromotionDispatchIdentityKind,
            value: str,
        ) -> bool:
            identity = decoded.value
            return (
                identity.identity_kind is kind
                and identity.identity_value == value
                and identity.dispatch_id == dispatch_id
                and identity.command_sha256 == command_sha256
                and identity.root_id == command.root_id
                and identity.root_sha256 == command.expected_root_sha256
                and identity.epoch == command.expected_epoch
                and identity.scheduled_at == command.scheduled_at
                and identity.source_receipt_sha256 == source_sha256
                and identity.health_chain_sha256
                == command.health_chain_locator.health_chain_sha256
            )

        request_conflicts = decoded_request is not None and not matches_command(
            decoded_request,
            PromotionDispatchIdentityKind.REQUEST,
            command.request_id,
        )
        idempotency_conflicts = decoded_idempotency is not None and not matches_command(
            decoded_idempotency,
            PromotionDispatchIdentityKind.IDEMPOTENCY,
            command.idempotency_key,
        )
        if request_conflicts or idempotency_conflicts:
            if decoded_dispatch is not None:
                raise AuthorityStoreCorruptRecord
            raise AuthorityStoreConflict
        if decoded_request is None and decoded_idempotency is None and decoded_dispatch is None:
            return None
        if decoded_request is None or decoded_idempotency is None or decoded_dispatch is None:
            raise AuthorityStoreCorruptRecord
        record = decoded_dispatch.value
        try:
            _validate_promotion_record_v2(self._target, command, record)
            if not _promotion_identity_matches_record_v2(
                decoded_request.value,
                record,
                PromotionDispatchIdentityKind.REQUEST,
            ) or not _promotion_identity_matches_record_v2(
                decoded_idempotency.value,
                record,
                PromotionDispatchIdentityKind.IDEMPOTENCY,
            ):
                raise ValueError("V2 promotion ownership does not match its dispatch")
        except (TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None
        return decoded_dispatch.stored

    async def prepare_or_adopt_promotion_dispatch_v2(
        self,
        command: PromotionCommandV2,
        prepared: PromotionDispatchRecordV2,
    ) -> StoredRecord[PromotionDispatchRecordV2]:
        """Reserve both V2 identities and persist the exact authorized task."""

        _validate_promotion_record_v2(self._target, command, prepared)
        if prepared.state is not PromotionDispatchState.PREPARED:
            raise ValueError("V2 promotion preparation must be PREPARED")
        request_identity = _promotion_dispatch_identity_v2(
            prepared,
            PromotionDispatchIdentityKind.REQUEST,
        )
        idempotency_identity = _promotion_dispatch_identity_v2(
            prepared,
            PromotionDispatchIdentityKind.IDEMPOTENCY,
        )
        request_logical_id = promotion_dispatch_identity_v2_logical_id(
            request_identity.identity_kind.value,
            request_identity.identity_value,
        )
        idempotency_logical_id = promotion_dispatch_identity_v2_logical_id(
            idempotency_identity.identity_kind.value,
            idempotency_identity.identity_value,
        )
        request_document = _prepared_document(
            kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
            logical_id=request_logical_id,
            document_id=promotion_dispatch_identity_v2_document_id(
                request_identity.identity_kind.value,
                request_identity.identity_value,
            ),
            revision=0,
            value=request_identity,
        )
        idempotency_document = _prepared_document(
            kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
            logical_id=idempotency_logical_id,
            document_id=promotion_dispatch_identity_v2_document_id(
                idempotency_identity.identity_kind.value,
                idempotency_identity.identity_value,
            ),
            revision=0,
            value=idempotency_identity,
        )
        dispatch_document = _prepared_document(
            kind=AuthorityStorageKind.PROMOTION_DISPATCH_V2,
            logical_id=prepared.dispatch_id,
            document_id=promotion_dispatch_v2_document_id(prepared.dispatch_id),
            revision=0,
            value=prepared,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            request_document,
            idempotency_document,
            dispatch_document,
        )

        async def create(transaction: _TransactionPort) -> None:
            client = await self._client()
            request_reference = self._reference(
                client,
                AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                request_document.document_id,
            )
            idempotency_reference = self._reference(
                client,
                AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                idempotency_document.document_id,
            )
            dispatch_reference = self._reference(
                client,
                AuthorityStorageKind.PROMOTION_DISPATCH_V2,
                dispatch_document.document_id,
            )
            existing_request = await self._transaction_read(
                transaction,
                reference=request_reference,
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                logical_id=request_logical_id,
                document_id=request_document.document_id,
                model_type=PromotionDispatchIdentityV2,
            )
            existing_idempotency = await self._transaction_read(
                transaction,
                reference=idempotency_reference,
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                logical_id=idempotency_logical_id,
                document_id=idempotency_document.document_id,
                model_type=PromotionDispatchIdentityV2,
            )
            existing_dispatch = await self._transaction_read(
                transaction,
                reference=dispatch_reference,
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_V2,
                logical_id=prepared.dispatch_id,
                document_id=dispatch_document.document_id,
                model_type=PromotionDispatchRecordV2,
            )
            if any(
                value is not None
                for value in (existing_request, existing_idempotency, existing_dispatch)
            ):
                raise _ExpectedStateMismatch
            transaction.create(
                request_reference,
                _document_data(request_document.wrapper),
            )
            transaction.create(
                idempotency_reference,
                _document_data(idempotency_document.wrapper),
            )
            transaction.create(
                dispatch_reference,
                _document_data(dispatch_document.wrapper),
            )

        try:
            await self._run_transaction(documents, create)
        except AuthorityStoreConflict:
            adopted = await self.read_promotion_dispatch_v2(command)
            if adopted is None:
                raise AuthorityStoreOutcomeUnknown from None
            return adopted
        return _stored(dispatch_document)

    async def _compare_and_set_promotion_dispatch_v2(
        self,
        expected: StoredRecord[PromotionDispatchRecordV2],
        replacement: PromotionDispatchRecordV2,
    ) -> tuple[
        StoredRecord[PromotionDispatchRecordV2],
        _TransactionCommitDisposition,
    ]:
        """Advance one V2 dispatch through its closed monotonic state machine."""

        _validate_promotion_replacement_v2(self._target, expected, replacement)
        current = expected.value
        request_identity = _promotion_dispatch_identity_v2(
            current,
            PromotionDispatchIdentityKind.REQUEST,
        )
        idempotency_identity = _promotion_dispatch_identity_v2(
            current,
            PromotionDispatchIdentityKind.IDEMPOTENCY,
        )
        request_logical_id = promotion_dispatch_identity_v2_logical_id(
            request_identity.identity_kind.value,
            request_identity.identity_value,
        )
        idempotency_logical_id = promotion_dispatch_identity_v2_logical_id(
            idempotency_identity.identity_kind.value,
            idempotency_identity.identity_value,
        )
        document = _prepared_document(
            kind=AuthorityStorageKind.PROMOTION_DISPATCH_V2,
            logical_id=replacement.dispatch_id,
            document_id=promotion_dispatch_v2_document_id(replacement.dispatch_id),
            revision=expected.revision + 1,
            value=replacement,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (document,)

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            request_document_id = promotion_dispatch_identity_v2_document_id(
                request_identity.identity_kind.value,
                request_identity.identity_value,
            )
            idempotency_document_id = promotion_dispatch_identity_v2_document_id(
                idempotency_identity.identity_kind.value,
                idempotency_identity.identity_value,
            )
            decoded_request = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                    request_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                logical_id=request_logical_id,
                document_id=request_document_id,
                model_type=PromotionDispatchIdentityV2,
            )
            decoded_idempotency = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                    idempotency_document_id,
                ),
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_IDENTITY_V2,
                logical_id=idempotency_logical_id,
                document_id=idempotency_document_id,
                model_type=PromotionDispatchIdentityV2,
            )
            if (
                decoded_request is None
                or decoded_idempotency is None
                or decoded_request.value != request_identity
                or decoded_idempotency.value != idempotency_identity
            ):
                raise AuthorityStoreCorruptRecord
            reference = self._reference(
                client,
                AuthorityStorageKind.PROMOTION_DISPATCH_V2,
                document.document_id,
            )
            decoded_current = await self._transaction_read(
                transaction,
                reference=reference,
                kind=AuthorityStorageKind.PROMOTION_DISPATCH_V2,
                logical_id=current.dispatch_id,
                document_id=document.document_id,
                model_type=PromotionDispatchRecordV2,
            )
            if decoded_current is None or decoded_current.stored != expected:
                raise _ExpectedStateMismatch
            transaction.update(reference, _document_data(document.wrapper))

        disposition = await self._run_transaction(documents, update)
        return _stored(document), disposition

    async def compare_and_set_promotion_dispatch_v2(
        self,
        expected: StoredRecord[PromotionDispatchRecordV2],
        replacement: PromotionDispatchRecordV2,
    ) -> StoredRecord[PromotionDispatchRecordV2]:
        """Commit one non-dispatching V2 promotion state transition."""

        if replacement.state is PromotionDispatchState.ENQUEUE_STARTED:
            raise ValueError("V2 promotion enqueue starts require direct confirmation")
        stored, _ = await self._compare_and_set_promotion_dispatch_v2(
            expected,
            replacement,
        )
        return stored

    async def begin_promotion_enqueue_v2(
        self,
        expected: StoredRecord[PromotionDispatchRecordV2],
        replacement: PromotionDispatchRecordV2,
    ) -> DirectPromotionEnqueueStartV2:
        """Issue V2 enqueue authority only for a directly confirmed start CAS."""

        if replacement.state is not PromotionDispatchState.ENQUEUE_STARTED:
            raise ValueError("V2 promotion enqueue start requires ENQUEUE_STARTED")
        stored, disposition = await self._compare_and_set_promotion_dispatch_v2(
            expected,
            replacement,
        )
        if disposition is not _TransactionCommitDisposition.DIRECT_CONFIRMED:
            raise AuthorityStoreOutcomeUnknown
        return DirectPromotionEnqueueStartV2(
            dispatch=stored,
            permit=PromotionEnqueuePermitV2._from_direct_store_start(stored),
        )

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

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        if type(receipt) is not ExecutionReceipt:
            raise TypeError("receipt claim requires an exact receipt")
        validate_receipt_claim_binding(receipt, binding)
        logical_id = _validate_receipt_identity(self._target, receipt)
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

        try:
            disposition = await self._run_transaction(documents, create)
        except AuthorityStoreConflict:
            existing = await self.read_receipt(receipt.idempotency_key)
            if existing is None:
                raise AuthorityStoreOutcomeUnknown from None
            if _receipt_semantic_binding(existing.value) != _receipt_semantic_binding(receipt):
                return ReceiptClaimConflict()
            return ReceiptClaimAdopted(existing)

        claimed = _stored(document)
        if disposition is _TransactionCommitDisposition.DIRECT_CONFIRMED:
            direct_create = DirectReceiptCreate._from_direct_store_create(
                claimed,
                binding,
            )
            return ReceiptClaimCreated(claimed, direct_create)
        return ReceiptClaimAdopted(claimed)

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        _validate_receipt_replacement(self._target, expected, replacement)
        _reject_generic_readback_resolution_marker(replacement)
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

    async def resolve_ambiguous_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        expected_service_claim: StoredRecord[ServiceClaimRecord],
    ) -> StoredRecord[ExecutionReceipt]:
        """Resolve one receipt only while its exact active authority remains current."""

        _validate_ambiguous_receipt_resolution(
            self._target,
            expected,
            replacement,
            expected_authority,
            expected_service_claim,
        )
        receipt_logical_id = execution_receipt_logical_id(
            self._target,
            replacement.idempotency_key,
        )
        receipt_document = _prepared_document(
            kind=AuthorityStorageKind.EXECUTION_RECEIPT,
            logical_id=receipt_logical_id,
            document_id=execution_receipt_document_id(
                self._target,
                replacement.idempotency_key,
            ),
            revision=expected.revision + 1,
            value=replacement,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            receipt_document,
        )
        before = expected.value

        async def update(transaction: _TransactionPort) -> None:
            client = await self._client()
            receipt_reference = self._reference(
                client,
                AuthorityStorageKind.EXECUTION_RECEIPT,
                receipt_document.document_id,
            )
            authority_document_id = epoch_authority_document_id(before.root_id)
            authority_reference = self._reference(
                client,
                AuthorityStorageKind.EPOCH_AUTHORITY,
                authority_document_id,
            )
            claim_logical_id = service_claim_logical_id(self._target)
            claim_document_id = service_claim_document_id(self._target)
            claim_reference = self._reference(
                client,
                AuthorityStorageKind.SERVICE_CLAIM,
                claim_document_id,
            )
            current_receipt = await self._transaction_read(
                transaction,
                reference=receipt_reference,
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=receipt_logical_id,
                document_id=receipt_document.document_id,
                model_type=ExecutionReceipt,
            )
            current_authority = await self._transaction_read(
                transaction,
                reference=authority_reference,
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=before.root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
            )
            current_claim = await self._transaction_read(
                transaction,
                reference=claim_reference,
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=claim_logical_id,
                document_id=claim_document_id,
                model_type=ServiceClaimRecord,
            )
            if (
                current_receipt is None
                or current_receipt.stored != expected
                or current_authority is None
                or current_authority.stored != expected_authority
                or current_claim is None
                or current_claim.stored != expected_service_claim
            ):
                raise _ExpectedStateMismatch
            transaction.update(
                receipt_reference,
                _document_data(receipt_document.wrapper),
            )

        await self._run_transaction(documents, update)
        return _stored(receipt_document)


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
