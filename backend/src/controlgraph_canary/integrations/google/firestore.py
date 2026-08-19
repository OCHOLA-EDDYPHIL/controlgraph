"""Transactional Firestore adapter sealed to ControlGraph authority state."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
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
from controlgraph_canary.authority.replay import MutationBinding
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
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV2,
    RootCreationResultV1,
    SignedEvidenceEventV1,
    capability_lineage_anchor,
)
from controlgraph_canary.contracts.storage import (
    AUTHORITY_STORAGE_DOCUMENT_V1,
    AuthorityStorageDocument,
    AuthorityStorageKind,
    ServiceClaimRecord,
    ServiceClaimStatus,
    active_service_claim_matches_root,
    active_service_claim_matches_root_v2,
    capability_lineage_anchor_document_id,
    capability_lineage_anchor_logical_id,
    epoch_authority_document_id,
    execution_receipt_document_id,
    execution_receipt_logical_id,
    rollout_root_document_id,
    rollout_root_v2_document_id,
    root_creation_result_document_id,
    service_claim_document_id,
    service_claim_logical_id,
    service_claim_matches_root_v2,
    signed_evidence_event_document_id,
)

FIRESTORE_AUTHORITY_DATABASE: Final = "controlgraph-authority"
FIRESTORE_AUTHORITY_REGION: Final = "us-central1"
FIRESTORE_OPERATION_TIMEOUT_SECONDS: Final = 5.0
FIRESTORE_MAX_TRANSACTION_ATTEMPTS: Final = 3

_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_SHA256_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
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
        or _SHA256_DIGEST.fullmatch(
            verified_candidate_revision_configuration_sha256
        )
        is None
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
        or replacement_claim.release_fence_epoch
        != replacement_authority.current_epoch
        or replacement_claim.release_fence_authority_revision
        != replacement_authority.revision
        or replacement_claim.release_fenced_by != replacement_authority.changed_by
        or replacement_claim.release_fence_request_id
        != replacement_authority.request_id
        or replacement_claim.release_fence_evidence_id
        != replacement_authority.evidence_id
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
        or replacement_claim.release_fence_request_id
        != current.release_fence_request_id
        or replacement_claim.release_fence_evidence_id
        != current.release_fence_evidence_id
        or replacement_claim.release_fenced_at != current.release_fenced_at
        or replacement_claim.terminal_root_proof != current.terminal_root_proof
        or authority.target != current.target
        or authority.root_id != current.root_id
        or authority.root_sha256 != current.root_sha256
        or authority.current_epoch != current.release_fence_epoch
        or authority.revision != current.release_fence_authority_revision
        or expected_authority.revision != authority.revision
        or authority.changed_at != current.release_fenced_at
    ):
        raise ValueError("service claim replacement is not an exact fenced release")


def _validate_released_takeover(
    configured_target: TargetBinding,
    expected_released_claim: StoredRecord[ServiceClaimRecord],
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
    if type(previous) is not ServiceClaimRecord:
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


def _rollout_root_v2_target_configuration_sha256(
    root: RolloutRootV2,
    *,
    stable_percent: int,
    candidate_percent: int,
) -> str:
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


def _validate_released_takeover_v2(
    configured_target: TargetBinding,
    expected_released_claim: StoredRecord[ServiceClaimRecord],
    root: RolloutRootV2,
    claim: ServiceClaimRecord,
) -> None:
    previous = expected_released_claim.value
    if type(previous) is not ServiceClaimRecord:
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
    root: RolloutRootV2,
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
    lineage_anchor: CapabilityLineageAnchorV1,
    signed_evidence: SignedEvidenceEventV1,
    creation_result: RootCreationResultV1,
    expected_released_claim: StoredRecord[ServiceClaimRecord] | None,
) -> None:
    exact_records = (
        (root, RolloutRootV2),
        (claim, ServiceClaimRecord),
        (authority, EpochAuthorityRecord),
        (lineage_anchor, CapabilityLineageAnchorV1),
        (signed_evidence, SignedEvidenceEventV1),
        (creation_result, RootCreationResultV1),
    )
    if any(type(record) is not model_type for record, model_type in exact_records):
        raise TypeError("root creation requires exact bundle records")
    stable_configuration_sha256 = _rollout_root_v2_target_configuration_sha256(
        root,
        stable_percent=100,
        candidate_percent=0,
    )
    candidate_configuration_sha256 = _rollout_root_v2_target_configuration_sha256(
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
        or not active_service_claim_matches_root_v2(
            claim,
            root,
            stable_target_configuration_sha256=stable_configuration_sha256,
            candidate_target_configuration_sha256=candidate_configuration_sha256,
        )
        or creation_result.winner_service_claim_id
        != service_claim_logical_id(configured_target)
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
        _validate_released_takeover_v2(
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
        stable_configuration_sha256 = _rollout_root_v2_target_configuration_sha256(
            root,
            stable_percent=100,
            candidate_percent=0,
        )
        candidate_configuration_sha256 = _rollout_root_v2_target_configuration_sha256(
            root,
            stable_percent=0,
            candidate_percent=100,
        )
        if not service_claim_matches_root_v2(
            claim,
            root,
            stable_target_configuration_sha256=stable_configuration_sha256,
            candidate_target_configuration_sha256=candidate_configuration_sha256,
        ):
            raise ValueError("root creation bundle claim is incoherent")
        if bundle.service_claim.revision == 0 and (
            result.winner_service_claim_sha256 != canonical_sha256(claim)
        ):
            raise ValueError("root creation bundle initial claim digest does not match")


def _adopted_root_creation_result(result: RootCreationResultV1) -> RootCreationResultV1:
    return RootCreationResultV1.model_validate(
        {**result.model_dump(mode="python"), "outcome": "ADOPTED"}
    )


def _root_creation_bundle_matches_request(
    bundle: RootCreationBundle,
    *,
    root: RolloutRootV2,
    service_claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
    lineage_anchor: CapabilityLineageAnchorV1,
    signed_evidence: SignedEvidenceEventV1,
    creation_result: RootCreationResultV1,
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
        expected_released_claim: StoredRecord[ServiceClaimRecord],
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
            current_claim = await self._transaction_read(
                transaction,
                reference=claim_reference,
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=claim_logical_id,
                document_id=claim_document.document_id,
                model_type=ServiceClaimRecord,
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
        root: RolloutRootV2,
        service_claim: ServiceClaimRecord,
        authority: EpochAuthorityRecord,
        lineage_anchor: CapabilityLineageAnchorV1,
        signed_evidence: SignedEvidenceEventV1,
        creation_result: RootCreationResultV1,
        *,
        expected_released_claim: StoredRecord[ServiceClaimRecord] | None = None,
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
            kind=AuthorityStorageKind.ROLLOUT_ROOT_V2,
            logical_id=root.root_id,
            document_id=rollout_root_v2_document_id(root.root_id),
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
            kind=AuthorityStorageKind.ROOT_CREATION_RESULT,
            logical_id=root.root_id,
            document_id=root_creation_result_document_id(root.root_id),
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
            current_claim = await self._transaction_read(
                transaction,
                reference=claim_reference,
                kind=AuthorityStorageKind.SERVICE_CLAIM,
                logical_id=claim_logical_id,
                document_id=claim_document.document_id,
                model_type=ServiceClaimRecord,
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
            root_document_id = rollout_root_v2_document_id(root_id)
            authority_document_id = epoch_authority_document_id(root_id)
            result_document_id = root_creation_result_document_id(root_id)
            root = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.ROLLOUT_ROOT_V2,
                    root_document_id,
                ),
                kind=AuthorityStorageKind.ROLLOUT_ROOT_V2,
                logical_id=root_id,
                document_id=root_document_id,
                model_type=RolloutRootV2,
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
            creation_result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.ROOT_CREATION_RESULT,
                    result_document_id,
                ),
                kind=AuthorityStorageKind.ROOT_CREATION_RESULT,
                logical_id=root_id,
                document_id=result_document_id,
                model_type=RootCreationResultV1,
            )
            root_specific = (root, authority, creation_result)
            if all(record is None for record in root_specific):
                completed = True
                return
            if any(record is None for record in root_specific):
                raise AuthorityStoreCorruptRecord
            decoded_root = cast(_DecodedDocument[RolloutRootV2], root)
            decoded_authority = cast(_DecodedDocument[EpochAuthorityRecord], authority)
            decoded_result = cast(
                _DecodedDocument[RootCreationResultV1],
                creation_result,
            )
            result = decoded_result.value
            claim_logical_id = service_claim_logical_id(self._target)
            claim_document_id = service_claim_document_id(self._target)
            anchor_logical_id = result.winner_lineage_anchor_id
            anchor_document_id = capability_lineage_anchor_document_id(
                result.lineage_anchor
            )
            evidence_logical_id = result.winner_evidence_id
            evidence_document_id = signed_evidence_event_document_id(evidence_logical_id)
            claim = await self._transaction_read(
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
                    if (
                        previous_read_time is not None
                        and current_read_time < previous_read_time
                    ):
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
        present = tuple(
            value for value in (root, service_claim, authority) if value is not None
        )
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
                document_id=epoch_authority_document_id(
                    expected_authority.value.root_id
                ),
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
            if _receipt_semantic_binding(existing.value) != _receipt_semantic_binding(
                receipt
            ):
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
