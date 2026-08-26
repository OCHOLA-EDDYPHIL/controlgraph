import asyncio
from collections.abc import AsyncIterator, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from google.api_core import exceptions as api_exceptions
from google.cloud import firestore_v1

from controlgraph_canary.application.authority_store import (
    AuthorityStore,
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreErrorCode,
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
    ReleasedServiceClaim,
    StoredRecord,
)
from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    RolloutRoot,
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
)
from controlgraph_canary.contracts.storage import (
    SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
    SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
    SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
    AuthorityStorageKind,
    ServiceClaimRecord,
    ServiceClaimStatus,
    ServiceClaimTargetClassification,
    ServiceClaimTargetClassificationProof,
    ServiceClaimTerminalRootProof,
    ServiceClaimTerminalRootState,
    epoch_authority_document_id,
    execution_receipt_document_id,
    execution_receipt_logical_id,
    rollout_root_document_id,
    service_claim_document_id,
)
from controlgraph_canary.integrations.google.firestore import (
    FIRESTORE_AUTHORITY_DATABASE,
    FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
    FirestoreAuthorityStore,
)

ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
THREE_DIGEST = "3" * 64
FOUR_DIGEST = "4" * 64


def target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id="controlgraph-canary-a1b2c3",
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )


def rollout_root(
    root_id: str = "root-firestore-001",
    *,
    captured_at: str = "2026-08-19T12:00:00Z",
    approved_at: str = "2026-08-19T12:01:00Z",
    service_generation: int = 12,
) -> RolloutRoot:
    configured_target = target()
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=configured_target,
        stable_revision="controlgraph-reference-target-stable-v8",
        traffic=(
            TrafficAllocation(
                revision="controlgraph-reference-target-stable-v8",
                percent=100,
            ),
        ),
        concurrency=8,
        service_generation=service_generation,
        provider_etag=f"etag-stable-{service_generation}",
        configuration_sha256=ZERO_DIGEST,
        stable_revision_configuration_sha256=ONE_DIGEST,
        captured_at=captured_at,
        captured_by=(
            f"controlgraph-verifier@{configured_target.project_id}.iam.gserviceaccount.com"
        ),
    )
    return RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id=root_id,
        target=configured_target,
        stable_snapshot=snapshot,
        candidate_revision="controlgraph-reference-target-candidate-v8",
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=ONE_DIGEST,
        maximum_recovery_attempts=1,
        initial_epoch=1,
        plan_sha256=TWO_DIGEST,
        approved_by="controlgraph.operator/v1",
        approved_at=approved_at,
    )


def initial_records(
    root_id: str = "root-firestore-001",
    *,
    captured_at: str = "2026-08-19T12:00:00Z",
    approved_at: str = "2026-08-19T12:01:00Z",
    claimed_at: str = "2026-08-19T12:01:01Z",
    service_generation: int = 12,
) -> tuple[RolloutRoot, ServiceClaimRecord, EpochAuthorityRecord]:
    root = rollout_root(
        root_id,
        captured_at=captured_at,
        approved_at=approved_at,
        service_generation=service_generation,
    )
    root_sha256 = canonical_sha256(root)
    stable_target_configuration_sha256 = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=root.target,
            stable_revision=root.stable_snapshot.stable_revision,
            candidate_revision=root.candidate_revision,
            stable_percent=100,
            candidate_percent=0,
            concurrency=root.stable_snapshot.concurrency,
        )
    )
    candidate_target_configuration_sha256 = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=root.target,
            stable_revision=root.stable_snapshot.stable_revision,
            candidate_revision=root.candidate_revision,
            stable_percent=0,
            candidate_percent=100,
            concurrency=root.stable_snapshot.concurrency,
        )
    )
    claim = ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v2",
        target=root.target,
        root_id=root.root_id,
        root_sha256=root_sha256,
        stable_revision=root.stable_snapshot.stable_revision,
        candidate_revision=root.candidate_revision,
        initial_epoch=root.initial_epoch,
        baseline_service_generation=root.stable_snapshot.service_generation,
        baseline_configuration_sha256=root.stable_snapshot.configuration_sha256,
        baseline_revision_configuration_sha256=(
            root.stable_snapshot.stable_revision_configuration_sha256
        ),
        candidate_revision_configuration_sha256=THREE_DIGEST,
        stable_target_configuration_sha256=stable_target_configuration_sha256,
        candidate_target_configuration_sha256=candidate_target_configuration_sha256,
        operator_owner=root.approved_by,
        workload_creator="controlgraph.api/v1",
        terminal_release_condition=SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
        status=ServiceClaimStatus.ACTIVE,
        claim_request_id=f"request-{root_id}",
        claim_evidence_id=f"evidence-{root_id}",
        claimed_at=claimed_at,
        release_fence_epoch=None,
        release_fence_authority_revision=None,
        release_fenced_by=None,
        release_fence_request_id=None,
        release_fence_evidence_id=None,
        release_fenced_at=None,
        released_by=None,
        release_request_id=None,
        release_evidence_id=None,
        released_at=None,
        terminal_root_proof=None,
        target_classification_proof=None,
    )
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root_sha256,
        target=root.target,
        current_epoch=1,
        previous_epoch=None,
        revision=0,
        cause=EpochChangeCause.ROOT_CREATED,
        changed_by=root.approved_by,
        request_id=claim.claim_request_id,
        evidence_id=claim.claim_evidence_id,
        changed_at=claimed_at,
    )
    return root, claim, authority


def advanced_authority(
    current: EpochAuthorityRecord,
    *,
    suffix: str,
    changed_at: str = "2026-08-19T12:05:00Z",
) -> EpochAuthorityRecord:
    return EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=current.root_id,
        root_sha256=current.root_sha256,
        target=current.target,
        current_epoch=current.current_epoch + 1,
        previous_epoch=current.current_epoch,
        revision=current.revision + 1,
        cause=EpochChangeCause.OPERATOR_REVOCATION,
        changed_by="controlgraph.operator/v1",
        request_id=f"request-revoke-{suffix}",
        evidence_id=f"evidence-revoke-{suffix}",
        changed_at=changed_at,
    )


def release_transition(
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
    *,
    suffix: str = "release",
    terminal_confirmed_at: str = "2026-08-19T12:03:00Z",
    fenced_at: str = "2026-08-19T12:05:00Z",
    classified_at: str = "2026-08-19T12:06:00Z",
    released_at: str = "2026-08-19T12:07:00Z",
    classified_generation: int = 14,
) -> tuple[ServiceClaimRecord, ServiceClaimRecord, EpochAuthorityRecord]:
    replacement_authority = advanced_authority(
        authority,
        suffix=suffix,
        changed_at=fenced_at,
    )
    terminal = ServiceClaimTerminalRootProof(
        schema_version=SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
        target=claim.target,
        root_id=claim.root_id,
        root_sha256=claim.root_sha256,
        state=ServiceClaimTerminalRootState.RECOVERED,
        target_configuration_sha256=claim.stable_target_configuration_sha256,
        evidence_id=f"evidence-terminal-{suffix}",
        evidence_sha256=ZERO_DIGEST,
        confirmed_by="controlgraph.coordinator/v1",
        confirmed_at=terminal_confirmed_at,
    )
    classification = ServiceClaimTargetClassificationProof(
        schema_version=SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
        target=claim.target,
        root_id=claim.root_id,
        root_sha256=claim.root_sha256,
        classification=ServiceClaimTargetClassification.STABLE_RESTORED,
        fenced_epoch=replacement_authority.current_epoch,
        fenced_authority_revision=replacement_authority.revision,
        service_generation=classified_generation,
        provider_etag=f"etag-stable-{classified_generation}",
        target_configuration_sha256=claim.stable_target_configuration_sha256,
        evidence_id=f"evidence-target-{suffix}",
        evidence_sha256=ONE_DIGEST,
        classified_by=(
            f"controlgraph-verifier@{claim.target.project_id}.iam.gserviceaccount.com"
        ),
        classified_at=classified_at,
    )
    fenced_claim = ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASING,
            "release_fence_epoch": replacement_authority.current_epoch,
            "release_fence_authority_revision": replacement_authority.revision,
            "release_fenced_by": replacement_authority.changed_by,
            "release_fence_request_id": replacement_authority.request_id,
            "release_fence_evidence_id": replacement_authority.evidence_id,
            "release_fenced_at": replacement_authority.changed_at,
            "terminal_root_proof": terminal,
        }
    )
    released_claim = ServiceClaimRecord(
        **{
            **fenced_claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASED,
            "released_by": "controlgraph.coordinator/v1",
            "release_request_id": f"request-release-{suffix}",
            "release_evidence_id": f"evidence-release-{suffix}",
            "released_at": released_at,
            "target_classification_proof": classification,
        }
    )
    return fenced_claim, released_claim, replacement_authority


def claimed_receipt(seed: str = "firestore-001") -> ExecutionReceipt:
    root = rollout_root()
    idempotency_key = f"intent-{seed}"
    initial = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(root.target, idempotency_key),
        request_id=f"request-{seed}",
        idempotency_key=idempotency_key,
        capability_sha256=ZERO_DIGEST,
        mutation_sha256=ONE_DIGEST,
        plan_sha256=TWO_DIGEST,
        expected_poststate_sha256=THREE_DIGEST,
        target=root.target,
        root_id=root.root_id,
        root_sha256=canonical_sha256(root),
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag="etag-stable-12",
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=None,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:02:00Z",
        evidence_ids=("evidence-receipt-claimed",),
    )
    return ExecutionReceipt(
        **{
            **initial.model_dump(mode="python"),
            "mutation_sha256": mutation_identity(receipt_binding(initial)),
        }
    )


def receipt_binding(receipt: ExecutionReceipt) -> MutationBinding:
    return MutationBinding(
        idempotency_key=receipt.idempotency_key,
        request_id=receipt.request_id,
        root_id=receipt.root_id,
        root_sha256=receipt.root_sha256,
        epoch=receipt.epoch,
        action=MutationAction(receipt.action.value),
        target=MutationTargetKey(
            project_id=receipt.target.project_id,
            region=receipt.target.region,
            environment=receipt.target.environment,
            service_name=receipt.target.service_name,
        ),
        provider_precondition=receipt.provider_etag,
        plan_sha256=receipt.plan_sha256,
        capability_sha256=receipt.capability_sha256,
        payload_sha256=FOUR_DIGEST,
        expected_poststate_sha256=receipt.expected_poststate_sha256,
    )


def rebound_receipt(receipt: ExecutionReceipt, **changes: object) -> ExecutionReceipt:
    changed = ExecutionReceipt(
        **{
            **receipt.model_dump(mode="python"),
            **changes,
        }
    )
    return ExecutionReceipt(
        **{
            **changed.model_dump(mode="python"),
            "mutation_sha256": mutation_identity(receipt_binding(changed)),
        }
    )


async def claim_or_adopt(
    store: FirestoreAuthorityStore,
    receipt: ExecutionReceipt,
) -> ReceiptClaimCreated | ReceiptClaimAdopted | ReceiptClaimConflict:
    return await store.claim_or_adopt_receipt(receipt, receipt_binding(receipt))


def ambiguous_receipt(current: ExecutionReceipt, *, suffix: str) -> ExecutionReceipt:
    return ExecutionReceipt(
        **{
            **current.model_dump(mode="python"),
            "outcome": ReceiptOutcome.AMBIGUOUS,
            "reason_code": ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
            "updated_at": "2026-08-19T12:02:01Z",
            "evidence_ids": (*current.evidence_ids, f"evidence-attempt-{suffix}"),
        }
    )


def resolvable_ambiguous_receipt(current: ExecutionReceipt) -> ExecutionReceipt:
    return ExecutionReceipt(
        **{
            **current.model_dump(mode="python"),
            "outcome": ReceiptOutcome.AMBIGUOUS,
            "reason_code": ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
            "provider_operation": (
                f"projects/{current.target.project_id}/locations/{current.target.region}/"
                "operations/readback-resolution"
            ),
            "observed_etag": "etag-ambiguous-12",
            "observed_authority_epoch": current.epoch,
            "updated_at": "2026-08-19T12:02:01Z",
            "evidence_ids": (*current.evidence_ids, "evidence-attempt-readback"),
        }
    )


def resolved_readback_receipt(
    current: ExecutionReceipt,
    *,
    marker_digest: str = "a" * 64,
) -> ExecutionReceipt:
    return ExecutionReceipt(
        **{
            **current.model_dump(mode="python"),
            "outcome": ReceiptOutcome.VERIFIED,
            "reason_code": None,
            "observed_etag": "etag-verified-13",
            "updated_at": "2026-08-19T12:02:02Z",
            "evidence_ids": (*current.evidence_ids, f"cgrrb:{marker_digest}"),
        }
    )


@dataclass
class _StoredDocument:
    data: dict[str, Any]
    update_time: datetime


@dataclass
class _WriteResult:
    update_time: datetime


class _Snapshot:
    def __init__(
        self,
        reference: "_Reference",
        stored: _StoredDocument | None,
        read_time: datetime,
    ) -> None:
        self.reference = reference
        self.exists = stored is not None
        self.read_time = read_time
        self.update_time = None if stored is None else stored.update_time
        self._data = None if stored is None else deepcopy(stored.data)

    def to_dict(self) -> dict[str, Any] | None:
        return deepcopy(self._data)


class _Reference:
    def __init__(self, client: "_FakeClient", path: str) -> None:
        self._client = client
        self.path = path

    async def get(
        self,
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> _Snapshot:
        del field_paths, retry, timeout, read_time
        if self._client.read_error is not None:
            raise self._client.read_error
        if isinstance(transaction, _Transaction):
            snapshot = transaction.snapshot(self)
            self._client.transaction_read_count += 1
            if self._client.pause_transaction_read_after == self._client.transaction_read_count:
                self._client.pause_transaction_read_after = None
                self._client.transaction_read_paused.set()
                await self._client.continue_transaction_read.wait()
            return snapshot
        return self._client.snapshot(self)


class _Transaction:
    def __init__(self, client: "_FakeClient", maximum_attempts: int) -> None:
        self.client = client
        self.maximum_attempts = maximum_attempts
        self.operations: list[tuple[str, _Reference, dict[str, Any], object | None]] = []
        self.write_results: list[object] = []

    def snapshot(self, reference: _Reference) -> _Snapshot:
        return self.client.snapshot(reference)

    def create(self, reference: _Reference, document_data: dict[str, Any]) -> None:
        self.operations.append(("create", reference, deepcopy(document_data), None))

    def update(
        self,
        reference: _Reference,
        field_updates: dict[str, Any],
        option: object | None = None,
    ) -> None:
        self.operations.append(("update", reference, deepcopy(field_updates), option))


class _FakeClient:
    def __init__(
        self,
        *,
        project_id: str = "controlgraph-canary-a1b2c3",
        database_id: str = FIRESTORE_AUTHORITY_DATABASE,
        database_resource: str | None = None,
    ) -> None:
        self.project = project_id
        self._database = database_id
        self._database_string = database_resource or (
            f"projects/{project_id}/databases/{database_id}"
        )
        self.documents: dict[str, _StoredDocument] = {}
        self.lock = asyncio.Lock()
        self.clock = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
        self.read_error: Exception | None = None
        self.document_calls = 0
        self.transaction_read_count = 0
        self.pause_transaction_read_after: int | None = None
        self.transaction_read_paused = asyncio.Event()
        self.continue_transaction_read = asyncio.Event()
        self.batch_get_calls = 0
        self.batch_get_arguments: list[tuple[object, ...]] = []
        self.batch_get_mode = "normal"
        self.pause_batch_get_before_capture = False
        self.batch_get_started = asyncio.Event()
        self.continue_batch_get = asyncio.Event()
        self.pause_batch_get_after_first = False
        self.batch_get_first_yielded = asyncio.Event()
        self.continue_batch_get_stream = asyncio.Event()

    def document(self, *document_path: str) -> _Reference:
        self.document_calls += 1
        return _Reference(self, "/".join(document_path))

    def transaction(self, max_attempts: int = 3, read_only: bool = False) -> _Transaction:
        del read_only
        return _Transaction(self, max_attempts)

    async def get_all(
        self,
        references: Sequence[_Reference],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> AsyncIterator[_Snapshot]:
        self.batch_get_calls += 1
        self.batch_get_arguments.append(
            (tuple(reference.path for reference in references), field_paths, transaction, retry,
             timeout, read_time)
        )
        self.batch_get_started.set()
        if self.pause_batch_get_before_capture:
            await self.continue_batch_get.wait()
        if self.read_error is not None:
            raise self.read_error
        async with self.lock:
            captured = deepcopy(self.documents)
            self.clock += timedelta(microseconds=1)
            initial_read_time = self.clock
        selected = list(references)
        if self.batch_get_mode == "reversed":
            selected.reverse()
        elif self.batch_get_mode == "partial":
            selected = selected[:-1]
        elif self.batch_get_mode == "duplicate":
            selected[-1] = selected[0]
        elif self.batch_get_mode == "unexpected":
            selected[-1] = _Reference(self, "unexpected/document")
        for index, reference in enumerate(selected):
            read_time = initial_read_time + timedelta(microseconds=index)
            if self.batch_get_mode == "read-time-regression" and index == 1:
                read_time = initial_read_time - timedelta(microseconds=1)
            yield _Snapshot(reference, captured.get(reference.path), read_time)
            if self.pause_batch_get_after_first and index == 0:
                self.batch_get_first_yielded.set()
                await self.continue_batch_get_stream.wait()
            if self.batch_get_mode == "mid-stream-error" and index == 0:
                raise RuntimeError("synthetic batch stream detail")

    def snapshot(self, reference: _Reference) -> _Snapshot:
        self.clock += timedelta(microseconds=1)
        return _Snapshot(reference, self.documents.get(reference.path), self.clock)


class _FakeTransactionRunner:
    def __init__(self) -> None:
        self.mode = "normal"
        self.maximum_attempts: list[int] = []
        self.expected_writes: list[int] = []
        self.write_result_counts: list[int] = []
        self.task_to_cancel: asyncio.Task[object] | None = None

    async def __call__(
        self,
        client: _FakeClient,
        maximum_attempts: int,
        expected_writes: int,
        body: Any,
    ) -> None:
        self.maximum_attempts.append(maximum_attempts)
        self.expected_writes.append(expected_writes)
        async with client.lock:
            transaction = client.transaction(max_attempts=maximum_attempts)
            if self.mode == "timeout-before-body":
                self.mode = "normal"
                raise TimeoutError("synthetic provider detail")
            await body(transaction)
            if len(transaction.operations) != expected_writes:
                raise RuntimeError("synthetic malformed write count")
            if self.mode == "timeout-before-commit":
                self.mode = "normal"
                raise TimeoutError("synthetic provider detail")
            original = deepcopy(client.documents)
            pending = deepcopy(client.documents)
            for operation, reference, data, option in transaction.operations:
                if operation == "create" and reference.path in pending:
                    raise api_exceptions.AlreadyExists("synthetic contention detail")
                if operation == "update" and reference.path not in pending:
                    raise api_exceptions.NotFound("synthetic contention detail")
                if isinstance(option, firestore_v1.LastUpdateOption):
                    expected_update_time = vars(option).get("_last_update_time")
                    current = pending.get(reference.path)
                    if (
                        type(expected_update_time) is not datetime
                        or current is None
                        or current.update_time != expected_update_time
                    ):
                        raise api_exceptions.FailedPrecondition(
                            "synthetic update-time contention detail"
                        )
                client.clock += timedelta(microseconds=1)
                pending[reference.path] = _StoredDocument(data, client.clock)
                transaction.write_results.append(_WriteResult(client.clock))
            client.documents = pending
            self.write_result_counts.append(len(transaction.write_results))
            if self.mode == "commit-then-cancel-caller":
                self.mode = "normal"
                if self.task_to_cancel is None:
                    raise AssertionError("a caller task is required")
                self.task_to_cancel.cancel()
            if self.mode == "commit-first-only-then-timeout":
                self.mode = "normal"
                last_path = transaction.operations[-1][1].path
                if last_path in original:
                    client.documents[last_path] = original[last_path]
                else:
                    del client.documents[last_path]
                raise TimeoutError("synthetic provider detail")
            if self.mode == "commit-corrupt-then-timeout":
                self.mode = "normal"
                last_path = transaction.operations[-1][1].path
                client.documents[last_path].data["payload_sha256"] = ZERO_DIGEST
                raise TimeoutError("synthetic provider detail")
            if self.mode == "commit-then-timeout":
                self.mode = "normal"
                raise TimeoutError("synthetic provider detail")


def store_fixture() -> tuple[FirestoreAuthorityStore, _FakeClient, _FakeTransactionRunner]:
    client = _FakeClient()
    runner = _FakeTransactionRunner()
    store = FirestoreAuthorityStore.for_test(
        target=target(),
        configured_project_id=target().project_id,
        client_factory=lambda: client,
        transaction_runner=runner,
    )
    return store, client, runner


async def _create_rollout(
    authority_store: FirestoreAuthorityStore,
    root: RolloutRoot,
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
) -> CreatedRollout:
    return await authority_store.create_rollout(
        root,
        claim,
        authority,
        verified_candidate_revision_configuration_sha256=(
            claim.candidate_revision_configuration_sha256
        ),
    )


async def _create_rollout_after_release(
    authority_store: FirestoreAuthorityStore,
    expected_released_claim: StoredRecord[ServiceClaimRecord],
    root: RolloutRoot,
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
) -> CreatedRollout:
    return await authority_store.create_rollout_after_release(
        expected_released_claim,
        root,
        claim,
        authority,
        verified_candidate_revision_configuration_sha256=(
            claim.candidate_revision_configuration_sha256
        ),
    )


async def _prepare_readback_resolution(
    store: FirestoreAuthorityStore,
) -> tuple[
    StoredRecord[ExecutionReceipt],
    ExecutionReceipt,
    StoredRecord[EpochAuthorityRecord],
    StoredRecord[ServiceClaimRecord],
]:
    root, claim, authority = initial_records()
    created = await _create_rollout(store, root, claim, authority)
    receipt = claimed_receipt("readback-resolution")
    claimed = await claim_or_adopt(store, receipt)
    assert type(claimed) is ReceiptClaimCreated
    ambiguous = resolvable_ambiguous_receipt(receipt)
    expected = await store.compare_and_set_receipt(claimed.receipt, ambiguous)
    return (
        expected,
        resolved_readback_receipt(ambiguous),
        created.authority,
        created.service_claim,
    )


def test_store_is_sealed_to_one_target_and_named_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FIRESTORE_EMULATOR_HOST", raising=False)
    store, _, _ = store_fixture()

    assert isinstance(store, AuthorityStore)
    assert store.target == target()
    assert store.database_id == FIRESTORE_AUTHORITY_DATABASE == "controlgraph-authority"
    wrong_region = TargetBinding(
        **{
            **target().model_dump(mode="python"),
            "region": "europe-west1",
        }
    )
    with pytest.raises(ValueError, match="must use us-central1"):
        FirestoreAuthorityStore(
            target=wrong_region,
            configured_project_id=wrong_region.project_id,
        )


def test_store_requires_exact_configured_controlgraph_project() -> None:
    client = _FakeClient()

    with pytest.raises(ValueError, match="does not match configuration"):
        FirestoreAuthorityStore.for_test(
            target=target(),
            configured_project_id="controlgraph-canary-b2c3d4",
            client_factory=lambda: client,
        )
    with pytest.raises(ValueError, match="must be a ControlGraph project"):
        FirestoreAuthorityStore.for_test(
            target=target(),
            configured_project_id="shared-authority-project",
            client_factory=lambda: client,
        )


def test_production_and_emulator_construction_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FIRESTORE_EMULATOR_HOST", raising=False)
    production_store = FirestoreAuthorityStore(
        target=target(),
        configured_project_id=target().project_id,
    )
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8787")
    with pytest.raises(ValueError, match="rejects the emulator host"):
        FirestoreAuthorityStore(
            target=target(),
            configured_project_id=target().project_id,
        )
    with pytest.raises(AuthorityStoreUnavailable):
        asyncio.run(production_store.read_rollout_root("root-emulator-substitution"))

    emulator_store = FirestoreAuthorityStore.for_emulator(
        target=target(),
        configured_project_id=target().project_id,
    )
    assert emulator_store.target == target()
    assert emulator_store.database_id == FIRESTORE_AUTHORITY_DATABASE

    monkeypatch.delenv("FIRESTORE_EMULATOR_HOST")
    with pytest.raises(ValueError, match="requires an emulator host"):
        FirestoreAuthorityStore.for_emulator(
            target=target(),
            configured_project_id=target().project_id,
        )


@pytest.mark.parametrize(
    ("project_id", "database_id", "database_resource"),
    [
        (
            "controlgraph-canary-b2c3d4",
            FIRESTORE_AUTHORITY_DATABASE,
            None,
        ),
        (
            "controlgraph-canary-a1b2c3",
            "other-authority",
            None,
        ),
        (
            "controlgraph-canary-a1b2c3",
            FIRESTORE_AUTHORITY_DATABASE,
            "projects/controlgraph-canary-a1b2c3/databases/(default)",
        ),
    ],
)
def test_injected_client_coordinates_are_attested_before_use(
    project_id: str,
    database_id: str,
    database_resource: str | None,
) -> None:
    async def scenario() -> None:
        client = _FakeClient(
            project_id=project_id,
            database_id=database_id,
            database_resource=database_resource,
        )
        store = FirestoreAuthorityStore.for_test(
            target=target(),
            configured_project_id=target().project_id,
            client_factory=lambda: client,
        )

        with pytest.raises(AuthorityStoreUnavailable):
            await store.read_rollout_root("root-client-attestation")

        assert client.document_calls == 0

    asyncio.run(scenario())


def test_rollout_creation_atomically_persists_three_strongly_read_records() -> None:
    async def scenario() -> None:
        store, client, runner = store_fixture()
        root, claim, authority = initial_records()

        created = await _create_rollout(store, root, claim, authority)

        assert created.root == StoredRecord(root, 0)
        assert created.service_claim == StoredRecord(claim, 0)
        assert created.authority == StoredRecord(authority, 0)
        assert claim.candidate_revision_configuration_sha256 == THREE_DIGEST
        assert await store.read_rollout_root(root.root_id) == created.root
        assert await store.read_service_claim() == created.service_claim
        assert await store.read_authority(root.root_id) == created.authority
        assert len(client.documents) == 3
        assert runner.maximum_attempts == [FIRESTORE_MAX_TRANSACTION_ATTEMPTS]
        expected_paths = {
            f"{AuthorityStorageKind.ROLLOUT_ROOT.value}/{rollout_root_document_id(root.root_id)}",
            f"{AuthorityStorageKind.SERVICE_CLAIM.value}/{service_claim_document_id(root.target)}",
            f"{AuthorityStorageKind.EPOCH_AUTHORITY.value}/"
            f"{epoch_authority_document_id(root.root_id)}",
        }
        assert set(client.documents) == expected_paths

    asyncio.run(scenario())


def test_rollout_creation_binds_initial_authority_to_operator_owner() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        root, claim, authority = initial_records()
        workload_attributed = authority.model_copy(
            update={"changed_by": claim.workload_creator}
        )

        with pytest.raises(ValueError, match="one atomic authority state"):
            await _create_rollout(store, root, claim, workload_attributed)

    asyncio.run(scenario())


def test_rollout_creation_rejects_workload_attribution_and_unverified_candidate() -> None:
    async def scenario() -> None:
        store, client, runner = store_fixture()
        root, claim, authority = initial_records()
        workload_claim = claim.model_copy(
            update={"operator_owner": claim.workload_creator}
        )
        workload_root = root.model_copy(update={"approved_by": claim.workload_creator})
        workload_authority = authority.model_copy(
            update={"changed_by": claim.workload_creator}
        )

        with pytest.raises(ValueError, match="one atomic authority state"):
            await FirestoreAuthorityStore.create_rollout(
                store,
                workload_root,
                workload_claim,
                workload_authority,
                verified_candidate_revision_configuration_sha256=(
                    workload_claim.candidate_revision_configuration_sha256
                ),
            )
        with pytest.raises(ValueError, match="verified candidate configuration"):
            await FirestoreAuthorityStore.create_rollout(
                store,
                root,
                claim,
                authority,
                verified_candidate_revision_configuration_sha256=FOUR_DIGEST,
            )

        assert client.documents == {}
        assert runner.maximum_attempts == []

    asyncio.run(scenario())


def test_racing_root_creates_have_one_service_claim_winner() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        first = initial_records("root-race-first")
        second = initial_records("root-race-second")

        results = await asyncio.gather(
            _create_rollout(store, *first),
            _create_rollout(store, *second),
            return_exceptions=True,
        )

        assert sum(not isinstance(result, Exception) for result in results) == 1
        conflicts = [result for result in results if isinstance(result, AuthorityStoreConflict)]
        assert len(conflicts) == 1
        assert str(conflicts[0]) == AuthorityStoreErrorCode.CONFLICT.value
        claim = await store.read_service_claim()
        assert claim is not None
        assert claim.value.root_id in {first[0].root_id, second[0].root_id}
        stored_roots = [
            path
            for path in client.documents
            if path.startswith(f"{AuthorityStorageKind.ROLLOUT_ROOT.value}/")
        ]
        assert len(stored_roots) == 1

    asyncio.run(scenario())


def test_legacy_active_claim_path_blocks_v2_creation() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        claim_path = (
            f"{AuthorityStorageKind.SERVICE_CLAIM.value}/"
            f"{service_claim_document_id(root.target)}"
        )
        client.documents[claim_path] = _StoredDocument(
            data={"schema_version": "controlgraph.service-claim/v1"},
            update_time=client.clock,
        )

        with pytest.raises(AuthorityStoreConflict):
            await _create_rollout(store, root, claim, authority)

        assert set(client.documents) == {claim_path}

    asyncio.run(scenario())


def test_authority_compare_and_advance_has_one_monotonic_winner() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        expected = await store.read_authority(root.root_id)
        assert expected is not None

        results = await asyncio.gather(
            store.advance_authority(expected, advanced_authority(authority, suffix="first")),
            store.advance_authority(expected, advanced_authority(authority, suffix="second")),
            return_exceptions=True,
        )

        assert sum(not isinstance(result, Exception) for result in results) == 1
        assert sum(isinstance(result, AuthorityStoreConflict) for result in results) == 1
        current = await store.read_authority(root.root_id)
        assert current is not None
        assert current.revision == current.value.revision == 1
        assert current.value.current_epoch == 2
        with pytest.raises(ValueError, match="monotonic advance"):
            await store.advance_authority(
                current,
                advanced_authority(authority, suffix="stale"),
            )

    asyncio.run(scenario())


def test_authority_advance_rejects_time_regression_without_writing() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        expected = await store.read_authority(root.root_id)
        assert expected is not None
        regressed = EpochAuthorityRecord(
            **{
                **advanced_authority(authority, suffix="time").model_dump(mode="python"),
                "changed_at": "2026-08-19T12:00:59Z",
            }
        )

        with pytest.raises(ValueError, match="monotonic advance"):
            await store.advance_authority(expected, regressed)

        assert await store.read_authority(root.root_id) == expected

    asyncio.run(scenario())


def test_receipt_claim_and_compare_and_set_each_have_one_winner() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        receipt = claimed_receipt()

        claims = await asyncio.gather(
            claim_or_adopt(store, receipt),
            claim_or_adopt(store, receipt),
        )
        assert sum(type(result) is ReceiptClaimCreated for result in claims) == 1
        assert sum(type(result) is ReceiptClaimAdopted for result in claims) == 1
        created = next(result for result in claims if type(result) is ReceiptClaimCreated)
        adopted = next(result for result in claims if type(result) is ReceiptClaimAdopted)
        assert type(created.direct_create) is DirectReceiptCreate
        assert created.receipt == adopted.receipt == StoredRecord(receipt, 0)
        expected = await store.read_receipt(receipt.idempotency_key)
        assert expected == StoredRecord(receipt, 0)
        assert expected is not None

        updates = await asyncio.gather(
            store.compare_and_set_receipt(
                expected,
                ambiguous_receipt(receipt, suffix="first"),
            ),
            store.compare_and_set_receipt(
                expected,
                ambiguous_receipt(receipt, suffix="second"),
            ),
            return_exceptions=True,
        )
        assert sum(not isinstance(result, Exception) for result in updates) == 1
        assert sum(isinstance(result, AuthorityStoreConflict) for result in updates) == 1
        current = await store.read_receipt(receipt.idempotency_key)
        assert current is not None
        assert current.revision == 1
        assert current.value.outcome is ReceiptOutcome.AMBIGUOUS

    asyncio.run(scenario())


def test_exact_duplicate_adopts_the_original_claim_timestamp() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        original = claimed_receipt("receipt-created-at-adoption")
        created = await claim_or_adopt(store, original)
        assert type(created) is ReceiptClaimCreated
        duplicate = ExecutionReceipt(
            **{
                **original.model_dump(mode="python"),
                "created_at": "2026-08-19T12:02:01Z",
                "updated_at": "2026-08-19T12:02:01Z",
            }
        )

        adopted = await claim_or_adopt(store, duplicate)

        assert adopted == ReceiptClaimAdopted(StoredRecord(original, 0))

    asyncio.run(scenario())


def test_receipt_claim_rejects_a_caller_selected_identifier_before_io() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        receipt = claimed_receipt("caller-selected-id")
        substituted = ExecutionReceipt(
            **{
                **receipt.model_dump(mode="python"),
                "receipt_id": "caller-selected-receipt",
            }
        )

        with pytest.raises(ValueError, match="initial claim"):
            await store.claim_or_adopt_receipt(
                substituted,
                receipt_binding(substituted),
            )

        assert client.document_calls == 0
        assert client.documents == {}

    asyncio.run(scenario())


def test_same_idempotency_key_with_a_changed_binding_has_one_claim_winner() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        first = claimed_receipt("shared-idempotency")
        second = rebound_receipt(
            first,
            request_id="request-changed-binding",
            capability_sha256=THREE_DIGEST,
        )

        results = await asyncio.gather(
            claim_or_adopt(store, first),
            claim_or_adopt(store, second),
        )

        assert sum(type(result) is ReceiptClaimCreated for result in results) == 1
        assert sum(type(result) is ReceiptClaimConflict for result in results) == 1
        assert len(client.documents) == 1
        stored = await store.read_receipt(first.idempotency_key)
        assert stored is not None
        assert stored.value in (first, second)

        losing = second if stored.value == first else first
        assert type(await claim_or_adopt(store, losing)) is ReceiptClaimConflict
        assert len(client.documents) == 1

    asyncio.run(scenario())


def test_receipt_cas_rejects_binding_changes_and_terminal_regression() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        receipt = claimed_receipt()
        claimed = await claim_or_adopt(store, receipt)
        assert type(claimed) is ReceiptClaimCreated
        expected = claimed.receipt
        changed_binding = ExecutionReceipt(
            **{
                **ambiguous_receipt(receipt, suffix="binding").model_dump(mode="python"),
                "mutation_sha256": ZERO_DIGEST,
            }
        )
        with pytest.raises(ValueError, match="immutable binding"):
            await store.compare_and_set_receipt(expected, changed_binding)

        denied = ExecutionReceipt(
            **{
                **receipt.model_dump(mode="python"),
                "outcome": ReceiptOutcome.DENIED,
                "reason_code": ReasonCode.EPOCH_MISMATCH,
                "observed_authority_epoch": 2,
                "updated_at": "2026-08-19T12:02:01Z",
            }
        )
        terminal = await store.compare_and_set_receipt(expected, denied)
        with pytest.raises(ValueError, match="permitted forward transition"):
            await store.compare_and_set_receipt(
                terminal,
                ambiguous_receipt(denied, suffix="regression"),
            )

    asyncio.run(scenario())


def test_receipt_cas_cannot_replace_a_recorded_provider_operation() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        receipt = claimed_receipt("provider-operation-immutable")
        claimed = await claim_or_adopt(store, receipt)
        assert type(claimed) is ReceiptClaimCreated
        applied = ExecutionReceipt(
            **{
                **receipt.model_dump(mode="python"),
                "outcome": ReceiptOutcome.APPLIED,
                "provider_operation": "operations/original",
                "observed_authority_epoch": 1,
                "updated_at": "2026-08-19T12:02:01Z",
            }
        )
        stored = await store.compare_and_set_receipt(claimed.receipt, applied)
        substituted = ExecutionReceipt(
            **{
                **applied.model_dump(mode="python"),
                "outcome": ReceiptOutcome.AMBIGUOUS,
                "reason_code": ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
                "provider_operation": "operations/substituted",
                "updated_at": "2026-08-19T12:02:02Z",
            }
        )

        with pytest.raises(ValueError, match="provider operation"):
            await store.compare_and_set_receipt(stored, substituted)

        assert await store.read_receipt(receipt.idempotency_key) == stored

    asyncio.run(scenario())


def test_readback_resolution_atomically_reads_three_fences_and_writes_only_receipt() -> None:
    async def scenario() -> None:
        store, client, runner = store_fixture()
        expected, replacement, authority, service_claim = (
            await _prepare_readback_resolution(store)
        )
        authority_path = (
            f"{AuthorityStorageKind.EPOCH_AUTHORITY.value}/"
            f"{epoch_authority_document_id(expected.value.root_id)}"
        )
        claim_path = (
            f"{AuthorityStorageKind.SERVICE_CLAIM.value}/"
            f"{service_claim_document_id(expected.value.target)}"
        )
        receipt_path = (
            f"{AuthorityStorageKind.EXECUTION_RECEIPT.value}/"
            f"{execution_receipt_document_id(
                expected.value.target,
                expected.value.idempotency_key,
            )}"
        )
        authority_before = deepcopy(client.documents[authority_path])
        claim_before = deepcopy(client.documents[claim_path])
        receipt_before = deepcopy(client.documents[receipt_path])
        transaction_count = len(runner.maximum_attempts)
        transaction_reads = client.transaction_read_count

        resolved = await store.resolve_ambiguous_receipt(
            expected,
            replacement,
            authority,
            service_claim,
        )

        assert resolved == StoredRecord(replacement, expected.revision + 1)
        assert len(runner.maximum_attempts) == transaction_count + 1
        assert runner.expected_writes[-1] == 1
        assert runner.write_result_counts[-1] == 1
        assert client.transaction_read_count == transaction_reads + 3
        assert client.documents[authority_path] == authority_before
        assert client.documents[claim_path] == claim_before
        assert client.documents[receipt_path] != receipt_before
        assert await store.read_receipt(expected.value.idempotency_key) == resolved

    asyncio.run(scenario())


def test_readback_resolution_rejects_advanced_authority_without_receipt_write() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        expected, replacement, authority, service_claim = (
            await _prepare_readback_resolution(store)
        )
        advanced = advanced_authority(authority.value, suffix="readback-race")
        await store.advance_authority(authority, advanced)

        with pytest.raises(AuthorityStoreConflict):
            await store.resolve_ambiguous_receipt(
                expected,
                replacement,
                authority,
                service_claim,
            )

        assert await store.read_receipt(expected.value.idempotency_key) == expected

    asyncio.run(scenario())


def test_readback_resolution_rejects_nonactive_changed_claim_without_receipt_write() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        expected, replacement, authority, service_claim = (
            await _prepare_readback_resolution(store)
        )
        authority_path = (
            f"{AuthorityStorageKind.EPOCH_AUTHORITY.value}/"
            f"{epoch_authority_document_id(expected.value.root_id)}"
        )
        authority_before = deepcopy(client.documents[authority_path])
        fenced_claim, _, replacement_authority = release_transition(
            service_claim.value,
            authority.value,
            suffix="readback-claim-race",
        )
        await store.fence_service_claim(
            service_claim,
            fenced_claim,
            authority,
            replacement_authority,
        )
        client.documents[authority_path] = authority_before
        changed_claim = await store.read_service_claim()
        assert changed_claim is not None
        assert changed_claim.value.status is ServiceClaimStatus.RELEASING

        with pytest.raises(AuthorityStoreConflict):
            await store.resolve_ambiguous_receipt(
                expected,
                replacement,
                authority,
                service_claim,
            )

        assert await store.read_receipt(expected.value.idempotency_key) == expected

    asyncio.run(scenario())


def test_readback_resolution_rejects_competing_receipt_revision() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        expected, replacement, authority, service_claim = (
            await _prepare_readback_resolution(store)
        )
        competing = ambiguous_receipt(expected.value, suffix="readback-race")
        winner = await store.compare_and_set_receipt(expected, competing)

        with pytest.raises(AuthorityStoreConflict):
            await store.resolve_ambiguous_receipt(
                expected,
                replacement,
                authority,
                service_claim,
            )

        assert await store.read_receipt(expected.value.idempotency_key) == winner

    asyncio.run(scenario())


def test_readback_resolution_adopts_exact_unknown_commit() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        expected, replacement, authority, service_claim = (
            await _prepare_readback_resolution(store)
        )
        runner.mode = "commit-then-timeout"

        resolved = await store.resolve_ambiguous_receipt(
            expected,
            replacement,
            authority,
            service_claim,
        )

        assert resolved == StoredRecord(replacement, expected.revision + 1)
        assert await store.read_receipt(expected.value.idempotency_key) == resolved

    asyncio.run(scenario())


def test_generic_receipt_cas_cannot_append_readback_resolution_marker() -> None:
    async def scenario() -> None:
        store, client, runner = store_fixture()
        expected, replacement, _, _ = await _prepare_readback_resolution(store)
        documents_before = deepcopy(client.documents)
        transaction_count = len(runner.maximum_attempts)

        with pytest.raises(ValueError, match="dedicated operation"):
            await store.compare_and_set_receipt(expected, replacement)

        assert len(runner.maximum_attempts) == transaction_count
        assert client.documents == documents_before
        assert await store.read_receipt(expected.value.idempotency_key) == expected

    asyncio.run(scenario())


def test_ambiguous_commit_is_adopted_only_after_exact_readback() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        committed = claimed_receipt("receipt-ambiguous-committed")
        runner.mode = "commit-then-timeout"

        result = await claim_or_adopt(store, committed)

        assert result == ReceiptClaimAdopted(StoredRecord(committed, 0))
        assert await store.read_receipt(committed.idempotency_key) == result.receipt
        attempted = ambiguous_receipt(committed, suffix="commit-readback")
        runner.mode = "commit-then-timeout"
        updated = await store.compare_and_set_receipt(result.receipt, attempted)
        assert updated == StoredRecord(attempted, 1)
        assert await store.read_receipt(committed.idempotency_key) == updated

        absent = claimed_receipt("receipt-ambiguous-absent")
        runner.mode = "timeout-before-commit"
        with pytest.raises(AuthorityStoreOutcomeUnknown) as error:
            await claim_or_adopt(store, absent)
        assert str(error.value) == AuthorityStoreErrorCode.OUTCOME_UNKNOWN.value
        assert await store.read_receipt(absent.idempotency_key) is None

        corrupt = claimed_receipt("receipt-ambiguous-corrupt")
        runner.mode = "commit-corrupt-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await claim_or_adopt(store, corrupt)

    asyncio.run(scenario())


def test_caller_cancellation_after_commit_repropagates_without_create_proof() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        receipt = claimed_receipt("receipt-cancelled-after-commit")
        current_task = asyncio.current_task()
        assert current_task is not None
        runner.task_to_cancel = current_task
        runner.mode = "commit-then-cancel-caller"

        with pytest.raises(asyncio.CancelledError):
            await claim_or_adopt(store, receipt)

        assert await store.read_receipt(receipt.idempotency_key) == StoredRecord(receipt, 0)
        assert current_task.cancelling() == 0

    asyncio.run(scenario())


def test_ambiguous_cas_with_a_competing_next_revision_is_a_conflict() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        expected = await store.read_authority(root.root_id)
        assert expected is not None
        winning = advanced_authority(authority, suffix="winner")
        assert await store.advance_authority(expected, winning) == StoredRecord(winning, 1)

        runner.mode = "timeout-before-body"
        with pytest.raises(AuthorityStoreConflict):
            await store.advance_authority(
                expected,
                advanced_authority(authority, suffix="loser"),
            )

    asyncio.run(scenario())


def test_corrupt_and_unavailable_reads_fail_closed_with_sanitized_errors() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        receipt = claimed_receipt()
        await claim_or_adopt(store, receipt)
        path = (
            f"{AuthorityStorageKind.EXECUTION_RECEIPT.value}/"
            f"{execution_receipt_document_id(receipt.target, receipt.idempotency_key)}"
        )
        client.documents[path].data["unexpected"] = "provider-secret-detail"

        with pytest.raises(AuthorityStoreCorruptRecord) as corrupt:
            await store.read_receipt(receipt.idempotency_key)
        assert str(corrupt.value) == AuthorityStoreErrorCode.CORRUPT_RECORD.value
        assert "provider-secret-detail" not in str(corrupt.value)

        client.read_error = RuntimeError("credential-shaped-provider-detail")
        with pytest.raises(AuthorityStoreUnavailable) as unavailable:
            await store.read_authority("missing-root")
        assert str(unavailable.value) == AuthorityStoreErrorCode.UNAVAILABLE.value
        assert "credential-shaped-provider-detail" not in str(unavailable.value)

    asyncio.run(scenario())


def test_read_receipt_rejects_a_caller_selected_identity_as_corrupt() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        receipt = claimed_receipt()
        await claim_or_adopt(store, receipt)
        path = (
            f"{AuthorityStorageKind.EXECUTION_RECEIPT.value}/"
            f"{execution_receipt_document_id(receipt.target, receipt.idempotency_key)}"
        )
        attacker_selected = receipt.model_copy(update={"receipt_id": THREE_DIGEST})
        client.documents[path].data["canonical_payload"] = canonical_json_bytes(
            attacker_selected
        ).decode("utf-8")
        client.documents[path].data["payload_sha256"] = canonical_sha256(attacker_selected)

        with pytest.raises(AuthorityStoreCorruptRecord):
            await store.read_receipt(receipt.idempotency_key)

    asyncio.run(scenario())


def test_transactional_authority_read_rejects_revision_corruption_without_writing() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        expected = await store.read_authority(root.root_id)
        assert expected is not None
        path = (
            f"{AuthorityStorageKind.EPOCH_AUTHORITY.value}/"
            f"{epoch_authority_document_id(root.root_id)}"
        )
        client.documents[path].data["revision"] = 1

        with pytest.raises(AuthorityStoreCorruptRecord):
            await store.advance_authority(
                expected,
                advanced_authority(authority, suffix="corrupt"),
            )

        assert client.documents[path].data["revision"] == 1
        assert len(client.documents) == 3

    asyncio.run(scenario())


def test_service_claim_fence_atomically_revokes_then_release_preserves_authority() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        expected_claim = await store.read_service_claim()
        expected_authority = await store.read_authority(root.root_id)
        assert expected_claim is not None
        assert expected_authority is not None
        fenced, released, revoked = release_transition(claim, authority)

        fence_result = await store.fence_service_claim(
            expected_claim,
            fenced,
            expected_authority,
            revoked,
        )
        assert fence_result == FencedServiceClaim(
            service_claim=StoredRecord(fenced, 1),
            authority=StoredRecord(revoked, 1),
        )
        result = await store.release_service_claim(
            fence_result.service_claim,
            released,
            fence_result.authority,
        )
        assert result == ReleasedServiceClaim(
            service_claim=StoredRecord(released, 2),
            authority=StoredRecord(revoked, 1),
        )
        snapshot = await store.read_issuance_state(root.root_id)
        assert snapshot == IssuanceStateSnapshot(
            root=StoredRecord(root, 0),
            service_claim=StoredRecord(released, 2),
            authority=StoredRecord(revoked, 1),
        )
        with pytest.raises(AuthorityStoreConflict):
            await store.release_service_claim(
                fence_result.service_claim,
                released,
                fence_result.authority,
            )

    asyncio.run(scenario())


def test_ambiguous_fence_is_adopted_only_when_both_replacements_match() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, _, revoked = release_transition(claim, authority)
        runner.mode = "commit-then-timeout"

        adopted = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )

        assert adopted == FencedServiceClaim(
            service_claim=StoredRecord(fenced, 1),
            authority=StoredRecord(revoked, 1),
        )

        partial_store, _, partial_runner = store_fixture()
        partial_created = await _create_rollout(partial_store, root, claim, authority)
        partial_runner.mode = "commit-first-only-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await partial_store.fence_service_claim(
                partial_created.service_claim,
                fenced,
                partial_created.authority,
                revoked,
            )

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("root_id", "root-unmatched-release"),
        ("request_id", "request-unmatched-release"),
        ("evidence_id", "evidence-unmatched-release"),
        ("changed_at", "2026-08-19T12:02:01Z"),
    ],
)
def test_fence_rejects_unmatched_transition_bindings_before_writing(
    field: str,
    value: str,
) -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        expected_claim = await store.read_service_claim()
        expected_authority = await store.read_authority(root.root_id)
        assert expected_claim is not None
        assert expected_authority is not None
        fenced, _, revoked = release_transition(claim, authority)
        mismatched = EpochAuthorityRecord(
            **{
                **revoked.model_dump(mode="python"),
                field: value,
            }
        )
        before = deepcopy(client.documents)

        with pytest.raises(ValueError):
            await store.fence_service_claim(
                expected_claim,
                fenced,
                expected_authority,
                mismatched,
            )

        assert client.documents == before

    asyncio.run(scenario())


def test_fence_cannot_replace_the_claimed_candidate_revision_digest() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, _, revoked = release_transition(claim, authority)
        altered = fenced.model_copy(
            update={"candidate_revision_configuration_sha256": TWO_DIGEST}
        )
        before = deepcopy(client.documents)

        with pytest.raises(ValueError, match="exact epoch fence"):
            await store.fence_service_claim(
                created.service_claim,
                altered,
                created.authority,
                revoked,
            )

        assert client.documents == before

    asyncio.run(scenario())


def test_issuance_snapshot_cannot_mix_with_an_interleaved_fence() -> None:
    async def scenario() -> None:
        store, client, runner = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, _, revoked = release_transition(claim, authority)
        client.transaction_read_count = 0
        client.pause_transaction_read_after = 1

        snapshot_task = asyncio.create_task(store.read_issuance_state(root.root_id))
        await asyncio.wait_for(client.transaction_read_paused.wait(), timeout=1)
        fence_task = asyncio.create_task(
            store.fence_service_claim(
                created.service_claim,
                fenced,
                created.authority,
                revoked,
            )
        )
        await asyncio.sleep(0)
        assert not fence_task.done()
        client.continue_transaction_read.set()

        snapshot = await snapshot_task
        fenced_state = await fence_task

        assert snapshot == IssuanceStateSnapshot(
            root=created.root,
            service_claim=created.service_claim,
            authority=created.authority,
        )
        assert fenced_state == FencedServiceClaim(
            service_claim=StoredRecord(fenced, 1),
            authority=StoredRecord(revoked, 1),
        )
        assert await store.read_issuance_state(root.root_id) == IssuanceStateSnapshot(
            root=created.root,
            service_claim=fenced_state.service_claim,
            authority=fenced_state.authority,
        )
        assert runner.expected_writes == [3, 0, 2, 0]
        assert runner.write_result_counts == [3, 0, 2, 0]

    asyncio.run(scenario())


def test_release_requires_a_fenced_claim_and_the_exact_fenced_authority() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, released, revoked = release_transition(claim, authority)
        before = deepcopy(client.documents)

        with pytest.raises(ValueError, match="exact fenced release"):
            await store.release_service_claim(
                created.service_claim,
                released,
                created.authority,
            )
        assert client.documents == before

        fenced_state = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        before = deepcopy(client.documents)
        with pytest.raises(ValueError, match="exact fenced release"):
            await store.release_service_claim(
                fenced_state.service_claim,
                released,
                created.authority,
            )
        assert client.documents == before

    asyncio.run(scenario())


def test_ambiguous_final_release_adopts_only_the_exact_claim_revision() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, released, revoked = release_transition(claim, authority)
        fenced_state = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        runner.mode = "commit-then-timeout"

        adopted = await store.release_service_claim(
            fenced_state.service_claim,
            released,
            fenced_state.authority,
        )

        assert adopted == ReleasedServiceClaim(
            service_claim=StoredRecord(released, 2),
            authority=fenced_state.authority,
        )

        partial_store, _, partial_runner = store_fixture()
        partial_created = await _create_rollout(partial_store, root, claim, authority)
        partial_fenced = await partial_store.fence_service_claim(
            partial_created.service_claim,
            fenced,
            partial_created.authority,
            revoked,
        )
        partial_runner.mode = "commit-first-only-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await partial_store.release_service_claim(
                partial_fenced.service_claim,
                released,
                partial_fenced.authority,
            )

    asyncio.run(scenario())


def test_takeover_is_blocked_until_terminal_release_then_is_explicit() -> None:
    async def scenario() -> None:
        store, client, runner = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, released, revoked = release_transition(claim, authority)
        replacement = initial_records(
            "root-firestore-002",
            captured_at="2026-08-19T12:08:00Z",
            approved_at="2026-08-19T12:09:00Z",
            claimed_at="2026-08-19T12:09:01Z",
            service_generation=15,
        )

        with pytest.raises(ValueError, match="safely released claim"):
            await _create_rollout_after_release(store, created.service_claim, *replacement)

        fenced_state = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        with pytest.raises(ValueError, match="safely released claim"):
            await _create_rollout_after_release(store,
                fenced_state.service_claim,
                *replacement,
            )

        released_state = await store.release_service_claim(
            fenced_state.service_claim,
            released,
            fenced_state.authority,
        )
        before_mismatch = deepcopy(client.documents)
        attempts_before_mismatch = len(runner.maximum_attempts)
        with pytest.raises(ValueError, match="verified candidate configuration"):
            await FirestoreAuthorityStore.create_rollout_after_release(
                store,
                released_state.service_claim,
                *replacement,
                verified_candidate_revision_configuration_sha256=FOUR_DIGEST,
            )
        assert client.documents == before_mismatch
        assert len(runner.maximum_attempts) == attempts_before_mismatch

        takeover = await _create_rollout_after_release(
            store,
            released_state.service_claim,
            *replacement,
        )

        assert takeover.root == StoredRecord(replacement[0], 0)
        assert takeover.service_claim == StoredRecord(replacement[1], 3)
        assert takeover.authority == StoredRecord(replacement[2], 0)
        assert await store.read_service_claim() == takeover.service_claim

    asyncio.run(scenario())


def test_racing_released_claim_takeovers_have_one_winner() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, released, revoked = release_transition(claim, authority)
        fenced_state = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        released_state = await store.release_service_claim(
            fenced_state.service_claim,
            released,
            fenced_state.authority,
        )
        first = initial_records(
            "root-firestore-takeover-a",
            captured_at="2026-08-19T12:08:00Z",
            approved_at="2026-08-19T12:09:00Z",
            claimed_at="2026-08-19T12:09:01Z",
            service_generation=15,
        )
        second = initial_records(
            "root-firestore-takeover-b",
            captured_at="2026-08-19T12:08:00Z",
            approved_at="2026-08-19T12:09:00Z",
            claimed_at="2026-08-19T12:09:01Z",
            service_generation=15,
        )

        results = await asyncio.gather(
            _create_rollout_after_release(store, released_state.service_claim, *first),
            _create_rollout_after_release(store, released_state.service_claim, *second),
            return_exceptions=True,
        )

        winners = [result for result in results if not isinstance(result, BaseException)]
        conflicts = [result for result in results if isinstance(result, AuthorityStoreConflict)]
        assert len(winners) == len(conflicts) == 1
        winner = winners[0]
        assert winner.service_claim.revision == 3
        assert await store.read_service_claim() == winner.service_claim

    asyncio.run(scenario())


def test_ambiguous_takeover_adopts_exact_commit_and_rejects_partial_state() -> None:
    async def released_fixture() -> tuple[
        FirestoreAuthorityStore,
        _FakeTransactionRunner,
        StoredRecord[ServiceClaimRecord],
    ]:
        store, _, runner = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, released, revoked = release_transition(claim, authority)
        fenced_state = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        released_state = await store.release_service_claim(
            fenced_state.service_claim,
            released,
            fenced_state.authority,
        )
        return store, runner, released_state.service_claim

    async def scenario() -> None:
        replacement = initial_records(
            "root-firestore-ambiguous-takeover",
            captured_at="2026-08-19T12:08:00Z",
            approved_at="2026-08-19T12:09:00Z",
            claimed_at="2026-08-19T12:09:01Z",
            service_generation=15,
        )
        store, runner, expected = await released_fixture()
        runner.mode = "commit-then-timeout"

        adopted = await _create_rollout_after_release(store, expected, *replacement)

        assert adopted.root == StoredRecord(replacement[0], 0)
        assert adopted.service_claim == StoredRecord(replacement[1], 3)
        assert adopted.authority == StoredRecord(replacement[2], 0)

        partial_store, partial_runner, partial_expected = await released_fixture()
        partial_runner.mode = "commit-first-only-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await _create_rollout_after_release(partial_store,
                partial_expected,
                *replacement,
            )

    asyncio.run(scenario())


def test_claim_lifecycle_revisions_remain_monotonic_across_multiple_roots() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, released, revoked = release_transition(claim, authority)
        first_fence = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        first_release = await store.release_service_claim(
            first_fence.service_claim,
            released,
            first_fence.authority,
        )
        second = initial_records(
            "root-firestore-cycle-two",
            captured_at="2026-08-19T12:08:00Z",
            approved_at="2026-08-19T12:09:00Z",
            claimed_at="2026-08-19T12:09:01Z",
            service_generation=15,
        )
        takeover = await _create_rollout_after_release(store,
            first_release.service_claim,
            *second,
        )

        with pytest.raises(AuthorityStoreConflict):
            await store.release_service_claim(
                first_fence.service_claim,
                released,
                first_fence.authority,
            )

        second_fenced, second_released, second_revoked = release_transition(
            second[1],
            second[2],
            suffix="cycle-two",
            terminal_confirmed_at="2026-08-19T12:10:00Z",
            fenced_at="2026-08-19T12:11:00Z",
            classified_at="2026-08-19T12:12:00Z",
            released_at="2026-08-19T12:13:00Z",
            classified_generation=16,
        )
        second_fence = await store.fence_service_claim(
            takeover.service_claim,
            second_fenced,
            takeover.authority,
            second_revoked,
        )
        second_release = await store.release_service_claim(
            second_fence.service_claim,
            second_released,
            second_fence.authority,
        )

        assert first_release.service_claim.revision == 2
        assert takeover.service_claim.revision == 3
        assert second_fence.service_claim.revision == 4
        assert second_release.service_claim.revision == 5

    asyncio.run(scenario())


def test_final_authority_snapshot_uses_one_order_independent_batch_get() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        client.document_calls = 0
        client.batch_get_mode = "reversed"

        snapshot = await store.read_final_authority_snapshot(root.root_id)

        assert snapshot == FinalAuthoritySnapshot(
            root=created.root,
            service_claim=created.service_claim,
            authority=created.authority,
        )
        assert client.batch_get_calls == 1
        assert client.document_calls == 3
        paths, field_paths, transaction, retry, timeout, read_time = (
            client.batch_get_arguments[0]
        )
        assert len(paths) == 3
        assert field_paths is transaction is retry is read_time is None
        assert timeout == 5.0

    asyncio.run(scenario())


def test_final_authority_snapshot_returns_none_for_a_complete_missing_response() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        claim_path = (
            f"{AuthorityStorageKind.SERVICE_CLAIM.value}/"
            f"{service_claim_document_id(root.target)}"
        )
        del client.documents[claim_path]

        assert await store.read_final_authority_snapshot(root.root_id) is None
        assert client.batch_get_calls == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mode",
    ["partial", "duplicate", "unexpected", "read-time-regression"],
)
def test_final_authority_snapshot_rejects_malformed_batch_streams(mode: str) -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        client.batch_get_mode = mode

        with pytest.raises(AuthorityStoreCorruptRecord):
            await store.read_final_authority_snapshot(root.root_id)

        assert client.batch_get_calls == 1

    asyncio.run(scenario())


def test_final_authority_snapshot_sanitizes_batch_get_failure() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        await _create_rollout(store, root, claim, authority)
        client.batch_get_mode = "mid-stream-error"

        with pytest.raises(AuthorityStoreUnavailable) as error:
            await store.read_final_authority_snapshot(root.root_id)

        assert str(error.value) == AuthorityStoreErrorCode.UNAVAILABLE.value
        assert "synthetic batch stream detail" not in str(error.value)
        assert client.batch_get_calls == 1

    asyncio.run(scenario())


def test_final_authority_snapshot_captures_claim_fence_before_returning() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, _, revoked = release_transition(claim, authority)
        client.pause_batch_get_before_capture = True

        snapshot_task = asyncio.create_task(
            store.read_final_authority_snapshot(root.root_id)
        )
        await asyncio.wait_for(client.batch_get_started.wait(), timeout=1)
        fenced_state = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        client.continue_batch_get.set()

        assert await snapshot_task == FinalAuthoritySnapshot(
            root=created.root,
            service_claim=fenced_state.service_claim,
            authority=fenced_state.authority,
        )
        assert client.batch_get_calls == 1

    asyncio.run(scenario())


def test_final_authority_batch_get_cannot_mix_with_interleaved_fence() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        created = await _create_rollout(store, root, claim, authority)
        fenced, _, revoked = release_transition(claim, authority)
        client.pause_batch_get_after_first = True

        snapshot_task = asyncio.create_task(
            store.read_final_authority_snapshot(root.root_id)
        )
        await asyncio.wait_for(client.batch_get_first_yielded.wait(), timeout=1)
        fenced_state = await store.fence_service_claim(
            created.service_claim,
            fenced,
            created.authority,
            revoked,
        )
        client.continue_batch_get_stream.set()

        assert await snapshot_task == FinalAuthoritySnapshot(
            root=created.root,
            service_claim=created.service_claim,
            authority=created.authority,
        )
        assert await store.read_final_authority_snapshot(
            root.root_id
        ) == FinalAuthoritySnapshot(
            root=created.root,
            service_claim=fenced_state.service_claim,
            authority=fenced_state.authority,
        )

    asyncio.run(scenario())
