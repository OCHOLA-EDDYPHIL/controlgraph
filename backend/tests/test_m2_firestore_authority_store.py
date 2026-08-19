import asyncio
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from google.api_core import exceptions as api_exceptions

from controlgraph_canary.application.authority_store import (
    AuthorityStore,
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreErrorCode,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    IssuanceStateSnapshot,
    ReleasedServiceClaim,
    StoredRecord,
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
    AuthorityStorageKind,
    ServiceClaimRecord,
    ServiceClaimStatus,
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


def target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id="controlgraph-canary-a1b2c3",
        region="us-central1",
        environment="acceptance",
        service_name="reference-target",
    )


def rollout_root(root_id: str = "root-firestore-001") -> RolloutRoot:
    configured_target = target()
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=configured_target,
        stable_revision="reference-stable",
        traffic=(TrafficAllocation(revision="reference-stable", percent=100),),
        concurrency=8,
        service_generation=12,
        provider_etag="etag-stable-12",
        configuration_sha256=ZERO_DIGEST,
        captured_at="2026-08-19T12:00:00Z",
        captured_by="controlgraph.operator/v1",
    )
    return RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id=root_id,
        target=configured_target,
        stable_snapshot=snapshot,
        candidate_revision="reference-candidate",
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=ONE_DIGEST,
        maximum_recovery_attempts=1,
        initial_epoch=1,
        plan_sha256=TWO_DIGEST,
        approved_by="controlgraph.operator/v1",
        approved_at="2026-08-19T12:01:00Z",
    )


def initial_records(
    root_id: str = "root-firestore-001",
) -> tuple[RolloutRoot, ServiceClaimRecord, EpochAuthorityRecord]:
    root = rollout_root(root_id)
    root_sha256 = canonical_sha256(root)
    claim = ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v1",
        target=root.target,
        root_id=root.root_id,
        root_sha256=root_sha256,
        status=ServiceClaimStatus.ACTIVE,
        claimed_by="controlgraph.api/v1",
        claim_request_id=f"request-{root_id}",
        claim_evidence_id=f"evidence-{root_id}",
        claimed_at="2026-08-19T12:01:01Z",
        released_by=None,
        release_request_id=None,
        release_evidence_id=None,
        released_at=None,
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
        changed_by="controlgraph.api/v1",
        request_id=claim.claim_request_id,
        evidence_id=claim.claim_evidence_id,
        changed_at="2026-08-19T12:01:01Z",
    )
    return root, claim, authority


def advanced_authority(
    current: EpochAuthorityRecord,
    *,
    suffix: str,
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
        changed_at="2026-08-19T12:02:00Z",
    )


def release_transition(
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
    *,
    suffix: str = "release",
) -> tuple[ServiceClaimRecord, EpochAuthorityRecord]:
    replacement_authority = advanced_authority(authority, suffix=suffix)
    replacement_claim = ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASED,
            "released_by": replacement_authority.changed_by,
            "release_request_id": replacement_authority.request_id,
            "release_evidence_id": replacement_authority.evidence_id,
            "released_at": replacement_authority.changed_at,
        }
    )
    return replacement_claim, replacement_authority


def claimed_receipt(seed: str = "firestore-001") -> ExecutionReceipt:
    root = rollout_root()
    idempotency_key = f"intent-{seed}"
    return ExecutionReceipt(
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
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:02:00Z",
        evidence_ids=("evidence-receipt-claimed",),
    )


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
        self.operations: list[tuple[str, _Reference, dict[str, Any]]] = []
        self.write_results: list[object] = []

    def snapshot(self, reference: _Reference) -> _Snapshot:
        return self.client.snapshot(reference)

    def create(self, reference: _Reference, document_data: dict[str, Any]) -> None:
        self.operations.append(("create", reference, deepcopy(document_data)))

    def update(
        self,
        reference: _Reference,
        field_updates: dict[str, Any],
        option: object | None = None,
    ) -> None:
        del option
        self.operations.append(("update", reference, deepcopy(field_updates)))


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

    def document(self, *document_path: str) -> _Reference:
        self.document_calls += 1
        return _Reference(self, "/".join(document_path))

    def transaction(self, max_attempts: int = 3, read_only: bool = False) -> _Transaction:
        del read_only
        return _Transaction(self, max_attempts)

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
            for operation, reference, data in transaction.operations:
                if operation == "create" and reference.path in pending:
                    raise api_exceptions.AlreadyExists("synthetic contention detail")
                if operation == "update" and reference.path not in pending:
                    raise api_exceptions.NotFound("synthetic contention detail")
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

        created = await store.create_rollout(root, claim, authority)

        assert created.root == StoredRecord(root, 0)
        assert created.service_claim == StoredRecord(claim, 0)
        assert created.authority == StoredRecord(authority, 0)
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


def test_racing_root_creates_have_one_service_claim_winner() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        first = initial_records("root-race-first")
        second = initial_records("root-race-second")

        results = await asyncio.gather(
            store.create_rollout(*first),
            store.create_rollout(*second),
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


def test_authority_compare_and_advance_has_one_monotonic_winner() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        root, claim, authority = initial_records()
        await store.create_rollout(root, claim, authority)
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
        await store.create_rollout(root, claim, authority)
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
            store.claim_receipt(receipt),
            store.claim_receipt(receipt),
            return_exceptions=True,
        )
        assert sum(not isinstance(result, Exception) for result in claims) == 1
        assert sum(isinstance(result, AuthorityStoreConflict) for result in claims) == 1
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

        with pytest.raises(ValueError, match="idempotency claim"):
            await store.claim_receipt(substituted)

        assert client.document_calls == 0
        assert client.documents == {}

    asyncio.run(scenario())


def test_same_idempotency_key_with_a_changed_binding_has_one_claim_winner() -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        first = claimed_receipt("shared-idempotency")
        second = ExecutionReceipt(
            **{
                **first.model_dump(mode="python"),
                "request_id": "request-changed-binding",
                "capability_sha256": THREE_DIGEST,
            }
        )

        results = await asyncio.gather(
            store.claim_receipt(first),
            store.claim_receipt(second),
            return_exceptions=True,
        )

        assert sum(not isinstance(result, BaseException) for result in results) == 1
        assert sum(isinstance(result, AuthorityStoreConflict) for result in results) == 1
        assert len(client.documents) == 1
        stored = await store.read_receipt(first.idempotency_key)
        assert stored is not None
        assert stored.value in (first, second)

        losing = second if stored.value == first else first
        with pytest.raises(AuthorityStoreConflict):
            await store.claim_receipt(losing)
        assert len(client.documents) == 1

    asyncio.run(scenario())


def test_receipt_cas_rejects_binding_changes_and_terminal_regression() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        receipt = claimed_receipt()
        expected = await store.claim_receipt(receipt)
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


def test_ambiguous_commit_is_adopted_only_after_exact_readback() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        committed = claimed_receipt("receipt-ambiguous-committed")
        runner.mode = "commit-then-timeout"

        result = await store.claim_receipt(committed)

        assert result == StoredRecord(committed, 0)
        assert await store.read_receipt(committed.idempotency_key) == result
        attempted = ambiguous_receipt(committed, suffix="commit-readback")
        runner.mode = "commit-then-timeout"
        updated = await store.compare_and_set_receipt(result, attempted)
        assert updated == StoredRecord(attempted, 1)
        assert await store.read_receipt(committed.idempotency_key) == updated

        absent = claimed_receipt("receipt-ambiguous-absent")
        runner.mode = "timeout-before-commit"
        with pytest.raises(AuthorityStoreOutcomeUnknown) as error:
            await store.claim_receipt(absent)
        assert str(error.value) == AuthorityStoreErrorCode.OUTCOME_UNKNOWN.value
        assert await store.read_receipt(absent.idempotency_key) is None

        corrupt = claimed_receipt("receipt-ambiguous-corrupt")
        runner.mode = "commit-corrupt-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await store.claim_receipt(corrupt)

    asyncio.run(scenario())


def test_caller_cancellation_after_commit_returns_the_exact_durable_result() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        receipt = claimed_receipt("receipt-cancelled-after-commit")
        current_task = asyncio.current_task()
        assert current_task is not None
        runner.task_to_cancel = current_task
        runner.mode = "commit-then-cancel-caller"

        result = await store.claim_receipt(receipt)

        assert result == StoredRecord(receipt, 0)
        assert await store.read_receipt(receipt.idempotency_key) == result
        assert current_task.cancelling() == 0

    asyncio.run(scenario())


def test_ambiguous_cas_with_a_competing_next_revision_is_a_conflict() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        root, claim, authority = initial_records()
        await store.create_rollout(root, claim, authority)
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
        await store.claim_receipt(receipt)
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
        await store.claim_receipt(receipt)
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
        await store.create_rollout(root, claim, authority)
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


def test_service_claim_release_atomically_advances_authority() -> None:
    async def scenario() -> None:
        store, _, _ = store_fixture()
        root, claim, authority = initial_records()
        await store.create_rollout(root, claim, authority)
        expected_claim = await store.read_service_claim()
        expected_authority = await store.read_authority(root.root_id)
        assert expected_claim is not None
        assert expected_authority is not None
        released, revoked = release_transition(claim, authority)

        result = await store.release_service_claim(
            expected_claim,
            released,
            expected_authority,
            revoked,
        )

        assert result == ReleasedServiceClaim(
            service_claim=StoredRecord(released, 1),
            authority=StoredRecord(revoked, 1),
        )
        snapshot = await store.read_issuance_state(root.root_id)
        assert snapshot == IssuanceStateSnapshot(
            root=StoredRecord(root, 0),
            service_claim=StoredRecord(released, 1),
            authority=StoredRecord(revoked, 1),
        )
        with pytest.raises(AuthorityStoreConflict):
            await store.release_service_claim(
                expected_claim,
                released,
                expected_authority,
                revoked,
            )

    asyncio.run(scenario())


def test_ambiguous_release_is_adopted_only_when_both_replacements_match() -> None:
    async def scenario() -> None:
        store, _, runner = store_fixture()
        root, claim, authority = initial_records()
        created = await store.create_rollout(root, claim, authority)
        released, revoked = release_transition(claim, authority)
        runner.mode = "commit-then-timeout"

        adopted = await store.release_service_claim(
            created.service_claim,
            released,
            created.authority,
            revoked,
        )

        assert adopted == ReleasedServiceClaim(
            service_claim=StoredRecord(released, 1),
            authority=StoredRecord(revoked, 1),
        )

        partial_store, _, partial_runner = store_fixture()
        partial_created = await partial_store.create_rollout(root, claim, authority)
        partial_runner.mode = "commit-first-only-then-timeout"
        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await partial_store.release_service_claim(
                partial_created.service_claim,
                released,
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
def test_release_rejects_unmatched_transition_bindings_before_writing(
    field: str,
    value: str,
) -> None:
    async def scenario() -> None:
        store, client, _ = store_fixture()
        root, claim, authority = initial_records()
        await store.create_rollout(root, claim, authority)
        expected_claim = await store.read_service_claim()
        expected_authority = await store.read_authority(root.root_id)
        assert expected_claim is not None
        assert expected_authority is not None
        released, revoked = release_transition(claim, authority)
        mismatched = EpochAuthorityRecord(
            **{
                **revoked.model_dump(mode="python"),
                field: value,
            }
        )
        before = deepcopy(client.documents)

        with pytest.raises(ValueError):
            await store.release_service_claim(
                expected_claim,
                released,
                expected_authority,
                mismatched,
            )

        assert client.documents == before

    asyncio.run(scenario())


def test_issuance_snapshot_cannot_mix_with_an_interleaved_release() -> None:
    async def scenario() -> None:
        store, client, runner = store_fixture()
        root, claim, authority = initial_records()
        created = await store.create_rollout(root, claim, authority)
        released, revoked = release_transition(claim, authority)
        client.transaction_read_count = 0
        client.pause_transaction_read_after = 1

        snapshot_task = asyncio.create_task(store.read_issuance_state(root.root_id))
        await asyncio.wait_for(client.transaction_read_paused.wait(), timeout=1)
        release_task = asyncio.create_task(
            store.release_service_claim(
                created.service_claim,
                released,
                created.authority,
                revoked,
            )
        )
        await asyncio.sleep(0)
        assert not release_task.done()
        client.continue_transaction_read.set()

        snapshot = await snapshot_task
        released_state = await release_task

        assert snapshot == IssuanceStateSnapshot(
            root=created.root,
            service_claim=created.service_claim,
            authority=created.authority,
        )
        assert released_state == ReleasedServiceClaim(
            service_claim=StoredRecord(released, 1),
            authority=StoredRecord(revoked, 1),
        )
        assert await store.read_issuance_state(root.root_id) == IssuanceStateSnapshot(
            root=created.root,
            service_claim=released_state.service_claim,
            authority=released_state.authority,
        )
        assert runner.expected_writes == [3, 0, 2, 0]
        assert runner.write_result_counts == [3, 0, 2, 0]

    asyncio.run(scenario())
