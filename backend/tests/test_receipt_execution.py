from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from root_v2_support import RootBundle, root_bundle, root_records

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    DirectReceiptCreate,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    ReceiptClaimResult,
    StoredRecord,
    validate_receipt_claim_binding,
)
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.cloud_run import (
    CloudRunMutationOutcome,
    CloudRunMutationReason,
    CloudRunMutationResult,
    CloudRunTrafficAllocation,
    TargetConfigurationProjection,
    target_configuration_projection,
)
from controlgraph_canary.application.execution import (
    FinalMutationGate,
    MutationPermit,
    TargetBoundMutationAdapter,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.receipt_execution import (
    ReceiptClassifyingMutationAdapter,
    ReceiptExecutionCoordinator,
    ReceiptExecutionDenied,
    ReceiptExecutionStored,
    ReceiptMutationResult,
    ReceiptMutationStatus,
    ReceiptReadbackResult,
    map_cloud_run_mutation_result,
)
from controlgraph_canary.authority.replay import MutationBinding
from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    CapabilityClaims,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV2

PROJECT_ID = "controlgraph-canary-a1b2c3"
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
THREE_DIGEST = "3" * 64
NOW = datetime(2026, 8, 19, 12, 3, tzinfo=UTC)
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)


def _target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT_ID,
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )


def _route_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EXECUTOR,
        path=protected_path(ServiceRole.EXECUTOR),
        audience=(
            f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        caller=CallerBinding(
            role=CallerRole.EXECUTION_TASK_CALLER,
            email=(
                f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
            ),
            subject=SUBJECT,
        ),
    )


def _root() -> RolloutRootV2:
    root, _, _, _ = root_records(
        target=_target(),
        candidate_revision_configuration_sha256=THREE_DIGEST,
    )
    return root


def _verified() -> VerifiedMutation:
    root = _root()
    root_sha256 = root.root_sha256
    audience = "https://controlgraph-executor-123456789012.us-central1.run.app"
    claims = CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id="capability-receipt-execution",
        issuer=f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com",
        subject=f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com",
        audience=audience,
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root_sha256,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision=root.content.rollout_plan.stable_revision,
        candidate_revision=root.content.rollout_plan.candidate_revision,
        stable_percent=90,
        candidate_percent=10,
        concurrency=None,
        plan_sha256=canonical_sha256(root.content.rollout_plan),
        provider_etag=root.content.stable_snapshot.provider_etag,
        request_id="request-receipt-execution",
        idempotency_key="intent-receipt-execution",
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:02:00Z",
        not_before="2026-08-19T12:02:00Z",
        expires_at="2026-08-19T12:06:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=KEY_VERSION,
    )
    capability = SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-signature"),
    )
    intent = MutationIntent(
        schema_version="controlgraph.mutation-intent/v1",
        request_id=claims.request_id,
        idempotency_key=claims.idempotency_key,
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root_sha256,
        epoch=claims.epoch,
        action=claims.action,
        stable_revision=claims.stable_revision,
        candidate_revision=claims.candidate_revision,
        stable_percent=claims.stable_percent,
        candidate_percent=claims.candidate_percent,
        concurrency=claims.concurrency,
        plan_sha256=claims.plan_sha256,
        provider_etag=claims.provider_etag,
    )
    request = TaskRequest(
        schema_version="controlgraph.task-request/v1",
        task_id="task-receipt-execution",
        queue_region="us-central1",
        handler_audience=audience,
        scheduled_at="2026-08-19T12:02:00Z",
        expires_at="2026-08-19T12:05:00Z",
        capability=capability,
        intent=intent,
    )
    caller = AuthenticationContext(
        role=CallerRole.EXECUTION_TASK_CALLER,
        email=f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com",
        subject="123456789012345678901",
        issuer="https://accounts.google.com",
        audience=audience,
        issued_at=int(datetime(2026, 8, 19, 12, 0, tzinfo=UTC).timestamp()),
        expires_at=int(datetime(2026, 8, 19, 13, 0, tzinfo=UTC).timestamp()),
    )
    return VerifiedMutation(
        request=request,
        root=root,
        lineage_anchor=root_records(
            target=_target(),
            candidate_revision_configuration_sha256=THREE_DIGEST,
        )[1],
        caller=caller,
        capability_sha256=canonical_sha256(capability),
        claims_sha256=capability.claims_sha256,
        earliest_lineage_issued_at=int(
            datetime(2026, 8, 19, 12, 2, tzinfo=UTC).timestamp()
        ),
    )


def _snapshot(*, epoch: int = 1) -> RootBundle:
    root, anchor, claim, initial_authority = root_records(
        target=_target(),
        candidate_revision_configuration_sha256=THREE_DIGEST,
    )
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        current_epoch=epoch,
        previous_epoch=None if epoch == 1 else epoch - 1,
        revision=epoch - 1,
        cause=(
            EpochChangeCause.ROOT_CREATED
            if epoch == 1
            else EpochChangeCause.OPERATOR_REVOCATION
        ),
        changed_by=(
            initial_authority.changed_by if epoch == 1 else "controlgraph.operator/v1"
        ),
        request_id=f"request-authority-{epoch}",
        evidence_id=f"evidence-authority-{epoch}",
        changed_at=f"2026-08-19T12:0{epoch}:00Z",
    )
    return root_bundle(
        root=root,
        anchor=anchor,
        claim=claim,
        authority=authority,
    )


def _expected_state() -> TargetConfigurationProjection:
    root = _root()
    return target_configuration_projection(
        _verified().request.intent,
        expected_concurrency=root.content.rollout_plan.concurrency,
    )


def _semantic_binding(receipt: ExecutionReceipt) -> tuple[object, ...]:
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


class _Store:
    def __init__(self, events: list[str], *, adopt_fresh: bool = False) -> None:
        self.target = _target()
        self.events = events
        self.adopt_fresh = adopt_fresh
        self.record: StoredRecord[ExecutionReceipt] | None = None
        self.cas_unknown_once = False
        self.cas_unavailable_before_commit = 0
        self._lock = asyncio.Lock()

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        self.events.append("claim")
        validate_receipt_claim_binding(receipt, binding)
        async with self._lock:
            if self.record is None:
                self.record = StoredRecord(receipt, 0)
                if self.adopt_fresh:
                    return ReceiptClaimAdopted(self.record)
                proof = DirectReceiptCreate._from_direct_store_create(
                    self.record,
                    binding,
                )
                return ReceiptClaimCreated(self.record, proof)
            if _semantic_binding(self.record.value) == _semantic_binding(receipt):
                return ReceiptClaimAdopted(self.record)
            return ReceiptClaimConflict()

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        self.events.append("receipt-read")
        if self.record is None or self.record.value.idempotency_key != idempotency_key:
            return None
        return self.record

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        self.events.append("cas")
        if self.record != expected:
            raise AuthorityStoreConflict
        if self.cas_unavailable_before_commit:
            self.cas_unavailable_before_commit -= 1
            raise AuthorityStoreUnavailable
        self.record = StoredRecord(replacement, expected.revision + 1)
        if self.cas_unknown_once:
            self.cas_unknown_once = False
            raise AuthorityStoreOutcomeUnknown
        return self.record


class _SubstitutingClaimStore(_Store):
    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        self.events.append("claim")
        validate_receipt_claim_binding(receipt, binding)
        substituted = ExecutionReceipt(
            **{
                **receipt.model_dump(mode="python"),
                "capability_sha256": ZERO_DIGEST,
            }
        )
        self.record = StoredRecord(substituted, 0)
        return ReceiptClaimAdopted(self.record)


class _BlockingClaimStore(_Store):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self.started = asyncio.Event()
        self.resume = asyncio.Event()

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        self.started.set()
        await self.resume.wait()
        return await super().claim_or_adopt_receipt(receipt, binding)


class _ConflictingResolutionStore(_Store):
    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        self.events.append("cas")
        assert self.record == expected
        conflicting = ExecutionReceipt(
            **{
                **expected.value.model_dump(mode="python"),
                "capability_sha256": ZERO_DIGEST,
                "outcome": ReceiptOutcome.FAILED_SAFE,
                "reason_code": ReasonCode.PROVIDER_REQUEST_REJECTED,
                "updated_at": replacement.updated_at,
            }
        )
        self.record = StoredRecord(conflicting, expected.revision + 1)
        raise AuthorityStoreOutcomeUnknown


class _OperationSubstitutionStore(_Store):
    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        if expected.value.outcome is not ReceiptOutcome.APPLIED:
            return await super().compare_and_set_receipt(expected, replacement)
        self.events.append("cas")
        assert self.record == expected
        substituted = ExecutionReceipt(
            **{
                **replacement.model_dump(mode="python"),
                "provider_operation": "operations/substituted",
            }
        )
        self.record = StoredRecord(substituted, expected.revision + 1)
        raise AuthorityStoreOutcomeUnknown


class _Reader:
    def __init__(
        self,
        snapshot: RootBundle,
        events: list[str],
    ) -> None:
        self.target = _target()
        self.snapshot = snapshot
        self.events = events
        self.pause = False
        self.started = asyncio.Event()
        self.resume = asyncio.Event()

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootBundle:
        assert root_id == _root().root_id
        self.events.append("authority")
        self.started.set()
        if self.pause:
            await self.resume.wait()
        return self.snapshot


class _Adapter:
    def __init__(
        self,
        result: ReceiptMutationResult,
        events: list[str],
        *,
        error: Exception | None = None,
    ) -> None:
        self.target = _target()
        self.service_role = ServiceRole.EXECUTOR
        self.result = result
        self.events = events
        self.error = error
        self.calls: list[MutationIntent] = []
        self._prepared_intent: MutationIntent | None = None

    @property
    def intent(self) -> MutationIntent:
        assert self._prepared_intent is not None
        return self._prepared_intent

    async def prepare(self, intent: MutationIntent) -> _Adapter:
        self._prepared_intent = intent
        return self

    async def mutate(self, permit: MutationPermit) -> ReceiptMutationResult:
        self.events.append("adapter")
        self.calls.append(permit.intent)
        if self.error is not None:
            raise self.error
        return self.result


class _CloudRunAdapterSpy:
    def __init__(
        self,
        result: CloudRunMutationResult,
        events: list[str],
        *,
        error: BaseException | None = None,
    ) -> None:
        self.target = _target()
        self.service_role = ServiceRole.EXECUTOR
        self.result = result
        self.events = events
        self.error = error
        self.calls: list[MutationIntent] = []
        self._prepared_intent: MutationIntent | None = None

    @property
    def intent(self) -> MutationIntent:
        assert self._prepared_intent is not None
        return self._prepared_intent

    async def prepare(self, intent: MutationIntent) -> _CloudRunAdapterSpy:
        self._prepared_intent = intent
        return self

    async def mutate(self, permit: MutationPermit) -> CloudRunMutationResult:
        self.events.append("cloud-run-adapter")
        self.calls.append(permit.intent)
        if self.error is not None:
            raise self.error
        return self.result


class _PreparationFailureAdapter(_Adapter):
    async def prepare(self, intent: MutationIntent) -> _PreparationFailureAdapter:
        del intent
        raise RuntimeError("synthetic preparation failure")


class _Readback:
    def __init__(
        self,
        observations: list[ReceiptReadbackResult],
        events: list[str],
    ) -> None:
        self.target = _target()
        self.observations = observations
        self.events = events
        self.calls: list[TargetConfigurationProjection] = []

    async def readback(
        self,
        expected: TargetConfigurationProjection,
    ) -> ReceiptReadbackResult:
        self.events.append("readback")
        self.calls.append(expected)
        if len(self.observations) > 1:
            return self.observations.pop(0)
        return self.observations[0]


class _Clock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _applied() -> ReceiptMutationResult:
    return ReceiptMutationResult(
        status=ReceiptMutationStatus.APPLIED,
        provider_operation="operations/apply-canary-001",
        reason_code=None,
    )


def _exact_readback() -> ReceiptReadbackResult:
    return ReceiptReadbackResult(
        state=_expected_state(),
        observed_etag="etag-canary-8",
    )


def _coordinator(
    store: _Store,
    reader: _Reader,
    adapter: TargetBoundMutationAdapter[ReceiptMutationResult],
    readback: _Readback,
    clock: _Clock,
) -> ReceiptExecutionCoordinator:
    return ReceiptExecutionCoordinator(
        store=store,
        final_gate=FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            route_policy=_route_policy(),
            clock=clock,
        ),
        readback=readback,
        clock=clock,
    )


def _cloud_run_result(
    outcome: CloudRunMutationOutcome,
    *,
    reason: CloudRunMutationReason | None,
    operation_name: str | None = None,
) -> CloudRunMutationResult:
    return CloudRunMutationResult(
        outcome=outcome,
        requested_traffic=(
            CloudRunTrafficAllocation(
                revision="controlgraph-reference-target-stable-v13",
                percent=90,
                tag="stable",
            ),
            CloudRunTrafficAllocation(
                revision="controlgraph-reference-target-candidate-v13",
                percent=10,
                tag="candidate",
            ),
        ),
        expected_concurrency=40,
        operation_name=operation_name,
        service=None,
        reason=reason,
    )


def test_direct_claim_dispatches_once_and_verifies_in_exact_order() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        reader = _Reader(_snapshot(), events)
        adapter = _Adapter(_applied(), events)
        readback = _Readback([_exact_readback()], events)
        result = await _coordinator(
            store,
            reader,
            adapter,
            readback,
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.revision == 2
        assert result.receipt.value.outcome is ReceiptOutcome.VERIFIED
        assert result.receipt.value.observed_authority_epoch == 1
        assert result.receipt.value.evidence_ids == ()
        assert len(adapter.calls) == 1
        assert events == ["claim", "authority", "adapter", "cas", "readback", "cas"]

    asyncio.run(scenario())


def test_adapter_preparation_failure_is_denied_without_ambiguous_provider_state() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        reader = _Reader(_snapshot(), events)
        adapter = _PreparationFailureAdapter(_applied(), events)
        readback = _Readback([_exact_readback()], events)

        result = await _coordinator(
            store,
            reader,
            adapter,
            readback,
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.DENIED
        assert result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert result.receipt.value.provider_operation is None
        assert adapter.calls == []
        assert events == ["claim", "cas"]

    asyncio.run(scenario())


def test_concurrent_exact_duplicate_has_one_adapter_call() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        reader = _Reader(_snapshot(), events)
        reader.pause = True
        adapter = _Adapter(_applied(), events)
        readback = _Readback([_exact_readback()], events)
        coordinator = _coordinator(store, reader, adapter, readback, _Clock())

        winner = asyncio.create_task(coordinator.execute(_verified()))
        await asyncio.wait_for(reader.started.wait(), timeout=1)
        duplicate = await coordinator.execute(_verified())
        assert type(duplicate) is ReceiptExecutionStored
        assert duplicate.receipt.value.outcome is ReceiptOutcome.CLAIMED
        assert duplicate.reason_code is ReasonCode.RECEIPT_IN_PROGRESS
        assert adapter.calls == []

        reader.resume.set()
        completed = await winner
        assert type(completed) is ReceiptExecutionStored
        assert completed.receipt.value.outcome is ReceiptOutcome.VERIFIED
        assert len(adapter.calls) == 1

    asyncio.run(scenario())


def test_caller_expiring_while_receipt_claim_waits_never_reaches_adapter() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _BlockingClaimStore(events)
        reader = _Reader(_snapshot(), events)
        adapter = _Adapter(_applied(), events)
        readback = _Readback([_exact_readback()], events)
        clock = _Clock()
        original = _verified()
        verified = replace(
            original,
            caller=replace(
                original.caller,
                expires_at=int((NOW + timedelta(seconds=1)).timestamp()),
            ),
        )
        coordinator = _coordinator(store, reader, adapter, readback, clock)

        pending = asyncio.create_task(coordinator.execute(verified))
        await asyncio.wait_for(store.started.wait(), timeout=1)
        clock.value = NOW + timedelta(seconds=2)
        store.resume.set()
        result = await pending

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.DENIED
        assert result.reason_code is ReasonCode.CALLER_UNAUTHORIZED
        assert adapter.calls == []
        assert "authority" in events
        assert "adapter" not in events

    asyncio.run(scenario())


def test_commit_response_loss_adopts_claim_without_dispatch_proof() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events, adopt_fresh=True)
        reader = _Reader(_snapshot(), events)
        adapter = _Adapter(_applied(), events)
        clock = _Clock()
        readback = _Readback([_exact_readback()], events)
        coordinator = _coordinator(
            store,
            reader,
            adapter,
            readback,
            clock,
        )
        result = await coordinator.execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.reason_code is ReasonCode.RECEIPT_IN_PROGRESS
        assert adapter.calls == []
        assert "authority" not in events
        assert readback.calls == []

        clock.value = datetime(2026, 8, 19, 12, 4, 1, tzinfo=UTC)
        recovered = await coordinator.execute(_verified())

        assert type(recovered) is ReceiptExecutionStored
        assert recovered.receipt.value.outcome is ReceiptOutcome.VERIFIED
        assert recovered.receipt.value.observed_authority_epoch is None
        assert adapter.calls == []
        assert len(readback.calls) == 1
        assert "authority" not in events

    asyncio.run(scenario())


def test_terminal_duplicate_returns_exact_stored_receipt_without_redispatch() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        reader = _Reader(_snapshot(), events)
        adapter = _Adapter(_applied(), events)
        readback = _Readback([_exact_readback()], events)
        coordinator = _coordinator(store, reader, adapter, readback, _Clock())

        first = await coordinator.execute(_verified())
        assert type(first) is ReceiptExecutionStored
        event_count = len(events)
        second = await coordinator.execute(_verified())

        assert second == first
        assert len(adapter.calls) == 1
        assert len(readback.calls) == 1
        assert events[event_count:] == ["claim"]

    asyncio.run(scenario())


def test_changed_capability_binding_is_conflict_without_existing_receipt_exposure() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events, adopt_fresh=True)
        reader = _Reader(_snapshot(), events)
        adapter = _Adapter(_applied(), events)
        coordinator = _coordinator(
            store,
            reader,
            adapter,
            _Readback([_exact_readback()], events),
            _Clock(),
        )
        assert type(await coordinator.execute(_verified())) is ReceiptExecutionStored

        changed = replace(_verified(), capability_sha256=ZERO_DIGEST)
        result = await coordinator.execute(changed)

        assert result == ReceiptExecutionDenied(ReasonCode.IDEMPOTENCY_CONFLICT)
        assert adapter.calls == []

    asyncio.run(scenario())


def test_orphaned_claim_is_resolved_by_readback_without_dispatch() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events, adopt_fresh=True)
        reader = _Reader(_snapshot(), events)
        adapter = _Adapter(_applied(), events)
        clock = _Clock()
        coordinator = _coordinator(
            store,
            reader,
            adapter,
            _Readback([_exact_readback()], events),
            clock,
        )
        in_progress = await coordinator.execute(_verified())
        assert type(in_progress) is ReceiptExecutionStored
        assert in_progress.reason_code is ReasonCode.RECEIPT_IN_PROGRESS

        clock.value = datetime(2026, 8, 19, 12, 6, tzinfo=UTC)
        recovered = await coordinator.recover_orphaned(_verified())

        assert type(recovered) is ReceiptExecutionStored
        assert recovered.receipt.value.outcome is ReceiptOutcome.VERIFIED
        assert recovered.receipt.revision == 2
        assert recovered.receipt.value.observed_authority_epoch is None
        assert adapter.calls == []
        assert "authority" not in events

    asyncio.run(scenario())


def test_ambiguous_provider_result_never_redispatches_and_requires_readback() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        reader = _Reader(_snapshot(), events)
        ambiguous = ReceiptMutationResult(
            status=ReceiptMutationStatus.AMBIGUOUS,
            provider_operation=None,
            reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
        )
        adapter = _Adapter(ambiguous, events)
        mismatch = ReceiptReadbackResult(
            state=replace(_expected_state(), candidate_percent=100, stable_percent=0),
            observed_etag="etag-unexpected-8",
        )
        readback = _Readback([mismatch], events)
        clock = _Clock()
        coordinator = _coordinator(store, reader, adapter, readback, clock)

        first = await coordinator.execute(_verified())
        cas_count = events.count("cas")
        assert type(first) is ReceiptExecutionStored
        first_revision = first.receipt.revision
        clock.value = datetime(2026, 8, 19, 12, 4, tzinfo=UTC)
        second = await coordinator.execute(_verified())

        assert first.receipt.value.outcome is ReceiptOutcome.AMBIGUOUS
        assert type(second) is ReceiptExecutionStored
        assert second.receipt.value.outcome is ReceiptOutcome.AMBIGUOUS
        assert second.receipt.revision == first_revision
        assert events.count("cas") == cas_count
        assert len(adapter.calls) == 1
        assert len(readback.calls) == 2

    asyncio.run(scenario())


def test_adapter_exception_and_receipt_cas_ambiguity_use_readback_without_retry() -> None:
    async def adapter_error_scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        reader = _Reader(_snapshot(), events)
        adapter = _Adapter(
            _applied(),
            events,
            error=RuntimeError("synthetic provider response loss"),
        )
        result = await _coordinator(
            store,
            reader,
            adapter,
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.VERIFIED
        assert len(adapter.calls) == 1

    async def cas_unknown_scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        store.cas_unknown_once = True
        reader = _Reader(_snapshot(), events)
        adapter = _Adapter(_applied(), events)
        result = await _coordinator(
            store,
            reader,
            adapter,
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.VERIFIED
        assert len(adapter.calls) == 1
        assert "receipt-read" in events

    asyncio.run(adapter_error_scenario())
    asyncio.run(cas_unknown_scenario())


def test_precommit_receipt_failure_retries_result_persistence_before_readback() -> None:
    async def failed_safe_scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        store.cas_unavailable_before_commit = 1
        failed = ReceiptMutationResult(
            status=ReceiptMutationStatus.FAILED_SAFE,
            provider_operation=None,
            reason_code=ReasonCode.TARGET_BINDING_MISMATCH,
        )
        adapter = _Adapter(failed, events)
        readback = _Readback([_exact_readback()], events)

        result = await _coordinator(
            store,
            _Reader(_snapshot(), events),
            adapter,
            readback,
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.FAILED_SAFE
        assert result.receipt.value.reason_code is ReasonCode.TARGET_BINDING_MISMATCH
        assert result.receipt.value.observed_authority_epoch == 1
        assert events.count("cas") == 2
        assert readback.calls == []

    async def applied_scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        store.cas_unavailable_before_commit = 1
        readback = _Readback([_exact_readback()], events)

        result = await _coordinator(
            store,
            _Reader(_snapshot(), events),
            _Adapter(_applied(), events),
            readback,
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.VERIFIED
        assert result.receipt.value.provider_operation == "operations/apply-canary-001"
        assert result.receipt.value.observed_authority_epoch == 1
        assert events.count("cas") == 3

    async def authority_denial_scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        store.cas_unavailable_before_commit = 1
        adapter = _Adapter(_applied(), events)
        readback = _Readback([_exact_readback()], events)

        result = await _coordinator(
            store,
            _Reader(_snapshot(epoch=2), events),
            adapter,
            readback,
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.DENIED
        assert result.receipt.value.reason_code is ReasonCode.EPOCH_MISMATCH
        assert result.receipt.value.observed_authority_epoch == 2
        assert events.count("cas") == 2
        assert adapter.calls == []
        assert readback.calls == []

    asyncio.run(failed_safe_scenario())
    asyncio.run(applied_scenario())
    asyncio.run(authority_denial_scenario())


def test_cloud_run_wrapper_composes_final_gate_and_receipt_classification_once() -> None:
    async def failed_safe_scenario() -> None:
        events: list[str] = []
        delegate = _CloudRunAdapterSpy(
            _cloud_run_result(
                CloudRunMutationOutcome.FAILED_SAFE,
                reason=CloudRunMutationReason.DECLARATION_MISMATCH,
            ),
            events,
        )
        adapter = ReceiptClassifyingMutationAdapter(delegate)
        result = await _coordinator(
            _Store(events),
            _Reader(_snapshot(), events),
            adapter,
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.FAILED_SAFE
        assert result.reason_code is ReasonCode.TARGET_BINDING_MISMATCH
        assert len(delegate.calls) == 1
        assert events.count("cloud-run-adapter") == 1

    async def ambiguous_scenario() -> None:
        events: list[str] = []
        delegate = _CloudRunAdapterSpy(
            _cloud_run_result(
                CloudRunMutationOutcome.AMBIGUOUS,
                reason=CloudRunMutationReason.OUTCOME_UNKNOWN,
                operation_name="operations/unknown-001",
            ),
            events,
        )
        mismatch = ReceiptReadbackResult(
            state=replace(_expected_state(), stable_percent=0, candidate_percent=100),
            observed_etag="etag-other",
        )
        result = await _coordinator(
            _Store(events),
            _Reader(_snapshot(), events),
            ReceiptClassifyingMutationAdapter(delegate),
            _Readback([mismatch], events),
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.AMBIGUOUS
        assert result.receipt.value.provider_operation == "operations/unknown-001"
        assert len(delegate.calls) == 1

    asyncio.run(failed_safe_scenario())
    asyncio.run(ambiguous_scenario())


def test_cloud_run_wrapper_propagates_cancellation_without_a_second_call() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        delegate = _CloudRunAdapterSpy(
            _cloud_run_result(
                CloudRunMutationOutcome.AMBIGUOUS,
                reason=CloudRunMutationReason.OUTCOME_UNKNOWN,
            ),
            events,
            error=asyncio.CancelledError(),
        )
        coordinator = _coordinator(
            store,
            _Reader(_snapshot(), events),
            ReceiptClassifyingMutationAdapter(delegate),
            _Readback([_exact_readback()], events),
            _Clock(),
        )

        with pytest.raises(asyncio.CancelledError):
            await coordinator.execute(_verified())

        assert len(delegate.calls) == 1
        assert store.record is not None
        assert store.record.value.outcome is ReceiptOutcome.CLAIMED

    asyncio.run(scenario())


def test_unpersisted_known_result_never_falls_through_to_success_readback() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        store.cas_unavailable_before_commit = 2
        adapter = _Adapter(
            ReceiptMutationResult(
                status=ReceiptMutationStatus.FAILED_SAFE,
                provider_operation=None,
                reason_code=ReasonCode.PROVIDER_REQUEST_REJECTED,
            ),
            events,
        )
        readback = _Readback([_exact_readback()], events)

        result = await _coordinator(
            store,
            _Reader(_snapshot(), events),
            adapter,
            readback,
            _Clock(),
        ).execute(_verified())

        assert result == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        assert store.record is not None
        assert store.record.value.outcome is ReceiptOutcome.CLAIMED
        assert readback.calls == []
        assert len(adapter.calls) == 1

    asyncio.run(scenario())


def test_substituted_claim_and_conflicting_cas_readback_never_gain_authority() -> None:
    async def substituted_claim_scenario() -> None:
        events: list[str] = []
        store = _SubstitutingClaimStore(events)
        adapter = _Adapter(_applied(), events)
        result = await _coordinator(
            store,
            _Reader(_snapshot(), events),
            adapter,
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(_verified())

        assert result == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        assert adapter.calls == []
        assert events == ["claim"]

    async def conflicting_readback_scenario() -> None:
        events: list[str] = []
        store = _ConflictingResolutionStore(events)
        adapter = _Adapter(_applied(), events)
        result = await _coordinator(
            store,
            _Reader(_snapshot(), events),
            adapter,
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(_verified())

        assert result == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        assert len(adapter.calls) == 1
        assert events[-2:] == ["cas", "receipt-read"]

    asyncio.run(substituted_claim_scenario())
    asyncio.run(conflicting_readback_scenario())


def test_cas_readback_cannot_substitute_the_provider_operation() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _OperationSubstitutionStore(events)
        result = await _coordinator(
            store,
            _Reader(_snapshot(), events),
            _Adapter(_applied(), events),
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(_verified())

        assert result == ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        assert store.record is not None
        assert store.record.value.provider_operation == "operations/substituted"

    asyncio.run(scenario())


def test_stale_epoch_denial_records_issued_and_observed_epochs() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        reader = _Reader(_snapshot(epoch=2), events)
        adapter = _Adapter(_applied(), events)
        result = await _coordinator(
            store,
            reader,
            adapter,
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        receipt = result.receipt.value
        assert receipt.outcome is ReceiptOutcome.DENIED
        assert receipt.reason_code is ReasonCode.EPOCH_MISMATCH
        assert receipt.epoch == 1
        assert receipt.observed_authority_epoch == 2
        assert adapter.calls == []

    asyncio.run(scenario())


def test_structural_authority_corruption_denies_without_unrelated_epoch() -> None:
    async def scenario() -> None:
        events: list[str] = []
        snapshot = _snapshot()
        corrupt = replace(
            snapshot,
            authority=StoredRecord(snapshot.authority.value, 1),
        )
        store = _Store(events)
        adapter = _Adapter(_applied(), events)
        result = await _coordinator(
            store,
            _Reader(corrupt, events),
            adapter,
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        receipt = result.receipt.value
        assert receipt.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert receipt.observed_authority_epoch is None
        assert adapter.calls == []

    asyncio.run(scenario())


def test_failed_safe_result_is_terminal_without_readback() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        failed = ReceiptMutationResult(
            status=ReceiptMutationStatus.FAILED_SAFE,
            provider_operation=None,
            reason_code=ReasonCode.PROVIDER_PRECONDITION_FAILED,
        )
        adapter = _Adapter(failed, events)
        readback = _Readback([_exact_readback()], events)
        result = await _coordinator(
            store,
            _Reader(_snapshot(), events),
            adapter,
            readback,
            _Clock(),
        ).execute(_verified())

        assert type(result) is ReceiptExecutionStored
        assert result.receipt.value.outcome is ReceiptOutcome.FAILED_SAFE
        assert result.receipt.value.observed_authority_epoch == 1
        assert readback.calls == []
        assert len(adapter.calls) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "reason",
    [
        ReasonCode.PROVIDER_PRECONDITION_FAILED,
        ReasonCode.TARGET_BINDING_MISMATCH,
        ReasonCode.PROVIDER_REQUEST_REJECTED,
    ],
)
def test_failed_safe_mutation_result_accepts_only_sanitized_reasons(
    reason: ReasonCode,
) -> None:
    result = ReceiptMutationResult(
        status=ReceiptMutationStatus.FAILED_SAFE,
        provider_operation=None,
        reason_code=reason,
    )

    assert result.reason_code is reason

    with pytest.raises(ValueError, match="failed-safe mutation result"):
        ReceiptMutationResult(
            status=ReceiptMutationStatus.FAILED_SAFE,
            provider_operation=None,
            reason_code=ReasonCode.AUTHORITY_UNAVAILABLE,
        )
    with pytest.raises(ValueError, match="failed-safe mutation result"):
        ReceiptMutationResult(
            status=ReceiptMutationStatus.FAILED_SAFE,
            provider_operation="operations/forbidden",
            reason_code=reason,
        )


@pytest.mark.parametrize(
    ("provider_reason", "receipt_reason"),
    [
        (
            CloudRunMutationReason.PRECONDITION_FAILED,
            ReasonCode.PROVIDER_PRECONDITION_FAILED,
        ),
        (
            CloudRunMutationReason.DECLARATION_MISMATCH,
            ReasonCode.TARGET_BINDING_MISMATCH,
        ),
        (
            CloudRunMutationReason.PROVIDER_REJECTED,
            ReasonCode.PROVIDER_REQUEST_REJECTED,
        ),
    ],
)
def test_cloud_run_failed_safe_mapping_is_lossless(
    provider_reason: CloudRunMutationReason,
    receipt_reason: ReasonCode,
) -> None:
    traffic = (
        CloudRunTrafficAllocation(
            revision="controlgraph-reference-target-stable-v13",
            percent=90,
            tag="stable",
        ),
        CloudRunTrafficAllocation(
            revision="controlgraph-reference-target-candidate-v13",
            percent=10,
            tag="candidate",
        ),
    )
    mapped = map_cloud_run_mutation_result(
        CloudRunMutationResult(
            outcome=CloudRunMutationOutcome.FAILED_SAFE,
            requested_traffic=traffic,
            expected_concurrency=40,
            operation_name=None,
            service=None,
            reason=provider_reason,
        )
    )

    assert mapped == ReceiptMutationResult(
        status=ReceiptMutationStatus.FAILED_SAFE,
        provider_operation=None,
        reason_code=receipt_reason,
    )


def test_expired_verified_input_creates_no_receipt_and_malformed_input_is_rejected() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        coordinator = _coordinator(
            store,
            _Reader(_snapshot(), events),
            _Adapter(_applied(), events),
            _Readback([_exact_readback()], events),
            _Clock(datetime(2026, 8, 19, 12, 5, tzinfo=UTC)),
        )

        assert await coordinator.execute(_verified()) == ReceiptExecutionDenied(
            ReasonCode.CAPABILITY_EXPIRED
        )
        with pytest.raises(TypeError, match="verified mutation"):
            await coordinator.execute(object())  # type: ignore[arg-type]
        assert store.record is None
        assert events == ["receipt-read"]

    asyncio.run(scenario())


def test_delayed_first_delivery_refuses_a_claim_without_recovery_time() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        adapter = _Adapter(_applied(), events)
        readback = _Readback([_exact_readback()], events)
        coordinator = _coordinator(
            store,
            _Reader(_snapshot(), events),
            adapter,
            readback,
            _Clock(datetime(2026, 8, 19, 12, 3, 30, tzinfo=UTC)),
        )

        result = await coordinator.execute(_verified())

        assert result == ReceiptExecutionDenied(ReasonCode.CAPABILITY_EXPIRED)
        assert store.record is None
        assert adapter.calls == []
        assert readback.calls == []
        assert events == ["receipt-read"]

    asyncio.run(scenario())


def test_expired_orphaned_claim_uses_readback_without_mutation() -> None:
    async def scenario() -> None:
        events: list[str] = []
        clock = _Clock()
        store = _Store(events, adopt_fresh=True)
        adapter = _Adapter(_applied(), events)
        readback = _Readback([_exact_readback()], events)
        coordinator = _coordinator(
            store,
            _Reader(_snapshot(), events),
            adapter,
            readback,
            clock,
        )
        claimed = await coordinator.execute(_verified())
        assert type(claimed) is ReceiptExecutionStored
        assert claimed.receipt.value.outcome is ReceiptOutcome.CLAIMED
        event_count = len(events)
        clock.value = datetime(2026, 8, 19, 12, 6, tzinfo=UTC)

        recovered = await coordinator.execute(_verified())

        assert type(recovered) is ReceiptExecutionStored
        assert recovered.receipt.value.outcome is ReceiptOutcome.VERIFIED
        assert recovered.receipt.value.observed_authority_epoch is None
        assert adapter.calls == []
        assert events[event_count:] == ["receipt-read", "readback", "cas", "cas"]

    asyncio.run(scenario())


def test_expired_exact_replay_returns_original_terminal_receipt() -> None:
    async def scenario() -> None:
        events: list[str] = []
        clock = _Clock()
        store = _Store(events)
        adapter = _Adapter(_applied(), events)
        coordinator = _coordinator(
            store,
            _Reader(_snapshot(), events),
            adapter,
            _Readback([_exact_readback()], events),
            clock,
        )
        terminal = await coordinator.execute(_verified())
        assert type(terminal) is ReceiptExecutionStored
        event_count = len(events)
        clock.value = datetime(2026, 8, 19, 12, 6, tzinfo=UTC)

        replay = await coordinator.execute(_verified())

        assert replay == terminal
        assert events[event_count:] == ["receipt-read"]
        assert len(adapter.calls) == 1

    asyncio.run(scenario())


def test_forged_recovery_concurrency_is_denied_before_receipt_claim() -> None:
    async def scenario() -> None:
        events: list[str] = []
        store = _Store(events)
        verified = _verified()
        intent = verified.request.intent.model_copy(update={"concurrency": 41})
        forged = replace(
            verified,
            request=verified.request.model_copy(update={"intent": intent}),
        )

        result = await _coordinator(
            store,
            _Reader(_snapshot(), events),
            _Adapter(_applied(), events),
            _Readback([_exact_readback()], events),
            _Clock(),
        ).execute(forged)

        assert result == ReceiptExecutionDenied(ReasonCode.TARGET_BINDING_MISMATCH)
        assert store.record is None
        assert events == []

    asyncio.run(scenario())
