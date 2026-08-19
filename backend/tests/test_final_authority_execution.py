from __future__ import annotations

import ast
import asyncio
import inspect
import textwrap
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from controlgraph_canary.application.authority_store import (
    AuthorityStoreCorruptRecord,
    AuthorityStoreUnavailable,
    DirectReceiptCreate,
    FinalAuthoritySnapshot,
    StoredRecord,
)
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.execution import (
    DefinitiveFreshClaimLeaseFactory,
    FinalAuthorityDenial,
    FinalMutationGate,
    FinalMutationResult,
    MutationPermit,
    ReceiptDispatchLease,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    ServiceRole,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityClaims,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    RolloutRoot,
    SignedCapability,
    StableSnapshot,
    TargetBinding,
    TaskRequest,
    TrafficAllocation,
    canonical_sha256,
    encode_base64url,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    ServiceClaimStatus,
    execution_receipt_logical_id,
)

PROJECT_ID = "controlgraph-canary-a1b2c3"
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
THREE_DIGEST = "3" * 64
KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)
NOW = datetime(2026, 8, 19, 12, 3, tzinfo=UTC)


def _target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT_ID,
        region="us-central1",
        environment="acceptance",
        service_name="reference-target",
    )


def _root() -> RolloutRoot:
    target = _target()
    stable = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=target,
        stable_revision="reference-stable",
        traffic=(TrafficAllocation(revision="reference-stable", percent=100),),
        concurrency=40,
        service_generation=7,
        provider_etag="etag-stable-7",
        configuration_sha256=ZERO_DIGEST,
        stable_revision_configuration_sha256=ONE_DIGEST,
        captured_at="2026-08-19T12:00:00Z",
        captured_by="controlgraph.operator/v1",
    )
    return RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id="root-final-gate",
        target=target,
        stable_snapshot=stable,
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


def _action_shape(action: CapabilityAction) -> tuple[int, int, int | None]:
    if action is CapabilityAction.APPLY_CANARY:
        return 90, 10, None
    if action is CapabilityAction.PROMOTE_CANDIDATE:
        return 0, 100, None
    return 100, 0, 40


def _verified(
    *,
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
    epoch: int = 1,
) -> VerifiedMutation:
    root = _root()
    role = (
        ServiceRole.RECOVERY
        if action is CapabilityAction.RECOVER_STABLE
        else ServiceRole.EXECUTOR
    )
    stable_percent, candidate_percent, concurrency = _action_shape(action)
    audience = f"https://controlgraph-{role.value}-123456789012.us-central1.run.app"
    claims = CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id=f"capability-{action.value.lower()}",
        issuer=f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com",
        subject=f"controlgraph-{role.value}@{PROJECT_ID}.iam.gserviceaccount.com",
        audience=audience,
        target=root.target,
        root_id=root.root_id,
        root_sha256=canonical_sha256(root),
        epoch=epoch,
        action=action,
        stable_revision=root.stable_snapshot.stable_revision,
        candidate_revision=root.candidate_revision,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=concurrency,
        plan_sha256=root.plan_sha256,
        provider_etag=root.stable_snapshot.provider_etag,
        request_id=f"request-{action.value.lower()}-{epoch}",
        idempotency_key=f"intent-{action.value.lower()}-{epoch}",
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:02:00Z",
        not_before="2026-08-19T12:02:00Z",
        expires_at="2026-08-19T12:07:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=KEY_VERSION,
    )
    capability = SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-final-gate-signature"),
    )
    intent = MutationIntent(
        schema_version="controlgraph.mutation-intent/v1",
        request_id=claims.request_id,
        idempotency_key=claims.idempotency_key,
        target=claims.target,
        root_id=claims.root_id,
        root_sha256=claims.root_sha256,
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
        task_id=f"task-{action.value.lower()}-{epoch}",
        queue_region=root.target.region,
        handler_audience=audience,
        scheduled_at=claims.not_before,
        expires_at=claims.expires_at,
        capability=capability,
        intent=intent,
    )
    caller_role = (
        CallerRole.RECOVERY_TASK_CALLER
        if role is ServiceRole.RECOVERY
        else CallerRole.EXECUTION_TASK_CALLER
    )
    caller = AuthenticationContext(
        role=caller_role,
        email=f"caller@{PROJECT_ID}.iam.gserviceaccount.com",
        subject="123456789012345678901",
        issuer="https://accounts.google.com",
        audience=audience,
        issued_at=1,
        expires_at=2,
    )
    return VerifiedMutation(
        request=request,
        root=root,
        caller=caller,
        capability_sha256=canonical_sha256(capability),
        claims_sha256=capability.claims_sha256,
        earliest_lineage_issued_at=int(
            datetime(2026, 8, 19, 12, 2, tzinfo=UTC).timestamp()
        ),
    )


def _binding(verified: VerifiedMutation) -> MutationBinding:
    intent = verified.request.intent
    return MutationBinding(
        idempotency_key=intent.idempotency_key,
        request_id=intent.request_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=MutationAction(intent.action.value),
        target=MutationTargetKey(
            project_id=intent.target.project_id,
            region=intent.target.region,
            environment=intent.target.environment,
            service_name=intent.target.service_name,
        ),
        provider_precondition=intent.provider_etag,
        plan_sha256=intent.plan_sha256,
        capability_sha256=verified.capability_sha256,
        payload_sha256=canonical_sha256(verified.request),
        expected_poststate_sha256=THREE_DIGEST,
    )


def _claimed(verified: VerifiedMutation) -> StoredRecord[ExecutionReceipt]:
    intent = verified.request.intent
    binding = _binding(verified)
    receipt = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(intent.target, intent.idempotency_key),
        request_id=intent.request_id,
        idempotency_key=intent.idempotency_key,
        capability_sha256=verified.capability_sha256,
        mutation_sha256=mutation_identity(binding),
        plan_sha256=intent.plan_sha256,
        expected_poststate_sha256=THREE_DIGEST,
        target=intent.target,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=intent.action,
        provider_etag=intent.provider_etag,
        dispatch_not_after=verified.request.expires_at,
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=None,
        created_at="2026-08-19T12:02:01Z",
        updated_at="2026-08-19T12:02:01Z",
        evidence_ids=("evidence-receipt-claimed",),
    )
    return StoredRecord(receipt, 0)


def _snapshot(*, epoch: int = 1, released: bool = False) -> FinalAuthoritySnapshot:
    root = _root()
    root_sha256 = canonical_sha256(root)
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root_sha256,
        target=root.target,
        current_epoch=epoch,
        previous_epoch=None if epoch == 1 else epoch - 1,
        revision=epoch - 1,
        cause=(
            EpochChangeCause.ROOT_CREATED
            if epoch == 1
            else EpochChangeCause.OPERATOR_REVOCATION
        ),
        changed_by="controlgraph.operator/v1",
        request_id=f"request-authority-{epoch}",
        evidence_id=f"evidence-authority-{epoch}",
        changed_at=f"2026-08-19T12:0{epoch}:00Z",
    )
    claim_values: dict[str, object] = {
        "schema_version": "controlgraph.service-claim/v1",
        "target": root.target,
        "root_id": root.root_id,
        "root_sha256": root_sha256,
        "status": ServiceClaimStatus.RELEASED if released else ServiceClaimStatus.ACTIVE,
        "claimed_by": "controlgraph.api/v1",
        "claim_request_id": "request-claim",
        "claim_evidence_id": "evidence-claim",
        "claimed_at": "2026-08-19T12:01:01Z",
        "released_by": authority.changed_by if released else None,
        "release_request_id": authority.request_id if released else None,
        "release_evidence_id": authority.evidence_id if released else None,
        "released_at": authority.changed_at if released else None,
    }
    claim = ServiceClaimRecord(**claim_values)  # type: ignore[arg-type]
    return FinalAuthoritySnapshot(
        root=StoredRecord(root, 0),
        service_claim=StoredRecord(claim, 1 if released else 0),
        authority=StoredRecord(authority, authority.revision),
    )


def _lease(verified: VerifiedMutation) -> ReceiptDispatchLease:
    created = DirectReceiptCreate._from_direct_store_create(
        _claimed(verified),
        _binding(verified),
    )
    return DefinitiveFreshClaimLeaseFactory.mint(created)


class _Reader:
    def __init__(
        self,
        snapshot: FinalAuthoritySnapshot | None,
        *,
        error: Exception | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.target = _target()
        self.snapshot = snapshot
        self.error = error
        self.calls: list[str] = []
        self.events = events
        self.started = asyncio.Event()
        self.continue_read = asyncio.Event()
        self.pause = False

    async def read_final_authority_snapshot(
        self,
        root_id: str,
    ) -> FinalAuthoritySnapshot | None:
        self.calls.append(root_id)
        if self.events is not None:
            self.events.append("authority")
        self.started.set()
        if self.pause:
            await self.continue_read.wait()
        if self.error is not None:
            raise self.error
        return self.snapshot


class _Adapter:
    def __init__(
        self,
        role: ServiceRole,
        *,
        events: list[str] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.target = _target()
        self.service_role = role
        self.events = events
        self.error = error
        self.calls: list[MutationPermit] = []
        self.intents: list[MutationIntent] = []

    async def mutate(self, permit: MutationPermit) -> str:
        if self.events is not None:
            self.events.append("mutation")
        self.calls.append(permit)
        self.intents.append(permit.intent)
        if self.error is not None:
            raise self.error
        return "mutated"


class _BlockingAdapter(_Adapter):
    def __init__(self) -> None:
        super().__init__(ServiceRole.EXECUTOR)
        self.started = asyncio.Event()

    async def mutate(self, permit: MutationPermit) -> str:
        self.calls.append(permit)
        self.intents.append(permit.intent)
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


@pytest.mark.parametrize(
    ("role", "action"),
    [
        (ServiceRole.EXECUTOR, CapabilityAction.APPLY_CANARY),
        (ServiceRole.EXECUTOR, CapabilityAction.PROMOTE_CANDIDATE),
        (ServiceRole.RECOVERY, CapabilityAction.RECOVER_STABLE),
    ],
)
def test_exact_executor_and_recovery_actions_dispatch_once(
    role: ServiceRole,
    action: CapabilityAction,
) -> None:
    async def scenario() -> None:
        verified = _verified(action=action)
        reader = _Reader(_snapshot())
        adapter = _Adapter(role)
        gate = FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: NOW,
        )

        assert await gate.execute(_lease(verified), verified) == FinalMutationResult(
            "mutated",
            1,
        )
        assert len(adapter.calls) == 1
        assert type(adapter.calls[0]) is MutationPermit
        assert adapter.intents == [verified.request.intent]
        with pytest.raises(RuntimeError, match="consumed or closed"):
            _ = adapter.calls[0].intent
        assert reader.calls == [verified.root.root_id]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("role", "action"),
    [
        (ServiceRole.EXECUTOR, CapabilityAction.RECOVER_STABLE),
        (ServiceRole.RECOVERY, CapabilityAction.APPLY_CANARY),
    ],
)
def test_cross_role_action_is_denied_without_adapter_call(
    role: ServiceRole,
    action: CapabilityAction,
) -> None:
    async def scenario() -> None:
        verified = _verified(action=action)
        adapter = _Adapter(role)
        result = await FinalMutationGate(
            authority_reader=_Reader(_snapshot()),
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.CLAIM_BINDING_MISMATCH
        assert adapter.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("verified_epoch", "authority_epoch"),
    [(1, 2), (2, 1)],
)
def test_stale_and_future_epoch_are_denied_without_adapter_call(
    verified_epoch: int,
    authority_epoch: int,
) -> None:
    async def scenario() -> None:
        verified = _verified(epoch=verified_epoch)
        adapter = _Adapter(ServiceRole.EXECUTOR)
        result = await FinalMutationGate(
            authority_reader=_Reader(_snapshot(epoch=authority_epoch)),
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.EPOCH_MISMATCH
        assert result.observed_authority_epoch == authority_epoch
        assert adapter.calls == []

    asyncio.run(scenario())


def test_released_claim_is_denied_without_adapter_call() -> None:
    async def scenario() -> None:
        verified = _verified()
        adapter = _Adapter(ServiceRole.EXECUTOR)
        result = await FinalMutationGate(
            authority_reader=_Reader(_snapshot(epoch=2, released=True)),
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.EPOCH_MISMATCH
        assert result.observed_authority_epoch == 2
        assert adapter.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["unadvanced", "wrong-cause"])
def test_released_claim_requires_the_exact_atomic_revocation_authority(
    mode: str,
) -> None:
    async def scenario() -> None:
        base = _snapshot(epoch=1 if mode == "unadvanced" else 2)
        authority = base.authority.value
        if mode == "unadvanced":
            authority = EpochAuthorityRecord(
                **{
                    **authority.model_dump(mode="python"),
                    "changed_at": "2026-08-19T12:02:00Z",
                }
            )
        if mode == "wrong-cause":
            authority = EpochAuthorityRecord(
                **{
                    **authority.model_dump(mode="python"),
                    "cause": EpochChangeCause.RECOVERY,
                }
            )
        claim = ServiceClaimRecord(
            **{
                **base.service_claim.value.model_dump(mode="python"),
                "status": ServiceClaimStatus.RELEASED,
                "released_by": authority.changed_by,
                "release_request_id": authority.request_id,
                "release_evidence_id": authority.evidence_id,
                "released_at": authority.changed_at,
            }
        )
        snapshot = FinalAuthoritySnapshot(
            root=base.root,
            service_claim=StoredRecord(claim, 1),
            authority=StoredRecord(authority, authority.revision),
        )
        verified = _verified()
        adapter = _Adapter(ServiceRole.EXECUTOR)

        result = await FinalMutationGate(
            authority_reader=_Reader(snapshot),
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert result.observed_authority_epoch is None
        assert adapter.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "failure",
    [
        None,
        AuthorityStoreUnavailable(),
        AuthorityStoreCorruptRecord(),
        RuntimeError("synthetic store detail"),
    ],
)
def test_missing_error_and_corrupt_reads_fail_closed_without_adapter_call(
    failure: Exception | None,
) -> None:
    async def scenario() -> None:
        verified = _verified()
        adapter = _Adapter(ServiceRole.EXECUTOR)
        reader = _Reader(None, error=failure)
        result = await FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert adapter.calls == []

    asyncio.run(scenario())


def test_final_snapshot_revision_corruption_is_denied_without_adapter_call() -> None:
    async def scenario() -> None:
        verified = _verified()
        snapshot = _snapshot()
        corrupt = replace(
            snapshot,
            authority=StoredRecord(snapshot.authority.value, 1),
        )
        adapter = _Adapter(ServiceRole.EXECUTOR)

        result = await FinalMutationGate(
            authority_reader=_Reader(corrupt),
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert result.observed_authority_epoch is None
        assert adapter.calls == []

    asyncio.run(scenario())


def test_active_claim_at_noninitial_revision_is_denied_without_adapter_call() -> None:
    async def scenario() -> None:
        verified = _verified()
        snapshot = _snapshot()
        corrupt = replace(
            snapshot,
            service_claim=StoredRecord(snapshot.service_claim.value, 1),
        )
        adapter = _Adapter(ServiceRole.EXECUTOR)

        result = await FinalMutationGate(
            authority_reader=_Reader(corrupt),
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert result.observed_authority_epoch is None
        assert adapter.calls == []

    asyncio.run(scenario())


def test_revocation_while_final_read_is_paused_prevents_dispatch() -> None:
    async def scenario() -> None:
        verified = _verified()
        reader = _Reader(_snapshot())
        reader.pause = True
        adapter = _Adapter(ServiceRole.EXECUTOR)
        gate = FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: NOW,
        )

        result_task = asyncio.create_task(gate.execute(_lease(verified), verified))
        await asyncio.wait_for(reader.started.wait(), timeout=1)
        reader.snapshot = _snapshot(epoch=2)
        reader.continue_read.set()
        result = await result_task

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.EPOCH_MISMATCH
        assert adapter.calls == []

    asyncio.run(scenario())


def test_receipt_dispatch_lease_is_exactly_one_use_sequentially() -> None:
    async def scenario() -> None:
        verified = _verified()
        reader = _Reader(_snapshot())
        adapter = _Adapter(ServiceRole.EXECUTOR)
        gate = FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: NOW,
        )
        lease = _lease(verified)

        assert await gate.execute(lease, verified) == FinalMutationResult("mutated", 1)
        repeated = await gate.execute(lease, verified)

        assert isinstance(repeated, FinalAuthorityDenial)
        assert repeated.reason_code is ReasonCode.RECEIPT_IN_PROGRESS
        assert len(adapter.calls) == 1
        assert len(reader.calls) == 1

    asyncio.run(scenario())


def test_receipt_dispatch_lease_is_exactly_one_use_concurrently() -> None:
    async def scenario() -> None:
        verified = _verified()
        reader = _Reader(_snapshot())
        reader.pause = True
        adapter = _Adapter(ServiceRole.EXECUTOR)
        gate = FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: NOW,
        )
        lease = _lease(verified)

        first = asyncio.create_task(gate.execute(lease, verified))
        await asyncio.wait_for(reader.started.wait(), timeout=1)
        second = await gate.execute(lease, verified)
        reader.continue_read.set()

        assert await first == FinalMutationResult("mutated", 1)
        assert isinstance(second, FinalAuthorityDenial)
        assert second.reason_code is ReasonCode.RECEIPT_IN_PROGRESS
        assert len(adapter.calls) == 1
        assert len(reader.calls) == 1

    asyncio.run(scenario())


def test_receipt_dispatch_lease_has_one_cross_thread_entry_winner() -> None:
    async def scenario() -> None:
        verified = _verified()
        lease = _lease(verified)

        results = await asyncio.gather(
            asyncio.to_thread(lease._enter, verified),
            asyncio.to_thread(lease._enter, verified),
        )

        assert results.count(None) == 1
        assert results.count(ReasonCode.RECEIPT_IN_PROGRESS) == 1

    asyncio.run(scenario())


def test_mutation_permit_has_one_cross_thread_consumer() -> None:
    async def scenario() -> None:
        verified = _verified()
        lease = _lease(verified)
        assert lease._enter(verified) is None
        permit = lease._authorize(
            verified,
            verified.root.target,
            ServiceRole.EXECUTOR,
        )

        results = await asyncio.gather(
            asyncio.to_thread(lambda: permit.intent),
            asyncio.to_thread(lambda: permit.intent),
            return_exceptions=True,
        )

        assert sum(type(result) is MutationIntent for result in results) == 1
        assert sum(isinstance(result, RuntimeError) for result in results) == 1

    asyncio.run(scenario())


def test_adapter_exception_leaves_dispatch_lease_irrevocably_closed() -> None:
    async def scenario() -> None:
        verified = _verified()
        reader = _Reader(_snapshot())
        adapter = _Adapter(
            ServiceRole.EXECUTOR,
            error=RuntimeError("synthetic adapter failure"),
        )
        gate = FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: NOW,
        )
        lease = _lease(verified)

        with pytest.raises(RuntimeError, match="synthetic adapter failure"):
            await gate.execute(lease, verified)
        repeated = await gate.execute(lease, verified)

        assert isinstance(repeated, FinalAuthorityDenial)
        assert repeated.reason_code is ReasonCode.RECEIPT_IN_PROGRESS
        assert len(adapter.calls) == 1
        assert len(reader.calls) == 1

    asyncio.run(scenario())


def test_adapter_cancellation_leaves_dispatch_lease_irrevocably_closed() -> None:
    async def scenario() -> None:
        verified = _verified()
        reader = _Reader(_snapshot())
        adapter = _BlockingAdapter()
        gate = FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: NOW,
        )
        lease = _lease(verified)

        dispatch = asyncio.create_task(gate.execute(lease, verified))
        await asyncio.wait_for(adapter.started.wait(), timeout=1)
        dispatch.cancel()
        with pytest.raises(asyncio.CancelledError):
            await dispatch
        repeated = await gate.execute(lease, verified)

        assert isinstance(repeated, FinalAuthorityDenial)
        assert repeated.reason_code is ReasonCode.RECEIPT_IN_PROGRESS
        assert len(adapter.calls) == 1
        assert len(reader.calls) == 1

    asyncio.run(scenario())


def test_receipt_binding_mismatch_consumes_lease_before_authority_read() -> None:
    async def scenario() -> None:
        verified = _verified()
        other = _verified(action=CapabilityAction.PROMOTE_CANDIDATE)
        reader = _Reader(_snapshot())
        adapter = _Adapter(ServiceRole.EXECUTOR)

        result = await FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(other), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.IDEMPOTENCY_CONFLICT
        assert reader.calls == []
        assert adapter.calls == []

    asyncio.run(scenario())


def test_final_snapshot_is_followed_by_adapter_mutation_as_the_next_await() -> None:
    async def scenario() -> None:
        events: list[str] = []
        verified = _verified()
        result = await FinalMutationGate(
            authority_reader=_Reader(_snapshot(), events=events),
            adapter=_Adapter(ServiceRole.EXECUTOR, events=events),
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert result == FinalMutationResult("mutated", 1)
        assert events == ["authority", "mutation"]

    asyncio.run(scenario())
    tree = ast.parse(textwrap.dedent(inspect.getsource(FinalMutationGate.execute)))
    awaits = sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.Await)),
        key=lambda node: node.lineno,
    )
    assert len(awaits) == 2
    assert [awaited.value.func.attr for awaited in awaits] == [  # type: ignore[union-attr]
        "read_final_authority_snapshot",
        "mutate",
    ]


@pytest.mark.parametrize(
    ("scheduled_at", "expires_at", "now", "expected"),
    [
        (
            "2026-08-19T12:02:00Z",
            "2026-08-19T12:07:00Z",
            datetime(2026, 8, 19, 12, 1, 59, tzinfo=UTC),
            ReasonCode.CAPABILITY_NOT_YET_VALID,
        ),
        (
            "2026-08-19T12:04:00Z",
            "2026-08-19T12:06:00Z",
            datetime(2026, 8, 19, 12, 3, tzinfo=UTC),
            ReasonCode.CAPABILITY_NOT_YET_VALID,
        ),
        (
            "2026-08-19T12:02:00Z",
            "2026-08-19T12:03:00Z",
            datetime(2026, 8, 19, 12, 3, tzinfo=UTC),
            ReasonCode.CAPABILITY_EXPIRED,
        ),
        (
            "2026-08-19T12:02:00Z",
            "2026-08-19T12:07:00Z",
            datetime(2026, 8, 19, 12, 7, tzinfo=UTC),
            ReasonCode.CAPABILITY_EXPIRED,
        ),
    ],
)
def test_capability_and_task_time_are_rechecked_after_final_snapshot(
    scheduled_at: str,
    expires_at: str,
    now: datetime,
    expected: ReasonCode,
) -> None:
    async def scenario() -> None:
        original = _verified()
        request = TaskRequest(
            **{
                **original.request.model_dump(mode="python"),
                "scheduled_at": scheduled_at,
                "expires_at": expires_at,
            }
        )
        verified = replace(original, request=request)
        reader = _Reader(_snapshot())
        adapter = _Adapter(ServiceRole.EXECUTOR)

        result = await FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: now,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is expected
        assert reader.calls == [verified.root.root_id]
        assert adapter.calls == []

    asyncio.run(scenario())


def test_invalid_local_clock_fails_closed_after_final_snapshot() -> None:
    async def scenario() -> None:
        verified = _verified()
        reader = _Reader(_snapshot())
        adapter = _Adapter(ServiceRole.EXECUTOR)

        result = await FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            clock=lambda: datetime(2026, 8, 19, 12, 3),
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert len(reader.calls) == 1
        assert adapter.calls == []

    asyncio.run(scenario())


def test_capability_lineage_must_not_predate_current_authority() -> None:
    async def scenario() -> None:
        original = _verified()
        verified = replace(
                original,
                earliest_lineage_issued_at=int(
                    datetime(2026, 8, 19, 12, 0, 59, tzinfo=UTC).timestamp()
                ),
        )
        adapter = _Adapter(ServiceRole.EXECUTOR)

        result = await FinalMutationGate(
            authority_reader=_Reader(_snapshot()),
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert adapter.calls == []

    asyncio.run(scenario())


def test_authority_epoch_must_equal_persistence_revision_plus_one() -> None:
    async def scenario() -> None:
        verified = _verified(epoch=2)
        snapshot = _snapshot(epoch=2)
        incoherent_authority = EpochAuthorityRecord.model_construct(
            **{
                **snapshot.authority.value.model_dump(mode="python"),
                "revision": 2,
            }
        )
        incoherent = replace(
            snapshot,
            authority=StoredRecord(incoherent_authority, 2),
        )
        adapter = _Adapter(ServiceRole.EXECUTOR)

        result = await FinalMutationGate(
            authority_reader=_Reader(incoherent),
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert isinstance(result, FinalAuthorityDenial)
        assert result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
        assert result.observed_authority_epoch is None
        assert adapter.calls == []

    asyncio.run(scenario())


def test_lease_and_permit_construction_require_internal_proof() -> None:
    verified = _verified()
    claimed = _claimed(verified)

    with pytest.raises(TypeError):
        DirectReceiptCreate(claimed)  # type: ignore[call-arg,arg-type]
    with pytest.raises(TypeError):
        DefinitiveFreshClaimLeaseFactory.mint(claimed)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ReceiptDispatchLease(claimed)  # type: ignore[call-arg,arg-type]
    with pytest.raises(TypeError):
        MutationPermit(  # type: ignore[call-arg,arg-type]
            object(),
            target=verified.root.target,
            service_role=ServiceRole.EXECUTOR,
            intent=verified.request.intent,
            receipt_id=claimed.value.receipt_id,
            binding=_binding(verified),
        )


def test_definitive_create_proof_mints_only_one_lease() -> None:
    verified = _verified()
    created = DirectReceiptCreate._from_direct_store_create(
        _claimed(verified),
        _binding(verified),
    )

    assert type(DefinitiveFreshClaimLeaseFactory.mint(created)) is ReceiptDispatchLease
    with pytest.raises(ValueError, match="already consumed"):
        DefinitiveFreshClaimLeaseFactory.mint(created)


def test_definitive_create_proof_has_one_concurrent_mint_winner() -> None:
    async def scenario() -> None:
        verified = _verified()
        created = DirectReceiptCreate._from_direct_store_create(
            _claimed(verified),
            _binding(verified),
        )

        results = await asyncio.gather(
            asyncio.to_thread(DefinitiveFreshClaimLeaseFactory.mint, created),
            asyncio.to_thread(DefinitiveFreshClaimLeaseFactory.mint, created),
            return_exceptions=True,
        )

        assert sum(type(result) is ReceiptDispatchLease for result in results) == 1
        assert sum(isinstance(result, ValueError) for result in results) == 1

    asyncio.run(scenario())


def test_definitive_create_proof_rejects_noninitial_receipt_state() -> None:
    verified = _verified()
    claimed = _claimed(verified)
    denied = ExecutionReceipt(
        **{
            **claimed.value.model_dump(mode="python"),
            "outcome": ReceiptOutcome.DENIED,
            "reason_code": ReasonCode.EPOCH_MISMATCH,
            "observed_authority_epoch": 2,
        }
    )

    with pytest.raises(ValueError, match="initial claim"):
        DirectReceiptCreate._from_direct_store_create(
            StoredRecord(denied, 1),
            _binding(verified),
        )


def test_definitive_create_proof_rejects_a_changed_mutation_binding() -> None:
    verified = _verified()
    changed = replace(
        _binding(verified),
        expected_poststate_sha256=ZERO_DIGEST,
    )

    with pytest.raises(ValueError, match="mutation binding"):
        DirectReceiptCreate._from_direct_store_create(
            _claimed(verified),
            changed,
        )
