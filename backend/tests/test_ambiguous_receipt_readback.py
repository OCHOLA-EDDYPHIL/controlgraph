from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from root_v2_support import RootBundle, root_bundle, root_records, target_binding

from controlgraph_canary.application.ambiguous_receipt_readback import (
    AmbiguousReceiptReadbackError,
    AmbiguousReceiptReadbackErrorCode,
    AmbiguousReceiptReadbackResolver,
)
from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.receipt_execution import ReceiptReadbackResult
from controlgraph_canary.contracts.ambiguous_receipt_readback import (
    AMBIGUOUS_RECEIPT_READBACK_COMMAND_V1,
    AmbiguousReceiptReadbackCommandV1,
    AmbiguousReceiptReadbackDisposition,
    ambiguous_receipt_resolution_evidence_id,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
)
from controlgraph_canary.contracts.storage import execution_receipt_logical_id

CAPABILITY_DIGEST = "3" * 64
MUTATION_DIGEST = "4" * 64


def _replace_receipt(
    receipt: ExecutionReceipt,
    **changes: object,
) -> ExecutionReceipt:
    return ExecutionReceipt(
        **{
            **receipt.model_dump(mode="python"),
            **changes,
        }
    )


def _records() -> tuple[RootBundle, ExecutionReceipt]:
    root, anchor, claim, authority = root_records(concurrency=8)
    bundle = root_bundle(
        root=root,
        anchor=anchor,
        claim=claim,
        authority=authority,
    )
    plan = root.content.rollout_plan
    expected = TargetConfigurationProjection(
        target=root.content.target,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=plan.stable_percent,
        candidate_percent=plan.candidate_percent,
        concurrency=plan.concurrency,
    )
    receipt = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(
            root.content.target,
            "idempotency-apply-001",
        ),
        request_id="request-apply-001",
        idempotency_key="idempotency-apply-001",
        capability_sha256=CAPABILITY_DIGEST,
        mutation_sha256=MUTATION_DIGEST,
        plan_sha256=canonical_sha256(plan),
        expected_poststate_sha256=target_configuration_projection_sha256(expected),
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag=root.content.stable_snapshot.provider_etag,
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.AMBIGUOUS,
        reason_code=ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
        provider_operation=(
            f"projects/{root.content.target.project_id}/locations/us-central1/"
            "operations/apply-canary-001"
        ),
        observed_etag="etag-ambiguous-7",
        observed_authority_epoch=1,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:03:00Z",
        evidence_ids=("evidence-apply-001",),
    )
    return bundle, receipt


def _command(stored: StoredRecord[ExecutionReceipt]) -> AmbiguousReceiptReadbackCommandV1:
    receipt = stored.value
    return AmbiguousReceiptReadbackCommandV1(
        schema_version=AMBIGUOUS_RECEIPT_READBACK_COMMAND_V1,
        root_id=receipt.root_id,
        expected_root_sha256=receipt.root_sha256,
        expected_epoch=receipt.epoch,
        action=CapabilityAction.APPLY_CANARY,
        request_id=receipt.request_id,
        idempotency_key=receipt.idempotency_key,
        capability_sha256=receipt.capability_sha256,
        expected_receipt_sha256=canonical_sha256(receipt),
        expected_storage_revision=stored.revision,
        expected_ambiguous_observed_etag=receipt.observed_etag or "missing",
        expected_ambiguous_updated_at=receipt.updated_at,
        confirmation="READBACK_ONLY",
    )


def _expected(bundle: RootBundle) -> TargetConfigurationProjection:
    plan = bundle.root.value.content.rollout_plan
    return TargetConfigurationProjection(
        target=bundle.root.value.content.target,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=plan.stable_percent,
        candidate_percent=plan.candidate_percent,
        concurrency=plan.concurrency,
    )


class _RootReader:
    def __init__(
        self,
        bundle: RootBundle | tuple[RootBundle | None, ...] | None,
        events: list[str],
    ) -> None:
        self.target = target_binding()
        self.bundles = bundle if type(bundle) is tuple else (bundle,)
        self.events = events
        self.read_count = 0

    async def read_root_creation_bundle(self, root_id: str) -> RootBundle | None:
        del root_id
        self.events.append("root-read")
        selected = self.bundles[min(self.read_count, len(self.bundles) - 1)]
        self.read_count += 1
        return selected


class _Store:
    def __init__(
        self,
        stored: StoredRecord[ExecutionReceipt] | None,
        events: list[str],
    ) -> None:
        self.target = target_binding()
        self.stored = stored
        self.events = events
        self.cas_mode = "success"

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        del idempotency_key
        self.events.append("receipt-read")
        return self.stored

    async def resolve_ambiguous_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        expected_service_claim: object,
    ) -> StoredRecord[ExecutionReceipt]:
        del expected_authority, expected_service_claim
        self.events.append("cas")
        if self.stored != expected:
            raise RuntimeError("synthetic conflict")
        if self.cas_mode == "authority-race":
            raise RuntimeError("synthetic authority fence conflict")
        updated = StoredRecord(replacement, expected.revision + 1)
        if self.cas_mode == "unknown-after-commit":
            self.stored = updated
            raise RuntimeError("synthetic response loss")
        if self.cas_mode == "competing-commit":
            competing = _replace_receipt(
                replacement,
                observed_etag="etag-canary-competing-9",
                updated_at="2026-08-19T12:05:00Z",
            )
            self.stored = StoredRecord(competing, expected.revision + 1)
            raise RuntimeError("synthetic concurrent resolution")
        if self.cas_mode == "unknown-before-commit":
            raise RuntimeError("synthetic precommit loss")
        self.stored = updated
        return updated


class _OperationReadback:
    def __init__(self, success: bool, events: list[str]) -> None:
        self.target = target_binding()
        self.success = success
        self.events = events
        self.calls: list[str] = []

    async def terminal_success(self, operation_name: str) -> bool:
        self.events.append("operation-read")
        self.calls.append(operation_name)
        return self.success


class _TargetReadback:
    def __init__(
        self,
        observation: ReceiptReadbackResult,
        events: list[str],
    ) -> None:
        self.target = target_binding()
        self.observation = observation
        self.events = events
        self.calls: list[TargetConfigurationProjection] = []

    async def readback(
        self,
        expected: TargetConfigurationProjection,
    ) -> ReceiptReadbackResult:
        self.events.append("target-read")
        self.calls.append(expected)
        return self.observation


def _resolver(
    bundle: RootBundle,
    store: _Store,
    operation: _OperationReadback,
    target: _TargetReadback,
    events: list[str],
    *,
    root_reader: _RootReader | None = None,
) -> AmbiguousReceiptReadbackResolver:
    return AmbiguousReceiptReadbackResolver(
        root_reader=root_reader or _RootReader(bundle, events),
        receipt_store=store,
        operation_readback=operation,
        target_readback=target,
        clock=lambda: datetime(2026, 8, 19, 12, 4, tzinfo=UTC),
    )


def _run_error(
    resolver: AmbiguousReceiptReadbackResolver,
    command: AmbiguousReceiptReadbackCommandV1,
) -> AmbiguousReceiptReadbackErrorCode:
    with pytest.raises(AmbiguousReceiptReadbackError) as captured:
        asyncio.run(resolver.resolve(command))
    return captured.value.code


def test_exact_ambiguous_receipt_is_monotonically_resolved_without_dispatch() -> None:
    bundle, receipt = _records()
    stored = StoredRecord(receipt, 2)
    command = _command(stored)
    events: list[str] = []
    store = _Store(stored, events)
    operation = _OperationReadback(True, events)
    target = _TargetReadback(
        ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
        events,
    )

    result = asyncio.run(_resolver(bundle, store, operation, target, events).resolve(command))

    assert result.disposition is AmbiguousReceiptReadbackDisposition.RESOLVED
    assert result.stored_receipt.storage_revision == 3
    resolved = result.stored_receipt.receipt
    assert resolved.outcome is ReceiptOutcome.VERIFIED
    assert resolved.reason_code is None
    assert resolved.observed_etag == "etag-canary-8"
    assert resolved.provider_operation == receipt.provider_operation
    assert resolved.observed_authority_epoch == receipt.observed_authority_epoch
    assert resolved.evidence_ids == (
        *receipt.evidence_ids,
        ambiguous_receipt_resolution_evidence_id(command),
    )
    permitted_changes = {
        "outcome",
        "reason_code",
        "observed_etag",
        "updated_at",
        "evidence_ids",
    }
    assert all(
        getattr(receipt, field) == getattr(resolved, field)
        for field in ExecutionReceipt.model_fields
        if field not in permitted_changes
    )
    assert events == [
        "receipt-read",
        "root-read",
        "operation-read",
        "target-read",
        "root-read",
        "cas",
    ]


def test_exact_marked_verified_receipt_is_adopted_before_mutable_readback() -> None:
    bundle, receipt = _records()
    ambiguous = StoredRecord(receipt, 2)
    command = _command(ambiguous)
    marker = ambiguous_receipt_resolution_evidence_id(command)
    verified = _replace_receipt(
        receipt,
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        observed_etag="etag-canary-8",
        updated_at="2026-08-19T12:04:00Z",
        evidence_ids=(*receipt.evidence_ids, marker),
    )
    events: list[str] = []
    store = _Store(StoredRecord(verified, 3), events)

    result = asyncio.run(
        _resolver(
            bundle,
            store,
            _OperationReadback(False, events),
            _TargetReadback(
                ReceiptReadbackResult(
                    state=_expected(bundle),
                    observed_etag="etag-canary-8",
                ),
                events,
            ),
            events,
        ).resolve(command)
    )

    assert result.disposition is AmbiguousReceiptReadbackDisposition.ADOPTED
    assert "cas" not in events
    assert events == ["receipt-read"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "provider_operation",
            (
                "projects/controlgraph-canary-abc123/locations/us-central1/"
                "operations/tampered-operation"
            ),
        ),
        ("mutation_sha256", "9" * 64),
        ("created_at", "2026-08-19T12:01:00Z"),
        ("evidence_ids", ("evidence-tampered",)),
    ],
)
def test_adoption_reconstructs_the_exact_pinned_ambiguous_predecessor(
    field: str,
    value: object,
) -> None:
    bundle, receipt = _records()
    ambiguous = StoredRecord(receipt, 2)
    command = _command(ambiguous)
    marker = ambiguous_receipt_resolution_evidence_id(command)
    verified = _replace_receipt(
        receipt,
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        observed_etag="etag-canary-8",
        updated_at="2026-08-19T12:04:00Z",
        evidence_ids=(*receipt.evidence_ids, marker),
    )
    if field == "evidence_ids":
        value = ("evidence-tampered", marker)
    tampered = _replace_receipt(verified, **{field: value})
    events: list[str] = []
    resolver = _resolver(
        bundle,
        _Store(StoredRecord(tampered, 3), events),
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
    )

    assert _run_error(resolver, command) is (
        AmbiguousReceiptReadbackErrorCode.RECEIPT_STATE_DENIED
    )
    assert events == ["receipt-read"]


def test_unmarked_verified_and_nonambiguous_states_are_rejected_before_readback() -> None:
    bundle, receipt = _records()
    verified = _replace_receipt(
        receipt,
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        observed_etag="etag-canary-8",
    )
    stored = StoredRecord(verified, 3)
    events: list[str] = []
    resolver = _resolver(
        bundle,
        _Store(stored, events),
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
    )

    assert _run_error(resolver, _command(stored)) is (
        AmbiguousReceiptReadbackErrorCode.RECEIPT_STATE_DENIED
    )
    assert events == ["receipt-read"]


@pytest.mark.parametrize(
    "changes",
    [
        {"provider_operation": None},
        {"observed_etag": None},
    ],
)
def test_pinned_ambiguous_shape_is_explicitly_required(
    changes: dict[str, object],
) -> None:
    bundle, receipt = _records()
    invalid = _replace_receipt(receipt, **changes)
    stored = StoredRecord(invalid, 2)
    events: list[str] = []
    resolver = _resolver(
        bundle,
        _Store(stored, events),
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
    )

    assert _run_error(resolver, _command(stored)) is (
        AmbiguousReceiptReadbackErrorCode.RECEIPT_STATE_DENIED
    )
    assert events == ["receipt-read"]


def test_exact_locator_digest_and_root_bindings_are_required_before_provider_reads() -> None:
    bundle, receipt = _records()
    changed = _replace_receipt(receipt, expected_poststate_sha256="f" * 64)
    stored = StoredRecord(changed, 2)
    events: list[str] = []
    resolver = _resolver(
        bundle,
        _Store(stored, events),
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
    )

    assert _run_error(resolver, _command(stored)) is (
        AmbiguousReceiptReadbackErrorCode.ROOT_BINDING_MISMATCH
    )
    assert events == ["receipt-read", "root-read"]


def test_stale_authority_is_rejected_before_operation_or_target_readback() -> None:
    bundle, receipt = _records()
    root = bundle.root.value
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        current_epoch=2,
        previous_epoch=1,
        revision=1,
        cause=EpochChangeCause.OPERATOR_REVOCATION,
        changed_by="operator@example.com",
        request_id="request-revoke-002",
        evidence_id="evidence-revoke-002",
        changed_at="2026-08-19T12:03:30Z",
    )
    stale_bundle = RootBundle(
        root=bundle.root,
        service_claim=bundle.service_claim,
        authority=StoredRecord(authority, 1),
        lineage_anchor=bundle.lineage_anchor,
    )
    stored = StoredRecord(receipt, 2)
    events: list[str] = []
    resolver = _resolver(
        stale_bundle,
        _Store(stored, events),
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
    )

    assert _run_error(resolver, _command(stored)) is (
        AmbiguousReceiptReadbackErrorCode.AUTHORITY_STALE
    )
    assert events == ["receipt-read", "root-read"]


def test_authority_change_after_poststate_read_prevents_receipt_cas() -> None:
    bundle, receipt = _records()
    root = bundle.root.value
    advanced = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        current_epoch=2,
        previous_epoch=1,
        revision=1,
        cause=EpochChangeCause.OPERATOR_REVOCATION,
        changed_by="operator@example.com",
        request_id="request-revoke-during-readback",
        evidence_id="evidence-revoke-during-readback",
        changed_at="2026-08-19T12:03:30Z",
    )
    stale_bundle = RootBundle(
        root=bundle.root,
        service_claim=bundle.service_claim,
        authority=StoredRecord(advanced, 1),
        lineage_anchor=bundle.lineage_anchor,
    )
    stored = StoredRecord(receipt, 2)
    events: list[str] = []
    resolver = _resolver(
        bundle,
        _Store(stored, events),
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
        root_reader=_RootReader((bundle, stale_bundle), events),
    )

    assert _run_error(resolver, _command(stored)) is (
        AmbiguousReceiptReadbackErrorCode.AUTHORITY_STALE
    )
    assert events == [
        "receipt-read",
        "root-read",
        "operation-read",
        "target-read",
        "root-read",
    ]


def test_authority_change_inside_resolution_transaction_cannot_update_receipt() -> None:
    bundle, receipt = _records()
    stored = StoredRecord(receipt, 2)
    events: list[str] = []
    store = _Store(stored, events)
    store.cas_mode = "authority-race"
    resolver = _resolver(
        bundle,
        store,
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
    )

    assert _run_error(resolver, _command(stored)) is (
        AmbiguousReceiptReadbackErrorCode.COMPARE_AND_SET_UNCONFIRMED
    )
    assert store.stored == stored
    assert events[-2:] == ["cas", "receipt-read"]


def test_operation_and_poststate_must_each_be_independently_exact() -> None:
    bundle, receipt = _records()
    stored = StoredRecord(receipt, 2)

    operation_events: list[str] = []
    operation_denied = _resolver(
        bundle,
        _Store(stored, operation_events),
        _OperationReadback(False, operation_events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            operation_events,
        ),
        operation_events,
    )
    assert _run_error(operation_denied, _command(stored)) is (
        AmbiguousReceiptReadbackErrorCode.OPERATION_UNVERIFIED
    )
    assert operation_events == ["receipt-read", "root-read", "operation-read"]

    poststate_events: list[str] = []
    mismatch = replace(_expected(bundle), stable_percent=0, candidate_percent=100)
    poststate_denied = _resolver(
        bundle,
        _Store(stored, poststate_events),
        _OperationReadback(True, poststate_events),
        _TargetReadback(
            ReceiptReadbackResult(state=mismatch, observed_etag="etag-promoted-9"),
            poststate_events,
        ),
        poststate_events,
    )
    assert _run_error(poststate_denied, _command(stored)) is (
        AmbiguousReceiptReadbackErrorCode.POSTSTATE_UNVERIFIED
    )
    assert poststate_events == [
        "receipt-read",
        "root-read",
        "operation-read",
        "target-read",
    ]


@pytest.mark.parametrize(
    ("cas_mode", "expected_disposition", "expected_error"),
    [
        (
            "unknown-after-commit",
            AmbiguousReceiptReadbackDisposition.ADOPTED,
            None,
        ),
        (
            "competing-commit",
            AmbiguousReceiptReadbackDisposition.ADOPTED,
            None,
        ),
        (
            "unknown-before-commit",
            None,
            AmbiguousReceiptReadbackErrorCode.COMPARE_AND_SET_UNCONFIRMED,
        ),
    ],
)
def test_compare_and_set_unknown_is_adopted_only_after_exact_readback(
    cas_mode: str,
    expected_disposition: AmbiguousReceiptReadbackDisposition | None,
    expected_error: AmbiguousReceiptReadbackErrorCode | None,
) -> None:
    bundle, receipt = _records()
    stored = StoredRecord(receipt, 2)
    command = _command(stored)
    events: list[str] = []
    store = _Store(stored, events)
    store.cas_mode = cas_mode
    resolver = _resolver(
        bundle,
        store,
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
    )

    if expected_error is None:
        result = asyncio.run(resolver.resolve(command))
        assert result.disposition is expected_disposition
    else:
        assert _run_error(resolver, command) is expected_error
    assert events[-2:] == ["cas", "receipt-read"]


def test_missing_receipt_stops_without_root_or_provider_access() -> None:
    bundle, _ = _records()
    _, receipt = _records()
    command = _command(StoredRecord(receipt, 2))
    events: list[str] = []
    resolver = _resolver(
        bundle,
        _Store(None, events),
        _OperationReadback(True, events),
        _TargetReadback(
            ReceiptReadbackResult(state=_expected(bundle), observed_etag="etag-canary-8"),
            events,
        ),
        events,
    )

    assert _run_error(resolver, command) is (
        AmbiguousReceiptReadbackErrorCode.RECEIPT_MISSING
    )
    assert events == ["receipt-read"]
