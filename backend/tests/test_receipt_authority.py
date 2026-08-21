from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
from root_v2_support import root_records

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreUnavailable,
    DirectReceiptCreate,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    ReceiptClaimResult,
    StoredRecord,
    validate_receipt_claim_binding,
)
from controlgraph_canary.application.identity import (
    RECEIPT_AUTHORITY_PATH,
    CallerRole,
    ServiceRole,
)
from controlgraph_canary.application.receipt_authority import (
    ReceiptAuthorityClient,
    ReceiptAuthorityService,
)
from controlgraph_canary.application.receipt_execution import ReceiptStore
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.receipt_authority import (
    DirectReceiptCreateConfirmationV1,
    ReceiptAuthorityDisposition,
    ReceiptAuthorityOperation,
    ReceiptAuthorityRequestV1,
    ReceiptAuthorityResponseV1,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    execution_receipt_logical_id,
)

PROJECT_ID = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
ROOT_SHA256 = "1" * 64
PLAN_SHA256 = "2" * 64
CAPABILITY_SHA256 = "3" * 64
PAYLOAD_SHA256 = "4" * 64
POSTSTATE_SHA256 = "5" * 64


def _target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT_ID,
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )


def _binding() -> MutationBinding:
    target = _target()
    return MutationBinding(
        idempotency_key="receipt-authority-idempotency",
        request_id="receipt-authority-request",
        root_id="cgroot:receipt-authority",
        root_sha256=ROOT_SHA256,
        epoch=1,
        action=MutationAction.APPLY_CANARY,
        target=MutationTargetKey(
            project_id=target.project_id,
            region=target.region,
            environment=target.environment,
            service_name=target.service_name,
        ),
        provider_precondition="etag-stable-1",
        plan_sha256=PLAN_SHA256,
        capability_sha256=CAPABILITY_SHA256,
        payload_sha256=PAYLOAD_SHA256,
        expected_poststate_sha256=POSTSTATE_SHA256,
    )


def _claimed_receipt() -> ExecutionReceipt:
    target = _target()
    binding = _binding()
    return ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(target, binding.idempotency_key),
        request_id=binding.request_id,
        idempotency_key=binding.idempotency_key,
        capability_sha256=binding.capability_sha256,
        mutation_sha256=mutation_identity(binding),
        plan_sha256=binding.plan_sha256,
        expected_poststate_sha256=binding.expected_poststate_sha256,
        target=target,
        root_id=binding.root_id,
        root_sha256=binding.root_sha256,
        epoch=binding.epoch,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag=binding.provider_precondition,
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=None,
        created_at="2026-08-19T12:00:00Z",
        updated_at="2026-08-19T12:00:00Z",
        evidence_ids=(),
    )


def _denied_receipt() -> ExecutionReceipt:
    value = _claimed_receipt().model_dump(mode="python")
    value.update(
        {
            "outcome": ReceiptOutcome.DENIED,
            "reason_code": ReasonCode.AUTHORITY_UNAVAILABLE,
            "updated_at": "2026-08-19T12:00:01Z",
        }
    )
    return ExecutionReceipt.model_validate(value)


def _ambiguous_resolution_records() -> tuple[
    StoredRecord[ExecutionReceipt],
    ExecutionReceipt,
    StoredRecord[EpochAuthorityRecord],
    StoredRecord[ServiceClaimRecord],
]:
    root, _, claim, authority = root_records(
        target=_target(),
        concurrency=8,
        project_number=PROJECT_NUMBER,
    )
    value = _claimed_receipt().model_dump(mode="python")
    value.update(
        {
            "root_id": root.root_id,
            "root_sha256": root.root_sha256,
            "epoch": 1,
            "outcome": ReceiptOutcome.AMBIGUOUS,
            "reason_code": ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
            "provider_operation": (
                f"projects/{PROJECT_ID}/locations/us-central1/"
                "operations/receipt-authority-resolution"
            ),
            "observed_etag": "etag-ambiguous-1",
            "observed_authority_epoch": 1,
            "updated_at": "2026-08-19T12:00:01Z",
        }
    )
    ambiguous = ExecutionReceipt.model_validate(value)
    replacement_value = ambiguous.model_dump(mode="python")
    replacement_value.update(
        {
            "outcome": ReceiptOutcome.VERIFIED,
            "reason_code": None,
            "observed_etag": "etag-verified-2",
            "updated_at": "2026-08-19T12:00:02Z",
            "evidence_ids": ("cgrrb:" + "a" * 64,),
        }
    )
    return (
        StoredRecord(ambiguous, 2),
        ExecutionReceipt.model_validate(replacement_value),
        StoredRecord(authority, 0),
        StoredRecord(claim, 0),
    )


def _route() -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.EXECUTOR,
        service_role=ServiceRole.COORDINATOR,
        audience=(
            f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        override_path=RECEIPT_AUTHORITY_PATH,
    )


class _BackingStore:
    def __init__(self) -> None:
        self.target = _target()
        self.stored: StoredRecord[ExecutionReceipt] | None = None
        self.claim_calls = 0
        self.cas_calls = 0
        self.resolution_calls = 0
        self.authority: StoredRecord[EpochAuthorityRecord] | None = None
        self.service_claim: StoredRecord[ServiceClaimRecord] | None = None

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        self.claim_calls += 1
        validate_receipt_claim_binding(receipt, binding)
        if self.stored is None:
            self.stored = StoredRecord(receipt, 0)
            return ReceiptClaimCreated(
                self.stored,
                DirectReceiptCreate._from_direct_store_create(self.stored, binding),
            )
        if self.stored.value.mutation_sha256 != receipt.mutation_sha256:
            return ReceiptClaimConflict()
        return ReceiptClaimAdopted(self.stored)

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        if self.stored is None or self.stored.value.idempotency_key != idempotency_key:
            return None
        return self.stored

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        self.cas_calls += 1
        if self.stored != expected:
            raise AuthorityStoreConflict
        self.stored = StoredRecord(replacement, expected.revision + 1)
        return self.stored

    async def resolve_ambiguous_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        expected_service_claim: StoredRecord[ServiceClaimRecord],
    ) -> StoredRecord[ExecutionReceipt]:
        self.resolution_calls += 1
        if (
            self.stored != expected
            or self.authority != expected_authority
            or self.service_claim != expected_service_claim
        ):
            raise AuthorityStoreConflict
        self.stored = StoredRecord(replacement, expected.revision + 1)
        return self.stored


class _LoopbackTransport:
    def __init__(
        self,
        service: ReceiptAuthorityService,
        *,
        lose_after_calls: set[int] | None = None,
        transform: Callable[[bytes, int], bytes] | None = None,
    ) -> None:
        self.service = service
        self.lose_after_calls = lose_after_calls or set()
        self.transform = transform
        self.calls = 0
        self.requests: list[bytes] = []
        self.responses: list[bytes] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        assert route == _route()
        self.calls += 1
        self.requests.append(body)
        response = await self.service.handle(body)
        self.responses.append(response)
        if self.calls in self.lose_after_calls:
            raise RuntimeError("synthetic response loss")
        if self.transform is not None:
            return self.transform(response, self.calls)
        return response


def _client(
    store: _BackingStore,
    *,
    transport: _LoopbackTransport | None = None,
    attempts: tuple[str, ...] = ("attempt-1", "attempt-2", "attempt-3"),
) -> tuple[ReceiptAuthorityClient, _LoopbackTransport]:
    selected_transport = transport or _LoopbackTransport(ReceiptAuthorityService(store))
    iterator = iter(attempts)
    client = ReceiptAuthorityClient(
        target=_target(),
        route=_route(),
        transport=selected_transport,
        attempt_id_factory=lambda: next(iterator),
    )
    assert isinstance(client, ReceiptStore)
    return client, selected_transport


def test_direct_confirmed_facade_claim_mints_one_attempt_bound_proof() -> None:
    store = _BackingStore()
    client, transport = _client(store)

    result = asyncio.run(client.claim_or_adopt_receipt(_claimed_receipt(), _binding()))

    assert type(result) is ReceiptClaimCreated
    assert transport.calls == 1
    assert store.claim_calls == 1
    claimed, binding = result.direct_create._take_claim()
    assert claimed == result.receipt == StoredRecord(_claimed_receipt(), 0)
    assert binding == _binding()
    with pytest.raises(ValueError, match="already consumed"):
        result.direct_create._take_claim()


def test_lost_direct_create_response_retries_as_adopted_without_dispatch_grant() -> None:
    store = _BackingStore()
    transport = _LoopbackTransport(
        ReceiptAuthorityService(store),
        lose_after_calls={1},
    )
    client, _ = _client(store, transport=transport)

    with pytest.raises(AuthorityStoreUnavailable):
        asyncio.run(client.claim_or_adopt_receipt(_claimed_receipt(), _binding()))
    retried = asyncio.run(client.claim_or_adopt_receipt(_claimed_receipt(), _binding()))

    assert type(retried) is ReceiptClaimAdopted
    assert retried.receipt == StoredRecord(_claimed_receipt(), 0)
    assert store.claim_calls == 2
    assert len(transport.requests) == 2
    assert transport.requests[0] != transport.requests[1]
    retry_response = decode_contract(
        transport.responses[1],
        ReceiptAuthorityResponseV1,
    )
    assert retry_response.disposition is ReceiptAuthorityDisposition.CLAIM_ADOPTED
    assert retry_response.direct_create_confirmation is None


def test_response_from_another_attempt_cannot_reconstruct_direct_create_proof() -> None:
    store = _BackingStore()
    first_response: bytes | None = None

    def replay_first(response: bytes, call: int) -> bytes:
        nonlocal first_response
        if call == 1:
            first_response = response
            return response
        assert first_response is not None
        return first_response

    transport = _LoopbackTransport(
        ReceiptAuthorityService(store),
        transform=replay_first,
    )
    client, _ = _client(store, transport=transport)

    first = asyncio.run(client.claim_or_adopt_receipt(_claimed_receipt(), _binding()))
    assert type(first) is ReceiptClaimCreated
    with pytest.raises(AuthorityStoreCorruptRecord):
        asyncio.run(client.claim_or_adopt_receipt(_claimed_receipt(), _binding()))


def test_changed_request_digest_is_rejected_before_direct_proof_creation() -> None:
    store = _BackingStore()

    def change_request_digest(response: bytes, _call: int) -> bytes:
        decoded = decode_contract(response, ReceiptAuthorityResponseV1)
        confirmation = decoded.direct_create_confirmation
        assert confirmation is not None
        wrong_digest = "f" * 64
        changed_confirmation = DirectReceiptCreateConfirmationV1(
            schema_version=confirmation.schema_version,
            attempt_id=confirmation.attempt_id,
            request_sha256=wrong_digest,
            receipt_sha256=confirmation.receipt_sha256,
            mutation_sha256=confirmation.mutation_sha256,
        )
        changed = ReceiptAuthorityResponseV1(
            schema_version=decoded.schema_version,
            operation=decoded.operation,
            disposition=decoded.disposition,
            attempt_id=decoded.attempt_id,
            request_sha256=wrong_digest,
            target=decoded.target,
            stored_receipt=decoded.stored_receipt,
            direct_create_confirmation=changed_confirmation,
        )
        return canonical_json_bytes(changed)

    transport = _LoopbackTransport(
        ReceiptAuthorityService(store),
        transform=change_request_digest,
    )
    client, _ = _client(store, transport=transport)

    with pytest.raises(AuthorityStoreCorruptRecord):
        asyncio.run(client.claim_or_adopt_receipt(_claimed_receipt(), _binding()))


def test_client_implements_remote_read_and_compare_and_set_without_new_authority() -> None:
    store = _BackingStore()
    client, _ = _client(store)
    claimed = asyncio.run(client.claim_or_adopt_receipt(_claimed_receipt(), _binding()))
    assert type(claimed) is ReceiptClaimCreated

    updated = asyncio.run(
        client.compare_and_set_receipt(claimed.receipt, _denied_receipt())
    )
    readback = asyncio.run(client.read_receipt(_binding().idempotency_key))

    assert updated == StoredRecord(_denied_receipt(), 1)
    assert readback == updated
    assert store.cas_calls == 1


def test_client_resolves_ambiguous_receipt_through_exact_fenced_operation() -> None:
    expected, replacement, authority, service_claim = _ambiguous_resolution_records()
    store = _BackingStore()
    store.stored = expected
    store.authority = authority
    store.service_claim = service_claim
    client, transport = _client(store)

    updated = asyncio.run(
        client.resolve_ambiguous_receipt(
            expected,
            replacement,
            authority,
            service_claim,
        )
    )

    assert updated == StoredRecord(replacement, expected.revision + 1)
    assert store.stored == updated
    assert store.resolution_calls == 1
    assert store.cas_calls == 0
    request = decode_contract(transport.requests[0], ReceiptAuthorityRequestV1)
    assert request.operation is ReceiptAuthorityOperation.RESOLVE_AMBIGUOUS
    assert request.resolve_ambiguous is not None


def test_lost_resolution_response_leaves_exact_marked_receipt_for_adoption() -> None:
    expected, replacement, authority, service_claim = _ambiguous_resolution_records()
    store = _BackingStore()
    store.stored = expected
    store.authority = authority
    store.service_claim = service_claim
    transport = _LoopbackTransport(
        ReceiptAuthorityService(store),
        lose_after_calls={1},
    )
    client, _ = _client(store, transport=transport)

    with pytest.raises(AuthorityStoreUnavailable):
        asyncio.run(
            client.resolve_ambiguous_receipt(
                expected,
                replacement,
                authority,
                service_claim,
            )
        )

    assert store.stored == StoredRecord(replacement, expected.revision + 1)
    assert asyncio.run(client.read_receipt(expected.value.idempotency_key)) == store.stored
    assert store.resolution_calls == 1


@pytest.mark.parametrize("changed_fence", ["authority", "service_claim"])
def test_resolution_fence_race_cannot_update_receipt(changed_fence: str) -> None:
    expected, replacement, authority, service_claim = _ambiguous_resolution_records()
    store = _BackingStore()
    store.stored = expected
    store.authority = authority
    store.service_claim = service_claim
    if changed_fence == "authority":
        store.authority = StoredRecord(authority.value, authority.revision + 1)
    else:
        store.service_claim = StoredRecord(
            service_claim.value,
            service_claim.revision + 1,
        )
    client, _ = _client(store)

    with pytest.raises(AuthorityStoreUnavailable):
        asyncio.run(
            client.resolve_ambiguous_receipt(
                expected,
                replacement,
                authority,
                service_claim,
            )
        )

    assert store.stored == expected
    assert store.resolution_calls == 1


def test_generic_compare_and_set_cannot_append_readback_resolution_marker() -> None:
    expected, replacement, _, _ = _ambiguous_resolution_records()
    store = _BackingStore()
    store.stored = expected
    client, _ = _client(store)

    with pytest.raises(ValueError, match="dedicated operation"):
        asyncio.run(client.compare_and_set_receipt(expected, replacement))

    assert store.stored == expected
    assert store.cas_calls == 0


def test_attempt_identifier_cannot_be_reused_even_if_the_factory_repeats() -> None:
    store = _BackingStore()
    client, transport = _client(
        store,
        attempts=("same-attempt", "same-attempt"),
    )

    first = asyncio.run(client.claim_or_adopt_receipt(_claimed_receipt(), _binding()))
    assert type(first) is ReceiptClaimCreated
    with pytest.raises(AuthorityStoreUnavailable):
        asyncio.run(client.read_receipt(_binding().idempotency_key))
    assert transport.calls == 1
