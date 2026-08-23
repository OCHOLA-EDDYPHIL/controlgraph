"""Authenticated-transport core for coordinator-owned receipt authority writes."""

from __future__ import annotations

import asyncio
import hmac
import re
from collections.abc import Callable
from threading import Lock
from typing import Final, Protocol, runtime_checkable
from uuid import uuid4

from controlgraph_canary.application.authority_store import (
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
    RECOVERY_RECEIPT_AUTHORITY_PATH,
    AuthenticationContext,
    CallerRole,
    ServiceRole,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.independent_verification import (
    CompletionClassificationV1,
    CompletionKind,
)
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
    ReceiptAuthorityClaimV1,
    ReceiptAuthorityCompareAndSetV1,
    ReceiptAuthorityDisposition,
    ReceiptAuthorityOperation,
    ReceiptAuthorityReadV1,
    ReceiptAuthorityRequestV1,
    ReceiptAuthorityResolveAmbiguousV1,
    ReceiptAuthorityResponseV1,
    ReceiptMutationBindingV1,
    StoredEpochAuthorityV1,
    StoredExecutionReceiptV1,
    StoredServiceClaimV1,
)
from controlgraph_canary.contracts.storage import ServiceClaimRecord

_ATTEMPT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_STANDARD_RECEIPT_ACTIONS: Final = frozenset(
    {
        CapabilityAction.APPLY_CANARY,
        CapabilityAction.PROMOTE_CANDIDATE,
    }
)
_RECOVERY_RECEIPT_ACTIONS: Final = frozenset({CapabilityAction.RECOVER_STABLE})


@runtime_checkable
class ReceiptAuthorityBackingStore(Protocol):
    """Coordinator-owned durable receipt operations used by the facade."""

    @property
    def target(self) -> TargetBinding: ...

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]: ...


@runtime_checkable
class AmbiguousReceiptResolutionBackingStore(Protocol):
    """Coordinator store operation that atomically fences one readback resolution."""

    @property
    def target(self) -> TargetBinding: ...

    async def resolve_ambiguous_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        expected_service_claim: StoredRecord[ServiceClaimRecord],
    ) -> StoredRecord[ExecutionReceipt]: ...


@runtime_checkable
class StaleDenialCompletionWorkflow(Protocol):
    """Coordinator-owned classifier for persisted epoch-mismatch receipts."""

    @property
    def target(self) -> TargetBinding: ...

    async def classify_stale_denial(
        self,
        receipt: ExecutionReceipt,
    ) -> CompletionClassificationV1: ...


class ReceiptAuthorityService:
    """Serve canonical receipt operations through the coordinator's writer identity."""

    def __init__(
        self,
        store: ReceiptAuthorityBackingStore,
        *,
        completion_workflow: StaleDenialCompletionWorkflow | None = None,
    ) -> None:
        if not isinstance(store, ReceiptAuthorityBackingStore):
            raise TypeError("an exact receipt authority backing store is required")
        target = store.target
        if (
            type(target) is not TargetBinding
            or (
                completion_workflow is not None
                and (
                    not isinstance(
                        completion_workflow,
                        StaleDenialCompletionWorkflow,
                    )
                    or completion_workflow.target != target
                )
            )
        ):
            raise TypeError("receipt authority backing store must be target-bound")
        self._store = store
        self._target = target
        self._completion_workflow = completion_workflow

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def handle(self, payload: bytes) -> bytes:
        """Execute one canonical executor request after exact route authentication."""

        return await self._handle(payload, admitted_actions=_STANDARD_RECEIPT_ACTIONS)

    async def handle_authenticated(
        self,
        payload: bytes,
        caller: AuthenticationContext,
    ) -> bytes:
        """Execute standard receipt writes from the authenticated executor."""

        if (
            type(caller) is not AuthenticationContext
            or caller.role is not CallerRole.EXECUTOR
        ):
            raise AuthorityStoreCorruptRecord
        return await self._handle(
            payload,
            admitted_actions=_STANDARD_RECEIPT_ACTIONS,
        )

    async def handle_recovery_authenticated(
        self,
        payload: bytes,
        caller: AuthenticationContext,
    ) -> bytes:
        """Execute recovery-only receipt writes from the executor facade."""

        if (
            type(caller) is not AuthenticationContext
            or caller.role is not CallerRole.EXECUTOR
        ):
            raise AuthorityStoreCorruptRecord
        return await self._handle(
            payload,
            admitted_actions=_RECOVERY_RECEIPT_ACTIONS,
        )

    async def _handle(
        self,
        payload: bytes,
        *,
        admitted_actions: frozenset[CapabilityAction],
    ) -> bytes:
        if admitted_actions not in {
            _STANDARD_RECEIPT_ACTIONS,
            _RECOVERY_RECEIPT_ACTIONS,
        }:
            raise AuthorityStoreCorruptRecord

        try:
            request = decode_contract(payload, ReceiptAuthorityRequestV1)
        except (ContractError, TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None
        if request.target != self._target:
            raise AuthorityStoreCorruptRecord

        if request.operation is ReceiptAuthorityOperation.CLAIM:
            response = await self._claim(
                request,
                admitted_actions=admitted_actions,
            )
        elif request.operation is ReceiptAuthorityOperation.READ:
            response = await self._read(request)
        elif request.operation is ReceiptAuthorityOperation.COMPARE_AND_SET:
            response = await self._compare_and_set(
                request,
                admitted_actions=admitted_actions,
            )
        elif request.operation is ReceiptAuthorityOperation.RESOLVE_AMBIGUOUS:
            response = await self._resolve_ambiguous(
                request,
                admitted_actions=admitted_actions,
            )
        else:
            raise AuthorityStoreCorruptRecord
        await self._classify_stale_denial(response)
        try:
            return canonical_json_bytes(response)
        except (ContractError, TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None

    async def _classify_stale_denial(
        self,
        response: ReceiptAuthorityResponseV1,
    ) -> None:
        workflow = self._completion_workflow
        stored = response.stored_receipt
        if workflow is None or stored is None:
            return
        receipt = stored.receipt
        if not (
            receipt.outcome is ReceiptOutcome.DENIED
            and receipt.reason_code is ReasonCode.EPOCH_MISMATCH
        ):
            return
        classification = await workflow.classify_stale_denial(receipt)
        if (
            type(classification) is not CompletionClassificationV1
            or classification.request.kind
            is not CompletionKind.STALE_CAPABILITY_DENIAL
            or classification.request.verification.root_id != receipt.root_id
            or classification.request.verification.root_sha256 != receipt.root_sha256
            or classification.request.verification.epoch != receipt.epoch
            or classification.request.verification.target != receipt.target
            or classification.request.verification.plan_sha256 != receipt.plan_sha256
            or classification.request.verification.request_id != receipt.request_id
        ):
            raise AuthorityStoreCorruptRecord

    async def _claim(
        self,
        request: ReceiptAuthorityRequestV1,
        *,
        admitted_actions: frozenset[CapabilityAction],
    ) -> ReceiptAuthorityResponseV1:
        claim = request.claim
        if claim is None:
            raise AuthorityStoreCorruptRecord
        binding = _domain_binding(claim.binding)
        try:
            validate_receipt_claim_binding(claim.receipt, binding)
        except (TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None
        _require_worker_action(admitted_actions, claim.receipt.action)
        result = await self._store.claim_or_adopt_receipt(claim.receipt, binding)
        request_sha256 = canonical_sha256(request)

        if type(result) is ReceiptClaimCreated:
            try:
                confirmed_receipt, confirmed_binding = result.direct_create._take_claim()
            except (TypeError, ValueError):
                raise AuthorityStoreCorruptRecord from None
            expected = StoredRecord(claim.receipt, 0)
            if (
                result.receipt != expected
                or confirmed_receipt != expected
                or confirmed_binding != binding
            ):
                raise AuthorityStoreCorruptRecord
            stored = _wire_stored(result.receipt)
            return ReceiptAuthorityResponseV1(
                schema_version="controlgraph.receipt-authority-response/v1",
                operation=request.operation,
                disposition=ReceiptAuthorityDisposition.CLAIM_CREATED,
                attempt_id=request.attempt_id,
                request_sha256=request_sha256,
                target=self._target,
                stored_receipt=stored,
                direct_create_confirmation=DirectReceiptCreateConfirmationV1(
                    schema_version=(
                        "controlgraph.direct-receipt-create-confirmation/v1"
                    ),
                    attempt_id=request.attempt_id,
                    request_sha256=request_sha256,
                    receipt_sha256=canonical_sha256(result.receipt.value),
                    mutation_sha256=mutation_identity(binding),
                ),
            )
        if type(result) is ReceiptClaimAdopted:
            if not _stored_matches_binding(result.receipt, binding):
                raise AuthorityStoreCorruptRecord
            return ReceiptAuthorityResponseV1(
                schema_version="controlgraph.receipt-authority-response/v1",
                operation=request.operation,
                disposition=ReceiptAuthorityDisposition.CLAIM_ADOPTED,
                attempt_id=request.attempt_id,
                request_sha256=request_sha256,
                target=self._target,
                stored_receipt=_wire_stored(result.receipt),
            )
        if type(result) is ReceiptClaimConflict:
            return ReceiptAuthorityResponseV1(
                schema_version="controlgraph.receipt-authority-response/v1",
                operation=request.operation,
                disposition=ReceiptAuthorityDisposition.CLAIM_CONFLICT,
                attempt_id=request.attempt_id,
                request_sha256=request_sha256,
                target=self._target,
            )
        raise AuthorityStoreCorruptRecord

    async def _read(self, request: ReceiptAuthorityRequestV1) -> ReceiptAuthorityResponseV1:
        read = request.read
        if read is None:
            raise AuthorityStoreCorruptRecord
        stored = await self._store.read_receipt(read.idempotency_key)
        if stored is None:
            disposition = ReceiptAuthorityDisposition.RECEIPT_NOT_FOUND
            wire_stored = None
        else:
            _require_target_receipt(stored, self._target, read.idempotency_key)
            disposition = ReceiptAuthorityDisposition.RECEIPT_FOUND
            wire_stored = _wire_stored(stored)
        return ReceiptAuthorityResponseV1(
            schema_version="controlgraph.receipt-authority-response/v1",
            operation=request.operation,
            disposition=disposition,
            attempt_id=request.attempt_id,
            request_sha256=canonical_sha256(request),
            target=self._target,
            stored_receipt=wire_stored,
        )

    async def _compare_and_set(
        self,
        request: ReceiptAuthorityRequestV1,
        *,
        admitted_actions: frozenset[CapabilityAction],
    ) -> ReceiptAuthorityResponseV1:
        compare_and_set = request.compare_and_set
        if compare_and_set is None:
            raise AuthorityStoreCorruptRecord
        expected = _domain_stored(compare_and_set.expected)
        replacement = compare_and_set.replacement
        _require_worker_action(admitted_actions, expected.value.action)
        _require_worker_action(admitted_actions, replacement.action)
        _require_target_receipt(expected, self._target, replacement.idempotency_key)
        if replacement.target != self._target:
            raise AuthorityStoreCorruptRecord
        stored = await self._store.compare_and_set_receipt(expected, replacement)
        if stored != StoredRecord(replacement, expected.revision + 1):
            raise AuthorityStoreCorruptRecord
        return ReceiptAuthorityResponseV1(
            schema_version="controlgraph.receipt-authority-response/v1",
            operation=request.operation,
            disposition=ReceiptAuthorityDisposition.RECEIPT_UPDATED,
            attempt_id=request.attempt_id,
            request_sha256=canonical_sha256(request),
            target=self._target,
            stored_receipt=_wire_stored(stored),
        )

    async def _resolve_ambiguous(
        self,
        request: ReceiptAuthorityRequestV1,
        *,
        admitted_actions: frozenset[CapabilityAction],
    ) -> ReceiptAuthorityResponseV1:
        resolution = request.resolve_ambiguous
        if resolution is None or not isinstance(
            self._store,
            AmbiguousReceiptResolutionBackingStore,
        ):
            raise AuthorityStoreCorruptRecord
        expected = _domain_stored(resolution.expected)
        expected_authority = _domain_authority(resolution.expected_authority)
        expected_service_claim = _domain_service_claim(
            resolution.expected_service_claim
        )
        replacement = resolution.replacement
        _require_worker_action(admitted_actions, expected.value.action)
        _require_worker_action(admitted_actions, replacement.action)
        _require_target_receipt(expected, self._target, replacement.idempotency_key)
        if (
            replacement.target != self._target
            or expected_authority.value.target != self._target
            or expected_service_claim.value.target != self._target
        ):
            raise AuthorityStoreCorruptRecord
        stored = await self._store.resolve_ambiguous_receipt(
            expected,
            replacement,
            expected_authority,
            expected_service_claim,
        )
        if stored != StoredRecord(replacement, expected.revision + 1):
            raise AuthorityStoreCorruptRecord
        return ReceiptAuthorityResponseV1(
            schema_version="controlgraph.receipt-authority-response/v1",
            operation=request.operation,
            disposition=(
                ReceiptAuthorityDisposition.AMBIGUOUS_RECEIPT_RESOLVED
            ),
            attempt_id=request.attempt_id,
            request_sha256=canonical_sha256(request),
            target=self._target,
            stored_receipt=_wire_stored(stored),
        )


class ReceiptAuthorityClient:
    """Executor-side ReceiptStore implemented over one-shot canonical transport."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
        attempt_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if type(target) is not TargetBinding:
            raise TypeError("receipt authority client target must be exact")
        if (
            type(route) is not CoordinatorInternalRoute
            or route.project_id != target.project_id
            or route.caller_role is not CallerRole.EXECUTOR
            or route.service_role is not ServiceRole.COORDINATOR
            or route.path
            not in {RECEIPT_AUTHORITY_PATH, RECOVERY_RECEIPT_AUTHORITY_PATH}
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise ValueError("receipt authority client route is invalid")
        if attempt_id_factory is not None and not callable(attempt_id_factory):
            raise TypeError("receipt authority attempt factory must be callable")
        self._target = target
        self._route = route
        self._admitted_actions = (
            _RECOVERY_RECEIPT_ACTIONS
            if route.path == RECOVERY_RECEIPT_AUTHORITY_PATH
            else _STANDARD_RECEIPT_ACTIONS
        )
        self._transport = transport
        self._attempt_id_factory = attempt_id_factory or _new_attempt_id
        self._attempt_ids: set[str] = set()
        self._attempt_lock = Lock()

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        validate_receipt_claim_binding(receipt, binding)
        self._require_action(receipt.action)
        if receipt.target != self._target or not _binding_targets(binding, self._target):
            raise ValueError("receipt claim is outside the configured target")
        request = ReceiptAuthorityRequestV1(
            schema_version="controlgraph.receipt-authority-request/v1",
            operation=ReceiptAuthorityOperation.CLAIM,
            attempt_id=self._next_attempt_id(),
            target=self._target,
            claim=ReceiptAuthorityClaimV1(
                schema_version="controlgraph.receipt-authority-claim/v1",
                receipt=receipt,
                binding=_wire_binding(binding),
            ),
        )
        response = await self._exchange(request)
        if response.disposition is ReceiptAuthorityDisposition.CLAIM_CONFLICT:
            return ReceiptClaimConflict()
        stored_wire = response.stored_receipt
        if stored_wire is None:
            raise AuthorityStoreCorruptRecord
        stored = _domain_stored(stored_wire)
        if not _stored_matches_binding(stored, binding):
            raise AuthorityStoreCorruptRecord
        if response.disposition is ReceiptAuthorityDisposition.CLAIM_ADOPTED:
            return ReceiptClaimAdopted(stored)
        if response.disposition is not ReceiptAuthorityDisposition.CLAIM_CREATED:
            raise AuthorityStoreCorruptRecord
        if stored != StoredRecord(receipt, 0):
            raise AuthorityStoreCorruptRecord
        confirmation = response.direct_create_confirmation
        if confirmation is None:
            raise AuthorityStoreCorruptRecord
        try:
            direct_create = DirectReceiptCreate._from_direct_authority_confirmation(
                stored,
                binding,
                attempt_id=request.attempt_id,
                request_sha256=canonical_sha256(request),
                confirmed_attempt_id=confirmation.attempt_id,
                confirmed_request_sha256=confirmation.request_sha256,
                confirmed_receipt_sha256=confirmation.receipt_sha256,
                confirmed_mutation_sha256=confirmation.mutation_sha256,
            )
        except (TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None
        return ReceiptClaimCreated(stored, direct_create)

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        request = ReceiptAuthorityRequestV1(
            schema_version="controlgraph.receipt-authority-request/v1",
            operation=ReceiptAuthorityOperation.READ,
            attempt_id=self._next_attempt_id(),
            target=self._target,
            read=ReceiptAuthorityReadV1(
                schema_version="controlgraph.receipt-authority-read/v1",
                idempotency_key=idempotency_key,
            ),
        )
        response = await self._exchange(request)
        if response.disposition is ReceiptAuthorityDisposition.RECEIPT_NOT_FOUND:
            return None
        if response.disposition is not ReceiptAuthorityDisposition.RECEIPT_FOUND:
            raise AuthorityStoreCorruptRecord
        if response.stored_receipt is None:
            raise AuthorityStoreCorruptRecord
        stored = _domain_stored(response.stored_receipt)
        _require_target_receipt(stored, self._target, idempotency_key)
        return stored

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        _require_target_receipt(expected, self._target, replacement.idempotency_key)
        self._require_action(expected.value.action)
        self._require_action(replacement.action)
        if replacement.target != self._target:
            raise ValueError("receipt replacement is outside the configured target")
        request = ReceiptAuthorityRequestV1(
            schema_version="controlgraph.receipt-authority-request/v1",
            operation=ReceiptAuthorityOperation.COMPARE_AND_SET,
            attempt_id=self._next_attempt_id(),
            target=self._target,
            compare_and_set=ReceiptAuthorityCompareAndSetV1(
                schema_version="controlgraph.receipt-authority-compare-and-set/v1",
                expected=_wire_stored(expected),
                replacement=replacement,
            ),
        )
        response = await self._exchange(request)
        if (
            response.disposition is not ReceiptAuthorityDisposition.RECEIPT_UPDATED
            or response.stored_receipt is None
        ):
            raise AuthorityStoreCorruptRecord
        stored = _domain_stored(response.stored_receipt)
        if stored != StoredRecord(replacement, expected.revision + 1):
            raise AuthorityStoreCorruptRecord
        return stored

    async def resolve_ambiguous_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
        expected_authority: StoredRecord[EpochAuthorityRecord],
        expected_service_claim: StoredRecord[ServiceClaimRecord],
    ) -> StoredRecord[ExecutionReceipt]:
        _require_target_receipt(expected, self._target, replacement.idempotency_key)
        self._require_action(expected.value.action)
        self._require_action(replacement.action)
        if (
            replacement.target != self._target
            or expected_authority.value.target != self._target
            or expected_service_claim.value.target != self._target
        ):
            raise ValueError("ambiguous receipt resolution is outside the configured target")
        request = ReceiptAuthorityRequestV1(
            schema_version="controlgraph.receipt-authority-request/v1",
            operation=ReceiptAuthorityOperation.RESOLVE_AMBIGUOUS,
            attempt_id=self._next_attempt_id(),
            target=self._target,
            resolve_ambiguous=ReceiptAuthorityResolveAmbiguousV1(
                schema_version=(
                    "controlgraph.receipt-authority-resolve-ambiguous/v1"
                ),
                expected=_wire_stored(expected),
                replacement=replacement,
                expected_authority=_wire_authority(expected_authority),
                expected_service_claim=_wire_service_claim(
                    expected_service_claim
                ),
            ),
        )
        response = await self._exchange(request)
        if (
            response.disposition
            is not ReceiptAuthorityDisposition.AMBIGUOUS_RECEIPT_RESOLVED
            or response.stored_receipt is None
        ):
            raise AuthorityStoreCorruptRecord
        stored = _domain_stored(response.stored_receipt)
        if stored != StoredRecord(replacement, expected.revision + 1):
            raise AuthorityStoreCorruptRecord
        return stored

    def _require_action(self, action: CapabilityAction) -> None:
        if action not in self._admitted_actions:
            raise ValueError("receipt action is outside the configured authority path")

    async def _exchange(
        self,
        request: ReceiptAuthorityRequestV1,
    ) -> ReceiptAuthorityResponseV1:
        try:
            payload = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AuthorityStoreUnavailable from None
        try:
            response = decode_contract(payload, ReceiptAuthorityResponseV1)
        except (ContractError, TypeError, ValueError):
            raise AuthorityStoreCorruptRecord from None
        request_sha256 = canonical_sha256(request)
        if (
            response.operation is not request.operation
            or response.target != self._target
            or not hmac.compare_digest(response.attempt_id, request.attempt_id)
            or not hmac.compare_digest(response.request_sha256, request_sha256)
        ):
            raise AuthorityStoreCorruptRecord
        return response

    def _next_attempt_id(self) -> str:
        try:
            attempt_id = self._attempt_id_factory()
        except Exception:
            raise AuthorityStoreUnavailable from None
        if type(attempt_id) is not str or _ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise AuthorityStoreUnavailable
        with self._attempt_lock:
            if attempt_id in self._attempt_ids:
                raise AuthorityStoreUnavailable
            self._attempt_ids.add(attempt_id)
        return attempt_id


def _new_attempt_id() -> str:
    return f"cgra-{uuid4().hex}"


def _wire_binding(binding: MutationBinding) -> ReceiptMutationBindingV1:
    if type(binding) is not MutationBinding:
        raise TypeError("an exact mutation binding is required")
    return ReceiptMutationBindingV1(
        schema_version="controlgraph.receipt-mutation-binding/v1",
        idempotency_key=binding.idempotency_key,
        request_id=binding.request_id,
        root_id=binding.root_id,
        root_sha256=binding.root_sha256,
        epoch=binding.epoch,
        action=CapabilityAction(binding.action.value),
        target=TargetBinding(
            schema_version="controlgraph.target-binding/v1",
            project_id=binding.target.project_id,
            region=binding.target.region,
            environment=binding.target.environment,
            service_name=binding.target.service_name,
        ),
        provider_precondition=binding.provider_precondition,
        plan_sha256=binding.plan_sha256,
        capability_sha256=binding.capability_sha256,
        payload_sha256=binding.payload_sha256,
        expected_poststate_sha256=binding.expected_poststate_sha256,
    )


def _domain_binding(binding: ReceiptMutationBindingV1) -> MutationBinding:
    if type(binding) is not ReceiptMutationBindingV1:
        raise TypeError("an exact wire mutation binding is required")
    return MutationBinding(
        idempotency_key=binding.idempotency_key,
        request_id=binding.request_id,
        root_id=binding.root_id,
        root_sha256=binding.root_sha256,
        epoch=binding.epoch,
        action=MutationAction(binding.action.value),
        target=MutationTargetKey(
            project_id=binding.target.project_id,
            region=binding.target.region,
            environment=binding.target.environment,
            service_name=binding.target.service_name,
        ),
        provider_precondition=binding.provider_precondition,
        plan_sha256=binding.plan_sha256,
        capability_sha256=binding.capability_sha256,
        payload_sha256=binding.payload_sha256,
        expected_poststate_sha256=binding.expected_poststate_sha256,
    )


def _wire_stored(stored: StoredRecord[ExecutionReceipt]) -> StoredExecutionReceiptV1:
    if type(stored) is not StoredRecord or type(stored.value) is not ExecutionReceipt:
        raise AuthorityStoreCorruptRecord
    return StoredExecutionReceiptV1(
        schema_version="controlgraph.stored-execution-receipt/v1",
        receipt=stored.value,
        storage_revision=stored.revision,
    )


def _wire_authority(
    stored: StoredRecord[EpochAuthorityRecord],
) -> StoredEpochAuthorityV1:
    if type(stored) is not StoredRecord or type(stored.value) is not EpochAuthorityRecord:
        raise AuthorityStoreCorruptRecord
    return StoredEpochAuthorityV1(
        schema_version="controlgraph.stored-epoch-authority/v1",
        authority=stored.value,
        storage_revision=stored.revision,
    )


def _wire_service_claim(
    stored: StoredRecord[ServiceClaimRecord],
) -> StoredServiceClaimV1:
    if type(stored) is not StoredRecord or type(stored.value) is not ServiceClaimRecord:
        raise AuthorityStoreCorruptRecord
    return StoredServiceClaimV1(
        schema_version="controlgraph.stored-service-claim/v1",
        service_claim=stored.value,
        storage_revision=stored.revision,
    )


def _domain_stored(stored: StoredExecutionReceiptV1) -> StoredRecord[ExecutionReceipt]:
    if type(stored) is not StoredExecutionReceiptV1:
        raise AuthorityStoreCorruptRecord
    return StoredRecord(stored.receipt, stored.storage_revision)


def _domain_authority(
    stored: StoredEpochAuthorityV1,
) -> StoredRecord[EpochAuthorityRecord]:
    if type(stored) is not StoredEpochAuthorityV1:
        raise AuthorityStoreCorruptRecord
    return StoredRecord(stored.authority, stored.storage_revision)


def _domain_service_claim(
    stored: StoredServiceClaimV1,
) -> StoredRecord[ServiceClaimRecord]:
    if type(stored) is not StoredServiceClaimV1:
        raise AuthorityStoreCorruptRecord
    return StoredRecord(stored.service_claim, stored.storage_revision)


def _binding_targets(binding: MutationBinding, target: TargetBinding) -> bool:
    return (
        binding.target.project_id == target.project_id
        and binding.target.region == target.region
        and binding.target.environment == target.environment
        and binding.target.service_name == target.service_name
    )


def _stored_matches_binding(
    stored: StoredRecord[ExecutionReceipt],
    binding: MutationBinding,
) -> bool:
    if type(stored) is not StoredRecord or type(stored.value) is not ExecutionReceipt:
        return False
    receipt = stored.value
    target = binding.target
    return (
        receipt.idempotency_key == binding.idempotency_key
        and receipt.request_id == binding.request_id
        and receipt.root_id == binding.root_id
        and receipt.root_sha256 == binding.root_sha256
        and receipt.epoch == binding.epoch
        and receipt.action.value == binding.action.value
        and receipt.target.project_id == target.project_id
        and receipt.target.region == target.region
        and receipt.target.environment == target.environment
        and receipt.target.service_name == target.service_name
        and receipt.provider_etag == binding.provider_precondition
        and receipt.plan_sha256 == binding.plan_sha256
        and receipt.capability_sha256 == binding.capability_sha256
        and receipt.mutation_sha256 == mutation_identity(binding)
        and receipt.expected_poststate_sha256 == binding.expected_poststate_sha256
    )


def _require_target_receipt(
    stored: StoredRecord[ExecutionReceipt],
    target: TargetBinding,
    idempotency_key: str,
) -> None:
    if (
        type(stored) is not StoredRecord
        or type(stored.value) is not ExecutionReceipt
        or stored.value.target != target
        or stored.value.idempotency_key != idempotency_key
    ):
        raise AuthorityStoreCorruptRecord


def _require_worker_action(
    admitted_actions: frozenset[CapabilityAction],
    action: CapabilityAction,
) -> None:
    if action not in admitted_actions:
        raise AuthorityStoreCorruptRecord


__all__ = [
    "AmbiguousReceiptResolutionBackingStore",
    "ReceiptAuthorityBackingStore",
    "ReceiptAuthorityClient",
    "ReceiptAuthorityService",
]
