"""HTTP response composition for receipt-backed protected task execution."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import Response
from fastapi.responses import JSONResponse
from pydantic import field_validator

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.identity import (
    RECOVERY_EXECUTION_FACADE_PATH,
    AuthenticationContext,
    CallerRole,
    ServiceRole,
)
from controlgraph_canary.application.receipt_execution import (
    ReceiptExecutionCoordinator,
    ReceiptExecutionDenied,
    ReceiptExecutionResponse,
    ReceiptExecutionStored,
    RecoveryExecutorFacade,
    RecoveryTaskForwarder,
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
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    ContractError,
    ContractErrorCode,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.recovery_execution import RecoveryTaskRequestV2
from controlgraph_canary.contracts.storage import execution_receipt_logical_id
from controlgraph_canary.http.service import VerifiedTaskHandler

RECEIPT_TASK_RESPONSE_V1: Literal["controlgraph.receipt-task-response/v1"] = (
    "controlgraph.receipt-task-response/v1"
)
RECEIPT_TASK_DENIAL_V1: Literal["controlgraph.receipt-task-denial/v1"] = (
    "controlgraph.receipt-task-denial/v1"
)


class StoredReceiptTaskResponse(StrictContractModel):
    """Complete sanitized durable result returned identically on exact replay."""

    schema_version: Literal["controlgraph.receipt-task-response/v1"] = RECEIPT_TASK_RESPONSE_V1
    receipt: ExecutionReceipt
    storage_revision: int

    @field_validator("storage_revision")
    @classmethod
    def validate_storage_revision(cls, value: int) -> int:
        if type(value) is not int or not 0 <= value <= 2**53 - 1:
            raise ValueError("receipt storage revision is invalid")
        return value

    @classmethod
    def from_stored(cls, stored: StoredRecord[ExecutionReceipt]) -> StoredReceiptTaskResponse:
        if type(stored) is not StoredRecord or type(stored.value) is not ExecutionReceipt:
            raise TypeError("an exact stored execution receipt is required")
        return cls(receipt=stored.value, storage_revision=stored.revision)


class DeniedReceiptTaskResponse(StrictContractModel):
    """Minimal stable denial when no exact durable receipt can be returned."""

    schema_version: Literal["controlgraph.receipt-task-denial/v1"] = RECEIPT_TASK_DENIAL_V1
    code: ReasonCode


def create_receipt_task_handler(
    coordinator: ReceiptExecutionCoordinator,
) -> VerifiedTaskHandler:
    """Bind one receipt coordinator to the verified protected-task seam."""

    if type(coordinator) is not ReceiptExecutionCoordinator:
        raise TypeError("an exact receipt execution coordinator is required")

    async def handle(verified: VerifiedMutation) -> Response:
        result = await coordinator.execute(verified)
        if type(result) is ReceiptExecutionStored:
            receipt = result.receipt
            status_code = 503 if receipt.value.outcome is ReceiptOutcome.CLAIMED else 200
            stored_response = StoredReceiptTaskResponse.from_stored(receipt)
            return JSONResponse(
                status_code=status_code,
                content=stored_response.model_dump(mode="json"),
            )
        if type(result) is ReceiptExecutionDenied:
            status_code = _denial_status(result.reason_code)
            denial_response = DeniedReceiptTaskResponse(code=result.reason_code)
            return JSONResponse(
                status_code=status_code,
                content=denial_response.model_dump(mode="json"),
            )
        unavailable_response = DeniedReceiptTaskResponse(code=ReasonCode.AUTHORITY_UNAVAILABLE)
        return JSONResponse(
            status_code=503,
            content=unavailable_response.model_dump(mode="json"),
        )

    return handle


class RecoveryExecutorClient:
    """Call the executor recovery facade once and decode only its closed result."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
    ) -> None:
        if type(target) is not TargetBinding:
            raise TypeError("recovery executor client target must be exact")
        if (
            type(route) is not CoordinatorInternalRoute
            or route.project_id != target.project_id
            or route.caller_role is not CallerRole.RECOVERY
            or route.service_role is not ServiceRole.EXECUTOR
            or route.path != RECOVERY_EXECUTION_FACADE_PATH
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise ValueError("recovery executor client route is invalid")
        self._target = target
        self._route = route
        self._transport = transport

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def execute(self, payload: bytes) -> ReceiptExecutionResponse:
        if type(payload) is not bytes or not payload:
            raise TypeError("an exact canonical recovery task is required")
        try:
            request = decode_contract(payload, RecoveryTaskRequestV2)
        except ContractError:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        if request.intent.target != self._target:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        try:
            body = await self._transport.post(self._route, payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        return _decode_receipt_execution_response(body, request)


def create_recovery_forwarding_task_handler(
    forwarder: RecoveryTaskForwarder,
) -> VerifiedTaskHandler:
    """Bind the recovery task route to its one-shot executor facade forwarder."""

    if type(forwarder) is not RecoveryTaskForwarder:
        raise TypeError("an exact recovery task forwarder is required")

    async def handle(verified: VerifiedMutation) -> Response:
        try:
            result = await forwarder.forward(verified)
        except asyncio.CancelledError:
            raise
        except Exception:
            result = ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        return _receipt_execution_http_response(result)

    return handle


type RecoveryExecutorFacadeHandler = Callable[[bytes, AuthenticationContext], Awaitable[bytes]]


def create_recovery_executor_facade_handler(
    facade: RecoveryExecutorFacade,
) -> RecoveryExecutorFacadeHandler:
    """Serialize one independently verified executor-facade result as canonical JSON."""

    if type(facade) is not RecoveryExecutorFacade:
        raise TypeError("an exact recovery executor facade is required")

    async def handle(payload: bytes, caller: AuthenticationContext) -> bytes:
        result = await facade.execute(payload, caller)
        return _receipt_execution_response_bytes(result)

    return handle


def _receipt_execution_response_bytes(result: ReceiptExecutionResponse) -> bytes:
    if type(result) is ReceiptExecutionStored:
        return canonical_json_bytes(StoredReceiptTaskResponse.from_stored(result.receipt))
    if type(result) is ReceiptExecutionDenied:
        return canonical_json_bytes(DeniedReceiptTaskResponse(code=result.reason_code))
    raise TypeError("receipt execution response is invalid")


def _decode_receipt_execution_response(
    body: bytes,
    request: RecoveryTaskRequestV2,
) -> ReceiptExecutionResponse:
    try:
        stored = decode_contract(body, StoredReceiptTaskResponse)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
    else:
        receipt = StoredRecord(stored.receipt, stored.storage_revision)
        if not _recovery_receipt_matches_request(receipt, request):
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
        reason = (
            ReasonCode.RECEIPT_IN_PROGRESS
            if stored.receipt.outcome is ReceiptOutcome.CLAIMED
            else stored.receipt.reason_code
        )
        try:
            return ReceiptExecutionStored(receipt=receipt, reason_code=reason)
        except (TypeError, ValueError):
            return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)
    try:
        denied = decode_contract(body, DeniedReceiptTaskResponse)
        return ReceiptExecutionDenied(denied.code)
    except (ContractError, TypeError, ValueError):
        return ReceiptExecutionDenied(ReasonCode.AUTHORITY_UNAVAILABLE)


def _recovery_receipt_matches_request(
    stored: StoredRecord[ExecutionReceipt],
    request: RecoveryTaskRequestV2,
) -> bool:
    if (
        type(stored) is not StoredRecord
        or type(stored.value) is not ExecutionReceipt
        or type(request) is not RecoveryTaskRequestV2
    ):
        return False
    receipt = stored.value
    intent = request.intent
    binding = MutationBinding(
        idempotency_key=intent.idempotency_key,
        request_id=intent.request_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=MutationAction.RECOVER_STABLE,
        target=MutationTargetKey(
            project_id=intent.target.project_id,
            region=intent.target.region,
            environment=intent.target.environment,
            service_name=intent.target.service_name,
        ),
        provider_precondition=intent.provider_etag,
        plan_sha256=intent.plan_sha256,
        capability_sha256=canonical_sha256(request.capability),
        payload_sha256=canonical_sha256(request),
        expected_poststate_sha256=intent.desired_poststate_sha256,
    )
    if receipt.outcome is ReceiptOutcome.CLAIMED:
        valid_storage_state = stored.revision == 0
    elif receipt.outcome is ReceiptOutcome.VERIFIED:
        valid_storage_state = stored.revision >= 2
    else:
        valid_storage_state = (
            receipt.outcome
            in {
                ReceiptOutcome.DENIED,
                ReceiptOutcome.FAILED_SAFE,
                ReceiptOutcome.AMBIGUOUS,
            }
            and stored.revision >= 1
        )
    return (
        valid_storage_state
        and receipt.receipt_id
        == execution_receipt_logical_id(intent.target, intent.idempotency_key)
        and receipt.request_id == intent.request_id
        and receipt.idempotency_key == intent.idempotency_key
        and receipt.capability_sha256 == binding.capability_sha256
        and receipt.mutation_sha256 == mutation_identity(binding)
        and receipt.plan_sha256 == intent.plan_sha256
        and receipt.expected_poststate_sha256 == intent.desired_poststate_sha256
        and receipt.target == intent.target
        and receipt.root_id == intent.root_id
        and receipt.root_sha256 == intent.root_sha256
        and receipt.epoch == intent.epoch
        and receipt.action is CapabilityAction.RECOVER_STABLE
        and receipt.provider_etag == intent.provider_etag
        and receipt.dispatch_not_after == request.expires_at
    )


def _receipt_execution_http_response(result: ReceiptExecutionResponse) -> Response:
    if type(result) is ReceiptExecutionStored:
        status_code = 503 if result.receipt.value.outcome is ReceiptOutcome.CLAIMED else 200
        response = StoredReceiptTaskResponse.from_stored(result.receipt)
        return JSONResponse(
            status_code=status_code,
            content=response.model_dump(mode="json"),
        )
    if type(result) is ReceiptExecutionDenied:
        return JSONResponse(
            status_code=_denial_status(result.reason_code),
            content=DeniedReceiptTaskResponse(code=result.reason_code).model_dump(mode="json"),
        )
    return JSONResponse(
        status_code=503,
        content=DeniedReceiptTaskResponse(code=ReasonCode.AUTHORITY_UNAVAILABLE).model_dump(
            mode="json"
        ),
    )


def _denial_status(reason_code: ReasonCode) -> int:
    if reason_code is ReasonCode.AUTHORITY_UNAVAILABLE:
        return 503
    if reason_code is ReasonCode.IDEMPOTENCY_CONFLICT:
        return 409
    return 403


__all__ = [
    "RECEIPT_TASK_DENIAL_V1",
    "RECEIPT_TASK_RESPONSE_V1",
    "DeniedReceiptTaskResponse",
    "RecoveryExecutorClient",
    "RecoveryExecutorFacadeHandler",
    "StoredReceiptTaskResponse",
    "create_receipt_task_handler",
    "create_recovery_executor_facade_handler",
    "create_recovery_forwarding_task_handler",
]
