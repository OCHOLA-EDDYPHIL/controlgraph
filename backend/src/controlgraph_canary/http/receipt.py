"""HTTP response composition for receipt-backed protected task execution."""

from __future__ import annotations

from typing import Literal

from fastapi import Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, field_validator

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.receipt_execution import (
    ReceiptExecutionCoordinator,
    ReceiptExecutionDenied,
    ReceiptExecutionStored,
)
from controlgraph_canary.contracts.models import (
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
)
from controlgraph_canary.http.service import VerifiedTaskHandler

RECEIPT_TASK_RESPONSE_V1: Literal["controlgraph.receipt-task-response/v1"] = (
    "controlgraph.receipt-task-response/v1"
)
RECEIPT_TASK_DENIAL_V1: Literal["controlgraph.receipt-task-denial/v1"] = (
    "controlgraph.receipt-task-denial/v1"
)


class StoredReceiptTaskResponse(BaseModel):
    """Complete sanitized durable result returned identically on exact replay."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

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


class DeniedReceiptTaskResponse(BaseModel):
    """Minimal stable denial when no exact durable receipt can be returned."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

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
            status_code = 202 if receipt.value.outcome is ReceiptOutcome.CLAIMED else 200
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
        unavailable_response = DeniedReceiptTaskResponse(
            code=ReasonCode.AUTHORITY_UNAVAILABLE
        )
        return JSONResponse(
            status_code=503,
            content=unavailable_response.model_dump(mode="json"),
        )

    return handle


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
    "StoredReceiptTaskResponse",
    "create_receipt_task_handler",
]
