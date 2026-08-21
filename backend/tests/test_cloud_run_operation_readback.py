from __future__ import annotations

import asyncio

import pytest
from google.cloud import run_v2
from google.longrunning import operations_pb2
from google.protobuf import any_pb2, wrappers_pb2
from google.rpc import status_pb2
from root_v2_support import target_binding

from controlgraph_canary.integrations.google.cloud_run import (
    CLOUD_RUN_RPC_TIMEOUT_SECONDS,
    CloudRunV2OperationReadback,
)


class _OperationsClient:
    def __init__(self, response: operations_pb2.Operation | Exception) -> None:
        self.response = response
        self.calls: list[tuple[operations_pb2.GetOperationRequest, object, float]] = []

    async def get_operation(
        self,
        request: operations_pb2.GetOperationRequest,
        *,
        retry: object | None,
        timeout: float,
    ) -> operations_pb2.Operation:
        self.calls.append((request, retry, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _reader(client: _OperationsClient) -> CloudRunV2OperationReadback:
    target = target_binding()
    return CloudRunV2OperationReadback(
        target=target,
        configured_project_id=target.project_id,
        operations_client_factory=lambda: client,
    )


def _name(suffix: str = "apply-canary-001") -> str:
    target = target_binding()
    return (
        f"projects/{target.project_id}/locations/{target.region}/operations/{suffix}"
    )


def _service_name(service: str = "controlgraph-reference-target") -> str:
    target = target_binding()
    return f"projects/{target.project_id}/locations/{target.region}/services/{service}"


def _service_response(service: str = "controlgraph-reference-target") -> any_pb2.Any:
    response = any_pb2.Any()
    response.Pack(
        run_v2.Service.pb(run_v2.Service(name=_service_name(service)))
    )
    return response


def test_operation_readback_uses_one_exact_get_without_retry() -> None:
    operation = operations_pb2.Operation(
        name=_name(),
        done=True,
        response=_service_response(),
    )
    client = _OperationsClient(operation)

    assert asyncio.run(_reader(client).terminal_success(_name())) is True
    assert len(client.calls) == 1
    request, retry, timeout = client.calls[0]
    assert request.name == _name()
    assert retry is None
    assert timeout == CLOUD_RUN_RPC_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    "operation_name",
    [
        "operations/apply-canary-001",
        "projects/shared/locations/us-central1/operations/apply-canary-001",
        (
            "projects/controlgraph-canary-abc123/locations/europe-west1/"
            "operations/apply-canary-001"
        ),
        "projects/controlgraph-canary-abc123/locations/us-central1/operations/bad/name",
    ],
)
def test_operation_readback_rejects_nonexact_names_without_provider_access(
    operation_name: str,
) -> None:
    client = _OperationsClient(
        operations_pb2.Operation(name=_name(), done=True, response=_service_response())
    )

    assert asyncio.run(_reader(client).terminal_success(operation_name)) is False
    assert client.calls == []


@pytest.mark.parametrize(
    "response",
    [
        operations_pb2.Operation(name=_name(), done=False),
        operations_pb2.Operation(name=_name(), done=True),
        operations_pb2.Operation(
            name=_name(),
            done=True,
            error=status_pb2.Status(code=7, message="denied"),
        ),
        operations_pb2.Operation(
            name=_name("different-operation"),
            done=True,
            response=_service_response(),
        ),
    ],
)
def test_operation_readback_rejects_nonterminal_error_and_wrong_name(
    response: operations_pb2.Operation,
) -> None:
    assert asyncio.run(_reader(_OperationsClient(response)).terminal_success(_name())) is False


def test_operation_readback_rejects_wrong_response_type_and_service() -> None:
    wrong_type = any_pb2.Any()
    wrong_type.Pack(wrappers_pb2.StringValue(value="not-a-service"))
    for response in (
        operations_pb2.Operation(name=_name(), done=True, response=wrong_type),
        operations_pb2.Operation(
            name=_name(),
            done=True,
            response=_service_response("another-service"),
        ),
    ):
        assert (
            asyncio.run(_reader(_OperationsClient(response)).terminal_success(_name()))
            is False
        )


def test_operation_readback_fails_closed_on_provider_error() -> None:
    client = _OperationsClient(RuntimeError("synthetic unavailable"))

    assert asyncio.run(_reader(client).terminal_success(_name())) is False


def test_operation_readback_constructor_rejects_unbound_coordinates() -> None:
    target = target_binding()
    with pytest.raises(ValueError):
        CloudRunV2OperationReadback(
            target=target,
            configured_project_id="controlgraph-canary-other1",
        )
