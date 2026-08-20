"""Authenticated, target-sealed operator observations."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Protocol, cast, runtime_checkable

from controlgraph_canary.application.authority_store import (
    AuthorityStoreCorruptRecord,
    AuthorityStoreError,
    StoredRecord,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunReadyState,
    CloudRunTargetState,
    TargetConfigurationProjection,
    cloud_run_revision_configuration_sha256,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.application.stable_snapshot import (
    StableCaptureError,
    StableSnapshotCaptureConfiguration,
    StableSnapshotCapturer,
    StableSnapshotReader,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReceiptOutcome,
    TargetBinding,
    TrafficAllocation,
)
from controlgraph_canary.contracts.operator_observability import (
    EXECUTION_RECEIPT_READ_INVOCATION_V1,
    EXECUTION_RECEIPT_READ_RESULT_V1,
    STABLE_SNAPSHOT_CAPTURE_INVOCATION_V1,
    STABLE_SNAPSHOT_CAPTURE_REQUEST_V1,
    STABLE_SNAPSHOT_CAPTURE_RESULT_V1,
    TARGET_TRAFFIC_READ_INVOCATION_V1,
    TARGET_TRAFFIC_READ_REQUEST_V1,
    TARGET_TRAFFIC_READ_RESULT_V1,
    ExecutionReceiptReadCommandV1,
    ExecutionReceiptReadInvocationV1,
    ExecutionReceiptReadResultV1,
    StableSnapshotCaptureCommandV1,
    StableSnapshotCaptureInvocationV1,
    StableSnapshotCaptureRequestV1,
    StableSnapshotCaptureResultV1,
    TargetTrafficReadCommandV1,
    TargetTrafficReadInvocationV1,
    TargetTrafficReadRequestV1,
    TargetTrafficReadResultV1,
)
from controlgraph_canary.contracts.promotion_execution import (
    VERIFIED_APPLY_RECEIPT_LOCATOR_V1,
    VerifiedApplyReceiptLocatorV1,
)
from controlgraph_canary.contracts.storage import execution_receipt_logical_id

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")


class OperatorObservationErrorCode(StrEnum):
    """Stable payload-free failures for exact operator observations."""

    CONFIGURATION_INVALID = "OPERATOR_OBSERVATION_CONFIGURATION_INVALID"
    CALLER_DENIED = "OPERATOR_OBSERVATION_CALLER_DENIED"
    OPERATOR_DENIED = "OPERATOR_OBSERVATION_OPERATOR_DENIED"
    COMMAND_DENIED = "OPERATOR_OBSERVATION_COMMAND_DENIED"
    TARGET_DENIED = "OPERATOR_OBSERVATION_TARGET_DENIED"
    CAPTURE_DENIED = "OPERATOR_OBSERVATION_CAPTURE_DENIED"
    TARGET_STATE_DENIED = "OPERATOR_OBSERVATION_TARGET_STATE_DENIED"
    RECEIPT_NOT_FOUND = "OPERATOR_OBSERVATION_RECEIPT_NOT_FOUND"
    STORE_UNAVAILABLE = "OPERATOR_OBSERVATION_STORE_UNAVAILABLE"
    TRANSPORT_UNAVAILABLE = "OPERATOR_OBSERVATION_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "OPERATOR_OBSERVATION_RESPONSE_INVALID"


class OperatorObservationError(RuntimeError):
    """Sanitized failure containing no credential, provider, or stored payload."""

    def __init__(self, code: OperatorObservationErrorCode) -> None:
        if type(code) is not OperatorObservationErrorCode:
            raise TypeError("an exact operator observation error code is required")
        self.code = code
        super().__init__(code.value)


class StableSnapshotReaderFactory(Protocol):
    """Create one configured verifier reader for an exact capture request."""

    def __call__(
        self,
        request: StableSnapshotCaptureRequestV1,
    ) -> StableSnapshotReader: ...


@runtime_checkable
class TargetTrafficReader(Protocol):
    """Verifier-owned fixed-target state read with no list or mutation surface."""

    @property
    def target(self) -> TargetBinding: ...

    @property
    def service_role(self) -> ServiceRole: ...

    @property
    def reader_identity(self) -> str: ...

    async def read_target(self) -> CloudRunTargetState: ...


class TargetTrafficReaderFactory(Protocol):
    """Create one configured reader for an exact target traffic request."""

    def __call__(self, request: TargetTrafficReadRequestV1) -> TargetTrafficReader: ...


@runtime_checkable
class ExecutionReceiptObservationStore(Protocol):
    """Narrow target-bound receipt read used by the coordinator."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...


class StableSnapshotCaptureService:
    """Run one two-read stable capture under the verifier identity."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authentication_policy: RouteAuthenticationPolicy,
        reader_factory: StableSnapshotReaderFactory,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not _target_is_exact(target):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            )
        try:
            capture_configuration = StableSnapshotCaptureConfiguration(
                target=target,
                reader_identity=(
                    f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"
                ),
            )
        except (TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            ) from None
        if (
            type(target) is not TargetBinding
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.VERIFIER
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or authentication_policy.project_id != target.project_id
            or authentication_policy.path != protected_path(ServiceRole.VERIFIER)
            or not callable(reader_factory)
            or (clock is not None and not callable(clock))
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            )
        self._target = target
        self._authentication_policy = authentication_policy
        self._reader_factory = reader_factory
        self._clock = clock
        self._capture_configuration = capture_configuration

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def capture(
        self,
        request: StableSnapshotCaptureRequestV1,
        caller: AuthenticationContext,
    ) -> StableSnapshotCaptureResultV1:
        """Return only a configured-target snapshot after two matching reads."""

        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.COORDINATOR,
        ):
            raise OperatorObservationError(OperatorObservationErrorCode.CALLER_DENIED)
        if type(request) is not StableSnapshotCaptureRequestV1:
            raise OperatorObservationError(OperatorObservationErrorCode.COMMAND_DENIED)
        if request.target != self._target:
            raise OperatorObservationError(OperatorObservationErrorCode.TARGET_DENIED)
        try:
            reader = self._reader_factory(request)
            snapshot = await StableSnapshotCapturer(
                reader=reader,
                configuration=self._capture_configuration,
                clock=self._clock,
            ).capture()
            return StableSnapshotCaptureResultV1(
                schema_version=STABLE_SNAPSHOT_CAPTURE_RESULT_V1,
                request=request,
                request_sha256=canonical_sha256(request),
                snapshot=snapshot,
            )
        except asyncio.CancelledError:
            raise
        except StableCaptureError:
            raise OperatorObservationError(
                OperatorObservationErrorCode.CAPTURE_DENIED
            ) from None
        except OperatorObservationError:
            raise
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.CAPTURE_DENIED
            ) from None


class TargetTrafficObservationService:
    """Return one fresh verifier-owned observation of the fixed revision pair."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authentication_policy: RouteAuthenticationPolicy,
        reader_factory: TargetTrafficReaderFactory,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not _target_is_exact(target)
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.VERIFIER
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or authentication_policy.project_id != target.project_id
            or authentication_policy.path != protected_path(ServiceRole.VERIFIER)
            or not callable(reader_factory)
            or (clock is not None and not callable(clock))
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            )
        self._target = target
        self._authentication_policy = authentication_policy
        self._reader_factory = reader_factory
        self._clock = clock or _system_utc_second

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def observe(
        self,
        request: TargetTrafficReadRequestV1,
        caller: AuthenticationContext,
    ) -> TargetTrafficReadResultV1:
        """Read and classify only baseline, canary, or promoted target traffic."""

        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.COORDINATOR,
        ):
            raise OperatorObservationError(OperatorObservationErrorCode.CALLER_DENIED)
        if type(request) is not TargetTrafficReadRequestV1:
            raise OperatorObservationError(OperatorObservationErrorCode.COMMAND_DENIED)
        if request.target != self._target:
            raise OperatorObservationError(OperatorObservationErrorCode.TARGET_DENIED)
        try:
            reader = self._reader_factory(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.TARGET_STATE_DENIED
            ) from None
        expected_reader = (
            f"controlgraph-verifier@{self._target.project_id}.iam.gserviceaccount.com"
        )
        if (
            not isinstance(reader, TargetTrafficReader)
            or reader.target != self._target
            or reader.service_role is not ServiceRole.VERIFIER
            or reader.reader_identity != expected_reader
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.TARGET_STATE_DENIED
            )
        try:
            state = await reader.read_target()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.TARGET_STATE_DENIED
            ) from None
        if type(state) is not CloudRunTargetState:
            raise OperatorObservationError(
                OperatorObservationErrorCode.TARGET_STATE_DENIED
            )
        try:
            return _target_traffic_result(request, state, expected_reader, self._clock)
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.TARGET_STATE_DENIED
            ) from None


class CoordinatorStableSnapshotClient:
    """Call only the verifier route for the coordinator-selected target."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            not _target_is_exact(target)
            or type(route) is not CoordinatorInternalRoute
            or route.project_id != target.project_id
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.VERIFIER
            or route.path != protected_path(ServiceRole.VERIFIER)
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            )
        self._target = target
        self._route = route
        self._transport = transport

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def capture(
        self,
        command: StableSnapshotCaptureCommandV1,
    ) -> StableSnapshotCaptureResultV1:
        """Return an exact verifier response bound to the operator request identity."""

        if type(command) is not StableSnapshotCaptureCommandV1:
            raise OperatorObservationError(OperatorObservationErrorCode.COMMAND_DENIED)
        request = StableSnapshotCaptureRequestV1(
            schema_version=STABLE_SNAPSHOT_CAPTURE_REQUEST_V1,
            request_id=command.request_id,
            target=self._target,
        )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.TRANSPORT_UNAVAILABLE
            ) from None
        try:
            result = decode_contract(body, StableSnapshotCaptureResultV1)
        except (ContractError, TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            ) from None
        if result.request != request or result.request_sha256 != canonical_sha256(request):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            )
        return result

class CoordinatorTargetTrafficClient:
    """Call only the verifier for the fixed target and revision pair."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        stable_revision: str,
        candidate_revision: str,
        concurrency: int,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
    ) -> None:
        try:
            probe = TargetTrafficReadRequestV1(
                schema_version=TARGET_TRAFFIC_READ_REQUEST_V1,
                request_id="configuration-probe",
                target=target,
                stable_revision=stable_revision,
                candidate_revision=candidate_revision,
                concurrency=concurrency,
            )
        except (TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            ) from None
        if (
            type(route) is not CoordinatorInternalRoute
            or route.project_id != target.project_id
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.VERIFIER
            or route.path != protected_path(ServiceRole.VERIFIER)
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            )
        self._target = target
        self._stable_revision = probe.stable_revision
        self._candidate_revision = probe.candidate_revision
        self._concurrency = probe.concurrency
        self._route = route
        self._transport = transport

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def observe(
        self,
        command: TargetTrafficReadCommandV1,
    ) -> TargetTrafficReadResultV1:
        """Return one canonical verifier read bound to the command identity."""

        if type(command) is not TargetTrafficReadCommandV1:
            raise OperatorObservationError(OperatorObservationErrorCode.COMMAND_DENIED)
        request = TargetTrafficReadRequestV1(
            schema_version=TARGET_TRAFFIC_READ_REQUEST_V1,
            request_id=command.request_id,
            target=self._target,
            stable_revision=self._stable_revision,
            candidate_revision=self._candidate_revision,
            concurrency=self._concurrency,
        )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.TRANSPORT_UNAVAILABLE
            ) from None
        try:
            result = decode_contract(body, TargetTrafficReadResultV1)
            _require_target_traffic_result(result, request)
        except (ContractError, TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            ) from None
        return result


class ApiOperatorObservationClient:
    """Forward authenticated read commands only to the fixed coordinator."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        authentication_policy: RouteAuthenticationPolicy,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.API
            or route.service_role is not ServiceRole.COORDINATOR
            or route.path != protected_path(ServiceRole.COORDINATOR)
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.API
            or authentication_policy.caller.role is not CallerRole.OPERATOR
            or authentication_policy.path != protected_path(ServiceRole.API)
            or authentication_policy.project_id != route.project_id
            or authentication_policy.project_number != route.project_number
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            )
        self._route = route
        self._authentication_policy = authentication_policy
        self._transport = transport

    async def capture_snapshot(
        self,
        command: StableSnapshotCaptureCommandV1,
        principal: AuthenticationContext,
    ) -> StableSnapshotCaptureResultV1:
        """Return one exact snapshot response for an authenticated operator."""

        if type(command) is not StableSnapshotCaptureCommandV1:
            raise OperatorObservationError(OperatorObservationErrorCode.COMMAND_DENIED)
        invocation = self._snapshot_invocation(command, principal)
        body = await self._post(invocation)
        try:
            result = decode_contract(body, StableSnapshotCaptureResultV1)
        except (ContractError, TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            ) from None
        if (
            result.request.request_id != command.request_id
            or result.request.target.project_id != self._route.project_id
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            )
        return result

    async def read_receipt(
        self,
        command: ExecutionReceiptReadCommandV1,
        principal: AuthenticationContext,
    ) -> ExecutionReceiptReadResultV1:
        """Return one exact receipt response for an authenticated operator."""

        if type(command) is not ExecutionReceiptReadCommandV1:
            raise OperatorObservationError(OperatorObservationErrorCode.COMMAND_DENIED)
        invocation = self._receipt_invocation(command, principal)
        body = await self._post(invocation)
        try:
            result = decode_contract(body, ExecutionReceiptReadResultV1)
        except (ContractError, TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            ) from None
        if (
            result.command != command
            or result.command_sha256 != canonical_sha256(command)
            or result.receipt.target.project_id != self._route.project_id
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            )
        return result

    async def read_target_traffic(
        self,
        command: TargetTrafficReadCommandV1,
        principal: AuthenticationContext,
    ) -> TargetTrafficReadResultV1:
        """Return one exact verifier traffic observation for the operator."""

        if type(command) is not TargetTrafficReadCommandV1:
            raise OperatorObservationError(OperatorObservationErrorCode.COMMAND_DENIED)
        invocation = self._traffic_invocation(command, principal)
        body = await self._post(invocation)
        try:
            result = decode_contract(body, TargetTrafficReadResultV1)
            if (
                result.request.request_id != command.request_id
                or result.request.target.project_id != self._route.project_id
            ):
                raise ValueError("traffic response is not bound to the API route")
            _require_target_traffic_result(result, result.request)
        except (ContractError, TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            ) from None
        return result

    def _snapshot_invocation(
        self,
        command: StableSnapshotCaptureCommandV1,
        principal: AuthenticationContext,
    ) -> StableSnapshotCaptureInvocationV1:
        self._require_operator(principal)
        try:
            return StableSnapshotCaptureInvocationV1(
                schema_version=STABLE_SNAPSHOT_CAPTURE_INVOCATION_V1,
                command=command,
                operator_identity=principal.email,
                operator_subject=principal.subject,
                operator_issuer=cast(
                    Literal["accounts.google.com", "https://accounts.google.com"],
                    principal.issuer,
                ),
                operator_audience=principal.audience,
                operator_issued_at=principal.issued_at,
                operator_expires_at=principal.expires_at,
            )
        except (TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.OPERATOR_DENIED
            ) from None

    def _receipt_invocation(
        self,
        command: ExecutionReceiptReadCommandV1,
        principal: AuthenticationContext,
    ) -> ExecutionReceiptReadInvocationV1:
        self._require_operator(principal)
        try:
            return ExecutionReceiptReadInvocationV1(
                schema_version=EXECUTION_RECEIPT_READ_INVOCATION_V1,
                command=command,
                operator_identity=principal.email,
                operator_subject=principal.subject,
                operator_issuer=cast(
                    Literal["accounts.google.com", "https://accounts.google.com"],
                    principal.issuer,
                ),
                operator_audience=principal.audience,
                operator_issued_at=principal.issued_at,
                operator_expires_at=principal.expires_at,
            )
        except (TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.OPERATOR_DENIED
            ) from None

    def _traffic_invocation(
        self,
        command: TargetTrafficReadCommandV1,
        principal: AuthenticationContext,
    ) -> TargetTrafficReadInvocationV1:
        self._require_operator(principal)
        try:
            return TargetTrafficReadInvocationV1(
                schema_version=TARGET_TRAFFIC_READ_INVOCATION_V1,
                command=command,
                operator_identity=principal.email,
                operator_subject=principal.subject,
                operator_issuer=cast(
                    Literal["accounts.google.com", "https://accounts.google.com"],
                    principal.issuer,
                ),
                operator_audience=principal.audience,
                operator_issued_at=principal.issued_at,
                operator_expires_at=principal.expires_at,
            )
        except (TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.OPERATOR_DENIED
            ) from None

    def _require_operator(self, principal: AuthenticationContext) -> None:
        if not _context_matches_policy(
            principal,
            self._authentication_policy,
            role=CallerRole.OPERATOR,
        ):
            raise OperatorObservationError(OperatorObservationErrorCode.OPERATOR_DENIED)

    async def _post(
        self,
        invocation: StableSnapshotCaptureInvocationV1
        | ExecutionReceiptReadInvocationV1
        | TargetTrafficReadInvocationV1,
    ) -> bytes:
        try:
            return await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.TRANSPORT_UNAVAILABLE
            ) from None


class CoordinatorOperatorObservationRelay:
    """Authorize API-propagated operators and expose only bounded observations."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        snapshot_client: CoordinatorStableSnapshotClient,
        traffic_client: CoordinatorTargetTrafficClient,
        receipt_store: ExecutionReceiptObservationStore,
    ) -> None:
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.COORDINATOR
            or authentication_policy.caller.role is not CallerRole.API
            or authentication_policy.path != protected_path(ServiceRole.COORDINATOR)
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.path != protected_path(ServiceRole.API)
            or operator_policy.project_id != authentication_policy.project_id
            or operator_policy.project_number != authentication_policy.project_number
            or type(snapshot_client) is not CoordinatorStableSnapshotClient
            or type(traffic_client) is not CoordinatorTargetTrafficClient
            or not isinstance(receipt_store, ExecutionReceiptObservationStore)
            or not _target_is_exact(receipt_store.target)
            or snapshot_client.target != receipt_store.target
            or traffic_client.target != receipt_store.target
            or snapshot_client.target.project_id != authentication_policy.project_id
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.CONFIGURATION_INVALID
            )
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._snapshot_client = snapshot_client
        self._traffic_client = traffic_client
        self._receipt_store = receipt_store
        self._target = snapshot_client.target

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def capture_snapshot(
        self,
        invocation: StableSnapshotCaptureInvocationV1,
        caller: AuthenticationContext,
    ) -> StableSnapshotCaptureResultV1:
        """Capture only after verifying the API caller and propagated operator."""

        self._authorize(invocation, caller)
        try:
            result = await self._snapshot_client.capture(invocation.command)
        except asyncio.CancelledError:
            raise
        except OperatorObservationError:
            raise
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.CAPTURE_DENIED
            ) from None
        if result.request.target != self._target:
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            )
        return result

    async def read_receipt(
        self,
        invocation: ExecutionReceiptReadInvocationV1,
        caller: AuthenticationContext,
    ) -> ExecutionReceiptReadResultV1:
        """Read exactly one receipt and collapse absence or mismatch to one denial."""

        self._authorize(invocation, caller)
        command = invocation.command
        try:
            stored = await self._receipt_store.read_receipt(command.idempotency_key)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise OperatorObservationError(
                OperatorObservationErrorCode.STORE_UNAVAILABLE
            ) from None
        except AuthorityStoreError:
            raise OperatorObservationError(
                OperatorObservationErrorCode.STORE_UNAVAILABLE
            ) from None
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.STORE_UNAVAILABLE
            ) from None
        if (
            type(stored) is not StoredRecord
            or type(stored.value) is not ExecutionReceipt
            or not _receipt_matches_command(stored.value, command, self._target)
        ):
            raise OperatorObservationError(
                OperatorObservationErrorCode.RECEIPT_NOT_FOUND
            )
        receipt = stored.value
        try:
            receipt_sha256 = canonical_sha256(receipt)
            locator = _verified_apply_locator(
                receipt,
                stored.revision,
                receipt_sha256,
            )
            return ExecutionReceiptReadResultV1(
                schema_version=EXECUTION_RECEIPT_READ_RESULT_V1,
                command=command,
                command_sha256=canonical_sha256(command),
                receipt=receipt,
                storage_revision=stored.revision,
                receipt_sha256=receipt_sha256,
                verified_apply_receipt=locator,
            )
        except (ContractError, TypeError, ValueError):
            raise OperatorObservationError(
                OperatorObservationErrorCode.STORE_UNAVAILABLE
            ) from None

    async def read_target_traffic(
        self,
        invocation: TargetTrafficReadInvocationV1,
        caller: AuthenticationContext,
    ) -> TargetTrafficReadResultV1:
        """Return only the fixed verifier-owned traffic observation."""

        self._authorize(invocation, caller)
        try:
            result = await self._traffic_client.observe(invocation.command)
        except asyncio.CancelledError:
            raise
        except OperatorObservationError:
            raise
        except Exception:
            raise OperatorObservationError(
                OperatorObservationErrorCode.TARGET_STATE_DENIED
            ) from None
        if result.request.target != self._target:
            raise OperatorObservationError(
                OperatorObservationErrorCode.RESPONSE_INVALID
            )
        return result

    def _authorize(
        self,
        invocation: StableSnapshotCaptureInvocationV1
        | ExecutionReceiptReadInvocationV1
        | TargetTrafficReadInvocationV1,
        caller: AuthenticationContext,
    ) -> None:
        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise OperatorObservationError(OperatorObservationErrorCode.CALLER_DENIED)
        if type(invocation) not in {
            StableSnapshotCaptureInvocationV1,
            ExecutionReceiptReadInvocationV1,
            TargetTrafficReadInvocationV1,
        }:
            raise OperatorObservationError(OperatorObservationErrorCode.COMMAND_DENIED)
        expected = self._operator_policy.caller
        if (
            invocation.operator_identity != expected.email
            or invocation.operator_subject != expected.subject
            or invocation.operator_issuer
            not in {"accounts.google.com", "https://accounts.google.com"}
            or invocation.operator_audience != self._operator_policy.audience
        ):
            raise OperatorObservationError(OperatorObservationErrorCode.OPERATOR_DENIED)


def _receipt_matches_command(
    receipt: ExecutionReceipt,
    command: ExecutionReceiptReadCommandV1,
    target: TargetBinding,
) -> bool:
    return (
        receipt.target == target
        and receipt.root_id == command.root_id
        and receipt.root_sha256 == command.expected_root_sha256
        and receipt.epoch == command.expected_epoch
        and receipt.action is command.action
        and receipt.request_id == command.request_id
        and receipt.idempotency_key == command.idempotency_key
        and receipt.capability_sha256 == command.capability_sha256
        and receipt.receipt_id
        == execution_receipt_logical_id(target, command.idempotency_key)
    )


def _verified_apply_locator(
    receipt: ExecutionReceipt,
    storage_revision: int,
    receipt_sha256: str,
) -> VerifiedApplyReceiptLocatorV1 | None:
    if not (
        receipt.action is CapabilityAction.APPLY_CANARY
        and receipt.outcome is ReceiptOutcome.VERIFIED
        and receipt.provider_operation is not None
        and storage_revision >= 2
    ):
        return None
    return VerifiedApplyReceiptLocatorV1(
        schema_version=VERIFIED_APPLY_RECEIPT_LOCATOR_V1,
        receipt_id=receipt.receipt_id,
        request_id=receipt.request_id,
        idempotency_key=receipt.idempotency_key,
        capability_sha256=receipt.capability_sha256,
        mutation_sha256=receipt.mutation_sha256,
        expected_poststate_sha256=receipt.expected_poststate_sha256,
        provider_operation=receipt.provider_operation,
        receipt_sha256=receipt_sha256,
    )


def _target_traffic_result(
    request: TargetTrafficReadRequestV1,
    state: CloudRunTargetState,
    reader_identity: str,
    clock: Callable[[], datetime],
) -> TargetTrafficReadResultV1:
    service = state.service
    stable = state.stable_revision
    candidate = state.candidate_revision
    if (
        service.target != request.target
        or stable.target != request.target
        or candidate.target != request.target
        or service.reconciling
        or service.ready_state is not CloudRunReadyState.READY
        or service.generation != service.observed_generation
        or service.template_revision != request.candidate_revision
        or service.latest_created_revision != request.candidate_revision
        or service.latest_ready_revision != request.candidate_revision
        or service.template_concurrency != request.concurrency
        or stable.revision != request.stable_revision
        or candidate.revision != request.candidate_revision
        or stable.reconciling
        or candidate.reconciling
        or stable.ready_state is not CloudRunReadyState.READY
        or candidate.ready_state is not CloudRunReadyState.READY
        or stable.generation != stable.observed_generation
        or candidate.generation != candidate.observed_generation
        or stable.concurrency != request.concurrency
        or candidate.concurrency != request.concurrency
    ):
        raise ValueError("target traffic provider state is not exact")
    traffic = tuple(
        TrafficAllocation(revision=item.revision, percent=item.percent)
        for item in service.traffic
    )
    statuses = tuple(
        TrafficAllocation(revision=item.revision, percent=item.percent)
        for item in service.traffic_statuses
    )
    if traffic != statuses:
        raise ValueError("target traffic and status do not agree")
    traffic_map = {item.revision: item.percent for item in traffic}
    if len(traffic_map) != len(traffic):
        raise ValueError("target traffic contains a duplicate revision")
    allowed = {request.stable_revision, request.candidate_revision}
    if not set(traffic_map).issubset(allowed):
        raise ValueError("target traffic contains an undeclared revision")
    stable_percent = traffic_map.get(request.stable_revision, 0)
    candidate_percent = traffic_map.get(request.candidate_revision, 0)
    if (stable_percent, candidate_percent) not in {(100, 0), (90, 10), (0, 100)}:
        raise ValueError("target traffic is outside the supported rollout states")
    projection = TargetConfigurationProjection(
        target=request.target,
        stable_revision=request.stable_revision,
        candidate_revision=request.candidate_revision,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=request.concurrency,
    )
    observed_at = _utc_second_text(clock())
    return TargetTrafficReadResultV1(
        schema_version=TARGET_TRAFFIC_READ_RESULT_V1,
        request=request,
        request_sha256=canonical_sha256(request),
        traffic=traffic,
        traffic_statuses=statuses,
        service_generation=service.generation,
        provider_etag=service.etag,
        concurrency=request.concurrency,
        stable_revision_configuration_sha256=(
            cloud_run_revision_configuration_sha256(stable.configuration)
        ),
        candidate_revision_configuration_sha256=(
            cloud_run_revision_configuration_sha256(candidate.configuration)
        ),
        target_configuration_sha256=target_configuration_projection_sha256(
            projection
        ),
        observed_by=reader_identity,
        observed_at=observed_at,
    )


def _require_target_traffic_result(
    result: TargetTrafficReadResultV1,
    request: TargetTrafficReadRequestV1,
) -> None:
    if result.request != request or result.request_sha256 != canonical_sha256(request):
        raise ValueError("target traffic response request binding is invalid")
    traffic = {item.revision: item.percent for item in result.traffic}
    projection = TargetConfigurationProjection(
        target=request.target,
        stable_revision=request.stable_revision,
        candidate_revision=request.candidate_revision,
        stable_percent=traffic.get(request.stable_revision, 0),
        candidate_percent=traffic.get(request.candidate_revision, 0),
        concurrency=request.concurrency,
    )
    if (
        result.target_configuration_sha256
        != target_configuration_projection_sha256(projection)
    ):
        raise ValueError("target traffic response digest is invalid")


def _target_is_exact(target: object) -> bool:
    return (
        type(target) is TargetBinding
        and _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is not None
        and "reconcile" not in target.project_id.lower()
        and target.region == "us-central1"
        and target.environment == "nonprod"
        and target.service_name == "controlgraph-reference-target"
    )


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _utc_second_text(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError("observation clock is invalid")
    normalized = value.astimezone(UTC).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _context_matches_policy(
    context: object,
    policy: RouteAuthenticationPolicy,
    *,
    role: CallerRole,
) -> bool:
    return (
        type(context) is AuthenticationContext
        and context.role is role
        and context.role is policy.caller.role
        and context.email == policy.caller.email
        and context.subject == policy.caller.subject
        and context.issuer in {"accounts.google.com", "https://accounts.google.com"}
        and context.audience == policy.audience
        and type(context.issued_at) is int
        and type(context.expires_at) is int
        and context.issued_at < context.expires_at
        and context.expires_at - context.issued_at <= 3_660
    )


__all__ = [
    "ApiOperatorObservationClient",
    "CoordinatorOperatorObservationRelay",
    "CoordinatorStableSnapshotClient",
    "CoordinatorTargetTrafficClient",
    "ExecutionReceiptObservationStore",
    "OperatorObservationError",
    "OperatorObservationErrorCode",
    "StableSnapshotCaptureService",
    "StableSnapshotReaderFactory",
    "TargetTrafficObservationService",
    "TargetTrafficReader",
    "TargetTrafficReaderFactory",
]
