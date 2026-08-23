"""Deterministic boundary around read-only model assistance."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Protocol, cast, runtime_checkable

from pydantic import ValidationError

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
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.model_assistance import (
    ADVISOR_DISPOSITION_INVOCATION_V1,
    ADVISOR_INTERACTION_AUDIT_V1,
    ADVISOR_OPERATOR_INVOCATION_V1,
    ADVISOR_OPERATOR_RESULT_V1,
    ADVISOR_RESPONSE_V1,
    ADVISOR_TOOL_CALL_AUDIT_V1,
    ADVISOR_VALIDATION_V1,
    DIAGNOSTIC_TOOL_INPUT_V1,
    DIAGNOSTIC_TOOL_RESULT_V1,
    MAX_TOOL_CALLS,
    MODEL_ASSISTANCE_TIMELINE_AUDIT_V1,
    AdvisorDispositionCommandV1,
    AdvisorDispositionInvocationV1,
    AdvisorDispositionResultV1,
    AdvisorFallbackCode,
    AdvisorInteractionAuditV1,
    AdvisorInvocationRequestV1,
    AdvisorOperatorCommandV1,
    AdvisorOperatorInvocationV1,
    AdvisorOperatorResultV1,
    AdvisorRecommendationV1,
    AdvisorResponseV1,
    AdvisorToolCallAuditV1,
    AdvisorValidationV1,
    AdvisoryHealth,
    DiagnosticEvidenceKind,
    DiagnosticEvidenceSummaryV1,
    DiagnosticRegistryV1,
    DiagnosticToolId,
    DiagnosticToolInputV1,
    DiagnosticToolResultV1,
    EvidenceConsistency,
    ModelAssistanceActorRole,
    ModelAssistanceLifecycle,
    ModelAssistanceTimelineAuditV1,
    OperatorDisposition,
    RecommendationValidationCode,
    RequestedOperatorAction,
    RolloutPhase,
    ToolCallStatus,
    diagnostic_model_context,
    diagnostic_registry_v1,
)


class AdvisorModelFailureCode(StrEnum):
    """Sanitized failures reported by a model integration."""

    QUOTA = "quota"
    MALFORMED_OUTPUT = "malformed_output"
    MODEL_UNAVAILABLE = "model_unavailable"
    TOOL_ERROR = "tool_error"


class AdvisorModelFailure(RuntimeError):
    """A model boundary failure that retains no provider content."""

    def __init__(self, code: AdvisorModelFailureCode) -> None:
        if type(code) is not AdvisorModelFailureCode:
            raise TypeError("an exact advisor model failure code is required")
        self.code = code
        super().__init__(code.value)


class DiagnosticToolError(RuntimeError):
    """A sanitized denial from the invocation-bound registry."""


@runtime_checkable
class VerifiedDiagnosticEvidenceReader(Protocol):
    """Read one coordinator-verified, invocation-bound M6 evidence summary."""

    async def read_verified(
        self,
        request: AdvisorInvocationRequestV1,
        evidence_kind: DiagnosticEvidenceKind,
    ) -> DiagnosticEvidenceSummaryV1: ...


class SnapshotDiagnosticEvidenceReader:
    """Expose only the summaries already assembled by the authenticated coordinator."""

    async def read_verified(
        self,
        request: AdvisorInvocationRequestV1,
        evidence_kind: DiagnosticEvidenceKind,
    ) -> DiagnosticEvidenceSummaryV1:
        if type(request) is not AdvisorInvocationRequestV1:
            raise DiagnosticToolError("diagnostic request is invalid")
        return {
            summary.evidence_kind: summary
            for summary in request.snapshot.evidence_summaries
        }[evidence_kind]


@runtime_checkable
class AdvisorModel(Protocol):
    """Optional model integration allowed to consume only registered tools."""

    @property
    def model_id(self) -> Literal["gemini-3.5-flash"]: ...

    @property
    def model_location(self) -> Literal["global"]: ...

    @property
    def prompt_version(self) -> Literal["controlgraph.rollout-advisor-prompt/v1"]: ...

    async def recommend(
        self,
        request: AdvisorInvocationRequestV1,
        tools: InvocationDiagnosticRegistry,
    ) -> AdvisorRecommendationV1: ...


@dataclass(frozen=True, slots=True)
class _EvidenceIndexEntry:
    kind: DiagnosticEvidenceKind
    source_sha256: str


class InvocationDiagnosticRegistry:
    """Serve only durable, signature-verified M6 evidence through fixed tools."""

    def __init__(
        self,
        request: AdvisorInvocationRequestV1,
        *,
        evidence_reader: VerifiedDiagnosticEvidenceReader,
        registry: DiagnosticRegistryV1 | None = None,
    ) -> None:
        if type(request) is not AdvisorInvocationRequestV1:
            raise TypeError("an exact advisor request is required")
        selected_registry = registry or diagnostic_registry_v1()
        if (
            selected_registry != diagnostic_registry_v1()
            or not isinstance(evidence_reader, VerifiedDiagnosticEvidenceReader)
        ):
            raise ValueError("diagnostic registry must match the fixed allowlist")
        self._request = request
        self._evidence_reader = evidence_reader
        self._registry = selected_registry
        self._calls: list[AdvisorToolCallAuditV1] = []
        self._called_tools: set[DiagnosticToolId] = set()

    @property
    def registry(self) -> DiagnosticRegistryV1:
        return self._registry

    @property
    def calls(self) -> tuple[AdvisorToolCallAuditV1, ...]:
        return tuple(self._calls)

    async def read(
        self,
        tool_id: DiagnosticToolId,
        snapshot_sha256: str,
    ) -> dict[str, object]:
        """Return one redacted summary after exact scope and call-budget checks."""

        definition = next(
            (item for item in self._registry.tools if item.tool_id is tool_id),
            None,
        )
        if definition is None:
            raise DiagnosticToolError("diagnostic tool is not registered")
        input_sha256 = _untrusted_tool_input_sha256(snapshot_sha256)
        try:
            tool_input = DiagnosticToolInputV1(
                schema_version=DIAGNOSTIC_TOOL_INPUT_V1,
                snapshot_sha256=snapshot_sha256,
            )
            input_sha256 = canonical_sha256(tool_input)
            if (
                tool_input.snapshot_sha256 != self._request.snapshot_sha256
                or tool_id in self._called_tools
                or len(self._calls) >= MAX_TOOL_CALLS
            ):
                raise DiagnosticToolError("diagnostic tool call is outside its scope")
            summary = await self._evidence_reader.read_verified(
                self._request,
                definition.evidence_source,
            )
            if (
                type(summary) is not DiagnosticEvidenceSummaryV1
                or summary != _summary_for_tool(self._request, tool_id)
            ):
                raise DiagnosticToolError("diagnostic evidence binding is invalid")
            result = DiagnosticToolResultV1(
                schema_version=DIAGNOSTIC_TOOL_RESULT_V1,
                tool_id=tool_id,
                snapshot_sha256=self._request.snapshot_sha256,
                evidence=summary,
                context=diagnostic_model_context(self._request.snapshot),
            )
            body = canonical_json_bytes(result)
            if len(body) > definition.max_response_bytes:
                raise DiagnosticToolError("diagnostic tool result exceeds its bound")
        except asyncio.CancelledError:
            raise
        except (DiagnosticToolError, TypeError, ValueError, ValidationError):
            self._record_call(
                tool_id=tool_id,
                input_sha256=input_sha256,
                output_sha256=None,
                status=ToolCallStatus.DENIED,
            )
            raise DiagnosticToolError("diagnostic tool call denied") from None
        except Exception:
            self._record_call(
                tool_id=tool_id,
                input_sha256=input_sha256,
                output_sha256=None,
                status=ToolCallStatus.FAILED,
            )
            raise DiagnosticToolError("diagnostic tool call failed") from None
        self._called_tools.add(tool_id)
        self._record_call(
            tool_id=tool_id,
            input_sha256=input_sha256,
            output_sha256=canonical_sha256(result),
            status=ToolCallStatus.SUCCEEDED,
        )
        return result.model_dump(mode="json")

    async def read_root_summary(self, snapshot_sha256: str) -> dict[str, object]:
        """Read the invocation-bound redacted root summary."""

        return await self.read(DiagnosticToolId.READ_ROOT_SUMMARY, snapshot_sha256)

    async def read_target_summary(self, snapshot_sha256: str) -> dict[str, object]:
        """Read the invocation-bound redacted target summary."""

        return await self.read(DiagnosticToolId.READ_TARGET_SUMMARY, snapshot_sha256)

    async def read_health_summary(self, snapshot_sha256: str) -> dict[str, object]:
        """Read the invocation-bound redacted health summary."""

        return await self.read(DiagnosticToolId.READ_HEALTH_SUMMARY, snapshot_sha256)

    async def read_receipt_summary(self, snapshot_sha256: str) -> dict[str, object]:
        """Read the invocation-bound redacted receipt summary."""

        return await self.read(DiagnosticToolId.READ_RECEIPT_SUMMARY, snapshot_sha256)

    async def read_timeline_summary(self, snapshot_sha256: str) -> dict[str, object]:
        """Read the invocation-bound redacted timeline summary."""

        return await self.read(DiagnosticToolId.READ_TIMELINE_SUMMARY, snapshot_sha256)

    async def read_verifier_summary(self, snapshot_sha256: str) -> dict[str, object]:
        """Read the invocation-bound redacted verifier summary."""

        return await self.read(DiagnosticToolId.READ_VERIFIER_SUMMARY, snapshot_sha256)

    def _record_call(
        self,
        *,
        tool_id: DiagnosticToolId,
        input_sha256: str,
        output_sha256: str | None,
        status: ToolCallStatus,
    ) -> None:
        if len(self._calls) >= MAX_TOOL_CALLS:
            return
        self._calls.append(
            AdvisorToolCallAuditV1(
                schema_version=ADVISOR_TOOL_CALL_AUDIT_V1,
                sequence=len(self._calls) + 1,
                tool_id=tool_id,
                input_sha256=input_sha256,
                output_sha256=output_sha256,
                status=status,
            )
        )


class ReadOnlyAdvisorService:
    """Invoke the optional model and retain deterministic proposal authority."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        model: AdvisorModel,
        evidence_reader: VerifiedDiagnosticEvidenceReader | None = None,
        timeout_seconds: float = 20.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.ADVISOR
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or authentication_policy.path != protected_path(ServiceRole.ADVISOR)
            or not isinstance(model, AdvisorModel)
            or (
                evidence_reader is not None
                and not isinstance(evidence_reader, VerifiedDiagnosticEvidenceReader)
            )
            or type(timeout_seconds) not in {int, float}
            or not 0.01 <= float(timeout_seconds) <= 30
            or (clock is not None and not callable(clock))
        ):
            raise ValueError("advisor service configuration is invalid")
        self._policy = authentication_policy
        self._model = model
        self._evidence_reader = evidence_reader or SnapshotDiagnosticEvidenceReader()
        self._timeout_seconds = float(timeout_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))

    async def advise(
        self,
        request: AdvisorInvocationRequestV1,
        caller: AuthenticationContext,
    ) -> AdvisorResponseV1:
        """Return a validated recommendation or a side-effect-free fallback."""

        if (
            type(request) is not AdvisorInvocationRequestV1
            or not _caller_matches_policy(caller, self._policy)
            or request.snapshot.target.project_id != self._policy.project_id
        ):
            raise ValueError("advisor request is outside its authenticated scope")
        registry = InvocationDiagnosticRegistry(
            request,
            evidence_reader=self._evidence_reader,
        )
        recommendation: AdvisorRecommendationV1 | None = None
        candidate: AdvisorRecommendationV1 | None = None
        fallback: AdvisorFallbackCode | None = None
        validation: AdvisorValidationV1
        try:
            async with asyncio.timeout(self._timeout_seconds):
                candidate = await self._model.recommend(request, registry)
            if type(candidate) is not AdvisorRecommendationV1:
                raise AdvisorModelFailure(AdvisorModelFailureCode.MALFORMED_OUTPUT)
            try:
                candidate = AdvisorRecommendationV1.model_validate(candidate)
            except (TypeError, ValueError, ValidationError):
                raise AdvisorModelFailure(
                    AdvisorModelFailureCode.MALFORMED_OUTPUT
                ) from None
            recommendation = candidate
            validation = validate_recommendation(
                request,
                recommendation,
                tool_calls=registry.calls,
                now=self._clock(),
            )
            if not validation.accepted:
                fallback = AdvisorFallbackCode.UNSAFE_RECOMMENDATION
                recommendation = None
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            fallback = AdvisorFallbackCode.TIMEOUT
            validation = _failed_validation(
                RecommendationValidationCode.MODEL_RESPONSE_INVALID
            )
        except AdvisorModelFailure as error:
            fallback = AdvisorFallbackCode(error.code.value)
            validation = _failed_validation(
                RecommendationValidationCode.TOOL_CALL_INVALID
                if error.code is AdvisorModelFailureCode.TOOL_ERROR
                else RecommendationValidationCode.MODEL_RESPONSE_INVALID
            )
        except Exception:
            fallback = AdvisorFallbackCode.MODEL_UNAVAILABLE
            validation = _failed_validation(
                RecommendationValidationCode.MODEL_RESPONSE_INVALID
            )

        candidate_digest = _valid_candidate_digest(candidate)
        citations = (
            _cited_evidence_ids(candidate)
            if type(candidate) is AdvisorRecommendationV1
            else ()
        )
        request_sha256 = canonical_sha256(request)
        audit = AdvisorInteractionAuditV1(
            schema_version=ADVISOR_INTERACTION_AUDIT_V1,
            interaction_id=_interaction_id(request_sha256),
            correlation_id=request.correlation_id,
            model_id=self._model.model_id,
            model_location=self._model.model_location,
            prompt_version=self._model.prompt_version,
            registry_sha256=canonical_sha256(registry.registry),
            snapshot_sha256=request.snapshot_sha256,
            tool_calls=registry.calls,
            cited_evidence_ids=citations,
            structured_output_sha256=candidate_digest,
            validation=validation,
            operator_disposition=OperatorDisposition.PENDING_REVIEW,
            fallback_code=fallback,
        )
        return AdvisorResponseV1(
            schema_version=ADVISOR_RESPONSE_V1,
            request_sha256=request_sha256,
            recommendation=recommendation,
            audit=audit,
            manual_next_step=(
                "review_named_evidence_and_use_deterministic_operator_commands_only"
            ),
        )


class CoordinatorAdvisorClient:
    """Call only the advisor's fixed read-only route and validate its binding."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.ADVISOR
            or route.path != protected_path(ServiceRole.ADVISOR)
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise ValueError("coordinator advisor client configuration is invalid")
        self._route = route
        self._transport = transport

    async def advise(self, request: AdvisorInvocationRequestV1) -> AdvisorResponseV1:
        """Make one authenticated request without accepting an alternate destination."""

        if (
            type(request) is not AdvisorInvocationRequestV1
            or request.snapshot.target.project_id != self._route.project_id
        ):
            raise ValueError("advisor request target is invalid")
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
            response = decode_contract(body, AdvisorResponseV1)
        except asyncio.CancelledError:
            raise
        except (ContractError, TypeError, ValueError, RuntimeError):
            raise AdvisorModelFailure(AdvisorModelFailureCode.MODEL_UNAVAILABLE) from None
        if (
            response.request_sha256 != canonical_sha256(request)
            or response.audit.correlation_id != request.correlation_id
            or response.audit.snapshot_sha256 != request.snapshot_sha256
        ):
            raise AdvisorModelFailure(AdvisorModelFailureCode.MALFORMED_OUTPUT)
        return response


class AdvisorWorkflowErrorCode(StrEnum):
    """Stable failures at the authenticated operator-to-advisor boundary."""

    CONFIGURATION_INVALID = "ADVISOR_WORKFLOW_CONFIGURATION_INVALID"
    CALLER_DENIED = "ADVISOR_WORKFLOW_CALLER_DENIED"
    OPERATOR_DENIED = "ADVISOR_WORKFLOW_OPERATOR_DENIED"
    COMMAND_DENIED = "ADVISOR_WORKFLOW_COMMAND_DENIED"
    EVIDENCE_UNAVAILABLE = "ADVISOR_WORKFLOW_EVIDENCE_UNAVAILABLE"
    ADVISOR_UNAVAILABLE = "ADVISOR_WORKFLOW_ADVISOR_UNAVAILABLE"
    AUDIT_UNAVAILABLE = "ADVISOR_WORKFLOW_AUDIT_UNAVAILABLE"
    RESPONSE_INVALID = "ADVISOR_WORKFLOW_RESPONSE_INVALID"


class AdvisorWorkflowError(RuntimeError):
    """Payload-free workflow failure."""

    def __init__(self, code: AdvisorWorkflowErrorCode) -> None:
        if type(code) is not AdvisorWorkflowErrorCode:
            raise TypeError("an exact advisor workflow error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class DiagnosticSnapshotAssembler(Protocol):
    """Build a snapshot only from validated durable M6 records."""

    async def assemble(
        self,
        command: AdvisorOperatorCommandV1,
    ) -> AdvisorInvocationRequestV1: ...


@dataclass(frozen=True, slots=True)
class AdvisorAuditWriteResult:
    """Winner of one atomic idempotent response write."""

    result: AdvisorOperatorResultV1
    created: bool

    def __post_init__(self) -> None:
        if type(self.result) is not AdvisorOperatorResultV1 or type(self.created) is not bool:
            raise TypeError("advisor audit write result is invalid")


@dataclass(frozen=True, slots=True)
class AdvisorDispositionWriteResult:
    """Winner of one compare-and-set operator disposition write."""

    interaction: AdvisorOperatorResultV1
    result: AdvisorDispositionResultV1
    created: bool

    def __post_init__(self) -> None:
        if (
            type(self.interaction) is not AdvisorOperatorResultV1
            or type(self.result) is not AdvisorDispositionResultV1
            or type(self.created) is not bool
            or self.interaction.interaction_id != self.result.interaction_id
        ):
            raise TypeError("advisor disposition write result is invalid")


@runtime_checkable
class ModelAssistanceAuditStore(Protocol):
    """Durable M6 store for response replay and disposition compare-and-set."""

    async def read_response(
        self,
        idempotency_key: str,
    ) -> AdvisorOperatorResultV1 | None: ...

    async def write_response_if_absent(
        self,
        idempotency_key: str,
        result: AdvisorOperatorResultV1,
    ) -> AdvisorAuditWriteResult: ...

    async def write_disposition(
        self,
        command: AdvisorDispositionCommandV1,
    ) -> AdvisorDispositionWriteResult: ...


@runtime_checkable
class ModelAssistanceTimelineRecorder(Protocol):
    """Append redacted model lifecycle records to the target-scoped M6 timeline."""

    async def record_model_assistance(
        self,
        event: ModelAssistanceTimelineAuditV1,
    ) -> None: ...


class ApiAdvisorClient:
    """Forward an authenticated operator command only to the fixed coordinator."""

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
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.API
            or authentication_policy.caller.role is not CallerRole.OPERATOR
            or authentication_policy.project_id != route.project_id
            or authentication_policy.project_number != route.project_number
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._policy = authentication_policy
        self._transport = transport

    async def advise(
        self,
        command: AdvisorOperatorCommandV1,
        principal: AuthenticationContext,
    ) -> AdvisorOperatorResultV1:
        invocation = self._operator_invocation(command, principal)
        try:
            body = await self._transport.post(self._route, canonical_json_bytes(invocation))
            return decode_contract(body, AdvisorOperatorResultV1)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.ADVISOR_UNAVAILABLE) from None

    async def record_disposition(
        self,
        command: AdvisorDispositionCommandV1,
        principal: AuthenticationContext,
    ) -> AdvisorDispositionResultV1:
        invocation = self._disposition_invocation(command, principal)
        try:
            body = await self._transport.post(self._route, canonical_json_bytes(invocation))
            return decode_contract(body, AdvisorDispositionResultV1)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.ADVISOR_UNAVAILABLE) from None

    def _operator_invocation(
        self,
        command: AdvisorOperatorCommandV1,
        principal: AuthenticationContext,
    ) -> AdvisorOperatorInvocationV1:
        self._validate_principal(principal)
        if (
            type(command) is not AdvisorOperatorCommandV1
            or command.target.project_id != self._route.project_id
        ):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.COMMAND_DENIED)
        return AdvisorOperatorInvocationV1(
            schema_version=ADVISOR_OPERATOR_INVOCATION_V1,
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

    def _disposition_invocation(
        self,
        command: AdvisorDispositionCommandV1,
        principal: AuthenticationContext,
    ) -> AdvisorDispositionInvocationV1:
        self._validate_principal(principal)
        if (
            type(command) is not AdvisorDispositionCommandV1
            or command.target.project_id != self._route.project_id
        ):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.COMMAND_DENIED)
        return AdvisorDispositionInvocationV1(
            schema_version=ADVISOR_DISPOSITION_INVOCATION_V1,
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

    def _validate_principal(self, principal: AuthenticationContext) -> None:
        if not _caller_matches_policy(principal, self._policy):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.OPERATOR_DENIED)

class CoordinatorAdvisorWorkflow:
    """Load M6 evidence, invoke the read-only advisor, and persist its audit lifecycle."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        assembler: DiagnosticSnapshotAssembler,
        advisor: CoordinatorAdvisorClient,
        audit_store: ModelAssistanceAuditStore,
        timeline: ModelAssistanceTimelineRecorder,
    ) -> None:
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.COORDINATOR
            or authentication_policy.caller.role is not CallerRole.API
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.project_id != authentication_policy.project_id
            or operator_policy.project_number != authentication_policy.project_number
            or not isinstance(assembler, DiagnosticSnapshotAssembler)
            or type(advisor) is not CoordinatorAdvisorClient
            or not isinstance(audit_store, ModelAssistanceAuditStore)
            or not isinstance(timeline, ModelAssistanceTimelineRecorder)
        ):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.CONFIGURATION_INVALID)
        self._policy = authentication_policy
        self._operator_policy = operator_policy
        self._assembler = assembler
        self._advisor = advisor
        self._audit_store = audit_store
        self._timeline = timeline

    async def advise(
        self,
        invocation: AdvisorOperatorInvocationV1,
        caller: AuthenticationContext,
    ) -> AdvisorOperatorResultV1:
        self._validate_invocation(invocation, caller)
        command = invocation.command
        command_sha256 = canonical_sha256(command)
        try:
            stored = await self._audit_store.read_response(command.idempotency_key)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.AUDIT_UNAVAILABLE) from None
        if stored is not None:
            result = _validated_stored_result(stored, command_sha256, command)
            await self._record_result(command, result, replay=True)
            return result.model_copy(update={"replayed": True})
        try:
            request = await self._assembler.assemble(command)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.EVIDENCE_UNAVAILABLE) from None
        if not _request_matches_command(request, command):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.EVIDENCE_UNAVAILABLE)
        try:
            response = await self._advisor.advise(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.ADVISOR_UNAVAILABLE) from None
        candidate = AdvisorOperatorResultV1(
            schema_version=ADVISOR_OPERATOR_RESULT_V1,
            command_sha256=command_sha256,
            interaction_id=response.audit.interaction_id,
            target=request.snapshot.target,
            root_id=request.snapshot.root_id,
            root_sha256=request.snapshot.root_sha256,
            epoch=request.snapshot.current_epoch,
            response=response,
            replayed=False,
        )
        try:
            written = await self._audit_store.write_response_if_absent(
                command.idempotency_key,
                candidate,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.AUDIT_UNAVAILABLE) from None
        if type(written) is not AdvisorAuditWriteResult:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.AUDIT_UNAVAILABLE)
        winner = _validated_stored_result(written.result, command_sha256, command)
        await self._record_result(command, winner, replay=not written.created)
        return winner.model_copy(update={"replayed": not written.created})

    async def record_disposition(
        self,
        invocation: AdvisorDispositionInvocationV1,
        caller: AuthenticationContext,
    ) -> AdvisorDispositionResultV1:
        self._validate_invocation(invocation, caller)
        command = invocation.command
        try:
            written = await self._audit_store.write_disposition(command)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.AUDIT_UNAVAILABLE) from None
        if type(written) is not AdvisorDispositionWriteResult:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.AUDIT_UNAVAILABLE)
        interaction = written.interaction
        result = written.result
        if (
            interaction.interaction_id != command.interaction_id
            or interaction.target != command.target
            or interaction.root_id != command.root_id
            or interaction.root_sha256 != command.expected_root_sha256
            or interaction.epoch != command.expected_epoch
            or result.command_sha256 != canonical_sha256(command)
            or result.response_sha256 != canonical_sha256(interaction.response)
            or result.disposition is not command.disposition
            or result.replayed is written.created
        ):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.RESPONSE_INVALID)
        event = _timeline_audit_event(
            command=command,
            result=interaction,
            lifecycle=(
                ModelAssistanceLifecycle.DISPOSITION_RECORDED
                if written.created
                else ModelAssistanceLifecycle.DISPOSITION_REPLAYED
            ),
            disposition=result.disposition,
            occurred_at=command.recorded_at,
            actor_role=ModelAssistanceActorRole.OPERATOR,
            actor_identity=invocation.operator_identity,
        )
        await self._record_event(event)
        return result

    def _validate_invocation(
        self,
        invocation: AdvisorOperatorInvocationV1 | AdvisorDispositionInvocationV1,
        caller: AuthenticationContext,
    ) -> None:
        if not _caller_matches_policy(caller, self._policy):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.CALLER_DENIED)
        if type(invocation) not in {
            AdvisorOperatorInvocationV1,
            AdvisorDispositionInvocationV1,
        }:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.COMMAND_DENIED)
        expected = self._operator_policy.caller
        if (
            invocation.command.target.project_id != self._policy.project_id
            or invocation.operator_identity != expected.email
            or invocation.operator_subject != expected.subject
            or invocation.operator_issuer
            not in {"accounts.google.com", "https://accounts.google.com"}
            or invocation.operator_audience != self._operator_policy.audience
        ):
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.OPERATOR_DENIED)

    async def _record_result(
        self,
        command: AdvisorOperatorCommandV1,
        result: AdvisorOperatorResultV1,
        *,
        replay: bool,
    ) -> None:
        original_lifecycle = (
            ModelAssistanceLifecycle.COMPLETED
            if result.response.audit.validation.accepted
            else ModelAssistanceLifecycle.FALLBACK
        )
        await self._record_event(
            _timeline_audit_event(
                command=command,
                result=result,
                lifecycle=original_lifecycle,
                disposition=OperatorDisposition.PENDING_REVIEW,
                occurred_at=command.requested_at,
                actor_role=ModelAssistanceActorRole.ADVISOR,
                actor_identity=(
                    f"controlgraph-advisor@{result.target.project_id}.iam.gserviceaccount.com"
                ),
            )
        )
        if replay:
            await self._record_event(
                _timeline_audit_event(
                    command=command,
                    result=result,
                    lifecycle=ModelAssistanceLifecycle.REPLAYED,
                    disposition=OperatorDisposition.PENDING_REVIEW,
                    occurred_at=command.requested_at,
                    actor_role=ModelAssistanceActorRole.ADVISOR,
                    actor_identity=(
                        f"controlgraph-advisor@{result.target.project_id}.iam.gserviceaccount.com"
                    ),
                )
            )

    async def _record_event(self, event: ModelAssistanceTimelineAuditV1) -> None:
        try:
            await self._timeline.record_model_assistance(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.AUDIT_UNAVAILABLE) from None


def validate_recommendation(
    request: AdvisorInvocationRequestV1,
    recommendation: AdvisorRecommendationV1,
    *,
    tool_calls: tuple[AdvisorToolCallAuditV1, ...],
    now: datetime,
) -> AdvisorValidationV1:
    """Validate model output against the immutable current-state snapshot."""

    if (
        type(request) is not AdvisorInvocationRequestV1
        or type(recommendation) is not AdvisorRecommendationV1
        or type(tool_calls) is not tuple
        or type(now) is not datetime
    ):
        raise TypeError("exact recommendation validation inputs are required")
    codes: list[RecommendationValidationCode] = []
    snapshot = request.snapshot
    if recommendation.snapshot_sha256 != request.snapshot_sha256:
        codes.append(RecommendationValidationCode.SNAPSHOT_DIGEST_MISMATCH)
    if recommendation.target != snapshot.target:
        codes.append(RecommendationValidationCode.TARGET_MISMATCH)
    if recommendation.root_id != snapshot.root_id:
        codes.append(RecommendationValidationCode.ROOT_MISMATCH)
    if recommendation.current_epoch != snapshot.current_epoch:
        codes.append(RecommendationValidationCode.EPOCH_MISMATCH)

    manual_review = (
        recommendation.requested_operator_action is RequestedOperatorAction.MANUAL_REVIEW
    )
    current = _naive_utc_second(now)
    if (
        current < _utc(request.snapshot.assembled_at)
        or current >= _utc(request.snapshot.expires_at)
    ) and not manual_review:
        codes.append(RecommendationValidationCode.EVIDENCE_STALE)
    if (
        snapshot.evidence_consistency is EvidenceConsistency.INCOMPLETE
        and not manual_review
    ):
        codes.append(RecommendationValidationCode.EVIDENCE_INCOMPLETE)
    if (
        snapshot.evidence_consistency is EvidenceConsistency.CONFLICTING
        and not manual_review
    ):
        codes.append(RecommendationValidationCode.EVIDENCE_CONFLICT)
    if (
        recommendation.confidence_basis_points < 7_000
        and not manual_review
    ):
        codes.append(RecommendationValidationCode.LOW_CONFIDENCE)
    if not _citations_are_valid(request, recommendation, tool_calls):
        codes.append(RecommendationValidationCode.CITATION_INVALID)
    if not _action_is_allowed(request, recommendation.requested_operator_action):
        codes.append(RecommendationValidationCode.ACTION_NOT_ALLOWED)

    unique_codes = tuple(dict.fromkeys(codes))
    if unique_codes:
        return AdvisorValidationV1(
            schema_version=ADVISOR_VALIDATION_V1,
            accepted=False,
            codes=unique_codes,
        )
    return AdvisorValidationV1(
        schema_version=ADVISOR_VALIDATION_V1,
        accepted=True,
        codes=(RecommendationValidationCode.ACCEPTED,),
    )


def _action_is_allowed(
    request: AdvisorInvocationRequestV1,
    action: RequestedOperatorAction,
) -> bool:
    snapshot = request.snapshot
    exact_canary = (snapshot.stable_percent, snapshot.candidate_percent) == (90, 10)
    if action is RequestedOperatorAction.MANUAL_REVIEW:
        return True
    if snapshot.evidence_consistency is not EvidenceConsistency.CONSISTENT:
        return False
    if action in {
        RequestedOperatorAction.WAIT,
        RequestedOperatorAction.COLLECT_APPROVED_DIAGNOSTICS,
    }:
        return snapshot.rollout_phase is not RolloutPhase.UNKNOWN
    if action is RequestedOperatorAction.REQUEST_REVOCATION:
        return (
            exact_canary
            and snapshot.rollout_phase is RolloutPhase.CANARY
            and not snapshot.authority_revoked
        )
    if action is RequestedOperatorAction.REQUEST_CAPTURED_STABLE_RECOVERY:
        return (
            exact_canary
            and snapshot.recovery_revision == snapshot.stable_revision
            and snapshot.rollout_phase
            in {RolloutPhase.CANARY, RolloutPhase.REVOKED, RolloutPhase.RECOVERY_PENDING}
            and (
                snapshot.authority_revoked
                or (
                    snapshot.terminal_health
                    and snapshot.health is AdvisoryHealth.UNHEALTHY
                )
            )
        )
    if action is RequestedOperatorAction.REQUEST_NEW_OPERATOR_APPROVED_ROLLOUT:
        return (
            snapshot.rollout_phase in {RolloutPhase.STABLE, RolloutPhase.PROMOTED}
            and not exact_canary
        )
    return False


def _citations_are_valid(
    request: AdvisorInvocationRequestV1,
    recommendation: AdvisorRecommendationV1,
    tool_calls: tuple[AdvisorToolCallAuditV1, ...],
) -> bool:
    expected_tools = set(DiagnosticToolId)
    succeeded_tools = {
        call.tool_id for call in tool_calls if call.status is ToolCallStatus.SUCCEEDED
    }
    if (
        len(tool_calls) != MAX_TOOL_CALLS
        or len(succeeded_tools) != MAX_TOOL_CALLS
        or succeeded_tools != expected_tools
        or any(call.status is not ToolCallStatus.SUCCEEDED for call in tool_calls)
    ):
        return False
    evidence_index: dict[str, _EvidenceIndexEntry] = {}
    for summary in request.snapshot.evidence_summaries:
        for evidence_id in summary.evidence_ids:
            evidence_index[evidence_id] = _EvidenceIndexEntry(
                kind=summary.evidence_kind,
                source_sha256=summary.source_sha256,
            )
    for finding in recommendation.findings:
        for citation in finding.citations:
            expected = evidence_index.get(citation.evidence_id)
            if expected is None or (
                expected.kind is not citation.evidence_kind
                or expected.source_sha256 != citation.source_sha256
            ):
                return False
    return True


def _summary_for_tool(
    request: AdvisorInvocationRequestV1,
    tool_id: DiagnosticToolId,
) -> DiagnosticEvidenceSummaryV1:
    snapshot = request.snapshot
    summaries = {
        DiagnosticToolId.READ_ROOT_SUMMARY: snapshot.root_summary,
        DiagnosticToolId.READ_TARGET_SUMMARY: snapshot.target_summary,
        DiagnosticToolId.READ_HEALTH_SUMMARY: snapshot.health_summary,
        DiagnosticToolId.READ_RECEIPT_SUMMARY: snapshot.receipt_summary,
        DiagnosticToolId.READ_TIMELINE_SUMMARY: snapshot.timeline_summary,
        DiagnosticToolId.READ_VERIFIER_SUMMARY: snapshot.verifier_summary,
    }
    return summaries[tool_id]


def _request_matches_command(
    request: object,
    command: AdvisorOperatorCommandV1,
) -> bool:
    if type(request) is not AdvisorInvocationRequestV1:
        return False
    snapshot = request.snapshot
    return (
        request.correlation_id == command.request_id
        and request.requested_at == command.requested_at
        and snapshot.target == command.target
        and snapshot.root_id == command.root_id
        and snapshot.root_sha256 == command.expected_root_sha256
        and snapshot.current_epoch == command.expected_epoch
    )


def _validated_stored_result(
    stored: object,
    command_sha256: str,
    command: AdvisorOperatorCommandV1,
) -> AdvisorOperatorResultV1:
    if (
        type(stored) is not AdvisorOperatorResultV1
        or stored.command_sha256 != command_sha256
        or stored.target != command.target
        or stored.root_id != command.root_id
        or stored.root_sha256 != command.expected_root_sha256
        or stored.epoch != command.expected_epoch
        or stored.response.audit.correlation_id != command.request_id
    ):
        raise AdvisorWorkflowError(AdvisorWorkflowErrorCode.RESPONSE_INVALID)
    return stored


def _timeline_audit_event(
    *,
    command: AdvisorOperatorCommandV1 | AdvisorDispositionCommandV1,
    result: AdvisorOperatorResultV1,
    lifecycle: ModelAssistanceLifecycle,
    disposition: OperatorDisposition,
    occurred_at: str,
    actor_role: ModelAssistanceActorRole,
    actor_identity: str,
) -> ModelAssistanceTimelineAuditV1:
    material = (
        f"{lifecycle.value}\0{result.interaction_id}\0{command.request_id}\0"
        f"{disposition.value}"
    ).encode()
    event_id = f"cgmodelaudit:{hashlib.sha256(material).hexdigest()}"
    return ModelAssistanceTimelineAuditV1(
        schema_version=MODEL_ASSISTANCE_TIMELINE_AUDIT_V1,
        event_id=event_id,
        lifecycle=lifecycle,
        target=result.target,
        root_id=result.root_id,
        root_sha256=result.root_sha256,
        epoch=result.epoch,
        request_id=command.request_id,
        interaction_id=result.interaction_id,
        actor_role=actor_role,
        actor_id=f"actor:{hashlib.sha256(actor_identity.encode('utf-8')).hexdigest()}",
        occurred_at=occurred_at,
        command_sha256=canonical_sha256(command),
        response_sha256=canonical_sha256(result.response),
        audit=result.response.audit,
        disposition=disposition,
    )


def _caller_matches_policy(
    caller: AuthenticationContext,
    policy: RouteAuthenticationPolicy,
) -> bool:
    return (
        type(caller) is AuthenticationContext
        and caller.role is policy.caller.role
        and caller.email == policy.caller.email
        and caller.subject == policy.caller.subject
        and caller.audience == policy.audience
    )


def _failed_validation(code: RecommendationValidationCode) -> AdvisorValidationV1:
    return AdvisorValidationV1(
        schema_version=ADVISOR_VALIDATION_V1,
        accepted=False,
        codes=(code,),
    )


def _cited_evidence_ids(
    recommendation: AdvisorRecommendationV1,
) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            citation.evidence_id
            for finding in recommendation.findings
            for citation in finding.citations
        )
    )


def _valid_candidate_digest(candidate: object) -> str | None:
    if type(candidate) is not AdvisorRecommendationV1:
        return None
    try:
        return canonical_sha256(candidate)
    except (ContractError, TypeError, ValueError, ValidationError):
        return None


def _interaction_id(request_sha256: str) -> str:
    return f"cgmodel:{request_sha256[:32]}"


def _untrusted_tool_input_sha256(value: object) -> str:
    material = repr(value).encode("utf-8", errors="replace")[:1_024]
    return hashlib.sha256(b"controlgraph.denied-tool-input/v1\0" + material).hexdigest()


def _utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _naive_utc_second(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("validation clock must be timezone-aware")
    return value.astimezone(UTC).replace(tzinfo=None, microsecond=0)


__all__ = [
    "AdvisorAuditWriteResult",
    "AdvisorDispositionWriteResult",
    "AdvisorModel",
    "AdvisorModelFailure",
    "AdvisorModelFailureCode",
    "AdvisorWorkflowError",
    "AdvisorWorkflowErrorCode",
    "ApiAdvisorClient",
    "CoordinatorAdvisorClient",
    "CoordinatorAdvisorWorkflow",
    "DiagnosticSnapshotAssembler",
    "DiagnosticToolError",
    "InvocationDiagnosticRegistry",
    "ModelAssistanceAuditStore",
    "ModelAssistanceTimelineRecorder",
    "ReadOnlyAdvisorService",
    "SnapshotDiagnosticEvidenceReader",
    "VerifiedDiagnosticEvidenceReader",
    "validate_recommendation",
]
