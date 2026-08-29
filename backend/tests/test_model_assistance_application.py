from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

import pytest
from model_assistance_test_data import (
    ADVISOR_AUDIENCE,
    PROJECT_ID,
    PROJECT_NUMBER,
    authentication_context,
    authentication_policy,
    invocation,
    recommendation,
    verified_evidence_reader,
)

from controlgraph_canary.application.identity import CallerRole, ServiceRole
from controlgraph_canary.application.model_assistance import (
    AdvisorModelFailure,
    AdvisorModelFailureCode,
    CoordinatorAdvisorClient,
    DiagnosticToolError,
    InvocationDiagnosticRegistry,
    ReadOnlyAdvisorService,
    stale_denial_causal_path_clause,
    validate_recommendation,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.model_assistance import (
    PROMPT_VERSION,
    PROMPT_VERSION_V1,
    AdvisorFallbackCode,
    AdvisorInteractionAuditV1,
    AdvisorInvocationRequestV1,
    AdvisorRecommendationV1,
    AdvisorResponseV1,
    AdvisorToolCallAuditV1,
    AdvisoryHealth,
    DiagnosticEvidenceFactName,
    DiagnosticEvidenceKind,
    DiagnosticSnapshotV1,
    DiagnosticToolId,
    EvidenceConsistency,
    RecommendationValidationCode,
    RequestedOperatorAction,
    RolloutPhase,
    ToolCallStatus,
)

NOW = datetime(2026, 8, 22, 10, 1, tzinfo=UTC)
STALE_CAUSAL_PATH = stale_denial_causal_path_clause(
    work_epoch=2,
    current_authority_epoch=3,
    target_configuration_sha256="9" * 64,
)


async def _call_all_tools(
    request: AdvisorInvocationRequestV1,
    registry: InvocationDiagnosticRegistry,
) -> None:
    for tool_id in DiagnosticToolId:
        await registry.read(tool_id, request.snapshot_sha256)


def _audits(
    request: AdvisorInvocationRequestV1,
) -> tuple[AdvisorToolCallAuditV1, ...]:
    registry = InvocationDiagnosticRegistry(
        request,
        evidence_reader=verified_evidence_reader(),
    )
    asyncio.run(_call_all_tools(request, registry))
    return registry.calls


class _SuccessfulModel:
    def __init__(self, result: AdvisorRecommendationV1) -> None:
        self._result = result

    @property
    def model_id(self) -> Literal["gemini-3.5-flash"]:
        return "gemini-3.5-flash"

    @property
    def model_location(self) -> Literal["global"]:
        return "global"

    @property
    def prompt_version(self) -> Literal["controlgraph.rollout-advisor-prompt/v2"]:
        return "controlgraph.rollout-advisor-prompt/v2"

    async def recommend(
        self,
        request: AdvisorInvocationRequestV1,
        tools: InvocationDiagnosticRegistry,
    ) -> AdvisorRecommendationV1:
        await _call_all_tools(request, tools)
        return self._result


class _FailingModel(_SuccessfulModel):
    def __init__(self, code: AdvisorModelFailureCode) -> None:
        self._code = code
        super().__init__(recommendation(invocation()))

    async def recommend(
        self,
        request: AdvisorInvocationRequestV1,
        tools: InvocationDiagnosticRegistry,
    ) -> AdvisorRecommendationV1:
        del request, tools
        raise AdvisorModelFailure(self._code)


class _SlowModel(_SuccessfulModel):
    async def recommend(
        self,
        request: AdvisorInvocationRequestV1,
        tools: InvocationDiagnosticRegistry,
    ) -> AdvisorRecommendationV1:
        del request, tools
        await asyncio.sleep(1)
        raise AssertionError("timeout must cancel model execution")


class _MalformedModel(_SuccessfulModel):
    async def recommend(
        self,
        request: AdvisorInvocationRequestV1,
        tools: InvocationDiagnosticRegistry,
    ) -> AdvisorRecommendationV1:
        del tools
        return recommendation(request).model_copy(
            update={"requested_operator_action": "not_an_action"}
        )


class _LegacyPromptModel(_SuccessfulModel):
    @property
    def prompt_version(self) -> Literal["controlgraph.rollout-advisor-prompt/v1"]:
        return "controlgraph.rollout-advisor-prompt/v1"


def test_registry_returns_only_bound_summaries_once_each() -> None:
    request = invocation()
    reader = verified_evidence_reader()
    registry = InvocationDiagnosticRegistry(request, evidence_reader=reader)

    asyncio.run(_call_all_tools(request, registry))

    assert tuple(call.tool_id for call in registry.calls) == tuple(DiagnosticToolId)
    assert all(call.status is ToolCallStatus.SUCCEEDED for call in registry.calls)
    assert all(call.output_sha256 is not None for call in registry.calls)
    assert tuple(reader.calls) == tuple(DiagnosticEvidenceKind)

    with pytest.raises(DiagnosticToolError, match="denied"):
        asyncio.run(
            registry.read(
                DiagnosticToolId.READ_ROOT_SUMMARY,
                request.snapshot_sha256,
            )
        )


def test_registry_rejects_cross_snapshot_input_before_returning_evidence() -> None:
    request = invocation()
    registry = InvocationDiagnosticRegistry(
        request,
        evidence_reader=verified_evidence_reader(),
    )

    with pytest.raises(DiagnosticToolError, match="denied"):
        asyncio.run(registry.read(DiagnosticToolId.READ_ROOT_SUMMARY, "f" * 64))

    assert len(registry.calls) == 1
    assert registry.calls[0].status is ToolCallStatus.DENIED
    assert registry.calls[0].output_sha256 is None


def test_validator_accepts_only_fully_cited_fresh_bound_recommendation() -> None:
    request = invocation()

    result = validate_recommendation(
        request,
        recommendation(request),
        tool_calls=_audits(request),
        now=NOW,
    )

    assert result.accepted is True
    assert result.codes == (RecommendationValidationCode.ACCEPTED,)


@pytest.mark.parametrize(
    "target_evidence",
    [DiagnosticEvidenceKind.TARGET, DiagnosticEvidenceKind.VERIFIER],
)
def test_fresh_revoked_epoch_mismatch_requires_causal_citations(
    target_evidence: DiagnosticEvidenceKind,
) -> None:
    request = invocation(
        phase=RolloutPhase.REVOKED,
        authority_revoked=True,
        stale_epoch_mismatch=True,
    )
    required = (
        DiagnosticEvidenceKind.RECEIPT,
        DiagnosticEvidenceKind.TIMELINE,
        target_evidence,
    )

    accepted = validate_recommendation(
        request,
        recommendation(
            request,
            statement=STALE_CAUSAL_PATH,
            citation_kinds=required,
        ),
        tool_calls=_audits(request),
        now=NOW,
    )
    missing_target_evidence = validate_recommendation(
        request,
        recommendation(
            request,
            statement=STALE_CAUSAL_PATH,
            citation_kinds=required[:2],
        ),
        tool_calls=_audits(request),
        now=NOW,
    )
    missing_timeline = validate_recommendation(
        request,
        recommendation(
            request,
            statement=STALE_CAUSAL_PATH,
            citation_kinds=(DiagnosticEvidenceKind.RECEIPT, target_evidence),
        ),
        tool_calls=_audits(request),
        now=NOW,
    )
    missing_receipt = validate_recommendation(
        request,
        recommendation(
            request,
            statement=STALE_CAUSAL_PATH,
            citation_kinds=(DiagnosticEvidenceKind.TIMELINE, target_evidence),
        ),
        tool_calls=_audits(request),
        now=NOW,
    )

    assert accepted.codes == (RecommendationValidationCode.ACCEPTED,)
    assert RecommendationValidationCode.CITATION_INVALID in missing_target_evidence.codes
    assert RecommendationValidationCode.CITATION_INVALID in missing_timeline.codes
    assert RecommendationValidationCode.CITATION_INVALID in missing_receipt.codes


@pytest.mark.parametrize(
    "statement",
    (
        "The cited records support this bounded operator review.",
        STALE_CAUSAL_PATH + " reason=TARGET_CHANGED",
        STALE_CAUSAL_PATH.replace("work_epoch=2", "work_epoch=1"),
        STALE_CAUSAL_PATH.replace(
            "current_authority_epoch=3",
            "current_authority_epoch=4",
        ),
        STALE_CAUSAL_PATH.replace("reason=EPOCH_MISMATCH", "reason=TARGET_CHANGED"),
        STALE_CAUSAL_PATH.replace("target=90/10", "target=100/0"),
        STALE_CAUSAL_PATH.replace("9" * 64, "8" * 64),
        STALE_CAUSAL_PATH.replace(
            "relation=AT_OR_AFTER_DENIAL",
            "relation=BEFORE_DENIAL",
        ),
    ),
)
def test_stale_denial_rejects_noncanonical_causal_path(statement: str) -> None:
    request = invocation(
        phase=RolloutPhase.REVOKED,
        authority_revoked=True,
        stale_epoch_mismatch=True,
    )

    result = validate_recommendation(
        request,
        recommendation(
            request,
            statement=statement,
            citation_kinds=(
                DiagnosticEvidenceKind.RECEIPT,
                DiagnosticEvidenceKind.TIMELINE,
                DiagnosticEvidenceKind.TARGET,
            ),
        ),
        tool_calls=_audits(request),
        now=NOW,
    )

    assert RecommendationValidationCode.CITATION_INVALID in result.codes


def test_stale_denial_rejects_causal_citations_split_across_findings() -> None:
    request = invocation(
        phase=RolloutPhase.REVOKED,
        authority_revoked=True,
        stale_epoch_mismatch=True,
    )
    combined = recommendation(
        request,
        statement=STALE_CAUSAL_PATH,
        citation_kinds=(
            DiagnosticEvidenceKind.RECEIPT,
            DiagnosticEvidenceKind.TIMELINE,
            DiagnosticEvidenceKind.TARGET,
        ),
    )
    citations = combined.findings[0].citations
    split = combined.model_copy(
        update={
            "findings": tuple(
                combined.findings[0].model_copy(update={"citations": (citation,)})
                for citation in citations
            )
        }
    )

    result = validate_recommendation(
        request,
        split,
        tool_calls=_audits(request),
        now=NOW,
    )

    assert RecommendationValidationCode.CITATION_INVALID in result.codes


def test_stale_denial_rejects_duplicate_causal_findings() -> None:
    request = invocation(
        phase=RolloutPhase.REVOKED,
        authority_revoked=True,
        stale_epoch_mismatch=True,
    )
    recommendation_with_causal_path = recommendation(
        request,
        statement=STALE_CAUSAL_PATH,
        citation_kinds=(
            DiagnosticEvidenceKind.RECEIPT,
            DiagnosticEvidenceKind.TIMELINE,
            DiagnosticEvidenceKind.TARGET,
        ),
    )
    duplicate = recommendation_with_causal_path.model_copy(
        update={
            "findings": (
                recommendation_with_causal_path.findings[0],
                recommendation_with_causal_path.findings[0],
            )
        }
    )

    result = validate_recommendation(
        request,
        duplicate,
        tool_calls=_audits(request),
        now=NOW,
    )

    assert RecommendationValidationCode.CITATION_INVALID in result.codes


@pytest.mark.parametrize(
    "distractor_kind",
    (
        DiagnosticEvidenceKind.RECEIPT,
        DiagnosticEvidenceKind.TIMELINE,
        DiagnosticEvidenceKind.TARGET,
    ),
)
def test_stale_denial_rejects_non_fact_bearing_citation_ids(
    distractor_kind: DiagnosticEvidenceKind,
) -> None:
    original = invocation(
        phase=RolloutPhase.REVOKED,
        authority_revoked=True,
        stale_epoch_mismatch=True,
    )
    snapshot_payload = original.snapshot.model_dump(mode="python")
    for field, kind in (
        ("receipt_summary", DiagnosticEvidenceKind.RECEIPT),
        ("timeline_summary", DiagnosticEvidenceKind.TIMELINE),
        ("target_summary", DiagnosticEvidenceKind.TARGET),
    ):
        summary = snapshot_payload[field]
        summary["evidence_ids"] = (
            f"{kind.value}-distractor",
            *summary["evidence_ids"],
        )
    selected_snapshot = DiagnosticSnapshotV1.model_validate(snapshot_payload)
    request = AdvisorInvocationRequestV1(
        schema_version=original.schema_version,
        correlation_id=original.correlation_id,
        requested_at=original.requested_at,
        snapshot=selected_snapshot,
        snapshot_sha256=canonical_sha256(selected_snapshot),
    )
    summary_by_kind = {
        summary.evidence_kind: summary for summary in request.snapshot.evidence_summaries
    }
    fact_name = {
        DiagnosticEvidenceKind.RECEIPT: DiagnosticEvidenceFactName.RECEIPT_REASON,
        DiagnosticEvidenceKind.TIMELINE: (DiagnosticEvidenceFactName.AUTHORITY_TRANSITION),
        DiagnosticEvidenceKind.TARGET: (DiagnosticEvidenceFactName.TARGET_CONFIGURATION_SHA256),
    }
    exact_ids = {
        kind: next(
            fact.evidence_id for fact in summary_by_kind[kind].facts if fact.name is fact_name[kind]
        )
        for kind in fact_name
    }
    cited_ids = {
        **exact_ids,
        distractor_kind: f"{distractor_kind.value}-distractor",
    }

    result = validate_recommendation(
        request,
        recommendation(
            request,
            statement=STALE_CAUSAL_PATH,
            citation_kinds=(
                DiagnosticEvidenceKind.RECEIPT,
                DiagnosticEvidenceKind.TIMELINE,
                DiagnosticEvidenceKind.TARGET,
            ),
            citation_evidence_ids=cited_ids,
        ),
        tool_calls=_audits(request),
        now=NOW,
    )

    assert RecommendationValidationCode.CITATION_INVALID in result.codes


def test_validator_fails_closed_when_a_tool_was_not_called() -> None:
    request = invocation()
    calls = _audits(request)

    result = validate_recommendation(
        request,
        recommendation(request),
        tool_calls=calls[:-1],
        now=NOW,
    )

    assert result.accepted is False
    assert RecommendationValidationCode.CITATION_INVALID in result.codes


def test_conflicting_evidence_allows_only_explicit_manual_review() -> None:
    request = invocation(consistency=EvidenceConsistency.CONFLICTING)
    calls = _audits(request)

    ordinary = validate_recommendation(
        request,
        recommendation(request),
        tool_calls=calls,
        now=NOW,
    )
    manual = validate_recommendation(
        request,
        recommendation(
            request,
            action=RequestedOperatorAction.MANUAL_REVIEW,
            confidence_basis_points=0,
        ),
        tool_calls=calls,
        now=NOW,
    )

    assert ordinary.accepted is False
    assert RecommendationValidationCode.EVIDENCE_CONFLICT in ordinary.codes
    assert manual.accepted is True


def test_captured_stable_recovery_requires_exact_canary_and_terminal_basis() -> None:
    healthy = invocation()
    unhealthy = invocation(
        health=AdvisoryHealth.UNHEALTHY,
        terminal_health=True,
    )
    promoted = invocation(
        phase=RolloutPhase.PROMOTED,
        stable_percent=0,
        candidate_percent=100,
    )

    denied = validate_recommendation(
        healthy,
        recommendation(
            healthy,
            action=RequestedOperatorAction.REQUEST_CAPTURED_STABLE_RECOVERY,
        ),
        tool_calls=_audits(healthy),
        now=NOW,
    )
    allowed = validate_recommendation(
        unhealthy,
        recommendation(
            unhealthy,
            action=RequestedOperatorAction.REQUEST_CAPTURED_STABLE_RECOVERY,
        ),
        tool_calls=_audits(unhealthy),
        now=NOW,
    )
    wrong_phase = validate_recommendation(
        promoted,
        recommendation(
            promoted,
            action=RequestedOperatorAction.REQUEST_CAPTURED_STABLE_RECOVERY,
        ),
        tool_calls=_audits(promoted),
        now=NOW,
    )

    assert RecommendationValidationCode.ACTION_NOT_ALLOWED in denied.codes
    assert allowed.accepted is True
    assert RecommendationValidationCode.ACTION_NOT_ALLOWED in wrong_phase.codes


def test_service_returns_content_free_audit_for_valid_recommendation() -> None:
    request = invocation()
    model = _SuccessfulModel(recommendation(request))
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=model,
        evidence_reader=verified_evidence_reader(),
        clock=lambda: NOW,
    )

    response = asyncio.run(service.advise(request, authentication_context()))

    assert response.recommendation is not None
    assert response.audit.validation.accepted is True
    assert response.audit.fallback_code is None
    assert response.audit.prompt_version == PROMPT_VERSION
    assert tuple(call.tool_id for call in response.audit.tool_calls) == tuple(DiagnosticToolId)
    audit_text = response.audit.model_dump_json()
    assert "instruction authority" not in audit_text
    assert "chain-of-thought" not in audit_text
    assert "Bearer" not in audit_text


def test_current_audit_contract_decodes_legacy_prompt_metadata() -> None:
    request = invocation()
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=_SuccessfulModel(recommendation(request)),
        clock=lambda: NOW,
    )
    current = asyncio.run(service.advise(request, authentication_context())).audit
    payload = current.model_dump(mode="python")
    payload["prompt_version"] = PROMPT_VERSION_V1

    decoded = AdvisorInteractionAuditV1.model_validate(payload)

    assert decoded.prompt_version == PROMPT_VERSION_V1


def test_service_emits_only_the_current_prompt_version() -> None:
    request = invocation()

    with pytest.raises(ValueError, match="configuration is invalid"):
        ReadOnlyAdvisorService(
            authentication_policy=authentication_policy(),
            model=_LegacyPromptModel(recommendation(request)),
            clock=lambda: NOW,
        )


def test_service_uses_the_coordinator_bound_snapshot_without_an_extra_reader() -> None:
    request = invocation()
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=_SuccessfulModel(recommendation(request)),
        clock=lambda: NOW,
    )

    response = asyncio.run(service.advise(request, authentication_context()))

    assert response.audit.validation.accepted is True
    assert all(call.status is ToolCallStatus.SUCCEEDED for call in response.audit.tool_calls)


def test_service_discards_schema_valid_but_policy_invalid_output() -> None:
    request = invocation()
    unsafe = recommendation(request).model_copy(update={"root_id": "cgroot:" + "f" * 64})
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=_SuccessfulModel(unsafe),
        evidence_reader=verified_evidence_reader(),
        clock=lambda: NOW,
    )

    response = asyncio.run(service.advise(request, authentication_context()))

    assert response.recommendation is None
    assert response.audit.validation.accepted is False
    assert RecommendationValidationCode.ROOT_MISMATCH in response.audit.validation.codes
    assert response.audit.fallback_code is AdvisorFallbackCode.UNSAFE_RECOMMENDATION
    assert response.audit.structured_output_sha256 is not None


@pytest.mark.parametrize(
    ("failure", "fallback"),
    [
        (AdvisorModelFailureCode.QUOTA, AdvisorFallbackCode.QUOTA),
        (
            AdvisorModelFailureCode.MALFORMED_OUTPUT,
            AdvisorFallbackCode.MALFORMED_OUTPUT,
        ),
        (
            AdvisorModelFailureCode.MODEL_UNAVAILABLE,
            AdvisorFallbackCode.MODEL_UNAVAILABLE,
        ),
        (AdvisorModelFailureCode.TOOL_ERROR, AdvisorFallbackCode.TOOL_ERROR),
    ],
)
def test_service_maps_model_failures_to_side_effect_free_fallbacks(
    failure: AdvisorModelFailureCode,
    fallback: AdvisorFallbackCode,
) -> None:
    request = invocation()
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=_FailingModel(failure),
        evidence_reader=verified_evidence_reader(),
        clock=lambda: NOW,
    )

    response = asyncio.run(service.advise(request, authentication_context()))

    assert response.recommendation is None
    assert response.audit.fallback_code is fallback
    assert response.manual_next_step.endswith("deterministic_operator_commands_only")


def test_service_bounds_total_model_execution_time() -> None:
    request = invocation()
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=_SlowModel(recommendation(request)),
        evidence_reader=verified_evidence_reader(),
        timeout_seconds=0.01,
        clock=lambda: NOW,
    )

    response = asyncio.run(service.advise(request, authentication_context()))

    assert response.recommendation is None
    assert response.audit.fallback_code is AdvisorFallbackCode.TIMEOUT


def test_service_handles_a_non_contract_model_return_without_hashing_it() -> None:
    request = invocation()
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=_MalformedModel(recommendation(request)),
        evidence_reader=verified_evidence_reader(),
        clock=lambda: NOW,
    )

    response = asyncio.run(service.advise(request, authentication_context()))

    assert response.recommendation is None
    assert response.audit.structured_output_sha256 is None
    assert response.audit.fallback_code is AdvisorFallbackCode.MALFORMED_OUTPUT


def test_snapshot_expires_at_the_exact_expiry_second() -> None:
    request = invocation()
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=_SuccessfulModel(recommendation(request)),
        evidence_reader=verified_evidence_reader(),
        clock=lambda: datetime(2026, 8, 22, 10, 4, tzinfo=UTC),
    )

    response = asyncio.run(service.advise(request, authentication_context()))

    assert response.recommendation is None
    assert RecommendationValidationCode.EVIDENCE_STALE in response.audit.validation.codes


class _Transport:
    def __init__(self, response: AdvisorResponseV1) -> None:
        self._response = canonical_json_bytes(response)
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        return self._response


def test_coordinator_client_is_sealed_to_the_advisor_route() -> None:
    request = invocation()
    service = ReadOnlyAdvisorService(
        authentication_policy=authentication_policy(),
        model=_SuccessfulModel(recommendation(request)),
        evidence_reader=verified_evidence_reader(),
        clock=lambda: NOW,
    )
    response = asyncio.run(service.advise(request, authentication_context()))
    route = CoordinatorInternalRoute(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.COORDINATOR,
        service_role=ServiceRole.ADVISOR,
        audience=ADVISOR_AUDIENCE,
    )
    transport = _Transport(response)
    client = CoordinatorAdvisorClient(route=route, transport=transport)

    observed = asyncio.run(client.advise(request))

    assert observed == response
    assert transport.calls == [(route, canonical_json_bytes(request))]
