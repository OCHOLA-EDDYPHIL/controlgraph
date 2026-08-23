from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from model_assistance_test_data import (
    authentication_context,
    authentication_policy,
    invocation,
    recommendation,
    verified_evidence_reader,
)
from pydantic import ValidationError

from controlgraph_canary.application.model_assistance import (
    InvocationDiagnosticRegistry,
    ReadOnlyAdvisorService,
    validate_recommendation,
)
from controlgraph_canary.contracts.model_assistance import (
    AdvisorFallbackCode,
    AdvisorInvocationRequestV1,
    AdvisorRecommendationV1,
    EvidenceCitationV1,
    EvidenceConsistency,
    RecommendationValidationCode,
    RequestedOperatorAction,
)
from controlgraph_canary.contracts.models import TargetBinding

_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "model-assistance"
    / "v1"
    / "validation-replays.json"
)


async def _call_tools(
    registry: InvocationDiagnosticRegistry,
    request_sha256: str,
) -> None:
    for tool in registry.registry.tools:
        await registry.read(tool.tool_id, request_sha256)


class _InjectedProposalModel:
    calls = 0

    @property
    def model_id(self) -> Literal["gemini-3.5-flash"]:
        return "gemini-3.5-flash"

    @property
    def model_location(self) -> Literal["global"]:
        return "global"

    @property
    def prompt_version(self) -> Literal["controlgraph.rollout-advisor-prompt/v1"]:
        return "controlgraph.rollout-advisor-prompt/v1"

    async def recommend(
        self,
        request: AdvisorInvocationRequestV1,
        tools: InvocationDiagnosticRegistry,
    ) -> AdvisorRecommendationV1:
        type(self).calls += 1
        await _call_tools(tools, request.snapshot_sha256)
        return recommendation(request).model_copy(
            update={
                "requested_operator_action": (
                    RequestedOperatorAction.REQUEST_NEW_OPERATOR_APPROVED_ROLLOUT
                )
            }
        )


def test_validation_replay_cases_remain_deterministic() -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "controlgraph.advisor-validation-replays/v1"
    assert len({case["case_id"] for case in payload["cases"]}) == len(payload["cases"])

    for case in payload["cases"]:
        request_arguments: dict[str, object] = {
            "consistency": (
                EvidenceConsistency.CONFLICTING
                if case["scenario"] == "conflicting_evidence"
                else EvidenceConsistency.CONSISTENT
            )
        }
        request = invocation(**request_arguments)
        candidate = recommendation(request)
        now = datetime(2026, 8, 22, 10, 1, tzinfo=UTC)
        if case["scenario"] == "unknown_citation":
            finding = candidate.findings[0]
            bad_citation = EvidenceCitationV1(
                evidence_kind=finding.citations[0].evidence_kind,
                evidence_id="unknown-record",
                source_sha256=finding.citations[0].source_sha256,
            )
            candidate = candidate.model_copy(
                update={
                    "findings": (
                        finding.model_copy(update={"citations": (bad_citation,)}),
                    )
                }
            )
        elif case["scenario"] == "cross_target":
            candidate = candidate.model_copy(
                update={
                    "target": TargetBinding(
                        schema_version="controlgraph.target-binding/v1",
                        project_id="controlgraph-canary-other1",
                        region="us-central1",
                        environment="nonprod",
                        service_name="controlgraph-reference-target",
                    )
                }
            )
        elif case["scenario"] == "stale_snapshot":
            now = datetime(2026, 8, 22, 10, 4, 1, tzinfo=UTC)
        elif case["scenario"] == "unsupported_mutation":
            invalid = candidate.model_dump(mode="python")
            invalid["requested_operator_action"] = "delete_service"
            try:
                AdvisorRecommendationV1.model_validate(invalid)
            except ValidationError:
                actual = "schema_rejected"
            else:
                actual = "unexpected_acceptance"
            assert actual == case["expected_code"], case["case_id"]
            continue

        elif case["scenario"] == "injected_tool_instruction":
            model = _InjectedProposalModel()
            response = asyncio.run(
                ReadOnlyAdvisorService(
                    authentication_policy=authentication_policy(),
                    model=model,
                    evidence_reader=verified_evidence_reader(),
                    clock=lambda now=now: now,
                ).advise(request, authentication_context())
            )
            assert response.audit.fallback_code is AdvisorFallbackCode.UNSAFE_RECOMMENDATION
            assert _InjectedProposalModel.calls > 0
            assert response.recommendation is None
            assert case["expected_code"] == "unsafe_recommendation"
            continue

        registry = InvocationDiagnosticRegistry(
            request,
            evidence_reader=verified_evidence_reader(),
        )

        asyncio.run(_call_tools(registry, request.snapshot_sha256))
        result = validate_recommendation(
            request,
            candidate,
            tool_calls=registry.calls,
            now=now,
        )
        assert result.accepted == case["expected_accepted"], case["case_id"]
        assert RecommendationValidationCode(case["expected_code"]) in result.codes
