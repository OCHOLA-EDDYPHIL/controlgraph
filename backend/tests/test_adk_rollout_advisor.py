from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import pytest
from google.adk.telemetry.context import ContentCapturingMode
from google.genai import _transformers, types
from model_assistance_test_data import (
    invocation,
    recommendation,
    verified_evidence_reader,
)

from controlgraph_canary.application.model_assistance import (
    AdvisorModelFailure,
    AdvisorModelFailureCode,
    InvocationDiagnosticRegistry,
)
from controlgraph_canary.contracts.model_assistance import (
    MAX_LLM_CALLS,
    MAX_MODEL_OUTPUT_TOKENS,
    PROMPT_VERSION,
    DiagnosticToolId,
)
from controlgraph_canary.integrations.adk import rollout_advisor
from controlgraph_canary.integrations.adk.rollout_advisor import GoogleAdkRolloutAdvisor


class _SessionService:
    async def create_session(self, **kwargs: object) -> object:
        _FakeRunner.session_arguments = kwargs
        return object()


class _Event:
    def __init__(self, output: str) -> None:
        self.content = types.Content(
            role="model",
            parts=[types.Part.from_text(text=output)],
        )

    def is_final_response(self) -> bool:
        return True


class _FakeRunner:
    output = ""
    created_agent: object | None = None
    run_arguments: ClassVar[dict[str, Any]] = {}
    session_arguments: ClassVar[dict[str, object]] = {}

    def __init__(self, *, agent: object, app_name: str) -> None:
        self.agent = agent
        self.app_name = app_name
        self.session_service = _SessionService()
        _FakeRunner.created_agent = agent

    async def run_async(self, **kwargs: Any):  # type: ignore[no-untyped-def]
        _FakeRunner.run_arguments = kwargs
        message = kwargs["new_message"]
        text = message.parts[0].text
        assert isinstance(text, str)
        snapshot_sha256 = text.rsplit("=", maxsplit=1)[1].removesuffix(".")
        for tool in self.agent.tools:
            await tool(snapshot_sha256=snapshot_sha256)
        yield _Event(self.output)


def test_recommendation_schema_is_accepted_by_the_pinned_genai_transformer() -> None:
    schema = rollout_advisor._vertex_response_schema()

    _transformers.process_schema(schema, client=None)

    properties = schema["properties"]
    assert properties["operator_review_required"]["type"] == "boolean"
    assert properties["deterministic_health_override"]["type"] == "boolean"
    assert properties["confidence_basis_points"]["maximum"] == 10_000
    pending: list[object] = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            assert "minItems" not in value
            assert "maxItems" not in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)


def test_adk_runner_exposes_only_six_bounded_snapshot_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = invocation()
    registry = InvocationDiagnosticRegistry(
        request,
        evidence_reader=verified_evidence_reader(),
    )
    _FakeRunner.output = recommendation(request).model_dump_json()
    monkeypatch.setattr(rollout_advisor, "InMemoryRunner", _FakeRunner)
    advisor = GoogleAdkRolloutAdvisor(project_id=request.snapshot.target.project_id)

    result = asyncio.run(advisor.recommend(request, registry))

    assert result == recommendation(request)
    assert advisor.prompt_version == PROMPT_VERSION
    agent = _FakeRunner.created_agent
    assert agent is not None
    assert tuple(tool.__name__ for tool in agent.tools) == tuple(
        tool_id.value for tool_id in DiagnosticToolId
    )
    canonical_tools = asyncio.run(agent.canonical_tools())
    assert tuple(tool.name for tool in canonical_tools) == tuple(
        tool_id.value for tool_id in DiagnosticToolId
    )
    assert all(tool._get_declaration() is not None for tool in canonical_tools)
    assert agent.sub_agents == []
    assert agent.code_executor is None
    assert agent.output_schema == rollout_advisor._vertex_response_schema()
    assert "receipt work_epoch" in agent.instruction
    assert "timeline evidence" in agent.instruction
    assert "target or verifier" in agent.instruction
    assert rollout_advisor._STALE_CAUSAL_PATH_TEMPLATE in agent.instruction
    assert "Do not add prose to the clause or split those citations" in agent.instruction
    assert agent.model.client_kwargs["enterprise"] is True
    assert agent.model.client_kwargs["project"] == request.snapshot.target.project_id
    assert agent.model.client_kwargs["location"] == "global"
    assert "api_key" not in agent.model.client_kwargs
    assert agent.model.client_kwargs["http_options"].timeout == 19_000
    run_config = _FakeRunner.run_arguments["run_config"]
    assert run_config.max_llm_calls == MAX_LLM_CALLS
    assert run_config.telemetry.capture_message_content is ContentCapturingMode.NO_CONTENT
    assert agent.generate_content_config.max_output_tokens == MAX_MODEL_OUTPUT_TOKENS
    assert agent.generate_content_config.temperature == 0
    assert (
        agent.generate_content_config.thinking_config.thinking_level is types.ThinkingLevel.MINIMAL
    )


def test_adk_runner_rejects_malformed_or_oversized_public_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = invocation()
    monkeypatch.setattr(rollout_advisor, "InMemoryRunner", _FakeRunner)
    advisor = GoogleAdkRolloutAdvisor(project_id=request.snapshot.target.project_id)

    _FakeRunner.output = "{" + "x" * 17_000
    with pytest.raises(AdvisorModelFailure) as failure:
        asyncio.run(
            advisor.recommend(
                request,
                InvocationDiagnosticRegistry(
                    request,
                    evidence_reader=verified_evidence_reader(),
                ),
            )
        )

    assert failure.value.code is AdvisorModelFailureCode.MALFORMED_OUTPUT


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("project_id", "shared-project"),
        ("model_id", "gemini-flash-latest"),
        ("model_location", "us-central1"),
        ("api_version", "v1beta1"),
        ("max_llm_calls", MAX_LLM_CALLS + 1),
        ("max_output_tokens", MAX_MODEL_OUTPUT_TOKENS + 1),
    ],
)
def test_adk_runner_rejects_unbounded_configuration(field: str, value: object) -> None:
    values = {"project_id": "controlgraph-canary-abc123", field: value}

    with pytest.raises(ValueError, match="fixed bounds"):
        GoogleAdkRolloutAdvisor(**values)  # type: ignore[arg-type]
