from __future__ import annotations

import pytest
from model_assistance_test_data import evidence_summary, invocation, recommendation, snapshot
from pydantic import ValidationError

from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.model_assistance import (
    MAX_TOOL_CALLS,
    MAX_TOOL_RESPONSE_BYTES,
    AdvisorRecommendationV1,
    DiagnosticEvidenceKind,
    DiagnosticEvidenceSummaryCode,
    DiagnosticEvidenceSummaryV1,
    DiagnosticToolId,
    EvidenceConsistency,
    RequestedOperatorAction,
    diagnostic_registry_v1,
)


def test_diagnostic_registry_is_the_exact_read_only_allowlist() -> None:
    registry = diagnostic_registry_v1()

    assert tuple(tool.tool_id for tool in registry.tools) == tuple(DiagnosticToolId)
    assert tuple(tool.evidence_source for tool in registry.tools) == tuple(
        DiagnosticEvidenceKind
    )
    assert len(registry.tools) == MAX_TOOL_CALLS
    assert all(tool.execution_identity == "controlgraph-advisor" for tool in registry.tools)
    assert all(tool.target_scope == "invocation_snapshot" for tool in registry.tools)
    assert all(tool.read_only and tool.redaction_required for tool in registry.tools)
    assert all(tool.max_response_bytes == MAX_TOOL_RESPONSE_BYTES for tool in registry.tools)
    assert all(tool.timeout_ms == 250 for tool in registry.tools)
    assert not any(
        forbidden in tool.tool_id.value
        for tool in registry.tools
        for forbidden in ("shell", "code", "query", "network", "sign", "mutate")
    )


def test_snapshot_binds_root_target_revisions_policy_and_six_evidence_classes() -> None:
    value = snapshot()

    assert value.root_id == f"cgroot:{value.root_sha256}"
    assert value.recovery_revision == value.stable_revision
    assert (value.stable_percent, value.candidate_percent) == (90, 10)
    assert tuple(item.evidence_kind for item in value.evidence_summaries) == tuple(
        DiagnosticEvidenceKind
    )
    assert len(
        {
            evidence_id
            for summary in value.evidence_summaries
            for evidence_id in summary.evidence_ids
        }
    ) == 6


@pytest.mark.parametrize(
    "changes",
    [
        {"root_id": "cgroot:" + "b" * 64},
        {"recovery_revision": "controlgraph-reference-target-candidate"},
        {"stable_percent": 80, "candidate_percent": 20},
        {"expires_at": "2026-08-22T10:06:00Z"},
    ],
)
def test_snapshot_rejects_unbound_or_out_of_policy_state(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        snapshot().model_copy(update=changes, deep=True).__class__.model_validate(
            {**snapshot().model_dump(mode="python"), **changes}
        )


def test_evidence_contract_has_no_free_form_capability_or_token_field() -> None:
    value = evidence_summary(DiagnosticEvidenceKind.ROOT, digest_character="a")
    with pytest.raises(ValidationError, match="Extra inputs"):
        DiagnosticEvidenceSummaryV1.model_validate(
            {
                **value.model_dump(mode="python"),
                "summary": "Bearer synthetic-secret-token-value",
            }
        )


def test_evidence_contract_rejects_a_summary_code_from_another_record_family() -> None:
    value = evidence_summary(DiagnosticEvidenceKind.ROOT, digest_character="a")
    with pytest.raises(ValidationError, match="evidence class"):
        DiagnosticEvidenceSummaryV1.model_validate(
            {
                **value.model_dump(mode="python"),
                "summary_code": DiagnosticEvidenceSummaryCode.HEALTH_EVIDENCE_VERIFIED,
            }
        )


def test_invocation_rejects_snapshot_digest_substitution() -> None:
    value = invocation()

    with pytest.raises(ValidationError, match="exact snapshot"):
        value.__class__.model_validate(
            {**value.model_dump(mode="python"), "snapshot_sha256": "f" * 64}
        )


def test_recommendation_schema_has_no_revision_or_mutation_authority_fields() -> None:
    value = recommendation(invocation())
    payload = value.model_dump(mode="python")
    payload["requested_revision"] = "controlgraph-reference-target-injected"

    with pytest.raises(ValidationError, match="Extra inputs"):
        AdvisorRecommendationV1.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("operator_review_required", False),
        ("deterministic_health_override", True),
    ],
)
def test_recommendation_rejects_changes_to_advisory_authority_flags(
    field: str,
    value: bool,
) -> None:
    payload = recommendation(invocation()).model_dump(mode="python")
    payload[field] = value

    with pytest.raises(ValidationError, match="advisory authority boundary"):
        AdvisorRecommendationV1.model_validate(payload)


def test_low_confidence_requires_explicit_manual_review() -> None:
    request = invocation()
    value = recommendation(request)
    payload = value.model_dump(mode="python")
    payload["confidence_basis_points"] = 6_999

    with pytest.raises(ValidationError, match="manual review"):
        AdvisorRecommendationV1.model_validate(payload)

    manual = recommendation(
        request,
        action=RequestedOperatorAction.MANUAL_REVIEW,
        confidence_basis_points=0,
    )
    assert manual.manual_review_reason is not None


def test_request_digest_changes_with_evidence_consistency() -> None:
    consistent = invocation()
    incomplete = invocation(consistency=EvidenceConsistency.INCOMPLETE)

    assert canonical_sha256(consistent) != canonical_sha256(incomplete)


def test_snapshot_allows_immutable_root_evidence_to_predate_dynamic_freshness() -> None:
    value = snapshot()
    payload = value.model_dump(mode="python")
    payload["root_summary"]["observed_at"] = "2025-08-22T09:59:00Z"

    validated = value.__class__.model_validate(payload)

    assert validated.root_summary.observed_at == "2025-08-22T09:59:00Z"
