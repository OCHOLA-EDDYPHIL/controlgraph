from __future__ import annotations

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.model_assistance import (
    ADVISOR_INVOCATION_REQUEST_V1,
    ADVISOR_RECOMMENDATION_V1,
    DIAGNOSTIC_EVIDENCE_SUMMARY_V1,
    DIAGNOSTIC_SNAPSHOT_V1,
    VERIFIED_DIAGNOSTIC_EVIDENCE_V1,
    AdvisorInvocationRequestV1,
    AdvisorRecommendationV1,
    AdvisoryHealth,
    DiagnosticEvidenceKind,
    DiagnosticEvidenceSummaryCode,
    DiagnosticEvidenceSummaryV1,
    DiagnosticFindingV1,
    DiagnosticSnapshotV1,
    EvidenceCitationV1,
    EvidenceConsistency,
    RequestedOperatorAction,
    RolloutPhase,
    VerifiedDiagnosticEvidenceV1,
)
from controlgraph_canary.contracts.models import TargetBinding

PROJECT_ID = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
ADVISOR_AUDIENCE = (
    f"https://controlgraph-advisor-{PROJECT_NUMBER}.us-central1.run.app"
)


def target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT_ID,
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
    )


def evidence_summary(
    kind: DiagnosticEvidenceKind,
    *,
    digest_character: str,
) -> DiagnosticEvidenceSummaryV1:
    summary_code = dict(
        zip(
            tuple(DiagnosticEvidenceKind),
            tuple(DiagnosticEvidenceSummaryCode),
            strict=True,
        )
    )[kind]
    return DiagnosticEvidenceSummaryV1(
        schema_version=DIAGNOSTIC_EVIDENCE_SUMMARY_V1,
        evidence_kind=kind,
        evidence_ids=(f"{kind.value}-record-1",),
        source_sha256=digest_character * 64,
        observed_at="2026-08-22T09:59:00Z",
        fresh_until="2026-08-22T10:05:00Z",
        summary_code=summary_code,
        redacted=True,
        untrusted_model_context=True,
    )


def snapshot(
    *,
    consistency: EvidenceConsistency = EvidenceConsistency.CONSISTENT,
    phase: RolloutPhase = RolloutPhase.CANARY,
    health: AdvisoryHealth = AdvisoryHealth.HEALTHY,
    terminal_health: bool = False,
    authority_revoked: bool = False,
    stable_percent: int = 90,
    candidate_percent: int = 10,
) -> DiagnosticSnapshotV1:
    return DiagnosticSnapshotV1(
        schema_version=DIAGNOSTIC_SNAPSHOT_V1,
        snapshot_id="snapshot-1",
        target=target(),
        root_id=f"cgroot:{'a' * 64}",
        root_sha256="a" * 64,
        current_epoch=3,
        stable_revision="controlgraph-reference-target-stable",
        candidate_revision="controlgraph-reference-target-candidate",
        recovery_revision="controlgraph-reference-target-stable",
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        rollout_phase=phase,
        authority_revoked=authority_revoked,
        health=health,
        terminal_health=terminal_health,
        health_policy_sha256="b" * 64,
        evidence_consistency=consistency,
        assembled_at="2026-08-22T10:00:00Z",
        expires_at="2026-08-22T10:04:00Z",
        root_summary=evidence_summary(
            DiagnosticEvidenceKind.ROOT,
            digest_character="1",
        ),
        target_summary=evidence_summary(DiagnosticEvidenceKind.TARGET, digest_character="2"),
        health_summary=evidence_summary(DiagnosticEvidenceKind.HEALTH, digest_character="3"),
        receipt_summary=evidence_summary(DiagnosticEvidenceKind.RECEIPT, digest_character="4"),
        timeline_summary=evidence_summary(DiagnosticEvidenceKind.TIMELINE, digest_character="5"),
        verifier_summary=evidence_summary(DiagnosticEvidenceKind.VERIFIER, digest_character="6"),
    )


class VerifiedEvidenceReader:
    def __init__(self) -> None:
        self.calls: list[DiagnosticEvidenceKind] = []

    async def read_verified(
        self,
        request: AdvisorInvocationRequestV1,
        evidence_kind: DiagnosticEvidenceKind,
    ) -> VerifiedDiagnosticEvidenceV1:
        self.calls.append(evidence_kind)
        summary = {
            item.evidence_kind: item for item in request.snapshot.evidence_summaries
        }[evidence_kind]
        return VerifiedDiagnosticEvidenceV1(
            schema_version=VERIFIED_DIAGNOSTIC_EVIDENCE_V1,
            evidence=summary,
            durable_record_sha256=summary.source_sha256,
            signature_sha256="d" * 64,
            signing_key_version=(
                f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
                "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
            ),
            verified_at="2026-08-22T10:00:00Z",
            verification_status="verified",
        )


def verified_evidence_reader() -> VerifiedEvidenceReader:
    return VerifiedEvidenceReader()


def invocation(**snapshot_overrides: object) -> AdvisorInvocationRequestV1:
    selected = snapshot(**snapshot_overrides)
    return AdvisorInvocationRequestV1(
        schema_version=ADVISOR_INVOCATION_REQUEST_V1,
        correlation_id="correlation-1",
        requested_at=selected.assembled_at,
        snapshot=selected,
        snapshot_sha256=canonical_sha256(selected),
    )


def recommendation(
    request: AdvisorInvocationRequestV1,
    *,
    action: RequestedOperatorAction = RequestedOperatorAction.WAIT,
    confidence_basis_points: int = 9_000,
    citation_kind: DiagnosticEvidenceKind = DiagnosticEvidenceKind.ROOT,
) -> AdvisorRecommendationV1:
    summary_by_kind = {
        item.evidence_kind: item for item in request.snapshot.evidence_summaries
    }
    cited = summary_by_kind[citation_kind]
    return AdvisorRecommendationV1(
        schema_version=ADVISOR_RECOMMENDATION_V1,
        recommendation_id="recommendation-1",
        snapshot_sha256=request.snapshot_sha256,
        target=request.snapshot.target,
        root_id=request.snapshot.root_id,
        current_epoch=request.snapshot.current_epoch,
        findings=(
            DiagnosticFindingV1(
                statement="The cited records support this bounded operator review.",
                citations=(
                    EvidenceCitationV1(
                        evidence_kind=citation_kind,
                        evidence_id=cited.evidence_ids[0],
                        source_sha256=cited.source_sha256,
                    ),
                ),
            ),
        ),
        assumptions=(),
        uncertainties=("The model does not establish authority or health.",),
        confidence_basis_points=confidence_basis_points,
        requested_operator_action=action,
        manual_review_reason=(
            "Evidence requires deterministic operator review."
            if action is RequestedOperatorAction.MANUAL_REVIEW
            else None
        ),
        operator_review_required=True,
        authority_effect="none",
        deterministic_health_override=False,
    )


def authentication_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.ADVISOR,
        path=protected_path(ServiceRole.ADVISOR),
        audience=ADVISOR_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.COORDINATOR,
            email=f"controlgraph-coordinator@{PROJECT_ID}.iam.gserviceaccount.com",
            subject=SUBJECT,
        ),
    )


def authentication_context() -> AuthenticationContext:
    policy = authentication_policy()
    return AuthenticationContext(
        role=CallerRole.COORDINATOR,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=1_776_500_000,
        expires_at=1_776_500_600,
    )
