from __future__ import annotations

from dataclasses import dataclass

from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityLineageAnchorV1,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    RolloutHealthPolicyV1,
    RolloutHealthPolicyV2,
    RolloutPlanV1,
    RolloutRootContentV2,
    RolloutRootContentV3,
    RolloutRootV2,
    RolloutRootV3,
    RootActionGrantV1,
    RootAuthorityBoundsV1,
    RootCreationEvidenceSubjectV1,
    RootCreationResultV1,
    RootCreationResultV2,
    SignedEvidenceEventV1,
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
    canonical_sha256,
    capability_lineage_anchor,
    create_rollout_health_policy_v2,
    create_rollout_root,
    create_rollout_root_v3,
    encode_base64url,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
    root_creation_request_sha256,
)
from controlgraph_canary.contracts.storage import (
    SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
    ServiceClaimRecord,
    ServiceClaimStatus,
)

PROJECT = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
SERVICE = "controlgraph-reference-target"
STABLE = f"{SERVICE}-stable-v1"
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64


@dataclass(frozen=True, slots=True)
class RootV2Records:
    root: RolloutRootV2
    service_claim: ServiceClaimRecord
    authority: EpochAuthorityRecord
    lineage_anchor: CapabilityLineageAnchorV1
    signed_evidence: SignedEvidenceEventV1
    creation_result: RootCreationResultV1


@dataclass(frozen=True, slots=True)
class RootV3Records:
    root: RolloutRootV3
    service_claim: ServiceClaimRecord
    authority: EpochAuthorityRecord
    lineage_anchor: CapabilityLineageAnchorV1
    signed_evidence: SignedEvidenceEventV1
    creation_result: RootCreationResultV2


def root_v2_target(*, project_id: str = PROJECT) -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=project_id,
        region="us-central1",
        environment="nonprod",
        service_name=SERVICE,
    )


def _grant(
    action: CapabilityAction,
    *,
    project_id: str,
) -> RootActionGrantV1:
    role = "recovery" if action is CapabilityAction.RECOVER_STABLE else "executor"
    stable_percent, candidate_percent, maximum_attempts = {
        CapabilityAction.APPLY_CANARY: (90, 10, None),
        CapabilityAction.PROMOTE_CANDIDATE: (0, 100, None),
        CapabilityAction.RECOVER_STABLE: (100, 0, 1),
    }[action]
    return RootActionGrantV1(
        schema_version="controlgraph.root-action-grant/v1",
        action=action,
        subject_identity=f"controlgraph-{role}@{project_id}.iam.gserviceaccount.com",
        audience=f"https://controlgraph-{role}-{PROJECT_NUMBER}.us-central1.run.app",
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        maximum_attempts=maximum_attempts,
    )


def make_root_v2_records(
    *,
    project_id: str = PROJECT,
    variant: int = 1,
) -> RootV2Records:
    if not 1 <= variant <= 9:
        raise ValueError("test root variant is out of range")
    target = root_v2_target(project_id=project_id)
    candidate = f"{SERVICE}-candidate-v{variant}"
    candidate_digest = str(variant + 1) * 64
    request_id = f"request-root-{variant:03d}"
    idempotency_key = f"root-create-{variant:03d}"
    evidence_id = f"evidence-root-{variant:03d}"
    operator = "operator@example.test"
    operator_subject = "123456789012345678901"
    approved_at = "2026-08-19T12:01:00Z"
    created_at = "2026-08-19T12:01:01Z"
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=target,
        stable_revision=STABLE,
        traffic=(TrafficAllocation(revision=STABLE, percent=100),),
        concurrency=8,
        service_generation=7,
        provider_etag="stable-etag-7",
        configuration_sha256=ZERO_DIGEST,
        stable_revision_configuration_sha256=ONE_DIGEST,
        captured_at="2026-08-19T12:00:00Z",
        captured_by=f"controlgraph-verifier@{project_id}.iam.gserviceaccount.com",
    )
    policy = RolloutHealthPolicyV1(
        schema_version="controlgraph.rollout-health-policy/v1",
        input_schema_version="controlgraph.health-input/v1",
        evaluation_window_seconds=60,
        minimum_request_count=100,
        maximum_error_rate_basis_points=100,
        maximum_p95_latency_ms=500,
        minimum_probe_count=10,
        minimum_probe_success_basis_points=9_900,
        healthy_consecutive_windows=2,
        unhealthy_consecutive_windows=2,
        window_semantics="HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE",
        incomplete_data_action="INDETERMINATE_NO_MUTATION",
        late_data_action="INDETERMINATE_NO_MUTATION",
        duplicate_data_action="REJECT",
    )
    plan = RolloutPlanV1(
        schema_version="controlgraph.rollout-plan/v1",
        target=target,
        stable_snapshot_sha256=canonical_sha256(snapshot),
        stable_revision=STABLE,
        stable_revision_configuration_sha256=ONE_DIGEST,
        candidate_revision=candidate,
        candidate_revision_configuration_sha256=candidate_digest,
        concurrency=snapshot.concurrency,
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=canonical_sha256(policy),
        maximum_recovery_attempts=1,
        initial_epoch=1,
    )
    capability_key = (
        f"projects/{project_id}/locations/us-central1/keyRings/controlgraph-signing/"
        "cryptoKeys/capability-signing/cryptoKeyVersions/1"
    )
    evidence_key = (
        f"projects/{project_id}/locations/us-central1/keyRings/controlgraph-signing/"
        "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
    )
    bounds = RootAuthorityBoundsV1(
        schema_version="controlgraph.root-authority-bounds/v1",
        target=target,
        stable_revision=STABLE,
        stable_revision_configuration_sha256=ONE_DIGEST,
        candidate_revision=candidate,
        candidate_revision_configuration_sha256=candidate_digest,
        concurrency=plan.concurrency,
        plan_sha256=canonical_sha256(plan),
        capability_signing_key_version=capability_key,
        issuer_identity=f"controlgraph-issuer@{project_id}.iam.gserviceaccount.com",
        executor_identity=f"controlgraph-executor@{project_id}.iam.gserviceaccount.com",
        recovery_identity=f"controlgraph-recovery@{project_id}.iam.gserviceaccount.com",
        executor_audience=(
            f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        recovery_audience=(
            f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        maximum_capability_lifetime_seconds=600,
        maximum_recovery_attempts=1,
        apply_canary=_grant(CapabilityAction.APPLY_CANARY, project_id=project_id),
        promote_candidate=_grant(
            CapabilityAction.PROMOTE_CANDIDATE,
            project_id=project_id,
        ),
        recover_stable=_grant(CapabilityAction.RECOVER_STABLE, project_id=project_id),
    )
    root = create_rollout_root(
        RolloutRootContentV2(
            schema_version="controlgraph.rollout-root-content/v2",
            target=target,
            stable_snapshot=snapshot,
            health_policy=policy,
            rollout_plan=plan,
            authority_bounds=bounds,
            evidence_signing_key_version=evidence_key,
            approved_by=operator,
            approved_by_subject=operator_subject,
            approved_at=approved_at,
        )
    )
    stable_target_digest = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=target,
            stable_revision=STABLE,
            candidate_revision=candidate,
            stable_percent=100,
            candidate_percent=0,
            concurrency=plan.concurrency,
        )
    )
    candidate_target_digest = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=target,
            stable_revision=STABLE,
            candidate_revision=candidate,
            stable_percent=0,
            candidate_percent=100,
            concurrency=plan.concurrency,
        )
    )
    claim = ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v2",
        target=target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        stable_revision=STABLE,
        candidate_revision=candidate,
        initial_epoch=1,
        baseline_service_generation=snapshot.service_generation,
        baseline_configuration_sha256=snapshot.configuration_sha256,
        baseline_revision_configuration_sha256=ONE_DIGEST,
        candidate_revision_configuration_sha256=candidate_digest,
        stable_target_configuration_sha256=stable_target_digest,
        candidate_target_configuration_sha256=candidate_target_digest,
        operator_owner=operator,
        workload_creator="controlgraph.api/v1",
        terminal_release_condition=SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
        status=ServiceClaimStatus.ACTIVE,
        claim_request_id=request_id,
        claim_evidence_id=evidence_id,
        claimed_at=created_at,
        release_fence_epoch=None,
        release_fence_authority_revision=None,
        release_fenced_by=None,
        release_fence_request_id=None,
        release_fence_evidence_id=None,
        release_fenced_at=None,
        released_by=None,
        release_request_id=None,
        release_evidence_id=None,
        released_at=None,
        terminal_root_proof=None,
        target_classification_proof=None,
    )
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=target,
        current_epoch=1,
        previous_epoch=None,
        revision=0,
        cause=EpochChangeCause.ROOT_CREATED,
        changed_by=operator,
        request_id=request_id,
        evidence_id=evidence_id,
        changed_at=created_at,
    )
    anchor = capability_lineage_anchor(root)
    request_digest = root_creation_request_sha256(
        root=root,
        request_id=request_id,
        idempotency_key=idempotency_key,
        operator_identity=operator,
        operator_subject=operator_subject,
    )
    anchor_digest = canonical_sha256(anchor)
    claim_digest = canonical_sha256(claim)
    authority_digest = canonical_sha256(authority)
    subject = RootCreationEvidenceSubjectV1(
        schema_version="controlgraph.root-creation-evidence-subject/v1",
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        request_sha256=request_digest,
        created_at=created_at,
        service_claim_id=canonical_sha256(target),
        service_claim_sha256=claim_digest,
        authority_id=root.root_id,
        authority_sha256=authority_digest,
        lineage_anchor_id=f"cganchor:{anchor_digest}",
        lineage_anchor_sha256=anchor_digest,
        evidence_id=evidence_id,
    )
    event = EvidenceEvent(
        schema_version="controlgraph.evidence-event/v1",
        evidence_id=evidence_id,
        sequence=0,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=target,
        epoch=1,
        kind=EvidenceKind.ROOT_CREATED,
        actor=operator,
        request_id=request_id,
        receipt_id=None,
        occurred_at=created_at,
        subject_sha256=canonical_sha256(subject),
        previous_event_sha256=None,
        reason_code=None,
        provider_operation=None,
        target_configuration_sha256=snapshot.configuration_sha256,
    )
    signed_evidence = SignedEvidenceEventV1(
        schema_version="controlgraph.signed-evidence-event/v1",
        event=event,
        purpose="EVIDENCE",
        signing_key_version=evidence_key,
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=evidence_payload_sha256(event),
        signing_input_sha256=evidence_signing_input_sha256(event, evidence_key),
        signature=encode_base64url(b"synthetic-p256-signature"),
    )
    result = RootCreationResultV1(
        schema_version="controlgraph.root-creation-result/v1",
        outcome="CREATED",
        request_id=request_id,
        idempotency_key=idempotency_key,
        operator_identity=operator,
        operator_subject=operator_subject,
        request_sha256=request_digest,
        created_at=created_at,
        winner_request_id=request_id,
        winner_idempotency_key=idempotency_key,
        winner_operator_identity=operator,
        winner_operator_subject=operator_subject,
        winner_request_sha256=request_digest,
        winner_service_claim_id=canonical_sha256(target),
        winner_service_claim_sha256=claim_digest,
        winner_authority_id=root.root_id,
        winner_authority_sha256=authority_digest,
        winner_lineage_anchor_id=f"cganchor:{anchor_digest}",
        winner_lineage_anchor_sha256=anchor_digest,
        winner_evidence_id=evidence_id,
        winner_evidence_sha256=canonical_sha256(signed_evidence),
        root=root,
        initial_authority=authority,
        lineage_anchor=anchor,
        evidence_subject=subject,
        signed_evidence=signed_evidence,
    )
    return RootV2Records(
        root=root,
        service_claim=claim,
        authority=authority,
        lineage_anchor=anchor,
        signed_evidence=signed_evidence,
        creation_result=result,
    )


def make_root_v3_records(
    *,
    project_id: str = PROJECT,
    variant: int = 1,
) -> RootV3Records:
    """Build the current root family from the historical fixture coordinates."""

    historical = make_root_v2_records(project_id=project_id, variant=variant)
    historical_root = historical.root
    historical_result = historical.creation_result
    policy: RolloutHealthPolicyV2 = create_rollout_health_policy_v2()
    plan = RolloutPlanV1.model_validate(
        {
            **historical_root.content.rollout_plan.model_dump(mode="python"),
            "health_policy_sha256": canonical_sha256(policy),
        }
    )
    bounds = RootAuthorityBoundsV1.model_validate(
        {
            **historical_root.content.authority_bounds.model_dump(mode="python"),
            "plan_sha256": canonical_sha256(plan),
        }
    )
    root = create_rollout_root_v3(
        RolloutRootContentV3(
            schema_version="controlgraph.rollout-root-content/v3",
            target=historical_root.content.target,
            stable_snapshot=historical_root.content.stable_snapshot,
            health_policy=policy,
            rollout_plan=plan,
            authority_bounds=bounds,
            evidence_signing_key_version=(
                historical_root.content.evidence_signing_key_version
            ),
            approved_by=historical_root.content.approved_by,
            approved_by_subject=historical_root.content.approved_by_subject,
            approved_at=historical_root.content.approved_at,
        )
    )
    claim = ServiceClaimRecord.model_validate(
        {
            **historical.service_claim.model_dump(mode="python"),
            "root_id": root.root_id,
            "root_sha256": root.root_sha256,
        }
    )
    authority = EpochAuthorityRecord.model_validate(
        {
            **historical.authority.model_dump(mode="python"),
            "root_id": root.root_id,
            "root_sha256": root.root_sha256,
        }
    )
    anchor = capability_lineage_anchor(root)
    request_digest = root_creation_request_sha256(
        root=root,
        request_id=historical_result.request_id,
        idempotency_key=historical_result.idempotency_key,
        operator_identity=historical_result.operator_identity,
        operator_subject=historical_result.operator_subject,
    )
    anchor_digest = canonical_sha256(anchor)
    subject = RootCreationEvidenceSubjectV1.model_validate(
        {
            **historical_result.evidence_subject.model_dump(mode="python"),
            "root_id": root.root_id,
            "root_sha256": root.root_sha256,
            "request_sha256": request_digest,
            "service_claim_sha256": canonical_sha256(claim),
            "authority_id": root.root_id,
            "authority_sha256": canonical_sha256(authority),
            "lineage_anchor_id": f"cganchor:{anchor_digest}",
            "lineage_anchor_sha256": anchor_digest,
        }
    )
    event = EvidenceEvent.model_validate(
        {
            **historical.signed_evidence.event.model_dump(mode="python"),
            "root_id": root.root_id,
            "root_sha256": root.root_sha256,
            "subject_sha256": canonical_sha256(subject),
        }
    )
    evidence_key = root.content.evidence_signing_key_version
    signed_evidence = SignedEvidenceEventV1.model_validate(
        {
            **historical.signed_evidence.model_dump(mode="python"),
            "event": event,
            "payload_sha256": evidence_payload_sha256(event),
            "signing_input_sha256": evidence_signing_input_sha256(
                event,
                evidence_key,
            ),
        }
    )
    result = RootCreationResultV2.model_validate(
        {
            **historical_result.model_dump(mode="python"),
            "schema_version": "controlgraph.root-creation-result/v2",
            "request_sha256": request_digest,
            "winner_request_sha256": request_digest,
            "winner_service_claim_sha256": canonical_sha256(claim),
            "winner_authority_id": root.root_id,
            "winner_authority_sha256": canonical_sha256(authority),
            "winner_lineage_anchor_id": f"cganchor:{anchor_digest}",
            "winner_lineage_anchor_sha256": anchor_digest,
            "winner_evidence_sha256": canonical_sha256(signed_evidence),
            "root": root,
            "initial_authority": authority,
            "lineage_anchor": anchor,
            "evidence_subject": subject,
            "signed_evidence": signed_evidence,
        }
    )
    return RootV3Records(
        root=root,
        service_claim=claim,
        authority=authority,
        lineage_anchor=anchor,
        signed_evidence=signed_evidence,
        creation_result=result,
    )
