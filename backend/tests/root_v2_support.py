from __future__ import annotations

from dataclasses import dataclass

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.cloud_run import (
    rollout_root_v2_target_configuration_sha256,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
)
from controlgraph_canary.contracts.root_creation import (
    CAPABILITY_LINEAGE_ANCHOR_V1,
    ROLLOUT_HEALTH_POLICY_V1,
    ROLLOUT_PLAN_V1,
    ROLLOUT_ROOT_CONTENT_V2,
    ROOT_ACTION_GRANT_V1,
    ROOT_AUTHORITY_BOUNDS_V1,
    CapabilityLineageAnchorV1,
    RolloutHealthPolicyV1,
    RolloutPlanV1,
    RolloutRootContentV2,
    RolloutRootV2,
    RootActionGrantV1,
    RootAuthorityBoundsV1,
    capability_lineage_anchor,
    create_rollout_root,
)
from controlgraph_canary.contracts.storage import (
    SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
    SERVICE_CLAIM_V2,
    ServiceClaimRecord,
    ServiceClaimStatus,
)

ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
DEFAULT_PROJECT_ID = "controlgraph-canary-abc123"
DEFAULT_PROJECT_NUMBER = "123456789012"


@dataclass(frozen=True, slots=True)
class RootBundle:
    root: StoredRecord[RolloutRootV2]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]
    lineage_anchor: StoredRecord[CapabilityLineageAnchorV1]


def target_binding(
    *,
    project_id: str = DEFAULT_PROJECT_ID,
    region: str = "us-central1",
    environment: str = "nonprod",
    service_name: str = "controlgraph-reference-target",
) -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=project_id,
        region=region,
        environment=environment,
        service_name=service_name,
    )


def service_audience(
    role: str,
    *,
    project_number: str = DEFAULT_PROJECT_NUMBER,
) -> str:
    return f"https://controlgraph-{role}-{project_number}.us-central1.run.app"


def capability_key_version(project_id: str = DEFAULT_PROJECT_ID) -> str:
    return (
        f"projects/{project_id}/locations/us-central1/keyRings/controlgraph-signing/"
        "cryptoKeys/capability-signing/cryptoKeyVersions/1"
    )


def evidence_key_version(project_id: str = DEFAULT_PROJECT_ID) -> str:
    return (
        f"projects/{project_id}/locations/us-central1/keyRings/controlgraph-signing/"
        "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
    )


def root_records(
    *,
    target: TargetBinding | None = None,
    stable_revision: str = "controlgraph-reference-target-stable-v17",
    candidate_revision: str = "controlgraph-reference-target-candidate-v17",
    concurrency: int = 40,
    service_generation: int = 7,
    provider_etag: str = "etag-stable-7",
    baseline_configuration_sha256: str = ZERO_DIGEST,
    stable_revision_configuration_sha256: str = ONE_DIGEST,
    candidate_revision_configuration_sha256: str = TWO_DIGEST,
    captured_at: str = "2026-08-19T12:00:00Z",
    approved_at: str = "2026-08-19T12:01:00Z",
    claimed_at: str | None = None,
    operator: str = "operator@example.com",
    project_number: str = DEFAULT_PROJECT_NUMBER,
    maximum_capability_lifetime_seconds: int = 300,
) -> tuple[
    RolloutRootV2,
    CapabilityLineageAnchorV1,
    ServiceClaimRecord,
    EpochAuthorityRecord,
]:
    bound_target = target or target_binding()
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=bound_target,
        stable_revision=stable_revision,
        traffic=(TrafficAllocation(revision=stable_revision, percent=100),),
        concurrency=concurrency,
        service_generation=service_generation,
        provider_etag=provider_etag,
        configuration_sha256=baseline_configuration_sha256,
        stable_revision_configuration_sha256=(
            stable_revision_configuration_sha256
        ),
        captured_at=captured_at,
        captured_by=(
            f"controlgraph-verifier@{bound_target.project_id}.iam.gserviceaccount.com"
        ),
    )
    health = RolloutHealthPolicyV1(
        schema_version=ROLLOUT_HEALTH_POLICY_V1,
        input_schema_version="controlgraph.health-input/v1",
        evaluation_window_seconds=60,
        minimum_request_count=100,
        maximum_error_rate_basis_points=100,
        maximum_p95_latency_ms=500,
        minimum_probe_count=3,
        minimum_probe_success_basis_points=10_000,
        healthy_consecutive_windows=2,
        unhealthy_consecutive_windows=2,
        window_semantics="HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE",
        incomplete_data_action="INDETERMINATE_NO_MUTATION",
        late_data_action="INDETERMINATE_NO_MUTATION",
        duplicate_data_action="REJECT",
    )
    plan = RolloutPlanV1(
        schema_version=ROLLOUT_PLAN_V1,
        target=bound_target,
        stable_snapshot_sha256=canonical_sha256(snapshot),
        stable_revision=stable_revision,
        stable_revision_configuration_sha256=(
            stable_revision_configuration_sha256
        ),
        candidate_revision=candidate_revision,
        candidate_revision_configuration_sha256=(
            candidate_revision_configuration_sha256
        ),
        concurrency=concurrency,
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=canonical_sha256(health),
        maximum_recovery_attempts=1,
        initial_epoch=1,
    )
    executor_identity = (
        f"controlgraph-executor@{bound_target.project_id}.iam.gserviceaccount.com"
    )
    recovery_identity = (
        f"controlgraph-recovery@{bound_target.project_id}.iam.gserviceaccount.com"
    )
    executor_audience = service_audience("executor", project_number=project_number)
    recovery_audience = service_audience("recovery", project_number=project_number)

    def grant(
        action: CapabilityAction,
        identity: str,
        audience: str,
        stable_percent: int,
        candidate_percent: int,
        maximum_attempts: int | None,
    ) -> RootActionGrantV1:
        return RootActionGrantV1.model_validate(
            {
                "schema_version": ROOT_ACTION_GRANT_V1,
                "action": action,
                "subject_identity": identity,
                "audience": audience,
                "stable_percent": stable_percent,
                "candidate_percent": candidate_percent,
                "maximum_attempts": maximum_attempts,
            }
        )

    bounds = RootAuthorityBoundsV1(
        schema_version=ROOT_AUTHORITY_BOUNDS_V1,
        target=bound_target,
        stable_revision=stable_revision,
        stable_revision_configuration_sha256=(
            stable_revision_configuration_sha256
        ),
        candidate_revision=candidate_revision,
        candidate_revision_configuration_sha256=(
            candidate_revision_configuration_sha256
        ),
        concurrency=concurrency,
        plan_sha256=canonical_sha256(plan),
        capability_signing_key_version=capability_key_version(bound_target.project_id),
        issuer_identity=(
            f"controlgraph-issuer@{bound_target.project_id}.iam.gserviceaccount.com"
        ),
        executor_identity=executor_identity,
        recovery_identity=recovery_identity,
        executor_audience=executor_audience,
        recovery_audience=recovery_audience,
        maximum_capability_lifetime_seconds=maximum_capability_lifetime_seconds,
        maximum_recovery_attempts=1,
        apply_canary=grant(
            CapabilityAction.APPLY_CANARY,
            executor_identity,
            executor_audience,
            90,
            10,
            None,
        ),
        promote_candidate=grant(
            CapabilityAction.PROMOTE_CANDIDATE,
            executor_identity,
            executor_audience,
            0,
            100,
            None,
        ),
        recover_stable=grant(
            CapabilityAction.RECOVER_STABLE,
            recovery_identity,
            recovery_audience,
            100,
            0,
            1,
        ),
    )
    content = RolloutRootContentV2(
        schema_version=ROLLOUT_ROOT_CONTENT_V2,
        target=bound_target,
        stable_snapshot=snapshot,
        health_policy=health,
        rollout_plan=plan,
        authority_bounds=bounds,
        evidence_signing_key_version=evidence_key_version(bound_target.project_id),
        approved_by=operator,
        approved_by_subject="123456789012345678901",
        approved_at=approved_at,
    )
    root = create_rollout_root(content)
    anchor = capability_lineage_anchor(root)
    claim = ServiceClaimRecord(
        schema_version=SERVICE_CLAIM_V2,
        target=bound_target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        stable_revision=stable_revision,
        candidate_revision=candidate_revision,
        initial_epoch=1,
        baseline_service_generation=service_generation,
        baseline_configuration_sha256=baseline_configuration_sha256,
        baseline_revision_configuration_sha256=(
            stable_revision_configuration_sha256
        ),
        candidate_revision_configuration_sha256=(
            candidate_revision_configuration_sha256
        ),
        stable_target_configuration_sha256=(
            rollout_root_v2_target_configuration_sha256(
                root,
                stable_percent=100,
                candidate_percent=0,
            )
        ),
        candidate_target_configuration_sha256=(
            rollout_root_v2_target_configuration_sha256(
                root,
                stable_percent=0,
                candidate_percent=100,
            )
        ),
        operator_owner=operator,
        workload_creator="controlgraph.api/v1",
        terminal_release_condition=SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
        status=ServiceClaimStatus.ACTIVE,
        claim_request_id="request-root-001",
        claim_evidence_id="evidence-root-001",
        claimed_at=claimed_at or approved_at,
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
        target=bound_target,
        current_epoch=1,
        previous_epoch=None,
        revision=0,
        cause=EpochChangeCause.ROOT_CREATED,
        changed_by=operator,
        request_id="request-root-001",
        evidence_id="evidence-root-001",
        changed_at=claimed_at or approved_at,
    )
    return root, anchor, claim, authority


def root_bundle(
    *,
    root: RolloutRootV2 | None = None,
    anchor: CapabilityLineageAnchorV1 | None = None,
    claim: ServiceClaimRecord | None = None,
    authority: EpochAuthorityRecord | None = None,
    root_revision: int = 0,
    anchor_revision: int = 0,
    claim_revision: int | None = None,
) -> RootBundle:
    default_root, default_anchor, default_claim, default_authority = root_records()
    selected_root = root or default_root
    selected_anchor = anchor or (
        capability_lineage_anchor(selected_root) if root is not None else default_anchor
    )
    selected_claim = claim or default_claim
    selected_authority = authority or default_authority
    if claim_revision is None:
        claim_revision = {
            ServiceClaimStatus.ACTIVE: 0,
            ServiceClaimStatus.RELEASING: 1,
            ServiceClaimStatus.RELEASED: 2,
        }[selected_claim.status]
    return RootBundle(
        root=StoredRecord(selected_root, root_revision),
        service_claim=StoredRecord(selected_claim, claim_revision),
        authority=StoredRecord(selected_authority, selected_authority.revision),
        lineage_anchor=StoredRecord(selected_anchor, anchor_revision),
    )


__all__ = [
    "CAPABILITY_LINEAGE_ANCHOR_V1",
    "DEFAULT_PROJECT_ID",
    "DEFAULT_PROJECT_NUMBER",
    "ONE_DIGEST",
    "TWO_DIGEST",
    "ZERO_DIGEST",
    "RootBundle",
    "capability_key_version",
    "evidence_key_version",
    "root_bundle",
    "root_records",
    "service_audience",
    "target_binding",
]
