"""Deterministic construction of one immutable rollout-root authority bundle."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from controlgraph_canary.application.candidate_revision import (
    CandidateRevisionAttestation,
    CandidateRevisionValidationConfiguration,
)
from controlgraph_canary.application.cloud_run import (
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    EPOCH_AUTHORITY_V1,
    EVIDENCE_EVENT_V1,
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    StableSnapshot,
    TargetBinding,
)
from controlgraph_canary.contracts.root_creation import (
    ROLLOUT_PLAN_V1,
    ROLLOUT_ROOT_CONTENT_V2,
    ROOT_ACTION_GRANT_V1,
    ROOT_AUTHORITY_BOUNDS_V1,
    ROOT_CREATION_EVIDENCE_SUBJECT_V1,
    ROOT_CREATION_RESULT_V1,
    CapabilityLineageAnchorV1,
    RolloutHealthPolicyV1,
    RolloutPlanV1,
    RolloutRootContentV2,
    RolloutRootV2,
    RootActionGrantV1,
    RootAuthorityBoundsV1,
    RootCreationCommandV1,
    RootCreationEvidenceSubjectV1,
    RootCreationResultV1,
    SignedEvidenceEventV1,
    capability_lineage_anchor,
    create_rollout_root,
    root_creation_request_sha256,
)
from controlgraph_canary.contracts.storage import (
    SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
    ServiceClaimRecord,
    ServiceClaimStatus,
    service_claim_logical_id,
)

ROOT_CREATION_MAX_SNAPSHOT_AGE_SECONDS = 300

_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_GOOGLE_SUBJECT = re.compile(r"^[1-9][0-9]{5,31}$")
_KEY_VERSION = re.compile(
    r"^projects/(?P<project>controlgraph-canary-[a-z0-9]{6,10})/"
    r"locations/us-central1/keyRings/controlgraph-signing/cryptoKeys/"
    r"(?P<key>capability-signing|evidence-signing)/cryptoKeyVersions/[1-9][0-9]*$"
)


@dataclass(frozen=True, slots=True)
class RootCreationConfiguration:
    """Trusted fixed bounds from which one approved rollout root is derived."""

    target: TargetBinding
    verifier_identity: str
    candidate_revision: str
    candidate_revision_configuration_sha256: str
    concurrency: int
    health_policy: RolloutHealthPolicyV1
    capability_signing_key_version: str
    evidence_signing_key_version: str
    issuer_identity: str
    executor_identity: str
    recovery_identity: str
    executor_audience: str
    recovery_audience: str
    maximum_capability_lifetime_seconds: int
    operator_identity: str
    operator_subject: str

    def __post_init__(self) -> None:
        if type(self.health_policy) is not RolloutHealthPolicyV1:
            raise TypeError("root creation requires an exact health policy")
        CandidateRevisionValidationConfiguration(
            target=self.target,
            candidate_revision=self.candidate_revision,
            expected_configuration_sha256=(
                self.candidate_revision_configuration_sha256
            ),
            expected_concurrency=self.concurrency,
            reader_identity=self.verifier_identity,
        )
        _validate_operator(self.operator_identity, self.operator_subject)
        _validate_key(
            self.capability_signing_key_version,
            project_id=self.target.project_id,
            key_name="capability-signing",
        )
        _validate_key(
            self.evidence_signing_key_version,
            project_id=self.target.project_id,
            key_name="evidence-signing",
        )
        validation_plan = RolloutPlanV1(
            schema_version=ROLLOUT_PLAN_V1,
            target=self.target,
            stable_snapshot_sha256="0" * 64,
            stable_revision=f"{self.target.service_name}-stable-check",
            stable_revision_configuration_sha256="1" * 64,
            candidate_revision=self.candidate_revision,
            candidate_revision_configuration_sha256=(
                self.candidate_revision_configuration_sha256
            ),
            concurrency=self.concurrency,
            stable_percent=90,
            candidate_percent=10,
            health_policy_sha256=canonical_sha256(self.health_policy),
            maximum_recovery_attempts=1,
            initial_epoch=1,
        )
        _authority_bounds(self, validation_plan)


@dataclass(frozen=True, slots=True)
class UnsignedRootCreation:
    """Complete root bundle awaiting only the purpose-separated evidence signature."""

    command: RootCreationCommandV1
    created_at: str
    request_sha256: str
    root: RolloutRootV2
    service_claim: ServiceClaimRecord
    initial_authority: EpochAuthorityRecord
    lineage_anchor: CapabilityLineageAnchorV1
    evidence_subject: RootCreationEvidenceSubjectV1
    evidence_event: EvidenceEvent


@dataclass(frozen=True, slots=True)
class RootCreationArtifacts:
    """Exact records committed atomically for one root-creation winner."""

    root: RolloutRootV2
    service_claim: ServiceClaimRecord
    initial_authority: EpochAuthorityRecord
    lineage_anchor: CapabilityLineageAnchorV1
    signed_evidence: SignedEvidenceEventV1
    creation_result: RootCreationResultV1


def build_unsigned_root_creation(
    *,
    command: RootCreationCommandV1,
    operator_identity: str,
    operator_subject: str,
    stable_snapshot: StableSnapshot,
    candidate_revision: CandidateRevisionAttestation,
    configuration: RootCreationConfiguration,
    created_at: str,
) -> UnsignedRootCreation:
    """Build every deterministic record that precedes evidence signing."""

    if type(command) is not RootCreationCommandV1:
        raise TypeError("root creation requires an exact command")
    if type(configuration) is not RootCreationConfiguration:
        raise TypeError("root creation requires exact trusted configuration")
    if type(stable_snapshot) is not StableSnapshot:
        raise TypeError("root creation requires an exact stable snapshot")
    if type(candidate_revision) is not CandidateRevisionAttestation:
        raise TypeError("root creation requires an exact candidate attestation")
    _validate_operator(operator_identity, operator_subject)
    if (
        operator_identity != configuration.operator_identity
        or operator_subject != configuration.operator_subject
    ):
        raise ValueError("root creation operator does not match trusted configuration")
    _validate_preflight(
        stable_snapshot,
        candidate_revision,
        configuration=configuration,
        created_at=created_at,
    )

    plan = RolloutPlanV1(
        schema_version=ROLLOUT_PLAN_V1,
        target=configuration.target,
        stable_snapshot_sha256=canonical_sha256(stable_snapshot),
        stable_revision=stable_snapshot.stable_revision,
        stable_revision_configuration_sha256=(
            stable_snapshot.stable_revision_configuration_sha256
        ),
        candidate_revision=candidate_revision.candidate_revision,
        candidate_revision_configuration_sha256=(
            candidate_revision.configuration_sha256
        ),
        concurrency=stable_snapshot.concurrency,
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=canonical_sha256(configuration.health_policy),
        maximum_recovery_attempts=1,
        initial_epoch=1,
    )
    content = RolloutRootContentV2(
        schema_version=ROLLOUT_ROOT_CONTENT_V2,
        target=configuration.target,
        stable_snapshot=stable_snapshot,
        health_policy=configuration.health_policy,
        rollout_plan=plan,
        authority_bounds=_authority_bounds(configuration, plan),
        evidence_signing_key_version=configuration.evidence_signing_key_version,
        approved_by=operator_identity,
        approved_by_subject=operator_subject,
        approved_at=created_at,
    )
    root = create_rollout_root(content)
    request_sha256 = root_creation_request_sha256(
        root=root,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        operator_identity=operator_identity,
        operator_subject=operator_subject,
    )
    evidence_id = f"cgevidence:{request_sha256}"
    service_claim = _service_claim(
        root,
        request_id=command.request_id,
        evidence_id=evidence_id,
        created_at=created_at,
    )
    initial_authority = EpochAuthorityRecord(
        schema_version=EPOCH_AUTHORITY_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        current_epoch=1,
        previous_epoch=None,
        revision=0,
        cause=EpochChangeCause.ROOT_CREATED,
        changed_by=operator_identity,
        request_id=command.request_id,
        evidence_id=evidence_id,
        changed_at=created_at,
    )
    lineage_anchor = capability_lineage_anchor(root)
    anchor_sha256 = canonical_sha256(lineage_anchor)
    evidence_subject = RootCreationEvidenceSubjectV1(
        schema_version=ROOT_CREATION_EVIDENCE_SUBJECT_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        request_sha256=request_sha256,
        created_at=created_at,
        service_claim_id=service_claim_logical_id(root.content.target),
        service_claim_sha256=canonical_sha256(service_claim),
        authority_id=root.root_id,
        authority_sha256=canonical_sha256(initial_authority),
        lineage_anchor_id=f"cganchor:{anchor_sha256}",
        lineage_anchor_sha256=anchor_sha256,
        evidence_id=evidence_id,
    )
    evidence_event = EvidenceEvent(
        schema_version=EVIDENCE_EVENT_V1,
        evidence_id=evidence_id,
        sequence=0,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        epoch=1,
        kind=EvidenceKind.ROOT_CREATED,
        actor=operator_identity,
        request_id=command.request_id,
        receipt_id=None,
        occurred_at=created_at,
        subject_sha256=canonical_sha256(evidence_subject),
        previous_event_sha256=None,
        reason_code=None,
        provider_operation=None,
        target_configuration_sha256=stable_snapshot.configuration_sha256,
    )
    return UnsignedRootCreation(
        command=command,
        created_at=created_at,
        request_sha256=request_sha256,
        root=root,
        service_claim=service_claim,
        initial_authority=initial_authority,
        lineage_anchor=lineage_anchor,
        evidence_subject=evidence_subject,
        evidence_event=evidence_event,
    )


def complete_root_creation(
    unsigned: UnsignedRootCreation,
    signed_evidence: SignedEvidenceEventV1,
) -> RootCreationArtifacts:
    """Bind an authenticated evidence signature into the persisted result contract."""

    if type(unsigned) is not UnsignedRootCreation:
        raise TypeError("root completion requires exact unsigned artifacts")
    if type(signed_evidence) is not SignedEvidenceEventV1:
        raise TypeError("root completion requires exact signed evidence")
    if (
        signed_evidence.event != unsigned.evidence_event
        or signed_evidence.signing_key_version
        != unsigned.root.content.evidence_signing_key_version
    ):
        raise ValueError("signed evidence does not match the root creation event")

    claim_id = service_claim_logical_id(unsigned.root.content.target)
    claim_sha256 = canonical_sha256(unsigned.service_claim)
    authority_sha256 = canonical_sha256(unsigned.initial_authority)
    anchor_sha256 = canonical_sha256(unsigned.lineage_anchor)
    evidence_sha256 = canonical_sha256(signed_evidence)
    command = unsigned.command
    root = unsigned.root
    result = RootCreationResultV1(
        schema_version=ROOT_CREATION_RESULT_V1,
        outcome="CREATED",
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        operator_identity=root.content.approved_by,
        operator_subject=root.content.approved_by_subject,
        request_sha256=unsigned.request_sha256,
        created_at=unsigned.created_at,
        winner_request_id=command.request_id,
        winner_idempotency_key=command.idempotency_key,
        winner_operator_identity=root.content.approved_by,
        winner_operator_subject=root.content.approved_by_subject,
        winner_request_sha256=unsigned.request_sha256,
        winner_service_claim_id=claim_id,
        winner_service_claim_sha256=claim_sha256,
        winner_authority_id=root.root_id,
        winner_authority_sha256=authority_sha256,
        winner_lineage_anchor_id=f"cganchor:{anchor_sha256}",
        winner_lineage_anchor_sha256=anchor_sha256,
        winner_evidence_id=signed_evidence.event.evidence_id,
        winner_evidence_sha256=evidence_sha256,
        root=root,
        initial_authority=unsigned.initial_authority,
        lineage_anchor=unsigned.lineage_anchor,
        evidence_subject=unsigned.evidence_subject,
        signed_evidence=signed_evidence,
    )
    return RootCreationArtifacts(
        root=root,
        service_claim=unsigned.service_claim,
        initial_authority=unsigned.initial_authority,
        lineage_anchor=unsigned.lineage_anchor,
        signed_evidence=signed_evidence,
        creation_result=result,
    )


def _authority_bounds(
    configuration: RootCreationConfiguration,
    plan: RolloutPlanV1,
) -> RootAuthorityBoundsV1:
    apply_canary = _action_grant(
        CapabilityAction.APPLY_CANARY,
        identity=configuration.executor_identity,
        audience=configuration.executor_audience,
    )
    promote_candidate = _action_grant(
        CapabilityAction.PROMOTE_CANDIDATE,
        identity=configuration.executor_identity,
        audience=configuration.executor_audience,
    )
    recover_stable = _action_grant(
        CapabilityAction.RECOVER_STABLE,
        identity=configuration.recovery_identity,
        audience=configuration.recovery_audience,
    )
    return RootAuthorityBoundsV1(
        schema_version=ROOT_AUTHORITY_BOUNDS_V1,
        target=configuration.target,
        stable_revision=plan.stable_revision,
        stable_revision_configuration_sha256=(
            plan.stable_revision_configuration_sha256
        ),
        candidate_revision=plan.candidate_revision,
        candidate_revision_configuration_sha256=(
            plan.candidate_revision_configuration_sha256
        ),
        concurrency=plan.concurrency,
        plan_sha256=canonical_sha256(plan),
        capability_signing_key_version=(
            configuration.capability_signing_key_version
        ),
        issuer_identity=configuration.issuer_identity,
        executor_identity=configuration.executor_identity,
        recovery_identity=configuration.recovery_identity,
        executor_audience=configuration.executor_audience,
        recovery_audience=configuration.recovery_audience,
        maximum_capability_lifetime_seconds=(
            configuration.maximum_capability_lifetime_seconds
        ),
        maximum_recovery_attempts=1,
        apply_canary=apply_canary,
        promote_candidate=promote_candidate,
        recover_stable=recover_stable,
    )


def _action_grant(
    action: CapabilityAction,
    *,
    identity: str,
    audience: str,
) -> RootActionGrantV1:
    stable_percent, candidate_percent = {
        CapabilityAction.APPLY_CANARY: (90, 10),
        CapabilityAction.PROMOTE_CANDIDATE: (0, 100),
        CapabilityAction.RECOVER_STABLE: (100, 0),
    }[action]
    maximum_attempts: Literal[1] | None = (
        1 if action is CapabilityAction.RECOVER_STABLE else None
    )
    return RootActionGrantV1(
        schema_version=ROOT_ACTION_GRANT_V1,
        action=action,
        subject_identity=identity,
        audience=audience,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        maximum_attempts=maximum_attempts,
    )


def _service_claim(
    root: RolloutRootV2,
    *,
    request_id: str,
    evidence_id: str,
    created_at: str,
) -> ServiceClaimRecord:
    plan = root.content.rollout_plan
    stable_target_sha256 = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=root.content.target,
            stable_revision=plan.stable_revision,
            candidate_revision=plan.candidate_revision,
            stable_percent=100,
            candidate_percent=0,
            concurrency=plan.concurrency,
        )
    )
    candidate_target_sha256 = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=root.content.target,
            stable_revision=plan.stable_revision,
            candidate_revision=plan.candidate_revision,
            stable_percent=0,
            candidate_percent=100,
            concurrency=plan.concurrency,
        )
    )
    snapshot = root.content.stable_snapshot
    return ServiceClaimRecord(
        schema_version="controlgraph.service-claim/v2",
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        initial_epoch=1,
        baseline_service_generation=snapshot.service_generation,
        baseline_configuration_sha256=snapshot.configuration_sha256,
        baseline_revision_configuration_sha256=(
            snapshot.stable_revision_configuration_sha256
        ),
        candidate_revision_configuration_sha256=(
            plan.candidate_revision_configuration_sha256
        ),
        stable_target_configuration_sha256=stable_target_sha256,
        candidate_target_configuration_sha256=candidate_target_sha256,
        operator_owner=root.content.approved_by,
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


def _validate_preflight(
    stable_snapshot: StableSnapshot,
    candidate_revision: CandidateRevisionAttestation,
    *,
    configuration: RootCreationConfiguration,
    created_at: str,
) -> None:
    created = _parse_utc_second(created_at)
    stable_captured = _parse_utc_second(stable_snapshot.captured_at)
    candidate_captured = _parse_utc_second(candidate_revision.captured_at)
    if (
        stable_snapshot.target != configuration.target
        or candidate_revision.target != configuration.target
        or stable_snapshot.captured_by != configuration.verifier_identity
        or candidate_revision.reader_identity != configuration.verifier_identity
        or candidate_revision.candidate_revision != configuration.candidate_revision
        or candidate_revision.configuration_sha256
        != configuration.candidate_revision_configuration_sha256
        or stable_snapshot.concurrency != configuration.concurrency
        or candidate_revision.concurrency != configuration.concurrency
        or candidate_captured > stable_captured
        or stable_captured > created
        or (created - stable_captured).total_seconds()
        > ROOT_CREATION_MAX_SNAPSHOT_AGE_SECONDS
        or (created - candidate_captured).total_seconds()
        > ROOT_CREATION_MAX_SNAPSHOT_AGE_SECONDS
    ):
        raise ValueError("root creation preflight does not match trusted fresh state")


def _validate_operator(identity: object, subject: object) -> None:
    if (
        type(identity) is not str
        or _HUMAN_EMAIL.fullmatch(identity) is None
        or identity.endswith(".iam.gserviceaccount.com")
        or type(subject) is not str
        or _GOOGLE_SUBJECT.fullmatch(subject) is None
    ):
        raise ValueError("root creation operator identity is invalid")


def _validate_key(value: object, *, project_id: str, key_name: str) -> None:
    matched = _KEY_VERSION.fullmatch(value) if type(value) is str else None
    if (
        matched is None
        or matched.group("project") != project_id
        or matched.group("key") != key_name
    ):
        raise ValueError("root creation signing key is outside its purpose boundary")


def _parse_utc_second(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("root creation time is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise ValueError("root creation time is invalid") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("root creation time is invalid")
    return parsed


__all__ = [
    "ROOT_CREATION_MAX_SNAPSHOT_AGE_SECONDS",
    "RootCreationArtifacts",
    "RootCreationConfiguration",
    "UnsignedRootCreation",
    "build_unsigned_root_creation",
    "complete_root_creation",
]
