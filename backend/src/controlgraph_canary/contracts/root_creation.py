"""Strict immutable contracts for rollout-root creation."""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Final, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    Base64Url,
    BoundedText,
    CloudRunName,
    Identifier,
    KeyVersionResource,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import (
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    canonical_sha256,
    decode_base64url,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    StableSnapshot,
    TargetBinding,
)

ROLLOUT_HEALTH_POLICY_V1: Final = "controlgraph.rollout-health-policy/v1"
ROLLOUT_PLAN_V1: Final = "controlgraph.rollout-plan/v1"
ROOT_ACTION_GRANT_V1: Final = "controlgraph.root-action-grant/v1"
ROOT_AUTHORITY_BOUNDS_V1: Final = "controlgraph.root-authority-bounds/v1"
ROLLOUT_ROOT_CONTENT_V2: Final = "controlgraph.rollout-root-content/v2"
ROLLOUT_ROOT_V2: Final = "controlgraph.rollout-root/v2"
CAPABILITY_LINEAGE_ANCHOR_V1: Final = "controlgraph.capability-lineage-anchor/v1"
SIGNED_EVIDENCE_EVENT_V1: Final = "controlgraph.signed-evidence-event/v1"
ROOT_CREATION_RESULT_V1: Final = "controlgraph.root-creation-result/v1"
ROOT_CREATION_EVIDENCE_SUBJECT_V1: Final = "controlgraph.root-creation-evidence-subject/v1"
ROOT_CREATION_COMMAND_V1: Final = "controlgraph.root-creation-command/v1"

SIGNATURE_INPUT_V1: Final = "controlgraph.signature-input/v1"
P256_SIGNING_ALGORITHM: Final = "EC_SIGN_P256_SHA256"
EVIDENCE_SIGNING_PURPOSE: Final = "EVIDENCE"
_SIGNING_DOMAIN: Final = b"controlgraph.signature-input/v1\0"
_ROOT_CREATION_REQUEST_DOMAIN: Final = b"controlgraph.root-creation-request-sha256/v1\0"

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_ROLE_IDENTITY = re.compile(
    r"^controlgraph-(?P<role>issuer|executor|recovery)@"
    r"(?P<project>controlgraph-canary-[a-z0-9]{6,10})\.iam\.gserviceaccount\.com$"
)
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


class _RootCreationRequestProjection(StrictContractModel):
    """Validated identity fields used by the canonical request-digest helper."""

    request_id: Identifier
    idempotency_key: Identifier
    operator_identity: BoundedText
    operator_subject: GoogleSubject

    @model_validator(mode="after")
    def validate_operator(self) -> Self:
        _validate_operator_identity(self.operator_identity)
        return self


class RootCreationCommandV1(StrictContractModel):
    """Caller-controlled identifiers for one authenticated root approval."""

    schema_version: Literal["controlgraph.root-creation-command/v1"]
    request_id: Identifier
    idempotency_key: Identifier


class RolloutHealthPolicyV1(StrictContractModel):
    """The bounded deterministic health policy admitted by the first rollout."""

    schema_version: Literal["controlgraph.rollout-health-policy/v1"]
    input_schema_version: Literal["controlgraph.health-input/v1"]
    evaluation_window_seconds: Annotated[int, Field(ge=1, le=86_400)]
    minimum_request_count: PositiveSafeInteger
    maximum_error_rate_basis_points: Annotated[int, Field(ge=0, le=10_000)]
    maximum_p95_latency_ms: PositiveSafeInteger
    minimum_probe_count: PositiveSafeInteger
    minimum_probe_success_basis_points: Annotated[int, Field(ge=0, le=10_000)]
    healthy_consecutive_windows: Annotated[int, Field(ge=1, le=64)]
    unhealthy_consecutive_windows: Annotated[int, Field(ge=1, le=64)]
    window_semantics: Literal["HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE"]
    incomplete_data_action: Literal["INDETERMINATE_NO_MUTATION"]
    late_data_action: Literal["INDETERMINATE_NO_MUTATION"]
    duplicate_data_action: Literal["REJECT"]


class RolloutPlanV1(StrictContractModel):
    """One exact stable-to-candidate 90/10 rollout plan."""

    schema_version: Literal["controlgraph.rollout-plan/v1"]
    target: TargetBinding
    stable_snapshot_sha256: Sha256Digest
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    stable_percent: Literal[90]
    candidate_percent: Literal[10]
    health_policy_sha256: Sha256Digest
    maximum_recovery_attempts: Literal[1]
    initial_epoch: Literal[1]

    @model_validator(mode="after")
    def validate_revision_pair(self) -> Self:
        _validate_target(self.target)
        prefix = f"{self.target.service_name}-"
        if (
            self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(prefix)
            or not self.candidate_revision.startswith(prefix)
        ):
            raise ValueError("rollout plan revisions must be distinct and target-bound")
        return self


class RootActionGrantV1(StrictContractModel):
    """A closed, one-action attenuation boundary under a rollout root."""

    schema_version: Literal["controlgraph.root-action-grant/v1"]
    action: CapabilityAction
    subject_identity: BoundedText
    audience: Audience
    stable_percent: Annotated[int, Field(ge=0, le=100)]
    candidate_percent: Annotated[int, Field(ge=0, le=100)]
    maximum_attempts: Literal[1] | None

    @model_validator(mode="after")
    def validate_closed_action(self) -> Self:
        expected = {
            CapabilityAction.APPLY_CANARY: (90, 10, None),
            CapabilityAction.PROMOTE_CANDIDATE: (0, 100, None),
            CapabilityAction.RECOVER_STABLE: (100, 0, 1),
        }[self.action]
        if (
            self.stable_percent,
            self.candidate_percent,
            self.maximum_attempts,
        ) != expected:
            raise ValueError("root action grant exceeds its closed action boundary")
        return self


class RootAuthorityBoundsV1(StrictContractModel):
    """Maximum target, identity, signing, lifetime, and action authority."""

    schema_version: Literal["controlgraph.root-authority-bounds/v1"]
    target: TargetBinding
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    plan_sha256: Sha256Digest
    capability_signing_key_version: KeyVersionResource
    issuer_identity: BoundedText
    executor_identity: BoundedText
    recovery_identity: BoundedText
    executor_audience: Audience
    recovery_audience: Audience
    maximum_capability_lifetime_seconds: Annotated[int, Field(ge=1, le=900)]
    maximum_recovery_attempts: Literal[1]
    apply_canary: RootActionGrantV1
    promote_candidate: RootActionGrantV1
    recover_stable: RootActionGrantV1

    @model_validator(mode="after")
    def validate_closed_bounds(self) -> Self:
        _validate_target(self.target)
        if self.stable_revision == self.candidate_revision:
            raise ValueError("root authority revisions must be distinct")
        _validate_role_identity(self.issuer_identity, "issuer", self.target.project_id)
        _validate_role_identity(self.executor_identity, "executor", self.target.project_id)
        _validate_role_identity(self.recovery_identity, "recovery", self.target.project_id)
        _validate_service_audience(self.executor_audience, "executor")
        _validate_service_audience(self.recovery_audience, "recovery")
        if _audience_project_number(self.executor_audience) != _audience_project_number(
            self.recovery_audience
        ):
            raise ValueError("root authority audiences must use one project number")
        _validate_signing_key(
            self.capability_signing_key_version,
            project_id=self.target.project_id,
            key_name="capability-signing",
        )
        expected_grants = (
            (
                self.apply_canary,
                CapabilityAction.APPLY_CANARY,
                self.executor_identity,
                self.executor_audience,
            ),
            (
                self.promote_candidate,
                CapabilityAction.PROMOTE_CANDIDATE,
                self.executor_identity,
                self.executor_audience,
            ),
            (
                self.recover_stable,
                CapabilityAction.RECOVER_STABLE,
                self.recovery_identity,
                self.recovery_audience,
            ),
        )
        for grant, action, identity, audience in expected_grants:
            if (
                grant.action is not action
                or grant.subject_identity != identity
                or grant.audience != audience
            ):
                raise ValueError("root action grant identity or audience is not exact")
        return self


class RolloutRootContentV2(StrictContractModel):
    """Canonical immutable content whose digest is the rollout-root identity."""

    schema_version: Literal["controlgraph.rollout-root-content/v2"]
    target: TargetBinding
    stable_snapshot: StableSnapshot
    health_policy: RolloutHealthPolicyV1
    rollout_plan: RolloutPlanV1
    authority_bounds: RootAuthorityBoundsV1
    evidence_signing_key_version: KeyVersionResource
    approved_by: BoundedText
    approved_by_subject: GoogleSubject
    approved_at: UtcSecond

    @model_validator(mode="after")
    def validate_content_bindings(self) -> Self:
        _validate_target(self.target)
        _validate_operator_identity(self.approved_by)
        if self.stable_snapshot.target != self.target:
            raise ValueError("root snapshot target does not match root target")
        if self.rollout_plan.target != self.target:
            raise ValueError("root plan target does not match root target")
        if self.authority_bounds.target != self.target:
            raise ValueError("root authority target does not match root target")
        plan = self.rollout_plan
        snapshot = self.stable_snapshot
        bounds = self.authority_bounds
        expected_reader = (
            f"controlgraph-verifier@{self.target.project_id}.iam.gserviceaccount.com"
        )
        if snapshot.captured_by != expected_reader:
            raise ValueError("root snapshot was not captured by the configured verifier")
        if snapshot.captured_at > self.approved_at:
            raise ValueError("root approval predates its stable snapshot")
        if plan.stable_snapshot_sha256 != canonical_sha256(snapshot):
            raise ValueError("root plan does not bind the canonical stable snapshot")
        if plan.health_policy_sha256 != canonical_sha256(self.health_policy):
            raise ValueError("root plan does not bind the canonical health policy")
        if (
            plan.stable_revision != snapshot.stable_revision
            or plan.stable_revision_configuration_sha256
            != snapshot.stable_revision_configuration_sha256
            or plan.concurrency != snapshot.concurrency
        ):
            raise ValueError("root plan does not bind the stable snapshot configuration")
        if (
            bounds.stable_revision != plan.stable_revision
            or bounds.stable_revision_configuration_sha256
            != plan.stable_revision_configuration_sha256
            or bounds.candidate_revision != plan.candidate_revision
            or bounds.candidate_revision_configuration_sha256
            != plan.candidate_revision_configuration_sha256
            or bounds.concurrency != plan.concurrency
            or bounds.plan_sha256 != canonical_sha256(plan)
            or bounds.maximum_recovery_attempts != plan.maximum_recovery_attempts
        ):
            raise ValueError("root authority bounds do not match the canonical plan")
        _validate_signing_key(
            self.evidence_signing_key_version,
            project_id=self.target.project_id,
            key_name="evidence-signing",
        )
        return self


class RolloutRootV2(StrictContractModel):
    """A self-addressing immutable rollout root."""

    schema_version: Literal["controlgraph.rollout-root/v2"]
    root_id: Identifier
    root_sha256: Sha256Digest
    content: RolloutRootContentV2

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        expected_digest = canonical_sha256(self.content)
        if self.root_sha256 != expected_digest:
            raise ValueError("rollout root digest does not match its canonical content")
        if self.root_id != f"cgroot:{expected_digest}":
            raise ValueError("rollout root identifier does not match its content digest")
        return self


class CapabilityLineageAnchorV1(StrictContractModel):
    """Immutable maximum authority inherited by the first capability."""

    schema_version: Literal["controlgraph.capability-lineage-anchor/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    stable_snapshot_sha256: Sha256Digest
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    plan_sha256: Sha256Digest
    health_policy_sha256: Sha256Digest
    authority_bounds_sha256: Sha256Digest
    initial_epoch: Literal[1]


class RootCreationEvidenceSubjectV1(StrictContractModel):
    """The atomic creation records bound by the signed root evidence event."""

    schema_version: Literal["controlgraph.root-creation-evidence-subject/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    request_sha256: Sha256Digest
    created_at: UtcSecond
    service_claim_id: Identifier
    service_claim_sha256: Sha256Digest
    authority_id: Identifier
    authority_sha256: Sha256Digest
    lineage_anchor_id: Identifier
    lineage_anchor_sha256: Sha256Digest
    evidence_id: Identifier


class SignedEvidenceEventV1(StrictContractModel):
    """An evidence event and the exact purpose-separated P-256 signature bindings."""

    schema_version: Literal["controlgraph.signed-evidence-event/v1"]
    event: EvidenceEvent
    purpose: Literal["EVIDENCE"]
    signing_key_version: KeyVersionResource
    signing_algorithm: Literal["EC_SIGN_P256_SHA256"]
    payload_sha256: Sha256Digest
    signing_input_sha256: Sha256Digest
    signature: Base64Url

    @model_validator(mode="after")
    def validate_signature_bindings(self) -> Self:
        _validate_target(self.event.target)
        _validate_signing_key(
            self.signing_key_version,
            project_id=self.event.target.project_id,
            key_name="evidence-signing",
        )
        expected_payload = evidence_payload_sha256(self.event)
        if self.payload_sha256 != expected_payload:
            raise ValueError("evidence payload digest does not match its canonical event")
        if self.signing_input_sha256 != evidence_signing_input_sha256(
            self.event,
            self.signing_key_version,
        ):
            raise ValueError("evidence signing-input digest does not match its bindings")
        try:
            signature = decode_base64url(self.signature, maximum_bytes=256)
        except ValueError as error:
            raise ValueError("evidence signature is invalid") from error
        if not signature:
            raise ValueError("evidence signature is invalid")
        return self


class RootCreationResultV1(StrictContractModel):
    """A deterministic root-creation winner and its immutable emitted artifacts."""

    schema_version: Literal["controlgraph.root-creation-result/v1"]
    outcome: Literal["CREATED", "ADOPTED"]
    request_id: Identifier
    idempotency_key: Identifier
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    request_sha256: Sha256Digest
    created_at: UtcSecond
    winner_request_id: Identifier
    winner_idempotency_key: Identifier
    winner_operator_identity: BoundedText
    winner_operator_subject: GoogleSubject
    winner_request_sha256: Sha256Digest
    winner_service_claim_id: Identifier
    winner_service_claim_sha256: Sha256Digest
    winner_authority_id: Identifier
    winner_authority_sha256: Sha256Digest
    winner_lineage_anchor_id: Identifier
    winner_lineage_anchor_sha256: Sha256Digest
    winner_evidence_id: Identifier
    winner_evidence_sha256: Sha256Digest
    root: RolloutRootV2
    initial_authority: EpochAuthorityRecord
    lineage_anchor: CapabilityLineageAnchorV1
    evidence_subject: RootCreationEvidenceSubjectV1
    signed_evidence: SignedEvidenceEventV1

    @model_validator(mode="after")
    def validate_deterministic_winner(self) -> Self:
        _validate_operator_identity(self.operator_identity)
        _validate_operator_identity(self.winner_operator_identity)
        if (
            self.request_id != self.winner_request_id
            or self.idempotency_key != self.winner_idempotency_key
            or self.operator_identity != self.winner_operator_identity
            or self.operator_subject != self.winner_operator_subject
            or self.winner_operator_identity != self.root.content.approved_by
            or self.winner_operator_subject != self.root.content.approved_by_subject
        ):
            raise ValueError("root creation may adopt only the exact winning request")
        expected_request_sha256 = root_creation_request_sha256(
            root=self.root,
            request_id=self.request_id,
            idempotency_key=self.idempotency_key,
            operator_identity=self.operator_identity,
            operator_subject=self.operator_subject,
        )
        if (
            self.request_sha256 != expected_request_sha256
            or self.winner_request_sha256 != expected_request_sha256
        ):
            raise ValueError("root creation request digest does not match the winner")
        expected_anchor = capability_lineage_anchor(self.root)
        if self.lineage_anchor != expected_anchor:
            raise ValueError("root creation lineage anchor does not match the root")
        anchor_sha256 = canonical_sha256(self.lineage_anchor)
        authority_sha256 = canonical_sha256(self.initial_authority)
        evidence_sha256 = canonical_sha256(self.signed_evidence)
        event = self.signed_evidence.event
        if (
            self.root.content.approved_at > self.created_at
            or event.occurred_at != self.created_at
            or event.kind is not EvidenceKind.ROOT_CREATED
            or event.sequence != 0
            or event.previous_event_sha256 is not None
            or event.root_id != self.root.root_id
            or event.root_sha256 != self.root.root_sha256
            or event.target != self.root.content.target
            or event.epoch != self.root.content.rollout_plan.initial_epoch
            or event.actor != self.winner_operator_identity
            or event.request_id != self.winner_request_id
            or event.receipt_id is not None
            or event.reason_code is not None
            or event.provider_operation is not None
            or event.target_configuration_sha256
            != self.root.content.stable_snapshot.configuration_sha256
            or event.subject_sha256 != canonical_sha256(self.evidence_subject)
            or self.signed_evidence.signing_key_version
            != self.root.content.evidence_signing_key_version
        ):
            raise ValueError("root creation evidence does not match the winning root")
        if (
            self.initial_authority.root_id != self.root.root_id
            or self.initial_authority.root_sha256 != self.root.root_sha256
            or self.initial_authority.target != self.root.content.target
            or self.initial_authority.current_epoch != self.root.content.rollout_plan.initial_epoch
            or self.initial_authority.previous_epoch is not None
            or self.initial_authority.revision != 0
            or self.initial_authority.cause is not EpochChangeCause.ROOT_CREATED
            or self.initial_authority.changed_by != self.winner_operator_identity
            or self.initial_authority.request_id != self.winner_request_id
            or self.initial_authority.evidence_id != event.evidence_id
            or self.initial_authority.changed_at != self.created_at
        ):
            raise ValueError("initial authority does not match the winning root")
        expected_claim_id = canonical_sha256(self.root.content.target)
        expected_anchor_id = f"cganchor:{anchor_sha256}"
        expected_subject = RootCreationEvidenceSubjectV1(
            schema_version=ROOT_CREATION_EVIDENCE_SUBJECT_V1,
            root_id=self.root.root_id,
            root_sha256=self.root.root_sha256,
            request_sha256=expected_request_sha256,
            created_at=self.created_at,
            service_claim_id=self.winner_service_claim_id,
            service_claim_sha256=self.winner_service_claim_sha256,
            authority_id=self.winner_authority_id,
            authority_sha256=self.winner_authority_sha256,
            lineage_anchor_id=self.winner_lineage_anchor_id,
            lineage_anchor_sha256=self.winner_lineage_anchor_sha256,
            evidence_id=self.winner_evidence_id,
        )
        if (
            self.winner_service_claim_id != expected_claim_id
            or self.winner_authority_id != self.root.root_id
            or self.winner_authority_sha256 != authority_sha256
            or self.winner_lineage_anchor_id != expected_anchor_id
            or self.winner_lineage_anchor_sha256 != anchor_sha256
            or self.winner_evidence_id != event.evidence_id
            or self.winner_evidence_sha256 != evidence_sha256
            or self.evidence_subject != expected_subject
        ):
            raise ValueError("root creation artifact identity or digest does not match")
        return self


def create_rollout_root(content: RolloutRootContentV2) -> RolloutRootV2:
    """Create the sole valid self-address for canonical root content."""

    if type(content) is not RolloutRootContentV2:
        raise TypeError("root creation requires exact rollout-root content")
    digest = canonical_sha256(content)
    return RolloutRootV2(
        schema_version=ROLLOUT_ROOT_V2,
        root_id=f"cgroot:{digest}",
        root_sha256=digest,
        content=content,
    )


def capability_lineage_anchor(root: RolloutRootV2) -> CapabilityLineageAnchorV1:
    """Project immutable root authority into the first lineage anchor."""

    if type(root) is not RolloutRootV2:
        raise TypeError("lineage anchoring requires an exact rollout root")
    content = root.content
    plan = content.rollout_plan
    return CapabilityLineageAnchorV1(
        schema_version=CAPABILITY_LINEAGE_ANCHOR_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=content.target,
        stable_snapshot_sha256=plan.stable_snapshot_sha256,
        stable_revision=plan.stable_revision,
        stable_revision_configuration_sha256=plan.stable_revision_configuration_sha256,
        candidate_revision=plan.candidate_revision,
        candidate_revision_configuration_sha256=plan.candidate_revision_configuration_sha256,
        plan_sha256=canonical_sha256(plan),
        health_policy_sha256=canonical_sha256(content.health_policy),
        authority_bounds_sha256=canonical_sha256(content.authority_bounds),
        initial_epoch=plan.initial_epoch,
    )


def root_creation_request_sha256(
    *,
    root: RolloutRootV2,
    request_id: str,
    idempotency_key: str,
    operator_identity: str,
    operator_subject: str,
) -> str:
    """Hash the complete authenticated root-creation request projection."""

    if type(root) is not RolloutRootV2:
        raise TypeError("root creation request hashing requires an exact rollout root")
    try:
        request = _RootCreationRequestProjection(
            request_id=request_id,
            idempotency_key=idempotency_key,
            operator_identity=operator_identity,
            operator_subject=operator_subject,
        )
    except ValueError as error:
        raise ValueError("root creation request identity is invalid") from error
    value: RestrictedJson = {
        "idempotency_key": request.idempotency_key,
        "operator_identity": request.operator_identity,
        "operator_subject": request.operator_subject,
        "request_id": request.request_id,
        "root_id": root.root_id,
        "root_sha256": root.root_sha256,
        "schema_version": "controlgraph.root-creation-request/v1",
    }
    return hashlib.sha256(
        _ROOT_CREATION_REQUEST_DOMAIN + canonical_json_value_bytes(value)
    ).hexdigest()


def evidence_payload_sha256(event: EvidenceEvent) -> str:
    """Hash the canonical event bytes exactly as the evidence signer does."""

    if type(event) is not EvidenceEvent:
        raise TypeError("evidence payload hashing requires an exact evidence event")
    return hashlib.sha256(canonical_json_bytes(event)).hexdigest()


def evidence_signing_input_sha256(event: EvidenceEvent, key_version: str) -> str:
    """Build the exact purpose, key, algorithm, and payload-bound signing digest."""

    if type(event) is not EvidenceEvent:
        raise TypeError("evidence signing input requires an exact evidence event")
    _validate_signing_key(
        key_version,
        project_id=event.target.project_id,
        key_name="evidence-signing",
    )
    header: RestrictedJson = {
        "algorithm": P256_SIGNING_ALGORITHM,
        "key_version": key_version,
        "payload_version": event.schema_version,
        "purpose": EVIDENCE_SIGNING_PURPOSE,
        "schema_version": SIGNATURE_INPUT_V1,
    }
    return hashlib.sha256(
        _SIGNING_DOMAIN + canonical_json_value_bytes(header) + b"\0" + canonical_json_bytes(event)
    ).hexdigest()


def _validate_target(target: TargetBinding) -> None:
    if (
        _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is None
        or "reconcile" in target.project_id
        or target.region != "us-central1"
        or target.environment != "nonprod"
        or target.service_name != _REFERENCE_SERVICE
    ):
        raise ValueError("rollout root target is outside the dedicated ControlGraph boundary")


def _validate_role_identity(identity: str, role: str, project_id: str) -> None:
    matched = _ROLE_IDENTITY.fullmatch(identity)
    if matched is None or matched.group("role") != role or matched.group("project") != project_id:
        raise ValueError("root authority role identity is not exact")


def _validate_operator_identity(identity: str) -> None:
    if _HUMAN_EMAIL.fullmatch(identity) is None or identity.lower().endswith(
        ".iam.gserviceaccount.com"
    ):
        raise ValueError("root operator identity must be one human email")


def _validate_service_audience(audience: str, role: str) -> None:
    parsed = urlsplit(audience)
    hostname = parsed.hostname or ""
    expected = re.compile(
        rf"^controlgraph-{re.escape(role)}-[1-9][0-9]{{5,31}}\.us-central1\.run\.app$"
    )
    if (
        parsed.scheme != "https"
        or parsed.netloc != hostname
        or expected.fullmatch(hostname) is None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.port is not None
        or audience.endswith("/")
    ):
        raise ValueError("root authority audience is not exact")


def _audience_project_number(audience: str) -> str:
    hostname = urlsplit(audience).hostname or ""
    return hostname.rsplit("-", 1)[-1].split(".", 1)[0]


def _validate_signing_key(key_version: str, *, project_id: str, key_name: str) -> None:
    expected = re.compile(
        rf"^projects/{re.escape(project_id)}/locations/us-central1/"
        rf"keyRings/controlgraph-signing/cryptoKeys/{re.escape(key_name)}/"
        r"cryptoKeyVersions/[1-9][0-9]*$"
    )
    if type(key_version) is not str or expected.fullmatch(key_version) is None:
        raise ValueError("signing key version is outside its exact purpose boundary")


__all__ = [
    "CAPABILITY_LINEAGE_ANCHOR_V1",
    "EVIDENCE_SIGNING_PURPOSE",
    "P256_SIGNING_ALGORITHM",
    "ROLLOUT_HEALTH_POLICY_V1",
    "ROLLOUT_PLAN_V1",
    "ROLLOUT_ROOT_CONTENT_V2",
    "ROLLOUT_ROOT_V2",
    "ROOT_ACTION_GRANT_V1",
    "ROOT_AUTHORITY_BOUNDS_V1",
    "ROOT_CREATION_COMMAND_V1",
    "ROOT_CREATION_EVIDENCE_SUBJECT_V1",
    "ROOT_CREATION_RESULT_V1",
    "SIGNED_EVIDENCE_EVENT_V1",
    "CapabilityLineageAnchorV1",
    "RolloutHealthPolicyV1",
    "RolloutPlanV1",
    "RolloutRootContentV2",
    "RolloutRootV2",
    "RootActionGrantV1",
    "RootAuthorityBoundsV1",
    "RootCreationCommandV1",
    "RootCreationEvidenceSubjectV1",
    "RootCreationResultV1",
    "SignedEvidenceEventV1",
    "capability_lineage_anchor",
    "create_rollout_root",
    "evidence_payload_sha256",
    "evidence_signing_input_sha256",
    "root_creation_request_sha256",
]
