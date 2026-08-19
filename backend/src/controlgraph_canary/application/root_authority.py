"""Application checks for the persisted rollout-root authority boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.cloud_run import (
    rollout_root_v2_target_configuration_sha256,
)
from controlgraph_canary.authority.policy import (
    CanaryAction,
    CapabilityScope,
    IntegerBounds,
    OperatorRootAnchor,
    TimeBounds,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    CapabilityClaims,
    EpochAuthorityRecord,
    TargetBinding,
)
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV2,
    RootActionGrantV1,
    capability_lineage_anchor,
)
from controlgraph_canary.contracts.storage import (
    SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
    ServiceClaimRecord,
    ServiceClaimStatus,
)


@runtime_checkable
class RootAuthorityBundle(Protocol):
    """Atomic persisted records needed by authority-bearing application paths."""

    @property
    def root(self) -> StoredRecord[RolloutRootV2]: ...

    @property
    def service_claim(self) -> StoredRecord[ServiceClaimRecord]: ...

    @property
    def authority(self) -> StoredRecord[EpochAuthorityRecord]: ...

    @property
    def lineage_anchor(self) -> StoredRecord[CapabilityLineageAnchorV1]: ...


@runtime_checkable
class RootAuthorityBundleReader(Protocol):
    """Read one transactionally consistent root, claim, epoch, and anchor view."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootAuthorityBundle | None: ...


@dataclass(frozen=True, slots=True)
class TrustedRootAuthority:
    """Validated values and revisions from one atomic authority read."""

    root: RolloutRootV2
    service_claim: ServiceClaimRecord
    authority: EpochAuthorityRecord
    lineage_anchor: CapabilityLineageAnchorV1
    root_revision: int
    service_claim_revision: int
    authority_revision: int
    lineage_anchor_revision: int


def inspect_root_authority_bundle(
    bundle: object,
    *,
    target: TargetBinding,
) -> TrustedRootAuthority | None:
    """Validate the complete immutable boundary and its mutable claim and epoch."""

    if not isinstance(bundle, RootAuthorityBundle):
        return None
    try:
        root_record = bundle.root
        claim_record = bundle.service_claim
        authority_record = bundle.authority
        anchor_record = bundle.lineage_anchor
    except Exception:
        return None
    if any(
        type(record) is not StoredRecord
        for record in (root_record, claim_record, authority_record, anchor_record)
    ):
        return None
    root = root_record.value
    claim = claim_record.value
    authority = authority_record.value
    anchor = anchor_record.value
    if (
        type(target) is not TargetBinding
        or type(root) is not RolloutRootV2
        or type(claim) is not ServiceClaimRecord
        or type(authority) is not EpochAuthorityRecord
        or type(anchor) is not CapabilityLineageAnchorV1
    ):
        return None
    try:
        content_sha256 = canonical_sha256(root.content)
        expected_anchor = capability_lineage_anchor(root)
        claim_matches = service_claim_matches_root_v2(claim, root)
    except Exception:
        return None
    if (
        root_record.revision != 0
        or anchor_record.revision != 0
        or root.content.target != target
        or root.root_sha256 != content_sha256
        or root.root_id != f"cgroot:{root.root_sha256}"
        or anchor != expected_anchor
        or not claim_matches
        or not _claim_lifecycle_revision_matches(claim, claim_record.revision)
        or authority.target != target
        or authority.root_id != root.root_id
        or authority.root_sha256 != root.root_sha256
        or authority_record.revision != authority.revision
        or authority.current_epoch != authority.revision + 1
    ):
        return None
    return TrustedRootAuthority(
        root=root,
        service_claim=claim,
        authority=authority,
        lineage_anchor=anchor,
        root_revision=root_record.revision,
        service_claim_revision=claim_record.revision,
        authority_revision=authority_record.revision,
        lineage_anchor_revision=anchor_record.revision,
    )


def service_claim_matches_root_v2(
    claim: ServiceClaimRecord,
    root: RolloutRootV2,
) -> bool:
    """Return whether a service claim binds every root-derived target field."""

    if type(claim) is not ServiceClaimRecord or type(root) is not RolloutRootV2:
        return False
    content = root.content
    snapshot = content.stable_snapshot
    plan = content.rollout_plan
    try:
        stable_target_sha256 = rollout_root_v2_target_configuration_sha256(
            root,
            stable_percent=100,
            candidate_percent=0,
        )
        candidate_target_sha256 = rollout_root_v2_target_configuration_sha256(
            root,
            stable_percent=0,
            candidate_percent=100,
        )
    except (TypeError, ValueError):
        return False
    return (
        claim.target == content.target
        and claim.root_id == root.root_id
        and claim.root_sha256 == root.root_sha256
        and claim.stable_revision == plan.stable_revision
        and claim.candidate_revision == plan.candidate_revision
        and claim.initial_epoch == plan.initial_epoch
        and claim.baseline_service_generation == snapshot.service_generation
        and claim.baseline_configuration_sha256 == snapshot.configuration_sha256
        and claim.baseline_revision_configuration_sha256
        == plan.stable_revision_configuration_sha256
        and claim.candidate_revision_configuration_sha256
        == plan.candidate_revision_configuration_sha256
        and claim.stable_target_configuration_sha256 == stable_target_sha256
        and claim.candidate_target_configuration_sha256 == candidate_target_sha256
        and claim.operator_owner == content.approved_by
        and claim.workload_creator == "controlgraph.api/v1"
        and claim.terminal_release_condition == SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION
        and content.approved_at <= claim.claimed_at
    )


def root_action_grant(
    root: RolloutRootV2,
    action: CapabilityAction,
) -> RootActionGrantV1:
    """Select the exact closed action grant committed into a rollout root."""

    if type(root) is not RolloutRootV2 or type(action) is not CapabilityAction:
        raise TypeError("an exact rollout root and capability action are required")
    bounds = root.content.authority_bounds
    return {
        CapabilityAction.APPLY_CANARY: bounds.apply_canary,
        CapabilityAction.PROMOTE_CANDIDATE: bounds.promote_candidate,
        CapabilityAction.RECOVER_STABLE: bounds.recover_stable,
    }[action]


def capability_claims_match_root_authority(
    claims: CapabilityClaims,
    root: RolloutRootV2,
    anchor: CapabilityLineageAnchorV1,
) -> bool:
    """Check one capability against only persisted root and anchor authority."""

    if (
        type(claims) is not CapabilityClaims
        or type(root) is not RolloutRootV2
        or type(anchor) is not CapabilityLineageAnchorV1
        or anchor != capability_lineage_anchor(root)
    ):
        return False
    content = root.content
    plan = content.rollout_plan
    bounds = content.authority_bounds
    try:
        grant = root_action_grant(root, claims.action)
        issued_at = _parse_utc_second(claims.issued_at)
        not_before = _parse_utc_second(claims.not_before)
        expires_at = _parse_utc_second(claims.expires_at)
    except (KeyError, TypeError, ValueError):
        return False
    expected_concurrency = (
        bounds.concurrency
        if claims.action is CapabilityAction.RECOVER_STABLE
        else None
    )
    if claims.action is CapabilityAction.APPLY_CANARY:
        expected_precondition = content.stable_snapshot.provider_etag
        if claims.provider_etag != expected_precondition:
            return False
    return (
        claims.target == anchor.target == content.target
        and claims.root_id == anchor.root_id == root.root_id
        and claims.root_sha256 == anchor.root_sha256 == root.root_sha256
        and claims.plan_sha256 == anchor.plan_sha256 == canonical_sha256(plan)
        and claims.stable_revision == anchor.stable_revision == plan.stable_revision
        and claims.candidate_revision == anchor.candidate_revision == plan.candidate_revision
        and anchor.stable_revision_configuration_sha256
        == plan.stable_revision_configuration_sha256
        and anchor.candidate_revision_configuration_sha256
        == plan.candidate_revision_configuration_sha256
        and anchor.authority_bounds_sha256 == canonical_sha256(bounds)
        and claims.issuer == bounds.issuer_identity
        and claims.subject == grant.subject_identity
        and claims.audience == grant.audience
        and claims.signing_key_version == bounds.capability_signing_key_version
        and claims.signing_algorithm == "EC_SIGN_P256_SHA256"
        and claims.stable_percent == grant.stable_percent
        and claims.candidate_percent == grant.candidate_percent
        and claims.concurrency == expected_concurrency
        and issued_at >= _parse_utc_second(content.approved_at)
        and issued_at <= not_before < expires_at
        and expires_at - issued_at <= bounds.maximum_capability_lifetime_seconds
    )


def capability_scope_from_claims(
    claims: CapabilityClaims,
    root: RolloutRootV2,
) -> CapabilityScope:
    """Project a capability scope using root-fixed concurrency."""

    if type(claims) is not CapabilityClaims or type(root) is not RolloutRootV2:
        raise TypeError("an exact capability and rollout root are required")
    concurrency = claims.concurrency or root.content.authority_bounds.concurrency
    return CapabilityScope(
        project_id=claims.target.project_id,
        region=claims.target.region,
        environment=claims.target.environment,
        service_name=claims.target.service_name,
        root_id=claims.root_id,
        root_sha256=claims.root_sha256,
        epoch=claims.epoch,
        plan_sha256=claims.plan_sha256,
        provider_precondition=claims.provider_etag,
        request_id=claims.request_id,
        idempotency_key=claims.idempotency_key,
        callers=frozenset({claims.subject}),
        audiences=frozenset({claims.audience}),
        stable_revision=claims.stable_revision,
        candidate_revision=claims.candidate_revision,
        revisions=frozenset({claims.stable_revision, claims.candidate_revision}),
        actions=frozenset({CanaryAction(claims.action.value)}),
        traffic_percent=IntegerBounds(claims.candidate_percent, claims.candidate_percent),
        concurrency=IntegerBounds(concurrency, concurrency),
        validity=TimeBounds(
            _parse_utc_second(claims.not_before),
            _parse_utc_second(claims.expires_at),
        ),
    )


def operator_lineage_anchor(
    root: RolloutRootV2,
    anchor: CapabilityLineageAnchorV1,
    first_claims: CapabilityClaims,
) -> OperatorRootAnchor:
    """Build lineage policy from persisted maximum authority and correlation fields."""

    if not capability_claims_match_root_authority(first_claims, root, anchor):
        raise ValueError("capability is outside the persisted root authority")
    content = root.content
    bounds = content.authority_bounds
    grant = root_action_grant(root, first_claims.action)
    issued_at = _parse_utc_second(first_claims.issued_at)
    provider_precondition = first_claims.provider_etag
    if first_claims.action is CapabilityAction.APPLY_CANARY:
        provider_precondition = content.stable_snapshot.provider_etag
    return OperatorRootAnchor(
        root_sha256=anchor.root_sha256,
        scope=CapabilityScope(
            project_id=anchor.target.project_id,
            region=anchor.target.region,
            environment=anchor.target.environment,
            service_name=anchor.target.service_name,
            root_id=anchor.root_id,
            root_sha256=anchor.root_sha256,
            epoch=first_claims.epoch,
            plan_sha256=anchor.plan_sha256,
            provider_precondition=provider_precondition,
            request_id=first_claims.request_id,
            idempotency_key=first_claims.idempotency_key,
            callers=frozenset({grant.subject_identity}),
            audiences=frozenset({grant.audience}),
            stable_revision=anchor.stable_revision,
            candidate_revision=anchor.candidate_revision,
            revisions=frozenset({anchor.stable_revision, anchor.candidate_revision}),
            actions=frozenset({CanaryAction(grant.action.value)}),
            traffic_percent=IntegerBounds(
                grant.candidate_percent,
                grant.candidate_percent,
            ),
            concurrency=IntegerBounds(bounds.concurrency, bounds.concurrency),
            validity=TimeBounds(
                issued_at,
                issued_at + bounds.maximum_capability_lifetime_seconds,
            ),
        ),
    )


def _claim_lifecycle_revision_matches(claim: ServiceClaimRecord, revision: int) -> bool:
    return (
        claim.status is ServiceClaimStatus.ACTIVE
        and revision % 3 == 0
    ) or (
        claim.status is ServiceClaimStatus.RELEASING
        and revision % 3 == 1
    ) or (
        claim.status is ServiceClaimStatus.RELEASED
        and revision % 3 == 2
    )


def _parse_utc_second(value: str) -> int:
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


__all__ = [
    "RootAuthorityBundle",
    "RootAuthorityBundleReader",
    "TrustedRootAuthority",
    "capability_claims_match_root_authority",
    "capability_scope_from_claims",
    "inspect_root_authority_bundle",
    "operator_lineage_anchor",
    "root_action_grant",
    "service_claim_matches_root_v2",
]
