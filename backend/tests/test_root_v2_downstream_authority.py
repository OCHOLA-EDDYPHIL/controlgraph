from __future__ import annotations

from datetime import UTC, datetime

import pytest
from root_v2_support import (
    ZERO_DIGEST,
    capability_key_version,
    root_bundle,
    root_records,
    service_audience,
)

from controlgraph_canary.application.root_authority import (
    capability_claims_match_root_authority,
    inspect_root_authority_bundle,
    operator_lineage_anchor,
)
from controlgraph_canary.authority.policy import CanaryAction
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import CapabilityAction, CapabilityClaims


def _claims(
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
) -> CapabilityClaims:
    root, _, _, _ = root_records()
    plan = root.content.rollout_plan
    bounds = root.content.authority_bounds
    grant = {
        CapabilityAction.APPLY_CANARY: bounds.apply_canary,
        CapabilityAction.PROMOTE_CANDIDATE: bounds.promote_candidate,
        CapabilityAction.RECOVER_STABLE: bounds.recover_stable,
    }[action]
    return CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id=f"capability-{action.value.lower()}",
        issuer=bounds.issuer_identity,
        subject=grant.subject_identity,
        audience=grant.audience,
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=action,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=grant.stable_percent,
        candidate_percent=grant.candidate_percent,
        concurrency=(
            bounds.concurrency
            if action is CapabilityAction.RECOVER_STABLE
            else None
        ),
        plan_sha256=canonical_sha256(plan),
        provider_etag=root.content.stable_snapshot.provider_etag,
        request_id="request-root-boundary",
        idempotency_key="intent-root-boundary",
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:02:00Z",
        not_before="2026-08-19T12:02:00Z",
        expires_at="2026-08-19T12:07:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=capability_key_version(),
    )


@pytest.mark.parametrize(
    "tamper",
    [
        "anchor-stable-configuration",
        "anchor-candidate-configuration",
        "root-lifetime",
        "claim-candidate-configuration",
    ],
)
def test_atomic_root_boundary_rejects_persisted_widening_and_tamper(
    tamper: str,
) -> None:
    root, anchor, claim, authority = root_records()
    if tamper == "anchor-stable-configuration":
        anchor = anchor.model_copy(
            update={"stable_revision_configuration_sha256": ZERO_DIGEST}
        )
    elif tamper == "anchor-candidate-configuration":
        anchor = anchor.model_copy(
            update={"candidate_revision_configuration_sha256": ZERO_DIGEST}
        )
    elif tamper == "root-lifetime":
        widened_bounds = root.content.authority_bounds.model_copy(
            update={"maximum_capability_lifetime_seconds": 900}
        )
        root = root.model_copy(
            update={
                "content": root.content.model_copy(
                    update={"authority_bounds": widened_bounds}
                )
            }
        )
    else:
        claim = claim.model_copy(
            update={"candidate_revision_configuration_sha256": ZERO_DIGEST}
        )
    bundle = root_bundle(
        root=root,
        anchor=anchor,
        claim=claim,
        authority=authority,
    )

    assert (
        inspect_root_authority_bundle(bundle, target=root.content.target)
        is None
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"root_sha256": ZERO_DIGEST},
        {"plan_sha256": ZERO_DIGEST},
        {"stable_revision": "controlgraph-reference-target-stable-v11"},
        {"candidate_revision": "controlgraph-reference-target-candidate-v11"},
        {"issuer": "controlgraph-executor@controlgraph-canary-abc123.iam.gserviceaccount.com"},
        {"subject": "controlgraph-recovery@controlgraph-canary-abc123.iam.gserviceaccount.com"},
        {"audience": service_audience("recovery")},
        {
            "signing_key_version": (
                "projects/controlgraph-canary-abc123/locations/us-central1/"
                "keyRings/controlgraph-signing/cryptoKeys/capability-signing/"
                "cryptoKeyVersions/2"
            )
        },
        {"stable_percent": 80, "candidate_percent": 20},
        {"concurrency": 41},
        {"expires_at": "2026-08-19T12:08:00Z"},
    ],
)
def test_capability_cannot_widen_the_persisted_root_authority(
    changes: dict[str, object],
) -> None:
    root, anchor, _, _ = root_records()
    widened = _claims().model_copy(update=changes)

    assert not capability_claims_match_root_authority(widened, root, anchor)


@pytest.mark.parametrize(
    "action",
    [
        CapabilityAction.APPLY_CANARY,
        CapabilityAction.PROMOTE_CANDIDATE,
        CapabilityAction.RECOVER_STABLE,
    ],
)
def test_lineage_policy_uses_the_persisted_action_grant(
    action: CapabilityAction,
) -> None:
    root, anchor, _, _ = root_records()
    claims = _claims(action)

    policy_anchor = operator_lineage_anchor(root, anchor, claims)
    grant = {
        CapabilityAction.APPLY_CANARY: root.content.authority_bounds.apply_canary,
        CapabilityAction.PROMOTE_CANDIDATE: root.content.authority_bounds.promote_candidate,
        CapabilityAction.RECOVER_STABLE: root.content.authority_bounds.recover_stable,
    }[action]

    assert policy_anchor.root_sha256 == root.root_sha256
    assert policy_anchor.scope.actions == frozenset({CanaryAction(action.value)})
    assert policy_anchor.scope.callers == frozenset({grant.subject_identity})
    assert policy_anchor.scope.audiences == frozenset({grant.audience})
    assert policy_anchor.scope.traffic_percent.minimum == grant.candidate_percent
    assert policy_anchor.scope.traffic_percent.maximum == grant.candidate_percent
    assert policy_anchor.scope.concurrency.minimum == root.content.authority_bounds.concurrency
    assert policy_anchor.scope.concurrency.maximum == root.content.authority_bounds.concurrency
    assert policy_anchor.scope.validity.expires_at - policy_anchor.scope.validity.not_before == 300
    assert policy_anchor.scope.validity.not_before == int(
        datetime(2026, 8, 19, 12, 2, tzinfo=UTC).timestamp()
    )
