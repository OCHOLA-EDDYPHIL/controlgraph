from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from controlgraph_canary.contracts import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    RolloutHealthPolicyV1,
    RolloutPlanV1,
    RolloutRootContentV2,
    RolloutRootV2,
    RootActionGrantV1,
    RootAuthorityBoundsV1,
    RootCreationEvidenceSubjectV1,
    RootCreationResultV1,
    SignedEvidenceEventV1,
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
    canonical_json_bytes,
    canonical_sha256,
    capability_lineage_anchor,
    create_rollout_root,
    decode_contract,
    encode_base64url,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
    root_creation_request_sha256,
)
from controlgraph_canary.contracts.base import MAX_SAFE_INTEGER

PROJECT = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
SERVICE = "controlgraph-reference-target"
STABLE = f"{SERVICE}-stable-v17"
CANDIDATE = f"{SERVICE}-candidate-v17"
CAPABILITY_KEY = (
    f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)
EVIDENCE_KEY = (
    f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
)
ZERO = "0" * 64
ONE = "1" * 64
TWO = "2" * 64


def _target(*, project_id: str = PROJECT) -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=project_id,
        region="us-central1",
        environment="nonprod",
        service_name=SERVICE,
    )


def _snapshot(*, target: TargetBinding | None = None, **changes: object) -> StableSnapshot:
    values: dict[str, object] = {
        "schema_version": "controlgraph.stable-snapshot/v1",
        "target": target or _target(),
        "stable_revision": STABLE,
        "traffic": (TrafficAllocation(revision=STABLE, percent=100),),
        "concurrency": 8,
        "service_generation": 7,
        "provider_etag": "stable-etag-7",
        "configuration_sha256": ZERO,
        "stable_revision_configuration_sha256": ONE,
        "captured_at": "2026-08-19T12:00:00Z",
        "captured_by": (
            f"controlgraph-verifier@{(target or _target()).project_id}.iam.gserviceaccount.com"
        ),
    }
    values.update(changes)
    return StableSnapshot.model_validate(values)


def _policy(**changes: object) -> RolloutHealthPolicyV1:
    values: dict[str, object] = {
        "schema_version": "controlgraph.rollout-health-policy/v1",
        "input_schema_version": "controlgraph.health-input/v1",
        "evaluation_window_seconds": 60,
        "minimum_request_count": 100,
        "maximum_error_rate_basis_points": 100,
        "maximum_p95_latency_ms": 500,
        "minimum_probe_count": 10,
        "minimum_probe_success_basis_points": 9_900,
        "healthy_consecutive_windows": 2,
        "unhealthy_consecutive_windows": 2,
        "window_semantics": "HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE",
        "incomplete_data_action": "INDETERMINATE_NO_MUTATION",
        "late_data_action": "INDETERMINATE_NO_MUTATION",
        "duplicate_data_action": "REJECT",
    }
    values.update(changes)
    return RolloutHealthPolicyV1.model_validate(values)


def _grant(action: CapabilityAction, *, project_id: str = PROJECT) -> RootActionGrantV1:
    role = "recovery" if action is CapabilityAction.RECOVER_STABLE else "executor"
    traffic = {
        CapabilityAction.APPLY_CANARY: (90, 10, None),
        CapabilityAction.PROMOTE_CANDIDATE: (0, 100, None),
        CapabilityAction.RECOVER_STABLE: (100, 0, 1),
    }[action]
    return RootActionGrantV1(
        schema_version="controlgraph.root-action-grant/v1",
        action=action,
        subject_identity=f"controlgraph-{role}@{project_id}.iam.gserviceaccount.com",
        audience=f"https://controlgraph-{role}-{PROJECT_NUMBER}.us-central1.run.app",
        stable_percent=traffic[0],
        candidate_percent=traffic[1],
        maximum_attempts=traffic[2],
    )


def _plan(
    *,
    target: TargetBinding | None = None,
    snapshot: StableSnapshot | None = None,
    policy: RolloutHealthPolicyV1 | None = None,
    **changes: object,
) -> RolloutPlanV1:
    bound_target = target or _target()
    bound_snapshot = snapshot or _snapshot(target=bound_target)
    bound_policy = policy or _policy()
    values: dict[str, object] = {
        "schema_version": "controlgraph.rollout-plan/v1",
        "target": bound_target,
        "stable_snapshot_sha256": canonical_sha256(bound_snapshot),
        "stable_revision": bound_snapshot.stable_revision,
        "stable_revision_configuration_sha256": (
            bound_snapshot.stable_revision_configuration_sha256
        ),
        "candidate_revision": CANDIDATE,
        "candidate_revision_configuration_sha256": TWO,
        "concurrency": bound_snapshot.concurrency,
        "stable_percent": 90,
        "candidate_percent": 10,
        "health_policy_sha256": canonical_sha256(bound_policy),
        "maximum_recovery_attempts": 1,
        "initial_epoch": 1,
    }
    values.update(changes)
    return RolloutPlanV1.model_validate(values)


def _bounds(
    *,
    target: TargetBinding | None = None,
    plan: RolloutPlanV1 | None = None,
    **changes: object,
) -> RootAuthorityBoundsV1:
    bound_target = target or _target()
    bound_plan = plan or _plan(target=bound_target)
    project_id = bound_target.project_id
    values: dict[str, object] = {
        "schema_version": "controlgraph.root-authority-bounds/v1",
        "target": bound_target,
        "stable_revision": bound_plan.stable_revision,
        "stable_revision_configuration_sha256": (bound_plan.stable_revision_configuration_sha256),
        "candidate_revision": bound_plan.candidate_revision,
        "candidate_revision_configuration_sha256": (
            bound_plan.candidate_revision_configuration_sha256
        ),
        "concurrency": bound_plan.concurrency,
        "plan_sha256": canonical_sha256(bound_plan),
        "capability_signing_key_version": CAPABILITY_KEY.replace(PROJECT, project_id),
        "issuer_identity": f"controlgraph-issuer@{project_id}.iam.gserviceaccount.com",
        "executor_identity": f"controlgraph-executor@{project_id}.iam.gserviceaccount.com",
        "recovery_identity": f"controlgraph-recovery@{project_id}.iam.gserviceaccount.com",
        "executor_audience": (
            f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "recovery_audience": (
            f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "maximum_capability_lifetime_seconds": 600,
        "maximum_recovery_attempts": 1,
        "apply_canary": _grant(CapabilityAction.APPLY_CANARY, project_id=project_id),
        "promote_candidate": _grant(CapabilityAction.PROMOTE_CANDIDATE, project_id=project_id),
        "recover_stable": _grant(CapabilityAction.RECOVER_STABLE, project_id=project_id),
    }
    values.update(changes)
    return RootAuthorityBoundsV1.model_validate(values)


def _content(
    *,
    target: TargetBinding | None = None,
    snapshot: StableSnapshot | None = None,
    policy: RolloutHealthPolicyV1 | None = None,
    plan_changes: dict[str, object] | None = None,
    bounds_changes: dict[str, object] | None = None,
    **changes: object,
) -> RolloutRootContentV2:
    bound_target = target or _target()
    bound_snapshot = snapshot or _snapshot(target=bound_target)
    bound_policy = policy or _policy()
    plan = _plan(
        target=bound_target,
        snapshot=bound_snapshot,
        policy=bound_policy,
        **(plan_changes or {}),
    )
    bounds = _bounds(target=bound_target, plan=plan, **(bounds_changes or {}))
    values: dict[str, object] = {
        "schema_version": "controlgraph.rollout-root-content/v2",
        "target": bound_target,
        "stable_snapshot": bound_snapshot,
        "health_policy": bound_policy,
        "rollout_plan": plan,
        "authority_bounds": bounds,
        "evidence_signing_key_version": EVIDENCE_KEY.replace(PROJECT, bound_target.project_id),
        "approved_by": "operator@example.test",
        "approved_by_subject": "123456789012345678901",
        "approved_at": "2026-08-19T12:01:00Z",
    }
    values.update(changes)
    return RolloutRootContentV2.model_validate(values)


def _root(**changes: object) -> RolloutRootV2:
    content = _content(**changes)
    return create_rollout_root(content)


def _event(root: RolloutRootV2 | None = None, **changes: object) -> EvidenceEvent:
    bound_root = root or _root()
    values: dict[str, object] = {
        "schema_version": "controlgraph.evidence-event/v1",
        "evidence_id": "evidence-root-001",
        "sequence": 0,
        "root_id": bound_root.root_id,
        "root_sha256": bound_root.root_sha256,
        "target": bound_root.content.target,
        "epoch": 1,
        "kind": EvidenceKind.ROOT_CREATED,
        "actor": "operator@example.test",
        "request_id": "request-root-001",
        "receipt_id": None,
        "occurred_at": "2026-08-19T12:01:00Z",
        "subject_sha256": bound_root.root_sha256,
        "previous_event_sha256": None,
        "reason_code": None,
        "provider_operation": None,
        "target_configuration_sha256": (
            bound_root.content.stable_snapshot.configuration_sha256
        ),
    }
    values.update(changes)
    return EvidenceEvent.model_validate(values)


def _signed_evidence(
    root: RolloutRootV2 | None = None,
    *,
    event: EvidenceEvent | None = None,
    **changes: object,
) -> SignedEvidenceEventV1:
    bound_root = root or _root()
    bound_event = event or _event(bound_root)
    key = bound_root.content.evidence_signing_key_version
    values: dict[str, object] = {
        "schema_version": "controlgraph.signed-evidence-event/v1",
        "event": bound_event,
        "purpose": "EVIDENCE",
        "signing_key_version": key,
        "signing_algorithm": "EC_SIGN_P256_SHA256",
        "payload_sha256": evidence_payload_sha256(bound_event),
        "signing_input_sha256": evidence_signing_input_sha256(bound_event, key),
        "signature": encode_base64url(b"synthetic-p256-signature"),
    }
    values.update(changes)
    return SignedEvidenceEventV1.model_validate(values)


def _result(root: RolloutRootV2 | None = None, **changes: object) -> RootCreationResultV1:
    bound_root = root or _root()
    created_at = "2026-08-19T12:01:01Z"
    request_sha256 = root_creation_request_sha256(
        root=bound_root,
        request_id="request-root-001",
        idempotency_key="root-create-001",
        operator_identity="operator@example.test",
        operator_subject="123456789012345678901",
    )
    anchor = capability_lineage_anchor(bound_root)
    anchor_sha256 = canonical_sha256(anchor)
    evidence_id = "evidence-root-001"
    initial_authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=bound_root.root_id,
        root_sha256=bound_root.root_sha256,
        target=bound_root.content.target,
        current_epoch=1,
        previous_epoch=None,
        revision=0,
        cause=EpochChangeCause.ROOT_CREATED,
        changed_by="operator@example.test",
        request_id="request-root-001",
        evidence_id=evidence_id,
        changed_at=created_at,
    )
    claim_id = canonical_sha256(bound_root.content.target)
    claim_sha256 = "5" * 64
    authority_sha256 = canonical_sha256(initial_authority)
    anchor_id = f"cganchor:{anchor_sha256}"
    evidence_subject = RootCreationEvidenceSubjectV1(
        schema_version="controlgraph.root-creation-evidence-subject/v1",
        root_id=bound_root.root_id,
        root_sha256=bound_root.root_sha256,
        request_sha256=request_sha256,
        created_at=created_at,
        service_claim_id=claim_id,
        service_claim_sha256=claim_sha256,
        authority_id=bound_root.root_id,
        authority_sha256=authority_sha256,
        lineage_anchor_id=anchor_id,
        lineage_anchor_sha256=anchor_sha256,
        evidence_id=evidence_id,
    )
    event = _event(
        bound_root,
        subject_sha256=canonical_sha256(evidence_subject),
        occurred_at=created_at,
    )
    signed_evidence = _signed_evidence(bound_root, event=event)
    values: dict[str, object] = {
        "schema_version": "controlgraph.root-creation-result/v1",
        "outcome": "CREATED",
        "request_id": "request-root-001",
        "idempotency_key": "root-create-001",
        "operator_identity": "operator@example.test",
        "operator_subject": "123456789012345678901",
        "request_sha256": request_sha256,
        "created_at": created_at,
        "winner_request_id": "request-root-001",
        "winner_idempotency_key": "root-create-001",
        "winner_operator_identity": "operator@example.test",
        "winner_operator_subject": "123456789012345678901",
        "winner_request_sha256": request_sha256,
        "winner_service_claim_id": claim_id,
        "winner_service_claim_sha256": claim_sha256,
        "winner_authority_id": bound_root.root_id,
        "winner_authority_sha256": authority_sha256,
        "winner_lineage_anchor_id": anchor_id,
        "winner_lineage_anchor_sha256": anchor_sha256,
        "winner_evidence_id": evidence_id,
        "winner_evidence_sha256": canonical_sha256(signed_evidence),
        "root": bound_root,
        "initial_authority": initial_authority,
        "lineage_anchor": anchor,
        "evidence_subject": evidence_subject,
        "signed_evidence": signed_evidence,
    }
    values.update(changes)
    return RootCreationResultV1.model_validate(values)


def test_root_content_is_self_addressed_and_round_trips() -> None:
    root = _root()

    assert root.root_sha256 == canonical_sha256(root.content)
    assert root.root_id == f"cgroot:{root.root_sha256}"
    assert decode_contract(canonical_json_bytes(root), RolloutRootV2) == root
    assert decode_contract(canonical_json_bytes(_result(root)), RootCreationResultV1) == _result(
        root
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda: _content(snapshot=_snapshot(provider_etag="stable-etag-8")),
        lambda: _content(policy=_policy(evaluation_window_seconds=61)),
        lambda: _content(plan_changes={"candidate_revision_configuration_sha256": "4" * 64}),
        lambda: _content(bounds_changes={"maximum_capability_lifetime_seconds": 599}),
        lambda: _content(
            evidence_signing_key_version=EVIDENCE_KEY.replace(
                "cryptoKeyVersions/1", "cryptoKeyVersions/2"
            )
        ),
        lambda: _content(approved_by="other.operator@example.test"),
        lambda: _content(approved_by_subject="223456789012345678901"),
        lambda: _content(approved_at="2026-08-19T12:01:01Z"),
    ],
)
def test_each_root_content_binding_changes_the_content_address(
    change: Callable[[], RolloutRootContentV2],
) -> None:
    assert canonical_sha256(change()) != canonical_sha256(_content())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evaluation_window_seconds", 61),
        ("minimum_request_count", 101),
        ("maximum_error_rate_basis_points", 101),
        ("maximum_p95_latency_ms", 501),
        ("minimum_probe_count", 11),
        ("minimum_probe_success_basis_points", 9_899),
        ("healthy_consecutive_windows", 3),
        ("unhealthy_consecutive_windows", 3),
    ],
)
def test_each_variable_health_policy_field_changes_its_hash(field: str, value: int) -> None:
    assert canonical_sha256(_policy(**{field: value})) != canonical_sha256(_policy())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stable_snapshot_sha256", "4" * 64),
        ("stable_revision", f"{SERVICE}-stable-v18"),
        ("stable_revision_configuration_sha256", "4" * 64),
        ("candidate_revision", f"{SERVICE}-candidate-v18"),
        ("candidate_revision_configuration_sha256", "4" * 64),
        ("concurrency", 9),
        ("health_policy_sha256", "4" * 64),
    ],
)
def test_each_variable_plan_field_changes_its_hash(field: str, value: object) -> None:
    assert canonical_sha256(_plan(**{field: value})) != canonical_sha256(_plan())


def test_target_change_changes_plan_hash() -> None:
    other_target = _target(project_id="controlgraph-canary-d4e5f6")
    other_snapshot = _snapshot(target=other_target)

    assert canonical_sha256(
        _plan(target=other_target, snapshot=other_snapshot)
    ) != canonical_sha256(_plan())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stable_revision", f"{SERVICE}-stable-v18"),
        ("stable_revision_configuration_sha256", "4" * 64),
        ("candidate_revision", f"{SERVICE}-candidate-v18"),
        ("candidate_revision_configuration_sha256", "4" * 64),
        ("concurrency", 9),
        ("plan_sha256", "4" * 64),
        (
            "capability_signing_key_version",
            CAPABILITY_KEY.replace("cryptoKeyVersions/1", "cryptoKeyVersions/2"),
        ),
        ("maximum_capability_lifetime_seconds", 599),
    ],
)
def test_each_variable_authority_bound_changes_its_hash(field: str, value: object) -> None:
    assert canonical_sha256(_bounds(**{field: value})) != canonical_sha256(_bounds())


@pytest.mark.parametrize(
    "changes",
    [
        {"root_sha256": "4" * 64},
        {"root_id": f"cgroot:{'4' * 64}"},
    ],
)
def test_root_rejects_self_address_mismatch(changes: dict[str, object]) -> None:
    values = _root().model_dump(mode="python")
    values.update(changes)

    with pytest.raises(ValidationError, match="rollout root"):
        RolloutRootV2.model_validate(values)


@pytest.mark.parametrize(
    ("field", "bad_values"),
    [
        ("evaluation_window_seconds", (0, 86_401)),
        ("minimum_request_count", (0, MAX_SAFE_INTEGER + 1)),
        ("maximum_error_rate_basis_points", (-1, 10_001)),
        ("maximum_p95_latency_ms", (0, MAX_SAFE_INTEGER + 1)),
        ("minimum_probe_count", (0, MAX_SAFE_INTEGER + 1)),
        ("minimum_probe_success_basis_points", (-1, 10_001)),
        ("healthy_consecutive_windows", (0, 65)),
        ("unhealthy_consecutive_windows", (0, 65)),
    ],
)
def test_health_policy_rejects_every_numeric_limit(field: str, bad_values: tuple[int, int]) -> None:
    for value in bad_values:
        with pytest.raises(ValidationError):
            _policy(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_schema_version", "controlgraph.health-input/v2"),
        ("window_semantics", "CLOSED"),
        ("incomplete_data_action", "HEALTHY"),
        ("late_data_action", "IGNORE"),
        ("duplicate_data_action", "COUNT"),
    ],
)
def test_health_policy_rejects_non_deterministic_semantics(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        _policy(**{field: value})


@pytest.mark.parametrize(
    "changes",
    [
        {"candidate_revision": STABLE},
        {"stable_revision": "unrelated-service-stable-v1"},
        {"candidate_revision": "unrelated-service-candidate-v1"},
        {"stable_percent": 89},
        {"candidate_percent": 11},
        {"maximum_recovery_attempts": 2},
        {"initial_epoch": 2},
        {"candidate_revision_configuration_sha256": "not-a-digest"},
    ],
)
def test_plan_rejects_widened_or_incomplete_bindings(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _plan(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"maximum_capability_lifetime_seconds": 901},
        {"maximum_recovery_attempts": 2},
        {"issuer_identity": f"controlgraph-executor@{PROJECT}.iam.gserviceaccount.com"},
        {
            "executor_audience": f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
        },
        {"recovery_audience": ("https://controlgraph-recovery-999999.us-central1.run.app")},
        {
            "capability_signing_key_version": CAPABILITY_KEY.replace(
                "capability-signing", "evidence-signing"
            )
        },
        {"apply_canary": _grant(CapabilityAction.PROMOTE_CANDIDATE)},
        {"recover_stable": _grant(CapabilityAction.APPLY_CANARY)},
    ],
)
def test_authority_bounds_reject_role_action_or_lifetime_widening(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _bounds(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"stable_percent": 91},
        {"candidate_percent": 9},
        {"maximum_attempts": 1},
    ],
)
def test_apply_grant_is_closed(changes: dict[str, object]) -> None:
    values = _grant(CapabilityAction.APPLY_CANARY).model_dump(mode="python")
    values.update(changes)
    with pytest.raises(ValidationError, match="closed action"):
        RootActionGrantV1.model_validate(values)


def test_root_content_rejects_independently_valid_recombined_objects() -> None:
    policy = _policy(maximum_error_rate_basis_points=200)
    plan = _plan()
    values = _content().model_dump(mode="python")
    values.update(health_policy=policy, rollout_plan=plan)
    with pytest.raises(ValidationError, match="health policy"):
        RolloutRootContentV2.model_validate(values)

    values = _content().model_dump(mode="python")
    values["authority_bounds"]["plan_sha256"] = "4" * 64  # type: ignore[index]
    with pytest.raises(ValidationError, match="canonical plan"):
        RolloutRootContentV2.model_validate(values)


@pytest.mark.parametrize(
    "changes",
    [
        {"approved_by": "Operator@example.test"},
        {"snapshot": _snapshot(captured_by="untrusted@example.test")},
        {
            "snapshot": _snapshot(captured_at="2026-08-19T12:02:00Z"),
            "approved_at": "2026-08-19T12:01:00Z",
        },
        {"target": _target(project_id="controlgraph-canary-reconcile")},
    ],
)
def test_root_content_rejects_aliased_identity_or_forbidden_target(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _content(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"purpose": "CAPABILITY"},
        {"signing_algorithm": "RSA_SIGN_PSS_2048_SHA256"},
        {"signing_key_version": EVIDENCE_KEY.replace("evidence-signing", "capability-signing")},
        {"payload_sha256": "4" * 64},
        {"signing_input_sha256": "4" * 64},
        {"payload_sha256": "short"},
        {"signature": "%%%"},
    ],
)
def test_signed_evidence_rejects_wrong_purpose_key_algorithm_or_digest(
    changes: dict[str, object],
) -> None:
    values = _signed_evidence().model_dump(mode="python")
    values.update(changes)
    with pytest.raises(ValidationError):
        SignedEvidenceEventV1.model_validate(values)


def test_signed_evidence_uses_the_existing_canonical_signing_input() -> None:
    signed = _signed_evidence()

    assert signed.payload_sha256 == evidence_payload_sha256(signed.event)
    assert signed.signing_input_sha256 == evidence_signing_input_sha256(
        signed.event, signed.signing_key_version
    )


@pytest.mark.parametrize(
    "event_changes",
    [
        {"provider_operation": "operations/unrelated"},
        {"target_configuration_sha256": None},
        {"target_configuration_sha256": "4" * 64},
    ],
)
def test_root_creation_evidence_rejects_non_root_event_fields(
    event_changes: dict[str, object],
) -> None:
    result = _result()
    event = _event(
        result.root,
        subject_sha256=canonical_sha256(result.evidence_subject),
        occurred_at=result.created_at,
        **event_changes,
    )
    signed = _signed_evidence(result.root, event=event)
    values = result.model_dump(mode="python")
    values["signed_evidence"] = signed
    values["winner_evidence_sha256"] = canonical_sha256(signed)

    with pytest.raises(ValidationError, match="root creation evidence"):
        RootCreationResultV1.model_validate(values)


def test_lineage_anchor_excludes_mutable_execution_and_time_facts() -> None:
    anchor = capability_lineage_anchor(_root()).model_dump(mode="json")

    for forbidden in (
        "current_epoch",
        "request_id",
        "idempotency_key",
        "provider_etag",
        "approved_at",
        "issued_at",
        "not_before",
        "expires_at",
    ):
        assert forbidden not in anchor
    assert anchor["initial_epoch"] == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"winner_request_id": "other-request"},
        {"winner_idempotency_key": "other-key"},
        {"winner_operator_identity": "other.operator@example.test"},
        {"winner_operator_subject": "223456789012345678901"},
        {"request_sha256": "4" * 64},
        {"created_at": "2026-08-19T12:00:59Z"},
        {"winner_service_claim_sha256": "4" * 64},
        {"winner_authority_sha256": "4" * 64},
        {"winner_lineage_anchor_sha256": "4" * 64},
        {"winner_evidence_sha256": "4" * 64},
        {"operator_identity": f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com"},
        {"lineage_anchor": capability_lineage_anchor(_root(approved_at="2026-08-19T12:01:01Z"))},
        {"signed_evidence": _signed_evidence(_root(approved_at="2026-08-19T12:01:01Z"))},
    ],
)
def test_creation_result_rejects_non_winner_or_recombined_artifacts(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _result(**changes)


@pytest.mark.parametrize(
    ("value", "model_type"),
    [
        (_policy(), RolloutHealthPolicyV1),
        (_plan(), RolloutPlanV1),
        (_grant(CapabilityAction.APPLY_CANARY), RootActionGrantV1),
        (_bounds(), RootAuthorityBoundsV1),
        (_content(), RolloutRootContentV2),
        (_root(), RolloutRootV2),
        (capability_lineage_anchor(_root()), type(capability_lineage_anchor(_root()))),
        (_result().evidence_subject, RootCreationEvidenceSubjectV1),
        (_signed_evidence(), SignedEvidenceEventV1),
        (_result(), RootCreationResultV1),
    ],
)
def test_every_root_creation_contract_rejects_unknown_fields(
    value: object,
    model_type: type,
) -> None:
    raw = json.loads(canonical_json_bytes(value))  # type: ignore[arg-type]
    raw["unexpected"] = "rejected"
    with pytest.raises(ValidationError):
        model_type.model_validate(raw)
