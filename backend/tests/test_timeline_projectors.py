import hashlib

import pytest
from health_execution_test_data import (
    make_health_root,
    make_healthy_chain,
    make_verified_apply_receipt,
)
from revocation_proof_test_data import make_revocation_proof_records
from root_v2_test_data import make_root_v2_records
from timeline_test_data import OTHER_TARGET

from controlgraph_canary.application.timeline_projectors import (
    project_epoch_authority,
    project_epoch_revocation,
    project_execution_receipt,
    project_signed_evidence_event,
    project_signed_health_proof,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes
from controlgraph_canary.contracts.timeline import (
    TimelineDisplayFieldName,
    TimelineEventType,
    TimelineTerminalClassification,
    TimelineVerificationStatus,
    standard_timeline_evidence_policy_set,
)


def _fields(projection):  # type: ignore[no-untyped-def]
    return {item.name: item.value for item in projection.event.display_fields}


def test_signed_evidence_projection_is_raw_bound_and_verification_honest() -> None:
    records = make_root_v2_records()
    signed = records.signed_evidence
    policy_set = standard_timeline_evidence_policy_set(records.root.content.target)

    verified = project_signed_evidence_event(
        signed,
        policy_set=policy_set,
        signature_verified=True,
    )
    unverified = project_signed_evidence_event(
        signed,
        policy_set=policy_set,
        signature_verified=False,
    )

    assert verified.event.event_type is TimelineEventType.AUTHORITY_ROOT_CREATED
    assert verified.event.verification_status is TimelineVerificationStatus.VERIFIED
    assert unverified.event.verification_status is TimelineVerificationStatus.UNVERIFIED
    assert verified.event.signature is not None
    assert verified.event.signature.purpose == "EVIDENCE"
    assert verified.raw_source.canonical_record == canonical_json_bytes(signed).decode()
    assert verified.raw_source.record_sha256 == hashlib.sha256(
        canonical_json_bytes(signed)
    ).hexdigest()
    assert verified.event.raw_record_sha256 == verified.raw_source.record_sha256
    assert signed.event.actor not in canonical_json_bytes(verified.event).decode()

    with pytest.raises(ValueError):
        project_signed_evidence_event(
            signed,
            policy_set=standard_timeline_evidence_policy_set(OTHER_TARGET),
            signature_verified=True,
        )


def test_health_projection_separates_observation_and_decision_with_one_proof() -> None:
    signed = make_healthy_chain().signed_proofs[0]
    policy_set = standard_timeline_evidence_policy_set(signed.proof.decision.target)

    observed, decided = project_signed_health_proof(
        signed,
        policy_set=policy_set,
        signature_verified=True,
    )

    assert observed.event.event_type is TimelineEventType.HEALTH_OBSERVED
    assert decided.event.event_type is TimelineEventType.HEALTH_DECIDED
    assert observed.event.source_id.endswith(":observation")
    assert decided.event.source_id.endswith(":decision")
    assert observed.event.signature == decided.event.signature
    assert observed.event.signature is not None
    assert observed.event.signature.purpose == "HEALTH_ATTESTATION"
    assert observed.raw_source.raw_source_id == decided.raw_source.raw_source_id
    assert observed.raw_source.record_sha256 == decided.raw_source.record_sha256
    assert observed.raw_source.canonical_record == decided.raw_source.canonical_record
    assert _fields(observed)[TimelineDisplayFieldName.OBSERVATION] == "COMPLETE"
    assert _fields(decided)[TimelineDisplayFieldName.OUTCOME] == (
        signed.proof.decision.status.value
    )


def test_receipt_and_authority_projectors_do_not_invent_terminal_state() -> None:
    root = make_health_root()
    receipt = make_verified_apply_receipt(root)
    root_records = make_root_v2_records()
    policy_set = standard_timeline_evidence_policy_set(root.content.target)

    receipt_projection = project_execution_receipt(receipt, policy_set=policy_set)
    authority_projection = project_epoch_authority(
        root_records.authority,
        policy_set=standard_timeline_evidence_policy_set(
            root_records.authority.target
        ),
    )

    assert receipt_projection.event.event_type is TimelineEventType.MUTATION_APPLIED
    assert receipt_projection.event.terminal_classification is (
        TimelineTerminalClassification.NONE
    )
    assert receipt_projection.event.signature is None
    assert receipt_projection.event.verification_status is TimelineVerificationStatus.VERIFIED
    assert authority_projection.event.terminal_classification is (
        TimelineTerminalClassification.NONE
    )


def test_epoch_revocation_projects_action_before_terminal_classification() -> None:
    outcome = make_revocation_proof_records().call_outcome
    policy_set = standard_timeline_evidence_policy_set(outcome.result.target)

    action, terminal = project_epoch_revocation(outcome, policy_set=policy_set)

    assert action.event.event_type is TimelineEventType.OPERATOR_ACTION_RECORDED
    assert _fields(action)[TimelineDisplayFieldName.ACTION] == "REVOKE_EPOCH"
    assert _fields(action)[TimelineDisplayFieldName.REASON_CODE] == "OPERATOR_REQUESTED"
    assert action.event.terminal_classification is TimelineTerminalClassification.NONE
    assert terminal.event.event_type is TimelineEventType.TERMINAL_CLASSIFIED
    assert terminal.event.terminal_classification is TimelineTerminalClassification.REVOKED
    assert action.event.occurred_at == terminal.event.occurred_at
