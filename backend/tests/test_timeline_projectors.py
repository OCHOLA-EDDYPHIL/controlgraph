import hashlib

import pytest
from health_execution_test_data import (
    make_health_root,
    make_healthy_chain,
    make_verified_apply_receipt,
)
from revocation_proof_test_data import make_revocation_proof_records
from root_v2_test_data import make_root_v2_records
from test_independent_verification import (
    _async,
    _bundle,
    _caller,
    _request,
    _service_with,
    _state,
    _verified,
)
from timeline_test_data import OTHER_TARGET

from controlgraph_canary.application.completion_classification import classify_completion
from controlgraph_canary.application.timeline_projectors import (
    project_completion_classification,
    project_epoch_authority,
    project_epoch_revocation,
    project_execution_receipt,
    project_independent_verification,
    project_signed_evidence_event,
    project_signed_health_proof,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.independent_verification import (
    COMPLETION_ASSESSMENT_REQUEST_V1,
    COMPLETION_CLASSIFICATION_V1,
    CompletionAssessmentRequestV1,
    CompletionClassificationV1,
    CompletionKind,
    CompletionReason,
    CompletionStatus,
    IndependentVerificationAttestationV1,
)
from controlgraph_canary.contracts.models import CapabilityAction
from controlgraph_canary.contracts.timeline import (
    TimelineCorrelationKind,
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


def test_independent_verification_projection_preserves_verified_signature_and_bindings() -> None:
    service, _, _, _ = _service_with(_state())
    attestation = _async(service.attest_configuration(_request(), _caller()))
    assert isinstance(attestation, IndependentVerificationAttestationV1)
    verified = _verified(attestation)
    policy_set = standard_timeline_evidence_policy_set(_request().target)

    projection = project_independent_verification(
        verified,
        policy_set=policy_set,
    )
    repeated = project_independent_verification(
        verified,
        policy_set=policy_set,
    )

    assert projection == repeated
    assert projection.event.event_type is TimelineEventType.VERIFICATION_RECORDED
    assert projection.event.verification_status is TimelineVerificationStatus.VERIFIED
    assert projection.event.terminal_classification is TimelineTerminalClassification.NONE
    assert projection.event.payload_sha256 == verified.signed_evidence.payload_sha256
    assert projection.event.signature is not None
    assert projection.event.signature.purpose == "INDEPENDENT_VERIFICATION"
    assert projection.event.signature.signing_input_sha256 == (
        verified.signed_evidence.signing_input_sha256
    )
    assert projection.event.signature.signature_sha256 == hashlib.sha256(b"\x01").hexdigest()
    assert projection.raw_source.canonical_record == canonical_json_bytes(verified).decode()
    correlations = {
        item.kind: item.correlation_id for item in projection.event.correlations
    }
    assert correlations == {
        TimelineCorrelationKind.EVIDENCE: (
            f"verification-evidence:{verified.signed_evidence.payload_sha256}"
        ),
        TimelineCorrelationKind.REQUEST: _request().request_id,
        TimelineCorrelationKind.VERIFICATION: _request().correlation_id,
    }


@pytest.mark.parametrize(
    ("kind", "action", "stable_percent", "candidate_percent", "reason", "terminal"),
    [
        (
            CompletionKind.PROMOTION,
            CapabilityAction.PROMOTE_CANDIDATE,
            0,
            100,
            CompletionReason.PROMOTION_COMPLETE,
            TimelineTerminalClassification.PROMOTED,
        ),
        (
            CompletionKind.RECOVERY,
            CapabilityAction.RECOVER_STABLE,
            100,
            0,
            CompletionReason.RECOVERY_COMPLETE,
            TimelineTerminalClassification.RECOVERED,
        ),
        (
            CompletionKind.REVOCATION,
            CapabilityAction.APPLY_CANARY,
            90,
            10,
            CompletionReason.REVOCATION_COMPLETE,
            TimelineTerminalClassification.REVOKED,
        ),
        (
            CompletionKind.STALE_CAPABILITY_DENIAL,
            CapabilityAction.APPLY_CANARY,
            90,
            10,
            CompletionReason.STALE_CAPABILITY_DENIAL_COMPLETE,
            TimelineTerminalClassification.DENIED,
        ),
    ],
)
def test_completion_projection_maps_each_complete_result_without_a_signature(
    kind: CompletionKind,
    action: CapabilityAction,
    stable_percent: int,
    candidate_percent: int,
    reason: CompletionReason,
    terminal: TimelineTerminalClassification,
) -> None:
    verification = _request(
        action=action,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
    )
    request = CompletionAssessmentRequestV1(
        schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
        kind=kind,
        verification=verification,
        assessed_at="2026-08-19T12:02:00Z",
    )
    classification = CompletionClassificationV1(
        schema_version=COMPLETION_CLASSIFICATION_V1,
        request=request,
        bundle_sha256="f" * 64,
        status=CompletionStatus.COMPLETE,
        reason=reason,
        follow_up_required=False,
        follow_up_after_seconds=None,
        follow_up_attempt_limit=None,
        classified_at=request.assessed_at,
    )

    projection = project_completion_classification(
        classification,
        policy_set=standard_timeline_evidence_policy_set(verification.target),
    )

    assert projection.event.terminal_classification is terminal
    assert projection.event.verification_status is TimelineVerificationStatus.VERIFIED
    assert projection.event.signature is None
    assert projection.event.payload_sha256 == canonical_sha256(classification)
    assert projection.raw_source.canonical_record == canonical_json_bytes(
        classification
    ).decode()


def test_ambiguous_completion_projection_stays_ambiguous_and_deterministic() -> None:
    request = _request(
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_percent=0,
        candidate_percent=100,
    )
    service, _, _, _ = _service_with(_state(0, 100), ["candidate"] * 20)
    configuration = _async(service.attest_configuration(request, _caller()))
    probe = _async(service.attest_probe(request, _caller()))
    assert isinstance(configuration, IndependentVerificationAttestationV1)
    assert isinstance(probe, IndependentVerificationAttestationV1)
    bundle = _bundle(request, configuration, probe).model_copy(update={"probe": None})
    classification = classify_completion(bundle)
    policy_set = standard_timeline_evidence_policy_set(request.target)

    first = project_completion_classification(classification, policy_set=policy_set)
    second = project_completion_classification(classification, policy_set=policy_set)

    assert first == second
    assert first.event.terminal_classification is TimelineTerminalClassification.AMBIGUOUS
    assert first.event.verification_status is TimelineVerificationStatus.AMBIGUOUS
    assert first.event.signature is None
    assert _fields(first)[TimelineDisplayFieldName.REASON_CODE] == (
        CompletionReason.PROBE_PROOF_ABSENT.value
    )
