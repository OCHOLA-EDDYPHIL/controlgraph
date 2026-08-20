from __future__ import annotations

from dataclasses import dataclass

from root_v2_test_data import PROJECT_NUMBER, make_root_v2_records

from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.models import (
    EPOCH_AUTHORITY_V1,
    EVIDENCE_EVENT_V1,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_AUDIT_V1,
    EPOCH_REVOCATION_CALL_OUTCOME_V1,
    EPOCH_REVOCATION_COMMAND_V1,
    EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1,
    EPOCH_REVOCATION_INVOCATION_V1,
    EPOCH_REVOCATION_PROOF_COMMAND_V1,
    EPOCH_REVOCATION_PROOF_INVOCATION_V1,
    EPOCH_REVOCATION_PROOF_V1,
    EPOCH_REVOCATION_RESULT_V1,
    EpochRevocationAuditOutcome,
    EpochRevocationAuditV1,
    EpochRevocationCallOutcomeV1,
    EpochRevocationCommandV1,
    EpochRevocationEvidenceSubjectV1,
    EpochRevocationInvocationV1,
    EpochRevocationProofCommandV1,
    EpochRevocationProofInvocationV1,
    EpochRevocationProofV1,
    EpochRevocationResultV1,
    epoch_revocation_evidence_id,
    epoch_revocation_request_sha256,
)
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    SignedEvidenceEventV1,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)

OPERATOR = "operator@example.test"
OPERATOR_SUBJECT = "123456789012345678901"
API_AUDIENCE = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
COMMITTED_AT = "2026-08-19T12:05:00Z"


@dataclass(frozen=True, slots=True)
class RevocationProofRecords:
    invocation: EpochRevocationInvocationV1
    call_outcome: EpochRevocationCallOutcomeV1
    proof_command: EpochRevocationProofCommandV1
    proof_invocation: EpochRevocationProofInvocationV1
    proof: EpochRevocationProofV1


def make_revocation_proof_records(
    *,
    attempt_id: str = "cgrevoke-attempt-proof-001",
) -> RevocationProofRecords:
    root_records = make_root_v2_records()
    root = root_records.root
    command = EpochRevocationCommandV1(
        schema_version=EPOCH_REVOCATION_COMMAND_V1,
        root_id=root.root_id,
        expected_root_sha256=root.root_sha256,
        expected_epoch=1,
        reason="Stop the canary before delayed work executes.",
        request_id="request-revoke-proof-001",
        idempotency_key="revoke-proof-001",
        confirmation="REVOKE",
    )
    invocation = EpochRevocationInvocationV1(
        schema_version=EPOCH_REVOCATION_INVOCATION_V1,
        command=command,
        attempt_id=attempt_id,
        operator_identity=OPERATOR,
        operator_subject=OPERATOR_SUBJECT,
        operator_issuer="https://accounts.google.com",
        operator_audience=API_AUDIENCE,
        operator_issued_at=1_787_140_000,
        operator_expires_at=1_787_140_600,
    )
    request_sha256 = epoch_revocation_request_sha256(invocation)
    evidence_id = epoch_revocation_evidence_id(
        request_sha256,
        root.root_sha256,
        2,
    )
    authority = EpochAuthorityRecord(
        schema_version=EPOCH_AUTHORITY_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        current_epoch=2,
        previous_epoch=1,
        revision=1,
        cause=EpochChangeCause.OPERATOR_REVOCATION,
        changed_by=OPERATOR,
        request_id=command.request_id,
        evidence_id=evidence_id,
        changed_at=COMMITTED_AT,
    )
    subject = EpochRevocationEvidenceSubjectV1(
        schema_version=EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        request_sha256=request_sha256,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        operator_identity=OPERATOR,
        operator_subject=OPERATOR_SUBJECT,
        reason=command.reason,
        service_claim_sha256=canonical_sha256(root_records.service_claim),
        previous_authority_sha256=canonical_sha256(root_records.authority),
        replacement_authority_sha256=canonical_sha256(authority),
        previous_epoch=1,
        new_epoch=2,
        evidence_id=evidence_id,
        committed_at=COMMITTED_AT,
    )
    event = EvidenceEvent(
        schema_version=EVIDENCE_EVENT_V1,
        evidence_id=evidence_id,
        sequence=1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        epoch=2,
        kind=EvidenceKind.EPOCH_ADVANCED,
        actor=OPERATOR,
        request_id=command.request_id,
        receipt_id=None,
        occurred_at=COMMITTED_AT,
        subject_sha256=canonical_sha256(subject),
        previous_event_sha256=canonical_sha256(root_records.signed_evidence),
        reason_code=None,
        provider_operation=None,
        target_configuration_sha256=None,
    )
    key_version = root.content.evidence_signing_key_version
    signed_evidence = SignedEvidenceEventV1(
        schema_version=SIGNED_EVIDENCE_EVENT_V1,
        event=event,
        purpose="EVIDENCE",
        signing_key_version=key_version,
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=evidence_payload_sha256(event),
        signing_input_sha256=evidence_signing_input_sha256(event, key_version),
        signature=encode_base64url(b"synthetic-revocation-proof-signature"),
    )
    result = EpochRevocationResultV1(
        schema_version=EPOCH_REVOCATION_RESULT_V1,
        result_id=f"cgrevoke:{request_sha256}",
        request_sha256=request_sha256,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        operator_identity=OPERATOR,
        operator_subject=OPERATOR_SUBJECT,
        reason=command.reason,
        previous_epoch=1,
        new_epoch=2,
        evidence_id=evidence_id,
        evidence_sha256=canonical_sha256(signed_evidence),
        evidence_subject=subject,
        committed_at=COMMITTED_AT,
    )
    audit = EpochRevocationAuditV1(
        schema_version=EPOCH_REVOCATION_AUDIT_V1,
        audit_id=attempt_id,
        attempt_id=attempt_id,
        request_sha256=request_sha256,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        expected_epoch=1,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        operator_identity=OPERATOR,
        operator_subject=OPERATOR_SUBJECT,
        outcome=EpochRevocationAuditOutcome.COMMITTED,
        failure_code=None,
        result_id=result.result_id,
        evidence_id=evidence_id,
        new_epoch=2,
        recorded_at=COMMITTED_AT,
    )
    proof = EpochRevocationProofV1(
        schema_version=EPOCH_REVOCATION_PROOF_V1,
        authority=authority,
        signed_evidence=signed_evidence,
        result=result,
        audit=audit,
    )
    call_outcome = EpochRevocationCallOutcomeV1(
        schema_version=EPOCH_REVOCATION_CALL_OUTCOME_V1,
        attempt_id=attempt_id,
        audit_id=attempt_id,
        result=result,
    )
    proof_command = EpochRevocationProofCommandV1(
        schema_version=EPOCH_REVOCATION_PROOF_COMMAND_V1,
        root_id=result.root_id,
        root_sha256=result.root_sha256,
        previous_epoch=result.previous_epoch,
        new_epoch=result.new_epoch,
        reason=result.reason,
        request_sha256=result.request_sha256,
        request_id=result.request_id,
        idempotency_key=result.idempotency_key,
        result_id=result.result_id,
        evidence_id=result.evidence_id,
        evidence_sha256=result.evidence_sha256,
        attempt_id=attempt_id,
        audit_id=attempt_id,
    )
    proof_invocation = EpochRevocationProofInvocationV1(
        schema_version=EPOCH_REVOCATION_PROOF_INVOCATION_V1,
        command=proof_command,
        operator_identity=OPERATOR,
        operator_subject=OPERATOR_SUBJECT,
        operator_issuer="https://accounts.google.com",
        operator_audience=API_AUDIENCE,
        operator_issued_at=invocation.operator_issued_at,
        operator_expires_at=invocation.operator_expires_at,
    )
    return RevocationProofRecords(
        invocation=invocation,
        call_outcome=call_outcome,
        proof_command=proof_command,
        proof_invocation=proof_invocation,
        proof=proof,
    )


__all__ = [
    "API_AUDIENCE",
    "OPERATOR",
    "OPERATOR_SUBJECT",
    "RevocationProofRecords",
    "make_revocation_proof_records",
]
