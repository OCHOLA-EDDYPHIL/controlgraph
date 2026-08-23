"""Pure, fail-closed completion classification for ControlGraph terminal claims."""

from __future__ import annotations

from datetime import datetime

from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.independent_verification import (
    COMPLETION_CLASSIFICATION_V1,
    AuthorityCompletionKind,
    CompletionClassificationV1,
    CompletionEvidenceBundleV1,
    CompletionKind,
    CompletionReason,
    CompletionStatus,
    ConfigurationAttestationStatus,
    IndependentVerificationKind,
    ProbeAttestationReason,
    ProbeAttestationStatus,
    VerificationRequestV1,
    VerifiedIndependentVerificationEvidenceV1,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ReasonCode,
    ReceiptOutcome,
)

_MAX_EVIDENCE_ASSESSMENT_LAG_SECONDS = 300


def classify_completion(bundle: CompletionEvidenceBundleV1) -> CompletionClassificationV1:
    """Classify one closed bundle without I/O, clocks, retries, or side effects."""

    if type(bundle) is not CompletionEvidenceBundleV1:
        raise TypeError("an exact completion evidence bundle is required")

    reason = _classification_reason(bundle)
    complete_reasons = {
        CompletionReason.PROMOTION_COMPLETE,
        CompletionReason.RECOVERY_COMPLETE,
        CompletionReason.REVOCATION_COMPLETE,
        CompletionReason.STALE_CAPABILITY_DENIAL_COMPLETE,
    }
    status = (
        CompletionStatus.COMPLETE
        if reason in complete_reasons
        else CompletionStatus.AMBIGUOUS
    )
    return CompletionClassificationV1(
        schema_version=COMPLETION_CLASSIFICATION_V1,
        request=bundle.request,
        bundle_sha256=canonical_sha256(bundle),
        status=status,
        reason=reason,
        follow_up_required=status is CompletionStatus.AMBIGUOUS,
        follow_up_after_seconds=(5 if status is CompletionStatus.AMBIGUOUS else None),
        follow_up_attempt_limit=(3 if status is CompletionStatus.AMBIGUOUS else None),
        classified_at=bundle.request.assessed_at,
    )


def _classification_reason(bundle: CompletionEvidenceBundleV1) -> CompletionReason:
    request = bundle.request
    verification = request.verification
    execution = bundle.execution

    if execution is not None and (
        not execution.write_outcome_known
        or execution.outcome is ReceiptOutcome.AMBIGUOUS
    ):
        return CompletionReason.UNCERTAIN_WRITE

    if execution is not None and (
        execution.root_id != verification.root_id
        or execution.root_sha256 != verification.root_sha256
        or execution.epoch != verification.epoch
        or execution.target != verification.target
        or execution.plan_sha256 != verification.plan_sha256
        or execution.signed_intent_sha256 != verification.signed_intent_sha256
        or execution.request_id != verification.request_id
        or execution.correlation_id != verification.correlation_id
        or execution.observation_window_started_at
        != verification.observation_window_started_at
        or execution.observation_window_ends_at
        != verification.observation_window_ends_at
    ):
        return CompletionReason.EVIDENCE_BINDING_MISMATCH

    if request.kind is CompletionKind.REVOCATION:
        if bundle.authority is None:
            return CompletionReason.AUTHORITY_PROOF_ABSENT
        if not _authority_matches(bundle, AuthorityCompletionKind.REVOCATION):
            return CompletionReason.EVIDENCE_BINDING_MISMATCH
        if _assessment_is_stale(bundle):
            return CompletionReason.EVIDENCE_STALE
        return CompletionReason.REVOCATION_COMPLETE

    if request.kind is CompletionKind.STALE_CAPABILITY_DENIAL:
        if bundle.authority is None:
            return CompletionReason.AUTHORITY_PROOF_ABSENT
        if not _authority_matches(bundle, AuthorityCompletionKind.EPOCH_ADVANCEMENT):
            return CompletionReason.EVIDENCE_BINDING_MISMATCH
        if execution is None:
            return CompletionReason.EXECUTION_PROOF_ABSENT
        if _assessment_is_stale(bundle):
            return CompletionReason.EVIDENCE_STALE
        if (
            execution.outcome is not ReceiptOutcome.DENIED
            or execution.reason_code is not ReasonCode.EPOCH_MISMATCH
        ):
            return CompletionReason.EXECUTION_EVIDENCE_CONTRADICTORY
        return CompletionReason.STALE_CAPABILITY_DENIAL_COMPLETE

    expected_action = (
        CapabilityAction.PROMOTE_CANDIDATE
        if request.kind is CompletionKind.PROMOTION
        else CapabilityAction.RECOVER_STABLE
    )
    if execution is None:
        return CompletionReason.EXECUTION_PROOF_ABSENT
    if (
        execution.action is not expected_action
        or execution.outcome is not ReceiptOutcome.VERIFIED
        or execution.reason_code is not None
    ):
        return CompletionReason.EXECUTION_EVIDENCE_CONTRADICTORY

    configuration = bundle.configuration
    if configuration is None:
        return CompletionReason.CONFIGURATION_PROOF_ABSENT
    if not _evidence_matches(
        configuration,
        bundle,
        IndependentVerificationKind.CONFIGURATION,
    ):
        return CompletionReason.EVIDENCE_BINDING_MISMATCH
    if _evidence_is_stale(configuration, bundle):
        return CompletionReason.EVIDENCE_STALE
    configuration_result = configuration.signing_request.configuration
    if configuration_result is None:
        return CompletionReason.EVIDENCE_BINDING_MISMATCH
    if configuration_result.status is ConfigurationAttestationStatus.UNAVAILABLE:
        return CompletionReason.CONFIGURATION_UNAVAILABLE
    if configuration_result.status is ConfigurationAttestationStatus.MISMATCH:
        return CompletionReason.CONFIGURATION_MISMATCH

    probe = bundle.probe
    if probe is None:
        return CompletionReason.PROBE_PROOF_ABSENT
    if not _evidence_matches(probe, bundle, IndependentVerificationKind.PROBE):
        return CompletionReason.EVIDENCE_BINDING_MISMATCH
    if _evidence_is_stale(probe, bundle):
        return CompletionReason.EVIDENCE_STALE
    probe_result = probe.signing_request.probe
    if probe_result is None:
        return CompletionReason.EVIDENCE_BINDING_MISMATCH
    if probe_result.status is ProbeAttestationStatus.INCONCLUSIVE:
        if probe_result.reason in {
            ProbeAttestationReason.DISTRIBUTION_MISMATCH,
            ProbeAttestationReason.RESPONSE_INVALID,
        }:
            return CompletionReason.CONFIGURATION_DATA_DISAGREEMENT
        return CompletionReason.PROBE_INCONCLUSIVE

    if request.kind is CompletionKind.PROMOTION:
        return CompletionReason.PROMOTION_COMPLETE
    return CompletionReason.RECOVERY_COMPLETE


def _evidence_matches(
    evidence: VerifiedIndependentVerificationEvidenceV1,
    bundle: CompletionEvidenceBundleV1,
    kind: IndependentVerificationKind,
) -> bool:
    expected = bundle.request.verification
    signing_request = evidence.signing_request
    signed = evidence.signed_evidence.evidence
    bound_request: VerificationRequestV1 | None
    if kind is IndependentVerificationKind.CONFIGURATION:
        configuration = signing_request.configuration
        bound_request = configuration.request if configuration is not None else None
    else:
        probe = signing_request.probe
        bound_request = probe.request.verification if probe is not None else None
    return (
        bound_request == expected
        and evidence.signed_evidence.evidence == signing_request.evidence
        and signed.kind is kind
        and signed.verification_request_sha256 == canonical_sha256(expected)
        and signed.root_id == expected.root_id
        and signed.root_sha256 == expected.root_sha256
        and signed.epoch == expected.epoch
        and signed.target == expected.target
        and signed.plan_sha256 == expected.plan_sha256
        and signed.signed_intent_sha256 == expected.signed_intent_sha256
        and signed.action is expected.action
        and signed.stable_revision == expected.stable_revision
        and signed.candidate_revision == expected.candidate_revision
        and signed.stable_percent == expected.stable_percent
        and signed.candidate_percent == expected.candidate_percent
        and signed.concurrency == expected.concurrency
        and signed.request_id == expected.request_id
        and signed.correlation_id == expected.correlation_id
        and signed.observation_window_started_at
        == expected.observation_window_started_at
        and signed.observation_window_ends_at == expected.observation_window_ends_at
        and signed.verifier_identity
        == (
            f"controlgraph-verifier@{expected.target.project_id}"
            ".iam.gserviceaccount.com"
        )
    )


def _authority_matches(
    bundle: CompletionEvidenceBundleV1,
    kind: AuthorityCompletionKind,
) -> bool:
    authority = bundle.authority
    expected = bundle.request.verification
    return authority is not None and (
        authority.kind is kind
        and authority.root_id == expected.root_id
        and authority.root_sha256 == expected.root_sha256
        and authority.epoch == expected.epoch
        and authority.target == expected.target
        and authority.plan_sha256 == expected.plan_sha256
        and authority.request_id == expected.request_id
        and authority.correlation_id == expected.correlation_id
        and authority.observation_window_started_at
        == expected.observation_window_started_at
        and authority.observation_window_ends_at
        == expected.observation_window_ends_at
    )


def _evidence_is_stale(
    evidence: VerifiedIndependentVerificationEvidenceV1,
    bundle: CompletionEvidenceBundleV1,
) -> bool:
    assessed_at = _parse_utc(bundle.request.assessed_at)
    verified_at = _parse_utc(evidence.verified_at)
    return (
        assessed_at < verified_at
        or _assessment_is_stale(bundle)
    )


def _assessment_is_stale(bundle: CompletionEvidenceBundleV1) -> bool:
    assessed_at = _parse_utc(bundle.request.assessed_at)
    window_end = _parse_utc(bundle.request.verification.observation_window_ends_at)
    return (
        assessed_at - window_end
    ).total_seconds() > _MAX_EVIDENCE_ASSESSMENT_LAG_SECONDS


def _parse_utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


__all__ = ["classify_completion"]
