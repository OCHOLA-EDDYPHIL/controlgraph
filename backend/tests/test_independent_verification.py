from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_root_trust import (
    CANDIDATE,
    CANDIDATE_CONFIGURATION,
    EVIDENCE_KEY_VERSION,
    NOW,
    PROJECT,
    PROJECT_NUMBER,
    STABLE,
    STABLE_CONFIGURATION,
    VERIFIER_AUDIENCE,
    VERIFIER_IDENTITY,
    _revision,
    _service,
    _target,
)

from controlgraph_canary.application.cloud_run import (
    CloudRunReadyState,
    CloudRunTargetState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
    TargetConfigurationProjection,
    cloud_run_revision_configuration_sha256,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.completion_classification import (
    CoordinatorCompletionClassificationService,
    classify_completion,
)
from controlgraph_canary.application.identity import (
    INDEPENDENT_VERIFICATION_EVIDENCE_PATH,
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.independent_verification import (
    IndependentVerificationError,
    IndependentVerificationErrorCode,
    IndependentVerificationService,
    ProbeHttpResponse,
)
from controlgraph_canary.application.independent_verification_signing import (
    CoordinatorIndependentVerificationClient,
    IndependentVerificationSigningService,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.signing import SigningProfile
from controlgraph_canary.cli import main
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.independent_verification import (
    AUTHORITY_COMPLETION_EVIDENCE_V1,
    COMPLETION_ASSESSMENT_REQUEST_V1,
    COMPLETION_EVIDENCE_BUNDLE_V1,
    EXECUTION_COMPLETION_EVIDENCE_V1,
    INDEPENDENT_VERIFICATION_INVOCATION_V1,
    INDEPENDENT_VERIFICATION_PURPOSE,
    P256_SIGNING_ALGORITHM,
    PROBE_REQUEST_V1,
    SEALED_REFERENCE_PROBE_V1,
    SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
    VERIFICATION_REQUEST_V1,
    VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
    AuthorityCompletionEvidenceV1,
    AuthorityCompletionKind,
    CompletionAssessmentRequestV1,
    CompletionClassificationV1,
    CompletionEvidenceBundleV1,
    CompletionKind,
    CompletionReason,
    CompletionStatus,
    ConfigurationAttestationReason,
    ConfigurationAttestationStatus,
    ExecutionCompletionEvidenceV1,
    IndependentVerificationAttestationV1,
    IndependentVerificationInvocationV1,
    IndependentVerificationKind,
    ProbeAttestationReason,
    ProbeAttestationStatus,
    ProbeRequestV1,
    SealedReferenceProbeV1,
    SignedIndependentVerificationEvidenceV1,
    VerificationRequestV1,
    VerifiedIndependentVerificationEvidenceV1,
    fixed_probe_policy,
    independent_verification_signing_input_sha256,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.http.service import create_service_app
from controlgraph_canary.reference_target import (
    STABLE_MARKER,
    ReferenceVariant,
    create_reference_app,
)


def _async(coroutine: object) -> object:
    return asyncio.run(coroutine)  # type: ignore[arg-type]


def _policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.VERIFIER,
        path=protected_path(ServiceRole.VERIFIER),
        audience=VERIFIER_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.COORDINATOR,
            email=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com",
            subject="345678901234567890123",
        ),
    )


def _caller() -> AuthenticationContext:
    return AuthenticationContext(
        role=CallerRole.COORDINATOR,
        email=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com",
        subject="345678901234567890123",
        issuer="https://accounts.google.com",
        audience=VERIFIER_AUDIENCE,
        issued_at=1_776_236_400,
        expires_at=1_776_237_000,
    )


def _state(stable_percent: int = 90, candidate_percent: int = 10) -> CloudRunTargetState:
    traffic = tuple(
        CloudRunTrafficAllocation(revision=revision, percent=percent, tag=None)
        for revision, percent in (
            (STABLE, stable_percent),
            (CANDIDATE, candidate_percent),
        )
    )
    statuses = tuple(
        CloudRunTrafficStatus(
            revision=revision,
            percent=percent,
            tag=None,
            uri=None,
        )
        for revision, percent in (
            (STABLE, stable_percent),
            (CANDIDATE, candidate_percent),
        )
    )
    return CloudRunTargetState(
        service=replace(_service(), traffic=traffic, traffic_statuses=statuses),
        stable_revision=_revision(STABLE, configuration=STABLE_CONFIGURATION),
        candidate_revision=_revision(CANDIDATE, configuration=CANDIDATE_CONFIGURATION),
    )


def _request(
    *,
    action: CapabilityAction = CapabilityAction.APPLY_CANARY,
    stable_percent: int = 90,
    candidate_percent: int = 10,
) -> VerificationRequestV1:
    digest = target_configuration_projection_sha256(
        TargetConfigurationProjection(
            target=_target(),
            stable_revision=STABLE,
            candidate_revision=CANDIDATE,
            stable_percent=stable_percent,
            candidate_percent=candidate_percent,
            concurrency=8,
        )
    )
    return VerificationRequestV1(
        schema_version=VERIFICATION_REQUEST_V1,
        root_id=f"cgroot:{'a' * 64}",
        root_sha256="a" * 64,
        epoch=2,
        target=_target(),
        plan_sha256="b" * 64,
        service_claim_sha256="d" * 64,
        probe_policy_sha256=canonical_sha256(
            fixed_probe_policy(stable_percent, candidate_percent)
        ),
        signed_intent_sha256="9" * 64,
        action=action,
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=8,
        expected_stable_revision_configuration_sha256=(
            cloud_run_revision_configuration_sha256(STABLE_CONFIGURATION)
        ),
        expected_candidate_revision_configuration_sha256=(
            cloud_run_revision_configuration_sha256(CANDIDATE_CONFIGURATION)
        ),
        expected_target_configuration_sha256=digest,
        observation_window_started_at="2026-08-19T11:59:00Z",
        observation_window_ends_at="2026-08-19T12:01:00Z",
        request_id="verify-001",
        correlation_id="probe-001",
    )


class _Reader:
    def __init__(self, state: object) -> None:
        self.state = state
        self.calls = 0

    @property
    def target(self):  # type: ignore[no-untyped-def]
        return _target()

    @property
    def service_role(self) -> ServiceRole:
        return ServiceRole.VERIFIER

    @property
    def reader_identity(self) -> str:
        return VERIFIER_IDENTITY

    async def read_target(self) -> CloudRunTargetState:
        self.calls += 1
        if isinstance(self.state, BaseException):
            raise self.state
        return self.state  # type: ignore[return-value]


class _ProbeTransport:
    endpoint = (
        f"https://controlgraph-reference-target-{PROJECT_NUMBER}.us-central1.run.app"
        "/v1/probe"
    )

    def __init__(self, outcomes: list[str]) -> None:
        self.outcomes = outcomes
        self.calls: list[tuple[str, str, int, int]] = []

    async def get(
        self,
        *,
        nonce: str,
        correlation_id: str,
        timeout_milliseconds: int,
        response_limit_bytes: int,
    ) -> ProbeHttpResponse:
        self.calls.append(
            (nonce, correlation_id, timeout_milliseconds, response_limit_bytes)
        )
        outcome = self.outcomes[len(self.calls) - 1]
        if outcome == "unavailable":
            raise OSError("synthetic transport failure")
        revision, marker = (
            (STABLE, "controlgraph-stable-v1")
            if outcome == "stable"
            else (CANDIDATE, "controlgraph-candidate-v1")
        )
        response = SealedReferenceProbeV1(
            schema_version=SEALED_REFERENCE_PROBE_V1,
            revision=revision,
            marker=marker,
            nonce=nonce,
            correlation_id=(
                "substituted-correlation" if outcome == "invalid" else correlation_id
            ),
        )
        return ProbeHttpResponse(
            status_code=200,
            content_type="application/json",
            body=canonical_json_bytes(response),
        )


class _EvidenceClient:
    def __init__(self) -> None:
        self.calls = []

    async def sign(self, request):  # type: ignore[no-untyped-def]
        self.calls.append(request)
        evidence = request.evidence
        return SignedIndependentVerificationEvidenceV1(
            schema_version=SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
            evidence=evidence,
            purpose=INDEPENDENT_VERIFICATION_PURPOSE,
            signing_key_version=EVIDENCE_KEY_VERSION,
            signing_algorithm=P256_SIGNING_ALGORITHM,
            payload_sha256=canonical_sha256(evidence),
            signing_input_sha256=independent_verification_signing_input_sha256(
                evidence,
                EVIDENCE_KEY_VERSION,
            ),
            signature="AQ",
        )


def _service_with(
    state: object,
    outcomes: list[str] | None = None,
) -> tuple[IndependentVerificationService, _Reader, _ProbeTransport, _EvidenceClient]:
    reader = _Reader(state)
    transport = _ProbeTransport(outcomes or (["stable"] * 18 + ["candidate"] * 2))
    evidence = _EvidenceClient()
    service = IndependentVerificationService(
        target=_target(),
        authentication_policy=_policy(),
        reader_factory=lambda _request: reader,
        probe_transport=transport,
        evidence_client=evidence,
        clock=lambda: NOW,
        nonce_factory=lambda: "n" * 32,
    )
    return service, reader, transport, evidence


def _verified(
    attestation: IndependentVerificationAttestationV1,
) -> VerifiedIndependentVerificationEvidenceV1:
    return VerifiedIndependentVerificationEvidenceV1(
        schema_version=VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
        signing_request=attestation.signing_request,
        signed_evidence=attestation.signed_evidence,
        verified_at="2026-08-19T12:01:30Z",
    )


def _execution(request: VerificationRequestV1) -> ExecutionCompletionEvidenceV1:
    return ExecutionCompletionEvidenceV1(
        schema_version=EXECUTION_COMPLETION_EVIDENCE_V1,
        root_id=request.root_id,
        root_sha256=request.root_sha256,
        epoch=request.epoch,
        target=request.target,
        plan_sha256=request.plan_sha256,
        service_claim_sha256=request.service_claim_sha256,
        probe_policy_sha256=request.probe_policy_sha256,
        signed_intent_sha256=request.signed_intent_sha256,
        intent_signature_verified=True,
        request_id=request.request_id,
        correlation_id=request.correlation_id,
        observation_window_started_at=request.observation_window_started_at,
        observation_window_ends_at=request.observation_window_ends_at,
        action=request.action,
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        observed_authority_epoch=request.epoch,
        receipt_sha256="c" * 64,
        receipt_persisted=True,
        write_outcome_known=True,
    )


def _authority(
    request: VerificationRequestV1,
    kind: AuthorityCompletionKind,
) -> AuthorityCompletionEvidenceV1:
    return AuthorityCompletionEvidenceV1(
        schema_version=AUTHORITY_COMPLETION_EVIDENCE_V1,
        kind=kind,
        root_id=request.root_id,
        root_sha256=request.root_sha256,
        epoch=request.epoch,
        target=request.target,
        plan_sha256=request.plan_sha256,
        request_id=request.request_id,
        correlation_id=request.correlation_id,
        observation_window_started_at=request.observation_window_started_at,
        observation_window_ends_at=request.observation_window_ends_at,
        authority_evidence_sha256="e" * 64,
        signature_verified=True,
        occurred_at="2026-08-19T12:00:30Z",
    )


def _bundle(
    request: VerificationRequestV1,
    configuration: IndependentVerificationAttestationV1,
    probe: IndependentVerificationAttestationV1,
) -> CompletionEvidenceBundleV1:
    assessment = CompletionAssessmentRequestV1(
        schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
        kind=(
            CompletionKind.PROMOTION
            if request.action is CapabilityAction.PROMOTE_CANDIDATE
            else CompletionKind.RECOVERY
        ),
        verification=request,
        assessed_at="2026-08-19T12:02:00Z",
    )
    return CompletionEvidenceBundleV1(
        schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
        request=assessment,
        execution=_execution(request),
        configuration=_verified(configuration),
        probe=_verified(probe),
    )


def test_configuration_match_is_separately_signed_with_complete_observation() -> None:
    service, reader, _, evidence = _service_with(_state())

    result = _async(service.attest_configuration(_request(), _caller()))

    assert isinstance(result, IndependentVerificationAttestationV1)
    configuration = result.signing_request.configuration
    assert configuration is not None
    assert configuration.status is ConfigurationAttestationStatus.MATCH
    assert configuration.reason is ConfigurationAttestationReason.MATCH
    assert configuration.observation is not None
    facts = configuration.observation.facts
    assert facts.source_generation == 7
    assert facts.observed_generation == 7
    assert facts.stable_revision == STABLE
    assert facts.candidate_revision == CANDIDATE
    assert facts.retrieved_by == VERIFIER_IDENTITY
    assert facts.target_configuration_sha256 == (
        _request().expected_target_configuration_sha256
    )
    assert reader.calls == 1
    assert len(evidence.calls) == 1


def test_verification_request_rejects_a_substituted_probe_policy_digest() -> None:
    request = _request()

    with pytest.raises(ValidationError):
        VerificationRequestV1.model_validate(
            {
                **request.model_dump(mode="python"),
                "probe_policy_sha256": "f" * 64,
            }
        )


def test_probe_request_rejects_policy_not_matching_committed_digest() -> None:
    request = _request()
    altered_policy = fixed_probe_policy(90, 10).model_copy(
        update={"timeout_milliseconds": 1_999}
    )
    probe_request = ProbeRequestV1.model_construct(
        schema_version=PROBE_REQUEST_V1,
        verification=request,
        policy=altered_policy,
        endpoint="https://controlgraph-reference-target.example/v1/probe",
        nonce="n" * 32,
        started_at="2026-08-19T12:00:00Z",
    )

    with pytest.raises(ValueError):
        probe_request.validate_probe()


def test_configuration_mismatch_and_unavailable_are_signed_not_promoted_to_match() -> None:
    mismatched = replace(_state(), service=replace(_state().service, template_concurrency=9))
    mismatch_service, _, _, _ = _service_with(mismatched)
    unavailable_service, _, _, _ = _service_with(OSError("synthetic"))

    mismatch = _async(mismatch_service.attest_configuration(_request(), _caller()))
    unavailable = _async(unavailable_service.attest_configuration(_request(), _caller()))

    assert isinstance(mismatch, IndependentVerificationAttestationV1)
    assert mismatch.signing_request.configuration is not None
    assert mismatch.signing_request.configuration.status is ConfigurationAttestationStatus.MISMATCH
    assert mismatch.signing_request.configuration.reason is (
        ConfigurationAttestationReason.CONCURRENCY_MISMATCH
    )
    assert isinstance(unavailable, IndependentVerificationAttestationV1)
    assert unavailable.signing_request.configuration is not None
    assert unavailable.signing_request.configuration.status is (
        ConfigurationAttestationStatus.UNAVAILABLE
    )
    assert unavailable.signing_request.configuration.observation is None


@pytest.mark.parametrize(
    ("service_changes", "reason"),
    [
        ({"reconciling": True}, ConfigurationAttestationReason.RECONCILING),
        (
            {"ready_state": CloudRunReadyState.NOT_READY},
            ConfigurationAttestationReason.NOT_READY,
        ),
        (
            {"observed_generation": 6},
            ConfigurationAttestationReason.GENERATION_MISMATCH,
        ),
        (
            {"template_revision": STABLE},
            ConfigurationAttestationReason.REVISION_MAPPING_MISMATCH,
        ),
    ],
)
def test_configuration_attestation_emits_stable_provider_state_reasons(
    service_changes: dict[str, object],
    reason: ConfigurationAttestationReason,
) -> None:
    state = _state()
    state = replace(
        state,
        service=replace(state.service, **service_changes),
    )
    service, _, _, _ = _service_with(state)

    result = _async(service.attest_configuration(_request(), _caller()))

    assert isinstance(result, IndependentVerificationAttestationV1)
    configuration = result.signing_request.configuration
    assert configuration is not None
    assert configuration.status is ConfigurationAttestationStatus.MISMATCH
    assert configuration.reason is reason


def test_recovery_configuration_accepts_provider_omitted_zero_candidate() -> None:
    request = _request(
        action=CapabilityAction.RECOVER_STABLE,
        stable_percent=100,
        candidate_percent=0,
    )
    state = _state(100, 0)
    stable_traffic = (
        CloudRunTrafficAllocation(revision=STABLE, percent=100, tag=None),
    )
    stable_status = (
        CloudRunTrafficStatus(
            revision=STABLE,
            percent=100,
            tag=None,
            uri=None,
        ),
    )
    state = replace(
        state,
        service=replace(
            state.service,
            traffic=stable_traffic,
            traffic_statuses=stable_status,
        ),
    )
    service, _, _, _ = _service_with(state)

    result = _async(service.attest_configuration(request, _caller()))

    assert isinstance(result, IndependentVerificationAttestationV1)
    configuration = result.signing_request.configuration
    assert configuration is not None
    assert configuration.status is ConfigurationAttestationStatus.MATCH
    assert configuration.reason is ConfigurationAttestationReason.MATCH


def test_configuration_attestation_binds_both_immutable_revision_configs() -> None:
    state = _state()
    drifted_configuration = replace(
        CANDIDATE_CONFIGURATION,
        image=CANDIDATE_CONFIGURATION.image.replace("2" * 64, "3" * 64),
    )
    state = replace(
        state,
        candidate_revision=_revision(
            CANDIDATE,
            configuration=drifted_configuration,
        ),
    )
    service, _, _, _ = _service_with(state)

    result = _async(service.attest_configuration(_request(), _caller()))

    assert isinstance(result, IndependentVerificationAttestationV1)
    configuration = result.signing_request.configuration
    assert configuration is not None
    assert configuration.status is ConfigurationAttestationStatus.MISMATCH
    assert configuration.reason is ConfigurationAttestationReason.DIGEST_MISMATCH


def test_probe_uses_fixed_bounds_nonce_correlations_and_marker_counts() -> None:
    service, _, transport, evidence = _service_with(_state())

    result = _async(service.attest_probe(_request(), _caller()))

    assert isinstance(result, IndependentVerificationAttestationV1)
    probe = result.signing_request.probe
    assert probe is not None
    assert probe.status is ProbeAttestationStatus.MATCH
    assert probe.reason is ProbeAttestationReason.MATCH
    assert probe.observation.stable_count == 18
    assert probe.observation.candidate_count == 2
    assert len(transport.calls) == 20
    assert {call[0] for call in transport.calls} == {"n" * 32}
    assert [call[1] for call in transport.calls] == [
        f"probe-001:{index}" for index in range(1, 21)
    ]
    assert all(call[2:] == (2_000, 1_024) for call in transport.calls)
    assert len(evidence.calls) == 1


@pytest.mark.parametrize(
    ("outcomes", "reason"),
    [
        (["stable"] * 19 + ["unavailable"], ProbeAttestationReason.TRANSPORT_UNAVAILABLE),
        (["stable"] * 19 + ["invalid"], ProbeAttestationReason.RESPONSE_INVALID),
        (["stable"] * 20, ProbeAttestationReason.DISTRIBUTION_MISMATCH),
    ],
)
def test_probe_uncertainty_is_always_inconclusive(
    outcomes: list[str],
    reason: ProbeAttestationReason,
) -> None:
    service, _, _, _ = _service_with(_state(), outcomes)

    result = _async(service.attest_probe(_request(), _caller()))

    assert isinstance(result, IndependentVerificationAttestationV1)
    assert result.signing_request.probe is not None
    assert result.signing_request.probe.status is ProbeAttestationStatus.INCONCLUSIVE
    assert result.signing_request.probe.reason is reason


@pytest.mark.parametrize(
    ("action", "stable_percent", "candidate_percent", "kind", "complete_reason"),
    [
        (
            CapabilityAction.PROMOTE_CANDIDATE,
            0,
            100,
            CompletionKind.PROMOTION,
            CompletionReason.PROMOTION_COMPLETE,
        ),
        (
            CapabilityAction.RECOVER_STABLE,
            100,
            0,
            CompletionKind.RECOVERY,
            CompletionReason.RECOVERY_COMPLETE,
        ),
    ],
)
def test_classifier_requires_matching_configuration_probe_and_verified_receipt(
    action: CapabilityAction,
    stable_percent: int,
    candidate_percent: int,
    kind: CompletionKind,
    complete_reason: CompletionReason,
) -> None:
    request = _request(
        action=action,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
    )
    state = _state(stable_percent, candidate_percent)
    outcomes = (
        ["candidate"] * 20
        if action is CapabilityAction.PROMOTE_CANDIDATE
        else ["stable"] * 20
    )
    service, _, _, _ = _service_with(state, outcomes)
    configuration = _async(service.attest_configuration(request, _caller()))
    probe = _async(service.attest_probe(request, _caller()))
    assert isinstance(configuration, IndependentVerificationAttestationV1)
    assert isinstance(probe, IndependentVerificationAttestationV1)
    bundle = _bundle(request, configuration, probe)
    assert bundle.request.kind is kind

    result = classify_completion(bundle)

    assert result.status is CompletionStatus.COMPLETE
    assert result.reason is complete_reason
    assert result.follow_up_required is False


def test_classifier_golden_configuration_data_disagreement_is_ambiguous() -> None:
    request = _request(
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_percent=0,
        candidate_percent=100,
    )
    service, _, _, _ = _service_with(_state(0, 100), ["stable"] * 20)
    configuration = _async(service.attest_configuration(request, _caller()))
    probe = _async(service.attest_probe(request, _caller()))
    assert isinstance(configuration, IndependentVerificationAttestationV1)
    assert isinstance(probe, IndependentVerificationAttestationV1)

    result = classify_completion(_bundle(request, configuration, probe))

    assert result.status is CompletionStatus.AMBIGUOUS
    assert result.reason is CompletionReason.CONFIGURATION_DATA_DISAGREEMENT
    assert result.follow_up_required is True


def test_classifier_golden_uncertain_write_is_ambiguous_even_with_matching_proofs() -> None:
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
    bundle = _bundle(request, configuration, probe)
    assert bundle.execution is not None
    ambiguous_execution = bundle.execution.model_copy(
        update={
            "outcome": ReceiptOutcome.AMBIGUOUS,
            "reason_code": ReasonCode.PROVIDER_OUTCOME_AMBIGUOUS,
            "write_outcome_known": False,
        }
    )
    bundle = bundle.model_copy(update={"execution": ambiguous_execution})

    result = classify_completion(bundle)

    assert result.status is CompletionStatus.AMBIGUOUS
    assert result.reason is CompletionReason.UNCERTAIN_WRITE


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("configuration", CompletionReason.CONFIGURATION_PROOF_ABSENT),
        ("probe", CompletionReason.PROBE_PROOF_ABSENT),
        ("execution", CompletionReason.EXECUTION_PROOF_ABSENT),
    ],
)
def test_classifier_absent_required_evidence_is_ambiguous(
    field: str,
    reason: CompletionReason,
) -> None:
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
    bundle = _bundle(request, configuration, probe).model_copy(update={field: None})

    result = classify_completion(bundle)

    assert result.status is CompletionStatus.AMBIGUOUS
    assert result.reason is reason


@pytest.mark.parametrize(
    ("configuration_state", "expected_reason"),
    [
        (OSError("synthetic read unavailable"), CompletionReason.CONFIGURATION_UNAVAILABLE),
        ("mismatch", CompletionReason.CONFIGURATION_MISMATCH),
    ],
)
def test_classifier_configuration_failures_are_ambiguous(
    configuration_state: object,
    expected_reason: CompletionReason,
) -> None:
    request = _request(
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_percent=0,
        candidate_percent=100,
    )
    state = (
        replace(_state(0, 100), service=replace(_state(0, 100).service, template_concurrency=9))
        if configuration_state == "mismatch"
        else configuration_state
    )
    configuration_service, _, _, _ = _service_with(state, ["candidate"] * 20)
    probe_service, _, _, _ = _service_with(_state(0, 100), ["candidate"] * 20)
    configuration = _async(
        configuration_service.attest_configuration(request, _caller())
    )
    probe = _async(probe_service.attest_probe(request, _caller()))
    assert isinstance(configuration, IndependentVerificationAttestationV1)
    assert isinstance(probe, IndependentVerificationAttestationV1)

    result = classify_completion(_bundle(request, configuration, probe))

    assert result.status is CompletionStatus.AMBIGUOUS
    assert result.reason is expected_reason


def test_classifier_transport_inconclusive_stale_and_binding_mismatch_fail_closed() -> None:
    request = _request(
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_percent=0,
        candidate_percent=100,
    )
    service, _, _, _ = _service_with(
        _state(0, 100),
        ["candidate"] * 19 + ["unavailable"],
    )
    configuration = _async(service.attest_configuration(request, _caller()))
    probe = _async(service.attest_probe(request, _caller()))
    assert isinstance(configuration, IndependentVerificationAttestationV1)
    assert isinstance(probe, IndependentVerificationAttestationV1)
    bundle = _bundle(request, configuration, probe)
    assert classify_completion(bundle).reason is CompletionReason.PROBE_INCONCLUSIVE

    matching_service, _, _, _ = _service_with(_state(0, 100), ["candidate"] * 20)
    matching_probe = _async(matching_service.attest_probe(request, _caller()))
    assert isinstance(matching_probe, IndependentVerificationAttestationV1)
    matching_bundle = _bundle(request, configuration, matching_probe)
    stale_request = CompletionAssessmentRequestV1(
        schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
        kind=CompletionKind.PROMOTION,
        verification=request,
        assessed_at="2026-08-19T12:07:00Z",
    )
    stale_bundle = matching_bundle.model_copy(update={"request": stale_request})
    assert classify_completion(stale_bundle).reason is CompletionReason.EVIDENCE_STALE

    wrong_request = _request()
    wrong_service, _, _, _ = _service_with(_state())
    wrong_configuration = _async(
        wrong_service.attest_configuration(wrong_request, _caller())
    )
    assert isinstance(wrong_configuration, IndependentVerificationAttestationV1)
    substituted = matching_bundle.model_copy(
        update={"configuration": _verified(wrong_configuration)}
    )
    assert classify_completion(substituted).reason is (
        CompletionReason.EVIDENCE_BINDING_MISMATCH
    )


def test_classifier_executor_success_without_target_evidence_never_completes() -> None:
    request = _request(
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_percent=0,
        candidate_percent=100,
    )
    assessment = CompletionAssessmentRequestV1(
        schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
        kind=CompletionKind.PROMOTION,
        verification=request,
        assessed_at="2026-08-19T12:02:00Z",
    )
    receipt_only = CompletionEvidenceBundleV1(
        schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
        request=assessment,
        execution=_execution(request),
    )

    result = classify_completion(receipt_only)

    assert result.status is CompletionStatus.AMBIGUOUS
    assert result.reason is CompletionReason.CONFIGURATION_PROOF_ABSENT


def test_revocation_and_stale_denial_require_authority_evidence() -> None:
    request = _request()
    revocation_request = CompletionAssessmentRequestV1(
        schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
        kind=CompletionKind.REVOCATION,
        verification=request,
        assessed_at="2026-08-19T12:02:00Z",
    )
    stale_request = revocation_request.model_copy(
        update={"kind": CompletionKind.STALE_CAPABILITY_DENIAL}
    )
    stale_execution = ExecutionCompletionEvidenceV1(
        schema_version=EXECUTION_COMPLETION_EVIDENCE_V1,
        root_id=request.root_id,
        root_sha256=request.root_sha256,
        epoch=request.epoch,
        target=request.target,
        plan_sha256=request.plan_sha256,
        service_claim_sha256=request.service_claim_sha256,
        probe_policy_sha256=request.probe_policy_sha256,
        signed_intent_sha256=request.signed_intent_sha256,
        intent_signature_verified=True,
        request_id=request.request_id,
        correlation_id=request.correlation_id,
        observation_window_started_at=request.observation_window_started_at,
        observation_window_ends_at=request.observation_window_ends_at,
        action=request.action,
        outcome=ReceiptOutcome.DENIED,
        reason_code=ReasonCode.EPOCH_MISMATCH,
        observed_authority_epoch=request.epoch + 1,
        receipt_sha256="d" * 64,
        receipt_persisted=True,
        write_outcome_known=True,
    )
    revocation = CompletionEvidenceBundleV1(
        schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
        request=revocation_request,
        authority=_authority(request, AuthorityCompletionKind.REVOCATION),
    )
    stale = CompletionEvidenceBundleV1(
        schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
        request=stale_request,
        authority=_authority(
            request,
            AuthorityCompletionKind.EPOCH_ADVANCEMENT,
        ).model_copy(update={"epoch": request.epoch + 1}),
        execution=stale_execution,
    )

    assert classify_completion(revocation).reason is CompletionReason.REVOCATION_COMPLETE
    assert classify_completion(stale).reason is (
        CompletionReason.STALE_CAPABILITY_DENIAL_COMPLETE
    )
    conflicting_epoch = stale.model_copy(
        update={
            "execution": stale_execution.model_copy(
                update={"observed_authority_epoch": request.epoch + 2}
            )
        }
    )
    assert classify_completion(conflicting_epoch).reason is (
        CompletionReason.EVIDENCE_BINDING_MISMATCH
    )
    missing = revocation.model_copy(update={"authority": None})
    assert classify_completion(missing).reason is (
        CompletionReason.AUTHORITY_PROOF_ABSENT
    )

    substituted = revocation.model_copy(
        update={
            "authority": _authority(
                request,
                AuthorityCompletionKind.EPOCH_ADVANCEMENT,
            )
        }
    )
    assert classify_completion(substituted).reason is (
        CompletionReason.EVIDENCE_BINDING_MISMATCH
    )

    stale_assessment = revocation_request.model_copy(
        update={"assessed_at": "2026-08-19T12:07:00Z"}
    )
    stale_revocation = revocation.model_copy(update={"request": stale_assessment})
    assert classify_completion(stale_revocation).reason is CompletionReason.EVIDENCE_STALE


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signed_intent_sha256", "8" * 64),
        ("request_id", "substituted-request"),
        ("correlation_id", "substituted-correlation"),
        ("observation_window_started_at", "2026-08-19T11:58:59Z"),
        ("observation_window_ends_at", "2026-08-19T12:00:59Z"),
    ],
)
def test_classifier_rejects_unbound_execution_evidence(
    field: str,
    value: object,
) -> None:
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
    bundle = _bundle(request, configuration, probe)
    assert bundle.execution is not None
    substituted = bundle.model_copy(
        update={"execution": bundle.execution.model_copy(update={field: value})}
    )

    assert classify_completion(substituted).reason is (
        CompletionReason.EVIDENCE_BINDING_MISMATCH
    )


def test_contract_rejects_unsigned_or_substituted_evidence() -> None:
    service, _, _, _ = _service_with(_state())
    result = _async(service.attest_configuration(_request(), _caller()))
    assert isinstance(result, IndependentVerificationAttestationV1)
    substituted = result.signed_evidence.model_copy(
        update={
            "evidence": result.signed_evidence.evidence.model_copy(
                update={"epoch": 3}
            )
        }
    )

    with pytest.raises(ValidationError):
        VerifiedIndependentVerificationEvidenceV1(
            schema_version=VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
            signing_request=result.signing_request,
            signed_evidence=substituted,
            verified_at="2026-08-19T12:01:30Z",
        )


def test_reference_target_echoes_only_valid_harmless_probe_seals() -> None:
    client = TestClient(create_reference_app(ReferenceVariant.STABLE, revision=STABLE))
    response = client.get(
        "/v1/probe",
        params={"nonce": "n" * 32, "correlation_id": "probe-001:1"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "correlation_id": "probe-001:1",
        "marker": STABLE_MARKER,
        "nonce": "n" * 32,
        "revision": STABLE,
        "schema_version": SEALED_REFERENCE_PROBE_V1,
    }
    assert client.get("/v1/probe", params={"nonce": "n" * 32}).status_code == 400


class _PolicyAuthenticator:
    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        assert authorization_header == "Bearer synthetic.verification.token"
        return AuthenticationContext(
            role=policy.caller.role,
            email=policy.caller.email,
            subject=policy.caller.subject,
            issuer="https://accounts.google.com",
            audience=policy.audience,
            issued_at=1_776_236_400,
            expires_at=1_776_237_000,
        )


class _AsyncEvidenceSigner:
    def __init__(self) -> None:
        self.profile = SigningProfile.evidence(PROJECT, EVIDENCE_KEY_VERSION)
        self.digests: list[bytes] = []

    async def sign_digest(self, digest: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import utils

        self.digests.append(digest)
        return utils.encode_dss_signature(1, 1)


class _InternalTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        return self.response


class _SignatureVerifier:
    project_id = PROJECT
    key_version = EVIDENCE_KEY_VERSION

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[SignedIndependentVerificationEvidenceV1] = []

    async def verify(self, signed: SignedIndependentVerificationEvidenceV1) -> None:
        self.calls.append(signed)
        if self.error is not None:
            raise self.error


class _TimelineRecorder:
    def __init__(
        self,
        error: Exception | None = None,
        *,
        target: TargetBinding | None = None,
    ) -> None:
        self.error = error
        self.target = target or _target()
        self.verifications: list[VerifiedIndependentVerificationEvidenceV1] = []
        self.classifications: list[CompletionClassificationV1] = []

    async def record_independent_verification(
        self,
        verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None:
        if self.error is not None:
            raise self.error
        self.verifications.append(verified)

    async def record_completion_classification(
        self,
        classification: CompletionClassificationV1,
    ) -> None:
        if self.error is not None:
            raise self.error
        self.classifications.append(classification)


def _writer_policy(*, verification_route: bool) -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EVIDENCE_WRITER,
        path=(
            INDEPENDENT_VERIFICATION_EVIDENCE_PATH
            if verification_route
            else protected_path(ServiceRole.EVIDENCE_WRITER)
        ),
        audience=(
            f"https://controlgraph-evidence-writer-{PROJECT_NUMBER}"
            ".us-central1.run.app"
        ),
        caller=CallerBinding(
            role=(
                CallerRole.VERIFIER
                if verification_route
                else CallerRole.COORDINATOR
            ),
            email=(
                VERIFIER_IDENTITY
                if verification_route
                else f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com"
            ),
            subject="345678901234567890123",
        ),
    )


def test_verifier_http_dispatches_closed_configuration_invocation() -> None:
    service, _, _, _ = _service_with(_state())
    invocation = IndependentVerificationInvocationV1(
        schema_version=INDEPENDENT_VERIFICATION_INVOCATION_V1,
        kind=IndependentVerificationKind.CONFIGURATION,
        verification=_request(),
    )
    app = create_service_app(
        ServiceRole.VERIFIER,
        authenticator=_PolicyAuthenticator(),
        authentication_policy=_policy(),
        independent_verification_service=service,
    )

    response = TestClient(app).post(
        protected_path(ServiceRole.VERIFIER),
        headers={"Authorization": "Bearer synthetic.verification.token"},
        content=canonical_json_bytes(invocation),
    )

    assert response.status_code == 200
    decoded = IndependentVerificationAttestationV1.model_validate_json(response.content)
    assert decoded.signing_request.configuration is not None
    assert decoded.signing_request.configuration.status is (
        ConfigurationAttestationStatus.MATCH
    )


def test_evidence_writer_http_route_is_verifier_only_and_purpose_separated() -> None:
    service, _, _, _ = _service_with(_state())
    attestation = _async(service.attest_configuration(_request(), _caller()))
    assert isinstance(attestation, IndependentVerificationAttestationV1)
    signer = _AsyncEvidenceSigner()
    verification_policy = _writer_policy(verification_route=True)
    signing_service = IndependentVerificationSigningService(
        project_id=PROJECT,
        authentication_policy=verification_policy,
        signer=signer,
    )
    app = create_service_app(
        ServiceRole.EVIDENCE_WRITER,
        authenticator=_PolicyAuthenticator(),
        authentication_policy=_writer_policy(verification_route=False),
        independent_verification_signing_service=signing_service,
        independent_verification_evidence_authentication_policy=verification_policy,
    )

    response = TestClient(app).post(
        INDEPENDENT_VERIFICATION_EVIDENCE_PATH,
        headers={"Authorization": "Bearer synthetic.verification.token"},
        content=canonical_json_bytes(attestation.signing_request),
    )

    assert response.status_code == 200
    signed = SignedIndependentVerificationEvidenceV1.model_validate_json(
        response.content
    )
    assert signed.evidence == attestation.signing_request.evidence
    assert signed.purpose == INDEPENDENT_VERIFICATION_PURPOSE
    assert signer.digests == [bytes.fromhex(signed.signing_input_sha256)]


def test_coordinator_exposes_only_signature_verified_verifier_evidence() -> None:
    service, _, _, _ = _service_with(_state())
    attestation = _async(service.attest_configuration(_request(), _caller()))
    assert isinstance(attestation, IndependentVerificationAttestationV1)
    invocation = IndependentVerificationInvocationV1(
        schema_version=INDEPENDENT_VERIFICATION_INVOCATION_V1,
        kind=IndependentVerificationKind.CONFIGURATION,
        verification=_request(),
    )
    transport = _InternalTransport(canonical_json_bytes(attestation))
    verifier = _SignatureVerifier()
    client = CoordinatorIndependentVerificationClient(
        route=CoordinatorInternalRoute(
            project_id=PROJECT,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.COORDINATOR,
            service_role=ServiceRole.VERIFIER,
            audience=VERIFIER_AUDIENCE,
        ),
        transport=transport,
        signature_verifier=verifier,
        clock=lambda: NOW.replace(minute=1, second=30),
    )

    verified = _async(client.attest(invocation))

    assert isinstance(verified, VerifiedIndependentVerificationEvidenceV1)
    assert verified.signing_request == attestation.signing_request
    assert verifier.calls == [attestation.signed_evidence]
    assert len(transport.calls) == 1


def test_coordinator_records_only_verified_evidence_and_exact_replay_is_stable() -> None:
    service, _, _, _ = _service_with(_state())
    attestation = _async(service.attest_configuration(_request(), _caller()))
    assert isinstance(attestation, IndependentVerificationAttestationV1)
    invocation = IndependentVerificationInvocationV1(
        schema_version=INDEPENDENT_VERIFICATION_INVOCATION_V1,
        kind=IndependentVerificationKind.CONFIGURATION,
        verification=_request(),
    )
    recorder = _TimelineRecorder()
    verifier = _SignatureVerifier()
    client = CoordinatorIndependentVerificationClient(
        route=CoordinatorInternalRoute(
            project_id=PROJECT,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.COORDINATOR,
            service_role=ServiceRole.VERIFIER,
            audience=VERIFIER_AUDIENCE,
        ),
        transport=_InternalTransport(canonical_json_bytes(attestation)),
        signature_verifier=verifier,
        clock=lambda: NOW.replace(minute=1, second=30),
        timeline_recorder=recorder,
    )

    first = _async(client.attest(invocation))
    second = _async(client.attest(invocation))

    assert first == second
    assert recorder.verifications == [first, first]
    assert verifier.calls == [attestation.signed_evidence, attestation.signed_evidence]


def test_coordinator_never_records_unverified_or_unpersistable_evidence() -> None:
    service, _, _, _ = _service_with(_state())
    attestation = _async(service.attest_configuration(_request(), _caller()))
    assert isinstance(attestation, IndependentVerificationAttestationV1)
    invocation = IndependentVerificationInvocationV1(
        schema_version=INDEPENDENT_VERIFICATION_INVOCATION_V1,
        kind=IndependentVerificationKind.CONFIGURATION,
        verification=_request(),
    )
    route = CoordinatorInternalRoute(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.COORDINATOR,
        service_role=ServiceRole.VERIFIER,
        audience=VERIFIER_AUDIENCE,
    )
    recorder = _TimelineRecorder()
    invalid_client = CoordinatorIndependentVerificationClient(
        route=route,
        transport=_InternalTransport(canonical_json_bytes(attestation)),
        signature_verifier=_SignatureVerifier(ValueError("synthetic signature failure")),
        timeline_recorder=recorder,
    )

    with pytest.raises(IndependentVerificationError) as invalid:
        _async(invalid_client.attest(invocation))

    assert invalid.value.code is IndependentVerificationErrorCode.RESPONSE_INVALID
    assert recorder.verifications == []

    unavailable_client = CoordinatorIndependentVerificationClient(
        route=route,
        transport=_InternalTransport(canonical_json_bytes(attestation)),
        signature_verifier=_SignatureVerifier(),
        timeline_recorder=_TimelineRecorder(RuntimeError("synthetic store failure")),
    )
    with pytest.raises(IndependentVerificationError) as unavailable:
        _async(unavailable_client.attest(invocation))
    assert unavailable.value.code is IndependentVerificationErrorCode.UNAVAILABLE


def test_coordinator_rejects_timeline_target_substitution_before_transport() -> None:
    other_target = TargetBinding.model_validate(
        {**_request().target.model_dump(mode="python"), "environment": "acceptance"}
    )
    recorder = _TimelineRecorder(target=other_target)
    transport = _InternalTransport(b"unused")
    verifier = _SignatureVerifier()
    client = CoordinatorIndependentVerificationClient(
        route=CoordinatorInternalRoute(
            project_id=PROJECT,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.COORDINATOR,
            service_role=ServiceRole.VERIFIER,
            audience=VERIFIER_AUDIENCE,
        ),
        transport=transport,
        signature_verifier=verifier,
        timeline_recorder=recorder,
    )
    invocation = IndependentVerificationInvocationV1(
        schema_version=INDEPENDENT_VERIFICATION_INVOCATION_V1,
        kind=IndependentVerificationKind.CONFIGURATION,
        verification=_request(),
    )

    with pytest.raises(IndependentVerificationError) as denied:
        _async(client.attest(invocation))

    assert denied.value.code is IndependentVerificationErrorCode.REQUEST_DENIED
    assert transport.calls == []
    assert verifier.calls == []
    assert recorder.verifications == []


def test_coordinator_completion_service_records_the_pure_result_before_return() -> None:
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
    bundle = _bundle(request, configuration, probe)
    recorder = _TimelineRecorder()
    classifier = CoordinatorCompletionClassificationService(
        target=request.target,
        timeline_recorder=recorder,
    )

    first = _async(classifier.classify(bundle))
    second = _async(classifier.classify(bundle))

    assert isinstance(first, CompletionClassificationV1)
    assert first == classify_completion(bundle)
    assert second == first
    assert recorder.classifications == [first, first]


def test_coordinator_completion_service_rejects_another_target_before_recording() -> None:
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
    bundle = _bundle(request, configuration, probe)
    other_target = TargetBinding.model_validate(
        {**request.target.model_dump(mode="python"), "environment": "acceptance"}
    )
    recorder = _TimelineRecorder(target=other_target)
    classifier = CoordinatorCompletionClassificationService(
        target=other_target,
        timeline_recorder=recorder,
    )

    with pytest.raises(ValueError, match="outside the configured target"):
        _async(classifier.classify(bundle))

    assert recorder.classifications == []


def test_completion_contract_rejects_complete_reason_for_another_kind() -> None:
    request = CompletionAssessmentRequestV1(
        schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
        kind=CompletionKind.PROMOTION,
        verification=_request(
            action=CapabilityAction.PROMOTE_CANDIDATE,
            stable_percent=0,
            candidate_percent=100,
        ),
        assessed_at="2026-08-19T12:02:00Z",
    )

    with pytest.raises(ValidationError, match="classification shape"):
        CompletionClassificationV1(
            schema_version="controlgraph.completion-classification/v1",
            request=request,
            bundle_sha256="f" * 64,
            status=CompletionStatus.COMPLETE,
            reason=CompletionReason.RECOVERY_COMPLETE,
            follow_up_required=False,
            follow_up_after_seconds=None,
            follow_up_attempt_limit=None,
            classified_at=request.assessed_at,
        )


def test_cli_classifies_canonical_bundle_without_cloud_access(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
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
    bundle_path = tmp_path / "completion-bundle.json"
    bundle_path.write_bytes(canonical_json_bytes(_bundle(request, configuration, probe)))

    result = main(["classify-completion", "--bundle-file", str(bundle_path)])

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == CompletionStatus.COMPLETE.value
    assert output["reason"] == CompletionReason.PROMOTION_COMPLETE.value
