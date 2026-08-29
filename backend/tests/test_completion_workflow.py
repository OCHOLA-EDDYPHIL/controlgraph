from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from health_execution_test_data import make_verified_apply_receipt
from revocation_proof_test_data import make_revocation_proof_records
from root_v2_test_data import make_root_v3_records

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.application.completion_classification import (
    CoordinatorCompletionClassificationService,
)
from controlgraph_canary.application.completion_workflow import (
    CoordinatorCompletionWorkflow,
    create_verification_request,
)
from controlgraph_canary.application.independent_verification import (
    _configuration_signing_request,
    _probe_signing_request,
)
from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.independent_verification import (
    CONFIGURATION_ATTESTATION_V1,
    CONFIGURATION_OBSERVATION_FACTS_V1,
    CONFIGURATION_OBSERVATION_V1,
    INDEPENDENT_VERIFICATION_PURPOSE,
    PROBE_ATTESTATION_V1,
    PROBE_OBSERVATION_V1,
    PROBE_REQUEST_V1,
    PROBE_SAMPLE_OBSERVATION_V1,
    SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
    VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
    CompletionClassificationV1,
    CompletionReason,
    CompletionStatus,
    ConfigurationAttestationReason,
    ConfigurationAttestationStatus,
    ConfigurationAttestationV1,
    ConfigurationObservationFactsV1,
    ConfigurationObservationV1,
    ConfigurationReadyState,
    IndependentVerificationInvocationV1,
    IndependentVerificationKind,
    IndependentVerificationSigningRequestV1,
    ProbeAttestationReason,
    ProbeAttestationStatus,
    ProbeAttestationV1,
    ProbeObservationV1,
    ProbeRequestV1,
    ProbeSampleObservationV1,
    ProbeSampleOutcome,
    SignedIndependentVerificationEvidenceV1,
    VerificationRequestV1,
    VerifiedIndependentVerificationEvidenceV1,
    fixed_probe_policy,
    independent_verification_signing_input_sha256,
    probe_observation_sha256,
)
from controlgraph_canary.contracts.models import (
    CAPABILITY_CLAIMS_V1,
    EPOCH_AUTHORITY_V1,
    EVIDENCE_EVENT_V1,
    SIGNED_CAPABILITY_V1,
    CapabilityAction,
    CapabilityClaims,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    SignedCapability,
    TrafficAllocation,
)
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    RolloutRootV3,
    SignedEvidenceEventV1,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    execution_receipt_logical_id,
)

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


class _Verifier:
    def __init__(
        self,
        *,
        unavailable: bool = False,
        observed_at: str | None = None,
    ) -> None:
        self.unavailable = unavailable
        self.observed_at = observed_at
        self.calls: list[IndependentVerificationInvocationV1] = []

    async def attest(
        self,
        invocation: IndependentVerificationInvocationV1,
    ) -> VerifiedIndependentVerificationEvidenceV1:
        self.calls.append(invocation)
        if self.unavailable:
            raise TimeoutError("synthetic verifier timeout")
        if invocation.kind is IndependentVerificationKind.CONFIGURATION:
            return _configuration_evidence(
                invocation.verification,
                observed_at=self.observed_at,
            )
        return _probe_evidence(
            invocation.verification,
            observed_at=self.observed_at,
        )


class _Timeline:
    def __init__(self, target) -> None:  # type: ignore[no-untyped-def]
        self._target = target
        self.verification_groups: list[
            tuple[VerifiedIndependentVerificationEvidenceV1, ...]
        ] = []
        self.completion_groups: list[
            tuple[
                CompletionClassificationV1,
                tuple[VerifiedIndependentVerificationEvidenceV1, ...],
            ]
        ] = []
        self.stale_denial_groups: list[
            tuple[
                ExecutionReceipt,
                SignedEvidenceEventV1 | None,
                CompletionClassificationV1,
                tuple[VerifiedIndependentVerificationEvidenceV1, ...],
            ]
        ] = []

    @property
    def target(self):  # type: ignore[no-untyped-def]
        return self._target

    async def record_verification_bundle(
        self,
        *verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None:
        self.verification_groups.append(verified)

    async def record_completion_bundle(
        self,
        classification: CompletionClassificationV1,
        *verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None:
        self.completion_groups.append((classification, verified))

    async def record_stale_denial_completion(
        self,
        receipt: ExecutionReceipt,
        signed_authority: SignedEvidenceEventV1 | None,
        classification: CompletionClassificationV1,
        *verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None:
        self.stale_denial_groups.append(
            (receipt, signed_authority, classification, verified)
        )


class _AuthorityReader:
    def __init__(
        self,
        bundle: RootCreationBundle,
        signed_evidence: SignedEvidenceEventV1 | None,
        *,
        epoch_evidence: dict[int, SignedEvidenceEventV1] | None = None,
    ) -> None:
        self._target = bundle.root.value.content.target
        self.bundle = bundle
        self.signed_evidence = signed_evidence
        self.epoch_evidence = epoch_evidence or {}

    @property
    def target(self):  # type: ignore[no-untyped-def]
        return self._target

    async def read_root_creation_bundle(self, root_id: str) -> RootCreationBundle | None:
        return self.bundle if root_id == self.bundle.root.value.root_id else None

    async def read_signed_evidence_event(
        self,
        evidence_id: str,
    ) -> StoredRecord[SignedEvidenceEventV1] | None:
        if (
            self.signed_evidence is None
            or evidence_id != self.signed_evidence.event.evidence_id
        ):
            return None
        return StoredRecord(self.signed_evidence, 0)

    async def read_signed_epoch_evidence(
        self,
        root_id: str,
        epoch: int,
    ) -> StoredRecord[SignedEvidenceEventV1] | None:
        signed = self.epoch_evidence.get(epoch)
        if signed is None or signed.event.root_id != root_id:
            return None
        return StoredRecord(signed, 0)


class _AuthorityEvidenceVerifier:
    def __init__(self) -> None:
        self.calls: list[SignedEvidenceEventV1] = []

    async def verify(self, signed: SignedEvidenceEventV1) -> None:
        self.calls.append(signed)


class _IntentReader:
    def __init__(self, signed: SignedCapability | None, target) -> None:  # type: ignore[no-untyped-def]
        self.signed = signed
        self._target = target
        self.calls: list[str] = []

    @property
    def target(self):  # type: ignore[no-untyped-def]
        return self._target

    async def read_signed_intent(
        self,
        capability_sha256: str,
    ) -> SignedCapability | None:
        self.calls.append(capability_sha256)
        if self.signed is None or canonical_sha256(self.signed) != capability_sha256:
            return None
        return self.signed


class _IntentVerifier:
    def __init__(self, *, rejected: bool = False) -> None:
        self.rejected = rejected
        self.calls: list[SignedCapability] = []

    def verify(self, signed: SignedCapability) -> None:
        self.calls.append(signed)
        if self.rejected:
            raise ValueError("synthetic invalid signature")


def _receipt(
    action: CapabilityAction,
    *,
    day: str = "2026-08-22",
) -> tuple[RolloutRootV3, ServiceClaimRecord, ExecutionReceipt, SignedCapability]:
    records = make_root_v3_records()
    source = make_verified_apply_receipt(records.root)
    expected = {
        CapabilityAction.APPLY_CANARY: source.expected_poststate_sha256,
        CapabilityAction.PROMOTE_CANDIDATE: (
            records.service_claim.candidate_target_configuration_sha256
        ),
        CapabilityAction.RECOVER_STABLE: (
            records.service_claim.stable_target_configuration_sha256
        ),
    }[action]
    idempotency_key = f"verify-{action.value.lower()}-001"
    receipt = ExecutionReceipt.model_validate(
        {
            **source.model_dump(mode="python"),
            "receipt_id": execution_receipt_logical_id(
                source.target,
                idempotency_key,
            ),
            "request_id": f"request-{action.value.lower()}-001",
            "idempotency_key": idempotency_key,
            "plan_sha256": canonical_sha256(records.root.content.rollout_plan),
            "expected_poststate_sha256": expected,
            "action": action,
            "outcome": ReceiptOutcome.VERIFIED,
            "reason_code": None,
            "dispatch_not_after": f"{day}T12:09:00Z",
            "created_at": f"{day}T12:00:00Z",
            "updated_at": f"{day}T12:00:00Z",
        }
    )
    grant = {
        CapabilityAction.APPLY_CANARY: records.root.content.authority_bounds.apply_canary,
        CapabilityAction.PROMOTE_CANDIDATE: (
            records.root.content.authority_bounds.promote_candidate
        ),
        CapabilityAction.RECOVER_STABLE: (
            records.root.content.authority_bounds.recover_stable
        ),
    }[action]
    claims = CapabilityClaims(
        schema_version=CAPABILITY_CLAIMS_V1,
        capability_id=f"cgcap-{'c' * 64}",
        issuer=records.root.content.authority_bounds.issuer_identity,
        subject=grant.subject_identity,
        audience=grant.audience,
        target=receipt.target,
        root_id=receipt.root_id,
        root_sha256=receipt.root_sha256,
        epoch=receipt.epoch,
        action=receipt.action,
        stable_revision=records.root.content.rollout_plan.stable_revision,
        candidate_revision=records.root.content.rollout_plan.candidate_revision,
        stable_percent=grant.stable_percent,
        candidate_percent=grant.candidate_percent,
        concurrency=(
            records.root.content.authority_bounds.concurrency
            if action is CapabilityAction.RECOVER_STABLE
            else None
        ),
        plan_sha256=receipt.plan_sha256,
        provider_etag=receipt.provider_etag,
        request_id=receipt.request_id,
        idempotency_key=receipt.idempotency_key,
        parent_capability_sha256=None,
        issued_at=f"{day}T12:00:00Z",
        not_before=f"{day}T12:00:00Z",
        expires_at=f"{day}T12:10:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=(
            records.root.content.authority_bounds.capability_signing_key_version
        ),
    )
    signed = SignedCapability(
        schema_version=SIGNED_CAPABILITY_V1,
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-completion-capability"),
    )
    receipt = ExecutionReceipt.model_validate(
        {
            **receipt.model_dump(mode="python"),
            "capability_sha256": canonical_sha256(signed),
        }
    )
    return records.root, records.service_claim, receipt, signed


def _signed(
    request: VerificationRequestV1,
    signing_request: IndependentVerificationSigningRequestV1,
) -> VerifiedIndependentVerificationEvidenceV1:
    evidence = signing_request.evidence
    key_version = (
        f"projects/{request.target.project_id}/locations/us-central1/keyRings/"
        "controlgraph/cryptoKeys/evidence-signing/cryptoKeyVersions/1"
    )
    signed = SignedIndependentVerificationEvidenceV1(
        schema_version=SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
        evidence=evidence,
        purpose=INDEPENDENT_VERIFICATION_PURPOSE,
        signing_key_version=key_version,
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=canonical_sha256(evidence),
        signing_input_sha256=independent_verification_signing_input_sha256(
            evidence,
            key_version,
        ),
        signature="AQ",
    )
    return VerifiedIndependentVerificationEvidenceV1(
        schema_version=VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
        signing_request=signing_request,
        signed_evidence=signed,
        verified_at=signing_request.evidence.occurred_at,
    )


def _configuration_evidence(
    request: VerificationRequestV1,
    *,
    observed_at: str | None = None,
) -> VerifiedIndependentVerificationEvidenceV1:
    occurred_at = observed_at or request.observation_window_started_at
    traffic = tuple(
        TrafficAllocation(revision=revision, percent=percent)
        for revision, percent in (
            (request.stable_revision, request.stable_percent),
            (request.candidate_revision, request.candidate_percent),
        )
        if percent > 0
    )
    facts = ConfigurationObservationFactsV1(
        schema_version=CONFIGURATION_OBSERVATION_FACTS_V1,
        target=request.target,
        source_generation=8,
        observed_generation=8,
        provider_etag="verification-etag-001",
        reconciling=False,
        ready_state=ConfigurationReadyState.READY,
        template_revision=request.candidate_revision,
        latest_created_revision=request.candidate_revision,
        latest_ready_revision=request.candidate_revision,
        stable_revision=request.stable_revision,
        candidate_revision=request.candidate_revision,
        traffic=traffic,
        traffic_statuses=traffic,
        concurrency=request.concurrency,
        stable_revision_configuration_sha256=(
            request.expected_stable_revision_configuration_sha256
        ),
        candidate_revision_configuration_sha256=(
            request.expected_candidate_revision_configuration_sha256
        ),
        target_configuration_sha256=request.expected_target_configuration_sha256,
        retrieved_by=(
            f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        ),
        retrieved_at=occurred_at,
    )
    observation = ConfigurationObservationV1(
        schema_version=CONFIGURATION_OBSERVATION_V1,
        facts=facts,
        observation_sha256=canonical_sha256(facts),
    )
    result = ConfigurationAttestationV1(
        schema_version=CONFIGURATION_ATTESTATION_V1,
        request=request,
        request_sha256=canonical_sha256(request),
        status=ConfigurationAttestationStatus.MATCH,
        reason=ConfigurationAttestationReason.MATCH,
        observation=observation,
        attested_by=facts.retrieved_by,
        attested_at=occurred_at,
    )
    return _signed(request, _configuration_signing_request(result))


def _probe_evidence(
    request: VerificationRequestV1,
    *,
    observed_at: str | None = None,
) -> VerifiedIndependentVerificationEvidenceV1:
    occurred_at = observed_at or request.observation_window_started_at
    policy = fixed_probe_policy(request.stable_percent, request.candidate_percent)
    probe_request = ProbeRequestV1(
        schema_version=PROBE_REQUEST_V1,
        verification=request,
        policy=policy,
        endpoint="https://controlgraph-reference-target-123.us-central1.run.app/v1/probe",
        nonce="n" * 32,
        started_at=occurred_at,
    )
    stable_count = policy.stable_minimum
    samples = tuple(
        ProbeSampleObservationV1(
            schema_version=PROBE_SAMPLE_OBSERVATION_V1,
            sample_index=index,
            correlation_id=f"{request.correlation_id}:{index}",
            requested_at=occurred_at,
            completed_at=occurred_at,
            outcome=(
                ProbeSampleOutcome.STABLE
                if index <= stable_count
                else ProbeSampleOutcome.CANDIDATE
            ),
            revision=(
                request.stable_revision
                if index <= stable_count
                else request.candidate_revision
            ),
            marker=(
                "controlgraph-stable-v1"
                if index <= stable_count
                else "controlgraph-candidate-v1"
            ),
            response_sha256=f"{index:064x}",
        )
        for index in range(1, 21)
    )
    observation = ProbeObservationV1(
        schema_version=PROBE_OBSERVATION_V1,
        samples=samples,
        stable_count=stable_count,
        candidate_count=20 - stable_count,
        invalid_count=0,
        unavailable_count=0,
        observation_sha256=probe_observation_sha256(samples),
    )
    result = ProbeAttestationV1(
        schema_version=PROBE_ATTESTATION_V1,
        request=probe_request,
        request_sha256=canonical_sha256(probe_request),
        status=ProbeAttestationStatus.MATCH,
        reason=ProbeAttestationReason.MATCH,
        observation=observation,
        attested_by=(
            f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        ),
        completed_at=occurred_at,
    )
    return _signed(request, _probe_signing_request(result))


def test_request_binds_fixed_policy_and_current_service_claim() -> None:
    root, claim, receipt, _ = _receipt(CapabilityAction.PROMOTE_CANDIDATE)

    request = create_verification_request(
        root=root,
        service_claim=claim,
        receipt=receipt,
        started_at="2026-08-22T12:00:00Z",
    )

    assert request.service_claim_sha256 == canonical_sha256(claim)
    assert request.probe_policy_sha256 == canonical_sha256(fixed_probe_policy(0, 100))
    assert request.expected_target_configuration_sha256 == receipt.expected_poststate_sha256
    assert request.signed_intent_sha256 == receipt.capability_sha256


def test_terminal_workflow_collects_both_signals_and_records_one_group() -> None:
    root, claim, receipt, signed = _receipt(CapabilityAction.PROMOTE_CANDIDATE)
    verifier = _Verifier()
    timeline = _Timeline(receipt.target)
    workflow = CoordinatorCompletionWorkflow(
        target=receipt.target,
        verifier=verifier,
        classifier=CoordinatorCompletionClassificationService(target=receipt.target),
        timeline_recorder=timeline,
        signed_intent_reader=_IntentReader(signed, receipt.target),
        signed_intent_verifier=_IntentVerifier(),
        clock=lambda: NOW,
    )

    result = asyncio.run(
        workflow.classify_completion(
            root=root,
            service_claim=claim,
            receipt=receipt,
        )
    )

    assert result.status is CompletionStatus.COMPLETE
    assert result.reason is CompletionReason.PROMOTION_COMPLETE
    assert [call.kind for call in verifier.calls] == [
        IndependentVerificationKind.CONFIGURATION,
        IndependentVerificationKind.PROBE,
    ]
    assert timeline.verification_groups == []
    assert len(timeline.completion_groups) == 1
    assert timeline.completion_groups[0][0] == result
    assert len(timeline.completion_groups[0][1]) == 2


def test_terminal_workflow_classifies_verifier_outage_as_ambiguous() -> None:
    root, claim, receipt, signed = _receipt(CapabilityAction.RECOVER_STABLE)
    timeline = _Timeline(receipt.target)
    workflow = CoordinatorCompletionWorkflow(
        target=receipt.target,
        verifier=_Verifier(unavailable=True),
        classifier=CoordinatorCompletionClassificationService(target=receipt.target),
        timeline_recorder=timeline,
        signed_intent_reader=_IntentReader(signed, receipt.target),
        signed_intent_verifier=_IntentVerifier(),
        clock=lambda: NOW,
    )

    result = asyncio.run(
        workflow.classify_completion(
            root=root,
            service_claim=claim,
            receipt=receipt,
        )
    )

    assert result.status is CompletionStatus.AMBIGUOUS
    assert result.reason is CompletionReason.CONFIGURATION_PROOF_ABSENT
    assert timeline.completion_groups == [(result, ())]


def test_terminal_workflow_rejects_an_unverified_signed_intent() -> None:
    root, claim, receipt, signed = _receipt(CapabilityAction.PROMOTE_CANDIDATE)
    workflow = CoordinatorCompletionWorkflow(
        target=receipt.target,
        verifier=_Verifier(),
        classifier=CoordinatorCompletionClassificationService(target=receipt.target),
        signed_intent_reader=_IntentReader(signed, receipt.target),
        signed_intent_verifier=_IntentVerifier(rejected=True),
        clock=lambda: NOW,
    )

    result = asyncio.run(
        workflow.classify_completion(
            root=root,
            service_claim=claim,
            receipt=receipt,
        )
    )

    assert result.status is CompletionStatus.AMBIGUOUS
    assert result.reason is CompletionReason.EXECUTION_PROOF_ABSENT


def test_terminal_workflow_reverifies_an_old_receipt_in_a_fresh_window() -> None:
    root, claim, old_receipt, signed = _receipt(
        CapabilityAction.PROMOTE_CANDIDATE,
        day="2026-08-21",
    )
    workflow = CoordinatorCompletionWorkflow(
        target=old_receipt.target,
        verifier=_Verifier(),
        classifier=CoordinatorCompletionClassificationService(
            target=old_receipt.target
        ),
        signed_intent_reader=_IntentReader(signed, old_receipt.target),
        signed_intent_verifier=_IntentVerifier(),
        clock=lambda: NOW,
    )

    result = asyncio.run(
        workflow.classify_completion(
            root=root,
            service_claim=claim,
            receipt=old_receipt,
        )
    )

    assert result.status is CompletionStatus.COMPLETE
    assert result.reason is CompletionReason.PROMOTION_COMPLETE
    assert (
        result.request.verification.observation_window_started_at
        == "2026-08-22T12:00:00Z"
    )
    assert result.request.verification.signed_intent_sha256 == old_receipt.capability_sha256


def test_revocation_workflow_uses_signature_verified_authority_evidence() -> None:
    records = make_root_v3_records()
    proof_records = make_revocation_proof_records(root_records=records)
    workflow = CoordinatorCompletionWorkflow(
        target=records.root.content.target,
        verifier=_Verifier(unavailable=True),
        classifier=CoordinatorCompletionClassificationService(
            target=records.root.content.target
        ),
        clock=lambda: NOW,
    )

    result = asyncio.run(
        workflow.classify_revocation(
            root=records.root,
            service_claim=records.service_claim,
            result=proof_records.proof.result,
            signed_evidence=proof_records.proof.signed_evidence,
        )
    )

    assert result.status is CompletionStatus.COMPLETE
    assert result.reason is CompletionReason.REVOCATION_COMPLETE
    assert result.request.verification.epoch == proof_records.proof.authority.current_epoch


def test_stale_denial_workflow_binds_receipt_to_signed_epoch_advancement() -> None:
    records = make_root_v3_records()
    _, _, verified, signed = _receipt(CapabilityAction.RECOVER_STABLE)
    proof_records = make_revocation_proof_records(
        root_records=records,
        committed_at="2026-08-22T12:00:00Z",
    )
    receipt = ExecutionReceipt.model_validate(
        {
            **verified.model_dump(mode="python"),
            "outcome": ReceiptOutcome.DENIED,
            "reason_code": ReasonCode.EPOCH_MISMATCH,
            "provider_operation": None,
            "observed_etag": None,
            "observed_authority_epoch": 2,
            "dispatch_not_after": "2026-08-22T12:01:00Z",
            "created_at": "2026-08-22T12:00:10Z",
            "updated_at": "2026-08-22T12:00:11Z",
            "evidence_ids": (),
        }
    )
    proof = proof_records.proof
    bundle = RootCreationBundle(
        root=StoredRecord(records.root, 0),
        service_claim=StoredRecord(records.service_claim, 0),
        authority=StoredRecord(proof.authority, 1),
        lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        signed_evidence=StoredRecord(records.signed_evidence, 0),
        creation_result=StoredRecord(records.creation_result, 0),
    )
    authority_reader = _AuthorityReader(bundle, proof.signed_evidence)
    authority_verifier = _AuthorityEvidenceVerifier()
    target_verifier = _Verifier(observed_at="2026-08-22T12:00:12Z")
    timeline = _Timeline(records.root.content.target)
    workflow = CoordinatorCompletionWorkflow(
        target=records.root.content.target,
        verifier=target_verifier,
        classifier=CoordinatorCompletionClassificationService(
            target=records.root.content.target
        ),
        timeline_recorder=timeline,
        authority_reader=authority_reader,
        authority_evidence_verifier=authority_verifier,
        signed_intent_reader=_IntentReader(signed, receipt.target),
        signed_intent_verifier=_IntentVerifier(),
        clock=lambda: NOW,
    )

    result = asyncio.run(workflow.classify_stale_denial(receipt))

    assert result.status is CompletionStatus.COMPLETE
    assert result.reason is CompletionReason.STALE_CAPABILITY_DENIAL_COMPLETE
    assert result.request.verification.epoch == receipt.epoch
    assert result.request.verification.action is CapabilityAction.APPLY_CANARY
    assert (
        result.request.verification.stable_percent,
        result.request.verification.candidate_percent,
    ) == (90, 10)
    assert result.request.verification.service_claim_sha256 == canonical_sha256(
        records.service_claim
    )
    assert (
        result.request.verification.observation_window_started_at
        == proof.signed_evidence.event.occurred_at
    )
    assert authority_verifier.calls == [proof.signed_evidence]
    assert [call.kind for call in target_verifier.calls] == [
        IndependentVerificationKind.CONFIGURATION,
        IndependentVerificationKind.PROBE,
    ]
    stale_group = timeline.stale_denial_groups[0]
    assert stale_group[:3] == (receipt, proof.signed_evidence, result)
    assert len(stale_group[3]) == 2


def test_stale_denial_verifier_failure_preserves_denial_without_retry() -> None:
    records = make_root_v3_records()
    _, _, verified, signed = _receipt(CapabilityAction.RECOVER_STABLE)
    first = make_revocation_proof_records(
        root_records=records,
        committed_at="2026-08-22T12:00:00Z",
    ).proof.signed_evidence
    event = EvidenceEvent(
        schema_version=EVIDENCE_EVENT_V1,
        evidence_id=f"cgevidence:{'3' * 64}",
        sequence=first.event.sequence + 1,
        root_id=records.root.root_id,
        root_sha256=records.root.root_sha256,
        target=records.root.content.target,
        epoch=3,
        kind=first.event.kind,
        actor="operator@example.test",
        request_id="request-revoke-proof-002",
        receipt_id=None,
        occurred_at="2026-08-22T12:00:05Z",
        subject_sha256="3" * 64,
        previous_event_sha256=canonical_sha256(first),
        reason_code=None,
        provider_operation=None,
        target_configuration_sha256=None,
    )
    key_version = records.root.content.evidence_signing_key_version
    epoch_three_evidence = SignedEvidenceEventV1(
        schema_version=SIGNED_EVIDENCE_EVENT_V1,
        event=event,
        purpose="EVIDENCE",
        signing_key_version=key_version,
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=evidence_payload_sha256(event),
        signing_input_sha256=evidence_signing_input_sha256(event, key_version),
        signature=encode_base64url(b"synthetic-epoch-three-signature"),
    )
    authority_three = EpochAuthorityRecord(
        schema_version=EPOCH_AUTHORITY_V1,
        root_id=records.root.root_id,
        root_sha256=records.root.root_sha256,
        target=records.root.content.target,
        current_epoch=3,
        previous_epoch=2,
        revision=2,
        cause=EpochChangeCause.OPERATOR_REVOCATION,
        changed_by=event.actor,
        request_id=event.request_id,
        evidence_id=event.evidence_id,
        changed_at=event.occurred_at,
    )
    receipt = ExecutionReceipt.model_validate(
        {
            **verified.model_dump(mode="python"),
            "outcome": ReceiptOutcome.DENIED,
            "reason_code": ReasonCode.EPOCH_MISMATCH,
            "provider_operation": None,
            "observed_etag": None,
            "observed_authority_epoch": 3,
            "dispatch_not_after": "2026-08-22T12:01:00Z",
            "created_at": "2026-08-22T12:00:10Z",
            "updated_at": "2026-08-22T12:00:11Z",
            "evidence_ids": (),
        }
    )
    bundle = RootCreationBundle(
        root=StoredRecord(records.root, 0),
        service_claim=StoredRecord(records.service_claim, 0),
        authority=StoredRecord(authority_three, 2),
        lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        signed_evidence=StoredRecord(records.signed_evidence, 0),
        creation_result=StoredRecord(records.creation_result, 0),
    )
    authority_reader = _AuthorityReader(
        bundle,
        epoch_three_evidence,
        epoch_evidence={3: epoch_three_evidence},
    )
    authority_verifier = _AuthorityEvidenceVerifier()
    target_verifier = _Verifier(unavailable=True)
    timeline = _Timeline(receipt.target)
    workflow = CoordinatorCompletionWorkflow(
        target=records.root.content.target,
        verifier=target_verifier,
        classifier=CoordinatorCompletionClassificationService(
            target=records.root.content.target
        ),
        timeline_recorder=timeline,
        authority_reader=authority_reader,
        authority_evidence_verifier=authority_verifier,
        signed_intent_reader=_IntentReader(signed, receipt.target),
        signed_intent_verifier=_IntentVerifier(),
        clock=lambda: NOW,
    )

    initial = asyncio.run(workflow.classify_stale_denial(receipt))

    authority_reader.bundle = RootCreationBundle(
        root=bundle.root,
        service_claim=bundle.service_claim,
        authority=StoredRecord(
            EpochAuthorityRecord(
                schema_version=EPOCH_AUTHORITY_V1,
                root_id=records.root.root_id,
                root_sha256=records.root.root_sha256,
                target=records.root.content.target,
                current_epoch=4,
                previous_epoch=3,
                revision=3,
                cause=EpochChangeCause.OPERATOR_REVOCATION,
                changed_by="operator@example.test",
                request_id="request-revoke-proof-003",
                evidence_id=f"cgevidence:{'4' * 64}",
                changed_at="2026-08-22T12:00:20Z",
            ),
            3,
        ),
        lineage_anchor=bundle.lineage_anchor,
        signed_evidence=bundle.signed_evidence,
        creation_result=bundle.creation_result,
    )
    replay = asyncio.run(workflow.classify_stale_denial(receipt))

    assert initial.status is CompletionStatus.COMPLETE
    assert initial.reason is CompletionReason.STALE_CAPABILITY_DENIAL_COMPLETE
    assert initial.follow_up_required is False
    assert initial.follow_up_after_seconds is None
    assert initial.follow_up_attempt_limit is None
    assert replay == initial
    assert receipt.outcome is ReceiptOutcome.DENIED
    assert receipt.reason_code is ReasonCode.EPOCH_MISMATCH
    assert all(group[0] == receipt and group[3] == () for group in timeline.stale_denial_groups)
    assert [call.kind for call in target_verifier.calls] == [
        IndependentVerificationKind.CONFIGURATION,
        IndependentVerificationKind.PROBE,
        IndependentVerificationKind.CONFIGURATION,
        IndependentVerificationKind.PROBE,
    ]
    assert authority_verifier.calls == [epoch_three_evidence, epoch_three_evidence]


def test_stale_denial_workflow_classifies_missing_authority_proof_as_ambiguous() -> None:
    records = make_root_v3_records()
    _, _, verified, signed = _receipt(CapabilityAction.RECOVER_STABLE)
    proof = make_revocation_proof_records(
        root_records=records,
        committed_at="2026-08-22T12:00:00Z",
    ).proof
    receipt = ExecutionReceipt.model_validate(
        {
            **verified.model_dump(mode="python"),
            "outcome": ReceiptOutcome.DENIED,
            "reason_code": ReasonCode.EPOCH_MISMATCH,
            "provider_operation": None,
            "observed_etag": None,
            "observed_authority_epoch": 2,
            "dispatch_not_after": "2026-08-22T12:01:00Z",
            "created_at": "2026-08-22T12:00:00Z",
            "updated_at": "2026-08-22T12:00:01Z",
            "evidence_ids": (),
        }
    )
    bundle = RootCreationBundle(
        root=StoredRecord(records.root, 0),
        service_claim=StoredRecord(records.service_claim, 0),
        authority=StoredRecord(proof.authority, 1),
        lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        signed_evidence=StoredRecord(records.signed_evidence, 0),
        creation_result=StoredRecord(records.creation_result, 0),
    )
    timeline = _Timeline(records.root.content.target)
    workflow = CoordinatorCompletionWorkflow(
        target=records.root.content.target,
        verifier=_Verifier(unavailable=True),
        classifier=CoordinatorCompletionClassificationService(
            target=records.root.content.target
        ),
        timeline_recorder=timeline,
        authority_reader=_AuthorityReader(bundle, None),
        authority_evidence_verifier=_AuthorityEvidenceVerifier(),
        signed_intent_reader=_IntentReader(signed, receipt.target),
        signed_intent_verifier=_IntentVerifier(),
        clock=lambda: NOW,
    )

    result = asyncio.run(workflow.classify_stale_denial(receipt))

    assert result.status is CompletionStatus.AMBIGUOUS
    assert result.reason is CompletionReason.AUTHORITY_PROOF_ABSENT
    assert timeline.stale_denial_groups == [(receipt, None, result, ())]
