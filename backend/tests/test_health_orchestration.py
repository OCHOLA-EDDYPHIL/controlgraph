from __future__ import annotations

import asyncio
import inspect
import struct
from datetime import UTC, datetime

import pytest
from health_execution_test_data import (
    make_anchor,
    make_healthy_chain,
    make_signed_proof,
)

from controlgraph_canary.application.health_evaluation import (
    initial_health_evaluation_state,
)
from controlgraph_canary.application.health_orchestration import (
    HealthOrchestrationError,
    HealthOrchestrationErrorCode,
    VerifierHealthProofService,
    validate_health_attestation_signing_request_decisions,
    verify_healthy_promotion_chain,
)
from controlgraph_canary.application.monitoring import (
    MonitoringCollectedPoint,
    MonitoringQueryCollection,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.health import (
    MonitoringMetricQueryV1,
    MonitoringQueryKind,
)
from controlgraph_canary.contracts.health_execution import (
    HEALTH_ATTESTATION_PURPOSE,
    HealthAttestationSigningRequestV1,
    PostApplyHealthAnchorV1,
    SignedHealthDecisionProofV1,
    create_health_attestation_signing_request,
    create_health_decision_proof,
)


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _HealthyQueryCollector:
    def __init__(self) -> None:
        self.calls: list[MonitoringMetricQueryV1] = []

    async def collect(
        self,
        query: MonitoringMetricQueryV1,
        *,
        timeout_seconds: float,
    ) -> MonitoringQueryCollection:
        assert timeout_seconds == 10.0
        self.calls.append(query)
        query_sha256 = canonical_sha256(query)
        if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
            points = (
                MonitoringCollectedPoint(
                    query_sha256=query_sha256,
                    query_kind=query.query_kind,
                    interval_started_at=query.window_started_at,
                    interval_ended_at=query.window_ended_at,
                    response_code_class=None,
                    provider_value_type="DOUBLE",
                    int64_value=None,
                    provider_double_bits=struct.pack(">d", 400.0).hex(),
                ),
            )
        else:
            points = tuple(
                MonitoringCollectedPoint(
                    query_sha256=query_sha256,
                    query_kind=query.query_kind,
                    interval_started_at=query.window_started_at,
                    interval_ended_at=query.window_ended_at,
                    response_code_class=response_code_class,  # type: ignore[arg-type]
                    provider_value_type="INT64",
                    int64_value=count,
                    provider_double_bits=None,
                )
                for response_code_class, count in (
                    ("2xx", 995),
                    ("3xx", 2),
                    ("4xx", 2),
                    ("5xx", 1),
                )
            )
        return MonitoringQueryCollection(
            query_sha256=query_sha256,
            query_kind=query.query_kind,
            points=points,
        )


class _Attestor:
    purpose = HEALTH_ATTESTATION_PURPOSE

    def __init__(self, anchor: PostApplyHealthAnchorV1) -> None:
        self.anchor = anchor
        self.signing_key_version = anchor.evidence_signing_key_version
        self.calls: list[HealthAttestationSigningRequestV1] = []

    async def attest(
        self,
        request: HealthAttestationSigningRequestV1,
    ) -> SignedHealthDecisionProofV1:
        self.calls.append(request)
        proof = request.pending_proof
        return make_signed_proof(
            proof,
            self.anchor,
            marker=f"health-proof-{proof.sequence}".encode(),
        )


class _SignatureVerifier:
    def __init__(self, *, rejected_proof_id: str | None = None) -> None:
        self.rejected_proof_id = rejected_proof_id
        self.calls: list[SignedHealthDecisionProofV1] = []

    async def verify(self, signed_proof: SignedHealthDecisionProofV1) -> None:
        self.calls.append(signed_proof)
        if signed_proof.proof.proof_id == self.rejected_proof_id:
            raise ValueError("synthetic invalid signature")


def test_stateless_verifier_derives_state_and_returns_only_verified_signed_proofs() -> None:
    root, anchor = make_anchor()
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    collector = _HealthyQueryCollector()
    attestor = _Attestor(anchor)
    signature_verifier = _SignatureVerifier()
    service = VerifierHealthProofService(
        root=root,
        anchor=anchor,
        query_collector=collector,
        attestor=attestor,
        signature_verifier=signature_verifier,
        clock=clock,
    )

    first = asyncio.run(service.evaluate_and_attest(None))
    clock.value = datetime(2026, 8, 21, 12, 9, tzinfo=UTC)
    second = asyncio.run(service.evaluate_and_attest(first))

    assert first.proof.sequence == 1
    assert first.proof.decision.status.value == "wait"
    assert second.proof.sequence == 2
    assert second.proof.previous_signed_proof_sha256 == canonical_sha256(first)
    assert second.proof.decision.status.value == "healthy"
    assert len(collector.calls) == 4
    assert [request.pending_proof for request in attestor.calls] == [
        first.proof,
        second.proof,
    ]
    assert not hasattr(service, "_state_store")
    assert not hasattr(service, "stage")
    assert not hasattr(service, "finalize")
    assert not hasattr(service, "sign")
    assert not hasattr(service, "enqueue")
    assert tuple(inspect.signature(service.evaluate_and_attest).parameters) == (
        "predecessor",
    )


def test_stateless_verifier_rejects_predecessor_signature_before_collection() -> None:
    root, anchor = make_anchor()
    initial_clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    first_service = VerifierHealthProofService(
        root=root,
        anchor=anchor,
        query_collector=_HealthyQueryCollector(),
        attestor=_Attestor(anchor),
        signature_verifier=_SignatureVerifier(),
        clock=initial_clock,
    )
    predecessor = asyncio.run(first_service.evaluate_and_attest(None))
    collector = _HealthyQueryCollector()
    attestor = _Attestor(anchor)
    service = VerifierHealthProofService(
        root=root,
        anchor=anchor,
        query_collector=collector,
        attestor=attestor,
        signature_verifier=_SignatureVerifier(
            rejected_proof_id=predecessor.proof.proof_id
        ),
        clock=_Clock(datetime(2026, 8, 21, 12, 9, tzinfo=UTC)),
    )

    with pytest.raises(HealthOrchestrationError) as error:
        asyncio.run(service.evaluate_and_attest(predecessor))

    assert error.value.code is HealthOrchestrationErrorCode.SIGNATURE_INVALID
    assert collector.calls == []
    assert attestor.calls == []


def test_evidence_writer_recomputes_and_rejects_evaluator_false_healthy_proof() -> None:
    _, anchor = make_anchor()
    healthy_chain = make_healthy_chain()
    terminal = healthy_chain.signed_proofs[-1].proof
    initial = initial_health_evaluation_state(
        policy=anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
    )
    forged_decision = terminal.decision.model_copy(
        update={"prior_state_sha256": canonical_sha256(initial)}
    )
    forged = create_health_decision_proof(
        anchor=anchor,
        sequence=1,
        previous_signed_proof_sha256=None,
        prior_state=initial,
        observation=terminal.observation,
        decision=forged_decision,
    )
    request = create_health_attestation_signing_request(
        anchor=anchor,
        prior_signed_proof=None,
        pending_proof=forged,
    )

    with pytest.raises(ValueError, match="noncanonical decision"):
        validate_health_attestation_signing_request_decisions(request)


def test_promotion_verification_fails_on_signature_error_and_expiration() -> None:
    chain = make_healthy_chain()
    terminal = chain.signed_proofs[-1]
    invalid_verifier = _SignatureVerifier(rejected_proof_id=terminal.proof.proof_id)

    with pytest.raises(HealthOrchestrationError) as signature_error:
        asyncio.run(
            verify_healthy_promotion_chain(
                chain=chain,
                signature_verifier=invalid_verifier,
                now=datetime(2026, 8, 21, 12, 10, tzinfo=UTC),
            )
        )
    assert signature_error.value.code is HealthOrchestrationErrorCode.SIGNATURE_INVALID

    with pytest.raises(HealthOrchestrationError) as expiry_error:
        asyncio.run(
            verify_healthy_promotion_chain(
                chain=chain,
                signature_verifier=_SignatureVerifier(),
                now=datetime(2026, 8, 21, 12, 11, 1, tzinfo=UTC),
            )
        )
    assert expiry_error.value.code is HealthOrchestrationErrorCode.PROMOTION_PROOF_EXPIRED

    with pytest.raises(HealthOrchestrationError) as boundary_error:
        asyncio.run(
            verify_healthy_promotion_chain(
                chain=chain,
                signature_verifier=_SignatureVerifier(),
                now=datetime(2026, 8, 21, 12, 11, tzinfo=UTC),
            )
        )
    assert boundary_error.value.code is HealthOrchestrationErrorCode.PROMOTION_PROOF_EXPIRED
