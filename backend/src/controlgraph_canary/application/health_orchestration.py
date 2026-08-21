"""Verifier-owned health evaluation and separately privileged attestation orchestration."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.health_evaluation import (
    derive_next_health_evaluation_state,
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.application.monitoring import (
    MonitoringCollectionError,
    MonitoringCollectionScope,
    MonitoringQueryCollector,
    MonitoringWindowCollector,
    _issue_monitoring_collection_scope,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.health import HealthDecisionV1, HealthReasonCode
from controlgraph_canary.contracts.health_execution import (
    HEALTH_ATTESTATION_PURPOSE,
    P256_SIGNING_ALGORITHM,
    HealthAttestationSigningRequestV1,
    HealthDecisionProofV1,
    HealthyPromotionProofV1,
    PostApplyHealthAnchorV1,
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    create_health_attestation_signing_request,
    create_health_decision_proof,
    create_post_apply_health_anchor,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV3


class HealthOrchestrationErrorCode(StrEnum):
    """Stable payload-free failures for the health evaluation pipeline."""

    CONFIGURATION_INVALID = "HEALTH_ORCHESTRATION_CONFIGURATION_INVALID"
    STATE_INVALID = "HEALTH_ORCHESTRATION_STATE_INVALID"
    EVALUATION_NOT_READY = "HEALTH_ORCHESTRATION_EVALUATION_NOT_READY"
    EVALUATION_TERMINAL = "HEALTH_ORCHESTRATION_EVALUATION_TERMINAL"
    COLLECTION_UNAVAILABLE = "HEALTH_ORCHESTRATION_COLLECTION_UNAVAILABLE"
    EVALUATION_INVALID = "HEALTH_ORCHESTRATION_EVALUATION_INVALID"
    ATTESTATION_UNAVAILABLE = "HEALTH_ORCHESTRATION_ATTESTATION_UNAVAILABLE"
    ATTESTATION_INVALID = "HEALTH_ORCHESTRATION_ATTESTATION_INVALID"
    SIGNATURE_INVALID = "HEALTH_ORCHESTRATION_SIGNATURE_INVALID"
    PROMOTION_PROOF_UNAVAILABLE = "HEALTH_ORCHESTRATION_PROMOTION_PROOF_UNAVAILABLE"
    PROMOTION_PROOF_EXPIRED = "HEALTH_ORCHESTRATION_PROMOTION_PROOF_EXPIRED"


class HealthOrchestrationError(RuntimeError):
    """One sanitized health-orchestration failure."""

    def __init__(self, code: HealthOrchestrationErrorCode) -> None:
        if type(code) is not HealthOrchestrationErrorCode:
            raise TypeError("an exact health orchestration error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class PurposeSealedHealthAttestor(Protocol):
    """Evidence-writer port that can attest only an exact health proof."""

    @property
    def purpose(self) -> str: ...

    @property
    def signing_key_version(self) -> str: ...

    async def attest(
        self,
        request: HealthAttestationSigningRequestV1,
    ) -> SignedHealthDecisionProofV1: ...


@runtime_checkable
class HealthAttestationVerifier(Protocol):
    """Read-only verifier for the fixed health-attestation signature purpose."""

    async def verify(self, signed_proof: SignedHealthDecisionProofV1) -> None: ...


def create_monitoring_collection_scope(
    *,
    root: RolloutRootV3,
    anchor: PostApplyHealthAnchorV1,
) -> MonitoringCollectionScope:
    """Issue the only collection scope: one recomputed V3 root/receipt anchor."""

    if type(root) is not RolloutRootV3 or type(anchor) is not PostApplyHealthAnchorV1:
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.CONFIGURATION_INVALID
        )
    try:
        validated_root = RolloutRootV3.model_validate(root)
        expected_anchor = create_post_apply_health_anchor(
            root=validated_root,
            apply_receipt=anchor.apply_receipt,
        )
    except (TypeError, ValueError):
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.CONFIGURATION_INVALID
        ) from None
    if expected_anchor != anchor:
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.CONFIGURATION_INVALID
        )
    return _issue_monitoring_collection_scope(
        policy=anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
    )


class VerifierHealthProofService:
    """Stateless verifier flow with no storage, signing-key, or mutation privilege."""

    def __init__(
        self,
        *,
        root: RolloutRootV3,
        anchor: PostApplyHealthAnchorV1,
        query_collector: MonitoringQueryCollector,
        attestor: PurposeSealedHealthAttestor,
        signature_verifier: HealthAttestationVerifier,
        clock: Callable[[], datetime] | None = None,
        query_timeout_seconds: float = 10.0,
    ) -> None:
        scope = create_monitoring_collection_scope(root=root, anchor=anchor)
        if (
            not isinstance(query_collector, MonitoringQueryCollector)
            or not isinstance(attestor, PurposeSealedHealthAttestor)
            or not isinstance(signature_verifier, HealthAttestationVerifier)
            or attestor.purpose != HEALTH_ATTESTATION_PURPOSE
            or attestor.signing_key_version != anchor.evidence_signing_key_version
            or (clock is not None and not callable(clock))
        ):
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.CONFIGURATION_INVALID
            )
        self._anchor = anchor
        self._attestor = attestor
        self._signature_verifier = signature_verifier
        self._clock = clock or (lambda: datetime.now(UTC))
        self._collector = MonitoringWindowCollector(
            scope=scope,
            query_collector=query_collector,
            query_timeout_seconds=query_timeout_seconds,
            clock=self._clock,
        )

    async def evaluate_and_attest(
        self,
        predecessor: SignedHealthDecisionProofV1 | None,
    ) -> SignedHealthDecisionProofV1:
        """Verify one predecessor, derive all state, collect, evaluate, and attest once."""

        now = _clock_utc_second(self._clock)
        predecessor_decision: HealthDecisionV1 | None = None
        if predecessor is None:
            prior_state = initial_health_evaluation_state(
                policy=self._anchor.policy,
                target=self._anchor.target,
                root_id=self._anchor.root_id,
                root_sha256=self._anchor.root_sha256,
                epoch=self._anchor.epoch,
                candidate_revision=self._anchor.candidate_revision,
                observation_started_at=self._anchor.observation_started_at,
            )
            sequence = 1
            predecessor_sha256 = None
        else:
            if type(predecessor) is not SignedHealthDecisionProofV1:
                raise HealthOrchestrationError(
                    HealthOrchestrationErrorCode.STATE_INVALID
                )
            try:
                validated_predecessor = SignedHealthDecisionProofV1.model_validate(
                    predecessor
                )
            except (TypeError, ValueError):
                raise HealthOrchestrationError(
                    HealthOrchestrationErrorCode.STATE_INVALID
                ) from None
            proof = validated_predecessor.proof
            if (
                proof.anchor_id != self._anchor.anchor_id
                or proof.anchor_sha256 != canonical_sha256(self._anchor)
                or validated_predecessor.signing_key_version
                != self._anchor.evidence_signing_key_version
            ):
                raise HealthOrchestrationError(
                    HealthOrchestrationErrorCode.STATE_INVALID
                )
            try:
                await self._signature_verifier.verify(validated_predecessor)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise HealthOrchestrationError(
                    HealthOrchestrationErrorCode.SIGNATURE_INVALID
                ) from None
            predecessor_decision = proof.decision
            if predecessor_decision.next_evaluation_at is None:
                raise HealthOrchestrationError(
                    HealthOrchestrationErrorCode.EVALUATION_TERMINAL
                )
            if now < predecessor_decision.next_evaluation_at:
                raise HealthOrchestrationError(
                    HealthOrchestrationErrorCode.EVALUATION_NOT_READY
                )
            try:
                prior_state = derive_next_health_evaluation_state(
                    policy=self._anchor.policy,
                    predecessor_decision=predecessor_decision,
                )
            except (TypeError, ValueError):
                raise HealthOrchestrationError(
                    HealthOrchestrationErrorCode.STATE_INVALID
                ) from None
            sequence = proof.sequence + 1
            predecessor_sha256 = canonical_sha256(validated_predecessor)

        window_index = prior_state.evaluated_windows + 1
        if (
            sequence > self._anchor.policy.maximum_windows * 2
            or window_index > self._anchor.policy.maximum_windows
        ):
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.EVALUATION_TERMINAL
            )
        ready_at = _window_ready_at(self._anchor, window_index)
        if now < ready_at:
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.EVALUATION_NOT_READY
            )
        try:
            collected = await self._collector.collect(window_index)
            observation = collected.observation
            decision = evaluate_health_observation(
                policy=self._anchor.policy,
                prior_state=prior_state,
                predecessor_decision=predecessor_decision,
                observation=observation,
                evaluated_at=observation.observed_at,
            )
            pending = create_health_decision_proof(
                anchor=self._anchor,
                sequence=sequence,
                previous_signed_proof_sha256=predecessor_sha256,
                prior_state=prior_state,
                observation=observation,
                decision=decision,
            )
            request = create_health_attestation_signing_request(
                anchor=self._anchor,
                prior_signed_proof=predecessor,
                pending_proof=pending,
            )
            validate_health_attestation_signing_request_decisions(request)
            _validate_predecessor_attempt(predecessor, pending, self._anchor)
        except asyncio.CancelledError:
            raise
        except MonitoringCollectionError:
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.COLLECTION_UNAVAILABLE
            ) from None
        except (TypeError, ValueError):
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.EVALUATION_INVALID
            ) from None
        except Exception:
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.COLLECTION_UNAVAILABLE
            ) from None
        try:
            signed = await self._attestor.attest(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.ATTESTATION_UNAVAILABLE
            ) from None
        if (
            type(signed) is not SignedHealthDecisionProofV1
            or signed.proof != pending
            or signed.signing_key_version != self._anchor.evidence_signing_key_version
            or signed.purpose != HEALTH_ATTESTATION_PURPOSE
            or signed.signing_algorithm != P256_SIGNING_ALGORITHM
        ):
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.ATTESTATION_INVALID
            )
        try:
            await self._signature_verifier.verify(signed)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthOrchestrationError(
                HealthOrchestrationErrorCode.SIGNATURE_INVALID
            ) from None
        return signed


def validate_health_chain_decisions(chain: SignedHealthDecisionChainV1) -> None:
    """Independently replay every deterministic decision in one structural chain."""

    if type(chain) is not SignedHealthDecisionChainV1:
        raise TypeError("health decision replay requires an exact signed chain")
    predecessor: HealthDecisionV1 | None = None
    for signed in chain.signed_proofs:
        proof = signed.proof
        expected = evaluate_health_observation(
            policy=chain.anchor.policy,
            prior_state=proof.prior_state,
            predecessor_decision=predecessor,
            observation=proof.observation,
            evaluated_at=proof.produced_at,
        )
        if expected != proof.decision:
            raise ValueError("signed health chain contains a noncanonical decision")
        predecessor = proof.decision


def validate_health_attestation_signing_request_decisions(
    request: HealthAttestationSigningRequestV1,
) -> None:
    """Replay a signing request so the writer never signs an asserted decision."""

    if type(request) is not HealthAttestationSigningRequestV1:
        raise TypeError("health attestation replay requires an exact signing request")
    validated = HealthAttestationSigningRequestV1.model_validate(request)
    predecessor = validated.prior_signed_proof
    predecessor_decision = None if predecessor is None else predecessor.proof.decision
    expected = evaluate_health_observation(
        policy=validated.anchor.policy,
        prior_state=validated.pending_proof.prior_state,
        predecessor_decision=predecessor_decision,
        observation=validated.pending_proof.observation,
        evaluated_at=validated.pending_proof.produced_at,
    )
    if expected != validated.pending_proof.decision:
        raise ValueError("health attestation request contains a noncanonical decision")


async def verify_healthy_promotion_chain(
    *,
    chain: SignedHealthDecisionChainV1,
    signature_verifier: HealthAttestationVerifier,
    now: datetime,
) -> HealthyPromotionProofV1:
    """Verify signatures, replay decisions, and return one still-fresh healthy proof."""

    if (
        type(chain) is not SignedHealthDecisionChainV1
        or not isinstance(signature_verifier, HealthAttestationVerifier)
    ):
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.PROMOTION_PROOF_UNAVAILABLE
        )
    try:
        now_value = _clock_utc_second(lambda: now)
        validated = SignedHealthDecisionChainV1.model_validate(chain)
        validate_health_chain_decisions(validated)
        for signed in validated.signed_proofs:
            await signature_verifier.verify(signed)
    except asyncio.CancelledError:
        raise
    except Exception:
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.SIGNATURE_INVALID
        ) from None
    promotion = validated.healthy_promotion_proof
    if promotion is None:
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.PROMOTION_PROOF_UNAVAILABLE
        )
    if now_value < promotion.issued_at or now_value >= promotion.valid_until:
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.PROMOTION_PROOF_EXPIRED
        )
    return promotion


def _validate_predecessor_attempt(
    predecessor: SignedHealthDecisionProofV1 | None,
    pending: HealthDecisionProofV1,
    anchor: PostApplyHealthAnchorV1,
) -> None:
    if predecessor is None:
        if pending.sequence != 1 or pending.observation.window_index != 1:
            raise ValueError("initial health proof attempt is invalid")
        return
    previous = predecessor.proof
    if pending.observation.window_index != previous.observation.window_index:
        return
    policy = anchor.policy
    deadline = _timestamp_plus_seconds(
        pending.observation.window_ended_at,
        policy.maximum_observation_delay_seconds,
    )
    if (
        len(previous.decision.reason_codes) != 1
        or previous.decision.reason_codes[0]
        not in {
            HealthReasonCode.SAMPLE_MISSING,
            HealthReasonCode.SAMPLE_PARTIAL,
            HealthReasonCode.MINIMUM_REQUESTS_NOT_MET,
        }
        or previous.decision.next_evaluation_at != deadline
        or previous.decision.evaluated_at >= deadline
        or pending.decision.evaluated_at < deadline
    ):
        raise ValueError("health proof is not the one canonical deadline retry")


def _window_ready_at(anchor: PostApplyHealthAnchorV1, window_index: int) -> str:
    seconds = (
        window_index * anchor.policy.window_seconds
        + anchor.policy.observation_delay_seconds
    )
    return _timestamp_plus_seconds(anchor.observation_started_at, seconds)


def _timestamp_plus_seconds(value: str, seconds: int) -> str:
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return (parsed + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clock_utc_second(clock: Callable[[], datetime]) -> str:
    try:
        value = clock()
    except Exception:
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.EVALUATION_INVALID
        ) from None
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise HealthOrchestrationError(
            HealthOrchestrationErrorCode.EVALUATION_INVALID
        )
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "HealthAttestationVerifier",
    "HealthOrchestrationError",
    "HealthOrchestrationErrorCode",
    "PurposeSealedHealthAttestor",
    "VerifierHealthProofService",
    "create_monitoring_collection_scope",
    "validate_health_attestation_signing_request_decisions",
    "validate_health_chain_decisions",
    "verify_healthy_promotion_chain",
]
