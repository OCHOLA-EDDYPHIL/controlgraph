from __future__ import annotations

from health_execution_test_data import (
    make_anchor,
    make_missing_observation,
    make_signed_proof,
)

from controlgraph_canary.application.health_evaluation import (
    derive_next_health_evaluation_state,
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.health import HealthDecisionV1
from controlgraph_canary.contracts.health_execution import (
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    create_health_decision_proof,
    create_signed_health_decision_chain,
)


def make_twenty_proof_chain() -> SignedHealthDecisionChainV1:
    _, anchor = make_anchor()
    state = initial_health_evaluation_state(
        policy=anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
    )
    predecessor: HealthDecisionV1 | None = None
    signed_proofs: list[SignedHealthDecisionProofV1] = []
    for window_index in range(1, anchor.policy.maximum_windows + 1):
        window_end_minute = 4 + window_index
        for observation_minute in (window_end_minute + 3, window_end_minute + 5):
            observation = make_missing_observation(
                anchor,
                window_index=window_index,
                observed_at=f"2026-08-21T12:{observation_minute:02d}:00Z",
            )
            decision = evaluate_health_observation(
                policy=anchor.policy,
                prior_state=state,
                predecessor_decision=predecessor,
                observation=observation,
                evaluated_at=observation.observed_at,
            )
            proof = create_health_decision_proof(
                anchor=anchor,
                sequence=len(signed_proofs) + 1,
                previous_signed_proof_sha256=(
                    canonical_sha256(signed_proofs[-1]) if signed_proofs else None
                ),
                prior_state=state,
                observation=observation,
                decision=decision,
            )
            signed_proofs.append(
                make_signed_proof(
                    proof,
                    anchor,
                    marker=f"normalized-proof-{len(signed_proofs) + 1}".encode(),
                )
            )
            predecessor = decision
            if decision.next_evaluation_at is not None:
                state = derive_next_health_evaluation_state(
                    policy=anchor.policy,
                    predecessor_decision=decision,
                )
    return create_signed_health_decision_chain(
        anchor=anchor,
        signed_proofs=tuple(signed_proofs),
    )


__all__ = ["make_twenty_proof_chain"]
