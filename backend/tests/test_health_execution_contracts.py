from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

import pytest
from health_execution_test_data import (
    make_anchor,
    make_health_root,
    make_healthy_chain,
    make_missing_observation,
    make_observation,
    make_signed_proof,
    make_verified_apply_receipt,
    target_state_sha256,
)
from pydantic import ValidationError

from controlgraph_canary.application.cloud_run import (
    rollout_root_v3_target_configuration_sha256,
)
from controlgraph_canary.application.health_evaluation import (
    derive_next_health_evaluation_state,
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.application.health_orchestration import (
    HealthOrchestrationError,
    create_monitoring_collection_scope,
)
from controlgraph_canary.application.monitoring import MonitoringCollectionScope
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.health import MonitoringWindowObservationV1
from controlgraph_canary.contracts.health_execution import (
    HealthAttestationSigningRequestV1,
    HealthyPromotionProofV1,
    PostApplyHealthAnchorV1,
    SignedHealthDecisionChainV1,
    create_health_attestation_signing_request,
    create_health_decision_proof,
    create_post_apply_health_anchor,
    create_signed_health_decision_chain,
    health_chain_manifest_sha256,
    next_utc_minute_strictly_after,
    signed_health_decision_chain_sha256,
    signed_health_proof_chain_sha256,
)
from controlgraph_canary.contracts.models import CapabilityAction, ReceiptOutcome


@pytest.mark.parametrize(
    ("receipt_time", "expected_start"),
    (
        ("2026-08-21T12:03:00Z", "2026-08-21T12:04:00Z"),
        ("2026-08-21T12:03:59Z", "2026-08-21T12:04:00Z"),
    ),
)
def test_anchor_starts_at_the_next_strict_utc_minute(
    receipt_time: str,
    expected_start: str,
) -> None:
    root = make_health_root()
    receipt = make_verified_apply_receipt(root, updated_at=receipt_time)

    anchor = create_post_apply_health_anchor(root=root, apply_receipt=receipt)

    assert anchor.observation_started_at == expected_start
    assert anchor.source_receipt_sha256 == canonical_sha256(receipt)
    assert anchor.provider_etag == receipt.observed_etag
    assert anchor.anchor_id.startswith("cghealthanchor:")
    assert next_utc_minute_strictly_after(receipt_time) == expected_start


@pytest.mark.parametrize(
    "change",
    (
        {"outcome": ReceiptOutcome.APPLIED, "observed_etag": None},
        {"action": CapabilityAction.PROMOTE_CANDIDATE},
        {"plan_sha256": "f" * 64},
        {"observed_authority_epoch": 2},
    ),
)
def test_anchor_rejects_receipts_outside_the_exact_verified_apply_result(
    change: dict[str, object],
) -> None:
    root = make_health_root()
    values = make_verified_apply_receipt(root).model_dump(mode="python")
    values.update(change)
    receipt = type(make_verified_apply_receipt(root)).model_validate(values)

    with pytest.raises((ValueError, ValidationError)):
        create_post_apply_health_anchor(root=root, apply_receipt=receipt)


def test_target_projection_digests_match_the_execution_boundary_for_both_states() -> None:
    root, anchor = make_anchor()
    chain = make_healthy_chain()
    promotion = chain.healthy_promotion_proof
    assert promotion is not None

    assert anchor.expected_prestate_sha256 == target_state_sha256(
        root,
        stable_percent=90,
        candidate_percent=10,
    )
    assert anchor.expected_prestate_sha256 == rollout_root_v3_target_configuration_sha256(
        root,
        stable_percent=90,
        candidate_percent=10,
    )
    assert promotion.desired_poststate_sha256 == target_state_sha256(
        root,
        stable_percent=0,
        candidate_percent=100,
    )
    assert promotion.desired_poststate_sha256 == rollout_root_v3_target_configuration_sha256(
        root,
        stable_percent=0,
        candidate_percent=100,
    )


def test_monitoring_scope_is_issued_only_from_the_exact_root_and_anchor() -> None:
    root, anchor = make_anchor()

    with pytest.raises(TypeError):
        MonitoringCollectionScope(  # type: ignore[call-arg]
            policy=anchor.policy,
            target=anchor.target,
            root_id=anchor.root_id,
            root_sha256=anchor.root_sha256,
            epoch=anchor.epoch,
            candidate_revision=anchor.candidate_revision,
            observation_started_at=anchor.observation_started_at,
        )

    scope = create_monitoring_collection_scope(root=root, anchor=anchor)
    assert scope.policy == anchor.policy
    assert scope.root_sha256 == root.root_sha256

    forged = anchor.model_copy(update={"source_receipt_sha256": "f" * 64})
    with pytest.raises(HealthOrchestrationError):
        create_monitoring_collection_scope(root=root, anchor=forged)


def test_healthy_chain_binds_every_promotion_input_and_policy_late_bound() -> None:
    chain = make_healthy_chain()
    anchor = chain.anchor
    terminal = chain.signed_proofs[-1]
    promotion = chain.healthy_promotion_proof
    assert promotion is not None

    expected_valid_until = (
        terminal.proof.observation.window_ended_at[:-1]
    )
    terminal_end = datetime.fromisoformat(expected_valid_until)
    expected_valid_until = (
        terminal_end + timedelta(seconds=anchor.policy.maximum_observation_delay_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert promotion.anchor_sha256 == canonical_sha256(anchor)
    assert promotion.source_receipt_sha256 == anchor.source_receipt_sha256
    assert promotion.expected_prestate_sha256 == anchor.expected_prestate_sha256
    assert promotion.terminal_health_decision_sha256 == terminal.proof.decision_sha256
    assert promotion.signed_health_chain_sha256 == signed_health_proof_chain_sha256(
        chain.signed_proofs
    )
    assert promotion.valid_until == expected_valid_until
    assert promotion.valid_until == "2026-08-21T12:12:00Z"


def test_chain_rejects_a_substituted_predecessor_or_compact_proof() -> None:
    chain = make_healthy_chain()
    first, second = chain.signed_proofs
    tampered_proof = create_health_decision_proof(
        anchor=chain.anchor,
        sequence=second.proof.sequence,
        previous_signed_proof_sha256="f" * 64,
        prior_state=second.proof.prior_state,
        observation=second.proof.observation,
        decision=second.proof.decision,
    )
    tampered_second = make_signed_proof(
        tampered_proof,
        chain.anchor,
        marker=b"tampered-predecessor-proof",
    )

    with pytest.raises(ValidationError, match="predecessor"):
        create_signed_health_decision_chain(
            anchor=chain.anchor,
            signed_proofs=(first, tampered_second),
        )

    promotion = chain.healthy_promotion_proof
    assert promotion is not None
    tampered_promotion = promotion.model_copy(update={"valid_until": "2026-08-21T12:13:00Z"})
    with pytest.raises(ValidationError, match="promotion proof"):
        SignedHealthDecisionChainV1.model_validate(
            chain.model_copy(update={"healthy_promotion_proof": tampered_promotion})
        )


def test_signing_request_carries_the_exact_prior_chain_and_pending_proof() -> None:
    complete = make_healthy_chain()
    first, second = complete.signed_proofs
    prior = create_signed_health_decision_chain(
        anchor=complete.anchor,
        signed_proofs=(first,),
    )

    request = create_health_attestation_signing_request(
        anchor=complete.anchor,
        prior_signed_proof=prior.signed_proofs[-1],
        pending_proof=second.proof,
    )

    assert request.prior_signed_proof == prior.signed_proofs[-1]
    assert request.pending_proof == second.proof
    assert request.pending_proof.previous_signed_proof_sha256 == prior.chain_head_sha256
    assert request.request_id.startswith("cghealthattest:")

    substituted = request.model_copy(update={"prior_signed_proof": None})
    with pytest.raises(ValidationError, match="predecessor"):
        HealthAttestationSigningRequestV1.model_validate(substituted)


def test_same_window_retry_is_admitted_only_at_the_policy_deadline() -> None:
    _, anchor = make_anchor()
    initial = initial_health_evaluation_state(
        policy=anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
    )
    ready_observation = make_missing_observation(
        anchor,
        window_index=1,
        observed_at="2026-08-21T12:08:00Z",
    )
    ready_decision = evaluate_health_observation(
        policy=anchor.policy,
        prior_state=initial,
        observation=ready_observation,
        evaluated_at=ready_observation.observed_at,
    )
    ready_proof = create_health_decision_proof(
        anchor=anchor,
        sequence=1,
        previous_signed_proof_sha256=None,
        prior_state=initial,
        observation=ready_observation,
        decision=ready_decision,
    )
    ready_signed = make_signed_proof(ready_proof, anchor, marker=b"missing-ready-proof")
    linked = derive_next_health_evaluation_state(
        policy=anchor.policy,
        predecessor_decision=ready_decision,
    )

    def retry(observed_at: str):  # type: ignore[no-untyped-def]
        observation = make_missing_observation(
            anchor,
            window_index=1,
            observed_at=observed_at,
        )
        decision = evaluate_health_observation(
            policy=anchor.policy,
            prior_state=linked,
            predecessor_decision=ready_decision,
            observation=observation,
            evaluated_at=observation.observed_at,
        )
        proof = create_health_decision_proof(
            anchor=anchor,
            sequence=2,
            previous_signed_proof_sha256=canonical_sha256(ready_signed),
            prior_state=linked,
            observation=observation,
            decision=decision,
        )
        return make_signed_proof(proof, anchor, marker=observed_at.encode())

    with pytest.raises(ValidationError, match="deadline retry"):
        create_signed_health_decision_chain(
            anchor=anchor,
            signed_proofs=(ready_signed, retry("2026-08-21T12:10:00Z")),
        )

    deadline_chain = create_signed_health_decision_chain(
        anchor=anchor,
        signed_proofs=(ready_signed, retry("2026-08-21T12:11:00Z")),
    )
    assert len(deadline_chain.signed_proofs) == 2
    assert deadline_chain.signed_proofs[-1].proof.decision.next_state.evaluated_windows == 1


def test_maximum_source_evidence_signing_request_stays_below_contract_byte_limit() -> None:
    _, anchor = make_anchor()

    def maximal_sources(window_index: int) -> MonitoringWindowObservationV1:
        observation = make_observation(anchor, window_index=window_index)
        digests = set(observation.sample_sha256s)
        marker = 0
        while len(digests) < 64:
            digests.add(hashlib.sha256(f"synthetic-source-{marker}".encode()).hexdigest())
            marker += 1
        values = observation.model_dump(mode="python")
        values.update(
            {
                "observation_id": f"maximal-source-window-{window_index}",
                "source_sample_sha256s": tuple(sorted(digests)),
                "duplicate_count": 64 - len(observation.sample_sha256s),
                "conflicting_duplicate": True,
            }
        )
        return MonitoringWindowObservationV1.model_validate(values)

    initial = initial_health_evaluation_state(
        policy=anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
    )
    first_observation = maximal_sources(1)
    first_decision = evaluate_health_observation(
        policy=anchor.policy,
        prior_state=initial,
        observation=first_observation,
        evaluated_at=first_observation.observed_at,
    )
    first_proof = create_health_decision_proof(
        anchor=anchor,
        sequence=1,
        previous_signed_proof_sha256=None,
        prior_state=initial,
        observation=first_observation,
        decision=first_decision,
    )
    first_signed = make_signed_proof(first_proof, anchor, marker=b"maximal-first-proof")
    linked = derive_next_health_evaluation_state(
        policy=anchor.policy,
        predecessor_decision=first_decision,
    )
    second_observation = maximal_sources(2)
    second_decision = evaluate_health_observation(
        policy=anchor.policy,
        prior_state=linked,
        predecessor_decision=first_decision,
        observation=second_observation,
        evaluated_at=second_observation.observed_at,
    )
    second_proof = create_health_decision_proof(
        anchor=anchor,
        sequence=2,
        previous_signed_proof_sha256=canonical_sha256(first_signed),
        prior_state=linked,
        observation=second_observation,
        decision=second_decision,
    )
    request = create_health_attestation_signing_request(
        anchor=anchor,
        prior_signed_proof=first_signed,
        pending_proof=second_proof,
    )

    encoded = canonical_json_bytes(request)
    assert 35_000 < len(encoded) <= MAX_CONTRACT_BYTES


def test_twenty_proof_chain_uses_manifest_identity_without_aggregate_encoding() -> None:
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
    predecessor = None
    signed_proofs = []
    for window_index in range(1, anchor.policy.maximum_windows + 1):
        window_end_minute = 4 + window_index
        for observation_minute in (window_end_minute + 3, window_end_minute + 6):
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
                    marker=f"bounded-proof-{len(signed_proofs) + 1}".encode(),
                )
            )
            predecessor = decision
            if decision.next_evaluation_at is not None:
                state = derive_next_health_evaluation_state(
                    policy=anchor.policy,
                    predecessor_decision=decision,
                )

    proofs = tuple(signed_proofs)
    chain = create_signed_health_decision_chain(
        anchor=anchor,
        signed_proofs=proofs,
    )
    manifest_sha256 = signed_health_decision_chain_sha256(chain)

    assert len(chain.signed_proofs) == 2 * anchor.policy.maximum_windows == 20
    assert chain.chain_id == f"cghealthchain:{manifest_sha256}"
    assert manifest_sha256 == signed_health_decision_chain_sha256(chain)
    assert all(len(canonical_json_bytes(proof)) <= MAX_CONTRACT_BYTES for proof in proofs)


def test_component_manifest_hash_matches_chain_and_binds_every_component() -> None:
    chain = make_healthy_chain()
    promotion = chain.healthy_promotion_proof
    assert promotion is not None
    components = {
        "anchor_sha256": chain.anchor_sha256,
        "ordered_proof_chain_sha256": signed_health_proof_chain_sha256(
            chain.signed_proofs
        ),
        "chain_head_sha256": chain.chain_head_sha256,
        "healthy_promotion_proof_sha256": canonical_sha256(promotion),
    }

    expected = signed_health_decision_chain_sha256(chain)

    assert health_chain_manifest_sha256(**components) == expected
    for name in components:
        tampered = dict(components)
        tampered[name] = "f" * 64 if components[name] != "f" * 64 else "e" * 64
        assert health_chain_manifest_sha256(**tampered) != expected


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("anchor_sha256", "A" * 64),
        ("ordered_proof_chain_sha256", "0" * 63),
        ("chain_head_sha256", 7),
        ("healthy_promotion_proof_sha256", "not-a-digest"),
    ),
)
def test_component_manifest_hash_rejects_noncanonical_digests(
    field: str,
    value: object,
) -> None:
    chain = make_healthy_chain()
    promotion = chain.healthy_promotion_proof
    assert promotion is not None
    components: dict[str, object] = {
        "anchor_sha256": chain.anchor_sha256,
        "ordered_proof_chain_sha256": signed_health_proof_chain_sha256(
            chain.signed_proofs
        ),
        "chain_head_sha256": chain.chain_head_sha256,
        "healthy_promotion_proof_sha256": canonical_sha256(promotion),
    }
    components[field] = value

    with pytest.raises(ValueError, match="manifest"):
        health_chain_manifest_sha256(**components)  # type: ignore[arg-type]


def test_factories_reject_non_exact_contract_types() -> None:
    root, anchor = make_anchor()
    chain = make_healthy_chain()

    with pytest.raises(TypeError):
        create_post_apply_health_anchor(  # type: ignore[arg-type]
            root=root.model_dump(mode="python"),
            apply_receipt=anchor.apply_receipt,
        )
    with pytest.raises(TypeError):
        create_signed_health_decision_chain(  # type: ignore[arg-type]
            anchor=anchor,
            signed_proofs=list(chain.signed_proofs),
        )


def test_compact_proof_cannot_be_revalidated_after_field_substitution() -> None:
    promotion = make_healthy_chain().healthy_promotion_proof
    assert promotion is not None
    substituted = promotion.model_copy(update={"terminal_health_decision_sha256": "f" * 64})

    with pytest.raises(ValidationError, match="identifier"):
        HealthyPromotionProofV1.model_validate(substituted)


def test_anchor_cannot_be_revalidated_after_receipt_substitution() -> None:
    _, anchor = make_anchor()
    substituted_receipt = anchor.apply_receipt.model_copy(update={"observed_etag": "other-etag"})
    substituted = anchor.model_copy(update={"apply_receipt": substituted_receipt})

    with pytest.raises(ValidationError, match="receipt"):
        PostApplyHealthAnchorV1.model_validate(substituted)
