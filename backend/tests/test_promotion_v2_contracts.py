from __future__ import annotations

from typing import Any

import pytest
from health_execution_test_data import make_health_root, make_healthy_chain, make_signed_proof
from pydantic import ValidationError

from controlgraph_canary.application.health_evaluation import (
    derive_next_health_evaluation_state,
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
    encode_base64url,
)
from controlgraph_canary.contracts.health import (
    HealthDecisionV1,
    HealthSignal,
    MonitoringObservationCompleteness,
    MonitoringWindowObservationV1,
)
from controlgraph_canary.contracts.health_execution import (
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    create_health_decision_proof,
    create_signed_health_decision_chain,
    signed_health_decision_chain_sha256,
    signed_health_proof_chain_sha256,
)
from controlgraph_canary.contracts.models import (
    CAPABILITY_CLAIMS_V1,
    SIGNED_CAPABILITY_V1,
    CapabilityAction,
    CapabilityClaims,
    MutationIntent,
    SignedCapability,
    TaskRequest,
)
from controlgraph_canary.contracts.promotion_execution import (
    MAX_PROMOTION_TASK_CANONICAL_BYTES,
    PROMOTION_AUTHORIZATION_V1,
    PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V2,
    PROMOTION_COMMAND_V1,
    PROMOTION_COMMAND_V2,
    PROMOTION_DISPATCH_IDENTITY_V2,
    PROMOTION_DISPATCH_RECORD_V2,
    PROMOTION_DISPATCH_RESULT_V2,
    PROMOTION_INVOCATION_V2,
    PROMOTION_MUTATION_INTENT_V2,
    PROMOTION_TASK_REQUEST_V2,
    PromotionAuthorizationV1,
    PromotionCapabilityIssuanceCommandV2,
    PromotionCommandV1,
    PromotionCommandV2,
    PromotionDispatchIdentityKind,
    PromotionDispatchIdentityV2,
    PromotionDispatchRecordV2,
    PromotionDispatchResultV2,
    PromotionDispatchState,
    PromotionInvocationV2,
    PromotionMutationIntentV2,
    PromotionTaskRequestV2,
    create_promotion_authorization,
    create_verified_apply_receipt_locator,
    promotion_capability_id,
    promotion_command_sha256,
    promotion_command_v2_sha256,
    promotion_dispatch_v2_id,
)
from controlgraph_canary.contracts.root_creation import create_rollout_root_v3


def _missing_observation(
    observation: MonitoringWindowObservationV1,
) -> MonitoringWindowObservationV1:
    values = observation.model_dump(mode="python")
    values.update(
        samples=(),
        sample_sha256s=(),
        source_sample_sha256s=(),
        completeness=MonitoringObservationCompleteness.MISSING,
        missing_signals=tuple(HealthSignal),
        request_count=None,
        response_1xx_count=None,
        successful_request_count=None,
        response_3xx_count=None,
        response_4xx_count=None,
        server_error_count=None,
        latency_distribution=None,
    )
    return MonitoringWindowObservationV1.model_validate(values)


def _healthy_chain_after_retry(
    *,
    retry_recovers: bool,
):
    from health_execution_test_data import make_anchor, make_observation

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
    signed: list[SignedHealthDecisionProofV1] = []

    def append(observation: MonitoringWindowObservationV1) -> None:
        nonlocal predecessor, state
        decision = evaluate_health_observation(
            policy=anchor.policy,
            prior_state=state,
            predecessor_decision=predecessor,
            observation=observation,
            evaluated_at=observation.observed_at,
        )
        proof = create_health_decision_proof(
            anchor=anchor,
            sequence=len(signed) + 1,
            previous_signed_proof_sha256=(
                canonical_sha256(signed[-1]) if signed else None
            ),
            prior_state=state,
            observation=observation,
            decision=decision,
        )
        signed.append(
            make_signed_proof(
                proof,
                anchor,
                marker=f"retry-proof-{len(signed) + 1}".encode(),
            )
        )
        predecessor = decision
        if decision.next_evaluation_at is not None:
            state = derive_next_health_evaluation_state(
                policy=anchor.policy,
                predecessor_decision=decision,
            )

    append(_missing_observation(make_observation(anchor, window_index=1)))
    assert predecessor is not None and predecessor.next_evaluation_at is not None
    deadline = predecessor.next_evaluation_at
    deadline_observation = make_observation(
        anchor,
        window_index=1,
        observed_at=deadline,
    )
    append(deadline_observation if retry_recovers else _missing_observation(deadline_observation))
    assert predecessor is not None and predecessor.next_evaluation_at is not None
    append(
        make_observation(
            anchor,
            window_index=2,
            observed_at=predecessor.next_evaluation_at,
        )
    )
    if not retry_recovers:
        assert predecessor is not None and predecessor.next_evaluation_at is not None
        append(
            make_observation(
                anchor,
                window_index=3,
                observed_at=predecessor.next_evaluation_at,
            )
        )
    return create_signed_health_decision_chain(
        anchor=anchor,
        signed_proofs=tuple(signed),
    )


def _maximum_policy_chain(*, promotable: bool) -> SignedHealthDecisionChainV1:
    from health_execution_test_data import make_anchor, make_observation

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
    signed: list[SignedHealthDecisionProofV1] = []

    def append(observation: MonitoringWindowObservationV1) -> None:
        nonlocal predecessor, state
        decision = evaluate_health_observation(
            policy=anchor.policy,
            prior_state=state,
            predecessor_decision=predecessor,
            observation=observation,
            evaluated_at=observation.observed_at,
        )
        proof = create_health_decision_proof(
            anchor=anchor,
            sequence=len(signed) + 1,
            previous_signed_proof_sha256=(
                canonical_sha256(signed[-1]) if signed else None
            ),
            prior_state=state,
            observation=observation,
            decision=decision,
        )
        signed.append(
            make_signed_proof(
                proof,
                anchor,
                marker=f"maximum-proof-{len(signed) + 1}".encode(),
            )
        )
        predecessor = decision
        if decision.next_evaluation_at is not None:
            state = derive_next_health_evaluation_state(
                policy=anchor.policy,
                predecessor_decision=decision,
            )

    def observation(window_index: int) -> MonitoringWindowObservationV1:
        if predecessor is None:
            return make_observation(anchor, window_index=window_index)
        assert predecessor.next_evaluation_at is not None
        return make_observation(
            anchor,
            window_index=window_index,
            observed_at=predecessor.next_evaluation_at,
        )

    def exhaust_window(window_index: int) -> None:
        append(_missing_observation(observation(window_index)))
        append(_missing_observation(observation(window_index)))

    for window_index in range(1, 9):
        exhaust_window(window_index)
    if promotable:
        append(_missing_observation(observation(9)))
        append(observation(9))
        append(observation(10))
    else:
        exhaust_window(9)
        exhaust_window(10)
    return create_signed_health_decision_chain(
        anchor=anchor,
        signed_proofs=tuple(signed),
    )


def _authorization() -> PromotionAuthorizationV1:
    chain = make_healthy_chain()
    proof = chain.healthy_promotion_proof
    assert proof is not None
    return create_promotion_authorization(
        root=make_health_root(),
        signed_health_chain=chain,
        request_id="request-promote-health-001",
        idempotency_key="promote-health-001",
        scheduled_at=proof.issued_at,
    )


def _command(authorization: PromotionAuthorizationV1) -> PromotionCommandV2:
    return PromotionCommandV2(
        schema_version=PROMOTION_COMMAND_V2,
        root_id=authorization.root_id,
        expected_root_sha256=authorization.root_sha256,
        expected_epoch=authorization.epoch,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        scheduled_at=authorization.scheduled_at,
        verified_apply_receipt=authorization.verified_apply_receipt,
        health_chain_locator=authorization.health_chain_locator,
    )


def _capability(
    authorization: PromotionAuthorizationV1,
    *,
    expires_at: str | None = None,
    capability_id: str | None = None,
) -> SignedCapability:
    claims = CapabilityClaims(
        schema_version=CAPABILITY_CLAIMS_V1,
        capability_id=capability_id or promotion_capability_id(authorization),
        issuer=authorization.issuer_identity,
        subject=authorization.executor_identity,
        audience=authorization.executor_audience,
        target=authorization.target,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        concurrency=None,
        plan_sha256=authorization.plan_sha256,
        provider_etag=authorization.provider_etag,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        parent_capability_sha256=None,
        issued_at=authorization.healthy_promotion_proof.issued_at,
        not_before=authorization.scheduled_at,
        expires_at=expires_at or authorization.proof_valid_until,
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=authorization.capability_signing_key_version,
    )
    return SignedCapability(
        schema_version=SIGNED_CAPABILITY_V1,
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-promotion-capability"),
    )


def _intent(
    authorization: PromotionAuthorizationV1,
    capability: SignedCapability,
) -> PromotionMutationIntentV2:
    return PromotionMutationIntentV2(
        schema_version=PROMOTION_MUTATION_INTENT_V2,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        concurrency=None,
        plan_sha256=authorization.plan_sha256,
        provider_etag=authorization.provider_etag,
        capability_id=capability.claims.capability_id,
        promotion_authorization_sha256=canonical_sha256(authorization),
        expected_prestate_sha256=authorization.expected_prestate_sha256,
        terminal_health_decision_sha256=authorization.terminal_health_decision_sha256,
        health_chain_sha256=authorization.health_chain_locator.health_chain_sha256,
        desired_poststate_sha256=authorization.desired_poststate_sha256,
        proof_valid_until=authorization.proof_valid_until,
        authorization=authorization,
    )


def _task(
    authorization: PromotionAuthorizationV1,
    *,
    expires_at: str = "2026-08-21T12:10:00Z",
    capability_expires_at: str | None = None,
    capability_id: str | None = None,
) -> PromotionTaskRequestV2:
    capability = _capability(
        authorization,
        expires_at=capability_expires_at,
        capability_id=capability_id,
    )
    return PromotionTaskRequestV2(
        schema_version=PROMOTION_TASK_REQUEST_V2,
        task_id=f"task-{capability.claims_sha256}",
        queue_region="us-central1",
        handler_audience=capability.claims.audience,
        scheduled_at=authorization.scheduled_at,
        expires_at=expires_at,
        capability=capability,
        intent=_intent(authorization, capability),
    )


def _reidentified(
    authorization: PromotionAuthorizationV1,
    **updates: Any,
) -> PromotionAuthorizationV1:
    altered = authorization.model_copy(update=updates)
    return altered.model_copy(update={"capability_id": promotion_capability_id(altered)})


def test_authorization_is_canonical_and_binds_the_complete_healthy_chain() -> None:
    first = _authorization()
    second = _authorization()
    chain = make_healthy_chain()

    assert first == second
    assert first.schema_version == PROMOTION_AUTHORIZATION_V1
    assert first.capability_id == promotion_capability_id(first)
    assert first.capability_id.startswith("cgcap-")
    assert first.health_chain_locator.health_chain_sha256 == (
        signed_health_decision_chain_sha256(chain)
    )
    assert first.health_chain_locator.ordered_proof_chain_sha256 == (
        signed_health_proof_chain_sha256(chain.signed_proofs)
    )
    assert first.healthy_promotion_proof_sha256 == canonical_sha256(
        first.healthy_promotion_proof
    )
    encoded = canonical_json_bytes(first)
    assert len(encoded) <= MAX_CONTRACT_BYTES
    assert decode_contract(encoded, PromotionAuthorizationV1) == first

    changed_request = create_promotion_authorization(
        root=make_health_root(),
        signed_health_chain=chain,
        request_id="request-promote-health-002",
        idempotency_key=first.idempotency_key,
        scheduled_at=first.scheduled_at,
    )
    assert changed_request.capability_id != first.capability_id


def test_retry_chains_use_compact_authorizations_within_the_task_budget() -> None:
    retry_chain = _healthy_chain_after_retry(retry_recovers=True)
    retry_proof = retry_chain.healthy_promotion_proof
    assert retry_proof is not None
    authorization = create_promotion_authorization(
        root=make_health_root(),
        signed_health_chain=retry_chain,
        request_id="request-promote-after-retry",
        idempotency_key="promote-after-retry",
        scheduled_at=retry_proof.issued_at,
    )
    task = _task(
        authorization,
        expires_at="2026-08-21T12:11:30Z",
    )
    assert len(retry_chain.signed_proofs) == 3
    assert len(canonical_json_bytes(task)) <= MAX_PROMOTION_TASK_CANONICAL_BYTES

    extended_chain = _healthy_chain_after_retry(retry_recovers=False)
    extended_proof = extended_chain.healthy_promotion_proof
    assert extended_proof is not None
    extended = create_promotion_authorization(
        root=make_health_root(),
        signed_health_chain=extended_chain,
        request_id="request-extended-promotion",
        idempotency_key="extended-promotion",
        scheduled_at=extended_proof.issued_at,
    )
    assert len(extended_chain.signed_proofs) == 4
    assert len(canonical_json_bytes(extended)) < len(canonical_json_bytes(extended_chain))


def test_maximum_promotable_chain_is_compact_and_twentieth_proof_has_no_authority() -> None:
    maximum = _maximum_policy_chain(promotable=True)
    proof = maximum.healthy_promotion_proof
    assert proof is not None
    assert len(maximum.signed_proofs) == 19
    authorization = create_promotion_authorization(
        root=make_health_root(),
        signed_health_chain=maximum,
        request_id="request-maximum-promotion",
        idempotency_key="maximum-promotion",
        scheduled_at=proof.issued_at,
    )
    task = _task(
        authorization,
        expires_at="2026-08-21T12:19:30Z",
    )
    assert authorization.health_chain_locator.terminal_sequence == 19
    assert authorization.health_chain_locator.health_chain_sha256 == (
        signed_health_decision_chain_sha256(maximum)
    )
    assert len(canonical_json_bytes(task)) <= MAX_PROMOTION_TASK_CANONICAL_BYTES

    terminal_twentieth = _maximum_policy_chain(promotable=False)
    assert len(terminal_twentieth.signed_proofs) == 20
    assert terminal_twentieth.healthy_promotion_proof is None
    manifest_sha256 = signed_health_decision_chain_sha256(terminal_twentieth)
    assert terminal_twentieth.chain_id == f"cghealthchain:{manifest_sha256}"
    with pytest.raises(ValueError, match="terminal healthy proof"):
        create_promotion_authorization(
            root=make_health_root(),
            signed_health_chain=terminal_twentieth,
            request_id="request-twentieth-proof",
            idempotency_key="twentieth-proof",
            scheduled_at="2026-08-21T12:19:00Z",
        )


def test_authorization_rejects_swapped_or_tampered_authority_inputs() -> None:
    authorization = _authorization()
    chain = make_healthy_chain()
    alternate_terminal = make_signed_proof(
        chain.signed_proofs[-1].proof,
        chain.anchor,
        marker=b"alternate-terminal-health-proof",
    )
    alternate_chain = create_signed_health_decision_chain(
        anchor=chain.anchor,
        signed_proofs=(*chain.signed_proofs[:-1], alternate_terminal),
    )
    alternate_proof = alternate_chain.healthy_promotion_proof
    assert alternate_proof is not None

    other_receipt = chain.anchor.apply_receipt.model_copy(
        update={"request_id": "request-other-verified-apply"}
    )
    other_locator = create_verified_apply_receipt_locator(other_receipt)
    source_root = make_health_root()
    other_root = create_rollout_root_v3(
        source_root.content.model_copy(update={"approved_at": "2026-08-19T12:02:00Z"})
    )
    tampered_chain_locator = authorization.health_chain_locator.model_copy(
        update={"ordered_proof_chain_sha256": "e" * 64}
    )
    substituted_manifest_locator = authorization.health_chain_locator.model_copy(
        update={
            "chain_id": f"cghealthchain:{'d' * 64}",
            "health_chain_sha256": "d" * 64,
        }
    )

    altered_values = (
        {"healthy_promotion_proof": alternate_proof},
        {"verified_apply_receipt": other_locator},
        {"root_id": other_root.root_id, "root_sha256": other_root.root_sha256},
        {"epoch": authorization.epoch + 1},
        {"candidate_revision": "controlgraph-reference-target-candidate-v2"},
        {"desired_poststate_sha256": "f" * 64},
        {"health_chain_locator": tampered_chain_locator},
        {"health_chain_locator": substituted_manifest_locator},
    )
    for updates in altered_values:
        altered = _reidentified(authorization, **updates)
        with pytest.raises(ValidationError):
            PromotionAuthorizationV1.model_validate(altered.model_dump(mode="python"))


def test_authorization_rejects_noncanonical_identity_and_schedule() -> None:
    authorization = _authorization()
    with pytest.raises(ValidationError):
        PromotionAuthorizationV1.model_validate(
            {
                **authorization.model_dump(mode="python"),
                "capability_id": "cgcap-" + "0" * 64,
            }
        )
    for scheduled_at in (
        "2026-08-21T12:08:59Z",
        authorization.proof_valid_until,
    ):
        with pytest.raises(ValidationError):
            create_promotion_authorization(
                root=make_health_root(),
                signed_health_chain=make_healthy_chain(),
                request_id=authorization.request_id,
                idempotency_key=authorization.idempotency_key,
                scheduled_at=scheduled_at,
            )


def test_v2_command_task_and_dispatch_record_preserve_all_bindings() -> None:
    authorization = _authorization()
    command = _command(authorization)
    task = _task(authorization)
    command_sha256 = promotion_command_v2_sha256(command)
    task_sha256 = canonical_sha256(task)
    task_name = (
        f"projects/{authorization.target.project_id}/locations/us-central1/queues/"
        f"controlgraph-execution/tasks/cg-{task_sha256}"
    )
    authorization_sha256 = canonical_sha256(authorization)

    invocation = PromotionInvocationV2(
        schema_version=PROMOTION_INVOCATION_V2,
        command=command,
        operator_identity="operator@example.com",
        operator_subject="123456789012",
        operator_issuer="https://accounts.google.com",
        operator_audience="https://controlgraph-api-123456789012.us-central1.run.app",
        operator_issued_at=1_776_945_600,
        operator_expires_at=1_776_949_200,
    )
    issuance = PromotionCapabilityIssuanceCommandV2(
        schema_version=PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V2,
        root_id=command.root_id,
        expected_root_sha256=command.expected_root_sha256,
        expected_epoch=command.expected_epoch,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        scheduled_at=command.scheduled_at,
        verified_apply_receipt=command.verified_apply_receipt,
        authorization=authorization,
    )
    identity = PromotionDispatchIdentityV2(
        schema_version=PROMOTION_DISPATCH_IDENTITY_V2,
        identity_kind=PromotionDispatchIdentityKind.REQUEST,
        identity_value=authorization.request_id,
        dispatch_id=promotion_dispatch_v2_id(command_sha256),
        command_sha256=command_sha256,
        promotion_authorization_sha256=authorization_sha256,
        capability_id=authorization.capability_id,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        scheduled_at=authorization.scheduled_at,
        source_receipt_sha256=authorization.source_receipt_sha256,
        health_chain_sha256=authorization.health_chain_locator.health_chain_sha256,
        claimed_at=authorization.scheduled_at,
    )
    result = PromotionDispatchResultV2(
        schema_version=PROMOTION_DISPATCH_RESULT_V2,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        provider_etag=authorization.provider_etag,
        verified_apply_receipt=authorization.verified_apply_receipt,
        source_receipt_sha256=authorization.source_receipt_sha256,
        expected_prestate_sha256=authorization.expected_prestate_sha256,
        terminal_health_decision_sha256=authorization.terminal_health_decision_sha256,
        health_chain_sha256=authorization.health_chain_locator.health_chain_sha256,
        health_chain_locator=authorization.health_chain_locator,
        healthy_promotion_proof_sha256=authorization.healthy_promotion_proof_sha256,
        desired_poststate_sha256=authorization.desired_poststate_sha256,
        proof_valid_until=authorization.proof_valid_until,
        promotion_authorization_sha256=authorization_sha256,
        capability_id=authorization.capability_id,
        capability_sha256=canonical_sha256(task.capability),
        task_id=task.task_id,
        task_name=task_name,
        enqueue_disposition="CREATED",
        scheduled_at=task.scheduled_at,
        expires_at=task.expires_at,
    )
    record = PromotionDispatchRecordV2(
        schema_version=PROMOTION_DISPATCH_RECORD_V2,
        dispatch_id=identity.dispatch_id,
        command_sha256=command_sha256,
        promotion_authorization_sha256=authorization_sha256,
        capability_id=authorization.capability_id,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        scheduled_at=authorization.scheduled_at,
        source_receipt_sha256=authorization.source_receipt_sha256,
        health_chain_sha256=authorization.health_chain_locator.health_chain_sha256,
        task_sha256=task_sha256,
        task_name=task_name,
        task=task,
        state=PromotionDispatchState.CREATED,
        prepared_at=authorization.scheduled_at,
        enqueue_started_at="2026-08-21T12:09:01Z",
        terminal_at="2026-08-21T12:09:02Z",
        result=result,
    )

    for value in (command, invocation, issuance, task, identity, result, record):
        assert len(canonical_json_bytes(value)) <= MAX_CONTRACT_BYTES
    assert record.capability_id == promotion_capability_id(record.task.intent.authorization)


def test_v2_task_denies_capability_or_health_expiry_substitution() -> None:
    authorization = _authorization()
    with pytest.raises(ValidationError):
        _task(authorization, capability_id="cgcap-" + "f" * 64)
    with pytest.raises(ValidationError):
        _task(
            authorization,
            capability_expires_at="2026-08-21T12:12:01Z",
        )


def test_v1_and_v2_promotion_contracts_are_not_interchangeable() -> None:
    authorization = _authorization()
    v2 = _command(authorization)
    v1 = PromotionCommandV1(
        schema_version=PROMOTION_COMMAND_V1,
        root_id=authorization.root_id,
        expected_root_sha256=authorization.root_sha256,
        expected_epoch=authorization.epoch,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        scheduled_at=authorization.scheduled_at,
        verified_apply_receipt=authorization.verified_apply_receipt,
    )
    with pytest.raises(TypeError):
        promotion_command_sha256(v2)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        promotion_command_v2_sha256(v1)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        PromotionCommandV2.model_validate(v1.model_dump(mode="python"))
    with pytest.raises(ValidationError):
        PromotionCommandV1.model_validate(v2.model_dump(mode="python"))

    capability = _capability(authorization)
    claims = capability.claims
    legacy_intent = MutationIntent(
        schema_version="controlgraph.mutation-intent/v1",
        request_id=claims.request_id,
        idempotency_key=claims.idempotency_key,
        target=claims.target,
        root_id=claims.root_id,
        root_sha256=claims.root_sha256,
        epoch=claims.epoch,
        action=claims.action,
        stable_revision=claims.stable_revision,
        candidate_revision=claims.candidate_revision,
        stable_percent=claims.stable_percent,
        candidate_percent=claims.candidate_percent,
        concurrency=claims.concurrency,
        plan_sha256=claims.plan_sha256,
        provider_etag=claims.provider_etag,
    )
    legacy_task = TaskRequest(
        schema_version="controlgraph.task-request/v1",
        task_id=f"task-{capability.claims_sha256}",
        queue_region="us-central1",
        handler_audience=claims.audience,
        scheduled_at=claims.not_before,
        expires_at="2026-08-21T12:10:00Z",
        capability=capability,
        intent=legacy_intent,
    )
    with pytest.raises(ValidationError):
        PromotionTaskRequestV2.model_validate(legacy_task.model_dump(mode="python"))
