import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from controlgraph_canary.authority import (
    DenialReason,
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    ProviderAttemptResult,
    ReceiptPhase,
    ReplayAction,
    ReplayReceipt,
    ReplayReceiptOutcome,
    TransportAction,
    TransportFailure,
    claim_receipt,
    close_unresolved_ambiguity,
    decide_replay,
    decide_transport_failure,
    deny_before_dispatch,
    mutation_identity,
    receipt_claim_identity,
    record_provider_result,
    record_readback,
)
from controlgraph_canary.contracts import TaskRequest, canonical_sha256, decode_contract

FIXTURE_ROOT = Path(__file__).parents[2] / "contract-fixtures" / "v1"
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
THREE_DIGEST = "3" * 64
FOUR_DIGEST = "4" * 64


def binding() -> MutationBinding:
    return MutationBinding(
        idempotency_key="intent-001",
        request_id="request-001",
        root_id="root-001",
        root_sha256=(
            "0e818e3c0435c2743ad7954ae0bcdd6925bb9d1bcd950d745300cafab0ecf0aa"
        ),
        epoch=7,
        action=MutationAction.APPLY_CANARY,
        target=MutationTargetKey(
            project_id="demo-project-123",
            region="us-central1",
            environment="acceptance",
            service_name="canary-target",
        ),
        provider_precondition="etag-stable-7",
        plan_sha256=TWO_DIGEST,
        capability_sha256=(
            "2eed196f05ef954e93eaa31313b68a44930fb95aeefb60af95543d0a8d4c04c3"
        ),
        payload_sha256=(
            "0035f0477ba773bd57db97ff279dd4917ba6bcb4e51de3b71d6901eb6f815f25"
        ),
        expected_poststate_sha256=THREE_DIGEST,
    )


def changed_bindings(value: MutationBinding) -> tuple[MutationBinding, ...]:
    return (
        replace(value, idempotency_key="intent-002"),
        replace(value, request_id="request-002"),
        replace(value, root_id="root-002"),
        replace(value, root_sha256=ZERO_DIGEST),
        replace(value, epoch=8),
        replace(value, action=MutationAction.PROMOTE_CANDIDATE),
        replace(value, target=replace(value.target, project_id="other-project-123")),
        replace(value, target=replace(value.target, region="europe-west1")),
        replace(value, target=replace(value.target, environment="staging")),
        replace(value, target=replace(value.target, service_name="other-target")),
        replace(value, provider_precondition="etag-stable-8"),
        replace(value, plan_sha256=ONE_DIGEST),
        replace(value, capability_sha256=ZERO_DIGEST),
        replace(value, payload_sha256=FOUR_DIGEST),
        replace(value, expected_poststate_sha256=FOUR_DIGEST),
    )


def fixture_binding() -> MutationBinding:
    fixture = json.loads((FIXTURE_ROOT / "golden.json").read_text(encoding="utf-8"))
    vector = next(item for item in fixture["vectors"] if item["model"] == "TaskRequest")
    task = decode_contract(vector["canonical"], TaskRequest)
    intent = task.intent
    return MutationBinding(
        idempotency_key=intent.idempotency_key,
        request_id=intent.request_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=MutationAction(intent.action.value),
        target=MutationTargetKey(
            project_id=intent.target.project_id,
            region=intent.target.region,
            environment=intent.target.environment,
            service_name=intent.target.service_name,
        ),
        provider_precondition=intent.provider_etag,
        plan_sha256=intent.plan_sha256,
        capability_sha256=canonical_sha256(task.capability),
        payload_sha256=canonical_sha256(task),
        expected_poststate_sha256=THREE_DIGEST,
    )


def test_mutation_identity_is_stable_for_the_canonical_intent_fixture() -> None:
    value = fixture_binding()

    assert value == binding()
    assert mutation_identity(value) == mutation_identity(value)
    assert mutation_identity(value) == (
        "7896ab8877fa405bca7e325b31a17145112e94d21124c654227db88ac37c4bbe"
    )


def test_mutation_identity_changes_for_every_bound_field() -> None:
    value = binding()
    identities = {mutation_identity(value)}

    for changed in changed_bindings(value):
        identities.add(mutation_identity(changed))

    assert len(identities) == len(changed_bindings(value)) + 1


def test_receipt_claim_identity_is_stable_only_for_one_target_key() -> None:
    value = binding()
    expected = receipt_claim_identity(value.target, value.idempotency_key)

    assert claim_receipt(value).receipt_id == expected
    for changed in changed_bindings(value):
        actual = claim_receipt(changed).receipt_id
        if changed.idempotency_key != value.idempotency_key or changed.target != value.target:
            assert actual != expected
        else:
            assert actual == expected


@pytest.mark.parametrize(
    "change",
    [
        lambda value: replace(value, epoch=0),
        lambda value: replace(value, plan_sha256="A" * 64),
        lambda value: replace(value, capability_sha256="short"),
        lambda value: replace(value, payload_sha256="short"),
        lambda value: replace(value, expected_poststate_sha256="short"),
        lambda value: replace(value, provider_precondition=" "),
    ],
)
def test_invalid_identity_inputs_fail_closed(
    change: Callable[[MutationBinding], MutationBinding],
) -> None:
    with pytest.raises(ValueError):
        change(binding())


def test_new_claim_and_exact_duplicate_have_nonresumable_decisions() -> None:
    value = binding()
    claimed = decide_replay(value, None)

    assert claimed.action is ReplayAction.CLAIM_NEW
    assert claimed.receipt == claim_receipt(value)
    assert claimed.requires_readback is False

    duplicate = decide_replay(value, claimed.receipt)

    assert duplicate.action is ReplayAction.RETURN_IN_PROGRESS
    assert duplicate.receipt is claimed.receipt
    assert duplicate.reason is DenialReason.RECEIPT_IN_PROGRESS


def test_reuse_with_any_changed_binding_is_denied_as_a_conflict() -> None:
    stored = claim_receipt(binding())

    for changed in changed_bindings(binding()):
        decision = decide_replay(changed, stored)

        assert decision.action is ReplayAction.DENY_CONFLICT
        assert decision.receipt is stored
        assert decision.reason is DenialReason.IDEMPOTENCY_CONFLICT
        assert decision.requires_readback is False


def terminal_receipts() -> tuple[ReplayReceipt, ...]:
    denied = deny_before_dispatch(
        claim_receipt(binding()),
        DenialReason.EPOCH_MISMATCH,
    )
    failed_safe = record_provider_result(
        claim_receipt(binding()),
        ProviderAttemptResult.PRECONDITION_REJECTED,
    )
    applied = record_provider_result(
        claim_receipt(binding()),
        ProviderAttemptResult.ACCEPTED,
    )
    verified = record_readback(
        applied,
        observed_poststate_sha256=THREE_DIGEST,
    )
    ambiguous = record_readback(
        record_provider_result(
            claim_receipt(binding()),
            ProviderAttemptResult.UNKNOWN,
        ),
        observed_poststate_sha256=ONE_DIGEST,
    )
    unresolved = close_unresolved_ambiguity(ambiguous)
    return denied, failed_safe, verified, unresolved


def test_exact_terminal_duplicate_returns_the_stored_result() -> None:
    for stored in terminal_receipts():
        decision = decide_replay(binding(), stored)

        assert decision.action is ReplayAction.RETURN_STORED
        assert decision.receipt is stored
        assert stored.terminal is True
        assert decision.requires_readback is False


def test_claimed_duplicate_is_in_progress_and_never_requires_readback() -> None:
    claimed = claim_receipt(binding())

    assert claimed.phase is ReceiptPhase.CLAIMED
    assert claimed.outcome is ReplayReceiptOutcome.CLAIMED
    assert claimed.awaits_readback is False
    duplicate = decide_replay(binding(), claimed)
    assert duplicate.action is ReplayAction.RETURN_IN_PROGRESS
    assert duplicate.reason is DenialReason.RECEIPT_IN_PROGRESS
    assert duplicate.requires_readback is False


def test_known_pre_dispatch_denial_is_terminal_without_provider_uncertainty() -> None:
    denied = deny_before_dispatch(
        claim_receipt(binding()),
        DenialReason.EPOCH_MISMATCH,
    )

    assert denied.phase is ReceiptPhase.TERMINAL
    assert denied.outcome is ReplayReceiptOutcome.DENIED
    assert denied.reason is DenialReason.EPOCH_MISMATCH
    assert denied.awaits_readback is False


def test_known_provider_precondition_rejection_is_failed_safe() -> None:
    result = record_provider_result(
        claim_receipt(binding()),
        ProviderAttemptResult.PRECONDITION_REJECTED,
    )

    assert result.phase is ReceiptPhase.TERMINAL
    assert result.outcome is ReplayReceiptOutcome.FAILED_SAFE
    assert result.reason is DenialReason.PROVIDER_PRECONDITION_FAILED
    assert result.awaits_readback is False


def test_known_provider_request_rejection_is_failed_safe_without_raw_detail() -> None:
    result = record_provider_result(
        claim_receipt(binding()),
        ProviderAttemptResult.REQUEST_REJECTED,
    )

    assert result.phase is ReceiptPhase.TERMINAL
    assert result.outcome is ReplayReceiptOutcome.FAILED_SAFE
    assert result.reason is DenialReason.PROVIDER_REQUEST_REJECTED
    assert result.result_sha256 is None
    assert result.awaits_readback is False


def test_accepted_provider_result_still_requires_exact_readback() -> None:
    result = record_provider_result(
        claim_receipt(binding()),
        ProviderAttemptResult.ACCEPTED,
    )

    assert result.phase is ReceiptPhase.READBACK_REQUIRED
    assert result.outcome is ReplayReceiptOutcome.APPLIED
    assert result.reason is None
    assert result.awaits_readback is True
    assert decide_replay(binding(), result).action is ReplayAction.REQUIRE_READBACK


@pytest.mark.parametrize(
    "result",
    [
        ProviderAttemptResult.TIMEOUT,
        ProviderAttemptResult.CONNECTION_LOST,
        ProviderAttemptResult.MALFORMED_RESPONSE,
        ProviderAttemptResult.UNKNOWN,
    ],
)
def test_uncertain_provider_results_require_readback_and_never_resume(
    result: ProviderAttemptResult,
) -> None:
    uncertain = record_provider_result(claim_receipt(binding()), result)

    assert uncertain.phase is ReceiptPhase.READBACK_REQUIRED
    assert uncertain.outcome is ReplayReceiptOutcome.AMBIGUOUS
    assert uncertain.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
    assert uncertain.awaits_readback is True

    replay = decide_replay(binding(), uncertain)
    assert replay.action is ReplayAction.REQUIRE_READBACK
    with pytest.raises(ValueError):
        record_provider_result(uncertain, ProviderAttemptResult.ACCEPTED)


@pytest.mark.parametrize("observed", [ONE_DIGEST, None])
def test_only_exact_readback_adopts_verified_success(observed: str | None) -> None:
    uncertain = record_provider_result(
        claim_receipt(binding()),
        ProviderAttemptResult.TIMEOUT,
    )

    unresolved = record_readback(
        uncertain,
        observed_poststate_sha256=observed,
    )

    assert unresolved.phase is ReceiptPhase.READBACK_REQUIRED
    assert unresolved.outcome is ReplayReceiptOutcome.AMBIGUOUS
    assert unresolved.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
    assert unresolved.result_sha256 == observed
    assert unresolved.readback_attempted is True
    assert decide_replay(binding(), unresolved).action is ReplayAction.REQUIRE_READBACK

    closed = close_unresolved_ambiguity(unresolved)
    assert closed.phase is ReceiptPhase.TERMINAL
    assert closed.outcome is ReplayReceiptOutcome.AMBIGUOUS
    assert closed.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS


def test_exact_readback_can_resolve_an_unknown_provider_response() -> None:
    uncertain = record_provider_result(
        claim_receipt(binding()),
        ProviderAttemptResult.UNKNOWN,
    )

    verified = record_readback(
        uncertain,
        observed_poststate_sha256=THREE_DIGEST,
    )

    assert verified.phase is ReceiptPhase.TERMINAL
    assert verified.outcome is ReplayReceiptOutcome.VERIFIED
    assert verified.reason is None
    assert verified.result_sha256 == THREE_DIGEST
    assert verified.readback_attempted is True


def test_unresolved_ambiguity_cannot_close_before_readback() -> None:
    uncertain = record_provider_result(
        claim_receipt(binding()),
        ProviderAttemptResult.TIMEOUT,
    )

    with pytest.raises(ValueError):
        close_unresolved_ambiguity(uncertain)


@pytest.mark.parametrize(
    "failure",
    [
        TransportFailure.DISPATCH_STARTED,
        TransportFailure.TIMEOUT,
        TransportFailure.RESPONSE_LOST,
        TransportFailure.MALFORMED_RESPONSE,
        TransportFailure.UNKNOWN,
    ],
)
def test_transport_uncertainty_never_permits_mutation_retry(
    failure: TransportFailure,
) -> None:
    decision = decide_transport_failure(
        failure,
        attempt_number=1,
        maximum_attempts=3,
    )

    assert decision.action is TransportAction.REQUIRE_READBACK
    assert decision.retry_permitted is False
    assert decision.requires_readback is True
    assert decision.reason is DenialReason.PROVIDER_OUTCOME_AMBIGUOUS


def test_transport_retry_is_bounded_and_only_before_dispatch() -> None:
    first = decide_transport_failure(
        TransportFailure.BEFORE_DISPATCH,
        attempt_number=1,
        maximum_attempts=3,
    )
    second = decide_transport_failure(
        TransportFailure.BEFORE_DISPATCH,
        attempt_number=2,
        maximum_attempts=3,
    )
    final = decide_transport_failure(
        TransportFailure.BEFORE_DISPATCH,
        attempt_number=3,
        maximum_attempts=3,
    )

    assert first.action is TransportAction.RETRY_BEFORE_DISPATCH
    assert second.action is TransportAction.RETRY_BEFORE_DISPATCH
    assert first.retry_permitted is True
    assert second.retry_permitted is True
    assert final.action is TransportAction.STOP_BEFORE_DISPATCH
    assert final.retry_permitted is False
    assert final.requires_readback is False
    assert final.reason is DenialReason.TRANSPORT_UNAVAILABLE


def test_durable_claim_never_turns_a_later_delivery_into_dispatch_authority() -> None:
    claimed = claim_receipt(binding())

    for _ in range(3):
        replay = decide_replay(binding(), claimed)
        assert replay.action is ReplayAction.RETURN_IN_PROGRESS
        assert replay.reason is DenialReason.RECEIPT_IN_PROGRESS


@pytest.mark.parametrize(
    ("attempt_number", "maximum_attempts"),
    [(0, 1), (2, 1), (1, 0), (1, 4), (True, 1)],
)
def test_invalid_transport_bounds_fail_closed(
    attempt_number: int,
    maximum_attempts: int,
) -> None:
    with pytest.raises(ValueError):
        decide_transport_failure(
            TransportFailure.BEFORE_DISPATCH,
            attempt_number=attempt_number,
            maximum_attempts=maximum_attempts,
        )


def test_invalid_terminal_or_ambiguous_receipt_shapes_fail_closed() -> None:
    with pytest.raises(ValueError):
        ReplayReceipt(
            binding=binding(),
            phase=ReceiptPhase.TERMINAL,
            outcome=ReplayReceiptOutcome.VERIFIED,
            result_sha256=ZERO_DIGEST,
            readback_attempted=False,
        )

    with pytest.raises(ValueError):
        ReplayReceipt(
            binding=binding(),
            phase=ReceiptPhase.TERMINAL,
            outcome=ReplayReceiptOutcome.AMBIGUOUS,
            reason=DenialReason.PROVIDER_OUTCOME_AMBIGUOUS,
            readback_attempted=False,
        )
