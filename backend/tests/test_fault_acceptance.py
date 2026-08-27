from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from controlgraph_canary.contracts.health import (
    HealthDecisionStatus,
    HealthReasonCode,
    MonitoringObservationCompleteness,
)
from controlgraph_canary.contracts.health_execution import SignedHealthDecisionProofV1
from controlgraph_canary.contracts.health_pipeline import (
    HealthEvaluationResultV2,
)
from controlgraph_canary.contracts.independent_verification import (
    CompletionClassificationV1,
    CompletionEvidenceBundleV1,
    CompletionReason,
    CompletionStatus,
    ConfigurationAttestationStatus,
    IndependentVerificationKind,
    IndependentVerificationVerdict,
    ProbeAttestationReason,
    ProbeAttestationStatus,
    VerifiedIndependentVerificationEvidenceV1,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.operator_observability import (
    ExecutionReceiptReadResultV1,
    TargetTrafficReadResultV1,
)
from controlgraph_canary.contracts.promotion_execution import PromotionCommandV2
from controlgraph_canary.contracts.recovery_execution import RecoveryIntentV1
from controlgraph_canary.contracts.revocation import EpochRevocationProofV1

SCRIPT = Path(__file__).parents[2] / "scripts" / "fault_acceptance.py"
sys.path.insert(0, str(SCRIPT.parent))
MODULE_SPEC = importlib.util.spec_from_file_location("fault_acceptance_test", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
FAULTS = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = FAULTS
MODULE_SPEC.loader.exec_module(FAULTS)

PROJECT = "controlgraph-canary-abc123"
STABLE = "controlgraph-reference-target-stable"
CANDIDATE = "controlgraph-reference-target-candidate"
IDENTITY = "acceptance@example.invalid"
TARGET = TargetBinding(
    schema_version="controlgraph.target-binding/v1",
    project_id=PROJECT,
    region="us-central1",
    environment="nonprod",
    service_name="controlgraph-reference-target",
)
CORE_INPUTS_SHA256 = "c" * 64
CORE_MANIFEST_SHA256 = "d" * 64
FAULT_INPUTS_SHA256 = FAULTS.hashlib.sha256(
    FAULTS._FAULT_INPUT_DOMAIN
    + bytes.fromhex(CORE_INPUTS_SHA256)
    + bytes.fromhex(CORE_MANIFEST_SHA256)
).hexdigest()


def _context(kind: Any) -> Any:
    scenario = FAULTS._scenario(17, kind)
    if kind is FAULTS.FaultKind.REVOCATION_RACE:
        scenario = FAULTS._race_scenario(scenario, 1)
    return FAULTS._Context(
        target=TARGET,
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
        acceptance_identity=IDENTITY,
        scenario=scenario,
    )


def _read(
    split: tuple[int, int],
    at: str,
    *,
    target_sha256: str,
) -> TargetTrafficReadResultV1:
    traffic = tuple(
        SimpleNamespace(revision=revision, percent=percent)
        for revision, percent in zip((STABLE, CANDIDATE), split, strict=True)
        if percent
    )
    return TargetTrafficReadResultV1.model_construct(
        request=SimpleNamespace(
            target=TARGET,
            stable_revision=STABLE,
            candidate_revision=CANDIDATE,
        ),
        traffic=traffic,
        traffic_statuses=traffic,
        concurrency=80,
        stable_revision_configuration_sha256="a" * 64,
        candidate_revision_configuration_sha256="b" * 64,
        target_configuration_sha256=target_sha256,
        service_generation=2,
        provider_etag="provider-etag",
        observed_at=at,
    )


def _artifact(value: object, name: str, payload: bytes = b"{}") -> Any:
    return FAULTS._LoadedArtifact(name=name, payload=payload, value=value)


def _target_artifacts(*items: tuple[str, TargetTrafficReadResultV1]) -> dict[str, Any]:
    return {name: _artifact(value, name) for name, value in items}


def _queue(action: str, state: str) -> dict[str, object]:
    return {
        "action": action,
        "location": "us-central1",
        "project_id": PROJECT,
        "queue_id": "controlgraph-execution",
        "state": state,
    }


def _stale_artifacts(kind: Any, *, race: bool) -> dict[str, Any]:
    ctx = _context(kind)
    proof_time = "2026-08-24T00:02:00Z"
    receipt_created = "2026-08-24T00:01:00Z" if race else "2026-08-24T00:03:00Z"
    proof = EpochRevocationProofV1.model_construct(
        authority=SimpleNamespace(current_epoch=2),
        result=SimpleNamespace(
            committed_at=proof_time,
            previous_epoch=1,
            new_epoch=2,
            target=TARGET,
            operator_identity=IDENTITY,
            request_id=ctx.scenario.request_id("revoke"),
            root_id=f"cgroot:{kind.value.lower()}",
            root_sha256=kind.value.lower().ljust(64, "0")[:64],
        ),
    )
    receipt = SimpleNamespace(
        created_at=receipt_created,
        updated_at="2026-08-24T00:03:00Z",
        target=TARGET,
        root_id=proof.result.root_id,
        root_sha256=proof.result.root_sha256,
        epoch=1,
        request_id=ctx.scenario.request_id("promotion"),
        idempotency_key=ctx.scenario.idempotency_key("promotion"),
        action=CapabilityAction.PROMOTE_CANDIDATE,
        outcome=ReceiptOutcome.DENIED,
        reason_code=ReasonCode.EPOCH_MISMATCH,
        observed_authority_epoch=2,
    )
    artifacts = _target_artifacts(
        ("before-target.json", _read((90, 10), "2026-08-24T00:00:00Z", target_sha256="c" * 64)),
        ("denied-target.json", _read((90, 10), "2026-08-24T00:04:00Z", target_sha256="c" * 64)),
        ("after-target.json", _read((100, 0), "2026-08-24T00:05:00Z", target_sha256="d" * 64)),
    )
    artifacts.update(
        {
            "revocation-proof.json": _artifact(proof, "revocation-proof.json"),
            "stale-receipt.json": _artifact(
                ExecutionReceiptReadResultV1.model_construct(receipt=receipt),
                "stale-receipt.json",
            ),
            "queue-held.json": _artifact(_queue("hold", "PAUSED"), "queue-held.json"),
            "queue-released.json": _artifact(
                _queue("release", "RUNNING"), "queue-released.json"
            ),
        }
    )
    if race:
        artifacts["race-attempt.json"] = _artifact(
            {
                "attempt": 1,
                "maximum_attempts": 3,
                "scenario_id": ctx.scenario.scenario_id,
                "schema_version": "controlgraph.revocation-race-attempt/v1",
            },
            "race-attempt.json",
        )
    return artifacts


def test_surface_is_exactly_seven_seeded_cases_without_self_attestation_inputs() -> None:
    assert tuple(FAULTS.FaultKind) == (
        FAULTS.FaultKind.DELAYED_TASK,
        FAULTS.FaultKind.DUPLICATE_DELIVERY,
        FAULTS.FaultKind.REVOCATION_RACE,
        FAULTS.FaultKind.MONITORING_GAP,
        FAULTS.FaultKind.API_TIMEOUT,
        FAULTS.FaultKind.CONFIGURATION_DRIFT,
        FAULTS.FaultKind.PROBE_FAILURE,
    )
    assert set(FAULTS._TYPED_LAYOUT) == set(FAULTS.FaultKind)
    parser_destinations = {action.dest for action in FAULTS._parser()._actions}
    assert "observed_invariants" not in parser_destinations
    assert "observation_sha256" not in parser_destinations
    assert "fault" not in parser_destinations
    assert FAULTS._scenario(17, FAULTS.FaultKind.DELAYED_TASK) == FAULTS._scenario(
        17, FAULTS.FaultKind.DELAYED_TASK
    )

    with pytest.raises(FAULTS.FaultAcceptanceError, match="FAULT_RUN_BINDING_INVALID"):
        FAULTS.bind_fault_suite(
            evidence_root=Path("unused"),
            run_seed=17,
            project_id=PROJECT,
            stable_revision=STABLE,
            candidate_revision=CANDIDATE,
            acceptance_identity=IDENTITY,
            active_identity="different@example.invalid",
            source_commit="a" * 40,
            core_run_id=f"cgacceptance:{'b' * 64}",
            core_run_inputs_sha256=CORE_INPUTS_SHA256,
            core_manifest_sha256=CORE_MANIFEST_SHA256,
            fault_run_inputs_sha256=FAULT_INPUTS_SHA256,
        )


def test_fault_promotion_uses_five_second_schedule_lead(monkeypatch: Any) -> None:
    fixed_now = FAULTS.datetime(2026, 8, 27, 12, 0, tzinfo=FAULTS.UTC)

    class _FixedDateTime(FAULTS.datetime):
        @classmethod
        def now(cls, tz: object = None) -> Any:
            assert tz is FAULTS.UTC
            return fixed_now

    monkeypatch.setattr(FAULTS, "datetime", _FixedDateTime)
    monkeypatch.setattr(
        FAULTS,
        "PromotionCommandV2",
        lambda **values: SimpleNamespace(**values),
    )
    command = FAULTS._build_promotion_command(
        SimpleNamespace(run=SimpleNamespace(run_inputs_sha256="a" * 64)),
        SimpleNamespace(case_id="fault-api-timeout"),
        root_result=SimpleNamespace(
            root=SimpleNamespace(root_id=f"cgroot:{'b' * 64}", root_sha256="b" * 64)
        ),
        apply_receipt=SimpleNamespace(verified_apply_receipt=SimpleNamespace()),
        health=SimpleNamespace(promotion_health_chain=SimpleNamespace()),
    )

    assert command.scheduled_at == "2026-08-27T12:00:05Z"


def test_stale_cases_require_real_denial_and_safe_queue_release() -> None:
    for kind, race in (
        (FAULTS.FaultKind.DELAYED_TASK, False),
        (FAULTS.FaultKind.REVOCATION_RACE, True),
    ):
        result = FAULTS._evaluate(_context(kind), _stale_artifacts(kind, race=race))
        assert result.invariants == (FAULTS.SafetyInvariant.STALE_DENIAL,)

    broken = _stale_artifacts(FAULTS.FaultKind.DELAYED_TASK, race=False)
    broken["queue-released.json"] = _artifact(
        _queue("release", "PAUSED"), "queue-released.json"
    )
    with pytest.raises(FAULTS.FaultAcceptanceError, match="FAULT_QUEUE_EVIDENCE_INVALID"):
        FAULTS._evaluate(_context(FAULTS.FaultKind.DELAYED_TASK), broken)


def test_duplicate_delivery_derives_one_root_unique_recovery_intent() -> None:
    ctx = _context(FAULTS.FaultKind.DUPLICATE_DELIVERY)
    dispatch = SimpleNamespace(
        enqueue_disposition="CREATED",
        root_id="cgroot:duplicate",
        root_sha256="1" * 64,
        epoch=1,
        request_id="recovery-request",
        idempotency_key="recovery-idempotency",
        source_receipt_sha256="2" * 64,
        trigger_proof_sha256="3" * 64,
        task_id="recovery-task",
        scheduled_at="2026-08-24T00:00:30Z",
    )
    first = HealthEvaluationResultV2.model_construct(
        request_id=ctx.scenario.request_id("health-2"),
        idempotency_key=ctx.scenario.idempotency_key("health-2"),
        target=TARGET,
        root_id=dispatch.root_id,
        terminal_status=HealthDecisionStatus.UNHEALTHY,
        recovery_dispatch=dispatch,
    )
    intent = RecoveryIntentV1.model_construct(
        intent_id="cgrecoveryintent:root-unique",
        root_id=dispatch.root_id,
        root_sha256=dispatch.root_sha256,
        epoch=dispatch.epoch,
        request_id=dispatch.request_id,
        idempotency_key=dispatch.idempotency_key,
        source_receipt_sha256=dispatch.source_receipt_sha256,
        trigger_proof_sha256=dispatch.trigger_proof_sha256,
    )
    artifacts = _target_artifacts(
        ("after-target.json", _read((100, 0), "2026-08-24T00:01:00Z", target_sha256="b" * 64)),
    )
    artifacts.update(
        {
            "first-health-result.json": _artifact(first, "first-health-result.json", b"first"),
            "duplicate-health-result.json": _artifact(
                first.model_copy(), "duplicate-health-result.json", b"first"
            ),
            "recovery-intent.json": _artifact(intent, "recovery-intent.json"),
            "recovery-intent-query.json": _artifact(
                {
                    "fixed_head_entry_sha256": "4" * 64,
                    "fixed_head_sequence": 1,
                    "matched_count": 1,
                    "matched_entry_ids": ["timeline-entry"],
                    "matched_record_sha256s": [
                        FAULTS.hashlib.sha256(b"{}").hexdigest()
                    ],
                    "root_id": intent.root_id,
                    "scanned_entry_count": 1,
                    "schema_version": "controlgraph.recovery-intent-query/v1",
                },
                "recovery-intent-query.json",
            ),
        }
    )

    result = FAULTS._evaluate(ctx, artifacts)

    assert result.invariants == (FAULTS.SafetyInvariant.ONE_RECOVERY_INTENT,)
    assert result.observation["intent_id"] == intent.intent_id


def test_monitoring_gap_derives_insufficient_evidence(monkeypatch: Any) -> None:
    ctx = _context(FAULTS.FaultKind.MONITORING_GAP)
    monkeypatch.setattr(FAULTS, "canonical_sha256", lambda _value: "4" * 64)
    observation = SimpleNamespace(
        completeness=MonitoringObservationCompleteness.MISSING,
        missing_signals=(SimpleNamespace(value="REQUEST_COUNT"),),
    )
    decision = SimpleNamespace(
        status=HealthDecisionStatus.INSUFFICIENT_EVIDENCE,
        reason_codes=(HealthReasonCode.SAMPLE_MISSING,),
    )
    decision.target = TARGET
    decision.root_id = "cgroot:monitoring"
    decision.root_sha256 = "5" * 64
    decision.epoch = 1
    signed = SignedHealthDecisionProofV1.model_construct(
        proof=SimpleNamespace(
            observation=observation,
            decision=decision,
            produced_at="2026-08-24T00:00:30Z",
        )
    )
    health = HealthEvaluationResultV2.model_construct(
        request_id=ctx.scenario.request_id("health-1"),
        idempotency_key=ctx.scenario.idempotency_key("health-1"),
        target=TARGET,
        root_id=decision.root_id,
        root_sha256=decision.root_sha256,
        epoch=1,
        terminal_status=HealthDecisionStatus.INSUFFICIENT_EVIDENCE,
        terminal_health_decision_sha256="4" * 64,
        chain_head_sha256="4" * 64,
    )
    baseline = _read((90, 10), "2026-08-24T00:00:00Z", target_sha256="7" * 64)
    after = _read((90, 10), "2026-08-24T00:01:00Z", target_sha256="7" * 64)
    artifacts = _target_artifacts(
        ("before-target.json", baseline), ("after-target.json", after)
    )
    artifacts.update(
        {
            "health-result.json": _artifact(health, "health-result.json"),
            "signed-health-proof.json": _artifact(
                signed, "signed-health-proof.json"
            ),
        }
    )

    result = FAULTS._evaluate(ctx, artifacts)

    assert result.invariants == (FAULTS.SafetyInvariant.DETERMINISTIC_HEALTH,)
    assert result.observation["decision"] == "insufficient-evidence"


def test_api_timeout_derives_ambiguity_and_readback_only_follow_up(monkeypatch: Any) -> None:
    ctx = _context(FAULTS.FaultKind.API_TIMEOUT)
    monkeypatch.setattr(FAULTS, "canonical_sha256", lambda _value: "8" * 64)
    command = PromotionCommandV2.model_construct(
        request_id=ctx.scenario.request_id("promotion"),
        idempotency_key=ctx.scenario.idempotency_key("promotion"),
    )
    receipt = SimpleNamespace(
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        target=TARGET,
        action=CapabilityAction.PROMOTE_CANDIDATE,
        outcome=ReceiptOutcome.VERIFIED,
        reason_code=None,
        root_id="cgroot:timeout",
        root_sha256="9" * 64,
        epoch=1,
        updated_at="2026-08-24T00:00:30Z",
    )
    observed = ExecutionReceiptReadResultV1.model_construct(
        receipt=receipt, receipt_sha256="a" * 64
    )
    verification = SimpleNamespace(
        target=TARGET,
        root_id=receipt.root_id,
        root_sha256=receipt.root_sha256,
        epoch=1,
        request_id=receipt.request_id,
        action=receipt.action,
    )
    request = SimpleNamespace(verification=verification)
    bundle = CompletionEvidenceBundleV1.model_construct(request=request, execution=None)
    classification = CompletionClassificationV1.model_construct(
        request=request,
        bundle_sha256="8" * 64,
        status=CompletionStatus.AMBIGUOUS,
        reason=CompletionReason.EXECUTION_PROOF_ABSENT,
        follow_up_required=True,
        follow_up_after_seconds=5,
        follow_up_attempt_limit=3,
    )
    artifacts = _target_artifacts(
        ("before-target.json", _read((90, 10), "2026-08-24T00:00:00Z", target_sha256="b" * 64)),
        ("readback-target.json", _read((0, 100), "2026-08-24T00:01:00Z", target_sha256="c" * 64)),
        ("after-target.json", _read((100, 0), "2026-08-24T00:02:00Z", target_sha256="d" * 64)),
    )
    artifacts.update(
            {
                "promotion-command.json": _artifact(
                    command, "promotion-command.json"
                ),
                "receipt.json": _artifact(observed, "receipt.json"),
                "completion-bundle.json": _artifact(bundle, "completion-bundle.json"),
                "classification.json": _artifact(classification, "classification.json"),
                "client-timeout.json": _artifact(
                    {
                        "attempt_count": 1,
                        "deadline_milliseconds": 1,
                        "outcome": "TIMEOUT",
                        "request_id": command.request_id,
                        "request_sha256": "8" * 64,
                        "retry_count": 0,
                        "schema_version": "controlgraph.fault-client-timeout/v1",
                    },
                    "client-timeout.json",
                ),
            }
        )

    result = FAULTS._evaluate(ctx, artifacts)

    assert result.invariants == (
        FAULTS.SafetyInvariant.NO_BLIND_RETRY,
        FAULTS.SafetyInvariant.AMBIGUITY_CLASSIFICATION,
    )


def test_drift_and_probe_failures_require_exact_restoration() -> None:
    drift_ctx = _context(FAULTS.FaultKind.CONFIGURATION_DRIFT)
    before = _read((90, 10), "2026-08-24T00:00:00Z", target_sha256="e" * 64)
    drifted = _read((100, 0), "2026-08-24T00:01:00Z", target_sha256="f" * 64)
    after = _read((90, 10), "2026-08-24T00:02:00Z", target_sha256="e" * 64)
    facts = SimpleNamespace(
        traffic=drifted.traffic,
        traffic_statuses=drifted.traffic_statuses,
        concurrency=drifted.concurrency,
        stable_revision_configuration_sha256=drifted.stable_revision_configuration_sha256,
        candidate_revision_configuration_sha256=drifted.candidate_revision_configuration_sha256,
        target_configuration_sha256=drifted.target_configuration_sha256,
        observed_generation=drifted.service_generation,
        provider_etag=drifted.provider_etag,
        retrieved_at="2026-08-24T00:01:00Z",
    )
    drift_request = SimpleNamespace(
        request_id=drift_ctx.scenario.request_id("verification"),
        target=TARGET,
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
        stable_percent=90,
        candidate_percent=10,
        expected_target_configuration_sha256=before.target_configuration_sha256,
        expected_stable_revision_configuration_sha256=(
            before.stable_revision_configuration_sha256
        ),
        expected_candidate_revision_configuration_sha256=(
            before.candidate_revision_configuration_sha256
        ),
    )
    drift_evidence = SimpleNamespace(
        kind=IndependentVerificationKind.CONFIGURATION,
        verdict=IndependentVerificationVerdict.MISMATCH,
        reason_code="CONFIGURATION_TRAFFIC_MISMATCH",
        root_id="cgroot:drift",
    )
    drift_verification = VerifiedIndependentVerificationEvidenceV1.model_construct(
        signing_request=SimpleNamespace(
            evidence=drift_evidence,
            configuration=SimpleNamespace(
                request=drift_request,
                status=ConfigurationAttestationStatus.MISMATCH,
                observation=SimpleNamespace(facts=facts),
            ),
        )
    )
    drift_artifacts = _target_artifacts(
        ("before-target.json", before),
        ("drifted-target.json", drifted),
        ("after-target.json", after),
    )
    drift_artifacts["verification.json"] = _artifact(
        drift_verification, "verification.json"
    )
    drift_artifacts["drift-update.json"] = _artifact(
        {
            "candidate_percent": 0,
            "project_id": PROJECT,
            "provider_response": {"metadata": {"name": "synthetic"}},
            "region": "us-central1",
            "schema_version": "controlgraph.traffic-fault-change/v1",
            "service_name": "controlgraph-reference-target",
            "stable_percent": 100,
        },
        "drift-update.json",
    )
    drift_artifacts["drift-restore.json"] = _artifact(
        {
            "candidate_percent": 10,
            "project_id": PROJECT,
            "provider_response": {"metadata": {"name": "synthetic"}},
            "region": "us-central1",
            "schema_version": "controlgraph.traffic-fault-change/v1",
            "service_name": "controlgraph-reference-target",
            "stable_percent": 90,
        },
        "drift-restore.json",
    )
    assert FAULTS._evaluate(drift_ctx, drift_artifacts).invariants == (
        FAULTS.SafetyInvariant.SAFE_FALLBACK,
    )

    probe_ctx = _context(FAULTS.FaultKind.PROBE_FAILURE)
    probe_request = SimpleNamespace(
        request_id=probe_ctx.scenario.request_id("verification"),
        target=TARGET,
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
        stable_percent=90,
        candidate_percent=10,
    )
    probe_evidence = SimpleNamespace(
        kind=IndependentVerificationKind.PROBE,
        verdict=IndependentVerificationVerdict.INCONCLUSIVE,
        root_id="cgroot:probe",
        occurred_at="2026-08-24T00:01:00Z",
    )
    probe = SimpleNamespace(
        request=SimpleNamespace(verification=probe_request),
        status=ProbeAttestationStatus.INCONCLUSIVE,
        reason=ProbeAttestationReason.TRANSPORT_UNAVAILABLE,
        observation=SimpleNamespace(
            unavailable_count=20,
            samples=tuple(
                SimpleNamespace(outcome=SimpleNamespace(value="TRANSPORT_UNAVAILABLE"))
                for _index in range(20)
            ),
        ),
    )
    probe_verification = VerifiedIndependentVerificationEvidenceV1.model_construct(
        signing_request=SimpleNamespace(evidence=probe_evidence, probe=probe),
        verified_at="2026-08-24T00:01:00Z",
    )
    verifier = f"serviceAccount:controlgraph-verifier@{PROJECT}.iam.gserviceaccount.com"
    other = "serviceAccount:other@controlgraph-canary-abc123.iam.gserviceaccount.com"
    iam_before = {"bindings": [{"role": "roles/run.invoker", "members": [verifier, other]}]}
    iam_denied = {"bindings": [{"role": "roles/run.invoker", "members": [other]}]}
    probe_artifacts = _target_artifacts(
        ("before-target.json", before), ("after-target.json", after)
    )
    probe_artifacts.update(
        {
            "verification.json": _artifact(probe_verification, "verification.json"),
            "iam-before.json": _artifact(iam_before, "iam-before.json"),
            "iam-denied.json": _artifact(iam_denied, "iam-denied.json"),
            "iam-after.json": _artifact(iam_before, "iam-after.json"),
        }
    )
    assert FAULTS._evaluate(probe_ctx, probe_artifacts).invariants == (
        FAULTS.SafetyInvariant.SAFE_FALLBACK,
    )

    probe_artifacts["iam-after.json"] = _artifact(
        iam_denied, "iam-after.json"
    )
    with pytest.raises(FAULTS.FaultAcceptanceError, match="FAULT_PROBE_FAILURE_NOT_PROVEN"):
        FAULTS._evaluate(probe_ctx, probe_artifacts)


def test_execute_produces_all_cases_before_binding(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    target = SimpleNamespace(
        project_id=PROJECT,
        region="us-central1",
        environment="nonprod",
        service_name="controlgraph-reference-target",
        stable_revision=STABLE,
        candidate_revision=CANDIDATE,
    )
    spec = SimpleNamespace(
        source_commit="a" * 40,
        random_seed=17,
        target=target,
    )
    bridge = FAULTS._CoreBridge(
        spec=spec,
        run_id=f"cgacceptance:{'b' * 64}",
        run_inputs_sha256=CORE_INPUTS_SHA256,
        manifest_sha256=CORE_MANIFEST_SHA256,
    )
    calls: list[str] = []
    monkeypatch.setenv(FAULTS.CONFIRMATION_ENV, FAULTS.CONFIRMATION)
    monkeypatch.setattr(FAULTS, "_load_core_bridge", lambda **_kwargs: bridge)
    monkeypatch.setattr(FAULTS, "_verify_source", lambda *_args: None)
    monkeypatch.setattr(FAULTS.core, "_validate_execute_destination", lambda *_args: None)
    monkeypatch.setattr(FAULTS.core, "_verify_hosted_bindings", lambda *_args: None)
    monkeypatch.setattr(FAULTS.core, "_reset_target", lambda *_args: None)
    monkeypatch.setattr(FAULTS, "_fault_case", lambda *_args: SimpleNamespace())
    monkeypatch.setattr(FAULTS, "_active_identity", lambda _repo: IDENTITY)
    monkeypatch.setattr(
        FAULTS,
        "bind_fault_suite",
        lambda **kwargs: (
            calls.append(f"bind:{kwargs['core_run_id']}"),
            b'{"result":"PASSED"}',
        )[1],
    )
    for kind, name in (
        (FAULTS.FaultKind.DELAYED_TASK, "_execute_delayed_task"),
        (FAULTS.FaultKind.DUPLICATE_DELIVERY, "_execute_duplicate_delivery"),
        (FAULTS.FaultKind.MONITORING_GAP, "_execute_monitoring_gap"),
        (FAULTS.FaultKind.API_TIMEOUT, "_execute_api_timeout"),
        (FAULTS.FaultKind.CONFIGURATION_DRIFT, "_execute_configuration_drift"),
        (FAULTS.FaultKind.PROBE_FAILURE, "_execute_probe_failure"),
    ):
        monkeypatch.setattr(
            FAULTS,
            name,
            lambda _state, _scenario, _sequence, selected=kind: calls.append(
                selected.value
            ),
        )
    monkeypatch.setattr(
        FAULTS,
        "_execute_revocation_race",
        lambda _state, scenario, _sequence: (
            calls.append(FAULTS.FaultKind.REVOCATION_RACE.value),
            scenario,
        )[1],
    )
    evidence_root = tmp_path / "fault-evidence"
    output = tmp_path / "fault-manifest.json"

    payload = FAULTS.execute_fault_suite(
        core_spec=tmp_path / "core-spec.json",
        core_manifest=tmp_path / "core-manifest.json",
        core_artifact_root=tmp_path,
        evidence_root=evidence_root,
        output=output,
        project_number="123456789012",
        network_resource=f"projects/{PROJECT}/global/networks/controlgraph",
        subnetwork_resource=(
            f"projects/{PROJECT}/regions/us-central1/subnetworks/controlgraph"
        ),
        verifier_service_account=(
            f"controlgraph-verifier@{PROJECT}.iam.gserviceaccount.com"
        ),
        restricted_exporter_service_account=(
            f"cg-restricted-exporter@{PROJECT}.iam.gserviceaccount.com"
        ),
        acceptance_identity=IDENTITY,
        confirmation=FAULTS.CONFIRMATION,
    )

    assert payload == b'{"result":"PASSED"}'
    assert output.read_bytes() == payload
    assert calls[:-1] == [kind.value for kind in FAULTS.FaultKind]
    assert calls[-1] == bridge.run_id.join(("bind:", ""))
