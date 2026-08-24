"""Execute seven seeded hosted faults and bind their product evidence."""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, cast

import core_acceptance as core
from pydantic import ValidationError

import controlgraph_canary
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.contracts.base import (
    MAX_CONTRACT_BYTES,
    MAX_SAFE_INTEGER,
    StrictContractModel,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    canonical_sha256,
    decode_contract,
)
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
    COMPLETION_ASSESSMENT_REQUEST_V1,
    COMPLETION_EVIDENCE_BUNDLE_V1,
    INDEPENDENT_VERIFICATION_INVOCATION_V1,
    VERIFICATION_REQUEST_V1,
    CompletionAssessmentRequestV1,
    CompletionClassificationV1,
    CompletionEvidenceBundleV1,
    CompletionKind,
    CompletionReason,
    CompletionStatus,
    ConfigurationAttestationStatus,
    IndependentVerificationAttestationV1,
    IndependentVerificationInvocationV1,
    IndependentVerificationKind,
    IndependentVerificationVerdict,
    ProbeAttestationReason,
    ProbeAttestationStatus,
    VerificationRequestV1,
    VerifiedIndependentVerificationEvidenceV1,
    fixed_probe_policy,
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
from controlgraph_canary.integrations.google.kms import (
    GoogleKmsIndependentVerificationEvidenceVerifier,
)

MANIFEST_SCHEMA: Final = "controlgraph.fault-acceptance-manifest/v1"
CONFIRMATION: Final = "RUN_CONTROLGRAPH_FAULT_ACCEPTANCE"
CONFIRMATION_ENV: Final = "CONTROLGRAPH_FAULT_ACCEPTANCE_CONFIRM"
REGION: Final = "us-central1"
ENVIRONMENT: Final = "nonprod"
SERVICE: Final = "controlgraph-reference-target"
_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_REVISION = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_IDENTITY = re.compile(r"^[^@\s]+@[^@\s]+$")
_SEED_DOMAIN: Final = b"controlgraph.fault-acceptance-seed/v1\0"
_IDENTITY_DOMAIN: Final = b"controlgraph.acceptance-identity/v1\0"
_FAULT_INPUT_DOMAIN: Final = b"controlgraph.fault-acceptance-run-inputs/v1\0"
_VERIFIER_ORIGIN = "https://controlgraph-verifier-{project_number}.us-central1.run.app"


class FaultAcceptanceError(ValueError):
    """Stable failure that never reflects untrusted artifact content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FaultKind(StrEnum):
    DELAYED_TASK = "DELAYED_TASK"
    DUPLICATE_DELIVERY = "DUPLICATE_DELIVERY"
    REVOCATION_RACE = "REVOCATION_RACE"
    MONITORING_GAP = "MONITORING_GAP"
    API_TIMEOUT = "API_TIMEOUT"
    CONFIGURATION_DRIFT = "CONFIGURATION_DRIFT"
    PROBE_FAILURE = "PROBE_FAILURE"


class SafetyInvariant(StrEnum):
    STALE_DENIAL = "STALE_DENIAL"
    ONE_RECOVERY_INTENT = "ONE_RECOVERY_INTENT"
    NO_BLIND_RETRY = "NO_BLIND_RETRY"
    DETERMINISTIC_HEALTH = "DETERMINISTIC_HEALTH"
    AMBIGUITY_CLASSIFICATION = "AMBIGUITY_CLASSIFICATION"
    SAFE_FALLBACK = "SAFE_FALLBACK"


@dataclass(frozen=True, slots=True)
class _Scenario:
    kind: FaultKind
    scenario_id: str
    random_seed: int
    boundary: str
    injection: str
    run_inputs_sha256: str

    def request_id(self, label: str) -> str:
        return self._stable_id(f"{label}-request")

    def idempotency_key(self, label: str) -> str:
        return self._stable_id(f"{label}-idempotency")

    def correlation_id(self, label: str) -> str:
        return self._stable_id(f"{label}-correlation")

    def _stable_id(self, label: str) -> str:
        digest = hashlib.sha256(
            f"{self.run_inputs_sha256}\0{self.scenario_id}\0{label}".encode("ascii")
        ).hexdigest()
        return f"cgm8-{label}-{digest[:24]}"


@dataclass(frozen=True, slots=True)
class _Context:
    target: TargetBinding
    stable_revision: str
    candidate_revision: str
    acceptance_identity: str
    scenario: _Scenario


@dataclass(frozen=True, slots=True)
class _LoadedArtifact:
    name: str
    payload: bytes
    value: object


@dataclass(frozen=True, slots=True)
class _DerivedCase:
    root_id: str
    invariants: tuple[SafetyInvariant, ...]
    observation: Mapping[str, RestrictedJson]


@dataclass(slots=True)
class _ExecutionState:
    run: core._HostedExecution
    evidence_root: Path
    cleanup_required: set[str]


@dataclass(frozen=True, slots=True)
class _CoreBridge:
    spec: core.CoreAcceptanceRunSpecV1
    run_id: str
    run_inputs_sha256: str
    manifest_sha256: str


_SCENARIO_ACTIONS: Final[dict[FaultKind, tuple[str, str]]] = {
    FaultKind.DELAYED_TASK: (
        "cloud_tasks.execution_queue_delivery",
        "HOLD_REVOKE_RELEASE",
    ),
    FaultKind.DUPLICATE_DELIVERY: (
        "coordinator.health_evaluation",
        "REPEAT_IDENTICAL_REQUEST",
    ),
    FaultKind.REVOCATION_RACE: (
        "executor.final_authority_read",
        "REVOKE_BETWEEN_CLAIM_AND_FINAL_READ",
    ),
    FaultKind.MONITORING_GAP: (
        "verifier.monitoring_window",
        "OMIT_REAL_MONITORING_SIGNAL",
    ),
    FaultKind.API_TIMEOUT: (
        "operator.mutation_response",
        "ONE_SHORT_DEADLINE_NO_RETRY_THEN_READBACK",
    ),
    FaultKind.CONFIGURATION_DRIFT: (
        "verifier.configuration_read",
        "CHANGE_TRAFFIC_THEN_VERIFY_AND_RESTORE",
    ),
    FaultKind.PROBE_FAILURE: (
        "verifier.probe_transport",
        "REMOVE_ONLY_VERIFIER_INVOKER_THEN_RESTORE",
    ),
}

type _ModelType = type[StrictContractModel]
_T = TargetTrafficReadResultV1
_TYPED_LAYOUT: Final[dict[FaultKind, tuple[tuple[str, _ModelType], ...]]] = {
    FaultKind.DELAYED_TASK: (
        ("before-target.json", _T),
        ("denied-target.json", _T),
        ("after-target.json", _T),
        ("revocation-proof.json", EpochRevocationProofV1),
        ("stale-receipt.json", ExecutionReceiptReadResultV1),
    ),
    FaultKind.DUPLICATE_DELIVERY: (
        ("after-target.json", _T),
        ("first-health-result.json", HealthEvaluationResultV2),
        ("duplicate-health-result.json", HealthEvaluationResultV2),
        ("recovery-intent.json", RecoveryIntentV1),
    ),
    FaultKind.REVOCATION_RACE: (
        ("before-target.json", _T),
        ("denied-target.json", _T),
        ("after-target.json", _T),
        ("revocation-proof.json", EpochRevocationProofV1),
        ("stale-receipt.json", ExecutionReceiptReadResultV1),
    ),
    FaultKind.MONITORING_GAP: (
        ("before-target.json", _T),
        ("after-target.json", _T),
        ("health-result.json", HealthEvaluationResultV2),
        ("signed-health-proof.json", SignedHealthDecisionProofV1),
    ),
    FaultKind.API_TIMEOUT: (
        ("before-target.json", _T),
        ("readback-target.json", _T),
        ("after-target.json", _T),
        ("promotion-command.json", PromotionCommandV2),
        ("receipt.json", ExecutionReceiptReadResultV1),
        ("completion-bundle.json", CompletionEvidenceBundleV1),
        ("classification.json", CompletionClassificationV1),
    ),
    FaultKind.CONFIGURATION_DRIFT: (
        ("before-target.json", _T),
        ("drifted-target.json", _T),
        ("after-target.json", _T),
        ("verification.json", VerifiedIndependentVerificationEvidenceV1),
    ),
    FaultKind.PROBE_FAILURE: (
        ("before-target.json", _T),
        ("after-target.json", _T),
        ("verification.json", VerifiedIndependentVerificationEvidenceV1),
    ),
}
_RAW_LAYOUT: Final[dict[FaultKind, tuple[str, ...]]] = {
    FaultKind.DELAYED_TASK: ("queue-held.json", "queue-released.json"),
    FaultKind.DUPLICATE_DELIVERY: ("recovery-intent-query.json",),
    FaultKind.REVOCATION_RACE: (
        "queue-held.json",
        "queue-released.json",
        "race-attempt.json",
    ),
    FaultKind.API_TIMEOUT: ("client-timeout.json",),
    FaultKind.CONFIGURATION_DRIFT: (
        "drift-update.json",
        "drift-restore.json",
    ),
    FaultKind.PROBE_FAILURE: (
        "iam-before.json",
        "iam-denied.json",
        "iam-after.json",
    ),
}


def _scenario(
    run_seed: int,
    kind: FaultKind,
    run_inputs_sha256: str | None = None,
) -> _Scenario:
    digest = hashlib.sha256(
        _SEED_DOMAIN + str(run_seed).encode("ascii") + b"\0" + kind.value.encode("ascii")
    ).digest()
    slug = kind.value.lower().replace("_", "-")
    boundary, injection = _SCENARIO_ACTIONS[kind]
    return _Scenario(
        kind=kind,
        scenario_id=f"fault-{slug}-{digest.hex()[:16]}",
        random_seed=int.from_bytes(digest[:6], "big"),
        boundary=boundary,
        injection=injection,
        run_inputs_sha256=(
            run_inputs_sha256
            if run_inputs_sha256 is not None
            else hashlib.sha256(_SEED_DOMAIN + str(run_seed).encode("ascii")).hexdigest()
        ),
    )


def _race_scenario(base: _Scenario, attempt: int) -> _Scenario:
    if not 1 <= attempt <= 3:
        raise FaultAcceptanceError("FAULT_RACE_ATTEMPT_INVALID")
    digest = hashlib.sha256(
        f"{base.random_seed}\0{attempt}".encode("ascii")
    ).digest()
    return _Scenario(
        kind=base.kind,
        scenario_id=f"{base.scenario_id}-a{attempt}",
        random_seed=int.from_bytes(digest[:6], "big"),
        boundary=base.boundary,
        injection=base.injection,
        run_inputs_sha256=base.run_inputs_sha256,
    )


def _read(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError
        payload = path.read_bytes()
    except OSError as error:
        raise FaultAcceptanceError("FAULT_ARTIFACT_INVALID") from error
    if not 0 < len(payload) <= MAX_CONTRACT_BYTES:
        raise FaultAcceptanceError("FAULT_ARTIFACT_INVALID")
    return payload


def _load_contract(path: Path, model_type: _ModelType) -> _LoadedArtifact:
    payload = _read(path)
    try:
        value = decode_contract(payload, model_type)
    except (ContractError, TypeError, ValueError, ValidationError) as error:
        raise FaultAcceptanceError("FAULT_PRODUCT_EVIDENCE_INVALID") from error
    return _LoadedArtifact(name=path.name, payload=payload, value=value)


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _load_raw(path: Path) -> _LoadedArtifact:
    payload = _read(path)
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_json_pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise FaultAcceptanceError("FAULT_BOUNDARY_EVIDENCE_INVALID") from error
    if not isinstance(value, dict):
        raise FaultAcceptanceError("FAULT_BOUNDARY_EVIDENCE_INVALID")
    return _LoadedArtifact(name=path.name, payload=payload, value=value)


def _artifacts(root: Path, kind: FaultKind) -> dict[str, _LoadedArtifact]:
    case_root = root / kind.value.lower().replace("_", "-")
    loaded = {
        name: _load_contract(case_root / name, model_type)
        for name, model_type in _TYPED_LAYOUT[kind]
    }
    loaded.update(
        {name: _load_raw(case_root / name) for name in _RAW_LAYOUT.get(kind, ())}
    )
    return loaded


def _typed[ModelT: StrictContractModel](
    artifacts: Mapping[str, _LoadedArtifact], name: str, model_type: type[ModelT]
) -> ModelT:
    value = artifacts[name].value
    if type(value) is not model_type:
        raise FaultAcceptanceError("FAULT_PRODUCT_EVIDENCE_INVALID")
    return value


def _raw(artifacts: Mapping[str, _LoadedArtifact], name: str) -> dict[str, Any]:
    value = artifacts[name].value
    if not isinstance(value, dict):
        raise FaultAcceptanceError("FAULT_BOUNDARY_EVIDENCE_INVALID")
    return value


def _require_read(ctx: _Context, result: TargetTrafficReadResultV1) -> None:
    request = result.request
    if (
        request.target != ctx.target
        or request.stable_revision != ctx.stable_revision
        or request.candidate_revision != ctx.candidate_revision
    ):
        raise FaultAcceptanceError("FAULT_TARGET_READBACK_INVALID")


def _traffic(result: TargetTrafficReadResultV1) -> tuple[int, int]:
    values = {item.revision: item.percent for item in result.traffic}
    return (
        values.get(result.request.stable_revision, 0),
        values.get(result.request.candidate_revision, 0),
    )


def _state(result: TargetTrafficReadResultV1) -> tuple[object, ...]:
    return (
        tuple(sorted((item.revision, item.percent) for item in result.traffic)),
        tuple(sorted((item.revision, item.percent) for item in result.traffic_statuses)),
        result.concurrency,
        result.stable_revision_configuration_sha256,
        result.candidate_revision_configuration_sha256,
        result.target_configuration_sha256,
    )


def _reads(
    ctx: _Context,
    artifacts: Mapping[str, _LoadedArtifact],
    *names: str,
) -> tuple[TargetTrafficReadResultV1, ...]:
    results = tuple(_typed(artifacts, name, TargetTrafficReadResultV1) for name in names)
    for result in results:
        _require_read(ctx, result)
    if tuple(item.observed_at for item in results) != tuple(
        sorted(item.observed_at for item in results)
    ):
        raise FaultAcceptanceError("FAULT_TARGET_READBACK_INVALID")
    return results


def _queue(value: Mapping[str, Any], ctx: _Context, action: str, state: str) -> None:
    if value != {
        "action": action,
        "location": REGION,
        "project_id": ctx.target.project_id,
        "queue_id": "controlgraph-execution",
        "state": state,
    }:
        raise FaultAcceptanceError("FAULT_QUEUE_EVIDENCE_INVALID")


def _stale_case(
    ctx: _Context,
    artifacts: Mapping[str, _LoadedArtifact],
    *,
    race: bool,
) -> _DerivedCase:
    before, denied, after = _reads(
        ctx, artifacts, "before-target.json", "denied-target.json", "after-target.json"
    )
    proof = _typed(artifacts, "revocation-proof.json", EpochRevocationProofV1)
    observed = _typed(artifacts, "stale-receipt.json", ExecutionReceiptReadResultV1)
    receipt = observed.receipt
    revocation = proof.result
    _queue(_raw(artifacts, "queue-held.json"), ctx, "hold", "PAUSED")
    _queue(_raw(artifacts, "queue-released.json"), ctx, "release", "RUNNING")
    if race:
        attempt = _raw(artifacts, "race-attempt.json")
        if attempt != {
            "attempt": attempt.get("attempt"),
            "maximum_attempts": 3,
            "scenario_id": ctx.scenario.scenario_id,
            "schema_version": "controlgraph.revocation-race-attempt/v1",
        } or type(attempt.get("attempt")) is not int:
            raise FaultAcceptanceError("FAULT_RACE_ATTEMPT_INVALID")
    ordered = (
        receipt.created_at <= revocation.committed_at <= receipt.updated_at
        if race
        else revocation.committed_at <= receipt.created_at
    )
    if (
        proof.authority.current_epoch != 2
        or revocation.previous_epoch != 1
        or revocation.new_epoch != 2
        or revocation.target != ctx.target
        or revocation.operator_identity != ctx.acceptance_identity
        or revocation.request_id != ctx.scenario.request_id("revoke")
        or receipt.target != ctx.target
        or receipt.root_id != revocation.root_id
        or receipt.root_sha256 != revocation.root_sha256
        or receipt.epoch != revocation.previous_epoch
        or receipt.request_id != ctx.scenario.request_id("promotion")
        or receipt.idempotency_key != ctx.scenario.idempotency_key("promotion")
        or receipt.action is not CapabilityAction.PROMOTE_CANDIDATE
        or receipt.outcome is not ReceiptOutcome.DENIED
        or receipt.reason_code is not ReasonCode.EPOCH_MISMATCH
        or receipt.observed_authority_epoch != revocation.new_epoch
        or not ordered
        or not before.observed_at <= revocation.committed_at
        or not receipt.updated_at <= denied.observed_at
        or _traffic(before) != (90, 10)
        or _state(before) != _state(denied)
        or _traffic(after) != (100, 0)
    ):
        raise FaultAcceptanceError("FAULT_STALE_DENIAL_NOT_PROVEN")
    return _DerivedCase(
        root_id=receipt.root_id,
        invariants=(SafetyInvariant.STALE_DENIAL,),
        observation={
            "new_epoch": revocation.new_epoch,
            "outcome": receipt.outcome.value,
            "reason_code": receipt.reason_code.value,
        },
    )


def _duplicate_case(
    ctx: _Context, artifacts: Mapping[str, _LoadedArtifact]
) -> _DerivedCase:
    (after,) = _reads(ctx, artifacts, "after-target.json")
    first = _typed(artifacts, "first-health-result.json", HealthEvaluationResultV2)
    duplicate = _typed(artifacts, "duplicate-health-result.json", HealthEvaluationResultV2)
    intent = _typed(artifacts, "recovery-intent.json", RecoveryIntentV1)
    query = _raw(artifacts, "recovery-intent-query.json")
    dispatch = first.recovery_dispatch
    if (
        first != duplicate
        or artifacts["first-health-result.json"].payload
        != artifacts["duplicate-health-result.json"].payload
        or first.request_id != ctx.scenario.request_id("health-2")
        or first.idempotency_key != ctx.scenario.idempotency_key("health-2")
        or first.target != ctx.target
        or first.terminal_status is not HealthDecisionStatus.UNHEALTHY
        or dispatch is None
        or dispatch.enqueue_disposition not in {"CREATED", "DUPLICATE"}
        or intent.root_id != dispatch.root_id
        or intent.root_sha256 != dispatch.root_sha256
        or intent.epoch != dispatch.epoch
        or intent.request_id != dispatch.request_id
        or intent.idempotency_key != dispatch.idempotency_key
        or intent.source_receipt_sha256 != dispatch.source_receipt_sha256
        or intent.trigger_proof_sha256 != dispatch.trigger_proof_sha256
        or query
        != {
            "fixed_head_entry_sha256": query.get("fixed_head_entry_sha256"),
            "fixed_head_sequence": query.get("fixed_head_sequence"),
            "matched_count": 1,
            "matched_entry_ids": query.get("matched_entry_ids"),
            "matched_record_sha256s": [
                hashlib.sha256(artifacts["recovery-intent.json"].payload).hexdigest()
            ],
            "root_id": intent.root_id,
            "scanned_entry_count": query.get("scanned_entry_count"),
            "schema_version": "controlgraph.recovery-intent-query/v1",
        }
        or type(query.get("fixed_head_sequence")) is not int
        or cast(int, query["fixed_head_sequence"]) < 1
        or not isinstance(query.get("fixed_head_entry_sha256"), str)
        or len(cast(str, query["fixed_head_entry_sha256"])) != 64
        or not isinstance(query.get("matched_entry_ids"), list)
        or len(cast(list[object], query["matched_entry_ids"])) != 1
        or not isinstance(cast(list[object], query["matched_entry_ids"])[0], str)
        or type(query.get("scanned_entry_count")) is not int
        or cast(int, query["scanned_entry_count"]) < 1
        or dispatch.scheduled_at > after.observed_at
        or _traffic(after) != (100, 0)
    ):
        raise FaultAcceptanceError("FAULT_DUPLICATE_RECOVERY_NOT_PROVEN")
    return _DerivedCase(
        root_id=first.root_id,
        invariants=(SafetyInvariant.ONE_RECOVERY_INTENT,),
        observation={
            "intent_id": intent.intent_id,
            "recovery_task_id": dispatch.task_id,
            "response_sha256": hashlib.sha256(
                artifacts["first-health-result.json"].payload
            ).hexdigest(),
        },
    )


def _monitoring_gap_case(
    ctx: _Context, artifacts: Mapping[str, _LoadedArtifact]
) -> _DerivedCase:
    before, after = _reads(ctx, artifacts, "before-target.json", "after-target.json")
    health = _typed(artifacts, "health-result.json", HealthEvaluationResultV2)
    signed = _typed(
        artifacts, "signed-health-proof.json", SignedHealthDecisionProofV1
    )
    proof = signed.proof
    observation = proof.observation
    decision = proof.decision
    expected_reason = {
        MonitoringObservationCompleteness.MISSING: HealthReasonCode.SAMPLE_MISSING,
        MonitoringObservationCompleteness.PARTIAL: HealthReasonCode.SAMPLE_PARTIAL,
    }.get(observation.completeness)
    if (
        health.request_id != ctx.scenario.request_id("health-1")
        or health.idempotency_key != ctx.scenario.idempotency_key("health-1")
        or health.target != ctx.target
        or decision.target != ctx.target
        or health.root_id != decision.root_id
        or health.root_sha256 != decision.root_sha256
        or health.epoch != decision.epoch
        or health.terminal_status is not HealthDecisionStatus.INSUFFICIENT_EVIDENCE
        or decision.status is not HealthDecisionStatus.INSUFFICIENT_EVIDENCE
        or expected_reason is None
        or expected_reason not in decision.reason_codes
        or not observation.missing_signals
        or health.terminal_health_decision_sha256 != canonical_sha256(decision)
        or health.chain_head_sha256 != canonical_sha256(signed)
        or not before.observed_at <= proof.produced_at <= after.observed_at
        or _traffic(before) != (90, 10)
        or _state(before) != _state(after)
    ):
        raise FaultAcceptanceError("FAULT_MONITORING_GAP_NOT_PROVEN")
    return _DerivedCase(
        root_id=health.root_id,
        invariants=(SafetyInvariant.DETERMINISTIC_HEALTH,),
        observation={
            "completeness": observation.completeness.value,
            "decision": decision.status.value,
            "missing_signals": [item.value for item in observation.missing_signals],
        },
    )


def _api_timeout_case(
    ctx: _Context, artifacts: Mapping[str, _LoadedArtifact]
) -> _DerivedCase:
    before, readback, after = _reads(
        ctx, artifacts, "before-target.json", "readback-target.json", "after-target.json"
    )
    observed = _typed(artifacts, "receipt.json", ExecutionReceiptReadResultV1)
    command = _typed(artifacts, "promotion-command.json", PromotionCommandV2)
    bundle = _typed(artifacts, "completion-bundle.json", CompletionEvidenceBundleV1)
    classification = _typed(
        artifacts, "classification.json", CompletionClassificationV1
    )
    receipt = observed.receipt
    timeout = _raw(artifacts, "client-timeout.json")
    verification = classification.request.verification
    if (
        command.request_id != ctx.scenario.request_id("promotion")
        or command.idempotency_key != ctx.scenario.idempotency_key("promotion")
        or receipt.request_id != command.request_id
        or receipt.idempotency_key != command.idempotency_key
        or receipt.target != ctx.target
        or receipt.action is not CapabilityAction.PROMOTE_CANDIDATE
        or receipt.outcome is not ReceiptOutcome.VERIFIED
        or receipt.reason_code is not None
        or timeout
        != {
            "attempt_count": 1,
            "deadline_milliseconds": 1,
            "outcome": "TIMEOUT",
            "request_id": command.request_id,
            "request_sha256": canonical_sha256(command),
            "retry_count": 0,
            "schema_version": "controlgraph.fault-client-timeout/v1",
        }
        or bundle.execution is not None
        or classification.request != bundle.request
        or classification.bundle_sha256 != canonical_sha256(bundle)
        or classification.status is not CompletionStatus.AMBIGUOUS
        or classification.reason is not CompletionReason.EXECUTION_PROOF_ABSENT
        or not classification.follow_up_required
        or verification.target != ctx.target
        or verification.root_id != receipt.root_id
        or verification.root_sha256 != receipt.root_sha256
        or verification.epoch != receipt.epoch
        or verification.request_id != receipt.request_id
        or verification.action is not receipt.action
        or not before.observed_at <= receipt.updated_at <= readback.observed_at
        or _traffic(before) != (90, 10)
        or _traffic(readback) != (0, 100)
        or _traffic(after) != (100, 0)
    ):
        raise FaultAcceptanceError("FAULT_TIMEOUT_AMBIGUITY_NOT_PROVEN")
    return _DerivedCase(
        root_id=receipt.root_id,
        invariants=(
            SafetyInvariant.NO_BLIND_RETRY,
            SafetyInvariant.AMBIGUITY_CLASSIFICATION,
        ),
        observation={
            "classification": classification.status.value,
            "follow_up_after_seconds": classification.follow_up_after_seconds,
            "follow_up_attempt_limit": classification.follow_up_attempt_limit,
            "follow_up_required": classification.follow_up_required,
            "request_attempt_count": 1,
            "receipt_outcome": receipt.outcome.value,
        },
    )


def _configuration_drift_case(
    ctx: _Context, artifacts: Mapping[str, _LoadedArtifact]
) -> _DerivedCase:
    before, drifted, after = _reads(
        ctx, artifacts, "before-target.json", "drifted-target.json", "after-target.json"
    )
    verified = _typed(
        artifacts, "verification.json", VerifiedIndependentVerificationEvidenceV1
    )
    signing = verified.signing_request
    evidence = signing.evidence
    attestation = signing.configuration
    if attestation is None or attestation.observation is None:
        raise FaultAcceptanceError("FAULT_CONFIGURATION_DRIFT_NOT_PROVEN")
    request = attestation.request
    facts = attestation.observation.facts
    drift_update = _traffic_change(_raw(artifacts, "drift-update.json"), ctx)
    restore_update = _traffic_change(_raw(artifacts, "drift-restore.json"), ctx)
    actual = (
        tuple(sorted((item.revision, item.percent) for item in facts.traffic)),
        tuple(sorted((item.revision, item.percent) for item in facts.traffic_statuses)),
        facts.concurrency,
        facts.stable_revision_configuration_sha256,
        facts.candidate_revision_configuration_sha256,
        facts.target_configuration_sha256,
    )
    if (
        evidence.kind is not IndependentVerificationKind.CONFIGURATION
        or evidence.verdict is not IndependentVerificationVerdict.MISMATCH
        or attestation.status is not ConfigurationAttestationStatus.MISMATCH
        or request.request_id != ctx.scenario.request_id("verification")
        or request.target != ctx.target
        or request.stable_revision != ctx.stable_revision
        or request.candidate_revision != ctx.candidate_revision
        or before.target_configuration_sha256 != request.expected_target_configuration_sha256
        or before.stable_revision_configuration_sha256
        != request.expected_stable_revision_configuration_sha256
        or before.candidate_revision_configuration_sha256
        != request.expected_candidate_revision_configuration_sha256
        or drift_update != (100, 0)
        or restore_update != (90, 10)
        or _traffic(before) != (request.stable_percent, request.candidate_percent)
        or drifted.service_generation != facts.observed_generation
        or drifted.provider_etag != facts.provider_etag
        or _state(drifted) != actual
        or _state(before) == _state(drifted)
        or _state(before) != _state(after)
        or not before.observed_at <= facts.retrieved_at <= after.observed_at
    ):
        raise FaultAcceptanceError("FAULT_CONFIGURATION_DRIFT_NOT_PROVEN")
    return _DerivedCase(
        root_id=evidence.root_id,
        invariants=(SafetyInvariant.SAFE_FALLBACK,),
        observation={
            "reason_code": evidence.reason_code,
            "restored_configuration_sha256": after.target_configuration_sha256,
            "verdict": evidence.verdict.value,
        },
    )


def _traffic_change(value: Mapping[str, Any], ctx: _Context) -> tuple[int, int]:
    expected_keys = {
        "candidate_percent",
        "project_id",
        "provider_response",
        "region",
        "schema_version",
        "service_name",
        "stable_percent",
    }
    if (
        set(value) != expected_keys
        or value.get("schema_version") != "controlgraph.traffic-fault-change/v1"
        or value.get("project_id") != ctx.target.project_id
        or value.get("region") != ctx.target.region
        or value.get("service_name") != ctx.target.service_name
        or type(value.get("stable_percent")) is not int
        or type(value.get("candidate_percent")) is not int
        or cast(int, value["stable_percent"]) + cast(int, value["candidate_percent"])
        != 100
        or not isinstance(value.get("provider_response"), dict)
        or not cast(dict[str, Any], value["provider_response"])
    ):
        raise FaultAcceptanceError("FAULT_TRAFFIC_CHANGE_EVIDENCE_INVALID")
    return cast(int, value["stable_percent"]), cast(int, value["candidate_percent"])


def _policy_bindings(
    value: Mapping[str, Any],
) -> tuple[int, tuple[tuple[str, tuple[str, ...]], ...]]:
    bindings = value.get("bindings")
    version = value.get("version", 1)
    if (
        not set(value).issubset({"bindings", "etag", "version"})
        or not isinstance(bindings, list)
        or type(version) is not int
        or version not in {1, 3}
    ):
        raise FaultAcceptanceError("FAULT_IAM_EVIDENCE_INVALID")
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {"members", "role"}:
            raise FaultAcceptanceError("FAULT_IAM_EVIDENCE_INVALID")
        role = binding.get("role")
        members = binding.get("members")
        if (
            not isinstance(role, str)
            or not isinstance(members, list)
            or not members
            or any(not isinstance(member, str) for member in members)
        ):
            raise FaultAcceptanceError("FAULT_IAM_EVIDENCE_INVALID")
        normalized.append((role, tuple(sorted(cast(list[str], members)))))
    if len({role for role, _members in normalized}) != len(normalized):
        raise FaultAcceptanceError("FAULT_IAM_EVIDENCE_INVALID")
    return version, tuple(sorted(normalized))


def _remove_member(
    policy: tuple[int, tuple[tuple[str, tuple[str, ...]], ...]],
    role: str,
    member: str,
) -> tuple[int, tuple[tuple[str, tuple[str, ...]], ...]]:
    version, bindings = policy
    result: list[tuple[str, tuple[str, ...]]] = []
    found = False
    for binding_role, members in bindings:
        if binding_role == role and member in members:
            found = True
            retained = tuple(item for item in members if item != member)
            if retained:
                result.append((binding_role, retained))
        else:
            result.append((binding_role, members))
    if not found:
        raise FaultAcceptanceError("FAULT_IAM_EVIDENCE_INVALID")
    return version, tuple(sorted(result))


def _probe_failure_case(
    ctx: _Context, artifacts: Mapping[str, _LoadedArtifact]
) -> _DerivedCase:
    before, after = _reads(ctx, artifacts, "before-target.json", "after-target.json")
    verified = _typed(
        artifacts, "verification.json", VerifiedIndependentVerificationEvidenceV1
    )
    signing = verified.signing_request
    evidence = signing.evidence
    attestation = signing.probe
    if attestation is None:
        raise FaultAcceptanceError("FAULT_PROBE_FAILURE_NOT_PROVEN")
    request = attestation.request.verification
    observation = attestation.observation
    iam_before = _policy_bindings(_raw(artifacts, "iam-before.json"))
    iam_denied = _policy_bindings(_raw(artifacts, "iam-denied.json"))
    iam_after = _policy_bindings(_raw(artifacts, "iam-after.json"))
    verifier_member = (
        f"serviceAccount:controlgraph-verifier@{ctx.target.project_id}.iam.gserviceaccount.com"
    )
    if (
        iam_denied != _remove_member(iam_before, "roles/run.invoker", verifier_member)
        or iam_after != iam_before
        or evidence.kind is not IndependentVerificationKind.PROBE
        or evidence.verdict is not IndependentVerificationVerdict.INCONCLUSIVE
        or attestation.status is not ProbeAttestationStatus.INCONCLUSIVE
        or attestation.reason is not ProbeAttestationReason.TRANSPORT_UNAVAILABLE
        or observation.unavailable_count != 20
        or any(sample.outcome.value != "TRANSPORT_UNAVAILABLE" for sample in observation.samples)
        or request.request_id != ctx.scenario.request_id("verification")
        or request.target != ctx.target
        or request.stable_revision != ctx.stable_revision
        or request.candidate_revision != ctx.candidate_revision
        or _traffic(before) != (request.stable_percent, request.candidate_percent)
        or _state(before) != _state(after)
        or not before.observed_at <= evidence.occurred_at <= after.observed_at
        or verified.verified_at > after.observed_at
    ):
        raise FaultAcceptanceError("FAULT_PROBE_FAILURE_NOT_PROVEN")
    return _DerivedCase(
        root_id=evidence.root_id,
        invariants=(SafetyInvariant.SAFE_FALLBACK,),
        observation={
            "iam_restored": True,
            "probe_reason": attestation.reason.value,
            "unavailable_samples": observation.unavailable_count,
        },
    )


def _evaluate(
    ctx: _Context, artifacts: Mapping[str, _LoadedArtifact]
) -> _DerivedCase:
    if ctx.scenario.kind is FaultKind.DELAYED_TASK:
        return _stale_case(ctx, artifacts, race=False)
    if ctx.scenario.kind is FaultKind.DUPLICATE_DELIVERY:
        return _duplicate_case(ctx, artifacts)
    if ctx.scenario.kind is FaultKind.REVOCATION_RACE:
        return _stale_case(ctx, artifacts, race=True)
    if ctx.scenario.kind is FaultKind.MONITORING_GAP:
        return _monitoring_gap_case(ctx, artifacts)
    if ctx.scenario.kind is FaultKind.API_TIMEOUT:
        return _api_timeout_case(ctx, artifacts)
    if ctx.scenario.kind is FaultKind.CONFIGURATION_DRIFT:
        return _configuration_drift_case(ctx, artifacts)
    return _probe_failure_case(ctx, artifacts)


def _case_directory(state: _ExecutionState, kind: FaultKind) -> Path:
    return state.evidence_root / kind.value.lower().replace("_", "-")


def _write_evidence(
    state: _ExecutionState,
    kind: FaultKind,
    name: str,
    value: StrictContractModel | Mapping[str, Any],
) -> bytes:
    allowed = {item[0] for item in _TYPED_LAYOUT[kind]}.union(
        _RAW_LAYOUT.get(kind, ())
    )
    if name not in allowed:
        raise FaultAcceptanceError("FAULT_OUTPUT_INVALID")
    payload = (
        canonical_json_bytes(value)
        if isinstance(value, StrictContractModel)
        else core._canonical_object(dict(value))
    )
    core._write_once(_case_directory(state, kind) / name, payload)
    return payload


def _fault_case(
    spec: core.CoreAcceptanceRunSpecV1,
    scenario: _Scenario,
    sequence: int,
) -> core.CaseBindingV1:
    projection = spec.cases[sequence - 1].model_dump(mode="python")
    projection.update(
        {
            "case_id": scenario.scenario_id,
            "random_seed": scenario.random_seed,
            "sequence": sequence,
        }
    )
    try:
        return core.CaseBindingV1.model_validate(projection)
    except (TypeError, ValueError, ValidationError) as error:
        raise FaultAcceptanceError("FAULT_RUN_BINDING_INVALID") from error


def _wait_until(instant: datetime) -> None:
    while datetime.now(UTC) < instant:
        remaining = (instant - datetime.now(UTC)).total_seconds()
        time.sleep(min(5.0, max(0.05, remaining)))


def _recover_and_release(
    state: _ExecutionState,
    case: core.CaseBindingV1,
    *,
    root_result: Any,
    apply_receipt: Any,
    proof: EpochRevocationProofV1,
    label: str,
) -> TargetTrafficReadResultV1:
    dispatch, _receipt = core._recover_revoked(
        state.run,
        case,
        root_result=root_result,
        apply_receipt=apply_receipt,
        revocation_proof=proof,
    )
    recovered = core._read_traffic(state.run, case, f"{label}-recovered")
    core._require_split(recovered, state.run.spec, stable=100, candidate=0)
    core._release_claim(
        state.run,
        case,
        root=root_result.root,
        epoch=2,
        terminal_idempotency_key=dispatch.idempotency_key,
        label=label,
    )
    return cast(TargetTrafficReadResultV1, recovered)


def _timeline_snapshot(
    run: core._HostedExecution,
) -> tuple[tuple[Any, ...], tuple[Any, ...], tuple[dict[str, Any], ...]]:
    pages, raw = core._read_timeline_evidence(run)
    return pages, raw, core._available_raw_records(raw)


def _root_recovery_intent(
    run: core._HostedExecution,
    root_id: str,
) -> tuple[RecoveryIntentV1, dict[str, Any]]:
    pages, raw, _records = _timeline_snapshot(run)
    matches: list[tuple[Any, RecoveryIntentV1, bytes]] = []
    for item in raw:
        if item.canonical_record is None:
            continue
        try:
            record = json.loads(item.canonical_record)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise FaultAcceptanceError("FAULT_PRODUCT_EVIDENCE_INVALID") from error
        if not isinstance(record, dict):
            raise FaultAcceptanceError("FAULT_PRODUCT_EVIDENCE_INVALID")
        if record.get("schema_version") != "controlgraph.recovery-intent/v1":
            continue
        try:
            intent = RecoveryIntentV1.model_validate(record)
        except (TypeError, ValueError, ValidationError) as error:
            raise FaultAcceptanceError("FAULT_PRODUCT_EVIDENCE_INVALID") from error
        if intent.root_id == root_id:
            matches.append((item, intent, canonical_json_bytes(intent)))
    if len(matches) != 1:
        raise FaultAcceptanceError("FAULT_DUPLICATE_RECOVERY_NOT_PROVEN")
    item, intent, payload = matches[0]
    head = pages[0]
    query = {
        "fixed_head_entry_sha256": head.head_entry_sha256,
        "fixed_head_sequence": head.head_sequence,
        "matched_count": 1,
        "matched_entry_ids": [item.entry_id],
        "matched_record_sha256s": [hashlib.sha256(payload).hexdigest()],
        "root_id": root_id,
        "scanned_entry_count": len(raw),
        "schema_version": "controlgraph.recovery-intent-query/v1",
    }
    return intent, query


def _signed_health_proof(
    run: core._HostedExecution,
    *,
    root_id: str,
    signed_sha256: str,
) -> SignedHealthDecisionProofV1:
    _pages, _raw, records = _timeline_snapshot(run)
    matches: list[SignedHealthDecisionProofV1] = []
    for record in records:
        if record.get("schema_version") != "controlgraph.signed-health-decision-proof/v1":
            continue
        try:
            signed = SignedHealthDecisionProofV1.model_validate(record)
        except (TypeError, ValueError, ValidationError) as error:
            raise FaultAcceptanceError("FAULT_PRODUCT_EVIDENCE_INVALID") from error
        if (
            signed.proof.decision.root_id == root_id
            and canonical_sha256(signed) == signed_sha256
        ):
            matches.append(signed)
    if len(matches) != 1:
        raise FaultAcceptanceError("FAULT_MONITORING_GAP_NOT_PROVEN")
    return matches[0]


def _traffic_mutation(
    state: _ExecutionState,
    *,
    stable_percent: int,
    candidate_percent: int,
) -> dict[str, Any]:
    target = state.run.spec.target
    allocations = [f"{target.stable_revision}={stable_percent}"]
    if candidate_percent:
        allocations.append(f"{target.candidate_revision}={candidate_percent}")
    response = core._gcloud_json(
        (
            "run",
            "services",
            "update-traffic",
            target.service_name,
            f"--project={target.project_id}",
            f"--region={target.region}",
            f"--to-revisions={','.join(allocations)}",
            "--quiet",
        ),
        repo=state.run.repo,
        timeout=300,
    )
    if not isinstance(response, dict) or not response:
        raise FaultAcceptanceError("FAULT_TRAFFIC_CHANGE_EVIDENCE_INVALID")
    return {
        "candidate_percent": candidate_percent,
        "project_id": target.project_id,
        "provider_response": response,
        "region": target.region,
        "schema_version": "controlgraph.traffic-fault-change/v1",
        "service_name": target.service_name,
        "stable_percent": stable_percent,
    }


def _service_iam_policy(run: core._HostedExecution) -> dict[str, Any]:
    value = core._gcloud_json(
        (
            "run",
            "services",
            "get-iam-policy",
            run.spec.target.service_name,
            f"--project={run.spec.target.project_id}",
            f"--region={run.spec.target.region}",
        ),
        repo=run.repo,
    )
    if not isinstance(value, dict):
        raise FaultAcceptanceError("FAULT_IAM_EVIDENCE_INVALID")
    _policy_bindings(value)
    return cast(dict[str, Any], value)


def _change_verifier_invoker(
    run: core._HostedExecution,
    *,
    action: str,
) -> None:
    if action not in {"add", "remove"}:
        raise FaultAcceptanceError("FAULT_IAM_EVIDENCE_INVALID")
    core._gcloud_json(
        (
            "run",
            "services",
            f"{action}-iam-policy-binding",
            run.spec.target.service_name,
            f"--project={run.spec.target.project_id}",
            f"--region={run.spec.target.region}",
            f"--member=serviceAccount:{run.verifier_service_account}",
            "--role=roles/run.invoker",
            "--quiet",
        ),
        repo=run.repo,
    )


def _verification_request(
    root_result: Any,
    apply_receipt: ExecutionReceiptReadResultV1,
    scenario: _Scenario,
    *,
    request_id: str | None = None,
) -> VerificationRequestV1:
    root = root_result.root
    plan = root.content.rollout_plan
    receipt = apply_receipt.receipt
    stable_percent, candidate_percent = {
        CapabilityAction.APPLY_CANARY: (90, 10),
        CapabilityAction.PROMOTE_CANDIDATE: (0, 100),
        CapabilityAction.RECOVER_STABLE: (100, 0),
    }[receipt.action]
    started = datetime.now(UTC).replace(microsecond=0)
    return VerificationRequestV1(
        schema_version=VERIFICATION_REQUEST_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=receipt.epoch,
        target=root.content.target,
        plan_sha256=canonical_sha256(plan),
        service_claim_sha256=root_result.winner_service_claim_sha256,
        probe_policy_sha256=canonical_sha256(
            fixed_probe_policy(stable_percent, candidate_percent)
        ),
        signed_intent_sha256=receipt.capability_sha256,
        action=receipt.action,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=stable_percent,
        candidate_percent=candidate_percent,
        concurrency=plan.concurrency,
        expected_stable_revision_configuration_sha256=(
            plan.stable_revision_configuration_sha256
        ),
        expected_candidate_revision_configuration_sha256=(
            plan.candidate_revision_configuration_sha256
        ),
        expected_target_configuration_sha256=receipt.expected_poststate_sha256,
        observation_window_started_at=core._utc(started),
        observation_window_ends_at=core._utc(started + timedelta(seconds=300)),
        request_id=request_id or scenario.request_id("verification"),
        correlation_id=scenario.correlation_id("verification"),
    )


def _coordinator_token(run: core._HostedExecution, audience: str) -> str:
    coordinator = (
        f"controlgraph-coordinator@{run.spec.target.project_id}.iam.gserviceaccount.com"
    )
    _, payload = core._capture_process(
        (
            "gcloud",
            "auth",
            "print-identity-token",
            f"--impersonate-service-account={coordinator}",
            f"--audiences={audience}",
            "--include-email",
        ),
        repo=run.repo,
        timeout=60,
    )
    try:
        token = payload.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise FaultAcceptanceError("FAULT_VERIFIER_IDENTITY_INVALID") from error
    claims = core._jwt_claims(token)
    if claims.get("email") != coordinator or claims.get("aud") != audience:
        raise FaultAcceptanceError("FAULT_VERIFIER_IDENTITY_INVALID")
    return token


def _invoke_verifier(
    state: _ExecutionState,
    *,
    root_result: Any,
    request: VerificationRequestV1,
    kind: IndependentVerificationKind,
) -> VerifiedIndependentVerificationEvidenceV1:
    invocation = IndependentVerificationInvocationV1(
        schema_version=INDEPENDENT_VERIFICATION_INVOCATION_V1,
        kind=kind,
        verification=request,
    )
    origin = _VERIFIER_ORIGIN.format(project_number=state.run.project_number)
    token = _coordinator_token(state.run, origin)
    try:
        status, payload, _headers = core._http_request(
            url=f"{origin}/v1/internal/verify",
            token=token,
            body=canonical_json_bytes(invocation),
        )
    finally:
        token = ""
    if status != 200:
        raise FaultAcceptanceError("FAULT_VERIFIER_INVOCATION_FAILED")
    try:
        attestation = decode_contract(payload, IndependentVerificationAttestationV1)
    except (ContractError, TypeError, ValueError, ValidationError) as error:
        raise FaultAcceptanceError("FAULT_VERIFIER_RESPONSE_INVALID") from error
    signed = attestation.signed_evidence
    if (
        attestation.signing_request.evidence.verification_request_sha256
        != canonical_sha256(request)
        or signed.signing_key_version
        != root_result.root.content.evidence_signing_key_version
    ):
        raise FaultAcceptanceError("FAULT_VERIFIER_RESPONSE_INVALID")
    verifier = GoogleKmsIndependentVerificationEvidenceVerifier(
        project_id=state.run.spec.target.project_id,
        service_role=ServiceRole.COORDINATOR,
        key_version=root_result.root.content.evidence_signing_key_version,
    )
    try:
        asyncio.run(verifier.verify(signed))
        return VerifiedIndependentVerificationEvidenceV1(
            schema_version=(
                "controlgraph.verified-independent-verification-evidence/v1"
            ),
            signing_request=attestation.signing_request,
            signed_evidence=signed,
            verified_at=max(core._utc_now(), signed.evidence.occurred_at),
        )
    except Exception as error:
        raise FaultAcceptanceError("FAULT_VERIFIER_SIGNATURE_INVALID") from error


def _execute_delayed_task(
    state: _ExecutionState,
    scenario: _Scenario,
    sequence: int,
) -> None:
    kind = FaultKind.DELAYED_TASK
    case = _fault_case(state.run.spec, scenario, sequence)
    root_result = core._create_root(state.run, case)
    _load, _apply, apply_receipt, health = core._health_load(
        state.run,
        case,
        mode="healthy",
        root_result=root_result,
    )
    before = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "delayed-before"),
    )
    core._require_split(before, state.run.spec, stable=90, candidate=10)
    held = False
    proof: EpochRevocationProofV1 | None = None
    try:
        queue_held = core._queue_control(state.run, "hold")
        held = True
        promotion, promotion_command = core._promote(
            state.run,
            case,
            root_result=root_result,
            apply_receipt=apply_receipt,
            terminal=health,
        )
        _revocation, proof = core._revoke(state.run, case, root_result.root)
        queue_released = core._queue_control(state.run, "release")
        held = False
        stale = core._poll_receipt(
            state.run,
            case,
            root=root_result.root,
            epoch=1,
            request_id=promotion_command.request_id,
            idempotency_key=promotion_command.idempotency_key,
            action="PROMOTE_CANDIDATE_V1",
            capability_sha256=promotion.capability_sha256,
            label="delayed-stale-promotion",
        )
        denied = cast(
            TargetTrafficReadResultV1,
            core._read_traffic(state.run, case, "delayed-denied"),
        )
        after = _recover_and_release(
            state,
            case,
            root_result=root_result,
            apply_receipt=apply_receipt,
            proof=proof,
            label="delayed",
        )
    finally:
        if held:
            if proof is None:
                state.cleanup_required.add("execution-queue")
            else:
                try:
                    queue_released = core._queue_control(state.run, "release")
                    held = False
                except core.AcceptanceError:
                    state.cleanup_required.add("execution-queue")
    _write_evidence(state, kind, "before-target.json", before)
    _write_evidence(state, kind, "denied-target.json", denied)
    _write_evidence(state, kind, "after-target.json", after)
    _write_evidence(state, kind, "revocation-proof.json", proof)
    _write_evidence(state, kind, "stale-receipt.json", stale)
    _write_evidence(state, kind, "queue-held.json", queue_held)
    _write_evidence(state, kind, "queue-released.json", queue_released)


def _execute_duplicate_delivery(
    state: _ExecutionState,
    scenario: _Scenario,
    sequence: int,
) -> None:
    kind = FaultKind.DUPLICATE_DELIVERY
    case = _fault_case(state.run.spec, scenario, sequence)
    root_result = core._create_root(state.run, case)
    _load, _apply, _apply_receipt, first = core._health_load(
        state.run,
        case,
        mode="unhealthy",
        root_result=root_result,
    )
    recovery = first.recovery_dispatch
    if recovery is None:
        raise FaultAcceptanceError("FAULT_DUPLICATE_RECOVERY_NOT_PROVEN")
    command_path = state.run.command_path(case, "health-second")
    command_payload = core._read_regular_file(
        command_path,
        maximum_bytes=MAX_CONTRACT_BYTES,
        error_code="FAULT_PRODUCT_EVIDENCE_INVALID",
    )
    try:
        from controlgraph_canary.contracts.health_pipeline import (
            HealthEvaluationCommandV1,
        )

        command = decode_contract(command_payload, HealthEvaluationCommandV1)
    except (ContractError, TypeError, ValueError, ValidationError) as error:
        raise FaultAcceptanceError("FAULT_PRODUCT_EVIDENCE_INVALID") from error
    duplicate = core._evaluate_health(
        state.run,
        case,
        command=command,
        label="duplicate",
    )
    first_payload = canonical_json_bytes(first)
    if first_payload != canonical_json_bytes(duplicate):
        raise FaultAcceptanceError("FAULT_DUPLICATE_RECOVERY_NOT_PROVEN")
    receipt = core._poll_receipt(
        state.run,
        case,
        root=root_result.root,
        epoch=1,
        request_id=recovery.request_id,
        idempotency_key=recovery.idempotency_key,
        action="RECOVER_STABLE_V1",
        capability_sha256=recovery.capability_sha256,
        label="duplicate-recovery",
    )
    if receipt.receipt.outcome is not ReceiptOutcome.VERIFIED:
        raise FaultAcceptanceError("FAULT_DUPLICATE_RECOVERY_NOT_PROVEN")
    after = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "duplicate-recovered"),
    )
    core._require_split(after, state.run.spec, stable=100, candidate=0)
    intent, query = _root_recovery_intent(state.run, root_result.root.root_id)
    core._release_claim(
        state.run,
        case,
        root=root_result.root,
        epoch=1,
        terminal_idempotency_key=recovery.idempotency_key,
        label="duplicate",
    )
    _write_evidence(state, kind, "after-target.json", after)
    _write_evidence(state, kind, "first-health-result.json", first)
    _write_evidence(state, kind, "duplicate-health-result.json", duplicate)
    _write_evidence(state, kind, "recovery-intent.json", intent)
    _write_evidence(state, kind, "recovery-intent-query.json", query)


def _execute_monitoring_gap(
    state: _ExecutionState,
    scenario: _Scenario,
    sequence: int,
) -> None:
    kind = FaultKind.MONITORING_GAP
    case = _fault_case(state.run.spec, scenario, sequence)
    root_result = core._create_root(state.run, case)
    _dispatch, apply_receipt = core._apply_canary(state.run, case, root_result)
    before = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "monitoring-gap-before"),
    )
    core._require_split(before, state.run.spec, stable=90, candidate=10)
    receipt_time = core._parse_utc(apply_receipt.receipt.updated_at)
    anchor = receipt_time.replace(second=0, microsecond=0) + timedelta(minutes=1)
    _wait_until(anchor + timedelta(seconds=245))
    command = core._health_command(
        state.run,
        case,
        root_result=root_result,
        apply_receipt=apply_receipt,
        ordinal=1,
        expected_sequence=0,
        expected_chain_head_sha256=None,
    )
    health = core._evaluate_health(
        state.run,
        case,
        command=command,
        label="monitoring-gap",
    )
    if health.terminal_status is not HealthDecisionStatus.INSUFFICIENT_EVIDENCE:
        raise FaultAcceptanceError("FAULT_MONITORING_GAP_NOT_PROVEN")
    signed = _signed_health_proof(
        state.run,
        root_id=root_result.root.root_id,
        signed_sha256=health.chain_head_sha256,
    )
    after = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "monitoring-gap-after"),
    )
    core._require_split(after, state.run.spec, stable=90, candidate=10)
    _revocation, proof = core._revoke(state.run, case, root_result.root)
    _recover_and_release(
        state,
        case,
        root_result=root_result,
        apply_receipt=apply_receipt,
        proof=proof,
        label="monitoring-gap",
    )
    _write_evidence(state, kind, "before-target.json", before)
    _write_evidence(state, kind, "after-target.json", after)
    _write_evidence(state, kind, "health-result.json", health)
    _write_evidence(state, kind, "signed-health-proof.json", signed)


def _build_promotion_command(
    state: _ExecutionState,
    case: core.CaseBindingV1,
    *,
    root_result: Any,
    apply_receipt: Any,
    health: HealthEvaluationResultV2,
) -> PromotionCommandV2:
    from controlgraph_canary.contracts.promotion_execution import PROMOTION_COMMAND_V2

    if health.promotion_health_chain is None:
        raise FaultAcceptanceError("FAULT_TIMEOUT_AMBIGUITY_NOT_PROVEN")
    return PromotionCommandV2(
        schema_version=PROMOTION_COMMAND_V2,
        root_id=root_result.root.root_id,
        expected_root_sha256=root_result.root.root_sha256,
        expected_epoch=1,
        request_id=core._stable_id(
            state.run.run_inputs_sha256, case, "promotion-request"
        ),
        idempotency_key=core._stable_id(
            state.run.run_inputs_sha256, case, "promotion-idempotency"
        ),
        scheduled_at=core._utc(datetime.now(UTC) + timedelta(seconds=10)),
        verified_apply_receipt=apply_receipt.verified_apply_receipt,
        health_chain_locator=health.promotion_health_chain,
    )


def _one_timed_operator_request(
    run: core._HostedExecution,
    command: PromotionCommandV2,
) -> tuple[int, bytes, dict[str, str]]:
    body = canonical_json_bytes(command)
    token = core._identity_token(run)
    started = threading.Event()

    def send() -> tuple[int, bytes, dict[str, str]]:
        started.set()
        return core._http_request(
            url=f"{run.api_origin}/v1/operator/commands",
            token=token,
            operator=True,
            body=body,
        )

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(send)
            if not started.wait(timeout=5):
                raise FaultAcceptanceError("FAULT_API_TIMEOUT_NOT_REPRODUCED")
            try:
                future.result(timeout=0.001)
            except concurrent.futures.TimeoutError:
                pass
            else:
                raise FaultAcceptanceError("FAULT_API_TIMEOUT_NOT_REPRODUCED")
            return future.result(timeout=45)
    finally:
        token = ""


def _execute_api_timeout(
    state: _ExecutionState,
    scenario: _Scenario,
    sequence: int,
) -> None:
    kind = FaultKind.API_TIMEOUT
    case = _fault_case(state.run.spec, scenario, sequence)
    root_result = core._create_root(state.run, case)
    _load, _apply, apply_receipt, health = core._health_load(
        state.run,
        case,
        mode="healthy",
        root_result=root_result,
    )
    before = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "api-timeout-before"),
    )
    core._require_split(before, state.run.spec, stable=90, candidate=10)
    command = _build_promotion_command(
        state,
        case,
        root_result=root_result,
        apply_receipt=apply_receipt,
        health=health,
    )
    status, response, headers = _one_timed_operator_request(state.run, command)
    if status != 200 or headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise FaultAcceptanceError("FAULT_API_TIMEOUT_FOLLOW_UP_INVALID")
    try:
        from controlgraph_canary.contracts.promotion_execution import (
            PromotionDispatchResultV2,
        )

        dispatch = decode_contract(response, PromotionDispatchResultV2)
    except (ContractError, TypeError, ValueError, ValidationError) as error:
        raise FaultAcceptanceError("FAULT_API_TIMEOUT_FOLLOW_UP_INVALID") from error
    if (
        dispatch.request_id != command.request_id
        or dispatch.idempotency_key != command.idempotency_key
        or dispatch.root_id != command.root_id
        or dispatch.root_sha256 != command.expected_root_sha256
        or dispatch.epoch != command.expected_epoch
    ):
        raise FaultAcceptanceError("FAULT_API_TIMEOUT_FOLLOW_UP_INVALID")
    observed = core._poll_receipt(
        state.run,
        case,
        root=root_result.root,
        epoch=1,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        action="PROMOTE_CANDIDATE_V1",
        capability_sha256=dispatch.capability_sha256,
        label="api-timeout-promotion",
    )
    if observed.receipt.outcome is not ReceiptOutcome.VERIFIED:
        raise FaultAcceptanceError("FAULT_API_TIMEOUT_FOLLOW_UP_INVALID")
    readback = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "api-timeout-readback"),
    )
    core._require_split(readback, state.run.spec, stable=0, candidate=100)
    verification = _verification_request(
        root_result,
        observed,
        scenario,
        request_id=observed.receipt.request_id,
    )
    assessment = CompletionAssessmentRequestV1(
        schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
        kind=CompletionKind.PROMOTION,
        verification=verification,
        assessed_at=core._utc_now(),
    )
    bundle = CompletionEvidenceBundleV1(
        schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
        request=assessment,
    )
    bundle_path = state.run.command_path(case, "api-timeout-bundle")
    core._write_command(bundle_path, bundle)
    _status, _payload, classification = core._run_cli(
        repo=state.run.repo,
        entry_point="controlgraph-canary",
        arguments=("classify-completion", "--bundle-file", str(bundle_path)),
        model_type=CompletionClassificationV1,
    )
    if classification is None:
        raise FaultAcceptanceError("FAULT_TIMEOUT_AMBIGUITY_NOT_PROVEN")
    core._release_claim(
        state.run,
        case,
        root=root_result.root,
        epoch=1,
        terminal_idempotency_key=command.idempotency_key,
        label="api-timeout",
    )
    after = cast(TargetTrafficReadResultV1, core._reset_target(state.run, case))
    timeout = {
        "attempt_count": 1,
        "deadline_milliseconds": 1,
        "outcome": "TIMEOUT",
        "request_id": command.request_id,
        "request_sha256": canonical_sha256(command),
        "retry_count": 0,
        "schema_version": "controlgraph.fault-client-timeout/v1",
    }
    _write_evidence(state, kind, "before-target.json", before)
    _write_evidence(state, kind, "readback-target.json", readback)
    _write_evidence(state, kind, "after-target.json", after)
    _write_evidence(state, kind, "promotion-command.json", command)
    _write_evidence(state, kind, "receipt.json", observed)
    _write_evidence(state, kind, "completion-bundle.json", bundle)
    _write_evidence(state, kind, "classification.json", classification)
    _write_evidence(state, kind, "client-timeout.json", timeout)


def _execute_configuration_drift(
    state: _ExecutionState,
    scenario: _Scenario,
    sequence: int,
) -> None:
    kind = FaultKind.CONFIGURATION_DRIFT
    case = _fault_case(state.run.spec, scenario, sequence)
    root_result = core._create_root(state.run, case)
    _apply, apply_receipt = core._apply_canary(state.run, case, root_result)
    before = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "drift-before"),
    )
    core._require_split(before, state.run.spec, stable=90, candidate=10)
    restored = False
    try:
        drift_change = _traffic_mutation(
            state,
            stable_percent=100,
            candidate_percent=0,
        )
        drifted = cast(
            TargetTrafficReadResultV1,
            core._read_traffic(state.run, case, "drifted"),
        )
        core._require_split(drifted, state.run.spec, stable=100, candidate=0)
        request = _verification_request(root_result, apply_receipt, scenario)
        verified = _invoke_verifier(
            state,
            root_result=root_result,
            request=request,
            kind=IndependentVerificationKind.CONFIGURATION,
        )
    finally:
        try:
            restore_change = _traffic_mutation(
                state,
                stable_percent=90,
                candidate_percent=10,
            )
            after = cast(
                TargetTrafficReadResultV1,
                core._read_traffic(state.run, case, "drift-restored"),
            )
            if _state(before) != _state(after):
                raise FaultAcceptanceError("FAULT_CONFIGURATION_RESTORE_FAILED")
            restored = True
        except (FaultAcceptanceError, core.AcceptanceError):
            state.cleanup_required.add("reference-target-traffic")
            raise
    if not restored:
        raise FaultAcceptanceError("FAULT_CONFIGURATION_RESTORE_FAILED")
    _revocation, proof = core._revoke(state.run, case, root_result.root)
    _recover_and_release(
        state,
        case,
        root_result=root_result,
        apply_receipt=apply_receipt,
        proof=proof,
        label="drift",
    )
    _write_evidence(state, kind, "before-target.json", before)
    _write_evidence(state, kind, "drifted-target.json", drifted)
    _write_evidence(state, kind, "after-target.json", after)
    _write_evidence(state, kind, "verification.json", verified)
    _write_evidence(state, kind, "drift-update.json", drift_change)
    _write_evidence(state, kind, "drift-restore.json", restore_change)


def _execute_probe_failure(
    state: _ExecutionState,
    scenario: _Scenario,
    sequence: int,
) -> None:
    kind = FaultKind.PROBE_FAILURE
    case = _fault_case(state.run.spec, scenario, sequence)
    root_result = core._create_root(state.run, case)
    _apply, apply_receipt = core._apply_canary(state.run, case, root_result)
    before = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "probe-failure-before"),
    )
    core._require_split(before, state.run.spec, stable=90, candidate=10)
    iam_before = _service_iam_policy(state.run)
    verifier_member = f"serviceAccount:{state.run.verifier_service_account}"
    _remove_member(_policy_bindings(iam_before), "roles/run.invoker", verifier_member)
    removed = False
    try:
        _change_verifier_invoker(state.run, action="remove")
        removed = True
        iam_denied = _service_iam_policy(state.run)
        if _policy_bindings(iam_denied) != _remove_member(
            _policy_bindings(iam_before),
            "roles/run.invoker",
            verifier_member,
        ):
            raise FaultAcceptanceError("FAULT_IAM_EVIDENCE_INVALID")
        request = _verification_request(root_result, apply_receipt, scenario)
        verified = _invoke_verifier(
            state,
            root_result=root_result,
            request=request,
            kind=IndependentVerificationKind.PROBE,
        )
    finally:
        if removed:
            try:
                _change_verifier_invoker(state.run, action="add")
                iam_after = _service_iam_policy(state.run)
                if _policy_bindings(iam_after) != _policy_bindings(iam_before):
                    raise FaultAcceptanceError("FAULT_IAM_RESTORE_FAILED")
            except (FaultAcceptanceError, core.AcceptanceError):
                state.cleanup_required.add("reference-target-run-invoker")
                raise
    after = cast(
        TargetTrafficReadResultV1,
        core._read_traffic(state.run, case, "probe-failure-after"),
    )
    if _state(before) != _state(after):
        raise FaultAcceptanceError("FAULT_PROBE_FAILURE_NOT_PROVEN")
    _revocation, proof = core._revoke(state.run, case, root_result.root)
    _recover_and_release(
        state,
        case,
        root_result=root_result,
        apply_receipt=apply_receipt,
        proof=proof,
        label="probe-failure",
    )
    _write_evidence(state, kind, "before-target.json", before)
    _write_evidence(state, kind, "after-target.json", after)
    _write_evidence(state, kind, "verification.json", verified)
    _write_evidence(state, kind, "iam-before.json", iam_before)
    _write_evidence(state, kind, "iam-denied.json", iam_denied)
    _write_evidence(state, kind, "iam-after.json", iam_after)


def _execute_revocation_race(
    state: _ExecutionState,
    base_scenario: _Scenario,
    sequence: int,
) -> _Scenario:
    kind = FaultKind.REVOCATION_RACE
    for attempt in range(1, 4):
        scenario = _race_scenario(base_scenario, attempt)
        case = _fault_case(state.run.spec, scenario, sequence)
        core._reset_target(state.run, case)
        root_result = core._create_root(state.run, case)
        _load, _apply, apply_receipt, health = core._health_load(
            state.run,
            case,
            mode="healthy",
            root_result=root_result,
        )
        before = cast(
            TargetTrafficReadResultV1,
            core._read_traffic(state.run, case, f"race-{attempt}-before"),
        )
        core._require_split(before, state.run.spec, stable=90, candidate=10)
        queue_held = core._queue_control(state.run, "hold")
        state.cleanup_required.add("execution-queue")
        promotion, promotion_command = core._promote(
            state.run,
            case,
            root_result=root_result,
            apply_receipt=apply_receipt,
            terminal=health,
        )
        _wait_until(core._parse_utc(promotion_command.scheduled_at) + timedelta(seconds=1))
        barrier = threading.Barrier(2)

        def release_queue(race_barrier: threading.Barrier = barrier) -> dict[str, Any]:
            race_barrier.wait(timeout=5)
            return core._queue_control(state.run, "release")

        def revoke_epoch(
            race_barrier: threading.Barrier = barrier,
            race_case: core.CaseBindingV1 = case,
            race_root: Any = root_result.root,
        ) -> tuple[Any, EpochRevocationProofV1]:
            race_barrier.wait(timeout=5)
            return core._revoke(state.run, race_case, race_root)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                release_future = executor.submit(release_queue)
                revoke_future = executor.submit(revoke_epoch)
                queue_released = release_future.result(timeout=90)
                _revocation, proof = revoke_future.result(timeout=90)
            state.cleanup_required.discard("execution-queue")
        except Exception as error:
            state.cleanup_required.add("execution-queue")
            state.cleanup_required.add(root_result.root.root_id)
            raise FaultAcceptanceError("FAULT_REVOCATION_RACE_UNRESOLVED") from error
        stale = core._poll_receipt(
            state.run,
            case,
            root=root_result.root,
            epoch=1,
            request_id=promotion_command.request_id,
            idempotency_key=promotion_command.idempotency_key,
            action="PROMOTE_CANDIDATE_V1",
            capability_sha256=promotion.capability_sha256,
            label=f"race-{attempt}-promotion",
        )
        denied = cast(
            TargetTrafficReadResultV1,
            core._read_traffic(state.run, case, f"race-{attempt}-terminal"),
        )
        receipt = stale.receipt
        is_race = (
            receipt.outcome is ReceiptOutcome.DENIED
            and receipt.reason_code is ReasonCode.EPOCH_MISMATCH
            and receipt.created_at <= proof.result.committed_at <= receipt.updated_at
        )
        if receipt.outcome is ReceiptOutcome.DENIED:
            after = _recover_and_release(
                state,
                case,
                root_result=root_result,
                apply_receipt=apply_receipt,
                proof=proof,
                label=f"race-{attempt}",
            )
        elif receipt.outcome is ReceiptOutcome.VERIFIED:
            core._release_claim(
                state.run,
                case,
                root=root_result.root,
                epoch=2,
                terminal_idempotency_key=promotion_command.idempotency_key,
                label=f"race-{attempt}-promoted",
            )
            after = cast(TargetTrafficReadResultV1, core._reset_target(state.run, case))
        else:
            state.cleanup_required.add(root_result.root.root_id)
            raise FaultAcceptanceError("FAULT_REVOCATION_RACE_UNRESOLVED")
        if not is_race:
            core._reset_target(state.run, case)
            continue
        _write_evidence(state, kind, "before-target.json", before)
        _write_evidence(state, kind, "denied-target.json", denied)
        _write_evidence(state, kind, "after-target.json", after)
        _write_evidence(state, kind, "revocation-proof.json", proof)
        _write_evidence(state, kind, "stale-receipt.json", stale)
        _write_evidence(state, kind, "queue-held.json", queue_held)
        _write_evidence(state, kind, "queue-released.json", queue_released)
        _write_evidence(
            state,
            kind,
            "race-attempt.json",
            {
                "attempt": attempt,
                "maximum_attempts": 3,
                "scenario_id": scenario.scenario_id,
                "schema_version": "controlgraph.revocation-race-attempt/v1",
            },
        )
        return scenario
    raise FaultAcceptanceError("FAULT_REVOCATION_RACE_NOT_REPRODUCED")


def _verify_source(repo: Path, source_commit: str) -> None:
    if _COMMIT.fullmatch(source_commit) is None:
        raise FaultAcceptanceError("FAULT_SOURCE_INVALID")
    try:
        root = repo.resolve(strict=True)
    except OSError as error:
        raise FaultAcceptanceError("FAULT_SOURCE_INVALID") from error

    def git(*arguments: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ("git", "-C", str(root), *arguments),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise FaultAcceptanceError("FAULT_SOURCE_INVALID") from error

    top = git("rev-parse", "--show-toplevel")
    head = git("rev-parse", "HEAD")
    dirty = git("status", "--porcelain=v1")
    local_main = git("rev-parse", "origin/main")
    remote_main = git("ls-remote", "origin", "refs/heads/main", timeout=30)
    package_file = getattr(controlgraph_canary, "__file__", None)
    try:
        package_path = Path(package_file).resolve(strict=True) if package_file else None
        expected_package = (root / "backend/src/controlgraph_canary/__init__.py").resolve(
            strict=True
        )
        script_path = Path(__file__).resolve(strict=True)
        expected_script = (root / "scripts/fault_acceptance.py").resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise FaultAcceptanceError("FAULT_SOURCE_INVALID") from error
    if (
        not root.is_dir()
        or any(item.returncode != 0 for item in (top, head, dirty, local_main, remote_main))
        or Path(top.stdout.strip()).resolve() != root
        or head.stdout.strip() != source_commit
        or dirty.stdout
        or local_main.stdout.strip() != source_commit
        or not remote_main.stdout.startswith(f"{source_commit}\t")
        or package_path != expected_package
        or script_path != expected_script
    ):
        raise FaultAcceptanceError("FAULT_SOURCE_NOT_EXACT_MAIN")


def _active_identity(repo: Path) -> str:
    try:
        completed = subprocess.run(
            (
                "gcloud",
                "auth",
                "list",
                "--filter=status:ACTIVE",
                "--format=json",
            ),
            cwd=repo,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        value = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise FaultAcceptanceError("FAULT_ACTIVATION_IDENTITY_INVALID") from error
    if (
        completed.returncode != 0
        or not isinstance(value, list)
        or len(value) != 1
        or not isinstance(value[0], dict)
        or not isinstance(value[0].get("account"), str)
    ):
        raise FaultAcceptanceError("FAULT_ACTIVATION_IDENTITY_INVALID")
    return cast(str, value[0]["account"])


def _load_core_bridge(
    *,
    spec_path: Path,
    manifest_path: Path,
    artifact_root: Path,
) -> _CoreBridge:
    _spec_payload, spec = core._load_contract(
        spec_path,
        core.CoreAcceptanceRunSpecV1,
        error_code="FAULT_CORE_SPEC_INVALID",
    )
    expected, run_id, status = core.build_manifest(
        spec_path=spec_path,
        artifact_root=artifact_root,
    )
    actual = core._read_regular_file(
        manifest_path,
        maximum_bytes=core.MAX_ARTIFACT_BYTES,
        error_code="FAULT_CORE_MANIFEST_INVALID",
    )
    if status is not core.ResultStatus.PASSED or actual != expected:
        raise FaultAcceptanceError("FAULT_CORE_MANIFEST_INVALID")
    return _CoreBridge(
        spec=spec,
        run_id=run_id,
        run_inputs_sha256=core._run_inputs_sha256(spec),
        manifest_sha256=hashlib.sha256(actual).hexdigest(),
    )


def _create_evidence_root(path: Path, repo: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise FaultAcceptanceError("FAULT_OUTPUT_INVALID")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise FaultAcceptanceError("FAULT_OUTPUT_INVALID") from error
    if parent.is_relative_to(repo):
        raise FaultAcceptanceError("FAULT_OUTPUT_INVALID")
    try:
        path.mkdir(mode=0o700)
        resolved = path.resolve(strict=True)
        for kind in FaultKind:
            (resolved / kind.value.lower().replace("_", "-")).mkdir(mode=0o700)
    except OSError as error:
        raise FaultAcceptanceError("FAULT_OUTPUT_INVALID") from error
    return resolved


def execute_fault_suite(
    *,
    core_spec: Path,
    core_manifest: Path,
    core_artifact_root: Path,
    evidence_root: Path,
    output: Path,
    project_number: str,
    network_resource: str,
    subnetwork_resource: str,
    verifier_service_account: str,
    restricted_exporter_service_account: str,
    acceptance_identity: str,
    confirmation: str,
) -> bytes:
    if (
        confirmation != CONFIRMATION
        or os.environ.get(CONFIRMATION_ENV) != CONFIRMATION
    ):
        raise FaultAcceptanceError("FAULT_CONFIRMATION_REQUIRED")
    if re.fullmatch(r"[1-9][0-9]{5,19}", project_number) is None:
        raise FaultAcceptanceError("FAULT_RUN_BINDING_INVALID")
    repo = Path(__file__).resolve().parents[1]
    bridge = _load_core_bridge(
        spec_path=core_spec,
        manifest_path=core_manifest,
        artifact_root=core_artifact_root,
    )
    _verify_source(repo, bridge.spec.source_commit)
    core._validate_execute_destination(output, repo)
    root = _create_evidence_root(evidence_root, repo)
    fault_inputs_sha256 = hashlib.sha256(
        _FAULT_INPUT_DOMAIN
        + bytes.fromhex(bridge.run_inputs_sha256)
        + bytes.fromhex(bridge.manifest_sha256)
    ).hexdigest()
    run = core._HostedExecution(
        repo=repo,
        artifact_root=root,
        spec=bridge.spec,
        run_inputs_sha256=fault_inputs_sha256,
        project_number=project_number,
        network_resource=network_resource,
        subnetwork_resource=subnetwork_resource,
        verifier_service_account=verifier_service_account,
        restricted_exporter_service_account=restricted_exporter_service_account,
        acceptance_identity=acceptance_identity,
    )
    core._verify_hosted_bindings(run)
    state = _ExecutionState(run=run, evidence_root=root, cleanup_required=set())
    for sequence, kind in enumerate(FaultKind, start=1):
        scenario = _scenario(bridge.spec.random_seed, kind, fault_inputs_sha256)
        case = _fault_case(bridge.spec, scenario, sequence)
        if kind is not FaultKind.REVOCATION_RACE:
            core._reset_target(run, case)
        if kind is FaultKind.DELAYED_TASK:
            _execute_delayed_task(state, scenario, sequence)
        elif kind is FaultKind.DUPLICATE_DELIVERY:
            _execute_duplicate_delivery(state, scenario, sequence)
        elif kind is FaultKind.REVOCATION_RACE:
            _execute_revocation_race(state, scenario, sequence)
        elif kind is FaultKind.MONITORING_GAP:
            _execute_monitoring_gap(state, scenario, sequence)
        elif kind is FaultKind.API_TIMEOUT:
            _execute_api_timeout(state, scenario, sequence)
        elif kind is FaultKind.CONFIGURATION_DRIFT:
            _execute_configuration_drift(state, scenario, sequence)
        else:
            _execute_probe_failure(state, scenario, sequence)
    if state.cleanup_required:
        raise FaultAcceptanceError("FAULT_CLEANUP_REQUIRED")
    payload = bind_fault_suite(
        evidence_root=root,
        run_seed=bridge.spec.random_seed,
        project_id=bridge.spec.target.project_id,
        stable_revision=bridge.spec.target.stable_revision,
        candidate_revision=bridge.spec.target.candidate_revision,
        acceptance_identity=acceptance_identity,
        active_identity=_active_identity(repo),
        source_commit=bridge.spec.source_commit,
        core_run_id=bridge.run_id,
        core_run_inputs_sha256=bridge.run_inputs_sha256,
        core_manifest_sha256=bridge.manifest_sha256,
        fault_run_inputs_sha256=fault_inputs_sha256,
    )
    core._write_once(output, payload)
    return payload


def bind_fault_suite(
    *,
    evidence_root: Path,
    run_seed: int,
    project_id: str,
    stable_revision: str,
    candidate_revision: str,
    acceptance_identity: str,
    active_identity: str,
    source_commit: str,
    core_run_id: str,
    core_run_inputs_sha256: str,
    core_manifest_sha256: str,
    fault_run_inputs_sha256: str,
) -> bytes:
    if (
        type(run_seed) is not int
        or not 0 <= run_seed <= MAX_SAFE_INTEGER
        or _PROJECT.fullmatch(project_id) is None
        or "reconcile" in project_id
        or _REVISION.fullmatch(stable_revision) is None
        or _REVISION.fullmatch(candidate_revision) is None
        or stable_revision == candidate_revision
        or not stable_revision.startswith(f"{SERVICE}-")
        or not candidate_revision.startswith(f"{SERVICE}-")
        or _IDENTITY.fullmatch(acceptance_identity) is None
        or acceptance_identity.endswith(".iam.gserviceaccount.com")
        or active_identity != acceptance_identity
        or _COMMIT.fullmatch(source_commit) is None
        or re.fullmatch(r"cgacceptance:[0-9a-f]{64}", core_run_id) is None
        or any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in (
                core_run_inputs_sha256,
                core_manifest_sha256,
                fault_run_inputs_sha256,
            )
        )
        or fault_run_inputs_sha256
        != hashlib.sha256(
            _FAULT_INPUT_DOMAIN
            + bytes.fromhex(core_run_inputs_sha256)
            + bytes.fromhex(core_manifest_sha256)
        ).hexdigest()
    ):
        raise FaultAcceptanceError("FAULT_RUN_BINDING_INVALID")
    try:
        target = TargetBinding(
            schema_version="controlgraph.target-binding/v1",
            project_id=project_id,
            region=REGION,
            environment=ENVIRONMENT,
            service_name=SERVICE,
        )
    except ValidationError as error:
        raise FaultAcceptanceError("FAULT_RUN_BINDING_INVALID") from error
    cases: list[RestrictedJson] = []
    root_ids: set[str] = set()
    for kind in FaultKind:
        artifacts = _artifacts(evidence_root, kind)
        scenario = _scenario(run_seed, kind, fault_run_inputs_sha256)
        if kind is FaultKind.REVOCATION_RACE:
            attempt = _raw(artifacts, "race-attempt.json").get("attempt")
            if type(attempt) is not int:
                raise FaultAcceptanceError("FAULT_RACE_ATTEMPT_INVALID")
            scenario = _race_scenario(scenario, attempt)
        ctx = _Context(
            target=target,
            stable_revision=stable_revision,
            candidate_revision=candidate_revision,
            acceptance_identity=acceptance_identity,
            scenario=scenario,
        )
        derived = _evaluate(ctx, artifacts)
        if derived.root_id in root_ids:
            raise FaultAcceptanceError("FAULT_SCENARIO_EVIDENCE_REUSED")
        root_ids.add(derived.root_id)
        cases.append(
            {
                "artifacts": [
                    {
                        "name": item.name,
                        "relative_path": (
                            f"{kind.value.lower().replace('_', '-')}/{item.name}"
                        ),
                        "sha256": hashlib.sha256(item.payload).hexdigest(),
                    }
                    for item in artifacts.values()
                ],
                "boundary": scenario.boundary,
                "fault": kind.value,
                "injection": scenario.injection,
                "observed_invariants": [item.value for item in derived.invariants],
                "observation": dict(derived.observation),
                "random_seed": scenario.random_seed,
                "result": "PASSED",
                "root_id": derived.root_id,
                "scenario_id": scenario.scenario_id,
            }
        )
    principal_sha256 = hashlib.sha256(
        _IDENTITY_DOMAIN + acceptance_identity.encode("utf-8")
    ).hexdigest()
    manifest: RestrictedJson = {
        "acceptance_principal_sha256": principal_sha256,
        "allowlisted_faults": [kind.value for kind in FaultKind],
        "cases": cases,
        "environment": ENVIRONMENT,
        "project_id": project_id,
        "purpose": "PRODUCT_VALIDATION",
        "region": REGION,
        "result": "PASSED",
        "run_seed": run_seed,
        "schema_version": MANIFEST_SCHEMA,
        "service_name": SERVICE,
        "source_commit": source_commit,
        "stable_revision": stable_revision,
        "candidate_revision": candidate_revision,
        "core_manifest_sha256": core_manifest_sha256,
        "core_run_id": core_run_id,
        "core_run_inputs_sha256": core_run_inputs_sha256,
        "fault_run_inputs_sha256": fault_run_inputs_sha256,
    }
    return canonical_json_value_bytes(manifest)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Execute seven fixed faults against the isolated target and bind the evidence."
        )
    )
    parser.add_argument("--core-spec", required=True, type=Path)
    parser.add_argument("--core-manifest", required=True, type=Path)
    parser.add_argument("--core-artifact-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--project-number", required=True)
    parser.add_argument("--network-resource", required=True)
    parser.add_argument("--subnetwork-resource", required=True)
    parser.add_argument("--verifier-service-account", required=True)
    parser.add_argument("--restricted-exporter-service-account", required=True)
    parser.add_argument("--acceptance-identity", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--confirm", required=True, choices=(CONFIRMATION,))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "execute":
        arguments = arguments[1:]
    args = _parser().parse_args(arguments)
    try:
        payload = execute_fault_suite(
            core_spec=args.core_spec,
            core_manifest=args.core_manifest,
            core_artifact_root=args.core_artifact_root,
            evidence_root=args.evidence_root,
            output=args.output,
            project_number=args.project_number,
            network_resource=args.network_resource,
            subnetwork_resource=args.subnetwork_resource,
            verifier_service_account=args.verifier_service_account,
            restricted_exporter_service_account=args.restricted_exporter_service_account,
            acceptance_identity=args.acceptance_identity,
            confirmation=args.confirm,
        )
    except (FaultAcceptanceError, core.AcceptanceError, OSError) as error:
        code = (
            error.code
            if isinstance(error, (FaultAcceptanceError, core.AcceptanceError))
            else "FAULT_OUTPUT_INVALID"
        )
        print(json.dumps({"code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(payload.decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
