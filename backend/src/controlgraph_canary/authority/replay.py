"""Pure idempotency, replay, and no-blind-retry decisions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final

from controlgraph_canary.authority.reducer import DenialReason

MUTATION_IDENTITY_DOMAIN: Final = b"controlgraph.mutation-identity/v1\0"
MAX_PRE_DISPATCH_TRANSPORT_ATTEMPTS: Final = 3
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _require_text(name: str, value: object, *, maximum: int = 512) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name} must be bounded nonblank text")


def _require_sha256(name: str, value: object) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


class MutationAction(StrEnum):
    """Closed mutations that may receive an execution receipt."""

    APPLY_CANARY = "APPLY_CANARY_V1"
    PROMOTE_CANDIDATE = "PROMOTE_CANDIDATE_V1"
    RECOVER_STABLE = "RECOVER_STABLE_V1"


@dataclass(frozen=True, slots=True)
class MutationTargetKey:
    """Exact service coordinates included in mutation identity."""

    project_id: str
    region: str
    environment: str
    service_name: str

    def __post_init__(self) -> None:
        _require_text("project_id", self.project_id, maximum=128)
        _require_text("region", self.region, maximum=64)
        _require_text("environment", self.environment, maximum=128)
        _require_text("service_name", self.service_name, maximum=128)


@dataclass(frozen=True, slots=True)
class MutationBinding:
    """Complete immutable binding owned by one idempotency key."""

    idempotency_key: str
    request_id: str
    root_id: str
    root_sha256: str
    epoch: int
    action: MutationAction
    target: MutationTargetKey
    provider_precondition: str
    plan_sha256: str
    capability_sha256: str
    payload_sha256: str
    expected_poststate_sha256: str

    def __post_init__(self) -> None:
        _require_text("idempotency_key", self.idempotency_key, maximum=128)
        _require_text("request_id", self.request_id, maximum=128)
        _require_text("root_id", self.root_id, maximum=128)
        _require_sha256("root_sha256", self.root_sha256)
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("epoch must be a positive integer")
        if not isinstance(self.action, MutationAction):
            raise ValueError("action must be a closed mutation action")
        if not isinstance(self.target, MutationTargetKey):
            raise ValueError("target must be an exact mutation target key")
        _require_text("provider_precondition", self.provider_precondition)
        _require_sha256("plan_sha256", self.plan_sha256)
        _require_sha256("capability_sha256", self.capability_sha256)
        _require_sha256("payload_sha256", self.payload_sha256)
        _require_sha256("expected_poststate_sha256", self.expected_poststate_sha256)


def mutation_identity(binding: MutationBinding) -> str:
    """Return one domain-separated identity for an exact mutation binding."""

    if not isinstance(binding, MutationBinding):
        raise TypeError("binding must be a MutationBinding")
    value = {
        "action": binding.action.value,
        "capability_sha256": binding.capability_sha256,
        "epoch": binding.epoch,
        "expected_poststate_sha256": binding.expected_poststate_sha256,
        "idempotency_key": binding.idempotency_key,
        "payload_sha256": binding.payload_sha256,
        "plan_sha256": binding.plan_sha256,
        "provider_precondition": binding.provider_precondition,
        "request_id": binding.request_id,
        "root_id": binding.root_id,
        "root_sha256": binding.root_sha256,
        "schema_version": "controlgraph.mutation-identity/v1",
        "target": {
            "environment": binding.target.environment,
            "project_id": binding.target.project_id,
            "region": binding.target.region,
            "service_name": binding.target.service_name,
        },
    }
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(MUTATION_IDENTITY_DOMAIN + encoded).hexdigest()


class ReceiptPhase(StrEnum):
    """Durable phases that determine whether exact work may resume."""

    PRE_DISPATCH_CLAIMED = "PRE_DISPATCH_CLAIMED"
    PROVIDER_ATTEMPTED = "PROVIDER_ATTEMPTED"
    READBACK_REQUIRED = "READBACK_REQUIRED"
    TERMINAL = "TERMINAL"


class ReplayReceiptOutcome(StrEnum):
    """Execution classification stored with the replay phase."""

    CLAIMED = "CLAIMED"
    DENIED = "DENIED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class ReplayReceipt:
    """Pure durable receipt state for one exact mutation binding."""

    binding: MutationBinding
    phase: ReceiptPhase
    outcome: ReplayReceiptOutcome
    reason: DenialReason | None = None
    result_sha256: str | None = None
    readback_attempted: bool = False
    pre_dispatch_attempts: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.binding, MutationBinding):
            raise ValueError("binding must be a MutationBinding")
        if not isinstance(self.phase, ReceiptPhase):
            raise ValueError("phase must be a ReceiptPhase")
        if not isinstance(self.outcome, ReplayReceiptOutcome):
            raise ValueError("outcome must be a ReplayReceiptOutcome")
        if self.reason is not None and not isinstance(self.reason, DenialReason):
            raise ValueError("reason must be a stable denial reason")
        if self.result_sha256 is not None:
            _require_sha256("result_sha256", self.result_sha256)
        if type(self.readback_attempted) is not bool:
            raise ValueError("readback_attempted must be a boolean")
        if (
            type(self.pre_dispatch_attempts) is not int
            or not 0 <= self.pre_dispatch_attempts <= MAX_PRE_DISPATCH_TRANSPORT_ATTEMPTS
        ):
            raise ValueError("pre_dispatch_attempts is outside the durable retry bound")
        self._validate_shape()

    def _validate_shape(self) -> None:
        if self.phase is ReceiptPhase.PRE_DISPATCH_CLAIMED:
            if (
                self.outcome is not ReplayReceiptOutcome.CLAIMED
                or self.reason is not None
                or self.result_sha256 is not None
                or self.readback_attempted
                or self.pre_dispatch_attempts >= MAX_PRE_DISPATCH_TRANSPORT_ATTEMPTS
            ):
                raise ValueError("pre-dispatch receipt shape is invalid")
            return
        if self.phase is ReceiptPhase.PROVIDER_ATTEMPTED:
            if (
                self.outcome is not ReplayReceiptOutcome.AMBIGUOUS
                or self.reason is not DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
                or self.result_sha256 is not None
                or self.readback_attempted
            ):
                raise ValueError("provider-attempted receipt shape is invalid")
            return
        if self.phase is ReceiptPhase.READBACK_REQUIRED:
            if self.outcome is ReplayReceiptOutcome.APPLIED:
                if (
                    self.reason is not None
                    or self.result_sha256 is not None
                    or self.readback_attempted
                ):
                    raise ValueError("applied receipt shape is invalid")
            elif (
                self.outcome is not ReplayReceiptOutcome.AMBIGUOUS
                or self.reason is not DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
                or (self.result_sha256 is not None and not self.readback_attempted)
            ):
                raise ValueError("readback-required receipt shape is invalid")
            return
        if self.outcome is ReplayReceiptOutcome.VERIFIED:
            if (
                self.reason is not None
                or self.result_sha256 is None
                or not self.readback_attempted
            ):
                raise ValueError("verified terminal receipt shape is invalid")
        elif self.outcome in {
            ReplayReceiptOutcome.DENIED,
            ReplayReceiptOutcome.FAILED_SAFE,
        }:
            if (
                self.reason is None
                or self.result_sha256 is not None
                or self.readback_attempted
            ):
                raise ValueError("failed terminal receipt shape is invalid")
        elif self.outcome is ReplayReceiptOutcome.AMBIGUOUS:
            if (
                self.reason is not DenialReason.PROVIDER_OUTCOME_AMBIGUOUS
                or not self.readback_attempted
            ):
                raise ValueError("ambiguous terminal receipt shape is invalid")
        else:
            raise ValueError("terminal receipt outcome is invalid")

    @property
    def receipt_id(self) -> str:
        return mutation_identity(self.binding)

    @property
    def terminal(self) -> bool:
        return self.phase is ReceiptPhase.TERMINAL

    @property
    def awaits_readback(self) -> bool:
        return self.phase in {
            ReceiptPhase.PROVIDER_ATTEMPTED,
            ReceiptPhase.READBACK_REQUIRED,
        }


class ReplayAction(StrEnum):
    """Complete duplicate-delivery decision set."""

    CLAIM_NEW = "CLAIM_NEW"
    RESUME_PRE_DISPATCH = "RESUME_PRE_DISPATCH"
    RETURN_STORED = "RETURN_STORED"
    DENY_CONFLICT = "DENY_CONFLICT"
    REQUIRE_READBACK = "REQUIRE_READBACK"


@dataclass(frozen=True, slots=True)
class ReplayDecision:
    """Pure replay decision; persistence must apply it transactionally."""

    action: ReplayAction
    receipt: ReplayReceipt | None
    reason: DenialReason | None

    @property
    def may_enter_dispatch(self) -> bool:
        return self.action in {
            ReplayAction.CLAIM_NEW,
            ReplayAction.RESUME_PRE_DISPATCH,
        }

    @property
    def requires_readback(self) -> bool:
        return self.action is ReplayAction.REQUIRE_READBACK


def claim_receipt(binding: MutationBinding) -> ReplayReceipt:
    """Create the only phase from which exact work may enter dispatch."""

    return ReplayReceipt(
        binding=binding,
        phase=ReceiptPhase.PRE_DISPATCH_CLAIMED,
        outcome=ReplayReceiptOutcome.CLAIMED,
    )


def decide_replay(
    binding: MutationBinding,
    stored: ReplayReceipt | None,
) -> ReplayDecision:
    """Classify a new claim, exact duplicate, or conflicting key reuse."""

    if not isinstance(binding, MutationBinding):
        raise TypeError("binding must be a MutationBinding")
    if stored is None:
        return ReplayDecision(ReplayAction.CLAIM_NEW, claim_receipt(binding), None)
    if not isinstance(stored, ReplayReceipt):
        raise TypeError("stored must be a ReplayReceipt or None")
    if binding != stored.binding:
        return ReplayDecision(
            ReplayAction.DENY_CONFLICT,
            stored,
            DenialReason.IDEMPOTENCY_CONFLICT,
        )
    if stored.terminal:
        return ReplayDecision(ReplayAction.RETURN_STORED, stored, stored.reason)
    if stored.phase is ReceiptPhase.PRE_DISPATCH_CLAIMED:
        return ReplayDecision(ReplayAction.RESUME_PRE_DISPATCH, stored, None)
    return ReplayDecision(ReplayAction.REQUIRE_READBACK, stored, stored.reason)


def deny_before_dispatch(receipt: ReplayReceipt, reason: DenialReason) -> ReplayReceipt:
    """Record a known denial before any provider mutation could occur."""

    if receipt.phase is not ReceiptPhase.PRE_DISPATCH_CLAIMED:
        raise ValueError("denial is only valid before provider dispatch")
    if not isinstance(reason, DenialReason):
        raise TypeError("reason must be a DenialReason")
    return replace(
        receipt,
        phase=ReceiptPhase.TERMINAL,
        outcome=ReplayReceiptOutcome.DENIED,
        reason=reason,
    )


def mark_provider_attempted(receipt: ReplayReceipt) -> ReplayReceipt:
    """Persist mutation uncertainty before invoking the provider once."""

    if receipt.phase is not ReceiptPhase.PRE_DISPATCH_CLAIMED:
        raise ValueError("provider attempt may begin only from pre-dispatch claimed")
    return replace(
        receipt,
        phase=ReceiptPhase.PROVIDER_ATTEMPTED,
        outcome=ReplayReceiptOutcome.AMBIGUOUS,
        reason=DenialReason.PROVIDER_OUTCOME_AMBIGUOUS,
    )


def record_pre_dispatch_failure(
    receipt: ReplayReceipt,
    *,
    maximum_attempts: int = MAX_PRE_DISPATCH_TRANSPORT_ATTEMPTS,
) -> ReplayReceipt:
    """Durably consume one safe retry or terminalize before provider dispatch."""

    if receipt.phase is not ReceiptPhase.PRE_DISPATCH_CLAIMED:
        raise ValueError("pre-dispatch failure requires a claimed receipt")
    if (
        type(maximum_attempts) is not int
        or not 1 <= maximum_attempts <= MAX_PRE_DISPATCH_TRANSPORT_ATTEMPTS
    ):
        raise ValueError("maximum_attempts is outside the pre-dispatch bound")
    next_attempt = receipt.pre_dispatch_attempts + 1
    if next_attempt >= maximum_attempts:
        return replace(
            receipt,
            phase=ReceiptPhase.TERMINAL,
            outcome=ReplayReceiptOutcome.FAILED_SAFE,
            reason=DenialReason.TRANSPORT_UNAVAILABLE,
            pre_dispatch_attempts=next_attempt,
        )
    return replace(receipt, pre_dispatch_attempts=next_attempt)


class ProviderAttemptResult(StrEnum):
    """Closed provider signals after the mutation attempt was persisted."""

    ACCEPTED = "ACCEPTED"
    PRECONDITION_REJECTED = "PRECONDITION_REJECTED"
    TIMEOUT = "TIMEOUT"
    CONNECTION_LOST = "CONNECTION_LOST"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    UNKNOWN = "UNKNOWN"


def record_provider_result(
    receipt: ReplayReceipt,
    result: ProviderAttemptResult,
) -> ReplayReceipt:
    """Classify one provider attempt without ever authorizing another."""

    if receipt.phase is not ReceiptPhase.PROVIDER_ATTEMPTED:
        raise ValueError("provider result requires a persisted provider attempt")
    if not isinstance(result, ProviderAttemptResult):
        raise TypeError("result must be a ProviderAttemptResult")
    if result is ProviderAttemptResult.ACCEPTED:
        return replace(
            receipt,
            phase=ReceiptPhase.READBACK_REQUIRED,
            outcome=ReplayReceiptOutcome.APPLIED,
            reason=None,
        )
    if result is ProviderAttemptResult.PRECONDITION_REJECTED:
        return replace(
            receipt,
            phase=ReceiptPhase.TERMINAL,
            outcome=ReplayReceiptOutcome.FAILED_SAFE,
            reason=DenialReason.PROVIDER_PRECONDITION_FAILED,
        )
    return replace(
        receipt,
        phase=ReceiptPhase.READBACK_REQUIRED,
        outcome=ReplayReceiptOutcome.AMBIGUOUS,
        reason=DenialReason.PROVIDER_OUTCOME_AMBIGUOUS,
    )


def record_readback(
    receipt: ReplayReceipt,
    *,
    observed_poststate_sha256: str | None,
) -> ReplayReceipt:
    """Adopt success only when readback matches the immutable expected state."""

    if not receipt.awaits_readback:
        raise ValueError("readback requires provider uncertainty or an accepted result")
    if observed_poststate_sha256 is not None:
        _require_sha256("observed_poststate_sha256", observed_poststate_sha256)
    if observed_poststate_sha256 == receipt.binding.expected_poststate_sha256:
        return replace(
            receipt,
            phase=ReceiptPhase.TERMINAL,
            outcome=ReplayReceiptOutcome.VERIFIED,
            reason=None,
            result_sha256=observed_poststate_sha256,
            readback_attempted=True,
        )
    return replace(
        receipt,
        phase=ReceiptPhase.READBACK_REQUIRED,
        outcome=ReplayReceiptOutcome.AMBIGUOUS,
        reason=DenialReason.PROVIDER_OUTCOME_AMBIGUOUS,
        result_sha256=observed_poststate_sha256,
        readback_attempted=True,
    )


def close_unresolved_ambiguity(receipt: ReplayReceipt) -> ReplayReceipt:
    """Close only an ambiguity that already received an exact readback attempt."""

    if (
        receipt.phase is not ReceiptPhase.READBACK_REQUIRED
        or receipt.outcome is not ReplayReceiptOutcome.AMBIGUOUS
        or not receipt.readback_attempted
    ):
        raise ValueError("unresolved ambiguity requires a completed readback attempt")
    return replace(receipt, phase=ReceiptPhase.TERMINAL)


class TransportFailure(StrEnum):
    """Failure timing relevant to bounded transport retry safety."""

    BEFORE_DISPATCH = "BEFORE_DISPATCH"
    DISPATCH_STARTED = "DISPATCH_STARTED"
    TIMEOUT = "TIMEOUT"
    RESPONSE_LOST = "RESPONSE_LOST"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    UNKNOWN = "UNKNOWN"


class TransportAction(StrEnum):
    """Safe transport response to one classified failure."""

    RETRY_BEFORE_DISPATCH = "RETRY_BEFORE_DISPATCH"
    STOP_BEFORE_DISPATCH = "STOP_BEFORE_DISPATCH"
    REQUIRE_READBACK = "REQUIRE_READBACK"


@dataclass(frozen=True, slots=True)
class TransportDecision:
    """Bounded retry decision that never retries possible provider mutation."""

    action: TransportAction
    attempt_number: int
    maximum_attempts: int
    reason: DenialReason | None

    @property
    def retry_permitted(self) -> bool:
        return self.action is TransportAction.RETRY_BEFORE_DISPATCH

    @property
    def requires_readback(self) -> bool:
        return self.action is TransportAction.REQUIRE_READBACK


def decide_transport_failure(
    failure: TransportFailure,
    *,
    attempt_number: int,
    maximum_attempts: int,
) -> TransportDecision:
    """Permit bounded retry only when dispatch is known not to have started."""

    if not isinstance(failure, TransportFailure):
        raise TypeError("failure must be a TransportFailure")
    if (
        type(maximum_attempts) is not int
        or not 1 <= maximum_attempts <= MAX_PRE_DISPATCH_TRANSPORT_ATTEMPTS
    ):
        raise ValueError("maximum_attempts is outside the pre-dispatch bound")
    if type(attempt_number) is not int or not 1 <= attempt_number <= maximum_attempts:
        raise ValueError("attempt_number is outside the configured attempt bound")
    if failure is TransportFailure.BEFORE_DISPATCH:
        action = (
            TransportAction.RETRY_BEFORE_DISPATCH
            if attempt_number < maximum_attempts
            else TransportAction.STOP_BEFORE_DISPATCH
        )
        reason = (
            DenialReason.TRANSPORT_UNAVAILABLE
            if action is TransportAction.STOP_BEFORE_DISPATCH
            else None
        )
        return TransportDecision(action, attempt_number, maximum_attempts, reason)
    return TransportDecision(
        TransportAction.REQUIRE_READBACK,
        attempt_number,
        maximum_attempts,
        DenialReason.PROVIDER_OUTCOME_AMBIGUOUS,
    )


__all__ = [
    "MAX_PRE_DISPATCH_TRANSPORT_ATTEMPTS",
    "MUTATION_IDENTITY_DOMAIN",
    "MutationAction",
    "MutationBinding",
    "MutationTargetKey",
    "ProviderAttemptResult",
    "ReceiptPhase",
    "ReplayAction",
    "ReplayDecision",
    "ReplayReceipt",
    "ReplayReceiptOutcome",
    "TransportAction",
    "TransportDecision",
    "TransportFailure",
    "claim_receipt",
    "close_unresolved_ambiguity",
    "decide_replay",
    "decide_transport_failure",
    "deny_before_dispatch",
    "mark_provider_attempted",
    "mutation_identity",
    "record_pre_dispatch_failure",
    "record_provider_result",
    "record_readback",
]
