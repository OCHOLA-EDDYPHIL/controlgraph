"""Coordinator-owned append facade for exact source projections."""

from __future__ import annotations

import json
import sys
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.timeline import (
    TimelineWriteGrant,
    TimelineWriteService,
)
from controlgraph_canary.application.timeline_projectors import (
    TimelineProjection,
    project_canary_dispatch,
    project_completion_classification,
    project_epoch_revocation,
    project_execution_receipt,
    project_independent_verification,
    project_model_assistance,
    project_promotion_dispatch,
    project_recovery_abandonment,
    project_recovery_dispatch,
    project_recovery_intent,
    project_service_claim_release,
    project_signed_capability,
    project_signed_evidence_event,
    project_signed_health_proof,
)
from controlgraph_canary.contracts.canary_execution import CanaryDispatchResultV1
from controlgraph_canary.contracts.health_execution import SignedHealthDecisionProofV1
from controlgraph_canary.contracts.independent_verification import (
    CompletionClassificationV1,
    CompletionKind,
    CompletionReason,
    IndependentVerificationVerdict,
    VerifiedIndependentVerificationEvidenceV1,
)
from controlgraph_canary.contracts.model_assistance import ModelAssistanceTimelineAuditV1
from controlgraph_canary.contracts.models import (
    ExecutionReceipt,
    SignedCapability,
    TargetBinding,
)
from controlgraph_canary.contracts.promotion_execution import PromotionDispatchResultV2
from controlgraph_canary.contracts.recovery_abandonment import RecoveryAbandonmentResultV1
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryDispatchResultV2,
    RecoveryIntentV1,
)
from controlgraph_canary.contracts.revocation import EpochRevocationCallOutcomeV1
from controlgraph_canary.contracts.root_creation import (
    RootCreationResultV1,
    RootCreationResultV2,
    SignedEvidenceEventV1,
)
from controlgraph_canary.contracts.service_claim_release import ServiceClaimReleaseResultV1
from controlgraph_canary.contracts.timeline import (
    TimelineDisplayFieldName,
    TimelineEventType,
    TimelineEventV1,
    TimelineEvidencePolicySetV1,
    TimelineTerminalClassification,
)

_VERIFIER_DISAGREEMENT_REASONS = frozenset(
    {
        CompletionReason.CONFIGURATION_DATA_DISAGREEMENT.value,
        CompletionReason.CONFIGURATION_MISMATCH.value,
        CompletionReason.EXECUTION_EVIDENCE_CONTRADICTORY.value,
    }
)
_EVIDENCE_FAILURE_REASONS = frozenset(
    {
        CompletionReason.AUTHORITY_PROOF_ABSENT.value,
        CompletionReason.CONFIGURATION_PROOF_ABSENT.value,
        CompletionReason.CONFIGURATION_UNAVAILABLE.value,
        CompletionReason.EVIDENCE_BINDING_MISMATCH.value,
        CompletionReason.EVIDENCE_STALE.value,
        CompletionReason.EXECUTION_PROOF_ABSENT.value,
        CompletionReason.PROBE_INCONCLUSIVE.value,
        CompletionReason.PROBE_PROOF_ABSENT.value,
    }
)


def _operational_signals(event: TimelineEventV1) -> tuple[str, ...]:
    fields = {item.name: item.value for item in event.display_fields}
    action = fields.get(TimelineDisplayFieldName.ACTION)
    outcome = fields.get(TimelineDisplayFieldName.OUTCOME)
    reason = fields.get(TimelineDisplayFieldName.REASON_CODE)
    signals: list[str] = []

    if (
        event.event_type is TimelineEventType.TERMINAL_CLASSIFIED
        and event.terminal_classification is TimelineTerminalClassification.DENIED
    ):
        signals.append("stale_denial")
    if event.event_type is TimelineEventType.MUTATION_AMBIGUOUS:
        signals.append("ambiguous_mutation")
    if event.event_type is TimelineEventType.HEALTH_DECIDED and outcome == "unhealthy":
        signals.append("unhealthy_rollout")
    if (
        event.event_type is TimelineEventType.TERMINAL_CLASSIFIED
        and event.terminal_classification is TimelineTerminalClassification.AMBIGUOUS
        and action == CompletionKind.RECOVERY.value
    ):
        signals.append("failed_recovery")
    if (
        event.event_type is TimelineEventType.VERIFICATION_RECORDED
        and outcome == IndependentVerificationVerdict.MISMATCH.value
    ) or reason in _VERIFIER_DISAGREEMENT_REASONS:
        signals.append("verifier_disagreement")
    if (
        event.event_type is TimelineEventType.VERIFICATION_RECORDED
        and outcome
        in {
            IndependentVerificationVerdict.INCONCLUSIVE.value,
            IndependentVerificationVerdict.UNAVAILABLE.value,
        }
    ) or reason in _EVIDENCE_FAILURE_REASONS:
        signals.append("evidence_failure")
    return tuple(signals)


def _emit_operational_signals(event: TimelineEventV1) -> None:
    signals = _operational_signals(event)
    for signal in signals:
        summary = {
            "epoch": event.epoch,
            "event": "controlgraph.operational.signal",
            "event_type": event.event_type.value,
            "root_sha256": event.root_sha256,
            "signal": signal,
        }
        sys.stderr.write(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
    if signals:
        sys.stderr.flush()


@runtime_checkable
class TimelineProjectionRecorder(Protocol):
    """Narrow recording port accepted by authority-preserving application flows."""

    @property
    def target(self) -> TargetBinding: ...

    async def record(self, *projections: TimelineProjection) -> None: ...

    async def record_signed_health_proof(
        self,
        signed: SignedHealthDecisionProofV1,
    ) -> None: ...

    async def record_recovery_intent(self, intent: RecoveryIntentV1) -> None: ...


@runtime_checkable
class IndependentVerificationTimelineRecorder(Protocol):
    """Coordinator-only persistence surface for verified target evidence."""

    @property
    def target(self) -> TargetBinding: ...

    async def record_independent_verification(
        self,
        verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None: ...


@runtime_checkable
class CompletionClassificationTimelineRecorder(Protocol):
    """Coordinator-only persistence surface for pure terminal classifications."""

    @property
    def target(self) -> TargetBinding: ...

    async def record_completion_classification(
        self,
        classification: CompletionClassificationV1,
    ) -> None: ...


@runtime_checkable
class TimelineSignedIntentStore(Protocol):
    """Coordinator-only capability storage excluded from timeline evidence exports."""

    @property
    def target(self) -> TargetBinding: ...

    async def persist_signed_intent(self, signed: SignedCapability) -> None: ...


class TimelineRecorder:
    """Append already-derived projections in their causal order."""

    def __init__(
        self,
        *,
        service: TimelineWriteService,
        grant: TimelineWriteGrant,
        policy_set: TimelineEvidencePolicySetV1,
        signed_intent_store: TimelineSignedIntentStore,
    ) -> None:
        if (
            type(service) is not TimelineWriteService
            or type(grant) is not TimelineWriteGrant
            or type(policy_set) is not TimelineEvidencePolicySetV1
            or service.target != grant.target
            or policy_set.target != service.target
            or not isinstance(signed_intent_store, TimelineSignedIntentStore)
            or signed_intent_store.target != service.target
        ):
            raise ValueError("timeline recorder configuration is invalid")
        self._service = service
        self._grant = grant
        self._policy_set = policy_set
        self._signed_intent_store = signed_intent_store

    @property
    def target(self) -> TargetBinding:
        return self._service.target

    async def record(self, *projections: TimelineProjection) -> None:
        if not projections or any(type(item) is not TimelineProjection for item in projections):
            raise TypeError("timeline recorder requires exact projections")
        await self._service.append_many_with_raw(
            tuple((item.event, item.raw_source) for item in projections),
            self._grant,
        )
        for projection in projections:
            _emit_operational_signals(projection.event)

    async def record_root_creation(
        self,
        result: RootCreationResultV1 | RootCreationResultV2,
    ) -> None:
        if type(result) not in {RootCreationResultV1, RootCreationResultV2}:
            raise TypeError("root creation timeline result must be exact")
        await self.record(
            project_signed_evidence_event(
                result.signed_evidence,
                policy_set=self._policy_set,
                signature_verified=True,
            )
        )

    async def record_canary_dispatch(self, result: CanaryDispatchResultV1) -> None:
        await self.record(project_canary_dispatch(result, policy_set=self._policy_set))

    async def record_promotion_dispatch(self, result: PromotionDispatchResultV2) -> None:
        await self.record(project_promotion_dispatch(result, policy_set=self._policy_set))

    async def record_signed_health_proof(
        self,
        signed: SignedHealthDecisionProofV1,
    ) -> None:
        await self.record(
            *project_signed_health_proof(
                signed,
                policy_set=self._policy_set,
                signature_verified=True,
            )
        )

    async def record_execution_receipt(self, receipt: ExecutionReceipt) -> None:
        await self.record(project_execution_receipt(receipt, policy_set=self._policy_set))

    async def record_independent_verification(
        self,
        verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None:
        await self.record(
            project_independent_verification(verified, policy_set=self._policy_set)
        )

    async def record_model_assistance(
        self,
        audit: ModelAssistanceTimelineAuditV1,
    ) -> None:
        await self.record(project_model_assistance(audit, policy_set=self._policy_set))

    async def record_completion_classification(
        self,
        classification: CompletionClassificationV1,
    ) -> None:
        await self.record(
            project_completion_classification(
                classification,
                policy_set=self._policy_set,
            )
        )

    async def record_verification_bundle(
        self,
        *verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None:
        if not verified:
            raise TypeError("verification timeline bundle cannot be empty")
        await self.record(
            *(
                project_independent_verification(item, policy_set=self._policy_set)
                for item in verified
            )
        )

    async def record_completion_bundle(
        self,
        classification: CompletionClassificationV1,
        *verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None:
        await self.record(
            *(
                project_independent_verification(item, policy_set=self._policy_set)
                for item in verified
            ),
            project_completion_classification(
                classification,
                policy_set=self._policy_set,
            ),
        )

    async def record_stale_denial_completion(
        self,
        receipt: ExecutionReceipt,
        signed_authority: SignedEvidenceEventV1 | None,
        classification: CompletionClassificationV1,
    ) -> None:
        if signed_authority is not None:
            await self.record(
                project_signed_evidence_event(
                    signed_authority,
                    policy_set=self._policy_set,
                    signature_verified=True,
                )
            )
        await self.record(
            project_execution_receipt(receipt, policy_set=self._policy_set),
            project_completion_classification(
                classification,
                policy_set=self._policy_set,
            ),
        )

    async def record_signed_capability(
        self,
        signed: SignedCapability,
        *,
        signature_verified: bool,
    ) -> None:
        await self._signed_intent_store.persist_signed_intent(signed)
        await self.record(
            project_signed_capability(
                signed,
                policy_set=self._policy_set,
                signature_verified=signature_verified,
            )
        )

    async def record_recovery_intent(self, intent: RecoveryIntentV1) -> None:
        await self.record(project_recovery_intent(intent, policy_set=self._policy_set))

    async def record_recovery_dispatch(self, result: RecoveryDispatchResultV2) -> None:
        await self.record(project_recovery_dispatch(result, policy_set=self._policy_set))

    async def record_recovery_abandonment(
        self,
        result: RecoveryAbandonmentResultV1,
    ) -> None:
        await self.record(
            project_recovery_abandonment(result, policy_set=self._policy_set)
        )

    async def record_epoch_revocation(self, result: EpochRevocationCallOutcomeV1) -> None:
        await self.record(*project_epoch_revocation(result, policy_set=self._policy_set))

    async def record_epoch_revocation_completion(
        self,
        result: EpochRevocationCallOutcomeV1,
        signed_evidence: SignedEvidenceEventV1,
        classification: CompletionClassificationV1,
    ) -> None:
        await self.record(
            project_signed_evidence_event(
                signed_evidence,
                policy_set=self._policy_set,
                signature_verified=True,
            ),
            *project_epoch_revocation(result, policy_set=self._policy_set),
            project_completion_classification(
                classification,
                policy_set=self._policy_set,
            ),
        )

    async def record_service_claim_release(
        self,
        result: ServiceClaimReleaseResultV1,
    ) -> None:
        await self.record(project_service_claim_release(result, policy_set=self._policy_set))


__all__ = [
    "CompletionClassificationTimelineRecorder",
    "IndependentVerificationTimelineRecorder",
    "TimelineProjectionRecorder",
    "TimelineRecorder",
    "TimelineSignedIntentStore",
]
