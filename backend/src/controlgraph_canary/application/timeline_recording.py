"""Coordinator-owned append facade for exact source projections."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from controlgraph_canary.application.timeline import (
    TimelineWriteGrant,
    TimelineWriteService,
)
from controlgraph_canary.application.timeline_projectors import (
    TimelineProjection,
    project_canary_dispatch,
    project_epoch_revocation,
    project_execution_receipt,
    project_promotion_dispatch,
    project_recovery_dispatch,
    project_recovery_intent,
    project_service_claim_release,
    project_signed_capability,
    project_signed_evidence_event,
    project_signed_health_proof,
)
from controlgraph_canary.contracts.canary_execution import CanaryDispatchResultV1
from controlgraph_canary.contracts.health_execution import SignedHealthDecisionProofV1
from controlgraph_canary.contracts.models import (
    ExecutionReceipt,
    SignedCapability,
    TargetBinding,
)
from controlgraph_canary.contracts.promotion_execution import PromotionDispatchResultV2
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryDispatchResultV2,
    RecoveryIntentV1,
)
from controlgraph_canary.contracts.revocation import EpochRevocationCallOutcomeV1
from controlgraph_canary.contracts.root_creation import (
    RootCreationResultV1,
    RootCreationResultV2,
)
from controlgraph_canary.contracts.service_claim_release import ServiceClaimReleaseResultV1
from controlgraph_canary.contracts.timeline import TimelineEvidencePolicySetV1


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


class TimelineRecorder:
    """Append already-derived projections in their causal order."""

    def __init__(
        self,
        *,
        service: TimelineWriteService,
        grant: TimelineWriteGrant,
        policy_set: TimelineEvidencePolicySetV1,
    ) -> None:
        if (
            type(service) is not TimelineWriteService
            or type(grant) is not TimelineWriteGrant
            or type(policy_set) is not TimelineEvidencePolicySetV1
            or service.target != grant.target
            or policy_set.target != service.target
        ):
            raise ValueError("timeline recorder configuration is invalid")
        self._service = service
        self._grant = grant
        self._policy_set = policy_set

    @property
    def target(self) -> TargetBinding:
        return self._service.target

    async def record(self, *projections: TimelineProjection) -> None:
        if not projections or any(type(item) is not TimelineProjection for item in projections):
            raise TypeError("timeline recorder requires exact projections")
        for projection in projections:
            await self._service.append_with_raw(
                projection.event,
                projection.raw_source,
                self._grant,
            )

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

    async def record_signed_capability(
        self,
        signed: SignedCapability,
        *,
        signature_verified: bool,
    ) -> None:
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

    async def record_epoch_revocation(self, result: EpochRevocationCallOutcomeV1) -> None:
        await self.record(*project_epoch_revocation(result, policy_set=self._policy_set))

    async def record_service_claim_release(
        self,
        result: ServiceClaimReleaseResultV1,
    ) -> None:
        await self.record(project_service_claim_release(result, policy_set=self._policy_set))


__all__ = ["TimelineProjectionRecorder", "TimelineRecorder"]
