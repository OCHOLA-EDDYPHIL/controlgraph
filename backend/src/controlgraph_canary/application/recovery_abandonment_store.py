"""Cloud-independent persistence port for ambiguous recovery abandonment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.evidence import EvidenceChainHeadV1
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.recovery_abandonment import (
    RecoveryAbandonmentFenceCommitV1,
    RecoveryAbandonmentFinalizeCommitV1,
    RecoveryAbandonmentIdentityV1,
    RecoveryAbandonmentInvocationV1,
    RecoveryAbandonmentProgressV1,
    RecoveryAbandonmentResultV1,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryDispatchRecordV2,
    RecoveryIntentV1,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecordV3,
    execution_receipt_logical_id,
)


def late_fence_receipt_matches(
    stored: StoredRecord[ExecutionReceipt],
    dispatch: RecoveryDispatchRecordV2,
    *,
    fenced_epoch: int,
    fenced_at: str,
) -> bool:
    """Accept only the exact executor denial caused by this abandonment fence."""

    if (
        type(stored) is not StoredRecord
        or stored.revision != 1
        or type(stored.value) is not ExecutionReceipt
        or type(dispatch) is not RecoveryDispatchRecordV2
        or type(fenced_epoch) is not int
        or fenced_epoch not in {dispatch.epoch + 1, dispatch.epoch + 2}
        or type(fenced_at) is not str
    ):
        return False
    receipt = stored.value
    intent = dispatch.task.intent
    target = dispatch.target
    binding = MutationBinding(
        idempotency_key=intent.idempotency_key,
        request_id=intent.request_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=MutationAction.RECOVER_STABLE,
        target=MutationTargetKey(
            project_id=target.project_id,
            region=target.region,
            environment=target.environment,
            service_name=target.service_name,
        ),
        provider_precondition=intent.provider_etag,
        plan_sha256=intent.plan_sha256,
        capability_sha256=canonical_sha256(dispatch.task.capability),
        payload_sha256=canonical_sha256(dispatch.task),
        expected_poststate_sha256=intent.desired_poststate_sha256,
    )
    return (
        receipt.receipt_id
        == execution_receipt_logical_id(dispatch.target, dispatch.idempotency_key)
        and receipt.idempotency_key == binding.idempotency_key
        and receipt.request_id == binding.request_id
        and receipt.root_id == binding.root_id
        and receipt.root_sha256 == binding.root_sha256
        and receipt.epoch == binding.epoch
        and receipt.action is CapabilityAction.RECOVER_STABLE
        and receipt.target == dispatch.target
        and receipt.provider_etag == binding.provider_precondition
        and receipt.plan_sha256 == binding.plan_sha256
        and receipt.capability_sha256 == binding.capability_sha256
        and receipt.mutation_sha256 == mutation_identity(binding)
        and receipt.expected_poststate_sha256 == binding.expected_poststate_sha256
        and receipt.dispatch_not_after == dispatch.task.expires_at
        and receipt.outcome is ReceiptOutcome.DENIED
        and receipt.reason_code is ReasonCode.EPOCH_MISMATCH
        and receipt.provider_operation is None
        and receipt.observed_etag is None
        and receipt.observed_authority_epoch == fenced_epoch
        and receipt.updated_at >= fenced_at
        and receipt.evidence_ids == ()
    )


@dataclass(frozen=True, slots=True)
class RecoveryAbandonmentState:
    """One transactionally consistent view of the complete abandonment lifecycle."""

    invocation: RecoveryAbandonmentInvocationV1
    root_bundle: RootCreationBundle | None
    recovery_intent: StoredRecord[RecoveryIntentV1] | None
    recovery_dispatch: StoredRecord[RecoveryDispatchRecordV2] | None
    recovery_receipt: StoredRecord[ExecutionReceipt] | None
    chain_head: StoredRecord[EvidenceChainHeadV1] | None
    head_evidence: StoredRecord[SignedEvidenceEventV1] | None
    abandonment_evidence: StoredRecord[SignedEvidenceEventV1] | None
    fence_evidence: StoredRecord[SignedEvidenceEventV1] | None
    classification_evidence: StoredRecord[SignedEvidenceEventV1] | None
    release_evidence: StoredRecord[SignedEvidenceEventV1] | None
    request_identity: StoredRecord[RecoveryAbandonmentIdentityV1] | None
    idempotency_identity: StoredRecord[RecoveryAbandonmentIdentityV1] | None
    progress: StoredRecord[RecoveryAbandonmentProgressV1] | None
    result: StoredRecord[RecoveryAbandonmentResultV1] | None

    def __post_init__(self) -> None:
        if type(self.invocation) is not RecoveryAbandonmentInvocationV1:
            raise TypeError("abandonment state requires an exact invocation")


@dataclass(frozen=True, slots=True)
class RecoveryAbandonmentFenceWriteResult:
    recovery_dispatch: StoredRecord[RecoveryDispatchRecordV2]
    service_claim: StoredRecord[ServiceClaimRecordV3]
    authority: StoredRecord[EpochAuthorityRecord]
    abandonment_evidence: StoredRecord[SignedEvidenceEventV1]
    fence_evidence: StoredRecord[SignedEvidenceEventV1]
    chain_head: StoredRecord[EvidenceChainHeadV1]
    progress: StoredRecord[RecoveryAbandonmentProgressV1]
    request_identity: StoredRecord[RecoveryAbandonmentIdentityV1]
    idempotency_identity: StoredRecord[RecoveryAbandonmentIdentityV1]


@dataclass(frozen=True, slots=True)
class RecoveryAbandonmentFinalizeWriteResult:
    service_claim: StoredRecord[ServiceClaimRecordV3]
    authority: StoredRecord[EpochAuthorityRecord]
    classification_evidence: StoredRecord[SignedEvidenceEventV1]
    release_evidence: StoredRecord[SignedEvidenceEventV1]
    chain_head: StoredRecord[EvidenceChainHeadV1]
    result: StoredRecord[RecoveryAbandonmentResultV1]


@runtime_checkable
class RecoveryAbandonmentStore(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def read_recovery_abandonment_state(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
    ) -> RecoveryAbandonmentState: ...

    async def commit_recovery_abandonment_fence(
        self,
        expected: RecoveryAbandonmentState,
        commit: RecoveryAbandonmentFenceCommitV1,
    ) -> RecoveryAbandonmentFenceWriteResult: ...

    async def commit_recovery_abandonment_release(
        self,
        expected: RecoveryAbandonmentState,
        commit: RecoveryAbandonmentFinalizeCommitV1,
    ) -> RecoveryAbandonmentFinalizeWriteResult: ...


__all__ = [
    "RecoveryAbandonmentFenceWriteResult",
    "RecoveryAbandonmentFinalizeWriteResult",
    "RecoveryAbandonmentState",
    "RecoveryAbandonmentStore",
    "late_fence_receipt_matches",
]
