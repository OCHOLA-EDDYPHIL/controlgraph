"""Cloud-independent persistence port for service-claim release."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import (
    RootCreationBundle,
    StoredRecord,
)
from controlgraph_canary.contracts.evidence import EvidenceChainHeadV1
from controlgraph_canary.contracts.models import (
    EpochAuthorityRecord,
    ExecutionReceipt,
    TargetBinding,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1
from controlgraph_canary.contracts.service_claim_release import (
    ServiceClaimReleaseFenceCommitV1,
    ServiceClaimReleaseFinalizeCommitV1,
    ServiceClaimReleaseIdentityV1,
    ServiceClaimReleaseInvocationV1,
    ServiceClaimReleaseProgressV1,
    ServiceClaimReleaseResultV1,
)
from controlgraph_canary.contracts.storage import ServiceClaimRecord


@dataclass(frozen=True, slots=True)
class ServiceClaimReleaseState:
    """One transactionally consistent view for a release lifecycle decision."""

    invocation: ServiceClaimReleaseInvocationV1
    root_bundle: RootCreationBundle | None
    terminal_receipt: StoredRecord[ExecutionReceipt] | None
    chain_head: StoredRecord[EvidenceChainHeadV1] | None
    head_evidence: StoredRecord[SignedEvidenceEventV1] | None
    terminal_evidence: StoredRecord[SignedEvidenceEventV1] | None
    fence_evidence: StoredRecord[SignedEvidenceEventV1] | None
    classification_evidence: StoredRecord[SignedEvidenceEventV1] | None
    release_evidence: StoredRecord[SignedEvidenceEventV1] | None
    request_identity: StoredRecord[ServiceClaimReleaseIdentityV1] | None
    idempotency_identity: StoredRecord[ServiceClaimReleaseIdentityV1] | None
    progress: StoredRecord[ServiceClaimReleaseProgressV1] | None
    result: StoredRecord[ServiceClaimReleaseResultV1] | None

    def __post_init__(self) -> None:
        if type(self.invocation) is not ServiceClaimReleaseInvocationV1:
            raise TypeError("release state requires an exact invocation")


@dataclass(frozen=True, slots=True)
class ServiceClaimFenceWriteResult:
    """Complete exact stored winner for an atomic fence commit."""

    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]
    terminal_evidence: StoredRecord[SignedEvidenceEventV1]
    fence_evidence: StoredRecord[SignedEvidenceEventV1]
    chain_head: StoredRecord[EvidenceChainHeadV1]
    progress: StoredRecord[ServiceClaimReleaseProgressV1]
    request_identity: StoredRecord[ServiceClaimReleaseIdentityV1]
    idempotency_identity: StoredRecord[ServiceClaimReleaseIdentityV1]


@dataclass(frozen=True, slots=True)
class ServiceClaimFinalizeWriteResult:
    """Complete exact stored winner for an atomic final release commit."""

    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]
    classification_evidence: StoredRecord[SignedEvidenceEventV1]
    release_evidence: StoredRecord[SignedEvidenceEventV1]
    chain_head: StoredRecord[EvidenceChainHeadV1]
    result: StoredRecord[ServiceClaimReleaseResultV1]


@runtime_checkable
class ServiceClaimReleaseStore(Protocol):
    """Narrow coordinator-only durable operations for claim release."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_service_claim_release_state(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
    ) -> ServiceClaimReleaseState: ...

    async def commit_service_claim_fence(
        self,
        expected: ServiceClaimReleaseState,
        commit: ServiceClaimReleaseFenceCommitV1,
    ) -> ServiceClaimFenceWriteResult: ...

    async def commit_service_claim_release(
        self,
        expected: ServiceClaimReleaseState,
        commit: ServiceClaimReleaseFinalizeCommitV1,
    ) -> ServiceClaimFinalizeWriteResult: ...


__all__ = [
    "ServiceClaimFenceWriteResult",
    "ServiceClaimFinalizeWriteResult",
    "ServiceClaimReleaseState",
    "ServiceClaimReleaseStore",
]
