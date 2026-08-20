"""Cloud-independent persistence port for manual epoch revocation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.contracts.evidence import EvidenceChainHeadV1
from controlgraph_canary.contracts.models import EpochAuthorityRecord, TargetBinding
from controlgraph_canary.contracts.revocation import (
    EpochRevocationAuditV1,
    EpochRevocationCommitV1,
    EpochRevocationIdentityV1,
    EpochRevocationInvocationV1,
    EpochRevocationProofCommandV1,
    EpochRevocationResultV1,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1


@dataclass(frozen=True, slots=True)
class EpochRevocationState:
    """One transactionally consistent view used to decide a revocation attempt."""

    invocation: EpochRevocationInvocationV1
    root_bundle: RootCreationBundle | None
    chain_head: StoredRecord[EvidenceChainHeadV1] | None
    head_evidence: StoredRecord[SignedEvidenceEventV1] | None
    request_identity: StoredRecord[EpochRevocationIdentityV1] | None
    idempotency_identity: StoredRecord[EpochRevocationIdentityV1] | None
    result: StoredRecord[EpochRevocationResultV1] | None
    result_evidence: StoredRecord[SignedEvidenceEventV1] | None
    attempt_audit: StoredRecord[EpochRevocationAuditV1] | None

    def __post_init__(self) -> None:
        if type(self.invocation) is not EpochRevocationInvocationV1:
            raise TypeError("revocation state requires an exact invocation")


@dataclass(frozen=True, slots=True)
class EpochRevocationWriteResult:
    """The complete stored bundle from one directly confirmed or resolved commit."""

    authority: StoredRecord[EpochAuthorityRecord]
    signed_evidence: StoredRecord[SignedEvidenceEventV1]
    chain_head: StoredRecord[EvidenceChainHeadV1]
    result: StoredRecord[EpochRevocationResultV1]
    request_identity: StoredRecord[EpochRevocationIdentityV1]
    idempotency_identity: StoredRecord[EpochRevocationIdentityV1]
    audit: StoredRecord[EpochRevocationAuditV1]


@dataclass(frozen=True, slots=True)
class EpochRevocationProofState:
    """One exact-key consistent read used only for operator proof retrieval."""

    command: EpochRevocationProofCommandV1
    authority: StoredRecord[EpochAuthorityRecord]
    signed_evidence: StoredRecord[SignedEvidenceEventV1]
    result: StoredRecord[EpochRevocationResultV1]
    audit: StoredRecord[EpochRevocationAuditV1]

    def __post_init__(self) -> None:
        if type(self.command) is not EpochRevocationProofCommandV1:
            raise TypeError("revocation proof state requires an exact command")


@runtime_checkable
class EpochRevocationStore(Protocol):
    """Narrow coordinator-only persistence operations for epoch revocation."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_epoch_revocation_state(
        self,
        invocation: EpochRevocationInvocationV1,
    ) -> EpochRevocationState: ...

    async def commit_epoch_revocation(
        self,
        expected: EpochRevocationState,
        commit: EpochRevocationCommitV1,
    ) -> EpochRevocationWriteResult: ...

    async def record_epoch_revocation_audit(
        self,
        audit: EpochRevocationAuditV1,
    ) -> StoredRecord[EpochRevocationAuditV1]: ...


@runtime_checkable
class EpochRevocationProofStore(Protocol):
    """Exact-key coordinator read required to build one revocation proof."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_epoch_revocation_proof(
        self,
        command: EpochRevocationProofCommandV1,
    ) -> EpochRevocationProofState | None: ...


__all__ = [
    "EpochRevocationProofState",
    "EpochRevocationProofStore",
    "EpochRevocationState",
    "EpochRevocationStore",
    "EpochRevocationWriteResult",
]
