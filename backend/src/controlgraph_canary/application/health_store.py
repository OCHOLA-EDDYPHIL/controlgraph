"""Cloud-independent ports for normalized durable health-chain persistence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.contracts.health_execution import (
    PostApplyHealthAnchorV1,
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
)
from controlgraph_canary.contracts.health_storage import (
    HealthChainManifestV1,
    create_health_chain_manifest,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.promotion_execution import (
    PromotionHealthChainLocatorV1,
)


class HealthChainWriteDisposition(StrEnum):
    """Stable outcomes for immutable create and CAS-append operations."""

    CREATED = "CREATED"
    ADOPTED = "ADOPTED"


@dataclass(frozen=True, slots=True)
class HealthChainSnapshot:
    """One coherent in-process reconstruction from normalized durable documents."""

    anchor: StoredRecord[PostApplyHealthAnchorV1]
    manifest: StoredRecord[HealthChainManifestV1] | None
    signed_proofs: tuple[StoredRecord[SignedHealthDecisionProofV1], ...]
    signed_chain: SignedHealthDecisionChainV1 | None

    def __post_init__(self) -> None:
        if (
            type(self.anchor) is not StoredRecord
            or type(self.anchor.value) is not PostApplyHealthAnchorV1
            or self.anchor.revision != 0
            or type(self.signed_proofs) is not tuple
        ):
            raise TypeError("health-chain snapshot anchor is invalid")
        if self.manifest is None:
            if self.signed_proofs or self.signed_chain is not None:
                raise ValueError("anchor-only health snapshot contains chain state")
            return
        if (
            type(self.manifest) is not StoredRecord
            or type(self.manifest.value) is not HealthChainManifestV1
            or type(self.signed_chain) is not SignedHealthDecisionChainV1
            or self.manifest.revision != self.manifest.value.terminal_sequence
            or len(self.signed_proofs) != self.manifest.value.terminal_sequence
            or any(
                type(record) is not StoredRecord
                or type(record.value) is not SignedHealthDecisionProofV1
                or record.revision != 0
                for record in self.signed_proofs
            )
        ):
            raise TypeError("health-chain snapshot records are invalid")
        chain = self.signed_chain
        assert chain is not None
        if (
            chain.anchor != self.anchor.value
            or chain.signed_proofs
            != tuple(record.value for record in self.signed_proofs)
            or create_health_chain_manifest(chain) != self.manifest.value
        ):
            raise ValueError("health-chain snapshot reconstruction is inconsistent")

    @property
    def target(self) -> TargetBinding:
        return self.anchor.value.target

    @property
    def chain_head_sha256(self) -> str | None:
        return None if self.manifest is None else self.manifest.value.chain_head_sha256

    @property
    def terminal_sequence(self) -> int:
        return 0 if self.manifest is None else self.manifest.value.terminal_sequence


@dataclass(frozen=True, slots=True)
class HealthAnchorWriteResult:
    """One directly created or exactly adopted immutable health anchor."""

    disposition: HealthChainWriteDisposition
    snapshot: HealthChainSnapshot

    def __post_init__(self) -> None:
        if (
            type(self.disposition) is not HealthChainWriteDisposition
            or type(self.snapshot) is not HealthChainSnapshot
        ):
            raise ValueError("health anchor write result is invalid")


@dataclass(frozen=True, slots=True)
class HealthChainAppendResult:
    """One directly appended or exactly adopted signed-proof chain state."""

    disposition: HealthChainWriteDisposition
    snapshot: HealthChainSnapshot

    def __post_init__(self) -> None:
        if (
            type(self.disposition) is not HealthChainWriteDisposition
            or type(self.snapshot) is not HealthChainSnapshot
            or self.snapshot.manifest is None
        ):
            raise ValueError("health-chain append result is invalid")


@runtime_checkable
class HealthChainReader(Protocol):
    """Exact normalized reads available only to coordinator and issuer roles."""

    @property
    def target(self) -> TargetBinding: ...

    @property
    def service_role(self) -> ServiceRole: ...

    async def read_health_chain(
        self,
        anchor_id: str,
    ) -> HealthChainSnapshot | None: ...

    async def read_health_chain_by_manifest(
        self,
        manifest_sha256: str,
    ) -> HealthChainSnapshot | None: ...

    async def read_promotion_health_chain(
        self,
        locator: PromotionHealthChainLocatorV1,
    ) -> SignedHealthDecisionChainV1 | None: ...


@runtime_checkable
class HealthChainStore(HealthChainReader, Protocol):
    """Coordinator-only immutable anchor creation and transactional proof append."""

    async def create_or_adopt_health_anchor(
        self,
        anchor: PostApplyHealthAnchorV1,
    ) -> HealthAnchorWriteResult: ...

    async def append_signed_health_proof(
        self,
        expected: HealthChainSnapshot,
        signed_proof: SignedHealthDecisionProofV1,
    ) -> HealthChainAppendResult: ...


__all__ = [
    "HealthAnchorWriteResult",
    "HealthChainAppendResult",
    "HealthChainReader",
    "HealthChainSnapshot",
    "HealthChainStore",
    "HealthChainWriteDisposition",
]
