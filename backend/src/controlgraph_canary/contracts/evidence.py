"""Neutral contracts for the append-only signed evidence chain."""

from __future__ import annotations

from typing import Final, Literal, Self

from pydantic import model_validator

from controlgraph_canary.contracts.base import (
    Identifier,
    NonNegativeSafeInteger,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.models import EvidenceKind, TargetBinding

EVIDENCE_CHAIN_HEAD_V1: Final = "controlgraph.evidence-chain-head/v1"


class EvidenceChainHeadV1(StrictContractModel):
    """Mutable pointer to the latest immutable signed event for one root."""

    schema_version: Literal["controlgraph.evidence-chain-head/v1"]
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    sequence: NonNegativeSafeInteger
    evidence_id: Identifier
    evidence_sha256: Sha256Digest
    kind: EvidenceKind
    epoch: PositiveSafeInteger
    updated_at: UtcSecond

    @model_validator(mode="after")
    def validate_head(self) -> Self:
        if (self.sequence == 0) != (self.kind is EvidenceKind.ROOT_CREATED):
            raise ValueError("only sequence-zero evidence can identify root creation")
        if self.sequence == 0 and self.epoch != 1:
            raise ValueError("sequence-zero evidence head must identify epoch one")
        return self


__all__ = ["EVIDENCE_CHAIN_HEAD_V1", "EvidenceChainHeadV1"]
