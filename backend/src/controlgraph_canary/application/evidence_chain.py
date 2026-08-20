"""Cloud-independent validation for the shared append-only evidence head."""

from __future__ import annotations

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.evidence import (
    EVIDENCE_CHAIN_HEAD_V1,
    EvidenceChainHeadV1,
)
from controlgraph_canary.contracts.models import EvidenceKind, TargetBinding
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1


def current_evidence_chain_head(
    bundle: RootCreationBundle,
    *,
    target: TargetBinding,
    stored_head: StoredRecord[EvidenceChainHeadV1] | None,
    head_evidence: StoredRecord[SignedEvidenceEventV1] | None,
) -> EvidenceChainHeadV1:
    """Return the exact current head, bootstrapping only pristine root evidence."""

    if type(bundle) is not RootCreationBundle or type(target) is not TargetBinding:
        raise TypeError("evidence-chain inspection requires exact root state")
    root = bundle.root.value
    authority = bundle.authority.value
    root_evidence = bundle.signed_evidence.value
    if stored_head is None:
        event = root_evidence.event
        if (
            authority.revision != 0
            or authority.current_epoch != 1
            or head_evidence is not None
            or event.sequence != 0
            or event.kind is not EvidenceKind.ROOT_CREATED
            or event.previous_event_sha256 is not None
            or event.evidence_id != authority.evidence_id
            or event.root_id != root.root_id
            or event.root_sha256 != root.root_sha256
            or event.target != target
            or event.epoch != 1
            or event.request_id != authority.request_id
            or event.occurred_at != authority.changed_at
            or root_evidence.signing_key_version
            != root.content.evidence_signing_key_version
        ):
            raise ValueError("evidence head cannot be bootstrapped")
        return EvidenceChainHeadV1(
            schema_version=EVIDENCE_CHAIN_HEAD_V1,
            root_id=event.root_id,
            root_sha256=event.root_sha256,
            target=event.target,
            sequence=0,
            evidence_id=event.evidence_id,
            evidence_sha256=canonical_sha256(root_evidence),
            kind=event.kind,
            epoch=event.epoch,
            updated_at=event.occurred_at,
        )
    if (
        type(stored_head) is not StoredRecord
        or type(stored_head.value) is not EvidenceChainHeadV1
        or stored_head.revision != stored_head.value.sequence
        or type(head_evidence) is not StoredRecord
        or head_evidence.revision != 0
        or type(head_evidence.value) is not SignedEvidenceEventV1
    ):
        raise ValueError("evidence head record is invalid")
    head = stored_head.value
    signed = head_evidence.value
    event = signed.event
    if (
        head.root_id != root.root_id
        or head.root_sha256 != root.root_sha256
        or head.target != target
        or head.sequence < authority.revision
        or (
            head.kind is EvidenceKind.EPOCH_ADVANCED
            and head.evidence_id != authority.evidence_id
        )
        or head.epoch != authority.current_epoch
        or head.updated_at < authority.changed_at
        or head.evidence_sha256 != canonical_sha256(signed)
        or event.evidence_id != head.evidence_id
        or event.sequence != head.sequence
        or event.root_id != head.root_id
        or event.root_sha256 != head.root_sha256
        or event.target != head.target
        or event.epoch != head.epoch
        or event.kind is not head.kind
        or event.occurred_at != head.updated_at
        or signed.signing_key_version != root.content.evidence_signing_key_version
    ):
        raise ValueError("evidence head does not match its immutable event")
    return head


__all__ = ["current_evidence_chain_head"]
