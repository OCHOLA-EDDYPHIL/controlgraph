"""Atomic Firestore persistence for ambiguous recovery abandonment."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Final, Literal, cast
from uuid import uuid4

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    RootCreationBundle,
    StoredRecord,
)
from controlgraph_canary.application.evidence_chain import current_evidence_chain_head
from controlgraph_canary.application.recovery_abandonment_store import (
    RecoveryAbandonmentFenceWriteResult,
    RecoveryAbandonmentFinalizeWriteResult,
    RecoveryAbandonmentState,
    late_fence_receipt_matches,
)
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.evidence import EvidenceChainHeadV1
from controlgraph_canary.contracts.health_storage import (
    HEALTH_STORAGE_DOCUMENT_V1,
    HealthStorageDocumentV1,
    HealthStorageKind,
    RecoveryDispatchStorageRecordV2,
    create_recovery_dispatch_storage_record,
    recovery_dispatch_record_sha256,
    recovery_dispatch_storage_record_value,
    recovery_intent_document_id,
)
from controlgraph_canary.contracts.health_storage import (
    recovery_dispatch_document_id as health_recovery_dispatch_document_id,
)
from controlgraph_canary.contracts.health_storage import (
    recovery_dispatch_identity_document_id as health_recovery_dispatch_identity_document_id,
)
from controlgraph_canary.contracts.health_storage import (
    recovery_dispatch_identity_logical_id as health_recovery_dispatch_identity_logical_id,
)
from controlgraph_canary.contracts.models import (
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceKind,
    ExecutionReceipt,
    TargetBinding,
)
from controlgraph_canary.contracts.recovery_abandonment import (
    RECOVERY_ABANDONMENT_CLASSIFICATION_REQUEST_V1,
    RecoveryAbandonmentClassificationRequestV1,
    RecoveryAbandonmentFenceCommitV1,
    RecoveryAbandonmentFinalizeCommitV1,
    RecoveryAbandonmentIdentityKind,
    RecoveryAbandonmentIdentityV1,
    RecoveryAbandonmentInvocationV1,
    RecoveryAbandonmentProgressV1,
    RecoveryAbandonmentResultV1,
    recovery_abandonment_classification_request_sha256,
    recovery_abandonment_evidence_id,
    recovery_abandonment_request_sha256,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryDispatchIdentityKind,
    RecoveryDispatchIdentityV2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchState,
    RecoveryIntentV1,
    recovery_command_sha256,
    recovery_dispatch_id,
    recovery_intent_id,
)
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    SignedEvidenceEventV1,
)
from controlgraph_canary.contracts.storage import (
    AuthorityStorageDocument,
    AuthorityStorageKind,
    ServiceClaimAbandonmentProofV1,
    ServiceClaimRecord,
    ServiceClaimRecordV3,
    ServiceClaimStableBaselineProofV1,
    ServiceClaimStatus,
    capability_lineage_anchor_document_id,
    epoch_authority_document_id,
    evidence_chain_head_document_id,
    execution_receipt_document_id,
    execution_receipt_logical_id,
    recovery_abandonment_identity_document_id,
    recovery_abandonment_identity_logical_id,
    recovery_abandonment_progress_document_id,
    recovery_abandonment_result_document_id,
    service_claim_document_id,
    service_claim_logical_id,
    signed_evidence_event_document_id,
)
from controlgraph_canary.integrations.google.firestore import (
    FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
    AsyncFirestoreAuthorityClientPort,
    FirestoreAuthorityStore,
    _await_shielded,
    _aware_utc,
    _consume_background_result,
    _DecodedDocument,
    _document_data,
    _DocumentReferencePort,
    _ExpectedStateMismatch,
    _is_contention,
    _prepared_document,
    _PreparedDocument,
    _ProviderSnapshotPort,
    _stored,
    _TransactionBody,
    _TransactionCommitDisposition,
    _TransactionPort,
    _validate_authority_advance,
    _validate_read_root_creation_bundle,
)

_DOCUMENT_FIELDS: Final = frozenset(AuthorityStorageDocument.model_fields)
_HEALTH_DOCUMENT_FIELDS: Final = frozenset(HealthStorageDocumentV1.model_fields)
_RECOVERY_ABANDONMENT_OPERATION_TIMEOUT_SECONDS: Final = 15.0
_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS: Final = 10.0


def _claim_ownership_binding(
    claim: ServiceClaimRecord | ServiceClaimRecordV3,
) -> tuple[object, ...]:
    return (
        claim.target,
        claim.root_id,
        claim.root_sha256,
        claim.stable_revision,
        claim.candidate_revision,
        claim.initial_epoch,
        claim.baseline_service_generation,
        claim.baseline_configuration_sha256,
        claim.baseline_revision_configuration_sha256,
        claim.candidate_revision_configuration_sha256,
        claim.stable_target_configuration_sha256,
        claim.candidate_target_configuration_sha256,
        claim.operator_owner,
        claim.workload_creator,
        claim.claim_request_id,
        claim.claim_evidence_id,
        claim.claimed_at,
    )


@dataclass(frozen=True, slots=True)
class _DecodedHealthDocument[ModelT: StrictContractModel]:
    wrapper: HealthStorageDocumentV1
    value: ModelT

    @property
    def stored(self) -> StoredRecord[ModelT]:
        return StoredRecord(value=self.value, revision=self.wrapper.revision)


def _prepared_health_document[ModelT: StrictContractModel](
    *,
    kind: HealthStorageKind,
    logical_id: str,
    document_id: str,
    revision: int,
    target: TargetBinding,
    value: ModelT,
) -> tuple[HealthStorageDocumentV1, ModelT, str]:
    wrapper = HealthStorageDocumentV1(
        schema_version=HEALTH_STORAGE_DOCUMENT_V1,
        record_kind=kind,
        target=target,
        logical_id=logical_id,
        revision=revision,
        mutation_id=f"health-write-{uuid4().hex}",
        canonical_payload=canonical_json_bytes(value).decode("utf-8"),
        payload_sha256=canonical_sha256(value),
    )
    if type(document_id) is not str or len(document_id) != 64:
        raise ValueError("health storage document identity is invalid")
    return wrapper, value, document_id


def _health_document_data(document: HealthStorageDocumentV1) -> dict[str, Any]:
    data = document.model_dump(mode="json")
    if set(data) != _HEALTH_DOCUMENT_FIELDS:
        raise AuthorityStoreCorruptRecord
    return data


def _dispatch_state_is_abandonable(
    stored: StoredRecord[RecoveryDispatchRecordV2],
) -> bool:
    expected_revision = {
        RecoveryDispatchState.ENQUEUE_STARTED: 1,
        RecoveryDispatchState.CREATED: 2,
        RecoveryDispatchState.DUPLICATE: 2,
    }
    return stored.revision == expected_revision.get(stored.value.state)


def _dispatch_epoch_is_abandonable(
    authority: EpochAuthorityRecord,
    *,
    command_epoch: int,
    dispatch_epoch: int,
) -> bool:
    if authority.current_epoch != command_epoch:
        return False
    if dispatch_epoch == command_epoch:
        return True
    return (
        dispatch_epoch + 1 == command_epoch
        and authority.previous_epoch == dispatch_epoch
        and authority.cause is EpochChangeCause.OPERATOR_REVOCATION
    )


def _validate_abandonment_claim_fence_authority(
    configured_target: TargetBinding,
    expected_claim: StoredRecord[ServiceClaimRecord],
    replacement_claim: ServiceClaimRecordV3,
    expected_authority: StoredRecord[EpochAuthorityRecord],
    replacement_authority: EpochAuthorityRecord,
) -> None:
    current_claim = expected_claim.value
    if (
        type(current_claim) is not ServiceClaimRecord
        or type(replacement_claim) is not ServiceClaimRecordV3
        or current_claim.target != configured_target
        or replacement_claim.target != configured_target
        or current_claim.status is not ServiceClaimStatus.ACTIVE
        or replacement_claim.status is not ServiceClaimStatus.RELEASING
        or _claim_ownership_binding(replacement_claim) != _claim_ownership_binding(current_claim)
    ):
        raise ValueError("abandonment claim replacement is not an exact fence")
    _validate_authority_advance(
        configured_target,
        expected_authority,
        replacement_authority,
    )
    current_authority = expected_authority.value
    if (
        current_claim.root_id != current_authority.root_id
        or current_claim.root_sha256 != current_authority.root_sha256
        or replacement_claim.root_id != replacement_authority.root_id
        or replacement_claim.root_sha256 != replacement_authority.root_sha256
        or replacement_claim.release_fence_epoch != replacement_authority.current_epoch
        or replacement_claim.release_fence_authority_revision != replacement_authority.revision
        or replacement_claim.release_fenced_by != replacement_authority.changed_by
        or replacement_claim.release_fence_request_id != replacement_authority.request_id
        or replacement_claim.release_fence_evidence_id != replacement_authority.evidence_id
        or replacement_claim.release_fenced_at != replacement_authority.changed_at
        or replacement_authority.cause is not EpochChangeCause.OPERATOR_REVOCATION
    ):
        raise ValueError("abandonment claim fence and authority are not one transition")


def _validate_recovery_abandonment_fence_commit(
    configured_target: TargetBinding,
    expected: RecoveryAbandonmentState,
    commit: RecoveryAbandonmentFenceCommitV1,
) -> None:
    if (
        type(expected) is not RecoveryAbandonmentState
        or type(commit) is not RecoveryAbandonmentFenceCommitV1
        or expected.root_bundle is None
        or type(expected.recovery_intent) is not StoredRecord
        or expected.recovery_intent.revision != 0
        or type(expected.recovery_intent.value) is not RecoveryIntentV1
        or type(expected.recovery_dispatch) is not StoredRecord
        or type(expected.recovery_dispatch.value) is not RecoveryDispatchRecordV2
        or expected.recovery_receipt is not None
        or not _dispatch_state_is_abandonable(expected.recovery_dispatch)
        or any(
            value is not None
            for value in (
                expected.abandonment_evidence,
                expected.fence_evidence,
                expected.classification_evidence,
                expected.release_evidence,
                expected.request_identity,
                expected.idempotency_identity,
                expected.progress,
                expected.result,
            )
        )
    ):
        raise ValueError("recovery abandonment fence state is not pristine")
    bundle = expected.root_bundle
    _validate_read_root_creation_bundle(configured_target, bundle)
    current_claim = bundle.service_claim.value
    replacement_claim = commit.replacement_claim
    if (
        type(current_claim) is not ServiceClaimRecord
        or type(replacement_claim) is not ServiceClaimRecordV3
        or current_claim.status is not ServiceClaimStatus.ACTIVE
        or replacement_claim.status is not ServiceClaimStatus.RELEASING
        or _claim_ownership_binding(replacement_claim) != _claim_ownership_binding(current_claim)
    ):
        raise ValueError("abandonment claim version transition is invalid")
    _validate_abandonment_claim_fence_authority(
        configured_target,
        cast(StoredRecord[ServiceClaimRecord], bundle.service_claim),
        replacement_claim,
        bundle.authority,
        commit.replacement_authority,
    )
    dispatch = expected.recovery_dispatch.value
    intent = expected.recovery_intent.value
    replacement_dispatch = commit.replacement_dispatch
    immutable_dispatch = dispatch.model_dump(
        mode="python",
        exclude={"state", "terminal_at", "result"},
    )
    immutable_replacement = replacement_dispatch.model_dump(
        mode="python",
        exclude={"state", "terminal_at", "result"},
    )
    request_sha256 = recovery_abandonment_request_sha256(expected.invocation)
    command = expected.invocation.command
    progress = commit.progress
    abandonment = commit.abandonment_evidence
    fence = commit.fence_evidence
    abandonment_subject = commit.abandonment_subject
    fence_subject = commit.fence_subject
    abandonment_proof = replacement_claim.terminal_root_proof
    root = bundle.root.value
    authority = bundle.authority.value
    previous_dispatch_revision = expected.recovery_dispatch.revision
    ambiguous_dispatch_revision = previous_dispatch_revision + 1
    previous_head = current_evidence_chain_head(
        bundle,
        target=configured_target,
        stored_head=expected.chain_head,
        head_evidence=expected.head_evidence,
    )
    if (
        immutable_dispatch != immutable_replacement
        or type(abandonment_proof) is not ServiceClaimAbandonmentProofV1
        or intent.root_id != command.root_id
        or intent.root_sha256 != command.expected_root_sha256
        or intent.epoch != dispatch.epoch
        or intent.command_sha256 != dispatch.command_sha256
        or recovery_command_sha256(intent.command) != intent.command_sha256
        or replacement_dispatch.state is not RecoveryDispatchState.AMBIGUOUS
        or replacement_dispatch.result is None
        or replacement_dispatch.result.enqueue_disposition != "AMBIGUOUS"
        or (
            previous_dispatch_revision == 1
            and replacement_dispatch.terminal_at != progress.fenced_at
        )
        or (
            previous_dispatch_revision == 2
            and (
                replacement_dispatch.terminal_at != dispatch.terminal_at
                or replacement_dispatch.terminal_at is None
                or replacement_dispatch.terminal_at > progress.fenced_at
            )
        )
        or recovery_dispatch_record_sha256(dispatch) != command.expected_dispatch_sha256
        or dispatch.dispatch_id != command.recovery_dispatch_id
        or dispatch.dispatch_id != recovery_dispatch_id(intent.command_sha256)
        or not _dispatch_epoch_is_abandonable(
            authority,
            command_epoch=command.expected_epoch,
            dispatch_epoch=dispatch.epoch,
        )
        or dispatch.root_id != command.root_id
        or dispatch.root_sha256 != command.expected_root_sha256
        or dispatch.target != configured_target
        or dispatch.task.expires_at > progress.fenced_at
        or replacement_claim.release_fenced_by != expected.invocation.operator_identity
        or replacement_claim.release_fence_request_id != command.request_id
        or replacement_claim.release_fence_evidence_id
        != recovery_abandonment_evidence_id(request_sha256, "fence")
        or replacement_claim.release_fenced_at != progress.fenced_at
        or replacement_claim.released_by is not None
        or replacement_claim.release_request_id is not None
        or replacement_claim.release_evidence_id is not None
        or replacement_claim.released_at is not None
        or replacement_claim.target_classification_proof is not None
        or abandonment_proof.target != configured_target
        or abandonment_proof.root_id != root.root_id
        or abandonment_proof.root_sha256 != root.root_sha256
        or abandonment_proof.recovery_dispatch_id != dispatch.dispatch_id
        or abandonment_proof.recovery_dispatch_sha256
        != recovery_dispatch_record_sha256(replacement_dispatch)
        or abandonment_proof.recovery_dispatch_revision != ambiguous_dispatch_revision
        or abandonment_proof.recovery_receipt_id
        != execution_receipt_logical_id(configured_target, dispatch.idempotency_key)
        or abandonment_proof.receipt_absent_at_fence is not True
        or abandonment_proof.required_stable_baseline_configuration_sha256
        != current_claim.stable_target_configuration_sha256
        or abandonment_proof.evidence_id
        != recovery_abandonment_evidence_id(request_sha256, "ambiguity")
        or abandonment_proof.evidence_sha256 != canonical_sha256(abandonment)
        or abandonment_proof.confirmed_by != "controlgraph.coordinator/v1"
        or abandonment_proof.confirmed_at != progress.fenced_at
        or progress.request_sha256 != request_sha256
        or progress.request_id != command.request_id
        or progress.idempotency_key != command.idempotency_key
        or progress.root_id != root.root_id
        or progress.root_sha256 != root.root_sha256
        or progress.target != configured_target
        or progress.recovery_dispatch_id != dispatch.dispatch_id
        or progress.previous_dispatch_sha256 != recovery_dispatch_record_sha256(dispatch)
        or progress.ambiguous_dispatch_sha256
        != recovery_dispatch_record_sha256(replacement_dispatch)
        or progress.recovery_receipt_id
        != execution_receipt_logical_id(configured_target, dispatch.idempotency_key)
        or commit.abandonment_subject != progress.abandonment_subject
        or commit.fence_subject != progress.fence_subject
        or abandonment_subject.target != configured_target
        or abandonment_subject.root_id != root.root_id
        or abandonment_subject.root_sha256 != root.root_sha256
        or abandonment_subject.request_sha256 != request_sha256
        or abandonment_subject.recovery_dispatch_id != dispatch.dispatch_id
        or abandonment_subject.previous_dispatch_sha256 != recovery_dispatch_record_sha256(dispatch)
        or abandonment_subject.ambiguous_dispatch_sha256
        != recovery_dispatch_record_sha256(replacement_dispatch)
        or abandonment_subject.previous_dispatch_revision != previous_dispatch_revision
        or abandonment_subject.ambiguous_dispatch_revision != ambiguous_dispatch_revision
        or abandonment_subject.task_id != dispatch.task.task_id
        or abandonment_subject.task_name != dispatch.task_name
        or abandonment_subject.task_sha256 != dispatch.task_sha256
        or abandonment_subject.capability_id != dispatch.capability_id
        or abandonment_subject.capability_sha256 != canonical_sha256(dispatch.task.capability)
        or abandonment_subject.task_expires_at != dispatch.task.expires_at
        or abandonment_subject.recovery_receipt_id != progress.recovery_receipt_id
        or abandonment_subject.receipt_absent_at_fence is not True
        or abandonment_subject.reason != command.reason
        or abandonment_subject.operator_identity != expected.invocation.operator_identity
        or abandonment_subject.operator_subject != expected.invocation.operator_subject
        or abandonment_subject.evidence_id
        != recovery_abandonment_evidence_id(request_sha256, "ambiguity")
        or abandonment_subject.abandoned_at != progress.fenced_at
        or fence_subject.target != configured_target
        or fence_subject.root_id != root.root_id
        or fence_subject.root_sha256 != root.root_sha256
        or fence_subject.request_sha256 != request_sha256
        or fence_subject.request_id != command.request_id
        or fence_subject.idempotency_key != command.idempotency_key
        or fence_subject.operator_identity != expected.invocation.operator_identity
        or fence_subject.operator_subject != expected.invocation.operator_subject
        or fence_subject.abandonment_evidence_id != abandonment.event.evidence_id
        or fence_subject.abandonment_evidence_sha256 != canonical_sha256(abandonment)
        or fence_subject.previous_claim_sha256 != canonical_sha256(current_claim)
        or fence_subject.replacement_claim_sha256 != canonical_sha256(replacement_claim)
        or fence_subject.previous_authority_sha256 != canonical_sha256(authority)
        or fence_subject.replacement_authority_sha256
        != canonical_sha256(commit.replacement_authority)
        or fence_subject.previous_epoch != authority.current_epoch
        or fence_subject.new_epoch != commit.replacement_authority.current_epoch
        or fence_subject.evidence_id != recovery_abandonment_evidence_id(request_sha256, "fence")
        or fence_subject.fenced_at != progress.fenced_at
        or abandonment.event.evidence_id != abandonment_subject.evidence_id
        or abandonment.event.kind is not EvidenceKind.OUTCOME_AMBIGUOUS
        or abandonment.event.reason_code is not None
        or abandonment.event.sequence != previous_head.sequence + 1
        or abandonment.event.previous_event_sha256 != previous_head.evidence_sha256
        or abandonment.event.subject_sha256 != canonical_sha256(commit.abandonment_subject)
        or abandonment.event.root_id != root.root_id
        or abandonment.event.root_sha256 != root.root_sha256
        or abandonment.event.target != configured_target
        or abandonment.event.epoch != authority.current_epoch
        or abandonment.event.actor != expected.invocation.operator_identity
        or abandonment.event.request_id != command.request_id
        or abandonment.event.receipt_id is not None
        or abandonment.event.occurred_at != progress.fenced_at
        or abandonment.event.provider_operation is not None
        or abandonment.event.target_configuration_sha256 is not None
        or abandonment.signing_key_version != root.content.evidence_signing_key_version
        or fence.event.evidence_id != fence_subject.evidence_id
        or fence.event.kind is not EvidenceKind.EPOCH_ADVANCED
        or fence.event.sequence != abandonment.event.sequence + 1
        or fence.event.previous_event_sha256 != canonical_sha256(abandonment)
        or fence.event.subject_sha256 != canonical_sha256(commit.fence_subject)
        or fence.event.root_id != root.root_id
        or fence.event.root_sha256 != root.root_sha256
        or fence.event.target != configured_target
        or fence.event.epoch != commit.replacement_authority.current_epoch
        or fence.event.actor != expected.invocation.operator_identity
        or fence.event.request_id != command.request_id
        or fence.event.receipt_id is not None
        or fence.event.occurred_at != progress.fenced_at
        or fence.event.reason_code is not None
        or fence.event.provider_operation is not None
        or fence.event.target_configuration_sha256 is not None
        or fence.signing_key_version != root.content.evidence_signing_key_version
        or progress.abandonment_evidence_id != abandonment.event.evidence_id
        or progress.abandonment_evidence_sha256 != canonical_sha256(abandonment)
        or progress.fence_evidence_id != fence.event.evidence_id
        or progress.fence_evidence_sha256 != canonical_sha256(fence)
        or progress.fenced_epoch != commit.replacement_authority.current_epoch
        or progress.fenced_authority_revision != commit.replacement_authority.revision
        or progress.fenced_at != commit.replacement_authority.changed_at
        or commit.chain_head.root_id != root.root_id
        or commit.chain_head.root_sha256 != root.root_sha256
        or commit.chain_head.target != configured_target
        or commit.chain_head.evidence_sha256 != canonical_sha256(fence)
        or commit.chain_head.evidence_id != fence.event.evidence_id
        or commit.chain_head.sequence != fence.event.sequence
        or commit.chain_head.kind is not fence.event.kind
        or commit.chain_head.epoch != fence.event.epoch
        or commit.chain_head.updated_at != fence.event.occurred_at
        or commit.request_identity.identity_kind is not RecoveryAbandonmentIdentityKind.REQUEST
        or commit.idempotency_identity.identity_kind
        is not RecoveryAbandonmentIdentityKind.IDEMPOTENCY
        or commit.request_identity.request_sha256 != request_sha256
        or commit.idempotency_identity.request_sha256 != request_sha256
        or commit.request_identity.identity_value != command.request_id
        or commit.idempotency_identity.identity_value != command.idempotency_key
        or commit.request_identity.root_id != root.root_id
        or commit.idempotency_identity.root_id != root.root_id
        or commit.request_identity.root_sha256 != root.root_sha256
        or commit.idempotency_identity.root_sha256 != root.root_sha256
        or commit.request_identity.result_id != progress.result_id
        or commit.idempotency_identity.result_id != progress.result_id
        or commit.request_identity.claimed_at != progress.fenced_at
        or commit.idempotency_identity.claimed_at != progress.fenced_at
    ):
        raise ValueError("recovery abandonment fence commit is not exactly bound")


def _validate_recovery_abandonment_finalize_commit(
    configured_target: TargetBinding,
    expected: RecoveryAbandonmentState,
    commit: RecoveryAbandonmentFinalizeCommitV1,
) -> None:
    if (
        type(expected) is not RecoveryAbandonmentState
        or type(commit) is not RecoveryAbandonmentFinalizeCommitV1
        or expected.root_bundle is None
        or type(expected.root_bundle.service_claim.value) is not ServiceClaimRecordV3
        or type(expected.progress) is not StoredRecord
        or expected.progress.revision != 0
        or type(expected.progress.value) is not RecoveryAbandonmentProgressV1
        or type(expected.request_identity) is not StoredRecord
        or expected.request_identity.revision != 0
        or type(expected.request_identity.value) is not RecoveryAbandonmentIdentityV1
        or type(expected.idempotency_identity) is not StoredRecord
        or expected.idempotency_identity.revision != 0
        or type(expected.idempotency_identity.value) is not RecoveryAbandonmentIdentityV1
        or type(expected.abandonment_evidence) is not StoredRecord
        or expected.abandonment_evidence.revision != 0
        or type(expected.abandonment_evidence.value) is not SignedEvidenceEventV1
        or type(expected.fence_evidence) is not StoredRecord
        or expected.fence_evidence.revision != 0
        or type(expected.fence_evidence.value) is not SignedEvidenceEventV1
        or type(expected.chain_head) is not StoredRecord
        or type(expected.chain_head.value) is not EvidenceChainHeadV1
        or type(expected.head_evidence) is not StoredRecord
        or expected.head_evidence.revision != 0
        or type(expected.head_evidence.value) is not SignedEvidenceEventV1
        or type(expected.recovery_intent) is not StoredRecord
        or expected.recovery_intent.revision != 0
        or type(expected.recovery_intent.value) is not RecoveryIntentV1
        or type(expected.recovery_dispatch) is not StoredRecord
        or type(expected.recovery_dispatch.value) is not RecoveryDispatchRecordV2
        or expected.recovery_dispatch.revision
        != expected.progress.value.abandonment_subject.ambiguous_dispatch_revision
        or expected.recovery_dispatch.value.state is not RecoveryDispatchState.AMBIGUOUS
        or expected.result is not None
        or expected.classification_evidence is not None
        or expected.release_evidence is not None
    ):
        raise ValueError("recovery abandonment finalize state is incomplete")
    bundle = expected.root_bundle
    _validate_read_root_creation_bundle(configured_target, bundle)
    current_claim = cast(ServiceClaimRecordV3, bundle.service_claim.value)
    replacement_claim = commit.replacement_claim
    authority = bundle.authority.value
    command = expected.invocation.command
    invocation = expected.invocation
    request_sha256 = recovery_abandonment_request_sha256(invocation)
    if (
        current_claim.status is not ServiceClaimStatus.RELEASING
        or replacement_claim.status is not ServiceClaimStatus.RELEASED
        or _claim_ownership_binding(replacement_claim) != _claim_ownership_binding(current_claim)
        or replacement_claim.release_fence_epoch != current_claim.release_fence_epoch
        or replacement_claim.release_fence_authority_revision
        != current_claim.release_fence_authority_revision
        or replacement_claim.release_fenced_by != current_claim.release_fenced_by
        or replacement_claim.release_fence_request_id != current_claim.release_fence_request_id
        or replacement_claim.release_fence_evidence_id != current_claim.release_fence_evidence_id
        or replacement_claim.release_fenced_at != current_claim.release_fenced_at
        or replacement_claim.terminal_root_proof != current_claim.terminal_root_proof
        or replacement_claim.released_by != "controlgraph.coordinator/v1"
        or replacement_claim.release_request_id != command.request_id
        or replacement_claim.release_request_id != replacement_claim.release_fence_request_id
        or authority.current_epoch != current_claim.release_fence_epoch
        or authority.revision != current_claim.release_fence_authority_revision
        or authority.changed_by != current_claim.release_fenced_by
        or authority.request_id != current_claim.release_fence_request_id
        or authority.evidence_id != current_claim.release_fence_evidence_id
        or authority.changed_at != current_claim.release_fenced_at
    ):
        raise ValueError("recovery abandonment release transition is invalid")
    progress = expected.progress.value
    dispatch = expected.recovery_dispatch.value
    intent = expected.recovery_intent.value
    result = commit.result
    classification = commit.classification_evidence
    release = commit.release_evidence
    abandonment = expected.abandonment_evidence.value
    fence = expected.fence_evidence.value
    terminal_proof = current_claim.terminal_root_proof
    classification_proof = replacement_claim.target_classification_proof
    classification_subject = commit.classification_subject
    release_subject = commit.release_subject
    root = bundle.root.value
    expected_reader = (
        f"controlgraph-verifier@{configured_target.project_id}.iam.gserviceaccount.com"
    )
    previous_head = current_evidence_chain_head(
        bundle,
        target=configured_target,
        stored_head=expected.chain_head,
        head_evidence=expected.head_evidence,
    )
    if (
        type(terminal_proof) is not ServiceClaimAbandonmentProofV1
        or type(classification_proof) is not ServiceClaimStableBaselineProofV1
        or previous_head.evidence_id != fence.event.evidence_id
        or previous_head.evidence_sha256 != canonical_sha256(fence)
        or expected.head_evidence.value != fence
        or expected.chain_head.revision != previous_head.sequence
    ):
        raise ValueError("recovery abandonment predecessor is invalid")
    classification_request = RecoveryAbandonmentClassificationRequestV1(
        schema_version=RECOVERY_ABANDONMENT_CLASSIFICATION_REQUEST_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=configured_target,
        abandonment_request_sha256=request_sha256,
        classification_evidence_id=recovery_abandonment_evidence_id(
            request_sha256,
            "classification",
        ),
        previous_evidence_sequence=previous_head.sequence,
        previous_event_sha256=previous_head.evidence_sha256,
        stable_revision=current_claim.stable_revision,
        candidate_revision=current_claim.candidate_revision,
        concurrency=root.content.authority_bounds.concurrency,
        expected_classification="STABLE_BASELINE_CONFIRMED",
        expected_target_configuration_sha256=(current_claim.stable_target_configuration_sha256),
        minimum_service_generation_exclusive=(current_claim.baseline_service_generation),
        fenced_epoch=progress.fenced_epoch,
        fenced_authority_revision=progress.fenced_authority_revision,
        request_id=command.request_id,
    )
    if (
        (
            expected.recovery_receipt is not None
            and not late_fence_receipt_matches(
                expected.recovery_receipt,
                dispatch,
                fenced_epoch=progress.fenced_epoch,
                fenced_at=progress.fenced_at,
            )
        )
        or request_sha256 != progress.request_sha256
        or result.phase.value != "RELEASED"
        or result.result_id != progress.result_id
        or result.request_sha256 != request_sha256
        or result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.root_id != root.root_id
        or result.root_sha256 != root.root_sha256
        or result.target != configured_target
        or result.operator_identity != invocation.operator_identity
        or result.operator_subject != invocation.operator_subject
        or result.recovery_dispatch_id != progress.recovery_dispatch_id
        or result.ambiguous_dispatch_sha256 != progress.ambiguous_dispatch_sha256
        or result.recovery_receipt_id != progress.recovery_receipt_id
        or result.abandonment_evidence_id != progress.abandonment_evidence_id
        or result.abandonment_evidence_sha256 != progress.abandonment_evidence_sha256
        or result.fence_evidence_id != progress.fence_evidence_id
        or result.fence_evidence_sha256 != progress.fence_evidence_sha256
        or result.fenced_epoch != progress.fenced_epoch
        or result.fenced_authority_revision != progress.fenced_authority_revision
        or result.fenced_at != progress.fenced_at
        or recovery_dispatch_record_sha256(dispatch) != progress.ambiguous_dispatch_sha256
        or dispatch.dispatch_id != progress.recovery_dispatch_id
        or dispatch.state is not RecoveryDispatchState.AMBIGUOUS
        or (
            progress.abandonment_subject.previous_dispatch_revision == 1
            and dispatch.terminal_at != progress.fenced_at
        )
        or (
            progress.abandonment_subject.previous_dispatch_revision == 2
            and (dispatch.terminal_at is None or dispatch.terminal_at > progress.fenced_at)
        )
        or intent.command_sha256 != dispatch.command_sha256
        or intent.root_id != result.root_id
        or intent.root_sha256 != result.root_sha256
        or intent.epoch != dispatch.epoch
        or dispatch.epoch not in {command.expected_epoch, command.expected_epoch - 1}
        or result.fenced_epoch != command.expected_epoch + 1
        or canonical_sha256(abandonment) != progress.abandonment_evidence_sha256
        or abandonment.event.evidence_id != progress.abandonment_evidence_id
        or canonical_sha256(fence) != progress.fence_evidence_sha256
        or fence.event.evidence_id != progress.fence_evidence_id
        or result.stable_baseline_proof != replacement_claim.target_classification_proof
        or result.release_evidence_id != replacement_claim.release_evidence_id
        or result.release_evidence_sha256 != canonical_sha256(release)
        or result.classification_evidence_id != classification.event.evidence_id
        or result.classification_evidence_sha256 != canonical_sha256(classification)
        or result.classification_subject != classification_subject
        or result.release_subject != release_subject
        or result.released_at != replacement_claim.released_at
        or terminal_proof.evidence_id != result.abandonment_evidence_id
        or terminal_proof.evidence_sha256 != result.abandonment_evidence_sha256
        or classification_proof.target != configured_target
        or classification_proof.root_id != root.root_id
        or classification_proof.root_sha256 != root.root_sha256
        or classification_proof.classification != "STABLE_BASELINE_CONFIRMED"
        or classification_proof.fenced_epoch != progress.fenced_epoch
        or classification_proof.fenced_authority_revision != progress.fenced_authority_revision
        or classification_proof.service_generation <= current_claim.baseline_service_generation
        or classification_proof.target_configuration_sha256
        != current_claim.stable_target_configuration_sha256
        or classification_proof.evidence_id != result.classification_evidence_id
        or classification_proof.evidence_sha256 != result.classification_evidence_sha256
        or classification_proof.classified_by != expected_reader
        or classification_proof.classified_at != classification_subject.classified_at
        or classification_subject.target != configured_target
        or classification_subject.root_id != root.root_id
        or classification_subject.root_sha256 != root.root_sha256
        or classification_subject.request_sha256 != request_sha256
        or classification_subject.classification_request_sha256
        != recovery_abandonment_classification_request_sha256(classification_request)
        or classification_subject.classification != "STABLE_BASELINE_CONFIRMED"
        or classification_subject.fenced_epoch != progress.fenced_epoch
        or classification_subject.fenced_authority_revision != progress.fenced_authority_revision
        or classification_subject.service_generation != classification_proof.service_generation
        or classification_subject.provider_etag != classification_proof.provider_etag
        or classification_subject.target_configuration_sha256
        != classification_proof.target_configuration_sha256
        or classification_subject.evidence_id != result.classification_evidence_id
        or classification_subject.classified_by != expected_reader
        or classification_subject.classified_at != classification_proof.classified_at
        or classification.event.evidence_id
        != recovery_abandonment_evidence_id(request_sha256, "classification")
        or classification.event.kind is not EvidenceKind.TARGET_VERIFIED
        or classification.event.sequence != previous_head.sequence + 1
        or classification.event.previous_event_sha256 != previous_head.evidence_sha256
        or classification.event.subject_sha256 != canonical_sha256(classification_subject)
        or classification.event.root_id != root.root_id
        or classification.event.root_sha256 != root.root_sha256
        or classification.event.target != configured_target
        or classification.event.epoch != progress.fenced_epoch
        or classification.event.actor != expected_reader
        or classification.event.request_id != command.request_id
        or classification.event.receipt_id is not None
        or classification.event.occurred_at != classification_subject.classified_at
        or classification.event.occurred_at < progress.fenced_at
        or classification.event.reason_code is not None
        or classification.event.provider_operation is not None
        or classification.event.target_configuration_sha256
        != current_claim.stable_target_configuration_sha256
        or classification.signing_key_version != root.content.evidence_signing_key_version
        or release_subject.target != configured_target
        or release_subject.root_id != root.root_id
        or release_subject.root_sha256 != root.root_sha256
        or release_subject.request_sha256 != request_sha256
        or release_subject.request_id != command.request_id
        or release_subject.idempotency_key != command.idempotency_key
        or release_subject.operator_identity != invocation.operator_identity
        or release_subject.operator_subject != invocation.operator_subject
        or release_subject.classification_evidence_id != result.classification_evidence_id
        or release_subject.classification_evidence_sha256 != result.classification_evidence_sha256
        or release_subject.fenced_claim_sha256 != canonical_sha256(current_claim)
        or release_subject.released_claim_sha256 != canonical_sha256(replacement_claim)
        or release_subject.fenced_authority_sha256 != canonical_sha256(authority)
        or release_subject.fenced_epoch != progress.fenced_epoch
        or release_subject.fenced_authority_revision != progress.fenced_authority_revision
        or release_subject.evidence_id
        != recovery_abandonment_evidence_id(request_sha256, "release")
        or release_subject.released_at != result.released_at
        or release.event.evidence_id != release_subject.evidence_id
        or release.event.kind is not EvidenceKind.TARGET_VERIFIED
        or release.event.sequence != classification.event.sequence + 1
        or release.event.previous_event_sha256 != canonical_sha256(classification)
        or release.event.subject_sha256 != canonical_sha256(release_subject)
        or release.event.root_id != root.root_id
        or release.event.root_sha256 != root.root_sha256
        or release.event.target != configured_target
        or release.event.epoch != progress.fenced_epoch
        or release.event.actor != "controlgraph.coordinator/v1"
        or release.event.request_id != command.request_id
        or release.event.receipt_id is not None
        or release.event.occurred_at != result.released_at
        or release.event.occurred_at < classification.event.occurred_at
        or release.event.reason_code is not None
        or release.event.provider_operation is not None
        or release.event.target_configuration_sha256
        != current_claim.stable_target_configuration_sha256
        or release.signing_key_version != root.content.evidence_signing_key_version
        or commit.chain_head.root_id != root.root_id
        or commit.chain_head.root_sha256 != root.root_sha256
        or commit.chain_head.target != configured_target
        or commit.chain_head.evidence_id != release.event.evidence_id
        or commit.chain_head.evidence_sha256 != canonical_sha256(release)
        or commit.chain_head.sequence != release.event.sequence
        or commit.chain_head.kind is not release.event.kind
        or commit.chain_head.epoch != release.event.epoch
        or commit.chain_head.updated_at != release.event.occurred_at
    ):
        raise ValueError("recovery abandonment finalize commit is not exactly bound")


class FirestoreRecoveryAbandonmentStore(FirestoreAuthorityStore):
    @staticmethod
    def _health_reference(
        client: AsyncFirestoreAuthorityClientPort,
        kind: HealthStorageKind,
        document_id: str,
    ) -> _DocumentReferencePort:
        expected_path = f"{kind.value}/{document_id}"
        try:
            reference = client.document(kind.value, document_id)
            path = reference.path
        except Exception:
            raise AuthorityStoreUnavailable from None
        if path != expected_path:
            raise AuthorityStoreCorruptRecord
        return reference

    async def _transaction_read_health[ModelT: StrictContractModel](
        self,
        transaction: _TransactionPort,
        *,
        reference: _DocumentReferencePort,
        kind: HealthStorageKind,
        logical_id: str,
        document_id: str,
        model_type: type[ModelT],
        timeout_seconds: float | None = None,
    ) -> _DecodedHealthDocument[ModelT] | None:
        snapshot = await self._get_snapshot(
            reference,
            transaction=transaction,
            timeout_seconds=timeout_seconds,
        )
        try:
            provider_snapshot = cast(_ProviderSnapshotPort, snapshot)
            if provider_snapshot.reference.path != reference.path:
                raise ValueError("health snapshot reference does not match")
            if type(provider_snapshot.exists) is not bool:
                raise ValueError("health snapshot existence flag is invalid")
            _aware_utc(provider_snapshot.read_time)
            data = provider_snapshot.to_dict()
            if not provider_snapshot.exists:
                if data is not None or provider_snapshot.update_time is not None:
                    raise ValueError("missing health snapshot contains state")
                return None
            _aware_utc(provider_snapshot.update_time)
            if type(data) is not dict or set(data) != _HEALTH_DOCUMENT_FIELDS:
                raise ValueError("health storage wrapper is not exact")
            normalized = dict(data)
            normalized["record_kind"] = kind
            wrapper = HealthStorageDocumentV1.model_validate(normalized)
            if (
                wrapper.record_kind is not kind
                or wrapper.target != self._target
                or wrapper.logical_id != logical_id
                or reference.path != f"{kind.value}/{document_id}"
            ):
                raise ValueError("health storage identity does not match")
            value = decode_contract(wrapper.canonical_payload, model_type)
            if canonical_sha256(value) != wrapper.payload_sha256:
                raise ValueError("health storage payload digest does not match")
            return _DecodedHealthDocument(wrapper=wrapper, value=value)
        except (AuthorityStoreCorruptRecord, asyncio.CancelledError):
            raise
        except Exception:
            raise AuthorityStoreCorruptRecord from None

    async def _run_transaction(
        self,
        documents: tuple[_PreparedDocument[StrictContractModel], ...],
        body: _TransactionBody,
        *,
        expected_writes: int | None = None,
    ) -> _TransactionCommitDisposition:
        client = await self._client()
        write_count = len(documents) if expected_writes is None else expected_writes
        if type(write_count) is not int or write_count < len(documents):
            raise ValueError("transaction write count is invalid")

        async def execute() -> _TransactionCommitDisposition:
            try:
                await self._transaction_runner(
                    client,
                    FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
                    write_count,
                    body,
                )
            except asyncio.CancelledError:
                raise
            except AuthorityStoreCorruptRecord:
                raise
            except _ExpectedStateMismatch:
                raise AuthorityStoreConflict from None
            except Exception as error:
                if _is_contention(error):
                    raise AuthorityStoreConflict from None
                await self._resolve_ambiguous(documents)
                return _TransactionCommitDisposition.READBACK_RESOLVED
            return _TransactionCommitDisposition.DIRECT_CONFIRMED

        operation = asyncio.create_task(execute())
        try:
            return await _await_shielded(
                operation,
                timeout_seconds=_RECOVERY_ABANDONMENT_OPERATION_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            operation.add_done_callback(_consume_background_result)
            raise
        except TimeoutError:
            operation.add_done_callback(_consume_background_result)

        classification = asyncio.create_task(self._resolve_ambiguous(documents))
        try:
            await _await_shielded(
                classification,
                timeout_seconds=_RECOVERY_ABANDONMENT_OPERATION_TIMEOUT_SECONDS,
            )
            return _TransactionCommitDisposition.READBACK_RESOLVED
        except asyncio.CancelledError:
            classification.add_done_callback(_consume_background_result)
            raise
        except TimeoutError:
            classification.add_done_callback(_consume_background_result)
            raise AuthorityStoreOutcomeUnknown from None

    async def read_recovery_abandonment_state(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
    ) -> RecoveryAbandonmentState:
        """Read authority, health dispatch, receipt, and abandonment metadata together."""

        if type(invocation) is not RecoveryAbandonmentInvocationV1:
            raise TypeError("recovery abandonment state requires an exact invocation")
        command = invocation.command
        request_sha256 = recovery_abandonment_request_sha256(invocation)
        result_id = f"cgabandon:{request_sha256}"
        decoded_state: RecoveryAbandonmentState | None = None

        async def read(transaction: _TransactionPort) -> None:
            nonlocal decoded_state
            client = await self._client()
            root_id = command.root_id
            root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                root_id,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            authority_document_id = epoch_authority_document_id(root_id)
            authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            creation = await self._transaction_read_root_creation_result(
                transaction,
                client,
                root_id,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            root_bundle: RootCreationBundle | None = None
            root_evidence: _DecodedDocument[SignedEvidenceEventV1] | None = None
            if any(value is not None for value in (root, authority, creation)):
                if root is None or authority is None or creation is None:
                    raise AuthorityStoreCorruptRecord
                claim_logical_id = service_claim_logical_id(self._target)
                claim_document_id = service_claim_document_id(self._target)
                claim = await self._transaction_read_service_claim(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SERVICE_CLAIM,
                        claim_document_id,
                    ),
                    logical_id=claim_logical_id,
                    document_id=claim_document_id,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )
                anchor = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
                        capability_lineage_anchor_document_id(creation.value.lineage_anchor),
                    ),
                    kind=AuthorityStorageKind.CAPABILITY_LINEAGE_ANCHOR,
                    logical_id=creation.value.winner_lineage_anchor_id,
                    document_id=capability_lineage_anchor_document_id(
                        creation.value.lineage_anchor
                    ),
                    model_type=CapabilityLineageAnchorV1,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )
                root_evidence_id = creation.value.winner_evidence_id
                root_evidence_document_id = signed_evidence_event_document_id(root_evidence_id)
                root_evidence = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        root_evidence_document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=root_evidence_id,
                    document_id=root_evidence_document_id,
                    model_type=SignedEvidenceEventV1,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )
                if claim is None or anchor is None or root_evidence is None:
                    raise AuthorityStoreCorruptRecord
                root_bundle = RootCreationBundle(
                    root=root.stored,
                    service_claim=claim.stored,
                    authority=authority.stored,
                    lineage_anchor=anchor.stored,
                    signed_evidence=root_evidence.stored,
                    creation_result=creation.stored,
                )

            head_document_id = evidence_chain_head_document_id(root_id)
            head = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document_id,
                ),
                kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                logical_id=root_id,
                document_id=head_document_id,
                model_type=EvidenceChainHeadV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            head_evidence: _DecodedDocument[SignedEvidenceEventV1] | None = None
            if head is not None:
                if (
                    root_evidence is not None
                    and root_evidence.value.event.evidence_id == head.value.evidence_id
                ):
                    head_evidence = root_evidence
                else:
                    head_evidence_id = head.value.evidence_id
                    head_evidence_document_id = signed_evidence_event_document_id(head_evidence_id)
                    head_evidence = await self._transaction_read(
                        transaction,
                        reference=self._reference(
                            client,
                            AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                            head_evidence_document_id,
                        ),
                        kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        logical_id=head_evidence_id,
                        document_id=head_evidence_document_id,
                        model_type=SignedEvidenceEventV1,
                        timeout_seconds=(
                            _RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS
                        ),
                    )
                    if head_evidence is None:
                        raise AuthorityStoreCorruptRecord

            intent_logical_id = recovery_intent_id(command.expected_root_sha256)
            intent_document_id = recovery_intent_document_id(
                self._target,
                command.expected_root_sha256,
            )
            intent = await self._transaction_read_health(
                transaction,
                reference=self._health_reference(
                    client,
                    HealthStorageKind.RECOVERY_INTENT,
                    intent_document_id,
                ),
                kind=HealthStorageKind.RECOVERY_INTENT,
                logical_id=intent_logical_id,
                document_id=intent_document_id,
                model_type=RecoveryIntentV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            dispatch: _DecodedHealthDocument[RecoveryDispatchStorageRecordV2] | None = None
            receipt: _DecodedDocument[ExecutionReceipt] | None = None
            if intent is not None:
                recovery_command = intent.value.command
                command_sha256 = recovery_command_sha256(recovery_command)
                dispatch_id = recovery_dispatch_id(command_sha256)
                request_identity_logical_id = health_recovery_dispatch_identity_logical_id(
                    RecoveryDispatchIdentityKind.REQUEST.value,
                    recovery_command.request_id,
                )
                idempotency_identity_logical_id = health_recovery_dispatch_identity_logical_id(
                    RecoveryDispatchIdentityKind.IDEMPOTENCY.value,
                    recovery_command.idempotency_key,
                )
                request_identity_document_id = health_recovery_dispatch_identity_document_id(
                    self._target,
                    RecoveryDispatchIdentityKind.REQUEST.value,
                    recovery_command.request_id,
                )
                idempotency_identity_document_id = health_recovery_dispatch_identity_document_id(
                    self._target,
                    RecoveryDispatchIdentityKind.IDEMPOTENCY.value,
                    recovery_command.idempotency_key,
                )
                recovery_request_identity = await self._transaction_read_health(
                    transaction,
                    reference=self._health_reference(
                        client,
                        HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
                        request_identity_document_id,
                    ),
                    kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
                    logical_id=request_identity_logical_id,
                    document_id=request_identity_document_id,
                    model_type=RecoveryDispatchIdentityV2,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )
                recovery_idempotency_identity = await self._transaction_read_health(
                    transaction,
                    reference=self._health_reference(
                        client,
                        HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
                        idempotency_identity_document_id,
                    ),
                    kind=HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
                    logical_id=idempotency_identity_logical_id,
                    document_id=idempotency_identity_document_id,
                    model_type=RecoveryDispatchIdentityV2,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )
                dispatch_document_id = health_recovery_dispatch_document_id(
                    self._target,
                    dispatch_id,
                )
                dispatch = await self._transaction_read_health(
                    transaction,
                    reference=self._health_reference(
                        client,
                        HealthStorageKind.RECOVERY_DISPATCH,
                        dispatch_document_id,
                    ),
                    kind=HealthStorageKind.RECOVERY_DISPATCH,
                    logical_id=dispatch_id,
                    document_id=dispatch_document_id,
                    model_type=RecoveryDispatchStorageRecordV2,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )
                if any(
                    value is None
                    for value in (
                        recovery_request_identity,
                        recovery_idempotency_identity,
                        dispatch,
                    )
                ):
                    raise AuthorityStoreCorruptRecord
                assert recovery_request_identity is not None
                assert recovery_idempotency_identity is not None
                assert dispatch is not None
                dispatch_value = recovery_dispatch_storage_record_value(dispatch.value)
                if (
                    recovery_request_identity.value.dispatch_id != dispatch_id
                    or recovery_idempotency_identity.value.dispatch_id != dispatch_id
                    or dispatch_value.request_id != recovery_command.request_id
                    or dispatch_value.idempotency_key != recovery_command.idempotency_key
                ):
                    raise AuthorityStoreCorruptRecord
                receipt_logical_id = execution_receipt_logical_id(
                    self._target,
                    dispatch_value.idempotency_key,
                )
                receipt_document_id = execution_receipt_document_id(
                    self._target,
                    dispatch_value.idempotency_key,
                )
                receipt = await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.EXECUTION_RECEIPT,
                        receipt_document_id,
                    ),
                    kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                    logical_id=receipt_logical_id,
                    document_id=receipt_document_id,
                    model_type=ExecutionReceipt,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )

            async def abandonment_evidence(
                stage: Literal["ambiguity", "fence", "classification", "release"],
            ) -> _DecodedDocument[SignedEvidenceEventV1] | None:
                evidence_id = recovery_abandonment_evidence_id(
                    request_sha256,
                    stage,
                )
                document_id = signed_evidence_event_document_id(evidence_id)
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=evidence_id,
                    document_id=document_id,
                    model_type=SignedEvidenceEventV1,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )

            ambiguity = await abandonment_evidence("ambiguity")
            fence = await abandonment_evidence("fence")
            classification = await abandonment_evidence("classification")
            release = await abandonment_evidence("release")

            async def abandonment_identity(
                kind: RecoveryAbandonmentIdentityKind,
                value: str,
            ) -> _DecodedDocument[RecoveryAbandonmentIdentityV1] | None:
                logical_id = recovery_abandonment_identity_logical_id(
                    kind.value,
                    value,
                )
                document_id = recovery_abandonment_identity_document_id(
                    kind.value,
                    value,
                )
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY,
                        document_id,
                    ),
                    kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY,
                    logical_id=logical_id,
                    document_id=document_id,
                    model_type=RecoveryAbandonmentIdentityV1,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )

            request_identity = await abandonment_identity(
                RecoveryAbandonmentIdentityKind.REQUEST,
                command.request_id,
            )
            idempotency_identity = await abandonment_identity(
                RecoveryAbandonmentIdentityKind.IDEMPOTENCY,
                command.idempotency_key,
            )
            progress_document_id = recovery_abandonment_progress_document_id(result_id)
            progress = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS,
                    progress_document_id,
                ),
                kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS,
                logical_id=result_id,
                document_id=progress_document_id,
                model_type=RecoveryAbandonmentProgressV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            result_document_id = recovery_abandonment_result_document_id(result_id)
            result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
                    result_document_id,
                ),
                kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
                logical_id=result_id,
                document_id=result_document_id,
                model_type=RecoveryAbandonmentResultV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            decoded_state = RecoveryAbandonmentState(
                invocation=invocation,
                root_bundle=root_bundle,
                recovery_intent=None if intent is None else intent.stored,
                recovery_dispatch=(
                    None
                    if dispatch is None
                    else StoredRecord(
                        recovery_dispatch_storage_record_value(dispatch.value),
                        dispatch.wrapper.revision,
                    )
                ),
                recovery_receipt=None if receipt is None else receipt.stored,
                chain_head=None if head is None else head.stored,
                head_evidence=(None if head_evidence is None else head_evidence.stored),
                abandonment_evidence=(None if ambiguity is None else ambiguity.stored),
                fence_evidence=None if fence is None else fence.stored,
                classification_evidence=(None if classification is None else classification.stored),
                release_evidence=None if release is None else release.stored,
                request_identity=(None if request_identity is None else request_identity.stored),
                idempotency_identity=(
                    None if idempotency_identity is None else idempotency_identity.stored
                ),
                progress=None if progress is None else progress.stored,
                result=None if result is None else result.stored,
            )

        client = await self._client()
        try:
            async with asyncio.timeout(
                _RECOVERY_ABANDONMENT_OPERATION_TIMEOUT_SECONDS
            ):
                await self._transaction_runner(
                    client,
                    FIRESTORE_MAX_TRANSACTION_ATTEMPTS,
                    0,
                    read,
                )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise
        except Exception:
            raise AuthorityStoreUnavailable from None
        if decoded_state is None:
            raise AuthorityStoreUnavailable
        if decoded_state.root_bundle is not None:
            try:
                _validate_read_root_creation_bundle(
                    self._target,
                    decoded_state.root_bundle,
                )
            except (TypeError, ValueError):
                raise AuthorityStoreCorruptRecord from None
        return decoded_state

    async def commit_recovery_abandonment_fence(
        self,
        expected: RecoveryAbandonmentState,
        commit: RecoveryAbandonmentFenceCommitV1,
    ) -> RecoveryAbandonmentFenceWriteResult:
        """Atomically terminalize the dispatch, prove receipt absence, and fence."""

        _validate_recovery_abandonment_fence_commit(self._target, expected, commit)
        root_bundle = cast(RootCreationBundle, expected.root_bundle)
        expected_dispatch = cast(
            StoredRecord[RecoveryDispatchRecordV2],
            expected.recovery_dispatch,
        )
        claim_logical_id = service_claim_logical_id(self._target)
        claim_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=claim_logical_id,
            document_id=service_claim_document_id(self._target),
            revision=root_bundle.service_claim.revision + 1,
            value=commit.replacement_claim,
        )
        authority_document = _prepared_document(
            kind=AuthorityStorageKind.EPOCH_AUTHORITY,
            logical_id=commit.replacement_authority.root_id,
            document_id=epoch_authority_document_id(commit.replacement_authority.root_id),
            revision=root_bundle.authority.revision + 1,
            value=commit.replacement_authority,
        )
        dispatch_storage = create_recovery_dispatch_storage_record(commit.replacement_dispatch)
        dispatch_document = _prepared_health_document(
            kind=HealthStorageKind.RECOVERY_DISPATCH,
            logical_id=commit.replacement_dispatch.dispatch_id,
            document_id=health_recovery_dispatch_document_id(
                self._target,
                commit.replacement_dispatch.dispatch_id,
            ),
            revision=expected_dispatch.revision + 1,
            target=self._target,
            value=dispatch_storage,
        )

        def evidence_document(
            evidence: SignedEvidenceEventV1,
        ) -> _PreparedDocument[SignedEvidenceEventV1]:
            evidence_id = evidence.event.evidence_id
            return _prepared_document(
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=evidence_id,
                document_id=signed_evidence_event_document_id(evidence_id),
                revision=0,
                value=evidence,
            )

        abandonment_document = evidence_document(commit.abandonment_evidence)
        fence_document = evidence_document(commit.fence_evidence)
        head_document = _prepared_document(
            kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
            logical_id=commit.chain_head.root_id,
            document_id=evidence_chain_head_document_id(commit.chain_head.root_id),
            revision=commit.chain_head.sequence,
            value=commit.chain_head,
        )
        progress_document = _prepared_document(
            kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS,
            logical_id=commit.progress.result_id,
            document_id=recovery_abandonment_progress_document_id(commit.progress.result_id),
            revision=0,
            value=commit.progress,
        )

        def identity_document(
            identity: RecoveryAbandonmentIdentityV1,
        ) -> _PreparedDocument[RecoveryAbandonmentIdentityV1]:
            logical_id = recovery_abandonment_identity_logical_id(
                identity.identity_kind.value,
                identity.identity_value,
            )
            return _prepared_document(
                kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_IDENTITY,
                logical_id=logical_id,
                document_id=recovery_abandonment_identity_document_id(
                    identity.identity_kind.value,
                    identity.identity_value,
                ),
                revision=0,
                value=identity,
            )

        request_identity_document = identity_document(commit.request_identity)
        idempotency_identity_document = identity_document(commit.idempotency_identity)
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            claim_document,
            authority_document,
            abandonment_document,
            fence_document,
            head_document,
            progress_document,
            request_identity_document,
            idempotency_identity_document,
        )

        async def write(transaction: _TransactionPort) -> None:
            client = await self._client()
            current_root = await self._transaction_read_content_addressed_root(
                transaction,
                client,
                commit.progress.root_id,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            current_claim = await self._transaction_read_service_claim(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document.document_id,
                ),
                logical_id=claim_logical_id,
                document_id=claim_document.document_id,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            current_authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document.document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=commit.progress.root_id,
                document_id=authority_document.document_id,
                model_type=EpochAuthorityRecord,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            intent = cast(StoredRecord[RecoveryIntentV1], expected.recovery_intent)
            intent_document_id = recovery_intent_document_id(
                self._target,
                intent.value.root_sha256,
            )
            current_intent = await self._transaction_read_health(
                transaction,
                reference=self._health_reference(
                    client,
                    HealthStorageKind.RECOVERY_INTENT,
                    intent_document_id,
                ),
                kind=HealthStorageKind.RECOVERY_INTENT,
                logical_id=intent.value.intent_id,
                document_id=intent_document_id,
                model_type=RecoveryIntentV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            current_dispatch = await self._transaction_read_health(
                transaction,
                reference=self._health_reference(
                    client,
                    HealthStorageKind.RECOVERY_DISPATCH,
                    dispatch_document[2],
                ),
                kind=HealthStorageKind.RECOVERY_DISPATCH,
                logical_id=commit.replacement_dispatch.dispatch_id,
                document_id=dispatch_document[2],
                model_type=RecoveryDispatchStorageRecordV2,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            current_dispatch_domain = (
                None
                if current_dispatch is None
                else StoredRecord(
                    recovery_dispatch_storage_record_value(current_dispatch.value),
                    current_dispatch.wrapper.revision,
                )
            )
            receipt_document_id = execution_receipt_document_id(
                self._target,
                expected_dispatch.value.idempotency_key,
            )
            current_receipt = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EXECUTION_RECEIPT,
                    receipt_document_id,
                ),
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=execution_receipt_logical_id(
                    self._target,
                    expected_dispatch.value.idempotency_key,
                ),
                document_id=receipt_document_id,
                model_type=ExecutionReceipt,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            current_head = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document.document_id,
                ),
                kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                logical_id=commit.progress.root_id,
                document_id=head_document.document_id,
                model_type=EvidenceChainHeadV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            predecessor = expected.head_evidence or root_bundle.signed_evidence
            predecessor_document_id = signed_evidence_event_document_id(
                predecessor.value.event.evidence_id
            )
            current_predecessor = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    predecessor_document_id,
                ),
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=predecessor.value.event.evidence_id,
                document_id=predecessor_document_id,
                model_type=SignedEvidenceEventV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )

            async def current_authority_document(
                document: _PreparedDocument[StrictContractModel],
                model_type: type[StrictContractModel],
            ) -> _DecodedDocument[StrictContractModel] | None:
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        document.wrapper.record_kind,
                        document.document_id,
                    ),
                    kind=document.wrapper.record_kind,
                    logical_id=document.wrapper.logical_id,
                    document_id=document.document_id,
                    model_type=model_type,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )

            current_new_documents = tuple(
                [
                    await current_authority_document(
                        cast(_PreparedDocument[StrictContractModel], document),
                        type(document.value),
                    )
                    for document in (
                        abandonment_document,
                        fence_document,
                        progress_document,
                        request_identity_document,
                        idempotency_identity_document,
                    )
                ]
            )
            if (
                current_root is None
                or current_root.stored != root_bundle.root
                or current_claim is None
                or current_claim.stored != root_bundle.service_claim
                or current_authority is None
                or current_authority.stored != root_bundle.authority
                or current_intent is None
                or current_intent.stored != intent
                or current_dispatch_domain != expected_dispatch
                or current_receipt is not None
                or (None if current_head is None else current_head.stored) != expected.chain_head
                or current_predecessor is None
                or current_predecessor.stored != predecessor
                or any(value is not None for value in current_new_documents)
            ):
                raise _ExpectedStateMismatch
            transaction.update(
                self._health_reference(
                    client,
                    HealthStorageKind.RECOVERY_DISPATCH,
                    dispatch_document[2],
                ),
                _health_document_data(dispatch_document[0]),
            )
            transaction.update(
                self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document.document_id,
                ),
                _document_data(claim_document.wrapper),
            )
            transaction.update(
                self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document.document_id,
                ),
                _document_data(authority_document.wrapper),
            )
            for document in (
                abandonment_document,
                fence_document,
                progress_document,
                request_identity_document,
                idempotency_identity_document,
            ):
                transaction.create(
                    self._reference(
                        client,
                        document.wrapper.record_kind,
                        document.document_id,
                    ),
                    _document_data(document.wrapper),
                )
            head_reference = self._reference(
                client,
                AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                head_document.document_id,
            )
            if current_head is None:
                transaction.create(head_reference, _document_data(head_document.wrapper))
            else:
                transaction.update(head_reference, _document_data(head_document.wrapper))

        await self._run_transaction(
            documents,
            write,
            expected_writes=9,
        )
        return RecoveryAbandonmentFenceWriteResult(
            recovery_dispatch=StoredRecord(
                commit.replacement_dispatch,
                expected_dispatch.revision + 1,
            ),
            service_claim=_stored(claim_document),
            authority=_stored(authority_document),
            abandonment_evidence=_stored(abandonment_document),
            fence_evidence=_stored(fence_document),
            chain_head=_stored(head_document),
            progress=_stored(progress_document),
            request_identity=_stored(request_identity_document),
            idempotency_identity=_stored(idempotency_identity_document),
        )

    async def commit_recovery_abandonment_release(
        self,
        expected: RecoveryAbandonmentState,
        commit: RecoveryAbandonmentFinalizeCommitV1,
    ) -> RecoveryAbandonmentFinalizeWriteResult:
        """Atomically append stable-baseline proof and release the fenced claim."""

        _validate_recovery_abandonment_finalize_commit(
            self._target,
            expected,
            commit,
        )
        root_bundle = cast(RootCreationBundle, expected.root_bundle)
        claim_logical_id = service_claim_logical_id(self._target)
        claim_document = _prepared_document(
            kind=AuthorityStorageKind.SERVICE_CLAIM,
            logical_id=claim_logical_id,
            document_id=service_claim_document_id(self._target),
            revision=root_bundle.service_claim.revision + 1,
            value=commit.replacement_claim,
        )

        def evidence_document(
            evidence: SignedEvidenceEventV1,
        ) -> _PreparedDocument[SignedEvidenceEventV1]:
            evidence_id = evidence.event.evidence_id
            return _prepared_document(
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=evidence_id,
                document_id=signed_evidence_event_document_id(evidence_id),
                revision=0,
                value=evidence,
            )

        classification_document = evidence_document(commit.classification_evidence)
        release_document = evidence_document(commit.release_evidence)
        head_document = _prepared_document(
            kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
            logical_id=commit.chain_head.root_id,
            document_id=evidence_chain_head_document_id(commit.chain_head.root_id),
            revision=commit.chain_head.sequence,
            value=commit.chain_head,
        )
        result_document = _prepared_document(
            kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
            logical_id=commit.result.result_id,
            document_id=recovery_abandonment_result_document_id(commit.result.result_id),
            revision=0,
            value=commit.result,
        )
        documents: tuple[_PreparedDocument[StrictContractModel], ...] = (
            claim_document,
            classification_document,
            release_document,
            head_document,
            result_document,
        )

        async def write(transaction: _TransactionPort) -> None:
            client = await self._client()
            expected_dispatch = cast(
                StoredRecord[RecoveryDispatchRecordV2],
                expected.recovery_dispatch,
            )
            dispatch_document_id = health_recovery_dispatch_document_id(
                self._target,
                expected_dispatch.value.dispatch_id,
            )
            current_dispatch = await self._transaction_read_health(
                transaction,
                reference=self._health_reference(
                    client,
                    HealthStorageKind.RECOVERY_DISPATCH,
                    dispatch_document_id,
                ),
                kind=HealthStorageKind.RECOVERY_DISPATCH,
                logical_id=expected_dispatch.value.dispatch_id,
                document_id=dispatch_document_id,
                model_type=RecoveryDispatchStorageRecordV2,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            current_dispatch_record = (
                None
                if current_dispatch is None
                else StoredRecord(
                    recovery_dispatch_storage_record_value(current_dispatch.value),
                    current_dispatch.wrapper.revision,
                )
            )
            receipt_document_id = execution_receipt_document_id(
                self._target,
                expected_dispatch.value.idempotency_key,
            )
            current_receipt = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EXECUTION_RECEIPT,
                    receipt_document_id,
                ),
                kind=AuthorityStorageKind.EXECUTION_RECEIPT,
                logical_id=execution_receipt_logical_id(
                    self._target,
                    expected_dispatch.value.idempotency_key,
                ),
                document_id=receipt_document_id,
                model_type=ExecutionReceipt,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            current_claim = await self._transaction_read_service_claim(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document.document_id,
                ),
                logical_id=claim_logical_id,
                document_id=claim_document.document_id,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            authority_document_id = epoch_authority_document_id(commit.result.root_id)
            current_authority = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EPOCH_AUTHORITY,
                    authority_document_id,
                ),
                kind=AuthorityStorageKind.EPOCH_AUTHORITY,
                logical_id=commit.result.root_id,
                document_id=authority_document_id,
                model_type=EpochAuthorityRecord,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            current_head = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document.document_id,
                ),
                kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                logical_id=commit.result.root_id,
                document_id=head_document.document_id,
                model_type=EvidenceChainHeadV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            progress = cast(
                StoredRecord[RecoveryAbandonmentProgressV1],
                expected.progress,
            )
            progress_document_id = recovery_abandonment_progress_document_id(
                progress.value.result_id
            )
            current_progress = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS,
                    progress_document_id,
                ),
                kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_PROGRESS,
                logical_id=progress.value.result_id,
                document_id=progress_document_id,
                model_type=RecoveryAbandonmentProgressV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )

            async def current_evidence(
                stored: StoredRecord[SignedEvidenceEventV1] | None,
            ) -> _DecodedDocument[SignedEvidenceEventV1] | None:
                if stored is None:
                    raise _ExpectedStateMismatch
                evidence_id = stored.value.event.evidence_id
                document_id = signed_evidence_event_document_id(evidence_id)
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=evidence_id,
                    document_id=document_id,
                    model_type=SignedEvidenceEventV1,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )

            current_head_evidence = await current_evidence(expected.head_evidence)
            current_ambiguity = await current_evidence(expected.abandonment_evidence)
            current_fence = await current_evidence(expected.fence_evidence)

            async def new_evidence(
                document: _PreparedDocument[SignedEvidenceEventV1],
            ) -> _DecodedDocument[SignedEvidenceEventV1] | None:
                return await self._transaction_read(
                    transaction,
                    reference=self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        document.document_id,
                    ),
                    kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                    logical_id=document.wrapper.logical_id,
                    document_id=document.document_id,
                    model_type=SignedEvidenceEventV1,
                    timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
                )

            current_classification = await new_evidence(classification_document)
            current_release = await new_evidence(release_document)
            current_result = await self._transaction_read(
                transaction,
                reference=self._reference(
                    client,
                    AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
                    result_document.document_id,
                ),
                kind=AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
                logical_id=commit.result.result_id,
                document_id=result_document.document_id,
                model_type=RecoveryAbandonmentResultV1,
                timeout_seconds=_RECOVERY_ABANDONMENT_RPC_TIMEOUT_SECONDS,
            )
            if (
                current_dispatch_record != expected_dispatch
                or (
                    current_receipt is not None
                    and not late_fence_receipt_matches(
                        current_receipt.stored,
                        expected_dispatch.value,
                        fenced_epoch=progress.value.fenced_epoch,
                        fenced_at=progress.value.fenced_at,
                    )
                )
                or (None if current_receipt is None else current_receipt.stored)
                != expected.recovery_receipt
                or current_claim is None
                or current_claim.stored != root_bundle.service_claim
                or current_authority is None
                or current_authority.stored != root_bundle.authority
                or current_head is None
                or current_head.stored != expected.chain_head
                or current_head_evidence is None
                or current_head_evidence.stored != expected.head_evidence
                or current_ambiguity is None
                or current_ambiguity.stored != expected.abandonment_evidence
                or current_fence is None
                or current_fence.stored != expected.fence_evidence
                or current_progress is None
                or current_progress.stored != progress
                or current_classification is not None
                or current_release is not None
                or current_result is not None
            ):
                raise _ExpectedStateMismatch
            transaction.update(
                self._reference(
                    client,
                    AuthorityStorageKind.SERVICE_CLAIM,
                    claim_document.document_id,
                ),
                _document_data(claim_document.wrapper),
            )
            for document in (classification_document, release_document):
                transaction.create(
                    self._reference(
                        client,
                        AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                        document.document_id,
                    ),
                    _document_data(document.wrapper),
                )
            transaction.update(
                self._reference(
                    client,
                    AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
                    head_document.document_id,
                ),
                _document_data(head_document.wrapper),
            )
            transaction.create(
                self._reference(
                    client,
                    AuthorityStorageKind.RECOVERY_ABANDONMENT_RESULT,
                    result_document.document_id,
                ),
                _document_data(result_document.wrapper),
            )

        await self._run_transaction(documents, write)
        return RecoveryAbandonmentFinalizeWriteResult(
            service_claim=_stored(claim_document),
            authority=root_bundle.authority,
            classification_evidence=_stored(classification_document),
            release_evidence=_stored(release_document),
            chain_head=_stored(head_document),
            result=_stored(result_document),
        )
