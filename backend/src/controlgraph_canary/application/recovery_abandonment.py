"""Explicit, fail-closed abandonment of one expired ambiguous recovery dispatch."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final, Literal, Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    RootCreationBundle,
    StoredRecord,
)
from controlgraph_canary.application.evidence_chain import current_evidence_chain_head
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.recovery_abandonment_store import (
    RecoveryAbandonmentFenceWriteResult,
    RecoveryAbandonmentFinalizeWriteResult,
    RecoveryAbandonmentState,
    RecoveryAbandonmentStore,
    late_fence_receipt_matches,
)
from controlgraph_canary.application.root_authority import (
    TrustedRootAuthority,
    inspect_root_authority_bundle,
)
from controlgraph_canary.application.service_claim_release import (
    ServiceClaimReleaseEvidenceClient,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.evidence import (
    EVIDENCE_CHAIN_HEAD_V1,
    EvidenceChainHeadV1,
)
from controlgraph_canary.contracts.health_storage import recovery_dispatch_record_sha256
from controlgraph_canary.contracts.models import (
    EPOCH_AUTHORITY_V1,
    EVIDENCE_EVENT_V1,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    TargetBinding,
)
from controlgraph_canary.contracts.recovery_abandonment import (
    RECOVERY_ABANDONMENT_CLASSIFICATION_REQUEST_V1,
    RECOVERY_ABANDONMENT_EVIDENCE_SUBJECT_V1,
    RECOVERY_ABANDONMENT_FENCE_SUBJECT_V1,
    RECOVERY_ABANDONMENT_IDENTITY_V1,
    RECOVERY_ABANDONMENT_PROGRESS_V1,
    RECOVERY_ABANDONMENT_RESULT_V1,
    RecoveryAbandonmentClassificationAttestationV1,
    RecoveryAbandonmentClassificationRequestV1,
    RecoveryAbandonmentCommandV1,
    RecoveryAbandonmentEvidenceSubjectV1,
    RecoveryAbandonmentFailureCode,
    RecoveryAbandonmentFenceCommitV1,
    RecoveryAbandonmentFenceSubjectV1,
    RecoveryAbandonmentFinalizeCommitV1,
    RecoveryAbandonmentIdentityKind,
    RecoveryAbandonmentIdentityV1,
    RecoveryAbandonmentInvocationV1,
    RecoveryAbandonmentPhase,
    RecoveryAbandonmentProgressV1,
    RecoveryAbandonmentResultV1,
    recovery_abandonment_classification_request_sha256,
    recovery_abandonment_evidence_id,
    recovery_abandonment_request_sha256,
)
from controlgraph_canary.contracts.recovery_execution import (
    RECOVERY_DISPATCH_RESULT_V2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchResultV2,
    RecoveryDispatchState,
    RecoveryIntentV1,
    recovery_command_sha256,
    recovery_intent_id,
)
from controlgraph_canary.contracts.root_creation import (
    RolloutRootV3,
    SignedEvidenceEventV1,
)
from controlgraph_canary.contracts.service_claim_release import (
    SERVICE_CLAIM_RELEASE_EVIDENCE_SUBJECT_V1,
    ServiceClaimReleaseEvidenceSubjectV1,
)
from controlgraph_canary.contracts.storage import (
    SERVICE_CLAIM_ABANDONMENT_PROOF_V1,
    SERVICE_CLAIM_ABANDONMENT_RELEASE_CONDITION,
    SERVICE_CLAIM_STABLE_BASELINE_PROOF_V1,
    SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION,
    SERVICE_CLAIM_V2,
    SERVICE_CLAIM_V3,
    ServiceClaimAbandonmentProofV1,
    ServiceClaimRecord,
    ServiceClaimRecordV3,
    ServiceClaimStableBaselineProofV1,
    ServiceClaimStatus,
    execution_receipt_logical_id,
)

MAX_RECOVERY_ABANDONMENT_ATTEMPTS: Final = 4


class RecoveryAbandonmentError(PermissionError):
    def __init__(self, code: RecoveryAbandonmentFailureCode) -> None:
        if type(code) is not RecoveryAbandonmentFailureCode:
            raise TypeError("an exact recovery abandonment failure code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class RecoveryAbandonmentClassificationClient(Protocol):
    async def classify(
        self,
        request: RecoveryAbandonmentClassificationRequestV1,
    ) -> RecoveryAbandonmentClassificationAttestationV1: ...


class RecoveryAbandoner:
    """Fence first; release only after independent stable-baseline verification."""

    def __init__(
        self,
        *,
        store: RecoveryAbandonmentStore,
        evidence_client: ServiceClaimReleaseEvidenceClient,
        classification_client: RecoveryAbandonmentClassificationClient,
        operator_policy: RouteAuthenticationPolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(store, RecoveryAbandonmentStore)
            or not isinstance(evidence_client, ServiceClaimReleaseEvidenceClient)
            or not isinstance(classification_client, RecoveryAbandonmentClassificationClient)
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.project_id != store.target.project_id
            or (clock is not None and not callable(clock))
        ):
            raise TypeError("recovery abandonment configuration is invalid")
        self._store = store
        self._evidence_client = evidence_client
        self._classification_client = classification_client
        self._operator_policy = operator_policy
        self._clock = clock or _system_utc_second
        self._lock = asyncio.Lock()

    @property
    def target(self) -> TargetBinding:
        return self._store.target

    async def abandon(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> RecoveryAbandonmentResultV1:
        async with self._lock:
            return await self._abandon_locked(invocation, principal=principal)

    async def _abandon_locked(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> RecoveryAbandonmentResultV1:
        if type(invocation) is not RecoveryAbandonmentInvocationV1:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.COMMAND_DENIED)
        started_at = self._timestamp()
        if not self._operator_is_exact(invocation, principal, started_at):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.CALLER_DENIED)
        request_sha256 = recovery_abandonment_request_sha256(invocation)
        for _ in range(MAX_RECOVERY_ABANDONMENT_ATTEMPTS):
            state = await self._read_state(invocation)
            existing = await self._exact_result(state, request_sha256)
            if existing is not None:
                return existing
            progress = await self._exact_progress(state, request_sha256)
            denial = self._state_denial(
                state,
                request_sha256=request_sha256,
                progress=progress,
                now=started_at,
            )
            if denial is not None:
                raise RecoveryAbandonmentError(denial)
            if progress is None:
                fence_commit = await self._build_fence_commit(
                    state,
                    request_sha256=request_sha256,
                    fenced_at=started_at,
                )
                try:
                    fence_write = await self._store.commit_recovery_abandonment_fence(
                        state,
                        fence_commit,
                    )
                except asyncio.CancelledError:
                    raise
                except AuthorityStoreConflict:
                    continue
                except AuthorityStoreOutcomeUnknown:
                    resolved = await self._read_state(invocation)
                    resolved_progress = await self._exact_progress(
                        resolved,
                        request_sha256,
                    )
                    if resolved_progress is None:
                        raise RecoveryAbandonmentError(
                            RecoveryAbandonmentFailureCode.OUTCOME_UNKNOWN
                        ) from None
                    return _partial_result(invocation, resolved_progress)
                except (AuthorityStoreCorruptRecord, TypeError, ValueError):
                    raise RecoveryAbandonmentError(
                        RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
                    ) from None
                except AuthorityStoreUnavailable:
                    raise RecoveryAbandonmentError(
                        RecoveryAbandonmentFailureCode.STORE_UNAVAILABLE
                    ) from None
                except Exception:
                    raise RecoveryAbandonmentError(
                        RecoveryAbandonmentFailureCode.STORE_UNAVAILABLE
                    ) from None
                self._validate_fence_write(fence_write, state, fence_commit)
                return _partial_result(invocation, fence_commit.progress)

            finalize_commit = await self._build_finalize_commit(
                state,
                progress,
                request_sha256=request_sha256,
            )
            try:
                finalize_write = await self._store.commit_recovery_abandonment_release(
                    state,
                    finalize_commit,
                )
            except asyncio.CancelledError:
                raise
            except AuthorityStoreConflict:
                continue
            except AuthorityStoreOutcomeUnknown:
                resolved = await self._read_state(invocation)
                existing = await self._exact_result(resolved, request_sha256)
                if existing is not None:
                    return existing
                raise RecoveryAbandonmentError(
                    RecoveryAbandonmentFailureCode.OUTCOME_UNKNOWN
                ) from None
            except (AuthorityStoreCorruptRecord, TypeError, ValueError):
                raise RecoveryAbandonmentError(
                    RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
                ) from None
            except AuthorityStoreUnavailable:
                raise RecoveryAbandonmentError(
                    RecoveryAbandonmentFailureCode.STORE_UNAVAILABLE
                ) from None
            except Exception:
                raise RecoveryAbandonmentError(
                    RecoveryAbandonmentFailureCode.STORE_UNAVAILABLE
                ) from None
            self._validate_finalize_write(finalize_write, state, finalize_commit)
            return finalize_commit.result
        raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.OUTCOME_UNKNOWN)

    async def _read_state(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
    ) -> RecoveryAbandonmentState:
        try:
            state = await self._store.read_recovery_abandonment_state(invocation)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
            ) from None
        except Exception:
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.STORE_UNAVAILABLE
            ) from None
        if type(state) is not RecoveryAbandonmentState or state.invocation != invocation:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        return state

    def _state_denial(
        self,
        state: RecoveryAbandonmentState,
        *,
        request_sha256: str,
        progress: RecoveryAbandonmentProgressV1 | None,
        now: str,
    ) -> RecoveryAbandonmentFailureCode | None:
        command = state.invocation.command
        if state.result is not None:
            return RecoveryAbandonmentFailureCode.IDENTITY_CONFLICT
        if state.root_bundle is None:
            return RecoveryAbandonmentFailureCode.ROOT_NOT_FOUND
        trusted = inspect_root_authority_bundle(
            state.root_bundle,
            target=self._store.target,
        )
        if trusted is None:
            return RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
        if type(trusted.root) is not RolloutRootV3 or (
            trusted.root.root_id != command.root_id
            or trusted.root.root_sha256 != command.expected_root_sha256
        ):
            return RecoveryAbandonmentFailureCode.ROOT_MISMATCH
        try:
            current_evidence_chain_head(
                _root_bundle(state),
                target=self._store.target,
                stored_head=state.chain_head,
                head_evidence=state.head_evidence,
            )
        except (TypeError, ValueError):
            return RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
        if request_sha256 != recovery_abandonment_request_sha256(state.invocation):
            return RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
        if progress is None:
            if any(
                value is not None
                for value in (
                    state.request_identity,
                    state.idempotency_identity,
                    state.abandonment_evidence,
                    state.fence_evidence,
                    state.classification_evidence,
                    state.release_evidence,
                )
            ):
                return RecoveryAbandonmentFailureCode.IDENTITY_CONFLICT
            if type(trusted.service_claim) is not ServiceClaimRecord or (
                trusted.service_claim.status is not ServiceClaimStatus.ACTIVE
            ):
                return RecoveryAbandonmentFailureCode.CLAIM_NOT_ACTIVE
            if trusted.service_claim.operator_owner != state.invocation.operator_identity:
                return RecoveryAbandonmentFailureCode.CALLER_DENIED
            if trusted.authority.current_epoch != command.expected_epoch:
                return RecoveryAbandonmentFailureCode.EPOCH_MISMATCH
            intent = state.recovery_intent
            dispatch = state.recovery_dispatch
            if (
                type(intent) is not StoredRecord
                or type(intent.value) is not RecoveryIntentV1
                or intent.revision != 0
                or intent.value.root_id != command.root_id
                or intent.value.root_sha256 != command.expected_root_sha256
                or recovery_command_sha256(intent.value.command) != intent.value.command_sha256
            ):
                return RecoveryAbandonmentFailureCode.INTENT_INVALID
            if (
                type(dispatch) is not StoredRecord
                or type(dispatch.value) is not RecoveryDispatchRecordV2
                or not _dispatch_state_is_abandonable(dispatch)
                or dispatch.value.dispatch_id != command.recovery_dispatch_id
                or recovery_dispatch_record_sha256(dispatch.value)
                != command.expected_dispatch_sha256
                or dispatch.value.command_sha256 != intent.value.command_sha256
                or dispatch.value.root_id != command.root_id
                or dispatch.value.root_sha256 != command.expected_root_sha256
                or intent.value.epoch != dispatch.value.epoch
                or not _dispatch_epoch_is_abandonable(
                    trusted.authority,
                    command_epoch=command.expected_epoch,
                    dispatch_epoch=dispatch.value.epoch,
                )
                or dispatch.value.target != self._store.target
            ):
                return RecoveryAbandonmentFailureCode.DISPATCH_INVALID
            if dispatch.value.task.expires_at > now:
                return RecoveryAbandonmentFailureCode.DISPATCH_NOT_EXPIRED
            if state.recovery_receipt is not None:
                return RecoveryAbandonmentFailureCode.RECEIPT_EXISTS
            return None
        if not _identities_match(state, progress):
            return RecoveryAbandonmentFailureCode.IDENTITY_CONFLICT
        if (
            type(trusted.service_claim) is not ServiceClaimRecordV3
            or trusted.service_claim.status is not ServiceClaimStatus.RELEASING
            or trusted.authority.current_epoch != command.expected_epoch + 1
            or trusted.service_claim.release_fence_epoch != trusted.authority.current_epoch
            or type(state.recovery_dispatch) is not StoredRecord
            or state.recovery_dispatch.revision
            != progress.abandonment_subject.ambiguous_dispatch_revision
            or state.recovery_dispatch.value.state is not RecoveryDispatchState.AMBIGUOUS
            or recovery_dispatch_record_sha256(state.recovery_dispatch.value)
            != progress.ambiguous_dispatch_sha256
        ):
            return RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
        if state.recovery_receipt is not None and not late_fence_receipt_matches(
            state.recovery_receipt,
            state.recovery_dispatch.value,
            fenced_epoch=progress.fenced_epoch,
            fenced_at=progress.fenced_at,
        ):
            return RecoveryAbandonmentFailureCode.RECEIPT_EXISTS
        return None

    async def _build_fence_commit(
        self,
        state: RecoveryAbandonmentState,
        *,
        request_sha256: str,
        fenced_at: str,
    ) -> RecoveryAbandonmentFenceCommitV1:
        trusted = self._trusted(state)
        intent_record = state.recovery_intent
        dispatch_record = state.recovery_dispatch
        if (
            type(intent_record) is not StoredRecord
            or type(dispatch_record) is not StoredRecord
            or type(dispatch_record.value) is not RecoveryDispatchRecordV2
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.DISPATCH_INVALID)
        command = state.invocation.command
        invocation = state.invocation
        claim = trusted.service_claim
        authority = trusted.authority
        if type(claim) is not ServiceClaimRecord:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.CLAIM_NOT_ACTIVE)
        previous_head = self._current_head(state)
        if (
            fenced_at < previous_head.updated_at
            or dispatch_record.value.task.expires_at > fenced_at
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.DISPATCH_NOT_EXPIRED)
        previous_dispatch_revision = dispatch_record.revision
        ambiguous_dispatch_revision = previous_dispatch_revision + 1
        ambiguous_result = _ambiguous_dispatch_result(dispatch_record.value)
        ambiguous_dispatch = RecoveryDispatchRecordV2.model_validate(
            {
                **dispatch_record.value.model_dump(mode="python"),
                "state": RecoveryDispatchState.AMBIGUOUS,
                "terminal_at": dispatch_record.value.terminal_at or fenced_at,
                "result": ambiguous_result,
            }
        )
        previous_dispatch_sha256 = recovery_dispatch_record_sha256(dispatch_record.value)
        ambiguous_dispatch_sha256 = recovery_dispatch_record_sha256(ambiguous_dispatch)
        receipt_id = execution_receipt_logical_id(
            self._store.target,
            ambiguous_dispatch.idempotency_key,
        )
        abandonment_evidence_id = recovery_abandonment_evidence_id(
            request_sha256,
            "ambiguity",
        )
        abandonment_subject = RecoveryAbandonmentEvidenceSubjectV1(
            schema_version=RECOVERY_ABANDONMENT_EVIDENCE_SUBJECT_V1,
            target=self._store.target,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            request_sha256=request_sha256,
            recovery_dispatch_id=ambiguous_dispatch.dispatch_id,
            previous_dispatch_sha256=previous_dispatch_sha256,
            ambiguous_dispatch_sha256=ambiguous_dispatch_sha256,
            previous_dispatch_revision=previous_dispatch_revision,
            ambiguous_dispatch_revision=ambiguous_dispatch_revision,
            task_id=ambiguous_dispatch.task.task_id,
            task_name=ambiguous_dispatch.task_name,
            task_sha256=ambiguous_dispatch.task_sha256,
            capability_id=ambiguous_dispatch.capability_id,
            capability_sha256=canonical_sha256(ambiguous_dispatch.task.capability),
            task_expires_at=ambiguous_dispatch.task.expires_at,
            recovery_receipt_id=receipt_id,
            receipt_absent_at_fence=True,
            reason=command.reason,
            operator_identity=invocation.operator_identity,
            operator_subject=invocation.operator_subject,
            evidence_id=abandonment_evidence_id,
            abandoned_at=fenced_at,
        )
        abandonment_event = EvidenceEvent(
            schema_version=EVIDENCE_EVENT_V1,
            evidence_id=abandonment_evidence_id,
            sequence=previous_head.sequence + 1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            epoch=authority.current_epoch,
            kind=EvidenceKind.OUTCOME_AMBIGUOUS,
            actor=invocation.operator_identity,
            request_id=command.request_id,
            receipt_id=None,
            occurred_at=fenced_at,
            subject_sha256=canonical_sha256(abandonment_subject),
            previous_event_sha256=previous_head.evidence_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=None,
        )
        abandonment_evidence = await self._sign(abandonment_event, trusted)
        abandonment_evidence_sha256 = canonical_sha256(abandonment_evidence)
        abandonment_proof = ServiceClaimAbandonmentProofV1(
            schema_version=SERVICE_CLAIM_ABANDONMENT_PROOF_V1,
            target=self._store.target,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            state="ABANDONED",
            required_stable_baseline_configuration_sha256=(
                claim.stable_target_configuration_sha256
            ),
            recovery_dispatch_id=ambiguous_dispatch.dispatch_id,
            recovery_dispatch_sha256=ambiguous_dispatch_sha256,
            recovery_dispatch_revision=ambiguous_dispatch_revision,
            recovery_receipt_id=receipt_id,
            receipt_absent_at_fence=True,
            evidence_id=abandonment_evidence_id,
            evidence_sha256=abandonment_evidence_sha256,
            confirmed_by="controlgraph.coordinator/v1",
            confirmed_at=fenced_at,
        )
        fence_evidence_id = recovery_abandonment_evidence_id(request_sha256, "fence")
        replacement_authority = EpochAuthorityRecord(
            schema_version=EPOCH_AUTHORITY_V1,
            root_id=authority.root_id,
            root_sha256=authority.root_sha256,
            target=self._store.target,
            current_epoch=authority.current_epoch + 1,
            previous_epoch=authority.current_epoch,
            revision=authority.revision + 1,
            cause=EpochChangeCause.OPERATOR_REVOCATION,
            changed_by=invocation.operator_identity,
            request_id=command.request_id,
            evidence_id=fence_evidence_id,
            changed_at=fenced_at,
        )
        replacement_claim = ServiceClaimRecordV3.model_validate(
            {
                **claim.model_dump(mode="python"),
                "schema_version": SERVICE_CLAIM_V3,
                "terminal_release_condition": (SERVICE_CLAIM_ABANDONMENT_RELEASE_CONDITION),
                "status": ServiceClaimStatus.RELEASING,
                "release_fence_epoch": replacement_authority.current_epoch,
                "release_fence_authority_revision": replacement_authority.revision,
                "release_fenced_by": invocation.operator_identity,
                "release_fence_request_id": command.request_id,
                "release_fence_evidence_id": fence_evidence_id,
                "release_fenced_at": fenced_at,
                "terminal_root_proof": abandonment_proof,
            }
        )
        fence_subject = RecoveryAbandonmentFenceSubjectV1(
            schema_version=RECOVERY_ABANDONMENT_FENCE_SUBJECT_V1,
            target=self._store.target,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            operator_identity=invocation.operator_identity,
            operator_subject=invocation.operator_subject,
            abandonment_evidence_id=abandonment_evidence_id,
            abandonment_evidence_sha256=abandonment_evidence_sha256,
            previous_claim_sha256=canonical_sha256(claim),
            replacement_claim_sha256=canonical_sha256(replacement_claim),
            previous_authority_sha256=canonical_sha256(authority),
            replacement_authority_sha256=canonical_sha256(replacement_authority),
            previous_epoch=authority.current_epoch,
            new_epoch=replacement_authority.current_epoch,
            evidence_id=fence_evidence_id,
            fenced_at=fenced_at,
        )
        fence_event = EvidenceEvent(
            schema_version=EVIDENCE_EVENT_V1,
            evidence_id=fence_evidence_id,
            sequence=abandonment_event.sequence + 1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            epoch=replacement_authority.current_epoch,
            kind=EvidenceKind.EPOCH_ADVANCED,
            actor=invocation.operator_identity,
            request_id=command.request_id,
            receipt_id=None,
            occurred_at=fenced_at,
            subject_sha256=canonical_sha256(fence_subject),
            previous_event_sha256=abandonment_evidence_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=None,
        )
        fence_evidence = await self._sign(fence_event, trusted)
        fence_evidence_sha256 = canonical_sha256(fence_evidence)
        progress = RecoveryAbandonmentProgressV1(
            schema_version=RECOVERY_ABANDONMENT_PROGRESS_V1,
            result_id=_result_id(request_sha256),
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            recovery_dispatch_id=ambiguous_dispatch.dispatch_id,
            previous_dispatch_sha256=previous_dispatch_sha256,
            ambiguous_dispatch_sha256=ambiguous_dispatch_sha256,
            recovery_receipt_id=receipt_id,
            abandonment_evidence_id=abandonment_evidence_id,
            abandonment_evidence_sha256=abandonment_evidence_sha256,
            abandonment_subject=abandonment_subject,
            fence_evidence_id=fence_evidence_id,
            fence_evidence_sha256=fence_evidence_sha256,
            fence_subject=fence_subject,
            fenced_epoch=replacement_authority.current_epoch,
            fenced_authority_revision=replacement_authority.revision,
            fenced_at=fenced_at,
        )
        request_identity, idempotency_identity = _identity_claims(
            invocation,
            request_sha256=request_sha256,
            claimed_at=fenced_at,
        )
        return RecoveryAbandonmentFenceCommitV1(
            replacement_dispatch=ambiguous_dispatch,
            replacement_claim=replacement_claim,
            replacement_authority=replacement_authority,
            abandonment_subject=abandonment_subject,
            abandonment_evidence=abandonment_evidence,
            fence_subject=fence_subject,
            fence_evidence=fence_evidence,
            chain_head=_chain_head(fence_evidence, fence_evidence_sha256),
            progress=progress,
            request_identity=request_identity,
            idempotency_identity=idempotency_identity,
        )

    async def _build_finalize_commit(
        self,
        state: RecoveryAbandonmentState,
        progress: RecoveryAbandonmentProgressV1,
        *,
        request_sha256: str,
    ) -> RecoveryAbandonmentFinalizeCommitV1:
        trusted = self._trusted(state)
        claim = trusted.service_claim
        if type(claim) is not ServiceClaimRecordV3:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        previous_head = self._current_head(state)
        classification_request = RecoveryAbandonmentClassificationRequestV1(
            schema_version=RECOVERY_ABANDONMENT_CLASSIFICATION_REQUEST_V1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            abandonment_request_sha256=request_sha256,
            classification_evidence_id=recovery_abandonment_evidence_id(
                request_sha256,
                "classification",
            ),
            previous_evidence_sequence=previous_head.sequence,
            previous_event_sha256=previous_head.evidence_sha256,
            stable_revision=claim.stable_revision,
            candidate_revision=claim.candidate_revision,
            concurrency=trusted.root.content.authority_bounds.concurrency,
            expected_classification="STABLE_BASELINE_CONFIRMED",
            expected_target_configuration_sha256=(claim.stable_target_configuration_sha256),
            minimum_service_generation_exclusive=claim.baseline_service_generation,
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            request_id=state.invocation.command.request_id,
        )
        try:
            attestation = await self._classification_client.classify(classification_request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.CLASSIFICATION_DENIED
            ) from None
        if (
            type(attestation) is not RecoveryAbandonmentClassificationAttestationV1
            or attestation.signing_request.result.request != classification_request
            or attestation.signing_request.result.request_sha256
            != recovery_abandonment_classification_request_sha256(classification_request)
            or attestation.signing_request.result.classified_at < previous_head.updated_at
            or attestation.signed_evidence.signing_key_version
            != trusted.root.content.evidence_signing_key_version
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.CLASSIFICATION_DENIED)
        classified = attestation.signing_request.result
        classification_subject = attestation.signing_request.subject
        classification_evidence = attestation.signed_evidence
        classification_evidence_sha256 = canonical_sha256(classification_evidence)
        proof = ServiceClaimStableBaselineProofV1(
            schema_version=SERVICE_CLAIM_STABLE_BASELINE_PROOF_V1,
            target=self._store.target,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            classification="STABLE_BASELINE_CONFIRMED",
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            service_generation=classified.service_generation,
            provider_etag=classified.provider_etag,
            target_configuration_sha256=classified.target_configuration_sha256,
            evidence_id=classification_evidence.event.evidence_id,
            evidence_sha256=classification_evidence_sha256,
            classified_by=classified.classified_by,
            classified_at=classified.classified_at,
        )
        released_at = self._timestamp()
        if released_at < classified.classified_at:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        invocation = state.invocation
        command = invocation.command
        release_evidence_id = recovery_abandonment_evidence_id(
            request_sha256,
            "release",
        )
        replacement_claim = ServiceClaimRecordV3.model_validate(
            {
                **claim.model_dump(mode="python"),
                "status": ServiceClaimStatus.RELEASED,
                "released_by": "controlgraph.coordinator/v1",
                "release_request_id": command.request_id,
                "release_evidence_id": release_evidence_id,
                "released_at": released_at,
                "target_classification_proof": proof,
            }
        )
        release_subject = ServiceClaimReleaseEvidenceSubjectV1(
            schema_version=SERVICE_CLAIM_RELEASE_EVIDENCE_SUBJECT_V1,
            target=self._store.target,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            operator_identity=invocation.operator_identity,
            operator_subject=invocation.operator_subject,
            classification_evidence_id=classification_evidence.event.evidence_id,
            classification_evidence_sha256=classification_evidence_sha256,
            fenced_claim_sha256=canonical_sha256(claim),
            released_claim_sha256=canonical_sha256(replacement_claim),
            fenced_authority_sha256=canonical_sha256(trusted.authority),
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            evidence_id=release_evidence_id,
            released_at=released_at,
        )
        release_event = EvidenceEvent(
            schema_version=EVIDENCE_EVENT_V1,
            evidence_id=release_evidence_id,
            sequence=classification_evidence.event.sequence + 1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            epoch=progress.fenced_epoch,
            kind=EvidenceKind.TARGET_VERIFIED,
            actor="controlgraph.coordinator/v1",
            request_id=command.request_id,
            receipt_id=None,
            occurred_at=released_at,
            subject_sha256=canonical_sha256(release_subject),
            previous_event_sha256=classification_evidence_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=classified.target_configuration_sha256,
        )
        release_evidence = await self._sign(release_event, trusted)
        release_evidence_sha256 = canonical_sha256(release_evidence)
        result = RecoveryAbandonmentResultV1(
            schema_version=RECOVERY_ABANDONMENT_RESULT_V1,
            result_id=progress.result_id,
            phase=RecoveryAbandonmentPhase.RELEASED,
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            operator_identity=invocation.operator_identity,
            operator_subject=invocation.operator_subject,
            recovery_dispatch_id=progress.recovery_dispatch_id,
            ambiguous_dispatch_sha256=progress.ambiguous_dispatch_sha256,
            recovery_receipt_id=progress.recovery_receipt_id,
            abandonment_evidence_id=progress.abandonment_evidence_id,
            abandonment_evidence_sha256=progress.abandonment_evidence_sha256,
            fence_evidence_id=progress.fence_evidence_id,
            fence_evidence_sha256=progress.fence_evidence_sha256,
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            fenced_at=progress.fenced_at,
            classification_evidence_id=classification_evidence.event.evidence_id,
            classification_evidence_sha256=classification_evidence_sha256,
            classification_subject=classification_subject,
            release_evidence_id=release_evidence_id,
            release_evidence_sha256=release_evidence_sha256,
            release_subject=release_subject,
            stable_baseline_proof=proof,
            released_at=released_at,
        )
        return RecoveryAbandonmentFinalizeCommitV1(
            replacement_claim=replacement_claim,
            classification_subject=classification_subject,
            classification_evidence=classification_evidence,
            release_subject=release_subject,
            release_evidence=release_evidence,
            chain_head=_chain_head(release_evidence, release_evidence_sha256),
            result=result,
        )

    async def _exact_progress(
        self,
        state: RecoveryAbandonmentState,
        request_sha256: str,
    ) -> RecoveryAbandonmentProgressV1 | None:
        stored = state.progress
        if stored is None:
            return None
        if (
            type(stored) is not StoredRecord
            or stored.revision != 0
            or type(stored.value) is not RecoveryAbandonmentProgressV1
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        progress = stored.value
        invocation = state.invocation
        command = invocation.command
        trusted = self._trusted(state)
        claim = trusted.service_claim
        authority = trusted.authority
        dispatch_record = state.recovery_dispatch
        intent_record = state.recovery_intent
        if (
            type(trusted.root) is not RolloutRootV3
            or type(claim) is not ServiceClaimRecordV3
            or claim.status not in {ServiceClaimStatus.RELEASING, ServiceClaimStatus.RELEASED}
            or type(dispatch_record) is not StoredRecord
            or type(dispatch_record.value) is not RecoveryDispatchRecordV2
            or type(intent_record) is not StoredRecord
            or intent_record.revision != 0
            or type(intent_record.value) is not RecoveryIntentV1
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        dispatch = dispatch_record.value
        intent = intent_record.value
        abandonment_subject = progress.abandonment_subject
        if (
            dispatch.state is not RecoveryDispatchState.AMBIGUOUS
            or dispatch_record.revision
            != abandonment_subject.ambiguous_dispatch_revision
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        try:
            previous_dispatch = _previous_recovery_dispatch(
                dispatch,
                abandonment_subject,
            )
            fenced_claim = ServiceClaimRecordV3.model_validate(
                {
                    **claim.model_dump(mode="python"),
                    "status": ServiceClaimStatus.RELEASING,
                    "released_by": None,
                    "release_request_id": None,
                    "release_evidence_id": None,
                    "released_at": None,
                    "target_classification_proof": None,
                }
            )
            previous_claim = ServiceClaimRecord.model_validate(
                {
                    **fenced_claim.model_dump(mode="python"),
                    "schema_version": SERVICE_CLAIM_V2,
                    "terminal_release_condition": (SERVICE_CLAIM_TERMINAL_RELEASE_CONDITION),
                    "status": ServiceClaimStatus.ACTIVE,
                    "release_fence_epoch": None,
                    "release_fence_authority_revision": None,
                    "release_fenced_by": None,
                    "release_fence_request_id": None,
                    "release_fence_evidence_id": None,
                    "release_fenced_at": None,
                    "terminal_root_proof": None,
                }
            )
        except (TypeError, ValueError):
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
            ) from None
        abandonment = _stored_evidence(
            state.abandonment_evidence,
            progress.abandonment_evidence_id,
            progress.abandonment_evidence_sha256,
        )
        fence = _stored_evidence(
            state.fence_evidence,
            progress.fence_evidence_id,
            progress.fence_evidence_sha256,
        )
        fenced_authority = self._fenced_authority(progress, command, fence)
        proof = claim.terminal_root_proof
        fence_subject = progress.fence_subject
        abandonment_event = abandonment.event
        fence_event = fence.event
        if (
            proof is None
            or progress.request_sha256 != request_sha256
            or progress.result_id != _result_id(request_sha256)
            or progress.request_id != command.request_id
            or progress.idempotency_key != command.idempotency_key
            or progress.root_id != command.root_id
            or progress.root_sha256 != command.expected_root_sha256
            or progress.target != self._store.target
            or progress.recovery_dispatch_id != command.recovery_dispatch_id
            or progress.previous_dispatch_sha256 != command.expected_dispatch_sha256
            or progress.ambiguous_dispatch_sha256 != recovery_dispatch_record_sha256(dispatch)
            or recovery_dispatch_record_sha256(previous_dispatch)
            != progress.previous_dispatch_sha256
            or not _identities_match(state, progress)
            or intent.intent_id != recovery_intent_id(intent.root_sha256)
            or recovery_command_sha256(intent.command) != intent.command_sha256
            or intent.command_sha256 != dispatch.command_sha256
            or intent.root_id != progress.root_id
            or intent.root_sha256 != progress.root_sha256
            or intent.epoch != dispatch.epoch
            or dispatch.dispatch_id != progress.recovery_dispatch_id
            or dispatch.root_id != progress.root_id
            or dispatch.root_sha256 != progress.root_sha256
            or dispatch.target != progress.target
            or dispatch.epoch not in {command.expected_epoch, command.expected_epoch - 1}
            or (
                abandonment_subject.previous_dispatch_revision == 1
                and dispatch.terminal_at != progress.fenced_at
            )
            or (
                abandonment_subject.previous_dispatch_revision == 2
                and (
                    dispatch.terminal_at is None
                    or dispatch.terminal_at > progress.fenced_at
                )
            )
            or dispatch.result != _ambiguous_dispatch_result(dispatch)
            or dispatch.task.expires_at > progress.fenced_at
            or progress.recovery_receipt_id
            != execution_receipt_logical_id(
                self._store.target,
                dispatch.idempotency_key,
            )
            or claim.target != progress.target
            or claim.root_id != progress.root_id
            or claim.root_sha256 != progress.root_sha256
            or claim.release_fence_epoch != progress.fenced_epoch
            or claim.release_fence_authority_revision != progress.fenced_authority_revision
            or claim.release_fenced_by != invocation.operator_identity
            or claim.release_fence_request_id != command.request_id
            or claim.release_fence_evidence_id != progress.fence_evidence_id
            or claim.release_fenced_at != progress.fenced_at
            or proof.target != progress.target
            or proof.root_id != progress.root_id
            or proof.root_sha256 != progress.root_sha256
            or proof.state != "ABANDONED"
            or proof.required_stable_baseline_configuration_sha256
            != claim.stable_target_configuration_sha256
            or proof.recovery_dispatch_id != progress.recovery_dispatch_id
            or proof.recovery_dispatch_sha256 != progress.ambiguous_dispatch_sha256
            or proof.recovery_dispatch_revision != dispatch_record.revision
            or proof.recovery_receipt_id != progress.recovery_receipt_id
            or not proof.receipt_absent_at_fence
            or proof.evidence_id != progress.abandonment_evidence_id
            or proof.evidence_sha256 != progress.abandonment_evidence_sha256
            or proof.confirmed_by != "controlgraph.coordinator/v1"
            or proof.confirmed_at != progress.fenced_at
            or authority != fenced_authority
            or progress.fenced_epoch != command.expected_epoch + 1
            or progress.fenced_authority_revision != progress.fenced_epoch - 1
            or fence_subject.previous_claim_sha256 != canonical_sha256(previous_claim)
            or fence_subject.replacement_claim_sha256 != canonical_sha256(fenced_claim)
            or fence_subject.replacement_authority_sha256 != canonical_sha256(fenced_authority)
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        if state.recovery_receipt is not None and not late_fence_receipt_matches(
            state.recovery_receipt,
            dispatch,
            fenced_epoch=progress.fenced_epoch,
            fenced_at=progress.fenced_at,
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        if (
            progress.abandonment_evidence_id
            != recovery_abandonment_evidence_id(request_sha256, "ambiguity")
            or progress.fence_evidence_id
            != recovery_abandonment_evidence_id(request_sha256, "fence")
            or abandonment_subject.target != progress.target
            or abandonment_subject.root_id != progress.root_id
            or abandonment_subject.root_sha256 != progress.root_sha256
            or abandonment_subject.request_sha256 != request_sha256
            or abandonment_subject.recovery_dispatch_id != dispatch.dispatch_id
            or abandonment_subject.previous_dispatch_sha256 != progress.previous_dispatch_sha256
            or abandonment_subject.ambiguous_dispatch_sha256 != progress.ambiguous_dispatch_sha256
            or abandonment_subject.previous_dispatch_revision
            != dispatch_record.revision - 1
            or abandonment_subject.ambiguous_dispatch_revision
            != dispatch_record.revision
            or abandonment_subject.task_id != dispatch.task.task_id
            or abandonment_subject.task_name != dispatch.task_name
            or abandonment_subject.task_sha256 != dispatch.task_sha256
            or abandonment_subject.capability_id != dispatch.capability_id
            or abandonment_subject.capability_sha256 != canonical_sha256(dispatch.task.capability)
            or abandonment_subject.task_expires_at != dispatch.task.expires_at
            or abandonment_subject.recovery_receipt_id != progress.recovery_receipt_id
            or not abandonment_subject.receipt_absent_at_fence
            or abandonment_subject.reason != command.reason
            or abandonment_subject.operator_identity != invocation.operator_identity
            or abandonment_subject.operator_subject != invocation.operator_subject
            or abandonment_subject.evidence_id != progress.abandonment_evidence_id
            or abandonment_subject.abandoned_at != progress.fenced_at
            or abandonment_event.subject_sha256 != canonical_sha256(abandonment_subject)
            or abandonment_event.evidence_id != progress.abandonment_evidence_id
            or abandonment_event.kind is not EvidenceKind.OUTCOME_AMBIGUOUS
            or abandonment_event.sequence <= 0
            or abandonment_event.root_id != progress.root_id
            or abandonment_event.root_sha256 != progress.root_sha256
            or abandonment_event.target != progress.target
            or abandonment_event.epoch != command.expected_epoch
            or abandonment_event.actor != invocation.operator_identity
            or abandonment_event.request_id != command.request_id
            or abandonment_event.receipt_id is not None
            or abandonment_event.occurred_at != progress.fenced_at
            or abandonment_event.previous_event_sha256 is None
            or abandonment_event.reason_code is not None
            or abandonment_event.provider_operation is not None
            or abandonment_event.target_configuration_sha256 is not None
            or fence_subject.target != progress.target
            or fence_subject.root_id != progress.root_id
            or fence_subject.root_sha256 != progress.root_sha256
            or fence_subject.request_sha256 != request_sha256
            or fence_subject.request_id != command.request_id
            or fence_subject.idempotency_key != command.idempotency_key
            or fence_subject.operator_identity != invocation.operator_identity
            or fence_subject.operator_subject != invocation.operator_subject
            or fence_subject.abandonment_evidence_id != progress.abandonment_evidence_id
            or fence_subject.abandonment_evidence_sha256 != progress.abandonment_evidence_sha256
            or fence_subject.previous_epoch != command.expected_epoch
            or fence_subject.new_epoch != progress.fenced_epoch
            or fence_subject.evidence_id != progress.fence_evidence_id
            or fence_subject.fenced_at != progress.fenced_at
            or fence_event.subject_sha256 != canonical_sha256(fence_subject)
            or fence_event.evidence_id != progress.fence_evidence_id
            or fence_event.kind is not EvidenceKind.EPOCH_ADVANCED
            or fence_event.sequence != abandonment_event.sequence + 1
            or fence_event.previous_event_sha256 != progress.abandonment_evidence_sha256
            or fence_event.root_id != progress.root_id
            or fence_event.root_sha256 != progress.root_sha256
            or fence_event.target != progress.target
            or fence_event.epoch != progress.fenced_epoch
            or fence_event.actor != invocation.operator_identity
            or fence_event.request_id != command.request_id
            or fence_event.receipt_id is not None
            or fence_event.occurred_at != progress.fenced_at
            or fence_event.reason_code is not None
            or fence_event.provider_operation is not None
            or fence_event.target_configuration_sha256 is not None
            or abandonment.signing_key_version != trusted.root.content.evidence_signing_key_version
            or fence.signing_key_version != trusted.root.content.evidence_signing_key_version
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        await self._verify_stored_evidence(abandonment, fence)
        if state.result is None:
            head = self._current_head(state)
            if head != _chain_head(fence, progress.fence_evidence_sha256):
                raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        return progress

    async def _exact_result(
        self,
        state: RecoveryAbandonmentState,
        request_sha256: str,
    ) -> RecoveryAbandonmentResultV1 | None:
        stored = state.result
        if stored is None:
            return None
        if (
            type(stored) is not StoredRecord
            or stored.revision != 0
            or type(stored.value) is not RecoveryAbandonmentResultV1
            or stored.value.phase is not RecoveryAbandonmentPhase.RELEASED
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        result = stored.value
        progress = await self._exact_progress(state, request_sha256)
        trusted = self._trusted(state)
        claim = trusted.service_claim
        command = state.invocation.command
        if (
            progress is None
            or type(claim) is not ServiceClaimRecordV3
            or claim.status is not ServiceClaimStatus.RELEASED
            or claim.terminal_root_proof is None
            or claim.target_classification_proof is None
            or result.classification_evidence_id is None
            or result.classification_evidence_sha256 is None
            or result.classification_subject is None
            or result.release_evidence_id is None
            or result.release_evidence_sha256 is None
            or result.release_subject is None
            or result.stable_baseline_proof is None
            or result.released_at is None
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        try:
            fenced_claim = ServiceClaimRecordV3.model_validate(
                {
                    **claim.model_dump(mode="python"),
                    "status": ServiceClaimStatus.RELEASING,
                    "released_by": None,
                    "release_request_id": None,
                    "release_evidence_id": None,
                    "released_at": None,
                    "target_classification_proof": None,
                }
            )
        except (TypeError, ValueError):
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
            ) from None
        abandonment = _stored_evidence(
            state.abandonment_evidence,
            result.abandonment_evidence_id,
            result.abandonment_evidence_sha256,
        )
        fence = _stored_evidence(
            state.fence_evidence,
            result.fence_evidence_id,
            result.fence_evidence_sha256,
        )
        classification = _stored_evidence(
            state.classification_evidence,
            result.classification_evidence_id,
            result.classification_evidence_sha256,
        )
        release = _stored_evidence(
            state.release_evidence,
            result.release_evidence_id,
            result.release_evidence_sha256,
        )
        fenced_authority = self._fenced_authority(progress, command, fence)
        classification_event = classification.event
        release_event = release.event
        classification_subject = result.classification_subject
        release_subject = result.release_subject
        proof = result.stable_baseline_proof
        expected_reader = (
            f"controlgraph-verifier@{self._store.target.project_id}.iam.gserviceaccount.com"
        )
        classification_request = RecoveryAbandonmentClassificationRequestV1(
            schema_version=RECOVERY_ABANDONMENT_CLASSIFICATION_REQUEST_V1,
            root_id=result.root_id,
            root_sha256=result.root_sha256,
            target=result.target,
            abandonment_request_sha256=request_sha256,
            classification_evidence_id=result.classification_evidence_id,
            previous_evidence_sequence=fence.event.sequence,
            previous_event_sha256=result.fence_evidence_sha256,
            stable_revision=claim.stable_revision,
            candidate_revision=claim.candidate_revision,
            concurrency=trusted.root.content.authority_bounds.concurrency,
            expected_classification="STABLE_BASELINE_CONFIRMED",
            expected_target_configuration_sha256=(claim.stable_target_configuration_sha256),
            minimum_service_generation_exclusive=claim.baseline_service_generation,
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            request_id=command.request_id,
        )
        if (
            result.request_sha256 != request_sha256
            or result.result_id != _result_id(request_sha256)
            or result.request_id != command.request_id
            or result.idempotency_key != command.idempotency_key
            or result.root_id != command.root_id
            or result.root_sha256 != command.expected_root_sha256
            or result.target != self._store.target
            or result.operator_identity != state.invocation.operator_identity
            or result.operator_subject != state.invocation.operator_subject
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
            or claim.release_request_id != command.request_id
            or claim.release_evidence_id != result.release_evidence_id
            or claim.released_at != result.released_at
            or claim.target_classification_proof != proof
            or claim.terminal_root_proof.evidence_id != result.abandonment_evidence_id
            or trusted.authority != fenced_authority
            or classification_subject.classification_request_sha256
            != recovery_abandonment_classification_request_sha256(classification_request)
            or classification_event.evidence_id
            != recovery_abandonment_evidence_id(request_sha256, "classification")
            or classification_event.subject_sha256 != canonical_sha256(classification_subject)
            or classification_event.kind is not EvidenceKind.TARGET_VERIFIED
            or classification_event.sequence != fence.event.sequence + 1
            or classification_event.previous_event_sha256 != progress.fence_evidence_sha256
            or classification_event.root_id != result.root_id
            or classification_event.root_sha256 != result.root_sha256
            or classification_event.target != result.target
            or classification_event.epoch != progress.fenced_epoch
            or classification_event.actor != expected_reader
            or classification_event.request_id != result.request_id
            or classification_event.receipt_id is not None
            or classification_event.occurred_at != classification_subject.classified_at
            or classification_event.occurred_at < progress.fenced_at
            or classification_event.reason_code is not None
            or classification_event.provider_operation is not None
            or classification_event.target_configuration_sha256
            != claim.stable_target_configuration_sha256
            or classification_subject.target != result.target
            or classification_subject.root_id != result.root_id
            or classification_subject.root_sha256 != result.root_sha256
            or classification_subject.request_sha256 != request_sha256
            or classification_subject.classification != "STABLE_BASELINE_CONFIRMED"
            or classification_subject.fenced_epoch != progress.fenced_epoch
            or classification_subject.fenced_authority_revision
            != progress.fenced_authority_revision
            or classification_subject.service_generation <= claim.baseline_service_generation
            or classification_subject.provider_etag != proof.provider_etag
            or classification_subject.target_configuration_sha256
            != claim.stable_target_configuration_sha256
            or classification_subject.evidence_id != result.classification_evidence_id
            or classification_subject.classified_by != expected_reader
            or classification_subject.classified_at != proof.classified_at
            or proof.target != result.target
            or proof.root_id != result.root_id
            or proof.root_sha256 != result.root_sha256
            or proof.classification != "STABLE_BASELINE_CONFIRMED"
            or proof.fenced_epoch != progress.fenced_epoch
            or proof.fenced_authority_revision != progress.fenced_authority_revision
            or proof.service_generation != classification_subject.service_generation
            or proof.target_configuration_sha256 != claim.stable_target_configuration_sha256
            or proof.evidence_id != result.classification_evidence_id
            or proof.evidence_sha256 != result.classification_evidence_sha256
            or proof.classified_by != expected_reader
            or release_event.evidence_id
            != recovery_abandonment_evidence_id(request_sha256, "release")
            or release_event.subject_sha256 != canonical_sha256(release_subject)
            or release_event.kind is not EvidenceKind.TARGET_VERIFIED
            or release_event.sequence != classification_event.sequence + 1
            or release_event.previous_event_sha256 != result.classification_evidence_sha256
            or release_event.root_id != result.root_id
            or release_event.root_sha256 != result.root_sha256
            or release_event.target != result.target
            or release_event.epoch != progress.fenced_epoch
            or release_event.actor != "controlgraph.coordinator/v1"
            or release_event.request_id != result.request_id
            or release_event.receipt_id is not None
            or release_event.occurred_at != result.released_at
            or release_event.occurred_at < classification_event.occurred_at
            or release_event.reason_code is not None
            or release_event.provider_operation is not None
            or release_event.target_configuration_sha256 != claim.stable_target_configuration_sha256
            or release_subject.target != result.target
            or release_subject.root_id != result.root_id
            or release_subject.root_sha256 != result.root_sha256
            or release_subject.request_sha256 != request_sha256
            or release_subject.request_id != result.request_id
            or release_subject.idempotency_key != result.idempotency_key
            or release_subject.operator_identity != result.operator_identity
            or release_subject.operator_subject != result.operator_subject
            or release_subject.classification_evidence_id != result.classification_evidence_id
            or release_subject.classification_evidence_sha256
            != result.classification_evidence_sha256
            or release_subject.fenced_claim_sha256 != canonical_sha256(fenced_claim)
            or release_subject.released_claim_sha256 != canonical_sha256(claim)
            or release_subject.fenced_authority_sha256 != canonical_sha256(fenced_authority)
            or release_subject.fenced_epoch != progress.fenced_epoch
            or release_subject.fenced_authority_revision != progress.fenced_authority_revision
            or release_subject.evidence_id != result.release_evidence_id
            or release_subject.released_at != result.released_at
            or classification.signing_key_version
            != trusted.root.content.evidence_signing_key_version
            or release.signing_key_version != trusted.root.content.evidence_signing_key_version
            or self._current_head(state) != _chain_head(release, result.release_evidence_sha256)
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        await self._verify_stored_evidence(
            abandonment,
            fence,
            classification,
            release,
        )
        return result

    @staticmethod
    def _fenced_authority(
        progress: RecoveryAbandonmentProgressV1,
        command: RecoveryAbandonmentCommandV1,
        fence: SignedEvidenceEventV1,
    ) -> EpochAuthorityRecord:
        if type(command) is not RecoveryAbandonmentCommandV1:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        event = fence.event
        try:
            return EpochAuthorityRecord(
                schema_version=EPOCH_AUTHORITY_V1,
                root_id=progress.root_id,
                root_sha256=progress.root_sha256,
                target=progress.target,
                current_epoch=progress.fenced_epoch,
                previous_epoch=command.expected_epoch,
                revision=progress.fenced_authority_revision,
                cause=EpochChangeCause.OPERATOR_REVOCATION,
                changed_by=event.actor,
                request_id=command.request_id,
                evidence_id=event.evidence_id,
                changed_at=event.occurred_at,
            )
        except (TypeError, ValueError):
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
            ) from None

    def _current_head(self, state: RecoveryAbandonmentState) -> EvidenceChainHeadV1:
        try:
            return current_evidence_chain_head(
                _root_bundle(state),
                target=self._store.target,
                stored_head=state.chain_head,
                head_evidence=state.head_evidence,
            )
        except (TypeError, ValueError):
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
            ) from None

    def _trusted(self, state: RecoveryAbandonmentState) -> TrustedRootAuthority:
        trusted = inspect_root_authority_bundle(
            state.root_bundle,
            target=self._store.target,
        )
        if trusted is None:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        return trusted

    async def _sign(
        self,
        event: EvidenceEvent,
        trusted: TrustedRootAuthority,
    ) -> SignedEvidenceEventV1:
        try:
            signed = await self._evidence_client.sign(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.EVIDENCE_DENIED) from None
        if (
            type(signed) is not SignedEvidenceEventV1
            or signed.event != event
            or signed.signing_key_version != trusted.root.content.evidence_signing_key_version
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.EVIDENCE_DENIED)
        return signed

    async def _verify_stored_evidence(
        self,
        *signed_evidence: SignedEvidenceEventV1,
    ) -> None:
        for signed in signed_evidence:
            try:
                await self._evidence_client.verify(signed)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise RecoveryAbandonmentError(
                    RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
                ) from None

    def _operator_is_exact(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
        principal: AuthenticationContext | None,
        now: str,
    ) -> bool:
        if type(principal) is not AuthenticationContext:
            return False
        policy = self._operator_policy
        now_second = int(
            datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
        )
        return (
            principal.role is CallerRole.OPERATOR
            and principal.role is policy.caller.role
            and principal.email == invocation.operator_identity == policy.caller.email
            and principal.subject == invocation.operator_subject == policy.caller.subject
            and principal.issuer == invocation.operator_issuer
            and principal.issuer in {"accounts.google.com", "https://accounts.google.com"}
            and principal.audience == invocation.operator_audience == policy.audience
            and principal.issued_at == invocation.operator_issued_at
            and principal.expires_at == invocation.operator_expires_at
            and principal.issued_at <= now_second < principal.expires_at
        )

    def _timestamp(self) -> str:
        try:
            value = self._clock()
        except Exception:
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
            ) from None
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _validate_fence_write(
        written: RecoveryAbandonmentFenceWriteResult,
        state: RecoveryAbandonmentState,
        commit: RecoveryAbandonmentFenceCommitV1,
    ) -> None:
        if state.root_bundle is None or type(written) is not RecoveryAbandonmentFenceWriteResult:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        dispatch = state.recovery_dispatch
        if type(dispatch) is not StoredRecord:
            raise RecoveryAbandonmentError(
                RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
            )
        expected = (
            (
                written.recovery_dispatch,
                commit.replacement_dispatch,
                dispatch.revision + 1,
            ),
            (
                written.service_claim,
                commit.replacement_claim,
                state.root_bundle.service_claim.revision + 1,
            ),
            (
                written.authority,
                commit.replacement_authority,
                state.root_bundle.authority.revision + 1,
            ),
            (written.abandonment_evidence, commit.abandonment_evidence, 0),
            (written.fence_evidence, commit.fence_evidence, 0),
            (written.chain_head, commit.chain_head, commit.chain_head.sequence),
            (written.progress, commit.progress, 0),
            (written.request_identity, commit.request_identity, 0),
            (written.idempotency_identity, commit.idempotency_identity, 0),
        )
        if any(
            type(stored) is not StoredRecord or stored.value != value or stored.revision != revision
            for stored, value, revision in expected
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)

    @staticmethod
    def _validate_finalize_write(
        written: RecoveryAbandonmentFinalizeWriteResult,
        state: RecoveryAbandonmentState,
        commit: RecoveryAbandonmentFinalizeCommitV1,
    ) -> None:
        if state.root_bundle is None or type(written) is not RecoveryAbandonmentFinalizeWriteResult:
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
        expected = (
            (
                written.service_claim,
                commit.replacement_claim,
                state.root_bundle.service_claim.revision + 1,
            ),
            (
                written.authority,
                state.root_bundle.authority.value,
                state.root_bundle.authority.revision,
            ),
            (written.classification_evidence, commit.classification_evidence, 0),
            (written.release_evidence, commit.release_evidence, 0),
            (written.chain_head, commit.chain_head, commit.chain_head.sequence),
            (written.result, commit.result, 0),
        )
        if any(
            type(stored) is not StoredRecord or stored.value != value or stored.revision != revision
            for stored, value, revision in expected
        ):
            raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)


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


def _previous_recovery_dispatch(
    ambiguous: RecoveryDispatchRecordV2,
    subject: RecoveryAbandonmentEvidenceSubjectV1,
) -> RecoveryDispatchRecordV2:
    if subject.previous_dispatch_revision == 1:
        candidate = RecoveryDispatchRecordV2.model_validate(
            {
                **ambiguous.model_dump(mode="python"),
                "state": RecoveryDispatchState.ENQUEUE_STARTED,
                "terminal_at": None,
                "result": None,
            }
        )
        if recovery_dispatch_record_sha256(candidate) == subject.previous_dispatch_sha256:
            return candidate
        raise ValueError("previous recovery dispatch does not match abandonment evidence")

    for state in (RecoveryDispatchState.CREATED, RecoveryDispatchState.DUPLICATE):
        disposition: Literal["CREATED", "DUPLICATE", "AMBIGUOUS"] = (
            "CREATED" if state is RecoveryDispatchState.CREATED else "DUPLICATE"
        )
        candidate = RecoveryDispatchRecordV2.model_validate(
            {
                **ambiguous.model_dump(mode="python"),
                "state": state,
                "result": _recovery_dispatch_result(ambiguous, disposition),
            }
        )
        if recovery_dispatch_record_sha256(candidate) == subject.previous_dispatch_sha256:
            return candidate
    raise ValueError("previous recovery dispatch does not match abandonment evidence")


def _recovery_dispatch_result(
    record: RecoveryDispatchRecordV2,
    disposition: Literal["CREATED", "DUPLICATE", "AMBIGUOUS"],
) -> RecoveryDispatchResultV2:
    task = record.task
    authorization = task.intent.authorization
    return RecoveryDispatchResultV2(
        schema_version=RECOVERY_DISPATCH_RESULT_V2,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_schema_version=authorization.root_schema_version,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        stable_revision=authorization.stable_revision,
        stable_revision_configuration_sha256=(authorization.stable_revision_configuration_sha256),
        candidate_revision=authorization.candidate_revision,
        candidate_revision_configuration_sha256=(
            authorization.candidate_revision_configuration_sha256
        ),
        stable_percent=100,
        candidate_percent=0,
        concurrency=authorization.concurrency,
        provider_etag=authorization.current_provider_etag,
        verified_apply_receipt=authorization.verified_apply_receipt,
        source_receipt_sha256=authorization.source_receipt_sha256,
        trigger_basis=authorization.source.basis,
        trigger_proof_sha256=authorization.trigger_proof_sha256,
        prestate_attestation_sha256=authorization.prestate_attestation_sha256,
        expected_prestate_sha256=authorization.expected_prestate_sha256,
        desired_poststate_sha256=authorization.desired_poststate_sha256,
        proof_valid_until=authorization.proof_valid_until,
        recovery_authorization_sha256=canonical_sha256(authorization),
        capability_id=authorization.capability_id,
        capability_sha256=canonical_sha256(task.capability),
        task_id=task.task_id,
        task_name=record.task_name,
        enqueue_disposition=disposition,
        scheduled_at=task.scheduled_at,
        expires_at=task.expires_at,
    )


def _ambiguous_dispatch_result(record: RecoveryDispatchRecordV2) -> RecoveryDispatchResultV2:
    return _recovery_dispatch_result(record, "AMBIGUOUS")


def _identity_claims(
    invocation: RecoveryAbandonmentInvocationV1,
    *,
    request_sha256: str,
    claimed_at: str,
) -> tuple[RecoveryAbandonmentIdentityV1, RecoveryAbandonmentIdentityV1]:
    command = invocation.command

    def identity(
        kind: RecoveryAbandonmentIdentityKind,
        value: str,
    ) -> RecoveryAbandonmentIdentityV1:
        return RecoveryAbandonmentIdentityV1(
            schema_version=RECOVERY_ABANDONMENT_IDENTITY_V1,
            identity_kind=kind,
            identity_value=value,
            root_id=command.root_id,
            root_sha256=command.expected_root_sha256,
            request_sha256=request_sha256,
            result_id=_result_id(request_sha256),
            claimed_at=claimed_at,
        )

    return (
        identity(RecoveryAbandonmentIdentityKind.REQUEST, command.request_id),
        identity(
            RecoveryAbandonmentIdentityKind.IDEMPOTENCY,
            command.idempotency_key,
        ),
    )


def _identities_match(
    state: RecoveryAbandonmentState,
    progress: RecoveryAbandonmentProgressV1,
) -> bool:
    command = state.invocation.command
    expected = (
        (
            state.request_identity,
            RecoveryAbandonmentIdentityKind.REQUEST,
            command.request_id,
        ),
        (
            state.idempotency_identity,
            RecoveryAbandonmentIdentityKind.IDEMPOTENCY,
            command.idempotency_key,
        ),
    )
    return all(
        type(stored) is StoredRecord
        and stored.revision == 0
        and type(stored.value) is RecoveryAbandonmentIdentityV1
        and stored.value.identity_kind is kind
        and stored.value.identity_value == value
        and stored.value.root_id == progress.root_id
        and stored.value.root_sha256 == progress.root_sha256
        and stored.value.request_sha256 == progress.request_sha256
        and stored.value.result_id == progress.result_id
        and stored.value.claimed_at == progress.fenced_at
        for stored, kind, value in expected
    )


def _partial_result(
    invocation: RecoveryAbandonmentInvocationV1,
    progress: RecoveryAbandonmentProgressV1,
) -> RecoveryAbandonmentResultV1:
    return RecoveryAbandonmentResultV1(
        schema_version=RECOVERY_ABANDONMENT_RESULT_V1,
        result_id=progress.result_id,
        phase=RecoveryAbandonmentPhase.FENCED_RESET_REQUIRED,
        request_sha256=progress.request_sha256,
        request_id=progress.request_id,
        idempotency_key=progress.idempotency_key,
        root_id=progress.root_id,
        root_sha256=progress.root_sha256,
        target=progress.target,
        operator_identity=invocation.operator_identity,
        operator_subject=invocation.operator_subject,
        recovery_dispatch_id=progress.recovery_dispatch_id,
        ambiguous_dispatch_sha256=progress.ambiguous_dispatch_sha256,
        recovery_receipt_id=progress.recovery_receipt_id,
        abandonment_evidence_id=progress.abandonment_evidence_id,
        abandonment_evidence_sha256=progress.abandonment_evidence_sha256,
        fence_evidence_id=progress.fence_evidence_id,
        fence_evidence_sha256=progress.fence_evidence_sha256,
        fenced_epoch=progress.fenced_epoch,
        fenced_authority_revision=progress.fenced_authority_revision,
        fenced_at=progress.fenced_at,
        classification_evidence_id=None,
        classification_evidence_sha256=None,
        classification_subject=None,
        release_evidence_id=None,
        release_evidence_sha256=None,
        release_subject=None,
        stable_baseline_proof=None,
        released_at=None,
    )


def _chain_head(
    signed: SignedEvidenceEventV1,
    evidence_sha256: str,
) -> EvidenceChainHeadV1:
    event = signed.event
    return EvidenceChainHeadV1(
        schema_version=EVIDENCE_CHAIN_HEAD_V1,
        root_id=event.root_id,
        root_sha256=event.root_sha256,
        target=event.target,
        sequence=event.sequence,
        evidence_id=event.evidence_id,
        evidence_sha256=evidence_sha256,
        kind=event.kind,
        epoch=event.epoch,
        updated_at=event.occurred_at,
    )


def _stored_evidence(
    stored: StoredRecord[SignedEvidenceEventV1] | None,
    evidence_id: str,
    evidence_sha256: str,
) -> SignedEvidenceEventV1:
    if (
        type(stored) is not StoredRecord
        or stored.revision != 0
        or type(stored.value) is not SignedEvidenceEventV1
        or stored.value.event.evidence_id != evidence_id
        or canonical_sha256(stored.value) != evidence_sha256
    ):
        raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
    return stored.value


def _root_bundle(state: RecoveryAbandonmentState) -> RootCreationBundle:
    if type(state.root_bundle) is not RootCreationBundle:
        raise RecoveryAbandonmentError(RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID)
    return state.root_bundle


def _result_id(request_sha256: str) -> str:
    return f"cgabandon:{request_sha256}"


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "MAX_RECOVERY_ABANDONMENT_ATTEMPTS",
    "RecoveryAbandoner",
    "RecoveryAbandonmentClassificationClient",
    "RecoveryAbandonmentError",
]
