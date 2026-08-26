"""Explicit end-to-end lifecycle for evidence-backed service-claim release."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol, runtime_checkable

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
from controlgraph_canary.application.root_authority import (
    TrustedRootAuthority,
    inspect_root_authority_bundle,
)
from controlgraph_canary.application.service_claim_release_store import (
    ServiceClaimFenceWriteResult,
    ServiceClaimFinalizeWriteResult,
    ServiceClaimReleaseState,
    ServiceClaimReleaseStore,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.evidence import (
    EVIDENCE_CHAIN_HEAD_V1,
    EvidenceChainHeadV1,
)
from controlgraph_canary.contracts.independent_verification import (
    CompletionClassificationV1,
    CompletionKind,
    CompletionStatus,
)
from controlgraph_canary.contracts.models import (
    EPOCH_AUTHORITY_V1,
    EVIDENCE_EVENT_V1,
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    ExecutionReceipt,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.recovery_execution import (
    create_recovery_apply_receipt_locator,
    recovery_target_configuration_sha256,
)
from controlgraph_canary.contracts.root_creation import (
    RolloutRootV2,
    RolloutRootV3,
    SignedEvidenceEventV1,
)
from controlgraph_canary.contracts.service_claim_release import (
    SERVICE_CLAIM_FENCE_EVIDENCE_SUBJECT_V1,
    SERVICE_CLAIM_RELEASE_EVIDENCE_SUBJECT_V1,
    SERVICE_CLAIM_RELEASE_IDENTITY_V1,
    SERVICE_CLAIM_RELEASE_PROGRESS_V1,
    SERVICE_CLAIM_RELEASE_RESULT_V1,
    SERVICE_CLAIM_TERMINAL_EVIDENCE_SUBJECT_V1,
    STRANDED_STABLE_CLAIM_EVIDENCE_SUBJECT_V1,
    ServiceClaimClassificationAttestationV1,
    ServiceClaimClassificationRequestV1,
    ServiceClaimFenceEvidenceSubjectV1,
    ServiceClaimReleaseCommandV1,
    ServiceClaimReleaseEvidenceSubjectV1,
    ServiceClaimReleaseFailureCode,
    ServiceClaimReleaseFenceCommitV1,
    ServiceClaimReleaseFinalizeCommitV1,
    ServiceClaimReleaseIdentityKind,
    ServiceClaimReleaseIdentityV1,
    ServiceClaimReleaseInvocationV1,
    ServiceClaimReleaseProgressV1,
    ServiceClaimReleaseResultV1,
    ServiceClaimTerminalEvidenceSubjectV1,
    StrandedStableClaimEvidenceSubjectV1,
    StrandedStableClaimReleaseCommandV1,
    service_claim_classification_request_sha256,
    service_claim_release_evidence_id,
    service_claim_release_request_sha256,
)
from controlgraph_canary.contracts.storage import (
    SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
    SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
    ServiceClaimRecord,
    ServiceClaimStatus,
    ServiceClaimTargetClassification,
    ServiceClaimTargetClassificationProof,
    ServiceClaimTerminalRootProof,
    ServiceClaimTerminalRootState,
    execution_receipt_logical_id,
)

MAX_SERVICE_CLAIM_RELEASE_ATTEMPTS: Final = 4


class ServiceClaimReleaseError(PermissionError):
    """A payload-free release denial."""

    def __init__(self, code: ServiceClaimReleaseFailureCode) -> None:
        if type(code) is not ServiceClaimReleaseFailureCode:
            raise TypeError("an exact service-claim release failure code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class ServiceClaimReleaseEvidenceClient(Protocol):
    """Purpose-separated signed-evidence boundary."""

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1: ...

    async def verify(self, signed: SignedEvidenceEventV1) -> None: ...


@runtime_checkable
class ServiceClaimReleaseClassificationClient(Protocol):
    """Authenticated fixed verifier classification boundary."""

    async def classify(
        self,
        request: ServiceClaimClassificationRequestV1,
    ) -> ServiceClaimClassificationAttestationV1: ...


@runtime_checkable
class ServiceClaimCompletionWorkflow(Protocol):
    """Shared terminal classifier required by production release composition."""

    @property
    def target(self) -> TargetBinding: ...

    async def classify_completion(
        self,
        *,
        root: RolloutRootV2 | RolloutRootV3,
        service_claim: ServiceClaimRecord,
        receipt: ExecutionReceipt,
    ) -> CompletionClassificationV1: ...


class ServiceClaimReleaser:
    """Fence, classify, and release only one explicit authenticated request."""

    def __init__(
        self,
        *,
        store: ServiceClaimReleaseStore,
        evidence_client: ServiceClaimReleaseEvidenceClient,
        classification_client: ServiceClaimReleaseClassificationClient,
        operator_policy: RouteAuthenticationPolicy,
        completion_workflow: ServiceClaimCompletionWorkflow | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(store, ServiceClaimReleaseStore)
            or not isinstance(evidence_client, ServiceClaimReleaseEvidenceClient)
            or not isinstance(
                classification_client,
                ServiceClaimReleaseClassificationClient,
            )
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.project_id != store.target.project_id
            or (
                completion_workflow is not None
                and (
                    not isinstance(
                        completion_workflow,
                        ServiceClaimCompletionWorkflow,
                    )
                    or completion_workflow.target != store.target
                )
            )
            or (clock is not None and not callable(clock))
        ):
            raise TypeError("service-claim release configuration is invalid")
        self._store = store
        self._evidence_client = evidence_client
        self._classification_client = classification_client
        self._completion_workflow = completion_workflow
        self._operator_policy = operator_policy
        self._clock = clock or _system_utc_second
        self._lock = asyncio.Lock()

    @property
    def target(self) -> TargetBinding:
        """Return the single configured service target."""

        return self._store.target

    @property
    def evidence_key_version(self) -> str | None:
        """Return the coordinator-verified evidence key when exposed by the client."""

        value = getattr(self._evidence_client, "evidence_key_version", None)
        return value if type(value) is str else None

    async def release(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> ServiceClaimReleaseResultV1:
        """Serialize the low-volume explicit release path within one coordinator."""

        async with self._lock:
            return await self._release_locked(invocation, principal=principal)

    async def _release_locked(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> ServiceClaimReleaseResultV1:
        if type(invocation) is not ServiceClaimReleaseInvocationV1:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.COMMAND_DENIED
            )
        started_at = self._timestamp()
        if not self._operator_is_exact(invocation, principal, started_at):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.CALLER_DENIED
            )
        request_sha256 = service_claim_release_request_sha256(invocation)

        for _ in range(MAX_SERVICE_CLAIM_RELEASE_ATTEMPTS):
            state = await self._read_state(invocation)
            existing = await self._exact_result(state, request_sha256)
            if existing is not None:
                return existing
            progress = await self._exact_progress(state, request_sha256)
            denial = self._state_denial(state, request_sha256, progress)
            if denial is not None:
                raise ServiceClaimReleaseError(denial)
            if progress is None:
                fence_commit = await self._build_fence_commit(
                    state,
                    request_sha256=request_sha256,
                    fenced_at=started_at,
                )
                try:
                    fence_written = await self._store.commit_service_claim_fence(
                        state,
                        fence_commit,
                    )
                except asyncio.CancelledError:
                    raise
                except AuthorityStoreConflict:
                    continue
                except AuthorityStoreOutcomeUnknown:
                    resolved = await self._read_state(invocation)
                    if await self._exact_progress(resolved, request_sha256) is None:
                        raise ServiceClaimReleaseError(
                            ServiceClaimReleaseFailureCode.OUTCOME_UNKNOWN
                        ) from None
                    continue
                except (AuthorityStoreCorruptRecord, TypeError, ValueError):
                    raise ServiceClaimReleaseError(
                        ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
                    ) from None
                except AuthorityStoreUnavailable:
                    raise ServiceClaimReleaseError(
                        ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
                    ) from None
                except Exception:
                    raise ServiceClaimReleaseError(
                        ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
                    ) from None
                self._validate_fence_write(fence_written, state, fence_commit)
                continue

            finalize_commit = await self._build_finalize_commit(
                state,
                progress,
                request_sha256=request_sha256,
            )
            try:
                finalize_written = await self._store.commit_service_claim_release(
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
                raise ServiceClaimReleaseError(
                    ServiceClaimReleaseFailureCode.OUTCOME_UNKNOWN
                ) from None
            except (AuthorityStoreCorruptRecord, TypeError, ValueError):
                raise ServiceClaimReleaseError(
                    ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
                ) from None
            except AuthorityStoreUnavailable:
                raise ServiceClaimReleaseError(
                    ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
                ) from None
            except Exception:
                raise ServiceClaimReleaseError(
                    ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
                ) from None
            self._validate_finalize_write(
                finalize_written,
                state,
                finalize_commit,
            )
            return finalize_written.result.value

        state = await self._read_state(invocation)
        existing = await self._exact_result(state, request_sha256)
        if existing is not None:
            return existing
        raise ServiceClaimReleaseError(
            ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
        )

    async def _read_state(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
    ) -> ServiceClaimReleaseState:
        try:
            state = await self._store.read_service_claim_release_state(invocation)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            ) from None
        except (AuthorityStoreOutcomeUnknown, AuthorityStoreUnavailable):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
            ) from None
        except Exception:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
            ) from None
        if type(state) is not ServiceClaimReleaseState or state.invocation != invocation:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        return state

    def _state_denial(
        self,
        state: ServiceClaimReleaseState,
        request_sha256: str,
        progress: ServiceClaimReleaseProgressV1 | None,
    ) -> ServiceClaimReleaseFailureCode | None:
        if state.result is not None:
            return ServiceClaimReleaseFailureCode.IDENTITY_CONFLICT
        command = state.invocation.command
        bundle = state.root_bundle
        if bundle is None:
            return ServiceClaimReleaseFailureCode.ROOT_NOT_FOUND
        trusted = inspect_root_authority_bundle(bundle, target=self._store.target)
        if trusted is None:
            return ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
        if (
            trusted.root.root_id != command.root_id
            or trusted.root.root_sha256 != command.expected_root_sha256
        ):
            return ServiceClaimReleaseFailureCode.ROOT_MISMATCH
        try:
            current_evidence_chain_head(
                bundle,
                target=self._store.target,
                stored_head=state.chain_head,
                head_evidence=state.head_evidence,
            )
        except (TypeError, ValueError):
            return ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
        if request_sha256 != service_claim_release_request_sha256(state.invocation):
            return ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
        claim = trusted.service_claim
        if type(claim) is not ServiceClaimRecord:
            return ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
        authority = trusted.authority
        if progress is None:
            if any(
                value is not None
                for value in (
                    state.request_identity,
                    state.idempotency_identity,
                    state.terminal_evidence,
                    state.fence_evidence,
                    state.classification_evidence,
                    state.release_evidence,
                )
            ):
                return ServiceClaimReleaseFailureCode.IDENTITY_CONFLICT
            if claim.status is not ServiceClaimStatus.ACTIVE:
                return ServiceClaimReleaseFailureCode.CLAIM_NOT_ACTIVE
            if authority.current_epoch != command.expected_epoch:
                return ServiceClaimReleaseFailureCode.EPOCH_MISMATCH
            if type(command) is StrandedStableClaimReleaseCommandV1:
                if type(trusted.root) is not RolloutRootV3:
                    return ServiceClaimReleaseFailureCode.ROOT_MISMATCH
                if (
                    state.root_bundle is None
                    or state.root_bundle.service_claim.revision
                    != command.expected_service_claim_revision
                    or canonical_sha256(claim)
                    != command.expected_service_claim_sha256
                ):
                    return ServiceClaimReleaseFailureCode.CLAIM_NOT_ACTIVE
            if not self._terminal_receipt_is_exact(state, trusted):
                return ServiceClaimReleaseFailureCode.TERMINAL_RECEIPT_INVALID
            return None
        if claim.status is not ServiceClaimStatus.RELEASING:
            return ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
        if authority.current_epoch != command.expected_epoch + 1:
            return ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
        return None

    async def _build_fence_commit(
        self,
        state: ServiceClaimReleaseState,
        *,
        request_sha256: str,
        fenced_at: str,
    ) -> ServiceClaimReleaseFenceCommitV1:
        trusted = self._trusted(state)
        receipt_record = state.terminal_receipt
        if receipt_record is None or not self._terminal_receipt_is_exact(state, trusted):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TERMINAL_RECEIPT_INVALID
            )
        claim = self._legacy_claim(trusted)
        authority = trusted.authority
        invocation = state.invocation
        command = invocation.command
        previous_head = current_evidence_chain_head(
            _root_bundle(state),
            target=self._store.target,
            stored_head=state.chain_head,
            head_evidence=state.head_evidence,
        )
        if fenced_at < previous_head.updated_at or receipt_record.value.updated_at > fenced_at:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        if type(command) is StrandedStableClaimReleaseCommandV1:
            terminal_state = ServiceClaimTerminalRootState.STRANDED_STABLE
            target_configuration_sha256 = claim.stable_target_configuration_sha256
        else:
            terminal_state, _, target_configuration_sha256 = _terminal_mapping(
                receipt_record.value,
                claim,
            )
        terminal_evidence_id = service_claim_release_evidence_id(
            request_sha256,
            "terminal",
        )
        if type(command) is StrandedStableClaimReleaseCommandV1:
            terminal_subject: (
                ServiceClaimTerminalEvidenceSubjectV1
                | StrandedStableClaimEvidenceSubjectV1
            ) = StrandedStableClaimEvidenceSubjectV1(
                schema_version=STRANDED_STABLE_CLAIM_EVIDENCE_SUBJECT_V1,
                target=self._store.target,
                root_id=trusted.root.root_id,
                root_sha256=trusted.root.root_sha256,
                state=ServiceClaimTerminalRootState.STRANDED_STABLE,
                expected_stable_target_configuration_sha256=(
                    target_configuration_sha256
                ),
                expected_service_claim_sha256=(
                    command.expected_service_claim_sha256
                ),
                expected_service_claim_revision=(
                    command.expected_service_claim_revision
                ),
                verified_apply_receipt=command.verified_apply_receipt,
                reason=command.reason,
                confirmation=command.confirmation,
                classification_pending=True,
                evidence_id=terminal_evidence_id,
                confirmed_by="controlgraph.coordinator/v1",
                confirmed_at=fenced_at,
            )
            terminal_kind = EvidenceKind.OUTCOME_AMBIGUOUS
            terminal_event_target_configuration_sha256 = None
        else:
            terminal_subject = ServiceClaimTerminalEvidenceSubjectV1(
                schema_version=SERVICE_CLAIM_TERMINAL_EVIDENCE_SUBJECT_V1,
                target=self._store.target,
                root_id=trusted.root.root_id,
                root_sha256=trusted.root.root_sha256,
                state=terminal_state,
                target_configuration_sha256=target_configuration_sha256,
                receipt_id=receipt_record.value.receipt_id,
                receipt_sha256=canonical_sha256(receipt_record.value),
                receipt_revision=receipt_record.revision,
                receipt_epoch=receipt_record.value.epoch,
                receipt_action=receipt_record.value.action,
                receipt_outcome=ReceiptOutcome.VERIFIED,
                evidence_id=terminal_evidence_id,
                confirmed_by="controlgraph.coordinator/v1",
                confirmed_at=fenced_at,
            )
            terminal_kind = EvidenceKind.TARGET_VERIFIED
            terminal_event_target_configuration_sha256 = (
                target_configuration_sha256
            )
        terminal_event = EvidenceEvent(
            schema_version=EVIDENCE_EVENT_V1,
            evidence_id=terminal_evidence_id,
            sequence=previous_head.sequence + 1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            epoch=receipt_record.value.epoch,
            kind=terminal_kind,
            actor="controlgraph.coordinator/v1",
            request_id=command.request_id,
            receipt_id=receipt_record.value.receipt_id,
            occurred_at=fenced_at,
            subject_sha256=canonical_sha256(terminal_subject),
            previous_event_sha256=previous_head.evidence_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=terminal_event_target_configuration_sha256,
        )
        terminal_evidence = await self._sign(terminal_event, trusted)
        terminal_evidence_sha256 = canonical_sha256(terminal_evidence)
        terminal_proof = ServiceClaimTerminalRootProof(
            schema_version=SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
            target=self._store.target,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            state=terminal_state,
            target_configuration_sha256=target_configuration_sha256,
            evidence_id=terminal_evidence_id,
            evidence_sha256=terminal_evidence_sha256,
            confirmed_by="controlgraph.coordinator/v1",
            confirmed_at=fenced_at,
        )
        fence_evidence_id = service_claim_release_evidence_id(request_sha256, "fence")
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
        replacement_claim = ServiceClaimRecord.model_validate(
            {
                **claim.model_dump(mode="python"),
                "status": ServiceClaimStatus.RELEASING,
                "release_fence_epoch": replacement_authority.current_epoch,
                "release_fence_authority_revision": replacement_authority.revision,
                "release_fenced_by": invocation.operator_identity,
                "release_fence_request_id": command.request_id,
                "release_fence_evidence_id": fence_evidence_id,
                "release_fenced_at": fenced_at,
                "terminal_root_proof": terminal_proof,
            }
        )
        fence_subject = ServiceClaimFenceEvidenceSubjectV1(
            schema_version=SERVICE_CLAIM_FENCE_EVIDENCE_SUBJECT_V1,
            target=self._store.target,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            operator_identity=invocation.operator_identity,
            operator_subject=invocation.operator_subject,
            terminal_evidence_id=terminal_evidence_id,
            terminal_evidence_sha256=terminal_evidence_sha256,
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
            sequence=terminal_event.sequence + 1,
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
            previous_event_sha256=terminal_evidence_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=None,
        )
        fence_evidence = await self._sign(fence_event, trusted)
        fence_evidence_sha256 = canonical_sha256(fence_evidence)
        chain_head = _chain_head(fence_evidence, fence_evidence_sha256)
        progress = ServiceClaimReleaseProgressV1(
            schema_version=SERVICE_CLAIM_RELEASE_PROGRESS_V1,
            result_id=_result_id(request_sha256),
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            terminal_receipt_id=receipt_record.value.receipt_id,
            terminal_receipt_sha256=canonical_sha256(receipt_record.value),
            terminal_evidence_id=terminal_evidence_id,
            terminal_evidence_sha256=terminal_evidence_sha256,
            terminal_subject=terminal_subject,
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
        return ServiceClaimReleaseFenceCommitV1(
            replacement_claim=replacement_claim,
            replacement_authority=replacement_authority,
            terminal_subject=terminal_subject,
            terminal_evidence=terminal_evidence,
            fence_subject=fence_subject,
            fence_evidence=fence_evidence,
            chain_head=chain_head,
            progress=progress,
            request_identity=request_identity,
            idempotency_identity=idempotency_identity,
        )

    async def _build_finalize_commit(
        self,
        state: ServiceClaimReleaseState,
        progress: ServiceClaimReleaseProgressV1,
        *,
        request_sha256: str,
    ) -> ServiceClaimReleaseFinalizeCommitV1:
        trusted = self._trusted(state)
        claim = self._legacy_claim(trusted)
        authority = trusted.authority
        invocation = state.invocation
        command = invocation.command
        terminal = claim.terminal_root_proof
        if terminal is None:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        previous_head = current_evidence_chain_head(
            _root_bundle(state),
            target=self._store.target,
            stored_head=state.chain_head,
            head_evidence=state.head_evidence,
        )
        _, classification, target_configuration_sha256 = _terminal_mapping_from_state(
            terminal.state,
            claim,
        )
        receipt_record = state.terminal_receipt
        if (
            type(receipt_record) is not StoredRecord
            or type(receipt_record.value) is not ExecutionReceipt
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TERMINAL_RECEIPT_INVALID
            )
        completion_workflow = self._completion_workflow
        if (
            completion_workflow is not None
            and type(command) is ServiceClaimReleaseCommandV1
        ):
            try:
                completion = await completion_workflow.classify_completion(
                    root=trusted.root,
                    service_claim=claim,
                    receipt=receipt_record.value,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ServiceClaimReleaseError(
                    ServiceClaimReleaseFailureCode.CLASSIFICATION_DENIED
                ) from None
            expected_kind = {
                CapabilityAction.PROMOTE_CANDIDATE: CompletionKind.PROMOTION,
                CapabilityAction.RECOVER_STABLE: CompletionKind.RECOVERY,
            }.get(receipt_record.value.action)
            if (
                type(completion) is not CompletionClassificationV1
                or completion.status is not CompletionStatus.COMPLETE
                or completion.request.kind is not expected_kind
                or completion.request.verification.root_id != trusted.root.root_id
                or completion.request.verification.service_claim_sha256
                != canonical_sha256(claim)
            ):
                raise ServiceClaimReleaseError(
                    ServiceClaimReleaseFailureCode.CLASSIFICATION_DENIED
                )
        classification_request = ServiceClaimClassificationRequestV1(
            schema_version="controlgraph.service-claim-classification-request/v1",
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            release_request_sha256=request_sha256,
            classification_evidence_id=service_claim_release_evidence_id(
                request_sha256,
                "classification",
            ),
            previous_evidence_sequence=previous_head.sequence,
            previous_event_sha256=previous_head.evidence_sha256,
            stable_revision=claim.stable_revision,
            candidate_revision=claim.candidate_revision,
            concurrency=trusted.root.content.authority_bounds.concurrency,
            expected_classification=classification,
            expected_target_configuration_sha256=target_configuration_sha256,
            minimum_service_generation_exclusive=claim.baseline_service_generation,
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            request_id=command.request_id,
        )
        try:
            attestation = await self._classification_client.classify(
                classification_request
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.CLASSIFICATION_DENIED
            ) from None
        if (
            type(attestation) is not ServiceClaimClassificationAttestationV1
            or attestation.signing_request.result.request != classification_request
            or attestation.signing_request.result.request_sha256
            != service_claim_classification_request_sha256(classification_request)
            or attestation.signing_request.result.classified_at
            < previous_head.updated_at
            or attestation.signed_evidence.signing_key_version
            != trusted.root.content.evidence_signing_key_version
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.CLASSIFICATION_DENIED
            )
        classified = attestation.signing_request.result
        classification_subject = attestation.signing_request.subject
        classification_event = attestation.signing_request.event
        classification_evidence = attestation.signed_evidence
        classification_evidence_id = classification_event.evidence_id
        classification_evidence_sha256 = canonical_sha256(classification_evidence)
        classification_proof = ServiceClaimTargetClassificationProof(
            schema_version=SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
            target=self._store.target,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            classification=classified.classification,
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            service_generation=classified.service_generation,
            provider_etag=classified.provider_etag,
            target_configuration_sha256=classified.target_configuration_sha256,
            evidence_id=classification_evidence_id,
            evidence_sha256=classification_evidence_sha256,
            classified_by=classified.classified_by,
            classified_at=classified.classified_at,
        )
        released_at = self._timestamp()
        if released_at < classified.classified_at:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        release_evidence_id = service_claim_release_evidence_id(
            request_sha256,
            "release",
        )
        replacement_claim = ServiceClaimRecord.model_validate(
            {
                **claim.model_dump(mode="python"),
                "status": ServiceClaimStatus.RELEASED,
                "released_by": "controlgraph.coordinator/v1",
                "release_request_id": command.request_id,
                "release_evidence_id": release_evidence_id,
                "released_at": released_at,
                "target_classification_proof": classification_proof,
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
            classification_evidence_id=classification_evidence_id,
            classification_evidence_sha256=classification_evidence_sha256,
            fenced_claim_sha256=canonical_sha256(claim),
            released_claim_sha256=canonical_sha256(replacement_claim),
            fenced_authority_sha256=canonical_sha256(authority),
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            evidence_id=release_evidence_id,
            released_at=released_at,
        )
        release_event = EvidenceEvent(
            schema_version=EVIDENCE_EVENT_V1,
            evidence_id=release_evidence_id,
            sequence=classification_event.sequence + 1,
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
        result = ServiceClaimReleaseResultV1(
            schema_version=SERVICE_CLAIM_RELEASE_RESULT_V1,
            result_id=_result_id(request_sha256),
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            operator_identity=invocation.operator_identity,
            operator_subject=invocation.operator_subject,
            terminal_receipt_id=progress.terminal_receipt_id,
            terminal_receipt_sha256=progress.terminal_receipt_sha256,
            terminal_evidence_id=progress.terminal_evidence_id,
            terminal_evidence_sha256=progress.terminal_evidence_sha256,
            fence_evidence_id=progress.fence_evidence_id,
            fence_evidence_sha256=progress.fence_evidence_sha256,
            classification_evidence_id=classification_evidence_id,
            classification_evidence_sha256=classification_evidence_sha256,
            classification_subject=classification_subject,
            release_evidence_id=release_evidence_id,
            release_evidence_sha256=release_evidence_sha256,
            release_subject=release_subject,
            classification_proof=classification_proof,
            fenced_epoch=progress.fenced_epoch,
            fenced_authority_revision=progress.fenced_authority_revision,
            released_at=released_at,
        )
        return ServiceClaimReleaseFinalizeCommitV1(
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
        state: ServiceClaimReleaseState,
        request_sha256: str,
    ) -> ServiceClaimReleaseProgressV1 | None:
        stored = state.progress
        if stored is None:
            return None
        if (
            type(stored) is not StoredRecord
            or stored.revision != 0
            or type(stored.value) is not ServiceClaimReleaseProgressV1
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        progress = stored.value
        invocation = state.invocation
        command = invocation.command
        trusted = self._trusted(state)
        claim = self._legacy_claim(trusted)
        authority = trusted.authority
        terminal = _stored_evidence(
            state.terminal_evidence,
            progress.terminal_evidence_id,
            progress.terminal_evidence_sha256,
        )
        fence = _stored_evidence(
            state.fence_evidence,
            progress.fence_evidence_id,
            progress.fence_evidence_sha256,
        )
        receipt_record = state.terminal_receipt
        if (
            type(receipt_record) is not StoredRecord
            or type(receipt_record.value) is not ExecutionReceipt
            or canonical_sha256(receipt_record.value)
            != progress.terminal_receipt_sha256
            or not self._terminal_receipt_is_exact(state, trusted)
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        receipt = receipt_record.value
        fenced_claim = claim.model_copy(
            update={
                "status": ServiceClaimStatus.RELEASING,
                "released_by": None,
                "release_request_id": None,
                "release_evidence_id": None,
                "released_at": None,
                "target_classification_proof": None,
            }
        )
        if (
            claim.release_fenced_by is None
            or claim.release_fence_request_id is None
            or claim.release_fence_evidence_id is None
            or claim.release_fenced_at is None
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        fenced_authority = self._fenced_authority(progress, command, fence)
        authority_matches_fence = authority == fenced_authority
        authority_is_later = (
            claim.status is ServiceClaimStatus.RELEASED
            and authority.current_epoch > progress.fenced_epoch
            and authority.revision > progress.fenced_authority_revision
        )
        if (
            progress.request_sha256 != request_sha256
            or progress.result_id != _result_id(request_sha256)
            or progress.request_id != command.request_id
            or progress.idempotency_key != command.idempotency_key
            or progress.root_id != command.root_id
            or progress.root_sha256 != command.expected_root_sha256
            or progress.target != self._store.target
            or progress.fence_subject.operator_identity != invocation.operator_identity
            or progress.fence_subject.operator_subject != invocation.operator_subject
            or not _identities_match(state, progress)
            or claim.status not in {ServiceClaimStatus.RELEASING, ServiceClaimStatus.RELEASED}
            or claim.terminal_root_proof is None
            or claim.release_fence_epoch != progress.fenced_epoch
            or claim.release_fence_authority_revision
            != progress.fenced_authority_revision
            or claim.release_fence_request_id != command.request_id
            or claim.release_fence_evidence_id != progress.fence_evidence_id
            or claim.release_fenced_by != invocation.operator_identity
            or claim.release_fenced_at != progress.fenced_at
            or claim.terminal_root_proof.evidence_id != progress.terminal_evidence_id
            or claim.terminal_root_proof.evidence_sha256
            != progress.terminal_evidence_sha256
            or not (authority_matches_fence or authority_is_later)
            or progress.fence_subject.previous_epoch != command.expected_epoch
            or progress.fence_subject.replacement_claim_sha256
            != canonical_sha256(fenced_claim)
            or progress.fence_subject.replacement_authority_sha256
            != canonical_sha256(fenced_authority)
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        terminal_subject = progress.terminal_subject
        fence_subject = progress.fence_subject
        terminal_proof = claim.terminal_root_proof
        if type(command) is StrandedStableClaimReleaseCommandV1:
            active_claim = claim.model_copy(
                update={
                    "status": ServiceClaimStatus.ACTIVE,
                    "release_fence_epoch": None,
                    "release_fence_authority_revision": None,
                    "release_fenced_by": None,
                    "release_fence_request_id": None,
                    "release_fence_evidence_id": None,
                    "release_fenced_at": None,
                    "released_by": None,
                    "release_request_id": None,
                    "release_evidence_id": None,
                    "released_at": None,
                    "terminal_root_proof": None,
                    "target_classification_proof": None,
                }
            )
            terminal_details_are_exact = (
                type(terminal_subject) is StrandedStableClaimEvidenceSubjectV1
                and type(trusted.root) is RolloutRootV3
                and terminal_subject.state
                is ServiceClaimTerminalRootState.STRANDED_STABLE
                and terminal_subject.expected_stable_target_configuration_sha256
                == terminal_proof.target_configuration_sha256
                and terminal_subject.expected_stable_target_configuration_sha256
                == claim.stable_target_configuration_sha256
                and terminal_subject.expected_service_claim_sha256
                == command.expected_service_claim_sha256
                and terminal_subject.expected_service_claim_sha256
                == canonical_sha256(active_claim)
                and terminal_subject.expected_service_claim_revision
                == command.expected_service_claim_revision
                and state.root_bundle is not None
                and state.root_bundle.service_claim.revision
                == command.expected_service_claim_revision
                + (1 if claim.status is ServiceClaimStatus.RELEASING else 2)
                and terminal_subject.verified_apply_receipt
                == command.verified_apply_receipt
                and terminal_subject.reason == command.reason
                and terminal_subject.confirmation == command.confirmation
                and terminal_subject.classification_pending is True
                and terminal.event.kind is EvidenceKind.OUTCOME_AMBIGUOUS
                and terminal.event.target_configuration_sha256 is None
            )
        else:
            terminal_details_are_exact = (
                type(terminal_subject) is ServiceClaimTerminalEvidenceSubjectV1
                and terminal_subject.state is terminal_proof.state
                and terminal_subject.target_configuration_sha256
                == terminal_proof.target_configuration_sha256
                and terminal_subject.receipt_id == receipt.receipt_id
                and terminal_subject.receipt_sha256 == canonical_sha256(receipt)
                and terminal_subject.receipt_revision == receipt_record.revision
                and terminal_subject.receipt_epoch == receipt.epoch
                and terminal_subject.receipt_action is receipt.action
                and terminal_subject.receipt_outcome is ReceiptOutcome.VERIFIED
                and terminal.event.kind is EvidenceKind.TARGET_VERIFIED
                and terminal.event.target_configuration_sha256
                == terminal_subject.target_configuration_sha256
            )
        if (
            progress.terminal_evidence_id
            != service_claim_release_evidence_id(request_sha256, "terminal")
            or progress.fence_evidence_id
            != service_claim_release_evidence_id(request_sha256, "fence")
            or progress.terminal_receipt_id != receipt.receipt_id
            or terminal_subject.target != self._store.target
            or terminal_subject.root_id != trusted.root.root_id
            or terminal_subject.root_sha256 != trusted.root.root_sha256
            or terminal_proof.target != self._store.target
            or terminal_proof.root_id != trusted.root.root_id
            or terminal_proof.root_sha256 != trusted.root.root_sha256
            or terminal_proof.evidence_id != progress.terminal_evidence_id
            or terminal_proof.evidence_sha256 != progress.terminal_evidence_sha256
            or terminal_proof.confirmed_by != "controlgraph.coordinator/v1"
            or terminal_proof.confirmed_at != progress.fenced_at
            or not terminal_details_are_exact
            or terminal_subject.evidence_id != progress.terminal_evidence_id
            or terminal_subject.confirmed_by != "controlgraph.coordinator/v1"
            or terminal_subject.confirmed_at != progress.fenced_at
            or terminal.event.subject_sha256 != canonical_sha256(terminal_subject)
            or terminal.event.receipt_id != progress.terminal_receipt_id
            or terminal.event.evidence_id != progress.terminal_evidence_id
            or terminal.event.root_id != trusted.root.root_id
            or terminal.event.root_sha256 != trusted.root.root_sha256
            or terminal.event.target != self._store.target
            or terminal.event.epoch != receipt.epoch
            or terminal.event.actor != "controlgraph.coordinator/v1"
            or terminal.event.request_id != command.request_id
            or terminal.event.occurred_at != progress.fenced_at
            or terminal.event.previous_event_sha256 is None
            or terminal.event.reason_code is not None
            or terminal.event.provider_operation is not None
            or fence_subject.target != self._store.target
            or fence_subject.root_id != trusted.root.root_id
            or fence_subject.root_sha256 != trusted.root.root_sha256
            or fence_subject.request_sha256 != request_sha256
            or fence_subject.request_id != command.request_id
            or fence_subject.idempotency_key != command.idempotency_key
            or fence_subject.operator_identity != invocation.operator_identity
            or fence_subject.operator_subject != invocation.operator_subject
            or fence_subject.terminal_evidence_id != progress.terminal_evidence_id
            or fence_subject.terminal_evidence_sha256
            != progress.terminal_evidence_sha256
            or fence_subject.new_epoch != progress.fenced_epoch
            or fence_subject.evidence_id != progress.fence_evidence_id
            or fence_subject.fenced_at != progress.fenced_at
            or fence.event.subject_sha256 != canonical_sha256(fence_subject)
            or fence.event.kind is not EvidenceKind.EPOCH_ADVANCED
            or fence.event.evidence_id != progress.fence_evidence_id
            or fence.event.sequence != terminal.event.sequence + 1
            or fence.event.previous_event_sha256 != progress.terminal_evidence_sha256
            or fence.event.root_id != trusted.root.root_id
            or fence.event.root_sha256 != trusted.root.root_sha256
            or fence.event.target != self._store.target
            or fence.event.epoch != progress.fenced_epoch
            or fence.event.actor != invocation.operator_identity
            or fence.event.request_id != command.request_id
            or fence.event.receipt_id is not None
            or fence.event.occurred_at != progress.fenced_at
            or fence.event.reason_code is not None
            or fence.event.provider_operation is not None
            or fence.event.target_configuration_sha256 is not None
            or terminal.signing_key_version
            != trusted.root.content.evidence_signing_key_version
            or fence.signing_key_version
            != trusted.root.content.evidence_signing_key_version
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        await self._verify_stored_evidence(terminal, fence)
        if state.result is None:
            head = self._current_head(state)
            successor = self._immediate_head_successor(
                state,
                head=head,
                predecessor=fence,
                predecessor_sha256=progress.fence_evidence_sha256,
            )
            if successor is not None:
                await self._verify_stored_evidence(successor)
        return progress

    async def _exact_result(
        self,
        state: ServiceClaimReleaseState,
        request_sha256: str,
    ) -> ServiceClaimReleaseResultV1 | None:
        stored = state.result
        if stored is None:
            return None
        if (
            type(stored) is not StoredRecord
            or stored.revision != 0
            or type(stored.value) is not ServiceClaimReleaseResultV1
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        result = stored.value
        progress = await self._exact_progress(state, request_sha256)
        trusted = self._trusted(state)
        claim = self._legacy_claim(trusted)
        command = state.invocation.command
        fenced_claim = claim.model_copy(
            update={
                "status": ServiceClaimStatus.RELEASING,
                "released_by": None,
                "release_request_id": None,
                "release_evidence_id": None,
                "released_at": None,
                "target_classification_proof": None,
            }
        )
        if (
            progress is None
            or result.request_sha256 != request_sha256
            or result.result_id != _result_id(request_sha256)
            or result.request_id != command.request_id
            or result.idempotency_key != command.idempotency_key
            or result.root_id != command.root_id
            or result.root_sha256 != command.expected_root_sha256
            or result.target != self._store.target
            or result.operator_identity != state.invocation.operator_identity
            or result.operator_subject != state.invocation.operator_subject
            or result.terminal_receipt_id != progress.terminal_receipt_id
            or result.terminal_receipt_sha256 != progress.terminal_receipt_sha256
            or result.terminal_evidence_id != progress.terminal_evidence_id
            or result.terminal_evidence_sha256 != progress.terminal_evidence_sha256
            or result.fence_evidence_id != progress.fence_evidence_id
            or result.fence_evidence_sha256 != progress.fence_evidence_sha256
            or result.fenced_epoch != progress.fenced_epoch
            or result.fenced_authority_revision
            != progress.fenced_authority_revision
            or claim.status is not ServiceClaimStatus.RELEASED
            or claim.release_request_id != command.request_id
            or claim.release_evidence_id != result.release_evidence_id
            or claim.released_at != result.released_at
            or claim.target_classification_proof != result.classification_proof
            or result.release_subject.released_claim_sha256 != canonical_sha256(claim)
            or result.release_subject.fenced_authority_sha256
            != progress.fence_subject.replacement_authority_sha256
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        fence = _stored_evidence(
            state.fence_evidence,
            result.fence_evidence_id,
            result.fence_evidence_sha256,
        )
        fenced_authority = self._fenced_authority(progress, command, fence)
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
        head = self._current_head(state)
        classification_event = classification.event
        release_event = release.event
        classification_subject = result.classification_subject
        release_subject = result.release_subject
        classification_proof = result.classification_proof
        expected_reader = (
            f"controlgraph-verifier@{self._store.target.project_id}.iam.gserviceaccount.com"
        )
        if (
            classification_event.evidence_id
            != service_claim_release_evidence_id(request_sha256, "classification")
            or classification_event.subject_sha256
            != canonical_sha256(classification_subject)
            or classification_event.kind is not EvidenceKind.TARGET_VERIFIED
            or classification_event.sequence <= 0
            or classification_event.sequence >= release_event.sequence
            or classification_event.root_id != result.root_id
            or classification_event.root_sha256 != result.root_sha256
            or classification_event.target != result.target
            or classification_event.epoch != progress.fenced_epoch
            or classification_event.actor != expected_reader
            or classification_event.request_id != result.request_id
            or classification_event.receipt_id is not None
            or classification_event.occurred_at != classification_subject.classified_at
            or classification_event.occurred_at < progress.fenced_at
            or classification_event.previous_event_sha256 is None
            or classification_event.reason_code is not None
            or classification_event.provider_operation is not None
            or classification_event.target_configuration_sha256
            != classification_proof.target_configuration_sha256
            or classification_subject.target != result.target
            or classification_subject.root_id != result.root_id
            or classification_subject.root_sha256 != result.root_sha256
            or classification_subject.request_sha256 != result.request_sha256
            or classification_subject.classification is not classification_proof.classification
            or classification_subject.fenced_epoch != progress.fenced_epoch
            or classification_subject.fenced_authority_revision
            != progress.fenced_authority_revision
            or classification_subject.service_generation
            != classification_proof.service_generation
            or classification_subject.provider_etag != classification_proof.provider_etag
            or classification_subject.target_configuration_sha256
            != classification_proof.target_configuration_sha256
            or classification_subject.evidence_id != result.classification_evidence_id
            or classification_subject.classified_by != expected_reader
            or classification_subject.classified_at != classification_proof.classified_at
            or classification_proof.target != result.target
            or classification_proof.root_id != result.root_id
            or classification_proof.root_sha256 != result.root_sha256
            or classification_proof.classification
            is not classification_subject.classification
            or classification_proof.fenced_epoch != progress.fenced_epoch
            or classification_proof.fenced_authority_revision
            != progress.fenced_authority_revision
            or classification_proof.service_generation
            <= claim.baseline_service_generation
            or classification_proof.target_configuration_sha256
            != classification_subject.target_configuration_sha256
            or classification_proof.evidence_id != result.classification_evidence_id
            or classification_proof.evidence_sha256
            != result.classification_evidence_sha256
            or classification_proof.classified_by != expected_reader
            or release_event.evidence_id
            != service_claim_release_evidence_id(request_sha256, "release")
            or release_event.subject_sha256 != canonical_sha256(release_subject)
            or release_event.kind is not EvidenceKind.TARGET_VERIFIED
            or release_event.sequence != classification_event.sequence + 1
            or release_event.previous_event_sha256
            != result.classification_evidence_sha256
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
            or release_event.target_configuration_sha256
            != classification_proof.target_configuration_sha256
            or release_subject.target != result.target
            or release_subject.root_id != result.root_id
            or release_subject.root_sha256 != result.root_sha256
            or release_subject.request_sha256 != result.request_sha256
            or release_subject.request_id != result.request_id
            or release_subject.idempotency_key != result.idempotency_key
            or release_subject.operator_identity != result.operator_identity
            or release_subject.operator_subject != result.operator_subject
            or release_subject.classification_evidence_id
            != result.classification_evidence_id
            or release_subject.classification_evidence_sha256
            != result.classification_evidence_sha256
            or release_subject.fenced_claim_sha256 != canonical_sha256(fenced_claim)
            or release_subject.fenced_authority_sha256
            != canonical_sha256(fenced_authority)
            or release_subject.fenced_epoch != progress.fenced_epoch
            or release_subject.fenced_authority_revision
            != progress.fenced_authority_revision
            or release_subject.evidence_id != result.release_evidence_id
            or release_subject.released_at != result.released_at
            or classification.signing_key_version
            != trusted.root.content.evidence_signing_key_version
            or release.signing_key_version
            != trusted.root.content.evidence_signing_key_version
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        await self._verify_stored_evidence(classification, release)
        successor = self._immediate_head_successor(
            state,
            head=head,
            predecessor=release,
            predecessor_sha256=result.release_evidence_sha256,
        )
        if successor is not None:
            await self._verify_stored_evidence(successor)
        authority = trusted.authority
        if authority.current_epoch > progress.fenced_epoch and (
            successor is None
            or not self._later_authority_matches_successor(
                successor,
                authority=authority,
                progress=progress,
            )
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        return result

    def _current_head(self, state: ServiceClaimReleaseState) -> EvidenceChainHeadV1:
        try:
            return current_evidence_chain_head(
                _root_bundle(state),
                target=self._store.target,
                stored_head=state.chain_head,
                head_evidence=state.head_evidence,
            )
        except (TypeError, ValueError):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            ) from None

    @staticmethod
    def _fenced_authority(
        progress: ServiceClaimReleaseProgressV1,
        command: ServiceClaimReleaseCommandV1 | StrandedStableClaimReleaseCommandV1,
        fence: SignedEvidenceEventV1,
    ) -> EpochAuthorityRecord:
        event = fence.event
        if event.request_id is None:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
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
                request_id=event.request_id,
                evidence_id=event.evidence_id,
                changed_at=event.occurred_at,
            )
        except (TypeError, ValueError):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            ) from None

    @staticmethod
    def _immediate_head_successor(
        state: ServiceClaimReleaseState,
        *,
        head: EvidenceChainHeadV1,
        predecessor: SignedEvidenceEventV1,
        predecessor_sha256: str,
    ) -> SignedEvidenceEventV1 | None:
        predecessor_event = predecessor.event
        if head.sequence == predecessor_event.sequence:
            if (
                head.evidence_id != predecessor_event.evidence_id
                or head.evidence_sha256 != predecessor_sha256
                or head.updated_at != predecessor_event.occurred_at
            ):
                raise ServiceClaimReleaseError(
                    ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
                )
            return None
        if head.sequence != predecessor_event.sequence + 1:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        successor = _stored_evidence(
            state.head_evidence,
            head.evidence_id,
            head.evidence_sha256,
        )
        if (
            successor.event.previous_event_sha256 != predecessor_sha256
            or successor.event.occurred_at < predecessor_event.occurred_at
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        return successor

    def _later_authority_matches_successor(
        self,
        successor: SignedEvidenceEventV1,
        *,
        authority: EpochAuthorityRecord,
        progress: ServiceClaimReleaseProgressV1,
    ) -> bool:
        event = successor.event
        return (
            authority.root_id == progress.root_id
            and authority.root_sha256 == progress.root_sha256
            and authority.target == self._store.target
            and authority.current_epoch == progress.fenced_epoch + 1
            and authority.previous_epoch == progress.fenced_epoch
            and authority.revision == progress.fenced_authority_revision + 1
            and authority.cause is EpochChangeCause.OPERATOR_REVOCATION
            and authority.changed_by == event.actor
            and authority.request_id == event.request_id
            and authority.evidence_id == event.evidence_id
            and authority.changed_at == event.occurred_at
            and event.kind is EvidenceKind.EPOCH_ADVANCED
            and event.epoch == authority.current_epoch
            and event.receipt_id is None
            and event.reason_code is None
            and event.provider_operation is None
            and event.target_configuration_sha256 is None
        )

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
                raise ServiceClaimReleaseError(
                    ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
                ) from None

    def _terminal_receipt_is_exact(
        self,
        state: ServiceClaimReleaseState,
        trusted: TrustedRootAuthority,
    ) -> bool:
        stored = state.terminal_receipt
        if (
            type(stored) is not StoredRecord
            or stored.revision < 1
            or type(stored.value) is not ExecutionReceipt
        ):
            return False
        receipt = stored.value
        command = state.invocation.command
        claim = self._legacy_claim(trusted)
        if type(command) is StrandedStableClaimReleaseCommandV1:
            try:
                locator = create_recovery_apply_receipt_locator(
                    receipt,
                    storage_revision=stored.revision,
                )
                expected_poststate_sha256 = recovery_target_configuration_sha256(
                    trusted.root,
                    stable_percent=90,
                    candidate_percent=10,
                )
            except (TypeError, ValueError):
                return False
            return (
                locator == command.verified_apply_receipt
                and receipt.receipt_id
                == execution_receipt_logical_id(
                    self._store.target,
                    command.verified_apply_receipt.idempotency_key,
                )
                and receipt.target == self._store.target
                and receipt.root_id == trusted.root.root_id
                and receipt.root_sha256 == trusted.root.root_sha256
                and receipt.epoch == command.expected_epoch
                and receipt.action is CapabilityAction.APPLY_CANARY
                and receipt.plan_sha256
                == canonical_sha256(trusted.root.content.rollout_plan)
                and receipt.provider_etag
                == trusted.root.content.stable_snapshot.provider_etag
                and receipt.expected_poststate_sha256 == expected_poststate_sha256
                and receipt.outcome is ReceiptOutcome.VERIFIED
                and receipt.reason_code is None
                and receipt.provider_operation is not None
                and receipt.observed_etag is not None
                and receipt.observed_authority_epoch == command.expected_epoch
            )
        if type(command) is not ServiceClaimReleaseCommandV1:
            return False
        try:
            _terminal_mapping(receipt, claim)
        except (TypeError, ValueError):
            return False
        return (
            receipt.receipt_id
            == execution_receipt_logical_id(
                self._store.target,
                command.terminal_receipt_idempotency_key,
            )
            and receipt.idempotency_key == command.terminal_receipt_idempotency_key
            and receipt.target == self._store.target
            and receipt.root_id == trusted.root.root_id
            and receipt.root_sha256 == trusted.root.root_sha256
            and receipt.outcome is ReceiptOutcome.VERIFIED
            and receipt.reason_code is None
            and receipt.observed_etag is not None
            and receipt.epoch <= trusted.authority.current_epoch
        )

    def _trusted(self, state: ServiceClaimReleaseState) -> TrustedRootAuthority:
        trusted = inspect_root_authority_bundle(
            state.root_bundle,
            target=self._store.target,
        )
        if trusted is None:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        return trusted

    @staticmethod
    def _legacy_claim(trusted: TrustedRootAuthority) -> ServiceClaimRecord:
        claim = trusted.service_claim
        if type(claim) is not ServiceClaimRecord:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        return claim

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
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.EVIDENCE_DENIED
            ) from None
        if (
            type(signed) is not SignedEvidenceEventV1
            or signed.event != event
            or signed.signing_key_version
            != trusted.root.content.evidence_signing_key_version
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.EVIDENCE_DENIED
            )
        return signed

    def _operator_is_exact(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
        principal: AuthenticationContext | None,
        now: str,
    ) -> bool:
        if type(principal) is not AuthenticationContext:
            return False
        policy = self._operator_policy
        now_second = int(
            datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=UTC)
            .timestamp()
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
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            ) from None
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _validate_fence_write(
        written: ServiceClaimFenceWriteResult,
        state: ServiceClaimReleaseState,
        commit: ServiceClaimReleaseFenceCommitV1,
    ) -> None:
        if state.root_bundle is None or type(written) is not ServiceClaimFenceWriteResult:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        expected = (
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
            (written.terminal_evidence, commit.terminal_evidence, 0),
            (written.fence_evidence, commit.fence_evidence, 0),
            (written.chain_head, commit.chain_head, commit.chain_head.sequence),
            (written.progress, commit.progress, 0),
            (written.request_identity, commit.request_identity, 0),
            (written.idempotency_identity, commit.idempotency_identity, 0),
        )
        if any(
            type(stored) is not StoredRecord
            or stored.value != value
            or stored.revision != revision
            for stored, value, revision in expected
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )

    @staticmethod
    def _validate_finalize_write(
        written: ServiceClaimFinalizeWriteResult,
        state: ServiceClaimReleaseState,
        commit: ServiceClaimReleaseFinalizeCommitV1,
    ) -> None:
        if state.root_bundle is None or type(written) is not ServiceClaimFinalizeWriteResult:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
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
            type(stored) is not StoredRecord
            or stored.value != value
            or stored.revision != revision
            for stored, value, revision in expected
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )


def _terminal_mapping(
    receipt: ExecutionReceipt,
    claim: ServiceClaimRecord,
) -> tuple[
    ServiceClaimTerminalRootState,
    ServiceClaimTargetClassification,
    str,
]:
    if (
        type(receipt) is not ExecutionReceipt
        or type(claim) is not ServiceClaimRecord
        or receipt.outcome is not ReceiptOutcome.VERIFIED
    ):
        raise ValueError("terminal receipt is not verified")
    if receipt.action is CapabilityAction.PROMOTE_CANDIDATE:
        values = (
            ServiceClaimTerminalRootState.PROMOTED,
            ServiceClaimTargetClassification.CANDIDATE_PROMOTED,
            claim.candidate_target_configuration_sha256,
        )
    elif receipt.action is CapabilityAction.RECOVER_STABLE:
        values = (
            ServiceClaimTerminalRootState.RECOVERED,
            ServiceClaimTargetClassification.STABLE_RESTORED,
            claim.stable_target_configuration_sha256,
        )
    else:
        raise ValueError("receipt action is not terminal")
    if receipt.expected_poststate_sha256 != values[2]:
        raise ValueError("receipt poststate does not match its claimed terminal state")
    return values


def _terminal_mapping_from_state(
    state: ServiceClaimTerminalRootState,
    claim: ServiceClaimRecord,
) -> tuple[
    ServiceClaimTerminalRootState,
    ServiceClaimTargetClassification,
    str,
]:
    if state is ServiceClaimTerminalRootState.PROMOTED:
        return (
            state,
            ServiceClaimTargetClassification.CANDIDATE_PROMOTED,
            claim.candidate_target_configuration_sha256,
        )
    if state is ServiceClaimTerminalRootState.RECOVERED:
        return (
            state,
            ServiceClaimTargetClassification.STABLE_RESTORED,
            claim.stable_target_configuration_sha256,
        )
    if state is ServiceClaimTerminalRootState.STRANDED_STABLE:
        return (
            state,
            ServiceClaimTargetClassification.STABLE_RESTORED,
            claim.stable_target_configuration_sha256,
        )
    raise TypeError("an exact terminal root state is required")


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


def _identity_claims(
    invocation: ServiceClaimReleaseInvocationV1,
    *,
    request_sha256: str,
    claimed_at: str,
) -> tuple[ServiceClaimReleaseIdentityV1, ServiceClaimReleaseIdentityV1]:
    command = invocation.command

    def identity(
        kind: ServiceClaimReleaseIdentityKind,
        value: str,
    ) -> ServiceClaimReleaseIdentityV1:
        return ServiceClaimReleaseIdentityV1(
            schema_version=SERVICE_CLAIM_RELEASE_IDENTITY_V1,
            identity_kind=kind,
            identity_value=value,
            root_id=command.root_id,
            root_sha256=command.expected_root_sha256,
            request_sha256=request_sha256,
            result_id=_result_id(request_sha256),
            claimed_at=claimed_at,
        )

    return (
        identity(ServiceClaimReleaseIdentityKind.REQUEST, command.request_id),
        identity(ServiceClaimReleaseIdentityKind.IDEMPOTENCY, command.idempotency_key),
    )


def _identities_match(
    state: ServiceClaimReleaseState,
    progress: ServiceClaimReleaseProgressV1,
) -> bool:
    command = state.invocation.command
    expected = (
        (
            state.request_identity,
            ServiceClaimReleaseIdentityKind.REQUEST,
            command.request_id,
        ),
        (
            state.idempotency_identity,
            ServiceClaimReleaseIdentityKind.IDEMPOTENCY,
            command.idempotency_key,
        ),
    )
    return all(
        type(stored) is StoredRecord
        and stored.revision == 0
        and type(stored.value) is ServiceClaimReleaseIdentityV1
        and stored.value.identity_kind is kind
        and stored.value.identity_value == value
        and stored.value.root_id == progress.root_id
        and stored.value.root_sha256 == progress.root_sha256
        and stored.value.request_sha256 == progress.request_sha256
        and stored.value.result_id == progress.result_id
        and stored.value.claimed_at == progress.fenced_at
        for stored, kind, value in expected
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
        raise ServiceClaimReleaseError(
            ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
        )
    return stored.value


def _root_bundle(state: ServiceClaimReleaseState) -> RootCreationBundle:
    if type(state.root_bundle) is not RootCreationBundle:
        raise ServiceClaimReleaseError(
            ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
        )
    return state.root_bundle


def _result_id(request_sha256: str) -> str:
    return f"cgrelease:{request_sha256}"


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "MAX_SERVICE_CLAIM_RELEASE_ATTEMPTS",
    "ServiceClaimReleaseClassificationClient",
    "ServiceClaimReleaseError",
    "ServiceClaimReleaseEvidenceClient",
    "ServiceClaimReleaser",
]
