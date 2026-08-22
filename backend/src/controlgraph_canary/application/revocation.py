"""Authenticated coordinator orchestration for manual epoch revocation."""

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
    StoredRecord,
)
from controlgraph_canary.application.evidence_chain import current_evidence_chain_head
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.revocation_store import (
    EpochRevocationState,
    EpochRevocationStore,
    EpochRevocationWriteResult,
)
from controlgraph_canary.application.root_authority import inspect_root_authority_bundle
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
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    TargetBinding,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_AUDIT_V1,
    EPOCH_REVOCATION_CALL_OUTCOME_V1,
    EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1,
    EPOCH_REVOCATION_IDENTITY_V1,
    EPOCH_REVOCATION_RESULT_V1,
    EpochRevocationAuditOutcome,
    EpochRevocationAuditV1,
    EpochRevocationCallOutcomeV1,
    EpochRevocationCommitV1,
    EpochRevocationEvidenceSubjectV1,
    EpochRevocationFailureCode,
    EpochRevocationIdentityKind,
    EpochRevocationIdentityV1,
    EpochRevocationInvocationV1,
    EpochRevocationResultV1,
    epoch_revocation_evidence_id,
    epoch_revocation_request_sha256,
)
from controlgraph_canary.contracts.root_creation import (
    RolloutRootV2,
    RolloutRootV3,
    SignedEvidenceEventV1,
)
from controlgraph_canary.contracts.storage import ServiceClaimRecord, ServiceClaimStatus

MAX_REVOCATION_COMMIT_ATTEMPTS: Final = 4


class EpochRevocationError(PermissionError):
    """A payload-free revocation denial."""

    def __init__(self, code: EpochRevocationFailureCode) -> None:
        if type(code) is not EpochRevocationFailureCode:
            raise TypeError("an exact revocation failure code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class EpochRevocationEvidenceClient(Protocol):
    """Purpose-separated evidence signer used only through its narrow facade."""

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1: ...


@runtime_checkable
class RevocationCompletionWorkflow(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def classify_revocation(
        self,
        *,
        root: RolloutRootV2 | RolloutRootV3,
        service_claim: ServiceClaimRecord,
        result: EpochRevocationResultV1,
        signed_evidence: SignedEvidenceEventV1,
    ) -> CompletionClassificationV1: ...


@runtime_checkable
class RevocationTimelineRecorder(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def record_epoch_revocation_completion(
        self,
        result: EpochRevocationCallOutcomeV1,
        signed_evidence: SignedEvidenceEventV1,
        classification: CompletionClassificationV1,
    ) -> None: ...


class EpochRevoker:
    """Advance authority through signed evidence and one atomic Firestore bundle."""

    def __init__(
        self,
        *,
        store: EpochRevocationStore,
        evidence_client: EpochRevocationEvidenceClient,
        operator_policy: RouteAuthenticationPolicy,
        completion_workflow: RevocationCompletionWorkflow | None = None,
        timeline_recorder: RevocationTimelineRecorder | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(store, EpochRevocationStore)
            or not isinstance(evidence_client, EpochRevocationEvidenceClient)
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.project_id != store.target.project_id
            or (completion_workflow is None) != (timeline_recorder is None)
            or (
                completion_workflow is not None
                and (
                    not isinstance(completion_workflow, RevocationCompletionWorkflow)
                    or completion_workflow.target != store.target
                    or not callable(getattr(evidence_client, "verify", None))
                )
            )
            or (
                timeline_recorder is not None
                and (
                    not isinstance(timeline_recorder, RevocationTimelineRecorder)
                    or timeline_recorder.target != store.target
                )
            )
            or (clock is not None and not callable(clock))
        ):
            raise TypeError("revocation coordinator configuration is invalid")
        self._store = store
        self._evidence_client = evidence_client
        self._operator_policy = operator_policy
        self._completion_workflow = completion_workflow
        self._timeline_recorder = timeline_recorder
        self._clock = clock or _system_utc_second
        self._lock = asyncio.Lock()

    async def revoke(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> EpochRevocationResultV1:
        """Serialize the low-volume manual mutation path within one coordinator."""

        async with self._lock:
            result = await self._revoke_locked(invocation, principal=principal)
            await self._classify_committed(invocation, result)
            return result

    async def _classify_committed(
        self,
        invocation: EpochRevocationInvocationV1,
        result: EpochRevocationResultV1,
    ) -> None:
        workflow = self._completion_workflow
        recorder = self._timeline_recorder
        if workflow is None or recorder is None:
            return
        try:
            state = await self._read_state(invocation)
            trusted = inspect_root_authority_bundle(
                state.root_bundle,
                target=self._store.target,
            )
            stored = state.result_evidence
            if (
                trusted is None
                or type(trusted.service_claim) is not ServiceClaimRecord
                or type(stored) is not StoredRecord
                or type(stored.value) is not SignedEvidenceEventV1
                or stored.value.event.evidence_id != result.evidence_id
                or canonical_sha256(stored.value) != result.evidence_sha256
            ):
                raise ValueError("committed revocation evidence is unavailable")
            verify = getattr(self._evidence_client, "verify", None)
            if not callable(verify):
                raise ValueError("revocation evidence verifier is unavailable")
            await verify(stored.value)
            classification = await workflow.classify_revocation(
                root=trusted.root,
                service_claim=trusted.service_claim,
                result=result,
                signed_evidence=stored.value,
            )
            if (
                type(classification) is not CompletionClassificationV1
                or classification.status is not CompletionStatus.COMPLETE
                or classification.request.kind is not CompletionKind.REVOCATION
                or classification.request.verification.root_id != result.root_id
                or classification.request.verification.epoch != result.new_epoch
            ):
                raise ValueError("committed revocation was not classified complete")
            await recorder.record_epoch_revocation_completion(
                EpochRevocationCallOutcomeV1(
                    schema_version=EPOCH_REVOCATION_CALL_OUTCOME_V1,
                    attempt_id=invocation.attempt_id,
                    audit_id=invocation.attempt_id,
                    result=result,
                ),
                stored.value,
                classification,
            )
        except asyncio.CancelledError:
            raise
        except EpochRevocationError:
            raise
        except Exception:
            raise EpochRevocationError(EpochRevocationFailureCode.OUTCOME_UNKNOWN) from None

    async def record_authenticated_denial(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        code: EpochRevocationFailureCode,
    ) -> None:
        """Durably record a canonical denial detected at the coordinator relay."""

        if (
            type(invocation) is not EpochRevocationInvocationV1
            or type(code) is not EpochRevocationFailureCode
            or code
            not in {
                EpochRevocationFailureCode.CALLER_DENIED,
                EpochRevocationFailureCode.COMMAND_DENIED,
            }
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED)
        async with self._lock:
            await self._record_denial(
                invocation,
                request_sha256=epoch_revocation_request_sha256(invocation),
                code=code,
                recorded_at=self._timestamp(),
            )

    async def _revoke_locked(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> EpochRevocationResultV1:
        """Return one committed result or a durable, payload-free denial."""

        if type(invocation) is not EpochRevocationInvocationV1:
            raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED)
        recorded_at = self._timestamp()
        request_sha256 = epoch_revocation_request_sha256(invocation)
        if not self._operator_is_exact(invocation, principal, recorded_at):
            await self._record_denial(
                invocation,
                request_sha256=request_sha256,
                code=EpochRevocationFailureCode.CALLER_DENIED,
                recorded_at=recorded_at,
            )
            raise EpochRevocationError(EpochRevocationFailureCode.CALLER_DENIED)

        for _ in range(MAX_REVOCATION_COMMIT_ATTEMPTS):
            state = await self._read_state(invocation)
            existing = self._exact_result(state, request_sha256)
            attempt_audit = self._validated_attempt_audit(state, request_sha256)
            if attempt_audit is not None:
                if attempt_audit.outcome is EpochRevocationAuditOutcome.DENIED:
                    if attempt_audit.failure_code is None:
                        raise EpochRevocationError(
                            EpochRevocationFailureCode.TRUSTED_STATE_INVALID
                        )
                    raise EpochRevocationError(attempt_audit.failure_code)
                if existing is None or not self._successful_audit_matches(
                    attempt_audit,
                    invocation,
                    existing,
                    request_sha256=request_sha256,
                ):
                    raise EpochRevocationError(
                        EpochRevocationFailureCode.TRUSTED_STATE_INVALID
                    )
                return existing
            if existing is not None:
                await self._record_success_audit(
                    invocation,
                    existing,
                    request_sha256=request_sha256,
                    outcome=EpochRevocationAuditOutcome.ADOPTED,
                    recorded_at=recorded_at,
                )
                return existing
            denial = self._state_denial(state, request_sha256)
            if denial is not None:
                await self._record_denial(
                    invocation,
                    request_sha256=request_sha256,
                    code=denial,
                    recorded_at=recorded_at,
                )
                raise EpochRevocationError(denial)
            try:
                commit = await self._build_commit(
                    state,
                    request_sha256=request_sha256,
                    committed_at=recorded_at,
                )
            except asyncio.CancelledError:
                raise
            except EpochRevocationError as error:
                await self._record_denial(
                    invocation,
                    request_sha256=request_sha256,
                    code=error.code,
                    recorded_at=recorded_at,
                )
                raise
            try:
                written = await self._store.commit_epoch_revocation(state, commit)
            except asyncio.CancelledError:
                raise
            except AuthorityStoreConflict:
                continue
            except AuthorityStoreOutcomeUnknown:
                resolved = await self._resolve_ambiguous(invocation, request_sha256)
                if resolved is not None:
                    return resolved
                raise EpochRevocationError(EpochRevocationFailureCode.OUTCOME_UNKNOWN) from None
            except (AuthorityStoreCorruptRecord, TypeError, ValueError):
                raise EpochRevocationError(
                    EpochRevocationFailureCode.TRUSTED_STATE_INVALID
                ) from None
            except AuthorityStoreUnavailable:
                raise EpochRevocationError(
                    EpochRevocationFailureCode.STORE_UNAVAILABLE
                ) from None
            except Exception:
                raise EpochRevocationError(
                    EpochRevocationFailureCode.STORE_UNAVAILABLE
                ) from None
            self._validate_write_result(written, commit)
            return written.result.value
        state = await self._read_state(invocation)
        existing = self._exact_result(state, request_sha256)
        attempt_audit = self._validated_attempt_audit(state, request_sha256)
        if attempt_audit is not None:
            if attempt_audit.outcome is EpochRevocationAuditOutcome.DENIED:
                if attempt_audit.failure_code is None:
                    raise EpochRevocationError(
                        EpochRevocationFailureCode.TRUSTED_STATE_INVALID
                    )
                raise EpochRevocationError(attempt_audit.failure_code)
            if existing is None or not self._successful_audit_matches(
                attempt_audit,
                invocation,
                existing,
                request_sha256=request_sha256,
            ):
                raise EpochRevocationError(
                    EpochRevocationFailureCode.TRUSTED_STATE_INVALID
                )
            return existing
        if existing is not None:
            await self._record_success_audit(
                invocation,
                existing,
                request_sha256=request_sha256,
                outcome=EpochRevocationAuditOutcome.ADOPTED,
                recorded_at=recorded_at,
            )
            return existing
        raise EpochRevocationError(EpochRevocationFailureCode.STORE_UNAVAILABLE)

    async def _read_state(
        self,
        invocation: EpochRevocationInvocationV1,
    ) -> EpochRevocationState:
        try:
            state = await self._store.read_epoch_revocation_state(invocation)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise EpochRevocationError(
                EpochRevocationFailureCode.TRUSTED_STATE_INVALID
            ) from None
        except (AuthorityStoreOutcomeUnknown, AuthorityStoreUnavailable):
            raise EpochRevocationError(EpochRevocationFailureCode.STORE_UNAVAILABLE) from None
        except Exception:
            raise EpochRevocationError(EpochRevocationFailureCode.STORE_UNAVAILABLE) from None
        if type(state) is not EpochRevocationState or state.invocation != invocation:
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        return state

    def _exact_result(
        self,
        state: EpochRevocationState,
        request_sha256: str,
    ) -> EpochRevocationResultV1 | None:
        stored = state.result
        if stored is None:
            return None
        if (
            type(stored) is not StoredRecord
            or stored.revision != 0
            or type(stored.value) is not EpochRevocationResultV1
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        result = stored.value
        invocation = state.invocation
        command = invocation.command
        bundle = state.root_bundle
        trusted = (
            None
            if bundle is None
            else inspect_root_authority_bundle(bundle, target=self._store.target)
        )
        if (
            trusted is None
            or result.request_sha256 != request_sha256
            or result.result_id != _result_id(request_sha256)
            or result.request_id != command.request_id
            or result.idempotency_key != command.idempotency_key
            or result.root_id != command.root_id
            or result.root_sha256 != command.expected_root_sha256
            or result.target != self._store.target
            or result.operator_identity != invocation.operator_identity
            or result.operator_subject != invocation.operator_subject
            or result.reason != command.reason
            or result.previous_epoch != command.expected_epoch
            or result.new_epoch != command.expected_epoch + 1
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        authority = trusted.authority
        if authority.current_epoch < result.new_epoch:
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        if authority.current_epoch == result.new_epoch and (
            authority.previous_epoch != result.previous_epoch
            or authority.cause is not EpochChangeCause.OPERATOR_REVOCATION
            or authority.changed_by != result.operator_identity
            or authority.request_id != result.request_id
            or authority.evidence_id != result.evidence_id
            or authority.changed_at != result.committed_at
            or canonical_sha256(authority)
            != result.evidence_subject.replacement_authority_sha256
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        if not self._identities_match_result(state, result):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        try:
            current_head = self._predecessor_head(state)
        except (TypeError, ValueError):
            raise EpochRevocationError(
                EpochRevocationFailureCode.TRUSTED_STATE_INVALID
            ) from None
        if not self._result_evidence_matches(
            state.result_evidence,
            result,
            current_head=current_head,
            signing_key_version=trusted.root.content.evidence_signing_key_version,
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        return result

    def _state_denial(
        self,
        state: EpochRevocationState,
        request_sha256: str,
    ) -> EpochRevocationFailureCode | None:
        if state.result is not None:
            return EpochRevocationFailureCode.IDENTITY_CONFLICT
        identities = (state.request_identity, state.idempotency_identity)
        if any(identity is not None for identity in identities):
            if any(
                type(identity) is not StoredRecord
                or identity.revision != 0
                or type(identity.value) is not EpochRevocationIdentityV1
                for identity in identities
                if identity is not None
            ):
                return EpochRevocationFailureCode.TRUSTED_STATE_INVALID
            return EpochRevocationFailureCode.IDENTITY_CONFLICT
        bundle = state.root_bundle
        if bundle is None:
            return EpochRevocationFailureCode.ROOT_NOT_FOUND
        trusted = inspect_root_authority_bundle(bundle, target=self._store.target)
        if trusted is None:
            return EpochRevocationFailureCode.TRUSTED_STATE_INVALID
        command = state.invocation.command
        if (
            trusted.root.root_id != command.root_id
            or trusted.root.root_sha256 != command.expected_root_sha256
        ):
            return EpochRevocationFailureCode.ROOT_MISMATCH
        if (
            trusted.service_claim.status is not ServiceClaimStatus.ACTIVE
            or trusted.service_claim_revision % 3 != 0
        ):
            return EpochRevocationFailureCode.ACTIVE_CLAIM_REQUIRED
        if trusted.authority.current_epoch != command.expected_epoch:
            return EpochRevocationFailureCode.EPOCH_MISMATCH
        try:
            self._predecessor_head(state)
        except (TypeError, ValueError):
            return EpochRevocationFailureCode.TRUSTED_STATE_INVALID
        if request_sha256 != epoch_revocation_request_sha256(state.invocation):
            return EpochRevocationFailureCode.TRUSTED_STATE_INVALID
        return None

    async def _build_commit(
        self,
        state: EpochRevocationState,
        *,
        request_sha256: str,
        committed_at: str,
    ) -> EpochRevocationCommitV1:
        bundle = state.root_bundle
        if bundle is None:
            raise EpochRevocationError(EpochRevocationFailureCode.ROOT_NOT_FOUND)
        trusted = inspect_root_authority_bundle(bundle, target=self._store.target)
        if trusted is None:
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        command = state.invocation.command
        authority = trusted.authority
        previous_head = self._predecessor_head(state)
        if committed_at < previous_head.updated_at:
            raise EpochRevocationError(
                EpochRevocationFailureCode.TRUSTED_STATE_INVALID
            )
        evidence_id = epoch_revocation_evidence_id(
            request_sha256,
            trusted.root.root_sha256,
            authority.current_epoch + 1,
        )
        replacement = EpochAuthorityRecord(
            schema_version=EPOCH_AUTHORITY_V1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            current_epoch=authority.current_epoch + 1,
            previous_epoch=authority.current_epoch,
            revision=authority.revision + 1,
            cause=EpochChangeCause.OPERATOR_REVOCATION,
            changed_by=state.invocation.operator_identity,
            request_id=command.request_id,
            evidence_id=evidence_id,
            changed_at=committed_at,
        )
        subject = EpochRevocationEvidenceSubjectV1(
            schema_version=EPOCH_REVOCATION_EVIDENCE_SUBJECT_V1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            operator_identity=state.invocation.operator_identity,
            operator_subject=state.invocation.operator_subject,
            reason=command.reason,
            service_claim_sha256=canonical_sha256(trusted.service_claim),
            previous_authority_sha256=canonical_sha256(authority),
            replacement_authority_sha256=canonical_sha256(replacement),
            previous_epoch=authority.current_epoch,
            new_epoch=replacement.current_epoch,
            evidence_id=evidence_id,
            committed_at=committed_at,
        )
        event = EvidenceEvent(
            schema_version=EVIDENCE_EVENT_V1,
            evidence_id=evidence_id,
            sequence=previous_head.sequence + 1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            epoch=replacement.current_epoch,
            kind=EvidenceKind.EPOCH_ADVANCED,
            actor=state.invocation.operator_identity,
            request_id=command.request_id,
            receipt_id=None,
            occurred_at=committed_at,
            subject_sha256=canonical_sha256(subject),
            previous_event_sha256=previous_head.evidence_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=None,
        )
        try:
            signed = await self._evidence_client.sign(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise EpochRevocationError(EpochRevocationFailureCode.EVIDENCE_DENIED) from None
        if (
            type(signed) is not SignedEvidenceEventV1
            or signed.event != event
            or signed.signing_key_version
            != trusted.root.content.evidence_signing_key_version
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.EVIDENCE_DENIED)
        evidence_sha256 = canonical_sha256(signed)
        head = EvidenceChainHeadV1(
            schema_version=EVIDENCE_CHAIN_HEAD_V1,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            sequence=event.sequence,
            evidence_id=event.evidence_id,
            evidence_sha256=evidence_sha256,
            kind=event.kind,
            epoch=event.epoch,
            updated_at=committed_at,
        )
        result = EpochRevocationResultV1(
            schema_version=EPOCH_REVOCATION_RESULT_V1,
            result_id=_result_id(request_sha256),
            request_sha256=request_sha256,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            root_id=trusted.root.root_id,
            root_sha256=trusted.root.root_sha256,
            target=self._store.target,
            operator_identity=state.invocation.operator_identity,
            operator_subject=state.invocation.operator_subject,
            reason=command.reason,
            previous_epoch=authority.current_epoch,
            new_epoch=replacement.current_epoch,
            evidence_id=evidence_id,
            evidence_sha256=evidence_sha256,
            evidence_subject=subject,
            committed_at=committed_at,
        )
        request_identity, idempotency_identity = self._identity_claims(
            state.invocation,
            request_sha256=request_sha256,
            result=result,
            committed_at=committed_at,
        )
        audit = self._success_audit(
            state.invocation,
            result,
            request_sha256=request_sha256,
            outcome=EpochRevocationAuditOutcome.COMMITTED,
            recorded_at=committed_at,
        )
        return EpochRevocationCommitV1(
            replacement_authority=replacement,
            evidence_subject=subject,
            signed_evidence=signed,
            chain_head=head,
            result=result,
            request_identity=request_identity,
            idempotency_identity=idempotency_identity,
            audit=audit,
        )

    def _predecessor_head(self, state: EpochRevocationState) -> EvidenceChainHeadV1:
        bundle = state.root_bundle
        if bundle is None:
            raise ValueError("revocation predecessor root is missing")
        return current_evidence_chain_head(
            bundle,
            target=self._store.target,
            stored_head=state.chain_head,
            head_evidence=state.head_evidence,
        )

    @staticmethod
    def _result_evidence_matches(
        stored: StoredRecord[SignedEvidenceEventV1] | None,
        result: EpochRevocationResultV1,
        *,
        current_head: EvidenceChainHeadV1,
        signing_key_version: str,
    ) -> bool:
        if (
            type(stored) is not StoredRecord
            or stored.revision != 0
            or type(stored.value) is not SignedEvidenceEventV1
        ):
            return False
        signed = stored.value
        event = signed.event
        evidence_sha256 = canonical_sha256(signed)
        return (
            result.evidence_sha256 == evidence_sha256
            and result.evidence_subject.evidence_id == result.evidence_id
            and event.evidence_id == result.evidence_id
            and event.sequence > 0
            and event.sequence <= current_head.sequence
            and event.root_id == result.root_id
            and event.root_sha256 == result.root_sha256
            and event.target == result.target
            and event.epoch == result.new_epoch
            and event.kind is EvidenceKind.EPOCH_ADVANCED
            and event.actor == result.operator_identity
            and event.request_id == result.request_id
            and event.receipt_id is None
            and event.occurred_at == result.committed_at
            and event.subject_sha256 == canonical_sha256(result.evidence_subject)
            and event.previous_event_sha256 is not None
            and event.reason_code is None
            and event.provider_operation is None
            and event.target_configuration_sha256 is None
            and signed.signing_key_version == signing_key_version
            and (
                event.sequence < current_head.sequence
                or (
                    current_head.evidence_id == result.evidence_id
                    and current_head.evidence_sha256 == evidence_sha256
                )
            )
        )

    def _identity_claims(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        request_sha256: str,
        result: EpochRevocationResultV1,
        committed_at: str,
    ) -> tuple[EpochRevocationIdentityV1, EpochRevocationIdentityV1]:
        command = invocation.command

        def identity(
            kind: EpochRevocationIdentityKind,
            value: str,
        ) -> EpochRevocationIdentityV1:
            return EpochRevocationIdentityV1(
                schema_version=EPOCH_REVOCATION_IDENTITY_V1,
                identity_kind=kind,
                identity_value=value,
                root_id=result.root_id,
                root_sha256=result.root_sha256,
                request_sha256=request_sha256,
                result_id=result.result_id,
                claimed_at=committed_at,
            )

        return (
            identity(EpochRevocationIdentityKind.REQUEST, command.request_id),
            identity(EpochRevocationIdentityKind.IDEMPOTENCY, command.idempotency_key),
        )

    def _identities_match_result(
        self,
        state: EpochRevocationState,
        result: EpochRevocationResultV1,
    ) -> bool:
        command = state.invocation.command
        expected = (
            (
                state.request_identity,
                EpochRevocationIdentityKind.REQUEST,
                command.request_id,
            ),
            (
                state.idempotency_identity,
                EpochRevocationIdentityKind.IDEMPOTENCY,
                command.idempotency_key,
            ),
        )
        return all(
            type(stored) is StoredRecord
            and stored.revision == 0
            and type(stored.value) is EpochRevocationIdentityV1
            and stored.value.identity_kind is kind
            and stored.value.identity_value == value
            and stored.value.root_id == result.root_id
            and stored.value.root_sha256 == result.root_sha256
            and stored.value.request_sha256 == result.request_sha256
            and stored.value.result_id == result.result_id
            for stored, kind, value in expected
        )

    async def _resolve_ambiguous(
        self,
        invocation: EpochRevocationInvocationV1,
        request_sha256: str,
    ) -> EpochRevocationResultV1 | None:
        try:
            state = await self._read_state(invocation)
            result = self._exact_result(state, request_sha256)
            audit = self._validated_attempt_audit(state, request_sha256)
            if (
                result is None
                or audit is None
                or audit.outcome is not EpochRevocationAuditOutcome.COMMITTED
                or not self._successful_audit_matches(
                    audit,
                    invocation,
                    result,
                    request_sha256=request_sha256,
                )
                or audit.recorded_at != result.committed_at
            ):
                return None
            return result
        except EpochRevocationError:
            return None

    @staticmethod
    def _validated_attempt_audit(
        state: EpochRevocationState,
        request_sha256: str,
    ) -> EpochRevocationAuditV1 | None:
        stored = state.attempt_audit
        if stored is None:
            return None
        invocation = state.invocation
        command = invocation.command
        if (
            type(stored) is not StoredRecord
            or stored.revision != 0
            or type(stored.value) is not EpochRevocationAuditV1
            or stored.value.audit_id != invocation.attempt_id
            or stored.value.attempt_id != invocation.attempt_id
            or stored.value.request_sha256 != request_sha256
            or stored.value.root_id != command.root_id
            or stored.value.root_sha256 != command.expected_root_sha256
            or stored.value.expected_epoch != command.expected_epoch
            or stored.value.request_id != command.request_id
            or stored.value.idempotency_key != command.idempotency_key
            or stored.value.operator_identity != invocation.operator_identity
            or stored.value.operator_subject != invocation.operator_subject
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        return stored.value

    @staticmethod
    def _successful_audit_matches(
        audit: EpochRevocationAuditV1,
        invocation: EpochRevocationInvocationV1,
        result: EpochRevocationResultV1,
        *,
        request_sha256: str,
    ) -> bool:
        return (
            audit.outcome
            in {
                EpochRevocationAuditOutcome.COMMITTED,
                EpochRevocationAuditOutcome.ADOPTED,
            }
            and audit.failure_code is None
            and audit.request_sha256 == request_sha256
            and audit.root_id == result.root_id
            and audit.root_sha256 == result.root_sha256
            and audit.expected_epoch == invocation.command.expected_epoch
            and audit.request_id == result.request_id
            and audit.idempotency_key == result.idempotency_key
            and audit.operator_identity == result.operator_identity
            and audit.operator_subject == result.operator_subject
            and audit.result_id == result.result_id
            and audit.evidence_id == result.evidence_id
            and audit.new_epoch == result.new_epoch
            and audit.recorded_at >= result.committed_at
        )

    async def _record_denial(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        request_sha256: str,
        code: EpochRevocationFailureCode,
        recorded_at: str,
    ) -> None:
        command = invocation.command
        audit = EpochRevocationAuditV1(
            schema_version=EPOCH_REVOCATION_AUDIT_V1,
            audit_id=invocation.attempt_id,
            attempt_id=invocation.attempt_id,
            request_sha256=request_sha256,
            root_id=command.root_id,
            root_sha256=command.expected_root_sha256,
            expected_epoch=command.expected_epoch,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            operator_identity=invocation.operator_identity,
            operator_subject=invocation.operator_subject,
            outcome=EpochRevocationAuditOutcome.DENIED,
            failure_code=code,
            result_id=None,
            evidence_id=None,
            new_epoch=None,
            recorded_at=recorded_at,
        )
        await self._record_audit(audit)

    async def _record_success_audit(
        self,
        invocation: EpochRevocationInvocationV1,
        result: EpochRevocationResultV1,
        *,
        request_sha256: str,
        outcome: EpochRevocationAuditOutcome,
        recorded_at: str,
    ) -> None:
        await self._record_audit(
            self._success_audit(
                invocation,
                result,
                request_sha256=request_sha256,
                outcome=outcome,
                recorded_at=recorded_at,
            )
        )

    def _success_audit(
        self,
        invocation: EpochRevocationInvocationV1,
        result: EpochRevocationResultV1,
        *,
        request_sha256: str,
        outcome: EpochRevocationAuditOutcome,
        recorded_at: str,
    ) -> EpochRevocationAuditV1:
        if outcome is EpochRevocationAuditOutcome.DENIED:
            raise TypeError("successful revocation audit outcome is invalid")
        command = invocation.command
        return EpochRevocationAuditV1(
            schema_version=EPOCH_REVOCATION_AUDIT_V1,
            audit_id=invocation.attempt_id,
            attempt_id=invocation.attempt_id,
            request_sha256=request_sha256,
            root_id=command.root_id,
            root_sha256=command.expected_root_sha256,
            expected_epoch=command.expected_epoch,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            operator_identity=invocation.operator_identity,
            operator_subject=invocation.operator_subject,
            outcome=outcome,
            failure_code=None,
            result_id=result.result_id,
            evidence_id=result.evidence_id,
            new_epoch=result.new_epoch,
            recorded_at=recorded_at,
        )

    async def _record_audit(self, audit: EpochRevocationAuditV1) -> None:
        try:
            stored = await self._store.record_epoch_revocation_audit(audit)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raise EpochRevocationError(
                EpochRevocationFailureCode.TRUSTED_STATE_INVALID
            ) from None
        except (AuthorityStoreCorruptRecord, TypeError, ValueError):
            raise EpochRevocationError(
                EpochRevocationFailureCode.TRUSTED_STATE_INVALID
            ) from None
        except (AuthorityStoreOutcomeUnknown, AuthorityStoreUnavailable):
            raise EpochRevocationError(EpochRevocationFailureCode.STORE_UNAVAILABLE) from None
        except Exception:
            raise EpochRevocationError(EpochRevocationFailureCode.STORE_UNAVAILABLE) from None
        if (
            type(stored) is not StoredRecord
            or stored.revision != 0
            or stored.value != audit
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)

    def _operator_is_exact(
        self,
        invocation: EpochRevocationInvocationV1,
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
            raise EpochRevocationError(
                EpochRevocationFailureCode.TRUSTED_STATE_INVALID
            ) from None
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _validate_write_result(
        written: EpochRevocationWriteResult,
        commit: EpochRevocationCommitV1,
    ) -> None:
        if type(written) is not EpochRevocationWriteResult:
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)
        expected = (
            (
                written.authority,
                commit.replacement_authority,
                commit.replacement_authority.revision,
            ),
            (written.signed_evidence, commit.signed_evidence, 0),
            (written.chain_head, commit.chain_head, commit.chain_head.sequence),
            (written.result, commit.result, 0),
            (written.request_identity, commit.request_identity, 0),
            (written.idempotency_identity, commit.idempotency_identity, 0),
            (written.audit, commit.audit, 0),
        )
        if any(
            type(stored) is not StoredRecord
            or stored.value != value
            or stored.revision != revision
            for stored, value, revision in expected
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.TRUSTED_STATE_INVALID)


def _result_id(request_sha256: str) -> str:
    return f"cgrevoke:{request_sha256}"


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "MAX_REVOCATION_COMMIT_ATTEMPTS",
    "EpochRevocationError",
    "EpochRevocationEvidenceClient",
    "EpochRevoker",
    "RevocationCompletionWorkflow",
    "RevocationTimelineRecorder",
]
