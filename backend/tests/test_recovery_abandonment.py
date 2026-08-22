from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Any, Literal

import pytest
from pydantic import ValidationError
from recovery_v2_test_data import (
    RecoveryV2Bundle,
    make_revoked_v3_recovery_bundle,
    make_unhealthy_v3_recovery_bundle,
)
from revocation_proof_test_data import (
    OPERATOR,
    OPERATOR_SUBJECT,
    make_revocation_proof_records,
)
from root_v2_test_data import PROJECT_NUMBER, make_root_v3_records, root_v2_target
from test_recovery_execution_contracts import _dispatch_record
from test_root_creation_application import (
    _candidate as next_root_candidate,
)
from test_root_creation_application import (
    _command as next_root_command,
)
from test_root_creation_application import (
    _configuration as next_root_configuration,
)
from test_root_creation_application import (
    _snapshot as next_root_snapshot,
)

from controlgraph_canary.application.authority_store import (
    AuthorityStoreOutcomeUnknown,
    RootCreationBundle,
    RootCreationWriteResult,
    StoredRecord,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.recovery_abandonment import (
    RecoveryAbandoner,
    RecoveryAbandonmentError,
)
from controlgraph_canary.application.recovery_abandonment_relay import (
    CoordinatorRecoveryAbandonmentRelay,
)
from controlgraph_canary.application.recovery_abandonment_store import (
    RecoveryAbandonmentFenceWriteResult,
    RecoveryAbandonmentFinalizeWriteResult,
    RecoveryAbandonmentState,
    late_fence_receipt_matches,
)
from controlgraph_canary.application.root_authority import inspect_root_authority_bundle
from controlgraph_canary.application.root_creation_service import RolloutRootCreator
from controlgraph_canary.application.root_trust import TrustedRootPreflight
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.evidence import (
    EVIDENCE_CHAIN_HEAD_V1,
    EvidenceChainHeadV1,
)
from controlgraph_canary.contracts.health_storage import recovery_dispatch_record_sha256
from controlgraph_canary.contracts.models import (
    EVIDENCE_EVENT_V1,
    EXECUTION_RECEIPT_V1,
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
)
from controlgraph_canary.contracts.recovery_abandonment import (
    RECOVERY_ABANDONMENT_CLASSIFICATION_ATTESTATION_V1,
    RECOVERY_ABANDONMENT_CLASSIFICATION_RESULT_V1,
    RECOVERY_ABANDONMENT_CLASSIFICATION_SIGNING_REQUEST_V1,
    RECOVERY_ABANDONMENT_CLASSIFICATION_SUBJECT_V1,
    RECOVERY_ABANDONMENT_COMMAND_V1,
    RECOVERY_ABANDONMENT_INVOCATION_V1,
    RecoveryAbandonmentClassificationAttestationV1,
    RecoveryAbandonmentClassificationRequestV1,
    RecoveryAbandonmentClassificationResultV1,
    RecoveryAbandonmentClassificationSigningRequestV1,
    RecoveryAbandonmentClassificationSubjectV1,
    RecoveryAbandonmentCommandV1,
    RecoveryAbandonmentFailureCode,
    RecoveryAbandonmentFenceCommitV1,
    RecoveryAbandonmentFinalizeCommitV1,
    RecoveryAbandonmentInvocationV1,
    RecoveryAbandonmentPhase,
    RecoveryAbandonmentResultV1,
    recovery_abandonment_classification_request_sha256,
)
from controlgraph_canary.contracts.recovery_execution import (
    RECOVERY_DISPATCH_RECORD_V2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchState,
    create_recovery_intent,
    recovery_command_sha256,
    recovery_dispatch_id,
)
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    RootCreationCommandV1,
    SignedEvidenceEventV1,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecordV3,
    ServiceClaimStatus,
    execution_receipt_logical_id,
)
from controlgraph_canary.integrations.google.firestore import (
    _validate_initial_root_creation_bundle,
)
from controlgraph_canary.integrations.google.firestore_recovery_abandonment import (
    _validate_recovery_abandonment_fence_commit,
    _validate_recovery_abandonment_finalize_commit,
)

NOW = datetime(2026, 8, 21, 12, 12, tzinfo=UTC)


def _api_audience() -> str:
    return f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"


def _operator_policy() -> RouteAuthenticationPolicy:
    target = root_v2_target()
    return RouteAuthenticationPolicy(
        project_id=target.project_id,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.API,
        path=protected_path(ServiceRole.API),
        audience=_api_audience(),
        caller=CallerBinding(
            role=CallerRole.OPERATOR,
            email=OPERATOR,
            subject=OPERATOR_SUBJECT,
        ),
    )


def _principal(*, role: CallerRole = CallerRole.OPERATOR) -> AuthenticationContext:
    return AuthenticationContext(
        role=role,
        email=OPERATOR,
        subject=OPERATOR_SUBJECT,
        issuer="https://accounts.google.com",
        audience=_api_audience(),
        issued_at=int(NOW.timestamp()) - 60,
        expires_at=int(NOW.timestamp()) + 600,
    )


def _signed_event(
    event: EvidenceEvent,
    key_version: str,
    marker: bytes,
) -> SignedEvidenceEventV1:
    return SignedEvidenceEventV1(
        schema_version=SIGNED_EVIDENCE_EVENT_V1,
        event=event,
        purpose="EVIDENCE",
        signing_key_version=key_version,
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=evidence_payload_sha256(event),
        signing_input_sha256=evidence_signing_input_sha256(event, key_version),
        signature=encode_base64url(marker),
    )


def _dispatch(bundle: RecoveryV2Bundle) -> RecoveryDispatchRecordV2:
    command_sha256 = recovery_command_sha256(bundle.command)
    task_sha256 = canonical_sha256(bundle.task)
    task_name = (
        f"projects/{bundle.root.content.target.project_id}/locations/us-central1/"
        f"queues/controlgraph-recovery/tasks/cg-{task_sha256}"
    )
    return RecoveryDispatchRecordV2(
        schema_version=RECOVERY_DISPATCH_RECORD_V2,
        dispatch_id=recovery_dispatch_id(command_sha256),
        command_sha256=command_sha256,
        recovery_authorization_sha256=canonical_sha256(bundle.authorization),
        capability_id=bundle.authorization.capability_id,
        request_id=bundle.authorization.request_id,
        idempotency_key=bundle.authorization.idempotency_key,
        target=bundle.authorization.target,
        root_id=bundle.authorization.root_id,
        root_sha256=bundle.authorization.root_sha256,
        epoch=bundle.authorization.epoch,
        scheduled_at=bundle.authorization.scheduled_at,
        source_receipt_sha256=bundle.authorization.source_receipt_sha256,
        trigger_proof_sha256=bundle.authorization.trigger_proof_sha256,
        prestate_attestation_sha256=bundle.authorization.prestate_attestation_sha256,
        task_sha256=task_sha256,
        task_name=task_name,
        task=bundle.task,
        state=RecoveryDispatchState.ENQUEUE_STARTED,
        prepared_at=bundle.authorization.issued_at,
        enqueue_started_at=bundle.authorization.scheduled_at,
        terminal_at=None,
        result=None,
    )


def _invocation(
    dispatch: RecoveryDispatchRecordV2,
    *,
    expected_epoch: int | None = None,
) -> RecoveryAbandonmentInvocationV1:
    principal = _principal()
    return RecoveryAbandonmentInvocationV1(
        schema_version=RECOVERY_ABANDONMENT_INVOCATION_V1,
        command=RecoveryAbandonmentCommandV1(
            schema_version=RECOVERY_ABANDONMENT_COMMAND_V1,
            root_id=dispatch.root_id,
            expected_root_sha256=dispatch.root_sha256,
            expected_epoch=dispatch.epoch if expected_epoch is None else expected_epoch,
            recovery_dispatch_id=dispatch.dispatch_id,
            expected_dispatch_sha256=recovery_dispatch_record_sha256(dispatch),
            reason="The enqueue outcome is unknown after its bounded task lifetime.",
            request_id="request-abandon-recovery-001",
            idempotency_key="abandon-recovery-001",
            confirmation="ABANDON_AMBIGUOUS_RECOVERY",
        ),
        attempt_id="abandon-attempt-001",
        operator_identity=principal.email,
        operator_subject=principal.subject,
        operator_issuer="https://accounts.google.com",
        operator_audience=principal.audience,
        operator_issued_at=principal.issued_at,
        operator_expires_at=principal.expires_at,
    )


def _root_bundle_and_head() -> tuple[
    RootCreationBundle,
    StoredRecord[EvidenceChainHeadV1],
    StoredRecord[SignedEvidenceEventV1],
]:
    records = make_root_v3_records()
    revocation = make_revocation_proof_records(
        root_records=records,
        committed_at="2026-08-21T12:05:00Z",
    ).proof
    bundle = RootCreationBundle(
        root=StoredRecord(records.root, 0),
        service_claim=StoredRecord(records.service_claim, 0),
        authority=StoredRecord(revocation.authority, 1),
        lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        signed_evidence=StoredRecord(records.signed_evidence, 0),
        creation_result=StoredRecord(records.creation_result, 0),
    )
    signed = revocation.signed_evidence
    event = signed.event
    head = EvidenceChainHeadV1(
        schema_version=EVIDENCE_CHAIN_HEAD_V1,
        root_id=event.root_id,
        root_sha256=event.root_sha256,
        target=event.target,
        sequence=event.sequence,
        evidence_id=event.evidence_id,
        evidence_sha256=canonical_sha256(signed),
        kind=event.kind,
        epoch=event.epoch,
        updated_at=event.occurred_at,
    )
    return bundle, StoredRecord(head, head.sequence), StoredRecord(signed, 0)


@cache
def _initial_state() -> RecoveryAbandonmentState:
    recovery = make_revoked_v3_recovery_bundle()
    dispatch = _dispatch(recovery)
    invocation = _invocation(dispatch)
    bundle, head, head_evidence = _root_bundle_and_head()
    intent = create_recovery_intent(
        recovery.command,
        created_at=recovery.command.source.triggered_at,
    )
    return RecoveryAbandonmentState(
        invocation=invocation,
        root_bundle=bundle,
        recovery_intent=StoredRecord(intent, 0),
        recovery_dispatch=StoredRecord(dispatch, 1),
        recovery_receipt=None,
        chain_head=head,
        head_evidence=head_evidence,
        abandonment_evidence=None,
        fence_evidence=None,
        classification_evidence=None,
        release_evidence=None,
        request_identity=None,
        idempotency_identity=None,
        progress=None,
        result=None,
    )


class _EvidenceClient:
    def __init__(self, key_version: str) -> None:
        self.evidence_key_version = key_version
        self.calls: list[EvidenceEvent] = []
        self.verification_calls: list[SignedEvidenceEventV1] = []

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1:
        self.calls.append(event)
        return _signed_event(event, self.evidence_key_version, b"abandonment-evidence")

    async def verify(self, signed: SignedEvidenceEventV1) -> None:
        self.verification_calls.append(signed)
        if signed.signing_key_version != self.evidence_key_version:
            raise ValueError("unexpected evidence key")


class _ClassificationClient:
    def __init__(self, key_version: str) -> None:
        self.key_version = key_version
        self.calls: list[RecoveryAbandonmentClassificationRequestV1] = []
        self.mode: Literal["match", "mismatch", "unavailable"] = "match"

    async def classify(
        self,
        request: RecoveryAbandonmentClassificationRequestV1,
    ) -> RecoveryAbandonmentClassificationAttestationV1:
        self.calls.append(request)
        if self.mode == "unavailable":
            raise TimeoutError("synthetic verifier timeout")
        selected = (
            request
            if self.mode == "match"
            else request.model_copy(update={"request_id": "request-mismatched-classification"})
        )
        classified_at = "2026-08-21T12:12:02Z"
        reader = f"controlgraph-verifier@{selected.target.project_id}.iam.gserviceaccount.com"
        result = RecoveryAbandonmentClassificationResultV1(
            schema_version=RECOVERY_ABANDONMENT_CLASSIFICATION_RESULT_V1,
            request=selected,
            request_sha256=recovery_abandonment_classification_request_sha256(selected),
            classification="STABLE_BASELINE_CONFIRMED",
            service_generation=selected.minimum_service_generation_exclusive + 1,
            provider_etag="stable-reset-etag-001",
            target_configuration_sha256=selected.expected_target_configuration_sha256,
            classified_by=reader,
            classified_at=classified_at,
        )
        subject = RecoveryAbandonmentClassificationSubjectV1(
            schema_version=RECOVERY_ABANDONMENT_CLASSIFICATION_SUBJECT_V1,
            target=selected.target,
            root_id=selected.root_id,
            root_sha256=selected.root_sha256,
            request_sha256=selected.abandonment_request_sha256,
            classification_request_sha256=result.request_sha256,
            classification=result.classification,
            fenced_epoch=selected.fenced_epoch,
            fenced_authority_revision=selected.fenced_authority_revision,
            service_generation=result.service_generation,
            provider_etag=result.provider_etag,
            target_configuration_sha256=result.target_configuration_sha256,
            evidence_id=selected.classification_evidence_id,
            classified_by=reader,
            classified_at=classified_at,
        )
        event = EvidenceEvent(
            schema_version=EVIDENCE_EVENT_V1,
            evidence_id=selected.classification_evidence_id,
            sequence=selected.previous_evidence_sequence + 1,
            root_id=selected.root_id,
            root_sha256=selected.root_sha256,
            target=selected.target,
            epoch=selected.fenced_epoch,
            kind=EvidenceKind.TARGET_VERIFIED,
            actor=reader,
            request_id=selected.request_id,
            receipt_id=None,
            occurred_at=classified_at,
            subject_sha256=canonical_sha256(subject),
            previous_event_sha256=selected.previous_event_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=result.target_configuration_sha256,
        )
        signing_request = RecoveryAbandonmentClassificationSigningRequestV1(
            schema_version=RECOVERY_ABANDONMENT_CLASSIFICATION_SIGNING_REQUEST_V1,
            result=result,
            subject=subject,
            event=event,
        )
        return RecoveryAbandonmentClassificationAttestationV1(
            schema_version=RECOVERY_ABANDONMENT_CLASSIFICATION_ATTESTATION_V1,
            signing_request=signing_request,
            signed_evidence=_signed_event(
                event,
                self.key_version,
                b"stable-baseline-classification",
            ),
        )


class _Clock:
    def __init__(self, calls: int = 0) -> None:
        self.calls = calls

    def __call__(self) -> datetime:
        value = NOW + timedelta(seconds=self.calls)
        self.calls += 1
        return value


class _Store:
    def __init__(self, state: RecoveryAbandonmentState | None = None) -> None:
        self.state = _initial_state() if state is None else state
        assert self.state.root_bundle is not None
        self.target = self.state.root_bundle.root.value.content.target
        self.read_calls = 0
        self.fence_commits: list[
            tuple[RecoveryAbandonmentState, RecoveryAbandonmentFenceCommitV1]
        ] = []
        self.finalize_commits: list[
            tuple[RecoveryAbandonmentState, RecoveryAbandonmentFinalizeCommitV1]
        ] = []
        self.fence_outcome_unknown = False
        self.finalize_outcome_unknown = False
        self.late_epoch_denial: StoredRecord[ExecutionReceipt] | None = None
        self.late_epoch_denial_binding: MutationBinding | None = None

    async def read_recovery_abandonment_state(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
    ) -> RecoveryAbandonmentState:
        self.read_calls += 1
        return replace(self.state, invocation=invocation)

    async def commit_recovery_abandonment_fence(
        self,
        expected: RecoveryAbandonmentState,
        commit: RecoveryAbandonmentFenceCommitV1,
    ) -> RecoveryAbandonmentFenceWriteResult:
        _validate_recovery_abandonment_fence_commit(self.target, expected, commit)
        self.fence_commits.append((expected, commit))
        bundle = expected.root_bundle
        assert bundle is not None
        assert expected.recovery_dispatch is not None
        dispatch = StoredRecord(
            commit.replacement_dispatch,
            expected.recovery_dispatch.revision + 1,
        )
        claim = StoredRecord(commit.replacement_claim, bundle.service_claim.revision + 1)
        authority = StoredRecord(commit.replacement_authority, bundle.authority.revision + 1)
        abandonment = StoredRecord(commit.abandonment_evidence, 0)
        fence = StoredRecord(commit.fence_evidence, 0)
        head = StoredRecord(commit.chain_head, commit.chain_head.sequence)
        progress = StoredRecord(commit.progress, 0)
        request_identity = StoredRecord(commit.request_identity, 0)
        idempotency_identity = StoredRecord(commit.idempotency_identity, 0)
        self.state = replace(
            expected,
            root_bundle=replace(bundle, service_claim=claim, authority=authority),
            recovery_dispatch=dispatch,
            chain_head=head,
            head_evidence=fence,
            abandonment_evidence=abandonment,
            fence_evidence=fence,
            progress=progress,
            request_identity=request_identity,
            idempotency_identity=idempotency_identity,
        )
        written = RecoveryAbandonmentFenceWriteResult(
            recovery_dispatch=dispatch,
            service_claim=claim,
            authority=authority,
            abandonment_evidence=abandonment,
            fence_evidence=fence,
            chain_head=head,
            progress=progress,
            request_identity=request_identity,
            idempotency_identity=idempotency_identity,
        )
        if self.fence_outcome_unknown:
            self.fence_outcome_unknown = False
            raise AuthorityStoreOutcomeUnknown
        return written

    async def commit_recovery_abandonment_release(
        self,
        expected: RecoveryAbandonmentState,
        commit: RecoveryAbandonmentFinalizeCommitV1,
    ) -> RecoveryAbandonmentFinalizeWriteResult:
        _validate_recovery_abandonment_finalize_commit(self.target, expected, commit)
        self.finalize_commits.append((expected, commit))
        bundle = expected.root_bundle
        assert bundle is not None
        claim = StoredRecord(commit.replacement_claim, bundle.service_claim.revision + 1)
        classification = StoredRecord(commit.classification_evidence, 0)
        release = StoredRecord(commit.release_evidence, 0)
        head = StoredRecord(commit.chain_head, commit.chain_head.sequence)
        result = StoredRecord(commit.result, 0)
        self.state = replace(
            expected,
            root_bundle=replace(bundle, service_claim=claim),
            chain_head=head,
            head_evidence=release,
            classification_evidence=classification,
            release_evidence=release,
            result=result,
        )
        written = RecoveryAbandonmentFinalizeWriteResult(
            service_claim=claim,
            authority=bundle.authority,
            classification_evidence=classification,
            release_evidence=release,
            chain_head=head,
            result=result,
        )
        if self.finalize_outcome_unknown:
            self.finalize_outcome_unknown = False
            raise AuthorityStoreOutcomeUnknown
        return written


def _abandoner(
    store: _Store,
    *,
    classification: _ClassificationClient | None = None,
    clock: _Clock | None = None,
) -> tuple[RecoveryAbandoner, _EvidenceClient, _ClassificationClient]:
    assert store.state.root_bundle is not None
    key = store.state.root_bundle.root.value.content.evidence_signing_key_version
    evidence = _EvidenceClient(key)
    selected_classification = classification or _ClassificationClient(key)
    return (
        RecoveryAbandoner(
            store=store,
            evidence_client=evidence,
            classification_client=selected_classification,
            operator_policy=_operator_policy(),
            clock=clock or _Clock(),
        ),
        evidence,
        selected_classification,
    )


@dataclass(frozen=True, slots=True)
class _FirstStageTemplate:
    state: RecoveryAbandonmentState
    read_calls: int
    fence_commits: tuple[tuple[RecoveryAbandonmentState, RecoveryAbandonmentFenceCommitV1], ...]
    result: RecoveryAbandonmentResultV1
    evidence_calls: tuple[EvidenceEvent, ...]
    evidence_verification_calls: tuple[SignedEvidenceEventV1, ...]
    clock_calls: int


@cache
def _first_stage_template() -> _FirstStageTemplate:
    store = _Store()
    clock = _Clock()
    abandoner, evidence, _ = _abandoner(store, clock=clock)
    result = asyncio.run(abandoner.abandon(store.state.invocation, principal=_principal()))
    return _FirstStageTemplate(
        state=store.state,
        read_calls=store.read_calls,
        fence_commits=tuple(store.fence_commits),
        result=result,
        evidence_calls=tuple(evidence.calls),
        evidence_verification_calls=tuple(evidence.verification_calls),
        clock_calls=clock.calls,
    )


def _run_first_stage() -> tuple[
    _Store,
    RecoveryAbandoner,
    _EvidenceClient,
    _ClassificationClient,
    RecoveryAbandonmentResultV1,
]:
    template = _first_stage_template()
    store = _Store(template.state)
    store.read_calls = template.read_calls
    store.fence_commits.extend(template.fence_commits)
    abandoner, evidence, classification = _abandoner(
        store,
        clock=_Clock(template.clock_calls),
    )
    evidence.calls.extend(template.evidence_calls)
    evidence.verification_calls.extend(template.evidence_verification_calls)
    return store, abandoner, evidence, classification, template.result


@dataclass(frozen=True, slots=True)
class _ReleasedStageTemplate:
    state: RecoveryAbandonmentState
    read_calls: int
    fence_commits: tuple[tuple[RecoveryAbandonmentState, RecoveryAbandonmentFenceCommitV1], ...]
    finalize_commits: tuple[
        tuple[RecoveryAbandonmentState, RecoveryAbandonmentFinalizeCommitV1], ...
    ]
    result: RecoveryAbandonmentResultV1
    evidence_calls: tuple[EvidenceEvent, ...]
    evidence_verification_calls: tuple[SignedEvidenceEventV1, ...]
    classification_calls: tuple[RecoveryAbandonmentClassificationRequestV1, ...]


@cache
def _released_stage_template() -> _ReleasedStageTemplate:
    store, abandoner, evidence, classification, _ = _run_first_stage()
    result = asyncio.run(abandoner.abandon(store.state.invocation, principal=_principal()))
    return _ReleasedStageTemplate(
        state=store.state,
        read_calls=store.read_calls,
        fence_commits=tuple(store.fence_commits),
        finalize_commits=tuple(store.finalize_commits),
        result=result,
        evidence_calls=tuple(evidence.calls),
        evidence_verification_calls=tuple(evidence.verification_calls),
        classification_calls=tuple(classification.calls),
    )


def _run_released_stage() -> tuple[
    _Store,
    _EvidenceClient,
    _ClassificationClient,
    RecoveryAbandonmentResultV1,
]:
    template = _released_stage_template()
    store = _Store(template.state)
    store.read_calls = template.read_calls
    store.fence_commits.extend(template.fence_commits)
    store.finalize_commits.extend(template.finalize_commits)
    _, evidence, classification = _abandoner(store)
    evidence.calls.extend(template.evidence_calls)
    evidence.verification_calls.extend(template.evidence_verification_calls)
    classification.calls.extend(template.classification_calls)
    return store, evidence, classification, template.result


def _late_epoch_denial(
    store: _Store,
    *,
    revision: int = 1,
    **updates: Any,
) -> StoredRecord[ExecutionReceipt]:
    if store.late_epoch_denial is not None:
        value = store.late_epoch_denial.value
        if updates:
            value = value.model_copy(update=updates)
        return StoredRecord(value, revision)
    assert store.state.recovery_dispatch is not None
    assert store.state.progress is not None
    dispatch = store.state.recovery_dispatch.value
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
    store.late_epoch_denial_binding = binding
    values: dict[str, Any] = {
        "schema_version": EXECUTION_RECEIPT_V1,
        "receipt_id": execution_receipt_logical_id(target, intent.idempotency_key),
        "request_id": intent.request_id,
        "idempotency_key": intent.idempotency_key,
        "capability_sha256": binding.capability_sha256,
        "mutation_sha256": mutation_identity(binding),
        "plan_sha256": intent.plan_sha256,
        "expected_poststate_sha256": intent.desired_poststate_sha256,
        "target": target,
        "root_id": intent.root_id,
        "root_sha256": intent.root_sha256,
        "epoch": intent.epoch,
        "action": CapabilityAction.RECOVER_STABLE,
        "provider_etag": intent.provider_etag,
        "dispatch_not_after": dispatch.task.expires_at,
        "outcome": ReceiptOutcome.DENIED,
        "reason_code": ReasonCode.EPOCH_MISMATCH,
        "provider_operation": None,
        "observed_etag": None,
        "observed_authority_epoch": store.state.progress.value.fenced_epoch,
        "created_at": "2026-08-21T12:11:00Z",
        "updated_at": "2026-08-21T12:12:01Z",
        "evidence_ids": (),
    }
    receipt = ExecutionReceipt.model_validate(values)
    store.late_epoch_denial = StoredRecord(receipt, 1)
    if updates:
        receipt = receipt.model_copy(update=updates)
    return StoredRecord(receipt, revision)


def test_first_stage_atomically_fences_without_releasing_the_claim() -> None:
    store, _, evidence, classification, result = _run_first_stage()

    assert result.phase is RecoveryAbandonmentPhase.FENCED_RESET_REQUIRED
    assert result.classification_evidence_id is None
    assert len(store.fence_commits) == 1
    assert not store.finalize_commits
    assert len(evidence.calls) == 2
    assert not classification.calls
    assert store.state.root_bundle is not None
    claim = store.state.root_bundle.service_claim.value
    authority = store.state.root_bundle.authority.value
    dispatch = store.state.recovery_dispatch
    assert type(claim) is ServiceClaimRecordV3
    assert claim.status is ServiceClaimStatus.RELEASING
    assert claim.terminal_root_proof is not None
    assert claim.terminal_root_proof.state == "ABANDONED"
    assert claim.target_classification_proof is None
    assert authority.current_epoch == 3
    assert authority.revision == 2
    assert dispatch is not None
    assert dispatch.revision == 2
    assert dispatch.value.state is RecoveryDispatchState.AMBIGUOUS
    assert dispatch.value.result is not None
    assert dispatch.value.result.enqueue_disposition == "AMBIGUOUS"


def _prior_epoch_terminal_state(
    terminal_state: RecoveryDispatchState = RecoveryDispatchState.CREATED,
) -> RecoveryAbandonmentState:
    recovery = make_unhealthy_v3_recovery_bundle()
    terminal_dispatch = _dispatch_record(recovery, state=terminal_state)
    root_bundle, head, head_evidence = _root_bundle_and_head()
    return RecoveryAbandonmentState(
        invocation=_invocation(
            terminal_dispatch,
            expected_epoch=root_bundle.authority.value.current_epoch,
        ),
        root_bundle=root_bundle,
        recovery_intent=StoredRecord(
            create_recovery_intent(
                recovery.command,
                created_at=recovery.command.source.triggered_at,
            ),
            0,
        ),
        recovery_dispatch=StoredRecord(terminal_dispatch, 2),
        recovery_receipt=None,
        chain_head=head,
        head_evidence=head_evidence,
        abandonment_evidence=None,
        fence_evidence=None,
        classification_evidence=None,
        release_evidence=None,
        request_identity=None,
        idempotency_identity=None,
        progress=None,
        result=None,
    )


@pytest.mark.parametrize(
    "terminal_state",
    [RecoveryDispatchState.CREATED, RecoveryDispatchState.DUPLICATE],
)
def test_expired_terminal_dispatch_from_prior_operator_epoch_is_safely_abandoned(
    terminal_state: RecoveryDispatchState,
) -> None:
    state = _prior_epoch_terminal_state(terminal_state)
    root_bundle = state.root_bundle
    terminal_dispatch = state.recovery_dispatch
    assert root_bundle is not None and terminal_dispatch is not None
    assert root_bundle.authority.value.current_epoch == terminal_dispatch.value.epoch + 1
    assert root_bundle.authority.value.cause.value == "OPERATOR_REVOCATION"
    store = _Store(state)
    abandoner, _, _ = _abandoner(store)

    fenced = asyncio.run(abandoner.abandon(state.invocation, principal=_principal()))

    assert fenced.phase is RecoveryAbandonmentPhase.FENCED_RESET_REQUIRED
    assert store.state.root_bundle is not None
    assert store.state.root_bundle.authority.value.previous_epoch == 2
    assert store.state.root_bundle.authority.value.current_epoch == 3
    assert store.state.recovery_dispatch is not None
    assert store.state.recovery_dispatch.revision == 3
    assert store.state.recovery_dispatch.value.state is RecoveryDispatchState.AMBIGUOUS
    assert store.state.progress is not None
    assert store.state.progress.value.abandonment_subject.previous_dispatch_revision == 2
    assert store.state.progress.value.abandonment_subject.ambiguous_dispatch_revision == 3

    released = asyncio.run(
        abandoner.abandon(store.state.invocation, principal=_principal())
    )

    assert released.phase is RecoveryAbandonmentPhase.RELEASED
    assert len(store.fence_commits) == 1
    assert len(store.finalize_commits) == 1


@pytest.mark.parametrize("authority_case", ["two-behind", "wrong-cause", "wrong-previous"])
def test_prior_epoch_terminal_cleanup_rejects_any_wider_epoch_relation(
    authority_case: str,
) -> None:
    state = _prior_epoch_terminal_state()
    assert state.root_bundle is not None
    authority = state.root_bundle.authority.value
    if authority_case == "two-behind":
        authority = EpochAuthorityRecord.model_validate(
            {
                **authority.model_dump(mode="python"),
                "current_epoch": 3,
                "previous_epoch": 2,
                "revision": 2,
            }
        )
    elif authority_case == "wrong-cause":
        authority = authority.model_copy(update={"cause": EpochChangeCause.SUPERSESSION})
    else:
        authority = authority.model_copy(update={"previous_epoch": 2})
    command = state.invocation.command.model_copy(
        update={"expected_epoch": authority.current_epoch}
    )
    state = replace(
        state,
        invocation=state.invocation.model_copy(update={"command": command}),
        root_bundle=replace(
            state.root_bundle,
            authority=StoredRecord(authority, authority.revision),
        ),
    )
    store = _Store(state)
    abandoner, _, _ = _abandoner(store)

    with pytest.raises(RecoveryAbandonmentError) as failure:
        asyncio.run(abandoner.abandon(state.invocation, principal=_principal()))

    expected_code = (
        RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
        if authority_case == "two-behind"
        else RecoveryAbandonmentFailureCode.DISPATCH_INVALID
    )
    assert failure.value.code is expected_code
    assert not store.fence_commits


def test_prior_epoch_terminal_cleanup_accepts_only_exact_late_fence_denial() -> None:
    store = _Store(_prior_epoch_terminal_state())
    abandoner, _, _ = _abandoner(store)
    asyncio.run(abandoner.abandon(store.state.invocation, principal=_principal()))
    dispatch = store.state.recovery_dispatch
    progress = store.state.progress
    assert dispatch is not None and progress is not None
    exact = _late_epoch_denial(store)

    assert progress.value.fenced_epoch == dispatch.value.epoch + 2
    assert late_fence_receipt_matches(
        exact,
        dispatch.value,
        fenced_epoch=progress.value.fenced_epoch,
        fenced_at=progress.value.fenced_at,
    )
    for out_of_bounds in (dispatch.value.epoch, dispatch.value.epoch + 3):
        assert not late_fence_receipt_matches(
            exact,
            dispatch.value,
            fenced_epoch=out_of_bounds,
            fenced_at=progress.value.fenced_at,
        )
    assert not late_fence_receipt_matches(
        _late_epoch_denial(
            store,
            observed_authority_epoch=progress.value.fenced_epoch - 1,
        ),
        dispatch.value,
        fenced_epoch=progress.value.fenced_epoch,
        fenced_at=progress.value.fenced_at,
    )

    store.state = replace(store.state, recovery_receipt=exact)
    released = asyncio.run(
        abandoner.abandon(store.state.invocation, principal=_principal())
    )
    assert released.phase is RecoveryAbandonmentPhase.RELEASED


def test_finalize_requires_independent_stable_classification_and_never_marks_recovered() -> None:
    store, evidence, classification, result = _run_released_stage()
    partial = _first_stage_template().result

    assert partial.phase is RecoveryAbandonmentPhase.FENCED_RESET_REQUIRED
    assert result.phase is RecoveryAbandonmentPhase.RELEASED
    assert len(classification.calls) == 1
    assert len(evidence.calls) == 3
    assert len(store.finalize_commits) == 1
    assert store.state.root_bundle is not None
    claim = store.state.root_bundle.service_claim.value
    authority = store.state.root_bundle.authority.value
    assert type(claim) is ServiceClaimRecordV3
    assert claim.status is ServiceClaimStatus.RELEASED
    assert claim.terminal_root_proof is not None
    assert claim.terminal_root_proof.state == "ABANDONED"
    assert claim.target_classification_proof == result.stable_baseline_proof
    assert authority.current_epoch == result.fenced_epoch
    assert authority.cause.value == "OPERATOR_REVOCATION"
    assert inspect_root_authority_bundle(store.state.root_bundle, target=store.target) is not None


def test_lost_responses_are_adopted_without_a_second_fence_or_release() -> None:
    store = _Store()
    store.fence_outcome_unknown = True
    abandoner, evidence, classification = _abandoner(store)
    invocation = store.state.invocation

    partial = asyncio.run(abandoner.abandon(invocation, principal=_principal()))
    assert partial.phase is RecoveryAbandonmentPhase.FENCED_RESET_REQUIRED
    assert len(store.fence_commits) == 1

    store.finalize_outcome_unknown = True
    released = asyncio.run(abandoner.abandon(invocation, principal=_principal()))
    replay = asyncio.run(abandoner.abandon(invocation, principal=_principal()))

    assert released.phase is RecoveryAbandonmentPhase.RELEASED
    assert replay == released
    assert len(store.fence_commits) == 1
    assert len(store.finalize_commits) == 1
    assert len(classification.calls) == 1
    assert len(evidence.calls) == 3


@pytest.mark.parametrize("mode", ["mismatch", "unavailable"])
def test_classification_mismatch_or_unavailability_retains_the_fence(mode: str) -> None:
    store, abandoner, _, classification, _ = _run_first_stage()
    classification.mode = mode  # type: ignore[assignment]

    with pytest.raises(RecoveryAbandonmentError) as failure:
        asyncio.run(abandoner.abandon(store.state.invocation, principal=_principal()))

    assert failure.value.code is RecoveryAbandonmentFailureCode.CLASSIFICATION_DENIED
    assert len(store.fence_commits) == 1
    assert not store.finalize_commits
    assert store.state.root_bundle is not None
    assert store.state.root_bundle.service_claim.value.status is ServiceClaimStatus.RELEASING


@pytest.mark.parametrize(
    "principal",
    [
        None,
        _principal(role=CallerRole.API),
        AuthenticationContext(
            role=CallerRole.OPERATOR,
            email="other-operator@example.test",
            subject=OPERATOR_SUBJECT,
            issuer="https://accounts.google.com",
            audience=_api_audience(),
            issued_at=int(NOW.timestamp()) - 60,
            expires_at=int(NOW.timestamp()) + 600,
        ),
    ],
)
def test_abandonment_denies_missing_wrong_role_or_wrong_operator(
    principal: AuthenticationContext | None,
) -> None:
    store = _Store()
    abandoner, _, _ = _abandoner(store)

    with pytest.raises(RecoveryAbandonmentError) as failure:
        asyncio.run(abandoner.abandon(store.state.invocation, principal=principal))

    assert failure.value.code is RecoveryAbandonmentFailureCode.CALLER_DENIED
    assert store.read_calls == 0
    assert not store.fence_commits


class _NeverCalledAbandoner:
    def __init__(self) -> None:
        self.calls = 0

    async def abandon(
        self,
        invocation: RecoveryAbandonmentInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> RecoveryAbandonmentResultV1:
        del invocation, principal
        self.calls += 1
        raise AssertionError("denied relay must not call the coordinator application")


def _coordinator_policy() -> RouteAuthenticationPolicy:
    target = root_v2_target()
    return RouteAuthenticationPolicy(
        project_id=target.project_id,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.COORDINATOR,
        path=protected_path(ServiceRole.COORDINATOR),
        audience=f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app",
        caller=CallerBinding(
            role=CallerRole.API,
            email=f"controlgraph-api@{target.project_id}.iam.gserviceaccount.com",
            subject="123456789012345678902",
        ),
    )


def test_coordinator_relay_denies_non_api_service_identity() -> None:
    application = _NeverCalledAbandoner()
    relay = CoordinatorRecoveryAbandonmentRelay(
        authentication_policy=_coordinator_policy(),
        operator_policy=_operator_policy(),
        abandoner=application,
    )
    caller = AuthenticationContext(
        role=CallerRole.ISSUER,
        email=f"controlgraph-issuer@{root_v2_target().project_id}.iam.gserviceaccount.com",
        subject="123456789012345678903",
        issuer="https://accounts.google.com",
        audience=_coordinator_policy().audience,
        issued_at=int(NOW.timestamp()) - 60,
        expires_at=int(NOW.timestamp()) + 600,
    )

    with pytest.raises(RecoveryAbandonmentError) as failure:
        asyncio.run(relay.abandon(_initial_state().invocation, caller))

    assert failure.value.code is RecoveryAbandonmentFailureCode.CALLER_DENIED
    assert application.calls == 0


def test_exact_late_epoch_denial_is_accepted_and_all_near_misses_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, _, _, _ = _run_first_stage()
    dispatch = store.state.recovery_dispatch
    progress = store.state.progress
    assert dispatch is not None and progress is not None
    exact = _late_epoch_denial(store)
    assert late_fence_receipt_matches(
        exact,
        dispatch.value,
        fenced_epoch=progress.value.fenced_epoch,
        fenced_at=progress.value.fenced_at,
    )
    binding = store.late_epoch_denial_binding
    assert binding is not None

    def cached_fixture_sha256(value: object) -> str:
        if value is dispatch.value.task.capability:
            return binding.capability_sha256
        if value is dispatch.value.task:
            return binding.payload_sha256
        raise AssertionError("late-receipt matching hashed an unexpected value")

    monkeypatch.setattr(
        "controlgraph_canary.application.recovery_abandonment_store.canonical_sha256",
        cached_fixture_sha256,
    )

    target = dispatch.value.target.model_copy(update={"service_name": "other-service"})
    near_misses = (
        _late_epoch_denial(store, revision=0),
        _late_epoch_denial(store, receipt_id="cgreceipt:wrong"),
        _late_epoch_denial(store, request_id="request-wrong"),
        _late_epoch_denial(store, idempotency_key="idempotency-wrong"),
        _late_epoch_denial(store, root_id=f"cgroot:{'f' * 64}", root_sha256="f" * 64),
        _late_epoch_denial(store, epoch=dispatch.value.epoch + 1),
        _late_epoch_denial(store, action=CapabilityAction.PROMOTE_CANDIDATE),
        _late_epoch_denial(store, target=target),
        _late_epoch_denial(store, provider_etag="provider-etag-wrong"),
        _late_epoch_denial(store, plan_sha256="a" * 64),
        _late_epoch_denial(store, capability_sha256="b" * 64),
        _late_epoch_denial(store, mutation_sha256="c" * 64),
        _late_epoch_denial(store, expected_poststate_sha256="d" * 64),
        _late_epoch_denial(store, dispatch_not_after="2026-08-21T12:11:31Z"),
        _late_epoch_denial(store, reason_code=ReasonCode.CALLER_UNAUTHORIZED),
        _late_epoch_denial(store, observed_authority_epoch=progress.value.fenced_epoch + 1),
        _late_epoch_denial(store, updated_at="2026-08-21T12:11:59Z"),
        _late_epoch_denial(store, evidence_ids=("unexpected-evidence",)),
    )
    for near_miss in near_misses:
        assert not late_fence_receipt_matches(
            near_miss,
            dispatch.value,
            fenced_epoch=progress.value.fenced_epoch,
            fenced_at=progress.value.fenced_at,
        )


def test_exact_late_epoch_denial_does_not_block_final_release() -> None:
    store, abandoner, _, _, _ = _run_first_stage()
    store.state = replace(store.state, recovery_receipt=_late_epoch_denial(store))

    result = asyncio.run(abandoner.abandon(store.state.invocation, principal=_principal()))

    assert result.phase is RecoveryAbandonmentPhase.RELEASED
    assert len(store.finalize_commits) == 1


def test_near_miss_late_receipt_fails_closed_before_classification() -> None:
    store, abandoner, _, classification, _ = _run_first_stage()
    store.state = replace(
        store.state,
        recovery_receipt=_late_epoch_denial(
            store,
            reason_code=ReasonCode.CALLER_UNAUTHORIZED,
        ),
    )

    with pytest.raises(RecoveryAbandonmentError) as failure:
        asyncio.run(abandoner.abandon(store.state.invocation, principal=_principal()))

    assert failure.value.code is RecoveryAbandonmentFailureCode.TRUSTED_STATE_INVALID
    assert not classification.calls
    assert not store.finalize_commits


def test_command_contract_excludes_mutation_coordinates_and_binds_root() -> None:
    command = _initial_state().invocation.command
    assert set(command.model_dump(mode="json")) == {
        "schema_version",
        "root_id",
        "expected_root_sha256",
        "expected_epoch",
        "recovery_dispatch_id",
        "expected_dispatch_sha256",
        "reason",
        "request_id",
        "idempotency_key",
        "confirmation",
    }
    for updates in (
        {"target": root_v2_target()},
        {"confirmation": "RECOVER_CAPTURED_STABLE"},
        {"expected_root_sha256": "f" * 64},
    ):
        with pytest.raises(ValidationError):
            RecoveryAbandonmentCommandV1.model_validate(
                {**command.model_dump(mode="python"), **updates}
            )


@pytest.mark.parametrize(
    "tamper",
    [
        "proof-provider-etag",
        "subject-configuration",
        "release-request",
        "release-operator",
        "classification-evidence-hash",
        "release-time",
    ],
)
def test_released_result_contract_rejects_cross_binding_substitution(tamper: str) -> None:
    _, _, _, result = _run_released_stage()
    values = result.model_dump(mode="python")
    proof = result.stable_baseline_proof
    subject = result.classification_subject
    release = result.release_subject
    assert proof is not None and subject is not None and release is not None
    if tamper == "proof-provider-etag":
        values["stable_baseline_proof"] = proof.model_copy(
            update={"provider_etag": "substituted-etag"}
        )
    elif tamper == "subject-configuration":
        values["classification_subject"] = subject.model_copy(
            update={"target_configuration_sha256": "e" * 64}
        )
    elif tamper == "release-request":
        values["release_subject"] = release.model_copy(update={"request_id": "request-other"})
    elif tamper == "release-operator":
        values["release_subject"] = release.model_copy(
            update={"operator_identity": "other-operator@example.test"}
        )
    elif tamper == "classification-evidence-hash":
        values["classification_evidence_sha256"] = "f" * 64
    else:
        values["released_at"] = "2026-08-21T12:12:01Z"

    with pytest.raises(ValidationError):
        RecoveryAbandonmentResultV1.model_validate(values)


@pytest.mark.parametrize(
    "tamper",
    [
        "claim-actor",
        "dispatch-terminal",
        "ambiguity-actor",
        "fence-request",
        "request-identity",
    ],
)
def test_fence_commit_validator_rejects_externally_bound_substitution(tamper: str) -> None:
    store, _, _, _, _ = _run_first_stage()
    expected, valid = store.fence_commits[0]
    if tamper == "claim-actor":
        changed = valid.model_copy(
            update={
                "replacement_claim": valid.replacement_claim.model_copy(
                    update={"release_fenced_by": "other-operator@example.test"}
                )
            }
        )
    elif tamper == "dispatch-terminal":
        changed = valid.model_copy(
            update={
                "replacement_dispatch": valid.replacement_dispatch.model_copy(
                    update={"terminal_at": "2026-08-21T12:12:01Z"}
                )
            }
        )
    elif tamper == "ambiguity-actor":
        event = valid.abandonment_evidence.event.model_copy(
            update={"actor": "other-operator@example.test"}
        )
        changed = valid.model_copy(
            update={
                "abandonment_evidence": _signed_event(
                    event,
                    valid.abandonment_evidence.signing_key_version,
                    b"substituted-ambiguity",
                )
            }
        )
    elif tamper == "fence-request":
        event = valid.fence_evidence.event.model_copy(update={"request_id": "request-other"})
        changed = valid.model_copy(
            update={
                "fence_evidence": _signed_event(
                    event,
                    valid.fence_evidence.signing_key_version,
                    b"substituted-fence",
                )
            }
        )
    else:
        changed = valid.model_copy(
            update={
                "request_identity": valid.request_identity.model_copy(
                    update={"identity_value": "request-other"}
                )
            }
        )

    with pytest.raises(ValueError, match=r"not exactly bound|one transition"):
        _validate_recovery_abandonment_fence_commit(store.target, expected, changed)


@pytest.mark.parametrize(
    "tamper",
    [
        "claim-release-actor",
        "classification-request-hash",
        "classification-actor",
        "release-claim-hash",
        "release-target-digest",
        "result-dispatch",
    ],
)
def test_finalize_commit_validator_rejects_externally_bound_substitution(tamper: str) -> None:
    store, _, _, _ = _run_released_stage()
    expected, valid = store.finalize_commits[0]
    if tamper == "claim-release-actor":
        changed = valid.model_copy(
            update={
                "replacement_claim": valid.replacement_claim.model_copy(
                    update={"released_by": None}
                )
            }
        )
    elif tamper == "classification-request-hash":
        changed = valid.model_copy(
            update={
                "classification_subject": valid.classification_subject.model_copy(
                    update={"classification_request_sha256": "a" * 64}
                )
            }
        )
    elif tamper == "classification-actor":
        event = valid.classification_evidence.event.model_copy(
            update={"actor": "other-reader@example.test"}
        )
        changed = valid.model_copy(
            update={
                "classification_evidence": _signed_event(
                    event,
                    valid.classification_evidence.signing_key_version,
                    b"substituted-classification",
                )
            }
        )
    elif tamper == "release-claim-hash":
        changed = valid.model_copy(
            update={
                "release_subject": valid.release_subject.model_copy(
                    update={"fenced_claim_sha256": "b" * 64}
                )
            }
        )
    elif tamper == "release-target-digest":
        event = valid.release_evidence.event.model_copy(
            update={"target_configuration_sha256": "c" * 64}
        )
        changed = valid.model_copy(
            update={
                "release_evidence": _signed_event(
                    event,
                    valid.release_evidence.signing_key_version,
                    b"substituted-release",
                )
            }
        )
    else:
        changed = valid.model_copy(
            update={
                "result": valid.result.model_copy(update={"recovery_dispatch_id": "dispatch-other"})
            }
        )

    with pytest.raises(ValueError, match=r"not exactly bound|transition is invalid"):
        _validate_recovery_abandonment_finalize_commit(store.target, expected, changed)


class _NextRootPreflightClient:
    async def preflight(self, request: object) -> TrustedRootPreflight:
        del request
        return TrustedRootPreflight(
            stable_snapshot=next_root_snapshot(captured_at="2026-08-21T12:13:00Z"),
            candidate_revision=next_root_candidate(captured_at="2026-08-21T12:13:00Z"),
        )


class _NextRootEvidenceClient:
    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1:
        return _signed_event(
            event,
            next_root_configuration().evidence_signing_key_version,
            b"next-root-evidence",
        )


class _NextRootStore:
    def __init__(self, released_claim: StoredRecord[ServiceClaimRecordV3]) -> None:
        self.target = released_claim.value.target
        self.claim = released_claim
        self.expected_released_claim: StoredRecord[ServiceClaimRecordV3] | None = None

    async def read_service_claim(self) -> StoredRecord[ServiceClaimRecordV3]:
        return self.claim

    async def read_root_creation_bundle(self, root_id: str) -> None:
        del root_id
        return None

    async def create_or_adopt_root_creation_bundle(
        self,
        root: Any,
        service_claim: Any,
        authority: Any,
        lineage_anchor: Any,
        signed_evidence: Any,
        creation_result: Any,
        *,
        expected_released_claim: StoredRecord[ServiceClaimRecordV3] | None = None,
    ) -> RootCreationWriteResult:
        assert expected_released_claim == self.claim
        _validate_initial_root_creation_bundle(
            self.target,
            root,
            service_claim,
            authority,
            lineage_anchor,
            signed_evidence,
            creation_result,
            expected_released_claim,
        )
        self.expected_released_claim = expected_released_claim
        bundle = RootCreationBundle(
            root=StoredRecord(root, 0),
            service_claim=StoredRecord(service_claim, self.claim.revision + 1),
            authority=StoredRecord(authority, 0),
            lineage_anchor=StoredRecord(lineage_anchor, 0),
            signed_evidence=StoredRecord(signed_evidence, 0),
            creation_result=StoredRecord(creation_result, 0),
        )
        return RootCreationWriteResult(result=creation_result, bundle=bundle)


def test_released_v3_claim_allows_a_new_root_only_as_the_next_claim_revision() -> None:
    abandonment_store, _, _, _ = _run_released_stage()
    assert abandonment_store.state.root_bundle is not None
    released = abandonment_store.state.root_bundle.service_claim
    assert type(released.value) is ServiceClaimRecordV3
    assert released.value.status is ServiceClaimStatus.RELEASED
    assert released.revision == 2

    next_store = _NextRootStore(released)
    creator = RolloutRootCreator(
        store=next_store,
        preflight_client=_NextRootPreflightClient(),
        evidence_client=_NextRootEvidenceClient(),
        configuration=next_root_configuration(),
        clock=lambda: datetime(2026, 8, 21, 12, 13, 1, tzinfo=UTC),
    )
    expected_snapshot = next_root_snapshot(captured_at="2026-08-21T12:12:59Z")
    command = RootCreationCommandV1.model_validate(
        {
            **next_root_command(request_id="request-root-after-abandonment").model_dump(
                mode="python"
            ),
            "idempotency_key": "root-after-abandonment",
            "expected_stable_snapshot": expected_snapshot,
        }
    )

    created = asyncio.run(creator.create(command, principal=_principal()))

    assert next_store.expected_released_claim == released
    assert created.bundle.service_claim.revision == released.revision + 1
    assert created.bundle.service_claim.value.status is ServiceClaimStatus.ACTIVE
    assert created.bundle.root.value.root_id != released.value.root_id
