from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from root_v2_test_data import PROJECT_NUMBER, make_root_v2_records, root_v2_target
from test_m2_firestore_authority_store import (
    _FakeClient,
    _FakeTransactionRunner,
    _StoredDocument,
)

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreOutcomeUnknown,
    ReceiptClaimCreated,
    RootCreationBundle,
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
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.service_claim_release import (
    ServiceClaimReleaseError,
    ServiceClaimReleaser,
)
from controlgraph_canary.application.service_claim_release_relay import (
    ApiServiceClaimReleaseClient,
)
from controlgraph_canary.application.service_claim_release_store import (
    ServiceClaimFenceWriteResult,
    ServiceClaimFinalizeWriteResult,
    ServiceClaimReleaseState,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    encode_base64url,
)
from controlgraph_canary.contracts.evidence import (
    EVIDENCE_CHAIN_HEAD_V1,
    EvidenceChainHeadV1,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    EvidenceEvent,
    EvidenceKind,
    ExecutionReceipt,
    ReceiptOutcome,
)
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    SignedEvidenceEventV1,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)
from controlgraph_canary.contracts.service_claim_release import (
    SERVICE_CLAIM_CLASSIFICATION_ATTESTATION_V1,
    SERVICE_CLAIM_CLASSIFICATION_RESULT_V1,
    SERVICE_CLAIM_CLASSIFICATION_SIGNING_REQUEST_V1,
    SERVICE_CLAIM_RELEASE_COMMAND_V1,
    SERVICE_CLAIM_RELEASE_INVOCATION_V1,
    SERVICE_CLAIM_RELEASE_RELAY_RESPONSE_V1,
    SERVICE_CLAIM_TARGET_CLASSIFICATION_EVIDENCE_SUBJECT_V1,
    ServiceClaimClassificationAttestationV1,
    ServiceClaimClassificationRequestV1,
    ServiceClaimClassificationResultV1,
    ServiceClaimClassificationSigningRequestV1,
    ServiceClaimReleaseCommandV1,
    ServiceClaimReleaseFailureCode,
    ServiceClaimReleaseFenceCommitV1,
    ServiceClaimReleaseFinalizeCommitV1,
    ServiceClaimReleaseIdentityKind,
    ServiceClaimReleaseIdentityV1,
    ServiceClaimReleaseInvocationV1,
    ServiceClaimReleaseRelayResponseV1,
    ServiceClaimReleaseResultV1,
    ServiceClaimTargetClassificationEvidenceSubjectV1,
    service_claim_classification_request_sha256,
    service_claim_release_request_sha256,
)
from controlgraph_canary.contracts.storage import (
    AuthorityStorageKind,
    ServiceClaimStatus,
    evidence_chain_head_document_id,
    execution_receipt_logical_id,
    signed_evidence_event_document_id,
)
from controlgraph_canary.integrations.google.firestore import (
    FirestoreAuthorityStore,
    _document_data,
    _prepared_document,
    _validate_service_claim_fence_commit,
    _validate_service_claim_finalize_commit,
)

NOW = datetime(2026, 8, 20, 15, 0, tzinfo=UTC)
OPERATOR = "operator@example.test"
OPERATOR_SUBJECT = "123456789012345678901"
TERMINAL_KEY = "terminal-promote-001"


def _api_audience() -> str:
    return f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"


def _policy() -> RouteAuthenticationPolicy:
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


def _principal() -> AuthenticationContext:
    return AuthenticationContext(
        role=CallerRole.OPERATOR,
        email=OPERATOR,
        subject=OPERATOR_SUBJECT,
        issuer="https://accounts.google.com",
        audience=_api_audience(),
        issued_at=int(NOW.timestamp()) - 60,
        expires_at=int(NOW.timestamp()) + 600,
    )


def _invocation() -> ServiceClaimReleaseInvocationV1:
    records = make_root_v2_records()
    principal = _principal()
    return ServiceClaimReleaseInvocationV1(
        schema_version=SERVICE_CLAIM_RELEASE_INVOCATION_V1,
        command=ServiceClaimReleaseCommandV1(
            schema_version=SERVICE_CLAIM_RELEASE_COMMAND_V1,
            root_id=records.root.root_id,
            expected_root_sha256=records.root.root_sha256,
            expected_epoch=1,
            terminal_receipt_idempotency_key=TERMINAL_KEY,
            request_id="request-release-001",
            idempotency_key="release-001",
            confirmation="RELEASE",
        ),
        attempt_id="release-attempt-001",
        operator_identity=principal.email,
        operator_subject=principal.subject,
        operator_issuer="https://accounts.google.com",
        operator_audience=principal.audience,
        operator_issued_at=principal.issued_at,
        operator_expires_at=principal.expires_at,
    )


def _root_bundle() -> RootCreationBundle:
    records = make_root_v2_records()
    return RootCreationBundle(
        root=StoredRecord(records.root, 0),
        service_claim=StoredRecord(records.service_claim, 0),
        authority=StoredRecord(records.authority, 0),
        lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        signed_evidence=StoredRecord(records.signed_evidence, 0),
        creation_result=StoredRecord(records.creation_result, 0),
    )


def _receipt(
    *,
    action: CapabilityAction = CapabilityAction.PROMOTE_CANDIDATE,
    outcome: ReceiptOutcome = ReceiptOutcome.VERIFIED,
) -> StoredRecord[ExecutionReceipt]:
    bundle = _root_bundle()
    claim = bundle.service_claim.value
    expected_poststate = {
        CapabilityAction.PROMOTE_CANDIDATE: (claim.candidate_target_configuration_sha256),
        CapabilityAction.RECOVER_STABLE: claim.stable_target_configuration_sha256,
        CapabilityAction.APPLY_CANARY: "4" * 64,
    }[action]
    return StoredRecord(
        ExecutionReceipt(
            schema_version="controlgraph.execution-receipt/v1",
            receipt_id=execution_receipt_logical_id(claim.target, TERMINAL_KEY),
            request_id="request-terminal-001",
            idempotency_key=TERMINAL_KEY,
            capability_sha256="5" * 64,
            mutation_sha256="6" * 64,
            plan_sha256="7" * 64,
            expected_poststate_sha256=expected_poststate,
            target=claim.target,
            root_id=claim.root_id,
            root_sha256=claim.root_sha256,
            epoch=1,
            action=action,
            provider_etag="provider-before-001",
            dispatch_not_after="2026-08-20T15:10:00Z",
            outcome=outcome,
            reason_code=None,
            provider_operation="operations/promote-001",
            observed_etag="provider-after-001",
            observed_authority_epoch=1,
            created_at="2026-08-20T14:58:00Z",
            updated_at="2026-08-20T14:59:00Z",
            evidence_ids=("receipt-evidence-001",),
        ),
        2,
    )


def _receipt_binding(receipt: ExecutionReceipt) -> MutationBinding:
    return MutationBinding(
        idempotency_key=receipt.idempotency_key,
        request_id=receipt.request_id,
        root_id=receipt.root_id,
        root_sha256=receipt.root_sha256,
        epoch=receipt.epoch,
        action=MutationAction(receipt.action.value),
        target=MutationTargetKey(
            project_id=receipt.target.project_id,
            region=receipt.target.region,
            environment=receipt.target.environment,
            service_name=receipt.target.service_name,
        ),
        provider_precondition=receipt.provider_etag,
        plan_sha256=receipt.plan_sha256,
        capability_sha256=receipt.capability_sha256,
        payload_sha256="8" * 64,
        expected_poststate_sha256=receipt.expected_poststate_sha256,
    )


async def _persist_terminal_receipt(
    store: FirestoreAuthorityStore,
) -> StoredRecord[ExecutionReceipt]:
    terminal = _receipt().value
    claimed = ExecutionReceipt.model_validate(
        {
            **terminal.model_dump(mode="python"),
            "mutation_sha256": "0" * 64,
            "outcome": ReceiptOutcome.CLAIMED,
            "provider_operation": None,
            "observed_etag": None,
            "observed_authority_epoch": None,
            "updated_at": "2026-08-20T14:58:00Z",
            "evidence_ids": (),
        }
    )
    binding = _receipt_binding(claimed)
    claimed = claimed.model_copy(update={"mutation_sha256": mutation_identity(binding)})
    created = await store.claim_or_adopt_receipt(claimed, binding)
    assert type(created) is ReceiptClaimCreated
    applied = claimed.model_copy(
        update={
            "outcome": ReceiptOutcome.APPLIED,
            "provider_operation": terminal.provider_operation,
            "observed_authority_epoch": 1,
            "updated_at": "2026-08-20T14:58:30Z",
            "evidence_ids": ("receipt-evidence-applied",),
        }
    )
    stored_applied = await store.compare_and_set_receipt(created.receipt, applied)
    verified = applied.model_copy(
        update={
            "outcome": ReceiptOutcome.VERIFIED,
            "observed_etag": terminal.observed_etag,
            "updated_at": terminal.updated_at,
            "evidence_ids": (
                *applied.evidence_ids,
                "receipt-evidence-verified",
            ),
        }
    )
    return await store.compare_and_set_receipt(stored_applied, verified)


def _firestore_store(
    client: _FakeClient,
    runner: _FakeTransactionRunner,
) -> FirestoreAuthorityStore:
    target = root_v2_target()
    return FirestoreAuthorityStore.for_test(
        target=target,
        configured_project_id=target.project_id,
        client_factory=lambda: client,
        transaction_runner=runner,
    )


async def _created_firestore_release_stores() -> tuple[
    FirestoreAuthorityStore,
    FirestoreAuthorityStore,
    _FakeClient,
]:
    client = _FakeClient()
    runner = _FakeTransactionRunner()
    first = _firestore_store(client, runner)
    second = _firestore_store(client, runner)
    records = make_root_v2_records()
    await first.create_or_adopt_root_creation_bundle(
        records.root,
        records.service_claim,
        records.authority,
        records.lineage_anchor,
        records.signed_evidence,
        records.creation_result,
    )
    await _persist_terminal_receipt(first)
    return first, second, client


def _firestore_releaser(
    store: FirestoreAuthorityStore,
    *,
    evidence: _EvidenceClient | None = None,
    classification: _ClassificationClient | None = None,
) -> ServiceClaimReleaser:
    key = make_root_v2_records().root.content.evidence_signing_key_version
    return ServiceClaimReleaser(
        store=store,
        evidence_client=evidence or _EvidenceClient(key),
        classification_client=classification or _ClassificationClient(key),
        operator_policy=_policy(),
        clock=lambda: NOW + timedelta(seconds=2),
    )


def _signed_event(event: EvidenceEvent, key_version: str, marker: bytes) -> SignedEvidenceEventV1:
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


class _EvidenceClient:
    def __init__(
        self,
        key_version: str,
        marker: bytes = b"coordinator-evidence",
    ) -> None:
        self.evidence_key_version = key_version
        self.marker = marker
        self.calls: list[EvidenceEvent] = []
        self.verification_calls: list[SignedEvidenceEventV1] = []
        self.invalid_evidence_id: str | None = None

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1:
        self.calls.append(event)
        return _signed_event(event, self.evidence_key_version, self.marker)

    async def verify(self, signed: SignedEvidenceEventV1) -> None:
        self.verification_calls.append(signed)
        if signed.event.evidence_id == self.invalid_evidence_id:
            raise ValueError("stored evidence signature is invalid")


class _ClassificationClient:
    def __init__(
        self,
        key_version: str,
        marker: bytes = b"verifier-classification",
    ) -> None:
        self.key_version = key_version
        self.marker = marker
        self.calls: list[ServiceClaimClassificationRequestV1] = []
        self.error: BaseException | None = None

    async def classify(
        self,
        request: ServiceClaimClassificationRequestV1,
    ) -> ServiceClaimClassificationAttestationV1:
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        classified_at = "2026-08-20T15:00:01Z"
        reader = f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        result = ServiceClaimClassificationResultV1(
            schema_version=SERVICE_CLAIM_CLASSIFICATION_RESULT_V1,
            request=request,
            request_sha256=service_claim_classification_request_sha256(request),
            classification=request.expected_classification,
            service_generation=request.minimum_service_generation_exclusive + 1,
            provider_etag="classification-etag-001",
            target_configuration_sha256=(request.expected_target_configuration_sha256),
            classified_by=reader,
            classified_at=classified_at,
        )
        subject = ServiceClaimTargetClassificationEvidenceSubjectV1(
            schema_version=(SERVICE_CLAIM_TARGET_CLASSIFICATION_EVIDENCE_SUBJECT_V1),
            target=request.target,
            root_id=request.root_id,
            root_sha256=request.root_sha256,
            request_sha256=request.release_request_sha256,
            classification_request_sha256=result.request_sha256,
            classification=result.classification,
            fenced_epoch=request.fenced_epoch,
            fenced_authority_revision=request.fenced_authority_revision,
            service_generation=result.service_generation,
            provider_etag=result.provider_etag,
            target_configuration_sha256=result.target_configuration_sha256,
            evidence_id=request.classification_evidence_id,
            classified_by=reader,
            classified_at=classified_at,
        )
        event = EvidenceEvent(
            schema_version="controlgraph.evidence-event/v1",
            evidence_id=request.classification_evidence_id,
            sequence=request.previous_evidence_sequence + 1,
            root_id=request.root_id,
            root_sha256=request.root_sha256,
            target=request.target,
            epoch=request.fenced_epoch,
            kind=EvidenceKind.TARGET_VERIFIED,
            actor=reader,
            request_id=request.request_id,
            receipt_id=None,
            occurred_at=classified_at,
            subject_sha256=canonical_sha256(subject),
            previous_event_sha256=request.previous_event_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=result.target_configuration_sha256,
        )
        signing_request = ServiceClaimClassificationSigningRequestV1(
            schema_version=SERVICE_CLAIM_CLASSIFICATION_SIGNING_REQUEST_V1,
            result=result,
            subject=subject,
            event=event,
        )
        return ServiceClaimClassificationAttestationV1(
            schema_version=SERVICE_CLAIM_CLASSIFICATION_ATTESTATION_V1,
            signing_request=signing_request,
            signed_evidence=_signed_event(
                event,
                self.key_version,
                self.marker,
            ),
        )


class _Store:
    def __init__(self, invocation: ServiceClaimReleaseInvocationV1) -> None:
        bundle = _root_bundle()
        self.target = bundle.root.value.content.target
        self.state = ServiceClaimReleaseState(
            invocation=invocation,
            root_bundle=bundle,
            terminal_receipt=_receipt(),
            chain_head=None,
            head_evidence=None,
            terminal_evidence=None,
            fence_evidence=None,
            classification_evidence=None,
            release_evidence=None,
            request_identity=None,
            idempotency_identity=None,
            progress=None,
            result=None,
        )
        self.fence_commits: list[
            tuple[ServiceClaimReleaseState, ServiceClaimReleaseFenceCommitV1]
        ] = []
        self.finalize_commits: list[
            tuple[ServiceClaimReleaseState, ServiceClaimReleaseFinalizeCommitV1]
        ] = []
        self.fence_conflicts = 0
        self.fence_outcome_unknown = False
        self.finalize_outcome_unknown = False

    async def read_service_claim_release_state(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
    ) -> ServiceClaimReleaseState:
        return replace(self.state, invocation=invocation)

    async def commit_service_claim_fence(
        self,
        expected: ServiceClaimReleaseState,
        commit: ServiceClaimReleaseFenceCommitV1,
    ) -> ServiceClaimFenceWriteResult:
        self.fence_commits.append((expected, commit))
        if self.fence_conflicts:
            self.fence_conflicts -= 1
            raise AuthorityStoreConflict
        bundle = expected.root_bundle
        assert bundle is not None
        claim = StoredRecord(commit.replacement_claim, bundle.service_claim.revision + 1)
        authority = StoredRecord(
            commit.replacement_authority,
            bundle.authority.revision + 1,
        )
        terminal = StoredRecord(commit.terminal_evidence, 0)
        fence = StoredRecord(commit.fence_evidence, 0)
        head = StoredRecord(commit.chain_head, commit.chain_head.sequence)
        progress = StoredRecord(commit.progress, 0)
        request_identity = StoredRecord(commit.request_identity, 0)
        idempotency_identity = StoredRecord(commit.idempotency_identity, 0)
        self.state = replace(
            expected,
            root_bundle=replace(
                bundle,
                service_claim=claim,
                authority=authority,
            ),
            chain_head=head,
            head_evidence=fence,
            terminal_evidence=terminal,
            fence_evidence=fence,
            request_identity=request_identity,
            idempotency_identity=idempotency_identity,
            progress=progress,
        )
        written = ServiceClaimFenceWriteResult(
            service_claim=claim,
            authority=authority,
            terminal_evidence=terminal,
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

    async def commit_service_claim_release(
        self,
        expected: ServiceClaimReleaseState,
        commit: ServiceClaimReleaseFinalizeCommitV1,
    ) -> ServiceClaimFinalizeWriteResult:
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
        written = ServiceClaimFinalizeWriteResult(
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


def _releaser(
    store: _Store,
    *,
    classification: _ClassificationClient | None = None,
) -> tuple[ServiceClaimReleaser, _EvidenceClient, _ClassificationClient]:
    key = make_root_v2_records().root.content.evidence_signing_key_version
    evidence = _EvidenceClient(key)
    selected_classification = classification or _ClassificationClient(key)
    times = iter((NOW, NOW + timedelta(seconds=2)))
    return (
        ServiceClaimReleaser(
            store=store,
            evidence_client=evidence,
            classification_client=selected_classification,
            operator_policy=_policy(),
            clock=lambda: next(times),
        ),
        evidence,
        selected_classification,
    )


def test_release_fences_classifies_and_atomically_persists_exact_chain() -> None:
    invocation = _invocation()
    store = _Store(invocation)
    releaser, evidence, classification = _releaser(store)

    result = asyncio.run(releaser.release(invocation, principal=_principal()))

    assert len(evidence.calls) == 3
    assert len(classification.calls) == 1
    assert len(store.fence_commits) == 1
    assert len(store.finalize_commits) == 1
    state = store.state
    assert state.root_bundle is not None
    claim = state.root_bundle.service_claim.value
    authority = state.root_bundle.authority.value
    assert claim.status is ServiceClaimStatus.RELEASED
    assert authority.current_epoch == 2
    assert authority.revision == 1
    assert authority.cause is EpochChangeCause.OPERATOR_REVOCATION
    assert authority.changed_by == OPERATOR
    assert state.chain_head is not None
    assert state.chain_head.value.sequence == 4
    assert state.chain_head.value.sequence > authority.revision
    assert state.classification_evidence is not None
    assert state.classification_evidence.value.event.actor == (
        f"controlgraph-verifier@{store.target.project_id}.iam.gserviceaccount.com"
    )
    assert state.result is not None
    assert result == state.result.value
    fence_expected, fence_commit = store.fence_commits[0]
    final_expected, final_commit = store.finalize_commits[0]
    assert fence_commit.fence_evidence.event.actor == OPERATOR
    assert fence_commit.replacement_authority.changed_by == OPERATOR
    assert fence_commit.replacement_claim.release_fenced_by == OPERATOR
    _validate_service_claim_fence_commit(store.target, fence_expected, fence_commit)
    _validate_service_claim_finalize_commit(store.target, final_expected, final_commit)


@pytest.mark.parametrize(
    "invalid_kind",
    [None, "terminal", "fence", "classification", "release"],
)
def test_durable_release_replay_reverifies_every_bound_evidence_envelope(
    invalid_kind: str | None,
) -> None:
    invocation = _invocation()
    store = _Store(invocation)
    releaser, _, _ = _releaser(store)
    expected = asyncio.run(releaser.release(invocation, principal=_principal()))
    assert store.state.progress is not None
    progress = store.state.progress.value
    evidence_ids = {
        "terminal": progress.terminal_evidence_id,
        "fence": progress.fence_evidence_id,
        "classification": expected.classification_evidence_id,
        "release": expected.release_evidence_id,
    }
    verifier = _EvidenceClient(
        make_root_v2_records().root.content.evidence_signing_key_version
    )
    if invalid_kind is not None:
        verifier.invalid_evidence_id = evidence_ids[invalid_kind]
    replay = ServiceClaimReleaser(
        store=store,
        evidence_client=verifier,
        classification_client=_ClassificationClient(verifier.evidence_key_version),
        operator_policy=_policy(),
        clock=lambda: NOW + timedelta(seconds=3),
    )

    if invalid_kind is None:
        assert asyncio.run(replay.release(invocation, principal=_principal())) == expected
    else:
        with pytest.raises(ServiceClaimReleaseError) as failure:
            asyncio.run(replay.release(invocation, principal=_principal()))
        assert failure.value.code is ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID

    expected_order = [
        evidence_ids["terminal"],
        evidence_ids["fence"],
        evidence_ids["classification"],
        evidence_ids["release"],
    ]
    actual_order = [signed.event.evidence_id for signed in verifier.verification_calls]
    if invalid_kind is None:
        assert actual_order == expected_order
    else:
        invalid_index = expected_order.index(evidence_ids[invalid_kind])
        assert actual_order == expected_order[: invalid_index + 1]


def _advance_released_store_with_authority_head(
    store: _Store,
    invocation: ServiceClaimReleaseInvocationV1,
    *,
    sequence_delta: int = 1,
    previous_event_sha256: str | None = None,
    authority_changed_by: str = OPERATOR,
) -> SignedEvidenceEventV1:
    assert store.state.root_bundle is not None
    assert store.state.chain_head is not None
    assert store.state.head_evidence is not None
    key = store.state.root_bundle.root.value.content.evidence_signing_key_version
    current_authority = store.state.root_bundle.authority.value
    later_authority = EpochAuthorityRecord(
        schema_version=current_authority.schema_version,
        root_id=current_authority.root_id,
        root_sha256=current_authority.root_sha256,
        target=current_authority.target,
        current_epoch=current_authority.current_epoch + 1,
        previous_epoch=current_authority.current_epoch,
        revision=current_authority.revision + 1,
        cause=EpochChangeCause.OPERATOR_REVOCATION,
        changed_by=authority_changed_by,
        request_id="request-after-service-claim-release",
        evidence_id="evidence-after-service-claim-release",
        changed_at="2026-08-20T15:00:03Z",
    )
    later_event = EvidenceEvent(
        schema_version="controlgraph.evidence-event/v1",
        evidence_id="evidence-after-service-claim-release",
        sequence=store.state.chain_head.value.sequence + sequence_delta,
        root_id=invocation.command.root_id,
        root_sha256=invocation.command.expected_root_sha256,
        target=store.target,
        epoch=later_authority.current_epoch,
        kind=EvidenceKind.EPOCH_ADVANCED,
        actor=OPERATOR,
        request_id="request-after-service-claim-release",
        receipt_id=None,
        occurred_at="2026-08-20T15:00:03Z",
        subject_sha256="d" * 64,
        previous_event_sha256=(
            previous_event_sha256
            if previous_event_sha256 is not None
            else canonical_sha256(store.state.head_evidence.value)
        ),
        reason_code=None,
        provider_operation=None,
        target_configuration_sha256=None,
    )
    later_evidence = _signed_event(later_event, key, b"later-same-root-evidence")
    later_head = EvidenceChainHeadV1(
        schema_version=EVIDENCE_CHAIN_HEAD_V1,
        root_id=later_event.root_id,
        root_sha256=later_event.root_sha256,
        target=later_event.target,
        sequence=later_event.sequence,
        evidence_id=later_event.evidence_id,
        evidence_sha256=canonical_sha256(later_evidence),
        kind=later_event.kind,
        epoch=later_event.epoch,
        updated_at=later_event.occurred_at,
    )
    store.state = replace(
        store.state,
        root_bundle=replace(
            store.state.root_bundle,
            authority=StoredRecord(
                later_authority,
                store.state.root_bundle.authority.revision + 1,
            ),
        ),
        chain_head=StoredRecord(later_head, later_head.sequence),
        head_evidence=StoredRecord(later_evidence, 0),
    )
    return later_evidence


def _released_store() -> tuple[
    ServiceClaimReleaseInvocationV1,
    _Store,
    ServiceClaimReleaseResultV1,
]:
    invocation = _invocation()
    store = _Store(invocation)
    releaser, _, _ = _releaser(store)
    result = asyncio.run(releaser.release(invocation, principal=_principal()))
    return invocation, store, result


def test_durable_release_replay_accepts_and_verifies_a_later_authority_head() -> None:
    invocation, store, expected = _released_store()
    later_evidence = _advance_released_store_with_authority_head(store, invocation)
    assert store.state.root_bundle is not None
    key = store.state.root_bundle.root.value.content.evidence_signing_key_version
    verifier = _EvidenceClient(key)
    replay = ServiceClaimReleaser(
        store=store,
        evidence_client=verifier,
        classification_client=_ClassificationClient(key),
        operator_policy=_policy(),
        clock=lambda: NOW + timedelta(seconds=4),
    )

    assert asyncio.run(replay.release(invocation, principal=_principal())) == expected
    assert [
        signed.event.evidence_id for signed in verifier.verification_calls
    ] == [
        expected.terminal_evidence_id,
        expected.fence_evidence_id,
        expected.classification_evidence_id,
        expected.release_evidence_id,
        later_evidence.event.evidence_id,
    ]


@pytest.mark.parametrize(
    "tamper",
    ["signed-fork", "skipped-link", "mismatched-authority"],
)
def test_durable_release_replay_rejects_unproven_or_mismatched_successor(
    tamper: str,
) -> None:
    invocation, store, _ = _released_store()
    if tamper == "signed-fork":
        _advance_released_store_with_authority_head(
            store,
            invocation,
            previous_event_sha256="a" * 64,
        )
    elif tamper == "skipped-link":
        _advance_released_store_with_authority_head(
            store,
            invocation,
            sequence_delta=2,
            previous_event_sha256="b" * 64,
        )
    else:
        _advance_released_store_with_authority_head(
            store,
            invocation,
            authority_changed_by="different-operator@example.test",
        )
    assert store.state.root_bundle is not None
    key = store.state.root_bundle.root.value.content.evidence_signing_key_version
    replay = ServiceClaimReleaser(
        store=store,
        evidence_client=_EvidenceClient(key),
        classification_client=_ClassificationClient(key),
        operator_policy=_policy(),
        clock=lambda: NOW + timedelta(seconds=4),
    )

    with pytest.raises(ServiceClaimReleaseError) as failure:
        asyncio.run(replay.release(invocation, principal=_principal()))

    assert failure.value.code is ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID


@pytest.mark.parametrize("tamper", ["authority-digest", "request-fact"])
def test_later_authority_replay_rejects_tampered_historical_fence(
    tamper: str,
) -> None:
    invocation, store, _ = _released_store()
    _advance_released_store_with_authority_head(store, invocation)
    assert store.state.root_bundle is not None
    assert store.state.progress is not None
    assert store.state.fence_evidence is not None
    progress = store.state.progress.value
    fence = store.state.fence_evidence.value
    key = store.state.root_bundle.root.value.content.evidence_signing_key_version
    tampered_subject = (
        progress.fence_subject.model_copy(
            update={"replacement_authority_sha256": "f" * 64}
        )
        if tamper == "authority-digest"
        else progress.fence_subject
    )
    tampered_event = fence.event.model_copy(
        update=(
            {"subject_sha256": canonical_sha256(tampered_subject)}
            if tamper == "authority-digest"
            else {"request_id": "request-tampered-fence-authority"}
        )
    )
    tampered_fence = _signed_event(
        tampered_event,
        key,
        b"valid-signature-over-tampered-fence-subject",
    )
    tampered_progress = progress.model_copy(
        update={
            "fence_subject": tampered_subject,
            "fence_evidence_sha256": canonical_sha256(tampered_fence),
        }
    )
    store.state = replace(
        store.state,
        progress=StoredRecord(tampered_progress, store.state.progress.revision),
        fence_evidence=StoredRecord(
            tampered_fence,
            store.state.fence_evidence.revision,
        ),
    )
    replay = ServiceClaimReleaser(
        store=store,
        evidence_client=_EvidenceClient(key),
        classification_client=_ClassificationClient(key),
        operator_policy=_policy(),
        clock=lambda: NOW + timedelta(seconds=4),
    )

    with pytest.raises(ServiceClaimReleaseError) as failure:
        asyncio.run(
            replay._exact_progress(
                store.state,
                service_claim_release_request_sha256(invocation),
            )
        )

    assert failure.value.code is ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID


def test_nonterminal_apply_receipt_is_denied_before_signing_or_storage() -> None:
    invocation = _invocation()
    store = _Store(invocation)
    store.state = replace(
        store.state,
        terminal_receipt=_receipt(action=CapabilityAction.APPLY_CANARY),
    )
    releaser, evidence, classification = _releaser(store)

    with pytest.raises(ServiceClaimReleaseError) as failure:
        asyncio.run(releaser.release(invocation, principal=_principal()))

    assert failure.value.code is ServiceClaimReleaseFailureCode.TERMINAL_RECEIPT_INVALID
    assert evidence.calls == []
    assert classification.calls == []
    assert store.fence_commits == []


def test_conflict_retry_and_both_ambiguous_commits_adopt_exact_winners() -> None:
    invocation = _invocation()
    store = _Store(invocation)
    store.fence_conflicts = 1
    store.fence_outcome_unknown = True
    store.finalize_outcome_unknown = True
    releaser, _, _ = _releaser(store)

    result = asyncio.run(releaser.release(invocation, principal=_principal()))

    assert result.result_id == (f"cgrelease:{service_claim_release_request_sha256(invocation)}")
    assert len(store.fence_commits) == 2
    assert len(store.finalize_commits) == 1
    assert store.state.result is not None
    assert store.state.result.value == result


def test_existing_identity_without_exact_progress_blocks_silent_takeover() -> None:
    invocation = _invocation()
    store = _Store(invocation)
    store.state = replace(
        store.state,
        request_identity=StoredRecord(
            ServiceClaimReleaseIdentityV1(
                schema_version="controlgraph.service-claim-release-identity/v1",
                identity_kind=ServiceClaimReleaseIdentityKind.REQUEST,
                identity_value=invocation.command.request_id,
                root_id=invocation.command.root_id,
                root_sha256=invocation.command.expected_root_sha256,
                request_sha256="f" * 64,
                result_id=f"cgrelease:{'f' * 64}",
                claimed_at="2026-08-20T14:59:59Z",
            ),
            0,
        ),
    )
    releaser, evidence, _ = _releaser(store)

    with pytest.raises(ServiceClaimReleaseError) as failure:
        asyncio.run(releaser.release(invocation, principal=_principal()))

    assert failure.value.code is ServiceClaimReleaseFailureCode.IDENTITY_CONFLICT
    assert evidence.calls == []


def test_classification_failure_leaves_durable_fence_without_final_release() -> None:
    invocation = _invocation()
    store = _Store(invocation)
    key = make_root_v2_records().root.content.evidence_signing_key_version
    classification = _ClassificationClient(key)
    classification.error = RuntimeError("provider details must not escape")
    releaser, _, _ = _releaser(store, classification=classification)

    with pytest.raises(ServiceClaimReleaseError) as failure:
        asyncio.run(releaser.release(invocation, principal=_principal()))

    assert failure.value.code is ServiceClaimReleaseFailureCode.CLASSIFICATION_DENIED
    assert store.state.root_bundle is not None
    assert store.state.root_bundle.service_claim.value.status is ServiceClaimStatus.RELEASING
    assert store.state.progress is not None
    assert store.state.result is None
    assert store.finalize_commits == []


@pytest.mark.parametrize(
    "forked",
    [False, True],
    ids=["valid-immediate-successor", "signed-fork"],
)
def test_fenced_release_requires_exact_immediate_successor_ancestry(
    forked: bool,
) -> None:
    async def scenario() -> None:
        invocation = _invocation()
        store = _Store(invocation)
        key = make_root_v2_records().root.content.evidence_signing_key_version
        evidence = _EvidenceClient(key)
        classification = _ClassificationClient(key)
        releaser = ServiceClaimReleaser(
            store=store,
            evidence_client=evidence,
            classification_client=classification,
            operator_policy=_policy(),
            clock=lambda: NOW + timedelta(seconds=2),
        )
        initial = await store.read_service_claim_release_state(invocation)
        fence = await releaser._build_fence_commit(
            initial,
            request_sha256=service_claim_release_request_sha256(invocation),
            fenced_at="2026-08-20T15:00:00Z",
        )
        await store.commit_service_claim_fence(initial, fence)
        fenced = store.state
        assert fenced.root_bundle is not None
        assert fenced.chain_head is not None
        assert fenced.head_evidence is not None
        fork_event = EvidenceEvent(
            schema_version="controlgraph.evidence-event/v1",
            evidence_id="evidence-signed-fork-after-fence",
            sequence=fenced.chain_head.value.sequence + 1,
            root_id=invocation.command.root_id,
            root_sha256=invocation.command.expected_root_sha256,
            target=store.target,
            epoch=fenced.root_bundle.authority.value.current_epoch,
            kind=EvidenceKind.TARGET_VERIFIED,
            actor=f"controlgraph-verifier@{store.target.project_id}.iam.gserviceaccount.com",
            request_id="request-signed-fork-after-fence",
            receipt_id=None,
            occurred_at="2026-08-20T15:00:01Z",
            subject_sha256="c" * 64,
            previous_event_sha256=(
                "d" * 64
                if forked
                else canonical_sha256(fenced.head_evidence.value)
            ),
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256="e" * 64,
        )
        fork = _signed_event(fork_event, key, b"signed-fork-after-fence")
        fork_head = EvidenceChainHeadV1(
            schema_version=EVIDENCE_CHAIN_HEAD_V1,
            root_id=fork_event.root_id,
            root_sha256=fork_event.root_sha256,
            target=fork_event.target,
            sequence=fork_event.sequence,
            evidence_id=fork_event.evidence_id,
            evidence_sha256=canonical_sha256(fork),
            kind=fork_event.kind,
            epoch=fork_event.epoch,
            updated_at=fork_event.occurred_at,
        )
        store.state = replace(
            fenced,
            chain_head=StoredRecord(fork_head, fork_head.sequence),
            head_evidence=StoredRecord(fork, 0),
        )

        if forked:
            with pytest.raises(ServiceClaimReleaseError) as failure:
                await releaser.release(invocation, principal=_principal())
            assert failure.value.code is ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            assert classification.calls == []
            assert store.finalize_commits == []
        else:
            result = await releaser.release(invocation, principal=_principal())
            assert result.request_id == invocation.command.request_id
            assert len(classification.calls) == 1
            assert len(store.finalize_commits) == 1

    asyncio.run(scenario())


def test_firestore_validators_reject_authority_and_verifier_actor_substitution() -> None:
    invocation = _invocation()
    store = _Store(invocation)
    releaser, _, _ = _releaser(store)
    asyncio.run(releaser.release(invocation, principal=_principal()))
    fence_expected, fence_commit = store.fence_commits[0]
    final_expected, final_commit = store.finalize_commits[0]

    wrong_authority = fence_commit.replacement_authority.model_copy(
        update={"evidence_id": "evidence-substituted"}
    )
    with pytest.raises(ValueError, match=r"exactly bound|one transition"):
        _validate_service_claim_fence_commit(
            store.target,
            fence_expected,
            fence_commit.model_copy(update={"replacement_authority": wrong_authority}),
        )

    wrong_actor = final_commit.classification_evidence.event.model_copy(
        update={"actor": "controlgraph.coordinator/v1"}
    )
    wrong_classification = final_commit.classification_evidence.model_copy(
        update={"event": wrong_actor}
    )
    with pytest.raises(
        ValueError,
        match=r"exactly bound|contract validation failed",
    ):
        _validate_service_claim_finalize_commit(
            store.target,
            final_expected,
            final_commit.model_copy(update={"classification_evidence": wrong_classification}),
        )


class _RelayTransport:
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        del route, body
        return self.body


class _FailingRelayTransport:
    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        del route, body
        raise TimeoutError("coordinator response was not observed")


def test_typed_api_relay_preserves_deterministic_coordinator_denial() -> None:
    denial = ServiceClaimReleaseRelayResponseV1(
        schema_version=SERVICE_CLAIM_RELEASE_RELAY_RESPONSE_V1,
        result=None,
        failure_code=ServiceClaimReleaseFailureCode.IDENTITY_CONFLICT,
    )
    client = ApiServiceClaimReleaseClient(
        route=CoordinatorInternalRoute(
            project_id=root_v2_target().project_id,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.API,
            service_role=ServiceRole.COORDINATOR,
            audience=(f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"),
        ),
        authentication_policy=_policy(),
        transport=_RelayTransport(canonical_json_bytes(denial)),
    )

    with pytest.raises(ServiceClaimReleaseError) as failure:
        asyncio.run(
            client.release(
                _invocation().command,
                _principal(),
            )
        )

    assert failure.value.code is ServiceClaimReleaseFailureCode.IDENTITY_CONFLICT


def test_api_relay_transport_failure_is_outcome_ambiguous() -> None:
    client = ApiServiceClaimReleaseClient(
        route=CoordinatorInternalRoute(
            project_id=root_v2_target().project_id,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.API,
            service_role=ServiceRole.COORDINATOR,
            audience=(f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"),
        ),
        authentication_policy=_policy(),
        transport=_FailingRelayTransport(),
    )

    with pytest.raises(ServiceClaimReleaseError) as failure:
        asyncio.run(client.release(_invocation().command, _principal()))

    assert failure.value.code is ServiceClaimReleaseFailureCode.OUTCOME_UNKNOWN


@pytest.mark.parametrize("tamper", ["delete", "substitute"])
def test_firestore_fence_rechecks_the_exact_signed_predecessor(tamper: str) -> None:
    async def scenario() -> None:
        store, _, client = await _created_firestore_release_stores()
        invocation = _invocation()
        state = await store.read_service_claim_release_state(invocation)
        releaser = _firestore_releaser(store)
        commit = await releaser._build_fence_commit(
            state,
            request_sha256=service_claim_release_request_sha256(invocation),
            fenced_at="2026-08-20T15:00:00Z",
        )
        assert state.root_bundle is not None
        predecessor = state.root_bundle.signed_evidence
        predecessor_id = predecessor.value.event.evidence_id
        document_id = signed_evidence_event_document_id(predecessor_id)
        path = f"{AuthorityStorageKind.SIGNED_EVIDENCE_EVENT.value}/{document_id}"
        original = client.documents[path]
        if tamper == "delete":
            del client.documents[path]
        else:
            substituted = predecessor.value.model_copy(
                update={"signature": encode_base64url(b"substituted-predecessor")}
            )
            prepared = _prepared_document(
                kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
                logical_id=predecessor_id,
                document_id=document_id,
                revision=predecessor.revision,
                value=substituted,
            )
            client.documents[path] = _StoredDocument(
                _document_data(prepared.wrapper),
                original.update_time,
            )

        with pytest.raises(AuthorityStoreConflict):
            await store.commit_service_claim_fence(state, commit)

        client.documents[path] = original
        restored = await store.read_service_claim_release_state(invocation)
        assert restored.root_bundle is not None
        assert restored.root_bundle.service_claim.value.status is ServiceClaimStatus.ACTIVE
        assert restored.root_bundle.authority.value.current_epoch == 1
        assert restored.progress is None
        assert restored.chain_head is None

    asyncio.run(scenario())


def test_firestore_finalize_appends_after_interleaved_head_and_rechecks_predecessor() -> None:
    async def scenario() -> None:
        store, _, client = await _created_firestore_release_stores()
        invocation = _invocation()
        key = make_root_v2_records().root.content.evidence_signing_key_version
        releaser = _firestore_releaser(
            store,
            evidence=_EvidenceClient(key),
            classification=_ClassificationClient(key),
        )
        initial = await store.read_service_claim_release_state(invocation)
        request_sha256 = service_claim_release_request_sha256(invocation)
        fence = await releaser._build_fence_commit(
            initial,
            request_sha256=request_sha256,
            fenced_at="2026-08-20T15:00:00Z",
        )
        await store.commit_service_claim_fence(initial, fence)
        fenced = await store.read_service_claim_release_state(invocation)
        assert fenced.root_bundle is not None
        assert fenced.progress is not None
        assert fenced.chain_head is not None
        assert fenced.head_evidence is not None
        middle_event = EvidenceEvent(
            schema_version="controlgraph.evidence-event/v1",
            evidence_id="evidence-between-fence-and-classification",
            sequence=fenced.chain_head.value.sequence + 1,
            root_id=fenced.root_bundle.root.value.root_id,
            root_sha256=fenced.root_bundle.root.value.root_sha256,
            target=store.target,
            epoch=fenced.progress.value.fenced_epoch,
            kind=EvidenceKind.TARGET_VERIFIED,
            actor=(
                f"controlgraph-verifier@{store.target.project_id}.iam.gserviceaccount.com"
            ),
            request_id="request-between-fence-and-classification",
            receipt_id=None,
            occurred_at="2026-08-20T15:00:01Z",
            subject_sha256="e" * 64,
            previous_event_sha256=canonical_sha256(fenced.head_evidence.value),
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256="f" * 64,
        )
        middle_evidence = _signed_event(middle_event, key, b"interleaved-evidence")
        middle_sha256 = canonical_sha256(middle_evidence)
        middle_head = EvidenceChainHeadV1(
            schema_version=EVIDENCE_CHAIN_HEAD_V1,
            root_id=middle_event.root_id,
            root_sha256=middle_event.root_sha256,
            target=middle_event.target,
            sequence=middle_event.sequence,
            evidence_id=middle_event.evidence_id,
            evidence_sha256=middle_sha256,
            kind=middle_event.kind,
            epoch=middle_event.epoch,
            updated_at=middle_event.occurred_at,
        )
        middle_document_id = signed_evidence_event_document_id(middle_event.evidence_id)
        middle_document = _prepared_document(
            kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            logical_id=middle_event.evidence_id,
            document_id=middle_document_id,
            revision=0,
            value=middle_evidence,
        )
        head_document_id = evidence_chain_head_document_id(middle_event.root_id)
        head_document = _prepared_document(
            kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
            logical_id=middle_event.root_id,
            document_id=head_document_id,
            revision=middle_head.sequence,
            value=middle_head,
        )
        middle_path = (
            f"{AuthorityStorageKind.SIGNED_EVIDENCE_EVENT.value}/{middle_document_id}"
        )
        client.clock += timedelta(microseconds=1)
        client.documents[middle_path] = _StoredDocument(
            _document_data(middle_document.wrapper),
            client.clock,
        )
        client.clock += timedelta(microseconds=1)
        client.documents[
            f"{AuthorityStorageKind.EVIDENCE_CHAIN_HEAD.value}/{head_document_id}"
        ] = _StoredDocument(_document_data(head_document.wrapper), client.clock)

        interleaved = await store.read_service_claim_release_state(invocation)
        assert interleaved.head_evidence is not None
        assert interleaved.head_evidence.value == middle_evidence
        assert interleaved.fence_evidence is not None
        assert interleaved.head_evidence != interleaved.fence_evidence
        assert interleaved.progress is not None
        finalize = await releaser._build_finalize_commit(
            interleaved,
            interleaved.progress.value,
            request_sha256=request_sha256,
        )
        _validate_service_claim_finalize_commit(store.target, interleaved, finalize)
        assert finalize.classification_evidence.event.sequence == middle_event.sequence + 1
        assert (
            finalize.classification_evidence.event.previous_event_sha256
            == middle_sha256
        )

        original_middle = client.documents[middle_path]
        substituted_middle = middle_evidence.model_copy(
            update={"signature": encode_base64url(b"substituted-interleaved-evidence")}
        )
        substituted_document = _prepared_document(
            kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            logical_id=middle_event.evidence_id,
            document_id=middle_document_id,
            revision=0,
            value=substituted_middle,
        )
        client.documents[middle_path] = _StoredDocument(
            _document_data(substituted_document.wrapper),
            original_middle.update_time,
        )
        with pytest.raises(AuthorityStoreConflict):
            await store.commit_service_claim_release(interleaved, finalize)

        client.documents[middle_path] = original_middle
        await store.commit_service_claim_release(interleaved, finalize)
        released = await store.read_service_claim_release_state(invocation)
        assert released.root_bundle is not None
        assert released.root_bundle.service_claim.value.status is ServiceClaimStatus.RELEASED
        assert released.result is not None
        assert released.chain_head is not None
        assert released.chain_head.value.sequence == middle_event.sequence + 2

    asyncio.run(scenario())


def test_firestore_separate_instances_have_one_fence_and_finalize_winner() -> None:
    async def scenario() -> None:
        first, second, _ = await _created_firestore_release_stores()
        invocation = _invocation()
        initial = await first.read_service_claim_release_state(invocation)
        key = make_root_v2_records().root.content.evidence_signing_key_version
        first_releaser = _firestore_releaser(
            first,
            evidence=_EvidenceClient(key, b"coordinator-instance-a"),
            classification=_ClassificationClient(key, b"verifier-instance-a"),
        )
        second_releaser = _firestore_releaser(
            second,
            evidence=_EvidenceClient(key, b"coordinator-instance-b"),
            classification=_ClassificationClient(key, b"verifier-instance-b"),
        )
        request_sha256 = service_claim_release_request_sha256(invocation)
        first_fence = await first_releaser._build_fence_commit(
            initial,
            request_sha256=request_sha256,
            fenced_at="2026-08-20T15:00:00Z",
        )
        second_fence = await second_releaser._build_fence_commit(
            initial,
            request_sha256=request_sha256,
            fenced_at="2026-08-20T15:00:00Z",
        )
        fence_outcomes = await asyncio.gather(
            first.commit_service_claim_fence(initial, first_fence),
            second.commit_service_claim_fence(initial, second_fence),
            return_exceptions=True,
        )
        assert sum(type(outcome) is ServiceClaimFenceWriteResult for outcome in fence_outcomes) == 1
        assert sum(isinstance(outcome, AuthorityStoreConflict) for outcome in fence_outcomes) == 1

        fenced = await first.read_service_claim_release_state(invocation)
        assert fenced.progress is not None
        first_finalize = await first_releaser._build_finalize_commit(
            fenced,
            fenced.progress.value,
            request_sha256=request_sha256,
        )
        second_finalize = await second_releaser._build_finalize_commit(
            fenced,
            fenced.progress.value,
            request_sha256=request_sha256,
        )
        finalize_outcomes = await asyncio.gather(
            first.commit_service_claim_release(fenced, first_finalize),
            second.commit_service_claim_release(fenced, second_finalize),
            return_exceptions=True,
        )
        assert (
            sum(type(outcome) is ServiceClaimFinalizeWriteResult for outcome in finalize_outcomes)
            == 1
        )
        assert (
            sum(isinstance(outcome, AuthorityStoreConflict) for outcome in finalize_outcomes) == 1
        )

        released = await first.read_service_claim_release_state(invocation)
        assert released.root_bundle is not None
        assert released.root_bundle.service_claim.value.status is ServiceClaimStatus.RELEASED
        assert released.result is not None
        winning_results = {
            first_finalize.result,
            second_finalize.result,
        }
        assert released.result.value in winning_results
        assert released.chain_head is not None
        assert released.chain_head.value.sequence == 4

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "classification_error",
    [
        RuntimeError("classification failed"),
        TimeoutError("classification outcome is ambiguous"),
    ],
)
def test_firestore_classification_failure_retains_the_exact_fence(
    classification_error: BaseException,
) -> None:
    async def scenario() -> None:
        store, _, _ = await _created_firestore_release_stores()
        invocation = _invocation()
        key = make_root_v2_records().root.content.evidence_signing_key_version
        classification = _ClassificationClient(key)
        classification.error = classification_error
        releaser = _firestore_releaser(store, classification=classification)

        with pytest.raises(ServiceClaimReleaseError) as failure:
            await releaser.release(invocation, principal=_principal())

        assert failure.value.code is ServiceClaimReleaseFailureCode.CLASSIFICATION_DENIED
        retained = await store.read_service_claim_release_state(invocation)
        assert retained.root_bundle is not None
        assert retained.root_bundle.service_claim.value.status is ServiceClaimStatus.RELEASING
        assert retained.progress is not None
        assert retained.fence_evidence is not None
        assert retained.chain_head is not None
        assert retained.chain_head.value.evidence_id == (retained.progress.value.fence_evidence_id)
        assert retained.classification_evidence is None
        assert retained.release_evidence is None
        assert retained.result is None
        exact_claim = retained.root_bundle.service_claim
        exact_authority = retained.root_bundle.authority
        exact_progress = retained.progress
        exact_head = retained.chain_head

        competing = invocation.model_copy(
            update={
                "command": invocation.command.model_copy(
                    update={
                        "request_id": "request-release-competing",
                        "idempotency_key": "release-competing",
                    }
                ),
                "attempt_id": "release-attempt-competing",
            }
        )
        with pytest.raises(ServiceClaimReleaseError) as competing_failure:
            await _firestore_releaser(store).release(
                competing,
                principal=_principal(),
            )

        assert competing_failure.value.code is ServiceClaimReleaseFailureCode.CLAIM_NOT_ACTIVE
        after = await store.read_service_claim_release_state(invocation)
        assert after.root_bundle is not None
        assert after.root_bundle.service_claim == exact_claim
        assert after.root_bundle.authority == exact_authority
        assert after.progress == exact_progress
        assert after.chain_head == exact_head
        assert after.result is None

    asyncio.run(scenario())
