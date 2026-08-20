from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from root_v2_test_data import PROJECT_NUMBER, make_root_v2_records, root_v2_target
from test_final_authority_execution import _lease
from test_m2_firestore_authority_store import (
    _FakeClient,
    _FakeTransactionRunner,
    _StoredDocument,
)

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    StoredRecord,
)
from controlgraph_canary.application.capability_issuance import (
    AuthenticatedIssuancePrincipal,
    CapabilityIssuanceError,
    CapabilityIssuanceErrorCode,
    CapabilityIssuanceRequest,
    CapabilityIssuer,
    CapabilityIssuerConfiguration,
)
from controlgraph_canary.application.capability_verification import VerifiedMutation
from controlgraph_canary.application.evidence_chain import current_evidence_chain_head
from controlgraph_canary.application.execution import (
    FinalAuthorityDenial,
    FinalMutationGate,
    MutationPermit,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.revocation import EpochRevocationError, EpochRevoker
from controlgraph_canary.application.signing import PurposeSealedSigner, SigningProfile
from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.evidence import (
    EVIDENCE_CHAIN_HEAD_V1,
    EvidenceChainHeadV1,
)
from controlgraph_canary.contracts.models import (
    EvidenceEvent,
    EvidenceKind,
    MutationIntent,
    ReasonCode,
    TaskRequest,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_COMMAND_V1,
    EPOCH_REVOCATION_INVOCATION_V1,
    EpochRevocationAuditOutcome,
    EpochRevocationCommandV1,
    EpochRevocationFailureCode,
    EpochRevocationInvocationV1,
)
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    SignedEvidenceEventV1,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)
from controlgraph_canary.contracts.storage import (
    AuthorityStorageKind,
    evidence_chain_head_document_id,
    signed_evidence_event_document_id,
)
from controlgraph_canary.integrations.google.firestore import (
    FirestoreAuthorityStore,
    _document_data,
    _prepared_document,
)

NOW = datetime(2026, 8, 19, 12, 5, tzinfo=UTC)
OPERATOR = "operator@example.test"
OPERATOR_SUBJECT = "123456789012345678901"
API_AUDIENCE = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"


class _EvidenceClient:
    def __init__(self, key_version: str) -> None:
        self.key_version = key_version
        self.calls: list[EvidenceEvent] = []
        self.on_sign: object | None = None

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1:
        self.calls.append(event)
        if callable(self.on_sign):
            self.on_sign()
        return SignedEvidenceEventV1(
            schema_version=SIGNED_EVIDENCE_EVENT_V1,
            event=event,
            purpose="EVIDENCE",
            signing_key_version=self.key_version,
            signing_algorithm="EC_SIGN_P256_SHA256",
            payload_sha256=evidence_payload_sha256(event),
            signing_input_sha256=evidence_signing_input_sha256(
                event,
                self.key_version,
            ),
            signature=encode_base64url(b"synthetic-revocation-signature"),
        )


class _ConcurrentEvidenceClient(_EvidenceClient):
    def __init__(self, key_version: str) -> None:
        super().__init__(key_version)
        self.both_started = asyncio.Event()

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1:
        self.calls.append(event)
        if len(self.calls) == 2:
            self.both_started.set()
        await self.both_started.wait()
        return SignedEvidenceEventV1(
            schema_version=SIGNED_EVIDENCE_EVENT_V1,
            event=event,
            purpose="EVIDENCE",
            signing_key_version=self.key_version,
            signing_algorithm="EC_SIGN_P256_SHA256",
            payload_sha256=evidence_payload_sha256(event),
            signing_input_sha256=evidence_signing_input_sha256(
                event,
                self.key_version,
            ),
            signature=encode_base64url(b"synthetic-revocation-signature"),
        )


class _AuditConflictStore:
    def __init__(self, delegate: FirestoreAuthorityStore) -> None:
        self._delegate = delegate

    @property
    def target(self) -> object:
        return self._delegate.target

    async def read_epoch_revocation_state(self, invocation: object) -> object:
        return await self._delegate.read_epoch_revocation_state(invocation)  # type: ignore[arg-type]

    async def commit_epoch_revocation(
        self,
        expected: object,
        commit: object,
    ) -> object:
        return await self._delegate.commit_epoch_revocation(expected, commit)  # type: ignore[arg-type]

    async def record_epoch_revocation_audit(self, audit: object) -> object:
        del audit
        raise AuthorityStoreConflict


class _CapabilitySigningBackend:
    def __init__(self, profile: SigningProfile) -> None:
        self._profile = profile
        self.digests: list[bytes] = []

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    def sign_digest(self, digest: bytes) -> bytes:
        self.digests.append(digest)
        return b"synthetic-capability-signature"


class _NoMutationAdapter:
    def __init__(self) -> None:
        self.target = root_v2_target()
        self.service_role = ServiceRole.EXECUTOR
        self.calls: list[MutationPermit] = []

    async def mutate(self, permit: MutationPermit) -> str:
        self.calls.append(permit)
        return "unexpected"


def _store() -> tuple[FirestoreAuthorityStore, _FakeClient, _FakeTransactionRunner]:
    client = _FakeClient()
    runner = _FakeTransactionRunner()
    target = root_v2_target()
    store = FirestoreAuthorityStore.for_test(
        target=target,
        configured_project_id=target.project_id,
        client_factory=lambda: client,
        transaction_runner=runner,
    )
    return store, client, runner


def _policy() -> RouteAuthenticationPolicy:
    target = root_v2_target()
    return RouteAuthenticationPolicy(
        project_id=target.project_id,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.API,
        path=protected_path(ServiceRole.API),
        audience=API_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.OPERATOR,
            email=OPERATOR,
            subject=OPERATOR_SUBJECT,
        ),
    )


def _principal() -> AuthenticationContext:
    current = int(NOW.timestamp())
    return AuthenticationContext(
        role=CallerRole.OPERATOR,
        email=OPERATOR,
        subject=OPERATOR_SUBJECT,
        issuer="https://accounts.google.com",
        audience=API_AUDIENCE,
        issued_at=current - 60,
        expires_at=current + 600,
    )


def _invocation(
    *,
    root_id: str,
    root_sha256: str,
    expected_epoch: int = 1,
    request_id: str = "request-revoke-001",
    idempotency_key: str = "revoke-001",
    reason: str = "Stop the canary before delayed work executes.",
    attempt_id: str = "cgrevoke-attempt-001",
) -> EpochRevocationInvocationV1:
    principal = _principal()
    return EpochRevocationInvocationV1(
        schema_version=EPOCH_REVOCATION_INVOCATION_V1,
        command=EpochRevocationCommandV1(
            schema_version=EPOCH_REVOCATION_COMMAND_V1,
            root_id=root_id,
            expected_root_sha256=root_sha256,
            expected_epoch=expected_epoch,
            reason=reason,
            request_id=request_id,
            idempotency_key=idempotency_key,
            confirmation="REVOKE",
        ),
        attempt_id=attempt_id,
        operator_identity=principal.email,
        operator_subject=principal.subject,
        operator_issuer="https://accounts.google.com",
        operator_audience=principal.audience,
        operator_issued_at=principal.issued_at,
        operator_expires_at=principal.expires_at,
    )


async def _created_store() -> tuple[
    FirestoreAuthorityStore,
    _FakeClient,
    _FakeTransactionRunner,
    object,
]:
    store, client, runner = _store()
    records = make_root_v2_records()
    await store.create_or_adopt_root_creation_bundle(
        records.root,
        records.service_claim,
        records.authority,
        records.lineage_anchor,
        records.signed_evidence,
        records.creation_result,
    )
    return store, client, runner, records


def test_revocation_commits_authority_evidence_head_result_identities_and_audit() -> None:
    async def scenario() -> None:
        store, client, runner, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        invocation = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
        )

        result = await revoker.revoke(invocation, principal=_principal())
        state = await store.read_epoch_revocation_state(invocation)

        assert result.previous_epoch == 1
        assert result.new_epoch == 2
        assert len(evidence.calls) == 1
        assert evidence.calls[0].kind is EvidenceKind.EPOCH_ADVANCED
        assert evidence.calls[0].sequence == 1
        assert evidence.calls[0].previous_event_sha256 == canonical_sha256(
            records.signed_evidence
        )
        assert state.root_bundle is not None
        assert state.root_bundle.root == StoredRecord(records.root, 0)
        assert state.root_bundle.service_claim == StoredRecord(records.service_claim, 0)
        assert state.root_bundle.authority.value.current_epoch == 2
        assert state.chain_head is not None
        assert state.chain_head.value.sequence == 1
        assert state.result is not None and state.result.value == result
        assert state.request_identity is not None
        assert state.idempotency_identity is not None
        assert state.attempt_audit is not None
        assert state.attempt_audit.value.outcome is EpochRevocationAuditOutcome.COMMITTED
        assert runner.write_result_counts[-2:] == [7, 0]
        assert len(client.documents) == 12

    asyncio.run(scenario())


def test_exact_replay_returns_result_before_epoch_check_and_does_not_sign_again() -> None:
    async def scenario() -> None:
        store, client, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        first = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            attempt_id="cgrevoke-attempt-first",
        )
        replay = EpochRevocationInvocationV1.model_validate(
            {
                **first.model_dump(mode="python"),
                "attempt_id": "cgrevoke-attempt-replay",
            }
        )

        committed = await revoker.revoke(first, principal=_principal())
        adopted = await revoker.revoke(replay, principal=_principal())

        assert adopted == committed
        assert len(evidence.calls) == 1
        audits = [
            document.data["canonical_payload"]
            for path, document in client.documents.items()
            if path.startswith(f"{AuthorityStorageKind.EPOCH_REVOCATION_AUDIT.value}/")
        ]
        assert len(audits) == 2
        assert any(EpochRevocationAuditOutcome.ADOPTED.value in audit for audit in audits)

    asyncio.run(scenario())


def test_concurrent_exact_requests_have_one_epoch_advance_and_one_signature() -> None:
    async def scenario() -> None:
        store, _, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        first = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            attempt_id="cgrevoke-attempt-concurrent-a",
        )
        second = EpochRevocationInvocationV1.model_validate(
            {
                **first.model_dump(mode="python"),
                "attempt_id": "cgrevoke-attempt-concurrent-b",
            }
        )

        outcomes = await asyncio.gather(
            revoker.revoke(first, principal=_principal()),
            revoker.revoke(second, principal=_principal()),
        )

        assert outcomes[0] == outcomes[1]
        assert outcomes[0].new_epoch == 2
        assert len(evidence.calls) == 1

    asyncio.run(scenario())


def test_two_coordinator_instances_resolve_one_firestore_winner() -> None:
    async def scenario() -> None:
        store, _, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _ConcurrentEvidenceClient(
            records.root.content.evidence_signing_key_version
        )
        first_revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        second_revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        first = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            attempt_id="cgrevoke-attempt-instance-a",
        )
        second = EpochRevocationInvocationV1.model_validate(
            {
                **first.model_dump(mode="python"),
                "attempt_id": "cgrevoke-attempt-instance-b",
            }
        )

        outcomes = await asyncio.wait_for(
            asyncio.gather(
                first_revoker.revoke(first, principal=_principal()),
                second_revoker.revoke(second, principal=_principal()),
            ),
            timeout=2,
        )
        first_state = await store.read_epoch_revocation_state(first)
        second_state = await store.read_epoch_revocation_state(second)

        assert outcomes[0] == outcomes[1]
        assert outcomes[0].new_epoch == 2
        assert len(evidence.calls) == 2
        assert first_state.root_bundle is not None
        assert first_state.root_bundle.authority.value.current_epoch == 2
        audits = {
            first_state.attempt_audit.value.outcome,
            second_state.attempt_audit.value.outcome,
        }
        assert audits == {
            EpochRevocationAuditOutcome.COMMITTED,
            EpochRevocationAuditOutcome.ADOPTED,
        }

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("changed", "expected"),
    [
        ({}, EpochRevocationFailureCode.EPOCH_MISMATCH),
        ({"reason": "Different work."}, EpochRevocationFailureCode.IDENTITY_CONFLICT),
    ],
)
def test_stale_and_identity_conflicting_requests_are_audited(
    changed: dict[str, object],
    expected: EpochRevocationFailureCode,
) -> None:
    async def scenario() -> None:
        store, client, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        original = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            attempt_id="cgrevoke-attempt-original",
        )
        await revoker.revoke(original, principal=_principal())
        command_values = {
            **original.command.model_dump(mode="python"),
            "request_id": "request-revoke-conflict",
            "idempotency_key": (
                original.command.idempotency_key
                if "reason" in changed
                else "revoke-conflict"
            ),
            **changed,
        }
        conflicting = EpochRevocationInvocationV1.model_validate(
            {
                **original.model_dump(mode="python"),
                "attempt_id": "cgrevoke-attempt-conflict",
                "command": command_values,
            }
        )

        with pytest.raises(EpochRevocationError) as captured:
            await revoker.revoke(conflicting, principal=_principal())

        assert captured.value.code is expected
        audits = [
            document.data["canonical_payload"]
            for path, document in client.documents.items()
            if path.startswith(f"{AuthorityStorageKind.EPOCH_REVOCATION_AUDIT.value}/")
        ]
        assert any(expected.value in audit for audit in audits)

    asyncio.run(scenario())


def test_authenticated_relay_denial_is_durably_audited_without_mutation() -> None:
    async def scenario() -> None:
        store, _, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        invocation = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            attempt_id="cgrevoke-attempt-relay-denial",
        )
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )

        await revoker.record_authenticated_denial(
            invocation,
            code=EpochRevocationFailureCode.CALLER_DENIED,
        )
        state = await store.read_epoch_revocation_state(invocation)

        assert state.attempt_audit is not None
        assert state.attempt_audit.value.outcome is EpochRevocationAuditOutcome.DENIED
        assert (
            state.attempt_audit.value.failure_code
            is EpochRevocationFailureCode.CALLER_DENIED
        )
        assert state.root_bundle is not None
        assert state.root_bundle.authority.value.current_epoch == 1
        assert evidence.calls == []

    asyncio.run(scenario())


def test_missing_chain_head_after_an_advance_fails_closed_and_is_audited() -> None:
    async def scenario() -> None:
        store, client, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        first = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
        )
        await revoker.revoke(first, principal=_principal())
        head_path = (
            f"{AuthorityStorageKind.EVIDENCE_CHAIN_HEAD.value}/"
            f"{evidence_chain_head_document_id(records.root.root_id)}"
        )
        del client.documents[head_path]
        second = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            expected_epoch=2,
            request_id="request-revoke-002",
            idempotency_key="revoke-002",
            attempt_id="cgrevoke-attempt-002",
        )

        with pytest.raises(EpochRevocationError) as captured:
            await revoker.revoke(second, principal=_principal())

        assert captured.value.code is EpochRevocationFailureCode.TRUSTED_STATE_INVALID
        assert len(evidence.calls) == 1

    asyncio.run(scenario())


def test_ambiguous_complete_commit_is_resolved_as_the_exact_result() -> None:
    async def scenario() -> None:
        store, _, runner, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        evidence.on_sign = lambda: setattr(runner, "mode", "commit-then-timeout")

        result = await revoker.revoke(
            _invocation(
                root_id=records.root.root_id,
                root_sha256=records.root.root_sha256,
            ),
            principal=_principal(),
        )

        assert result.new_epoch == 2
        assert len(evidence.calls) == 1

    asyncio.run(scenario())


def test_ambiguous_partial_commit_without_atomic_audit_fails_closed() -> None:
    async def scenario() -> None:
        store, _, runner, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        evidence.on_sign = lambda: setattr(
            runner,
            "mode",
            "commit-first-only-then-timeout",
        )

        with pytest.raises(EpochRevocationError) as captured:
            await revoker.revoke(
                _invocation(
                    root_id=records.root.root_id,
                    root_sha256=records.root.root_sha256,
                ),
                principal=_principal(),
            )

        assert captured.value.code is EpochRevocationFailureCode.OUTCOME_UNKNOWN
        assert len(evidence.calls) == 1

    asyncio.run(scenario())


def test_historical_exact_result_requires_its_durable_signed_evidence() -> None:
    async def scenario() -> None:
        store, client, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        first = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            attempt_id="cgrevoke-attempt-history-first",
        )
        first_result = await revoker.revoke(first, principal=_principal())
        second = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            expected_epoch=2,
            request_id="request-revoke-history-second",
            idempotency_key="revoke-history-second",
            attempt_id="cgrevoke-attempt-history-second",
        )
        await revoker.revoke(second, principal=_principal())
        replay = EpochRevocationInvocationV1.model_validate(
            {
                **first.model_dump(mode="python"),
                "attempt_id": "cgrevoke-attempt-history-replay",
            }
        )
        evidence_path = (
            f"{AuthorityStorageKind.SIGNED_EVIDENCE_EVENT.value}/"
            f"{signed_evidence_event_document_id(first_result.evidence_id)}"
        )
        del client.documents[evidence_path]

        with pytest.raises(EpochRevocationError) as captured:
            await revoker.revoke(replay, principal=_principal())

        assert captured.value.code is EpochRevocationFailureCode.TRUSTED_STATE_INVALID

    asyncio.run(scenario())


def test_predecessor_evidence_deletion_between_read_and_commit_blocks_advance() -> None:
    async def scenario() -> None:
        store, client, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        root_evidence_path = (
            f"{AuthorityStorageKind.SIGNED_EVIDENCE_EVENT.value}/"
            f"{signed_evidence_event_document_id(records.signed_evidence.event.evidence_id)}"
        )
        evidence.on_sign = lambda: client.documents.pop(root_evidence_path)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )

        with pytest.raises(EpochRevocationError) as captured:
            await revoker.revoke(
                _invocation(
                    root_id=records.root.root_id,
                    root_sha256=records.root.root_sha256,
                ),
                principal=_principal(),
            )

        assert captured.value.code is EpochRevocationFailureCode.TRUSTED_STATE_INVALID
        assert len(evidence.calls) == 1

    asyncio.run(scenario())


def test_audit_identity_collision_is_not_silently_adopted() -> None:
    async def scenario() -> None:
        store, _, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )
        committed = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            attempt_id="cgrevoke-attempt-audit-winner",
        )
        await revoker.revoke(committed, principal=_principal())
        replay = EpochRevocationInvocationV1.model_validate(
            {
                **committed.model_dump(mode="python"),
                "attempt_id": "cgrevoke-attempt-audit-collision",
            }
        )
        conflicting_revoker = EpochRevoker(
            store=_AuditConflictStore(store),  # type: ignore[arg-type]
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        )

        with pytest.raises(EpochRevocationError) as captured:
            await conflicting_revoker.revoke(replay, principal=_principal())

        assert captured.value.code is EpochRevocationFailureCode.TRUSTED_STATE_INVALID

    asyncio.run(scenario())


def test_revocation_appends_after_a_non_authority_evidence_event() -> None:
    async def scenario() -> None:
        store, client, _, untyped_records = await _created_store()
        records = untyped_records
        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        first = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
        )
        await EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        ).revoke(first, principal=_principal())
        state = await store.read_epoch_revocation_state(first)
        assert state.root_bundle is not None
        assert state.chain_head is not None
        assert state.head_evidence is not None
        predecessor = state.head_evidence.value
        middle_event = EvidenceEvent(
            schema_version="controlgraph.evidence-event/v1",
            evidence_id="evidence-target-verified-between-revocations",
            sequence=state.chain_head.value.sequence + 1,
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            target=records.root.content.target,
            epoch=2,
            kind=EvidenceKind.TARGET_VERIFIED,
            actor=(
                "controlgraph-verifier@"
                f"{records.root.content.target.project_id}.iam.gserviceaccount.com"
            ),
            request_id="request-target-verified-between-revocations",
            receipt_id=None,
            occurred_at="2026-08-19T12:05:01Z",
            subject_sha256="e" * 64,
            previous_event_sha256=canonical_sha256(predecessor),
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256="f" * 64,
        )
        middle_evidence = await evidence.sign(middle_event)
        middle_head = EvidenceChainHeadV1(
            schema_version=EVIDENCE_CHAIN_HEAD_V1,
            root_id=middle_event.root_id,
            root_sha256=middle_event.root_sha256,
            target=middle_event.target,
            sequence=middle_event.sequence,
            evidence_id=middle_event.evidence_id,
            evidence_sha256=canonical_sha256(middle_evidence),
            kind=middle_event.kind,
            epoch=middle_event.epoch,
            updated_at=middle_event.occurred_at,
        )
        assert current_evidence_chain_head(
            state.root_bundle,
            target=records.root.content.target,
            stored_head=StoredRecord(middle_head, middle_head.sequence),
            head_evidence=StoredRecord(middle_evidence, 0),
        ) == middle_head
        evidence_document_id = signed_evidence_event_document_id(
            middle_event.evidence_id
        )
        evidence_document = _prepared_document(
            kind=AuthorityStorageKind.SIGNED_EVIDENCE_EVENT,
            logical_id=middle_event.evidence_id,
            document_id=evidence_document_id,
            revision=0,
            value=middle_evidence,
        )
        head_document_id = evidence_chain_head_document_id(records.root.root_id)
        head_document = _prepared_document(
            kind=AuthorityStorageKind.EVIDENCE_CHAIN_HEAD,
            logical_id=records.root.root_id,
            document_id=head_document_id,
            revision=middle_head.sequence,
            value=middle_head,
        )
        client.clock += timedelta(microseconds=1)
        client.documents[
            f"{AuthorityStorageKind.SIGNED_EVIDENCE_EVENT.value}/{evidence_document_id}"
        ] = _StoredDocument(_document_data(evidence_document.wrapper), client.clock)
        client.clock += timedelta(microseconds=1)
        client.documents[
            f"{AuthorityStorageKind.EVIDENCE_CHAIN_HEAD.value}/{head_document_id}"
        ] = _StoredDocument(_document_data(head_document.wrapper), client.clock)
        second = _invocation(
            root_id=records.root.root_id,
            root_sha256=records.root.root_sha256,
            expected_epoch=2,
            request_id="request-revoke-after-target-proof",
            idempotency_key="revoke-after-target-proof",
            attempt_id="cgrevoke-attempt-after-target-proof",
        )

        result = await EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW + timedelta(minutes=1),
        ).revoke(second, principal=_principal())

        assert result.new_epoch == 3
        assert evidence.calls[-1].sequence == middle_event.sequence + 1
        assert evidence.calls[-1].previous_event_sha256 == canonical_sha256(
            middle_evidence
        )

    asyncio.run(scenario())


def test_committed_revocation_fences_issuance_and_delayed_execution() -> None:
    async def scenario() -> None:
        store, _, _, untyped_records = await _created_store()
        records = untyped_records
        capability_backend = _CapabilitySigningBackend(
            SigningProfile.capability(
                records.root.content.target.project_id,
                records.root.content.authority_bounds.capability_signing_key_version,
            )
        )
        capability_issuer = CapabilityIssuer(
            store=store,
            signer=PurposeSealedSigner(capability_backend),
            configuration=CapabilityIssuerConfiguration(
                target=records.root.content.target,
                handler_audience=(
                    records.root.content.authority_bounds.executor_audience
                ),
            ),
        )
        issuance_request = CapabilityIssuanceRequest(
            root_id=records.root.root_id,
            expected_root_sha256=records.root.root_sha256,
            expected_epoch=1,
            request_id="request-issue-before-revocation",
            idempotency_key="issue-before-revocation",
        )
        issuance_principal = AuthenticatedIssuancePrincipal(
            identity=(
                "controlgraph-coordinator@"
                f"{records.root.content.target.project_id}.iam.gserviceaccount.com"
            )
        )
        issue_time = datetime(2026, 8, 19, 12, 2, tzinfo=UTC)
        capability = await capability_issuer.issue(
            issuance_request,
            principal=issuance_principal,
            now=issue_time,
        )
        claims = capability.claims
        intent = MutationIntent(
            schema_version="controlgraph.mutation-intent/v1",
            request_id=claims.request_id,
            idempotency_key=claims.idempotency_key,
            target=claims.target,
            root_id=claims.root_id,
            root_sha256=claims.root_sha256,
            epoch=claims.epoch,
            action=claims.action,
            stable_revision=claims.stable_revision,
            candidate_revision=claims.candidate_revision,
            stable_percent=claims.stable_percent,
            candidate_percent=claims.candidate_percent,
            concurrency=claims.concurrency,
            plan_sha256=claims.plan_sha256,
            provider_etag=claims.provider_etag,
        )
        task = TaskRequest(
            schema_version="controlgraph.task-request/v1",
            task_id="task-delayed-before-revocation",
            queue_region=claims.target.region,
            handler_audience=claims.audience,
            scheduled_at=claims.not_before,
            expires_at=claims.expires_at,
            capability=capability,
            intent=intent,
        )
        verified = VerifiedMutation(
            request=task,
            root=records.root,
            lineage_anchor=records.lineage_anchor,
            caller=AuthenticationContext(
                role=CallerRole.EXECUTION_TASK_CALLER,
                email=(
                    "cg-execution-task-caller@"
                    f"{claims.target.project_id}.iam.gserviceaccount.com"
                ),
                subject="234567890123456789012",
                issuer="https://accounts.google.com",
                audience=claims.audience,
                issued_at=int(issue_time.timestamp()),
                expires_at=int(issue_time.timestamp()) + 600,
            ),
            capability_sha256=canonical_sha256(capability),
            claims_sha256=capability.claims_sha256,
            earliest_lineage_issued_at=int(issue_time.timestamp()),
        )

        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        await EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_policy(),
            clock=lambda: NOW,
        ).revoke(
            _invocation(
                root_id=records.root.root_id,
                root_sha256=records.root.root_sha256,
            ),
            principal=_principal(),
        )

        with pytest.raises(CapabilityIssuanceError) as captured:
            await capability_issuer.issue(
                issuance_request,
                principal=issuance_principal,
                now=NOW,
            )

        adapter = _NoMutationAdapter()
        execution = await FinalMutationGate(
            authority_reader=store,
            adapter=adapter,
            clock=lambda: NOW,
        ).execute(_lease(verified), verified)

        assert captured.value.code is CapabilityIssuanceErrorCode.EXPECTED_STATE_MISMATCH
        assert len(capability_backend.digests) == 1
        assert isinstance(execution, FinalAuthorityDenial)
        assert execution.reason_code is ReasonCode.EPOCH_MISMATCH
        assert execution.observed_authority_epoch == 2
        assert adapter.calls == []

    asyncio.run(scenario())
