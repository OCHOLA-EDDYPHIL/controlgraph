from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from test_root_creation_application import (
    _candidate,
    _command,
    _configuration,
    _signed,
    _snapshot,
    _unsigned,
)

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreOutcomeUnknown,
    RootCreationBundle,
    RootCreationWriteResult,
    StoredRecord,
)
from controlgraph_canary.application.identity import AuthenticationContext, CallerRole
from controlgraph_canary.application.root_creation import (
    RootCreationArtifacts,
    complete_root_creation,
)
from controlgraph_canary.application.root_creation_service import (
    RolloutRootCreator,
    RootCreationError,
    RootCreationErrorCode,
)
from controlgraph_canary.application.root_trust import TrustedRootPreflight
from controlgraph_canary.contracts.codec import encode_base64url
from controlgraph_canary.contracts.models import EvidenceEvent
from controlgraph_canary.contracts.root_creation import (
    RootCreationCommandV1,
    SignedEvidenceEventV1,
)

NOW = datetime(2026, 8, 19, 12, 5, tzinfo=UTC)


class _PreflightClient:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.error: BaseException | None = None

    async def preflight(self, request: object) -> TrustedRootPreflight:
        self.events.append("preflight")
        if self.error is not None:
            raise self.error
        return TrustedRootPreflight(
            stable_snapshot=_snapshot(),
            candidate_revision=_candidate(),
        )


class _EvidenceClient:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.error: BaseException | None = None
        self.substitute = False

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1:
        self.events.append("evidence")
        if self.error is not None:
            raise self.error
        unsigned = _unsigned(
            command=_command(request_id="request-root-substituted")
            if self.substitute
            else _command()
        )
        if not self.substitute:
            unsigned = replace(unsigned, evidence_event=event)
        return _signed(unsigned)


class _Store:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.target = _configuration().target
        self.claim: StoredRecord | None = None
        self.bundle: RootCreationBundle | None = None
        self.write_error: BaseException | None = None
        self.conflict_bundle: RootCreationBundle | None = None
        self.attempted_creation_result: object | None = None
        self.expected_released_claim: StoredRecord | None = None

    async def read_service_claim(self) -> StoredRecord | None:
        self.events.append("read-claim")
        return self.claim

    async def read_root_creation_bundle(self, root_id: str) -> RootCreationBundle | None:
        self.events.append("read-bundle")
        if self.bundle is None or self.bundle.root.value.root_id != root_id:
            return None
        return self.bundle

    async def create_or_adopt_root_creation_bundle(
        self,
        root: object,
        service_claim: object,
        authority: object,
        lineage_anchor: object,
        signed_evidence: object,
        creation_result: object,
        *,
        expected_released_claim: StoredRecord | None = None,
    ) -> RootCreationWriteResult:
        self.events.append("write")
        self.expected_released_claim = expected_released_claim
        self.attempted_creation_result = creation_result
        if self.write_error is not None:
            if self.conflict_bundle is not None:
                self.bundle = self.conflict_bundle
                self.claim = self.conflict_bundle.service_claim
            raise self.write_error
        artifacts = RootCreationArtifacts(
            root=root,
            service_claim=service_claim,
            initial_authority=authority,
            lineage_anchor=lineage_anchor,
            signed_evidence=signed_evidence,
            creation_result=creation_result,
        )
        self.bundle = _bundle(artifacts)
        self.claim = self.bundle.service_claim
        return RootCreationWriteResult(
            result=artifacts.creation_result,
            bundle=self.bundle,
        )


def _bundle(artifacts: RootCreationArtifacts) -> RootCreationBundle:
    return RootCreationBundle(
        root=StoredRecord(artifacts.root, 0),
        service_claim=StoredRecord(artifacts.service_claim, 0),
        authority=StoredRecord(artifacts.initial_authority, 0),
        lineage_anchor=StoredRecord(artifacts.lineage_anchor, 0),
        signed_evidence=StoredRecord(artifacts.signed_evidence, 0),
        creation_result=StoredRecord(artifacts.creation_result, 0),
    )


def _principal(**changes: object) -> AuthenticationContext:
    values: dict[str, object] = {
        "role": CallerRole.OPERATOR,
        "email": "operator@example.test",
        "subject": "123456789012345678901",
        "issuer": "https://accounts.google.com",
        "audience": "https://controlgraph-api-123456789012.us-central1.run.app",
        "issued_at": int(datetime(2026, 8, 19, 12, 0, tzinfo=UTC).timestamp()),
        "expires_at": int(datetime(2026, 8, 19, 12, 10, tzinfo=UTC).timestamp()),
    }
    values.update(changes)
    return AuthenticationContext(**values)


def _creator(
    events: list[str],
    *,
    now: datetime = NOW,
) -> tuple[RolloutRootCreator, _Store, _PreflightClient, _EvidenceClient]:
    store = _Store(events)
    preflight = _PreflightClient(events)
    evidence = _EvidenceClient(events)
    creator = RolloutRootCreator(
        store=store,
        preflight_client=preflight,
        evidence_client=evidence,
        configuration=_configuration(),
        clock=lambda: now,
    )
    return creator, store, preflight, evidence


def test_authenticated_creation_orders_trust_before_one_atomic_write() -> None:
    async def scenario() -> None:
        events: list[str] = []
        creator, store, _, _ = _creator(events)

        result = await creator.create(_command(), principal=_principal())

        assert result.result.outcome == "CREATED"
        assert result.result.root.content.approved_by == "operator@example.test"
        assert result.result.root.content.rollout_plan.stable_percent == 90
        assert result.result.root.content.rollout_plan.candidate_percent == 10
        assert store.bundle == result.bundle
        assert events == ["read-claim", "preflight", "evidence", "write"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("principal", "code"),
    [
        (None, RootCreationErrorCode.CALLER_UNAUTHENTICATED),
        (
            _principal(email="other.operator@example.test"),
            RootCreationErrorCode.CALLER_UNAUTHORIZED,
        ),
        (
            _principal(role=CallerRole.API),
            RootCreationErrorCode.CALLER_UNAUTHORIZED,
        ),
        (
            _principal(audience="https://controlgraph-api-999999.us-central1.run.app"),
            RootCreationErrorCode.CALLER_UNAUTHORIZED,
        ),
    ],
)
def test_authentication_denies_before_any_trust_or_store_io(
    principal: AuthenticationContext | None,
    code: RootCreationErrorCode,
) -> None:
    async def scenario() -> None:
        events: list[str] = []
        creator, _, _, _ = _creator(events)

        with pytest.raises(RootCreationError) as error:
            await creator.create(_command(), principal=principal)

        assert error.value.code is code
        assert events == []

    asyncio.run(scenario())


def test_exact_active_claim_replay_adopts_without_new_trust_io() -> None:
    async def scenario() -> None:
        events: list[str] = []
        creator, store, _, _ = _creator(events)
        artifacts = complete_root_creation(_unsigned(), _signed())
        store.bundle = _bundle(artifacts)
        store.claim = store.bundle.service_claim

        result = await creator.create(_command(), principal=_principal())

        assert result.result.outcome == "ADOPTED"
        assert result.bundle == store.bundle
        assert events == ["read-claim", "read-bundle"]

    asyncio.run(scenario())


def test_active_claim_with_different_canonical_request_fails_before_preflight() -> None:
    async def scenario() -> None:
        events: list[str] = []
        creator, store, _, _ = _creator(events)
        artifacts = complete_root_creation(_unsigned(), _signed())
        store.bundle = _bundle(artifacts)
        store.claim = store.bundle.service_claim
        command = RootCreationCommandV1.model_validate(
            {**_command().model_dump(mode="python"), "idempotency_key": "other-key"}
        )

        with pytest.raises(RootCreationError) as error:
            await creator.create(command, principal=_principal())

        assert error.value.code is RootCreationErrorCode.ACTIVE_CLAIM_CONFLICT
        assert events == ["read-claim", "read-bundle"]

    asyncio.run(scenario())


def test_preflight_and_evidence_failures_never_reach_the_atomic_write() -> None:
    async def scenario() -> None:
        events: list[str] = []
        creator, _, preflight, _ = _creator(events)
        preflight.error = RuntimeError("provider detail")
        with pytest.raises(RootCreationError) as preflight_error:
            await creator.create(_command(), principal=_principal())
        assert preflight_error.value.code is RootCreationErrorCode.PREFLIGHT_DENIED
        assert events == ["read-claim", "preflight"]

        events.clear()
        creator, _, _, evidence = _creator(events)
        evidence.substitute = True
        with pytest.raises(RootCreationError) as evidence_error:
            await creator.create(_command(), principal=_principal())
        assert evidence_error.value.code is RootCreationErrorCode.EVIDENCE_DENIED
        assert events == ["read-claim", "preflight", "evidence"]

    asyncio.run(scenario())


def test_store_unknown_outcome_stays_explicit_and_cancellation_propagates() -> None:
    async def scenario() -> None:
        events: list[str] = []
        creator, store, _, _ = _creator(events)
        store.write_error = AuthorityStoreOutcomeUnknown()
        with pytest.raises(RootCreationError) as error:
            await creator.create(_command(), principal=_principal())
        assert error.value.code is RootCreationErrorCode.OUTCOME_UNKNOWN

        events.clear()
        creator, _, preflight, _ = _creator(events)
        preflight.error = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await creator.create(_command(), principal=_principal())
        assert events == ["read-claim", "preflight"]

    asyncio.run(scenario())


def test_concurrent_logical_replay_adopts_winner_with_other_time_and_signature() -> None:
    async def scenario() -> None:
        events: list[str] = []
        creator, store, _, _ = _creator(
            events,
            now=datetime(2026, 8, 19, 12, 5, 2, tzinfo=UTC),
        )
        winner_unsigned = _unsigned()
        winner_signed = _signed(winner_unsigned).model_copy(
            update={"signature": encode_base64url(b"winner-p256-signature")}
        )
        winner = complete_root_creation(winner_unsigned, winner_signed)
        store.write_error = AuthorityStoreConflict()
        store.conflict_bundle = _bundle(winner)

        result = await creator.create(_command(), principal=_principal())

        assert result.result.outcome == "ADOPTED"
        assert result.bundle == store.conflict_bundle
        assert result.result.root.content.approved_at == "2026-08-19T12:05:00Z"
        assert store.attempted_creation_result is not None
        assert (
            store.attempted_creation_result.root.content.approved_at
            == "2026-08-19T12:05:02Z"
        )
        assert store.attempted_creation_result.root.root_id != result.result.root.root_id
        assert events == [
            "read-claim",
            "preflight",
            "evidence",
            "write",
            "read-claim",
            "read-bundle",
        ]

    asyncio.run(scenario())
