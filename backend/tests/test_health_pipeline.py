from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from health_execution_test_data import (
    make_anchor,
    make_signed_proof,
    make_verified_apply_receipt,
)
from recovery_v2_test_data import RecoveryV2Bundle, _finish_bundle
from root_v2_test_data import PROJECT_NUMBER, make_root_v3_records
from test_recovery_execution_contracts import _dispatch_result

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    RootCreationBundle,
    StoredRecord,
)
from controlgraph_canary.application.health_orchestration import (
    VerifierHealthProofService,
)
from controlgraph_canary.application.health_pipeline import (
    ApiHealthEvaluationClient,
    CoordinatorHealthEvaluationClient,
    CoordinatorHealthEvaluationService,
    HealthPipelineError,
    HealthPipelineErrorCode,
    VerifierHealthEvaluationService,
)
from controlgraph_canary.application.health_store import (
    HealthAnchorWriteResult,
    HealthChainAppendResult,
    HealthChainSnapshot,
    HealthChainWriteDisposition,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
    runtime_service_name,
)
from controlgraph_canary.application.monitoring import (
    MonitoringCollectedPoint,
    MonitoringQueryCollection,
)
from controlgraph_canary.application.recovery_execution import RecoveryCoordinator
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.health import (
    HealthDecisionStatus,
    MonitoringMetricQueryV1,
    MonitoringQueryKind,
)
from controlgraph_canary.contracts.health_execution import (
    HEALTH_ATTESTATION_PURPOSE,
    HealthAttestationSigningRequestV1,
    PostApplyHealthAnchorV1,
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    create_signed_health_decision_chain,
)
from controlgraph_canary.contracts.health_pipeline import (
    HEALTH_EVALUATION_COMMAND_V1,
    HEALTH_EVALUATION_INVOCATION_V1,
    HealthEvaluationCommandV1,
    HealthEvaluationInvocationV1,
    HealthEvaluationResultV1,
    HealthEvaluationResultV2,
    VerifierHealthEvaluationRequestV1,
    create_verifier_health_evaluation_request,
)
from controlgraph_canary.contracts.health_storage import create_health_chain_manifest
from controlgraph_canary.contracts.models import EpochChangeCause, ExecutionReceipt, TargetBinding
from controlgraph_canary.contracts.promotion_execution import (
    PromotionHealthChainLocatorV1,
    create_verified_apply_receipt_locator,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryCommandV2,
    RecoveryDispatchResultV2,
    RecoveryIntentV1,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV3


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _HealthyQueryCollector:
    def __init__(
        self,
        *,
        successful_request_count: int = 995,
        server_error_count: int = 1,
    ) -> None:
        self._successful_request_count = successful_request_count
        self._server_error_count = server_error_count

    async def collect(
        self,
        query: MonitoringMetricQueryV1,
        *,
        timeout_seconds: float,
    ) -> MonitoringQueryCollection:
        assert timeout_seconds == 10.0
        query_sha256 = canonical_sha256(query)
        if query.query_kind is MonitoringQueryKind.REQUEST_LATENCY_DISTRIBUTION:
            points: tuple[MonitoringCollectedPoint, ...] = (
                MonitoringCollectedPoint(
                    query_sha256=query_sha256,
                    query_kind=query.query_kind,
                    interval_started_at=query.window_started_at,
                    interval_ended_at=query.window_ended_at,
                    response_code_class=None,
                    provider_value_type="DOUBLE",
                    int64_value=None,
                    provider_double_bits=struct.pack(">d", 400.0).hex(),
                ),
            )
        else:
            points = tuple(
                MonitoringCollectedPoint(
                    query_sha256=query_sha256,
                    query_kind=query.query_kind,
                    interval_started_at=query.window_started_at,
                    interval_ended_at=query.window_ended_at,
                    response_code_class=response_code_class,  # type: ignore[arg-type]
                    provider_value_type="INT64",
                    int64_value=count,
                    provider_double_bits=None,
                )
                for response_code_class, count in (
                    ("2xx", self._successful_request_count),
                    ("3xx", 2),
                    ("4xx", 2),
                    ("5xx", self._server_error_count),
                )
            )
        return MonitoringQueryCollection(
            query_sha256=query_sha256,
            query_kind=query.query_kind,
            points=points,
        )


class _Attestor:
    purpose = HEALTH_ATTESTATION_PURPOSE

    def __init__(
        self,
        anchor: PostApplyHealthAnchorV1,
        *,
        unhealthy: bool = False,
    ) -> None:
        self._anchor = anchor
        self._unhealthy = unhealthy
        self.signing_key_version = anchor.evidence_signing_key_version

    async def attest(
        self,
        request: HealthAttestationSigningRequestV1,
    ) -> SignedHealthDecisionProofV1:
        marker = f"pipeline-proof-{request.pending_proof.sequence}".encode()
        if self._unhealthy:
            marker = (
                b"first-unhealthy-recovery-proof"
                if request.pending_proof.sequence == 1
                else b"second-unhealthy-recovery-proof"
            )
        return make_signed_proof(
            request.pending_proof,
            self._anchor,
            marker=marker,
        )


class _SignatureVerifier:
    def __init__(
        self,
        project_id: str,
        key_version: str,
        *,
        reject: bool = False,
    ) -> None:
        self.project_id = project_id
        self.key_version = key_version
        self.reject = reject
        self.calls: list[SignedHealthDecisionProofV1] = []

    async def verify(self, signed_proof: SignedHealthDecisionProofV1) -> None:
        assert type(signed_proof) is SignedHealthDecisionProofV1
        self.calls.append(signed_proof)
        if self.reject:
            raise ValueError("synthetic invalid signature")


class _ProofServiceFactory:
    def __init__(self, clock: _Clock, *, unhealthy: bool = False) -> None:
        self.clock = clock
        self.unhealthy = unhealthy
        self.calls = 0

    def __call__(
        self,
        *,
        root: RolloutRootV3,
        anchor: PostApplyHealthAnchorV1,
    ) -> VerifierHealthProofService:
        self.calls += 1
        return VerifierHealthProofService(
            root=root,
            anchor=anchor,
            query_collector=(
                _HealthyQueryCollector(
                    successful_request_count=946,
                    server_error_count=50,
                )
                if self.unhealthy
                else _HealthyQueryCollector()
            ),
            attestor=_Attestor(anchor, unhealthy=self.unhealthy),
            signature_verifier=_SignatureVerifier(
                anchor.target.project_id,
                anchor.evidence_signing_key_version,
            ),
            clock=self.clock,
        )


class _AuthorityReader:
    def __init__(
        self,
        receipt: ExecutionReceipt,
        *,
        receipt_revision: int = 2,
    ) -> None:
        records = make_root_v3_records()
        assert records.root == make_anchor()[0]
        self.target = records.root.content.target
        self._records = records
        self._receipt = StoredRecord(receipt, receipt_revision)
        self.revoked = False

    def _bundle(self) -> RootCreationBundle:
        authority = self._records.authority
        revision = 0
        if self.revoked:
            authority = authority.model_copy(
                update={
                    "current_epoch": 2,
                    "previous_epoch": 1,
                    "revision": 1,
                    "cause": EpochChangeCause.OPERATOR_REVOCATION,
                    "request_id": "revoke-health-001",
                    "evidence_id": "evidence-revoke-health-001",
                    "changed_at": "2026-08-21T12:08:30Z",
                }
            )
            revision = 1
        return RootCreationBundle(
            root=StoredRecord(self._records.root, 0),
            service_claim=StoredRecord(self._records.service_claim, 0),
            authority=StoredRecord(authority, revision),
            lineage_anchor=StoredRecord(self._records.lineage_anchor, 0),
            signed_evidence=StoredRecord(self._records.signed_evidence, 0),
            creation_result=StoredRecord(self._records.creation_result, 0),
        )

    async def read_root_creation_bundle(self, root_id: str) -> RootCreationBundle | None:
        if root_id != self._records.root.root_id:
            return None
        return self._bundle()

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        if idempotency_key != self._receipt.value.idempotency_key:
            return None
        return self._receipt


class _HealthStore:
    service_role = ServiceRole.COORDINATOR

    def __init__(self, target: TargetBinding) -> None:
        self.target = target
        self.snapshot: HealthChainSnapshot | None = None
        self.append_calls = 0
        self.raise_conflict_after_write = False

    async def create_or_adopt_health_anchor(
        self,
        anchor: PostApplyHealthAnchorV1,
    ) -> HealthAnchorWriteResult:
        if self.snapshot is None:
            self.snapshot = HealthChainSnapshot(
                anchor=StoredRecord(anchor, 0),
                manifest=None,
                signed_proofs=(),
                signed_chain=None,
            )
            disposition = HealthChainWriteDisposition.CREATED
        else:
            if self.snapshot.anchor.value != anchor:
                raise AuthorityStoreConflict
            disposition = HealthChainWriteDisposition.ADOPTED
        return HealthAnchorWriteResult(disposition, self.snapshot)

    async def append_signed_health_proof(
        self,
        expected: HealthChainSnapshot,
        signed_proof: SignedHealthDecisionProofV1,
        recovery_intent: RecoveryIntentV1 | None = None,
    ) -> HealthChainAppendResult:
        self.append_calls += 1
        if self.snapshot != expected:
            raise AuthorityStoreConflict
        prior = tuple(record.value for record in expected.signed_proofs)
        chain = create_signed_health_decision_chain(
            anchor=expected.anchor.value,
            signed_proofs=(*prior, signed_proof),
        )
        manifest = create_health_chain_manifest(chain)
        self.snapshot = HealthChainSnapshot(
            anchor=expected.anchor,
            manifest=StoredRecord(manifest, manifest.terminal_sequence),
            signed_proofs=tuple(StoredRecord(proof, 0) for proof in chain.signed_proofs),
            signed_chain=chain,
            recovery_intent=(
                StoredRecord(recovery_intent, 0) if recovery_intent is not None else None
            ),
        )
        if self.raise_conflict_after_write:
            self.raise_conflict_after_write = False
            raise AuthorityStoreConflict
        return HealthChainAppendResult(
            HealthChainWriteDisposition.CREATED,
            self.snapshot,
        )

    async def read_health_chain(self, anchor_id: str) -> HealthChainSnapshot | None:
        if self.snapshot is None or self.snapshot.anchor.value.anchor_id != anchor_id:
            return None
        return self.snapshot

    async def read_health_chain_by_manifest(
        self,
        manifest_sha256: str,
    ) -> HealthChainSnapshot | None:
        if (
            self.snapshot is None
            or self.snapshot.manifest is None
            or self.snapshot.manifest.value.manifest_sha256 != manifest_sha256
        ):
            return None
        return self.snapshot

    async def read_promotion_health_chain(
        self,
        locator: PromotionHealthChainLocatorV1,
    ) -> SignedHealthDecisionChainV1 | None:
        if (
            self.snapshot is not None
            and self.snapshot.manifest is not None
            and self.snapshot.manifest.value.manifest_sha256
            == getattr(locator, "health_chain_sha256", None)
        ):
            return self.snapshot.signed_chain
        return None


class _RecoveryCoordinator:
    async def dispatch(
        self,
        command: RecoveryCommandV2,
    ) -> RecoveryDispatchResultV2:
        raise AssertionError(f"unexpected recovery dispatch: {command.root_id}")


class _CapturingRecoveryCoordinator:
    def __init__(self, root: RolloutRootV3) -> None:
        self._root = root
        self.commands: list[RecoveryCommandV2] = []
        self.issuances: list[RecoveryV2Bundle] = []
        self._results: dict[str, RecoveryDispatchResultV2] = {}

    async def dispatch(
        self,
        command: RecoveryCommandV2,
    ) -> RecoveryDispatchResultV2:
        self.commands.append(command)
        command_sha256 = canonical_sha256(command)
        existing = self._results.get(command_sha256)
        if existing is not None:
            return existing
        triggered_at = datetime.strptime(
            command.source.triggered_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        scheduled_at = datetime.strptime(
            command.scheduled_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        bundle = _finish_bundle(
            root=self._root,
            command=command,
            requested_at=(triggered_at + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            retrieved_at=(triggered_at + timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            valid_until=(triggered_at + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            current_provider_etag="pipeline-recovery-etag-9",
            service_generation=9,
            task_expires_at=(scheduled_at + timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        result = _dispatch_result(bundle)
        self.issuances.append(bundle)
        self._results[command_sha256] = result
        return result


@dataclass
class _LoopbackTransport:
    coordinator_caller: AuthenticationContext
    verifier_caller: AuthenticationContext
    coordinator_service: CoordinatorHealthEvaluationService | None = None
    verifier_service: VerifierHealthEvaluationService | None = None
    authority_reader: _AuthorityReader | None = None
    revoke_after_verifier: bool = False

    def __post_init__(self) -> None:
        self.calls: list[CoordinatorInternalRoute] = []
        self.verifier_requests: list[VerifierHealthEvaluationRequestV1] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append(route)
        if route.service_role is ServiceRole.VERIFIER:
            assert self.verifier_service is not None
            request = decode_contract(body, VerifierHealthEvaluationRequestV1)
            self.verifier_requests.append(request)
            verifier_result = await self.verifier_service.evaluate(
                request,
                self.verifier_caller,
            )
            if self.revoke_after_verifier:
                assert self.authority_reader is not None
                self.authority_reader.revoked = True
            return canonical_json_bytes(verifier_result)
        assert route.service_role is ServiceRole.COORDINATOR
        assert self.coordinator_service is not None
        invocation = decode_contract(body, HealthEvaluationInvocationV1)
        coordinator_result = await self.coordinator_service.evaluate(
            invocation,
            self.coordinator_caller,
        )
        return canonical_json_bytes(coordinator_result)


def _audience(role: ServiceRole) -> str:
    return f"https://{runtime_service_name(role)}-{PROJECT_NUMBER}.us-central1.run.app"


def _policy(
    service_role: ServiceRole,
    caller_role: CallerRole,
) -> RouteAuthenticationPolicy:
    records = make_root_v3_records()
    project_id = records.root.content.target.project_id
    email = (
        "operator@example.test"
        if caller_role is CallerRole.OPERATOR
        else f"controlgraph-{caller_role.value}@{project_id}.iam.gserviceaccount.com"
    )
    return RouteAuthenticationPolicy(
        project_id=project_id,
        project_number=PROJECT_NUMBER,
        service_role=service_role,
        path=protected_path(service_role),
        audience=_audience(service_role),
        caller=CallerBinding(
            role=caller_role,
            email=email,
            subject={
                CallerRole.OPERATOR: "123456789012345678901",
                CallerRole.API: "223456789012345678901",
                CallerRole.COORDINATOR: "323456789012345678901",
            }[caller_role],
        ),
    )


def _context(policy: RouteAuthenticationPolicy) -> AuthenticationContext:
    return AuthenticationContext(
        role=policy.caller.role,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=1_777_000_000,
        expires_at=1_777_003_600,
    )


def _route(caller: CallerRole, service: ServiceRole) -> CoordinatorInternalRoute:
    project_id = make_root_v3_records().root.content.target.project_id
    return CoordinatorInternalRoute(
        project_id=project_id,
        project_number=PROJECT_NUMBER,
        caller_role=caller,
        service_role=service,
        audience=_audience(service),
    )


def _command(
    root: RolloutRootV3,
    receipt: ExecutionReceipt,
    *,
    ordinal: int = 1,
    expected_sequence: int = 0,
    expected_chain_head_sha256: str | None = None,
) -> HealthEvaluationCommandV1:
    return HealthEvaluationCommandV1(
        schema_version=HEALTH_EVALUATION_COMMAND_V1,
        request_id=f"health-evaluate-{ordinal:03d}",
        idempotency_key=f"health-evaluate-once-{ordinal:03d}",
        target=root.content.target,
        root_id=root.root_id,
        expected_root_sha256=root.root_sha256,
        expected_epoch=receipt.epoch,
        verified_apply_receipt=create_verified_apply_receipt_locator(receipt),
        expected_sequence=expected_sequence,
        expected_chain_head_sha256=expected_chain_head_sha256,
    )


def _pipeline(
    *,
    clock: _Clock,
    receipt_revision: int = 2,
    reject_client_signatures: bool = False,
    unhealthy: bool = False,
    recovery_coordinator: RecoveryCoordinator | None = None,
) -> tuple[
    ApiHealthEvaluationClient,
    _LoopbackTransport,
    _AuthorityReader,
    _HealthStore,
    HealthEvaluationCommandV1,
    AuthenticationContext,
    CoordinatorHealthEvaluationService,
    _SignatureVerifier,
]:
    root, _ = make_anchor()
    receipt = make_verified_apply_receipt(root)
    authority = _AuthorityReader(receipt, receipt_revision=receipt_revision)
    store = _HealthStore(root.content.target)
    api_policy = _policy(ServiceRole.API, CallerRole.OPERATOR)
    coordinator_policy = _policy(ServiceRole.COORDINATOR, CallerRole.API)
    verifier_policy = _policy(ServiceRole.VERIFIER, CallerRole.COORDINATOR)
    transport = _LoopbackTransport(
        coordinator_caller=_context(coordinator_policy),
        verifier_caller=_context(verifier_policy),
    )
    verifier_service = VerifierHealthEvaluationService(
        target=root.content.target,
        authentication_policy=verifier_policy,
        proof_service_factory=_ProofServiceFactory(clock, unhealthy=unhealthy),
    )
    client_signature_verifier = _SignatureVerifier(
        root.content.target.project_id,
        root.content.evidence_signing_key_version,
        reject=reject_client_signatures,
    )
    verifier_client = CoordinatorHealthEvaluationClient(
        route=_route(CallerRole.COORDINATOR, ServiceRole.VERIFIER),
        transport=transport,
        signature_verifier=client_signature_verifier,
    )
    coordinator_service = CoordinatorHealthEvaluationService(
        target=root.content.target,
        authentication_policy=coordinator_policy,
        operator_policy=api_policy,
        authority_reader=authority,
        receipt_reader=authority,
        health_store=store,
        verifier=verifier_client,
        recovery_coordinator=recovery_coordinator or _RecoveryCoordinator(),
    )
    transport.coordinator_service = coordinator_service
    transport.verifier_service = verifier_service
    transport.authority_reader = authority
    api_client = ApiHealthEvaluationClient(
        route=_route(CallerRole.API, ServiceRole.COORDINATOR),
        authentication_policy=api_policy,
        transport=transport,
    )
    return (
        api_client,
        transport,
        authority,
        store,
        _command(root, receipt),
        _context(api_policy),
        coordinator_service,
        client_signature_verifier,
    )


def _next_command(
    command: HealthEvaluationCommandV1,
    result: HealthEvaluationResultV1 | HealthEvaluationResultV2,
) -> HealthEvaluationCommandV1:
    values = command.model_dump(mode="python")
    values.update(
        {
            "request_id": "health-evaluate-002",
            "idempotency_key": "health-evaluate-once-002",
            "expected_sequence": result.terminal_sequence,
            "expected_chain_head_sha256": result.chain_head_sha256,
        }
    )
    return HealthEvaluationCommandV1.model_validate(values)


def _invocation(
    command: HealthEvaluationCommandV1,
    operator: AuthenticationContext,
) -> HealthEvaluationInvocationV1:
    return HealthEvaluationInvocationV1(
        schema_version=HEALTH_EVALUATION_INVOCATION_V1,
        command=command,
        operator_identity=operator.email,
        operator_subject=operator.subject,
        operator_issuer="https://accounts.google.com",
        operator_audience=operator.audience,
        operator_issued_at=operator.issued_at,
        operator_expires_at=operator.expires_at,
    )


def test_live_pipeline_advances_by_predecessor_and_returns_locator_only_when_healthy() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    (
        api,
        transport,
        _,
        store,
        first_command,
        operator,
        coordinator,
        client_signature_verifier,
    ) = _pipeline(clock=clock)

    first = asyncio.run(api.evaluate(first_command, operator))
    first_adopted = asyncio.run(api.evaluate(first_command, operator))
    second_command = _next_command(first_command, first)
    clock.value = datetime(2026, 8, 21, 12, 9, tzinfo=UTC)
    second = asyncio.run(api.evaluate(second_command, operator))
    adopted = asyncio.run(api.evaluate(second_command, operator))

    assert first.terminal_status is HealthDecisionStatus.WAIT
    assert first.terminal_sequence == 1
    assert first.promotion_health_chain is None
    assert first_adopted == first.model_copy(update={"append_disposition": "ADOPTED"})
    assert second.terminal_status is HealthDecisionStatus.HEALTHY
    assert second.terminal_sequence == 2
    assert second.promotion_health_chain is not None
    assert adopted.promotion_health_chain == second.promotion_health_chain
    assert adopted.append_disposition == "ADOPTED"
    assert store.append_calls == 2
    assert len(transport.verifier_requests) == 2
    assert transport.verifier_requests[0].prior_signed_proof is None
    assert (
        transport.verifier_requests[1].prior_signed_proof == store.snapshot.signed_proofs[0].value  # type: ignore[union-attr]
    )
    assert "signed_proofs" not in VerifierHealthEvaluationRequestV1.model_fields
    assert all(
        len(canonical_json_bytes(request)) <= MAX_CONTRACT_BYTES
        for request in transport.verifier_requests
    )
    assert len(transport.calls) == 6
    assert len(client_signature_verifier.calls) == 4

    with pytest.raises(HealthPipelineError) as stale:
        asyncio.run(
            coordinator.evaluate(
                _invocation(first_command, operator),
                _context(_policy(ServiceRole.COORDINATOR, CallerRole.API)),
            )
        )
    assert stale.value.code is HealthPipelineErrorCode.STORE_CONFLICT
    assert len(transport.verifier_requests) == 2


def test_terminal_unhealthy_v3_pipeline_dispatches_one_root_bound_recovery() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    root, _ = make_anchor()
    recovery = _CapturingRecoveryCoordinator(root)
    (
        api,
        _,
        _,
        store,
        first_command,
        operator,
        _,
        _,
    ) = _pipeline(
        clock=clock,
        unhealthy=True,
        recovery_coordinator=recovery,
    )

    first = asyncio.run(api.evaluate(first_command, operator))
    second_command = _next_command(first_command, first)
    clock.value = datetime(2026, 8, 21, 12, 9, tzinfo=UTC)
    terminal = asyncio.run(api.evaluate(second_command, operator))
    replay = asyncio.run(api.evaluate(second_command, operator))

    assert first.terminal_status is HealthDecisionStatus.WAIT
    assert first.recovery_dispatch is None
    assert terminal.terminal_status is HealthDecisionStatus.UNHEALTHY
    assert terminal.recovery_dispatch is not None
    assert replay.recovery_dispatch == terminal.recovery_dispatch
    assert replay.append_disposition == "ADOPTED"
    assert len(recovery.commands) == 2
    assert recovery.commands[0] == recovery.commands[1]
    assert len(recovery.issuances) == 1
    issued = recovery.issuances[0]
    assert issued.command == recovery.commands[0]
    assert issued.authorization.root_schema_version == root.schema_version
    assert issued.authorization.source.basis.value == "TERMINAL_UNHEALTHY_V3"
    assert issued.issuance_result.capability.claims.action.value == "RECOVER_STABLE_V1"
    assert (
        issued.issuance_result.capability.claims.subject
        == root.content.authority_bounds.recovery_identity
    )
    assert issued.issuance_result.capability.signature
    assert store.snapshot is not None
    assert store.snapshot.recovery_intent is not None
    assert store.snapshot.recovery_intent.value.command == issued.command


def test_coordinator_rechecks_authority_before_cas_append() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    _, transport, _, store, command, operator, coordinator, _ = _pipeline(clock=clock)
    transport.revoke_after_verifier = True
    invocation = _invocation(command, operator)
    coordinator_policy = _policy(ServiceRole.COORDINATOR, CallerRole.API)

    with pytest.raises(HealthPipelineError) as error:
        asyncio.run(coordinator.evaluate(invocation, _context(coordinator_policy)))

    assert error.value.code is HealthPipelineErrorCode.AUTHORITY_STALE
    assert store.append_calls == 0
    assert store.snapshot is not None
    assert store.snapshot.signed_proofs == ()


def test_cas_race_adopts_only_the_exact_immediate_next_step() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    (
        api,
        transport,
        _,
        store,
        command,
        operator,
        _,
        client_signature_verifier,
    ) = _pipeline(clock=clock)
    store.raise_conflict_after_write = True

    result = asyncio.run(api.evaluate(command, operator))

    assert result.terminal_sequence == 1
    assert result.append_disposition == "ADOPTED"
    assert store.append_calls == 1
    assert len(transport.verifier_requests) == 1
    assert len(client_signature_verifier.calls) == 2


def test_verified_receipt_requires_a_completed_storage_lifecycle() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    _, transport, _, store, command, operator, coordinator, _ = _pipeline(
        clock=clock,
        receipt_revision=1,
    )

    with pytest.raises(HealthPipelineError) as error:
        asyncio.run(
            coordinator.evaluate(
                _invocation(command, operator),
                _context(_policy(ServiceRole.COORDINATOR, CallerRole.API)),
            )
        )

    assert error.value.code is HealthPipelineErrorCode.RECEIPT_INVALID
    assert transport.verifier_requests == []
    assert store.snapshot is None


def test_coordinator_client_rejects_the_returned_proof_before_storage() -> None:
    clock = _Clock(datetime(2026, 8, 21, 12, 8, tzinfo=UTC))
    _, transport, _, store, command, operator, coordinator, verifier = _pipeline(
        clock=clock,
        reject_client_signatures=True,
    )

    with pytest.raises(HealthPipelineError) as error:
        asyncio.run(
            coordinator.evaluate(
                _invocation(command, operator),
                _context(_policy(ServiceRole.COORDINATOR, CallerRole.API)),
            )
        )

    assert error.value.code is HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
    assert len(verifier.calls) == 1
    assert store.append_calls == 0
    assert store.snapshot is not None
    assert store.snapshot.signed_proofs == ()
    assert len(transport.verifier_requests) == 1


def test_verifier_request_rejects_root_substitution_and_is_bounded() -> None:
    root, anchor = make_anchor()
    command = _command(root, anchor.apply_receipt)
    request = create_verifier_health_evaluation_request(
        command=command,
        root=root,
        anchor=anchor,
        prior_signed_proof=None,
    )
    other = make_root_v3_records(variant=2).root
    substituted = request.model_dump(mode="python")
    substituted["root"] = other

    with pytest.raises(ValueError, match=r"verifier health request .* invalid"):
        VerifierHealthEvaluationRequestV1.model_validate(substituted)

    assert len(canonical_json_bytes(request)) < MAX_CONTRACT_BYTES
    assert set(VerifierHealthEvaluationRequestV1.model_fields) == {
        "schema_version",
        "request_sha256",
        "command",
        "command_sha256",
        "root",
        "anchor",
        "anchor_sha256",
        "prior_signed_proof",
    }


def test_command_requires_an_exact_first_step_predecessor_pair() -> None:
    root, anchor = make_anchor()
    command = _command(root, anchor.apply_receipt)
    values = command.model_dump(mode="python")
    values["expected_chain_head_sha256"] = "a" * 64

    with pytest.raises(ValueError, match="command bindings are invalid"):
        HealthEvaluationCommandV1.model_validate(values)

    values["expected_sequence"] = 1
    values["expected_chain_head_sha256"] = None
    with pytest.raises(ValueError, match="command bindings are invalid"):
        HealthEvaluationCommandV1.model_validate(values)
