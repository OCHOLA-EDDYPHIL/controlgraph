from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from health_execution_test_data import make_health_root, make_healthy_chain
from root_v2_test_data import make_root_v3_records
from test_cloud_run_adapter import _FakeOperation, _FakeServicesClient, _service

from controlgraph_canary.application.authority_store import (
    DirectReceiptCreate,
    ReceiptClaimCreated,
    StoredRecord,
    validate_receipt_claim_binding,
)
from controlgraph_canary.application.capability_verification import (
    CapabilityVerificationError,
    CapabilityVerifier,
    CapabilityVerifierConfiguration,
    VerifiedMutation,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunMutationOutcome,
    CloudRunMutationResult,
    CloudRunTargetConfiguration,
    TargetConfigurationProjection,
)
from controlgraph_canary.application.execution import (
    DefinitiveFreshClaimLeaseFactory,
    FinalAuthorityDenial,
    FinalMutationGate,
    FinalMutationResult,
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
from controlgraph_canary.application.receipt_execution import (
    ReceiptExecutionCoordinator,
    ReceiptExecutionStored,
    ReceiptMutationResult,
    ReceiptMutationStatus,
    ReceiptReadbackResult,
)
from controlgraph_canary.application.signing import (
    DigestSigningBackend,
    PurposeSealedSigner,
    SigningKeyState,
    SigningProfile,
    TrustBundle,
    TrustBundleVerifier,
    VerificationProfile,
    make_trust_bundle_entry,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import canonical_json_bytes, canonical_sha256
from controlgraph_canary.contracts.models import (
    CAPABILITY_CLAIMS_V1,
    SIGNED_CAPABILITY_V1,
    CapabilityAction,
    CapabilityClaims,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
)
from controlgraph_canary.contracts.promotion_execution import (
    PROMOTION_MUTATION_INTENT_V2,
    PROMOTION_TASK_REQUEST_V2,
    PromotionAuthorizationV1,
    PromotionMutationIntentV2,
    PromotionTaskRequestV2,
    create_promotion_authorization,
    promotion_capability_id,
)
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV3,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    execution_receipt_logical_id,
)
from controlgraph_canary.integrations.google.cloud_run import CloudRunV2Adapter

PROJECT_ID = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
VERIFY_TIME = datetime(2026, 8, 21, 12, 9, 30, tzinfo=UTC)
_DEFAULT_SOURCE_RECEIPT = object()


@dataclass(frozen=True, slots=True)
class _Bundle:
    root: StoredRecord[RolloutRootV3]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]
    lineage_anchor: StoredRecord[CapabilityLineageAnchorV1]


class _RootReader:
    def __init__(
        self,
        *,
        returned_root: RolloutRootV3 | None = None,
        authority_epoch: int = 1,
    ) -> None:
        records = make_root_v3_records()
        root = returned_root or records.root
        authority = records.authority
        if authority_epoch != 1:
            authority = EpochAuthorityRecord.model_validate(
                {
                    **authority.model_dump(mode="python"),
                    "current_epoch": authority_epoch,
                    "previous_epoch": authority_epoch - 1,
                    "revision": authority_epoch - 1,
                    "cause": EpochChangeCause.OPERATOR_REVOCATION,
                    "changed_by": "operator@example.test",
                    "request_id": f"request-revoke-{authority_epoch}",
                    "evidence_id": f"evidence-revoke-{authority_epoch}",
                    "changed_at": "2026-08-21T12:09:10Z",
                }
            )
        self.target = records.root.content.target
        self.reads: list[str] = []
        self.bundle = _Bundle(
            root=StoredRecord(root, 0),
            service_claim=StoredRecord(records.service_claim, 0),
            authority=StoredRecord(authority, authority.revision),
            lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        )

    async def read_root_creation_bundle(self, root_id: str) -> _Bundle | None:
        self.reads.append(root_id)
        return self.bundle


class _SigningBackend:
    def __init__(
        self,
        profile: SigningProfile,
        private_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        self._profile = profile
        self._private_key = private_key

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    def sign_digest(self, digest: bytes) -> bytes:
        return self._private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )


def _authorization() -> PromotionAuthorizationV1:
    chain = make_healthy_chain()
    proof = chain.healthy_promotion_proof
    assert proof is not None
    return create_promotion_authorization(
        root=make_health_root(),
        signed_health_chain=chain,
        request_id="request-protected-promotion",
        idempotency_key="protected-promotion",
        scheduled_at=proof.issued_at,
    )


def _signed_capability(
    authorization: PromotionAuthorizationV1,
    private_key: ec.EllipticCurvePrivateKey,
) -> SignedCapability:
    claims = CapabilityClaims(
        schema_version=CAPABILITY_CLAIMS_V1,
        capability_id=promotion_capability_id(authorization),
        issuer=authorization.issuer_identity,
        subject=authorization.executor_identity,
        audience=authorization.executor_audience,
        target=authorization.target,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        concurrency=None,
        plan_sha256=authorization.plan_sha256,
        provider_etag=authorization.provider_etag,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        parent_capability_sha256=None,
        issued_at=authorization.healthy_promotion_proof.issued_at,
        not_before=authorization.scheduled_at,
        expires_at="2026-08-21T12:10:59Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=authorization.capability_signing_key_version,
    )
    signer = PurposeSealedSigner(
        cast(
            DigestSigningBackend,
            _SigningBackend(
                SigningProfile.capability(
                    authorization.target.project_id,
                    authorization.capability_signing_key_version,
                ),
                private_key,
            ),
        )
    )
    signature = signer.sign(claims)
    return SignedCapability(
        schema_version=SIGNED_CAPABILITY_V1,
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=signature.signature,
    )


def _task(
    authorization: PromotionAuthorizationV1,
    private_key: ec.EllipticCurvePrivateKey,
) -> PromotionTaskRequestV2:
    capability = _signed_capability(authorization, private_key)
    intent = PromotionMutationIntentV2(
        schema_version=PROMOTION_MUTATION_INTENT_V2,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        action=CapabilityAction.PROMOTE_CANDIDATE,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        concurrency=None,
        plan_sha256=authorization.plan_sha256,
        provider_etag=authorization.provider_etag,
        capability_id=authorization.capability_id,
        promotion_authorization_sha256=canonical_sha256(authorization),
        expected_prestate_sha256=authorization.expected_prestate_sha256,
        terminal_health_decision_sha256=(
            authorization.terminal_health_decision_sha256
        ),
        health_chain_sha256=authorization.health_chain_locator.health_chain_sha256,
        desired_poststate_sha256=authorization.desired_poststate_sha256,
        proof_valid_until=authorization.proof_valid_until,
        authorization=authorization,
    )
    return PromotionTaskRequestV2(
        schema_version=PROMOTION_TASK_REQUEST_V2,
        task_id=f"task-{capability.claims_sha256}",
        queue_region="us-central1",
        handler_audience=capability.claims.audience,
        scheduled_at=authorization.scheduled_at,
        expires_at=capability.claims.expires_at,
        capability=capability,
        intent=intent,
    )


def _route_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EXECUTOR,
        path=protected_path(ServiceRole.EXECUTOR),
        audience=(
            f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        caller=CallerBinding(
            role=CallerRole.EXECUTION_TASK_CALLER,
            email=(
                f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
            ),
            subject=SUBJECT,
        ),
    )


def _caller() -> AuthenticationContext:
    policy = _route_policy()
    return AuthenticationContext(
        role=policy.caller.role,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=int(datetime(2026, 8, 21, 12, 0, tzinfo=UTC).timestamp()),
        expires_at=int(datetime(2026, 8, 21, 13, 0, tzinfo=UTC).timestamp()),
    )


def _trust_verifier(
    private_key: ec.EllipticCurvePrivateKey,
    key_version: str,
) -> TrustBundleVerifier:
    profile = SigningProfile.capability(PROJECT_ID, key_version)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return TrustBundleVerifier(
        VerificationProfile.capability(PROJECT_ID, profile.key_resource),
        TrustBundle(
            entries=(
                make_trust_bundle_entry(
                    profile=profile,
                    state=SigningKeyState.ENABLED,
                    public_key_pem=public_key_pem,
                ),
            )
        ),
    )


def _verify(
    task: PromotionTaskRequestV2,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    clock: datetime = VERIFY_TIME,
    reader: _RootReader | None = None,
) -> tuple[VerifiedMutation, _RootReader]:
    selected_reader = reader or _RootReader()
    verifier = CapabilityVerifier(
        root_reader=selected_reader,
        trust_verifier=_trust_verifier(
            private_key,
            task.capability.claims.signing_key_version,
        ),
        configuration=CapabilityVerifierConfiguration(
            target=selected_reader.target,
            route_policy=_route_policy(),
        ),
        clock=lambda: clock,
    )
    return (
        asyncio.run(verifier.verify(canonical_json_bytes(task), _caller())),
        selected_reader,
    )


def _binding(
    verified: VerifiedMutation,
    *,
    expected_poststate_sha256: str | None = None,
) -> MutationBinding:
    intent = verified.request.intent
    assert type(intent) is PromotionMutationIntentV2
    return MutationBinding(
        idempotency_key=intent.idempotency_key,
        request_id=intent.request_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=MutationAction.PROMOTE_CANDIDATE,
        target=MutationTargetKey(
            project_id=intent.target.project_id,
            region=intent.target.region,
            environment=intent.target.environment,
            service_name=intent.target.service_name,
        ),
        provider_precondition=intent.provider_etag,
        plan_sha256=intent.plan_sha256,
        capability_sha256=verified.capability_sha256,
        payload_sha256=canonical_sha256(verified.request),
        expected_poststate_sha256=(
            expected_poststate_sha256 or intent.desired_poststate_sha256
        ),
    )


def _lease(
    verified: VerifiedMutation,
    *,
    expected_poststate_sha256: str | None = None,
):
    intent = verified.request.intent
    binding = _binding(
        verified,
        expected_poststate_sha256=expected_poststate_sha256,
    )
    receipt = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(intent.target, intent.idempotency_key),
        request_id=intent.request_id,
        idempotency_key=intent.idempotency_key,
        capability_sha256=verified.capability_sha256,
        mutation_sha256=mutation_identity(binding),
        plan_sha256=intent.plan_sha256,
        expected_poststate_sha256=binding.expected_poststate_sha256,
        target=intent.target,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=intent.action,
        provider_etag=intent.provider_etag,
        dispatch_not_after=verified.request.expires_at,
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=None,
        created_at="2026-08-21T12:09:31Z",
        updated_at="2026-08-21T12:09:31Z",
        evidence_ids=(),
    )
    direct = DirectReceiptCreate._from_direct_store_create(
        StoredRecord(receipt, 0),
        binding,
    )
    return DefinitiveFreshClaimLeaseFactory.mint(direct)


class _SourceReceiptReader:
    def __init__(
        self,
        authorization: PromotionAuthorizationV1,
        *,
        stored: object = _DEFAULT_SOURCE_RECEIPT,
    ) -> None:
        self.target = authorization.target
        receipt = make_healthy_chain().anchor.apply_receipt
        assert canonical_sha256(receipt) == authorization.source_receipt_sha256
        self.stored = (
            StoredRecord(receipt, 2)
            if stored is _DEFAULT_SOURCE_RECEIPT
            else stored
        )
        self.reads: list[str] = []

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        self.reads.append(idempotency_key)
        return cast(StoredRecord[ExecutionReceipt] | None, self.stored)


class _MutationAdapter:
    def __init__(self, target: TargetBinding) -> None:
        self.target = target
        self.service_role = ServiceRole.EXECUTOR
        self.intents: list[PromotionMutationIntentV2] = []
        self._prepared_intent: PromotionMutationIntentV2 | None = None

    @property
    def intent(self) -> PromotionMutationIntentV2:
        assert self._prepared_intent is not None
        return self._prepared_intent

    async def prepare(
        self,
        intent: PromotionMutationIntentV2,
    ) -> _MutationAdapter:
        self._prepared_intent = intent
        return self

    async def mutate(self, permit: MutationPermit) -> str:
        intent = permit.intent
        assert type(intent) is PromotionMutationIntentV2
        self.intents.append(intent)
        return "promoted"


class _ReceiptStore:
    def __init__(self, target: TargetBinding) -> None:
        self.target = target
        self.record: StoredRecord[ExecutionReceipt] | None = None
        self.bindings: list[MutationBinding] = []

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimCreated:
        validate_receipt_claim_binding(receipt, binding)
        assert self.record is None
        self.record = StoredRecord(receipt, 0)
        self.bindings.append(binding)
        return ReceiptClaimCreated(
            receipt=self.record,
            direct_create=DirectReceiptCreate._from_direct_store_create(
                self.record,
                binding,
            ),
        )

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        if self.record is None or self.record.value.idempotency_key != idempotency_key:
            return None
        return self.record

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        assert self.record == expected
        self.record = StoredRecord(replacement, expected.revision + 1)
        return self.record


class _ReceiptMutationAdapter:
    def __init__(self, target: TargetBinding) -> None:
        self.target = target
        self.service_role = ServiceRole.EXECUTOR
        self.intents: list[PromotionMutationIntentV2] = []
        self._prepared_intent: PromotionMutationIntentV2 | None = None

    @property
    def intent(self) -> PromotionMutationIntentV2:
        assert self._prepared_intent is not None
        return self._prepared_intent

    async def prepare(
        self,
        intent: PromotionMutationIntentV2,
    ) -> _ReceiptMutationAdapter:
        self._prepared_intent = intent
        return self

    async def mutate(self, permit: MutationPermit) -> ReceiptMutationResult:
        intent = permit.intent
        assert type(intent) is PromotionMutationIntentV2
        self.intents.append(intent)
        return ReceiptMutationResult(
            status=ReceiptMutationStatus.APPLIED,
            provider_operation="operations/promote-v2",
            reason_code=None,
        )


class _ReceiptReadback:
    def __init__(
        self,
        target: TargetBinding,
        expected: TargetConfigurationProjection,
    ) -> None:
        self.target = target
        self.expected = expected
        self.requests: list[TargetConfigurationProjection] = []

    async def readback(
        self,
        expected: TargetConfigurationProjection,
    ) -> ReceiptReadbackResult:
        self.requests.append(expected)
        return ReceiptReadbackResult(
            state=self.expected,
            observed_etag="etag-promoted-v2",
        )


def test_verifier_accepts_only_exact_v2_health_authorized_promotion() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    task = _task(authorization, private_key)

    verified, reader = _verify(task, private_key)

    assert verified.request == task
    assert type(verified.root) is RolloutRootV3
    assert verified.root == make_health_root()
    assert verified.request.intent.authorization == authorization
    assert reader.reads == [authorization.root_id]


def test_stale_promotion_persists_epoch_denial_at_final_authority_gate() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    task = _task(authorization, private_key)
    reader = _RootReader(authority_epoch=2)
    execution_time = datetime(2026, 8, 21, 12, 9, tzinfo=UTC)
    verified, _ = _verify(
        task,
        private_key,
        clock=execution_time,
        reader=reader,
    )
    expected = TargetConfigurationProjection(
        target=authorization.target,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        concurrency=authorization.concurrency,
    )
    store = _ReceiptStore(authorization.target)
    mutation = _ReceiptMutationAdapter(authorization.target)
    readback = _ReceiptReadback(authorization.target, expected)
    coordinator = ReceiptExecutionCoordinator(
        store=store,
        final_gate=FinalMutationGate(
            authority_reader=reader,
            adapter=mutation,
            route_policy=_route_policy(),
            source_receipt_reader=_SourceReceiptReader(authorization),
            clock=lambda: execution_time,
        ),
        readback=readback,
        clock=lambda: execution_time,
    )

    result = asyncio.run(coordinator.execute(verified))

    assert type(result) is ReceiptExecutionStored
    assert result.receipt.value.outcome is ReceiptOutcome.DENIED
    assert result.receipt.value.reason_code is ReasonCode.EPOCH_MISMATCH
    assert result.receipt.value.observed_authority_epoch == 2
    assert result.receipt.revision == 1
    assert store.record == result.receipt
    assert mutation.intents == []
    assert readback.requests == []
    assert reader.reads == [authorization.root_id, authorization.root_id]


def test_verifier_rejects_valid_compact_authorization_outside_current_root() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    draft = authorization.model_copy(
        update={"stable_revision_configuration_sha256": "9" * 64}
    )
    altered = PromotionAuthorizationV1.model_validate(
        {
            **draft.model_dump(mode="python"),
            "capability_id": promotion_capability_id(draft),
        }
    )
    task = _task(altered, private_key)

    with pytest.raises(CapabilityVerificationError) as denied:
        _verify(task, private_key)

    assert denied.value.code is ReasonCode.CLAIM_BINDING_MISMATCH


def test_verifier_denies_promotion_at_the_proof_deadline() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    task = _task(authorization, private_key)
    deadline = datetime.strptime(
        authorization.proof_valid_until,
        "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=UTC)

    with pytest.raises(CapabilityVerificationError) as denied:
        _verify(task, private_key, clock=deadline)

    assert denied.value.code is ReasonCode.CAPABILITY_EXPIRED


def test_final_gate_dispatches_v2_promotion_with_exact_poststate_binding() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    verified, reader = _verify(_task(authorization, private_key), private_key)
    adapter = _MutationAdapter(reader.target)
    gate = FinalMutationGate(
        authority_reader=reader,
        adapter=adapter,
        route_policy=_route_policy(),
        source_receipt_reader=_SourceReceiptReader(authorization),
        clock=lambda: VERIFY_TIME,
    )

    result = asyncio.run(gate.execute(_lease(verified), verified))

    assert result == FinalMutationResult("promoted", 1)
    assert adapter.intents == [verified.request.intent]
    assert reader.reads == [verified.root.root_id, verified.root.root_id]


@pytest.mark.parametrize(
    ("source_kind", "expected_reason"),
    [
        ("deleted", ReasonCode.AUTHORITY_UNAVAILABLE),
        ("corrupt", ReasonCode.AUTHORITY_UNAVAILABLE),
        ("substituted", ReasonCode.CLAIM_BINDING_MISMATCH),
    ],
)
def test_final_gate_fails_closed_when_source_apply_receipt_changes(
    source_kind: str,
    expected_reason: ReasonCode,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    verified, reader = _verify(_task(authorization, private_key), private_key)
    receipt = make_healthy_chain().anchor.apply_receipt
    source: object
    if source_kind == "deleted":
        source = None
    elif source_kind == "corrupt":
        source = StoredRecord(object(), 2)
    else:
        source = StoredRecord(
            receipt.model_copy(update={"updated_at": "2026-08-21T12:09:29Z"}),
            2,
        )
    source_reader = _SourceReceiptReader(authorization, stored=source)
    adapter = _MutationAdapter(reader.target)

    result = asyncio.run(
        FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            route_policy=_route_policy(),
            source_receipt_reader=source_reader,
            clock=lambda: VERIFY_TIME,
        ).execute(_lease(verified), verified)
    )

    assert isinstance(result, FinalAuthorityDenial)
    assert result.reason_code is expected_reason
    assert adapter.intents == []
    assert reader.reads == [authorization.root_id]


@pytest.mark.parametrize(
    "receipt_update",
    [
        {"observed_etag": "etag-substituted"},
        {"observed_authority_epoch": 2},
    ],
)
def test_final_gate_requires_source_receipt_observation_bindings(
    receipt_update: dict[str, object],
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    verified, reader = _verify(_task(authorization, private_key), private_key)
    receipt = make_healthy_chain().anchor.apply_receipt.model_copy(
        update=receipt_update
    )
    source_reader = _SourceReceiptReader(
        authorization,
        stored=StoredRecord(receipt, 2),
    )
    adapter = _MutationAdapter(reader.target)

    result = asyncio.run(
        FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            route_policy=_route_policy(),
            source_receipt_reader=source_reader,
            clock=lambda: VERIFY_TIME,
        ).execute(_lease(verified), verified)
    )

    assert isinstance(result, FinalAuthorityDenial)
    assert result.reason_code is ReasonCode.CLAIM_BINDING_MISMATCH
    assert adapter.intents == []
    assert reader.reads == [authorization.root_id]


def test_final_gate_denies_changed_v2_poststate_before_authority_read() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    verified, reader = _verify(_task(authorization, private_key), private_key)
    reads_after_verification = len(reader.reads)
    adapter = _MutationAdapter(reader.target)
    gate = FinalMutationGate(
        authority_reader=reader,
        adapter=adapter,
        route_policy=_route_policy(),
        source_receipt_reader=_SourceReceiptReader(authorization),
        clock=lambda: VERIFY_TIME,
    )

    result = asyncio.run(
        gate.execute(
            _lease(verified, expected_poststate_sha256="f" * 64),
            verified,
        )
    )

    assert isinstance(result, FinalAuthorityDenial)
    assert result.reason_code is ReasonCode.IDEMPOTENCY_CONFLICT
    assert len(reader.reads) == reads_after_verification
    assert adapter.intents == []


def test_final_gate_rechecks_v2_proof_deadline_without_mutating() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    verified, reader = _verify(_task(authorization, private_key), private_key)
    deadline = datetime.strptime(
        authorization.proof_valid_until,
        "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=UTC)
    adapter = _MutationAdapter(reader.target)
    gate = FinalMutationGate(
        authority_reader=reader,
        adapter=adapter,
        route_policy=_route_policy(),
        source_receipt_reader=_SourceReceiptReader(authorization),
        clock=lambda: deadline,
    )

    result = asyncio.run(gate.execute(_lease(verified), verified))

    assert isinstance(result, FinalAuthorityDenial)
    assert result.reason_code is ReasonCode.CAPABILITY_EXPIRED
    assert adapter.intents == []


def test_receipt_execution_persists_and_verifies_authorized_v2_poststate() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    execution_time = datetime(2026, 8, 21, 12, 9, tzinfo=UTC)
    verified, reader = _verify(
        _task(authorization, private_key),
        private_key,
        clock=execution_time,
    )
    expected = TargetConfigurationProjection(
        target=authorization.target,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        stable_percent=0,
        candidate_percent=100,
        concurrency=authorization.concurrency,
    )
    store = _ReceiptStore(authorization.target)
    mutation = _ReceiptMutationAdapter(authorization.target)
    readback = _ReceiptReadback(authorization.target, expected)
    coordinator = ReceiptExecutionCoordinator(
        store=store,
        final_gate=FinalMutationGate(
            authority_reader=reader,
            adapter=mutation,
            route_policy=_route_policy(),
            source_receipt_reader=_SourceReceiptReader(authorization),
            clock=lambda: execution_time,
        ),
        readback=readback,
        clock=lambda: execution_time,
    )

    result = asyncio.run(coordinator.execute(verified))

    assert type(result) is ReceiptExecutionStored
    assert result.receipt.value.outcome is ReceiptOutcome.VERIFIED
    assert result.receipt.value.expected_poststate_sha256 == (
        authorization.desired_poststate_sha256
    )
    assert result.receipt.value.provider_etag == authorization.provider_etag
    assert result.receipt.value.observed_etag == "etag-promoted-v2"
    assert result.receipt.revision == 2
    assert mutation.intents == [verified.request.intent]
    assert readback.requests == [expected]
    assert len(store.bindings) == 1
    assert store.bindings[0].expected_poststate_sha256 == (
        authorization.desired_poststate_sha256
    )


def test_google_adapter_uses_v2_receipt_etag_and_only_candidate_traffic() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    authorization = _authorization()
    verified, reader = _verify(_task(authorization, private_key), private_key)
    response = _service(
        0,
        100,
        stable_revision=authorization.stable_revision,
        candidate_revision=authorization.candidate_revision,
        template_revision=authorization.candidate_revision,
        concurrency=authorization.concurrency,
        etag="etag-promoted-v2",
    )
    services = _FakeServicesClient(update=_FakeOperation(response))
    adapter = CloudRunV2Adapter(
        configuration=CloudRunTargetConfiguration(
            target=authorization.target,
            stable_revision=authorization.stable_revision,
            candidate_revision=authorization.candidate_revision,
            stable_concurrency=authorization.concurrency,
            candidate_concurrency=authorization.concurrency,
            network_resource=(
                f"projects/{PROJECT_ID}/global/networks/controlgraph"
            ),
            subnetwork_resource=(
                f"projects/{PROJECT_ID}/regions/us-central1/subnetworks/controlgraph"
            ),
        ),
        service_role=ServiceRole.EXECUTOR,
        configured_project_id=PROJECT_ID,
        services_client_factory=lambda: services,
    )

    gated = asyncio.run(
        FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            route_policy=_route_policy(),
            source_receipt_reader=_SourceReceiptReader(authorization),
            clock=lambda: VERIFY_TIME,
        ).execute(_lease(verified), verified)
    )

    assert type(gated) is FinalMutationResult
    assert type(gated.result) is CloudRunMutationResult
    assert gated.result.outcome is CloudRunMutationOutcome.APPLIED
    assert len(services.update_calls) == 1
    request, retry, timeout = services.update_calls[0]
    assert retry is None
    assert timeout == 15.0
    assert request.service.etag == authorization.provider_etag
    assert request.update_mask.paths == ["traffic"]
    assert request.allow_missing is False
    assert request.validate_only is False
    assert [
        (traffic.revision, traffic.percent, traffic.tag)
        for traffic in request.service.traffic
    ] == [
        (authorization.stable_revision, 0, "stable"),
        (authorization.candidate_revision, 100, "candidate"),
    ]
