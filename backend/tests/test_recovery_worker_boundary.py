from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from recovery_v2_test_data import (
    RecoveryV2Bundle,
    make_revoked_v2_recovery_bundle,
    make_revoked_v3_recovery_bundle,
    make_unhealthy_recovery_chain,
    make_unhealthy_v3_recovery_bundle,
    make_v2_verified_apply_receipt,
)
from root_v2_test_data import make_root_v2_records, make_root_v3_records
from test_cloud_run_adapter import _FakeOperation, _FakeServicesClient, _service

from controlgraph_canary.application.authority_store import (
    DirectReceiptCreate,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    ReceiptClaimResult,
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
    CloudRunMutationPurpose,
    CloudRunMutationReason,
    CloudRunTargetConfiguration,
    TargetConfigurationProjection,
    target_configuration_projection,
)
from controlgraph_canary.application.execution import (
    DefinitiveFreshClaimLeaseFactory,
    FinalAuthorityDenial,
    FinalMutationGate,
    FinalMutationResult,
    MutationPermit,
)
from controlgraph_canary.application.identity import (
    RECOVERY_EXECUTION_FACADE_PATH,
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.receipt_execution import (
    ReceiptClassifyingMutationAdapter,
    ReceiptExecutionCoordinator,
    ReceiptExecutionStored,
    ReceiptMutationResult,
    ReceiptMutationStatus,
    ReceiptReadbackResult,
    RecoveryExecutorFacade,
    RecoveryTaskForwarder,
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
    CapabilityAction,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryMutationIntentV2,
    RecoveryPrestateAttestationV1,
    RecoveryTaskRequestV2,
    RevokedV3RecoverySourceV1,
)
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV2,
    RolloutRootV3,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    execution_receipt_logical_id,
)
from controlgraph_canary.integrations.google.cloud_run import (
    CloudRunV2Adapter,
    CloudRunV2ReceiptReadback,
)

PROJECT_ID = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"


@dataclass(frozen=True, slots=True)
class _AuthorityBundle:
    root: StoredRecord[RolloutRootV2 | RolloutRootV3]
    service_claim: StoredRecord[ServiceClaimRecord]
    authority: StoredRecord[EpochAuthorityRecord]
    lineage_anchor: StoredRecord[CapabilityLineageAnchorV1]


class _RootReader:
    def __init__(self, bundle: RecoveryV2Bundle, events: list[str] | None = None) -> None:
        if type(bundle.root) is RolloutRootV2:
            records = make_root_v2_records()
            authority = bundle.command.source.revocation_proof.authority
        else:
            records = make_root_v3_records()
            authority = (
                bundle.command.source.revocation_proof.authority
                if type(bundle.command.source) is RevokedV3RecoverySourceV1
                else records.authority
            )
        assert records.root == bundle.root
        self.target = bundle.root.content.target
        self.events = events
        self.reads: list[str] = []
        self.bundle = _AuthorityBundle(
            root=StoredRecord(records.root, 0),
            service_claim=StoredRecord(records.service_claim, 0),
            authority=StoredRecord(authority, authority.revision),
            lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        )

    async def read_root_creation_bundle(self, root_id: str) -> _AuthorityBundle:
        self.reads.append(root_id)
        if self.events is not None:
            self.events.append("authority")
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


class _PrestateVerifier:
    def __init__(self, attestation: RecoveryPrestateAttestationV1) -> None:
        self.project_id = attestation.result.request.target.project_id
        self.key_version = attestation.signing_key_version
        self.calls: list[RecoveryPrestateAttestationV1] = []

    async def verify(self, signed: RecoveryPrestateAttestationV1) -> None:
        self.calls.append(signed)


def _route_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.RECOVERY,
        path=protected_path(ServiceRole.RECOVERY),
        audience=(
            f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        caller=CallerBinding(
            role=CallerRole.RECOVERY_TASK_CALLER,
            email=(
                f"cg-recovery-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
            ),
            subject=SUBJECT,
        ),
    )


def _facade_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EXECUTOR,
        path=RECOVERY_EXECUTION_FACADE_PATH,
        audience=(
            f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        caller=CallerBinding(
            role=CallerRole.RECOVERY,
            email=f"controlgraph-recovery@{PROJECT_ID}.iam.gserviceaccount.com",
            subject=SUBJECT,
        ),
    )


def _caller(at: datetime) -> AuthenticationContext:
    policy = _route_policy()
    return AuthenticationContext(
        role=policy.caller.role,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=int((at - timedelta(minutes=1)).timestamp()),
        expires_at=int((at + timedelta(minutes=30)).timestamp()),
    )


def _facade_caller(at: datetime) -> AuthenticationContext:
    policy = _facade_policy()
    return AuthenticationContext(
        role=policy.caller.role,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=int((at - timedelta(minutes=1)).timestamp()),
        expires_at=int((at + timedelta(minutes=30)).timestamp()),
    )


def _utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _signed_task(
    bundle: RecoveryV2Bundle,
    private_key: ec.EllipticCurvePrivateKey,
) -> RecoveryTaskRequestV2:
    claims = bundle.task.capability.claims
    profile = SigningProfile.capability(PROJECT_ID, claims.signing_key_version)
    signer = PurposeSealedSigner(
        cast(DigestSigningBackend, _SigningBackend(profile, private_key))
    )
    signature = signer.sign(claims)
    capability = SignedCapability(
        schema_version=bundle.task.capability.schema_version,
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=signature.signature,
    )
    return bundle.task.model_copy(update={"capability": capability})


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


def _verification_boundary(
    bundle: RecoveryV2Bundle,
    *,
    task: RecoveryTaskRequestV2,
    private_key: ec.EllipticCurvePrivateKey,
    events: list[str] | None = None,
    facade: bool = False,
) -> tuple[
    CapabilityVerifier,
    _RootReader,
    _PrestateVerifier,
    datetime,
    AuthenticationContext,
]:
    reader = _RootReader(bundle, events)
    prestate_verifier = _PrestateVerifier(bundle.prestate_attestation)
    now = _utc(task.scheduled_at) + timedelta(seconds=1)
    route_policy = _facade_policy() if facade else _route_policy()
    verifier = CapabilityVerifier(
        root_reader=reader,
        trust_verifier=_trust_verifier(
            private_key,
            task.capability.claims.signing_key_version,
        ),
        configuration=CapabilityVerifierConfiguration(
            target=reader.target,
            route_policy=route_policy,
            recovery_executor_facade=facade,
        ),
        recovery_prestate_verifier=prestate_verifier,
        clock=lambda: now,
    )
    caller = _facade_caller(now) if facade else _caller(now)
    return verifier, reader, prestate_verifier, now, caller


def _verify(
    bundle: RecoveryV2Bundle,
    *,
    events: list[str] | None = None,
    facade: bool = False,
) -> tuple[VerifiedMutation, _RootReader, _PrestateVerifier, datetime]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    task = _signed_task(bundle, private_key)
    verifier, reader, prestate_verifier, now, caller = _verification_boundary(
        bundle,
        task=task,
        private_key=private_key,
        events=events,
        facade=facade,
    )
    verified = asyncio.run(verifier.verify(canonical_json_bytes(task), caller))
    return verified, reader, prestate_verifier, now


def _binding(verified: VerifiedMutation) -> MutationBinding:
    intent = verified.request.intent
    assert type(intent) is RecoveryMutationIntentV2
    return MutationBinding(
        idempotency_key=intent.idempotency_key,
        request_id=intent.request_id,
        root_id=intent.root_id,
        root_sha256=intent.root_sha256,
        epoch=intent.epoch,
        action=MutationAction.RECOVER_STABLE,
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
        expected_poststate_sha256=intent.desired_poststate_sha256,
    )


def _claimed(
    verified: VerifiedMutation,
    *,
    created_at: str | None = None,
) -> StoredRecord[ExecutionReceipt]:
    intent = verified.request.intent
    binding = _binding(verified)
    timestamp = created_at or verified.request.scheduled_at
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
        created_at=timestamp,
        updated_at=timestamp,
        evidence_ids=(),
    )
    return StoredRecord(receipt, 0)


def _lease(verified: VerifiedMutation):
    claimed = _claimed(verified)
    direct = DirectReceiptCreate._from_direct_store_create(
        claimed,
        _binding(verified),
    )
    return DefinitiveFreshClaimLeaseFactory.mint(direct)


def _source_receipt(bundle: RecoveryV2Bundle) -> ExecutionReceipt:
    if type(bundle.root) is RolloutRootV2:
        return make_v2_verified_apply_receipt(bundle.root)
    return make_unhealthy_recovery_chain(bundle.root).anchor.apply_receipt


class _SourceReader:
    def __init__(
        self,
        bundle: RecoveryV2Bundle,
        events: list[str] | None = None,
    ) -> None:
        self.target = bundle.root.content.target
        self.stored: StoredRecord[ExecutionReceipt] | None = StoredRecord(
            _source_receipt(bundle),
            2,
        )
        self.events = events
        self.reads: list[str] = []

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        self.reads.append(idempotency_key)
        if self.events is not None:
            self.events.append("source-receipt")
        if self.stored is None or self.stored.value.idempotency_key != idempotency_key:
            return None
        return self.stored


class _MutationAdapter:
    def __init__(
        self,
        target: TargetBinding,
        result: object,
        events: list[str] | None = None,
        on_prepare: Callable[[], None] | None = None,
    ) -> None:
        self.target = target
        self.service_role = ServiceRole.EXECUTOR
        self.mutation_purpose = CloudRunMutationPurpose.STABLE_RECOVERY
        self.result = result
        self.events = events
        self.on_prepare = on_prepare
        self.calls: list[RecoveryMutationIntentV2] = []
        self._intent: RecoveryMutationIntentV2 | None = None

    @property
    def intent(self) -> RecoveryMutationIntentV2:
        assert self._intent is not None
        return self._intent

    async def prepare(self, intent: RecoveryMutationIntentV2) -> _MutationAdapter:
        assert type(intent) is RecoveryMutationIntentV2
        self._intent = intent
        if self.events is not None:
            self.events.append("prepare")
        if self.on_prepare is not None:
            self.on_prepare()
        return self

    async def mutate(self, permit: MutationPermit) -> object:
        intent = permit.intent
        assert type(intent) is RecoveryMutationIntentV2
        self.calls.append(intent)
        if self.events is not None:
            self.events.append("mutate")
        return self.result


@pytest.mark.parametrize(
    "bundle_factory",
    [
        make_unhealthy_v3_recovery_bundle,
        make_revoked_v2_recovery_bundle,
        make_revoked_v3_recovery_bundle,
    ],
)
def test_exact_recovery_v2_verifies_and_dispatches_after_both_final_reads(
    bundle_factory: object,
) -> None:
    bundle = bundle_factory()  # type: ignore[operator]
    events: list[str] = []
    verified, reader, prestate_verifier, now = _verify(
        bundle,
        events=events,
        facade=True,
    )
    events.clear()
    adapter = _MutationAdapter(reader.target, "recovered", events)
    source_reader = _SourceReader(bundle, events)
    gate = FinalMutationGate(
        authority_reader=reader,
        adapter=adapter,
        route_policy=_facade_policy(),
        source_receipt_reader=source_reader,
        mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
        clock=lambda: now,
    )

    result = asyncio.run(gate.execute(_lease(verified), verified))

    assert result == FinalMutationResult("recovered", bundle.authorization.epoch)
    assert events == ["prepare", "source-receipt", "authority", "mutate"]
    assert prestate_verifier.calls == [bundle.prestate_attestation]
    assert adapter.calls == [verified.request.intent]
    assert source_reader.reads == [bundle.authorization.verified_apply_receipt.idempotency_key]
    assert source_reader.stored is not None
    assert (
        source_reader.stored.value.epoch
        == bundle.authorization.verified_apply_receipt.epoch
    )


def test_final_gate_denies_deleted_or_substituted_recovery_source_receipt() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    verified, reader, _, now = _verify(bundle, facade=True)

    deleted = _SourceReader(bundle)
    deleted.stored = None
    deleted_adapter = _MutationAdapter(reader.target, "must-not-run")
    deleted_result = asyncio.run(
        FinalMutationGate(
            authority_reader=reader,
            adapter=deleted_adapter,
            route_policy=_facade_policy(),
            source_receipt_reader=deleted,
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            clock=lambda: now,
        ).execute(_lease(verified), verified)
    )

    assert isinstance(deleted_result, FinalAuthorityDenial)
    assert deleted_result.reason_code is ReasonCode.AUTHORITY_UNAVAILABLE
    assert deleted_adapter.calls == []

    substituted = _SourceReader(bundle)
    assert substituted.stored is not None
    altered = substituted.stored.value.model_copy(
        update={"updated_at": "2026-08-21T12:09:29Z"}
    )
    substituted.stored = StoredRecord(altered, 2)
    substituted_adapter = _MutationAdapter(reader.target, "must-not-run")
    substituted_result = asyncio.run(
        FinalMutationGate(
            authority_reader=reader,
            adapter=substituted_adapter,
            route_policy=_facade_policy(),
            source_receipt_reader=substituted,
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            clock=lambda: now,
        ).execute(_lease(verified), verified)
    )

    assert isinstance(substituted_result, FinalAuthorityDenial)
    assert substituted_result.reason_code is ReasonCode.CLAIM_BINDING_MISMATCH
    assert substituted_adapter.calls == []


@pytest.mark.parametrize(
    "bundle_factory",
    [
        make_unhealthy_v3_recovery_bundle,
        make_revoked_v2_recovery_bundle,
        make_revoked_v3_recovery_bundle,
    ],
)
def test_epoch_change_after_prepare_denies_recovery_before_mutation(
    bundle_factory: object,
) -> None:
    bundle = bundle_factory()  # type: ignore[operator]
    events: list[str] = []
    verified, reader, _, now = _verify(bundle, events=events, facade=True)
    events.clear()

    def revoke() -> None:
        before = reader.bundle.authority.value
        changed = EpochAuthorityRecord.model_validate(
            {
                **before.model_dump(mode="python"),
                "current_epoch": before.current_epoch + 1,
                "previous_epoch": before.current_epoch,
                "revision": before.revision + 1,
                "cause": EpochChangeCause.OPERATOR_REVOCATION,
                "changed_by": "operator@example.test",
                "request_id": "request-revoke-after-prepare",
                "evidence_id": "evidence-revoke-after-prepare",
                "changed_at": "2026-08-21T12:09:31Z",
            }
        )
        reader.bundle = _AuthorityBundle(
            root=reader.bundle.root,
            service_claim=reader.bundle.service_claim,
            authority=StoredRecord(changed, changed.revision),
            lineage_anchor=reader.bundle.lineage_anchor,
        )

    adapter = _MutationAdapter(reader.target, "must-not-run", events, revoke)
    result = asyncio.run(
        FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            route_policy=_facade_policy(),
            source_receipt_reader=_SourceReader(bundle, events),
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            clock=lambda: now,
        ).execute(_lease(verified), verified)
    )

    assert isinstance(result, FinalAuthorityDenial)
    assert result.reason_code is ReasonCode.EPOCH_MISMATCH
    assert events == ["prepare", "source-receipt", "authority"]
    assert adapter.calls == []


@pytest.mark.parametrize(
    ("bundle_factory", "other_records_factory"),
    [
        (make_unhealthy_v3_recovery_bundle, make_root_v2_records),
        (make_revoked_v2_recovery_bundle, make_root_v3_records),
        (make_revoked_v3_recovery_bundle, make_root_v2_records),
    ],
)
def test_final_gate_denies_recovery_request_with_cross_mode_root(
    bundle_factory: object,
    other_records_factory: object,
) -> None:
    bundle = bundle_factory()  # type: ignore[operator]
    verified, reader, _, now = _verify(bundle, facade=True)
    other = other_records_factory()  # type: ignore[operator]
    crossed = VerifiedMutation(
        request=verified.request,
        root=other.root,
        lineage_anchor=other.lineage_anchor,
        caller=verified.caller,
        capability_sha256=verified.capability_sha256,
        claims_sha256=verified.claims_sha256,
        earliest_lineage_issued_at=verified.earliest_lineage_issued_at,
    )
    adapter = _MutationAdapter(reader.target, "must-not-run")

    result = asyncio.run(
        FinalMutationGate(
            authority_reader=reader,
            adapter=adapter,
            route_policy=_facade_policy(),
            source_receipt_reader=_SourceReader(bundle),
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            clock=lambda: now,
        ).execute(_lease(crossed), crossed)
    )

    assert isinstance(result, FinalAuthorityDenial)
    assert result.reason_code is ReasonCode.IDEMPOTENCY_CONFLICT
    assert adapter.calls == []


def test_generic_legacy_recovery_task_is_rejected_before_authority_lookup() -> None:
    bundle = make_revoked_v2_recovery_bundle()
    private_key = ec.generate_private_key(ec.SECP256R1())
    task = _signed_task(bundle, private_key)
    recovery = task.intent
    legacy_intent = MutationIntent(
        schema_version="controlgraph.mutation-intent/v1",
        request_id=recovery.request_id,
        idempotency_key=recovery.idempotency_key,
        target=recovery.target,
        root_id=recovery.root_id,
        root_sha256=recovery.root_sha256,
        epoch=recovery.epoch,
        action=CapabilityAction.RECOVER_STABLE,
        stable_revision=recovery.stable_revision,
        candidate_revision=recovery.candidate_revision,
        stable_percent=100,
        candidate_percent=0,
        concurrency=recovery.concurrency,
        plan_sha256=recovery.plan_sha256,
        provider_etag=recovery.provider_etag,
    )
    legacy = TaskRequest(
        schema_version="controlgraph.task-request/v1",
        task_id=task.task_id,
        queue_region=task.queue_region,
        handler_audience=task.handler_audience,
        scheduled_at=task.scheduled_at,
        expires_at=task.expires_at,
        capability=task.capability,
        intent=legacy_intent,
    )
    reader = _RootReader(bundle)
    now = _utc(task.scheduled_at) + timedelta(seconds=1)
    verifier = CapabilityVerifier(
        root_reader=reader,
        trust_verifier=_trust_verifier(
            private_key,
            task.capability.claims.signing_key_version,
        ),
        configuration=CapabilityVerifierConfiguration(
            target=reader.target,
            route_policy=_route_policy(),
        ),
        recovery_prestate_verifier=_PrestateVerifier(bundle.prestate_attestation),
        clock=lambda: now,
    )

    with pytest.raises(CapabilityVerificationError) as denied:
        asyncio.run(verifier.verify(canonical_json_bytes(legacy), _caller(now)))

    assert denied.value.code is ReasonCode.CLAIM_BINDING_MISMATCH
    assert reader.reads == []


class _ReceiptStore:
    def __init__(self, bundle: RecoveryV2Bundle) -> None:
        self.target = bundle.root.content.target
        source = _source_receipt(bundle)
        self.records = {
            source.idempotency_key: StoredRecord(source, 2),
        }
        self.claims = 0
        self.cas_calls = 0

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        self.claims += 1
        validate_receipt_claim_binding(receipt, binding)
        current = self.records.get(receipt.idempotency_key)
        if current is not None:
            if current.value.mutation_sha256 != receipt.mutation_sha256:
                return ReceiptClaimConflict()
            return ReceiptClaimAdopted(current)
        stored = StoredRecord(receipt, 0)
        self.records[receipt.idempotency_key] = stored
        return ReceiptClaimCreated(
            stored,
            DirectReceiptCreate._from_direct_store_create(stored, binding),
        )

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        return self.records.get(idempotency_key)

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        self.cas_calls += 1
        assert self.records[expected.value.idempotency_key] == expected
        stored = StoredRecord(replacement, expected.revision + 1)
        self.records[replacement.idempotency_key] = stored
        return stored


class _Readback:
    def __init__(self, expected: TargetConfigurationProjection) -> None:
        self.target = expected.target
        self.expected = expected
        self.calls = 0

    async def readback(
        self,
        expected: TargetConfigurationProjection,
    ) -> ReceiptReadbackResult:
        self.calls += 1
        assert expected == self.expected
        return ReceiptReadbackResult(
            state=self.expected,
            observed_etag="stable-recovered-etag-10",
        )


class _AmbiguousReadback:
    def __init__(self, target: TargetBinding) -> None:
        self.target = target
        self.calls = 0

    async def readback(
        self,
        expected: TargetConfigurationProjection,
    ) -> ReceiptReadbackResult:
        del expected
        self.calls += 1
        return ReceiptReadbackResult(state=None, observed_etag=None)


class _FacadeClient:
    def __init__(
        self,
        facade: RecoveryExecutorFacade,
        caller: AuthenticationContext,
    ) -> None:
        self.target = facade.target
        self.facade = facade
        self.caller = caller
        self.payloads: list[bytes] = []

    async def execute(self, payload: bytes):  # type: ignore[no-untyped-def]
        self.payloads.append(payload)
        return await self.facade.execute(payload, self.caller)


def test_forwarded_recovery_is_reverified_and_duplicate_never_dispatches() -> None:
    bundle = make_revoked_v2_recovery_bundle()
    private_key = ec.generate_private_key(ec.SECP256R1())
    task = _signed_task(bundle, private_key)
    intake_verifier, _, intake_prestate, now, intake_caller = _verification_boundary(
        bundle,
        task=task,
        private_key=private_key,
    )
    verified = asyncio.run(
        intake_verifier.verify(canonical_json_bytes(task), intake_caller)
    )
    facade_verifier, reader, facade_prestate, _, facade_caller = (
        _verification_boundary(
            bundle,
            task=task,
            private_key=private_key,
            facade=True,
        )
    )
    store = _ReceiptStore(bundle)
    adapter = _MutationAdapter(
        reader.target,
        ReceiptMutationResult(
            status=ReceiptMutationStatus.APPLIED,
            provider_operation="operations/recover-stable-v2",
            reason_code=None,
        ),
    )
    gate = FinalMutationGate(
        authority_reader=reader,
        adapter=adapter,
        route_policy=_facade_policy(),
        source_receipt_reader=store,
        mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
        clock=lambda: now,
    )
    intent = verified.request.intent
    expected = target_configuration_projection(
        intent,
        expected_concurrency=verified.root.content.authority_bounds.concurrency,
    )
    readback = _Readback(expected)
    coordinator = ReceiptExecutionCoordinator(
        store=store,
        final_gate=gate,
        readback=readback,
        clock=lambda: now,
    )
    facade = RecoveryExecutorFacade(
        verifier=facade_verifier,
        coordinator=coordinator,
    )
    client = _FacadeClient(facade, facade_caller)
    forwarder = RecoveryTaskForwarder(
        client=client,
        route_policy=_route_policy(),
    )

    first = asyncio.run(forwarder.forward(verified))
    second = asyncio.run(forwarder.forward(verified))

    assert type(first) is ReceiptExecutionStored
    assert type(second) is ReceiptExecutionStored
    assert first.receipt == second.receipt
    receipt = first.receipt.value
    assert receipt.outcome is ReceiptOutcome.VERIFIED
    assert receipt.action is CapabilityAction.RECOVER_STABLE
    assert receipt.epoch == bundle.authorization.epoch == 2
    assert receipt.observed_authority_epoch == 2
    assert receipt.expected_poststate_sha256 == intent.desired_poststate_sha256
    assert receipt.provider_operation == "operations/recover-stable-v2"
    assert len(adapter.calls) == 1
    assert readback.calls == 1
    assert store.claims == 2
    assert store.cas_calls == 2
    assert intake_prestate.calls == [bundle.prestate_attestation]
    assert facade_prestate.calls == [
        bundle.prestate_attestation,
        bundle.prestate_attestation,
    ]
    assert client.payloads == [canonical_json_bytes(task), canonical_json_bytes(task)]


class _TrackingServicesClient(_FakeServicesClient):
    def __init__(self, events: list[str], **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.events = events

    async def get_service(self, request, *, retry, timeout):  # type: ignore[no-untyped-def]
        self.events.append("prestate")
        return await super().get_service(request, retry=retry, timeout=timeout)

    async def update_service(self, request, *, retry, timeout):  # type: ignore[no-untyped-def]
        self.events.append("update")
        return await super().update_service(request, retry=retry, timeout=timeout)


def _cloud_configuration(bundle: RecoveryV2Bundle) -> CloudRunTargetConfiguration:
    root = bundle.root
    plan = root.content.rollout_plan
    target = root.content.target
    return CloudRunTargetConfiguration(
        target=target,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_concurrency=plan.concurrency,
        candidate_concurrency=plan.concurrency,
        network_resource=(
            f"projects/{target.project_id}/global/networks/controlgraph"
        ),
        subnetwork_resource=(
            f"projects/{target.project_id}/regions/{target.region}/"
            "subnetworks/controlgraph"
        ),
    )


def _cloud_service(
    bundle: RecoveryV2Bundle,
    stable_percent: int,
    candidate_percent: int,
    *,
    generation: int = 9,
    etag: str | None = None,
):
    plan = bundle.root.content.rollout_plan
    return _service(
        stable_percent,
        candidate_percent,
        resource_name=_cloud_configuration(bundle).service_resource,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        template_revision=plan.candidate_revision,
        concurrency=plan.concurrency,
        etag=etag or bundle.authorization.current_provider_etag,
        generation=generation,
    )


def _stable_only_cloud_service(
    bundle: RecoveryV2Bundle,
    *,
    generation: int = 10,
    etag: str = "recovered-etag-10",
):
    service = _cloud_service(
        bundle,
        100,
        0,
        generation=generation,
        etag=etag,
    )
    service.traffic.pop()
    service.traffic_statuses.pop()
    return service


def _cloud_gate(
    bundle: RecoveryV2Bundle,
    verified: VerifiedMutation,
    reader: _RootReader,
    now: datetime,
    services: _TrackingServicesClient,
) -> FinalMutationGate:
    adapter = CloudRunV2Adapter(
        configuration=_cloud_configuration(bundle),
        service_role=ServiceRole.EXECUTOR,
        configured_project_id=PROJECT_ID,
        mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
        services_client_factory=lambda: services,
    )
    return FinalMutationGate(
        authority_reader=reader,
        adapter=adapter,
        route_policy=_facade_policy(),
        source_receipt_reader=_SourceReader(bundle, services.events),
        mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
        clock=lambda: now,
    )


def test_cloud_run_recovery_is_exact_traffic_only_and_timeout_is_not_retried() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    events: list[str] = []
    verified, reader, _, now = _verify(bundle, events=events, facade=True)
    events.clear()
    after = _stable_only_cloud_service(bundle)
    operation = _FakeOperation(after, name="operations/recover-stable-v4")
    services = _TrackingServicesClient(
        events,
        service=_cloud_service(bundle, 90, 10),
        update=operation,
    )

    applied = asyncio.run(
        _cloud_gate(bundle, verified, reader, now, services).execute(
            _lease(verified),
            verified,
        )
    )

    assert isinstance(applied, FinalMutationResult)
    assert applied.result.outcome is CloudRunMutationOutcome.APPLIED
    assert events == ["prestate", "source-receipt", "authority", "update"]
    assert len(services.get_calls) == 1
    assert len(services.update_calls) == 1
    request = services.update_calls[0][0]
    assert list(request.update_mask.paths) == ["traffic"]
    assert request.service.etag == bundle.authorization.current_provider_etag
    assert [(item.revision, item.percent, item.tag) for item in request.service.traffic] == [
        (bundle.authorization.stable_revision, 100, "stable"),
    ]

    timeout_events: list[str] = []
    timed_out = _TrackingServicesClient(
        timeout_events,
        service=_cloud_service(bundle, 90, 10),
        update=TimeoutError("outcome unknown"),
    )
    timeout_adapter = ReceiptClassifyingMutationAdapter(
        CloudRunV2Adapter(
            configuration=_cloud_configuration(bundle),
            service_role=ServiceRole.EXECUTOR,
            configured_project_id=PROJECT_ID,
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            services_client_factory=lambda: timed_out,
        )
    )
    timeout_store = _ReceiptStore(bundle)
    timeout_readback = _AmbiguousReadback(reader.target)
    timeout_coordinator = ReceiptExecutionCoordinator(
        store=timeout_store,
        final_gate=FinalMutationGate(
            authority_reader=reader,
            adapter=timeout_adapter,
            route_policy=_facade_policy(),
            source_receipt_reader=timeout_store,
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            clock=lambda: now,
        ),
        readback=timeout_readback,
        clock=lambda: now,
    )
    ambiguous = asyncio.run(timeout_coordinator.execute(verified))
    duplicate = asyncio.run(timeout_coordinator.execute(verified))

    assert type(ambiguous) is ReceiptExecutionStored
    assert type(duplicate) is ReceiptExecutionStored
    assert ambiguous.receipt.value.outcome is ReceiptOutcome.AMBIGUOUS
    assert duplicate.receipt == ambiguous.receipt
    assert len(timed_out.update_calls) == 1
    assert timeout_readback.calls == 2


def test_cloud_run_recovery_readback_requires_one_stable_traffic_target() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    expected = target_configuration_projection(
        bundle.task.intent,
        expected_concurrency=bundle.authorization.concurrency,
    )
    exact_services = _TrackingServicesClient(
        [],
        service=_stable_only_cloud_service(bundle),
    )
    extra_candidate_services = _TrackingServicesClient(
        [],
        service=_cloud_service(bundle, 100, 0),
    )

    exact = asyncio.run(
        CloudRunV2ReceiptReadback(
            configuration=_cloud_configuration(bundle),
            configured_project_id=PROJECT_ID,
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            services_client_factory=lambda: exact_services,
        ).readback(expected)
    )
    extra_candidate = asyncio.run(
        CloudRunV2ReceiptReadback(
            configuration=_cloud_configuration(bundle),
            configured_project_id=PROJECT_ID,
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            services_client_factory=lambda: extra_candidate_services,
        ).readback(expected)
    )

    assert exact == ReceiptReadbackResult(
        state=expected,
        observed_etag="recovered-etag-10",
    )
    assert extra_candidate == ReceiptReadbackResult(
        state=None,
        observed_etag=bundle.authorization.current_provider_etag,
    )


def test_standard_readback_rejects_recovery_expectation_before_provider_access() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    services = _TrackingServicesClient([], service=_stable_only_cloud_service(bundle))
    expected = target_configuration_projection(
        bundle.task.intent,
        expected_concurrency=bundle.authorization.concurrency,
    )

    observation = asyncio.run(
        CloudRunV2ReceiptReadback(
            configuration=_cloud_configuration(bundle),
            configured_project_id=PROJECT_ID,
            services_client_factory=lambda: services,
        ).readback(expected)
    )

    assert observation == ReceiptReadbackResult(state=None, observed_etag=None)
    assert services.get_calls == []


def test_cloud_run_recovery_prestate_drift_never_updates() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    events: list[str] = []
    verified, reader, _, now = _verify(bundle, events=events, facade=True)
    events.clear()
    services = _TrackingServicesClient(
        events,
        service=_cloud_service(bundle, 90, 10, generation=10),
    )

    result = asyncio.run(
        _cloud_gate(bundle, verified, reader, now, services).execute(
            _lease(verified),
            verified,
        )
    )

    assert isinstance(result, FinalMutationResult)
    assert result.result.outcome is CloudRunMutationOutcome.FAILED_SAFE
    assert result.result.reason is CloudRunMutationReason.PRECONDITION_FAILED
    assert services.update_calls == []

    with pytest.raises(ValueError, match="executor identity"):
        CloudRunV2Adapter(
            configuration=_cloud_configuration(bundle),
            service_role=ServiceRole.RECOVERY,
            configured_project_id=PROJECT_ID,
            mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
            services_client_factory=lambda: services,
        )
