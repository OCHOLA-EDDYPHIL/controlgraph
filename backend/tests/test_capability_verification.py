from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from datetime import UTC, datetime
from threading import Event, Lock
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi import Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from httpx import Response as ClientResponse
from root_v2_support import RootBundle, root_bundle, root_records

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreUnavailable,
    DirectReceiptCreate,
    ReceiptClaimAdopted,
    ReceiptClaimConflict,
    ReceiptClaimCreated,
    ReceiptClaimResult,
    StoredRecord,
    validate_receipt_claim_binding,
)
from controlgraph_canary.application.capability_verification import (
    CapabilityLineageReader,
    CapabilityVerificationError,
    CapabilityVerifier,
    CapabilityVerifierConfiguration,
    VerifiedMutation,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunMutationOutcome,
    CloudRunMutationReason,
    CloudRunMutationResult,
    CloudRunTrafficAllocation,
    TargetConfigurationProjection,
    target_configuration_projection,
)
from controlgraph_canary.application.execution import FinalMutationGate, MutationPermit
from controlgraph_canary.application.identity import (
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
from controlgraph_canary.authority.replay import MutationBinding
from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityClaims,
    EpochAuthorityRecord,
    EpochChangeCause,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    RolloutRootV2,
    SignedCapability,
    TargetBinding,
    TaskRequest,
    canonical_json_bytes,
    canonical_sha256,
    encode_base64url,
)
from controlgraph_canary.http.receipt import create_receipt_task_handler
from controlgraph_canary.http.service import create_service_app

PROJECT_ID = "controlgraph-canary-abc123"
OTHER_PROJECT_ID = "controlgraph-canary-def456"
PROJECT_NUMBER = "123456789012"
SUBJECT = "123456789012345678901"
NOW = datetime(2026, 8, 19, 12, 3, tzinfo=UTC)
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
THREE_DIGEST = "3" * 64
CAPABILITY_KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)
UNTRUSTED_KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/2"
)


def _target(**overrides: object) -> TargetBinding:
    values: dict[str, object] = {
        "schema_version": "controlgraph.target-binding/v1",
        "project_id": PROJECT_ID,
        "region": "us-central1",
        "environment": "nonprod",
        "service_name": "controlgraph-reference-target",
    }
    values.update(overrides)
    return TargetBinding(**values)  # type: ignore[arg-type]


def _root() -> RolloutRootV2:
    root, _, _, _ = root_records()
    return root


def _policy(role: ServiceRole) -> RouteAuthenticationPolicy:
    if role is ServiceRole.EXECUTOR:
        caller_role = CallerRole.EXECUTION_TASK_CALLER
        account = "cg-execution-task-caller"
    elif role is ServiceRole.RECOVERY:
        caller_role = CallerRole.RECOVERY_TASK_CALLER
        account = "cg-recovery-task-caller"
    else:
        caller_role = CallerRole.COORDINATOR
        account = "controlgraph-coordinator"
    return RouteAuthenticationPolicy(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        service_role=role,
        path=protected_path(role),
        audience=f"https://controlgraph-{role.value}-{PROJECT_NUMBER}.us-central1.run.app",
        caller=CallerBinding(
            role=caller_role,
            email=f"{account}@{PROJECT_ID}.iam.gserviceaccount.com",
            subject=SUBJECT,
        ),
    )


def _caller(role: ServiceRole) -> AuthenticationContext:
    policy = _policy(role)
    return AuthenticationContext(
        role=policy.caller.role,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=int(datetime(2026, 8, 19, 12, 0, tzinfo=UTC).timestamp()),
        expires_at=int(datetime(2026, 8, 19, 13, 0, tzinfo=UTC).timestamp()),
    )


def _action_shape(action: CapabilityAction) -> tuple[int, int, int | None]:
    if action is CapabilityAction.APPLY_CANARY:
        return 90, 10, None
    if action is CapabilityAction.PROMOTE_CANDIDATE:
        return 0, 100, None
    return 100, 0, 40


def _claims(
    role: ServiceRole,
    *,
    action: CapabilityAction | None = None,
    **overrides: object,
) -> CapabilityClaims:
    root = _root()
    selected_action = action or (
        CapabilityAction.RECOVER_STABLE
        if role is ServiceRole.RECOVERY
        else CapabilityAction.APPLY_CANARY
    )
    stable_percent, candidate_percent, concurrency = _action_shape(selected_action)
    values: dict[str, object] = {
        "schema_version": "controlgraph.capability-claims/v1",
        "capability_id": "cgcap-root-001",
        "issuer": f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com",
        "subject": f"controlgraph-{role.value}@{PROJECT_ID}.iam.gserviceaccount.com",
        "audience": _policy(role).audience,
        "target": root.content.target,
        "root_id": root.root_id,
        "root_sha256": root.root_sha256,
        "epoch": 1,
        "action": selected_action,
        "stable_revision": root.content.rollout_plan.stable_revision,
        "candidate_revision": root.content.rollout_plan.candidate_revision,
        "stable_percent": stable_percent,
        "candidate_percent": candidate_percent,
        "concurrency": concurrency,
        "plan_sha256": canonical_sha256(root.content.rollout_plan),
        "provider_etag": root.content.stable_snapshot.provider_etag,
        "request_id": "request-001",
        "idempotency_key": "intent-001",
        "parent_capability_sha256": None,
        "issued_at": "2026-08-19T12:02:00Z",
        "not_before": "2026-08-19T12:02:00Z",
        "expires_at": "2026-08-19T12:07:00Z",
        "signing_algorithm": "EC_SIGN_P256_SHA256",
        "signing_key_version": CAPABILITY_KEY_VERSION,
    }
    values.update(overrides)
    return CapabilityClaims(**values)  # type: ignore[arg-type]


class _LocalSigningBackend:
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


def _signed(
    claims: CapabilityClaims,
    private_key: ec.EllipticCurvePrivateKey,
) -> SignedCapability:
    profile = SigningProfile.capability(claims.target.project_id, claims.signing_key_version)
    signer = PurposeSealedSigner(
        cast(DigestSigningBackend, _LocalSigningBackend(profile, private_key))
    )
    detached = signer.sign(claims)
    return SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=detached.signature,
    )


def _unchecked_envelope(claims: CapabilityClaims) -> SignedCapability:
    return SignedCapability(
        schema_version="controlgraph.signed-capability/v1",
        claims=claims,
        claims_sha256=canonical_sha256(claims),
        signature=encode_base64url(b"synthetic-unverified-signature"),
    )


def _task(
    capability: SignedCapability,
    **overrides: object,
) -> TaskRequest:
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
    values: dict[str, object] = {
        "schema_version": "controlgraph.task-request/v1",
        "task_id": "task-001",
        "queue_region": claims.target.region,
        "handler_audience": claims.audience,
        "scheduled_at": claims.not_before,
        "expires_at": claims.expires_at,
        "capability": capability,
        "intent": intent,
    }
    values.update(overrides)
    return TaskRequest(**values)  # type: ignore[arg-type]


class _RootReader:
    def __init__(
        self,
        root: RolloutRootV2 | None = None,
        *,
        fail: bool = False,
        revision: int = 0,
        events: list[str] | None = None,
    ) -> None:
        self.root = _root() if root is None else root
        self.target = _root().content.target
        self.fail = fail
        self.revision = revision
        self.events = events
        self.reads: list[str] = []
        self.receipt_claims = 0

    async def read_root_creation_bundle(self, root_id: str) -> RootBundle | None:
        if self.events is not None:
            self.events.append("root-read")
        self.reads.append(root_id)
        if self.fail:
            raise AuthorityStoreUnavailable()
        if root_id != self.root.root_id:
            return None
        _, anchor, default_claim, default_authority = root_records()
        return root_bundle(
            root=self.root,
            anchor=anchor,
            claim=default_claim,
            authority=default_authority,
            root_revision=self.revision,
        )

    def record_receipt_claim(self) -> None:
        self.receipt_claims += 1


class _LineageReader:
    def __init__(
        self,
        lineage: tuple[SignedCapability, ...] | None,
        *,
        fail: bool = False,
    ) -> None:
        self.lineage = lineage
        self.fail = fail
        self.lookups: list[str] = []

    async def resolve_lineage(
        self,
        parent_capability_sha256: str,
    ) -> tuple[SignedCapability, ...] | None:
        self.lookups.append(parent_capability_sha256)
        if self.fail:
            raise RuntimeError("synthetic lineage read failure")
        return self.lineage


def _trust_verifier(
    private_key: ec.EllipticCurvePrivateKey,
) -> TrustBundleVerifier:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_KEY_VERSION)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    bundle = TrustBundle(
        entries=(
            make_trust_bundle_entry(
                profile=profile,
                state=SigningKeyState.ENABLED,
                public_key_pem=public_key_pem,
            ),
        )
    )
    return TrustBundleVerifier(
        VerificationProfile.capability(PROJECT_ID, profile.key_resource),
        bundle,
    )


def _verifier(
    role: ServiceRole,
    private_key: ec.EllipticCurvePrivateKey,
    root_reader: _RootReader,
    lineage_reader: _LineageReader | None = None,
) -> CapabilityVerifier:
    return CapabilityVerifier(
        root_reader=root_reader,
        trust_verifier=_trust_verifier(private_key),
        configuration=CapabilityVerifierConfiguration(
            target=_root().content.target,
            route_policy=_policy(role),
        ),
        lineage_reader=cast(CapabilityLineageReader | None, lineage_reader),
        clock=lambda: NOW,
    )


def _verify(
    verifier: CapabilityVerifier,
    payload: bytes,
    caller: AuthenticationContext,
) -> VerifiedMutation:
    return asyncio.run(verifier.verify(payload, caller))


@pytest.mark.parametrize(
    ("role", "action"),
    [
        (ServiceRole.EXECUTOR, CapabilityAction.APPLY_CANARY),
        (ServiceRole.RECOVERY, CapabilityAction.RECOVER_STABLE),
    ],
)
def test_verifies_legacy_apply_and_recovery_for_both_protected_routes(
    role: ServiceRole,
    action: CapabilityAction,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    root_reader = _RootReader()
    claims = _claims(
        role,
        action=action,
        provider_etag=(
            "etag-canary-8" if action is CapabilityAction.PROMOTE_CANDIDATE else "etag-stable-7"
        ),
    )
    request = _task(_signed(claims, private_key))

    verified = _verify(
        _verifier(role, private_key, root_reader),
        canonical_json_bytes(request),
        _caller(role),
    )

    assert verified.request == request
    assert verified.root == _root()
    assert verified.claims_sha256 == request.capability.claims_sha256
    assert verified.capability_sha256 == canonical_sha256(request.capability)
    assert verified.earliest_lineage_issued_at == int(
        datetime(2026, 8, 19, 12, 2, tzinfo=UTC).timestamp()
    )
    assert root_reader.reads == [_root().root_id]
    assert root_reader.receipt_claims == 0


def test_legacy_promotion_task_is_rejected_before_trusted_reads() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    root_reader = _RootReader()
    request = _task(
        _signed(
            _claims(
                ServiceRole.EXECUTOR,
                action=CapabilityAction.PROMOTE_CANDIDATE,
                provider_etag="etag-canary-8",
            ),
            private_key,
        )
    )

    with pytest.raises(CapabilityVerificationError) as denied:
        _verify(
            _verifier(ServiceRole.EXECUTOR, private_key, root_reader),
            canonical_json_bytes(request),
            _caller(ServiceRole.EXECUTOR),
        )

    assert denied.value.code is ReasonCode.CLAIM_BINDING_MISMATCH
    assert root_reader.reads == []


def test_verifier_configuration_has_no_action_key_or_resource_selector() -> None:
    assert {field.name for field in fields(CapabilityVerifierConfiguration)} == {
        "target",
        "route_policy",
    }


def test_complete_lineage_uses_verified_claim_digests() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    parent = _signed(
        _claims(
            ServiceRole.EXECUTOR,
            capability_id="cgcap-parent-001",
            expires_at="2026-08-19T12:06:00Z",
        ),
        private_key,
    )
    child = _signed(
        _claims(
            ServiceRole.EXECUTOR,
            capability_id="cgcap-child-001",
            parent_capability_sha256=parent.claims_sha256,
            issued_at="2026-08-19T12:03:00Z",
            not_before="2026-08-19T12:03:00Z",
            expires_at="2026-08-19T12:05:00Z",
        ),
        private_key,
    )
    lineage_reader = _LineageReader((parent,))

    verified = _verify(
        _verifier(ServiceRole.EXECUTOR, private_key, _RootReader(), lineage_reader),
        canonical_json_bytes(_task(child)),
        _caller(ServiceRole.EXECUTOR),
    )

    assert verified.claims_sha256 == child.claims_sha256
    assert verified.earliest_lineage_issued_at == int(
        datetime(2026, 8, 19, 12, 2, tzinfo=UTC).timestamp()
    )
    assert lineage_reader.lookups == [parent.claims_sha256]


def test_verified_lineage_records_its_earliest_causal_issuance() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    parent = _signed(
        _claims(
            ServiceRole.EXECUTOR,
            capability_id="cgcap-parent-001",
            issued_at="2026-08-19T12:02:00Z",
            not_before="2026-08-19T12:02:00Z",
            expires_at="2026-08-19T12:06:00Z",
        ),
        private_key,
    )
    child = _signed(
        _claims(
            ServiceRole.EXECUTOR,
            capability_id="cgcap-child-001",
            parent_capability_sha256=parent.claims_sha256,
            issued_at="2026-08-19T12:03:00Z",
            not_before="2026-08-19T12:03:00Z",
            expires_at="2026-08-19T12:05:00Z",
        ),
        private_key,
    )

    verified = _verify(
        _verifier(
            ServiceRole.EXECUTOR,
            private_key,
            _RootReader(),
            _LineageReader((parent,)),
        ),
        canonical_json_bytes(_task(child)),
        _caller(ServiceRole.EXECUTOR),
    )

    assert verified.earliest_lineage_issued_at == int(
        datetime(2026, 8, 19, 12, 2, tzinfo=UTC).timestamp()
    )


@pytest.mark.parametrize(
    ("parent_issued_at", "parent_not_before", "child_issued_at"),
    [
        ("2026-08-19T12:02:00Z", "2026-08-19T12:02:00Z", "2026-08-19T12:01:00Z"),
        ("2026-08-19T12:00:00Z", "2026-08-19T12:02:00Z", "2026-08-19T12:03:00Z"),
    ],
)
def test_lineage_rejects_noncausal_or_preapproval_parent_issuance(
    parent_issued_at: str,
    parent_not_before: str,
    child_issued_at: str,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    parent = _signed(
        _claims(
            ServiceRole.EXECUTOR,
            capability_id="cgcap-parent-temporal",
            issued_at=parent_issued_at,
            not_before=parent_not_before,
            expires_at="2026-08-19T12:06:00Z",
        ),
        private_key,
    )
    child = _signed(
        _claims(
            ServiceRole.EXECUTOR,
            capability_id="cgcap-child-temporal",
            parent_capability_sha256=parent.claims_sha256,
            issued_at=child_issued_at,
            not_before="2026-08-19T12:03:00Z",
            expires_at="2026-08-19T12:05:00Z",
        ),
        private_key,
    )

    with pytest.raises(CapabilityVerificationError) as denied:
        _verify(
            _verifier(
                ServiceRole.EXECUTOR,
                private_key,
                _RootReader(),
                _LineageReader((parent,)),
            ),
            canonical_json_bytes(_task(child)),
            _caller(ServiceRole.EXECUTOR),
        )

    assert denied.value.code is ReasonCode.LINEAGE_INVALID


def test_nonzero_immutable_root_storage_revision_fails_closed() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    request = _task(_signed(_claims(ServiceRole.EXECUTOR), private_key))

    with pytest.raises(CapabilityVerificationError) as denied:
        _verify(
            _verifier(
                ServiceRole.EXECUTOR,
                private_key,
                _RootReader(revision=9),
            ),
            canonical_json_bytes(request),
            _caller(ServiceRole.EXECUTOR),
        )

    assert denied.value.code is ReasonCode.AUTHORITY_UNAVAILABLE


def test_widened_child_lifetime_is_scope_amplification() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    parent = _signed(
        _claims(
            ServiceRole.EXECUTOR,
            capability_id="cgcap-parent-001",
            expires_at="2026-08-19T12:04:00Z",
        ),
        private_key,
    )
    child = _signed(
        _claims(
            ServiceRole.EXECUTOR,
            capability_id="cgcap-child-001",
            parent_capability_sha256=parent.claims_sha256,
            expires_at="2026-08-19T12:05:00Z",
        ),
        private_key,
    )

    with pytest.raises(CapabilityVerificationError) as denied:
        _verify(
            _verifier(
                ServiceRole.EXECUTOR,
                private_key,
                _RootReader(),
                _LineageReader((parent,)),
            ),
            canonical_json_bytes(_task(child)),
            _caller(ServiceRole.EXECUTOR),
        )

    assert denied.value.code is ReasonCode.SCOPE_AMPLIFICATION


class _ExactAuthenticator:
    def __init__(
        self,
        context: AuthenticationContext,
        events: list[str] | None = None,
    ) -> None:
        self.context = context
        self.events = events
        self.calls = 0

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        if self.events is not None:
            self.events.append("caller-admission")
        self.calls += 1
        assert authorization_header == "Bearer exact.test.credential"
        return self.context


def _canonical_raw(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _joined_final_snapshot(*, epoch: int = 1) -> RootBundle:
    root, anchor, claim, initial_authority = root_records()
    authority = EpochAuthorityRecord(
        schema_version="controlgraph.epoch-authority/v1",
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        target=root.content.target,
        current_epoch=epoch,
        previous_epoch=None if epoch == 1 else epoch - 1,
        revision=epoch - 1,
        cause=(EpochChangeCause.ROOT_CREATED if epoch == 1 else EpochChangeCause.RECOVERY),
        changed_by=initial_authority.changed_by,
        request_id=f"request-authority-{epoch}",
        evidence_id=f"evidence-authority-{epoch}",
        changed_at=f"2026-08-19T12:0{epoch}:00Z",
    )
    return root_bundle(
        root=root,
        anchor=anchor,
        claim=claim,
        authority=authority,
    )


def _initial_target_state() -> TargetConfigurationProjection:
    root = _root()
    return TargetConfigurationProjection(
        target=root.content.target,
        stable_revision=root.content.rollout_plan.stable_revision,
        candidate_revision=root.content.rollout_plan.candidate_revision,
        stable_percent=100,
        candidate_percent=0,
        concurrency=root.content.rollout_plan.concurrency,
    )


def _receipt_binding(receipt: ExecutionReceipt) -> tuple[object, ...]:
    return (
        receipt.receipt_id,
        receipt.request_id,
        receipt.idempotency_key,
        receipt.capability_sha256,
        receipt.mutation_sha256,
        receipt.plan_sha256,
        receipt.expected_poststate_sha256,
        receipt.target,
        receipt.root_id,
        receipt.root_sha256,
        receipt.epoch,
        receipt.action,
        receipt.provider_etag,
        receipt.dispatch_not_after,
    )


class _JoinedReceiptStore:
    def __init__(self, events: list[str], *, fail_claim: bool = False) -> None:
        self.target = _target()
        self.events = events
        self.fail_claim = fail_claim
        self.record: StoredRecord[ExecutionReceipt] | None = None
        self._lock = Lock()

    async def claim_or_adopt_receipt(
        self,
        receipt: ExecutionReceipt,
        binding: MutationBinding,
    ) -> ReceiptClaimResult:
        self.events.append("receipt-claim")
        if self.fail_claim:
            raise AuthorityStoreUnavailable()
        validate_receipt_claim_binding(receipt, binding)
        with self._lock:
            if self.record is None:
                self.record = StoredRecord(receipt, 0)
                proof = DirectReceiptCreate._from_direct_store_create(
                    self.record,
                    binding,
                )
                return ReceiptClaimCreated(self.record, proof)
            if _receipt_binding(self.record.value) == _receipt_binding(receipt):
                return ReceiptClaimAdopted(self.record)
            return ReceiptClaimConflict()

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        self.events.append("receipt-read")
        with self._lock:
            if self.record is None or self.record.value.idempotency_key != idempotency_key:
                return None
            return self.record

    async def compare_and_set_receipt(
        self,
        expected: StoredRecord[ExecutionReceipt],
        replacement: ExecutionReceipt,
    ) -> StoredRecord[ExecutionReceipt]:
        self.events.append("receipt-cas")
        with self._lock:
            if self.record != expected:
                raise AuthorityStoreConflict()
            self.record = StoredRecord(replacement, expected.revision + 1)
            return self.record


class _JoinedFinalAuthorityReader:
    def __init__(
        self,
        events: list[str],
        snapshot: RootBundle,
        *,
        error: Exception | None = None,
    ) -> None:
        self.target = _target()
        self.events = events
        self._snapshot = snapshot
        self._snapshot_lock = Lock()
        self.error = error
        self.pause = False
        self.started = Event()
        self.resume = Event()

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootBundle:
        assert root_id == _root().root_id
        self.events.append("final-authority-read")
        self.started.set()
        if self.pause:
            resumed = await asyncio.to_thread(self.resume.wait, 2)
            if not resumed:
                raise AuthorityStoreUnavailable()
        if self.error is not None:
            raise self.error
        with self._snapshot_lock:
            return self._snapshot

    def replace_snapshot(self, snapshot: RootBundle) -> None:
        if type(snapshot) is not RootBundle:
            raise TypeError("an exact root authority bundle is required")
        with self._snapshot_lock:
            self._snapshot = snapshot


class _JoinedCloudRunAdapter:
    def __init__(self, role: ServiceRole, events: list[str]) -> None:
        self.target = _target()
        self.service_role = role
        self.events = events
        self.calls: list[MutationIntent] = []
        self._state = _initial_target_state()
        self._lock = Lock()
        self._prepared_intent: MutationIntent | None = None

    @property
    def intent(self) -> MutationIntent:
        assert self._prepared_intent is not None
        return self._prepared_intent

    async def prepare(self, intent: MutationIntent) -> _JoinedCloudRunAdapter:
        self._prepared_intent = intent
        return self

    @property
    def state(self) -> TargetConfigurationProjection:
        with self._lock:
            return self._state

    async def mutate(self, permit: MutationPermit) -> CloudRunMutationResult:
        self.events.append("cloud-run-adapter")
        intent = permit.intent
        projected = target_configuration_projection(
            intent,
            expected_concurrency=_root().content.rollout_plan.concurrency,
        )
        with self._lock:
            self.calls.append(intent)
            self._state = projected
        return CloudRunMutationResult(
            outcome=CloudRunMutationOutcome.AMBIGUOUS,
            requested_traffic=(
                CloudRunTrafficAllocation(
                    revision=intent.stable_revision,
                    percent=intent.stable_percent,
                    tag="stable",
                ),
                CloudRunTrafficAllocation(
                    revision=intent.candidate_revision,
                    percent=intent.candidate_percent,
                    tag="candidate",
                ),
            ),
            expected_concurrency=projected.concurrency,
            operation_name="operations/joined-conformance-001",
            service=None,
            reason=CloudRunMutationReason.OUTCOME_UNKNOWN,
        )


class _JoinedReadback:
    def __init__(self, adapter: _JoinedCloudRunAdapter, events: list[str]) -> None:
        self.target = _target()
        self.adapter = adapter
        self.events = events

    async def readback(
        self,
        expected: TargetConfigurationProjection,
    ) -> ReceiptReadbackResult:
        self.events.append("target-readback")
        state = self.adapter.state
        return ReceiptReadbackResult(
            state=state,
            observed_etag=("etag-after-joined-8" if state == expected else "etag-stable-7"),
        )


class _JoinedConformancePath:
    def __init__(
        self,
        role: ServiceRole,
        private_key: ec.EllipticCurvePrivateKey,
        root_reader: _RootReader,
        caller: AuthenticationContext,
        lineage_reader: _LineageReader | None = None,
        *,
        final_snapshot: RootBundle | None = None,
        final_error: Exception | None = None,
        fail_claim: bool = False,
    ) -> None:
        self.events: list[str] = []
        self.handler_entries: list[VerifiedMutation] = []
        root_reader.events = self.events
        self.store = _JoinedReceiptStore(self.events, fail_claim=fail_claim)
        self.final_reader = _JoinedFinalAuthorityReader(
            self.events,
            final_snapshot or _joined_final_snapshot(),
            error=final_error,
        )
        self.cloud_run_adapter = _JoinedCloudRunAdapter(role, self.events)
        classifying_adapter = ReceiptClassifyingMutationAdapter(self.cloud_run_adapter)
        coordinator = ReceiptExecutionCoordinator(
            store=self.store,
            final_gate=FinalMutationGate(
                authority_reader=self.final_reader,
                adapter=classifying_adapter,
                route_policy=_policy(role),
                clock=lambda: NOW,
            ),
            readback=_JoinedReadback(self.cloud_run_adapter, self.events),
            clock=lambda: NOW,
        )
        receipt_handler = create_receipt_task_handler(coordinator)

        async def traced_handler(verified: VerifiedMutation) -> Response:
            self.events.append("verified-handler")
            self.handler_entries.append(verified)
            return await receipt_handler(verified)

        self.authenticator = _ExactAuthenticator(caller, self.events)
        self.app = create_service_app(
            role,
            authenticator=self.authenticator,
            authentication_policy=_policy(role),
            capability_verifier=_verifier(
                role,
                private_key,
                root_reader,
                lineage_reader,
            ),
            verified_task_handler=traced_handler,
            mutation_enabled=True,
        )


def _post_task(
    client: TestClient,
    role: ServiceRole,
    payload: bytes,
) -> ClientResponse:
    return client.post(
        protected_path(role),
        content=payload,
        headers={
            "Authorization": "Bearer exact.test.credential",
            "Content-Type": "application/json",
        },
    )


def _denial_scenario(
    role: ServiceRole,
    name: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> tuple[
    bytes,
    AuthenticationContext,
    _RootReader,
    _LineageReader | None,
    ReasonCode,
]:
    caller = _caller(role)
    root_reader = _RootReader()
    lineage_reader: _LineageReader | None = None
    capability = _signed(_claims(role), private_key)
    request = _task(capability)
    payload = canonical_json_bytes(request)
    expected = ReasonCode.CONTRACT_INVALID

    if name == "malformed":
        payload = b"{"
    elif name == "noncanonical":
        payload = json.dumps(request.model_dump(mode="json"), indent=2).encode("utf-8")
    elif name == "version":
        raw = request.model_dump(mode="json")
        raw["schema_version"] = "controlgraph.task-request/v2"
        payload = _canonical_raw(raw)
        expected = ReasonCode.CONTRACT_VERSION_UNSUPPORTED
    elif name == "claims_digest":
        raw = request.model_dump(mode="json")
        raw["capability"]["claims_sha256"] = "f" * 64
        payload = _canonical_raw(raw)
    elif name == "signature":
        invalid = SignedCapability(
            schema_version=capability.schema_version,
            claims=capability.claims,
            claims_sha256=capability.claims_sha256,
            signature=encode_base64url(b"synthetic-invalid-signature"),
        )
        payload = canonical_json_bytes(_task(invalid))
        expected = ReasonCode.SIGNATURE_INVALID
    elif name == "key_version":
        untrusted = _signed(
            _claims(role, signing_key_version=UNTRUSTED_KEY_VERSION),
            private_key,
        )
        payload = canonical_json_bytes(_task(untrusted))
        expected = ReasonCode.KEY_VERSION_UNTRUSTED
    elif name == "public_key_url":
        raw = request.model_dump(mode="json")
        raw["capability"]["public_key_url"] = "https://keys.example.test/key.pem"
        payload = _canonical_raw(raw)
    elif name == "target_injection":
        raw = request.model_dump(mode="json")
        raw["intent"]["target"]["provider_resource"] = (
            f"projects/{PROJECT_ID}/locations/us-central1/services/other-target"
        )
        payload = _canonical_raw(raw)
    elif name == "algorithm":
        raw = request.model_dump(mode="json")
        raw["capability"]["claims"]["signing_algorithm"] = "RS256"
        payload = _canonical_raw(raw)
    elif name == "caller":
        caller = replace(caller, email=f"other@{PROJECT_ID}.iam.gserviceaccount.com")
        expected = ReasonCode.CALLER_UNAUTHORIZED
    elif name == "caller_expired":
        caller = replace(caller, expires_at=int(NOW.timestamp()))
        expected = ReasonCode.CALLER_UNAUTHORIZED
    elif name == "issuer":
        altered = _signed(_claims(role, issuer="controlgraph-other/v1"), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.CLAIM_BINDING_MISMATCH
    elif name == "subject":
        alternate_subject = (
            f"controlgraph-recovery@{PROJECT_ID}.iam.gserviceaccount.com"
            if role is ServiceRole.EXECUTOR
            else f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"
        )
        altered = _signed(_claims(role, subject=alternate_subject), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.CLAIM_BINDING_MISMATCH
    elif name == "audience":
        alternate_audience = f"https://controlgraph-{role.value}-999999999999.us-central1.run.app"
        altered = _signed(_claims(role, audience=alternate_audience), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.CLAIM_BINDING_MISMATCH
    elif name in {"project", "region"}:
        target = (
            _target(project_id=OTHER_PROJECT_ID)
            if name == "project"
            else _target(region="europe-west1")
        )
        altered_claims = _claims(role, target=target)
        payload = canonical_json_bytes(_task(_unchecked_envelope(altered_claims)))
        expected = ReasonCode.TARGET_BINDING_MISMATCH
    elif name in {"environment", "service"}:
        target = (
            _target(environment="alternate")
            if name == "environment"
            else _target(service_name="other-target")
        )
        altered = _signed(_claims(role, target=target), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.TARGET_BINDING_MISMATCH
    elif name == "revision":
        altered = _signed(
            _claims(
                role,
                stable_revision="controlgraph-reference-target-other-stable",
            ),
            private_key,
        )
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.TARGET_BINDING_MISMATCH
    elif name == "queue_region":
        payload = canonical_json_bytes(_task(capability, queue_region="europe-west1"))
        expected = ReasonCode.TARGET_BINDING_MISMATCH
    elif name == "handler_audience":
        raw = request.model_dump(mode="json")
        raw["handler_audience"] = "https://other-handler.example.test"
        payload = _canonical_raw(raw)
    elif name == "plan":
        altered = _signed(_claims(role, plan_sha256=THREE_DIGEST), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.CLAIM_BINDING_MISMATCH
    elif name == "precondition":
        if role is ServiceRole.EXECUTOR:
            altered = _signed(_claims(role, provider_etag="etag-other-8"), private_key)
            payload = canonical_json_bytes(_task(altered))
            expected = ReasonCode.TARGET_BINDING_MISMATCH
        else:
            raw = request.model_dump(mode="json")
            raw["intent"]["provider_etag"] = "etag-other-8"
            payload = _canonical_raw(raw)
    elif name == "idempotency":
        raw = request.model_dump(mode="json")
        raw["intent"]["idempotency_key"] = "intent-other"
        payload = _canonical_raw(raw)
    elif name == "request_id":
        raw = request.model_dump(mode="json")
        raw["intent"]["request_id"] = "request-other"
        payload = _canonical_raw(raw)
    elif name == "traffic":
        raw = request.model_dump(mode="json")
        raw["intent"]["candidate_percent"] = 11
        payload = _canonical_raw(raw)
    elif name == "concurrency":
        concurrency = 41 if role is ServiceRole.RECOVERY else 40
        altered = _signed(_claims(role, concurrency=concurrency), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = (
            ReasonCode.TARGET_BINDING_MISMATCH
            if role is ServiceRole.RECOVERY
            else ReasonCode.CLAIM_BINDING_MISMATCH
        )
    elif name == "action_route":
        action = (
            CapabilityAction.APPLY_CANARY
            if role is ServiceRole.RECOVERY
            else CapabilityAction.RECOVER_STABLE
        )
        altered = _signed(_claims(role, action=action), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.CLAIM_BINDING_MISMATCH
    elif name == "not_yet_valid":
        altered = _signed(
            _claims(
                role,
                not_before="2026-08-19T12:04:00Z",
                expires_at="2026-08-19T12:07:00Z",
            ),
            private_key,
        )
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.CAPABILITY_NOT_YET_VALID
    elif name == "expired":
        altered = _signed(
            _claims(role, expires_at="2026-08-19T12:03:00Z"),
            private_key,
        )
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.CAPABILITY_EXPIRED
    elif name == "task_expired":
        payload = canonical_json_bytes(_task(capability, expires_at="2026-08-19T12:03:00Z"))
        expected = ReasonCode.CAPABILITY_EXPIRED
    elif name == "root_id":
        altered = _signed(_claims(role, root_id="root-other"), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.LINEAGE_INVALID
    elif name == "root_digest":
        altered = _signed(_claims(role, root_sha256="f" * 64), private_key)
        payload = canonical_json_bytes(_task(altered))
        expected = ReasonCode.LINEAGE_INVALID
    elif name == "missing_lineage":
        child = _signed(_claims(role, parent_capability_sha256="e" * 64), private_key)
        payload = canonical_json_bytes(_task(child))
        lineage_reader = _LineageReader(None)
        expected = ReasonCode.LINEAGE_INVALID
    elif name == "scope_amplification":
        parent = _signed(
            _claims(
                role,
                capability_id="cgcap-parent-001",
                expires_at="2026-08-19T12:04:00Z",
            ),
            private_key,
        )
        child = _signed(
            _claims(
                role,
                capability_id="cgcap-child-001",
                parent_capability_sha256=parent.claims_sha256,
                expires_at="2026-08-19T12:05:00Z",
            ),
            private_key,
        )
        payload = canonical_json_bytes(_task(child))
        lineage_reader = _LineageReader((parent,))
        expected = ReasonCode.SCOPE_AMPLIFICATION
    elif name == "lineage_signature":
        parent = _signed(
            _claims(role, capability_id="cgcap-parent-001"),
            private_key,
        )
        invalid_parent = SignedCapability(
            schema_version=parent.schema_version,
            claims=parent.claims,
            claims_sha256=parent.claims_sha256,
            signature=encode_base64url(b"synthetic-invalid-parent-signature"),
        )
        child = _signed(
            _claims(
                role,
                capability_id="cgcap-child-001",
                parent_capability_sha256=parent.claims_sha256,
            ),
            private_key,
        )
        payload = canonical_json_bytes(_task(child))
        lineage_reader = _LineageReader((invalid_parent,))
        expected = ReasonCode.SIGNATURE_INVALID
    elif name == "lineage_duplicate":
        parent = _signed(
            _claims(role, capability_id="cgcap-shared-001"),
            private_key,
        )
        child = _signed(
            _claims(
                role,
                capability_id="cgcap-shared-001",
                parent_capability_sha256=parent.claims_sha256,
            ),
            private_key,
        )
        payload = canonical_json_bytes(_task(child))
        lineage_reader = _LineageReader((parent,))
        expected = ReasonCode.LINEAGE_INVALID
    elif name == "lineage_uncertain":
        child = _signed(_claims(role, parent_capability_sha256="e" * 64), private_key)
        payload = canonical_json_bytes(_task(child))
        lineage_reader = _LineageReader(None, fail=True)
        expected = ReasonCode.AUTHORITY_UNAVAILABLE
    elif name == "authority_uncertain":
        root_reader = _RootReader(fail=True)
        expected = ReasonCode.AUTHORITY_UNAVAILABLE
    else:
        raise AssertionError(f"unknown denial scenario: {name}")
    return payload, caller, root_reader, lineage_reader, expected


_DENIAL_SCENARIOS = (
    "malformed",
    "noncanonical",
    "version",
    "claims_digest",
    "signature",
    "key_version",
    "public_key_url",
    "target_injection",
    "algorithm",
    "caller",
    "caller_expired",
    "issuer",
    "subject",
    "audience",
    "project",
    "region",
    "environment",
    "service",
    "revision",
    "queue_region",
    "handler_audience",
    "plan",
    "precondition",
    "idempotency",
    "request_id",
    "traffic",
    "concurrency",
    "action_route",
    "not_yet_valid",
    "expired",
    "task_expired",
    "root_id",
    "root_digest",
    "missing_lineage",
    "scope_amplification",
    "lineage_signature",
    "lineage_duplicate",
    "lineage_uncertain",
    "authority_uncertain",
)


@pytest.mark.parametrize("role", [ServiceRole.EXECUTOR, ServiceRole.RECOVERY])
@pytest.mark.parametrize("scenario", _DENIAL_SCENARIOS)
def test_initial_and_retried_denials_never_enter_handler_or_claim_receipt(
    role: ServiceRole,
    scenario: str,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    payload, caller, root_reader, lineage_reader, expected = _denial_scenario(
        role,
        scenario,
        private_key,
    )
    joined = _JoinedConformancePath(
        role,
        private_key,
        root_reader,
        caller,
        lineage_reader,
    )
    with TestClient(joined.app) as client:
        responses = [_post_task(client, role, payload) for _ in range(2)]

    assert [response.json()["code"] for response in responses] == [
        expected.value,
        expected.value,
    ]
    assert joined.handler_entries == []
    assert joined.store.record is None
    assert joined.cloud_run_adapter.calls == []
    assert joined.cloud_run_adapter.state == _initial_target_state()
    assert "receipt-claim" not in joined.events
    assert "final-authority-read" not in joined.events
    assert "cloud-run-adapter" not in joined.events
    assert joined.authenticator.calls == 2


@pytest.mark.parametrize(
    ("role", "action"),
    [
        (ServiceRole.EXECUTOR, CapabilityAction.APPLY_CANARY),
        (ServiceRole.RECOVERY, CapabilityAction.RECOVER_STABLE),
    ],
)
def test_initial_and_retried_valid_tasks_share_the_verified_handler_gate(
    role: ServiceRole,
    action: CapabilityAction,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    root_reader = _RootReader()
    request = _task(_signed(_claims(role, action=action), private_key))
    payload = canonical_json_bytes(request)
    joined = _JoinedConformancePath(
        role,
        private_key,
        root_reader,
        _caller(role),
    )
    with TestClient(joined.app) as client:
        responses = [_post_task(client, role, payload) for _ in range(2)]

    assert [response.status_code for response in responses] == [200, 200]
    assert responses[0].content == responses[1].content
    assert responses[0].json()["schema_version"] == ("controlgraph.receipt-task-response/v1")
    assert responses[0].json()["receipt"]["outcome"] == ReceiptOutcome.VERIFIED.value
    assert responses[0].json()["storage_revision"] == 2
    assert responses[0].json()["receipt"]["provider_operation"] == (
        "operations/joined-conformance-001"
    )
    assert responses[0].json()["receipt"]["observed_etag"] == "etag-after-joined-8"
    assert responses[0].json()["receipt"]["observed_authority_epoch"] == 1
    assert [entry.request for entry in joined.handler_entries] == [request, request]
    assert len(joined.cloud_run_adapter.calls) == 1
    assert joined.cloud_run_adapter.state == target_configuration_projection(
        request.intent,
        expected_concurrency=_root().content.rollout_plan.concurrency,
    )


def test_delayed_stale_task_is_fenced_when_epoch_advances_at_final_read() -> None:
    role = ServiceRole.EXECUTOR
    private_key = ec.generate_private_key(ec.SECP256R1())
    request = _task(_signed(_claims(role), private_key))
    payload = canonical_json_bytes(request)
    joined = _JoinedConformancePath(
        role,
        private_key,
        _RootReader(),
        _caller(role),
    )
    joined.final_reader.pause = True

    with (
        TestClient(joined.app) as client,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        response_future = executor.submit(_post_task, client, role, payload)
        assert joined.final_reader.started.wait(2)
        joined.final_reader.replace_snapshot(_joined_final_snapshot(epoch=2))
        joined.final_reader.resume.set()
        first = response_future.result(timeout=3)
        first_trace = tuple(joined.events)
        replay = _post_task(client, role, payload)

    assert first.status_code == 200
    assert replay.status_code == 200
    assert first.content == replay.content
    body = first.json()
    assert body["schema_version"] == "controlgraph.receipt-task-response/v1"
    assert body["storage_revision"] == 1
    assert body["receipt"]["outcome"] == ReceiptOutcome.DENIED.value
    assert body["receipt"]["reason_code"] == ReasonCode.EPOCH_MISMATCH.value
    assert body["receipt"]["observed_authority_epoch"] == 2
    assert body["receipt"]["request_id"] == request.intent.request_id
    assert body["receipt"]["root_sha256"] == request.intent.root_sha256
    assert first_trace == (
        "caller-admission",
        "root-read",
        "verified-handler",
        "receipt-claim",
        "final-authority-read",
        "receipt-cas",
    )
    assert tuple(joined.events[len(first_trace) :]) == (
        "caller-admission",
        "root-read",
        "verified-handler",
        "receipt-claim",
    )
    assert joined.cloud_run_adapter.calls == []
    assert joined.cloud_run_adapter.state == _initial_target_state()


@pytest.mark.parametrize("stage", ["claim", "final-authority"])
def test_postverification_store_uncertainty_fails_closed_at_its_exact_boundary(
    stage: str,
) -> None:
    role = ServiceRole.EXECUTOR
    private_key = ec.generate_private_key(ec.SECP256R1())
    request = _task(_signed(_claims(role), private_key))
    joined = _JoinedConformancePath(
        role,
        private_key,
        _RootReader(),
        _caller(role),
        fail_claim=stage == "claim",
        final_error=(AuthorityStoreUnavailable() if stage == "final-authority" else None),
    )

    with TestClient(joined.app) as client:
        response = _post_task(client, role, canonical_json_bytes(request))

    assert joined.cloud_run_adapter.calls == []
    assert joined.cloud_run_adapter.state == _initial_target_state()
    if stage == "claim":
        assert response.status_code == 503
        assert response.json() == {
            "schema_version": "controlgraph.receipt-task-denial/v1",
            "code": ReasonCode.AUTHORITY_UNAVAILABLE.value,
        }
        assert joined.store.record is None
        assert joined.events == [
            "caller-admission",
            "root-read",
            "verified-handler",
            "receipt-claim",
        ]
    else:
        assert response.status_code == 200
        assert response.json()["receipt"]["outcome"] == ReceiptOutcome.DENIED.value
        assert response.json()["receipt"]["reason_code"] == (ReasonCode.AUTHORITY_UNAVAILABLE.value)
        assert response.json()["receipt"]["observed_authority_epoch"] is None
        assert joined.store.record is not None
        assert joined.events == [
            "caller-admission",
            "root-read",
            "verified-handler",
            "receipt-claim",
            "final-authority-read",
            "receipt-cas",
        ]


def test_conflicting_verified_payload_cannot_overwrite_the_first_receipt() -> None:
    role = ServiceRole.EXECUTOR
    private_key = ec.generate_private_key(ec.SECP256R1())
    original = _task(_signed(_claims(role), private_key))
    conflicting = _task(
        _signed(
            _claims(
                role,
                capability_id="cgcap-conflicting-001",
                request_id="request-conflicting-001",
            ),
            private_key,
        )
    )
    joined = _JoinedConformancePath(
        role,
        private_key,
        _RootReader(),
        _caller(role),
        final_snapshot=_joined_final_snapshot(epoch=2),
    )

    with TestClient(joined.app) as client:
        first = _post_task(client, role, canonical_json_bytes(original))
        first_record = joined.store.record
        trace_boundary = len(joined.events)
        denied = _post_task(client, role, canonical_json_bytes(conflicting))

    assert first.status_code == 200
    assert denied.status_code == 409
    assert denied.json() == {
        "schema_version": "controlgraph.receipt-task-denial/v1",
        "code": ReasonCode.IDEMPOTENCY_CONFLICT.value,
    }
    assert joined.store.record == first_record
    assert joined.store.record is not None
    assert joined.store.record.value.request_id == original.intent.request_id
    assert tuple(joined.events[trace_boundary:]) == (
        "caller-admission",
        "root-read",
        "verified-handler",
        "receipt-claim",
    )
    assert joined.cloud_run_adapter.calls == []
    assert joined.cloud_run_adapter.state == _initial_target_state()


def test_concurrent_exact_duplicate_has_one_joined_cloud_run_dispatch() -> None:
    role = ServiceRole.EXECUTOR
    private_key = ec.generate_private_key(ec.SECP256R1())
    request = _task(_signed(_claims(role), private_key))
    payload = canonical_json_bytes(request)
    joined = _JoinedConformancePath(
        role,
        private_key,
        _RootReader(),
        _caller(role),
    )
    joined.final_reader.pause = True

    with (
        TestClient(joined.app) as first_client,
        TestClient(joined.app) as duplicate_client,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        winner_future = executor.submit(_post_task, first_client, role, payload)
        assert joined.final_reader.started.wait(2)
        duplicate = _post_task(duplicate_client, role, payload)
        joined.final_reader.resume.set()
        winner = winner_future.result(timeout=3)
        replay = _post_task(duplicate_client, role, payload)

    assert duplicate.status_code == 503
    assert duplicate.json()["receipt"]["outcome"] == ReceiptOutcome.CLAIMED.value
    assert duplicate.json()["storage_revision"] == 0
    assert winner.status_code == 200
    assert winner.json()["receipt"]["outcome"] == ReceiptOutcome.VERIFIED.value
    assert winner.content == replay.content
    assert len(joined.cloud_run_adapter.calls) == 1
    assert joined.events.count("final-authority-read") == 1
    assert joined.events.count("cloud-run-adapter") == 1
    assert joined.events.count("target-readback") == 1
    assert joined.events.count("receipt-cas") == 2


def test_receipt_http_composition_rejects_a_noncoordinator_bypass() -> None:
    with pytest.raises(TypeError, match="exact receipt execution coordinator"):
        create_receipt_task_handler(cast(ReceiptExecutionCoordinator, object()))


def test_http_composition_cannot_install_a_task_handler_without_the_verifier() -> None:
    async def protected_handler(verified: VerifiedMutation) -> JSONResponse:
        return JSONResponse(status_code=202, content={"status": verified.claims_sha256})

    with pytest.raises(ValueError, match="requires capability verification"):
        create_service_app(
            ServiceRole.EXECUTOR,
            authenticator=_ExactAuthenticator(_caller(ServiceRole.EXECUTOR)),
            authentication_policy=_policy(ServiceRole.EXECUTOR),
            verified_task_handler=protected_handler,
        )

    private_key = ec.generate_private_key(ec.SECP256R1())
    verifier = _verifier(ServiceRole.EXECUTOR, private_key, _RootReader())
    with pytest.raises(ValueError, match="requires mutation enablement"):
        create_service_app(
            ServiceRole.EXECUTOR,
            authenticator=_ExactAuthenticator(_caller(ServiceRole.EXECUTOR)),
            authentication_policy=_policy(ServiceRole.EXECUTOR),
            capability_verifier=verifier,
            verified_task_handler=protected_handler,
        )
    with pytest.raises(ValueError, match="complete protected task path"):
        create_service_app(
            ServiceRole.EXECUTOR,
            authenticator=_ExactAuthenticator(_caller(ServiceRole.EXECUTOR)),
            authentication_policy=_policy(ServiceRole.EXECUTOR),
            capability_verifier=verifier,
            mutation_enabled=True,
        )


def test_root_and_lineage_read_failures_are_distinct_from_invalid_signatures() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    valid = _task(_signed(_claims(ServiceRole.EXECUTOR), private_key))
    with pytest.raises(CapabilityVerificationError) as unavailable:
        _verify(
            _verifier(ServiceRole.EXECUTOR, private_key, _RootReader(fail=True)),
            canonical_json_bytes(valid),
            _caller(ServiceRole.EXECUTOR),
        )
    assert unavailable.value.code is ReasonCode.AUTHORITY_UNAVAILABLE

    invalid = _task(
        SignedCapability(
            schema_version=valid.capability.schema_version,
            claims=valid.capability.claims,
            claims_sha256=valid.capability.claims_sha256,
            signature=encode_base64url(b"synthetic-invalid-signature"),
        )
    )
    reader = _RootReader(fail=True)
    with pytest.raises(CapabilityVerificationError) as signature_denial:
        _verify(
            _verifier(ServiceRole.EXECUTOR, private_key, reader),
            canonical_json_bytes(invalid),
            _caller(ServiceRole.EXECUTOR),
        )
    assert signature_denial.value.code is ReasonCode.SIGNATURE_INVALID
    assert reader.reads == []


def test_untrusted_key_version_is_not_reported_as_an_invalid_signature() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    capability = _signed(
        _claims(ServiceRole.EXECUTOR, signing_key_version=UNTRUSTED_KEY_VERSION),
        private_key,
    )

    with pytest.raises(CapabilityVerificationError) as denied:
        _verify(
            _verifier(ServiceRole.EXECUTOR, private_key, _RootReader()),
            canonical_json_bytes(_task(capability)),
            _caller(ServiceRole.EXECUTOR),
        )

    assert denied.value.code is ReasonCode.KEY_VERSION_UNTRUSTED


@pytest.mark.parametrize(
    "target",
    [
        _target(project_id=OTHER_PROJECT_ID),
        _target(region="europe-west1"),
        _target(environment="alternate"),
        _target(service_name="other-target"),
    ],
)
def test_configured_target_substitution_precedes_signature_and_root_lookup(
    target: TargetBinding,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    reader = _RootReader(fail=True)
    capability = _unchecked_envelope(_claims(ServiceRole.EXECUTOR, target=target))

    with pytest.raises(CapabilityVerificationError) as denied:
        _verify(
            _verifier(ServiceRole.EXECUTOR, private_key, reader),
            canonical_json_bytes(_task(capability)),
            _caller(ServiceRole.EXECUTOR),
        )

    assert denied.value.code is ReasonCode.TARGET_BINDING_MISMATCH
    assert reader.reads == []
