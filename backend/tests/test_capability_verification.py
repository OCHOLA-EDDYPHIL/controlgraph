from __future__ import annotations

import asyncio
import json
from dataclasses import fields, replace
from datetime import UTC, datetime
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from controlgraph_canary.application.authority_store import (
    AuthorityStoreUnavailable,
    StoredRecord,
)
from controlgraph_canary.application.capability_verification import (
    CapabilityLineageReader,
    CapabilityVerificationError,
    CapabilityVerifier,
    CapabilityVerifierConfiguration,
    VerifiedMutation,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
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
from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityClaims,
    MutationIntent,
    ReasonCode,
    RolloutRoot,
    SignedCapability,
    StableSnapshot,
    TargetBinding,
    TaskRequest,
    TrafficAllocation,
    canonical_json_bytes,
    canonical_sha256,
    encode_base64url,
)
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
        "environment": "acceptance",
        "service_name": "reference-target",
    }
    values.update(overrides)
    return TargetBinding(**values)  # type: ignore[arg-type]


def _root() -> RolloutRoot:
    target = _target()
    snapshot = StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=target,
        stable_revision="reference-target-stable",
        traffic=(TrafficAllocation(revision="reference-target-stable", percent=100),),
        concurrency=40,
        service_generation=7,
        provider_etag="etag-stable-7",
        configuration_sha256=ZERO_DIGEST,
        captured_at="2026-08-19T12:00:00Z",
        captured_by="controlgraph.operator/v1",
    )
    return RolloutRoot(
        schema_version="controlgraph.rollout-root/v1",
        root_id="root-001",
        target=target,
        stable_snapshot=snapshot,
        candidate_revision="reference-target-candidate",
        stable_percent=90,
        candidate_percent=10,
        health_policy_sha256=ONE_DIGEST,
        maximum_recovery_attempts=1,
        initial_epoch=1,
        plan_sha256=TWO_DIGEST,
        approved_by="controlgraph.operator/v1",
        approved_at="2026-08-19T12:01:00Z",
    )


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
        "target": root.target,
        "root_id": root.root_id,
        "root_sha256": canonical_sha256(root),
        "epoch": 1,
        "action": selected_action,
        "stable_revision": root.stable_snapshot.stable_revision,
        "candidate_revision": root.candidate_revision,
        "stable_percent": stable_percent,
        "candidate_percent": candidate_percent,
        "concurrency": concurrency,
        "plan_sha256": root.plan_sha256,
        "provider_etag": root.stable_snapshot.provider_etag,
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
    def __init__(self, root: RolloutRoot | None = None, *, fail: bool = False) -> None:
        self.root = _root() if root is None else root
        self.target = _root().target
        self.fail = fail
        self.reads: list[str] = []
        self.receipt_claims = 0

    async def read_rollout_root(self, root_id: str) -> StoredRecord[RolloutRoot] | None:
        self.reads.append(root_id)
        if self.fail:
            raise AuthorityStoreUnavailable()
        if root_id != self.root.root_id:
            return None
        return StoredRecord(value=self.root, revision=0)

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
            target=_root().target,
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
        (ServiceRole.EXECUTOR, CapabilityAction.PROMOTE_CANDIDATE),
        (ServiceRole.RECOVERY, CapabilityAction.RECOVER_STABLE),
    ],
)
def test_verifies_closed_signed_actions_for_both_protected_routes(
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
    assert root_reader.reads == ["root-001"]
    assert root_reader.receipt_claims == 0


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
    assert lineage_reader.lookups == [parent.claims_sha256]


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
    def __init__(self, context: AuthenticationContext) -> None:
        self.context = context
        self.calls = 0

    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
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
        alternate_audience = (
            f"https://controlgraph-{role.value}-999999999999.us-central1.run.app"
        )
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
        expected = ReasonCode.KEY_VERSION_UNTRUSTED
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
            _claims(role, stable_revision="reference-target-other-stable"),
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
        payload = canonical_json_bytes(
            _task(capability, expires_at="2026-08-19T12:03:00Z")
        )
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
    authenticator = _ExactAuthenticator(caller)
    handler_entries: list[VerifiedMutation] = []

    async def protected_handler(verified: VerifiedMutation) -> JSONResponse:
        handler_entries.append(verified)
        root_reader.record_receipt_claim()
        return JSONResponse(status_code=202, content={"status": "accepted"})

    client = TestClient(
        create_service_app(
            role,
            authenticator=authenticator,
            authentication_policy=_policy(role),
            capability_verifier=_verifier(
                role,
                private_key,
                root_reader,
                lineage_reader,
            ),
            verified_task_handler=protected_handler,
        )
    )

    responses = [
        client.post(
            protected_path(role),
            content=payload,
            headers={
                "Authorization": "Bearer exact.test.credential",
                "Content-Type": "application/json",
            },
        )
        for _ in range(2)
    ]

    assert [response.json()["code"] for response in responses] == [
        expected.value,
        expected.value,
    ]
    assert handler_entries == []
    assert root_reader.receipt_claims == 0
    assert authenticator.calls == 2


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
    handler_entries: list[VerifiedMutation] = []

    async def protected_handler(verified: VerifiedMutation) -> JSONResponse:
        handler_entries.append(verified)
        root_reader.record_receipt_claim()
        return JSONResponse(status_code=202, content={"status": "accepted"})

    client = TestClient(
        create_service_app(
            role,
            authenticator=_ExactAuthenticator(_caller(role)),
            authentication_policy=_policy(role),
            capability_verifier=_verifier(role, private_key, root_reader),
            verified_task_handler=protected_handler,
        )
    )

    responses = [
        client.post(
            protected_path(role),
            content=canonical_json_bytes(request),
            headers={
                "Authorization": "Bearer exact.test.credential",
                "Content-Type": "application/json",
            },
        )
        for _ in range(2)
    ]

    assert [response.status_code for response in responses] == [202, 202]
    assert [entry.request for entry in handler_entries] == [request, request]
    assert root_reader.receipt_claims == 2


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
