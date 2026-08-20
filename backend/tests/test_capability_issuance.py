import asyncio
from collections.abc import Callable
from dataclasses import fields
from datetime import UTC, datetime
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from root_v2_support import RootBundle, root_bundle, root_records, service_audience

from controlgraph_canary.application.authority_store import (
    AuthorityStoreUnavailable,
)
from controlgraph_canary.application.capability_issuance import (
    MAX_CAPABILITY_LIFETIME_SECONDS,
    AuthenticatedIssuancePrincipal,
    CapabilityEnvelopeVerifier,
    CapabilityIssuanceError,
    CapabilityIssuanceErrorCode,
    CapabilityIssuanceRequest,
    CapabilityIssuer,
    CapabilityIssuerConfiguration,
    TrustBundleCapabilityVerifier,
)
from controlgraph_canary.application.signing import (
    DigestSigningBackend,
    PurposeSealedSigner,
    SigningError,
    SigningKeyState,
    SigningProfile,
    TrustBundle,
    TrustBundleVerifier,
    VerificationProfile,
    build_signing_input,
    make_trust_bundle_entry,
)
from controlgraph_canary.authority import EpochCheckOutcome, check_epoch
from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityClaims,
    EpochAuthorityRecord,
    EpochChangeCause,
    RolloutRootV2,
    SignedCapability,
    TargetBinding,
    canonical_sha256,
    encode_base64url,
)
from controlgraph_canary.contracts.base import MAX_SAFE_INTEGER
from controlgraph_canary.contracts.storage import (
    SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
    SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
    ServiceClaimRecord,
    ServiceClaimStatus,
    ServiceClaimTargetClassification,
    ServiceClaimTargetClassificationProof,
    ServiceClaimTerminalRootProof,
    ServiceClaimTerminalRootState,
)

PROJECT_ID = "controlgraph-canary-abc123"
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
TWO_DIGEST = "2" * 64
NOW = datetime(2026, 8, 19, 12, 2, tzinfo=UTC)
AUDIENCE = service_audience("executor")
CAPABILITY_KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)
EVIDENCE_KEY_VERSION = (
    f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
)


def target(
    *,
    project_id: str = PROJECT_ID,
    region: str = "us-central1",
    service_name: str = "controlgraph-reference-target",
) -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=project_id,
        region=region,
        environment="nonprod",
        service_name=service_name,
    )


def trusted_records() -> tuple[RolloutRootV2, ServiceClaimRecord, EpochAuthorityRecord]:
    root, _, claim, authority = root_records()
    return root, claim, authority


def released_claim(
    claim: ServiceClaimRecord,
    authority: EpochAuthorityRecord,
) -> ServiceClaimRecord:
    terminal = ServiceClaimTerminalRootProof(
        schema_version=SERVICE_CLAIM_TERMINAL_ROOT_PROOF_V1,
        target=claim.target,
        root_id=claim.root_id,
        root_sha256=claim.root_sha256,
        state=ServiceClaimTerminalRootState.RECOVERED,
        target_configuration_sha256=claim.stable_target_configuration_sha256,
        evidence_id="evidence-terminal-release",
        evidence_sha256=ZERO_DIGEST,
        confirmed_by="controlgraph.coordinator/v1",
        confirmed_at="2026-08-19T12:01:10Z",
    )
    classification = ServiceClaimTargetClassificationProof(
        schema_version=SERVICE_CLAIM_TARGET_CLASSIFICATION_PROOF_V1,
        target=claim.target,
        root_id=claim.root_id,
        root_sha256=claim.root_sha256,
        classification=ServiceClaimTargetClassification.STABLE_RESTORED,
        fenced_epoch=authority.current_epoch,
        fenced_authority_revision=authority.revision,
        service_generation=8,
        provider_etag="etag-stable-8",
        target_configuration_sha256=claim.stable_target_configuration_sha256,
        evidence_id="evidence-target-release",
        evidence_sha256=ONE_DIGEST,
        classified_by=(
            f"controlgraph-verifier@{claim.target.project_id}.iam.gserviceaccount.com"
        ),
        classified_at="2026-08-19T12:04:00Z",
    )
    return ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            "status": ServiceClaimStatus.RELEASED,
            "release_fence_epoch": authority.current_epoch,
            "release_fence_authority_revision": authority.revision,
            "release_fenced_by": authority.changed_by,
            "release_fence_request_id": authority.request_id,
            "release_fence_evidence_id": authority.evidence_id,
            "release_fenced_at": authority.changed_at,
            "released_by": "controlgraph.coordinator/v1",
            "release_request_id": "request-claim-release",
            "release_evidence_id": "evidence-claim-release",
            "released_at": "2026-08-19T12:05:00Z",
            "terminal_root_proof": terminal,
            "target_classification_proof": classification,
        }
    )


class FakeAuthorityStore:
    def __init__(
        self,
        *,
        root: RolloutRootV2 | None = None,
        claim: ServiceClaimRecord | None = None,
        authority: EpochAuthorityRecord | None = None,
        fail: bool = False,
    ) -> None:
        default_root, default_claim, default_authority = trusted_records()
        _, default_anchor, _, _ = root_records()
        self._root = default_root if root is None else root
        self._anchor = default_anchor
        self._claim = default_claim if claim is None else claim
        self._authority = default_authority if authority is None else authority
        self._claim_revision = 0 if self._claim.status is ServiceClaimStatus.ACTIVE else 2
        self._fail = fail
        self.target = default_root.content.target
        self.reads: list[str] = []

    async def read_root_creation_bundle(self, root_id: str) -> RootBundle | None:
        self.reads.append(f"snapshot:{root_id}")
        if self._fail:
            raise AuthorityStoreUnavailable
        if root_id != self._root.root_id:
            return None
        return root_bundle(
            root=self._root,
            anchor=self._anchor,
            claim=self._claim,
            authority=self._authority,
            claim_revision=self._claim_revision,
        )

    def replace_authority(self, replacement: EpochAuthorityRecord) -> None:
        self._authority = replacement

    def release(self, claim: ServiceClaimRecord, authority: EpochAuthorityRecord) -> None:
        self._claim = claim
        self._claim_revision = 2
        self._authority = authority


class RecordingSigningBackend:
    def __init__(self, profile: SigningProfile, signature: bytes = b"fixed-signature") -> None:
        self._profile = profile
        self.signature = signature
        self.digests: list[bytes] = []

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    def sign_digest(self, digest: bytes) -> bytes:
        self.digests.append(digest)
        return self.signature


class StateChangingSigningBackend(RecordingSigningBackend):
    def __init__(self, profile: SigningProfile, change_state: Callable[[], None]) -> None:
        super().__init__(profile)
        self._change_state = change_state

    def sign_digest(self, digest: bytes) -> bytes:
        signature = super().sign_digest(digest)
        self._change_state()
        return signature


class LocalSigningBackend(RecordingSigningBackend):
    def __init__(
        self,
        profile: SigningProfile,
        private_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        super().__init__(profile)
        self._private_key = private_key

    def sign_digest(self, digest: bytes) -> bytes:
        self.digests.append(digest)
        return self._private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )


class FakeLineageResolver:
    def __init__(self, lineage: tuple[SignedCapability, ...] | None) -> None:
        self.lineage = lineage
        self.lookups: list[str] = []

    async def resolve_lineage(
        self,
        parent_capability_id: str,
    ) -> tuple[SignedCapability, ...] | None:
        self.lookups.append(parent_capability_id)
        return self.lineage


class RecordingEnvelopeVerifier:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.verified: list[SignedCapability] = []

    def verify(self, capability: SignedCapability) -> None:
        self.verified.append(capability)
        if self.fail:
            raise ValueError("synthetic verification failure")


def configuration(**overrides: object) -> CapabilityIssuerConfiguration:
    values: dict[str, object] = {
        "target": target(),
        "handler_audience": AUDIENCE,
        "lifetime_seconds": 300,
    }
    values.update(overrides)
    return CapabilityIssuerConfiguration(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> CapabilityIssuanceRequest:
    root, _, authority = trusted_records()
    values: dict[str, object] = {
        "root_id": root.root_id,
        "expected_root_sha256": root.root_sha256,
        "expected_epoch": authority.current_epoch,
        "request_id": "request-issue-001",
        "idempotency_key": "intent-apply-001",
    }
    values.update(overrides)
    return CapabilityIssuanceRequest(**values)  # type: ignore[arg-type]


def principal(role: str = "coordinator") -> AuthenticatedIssuancePrincipal:
    return AuthenticatedIssuancePrincipal(
        identity=f"controlgraph-{role}@{PROJECT_ID}.iam.gserviceaccount.com"
    )


def issuer(
    *,
    store: FakeAuthorityStore | None = None,
    config: CapabilityIssuerConfiguration | None = None,
    backend: RecordingSigningBackend | None = None,
    resolver: FakeLineageResolver | None = None,
    verifier: CapabilityEnvelopeVerifier | None = None,
) -> tuple[CapabilityIssuer, RecordingSigningBackend, FakeAuthorityStore]:
    selected_store = store or FakeAuthorityStore()
    selected_backend = backend or RecordingSigningBackend(
        SigningProfile.capability(PROJECT_ID, CAPABILITY_KEY_VERSION)
    )
    value = CapabilityIssuer(
        store=cast(object, selected_store),  # type: ignore[arg-type]
        signer=PurposeSealedSigner(cast(DigestSigningBackend, selected_backend)),
        configuration=config or configuration(),
        lineage_resolver=resolver,
        envelope_verifier=verifier,
    )
    return value, selected_backend, selected_store


def issue(
    value: CapabilityIssuer,
    issuance_request: CapabilityIssuanceRequest | None = None,
    *,
    caller: AuthenticatedIssuancePrincipal | None = None,
    now: datetime = NOW,
) -> SignedCapability:
    return asyncio.run(
        value.issue(
            issuance_request or request(),
            principal=caller if caller is not None else principal(),
            now=now,
        )
    )


def test_issues_exact_canonical_root_bound_claims_through_capability_signer() -> None:
    value, backend, store = issuer()

    envelope = issue(value)
    root, _, authority = trusted_records()
    claims = envelope.claims

    assert claims.issuer == f"controlgraph-issuer@{PROJECT_ID}.iam.gserviceaccount.com"
    assert claims.subject == f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"
    assert claims.audience == AUDIENCE
    assert claims.target == root.content.target
    assert claims.root_id == root.root_id
    assert claims.root_sha256 == root.root_sha256
    assert claims.epoch == authority.current_epoch
    assert claims.action is CapabilityAction.APPLY_CANARY
    assert claims.stable_revision == root.content.rollout_plan.stable_revision
    assert claims.candidate_revision == root.content.rollout_plan.candidate_revision
    assert (claims.stable_percent, claims.candidate_percent) == (90, 10)
    assert claims.concurrency is None
    assert claims.plan_sha256 == canonical_sha256(root.content.rollout_plan)
    assert claims.provider_etag == root.content.stable_snapshot.provider_etag
    assert claims.request_id == "request-issue-001"
    assert claims.idempotency_key == "intent-apply-001"
    assert claims.parent_capability_sha256 is None
    assert claims.issued_at == claims.not_before == "2026-08-19T12:02:00Z"
    assert claims.expires_at == "2026-08-19T12:07:00Z"
    assert claims.signing_algorithm == "EC_SIGN_P256_SHA256"
    assert claims.signing_key_version == CAPABILITY_KEY_VERSION
    assert envelope.claims_sha256 == canonical_sha256(claims)
    assert backend.digests == [build_signing_input(backend.profile, claims).digest]
    assert store.reads == [f"snapshot:{root.root_id}", f"snapshot:{root.root_id}"]


def test_claims_and_signing_input_are_deterministic_for_identical_trusted_inputs() -> None:
    value, backend, _ = issuer()

    first = issue(value)
    second = issue(value)

    assert first == second
    assert backend.digests == [backend.digests[0], backend.digests[0]]
    assert first.claims.capability_id.startswith("cgcap-")
    assert len(first.claims.capability_id) == 70


def test_matching_expected_epoch_is_loaded_from_current_authority() -> None:
    root, claim, authority = trusted_records()
    advanced = EpochAuthorityRecord(
        **{
            **authority.model_dump(mode="python"),
            "current_epoch": 2,
            "previous_epoch": 1,
            "revision": 1,
            "cause": EpochChangeCause.OPERATOR_REVOCATION,
            "request_id": "request-revoke-001",
            "evidence_id": "evidence-revoke-001",
            "changed_at": "2026-08-19T12:01:30Z",
        }
    )
    value, _, _ = issuer(store=FakeAuthorityStore(root=root, claim=claim, authority=advanced))

    envelope = issue(value, request(expected_epoch=2))

    assert envelope.claims.epoch == 2


@pytest.mark.parametrize("expected_epoch", [1, 3])
def test_stale_or_future_expected_epoch_is_denied_before_signing(
    expected_epoch: int,
) -> None:
    root, claim, authority = trusted_records()
    advanced = EpochAuthorityRecord(
        **{
            **authority.model_dump(mode="python"),
            "current_epoch": 2,
            "previous_epoch": 1,
            "revision": 1,
            "cause": EpochChangeCause.OPERATOR_REVOCATION,
            "request_id": "request-revoke-001",
            "evidence_id": "evidence-revoke-001",
            "changed_at": "2026-08-19T12:01:30Z",
        }
    )
    value, backend, store = issuer(
        store=FakeAuthorityStore(root=root, claim=claim, authority=advanced)
    )

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(value, request(expected_epoch=expected_epoch))

    assert denied.value.code is CapabilityIssuanceErrorCode.EXPECTED_STATE_MISMATCH
    assert backend.digests == []
    assert store.reads == [f"snapshot:{root.root_id}"]


def test_mismatched_expected_root_digest_is_denied_before_signing() -> None:
    root, _, _ = trusted_records()
    value, backend, store = issuer()

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(value, request(expected_root_sha256=ZERO_DIGEST))

    assert denied.value.code is CapabilityIssuanceErrorCode.EXPECTED_STATE_MISMATCH
    assert backend.digests == []
    assert store.reads == [f"snapshot:{root.root_id}"]


@pytest.mark.parametrize("release_claim", [False, True])
def test_authority_change_during_signing_never_returns_current_authority(
    release_claim: bool,
) -> None:
    root, claim, authority = trusted_records()
    store = FakeAuthorityStore(root=root, claim=claim, authority=authority)
    advanced = EpochAuthorityRecord(
        **{
            **authority.model_dump(mode="python"),
            "current_epoch": 2,
            "previous_epoch": 1,
            "revision": 1,
            "cause": EpochChangeCause.OPERATOR_REVOCATION,
            "changed_by": "controlgraph.operator/v1",
            "request_id": "request-release-001",
            "evidence_id": "evidence-release-001",
            "changed_at": "2026-08-19T12:02:00Z",
        }
    )
    released = released_claim(claim, advanced)

    def change_state() -> None:
        if release_claim:
            store.release(released, advanced)
        else:
            store.replace_authority(advanced)

    backend = StateChangingSigningBackend(
        SigningProfile.capability(PROJECT_ID, CAPABILITY_KEY_VERSION),
        change_state,
    )
    value, _, _ = issuer(store=store, backend=backend)

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(value)

    assert denied.value.code is (
        CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID
        if release_claim
        else CapabilityIssuanceErrorCode.EXPECTED_STATE_MISMATCH
    )
    assert len(backend.digests) == 1
    assert store.reads == [f"snapshot:{root.root_id}", f"snapshot:{root.root_id}"]


def test_release_after_issuance_atomically_makes_the_capability_epoch_stale() -> None:
    root, claim, authority = trusted_records()
    store = FakeAuthorityStore(root=root, claim=claim, authority=authority)
    value, _, _ = issuer(store=store)
    envelope = issue(value)
    revoked = EpochAuthorityRecord(
        **{
            **authority.model_dump(mode="python"),
            "current_epoch": 2,
            "previous_epoch": 1,
            "revision": 1,
            "cause": EpochChangeCause.OPERATOR_REVOCATION,
            "changed_by": "controlgraph.operator/v1",
            "request_id": "request-release-001",
            "evidence_id": "evidence-release-001",
            "changed_at": "2026-08-19T12:03:00Z",
        }
    )
    released = released_claim(claim, revoked)

    store.release(released, revoked)
    current = asyncio.run(store.read_root_creation_bundle(root.root_id))
    assert current is not None
    epoch_check = check_epoch(
        token_root_id=envelope.claims.root_id,
        token_epoch=envelope.claims.epoch,
        authority_root_id=current.authority.value.root_id,
        current_epoch=current.authority.value.current_epoch,
    )

    assert current.service_claim.value.status is ServiceClaimStatus.RELEASED
    assert epoch_check.outcome is EpochCheckOutcome.STALE
    assert epoch_check.authorized is False


def test_signed_envelope_adapts_to_exact_trust_bundle_verification() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_KEY_VERSION)
    backend = LocalSigningBackend(profile, private_key)
    value, _, _ = issuer(backend=backend)
    envelope = issue(value)
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
    verifier = TrustBundleCapabilityVerifier(
        TrustBundleVerifier(
            VerificationProfile.capability(PROJECT_ID, profile.key_resource),
            bundle,
        )
    )

    verifier.verify(envelope)

    tampered = SignedCapability(
        schema_version=envelope.schema_version,
        claims=envelope.claims,
        claims_sha256=envelope.claims_sha256,
        signature=encode_base64url(b"invalid-signature"),
    )
    with pytest.raises(SigningError):
        verifier.verify(tampered)


def test_request_surface_has_no_target_action_method_lifetime_or_key_selector() -> None:
    assert {field.name for field in fields(CapabilityIssuanceRequest)} == {
        "root_id",
        "expected_root_sha256",
        "expected_epoch",
        "request_id",
        "idempotency_key",
        "parent_capability_id",
    }
    with pytest.raises(TypeError):
        CapabilityIssuanceRequest(  # type: ignore[call-arg]
            root_id=trusted_records()[0].root_id,
            expected_root_sha256=trusted_records()[0].root_sha256,
            expected_epoch=trusted_records()[2].current_epoch,
            request_id="request-001",
            idempotency_key="intent-001",
            method="run.services.patch",
            signing_key_version=CAPABILITY_KEY_VERSION,
        )


@pytest.mark.parametrize("caller", [None, principal("executor")])
def test_only_authenticated_configured_coordinator_can_request_issuance(
    caller: AuthenticatedIssuancePrincipal | None,
) -> None:
    value, backend, store = issuer()

    with pytest.raises(CapabilityIssuanceError) as denied:
        asyncio.run(value.issue(request(), principal=caller, now=NOW))

    assert denied.value.code is (
        CapabilityIssuanceErrorCode.CALLER_UNAUTHENTICATED
        if caller is None
        else CapabilityIssuanceErrorCode.CALLER_UNAUTHORIZED
    )
    assert backend.digests == []
    assert store.reads == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"root_id": "root-*"},
        {"expected_root_sha256": "A" * 64},
        {"expected_root_sha256": "0" * 63},
        {"expected_epoch": 0},
        {"expected_epoch": True},
        {"expected_epoch": MAX_SAFE_INTEGER + 1},
        {"request_id": "request?"},
        {"idempotency_key": "intent[0]"},
        {"parent_capability_id": "parent-*"},
    ],
)
def test_request_rejects_wildcards(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        request(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"target": target(project_id="example-project-123")},
        {"target": target(project_id="controlgraph-canary-reconcile")},
        {"target": target(region="europe-west1")},
        {"target": target(service_name="reconcile-target")},
        {"handler_audience": "https://controlgraph-executor-*.a.run.app"},
        {"handler_audience": "https://controlgraph-recovery-abc123-uc.a.run.app"},
        {"handler_audience": "https://controlgraph-executor-reconcile-uc.a.run.app"},
        {"handler_audience": f"{AUDIENCE}/"},
        {"handler_audience": f"{AUDIENCE}/internal/v1/execute"},
        {"handler_audience": "http://controlgraph-executor-abc123-uc.a.run.app"},
        {"lifetime_seconds": 0},
        {"lifetime_seconds": MAX_CAPABILITY_LIFETIME_SECONDS + 1},
        {"lifetime_seconds": True},
    ],
)
def test_configuration_rejects_cross_boundary_and_indefinite_authority(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        configuration(**overrides)


def test_issuer_rejects_evidence_key_and_cross_target_store_before_signing() -> None:
    evidence_backend = RecordingSigningBackend(
        SigningProfile.evidence(PROJECT_ID, EVIDENCE_KEY_VERSION)
    )
    with pytest.raises(ValueError, match="capability purpose"):
        issuer(backend=evidence_backend)

    mismatched_store = FakeAuthorityStore()
    mismatched_store.target = target(service_name="other-target")
    with pytest.raises(ValueError, match="store target"):
        issuer(store=mismatched_store)


def test_issuer_fails_closed_for_unavailable_or_inconsistent_trusted_state() -> None:
    unavailable, backend, _ = issuer(store=FakeAuthorityStore(fail=True))
    with pytest.raises(CapabilityIssuanceError) as unavailable_error:
        issue(unavailable)
    assert unavailable_error.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_UNAVAILABLE
    assert backend.digests == []

    root, claim, authority = trusted_records()
    inconsistent_authority = EpochAuthorityRecord(
        **{
            **authority.model_dump(mode="python"),
            "root_sha256": ZERO_DIGEST,
        }
    )
    inconsistent, backend, _ = issuer(
        store=FakeAuthorityStore(
            root=root,
            claim=claim,
            authority=inconsistent_authority,
        )
    )
    with pytest.raises(CapabilityIssuanceError) as inconsistent_error:
        issue(inconsistent)
    assert inconsistent_error.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID
    assert backend.digests == []


@pytest.mark.parametrize(
    "field",
    [
        "stable_target_configuration_sha256",
        "candidate_target_configuration_sha256",
    ],
)
def test_issuer_rejects_a_canonically_wrapped_tampered_claim_projection(
    field: str,
) -> None:
    root, claim, authority = trusted_records()
    altered_claim = ServiceClaimRecord(
        **{
            **claim.model_dump(mode="python"),
            field: ZERO_DIGEST,
        }
    )
    value, backend, _ = issuer(
        store=FakeAuthorityStore(
            root=root,
            claim=altered_claim,
            authority=authority,
        )
    )

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(value)

    assert denied.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID
    assert backend.digests == []

def test_released_service_claim_cannot_issue_new_authority() -> None:
    root, claim, authority = trusted_records()
    release_authority = EpochAuthorityRecord(
        **{
            **authority.model_dump(mode="python"),
            "current_epoch": 2,
            "previous_epoch": 1,
            "revision": 1,
            "cause": EpochChangeCause.OPERATOR_REVOCATION,
            "changed_by": "controlgraph.operator/v1",
            "request_id": "request-release-001",
            "evidence_id": "evidence-release-001",
            "changed_at": "2026-08-19T12:01:30Z",
        }
    )
    released = released_claim(claim, release_authority)
    value, backend, _ = issuer(
        store=FakeAuthorityStore(root=root, claim=released, authority=authority)
    )

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(value)

    assert denied.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID
    assert backend.digests == []


def test_trusted_root_cannot_introduce_an_unrelated_revision_resource() -> None:
    root, claim, authority = trusted_records()
    altered_plan = root.content.rollout_plan.model_copy(
        update={"candidate_revision": "reconcile-candidate"}
    )
    altered_content = root.content.model_copy(
        update={"rollout_plan": altered_plan}
    )
    altered_root = root.model_copy(
        update={"content": altered_content}
    )
    value, backend, _ = issuer(
        store=FakeAuthorityStore(
            root=altered_root,
            claim=claim,
            authority=authority,
        )
    )

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(value)

    assert denied.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID
    assert backend.digests == []


def test_derived_child_uses_locally_computed_verified_parent_digest_and_narrower_time() -> None:
    root_issuer, _, _ = issuer()
    parent = issue(root_issuer)
    resolver = FakeLineageResolver((parent,))
    verifier = RecordingEnvelopeVerifier()
    child_issuer, _, _ = issuer(resolver=resolver, verifier=verifier)
    child_request = request(parent_capability_id=parent.claims.capability_id)

    child = issue(
        child_issuer,
        child_request,
        now=datetime(2026, 8, 19, 12, 3, tzinfo=UTC),
    )

    assert resolver.lookups == [parent.claims.capability_id]
    assert verifier.verified == [parent]
    assert child.claims.parent_capability_sha256 == parent.claims_sha256
    assert child.claims.not_before == "2026-08-19T12:03:00Z"
    assert child.claims.expires_at == parent.claims.expires_at
    assert child.claims.capability_id != parent.claims.capability_id


@pytest.mark.parametrize(
    ("parent_issued_at", "parent_not_before", "use_grandparent"),
    [
        ("2026-08-19T12:00:00Z", "2026-08-19T12:02:00Z", False),
        ("2026-08-19T12:01:00Z", "2026-08-19T12:03:00Z", True),
    ],
)
def test_issuance_rejects_preapproval_or_noncausal_parent_lineage(
    parent_issued_at: str,
    parent_not_before: str,
    use_grandparent: bool,
) -> None:
    root_issuer, _, _ = issuer()
    original = issue(root_issuer)
    parent_claims = CapabilityClaims(
        **{
            **original.claims.model_dump(mode="python"),
            "capability_id": "cgcap-temporal-parent",
            "parent_capability_sha256": (
                original.claims_sha256 if use_grandparent else None
            ),
            "issued_at": parent_issued_at,
            "not_before": parent_not_before,
            "expires_at": "2026-08-19T12:06:00Z",
        }
    )
    parent = SignedCapability(
        schema_version=original.schema_version,
        claims=parent_claims,
        claims_sha256=canonical_sha256(parent_claims),
        signature=original.signature,
    )
    lineage = (original, parent) if use_grandparent else (parent,)
    verifier = RecordingEnvelopeVerifier()
    child_issuer, backend, _ = issuer(
        resolver=FakeLineageResolver(lineage),
        verifier=verifier,
    )

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(
            child_issuer,
            request(parent_capability_id=parent.claims.capability_id),
            now=datetime(2026, 8, 19, 12, 4, tzinfo=UTC),
        )

    assert denied.value.code is CapabilityIssuanceErrorCode.LINEAGE_INVALID
    assert backend.digests == []


def test_verified_claims_digest_is_stable_across_distinct_valid_ecdsa_signatures() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_KEY_VERSION)
    backend = LocalSigningBackend(profile, private_key)
    root_issuer, _, _ = issuer(backend=backend)
    first_parent = issue(root_issuer)
    second_parent = issue(root_issuer)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    verifier = TrustBundleCapabilityVerifier(
        TrustBundleVerifier(
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
    )

    verifier.verify(first_parent)
    verifier.verify(second_parent)
    assert first_parent.claims == second_parent.claims
    assert first_parent.signature != second_parent.signature
    assert canonical_sha256(first_parent) != canonical_sha256(second_parent)
    assert first_parent.claims_sha256 == second_parent.claims_sha256

    first_child_issuer, _, _ = issuer(
        backend=backend,
        resolver=FakeLineageResolver((first_parent,)),
        verifier=verifier,
    )
    second_child_issuer, _, _ = issuer(
        backend=backend,
        resolver=FakeLineageResolver((second_parent,)),
        verifier=verifier,
    )
    child_request = request(parent_capability_id=first_parent.claims.capability_id)
    child_time = datetime(2026, 8, 19, 12, 3, tzinfo=UTC)

    first_child = issue(first_child_issuer, child_request, now=child_time)
    second_child = issue(second_child_issuer, child_request, now=child_time)

    assert first_child.claims == second_child.claims
    assert first_child.claims.parent_capability_sha256 == first_parent.claims_sha256


def test_parent_locator_must_resolve_to_matching_verified_envelope() -> None:
    root_issuer, _, _ = issuer()
    parent = issue(root_issuer)
    resolver = FakeLineageResolver((parent,))
    verifier = RecordingEnvelopeVerifier()
    value, backend, _ = issuer(resolver=resolver, verifier=verifier)

    with pytest.raises(CapabilityIssuanceError) as mismatch:
        issue(value, request(parent_capability_id="cgcap-unrelated"))

    assert mismatch.value.code is CapabilityIssuanceErrorCode.LINEAGE_INVALID
    assert verifier.verified == []
    assert backend.digests == []


def test_resolved_parent_pointer_is_validated_from_complete_signed_lineage() -> None:
    root_issuer, _, _ = issuer()
    parent = issue(root_issuer)
    altered_claims = type(parent.claims)(
        **{
            **parent.claims.model_dump(mode="python"),
            "parent_capability_sha256": "f" * 64,
        }
    )
    altered_parent = SignedCapability(
        schema_version=parent.schema_version,
        claims=altered_claims,
        claims_sha256=canonical_sha256(altered_claims),
        signature=parent.signature,
    )
    value, backend, _ = issuer(
        resolver=FakeLineageResolver((altered_parent,)),
        verifier=RecordingEnvelopeVerifier(),
    )

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(
            value,
            request(parent_capability_id=altered_parent.claims.capability_id),
        )

    assert denied.value.code is CapabilityIssuanceErrorCode.LINEAGE_INVALID
    assert backend.digests == []

    failing_verifier = RecordingEnvelopeVerifier(fail=True)
    value, backend, _ = issuer(
        resolver=FakeLineageResolver((parent,)),
        verifier=failing_verifier,
    )
    with pytest.raises(CapabilityIssuanceError) as unverified:
        issue(value, request(parent_capability_id=parent.claims.capability_id))
    assert unverified.value.code is CapabilityIssuanceErrorCode.LINEAGE_UNVERIFIED
    assert backend.digests == []


def test_parent_scope_cannot_be_switched_to_another_fixed_handler() -> None:
    root_issuer, _, _ = issuer()
    parent = issue(root_issuer)
    different_audience = "https://controlgraph-executor-def456-uc.a.run.app"
    value, backend, _ = issuer(
        config=configuration(handler_audience=different_audience),
        resolver=FakeLineageResolver((parent,)),
        verifier=RecordingEnvelopeVerifier(),
    )

    with pytest.raises(CapabilityIssuanceError) as denied:
        issue(value, request(parent_capability_id=parent.claims.capability_id))

    assert denied.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID
    assert backend.digests == []


def test_expired_parent_and_malformed_clock_are_denied_before_signing() -> None:
    root_issuer, _, _ = issuer()
    parent = issue(root_issuer)
    value, backend, _ = issuer(
        resolver=FakeLineageResolver((parent,)),
        verifier=RecordingEnvelopeVerifier(),
    )

    with pytest.raises(CapabilityIssuanceError) as expired:
        issue(
            value,
            request(parent_capability_id=parent.claims.capability_id),
            now=datetime(2026, 8, 19, 12, 7, tzinfo=UTC),
        )
    assert expired.value.code is CapabilityIssuanceErrorCode.LINEAGE_INVALID
    assert backend.digests == []

    with pytest.raises(ValueError, match="exact UTC second"):
        issue(value, now=datetime(2026, 8, 19, 12, 2, 0, 1, tzinfo=UTC))
