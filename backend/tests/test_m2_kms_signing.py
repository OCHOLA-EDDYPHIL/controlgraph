from __future__ import annotations

import json
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import cast

import google_crc32c
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.application.signing import (
    SIGNING_ALGORITHM,
    DetachedSignature,
    PurposeSealedSigner,
    SigningError,
    SigningErrorCode,
    SigningKeyState,
    SigningProfile,
    SigningPurpose,
    TrustBundle,
    TrustBundleVerifier,
    VerificationProfile,
    build_signing_input,
    make_trust_bundle_entry,
)
from controlgraph_canary.contracts import (
    CapabilityAction,
    CapabilityClaims,
    EvidenceEvent,
    EvidenceKind,
    TargetBinding,
)
from controlgraph_canary.integrations.google.kms import (
    GoogleKmsCapabilityTrustLoader,
    GoogleKmsDigestSigner,
    GoogleKmsTrustBundlePublisher,
)

PROJECT_ID = "controlgraph-canary-test01"
CAPABILITY_KEY = (
    "projects/controlgraph-canary-test01/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing"
)
CAPABILITY_V1 = f"{CAPABILITY_KEY}/cryptoKeyVersions/1"
CAPABILITY_V2 = f"{CAPABILITY_KEY}/cryptoKeyVersions/2"
EVIDENCE_KEY = (
    "projects/controlgraph-canary-test01/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/evidence-signing"
)
EVIDENCE_V1 = f"{EVIDENCE_KEY}/cryptoKeyVersions/1"
EVIDENCE_V2 = f"{EVIDENCE_KEY}/cryptoKeyVersions/2"
VECTOR_PAYLOAD_SHA256 = "177539b7ec00352b5ac73f32e2858119535e11f8eed3870c6333c20ee994bb47"
VECTOR_DIGEST_SHA256 = "80c673dec869965263a827498d5ba8e05129dd67ccd8b41c22d3346d06963de7"
VECTOR_SIGNATURE = (
    "MEQCIByfVz7WDh9SNvnk1lj70QEsm9wtZYZPaGpDj_YWaA56AiBQS3Zbfsl8JgdJb7d361s33wtyTB9onnG0uDMDxE7DJw"
)
VECTOR_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU19Ea2hiagKXP6AO6J0lpOd63CxF
+raVNX3fwotq+Fv+nPhe5NibAUpY+i7IBYlS9GFCXTX93vGuUV9yB2qA7g==
-----END PUBLIC KEY-----
"""


def _target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id="controlgraph-canary-test01",
        region="us-central1",
        environment="acceptance",
        service_name="reference-target",
    )


def _capability(key_version: str = CAPABILITY_V1) -> CapabilityClaims:
    return CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id="capability-001",
        issuer="issuer@controlgraph-canary-test01.iam.gserviceaccount.com",
        subject="executor@controlgraph-canary-test01.iam.gserviceaccount.com",
        audience="https://executor.example.test/tasks/apply",
        target=_target(),
        root_id="root-001",
        root_sha256="1" * 64,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision="reference-stable",
        candidate_revision="reference-candidate",
        stable_percent=90,
        candidate_percent=10,
        concurrency=10,
        plan_sha256="2" * 64,
        provider_etag="etag-001",
        request_id="request-001",
        idempotency_key="idempotency-001",
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:00:00Z",
        not_before="2026-08-19T12:00:00Z",
        expires_at="2026-08-19T12:10:00Z",
        signing_algorithm=SIGNING_ALGORITHM,
        signing_key_version=key_version,
    )


def _evidence() -> EvidenceEvent:
    return EvidenceEvent(
        schema_version="controlgraph.evidence-event/v1",
        evidence_id="evidence-001",
        sequence=0,
        root_id="root-001",
        root_sha256="1" * 64,
        target=_target(),
        epoch=1,
        kind=EvidenceKind.ROOT_CREATED,
        actor="operator@example.test",
        request_id="request-001",
        receipt_id=None,
        occurred_at="2026-08-19T12:00:00Z",
        subject_sha256="3" * 64,
        previous_event_sha256=None,
        reason_code=None,
        provider_operation=None,
        target_configuration_sha256=None,
    )


def _public_pem(private_key: ec.EllipticCurvePrivateKey) -> str:
    return (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


class _LocalDigestSigner:
    def __init__(
        self,
        profile: SigningProfile,
        private_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        self.profile = profile
        self._private_key = private_key

    def sign_digest(self, digest: bytes) -> bytes:
        return self._private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )


def _local_signature(
    profile: SigningProfile,
    payload: CapabilityClaims | EvidenceEvent,
    private_key: ec.EllipticCurvePrivateKey,
) -> DetachedSignature:
    return PurposeSealedSigner(_LocalDigestSigner(profile, private_key)).sign(payload)


def _bundle_entry(
    profile: SigningProfile,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    state: SigningKeyState = SigningKeyState.ENABLED,
):
    return make_trust_bundle_entry(
        profile=profile,
        state=state,
        public_key_pem=_public_pem(private_key),
    )


@pytest.mark.parametrize(
    "key_version",
    [
        EVIDENCE_V1,
        CAPABILITY_V1.replace("us-central1", "europe-west1"),
        CAPABILITY_V1.replace("controlgraph-canary-test01", "reconcile-production"),
        CAPABILITY_V1.replace("controlgraph-signing", "reconcile-signing"),
        CAPABILITY_V1.replace("capability-signing", "operator-selected-key"),
        CAPABILITY_V1.replace("cryptoKeyVersions/1", "cryptoKeyVersions/0"),
        CAPABILITY_V1.replace("cryptoKeyVersions/1", "cryptoKeyVersions/01"),
    ],
)
def test_signing_profile_rejects_resources_outside_its_controlgraph_purpose(
    key_version: str,
) -> None:
    with pytest.raises(SigningError) as failure:
        SigningProfile.capability(PROJECT_ID, key_version)
    assert failure.value.code is SigningErrorCode.PROFILE_INVALID


@pytest.mark.parametrize(
    "key_resource",
    [
        EVIDENCE_KEY,
        CAPABILITY_KEY.replace("us-central1", "europe-west1"),
        CAPABILITY_KEY.replace("controlgraph-canary-test01", "reconcile-production"),
        CAPABILITY_KEY.replace("controlgraph-signing", "reconcile-signing"),
    ],
)
def test_verification_profile_rejects_resources_outside_its_controlgraph_purpose(
    key_resource: str,
) -> None:
    with pytest.raises(SigningError) as failure:
        VerificationProfile.capability(PROJECT_ID, key_resource)
    assert failure.value.code is SigningErrorCode.PROFILE_INVALID


def test_fixed_public_vector_verifies_canonical_prehashed_p256_signature() -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    signing_input = build_signing_input(profile, _capability())
    assert signing_input.payload_sha256 == VECTOR_PAYLOAD_SHA256
    assert signing_input.digest_sha256 == VECTOR_DIGEST_SHA256

    bundle = TrustBundle(
        entries=(
            make_trust_bundle_entry(
                profile=profile,
                state=SigningKeyState.ENABLED,
                public_key_pem=VECTOR_PUBLIC_KEY,
            ),
        )
    )
    detached = DetachedSignature(
        schema_version="controlgraph.detached-signature/v1",
        purpose=SigningPurpose.CAPABILITY,
        key_version=CAPABILITY_V1,
        algorithm=SIGNING_ALGORITHM,
        payload_version="controlgraph.capability-claims/v1",
        payload_sha256=VECTOR_PAYLOAD_SHA256,
        digest_sha256=VECTOR_DIGEST_SHA256,
        signature=VECTOR_SIGNATURE,
    )

    TrustBundleVerifier(VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY), bundle).verify(
        _capability(), detached
    )


def test_capability_signing_is_purpose_and_profile_sealed() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    signature = _local_signature(profile, _capability(), private_key)
    bundle = TrustBundle(entries=(_bundle_entry(profile, private_key),))

    TrustBundleVerifier(VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY), bundle).verify(
        _capability(), signature
    )
    assert signature.key_version == CAPABILITY_V1
    assert signature.algorithm == SIGNING_ALGORITHM
    assert signature.payload_version == "controlgraph.capability-claims/v1"

    with pytest.raises(SigningError) as mismatch:
        PurposeSealedSigner(_LocalDigestSigner(profile, private_key)).sign(
            _capability(CAPABILITY_V2)
        )
    assert mismatch.value.code is SigningErrorCode.KEY_VERSION_MISMATCH

    with pytest.raises(SigningError) as wrong_payload:
        PurposeSealedSigner(_LocalDigestSigner(profile, private_key)).sign(_evidence())
    assert wrong_payload.value.code is SigningErrorCode.PAYLOAD_VERSION_MISMATCH


def test_signing_profiles_reject_key_project_substitution() -> None:
    other_key_version = CAPABILITY_V1.replace(
        "controlgraph-canary-test01", "controlgraph-canary-test02"
    )
    with pytest.raises(SigningError) as cross_project:
        SigningProfile.capability(PROJECT_ID, other_key_version)
    assert cross_project.value.code is SigningErrorCode.PROFILE_INVALID

    other_key_resource = CAPABILITY_KEY.replace(
        "controlgraph-canary-test01", "controlgraph-canary-test02"
    )
    with pytest.raises(SigningError) as verification_cross_project:
        VerificationProfile.capability(PROJECT_ID, other_key_resource)
    assert verification_cross_project.value.code is SigningErrorCode.PROFILE_INVALID

    other_evidence_version = EVIDENCE_V1.replace(
        "controlgraph-canary-test01", "controlgraph-canary-test02"
    )
    with pytest.raises(SigningError) as evidence_cross_project:
        SigningProfile.evidence(PROJECT_ID, other_evidence_version)
    assert evidence_cross_project.value.code is SigningErrorCode.PROFILE_INVALID


def test_signing_profiles_bind_configured_project_and_region_to_payload() -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    wrong_project = _capability().model_copy(
        update={"target": _target().model_copy(update={"project_id": "controlgraph-canary-test02"})}
    )
    with pytest.raises(SigningError) as cross_project:
        build_signing_input(profile, wrong_project)
    assert cross_project.value.code is SigningErrorCode.KEY_VERSION_MISMATCH

    wrong_region = _capability().model_copy(
        update={"target": _target().model_copy(update={"region": "europe-west1"})}
    )
    with pytest.raises(SigningError) as cross_region:
        build_signing_input(profile, wrong_region)
    assert cross_region.value.code is SigningErrorCode.KEY_VERSION_MISMATCH

    evidence_profile = SigningProfile.evidence(PROJECT_ID, EVIDENCE_V1)
    wrong_evidence_project = _evidence().model_copy(
        update={"target": _target().model_copy(update={"project_id": "controlgraph-canary-test02"})}
    )
    with pytest.raises(SigningError) as evidence_cross_project:
        build_signing_input(evidence_profile, wrong_evidence_project)
    assert evidence_cross_project.value.code is SigningErrorCode.KEY_VERSION_MISMATCH


def test_evidence_uses_a_distinct_purpose_and_key() -> None:
    capability_private = ec.generate_private_key(ec.SECP256R1())
    evidence_private = ec.generate_private_key(ec.SECP256R1())
    capability_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    evidence_profile = SigningProfile.evidence(PROJECT_ID, EVIDENCE_V1)
    signature = _local_signature(evidence_profile, _evidence(), evidence_private)
    bundle = TrustBundle(
        entries=(
            _bundle_entry(capability_profile, capability_private),
            _bundle_entry(evidence_profile, evidence_private),
        )
    )

    TrustBundleVerifier(VerificationProfile.evidence(PROJECT_ID, EVIDENCE_KEY), bundle).verify(
        _evidence(), signature
    )
    with pytest.raises(SigningError) as wrong_purpose:
        TrustBundleVerifier(
            VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY), bundle
        ).verify(_capability(), signature)
    assert wrong_purpose.value.code is SigningErrorCode.PURPOSE_MISMATCH


def test_rotation_accepts_enabled_versions_of_only_the_configured_key() -> None:
    old_private = ec.generate_private_key(ec.SECP256R1())
    new_private = ec.generate_private_key(ec.SECP256R1())
    old_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    new_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V2)
    bundle = TrustBundle(
        entries=(
            _bundle_entry(old_profile, old_private),
            _bundle_entry(new_profile, new_private),
        )
    )
    verifier = TrustBundleVerifier(
        VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY), bundle
    )

    verifier.verify(
        _capability(CAPABILITY_V1),
        _local_signature(old_profile, _capability(CAPABILITY_V1), old_private),
    )
    verifier.verify(
        _capability(CAPABILITY_V2),
        _local_signature(new_profile, _capability(CAPABILITY_V2), new_private),
    )

    unknown = replace(
        _local_signature(new_profile, _capability(CAPABILITY_V2), new_private),
        key_version=f"{CAPABILITY_KEY}/cryptoKeyVersions/3",
    )
    with pytest.raises(SigningError) as untrusted:
        verifier.verify(_capability(CAPABILITY_V2), unknown)
    assert untrusted.value.code is SigningErrorCode.KEY_VERSION_UNTRUSTED

    relabeled = replace(
        _local_signature(old_profile, _capability(CAPABILITY_V1), old_private),
        key_version=CAPABILITY_V2,
    )
    with pytest.raises(SigningError) as key_binding:
        verifier.verify(_capability(CAPABILITY_V1), relabeled)
    assert key_binding.value.code is SigningErrorCode.KEY_VERSION_MISMATCH


def test_disabled_version_fails_closed_before_local_verification() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    bundle = TrustBundle(
        entries=(_bundle_entry(profile, private_key, state=SigningKeyState.DISABLED),)
    )
    signature = _local_signature(profile, _capability(), private_key)

    with pytest.raises(SigningError) as disabled:
        TrustBundleVerifier(
            VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY), bundle
        ).verify(_capability(), signature)
    assert disabled.value.code is SigningErrorCode.KEY_VERSION_DISABLED


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"purpose": SigningPurpose.EVIDENCE}, SigningErrorCode.PURPOSE_MISMATCH),
        ({"algorithm": "EC_SIGN_P384_SHA384"}, SigningErrorCode.ALGORITHM_MISMATCH),
        (
            {"payload_version": "controlgraph.evidence-event/v1"},
            SigningErrorCode.PAYLOAD_VERSION_MISMATCH,
        ),
        ({"payload_sha256": "0" * 64}, SigningErrorCode.DIGEST_MISMATCH),
        ({"digest_sha256": "0" * 64}, SigningErrorCode.DIGEST_MISMATCH),
        ({"signature": "AA"}, SigningErrorCode.SIGNATURE_INVALID),
        ({"signature": "AA=="}, SigningErrorCode.SIGNATURE_INVALID),
    ],
)
def test_detached_metadata_and_signature_tampering_fails_closed(
    change: dict[str, object],
    code: SigningErrorCode,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    signature = _local_signature(profile, _capability(), private_key)
    tampered = replace(signature, **change)
    bundle = TrustBundle(entries=(_bundle_entry(profile, private_key),))

    with pytest.raises(SigningError) as failure:
        TrustBundleVerifier(
            VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY), bundle
        ).verify(_capability(), tampered)
    assert failure.value.code is code


def test_payload_tampering_changes_both_bound_digests() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    signature = _local_signature(profile, _capability(), private_key)
    changed = _capability().model_copy(update={"epoch": 2})
    bundle = TrustBundle(entries=(_bundle_entry(profile, private_key),))

    with pytest.raises(SigningError) as failure:
        TrustBundleVerifier(
            VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY), bundle
        ).verify(changed, signature)
    assert failure.value.code is SigningErrorCode.DIGEST_MISMATCH


def test_trust_bundle_round_trip_is_strict_and_canonical() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    bundle = TrustBundle(entries=(_bundle_entry(profile, private_key),))
    encoded = bundle.to_json_bytes()

    assert TrustBundle.parse(encoded) == bundle
    for malformed in (
        b" " + encoded,
        encoded.replace(b'"schema_version":', b'"schema_version":"duplicate",'),
        encoded.replace(b'"entries":', b'"unknown":true,"entries":'),
    ):
        with pytest.raises(SigningError) as failure:
            TrustBundle.parse(malformed)
        assert failure.value.code is SigningErrorCode.TRUST_BUNDLE_INVALID


def test_trust_bundle_parser_rejects_recursive_nesting_with_a_stable_error() -> None:
    nesting = 2_000
    malformed = (
        b'{"entries":'
        + (b"[" * nesting)
        + (b"]" * nesting)
        + b',"schema_version":"controlgraph.signing-trust-bundle/v1"}'
    )

    with pytest.raises(SigningError) as failure:
        TrustBundle.parse(malformed)
    assert failure.value.code is SigningErrorCode.TRUST_BUNDLE_INVALID
    assert failure.value.__cause__ is None


def test_trust_bundle_rejects_wrong_curve_malformed_pem_and_digest() -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    p384_private = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(SigningError) as wrong_curve:
        make_trust_bundle_entry(
            profile=profile,
            state=SigningKeyState.ENABLED,
            public_key_pem=_public_pem(p384_private),
        )
    assert wrong_curve.value.code is SigningErrorCode.PUBLIC_KEY_INVALID

    with pytest.raises(SigningError) as malformed:
        make_trust_bundle_entry(
            profile=profile,
            state=SigningKeyState.ENABLED,
            public_key_pem="-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n",
        )
    assert malformed.value.code is SigningErrorCode.PUBLIC_KEY_INVALID

    private_key = ec.generate_private_key(ec.SECP256R1())
    entry = replace(_bundle_entry(profile, private_key), public_key_sha256="0" * 64)
    with pytest.raises(SigningError) as digest:
        TrustBundle(entries=(entry,))
    assert digest.value.code is SigningErrorCode.DIGEST_MISMATCH


def test_trust_bundle_rejects_cross_purpose_key_or_public_material_reuse() -> None:
    capability_private = ec.generate_private_key(ec.SECP256R1())
    evidence_private = ec.generate_private_key(ec.SECP256R1())
    capability_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    with pytest.raises(SigningError) as wrong_purpose:
        SigningProfile.evidence(PROJECT_ID, CAPABILITY_V2)
    assert wrong_purpose.value.code is SigningErrorCode.PROFILE_INVALID

    second_capability_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V2)
    relabeled_entry = replace(
        _bundle_entry(second_capability_profile, evidence_private),
        purpose=SigningPurpose.EVIDENCE,
        payload_version="controlgraph.evidence-event/v1",
    )
    with pytest.raises(SigningError) as relabeled:
        TrustBundle(
            entries=(_bundle_entry(capability_profile, capability_private), relabeled_entry)
        )
    assert relabeled.value.code is SigningErrorCode.TRUST_BUNDLE_INVALID

    evidence_profile = SigningProfile.evidence(PROJECT_ID, EVIDENCE_V1)
    with pytest.raises(SigningError) as same_material:
        TrustBundle(
            entries=(
                _bundle_entry(capability_profile, capability_private),
                _bundle_entry(evidence_profile, capability_private),
            )
        )
    assert same_material.value.code is SigningErrorCode.TRUST_BUNDLE_INVALID


def test_trust_bundle_rejects_keys_from_multiple_controlgraph_projects() -> None:
    capability_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    other_evidence_key = EVIDENCE_KEY.replace(
        "controlgraph-canary-test01", "controlgraph-canary-test02"
    )
    evidence_profile = SigningProfile.evidence(
        "controlgraph-canary-test02",
        f"{other_evidence_key}/cryptoKeyVersions/1",
    )

    with pytest.raises(SigningError) as failure:
        TrustBundle(
            entries=(
                _bundle_entry(
                    capability_profile,
                    ec.generate_private_key(ec.SECP256R1()),
                ),
                _bundle_entry(
                    evidence_profile,
                    ec.generate_private_key(ec.SECP256R1()),
                ),
            )
        )
    assert failure.value.code is SigningErrorCode.TRUST_BUNDLE_INVALID


@dataclass
class _FakeKeyVersion:
    profile: SigningProfile
    private_key: ec.EllipticCurvePrivateKey
    state: str = "ENABLED"
    algorithm: str = SIGNING_ALGORITHM


class _FakeKmsClient:
    def __init__(self, versions: list[_FakeKeyVersion]) -> None:
        self.versions = {version.profile.key_version: version for version in versions}
        self.version_requests: list[dict[str, object]] = []
        self.sign_requests: list[dict[str, object]] = []
        self.public_key_requests: list[dict[str, object]] = []
        self.verified_digest_crc32c = True
        self.signature_crc_offset = 0
        self.public_key_crc_offset = 0
        self.response_name: str | None = None
        self.version_response_name: str | None = None
        self.public_key_response_name: str | None = None
        self.public_key_algorithm: str | None = None
        self.public_key_pem: str | None = None
        self.provider_failure: str | None = None

    def get_crypto_key_version(self, request: dict[str, object]) -> object:
        self.version_requests.append(request)
        if self.provider_failure == "version":
            raise RuntimeError("provider diagnostic must remain private")
        name = cast(str, request["name"])
        version = self.versions[name]
        return SimpleNamespace(
            name=self.version_response_name or self.response_name or name,
            state=version.state,
            algorithm=version.algorithm,
        )

    def asymmetric_sign(self, request: dict[str, object]) -> object:
        if self.provider_failure == "sign":
            raise RuntimeError("provider diagnostic must remain private")
        self.sign_requests.append(request)
        name = cast(str, request["name"])
        version = self.versions[name]
        digest = cast(dict[str, bytes], request["digest"])["sha256"]
        signature = version.private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return SimpleNamespace(
            name=self.response_name or name,
            signature=signature,
            signature_crc32c=google_crc32c.value(signature) + self.signature_crc_offset,
            verified_digest_crc32c=self.verified_digest_crc32c,
        )

    def get_public_key(self, request: dict[str, object]) -> object:
        self.public_key_requests.append(request)
        if self.provider_failure == "public_key":
            raise RuntimeError("provider diagnostic must remain private")
        name = cast(str, request["name"])
        version = self.versions[name]
        pem = self.public_key_pem or _public_pem(version.private_key)
        return SimpleNamespace(
            name=self.public_key_response_name or self.response_name or name,
            algorithm=self.public_key_algorithm or version.algorithm,
            pem=pem,
            pem_crc32c=google_crc32c.value(pem.encode("ascii")) + self.public_key_crc_offset,
        )


@pytest.mark.parametrize("service_role", [ServiceRole.EXECUTOR, ServiceRole.RECOVERY])
def test_kms_capability_trust_loader_verifies_only_the_exact_enabled_version(
    service_role: ServiceRole,
) -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    private_key = ec.generate_private_key(ec.SECP256R1())
    fake = _FakeKmsClient([_FakeKeyVersion(profile, private_key)])
    loader = GoogleKmsCapabilityTrustLoader(
        project_id=PROJECT_ID,
        service_role=service_role,
        key_version=CAPABILITY_V1,
        client=fake,
    )

    verifier = loader.load()

    assert loader.project_id == PROJECT_ID
    assert loader.service_role is service_role
    assert loader.key_version == CAPABILITY_V1
    assert loader.key_resource == CAPABILITY_KEY
    assert verifier.profile == VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY)
    assert verifier.profile.purpose is SigningPurpose.CAPABILITY
    assert fake.version_requests == [{"name": CAPABILITY_V1}]
    assert fake.public_key_requests == [{"name": CAPABILITY_V1}]
    assert fake.sign_requests == []
    public_callables = {
        name
        for name in dir(loader)
        if not name.startswith("_") and callable(getattr(loader, name))
    }
    assert public_callables == {"load"}
    assert not hasattr(loader, "sign")
    assert not hasattr(loader, "sign_digest")

    payload = _capability()
    verifier.verify(payload, _local_signature(profile, payload, private_key))

    other_private_key = ec.generate_private_key(ec.SECP256R1())
    other_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V2)
    other_payload = _capability(CAPABILITY_V2)
    with pytest.raises(SigningError) as untrusted:
        verifier.verify(
            other_payload,
            _local_signature(other_profile, other_payload, other_private_key),
        )
    assert untrusted.value.code is SigningErrorCode.KEY_VERSION_UNTRUSTED


@pytest.mark.parametrize(
    "service_role",
    [
        ServiceRole.API,
        ServiceRole.COORDINATOR,
        ServiceRole.ISSUER,
        ServiceRole.VERIFIER,
        ServiceRole.EVIDENCE_WRITER,
        "executor",
    ],
)
def test_kms_capability_trust_loader_rejects_other_roles_before_kms_access(
    service_role: object,
) -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    fake = _FakeKmsClient([_FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1()))])

    with pytest.raises(SigningError) as failure:
        GoogleKmsCapabilityTrustLoader(
            project_id=PROJECT_ID,
            service_role=cast(ServiceRole, service_role),
            key_version=CAPABILITY_V1,
            client=fake,
        )

    assert failure.value.code is SigningErrorCode.PROFILE_INVALID
    assert fake.version_requests == []
    assert fake.public_key_requests == []


@pytest.mark.parametrize(
    ("project_id", "key_version"),
    [
        ("shared-project", CAPABILITY_V1),
        (PROJECT_ID, EVIDENCE_V1),
        ("controlgraph-canary-test02", CAPABILITY_V1),
    ],
)
def test_kms_capability_trust_loader_rejects_unbound_profiles_before_kms_access(
    project_id: str,
    key_version: str,
) -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    fake = _FakeKmsClient([_FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1()))])

    with pytest.raises(SigningError) as failure:
        GoogleKmsCapabilityTrustLoader(
            project_id=project_id,
            service_role=ServiceRole.EXECUTOR,
            key_version=key_version,
            client=fake,
        )

    assert failure.value.code is SigningErrorCode.PROFILE_INVALID
    assert fake.version_requests == []
    assert fake.public_key_requests == []


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("disabled", SigningErrorCode.KEY_VERSION_DISABLED),
        ("version_algorithm", SigningErrorCode.ALGORITHM_MISMATCH),
        ("version_name", SigningErrorCode.KEY_VERSION_MISMATCH),
        ("public_algorithm", SigningErrorCode.ALGORITHM_MISMATCH),
        ("public_name", SigningErrorCode.KEY_VERSION_MISMATCH),
        ("public_crc", SigningErrorCode.CRC_MISMATCH),
        ("public_pem", SigningErrorCode.PUBLIC_KEY_INVALID),
        ("version_failure", SigningErrorCode.PROVIDER_FAILURE),
        ("public_failure", SigningErrorCode.PROVIDER_FAILURE),
    ],
)
def test_kms_capability_trust_loader_fails_closed_on_provider_integrity_errors(
    mutation: str,
    code: SigningErrorCode,
) -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    version = _FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1()))
    fake = _FakeKmsClient([version])
    if mutation == "disabled":
        version.state = "DISABLED"
    elif mutation == "version_algorithm":
        version.algorithm = "EC_SIGN_P384_SHA384"
    elif mutation == "version_name":
        fake.version_response_name = CAPABILITY_V2
    elif mutation == "public_algorithm":
        fake.public_key_algorithm = "EC_SIGN_P384_SHA384"
    elif mutation == "public_name":
        fake.public_key_response_name = CAPABILITY_V2
    elif mutation == "public_crc":
        fake.public_key_crc_offset = 1
    elif mutation == "public_pem":
        fake.public_key_pem = "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n"
    elif mutation == "version_failure":
        fake.provider_failure = "version"
    else:
        fake.provider_failure = "public_key"
    loader = GoogleKmsCapabilityTrustLoader(
        project_id=PROJECT_ID,
        service_role=ServiceRole.EXECUTOR,
        key_version=CAPABILITY_V1,
        client=fake,
    )

    with pytest.raises(SigningError) as failure:
        loader.load()

    assert failure.value.code is code
    assert fake.sign_requests == []
    if code is SigningErrorCode.PROVIDER_FAILURE:
        assert failure.value.__cause__ is None
        assert failure.value.__suppress_context__ is True
        assert "provider diagnostic" not in str(failure.value)


def test_payload_project_substitution_is_rejected_before_kms_access() -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    fake = _FakeKmsClient([_FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1()))])
    substituted = _capability().model_copy(
        update={"target": _target().model_copy(update={"project_id": "controlgraph-canary-test02"})}
    )

    with pytest.raises(SigningError) as failure:
        PurposeSealedSigner(GoogleKmsDigestSigner(profile, client=fake)).sign(substituted)

    assert failure.value.code is SigningErrorCode.KEY_VERSION_MISMATCH
    assert fake.version_requests == []
    assert fake.sign_requests == []


def test_kms_signer_sends_and_verifies_crc32c_without_key_selection_inputs() -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    fake = _FakeKmsClient([_FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1()))])
    signing_input = build_signing_input(profile, _capability())
    signer = GoogleKmsDigestSigner(profile, client=fake)

    signature = signer.sign_digest(signing_input.digest)

    assert signature
    assert fake.sign_requests == [
        {
            "name": CAPABILITY_V1,
            "digest": {"sha256": signing_input.digest},
            "digest_crc32c": google_crc32c.value(signing_input.digest),
        }
    ]
    assert set(fake.sign_requests[0]) == {"name", "digest", "digest_crc32c"}


def test_kms_signer_defers_default_credentials_until_signing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    calls = 0

    def unavailable_client() -> object:
        nonlocal calls
        calls += 1
        raise SigningError(SigningErrorCode.PROVIDER_FAILURE, "unavailable")

    monkeypatch.setattr(
        "controlgraph_canary.integrations.google.kms._default_client",
        unavailable_client,
    )

    signer = GoogleKmsDigestSigner(profile)

    assert calls == 0
    with pytest.raises(SigningError) as failure:
        signer.sign_digest(b"d" * 32)
    assert failure.value.code is SigningErrorCode.PROVIDER_FAILURE
    assert calls == 1


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        ("disable", SigningErrorCode.KEY_VERSION_DISABLED),
        ("algorithm", SigningErrorCode.ALGORITHM_MISMATCH),
        ("request_crc", SigningErrorCode.CRC_MISMATCH),
        ("response_crc", SigningErrorCode.CRC_MISMATCH),
        ("response_name", SigningErrorCode.KEY_VERSION_MISMATCH),
    ],
)
def test_kms_signer_fails_closed_on_version_and_integrity_errors(
    mutate: str,
    code: SigningErrorCode,
) -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    version = _FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1()))
    fake = _FakeKmsClient([version])
    if mutate == "disable":
        version.state = "DISABLED"
    elif mutate == "algorithm":
        version.algorithm = "EC_SIGN_P384_SHA384"
    elif mutate == "request_crc":
        fake.verified_digest_crc32c = False
    elif mutate == "response_crc":
        fake.signature_crc_offset = 1
    else:
        fake.response_name = CAPABILITY_V2

    with pytest.raises(SigningError) as failure:
        GoogleKmsDigestSigner(profile, client=fake).sign_digest(b"d" * 32)
    assert failure.value.code is code


@pytest.mark.parametrize("operation", ["version", "sign", "public_key"])
def test_kms_provider_exceptions_are_sanitized_without_chained_causes(
    operation: str,
) -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    evidence_profile = SigningProfile.evidence(PROJECT_ID, EVIDENCE_V1)
    fake = _FakeKmsClient(
        [
            _FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1())),
            _FakeKeyVersion(evidence_profile, ec.generate_private_key(ec.SECP256R1())),
        ]
    )
    fake.provider_failure = operation

    with pytest.raises(SigningError) as failure:
        if operation == "public_key":
            GoogleKmsTrustBundlePublisher(
                project_id=PROJECT_ID,
                role="api",
                client=fake,
            ).publish([profile, evidence_profile])
        else:
            GoogleKmsDigestSigner(profile, client=fake).sign_digest(b"d" * 32)

    assert failure.value.code is SigningErrorCode.PROVIDER_FAILURE
    assert failure.value.__cause__ is None
    assert failure.value.__suppress_context__ is True
    assert "provider diagnostic" not in str(failure.value)


@pytest.mark.parametrize(
    "role",
    ["coordinator", "issuer", "executor", "recovery", "verifier", "evidence_writer"],
)
def test_kms_publication_rejects_non_api_roles_before_kms_access(role: str) -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    fake = _FakeKmsClient([_FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1()))])

    with pytest.raises(SigningError) as failure:
        GoogleKmsTrustBundlePublisher(
            project_id=PROJECT_ID,
            role=role,
            client=fake,
        )

    assert failure.value.code is SigningErrorCode.PROFILE_INVALID
    assert fake.version_requests == []


@pytest.mark.parametrize(
    ("profiles", "code"),
    [
        ("capability_only", SigningErrorCode.TRUST_BUNDLE_INVALID),
        ("evidence_only", SigningErrorCode.TRUST_BUNDLE_INVALID),
        ("cross_project", SigningErrorCode.PROFILE_INVALID),
        ("duplicate", SigningErrorCode.TRUST_BUNDLE_INVALID),
    ],
)
def test_kms_publication_rejects_unsealed_profile_sets_before_kms_access(
    profiles: str,
    code: SigningErrorCode,
) -> None:
    capability_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    evidence_profile = SigningProfile.evidence(PROJECT_ID, EVIDENCE_V1)
    other_project = "controlgraph-canary-test02"
    other_evidence_profile = SigningProfile.evidence(
        other_project,
        EVIDENCE_V1.replace(PROJECT_ID, other_project),
    )
    selected = {
        "capability_only": [capability_profile],
        "evidence_only": [evidence_profile],
        "cross_project": [capability_profile, other_evidence_profile],
        "duplicate": [capability_profile, capability_profile, evidence_profile],
    }[profiles]
    fake = _FakeKmsClient(
        [
            _FakeKeyVersion(capability_profile, ec.generate_private_key(ec.SECP256R1())),
            _FakeKeyVersion(evidence_profile, ec.generate_private_key(ec.SECP256R1())),
        ]
    )
    publisher = GoogleKmsTrustBundlePublisher(
        project_id=PROJECT_ID,
        role="api",
        client=fake,
    )

    with pytest.raises(SigningError) as failure:
        publisher.publish(selected)

    assert failure.value.code is code
    assert fake.version_requests == []


def test_kms_publication_validates_crc_and_preserves_disabled_rotation_state() -> None:
    old_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    new_profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V2)
    old_evidence_profile = SigningProfile.evidence(PROJECT_ID, EVIDENCE_V1)
    new_evidence_profile = SigningProfile.evidence(PROJECT_ID, EVIDENCE_V2)
    old_version = _FakeKeyVersion(
        old_profile,
        ec.generate_private_key(ec.SECP256R1()),
        state="DISABLED",
    )
    new_version = _FakeKeyVersion(new_profile, ec.generate_private_key(ec.SECP256R1()))
    old_evidence_version = _FakeKeyVersion(
        old_evidence_profile,
        ec.generate_private_key(ec.SECP256R1()),
        state="DISABLED",
    )
    new_evidence_version = _FakeKeyVersion(
        new_evidence_profile,
        ec.generate_private_key(ec.SECP256R1()),
    )
    fake = _FakeKmsClient([old_version, new_version, old_evidence_version, new_evidence_version])

    bundle = GoogleKmsTrustBundlePublisher(
        project_id=PROJECT_ID,
        role="api",
        client=fake,
    ).publish([old_profile, new_profile, old_evidence_profile, new_evidence_profile])

    assert [entry.state for entry in bundle.entries] == [
        SigningKeyState.DISABLED,
        SigningKeyState.ENABLED,
        SigningKeyState.DISABLED,
        SigningKeyState.ENABLED,
    ]
    assert TrustBundle.parse(bundle.to_json_bytes()) == bundle

    fake.public_key_crc_offset = 1
    with pytest.raises(SigningError) as crc:
        GoogleKmsTrustBundlePublisher(
            project_id=PROJECT_ID,
            role="api",
            client=fake,
        ).publish([new_profile, new_evidence_profile])
    assert crc.value.code is SigningErrorCode.CRC_MISMATCH


def test_kms_signer_and_published_bundle_verify_end_to_end() -> None:
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    evidence_profile = SigningProfile.evidence(PROJECT_ID, EVIDENCE_V1)
    fake = _FakeKmsClient(
        [
            _FakeKeyVersion(profile, ec.generate_private_key(ec.SECP256R1())),
            _FakeKeyVersion(evidence_profile, ec.generate_private_key(ec.SECP256R1())),
        ]
    )
    bundle = GoogleKmsTrustBundlePublisher(
        project_id=PROJECT_ID,
        role="api",
        client=fake,
    ).publish([profile, evidence_profile])
    detached = PurposeSealedSigner(GoogleKmsDigestSigner(profile, client=fake)).sign(_capability())

    TrustBundleVerifier(VerificationProfile.capability(PROJECT_ID, CAPABILITY_KEY), bundle).verify(
        _capability(), detached
    )


def test_bundle_parser_rejects_non_string_entry_values() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    profile = SigningProfile.capability(PROJECT_ID, CAPABILITY_V1)
    encoded = _bundle_entry(profile, private_key)
    value = json.loads(TrustBundle(entries=(encoded,)).to_json_bytes())
    value["entries"][0]["state"] = True
    malformed = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(SigningError) as failure:
        TrustBundle.parse(malformed)
    assert failure.value.code is SigningErrorCode.TRUST_BUNDLE_INVALID
