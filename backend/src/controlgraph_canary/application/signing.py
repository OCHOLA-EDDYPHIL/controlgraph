"""Purpose-sealed signing and verification for canonical ControlGraph contracts."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast

from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    ContractError,
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    decode_base64url,
    encode_base64url,
)
from controlgraph_canary.contracts.models import (
    CAPABILITY_CLAIMS_V1,
    EVIDENCE_EVENT_V1,
    CapabilityClaims,
    EvidenceEvent,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

SIGNATURE_INPUT_V1 = "controlgraph.signature-input/v1"
DETACHED_SIGNATURE_V1 = "controlgraph.detached-signature/v1"
TRUST_BUNDLE_V1 = "controlgraph.signing-trust-bundle/v1"
SIGNING_ALGORITHM = "EC_SIGN_P256_SHA256"
_SIGNING_DOMAIN = b"controlgraph.signature-input/v1\0"
_MAX_TRUST_BUNDLE_BYTES = 65_536
_MAX_TRUST_ENTRIES = 32
_MAX_PUBLIC_KEY_PEM_BYTES = 1_024

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_KEY_RESOURCE_PATTERN = (
    r"projects/(?P<project>controlgraph-canary-[a-z0-9]{6,10})/"
    r"locations/us-central1/keyRings/controlgraph-signing/"
    r"cryptoKeys/(?P<key_name>capability-signing|evidence-signing)"
)
_KEY_VERSION = re.compile(
    rf"^(?P<key>{_KEY_RESOURCE_PATTERN})/cryptoKeyVersions/(?P<version>[1-9][0-9]*)$"
)
_KEY_RESOURCE = re.compile(rf"^{_KEY_RESOURCE_PATTERN}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SigningPurpose(StrEnum):
    """The only signing purposes admitted by the first ControlGraph vertical."""

    CAPABILITY = "CAPABILITY"
    EVIDENCE = "EVIDENCE"


class SigningKeyState(StrEnum):
    """Trust-relevant key-version states."""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class SigningErrorCode(StrEnum):
    """Stable, payload-free signing and verification failures."""

    PROFILE_INVALID = "SIGNING_PROFILE_INVALID"
    PURPOSE_MISMATCH = "SIGNING_PURPOSE_MISMATCH"
    PAYLOAD_VERSION_MISMATCH = "SIGNING_PAYLOAD_VERSION_MISMATCH"
    KEY_VERSION_MISMATCH = "SIGNING_KEY_VERSION_MISMATCH"
    KEY_VERSION_UNTRUSTED = "SIGNING_KEY_VERSION_UNTRUSTED"
    KEY_VERSION_DISABLED = "SIGNING_KEY_VERSION_DISABLED"
    ALGORITHM_MISMATCH = "SIGNING_ALGORITHM_MISMATCH"
    DIGEST_MISMATCH = "SIGNING_DIGEST_MISMATCH"
    CRC_MISMATCH = "SIGNING_CRC_MISMATCH"
    PUBLIC_KEY_INVALID = "SIGNING_PUBLIC_KEY_INVALID"
    TRUST_BUNDLE_INVALID = "SIGNING_TRUST_BUNDLE_INVALID"
    SIGNATURE_INVALID = "SIGNING_SIGNATURE_INVALID"
    PROVIDER_FAILURE = "SIGNING_PROVIDER_FAILURE"


class SigningError(ValueError):
    """A bounded failure that never reflects payload or provider text."""

    def __init__(self, code: SigningErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _fail(code: SigningErrorCode, message: str) -> SigningError:
    return SigningError(code, message)


def _purpose_payload_version(purpose: SigningPurpose) -> str:
    if purpose is SigningPurpose.CAPABILITY:
        return CAPABILITY_CLAIMS_V1
    if purpose is SigningPurpose.EVIDENCE:
        return EVIDENCE_EVENT_V1
    raise _fail(SigningErrorCode.PROFILE_INVALID, "signing purpose is unsupported")


def _parse_key_version(key_version: str) -> tuple[str, int]:
    if type(key_version) is not str:
        raise _fail(SigningErrorCode.PROFILE_INVALID, "key version resource is invalid")
    matched = _KEY_VERSION.fullmatch(key_version)
    if matched is None:
        raise _fail(SigningErrorCode.PROFILE_INVALID, "key version resource is invalid")
    return matched.group("key"), int(matched.group("version"))


def _parse_key_resource(key_resource: str) -> tuple[str, str]:
    if type(key_resource) is not str:
        raise _fail(SigningErrorCode.PROFILE_INVALID, "key resource is invalid")
    matched = _KEY_RESOURCE.fullmatch(key_resource)
    if matched is None:
        raise _fail(SigningErrorCode.PROFILE_INVALID, "key resource is invalid")
    return matched.group("project"), matched.group("key_name")


def _validate_purpose_key(purpose: SigningPurpose, key_resource: str) -> None:
    _, key_name = _parse_key_resource(key_resource)
    expected_key_name = {
        SigningPurpose.CAPABILITY: "capability-signing",
        SigningPurpose.EVIDENCE: "evidence-signing",
    }[purpose]
    if key_name != expected_key_name:
        raise _fail(SigningErrorCode.PROFILE_INVALID, "key resource does not match its purpose")


@dataclass(frozen=True, slots=True)
class SigningProfile:
    """One immutable purpose, key version, algorithm, and payload-version binding."""

    purpose: SigningPurpose
    project_id: str
    key_version: str
    algorithm: str = field(init=False, default=SIGNING_ALGORITHM)
    payload_version: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.purpose) is not SigningPurpose:
            raise _fail(SigningErrorCode.PROFILE_INVALID, "signing purpose is invalid")
        if type(self.project_id) is not str or _PROJECT_ID.fullmatch(self.project_id) is None:
            raise _fail(SigningErrorCode.PROFILE_INVALID, "signing project is invalid")
        key_resource, _ = _parse_key_version(self.key_version)
        key_project, _ = _parse_key_resource(key_resource)
        if key_project != self.project_id:
            raise _fail(
                SigningErrorCode.PROFILE_INVALID,
                "signing key does not belong to the configured project",
            )
        _validate_purpose_key(self.purpose, key_resource)
        object.__setattr__(self, "payload_version", _purpose_payload_version(self.purpose))

    @classmethod
    def capability(cls, project_id: str, key_version: str) -> SigningProfile:
        return cls(
            purpose=SigningPurpose.CAPABILITY,
            project_id=project_id,
            key_version=key_version,
        )

    @classmethod
    def evidence(cls, project_id: str, key_version: str) -> SigningProfile:
        return cls(
            purpose=SigningPurpose.EVIDENCE,
            project_id=project_id,
            key_version=key_version,
        )

    @property
    def key_resource(self) -> str:
        return _parse_key_version(self.key_version)[0]


@dataclass(frozen=True, slots=True)
class VerificationProfile:
    """A purpose-sealed verifier policy that permits rotation within one KMS key."""

    purpose: SigningPurpose
    project_id: str
    key_resource: str
    algorithm: str = field(init=False, default=SIGNING_ALGORITHM)
    payload_version: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.purpose) is not SigningPurpose:
            raise _fail(SigningErrorCode.PROFILE_INVALID, "verification purpose is invalid")
        if type(self.project_id) is not str or _PROJECT_ID.fullmatch(self.project_id) is None:
            raise _fail(SigningErrorCode.PROFILE_INVALID, "verification project is invalid")
        key_project, _ = _parse_key_resource(self.key_resource)
        if key_project != self.project_id:
            raise _fail(
                SigningErrorCode.PROFILE_INVALID,
                "verification key does not belong to the configured project",
            )
        _validate_purpose_key(self.purpose, self.key_resource)
        object.__setattr__(self, "payload_version", _purpose_payload_version(self.purpose))

    @classmethod
    def capability(cls, project_id: str, key_resource: str) -> VerificationProfile:
        return cls(
            purpose=SigningPurpose.CAPABILITY,
            project_id=project_id,
            key_resource=key_resource,
        )

    @classmethod
    def evidence(cls, project_id: str, key_resource: str) -> VerificationProfile:
        return cls(
            purpose=SigningPurpose.EVIDENCE,
            project_id=project_id,
            key_resource=key_resource,
        )


@dataclass(frozen=True, slots=True)
class CanonicalSigningInput:
    """Canonical payload bytes and the exact digest sent to a signing backend."""

    canonical_bytes: bytes
    payload_sha256: str
    digest: bytes

    @property
    def digest_sha256(self) -> str:
        return self.digest.hex()


@dataclass(frozen=True, slots=True)
class DetachedSignature:
    """A signature and its non-payload trust bindings."""

    schema_version: str
    purpose: SigningPurpose
    key_version: str
    algorithm: str
    payload_version: str
    payload_sha256: str
    digest_sha256: str
    signature: str


class DigestSigningBackend(Protocol):
    """A backend already sealed to one exact signing profile."""

    @property
    def profile(self) -> SigningProfile: ...

    def sign_digest(self, digest: bytes) -> bytes: ...


def _validate_payload(profile: SigningProfile | VerificationProfile, payload: object) -> None:
    if not isinstance(payload, StrictContractModel):
        raise _fail(SigningErrorCode.PURPOSE_MISMATCH, "signing payload type is invalid")
    version = getattr(payload, "schema_version", None)
    if version != profile.payload_version:
        raise _fail(
            SigningErrorCode.PAYLOAD_VERSION_MISMATCH,
            "signing payload version does not match its profile",
        )
    if not isinstance(payload, (CapabilityClaims, EvidenceEvent)):
        raise _fail(SigningErrorCode.PURPOSE_MISMATCH, "signing payload type is invalid")
    if payload.target.project_id != profile.project_id or payload.target.region != "us-central1":
        raise _fail(
            SigningErrorCode.KEY_VERSION_MISMATCH,
            "signing key coordinates do not match the payload target",
        )
    if profile.purpose is SigningPurpose.CAPABILITY:
        if not isinstance(payload, CapabilityClaims):
            raise _fail(
                SigningErrorCode.PURPOSE_MISMATCH,
                "signing payload does not match the capability purpose",
            )
        if isinstance(profile, SigningProfile):
            key_matches = payload.signing_key_version == profile.key_version
        else:
            try:
                key_matches = (
                    _parse_key_version(payload.signing_key_version)[0] == profile.key_resource
                )
            except SigningError:
                key_matches = False
        if not key_matches:
            raise _fail(
                SigningErrorCode.KEY_VERSION_MISMATCH,
                "capability key version does not match its signing profile",
            )
        if payload.signing_algorithm != profile.algorithm:
            raise _fail(
                SigningErrorCode.ALGORITHM_MISMATCH,
                "capability algorithm does not match its signing profile",
            )
    elif not isinstance(payload, EvidenceEvent):
        raise _fail(
            SigningErrorCode.PURPOSE_MISMATCH,
            "signing payload does not match the evidence purpose",
        )


def build_signing_input(
    profile: SigningProfile,
    payload: StrictContractModel,
) -> CanonicalSigningInput:
    """Bind canonical bytes to purpose, key, algorithm, and payload version."""

    _validate_payload(profile, payload)
    canonical = canonical_json_bytes(payload)
    header: RestrictedJson = {
        "algorithm": profile.algorithm,
        "key_version": profile.key_version,
        "payload_version": profile.payload_version,
        "purpose": profile.purpose.value,
        "schema_version": SIGNATURE_INPUT_V1,
    }
    header_bytes = canonical_json_value_bytes(header)
    digest = hashlib.sha256(_SIGNING_DOMAIN + header_bytes + b"\0" + canonical).digest()
    return CanonicalSigningInput(
        canonical_bytes=canonical,
        payload_sha256=hashlib.sha256(canonical).hexdigest(),
        digest=digest,
    )


def _build_verification_input(
    profile: VerificationProfile,
    key_version: str,
    payload: StrictContractModel,
) -> CanonicalSigningInput:
    _validate_payload(profile, payload)
    if isinstance(payload, CapabilityClaims) and payload.signing_key_version != key_version:
        raise _fail(
            SigningErrorCode.KEY_VERSION_MISMATCH,
            "capability key version does not match its detached signature",
        )
    canonical = canonical_json_bytes(payload)
    header: RestrictedJson = {
        "algorithm": profile.algorithm,
        "key_version": key_version,
        "payload_version": profile.payload_version,
        "purpose": profile.purpose.value,
        "schema_version": SIGNATURE_INPUT_V1,
    }
    header_bytes = canonical_json_value_bytes(header)
    digest = hashlib.sha256(_SIGNING_DOMAIN + header_bytes + b"\0" + canonical).digest()
    return CanonicalSigningInput(
        canonical_bytes=canonical,
        payload_sha256=hashlib.sha256(canonical).hexdigest(),
        digest=digest,
    )


class PurposeSealedSigner:
    """Sign canonical contracts through one fixed backend profile."""

    def __init__(self, backend: DigestSigningBackend) -> None:
        self._backend = backend
        self._profile = backend.profile
        if not isinstance(self._profile, SigningProfile):
            raise _fail(SigningErrorCode.PROFILE_INVALID, "signing backend profile is invalid")

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    def sign(self, payload: StrictContractModel) -> DetachedSignature:
        signing_input = build_signing_input(self._profile, payload)
        signature = self._backend.sign_digest(signing_input.digest)
        if type(signature) is not bytes or not signature or len(signature) > 256:
            raise _fail(SigningErrorCode.SIGNATURE_INVALID, "signer returned an invalid signature")
        return DetachedSignature(
            schema_version=DETACHED_SIGNATURE_V1,
            purpose=self._profile.purpose,
            key_version=self._profile.key_version,
            algorithm=self._profile.algorithm,
            payload_version=self._profile.payload_version,
            payload_sha256=signing_input.payload_sha256,
            digest_sha256=signing_input.digest_sha256,
            signature=encode_base64url(signature),
        )


@dataclass(frozen=True, slots=True)
class TrustBundleEntry:
    """One public key version and its fixed trust metadata."""

    purpose: SigningPurpose
    key_version: str
    algorithm: str
    payload_version: str
    state: SigningKeyState
    public_key_pem: str
    public_key_sha256: str

    @property
    def key_resource(self) -> str:
        return _parse_key_version(self.key_version)[0]


def _load_p256_public_key(pem: str) -> EllipticCurvePublicKey:
    try:
        encoded = pem.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        raise _fail(SigningErrorCode.PUBLIC_KEY_INVALID, "public key PEM is invalid") from None
    if not encoded or len(encoded) > _MAX_PUBLIC_KEY_PEM_BYTES or b"\r" in encoded:
        raise _fail(SigningErrorCode.PUBLIC_KEY_INVALID, "public key PEM is invalid")

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        loaded = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError):
        raise _fail(SigningErrorCode.PUBLIC_KEY_INVALID, "public key PEM is invalid") from None
    if not isinstance(loaded, ec.EllipticCurvePublicKey) or not isinstance(
        loaded.curve, ec.SECP256R1
    ):
        raise _fail(SigningErrorCode.PUBLIC_KEY_INVALID, "public key must use P-256")
    canonical = loaded.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if canonical != encoded:
        raise _fail(SigningErrorCode.PUBLIC_KEY_INVALID, "public key PEM is not canonical")
    return loaded


def make_trust_bundle_entry(
    *,
    profile: SigningProfile,
    state: SigningKeyState,
    public_key_pem: str,
) -> TrustBundleEntry:
    """Validate public material before admitting it to a trust bundle."""

    if type(state) is not SigningKeyState:
        raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "key state is invalid")
    _load_p256_public_key(public_key_pem)
    return TrustBundleEntry(
        purpose=profile.purpose,
        key_version=profile.key_version,
        algorithm=profile.algorithm,
        payload_version=profile.payload_version,
        state=state,
        public_key_pem=public_key_pem,
        public_key_sha256=hashlib.sha256(public_key_pem.encode("ascii")).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class TrustBundle:
    """Strict public-only trust material for one or both fixed purposes."""

    entries: tuple[TrustBundleEntry, ...]

    def __post_init__(self) -> None:
        if not self.entries or len(self.entries) > _MAX_TRUST_ENTRIES:
            raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust entry count is invalid")
        seen_versions: set[str] = set()
        projects: set[str] = set()
        purpose_resources: dict[SigningPurpose, str] = {}
        purpose_public_keys: dict[SigningPurpose, set[str]] = {}
        for entry in self.entries:
            if type(entry) is not TrustBundleEntry:
                raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust entry is invalid")
            if type(entry.key_version) is not str:
                raise _fail(
                    SigningErrorCode.TRUST_BUNDLE_INVALID,
                    "trusted key version is invalid",
                )
            if entry.key_version in seen_versions:
                raise _fail(
                    SigningErrorCode.TRUST_BUNDLE_INVALID,
                    "trust bundle contains a duplicate key version",
                )
            seen_versions.add(entry.key_version)
            if type(entry.purpose) is not SigningPurpose:
                raise _fail(
                    SigningErrorCode.TRUST_BUNDLE_INVALID,
                    "trusted key purpose is invalid",
                )
            try:
                key_resource, _ = _parse_key_version(entry.key_version)
                project, _ = _parse_key_resource(key_resource)
                _validate_purpose_key(entry.purpose, key_resource)
            except SigningError:
                raise _fail(
                    SigningErrorCode.TRUST_BUNDLE_INVALID,
                    "trusted key resource is invalid",
                ) from None
            projects.add(project)
            if entry.algorithm != SIGNING_ALGORITHM:
                raise _fail(SigningErrorCode.ALGORITHM_MISMATCH, "trusted algorithm is invalid")
            if entry.payload_version != _purpose_payload_version(entry.purpose):
                raise _fail(
                    SigningErrorCode.PAYLOAD_VERSION_MISMATCH,
                    "trusted payload version is invalid",
                )
            if type(entry.state) is not SigningKeyState:
                raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trusted key state is invalid")
            _load_p256_public_key(entry.public_key_pem)
            expected_key_digest = hashlib.sha256(entry.public_key_pem.encode("ascii")).hexdigest()
            if not hmac.compare_digest(expected_key_digest, entry.public_key_sha256):
                raise _fail(
                    SigningErrorCode.DIGEST_MISMATCH,
                    "trusted public key digest is invalid",
                )
            existing_resource = purpose_resources.setdefault(entry.purpose, key_resource)
            if existing_resource != key_resource:
                raise _fail(
                    SigningErrorCode.TRUST_BUNDLE_INVALID,
                    "one purpose cannot span multiple KMS keys",
                )
            purpose_public_keys.setdefault(entry.purpose, set()).add(entry.public_key_sha256)

        if len(projects) != 1:
            raise _fail(
                SigningErrorCode.TRUST_BUNDLE_INVALID,
                "trust bundle keys must belong to one ControlGraph project",
            )

        capability_resource = purpose_resources.get(SigningPurpose.CAPABILITY)
        evidence_resource = purpose_resources.get(SigningPurpose.EVIDENCE)
        if capability_resource is not None and capability_resource == evidence_resource:
            raise _fail(
                SigningErrorCode.TRUST_BUNDLE_INVALID,
                "capability and evidence purposes require distinct KMS keys",
            )
        if (
            set.intersection(*purpose_public_keys.values())
            if len(purpose_public_keys) == 2
            else set()
        ):
            raise _fail(
                SigningErrorCode.TRUST_BUNDLE_INVALID,
                "capability and evidence purposes require distinct public keys",
            )
        object.__setattr__(
            self,
            "entries",
            tuple(sorted(self.entries, key=lambda item: (item.purpose.value, item.key_version))),
        )

    def entry(self, key_version: str) -> TrustBundleEntry | None:
        return next((entry for entry in self.entries if entry.key_version == key_version), None)

    def to_json_bytes(self) -> bytes:
        value = {
            "entries": [
                {
                    "algorithm": entry.algorithm,
                    "key_version": entry.key_version,
                    "payload_version": entry.payload_version,
                    "public_key_pem": entry.public_key_pem,
                    "public_key_sha256": entry.public_key_sha256,
                    "purpose": entry.purpose.value,
                    "state": entry.state.value,
                }
                for entry in sorted(
                    self.entries, key=lambda item: (item.purpose.value, item.key_version)
                )
            ],
            "schema_version": TRUST_BUNDLE_V1,
        }
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def parse(cls, payload: bytes) -> TrustBundle:
        if type(payload) is not bytes or not payload or len(payload) > _MAX_TRUST_BUNDLE_BYTES:
            raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust bundle bytes are invalid")
        if payload.startswith(b"\xef\xbb\xbf"):
            raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust bundle bytes are invalid")

        def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        try:
            decoded = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
        except (RecursionError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
            raise _fail(
                SigningErrorCode.TRUST_BUNDLE_INVALID, "trust bundle JSON is invalid"
            ) from None
        if type(decoded) is not dict or set(decoded) != {"entries", "schema_version"}:
            raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust bundle shape is invalid")
        if decoded["schema_version"] != TRUST_BUNDLE_V1 or type(decoded["entries"]) is not list:
            raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust bundle version is invalid")

        entries: list[TrustBundleEntry] = []
        for raw_entry in cast(list[object], decoded["entries"]):
            if type(raw_entry) is not dict or set(raw_entry) != {
                "algorithm",
                "key_version",
                "payload_version",
                "public_key_pem",
                "public_key_sha256",
                "purpose",
                "state",
            }:
                raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust entry shape is invalid")
            entry = cast(dict[str, object], raw_entry)
            if not all(type(value) is str for value in entry.values()):
                raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust entry values are invalid")
            try:
                purpose = SigningPurpose(cast(str, entry["purpose"]))
                state = SigningKeyState(cast(str, entry["state"]))
            except ValueError:
                raise _fail(
                    SigningErrorCode.TRUST_BUNDLE_INVALID,
                    "trust entry enumeration is invalid",
                ) from None
            parsed_entry = TrustBundleEntry(
                purpose=purpose,
                key_version=cast(str, entry["key_version"]),
                algorithm=cast(str, entry["algorithm"]),
                payload_version=cast(str, entry["payload_version"]),
                state=state,
                public_key_pem=cast(str, entry["public_key_pem"]),
                public_key_sha256=cast(str, entry["public_key_sha256"]),
            )
            entries.append(parsed_entry)
        bundle = cls(entries=tuple(entries))
        if bundle.to_json_bytes() != payload:
            raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trust bundle is not canonical")
        return bundle


class TrustBundleVerifier:
    """Verify detached P-256 signatures against one configured purpose and KMS key."""

    def __init__(self, profile: VerificationProfile, trust_bundle: TrustBundle) -> None:
        self._profile = profile
        self._trust_bundle = trust_bundle

    @property
    def profile(self) -> VerificationProfile:
        return self._profile

    def verify(self, payload: StrictContractModel, detached: DetachedSignature) -> None:
        if detached.schema_version != DETACHED_SIGNATURE_V1:
            raise _fail(SigningErrorCode.SIGNATURE_INVALID, "signature version is invalid")
        if detached.purpose is not self._profile.purpose:
            raise _fail(SigningErrorCode.PURPOSE_MISMATCH, "signature purpose is invalid")
        if detached.algorithm != self._profile.algorithm:
            raise _fail(SigningErrorCode.ALGORITHM_MISMATCH, "signature algorithm is invalid")
        if detached.payload_version != self._profile.payload_version:
            raise _fail(
                SigningErrorCode.PAYLOAD_VERSION_MISMATCH,
                "signature payload version is invalid",
            )
        try:
            key_resource, _ = _parse_key_version(detached.key_version)
        except SigningError:
            raise _fail(
                SigningErrorCode.KEY_VERSION_UNTRUSTED,
                "signature key version is invalid",
            ) from None
        if key_resource != self._profile.key_resource:
            raise _fail(
                SigningErrorCode.KEY_VERSION_UNTRUSTED,
                "signature key version is not trusted",
            )
        entry = self._trust_bundle.entry(detached.key_version)
        if entry is None or entry.purpose is not self._profile.purpose:
            raise _fail(
                SigningErrorCode.KEY_VERSION_UNTRUSTED,
                "signature key version is not trusted",
            )
        if entry.state is not SigningKeyState.ENABLED:
            raise _fail(SigningErrorCode.KEY_VERSION_DISABLED, "signature key version is disabled")
        if (
            entry.algorithm != detached.algorithm
            or entry.payload_version != detached.payload_version
        ):
            raise _fail(SigningErrorCode.TRUST_BUNDLE_INVALID, "trusted key binding is invalid")

        expected = _build_verification_input(self._profile, detached.key_version, payload)
        if not _SHA256.fullmatch(detached.payload_sha256) or not hmac.compare_digest(
            expected.payload_sha256, detached.payload_sha256
        ):
            raise _fail(SigningErrorCode.DIGEST_MISMATCH, "payload digest is invalid")
        if not _SHA256.fullmatch(detached.digest_sha256) or not hmac.compare_digest(
            expected.digest_sha256, detached.digest_sha256
        ):
            raise _fail(SigningErrorCode.DIGEST_MISMATCH, "signing digest is invalid")
        try:
            signature = decode_base64url(detached.signature, maximum_bytes=256)
        except ContractError:
            raise _fail(
                SigningErrorCode.SIGNATURE_INVALID, "signature encoding is invalid"
            ) from None

        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, utils

            r, s = utils.decode_dss_signature(signature)
            if utils.encode_dss_signature(r, s) != signature:
                raise ValueError("non-canonical DER")
            public_key = _load_p256_public_key(entry.public_key_pem)
            public_key.verify(
                signature,
                expected.digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        except (InvalidSignature, TypeError, ValueError):
            raise _fail(
                SigningErrorCode.SIGNATURE_INVALID, "signature verification failed"
            ) from None


__all__ = [
    "DETACHED_SIGNATURE_V1",
    "SIGNATURE_INPUT_V1",
    "SIGNING_ALGORITHM",
    "TRUST_BUNDLE_V1",
    "CanonicalSigningInput",
    "DetachedSignature",
    "DigestSigningBackend",
    "PurposeSealedSigner",
    "SigningError",
    "SigningErrorCode",
    "SigningKeyState",
    "SigningProfile",
    "SigningPurpose",
    "TrustBundle",
    "TrustBundleEntry",
    "TrustBundleVerifier",
    "VerificationProfile",
    "build_signing_input",
    "make_trust_bundle_entry",
]
