"""Cloud KMS adapters for fixed-profile digest signing and public trust material."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from threading import Lock
from typing import Protocol, cast

from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.application.signing import (
    DETACHED_SIGNATURE_V1,
    SIGNING_ALGORITHM,
    DetachedSignature,
    SigningError,
    SigningErrorCode,
    SigningKeyState,
    SigningProfile,
    SigningPurpose,
    TrustBundle,
    TrustBundleVerifier,
    VerificationProfile,
    make_trust_bundle_entry,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_TRUST_BUNDLE_PUBLISHER_ROLE = "api"
_TRUST_BUNDLE_PURPOSES = frozenset({SigningPurpose.CAPABILITY, SigningPurpose.EVIDENCE})
_MAX_TRUST_BUNDLE_PROFILES = 32
_KMS_REQUEST_TIMEOUT_SECONDS = 5.0


class _KmsClient(Protocol):
    def get_crypto_key_version(self, request: dict[str, object]) -> object: ...

    def asymmetric_sign(self, request: dict[str, object]) -> object: ...

    def get_public_key(self, request: dict[str, object]) -> object: ...


class _AsyncKmsClient(Protocol):
    async def get_crypto_key_version(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object: ...

    async def asymmetric_sign(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object: ...

    async def get_public_key(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object: ...


class _VersionResponse(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def state(self) -> object: ...

    @property
    def algorithm(self) -> object: ...


class _SignResponse(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def signature(self) -> bytes: ...

    @property
    def signature_crc32c(self) -> int: ...

    @property
    def verified_digest_crc32c(self) -> bool: ...


class _PublicKeyResponse(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def algorithm(self) -> object: ...

    @property
    def pem(self) -> str: ...

    @property
    def pem_crc32c(self) -> int: ...


def _error(code: SigningErrorCode, message: str) -> SigningError:
    return SigningError(code, message)


def _default_client() -> _KmsClient:
    try:
        from google.cloud import kms_v1

        return cast(_KmsClient, kms_v1.KeyManagementServiceClient())
    except Exception:
        raise _error(
            SigningErrorCode.PROVIDER_FAILURE, "KMS client initialization failed"
        ) from None


def _default_async_client() -> _AsyncKmsClient:
    try:
        from google.cloud import kms_v1

        return cast(_AsyncKmsClient, kms_v1.KeyManagementServiceAsyncClient())
    except Exception:
        raise _error(
            SigningErrorCode.PROVIDER_FAILURE, "KMS client initialization failed"
        ) from None


def _crc32c(value: bytes) -> int:
    try:
        import google_crc32c

        checksum = google_crc32c.value(value)
    except Exception:
        raise _error(SigningErrorCode.CRC_MISMATCH, "CRC32C computation failed") from None
    if type(checksum) is not int:
        raise _error(SigningErrorCode.CRC_MISMATCH, "CRC32C computation failed")
    return checksum


def _enum_name(value: object) -> str | None:
    if type(value) is str:
        return value
    name = getattr(value, "name", None)
    return name if type(name) is str else None


def _load_version(
    client: _KmsClient,
    profile: SigningProfile,
    *,
    permit_disabled: bool,
) -> SigningKeyState:
    try:
        raw_response = client.get_crypto_key_version({"name": profile.key_version})
        response = cast(_VersionResponse, raw_response)
        name = response.name
        state_name = _enum_name(response.state)
        algorithm_name = _enum_name(response.algorithm)
    except SigningError:
        raise
    except Exception:
        raise _error(SigningErrorCode.PROVIDER_FAILURE, "KMS version lookup failed") from None

    if type(name) is not str or name != profile.key_version:
        raise _error(SigningErrorCode.KEY_VERSION_MISMATCH, "KMS returned another key version")
    if algorithm_name != SIGNING_ALGORITHM or algorithm_name != profile.algorithm:
        raise _error(SigningErrorCode.ALGORITHM_MISMATCH, "KMS key algorithm is invalid")
    if state_name == SigningKeyState.ENABLED.value:
        return SigningKeyState.ENABLED
    if permit_disabled and state_name == SigningKeyState.DISABLED.value:
        return SigningKeyState.DISABLED
    raise _error(SigningErrorCode.KEY_VERSION_DISABLED, "KMS key version is not enabled")


def _load_public_key(client: _KmsClient, profile: SigningProfile) -> str:
    try:
        raw_response = client.get_public_key({"name": profile.key_version})
        response = cast(_PublicKeyResponse, raw_response)
        response_name = response.name
        algorithm_name = _enum_name(response.algorithm)
        public_key_pem = response.pem
        public_key_crc32c = response.pem_crc32c
    except SigningError:
        raise
    except Exception:
        raise _error(
            SigningErrorCode.PROVIDER_FAILURE,
            "KMS public key lookup failed",
        ) from None

    if type(response_name) is not str or response_name != profile.key_version:
        raise _error(
            SigningErrorCode.KEY_VERSION_MISMATCH,
            "KMS returned another public key version",
        )
    if algorithm_name != SIGNING_ALGORITHM or algorithm_name != profile.algorithm:
        raise _error(
            SigningErrorCode.ALGORITHM_MISMATCH,
            "KMS public key algorithm is invalid",
        )
    if type(public_key_pem) is not str:
        raise _error(SigningErrorCode.PUBLIC_KEY_INVALID, "KMS public key PEM is invalid")
    try:
        public_key_bytes = public_key_pem.encode("ascii")
    except UnicodeEncodeError:
        raise _error(
            SigningErrorCode.PUBLIC_KEY_INVALID,
            "KMS public key PEM is invalid",
        ) from None
    if (
        type(public_key_crc32c) is not int
        or public_key_crc32c != _crc32c(public_key_bytes)
    ):
        raise _error(SigningErrorCode.CRC_MISMATCH, "KMS public key CRC32C is invalid")
    return public_key_pem


async def _load_version_async(
    client: _AsyncKmsClient,
    profile: SigningProfile,
) -> None:
    try:
        raw_response = await client.get_crypto_key_version(
            {"name": profile.key_version},
            retry=None,
            timeout=_KMS_REQUEST_TIMEOUT_SECONDS,
        )
        response = cast(_VersionResponse, raw_response)
        name = response.name
        state_name = _enum_name(response.state)
        algorithm_name = _enum_name(response.algorithm)
    except asyncio.CancelledError:
        raise
    except SigningError:
        raise
    except Exception:
        raise _error(SigningErrorCode.PROVIDER_FAILURE, "KMS version lookup failed") from None

    if type(name) is not str or name != profile.key_version:
        raise _error(SigningErrorCode.KEY_VERSION_MISMATCH, "KMS returned another key version")
    if algorithm_name != SIGNING_ALGORITHM or algorithm_name != profile.algorithm:
        raise _error(SigningErrorCode.ALGORITHM_MISMATCH, "KMS key algorithm is invalid")
    if state_name != SigningKeyState.ENABLED.value:
        raise _error(SigningErrorCode.KEY_VERSION_DISABLED, "KMS key version is not enabled")


class GoogleKmsDigestSigner:
    """Sign only SHA-256 digests with one exact KMS key version and algorithm."""

    def __init__(self, profile: SigningProfile, *, client: object | None = None) -> None:
        if type(profile) is not SigningProfile:
            raise _error(SigningErrorCode.PROFILE_INVALID, "KMS profile is invalid")
        self._profile = profile
        self._client = None if client is None else cast(_KmsClient, client)
        self._client_lock = Lock()

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    def sign_digest(self, digest: bytes) -> bytes:
        if type(digest) is not bytes or len(digest) != 32:
            raise _error(SigningErrorCode.DIGEST_MISMATCH, "signing digest must be SHA-256")
        client = self._get_client()
        _load_version(client, self._profile, permit_disabled=False)
        digest_crc32c = _crc32c(digest)
        request: dict[str, object] = {
            "name": self._profile.key_version,
            "digest": {"sha256": digest},
            "digest_crc32c": digest_crc32c,
        }
        try:
            raw_response = client.asymmetric_sign(request)
            response = cast(_SignResponse, raw_response)
            response_name = response.name
            signature = response.signature
            signature_crc32c = response.signature_crc32c
            verified_digest_crc32c = response.verified_digest_crc32c
        except SigningError:
            raise
        except Exception:
            raise _error(SigningErrorCode.PROVIDER_FAILURE, "KMS signing failed") from None

        if type(response_name) is not str or response_name != self._profile.key_version:
            raise _error(
                SigningErrorCode.KEY_VERSION_MISMATCH, "KMS signed with another key version"
            )
        if verified_digest_crc32c is not True:
            raise _error(SigningErrorCode.CRC_MISMATCH, "KMS did not verify the digest CRC32C")
        if type(signature) is not bytes or not signature or len(signature) > 256:
            raise _error(SigningErrorCode.SIGNATURE_INVALID, "KMS signature is invalid")
        if type(signature_crc32c) is not int or signature_crc32c != _crc32c(signature):
            raise _error(SigningErrorCode.CRC_MISMATCH, "KMS signature CRC32C is invalid")
        return signature

    def _get_client(self) -> _KmsClient:
        client = self._client
        if client is not None:
            return client
        with self._client_lock:
            client = self._client
            if client is None:
                client = _default_client()
                self._client = client
        return client


class GoogleKmsAsyncDigestSigner:
    """Asynchronously sign one digest with no retries and bounded cancellation."""

    def __init__(self, profile: SigningProfile, *, client: object | None = None) -> None:
        if type(profile) is not SigningProfile:
            raise _error(SigningErrorCode.PROFILE_INVALID, "KMS profile is invalid")
        self._profile = profile
        self._client = None if client is None else cast(_AsyncKmsClient, client)

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    async def sign_digest(self, digest: bytes) -> bytes:
        if type(digest) is not bytes or len(digest) != 32:
            raise _error(SigningErrorCode.DIGEST_MISMATCH, "signing digest must be SHA-256")
        client = self._client
        if client is None:
            client = _default_async_client()
            self._client = client
        await _load_version_async(client, self._profile)
        digest_crc32c = _crc32c(digest)
        request: dict[str, object] = {
            "name": self._profile.key_version,
            "digest": {"sha256": digest},
            "digest_crc32c": digest_crc32c,
        }
        try:
            raw_response = await client.asymmetric_sign(
                request,
                retry=None,
                timeout=_KMS_REQUEST_TIMEOUT_SECONDS,
            )
            response = cast(_SignResponse, raw_response)
            response_name = response.name
            signature = response.signature
            signature_crc32c = response.signature_crc32c
            verified_digest_crc32c = response.verified_digest_crc32c
        except asyncio.CancelledError:
            raise
        except SigningError:
            raise
        except Exception:
            raise _error(SigningErrorCode.PROVIDER_FAILURE, "KMS signing failed") from None

        if type(response_name) is not str or response_name != self._profile.key_version:
            raise _error(
                SigningErrorCode.KEY_VERSION_MISMATCH, "KMS signed with another key version"
            )
        if verified_digest_crc32c is not True:
            raise _error(SigningErrorCode.CRC_MISMATCH, "KMS did not verify the digest CRC32C")
        if type(signature) is not bytes or not signature or len(signature) > 256:
            raise _error(SigningErrorCode.SIGNATURE_INVALID, "KMS signature is invalid")
        if type(signature_crc32c) is not int or signature_crc32c != _crc32c(signature):
            raise _error(SigningErrorCode.CRC_MISMATCH, "KMS signature CRC32C is invalid")
        return signature


class GoogleKmsEvidenceSignatureVerifier:
    """Verify evidence against one live, exact, coordinator-readable KMS version."""

    def __init__(
        self,
        *,
        project_id: str,
        service_role: ServiceRole,
        key_version: str,
        client: object | None = None,
    ) -> None:
        if service_role is not ServiceRole.COORDINATOR:
            raise _error(
                SigningErrorCode.PROFILE_INVALID,
                "evidence verification role is invalid",
            )
        try:
            profile = SigningProfile.evidence(project_id, key_version)
        except SigningError:
            raise
        except Exception:
            raise _error(
                SigningErrorCode.PROFILE_INVALID,
                "evidence verification profile is invalid",
            ) from None
        self._profile = profile
        self._client = None if client is None else cast(_AsyncKmsClient, client)

    @property
    def project_id(self) -> str:
        return self._profile.project_id

    @property
    def key_version(self) -> str:
        return self._profile.key_version

    async def verify(self, signed: SignedEvidenceEventV1) -> None:
        """Load exact public material once and verify the canonical event signature."""

        if (
            type(signed) is not SignedEvidenceEventV1
            or signed.signing_key_version != self._profile.key_version
            or signed.event.target.project_id != self._profile.project_id
        ):
            raise _error(
                SigningErrorCode.KEY_VERSION_UNTRUSTED,
                "evidence signature key version is not trusted",
            )
        client = self._client
        if client is None:
            client = _default_async_client()
            self._client = client
        await _load_version_async(client, self._profile)
        try:
            raw_response = await client.get_public_key(
                {"name": self._profile.key_version},
                retry=None,
                timeout=_KMS_REQUEST_TIMEOUT_SECONDS,
            )
            response = cast(_PublicKeyResponse, raw_response)
            response_name = response.name
            algorithm_name = _enum_name(response.algorithm)
            public_key_pem = response.pem
            public_key_crc32c = response.pem_crc32c
        except asyncio.CancelledError:
            raise
        except SigningError:
            raise
        except Exception:
            raise _error(
                SigningErrorCode.PROVIDER_FAILURE,
                "KMS public key lookup failed",
            ) from None
        if type(response_name) is not str or response_name != self._profile.key_version:
            raise _error(
                SigningErrorCode.KEY_VERSION_MISMATCH,
                "KMS returned another public key version",
            )
        if algorithm_name != SIGNING_ALGORITHM or algorithm_name != self._profile.algorithm:
            raise _error(
                SigningErrorCode.ALGORITHM_MISMATCH,
                "KMS public key algorithm is invalid",
            )
        if type(public_key_pem) is not str:
            raise _error(SigningErrorCode.PUBLIC_KEY_INVALID, "KMS public key PEM is invalid")
        try:
            public_key_bytes = public_key_pem.encode("ascii")
        except UnicodeEncodeError:
            raise _error(
                SigningErrorCode.PUBLIC_KEY_INVALID,
                "KMS public key PEM is invalid",
            ) from None
        if (
            type(public_key_crc32c) is not int
            or public_key_crc32c != _crc32c(public_key_bytes)
        ):
            raise _error(SigningErrorCode.CRC_MISMATCH, "KMS public key CRC32C is invalid")
        bundle = TrustBundle(
            entries=(
                make_trust_bundle_entry(
                    profile=self._profile,
                    state=SigningKeyState.ENABLED,
                    public_key_pem=public_key_pem,
                ),
            )
        )
        detached = DetachedSignature(
            schema_version=DETACHED_SIGNATURE_V1,
            purpose=SigningPurpose.EVIDENCE,
            key_version=signed.signing_key_version,
            algorithm=signed.signing_algorithm,
            payload_version=signed.event.schema_version,
            payload_sha256=signed.payload_sha256,
            digest_sha256=signed.signing_input_sha256,
            signature=signed.signature,
        )
        TrustBundleVerifier(
            VerificationProfile.evidence(
                self._profile.project_id,
                self._profile.key_resource,
            ),
            bundle,
        ).verify(signed.event, detached)


class GoogleKmsCapabilityTrustLoader:
    """Load one enabled capability key version for an execution service."""

    def __init__(
        self,
        *,
        project_id: str,
        service_role: ServiceRole,
        key_version: str,
        client: object | None = None,
    ) -> None:
        if type(service_role) is not ServiceRole or service_role not in {
            ServiceRole.EXECUTOR,
            ServiceRole.RECOVERY,
        }:
            raise _error(
                SigningErrorCode.PROFILE_INVALID,
                "capability trust role is invalid",
            )
        try:
            profile = SigningProfile.capability(project_id, key_version)
        except SigningError:
            raise
        except Exception:
            raise _error(
                SigningErrorCode.PROFILE_INVALID,
                "capability trust profile is invalid",
            ) from None
        self._profile = profile
        self._service_role = service_role
        self._client = None if client is None else cast(_KmsClient, client)

    @property
    def project_id(self) -> str:
        return self._profile.project_id

    @property
    def service_role(self) -> ServiceRole:
        return self._service_role

    @property
    def key_version(self) -> str:
        return self._profile.key_version

    @property
    def key_resource(self) -> str:
        return self._profile.key_resource

    def load(self) -> TrustBundleVerifier:
        """Load exact enabled public material and return capability-only trust."""

        client = self._client
        if client is None:
            client = _default_client()
            self._client = client
        state = _load_version(client, self._profile, permit_disabled=False)
        public_key_pem = _load_public_key(client, self._profile)
        bundle = TrustBundle(
            entries=(
                make_trust_bundle_entry(
                    profile=self._profile,
                    state=state,
                    public_key_pem=public_key_pem,
                ),
            )
        )
        return TrustBundleVerifier(
            VerificationProfile.capability(
                self._profile.project_id,
                self._profile.key_resource,
            ),
            bundle,
        )


class GoogleKmsTrustBundlePublisher:
    """Publish both fixed-purpose trust sets through the API service role."""

    def __init__(
        self,
        *,
        project_id: str,
        role: str,
        client: object | None = None,
    ) -> None:
        if type(project_id) is not str or _PROJECT_ID.fullmatch(project_id) is None:
            raise _error(SigningErrorCode.PROFILE_INVALID, "KMS publication project is invalid")
        if type(role) is not str or role != _TRUST_BUNDLE_PUBLISHER_ROLE:
            raise _error(SigningErrorCode.PROFILE_INVALID, "KMS publication role is invalid")
        self._project_id = project_id
        self._client = None if client is None else cast(_KmsClient, client)

    def publish(self, profiles: Sequence[SigningProfile]) -> TrustBundle:
        selected_profiles = self._validate_profiles(profiles)
        client = self._client
        if client is None:
            client = _default_client()
            self._client = client

        entries = []
        for profile in selected_profiles:
            state = _load_version(client, profile, permit_disabled=True)
            public_key_pem = _load_public_key(client, profile)
            entries.append(
                make_trust_bundle_entry(
                    profile=profile,
                    state=state,
                    public_key_pem=public_key_pem,
                )
            )
        return TrustBundle(entries=tuple(entries))

    def _validate_profiles(
        self,
        profiles: Sequence[SigningProfile],
    ) -> tuple[SigningProfile, ...]:
        try:
            selected_profiles = tuple(profiles)
        except Exception:
            raise _error(
                SigningErrorCode.TRUST_BUNDLE_INVALID,
                "KMS publication profile set is invalid",
            ) from None
        if not 2 <= len(selected_profiles) <= _MAX_TRUST_BUNDLE_PROFILES:
            raise _error(
                SigningErrorCode.TRUST_BUNDLE_INVALID,
                "KMS publication profile set is invalid",
            )

        purposes: set[SigningPurpose] = set()
        key_versions: set[str] = set()
        for profile in selected_profiles:
            if type(profile) is not SigningProfile or profile.project_id != self._project_id:
                raise _error(SigningErrorCode.PROFILE_INVALID, "KMS profile is invalid")
            if profile.key_version in key_versions:
                raise _error(
                    SigningErrorCode.TRUST_BUNDLE_INVALID,
                    "KMS publication contains a duplicate key version",
                )
            key_versions.add(profile.key_version)
            purposes.add(profile.purpose)

        if purposes != _TRUST_BUNDLE_PURPOSES:
            raise _error(
                SigningErrorCode.TRUST_BUNDLE_INVALID,
                "KMS publication requires both fixed signing purposes",
            )
        return selected_profiles


__all__ = [
    "GoogleKmsAsyncDigestSigner",
    "GoogleKmsCapabilityTrustLoader",
    "GoogleKmsDigestSigner",
    "GoogleKmsEvidenceSignatureVerifier",
    "GoogleKmsTrustBundlePublisher",
]
