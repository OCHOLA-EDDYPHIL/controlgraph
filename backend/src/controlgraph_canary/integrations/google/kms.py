"""Cloud KMS adapters for fixed-profile digest signing and public trust material."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from typing import Protocol, cast

from controlgraph_canary.application.signing import (
    SIGNING_ALGORITHM,
    SigningError,
    SigningErrorCode,
    SigningKeyState,
    SigningProfile,
    SigningPurpose,
    TrustBundle,
    make_trust_bundle_entry,
)

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
        self._client = _default_client() if client is None else cast(_KmsClient, client)

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    def sign_digest(self, digest: bytes) -> bytes:
        if type(digest) is not bytes or len(digest) != 32:
            raise _error(SigningErrorCode.DIGEST_MISMATCH, "signing digest must be SHA-256")
        _load_version(self._client, self._profile, permit_disabled=False)
        digest_crc32c = _crc32c(digest)
        request: dict[str, object] = {
            "name": self._profile.key_version,
            "digest": {"sha256": digest},
            "digest_crc32c": digest_crc32c,
        }
        try:
            raw_response = self._client.asymmetric_sign(request)
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
                    SigningErrorCode.ALGORITHM_MISMATCH, "KMS public key algorithm is invalid"
                )
            if type(public_key_pem) is not str:
                raise _error(SigningErrorCode.PUBLIC_KEY_INVALID, "KMS public key PEM is invalid")
            try:
                pem_bytes = public_key_pem.encode("ascii")
            except UnicodeEncodeError:
                raise _error(
                    SigningErrorCode.PUBLIC_KEY_INVALID, "KMS public key PEM is invalid"
                ) from None
            if type(public_key_crc32c) is not int or public_key_crc32c != _crc32c(pem_bytes):
                raise _error(SigningErrorCode.CRC_MISMATCH, "KMS public key CRC32C is invalid")
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
    "GoogleKmsDigestSigner",
    "GoogleKmsTrustBundlePublisher",
]
