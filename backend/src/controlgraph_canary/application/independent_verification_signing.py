"""Verifier-authenticated signing for independent verification evidence."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.identity import (
    INDEPENDENT_VERIFICATION_EVIDENCE_PATH,
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.independent_verification import (
    IndependentVerificationError,
    IndependentVerificationErrorCode,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.application.signing import (
    SIGNING_ALGORITHM,
    AsyncDigestSigningBackend,
    SigningProfile,
    SigningPurpose,
)
from controlgraph_canary.application.timeline_recording import (
    IndependentVerificationTimelineRecorder,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
    encode_base64url,
)
from controlgraph_canary.contracts.independent_verification import (
    INDEPENDENT_VERIFICATION_PURPOSE,
    P256_SIGNING_ALGORITHM,
    SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
    VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
    IndependentVerificationAttestationV1,
    IndependentVerificationInvocationV1,
    IndependentVerificationKind,
    IndependentVerificationSigningRequestV1,
    SignedIndependentVerificationEvidenceV1,
    VerifiedIndependentVerificationEvidenceV1,
    independent_verification_signing_input_sha256,
)

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")


@runtime_checkable
class IndependentVerificationSignatureVerifier(Protocol):
    """Read-only trust port for the fixed evidence signing key version."""

    @property
    def project_id(self) -> str: ...

    @property
    def key_version(self) -> str: ...

    async def verify(self, signed: SignedIndependentVerificationEvidenceV1) -> None: ...


class IndependentVerificationSigningService:
    """Sign only request-bound evidence from the authenticated verifier."""

    def __init__(
        self,
        *,
        project_id: str,
        authentication_policy: RouteAuthenticationPolicy,
        signer: AsyncDigestSigningBackend,
    ) -> None:
        profile = getattr(signer, "profile", None)
        if (
            type(project_id) is not str
            or _PROJECT_ID.fullmatch(project_id) is None
            or "reconcile" in project_id
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != project_id
            or authentication_policy.service_role is not ServiceRole.EVIDENCE_WRITER
            or authentication_policy.path != INDEPENDENT_VERIFICATION_EVIDENCE_PATH
            or authentication_policy.caller.role is not CallerRole.VERIFIER
            or type(profile) is not SigningProfile
            or profile.project_id != project_id
            or profile.purpose is not SigningPurpose.EVIDENCE
            or profile.algorithm != SIGNING_ALGORITHM
            or not callable(getattr(signer, "sign_digest", None))
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.CONFIGURATION_INVALID
            )
        self._project_id = project_id
        self._authentication_policy = authentication_policy
        self._signer = signer
        self._profile = profile

    @property
    def signing_key_version(self) -> str:
        """Return the sole evidence key version this service may use."""

        return self._profile.key_version

    async def sign(
        self,
        request: IndependentVerificationSigningRequestV1,
        caller: AuthenticationContext,
    ) -> SignedIndependentVerificationEvidenceV1:
        """Validate all bindings before asking KMS to sign one digest."""

        expected = self._authentication_policy.caller
        if (
            type(caller) is not AuthenticationContext
            or caller.role is not CallerRole.VERIFIER
            or caller.role is not expected.role
            or caller.email != expected.email
            or caller.subject != expected.subject
            or caller.issuer not in {"accounts.google.com", "https://accounts.google.com"}
            or caller.audience != self._authentication_policy.audience
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.CALLER_DENIED
            )
        try:
            validated = IndependentVerificationSigningRequestV1.model_validate(request)
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.REQUEST_DENIED
            ) from None
        evidence = validated.evidence
        if (
            evidence.target.project_id != self._project_id
            or evidence.verifier_identity != caller.email
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.REQUEST_DENIED
            )
        signing_input_sha256 = independent_verification_signing_input_sha256(
            evidence,
            self._profile.key_version,
        )
        try:
            signature = await self._signer.sign_digest(bytes.fromhex(signing_input_sha256))
        except asyncio.CancelledError:
            raise
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.SIGNING_UNAVAILABLE
            ) from None
        if not _is_canonical_p256_der_signature(signature):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.SIGNING_UNAVAILABLE
            )
        try:
            return SignedIndependentVerificationEvidenceV1(
                schema_version=SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
                evidence=evidence,
                purpose=INDEPENDENT_VERIFICATION_PURPOSE,
                signing_key_version=self._profile.key_version,
                signing_algorithm=P256_SIGNING_ALGORITHM,
                payload_sha256=canonical_sha256(evidence),
                signing_input_sha256=signing_input_sha256,
                signature=encode_base64url(signature),
            )
        except (TypeError, ValueError):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.SIGNING_UNAVAILABLE
            ) from None


class VerifierIndependentVerificationEvidenceClient:
    """Call the fixed verifier-only evidence route once without retries."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
        signing_key_version: str,
    ) -> None:
        try:
            profile = SigningProfile.evidence(route.project_id, signing_key_version)
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.CONFIGURATION_INVALID
            ) from None
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.VERIFIER
            or route.service_role is not ServiceRole.EVIDENCE_WRITER
            or route.path != INDEPENDENT_VERIFICATION_EVIDENCE_PATH
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.CONFIGURATION_INVALID
            )
        self._route = route
        self._transport = transport
        self._signing_key_version = profile.key_version

    async def sign(
        self,
        request: IndependentVerificationSigningRequestV1,
    ) -> SignedIndependentVerificationEvidenceV1:
        """Accept only the exact evidence and configured key requested."""

        if (
            type(request) is not IndependentVerificationSigningRequestV1
            or request.evidence.target.project_id != self._route.project_id
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.REQUEST_DENIED
            )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.SIGNING_UNAVAILABLE
            ) from None
        try:
            signed = decode_contract(body, SignedIndependentVerificationEvidenceV1)
        except (ContractError, TypeError, ValueError):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.RESPONSE_INVALID
            ) from None
        if (
            signed.evidence != request.evidence
            or signed.signing_key_version != self._signing_key_version
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.RESPONSE_INVALID
            )
        return signed


class CoordinatorIndependentVerificationClient:
    """Request one verifier operation and return only signature-verified evidence."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
        signature_verifier: IndependentVerificationSignatureVerifier,
        clock: Callable[[], datetime] | None = None,
        timeline_recorder: IndependentVerificationTimelineRecorder | None = None,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.VERIFIER
            or route.path != "/v1/internal/verify"
            or not isinstance(transport, CanonicalInternalTransport)
            or not isinstance(
                signature_verifier,
                IndependentVerificationSignatureVerifier,
            )
            or signature_verifier.project_id != route.project_id
            or (clock is not None and not callable(clock))
            or (
                timeline_recorder is not None
                and (
                    not isinstance(
                        timeline_recorder,
                        IndependentVerificationTimelineRecorder,
                    )
                    or timeline_recorder.target.project_id != route.project_id
                )
            )
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.CONFIGURATION_INVALID
            )
        self._route = route
        self._transport = transport
        self._signature_verifier = signature_verifier
        self._clock = clock or _system_utc_second
        self._timeline_recorder = timeline_recorder

    async def attest(
        self,
        invocation: IndependentVerificationInvocationV1,
    ) -> VerifiedIndependentVerificationEvidenceV1:
        """Reject response substitution before exposing evidence to classification."""

        if (
            type(invocation) is not IndependentVerificationInvocationV1
            or invocation.verification.target.project_id != self._route.project_id
            or (
                self._timeline_recorder is not None
                and self._timeline_recorder.target != invocation.verification.target
            )
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.REQUEST_DENIED
            )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.UNAVAILABLE
            ) from None
        try:
            attestation = decode_contract(body, IndependentVerificationAttestationV1)
        except (ContractError, TypeError, ValueError):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.RESPONSE_INVALID
            ) from None
        signing_request = attestation.signing_request
        if invocation.kind is IndependentVerificationKind.CONFIGURATION:
            configuration = signing_request.configuration
            verification = configuration.request if configuration is not None else None
        else:
            probe = signing_request.probe
            verification = probe.request.verification if probe is not None else None
        if (
            verification != invocation.verification
            or attestation.signed_evidence.signing_key_version
            != self._signature_verifier.key_version
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.RESPONSE_INVALID
            )
        try:
            await self._signature_verifier.verify(attestation.signed_evidence)
            verified_at = _timestamp(self._clock())
            verified = VerifiedIndependentVerificationEvidenceV1(
                schema_version=VERIFIED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
                signing_request=signing_request,
                signed_evidence=attestation.signed_evidence,
                verified_at=verified_at,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.RESPONSE_INVALID
            ) from None
        recorder = self._timeline_recorder
        if recorder is not None:
            try:
                await recorder.record_independent_verification(verified)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise IndependentVerificationError(
                    IndependentVerificationErrorCode.UNAVAILABLE
                ) from None
        return verified


def _is_canonical_p256_der_signature(value: object) -> bool:
    if type(value) is not bytes or not value or len(value) > 72:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric import utils

        r, s = utils.decode_dss_signature(value)
        return r > 0 and s > 0 and utils.encode_dss_signature(r, s) == value
    except (TypeError, ValueError):
        return False


def _timestamp(value: datetime) -> str:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ValueError("verification clock is invalid")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "CoordinatorIndependentVerificationClient",
    "IndependentVerificationSignatureVerifier",
    "IndependentVerificationSigningService",
    "VerifierIndependentVerificationEvidenceClient",
]
