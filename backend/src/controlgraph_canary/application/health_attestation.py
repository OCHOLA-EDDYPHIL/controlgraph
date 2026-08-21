"""Role-sealed health-proof signing and one-shot verifier client."""

from __future__ import annotations

import asyncio
import re
from enum import StrEnum

from controlgraph_canary.application.health_orchestration import (
    HealthAttestationVerifier,
    validate_health_attestation_signing_request_decisions,
)
from controlgraph_canary.application.identity import (
    HEALTH_ATTESTATION_PATH,
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
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
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
    encode_base64url,
)
from controlgraph_canary.contracts.health_execution import (
    HEALTH_ATTESTATION_PURPOSE,
    P256_SIGNING_ALGORITHM,
    SIGNED_HEALTH_DECISION_PROOF_V1,
    HealthAttestationSigningRequestV1,
    SignedHealthDecisionProofV1,
    health_attestation_signing_input_sha256,
)

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")


class HealthAttestationErrorCode(StrEnum):
    """Stable payload-free failures for the health signing boundary."""

    CONFIGURATION_INVALID = "HEALTH_ATTESTATION_CONFIGURATION_INVALID"
    CALLER_DENIED = "HEALTH_ATTESTATION_CALLER_DENIED"
    REQUEST_DENIED = "HEALTH_ATTESTATION_REQUEST_DENIED"
    TRANSPORT_UNAVAILABLE = "HEALTH_ATTESTATION_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "HEALTH_ATTESTATION_RESPONSE_INVALID"
    UNAVAILABLE = "HEALTH_ATTESTATION_UNAVAILABLE"


class HealthAttestationError(RuntimeError):
    """One sanitized health-attestation failure."""

    def __init__(self, code: HealthAttestationErrorCode) -> None:
        if type(code) is not HealthAttestationErrorCode:
            raise TypeError("an exact health attestation error code is required")
        self.code = code
        super().__init__(code.value)


class HealthAttestationSigningService:
    """Re-evaluate and sign one exact verifier-owned health proof."""

    def __init__(
        self,
        *,
        project_id: str,
        authentication_policy: RouteAuthenticationPolicy,
        signer: AsyncDigestSigningBackend,
        signature_verifier: HealthAttestationVerifier,
    ) -> None:
        profile = getattr(signer, "profile", None)
        if (
            type(project_id) is not str
            or _PROJECT_ID.fullmatch(project_id) is None
            or "reconcile" in project_id
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != project_id
            or authentication_policy.service_role is not ServiceRole.EVIDENCE_WRITER
            or authentication_policy.path != HEALTH_ATTESTATION_PATH
            or authentication_policy.caller.role is not CallerRole.VERIFIER
            or type(profile) is not SigningProfile
            or profile.project_id != project_id
            or profile.purpose is not SigningPurpose.EVIDENCE
            or profile.algorithm != SIGNING_ALGORITHM
            or not callable(getattr(signer, "sign_digest", None))
            or not isinstance(signature_verifier, HealthAttestationVerifier)
            or getattr(signature_verifier, "project_id", None) != project_id
            or getattr(signature_verifier, "key_version", None)
            != profile.key_version
        ):
            raise HealthAttestationError(
                HealthAttestationErrorCode.CONFIGURATION_INVALID
            )
        self._project_id = project_id
        self._authentication_policy = authentication_policy
        self._signer = signer
        self._profile = profile
        self._signature_verifier = signature_verifier

    @property
    def signing_key_version(self) -> str:
        """Return the sole evidence key version this service may use."""

        return self._profile.key_version

    async def attest(
        self,
        request: HealthAttestationSigningRequestV1,
        caller: AuthenticationContext,
    ) -> SignedHealthDecisionProofV1:
        """Replay the complete request and sign only its canonical pending proof."""

        expected_caller = self._authentication_policy.caller
        if (
            type(caller) is not AuthenticationContext
            or caller.role is not CallerRole.VERIFIER
            or caller.role is not expected_caller.role
            or caller.email != expected_caller.email
            or caller.subject != expected_caller.subject
            or caller.issuer not in {"accounts.google.com", "https://accounts.google.com"}
            or caller.audience != self._authentication_policy.audience
        ):
            raise HealthAttestationError(HealthAttestationErrorCode.CALLER_DENIED)
        if type(request) is not HealthAttestationSigningRequestV1:
            raise HealthAttestationError(HealthAttestationErrorCode.REQUEST_DENIED)
        try:
            validated = HealthAttestationSigningRequestV1.model_validate(request)
            predecessor = validated.prior_signed_proof
            if predecessor is not None:
                await self._signature_verifier.verify(predecessor)
            validate_health_attestation_signing_request_decisions(validated)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthAttestationError(
                HealthAttestationErrorCode.REQUEST_DENIED
            ) from None
        proof = validated.pending_proof
        anchor = validated.anchor
        if (
            anchor.target.project_id != self._project_id
            or anchor.evidence_signing_key_version != self._profile.key_version
            or proof.verifier_identity != caller.email
        ):
            raise HealthAttestationError(HealthAttestationErrorCode.REQUEST_DENIED)
        signing_input_sha256 = health_attestation_signing_input_sha256(
            proof,
            self._profile.key_version,
        )
        try:
            signature = await self._signer.sign_digest(
                bytes.fromhex(signing_input_sha256)
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthAttestationError(HealthAttestationErrorCode.UNAVAILABLE) from None
        if not _is_canonical_p256_der_signature(signature):
            raise HealthAttestationError(HealthAttestationErrorCode.UNAVAILABLE)
        try:
            return SignedHealthDecisionProofV1(
                schema_version=SIGNED_HEALTH_DECISION_PROOF_V1,
                proof=proof,
                purpose=HEALTH_ATTESTATION_PURPOSE,
                signing_key_version=self._profile.key_version,
                signing_algorithm=P256_SIGNING_ALGORITHM,
                payload_sha256=canonical_sha256(proof),
                signing_input_sha256=signing_input_sha256,
                signature=encode_base64url(signature),
            )
        except (TypeError, ValueError):
            raise HealthAttestationError(HealthAttestationErrorCode.UNAVAILABLE) from None


class VerifierHealthAttestationClient:
    """Call the fixed evidence-writer health route once without retries."""

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
            raise HealthAttestationError(
                HealthAttestationErrorCode.CONFIGURATION_INVALID
            ) from None
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.VERIFIER
            or route.service_role is not ServiceRole.EVIDENCE_WRITER
            or route.path != HEALTH_ATTESTATION_PATH
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise HealthAttestationError(
                HealthAttestationErrorCode.CONFIGURATION_INVALID
            )
        self._route = route
        self._transport = transport
        self._signing_key_version = profile.key_version

    @property
    def purpose(self) -> str:
        """Return the fixed health-only signing purpose."""

        return HEALTH_ATTESTATION_PURPOSE

    @property
    def signing_key_version(self) -> str:
        """Return the exact root-configured evidence key version."""

        return self._signing_key_version

    async def attest(
        self,
        request: HealthAttestationSigningRequestV1,
    ) -> SignedHealthDecisionProofV1:
        """Send one canonical signing request and reject substituted responses."""

        if type(request) is not HealthAttestationSigningRequestV1:
            raise HealthAttestationError(HealthAttestationErrorCode.REQUEST_DENIED)
        key_version = self.signing_key_version
        if request.anchor.evidence_signing_key_version != key_version:
            raise HealthAttestationError(HealthAttestationErrorCode.REQUEST_DENIED)
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthAttestationError(
                HealthAttestationErrorCode.TRANSPORT_UNAVAILABLE
            ) from None
        try:
            signed = decode_contract(body, SignedHealthDecisionProofV1)
        except (ContractError, TypeError, ValueError):
            raise HealthAttestationError(
                HealthAttestationErrorCode.RESPONSE_INVALID
            ) from None
        if (
            signed.proof != request.pending_proof
            or signed.purpose != HEALTH_ATTESTATION_PURPOSE
            or signed.signing_key_version != key_version
            or signed.signing_algorithm != P256_SIGNING_ALGORITHM
        ):
            raise HealthAttestationError(HealthAttestationErrorCode.RESPONSE_INVALID)
        return signed


def _is_canonical_p256_der_signature(value: object) -> bool:
    if type(value) is not bytes or not value or len(value) > 72:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric import utils

        r, s = utils.decode_dss_signature(value)
        return r > 0 and s > 0 and utils.encode_dss_signature(r, s) == value
    except (TypeError, ValueError):
        return False


__all__ = [
    "HealthAttestationError",
    "HealthAttestationErrorCode",
    "HealthAttestationSigningService",
    "VerifierHealthAttestationClient",
]
