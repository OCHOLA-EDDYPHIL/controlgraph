"""Verifier-authenticated, classification-only evidence signing boundary."""

from __future__ import annotations

import asyncio
import re
from typing import Literal, cast

from controlgraph_canary.application.identity import (
    CLASSIFICATION_EVIDENCE_PATH,
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.application.service_claim_classification import (
    ServiceClaimClassificationError,
    ServiceClaimClassificationErrorCode,
)
from controlgraph_canary.application.signing import (
    DETACHED_SIGNATURE_V1,
    SIGNING_ALGORITHM,
    AsyncPurposeSealedSigner,
    DetachedSignature,
    SigningError,
    SigningPurpose,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.recovery_abandonment import (
    RecoveryAbandonmentClassificationSigningRequestV1,
)
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    SignedEvidenceEventV1,
)
from controlgraph_canary.contracts.service_claim_release import (
    ServiceClaimClassificationSigningRequestV1,
)

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")


class ClassificationEvidenceSigningService:
    """Sign only an exact verifier-derived classification contract."""

    def __init__(
        self,
        *,
        project_id: str,
        authentication_policy: RouteAuthenticationPolicy,
        signer: AsyncPurposeSealedSigner,
    ) -> None:
        if (
            type(project_id) is not str
            or _PROJECT_ID.fullmatch(project_id) is None
            or "reconcile" in project_id
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != project_id
            or authentication_policy.service_role is not ServiceRole.EVIDENCE_WRITER
            or authentication_policy.path != CLASSIFICATION_EVIDENCE_PATH
            or authentication_policy.caller.role is not CallerRole.VERIFIER
            or type(signer) is not AsyncPurposeSealedSigner
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.CONFIGURATION_INVALID
            )
        profile = signer.profile
        if (
            profile.purpose is not SigningPurpose.EVIDENCE
            or profile.project_id != project_id
            or profile.algorithm != SIGNING_ALGORITHM
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.CONFIGURATION_INVALID
            )
        self._project_id = project_id
        self._authentication_policy = authentication_policy
        self._signer = signer

    async def sign(
        self,
        request: (
            ServiceClaimClassificationSigningRequestV1
            | RecoveryAbandonmentClassificationSigningRequestV1
        ),
        caller: AuthenticationContext,
    ) -> SignedEvidenceEventV1:
        """Sign only when authenticated verifier identity and event actor coincide."""

        expected = self._authentication_policy.caller
        expected_email = f"controlgraph-verifier@{self._project_id}.iam.gserviceaccount.com"
        if (
            type(request)
            not in (
                ServiceClaimClassificationSigningRequestV1,
                RecoveryAbandonmentClassificationSigningRequestV1,
            )
            or request.event.target.project_id != self._project_id
            or type(caller) is not AuthenticationContext
            or caller.role is not CallerRole.VERIFIER
            or caller.role is not expected.role
            or caller.email != expected_email
            or caller.email != expected.email
            or caller.email != request.event.actor
            or caller.subject != expected.subject
            or caller.issuer not in {"accounts.google.com", "https://accounts.google.com"}
            or caller.audience != self._authentication_policy.audience
        ):
            raise ServiceClaimClassificationError(ServiceClaimClassificationErrorCode.CALLER_DENIED)
        try:
            detached = await self._signer.sign(request.event)
        except asyncio.CancelledError:
            raise
        except (SigningError, Exception):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            ) from None
        if (
            type(detached) is not DetachedSignature
            or detached.schema_version != DETACHED_SIGNATURE_V1
            or detached.purpose is not SigningPurpose.EVIDENCE
            or detached.key_version != self._signer.profile.key_version
            or detached.algorithm != SIGNING_ALGORITHM
            or detached.payload_version != request.event.schema_version
        ):
            raise ServiceClaimClassificationError(ServiceClaimClassificationErrorCode.UNAVAILABLE)
        try:
            return SignedEvidenceEventV1(
                schema_version=SIGNED_EVIDENCE_EVENT_V1,
                event=request.event,
                purpose=cast(Literal["EVIDENCE"], detached.purpose.value),
                signing_key_version=detached.key_version,
                signing_algorithm=cast(
                    Literal["EC_SIGN_P256_SHA256"],
                    detached.algorithm,
                ),
                payload_sha256=detached.payload_sha256,
                signing_input_sha256=detached.digest_sha256,
                signature=detached.signature,
            )
        except (TypeError, ValueError):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            ) from None


class VerifierClassificationEvidenceClient:
    """Use verifier workload identity on the classification-only writer route."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        evidence_key_version: str,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.VERIFIER
            or route.service_role is not ServiceRole.EVIDENCE_WRITER
            or route.path != CLASSIFICATION_EVIDENCE_PATH
            or type(evidence_key_version) is not str
            or not evidence_key_version
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.CONFIGURATION_INVALID
            )
        self._route = route
        self._evidence_key_version = evidence_key_version
        self._transport = transport

    async def sign(
        self,
        request: (
            ServiceClaimClassificationSigningRequestV1
            | RecoveryAbandonmentClassificationSigningRequestV1
        ),
    ) -> SignedEvidenceEventV1:
        """Return only the exact signed event requested by the verifier."""

        if (
            type(request)
            not in (
                ServiceClaimClassificationSigningRequestV1,
                RecoveryAbandonmentClassificationSigningRequestV1,
            )
            or request.event.target.project_id != self._route.project_id
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.REQUEST_DENIED
            )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.TRANSPORT_UNAVAILABLE
            ) from None
        try:
            signed = decode_contract(body, SignedEvidenceEventV1)
        except ContractError:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.RESPONSE_INVALID
            ) from None
        except Exception:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.RESPONSE_INVALID
            ) from None
        if (
            signed.event != request.event
            or signed.signing_key_version != self._evidence_key_version
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.RESPONSE_INVALID
            )
        return signed


__all__ = [
    "ClassificationEvidenceSigningService",
    "VerifierClassificationEvidenceClient",
]
