"""Purpose-sealed evidence signing behind one exact target boundary."""

from __future__ import annotations

import asyncio
import re
from enum import StrEnum
from typing import Literal, cast

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.signing import (
    DETACHED_SIGNATURE_V1,
    SIGNING_ALGORITHM,
    AsyncPurposeSealedSigner,
    DetachedSignature,
    SigningError,
    SigningPurpose,
)
from controlgraph_canary.contracts.models import EvidenceEvent, TargetBinding
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    SignedEvidenceEventV1,
)

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_REFERENCE_SERVICE = "controlgraph-reference-target"


class EvidenceSigningErrorCode(StrEnum):
    """Stable payload-free evidence-writer failure classes."""

    CONFIGURATION_INVALID = "EVIDENCE_SIGNING_CONFIGURATION_INVALID"
    CALLER_DENIED = "EVIDENCE_SIGNING_CALLER_DENIED"
    TARGET_DENIED = "EVIDENCE_SIGNING_TARGET_DENIED"
    ACTOR_DENIED = "EVIDENCE_SIGNING_ACTOR_DENIED"
    UNAVAILABLE = "EVIDENCE_SIGNING_UNAVAILABLE"


class EvidenceSigningError(Exception):
    """A sanitized evidence-writer failure."""

    def __init__(self, code: EvidenceSigningErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class EvidenceSigningService:
    """Sign only canonical events for the configured reference target."""

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
        ):
            raise EvidenceSigningError(EvidenceSigningErrorCode.CONFIGURATION_INVALID)
        if type(signer) is not AsyncPurposeSealedSigner:
            raise EvidenceSigningError(EvidenceSigningErrorCode.CONFIGURATION_INVALID)
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != project_id
            or authentication_policy.service_role is not ServiceRole.EVIDENCE_WRITER
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
        ):
            raise EvidenceSigningError(EvidenceSigningErrorCode.CONFIGURATION_INVALID)
        profile = signer.profile
        if (
            profile.purpose is not SigningPurpose.EVIDENCE
            or profile.project_id != project_id
            or profile.algorithm != SIGNING_ALGORITHM
        ):
            raise EvidenceSigningError(EvidenceSigningErrorCode.CONFIGURATION_INVALID)
        self._project_id = project_id
        self._authentication_policy = authentication_policy
        self._signer = signer
        self._target = TargetBinding(
            schema_version="controlgraph.target-binding/v1",
            project_id=project_id,
            region="us-central1",
            environment="nonprod",
            service_name=_REFERENCE_SERVICE,
        )

    @property
    def target(self) -> TargetBinding:
        """Return the sole target whose events may be signed."""

        return self._target

    async def sign(
        self,
        event: EvidenceEvent,
        caller: AuthenticationContext,
    ) -> SignedEvidenceEventV1:
        """Return the strict signed-event contract for one exact canonical event."""

        expected_email = (
            f"controlgraph-coordinator@{self._project_id}.iam.gserviceaccount.com"
        )
        expected_caller = self._authentication_policy.caller
        if (
            type(caller) is not AuthenticationContext
            or caller.role is not CallerRole.COORDINATOR
            or type(caller.email) is not str
            or type(caller.subject) is not str
            or type(caller.issuer) is not str
            or type(caller.audience) is not str
            or caller.email != expected_email
            or caller.email != expected_caller.email
            or caller.subject != expected_caller.subject
            or caller.issuer not in ("accounts.google.com", "https://accounts.google.com")
            or caller.audience != self._authentication_policy.audience
        ):
            raise EvidenceSigningError(EvidenceSigningErrorCode.CALLER_DENIED)
        if type(event) is not EvidenceEvent or event.target != self._target:
            raise EvidenceSigningError(EvidenceSigningErrorCode.TARGET_DENIED)
        if event.actor.endswith(".iam.gserviceaccount.com"):
            raise EvidenceSigningError(EvidenceSigningErrorCode.ACTOR_DENIED)
        try:
            detached = await self._signer.sign(event)
        except asyncio.CancelledError:
            raise
        except SigningError:
            raise EvidenceSigningError(EvidenceSigningErrorCode.UNAVAILABLE) from None
        except Exception:
            raise EvidenceSigningError(EvidenceSigningErrorCode.UNAVAILABLE) from None

        if (
            type(detached) is not DetachedSignature
            or detached.schema_version != DETACHED_SIGNATURE_V1
            or detached.purpose is not SigningPurpose.EVIDENCE
            or detached.key_version != self._signer.profile.key_version
            or detached.algorithm != SIGNING_ALGORITHM
            or detached.payload_version != event.schema_version
        ):
            raise EvidenceSigningError(EvidenceSigningErrorCode.UNAVAILABLE)
        try:
            return SignedEvidenceEventV1(
                schema_version=SIGNED_EVIDENCE_EVENT_V1,
                event=event,
                purpose=cast(Literal["EVIDENCE"], detached.purpose.value),
                signing_key_version=detached.key_version,
                signing_algorithm=cast(Literal["EC_SIGN_P256_SHA256"], detached.algorithm),
                payload_sha256=detached.payload_sha256,
                signing_input_sha256=detached.digest_sha256,
                signature=detached.signature,
            )
        except (TypeError, ValueError):
            raise EvidenceSigningError(EvidenceSigningErrorCode.UNAVAILABLE) from None


__all__ = [
    "EvidenceSigningError",
    "EvidenceSigningErrorCode",
    "EvidenceSigningService",
]
