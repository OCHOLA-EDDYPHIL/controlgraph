"""Authenticated verifier classification for a fenced service claim."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.cloud_run import (
    CloudRunReadyState,
    CloudRunServiceState,
    TargetConfigurationProjection,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
    ExactEvidenceSignatureVerifier,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import (
    EVIDENCE_EVENT_V1,
    EvidenceEvent,
    EvidenceKind,
    TargetBinding,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1
from controlgraph_canary.contracts.service_claim_release import (
    SERVICE_CLAIM_CLASSIFICATION_ATTESTATION_V1,
    SERVICE_CLAIM_CLASSIFICATION_RESULT_V1,
    SERVICE_CLAIM_CLASSIFICATION_SIGNING_REQUEST_V1,
    SERVICE_CLAIM_TARGET_CLASSIFICATION_EVIDENCE_SUBJECT_V1,
    ServiceClaimClassificationAttestationV1,
    ServiceClaimClassificationRequestV1,
    ServiceClaimClassificationResultV1,
    ServiceClaimClassificationSigningRequestV1,
    ServiceClaimTargetClassificationEvidenceSubjectV1,
    service_claim_classification_request_sha256,
)
from controlgraph_canary.contracts.storage import ServiceClaimTargetClassification


class ServiceClaimClassificationErrorCode(StrEnum):
    """Stable payload-free classification failure classes."""

    CONFIGURATION_INVALID = "SERVICE_CLAIM_CLASSIFICATION_CONFIGURATION_INVALID"
    CALLER_DENIED = "SERVICE_CLAIM_CLASSIFICATION_CALLER_DENIED"
    REQUEST_DENIED = "SERVICE_CLAIM_CLASSIFICATION_REQUEST_DENIED"
    TARGET_MISMATCH = "SERVICE_CLAIM_CLASSIFICATION_TARGET_MISMATCH"
    TRANSPORT_UNAVAILABLE = "SERVICE_CLAIM_CLASSIFICATION_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "SERVICE_CLAIM_CLASSIFICATION_RESPONSE_INVALID"
    UNAVAILABLE = "SERVICE_CLAIM_CLASSIFICATION_UNAVAILABLE"


class ServiceClaimClassificationError(RuntimeError):
    """Sanitized denial without provider response or credential material."""

    def __init__(self, code: ServiceClaimClassificationErrorCode) -> None:
        if type(code) is not ServiceClaimClassificationErrorCode:
            raise TypeError("an exact classification error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class ServiceClaimClassificationReader(Protocol):
    """Verifier-owned read-only surface for one exact service."""

    @property
    def target(self) -> TargetBinding: ...

    @property
    def reader_identity(self) -> str: ...

    async def read_service(self) -> CloudRunServiceState: ...


class ServiceClaimClassificationReaderFactory(Protocol):
    """Build a fixed target reader from one coordinator-derived expectation."""

    def __call__(
        self,
        request: ServiceClaimClassificationRequestV1,
    ) -> ServiceClaimClassificationReader: ...


@runtime_checkable
class VerifierClassificationEvidenceClientPort(Protocol):
    """Classification-only signing route called with verifier identity."""

    async def sign(
        self,
        request: ServiceClaimClassificationSigningRequestV1,
    ) -> SignedEvidenceEventV1: ...


class ServiceClaimClassificationService:
    """Classify fresh provider state behind the authenticated verifier route."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        reader_factory: ServiceClaimClassificationReaderFactory,
        evidence_client: VerifierClassificationEvidenceClientPort,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.VERIFIER
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or authentication_policy.path != protected_path(ServiceRole.VERIFIER)
            or not callable(reader_factory)
            or not isinstance(
                evidence_client,
                VerifierClassificationEvidenceClientPort,
            )
            or (clock is not None and not callable(clock))
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.CONFIGURATION_INVALID
            )
        self._authentication_policy = authentication_policy
        self._reader_factory = reader_factory
        self._evidence_client = evidence_client
        self._clock = clock or _system_utc_second

    async def classify(
        self,
        request: ServiceClaimClassificationRequestV1,
        caller: AuthenticationContext,
    ) -> ServiceClaimClassificationAttestationV1:
        """Return only fresh, exact facts derived by the verifier reader."""

        if (
            type(request) is not ServiceClaimClassificationRequestV1
            or request.target.project_id != self._authentication_policy.project_id
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.REQUEST_DENIED
            )
        if not self._caller_is_exact(caller):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.CALLER_DENIED
            )
        try:
            reader = self._reader_factory(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            ) from None
        if (
            not isinstance(reader, ServiceClaimClassificationReader)
            or reader.target != request.target
            or reader.reader_identity
            != f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            )
        try:
            observed = await reader.read_service()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            ) from None
        if type(observed) is not CloudRunServiceState:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            )
        expected_stable, expected_candidate = _expected_traffic(
            request.expected_classification
        )
        projection = TargetConfigurationProjection(
            target=request.target,
            stable_revision=request.stable_revision,
            candidate_revision=request.candidate_revision,
            stable_percent=expected_stable,
            candidate_percent=expected_candidate,
            concurrency=request.concurrency,
        )
        expected_digest = target_configuration_projection_sha256(projection)
        traffic = {item.revision: item.percent for item in observed.traffic}
        statuses = {item.revision: item.percent for item in observed.traffic_statuses}
        expected_traffic = {
            request.stable_revision: expected_stable,
            request.candidate_revision: expected_candidate,
        }
        if (
            observed.target != request.target
            or observed.reconciling
            or observed.ready_state is not CloudRunReadyState.READY
            or observed.generation != observed.observed_generation
            or observed.generation <= request.minimum_service_generation_exclusive
            or observed.template_revision != request.candidate_revision
            or observed.latest_created_revision != request.candidate_revision
            or observed.latest_ready_revision != request.candidate_revision
            or observed.template_concurrency != request.concurrency
            or traffic != expected_traffic
            or statuses != expected_traffic
            or expected_digest != request.expected_target_configuration_sha256
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.TARGET_MISMATCH
            )
        classified_at = self._timestamp()
        try:
            result = ServiceClaimClassificationResultV1(
                schema_version=SERVICE_CLAIM_CLASSIFICATION_RESULT_V1,
                request=request,
                request_sha256=service_claim_classification_request_sha256(request),
                classification=request.expected_classification,
                service_generation=observed.generation,
                provider_etag=observed.etag,
                target_configuration_sha256=expected_digest,
                classified_by=reader.reader_identity,
                classified_at=classified_at,
            )
        except (TypeError, ValueError):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            ) from None
        subject = ServiceClaimTargetClassificationEvidenceSubjectV1(
            schema_version=SERVICE_CLAIM_TARGET_CLASSIFICATION_EVIDENCE_SUBJECT_V1,
            target=request.target,
            root_id=request.root_id,
            root_sha256=request.root_sha256,
            request_sha256=request.release_request_sha256,
            classification_request_sha256=result.request_sha256,
            classification=result.classification,
            fenced_epoch=request.fenced_epoch,
            fenced_authority_revision=request.fenced_authority_revision,
            service_generation=result.service_generation,
            provider_etag=result.provider_etag,
            target_configuration_sha256=result.target_configuration_sha256,
            evidence_id=request.classification_evidence_id,
            classified_by=result.classified_by,
            classified_at=result.classified_at,
        )
        event = EvidenceEvent(
            schema_version=EVIDENCE_EVENT_V1,
            evidence_id=request.classification_evidence_id,
            sequence=request.previous_evidence_sequence + 1,
            root_id=request.root_id,
            root_sha256=request.root_sha256,
            target=request.target,
            epoch=request.fenced_epoch,
            kind=EvidenceKind.TARGET_VERIFIED,
            actor=result.classified_by,
            request_id=request.request_id,
            receipt_id=None,
            occurred_at=result.classified_at,
            subject_sha256=canonical_sha256(subject),
            previous_event_sha256=request.previous_event_sha256,
            reason_code=None,
            provider_operation=None,
            target_configuration_sha256=result.target_configuration_sha256,
        )
        signing_request = ServiceClaimClassificationSigningRequestV1(
            schema_version=SERVICE_CLAIM_CLASSIFICATION_SIGNING_REQUEST_V1,
            result=result,
            subject=subject,
            event=event,
        )
        try:
            signed = await self._evidence_client.sign(signing_request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            ) from None
        try:
            return ServiceClaimClassificationAttestationV1(
                schema_version=SERVICE_CLAIM_CLASSIFICATION_ATTESTATION_V1,
                signing_request=signing_request,
                signed_evidence=signed,
            )
        except (TypeError, ValueError):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            ) from None

    def _caller_is_exact(self, caller: AuthenticationContext) -> bool:
        expected = self._authentication_policy.caller
        return (
            type(caller) is AuthenticationContext
            and caller.role is CallerRole.COORDINATOR
            and caller.role is expected.role
            and caller.email == expected.email
            and caller.subject == expected.subject
            and caller.issuer in {"accounts.google.com", "https://accounts.google.com"}
            and caller.audience == self._authentication_policy.audience
        )

    def _timestamp(self) -> str:
        try:
            value = self._clock()
        except Exception:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            ) from None
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.UNAVAILABLE
            )
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class CoordinatorServiceClaimClassificationClient:
    """Call the fixed verifier and accept only a request-bound response."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
        evidence_key_version: str,
        signature_verifier: ExactEvidenceSignatureVerifier,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.VERIFIER
            or not isinstance(transport, CanonicalInternalTransport)
            or type(evidence_key_version) is not str
            or not evidence_key_version
            or not isinstance(signature_verifier, ExactEvidenceSignatureVerifier)
            or signature_verifier.project_id != route.project_id
            or signature_verifier.key_version != evidence_key_version
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.CONFIGURATION_INVALID
            )
        self._route = route
        self._transport = transport
        self._evidence_key_version = evidence_key_version
        self._signature_verifier = signature_verifier

    async def classify(
        self,
        request: ServiceClaimClassificationRequestV1,
    ) -> ServiceClaimClassificationAttestationV1:
        """Return only exact authenticated verifier facts for this request."""

        if (
            type(request) is not ServiceClaimClassificationRequestV1
            or request.target.project_id != self._route.project_id
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
            attestation = decode_contract(
                body,
                ServiceClaimClassificationAttestationV1,
            )
        except ContractError:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.RESPONSE_INVALID
            ) from None
        except Exception:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.RESPONSE_INVALID
            ) from None
        if (
            attestation.signing_request.result.request != request
            or attestation.signing_request.result.request_sha256
            != service_claim_classification_request_sha256(request)
            or attestation.signing_request.result.classified_by
            != f"controlgraph-verifier@{self._route.project_id}.iam.gserviceaccount.com"
            or attestation.signed_evidence.signing_key_version
            != self._evidence_key_version
        ):
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.RESPONSE_INVALID
            )
        try:
            await self._signature_verifier.verify(attestation.signed_evidence)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ServiceClaimClassificationError(
                ServiceClaimClassificationErrorCode.RESPONSE_INVALID
            ) from None
        return attestation


def _expected_traffic(
    classification: ServiceClaimTargetClassification,
) -> tuple[int, int]:
    if classification is ServiceClaimTargetClassification.CANDIDATE_PROMOTED:
        return 0, 100
    if classification is ServiceClaimTargetClassification.STABLE_RESTORED:
        return 100, 0
    raise TypeError("an exact target classification is required")


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "CoordinatorServiceClaimClassificationClient",
    "ServiceClaimClassificationError",
    "ServiceClaimClassificationErrorCode",
    "ServiceClaimClassificationReader",
    "ServiceClaimClassificationReaderFactory",
    "ServiceClaimClassificationService",
    "VerifierClassificationEvidenceClientPort",
]
