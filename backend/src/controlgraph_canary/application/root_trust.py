"""Trusted verifier preflight and coordinator internal-client boundaries."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from controlgraph_canary.application.candidate_revision import (
    CandidateRevisionAttestation,
    CandidateRevisionReader,
    CandidateRevisionValidationConfiguration,
    CandidateRevisionValidator,
    CandidateValidationError,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
    runtime_service_name,
)
from controlgraph_canary.application.stable_snapshot import (
    StableCaptureError,
    StableSnapshotCaptureConfiguration,
    StableSnapshotCapturer,
    StableSnapshotReader,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.models import EvidenceEvent, StableSnapshot, TargetBinding
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1
from controlgraph_canary.contracts.root_trust import (
    ROOT_CANDIDATE_ATTESTATION_V1,
    ROOT_PREFLIGHT_RESULT_V1,
    RootCandidateAttestationV1,
    RootPreflightRequestV1,
    RootPreflightResultV1,
    root_preflight_request_sha256,
    stable_snapshots_match,
)

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_PROJECT_NUMBER = re.compile(r"^[1-9][0-9]{5,31}$")
_REFERENCE_SERVICE = "controlgraph-reference-target"


class RootPreflightErrorCode(StrEnum):
    """Stable payload-free verifier preflight failures."""

    CONFIGURATION_INVALID = "ROOT_PREFLIGHT_CONFIGURATION_INVALID"
    CALLER_DENIED = "ROOT_PREFLIGHT_CALLER_DENIED"
    REQUEST_DENIED = "ROOT_PREFLIGHT_REQUEST_DENIED"
    STABLE_UNAVAILABLE = "ROOT_PREFLIGHT_STABLE_UNAVAILABLE"
    STABLE_MISMATCH = "ROOT_PREFLIGHT_STABLE_MISMATCH"
    CANDIDATE_DENIED = "ROOT_PREFLIGHT_CANDIDATE_DENIED"
    UNAVAILABLE = "ROOT_PREFLIGHT_UNAVAILABLE"


class RootPreflightError(RuntimeError):
    """Sanitized verifier preflight denial."""

    def __init__(self, code: RootPreflightErrorCode) -> None:
        if type(code) is not RootPreflightErrorCode:
            raise TypeError("an exact root preflight error code is required")
        self.code = code
        super().__init__(code.value)


class RootTrustClientErrorCode(StrEnum):
    """Stable coordinator-side internal trust failures."""

    CONFIGURATION_INVALID = "ROOT_TRUST_CONFIGURATION_INVALID"
    TARGET_DENIED = "ROOT_TRUST_TARGET_DENIED"
    TRANSPORT_UNAVAILABLE = "ROOT_TRUST_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "ROOT_TRUST_RESPONSE_INVALID"
    EVIDENCE_INVALID = "ROOT_TRUST_EVIDENCE_INVALID"


class RootTrustClientError(RuntimeError):
    """Sanitized internal-client failure with no response or credential material."""

    def __init__(self, code: RootTrustClientErrorCode) -> None:
        if type(code) is not RootTrustClientErrorCode:
            raise TypeError("an exact root trust client error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class RootPreflightReader(StableSnapshotReader, CandidateRevisionReader, Protocol):
    """One verifier-owned reader for the exact service and declared revisions."""


class RootPreflightReaderFactory(Protocol):
    """Create a target-bound read adapter from one validated preflight request."""

    def __call__(self, request: RootPreflightRequestV1) -> RootPreflightReader: ...


@runtime_checkable
class CanonicalInternalTransport(Protocol):
    """One-shot canonical POST transport sealed to an internal route."""

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes: ...


@runtime_checkable
class ExactEvidenceSignatureVerifier(Protocol):
    """Verify evidence against one exact public KMS key version."""

    @property
    def project_id(self) -> str: ...

    @property
    def key_version(self) -> str: ...

    async def verify(self, signed: SignedEvidenceEventV1) -> None: ...


@dataclass(frozen=True, slots=True)
class TrustedRootPreflight:
    """Application-only trusted facts returned after canonical response checks."""

    stable_snapshot: StableSnapshot
    candidate_revision: CandidateRevisionAttestation

    def __post_init__(self) -> None:
        if type(self.stable_snapshot) is not StableSnapshot:
            raise TypeError("trusted root preflight requires an exact stable snapshot")
        if type(self.candidate_revision) is not CandidateRevisionAttestation:
            raise TypeError("trusted root preflight requires an exact candidate attestation")


@dataclass(frozen=True, slots=True)
class CoordinatorInternalRoute:
    """Fixed internal caller, audience, role, and path for one private service."""

    project_id: str
    project_number: str
    caller_role: CallerRole
    service_role: ServiceRole
    audience: str

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not str
            or _CONTROLGRAPH_PROJECT.fullmatch(self.project_id) is None
            or "reconcile" in self.project_id
            or type(self.project_number) is not str
            or _PROJECT_NUMBER.fullmatch(self.project_number) is None
            or (self.caller_role, self.service_role)
            not in {
                (CallerRole.API, ServiceRole.COORDINATOR),
                (CallerRole.COORDINATOR, ServiceRole.VERIFIER),
                (CallerRole.COORDINATOR, ServiceRole.EVIDENCE_WRITER),
            }
        ):
            raise ValueError("coordinator internal route coordinates are invalid")
        expected = (
            f"https://{runtime_service_name(self.service_role)}-{self.project_number}"
            ".us-central1.run.app"
        )
        try:
            parsed = urlsplit(self.audience)
            port = parsed.port
        except ValueError:
            raise ValueError("coordinator internal route audience is invalid") from None
        if (
            self.audience != expected
            or parsed.scheme != "https"
            or parsed.netloc != parsed.hostname
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or port is not None
            or self.audience.endswith("/")
        ):
            raise ValueError("coordinator internal route audience is invalid")

    @property
    def path(self) -> str:
        return protected_path(self.service_role)

    @property
    def url(self) -> str:
        return f"{self.audience}{self.path}"


InternalServiceRoute = CoordinatorInternalRoute


class RootPreflightService:
    """Recapture the exact stable baseline and validate one candidate as verifier."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authentication_policy: RouteAuthenticationPolicy,
        reader_factory: RootPreflightReaderFactory,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not _target_is_exact(target):
            raise RootPreflightError(RootPreflightErrorCode.CONFIGURATION_INVALID)
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != target.project_id
            or authentication_policy.service_role is not ServiceRole.VERIFIER
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or authentication_policy.path != protected_path(ServiceRole.VERIFIER)
            or not callable(reader_factory)
            or (clock is not None and not callable(clock))
        ):
            raise RootPreflightError(RootPreflightErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._authentication_policy = authentication_policy
        self._reader_factory = reader_factory
        self._clock = clock

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def preflight(
        self,
        request: RootPreflightRequestV1,
        caller: AuthenticationContext,
    ) -> RootPreflightResultV1:
        """Return canonical verifier observations or one closed denial."""

        if type(request) is not RootPreflightRequestV1 or request.target != self._target:
            raise RootPreflightError(RootPreflightErrorCode.REQUEST_DENIED)
        if not self._caller_is_exact(caller):
            raise RootPreflightError(RootPreflightErrorCode.CALLER_DENIED)
        try:
            reader = self._reader_factory(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RootPreflightError(RootPreflightErrorCode.UNAVAILABLE) from None
        if not isinstance(reader, RootPreflightReader):
            raise RootPreflightError(RootPreflightErrorCode.UNAVAILABLE)
        expected_reader = f"controlgraph-verifier@{self._target.project_id}.iam.gserviceaccount.com"
        try:
            initial_stable = await StableSnapshotCapturer(
                reader=reader,
                configuration=StableSnapshotCaptureConfiguration(
                    target=self._target,
                    reader_identity=expected_reader,
                ),
                clock=self._clock,
            ).capture()
        except asyncio.CancelledError:
            raise
        except StableCaptureError:
            raise RootPreflightError(RootPreflightErrorCode.STABLE_UNAVAILABLE) from None
        except Exception:
            raise RootPreflightError(RootPreflightErrorCode.UNAVAILABLE) from None
        if (
            not stable_snapshots_match(initial_stable, request.expected_stable_snapshot)
            or initial_stable.captured_at < request.expected_stable_snapshot.captured_at
        ):
            raise RootPreflightError(RootPreflightErrorCode.STABLE_MISMATCH)
        try:
            candidate = await CandidateRevisionValidator(
                reader=reader,
                configuration=CandidateRevisionValidationConfiguration(
                    target=self._target,
                    candidate_revision=request.candidate_revision,
                    expected_configuration_sha256=(
                        request.candidate_revision_configuration_sha256
                    ),
                    expected_concurrency=request.concurrency,
                    reader_identity=expected_reader,
                ),
                clock=self._clock,
            ).validate()
        except asyncio.CancelledError:
            raise
        except CandidateValidationError:
            raise RootPreflightError(RootPreflightErrorCode.CANDIDATE_DENIED) from None
        except Exception:
            raise RootPreflightError(RootPreflightErrorCode.UNAVAILABLE) from None
        if candidate.captured_at < initial_stable.captured_at:
            raise RootPreflightError(RootPreflightErrorCode.UNAVAILABLE)
        try:
            final_stable = await StableSnapshotCapturer(
                reader=reader,
                configuration=StableSnapshotCaptureConfiguration(
                    target=self._target,
                    reader_identity=expected_reader,
                ),
                clock=self._clock,
            ).capture()
        except asyncio.CancelledError:
            raise
        except StableCaptureError:
            raise RootPreflightError(RootPreflightErrorCode.STABLE_UNAVAILABLE) from None
        except Exception:
            raise RootPreflightError(RootPreflightErrorCode.UNAVAILABLE) from None
        if (
            not stable_snapshots_match(final_stable, request.expected_stable_snapshot)
            or not stable_snapshots_match(final_stable, initial_stable)
            or final_stable.captured_at < candidate.captured_at
        ):
            raise RootPreflightError(RootPreflightErrorCode.STABLE_MISMATCH)
        try:
            return RootPreflightResultV1(
                schema_version=ROOT_PREFLIGHT_RESULT_V1,
                request=request,
                request_sha256=root_preflight_request_sha256(request),
                stable_snapshot=final_stable,
                candidate_revision=_candidate_contract(candidate),
            )
        except (TypeError, ValueError):
            raise RootPreflightError(RootPreflightErrorCode.UNAVAILABLE) from None

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


class CoordinatorRootPreflightClient:
    """Call only the verifier preflight route and return independently bound facts."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.service_role is not ServiceRole.VERIFIER
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise RootTrustClientError(RootTrustClientErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._transport = transport

    async def preflight(self, request: RootPreflightRequestV1) -> TrustedRootPreflight:
        """Return trusted stable and candidate observations from one canonical response."""

        if (
            type(request) is not RootPreflightRequestV1
            or request.target.project_id != self._route.project_id
        ):
            raise RootTrustClientError(RootTrustClientErrorCode.TARGET_DENIED)
        try:
            body = await self._transport.post(self._route, canonical_json_bytes(request))
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RootTrustClientError(
                RootTrustClientErrorCode.TRANSPORT_UNAVAILABLE
            ) from None
        try:
            result = decode_contract(body, RootPreflightResultV1)
        except ContractError:
            raise RootTrustClientError(RootTrustClientErrorCode.RESPONSE_INVALID) from None
        except Exception:
            raise RootTrustClientError(RootTrustClientErrorCode.RESPONSE_INVALID) from None
        if (
            result.request != request
            or result.request_sha256 != root_preflight_request_sha256(request)
        ):
            raise RootTrustClientError(RootTrustClientErrorCode.RESPONSE_INVALID)
        attestation = result.candidate_revision
        try:
            candidate = CandidateRevisionAttestation(
                target=attestation.target,
                candidate_revision=attestation.candidate_revision,
                configuration_sha256=attestation.configuration_sha256,
                generation=attestation.generation,
                etag=attestation.etag,
                concurrency=attestation.concurrency,
                reader_identity=attestation.reader_identity,
                captured_at=attestation.captured_at,
            )
            return TrustedRootPreflight(
                stable_snapshot=result.stable_snapshot,
                candidate_revision=candidate,
            )
        except (TypeError, ValueError):
            raise RootTrustClientError(RootTrustClientErrorCode.RESPONSE_INVALID) from None


class CoordinatorEvidenceClient:
    """Obtain and independently verify evidence from the fixed writer route."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        evidence_key_version: str,
        transport: CanonicalInternalTransport,
        signature_verifier: ExactEvidenceSignatureVerifier,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.service_role is not ServiceRole.EVIDENCE_WRITER
            or type(evidence_key_version) is not str
            or not isinstance(transport, CanonicalInternalTransport)
            or not isinstance(signature_verifier, ExactEvidenceSignatureVerifier)
            or signature_verifier.project_id != route.project_id
            or signature_verifier.key_version != evidence_key_version
        ):
            raise RootTrustClientError(RootTrustClientErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._evidence_key_version = evidence_key_version
        self._transport = transport
        self._signature_verifier = signature_verifier

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1:
        """Return evidence only after exact response and ECDSA verification."""

        if (
            type(event) is not EvidenceEvent
            or event.target.project_id != self._route.project_id
            or not _target_is_exact(event.target)
        ):
            raise RootTrustClientError(RootTrustClientErrorCode.TARGET_DENIED)
        try:
            body = await self._transport.post(self._route, canonical_json_bytes(event))
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RootTrustClientError(
                RootTrustClientErrorCode.TRANSPORT_UNAVAILABLE
            ) from None
        try:
            signed = decode_contract(body, SignedEvidenceEventV1)
        except ContractError:
            raise RootTrustClientError(RootTrustClientErrorCode.RESPONSE_INVALID) from None
        except Exception:
            raise RootTrustClientError(RootTrustClientErrorCode.RESPONSE_INVALID) from None
        if signed.event != event or signed.signing_key_version != self._evidence_key_version:
            raise RootTrustClientError(RootTrustClientErrorCode.EVIDENCE_INVALID)
        try:
            await self._signature_verifier.verify(signed)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RootTrustClientError(RootTrustClientErrorCode.EVIDENCE_INVALID) from None
        return signed


def _candidate_contract(
    candidate: CandidateRevisionAttestation,
) -> RootCandidateAttestationV1:
    if type(candidate) is not CandidateRevisionAttestation:
        raise TypeError("candidate attestation is invalid")
    return RootCandidateAttestationV1(
        schema_version=ROOT_CANDIDATE_ATTESTATION_V1,
        target=candidate.target,
        candidate_revision=candidate.candidate_revision,
        configuration_sha256=candidate.configuration_sha256,
        generation=candidate.generation,
        etag=candidate.etag,
        concurrency=candidate.concurrency,
        reader_identity=candidate.reader_identity,
        captured_at=candidate.captured_at,
    )


def _target_is_exact(target: object) -> bool:
    return (
        type(target) is TargetBinding
        and _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is not None
        and "reconcile" not in target.project_id
        and target.region == "us-central1"
        and target.environment == "nonprod"
        and target.service_name == _REFERENCE_SERVICE
    )


__all__ = [
    "CanonicalInternalTransport",
    "CoordinatorEvidenceClient",
    "CoordinatorInternalRoute",
    "CoordinatorRootPreflightClient",
    "ExactEvidenceSignatureVerifier",
    "InternalServiceRoute",
    "RootPreflightError",
    "RootPreflightErrorCode",
    "RootPreflightReader",
    "RootPreflightReaderFactory",
    "RootPreflightService",
    "RootTrustClientError",
    "RootTrustClientErrorCode",
    "TrustedRootPreflight",
]
