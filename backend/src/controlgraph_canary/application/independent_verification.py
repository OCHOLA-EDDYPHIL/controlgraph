"""Read-only configuration attestation and harmless data-plane probing."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast, runtime_checkable

from controlgraph_canary.application.cloud_run import (
    CloudRunReadyState,
    CloudRunTargetState,
    TargetConfigurationProjection,
    cloud_run_revision_configuration_sha256,
    target_configuration_projection_sha256,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    RestrictedJson,
    canonical_json_value_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.independent_verification import (
    CONFIGURATION_ATTESTATION_V1,
    CONFIGURATION_OBSERVATION_FACTS_V1,
    CONFIGURATION_OBSERVATION_V1,
    INDEPENDENT_VERIFICATION_ATTESTATION_V1,
    INDEPENDENT_VERIFICATION_EVIDENCE_V1,
    INDEPENDENT_VERIFICATION_SIGNING_REQUEST_V1,
    PROBE_ATTESTATION_V1,
    PROBE_OBSERVATION_V1,
    PROBE_REQUEST_V1,
    PROBE_SAMPLE_OBSERVATION_V1,
    ConfigurationAttestationReason,
    ConfigurationAttestationStatus,
    ConfigurationAttestationV1,
    ConfigurationObservationFactsV1,
    ConfigurationObservationV1,
    ConfigurationReadyState,
    IndependentVerificationAttestationV1,
    IndependentVerificationEvidenceV1,
    IndependentVerificationKind,
    IndependentVerificationSigningRequestV1,
    IndependentVerificationVerdict,
    ProbeAttestationReason,
    ProbeAttestationStatus,
    ProbeAttestationV1,
    ProbeObservationV1,
    ProbeRequestV1,
    ProbeSampleObservationV1,
    ProbeSampleOutcome,
    SealedReferenceProbeV1,
    SignedIndependentVerificationEvidenceV1,
    VerificationRequestV1,
    configuration_attestation_reason,
    fixed_probe_policy,
    probe_attestation_reason,
    probe_observation_sha256,
)
from controlgraph_canary.contracts.models import TargetBinding, TrafficAllocation

_STABLE_MARKER = "controlgraph-stable-v1"
_CANDIDATE_MARKER = "controlgraph-candidate-v1"


class IndependentVerificationErrorCode(StrEnum):
    """Stable payload-free failures at the independent verifier boundary."""

    CONFIGURATION_INVALID = "INDEPENDENT_VERIFICATION_CONFIGURATION_INVALID"
    CALLER_DENIED = "INDEPENDENT_VERIFICATION_CALLER_DENIED"
    REQUEST_DENIED = "INDEPENDENT_VERIFICATION_REQUEST_DENIED"
    SIGNING_UNAVAILABLE = "INDEPENDENT_VERIFICATION_SIGNING_UNAVAILABLE"
    RESPONSE_INVALID = "INDEPENDENT_VERIFICATION_RESPONSE_INVALID"
    UNAVAILABLE = "INDEPENDENT_VERIFICATION_UNAVAILABLE"


class IndependentVerificationError(RuntimeError):
    """Sanitized failure that retains no provider body or credential material."""

    def __init__(self, code: IndependentVerificationErrorCode) -> None:
        if type(code) is not IndependentVerificationErrorCode:
            raise TypeError("an exact independent verification error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class IndependentConfigurationReader(Protocol):
    """Verifier-owned fixed-target read surface with no mutation methods."""

    @property
    def target(self) -> TargetBinding: ...

    @property
    def service_role(self) -> ServiceRole: ...

    @property
    def reader_identity(self) -> str: ...

    async def read_target(self) -> CloudRunTargetState: ...


class IndependentConfigurationReaderFactory(Protocol):
    """Build a reader sealed to one exact verification request."""

    def __call__(
        self,
        request: VerificationRequestV1,
    ) -> IndependentConfigurationReader: ...


@dataclass(frozen=True, slots=True)
class ProbeHttpResponse:
    """Bounded transport response retained only until strict decoding."""

    status_code: int
    content_type: str
    body: bytes

    def __post_init__(self) -> None:
        if (
            type(self.status_code) is not int
            or not 100 <= self.status_code <= 599
            or type(self.content_type) is not str
            or len(self.content_type) > 128
            or type(self.body) is not bytes
            or len(self.body) > 1_024
        ):
            raise ValueError("probe HTTP response is outside its fixed bounds")


@runtime_checkable
class SealedProbeTransport(Protocol):
    """One-shot GET-only transport sealed to a configured HTTPS endpoint."""

    @property
    def endpoint(self) -> str: ...

    async def get(
        self,
        *,
        nonce: str,
        correlation_id: str,
        timeout_milliseconds: int,
        response_limit_bytes: int,
    ) -> ProbeHttpResponse: ...


@runtime_checkable
class IndependentVerificationEvidenceClient(Protocol):
    """Verifier-only client for the purpose-separated evidence writer route."""

    async def sign(
        self,
        request: IndependentVerificationSigningRequestV1,
    ) -> SignedIndependentVerificationEvidenceV1: ...


class IndependentVerificationService:
    """Observe the fixed target and obtain a separate evidence-writer signature."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authentication_policy: RouteAuthenticationPolicy,
        reader_factory: IndependentConfigurationReaderFactory,
        probe_transport: SealedProbeTransport,
        evidence_client: IndependentVerificationEvidenceClient,
        clock: Callable[[], datetime] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        expected_identity = _verifier_identity(target)
        if (
            type(target) is not TargetBinding
            or target.service_name != "controlgraph-reference-target"
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.VERIFIER
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or authentication_policy.project_id != target.project_id
            or authentication_policy.path != protected_path(ServiceRole.VERIFIER)
            or not callable(reader_factory)
            or not isinstance(probe_transport, SealedProbeTransport)
            or not isinstance(evidence_client, IndependentVerificationEvidenceClient)
            or (clock is not None and not callable(clock))
            or (nonce_factory is not None and not callable(nonce_factory))
            or expected_identity
            != f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.CONFIGURATION_INVALID
            )
        self._target = target
        self._authentication_policy = authentication_policy
        self._reader_factory = reader_factory
        self._probe_transport = probe_transport
        self._evidence_client = evidence_client
        self._clock = clock or _system_utc_second
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(24))

    async def attest_configuration(
        self,
        request: VerificationRequestV1,
        caller: AuthenticationContext,
    ) -> IndependentVerificationAttestationV1:
        """Read exact Cloud Run state and sign match, mismatch, or unavailable."""

        self._require_request(request, caller)
        observation: ConfigurationObservationV1 | None = None
        try:
            reader = self._reader_factory(request)
            if (
                not isinstance(reader, IndependentConfigurationReader)
                or reader.target != self._target
                or reader.service_role is not ServiceRole.VERIFIER
                or reader.reader_identity != _verifier_identity(self._target)
            ):
                raise TypeError("reader is outside the verifier boundary")
            state = await reader.read_target()
            if type(state) is not CloudRunTargetState:
                raise TypeError("reader returned an invalid target state")
            observed_at = self._timestamp()
            observation = _configuration_observation(
                request,
                state,
                reader.reader_identity,
                observed_at,
            )
            reason = configuration_attestation_reason(request, observation.facts)
            status = (
                ConfigurationAttestationStatus.MATCH
                if reason is ConfigurationAttestationReason.MATCH
                else ConfigurationAttestationStatus.MISMATCH
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            observed_at = self._timestamp()
            status = ConfigurationAttestationStatus.UNAVAILABLE
            reason = ConfigurationAttestationReason.READ_UNAVAILABLE
            observation = None
        try:
            result = ConfigurationAttestationV1(
                schema_version=CONFIGURATION_ATTESTATION_V1,
                request=request,
                request_sha256=canonical_sha256(request),
                status=status,
                reason=reason,
                observation=observation,
                attested_by=_verifier_identity(self._target),
                attested_at=observed_at,
            )
            signing_request = _configuration_signing_request(result)
        except (TypeError, ValueError, ContractError):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.UNAVAILABLE
            ) from None
        return await self._sign(signing_request)

    async def attest_probe(
        self,
        request: VerificationRequestV1,
        caller: AuthenticationContext,
    ) -> IndependentVerificationAttestationV1:
        """Send exactly twenty GET probes with no retries or redirect authority."""

        self._require_request(request, caller)
        try:
            policy = fixed_probe_policy(
                request.stable_percent,
                request.candidate_percent,
            )
            if canonical_sha256(policy) != request.probe_policy_sha256:
                raise ValueError("probe policy is not request-bound")
            probe_request = ProbeRequestV1(
                schema_version=PROBE_REQUEST_V1,
                verification=request,
                policy=policy,
                endpoint=self._probe_transport.endpoint,
                nonce=self._nonce_factory(),
                started_at=self._timestamp(),
            )
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.UNAVAILABLE
            ) from None

        samples: list[ProbeSampleObservationV1] = []
        for sample_index in range(1, policy.sample_count + 1):
            samples.append(
                await self._probe_once(probe_request, sample_index)
            )
        sample_tuple = tuple(samples)
        counts = [sample.outcome for sample in sample_tuple]
        try:
            observation = ProbeObservationV1(
                schema_version=PROBE_OBSERVATION_V1,
                samples=sample_tuple,
                stable_count=counts.count(ProbeSampleOutcome.STABLE),
                candidate_count=counts.count(ProbeSampleOutcome.CANDIDATE),
                invalid_count=counts.count(ProbeSampleOutcome.RESPONSE_INVALID),
                unavailable_count=counts.count(
                    ProbeSampleOutcome.TRANSPORT_UNAVAILABLE
                ),
                observation_sha256=probe_observation_sha256(sample_tuple),
            )
            reason = probe_attestation_reason(policy, observation)
            status = (
                ProbeAttestationStatus.MATCH
                if reason is ProbeAttestationReason.MATCH
                else ProbeAttestationStatus.INCONCLUSIVE
            )
            result = ProbeAttestationV1(
                schema_version=PROBE_ATTESTATION_V1,
                request=probe_request,
                request_sha256=canonical_sha256(probe_request),
                status=status,
                reason=reason,
                observation=observation,
                attested_by=_verifier_identity(self._target),
                completed_at=self._timestamp(),
            )
            signing_request = _probe_signing_request(result)
        except (TypeError, ValueError, ContractError):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.UNAVAILABLE
            ) from None
        return await self._sign(signing_request)

    async def _probe_once(
        self,
        request: ProbeRequestV1,
        sample_index: int,
    ) -> ProbeSampleObservationV1:
        correlation_id = f"{request.verification.correlation_id}:{sample_index}"
        requested_at = self._timestamp()
        response: ProbeHttpResponse | None = None
        try:
            response = await asyncio.wait_for(
                self._probe_transport.get(
                    nonce=request.nonce,
                    correlation_id=correlation_id,
                    timeout_milliseconds=request.policy.timeout_milliseconds,
                    response_limit_bytes=request.policy.response_limit_bytes,
                ),
                timeout=request.policy.timeout_milliseconds / 1_000,
            )
            outcome, revision, marker = _classify_probe_response(
                response,
                request,
                correlation_id,
            )
            response_sha256: str | None = hashlib.sha256(response.body).hexdigest()
        except asyncio.CancelledError:
            raise
        except (TimeoutError, OSError):
            outcome = ProbeSampleOutcome.TRANSPORT_UNAVAILABLE
            revision = None
            marker = None
            response_sha256 = None
        except Exception:
            outcome = ProbeSampleOutcome.RESPONSE_INVALID
            revision = None
            marker = None
            response_sha256 = (
                hashlib.sha256(response.body).hexdigest()
                if response is not None
                else None
            )
        return ProbeSampleObservationV1(
            schema_version=PROBE_SAMPLE_OBSERVATION_V1,
            sample_index=sample_index,
            correlation_id=correlation_id,
            requested_at=requested_at,
            completed_at=self._timestamp(),
            outcome=outcome,
            revision=revision,
            marker=marker,
            response_sha256=response_sha256,
        )

    async def _sign(
        self,
        request: IndependentVerificationSigningRequestV1,
    ) -> IndependentVerificationAttestationV1:
        try:
            signed = await self._evidence_client.sign(request)
            return IndependentVerificationAttestationV1(
                schema_version=INDEPENDENT_VERIFICATION_ATTESTATION_V1,
                signing_request=request,
                signed_evidence=signed,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.SIGNING_UNAVAILABLE
            ) from None

    def _require_request(
        self,
        request: VerificationRequestV1,
        caller: AuthenticationContext,
    ) -> None:
        if type(request) is not VerificationRequestV1 or request.target != self._target:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.REQUEST_DENIED
            )
        expected = self._authentication_policy.caller
        if (
            type(caller) is not AuthenticationContext
            or caller.role is not CallerRole.COORDINATOR
            or caller.role is not expected.role
            or caller.email != expected.email
            or caller.subject != expected.subject
            or caller.issuer not in {"accounts.google.com", "https://accounts.google.com"}
            or caller.audience != self._authentication_policy.audience
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.CALLER_DENIED
            )

    def _timestamp(self) -> str:
        try:
            value = self._clock()
        except Exception:
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.UNAVAILABLE
            ) from None
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise IndependentVerificationError(
                IndependentVerificationErrorCode.UNAVAILABLE
            )
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _configuration_observation(
    request: VerificationRequestV1,
    state: CloudRunTargetState,
    reader_identity: str,
    observed_at: str,
) -> ConfigurationObservationV1:
    service = state.service
    if service.target != request.target:
        raise ValueError("configuration read returned a substituted target")
    traffic = tuple(
        TrafficAllocation(revision=item.revision, percent=item.percent)
        for item in service.traffic
    )
    traffic_statuses = tuple(
        TrafficAllocation(revision=item.revision, percent=item.percent)
        for item in service.traffic_statuses
    )
    target_digest = _target_configuration_sha256(request, state)
    facts = ConfigurationObservationFactsV1(
        schema_version=CONFIGURATION_OBSERVATION_FACTS_V1,
        target=service.target,
        source_generation=service.generation,
        observed_generation=service.observed_generation,
        provider_etag=service.etag,
        reconciling=service.reconciling,
        ready_state={
            CloudRunReadyState.READY: ConfigurationReadyState.READY,
            CloudRunReadyState.NOT_READY: ConfigurationReadyState.NOT_READY,
            CloudRunReadyState.FAILED: ConfigurationReadyState.NOT_READY,
        }[service.ready_state],
        template_revision=service.template_revision,
        latest_created_revision=service.latest_created_revision,
        latest_ready_revision=service.latest_ready_revision,
        stable_revision=state.stable_revision.revision,
        candidate_revision=state.candidate_revision.revision,
        traffic=traffic,
        traffic_statuses=traffic_statuses,
        concurrency=service.template_concurrency,
        stable_revision_configuration_sha256=(
            cloud_run_revision_configuration_sha256(
                state.stable_revision.configuration
            )
        ),
        candidate_revision_configuration_sha256=(
            cloud_run_revision_configuration_sha256(
                state.candidate_revision.configuration
            )
        ),
        target_configuration_sha256=target_digest,
        retrieved_by=reader_identity,
        retrieved_at=observed_at,
    )
    return ConfigurationObservationV1(
        schema_version=CONFIGURATION_OBSERVATION_V1,
        facts=facts,
        observation_sha256=canonical_sha256(facts),
    )


def _target_configuration_sha256(
    request: VerificationRequestV1,
    state: CloudRunTargetState,
) -> str:
    traffic = {item.revision: item.percent for item in state.service.traffic}
    if set(traffic).issubset({request.stable_revision, request.candidate_revision}):
        return target_configuration_projection_sha256(
            TargetConfigurationProjection(
                target=request.target,
                stable_revision=request.stable_revision,
                candidate_revision=request.candidate_revision,
                stable_percent=traffic.get(request.stable_revision, 0),
                candidate_percent=traffic.get(request.candidate_revision, 0),
                concurrency=state.service.template_concurrency,
            )
        )
    material = canonical_json_value_bytes(
        cast(
            RestrictedJson,
            {
                "concurrency": state.service.template_concurrency,
                "target": request.target.model_dump(mode="json"),
                "traffic": [
                    {"percent": percent, "revision": revision}
                    for revision, percent in sorted(traffic.items())
                ],
            },
        )
    )
    return hashlib.sha256(
        b"controlgraph.unexpected-target-configuration/v1\0" + material
    ).hexdigest()


def _classify_probe_response(
    response: ProbeHttpResponse,
    request: ProbeRequestV1,
    correlation_id: str,
) -> tuple[ProbeSampleOutcome, str, str]:
    if response.status_code != 200 or response.content_type.split(";", 1)[0] != "application/json":
        raise ValueError("probe response metadata is invalid")
    decoded = decode_contract(response.body, SealedReferenceProbeV1)
    if decoded.nonce != request.nonce or decoded.correlation_id != correlation_id:
        raise ValueError("probe response seal is invalid")
    verification = request.verification
    if (
        decoded.revision == verification.stable_revision
        and decoded.marker == _STABLE_MARKER
    ):
        return ProbeSampleOutcome.STABLE, decoded.revision, decoded.marker
    if (
        decoded.revision == verification.candidate_revision
        and decoded.marker == _CANDIDATE_MARKER
    ):
        return ProbeSampleOutcome.CANDIDATE, decoded.revision, decoded.marker
    raise ValueError("probe response marker is invalid")


def _configuration_signing_request(
    result: ConfigurationAttestationV1,
) -> IndependentVerificationSigningRequestV1:
    verification = result.request
    verdict = {
        ConfigurationAttestationStatus.MATCH: IndependentVerificationVerdict.MATCH,
        ConfigurationAttestationStatus.MISMATCH: IndependentVerificationVerdict.MISMATCH,
        ConfigurationAttestationStatus.UNAVAILABLE: IndependentVerificationVerdict.UNAVAILABLE,
    }[result.status]
    evidence = _evidence(
        verification,
        kind=IndependentVerificationKind.CONFIGURATION,
        subject_sha256=canonical_sha256(result),
        verdict=verdict,
        reason_code=result.reason.value,
        occurred_at=result.attested_at,
    )
    return IndependentVerificationSigningRequestV1(
        schema_version=INDEPENDENT_VERIFICATION_SIGNING_REQUEST_V1,
        configuration=result,
        evidence=evidence,
    )


def _probe_signing_request(
    result: ProbeAttestationV1,
) -> IndependentVerificationSigningRequestV1:
    verification = result.request.verification
    evidence = _evidence(
        verification,
        kind=IndependentVerificationKind.PROBE,
        subject_sha256=canonical_sha256(result),
        verdict=(
            IndependentVerificationVerdict.MATCH
            if result.status is ProbeAttestationStatus.MATCH
            else IndependentVerificationVerdict.INCONCLUSIVE
        ),
        reason_code=result.reason.value,
        occurred_at=result.completed_at,
    )
    return IndependentVerificationSigningRequestV1(
        schema_version=INDEPENDENT_VERIFICATION_SIGNING_REQUEST_V1,
        probe=result,
        evidence=evidence,
    )


def _evidence(
    request: VerificationRequestV1,
    *,
    kind: IndependentVerificationKind,
    subject_sha256: str,
    verdict: IndependentVerificationVerdict,
    reason_code: str,
    occurred_at: str,
) -> IndependentVerificationEvidenceV1:
    return IndependentVerificationEvidenceV1(
        schema_version=INDEPENDENT_VERIFICATION_EVIDENCE_V1,
        kind=kind,
        verification_request_sha256=canonical_sha256(request),
        root_id=request.root_id,
        root_sha256=request.root_sha256,
        epoch=request.epoch,
        target=request.target,
        plan_sha256=request.plan_sha256,
        service_claim_sha256=request.service_claim_sha256,
        probe_policy_sha256=request.probe_policy_sha256,
        signed_intent_sha256=request.signed_intent_sha256,
        action=request.action,
        stable_revision=request.stable_revision,
        candidate_revision=request.candidate_revision,
        stable_percent=request.stable_percent,
        candidate_percent=request.candidate_percent,
        concurrency=request.concurrency,
        request_id=request.request_id,
        correlation_id=request.correlation_id,
        observation_window_started_at=request.observation_window_started_at,
        observation_window_ends_at=request.observation_window_ends_at,
        subject_sha256=subject_sha256,
        verdict=verdict,
        reason_code=reason_code,
        verifier_identity=_verifier_identity(request.target),
        occurred_at=occurred_at,
    )


def _verifier_identity(target: TargetBinding) -> str:
    return f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "IndependentConfigurationReader",
    "IndependentConfigurationReaderFactory",
    "IndependentVerificationError",
    "IndependentVerificationErrorCode",
    "IndependentVerificationEvidenceClient",
    "IndependentVerificationService",
    "ProbeHttpResponse",
    "SealedProbeTransport",
]
