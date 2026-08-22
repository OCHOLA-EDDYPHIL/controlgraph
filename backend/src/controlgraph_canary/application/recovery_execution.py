"""Authenticated orchestration for one root-owned captured-stable recovery."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreError,
    AuthorityStoreOutcomeUnknown,
    StoredRecord,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunReadyState,
    CloudRunRevisionState,
    CloudRunServiceState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
    cloud_run_revision_configuration_sha256,
)
from controlgraph_canary.application.health_orchestration import (
    HealthAttestationVerifier,
)
from controlgraph_canary.application.identity import (
    RECOVERY_PRESTATE_ATTESTATION_PATH,
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.recovery_store import (
    RecoveryDispatchStore,
    RecoveryEnqueuePermit,
    RecoveryIntentReader,
)
from controlgraph_canary.application.revocation_proof import (
    EpochRevocationEvidenceVerifier,
)
from controlgraph_canary.application.root_authority import (
    RootAuthorityBundleReader,
    TrustedRootAuthority,
    inspect_root_authority_bundle,
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
from controlgraph_canary.application.stable_snapshot import StableSnapshotReader
from controlgraph_canary.application.tasks import (
    AddressedTask,
    TaskEnqueueDisposition,
    TaskEnqueueResult,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
    encode_base64url,
)
from controlgraph_canary.contracts.health_execution import (
    SignedHealthDecisionChainV1,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochChangeCause,
    ExecutionReceipt,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.recovery_execution import (
    RECOVERY_CAPABILITY_ISSUANCE_COMMAND_V2,
    RECOVERY_DISPATCH_RECORD_V2,
    RECOVERY_DISPATCH_RESULT_V2,
    RECOVERY_INVOCATION_V2,
    RECOVERY_MUTATION_INTENT_V2,
    RECOVERY_TASK_REQUEST_V2,
    RecoveryAuthorizationV1,
    RecoveryCapabilityIssuanceCommandV2,
    RecoveryCapabilityIssuanceResultV2,
    RecoveryCommandV2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchResultV2,
    RecoveryDispatchState,
    RecoveryHealthChainLocatorV1,
    RecoveryIntentV1,
    RecoveryInvocationV2,
    RecoveryMutationIntentV2,
    RecoveryPrestateAttestationV1,
    RecoveryPrestateRequestV1,
    RecoveryPrestateSigningRequestV1,
    RecoveryTaskRequestV2,
    RevokedV2RecoverySourceV1,
    RevokedV3RecoverySourceV1,
    UnhealthyRecoverySourceV1,
    create_recovery_apply_receipt_locator,
    create_recovery_authorization,
    create_recovery_health_chain_locator,
    create_recovery_intent,
    create_recovery_prestate_attestation,
    create_recovery_prestate_request,
    create_recovery_prestate_result,
    create_recovery_prestate_signing_request,
    recovery_capability_issuance_command_sha256,
    recovery_command_sha256,
    recovery_dispatch_id,
    recovery_prestate_signing_input_sha256,
    recovery_target_configuration_sha256,
    recovery_trigger_proof_sha256,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV2, RolloutRootV3
from controlgraph_canary.contracts.storage import ServiceClaimStatus

RECOVERY_PRESTATE_VALIDITY_SECONDS = 300


class RecoveryExecutionErrorCode(StrEnum):
    """Stable payload-free failures for recovery orchestration."""

    CONFIGURATION_INVALID = "RECOVERY_CONFIGURATION_INVALID"
    CALLER_DENIED = "RECOVERY_CALLER_DENIED"
    OPERATOR_DENIED = "RECOVERY_OPERATOR_DENIED"
    COMMAND_DENIED = "RECOVERY_COMMAND_DENIED"
    TRUSTED_STATE_UNAVAILABLE = "RECOVERY_TRUSTED_STATE_UNAVAILABLE"
    TRUSTED_STATE_INVALID = "RECOVERY_TRUSTED_STATE_INVALID"
    SOURCE_RECEIPT_INVALID = "RECOVERY_SOURCE_RECEIPT_INVALID"
    TRIGGER_INVALID = "RECOVERY_TRIGGER_INVALID"
    PRESTATE_UNAVAILABLE = "RECOVERY_PRESTATE_UNAVAILABLE"
    PRESTATE_MISMATCH = "RECOVERY_PRESTATE_MISMATCH"
    ATTESTATION_INVALID = "RECOVERY_ATTESTATION_INVALID"
    ISSUANCE_DENIED = "RECOVERY_ISSUANCE_DENIED"
    TRANSPORT_UNAVAILABLE = "RECOVERY_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "RECOVERY_RESPONSE_INVALID"
    DISPATCH_UNAVAILABLE = "RECOVERY_DISPATCH_UNAVAILABLE"
    IDENTITY_CONFLICT = "RECOVERY_IDENTITY_CONFLICT"
    OUTCOME_UNKNOWN = "RECOVERY_OUTCOME_UNKNOWN"
    RESULT_INVALID = "RECOVERY_RESULT_INVALID"


class RecoveryExecutionError(RuntimeError):
    """One sanitized recovery orchestration failure."""

    def __init__(self, code: RecoveryExecutionErrorCode) -> None:
        if type(code) is not RecoveryExecutionErrorCode:
            raise TypeError("an exact recovery execution error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class RecoveryReceiptReader(Protocol):
    """Strongly read the source APPLY receipt named by a recovery command."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...


@runtime_checkable
class RecoveryHealthChainReader(Protocol):
    """Read a terminal unhealthy chain through all compact locator bindings."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_recovery_health_chain(
        self,
        locator: RecoveryHealthChainLocatorV1,
    ) -> SignedHealthDecisionChainV1 | None: ...


@runtime_checkable
class RecoveryPrestateAttestationVerifier(Protocol):
    """Verify the recovery-specific evidence-key signature purpose."""

    @property
    def project_id(self) -> str: ...

    @property
    def key_version(self) -> str: ...

    async def verify(self, attestation: RecoveryPrestateAttestationV1) -> None: ...


@runtime_checkable
class RecoveryPrestateAttestor(Protocol):
    """Request a purpose-separated signature for one exact verifier result."""

    @property
    def signing_key_version(self) -> str: ...

    async def attest(
        self,
        request: RecoveryPrestateSigningRequestV1,
    ) -> RecoveryPrestateAttestationV1: ...


@runtime_checkable
class RecoveryPrestateEvaluator(Protocol):
    """Return a signed exact-current 90/10 observation without mutation authority."""

    async def evaluate(
        self,
        request: RecoveryPrestateRequestV1,
    ) -> RecoveryPrestateAttestationV1: ...


@runtime_checkable
class RecoveryAuthorizationResolver(Protocol):
    """Resolve durable trigger state into a fresh stable-only authorization."""

    async def resolve(
        self,
        command: RecoveryCommandV2,
        *,
        now: datetime,
    ) -> RecoveryAuthorizationV1: ...


@runtime_checkable
class RecoveryCapabilityClient(Protocol):
    """Issue a root-derived capability to the recovery identity only."""

    async def issue(
        self,
        command: RecoveryCommandV2,
        authorization: RecoveryAuthorizationV1,
    ) -> RecoveryCapabilityIssuanceResultV2: ...


@runtime_checkable
class RecoveryCoordinator(Protocol):
    """Dispatch one root-owned stable-only recovery command."""

    async def dispatch(
        self,
        command: RecoveryCommandV2,
    ) -> RecoveryDispatchResultV2: ...


@runtime_checkable
class RecoveryTaskDispatcher(Protocol):
    """Address and enqueue a recovery task only under a direct store permit."""

    def prepare(
        self,
        request: RecoveryTaskRequestV2,
        *,
        now: datetime,
    ) -> AddressedTask: ...

    async def dispatch_prepared_recovery(
        self,
        task: AddressedTask,
        *,
        permit: RecoveryEnqueuePermit,
        now: datetime,
    ) -> TaskEnqueueResult: ...


def _error(code: RecoveryExecutionErrorCode) -> RecoveryExecutionError:
    return RecoveryExecutionError(code)


def _utc(value: datetime) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond
    ):
        raise ValueError("recovery clock is invalid")
    return value


def _utc_text(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seconds(value: str) -> int:
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _context_matches_policy(
    context: object,
    policy: RouteAuthenticationPolicy,
    *,
    role: CallerRole,
) -> bool:
    return (
        type(context) is AuthenticationContext
        and context.role is role
        and context.role is policy.caller.role
        and context.email == policy.caller.email
        and context.subject == policy.caller.subject
        and context.issuer in {"accounts.google.com", "https://accounts.google.com"}
        and context.audience == policy.audience
        and type(context.issued_at) is int
        and type(context.expires_at) is int
        and context.issued_at < context.expires_at
        and context.expires_at - context.issued_at <= 3_660
    )


class RecoveryPrestateSigningService:
    """Authenticate the verifier and sign only one exact prestate result digest."""

    def __init__(
        self,
        *,
        project_id: str,
        authentication_policy: RouteAuthenticationPolicy,
        signer: AsyncDigestSigningBackend,
    ) -> None:
        profile = getattr(signer, "profile", None)
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != project_id
            or authentication_policy.service_role is not ServiceRole.EVIDENCE_WRITER
            or authentication_policy.caller.role is not CallerRole.VERIFIER
            or type(profile) is not SigningProfile
            or profile.project_id != project_id
            or profile.purpose is not SigningPurpose.EVIDENCE
            or profile.algorithm != SIGNING_ALGORITHM
            or not callable(getattr(signer, "sign_digest", None))
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._project_id = project_id
        self._authentication_policy = authentication_policy
        self._signer = signer
        self._profile = profile

    @property
    def signing_key_version(self) -> str:
        return self._profile.key_version

    async def attest(
        self,
        request: RecoveryPrestateSigningRequestV1,
        caller: AuthenticationContext,
    ) -> RecoveryPrestateAttestationV1:
        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.VERIFIER,
        ):
            raise _error(RecoveryExecutionErrorCode.CALLER_DENIED)
        if type(request) is not RecoveryPrestateSigningRequestV1:
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        try:
            validated = RecoveryPrestateSigningRequestV1.model_validate(request)
            expected = create_recovery_prestate_signing_request(validated.result)
        except (TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED) from None
        if (
            validated != expected
            or validated.result.target.project_id != self._project_id
            or validated.result.verifier_identity != caller.email
            or validated.signing_key_version != self._profile.key_version
        ):
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        digest = recovery_prestate_signing_input_sha256(
            validated.result,
            self._profile.key_version,
        )
        try:
            signature = await self._signer.sign_digest(bytes.fromhex(digest))
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.PRESTATE_UNAVAILABLE) from None
        if not _canonical_p256_signature(signature):
            raise _error(RecoveryExecutionErrorCode.PRESTATE_UNAVAILABLE)
        try:
            return create_recovery_prestate_attestation(
                result=validated.result,
                signature=encode_base64url(signature),
            )
        except (TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.PRESTATE_UNAVAILABLE) from None


class VerifierRecoveryPrestateAttestationClient:
    """Call the fixed evidence-writer route once with no application retry."""

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
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID) from None
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.VERIFIER
            or route.service_role is not ServiceRole.EVIDENCE_WRITER
            or route.path != RECOVERY_PRESTATE_ATTESTATION_PATH
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._transport = transport
        self._signing_key_version = profile.key_version

    @property
    def signing_key_version(self) -> str:
        return self._signing_key_version

    async def attest(
        self,
        request: RecoveryPrestateSigningRequestV1,
    ) -> RecoveryPrestateAttestationV1:
        if (
            type(request) is not RecoveryPrestateSigningRequestV1
            or request.signing_key_version != self._signing_key_version
        ):
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.TRANSPORT_UNAVAILABLE) from None
        try:
            attestation = decode_contract(body, RecoveryPrestateAttestationV1)
        except (ContractError, TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.RESPONSE_INVALID) from None
        if (
            attestation.result != request.result
            or attestation.signing_request_sha256 != canonical_sha256(request)
            or attestation.signing_key_version != self._signing_key_version
        ):
            raise _error(RecoveryExecutionErrorCode.RESPONSE_INVALID)
        return attestation


class VerifierRecoveryPrestateService:
    """Observe exactly one 90/10 target and return purpose-signed evidence."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authentication_policy: RouteAuthenticationPolicy,
        reader: StableSnapshotReader,
        attestor: RecoveryPrestateAttestor,
        signature_verifier: RecoveryPrestateAttestationVerifier,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != target.project_id
            or authentication_policy.service_role is not ServiceRole.VERIFIER
            or authentication_policy.path != protected_path(ServiceRole.VERIFIER)
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or not isinstance(reader, StableSnapshotReader)
            or reader.target != target
            or reader.service_role is not ServiceRole.VERIFIER
            or reader.reader_identity
            != f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"
            or not isinstance(attestor, RecoveryPrestateAttestor)
            or not isinstance(signature_verifier, RecoveryPrestateAttestationVerifier)
            or signature_verifier.project_id != target.project_id
            or signature_verifier.key_version != attestor.signing_key_version
            or (clock is not None and not callable(clock))
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._authentication_policy = authentication_policy
        self._reader = reader
        self._attestor = attestor
        self._signature_verifier = signature_verifier
        self._clock = clock or _now

    async def evaluate(
        self,
        request: RecoveryPrestateRequestV1,
        caller: AuthenticationContext,
    ) -> RecoveryPrestateAttestationV1:
        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.COORDINATOR,
        ):
            raise _error(RecoveryExecutionErrorCode.CALLER_DENIED)
        if type(request) is not RecoveryPrestateRequestV1 or request.target != self._target:
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        now = _utc(self._clock())
        now_text = _utc_text(now)
        if not request.requested_at <= now_text <= request.command.scheduled_at:
            raise _error(RecoveryExecutionErrorCode.PRESTATE_UNAVAILABLE)
        try:
            service, stable, candidate = await asyncio.gather(
                self._reader.read_service(),
                self._reader.read_revision(request.stable_revision),
                self._reader.read_revision(request.candidate_revision),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.PRESTATE_UNAVAILABLE) from None
        if not _prestate_matches(request, service, stable, candidate):
            raise _error(RecoveryExecutionErrorCode.PRESTATE_MISMATCH)
        try:
            result = create_recovery_prestate_result(
                request=request,
                current_provider_etag=service.etag,
                service_generation=service.generation,
                retrieved_at=now_text,
            )
            signing_request = create_recovery_prestate_signing_request(result)
            attestation = await self._attestor.attest(signing_request)
            await self._signature_verifier.verify(attestation)
        except asyncio.CancelledError:
            raise
        except RecoveryExecutionError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.ATTESTATION_INVALID) from None
        if (
            type(attestation) is not RecoveryPrestateAttestationV1
            or attestation.result != result
            or attestation.signing_request_sha256 != canonical_sha256(signing_request)
        ):
            raise _error(RecoveryExecutionErrorCode.ATTESTATION_INVALID)
        return attestation


class CoordinatorRecoveryPrestateClient:
    """Call the verifier once and reject substituted or invalid signed evidence."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
        signature_verifier: RecoveryPrestateAttestationVerifier,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.VERIFIER
            or route.path != protected_path(ServiceRole.VERIFIER)
            or not isinstance(transport, CanonicalInternalTransport)
            or not isinstance(signature_verifier, RecoveryPrestateAttestationVerifier)
            or signature_verifier.project_id != route.project_id
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._transport = transport
        self._signature_verifier = signature_verifier

    async def evaluate(
        self,
        request: RecoveryPrestateRequestV1,
    ) -> RecoveryPrestateAttestationV1:
        if (
            type(request) is not RecoveryPrestateRequestV1
            or request.target.project_id != self._route.project_id
        ):
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.TRANSPORT_UNAVAILABLE) from None
        try:
            attestation = decode_contract(body, RecoveryPrestateAttestationV1)
        except (ContractError, TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.RESPONSE_INVALID) from None
        if (
            attestation.result.request != request
            or attestation.signing_key_version
            != request.evidence_signing_key_version
            or self._signature_verifier.key_version
            != request.evidence_signing_key_version
        ):
            raise _error(RecoveryExecutionErrorCode.RESPONSE_INVALID)
        try:
            await self._signature_verifier.verify(attestation)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.ATTESTATION_INVALID) from None
        return attestation


def _prestate_matches(
    request: RecoveryPrestateRequestV1,
    service: object,
    stable: object,
    candidate: object,
) -> bool:
    if (
        type(service) is not CloudRunServiceState
        or type(stable) is not CloudRunRevisionState
        or type(candidate) is not CloudRunRevisionState
    ):
        return False
    desired = (
        CloudRunTrafficAllocation(
            revision=request.stable_revision,
            percent=90,
            tag="stable",
        ),
        CloudRunTrafficAllocation(
            revision=request.candidate_revision,
            percent=10,
            tag="candidate",
        ),
    )
    desired_statuses = tuple(
        (item.revision, item.percent, item.tag) for item in desired
    )
    statuses = tuple(
        (item.revision, item.percent, item.tag)
        for item in service.traffic_statuses
    )
    try:
        stable_configuration = cloud_run_revision_configuration_sha256(
            stable.configuration
        )
        candidate_configuration = cloud_run_revision_configuration_sha256(
            candidate.configuration
        )
    except (TypeError, ValueError):
        return False
    return (
        service.target == request.target
        and not service.reconciling
        and service.ready_state is CloudRunReadyState.READY
        and service.generation == service.observed_generation
        and service.template_revision == request.candidate_revision
        and service.latest_created_revision == request.candidate_revision
        and service.latest_ready_revision == request.candidate_revision
        and service.template_concurrency == request.concurrency
        and service.traffic == desired
        and statuses == desired_statuses
        and all(
            _tagged_status_uri_matches(item, request.target.service_name)
            for item in service.traffic_statuses
        )
        and stable.target == request.target
        and stable.revision == request.stable_revision
        and not stable.reconciling
        and stable.ready_state is CloudRunReadyState.READY
        and stable.generation == stable.observed_generation
        and stable.concurrency == request.concurrency
        and stable_configuration
        == request.stable_revision_configuration_sha256
        and candidate.target == request.target
        and candidate.revision == request.candidate_revision
        and not candidate.reconciling
        and candidate.ready_state is CloudRunReadyState.READY
        and candidate.generation == candidate.observed_generation
        and candidate.concurrency == request.concurrency
        and candidate_configuration
        == request.candidate_revision_configuration_sha256
    )


def _tagged_status_uri_matches(
    status: CloudRunTrafficStatus,
    service_name: str,
) -> bool:
    if status.uri is None or status.tag not in {"stable", "candidate"}:
        return False
    try:
        parsed = urlsplit(status.uri)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and port is None
        and parsed.hostname is not None
        and parsed.hostname.startswith(f"{status.tag}---{service_name}-")
        and parsed.hostname.endswith(".run.app")
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


def _canonical_p256_signature(value: object) -> bool:
    if type(value) is not bytes or not value or len(value) > 72:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric import utils

        r, s = utils.decode_dss_signature(value)
        return r > 0 and s > 0 and utils.encode_dss_signature(r, s) == value
    except (TypeError, ValueError):
        return False


@dataclass(frozen=True, slots=True)
class _TrustedRecoveryInputs:
    authority: TrustedRootAuthority
    receipt: StoredRecord[ExecutionReceipt]
    intent: StoredRecord[RecoveryIntentV1]
    health_chain: SignedHealthDecisionChainV1 | None


class StoredRecoveryAuthorizationResolver:
    """Replay all durable recovery sources and obtain fresh signed prestate."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        root_reader: RootAuthorityBundleReader,
        receipt_reader: RecoveryReceiptReader,
        intent_reader: RecoveryIntentReader,
        health_chain_reader: RecoveryHealthChainReader,
        health_signature_verifier: HealthAttestationVerifier,
        revocation_evidence_verifier: EpochRevocationEvidenceVerifier,
        prestate_evaluator: RecoveryPrestateEvaluator,
        prestate_signature_verifier: RecoveryPrestateAttestationVerifier,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or not isinstance(root_reader, RootAuthorityBundleReader)
            or root_reader.target != target
            or not isinstance(receipt_reader, RecoveryReceiptReader)
            or receipt_reader.target != target
            or not isinstance(intent_reader, RecoveryIntentReader)
            or intent_reader.target != target
            or not isinstance(health_chain_reader, RecoveryHealthChainReader)
            or health_chain_reader.target != target
            or not isinstance(health_signature_verifier, HealthAttestationVerifier)
            or getattr(health_signature_verifier, "project_id", None)
            != target.project_id
            or not isinstance(
                revocation_evidence_verifier,
                EpochRevocationEvidenceVerifier,
            )
            or not isinstance(prestate_evaluator, RecoveryPrestateEvaluator)
            or not isinstance(
                prestate_signature_verifier,
                RecoveryPrestateAttestationVerifier,
            )
            or prestate_signature_verifier.project_id != target.project_id
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._root_reader = root_reader
        self._receipt_reader = receipt_reader
        self._intent_reader = intent_reader
        self._health_chain_reader = health_chain_reader
        self._health_signature_verifier = health_signature_verifier
        self._revocation_evidence_verifier = revocation_evidence_verifier
        self._prestate_evaluator = prestate_evaluator
        self._prestate_signature_verifier = prestate_signature_verifier

    async def resolve(
        self,
        command: RecoveryCommandV2,
        *,
        now: datetime,
    ) -> RecoveryAuthorizationV1:
        if type(command) is not RecoveryCommandV2:
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        evaluation_time = _utc(now)
        initial = await self._read_inputs(command, now=evaluation_time)
        valid_until = evaluation_time + timedelta(
            seconds=RECOVERY_PRESTATE_VALIDITY_SECONDS
        )
        try:
            request = create_recovery_prestate_request(
                command=command,
                root=initial.authority.root,
                requested_at=_utc_text(evaluation_time),
                valid_until=_utc_text(valid_until),
            )
            attestation = await self._prestate_evaluator.evaluate(request)
            if (
                type(attestation) is not RecoveryPrestateAttestationV1
                or attestation.result.request != request
                or attestation.signing_key_version
                != initial.authority.root.content.evidence_signing_key_version
                or self._prestate_signature_verifier.key_version
                != attestation.signing_key_version
            ):
                raise ValueError("recovery prestate response is substituted")
            await self._prestate_signature_verifier.verify(attestation)
        except asyncio.CancelledError:
            raise
        except RecoveryExecutionError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.ATTESTATION_INVALID) from None
        confirmed = await self._read_inputs(command, now=evaluation_time)
        if confirmed != initial:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID)
        try:
            authorization = create_recovery_authorization(
                root=initial.authority.root,
                command=command,
                prestate_attestation=attestation,
            )
        except (TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        if (
            authorization.target != self._target
            or authorization.source != command.source
            or authorization.verified_apply_receipt
            != command.verified_apply_receipt
        ):
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID)
        return authorization

    async def _read_inputs(
        self,
        command: RecoveryCommandV2,
        *,
        now: datetime,
    ) -> _TrustedRecoveryInputs:
        try:
            bundle, receipt, intent = await asyncio.gather(
                self._root_reader.read_root_creation_bundle(command.root_id),
                self._receipt_reader.read_receipt(
                    command.verified_apply_receipt.idempotency_key
                ),
                self._intent_reader.read_recovery_intent(
                    command.expected_root_sha256
                ),
            )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except Exception:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_UNAVAILABLE) from None
        trusted = inspect_root_authority_bundle(bundle, target=self._target)
        if (
            trusted is None
            or trusted.root.root_id != command.root_id
            or trusted.root.root_sha256 != command.expected_root_sha256
            or trusted.root.content.target != self._target
            or trusted.service_claim.status is not ServiceClaimStatus.ACTIVE
            or trusted.authority.current_epoch != command.expected_epoch
            or type(intent) is not StoredRecord
            or type(intent.value) is not RecoveryIntentV1
            or intent.revision != 0
            or intent.value.command != command
            or intent.value.command_sha256 != recovery_command_sha256(command)
        ):
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID)
        self._validate_apply_receipt(
            trusted,
            command,
            receipt,
            now=now,
        )
        assert type(receipt) is StoredRecord
        assert type(receipt.value) is ExecutionReceipt
        source = command.source
        chain: SignedHealthDecisionChainV1 | None = None
        if type(source) is UnhealthyRecoverySourceV1:
            if type(trusted.root) is not RolloutRootV3:
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
            try:
                chain = await self._health_chain_reader.read_recovery_health_chain(
                    source.health_chain_locator
                )
            except asyncio.CancelledError:
                raise
            except AuthorityStoreCorruptRecord:
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID) from None
            except Exception:
                raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_UNAVAILABLE) from None
            if chain is None:
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
            try:
                for signed in chain.signed_proofs:
                    await self._health_signature_verifier.verify(signed)
                locator = create_recovery_health_chain_locator(chain)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID) from None
            if (
                locator != source.health_chain_locator
                or chain.anchor.apply_receipt != receipt.value
            ):
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
        elif type(source) is RevokedV2RecoverySourceV1:
            if type(trusted.root) is not RolloutRootV2:
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
            proof = source.revocation_proof
            authority = trusted.authority
            if (
                trusted.authority_revision != 1
                or authority.revision != 1
                or authority.current_epoch != 2
                or authority.previous_epoch != 1
                or authority.cause is not EpochChangeCause.OPERATOR_REVOCATION
                or proof.authority != authority
                or proof.result.previous_epoch != 1
                or proof.result.new_epoch != 2
                or proof.signed_evidence.signing_key_version
                != trusted.root.content.evidence_signing_key_version
                or self._revocation_evidence_verifier.evidence_key_version
                != trusted.root.content.evidence_signing_key_version
            ):
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
            try:
                await self._revocation_evidence_verifier.verify(
                    proof.signed_evidence
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID) from None
        elif type(source) is RevokedV3RecoverySourceV1:
            if type(trusted.root) is not RolloutRootV3:
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
            proof = source.revocation_proof
            authority = trusted.authority
            if (
                trusted.authority_revision != authority.revision
                or authority.revision < 1
                or authority.current_epoch != source.epoch
                or authority.previous_epoch != receipt.value.epoch
                or authority.cause is not EpochChangeCause.OPERATOR_REVOCATION
                or proof.authority != authority
                or proof.result.previous_epoch != receipt.value.epoch
                or proof.result.new_epoch != source.epoch
                or _seconds(receipt.value.updated_at) > _seconds(proof.result.committed_at)
                or proof.signed_evidence.signing_key_version
                != trusted.root.content.evidence_signing_key_version
                or self._revocation_evidence_verifier.evidence_key_version
                != trusted.root.content.evidence_signing_key_version
            ):
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
            try:
                await self._revocation_evidence_verifier.verify(proof.signed_evidence)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID) from None
        else:
            raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
        return _TrustedRecoveryInputs(
            authority=trusted,
            receipt=receipt,
            intent=intent,
            health_chain=chain,
        )

    def _validate_apply_receipt(
        self,
        trusted: TrustedRootAuthority,
        command: RecoveryCommandV2,
        stored: object,
        *,
        now: datetime,
    ) -> None:
        if (
            type(stored) is not StoredRecord
            or type(stored.value) is not ExecutionReceipt
            or stored.revision < 2
        ):
            raise _error(RecoveryExecutionErrorCode.SOURCE_RECEIPT_INVALID)
        receipt = stored.value
        root = trusted.root
        source = command.source
        if type(source) is UnhealthyRecoverySourceV1:
            expected_receipt_epoch = command.expected_epoch
        elif type(source) is RevokedV2RecoverySourceV1:
            expected_receipt_epoch = 1
        elif type(source) is RevokedV3RecoverySourceV1:
            expected_receipt_epoch = source.revocation_proof.result.previous_epoch
        else:
            raise _error(RecoveryExecutionErrorCode.TRIGGER_INVALID)
        try:
            locator = create_recovery_apply_receipt_locator(
                receipt,
                storage_revision=stored.revision,
            )
            expected_prestate = recovery_target_configuration_sha256(
                root,
                stable_percent=90,
                candidate_percent=10,
            )
        except (TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.SOURCE_RECEIPT_INVALID) from None
        if (
            locator != command.verified_apply_receipt
            or receipt.target != self._target
            or receipt.root_id != command.root_id
            or receipt.root_sha256 != command.expected_root_sha256
            or receipt.epoch != expected_receipt_epoch
            or receipt.action is not CapabilityAction.APPLY_CANARY
            or receipt.outcome is not ReceiptOutcome.VERIFIED
            or receipt.reason_code is not None
            or receipt.expected_poststate_sha256 != expected_prestate
            or receipt.plan_sha256 != canonical_sha256(root.content.rollout_plan)
            or receipt.provider_etag != root.content.stable_snapshot.provider_etag
            or receipt.observed_etag is None
            or receipt.observed_authority_epoch != expected_receipt_epoch
            or _seconds(receipt.updated_at) > int(now.timestamp())
        ):
            raise _error(RecoveryExecutionErrorCode.SOURCE_RECEIPT_INVALID)


class CoordinatorRecoveryCapabilityClient:
    """Request one recovery-only capability from the fixed issuer once."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.ISSUER
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._transport = transport

    async def issue(
        self,
        command: RecoveryCommandV2,
        authorization: RecoveryAuthorizationV1,
    ) -> RecoveryCapabilityIssuanceResultV2:
        if (
            type(command) is not RecoveryCommandV2
            or type(authorization) is not RecoveryAuthorizationV1
            or authorization.root_id != command.root_id
            or authorization.root_sha256 != command.expected_root_sha256
            or authorization.epoch != command.expected_epoch
            or authorization.source != command.source
            or authorization.verified_apply_receipt
            != command.verified_apply_receipt
        ):
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        try:
            issuance = RecoveryCapabilityIssuanceCommandV2(
                schema_version=RECOVERY_CAPABILITY_ISSUANCE_COMMAND_V2,
                root_id=command.root_id,
                expected_root_sha256=command.expected_root_sha256,
                expected_epoch=command.expected_epoch,
                request_id=command.request_id,
                idempotency_key=command.idempotency_key,
                scheduled_at=command.scheduled_at,
                authorization=authorization,
                authorization_sha256=canonical_sha256(authorization),
            )
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(issuance),
            )
        except asyncio.CancelledError:
            raise
        except RecoveryExecutionError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.TRANSPORT_UNAVAILABLE) from None
        try:
            result = decode_contract(body, RecoveryCapabilityIssuanceResultV2)
        except (ContractError, TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.RESPONSE_INVALID) from None
        if not _issuance_matches(
            result,
            issuance,
            project_id=self._route.project_id,
        ):
            raise _error(RecoveryExecutionErrorCode.RESPONSE_INVALID)
        return result


class RecoveryRolloutCoordinator:
    """Issue, seal, and enqueue the single root-owned recovery attempt."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authorization_resolver: RecoveryAuthorizationResolver,
        capability_client: RecoveryCapabilityClient,
        dispatch_store: RecoveryDispatchStore,
        task_dispatcher: RecoveryTaskDispatcher,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or target.region != "us-central1"
            or target.environment != "nonprod"
            or target.service_name != "controlgraph-reference-target"
            or "reconcile" in target.project_id.lower()
            or not isinstance(
                authorization_resolver,
                RecoveryAuthorizationResolver,
            )
            or not isinstance(capability_client, RecoveryCapabilityClient)
            or not isinstance(dispatch_store, RecoveryDispatchStore)
            or dispatch_store.target != target
            or not isinstance(task_dispatcher, RecoveryTaskDispatcher)
            or (clock is not None and not callable(clock))
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._authorization_resolver = authorization_resolver
        self._capability_client = capability_client
        self._dispatch_store = dispatch_store
        self._task_dispatcher = task_dispatcher
        self._clock = clock or _now

    async def dispatch(
        self,
        command: RecoveryCommandV2,
    ) -> RecoveryDispatchResultV2:
        if type(command) is not RecoveryCommandV2:
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        intent = await self._owned_intent(command)
        existing = await self._read_dispatch(command)
        if existing is not None:
            result = self._adopt_existing(existing, command)
            if result is not None:
                return result
            prepared = existing
        else:
            prepared = await self._prepare(intent)
            result = self._adopt_existing(prepared, command)
            if result is not None:
                return result

        dispatch_time = _utc(self._clock())
        try:
            addressed = self._task_dispatcher.prepare(
                prepared.value.task,
                now=dispatch_time,
            )
            if addressed.name != prepared.value.task_name:
                raise ValueError("recovery task address changed")
            started_value = RecoveryDispatchRecordV2.model_validate(
                {
                    **prepared.value.model_dump(mode="python"),
                    "state": RecoveryDispatchState.ENQUEUE_STARTED,
                    "enqueue_started_at": _utc_text(dispatch_time),
                }
            )
        except Exception:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None

        try:
            direct_start = await self._dispatch_store.begin_recovery_enqueue(
                prepared,
                started_value,
            )
            started = direct_start.dispatch
        except asyncio.CancelledError:
            raise
        except (AuthorityStoreConflict, AuthorityStoreOutcomeUnknown):
            replay = await self._read_after_transition(command)
            result = self._adopt_existing(replay, command)
            if result is not None:
                return result
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreCorruptRecord:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreError:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        except Exception:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None

        try:
            dispatched = await self._task_dispatcher.dispatch_prepared_recovery(
                addressed,
                permit=direct_start.permit,
                now=dispatch_time,
            )
        except Exception:
            dispatched = TaskEnqueueResult(
                task_name=started.value.task_name,
                disposition=TaskEnqueueDisposition.AMBIGUOUS,
            )
        if (
            type(dispatched) is not TaskEnqueueResult
            or type(dispatched.disposition) is not TaskEnqueueDisposition
            or dispatched.task_name != started.value.task_name
        ):
            dispatched = TaskEnqueueResult(
                task_name=started.value.task_name,
                disposition=TaskEnqueueDisposition.AMBIGUOUS,
            )
        terminal_time = _utc(self._clock())
        try:
            result = _recovery_result(started.value, dispatched)
            terminal_value = RecoveryDispatchRecordV2.model_validate(
                {
                    **started.value.model_dump(mode="python"),
                    "state": RecoveryDispatchState(dispatched.disposition.value),
                    "terminal_at": _utc_text(terminal_time),
                    "result": result,
                }
            )
        except Exception:
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        try:
            terminal = await self._dispatch_store.compare_and_set_recovery_dispatch(
                started,
                terminal_value,
            )
        except asyncio.CancelledError:
            raise
        except (AuthorityStoreConflict, AuthorityStoreOutcomeUnknown):
            replay = await self._read_after_transition(command)
            result = self._adopt_existing(replay, command)
            if result is not None:
                return result
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreCorruptRecord:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except Exception:
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        adopted = self._adopt_existing(terminal, command)
        if adopted is None:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID)
        return adopted

    async def _owned_intent(
        self,
        command: RecoveryCommandV2,
    ) -> StoredRecord[RecoveryIntentV1]:
        try:
            current = await self._dispatch_store.read_recovery_intent(
                command.expected_root_sha256
            )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except Exception:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        if current is not None:
            return self._validate_intent(current, command)
        if type(command.source) is UnhealthyRecoverySourceV1:
            # V3 intent must have been created in the terminal health append.
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID)
        if type(command.source) not in (
            RevokedV2RecoverySourceV1,
            RevokedV3RecoverySourceV1,
        ):
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        try:
            proposed = create_recovery_intent(
                command,
                created_at=command.source.triggered_at,
            )
            stored = await self._dispatch_store.create_or_adopt_recovery_intent(
                proposed
            )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raise _error(RecoveryExecutionErrorCode.IDENTITY_CONFLICT) from None
        except AuthorityStoreOutcomeUnknown:
            try:
                uncertain = await self._dispatch_store.read_recovery_intent(
                    command.expected_root_sha256
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
            if uncertain is None:
                raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
            return self._validate_intent(uncertain, command)
        except AuthorityStoreCorruptRecord:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreError:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        except (TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED) from None
        except Exception:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        return self._validate_intent(stored, command)

    def _validate_intent(
        self,
        stored: StoredRecord[RecoveryIntentV1],
        command: RecoveryCommandV2,
    ) -> StoredRecord[RecoveryIntentV1]:
        if (
            type(stored) is not StoredRecord
            or type(stored.value) is not RecoveryIntentV1
            or stored.revision != 0
            or stored.value.command != command
            or stored.value.command_sha256 != recovery_command_sha256(command)
            or stored.value.root_sha256 != command.expected_root_sha256
            or stored.value.command.source.target != self._target
        ):
            raise _error(RecoveryExecutionErrorCode.IDENTITY_CONFLICT)
        return stored

    async def _prepare(
        self,
        intent: StoredRecord[RecoveryIntentV1],
    ) -> StoredRecord[RecoveryDispatchRecordV2]:
        command = intent.value.command
        prepared_time = _utc(self._clock())
        try:
            authorization = await self._authorization_resolver.resolve(
                command,
                now=prepared_time,
            )
            issuance = await self._capability_client.issue(
                command,
                authorization,
            )
        except asyncio.CancelledError:
            raise
        except RecoveryExecutionError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.ISSUANCE_DENIED) from None
        if not _issuance_matches_command(
            issuance,
            command,
            authorization=authorization,
            project_id=self._target.project_id,
        ):
            raise _error(RecoveryExecutionErrorCode.ISSUANCE_DENIED)
        capability = issuance.capability
        claims = capability.claims
        try:
            mutation = RecoveryMutationIntentV2(
                schema_version=RECOVERY_MUTATION_INTENT_V2,
                request_id=authorization.request_id,
                idempotency_key=authorization.idempotency_key,
                target=authorization.target,
                root_schema_version=authorization.root_schema_version,
                root_id=authorization.root_id,
                root_sha256=authorization.root_sha256,
                epoch=authorization.epoch,
                action=CapabilityAction.RECOVER_STABLE,
                stable_revision=authorization.stable_revision,
                stable_revision_configuration_sha256=(
                    authorization.stable_revision_configuration_sha256
                ),
                candidate_revision=authorization.candidate_revision,
                candidate_revision_configuration_sha256=(
                    authorization.candidate_revision_configuration_sha256
                ),
                stable_percent=100,
                candidate_percent=0,
                concurrency=authorization.concurrency,
                plan_sha256=authorization.plan_sha256,
                stable_snapshot_sha256=authorization.stable_snapshot_sha256,
                provider_etag=authorization.current_provider_etag,
                capability_id=authorization.capability_id,
                recovery_authorization_sha256=canonical_sha256(authorization),
                verified_apply_receipt=authorization.verified_apply_receipt,
                source_receipt_sha256=authorization.source_receipt_sha256,
                source_receipt_storage_revision=(
                    authorization.source_receipt_storage_revision
                ),
                source=authorization.source,
                trigger_proof_sha256=authorization.trigger_proof_sha256,
                prestate_attestation_sha256=(
                    authorization.prestate_attestation_sha256
                ),
                expected_prestate_sha256=authorization.expected_prestate_sha256,
                desired_poststate_sha256=authorization.desired_poststate_sha256,
                proof_valid_until=authorization.proof_valid_until,
                authorization=authorization,
            )
            task = RecoveryTaskRequestV2(
                schema_version=RECOVERY_TASK_REQUEST_V2,
                task_id=f"task-{capability.claims_sha256}",
                queue_region="us-central1",
                handler_audience=claims.audience,
                scheduled_at=claims.not_before,
                expires_at=claims.expires_at,
                capability=capability,
                intent=mutation,
            )
            addressed = self._task_dispatcher.prepare(task, now=prepared_time)
            command_digest = recovery_command_sha256(command)
            prepared_value = RecoveryDispatchRecordV2(
                schema_version=RECOVERY_DISPATCH_RECORD_V2,
                dispatch_id=recovery_dispatch_id(command_digest),
                command_sha256=command_digest,
                recovery_authorization_sha256=canonical_sha256(authorization),
                capability_id=authorization.capability_id,
                request_id=authorization.request_id,
                idempotency_key=authorization.idempotency_key,
                target=authorization.target,
                root_id=authorization.root_id,
                root_sha256=authorization.root_sha256,
                epoch=authorization.epoch,
                scheduled_at=authorization.scheduled_at,
                source_receipt_sha256=authorization.source_receipt_sha256,
                trigger_proof_sha256=authorization.trigger_proof_sha256,
                prestate_attestation_sha256=(
                    authorization.prestate_attestation_sha256
                ),
                task_sha256=canonical_sha256(task),
                task_name=addressed.name,
                task=task,
                state=RecoveryDispatchState.PREPARED,
                prepared_at=_utc_text(prepared_time),
                enqueue_started_at=None,
                terminal_at=None,
                result=None,
            )
        except Exception:
            raise _error(RecoveryExecutionErrorCode.ISSUANCE_DENIED) from None
        try:
            return await self._dispatch_store.prepare_or_adopt_recovery_dispatch(
                intent,
                prepared_value,
            )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raise _error(RecoveryExecutionErrorCode.IDENTITY_CONFLICT) from None
        except AuthorityStoreCorruptRecord:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreOutcomeUnknown:
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreError:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        except Exception:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None

    async def _read_dispatch(
        self,
        command: RecoveryCommandV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2] | None:
        try:
            return await self._dispatch_store.read_recovery_dispatch(command)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raise _error(RecoveryExecutionErrorCode.IDENTITY_CONFLICT) from None
        except AuthorityStoreCorruptRecord:
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreOutcomeUnknown:
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreError:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        except Exception:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None

    async def _read_after_transition(
        self,
        command: RecoveryCommandV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2]:
        try:
            current = await self._read_dispatch(command)
        except RecoveryExecutionError as error:
            if error.code in {
                RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID,
                RecoveryExecutionErrorCode.IDENTITY_CONFLICT,
            }:
                raise
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN) from None
        if current is None:
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN)
        return current

    def _adopt_existing(
        self,
        stored: StoredRecord[RecoveryDispatchRecordV2],
        command: RecoveryCommandV2,
    ) -> RecoveryDispatchResultV2 | None:
        expected_revisions = {
            RecoveryDispatchState.PREPARED: frozenset({0}),
            RecoveryDispatchState.ENQUEUE_STARTED: frozenset({1}),
            RecoveryDispatchState.CREATED: frozenset({2}),
            RecoveryDispatchState.DUPLICATE: frozenset({2}),
            RecoveryDispatchState.AMBIGUOUS: frozenset({2, 3}),
        }
        if (
            type(stored) is not StoredRecord
            or type(stored.value) is not RecoveryDispatchRecordV2
            or stored.value.target != self._target
            or stored.revision not in expected_revisions.get(stored.value.state, frozenset())
            or stored.value.command_sha256 != recovery_command_sha256(command)
            or stored.value.task.intent.authorization.source != command.source
        ):
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID)
        if stored.value.state is RecoveryDispatchState.PREPARED:
            return None
        if stored.value.state is RecoveryDispatchState.ENQUEUE_STARTED:
            raise _error(RecoveryExecutionErrorCode.OUTCOME_UNKNOWN)
        result = stored.value.result
        if not _result_matches_command(
            result,
            command,
            project_id=self._target.project_id,
        ):
            raise _error(RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID)
        return cast(RecoveryDispatchResultV2, result)


class ApiRecoveryClient:
    """Forward only an explicitly confirmed revoked-root operator recovery."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        authentication_policy: RouteAuthenticationPolicy,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.API
            or route.service_role is not ServiceRole.COORDINATOR
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.API
            or authentication_policy.caller.role is not CallerRole.OPERATOR
            or authentication_policy.project_id != route.project_id
            or authentication_policy.project_number != route.project_number
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._authentication_policy = authentication_policy
        self._transport = transport

    async def dispatch(
        self,
        command: RecoveryCommandV2,
        principal: AuthenticationContext,
    ) -> RecoveryDispatchResultV2:
        if (
            type(command) is not RecoveryCommandV2
            or type(command.source)
            not in (RevokedV2RecoverySourceV1, RevokedV3RecoverySourceV1)
        ):
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        if not _context_matches_policy(
            principal,
            self._authentication_policy,
            role=CallerRole.OPERATOR,
        ):
            raise _error(RecoveryExecutionErrorCode.OPERATOR_DENIED)
        try:
            invocation = RecoveryInvocationV2(
                schema_version=RECOVERY_INVOCATION_V2,
                command=command,
                operator_identity=principal.email,
                operator_subject=principal.subject,
                operator_issuer=cast(
                    Literal[
                        "accounts.google.com",
                        "https://accounts.google.com",
                    ],
                    principal.issuer,
                ),
                operator_audience=principal.audience,
                operator_issued_at=principal.issued_at,
                operator_expires_at=principal.expires_at,
            )
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
        except asyncio.CancelledError:
            raise
        except RecoveryExecutionError:
            raise
        except (TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.OPERATOR_DENIED) from None
        except Exception:
            raise _error(RecoveryExecutionErrorCode.TRANSPORT_UNAVAILABLE) from None
        try:
            result = decode_contract(body, RecoveryDispatchResultV2)
        except (ContractError, TypeError, ValueError):
            raise _error(RecoveryExecutionErrorCode.RESPONSE_INVALID) from None
        if not _result_matches_command(
            result,
            command,
            project_id=self._route.project_id,
        ):
            raise _error(RecoveryExecutionErrorCode.RESPONSE_INVALID)
        return result


class CoordinatorRecoveryRelay:
    """Authenticate API plus propagated operator before revoked-root recovery."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        coordinator: RecoveryCoordinator,
    ) -> None:
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.COORDINATOR
            or authentication_policy.caller.role is not CallerRole.API
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.project_id != authentication_policy.project_id
            or operator_policy.project_number
            != authentication_policy.project_number
            or not isinstance(coordinator, RecoveryCoordinator)
        ):
            raise _error(RecoveryExecutionErrorCode.CONFIGURATION_INVALID)
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._coordinator = coordinator

    async def dispatch(
        self,
        invocation: RecoveryInvocationV2,
        caller: AuthenticationContext,
    ) -> RecoveryDispatchResultV2:
        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise _error(RecoveryExecutionErrorCode.CALLER_DENIED)
        if type(invocation) is not RecoveryInvocationV2:
            raise _error(RecoveryExecutionErrorCode.COMMAND_DENIED)
        propagated = AuthenticationContext(
            role=CallerRole.OPERATOR,
            email=invocation.operator_identity,
            subject=invocation.operator_subject,
            issuer=invocation.operator_issuer,
            audience=invocation.operator_audience,
            issued_at=invocation.operator_issued_at,
            expires_at=invocation.operator_expires_at,
        )
        if not _context_matches_policy(
            propagated,
            self._operator_policy,
            role=CallerRole.OPERATOR,
        ):
            raise _error(RecoveryExecutionErrorCode.OPERATOR_DENIED)
        try:
            result = await self._coordinator.dispatch(invocation.command)
        except asyncio.CancelledError:
            raise
        except RecoveryExecutionError:
            raise
        except Exception:
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE) from None
        if not _result_matches_command(
            result,
            invocation.command,
            project_id=self._authentication_policy.project_id,
        ):
            raise _error(RecoveryExecutionErrorCode.DISPATCH_UNAVAILABLE)
        return result


def _recovery_result(
    record: RecoveryDispatchRecordV2,
    dispatched: TaskEnqueueResult,
) -> RecoveryDispatchResultV2:
    task = record.task
    authorization = task.intent.authorization
    return RecoveryDispatchResultV2(
        schema_version=RECOVERY_DISPATCH_RESULT_V2,
        request_id=authorization.request_id,
        idempotency_key=authorization.idempotency_key,
        target=authorization.target,
        root_schema_version=authorization.root_schema_version,
        root_id=authorization.root_id,
        root_sha256=authorization.root_sha256,
        epoch=authorization.epoch,
        stable_revision=authorization.stable_revision,
        stable_revision_configuration_sha256=(
            authorization.stable_revision_configuration_sha256
        ),
        candidate_revision=authorization.candidate_revision,
        candidate_revision_configuration_sha256=(
            authorization.candidate_revision_configuration_sha256
        ),
        stable_percent=100,
        candidate_percent=0,
        concurrency=authorization.concurrency,
        provider_etag=authorization.current_provider_etag,
        verified_apply_receipt=authorization.verified_apply_receipt,
        source_receipt_sha256=authorization.source_receipt_sha256,
        trigger_basis=authorization.source.basis,
        trigger_proof_sha256=authorization.trigger_proof_sha256,
        prestate_attestation_sha256=authorization.prestate_attestation_sha256,
        expected_prestate_sha256=authorization.expected_prestate_sha256,
        desired_poststate_sha256=authorization.desired_poststate_sha256,
        proof_valid_until=authorization.proof_valid_until,
        recovery_authorization_sha256=canonical_sha256(authorization),
        capability_id=authorization.capability_id,
        capability_sha256=canonical_sha256(task.capability),
        task_id=task.task_id,
        task_name=dispatched.task_name,
        enqueue_disposition=dispatched.disposition.value,
        scheduled_at=task.scheduled_at,
        expires_at=task.expires_at,
    )


def _issuance_matches(
    result: object,
    command: RecoveryCapabilityIssuanceCommandV2,
    *,
    project_id: str,
) -> bool:
    if (
        type(result) is not RecoveryCapabilityIssuanceResultV2
        or result.issuance_command != command
        or result.issuance_command_sha256
        != recovery_capability_issuance_command_sha256(command)
        or result.authorization_sha256 != command.authorization_sha256
    ):
        return False
    authorization = command.authorization
    claims = result.capability.claims
    return (
        claims.target.project_id == project_id
        and claims.action is CapabilityAction.RECOVER_STABLE
        and claims.capability_id == authorization.capability_id
        and claims.subject == authorization.recovery_identity
        and claims.audience == authorization.recovery_audience
        and claims.root_id == authorization.root_id
        and claims.root_sha256 == authorization.root_sha256
        and claims.epoch == authorization.epoch
        and claims.request_id == authorization.request_id
        and claims.idempotency_key == authorization.idempotency_key
        and claims.concurrency == authorization.concurrency
        and claims.stable_percent == 100
        and claims.candidate_percent == 0
        and claims.parent_capability_sha256 is None
    )


def _issuance_matches_command(
    result: object,
    command: RecoveryCommandV2,
    *,
    authorization: RecoveryAuthorizationV1,
    project_id: str,
) -> bool:
    return (
        type(result) is RecoveryCapabilityIssuanceResultV2
        and result.issuance_command.authorization == authorization
        and result.issuance_command.root_id == command.root_id
        and result.issuance_command.expected_root_sha256
        == command.expected_root_sha256
        and result.issuance_command.expected_epoch == command.expected_epoch
        and result.issuance_command.request_id == command.request_id
        and result.issuance_command.idempotency_key == command.idempotency_key
        and result.issuance_command.scheduled_at == command.scheduled_at
        and authorization.source == command.source
        and authorization.verified_apply_receipt
        == command.verified_apply_receipt
        and _issuance_matches(
            result,
            result.issuance_command,
            project_id=project_id,
        )
    )


def _result_matches_command(
    result: object,
    command: RecoveryCommandV2,
    *,
    project_id: str,
) -> bool:
    return (
        type(result) is RecoveryDispatchResultV2
        and result.request_id == command.request_id
        and result.idempotency_key == command.idempotency_key
        and result.root_id == command.root_id
        and result.root_sha256 == command.expected_root_sha256
        and result.epoch == command.expected_epoch
        and result.target == command.source.target
        and result.target.project_id == project_id
        and result.trigger_basis is command.source.basis
        and result.trigger_proof_sha256
        == recovery_trigger_proof_sha256(command.source)
        and result.verified_apply_receipt == command.verified_apply_receipt
        and result.source_receipt_sha256
        == command.verified_apply_receipt.receipt_sha256
        and result.stable_percent == 100
        and result.candidate_percent == 0
        and result.scheduled_at == command.scheduled_at
        and result.scheduled_at < result.expires_at <= result.proof_valid_until
    )


__all__ = [
    "RECOVERY_PRESTATE_ATTESTATION_PATH",
    "ApiRecoveryClient",
    "CoordinatorRecoveryCapabilityClient",
    "CoordinatorRecoveryPrestateClient",
    "CoordinatorRecoveryRelay",
    "RecoveryAuthorizationResolver",
    "RecoveryCapabilityClient",
    "RecoveryCoordinator",
    "RecoveryExecutionError",
    "RecoveryExecutionErrorCode",
    "RecoveryHealthChainReader",
    "RecoveryPrestateAttestationVerifier",
    "RecoveryPrestateEvaluator",
    "RecoveryPrestateSigningService",
    "RecoveryReceiptReader",
    "RecoveryRolloutCoordinator",
    "StoredRecoveryAuthorizationResolver",
    "VerifierRecoveryPrestateAttestationClient",
    "VerifierRecoveryPrestateService",
]
