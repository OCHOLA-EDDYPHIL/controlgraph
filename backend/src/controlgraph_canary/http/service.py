"""Identity-safe private service surfaces with closed protected handlers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import uuid
from collections.abc import Awaitable, Callable
from typing import Final, cast

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from controlgraph_canary import __version__
from controlgraph_canary.application.authority_store import AuthorityStoreError
from controlgraph_canary.application.canary_execution import (
    ApiCanaryClient,
    CanaryExecutionError,
    CanaryExecutionErrorCode,
    CapabilityIssuanceService,
    CoordinatorCanaryRelay,
)
from controlgraph_canary.application.capability_verification import (
    CapabilityRequestVerifier,
    CapabilityVerificationError,
    VerifiedMutation,
)
from controlgraph_canary.application.evidence_signing import (
    EvidenceSigningError,
    EvidenceSigningErrorCode,
    EvidenceSigningService,
)
from controlgraph_canary.application.health_attestation import (
    HealthAttestationError,
    HealthAttestationErrorCode,
    HealthAttestationSigningService,
)
from controlgraph_canary.application.health_pipeline import (
    ApiHealthEvaluationClient,
    CoordinatorHealthEvaluationService,
    HealthPipelineError,
    HealthPipelineErrorCode,
    VerifierHealthEvaluationService,
)
from controlgraph_canary.application.identity import (
    CLASSIFICATION_EVIDENCE_PATH,
    HEALTH_ATTESTATION_PATH,
    INDEPENDENT_VERIFICATION_EVIDENCE_PATH,
    RECEIPT_AUTHORITY_PATH,
    RECOVERY_EXECUTION_FACADE_PATH,
    RECOVERY_PRESTATE_ATTESTATION_PATH,
    RECOVERY_RECEIPT_AUTHORITY_PATH,
    TIMELINE_RAW_EXPORT_PATH,
    TIMELINE_READ_PATH,
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
    IdentityAuthenticator,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.independent_verification import (
    IndependentVerificationError,
    IndependentVerificationErrorCode,
    IndependentVerificationService,
)
from controlgraph_canary.application.independent_verification_signing import (
    IndependentVerificationSigningService,
)
from controlgraph_canary.application.operator_observability import (
    ApiOperatorObservationClient,
    CoordinatorOperatorObservationRelay,
    OperatorObservationError,
    OperatorObservationErrorCode,
    StableSnapshotCaptureService,
    TargetTrafficObservationService,
)
from controlgraph_canary.application.promotion_execution import (
    ApiPromotionClient,
    CoordinatorPromotionRelay,
)
from controlgraph_canary.application.receipt_authority import ReceiptAuthorityService
from controlgraph_canary.application.recovery_abandonment import (
    RecoveryAbandonmentError,
)
from controlgraph_canary.application.recovery_abandonment_relay import (
    ApiRecoveryAbandonmentClient,
    CoordinatorRecoveryAbandonmentRelay,
)
from controlgraph_canary.application.recovery_execution import (
    ApiRecoveryClient,
    CoordinatorRecoveryRelay,
    RecoveryExecutionError,
    RecoveryExecutionErrorCode,
    RecoveryPrestateSigningService,
    VerifierRecoveryPrestateService,
)
from controlgraph_canary.application.revocation import EpochRevocationError
from controlgraph_canary.application.revocation_relay import (
    ApiEpochRevocationClient,
    CoordinatorEpochRevocationRelay,
)
from controlgraph_canary.application.root_relay import (
    ApiRootCreationClient,
    CoordinatorRootCreationRelay,
    RootRelayError,
    RootRelayErrorCode,
)
from controlgraph_canary.application.root_trust import (
    RootPreflightError,
    RootPreflightErrorCode,
    RootPreflightService,
)
from controlgraph_canary.application.service_claim_classification import (
    ServiceClaimClassificationError,
    ServiceClaimClassificationErrorCode,
    ServiceClaimClassificationService,
)
from controlgraph_canary.application.service_claim_classification_signing import (
    ClassificationEvidenceSigningService,
)
from controlgraph_canary.application.service_claim_release import (
    ServiceClaimReleaseError,
)
from controlgraph_canary.application.service_claim_release_relay import (
    ApiServiceClaimReleaseClient,
    CoordinatorServiceClaimReleaseRelay,
)
from controlgraph_canary.application.timeline import (
    TimelineRawExportError,
    TimelineRawExportErrorCode,
    TimelineRawExportGrant,
    TimelineRawExportService,
    TimelineReadError,
    TimelineReadErrorCode,
    TimelineReadGrant,
    TimelineReadService,
)
from controlgraph_canary.application.timeline_recording import TimelineRecorder
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.canary_execution import (
    ApplyCanaryCommandV1,
    ApplyCanaryInvocationV1,
    CapabilityIssuanceCommandV1,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    ContractErrorCode,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.health_execution import (
    HealthAttestationSigningRequestV1,
)
from controlgraph_canary.contracts.health_pipeline import (
    HealthEvaluationCommandV1,
    HealthEvaluationInvocationV1,
    VerifierHealthEvaluationRequestV1,
)
from controlgraph_canary.contracts.independent_verification import (
    IndependentVerificationInvocationV1,
    IndependentVerificationKind,
    IndependentVerificationSigningRequestV1,
)
from controlgraph_canary.contracts.models import EvidenceEvent, ReasonCode
from controlgraph_canary.contracts.operator_observability import (
    ExecutionReceiptReadCommandV1,
    ExecutionReceiptReadInvocationV1,
    StableSnapshotCaptureCommandV1,
    StableSnapshotCaptureInvocationV1,
    StableSnapshotCaptureRequestV1,
    TargetTrafficReadCommandV1,
    TargetTrafficReadInvocationV1,
    TargetTrafficReadRequestV1,
)
from controlgraph_canary.contracts.promotion_execution import (
    PromotionCapabilityIssuanceCommandV2,
    PromotionCommandV2,
    PromotionInvocationV2,
)
from controlgraph_canary.contracts.receipt_authority import (
    ReceiptAuthorityOperation,
    ReceiptAuthorityResponseV1,
)
from controlgraph_canary.contracts.recovery_abandonment import (
    RECOVERY_ABANDONMENT_RELAY_RESPONSE_V1,
    RecoveryAbandonmentClassificationRequestV1,
    RecoveryAbandonmentClassificationSigningRequestV1,
    RecoveryAbandonmentCommandV1,
    RecoveryAbandonmentFailureCode,
    RecoveryAbandonmentInvocationV1,
    RecoveryAbandonmentRelayResponseV1,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryCapabilityIssuanceCommandV2,
    RecoveryCommandV2,
    RecoveryInvocationV2,
    RecoveryPrestateRequestV1,
    RecoveryPrestateSigningRequestV1,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_PROOF_RELAY_RESPONSE_V1,
    EPOCH_REVOCATION_RELAY_RESPONSE_V1,
    EpochRevocationCommandV1,
    EpochRevocationFailureCode,
    EpochRevocationInvocationV1,
    EpochRevocationProofCommandV1,
    EpochRevocationProofInvocationV1,
    EpochRevocationProofRelayResponseV1,
    EpochRevocationRelayResponseV1,
)
from controlgraph_canary.contracts.root_creation import RootCreationCommandV1
from controlgraph_canary.contracts.root_relay import RootCreationInvocationV1
from controlgraph_canary.contracts.root_trust import RootPreflightRequestV1
from controlgraph_canary.contracts.service_claim_release import (
    SERVICE_CLAIM_RELEASE_RELAY_RESPONSE_V1,
    ServiceClaimClassificationRequestV1,
    ServiceClaimClassificationSigningRequestV1,
    ServiceClaimReleaseCommandV1,
    ServiceClaimReleaseFailureCode,
    ServiceClaimReleaseInvocationV1,
    ServiceClaimReleaseRelayResponseV1,
)
from controlgraph_canary.contracts.timeline import (
    TIMELINE_PAGE_COMMAND_V1,
    TIMELINE_RAW_EXPORT_COMMAND_V1,
    TimelineAudience,
    TimelinePageCommandV1,
    TimelineRawExportCommandV1,
)
from controlgraph_canary.http.identity_headers import authentication_header

PRODUCT_CONTRACT_VERSION: Final = "controlgraph.contract/v1"
SERVICE_SHELL_VERSION: Final = "controlgraph.service-shell/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_UINT = re.compile(r"^(?:0|[1-9][0-9]{0,15})$")
_RAW_EXPORT_CONFIRMATION = "EXPORT_RESTRICTED_EVIDENCE_V1"


class ServiceHealth(BaseModel):
    """Safe liveness metadata that carries no caller identity."""

    model_config = ConfigDict(frozen=True)

    status: str
    service_role: ServiceRole
    correlation_id: str


class ServiceMetadata(BaseModel):
    """Safe deployment contract metadata for an authenticated probe."""

    model_config = ConfigDict(frozen=True)

    contract_version: str
    service_shell_version: str
    application_version: str
    service_role: ServiceRole
    build_digest: str | None
    mutation_enabled: bool
    correlation_id: str


class DisabledWork(BaseModel):
    """Stable fail-closed response when no protected handler is composed."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class AuthenticationDenied(BaseModel):
    """Credential-free authentication denial returned before protected work."""

    model_config = ConfigDict(frozen=True)

    code: AuthenticationDenialCode
    correlation_id: str


class CapabilityDenied(BaseModel):
    """Payload-free capability denial returned before protected handler entry."""

    model_config = ConfigDict(frozen=True)

    code: ReasonCode
    correlation_id: str


class EvidenceSigningDenied(BaseModel):
    """Payload-free evidence signing failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class RootPreflightDenied(BaseModel):
    """Payload-free verifier preflight failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class RootCreationDenied(BaseModel):
    """Payload-free root-creation relay failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class CanaryExecutionDenied(BaseModel):
    """Payload-free issuance or dispatch failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class EpochRevocationDenied(BaseModel):
    """Payload-free manual revocation failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class ServiceClaimReleaseDenied(BaseModel):
    """Payload-free service-claim release failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class RecoveryAbandonmentDenied(BaseModel):
    """Payload-free ambiguous-recovery abandonment failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class ServiceClaimClassificationDenied(BaseModel):
    """Payload-free verifier classification failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class IndependentVerificationDenied(BaseModel):
    """Payload-free independent verification failure."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class OperatorObservationDenied(BaseModel):
    """Payload-free stable denial for one bounded operator observation."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class TimelineDenied(BaseModel):
    """Payload-free timeline or restricted-export denial."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


class HealthPipelineDenied(BaseModel):
    """Payload-free deterministic health-pipeline denial."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


type VerifiedTaskHandler = Callable[[VerifiedMutation], Awaitable[Response]]
type RecoveryExecutorFacadeHandler = Callable[[bytes, AuthenticationContext], Awaitable[bytes]]


def create_service_app(
    role: ServiceRole,
    *,
    build_digest: str | None = None,
    authenticator: IdentityAuthenticator | None = None,
    authentication_policy: RouteAuthenticationPolicy | None = None,
    capability_verifier: CapabilityRequestVerifier | None = None,
    verified_task_handler: VerifiedTaskHandler | None = None,
    evidence_signing_service: EvidenceSigningService | None = None,
    root_preflight_service: RootPreflightService | None = None,
    api_root_creation_client: ApiRootCreationClient | None = None,
    coordinator_root_creation_relay: CoordinatorRootCreationRelay | None = None,
    stable_snapshot_capture_service: StableSnapshotCaptureService | None = None,
    target_traffic_observation_service: TargetTrafficObservationService | None = None,
    api_operator_observation_client: ApiOperatorObservationClient | None = None,
    coordinator_operator_observation_relay: (CoordinatorOperatorObservationRelay | None) = None,
    api_canary_client: ApiCanaryClient | None = None,
    coordinator_canary_relay: CoordinatorCanaryRelay | None = None,
    api_promotion_client: ApiPromotionClient | None = None,
    coordinator_promotion_relay: CoordinatorPromotionRelay | None = None,
    api_health_evaluation_client: ApiHealthEvaluationClient | None = None,
    coordinator_health_evaluation_service: (CoordinatorHealthEvaluationService | None) = None,
    verifier_health_evaluation_service: VerifierHealthEvaluationService | None = None,
    api_recovery_client: ApiRecoveryClient | None = None,
    coordinator_recovery_relay: CoordinatorRecoveryRelay | None = None,
    verifier_recovery_prestate_service: VerifierRecoveryPrestateService | None = None,
    api_epoch_revocation_client: ApiEpochRevocationClient | None = None,
    coordinator_epoch_revocation_relay: CoordinatorEpochRevocationRelay | None = None,
    api_service_claim_release_client: ApiServiceClaimReleaseClient | None = None,
    coordinator_service_claim_release_relay: (CoordinatorServiceClaimReleaseRelay | None) = None,
    api_recovery_abandonment_client: ApiRecoveryAbandonmentClient | None = None,
    coordinator_recovery_abandonment_relay: (CoordinatorRecoveryAbandonmentRelay | None) = None,
    service_claim_classification_service: (ServiceClaimClassificationService | None) = None,
    independent_verification_service: IndependentVerificationService | None = None,
    classification_evidence_signing_service: (ClassificationEvidenceSigningService | None) = None,
    classification_evidence_authentication_policy: (RouteAuthenticationPolicy | None) = None,
    independent_verification_signing_service: (
        IndependentVerificationSigningService | None
    ) = None,
    independent_verification_evidence_authentication_policy: (
        RouteAuthenticationPolicy | None
    ) = None,
    health_attestation_signing_service: HealthAttestationSigningService | None = None,
    health_attestation_authentication_policy: RouteAuthenticationPolicy | None = None,
    recovery_prestate_signing_service: RecoveryPrestateSigningService | None = None,
    recovery_prestate_authentication_policy: RouteAuthenticationPolicy | None = None,
    capability_issuance_service: CapabilityIssuanceService | None = None,
    receipt_authority_service: ReceiptAuthorityService | None = None,
    receipt_authority_authentication_policy: RouteAuthenticationPolicy | None = None,
    recovery_receipt_authority_authentication_policy: (RouteAuthenticationPolicy | None) = None,
    recovery_executor_facade_handler: RecoveryExecutorFacadeHandler | None = None,
    recovery_executor_facade_authentication_policy: (RouteAuthenticationPolicy | None) = None,
    timeline_read_service: TimelineReadService | None = None,
    timeline_read_authentication_policy: RouteAuthenticationPolicy | None = None,
    timeline_raw_export_service: TimelineRawExportService | None = None,
    timeline_raw_export_authentication_policy: RouteAuthenticationPolicy | None = None,
    timeline_recorder: TimelineRecorder | None = None,
    mutation_enabled: bool = False,
) -> FastAPI:
    """Create one authenticated role shell with explicitly bounded work."""

    if type(role) is not ServiceRole:
        raise ValueError("service role is invalid")
    if (authenticator is None) != (authentication_policy is None):
        raise ValueError("authenticator and authentication policy must be configured together")
    if authentication_policy is not None and authentication_policy.service_role is not role:
        raise ValueError("authentication policy does not match the service role")
    if verified_task_handler is not None and capability_verifier is None:
        raise ValueError("a protected task handler requires capability verification")
    if verified_task_handler is not None and not mutation_enabled:
        raise ValueError("a protected task handler requires mutation enablement")
    if mutation_enabled and (capability_verifier is None or verified_task_handler is None):
        raise ValueError("mutation enablement requires the complete protected task path")
    if (capability_verifier is not None or verified_task_handler is not None) and role not in {
        ServiceRole.EXECUTOR,
        ServiceRole.RECOVERY,
    }:
        raise ValueError("capability verification is limited to protected task routes")
    if evidence_signing_service is not None and role is not ServiceRole.EVIDENCE_WRITER:
        raise ValueError("evidence signing is limited to the evidence-writer route")
    if root_preflight_service is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("root preflight is limited to the verifier route")
    if api_root_creation_client is not None and role is not ServiceRole.API:
        raise ValueError("operator root creation is limited to the API route")
    if coordinator_root_creation_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("root creation coordination is limited to the coordinator route")
    if stable_snapshot_capture_service is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("stable snapshot capture is limited to the verifier route")
    if target_traffic_observation_service is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("target traffic observation is limited to the verifier route")
    if api_operator_observation_client is not None and role is not ServiceRole.API:
        raise ValueError("operator observations are limited to the API route")
    if coordinator_operator_observation_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("operator observation coordination is coordinator-limited")
    if api_canary_client is not None and role is not ServiceRole.API:
        raise ValueError("canary dispatch is limited to the API route")
    if coordinator_canary_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("canary coordination is limited to the coordinator route")
    if api_promotion_client is not None and role is not ServiceRole.API:
        raise ValueError("promotion dispatch is limited to the API route")
    if coordinator_promotion_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("promotion coordination is limited to the coordinator route")
    if api_health_evaluation_client is not None and role is not ServiceRole.API:
        raise ValueError("health evaluation is limited to the API route")
    if coordinator_health_evaluation_service is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("health evaluation coordination is coordinator-limited")
    if verifier_health_evaluation_service is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("health evaluation verification is verifier-limited")
    if api_recovery_client is not None and role is not ServiceRole.API:
        raise ValueError("operator recovery is limited to the API route")
    if coordinator_recovery_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("recovery coordination is coordinator-limited")
    if verifier_recovery_prestate_service is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("recovery prestate verification is verifier-limited")
    if api_epoch_revocation_client is not None and role is not ServiceRole.API:
        raise ValueError("manual revocation is limited to the API route")
    if coordinator_epoch_revocation_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("revocation coordination is limited to the coordinator route")
    if api_service_claim_release_client is not None and role is not ServiceRole.API:
        raise ValueError("service-claim release is limited to the API route")
    if coordinator_service_claim_release_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("claim release coordination is limited to the coordinator route")
    if api_recovery_abandonment_client is not None and role is not ServiceRole.API:
        raise ValueError("recovery abandonment is limited to the API route")
    if coordinator_recovery_abandonment_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("recovery abandonment coordination is coordinator-limited")
    if service_claim_classification_service is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("claim classification is limited to the verifier route")
    if independent_verification_service is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("independent verification is limited to the verifier route")
    if (classification_evidence_signing_service is None) != (
        classification_evidence_authentication_policy is None
    ):
        raise ValueError("classification evidence service and policy must be configured together")
    if classification_evidence_signing_service is not None and (
        role is not ServiceRole.EVIDENCE_WRITER
        or type(classification_evidence_authentication_policy) is not RouteAuthenticationPolicy
        or classification_evidence_authentication_policy.service_role
        is not ServiceRole.EVIDENCE_WRITER
        or classification_evidence_authentication_policy.path != CLASSIFICATION_EVIDENCE_PATH
        or classification_evidence_authentication_policy.caller.role is not CallerRole.VERIFIER
    ):
        raise ValueError("classification evidence is limited to the verifier-to-writer route")
    if (independent_verification_signing_service is None) != (
        independent_verification_evidence_authentication_policy is None
    ):
        raise ValueError(
            "independent verification evidence service and policy must be configured together"
        )
    if independent_verification_signing_service is not None and (
        role is not ServiceRole.EVIDENCE_WRITER
        or type(independent_verification_evidence_authentication_policy)
        is not RouteAuthenticationPolicy
        or independent_verification_evidence_authentication_policy.service_role
        is not ServiceRole.EVIDENCE_WRITER
        or independent_verification_evidence_authentication_policy.path
        != INDEPENDENT_VERIFICATION_EVIDENCE_PATH
        or independent_verification_evidence_authentication_policy.caller.role
        is not CallerRole.VERIFIER
    ):
        raise ValueError(
            "independent verification evidence is limited to the verifier-to-writer route"
        )
    if (health_attestation_signing_service is None) != (
        health_attestation_authentication_policy is None
    ):
        raise ValueError("health attestation service and policy must be configured together")
    if health_attestation_signing_service is not None and (
        role is not ServiceRole.EVIDENCE_WRITER
        or type(health_attestation_authentication_policy) is not RouteAuthenticationPolicy
        or health_attestation_authentication_policy.service_role is not ServiceRole.EVIDENCE_WRITER
        or health_attestation_authentication_policy.path != HEALTH_ATTESTATION_PATH
        or health_attestation_authentication_policy.caller.role is not CallerRole.VERIFIER
    ):
        raise ValueError("health attestation is limited to the verifier-to-writer route")
    if (recovery_prestate_signing_service is None) != (
        recovery_prestate_authentication_policy is None
    ):
        raise ValueError("recovery prestate service and policy must be configured together")
    if recovery_prestate_signing_service is not None and (
        role is not ServiceRole.EVIDENCE_WRITER
        or type(recovery_prestate_authentication_policy) is not RouteAuthenticationPolicy
        or recovery_prestate_authentication_policy.service_role is not ServiceRole.EVIDENCE_WRITER
        or recovery_prestate_authentication_policy.path != RECOVERY_PRESTATE_ATTESTATION_PATH
        or recovery_prestate_authentication_policy.caller.role is not CallerRole.VERIFIER
    ):
        raise ValueError("recovery prestate signing is limited to the verifier-to-writer route")
    if capability_issuance_service is not None and role is not ServiceRole.ISSUER:
        raise ValueError("capability issuance is limited to the issuer route")
    receipt_policies = (
        receipt_authority_authentication_policy,
        recovery_receipt_authority_authentication_policy,
    )
    if receipt_authority_service is None and any(policy is not None for policy in receipt_policies):
        raise ValueError("receipt authority policies require the service")
    if receipt_authority_service is not None and all(policy is None for policy in receipt_policies):
        raise ValueError("receipt authority service requires at least one policy")
    for receipt_policy, receipt_path, caller_role in (
        (
            receipt_authority_authentication_policy,
            RECEIPT_AUTHORITY_PATH,
            CallerRole.EXECUTOR,
        ),
        (
            recovery_receipt_authority_authentication_policy,
            RECOVERY_RECEIPT_AUTHORITY_PATH,
            CallerRole.EXECUTOR,
        ),
    ):
        if receipt_policy is not None and (
            role is not ServiceRole.COORDINATOR
            or type(receipt_policy) is not RouteAuthenticationPolicy
            or receipt_policy.service_role is not ServiceRole.COORDINATOR
            or receipt_policy.path != receipt_path
            or receipt_policy.caller.role is not caller_role
        ):
            raise ValueError("receipt authority is limited to its exact execution-worker route")
    if (recovery_executor_facade_handler is None) != (
        recovery_executor_facade_authentication_policy is None
    ):
        raise ValueError("recovery executor facade requires its exact route policy")
    facade_policy = recovery_executor_facade_authentication_policy
    if recovery_executor_facade_handler is not None and (
        role is not ServiceRole.EXECUTOR
        or not callable(recovery_executor_facade_handler)
        or type(facade_policy) is not RouteAuthenticationPolicy
        or facade_policy.service_role is not ServiceRole.EXECUTOR
        or facade_policy.path != RECOVERY_EXECUTION_FACADE_PATH
        or facade_policy.caller.role is not CallerRole.RECOVERY
        or not mutation_enabled
    ):
        raise ValueError("recovery executor facade is limited to its exact route")
    timeline_pairs = (
        (
            timeline_read_service,
            timeline_read_authentication_policy,
            TIMELINE_READ_PATH,
        ),
        (
            timeline_raw_export_service,
            timeline_raw_export_authentication_policy,
            TIMELINE_RAW_EXPORT_PATH,
        ),
    )
    for timeline_service, timeline_policy, timeline_path in timeline_pairs:
        if (timeline_service is None) != (timeline_policy is None):
            raise ValueError("timeline service requires its exact route policy")
        if timeline_service is not None and (
            role is not ServiceRole.API
            or type(timeline_policy) is not RouteAuthenticationPolicy
            or timeline_policy.service_role is not ServiceRole.API
            or timeline_policy.path != timeline_path
            or timeline_policy.caller.role is not CallerRole.OPERATOR
        ):
            raise ValueError("timeline reads are limited to exact operator API routes")
    if timeline_recorder is not None and (
        role is not ServiceRole.COORDINATOR or type(timeline_recorder) is not TimelineRecorder
    ):
        raise ValueError("timeline recording is coordinator-limited")
    if type(mutation_enabled) is not bool or (
        mutation_enabled and role not in {ServiceRole.EXECUTOR, ServiceRole.RECOVERY}
    ):
        raise ValueError("mutation enablement is limited to execution roles")
    if build_digest is None:
        build_digest = os.environ.get("CONTROLGRAPH_BUILD_DIGEST")
    if build_digest is not None and _DIGEST.fullmatch(build_digest) is None:
        raise ValueError("build_digest must be an immutable sha256 digest")
    configured_contract = os.environ.get("CONTROLGRAPH_CONTRACT_VERSION")
    if configured_contract not in {None, PRODUCT_CONTRACT_VERSION}:
        raise ValueError("CONTROLGRAPH_CONTRACT_VERSION is unsupported")
    app = FastAPI(
        title=f"ControlGraph {role.value}",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def record_request(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        correlation_id = response.headers.get("X-ControlGraph-Correlation-Id")
        if correlation_id is None:
            correlation_id = _correlation_id()
            response.headers["X-ControlGraph-Correlation-Id"] = correlation_id
        _emit_service_event(
            role=role,
            status_code=response.status_code,
            correlation_id=correlation_id,
        )
        return response

    @app.get("/healthz", response_model=ServiceHealth)
    def healthz(response: Response) -> ServiceHealth:
        correlation_id = _correlation_id()
        response.headers["X-ControlGraph-Correlation-Id"] = correlation_id
        return ServiceHealth(
            status="ok",
            service_role=role,
            correlation_id=correlation_id,
        )

    @app.get("/v1/metadata", response_model=ServiceMetadata)
    def metadata(response: Response) -> ServiceMetadata:
        correlation_id = _correlation_id()
        response.headers["X-ControlGraph-Correlation-Id"] = correlation_id
        return ServiceMetadata(
            contract_version=PRODUCT_CONTRACT_VERSION,
            service_shell_version=SERVICE_SHELL_VERSION,
            application_version=__version__,
            service_role=role,
            build_digest=build_digest,
            mutation_enabled=mutation_enabled,
            correlation_id=correlation_id,
        )

    def _timeline_query(request: Request, *, raw: bool) -> tuple[int, str | None, int, str]:
        allowed = {"after_sequence", "after_entry_sha256", "limit"}
        if not raw:
            allowed.add("audience")
        items = tuple(request.query_params.multi_items())
        names = tuple(name for name, _ in items)
        if any(name not in allowed for name in names) or len(set(names)) != len(names):
            raise ValueError("timeline query is invalid")
        values = dict(items)
        sequence_text = values.get("after_sequence", "0")
        limit_text = values.get("limit", "25" if raw else "50")
        if (
            _CANONICAL_UINT.fullmatch(sequence_text) is None
            or _CANONICAL_UINT.fullmatch(limit_text) is None
        ):
            raise ValueError("timeline query integer is invalid")
        sequence = int(sequence_text)
        limit = int(limit_text)
        digest = values.get("after_entry_sha256")
        if (sequence == 0) != (digest is None) or (
            digest is not None and _SHA256.fullmatch(digest) is None
        ):
            raise ValueError("timeline cursor is invalid")
        audience = values.get("audience", TimelineAudience.OPERATOR.value)
        if raw:
            audience = TimelineAudience.RESTRICTED.value
        elif audience not in {
            TimelineAudience.PUBLIC_DEMO.value,
            TimelineAudience.OPERATOR.value,
        }:
            if audience in {
                TimelineAudience.SECURITY_AUDIT.value,
                TimelineAudience.RESTRICTED.value,
            }:
                raise TimelineReadError(TimelineReadErrorCode.ACCESS_DENIED)
            raise ValueError("timeline audience is invalid")
        return sequence, digest, limit, audience

    def _timeline_principal(context: AuthenticationContext) -> str:
        digest = hashlib.sha256(context.subject.encode("ascii")).hexdigest()
        return f"operator:{digest}"

    async def timeline_read(request: Request) -> Response:
        correlation_id = _correlation_id()
        service = timeline_read_service
        route_policy = timeline_read_authentication_policy
        if (
            authenticator is None
            or type(service) is not TimelineReadService
            or type(route_policy) is not RouteAuthenticationPolicy
        ):
            return _timeline_denial(
                TimelineReadErrorCode.CONFIGURATION_INVALID.value,
                correlation_id,
            )
        try:
            context = authenticator.authenticate(
                authentication_header(request.headers, route_policy),
                route_policy,
            )
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext or context.role is not CallerRole.OPERATOR:
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        try:
            sequence, digest, limit, audience_value = _timeline_query(request, raw=False)
            command = TimelinePageCommandV1(
                schema_version=TIMELINE_PAGE_COMMAND_V1,
                target=service.target,
                after_sequence=sequence,
                after_entry_sha256=digest,
                limit=limit,
                audience=TimelineAudience(audience_value),
            )
            page = await service.read(
                command,
                TimelineReadGrant(
                    target=service.target,
                    maximum_audience=TimelineAudience.OPERATOR,
                    principal_id=_timeline_principal(context),
                ),
            )
        except asyncio.CancelledError:
            raise
        except (TypeError, ValueError):
            return _timeline_denial(
                TimelineReadErrorCode.CURSOR_INVALID.value,
                correlation_id,
            )
        except TimelineReadError as error:
            return _timeline_denial(error.code.value, correlation_id)
        return Response(
            content=canonical_json_bytes(page),
            status_code=200,
            media_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "X-ControlGraph-Correlation-Id": correlation_id,
            },
        )

    async def timeline_raw_export(request: Request) -> Response:
        correlation_id = _correlation_id()
        service = timeline_raw_export_service
        route_policy = timeline_raw_export_authentication_policy
        if (
            authenticator is None
            or type(service) is not TimelineRawExportService
            or type(route_policy) is not RouteAuthenticationPolicy
        ):
            return _timeline_denial(
                TimelineRawExportErrorCode.CONFIGURATION_INVALID.value,
                correlation_id,
            )
        try:
            context = authenticator.authenticate(
                authentication_header(request.headers, route_policy),
                route_policy,
            )
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext or context.role is not CallerRole.OPERATOR:
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        confirmations = request.headers.getlist("X-ControlGraph-Raw-Export")
        if confirmations != [_RAW_EXPORT_CONFIRMATION]:
            return _timeline_denial(
                TimelineRawExportErrorCode.ACCESS_DENIED.value,
                correlation_id,
            )
        try:
            sequence, digest, limit, _ = _timeline_query(request, raw=True)
            command = TimelineRawExportCommandV1(
                schema_version=TIMELINE_RAW_EXPORT_COMMAND_V1,
                target=service.target,
                after_sequence=sequence,
                after_entry_sha256=digest,
                limit=limit,
            )
            exported = await service.export(
                command,
                TimelineRawExportGrant(
                    target=service.target,
                    principal_id=_timeline_principal(context),
                ),
            )
        except asyncio.CancelledError:
            raise
        except (TypeError, ValueError):
            return _timeline_denial(
                TimelineRawExportErrorCode.CURSOR_INVALID.value,
                correlation_id,
            )
        except TimelineRawExportError as error:
            return _timeline_denial(error.code.value, correlation_id)
        return Response(
            content=canonical_json_bytes(exported),
            status_code=200,
            media_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "X-ControlGraph-Correlation-Id": correlation_id,
            },
        )

    async def protected_work(request: Request) -> Response:
        correlation_id = _correlation_id()
        if authenticator is None or authentication_policy is None:
            return _authentication_denial(
                AuthenticationDenialCode.CONFIGURATION_INVALID,
                correlation_id,
            )
        try:
            authorization_header = authentication_header(
                request.headers,
                authentication_policy,
            )
            context = await asyncio.to_thread(
                authenticator.authenticate,
                authorization_header,
                authentication_policy,
            )
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        request.state.authentication = context
        if role is ServiceRole.API and (
            api_root_creation_client is not None
            or api_canary_client is not None
            or api_promotion_client is not None
            or api_health_evaluation_client is not None
            or api_recovery_client is not None
            or api_epoch_revocation_client is not None
            or api_service_claim_release_client is not None
            or api_recovery_abandonment_client is not None
            or api_operator_observation_client is not None
        ):
            try:
                body = await _read_contract_body(request)
                command = _decode_api_command(body)
                if type(command) is RootCreationCommandV1:
                    if api_root_creation_client is None:
                        raise RootRelayError(RootRelayErrorCode.CONFIGURATION_INVALID)
                    root_result = await api_root_creation_client.create(command, context)
                    response_body = canonical_json_bytes(root_result)
                elif type(command) is ApplyCanaryCommandV1:
                    if api_canary_client is None:
                        raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
                    canary_result = await api_canary_client.dispatch(command, context)
                    response_body = canonical_json_bytes(canary_result)
                elif type(command) is PromotionCommandV2:
                    if api_promotion_client is None:
                        raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
                    promotion_result = await api_promotion_client.dispatch(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(promotion_result)
                elif type(command) is HealthEvaluationCommandV1:
                    if api_health_evaluation_client is None:
                        raise HealthPipelineError(HealthPipelineErrorCode.CONFIGURATION_INVALID)
                    health_result = await api_health_evaluation_client.evaluate(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(health_result)
                elif type(command) is RecoveryCommandV2:
                    if api_recovery_client is None:
                        raise RecoveryExecutionError(
                            RecoveryExecutionErrorCode.CONFIGURATION_INVALID
                        )
                    recovery_result = await api_recovery_client.dispatch(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(recovery_result)
                elif type(command) is ServiceClaimReleaseCommandV1:
                    if api_service_claim_release_client is None:
                        raise ServiceClaimReleaseError(
                            ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
                        )
                    release_result = await api_service_claim_release_client.release(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(release_result)
                elif type(command) is RecoveryAbandonmentCommandV1:
                    if api_recovery_abandonment_client is None:
                        raise RecoveryAbandonmentError(
                            RecoveryAbandonmentFailureCode.STORE_UNAVAILABLE
                        )
                    abandonment_result = await api_recovery_abandonment_client.abandon(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(abandonment_result)
                elif type(command) is StableSnapshotCaptureCommandV1:
                    if api_operator_observation_client is None:
                        raise OperatorObservationError(
                            OperatorObservationErrorCode.CONFIGURATION_INVALID
                        )
                    snapshot_result = await api_operator_observation_client.capture_snapshot(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(snapshot_result)
                elif type(command) is ExecutionReceiptReadCommandV1:
                    if api_operator_observation_client is None:
                        raise OperatorObservationError(
                            OperatorObservationErrorCode.CONFIGURATION_INVALID
                        )
                    receipt_result = await api_operator_observation_client.read_receipt(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(receipt_result)
                elif type(command) is TargetTrafficReadCommandV1:
                    if api_operator_observation_client is None:
                        raise OperatorObservationError(
                            OperatorObservationErrorCode.CONFIGURATION_INVALID
                        )
                    traffic_result = await api_operator_observation_client.read_target_traffic(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(traffic_result)
                elif type(command) is EpochRevocationProofCommandV1:
                    if api_epoch_revocation_client is None:
                        raise EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED)
                    revocation_proof = await api_epoch_revocation_client.proof(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(revocation_proof)
                else:
                    if type(command) is not EpochRevocationCommandV1:
                        raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED)
                    if api_epoch_revocation_client is None:
                        raise EpochRevocationError(EpochRevocationFailureCode.STORE_UNAVAILABLE)
                    revocation_call_outcome = await api_epoch_revocation_client.revoke(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(revocation_call_outcome)
            except asyncio.CancelledError:
                raise
            except CapabilityVerificationError:
                return _canary_execution_denial("CONTRACT_INVALID", correlation_id)
            except ContractError as error:
                return _canary_execution_denial(error.code.value, correlation_id)
            except RootRelayError as error:
                return _root_creation_denial(error.code.value, correlation_id)
            except CanaryExecutionError as error:
                return _canary_execution_denial(error.code.value, correlation_id)
            except HealthPipelineError as error:
                return _health_pipeline_denial(error.code.value, correlation_id)
            except RecoveryExecutionError as error:
                return _recovery_execution_denial(error.code.value, correlation_id)
            except EpochRevocationError as error:
                return _epoch_revocation_denial(error.code.value, correlation_id)
            except ServiceClaimReleaseError as error:
                return _service_claim_release_denial(
                    error.code.value,
                    correlation_id,
                )
            except RecoveryAbandonmentError as error:
                return _recovery_abandonment_denial(
                    error.code.value,
                    correlation_id,
                )
            except OperatorObservationError as error:
                return _operator_observation_denial(error.code.value, correlation_id)
            except Exception:
                return _canary_execution_denial(
                    CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE.value,
                    correlation_id,
                )
            return Response(
                content=response_body,
                status_code=200,
                media_type="application/json",
                headers={"X-ControlGraph-Correlation-Id": correlation_id},
            )
        if role is ServiceRole.COORDINATOR and (
            coordinator_root_creation_relay is not None
            or coordinator_canary_relay is not None
            or coordinator_promotion_relay is not None
            or coordinator_health_evaluation_service is not None
            or coordinator_recovery_relay is not None
            or coordinator_epoch_revocation_relay is not None
            or coordinator_service_claim_release_relay is not None
            or coordinator_recovery_abandonment_relay is not None
            or coordinator_operator_observation_relay is not None
        ):
            try:
                body = await _read_contract_body(request)
                invocation = _decode_coordinator_invocation(body)
                if type(invocation) is RootCreationInvocationV1:
                    if coordinator_root_creation_relay is None:
                        raise RootRelayError(RootRelayErrorCode.CONFIGURATION_INVALID)
                    root_result = await coordinator_root_creation_relay.create(
                        invocation,
                        context,
                    )
                    if timeline_recorder is not None:
                        await timeline_recorder.record_root_creation(root_result)
                    response_body = canonical_json_bytes(root_result)
                elif type(invocation) is ApplyCanaryInvocationV1:
                    if coordinator_canary_relay is None:
                        raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
                    canary_result = await coordinator_canary_relay.dispatch(
                        invocation,
                        context,
                    )
                    if timeline_recorder is not None:
                        await timeline_recorder.record_canary_dispatch(canary_result)
                    response_body = canonical_json_bytes(canary_result)
                elif type(invocation) is PromotionInvocationV2:
                    if coordinator_promotion_relay is None:
                        raise CanaryExecutionError(CanaryExecutionErrorCode.CONFIGURATION_INVALID)
                    promotion_result = await coordinator_promotion_relay.dispatch(
                        invocation,
                        context,
                    )
                    if timeline_recorder is not None:
                        await timeline_recorder.record_promotion_dispatch(promotion_result)
                    response_body = canonical_json_bytes(promotion_result)
                elif type(invocation) is HealthEvaluationInvocationV1:
                    if coordinator_health_evaluation_service is None:
                        raise HealthPipelineError(HealthPipelineErrorCode.CONFIGURATION_INVALID)
                    health_result = await coordinator_health_evaluation_service.evaluate(
                        invocation,
                        context,
                    )
                    if (
                        timeline_recorder is not None
                        and health_result.recovery_dispatch is not None
                    ):
                        await timeline_recorder.record_recovery_dispatch(
                            health_result.recovery_dispatch
                        )
                    response_body = canonical_json_bytes(health_result)
                elif type(invocation) is RecoveryInvocationV2:
                    if coordinator_recovery_relay is None:
                        raise RecoveryExecutionError(
                            RecoveryExecutionErrorCode.CONFIGURATION_INVALID
                        )
                    recovery_result = await coordinator_recovery_relay.dispatch(
                        invocation,
                        context,
                    )
                    if timeline_recorder is not None:
                        await timeline_recorder.record_recovery_dispatch(recovery_result)
                    response_body = canonical_json_bytes(recovery_result)
                elif type(invocation) is ServiceClaimReleaseInvocationV1:
                    if coordinator_service_claim_release_relay is None:
                        raise ServiceClaimReleaseError(
                            ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
                        )
                    try:
                        release_result = await coordinator_service_claim_release_relay.release(
                            invocation,
                            context,
                        )
                    except ServiceClaimReleaseError as error:
                        release_outcome = ServiceClaimReleaseRelayResponseV1(
                            schema_version=(SERVICE_CLAIM_RELEASE_RELAY_RESPONSE_V1),
                            result=None,
                            failure_code=error.code,
                        )
                    else:
                        if timeline_recorder is not None:
                            await timeline_recorder.record_service_claim_release(
                                release_result
                            )
                        release_outcome = ServiceClaimReleaseRelayResponseV1(
                            schema_version=(SERVICE_CLAIM_RELEASE_RELAY_RESPONSE_V1),
                            result=release_result,
                            failure_code=None,
                        )
                    response_body = canonical_json_bytes(release_outcome)
                elif type(invocation) is RecoveryAbandonmentInvocationV1:
                    if coordinator_recovery_abandonment_relay is None:
                        raise RecoveryAbandonmentError(
                            RecoveryAbandonmentFailureCode.STORE_UNAVAILABLE
                        )
                    try:
                        abandonment_result = await coordinator_recovery_abandonment_relay.abandon(
                            invocation,
                            context,
                        )
                    except RecoveryAbandonmentError as error:
                        abandonment_outcome = RecoveryAbandonmentRelayResponseV1(
                            schema_version=RECOVERY_ABANDONMENT_RELAY_RESPONSE_V1,
                            result=None,
                            failure_code=error.code,
                        )
                    else:
                        if timeline_recorder is not None:
                            await timeline_recorder.record_recovery_abandonment(
                                abandonment_result
                            )
                        abandonment_outcome = RecoveryAbandonmentRelayResponseV1(
                            schema_version=RECOVERY_ABANDONMENT_RELAY_RESPONSE_V1,
                            result=abandonment_result,
                            failure_code=None,
                        )
                    response_body = canonical_json_bytes(abandonment_outcome)
                elif type(invocation) is StableSnapshotCaptureInvocationV1:
                    if coordinator_operator_observation_relay is None:
                        raise OperatorObservationError(
                            OperatorObservationErrorCode.CONFIGURATION_INVALID
                        )
                    snapshot_result = await coordinator_operator_observation_relay.capture_snapshot(
                        invocation,
                        context,
                    )
                    response_body = canonical_json_bytes(snapshot_result)
                elif type(invocation) is ExecutionReceiptReadInvocationV1:
                    if coordinator_operator_observation_relay is None:
                        raise OperatorObservationError(
                            OperatorObservationErrorCode.CONFIGURATION_INVALID
                        )
                    receipt_result = await coordinator_operator_observation_relay.read_receipt(
                        invocation,
                        context,
                    )
                    response_body = canonical_json_bytes(receipt_result)
                elif type(invocation) is TargetTrafficReadInvocationV1:
                    if coordinator_operator_observation_relay is None:
                        raise OperatorObservationError(
                            OperatorObservationErrorCode.CONFIGURATION_INVALID
                        )
                    traffic_result = (
                        await coordinator_operator_observation_relay.read_target_traffic(
                            invocation,
                            context,
                        )
                    )
                    response_body = canonical_json_bytes(traffic_result)
                elif type(invocation) is EpochRevocationProofInvocationV1:
                    if coordinator_epoch_revocation_relay is None:
                        raise EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED)
                    try:
                        revocation_proof = await coordinator_epoch_revocation_relay.proof(
                            invocation,
                            context,
                        )
                    except EpochRevocationError:
                        proof_outcome = EpochRevocationProofRelayResponseV1(
                            schema_version=(EPOCH_REVOCATION_PROOF_RELAY_RESPONSE_V1),
                            proof=None,
                            failure_code=EpochRevocationFailureCode.PROOF_DENIED,
                        )
                    else:
                        proof_outcome = EpochRevocationProofRelayResponseV1(
                            schema_version=(EPOCH_REVOCATION_PROOF_RELAY_RESPONSE_V1),
                            proof=revocation_proof,
                            failure_code=None,
                        )
                    response_body = canonical_json_bytes(proof_outcome)
                else:
                    if type(invocation) is not EpochRevocationInvocationV1:
                        raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED)
                    if coordinator_epoch_revocation_relay is None:
                        raise EpochRevocationError(EpochRevocationFailureCode.STORE_UNAVAILABLE)
                    try:
                        revocation_call = await coordinator_epoch_revocation_relay.revoke(
                            invocation,
                            context,
                        )
                    except EpochRevocationError as error:
                        revocation_relay_outcome = EpochRevocationRelayResponseV1(
                            schema_version=EPOCH_REVOCATION_RELAY_RESPONSE_V1,
                            outcome=None,
                            failure_code=error.code,
                        )
                    else:
                        if timeline_recorder is not None:
                            await timeline_recorder.record_epoch_revocation(
                                revocation_call
                            )
                        revocation_relay_outcome = EpochRevocationRelayResponseV1(
                            schema_version=EPOCH_REVOCATION_RELAY_RESPONSE_V1,
                            outcome=revocation_call,
                            failure_code=None,
                        )
                    response_body = canonical_json_bytes(revocation_relay_outcome)
            except asyncio.CancelledError:
                raise
            except CapabilityVerificationError:
                return _canary_execution_denial("CONTRACT_INVALID", correlation_id)
            except ContractError as error:
                return _canary_execution_denial(error.code.value, correlation_id)
            except RootRelayError as error:
                return _root_creation_denial(error.code.value, correlation_id)
            except CanaryExecutionError as error:
                return _canary_execution_denial(error.code.value, correlation_id)
            except HealthPipelineError as error:
                return _health_pipeline_denial(error.code.value, correlation_id)
            except RecoveryExecutionError as error:
                return _recovery_execution_denial(error.code.value, correlation_id)
            except EpochRevocationError as error:
                return _epoch_revocation_denial(error.code.value, correlation_id)
            except ServiceClaimReleaseError as error:
                return _service_claim_release_denial(
                    error.code.value,
                    correlation_id,
                )
            except RecoveryAbandonmentError as error:
                return _recovery_abandonment_denial(
                    error.code.value,
                    correlation_id,
                )
            except OperatorObservationError as error:
                return _operator_observation_denial(error.code.value, correlation_id)
            except Exception:
                return _canary_execution_denial(
                    CanaryExecutionErrorCode.DISPATCH_UNAVAILABLE.value,
                    correlation_id,
                )
            return Response(
                content=response_body,
                status_code=200,
                media_type="application/json",
                headers={"X-ControlGraph-Correlation-Id": correlation_id},
            )
        if role is ServiceRole.ISSUER and capability_issuance_service is not None:
            try:
                body = await _read_contract_body(request)
                issuance_command = _decode_issuance_command(body)
                capability = await capability_issuance_service.issue(
                    issuance_command,
                    context,
                )
                response_body = canonical_json_bytes(capability)
            except asyncio.CancelledError:
                raise
            except ContractError as error:
                return _canary_execution_denial(error.code.value, correlation_id)
            except CanaryExecutionError as error:
                return _canary_execution_denial(error.code.value, correlation_id)
            except Exception:
                return _canary_execution_denial(
                    CanaryExecutionErrorCode.ISSUANCE_DENIED.value,
                    correlation_id,
                )
            return Response(
                content=response_body,
                status_code=200,
                media_type="application/json",
                headers={"X-ControlGraph-Correlation-Id": correlation_id},
            )
        if role is ServiceRole.EVIDENCE_WRITER:
            if evidence_signing_service is None:
                return _evidence_signing_denial(
                    EvidenceSigningErrorCode.CONFIGURATION_INVALID.value,
                    correlation_id,
                )
            try:
                body = await _read_contract_body(request)
                event = decode_contract(body, EvidenceEvent)
                signed = await evidence_signing_service.sign(event, context)
                response_body = canonical_json_bytes(signed)
            except asyncio.CancelledError:
                raise
            except CapabilityVerificationError:
                return _evidence_signing_denial("CONTRACT_INVALID", correlation_id)
            except ContractError as error:
                return _evidence_signing_denial(error.code.value, correlation_id)
            except EvidenceSigningError as error:
                return _evidence_signing_denial(error.code.value, correlation_id)
            except Exception:
                return _evidence_signing_denial(
                    EvidenceSigningErrorCode.UNAVAILABLE.value,
                    correlation_id,
                )
            return Response(
                content=response_body,
                status_code=200,
                media_type="application/json",
                headers={"X-ControlGraph-Correlation-Id": correlation_id},
            )
        if role is ServiceRole.VERIFIER and (
            root_preflight_service is not None
            or service_claim_classification_service is not None
            or stable_snapshot_capture_service is not None
            or target_traffic_observation_service is not None
            or verifier_health_evaluation_service is not None
            or verifier_recovery_prestate_service is not None
            or independent_verification_service is not None
        ):
            try:
                body = await _read_contract_body(request)
                verifier_request = _decode_verifier_request(body)
                if type(verifier_request) is RootPreflightRequestV1:
                    if root_preflight_service is None:
                        raise RootPreflightError(RootPreflightErrorCode.CONFIGURATION_INVALID)
                    preflight_result = await root_preflight_service.preflight(
                        verifier_request,
                        context,
                    )
                    response_body = canonical_json_bytes(preflight_result)
                elif type(verifier_request) is StableSnapshotCaptureRequestV1:
                    if stable_snapshot_capture_service is None:
                        raise OperatorObservationError(
                            OperatorObservationErrorCode.CONFIGURATION_INVALID
                        )
                    snapshot_result = await stable_snapshot_capture_service.capture(
                        verifier_request,
                        context,
                    )
                    response_body = canonical_json_bytes(snapshot_result)
                elif type(verifier_request) is TargetTrafficReadRequestV1:
                    if target_traffic_observation_service is None:
                        raise OperatorObservationError(
                            OperatorObservationErrorCode.CONFIGURATION_INVALID
                        )
                    traffic_result = await target_traffic_observation_service.observe(
                        verifier_request,
                        context,
                    )
                    response_body = canonical_json_bytes(traffic_result)
                elif type(verifier_request) is VerifierHealthEvaluationRequestV1:
                    if verifier_health_evaluation_service is None:
                        raise HealthPipelineError(HealthPipelineErrorCode.CONFIGURATION_INVALID)
                    verifier_health_result = await verifier_health_evaluation_service.evaluate(
                        verifier_request,
                        context,
                    )
                    response_body = canonical_json_bytes(verifier_health_result)
                elif type(verifier_request) is RecoveryPrestateRequestV1:
                    if verifier_recovery_prestate_service is None:
                        raise RecoveryExecutionError(
                            RecoveryExecutionErrorCode.CONFIGURATION_INVALID
                        )
                    prestate_result = await verifier_recovery_prestate_service.evaluate(
                        verifier_request,
                        context,
                    )
                    response_body = canonical_json_bytes(prestate_result)
                elif type(verifier_request) is IndependentVerificationInvocationV1:
                    if independent_verification_service is None:
                        raise IndependentVerificationError(
                            IndependentVerificationErrorCode.CONFIGURATION_INVALID
                        )
                    if verifier_request.kind is IndependentVerificationKind.CONFIGURATION:
                        verification_result = (
                            await independent_verification_service.attest_configuration(
                                verifier_request.verification,
                                context,
                            )
                        )
                    else:
                        verification_result = (
                            await independent_verification_service.attest_probe(
                                verifier_request.verification,
                                context,
                            )
                        )
                    response_body = canonical_json_bytes(verification_result)
                else:
                    if (
                        type(verifier_request)
                        not in (
                            ServiceClaimClassificationRequestV1,
                            RecoveryAbandonmentClassificationRequestV1,
                        )
                        or service_claim_classification_service is None
                    ):
                        raise ServiceClaimClassificationError(
                            ServiceClaimClassificationErrorCode.CONFIGURATION_INVALID
                        )
                    classification_result = await service_claim_classification_service.classify(
                        cast(
                            ServiceClaimClassificationRequestV1
                            | RecoveryAbandonmentClassificationRequestV1,
                            verifier_request,
                        ),
                        context,
                    )
                    response_body = canonical_json_bytes(classification_result)
            except asyncio.CancelledError:
                raise
            except CapabilityVerificationError:
                return _root_preflight_denial("CONTRACT_INVALID", correlation_id)
            except ContractError as error:
                return _root_preflight_denial(error.code.value, correlation_id)
            except RootPreflightError as error:
                return _root_preflight_denial(error.code.value, correlation_id)
            except HealthPipelineError as error:
                return _health_pipeline_denial(error.code.value, correlation_id)
            except RecoveryExecutionError as error:
                return _recovery_execution_denial(error.code.value, correlation_id)
            except IndependentVerificationError as error:
                return _independent_verification_denial(
                    error.code.value,
                    correlation_id,
                )
            except ServiceClaimClassificationError as error:
                return _service_claim_classification_denial(
                    error.code.value,
                    correlation_id,
                )
            except OperatorObservationError as error:
                return _operator_observation_denial(error.code.value, correlation_id)
            except Exception:
                return _root_preflight_denial(
                    RootPreflightErrorCode.UNAVAILABLE.value,
                    correlation_id,
                )
            return Response(
                content=response_body,
                status_code=200,
                media_type="application/json",
                headers={"X-ControlGraph-Correlation-Id": correlation_id},
            )
        if capability_verifier is not None:
            try:
                body = await _read_contract_body(request)
                verified = await capability_verifier.verify(body, context)
            except CapabilityVerificationError as error:
                return _capability_denial(error.code, correlation_id)
            except Exception:
                return _capability_denial(ReasonCode.AUTHORITY_UNAVAILABLE, correlation_id)
            if type(verified) is not VerifiedMutation:
                return _capability_denial(ReasonCode.AUTHORITY_UNAVAILABLE, correlation_id)
            request.state.verified_mutation = verified
            if verified_task_handler is not None:
                handler_response = await verified_task_handler(verified)
                if not isinstance(handler_response, Response):
                    return _capability_denial(ReasonCode.AUTHORITY_UNAVAILABLE, correlation_id)
                handler_response.headers.setdefault("X-ControlGraph-Correlation-Id", correlation_id)
                return handler_response
        disabled_response = DisabledWork(
            code="MUTATION_DISABLED",
            correlation_id=correlation_id,
        )
        return JSONResponse(
            status_code=503,
            content=disabled_response.model_dump(mode="json"),
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    async def _receipt_authority_work(
        request: Request,
        policy: RouteAuthenticationPolicy | None,
        caller_role: CallerRole,
        *,
        recovery: bool,
    ) -> Response:
        correlation_id = _correlation_id()
        service = receipt_authority_service
        if (
            authenticator is None
            or type(policy) is not RouteAuthenticationPolicy
            or type(service) is not ReceiptAuthorityService
        ):
            return _authentication_denial(
                AuthenticationDenialCode.CONFIGURATION_INVALID,
                correlation_id,
            )
        try:
            authorization_header = authentication_header(request.headers, policy)
            context = await asyncio.to_thread(
                authenticator.authenticate,
                authorization_header,
                policy,
            )
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext or context.role is not caller_role:
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        try:
            body = await _read_contract_body(request)
            if recovery:
                response_body = await service.handle_recovery_authenticated(
                    body,
                    context,
                )
            else:
                response_body = await service.handle_authenticated(body, context)
            if timeline_recorder is not None:
                authority_response = decode_contract(
                    response_body,
                    ReceiptAuthorityResponseV1,
                )
                if (
                    authority_response.operation is not ReceiptAuthorityOperation.READ
                    and authority_response.stored_receipt is not None
                ):
                    await timeline_recorder.record_execution_receipt(
                        authority_response.stored_receipt.receipt
                    )
        except asyncio.CancelledError:
            raise
        except CapabilityVerificationError:
            return _receipt_authority_denial("CONTRACT_INVALID", correlation_id)
        except AuthorityStoreError:
            return _receipt_authority_denial(
                "RECEIPT_AUTHORITY_UNAVAILABLE",
                correlation_id,
            )
        except Exception:
            return _receipt_authority_denial(
                "RECEIPT_AUTHORITY_UNAVAILABLE",
                correlation_id,
            )
        return Response(
            content=response_body,
            status_code=200,
            media_type="application/json",
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    async def receipt_authority_work(request: Request) -> Response:
        return await _receipt_authority_work(
            request,
            receipt_authority_authentication_policy,
            CallerRole.EXECUTOR,
            recovery=False,
        )

    async def recovery_receipt_authority_work(request: Request) -> Response:
        return await _receipt_authority_work(
            request,
            recovery_receipt_authority_authentication_policy,
            CallerRole.EXECUTOR,
            recovery=True,
        )

    async def recovery_executor_facade_work(request: Request) -> Response:
        correlation_id = _correlation_id()
        policy = recovery_executor_facade_authentication_policy
        handler = recovery_executor_facade_handler
        if (
            authenticator is None
            or type(policy) is not RouteAuthenticationPolicy
            or not callable(handler)
        ):
            return _authentication_denial(
                AuthenticationDenialCode.CONFIGURATION_INVALID,
                correlation_id,
            )
        try:
            authorization_header = authentication_header(request.headers, policy)
            context = await asyncio.to_thread(
                authenticator.authenticate,
                authorization_header,
                policy,
            )
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext or context.role is not CallerRole.RECOVERY:
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        try:
            body = await _read_contract_body(request)
            response_body = await handler(body, context)
        except asyncio.CancelledError:
            raise
        except CapabilityVerificationError as error:
            return _capability_denial(error.code, correlation_id)
        except Exception:
            return _capability_denial(
                ReasonCode.AUTHORITY_UNAVAILABLE,
                correlation_id,
            )
        if type(response_body) is not bytes or not response_body:
            return _capability_denial(
                ReasonCode.AUTHORITY_UNAVAILABLE,
                correlation_id,
            )
        return Response(
            content=response_body,
            status_code=200,
            media_type="application/json",
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    async def classification_evidence_work(request: Request) -> Response:
        correlation_id = _correlation_id()
        policy = classification_evidence_authentication_policy
        service = classification_evidence_signing_service
        if (
            authenticator is None
            or type(policy) is not RouteAuthenticationPolicy
            or type(service) is not ClassificationEvidenceSigningService
        ):
            return _authentication_denial(
                AuthenticationDenialCode.CONFIGURATION_INVALID,
                correlation_id,
            )
        try:
            authorization_header = authentication_header(request.headers, policy)
            context = await asyncio.to_thread(
                authenticator.authenticate,
                authorization_header,
                policy,
            )
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext or context.role is not CallerRole.VERIFIER:
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        try:
            body = await _read_contract_body(request)
            signing_request = _decode_classification_signing_request(body)
            signed = await service.sign(signing_request, context)
            response_body = canonical_json_bytes(signed)
        except asyncio.CancelledError:
            raise
        except ContractError as error:
            return _service_claim_classification_denial(
                error.code.value,
                correlation_id,
            )
        except ServiceClaimClassificationError as error:
            return _service_claim_classification_denial(
                error.code.value,
                correlation_id,
            )
        except Exception:
            return _service_claim_classification_denial(
                ServiceClaimClassificationErrorCode.UNAVAILABLE.value,
                correlation_id,
            )
        return Response(
            content=response_body,
            status_code=200,
            media_type="application/json",
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    async def health_attestation_work(request: Request) -> Response:
        correlation_id = _correlation_id()
        policy = health_attestation_authentication_policy
        service = health_attestation_signing_service
        if (
            authenticator is None
            or type(policy) is not RouteAuthenticationPolicy
            or type(service) is not HealthAttestationSigningService
        ):
            return _authentication_denial(
                AuthenticationDenialCode.CONFIGURATION_INVALID,
                correlation_id,
            )
        try:
            authorization_header = authentication_header(request.headers, policy)
            context = await asyncio.to_thread(
                authenticator.authenticate,
                authorization_header,
                policy,
            )
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext or context.role is not CallerRole.VERIFIER:
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        try:
            body = await _read_contract_body(request)
            signing_request = decode_contract(
                body,
                HealthAttestationSigningRequestV1,
            )
            signed = await service.attest(signing_request, context)
            response_body = canonical_json_bytes(signed)
        except asyncio.CancelledError:
            raise
        except ContractError as error:
            return _health_attestation_denial(error.code.value, correlation_id)
        except HealthAttestationError as error:
            return _health_attestation_denial(error.code.value, correlation_id)
        except Exception:
            return _health_attestation_denial(
                HealthAttestationErrorCode.UNAVAILABLE.value,
                correlation_id,
            )
        return Response(
            content=response_body,
            status_code=200,
            media_type="application/json",
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    async def independent_verification_evidence_work(request: Request) -> Response:
        correlation_id = _correlation_id()
        policy = independent_verification_evidence_authentication_policy
        service = independent_verification_signing_service
        if (
            authenticator is None
            or type(policy) is not RouteAuthenticationPolicy
            or type(service) is not IndependentVerificationSigningService
        ):
            return _authentication_denial(
                AuthenticationDenialCode.CONFIGURATION_INVALID,
                correlation_id,
            )
        try:
            authorization_header = authentication_header(request.headers, policy)
            context = authenticator.authenticate(authorization_header, policy)
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext or context.role is not CallerRole.VERIFIER:
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        try:
            body = await _read_contract_body(request)
            signing_request = decode_contract(
                body,
                IndependentVerificationSigningRequestV1,
            )
            signed = await service.sign(signing_request, context)
            response_body = canonical_json_bytes(signed)
        except asyncio.CancelledError:
            raise
        except ContractError as error:
            return _independent_verification_denial(
                error.code.value,
                correlation_id,
            )
        except IndependentVerificationError as error:
            return _independent_verification_denial(
                error.code.value,
                correlation_id,
            )
        except Exception:
            return _independent_verification_denial(
                IndependentVerificationErrorCode.UNAVAILABLE.value,
                correlation_id,
            )
        return Response(
            content=response_body,
            status_code=200,
            media_type="application/json",
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    async def recovery_prestate_attestation_work(request: Request) -> Response:
        correlation_id = _correlation_id()
        policy = recovery_prestate_authentication_policy
        service = recovery_prestate_signing_service
        if (
            authenticator is None
            or type(policy) is not RouteAuthenticationPolicy
            or type(service) is not RecoveryPrestateSigningService
        ):
            return _authentication_denial(
                AuthenticationDenialCode.CONFIGURATION_INVALID,
                correlation_id,
            )
        try:
            authorization_header = authentication_header(request.headers, policy)
            context = await asyncio.to_thread(
                authenticator.authenticate,
                authorization_header,
                policy,
            )
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if type(context) is not AuthenticationContext or context.role is not CallerRole.VERIFIER:
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        try:
            body = await _read_contract_body(request)
            signing_request = decode_contract(
                body,
                RecoveryPrestateSigningRequestV1,
            )
            signed = await service.attest(signing_request, context)
            response_body = canonical_json_bytes(signed)
        except asyncio.CancelledError:
            raise
        except ContractError as error:
            return _recovery_execution_denial(error.code.value, correlation_id)
        except RecoveryExecutionError as error:
            return _recovery_execution_denial(error.code.value, correlation_id)
        except Exception:
            return _recovery_execution_denial(
                RecoveryExecutionErrorCode.PRESTATE_UNAVAILABLE.value,
                correlation_id,
            )
        return Response(
            content=response_body,
            status_code=200,
            media_type="application/json",
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    for path in protected_paths(role):
        app.add_api_route(path, protected_work, methods=["POST"], include_in_schema=False)
    if timeline_read_authentication_policy is not None:
        app.add_api_route(
            TIMELINE_READ_PATH,
            timeline_read,
            methods=["GET"],
            include_in_schema=False,
        )
    if timeline_raw_export_authentication_policy is not None:
        app.add_api_route(
            TIMELINE_RAW_EXPORT_PATH,
            timeline_raw_export,
            methods=["GET"],
            include_in_schema=False,
        )
    if receipt_authority_authentication_policy is not None:
        app.add_api_route(
            RECEIPT_AUTHORITY_PATH,
            receipt_authority_work,
            methods=["POST"],
            include_in_schema=False,
        )
    if recovery_receipt_authority_authentication_policy is not None:
        app.add_api_route(
            RECOVERY_RECEIPT_AUTHORITY_PATH,
            recovery_receipt_authority_work,
            methods=["POST"],
            include_in_schema=False,
        )
    if recovery_executor_facade_authentication_policy is not None:
        app.add_api_route(
            RECOVERY_EXECUTION_FACADE_PATH,
            recovery_executor_facade_work,
            methods=["POST"],
            include_in_schema=False,
        )
    if classification_evidence_signing_service is not None:
        app.add_api_route(
            CLASSIFICATION_EVIDENCE_PATH,
            classification_evidence_work,
            methods=["POST"],
            include_in_schema=False,
        )
    if independent_verification_signing_service is not None:
        app.add_api_route(
            INDEPENDENT_VERIFICATION_EVIDENCE_PATH,
            independent_verification_evidence_work,
            methods=["POST"],
            include_in_schema=False,
        )
    if health_attestation_signing_service is not None:
        app.add_api_route(
            HEALTH_ATTESTATION_PATH,
            health_attestation_work,
            methods=["POST"],
            include_in_schema=False,
        )
    if recovery_prestate_signing_service is not None:
        app.add_api_route(
            RECOVERY_PRESTATE_ATTESTATION_PATH,
            recovery_prestate_attestation_work,
            methods=["POST"],
            include_in_schema=False,
        )
    return app


def protected_paths(role: ServiceRole) -> tuple[str, ...]:
    """Return the closed route set for deployment and local conformance checks."""

    return (protected_path(role),)


def _decode_api_command(
    body: bytes,
) -> (
    RootCreationCommandV1
    | ApplyCanaryCommandV1
    | PromotionCommandV2
    | ServiceClaimReleaseCommandV1
    | RecoveryAbandonmentCommandV1
    | StableSnapshotCaptureCommandV1
    | ExecutionReceiptReadCommandV1
    | TargetTrafficReadCommandV1
    | HealthEvaluationCommandV1
    | RecoveryCommandV2
    | EpochRevocationProofCommandV1
    | EpochRevocationCommandV1
):
    try:
        return decode_contract(body, RootCreationCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, ApplyCanaryCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, PromotionCommandV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, HealthEvaluationCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, RecoveryCommandV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, ServiceClaimReleaseCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, RecoveryAbandonmentCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, StableSnapshotCaptureCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, ExecutionReceiptReadCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, TargetTrafficReadCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, EpochRevocationProofCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    return decode_contract(body, EpochRevocationCommandV1)


def _decode_coordinator_invocation(
    body: bytes,
) -> (
    RootCreationInvocationV1
    | ApplyCanaryInvocationV1
    | PromotionInvocationV2
    | ServiceClaimReleaseInvocationV1
    | RecoveryAbandonmentInvocationV1
    | StableSnapshotCaptureInvocationV1
    | ExecutionReceiptReadInvocationV1
    | TargetTrafficReadInvocationV1
    | HealthEvaluationInvocationV1
    | RecoveryInvocationV2
    | EpochRevocationProofInvocationV1
    | EpochRevocationInvocationV1
):
    try:
        return decode_contract(body, RootCreationInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, ApplyCanaryInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, PromotionInvocationV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, HealthEvaluationInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, RecoveryInvocationV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, ServiceClaimReleaseInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, RecoveryAbandonmentInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, StableSnapshotCaptureInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, ExecutionReceiptReadInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, TargetTrafficReadInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, EpochRevocationProofInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    return decode_contract(body, EpochRevocationInvocationV1)


def _decode_verifier_request(
    body: bytes,
) -> (
    RootPreflightRequestV1
    | StableSnapshotCaptureRequestV1
    | TargetTrafficReadRequestV1
    | VerifierHealthEvaluationRequestV1
    | RecoveryPrestateRequestV1
    | IndependentVerificationInvocationV1
    | ServiceClaimClassificationRequestV1
    | RecoveryAbandonmentClassificationRequestV1
):
    try:
        return decode_contract(body, RootPreflightRequestV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, StableSnapshotCaptureRequestV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, TargetTrafficReadRequestV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, VerifierHealthEvaluationRequestV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, RecoveryPrestateRequestV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, IndependentVerificationInvocationV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, ServiceClaimClassificationRequestV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    return decode_contract(body, RecoveryAbandonmentClassificationRequestV1)


def _decode_issuance_command(
    body: bytes,
) -> (
    CapabilityIssuanceCommandV1
    | PromotionCapabilityIssuanceCommandV2
    | RecoveryCapabilityIssuanceCommandV2
):
    try:
        return decode_contract(body, CapabilityIssuanceCommandV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    try:
        return decode_contract(body, PromotionCapabilityIssuanceCommandV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    return decode_contract(body, RecoveryCapabilityIssuanceCommandV2)


def _decode_classification_signing_request(
    body: bytes,
) -> ServiceClaimClassificationSigningRequestV1 | RecoveryAbandonmentClassificationSigningRequestV1:
    try:
        return decode_contract(body, ServiceClaimClassificationSigningRequestV1)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    return decode_contract(body, RecoveryAbandonmentClassificationSigningRequestV1)


def _authentication_denial(
    code: AuthenticationDenialCode,
    correlation_id: str,
) -> JSONResponse:
    response = AuthenticationDenied(code=code, correlation_id=correlation_id)
    if code in {
        AuthenticationDenialCode.CONFIGURATION_INVALID,
        AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
    }:
        status_code = 503
    elif code is AuthenticationDenialCode.CALLER_DENIED:
        status_code = 403
    else:
        status_code = 401
    headers = {"X-ControlGraph-Correlation-Id": correlation_id}
    if status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers=headers,
    )


def _capability_denial(code: ReasonCode, correlation_id: str) -> JSONResponse:
    response = CapabilityDenied(code=code, correlation_id=correlation_id)
    status_code = 503 if code is ReasonCode.AUTHORITY_UNAVAILABLE else 403
    if code in {
        ReasonCode.CONTRACT_INVALID,
        ReasonCode.CONTRACT_VERSION_UNSUPPORTED,
    }:
        status_code = 400
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _evidence_signing_denial(code: str, correlation_id: str) -> JSONResponse:
    response = EvidenceSigningDenied(code=code, correlation_id=correlation_id)
    if code in {"CONTRACT_INVALID", "CONTRACT_VERSION_UNSUPPORTED"}:
        status_code = 400
    elif code in {
        EvidenceSigningErrorCode.CALLER_DENIED.value,
        EvidenceSigningErrorCode.TARGET_DENIED.value,
        EvidenceSigningErrorCode.ACTOR_DENIED.value,
    }:
        status_code = 403
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _health_attestation_denial(code: str, correlation_id: str) -> JSONResponse:
    response = EvidenceSigningDenied(code=code, correlation_id=correlation_id)
    if code in {"CONTRACT_INVALID", "CONTRACT_VERSION_UNSUPPORTED"}:
        status_code = 400
    elif code in {
        HealthAttestationErrorCode.CALLER_DENIED.value,
        HealthAttestationErrorCode.REQUEST_DENIED.value,
    }:
        status_code = 403
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _root_preflight_denial(code: str, correlation_id: str) -> JSONResponse:
    response = RootPreflightDenied(code=code, correlation_id=correlation_id)
    if code in {"CONTRACT_INVALID", "CONTRACT_VERSION_UNSUPPORTED"}:
        status_code = 400
    elif code in {
        RootPreflightErrorCode.CALLER_DENIED.value,
        RootPreflightErrorCode.REQUEST_DENIED.value,
    }:
        status_code = 403
    elif code in {
        RootPreflightErrorCode.STABLE_MISMATCH.value,
        RootPreflightErrorCode.CANDIDATE_DENIED.value,
    }:
        status_code = 409
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _root_creation_denial(code: str, correlation_id: str) -> JSONResponse:
    response = RootCreationDenied(code=code, correlation_id=correlation_id)
    if code in {"CONTRACT_INVALID", "CONTRACT_VERSION_UNSUPPORTED"}:
        status_code = 400
    elif code in {
        RootRelayErrorCode.CALLER_DENIED.value,
        RootRelayErrorCode.OPERATOR_DENIED.value,
        RootRelayErrorCode.COMMAND_DENIED.value,
    }:
        status_code = 403
    elif code in {
        RootRelayErrorCode.CREATION_CONFLICT.value,
        RootRelayErrorCode.CREATION_DENIED.value,
    }:
        status_code = 409
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _canary_execution_denial(code: str, correlation_id: str) -> JSONResponse:
    response = CanaryExecutionDenied(code=code, correlation_id=correlation_id)
    status_code = 503
    if code in {
        ContractErrorCode.INVALID.value,
        ContractErrorCode.VERSION_UNSUPPORTED.value,
    }:
        status_code = 400
    elif code in {
        CanaryExecutionErrorCode.CALLER_DENIED.value,
        CanaryExecutionErrorCode.OPERATOR_DENIED.value,
        CanaryExecutionErrorCode.COMMAND_DENIED.value,
        CanaryExecutionErrorCode.ISSUANCE_DENIED.value,
    }:
        status_code = 403
    elif code == CanaryExecutionErrorCode.IDENTITY_CONFLICT.value:
        status_code = 409
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _health_pipeline_denial(code: str, correlation_id: str) -> JSONResponse:
    response = HealthPipelineDenied(code=code, correlation_id=correlation_id)
    status_code = 503
    if code in {
        ContractErrorCode.INVALID.value,
        ContractErrorCode.VERSION_UNSUPPORTED.value,
    }:
        status_code = 400
    elif code in {
        HealthPipelineErrorCode.CALLER_DENIED.value,
        HealthPipelineErrorCode.OPERATOR_DENIED.value,
        HealthPipelineErrorCode.COMMAND_DENIED.value,
    }:
        status_code = 403
    elif code in {
        HealthPipelineErrorCode.AUTHORITY_STALE.value,
        HealthPipelineErrorCode.RECEIPT_INVALID.value,
        HealthPipelineErrorCode.STORE_CONFLICT.value,
        HealthPipelineErrorCode.EVALUATION_NOT_READY.value,
        HealthPipelineErrorCode.EVALUATION_TERMINAL.value,
        HealthPipelineErrorCode.TRUSTED_STATE_INVALID.value,
        HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID.value,
        HealthPipelineErrorCode.RESPONSE_INVALID.value,
        HealthPipelineErrorCode.RESULT_INVALID.value,
    }:
        status_code = 409
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _recovery_execution_denial(code: str, correlation_id: str) -> JSONResponse:
    response = CanaryExecutionDenied(code=code, correlation_id=correlation_id)
    status_code = 503
    if code in {
        ContractErrorCode.INVALID.value,
        ContractErrorCode.VERSION_UNSUPPORTED.value,
    }:
        status_code = 400
    elif code in {
        RecoveryExecutionErrorCode.CALLER_DENIED.value,
        RecoveryExecutionErrorCode.OPERATOR_DENIED.value,
        RecoveryExecutionErrorCode.COMMAND_DENIED.value,
        RecoveryExecutionErrorCode.ISSUANCE_DENIED.value,
    }:
        status_code = 403
    elif code in {
        RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID.value,
        RecoveryExecutionErrorCode.SOURCE_RECEIPT_INVALID.value,
        RecoveryExecutionErrorCode.TRIGGER_INVALID.value,
        RecoveryExecutionErrorCode.PRESTATE_MISMATCH.value,
        RecoveryExecutionErrorCode.ATTESTATION_INVALID.value,
        RecoveryExecutionErrorCode.IDENTITY_CONFLICT.value,
        RecoveryExecutionErrorCode.RESULT_INVALID.value,
    }:
        status_code = 409
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _epoch_revocation_denial(code: str, correlation_id: str) -> JSONResponse:
    response = EpochRevocationDenied(code=code, correlation_id=correlation_id)
    if code in {
        EpochRevocationFailureCode.CALLER_DENIED.value,
        EpochRevocationFailureCode.COMMAND_DENIED.value,
        EpochRevocationFailureCode.PROOF_DENIED.value,
    }:
        status_code = 403
    elif code in {
        EpochRevocationFailureCode.ROOT_NOT_FOUND.value,
        EpochRevocationFailureCode.ROOT_MISMATCH.value,
        EpochRevocationFailureCode.ACTIVE_CLAIM_REQUIRED.value,
        EpochRevocationFailureCode.EPOCH_MISMATCH.value,
        EpochRevocationFailureCode.IDENTITY_CONFLICT.value,
    }:
        status_code = 409
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _service_claim_release_denial(code: str, correlation_id: str) -> JSONResponse:
    response = ServiceClaimReleaseDenied(code=code, correlation_id=correlation_id)
    if code in {
        ServiceClaimReleaseFailureCode.CALLER_DENIED.value,
        ServiceClaimReleaseFailureCode.COMMAND_DENIED.value,
    }:
        status_code = 403
    elif code in {
        ServiceClaimReleaseFailureCode.ROOT_NOT_FOUND.value,
        ServiceClaimReleaseFailureCode.ROOT_MISMATCH.value,
        ServiceClaimReleaseFailureCode.CLAIM_NOT_ACTIVE.value,
        ServiceClaimReleaseFailureCode.EPOCH_MISMATCH.value,
        ServiceClaimReleaseFailureCode.TERMINAL_RECEIPT_INVALID.value,
        ServiceClaimReleaseFailureCode.IDENTITY_CONFLICT.value,
        ServiceClaimReleaseFailureCode.CLASSIFICATION_DENIED.value,
        ServiceClaimReleaseFailureCode.EVIDENCE_DENIED.value,
    }:
        status_code = 409
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _recovery_abandonment_denial(code: str, correlation_id: str) -> JSONResponse:
    response = RecoveryAbandonmentDenied(code=code, correlation_id=correlation_id)
    if code in {
        RecoveryAbandonmentFailureCode.CALLER_DENIED.value,
        RecoveryAbandonmentFailureCode.COMMAND_DENIED.value,
    }:
        status_code = 403
    elif code in {
        RecoveryAbandonmentFailureCode.ROOT_NOT_FOUND.value,
        RecoveryAbandonmentFailureCode.ROOT_MISMATCH.value,
        RecoveryAbandonmentFailureCode.CLAIM_NOT_ACTIVE.value,
        RecoveryAbandonmentFailureCode.EPOCH_MISMATCH.value,
        RecoveryAbandonmentFailureCode.INTENT_INVALID.value,
        RecoveryAbandonmentFailureCode.DISPATCH_INVALID.value,
        RecoveryAbandonmentFailureCode.DISPATCH_NOT_EXPIRED.value,
        RecoveryAbandonmentFailureCode.RECEIPT_EXISTS.value,
        RecoveryAbandonmentFailureCode.IDENTITY_CONFLICT.value,
        RecoveryAbandonmentFailureCode.CLASSIFICATION_DENIED.value,
        RecoveryAbandonmentFailureCode.EVIDENCE_DENIED.value,
    }:
        status_code = 409
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _service_claim_classification_denial(
    code: str,
    correlation_id: str,
) -> JSONResponse:
    response = ServiceClaimClassificationDenied(
        code=code,
        correlation_id=correlation_id,
    )
    if code in {
        ContractErrorCode.INVALID.value,
        ContractErrorCode.VERSION_UNSUPPORTED.value,
    }:
        status_code = 400
    elif code in {
        ServiceClaimClassificationErrorCode.CALLER_DENIED.value,
        ServiceClaimClassificationErrorCode.REQUEST_DENIED.value,
    }:
        status_code = 403
    elif code == ServiceClaimClassificationErrorCode.TARGET_MISMATCH.value:
        status_code = 409
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _independent_verification_denial(
    code: str,
    correlation_id: str,
) -> JSONResponse:
    response = IndependentVerificationDenied(
        code=code,
        correlation_id=correlation_id,
    )
    if code in {
        ContractErrorCode.INVALID.value,
        ContractErrorCode.VERSION_UNSUPPORTED.value,
    }:
        status_code = 400
    elif code in {
        IndependentVerificationErrorCode.CALLER_DENIED.value,
        IndependentVerificationErrorCode.REQUEST_DENIED.value,
    }:
        status_code = 403
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _receipt_authority_denial(code: str, correlation_id: str) -> JSONResponse:
    response = CanaryExecutionDenied(code=code, correlation_id=correlation_id)
    return JSONResponse(
        status_code=400 if code == "CONTRACT_INVALID" else 503,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _operator_observation_denial(code: str, correlation_id: str) -> JSONResponse:
    response = OperatorObservationDenied(code=code, correlation_id=correlation_id)
    if code in {
        OperatorObservationErrorCode.CALLER_DENIED.value,
        OperatorObservationErrorCode.OPERATOR_DENIED.value,
        OperatorObservationErrorCode.COMMAND_DENIED.value,
        OperatorObservationErrorCode.TARGET_DENIED.value,
    }:
        status_code = 403
    elif code == OperatorObservationErrorCode.RECEIPT_NOT_FOUND.value:
        status_code = 404
    elif code in {
        OperatorObservationErrorCode.CAPTURE_DENIED.value,
        OperatorObservationErrorCode.TARGET_STATE_DENIED.value,
    }:
        status_code = 409
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _timeline_denial(code: str, correlation_id: str) -> JSONResponse:
    response = TimelineDenied(code=code, correlation_id=correlation_id)
    if code in {
        TimelineReadErrorCode.CURSOR_INVALID.value,
        TimelineRawExportErrorCode.CURSOR_INVALID.value,
    }:
        status_code = 400
    elif code in {
        TimelineReadErrorCode.ACCESS_DENIED.value,
        TimelineReadErrorCode.TARGET_DENIED.value,
        TimelineRawExportErrorCode.ACCESS_DENIED.value,
        TimelineRawExportErrorCode.TARGET_DENIED.value,
    }:
        status_code = 403
    else:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
        headers={
            "Cache-Control": "no-store",
            "X-ControlGraph-Correlation-Id": correlation_id,
        },
    )


async def _read_contract_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if type(chunk) is not bytes or len(body) + len(chunk) > MAX_CONTRACT_BYTES:
            raise _deny_contract()
        body.extend(chunk)
    if not body:
        raise _deny_contract()
    return bytes(body)


def _deny_contract() -> CapabilityVerificationError:
    return CapabilityVerificationError(ReasonCode.CONTRACT_INVALID)


def _correlation_id() -> str:
    return uuid.uuid4().hex


def _emit_service_event(
    *,
    role: ServiceRole,
    status_code: int,
    correlation_id: str,
) -> None:
    event = {
        "correlation_id": correlation_id,
        "event": "controlgraph.service.request",
        "service_role": role.value,
        "status_code": status_code,
    }
    sys.stderr.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stderr.flush()


__all__ = [
    "PRODUCT_CONTRACT_VERSION",
    "SERVICE_SHELL_VERSION",
    "AuthenticationDenied",
    "CapabilityDenied",
    "DisabledWork",
    "EvidenceSigningDenied",
    "IndependentVerificationDenied",
    "OperatorObservationDenied",
    "RecoveryAbandonmentDenied",
    "RootCreationDenied",
    "RootPreflightDenied",
    "ServiceClaimClassificationDenied",
    "ServiceClaimReleaseDenied",
    "ServiceHealth",
    "ServiceMetadata",
    "ServiceRole",
    "TimelineDenied",
    "VerifiedTaskHandler",
    "create_service_app",
    "protected_paths",
]
