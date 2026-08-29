"""Runtime composition for authenticated role-specific service applications."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, cast

from fastapi import FastAPI

from controlgraph_canary.application.authority_store import AuthorityStore
from controlgraph_canary.application.canary_execution import (
    ApiCanaryClient,
    CanaryRolloutCoordinator,
    CapabilityIssuanceService,
    CoordinatorCanaryRelay,
    CoordinatorCapabilityClient,
)
from controlgraph_canary.application.capability_issuance import (
    CapabilityIssuer,
    CapabilityIssuerConfiguration,
    TrustBundleCapabilityVerifier,
)
from controlgraph_canary.application.capability_verification import (
    CapabilityVerifier,
    CapabilityVerifierConfiguration,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunMutationPurpose,
    CloudRunTargetConfiguration,
)
from controlgraph_canary.application.completion_classification import (
    CoordinatorCompletionClassificationService,
)
from controlgraph_canary.application.completion_workflow import (
    CompletionAuthorityEvidenceVerifier,
    CompletionAuthorityReader,
    CoordinatorCompletionWorkflow,
)
from controlgraph_canary.application.evidence_signing import EvidenceSigningService
from controlgraph_canary.application.execution import FinalMutationGate
from controlgraph_canary.application.health_attestation import (
    HealthAttestationSigningService,
    VerifierHealthAttestationClient,
)
from controlgraph_canary.application.health_orchestration import (
    VerifierHealthProofService,
)
from controlgraph_canary.application.health_pipeline import (
    ApiHealthEvaluationClient,
    CoordinatorHealthEvaluationClient,
    CoordinatorHealthEvaluationService,
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
    TIMELINE_RETENTION_PATH,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
    runtime_route_policy,
    runtime_service_name,
)
from controlgraph_canary.application.independent_verification import (
    IndependentVerificationService,
)
from controlgraph_canary.application.independent_verification_signing import (
    CoordinatorIndependentVerificationClient,
    IndependentVerificationSigningService,
    VerifierIndependentVerificationEvidenceClient,
)
from controlgraph_canary.application.model_assistance import (
    ApiAdvisorClient,
    CoordinatorAdvisorClient,
    CoordinatorAdvisorWorkflow,
    DiagnosticSnapshotAssembler,
    ModelAssistanceAuditStore,
    ModelAssistanceTimelineRecorder,
)
from controlgraph_canary.application.model_assistance_m6 import (
    M6DiagnosticSnapshotAssembler,
)
from controlgraph_canary.application.operator_observability import (
    ApiOperatorObservationClient,
    CoordinatorOperatorObservationRelay,
    CoordinatorStableSnapshotClient,
    CoordinatorTargetTrafficClient,
    ExecutionReceiptObservationStore,
    StableSnapshotCaptureService,
    TargetTrafficObservationService,
)
from controlgraph_canary.application.promotion_execution import (
    ApiPromotionClient,
    CoordinatorPromotionCapabilityClient,
    CoordinatorPromotionRelay,
    PromotionRolloutCoordinator,
    StoredPromotionAuthorizationResolver,
)
from controlgraph_canary.application.promotion_store import PromotionDispatchStoreV2
from controlgraph_canary.application.receipt_authority import (
    ReceiptAuthorityClient,
    ReceiptAuthorityService,
)
from controlgraph_canary.application.receipt_execution import (
    ReceiptClassifyingMutationAdapter,
    ReceiptExecutionCoordinator,
    RecoveryExecutorFacade,
    RecoveryTaskForwarder,
)
from controlgraph_canary.application.recovery_abandonment import (
    RecoveryAbandoner,
    RecoveryAbandonmentClassificationClient,
)
from controlgraph_canary.application.recovery_abandonment_relay import (
    ApiRecoveryAbandonmentClient,
    CoordinatorRecoveryAbandonmentRelay,
)
from controlgraph_canary.application.recovery_abandonment_store import (
    RecoveryAbandonmentStore,
)
from controlgraph_canary.application.recovery_execution import (
    ApiRecoveryClient,
    CoordinatorRecoveryCapabilityClient,
    CoordinatorRecoveryPrestateClient,
    CoordinatorRecoveryRelay,
    RecoveryPrestateSigningService,
    RecoveryRolloutCoordinator,
    StoredRecoveryAuthorizationResolver,
    VerifierRecoveryPrestateAttestationClient,
    VerifierRecoveryPrestateService,
)
from controlgraph_canary.application.recovery_store import RecoveryDispatchStore
from controlgraph_canary.application.revocation import EpochRevoker
from controlgraph_canary.application.revocation_proof import EpochRevocationProofService
from controlgraph_canary.application.revocation_relay import (
    ApiEpochRevocationClient,
    CoordinatorEpochRevocationRelay,
)
from controlgraph_canary.application.revocation_store import (
    EpochRevocationProofStore,
    EpochRevocationStore,
)
from controlgraph_canary.application.root_creation import RootCreationConfiguration
from controlgraph_canary.application.root_creation_service import RolloutRootCreator
from controlgraph_canary.application.root_relay import (
    ApiRootCreationClient,
    CoordinatorRootCreationRelay,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorEvidenceClient,
    CoordinatorInternalRoute,
    CoordinatorRootPreflightClient,
    RootPreflightService,
)
from controlgraph_canary.application.service_claim_classification import (
    CoordinatorServiceClaimClassificationClient,
    ServiceClaimClassificationService,
)
from controlgraph_canary.application.service_claim_classification_signing import (
    ClassificationEvidenceSigningService,
    VerifierClassificationEvidenceClient,
)
from controlgraph_canary.application.service_claim_release import ServiceClaimReleaser
from controlgraph_canary.application.service_claim_release_relay import (
    ApiServiceClaimReleaseClient,
    CoordinatorServiceClaimReleaseRelay,
)
from controlgraph_canary.application.service_claim_release_store import (
    ServiceClaimReleaseStore,
)
from controlgraph_canary.application.signing import (
    AsyncPurposeSealedSigner,
    PurposeSealedSigner,
    SigningProfile,
)
from controlgraph_canary.application.tasks import (
    TaskAddressor,
    TaskDeliverySettings,
    TaskDispatcher,
    TaskEnqueuer,
)
from controlgraph_canary.application.timeline import (
    TimelineRawExportService,
    TimelineReadService,
    TimelineRetentionService,
    TimelineWriteGrant,
    TimelineWriteService,
)
from controlgraph_canary.application.timeline_recording import TimelineRecorder
from controlgraph_canary.application.timeline_relay import (
    ApiTimelineClient,
    CoordinatorTimelineRelay,
)
from controlgraph_canary.contracts.health import (
    RolloutHealthPolicyV2,
    create_rollout_health_policy_v2,
)
from controlgraph_canary.contracts.health_execution import PostApplyHealthAnchorV1
from controlgraph_canary.contracts.independent_verification import VerificationRequestV1
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.operator_observability import (
    STABLE_SNAPSHOT_CAPTURE_REQUEST_V1,
    StableSnapshotCaptureRequestV1,
    TargetTrafficReadRequestV1,
)
from controlgraph_canary.contracts.recovery_abandonment import (
    RecoveryAbandonmentClassificationRequestV1,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV3
from controlgraph_canary.contracts.root_trust import RootPreflightRequestV1
from controlgraph_canary.contracts.service_claim_release import (
    ServiceClaimClassificationRequestV1,
)
from controlgraph_canary.contracts.timeline import (
    TimelineActorRole,
    standard_timeline_evidence_policy_set,
)
from controlgraph_canary.http.receipt import (
    RecoveryExecutorClient,
    RecoveryExecutorFacadeHandler,
    create_receipt_task_handler,
    create_recovery_executor_facade_handler,
    create_recovery_forwarding_task_handler,
)
from controlgraph_canary.http.service import create_service_app
from controlgraph_canary.integrations.google.identity import (
    GoogleIdentityVerifier,
    IdentityTokenVerifier,
)
from controlgraph_canary.integrations.google.internal_transport import (
    GoogleOneShotOidcTransport,
)
from controlgraph_canary.integrations.google.kms import (
    GoogleKmsAsyncDigestSigner,
    GoogleKmsCapabilityTrustLoader,
    GoogleKmsDigestSigner,
    GoogleKmsEvidenceSignatureVerifier,
    GoogleKmsHealthAttestationVerifier,
    GoogleKmsIndependentVerificationEvidenceVerifier,
    GoogleKmsRecoveryPrestateAttestationVerifier,
)
from controlgraph_canary.integrations.google.probe_transport import (
    GoogleSealedProbeTransport,
)
from controlgraph_canary.integrations.google.tasks import GoogleCloudTasksEnqueuer
from controlgraph_canary.settings import ControllerSettings

if TYPE_CHECKING:
    from controlgraph_canary.integrations.google.cloud_run import (
        CloudRunV2SnapshotReader,
        ReadOnlyServicesClientFactory,
        RevisionsClientFactory,
        ServicesClientFactory,
    )


@dataclass(frozen=True, slots=True)
class CoordinatorTrustClients:
    """Coordinator-only clients for verifier preflight and evidence signing."""

    preflight: CoordinatorRootPreflightClient
    evidence: CoordinatorEvidenceClient


def create_runtime_service_app(
    role: ServiceRole,
    *,
    environment: Mapping[str, str] | None = None,
    token_verifier: IdentityTokenVerifier | None = None,
    clock: Callable[[], float] | None = None,
    kms_client: object | None = None,
    internal_transport: CanonicalInternalTransport | None = None,
    preflight_clock: Callable[[], datetime] | None = None,
    classification_clock: Callable[[], datetime] | None = None,
    services_client_factory: ServicesClientFactory | None = None,
    revisions_client_factory: RevisionsClientFactory | None = None,
    readback_services_client_factory: ReadOnlyServicesClientFactory | None = None,
    authority_store: AuthorityStore | None = None,
    root_creation_clock: Callable[[], datetime] | None = None,
    service_claim_release_clock: Callable[[], datetime] | None = None,
    recovery_abandonment_clock: Callable[[], datetime] | None = None,
    capability_issuance_clock: Callable[[], datetime] | None = None,
    canary_clock: Callable[[], datetime] | None = None,
    promotion_clock: Callable[[], datetime] | None = None,
    task_enqueuer: TaskEnqueuer | None = None,
    final_authority_clock: Callable[[], datetime] | None = None,
    receipt_clock: Callable[[], datetime] | None = None,
    capability_verification_clock: Callable[[], datetime] | None = None,
    revocation_clock: Callable[[], datetime] | None = None,
    revocation_attempt_id_factory: Callable[[], str] | None = None,
    health_evaluation_clock: Callable[[], datetime] | None = None,
    recovery_clock: Callable[[], datetime] | None = None,
    diagnostic_snapshot_assembler: DiagnosticSnapshotAssembler | None = None,
    model_assistance_audit_store: ModelAssistanceAuditStore | None = None,
    model_assistance_timeline: ModelAssistanceTimelineRecorder | None = None,
) -> FastAPI:
    """Compose a fail-closed service from validated startup coordinates."""

    source = os.environ if environment is None else environment
    settings = ControllerSettings.from_environment(source)
    if settings.role != role.value:
        raise ValueError("runtime role does not match the service composition root")
    if kms_client is not None and role not in {
        ServiceRole.EVIDENCE_WRITER,
        ServiceRole.COORDINATOR,
        ServiceRole.ISSUER,
        ServiceRole.EXECUTOR,
        ServiceRole.RECOVERY,
        ServiceRole.VERIFIER,
    }:
        raise ValueError("KMS dependencies are limited to signing and trust roles")
    policy = runtime_route_policy(role, source)
    authenticator = GoogleIdentityVerifier(
        verifier=token_verifier,
        clock=clock,
        operator_oauth_client_audience=(
            settings.operator_oauth_client_audience if role is ServiceRole.API else None
        ),
    )
    evidence_signing_service = None
    classification_evidence_signing_service = None
    classification_evidence_authentication_policy = None
    independent_verification_signing_service = None
    independent_verification_evidence_authentication_policy = None
    health_attestation_signing_service = None
    health_attestation_authentication_policy = None
    recovery_prestate_signing_service = None
    recovery_prestate_authentication_policy = None
    root_preflight_service = None
    stable_snapshot_capture_service = None
    target_traffic_observation_service = None
    service_claim_classification_service = None
    independent_verification_service = None
    coordinator_clients = None
    coordinator_independent_verification_client = None
    coordinator_completion_classification_service = None
    coordinator_completion_workflow = None
    coordinator_advisor_client = None
    coordinator_advisor_workflow = None
    api_advisor_client = None
    api_root_creation_client = None
    coordinator_root_creation_relay = None
    api_operator_observation_client = None
    coordinator_operator_observation_relay = None
    service_claim_releaser = None
    api_service_claim_release_client = None
    coordinator_service_claim_release_relay = None
    recovery_abandoner = None
    api_recovery_abandonment_client = None
    coordinator_recovery_abandonment_relay = None
    api_canary_client = None
    coordinator_canary_relay = None
    api_promotion_client = None
    coordinator_promotion_relay = None
    api_health_evaluation_client = None
    coordinator_health_evaluation_service = None
    verifier_health_evaluation_service = None
    api_recovery_client = None
    coordinator_recovery_relay = None
    verifier_recovery_prestate_service = None
    api_epoch_revocation_client = None
    coordinator_epoch_revocation_relay = None
    capability_issuance_service = None
    receipt_authority_service = None
    receipt_authority_authentication_policy = None
    recovery_receipt_authority_authentication_policy = None
    capability_verifier = None
    verified_task_handler = None
    recovery_executor_facade_handler: RecoveryExecutorFacadeHandler | None = None
    recovery_executor_facade_authentication_policy = None
    timeline_read_service = None
    timeline_raw_export_service = None
    timeline_retention_service = None
    timeline_retention_authentication_policy = None
    timeline_recorder = None
    coordinator_timeline_relay = None
    if role is ServiceRole.EVIDENCE_WRITER:
        if settings.evidence_key_version is None or settings.signing_algorithm is None:
            raise ValueError("evidence-writer signing configuration is incomplete")
        profile = SigningProfile.evidence(settings.project_id, settings.evidence_key_version)
        if settings.signing_algorithm != profile.algorithm:
            raise ValueError("evidence-writer signing algorithm is invalid")
        evidence_signing_backend = GoogleKmsAsyncDigestSigner(
            profile,
            client=kms_client,
        )
        evidence_signer = AsyncPurposeSealedSigner(evidence_signing_backend)
        evidence_signing_service = EvidenceSigningService(
            project_id=settings.project_id,
            authentication_policy=policy,
            signer=evidence_signer,
        )
        classification_evidence_authentication_policy = _classification_evidence_policy(settings)
        classification_evidence_signing_service = ClassificationEvidenceSigningService(
            project_id=settings.project_id,
            authentication_policy=(classification_evidence_authentication_policy),
            signer=evidence_signer,
        )
        independent_verification_evidence_authentication_policy = (
            _independent_verification_evidence_policy(settings)
        )
        independent_verification_signing_service = (
            IndependentVerificationSigningService(
                project_id=settings.project_id,
                authentication_policy=(
                    independent_verification_evidence_authentication_policy
                ),
                signer=evidence_signing_backend,
            )
        )
        health_attestation_authentication_policy = _health_attestation_policy(settings)
        health_attestation_signing_service = HealthAttestationSigningService(
            project_id=settings.project_id,
            authentication_policy=health_attestation_authentication_policy,
            signer=evidence_signing_backend,
            signature_verifier=GoogleKmsHealthAttestationVerifier(
                project_id=settings.project_id,
                service_role=ServiceRole.EVIDENCE_WRITER,
                key_version=settings.evidence_key_version,
                client=kms_client,
            ),
        )
        recovery_prestate_authentication_policy = _recovery_prestate_policy(settings)
        recovery_prestate_signing_service = RecoveryPrestateSigningService(
            project_id=settings.project_id,
            authentication_policy=recovery_prestate_authentication_policy,
            signer=evidence_signing_backend,
        )
    elif role is ServiceRole.VERIFIER:
        from controlgraph_canary.integrations.google.cloud_run import (
            CloudRunV2SnapshotReader,
        )
        from controlgraph_canary.integrations.google.monitoring import (
            GoogleCloudMonitoringCollector,
        )

        if (
            settings.target_network_resource is None
            or settings.target_subnetwork_resource is None
            or settings.evidence_writer_url is None
            or settings.evidence_key_version is None
            or settings.reference_target_url is None
        ):
            raise ValueError("verifier preflight configuration is incomplete")
        target_network_resource = settings.target_network_resource
        target_subnetwork_resource = settings.target_subnetwork_resource
        target = TargetBinding(
            schema_version="controlgraph.target-binding/v1",
            project_id=settings.project_id,
            region=settings.region,
            environment=settings.environment,
            service_name="controlgraph-reference-target",
        )

        def reader_factory(
            request: RootPreflightRequestV1,
        ) -> CloudRunV2SnapshotReader:
            return CloudRunV2SnapshotReader(
                configuration=CloudRunTargetConfiguration(
                    target=target,
                    stable_revision=request.expected_stable_snapshot.stable_revision,
                    candidate_revision=request.candidate_revision,
                    stable_concurrency=request.concurrency,
                    candidate_concurrency=request.concurrency,
                    network_resource=target_network_resource,
                    subnetwork_resource=target_subnetwork_resource,
                ),
                service_role=ServiceRole.VERIFIER,
                configured_project_id=settings.project_id,
                services_client_factory=services_client_factory,
                revisions_client_factory=revisions_client_factory,
            )

        root_preflight_service = RootPreflightService(
            target=target,
            authentication_policy=policy,
            reader_factory=reader_factory,
            clock=preflight_clock,
        )

        def capture_reader_factory(
            request: StableSnapshotCaptureRequestV1,
        ) -> CloudRunV2SnapshotReader:
            if request.target != target:
                raise ValueError("snapshot capture target is not configured")
            return CloudRunV2SnapshotReader(
                configuration=CloudRunTargetConfiguration(
                    target=target,
                    stable_revision="controlgraph-reference-target-stable-v21",
                    candidate_revision="controlgraph-reference-target-candidate-v21",
                    stable_concurrency=8,
                    candidate_concurrency=8,
                    network_resource=target_network_resource,
                    subnetwork_resource=target_subnetwork_resource,
                ),
                service_role=ServiceRole.VERIFIER,
                configured_project_id=settings.project_id,
                services_client_factory=services_client_factory,
                revisions_client_factory=revisions_client_factory,
            )

        stable_snapshot_capture_service = StableSnapshotCaptureService(
            target=target,
            authentication_policy=policy,
            reader_factory=capture_reader_factory,
            clock=preflight_clock,
        )

        def traffic_reader_factory(
            request: TargetTrafficReadRequestV1,
        ) -> CloudRunV2SnapshotReader:
            if (
                request.target != target
                or request.stable_revision != "controlgraph-reference-target-stable-v21"
                or request.candidate_revision != "controlgraph-reference-target-candidate-v21"
                or request.concurrency != 8
            ):
                raise ValueError("target traffic request is not configured")
            return capture_reader_factory(
                StableSnapshotCaptureRequestV1(
                    schema_version=STABLE_SNAPSHOT_CAPTURE_REQUEST_V1,
                    request_id=request.request_id,
                    target=request.target,
                )
            )

        target_traffic_observation_service = TargetTrafficObservationService(
            target=target,
            authentication_policy=policy,
            reader_factory=traffic_reader_factory,
            clock=preflight_clock,
        )
        selected_transport = (
            internal_transport
            if internal_transport is not None
            else GoogleOneShotOidcTransport(
                project_id=settings.project_id,
                caller_role=CallerRole.VERIFIER,
            )
        )
        health_attestation_verifier = GoogleKmsHealthAttestationVerifier(
            project_id=settings.project_id,
            service_role=ServiceRole.VERIFIER,
            key_version=settings.evidence_key_version,
            client=kms_client,
        )
        health_attestor = VerifierHealthAttestationClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.VERIFIER,
                service_role=ServiceRole.EVIDENCE_WRITER,
                audience=settings.evidence_writer_url,
                override_path=HEALTH_ATTESTATION_PATH,
            ),
            transport=selected_transport,
            signing_key_version=settings.evidence_key_version,
        )
        health_query_collector = GoogleCloudMonitoringCollector(
            target=target,
            service_role=ServiceRole.VERIFIER,
            configured_project_id=settings.project_id,
        )

        def health_proof_service_factory(
            *,
            root: RolloutRootV3,
            anchor: PostApplyHealthAnchorV1,
        ) -> VerifierHealthProofService:
            return VerifierHealthProofService(
                root=root,
                anchor=anchor,
                query_collector=health_query_collector,
                attestor=health_attestor,
                signature_verifier=health_attestation_verifier,
                clock=health_evaluation_clock,
            )

        verifier_health_evaluation_service = VerifierHealthEvaluationService(
            target=target,
            authentication_policy=policy,
            proof_service_factory=health_proof_service_factory,
        )
        recovery_prestate_verifier = GoogleKmsRecoveryPrestateAttestationVerifier(
            project_id=settings.project_id,
            service_role=ServiceRole.VERIFIER,
            key_version=settings.evidence_key_version,
            client=kms_client,
        )
        recovery_prestate_attestor = VerifierRecoveryPrestateAttestationClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.VERIFIER,
                service_role=ServiceRole.EVIDENCE_WRITER,
                audience=settings.evidence_writer_url,
                override_path=RECOVERY_PRESTATE_ATTESTATION_PATH,
            ),
            transport=selected_transport,
            signing_key_version=settings.evidence_key_version,
        )
        verifier_recovery_prestate_service = VerifierRecoveryPrestateService(
            target=target,
            authentication_policy=policy,
            reader=CloudRunV2SnapshotReader(
                configuration=CloudRunTargetConfiguration(
                    target=target,
                    stable_revision="controlgraph-reference-target-stable-v21",
                    candidate_revision="controlgraph-reference-target-candidate-v21",
                    stable_concurrency=8,
                    candidate_concurrency=8,
                    network_resource=target_network_resource,
                    subnetwork_resource=target_subnetwork_resource,
                ),
                service_role=ServiceRole.VERIFIER,
                configured_project_id=settings.project_id,
                services_client_factory=services_client_factory,
                revisions_client_factory=revisions_client_factory,
            ),
            attestor=recovery_prestate_attestor,
            signature_verifier=recovery_prestate_verifier,
            clock=preflight_clock,
        )

        def classification_reader_factory(
            request: (
                ServiceClaimClassificationRequestV1 | RecoveryAbandonmentClassificationRequestV1
            ),
        ) -> CloudRunV2SnapshotReader:
            return CloudRunV2SnapshotReader(
                configuration=CloudRunTargetConfiguration(
                    target=target,
                    stable_revision=request.stable_revision,
                    candidate_revision=request.candidate_revision,
                    stable_concurrency=request.concurrency,
                    candidate_concurrency=request.concurrency,
                    network_resource=target_network_resource,
                    subnetwork_resource=target_subnetwork_resource,
                ),
                service_role=ServiceRole.VERIFIER,
                configured_project_id=settings.project_id,
                services_client_factory=services_client_factory,
                revisions_client_factory=revisions_client_factory,
            )

        service_claim_classification_service = ServiceClaimClassificationService(
            authentication_policy=policy,
            reader_factory=classification_reader_factory,
            evidence_client=VerifierClassificationEvidenceClient(
                route=CoordinatorInternalRoute(
                    project_id=settings.project_id,
                    project_number=settings.project_number,
                    caller_role=CallerRole.VERIFIER,
                    service_role=ServiceRole.EVIDENCE_WRITER,
                    audience=settings.evidence_writer_url,
                    override_path=CLASSIFICATION_EVIDENCE_PATH,
                ),
                evidence_key_version=settings.evidence_key_version,
                transport=selected_transport,
            ),
            clock=classification_clock,
        )

        def independent_reader_factory(
            request: VerificationRequestV1,
        ) -> CloudRunV2SnapshotReader:
            if (
                request.target != target
                or request.stable_revision
                != "controlgraph-reference-target-stable-v21"
                or request.candidate_revision
                != "controlgraph-reference-target-candidate-v21"
                or request.concurrency != 8
            ):
                raise ValueError("independent verification request is not configured")
            return CloudRunV2SnapshotReader(
                configuration=CloudRunTargetConfiguration(
                    target=target,
                    stable_revision=request.stable_revision,
                    candidate_revision=request.candidate_revision,
                    stable_concurrency=request.concurrency,
                    candidate_concurrency=request.concurrency,
                    network_resource=target_network_resource,
                    subnetwork_resource=target_subnetwork_resource,
                ),
                service_role=ServiceRole.VERIFIER,
                configured_project_id=settings.project_id,
                services_client_factory=services_client_factory,
                revisions_client_factory=revisions_client_factory,
            )

        independent_verification_service = IndependentVerificationService(
            target=target,
            authentication_policy=policy,
            reader_factory=independent_reader_factory,
            probe_transport=GoogleSealedProbeTransport(
                target=target,
                endpoint=f"{settings.reference_target_url}/v1/probe",
            ),
            evidence_client=VerifierIndependentVerificationEvidenceClient(
                route=CoordinatorInternalRoute(
                    project_id=settings.project_id,
                    project_number=settings.project_number,
                    caller_role=CallerRole.VERIFIER,
                    service_role=ServiceRole.EVIDENCE_WRITER,
                    audience=settings.evidence_writer_url,
                    override_path=INDEPENDENT_VERIFICATION_EVIDENCE_PATH,
                ),
                transport=selected_transport,
                signing_key_version=settings.evidence_key_version,
            ),
            clock=preflight_clock,
        )
    elif role is ServiceRole.API:
        if settings.coordinator_url is None:
            raise ValueError("API root-creation relay configuration is incomplete")
        timeline_target = _reference_target(settings)
        selected_transport = (
            internal_transport
            if internal_transport is not None
            else GoogleOneShotOidcTransport(
                project_id=settings.project_id,
                caller_role=CallerRole.API,
                timeout_seconds=45.0,
            )
        )
        timeline_client = ApiTimelineClient(
            target=timeline_target,
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                caller_role=CallerRole.API,
                project_number=settings.project_number,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            operator_policy=_operator_timeline_policy(policy, TIMELINE_READ_PATH),
            security_audit_policy=_security_audit_timeline_policy(settings),
            restricted_export_policy=_restricted_export_timeline_policy(settings),
            transport=selected_transport,
        )
        timeline_read_service = timeline_client
        timeline_raw_export_service = timeline_client
        api_root_creation_client = ApiRootCreationClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
        api_operator_observation_client = ApiOperatorObservationClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
        api_canary_client = ApiCanaryClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
        api_promotion_client = ApiPromotionClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
        api_health_evaluation_client = ApiHealthEvaluationClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
        api_recovery_client = ApiRecoveryClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
        api_epoch_revocation_client = ApiEpochRevocationClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
            attempt_id_factory=revocation_attempt_id_factory,
        )
        api_service_claim_release_client = ApiServiceClaimReleaseClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
        api_recovery_abandonment_client = ApiRecoveryAbandonmentClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
        api_advisor_client = ApiAdvisorClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
            ),
            authentication_policy=policy,
            transport=selected_transport,
        )
    elif role is ServiceRole.ISSUER:
        from controlgraph_canary.integrations.google.firestore import (
            FirestoreAuthorityStore,
        )
        from controlgraph_canary.integrations.google.firestore_health import (
            FirestoreHealthChainReader,
        )

        if (
            settings.capability_key_version is None
            or settings.evidence_key_version is None
            or settings.recovery_url is None
        ):
            raise ValueError("issuer capability-signing configuration is incomplete")
        target = _reference_target(settings)
        selected_store = (
            authority_store
            if authority_store is not None
            else FirestoreAuthorityStore(
                target=target,
                configured_project_id=settings.project_id,
            )
        )
        signer = PurposeSealedSigner(
            GoogleKmsDigestSigner(
                SigningProfile.capability(
                    settings.project_id,
                    settings.capability_key_version,
                ),
                client=kms_client,
            )
        )
        health_chain_reader = FirestoreHealthChainReader(
            target=target,
            configured_project_id=settings.project_id,
            service_role=ServiceRole.ISSUER,
        )
        capability_issuance_service = CapabilityIssuanceService(
            issuer=CapabilityIssuer(
                store=selected_store,
                signer=signer,
                configuration=CapabilityIssuerConfiguration(
                    target=target,
                    handler_audience=_service_audience(
                        ServiceRole.EXECUTOR,
                        settings.project_number,
                    ),
                    recovery_handler_audience=settings.recovery_url,
                ),
                receipt_reader=selected_store,
                promotion_health_chain_reader=health_chain_reader,
                health_signature_verifier=GoogleKmsHealthAttestationVerifier(
                    project_id=settings.project_id,
                    service_role=ServiceRole.ISSUER,
                    key_version=settings.evidence_key_version,
                    client=kms_client,
                ),
                recovery_intent_reader=health_chain_reader,
                recovery_health_chain_reader=health_chain_reader,
                recovery_prestate_verifier=(
                    GoogleKmsRecoveryPrestateAttestationVerifier(
                        project_id=settings.project_id,
                        service_role=ServiceRole.ISSUER,
                        key_version=settings.evidence_key_version,
                        client=kms_client,
                    )
                ),
                revocation_evidence_verifier=GoogleKmsEvidenceSignatureVerifier(
                    project_id=settings.project_id,
                    service_role=ServiceRole.ISSUER,
                    key_version=settings.evidence_key_version,
                    client=kms_client,
                ),
            ),
            authentication_policy=policy,
            clock=capability_issuance_clock,
        )
    elif role is ServiceRole.EXECUTOR and settings.mutations_enabled:
        from controlgraph_canary.integrations.google.cloud_run import (
            CloudRunV2Adapter,
            CloudRunV2ReceiptReadback,
        )
        from controlgraph_canary.integrations.google.firestore import (
            FirestoreAuthorityStore,
        )

        if (
            settings.capability_key_version is None
            or settings.evidence_key_version is None
            or settings.coordinator_url is None
            or settings.target_network_resource is None
            or settings.target_subnetwork_resource is None
            or settings.recovery_facade_caller_identity is None
            or settings.recovery_facade_caller_subject is None
        ):
            raise ValueError("executor mutation configuration is incomplete")
        target = _reference_target(settings)
        selected_store = (
            authority_store
            if authority_store is not None
            else FirestoreAuthorityStore(
                target=target,
                configured_project_id=settings.project_id,
            )
        )
        selected_transport = (
            internal_transport
            if internal_transport is not None
            else GoogleOneShotOidcTransport(
                project_id=settings.project_id,
                caller_role=CallerRole.EXECUTOR,
            )
        )
        receipt_store = ReceiptAuthorityClient(
            target=target,
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.EXECUTOR,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
                override_path=RECEIPT_AUTHORITY_PATH,
            ),
            transport=selected_transport,
        )
        cloud_run_configuration = CloudRunTargetConfiguration(
            target=target,
            stable_revision="controlgraph-reference-target-stable-v21",
            candidate_revision="controlgraph-reference-target-candidate-v21",
            stable_concurrency=8,
            candidate_concurrency=8,
            network_resource=settings.target_network_resource,
            subnetwork_resource=settings.target_subnetwork_resource,
        )
        mutation_adapter = ReceiptClassifyingMutationAdapter(
            CloudRunV2Adapter(
                configuration=cloud_run_configuration,
                service_role=ServiceRole.EXECUTOR,
                configured_project_id=settings.project_id,
                services_client_factory=services_client_factory,
                revisions_client_factory=revisions_client_factory,
            )
        )
        receipt_coordinator = ReceiptExecutionCoordinator(
            store=receipt_store,
            final_gate=FinalMutationGate(
                authority_reader=selected_store,
                adapter=mutation_adapter,
                route_policy=policy,
                source_receipt_reader=receipt_store,
                clock=final_authority_clock,
            ),
            readback=CloudRunV2ReceiptReadback(
                configuration=cloud_run_configuration,
                configured_project_id=settings.project_id,
                services_client_factory=readback_services_client_factory,
            ),
            clock=receipt_clock,
        )
        capability_trust_verifier = GoogleKmsCapabilityTrustLoader(
            project_id=settings.project_id,
            service_role=ServiceRole.EXECUTOR,
            key_version=settings.capability_key_version,
            client=kms_client,
        ).load()
        capability_verifier = CapabilityVerifier(
            root_reader=selected_store,
            trust_verifier=capability_trust_verifier,
            configuration=CapabilityVerifierConfiguration(
                target=target,
                route_policy=policy,
            ),
            clock=capability_verification_clock,
        )
        verified_task_handler = create_receipt_task_handler(receipt_coordinator)
        recovery_executor_facade_authentication_policy = _recovery_executor_facade_policy(settings)
        recovery_receipt_store = ReceiptAuthorityClient(
            target=target,
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.EXECUTOR,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
                override_path=RECOVERY_RECEIPT_AUTHORITY_PATH,
            ),
            transport=selected_transport,
        )
        recovery_mutation_adapter = ReceiptClassifyingMutationAdapter(
            CloudRunV2Adapter(
                configuration=cloud_run_configuration,
                service_role=ServiceRole.EXECUTOR,
                configured_project_id=settings.project_id,
                mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
                services_client_factory=services_client_factory,
                revisions_client_factory=revisions_client_factory,
            )
        )
        recovery_receipt_coordinator = ReceiptExecutionCoordinator(
            store=recovery_receipt_store,
            final_gate=FinalMutationGate(
                authority_reader=selected_store,
                adapter=recovery_mutation_adapter,
                route_policy=recovery_executor_facade_authentication_policy,
                source_receipt_reader=recovery_receipt_store,
                mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
                clock=final_authority_clock,
            ),
            readback=CloudRunV2ReceiptReadback(
                configuration=cloud_run_configuration,
                configured_project_id=settings.project_id,
                mutation_purpose=CloudRunMutationPurpose.STABLE_RECOVERY,
                services_client_factory=readback_services_client_factory,
            ),
            clock=receipt_clock,
        )
        recovery_facade_verifier = CapabilityVerifier(
            root_reader=selected_store,
            trust_verifier=capability_trust_verifier,
            configuration=CapabilityVerifierConfiguration(
                target=target,
                route_policy=recovery_executor_facade_authentication_policy,
                recovery_executor_facade=True,
            ),
            recovery_prestate_verifier=(
                GoogleKmsRecoveryPrestateAttestationVerifier(
                    project_id=settings.project_id,
                    service_role=ServiceRole.EXECUTOR,
                    key_version=settings.evidence_key_version,
                    client=kms_client,
                )
            ),
            clock=capability_verification_clock,
        )
        recovery_executor_facade_handler = create_recovery_executor_facade_handler(
            RecoveryExecutorFacade(
                verifier=recovery_facade_verifier,
                coordinator=recovery_receipt_coordinator,
            )
        )
    elif role is ServiceRole.RECOVERY and settings.mutations_enabled:
        from controlgraph_canary.integrations.google.firestore import (
            FirestoreAuthorityStore,
        )

        if (
            settings.capability_key_version is None
            or settings.evidence_key_version is None
            or settings.executor_url is None
        ):
            raise ValueError("recovery forwarding configuration is incomplete")
        target = _reference_target(settings)
        selected_store = (
            authority_store
            if authority_store is not None
            else FirestoreAuthorityStore(
                target=target,
                configured_project_id=settings.project_id,
            )
        )
        selected_transport = (
            internal_transport
            if internal_transport is not None
            else GoogleOneShotOidcTransport(
                project_id=settings.project_id,
                caller_role=CallerRole.RECOVERY,
                timeout_seconds=45.0,
            )
        )
        capability_verifier = CapabilityVerifier(
            root_reader=selected_store,
            trust_verifier=GoogleKmsCapabilityTrustLoader(
                project_id=settings.project_id,
                service_role=ServiceRole.RECOVERY,
                key_version=settings.capability_key_version,
                client=kms_client,
            ).load(),
            configuration=CapabilityVerifierConfiguration(
                target=target,
                route_policy=policy,
            ),
            recovery_prestate_verifier=(
                GoogleKmsRecoveryPrestateAttestationVerifier(
                    project_id=settings.project_id,
                    service_role=ServiceRole.RECOVERY,
                    key_version=settings.evidence_key_version,
                    client=kms_client,
                )
            ),
            clock=capability_verification_clock,
        )
        verified_task_handler = create_recovery_forwarding_task_handler(
            RecoveryTaskForwarder(
                client=RecoveryExecutorClient(
                    target=target,
                    route=CoordinatorInternalRoute(
                        project_id=settings.project_id,
                        project_number=settings.project_number,
                        caller_role=CallerRole.RECOVERY,
                        service_role=ServiceRole.EXECUTOR,
                        audience=settings.executor_url,
                        override_path=RECOVERY_EXECUTION_FACADE_PATH,
                    ),
                    transport=selected_transport,
                ),
                route_policy=policy,
            )
        )
    elif role is ServiceRole.COORDINATOR:
        from controlgraph_canary.integrations.google.firestore_health import (
            FirestoreHealthChainStore,
        )
        from controlgraph_canary.integrations.google.firestore_model_assistance import (
            FirestoreModelAssistanceAuditStore,
        )
        from controlgraph_canary.integrations.google.firestore_recovery_abandonment import (
            FirestoreRecoveryAbandonmentStore,
        )
        from controlgraph_canary.integrations.google.firestore_timeline import (
            FirestoreTimelineStore,
        )

        if (
            settings.issuer_url is None
            or settings.verifier_url is None
            or settings.evidence_writer_url is None
            or settings.capability_key_version is None
            or settings.evidence_key_version is None
            or settings.candidate_revision_configuration_sha256 is None
            or settings.operator_identity is None
            or settings.operator_subject is None
            or settings.executor_url is None
            or settings.recovery_url is None
            or settings.execution_queue is None
            or settings.recovery_queue is None
            or settings.execution_task_caller is None
            or settings.recovery_task_caller is None
            or settings.receipt_authority_caller_identity is None
            or settings.receipt_authority_caller_subject is None
            or settings.advisor_url is None
        ):
            raise ValueError("coordinator root-creation configuration is incomplete")
        selected_transport = (
            internal_transport
            if internal_transport is not None
            else GoogleOneShotOidcTransport(
                project_id=settings.project_id,
                caller_role=CallerRole.COORDINATOR,
                timeout_seconds=30.0,
            )
        )
        verifier_route = CoordinatorInternalRoute(
            project_id=settings.project_id,
            project_number=settings.project_number,
            caller_role=CallerRole.COORDINATOR,
            service_role=ServiceRole.VERIFIER,
            audience=settings.verifier_url,
        )
        evidence_route = CoordinatorInternalRoute(
            project_id=settings.project_id,
            project_number=settings.project_number,
            caller_role=CallerRole.COORDINATOR,
            service_role=ServiceRole.EVIDENCE_WRITER,
            audience=settings.evidence_writer_url,
        )
        coordinator_advisor_client = CoordinatorAdvisorClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.COORDINATOR,
                service_role=ServiceRole.ADVISOR,
                audience=settings.advisor_url,
            ),
            transport=selected_transport,
        )
        advisor_dependencies = (
            diagnostic_snapshot_assembler,
            model_assistance_audit_store,
            model_assistance_timeline,
        )
        if any(item is not None for item in advisor_dependencies) and not all(
            item is not None for item in advisor_dependencies
        ):
            raise ValueError("coordinator advisor workflow configuration is incomplete")
        evidence_signature_verifier = GoogleKmsEvidenceSignatureVerifier(
            project_id=settings.project_id,
            service_role=ServiceRole.COORDINATOR,
            key_version=settings.evidence_key_version,
            client=kms_client,
        )
        coordinator_clients = CoordinatorTrustClients(
            preflight=CoordinatorRootPreflightClient(
                route=verifier_route,
                transport=selected_transport,
            ),
            evidence=CoordinatorEvidenceClient(
                route=evidence_route,
                evidence_key_version=settings.evidence_key_version,
                transport=selected_transport,
                signature_verifier=evidence_signature_verifier,
            ),
        )
        target = TargetBinding(
            schema_version="controlgraph.target-binding/v1",
            project_id=settings.project_id,
            region=settings.region,
            environment=settings.environment,
            service_name="controlgraph-reference-target",
        )
        timeline_policy_set = standard_timeline_evidence_policy_set(target)
        timeline_store = FirestoreTimelineStore.production(
            target=target,
            configured_project_id=settings.project_id,
            policy_set=timeline_policy_set,
        )
        timeline_recorder = TimelineRecorder(
            service=TimelineWriteService(
                target=target,
                policy_set=timeline_policy_set,
                store=timeline_store,
            ),
            grant=TimelineWriteGrant(
                target=target,
                writer_role=TimelineActorRole.COORDINATOR,
                principal_id=(
                    f"controlgraph-coordinator@{settings.project_id}.iam.gserviceaccount.com"
                ),
            ),
            policy_set=timeline_policy_set,
            signed_intent_store=timeline_store,
        )
        timeline_retention_service = TimelineRetentionService(
            target=target,
            store=timeline_store,
        )
        timeline_retention_authentication_policy = _timeline_retention_policy(
            settings
        )
        coordinator_timeline_relay = CoordinatorTimelineRelay(
            authentication_policy=policy,
            operator_policy=_operator_timeline_policy(
                _operator_api_policy(settings),
                TIMELINE_READ_PATH,
            ),
            security_audit_policy=_security_audit_timeline_policy(settings),
            restricted_export_policy=_restricted_export_timeline_policy(settings),
            read_service=TimelineReadService(target=target, store=timeline_store),
            raw_export_service=TimelineRawExportService(
                target=target,
                store=timeline_store,
            ),
        )
        coordinator_independent_verification_client = (
            CoordinatorIndependentVerificationClient(
                route=verifier_route,
                transport=selected_transport,
                signature_verifier=(
                    GoogleKmsIndependentVerificationEvidenceVerifier(
                        project_id=settings.project_id,
                        service_role=ServiceRole.COORDINATOR,
                        key_version=settings.evidence_key_version,
                        client=kms_client,
                    )
                ),
            )
        )
        coordinator_completion_classification_service = (
            CoordinatorCompletionClassificationService(
                target=target,
            )
        )
        coordinator_capability_verifier = TrustBundleCapabilityVerifier(
            GoogleKmsCapabilityTrustLoader(
                project_id=settings.project_id,
                service_role=ServiceRole.COORDINATOR,
                key_version=settings.capability_key_version,
                client=kms_client,
            ).load()
        )
        selected_store = (
            authority_store
            if authority_store is not None
            else FirestoreRecoveryAbandonmentStore(
                target=target,
                configured_project_id=settings.project_id,
            )
        )
        selected_advisor_assembler = diagnostic_snapshot_assembler or (
            M6DiagnosticSnapshotAssembler(
                target=target,
                authority=selected_store,
                timeline=timeline_store,
            )
        )
        selected_advisor_audit_store = model_assistance_audit_store or (
            FirestoreModelAssistanceAuditStore(
                target=target,
                configured_project_id=settings.project_id,
            )
        )
        selected_advisor_timeline = model_assistance_timeline or timeline_recorder
        coordinator_advisor_workflow = CoordinatorAdvisorWorkflow(
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            assembler=selected_advisor_assembler,
            advisor=coordinator_advisor_client,
            audit_store=selected_advisor_audit_store,
            timeline=cast(ModelAssistanceTimelineRecorder, selected_advisor_timeline),
        )
        stale_authority_reader = (
            cast(CompletionAuthorityReader, selected_store)
            if isinstance(selected_store, CompletionAuthorityReader)
            else None
        )
        coordinator_completion_workflow = CoordinatorCompletionWorkflow(
            target=target,
            verifier=coordinator_independent_verification_client,
            classifier=coordinator_completion_classification_service,
            timeline_recorder=timeline_recorder,
            authority_reader=stale_authority_reader,
            authority_evidence_verifier=(
                cast(CompletionAuthorityEvidenceVerifier, coordinator_clients.evidence)
                if stale_authority_reader is not None
                else None
            ),
            signed_intent_reader=timeline_store,
            signed_intent_verifier=coordinator_capability_verifier,
        )
        health_chain_store = FirestoreHealthChainStore(
            target=target,
            configured_project_id=settings.project_id,
            service_role=ServiceRole.COORDINATOR,
        )
        coordinator_operator_observation_relay = CoordinatorOperatorObservationRelay(
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            snapshot_client=CoordinatorStableSnapshotClient(
                target=target,
                route=verifier_route,
                transport=selected_transport,
            ),
            traffic_client=CoordinatorTargetTrafficClient(
                target=target,
                stable_revision="controlgraph-reference-target-stable-v21",
                candidate_revision="controlgraph-reference-target-candidate-v21",
                concurrency=8,
                route=verifier_route,
                transport=selected_transport,
            ),
            receipt_store=cast(ExecutionReceiptObservationStore, selected_store),
        )
        service_claim_releaser = ServiceClaimReleaser(
            store=cast(ServiceClaimReleaseStore, selected_store),
            evidence_client=coordinator_clients.evidence,
            classification_client=CoordinatorServiceClaimClassificationClient(
                route=verifier_route,
                transport=selected_transport,
                evidence_key_version=settings.evidence_key_version,
                signature_verifier=evidence_signature_verifier,
            ),
            operator_policy=_operator_api_policy(settings),
            completion_workflow=coordinator_completion_workflow,
            clock=service_claim_release_clock,
        )
        if isinstance(selected_store, RecoveryAbandonmentStore):
            recovery_abandoner = RecoveryAbandoner(
                store=selected_store,
                evidence_client=coordinator_clients.evidence,
                classification_client=cast(
                    RecoveryAbandonmentClassificationClient,
                    CoordinatorServiceClaimClassificationClient(
                        route=verifier_route,
                        transport=selected_transport,
                        evidence_key_version=settings.evidence_key_version,
                        signature_verifier=evidence_signature_verifier,
                    ),
                ),
                operator_policy=_operator_api_policy(settings),
                clock=recovery_abandonment_clock,
            )
        receipt_authority_service = ReceiptAuthorityService(
            selected_store,
            completion_workflow=(
                coordinator_completion_workflow
                if stale_authority_reader is not None
                else None
            ),
        )
        receipt_authority_authentication_policy = _receipt_authority_policy(settings)
        recovery_receipt_authority_authentication_policy = _recovery_receipt_authority_policy(
            settings
        )
        health_signature_verifier = GoogleKmsHealthAttestationVerifier(
            project_id=settings.project_id,
            service_role=ServiceRole.COORDINATOR,
            key_version=settings.evidence_key_version,
            client=kms_client,
        )
        creator = RolloutRootCreator(
            store=selected_store,
            preflight_client=coordinator_clients.preflight,
            evidence_client=coordinator_clients.evidence,
            configuration=RootCreationConfiguration(
                target=target,
                verifier_identity=(
                    f"controlgraph-verifier@{settings.project_id}.iam.gserviceaccount.com"
                ),
                candidate_revision="controlgraph-reference-target-candidate-v21",
                candidate_revision_configuration_sha256=(
                    settings.candidate_revision_configuration_sha256
                ),
                concurrency=8,
                health_policy=_root_health_policy(),
                capability_signing_key_version=settings.capability_key_version,
                evidence_signing_key_version=settings.evidence_key_version,
                issuer_identity=(
                    f"controlgraph-issuer@{settings.project_id}.iam.gserviceaccount.com"
                ),
                executor_identity=(
                    f"controlgraph-executor@{settings.project_id}.iam.gserviceaccount.com"
                ),
                recovery_identity=(
                    f"controlgraph-recovery@{settings.project_id}.iam.gserviceaccount.com"
                ),
                executor_audience=_service_audience(
                    ServiceRole.EXECUTOR,
                    settings.project_number,
                ),
                recovery_audience=_service_audience(
                    ServiceRole.RECOVERY,
                    settings.project_number,
                ),
                maximum_capability_lifetime_seconds=600,
                operator_identity=settings.operator_identity,
                operator_subject=settings.operator_subject,
            ),
            clock=root_creation_clock,
        )
        coordinator_root_creation_relay = CoordinatorRootCreationRelay(
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            creator=creator,
        )
        coordinator_epoch_revocation_relay = CoordinatorEpochRevocationRelay(
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            revoker=EpochRevoker(
                store=cast(EpochRevocationStore, selected_store),
                evidence_client=coordinator_clients.evidence,
                operator_policy=_operator_api_policy(settings),
                completion_workflow=coordinator_completion_workflow,
                timeline_recorder=timeline_recorder,
                clock=revocation_clock,
            ),
            proof_reader=EpochRevocationProofService(
                store=cast(EpochRevocationProofStore, selected_store),
                evidence_verifier=coordinator_clients.evidence,
                operator_policy=_operator_api_policy(settings),
            ),
        )
        coordinator_service_claim_release_relay = CoordinatorServiceClaimReleaseRelay(
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            releaser=service_claim_releaser,
        )
        if recovery_abandoner is not None:
            coordinator_recovery_abandonment_relay = CoordinatorRecoveryAbandonmentRelay(
                authentication_policy=policy,
                operator_policy=_operator_api_policy(settings),
                abandoner=recovery_abandoner,
            )
        capability_client = CoordinatorCapabilityClient(
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.COORDINATOR,
                service_role=ServiceRole.ISSUER,
                audience=settings.issuer_url,
            ),
            transport=selected_transport,
        )
        task_addressor = TaskAddressor(
            TaskDeliverySettings(
                project_id=settings.project_id,
                execution_queue_id=settings.execution_queue,
                recovery_queue_id=settings.recovery_queue,
                executor_service_url=settings.executor_url,
                recovery_service_url=settings.recovery_url,
                execution_oidc_service_account=settings.execution_task_caller,
                recovery_oidc_service_account=settings.recovery_task_caller,
            )
        )
        selected_task_enqueuer = (
            task_enqueuer
            if task_enqueuer is not None
            else GoogleCloudTasksEnqueuer.from_default_credentials(task_addressor)
        )
        recovery_prestate_verifier = GoogleKmsRecoveryPrestateAttestationVerifier(
            project_id=settings.project_id,
            service_role=ServiceRole.COORDINATOR,
            key_version=settings.evidence_key_version,
            client=kms_client,
        )
        recovery_coordinator = RecoveryRolloutCoordinator(
            target=target,
            authorization_resolver=StoredRecoveryAuthorizationResolver(
                target=target,
                root_reader=selected_store,
                receipt_reader=selected_store,
                intent_reader=health_chain_store,
                health_chain_reader=health_chain_store,
                health_signature_verifier=health_signature_verifier,
                revocation_evidence_verifier=coordinator_clients.evidence,
                prestate_evaluator=CoordinatorRecoveryPrestateClient(
                    route=verifier_route,
                    transport=selected_transport,
                    signature_verifier=recovery_prestate_verifier,
                ),
                prestate_signature_verifier=recovery_prestate_verifier,
            ),
            capability_client=CoordinatorRecoveryCapabilityClient(
                route=CoordinatorInternalRoute(
                    project_id=settings.project_id,
                    project_number=settings.project_number,
                    caller_role=CallerRole.COORDINATOR,
                    service_role=ServiceRole.ISSUER,
                    audience=settings.issuer_url,
                ),
                transport=selected_transport,
            ),
            dispatch_store=cast(RecoveryDispatchStore, health_chain_store),
            task_dispatcher=TaskDispatcher(
                task_addressor,
                selected_task_enqueuer,
            ),
            clock=recovery_clock,
            capability_verifier=coordinator_capability_verifier,
            timeline_recorder=timeline_recorder,
        )
        coordinator_recovery_relay = CoordinatorRecoveryRelay(
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            coordinator=recovery_coordinator,
        )
        coordinator_health_evaluation_service = CoordinatorHealthEvaluationService(
            target=target,
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            authority_reader=selected_store,
            receipt_reader=selected_store,
            health_store=health_chain_store,
            verifier=CoordinatorHealthEvaluationClient(
                route=verifier_route,
                transport=selected_transport,
                signature_verifier=health_signature_verifier,
            ),
            recovery_coordinator=recovery_coordinator,
            target_verification_workflow=coordinator_completion_workflow,
            timeline_recorder=timeline_recorder,
        )
        coordinator_canary_relay = CoordinatorCanaryRelay(
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            coordinator=CanaryRolloutCoordinator(
                target=target,
                capability_client=capability_client,
                task_dispatcher=TaskDispatcher(
                    task_addressor,
                    selected_task_enqueuer,
                ),
                clock=canary_clock,
                capability_verifier=coordinator_capability_verifier,
                timeline_recorder=timeline_recorder,
            ),
        )
        coordinator_promotion_relay = CoordinatorPromotionRelay(
            authentication_policy=policy,
            operator_policy=_operator_api_policy(settings),
            coordinator=PromotionRolloutCoordinator(
                target=target,
                authorization_resolver=StoredPromotionAuthorizationResolver(
                    target=target,
                    root_reader=selected_store,
                    health_chain_reader=health_chain_store,
                    health_signature_verifier=health_signature_verifier,
                ),
                capability_client=CoordinatorPromotionCapabilityClient(
                    route=CoordinatorInternalRoute(
                        project_id=settings.project_id,
                        project_number=settings.project_number,
                        caller_role=CallerRole.COORDINATOR,
                        service_role=ServiceRole.ISSUER,
                        audience=settings.issuer_url,
                    ),
                    transport=selected_transport,
                ),
                dispatch_store=cast(PromotionDispatchStoreV2, selected_store),
                task_dispatcher=TaskDispatcher(
                    task_addressor,
                    selected_task_enqueuer,
                ),
                clock=promotion_clock,
                capability_verifier=coordinator_capability_verifier,
                timeline_recorder=timeline_recorder,
            ),
        )
    if (
        role
        not in {
            ServiceRole.API,
            ServiceRole.COORDINATOR,
            ServiceRole.EXECUTOR,
            ServiceRole.RECOVERY,
            ServiceRole.VERIFIER,
        }
        and internal_transport is not None
    ):
        raise ValueError("internal service transport is role-limited")
    if preflight_clock is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("Cloud Run preflight clocks are verifier-limited")
    if classification_clock is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("claim-classification clocks are verifier-limited")
    if health_evaluation_clock is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("health-evaluation clocks are verifier-limited")
    if (
        services_client_factory is not None or revisions_client_factory is not None
    ) and role not in {ServiceRole.VERIFIER, ServiceRole.EXECUTOR}:
        raise ValueError("Cloud Run dependencies are verifier/executor-limited")
    if readback_services_client_factory is not None and role is not ServiceRole.EXECUTOR:
        raise ValueError("Cloud Run receipt readback is executor-limited")
    if authority_store is not None and role not in {
        ServiceRole.COORDINATOR,
        ServiceRole.ISSUER,
        ServiceRole.EXECUTOR,
        ServiceRole.RECOVERY,
    }:
        raise ValueError("authority-store dependencies are role-limited")
    if root_creation_clock is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("root-creation clocks are coordinator-limited")
    if revocation_clock is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("revocation clocks are coordinator-limited")
    if revocation_attempt_id_factory is not None and role is not ServiceRole.API:
        raise ValueError("revocation attempt identities are API-limited")
    if service_claim_release_clock is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("service-claim release clocks are coordinator-limited")
    if recovery_abandonment_clock is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("recovery-abandonment clocks are coordinator-limited")
    if any(
        item is not None
        for item in (
            diagnostic_snapshot_assembler,
            model_assistance_audit_store,
            model_assistance_timeline,
        )
    ) and role is not ServiceRole.COORDINATOR:
        raise ValueError("model-assistance persistence is coordinator-limited")
    if capability_issuance_clock is not None and role is not ServiceRole.ISSUER:
        raise ValueError("capability-issuance clocks are issuer-limited")
    if (
        canary_clock is not None
        or promotion_clock is not None
        or recovery_clock is not None
        or task_enqueuer is not None
    ) and role is not (ServiceRole.COORDINATOR):
        raise ValueError("canary-dispatch dependencies are coordinator-limited")
    if (
        final_authority_clock is not None
        or receipt_clock is not None
        or capability_verification_clock is not None
    ) and role not in {ServiceRole.EXECUTOR, ServiceRole.RECOVERY}:
        raise ValueError("executor clocks are executor-limited")
    app = create_service_app(
        role,
        build_digest=settings.build_digest,
        authenticator=authenticator,
        authentication_policy=policy,
        capability_verifier=capability_verifier,
        verified_task_handler=verified_task_handler,
        evidence_signing_service=evidence_signing_service,
        classification_evidence_signing_service=(classification_evidence_signing_service),
        classification_evidence_authentication_policy=(
            classification_evidence_authentication_policy
        ),
        independent_verification_signing_service=(
            independent_verification_signing_service
        ),
        independent_verification_evidence_authentication_policy=(
            independent_verification_evidence_authentication_policy
        ),
        health_attestation_signing_service=health_attestation_signing_service,
        health_attestation_authentication_policy=(health_attestation_authentication_policy),
        recovery_prestate_signing_service=recovery_prestate_signing_service,
        recovery_prestate_authentication_policy=(recovery_prestate_authentication_policy),
        root_preflight_service=root_preflight_service,
        stable_snapshot_capture_service=stable_snapshot_capture_service,
        target_traffic_observation_service=target_traffic_observation_service,
        service_claim_classification_service=(service_claim_classification_service),
        independent_verification_service=independent_verification_service,
        api_root_creation_client=api_root_creation_client,
        coordinator_root_creation_relay=coordinator_root_creation_relay,
        api_operator_observation_client=api_operator_observation_client,
        coordinator_operator_observation_relay=(coordinator_operator_observation_relay),
        api_canary_client=api_canary_client,
        coordinator_canary_relay=coordinator_canary_relay,
        api_promotion_client=api_promotion_client,
        coordinator_promotion_relay=coordinator_promotion_relay,
        api_health_evaluation_client=api_health_evaluation_client,
        coordinator_health_evaluation_service=coordinator_health_evaluation_service,
        verifier_health_evaluation_service=verifier_health_evaluation_service,
        api_recovery_client=api_recovery_client,
        coordinator_recovery_relay=coordinator_recovery_relay,
        verifier_recovery_prestate_service=verifier_recovery_prestate_service,
        api_epoch_revocation_client=api_epoch_revocation_client,
        coordinator_epoch_revocation_relay=coordinator_epoch_revocation_relay,
        api_service_claim_release_client=api_service_claim_release_client,
        coordinator_service_claim_release_relay=(coordinator_service_claim_release_relay),
        api_recovery_abandonment_client=api_recovery_abandonment_client,
        coordinator_recovery_abandonment_relay=(coordinator_recovery_abandonment_relay),
        api_advisor_client=api_advisor_client,
        coordinator_advisor_workflow=coordinator_advisor_workflow,
        capability_issuance_service=capability_issuance_service,
        receipt_authority_service=receipt_authority_service,
        receipt_authority_authentication_policy=(receipt_authority_authentication_policy),
        recovery_receipt_authority_authentication_policy=(
            recovery_receipt_authority_authentication_policy
        ),
        recovery_executor_facade_handler=recovery_executor_facade_handler,
        recovery_executor_facade_authentication_policy=(
            recovery_executor_facade_authentication_policy
        ),
        timeline_read_service=timeline_read_service,
        timeline_read_authentication_policy=(
            _operator_timeline_policy(policy, TIMELINE_READ_PATH)
            if timeline_read_service is not None
            else None
        ),
        timeline_security_read_authentication_policy=(
            _security_audit_timeline_policy(settings)
            if timeline_read_service is not None
            else None
        ),
        timeline_raw_export_service=timeline_raw_export_service,
        timeline_raw_export_authentication_policy=(
            _restricted_export_timeline_policy(settings)
            if timeline_raw_export_service is not None
            else None
        ),
        timeline_retention_service=timeline_retention_service,
        timeline_retention_authentication_policy=(
            timeline_retention_authentication_policy
        ),
        coordinator_timeline_relay=coordinator_timeline_relay,
        timeline_recorder=timeline_recorder,
        operator_console_origin=(
            settings.operator_console_origin if role is ServiceRole.API else None
        ),
        mutation_enabled=settings.mutations_enabled,
    )
    if coordinator_clients is not None:
        app.state.controlgraph_trust_clients = coordinator_clients
    if coordinator_independent_verification_client is not None:
        app.state.controlgraph_independent_verification_client = (
            coordinator_independent_verification_client
        )
    if coordinator_completion_classification_service is not None:
        app.state.controlgraph_completion_classification = (
            coordinator_completion_classification_service
        )
    if coordinator_completion_workflow is not None:
        app.state.controlgraph_completion_workflow = coordinator_completion_workflow
    if coordinator_advisor_client is not None:
        app.state.controlgraph_advisor_client = coordinator_advisor_client
    if coordinator_advisor_workflow is not None:
        app.state.controlgraph_advisor_workflow = coordinator_advisor_workflow
    if api_advisor_client is not None:
        app.state.controlgraph_api_advisor_client = api_advisor_client
    if api_root_creation_client is not None:
        app.state.controlgraph_root_creation_client = api_root_creation_client
    if coordinator_root_creation_relay is not None:
        app.state.controlgraph_root_creation_relay = coordinator_root_creation_relay
    if stable_snapshot_capture_service is not None:
        app.state.controlgraph_stable_snapshot_capture = stable_snapshot_capture_service
    if target_traffic_observation_service is not None:
        app.state.controlgraph_target_traffic_observation = target_traffic_observation_service
    if api_operator_observation_client is not None:
        app.state.controlgraph_operator_observation_client = api_operator_observation_client
    if coordinator_operator_observation_relay is not None:
        app.state.controlgraph_operator_observation_relay = coordinator_operator_observation_relay
    if service_claim_releaser is not None:
        app.state.controlgraph_service_claim_releaser = service_claim_releaser
    if api_service_claim_release_client is not None:
        app.state.controlgraph_service_claim_release_client = api_service_claim_release_client
    if coordinator_service_claim_release_relay is not None:
        app.state.controlgraph_service_claim_release_relay = coordinator_service_claim_release_relay
    if recovery_abandoner is not None:
        app.state.controlgraph_recovery_abandoner = recovery_abandoner
    if api_recovery_abandonment_client is not None:
        app.state.controlgraph_recovery_abandonment_client = api_recovery_abandonment_client
    if coordinator_recovery_abandonment_relay is not None:
        app.state.controlgraph_recovery_abandonment_relay = coordinator_recovery_abandonment_relay
    if service_claim_classification_service is not None:
        app.state.controlgraph_service_claim_classification = service_claim_classification_service
    if classification_evidence_signing_service is not None:
        app.state.controlgraph_classification_evidence_signing = (
            classification_evidence_signing_service
        )
    if independent_verification_signing_service is not None:
        app.state.controlgraph_independent_verification_signing = (
            independent_verification_signing_service
        )
    if independent_verification_service is not None:
        app.state.controlgraph_independent_verification = independent_verification_service
    if health_attestation_signing_service is not None:
        app.state.controlgraph_health_attestation_signing = health_attestation_signing_service
    if api_canary_client is not None:
        app.state.controlgraph_canary_client = api_canary_client
    if coordinator_canary_relay is not None:
        app.state.controlgraph_canary_relay = coordinator_canary_relay
    if api_promotion_client is not None:
        app.state.controlgraph_promotion_client = api_promotion_client
    if coordinator_promotion_relay is not None:
        app.state.controlgraph_promotion_relay = coordinator_promotion_relay
    if api_health_evaluation_client is not None:
        app.state.controlgraph_health_evaluation_client = api_health_evaluation_client
    if coordinator_health_evaluation_service is not None:
        app.state.controlgraph_health_evaluation_service = coordinator_health_evaluation_service
    if verifier_health_evaluation_service is not None:
        app.state.controlgraph_verifier_health_evaluation = verifier_health_evaluation_service
    if api_recovery_client is not None:
        app.state.controlgraph_recovery_client = api_recovery_client
    if coordinator_recovery_relay is not None:
        app.state.controlgraph_recovery_relay = coordinator_recovery_relay
    if verifier_recovery_prestate_service is not None:
        app.state.controlgraph_recovery_prestate_verifier = verifier_recovery_prestate_service
    if recovery_prestate_signing_service is not None:
        app.state.controlgraph_recovery_prestate_signing = recovery_prestate_signing_service
    if api_epoch_revocation_client is not None:
        app.state.controlgraph_epoch_revocation_client = api_epoch_revocation_client
    if coordinator_epoch_revocation_relay is not None:
        app.state.controlgraph_epoch_revocation_relay = coordinator_epoch_revocation_relay
    if capability_issuance_service is not None:
        app.state.controlgraph_capability_issuance = capability_issuance_service
    if receipt_authority_service is not None:
        app.state.controlgraph_receipt_authority = receipt_authority_service
    if verified_task_handler is not None:
        app.state.controlgraph_receipt_execution = verified_task_handler
    if recovery_executor_facade_handler is not None:
        app.state.controlgraph_recovery_executor_facade = recovery_executor_facade_handler
    if timeline_read_service is not None:
        app.state.controlgraph_timeline_read = timeline_read_service
    if timeline_raw_export_service is not None:
        app.state.controlgraph_timeline_raw_export = timeline_raw_export_service
    if timeline_retention_service is not None:
        app.state.controlgraph_timeline_retention = timeline_retention_service
    if timeline_recorder is not None:
        app.state.controlgraph_timeline_recorder = timeline_recorder
    if coordinator_timeline_relay is not None:
        app.state.controlgraph_timeline_relay = coordinator_timeline_relay
    return app


def _service_audience(role: ServiceRole, project_number: str) -> str:
    return f"https://{runtime_service_name(role)}-{project_number}.us-central1.run.app"


def _reference_target(settings: ControllerSettings) -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=settings.project_id,
        region=settings.region,
        environment=settings.environment,
        service_name="controlgraph-reference-target",
    )


def _operator_api_policy(settings: ControllerSettings) -> RouteAuthenticationPolicy:
    if settings.operator_identity is None or settings.operator_subject is None:
        raise ValueError("operator root-creation policy is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.API,
        path=protected_path(ServiceRole.API),
        audience=_service_audience(ServiceRole.API, settings.project_number),
        caller=CallerBinding(
            role=CallerRole.OPERATOR,
            email=settings.operator_identity,
            subject=settings.operator_subject,
        ),
    )


def _operator_timeline_policy(
    base: RouteAuthenticationPolicy,
    path: str,
) -> RouteAuthenticationPolicy:
    if (
        type(base) is not RouteAuthenticationPolicy
        or base.service_role is not ServiceRole.API
        or base.caller.role is not CallerRole.OPERATOR
        or path != TIMELINE_READ_PATH
    ):
        raise ValueError("operator timeline path is invalid")
    return RouteAuthenticationPolicy(
        project_id=base.project_id,
        project_number=base.project_number,
        service_role=base.service_role,
        path=path,
        audience=base.audience,
        caller=base.caller,
    )


def _security_audit_timeline_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    return _privileged_timeline_policy(
        settings,
        path=TIMELINE_READ_PATH,
        role=CallerRole.SECURITY_AUDITOR,
        email=settings.security_auditor_identity,
        subject=settings.security_auditor_subject,
    )


def _restricted_export_timeline_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    return _privileged_timeline_policy(
        settings,
        path=TIMELINE_RAW_EXPORT_PATH,
        role=CallerRole.RESTRICTED_EXPORTER,
        email=settings.restricted_exporter_identity,
        subject=settings.restricted_exporter_subject,
    )


def _timeline_retention_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    if (
        settings.timeline_retention_caller_identity is None
        or settings.timeline_retention_caller_subject is None
    ):
        raise ValueError("timeline retention identity is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.COORDINATOR,
        path=TIMELINE_RETENTION_PATH,
        audience=_service_audience(ServiceRole.COORDINATOR, settings.project_number),
        caller=CallerBinding(
            role=CallerRole.RETENTION_SWEEPER,
            email=settings.timeline_retention_caller_identity,
            subject=settings.timeline_retention_caller_subject,
        ),
    )


def _privileged_timeline_policy(
    settings: ControllerSettings,
    *,
    path: str,
    role: CallerRole,
    email: str | None,
    subject: str | None,
) -> RouteAuthenticationPolicy:
    if email is None or subject is None:
        raise ValueError("privileged timeline identity is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.API,
        path=path,
        audience=_service_audience(ServiceRole.API, settings.project_number),
        caller=CallerBinding(
            role=role,
            email=email,
            subject=subject,
        ),
    )


def _receipt_authority_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    if (
        settings.receipt_authority_caller_identity is None
        or settings.receipt_authority_caller_subject is None
    ):
        raise ValueError("receipt authority policy is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.COORDINATOR,
        path=RECEIPT_AUTHORITY_PATH,
        audience=_service_audience(
            ServiceRole.COORDINATOR,
            settings.project_number,
        ),
        caller=CallerBinding(
            role=CallerRole.EXECUTOR,
            email=settings.receipt_authority_caller_identity,
            subject=settings.receipt_authority_caller_subject,
        ),
    )


def _recovery_receipt_authority_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    if (
        settings.recovery_receipt_authority_caller_identity is None
        or settings.recovery_receipt_authority_caller_subject is None
    ):
        raise ValueError("recovery receipt authority policy is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.COORDINATOR,
        path=RECOVERY_RECEIPT_AUTHORITY_PATH,
        audience=_service_audience(
            ServiceRole.COORDINATOR,
            settings.project_number,
        ),
        caller=CallerBinding(
            role=CallerRole.EXECUTOR,
            email=settings.recovery_receipt_authority_caller_identity,
            subject=settings.recovery_receipt_authority_caller_subject,
        ),
    )


def _recovery_executor_facade_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    if (
        settings.recovery_facade_caller_identity is None
        or settings.recovery_facade_caller_subject is None
    ):
        raise ValueError("recovery executor facade policy is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.EXECUTOR,
        path=RECOVERY_EXECUTION_FACADE_PATH,
        audience=_service_audience(
            ServiceRole.EXECUTOR,
            settings.project_number,
        ),
        caller=CallerBinding(
            role=CallerRole.RECOVERY,
            email=settings.recovery_facade_caller_identity,
            subject=settings.recovery_facade_caller_subject,
        ),
    )


def _classification_evidence_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    if (
        settings.classification_evidence_caller_identity is None
        or settings.classification_evidence_caller_subject is None
    ):
        raise ValueError("classification evidence policy is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.EVIDENCE_WRITER,
        path=CLASSIFICATION_EVIDENCE_PATH,
        audience=_service_audience(
            ServiceRole.EVIDENCE_WRITER,
            settings.project_number,
        ),
        caller=CallerBinding(
            role=CallerRole.VERIFIER,
            email=settings.classification_evidence_caller_identity,
            subject=settings.classification_evidence_caller_subject,
        ),
    )


def _health_attestation_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    if (
        settings.classification_evidence_caller_identity is None
        or settings.classification_evidence_caller_subject is None
    ):
        raise ValueError("health attestation policy is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.EVIDENCE_WRITER,
        path=HEALTH_ATTESTATION_PATH,
        audience=_service_audience(
            ServiceRole.EVIDENCE_WRITER,
            settings.project_number,
        ),
        caller=CallerBinding(
            role=CallerRole.VERIFIER,
            email=settings.classification_evidence_caller_identity,
            subject=settings.classification_evidence_caller_subject,
        ),
    )


def _independent_verification_evidence_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    if (
        settings.classification_evidence_caller_identity is None
        or settings.classification_evidence_caller_subject is None
    ):
        raise ValueError("independent verification evidence policy is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.EVIDENCE_WRITER,
        path=INDEPENDENT_VERIFICATION_EVIDENCE_PATH,
        audience=_service_audience(
            ServiceRole.EVIDENCE_WRITER,
            settings.project_number,
        ),
        caller=CallerBinding(
            role=CallerRole.VERIFIER,
            email=settings.classification_evidence_caller_identity,
            subject=settings.classification_evidence_caller_subject,
        ),
    )


def _recovery_prestate_policy(
    settings: ControllerSettings,
) -> RouteAuthenticationPolicy:
    if (
        settings.classification_evidence_caller_identity is None
        or settings.classification_evidence_caller_subject is None
    ):
        raise ValueError("recovery prestate policy is incomplete")
    return RouteAuthenticationPolicy(
        project_id=settings.project_id,
        project_number=settings.project_number,
        service_role=ServiceRole.EVIDENCE_WRITER,
        path=RECOVERY_PRESTATE_ATTESTATION_PATH,
        audience=_service_audience(
            ServiceRole.EVIDENCE_WRITER,
            settings.project_number,
        ),
        caller=CallerBinding(
            role=CallerRole.VERIFIER,
            email=settings.classification_evidence_caller_identity,
            subject=settings.classification_evidence_caller_subject,
        ),
    )


def _root_health_policy() -> RolloutHealthPolicyV2:
    return create_rollout_health_policy_v2()


__all__ = ["CoordinatorTrustClients", "create_runtime_service_app"]
