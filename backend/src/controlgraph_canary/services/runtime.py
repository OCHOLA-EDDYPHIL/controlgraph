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
)
from controlgraph_canary.application.capability_verification import (
    CapabilityVerifier,
    CapabilityVerifierConfiguration,
)
from controlgraph_canary.application.cloud_run import CloudRunTargetConfiguration
from controlgraph_canary.application.evidence_signing import EvidenceSigningService
from controlgraph_canary.application.execution import FinalMutationGate
from controlgraph_canary.application.identity import (
    RECEIPT_AUTHORITY_PATH,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
    runtime_route_policy,
    runtime_service_name,
)
from controlgraph_canary.application.receipt_authority import (
    ReceiptAuthorityClient,
    ReceiptAuthorityService,
)
from controlgraph_canary.application.receipt_execution import (
    ReceiptClassifyingMutationAdapter,
    ReceiptExecutionCoordinator,
)
from controlgraph_canary.application.revocation import EpochRevoker
from controlgraph_canary.application.revocation_relay import (
    ApiEpochRevocationClient,
    CoordinatorEpochRevocationRelay,
)
from controlgraph_canary.application.revocation_store import EpochRevocationStore
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
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.root_creation import RolloutHealthPolicyV1
from controlgraph_canary.contracts.root_trust import RootPreflightRequestV1
from controlgraph_canary.http.receipt import create_receipt_task_handler
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
    services_client_factory: ServicesClientFactory | None = None,
    revisions_client_factory: RevisionsClientFactory | None = None,
    readback_services_client_factory: ReadOnlyServicesClientFactory | None = None,
    authority_store: AuthorityStore | None = None,
    root_creation_clock: Callable[[], datetime] | None = None,
    capability_issuance_clock: Callable[[], datetime] | None = None,
    canary_clock: Callable[[], datetime] | None = None,
    task_enqueuer: TaskEnqueuer | None = None,
    final_authority_clock: Callable[[], datetime] | None = None,
    receipt_clock: Callable[[], datetime] | None = None,
    capability_verification_clock: Callable[[], datetime] | None = None,
    revocation_clock: Callable[[], datetime] | None = None,
    revocation_attempt_id_factory: Callable[[], str] | None = None,
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
    }:
        raise ValueError("KMS dependencies are limited to signing and trust roles")
    policy = runtime_route_policy(role, source)
    authenticator = GoogleIdentityVerifier(verifier=token_verifier, clock=clock)
    evidence_signing_service = None
    root_preflight_service = None
    coordinator_clients = None
    api_root_creation_client = None
    coordinator_root_creation_relay = None
    api_canary_client = None
    coordinator_canary_relay = None
    api_epoch_revocation_client = None
    coordinator_epoch_revocation_relay = None
    capability_issuance_service = None
    receipt_authority_service = None
    receipt_authority_authentication_policy = None
    capability_verifier = None
    verified_task_handler = None
    if role is ServiceRole.EVIDENCE_WRITER:
        if settings.evidence_key_version is None or settings.signing_algorithm is None:
            raise ValueError("evidence-writer signing configuration is incomplete")
        profile = SigningProfile.evidence(settings.project_id, settings.evidence_key_version)
        if settings.signing_algorithm != profile.algorithm:
            raise ValueError("evidence-writer signing algorithm is invalid")
        evidence_signing_service = EvidenceSigningService(
            project_id=settings.project_id,
            authentication_policy=policy,
            signer=AsyncPurposeSealedSigner(
                GoogleKmsAsyncDigestSigner(profile, client=kms_client)
            ),
        )
    elif role is ServiceRole.VERIFIER:
        from controlgraph_canary.integrations.google.cloud_run import (
            CloudRunV2SnapshotReader,
        )

        if (
            settings.target_network_resource is None
            or settings.target_subnetwork_resource is None
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
    elif role is ServiceRole.API:
        if settings.coordinator_url is None:
            raise ValueError("API root-creation relay configuration is incomplete")
        selected_transport = (
            internal_transport
            if internal_transport is not None
            else GoogleOneShotOidcTransport(
                project_id=settings.project_id,
                caller_role=CallerRole.API,
            )
        )
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
    elif role is ServiceRole.ISSUER:
        from controlgraph_canary.integrations.google.firestore import (
            FirestoreAuthorityStore,
        )

        if settings.capability_key_version is None:
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
            or settings.coordinator_url is None
            or settings.target_network_resource is None
            or settings.target_subnetwork_resource is None
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
            stable_revision="controlgraph-reference-target-stable-v1",
            candidate_revision="controlgraph-reference-target-candidate-v1",
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
                clock=final_authority_clock,
            ),
            readback=CloudRunV2ReceiptReadback(
                configuration=cloud_run_configuration,
                configured_project_id=settings.project_id,
                services_client_factory=readback_services_client_factory,
            ),
            clock=receipt_clock,
        )
        capability_verifier = CapabilityVerifier(
            root_reader=selected_store,
            trust_verifier=GoogleKmsCapabilityTrustLoader(
                project_id=settings.project_id,
                service_role=ServiceRole.EXECUTOR,
                key_version=settings.capability_key_version,
                client=kms_client,
            ).load(),
            configuration=CapabilityVerifierConfiguration(
                target=target,
                route_policy=policy,
            ),
            clock=capability_verification_clock,
        )
        verified_task_handler = create_receipt_task_handler(receipt_coordinator)
    elif role is ServiceRole.COORDINATOR:
        from controlgraph_canary.integrations.google.firestore import (
            FirestoreAuthorityStore,
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
        ):
            raise ValueError("coordinator root-creation configuration is incomplete")
        selected_transport = (
            internal_transport
            if internal_transport is not None
            else GoogleOneShotOidcTransport(
                project_id=settings.project_id,
                caller_role=CallerRole.COORDINATOR,
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
        coordinator_clients = CoordinatorTrustClients(
            preflight=CoordinatorRootPreflightClient(
                route=verifier_route,
                transport=selected_transport,
            ),
            evidence=CoordinatorEvidenceClient(
                route=evidence_route,
                evidence_key_version=settings.evidence_key_version,
                transport=selected_transport,
                signature_verifier=GoogleKmsEvidenceSignatureVerifier(
                    project_id=settings.project_id,
                    service_role=ServiceRole.COORDINATOR,
                    key_version=settings.evidence_key_version,
                    client=kms_client,
                ),
            ),
        )
        target = TargetBinding(
            schema_version="controlgraph.target-binding/v1",
            project_id=settings.project_id,
            region=settings.region,
            environment=settings.environment,
            service_name="controlgraph-reference-target",
        )
        selected_store = (
            authority_store
            if authority_store is not None
            else FirestoreAuthorityStore(
                target=target,
                configured_project_id=settings.project_id,
            )
        )
        receipt_authority_service = ReceiptAuthorityService(selected_store)
        receipt_authority_authentication_policy = _receipt_authority_policy(
            settings
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
                candidate_revision="controlgraph-reference-target-candidate-v1",
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
                clock=revocation_clock,
            ),
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
            ),
        )
    if role not in {
        ServiceRole.API,
        ServiceRole.COORDINATOR,
        ServiceRole.EXECUTOR,
    } and internal_transport is not None:
        raise ValueError("internal service transport is role-limited")
    if preflight_clock is not None and role is not ServiceRole.VERIFIER:
        raise ValueError("Cloud Run preflight clocks are verifier-limited")
    if (
        services_client_factory is not None or revisions_client_factory is not None
    ) and role not in {ServiceRole.VERIFIER, ServiceRole.EXECUTOR}:
        raise ValueError("Cloud Run dependencies are verifier/executor-limited")
    if (
        readback_services_client_factory is not None
        and role is not ServiceRole.EXECUTOR
    ):
        raise ValueError("Cloud Run receipt readback is executor-limited")
    if authority_store is not None and role not in {
        ServiceRole.COORDINATOR,
        ServiceRole.ISSUER,
        ServiceRole.EXECUTOR,
    }:
        raise ValueError("authority-store dependencies are role-limited")
    if root_creation_clock is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("root-creation clocks are coordinator-limited")
    if revocation_clock is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("revocation clocks are coordinator-limited")
    if revocation_attempt_id_factory is not None and role is not ServiceRole.API:
        raise ValueError("revocation attempt identities are API-limited")
    if capability_issuance_clock is not None and role is not ServiceRole.ISSUER:
        raise ValueError("capability-issuance clocks are issuer-limited")
    if (canary_clock is not None or task_enqueuer is not None) and role is not (
        ServiceRole.COORDINATOR
    ):
        raise ValueError("canary-dispatch dependencies are coordinator-limited")
    if (
        final_authority_clock is not None
        or receipt_clock is not None
        or capability_verification_clock is not None
    ) and role is not ServiceRole.EXECUTOR:
        raise ValueError("executor clocks are executor-limited")
    app = create_service_app(
        role,
        build_digest=settings.build_digest,
        authenticator=authenticator,
        authentication_policy=policy,
        capability_verifier=capability_verifier,
        verified_task_handler=verified_task_handler,
        evidence_signing_service=evidence_signing_service,
        root_preflight_service=root_preflight_service,
        api_root_creation_client=api_root_creation_client,
        coordinator_root_creation_relay=coordinator_root_creation_relay,
        api_canary_client=api_canary_client,
        coordinator_canary_relay=coordinator_canary_relay,
        api_epoch_revocation_client=api_epoch_revocation_client,
        coordinator_epoch_revocation_relay=coordinator_epoch_revocation_relay,
        capability_issuance_service=capability_issuance_service,
        receipt_authority_service=receipt_authority_service,
        receipt_authority_authentication_policy=(
            receipt_authority_authentication_policy
        ),
        mutation_enabled=settings.mutations_enabled,
    )
    if coordinator_clients is not None:
        app.state.controlgraph_trust_clients = coordinator_clients
    if api_root_creation_client is not None:
        app.state.controlgraph_root_creation_client = api_root_creation_client
    if coordinator_root_creation_relay is not None:
        app.state.controlgraph_root_creation_relay = coordinator_root_creation_relay
    if api_canary_client is not None:
        app.state.controlgraph_canary_client = api_canary_client
    if coordinator_canary_relay is not None:
        app.state.controlgraph_canary_relay = coordinator_canary_relay
    if api_epoch_revocation_client is not None:
        app.state.controlgraph_epoch_revocation_client = api_epoch_revocation_client
    if coordinator_epoch_revocation_relay is not None:
        app.state.controlgraph_epoch_revocation_relay = (
            coordinator_epoch_revocation_relay
        )
    if capability_issuance_service is not None:
        app.state.controlgraph_capability_issuance = capability_issuance_service
    if receipt_authority_service is not None:
        app.state.controlgraph_receipt_authority = receipt_authority_service
    if verified_task_handler is not None:
        app.state.controlgraph_receipt_execution = verified_task_handler
    return app


def _service_audience(role: ServiceRole, project_number: str) -> str:
    return (
        f"https://{runtime_service_name(role)}-{project_number}.us-central1.run.app"
    )


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


def _root_health_policy() -> RolloutHealthPolicyV1:
    return RolloutHealthPolicyV1(
        schema_version="controlgraph.rollout-health-policy/v1",
        input_schema_version="controlgraph.health-input/v1",
        evaluation_window_seconds=60,
        minimum_request_count=100,
        maximum_error_rate_basis_points=100,
        maximum_p95_latency_ms=500,
        minimum_probe_count=10,
        minimum_probe_success_basis_points=9_900,
        healthy_consecutive_windows=2,
        unhealthy_consecutive_windows=2,
        window_semantics="HALF_OPEN_START_INCLUSIVE_END_EXCLUSIVE",
        incomplete_data_action="INDETERMINATE_NO_MUTATION",
        late_data_action="INDETERMINATE_NO_MUTATION",
        duplicate_data_action="REJECT",
    )


__all__ = ["CoordinatorTrustClients", "create_runtime_service_app"]
