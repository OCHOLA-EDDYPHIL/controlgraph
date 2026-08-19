"""Runtime composition for authenticated role-specific service applications."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from fastapi import FastAPI

from controlgraph_canary.application.authority_store import AuthorityStore
from controlgraph_canary.application.cloud_run import CloudRunTargetConfiguration
from controlgraph_canary.application.evidence_signing import EvidenceSigningService
from controlgraph_canary.application.identity import (
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
    runtime_route_policy,
    runtime_service_name,
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
from controlgraph_canary.application.signing import AsyncPurposeSealedSigner, SigningProfile
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.root_creation import RolloutHealthPolicyV1
from controlgraph_canary.contracts.root_trust import RootPreflightRequestV1
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
    GoogleKmsEvidenceSignatureVerifier,
)
from controlgraph_canary.settings import ControllerSettings

if TYPE_CHECKING:
    from controlgraph_canary.integrations.google.cloud_run import (
        CloudRunV2SnapshotReader,
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
    authority_store: AuthorityStore | None = None,
    root_creation_clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Compose a fail-closed service from validated startup coordinates."""

    source = os.environ if environment is None else environment
    settings = ControllerSettings.from_environment(source)
    if settings.role != role.value:
        raise ValueError("runtime role does not match the service composition root")
    if kms_client is not None and role not in {
        ServiceRole.EVIDENCE_WRITER,
        ServiceRole.COORDINATOR,
    }:
        raise ValueError("KMS dependencies are limited to evidence trust roles")
    policy = runtime_route_policy(role, source)
    authenticator = GoogleIdentityVerifier(verifier=token_verifier, clock=clock)
    evidence_signing_service = None
    root_preflight_service = None
    coordinator_clients = None
    api_root_creation_client = None
    coordinator_root_creation_relay = None
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
    elif role is ServiceRole.COORDINATOR:
        from controlgraph_canary.integrations.google.firestore import (
            FirestoreAuthorityStore,
        )

        if (
            settings.verifier_url is None
            or settings.evidence_writer_url is None
            or settings.capability_key_version is None
            or settings.evidence_key_version is None
            or settings.candidate_revision_configuration_sha256 is None
            or settings.operator_identity is None
            or settings.operator_subject is None
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
    if role not in {ServiceRole.API, ServiceRole.COORDINATOR} and internal_transport is not None:
        raise ValueError("internal service transport is role-limited")
    if role is not ServiceRole.VERIFIER and (
        preflight_clock is not None
        or services_client_factory is not None
        or revisions_client_factory is not None
    ):
        raise ValueError("Cloud Run preflight dependencies are verifier-limited")
    if role is not ServiceRole.COORDINATOR and (
        authority_store is not None or root_creation_clock is not None
    ):
        raise ValueError("root creation dependencies are coordinator-limited")
    app = create_service_app(
        role,
        build_digest=settings.build_digest,
        authenticator=authenticator,
        authentication_policy=policy,
        evidence_signing_service=evidence_signing_service,
        root_preflight_service=root_preflight_service,
        api_root_creation_client=api_root_creation_client,
        coordinator_root_creation_relay=coordinator_root_creation_relay,
    )
    if coordinator_clients is not None:
        app.state.controlgraph_trust_clients = coordinator_clients
    if api_root_creation_client is not None:
        app.state.controlgraph_root_creation_client = api_root_creation_client
    if coordinator_root_creation_relay is not None:
        app.state.controlgraph_root_creation_relay = coordinator_root_creation_relay
    return app


def _service_audience(role: ServiceRole, project_number: str) -> str:
    return (
        f"https://{runtime_service_name(role)}-{project_number}.us-central1.run.app"
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
