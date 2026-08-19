"""Runtime composition for authenticated role-specific service applications."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from fastapi import FastAPI

from controlgraph_canary.application.cloud_run import CloudRunTargetConfiguration
from controlgraph_canary.application.evidence_signing import EvidenceSigningService
from controlgraph_canary.application.identity import CallerRole, ServiceRole, runtime_route_policy
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorEvidenceClient,
    CoordinatorInternalRoute,
    CoordinatorRootPreflightClient,
    RootPreflightService,
)
from controlgraph_canary.application.signing import AsyncPurposeSealedSigner, SigningProfile
from controlgraph_canary.contracts.models import TargetBinding
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
) -> FastAPI:
    """Compose a fail-closed service from validated startup coordinates."""

    source = os.environ if environment is None else environment
    settings = ControllerSettings.from_environment(source)
    if settings.role != role.value:
        raise ValueError("runtime role does not match the service composition root")
    policy = runtime_route_policy(role, source)
    authenticator = GoogleIdentityVerifier(verifier=token_verifier, clock=clock)
    evidence_signing_service = None
    root_preflight_service = None
    coordinator_clients = None
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
    elif role is ServiceRole.COORDINATOR:
        if (
            settings.verifier_url is None
            or settings.evidence_writer_url is None
            or settings.evidence_key_version is None
        ):
            raise ValueError("coordinator trust configuration is incomplete")
        selected_transport = internal_transport or GoogleOneShotOidcTransport(
            project_id=settings.project_id,
            caller_role=CallerRole.COORDINATOR,
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
    elif kms_client is not None:
        raise ValueError("KMS signing is limited to the evidence-writer service")
    if role is not ServiceRole.COORDINATOR and internal_transport is not None:
        raise ValueError("internal coordinator transport is role-limited")
    if role is not ServiceRole.VERIFIER and (
        preflight_clock is not None
        or services_client_factory is not None
        or revisions_client_factory is not None
    ):
        raise ValueError("Cloud Run preflight dependencies are verifier-limited")
    app = create_service_app(
        role,
        build_digest=settings.build_digest,
        authenticator=authenticator,
        authentication_policy=policy,
        evidence_signing_service=evidence_signing_service,
        root_preflight_service=root_preflight_service,
    )
    if coordinator_clients is not None:
        app.state.controlgraph_trust_clients = coordinator_clients
    return app


__all__ = ["CoordinatorTrustClients", "create_runtime_service_app"]
