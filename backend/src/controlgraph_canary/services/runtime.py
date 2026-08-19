"""Runtime composition for authenticated role-specific service applications."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping

from fastapi import FastAPI

from controlgraph_canary.application.evidence_signing import EvidenceSigningService
from controlgraph_canary.application.identity import ServiceRole, runtime_route_policy
from controlgraph_canary.application.signing import AsyncPurposeSealedSigner, SigningProfile
from controlgraph_canary.http.service import create_service_app
from controlgraph_canary.integrations.google.identity import (
    GoogleIdentityVerifier,
    IdentityTokenVerifier,
)
from controlgraph_canary.integrations.google.kms import GoogleKmsAsyncDigestSigner
from controlgraph_canary.settings import ControllerSettings


def create_runtime_service_app(
    role: ServiceRole,
    *,
    environment: Mapping[str, str] | None = None,
    token_verifier: IdentityTokenVerifier | None = None,
    clock: Callable[[], float] | None = None,
    kms_client: object | None = None,
) -> FastAPI:
    """Compose a fail-closed service from validated startup coordinates."""

    source = os.environ if environment is None else environment
    settings = ControllerSettings.from_environment(source)
    if settings.role != role.value:
        raise ValueError("runtime role does not match the service composition root")
    policy = runtime_route_policy(role, source)
    authenticator = GoogleIdentityVerifier(verifier=token_verifier, clock=clock)
    evidence_signing_service = None
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
    elif kms_client is not None:
        raise ValueError("KMS signing is limited to the evidence-writer service")
    return create_service_app(
        role,
        build_digest=settings.build_digest,
        authenticator=authenticator,
        authentication_policy=policy,
        evidence_signing_service=evidence_signing_service,
    )


__all__ = ["create_runtime_service_app"]
