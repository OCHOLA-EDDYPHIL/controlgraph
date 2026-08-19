"""Runtime composition for authenticated role-specific service applications."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping

from fastapi import FastAPI

from controlgraph_canary.application.identity import ServiceRole, runtime_route_policy
from controlgraph_canary.http.service import create_service_app
from controlgraph_canary.integrations.google.identity import (
    GoogleIdentityVerifier,
    IdentityTokenVerifier,
)
from controlgraph_canary.settings import ControllerSettings


def create_runtime_service_app(
    role: ServiceRole,
    *,
    environment: Mapping[str, str] | None = None,
    token_verifier: IdentityTokenVerifier | None = None,
    clock: Callable[[], float] | None = None,
) -> FastAPI:
    """Compose a fail-closed service from validated startup coordinates."""

    source = os.environ if environment is None else environment
    settings = ControllerSettings.from_environment(source)
    if settings.role != role.value:
        raise ValueError("runtime role does not match the service composition root")
    policy = runtime_route_policy(role, source)
    authenticator = GoogleIdentityVerifier(verifier=token_verifier, clock=clock)
    return create_service_app(
        role,
        build_digest=settings.build_digest,
        authenticator=authenticator,
        authentication_policy=policy,
    )


__all__ = ["create_runtime_service_app"]
