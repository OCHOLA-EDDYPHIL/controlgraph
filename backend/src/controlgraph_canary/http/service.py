"""Identity-safe private service shells with protected work disabled."""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from controlgraph_canary import __version__
from controlgraph_canary.application.tasks import (
    EXECUTION_HANDLER_PATH,
    RECOVERY_HANDLER_PATH,
)

PRODUCT_CONTRACT_VERSION: Final = "controlgraph.contract/v1"
SERVICE_SHELL_VERSION: Final = "controlgraph.service-shell/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ServiceRole(StrEnum):
    """Private runtime roles with separate deployment identities."""

    API = "api"
    COORDINATOR = "coordinator"
    ISSUER = "issuer"
    EXECUTOR = "executor"
    RECOVERY = "recovery"
    VERIFIER = "verifier"


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
    """Stable fail-closed response before M3 enforcement is composed."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


def create_service_app(
    role: ServiceRole,
    *,
    build_digest: str | None = None,
) -> FastAPI:
    """Create one private role shell with no enabled protected operation."""

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
            mutation_enabled=False,
            correlation_id=correlation_id,
        )

    def disabled_work() -> JSONResponse:
        correlation_id = _correlation_id()
        response = DisabledWork(
            code="MUTATION_DISABLED",
            correlation_id=correlation_id,
        )
        return JSONResponse(
            status_code=503,
            content=response.model_dump(mode="json"),
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    for path in protected_paths(role):
        app.add_api_route(path, disabled_work, methods=["POST"], include_in_schema=False)
    return app


def protected_paths(role: ServiceRole) -> tuple[str, ...]:
    """Return the closed route set for deployment and local conformance checks."""

    if role is ServiceRole.API:
        return ("/v1/operator/commands",)
    if role is ServiceRole.COORDINATOR:
        return ("/v1/internal/coordinate",)
    if role is ServiceRole.ISSUER:
        return ("/v1/internal/issue",)
    if role is ServiceRole.EXECUTOR:
        return (EXECUTION_HANDLER_PATH,)
    if role is ServiceRole.RECOVERY:
        return (RECOVERY_HANDLER_PATH,)
    if role is ServiceRole.VERIFIER:
        return ("/v1/internal/verify",)
    raise ValueError("unsupported service role")


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
    "DisabledWork",
    "ServiceHealth",
    "ServiceMetadata",
    "ServiceRole",
    "create_service_app",
    "protected_paths",
]
