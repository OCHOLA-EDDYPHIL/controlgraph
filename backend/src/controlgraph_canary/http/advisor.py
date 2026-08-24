"""Authenticated HTTP surface for the isolated read-only advisor."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from controlgraph_canary import __version__
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    IdentityAuthenticator,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.model_assistance import ReadOnlyAdvisorService
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.model_assistance import AdvisorInvocationRequestV1
from controlgraph_canary.http.identity_headers import authentication_header

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class AdvisorHealth(BaseModel):
    """Credential-free liveness response."""

    model_config = ConfigDict(frozen=True)

    status: str
    service_role: ServiceRole
    correlation_id: str


class AdvisorMetadata(BaseModel):
    """Safe runtime metadata with no model input or credential content."""

    model_config = ConfigDict(frozen=True)

    contract_version: str
    service_shell_version: str
    application_version: str
    service_role: ServiceRole
    build_digest: str | None
    mutation_enabled: bool
    correlation_id: str


class AdvisorDenied(BaseModel):
    """Payload-free advisor denial."""

    model_config = ConfigDict(frozen=True)

    code: str
    correlation_id: str


def create_advisor_app(
    *,
    authenticator: IdentityAuthenticator,
    authentication_policy: RouteAuthenticationPolicy,
    advisor_service: ReadOnlyAdvisorService,
    build_digest: str | None = None,
) -> FastAPI:
    """Create the advisor's sole authenticated work route."""

    if (
        not callable(getattr(authenticator, "authenticate", None))
        or type(authentication_policy) is not RouteAuthenticationPolicy
        or authentication_policy.service_role is not ServiceRole.ADVISOR
        or authentication_policy.path != protected_path(ServiceRole.ADVISOR)
        or type(advisor_service) is not ReadOnlyAdvisorService
    ):
        raise ValueError("advisor HTTP configuration is invalid")
    if build_digest is None:
        build_digest = os.environ.get("CONTROLGRAPH_BUILD_DIGEST")
    if build_digest is not None and _DIGEST.fullmatch(build_digest) is None:
        raise ValueError("build_digest must be an immutable sha256 digest")

    app = FastAPI(
        title="ControlGraph advisor",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def attach_correlation_id(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        if "X-ControlGraph-Correlation-Id" not in response.headers:
            response.headers["X-ControlGraph-Correlation-Id"] = _correlation_id()
        return response

    @app.get("/healthz", response_model=AdvisorHealth)
    def healthz(response: Response) -> AdvisorHealth:
        correlation_id = _correlation_id()
        response.headers["X-ControlGraph-Correlation-Id"] = correlation_id
        return AdvisorHealth(
            status="ok",
            service_role=ServiceRole.ADVISOR,
            correlation_id=correlation_id,
        )

    @app.get("/v1/metadata", response_model=AdvisorMetadata)
    def metadata(response: Response) -> AdvisorMetadata:
        correlation_id = _correlation_id()
        response.headers["X-ControlGraph-Correlation-Id"] = correlation_id
        return AdvisorMetadata(
            contract_version="controlgraph.contract/v1",
            service_shell_version="controlgraph.service-shell/v1",
            application_version=__version__,
            service_role=ServiceRole.ADVISOR,
            build_digest=build_digest,
            mutation_enabled=False,
            correlation_id=correlation_id,
        )

    @app.post(protected_path(ServiceRole.ADVISOR), include_in_schema=False)
    async def advise(request: Request) -> Response:
        correlation_id = _correlation_id()
        try:
            authorization = authentication_header(request.headers, authentication_policy)
            caller = authenticator.authenticate(authorization, authentication_policy)
        except AuthenticationError as error:
            return _denied(error.code.value, correlation_id, status_code=401)
        except Exception:
            return _denied(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE.value,
                correlation_id,
                status_code=401,
            )
        if type(caller) is not AuthenticationContext:
            return _denied(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE.value,
                correlation_id,
                status_code=401,
            )
        try:
            body = await _read_contract_body(request)
            invocation = decode_contract(body, AdvisorInvocationRequestV1)
            result = await advisor_service.advise(invocation, caller)
        except ContractError:
            return _denied("ADVISOR_REQUEST_INVALID", correlation_id, status_code=400)
        except ValueError:
            return _denied("ADVISOR_REQUEST_DENIED", correlation_id, status_code=403)
        except Exception:
            return _denied("ADVISOR_UNAVAILABLE", correlation_id, status_code=503)
        return Response(
            content=canonical_json_bytes(result),
            status_code=200,
            media_type="application/json",
            headers={"X-ControlGraph-Correlation-Id": correlation_id},
        )

    return app


def _denied(code: str, correlation_id: str, *, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=AdvisorDenied(code=code, correlation_id=correlation_id).model_dump(
            mode="json"
        ),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
    )


def _correlation_id() -> str:
    return uuid.uuid4().hex


async def _read_contract_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if type(chunk) is not bytes or len(body) + len(chunk) > MAX_CONTRACT_BYTES:
            raise ValueError("request body is outside its bound")
        body.extend(chunk)
    if not body:
        raise ValueError("request body is outside its bound")
    return bytes(body)


__all__ = ["AdvisorDenied", "AdvisorHealth", "AdvisorMetadata", "create_advisor_app"]
