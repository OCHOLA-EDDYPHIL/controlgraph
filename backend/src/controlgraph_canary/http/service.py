"""Identity-safe private service surfaces with closed protected handlers."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import uuid
from collections.abc import Awaitable, Callable
from typing import Final

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
from controlgraph_canary.application.identity import (
    RECEIPT_AUTHORITY_PATH,
    AuthenticationContext,
    AuthenticationDenialCode,
    AuthenticationError,
    CallerRole,
    IdentityAuthenticator,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.receipt_authority import ReceiptAuthorityService
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
from controlgraph_canary.contracts.models import EvidenceEvent, ReasonCode
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_RELAY_RESPONSE_V1,
    EpochRevocationCommandV1,
    EpochRevocationFailureCode,
    EpochRevocationInvocationV1,
    EpochRevocationRelayResponseV1,
)
from controlgraph_canary.contracts.root_creation import RootCreationCommandV1
from controlgraph_canary.contracts.root_relay import RootCreationInvocationV1
from controlgraph_canary.contracts.root_trust import RootPreflightRequestV1

PRODUCT_CONTRACT_VERSION: Final = "controlgraph.contract/v1"
SERVICE_SHELL_VERSION: Final = "controlgraph.service-shell/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


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


type VerifiedTaskHandler = Callable[[VerifiedMutation], Awaitable[Response]]


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
    api_canary_client: ApiCanaryClient | None = None,
    coordinator_canary_relay: CoordinatorCanaryRelay | None = None,
    api_epoch_revocation_client: ApiEpochRevocationClient | None = None,
    coordinator_epoch_revocation_relay: CoordinatorEpochRevocationRelay | None = None,
    capability_issuance_service: CapabilityIssuanceService | None = None,
    receipt_authority_service: ReceiptAuthorityService | None = None,
    receipt_authority_authentication_policy: RouteAuthenticationPolicy | None = None,
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
    if mutation_enabled and (
        capability_verifier is None or verified_task_handler is None
    ):
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
    if (
        coordinator_root_creation_relay is not None
        and role is not ServiceRole.COORDINATOR
    ):
        raise ValueError("root creation coordination is limited to the coordinator route")
    if api_canary_client is not None and role is not ServiceRole.API:
        raise ValueError("canary dispatch is limited to the API route")
    if coordinator_canary_relay is not None and role is not ServiceRole.COORDINATOR:
        raise ValueError("canary coordination is limited to the coordinator route")
    if api_epoch_revocation_client is not None and role is not ServiceRole.API:
        raise ValueError("manual revocation is limited to the API route")
    if (
        coordinator_epoch_revocation_relay is not None
        and role is not ServiceRole.COORDINATOR
    ):
        raise ValueError("revocation coordination is limited to the coordinator route")
    if capability_issuance_service is not None and role is not ServiceRole.ISSUER:
        raise ValueError("capability issuance is limited to the issuer route")
    if (receipt_authority_service is None) != (
        receipt_authority_authentication_policy is None
    ):
        raise ValueError("receipt authority service and policy must be configured together")
    if receipt_authority_service is not None and (
        role is not ServiceRole.COORDINATOR
        or type(receipt_authority_authentication_policy)
        is not RouteAuthenticationPolicy
        or receipt_authority_authentication_policy.service_role
        is not ServiceRole.COORDINATOR
        or receipt_authority_authentication_policy.path != RECEIPT_AUTHORITY_PATH
        or receipt_authority_authentication_policy.caller.role is not CallerRole.EXECUTOR
    ):
        raise ValueError("receipt authority is limited to the executor-to-coordinator route")
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

    async def protected_work(request: Request) -> Response:
        correlation_id = _correlation_id()
        if authenticator is None or authentication_policy is None:
            return _authentication_denial(
                AuthenticationDenialCode.CONFIGURATION_INVALID,
                correlation_id,
            )
        authorization_headers = request.headers.getlist("authorization")
        if len(authorization_headers) > 1:
            return _authentication_denial(
                AuthenticationDenialCode.CREDENTIAL_MALFORMED,
                correlation_id,
            )
        authorization_header = authorization_headers[0] if authorization_headers else None
        try:
            context = authenticator.authenticate(authorization_header, authentication_policy)
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
            or api_epoch_revocation_client is not None
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
                        raise CanaryExecutionError(
                            CanaryExecutionErrorCode.CONFIGURATION_INVALID
                        )
                    canary_result = await api_canary_client.dispatch(command, context)
                    response_body = canonical_json_bytes(canary_result)
                else:
                    if type(command) is not EpochRevocationCommandV1:
                        raise EpochRevocationError(
                            EpochRevocationFailureCode.COMMAND_DENIED
                        )
                    if api_epoch_revocation_client is None:
                        raise EpochRevocationError(
                            EpochRevocationFailureCode.STORE_UNAVAILABLE
                        )
                    revocation_result = await api_epoch_revocation_client.revoke(
                        command,
                        context,
                    )
                    response_body = canonical_json_bytes(revocation_result)
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
            except EpochRevocationError as error:
                return _epoch_revocation_denial(error.code.value, correlation_id)
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
            or coordinator_epoch_revocation_relay is not None
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
                    response_body = canonical_json_bytes(root_result)
                elif type(invocation) is ApplyCanaryInvocationV1:
                    if coordinator_canary_relay is None:
                        raise CanaryExecutionError(
                            CanaryExecutionErrorCode.CONFIGURATION_INVALID
                        )
                    canary_result = await coordinator_canary_relay.dispatch(
                        invocation,
                        context,
                    )
                    response_body = canonical_json_bytes(canary_result)
                else:
                    if type(invocation) is not EpochRevocationInvocationV1:
                        raise EpochRevocationError(
                            EpochRevocationFailureCode.COMMAND_DENIED
                        )
                    if coordinator_epoch_revocation_relay is None:
                        raise EpochRevocationError(
                            EpochRevocationFailureCode.STORE_UNAVAILABLE
                        )
                    try:
                        revocation_result = (
                            await coordinator_epoch_revocation_relay.revoke(
                                invocation,
                                context,
                            )
                        )
                    except EpochRevocationError as error:
                        revocation_outcome = EpochRevocationRelayResponseV1(
                            schema_version=EPOCH_REVOCATION_RELAY_RESPONSE_V1,
                            result=None,
                            failure_code=error.code,
                        )
                    else:
                        revocation_outcome = EpochRevocationRelayResponseV1(
                            schema_version=EPOCH_REVOCATION_RELAY_RESPONSE_V1,
                            result=revocation_result,
                            failure_code=None,
                        )
                    response_body = canonical_json_bytes(revocation_outcome)
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
            except EpochRevocationError as error:
                return _epoch_revocation_denial(error.code.value, correlation_id)
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
                issuance_command = decode_contract(body, CapabilityIssuanceCommandV1)
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
        if role is ServiceRole.VERIFIER and root_preflight_service is not None:
            try:
                body = await _read_contract_body(request)
                preflight_request = decode_contract(body, RootPreflightRequestV1)
                preflight_result = await root_preflight_service.preflight(
                    preflight_request,
                    context,
                )
                response_body = canonical_json_bytes(preflight_result)
            except asyncio.CancelledError:
                raise
            except CapabilityVerificationError:
                return _root_preflight_denial("CONTRACT_INVALID", correlation_id)
            except ContractError as error:
                return _root_preflight_denial(error.code.value, correlation_id)
            except RootPreflightError as error:
                return _root_preflight_denial(error.code.value, correlation_id)
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

    async def receipt_authority_work(request: Request) -> Response:
        correlation_id = _correlation_id()
        policy = receipt_authority_authentication_policy
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
        authorization_headers = request.headers.getlist("authorization")
        if len(authorization_headers) > 1:
            return _authentication_denial(
                AuthenticationDenialCode.CREDENTIAL_MALFORMED,
                correlation_id,
            )
        authorization_header = (
            authorization_headers[0] if authorization_headers else None
        )
        try:
            context = authenticator.authenticate(authorization_header, policy)
        except AuthenticationError as error:
            return _authentication_denial(error.code, correlation_id)
        except Exception:
            return _authentication_denial(
                AuthenticationDenialCode.VERIFICATION_UNAVAILABLE,
                correlation_id,
            )
        if (
            type(context) is not AuthenticationContext
            or context.role is not CallerRole.EXECUTOR
        ):
            return _authentication_denial(
                AuthenticationDenialCode.CALLER_DENIED,
                correlation_id,
            )
        request.state.authentication = context
        try:
            body = await _read_contract_body(request)
            response_body = await service.handle(body)
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

    for path in protected_paths(role):
        app.add_api_route(path, protected_work, methods=["POST"], include_in_schema=False)
    if receipt_authority_service is not None:
        app.add_api_route(
            RECEIPT_AUTHORITY_PATH,
            receipt_authority_work,
            methods=["POST"],
            include_in_schema=False,
        )
    return app


def protected_paths(role: ServiceRole) -> tuple[str, ...]:
    """Return the closed route set for deployment and local conformance checks."""

    return (protected_path(role),)


def _decode_api_command(
    body: bytes,
) -> RootCreationCommandV1 | ApplyCanaryCommandV1 | EpochRevocationCommandV1:
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
    return decode_contract(body, EpochRevocationCommandV1)


def _decode_coordinator_invocation(
    body: bytes,
) -> RootCreationInvocationV1 | ApplyCanaryInvocationV1 | EpochRevocationInvocationV1:
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
    return decode_contract(body, EpochRevocationInvocationV1)


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


def _receipt_authority_denial(code: str, correlation_id: str) -> JSONResponse:
    response = CanaryExecutionDenied(code=code, correlation_id=correlation_id)
    return JSONResponse(
        status_code=400 if code == "CONTRACT_INVALID" else 503,
        content=response.model_dump(mode="json"),
        headers={"X-ControlGraph-Correlation-Id": correlation_id},
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
    "RootCreationDenied",
    "RootPreflightDenied",
    "ServiceHealth",
    "ServiceMetadata",
    "ServiceRole",
    "VerifiedTaskHandler",
    "create_service_app",
    "protected_paths",
]
