"""Authenticated API-to-coordinator relay for service-claim release."""

from __future__ import annotations

import asyncio
import uuid
from typing import Literal, Protocol, cast, runtime_checkable

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.application.service_claim_release import (
    ServiceClaimReleaseError,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.service_claim_release import (
    SERVICE_CLAIM_RELEASE_INVOCATION_V1,
    ServiceClaimReleaseCommandV1,
    ServiceClaimReleaseFailureCode,
    ServiceClaimReleaseInvocationV1,
    ServiceClaimReleaseRelayResponseV1,
    ServiceClaimReleaseResultV1,
    service_claim_release_request_sha256,
)


@runtime_checkable
class ServiceClaimReleaseCoordinatorPort(Protocol):
    """Narrow coordinator orchestration port used by the relay."""

    async def release(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> ServiceClaimReleaseResultV1: ...


class ApiServiceClaimReleaseClient:
    """Forward an authenticated explicit release only to the coordinator."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        authentication_policy: RouteAuthenticationPolicy,
        transport: CanonicalInternalTransport,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.API
            or route.service_role is not ServiceRole.COORDINATOR
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.API
            or authentication_policy.caller.role is not CallerRole.OPERATOR
            or authentication_policy.project_id != route.project_id
            or authentication_policy.project_number != route.project_number
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise TypeError("release API relay configuration is invalid")
        self._route = route
        self._authentication_policy = authentication_policy
        self._transport = transport

    async def release(
        self,
        command: ServiceClaimReleaseCommandV1,
        principal: AuthenticationContext,
    ) -> ServiceClaimReleaseResultV1:
        """Return only an exact coordinator result for this operator request."""

        if type(command) is not ServiceClaimReleaseCommandV1:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.COMMAND_DENIED
            )
        if not _context_matches_policy(
            principal,
            self._authentication_policy,
            role=CallerRole.OPERATOR,
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.CALLER_DENIED
            )
        try:
            invocation = ServiceClaimReleaseInvocationV1(
                schema_version=SERVICE_CLAIM_RELEASE_INVOCATION_V1,
                command=command,
                attempt_id=str(uuid.uuid4()),
                operator_identity=principal.email,
                operator_subject=principal.subject,
                operator_issuer=cast(
                    Literal["accounts.google.com", "https://accounts.google.com"],
                    principal.issuer,
                ),
                operator_audience=principal.audience,
                operator_issued_at=principal.issued_at,
                operator_expires_at=principal.expires_at,
            )
        except (TypeError, ValueError):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.COMMAND_DENIED
            ) from None
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.OUTCOME_UNKNOWN
            ) from None
        try:
            outcome = decode_contract(body, ServiceClaimReleaseRelayResponseV1)
        except ContractError:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.OUTCOME_UNKNOWN
            ) from None
        except Exception:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.OUTCOME_UNKNOWN
            ) from None
        if outcome.failure_code is not None:
            raise ServiceClaimReleaseError(outcome.failure_code)
        result = outcome.result
        if result is None or not _result_matches_invocation(result, invocation):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.OUTCOME_UNKNOWN
            )
        return result


class CoordinatorServiceClaimReleaseRelay:
    """Authenticate the API relay and invoke the configured release lifecycle."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        releaser: ServiceClaimReleaseCoordinatorPort,
    ) -> None:
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.COORDINATOR
            or authentication_policy.caller.role is not CallerRole.API
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.project_id != authentication_policy.project_id
            or operator_policy.project_number != authentication_policy.project_number
            or not isinstance(releaser, ServiceClaimReleaseCoordinatorPort)
        ):
            raise TypeError("release coordinator relay configuration is invalid")
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._releaser = releaser

    async def release(
        self,
        invocation: ServiceClaimReleaseInvocationV1,
        caller: AuthenticationContext,
    ) -> ServiceClaimReleaseResultV1:
        """Execute only after both API-service and operator bindings match."""

        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.CALLER_DENIED
            )
        if type(invocation) is not ServiceClaimReleaseInvocationV1:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.COMMAND_DENIED
            )
        expected_operator = self._operator_policy.caller
        if (
            invocation.operator_identity != expected_operator.email
            or invocation.operator_subject != expected_operator.subject
            or invocation.operator_issuer
            not in {"accounts.google.com", "https://accounts.google.com"}
            or invocation.operator_audience != self._operator_policy.audience
        ):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.CALLER_DENIED
            )
        principal = AuthenticationContext(
            role=CallerRole.OPERATOR,
            email=invocation.operator_identity,
            subject=invocation.operator_subject,
            issuer=invocation.operator_issuer,
            audience=invocation.operator_audience,
            issued_at=invocation.operator_issued_at,
            expires_at=invocation.operator_expires_at,
        )
        try:
            result = await self._releaser.release(invocation, principal=principal)
        except asyncio.CancelledError:
            raise
        except ServiceClaimReleaseError:
            raise
        except Exception:
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.STORE_UNAVAILABLE
            ) from None
        if not _result_matches_invocation(result, invocation):
            raise ServiceClaimReleaseError(
                ServiceClaimReleaseFailureCode.TRUSTED_STATE_INVALID
            )
        return result


def _context_matches_policy(
    context: object,
    policy: RouteAuthenticationPolicy,
    *,
    role: CallerRole,
) -> bool:
    return (
        type(context) is AuthenticationContext
        and context.role is role
        and context.role is policy.caller.role
        and context.email == policy.caller.email
        and context.subject == policy.caller.subject
        and context.issuer in {"accounts.google.com", "https://accounts.google.com"}
        and context.audience == policy.audience
        and type(context.issued_at) is int
        and type(context.expires_at) is int
        and context.issued_at < context.expires_at
        and context.expires_at - context.issued_at <= 3_660
    )


def _result_matches_invocation(
    result: object,
    invocation: ServiceClaimReleaseInvocationV1,
) -> bool:
    if type(result) is not ServiceClaimReleaseResultV1:
        return False
    command = invocation.command
    return (
        result.request_sha256 == service_claim_release_request_sha256(invocation)
        and result.request_id == command.request_id
        and result.idempotency_key == command.idempotency_key
        and result.root_id == command.root_id
        and result.root_sha256 == command.expected_root_sha256
        and result.operator_identity == invocation.operator_identity
        and result.operator_subject == invocation.operator_subject
    )


__all__ = [
    "ApiServiceClaimReleaseClient",
    "CoordinatorServiceClaimReleaseRelay",
    "ServiceClaimReleaseCoordinatorPort",
]
