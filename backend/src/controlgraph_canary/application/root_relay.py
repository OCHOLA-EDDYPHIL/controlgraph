"""Authenticated API-to-coordinator relay for immutable root creation."""

from __future__ import annotations

import asyncio
from enum import StrEnum
from typing import Literal, Protocol, cast, runtime_checkable

from controlgraph_canary.application.authority_store import RootCreationWriteResult
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.root_creation_service import (
    RootCreationError,
    RootCreationErrorCode,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.root_creation import (
    RootCreationCommandV1,
    RootCreationResultV1,
)
from controlgraph_canary.contracts.root_relay import (
    ROOT_CREATION_INVOCATION_V1,
    RootCreationInvocationV1,
)
from controlgraph_canary.contracts.root_trust import stable_snapshots_match


class RootRelayErrorCode(StrEnum):
    """Stable payload-free root relay failure classes."""

    CONFIGURATION_INVALID = "ROOT_RELAY_CONFIGURATION_INVALID"
    CALLER_DENIED = "ROOT_RELAY_CALLER_DENIED"
    OPERATOR_DENIED = "ROOT_RELAY_OPERATOR_DENIED"
    COMMAND_DENIED = "ROOT_RELAY_COMMAND_DENIED"
    CREATION_CONFLICT = "ROOT_RELAY_CREATION_CONFLICT"
    CREATION_DENIED = "ROOT_RELAY_CREATION_DENIED"
    CREATION_UNAVAILABLE = "ROOT_RELAY_CREATION_UNAVAILABLE"
    TRANSPORT_UNAVAILABLE = "ROOT_RELAY_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "ROOT_RELAY_RESPONSE_INVALID"


class RootRelayError(RuntimeError):
    """Sanitized relay failure containing no request, credential, or provider data."""

    def __init__(self, code: RootRelayErrorCode) -> None:
        if type(code) is not RootRelayErrorCode:
            raise TypeError("an exact root relay error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class RolloutRootCreatorPort(Protocol):
    """Narrow method implemented by the coordinator's rollout-root creator."""

    async def create(
        self,
        command: RootCreationCommandV1,
        *,
        principal: AuthenticationContext | None,
    ) -> RootCreationWriteResult: ...


class ApiRootCreationClient:
    """Forward an authenticated operator command only to the fixed coordinator."""

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
            raise RootRelayError(RootRelayErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._authentication_policy = authentication_policy
        self._transport = transport

    async def create(
        self,
        command: RootCreationCommandV1,
        principal: AuthenticationContext,
    ) -> RootCreationResultV1:
        """Return only an exact coordinator result for the authenticated command."""

        if type(command) is not RootCreationCommandV1:
            raise RootRelayError(RootRelayErrorCode.COMMAND_DENIED)
        if not _context_matches_policy(
            principal,
            self._authentication_policy,
            role=CallerRole.OPERATOR,
        ):
            raise RootRelayError(RootRelayErrorCode.OPERATOR_DENIED)
        if command.expected_stable_snapshot.target.project_id != self._route.project_id:
            raise RootRelayError(RootRelayErrorCode.COMMAND_DENIED)
        try:
            invocation = RootCreationInvocationV1(
                schema_version=ROOT_CREATION_INVOCATION_V1,
                command=command,
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
            raise RootRelayError(RootRelayErrorCode.OPERATOR_DENIED) from None
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RootRelayError(RootRelayErrorCode.TRANSPORT_UNAVAILABLE) from None
        try:
            result = decode_contract(body, RootCreationResultV1)
        except ContractError:
            raise RootRelayError(RootRelayErrorCode.RESPONSE_INVALID) from None
        except Exception:
            raise RootRelayError(RootRelayErrorCode.RESPONSE_INVALID) from None
        if not _result_matches_invocation(result, invocation):
            raise RootRelayError(RootRelayErrorCode.RESPONSE_INVALID)
        return result


class CoordinatorRootCreationRelay:
    """Authenticate the API relay and invoke one configured rollout-root creator."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        creator: RolloutRootCreatorPort,
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
            or not isinstance(creator, RolloutRootCreatorPort)
        ):
            raise RootRelayError(RootRelayErrorCode.CONFIGURATION_INVALID)
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._creator = creator

    async def create(
        self,
        invocation: RootCreationInvocationV1,
        caller: AuthenticationContext,
    ) -> RootCreationResultV1:
        """Return the canonical creation winner after both identity checks."""

        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise RootRelayError(RootRelayErrorCode.CALLER_DENIED)
        if type(invocation) is not RootCreationInvocationV1:
            raise RootRelayError(RootRelayErrorCode.COMMAND_DENIED)
        command = invocation.command
        target = command.expected_stable_snapshot.target
        expected_operator = self._operator_policy.caller
        if (
            target.project_id != self._authentication_policy.project_id
            or invocation.operator_identity != expected_operator.email
            or invocation.operator_subject != expected_operator.subject
            or invocation.operator_issuer
            not in {"accounts.google.com", "https://accounts.google.com"}
            or invocation.operator_audience != self._operator_policy.audience
        ):
            raise RootRelayError(RootRelayErrorCode.OPERATOR_DENIED)
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
            written = await self._creator.create(command, principal=principal)
        except asyncio.CancelledError:
            raise
        except RootCreationError as error:
            raise RootRelayError(_map_creation_error(error.code)) from None
        except Exception:
            raise RootRelayError(RootRelayErrorCode.CREATION_UNAVAILABLE) from None
        if type(written) is not RootCreationWriteResult:
            raise RootRelayError(RootRelayErrorCode.CREATION_UNAVAILABLE)
        result = written.result
        if not _result_matches_invocation(result, invocation):
            raise RootRelayError(RootRelayErrorCode.CREATION_UNAVAILABLE)
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
    invocation: RootCreationInvocationV1,
) -> bool:
    if type(result) is not RootCreationResultV1:
        return False
    command = invocation.command
    root_snapshot = result.root.content.stable_snapshot
    return (
        result.request_id == command.request_id
        and result.idempotency_key == command.idempotency_key
        and result.operator_identity == invocation.operator_identity
        and result.operator_subject == invocation.operator_subject
        and result.root.content.target == command.expected_stable_snapshot.target
        and stable_snapshots_match(
            root_snapshot,
            command.expected_stable_snapshot,
        )
        and command.expected_stable_snapshot.captured_at <= root_snapshot.captured_at
    )


def _map_creation_error(code: RootCreationErrorCode) -> RootRelayErrorCode:
    if code is RootCreationErrorCode.ACTIVE_CLAIM_CONFLICT:
        return RootRelayErrorCode.CREATION_CONFLICT
    if code in {
        RootCreationErrorCode.CALLER_UNAUTHENTICATED,
        RootCreationErrorCode.CALLER_UNAUTHORIZED,
    }:
        return RootRelayErrorCode.OPERATOR_DENIED
    if code in {
        RootCreationErrorCode.OUTCOME_UNKNOWN,
        RootCreationErrorCode.STORE_UNAVAILABLE,
    }:
        return RootRelayErrorCode.CREATION_UNAVAILABLE
    return RootRelayErrorCode.CREATION_DENIED


__all__ = [
    "ApiRootCreationClient",
    "CoordinatorRootCreationRelay",
    "RolloutRootCreatorPort",
    "RootRelayError",
    "RootRelayErrorCode",
]
