"""Authenticated API-to-coordinator relay for manual epoch revocation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Literal, Protocol, cast, runtime_checkable
from uuid import uuid4

from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.revocation import EpochRevocationError
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_CALL_OUTCOME_V1,
    EPOCH_REVOCATION_INVOCATION_V1,
    EPOCH_REVOCATION_PROOF_INVOCATION_V1,
    EpochRevocationCallOutcomeV1,
    EpochRevocationCommandV1,
    EpochRevocationFailureCode,
    EpochRevocationInvocationV1,
    EpochRevocationProofCommandV1,
    EpochRevocationProofInvocationV1,
    EpochRevocationProofRelayResponseV1,
    EpochRevocationProofV1,
    EpochRevocationRelayResponseV1,
    EpochRevocationResultV1,
    epoch_revocation_evidence_id,
    epoch_revocation_proof_matches_command,
    epoch_revocation_request_sha256,
)


@runtime_checkable
class EpochRevokerPort(Protocol):
    async def revoke(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> EpochRevocationResultV1: ...

    async def record_authenticated_denial(
        self,
        invocation: EpochRevocationInvocationV1,
        *,
        code: EpochRevocationFailureCode,
    ) -> None: ...


@runtime_checkable
class EpochRevocationProofPort(Protocol):
    async def read(
        self,
        invocation: EpochRevocationProofInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> EpochRevocationProofV1: ...


class ApiEpochRevocationClient:
    """Forward one operator command only to the configured coordinator route."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        authentication_policy: RouteAuthenticationPolicy,
        transport: CanonicalInternalTransport,
        attempt_id_factory: Callable[[], str] | None = None,
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
            or (attempt_id_factory is not None and not callable(attempt_id_factory))
        ):
            raise TypeError("revocation API relay configuration is invalid")
        self._route = route
        self._policy = authentication_policy
        self._transport = transport
        self._attempt_id_factory = attempt_id_factory or _new_attempt_id

    async def revoke(
        self,
        command: EpochRevocationCommandV1,
        principal: AuthenticationContext,
    ) -> EpochRevocationCallOutcomeV1:
        if type(command) is not EpochRevocationCommandV1:
            raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED)
        if not _context_matches(principal, self._policy, CallerRole.OPERATOR):
            raise EpochRevocationError(EpochRevocationFailureCode.CALLER_DENIED)
        try:
            invocation = EpochRevocationInvocationV1(
                schema_version=EPOCH_REVOCATION_INVOCATION_V1,
                command=command,
                attempt_id=self._attempt_id_factory(),
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
            raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED) from None
        try:
            body = await self._transport.post(self._route, canonical_json_bytes(invocation))
        except asyncio.CancelledError:
            raise
        except Exception:
            raise EpochRevocationError(EpochRevocationFailureCode.OUTCOME_UNKNOWN) from None
        try:
            outcome = decode_contract(body, EpochRevocationRelayResponseV1)
        except (ContractError, TypeError, ValueError):
            raise EpochRevocationError(EpochRevocationFailureCode.OUTCOME_UNKNOWN) from None
        if outcome.failure_code is not None:
            raise EpochRevocationError(outcome.failure_code)
        call_outcome = outcome.outcome
        if call_outcome is None:
            raise EpochRevocationError(EpochRevocationFailureCode.OUTCOME_UNKNOWN)
        if not _call_outcome_matches(call_outcome, invocation, self._route):
            raise EpochRevocationError(EpochRevocationFailureCode.OUTCOME_UNKNOWN)
        return call_outcome

    async def proof(
        self,
        command: EpochRevocationProofCommandV1,
        principal: AuthenticationContext,
    ) -> EpochRevocationProofV1:
        """Retrieve one exact proof through the same authenticated relay."""

        if type(command) is not EpochRevocationProofCommandV1:
            raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED)
        if not _context_matches(principal, self._policy, CallerRole.OPERATOR):
            raise EpochRevocationError(EpochRevocationFailureCode.CALLER_DENIED)
        try:
            invocation = EpochRevocationProofInvocationV1(
                schema_version=EPOCH_REVOCATION_PROOF_INVOCATION_V1,
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
            raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED) from None
        try:
            body = await self._transport.post(self._route, canonical_json_bytes(invocation))
        except asyncio.CancelledError:
            raise
        except Exception:
            raise EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED) from None
        try:
            outcome = decode_contract(body, EpochRevocationProofRelayResponseV1)
        except (ContractError, TypeError, ValueError):
            raise EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED) from None
        if outcome.failure_code is not None:
            raise EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED)
        proof = outcome.proof
        if (
            proof is None
            or not epoch_revocation_proof_matches_command(proof, command)
            or proof.result.operator_identity != invocation.operator_identity
            or proof.result.operator_subject != invocation.operator_subject
            or proof.result.target.project_id != self._route.project_id
            or proof.result.target.region != "us-central1"
            or proof.result.target.environment != "nonprod"
            or proof.result.target.service_name != "controlgraph-reference-target"
        ):
            raise EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED)
        return proof


class CoordinatorEpochRevocationRelay:
    """Authenticate the API workload, then preserve the verified operator identity."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        revoker: EpochRevokerPort,
        proof_reader: EpochRevocationProofPort,
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
            or not isinstance(revoker, EpochRevokerPort)
            or not isinstance(proof_reader, EpochRevocationProofPort)
        ):
            raise TypeError("revocation coordinator relay configuration is invalid")
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._revoker = revoker
        self._proof_reader = proof_reader

    async def revoke(
        self,
        invocation: EpochRevocationInvocationV1,
        caller: AuthenticationContext,
    ) -> EpochRevocationCallOutcomeV1:
        if not _context_matches(caller, self._authentication_policy, CallerRole.API):
            raise EpochRevocationError(EpochRevocationFailureCode.CALLER_DENIED)
        if type(invocation) is not EpochRevocationInvocationV1:
            raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED)
        operator = AuthenticationContext(
            role=CallerRole.OPERATOR,
            email=invocation.operator_identity,
            subject=invocation.operator_subject,
            issuer=invocation.operator_issuer,
            audience=invocation.operator_audience,
            issued_at=invocation.operator_issued_at,
            expires_at=invocation.operator_expires_at,
        )
        if not _context_matches(operator, self._operator_policy, CallerRole.OPERATOR):
            await self._revoker.record_authenticated_denial(
                invocation,
                code=EpochRevocationFailureCode.CALLER_DENIED,
            )
            raise EpochRevocationError(EpochRevocationFailureCode.CALLER_DENIED)
        result = await self._revoker.revoke(invocation, principal=operator)
        return EpochRevocationCallOutcomeV1(
            schema_version=EPOCH_REVOCATION_CALL_OUTCOME_V1,
            attempt_id=invocation.attempt_id,
            audit_id=invocation.attempt_id,
            result=result,
        )

    async def proof(
        self,
        invocation: EpochRevocationProofInvocationV1,
        caller: AuthenticationContext,
    ) -> EpochRevocationProofV1:
        """Authenticate the relay and return one exact verified proof."""

        if not _context_matches(caller, self._authentication_policy, CallerRole.API):
            raise EpochRevocationError(EpochRevocationFailureCode.CALLER_DENIED)
        if type(invocation) is not EpochRevocationProofInvocationV1:
            raise EpochRevocationError(EpochRevocationFailureCode.COMMAND_DENIED)
        operator = AuthenticationContext(
            role=CallerRole.OPERATOR,
            email=invocation.operator_identity,
            subject=invocation.operator_subject,
            issuer=invocation.operator_issuer,
            audience=invocation.operator_audience,
            issued_at=invocation.operator_issued_at,
            expires_at=invocation.operator_expires_at,
        )
        if not _context_matches(operator, self._operator_policy, CallerRole.OPERATOR):
            raise EpochRevocationError(EpochRevocationFailureCode.CALLER_DENIED)
        try:
            return await self._proof_reader.read(invocation, principal=operator)
        except asyncio.CancelledError:
            raise
        except EpochRevocationError:
            raise EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED) from None
        except Exception:
            raise EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED) from None


def _context_matches(
    context: object,
    policy: RouteAuthenticationPolicy,
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


def _result_matches(
    result: EpochRevocationResultV1,
    invocation: EpochRevocationInvocationV1,
    route: CoordinatorInternalRoute,
) -> bool:
    command = invocation.command
    return (
        result.request_sha256 == epoch_revocation_request_sha256(invocation)
        and result.request_id == command.request_id
        and result.idempotency_key == command.idempotency_key
        and result.root_id == command.root_id
        and result.root_sha256 == command.expected_root_sha256
        and result.target.project_id == route.project_id
        and result.target.region == "us-central1"
        and result.target.environment == "nonprod"
        and result.target.service_name == "controlgraph-reference-target"
        and result.operator_identity == invocation.operator_identity
        and result.operator_subject == invocation.operator_subject
        and result.reason == command.reason
        and result.previous_epoch == command.expected_epoch
        and result.new_epoch == command.expected_epoch + 1
        and result.evidence_id
        == epoch_revocation_evidence_id(
            result.request_sha256,
            result.root_sha256,
            result.new_epoch,
        )
    )


def _call_outcome_matches(
    outcome: EpochRevocationCallOutcomeV1,
    invocation: EpochRevocationInvocationV1,
    route: CoordinatorInternalRoute,
) -> bool:
    return (
        type(outcome) is EpochRevocationCallOutcomeV1
        and outcome.attempt_id == invocation.attempt_id
        and outcome.audit_id == invocation.attempt_id
        and _result_matches(outcome.result, invocation, route)
    )


def _new_attempt_id() -> str:
    return f"cgrevoke-attempt-{uuid4().hex}"


__all__ = [
    "ApiEpochRevocationClient",
    "CoordinatorEpochRevocationRelay",
    "EpochRevocationProofPort",
    "EpochRevokerPort",
]
