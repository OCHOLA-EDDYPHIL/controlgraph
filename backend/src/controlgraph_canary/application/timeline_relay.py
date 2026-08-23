"""Narrow authenticated API-to-coordinator timeline projection boundary."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Literal, cast

from controlgraph_canary.application.identity import (
    TIMELINE_RAW_EXPORT_PATH,
    TIMELINE_READ_PATH,
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.application.timeline import (
    TimelineRawExportError,
    TimelineRawExportErrorCode,
    TimelineRawExportGrant,
    TimelineRawExportService,
    TimelineReadError,
    TimelineReadErrorCode,
    TimelineReadGrant,
    TimelineReadService,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.timeline import (
    TimelineAudience,
    TimelinePageCommandV1,
    TimelinePageV1,
    TimelineRawExportCommandV1,
    TimelineRawExportV1,
)
from controlgraph_canary.contracts.timeline_relay import (
    TIMELINE_RAW_EXPORT_INVOCATION_V1,
    TIMELINE_READ_INVOCATION_V1,
    TimelineRawExportInvocationV1,
    TimelineReaderIdentityV1,
    TimelineReadInvocationV1,
)


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


def _reader(context: AuthenticationContext) -> TimelineReaderIdentityV1:
    return TimelineReaderIdentityV1(
        email=context.email,
        subject=context.subject,
        issuer=cast(
            Literal["accounts.google.com", "https://accounts.google.com"],
            context.issuer,
        ),
        audience=context.audience,
        issued_at=context.issued_at,
        expires_at=context.expires_at,
    )


def _reader_matches_policy(
    reader: TimelineReaderIdentityV1,
    policy: RouteAuthenticationPolicy,
) -> bool:
    return (
        reader.email == policy.caller.email
        and reader.subject == policy.caller.subject
        and reader.audience == policy.audience
        and reader.issuer in {"accounts.google.com", "https://accounts.google.com"}
    )


class ApiTimelineClient:
    """Relay only typed projection requests; never access the authority database."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        route: CoordinatorInternalRoute,
        operator_policy: RouteAuthenticationPolicy,
        security_audit_policy: RouteAuthenticationPolicy,
        restricted_export_policy: RouteAuthenticationPolicy,
        transport: CanonicalInternalTransport,
    ) -> None:
        policies = (operator_policy, security_audit_policy, restricted_export_policy)
        expected_roles = (
            CallerRole.OPERATOR,
            CallerRole.SECURITY_AUDITOR,
            CallerRole.RESTRICTED_EXPORTER,
        )
        identities = {(item.caller.email, item.caller.subject) for item in policies}
        if (
            type(target) is not TargetBinding
            or type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.API
            or route.service_role is not ServiceRole.COORDINATOR
            or any(
                type(item) is not RouteAuthenticationPolicy
                or item.service_role is not ServiceRole.API
                or item.caller.role is not expected_role
                or item.project_id != target.project_id
                or item.project_id != route.project_id
                or item.project_number != route.project_number
                for item, expected_role in zip(policies, expected_roles, strict=True)
            )
            or operator_policy.path != TIMELINE_READ_PATH
            or security_audit_policy.path != TIMELINE_READ_PATH
            or restricted_export_policy.path != TIMELINE_RAW_EXPORT_PATH
            or len(identities) != len(policies)
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise ValueError("timeline relay configuration is invalid")
        self._target = target
        self._route = route
        self._operator_policy = operator_policy
        self._security_audit_policy = security_audit_policy
        self._restricted_export_policy = restricted_export_policy
        self._transport = transport

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def read(
        self,
        command: TimelinePageCommandV1,
        principal: AuthenticationContext,
    ) -> TimelinePageV1:
        policy = (
            self._security_audit_policy
            if command.audience is TimelineAudience.SECURITY_AUDIT
            else self._operator_policy
            if command.audience in {TimelineAudience.PUBLIC_DEMO, TimelineAudience.OPERATOR}
            else None
        )
        if (
            type(command) is not TimelinePageCommandV1
            or command.target != self._target
            or policy is None
            or not _context_matches_policy(
                principal,
                policy,
                role=(
                    CallerRole.SECURITY_AUDITOR
                    if command.audience is TimelineAudience.SECURITY_AUDIT
                    else CallerRole.OPERATOR
                ),
            )
        ):
            raise TimelineReadError(TimelineReadErrorCode.ACCESS_DENIED)
        invocation = TimelineReadInvocationV1(
            schema_version=TIMELINE_READ_INVOCATION_V1,
            command=command,
            reader=_reader(principal),
        )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
            page = decode_contract(body, TimelinePageV1)
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise TimelineReadError(TimelineReadErrorCode.RESPONSE_INVALID) from None
        except Exception:
            raise TimelineReadError(TimelineReadErrorCode.STORE_UNAVAILABLE) from None
        if page.command != command:
            raise TimelineReadError(TimelineReadErrorCode.RESPONSE_INVALID)
        return page

    async def export(
        self,
        command: TimelineRawExportCommandV1,
        principal: AuthenticationContext,
    ) -> TimelineRawExportV1:
        if (
            type(command) is not TimelineRawExportCommandV1
            or command.target != self._target
            or not _context_matches_policy(
                principal,
                self._restricted_export_policy,
                role=CallerRole.RESTRICTED_EXPORTER,
            )
        ):
            raise TimelineRawExportError(TimelineRawExportErrorCode.ACCESS_DENIED)
        invocation = TimelineRawExportInvocationV1(
            schema_version=TIMELINE_RAW_EXPORT_INVOCATION_V1,
            command=command,
            reader=_reader(principal),
        )
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
            exported = decode_contract(body, TimelineRawExportV1)
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise TimelineRawExportError(
                TimelineRawExportErrorCode.RESPONSE_INVALID
            ) from None
        except Exception:
            raise TimelineRawExportError(
                TimelineRawExportErrorCode.STORE_UNAVAILABLE
            ) from None
        if exported.command != command:
            raise TimelineRawExportError(TimelineRawExportErrorCode.RESPONSE_INVALID)
        return exported


class CoordinatorTimelineRelay:
    """Re-authorize forwarded readers before coordinator-owned exact-ID reads."""

    def __init__(
        self,
        *,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        security_audit_policy: RouteAuthenticationPolicy,
        restricted_export_policy: RouteAuthenticationPolicy,
        read_service: TimelineReadService,
        raw_export_service: TimelineRawExportService,
    ) -> None:
        policies = (operator_policy, security_audit_policy, restricted_export_policy)
        expected_roles = (
            CallerRole.OPERATOR,
            CallerRole.SECURITY_AUDITOR,
            CallerRole.RESTRICTED_EXPORTER,
        )
        if (
            type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.COORDINATOR
            or authentication_policy.caller.role is not CallerRole.API
            or any(
                type(item) is not RouteAuthenticationPolicy
                or item.service_role is not ServiceRole.API
                or item.caller.role is not expected_role
                or item.project_id != authentication_policy.project_id
                or item.project_number != authentication_policy.project_number
                for item, expected_role in zip(policies, expected_roles, strict=True)
            )
            or operator_policy.path != TIMELINE_READ_PATH
            or security_audit_policy.path != TIMELINE_READ_PATH
            or restricted_export_policy.path != TIMELINE_RAW_EXPORT_PATH
            or len({(item.caller.email, item.caller.subject) for item in policies}) != 3
            or type(read_service) is not TimelineReadService
            or type(raw_export_service) is not TimelineRawExportService
            or read_service.target != raw_export_service.target
        ):
            raise ValueError("coordinator timeline relay configuration is invalid")
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._security_audit_policy = security_audit_policy
        self._restricted_export_policy = restricted_export_policy
        self._read_service = read_service
        self._raw_export_service = raw_export_service

    async def read(
        self,
        invocation: TimelineReadInvocationV1,
        caller: AuthenticationContext,
    ) -> TimelinePageV1:
        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise TimelineReadError(TimelineReadErrorCode.ACCESS_DENIED)
        if type(invocation) is not TimelineReadInvocationV1:
            raise TimelineReadError(TimelineReadErrorCode.ACCESS_DENIED)
        policy, ceiling = (
            (self._security_audit_policy, TimelineAudience.SECURITY_AUDIT)
            if invocation.command.audience is TimelineAudience.SECURITY_AUDIT
            else (self._operator_policy, TimelineAudience.OPERATOR)
        )
        if (
            invocation.command.audience is TimelineAudience.RESTRICTED
            or not _reader_matches_policy(invocation.reader, policy)
        ):
            raise TimelineReadError(TimelineReadErrorCode.ACCESS_DENIED)
        return await self._read_service.read(
            invocation.command,
            TimelineReadGrant(
                target=self._read_service.target,
                maximum_audience=ceiling,
                principal_id=_principal_id(invocation.reader.subject),
            ),
        )

    async def export(
        self,
        invocation: TimelineRawExportInvocationV1,
        caller: AuthenticationContext,
    ) -> TimelineRawExportV1:
        if (
            not _context_matches_policy(
                caller,
                self._authentication_policy,
                role=CallerRole.API,
            )
            or type(invocation) is not TimelineRawExportInvocationV1
            or not _reader_matches_policy(
                invocation.reader,
                self._restricted_export_policy,
            )
        ):
            raise TimelineRawExportError(TimelineRawExportErrorCode.ACCESS_DENIED)
        return await self._raw_export_service.export(
            invocation.command,
            TimelineRawExportGrant(
                target=self._raw_export_service.target,
                principal_id=_principal_id(invocation.reader.subject),
            ),
        )


def _principal_id(subject: str) -> str:
    return f"timeline-reader:{hashlib.sha256(subject.encode('ascii')).hexdigest()}"


__all__ = ["ApiTimelineClient", "CoordinatorTimelineRelay"]
