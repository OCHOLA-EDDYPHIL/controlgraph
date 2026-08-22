from __future__ import annotations

import asyncio

import pytest
from recovery_v2_test_data import make_revoked_v3_recovery_bundle
from test_receipt_authority import (
    PROJECT_ID,
    PROJECT_NUMBER,
    _BackingStore,
    _binding,
    _claimed_receipt,
    _target,
)

from controlgraph_canary.application.authority_store import (
    AuthorityStoreCorruptRecord,
    ReceiptClaimCreated,
)
from controlgraph_canary.application.identity import (
    RECEIPT_AUTHORITY_PATH,
    RECOVERY_RECEIPT_AUTHORITY_PATH,
    AuthenticationContext,
    CallerRole,
    ServiceRole,
)
from controlgraph_canary.application.receipt_authority import (
    ReceiptAuthorityClient,
    ReceiptAuthorityService,
)
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.authority.replay import MutationAction, MutationBinding, mutation_identity
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
)

SUBJECT = "123456789012345678901"


def _route(path: str) -> CoordinatorInternalRoute:
    return CoordinatorInternalRoute(
        project_id=PROJECT_ID,
        project_number=PROJECT_NUMBER,
        caller_role=CallerRole.EXECUTOR,
        service_role=ServiceRole.COORDINATOR,
        audience=(
            f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        override_path=path,
    )


def _caller(role: CallerRole = CallerRole.EXECUTOR) -> AuthenticationContext:
    account = "controlgraph-executor" if role is CallerRole.EXECUTOR else "controlgraph-recovery"
    return AuthenticationContext(
        role=role,
        email=f"{account}@{PROJECT_ID}.iam.gserviceaccount.com",
        subject=SUBJECT,
        issuer="https://accounts.google.com",
        audience=(
            f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        issued_at=1_777_000_000,
        expires_at=1_777_003_600,
    )


class _LoopbackTransport:
    def __init__(self, service: ReceiptAuthorityService, *, recovery: bool) -> None:
        self.service = service
        self.recovery = recovery
        self.calls = 0

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls += 1
        expected_path = (
            RECOVERY_RECEIPT_AUTHORITY_PATH if self.recovery else RECEIPT_AUTHORITY_PATH
        )
        assert route.path == expected_path
        if self.recovery:
            return await self.service.handle_recovery_authenticated(
                body,
                _caller(),
            )
        return await self.service.handle_authenticated(body, _caller())


def _recovery_claim() -> tuple[ExecutionReceipt, MutationBinding]:
    standard = _binding()
    binding = MutationBinding(
        idempotency_key=standard.idempotency_key,
        request_id=standard.request_id,
        root_id=standard.root_id,
        root_sha256=standard.root_sha256,
        epoch=standard.epoch,
        action=MutationAction.RECOVER_STABLE,
        target=standard.target,
        provider_precondition=standard.provider_precondition,
        plan_sha256=standard.plan_sha256,
        capability_sha256=standard.capability_sha256,
        payload_sha256=standard.payload_sha256,
        expected_poststate_sha256=standard.expected_poststate_sha256,
    )
    receipt = ExecutionReceipt.model_validate(
        {
            **_claimed_receipt().model_dump(mode="python"),
            "action": CapabilityAction.RECOVER_STABLE,
            "mutation_sha256": mutation_identity(binding),
        }
    )
    return receipt, binding


def _client(
    store: _BackingStore,
    *,
    recovery: bool,
) -> tuple[ReceiptAuthorityClient, _LoopbackTransport]:
    service = ReceiptAuthorityService(store)
    transport = _LoopbackTransport(service, recovery=recovery)
    path = RECOVERY_RECEIPT_AUTHORITY_PATH if recovery else RECEIPT_AUTHORITY_PATH
    return (
        ReceiptAuthorityClient(
            target=_target(),
            route=_route(path),
            transport=transport,
            attempt_id_factory=lambda: "recovery-receipt-attempt",
        ),
        transport,
    )


def test_receipt_paths_are_action_separated_under_executor_identity() -> None:
    recovery_receipt, recovery_binding = _recovery_claim()
    recovery_client, recovery_transport = _client(_BackingStore(), recovery=True)

    result = asyncio.run(
        recovery_client.claim_or_adopt_receipt(recovery_receipt, recovery_binding)
    )

    assert type(result) is ReceiptClaimCreated
    assert recovery_transport.calls == 1

    standard_client, standard_transport = _client(_BackingStore(), recovery=False)
    with pytest.raises(ValueError, match="outside the configured authority path"):
        asyncio.run(
            standard_client.claim_or_adopt_receipt(
                recovery_receipt,
                recovery_binding,
            )
        )
    assert standard_transport.calls == 0

    recovery_client, recovery_transport = _client(_BackingStore(), recovery=True)
    with pytest.raises(ValueError, match="outside the configured authority path"):
        asyncio.run(
            recovery_client.claim_or_adopt_receipt(
                _claimed_receipt(),
                _binding(),
            )
        )
    assert recovery_transport.calls == 0


def test_revoked_v3_recovery_does_not_expand_receipt_writer_identity() -> None:
    bundle = make_revoked_v3_recovery_bundle()
    assert bundle.task.capability.claims.subject == (
        f"controlgraph-recovery@{PROJECT_ID}.iam.gserviceaccount.com"
    )
    assert bundle.task.capability.claims.action is CapabilityAction.RECOVER_STABLE
    service = ReceiptAuthorityService(_BackingStore())
    caller = _caller(CallerRole.RECOVERY)

    with pytest.raises(AuthorityStoreCorruptRecord):
        asyncio.run(service.handle_authenticated(b"{}", caller))
    with pytest.raises(AuthorityStoreCorruptRecord):
        asyncio.run(service.handle_recovery_authenticated(b"{}", caller))
