"""Authenticated exact-key observation of one durable epoch revocation."""

from __future__ import annotations

import asyncio
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.revocation import EpochRevocationError
from controlgraph_canary.application.revocation_store import (
    EpochRevocationProofState,
    EpochRevocationProofStore,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_PROOF_V1,
    EpochRevocationFailureCode,
    EpochRevocationProofInvocationV1,
    EpochRevocationProofV1,
    epoch_revocation_proof_matches_command,
    epoch_revocation_proof_request_sha256,
)
from controlgraph_canary.contracts.root_creation import SignedEvidenceEventV1


@runtime_checkable
class EpochRevocationEvidenceVerifier(Protocol):
    """Verify stored evidence against one configured public KMS key version."""

    @property
    def evidence_key_version(self) -> str: ...

    async def verify(self, signed: SignedEvidenceEventV1) -> None: ...


class EpochRevocationProofService:
    """Return proof only after exact storage binding and signature verification."""

    def __init__(
        self,
        *,
        store: EpochRevocationProofStore,
        evidence_verifier: EpochRevocationEvidenceVerifier,
        operator_policy: RouteAuthenticationPolicy,
    ) -> None:
        if (
            not isinstance(store, EpochRevocationProofStore)
            or not isinstance(evidence_verifier, EpochRevocationEvidenceVerifier)
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or operator_policy.project_id != store.target.project_id
        ):
            raise TypeError("revocation proof configuration is invalid")
        self._store = store
        self._evidence_verifier = evidence_verifier
        self._operator_policy = operator_policy

    async def read(
        self,
        invocation: EpochRevocationProofInvocationV1,
        *,
        principal: AuthenticationContext | None,
    ) -> EpochRevocationProofV1:
        """Read and verify one complete proof or return one closed denial."""

        if (
            type(invocation) is not EpochRevocationProofInvocationV1
            or not self._operator_is_exact(invocation, principal)
            or epoch_revocation_proof_request_sha256(invocation)
            != invocation.command.request_sha256
        ):
            raise _proof_denied()
        try:
            state = await self._store.read_epoch_revocation_proof(invocation.command)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _proof_denied() from None
        if not self._state_is_exact(state, invocation):
            raise _proof_denied()
        assert state is not None
        try:
            proof = EpochRevocationProofV1(
                schema_version=EPOCH_REVOCATION_PROOF_V1,
                authority=state.authority.value,
                signed_evidence=state.signed_evidence.value,
                result=state.result.value,
                audit=state.audit.value,
            )
        except (TypeError, ValueError):
            raise _proof_denied() from None
        if (
            not epoch_revocation_proof_matches_command(proof, invocation.command)
            or proof.result.operator_identity != invocation.operator_identity
            or proof.result.operator_subject != invocation.operator_subject
            or proof.signed_evidence.signing_key_version
            != self._evidence_verifier.evidence_key_version
        ):
            raise _proof_denied()
        try:
            await self._evidence_verifier.verify(proof.signed_evidence)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _proof_denied() from None
        return proof

    def _operator_is_exact(
        self,
        invocation: EpochRevocationProofInvocationV1,
        principal: AuthenticationContext | None,
    ) -> bool:
        policy = self._operator_policy
        return (
            type(principal) is AuthenticationContext
            and principal.role is CallerRole.OPERATOR
            and principal.role is policy.caller.role
            and principal.email == invocation.operator_identity == policy.caller.email
            and principal.subject == invocation.operator_subject == policy.caller.subject
            and principal.issuer == invocation.operator_issuer
            and principal.issuer in {"accounts.google.com", "https://accounts.google.com"}
            and principal.audience == invocation.operator_audience == policy.audience
            and principal.issued_at == invocation.operator_issued_at
            and principal.expires_at == invocation.operator_expires_at
        )

    @staticmethod
    def _state_is_exact(
        state: EpochRevocationProofState | None,
        invocation: EpochRevocationProofInvocationV1,
    ) -> bool:
        return (
            type(state) is EpochRevocationProofState
            and state.command == invocation.command
            and type(state.authority) is StoredRecord
            and state.authority.revision == state.authority.value.revision
            and type(state.signed_evidence) is StoredRecord
            and state.signed_evidence.revision == 0
            and type(state.result) is StoredRecord
            and state.result.revision == 0
            and type(state.audit) is StoredRecord
            and state.audit.revision == 0
        )


def _proof_denied() -> EpochRevocationError:
    return EpochRevocationError(EpochRevocationFailureCode.PROOF_DENIED)


__all__ = [
    "EpochRevocationEvidenceVerifier",
    "EpochRevocationProofService",
]
