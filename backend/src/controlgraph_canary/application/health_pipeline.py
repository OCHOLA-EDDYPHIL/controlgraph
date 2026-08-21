"""Authenticated coordinator and verifier boundary for health evaluation."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal, Protocol, cast, runtime_checkable

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    StoredRecord,
)
from controlgraph_canary.application.health_orchestration import (
    HealthAttestationVerifier,
    HealthOrchestrationError,
    HealthOrchestrationErrorCode,
    VerifierHealthProofService,
)
from controlgraph_canary.application.health_store import (
    HealthAnchorWriteResult,
    HealthChainAppendResult,
    HealthChainSnapshot,
    HealthChainStore,
    HealthChainWriteDisposition,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.recovery_execution import RecoveryCoordinator
from controlgraph_canary.application.root_authority import (
    RootAuthorityBundle,
    inspect_root_authority_bundle,
)
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.application.timeline_recording import TimelineProjectionRecorder
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.health import HealthDecisionStatus
from controlgraph_canary.contracts.health_execution import (
    PostApplyHealthAnchorV1,
    SignedHealthDecisionProofV1,
    create_post_apply_health_anchor,
    create_signed_health_decision_chain,
)
from controlgraph_canary.contracts.health_pipeline import (
    HEALTH_EVALUATION_INVOCATION_V1,
    HEALTH_EVALUATION_RESULT_V2,
    VERIFIER_HEALTH_EVALUATION_RESULT_V1,
    HealthEvaluationCommandV1,
    HealthEvaluationInvocationV1,
    HealthEvaluationResultV1,
    HealthEvaluationResultV2,
    VerifierHealthEvaluationRequestV1,
    VerifierHealthEvaluationResultV1,
    create_verifier_health_evaluation_request,
    health_evaluation_command_sha256,
)
from controlgraph_canary.contracts.models import ExecutionReceipt, TargetBinding
from controlgraph_canary.contracts.promotion_execution import (
    create_promotion_health_chain_locator,
    create_verified_apply_receipt_locator,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryDispatchResultV2,
    RecoveryIntentV1,
    create_recovery_apply_receipt_locator,
    create_recovery_intent,
    create_unhealthy_recovery_command,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV3
from controlgraph_canary.contracts.storage import ServiceClaimStatus

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_REFERENCE_SERVICE = "controlgraph-reference-target"


class HealthPipelineErrorCode(StrEnum):
    """Stable payload-free failures for the live health boundary."""

    CONFIGURATION_INVALID = "HEALTH_PIPELINE_CONFIGURATION_INVALID"
    CALLER_DENIED = "HEALTH_PIPELINE_CALLER_DENIED"
    OPERATOR_DENIED = "HEALTH_PIPELINE_OPERATOR_DENIED"
    COMMAND_DENIED = "HEALTH_PIPELINE_COMMAND_DENIED"
    TRUSTED_STATE_UNAVAILABLE = "HEALTH_PIPELINE_TRUSTED_STATE_UNAVAILABLE"
    TRUSTED_STATE_INVALID = "HEALTH_PIPELINE_TRUSTED_STATE_INVALID"
    AUTHORITY_STALE = "HEALTH_PIPELINE_AUTHORITY_STALE"
    RECEIPT_INVALID = "HEALTH_PIPELINE_RECEIPT_INVALID"
    STORE_CONFLICT = "HEALTH_PIPELINE_STORE_CONFLICT"
    STORE_UNAVAILABLE = "HEALTH_PIPELINE_STORE_UNAVAILABLE"
    VERIFIER_UNAVAILABLE = "HEALTH_PIPELINE_VERIFIER_UNAVAILABLE"
    VERIFIER_RESPONSE_INVALID = "HEALTH_PIPELINE_VERIFIER_RESPONSE_INVALID"
    EVALUATION_NOT_READY = "HEALTH_PIPELINE_EVALUATION_NOT_READY"
    EVALUATION_TERMINAL = "HEALTH_PIPELINE_EVALUATION_TERMINAL"
    TRANSPORT_UNAVAILABLE = "HEALTH_PIPELINE_TRANSPORT_UNAVAILABLE"
    RESPONSE_INVALID = "HEALTH_PIPELINE_RESPONSE_INVALID"
    RESULT_INVALID = "HEALTH_PIPELINE_RESULT_INVALID"
    RECOVERY_UNAVAILABLE = "HEALTH_PIPELINE_RECOVERY_UNAVAILABLE"


class HealthPipelineError(RuntimeError):
    """One sanitized health-pipeline failure."""

    def __init__(self, code: HealthPipelineErrorCode) -> None:
        if type(code) is not HealthPipelineErrorCode:
            raise TypeError("an exact health pipeline error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class HealthEvaluationAuthorityReader(Protocol):
    """Read one coherent root authority bundle without mutation authority."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootAuthorityBundle | None: ...


@runtime_checkable
class HealthEvaluationReceiptReader(Protocol):
    """Strongly read the exact apply receipt named by the operator command."""

    @property
    def target(self) -> TargetBinding: ...

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None: ...


@runtime_checkable
class HealthEvaluationVerifier(Protocol):
    """One-shot client for the read-only verifier health route."""

    async def evaluate(
        self,
        request: VerifierHealthEvaluationRequestV1,
    ) -> VerifierHealthEvaluationResultV1: ...

    async def verify(self, signed_proof: SignedHealthDecisionProofV1) -> None: ...


class VerifierHealthProofServiceFactory(Protocol):
    """Build one root-and-anchor-bound stateless verifier service."""

    def __call__(
        self,
        *,
        root: RolloutRootV3,
        anchor: PostApplyHealthAnchorV1,
    ) -> VerifierHealthProofService: ...


@dataclass(frozen=True, slots=True)
class _TrustedHealthInputs:
    root: RolloutRootV3
    root_revision: int
    authority_revision: int
    receipt: StoredRecord[ExecutionReceipt]
    anchor: PostApplyHealthAnchorV1


class VerifierHealthEvaluationService:
    """Authenticate the coordinator and evaluate one bounded predecessor step."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authentication_policy: RouteAuthenticationPolicy,
        proof_service_factory: VerifierHealthProofServiceFactory,
    ) -> None:
        if (
            not _target_is_exact(target)
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != target.project_id
            or authentication_policy.service_role is not ServiceRole.VERIFIER
            or authentication_policy.path != protected_path(ServiceRole.VERIFIER)
            or authentication_policy.caller.role is not CallerRole.COORDINATOR
            or not callable(proof_service_factory)
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._authentication_policy = authentication_policy
        self._proof_service_factory = proof_service_factory

    async def evaluate(
        self,
        request: VerifierHealthEvaluationRequestV1,
        caller: AuthenticationContext,
    ) -> VerifierHealthEvaluationResultV1:
        """Return exactly one independently evaluated and attested signed proof."""

        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.COORDINATOR,
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.CALLER_DENIED)
        if (
            type(request) is not VerifierHealthEvaluationRequestV1
            or request.command.target != self._target
            or request.root.content.target != self._target
            or request.anchor.target != self._target
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.COMMAND_DENIED)
        try:
            validated = VerifierHealthEvaluationRequestV1.model_validate(request)
            proof_service = self._proof_service_factory(
                root=validated.root,
                anchor=validated.anchor,
            )
        except asyncio.CancelledError:
            raise
        except (TypeError, ValueError):
            raise HealthPipelineError(HealthPipelineErrorCode.COMMAND_DENIED) from None
        except HealthOrchestrationError as error:
            raise HealthPipelineError(_map_orchestration_error(error.code)) from None
        except Exception:
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_UNAVAILABLE
            ) from None
        if type(proof_service) is not VerifierHealthProofService:
            raise HealthPipelineError(HealthPipelineErrorCode.VERIFIER_UNAVAILABLE)
        try:
            signed = await proof_service.evaluate_and_attest(
                validated.prior_signed_proof
            )
        except asyncio.CancelledError:
            raise
        except HealthOrchestrationError as error:
            raise HealthPipelineError(_map_orchestration_error(error.code)) from None
        except Exception:
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_UNAVAILABLE
            ) from None
        if not _signed_proof_matches_request(signed, validated):
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            )
        predecessor_sha256 = (
            canonical_sha256(validated.prior_signed_proof)
            if validated.prior_signed_proof is not None
            else None
        )
        try:
            return VerifierHealthEvaluationResultV1(
                schema_version=VERIFIER_HEALTH_EVALUATION_RESULT_V1,
                request_sha256=validated.request_sha256,
                target=self._target,
                root_id=validated.root.root_id,
                root_sha256=validated.root.root_sha256,
                epoch=validated.anchor.epoch,
                anchor_id=validated.anchor.anchor_id,
                anchor_sha256=validated.anchor_sha256,
                prior_signed_proof_sha256=predecessor_sha256,
                signed_proof=signed,
                signed_proof_sha256=canonical_sha256(signed),
            )
        except (TypeError, ValueError):
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            ) from None


class CoordinatorHealthEvaluationClient:
    """Call the fixed verifier route once and reject response substitution."""

    def __init__(
        self,
        *,
        route: CoordinatorInternalRoute,
        transport: CanonicalInternalTransport,
        signature_verifier: HealthAttestationVerifier,
    ) -> None:
        if (
            type(route) is not CoordinatorInternalRoute
            or route.caller_role is not CallerRole.COORDINATOR
            or route.service_role is not ServiceRole.VERIFIER
            or route.path != protected_path(ServiceRole.VERIFIER)
            or not isinstance(transport, CanonicalInternalTransport)
            or not isinstance(signature_verifier, HealthAttestationVerifier)
            or getattr(signature_verifier, "project_id", None) != route.project_id
            or type(getattr(signature_verifier, "key_version", None)) is not str
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._transport = transport
        self._signature_verifier = signature_verifier

    async def evaluate(
        self,
        request: VerifierHealthEvaluationRequestV1,
    ) -> VerifierHealthEvaluationResultV1:
        """Make one canonical POST with no application retry."""

        if (
            type(request) is not VerifierHealthEvaluationRequestV1
            or request.command.target.project_id != self._route.project_id
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.COMMAND_DENIED)
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthPipelineError(
                HealthPipelineErrorCode.TRANSPORT_UNAVAILABLE
            ) from None
        try:
            result = decode_contract(body, VerifierHealthEvaluationResultV1)
        except (ContractError, TypeError, ValueError):
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            ) from None
        if not _verifier_result_matches_request(result, request):
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            )
        if (
            result.signed_proof.signing_key_version
            != request.anchor.evidence_signing_key_version
            or getattr(self._signature_verifier, "key_version", None)
            != request.anchor.evidence_signing_key_version
        ):
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            )
        await self.verify(result.signed_proof)
        return result

    async def verify(self, signed_proof: SignedHealthDecisionProofV1) -> None:
        """Verify one returned or exactly adopted proof with the configured key."""

        if (
            type(signed_proof) is not SignedHealthDecisionProofV1
            or signed_proof.proof.decision.target.project_id != self._route.project_id
            or signed_proof.signing_key_version
            != getattr(self._signature_verifier, "key_version", None)
        ):
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            )
        try:
            await self._signature_verifier.verify(signed_proof)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            ) from None


class CoordinatorHealthEvaluationService:
    """Read trusted state, call the verifier, and append one proof by CAS."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authentication_policy: RouteAuthenticationPolicy,
        operator_policy: RouteAuthenticationPolicy,
        authority_reader: HealthEvaluationAuthorityReader,
        receipt_reader: HealthEvaluationReceiptReader,
        health_store: HealthChainStore,
        verifier: HealthEvaluationVerifier,
        recovery_coordinator: RecoveryCoordinator,
        timeline_recorder: TimelineProjectionRecorder | None = None,
    ) -> None:
        if (
            not _target_is_exact(target)
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.project_id != target.project_id
            or authentication_policy.service_role is not ServiceRole.COORDINATOR
            or authentication_policy.path != protected_path(ServiceRole.COORDINATOR)
            or authentication_policy.caller.role is not CallerRole.API
            or type(operator_policy) is not RouteAuthenticationPolicy
            or operator_policy.project_id != target.project_id
            or operator_policy.project_number != authentication_policy.project_number
            or operator_policy.service_role is not ServiceRole.API
            or operator_policy.caller.role is not CallerRole.OPERATOR
            or not isinstance(authority_reader, HealthEvaluationAuthorityReader)
            or not isinstance(receipt_reader, HealthEvaluationReceiptReader)
            or not isinstance(health_store, HealthChainStore)
            or not isinstance(verifier, HealthEvaluationVerifier)
            or not isinstance(recovery_coordinator, RecoveryCoordinator)
            or (
                timeline_recorder is not None
                and (
                    not isinstance(timeline_recorder, TimelineProjectionRecorder)
                    or timeline_recorder.target != target
                )
            )
            or authority_reader.target != target
            or receipt_reader.target != target
            or health_store.target != target
            or health_store.service_role is not ServiceRole.COORDINATOR
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.CONFIGURATION_INVALID)
        self._target = target
        self._authentication_policy = authentication_policy
        self._operator_policy = operator_policy
        self._authority_reader = authority_reader
        self._receipt_reader = receipt_reader
        self._health_store = health_store
        self._verifier = verifier
        self._recovery_coordinator = recovery_coordinator
        self._timeline_recorder = timeline_recorder

    async def evaluate(
        self,
        invocation: HealthEvaluationInvocationV1,
        caller: AuthenticationContext,
    ) -> HealthEvaluationResultV2:
        """Advance one exact health chain or adopt an already terminal result."""

        if not _context_matches_policy(
            caller,
            self._authentication_policy,
            role=CallerRole.API,
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.CALLER_DENIED)
        if type(invocation) is not HealthEvaluationInvocationV1:
            raise HealthPipelineError(HealthPipelineErrorCode.COMMAND_DENIED)
        if not _invocation_operator_is_exact(invocation, self._operator_policy):
            raise HealthPipelineError(HealthPipelineErrorCode.OPERATOR_DENIED)
        command = invocation.command
        if command.target != self._target:
            raise HealthPipelineError(HealthPipelineErrorCode.COMMAND_DENIED)

        trusted = await self._read_trusted_inputs(command)
        try:
            anchor_write = await self._health_store.create_or_adopt_health_anchor(
                trusted.anchor
            )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_CONFLICT) from None
        except (
            AuthorityStoreCorruptRecord,
            AuthorityStoreOutcomeUnknown,
            AuthorityStoreUnavailable,
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_UNAVAILABLE) from None
        except Exception:
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_UNAVAILABLE) from None
        if type(anchor_write) is not HealthAnchorWriteResult:
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_UNAVAILABLE)
        snapshot = anchor_write.snapshot
        if not _snapshot_matches_anchor(snapshot, trusted.anchor):
            raise HealthPipelineError(HealthPipelineErrorCode.TRUSTED_STATE_INVALID)
        relation = _snapshot_relation(snapshot, command)
        if relation == "CONFLICT":
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_CONFLICT)
        if relation == "ADOPT":
            return await self._adopt_snapshot(command, trusted, snapshot)

        predecessor = (
            snapshot.signed_proofs[-1].value if snapshot.signed_proofs else None
        )
        try:
            request = create_verifier_health_evaluation_request(
                command=command,
                root=trusted.root,
                anchor=trusted.anchor,
                prior_signed_proof=predecessor,
            )
            verifier_result = await self._verifier.evaluate(request)
        except asyncio.CancelledError:
            raise
        except HealthPipelineError:
            raise
        except Exception:
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_UNAVAILABLE
            ) from None
        if not _verifier_result_matches_request(verifier_result, request):
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            )

        refreshed = await self._read_trusted_inputs(command)
        if not _trusted_inputs_unchanged(trusted, refreshed):
            raise HealthPipelineError(HealthPipelineErrorCode.AUTHORITY_STALE)
        recovery_intent = _terminal_recovery_intent(
            trusted=trusted,
            snapshot=snapshot,
            signed_proof=verifier_result.signed_proof,
        )
        try:
            if recovery_intent is None:
                appended = await self._health_store.append_signed_health_proof(
                    snapshot,
                    verifier_result.signed_proof,
                )
            else:
                appended = await self._health_store.append_signed_health_proof(
                    snapshot,
                    verifier_result.signed_proof,
                    recovery_intent,
                )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            return await self._adopt_concurrent_next(command, trusted)
        except (
            AuthorityStoreCorruptRecord,
            AuthorityStoreOutcomeUnknown,
            AuthorityStoreUnavailable,
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_UNAVAILABLE) from None
        except Exception:
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_UNAVAILABLE) from None
        if (
            type(appended) is not HealthChainAppendResult
            or not _snapshot_matches_anchor(appended.snapshot, trusted.anchor)
            or _snapshot_relation(appended.snapshot, command) != "ADOPT"
            or appended.snapshot.signed_proofs[-1].value
            != verifier_result.signed_proof
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.TRUSTED_STATE_INVALID)
        await self._record_timeline_proof(verifier_result.signed_proof)
        return await self._complete_result(
            command=command,
            snapshot=appended.snapshot,
            disposition=appended.disposition,
        )

    async def _adopt_concurrent_next(
        self,
        command: HealthEvaluationCommandV1,
        trusted: _TrustedHealthInputs,
    ) -> HealthEvaluationResultV2:
        try:
            snapshot = await self._health_store.read_health_chain(
                trusted.anchor.anchor_id
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_UNAVAILABLE) from None
        if type(snapshot) is not HealthChainSnapshot or not _snapshot_matches_anchor(
            snapshot,
            trusted.anchor,
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_CONFLICT)
        if _snapshot_relation(snapshot, command) != "ADOPT":
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_CONFLICT)
        return await self._adopt_snapshot(command, trusted, snapshot)

    async def _adopt_snapshot(
        self,
        command: HealthEvaluationCommandV1,
        trusted: _TrustedHealthInputs,
        snapshot: HealthChainSnapshot,
    ) -> HealthEvaluationResultV2:
        if not snapshot.signed_proofs:
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_CONFLICT)
        try:
            await self._verifier.verify(snapshot.signed_proofs[-1].value)
        except asyncio.CancelledError:
            raise
        except HealthPipelineError:
            raise
        except Exception:
            raise HealthPipelineError(
                HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
            ) from None
        refreshed = await self._read_trusted_inputs(command)
        if not _trusted_inputs_unchanged(trusted, refreshed):
            raise HealthPipelineError(HealthPipelineErrorCode.AUTHORITY_STALE)
        await self._record_timeline_proof(snapshot.signed_proofs[-1].value)
        return await self._complete_result(
            command=command,
            snapshot=snapshot,
            disposition=HealthChainWriteDisposition.ADOPTED,
        )

    async def _complete_result(
        self,
        *,
        command: HealthEvaluationCommandV1,
        snapshot: HealthChainSnapshot,
        disposition: HealthChainWriteDisposition,
    ) -> HealthEvaluationResultV2:
        recovery: RecoveryDispatchResultV2 | None = None
        if (
            snapshot.signed_proofs
            and snapshot.signed_proofs[-1].value.proof.decision.status
            is HealthDecisionStatus.UNHEALTHY
        ):
            intent = snapshot.recovery_intent
            if (
                type(intent) is not StoredRecord
                or type(intent.value) is not RecoveryIntentV1
            ):
                raise HealthPipelineError(
                    HealthPipelineErrorCode.TRUSTED_STATE_INVALID
                )
            await self._record_timeline_recovery_intent(intent.value)
            try:
                recovery = await self._recovery_coordinator.dispatch(
                    intent.value.command
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise HealthPipelineError(
                    HealthPipelineErrorCode.RECOVERY_UNAVAILABLE
                ) from None
        return _health_result(
            command=command,
            snapshot=snapshot,
            disposition=disposition,
            recovery_dispatch=recovery,
        )

    async def _record_timeline_proof(
        self,
        signed_proof: SignedHealthDecisionProofV1,
    ) -> None:
        recorder = self._timeline_recorder
        if recorder is None:
            return
        try:
            await recorder.record_signed_health_proof(signed_proof)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_UNAVAILABLE) from None

    async def _record_timeline_recovery_intent(
        self,
        intent: RecoveryIntentV1,
    ) -> None:
        recorder = self._timeline_recorder
        if recorder is None:
            return
        try:
            await recorder.record_recovery_intent(intent)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthPipelineError(HealthPipelineErrorCode.STORE_UNAVAILABLE) from None

    async def _read_trusted_inputs(
        self,
        command: HealthEvaluationCommandV1,
    ) -> _TrustedHealthInputs:
        try:
            bundle, receipt_record = await asyncio.gather(
                self._authority_reader.read_root_creation_bundle(command.root_id),
                self._receipt_reader.read_receipt(
                    command.verified_apply_receipt.idempotency_key
                ),
            )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise HealthPipelineError(
                HealthPipelineErrorCode.TRUSTED_STATE_INVALID
            ) from None
        except (
            AuthorityStoreOutcomeUnknown,
            AuthorityStoreUnavailable,
        ):
            raise HealthPipelineError(
                HealthPipelineErrorCode.TRUSTED_STATE_UNAVAILABLE
            ) from None
        except Exception:
            raise HealthPipelineError(
                HealthPipelineErrorCode.TRUSTED_STATE_UNAVAILABLE
            ) from None
        trusted = inspect_root_authority_bundle(bundle, target=self._target)
        if trusted is None or type(trusted.root) is not RolloutRootV3:
            raise HealthPipelineError(HealthPipelineErrorCode.TRUSTED_STATE_INVALID)
        root = trusted.root
        if (
            root.root_id != command.root_id
            or root.root_sha256 != command.expected_root_sha256
            or root.content.target != command.target
            or trusted.service_claim.status is not ServiceClaimStatus.ACTIVE
            or trusted.authority.current_epoch != command.expected_epoch
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.AUTHORITY_STALE)
        if (
            type(receipt_record) is not StoredRecord
            or type(receipt_record.value) is not ExecutionReceipt
            or receipt_record.revision < 2
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.RECEIPT_INVALID)
        receipt = receipt_record.value
        try:
            receipt_locator = create_verified_apply_receipt_locator(receipt)
            anchor = create_post_apply_health_anchor(
                root=root,
                apply_receipt=receipt,
            )
        except (TypeError, ValueError):
            raise HealthPipelineError(HealthPipelineErrorCode.RECEIPT_INVALID) from None
        if (
            receipt_locator != command.verified_apply_receipt
            or receipt.target != command.target
            or receipt.root_id != command.root_id
            or receipt.root_sha256 != command.expected_root_sha256
            or receipt.epoch != command.expected_epoch
            or receipt.plan_sha256 != canonical_sha256(root.content.rollout_plan)
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.RECEIPT_INVALID)
        return _TrustedHealthInputs(
            root=root,
            root_revision=trusted.root_revision,
            authority_revision=trusted.authority_revision,
            receipt=receipt_record,
            anchor=anchor,
        )


class ApiHealthEvaluationClient:
    """Relay one authenticated operator command to the fixed coordinator route."""

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
            or route.path != protected_path(ServiceRole.COORDINATOR)
            or type(authentication_policy) is not RouteAuthenticationPolicy
            or authentication_policy.service_role is not ServiceRole.API
            or authentication_policy.caller.role is not CallerRole.OPERATOR
            or authentication_policy.project_id != route.project_id
            or authentication_policy.project_number != route.project_number
            or not isinstance(transport, CanonicalInternalTransport)
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.CONFIGURATION_INVALID)
        self._route = route
        self._authentication_policy = authentication_policy
        self._transport = transport

    async def evaluate(
        self,
        command: HealthEvaluationCommandV1,
        principal: AuthenticationContext,
    ) -> HealthEvaluationResultV2:
        """Forward the command once and accept only its exact compact result."""

        if (
            type(command) is not HealthEvaluationCommandV1
            or command.target.project_id != self._route.project_id
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.COMMAND_DENIED)
        if not _context_matches_policy(
            principal,
            self._authentication_policy,
            role=CallerRole.OPERATOR,
        ):
            raise HealthPipelineError(HealthPipelineErrorCode.OPERATOR_DENIED)
        try:
            invocation = HealthEvaluationInvocationV1(
                schema_version=HEALTH_EVALUATION_INVOCATION_V1,
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
            raise HealthPipelineError(HealthPipelineErrorCode.OPERATOR_DENIED) from None
        try:
            body = await self._transport.post(
                self._route,
                canonical_json_bytes(invocation),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HealthPipelineError(
                HealthPipelineErrorCode.TRANSPORT_UNAVAILABLE
            ) from None
        try:
            result = decode_contract(body, HealthEvaluationResultV2)
        except (ContractError, TypeError, ValueError):
            raise HealthPipelineError(HealthPipelineErrorCode.RESPONSE_INVALID) from None
        if not _health_result_matches_command(result, command):
            raise HealthPipelineError(HealthPipelineErrorCode.RESPONSE_INVALID)
        return result


def _signed_proof_matches_request(
    signed: object,
    request: VerifierHealthEvaluationRequestV1,
) -> bool:
    if type(signed) is not SignedHealthDecisionProofV1:
        return False
    proof = signed.proof
    predecessor = request.prior_signed_proof
    expected_sequence = 1 if predecessor is None else predecessor.proof.sequence + 1
    expected_previous = canonical_sha256(predecessor) if predecessor is not None else None
    return (
        proof.anchor_id == request.anchor.anchor_id
        and proof.anchor_sha256 == request.anchor_sha256
        and proof.sequence == expected_sequence
        and proof.previous_signed_proof_sha256 == expected_previous
        and proof.decision.target == request.command.target
        and proof.decision.root_id == request.root.root_id
        and proof.decision.root_sha256 == request.root.root_sha256
        and proof.decision.epoch == request.command.expected_epoch
        and signed.signing_key_version
        == request.anchor.evidence_signing_key_version
    )


def _verifier_result_matches_request(
    result: object,
    request: VerifierHealthEvaluationRequestV1,
) -> bool:
    if type(result) is not VerifierHealthEvaluationResultV1:
        return False
    predecessor_sha256 = (
        canonical_sha256(request.prior_signed_proof)
        if request.prior_signed_proof is not None
        else None
    )
    return (
        result.request_sha256 == request.request_sha256
        and result.target == request.command.target
        and result.root_id == request.root.root_id
        and result.root_sha256 == request.root.root_sha256
        and result.epoch == request.command.expected_epoch
        and result.anchor_id == request.anchor.anchor_id
        and result.anchor_sha256 == request.anchor_sha256
        and result.prior_signed_proof_sha256 == predecessor_sha256
        and result.signed_proof_sha256 == canonical_sha256(result.signed_proof)
        and _signed_proof_matches_request(result.signed_proof, request)
    )


def _snapshot_matches_anchor(
    snapshot: object,
    anchor: PostApplyHealthAnchorV1,
) -> bool:
    return (
        type(snapshot) is HealthChainSnapshot
        and snapshot.anchor.value == anchor
        and snapshot.anchor.revision == 0
        and snapshot.target == anchor.target
    )


def _trusted_inputs_unchanged(
    initial: _TrustedHealthInputs,
    refreshed: _TrustedHealthInputs,
) -> bool:
    return (
        refreshed.root == initial.root
        and refreshed.root_revision == initial.root_revision
        and refreshed.authority_revision == initial.authority_revision
        and refreshed.receipt == initial.receipt
        and refreshed.anchor == initial.anchor
    )


def _map_orchestration_error(
    code: HealthOrchestrationErrorCode,
) -> HealthPipelineErrorCode:
    if code is HealthOrchestrationErrorCode.EVALUATION_NOT_READY:
        return HealthPipelineErrorCode.EVALUATION_NOT_READY
    if code is HealthOrchestrationErrorCode.EVALUATION_TERMINAL:
        return HealthPipelineErrorCode.EVALUATION_TERMINAL
    if code in {
        HealthOrchestrationErrorCode.STATE_INVALID,
        HealthOrchestrationErrorCode.SIGNATURE_INVALID,
        HealthOrchestrationErrorCode.EVALUATION_INVALID,
        HealthOrchestrationErrorCode.ATTESTATION_INVALID,
    }:
        return HealthPipelineErrorCode.VERIFIER_RESPONSE_INVALID
    return HealthPipelineErrorCode.VERIFIER_UNAVAILABLE


def _snapshot_relation(
    snapshot: HealthChainSnapshot,
    command: HealthEvaluationCommandV1,
) -> Literal["EVALUATE", "ADOPT", "CONFLICT"]:
    sequence = snapshot.terminal_sequence
    head = snapshot.chain_head_sha256
    expected_sequence = command.expected_sequence
    expected_head = command.expected_chain_head_sha256
    if sequence == expected_sequence and head == expected_head:
        if (
            snapshot.signed_proofs
            and snapshot.signed_proofs[-1].value.proof.decision.next_evaluation_at
            is None
        ):
            return "CONFLICT"
        return "EVALUATE"
    if sequence != expected_sequence + 1 or not snapshot.signed_proofs:
        return "CONFLICT"
    proof = snapshot.signed_proofs[-1].value.proof
    if (
        proof.sequence != expected_sequence + 1
        or proof.previous_signed_proof_sha256 != expected_head
    ):
        return "CONFLICT"
    return "ADOPT"


def _health_result(
    *,
    command: HealthEvaluationCommandV1,
    snapshot: HealthChainSnapshot,
    disposition: HealthChainWriteDisposition,
    recovery_dispatch: RecoveryDispatchResultV2 | None,
) -> HealthEvaluationResultV2:
    manifest_record = snapshot.manifest
    chain = snapshot.signed_chain
    if (
        type(manifest_record) is not StoredRecord
        or chain is None
        or not snapshot.signed_proofs
        or type(disposition) is not HealthChainWriteDisposition
    ):
        raise HealthPipelineError(HealthPipelineErrorCode.RESULT_INVALID)
    manifest = manifest_record.value
    terminal = snapshot.signed_proofs[-1].value.proof
    try:
        locator = (
            create_promotion_health_chain_locator(chain)
            if terminal.decision.status.value == "healthy"
            else None
        )
        return HealthEvaluationResultV2(
            schema_version=HEALTH_EVALUATION_RESULT_V2,
            request_id=command.request_id,
            idempotency_key=command.idempotency_key,
            command_sha256=health_evaluation_command_sha256(command),
            target=command.target,
            root_id=command.root_id,
            root_sha256=command.expected_root_sha256,
            epoch=command.expected_epoch,
            verified_apply_receipt=command.verified_apply_receipt,
            expected_sequence=command.expected_sequence,
            expected_chain_head_sha256=command.expected_chain_head_sha256,
            anchor_id=snapshot.anchor.value.anchor_id,
            anchor_sha256=canonical_sha256(snapshot.anchor.value),
            chain_id=manifest.chain_id,
            health_chain_sha256=manifest.manifest_sha256,
            chain_head_sha256=manifest.chain_head_sha256,
            ordered_proof_chain_sha256=manifest.ordered_proof_chain_sha256,
            terminal_sequence=manifest.terminal_sequence,
            terminal_status=terminal.decision.status,
            terminal_health_decision_sha256=terminal.decision_sha256,
            next_evaluation_at=terminal.decision.next_evaluation_at,
            append_disposition=disposition.value,
            promotion_health_chain=locator,
            recovery_dispatch=recovery_dispatch,
        )
    except HealthPipelineError:
        raise
    except (TypeError, ValueError):
        raise HealthPipelineError(HealthPipelineErrorCode.RESULT_INVALID) from None


def _health_result_matches_command(
    result: object,
    command: HealthEvaluationCommandV1,
) -> bool:
    return (
        type(result) is HealthEvaluationResultV2
        and result.request_id == command.request_id
        and result.idempotency_key == command.idempotency_key
        and result.command_sha256 == health_evaluation_command_sha256(command)
        and result.target == command.target
        and result.root_id == command.root_id
        and result.root_sha256 == command.expected_root_sha256
        and result.epoch == command.expected_epoch
        and result.verified_apply_receipt == command.verified_apply_receipt
        and result.expected_sequence == command.expected_sequence
        and result.expected_chain_head_sha256
        == command.expected_chain_head_sha256
    )


def decode_health_evaluation_result(
    body: bytes,
) -> HealthEvaluationResultV1 | HealthEvaluationResultV2:
    """Decode the current result while retaining explicit historical V1 reads."""

    try:
        return decode_contract(body, HealthEvaluationResultV2)
    except ContractError:
        return decode_contract(body, HealthEvaluationResultV1)


def _terminal_recovery_intent(
    *,
    trusted: _TrustedHealthInputs,
    snapshot: HealthChainSnapshot,
    signed_proof: SignedHealthDecisionProofV1,
) -> RecoveryIntentV1 | None:
    decision = signed_proof.proof.decision
    if decision.status is not HealthDecisionStatus.UNHEALTHY:
        return None
    try:
        chain = create_signed_health_decision_chain(
            anchor=trusted.anchor,
            signed_proofs=(
                *(record.value for record in snapshot.signed_proofs),
                signed_proof,
            ),
        )
        receipt = create_recovery_apply_receipt_locator(
            trusted.receipt.value,
            storage_revision=trusted.receipt.revision,
        )
        triggered = datetime.strptime(
            decision.evaluated_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        scheduled_at = (triggered + timedelta(seconds=120)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        command = create_unhealthy_recovery_command(
            signed_health_chain=chain,
            verified_apply_receipt=receipt,
            request_id=f"recover-{trusted.root.root_sha256}",
            idempotency_key=f"recover-once-{trusted.root.root_sha256}",
            scheduled_at=scheduled_at,
        )
        return create_recovery_intent(
            command,
            created_at=decision.evaluated_at,
        )
    except (TypeError, ValueError):
        raise HealthPipelineError(HealthPipelineErrorCode.TRUSTED_STATE_INVALID) from None


def _invocation_operator_is_exact(
    invocation: HealthEvaluationInvocationV1,
    policy: RouteAuthenticationPolicy,
) -> bool:
    caller = policy.caller
    return (
        invocation.operator_identity == caller.email
        and invocation.operator_subject == caller.subject
        and invocation.operator_issuer
        in {"accounts.google.com", "https://accounts.google.com"}
        and invocation.operator_audience == policy.audience
        and invocation.operator_issued_at < invocation.operator_expires_at
        and invocation.operator_expires_at - invocation.operator_issued_at <= 3_660
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


def _target_is_exact(target: object) -> bool:
    return (
        type(target) is TargetBinding
        and _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is not None
        and "reconcile" not in target.project_id
        and target.region == "us-central1"
        and target.environment == "nonprod"
        and target.service_name == _REFERENCE_SERVICE
    )


__all__ = [
    "ApiHealthEvaluationClient",
    "CoordinatorHealthEvaluationClient",
    "CoordinatorHealthEvaluationService",
    "HealthEvaluationAuthorityReader",
    "HealthEvaluationReceiptReader",
    "HealthEvaluationVerifier",
    "HealthPipelineError",
    "HealthPipelineErrorCode",
    "VerifierHealthEvaluationService",
    "VerifierHealthProofServiceFactory",
    "decode_health_evaluation_result",
]
