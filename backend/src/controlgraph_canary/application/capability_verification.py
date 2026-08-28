"""Fail-closed verification for protected mutation task requests."""

from __future__ import annotations

import asyncio
import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import AuthorityStoreError
from controlgraph_canary.application.cloud_run import (
    rollout_root_v3_target_configuration_sha256,
)
from controlgraph_canary.application.identity import (
    RECOVERY_EXECUTION_FACADE_PATH,
    AuthenticationContext,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
)
from controlgraph_canary.application.root_authority import (
    RootAuthorityBundleReader,
    TrustedRootAuthority,
    capability_claims_match_root_authority,
    capability_scope_from_claims,
    inspect_root_authority_bundle,
    operator_lineage_anchor,
)
from controlgraph_canary.application.signing import (
    DETACHED_SIGNATURE_V1,
    DetachedSignature,
    SigningError,
    SigningErrorCode,
    SigningProfile,
    SigningPurpose,
    TrustBundleVerifier,
    build_signing_input,
)
from controlgraph_canary.authority.policy import (
    MAX_LINEAGE_DEPTH,
    CapabilityGrant,
    validate_lineage,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    ContractErrorCode,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    CapabilityClaims,
    ReasonCode,
    SignedCapability,
    TargetBinding,
    TaskRequest,
)
from controlgraph_canary.contracts.promotion_execution import (
    PromotionAuthorizationV1,
    PromotionTaskRequestV2,
    promotion_capability_id,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryAuthorizationV1,
    RecoveryPrestateAttestationV1,
    RecoveryTaskRequestV2,
    RevokedV2RecoverySourceV1,
    RevokedV3RecoverySourceV1,
    UnhealthyRecoverySourceV1,
    recovery_capability_id,
    recovery_target_configuration_sha256,
)
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV2,
    RolloutRootV3,
)

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})

type ProtectedMutationRequest = (
    TaskRequest | PromotionTaskRequestV2 | RecoveryTaskRequestV2
)


class CapabilityVerificationError(Exception):
    """A payload-free verification denial with one stable product reason."""

    def __init__(self, code: ReasonCode) -> None:
        if type(code) is not ReasonCode:
            raise TypeError("an exact capability verification reason is required")
        self.code = code
        super().__init__(code.value)


def _deny(code: ReasonCode) -> CapabilityVerificationError:
    return CapabilityVerificationError(code)


@runtime_checkable
class CapabilityLineageReader(Protocol):
    """Resolve one complete root-to-parent capability lineage by trusted digest."""

    async def resolve_lineage(
        self,
        parent_capability_sha256: str,
    ) -> tuple[SignedCapability, ...] | None: ...


@runtime_checkable
class CapabilityRequestVerifier(Protocol):
    """The sole verifier interface admitted by protected task entry points."""

    async def verify(
        self,
        payload: bytes,
        caller: AuthenticationContext,
    ) -> VerifiedMutation: ...


@runtime_checkable
class RecoveryPrestateAttestationVerifier(Protocol):
    """Verify one exact recovery-prestate signature under configured evidence trust."""

    @property
    def project_id(self) -> str: ...

    @property
    def key_version(self) -> str: ...

    async def verify(self, signed: RecoveryPrestateAttestationV1) -> None: ...


@dataclass(frozen=True, slots=True)
class CapabilityVerifierConfiguration:
    """Startup-sealed target, route, and workload identity bindings."""

    target: TargetBinding
    route_policy: RouteAuthenticationPolicy
    recovery_executor_facade: bool = False

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("an exact target binding is required")
        if type(self.route_policy) is not RouteAuthenticationPolicy:
            raise TypeError("an exact route authentication policy is required")
        if type(self.recovery_executor_facade) is not bool:
            raise TypeError("recovery executor facade selection must be exact")
        if (
            _PROJECT_ID.fullmatch(self.target.project_id) is None
            or self.target.region != "us-central1"
        ):
            raise ValueError("capability verification target is outside ControlGraph")
        if self.route_policy.service_role not in {
            ServiceRole.EXECUTOR,
            ServiceRole.RECOVERY,
        }:
            raise ValueError("capability verification requires an execution route")
        expected_audience = (
            f"https://controlgraph-{self.route_policy.service_role.value}-"
            f"{self.route_policy.project_number}.us-central1.run.app"
        )
        if (
            self.route_policy.project_id != self.target.project_id
            or self.route_policy.audience != expected_audience
        ):
            raise ValueError("capability route does not match the configured target")
        is_recovery_executor_facade = (
            self.route_policy.service_role is ServiceRole.EXECUTOR
            and self.route_policy.path == RECOVERY_EXECUTION_FACADE_PATH
            and self.route_policy.caller.role is CallerRole.RECOVERY
        )
        if self.recovery_executor_facade != is_recovery_executor_facade:
            raise ValueError("recovery executor facade route is not exact")

    @property
    def issuer_identity(self) -> str:
        return f"controlgraph-issuer@{self.target.project_id}.iam.gserviceaccount.com"

    @property
    def subject_identity(self) -> str:
        role = (
            ServiceRole.RECOVERY.value
            if self.accepts_recovery_task
            else self.route_policy.service_role.value
        )
        return f"controlgraph-{role}@{self.target.project_id}.iam.gserviceaccount.com"

    @property
    def capability_audience(self) -> str:
        if self.recovery_executor_facade:
            return (
                f"https://controlgraph-recovery-{self.route_policy.project_number}"
                ".us-central1.run.app"
            )
        return self.route_policy.audience

    @property
    def accepts_recovery_task(self) -> bool:
        return (
            self.route_policy.service_role is ServiceRole.RECOVERY
            or self.recovery_executor_facade
        )

    @property
    def admitted_actions(self) -> frozenset[CapabilityAction]:
        if self.accepts_recovery_task:
            return frozenset({CapabilityAction.RECOVER_STABLE})
        return frozenset(
            {
                CapabilityAction.APPLY_CANARY,
                CapabilityAction.PROMOTE_CANDIDATE,
            }
        )


@dataclass(frozen=True, slots=True)
class VerifiedMutation:
    """Immutable task authority proven before any receipt or provider side effect."""

    request: ProtectedMutationRequest
    root: RolloutRootV2 | RolloutRootV3
    lineage_anchor: CapabilityLineageAnchorV1
    caller: AuthenticationContext
    capability_sha256: str
    claims_sha256: str
    earliest_lineage_issued_at: int


class CapabilityVerifier:
    """Verify canonical task authority through one shared application boundary."""

    def __init__(
        self,
        *,
        root_reader: RootAuthorityBundleReader,
        trust_verifier: TrustBundleVerifier,
        configuration: CapabilityVerifierConfiguration,
        lineage_reader: CapabilityLineageReader | None = None,
        recovery_prestate_verifier: RecoveryPrestateAttestationVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(configuration) is not CapabilityVerifierConfiguration:
            raise TypeError("an exact capability verifier configuration is required")
        if type(trust_verifier) is not TrustBundleVerifier:
            raise TypeError("an exact trust-bundle verifier is required")
        if trust_verifier.profile.purpose is not SigningPurpose.CAPABILITY:
            raise ValueError("capability verification requires capability trust material")
        if trust_verifier.profile.project_id != configuration.target.project_id:
            raise ValueError("capability trust project does not match the configured target")
        try:
            reader_target = root_reader.target
        except Exception:
            raise TypeError("a target-bound rollout root reader is required") from None
        if type(reader_target) is not TargetBinding or reader_target != configuration.target:
            raise ValueError("rollout root reader target does not match configuration")
        self._root_reader = root_reader
        self._trust_verifier = trust_verifier
        self._configuration = configuration
        self._lineage_reader = lineage_reader
        if recovery_prestate_verifier is not None and (
            not isinstance(
                recovery_prestate_verifier,
                RecoveryPrestateAttestationVerifier,
            )
            or recovery_prestate_verifier.project_id
            != configuration.target.project_id
        ):
            raise ValueError("recovery prestate verifier does not match configuration")
        self._recovery_prestate_verifier = recovery_prestate_verifier
        self._clock = clock or _now_utc_second

    @property
    def target(self) -> TargetBinding:
        return self._configuration.target

    @property
    def route_policy(self) -> RouteAuthenticationPolicy:
        return self._configuration.route_policy

    @property
    def recovery_executor_facade(self) -> bool:
        return self._configuration.recovery_executor_facade

    async def verify(
        self,
        payload: bytes,
        caller: AuthenticationContext,
    ) -> VerifiedMutation:
        """Return proven mutation authority or one stable payload-free denial."""

        if type(payload) is not bytes:
            raise _deny(ReasonCode.CONTRACT_INVALID)
        request = _decode_protected_request(payload)
        if (
            type(request) is TaskRequest
            and request.intent.action
            in {
                CapabilityAction.PROMOTE_CANDIDATE,
                CapabilityAction.RECOVER_STABLE,
            }
        ):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)

        now = _require_utc_second(self._clock())
        now_second = int(now.timestamp())
        self._validate_caller(caller, now_second)
        self._precheck_target(request)
        self._verify_envelope(request.capability)
        self._validate_time(request, now_second)
        self._validate_route_and_identity(request)
        root_state = await self._read_root_boundary(request.intent.root_id)
        root = root_state.root
        anchor = root_state.lineage_anchor
        self._validate_root_bindings(request, root, anchor, now_second)
        if type(request) is RecoveryTaskRequestV2:
            await self._verify_recovery_prestate(request)
        ancestors = await self._read_ancestors(request.capability)
        earliest_lineage_issued_at = self._validate_lineage(
            (*ancestors, request.capability),
            root,
            anchor,
            now_second,
        )
        return VerifiedMutation(
            request=request,
            root=root,
            lineage_anchor=anchor,
            caller=caller,
            capability_sha256=canonical_sha256(request.capability),
            claims_sha256=request.capability.claims_sha256,
            earliest_lineage_issued_at=earliest_lineage_issued_at,
        )

    def _validate_caller(self, caller: AuthenticationContext, now_second: int) -> None:
        policy = self._configuration.route_policy
        if type(caller) is not AuthenticationContext:
            raise _deny(ReasonCode.CALLER_UNAUTHENTICATED)
        if (
            caller.role is not policy.caller.role
            or caller.email != policy.caller.email
            or caller.subject != policy.caller.subject
            or caller.audience != policy.audience
            or caller.issuer not in _GOOGLE_ISSUERS
            or type(caller.issued_at) is not int
            or type(caller.expires_at) is not int
            or not caller.issued_at <= now_second < caller.expires_at
        ):
            raise _deny(ReasonCode.CALLER_UNAUTHORIZED)

    def _precheck_target(self, request: ProtectedMutationRequest) -> None:
        """Reject configured-target substitutions before any trust-material lookup."""

        target = self._configuration.target
        if (
            request.capability.claims.target != target
            or request.intent.target != target
            or request.queue_region != target.region
        ):
            raise _deny(ReasonCode.TARGET_BINDING_MISMATCH)

    def _verify_envelope(self, capability: SignedCapability) -> None:
        if type(capability) is not SignedCapability:
            raise _deny(ReasonCode.CONTRACT_INVALID)
        try:
            expected_claims_sha256 = canonical_sha256(capability.claims)
            if not hmac.compare_digest(expected_claims_sha256, capability.claims_sha256):
                raise _deny(ReasonCode.SIGNATURE_INVALID)
            profile = SigningProfile.capability(
                capability.claims.target.project_id,
                capability.claims.signing_key_version,
            )
            signing_input = build_signing_input(profile, capability.claims)
            detached = DetachedSignature(
                schema_version=DETACHED_SIGNATURE_V1,
                purpose=SigningPurpose.CAPABILITY,
                key_version=capability.claims.signing_key_version,
                algorithm=capability.claims.signing_algorithm,
                payload_version=capability.claims.schema_version,
                payload_sha256=signing_input.payload_sha256,
                digest_sha256=signing_input.digest_sha256,
                signature=capability.signature,
            )
            self._trust_verifier.verify(capability.claims, detached)
        except CapabilityVerificationError:
            raise
        except SigningError as error:
            raise _deny(_signing_denial(error.code)) from None
        except (TypeError, ValueError):
            raise _deny(ReasonCode.SIGNATURE_INVALID) from None

    def _validate_time(
        self,
        request: ProtectedMutationRequest,
        now_second: int,
    ) -> None:
        claims = request.capability.claims
        not_before = _parse_utc_second(claims.not_before)
        expires_at = _parse_utc_second(claims.expires_at)
        scheduled_at = _parse_utc_second(request.scheduled_at)
        task_expires_at = _parse_utc_second(request.expires_at)
        if now_second < not_before or now_second < scheduled_at:
            raise _deny(ReasonCode.CAPABILITY_NOT_YET_VALID)
        if now_second >= expires_at or now_second >= task_expires_at:
            raise _deny(ReasonCode.CAPABILITY_EXPIRED)
        if (
            type(request) is PromotionTaskRequestV2
            and now_second >= _parse_utc_second(request.intent.proof_valid_until)
        ):
            raise _deny(ReasonCode.CAPABILITY_EXPIRED)
        if (
            type(request) is RecoveryTaskRequestV2
            and now_second >= _parse_utc_second(request.intent.proof_valid_until)
        ):
            raise _deny(ReasonCode.CAPABILITY_EXPIRED)

    def _validate_route_and_identity(
        self,
        request: ProtectedMutationRequest,
    ) -> None:
        claims = request.capability.claims
        configuration = self._configuration
        if configuration.accepts_recovery_task != (
            type(request) is RecoveryTaskRequestV2
        ):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)
        if (
            claims.issuer != configuration.issuer_identity
            or claims.subject != configuration.subject_identity
            or claims.audience != configuration.capability_audience
            or request.handler_audience != configuration.capability_audience
        ):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)
        if request.queue_region != configuration.target.region:
            raise _deny(ReasonCode.TARGET_BINDING_MISMATCH)
        if claims.action not in configuration.admitted_actions:
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)

    async def _read_root_boundary(self, root_id: str) -> TrustedRootAuthority:
        try:
            bundle = await self._root_reader.read_root_creation_bundle(root_id)
        except AuthorityStoreError:
            raise _deny(ReasonCode.AUTHORITY_UNAVAILABLE) from None
        except Exception:
            raise _deny(ReasonCode.AUTHORITY_UNAVAILABLE) from None
        if bundle is None:
            raise _deny(ReasonCode.LINEAGE_INVALID)
        state = inspect_root_authority_bundle(
            bundle,
            target=self._configuration.target,
        )
        if state is None:
            raise _deny(ReasonCode.AUTHORITY_UNAVAILABLE)
        return state

    def _validate_root_bindings(
        self,
        request: ProtectedMutationRequest,
        root: RolloutRootV2 | RolloutRootV3,
        anchor: CapabilityLineageAnchorV1,
        now_second: int,
    ) -> None:
        claims = request.capability.claims
        intent = request.intent
        configuration = self._configuration
        content = root.content
        plan = content.rollout_plan
        if content.target != configuration.target or claims.target != configuration.target:
            raise _deny(ReasonCode.TARGET_BINDING_MISMATCH)
        if intent.target != configuration.target:
            raise _deny(ReasonCode.TARGET_BINDING_MISMATCH)
        if (
            claims.root_id != root.root_id
            or intent.root_id != root.root_id
            or claims.root_sha256 != root.root_sha256
            or intent.root_sha256 != root.root_sha256
        ):
            raise _deny(ReasonCode.LINEAGE_INVALID)
        if (
            claims.stable_revision != plan.stable_revision
            or claims.candidate_revision != plan.candidate_revision
            or intent.stable_revision != plan.stable_revision
            or intent.candidate_revision != plan.candidate_revision
        ):
            raise _deny(ReasonCode.TARGET_BINDING_MISMATCH)
        plan_sha256 = canonical_sha256(plan)
        if claims.plan_sha256 != plan_sha256 or intent.plan_sha256 != plan_sha256:
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)
        if (
            claims.action is CapabilityAction.APPLY_CANARY
            and claims.provider_etag != content.stable_snapshot.provider_etag
        ):
            raise _deny(ReasonCode.TARGET_BINDING_MISMATCH)
        if claims.action is CapabilityAction.RECOVER_STABLE:
            if claims.concurrency != content.authority_bounds.concurrency:
                raise _deny(ReasonCode.TARGET_BINDING_MISMATCH)
        elif claims.concurrency is not None:
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)
        if not capability_claims_match_root_authority(claims, root, anchor):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)
        if _parse_utc_second(content.approved_at) > now_second:
            raise _deny(ReasonCode.LINEAGE_INVALID)
        if _parse_utc_second(claims.issued_at) < _parse_utc_second(content.approved_at):
            raise _deny(ReasonCode.LINEAGE_INVALID)
        if type(request) is PromotionTaskRequestV2:
            self._validate_promotion_authorization(request, root, now_second)
        if type(request) is RecoveryTaskRequestV2:
            self._validate_recovery_authorization(request, root, now_second)

    def _validate_promotion_authorization(
        self,
        request: PromotionTaskRequestV2,
        root: RolloutRootV2 | RolloutRootV3,
        now_second: int,
    ) -> None:
        """Bind one compact issuer-approved promotion to the exact current V3 root."""

        if type(root) is not RolloutRootV3:
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)
        intent = request.intent
        authorization = intent.authorization
        claims = request.capability.claims
        content = root.content
        plan = content.rollout_plan
        bounds = content.authority_bounds
        try:
            expected_capability_id = promotion_capability_id(authorization)
            expected_prestate_sha256 = rollout_root_v3_target_configuration_sha256(
                root,
                stable_percent=90,
                candidate_percent=10,
            )
            desired_poststate_sha256 = rollout_root_v3_target_configuration_sha256(
                root,
                stable_percent=0,
                candidate_percent=100,
            )
        except (TypeError, ValueError):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH) from None
        if (
            type(authorization) is not PromotionAuthorizationV1
            or authorization.root_schema_version != root.schema_version
            or authorization.root_id != root.root_id
            or authorization.root_sha256 != root.root_sha256
            or authorization.target != content.target
            or authorization.epoch != claims.epoch
            or authorization.request_id != claims.request_id
            or authorization.request_id != intent.request_id
            or authorization.idempotency_key != claims.idempotency_key
            or authorization.idempotency_key != intent.idempotency_key
            or authorization.scheduled_at != request.scheduled_at
            or authorization.scheduled_at != claims.not_before
            or authorization.plan_sha256 != canonical_sha256(plan)
            or authorization.policy_schema_version != content.health_policy.schema_version
            or authorization.policy_sha256 != canonical_sha256(content.health_policy)
            or authorization.stable_snapshot_sha256
            != canonical_sha256(content.stable_snapshot)
            or authorization.stable_revision != plan.stable_revision
            or authorization.stable_revision_configuration_sha256
            != plan.stable_revision_configuration_sha256
            or authorization.candidate_revision != plan.candidate_revision
            or authorization.candidate_revision_configuration_sha256
            != plan.candidate_revision_configuration_sha256
            or authorization.concurrency != plan.concurrency
            or authorization.evidence_signing_key_version
            != content.evidence_signing_key_version
            or authorization.capability_signing_key_version
            != bounds.capability_signing_key_version
            or authorization.issuer_identity != bounds.issuer_identity
            or authorization.executor_identity != bounds.executor_identity
            or authorization.executor_audience != bounds.executor_audience
            or authorization.expected_prestate_sha256 != expected_prestate_sha256
            or authorization.desired_poststate_sha256 != desired_poststate_sha256
            or authorization.expected_stable_percent != 90
            or authorization.expected_candidate_percent != 10
            or authorization.stable_percent != 0
            or authorization.candidate_percent != 100
            or authorization.provider_etag != claims.provider_etag
            or authorization.provider_etag != intent.provider_etag
            or authorization.capability_id != expected_capability_id
            or intent.capability_id != expected_capability_id
            or claims.capability_id != expected_capability_id
            or intent.promotion_authorization_sha256
            != canonical_sha256(authorization)
            or intent.expected_prestate_sha256
            != authorization.expected_prestate_sha256
            or intent.terminal_health_decision_sha256
            != authorization.terminal_health_decision_sha256
            or intent.health_chain_sha256
            != authorization.health_chain_locator.health_chain_sha256
            or intent.desired_poststate_sha256
            != authorization.desired_poststate_sha256
            or intent.proof_valid_until != authorization.proof_valid_until
            or claims.issuer != authorization.issuer_identity
            or claims.subject != authorization.executor_identity
            or claims.audience != authorization.executor_audience
            or claims.signing_key_version
            != authorization.capability_signing_key_version
            or request.expires_at > authorization.proof_valid_until
            or now_second >= _parse_utc_second(authorization.proof_valid_until)
        ):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)

    def _validate_recovery_authorization(
        self,
        request: RecoveryTaskRequestV2,
        root: RolloutRootV2 | RolloutRootV3,
        now_second: int,
    ) -> None:
        """Bind captured-stable recovery to one exact stored root and source."""

        intent = request.intent
        authorization = intent.authorization
        claims = request.capability.claims
        content = root.content
        plan = content.rollout_plan
        bounds = content.authority_bounds
        source = authorization.source
        try:
            capability_id = recovery_capability_id(authorization)
            expected_prestate_sha256 = recovery_target_configuration_sha256(
                root,
                stable_percent=90,
                candidate_percent=10,
            )
            desired_poststate_sha256 = recovery_target_configuration_sha256(
                root,
                stable_percent=100,
                candidate_percent=0,
            )
        except (TypeError, ValueError):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH) from None
        root_mode_matches = (
            type(root) is RolloutRootV3
            and type(source) is UnhealthyRecoverySourceV1
            and authorization.root_schema_version == root.schema_version
            and source.epoch == authorization.epoch
            and authorization.verified_apply_receipt.epoch
            == authorization.epoch
        ) or (
            type(root) is RolloutRootV2
            and type(source) is RevokedV2RecoverySourceV1
            and authorization.root_schema_version == root.schema_version
            and source.epoch == authorization.epoch
            and source.revocation_proof.authority.current_epoch
            == authorization.epoch
            and source.revocation_proof.authority.previous_epoch
            == authorization.verified_apply_receipt.epoch
        ) or (
            type(root) is RolloutRootV3
            and type(source) is RevokedV3RecoverySourceV1
            and authorization.root_schema_version == root.schema_version
            and source.epoch == authorization.epoch
            and source.revocation_proof.authority.current_epoch
            == authorization.epoch
            and source.revocation_proof.authority.previous_epoch
            == authorization.verified_apply_receipt.epoch
        )
        if (
            type(authorization) is not RecoveryAuthorizationV1
            or not root_mode_matches
            or authorization.prestate_attestation.result.request.root != root
            or authorization.root_id != root.root_id
            or authorization.root_sha256 != root.root_sha256
            or authorization.target != content.target
            or authorization.epoch != claims.epoch
            or authorization.epoch != intent.epoch
            or authorization.request_id != claims.request_id
            or authorization.request_id != intent.request_id
            or authorization.idempotency_key != claims.idempotency_key
            or authorization.idempotency_key != intent.idempotency_key
            or authorization.scheduled_at != request.scheduled_at
            or authorization.scheduled_at != claims.not_before
            or authorization.plan_sha256 != canonical_sha256(plan)
            or authorization.stable_snapshot_sha256
            != canonical_sha256(content.stable_snapshot)
            or authorization.stable_revision != plan.stable_revision
            or authorization.stable_revision_configuration_sha256
            != plan.stable_revision_configuration_sha256
            or authorization.candidate_revision != plan.candidate_revision
            or authorization.candidate_revision_configuration_sha256
            != plan.candidate_revision_configuration_sha256
            or authorization.concurrency != plan.concurrency
            or authorization.evidence_signing_key_version
            != content.evidence_signing_key_version
            or authorization.capability_signing_key_version
            != bounds.capability_signing_key_version
            or authorization.issuer_identity != bounds.issuer_identity
            or authorization.recovery_identity != bounds.recovery_identity
            or authorization.recovery_audience != bounds.recovery_audience
            or authorization.maximum_attempts != plan.maximum_recovery_attempts
            or authorization.maximum_attempts != 1
            or authorization.maximum_capability_lifetime_seconds
            != bounds.maximum_capability_lifetime_seconds
            or authorization.expected_prestate_sha256
            != expected_prestate_sha256
            or authorization.verified_apply_receipt.expected_poststate_sha256
            != expected_prestate_sha256
            or authorization.desired_poststate_sha256
            != desired_poststate_sha256
            or authorization.current_provider_etag != claims.provider_etag
            or authorization.current_provider_etag != intent.provider_etag
            or authorization.capability_id != capability_id
            or intent.capability_id != capability_id
            or claims.capability_id != capability_id
            or intent.recovery_authorization_sha256
            != canonical_sha256(authorization)
            or intent.expected_prestate_sha256
            != authorization.expected_prestate_sha256
            or intent.desired_poststate_sha256
            != authorization.desired_poststate_sha256
            or intent.source_receipt_sha256
            != authorization.source_receipt_sha256
            or intent.source_receipt_storage_revision
            != authorization.source_receipt_storage_revision
            or intent.trigger_proof_sha256
            != authorization.trigger_proof_sha256
            or intent.prestate_attestation_sha256
            != authorization.prestate_attestation_sha256
            or intent.proof_valid_until != authorization.proof_valid_until
            or claims.issuer != authorization.issuer_identity
            or claims.subject != authorization.recovery_identity
            or claims.audience != authorization.recovery_audience
            or claims.concurrency != authorization.concurrency
            or claims.signing_key_version
            != authorization.capability_signing_key_version
            or request.handler_audience != authorization.recovery_audience
            or request.expires_at > authorization.proof_valid_until
            or now_second >= _parse_utc_second(authorization.proof_valid_until)
        ):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)

    async def _verify_recovery_prestate(
        self,
        request: RecoveryTaskRequestV2,
    ) -> None:
        verifier = self._recovery_prestate_verifier
        attestation = request.intent.authorization.prestate_attestation
        if (
            verifier is None
            or verifier.project_id != request.intent.target.project_id
            or verifier.key_version != attestation.signing_key_version
        ):
            raise _deny(ReasonCode.KEY_VERSION_UNTRUSTED)
        try:
            await verifier.verify(attestation)
        except SigningError as error:
            raise _deny(_signing_denial(error.code)) from None
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _deny(ReasonCode.AUTHORITY_UNAVAILABLE) from None

    async def _read_ancestors(
        self,
        leaf: SignedCapability,
    ) -> tuple[SignedCapability, ...]:
        parent_sha256 = leaf.claims.parent_capability_sha256
        if parent_sha256 is None:
            return ()
        if self._lineage_reader is None:
            raise _deny(ReasonCode.LINEAGE_INVALID)
        try:
            ancestors = await self._lineage_reader.resolve_lineage(parent_sha256)
        except Exception:
            raise _deny(ReasonCode.AUTHORITY_UNAVAILABLE) from None
        if (
            type(ancestors) is not tuple
            or not ancestors
            or len(ancestors) >= MAX_LINEAGE_DEPTH
            or any(type(capability) is not SignedCapability for capability in ancestors)
        ):
            raise _deny(ReasonCode.LINEAGE_INVALID)
        if ancestors[-1].claims_sha256 != parent_sha256:
            raise _deny(ReasonCode.LINEAGE_INVALID)
        return ancestors

    def _validate_lineage(
        self,
        lineage: tuple[SignedCapability, ...],
        root: RolloutRootV2 | RolloutRootV3,
        anchor_record: CapabilityLineageAnchorV1,
        now_second: int,
    ) -> int:
        if not lineage or len(lineage) > MAX_LINEAGE_DEPTH:
            raise _deny(ReasonCode.LINEAGE_INVALID)
        root_approved_second = _parse_utc_second(root.content.approved_at)
        earliest_issued_at = _parse_utc_second(lineage[0].claims.issued_at)
        previous_claims: CapabilityClaims | None = None
        capability_ids: set[str] = set()
        grants: list[CapabilityGrant] = []
        for index, capability in enumerate(lineage):
            if index < len(lineage) - 1:
                self._verify_envelope(capability)
            self._validate_lineage_claim_identity(capability.claims)
            issued_at = _parse_utc_second(capability.claims.issued_at)
            if issued_at < root_approved_second:
                raise _deny(ReasonCode.LINEAGE_INVALID)
            if not capability_claims_match_root_authority(
                capability.claims,
                root,
                anchor_record,
            ):
                raise _deny(ReasonCode.SCOPE_AMPLIFICATION)
            _validate_claim_time(capability.claims, now_second)
            if previous_claims is not None and not (
                _parse_utc_second(previous_claims.not_before)
                <= issued_at
                < _parse_utc_second(previous_claims.expires_at)
            ):
                raise _deny(ReasonCode.LINEAGE_INVALID)
            previous_claims = capability.claims
            if capability.claims.capability_id in capability_ids:
                raise _deny(ReasonCode.LINEAGE_INVALID)
            capability_ids.add(capability.claims.capability_id)
            try:
                grants.append(
                    CapabilityGrant(
                        capability_sha256=capability.claims_sha256,
                        parent_capability_sha256=capability.claims.parent_capability_sha256,
                        scope=capability_scope_from_claims(capability.claims, root),
                    )
                )
            except (TypeError, ValueError):
                raise _deny(ReasonCode.LINEAGE_INVALID) from None

        try:
            anchor = operator_lineage_anchor(
                root,
                anchor_record,
                lineage[0].claims,
            )
        except (TypeError, ValueError):
            raise _deny(ReasonCode.LINEAGE_INVALID) from None
        result = validate_lineage(anchor, tuple(grants))
        if not result.allowed:
            reason = (
                result.reason.value
                if result.reason is not None
                else ReasonCode.LINEAGE_INVALID
            )
            try:
                code = ReasonCode(reason)
            except ValueError:
                code = ReasonCode.LINEAGE_INVALID
            raise _deny(code)
        return earliest_issued_at

    def _validate_lineage_claim_identity(self, claims: CapabilityClaims) -> None:
        configuration = self._configuration
        if (
            claims.issuer != configuration.issuer_identity
            or claims.subject != configuration.subject_identity
            or claims.audience != configuration.capability_audience
        ):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)


def _decode_protected_request(payload: bytes) -> ProtectedMutationRequest:
    try:
        return decode_contract(payload, RecoveryTaskRequestV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise _deny(ReasonCode.CONTRACT_INVALID) from None
    except (TypeError, ValueError):
        raise _deny(ReasonCode.CONTRACT_INVALID) from None
    try:
        return decode_contract(payload, PromotionTaskRequestV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise _deny(ReasonCode.CONTRACT_INVALID) from None
    except (TypeError, ValueError):
        raise _deny(ReasonCode.CONTRACT_INVALID) from None
    try:
        return decode_contract(payload, TaskRequest)
    except ContractError as error:
        code = (
            ReasonCode.CONTRACT_VERSION_UNSUPPORTED
            if error.code is ContractErrorCode.VERSION_UNSUPPORTED
            else ReasonCode.CONTRACT_INVALID
        )
        raise _deny(code) from None
    except (TypeError, ValueError):
        raise _deny(ReasonCode.CONTRACT_INVALID) from None


def _validate_claim_time(claims: CapabilityClaims, now_second: int) -> None:
    if now_second < _parse_utc_second(claims.not_before):
        raise _deny(ReasonCode.CAPABILITY_NOT_YET_VALID)
    if now_second >= _parse_utc_second(claims.expires_at):
        raise _deny(ReasonCode.CAPABILITY_EXPIRED)


def _signing_denial(code: SigningErrorCode) -> ReasonCode:
    if code in {
        SigningErrorCode.PROFILE_INVALID,
        SigningErrorCode.PURPOSE_MISMATCH,
        SigningErrorCode.PAYLOAD_VERSION_MISMATCH,
        SigningErrorCode.KEY_VERSION_MISMATCH,
        SigningErrorCode.KEY_VERSION_UNTRUSTED,
        SigningErrorCode.KEY_VERSION_DISABLED,
        SigningErrorCode.ALGORITHM_MISMATCH,
        SigningErrorCode.TRUST_BUNDLE_INVALID,
        SigningErrorCode.PUBLIC_KEY_INVALID,
    }:
        return ReasonCode.KEY_VERSION_UNTRUSTED
    return ReasonCode.SIGNATURE_INVALID


def _parse_utc_second(value: str) -> int:
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def _require_utc_second(value: datetime) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
        or value.microsecond
    ):
        raise _deny(ReasonCode.AUTHORITY_UNAVAILABLE)
    return value


def _now_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "CapabilityLineageReader",
    "CapabilityRequestVerifier",
    "CapabilityVerificationError",
    "CapabilityVerifier",
    "CapabilityVerifierConfiguration",
    "ProtectedMutationRequest",
    "RecoveryPrestateAttestationVerifier",
    "VerifiedMutation",
]
