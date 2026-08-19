"""Fail-closed verification for protected mutation task requests."""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import AuthorityStoreError
from controlgraph_canary.application.identity import (
    AuthenticationContext,
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
from controlgraph_canary.contracts.root_creation import (
    CapabilityLineageAnchorV1,
    RolloutRootV2,
)

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})


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


@dataclass(frozen=True, slots=True)
class CapabilityVerifierConfiguration:
    """Startup-sealed target, route, and workload identity bindings."""

    target: TargetBinding
    route_policy: RouteAuthenticationPolicy

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("an exact target binding is required")
        if type(self.route_policy) is not RouteAuthenticationPolicy:
            raise TypeError("an exact route authentication policy is required")
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

    @property
    def issuer_identity(self) -> str:
        return f"controlgraph-issuer@{self.target.project_id}.iam.gserviceaccount.com"

    @property
    def subject_identity(self) -> str:
        role = self.route_policy.service_role.value
        return f"controlgraph-{role}@{self.target.project_id}.iam.gserviceaccount.com"

    @property
    def admitted_actions(self) -> frozenset[CapabilityAction]:
        if self.route_policy.service_role is ServiceRole.RECOVERY:
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

    request: TaskRequest
    root: RolloutRootV2
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
        self._clock = clock or _now_utc_second

    async def verify(
        self,
        payload: bytes,
        caller: AuthenticationContext,
    ) -> VerifiedMutation:
        """Return proven mutation authority or one stable payload-free denial."""

        if type(payload) is not bytes:
            raise _deny(ReasonCode.CONTRACT_INVALID)
        try:
            request = decode_contract(payload, TaskRequest)
        except ContractError as error:
            code = (
                ReasonCode.CONTRACT_VERSION_UNSUPPORTED
                if error.code is ContractErrorCode.VERSION_UNSUPPORTED
                else ReasonCode.CONTRACT_INVALID
            )
            raise _deny(code) from None
        except (TypeError, ValueError):
            raise _deny(ReasonCode.CONTRACT_INVALID) from None

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

    def _precheck_target(self, request: TaskRequest) -> None:
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

    def _validate_time(self, request: TaskRequest, now_second: int) -> None:
        claims = request.capability.claims
        not_before = _parse_utc_second(claims.not_before)
        expires_at = _parse_utc_second(claims.expires_at)
        scheduled_at = _parse_utc_second(request.scheduled_at)
        task_expires_at = _parse_utc_second(request.expires_at)
        if now_second < not_before or now_second < scheduled_at:
            raise _deny(ReasonCode.CAPABILITY_NOT_YET_VALID)
        if now_second >= expires_at or now_second >= task_expires_at:
            raise _deny(ReasonCode.CAPABILITY_EXPIRED)

    def _validate_route_and_identity(self, request: TaskRequest) -> None:
        claims = request.capability.claims
        configuration = self._configuration
        if (
            claims.issuer != configuration.issuer_identity
            or claims.subject != configuration.subject_identity
            or claims.audience != configuration.route_policy.audience
            or request.handler_audience != configuration.route_policy.audience
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
        request: TaskRequest,
        root: RolloutRootV2,
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
        root: RolloutRootV2,
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
            or claims.audience != configuration.route_policy.audience
        ):
            raise _deny(ReasonCode.CLAIM_BINDING_MISMATCH)

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
    "VerifiedMutation",
]
