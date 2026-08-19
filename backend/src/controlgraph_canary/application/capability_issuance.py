"""Root-bound capability issuance through the purpose-sealed signer."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

from controlgraph_canary.application.authority_store import (
    AuthorityStore,
    AuthorityStoreError,
    IssuanceStateSnapshot,
)
from controlgraph_canary.application.cloud_run import (
    rollout_root_target_configuration_sha256,
)
from controlgraph_canary.application.signing import (
    DETACHED_SIGNATURE_V1,
    DetachedSignature,
    PurposeSealedSigner,
    SigningError,
    SigningErrorCode,
    SigningProfile,
    SigningPurpose,
    TrustBundleVerifier,
    build_signing_input,
)
from controlgraph_canary.authority.policy import (
    MAX_LINEAGE_DEPTH,
    CanaryAction,
    CapabilityGrant,
    CapabilityScope,
    IntegerBounds,
    OperatorRootAnchor,
    TimeBounds,
    check_attenuation,
    validate_lineage,
)
from controlgraph_canary.contracts.codec import (
    RestrictedJson,
    canonical_json_value_bytes,
    canonical_sha256,
)
from controlgraph_canary.contracts.models import (
    CAPABILITY_CLAIMS_V1,
    SIGNED_CAPABILITY_V1,
    CapabilityAction,
    CapabilityClaims,
    EpochAuthorityRecord,
    RolloutRoot,
    SignedCapability,
    TargetBinding,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    ServiceClaimStatus,
    active_service_claim_matches_root,
)

CAPABILITY_IDENTITY_V1 = "controlgraph.capability-identity/v1"
CAPABILITY_IDENTITY_DOMAIN = b"controlgraph.capability-identity/v1\0"
DEFAULT_CAPABILITY_LIFETIME_SECONDS = 300
MAX_CAPABILITY_LIFETIME_SECONDS = 900

_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SERVICE_ACCOUNT = re.compile(
    r"^controlgraph-(?:coordinator|issuer|executor)@"
    r"controlgraph-canary-[a-z0-9]{6,10}\.iam\.gserviceaccount\.com$"
)
_FORBIDDEN_RESOURCE_NAME = "reconcile"


class CapabilityIssuanceErrorCode(StrEnum):
    """Stable, payload-free issuance failure classes."""

    CALLER_UNAUTHENTICATED = "CAPABILITY_CALLER_UNAUTHENTICATED"
    CALLER_UNAUTHORIZED = "CAPABILITY_CALLER_UNAUTHORIZED"
    TRUSTED_STATE_UNAVAILABLE = "CAPABILITY_TRUSTED_STATE_UNAVAILABLE"
    TRUSTED_STATE_INVALID = "CAPABILITY_TRUSTED_STATE_INVALID"
    LINEAGE_NOT_FOUND = "CAPABILITY_LINEAGE_NOT_FOUND"
    LINEAGE_INVALID = "CAPABILITY_LINEAGE_INVALID"
    LINEAGE_UNVERIFIED = "CAPABILITY_LINEAGE_UNVERIFIED"
    VALIDITY_EXHAUSTED = "CAPABILITY_VALIDITY_EXHAUSTED"


class CapabilityIssuanceError(RuntimeError):
    """An issuance denial that never reflects claims or provider text."""

    def __init__(self, code: CapabilityIssuanceErrorCode) -> None:
        if type(code) is not CapabilityIssuanceErrorCode:
            raise TypeError("an exact capability issuance error code is required")
        self.code = code
        super().__init__(code.value)


def _deny(code: CapabilityIssuanceErrorCode) -> CapabilityIssuanceError:
    return CapabilityIssuanceError(code)


def _validate_identifier(name: str, value: object) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _service_account(role: str, project_id: str) -> str:
    return f"controlgraph-{role}@{project_id}.iam.gserviceaccount.com"


def _utc_second(value: datetime) -> tuple[str, int]:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError("issuance time must be an aware datetime")
    if value.utcoffset() != timedelta(0) or value.microsecond != 0:
        raise ValueError("issuance time must be an exact UTC second")
    normalized = value.astimezone(UTC)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ"), int(normalized.timestamp())


def _parse_utc_second(value: str) -> int:
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


@dataclass(frozen=True, slots=True)
class AuthenticatedIssuancePrincipal:
    """A workload identity established by the authentication boundary."""

    identity: str

    def __post_init__(self) -> None:
        if type(self.identity) is not str or _SERVICE_ACCOUNT.fullmatch(self.identity) is None:
            raise ValueError("authenticated issuance identity is invalid")


@dataclass(frozen=True, slots=True)
class CapabilityIssuanceRequest:
    """Unprivileged locators and request identities admitted by the issuer."""

    root_id: str
    request_id: str
    idempotency_key: str
    parent_capability_id: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier("root_id", self.root_id)
        _validate_identifier("request_id", self.request_id)
        _validate_identifier("idempotency_key", self.idempotency_key)
        if self.parent_capability_id is not None:
            _validate_identifier("parent_capability_id", self.parent_capability_id)


@dataclass(frozen=True, slots=True)
class CapabilityIssuerConfiguration:
    """Fixed issuer, handler, target, and lifetime bindings."""

    target: TargetBinding
    handler_audience: str
    lifetime_seconds: int = DEFAULT_CAPABILITY_LIFETIME_SECONDS

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise ValueError("issuer target must be an exact target binding")
        if _PROJECT_ID.fullmatch(self.target.project_id) is None:
            raise ValueError("issuer target must use the dedicated ControlGraph project")
        if self.target.region != "us-central1":
            raise ValueError("issuer target must use us-central1")
        if any(
            _FORBIDDEN_RESOURCE_NAME in value.lower()
            for value in (
                self.target.project_id,
                self.target.environment,
                self.target.service_name,
            )
        ):
            raise ValueError("issuer target cannot name an unrelated resource")
        if type(self.handler_audience) is not str or any(
            character in self.handler_audience for character in "*?[]"
        ):
            raise ValueError("issuer handler audience is invalid")
        try:
            self.handler_audience.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("issuer handler audience is invalid") from error
        parsed = urlsplit(self.handler_audience)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.hostname is None
            or not parsed.hostname.startswith("controlgraph-executor-")
            or not parsed.hostname.endswith(".run.app")
            or parsed.path
            or parsed.query
            or parsed.fragment
            or _FORBIDDEN_RESOURCE_NAME in parsed.hostname
        ):
            raise ValueError("issuer handler audience must be the fixed executor origin")
        if (
            type(self.lifetime_seconds) is not int
            or not 1 <= self.lifetime_seconds <= MAX_CAPABILITY_LIFETIME_SECONDS
        ):
            raise ValueError("capability lifetime is invalid")

    @property
    def issuer_identity(self) -> str:
        return _service_account("issuer", self.target.project_id)

    @property
    def authorized_caller_identity(self) -> str:
        return _service_account("coordinator", self.target.project_id)

    @property
    def subject_identity(self) -> str:
        return _service_account("executor", self.target.project_id)


@runtime_checkable
class CapabilityLineageResolver(Protocol):
    """Resolve an ordered root-to-parent lineage from durable trusted records."""

    async def resolve_lineage(
        self,
        parent_capability_id: str,
    ) -> tuple[SignedCapability, ...] | None: ...


@runtime_checkable
class CapabilityEnvelopeVerifier(Protocol):
    """Verify one signed capability against the configured trust policy."""

    def verify(self, capability: SignedCapability) -> None: ...


class TrustBundleCapabilityVerifier:
    """Adapt signed capability envelopes to the detached trust-bundle verifier."""

    def __init__(self, verifier: TrustBundleVerifier) -> None:
        if type(verifier) is not TrustBundleVerifier:
            raise TypeError("an exact trust-bundle verifier is required")
        if verifier.profile.purpose is not SigningPurpose.CAPABILITY:
            raise ValueError("capability verification requires the capability trust purpose")
        self._verifier = verifier

    def verify(self, capability: SignedCapability) -> None:
        if type(capability) is not SignedCapability:
            raise TypeError("an exact signed capability is required")
        claims = capability.claims
        profile = SigningProfile.capability(
            claims.target.project_id,
            claims.signing_key_version,
        )
        signing_input = build_signing_input(profile, claims)
        detached = DetachedSignature(
            schema_version=DETACHED_SIGNATURE_V1,
            purpose=SigningPurpose.CAPABILITY,
            key_version=claims.signing_key_version,
            algorithm=claims.signing_algorithm,
            payload_version=claims.schema_version,
            payload_sha256=signing_input.payload_sha256,
            digest_sha256=signing_input.digest_sha256,
            signature=capability.signature,
        )
        self._verifier.verify(claims, detached)


@dataclass(frozen=True, slots=True)
class _TrustedIssuanceState:
    snapshot: IssuanceStateSnapshot
    root: RolloutRoot
    root_sha256: str
    authority: EpochAuthorityRecord
    service_claim: ServiceClaimRecord


def _scope_from_claims(claims: CapabilityClaims, root: RolloutRoot) -> CapabilityScope:
    concurrency = claims.concurrency or root.stable_snapshot.concurrency
    return CapabilityScope(
        project_id=claims.target.project_id,
        region=claims.target.region,
        environment=claims.target.environment,
        service_name=claims.target.service_name,
        root_id=claims.root_id,
        root_sha256=claims.root_sha256,
        epoch=claims.epoch,
        plan_sha256=claims.plan_sha256,
        provider_precondition=claims.provider_etag,
        request_id=claims.request_id,
        idempotency_key=claims.idempotency_key,
        callers=frozenset({claims.subject}),
        audiences=frozenset({claims.audience}),
        stable_revision=claims.stable_revision,
        candidate_revision=claims.candidate_revision,
        revisions=frozenset({claims.stable_revision, claims.candidate_revision}),
        actions=frozenset({CanaryAction(claims.action.value)}),
        traffic_percent=IntegerBounds(claims.candidate_percent, claims.candidate_percent),
        concurrency=IntegerBounds(concurrency, concurrency),
        validity=TimeBounds(
            _parse_utc_second(claims.not_before),
            _parse_utc_second(claims.expires_at),
        ),
    )


def _root_anchor(
    state: _TrustedIssuanceState,
    configuration: CapabilityIssuerConfiguration,
    request: CapabilityIssuanceRequest,
    validity: TimeBounds,
) -> OperatorRootAnchor:
    root = state.root
    concurrency = root.stable_snapshot.concurrency
    return OperatorRootAnchor(
        root_sha256=state.root_sha256,
        scope=CapabilityScope(
            project_id=root.target.project_id,
            region=root.target.region,
            environment=root.target.environment,
            service_name=root.target.service_name,
            root_id=root.root_id,
            root_sha256=state.root_sha256,
            epoch=state.authority.current_epoch,
            plan_sha256=root.plan_sha256,
            provider_precondition=root.stable_snapshot.provider_etag,
            request_id=request.request_id,
            idempotency_key=request.idempotency_key,
            callers=frozenset({configuration.subject_identity}),
            audiences=frozenset({configuration.handler_audience}),
            stable_revision=root.stable_snapshot.stable_revision,
            candidate_revision=root.candidate_revision,
            revisions=frozenset({root.stable_snapshot.stable_revision, root.candidate_revision}),
            actions=frozenset({CanaryAction.APPLY_CANARY}),
            traffic_percent=IntegerBounds(root.candidate_percent, root.candidate_percent),
            concurrency=IntegerBounds(concurrency, concurrency),
            validity=validity,
        ),
    )


def _capability_id(claim_material: RestrictedJson) -> str:
    material = canonical_json_value_bytes(claim_material)
    digest = hashlib.sha256(CAPABILITY_IDENTITY_DOMAIN + material).hexdigest()
    return f"cgcap-{digest}"


class CapabilityIssuer:
    """Issue one apply-canary capability from trusted root and epoch state."""

    def __init__(
        self,
        *,
        store: AuthorityStore,
        signer: PurposeSealedSigner,
        configuration: CapabilityIssuerConfiguration,
        lineage_resolver: CapabilityLineageResolver | None = None,
        envelope_verifier: CapabilityEnvelopeVerifier | None = None,
    ) -> None:
        if type(configuration) is not CapabilityIssuerConfiguration:
            raise TypeError("an exact capability issuer configuration is required")
        if type(signer) is not PurposeSealedSigner:
            raise TypeError("an exact purpose-sealed signer is required")
        store_target = store.target
        if type(store_target) is not TargetBinding or store_target != configuration.target:
            raise ValueError("authority store target does not match issuer configuration")
        if signer.profile.purpose is not SigningPurpose.CAPABILITY:
            raise ValueError("issuer signer must use the capability purpose")
        if signer.profile.project_id != configuration.target.project_id:
            raise ValueError("issuer signer project does not match the configured target")
        if (lineage_resolver is None) != (envelope_verifier is None):
            raise ValueError("lineage resolution and verification must be configured together")
        self._store = store
        self._signer = signer
        self._configuration = configuration
        self._lineage_resolver = lineage_resolver
        self._envelope_verifier = envelope_verifier

    async def issue(
        self,
        request: CapabilityIssuanceRequest,
        *,
        principal: AuthenticatedIssuancePrincipal | None,
        now: datetime,
    ) -> SignedCapability:
        if type(request) is not CapabilityIssuanceRequest:
            raise TypeError("an exact capability issuance request is required")
        issued_at, issued_second = _utc_second(now)
        self._authorize(principal)
        state = await self._read_trusted_state(request.root_id, issued_second)
        lineage = await self._resolve_lineage(request.parent_capability_id)
        parent_digest, expires_second = self._validate_parent_lineage(
            state,
            request,
            lineage,
            issued_second,
        )
        configured_expiry = issued_second + self._configuration.lifetime_seconds
        if expires_second is not None:
            configured_expiry = min(configured_expiry, expires_second)
        if configured_expiry <= issued_second:
            raise _deny(CapabilityIssuanceErrorCode.VALIDITY_EXHAUSTED)
        expires_at = datetime.fromtimestamp(configured_expiry, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        claims = self._build_claims(
            state=state,
            request=request,
            issued_at=issued_at,
            expires_at=expires_at,
            parent_digest=parent_digest,
        )
        child_scope = _scope_from_claims(claims, state.root)
        if lineage:
            parent_scope = _scope_from_claims(lineage[-1].claims, state.root)
            attenuation = check_attenuation(parent_scope, child_scope)
            if not attenuation.allowed:
                raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)
        else:
            anchor = _root_anchor(state, self._configuration, request, child_scope.validity)
            attenuation = check_attenuation(anchor.scope, child_scope)
            if not attenuation.allowed:
                raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)

        signing_input = build_signing_input(self._signer.profile, claims)
        detached = self._signer.sign(claims)
        if (
            detached.purpose is not SigningPurpose.CAPABILITY
            or detached.key_version != claims.signing_key_version
            or detached.algorithm != claims.signing_algorithm
            or detached.payload_version != claims.schema_version
            or detached.payload_sha256 != signing_input.payload_sha256
            or detached.digest_sha256 != signing_input.digest_sha256
        ):
            raise SigningError(
                code=SigningErrorCode.SIGNATURE_INVALID,
                message="capability signer returned inconsistent metadata",
            )
        envelope = SignedCapability(
            schema_version=SIGNED_CAPABILITY_V1,
            claims=claims,
            claims_sha256=canonical_sha256(claims),
            signature=detached.signature,
        )
        self._validate_complete_lineage(state, request, (*lineage, envelope))
        confirmed_state = await self._read_trusted_state(request.root_id, issued_second)
        if confirmed_state.snapshot != state.snapshot:
            raise _deny(CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID)
        return envelope

    def _authorize(self, principal: AuthenticatedIssuancePrincipal | None) -> None:
        if principal is None:
            raise _deny(CapabilityIssuanceErrorCode.CALLER_UNAUTHENTICATED)
        if type(principal) is not AuthenticatedIssuancePrincipal:
            raise _deny(CapabilityIssuanceErrorCode.CALLER_UNAUTHENTICATED)
        if principal.identity != self._configuration.authorized_caller_identity:
            raise _deny(CapabilityIssuanceErrorCode.CALLER_UNAUTHORIZED)

    async def _read_trusted_state(
        self,
        root_id: str,
        issued_second: int,
    ) -> _TrustedIssuanceState:
        try:
            snapshot = await self._store.read_issuance_state(root_id)
        except AuthorityStoreError:
            raise _deny(CapabilityIssuanceErrorCode.TRUSTED_STATE_UNAVAILABLE) from None
        if snapshot is None:
            raise _deny(CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID)
        if type(snapshot) is not IssuanceStateSnapshot:
            raise _deny(CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID)
        root_record = snapshot.root
        claim_record = snapshot.service_claim
        authority_record = snapshot.authority
        root = root_record.value
        claim = claim_record.value
        authority = authority_record.value
        if (
            type(root) is not RolloutRoot
            or type(claim) is not ServiceClaimRecord
            or type(authority) is not EpochAuthorityRecord
        ):
            raise _deny(CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID)
        root_sha256 = canonical_sha256(root)
        try:
            stable_target_configuration_sha256 = (
                rollout_root_target_configuration_sha256(
                    root,
                    stable_percent=100,
                    candidate_percent=0,
                )
            )
            candidate_target_configuration_sha256 = (
                rollout_root_target_configuration_sha256(
                    root,
                    stable_percent=0,
                    candidate_percent=100,
                )
            )
        except (TypeError, ValueError):
            raise _deny(CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID) from None
        if (
            root.root_id != root_id
            or root.target != self._configuration.target
            or root_record.revision != 0
            or claim.status is not ServiceClaimStatus.ACTIVE
            or claim_record.revision % 3 != 0
            or claim.target != root.target
            or claim.root_id != root.root_id
            or claim.root_sha256 != root_sha256
            or not active_service_claim_matches_root(
                claim,
                root,
                stable_target_configuration_sha256=(
                    stable_target_configuration_sha256
                ),
                candidate_target_configuration_sha256=(
                    candidate_target_configuration_sha256
                ),
            )
            or authority.target != root.target
            or authority.root_id != root.root_id
            or authority.root_sha256 != root_sha256
            or authority_record.revision != authority.revision
            or authority.current_epoch != authority.revision + 1
            or _FORBIDDEN_RESOURCE_NAME in root.stable_snapshot.stable_revision.lower()
            or _FORBIDDEN_RESOURCE_NAME in root.candidate_revision.lower()
            or _parse_utc_second(root.approved_at) > issued_second
            or _parse_utc_second(claim.claimed_at) > issued_second
            or _parse_utc_second(authority.changed_at) > issued_second
        ):
            raise _deny(CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID)
        return _TrustedIssuanceState(
            snapshot=snapshot,
            root=root,
            root_sha256=root_sha256,
            authority=authority,
            service_claim=claim,
        )

    async def _resolve_lineage(
        self,
        parent_capability_id: str | None,
    ) -> tuple[SignedCapability, ...]:
        if parent_capability_id is None:
            return ()
        if self._lineage_resolver is None or self._envelope_verifier is None:
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_UNVERIFIED)
        try:
            lineage = await self._lineage_resolver.resolve_lineage(parent_capability_id)
        except Exception:
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_UNVERIFIED) from None
        if lineage is None:
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_NOT_FOUND)
        if type(lineage) is not tuple or not lineage or len(lineage) >= MAX_LINEAGE_DEPTH:
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)
        if any(type(capability) is not SignedCapability for capability in lineage):
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)
        if lineage[-1].claims.capability_id != parent_capability_id:
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)
        if len({capability.claims.capability_id for capability in lineage}) != len(lineage):
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)
        try:
            for capability in lineage:
                parent_profile = SigningProfile.capability(
                    self._configuration.target.project_id,
                    capability.claims.signing_key_version,
                )
                if parent_profile.key_resource != self._signer.profile.key_resource:
                    raise ValueError("parent capability uses another signing key")
                verify = cast(
                    Callable[[SignedCapability], object],
                    self._envelope_verifier.verify,
                )
                if verify(capability) is not None:
                    raise TypeError("capability verifier returned an invalid result")
        except (SigningError, TypeError, ValueError):
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_UNVERIFIED) from None
        return lineage

    def _validate_parent_lineage(
        self,
        state: _TrustedIssuanceState,
        request: CapabilityIssuanceRequest,
        lineage: tuple[SignedCapability, ...],
        issued_second: int,
    ) -> tuple[str | None, int | None]:
        if not lineage:
            return None, None
        root_approved_second = _parse_utc_second(state.root.approved_at)
        authority_changed_second = _parse_utc_second(state.authority.changed_at)
        previous_claims: CapabilityClaims | None = None
        for capability in lineage:
            claims = capability.claims
            issued_at = _parse_utc_second(claims.issued_at)
            if (
                claims.issuer != self._configuration.issuer_identity
                or issued_at < root_approved_second
                or issued_at < authority_changed_second
                or _parse_utc_second(claims.not_before) > issued_second
                or _parse_utc_second(claims.expires_at) <= issued_second
            ):
                raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)
            if previous_claims is not None and not (
                _parse_utc_second(previous_claims.not_before)
                <= issued_at
                < _parse_utc_second(previous_claims.expires_at)
            ):
                raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)
            previous_claims = claims
        self._validate_complete_lineage(state, request, lineage)
        parent = lineage[-1]
        return parent.claims_sha256, _parse_utc_second(parent.claims.expires_at)

    def _validate_complete_lineage(
        self,
        state: _TrustedIssuanceState,
        request: CapabilityIssuanceRequest,
        lineage: tuple[SignedCapability, ...],
    ) -> None:
        try:
            grants = tuple(
                CapabilityGrant(
                    capability_sha256=capability.claims_sha256,
                    parent_capability_sha256=capability.claims.parent_capability_sha256,
                    scope=_scope_from_claims(capability.claims, state.root),
                )
                for capability in lineage
            )
            anchor = _root_anchor(
                state,
                self._configuration,
                request,
                grants[0].scope.validity,
            )
            result = validate_lineage(anchor, grants)
        except (TypeError, ValueError):
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID) from None
        if not result.allowed:
            raise _deny(CapabilityIssuanceErrorCode.LINEAGE_INVALID)

    def _build_claims(
        self,
        *,
        state: _TrustedIssuanceState,
        request: CapabilityIssuanceRequest,
        issued_at: str,
        expires_at: str,
        parent_digest: str | None,
    ) -> CapabilityClaims:
        root = state.root
        identity_material: RestrictedJson = {
            "action": CapabilityAction.APPLY_CANARY.value,
            "audience": self._configuration.handler_audience,
            "epoch": state.authority.current_epoch,
            "expires_at": expires_at,
            "idempotency_key": request.idempotency_key,
            "issued_at": issued_at,
            "parent_capability_sha256": parent_digest,
            "request_id": request.request_id,
            "root_id": root.root_id,
            "root_sha256": state.root_sha256,
            "schema_version": CAPABILITY_IDENTITY_V1,
            "signing_key_version": self._signer.profile.key_version,
            "subject": self._configuration.subject_identity,
            "target": root.target.model_dump(mode="json"),
        }
        return CapabilityClaims(
            schema_version=CAPABILITY_CLAIMS_V1,
            capability_id=_capability_id(identity_material),
            issuer=self._configuration.issuer_identity,
            subject=self._configuration.subject_identity,
            audience=self._configuration.handler_audience,
            target=root.target,
            root_id=root.root_id,
            root_sha256=state.root_sha256,
            epoch=state.authority.current_epoch,
            action=CapabilityAction.APPLY_CANARY,
            stable_revision=root.stable_snapshot.stable_revision,
            candidate_revision=root.candidate_revision,
            stable_percent=root.stable_percent,
            candidate_percent=root.candidate_percent,
            concurrency=None,
            plan_sha256=root.plan_sha256,
            provider_etag=root.stable_snapshot.provider_etag,
            request_id=request.request_id,
            idempotency_key=request.idempotency_key,
            parent_capability_sha256=parent_digest,
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=expires_at,
            signing_algorithm="EC_SIGN_P256_SHA256",
            signing_key_version=self._signer.profile.key_version,
        )


__all__ = [
    "CAPABILITY_IDENTITY_DOMAIN",
    "CAPABILITY_IDENTITY_V1",
    "DEFAULT_CAPABILITY_LIFETIME_SECONDS",
    "MAX_CAPABILITY_LIFETIME_SECONDS",
    "AuthenticatedIssuancePrincipal",
    "CapabilityEnvelopeVerifier",
    "CapabilityIssuanceError",
    "CapabilityIssuanceErrorCode",
    "CapabilityIssuanceRequest",
    "CapabilityIssuer",
    "CapabilityIssuerConfiguration",
    "CapabilityLineageResolver",
    "TrustBundleCapabilityVerifier",
]
