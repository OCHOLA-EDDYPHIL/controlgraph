"""Authenticated orchestration for one immutable rollout-root bundle."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import (
    AuthorityStore,
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreError,
    AuthorityStoreOutcomeUnknown,
    RootCreationBundle,
    RootCreationWriteResult,
    StoredRecord,
)
from controlgraph_canary.application.identity import AuthenticationContext, CallerRole
from controlgraph_canary.application.root_creation import (
    RootCreationConfiguration,
    build_unsigned_root_creation,
    complete_root_creation,
)
from controlgraph_canary.application.root_trust import (
    RootTrustClientError,
    TrustedRootPreflight,
)
from controlgraph_canary.contracts.models import EvidenceEvent
from controlgraph_canary.contracts.root_creation import (
    RootCreationCommandV1,
    RootCreationResultV1,
    SignedEvidenceEventV1,
)
from controlgraph_canary.contracts.root_trust import (
    ROOT_PREFLIGHT_REQUEST_V1,
    RootPreflightRequestV1,
    stable_snapshots_match,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    ServiceClaimStatus,
)

_EXECUTOR_AUDIENCE = re.compile(
    r"^https://controlgraph-executor-(?P<project_number>[1-9][0-9]{5,31})"
    r"\.us-central1\.run\.app$"
)


class RootCreationErrorCode(StrEnum):
    """Stable payload-free root-creation failure classes."""

    CALLER_UNAUTHENTICATED = "ROOT_CREATION_CALLER_UNAUTHENTICATED"
    CALLER_UNAUTHORIZED = "ROOT_CREATION_CALLER_UNAUTHORIZED"
    ACTIVE_CLAIM_CONFLICT = "ROOT_CREATION_ACTIVE_CLAIM_CONFLICT"
    PREFLIGHT_DENIED = "ROOT_CREATION_PREFLIGHT_DENIED"
    TRUSTED_STATE_INVALID = "ROOT_CREATION_TRUSTED_STATE_INVALID"
    EVIDENCE_DENIED = "ROOT_CREATION_EVIDENCE_DENIED"
    STORE_UNAVAILABLE = "ROOT_CREATION_STORE_UNAVAILABLE"
    OUTCOME_UNKNOWN = "ROOT_CREATION_OUTCOME_UNKNOWN"


class RootCreationError(RuntimeError):
    """A sanitized root-creation denial with no provider response material."""

    def __init__(self, code: RootCreationErrorCode) -> None:
        if type(code) is not RootCreationErrorCode:
            raise TypeError("an exact root creation error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class RootPreflightClient(Protocol):
    """Coordinator port for independently verified root preflight facts."""

    async def preflight(self, request: RootPreflightRequestV1) -> TrustedRootPreflight: ...


@runtime_checkable
class RootEvidenceClient(Protocol):
    """Coordinator port for independently verified signed evidence."""

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1: ...


@dataclass(frozen=True, slots=True)
class _ExistingClaimDecision:
    adopted: RootCreationWriteResult | None
    released: StoredRecord[ServiceClaimRecord] | None


class RolloutRootCreator:
    """Authorize, preflight, sign, and atomically persist one rollout root."""

    def __init__(
        self,
        *,
        store: AuthorityStore,
        preflight_client: RootPreflightClient,
        evidence_client: RootEvidenceClient,
        configuration: RootCreationConfiguration,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(configuration) is not RootCreationConfiguration:
            raise TypeError("root creation requires exact trusted configuration")
        if store.target != configuration.target:
            raise ValueError("root creation store target does not match configuration")
        if not isinstance(preflight_client, RootPreflightClient):
            raise TypeError("root creation requires a preflight client")
        if not isinstance(evidence_client, RootEvidenceClient):
            raise TypeError("root creation requires an evidence client")
        if clock is not None and not callable(clock):
            raise TypeError("root creation clock must be callable")
        executor_audience = _EXECUTOR_AUDIENCE.fullmatch(
            configuration.executor_audience
        )
        if executor_audience is None:
            raise ValueError("root creation operator audience cannot be derived")
        project_number = executor_audience.group("project_number")
        self._operator_audience = (
            f"https://controlgraph-api-{project_number}.us-central1.run.app"
        )
        self._store = store
        self._preflight_client = preflight_client
        self._evidence_client = evidence_client
        self._configuration = configuration
        self._clock = _system_utc_second if clock is None else clock

    async def create(
        self,
        command: RootCreationCommandV1,
        *,
        principal: AuthenticationContext | None,
    ) -> RootCreationWriteResult:
        """Create or exactly adopt one authenticated immutable root bundle."""

        if type(command) is not RootCreationCommandV1:
            raise TypeError("root creation requires an exact command")
        _, authorization_second = self._read_clock()
        self._authorize(principal, authorization_second)
        authenticated = principal
        if type(authenticated) is not AuthenticationContext:
            raise RootCreationError(RootCreationErrorCode.CALLER_UNAUTHENTICATED)

        existing = await self._existing_claim(command, authenticated)
        if existing.adopted is not None:
            return existing.adopted

        request = RootPreflightRequestV1(
            schema_version=ROOT_PREFLIGHT_REQUEST_V1,
            target=self._configuration.target,
            expected_stable_snapshot=command.expected_stable_snapshot,
            candidate_revision=self._configuration.candidate_revision,
            candidate_revision_configuration_sha256=(
                self._configuration.candidate_revision_configuration_sha256
            ),
            concurrency=self._configuration.concurrency,
        )
        try:
            trusted = await self._preflight_client.preflight(request)
        except asyncio.CancelledError:
            raise
        except RootTrustClientError:
            raise RootCreationError(RootCreationErrorCode.PREFLIGHT_DENIED) from None
        except Exception:
            raise RootCreationError(RootCreationErrorCode.PREFLIGHT_DENIED) from None
        if type(trusted) is not TrustedRootPreflight:
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID)

        created_at, created_second = self._read_clock()
        if created_second < authorization_second:
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID)
        self._authorize(authenticated, created_second)
        try:
            unsigned = build_unsigned_root_creation(
                command=command,
                operator_identity=authenticated.email,
                operator_subject=authenticated.subject,
                stable_snapshot=trusted.stable_snapshot,
                candidate_revision=trusted.candidate_revision,
                configuration=self._configuration,
                created_at=created_at,
            )
        except (TypeError, ValueError):
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID) from None

        try:
            signed = await self._evidence_client.sign(unsigned.evidence_event)
        except asyncio.CancelledError:
            raise
        except RootTrustClientError:
            raise RootCreationError(RootCreationErrorCode.EVIDENCE_DENIED) from None
        except Exception:
            raise RootCreationError(RootCreationErrorCode.EVIDENCE_DENIED) from None
        try:
            artifacts = complete_root_creation(unsigned, signed)
        except (TypeError, ValueError):
            raise RootCreationError(RootCreationErrorCode.EVIDENCE_DENIED) from None

        try:
            return await self._store.create_or_adopt_root_creation_bundle(
                artifacts.root,
                artifacts.service_claim,
                artifacts.initial_authority,
                artifacts.lineage_anchor,
                artifacts.signed_evidence,
                artifacts.creation_result,
                expected_released_claim=existing.released,
            )
        except asyncio.CancelledError:
            raise
        except AuthorityStoreConflict:
            raise RootCreationError(RootCreationErrorCode.ACTIVE_CLAIM_CONFLICT) from None
        except AuthorityStoreOutcomeUnknown:
            raise RootCreationError(RootCreationErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreError:
            raise RootCreationError(RootCreationErrorCode.STORE_UNAVAILABLE) from None
        except Exception:
            raise RootCreationError(RootCreationErrorCode.STORE_UNAVAILABLE) from None

    async def _existing_claim(
        self,
        command: RootCreationCommandV1,
        principal: AuthenticationContext,
    ) -> _ExistingClaimDecision:
        try:
            claim_record = await self._store.read_service_claim()
        except asyncio.CancelledError:
            raise
        except AuthorityStoreOutcomeUnknown:
            raise RootCreationError(RootCreationErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreError:
            raise RootCreationError(RootCreationErrorCode.STORE_UNAVAILABLE) from None
        except Exception:
            raise RootCreationError(RootCreationErrorCode.STORE_UNAVAILABLE) from None
        if claim_record is None:
            return _ExistingClaimDecision(adopted=None, released=None)
        if (
            type(claim_record) is not StoredRecord
            or type(claim_record.value) is not ServiceClaimRecord
        ):
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID)
        claim = claim_record.value
        if claim.target != self._configuration.target:
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID)
        if claim.status is ServiceClaimStatus.RELEASED:
            return _ExistingClaimDecision(adopted=None, released=claim_record)
        if claim.status is not ServiceClaimStatus.ACTIVE:
            raise RootCreationError(RootCreationErrorCode.ACTIVE_CLAIM_CONFLICT)
        if (
            claim.claim_request_id != command.request_id
            or claim.operator_owner != principal.email
        ):
            raise RootCreationError(RootCreationErrorCode.ACTIVE_CLAIM_CONFLICT)
        try:
            bundle = await self._store.read_root_creation_bundle(claim.root_id)
        except asyncio.CancelledError:
            raise
        except AuthorityStoreCorruptRecord:
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID) from None
        except AuthorityStoreOutcomeUnknown:
            raise RootCreationError(RootCreationErrorCode.OUTCOME_UNKNOWN) from None
        except AuthorityStoreError:
            raise RootCreationError(RootCreationErrorCode.STORE_UNAVAILABLE) from None
        except Exception:
            raise RootCreationError(RootCreationErrorCode.STORE_UNAVAILABLE) from None
        if type(bundle) is not RootCreationBundle:
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID)
        winner = bundle.creation_result.value
        if not self._matches_existing(command, principal, claim, winner):
            raise RootCreationError(RootCreationErrorCode.ACTIVE_CLAIM_CONFLICT)
        try:
            adopted = RootCreationResultV1.model_validate(
                {**winner.model_dump(mode="python"), "outcome": "ADOPTED"}
            )
            return _ExistingClaimDecision(
                adopted=RootCreationWriteResult(result=adopted, bundle=bundle),
                released=None,
            )
        except (TypeError, ValueError):
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID) from None

    def _matches_existing(
        self,
        command: RootCreationCommandV1,
        principal: AuthenticationContext,
        claim: ServiceClaimRecord,
        winner: object,
    ) -> bool:
        if type(winner) is not RootCreationResultV1:
            return False
        root = winner.root
        return (
            winner.outcome == "CREATED"
            and winner.request_id == command.request_id
            and winner.idempotency_key == command.idempotency_key
            and winner.operator_identity == principal.email
            and winner.operator_subject == principal.subject
            and winner.root.content.target == self._configuration.target
            and claim.root_id == root.root_id
            and claim.root_sha256 == root.root_sha256
            and stable_snapshots_match(
                root.content.stable_snapshot,
                command.expected_stable_snapshot,
            )
            and command.expected_stable_snapshot.captured_at
            <= root.content.stable_snapshot.captured_at
        )

    def _authorize(
        self,
        principal: AuthenticationContext | None,
        current_second: int,
    ) -> None:
        if principal is None or type(principal) is not AuthenticationContext:
            raise RootCreationError(RootCreationErrorCode.CALLER_UNAUTHENTICATED)
        if (
            principal.role is not CallerRole.OPERATOR
            or principal.email != self._configuration.operator_identity
            or principal.subject != self._configuration.operator_subject
            or principal.issuer not in {"accounts.google.com", "https://accounts.google.com"}
            or principal.audience != self._operator_audience
            or type(principal.issued_at) is not int
            or type(principal.expires_at) is not int
            or principal.issued_at > current_second
            or principal.expires_at <= current_second
        ):
            raise RootCreationError(RootCreationErrorCode.CALLER_UNAUTHORIZED)

    def _read_clock(self) -> tuple[str, int]:
        try:
            value = self._clock()
        except Exception:
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID) from None
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise RootCreationError(RootCreationErrorCode.TRUSTED_STATE_INVALID)
        normalized = value.astimezone(UTC)
        return normalized.strftime("%Y-%m-%dT%H:%M:%SZ"), int(normalized.timestamp())


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "RolloutRootCreator",
    "RootCreationError",
    "RootCreationErrorCode",
    "RootEvidenceClient",
    "RootPreflightClient",
]
