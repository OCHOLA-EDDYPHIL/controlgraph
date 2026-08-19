"""Exact verifier-only validation of one configured candidate revision."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.cloud_run import (
    CloudRunReadError,
    CloudRunReadErrorCode,
    CloudRunReadyState,
    CloudRunRevisionState,
    cloud_run_revision_configuration_sha256,
)
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.contracts.base import MAX_SAFE_INTEGER
from controlgraph_canary.contracts.models import TargetBinding

_CONTROLGRAPH_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_CLOUD_RUN_NAME = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_TOKEN = re.compile(r"^[A-Za-z0-9._~:/+=-]+$")
_REFERENCE_SERVICE = "controlgraph-reference-target"
_CONTROLGRAPH_ENVIRONMENT = "nonprod"


class CandidateValidationReason(StrEnum):
    """Closed, provider-independent candidate validation failures."""

    NOT_FOUND = "CANDIDATE_REVISION_NOT_FOUND"
    UNAVAILABLE = "CANDIDATE_REVISION_UNAVAILABLE"
    CORRUPT = "CANDIDATE_REVISION_CORRUPT"
    MISMATCH = "CANDIDATE_REVISION_MISMATCH"
    NOT_READY = "CANDIDATE_REVISION_NOT_READY"
    RECONCILING = "CANDIDATE_REVISION_RECONCILING"
    STALE_GENERATION = "CANDIDATE_REVISION_STALE_GENERATION"


class CandidateValidationError(RuntimeError):
    """Sanitized candidate denial containing no provider response material."""

    def __init__(self, reason: CandidateValidationReason) -> None:
        if type(reason) is not CandidateValidationReason:
            raise TypeError("an exact candidate validation reason is required")
        self.reason = reason
        super().__init__(reason.value)


@runtime_checkable
class CandidateRevisionReader(Protocol):
    """Verifier-only exact-read port required for candidate validation."""

    @property
    def target(self) -> TargetBinding: ...

    @property
    def service_role(self) -> ServiceRole: ...

    @property
    def reader_identity(self) -> str: ...

    async def read_revision(self, revision_name: str) -> CloudRunRevisionState: ...


@dataclass(frozen=True, slots=True)
class CandidateRevisionValidationConfiguration:
    """Trusted candidate, configuration digest, and verifier binding."""

    target: TargetBinding
    candidate_revision: str
    expected_configuration_sha256: str
    expected_concurrency: int
    reader_identity: str

    def __post_init__(self) -> None:
        _validate_target(self.target)
        _validate_candidate_name(self.target, self.candidate_revision)
        _validate_sha256(
            "expected candidate configuration digest",
            self.expected_configuration_sha256,
        )
        _validate_concurrency(self.expected_concurrency)
        _validate_reader_identity(self.target, self.reader_identity)


@dataclass(frozen=True, slots=True)
class CandidateRevisionAttestation:
    """Trusted immutable candidate facts admitted for root creation."""

    target: TargetBinding
    candidate_revision: str
    configuration_sha256: str
    generation: int
    etag: str
    concurrency: int
    reader_identity: str
    captured_at: str

    def __post_init__(self) -> None:
        _validate_target(self.target)
        _validate_candidate_name(self.target, self.candidate_revision)
        _validate_sha256("candidate configuration digest", self.configuration_sha256)
        if type(self.generation) is not int or not 1 <= self.generation <= MAX_SAFE_INTEGER:
            raise ValueError("candidate generation is not a positive safe integer")
        if (
            type(self.etag) is not str
            or not self.etag
            or len(self.etag) > 512
            or _OPAQUE_TOKEN.fullmatch(self.etag) is None
        ):
            raise ValueError("candidate etag is not an opaque provider token")
        _validate_concurrency(self.concurrency)
        _validate_reader_identity(self.target, self.reader_identity)
        _validate_utc_second(self.captured_at)


class CandidateRevisionValidator:
    """Validate one configured candidate using one verifier-only exact read."""

    def __init__(
        self,
        *,
        reader: CandidateRevisionReader,
        configuration: CandidateRevisionValidationConfiguration,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(configuration) is not CandidateRevisionValidationConfiguration:
            raise TypeError("an exact candidate validation configuration is required")
        try:
            reader_target = reader.target
            reader_role = reader.service_role
            reader_identity = reader.reader_identity
            read_revision = reader.read_revision
        except Exception:
            raise CandidateValidationError(CandidateValidationReason.MISMATCH) from None
        if (
            type(reader_target) is not TargetBinding
            or reader_target != configuration.target
            or reader_role is not ServiceRole.VERIFIER
            or reader_identity != configuration.reader_identity
            or not callable(read_revision)
        ):
            raise CandidateValidationError(CandidateValidationReason.MISMATCH)
        if clock is not None and not callable(clock):
            raise TypeError("candidate validation clock must be callable")
        self._reader = reader
        self._configuration = configuration
        self._clock = clock or _now_utc_second

    @property
    def target(self) -> TargetBinding:
        return self._configuration.target

    async def validate(self) -> CandidateRevisionAttestation:
        """Return trusted candidate facts or one closed, payload-free denial."""

        revision = await self._read_candidate()
        expected_service_resource = (
            f"projects/{self.target.project_id}/locations/{self.target.region}/services/"
            f"{self.target.service_name}"
        )
        expected_revision_resource = (
            f"{expected_service_resource}/revisions/"
            f"{self._configuration.candidate_revision}"
        )
        if (
            revision.target != self.target
            or revision.revision != self._configuration.candidate_revision
            or revision.service_resource != expected_service_resource
            or revision.resource_name != expected_revision_resource
        ):
            raise CandidateValidationError(CandidateValidationReason.MISMATCH)
        if revision.reconciling:
            raise CandidateValidationError(CandidateValidationReason.RECONCILING)
        if revision.ready_state is not CloudRunReadyState.READY:
            raise CandidateValidationError(CandidateValidationReason.NOT_READY)
        if revision.observed_generation != revision.generation:
            raise CandidateValidationError(CandidateValidationReason.STALE_GENERATION)
        if revision.concurrency != self._configuration.expected_concurrency:
            raise CandidateValidationError(CandidateValidationReason.MISMATCH)
        configuration_sha256 = cloud_run_revision_configuration_sha256(
            revision.configuration
        )
        if configuration_sha256 != self._configuration.expected_configuration_sha256:
            raise CandidateValidationError(CandidateValidationReason.MISMATCH)
        captured_at = _utc_second(self._clock())
        return CandidateRevisionAttestation(
            target=self.target,
            candidate_revision=self._configuration.candidate_revision,
            configuration_sha256=configuration_sha256,
            generation=revision.generation,
            etag=revision.etag,
            concurrency=revision.concurrency,
            reader_identity=self._configuration.reader_identity,
            captured_at=captured_at,
        )

    async def _read_candidate(self) -> CloudRunRevisionState:
        try:
            value = await self._reader.read_revision(
                self._configuration.candidate_revision
            )
        except asyncio.CancelledError:
            raise
        except CloudRunReadError as error:
            if error.code is CloudRunReadErrorCode.NOT_FOUND:
                reason = CandidateValidationReason.NOT_FOUND
            elif error.code is CloudRunReadErrorCode.CORRUPT_RESPONSE:
                reason = CandidateValidationReason.CORRUPT
            else:
                reason = CandidateValidationReason.UNAVAILABLE
            raise CandidateValidationError(reason) from None
        except Exception:
            raise CandidateValidationError(CandidateValidationReason.UNAVAILABLE) from None
        if type(value) is not CloudRunRevisionState:
            raise CandidateValidationError(CandidateValidationReason.CORRUPT)
        return value


def _validate_target(target: object) -> None:
    if type(target) is not TargetBinding:
        raise TypeError("candidate validation requires an exact configured target")
    if (
        _CONTROLGRAPH_PROJECT_ID.fullmatch(target.project_id) is None
        or target.region != "us-central1"
        or target.environment != _CONTROLGRAPH_ENVIRONMENT
        or target.service_name != _REFERENCE_SERVICE
    ):
        raise ValueError("candidate target is outside the ControlGraph boundary")


def _validate_candidate_name(target: TargetBinding, value: object) -> None:
    if (
        type(value) is not str
        or _CLOUD_RUN_NAME.fullmatch(value) is None
        or not value.startswith(f"{target.service_name}-")
    ):
        raise ValueError("candidate revision is not bound to the configured service")


def _validate_sha256(name: str, value: object) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} is not a SHA-256 digest")


def _validate_concurrency(value: object) -> None:
    if type(value) is not int or not 1 <= value <= 1_000:
        raise ValueError("candidate concurrency is outside the approved bound")


def _validate_reader_identity(target: TargetBinding, value: object) -> None:
    expected = f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"
    if type(value) is not str or value != expected:
        raise ValueError("candidate reader is not the configured verifier identity")


def _validate_utc_second(value: object) -> None:
    if type(value) is not str or len(value) != 20:
        raise ValueError("candidate capture time must be an exact UTC second")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("candidate capture time must be an exact UTC second") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("candidate capture time must be an exact UTC second")


def _now_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _utc_second(value: datetime) -> str:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.microsecond != 0
    ):
        raise ValueError("candidate validation clock must return an exact aware second")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "CandidateRevisionAttestation",
    "CandidateRevisionReader",
    "CandidateRevisionValidationConfiguration",
    "CandidateRevisionValidator",
    "CandidateValidationError",
    "CandidateValidationReason",
]
