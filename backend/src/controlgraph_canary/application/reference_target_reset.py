"""Explicit deployment-time reset of the disposable reference target."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

from controlgraph_canary.application.cloud_run import CloudRunTargetConfiguration
from controlgraph_canary.contracts.models import TargetBinding

REFERENCE_TARGET_REGION: Final = "us-central1"
REFERENCE_TARGET_SERVICE: Final = "controlgraph-reference-target"
REFERENCE_TARGET_STABLE_REVISION: Final = f"{REFERENCE_TARGET_SERVICE}-stable-v1"
REFERENCE_TARGET_CANDIDATE_REVISION: Final = f"{REFERENCE_TARGET_SERVICE}-candidate-v1"
REFERENCE_TARGET_CONCURRENCY: Final = 8
REFERENCE_TARGET_RESET_CONFIRMATION: Final = "RESET_REFERENCE_TARGET_BASELINE"

_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_OPAQUE_ETAG: Final = re.compile(r"^[A-Za-z0-9._~+/=:-]{1,512}$")
_OPERATION_NAME: Final = re.compile(r"^[A-Za-z0-9._~+/=:-]{1,512}$")


class ReferenceTargetResetOutcome(StrEnum):
    """Closed successful outcomes for one explicit reset request."""

    ALREADY_BASELINE = "ALREADY_BASELINE"
    RESET_APPLIED = "RESET_APPLIED"
    RESET_CONFIRMED_AFTER_UNKNOWN = "RESET_CONFIRMED_AFTER_UNKNOWN"


class ReferenceTargetResetErrorCode(StrEnum):
    """Sanitized reset failures that retain no provider diagnostics."""

    TARGET_STATE_DENIED = "TARGET_STATE_DENIED"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    PROVIDER_REJECTED = "PROVIDER_REJECTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class ReferenceTargetResetError(RuntimeError):
    """Fail one reset with a stable credential-free reason."""

    def __init__(self, code: ReferenceTargetResetErrorCode) -> None:
        if type(code) is not ReferenceTargetResetErrorCode:
            raise TypeError("an exact reference-target reset error code is required")
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class ReferenceTargetResetConfiguration:
    """Deployment-owned coordinates for the one disposable reference target."""

    project_id: str
    stable_image: str
    candidate_image: str
    network_resource: str
    subnetwork_resource: str

    def __post_init__(self) -> None:
        if (
            type(self.project_id) is not str
            or _CONTROLGRAPH_PROJECT_ID.fullmatch(self.project_id) is None
            or "reconcile" in self.project_id
        ):
            raise ValueError("reset project is outside the ControlGraph boundary")
        stable_digest = _require_image(
            self.stable_image,
            project_id=self.project_id,
            image_name="reference-stable",
        )
        candidate_digest = _require_image(
            self.candidate_image,
            project_id=self.project_id,
            image_name="reference-candidate",
        )
        if stable_digest == candidate_digest:
            raise ValueError("reset image digests must be distinct")
        _ = self.target_configuration

    @property
    def target(self) -> TargetBinding:
        return TargetBinding(
            schema_version="controlgraph.target-binding/v1",
            project_id=self.project_id,
            region=REFERENCE_TARGET_REGION,
            environment="nonprod",
            service_name=REFERENCE_TARGET_SERVICE,
        )

    @property
    def target_configuration(self) -> CloudRunTargetConfiguration:
        return CloudRunTargetConfiguration(
            target=self.target,
            stable_revision=REFERENCE_TARGET_STABLE_REVISION,
            candidate_revision=REFERENCE_TARGET_CANDIDATE_REVISION,
            stable_concurrency=REFERENCE_TARGET_CONCURRENCY,
            candidate_concurrency=REFERENCE_TARGET_CONCURRENCY,
            network_resource=self.network_resource,
            subnetwork_resource=self.subnetwork_resource,
        )


@dataclass(frozen=True, slots=True)
class ReferenceTargetResetRequest:
    """One explicitly confirmed compare-and-set reset request."""

    expected_etag: str
    confirmation: str

    def __post_init__(self) -> None:
        if (
            type(self.expected_etag) is not str
            or _OPAQUE_ETAG.fullmatch(self.expected_etag) is None
        ):
            raise ValueError("reset expected etag is invalid")
        if self.confirmation != REFERENCE_TARGET_RESET_CONFIRMATION:
            raise ValueError("reset confirmation is invalid")


@dataclass(frozen=True, slots=True)
class ReferenceTargetResetResult:
    """Exact independently read back baseline reached by one reset request."""

    configuration: ReferenceTargetResetConfiguration
    request: ReferenceTargetResetRequest
    outcome: ReferenceTargetResetOutcome
    previous_generation: int
    observed_generation: int
    observed_etag: str
    operation_name: str | None

    def __post_init__(self) -> None:
        if type(self.configuration) is not ReferenceTargetResetConfiguration:
            raise TypeError("an exact reset configuration is required")
        if type(self.request) is not ReferenceTargetResetRequest:
            raise TypeError("an exact reset request is required")
        if type(self.outcome) is not ReferenceTargetResetOutcome:
            raise TypeError("an exact reset outcome is required")
        if (
            type(self.previous_generation) is not int
            or self.previous_generation < 1
            or type(self.observed_generation) is not int
            or self.observed_generation < 1
            or _OPAQUE_ETAG.fullmatch(self.observed_etag) is None
        ):
            raise ValueError("reset readback identity is invalid")
        if self.operation_name is not None and (
            type(self.operation_name) is not str
            or _OPERATION_NAME.fullmatch(self.operation_name) is None
        ):
            raise ValueError("reset operation identity is invalid")
        if self.outcome is ReferenceTargetResetOutcome.ALREADY_BASELINE:
            if (
                self.operation_name is not None
                or self.previous_generation != self.observed_generation
                or self.request.expected_etag != self.observed_etag
            ):
                raise ValueError("already-baseline reset result is invalid")
            return
        if (
            self.observed_generation <= self.previous_generation
            or self.request.expected_etag == self.observed_etag
        ):
            raise ValueError("applied reset readback did not advance")
        if (
            self.outcome is ReferenceTargetResetOutcome.RESET_APPLIED
            and self.operation_name is None
        ):
            raise ValueError("applied reset result requires an operation identity")


@runtime_checkable
class ReferenceTargetResetter(Protocol):
    """Purpose-sealed provider facade for the explicit pre-run reset."""

    @property
    def configuration(self) -> ReferenceTargetResetConfiguration: ...

    async def reset(
        self,
        request: ReferenceTargetResetRequest,
    ) -> ReferenceTargetResetResult: ...


def _require_image(value: object, *, project_id: str, image_name: str) -> str:
    prefix = (
        f"{REFERENCE_TARGET_REGION}-docker.pkg.dev/{project_id}/controlgraph-canary/"
        f"{image_name}@sha256:"
    )
    match = (
        re.fullmatch(re.escape(prefix) + r"(?P<digest>[0-9a-f]{64})", value)
        if type(value) is str
        else None
    )
    if match is None:
        raise ValueError("reset image is not the configured immutable image")
    return match.group("digest")


__all__ = [
    "REFERENCE_TARGET_CANDIDATE_REVISION",
    "REFERENCE_TARGET_CONCURRENCY",
    "REFERENCE_TARGET_REGION",
    "REFERENCE_TARGET_RESET_CONFIRMATION",
    "REFERENCE_TARGET_SERVICE",
    "REFERENCE_TARGET_STABLE_REVISION",
    "ReferenceTargetResetConfiguration",
    "ReferenceTargetResetError",
    "ReferenceTargetResetErrorCode",
    "ReferenceTargetResetOutcome",
    "ReferenceTargetResetRequest",
    "ReferenceTargetResetResult",
    "ReferenceTargetResetter",
]
