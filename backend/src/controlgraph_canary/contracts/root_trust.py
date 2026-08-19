"""Canonical internal contracts for trusted rollout-root preflight."""

from __future__ import annotations

import re
from typing import Annotated, Final, Literal, Self

from pydantic import Field, model_validator

from controlgraph_canary.contracts.base import (
    BoundedText,
    CloudRunName,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.models import StableSnapshot, TargetBinding

ROOT_PREFLIGHT_REQUEST_V1: Final = "controlgraph.root-preflight-request/v1"
ROOT_CANDIDATE_ATTESTATION_V1: Final = (
    "controlgraph.root-candidate-attestation/v1"
)
ROOT_PREFLIGHT_RESULT_V1: Final = "controlgraph.root-preflight-result/v1"

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_OPAQUE_TOKEN = re.compile(r"^[A-Za-z0-9._~:/+=-]+$")
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"


class RootPreflightRequestV1(StrictContractModel):
    """Exact stable baseline and candidate facts requested from the verifier."""

    schema_version: Literal["controlgraph.root-preflight-request/v1"]
    target: TargetBinding
    expected_stable_snapshot: StableSnapshot
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    concurrency: Annotated[int, Field(ge=1, le=1_000)]

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        _validate_target(self.target)
        snapshot = self.expected_stable_snapshot
        expected_reader = _verifier_identity(self.target)
        revision_prefix = f"{self.target.service_name}-"
        if (
            snapshot.target != self.target
            or snapshot.captured_by != expected_reader
            or not snapshot.stable_revision.startswith(revision_prefix)
            or not self.candidate_revision.startswith(revision_prefix)
            or snapshot.stable_revision == self.candidate_revision
            or snapshot.concurrency != self.concurrency
        ):
            raise ValueError("root preflight request bindings are not exact")
        return self


class RootCandidateAttestationV1(StrictContractModel):
    """Canonical verifier observation of one exact immutable candidate revision."""

    schema_version: Literal["controlgraph.root-candidate-attestation/v1"]
    target: TargetBinding
    candidate_revision: CloudRunName
    configuration_sha256: Sha256Digest
    generation: PositiveSafeInteger
    etag: BoundedText
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    reader_identity: BoundedText
    captured_at: UtcSecond

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        _validate_target(self.target)
        if (
            not self.candidate_revision.startswith(f"{self.target.service_name}-")
            or self.reader_identity != _verifier_identity(self.target)
            or len(self.etag) > 512
            or _OPAQUE_TOKEN.fullmatch(self.etag) is None
        ):
            raise ValueError("root candidate attestation bindings are not exact")
        return self


class RootPreflightResultV1(StrictContractModel):
    """Self-binding canonical verifier result for one exact preflight request."""

    schema_version: Literal["controlgraph.root-preflight-result/v1"]
    request: RootPreflightRequestV1
    request_sha256: Sha256Digest
    stable_snapshot: StableSnapshot
    candidate_revision: RootCandidateAttestationV1

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        request = self.request
        snapshot = self.stable_snapshot
        candidate = self.candidate_revision
        if self.request_sha256 != root_preflight_request_sha256(request):
            raise ValueError("root preflight result does not bind its request")
        if (
            _stable_projection(snapshot)
            != _stable_projection(request.expected_stable_snapshot)
            or snapshot.captured_at < request.expected_stable_snapshot.captured_at
            or candidate.target != request.target
            or candidate.candidate_revision != request.candidate_revision
            or candidate.configuration_sha256
            != request.candidate_revision_configuration_sha256
            or candidate.concurrency != request.concurrency
            or candidate.reader_identity != snapshot.captured_by
            or candidate.captured_at
            < request.expected_stable_snapshot.captured_at
            or snapshot.captured_at < candidate.captured_at
        ):
            raise ValueError("root preflight result does not match its exact request")
        return self


def root_preflight_request_sha256(request: RootPreflightRequestV1) -> str:
    """Return the canonical digest that binds a verifier response to its request."""

    if type(request) is not RootPreflightRequestV1:
        raise TypeError("root preflight hashing requires an exact request")
    return canonical_sha256(request)


def stable_snapshots_match(
    observed: StableSnapshot,
    expected: StableSnapshot,
) -> bool:
    """Compare every stable authority field except the new capture time."""

    if type(observed) is not StableSnapshot or type(expected) is not StableSnapshot:
        return False
    return _stable_projection(observed) == _stable_projection(expected)


def _stable_projection(snapshot: StableSnapshot) -> tuple[object, ...]:
    return (
        snapshot.schema_version,
        snapshot.target,
        snapshot.stable_revision,
        snapshot.traffic,
        snapshot.concurrency,
        snapshot.service_generation,
        snapshot.provider_etag,
        snapshot.configuration_sha256,
        snapshot.stable_revision_configuration_sha256,
        snapshot.captured_by,
    )


def _validate_target(target: TargetBinding) -> None:
    if (
        _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is None
        or "reconcile" in target.project_id
        or target.region != "us-central1"
        or target.environment != "nonprod"
        or target.service_name != _REFERENCE_SERVICE
    ):
        raise ValueError("root preflight target is outside the ControlGraph boundary")


def _verifier_identity(target: TargetBinding) -> str:
    return f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"


__all__ = [
    "ROOT_CANDIDATE_ATTESTATION_V1",
    "ROOT_PREFLIGHT_REQUEST_V1",
    "ROOT_PREFLIGHT_RESULT_V1",
    "RootCandidateAttestationV1",
    "RootPreflightRequestV1",
    "RootPreflightResultV1",
    "root_preflight_request_sha256",
    "stable_snapshots_match",
]
