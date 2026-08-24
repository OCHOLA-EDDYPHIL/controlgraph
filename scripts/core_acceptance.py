"""Bind one complete hosted core acceptance run to a redacted manifest."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from collections.abc import Sequence
from contextlib import suppress
from datetime import datetime
from enum import StrEnum
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal, Self, cast

from pydantic import AfterValidator, Field, StringConstraints, ValidationError, model_validator

import controlgraph_canary
import controlgraph_canary.contracts.base as contract_base_module
import controlgraph_canary.contracts.codec as contract_codec_module
from controlgraph_canary.contracts.base import (
    MAX_CONTRACT_BYTES,
    CloudRunName,
    Identifier,
    NonNegativeSafeInteger,
    PositiveSafeInteger,
    ProjectId,
    Region,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    RestrictedJson,
    canonical_json_value_bytes,
    decode_contract,
)

MANIFEST_SCHEMA: Final = "controlgraph.core-acceptance-manifest/v1"
MAX_ARTIFACT_BYTES: Final = 8 * 1024 * 1024
MAX_CASE_DURATION_MS: Final = 60 * 60 * 1_000
MAX_RUN_DURATION_MS: Final = 4 * 60 * 60 * 1_000
MAX_RUN_COST_MICROUSD: Final = 10_000_000

_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_IMAGE = re.compile(
    r"^(?P<region>[a-z]+-[a-z]+[0-9]+)-docker\.pkg\.dev/"
    r"(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])/controlgraph-canary/"
    r"(?P<name>[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)@sha256:"
    r"(?P<digest>[0-9a-f]{64})$"
)


class AcceptanceError(ValueError):
    """Stable failure that never includes untrusted input in its public form."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _relative_artifact_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("artifact path must be a normalized relative POSIX path")
    return value


RelativeArtifactPath = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$",
    ),
    AfterValidator(_relative_artifact_path),
]
SchemaVersion = Annotated[
    str,
    StringConstraints(
        min_length=5,
        max_length=128,
        pattern=r"^[a-z][a-z0-9.-]*/v[1-9][0-9]*$",
    ),
]
GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
ImageReference = Annotated[str, StringConstraints(min_length=100, max_length=512)]
CaseDurationMs = Annotated[int, Field(ge=0, le=MAX_CASE_DURATION_MS)]
CostMicrousd = Annotated[int, Field(ge=0, le=MAX_RUN_COST_MICROUSD)]


class CaseKind(StrEnum):
    TARGET_RESET = "TARGET_RESET"
    HEALTHY_PROMOTION = "HEALTHY_PROMOTION"
    UNHEALTHY_STABLE_RECOVERY = "UNHEALTHY_STABLE_RECOVERY"
    REVOCATION_STALE_DENIAL = "REVOCATION_STALE_DENIAL"
    INDEPENDENT_VERIFIER_PROBE = "INDEPENDENT_VERIFIER_PROBE"
    AMBIGUITY_CLASSIFICATION = "AMBIGUITY_CLASSIFICATION"
    TIMELINE_CONSOLE_READ = "TIMELINE_CONSOLE_READ"
    BOUNDED_ADVISOR = "BOUNDED_ADVISOR"


CORE_CASE_ORDER: Final = tuple(CaseKind)

EXPECTED_RESULTS: Final[dict[CaseKind, str]] = {
    CaseKind.TARGET_RESET: "RESET_VERIFIED",
    CaseKind.HEALTHY_PROMOTION: "PROMOTED",
    CaseKind.UNHEALTHY_STABLE_RECOVERY: "RECOVERED",
    CaseKind.REVOCATION_STALE_DENIAL: "DENIED",
    CaseKind.INDEPENDENT_VERIFIER_PROBE: "VERIFIED",
    CaseKind.AMBIGUITY_CLASSIFICATION: "AMBIGUOUS",
    CaseKind.TIMELINE_CONSOLE_READ: "READABLE",
    CaseKind.BOUNDED_ADVISOR: "ADVISORY_ONLY",
}


class ImageComponent(StrEnum):
    CONTROLLER = "controller"
    ADVISOR = "advisor"
    CONSOLE = "console"
    REFERENCE_STABLE = "reference-stable"
    REFERENCE_CANDIDATE = "reference-candidate"


class EvidenceKind(StrEnum):
    CLOUD_RUN_CONFIGURATION = "CLOUD_RUN_CONFIGURATION"
    DATA_PATH_PROBE = "DATA_PATH_PROBE"
    SIGNED_CAPABILITY = "SIGNED_CAPABILITY"
    EXECUTOR_EPOCH_CHECK = "EXECUTOR_EPOCH_CHECK"
    EXECUTION_RECEIPT = "EXECUTION_RECEIPT"
    HEALTH_DECISION = "HEALTH_DECISION"
    RECOVERY_IDENTITY = "RECOVERY_IDENTITY"
    AUTHORITY_TRANSITION = "AUTHORITY_TRANSITION"
    STALE_DENIAL = "STALE_DENIAL"
    INDEPENDENT_VERIFICATION = "INDEPENDENT_VERIFICATION"
    AMBIGUITY_CLASSIFICATION = "AMBIGUITY_CLASSIFICATION"
    TIMELINE = "TIMELINE"
    CONSOLE_READ = "CONSOLE_READ"
    COORDINATOR = "COORDINATOR"
    MODEL_AUDIT = "MODEL_AUDIT"


class ResultStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"


class CostBasis(StrEnum):
    MEASURED = "MEASURED"
    UPPER_BOUND = "UPPER_BOUND"


class EvidenceProjection(StrEnum):
    PUBLIC_REDACTED = "PUBLIC_REDACTED"
    PRIVATE_DIGEST_ONLY = "PRIVATE_DIGEST_ONLY"


REQUIRED_EVIDENCE: Final[dict[CaseKind, frozenset[EvidenceKind]]] = {
    CaseKind.TARGET_RESET: frozenset(
        {EvidenceKind.CLOUD_RUN_CONFIGURATION, EvidenceKind.DATA_PATH_PROBE}
    ),
    CaseKind.HEALTHY_PROMOTION: frozenset(
        {
            EvidenceKind.CLOUD_RUN_CONFIGURATION,
            EvidenceKind.DATA_PATH_PROBE,
            EvidenceKind.SIGNED_CAPABILITY,
            EvidenceKind.EXECUTOR_EPOCH_CHECK,
            EvidenceKind.EXECUTION_RECEIPT,
            EvidenceKind.HEALTH_DECISION,
            EvidenceKind.TIMELINE,
        }
    ),
    CaseKind.UNHEALTHY_STABLE_RECOVERY: frozenset(
        {
            EvidenceKind.CLOUD_RUN_CONFIGURATION,
            EvidenceKind.DATA_PATH_PROBE,
            EvidenceKind.SIGNED_CAPABILITY,
            EvidenceKind.EXECUTOR_EPOCH_CHECK,
            EvidenceKind.EXECUTION_RECEIPT,
            EvidenceKind.HEALTH_DECISION,
            EvidenceKind.RECOVERY_IDENTITY,
            EvidenceKind.TIMELINE,
        }
    ),
    CaseKind.REVOCATION_STALE_DENIAL: frozenset(
        {
            EvidenceKind.AUTHORITY_TRANSITION,
            EvidenceKind.CLOUD_RUN_CONFIGURATION,
            EvidenceKind.DATA_PATH_PROBE,
            EvidenceKind.SIGNED_CAPABILITY,
            EvidenceKind.EXECUTOR_EPOCH_CHECK,
            EvidenceKind.STALE_DENIAL,
            EvidenceKind.EXECUTION_RECEIPT,
            EvidenceKind.TIMELINE,
        }
    ),
    CaseKind.INDEPENDENT_VERIFIER_PROBE: frozenset(
        {
            EvidenceKind.CLOUD_RUN_CONFIGURATION,
            EvidenceKind.DATA_PATH_PROBE,
            EvidenceKind.INDEPENDENT_VERIFICATION,
            EvidenceKind.TIMELINE,
        }
    ),
    CaseKind.AMBIGUITY_CLASSIFICATION: frozenset(
        {
            EvidenceKind.CLOUD_RUN_CONFIGURATION,
            EvidenceKind.EXECUTION_RECEIPT,
            EvidenceKind.AMBIGUITY_CLASSIFICATION,
            EvidenceKind.TIMELINE,
        }
    ),
    CaseKind.TIMELINE_CONSOLE_READ: frozenset({EvidenceKind.TIMELINE, EvidenceKind.CONSOLE_READ}),
    CaseKind.BOUNDED_ADVISOR: frozenset(
        {EvidenceKind.COORDINATOR, EvidenceKind.MODEL_AUDIT, EvidenceKind.TIMELINE}
    ),
}

_RESET_AND_READ: Final = (
    "cli:controlgraph-reference-target-reset",
    "cli:controlgraph-canary:read-target-traffic",
)

ENTRY_POINTS: Final[dict[CaseKind, tuple[str, ...]]] = {
    CaseKind.TARGET_RESET: _RESET_AND_READ,
    CaseKind.HEALTHY_PROMOTION: (
        *_RESET_AND_READ,
        "cli:controlgraph-canary:capture-stable-snapshot",
        "cli:controlgraph-canary:create-rollout-root",
        "cli:controlgraph-canary:apply-canary",
        "cli:controlgraph-canary:evaluate-health",
        "cli:controlgraph-canary:promote-candidate",
        "cli:controlgraph-canary:read-execution-receipt",
        "cli:controlgraph-canary:read-target-traffic",
        "cli:controlgraph-canary:release-service-claim",
    ),
    CaseKind.UNHEALTHY_STABLE_RECOVERY: (
        *_RESET_AND_READ,
        "cli:controlgraph-canary:capture-stable-snapshot",
        "cli:controlgraph-canary:create-rollout-root",
        "cli:controlgraph-canary:apply-canary",
        "cli:controlgraph-canary:evaluate-health",
        "service:recovery",
        "cli:controlgraph-canary:read-execution-receipt",
        "cli:controlgraph-canary:read-target-traffic",
        "cli:controlgraph-canary:release-service-claim",
    ),
    CaseKind.REVOCATION_STALE_DENIAL: (
        *_RESET_AND_READ,
        "cli:controlgraph-canary:capture-stable-snapshot",
        "cli:controlgraph-canary:create-rollout-root",
        "cli:controlgraph-canary:apply-canary",
        "cli:controlgraph-canary:execution-queue:hold",
        "cli:controlgraph-canary:evaluate-health",
        "cli:controlgraph-canary:revoke-epoch",
        "cli:controlgraph-canary:execution-queue:release",
        "cli:controlgraph-canary:read-execution-receipt",
        "cli:controlgraph-canary:read-target-traffic",
        "cli:controlgraph-canary:recover-captured-stable",
        "cli:controlgraph-canary:release-service-claim",
    ),
    CaseKind.INDEPENDENT_VERIFIER_PROBE: (
        *_RESET_AND_READ,
        "service:verifier:independent-verification",
        "endpoint:reference-target:probe",
    ),
    CaseKind.AMBIGUITY_CLASSIFICATION: (
        *_RESET_AND_READ,
        "cli:controlgraph-canary:capture-stable-snapshot",
        "cli:controlgraph-canary:create-rollout-root",
        "cli:controlgraph-canary:apply-canary",
        "cli:controlgraph-ambiguous-receipt-readback",
        "cli:controlgraph-canary:classify-completion",
    ),
    CaseKind.TIMELINE_CONSOLE_READ: (
        *_RESET_AND_READ,
        "endpoint:api:timeline-read",
        "web:operator-console",
    ),
    CaseKind.BOUNDED_ADVISOR: (
        *_RESET_AND_READ,
        "endpoint:api:advisor-command",
        "service:coordinator:advisor",
        "service:advisor",
    ),
}


class ArtifactBindingV1(StrictContractModel):
    schema_version: Literal["controlgraph.acceptance-artifact-binding/v1"]
    artifact_id: Identifier
    relative_path: RelativeArtifactPath
    sha256: Sha256Digest
    media_type: Literal["application/json", "text/plain", "application/octet-stream"]


class AcceptanceTargetV1(StrictContractModel):
    schema_version: Literal["controlgraph.acceptance-target/v1"]
    project_id: ProjectId
    region: Region
    environment: Literal["acceptance"]
    service_name: CloudRunName
    stable_revision: CloudRunName
    candidate_revision: CloudRunName

    @model_validator(mode="after")
    def validate_isolated_target(self) -> Self:
        if (
            _PROJECT.fullmatch(self.project_id) is None
            or self.region != "us-central1"
            or self.service_name != "controlgraph-reference-target"
            or self.stable_revision == self.candidate_revision
        ):
            raise ValueError("acceptance target is outside the isolated reference boundary")
        return self


class ImageBindingV1(StrictContractModel):
    schema_version: Literal["controlgraph.acceptance-image/v1"]
    component: ImageComponent
    reference: ImageReference


class PolicyBindingV1(StrictContractModel):
    schema_version: Literal["controlgraph.acceptance-policy-binding/v1"]
    policy_schema_version: SchemaVersion
    artifact: ArtifactBindingV1


class TestClockTickV1(StrictContractModel):
    schema_version: Literal["controlgraph.acceptance-test-clock-tick/v1"]
    name: Identifier
    at: UtcSecond


class TestClockV1(StrictContractModel):
    schema_version: Literal["controlgraph.acceptance-test-clock/v1"]
    ticks: tuple[TestClockTickV1, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_ticks(self) -> Self:
        names = tuple(item.name for item in self.ticks)
        instants = tuple(item.at for item in self.ticks)
        if len(set(names)) != len(names) or instants != tuple(sorted(instants)):
            raise ValueError("test-clock ticks must be unique and chronological")
        return self


class CaseBindingV1(StrictContractModel):
    schema_version: Literal["controlgraph.core-acceptance-case-binding/v1"]
    sequence: PositiveSafeInteger
    case_id: Identifier
    kind: CaseKind
    random_seed: NonNegativeSafeInteger
    test_clock_keys: tuple[Identifier, ...] = Field(min_length=1, max_length=32)
    maximum_duration_ms: Annotated[int, Field(ge=1, le=MAX_CASE_DURATION_MS)]
    maximum_cost_microusd: CostMicrousd
    result: ArtifactBindingV1

    @model_validator(mode="after")
    def validate_clock_keys(self) -> Self:
        if len(set(self.test_clock_keys)) != len(self.test_clock_keys):
            raise ValueError("case test-clock keys must be unique")
        return self


class CoreAcceptanceRunSpecV1(StrictContractModel):
    schema_version: Literal["controlgraph.core-acceptance-run-spec/v1"]
    source_commit: GitCommit
    target: AcceptanceTargetV1
    images: tuple[ImageBindingV1, ...] = Field(min_length=5, max_length=5)
    terraform_plan: ArtifactBindingV1
    policies: tuple[PolicyBindingV1, ...] = Field(min_length=1, max_length=8)
    random_seed: NonNegativeSafeInteger
    test_clock: TestClockV1
    maximum_total_duration_ms: Annotated[int, Field(ge=1, le=MAX_RUN_DURATION_MS)]
    maximum_total_cost_microusd: CostMicrousd
    cases: tuple[CaseBindingV1, ...] = Field(min_length=8, max_length=8)

    @model_validator(mode="after")
    def validate_complete_core_run(self) -> Self:
        components = tuple(item.component for item in self.images)
        references = tuple(item.reference for item in self.images)
        if components != tuple(ImageComponent) or len(set(references)) != len(references):
            raise ValueError("images must contain the five distinct components in fixed order")
        expected_names = {
            ImageComponent.CONTROLLER: "controller",
            ImageComponent.ADVISOR: "advisor",
            ImageComponent.CONSOLE: "console",
            ImageComponent.REFERENCE_STABLE: "reference-stable",
            ImageComponent.REFERENCE_CANDIDATE: "reference-candidate",
        }
        image_digests: list[str] = []
        for image in self.images:
            match = _IMAGE.fullmatch(image.reference)
            if (
                match is None
                or match.group("project") != self.target.project_id
                or match.group("region") != self.target.region
                or match.group("name") != expected_names[image.component]
            ):
                raise ValueError("image is not an immutable reference for the isolated target")
            image_digests.append(match.group("digest"))
        if len(set(image_digests)) != len(image_digests):
            raise ValueError("acceptance images must have distinct immutable digests")
        if tuple(item.sequence for item in self.cases) != tuple(range(1, 9)):
            raise ValueError("core cases must have contiguous sequence numbers")
        if tuple(item.kind for item in self.cases) != CORE_CASE_ORDER:
            raise ValueError("core cases must use the fixed complete order")
        if len({item.case_id for item in self.cases}) != len(self.cases):
            raise ValueError("core case identities must be unique")
        if any(item.result.media_type != "application/json" for item in self.cases):
            raise ValueError("core case result artifacts must use JSON media")
        if any(item.artifact.media_type != "application/json" for item in self.policies):
            raise ValueError("policy artifacts must use JSON media")
        clock_keys = {item.name for item in self.test_clock.ticks}
        if any(not set(item.test_clock_keys).issubset(clock_keys) for item in self.cases):
            raise ValueError("core case references an unknown test-clock input")
        if sum(item.maximum_duration_ms for item in self.cases) > self.maximum_total_duration_ms:
            raise ValueError("case duration bounds exceed the run duration bound")
        if (
            sum(item.maximum_cost_microusd for item in self.cases)
            > self.maximum_total_cost_microusd
        ):
            raise ValueError("case cost bounds exceed the run cost bound")
        artifact_ids = [self.terraform_plan.artifact_id]
        artifact_ids.extend(item.artifact.artifact_id for item in self.policies)
        artifact_ids.extend(item.result.artifact_id for item in self.cases)
        if len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("top-level artifact identities must be unique")
        return self


class StepResultV1(StrictContractModel):
    schema_version: Literal["controlgraph.core-acceptance-step-result/v1"]
    sequence: PositiveSafeInteger
    operation: Identifier
    status: ResultStatus
    duration_ms: CaseDurationMs
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=32)


class EvidenceBindingV1(StrictContractModel):
    schema_version: Literal["controlgraph.acceptance-evidence-binding/v1"]
    evidence_id: Identifier
    kind: EvidenceKind
    observed_at: UtcSecond
    projection: EvidenceProjection
    run_inputs_sha256: Sha256Digest
    artifact: ArtifactBindingV1


class CoreAcceptanceCaseResultV1(StrictContractModel):
    schema_version: Literal["controlgraph.core-acceptance-case-result/v1"]
    case_id: Identifier
    kind: CaseKind
    execution_mode: Literal["HOSTED_GOOGLE_CLOUD"]
    source_commit: GitCommit
    run_inputs_sha256: Sha256Digest
    target: AcceptanceTargetV1
    random_seed: NonNegativeSafeInteger
    test_clock_keys: tuple[Identifier, ...] = Field(min_length=1, max_length=32)
    status: ResultStatus
    observed_result: Identifier
    started_at: UtcSecond
    completed_at: UtcSecond
    duration_ms: CaseDurationMs
    cost_microusd: CostMicrousd
    cost_basis: CostBasis
    steps: tuple[StepResultV1, ...] = Field(min_length=1, max_length=32)
    evidence: tuple[EvidenceBindingV1, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("case completion cannot precede its start")
        elapsed_ms = int(
            (
                datetime.strptime(self.completed_at, "%Y-%m-%dT%H:%M:%SZ")
                - datetime.strptime(self.started_at, "%Y-%m-%dT%H:%M:%SZ")
            ).total_seconds()
            * 1_000
        )
        if not max(0, elapsed_ms - 999) <= self.duration_ms <= elapsed_ms + 999:
            raise ValueError("case duration does not match its whole-second timestamps")
        if tuple(item.sequence for item in self.steps) != tuple(range(1, len(self.steps) + 1)):
            raise ValueError("case steps must have contiguous sequence numbers")
        if sum(item.duration_ms for item in self.steps) > self.duration_ms:
            raise ValueError("case step durations exceed the case duration")
        evidence_ids = tuple(item.evidence_id for item in self.evidence)
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("case evidence identities must be unique")
        referenced = tuple(item for step in self.steps for item in step.evidence_ids)
        if set(referenced) != set(evidence_ids):
            raise ValueError("case steps must reference all and only case evidence")
        if any(len(set(step.evidence_ids)) != len(step.evidence_ids) for step in self.steps):
            raise ValueError("step evidence identities must be unique")
        if any(
            not self.started_at <= item.observed_at <= self.completed_at for item in self.evidence
        ):
            raise ValueError("case evidence falls outside the case interval")
        if self.status is ResultStatus.PASSED and any(
            step.status is not ResultStatus.PASSED for step in self.steps
        ):
            raise ValueError("a passed case cannot contain a failed step")
        return self


CoreAcceptanceRunSpecV1.model_rebuild()
CoreAcceptanceCaseResultV1.model_rebuild()


def _run_inputs_sha256(spec: CoreAcceptanceRunSpecV1) -> str:
    """Bind every immutable run input without introducing a result-digest cycle."""

    projection: dict[str, RestrictedJson] = {
        "cases": cast(
            RestrictedJson,
            [item.model_dump(mode="json", exclude={"result"}) for item in spec.cases],
        ),
        "images": cast(
            RestrictedJson,
            [item.model_dump(mode="json") for item in spec.images],
        ),
        "maximum_total_cost_microusd": spec.maximum_total_cost_microusd,
        "maximum_total_duration_ms": spec.maximum_total_duration_ms,
        "policies": cast(
            RestrictedJson,
            [item.model_dump(mode="json") for item in spec.policies],
        ),
        "random_seed": spec.random_seed,
        "schema_version": "controlgraph.core-acceptance-run-inputs/v1",
        "source_commit": spec.source_commit,
        "target": cast(RestrictedJson, spec.target.model_dump(mode="json")),
        "terraform_plan": cast(
            RestrictedJson,
            spec.terraform_plan.model_dump(mode="json"),
        ),
        "test_clock": cast(RestrictedJson, spec.test_clock.model_dump(mode="json")),
    }
    return hashlib.sha256(canonical_json_value_bytes(projection)).hexdigest()


def _read_regular_file(path: Path, *, maximum_bytes: int, error_code: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AcceptanceError(error_code) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum_bytes:
            raise AcceptanceError(error_code)
        chunks: list[bytes] = []
        byte_count = 0
        while chunk := os.read(descriptor, min(65_536, maximum_bytes + 1 - byte_count)):
            chunks.append(chunk)
            byte_count += len(chunk)
            if byte_count > maximum_bytes:
                raise AcceptanceError(error_code)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or byte_count != before.st_size
        ):
            raise AcceptanceError(error_code)
        return b"".join(chunks)
    except OSError as error:
        raise AcceptanceError(error_code) from error
    finally:
        os.close(descriptor)


def _artifact_path(root: Path, relative_path: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative_path).parts)
    cursor = root
    try:
        for part in PurePosixPath(relative_path).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise AcceptanceError("ACCEPTANCE_ARTIFACT_INVALID")
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_INVALID") from error
    if not resolved.is_relative_to(root):
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_INVALID")
    return candidate


def _bind_artifact(
    binding: ArtifactBindingV1,
    *,
    artifact_root: Path,
    maximum_bytes: int = MAX_ARTIFACT_BYTES,
) -> tuple[bytes, dict[str, RestrictedJson]]:
    payload = _read_regular_file(
        _artifact_path(artifact_root, binding.relative_path),
        maximum_bytes=maximum_bytes,
        error_code="ACCEPTANCE_ARTIFACT_INVALID",
    )
    digest = hashlib.sha256(payload).hexdigest()
    if digest != binding.sha256:
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_DIGEST_MISMATCH")
    return payload, {
        "artifact_id": binding.artifact_id,
        "byte_count": len(payload),
        "media_type": binding.media_type,
        "sha256": digest,
    }


def _load_contract[ModelT: StrictContractModel](
    path: Path,
    model_type: type[ModelT],
    *,
    error_code: str,
) -> tuple[bytes, ModelT]:
    try:
        payload = _read_regular_file(
            path,
            maximum_bytes=MAX_CONTRACT_BYTES,
            error_code=error_code,
        )
        return payload, decode_contract(payload, model_type)
    except (ContractError, ValidationError, TypeError, ValueError) as error:
        if isinstance(error, AcceptanceError):
            raise
        raise AcceptanceError(error_code) from error


def _verify_source(repo: Path, expected_commit: str) -> None:
    try:
        root = repo.resolve(strict=True)
    except OSError as error:
        raise AcceptanceError("ACCEPTANCE_SOURCE_INVALID") from error
    if not root.is_dir():
        raise AcceptanceError("ACCEPTANCE_SOURCE_INVALID")

    def git(*arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ["git", "-C", str(root), *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AcceptanceError("ACCEPTANCE_SOURCE_INVALID") from error

    top = git("rev-parse", "--show-toplevel")
    head = git("rev-parse", "HEAD")
    dirty = git("status", "--porcelain=v1")
    if (
        top.returncode != 0
        or head.returncode != 0
        or dirty.returncode != 0
        or Path(top.stdout.strip()).resolve() != root
    ):
        raise AcceptanceError("ACCEPTANCE_SOURCE_INVALID")
    if head.stdout.strip() != expected_commit:
        raise AcceptanceError("ACCEPTANCE_SOURCE_MISMATCH")
    if dirty.stdout:
        raise AcceptanceError("ACCEPTANCE_SOURCE_DIRTY")
    expected_package = root / "backend" / "src" / "controlgraph_canary"
    expected_modules = (
        (controlgraph_canary, expected_package / "__init__.py"),
        (contract_base_module, expected_package / "contracts" / "base.py"),
        (contract_codec_module, expected_package / "contracts" / "codec.py"),
    )
    for module, expected_path in expected_modules:
        module_file = getattr(module, "__file__", None)
        try:
            loaded_path = Path(module_file).resolve(strict=True) if module_file else None
            pinned_path = expected_path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise AcceptanceError("ACCEPTANCE_SOURCE_MISMATCH") from error
        if loaded_path != pinned_path:
            raise AcceptanceError("ACCEPTANCE_SOURCE_MISMATCH")


def _manifest_case(
    binding: CaseBindingV1,
    result: CoreAcceptanceCaseResultV1,
    *,
    result_artifact: dict[str, RestrictedJson],
    artifact_root: Path,
    spec: CoreAcceptanceRunSpecV1,
    run_inputs_sha256: str,
) -> dict[str, RestrictedJson]:
    if (
        result.case_id != binding.case_id
        or result.kind is not binding.kind
        or result.source_commit != spec.source_commit
        or result.run_inputs_sha256 != run_inputs_sha256
        or result.target != spec.target
        or result.random_seed != binding.random_seed
        or result.test_clock_keys != binding.test_clock_keys
    ):
        raise AcceptanceError("ACCEPTANCE_CASE_BINDING_MISMATCH")
    if tuple(item.operation for item in result.steps) != ENTRY_POINTS[binding.kind]:
        raise AcceptanceError("ACCEPTANCE_CASE_BINDING_MISMATCH")
    if result.status is ResultStatus.PASSED and (
        result.observed_result != EXPECTED_RESULTS[binding.kind]
        or result.duration_ms > binding.maximum_duration_ms
        or result.cost_microusd > binding.maximum_cost_microusd
        or not REQUIRED_EVIDENCE[binding.kind].issubset(item.kind for item in result.evidence)
    ):
        raise AcceptanceError("ACCEPTANCE_CASE_RESULT_INVALID")

    evidence: list[RestrictedJson] = []
    for item in result.evidence:
        if item.run_inputs_sha256 != run_inputs_sha256:
            raise AcceptanceError("ACCEPTANCE_CASE_BINDING_MISMATCH")
        _, artifact = _bind_artifact(item.artifact, artifact_root=artifact_root)
        evidence.append(
            {
                "artifact": artifact,
                "evidence_id": item.evidence_id,
                "kind": item.kind.value,
                "observed_at": item.observed_at,
                "projection": item.projection.value,
            }
        )
    return {
        "case_id": binding.case_id,
        "completed_at": result.completed_at,
        "cost": {
            "basis": result.cost_basis.value,
            "maximum_microusd": binding.maximum_cost_microusd,
            "reported_microusd": result.cost_microusd,
        },
        "duration_ms": result.duration_ms,
        "entry_points": list(ENTRY_POINTS[binding.kind]),
        "evidence": evidence,
        "expected_result": EXPECTED_RESULTS[binding.kind],
        "execution_mode": result.execution_mode,
        "kind": binding.kind.value,
        "maximum_duration_ms": binding.maximum_duration_ms,
        "observed_result": result.observed_result,
        "random_seed": binding.random_seed,
        "result_artifact": result_artifact,
        "sequence": binding.sequence,
        "started_at": result.started_at,
        "status": result.status.value,
        "steps": cast(RestrictedJson, [item.model_dump(mode="json") for item in result.steps]),
        "test_clock_keys": list(binding.test_clock_keys),
    }


def build_manifest(
    *,
    spec_path: Path,
    artifact_root: Path,
) -> tuple[bytes, str, ResultStatus]:
    """Validate pinned hosted results and return one redacted canonical manifest."""

    spec_payload, spec = _load_contract(
        spec_path,
        CoreAcceptanceRunSpecV1,
        error_code="ACCEPTANCE_SPEC_INVALID",
    )
    try:
        root = artifact_root.resolve(strict=True)
    except OSError as error:
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_ROOT_INVALID") from error
    if artifact_root.is_symlink() or not root.is_dir():
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_ROOT_INVALID")
    _verify_source(Path(__file__).resolve().parents[1], spec.source_commit)
    run_inputs_sha256 = _run_inputs_sha256(spec)

    _, terraform_plan = _bind_artifact(spec.terraform_plan, artifact_root=root)
    policies: list[RestrictedJson] = []
    for policy in spec.policies:
        _, artifact = _bind_artifact(policy.artifact, artifact_root=root)
        policies.append(
            {
                "artifact": artifact,
                "policy_schema_version": policy.policy_schema_version,
            }
        )

    cases: list[dict[str, RestrictedJson]] = []
    result_records: list[CoreAcceptanceCaseResultV1] = []
    all_evidence_ids: set[str] = set()
    for binding in spec.cases:
        result_payload, result_artifact = _bind_artifact(
            binding.result,
            artifact_root=root,
            maximum_bytes=MAX_CONTRACT_BYTES,
        )
        try:
            result = decode_contract(result_payload, CoreAcceptanceCaseResultV1)
        except (ContractError, ValidationError, TypeError, ValueError) as error:
            raise AcceptanceError("ACCEPTANCE_CASE_RESULT_INVALID") from error
        case_evidence_ids = {item.evidence_id for item in result.evidence}
        if all_evidence_ids.intersection(case_evidence_ids):
            raise AcceptanceError("ACCEPTANCE_EVIDENCE_ID_REUSED")
        all_evidence_ids.update(case_evidence_ids)
        cases.append(
            _manifest_case(
                binding,
                result,
                result_artifact=result_artifact,
                artifact_root=root,
                spec=spec,
                run_inputs_sha256=run_inputs_sha256,
            )
        )
        result_records.append(result)

    if any(
        current.started_at < previous.completed_at
        for previous, current in pairwise(result_records)
    ):
        raise AcceptanceError("ACCEPTANCE_CASE_SEQUENCE_INVALID")

    total_duration_ms = sum(item.duration_ms for item in result_records)
    total_cost_microusd = sum(item.cost_microusd for item in result_records)
    passed = (
        all(item.status is ResultStatus.PASSED for item in result_records)
        and total_duration_ms <= spec.maximum_total_duration_ms
        and total_cost_microusd <= spec.maximum_total_cost_microusd
    )
    status_value = ResultStatus.PASSED if passed else ResultStatus.FAILED
    spec_sha256 = hashlib.sha256(spec_payload).hexdigest()
    run_id = f"cgacceptance:{spec_sha256}"
    manifest: dict[str, RestrictedJson] = {
        "cases": cast(RestrictedJson, cases),
        "completed_at": max(item.completed_at for item in result_records),
        "cost": {
            "basis": (
                CostBasis.MEASURED.value
                if all(item.cost_basis is CostBasis.MEASURED for item in result_records)
                else CostBasis.UPPER_BOUND.value
            ),
            "currency": "USD",
            "maximum_microusd": spec.maximum_total_cost_microusd,
            "reported_microusd": total_cost_microusd,
        },
        "duration_ms": total_duration_ms,
        "evidence_binding_complete": passed,
        "inputs": {
            "images": cast(
                RestrictedJson,
                [item.model_dump(mode="json") for item in spec.images],
            ),
            "policies": policies,
            "random_seed": spec.random_seed,
            "run_inputs_sha256": run_inputs_sha256,
            "source_commit": spec.source_commit,
            "target": cast(RestrictedJson, spec.target.model_dump(mode="json")),
            "terraform_plan": terraform_plan,
            "test_clock": cast(RestrictedJson, spec.test_clock.model_dump(mode="json")),
        },
        "maximum_duration_ms": spec.maximum_total_duration_ms,
        "run_id": run_id,
        "runner_mode": "EXPLICIT_HOSTED_EVIDENCE_BINDING",
        "schema_version": MANIFEST_SCHEMA,
        "spec_sha256": spec_sha256,
        "started_at": min(item.started_at for item in result_records),
        "status": status_value.value,
    }
    try:
        payload = canonical_json_value_bytes(cast(RestrictedJson, manifest))
    except ContractError as error:
        raise AcceptanceError("ACCEPTANCE_MANIFEST_INVALID") from error
    return payload, run_id, status_value


def _write_once(path: Path, payload: bytes) -> None:
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID") from error
    if not parent.is_dir() or path.exists() or path.is_symlink():
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        with suppress(OSError):
            path.unlink(missing_ok=True)
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID") from error


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlgraph-core-acceptance",
        description="Bind fixed hosted ControlGraph evidence into one redacted manifest.",
    )
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        payload, run_id, status_value = build_manifest(
            spec_path=args.spec,
            artifact_root=args.artifact_root,
        )
        _write_once(args.output, payload)
    except AcceptanceError as error:
        print('{"code":"' + error.code + '"}', file=sys.stderr)
        return 2
    print(
        canonical_json_value_bytes(
            {
                "manifest_sha256": hashlib.sha256(payload).hexdigest(),
                "run_id": run_id,
                "status": status_value.value,
            }
        ).decode("utf-8")
    )
    return 0 if status_value is ResultStatus.PASSED else 1


if __name__ == "__main__":
    raise SystemExit(main())
