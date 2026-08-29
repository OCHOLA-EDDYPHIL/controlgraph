"""Execute or bind one complete hosted core acceptance run."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Final, Literal, Self, cast

from pydantic import (
    AfterValidator,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

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
EXECUTE_CONFIRMATION: Final = "RUN_CONTROLGRAPH_CORE_ACCEPTANCE"
EXECUTE_CONFIRMATION_ENV: Final = "CONTROLGRAPH_CORE_ACCEPTANCE_CONFIRM"
_ZERO_SHA256: Final = "0" * 64
_API_ORIGIN = "https://controlgraph-api-{project_number}.us-central1.run.app"
_CONSOLE_ORIGIN = "https://controlgraph-console-{project_number}.us-central1.run.app"
_LOAD_JOB_PREFIX = "cg-m8-core-"
_LOAD_JOB_LABEL_KEY = "controlgraph-purpose"
_LOAD_JOB_LABEL = "m8-core-acceptance"
_LOAD_RESULT_SCHEMA = "controlgraph.core-acceptance-load-result/v1"
_LOAD_READY_SCHEMA = "controlgraph.core-acceptance-load-ready/v1"
_TIMELINE_PAGE_SET_DOMAIN = b"controlgraph.timeline-acceptance-page-set/v1\0"
_STALE_COMPLETION_READINESS_ATTEMPTS: Final = 30
_STALE_COMPLETION_READINESS_DELAY_SECONDS: Final = 1.0
_LOAD_JOB_PERMISSIONS = (
    "iam.serviceAccounts.actAs",
    "logging.logEntries.list",
    "run.executions.list",
    "run.jobs.create",
    "run.jobs.delete",
    "run.jobs.get",
    "run.jobs.list",
    "run.jobs.run",
)

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
    VERIFIED_CAPABILITY_METADATA = "VERIFIED_CAPABILITY_METADATA"
    EXECUTOR_EPOCH_CHECK = "EXECUTOR_EPOCH_CHECK"
    EXECUTION_RECEIPT = "EXECUTION_RECEIPT"
    HEALTH_DECISION = "HEALTH_DECISION"
    RECOVERY_SERVICE_IDENTITY_BINDING = "RECOVERY_SERVICE_IDENTITY_BINDING"
    AUTHORITY_TRANSITION = "AUTHORITY_TRANSITION"
    STALE_DENIAL = "STALE_DENIAL"
    INDEPENDENT_VERIFICATION = "INDEPENDENT_VERIFICATION"
    AMBIGUITY_CLASSIFICATION = "AMBIGUITY_CLASSIFICATION"
    TIMELINE = "TIMELINE"
    CONSOLE_READ = "CONSOLE_READ"
    COORDINATOR = "COORDINATOR"
    MODEL_AUDIT = "MODEL_AUDIT"
    PUBLIC_REPLAY_SEED = "PUBLIC_REPLAY_SEED"
    RUNNER_FAILURE = "RUNNER_FAILURE"


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
            EvidenceKind.VERIFIED_CAPABILITY_METADATA,
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
            EvidenceKind.VERIFIED_CAPABILITY_METADATA,
            EvidenceKind.EXECUTOR_EPOCH_CHECK,
            EvidenceKind.EXECUTION_RECEIPT,
            EvidenceKind.HEALTH_DECISION,
            EvidenceKind.RECOVERY_SERVICE_IDENTITY_BINDING,
            EvidenceKind.TIMELINE,
        }
    ),
    CaseKind.REVOCATION_STALE_DENIAL: frozenset(
        {
            EvidenceKind.AUTHORITY_TRANSITION,
            EvidenceKind.CLOUD_RUN_CONFIGURATION,
            EvidenceKind.DATA_PATH_PROBE,
            EvidenceKind.VERIFIED_CAPABILITY_METADATA,
            EvidenceKind.EXECUTOR_EPOCH_CHECK,
            EvidenceKind.STALE_DENIAL,
            EvidenceKind.EXECUTION_RECEIPT,
            EvidenceKind.COORDINATOR,
            EvidenceKind.MODEL_AUDIT,
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
    CaseKind.TIMELINE_CONSOLE_READ: frozenset(
        {
            EvidenceKind.CLOUD_RUN_CONFIGURATION,
            EvidenceKind.TIMELINE,
            EvidenceKind.CONSOLE_READ,
        }
    ),
    CaseKind.BOUNDED_ADVISOR: frozenset(
        {
            EvidenceKind.CLOUD_RUN_CONFIGURATION,
            EvidenceKind.COORDINATOR,
            EvidenceKind.MODEL_AUDIT,
            EvidenceKind.PUBLIC_REPLAY_SEED,
            EvidenceKind.TIMELINE,
        }
    ),
}

ENTRY_POINTS: Final[dict[CaseKind, tuple[str, ...]]] = {
    CaseKind.TARGET_RESET: (
        "runner:reset-reference-target",
        "runner:verify-stable-data-path",
    ),
    CaseKind.HEALTHY_PROMOTION: (
        "runner:reset-reference-target",
        "runner:observe-healthy-promotion",
    ),
    CaseKind.UNHEALTHY_STABLE_RECOVERY: (
        "runner:reset-reference-target",
        "runner:observe-unhealthy-stable-recovery",
    ),
    CaseKind.REVOCATION_STALE_DENIAL: (
        "runner:reset-reference-target",
        "runner:observe-revocation-stale-denial",
    ),
    CaseKind.INDEPENDENT_VERIFIER_PROBE: (
        "runner:reset-reference-target",
        "runner:observe-independent-verification",
    ),
    CaseKind.AMBIGUITY_CLASSIFICATION: (
        "runner:reset-reference-target",
        "runner:observe-ambiguity-classification",
    ),
    CaseKind.TIMELINE_CONSOLE_READ: (
        "runner:reset-reference-target",
        "runner:observe-timeline-console",
    ),
    CaseKind.BOUNDED_ADVISOR: (
        "runner:reset-reference-target",
        "runner:observe-bounded-advisor",
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
    environment: Literal["nonprod"]
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
                datetime.strptime(self.completed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
                - datetime.strptime(self.started_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
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
        evidence_payload, artifact = _bind_artifact(item.artifact, artifact_root=artifact_root)
        _validate_observation_artifact(
            evidence_payload,
            binding=binding,
            evidence=item,
            run_inputs_sha256=run_inputs_sha256,
        )
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


def _evidence_source_schema(kind: EvidenceKind) -> str:
    return f"controlgraph.hosted-evidence-{kind.value.lower().replace('_', '-')}/v1"


def _validate_observation_artifact(
    payload: bytes,
    *,
    binding: CaseBindingV1,
    evidence: EvidenceBindingV1,
    run_inputs_sha256: str,
) -> None:
    try:
        observation = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("ACCEPTANCE_EVIDENCE_INVALID") from error
    if not isinstance(observation, dict):
        raise AcceptanceError("ACCEPTANCE_EVIDENCE_INVALID")
    source = observation.get("source")
    if (
        observation.get("schema_version") != "controlgraph.hosted-acceptance-observation/v1"
        or observation.get("case_id") != binding.case_id
        or observation.get("evidence_id") != evidence.evidence_id
        or observation.get("kind") != evidence.kind.value
        or observation.get("observed_at") != evidence.observed_at
        or observation.get("run_inputs_sha256") != run_inputs_sha256
        or not isinstance(source, dict)
        or source.get("schema_version") != _evidence_source_schema(evidence.kind)
        or "observation" not in source
    ):
        raise AcceptanceError("ACCEPTANCE_EVIDENCE_INVALID")


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
        current.started_at < previous.completed_at for previous, current in pairwise(result_records)
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


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise AcceptanceError("ACCEPTANCE_HOSTED_TIME_INVALID")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID") from error


def _stable_id(run_inputs_sha256: str, case: CaseBindingV1, label: str) -> str:
    digest = hashlib.sha256(
        f"{run_inputs_sha256}\0{case.case_id}\0{label}".encode("ascii")
    ).hexdigest()
    return f"cgm8-{label}-{digest[:24]}"


def _model_dict(value: Any) -> dict[str, Any]:
    dumped = value.model_dump(mode="json")
    if not isinstance(dumped, dict):
        raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID")
    return cast(dict[str, Any], dumped)


def _canonical_object(value: object) -> bytes:
    try:
        return canonical_json_value_bytes(cast(RestrictedJson, value))
    except (ContractError, TypeError, ValueError) as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID") from error


def _process_environment(repo: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(repo / "backend" / "src")
    return environment


def _capture_process(
    argv: Sequence[str],
    *,
    repo: Path,
    timeout: int = 180,
    allowed_statuses: frozenset[int] = frozenset({0}),
) -> tuple[int, bytes]:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=repo / "backend",
            env=_process_environment(repo),
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_COMMAND_UNAVAILABLE") from error
    if completed.returncode not in allowed_statuses:
        raise AcceptanceError("ACCEPTANCE_HOSTED_COMMAND_FAILED")
    return completed.returncode, completed.stdout


def _cli_argv(repo: Path, entry_point: str, arguments: Sequence[str]) -> tuple[str, ...]:
    if entry_point == "controlgraph-canary":
        return (sys.executable, "-m", "controlgraph_canary", *arguments)
    if entry_point == "controlgraph-reference-target-reset":
        invocation = (
            "from controlgraph_canary.reference_target_reset_cli import main;"
            "raise SystemExit(main())"
        )
        return (sys.executable, "-c", invocation, *arguments)
    raise AcceptanceError("ACCEPTANCE_HOSTED_COMMAND_INVALID")


def _run_cli(
    *,
    repo: Path,
    entry_point: str,
    arguments: Sequence[str],
    model_type: type[Any] | None = None,
    timeout: int = 180,
    allowed_statuses: frozenset[int] = frozenset({0}),
) -> tuple[int, dict[str, Any], Any | None]:
    status, payload = _capture_process(
        _cli_argv(repo, entry_point, arguments),
        repo=repo,
        timeout=timeout,
        allowed_statuses=allowed_statuses,
    )
    if not 0 < len(payload) <= MAX_CONTRACT_BYTES:
        raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID")
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID") from error
    if not isinstance(decoded, dict):
        raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID")
    model = None
    if status == 0 and model_type is not None:
        try:
            model = model_type.model_validate_json(payload)
        except (TypeError, ValueError, ValidationError) as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID") from error
        decoded = _model_dict(model)
    return status, cast(dict[str, Any], decoded), model


def _gcloud_json(
    arguments: Sequence[str],
    *,
    repo: Path,
    timeout: int = 180,
) -> Any:
    _, payload = _capture_process(
        ("gcloud", *arguments, "--format=json"),
        repo=repo,
        timeout=timeout,
    )
    if not 0 < len(payload) <= MAX_ARTIFACT_BYTES:
        raise AcceptanceError("ACCEPTANCE_HOSTED_CLOUD_RESPONSE_INVALID")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_CLOUD_RESPONSE_INVALID") from error


def _write_command(path: Path, command: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_once(path, _canonical_object(_model_dict(command)))


def _traffic_percentages(result: Any) -> dict[str, int]:
    traffic = {(item.revision, item.percent) for item in result.traffic}
    statuses = {(item.revision, item.percent) for item in result.traffic_statuses}
    if traffic != statuses:
        raise AcceptanceError("ACCEPTANCE_HOSTED_TRAFFIC_INVALID")
    return dict(traffic)


def _require_target(result: Any, spec: CoreAcceptanceRunSpecV1) -> None:
    request = result.request
    if (
        request.target.project_id != spec.target.project_id
        or request.target.region != spec.target.region
        or request.target.environment != spec.target.environment
        or request.target.service_name != spec.target.service_name
        or request.stable_revision != spec.target.stable_revision
        or request.candidate_revision != spec.target.candidate_revision
        or result.concurrency != 8
        or result.observed_by
        != f"controlgraph-verifier@{spec.target.project_id}.iam.gserviceaccount.com"
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_TARGET_MISMATCH")


def _require_split(
    result: Any,
    spec: CoreAcceptanceRunSpecV1,
    *,
    stable: int,
    candidate: int,
) -> None:
    _require_target(result, spec)
    traffic = _traffic_percentages(result)
    if (
        set(traffic).difference({spec.target.stable_revision, spec.target.candidate_revision})
        or traffic.get(spec.target.stable_revision, 0) != stable
        or traffic.get(spec.target.candidate_revision, 0) != candidate
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_TRAFFIC_INVALID")


def _image(spec: CoreAcceptanceRunSpecV1, component: ImageComponent) -> str:
    return next(item.reference for item in spec.images if item.component is component)


@dataclass(slots=True)
class _HostedExecution:
    repo: Path
    artifact_root: Path
    spec: CoreAcceptanceRunSpecV1
    run_inputs_sha256: str
    project_number: str
    network_resource: str
    subnetwork_resource: str
    verifier_service_account: str
    restricted_exporter_service_account: str
    acceptance_identity: str
    root_ids: set[str] = field(default_factory=set)
    unreleased_root_ids: set[str] = field(default_factory=set)
    service_bindings: dict[str, dict[str, str]] = field(default_factory=dict)
    revocation_root: Any | None = None
    revocation_epoch: int | None = None
    advisor_command: Any | None = None
    advisor_result: Any | None = None
    public_replay_seed_values: _PublicReplaySeedState | None = None
    execution_queue_cleanup_required: bool = False

    @property
    def api_origin(self) -> str:
        return _API_ORIGIN.format(project_number=self.project_number)

    @property
    def console_origin(self) -> str:
        return _CONSOLE_ORIGIN.format(project_number=self.project_number)

    def command_path(self, case: CaseBindingV1, label: str) -> Path:
        return self.artifact_root / "commands" / f"{case.sequence:02d}-{label}.json"


@dataclass(frozen=True, slots=True)
class _CaseOutcome:
    observations: Mapping[EvidenceKind, object]
    terminal_result: str


@dataclass(frozen=True, slots=True)
class _PublicReplaySeedState:
    authority_occurred_at: str
    denial_occurred_at: str
    unchanged_observed_at: str
    advisor_requested_at: str
    recovery_occurred_at: str
    authority: Any
    denial: Any
    unchanged: Any
    recovery: Any
    advisor_causal_path_clause: str


def _read_traffic(run: _HostedExecution, case: CaseBindingV1, label: str) -> Any:
    from controlgraph_canary.contracts.operator_observability import (
        TargetTrafficReadResultV1,
    )

    _, _, model = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "read-target-traffic",
            "--project-number",
            run.project_number,
            "--request-id",
            _stable_id(run.run_inputs_sha256, case, f"traffic-{label}"),
        ),
        model_type=TargetTrafficReadResultV1,
    )
    assert model is not None
    _require_target(model, run.spec)
    return model


def _reset_target(run: _HostedExecution, case: CaseBindingV1) -> Any:
    before = _read_traffic(run, case, "before-reset")
    _, reset, _ = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-reference-target-reset",
        arguments=(
            "--project-id",
            run.spec.target.project_id,
            "--stable-image",
            _image(run.spec, ImageComponent.REFERENCE_STABLE),
            "--candidate-image",
            _image(run.spec, ImageComponent.REFERENCE_CANDIDATE),
            "--network-resource",
            run.network_resource,
            "--subnetwork-resource",
            run.subnetwork_resource,
            "--expected-etag",
            before.provider_etag,
            "--confirm",
            "RESET_REFERENCE_TARGET_BASELINE",
        ),
        timeout=300,
    )
    after = _read_traffic(run, case, "after-reset")
    _require_split(after, run.spec, stable=100, candidate=0)
    if (
        reset.get("project_id") != run.spec.target.project_id
        or reset.get("region") != run.spec.target.region
        or reset.get("service_name") != run.spec.target.service_name
        or reset.get("stable_revision") != run.spec.target.stable_revision
        or reset.get("candidate_revision") != run.spec.target.candidate_revision
        or reset.get("stable_image") != _image(run.spec, ImageComponent.REFERENCE_STABLE)
        or reset.get("candidate_image") != _image(run.spec, ImageComponent.REFERENCE_CANDIDATE)
        or reset.get("stable_percent") != 100
        or reset.get("candidate_percent") != 0
        or reset.get("observed_etag") != after.provider_etag
        or reset.get("observed_generation") != after.service_generation
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_RESET_INVALID")
    return after


def _submit_root_creation(run: _HostedExecution, command_path: Path) -> Any:
    from controlgraph_canary.contracts.root_creation import RootCreationResultV2

    saw_unknown_outcome = False
    for attempt in range(3):
        status, payload, result = _run_cli(
            repo=run.repo,
            entry_point="controlgraph-canary",
            arguments=(
                "create-rollout-root",
                "--project-number",
                run.project_number,
                "--command-file",
                str(command_path),
            ),
            model_type=RootCreationResultV2,
            allowed_statuses=frozenset({0, 4}),
        )
        if status == 0 and result is not None:
            if result.outcome == "CREATED" or (saw_unknown_outcome and result.outcome == "ADOPTED"):
                return result
            raise AcceptanceError("ACCEPTANCE_HOSTED_ROOT_INVALID")
        if payload != {"code": "ROOT_CREATION_OUTCOME_UNKNOWN"}:
            raise AcceptanceError("ACCEPTANCE_HOSTED_ROOT_INVALID")
        saw_unknown_outcome = True
        if attempt < 2:
            time.sleep(1)
    raise AcceptanceError("ACCEPTANCE_HOSTED_ROOT_AMBIGUOUS")


def _create_root(run: _HostedExecution, case: CaseBindingV1) -> Any:
    from controlgraph_canary.contracts.codec import canonical_json_bytes
    from controlgraph_canary.contracts.operator_observability import (
        StableSnapshotCaptureResultV1,
    )
    from controlgraph_canary.contracts.root_creation import (
        ROOT_CREATION_COMMAND_V1,
        RootCreationCommandV1,
    )

    _, _, snapshot = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "capture-stable-snapshot",
            "--project-number",
            run.project_number,
            "--request-id",
            _stable_id(run.run_inputs_sha256, case, "snapshot"),
        ),
        model_type=StableSnapshotCaptureResultV1,
    )
    assert snapshot is not None
    if (
        snapshot.request.target.project_id != run.spec.target.project_id
        or snapshot.request.target.region != run.spec.target.region
        or snapshot.request.target.service_name != run.spec.target.service_name
        or snapshot.snapshot.stable_revision != run.spec.target.stable_revision
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_SNAPSHOT_INVALID")
    command = RootCreationCommandV1(
        schema_version=ROOT_CREATION_COMMAND_V1,
        request_id=_stable_id(run.run_inputs_sha256, case, "root-request"),
        idempotency_key=_stable_id(run.run_inputs_sha256, case, "root-idempotency"),
        expected_stable_snapshot=snapshot.snapshot,
    )
    command_path = run.command_path(case, "root")
    _write_command(command_path, command)
    root_result = _submit_root_creation(run, command_path)
    root = root_result.root
    plan = root.content.rollout_plan
    policy_bindings = tuple(
        item
        for item in run.spec.policies
        if item.policy_schema_version == root.content.health_policy.schema_version
    )
    if (
        root.content.target.project_id != run.spec.target.project_id
        or root.content.target.region != run.spec.target.region
        or root.content.target.environment != run.spec.target.environment
        or root.content.target.service_name != run.spec.target.service_name
        or plan.stable_revision != run.spec.target.stable_revision
        or plan.candidate_revision != run.spec.target.candidate_revision
        or plan.stable_percent != 90
        or plan.candidate_percent != 10
        or plan.concurrency != 8
        or root_result.initial_authority.current_epoch != 1
        or len(policy_bindings) != 1
        or policy_bindings[0].artifact.sha256
        != hashlib.sha256(canonical_json_bytes(root.content.health_policy)).hexdigest()
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_ROOT_INVALID")
    return root_result


def _poll_receipt(
    run: _HostedExecution,
    case: CaseBindingV1,
    *,
    root: Any,
    epoch: int,
    request_id: str,
    idempotency_key: str,
    action: str,
    capability_sha256: str,
    label: str,
) -> Any:
    from controlgraph_canary.contracts.operator_observability import (
        ExecutionReceiptReadResultV1,
    )

    for _attempt in range(90):
        status, payload, model = _run_cli(
            repo=run.repo,
            entry_point="controlgraph-canary",
            arguments=(
                "read-execution-receipt",
                "--project-number",
                run.project_number,
                "--root-id",
                root.root_id,
                "--expected-root-sha256",
                root.root_sha256,
                "--expected-epoch",
                str(epoch),
                "--request-id",
                request_id,
                "--idempotency-key",
                idempotency_key,
                "--action",
                action,
                "--capability-sha256",
                capability_sha256,
            ),
            model_type=ExecutionReceiptReadResultV1,
            allowed_statuses=frozenset({0, 4, 5}),
        )
        if (
            status == 0
            and model is not None
            and model.receipt.outcome.value
            not in {
                "CLAIMED",
                "APPLIED",
            }
        ):
            return model
        if status != 0 and payload.get("code") not in {
            "EXECUTION_RECEIPT_NOT_FOUND",
            "EXECUTION_RECEIPT_OUTCOME_UNKNOWN",
            "RECEIPT_READ_OUTCOME_UNKNOWN",
            "RECEIPT_READ_AUTH_UNAVAILABLE",
        }:
            raise AcceptanceError("ACCEPTANCE_HOSTED_RECEIPT_INVALID")
        time.sleep(2)
    raise AcceptanceError(f"ACCEPTANCE_HOSTED_{label.upper()}_RECEIPT_TIMEOUT")


_REMOTE_LOAD_SCRIPT: Final = r"""from __future__ import annotations
import concurrent.futures
import datetime
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

RESULT = "controlgraph.core-acceptance-load-result/v1"
READY = "controlgraph.core-acceptance-load-ready/v1"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None

OPENER = urllib.request.build_opener(NoRedirect)

def utc(value):
    return (
        value.astimezone(datetime.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )

def emit(value):
    print(json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True), flush=True)

def token(audience):
    url = (
        "http://metadata.google.internal/computeMetadata/v1/instance/"
        "service-accounts/default/identity?audience="
        + urllib.parse.quote(audience, safe="")
    )
    request = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
    with OPENER.open(request, timeout=10) as response:
        value = response.read(16384).decode("ascii").strip()
    if value.count(".") != 2:
        raise RuntimeError("identity-token-envelope")
    return value

def one(url, credential, mode, expected_revision, timeout_seconds=5):
    code = 0
    body = b""
    for attempt in range(3):
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": "Bearer " + credential,
                "User-Agent": "controlgraph-m8-core/1",
            },
        )
        try:
            with OPENER.open(request, timeout=timeout_seconds) as response:
                code = response.status
                body = response.read(4096)
            break
        except urllib.error.HTTPError as error:
            code = error.code
            body = error.read(4096)
            break
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            if attempt == 2:
                raise
            time.sleep(0.75)
    if mode in {"probe-stable", "healthy"}:
        marker = "controlgraph-stable-v1" if mode == "probe-stable" else "controlgraph-candidate-v1"
        try:
            accepted = code == 200 and json.loads(body) == {
                "marker": marker,
                "revision": expected_revision,
                "schema_version": "controlgraph.reference-probe/v1",
            }
        except Exception:
            accepted = False
    else:
        accepted = code == 404
    return code, accepted

def main():
    audience = os.environ["CG_AUDIENCE"]
    destination = os.environ["CG_DESTINATION"]
    mode = os.environ["CG_MODE"]
    expected_revision = os.environ["CG_EXPECTED_REVISION"]
    started = time.time()
    credential = token(audience)
    acquired = time.time()
    if mode == "probe-stable":
        code, accepted = one(destination, credential, mode, expected_revision, 20)
        credential = ""
        emit({
            "accepted": accepted,
            "mode": mode,
            "request_count": 1,
            "response_codes": [{"code": int(code), "count": 1}],
            "schema_version": RESULT,
            "started_at": utc(datetime.datetime.fromtimestamp(
                started, datetime.timezone.utc
            )),
            "status": "COMPLETE" if accepted else "FAILED",
            "token_persisted": False,
            "windows": [],
        })
        return 0 if accepted else 3
    if mode not in {"healthy", "unhealthy"}:
        raise RuntimeError("mode")
    anchor_text = os.environ["CG_ANCHOR"]
    anchor = (
        datetime.datetime.strptime(anchor_text, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=datetime.timezone.utc)
        .timestamp()
    )
    emit({
        "anchor": anchor_text,
        "mode": mode,
        "schema_version": READY,
        "started_at": utc(datetime.datetime.fromtimestamp(
            started, datetime.timezone.utc
        )),
        "status": "READY",
        "token_acquired_at": utc(datetime.datetime.fromtimestamp(
            acquired, datetime.timezone.utc
        )),
        "token_persisted": False,
    })
    if acquired > anchor + 15:
        credential = ""
        emit({
            "anchor": anchor_text,
            "mode": mode,
            "schema_version": RESULT,
            "status": "LATE_START",
            "token_persisted": False,
            "windows": [],
        })
        return 2
    windows = []
    for index in (0, 1, 2):
        window_start = anchor + index * 60
        while time.time() < window_start + 2:
            time.sleep(min(0.25, window_start + 2 - time.time()))
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for ordinal in range(120):
                due = window_start + 2 + ordinal * 0.32
                while time.time() < due:
                    time.sleep(min(0.05, due - time.time()))
                if time.time() >= window_start + 55:
                    break
                futures.append(pool.submit(one, destination, credential, mode, expected_revision))
            results = [future.result(timeout=8) for future in futures]
        codes = {}
        accepted = 0
        for code, good in results:
            codes[int(code)] = codes.get(int(code), 0) + 1
            accepted += int(good)
        windows.append({
            "accepted": accepted,
            "ended_at": utc(datetime.datetime.fromtimestamp(
                window_start + 60, datetime.timezone.utc
            )),
            "response_codes": [
                {"code": code, "count": count} for code, count in sorted(codes.items())
            ],
            "started_at": utc(datetime.datetime.fromtimestamp(
                window_start, datetime.timezone.utc
            )),
            "submitted": len(results),
            "window_index": index + 1,
        })
    credential = ""
    ok = len(windows) == 3 and all(item["submitted"] >= 100 for item in windows)
    emit({
        "anchor": anchor_text,
        "mode": mode,
        "request_count": sum(item["submitted"] for item in windows),
        "schema_version": RESULT,
        "started_at": utc(datetime.datetime.fromtimestamp(
            started, datetime.timezone.utc
        )),
        "status": "COMPLETE" if ok else "FAILED",
        "token_persisted": False,
        "windows": windows,
    })
    return 0 if ok else 3

try:
    raise SystemExit(main())
except Exception as error:
    emit({
        "failure": type(error).__name__,
        "schema_version": RESULT,
        "status": "FAILED",
        "token_persisted": False,
        "windows": [],
    })
    raise SystemExit(4)
"""


def _walk_tagged_url(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        candidate = value.get("uri", value.get("url"))
        if value.get("tag") == "candidate" and isinstance(candidate, str):
            found.append(candidate)
        for nested in value.values():
            found.extend(_walk_tagged_url(nested))
    elif isinstance(value, list):
        for nested in value:
            found.extend(_walk_tagged_url(nested))
    return found


def _reference_urls(run: _HostedExecution) -> tuple[str, str]:
    document = _gcloud_json(
        (
            "run",
            "services",
            "describe",
            run.spec.target.service_name,
            f"--project={run.spec.target.project_id}",
            f"--region={run.spec.target.region}",
        ),
        repo=run.repo,
    )
    if not isinstance(document, dict):
        raise AcceptanceError("ACCEPTANCE_HOSTED_TARGET_MISMATCH")
    status = document.get("status")
    base = status.get("url") if isinstance(status, dict) else None
    tagged = sorted(set(_walk_tagged_url(document)))
    if (
        not isinstance(base, str)
        or not base.startswith("https://controlgraph-reference-target-")
        or len(tagged) != 1
        or not tagged[0].startswith("https://candidate---controlgraph-reference-target-")
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_TARGET_MISMATCH")
    return base.rstrip("/"), tagged[0].rstrip("/")


def _job_name(run: _HostedExecution, case: CaseBindingV1, mode: str) -> str:
    suffix = hashlib.sha256(
        f"{run.run_inputs_sha256}\0{case.case_id}\0{mode}".encode("ascii")
    ).hexdigest()[:12]
    return f"{_LOAD_JOB_PREFIX}{mode[0]}-{suffix}"


def _job_executions(run: _HostedExecution, job_name: str) -> dict[str, str]:
    values = _gcloud_json(
        (
            "run",
            "jobs",
            "executions",
            "list",
            f"--job={job_name}",
            f"--project={run.spec.target.project_id}",
            f"--region={run.spec.target.region}",
        ),
        repo=run.repo,
    )
    if not isinstance(values, list):
        raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
    result: dict[str, str] = {}
    for value in values:
        if not isinstance(value, dict):
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
        metadata = value.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else value
        name = metadata.get("name")
        created_at = metadata.get("creationTimestamp", value.get("createTime"))
        if isinstance(name, str) and isinstance(created_at, str):
            result[name.rsplit("/", 1)[-1]] = created_at
    return result


def _load_job_names(run: _HostedExecution) -> frozenset[str]:
    values = _gcloud_json(
        (
            "run",
            "jobs",
            "list",
            f"--project={run.spec.target.project_id}",
            f"--region={run.spec.target.region}",
            f"--filter=metadata.labels.{_LOAD_JOB_LABEL_KEY}={_LOAD_JOB_LABEL}",
        ),
        repo=run.repo,
    )
    if not isinstance(values, list):
        raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
    names: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
        metadata = value.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else value
        name = metadata.get("name")
        if isinstance(name, str):
            names.add(name.rsplit("/", 1)[-1])
    return frozenset(names)


def _load_log_record(
    run: _HostedExecution,
    execution_name: str,
    schema_version: str,
    *,
    attempts: int,
) -> dict[str, Any]:
    query = (
        'log_id("run.googleapis.com/stdout") AND resource.type="cloud_run_job" AND '
        f'labels."run.googleapis.com/execution_name"="{execution_name}"'
    )
    for _attempt in range(attempts):
        values = _gcloud_json(
            (
                "logging",
                "read",
                query,
                f"--project={run.spec.target.project_id}",
                "--limit=20",
                "--order=asc",
            ),
            repo=run.repo,
        )
        matches: list[dict[str, Any]] = []
        if isinstance(values, list):
            for entry in values:
                if not isinstance(entry, dict):
                    continue
                candidate = entry.get("jsonPayload")
                if not isinstance(candidate, dict):
                    text_payload = entry.get("textPayload")
                    if isinstance(text_payload, str):
                        with suppress(json.JSONDecodeError):
                            parsed = json.loads(text_payload)
                            candidate = parsed if isinstance(parsed, dict) else None
                if (
                    isinstance(candidate, dict)
                    and candidate.get("schema_version") == schema_version
                ):
                    matches.append(cast(dict[str, Any], candidate))
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
        time.sleep(2)
    raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_TIMEOUT")


def _create_load_job(
    run: _HostedExecution,
    case: CaseBindingV1,
    *,
    mode: str,
    destination: str,
    audience: str,
    expected_revision: str,
) -> str:
    job_name = _job_name(run, case, mode)
    if job_name in _load_job_names(run):
        raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_ALREADY_EXISTS")
    bootstrap = (
        "import base64;exec(base64.b64decode('"
        + base64.b64encode(_REMOTE_LOAD_SCRIPT.encode("utf-8")).decode("ascii")
        + "'))"
    )
    environment = (
        f"CG_AUDIENCE={audience},CG_DESTINATION={destination},CG_MODE={mode},"
        f"CG_EXPECTED_REVISION={expected_revision}"
    )
    try:
        _capture_process(
            (
                "gcloud",
                "run",
                "jobs",
                "create",
                job_name,
                f"--project={run.spec.target.project_id}",
                f"--region={run.spec.target.region}",
                f"--image={_image(run.spec, ImageComponent.CONTROLLER)}",
                f"--service-account={run.verifier_service_account}",
                "--command=/app/.venv/bin/python",
                f"--args=-c,{bootstrap}",
                f"--set-env-vars={environment}",
                "--tasks=1",
                "--parallelism=1",
                "--max-retries=0",
                "--task-timeout=600s",
                "--cpu=1",
                "--memory=512Mi",
                f"--network={run.network_resource}",
                f"--subnet={run.subnetwork_resource}",
                "--vpc-egress=all-traffic",
                f"--labels={_LOAD_JOB_LABEL_KEY}={_LOAD_JOB_LABEL}",
                "--quiet",
                "--format=none",
            ),
            repo=run.repo,
            timeout=300,
        )
        described = _gcloud_json(
            (
                "run",
                "jobs",
                "describe",
                job_name,
                f"--project={run.spec.target.project_id}",
                f"--region={run.spec.target.region}",
            ),
            repo=run.repo,
        )
        if not isinstance(described, dict):
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
        specification = described.get("spec")
        execution_template = (
            specification.get("template") if isinstance(specification, dict) else None
        )
        template_metadata = (
            execution_template.get("metadata") if isinstance(execution_template, dict) else None
        )
        template_spec = (
            execution_template.get("spec") if isinstance(execution_template, dict) else None
        )
        task_envelope = template_spec.get("template") if isinstance(template_spec, dict) else None
        containers: Any = None
        service_account: Any = None
        for task_source in (
            task_envelope,
            task_envelope.get("spec") if isinstance(task_envelope, dict) else None,
        ):
            if not isinstance(task_source, dict):
                continue
            if isinstance(task_source.get("containers"), list):
                containers = task_source["containers"]
            if "serviceAccountName" in task_source:
                service_account = task_source.get("serviceAccountName")
        deployed_images = (
            tuple(
                container.get("image")
                for container in containers
                if isinstance(container, dict) and isinstance(container.get("image"), str)
            )
            if containers is not None
            else ()
        )
        labels_match = True
        for label_source in (template_metadata, described.get("metadata")):
            values = label_source.get("labels") if isinstance(label_source, dict) else None
            if not isinstance(values, dict) or values.get(_LOAD_JOB_LABEL_KEY) != _LOAD_JOB_LABEL:
                labels_match = False
        if (
            deployed_images != (_image(run.spec, ImageComponent.CONTROLLER),)
            or service_account != run.verifier_service_account
            or not labels_match
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
    except AcceptanceError:
        if job_name in _load_job_names(run):
            try:
                _delete_load_job(run, job_name)
            except AcceptanceError as cleanup_error:
                raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_CLEANUP_FAILED") from cleanup_error
        raise
    return job_name


def _delete_load_job(run: _HostedExecution, job_name: str) -> None:
    if (
        not job_name.startswith(_LOAD_JOB_PREFIX)
        or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", job_name) is None
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
    _capture_process(
        (
            "gcloud",
            "run",
            "jobs",
            "delete",
            job_name,
            f"--project={run.spec.target.project_id}",
            f"--region={run.spec.target.region}",
            "--quiet",
            "--format=none",
        ),
        repo=run.repo,
        timeout=300,
    )
    for _attempt in range(30):
        if job_name not in _load_job_names(run):
            return
        time.sleep(1)
    raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_CLEANUP_FAILED")


def _execute_job(
    run: _HostedExecution,
    job_name: str,
    *,
    asynchronous: bool,
    anchor: datetime | None = None,
) -> str:
    before = _job_executions(run, job_name)
    arguments = [
        "gcloud",
        "run",
        "jobs",
        "execute",
        job_name,
        f"--project={run.spec.target.project_id}",
        f"--region={run.spec.target.region}",
    ]
    if anchor is not None:
        arguments.append(f"--update-env-vars=CG_ANCHOR={_utc(anchor)}")
    arguments.extend(("--async" if asynchronous else "--wait", "--quiet", "--format=none"))
    _capture_process(arguments, repo=run.repo, timeout=900)
    for _attempt in range(30):
        after = _job_executions(run, job_name)
        created = sorted(set(after).difference(before))
        if len(created) == 1:
            return created[0]
        if len(created) > 1:
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
        time.sleep(2)
    raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_TIMEOUT")


def _probe_stable(run: _HostedExecution, case: CaseBindingV1) -> dict[str, Any]:
    audience, _candidate = _reference_urls(run)
    job_name = _create_load_job(
        run,
        case,
        mode="probe-stable",
        destination=f"{audience}/v1/probe",
        audience=audience,
        expected_revision=run.spec.target.stable_revision,
    )
    try:
        execution = _execute_job(run, job_name, asynchronous=False)
        result = _load_log_record(run, execution, _LOAD_RESULT_SCHEMA, attempts=15)
        if (
            result.get("status") != "COMPLETE"
            or result.get("mode") != "probe-stable"
            or result.get("accepted") is not True
            or result.get("request_count") != 1
            or result.get("token_persisted") is not False
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_PROBE_INVALID")
        return result
    finally:
        _delete_load_job(run, job_name)


def _apply_canary(run: _HostedExecution, case: CaseBindingV1, root_result: Any) -> tuple[Any, Any]:
    from controlgraph_canary.contracts.canary_execution import CanaryDispatchResultV1

    root = root_result.root
    request_id = _stable_id(run.run_inputs_sha256, case, "apply-request")
    idempotency_key = _stable_id(run.run_inputs_sha256, case, "apply-idempotency")
    _, _, dispatch = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "apply-canary",
            "--project-number",
            run.project_number,
            "--root-id",
            root.root_id,
            "--expected-root-sha256",
            root.root_sha256,
            "--expected-epoch",
            "1",
            "--request-id",
            request_id,
            "--idempotency-key",
            idempotency_key,
        ),
        model_type=CanaryDispatchResultV1,
    )
    assert dispatch is not None
    if (
        dispatch.root_id != root.root_id
        or dispatch.epoch != 1
        or (dispatch.stable_percent, dispatch.candidate_percent) != (90, 10)
        or dispatch.enqueue_disposition not in {"CREATED", "DUPLICATE"}
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_APPLY_INVALID")
    receipt = _poll_receipt(
        run,
        case,
        root=root,
        epoch=1,
        request_id=request_id,
        idempotency_key=idempotency_key,
        action="APPLY_CANARY_V1",
        capability_sha256=dispatch.capability_sha256,
        label="apply",
    )
    if receipt.receipt.outcome.value != "VERIFIED" or receipt.verified_apply_receipt is None:
        raise AcceptanceError("ACCEPTANCE_HOSTED_APPLY_INVALID")
    return dispatch, receipt


def _health_command(
    run: _HostedExecution,
    case: CaseBindingV1,
    *,
    root_result: Any,
    apply_receipt: Any,
    ordinal: int,
    expected_sequence: int,
    expected_chain_head_sha256: str | None,
) -> Any:
    from controlgraph_canary.contracts.health_pipeline import (
        HEALTH_EVALUATION_COMMAND_V1,
        HealthEvaluationCommandV1,
    )

    root = root_result.root
    return HealthEvaluationCommandV1(
        schema_version=HEALTH_EVALUATION_COMMAND_V1,
        request_id=_stable_id(run.run_inputs_sha256, case, f"health-{ordinal}-request"),
        idempotency_key=_stable_id(run.run_inputs_sha256, case, f"health-{ordinal}-idempotency"),
        target=root.content.target,
        root_id=root.root_id,
        expected_root_sha256=root.root_sha256,
        expected_epoch=1,
        verified_apply_receipt=apply_receipt.verified_apply_receipt,
        expected_sequence=expected_sequence,
        expected_chain_head_sha256=expected_chain_head_sha256,
    )


def _evaluate_health(
    run: _HostedExecution,
    case: CaseBindingV1,
    *,
    command: Any,
    label: str,
) -> Any:
    from controlgraph_canary.contracts.health_pipeline import HealthEvaluationResultV2

    command_path = run.command_path(case, f"health-{label}")
    _write_command(command_path, command)
    for _attempt in range(10):
        status, payload, result = _run_cli(
            repo=run.repo,
            entry_point="controlgraph-canary",
            arguments=(
                "evaluate-health",
                "--project-number",
                run.project_number,
                "--command-file",
                str(command_path),
            ),
            model_type=HealthEvaluationResultV2,
            allowed_statuses=frozenset({0, 4}),
        )
        if status == 0 and result is not None:
            return result
        if payload != {"code": "HEALTH_EVALUATION_OUTCOME_UNKNOWN"}:
            raise AcceptanceError("ACCEPTANCE_HOSTED_HEALTH_INVALID")
        time.sleep(1)
    raise AcceptanceError("ACCEPTANCE_HOSTED_HEALTH_AMBIGUOUS")


def _prewarm_candidate(*, candidate_url: str, deadline: datetime) -> None:
    """Ramp the scaled-to-zero candidate until it answers one request."""

    probe_url = f"{candidate_url}/v1/probe"
    request = urllib.request.Request(probe_url, method="GET")
    last_error: Exception | None = None
    attempted = False
    while not attempted or datetime.now(UTC) < deadline - timedelta(seconds=5):
        attempted = True
        try:
            with urllib.request.urlopen(request, timeout=8):
                return
        except urllib.error.HTTPError:
            return
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            last_error = error
            time.sleep(0.5)
    raise AcceptanceError("ACCEPTANCE_HOSTED_CANDIDATE_UNREADY") from last_error


def _derive_health_anchor(*, load_start: datetime, receipt_updated_at: str) -> datetime:
    receipt_time = _parse_utc(receipt_updated_at)
    health_anchor = receipt_time.replace(second=0, microsecond=0) + timedelta(minutes=1)
    if health_anchor not in {load_start, load_start + timedelta(minutes=1)}:
        raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_ALIGNMENT_INVALID")
    return health_anchor


def _project_health_load(
    load: dict[str, Any],
    *,
    load_start: datetime,
    health_anchor: datetime,
) -> dict[str, Any]:
    windows = load.get("windows")
    if (
        health_anchor not in {load_start, load_start + timedelta(minutes=1)}
        or not isinstance(windows, list)
        or len(windows) != 3
        or any(
            not isinstance(window, dict) or type(window.get("submitted")) is not int
            for window in windows
        )
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
    bound_windows = cast(list[dict[str, Any]], windows)
    expected_starts = tuple(_utc(load_start + timedelta(minutes=index)) for index in range(3))
    if tuple(window.get("started_at") for window in bound_windows) != expected_starts:
        raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
    offset = int((health_anchor - load_start).total_seconds() // 60)
    selected = bound_windows[offset : offset + 2]
    if len(selected) != 2:
        raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_ALIGNMENT_INVALID")
    projected = dict(load)
    projected["anchor"] = _utc(health_anchor)
    projected["request_count"] = sum(cast(int, window["submitted"]) for window in selected)
    projected["windows"] = selected
    return projected


def _accepted_health_append_disposition(value: object) -> bool:
    return value in ("CREATED", "ADOPTED")


def _health_load(
    run: _HostedExecution,
    case: CaseBindingV1,
    *,
    mode: Literal["healthy", "unhealthy"],
    root_result: Any,
    before_terminal: Callable[[], None] | None = None,
) -> tuple[dict[str, Any], Any, Any, Any]:
    audience, candidate_url = _reference_urls(run)
    destination = (
        f"{candidate_url}/v1/probe"
        if mode == "healthy"
        else f"{candidate_url}/v1/cgm8-deliberate-404"
    )
    job_name = _create_load_job(
        run,
        case,
        mode=mode,
        destination=destination,
        audience=audience,
        expected_revision=run.spec.target.candidate_revision,
    )
    try:
        earliest = datetime.now(UTC) + timedelta(seconds=300)
        planned_anchor = earliest.replace(second=0, microsecond=0)
        if planned_anchor < earliest:
            planned_anchor += timedelta(minutes=1)
        load_start = planned_anchor - timedelta(minutes=1)
        execution = _execute_job(run, job_name, asynchronous=True, anchor=load_start)
        ready = _load_log_record(run, execution, _LOAD_READY_SCHEMA, attempts=75)
        if (
            ready.get("status") != "READY"
            or ready.get("mode") != mode
            or ready.get("anchor") != _utc(load_start)
            or ready.get("token_persisted") is not False
            or _parse_utc(cast(str, ready.get("token_acquired_at")))
            > load_start - timedelta(seconds=60)
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
        apply_at = load_start - timedelta(seconds=59)
        while datetime.now(UTC) < apply_at:
            time.sleep(min(5.0, max(0.05, (apply_at - datetime.now(UTC)).total_seconds())))
        dispatch, receipt = _apply_canary(run, case, root_result)
        health_anchor = _derive_health_anchor(
            load_start=load_start,
            receipt_updated_at=receipt.receipt.updated_at,
        )
        _prewarm_candidate(candidate_url=candidate_url, deadline=health_anchor)
        loaded = _read_traffic(run, case, "canary-loaded")
        _require_split(loaded, run.spec, stable=90, candidate=10)
        load_complete_at = load_start + timedelta(seconds=185)
        while datetime.now(UTC) < load_complete_at:
            remaining = (load_complete_at - datetime.now(UTC)).total_seconds()
            time.sleep(min(5.0, max(0.05, remaining)))
        load = _load_log_record(run, execution, _LOAD_RESULT_SCHEMA, attempts=20)
        windows = load.get("windows")
        if (
            load.get("status") != "COMPLETE"
            or load.get("mode") != mode
            or load.get("anchor") != _utc(load_start)
            or load.get("token_persisted") is not False
            or not isinstance(windows, list)
            or len(windows) != 3
            or any(
                not isinstance(window, dict)
                or type(window.get("submitted")) is not int
                or cast(int, window["submitted"]) < 100
                for window in windows
            )
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
        load = _project_health_load(
            load,
            load_start=load_start,
            health_anchor=health_anchor,
        )
        if any(
            type(window.get("accepted")) is not int
            or window.get("accepted") != window.get("submitted")
            for window in cast(list[dict[str, Any]], load["windows"])
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_LOAD_INVALID")
    finally:
        _delete_load_job(run, job_name)
    while datetime.now(UTC) < health_anchor + timedelta(seconds=250):
        remaining = (health_anchor + timedelta(seconds=250) - datetime.now(UTC)).total_seconds()
        time.sleep(min(5.0, max(0.05, remaining)))
    first_command = _health_command(
        run,
        case,
        root_result=root_result,
        apply_receipt=receipt,
        ordinal=1,
        expected_sequence=0,
        expected_chain_head_sha256=None,
    )
    first = _evaluate_health(run, case, command=first_command, label="first")
    if (
        first.terminal_status.value != "wait"
        or first.terminal_sequence != 1
        or not _accepted_health_append_disposition(first.append_disposition)
        or first.next_evaluation_at is None
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_HEALTH_INVALID")
    next_evaluation = _parse_utc(first.next_evaluation_at)
    if before_terminal is not None:
        before_terminal()
    # Preserve the terminal proof's bounded execution window for the receipt worker.
    while datetime.now(UTC) < next_evaluation:
        remaining = (next_evaluation - datetime.now(UTC)).total_seconds()
        time.sleep(min(5.0, max(0.05, remaining)))
    second_command = _health_command(
        run,
        case,
        root_result=root_result,
        apply_receipt=receipt,
        ordinal=2,
        expected_sequence=first.terminal_sequence,
        expected_chain_head_sha256=first.chain_head_sha256,
    )
    second = _evaluate_health(run, case, command=second_command, label="second")
    expected = "healthy" if mode == "healthy" else "unhealthy"
    if (
        second.terminal_status.value != expected
        or second.terminal_sequence != 2
        or not _accepted_health_append_disposition(second.append_disposition)
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_HEALTH_INVALID")
    return load, dispatch, receipt, second


def _promote(
    run: _HostedExecution,
    case: CaseBindingV1,
    *,
    root_result: Any,
    apply_receipt: Any,
    terminal: Any,
) -> tuple[Any, Any]:
    from controlgraph_canary.contracts.promotion_execution import (
        PROMOTION_COMMAND_V2,
        PromotionCommandV2,
        PromotionDispatchResultV2,
    )

    if terminal.terminal_status.value != "healthy" or terminal.promotion_health_chain is None:
        raise AcceptanceError("ACCEPTANCE_HOSTED_PROMOTION_INVALID")
    root = root_result.root
    request_id = _stable_id(run.run_inputs_sha256, case, "promotion-request")
    idempotency_key = _stable_id(run.run_inputs_sha256, case, "promotion-idempotency")
    command = PromotionCommandV2(
        schema_version=PROMOTION_COMMAND_V2,
        root_id=root.root_id,
        expected_root_sha256=root.root_sha256,
        expected_epoch=1,
        request_id=request_id,
        idempotency_key=idempotency_key,
        scheduled_at=_utc(datetime.now(UTC) + timedelta(seconds=5)),
        verified_apply_receipt=apply_receipt.verified_apply_receipt,
        health_chain_locator=terminal.promotion_health_chain,
    )
    path = run.command_path(case, "promotion")
    _write_command(path, command)
    _, _, dispatch = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "promote-candidate",
            "--project-number",
            run.project_number,
            "--command-file",
            str(path),
        ),
        model_type=PromotionDispatchResultV2,
    )
    assert dispatch is not None
    if (
        dispatch.root_id != root.root_id
        or dispatch.epoch != 1
        or dispatch.health_chain_locator != terminal.promotion_health_chain
        or dispatch.enqueue_disposition not in {"CREATED", "DUPLICATE"}
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_PROMOTION_INVALID")
    return dispatch, command


def _release_claim(
    run: _HostedExecution,
    case: CaseBindingV1,
    *,
    root: Any,
    epoch: int,
    terminal_idempotency_key: str,
    label: str,
) -> Any:
    from controlgraph_canary.contracts.service_claim_release import (
        SERVICE_CLAIM_RELEASE_COMMAND_V1,
        ServiceClaimReleaseCommandV1,
        ServiceClaimReleaseResultV1,
    )

    command = ServiceClaimReleaseCommandV1(
        schema_version=SERVICE_CLAIM_RELEASE_COMMAND_V1,
        root_id=root.root_id,
        expected_root_sha256=root.root_sha256,
        expected_epoch=epoch,
        terminal_receipt_idempotency_key=terminal_idempotency_key,
        request_id=_stable_id(run.run_inputs_sha256, case, f"{label}-release-request"),
        idempotency_key=_stable_id(run.run_inputs_sha256, case, f"{label}-release-idempotency"),
        confirmation="RELEASE",
    )
    path = run.command_path(case, f"{label}-release")
    _write_command(path, command)
    _, _, result = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "release-service-claim",
            "--project-number",
            run.project_number,
            "--command-file",
            str(path),
        ),
        model_type=ServiceClaimReleaseResultV1,
    )
    assert result is not None
    if (
        result.root_id != root.root_id
        or result.root_sha256 != root.root_sha256
        or result.fenced_epoch != epoch + 1
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_RELEASE_INVALID")
    return result


def _run_healthy_case(run: _HostedExecution, case: CaseBindingV1) -> _CaseOutcome:
    root_result = _create_root(run, case)
    run.root_ids.add(root_result.root.root_id)
    run.unreleased_root_ids.add(root_result.root.root_id)
    root = root_result.root
    terminal_idempotency_key: str | None = None
    released = False
    try:
        load, apply_dispatch, apply_receipt, health = _health_load(
            run, case, mode="healthy", root_result=root_result
        )
        promotion_dispatch, promotion_command = _promote(
            run,
            case,
            root_result=root_result,
            apply_receipt=apply_receipt,
            terminal=health,
        )
        promotion_receipt = _poll_receipt(
            run,
            case,
            root=root,
            epoch=1,
            request_id=promotion_command.request_id,
            idempotency_key=promotion_command.idempotency_key,
            action="PROMOTE_CANDIDATE_V1",
            capability_sha256=promotion_dispatch.capability_sha256,
            label="promotion",
        )
        if promotion_receipt.receipt.outcome.value != "VERIFIED":
            raise AcceptanceError("ACCEPTANCE_HOSTED_PROMOTION_INVALID")
        terminal_idempotency_key = promotion_command.idempotency_key
        traffic = _read_traffic(run, case, "promoted")
        _require_split(traffic, run.spec, stable=0, candidate=100)
        if (
            promotion_receipt.receipt.expected_poststate_sha256
            != traffic.target_configuration_sha256
            or promotion_receipt.receipt.observed_etag != traffic.provider_etag
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_PROMOTION_INVALID")
        release = _release_claim(
            run,
            case,
            root=root,
            epoch=1,
            terminal_idempotency_key=terminal_idempotency_key,
            label="healthy",
        )
        released = True
        run.unreleased_root_ids.discard(root.root_id)
        pages, raw = _read_timeline_evidence(run)
        terminal_result = _terminal_result(pages, root_id=root.root_id, expected="PROMOTED")
        capability_metadata = _verified_capability_metadata(
            pages=pages,
            raw=raw,
            root_id=root.root_id,
            capability_sha256s=frozenset(
                {apply_dispatch.capability_sha256, promotion_dispatch.capability_sha256}
            ),
        )
        return _CaseOutcome(
            observations={
                EvidenceKind.CLOUD_RUN_CONFIGURATION: traffic,
                EvidenceKind.DATA_PATH_PROBE: load,
                EvidenceKind.VERIFIED_CAPABILITY_METADATA: capability_metadata,
                EvidenceKind.EXECUTOR_EPOCH_CHECK: promotion_receipt,
                EvidenceKind.EXECUTION_RECEIPT: promotion_receipt,
                EvidenceKind.HEALTH_DECISION: health,
                EvidenceKind.TIMELINE: _timeline_evidence(pages, release=release),
            },
            terminal_result=terminal_result,
        )
    finally:
        if terminal_idempotency_key is not None and not released:
            try:
                _release_claim(
                    run,
                    case,
                    root=root,
                    epoch=1,
                    terminal_idempotency_key=terminal_idempotency_key,
                    label="healthy-cleanup",
                )
                run.unreleased_root_ids.discard(root.root_id)
            except AcceptanceError as error:
                raise AcceptanceError("ACCEPTANCE_HOSTED_CLAIM_CLEANUP_FAILED") from error


def _run_unhealthy_case(run: _HostedExecution, case: CaseBindingV1) -> _CaseOutcome:
    root_result = _create_root(run, case)
    run.root_ids.add(root_result.root.root_id)
    run.unreleased_root_ids.add(root_result.root.root_id)
    root = root_result.root
    terminal_idempotency_key: str | None = None
    released = False
    try:
        load, apply_dispatch, apply_receipt, health = _health_load(
            run, case, mode="unhealthy", root_result=root_result
        )
        recovery = health.recovery_dispatch
        if (
            recovery is None
            or recovery.trigger_basis.value != "TERMINAL_UNHEALTHY_V3"
            or recovery.enqueue_disposition not in {"CREATED", "DUPLICATE"}
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_RECOVERY_INVALID")
        receipt = _poll_receipt(
            run,
            case,
            root=root,
            epoch=1,
            request_id=recovery.request_id,
            idempotency_key=recovery.idempotency_key,
            action="RECOVER_STABLE_V1",
            capability_sha256=recovery.capability_sha256,
            label="recovery",
        )
        if receipt.receipt.outcome.value != "VERIFIED":
            raise AcceptanceError("ACCEPTANCE_HOSTED_RECOVERY_INVALID")
        terminal_idempotency_key = recovery.idempotency_key
        traffic = _read_traffic(run, case, "recovered")
        _require_split(traffic, run.spec, stable=100, candidate=0)
        release = _release_claim(
            run,
            case,
            root=root,
            epoch=1,
            terminal_idempotency_key=terminal_idempotency_key,
            label="unhealthy",
        )
        released = True
        run.unreleased_root_ids.discard(root.root_id)
        pages, raw = _read_timeline_evidence(run)
        terminal_result = _terminal_result(pages, root_id=root.root_id, expected="RECOVERED")
        capability_metadata = _verified_capability_metadata(
            pages=pages,
            raw=raw,
            root_id=root.root_id,
            capability_sha256s=frozenset(
                {apply_dispatch.capability_sha256, recovery.capability_sha256}
            ),
        )
        recovery_service = run.service_bindings.get("recovery")
        recovery_identity = root.content.authority_bounds.recovery_identity
        if recovery_service is None or recovery_service.get("service_account") != recovery_identity:
            raise AcceptanceError("ACCEPTANCE_HOSTED_RECOVERY_IDENTITY_INVALID")
        return _CaseOutcome(
            observations={
                EvidenceKind.CLOUD_RUN_CONFIGURATION: traffic,
                EvidenceKind.DATA_PATH_PROBE: load,
                EvidenceKind.VERIFIED_CAPABILITY_METADATA: capability_metadata,
                EvidenceKind.EXECUTOR_EPOCH_CHECK: receipt,
                EvidenceKind.EXECUTION_RECEIPT: {
                    "apply": _model_dict(apply_receipt),
                    "recovery": _model_dict(receipt),
                },
                EvidenceKind.HEALTH_DECISION: health,
                EvidenceKind.RECOVERY_SERVICE_IDENTITY_BINDING: {
                    "dispatch": _model_dict(recovery),
                    "root_authority_identity": recovery_identity,
                    "schema_version": "controlgraph.recovery-service-identity-binding/v1",
                    "service": recovery_service,
                },
                EvidenceKind.TIMELINE: _timeline_evidence(pages, release=release),
            },
            terminal_result=terminal_result,
        )
    finally:
        if terminal_idempotency_key is not None and not released:
            try:
                _release_claim(
                    run,
                    case,
                    root=root,
                    epoch=1,
                    terminal_idempotency_key=terminal_idempotency_key,
                    label="unhealthy-cleanup",
                )
                run.unreleased_root_ids.discard(root.root_id)
            except AcceptanceError as error:
                raise AcceptanceError("ACCEPTANCE_HOSTED_CLAIM_CLEANUP_FAILED") from error


def _queue_control(run: _HostedExecution, action: Literal["hold", "release"]) -> dict[str, Any]:
    confirmation = "HOLD_EXECUTION_QUEUE" if action == "hold" else "RELEASE_EXECUTION_QUEUE"
    _, result, _ = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "execution-queue",
            action,
            "--project-id",
            run.spec.target.project_id,
            "--confirm",
            confirmation,
        ),
    )
    expected = "PAUSED" if action == "hold" else "RUNNING"
    if (
        result.get("action") != action
        or result.get("project_id") != run.spec.target.project_id
        or result.get("location") != run.spec.target.region
        or result.get("queue_id") != "controlgraph-execution"
        or result.get("state") != expected
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_QUEUE_INVALID")
    return result


def _revoke(run: _HostedExecution, case: CaseBindingV1, root: Any) -> Any:
    from controlgraph_canary.contracts.revocation import EpochRevocationCallOutcomeV1

    request_id = _stable_id(run.run_inputs_sha256, case, "revoke-request")
    idempotency_key = _stable_id(run.run_inputs_sha256, case, "revoke-idempotency")
    reason = "M8 isolated stale-capability acceptance"
    _, _, outcome = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "revoke-epoch",
            "--project-number",
            run.project_number,
            "--root-id",
            root.root_id,
            "--expected-root-sha256",
            root.root_sha256,
            "--expected-epoch",
            "1",
            "--reason",
            reason,
            "--request-id",
            request_id,
            "--idempotency-key",
            idempotency_key,
            "--confirm",
            "REVOKE",
        ),
        model_type=EpochRevocationCallOutcomeV1,
    )
    assert outcome is not None
    result = outcome.result
    if result.root_id != root.root_id or result.previous_epoch != 1 or result.new_epoch != 2:
        raise AcceptanceError("ACCEPTANCE_HOSTED_REVOCATION_INVALID")
    return outcome


def _revocation_proof(run: _HostedExecution, outcome: Any) -> Any:
    from controlgraph_canary.contracts.revocation import EpochRevocationProofV1

    result = outcome.result
    _, _, proof = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "revocation-proof",
            "--project-number",
            run.project_number,
            "--root-id",
            result.root_id,
            "--root-sha256",
            result.root_sha256,
            "--previous-epoch",
            str(result.previous_epoch),
            "--new-epoch",
            str(result.new_epoch),
            "--reason",
            result.reason,
            "--request-sha256",
            result.request_sha256,
            "--request-id",
            result.request_id,
            "--idempotency-key",
            result.idempotency_key,
            "--result-id",
            result.result_id,
            "--evidence-id",
            result.evidence_id,
            "--evidence-sha256",
            result.evidence_sha256,
            "--attempt-id",
            outcome.attempt_id,
            "--audit-id",
            outcome.audit_id,
        ),
        model_type=EpochRevocationProofV1,
    )
    assert proof is not None
    if proof.result != result or proof.authority.current_epoch != 2:
        raise AcceptanceError("ACCEPTANCE_HOSTED_REVOCATION_INVALID")
    return proof


def _recover_revoked(
    run: _HostedExecution,
    case: CaseBindingV1,
    *,
    root_result: Any,
    apply_receipt: Any,
    revocation_proof: Any,
) -> tuple[Any, Any]:
    from controlgraph_canary.contracts.recovery_execution import (
        RecoveryDispatchResultV2,
        create_recovery_apply_receipt_locator,
        create_revoked_v3_recovery_command,
    )

    root = root_result.root
    apply_locator = create_recovery_apply_receipt_locator(
        apply_receipt.receipt,
        storage_revision=apply_receipt.storage_revision,
    )
    command = create_revoked_v3_recovery_command(
        root=root,
        revocation_proof=revocation_proof,
        verified_apply_receipt=apply_locator,
        request_id=_stable_id(run.run_inputs_sha256, case, "recovery-request"),
        idempotency_key=_stable_id(run.run_inputs_sha256, case, "recovery-idempotency"),
        scheduled_at=_utc(datetime.now(UTC) + timedelta(seconds=10)),
        confirmation="RECOVER_CAPTURED_STABLE",
    )
    path = run.command_path(case, "revoked-recovery")
    _write_command(path, command)
    _, _, dispatch = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=(
            "recover-captured-stable",
            "--project-number",
            run.project_number,
            "--command-file",
            str(path),
        ),
        model_type=RecoveryDispatchResultV2,
    )
    assert dispatch is not None
    if (
        dispatch.root_id != root.root_id
        or dispatch.epoch != 2
        or dispatch.trigger_basis.value != "OPERATOR_CONFIRMED_REVOKED_V3"
        or dispatch.enqueue_disposition not in {"CREATED", "DUPLICATE"}
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_RECOVERY_INVALID")
    receipt = _poll_receipt(
        run,
        case,
        root=root,
        epoch=2,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        action="RECOVER_STABLE_V1",
        capability_sha256=dispatch.capability_sha256,
        label="revoked-recovery",
    )
    if receipt.receipt.outcome.value != "VERIFIED":
        raise AcceptanceError("ACCEPTANCE_HOSTED_RECOVERY_INVALID")
    return dispatch, receipt


def _advisor_command(run: _HostedExecution, case: CaseBindingV1, root: Any, epoch: int) -> Any:
    from controlgraph_canary.contracts.model_assistance import (
        ADVISOR_OPERATOR_COMMAND_V1,
        AdvisorOperatorCommandV1,
    )

    return AdvisorOperatorCommandV1(
        schema_version=ADVISOR_OPERATOR_COMMAND_V1,
        request_id=_stable_id(run.run_inputs_sha256, case, "advisor-request"),
        idempotency_key=_stable_id(run.run_inputs_sha256, case, "advisor-idempotency"),
        target=root.content.target,
        root_id=root.root_id,
        expected_root_sha256=root.root_sha256,
        expected_epoch=epoch,
        requested_at=_utc_now(),
    )


def _invoke_advisor(run: _HostedExecution, command: Any) -> Any:
    from controlgraph_canary.contracts.model_assistance import AdvisorOperatorResultV1

    token = _identity_token(run)
    try:
        status, payload, headers = _http_request(
            url=f"{run.api_origin}/v1/operator/commands",
            token=token,
            operator=True,
            body=_canonical_object(_model_dict(command)),
        )
    finally:
        token = ""
    if status != 200 or headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise AcceptanceError("ACCEPTANCE_HOSTED_ADVISOR_INVALID")
    try:
        return AdvisorOperatorResultV1.model_validate_json(payload)
    except (TypeError, ValueError, ValidationError) as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_ADVISOR_INVALID") from error


def _timeline_enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _timeline_display_values(entry: Any) -> dict[str, str]:
    return {_timeline_enum_value(field.name): field.value for field in entry.display_fields}


def _timeline_has_correlation(entry: Any, kind: str, value: str) -> bool:
    return any(
        _timeline_enum_value(correlation.kind) == kind and correlation.correlation_id == value
        for correlation in entry.correlations
    )


def _stale_denial_completion_is_ready(
    pages: Sequence[Any],
    *,
    root: Any,
    revocation: Any,
    stale_receipt: Any,
    target_configuration_sha256: str,
) -> bool:
    receipt = stale_receipt.receipt
    revocation_result = revocation.result
    entries = tuple(
        entry
        for page in pages
        for entry in page.entries
        if entry.root_id == root.root_id and entry.root_sha256 == root.root_sha256
    )
    expected_verification = f"stale-denial:{stale_receipt.receipt_sha256[:32]}"
    expected_actor = (
        f"actor:{hashlib.sha256(revocation_result.operator_identity.encode('utf-8')).hexdigest()}"
    )
    transitions = tuple(
        entry
        for entry in entries
        if _timeline_enum_value(entry.event_type) == "AUTHORITY_EPOCH_ADVANCED"
        and entry.epoch == revocation_result.new_epoch
        and entry.occurred_at == revocation_result.committed_at
        and entry.actor_id == expected_actor
        and entry.signature is not None
        and entry.signature.purpose == "EVIDENCE"
        and _timeline_enum_value(entry.verification_status) == "VERIFIED"
        and _timeline_has_correlation(
            entry,
            "EVIDENCE",
            revocation_result.evidence_id,
        )
        and _timeline_has_correlation(
            entry,
            "REQUEST",
            revocation_result.request_id,
        )
    )
    receipts = tuple(
        entry
        for entry in entries
        if _timeline_enum_value(entry.event_type) == "MUTATION_DENIED"
        and entry.epoch == receipt.epoch
        and entry.occurred_at == receipt.updated_at
        and entry.payload_sha256 == stale_receipt.receipt_sha256
        and entry.signature is None
        and _timeline_enum_value(entry.verification_status) == "NOT_APPLICABLE"
        and _timeline_display_values(entry).get("OUTCOME") == "DENIED"
        and _timeline_display_values(entry).get("REASON_CODE") == "EPOCH_MISMATCH"
        and _timeline_has_correlation(entry, "RECEIPT", receipt.receipt_id)
        and _timeline_has_correlation(entry, "REQUEST", receipt.request_id)
    )
    if len(transitions) != 1 or len(receipts) != 1:
        return False
    transition = transitions[0]
    receipt_entry = receipts[0]
    if transition.sequence >= receipt_entry.sequence:
        return False

    expected_state = (
        "stable_percent=90;candidate_percent=10;"
        f"target_configuration_sha256={target_configuration_sha256}"
    )
    verified: dict[str, Any] = {}
    for entry in entries:
        display = _timeline_display_values(entry)
        observation = display.get("OBSERVATION")
        if (
            observation in {"CONFIGURATION", "PROBE"}
            and _timeline_enum_value(entry.event_type) == "VERIFICATION_RECORDED"
            and entry.epoch == receipt.epoch
            and entry.sequence > receipt_entry.sequence
            and _parse_utc(entry.occurred_at) >= _parse_utc(receipt.updated_at)
            and entry.signature is not None
            and entry.signature.purpose == "INDEPENDENT_VERIFICATION"
            and _timeline_enum_value(entry.verification_status) == "VERIFIED"
            and display.get("ACTION") == "APPLY_CANARY_V1"
            and display.get("OUTCOME") == "MATCH"
            and _timeline_has_correlation(entry, "REQUEST", receipt.request_id)
            and _timeline_has_correlation(
                entry,
                "VERIFICATION",
                expected_verification,
            )
            and (observation != "CONFIGURATION" or display.get("STATE") == expected_state)
        ):
            verified[observation] = entry
    if set(verified) != {"CONFIGURATION", "PROBE"}:
        return False

    evidence_sequence = max(entry.sequence for entry in verified.values())
    evidence_time = max(_parse_utc(entry.occurred_at) for entry in verified.values())
    return any(
        _timeline_enum_value(entry.event_type) == "TERMINAL_CLASSIFIED"
        and entry.epoch == receipt.epoch
        and entry.sequence > evidence_sequence
        and _parse_utc(entry.occurred_at) >= evidence_time
        and entry.signature is None
        and _timeline_enum_value(entry.verification_status) == "VERIFIED"
        and _timeline_enum_value(entry.terminal_classification) == "DENIED"
        and _timeline_display_values(entry).get("ACTION") == "STALE_CAPABILITY_DENIAL"
        and _timeline_display_values(entry).get("OUTCOME") == "COMPLETE"
        and _timeline_display_values(entry).get("REASON_CODE") == "STALE_CAPABILITY_DENIAL_COMPLETE"
        and _timeline_has_correlation(entry, "REQUEST", receipt.request_id)
        and _timeline_has_correlation(
            entry,
            "VERIFICATION",
            expected_verification,
        )
        for entry in entries
    )


def _wait_for_stale_denial_completion(
    run: _HostedExecution,
    *,
    root: Any,
    revocation: Any,
    stale_receipt: Any,
    target_configuration_sha256: str,
) -> tuple[Any, ...]:
    for attempt in range(_STALE_COMPLETION_READINESS_ATTEMPTS):
        try:
            pages = _read_operator_timeline(run)
        except AcceptanceError as error:
            if error.code != "ACCEPTANCE_HOSTED_TIMELINE_CHANGED":
                raise
        else:
            if _stale_denial_completion_is_ready(
                pages,
                root=root,
                revocation=revocation,
                stale_receipt=stale_receipt,
                target_configuration_sha256=target_configuration_sha256,
            ):
                return pages
        if attempt + 1 < _STALE_COMPLETION_READINESS_ATTEMPTS:
            time.sleep(_STALE_COMPLETION_READINESS_DELAY_SECONDS)
    raise AcceptanceError("ACCEPTANCE_HOSTED_STALE_COMPLETION_TIMEOUT")


def _validate_advisor_result(
    command: Any,
    result: Any,
    *,
    replayed: bool,
    original: Any | None = None,
    expected_causal_path_clause: str | None = None,
) -> None:
    from controlgraph_canary.contracts.codec import canonical_sha256
    from controlgraph_canary.contracts.model_assistance import DiagnosticToolId

    audit = result.response.audit
    recommendation = result.response.recommendation
    citation_kinds = (
        {
            citation.evidence_kind.value
            for finding in recommendation.findings
            for citation in finding.citations
        }
        if recommendation is not None
        else set()
    )
    causal_findings = (
        tuple(
            finding
            for finding in recommendation.findings
            if finding.statement == expected_causal_path_clause
            and {citation.evidence_kind.value for citation in finding.citations}
            >= {"receipt", "timeline"}
            and {citation.evidence_kind.value for citation in finding.citations}.intersection(
                {"target", "verifier"}
            )
        )
        if recommendation is not None and expected_causal_path_clause is not None
        else ()
    )
    if (
        result.replayed is not replayed
        or result.command_sha256 != canonical_sha256(command)
        or result.root_id != command.root_id
        or result.root_sha256 != command.expected_root_sha256
        or result.epoch != command.expected_epoch
        or recommendation is None
        or not audit.validation.accepted
        or tuple(code.value for code in audit.validation.codes) != ("accepted",)
        or audit.prompt_version != "controlgraph.rollout-advisor-prompt/v2"
        or len(audit.tool_calls) != len(DiagnosticToolId)
        or tuple(call.sequence for call in audit.tool_calls)
        != tuple(range(1, len(DiagnosticToolId) + 1))
        or {call.tool_id for call in audit.tool_calls} != set(DiagnosticToolId)
        or any(
            call.status.value != "succeeded" or call.output_sha256 is None
            for call in audit.tool_calls
        )
        or not {"receipt", "timeline"}.issubset(citation_kinds)
        or not citation_kinds.intersection({"target", "verifier"})
        or (expected_causal_path_clause is not None and len(causal_findings) != 1)
        or recommendation.authority_effect != "none"
        or recommendation.deterministic_health_override is not False
        or recommendation.operator_review_required is not True
        or (original is not None and result.model_copy(update={"replayed": False}) != original)
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_ADVISOR_INVALID")


def _public_traffic(result: Any) -> Any:
    from controlgraph_canary.contracts.public_replay import (
        PUBLIC_REPLAY_TRAFFIC_V1,
        PublicReplayTrafficV1,
    )

    traffic = _traffic_percentages(result)
    request = result.request
    return PublicReplayTrafficV1(
        schema_version=PUBLIC_REPLAY_TRAFFIC_V1,
        stable_percent=traffic.get(request.stable_revision, 0),
        candidate_percent=traffic.get(request.candidate_revision, 0),
        target_configuration_sha256=result.target_configuration_sha256,
    )


def _public_advisor(
    command: Any,
    initial: Any,
    replay: Any,
    *,
    expected_causal_path_clause: str,
) -> Any:
    from controlgraph_canary.contracts.codec import canonical_sha256
    from controlgraph_canary.contracts.public_replay import (
        PUBLIC_REPLAY_ADVISOR_V1,
        PUBLIC_REPLAY_CITATION_V1,
        PUBLIC_REPLAY_FINDING_V1,
        PUBLIC_REPLAY_TOOL_CALL_V1,
        PublicReplayAdvisorV1,
        PublicReplayCitationV1,
        PublicReplayFindingV1,
        PublicReplayToolCallV1,
    )

    _validate_advisor_result(
        command,
        initial,
        replayed=False,
        expected_causal_path_clause=expected_causal_path_clause,
    )
    _validate_advisor_result(
        command,
        replay,
        replayed=True,
        original=initial,
        expected_causal_path_clause=expected_causal_path_clause,
    )
    recommendation = initial.response.recommendation
    assert recommendation is not None
    audit = initial.response.audit
    tool_calls: list[PublicReplayToolCallV1] = []
    for call in audit.tool_calls:
        if call.output_sha256 is None:
            raise AcceptanceError("ACCEPTANCE_HOSTED_ADVISOR_INVALID")
        tool_calls.append(
            PublicReplayToolCallV1(
                schema_version=PUBLIC_REPLAY_TOOL_CALL_V1,
                sequence=call.sequence,
                tool_id=call.tool_id.value,
                input_sha256=call.input_sha256,
                output_sha256=call.output_sha256,
                status="succeeded",
            )
        )
    return PublicReplayAdvisorV1(
        schema_version=PUBLIC_REPLAY_ADVISOR_V1,
        model_id=audit.model_id,
        model_location=audit.model_location,
        prompt_version=audit.prompt_version,
        response_sha256=canonical_sha256(initial.response),
        audit_sha256=canonical_sha256(audit),
        registry_sha256=audit.registry_sha256,
        snapshot_sha256=audit.snapshot_sha256,
        structured_output_sha256=audit.structured_output_sha256,
        validation="accepted",
        authority_effect=recommendation.authority_effect,
        deterministic_health_override=recommendation.deterministic_health_override,
        operator_review_required=recommendation.operator_review_required,
        requested_operator_action=recommendation.requested_operator_action.value,
        confidence_basis_points=recommendation.confidence_basis_points,
        findings=tuple(
            PublicReplayFindingV1(
                schema_version=PUBLIC_REPLAY_FINDING_V1,
                statement=finding.statement,
                citations=tuple(
                    PublicReplayCitationV1(
                        schema_version=PUBLIC_REPLAY_CITATION_V1,
                        evidence_kind=citation.evidence_kind.value,
                        evidence_id=citation.evidence_id,
                        source_sha256=citation.source_sha256,
                    )
                    for citation in finding.citations
                ),
            )
            for finding in recommendation.findings
        ),
        tool_calls=tuple(tool_calls),
        replayed_without_model_call=True,
    )


def _public_timeline(pages: Sequence[Any], *, root_id: str) -> Any:
    from controlgraph_canary.contracts.public_replay import (
        PUBLIC_REPLAY_TIMELINE_ENTRY_V1,
        PUBLIC_REPLAY_TIMELINE_V1,
        PublicReplayTimelineEntryV1,
        PublicReplayTimelineEventType,
        PublicReplayTimelineV1,
    )

    summary = _timeline_page_summary(pages)
    allowed = {item.value for item in PublicReplayTimelineEventType}
    entries = tuple(
        PublicReplayTimelineEntryV1(
            schema_version=PUBLIC_REPLAY_TIMELINE_ENTRY_V1,
            sequence=entry.sequence,
            entry_sha256=entry.entry_sha256,
            event_type=entry.event_type.value,
            occurred_at=entry.occurred_at,
            verification_status=entry.verification_status.value,
        )
        for page in pages
        for entry in page.entries
        if entry.root_id == root_id and entry.event_type.value in allowed
    )
    head_entry_sha256 = summary["head_entry_sha256"]
    if not isinstance(head_entry_sha256, str):
        raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
    return PublicReplayTimelineV1(
        schema_version=PUBLIC_REPLAY_TIMELINE_V1,
        head_sequence=cast(int, summary["head_sequence"]),
        head_entry_sha256=head_entry_sha256,
        entry_count=cast(int, summary["entry_count"]),
        page_count=cast(int, summary["page_count"]),
        page_set_sha256=cast(str, summary["page_set_sha256"]),
        entries=entries,
    )


def _run_revocation_case(run: _HostedExecution, case: CaseBindingV1) -> _CaseOutcome:
    from controlgraph_canary.application.model_assistance import (
        stale_denial_causal_path_clause,
    )

    root_result = _create_root(run, case)
    run.root_ids.add(root_result.root.root_id)
    run.unreleased_root_ids.add(root_result.root.root_id)
    terminal_idempotency_key: str | None = None
    released = False
    try:

        def hold_execution_queue() -> None:
            _queue_control(run, "hold")
            run.execution_queue_cleanup_required = True

        load, apply_dispatch, apply_receipt, health = _health_load(
            run,
            case,
            mode="healthy",
            root_result=root_result,
            before_terminal=hold_execution_queue,
        )
        promotion_dispatch, promotion_command = _promote(
            run,
            case,
            root_result=root_result,
            apply_receipt=apply_receipt,
            terminal=health,
        )
        revocation = _revoke(run, case, root_result.root)
        before_denial = _read_traffic(run, case, "before-stale-denial")
        _require_split(before_denial, run.spec, stable=90, candidate=10)
        _queue_control(run, "release")
        run.execution_queue_cleanup_required = False
        stale_receipt = _poll_receipt(
            run,
            case,
            root=root_result.root,
            epoch=1,
            request_id=promotion_command.request_id,
            idempotency_key=promotion_command.idempotency_key,
            action="PROMOTE_CANDIDATE_V1",
            capability_sha256=promotion_dispatch.capability_sha256,
            label="stale-promotion",
        )
        if (
            stale_receipt.receipt.outcome.value != "DENIED"
            or stale_receipt.receipt.reason_code.value != "EPOCH_MISMATCH"
            or stale_receipt.receipt.observed_authority_epoch != 2
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_STALE_DENIAL_INVALID")
        proof = _revocation_proof(run, revocation)
        unchanged = _read_traffic(run, case, "after-stale-denial")
        _require_split(unchanged, run.spec, stable=90, candidate=10)
        if (
            unchanged.provider_etag != before_denial.provider_etag
            or unchanged.service_generation != before_denial.service_generation
            or unchanged.target_configuration_sha256 != before_denial.target_configuration_sha256
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_STALE_DENIAL_MUTATED_TARGET")
        _wait_for_stale_denial_completion(
            run,
            root=root_result.root,
            revocation=revocation,
            stale_receipt=stale_receipt,
            target_configuration_sha256=unchanged.target_configuration_sha256,
        )
        advisor_command = _advisor_command(
            run,
            case,
            root_result.root,
            revocation.result.new_epoch,
        )
        advisor_result = _invoke_advisor(run, advisor_command)
        advisor_causal_path_clause = stale_denial_causal_path_clause(
            work_epoch=stale_receipt.receipt.epoch,
            current_authority_epoch=revocation.result.new_epoch,
            target_configuration_sha256=unchanged.target_configuration_sha256,
        )
        _validate_advisor_result(
            advisor_command,
            advisor_result,
            replayed=False,
            expected_causal_path_clause=advisor_causal_path_clause,
        )
        after_advisor = _read_traffic(run, case, "after-stale-advisor")
        if (
            after_advisor.provider_etag != unchanged.provider_etag
            or after_advisor.service_generation != unchanged.service_generation
            or after_advisor.target_configuration_sha256 != unchanged.target_configuration_sha256
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_ADVISOR_MUTATED_TARGET")
        recovery_dispatch, recovery_receipt = _recover_revoked(
            run,
            case,
            root_result=root_result,
            apply_receipt=apply_receipt,
            revocation_proof=proof,
        )
        terminal_idempotency_key = recovery_dispatch.idempotency_key
        recovered = _read_traffic(run, case, "revoked-recovered")
        _require_split(recovered, run.spec, stable=100, candidate=0)
        release = _release_claim(
            run,
            case,
            root=root_result.root,
            epoch=2,
            terminal_idempotency_key=terminal_idempotency_key,
            label="revoked",
        )
        released = True
        run.unreleased_root_ids.discard(root_result.root.root_id)
        run.revocation_root = root_result.root
        run.revocation_epoch = release.fenced_epoch
        run.advisor_command = advisor_command
        run.advisor_result = advisor_result
        pages, raw = _read_timeline_evidence(run)
        terminal_result = _terminal_result(
            pages, root_id=root_result.root.root_id, expected="DENIED"
        )
        capability_metadata = _verified_capability_metadata(
            pages=pages,
            raw=raw,
            root_id=root_result.root.root_id,
            capability_sha256s=frozenset(
                {
                    apply_dispatch.capability_sha256,
                    promotion_dispatch.capability_sha256,
                    recovery_dispatch.capability_sha256,
                }
            ),
        )
        from controlgraph_canary.contracts.codec import canonical_sha256
        from controlgraph_canary.contracts.public_replay import (
            PUBLIC_REPLAY_AUTHORITY_ADVANCED_V1,
            PUBLIC_REPLAY_RECOVERY_VERIFIED_V1,
            PUBLIC_REPLAY_STALE_DENIAL_V1,
            PUBLIC_REPLAY_TARGET_UNCHANGED_V1,
            PublicReplayAuthorityAdvancedV1,
            PublicReplayRecoveryVerifiedV1,
            PublicReplayStaleDenialV1,
            PublicReplayTargetUnchangedV1,
        )

        revocation_result = revocation.result
        run.public_replay_seed_values = _PublicReplaySeedState(
            authority_occurred_at=revocation_result.committed_at,
            denial_occurred_at=stale_receipt.receipt.updated_at,
            unchanged_observed_at=unchanged.observed_at,
            advisor_requested_at=advisor_command.requested_at,
            recovery_occurred_at=recovery_receipt.receipt.updated_at,
            authority=PublicReplayAuthorityAdvancedV1(
                schema_version=PUBLIC_REPLAY_AUTHORITY_ADVANCED_V1,
                previous_epoch=revocation_result.previous_epoch,
                new_epoch=revocation_result.new_epoch,
                cause="OPERATOR_REVOCATION",
                transition_sha256=canonical_sha256(revocation_result),
            ),
            denial=PublicReplayStaleDenialV1(
                schema_version=PUBLIC_REPLAY_STALE_DENIAL_V1,
                work_epoch=stale_receipt.receipt.epoch,
                current_authority_epoch=stale_receipt.receipt.observed_authority_epoch,
                outcome="DENIED",
                reason_code="EPOCH_MISMATCH",
                receipt_sha256=stale_receipt.receipt_sha256,
            ),
            unchanged=PublicReplayTargetUnchangedV1(
                schema_version=PUBLIC_REPLAY_TARGET_UNCHANGED_V1,
                before_denial=_public_traffic(before_denial),
                after_denial=_public_traffic(unchanged),
            ),
            recovery=PublicReplayRecoveryVerifiedV1(
                schema_version=PUBLIC_REPLAY_RECOVERY_VERIFIED_V1,
                outcome="VERIFIED",
                receipt_sha256=recovery_receipt.receipt_sha256,
                traffic=_public_traffic(recovered),
            ),
            advisor_causal_path_clause=advisor_causal_path_clause,
        )
        return _CaseOutcome(
            observations={
                EvidenceKind.AUTHORITY_TRANSITION: {
                    "outcome": _model_dict(revocation),
                    "proof": _model_dict(proof),
                },
                EvidenceKind.CLOUD_RUN_CONFIGURATION: recovered,
                EvidenceKind.DATA_PATH_PROBE: load,
                EvidenceKind.VERIFIED_CAPABILITY_METADATA: capability_metadata,
                EvidenceKind.EXECUTOR_EPOCH_CHECK: stale_receipt,
                EvidenceKind.STALE_DENIAL: stale_receipt,
                EvidenceKind.EXECUTION_RECEIPT: recovery_receipt,
                EvidenceKind.COORDINATOR: advisor_result,
                EvidenceKind.MODEL_AUDIT: advisor_result.response.audit,
                EvidenceKind.TIMELINE: _timeline_evidence(pages, release=release),
            },
            terminal_result=terminal_result,
        )
    finally:
        if terminal_idempotency_key is not None and not released:
            try:
                _release_claim(
                    run,
                    case,
                    root=root_result.root,
                    epoch=2,
                    terminal_idempotency_key=terminal_idempotency_key,
                    label="revoked-cleanup",
                )
                run.unreleased_root_ids.discard(root_result.root.root_id)
            except AcceptanceError as error:
                raise AcceptanceError("ACCEPTANCE_HOSTED_CLAIM_CLEANUP_FAILED") from error


def _runner_failure_observation(
    run: _HostedExecution,
    *,
    code: str,
    disposition: Literal["FAILED", "NOT_RUN"],
    reset_completed: bool,
) -> dict[str, object]:
    return {
        "code": code,
        "disposition": disposition,
        "execution_queue_cleanup_required": run.execution_queue_cleanup_required,
        "reset_completed": reset_completed,
        "schema_version": "controlgraph.acceptance-runner-failure/v1",
        "unreleased_root_ids": sorted(run.unreleased_root_ids),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url


_HTTP_OPENER = urllib.request.build_opener(_NoRedirect)


def _jwt_claims(token: str) -> dict[str, Any]:
    if token.count(".") != 2 or any(character.isspace() for character in token):
        raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID")
    try:
        encoded = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID") from error
    if not isinstance(value, dict):
        raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID")
    now = int(time.time())
    if (
        value.get("iss") not in {"accounts.google.com", "https://accounts.google.com"}
        or type(value.get("iat")) is not int
        or type(value.get("exp")) is not int
        or cast(int, value["iat"]) > now + 30
        or cast(int, value["exp"]) <= now + 30
        or cast(int, value["exp"]) - cast(int, value["iat"]) > 3_660
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID")
    return cast(dict[str, Any], value)


def _service_account_identity_token(
    run: _HostedExecution,
    *,
    service_account: str,
    audience: str,
) -> str:
    try:
        _, access_token_payload = _capture_process(
            ("gcloud", "auth", "print-access-token", run.acceptance_identity),
            repo=run.repo,
            timeout=60,
        )
        access_token = access_token_payload.decode("ascii").strip()
        if (
            not access_token
            or len(access_token) > MAX_ARTIFACT_BYTES
            or any(character.isspace() for character in access_token)
        ):
            raise ValueError
        body = json.dumps(
            {"audience": audience, "includeEmail": True},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        account = urllib.parse.quote(service_account, safe="")
        request = urllib.request.Request(
            "https://iamcredentials.googleapis.com/v1/"
            f"projects/-/serviceAccounts/{account}:generateIdToken",
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "User-Agent": "controlgraph-m8-core/1",
                "X-Goog-User-Project": run.spec.target.project_id,
            },
            method="POST",
        )
        response = _HTTP_OPENER.open(request, timeout=30)
        with response:
            if response.status != 200:
                raise ValueError
            payload = response.read(MAX_ARTIFACT_BYTES + 1)
        if len(payload) > MAX_ARTIFACT_BYTES:
            raise ValueError
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise TypeError
        token = value.get("token")
    except Exception as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID") from error
    if type(token) is not str or not token or any(character.isspace() for character in token):
        raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID")
    return token


def _identity_token(run: _HostedExecution, service_account: str | None = None) -> str:
    if service_account is None:
        _, payload = _capture_process(
            ("gcloud", "auth", "print-identity-token"), repo=run.repo, timeout=60
        )
        try:
            token = payload.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID") from error
    else:
        token = _service_account_identity_token(
            run,
            service_account=service_account,
            audience=run.api_origin,
        )
    claims = _jwt_claims(token)
    if service_account is not None and (
        claims.get("email") != service_account or claims.get("aud") != run.api_origin
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID")
    return token


def _http_request(
    *,
    url: str,
    token: str | None,
    operator: bool = False,
    raw_export: bool = False,
    body: bytes | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    from controlgraph_canary.http.identity_headers import (
        CONTROLGRAPH_AUTHORIZATION_HEADER,
        SERVERLESS_AUTHORIZATION_HEADER,
    )

    headers = {"Accept": "application/json", "User-Agent": "controlgraph-m8-core/1"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token is not None:
        if operator:
            headers[CONTROLGRAPH_AUTHORIZATION_HEADER] = f"Bearer {token}"
            headers[SERVERLESS_AUTHORIZATION_HEADER] = f"Bearer {token}"
        else:
            headers["Authorization"] = f"Bearer {token}"
    if raw_export:
        headers["X-ControlGraph-Raw-Export"] = "EXPORT_RESTRICTED_EVIDENCE_V1"
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST" if body is not None else "GET",
    )
    try:
        response = _HTTP_OPENER.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise AcceptanceError("ACCEPTANCE_HOSTED_HTTP_UNAVAILABLE") from error
    with response:
        payload = response.read(MAX_ARTIFACT_BYTES + 1)
        status = response.status
        response_headers = {name.lower(): value for name, value in response.headers.items()}
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID")
    return status, payload, response_headers


def _timeline_pages(run: _HostedExecution, token: str) -> tuple[Any, ...]:
    from controlgraph_canary.contracts.timeline import TimelinePageV1

    sequence = 0
    cursor: str | None = None
    pages: list[Any] = []
    head: tuple[int, str | None] | None = None
    for _page in range(100):
        query: list[tuple[str, str]] = [
            ("after_sequence", str(sequence)),
            ("limit", "25"),
            ("audience", "OPERATOR"),
        ]
        if cursor is not None:
            query.insert(1, ("after_entry_sha256", cursor))
        status, payload, headers = _http_request(
            url=f"{run.api_origin}/v1/operator/timeline?{urllib.parse.urlencode(query)}",
            token=token,
            operator=True,
        )
        if status != 200 or headers.get("cache-control") != "no-store":
            raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
        try:
            page = TimelinePageV1.model_validate_json(payload)
        except (TypeError, ValueError, ValidationError) as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID") from error
        observed_head = (page.head_sequence, page.head_entry_sha256)
        head = observed_head if head is None else head
        if observed_head != head:
            raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_CHANGED")
        pages.append(page)
        sequence = page.next_after_sequence
        cursor = page.next_after_entry_sha256
        if not page.has_more:
            return tuple(pages)
    raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_TOO_LARGE")


def _raw_timeline(run: _HostedExecution, token: str) -> tuple[Any, ...]:
    from controlgraph_canary.contracts.timeline import TimelineRawExportV1

    sequence = 0
    cursor: str | None = None
    items: list[Any] = []
    head: tuple[int, str | None] | None = None
    for _page in range(1_000):
        query: list[tuple[str, str]] = [
            ("after_sequence", str(sequence)),
            ("limit", "1"),
        ]
        if cursor is not None:
            query.insert(1, ("after_entry_sha256", cursor))
        status, payload, headers = _http_request(
            url=f"{run.api_origin}/v1/operator/timeline/raw-export?{urllib.parse.urlencode(query)}",
            token=token,
            raw_export=True,
        )
        if status != 200 or headers.get("cache-control") != "no-store":
            raise AcceptanceError("ACCEPTANCE_HOSTED_RAW_EXPORT_INVALID")
        try:
            page = TimelineRawExportV1.model_validate_json(payload)
        except (TypeError, ValueError, ValidationError) as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_RAW_EXPORT_INVALID") from error
        observed_head = (page.head_sequence, page.head_entry_sha256)
        head = observed_head if head is None else head
        if observed_head != head:
            raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_CHANGED")
        items.extend(page.entries)
        sequence = page.next_after_sequence
        cursor = page.next_after_entry_sha256
        if not page.has_more:
            return tuple(items)
    raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_TOO_LARGE")


def _available_raw_records(items: Sequence[Any]) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    for item in items:
        if item.canonical_record is None:
            continue
        try:
            parsed = json.loads(item.canonical_record)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_RAW_EXPORT_INVALID") from error
        if not isinstance(parsed, dict):
            raise AcceptanceError("ACCEPTANCE_HOSTED_RAW_EXPORT_INVALID")
        records.append(cast(dict[str, Any], parsed))
    return tuple(records)


def _read_timeline_evidence(
    run: _HostedExecution,
) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    operator_token = _identity_token(run)
    exporter_token = _identity_token(run, run.restricted_exporter_service_account)
    try:
        pages = _timeline_pages(run, operator_token)
        raw = _raw_timeline(run, exporter_token)
    finally:
        operator_token = ""
        exporter_token = ""
    if not pages or not raw:
        raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
    return pages, raw


def _read_operator_timeline(run: _HostedExecution) -> tuple[Any, ...]:
    token = _identity_token(run)
    try:
        pages = _timeline_pages(run, token)
    finally:
        token = ""
    if not pages:
        raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
    return pages


def _timeline_page_summary(pages: Sequence[Any]) -> dict[str, object]:
    if not pages:
        raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
    first = pages[0]
    audience = first.command.audience
    expected_sequence = first.command.after_sequence
    expected_entry_sha256 = first.command.after_entry_sha256
    head = (first.head_sequence, first.head_entry_sha256)
    if expected_sequence != 0 or expected_entry_sha256 is not None:
        raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
    summaries: list[dict[str, object]] = []
    page_sha256s: list[str] = []
    entry_count = 0
    for page in pages:
        if (
            (page.head_sequence, page.head_entry_sha256) != head
            or page.command.audience != audience
            or page.command.after_sequence != expected_sequence
            or page.command.after_entry_sha256 != expected_entry_sha256
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
        page_sequence = page.command.after_sequence
        page_entry_sha256 = page.command.after_entry_sha256
        for entry in page.entries:
            page_sequence += 1
            if entry.sequence != page_sequence or entry.previous_entry_sha256 != page_entry_sha256:
                raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
            page_entry_sha256 = entry.entry_sha256
        if (
            page.next_after_sequence != page_sequence
            or page.next_after_entry_sha256 != page_entry_sha256
            or page.has_more != (page.next_after_sequence < head[0])
        ):
            raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
        page_sha256 = hashlib.sha256(_canonical_object(_model_dict(page))).hexdigest()
        page_sha256s.append(page_sha256)
        summaries.append(
            {
                "after_entry_sha256": page.command.after_entry_sha256,
                "after_sequence": page.command.after_sequence,
                "entry_count": len(page.entries),
                "next_after_entry_sha256": page.next_after_entry_sha256,
                "next_after_sequence": page.next_after_sequence,
                "page_sha256": page_sha256,
            }
        )
        entry_count += len(page.entries)
        expected_sequence = page.next_after_sequence
        expected_entry_sha256 = page.next_after_entry_sha256
    if pages[-1].has_more or expected_sequence != head[0] or expected_entry_sha256 != head[1]:
        raise AcceptanceError("ACCEPTANCE_HOSTED_TIMELINE_INVALID")
    return {
        "audience": audience.value,
        "entry_count": entry_count,
        "head_entry_sha256": head[1],
        "head_sequence": head[0],
        "page_count": len(pages),
        "page_bindings": tuple(summaries),
        "page_set_sha256": hashlib.sha256(
            _TIMELINE_PAGE_SET_DOMAIN
            + canonical_json_value_bytes(cast(RestrictedJson, page_sha256s))
        ).hexdigest(),
        "schema_version": "controlgraph.timeline-page-summary/v1",
    }


def _timeline_evidence(
    pages: Sequence[Any],
    *,
    release: Any | None = None,
) -> dict[str, object]:
    return {
        "release": _model_dict(release) if release is not None else None,
        "schema_version": "controlgraph.timeline-acceptance-evidence/v1",
        "summary": _timeline_page_summary(pages),
    }


def _verified_capability_metadata(
    *,
    pages: Sequence[Any],
    raw: Sequence[Any],
    root_id: str,
    capability_sha256s: frozenset[str],
) -> dict[str, object]:
    from controlgraph_canary.contracts.timeline import (
        TimelineEventType,
        TimelineRedactedSourceV1,
        TimelineVerificationStatus,
    )

    projections = {
        entry.entry_id: entry
        for page in pages
        for entry in page.entries
        if entry.root_id == root_id
        and entry.event_type is TimelineEventType.CAPABILITY_ISSUED
        and entry.verification_status is TimelineVerificationStatus.VERIFIED
        and entry.signature is not None
        and entry.signature.purpose == "CAPABILITY"
    }
    matched: dict[str, dict[str, object]] = {}
    for item in raw:
        if item.entry_id not in projections or item.canonical_record is None:
            continue
        try:
            redacted = TimelineRedactedSourceV1.model_validate_json(item.canonical_record)
        except (TypeError, ValueError, ValidationError) as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_CAPABILITY_EVIDENCE_INVALID") from error
        if redacted.source_sha256 in capability_sha256s:
            matched[redacted.source_sha256] = {
                "projection": projections[item.entry_id],
                "redacted_source": redacted,
            }
    if frozenset(matched) != capability_sha256s:
        raise AcceptanceError("ACCEPTANCE_HOSTED_CAPABILITY_EVIDENCE_INVALID")
    return {
        "capabilities": tuple(matched[digest] for digest in sorted(matched)),
        "schema_version": "controlgraph.verified-capability-metadata-set/v1",
    }


def _terminal_result(pages: Sequence[Any], *, root_id: str, expected: str) -> str:
    from controlgraph_canary.contracts.timeline import (
        TimelineEventType,
        TimelineVerificationStatus,
    )

    matches = [
        entry
        for page in pages
        for entry in page.entries
        if entry.root_id == root_id
        and entry.event_type is TimelineEventType.TERMINAL_CLASSIFIED
        and entry.verification_status is TimelineVerificationStatus.VERIFIED
        and entry.terminal_classification.value == expected
    ]
    if not matches:
        raise AcceptanceError("ACCEPTANCE_HOSTED_TERMINAL_RESULT_MISSING")
    return cast(
        str,
        max(matches, key=lambda entry: entry.sequence).terminal_classification.value,
    )


def _run_verifier_case(
    run: _HostedExecution,
    case: CaseBindingV1,
    reset: Any,
) -> _CaseOutcome:
    from controlgraph_canary.contracts.independent_verification import (
        VerifiedIndependentVerificationEvidenceV1,
    )

    pages, raw = _read_timeline_evidence(run)
    verified_by_request: dict[str, list[Any]] = {}
    for record in _available_raw_records(raw):
        if record.get("schema_version") != (
            "controlgraph.verified-independent-verification-evidence/v1"
        ):
            continue
        try:
            item = VerifiedIndependentVerificationEvidenceV1.model_validate(record)
        except (TypeError, ValueError, ValidationError) as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_VERIFICATION_INVALID") from error
        evidence = item.signing_request.evidence
        if evidence.root_id in run.root_ids and evidence.verdict.value == "MATCH":
            verified_by_request.setdefault(evidence.verification_request_sha256, []).append(item)
    coherent: list[tuple[Any, Any]] = []
    for items in verified_by_request.values():
        configuration = next(
            (item for item in items if item.signing_request.evidence.kind.value == "CONFIGURATION"),
            None,
        )
        probe = next(
            (
                item
                for item in items
                if item.signing_request.evidence.kind.value == "PROBE"
                and item.signing_request.probe is not None
                and len(item.signing_request.probe.observation.samples) == 20
            ),
            None,
        )
        if configuration is not None and probe is not None:
            coherent.append((configuration, probe))
    if not coherent:
        raise AcceptanceError("ACCEPTANCE_HOSTED_VERIFICATION_INVALID")
    configuration, probe = max(
        coherent,
        key=lambda pair: pair[1].signing_request.evidence.occurred_at,
    )
    return _CaseOutcome(
        observations={
            EvidenceKind.CLOUD_RUN_CONFIGURATION: reset,
            EvidenceKind.DATA_PATH_PROBE: probe,
            EvidenceKind.INDEPENDENT_VERIFICATION: (configuration, probe),
            EvidenceKind.TIMELINE: _timeline_evidence(pages),
        },
        terminal_result="VERIFIED",
    )


def _run_ambiguity_case(
    run: _HostedExecution,
    case: CaseBindingV1,
    reset: Any,
) -> _CaseOutcome:
    from controlgraph_canary.contracts.independent_verification import (
        COMPLETION_EVIDENCE_BUNDLE_V1,
        CompletionClassificationV1,
        CompletionEvidenceBundleV1,
    )
    from controlgraph_canary.contracts.models import ExecutionReceipt

    pages, raw = _read_timeline_evidence(run)
    records = _available_raw_records(raw)
    source: Any | None = None
    for record in reversed(records):
        if record.get("schema_version") != "controlgraph.completion-classification/v1":
            continue
        try:
            candidate = CompletionClassificationV1.model_validate(record)
        except (TypeError, ValueError, ValidationError) as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_CLASSIFICATION_INVALID") from error
        if candidate.request.verification.root_id in run.root_ids:
            source = candidate
            break
    if source is None:
        raise AcceptanceError("ACCEPTANCE_HOSTED_CLASSIFICATION_INVALID")
    receipt: Any | None = None
    for record in reversed(records):
        if record.get("schema_version") != "controlgraph.execution-receipt/v1":
            continue
        try:
            candidate_receipt = ExecutionReceipt.model_validate(record)
        except (TypeError, ValueError, ValidationError) as error:
            raise AcceptanceError("ACCEPTANCE_HOSTED_RECEIPT_INVALID") from error
        verification = source.request.verification
        if (
            candidate_receipt.root_id == verification.root_id
            and candidate_receipt.root_sha256 == verification.root_sha256
            and candidate_receipt.request_id == verification.request_id
            and candidate_receipt.epoch == verification.epoch
            and candidate_receipt.action == verification.action
        ):
            receipt = candidate_receipt
            break
    if receipt is None:
        raise AcceptanceError("ACCEPTANCE_HOSTED_RECEIPT_INVALID")
    bundle = CompletionEvidenceBundleV1(
        schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
        request=source.request,
    )
    path = run.command_path(case, "ambiguity-bundle")
    _write_command(path, bundle)
    _, _, classification = _run_cli(
        repo=run.repo,
        entry_point="controlgraph-canary",
        arguments=("classify-completion", "--bundle-file", str(path)),
        model_type=CompletionClassificationV1,
    )
    assert classification is not None
    if classification.status.value != "AMBIGUOUS" or not classification.follow_up_required:
        raise AcceptanceError("ACCEPTANCE_HOSTED_CLASSIFICATION_INVALID")
    return _CaseOutcome(
        observations={
            EvidenceKind.CLOUD_RUN_CONFIGURATION: reset,
            EvidenceKind.EXECUTION_RECEIPT: receipt,
            EvidenceKind.AMBIGUITY_CLASSIFICATION: classification,
            EvidenceKind.TIMELINE: _timeline_evidence(pages),
        },
        terminal_result=classification.status.value,
    )


def _run_timeline_console_case(
    run: _HostedExecution,
    case: CaseBindingV1,
) -> _CaseOutcome:
    del case
    pages = _read_operator_timeline(run)
    status, body, headers = _http_request(url=f"{run.console_origin}/", token=None)
    content_type = headers.get("content-type", "").split(";", 1)[0].lower()
    if (
        status != 200
        or not body
        or content_type != "text/html"
        or headers.get("cache-control") != "no-store"
        or "frame-ancestors 'none'" not in headers.get("content-security-policy", "")
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_CONSOLE_INVALID")
    console = {
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "byte_count": len(body),
        "cache_control": headers["cache-control"],
        "content_security_policy": headers["content-security-policy"],
        "schema_version": "controlgraph.hosted-console-observation/v1",
        "status_code": status,
    }
    return _CaseOutcome(
        observations={
            EvidenceKind.TIMELINE: _timeline_evidence(pages),
            EvidenceKind.CONSOLE_READ: console,
        },
        terminal_result="READABLE",
    )


def _run_advisor_case(
    run: _HostedExecution,
    case: CaseBindingV1,
    baseline: Any,
) -> _CaseOutcome:
    from controlgraph_canary.contracts.public_replay import (
        PUBLIC_REPLAY_ADVISOR_VALIDATED_V1,
        PUBLIC_REPLAY_SEED_V1,
        PUBLIC_REPLAY_TIMELINE_COMMITTED_V1,
        PublicReplayAdvisorValidatedV1,
        PublicReplaySeedV1,
        PublicReplayTimelineCommittedV1,
    )

    if (
        run.revocation_root is None
        or run.advisor_command is None
        or run.advisor_result is None
        or run.public_replay_seed_values is None
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_ADVISOR_INPUT_UNAVAILABLE")
    result = _invoke_advisor(run, run.advisor_command)
    _validate_advisor_result(
        run.advisor_command,
        result,
        replayed=True,
        original=run.advisor_result,
        expected_causal_path_clause=(run.public_replay_seed_values.advisor_causal_path_clause),
    )
    after = _read_traffic(run, case, "after-advisor")
    if (
        after.provider_etag != baseline.provider_etag
        or after.service_generation != baseline.service_generation
        or after.target_configuration_sha256 != baseline.target_configuration_sha256
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_ADVISOR_MUTATED_TARGET")
    pages = _read_operator_timeline(run)
    timeline_observed_at = _utc_now()
    seed_values = run.public_replay_seed_values
    seed = PublicReplaySeedV1(
        schema_version=PUBLIC_REPLAY_SEED_V1,
        authority_occurred_at=seed_values.authority_occurred_at,
        denial_occurred_at=seed_values.denial_occurred_at,
        unchanged_observed_at=seed_values.unchanged_observed_at,
        advisor_requested_at=seed_values.advisor_requested_at,
        recovery_occurred_at=seed_values.recovery_occurred_at,
        authority=seed_values.authority,
        denial=seed_values.denial,
        unchanged=seed_values.unchanged,
        advisor=PublicReplayAdvisorValidatedV1(
            schema_version=PUBLIC_REPLAY_ADVISOR_VALIDATED_V1,
            advisor=_public_advisor(
                run.advisor_command,
                run.advisor_result,
                result,
                expected_causal_path_clause=(seed_values.advisor_causal_path_clause),
            ),
        ),
        recovery=seed_values.recovery,
        timeline_observed_at=timeline_observed_at,
        timeline=PublicReplayTimelineCommittedV1(
            schema_version=PUBLIC_REPLAY_TIMELINE_COMMITTED_V1,
            timeline=_public_timeline(pages, root_id=run.revocation_root.root_id),
        ),
    )
    return _CaseOutcome(
        observations={
            EvidenceKind.COORDINATOR: result,
            EvidenceKind.MODEL_AUDIT: result.response.audit,
            EvidenceKind.PUBLIC_REPLAY_SEED: seed,
            EvidenceKind.TIMELINE: _timeline_evidence(pages),
        },
        terminal_result="ADVISORY_ONLY",
    )


def _json_value(value: object) -> RestrictedJson:
    if isinstance(value, StrictContractModel):
        return cast(RestrictedJson, value.model_dump(mode="json"))
    if isinstance(value, StrEnum):
        return value.value
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, Mapping):
        converted: dict[str, RestrictedJson] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID")
            converted[key] = _json_value(nested)
        return converted
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    raise AcceptanceError("ACCEPTANCE_HOSTED_RESPONSE_INVALID")


def _new_artifact_path(root: Path, relative_path: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative_path).parts)
    current = root
    for part in PurePosixPath(relative_path).parts[:-1]:
        current = current / part
        if current.exists() and (current.is_symlink() or not current.is_dir()):
            raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID")
        if not current.exists():
            current.mkdir(mode=0o700)
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as error:
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID") from error
    if not parent.is_relative_to(root) or candidate.exists() or candidate.is_symlink():
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID")
    return candidate


def _write_case_result(
    run: _HostedExecution,
    case: CaseBindingV1,
    observations: Mapping[EvidenceKind, object],
    *,
    started: datetime,
    completed: datetime,
    status: ResultStatus,
    observed_result: str,
    reset_duration_ms: int,
    flow_duration_ms: int,
    reset_succeeded: bool,
) -> CaseBindingV1:
    required = REQUIRED_EVIDENCE[case.kind]
    if status is ResultStatus.PASSED and set(observations) != set(required):
        raise AcceptanceError("ACCEPTANCE_HOSTED_EVIDENCE_INCOMPLETE")
    if status is ResultStatus.FAILED and set(observations) != {EvidenceKind.RUNNER_FAILURE}:
        raise AcceptanceError("ACCEPTANCE_HOSTED_EVIDENCE_INCOMPLETE")
    observed_at = _utc(completed)
    evidence: list[EvidenceBindingV1] = []
    for ordinal, kind in enumerate(sorted(observations, key=lambda value: value.value), start=1):
        slug = kind.value.lower().replace("_", "-")
        evidence_id = _stable_id(run.run_inputs_sha256, case, f"evidence-{slug}")
        relative_path = f"evidence/{case.sequence:02d}-{slug}.json"
        payload = _canonical_object(
            {
                "case_id": case.case_id,
                "evidence_id": evidence_id,
                "kind": kind.value,
                "observed_at": observed_at,
                "ordinal": ordinal,
                "run_inputs_sha256": run.run_inputs_sha256,
                "schema_version": "controlgraph.hosted-acceptance-observation/v1",
                "source": {
                    "observation": _json_value(observations[kind]),
                    "schema_version": _evidence_source_schema(kind),
                },
            }
        )
        path = _new_artifact_path(run.artifact_root, relative_path)
        _write_once(path, payload)
        artifact = ArtifactBindingV1(
            schema_version="controlgraph.acceptance-artifact-binding/v1",
            artifact_id=_stable_id(run.run_inputs_sha256, case, f"artifact-{slug}"),
            relative_path=relative_path,
            sha256=hashlib.sha256(payload).hexdigest(),
            media_type="application/json",
        )
        evidence.append(
            EvidenceBindingV1(
                schema_version="controlgraph.acceptance-evidence-binding/v1",
                evidence_id=evidence_id,
                kind=kind,
                observed_at=observed_at,
                projection=(
                    EvidenceProjection.PUBLIC_REDACTED
                    if kind is EvidenceKind.PUBLIC_REPLAY_SEED
                    else EvidenceProjection.PRIVATE_DIGEST_ONLY
                ),
                run_inputs_sha256=run.run_inputs_sha256,
                artifact=artifact,
            )
        )
    evidence_ids = tuple(item.evidence_id for item in evidence)
    operations = ENTRY_POINTS[case.kind]
    step_evidence: tuple[tuple[str, ...], tuple[str, ...]]
    if status is ResultStatus.PASSED:
        configuration_id = next(
            item.evidence_id
            for item in evidence
            if item.kind is EvidenceKind.CLOUD_RUN_CONFIGURATION
        )
        step_evidence = ((configuration_id,), evidence_ids)
        step_statuses = (ResultStatus.PASSED, ResultStatus.PASSED)
    else:
        step_evidence = (evidence_ids, evidence_ids)
        step_statuses = (
            ResultStatus.PASSED if reset_succeeded else ResultStatus.FAILED,
            ResultStatus.FAILED,
        )
    step_durations = (reset_duration_ms, flow_duration_ms)
    steps = tuple(
        StepResultV1(
            schema_version="controlgraph.core-acceptance-step-result/v1",
            sequence=sequence,
            operation=operation,
            status=step_statuses[sequence - 1],
            duration_ms=step_durations[sequence - 1],
            evidence_ids=step_evidence[sequence - 1],
        )
        for sequence, operation in enumerate(operations, start=1)
    )
    duration_ms = max(
        reset_duration_ms + flow_duration_ms,
        int((completed - started).total_seconds() * 1_000),
    )
    result = CoreAcceptanceCaseResultV1(
        schema_version="controlgraph.core-acceptance-case-result/v1",
        case_id=case.case_id,
        kind=case.kind,
        execution_mode="HOSTED_GOOGLE_CLOUD",
        source_commit=run.spec.source_commit,
        run_inputs_sha256=run.run_inputs_sha256,
        target=run.spec.target,
        random_seed=case.random_seed,
        test_clock_keys=case.test_clock_keys,
        status=status,
        observed_result=observed_result,
        started_at=_utc(started),
        completed_at=_utc(completed),
        duration_ms=duration_ms,
        cost_microusd=case.maximum_cost_microusd,
        cost_basis=CostBasis.UPPER_BOUND,
        steps=steps,
        evidence=tuple(evidence),
    )
    payload = _canonical_object(_model_dict(result))
    destination = _new_artifact_path(run.artifact_root, case.result.relative_path)
    _write_once(destination, payload)
    return case.model_copy(
        update={
            "result": case.result.model_copy(update={"sha256": hashlib.sha256(payload).hexdigest()})
        }
    )


def _input_artifact_binding(
    *,
    artifact_root: Path,
    artifact_id: str,
    relative_path: str,
) -> ArtifactBindingV1:
    try:
        normalized = _relative_artifact_path(relative_path)
    except ValueError as error:
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_INVALID") from error
    payload = _read_regular_file(
        _artifact_path(artifact_root, normalized),
        maximum_bytes=MAX_ARTIFACT_BYTES,
        error_code="ACCEPTANCE_ARTIFACT_INVALID",
    )
    return ArtifactBindingV1(
        schema_version="controlgraph.acceptance-artifact-binding/v1",
        artifact_id=artifact_id,
        relative_path=normalized,
        sha256=hashlib.sha256(payload).hexdigest(),
        media_type="application/json",
    )


def generate_spec_template(
    *,
    artifact_root: Path,
    output: Path,
    project_id: str,
    source_commit: str,
    stable_revision: str,
    candidate_revision: str,
    image_references: Mapping[ImageComponent, str],
    terraform_plan_path: str,
    policy_schema_version: str,
    policy_path: str,
    clock_start: str,
    random_seed: int,
) -> bytes:
    """Generate the complete deterministic eight-case input template."""

    try:
        root = artifact_root.resolve(strict=True)
    except OSError as error:
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_ROOT_INVALID") from error
    if artifact_root.is_symlink() or not root.is_dir():
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_ROOT_INVALID")
    if output.exists() or output.is_symlink():
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID")
    try:
        start = _parse_utc(clock_start)
    except AcceptanceError as error:
        raise AcceptanceError("ACCEPTANCE_TEMPLATE_CLOCK_INVALID") from error
    ticks: list[TestClockTickV1] = []
    cases: list[CaseBindingV1] = []
    for sequence, kind in enumerate(CORE_CASE_ORDER, start=1):
        slug = kind.value.lower().replace("_", "-")
        clock_key = f"case-{sequence:02d}-start"
        ticks.append(
            TestClockTickV1(
                schema_version="controlgraph.acceptance-test-clock-tick/v1",
                name=clock_key,
                at=_utc(start + timedelta(seconds=sequence - 1)),
            )
        )
        seed = int.from_bytes(
            hashlib.sha256(f"{random_seed}\0{kind.value}".encode("ascii")).digest()[:6],
            "big",
        )
        cases.append(
            CaseBindingV1(
                schema_version="controlgraph.core-acceptance-case-binding/v1",
                sequence=sequence,
                case_id=f"core-{sequence:02d}-{slug}",
                kind=kind,
                random_seed=seed,
                test_clock_keys=(clock_key,),
                maximum_duration_ms=30 * 60 * 1_000,
                maximum_cost_microusd=1_000_000,
                result=ArtifactBindingV1(
                    schema_version="controlgraph.acceptance-artifact-binding/v1",
                    artifact_id=f"result-{sequence:02d}-{slug}",
                    relative_path=f"results/{sequence:02d}-{slug}.json",
                    sha256=_ZERO_SHA256,
                    media_type="application/json",
                ),
            )
        )
    try:
        spec = CoreAcceptanceRunSpecV1(
            schema_version="controlgraph.core-acceptance-run-spec/v1",
            source_commit=source_commit,
            target=AcceptanceTargetV1(
                schema_version="controlgraph.acceptance-target/v1",
                project_id=project_id,
                region="us-central1",
                environment="nonprod",
                service_name="controlgraph-reference-target",
                stable_revision=stable_revision,
                candidate_revision=candidate_revision,
            ),
            images=tuple(
                ImageBindingV1(
                    schema_version="controlgraph.acceptance-image/v1",
                    component=component,
                    reference=image_references[component],
                )
                for component in ImageComponent
            ),
            terraform_plan=_input_artifact_binding(
                artifact_root=root,
                artifact_id="terraform-plan",
                relative_path=terraform_plan_path,
            ),
            policies=(
                PolicyBindingV1(
                    schema_version="controlgraph.acceptance-policy-binding/v1",
                    policy_schema_version=policy_schema_version,
                    artifact=_input_artifact_binding(
                        artifact_root=root,
                        artifact_id="health-policy",
                        relative_path=policy_path,
                    ),
                ),
            ),
            random_seed=random_seed,
            test_clock=TestClockV1(
                schema_version="controlgraph.acceptance-test-clock/v1",
                ticks=tuple(ticks),
            ),
            maximum_total_duration_ms=MAX_RUN_DURATION_MS,
            maximum_total_cost_microusd=8_000_000,
            cases=tuple(cases),
        )
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        raise AcceptanceError("ACCEPTANCE_TEMPLATE_INVALID") from error
    payload = _canonical_object(_model_dict(spec))
    _write_once(output, payload)
    return payload


def _verify_exact_remote_main(repo: Path, source_commit: str) -> None:
    try:
        local = subprocess.run(
            ("git", "-C", str(repo), "rev-parse", "origin/main"),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        remote = subprocess.run(
            ("git", "-C", str(repo), "ls-remote", "origin", "refs/heads/main"),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AcceptanceError("ACCEPTANCE_SOURCE_INVALID") from error
    if (
        local.returncode != 0
        or remote.returncode != 0
        or local.stdout.strip() != source_commit
        or not remote.stdout.startswith(f"{source_commit}\t")
    ):
        raise AcceptanceError("ACCEPTANCE_SOURCE_NOT_EXACT_MAIN")


def _verify_hosted_bindings(run: _HostedExecution) -> None:
    accounts = _gcloud_json(
        ("auth", "list", "--filter=status:ACTIVE"),
        repo=run.repo,
    )
    if (
        not isinstance(accounts, list)
        or len(accounts) != 1
        or not isinstance(accounts[0], dict)
        or accounts[0].get("account") != run.acceptance_identity
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID")
    project = _gcloud_json(
        ("projects", "describe", run.spec.target.project_id),
        repo=run.repo,
    )
    if not isinstance(project, dict) or str(project.get("projectNumber")) != run.project_number:
        raise AcceptanceError("ACCEPTANCE_HOSTED_PROJECT_MISMATCH")
    expected_accounts = {
        run.verifier_service_account: "controlgraph-verifier",
        run.restricted_exporter_service_account: "cg-restricted-exporter",
    }
    for account, name in expected_accounts.items():
        if account != f"{name}@{run.spec.target.project_id}.iam.gserviceaccount.com":
            raise AcceptanceError("ACCEPTANCE_HOSTED_IDENTITY_INVALID")
    project_marker = f"projects/{run.spec.target.project_id}/"
    if (
        project_marker not in run.network_resource
        or "/global/networks/" not in run.network_resource
        or project_marker not in run.subnetwork_resource
        or f"/regions/{run.spec.target.region}/subnetworks/" not in run.subnetwork_resource
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_NETWORK_INVALID")
    service_images = {
        **{
            role: _image(run.spec, ImageComponent.CONTROLLER)
            for role in (
                "api",
                "coordinator",
                "issuer",
                "executor",
                "recovery",
                "verifier",
                "evidence-writer",
            )
        },
        "advisor": _image(run.spec, ImageComponent.ADVISOR),
        "console": _image(run.spec, ImageComponent.CONSOLE),
    }
    for role, image in service_images.items():
        document = _gcloud_json(
            (
                "run",
                "services",
                "describe",
                f"controlgraph-{role}",
                f"--project={run.spec.target.project_id}",
                f"--region={run.spec.target.region}",
            ),
            repo=run.repo,
        )
        if not isinstance(document, dict):
            raise AcceptanceError("ACCEPTANCE_HOSTED_IMAGE_MISMATCH")
        specification = document.get("spec")
        template = specification.get("template") if isinstance(specification, dict) else None
        template_spec = template.get("spec") if isinstance(template, dict) else None
        if not isinstance(template_spec, dict):
            template_spec = document.get("template")
        containers = template_spec.get("containers") if isinstance(template_spec, dict) else None
        service_account = None
        if isinstance(template_spec, dict):
            service_account = template_spec.get(
                "serviceAccountName", template_spec.get("serviceAccount")
            )
        deployed_images = (
            tuple(
                container.get("image")
                for container in containers
                if isinstance(container, dict) and isinstance(container.get("image"), str)
            )
            if isinstance(containers, list)
            else ()
        )
        account_id = "cg-evidence-writer" if role == "evidence-writer" else f"controlgraph-{role}"
        expected_service_account = (
            f"{account_id}@{run.spec.target.project_id}.iam.gserviceaccount.com"
        )
        if deployed_images != (image,) or service_account != expected_service_account:
            raise AcceptanceError("ACCEPTANCE_HOSTED_IMAGE_MISMATCH")
        run.service_bindings[role] = {
            "image": image,
            "service_account": expected_service_account,
        }


def _validate_execute_destination(path: Path, repo: Path) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID") from error
    if parent.is_relative_to(repo):
        raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID")


def execute_hosted(
    *,
    spec_path: Path,
    artifact_root: Path,
    output_spec: Path,
    output_manifest: Path,
    project_number: str,
    network_resource: str,
    subnetwork_resource: str,
    verifier_service_account: str,
    restricted_exporter_service_account: str,
    acceptance_identity: str,
    confirmation: str,
) -> tuple[bytes, str, ResultStatus]:
    """Run the fixed hosted suite and feed its typed observations to the binder."""

    if (
        confirmation != EXECUTE_CONFIRMATION
        or os.environ.get(EXECUTE_CONFIRMATION_ENV) != EXECUTE_CONFIRMATION
    ):
        raise AcceptanceError("ACCEPTANCE_HOSTED_CONFIRMATION_REQUIRED")
    if re.fullmatch(r"[1-9][0-9]{5,19}", project_number) is None:
        raise AcceptanceError("ACCEPTANCE_HOSTED_PROJECT_MISMATCH")
    _, spec = _load_contract(
        spec_path,
        CoreAcceptanceRunSpecV1,
        error_code="ACCEPTANCE_SPEC_INVALID",
    )
    repo = Path(__file__).resolve().parents[1]
    _verify_source(repo, spec.source_commit)
    _verify_exact_remote_main(repo, spec.source_commit)
    try:
        root = artifact_root.resolve(strict=True)
    except OSError as error:
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_ROOT_INVALID") from error
    if artifact_root.is_symlink() or not root.is_dir() or root.is_relative_to(repo):
        raise AcceptanceError("ACCEPTANCE_ARTIFACT_ROOT_INVALID")
    _validate_execute_destination(output_spec, repo)
    _validate_execute_destination(output_manifest, repo)
    _bind_artifact(spec.terraform_plan, artifact_root=root)
    for policy in spec.policies:
        _bind_artifact(policy.artifact, artifact_root=root)
    if any(case.result.sha256 != _ZERO_SHA256 for case in spec.cases):
        raise AcceptanceError("ACCEPTANCE_HOSTED_TEMPLATE_ALREADY_BOUND")
    for case in spec.cases:
        candidate = root.joinpath(*PurePosixPath(case.result.relative_path).parts)
        if candidate.exists() or candidate.is_symlink():
            raise AcceptanceError("ACCEPTANCE_OUTPUT_INVALID")
    run = _HostedExecution(
        repo=repo,
        artifact_root=root,
        spec=spec,
        run_inputs_sha256=_run_inputs_sha256(spec),
        project_number=project_number,
        network_resource=network_resource,
        subnetwork_resource=subnetwork_resource,
        verifier_service_account=verifier_service_account,
        restricted_exporter_service_account=restricted_exporter_service_account,
        acceptance_identity=acceptance_identity,
    )
    _verify_hosted_bindings(run)
    updated_cases: list[CaseBindingV1] = []
    for case_index, case in enumerate(spec.cases):
        started = datetime.now(UTC)
        reset_started = time.monotonic_ns()
        flow_started = reset_started
        reset_duration_ms = 0
        flow_duration_ms = 0
        reset_succeeded = False
        try:
            reset = _reset_target(run, case)
            reset_duration_ms = max(0, (time.monotonic_ns() - reset_started) // 1_000_000)
            reset_succeeded = True
            flow_started = time.monotonic_ns()
            if case.kind is CaseKind.TARGET_RESET:
                probe = _probe_stable(run, case)
                outcome = _CaseOutcome(
                    observations={
                        EvidenceKind.CLOUD_RUN_CONFIGURATION: reset,
                        EvidenceKind.DATA_PATH_PROBE: probe,
                    },
                    terminal_result=(
                        "RESET_VERIFIED" if probe.get("status") == "COMPLETE" else "FAILED_SAFE"
                    ),
                )
            elif case.kind is CaseKind.HEALTHY_PROMOTION:
                outcome = _run_healthy_case(run, case)
            elif case.kind is CaseKind.UNHEALTHY_STABLE_RECOVERY:
                outcome = _run_unhealthy_case(run, case)
            elif case.kind is CaseKind.REVOCATION_STALE_DENIAL:
                outcome = _run_revocation_case(run, case)
            elif case.kind is CaseKind.INDEPENDENT_VERIFIER_PROBE:
                outcome = _run_verifier_case(run, case, reset)
            elif case.kind is CaseKind.AMBIGUITY_CLASSIFICATION:
                outcome = _run_ambiguity_case(run, case, reset)
            elif case.kind is CaseKind.TIMELINE_CONSOLE_READ:
                outcome = _run_timeline_console_case(run, case)
            else:
                outcome = _run_advisor_case(run, case, reset)
            flow_duration_ms = max(0, (time.monotonic_ns() - flow_started) // 1_000_000)
            completed = datetime.now(UTC)
            elapsed_ms = max(
                reset_duration_ms + flow_duration_ms,
                int((completed - started).total_seconds() * 1_000),
            )
            if elapsed_ms > case.maximum_duration_ms:
                raise AcceptanceError("ACCEPTANCE_HOSTED_CASE_DURATION_EXCEEDED")
            observations = dict(outcome.observations)
            terminal_configuration = observations.get(EvidenceKind.CLOUD_RUN_CONFIGURATION, reset)
            observations[EvidenceKind.CLOUD_RUN_CONFIGURATION] = {
                "reset": reset,
                "terminal": terminal_configuration,
            }
            updated_cases.append(
                _write_case_result(
                    run,
                    case,
                    observations,
                    started=started,
                    completed=completed,
                    status=ResultStatus.PASSED,
                    observed_result=outcome.terminal_result,
                    reset_duration_ms=reset_duration_ms,
                    flow_duration_ms=flow_duration_ms,
                    reset_succeeded=True,
                )
            )
        except AcceptanceError as error:
            completed = datetime.now(UTC)
            if reset_succeeded:
                flow_duration_ms = max(0, (time.monotonic_ns() - flow_started) // 1_000_000)
            else:
                reset_duration_ms = max(0, (time.monotonic_ns() - reset_started) // 1_000_000)
            updated_cases.append(
                _write_case_result(
                    run,
                    case,
                    {
                        EvidenceKind.RUNNER_FAILURE: _runner_failure_observation(
                            run,
                            code=error.code,
                            disposition="FAILED",
                            reset_completed=reset_succeeded,
                        )
                    },
                    started=started,
                    completed=completed,
                    status=ResultStatus.FAILED,
                    observed_result=error.code,
                    reset_duration_ms=reset_duration_ms,
                    flow_duration_ms=flow_duration_ms,
                    reset_succeeded=reset_succeeded,
                )
            )
            for skipped in spec.cases[case_index + 1 :]:
                skipped_at = datetime.now(UTC)
                updated_cases.append(
                    _write_case_result(
                        run,
                        skipped,
                        {
                            EvidenceKind.RUNNER_FAILURE: _runner_failure_observation(
                                run,
                                code="ACCEPTANCE_NOT_RUN_AFTER_FAILURE",
                                disposition="NOT_RUN",
                                reset_completed=False,
                            )
                        },
                        started=skipped_at,
                        completed=skipped_at,
                        status=ResultStatus.FAILED,
                        observed_result="ACCEPTANCE_NOT_RUN_AFTER_FAILURE",
                        reset_duration_ms=0,
                        flow_duration_ms=0,
                        reset_succeeded=False,
                    )
                )
            break
    final_spec = spec.model_copy(update={"cases": tuple(updated_cases)})
    _write_once(output_spec, _canonical_object(_model_dict(final_spec)))
    payload, run_id, status = build_manifest(spec_path=output_spec, artifact_root=root)
    _write_once(output_manifest, payload)
    return payload, run_id, status


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlgraph-core-acceptance",
        description="Bind fixed hosted ControlGraph evidence into one redacted manifest.",
        epilog="Use 'controlgraph-core-acceptance execute --help' for the hosted executor.",
    )
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def _build_execute_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlgraph-core-acceptance execute",
        description=(
            "Execute the eight fixed cases against the isolated retained Google Cloud target."
        ),
        epilog=(
            "The pinned active principal needs the configured ControlGraph operator access plus "
            "these permissions for the bounded ephemeral probe job: "
            + ", ".join(_LOAD_JOB_PERMISSIONS)
        ),
    )
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output-spec", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--project-number", required=True)
    parser.add_argument("--network-resource", required=True)
    parser.add_argument("--subnetwork-resource", required=True)
    parser.add_argument("--verifier-service-account", required=True)
    parser.add_argument("--restricted-exporter-service-account", required=True)
    parser.add_argument("--acceptance-identity", required=True)
    parser.add_argument("--confirm", required=True, choices=(EXECUTE_CONFIRMATION,))
    return parser


def _build_generate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlgraph-core-acceptance generate-spec",
        description="Generate the deterministic eight-case hosted acceptance input spec.",
    )
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--stable-revision", required=True)
    parser.add_argument("--candidate-revision", required=True)
    parser.add_argument("--controller-image", required=True)
    parser.add_argument("--advisor-image", required=True)
    parser.add_argument("--console-image", required=True)
    parser.add_argument("--reference-stable-image", required=True)
    parser.add_argument("--reference-candidate-image", required=True)
    parser.add_argument("--terraform-plan", required=True)
    parser.add_argument("--policy-schema-version", required=True)
    parser.add_argument("--policy-artifact", required=True)
    parser.add_argument("--clock-start", required=True)
    parser.add_argument("--random-seed", required=True, type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    execute = bool(arguments and arguments[0] == "execute")
    generate = bool(arguments and arguments[0] == "generate-spec")
    if execute:
        args = _build_execute_parser().parse_args(arguments[1:])
    elif generate:
        args = _build_generate_parser().parse_args(arguments[1:])
    else:
        if arguments and arguments[0] == "bind":
            arguments = arguments[1:]
        args = _build_parser().parse_args(arguments)
    try:
        if generate:
            payload = generate_spec_template(
                artifact_root=args.artifact_root,
                output=args.output,
                project_id=args.project_id,
                source_commit=args.source_commit,
                stable_revision=args.stable_revision,
                candidate_revision=args.candidate_revision,
                image_references={
                    ImageComponent.CONTROLLER: args.controller_image,
                    ImageComponent.ADVISOR: args.advisor_image,
                    ImageComponent.CONSOLE: args.console_image,
                    ImageComponent.REFERENCE_STABLE: args.reference_stable_image,
                    ImageComponent.REFERENCE_CANDIDATE: args.reference_candidate_image,
                },
                terraform_plan_path=args.terraform_plan,
                policy_schema_version=args.policy_schema_version,
                policy_path=args.policy_artifact,
                clock_start=args.clock_start,
                random_seed=args.random_seed,
            )
            print(
                canonical_json_value_bytes(
                    {
                        "spec_sha256": hashlib.sha256(payload).hexdigest(),
                        "status": "TEMPLATE",
                    }
                ).decode("utf-8")
            )
            return 0
        if execute:
            payload, run_id, status_value = execute_hosted(
                spec_path=args.spec,
                artifact_root=args.artifact_root,
                output_spec=args.output_spec,
                output_manifest=args.output,
                project_number=args.project_number,
                network_resource=args.network_resource,
                subnetwork_resource=args.subnetwork_resource,
                verifier_service_account=args.verifier_service_account,
                restricted_exporter_service_account=args.restricted_exporter_service_account,
                acceptance_identity=args.acceptance_identity,
                confirmation=args.confirm,
            )
        else:
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
