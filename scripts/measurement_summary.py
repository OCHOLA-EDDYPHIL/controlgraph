#!/usr/bin/env python3
"""Summarize bounded acceptance observations without generating load."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Self, cast

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from controlgraph_canary.contracts.base import (
    MAX_CONTRACT_BYTES,
    CloudRunName,
    Identifier,
    ProjectId,
    Region,
    Sha256Digest,
    StrictContractModel,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    RestrictedJson,
    canonical_json_value_bytes,
    decode_contract,
)

SUMMARY_SCHEMA: Final = "controlgraph.measurement-summary/v1"
MAX_SAMPLE_DURATION_MS: Final = 60 * 60 * 1_000
MAX_RUN_DURATION_MS: Final = 4 * 60 * 60 * 1_000
MAX_RUN_COST_MICROUSD: Final = 10_000_000
CONFIDENCE_LEVEL_BASIS_POINTS: Final = 9_500

_IMAGE_DIGEST = re.compile(r"@sha256:(?P<digest>[0-9a-f]{64})$")
_REQUIRED_IMAGES: Final = {
    "advisor",
    "console",
    "controller",
    "reference-candidate",
    "reference-stable",
}


class MeasurementError(ValueError):
    """Stable failure that never repeats untrusted input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MeasurementPhase(StrEnum):
    """Closed intervals measured from cited evidence timestamps."""

    ISSUANCE = "ISSUANCE"
    QUEUEING = "QUEUEING"
    EXECUTOR_EPOCH_DENIAL = "EXECUTOR_EPOCH_DENIAL"
    TRAFFIC_MUTATION = "TRAFFIC_MUTATION"
    MONITORING = "MONITORING"
    RECOVERY = "RECOVERY"
    VERIFICATION = "VERIFICATION"
    TIMELINE_DELIVERY = "TIMELINE_DELIVERY"
    MODEL_ASSISTANCE = "MODEL_ASSISTANCE"


INTERVAL_BY_PHASE: Final[dict[MeasurementPhase, str]] = {
    MeasurementPhase.ISSUANCE: "ISSUANCE_REQUEST_TO_SIGNED_CAPABILITY",
    MeasurementPhase.QUEUEING: "TASK_CREATED_TO_HANDLER_START",
    MeasurementPhase.EXECUTOR_EPOCH_DENIAL: "REVOCATION_COMMIT_TO_DENIED_RECEIPT",
    MeasurementPhase.TRAFFIC_MUTATION: "PROVIDER_REQUEST_TO_VERIFIED_READBACK",
    MeasurementPhase.MONITORING: "QUERY_START_TO_PERSISTED_HEALTH_DECISION",
    MeasurementPhase.RECOVERY: "TERMINAL_UNHEALTHY_TO_VERIFIED_STABLE_READBACK",
    MeasurementPhase.VERIFICATION: "VERIFICATION_REQUEST_TO_SIGNED_ATTESTATION",
    MeasurementPhase.TIMELINE_DELIVERY: "TIMELINE_REQUEST_TO_FINAL_PAGE",
    MeasurementPhase.MODEL_ASSISTANCE: "ADVISOR_REQUEST_TO_VALIDATED_AUDIT",
}


class SampleStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"


class VerifierAgreement(StrEnum):
    AGREED = "AGREED"
    DISAGREED = "DISAGREED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class MeasurementBoundsV1(StrictContractModel):
    schema_version: Literal["controlgraph.measurement-bounds/v1"]
    maximum_samples: Annotated[int, Field(ge=9, le=64)]
    maximum_parallel_runs: Literal[1]
    maximum_cloud_run_instances: Annotated[int, Field(ge=1, le=4)]
    maximum_task_dispatches_per_second: Literal[1]
    maximum_task_concurrent_dispatches: Literal[1]
    maximum_model_calls_per_request: Literal[4]
    maximum_model_output_tokens: Literal[2048]
    maximum_model_duration_ms: Literal[20_000]


class MeasurementSampleV1(StrictContractModel):
    schema_version: Literal["controlgraph.measurement-sample/v1"]
    sequence: Annotated[int, Field(ge=1, le=64)]
    sample_id: Identifier
    case_id: Identifier
    phase: MeasurementPhase
    duration_ms: Annotated[int, Field(ge=0, le=MAX_SAMPLE_DURATION_MS)]
    status: SampleStatus
    duplicate_protected_effect: bool
    verifier_agreement: VerifierAgreement
    evidence_id: Identifier
    evidence_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_verifier_agreement(self) -> Self:
        is_verification = self.phase is MeasurementPhase.VERIFICATION
        is_applicable = self.verifier_agreement is not VerifierAgreement.NOT_APPLICABLE
        if is_verification != is_applicable:
            raise ValueError("verifier agreement must be reported only for verification samples")
        return self


class MeasurementSampleSetV1(StrictContractModel):
    schema_version: Literal["controlgraph.measurement-sample-set/v1"]
    source_manifest_sha256: Sha256Digest
    bounds: MeasurementBoundsV1
    samples: tuple[MeasurementSampleV1, ...] = Field(min_length=9, max_length=64)

    @model_validator(mode="after")
    def validate_complete_sample_set(self) -> Self:
        if tuple(item.sequence for item in self.samples) != tuple(range(1, len(self.samples) + 1)):
            raise ValueError("sample sequence must be contiguous")
        if len({item.sample_id for item in self.samples}) != len(self.samples):
            raise ValueError("sample identities must be unique")
        if {item.phase for item in self.samples} != set(MeasurementPhase):
            raise ValueError("sample set must cover every measurement phase")
        if len(self.samples) > self.bounds.maximum_samples:
            raise ValueError("sample count exceeds the declared bound")
        return self


def _immutable_image(value: str) -> str:
    if _IMAGE_DIGEST.search(value) is None:
        raise ValueError("image reference must be immutable")
    return value


ImmutableImageReference = Annotated[
    str,
    StringConstraints(min_length=80, max_length=512),
    AfterValidator(_immutable_image),
]
GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
AcceptanceRunId = Annotated[
    str,
    StringConstraints(pattern=r"^cgacceptance:[0-9a-f]{64}$"),
]


class _ProjectionModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)


class _ArtifactProjection(_ProjectionModel):
    artifact_id: Identifier
    sha256: Sha256Digest


class _ImageProjection(_ProjectionModel):
    component: Literal[
        "advisor",
        "console",
        "controller",
        "reference-candidate",
        "reference-stable",
    ]
    reference: ImmutableImageReference


class _PolicyProjection(_ProjectionModel):
    policy_schema_version: str
    artifact: _ArtifactProjection


class _TargetProjection(_ProjectionModel):
    project_id: ProjectId
    region: Region
    environment: Literal["nonprod"]
    service_name: Literal["controlgraph-reference-target"]
    stable_revision: CloudRunName
    candidate_revision: CloudRunName

    @model_validator(mode="after")
    def validate_isolated_target(self) -> Self:
        if (
            not self.project_id.startswith("controlgraph-canary-")
            or "reconcile" in self.project_id
            or self.region != "us-central1"
            or self.stable_revision == self.candidate_revision
        ):
            raise ValueError("source target is outside the isolated boundary")
        return self


class _EvidenceProjection(_ProjectionModel):
    evidence_id: Identifier
    artifact: _ArtifactProjection


class _CaseProjection(_ProjectionModel):
    case_id: Identifier
    status: Literal["PASSED", "FAILED"]
    execution_mode: Literal["HOSTED_GOOGLE_CLOUD"]
    evidence: tuple[_EvidenceProjection, ...] = Field(min_length=1, max_length=32)


class _InputsProjection(_ProjectionModel):
    source_commit: GitCommit
    target: _TargetProjection
    images: tuple[_ImageProjection, ...] = Field(min_length=5, max_length=5)
    terraform_plan: _ArtifactProjection
    policies: tuple[_PolicyProjection, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_images(self) -> Self:
        if {item.component for item in self.images} != _REQUIRED_IMAGES:
            raise ValueError("source manifest must bind every deployed image")
        return self


class _CostProjection(_ProjectionModel):
    basis: Literal["MEASURED", "UPPER_BOUND"]
    currency: Literal["USD"]
    reported_microusd: Annotated[int, Field(ge=0, le=MAX_RUN_COST_MICROUSD)]
    maximum_microusd: Annotated[int, Field(ge=0, le=MAX_RUN_COST_MICROUSD)]


class _ManifestProjection(_ProjectionModel):
    schema_version: Literal["controlgraph.core-acceptance-manifest/v1"]
    runner_mode: Literal["EXPLICIT_HOSTED_EVIDENCE_BINDING"]
    run_id: AcceptanceRunId
    status: Literal["PASSED", "FAILED"]
    evidence_binding_complete: bool
    duration_ms: Annotated[int, Field(ge=0, le=MAX_RUN_DURATION_MS)]
    maximum_duration_ms: Annotated[int, Field(ge=1, le=MAX_RUN_DURATION_MS)]
    inputs: _InputsProjection
    cases: tuple[_CaseProjection, ...] = Field(min_length=1, max_length=16)
    cost: _CostProjection


@dataclass(frozen=True)
class SourceManifest:
    run_id: str
    status: str
    evidence_binding_complete: bool
    source_commit: str
    target: dict[str, RestrictedJson]
    images: tuple[dict[str, RestrictedJson], ...]
    terraform_plan_sha256: str
    policy_digests: tuple[dict[str, RestrictedJson], ...]
    evidence_digests: dict[tuple[str, str], str]
    failed_case_ids: tuple[str, ...]
    duration_ms: int
    maximum_duration_ms: int
    cost: dict[str, RestrictedJson]


def _read_regular_file(path: Path, *, error_code: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MeasurementError(error_code) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_CONTRACT_BYTES:
            raise MeasurementError(error_code)
        chunks: list[bytes] = []
        byte_count = 0
        while chunk := os.read(descriptor, min(65_536, MAX_CONTRACT_BYTES + 1 - byte_count)):
            chunks.append(chunk)
            byte_count += len(chunk)
            if byte_count > MAX_CONTRACT_BYTES:
                raise MeasurementError(error_code)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise MeasurementError(error_code)
        return payload
    except OSError as error:
        raise MeasurementError(error_code) from error
    finally:
        os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate object key")
        value[key] = item
    return value


def _reject_number(_value: str) -> None:
    raise ValueError("non-integer JSON number")


def _load_restricted_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        if type(value) is not dict:
            raise ValueError("root must be an object")
        if canonical_json_value_bytes(cast(RestrictedJson, value)) != payload:
            raise ValueError("JSON is not canonical")
        return cast(dict[str, Any], value)
    except (ContractError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise MeasurementError("MEASUREMENT_SOURCE_INVALID") from error


def _source_manifest(payload: bytes) -> SourceManifest:
    _load_restricted_object(payload)
    try:
        manifest = _ManifestProjection.model_validate_json(payload)
    except ValidationError as error:
        raise MeasurementError("MEASUREMENT_SOURCE_INVALID") from error
    evidence_digests: dict[tuple[str, str], str] = {}
    failed_case_ids: list[str] = []
    for case in manifest.cases:
        if case.status == "FAILED":
            failed_case_ids.append(case.case_id)
        for evidence in case.evidence:
            key = (case.case_id, evidence.evidence_id)
            if key in evidence_digests:
                raise MeasurementError("MEASUREMENT_SOURCE_INVALID")
            evidence_digests[key] = evidence.artifact.sha256
    inputs = manifest.inputs
    images: list[dict[str, RestrictedJson]] = []
    for image in inputs.images:
        match = _IMAGE_DIGEST.search(image.reference)
        assert match is not None
        images.append({"component": image.component, "sha256": match.group("digest")})
    policy_digests: tuple[dict[str, RestrictedJson], ...] = tuple(
        {
            "artifact_id": policy.artifact.artifact_id,
            "policy_schema_version": policy.policy_schema_version,
            "sha256": policy.artifact.sha256,
        }
        for policy in inputs.policies
    )
    normalized_cost: dict[str, RestrictedJson] = {
        "basis": manifest.cost.basis,
        "currency": "USD",
        "maximum_microusd_per_run": manifest.cost.maximum_microusd,
        "reported_microusd_per_run": manifest.cost.reported_microusd,
        "run_count": 1,
        "within_bound": manifest.cost.reported_microusd <= manifest.cost.maximum_microusd,
    }
    return SourceManifest(
        run_id=manifest.run_id,
        status=manifest.status,
        evidence_binding_complete=manifest.evidence_binding_complete,
        source_commit=inputs.source_commit,
        target=cast(dict[str, RestrictedJson], inputs.target.model_dump(mode="json")),
        images=tuple(images),
        terraform_plan_sha256=inputs.terraform_plan.sha256,
        policy_digests=policy_digests,
        evidence_digests=evidence_digests,
        failed_case_ids=tuple(failed_case_ids),
        duration_ms=manifest.duration_ms,
        maximum_duration_ms=manifest.maximum_duration_ms,
        cost=normalized_cost,
    )


def _nearest_rank(values: Sequence[int], percentile_basis_points: int) -> int:
    ordered = sorted(values)
    rank = math.ceil(percentile_basis_points * len(ordered) / 10_000)
    return ordered[max(1, rank) - 1]


def _distribution(samples: Sequence[MeasurementSampleV1]) -> dict[str, RestrictedJson]:
    values = [item.duration_ms for item in samples]
    return {
        "maximum_ms": max(values),
        "minimum_ms": min(values),
        "p50_ms": _nearest_rank(values, 5_000),
        "p95_ms": _nearest_rank(values, 9_500),
        "p99_ms": _nearest_rank(values, 9_900),
        "sample_count": len(values),
    }


def _wilson_rate(count: int, sample_count: int) -> dict[str, RestrictedJson]:
    z = Decimal("1.959963984540054")
    n = Decimal(sample_count)
    proportion = Decimal(count) / n
    z_squared = z * z
    denominator = Decimal(1) + z_squared / n
    center = (proportion + z_squared / (Decimal(2) * n)) / denominator
    margin = (
        z
        * (proportion * (Decimal(1) - proportion) / n + z_squared / (Decimal(4) * n * n)).sqrt()
        / denominator
    )
    scale = Decimal(10_000)
    lower = int((max(Decimal(0), center - margin) * scale).to_integral_value(ROUND_FLOOR))
    upper = int((min(Decimal(1), center + margin) * scale).to_integral_value(ROUND_CEILING))
    return {
        "confidence_level_basis_points": CONFIDENCE_LEVEL_BASIS_POINTS,
        "count": count,
        "lower_basis_points": lower,
        "method": "WILSON_SCORE",
        "rate_basis_points": (count * 10_000 + sample_count // 2) // sample_count,
        "sample_count": sample_count,
        "upper_basis_points": upper,
    }


def build_summary(
    *,
    source_manifest_path: Path,
    sample_set_path: Path,
) -> tuple[bytes, str]:
    """Bind observations to one accepted run and return a canonical summary."""

    source_payload = _read_regular_file(
        source_manifest_path,
        error_code="MEASUREMENT_SOURCE_INVALID",
    )
    source_digest = hashlib.sha256(source_payload).hexdigest()
    source = _source_manifest(source_payload)
    sample_payload = _read_regular_file(
        sample_set_path,
        error_code="MEASUREMENT_SAMPLE_SET_INVALID",
    )
    try:
        sample_set = decode_contract(sample_payload, MeasurementSampleSetV1)
    except (ContractError, ValidationError, TypeError, ValueError) as error:
        raise MeasurementError("MEASUREMENT_SAMPLE_SET_INVALID") from error
    if sample_set.source_manifest_sha256 != source_digest:
        raise MeasurementError("MEASUREMENT_SOURCE_DIGEST_MISMATCH")

    for sample in sample_set.samples:
        if source.evidence_digests.get((sample.case_id, sample.evidence_id)) != (
            sample.evidence_sha256
        ):
            raise MeasurementError("MEASUREMENT_EVIDENCE_BINDING_MISMATCH")

    phase_summaries: list[RestrictedJson] = []
    for phase in MeasurementPhase:
        phase_samples = tuple(item for item in sample_set.samples if item.phase is phase)
        phase_summaries.append(
            {
                "latency_ms": _distribution(phase_samples),
                "interval": INTERVAL_BY_PHASE[phase],
                "phase": phase.value,
            }
        )
    failures: list[RestrictedJson] = [
        {
            "case_id": item.case_id,
            "evidence_id": item.evidence_id,
            "phase": item.phase.value,
            "sample_id": item.sample_id,
        }
        for item in sample_set.samples
        if item.status is SampleStatus.FAILED
    ]
    verification_samples = tuple(
        item for item in sample_set.samples if item.phase is MeasurementPhase.VERIFICATION
    )
    evidence_artifacts = sorted(
        {(item.evidence_id, item.evidence_sha256) for item in sample_set.samples}
    )
    sample_set_digest = hashlib.sha256(sample_payload).hexdigest()
    report_id = f"cgmeasurements:{sample_set_digest}"
    summary: dict[str, RestrictedJson] = {
        "artifact_digests": {
            "acceptance_manifest_sha256": source_digest,
            "evidence": [
                {"evidence_id": evidence_id, "sha256": digest}
                for evidence_id, digest in evidence_artifacts
            ],
            "images": list(source.images),
            "policies": list(source.policy_digests),
            "terraform_plan_sha256": source.terraform_plan_sha256,
        },
        "bounds": cast(RestrictedJson, sample_set.bounds.model_dump(mode="json")),
        "claim_scope": {
            "internet_scale_claim": False,
            "production_reliability_claim": False,
            "production_slo_claim": False,
            "scope": "ISOLATED_ACCEPTANCE_ONLY",
        },
        "confidence_limits": {
            "latency_population_interval": "NOT_CLAIMED",
            "proportion_interval": "WILSON_SCORE_95",
        },
        "environment": {
            "execution_mode": "HOSTED_GOOGLE_CLOUD",
            "source_commit": source.source_commit,
            "target": source.target,
        },
        "failures": failures,
        "measurements": {
            "duplicate_rate": _wilson_rate(
                sum(item.duplicate_protected_effect for item in sample_set.samples),
                len(sample_set.samples),
            ),
            "error_rate": _wilson_rate(
                sum(item.status is SampleStatus.FAILED for item in sample_set.samples),
                len(sample_set.samples),
            ),
            "latency_by_phase": phase_summaries,
            "queue_age_ms": _distribution(
                tuple(
                    item for item in sample_set.samples if item.phase is MeasurementPhase.QUEUEING
                )
            ),
            "recovery_time_ms": _distribution(
                tuple(
                    item for item in sample_set.samples if item.phase is MeasurementPhase.RECOVERY
                )
            ),
            "revocation_to_denial_ms": _distribution(
                tuple(
                    item
                    for item in sample_set.samples
                    if item.phase is MeasurementPhase.EXECUTOR_EPOCH_DENIAL
                )
            ),
            "run_cost": source.cost,
            "verifier_agreement_rate": _wilson_rate(
                sum(
                    item.verifier_agreement is VerifierAgreement.AGREED
                    for item in verification_samples
                ),
                len(verification_samples),
            ),
        },
        "measurement_result": (
            "OBSERVED_WITH_FAILURES" if failures or source.status == "FAILED" else "OBSERVED"
        ),
        "measurement_set_sha256": sample_set_digest,
        "report_id": report_id,
        "sample_count": len(sample_set.samples),
        "schema_version": SUMMARY_SCHEMA,
        "source_run": {
            "duration_ms": source.duration_ms,
            "evidence_binding_complete": source.evidence_binding_complete,
            "failed_case_ids": list(source.failed_case_ids),
            "maximum_duration_ms": source.maximum_duration_ms,
            "run_id": source.run_id,
            "status": source.status,
            "within_duration_bound": source.duration_ms <= source.maximum_duration_ms,
        },
        "known_limitations": [
            "BOUNDED_SAMPLE_NOT_A_PRODUCTION_SLO",
            "ISOLATED_SINGLE_PROJECT_AND_REGION",
            "LATENCY_PERCENTILES_DESCRIBE_RECORDED_SAMPLES_ONLY",
            "PROPORTION_INTERVALS_ASSUME_INDEPENDENT_TRIALS",
        ],
    }
    try:
        payload = canonical_json_value_bytes(cast(RestrictedJson, summary))
    except ContractError as error:
        raise MeasurementError("MEASUREMENT_SUMMARY_INVALID") from error
    return payload, report_id


def _write_once(path: Path, payload: bytes) -> None:
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise MeasurementError("MEASUREMENT_OUTPUT_INVALID") from error
    if not parent.is_dir() or path.exists() or path.is_symlink():
        raise MeasurementError("MEASUREMENT_OUTPUT_INVALID")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        with suppress(OSError):
            path.unlink(missing_ok=True)
        raise MeasurementError("MEASUREMENT_OUTPUT_INVALID") from error


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlgraph-measurement-summary",
        description="Summarize bounded observations from one hosted acceptance manifest.",
    )
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--sample-set", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        payload, report_id = build_summary(
            source_manifest_path=args.source_manifest,
            sample_set_path=args.sample_set,
        )
        _write_once(args.output, payload)
    except MeasurementError as error:
        print('{"code":"' + error.code + '"}', file=sys.stderr)
        return 2
    print(
        canonical_json_value_bytes(
            {
                "report_id": report_id,
                "summary_sha256": hashlib.sha256(payload).hexdigest(),
            }
        ).decode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
