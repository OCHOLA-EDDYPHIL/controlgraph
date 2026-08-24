#!/usr/bin/env python3
"""Bind one fixed hosted security/IAM abuse run to a redacted manifest."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from contextlib import suppress
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal, Self, cast

import controlgraph_canary
from controlgraph_canary.contracts.base import (
    CloudRunName,
    Identifier,
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
from pydantic import (
    AfterValidator,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

MANIFEST_SCHEMA: Final = "controlgraph.security-abuse-manifest/v1"
MAX_ARTIFACT_BYTES: Final = 1024 * 1024
_ISOLATED_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")


class AbuseError(ValueError):
    """Stable failure that never contains untrusted evidence."""

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
        raise ValueError("artifact path must be normalized and relative")
    return value


RelativeArtifactPath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$"),
    AfterValidator(_relative_artifact_path),
]
GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
ReasonCode = Annotated[
    str,
    StringConstraints(min_length=3, max_length=96, pattern=r"^[A-Z][A-Z0-9_]*$"),
]


class CaseKind(StrEnum):
    CROSS_IDENTITY_INVOCATION = "CROSS_IDENTITY_INVOCATION"
    CROSS_PROJECT_TARGET = "CROSS_PROJECT_TARGET"
    CROSS_SERVICE_TARGET = "CROSS_SERVICE_TARGET"
    CAPABILITY_TAMPER = "CAPABILITY_TAMPER"
    CAPABILITY_REPLAY = "CAPABILITY_REPLAY"
    STALE_EPOCH = "STALE_EPOCH"
    SCOPE_AMPLIFICATION = "SCOPE_AMPLIFICATION"
    RECEIPT_COLLISION = "RECEIPT_COLLISION"
    RECOVERY_PROMOTION = "RECOVERY_PROMOTION"
    RECOVERY_REVISION_SELECTION = "RECOVERY_REVISION_SELECTION"
    VERIFIER_MUTATION = "VERIFIER_MUTATION"
    ISSUER_MUTATION = "ISSUER_MUTATION"
    UNAUTHORIZED_EVIDENCE_READ = "UNAUTHORIZED_EVIDENCE_READ"
    MODEL_TOOL_MUTATION = "MODEL_TOOL_MUTATION"
    ADVISOR_MUTATION = "ADVISOR_MUTATION"


class ProbeMethod(StrEnum):
    AUTHENTICATED_HTTP = "AUTHENTICATED_HTTP"
    IAM_POLICY_TROUBLESHOOTER = "IAM_POLICY_TROUBLESHOOTER"
    PROTECTED_APPLICATION_ROUTE = "PROTECTED_APPLICATION_ROUTE"
    ADK_TOOL_REGISTRY = "ADK_TOOL_REGISTRY"


class DenialLayer(StrEnum):
    CLOUD_IAM = "CLOUD_IAM"
    APPLICATION = "APPLICATION"


class DenialClass(StrEnum):
    IDENTITY_DENIED = "IDENTITY_DENIED"
    TARGET_DENIED = "TARGET_DENIED"
    SIGNATURE_DENIED = "SIGNATURE_DENIED"
    REPLAY_DENIED = "REPLAY_DENIED"
    EPOCH_DENIED = "EPOCH_DENIED"
    SCOPE_DENIED = "SCOPE_DENIED"
    RECEIPT_DENIED = "RECEIPT_DENIED"
    RECOVERY_LIMIT_DENIED = "RECOVERY_LIMIT_DENIED"
    MUTATION_AUTHORITY_DENIED = "MUTATION_AUTHORITY_DENIED"
    EVIDENCE_ACCESS_DENIED = "EVIDENCE_ACCESS_DENIED"
    TOOL_DENIED = "TOOL_DENIED"


class CaseStatus(StrEnum):
    DENIED = "DENIED"
    PERMITTED = "PERMITTED"
    ERROR = "ERROR"


class CasePolicy(StrictContractModel):
    operation: str
    probe_method: ProbeMethod
    denial_layer: DenialLayer
    denial_class: DenialClass
    minimum_attempt_count: int = 1


CASE_POLICIES: Final[dict[CaseKind, CasePolicy]] = {
    CaseKind.CROSS_IDENTITY_INVOCATION: CasePolicy(
        operation="cloud-run:cross-identity-invocation",
        probe_method=ProbeMethod.AUTHENTICATED_HTTP,
        denial_layer=DenialLayer.CLOUD_IAM,
        denial_class=DenialClass.IDENTITY_DENIED,
        minimum_attempt_count=4,
    ),
    CaseKind.CROSS_PROJECT_TARGET: CasePolicy(
        operation="controlgraph:cross-project-target",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.TARGET_DENIED,
    ),
    CaseKind.CROSS_SERVICE_TARGET: CasePolicy(
        operation="controlgraph:cross-service-target",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.TARGET_DENIED,
    ),
    CaseKind.CAPABILITY_TAMPER: CasePolicy(
        operation="controlgraph:tampered-capability",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.SIGNATURE_DENIED,
    ),
    CaseKind.CAPABILITY_REPLAY: CasePolicy(
        operation="controlgraph:cross-request-capability-replay",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.REPLAY_DENIED,
    ),
    CaseKind.STALE_EPOCH: CasePolicy(
        operation="controlgraph:stale-epoch-execution",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.EPOCH_DENIED,
    ),
    CaseKind.SCOPE_AMPLIFICATION: CasePolicy(
        operation="controlgraph:widened-capability-scope",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.SCOPE_DENIED,
    ),
    CaseKind.RECEIPT_COLLISION: CasePolicy(
        operation="controlgraph:receipt-key-collision",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.RECEIPT_DENIED,
    ),
    CaseKind.RECOVERY_PROMOTION: CasePolicy(
        operation="controlgraph:recovery-promote-candidate",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.RECOVERY_LIMIT_DENIED,
    ),
    CaseKind.RECOVERY_REVISION_SELECTION: CasePolicy(
        operation="controlgraph:recovery-select-revision",
        probe_method=ProbeMethod.PROTECTED_APPLICATION_ROUTE,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.RECOVERY_LIMIT_DENIED,
    ),
    CaseKind.VERIFIER_MUTATION: CasePolicy(
        operation="iam:verifier-update-target",
        probe_method=ProbeMethod.IAM_POLICY_TROUBLESHOOTER,
        denial_layer=DenialLayer.CLOUD_IAM,
        denial_class=DenialClass.MUTATION_AUTHORITY_DENIED,
    ),
    CaseKind.ISSUER_MUTATION: CasePolicy(
        operation="iam:issuer-update-target",
        probe_method=ProbeMethod.IAM_POLICY_TROUBLESHOOTER,
        denial_layer=DenialLayer.CLOUD_IAM,
        denial_class=DenialClass.MUTATION_AUTHORITY_DENIED,
    ),
    CaseKind.UNAUTHORIZED_EVIDENCE_READ: CasePolicy(
        operation="controlgraph:restricted-evidence-read",
        probe_method=ProbeMethod.AUTHENTICATED_HTTP,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.EVIDENCE_ACCESS_DENIED,
    ),
    CaseKind.MODEL_TOOL_MUTATION: CasePolicy(
        operation="adk:unregistered-mutation-tool",
        probe_method=ProbeMethod.ADK_TOOL_REGISTRY,
        denial_layer=DenialLayer.APPLICATION,
        denial_class=DenialClass.TOOL_DENIED,
    ),
    CaseKind.ADVISOR_MUTATION: CasePolicy(
        operation="iam:advisor-update-target",
        probe_method=ProbeMethod.IAM_POLICY_TROUBLESHOOTER,
        denial_layer=DenialLayer.CLOUD_IAM,
        denial_class=DenialClass.MUTATION_AUTHORITY_DENIED,
    ),
}

EXPECTED_REASON_CODES: Final[dict[CaseKind, frozenset[str]]] = {
    CaseKind.CROSS_IDENTITY_INVOCATION: frozenset(
        {"CLOUD_RUN_FORBIDDEN", "IAM_PERMISSION_DENIED", "PERMISSION_DENIED"}
    ),
    CaseKind.CROSS_PROJECT_TARGET: frozenset(
        {"CONTRACT_INVALID", "TARGET_BINDING_MISMATCH"}
    ),
    CaseKind.CROSS_SERVICE_TARGET: frozenset(
        {"CONTRACT_INVALID", "TARGET_BINDING_MISMATCH"}
    ),
    CaseKind.CAPABILITY_TAMPER: frozenset({"CONTRACT_INVALID", "SIGNATURE_INVALID"}),
    CaseKind.CAPABILITY_REPLAY: frozenset(
        {"CLAIM_BINDING_MISMATCH", "IDEMPOTENCY_CONFLICT"}
    ),
    CaseKind.STALE_EPOCH: frozenset({"EPOCH_MISMATCH"}),
    CaseKind.SCOPE_AMPLIFICATION: frozenset({"SCOPE_AMPLIFICATION"}),
    CaseKind.RECEIPT_COLLISION: frozenset({"IDEMPOTENCY_CONFLICT"}),
    CaseKind.RECOVERY_PROMOTION: frozenset(
        {"CONTRACT_INVALID", "RECOVERY_COMMAND_DENIED", "TARGET_BINDING_MISMATCH"}
    ),
    CaseKind.RECOVERY_REVISION_SELECTION: frozenset(
        {"CONTRACT_INVALID", "RECOVERY_COMMAND_DENIED", "TARGET_BINDING_MISMATCH"}
    ),
    CaseKind.VERIFIER_MUTATION: frozenset({"IAM_PERMISSION_DENIED", "PERMISSION_DENIED"}),
    CaseKind.ISSUER_MUTATION: frozenset({"IAM_PERMISSION_DENIED", "PERMISSION_DENIED"}),
    CaseKind.UNAUTHORIZED_EVIDENCE_READ: frozenset(
        {
            "AUTH_CALLER_DENIED",
            "CLOUD_RUN_FORBIDDEN",
            "TIMELINE_RAW_EXPORT_ACCESS_DENIED",
        }
    ),
    CaseKind.MODEL_TOOL_MUTATION: frozenset(
        {"ADVISOR_WORKFLOW_COMMAND_DENIED", "CONTRACT_INVALID", "DIAGNOSTIC_TOOL_DENIED"}
    ),
    CaseKind.ADVISOR_MUTATION: frozenset({"IAM_PERMISSION_DENIED", "PERMISSION_DENIED"}),
}


class TargetV1(StrictContractModel):
    schema_version: Literal["controlgraph.security-abuse-target/v1"]
    project_id: ProjectId
    region: Region
    service_name: CloudRunName

    @model_validator(mode="after")
    def isolated_target(self) -> Self:
        if (
            _ISOLATED_PROJECT.fullmatch(self.project_id) is None
            or self.service_name != "controlgraph-reference-target"
        ):
            raise ValueError("security abuse target is outside the isolated reference service")
        return self


class ArtifactBindingV1(StrictContractModel):
    schema_version: Literal["controlgraph.security-abuse-artifact/v1"]
    artifact_id: Identifier
    media_type: Literal["application/json"]
    relative_path: RelativeArtifactPath
    sha256: Sha256Digest


class CaseEvidenceV1(StrictContractModel):
    schema_version: Literal["controlgraph.security-abuse-case-evidence/v1"]
    case_id: Identifier
    sequence: PositiveSafeInteger
    kind: CaseKind
    source_commit: GitCommit
    target: TargetV1
    operation: str
    probe_method: ProbeMethod
    denial_layer: DenialLayer
    denial_class: DenialClass
    observed_reason_code: ReasonCode
    attempt_count: Annotated[int, Field(ge=1, le=64)]
    status: CaseStatus
    provider_mutation_calls: Annotated[int, Field(ge=0, le=64)]
    unauthorized_target_change: bool
    target_before_sha256: Sha256Digest
    target_after_sha256: Sha256Digest
    readback_before_at: UtcSecond
    attempted_at: UtcSecond
    readback_after_at: UtcSecond

    @model_validator(mode="after")
    def ordered_observations(self) -> Self:
        if not self.readback_before_at <= self.attempted_at <= self.readback_after_at:
            raise ValueError("security abuse observations are out of order")
        return self


class CaseBindingV1(StrictContractModel):
    schema_version: Literal["controlgraph.security-abuse-case-binding/v1"]
    case_id: Identifier
    sequence: PositiveSafeInteger
    kind: CaseKind
    evidence: ArtifactBindingV1


class RunSpecV1(StrictContractModel):
    schema_version: Literal["controlgraph.security-abuse-run/v1"]
    source_commit: GitCommit
    core_acceptance_manifest_sha256: Sha256Digest
    target: TargetV1
    execution_mode: Literal["HOSTED_GOOGLE_CLOUD"]
    identity_mode: Literal["EXISTING_IDENTITIES_ONLY"]
    temporary_service_accounts_created: Literal[0]
    temporary_iam_bindings_created: Literal[0]
    controls_disabled: Annotated[tuple[str, ...], Field(max_length=0)]
    fixture_cleanup_status: Literal["NOT_REQUIRED"]
    started_at: UtcSecond
    completed_at: UtcSecond
    cases: Annotated[tuple[CaseBindingV1, ...], Field(min_length=15, max_length=15)]

    @model_validator(mode="after")
    def complete_fixed_run(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("security abuse run timestamps are out of order")
        if tuple(item.kind for item in self.cases) != tuple(CaseKind):
            raise ValueError("security abuse case set or order is invalid")
        if tuple(item.sequence for item in self.cases) != tuple(range(1, 16)):
            raise ValueError("security abuse case sequence is invalid")
        if len({item.case_id for item in self.cases}) != len(self.cases):
            raise ValueError("security abuse case identifiers must be unique")
        paths = [item.evidence.relative_path for item in self.cases]
        identifiers = [item.evidence.artifact_id for item in self.cases]
        if len(set(paths)) != len(paths) or len(set(identifiers)) != len(identifiers):
            raise ValueError("security abuse evidence bindings must be unique")
        return self


def _run_git(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise AbuseError("SECURITY_ABUSE_SOURCE_INVALID") from error
    return completed.stdout.strip()


def _verify_source(root: Path, source_commit: str) -> None:
    if _run_git(root, "rev-parse", "--show-toplevel") != str(root):
        raise AbuseError("SECURITY_ABUSE_SOURCE_INVALID")
    if _run_git(root, "rev-parse", "HEAD") != source_commit:
        raise AbuseError("SECURITY_ABUSE_SOURCE_MISMATCH")
    if _run_git(root, "status", "--porcelain"):
        raise AbuseError("SECURITY_ABUSE_SOURCE_DIRTY")
    package = Path(controlgraph_canary.__file__).resolve().parent
    expected_package = (root / "backend" / "src" / "controlgraph_canary").resolve()
    if package != expected_package:
        raise AbuseError("SECURITY_ABUSE_SOURCE_MISMATCH")


def _load_contract[ModelT: StrictContractModel](
    path: Path,
    model_type: type[ModelT],
    *,
    error_code: str,
) -> tuple[bytes, ModelT]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise OSError
        payload = path.read_bytes()
        return payload, decode_contract(payload, model_type)
    except (ContractError, OSError, TypeError, ValidationError, ValueError) as error:
        raise AbuseError(error_code) from error


def _bind_artifact(binding: ArtifactBindingV1, *, artifact_root: Path) -> tuple[bytes, str]:
    candidate = artifact_root / binding.relative_path
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise AbuseError("SECURITY_ABUSE_ARTIFACT_INVALID") from error
    if (
        candidate != resolved
        or not resolved.is_relative_to(artifact_root)
        or not resolved.is_file()
        or resolved.stat().st_size > MAX_ARTIFACT_BYTES
    ):
        raise AbuseError("SECURITY_ABUSE_ARTIFACT_INVALID")
    try:
        payload = resolved.read_bytes()
    except OSError as error:
        raise AbuseError("SECURITY_ABUSE_ARTIFACT_INVALID") from error
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise AbuseError("SECURITY_ABUSE_ARTIFACT_INVALID")
    if hashlib.sha256(payload).hexdigest() != binding.sha256:
        raise AbuseError("SECURITY_ABUSE_ARTIFACT_DIGEST_MISMATCH")
    return payload, binding.sha256


def _case_manifest(
    binding: CaseBindingV1,
    evidence: CaseEvidenceV1,
    *,
    spec: RunSpecV1,
    artifact_sha256: str,
) -> tuple[dict[str, RestrictedJson], bool]:
    policy = CASE_POLICIES[binding.kind]
    if (
        evidence.case_id != binding.case_id
        or evidence.sequence != binding.sequence
        or evidence.kind is not binding.kind
        or evidence.source_commit != spec.source_commit
        or evidence.target != spec.target
        or evidence.operation != policy.operation
        or evidence.probe_method is not policy.probe_method
        or evidence.denial_layer is not policy.denial_layer
        or evidence.denial_class is not policy.denial_class
        or evidence.attempt_count < policy.minimum_attempt_count
        or (
            evidence.status is CaseStatus.DENIED
            and evidence.observed_reason_code not in EXPECTED_REASON_CODES[binding.kind]
        )
        or not spec.started_at <= evidence.readback_before_at
        or evidence.readback_after_at > spec.completed_at
    ):
        raise AbuseError("SECURITY_ABUSE_CASE_BINDING_MISMATCH")
    passed = (
        evidence.status is CaseStatus.DENIED
        and evidence.provider_mutation_calls == 0
        and not evidence.unauthorized_target_change
        and evidence.target_before_sha256 == evidence.target_after_sha256
    )
    return (
        {
            "attempt_count": evidence.attempt_count,
            "case_id": evidence.case_id,
            "denial_class": evidence.denial_class.value,
            "denial_layer": evidence.denial_layer.value,
            "evidence": {
                "artifact_id": binding.evidence.artifact_id,
                "media_type": binding.evidence.media_type,
                "sha256": artifact_sha256,
            },
            "kind": evidence.kind.value,
            "observed_reason_code": evidence.observed_reason_code,
            "operation": evidence.operation,
            "probe_method": evidence.probe_method.value,
            "provider_mutation_calls": evidence.provider_mutation_calls,
            "readback_after_at": evidence.readback_after_at,
            "readback_before_at": evidence.readback_before_at,
            "sequence": evidence.sequence,
            "status": "PASSED" if passed else "FAILED",
            "target_after_sha256": evidence.target_after_sha256,
            "target_before_sha256": evidence.target_before_sha256,
            "unauthorized_target_change": evidence.unauthorized_target_change,
        },
        passed,
    )


def build_manifest(*, spec_path: Path, artifact_root: Path) -> tuple[bytes, str, bool]:
    """Validate one fixed hosted run and return a redacted canonical manifest."""

    spec_payload, spec = _load_contract(
        spec_path,
        RunSpecV1,
        error_code="SECURITY_ABUSE_SPEC_INVALID",
    )
    try:
        root = artifact_root.resolve(strict=True)
    except OSError as error:
        raise AbuseError("SECURITY_ABUSE_ARTIFACT_ROOT_INVALID") from error
    if artifact_root.is_symlink() or not root.is_dir():
        raise AbuseError("SECURITY_ABUSE_ARTIFACT_ROOT_INVALID")
    source_root = Path(__file__).resolve().parents[1]
    _verify_source(source_root, spec.source_commit)

    cases: list[dict[str, RestrictedJson]] = []
    passed = True
    target_unchanged = True
    target_sha256: str | None = None
    for binding in spec.cases:
        payload, artifact_sha256 = _bind_artifact(binding.evidence, artifact_root=root)
        try:
            evidence = decode_contract(payload, CaseEvidenceV1)
        except (ContractError, TypeError, ValidationError, ValueError) as error:
            raise AbuseError("SECURITY_ABUSE_CASE_EVIDENCE_INVALID") from error
        case, case_passed = _case_manifest(
            binding,
            evidence,
            spec=spec,
            artifact_sha256=artifact_sha256,
        )
        if target_sha256 is None:
            target_sha256 = evidence.target_before_sha256
        elif evidence.target_before_sha256 != target_sha256:
            case_passed = False
            case["status"] = "FAILED"
        target_unchanged = target_unchanged and (
            not evidence.unauthorized_target_change
            and evidence.target_before_sha256 == evidence.target_after_sha256
            and evidence.target_before_sha256 == target_sha256
        )
        cases.append(case)
        passed = passed and case_passed

    spec_sha256 = hashlib.sha256(spec_payload).hexdigest()
    run_id = f"cgsecurity:{spec_sha256}"
    manifest: dict[str, RestrictedJson] = {
        "cases": cast(RestrictedJson, cases),
        "completed_at": spec.completed_at,
        "core_acceptance_manifest_sha256": spec.core_acceptance_manifest_sha256,
        "execution_mode": spec.execution_mode,
        "identity_mode": spec.identity_mode,
        "no_controls_disabled": True,
        "no_temporary_iam": True,
        "run_id": run_id,
        "schema_version": MANIFEST_SCHEMA,
        "source_commit": spec.source_commit,
        "spec_sha256": spec_sha256,
        "started_at": spec.started_at,
        "status": "PASSED" if passed else "FAILED",
        "target": cast(RestrictedJson, spec.target.model_dump(mode="json")),
        "target_unchanged_for_every_case": target_unchanged,
    }
    try:
        payload = canonical_json_value_bytes(cast(RestrictedJson, manifest))
    except ContractError as error:
        raise AbuseError("SECURITY_ABUSE_MANIFEST_INVALID") from error
    return payload, run_id, passed


def _write_once(path: Path, payload: bytes) -> None:
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise AbuseError("SECURITY_ABUSE_OUTPUT_INVALID") from error
    if not parent.is_dir() or path.exists() or path.is_symlink():
        raise AbuseError("SECURITY_ABUSE_OUTPUT_INVALID")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        with suppress(OSError):
            path.unlink(missing_ok=True)
        raise AbuseError("SECURITY_ABUSE_OUTPUT_INVALID") from error


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlgraph-security-abuse",
        description="Bind fixed hosted security/IAM denial evidence into one redacted manifest.",
    )
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        payload, run_id, passed = build_manifest(
            spec_path=args.spec,
            artifact_root=args.artifact_root,
        )
        _write_once(args.output, payload)
    except AbuseError as error:
        print('{"code":"' + error.code + '"}', file=sys.stderr)
        return 2
    print(
        canonical_json_value_bytes(
            {
                "manifest_sha256": hashlib.sha256(payload).hexdigest(),
                "run_id": run_id,
                "status": "PASSED" if passed else "FAILED",
            }
        ).decode("utf-8")
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
