#!/usr/bin/env python3
"""Verify a source-bound, claim-ledger release bundle without creating evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Final

SPEC_SCHEMA: Final = "controlgraph.frozen-bundle-spec/v1"
BUNDLE_SCHEMA: Final = "controlgraph.frozen-bundle/v1"
REPOSITORY: Final = "https://github.com/OCHOLA-EDDYPHIL/controlgraph"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[a-z][a-z0-9.-]{0,95}$")
CORE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SCHEMA_RE = re.compile(r"^[a-z][a-z0-9.-]*/v[1-9][0-9]*$")
PROJECT_RE = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
CLOUD_RUN_NAME_RE = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
IMAGE_RE = re.compile(
    r"^(?P<region>us-central1)-docker\.pkg\.dev/"
    r"(?P<project>controlgraph-canary-[a-z0-9]{6,10})/controlgraph-canary/"
    r"(?P<image>[a-z-]+)@sha256:(?P<digest>[0-9a-f]{64})$"
)
IMAGE_COMPONENTS: Final = frozenset(
    {"controller", "console", "advisor", "reference-stable", "reference-candidate"}
)
CORE_CASE_ORDER: Final = (
    "TARGET_RESET",
    "HEALTHY_PROMOTION",
    "UNHEALTHY_STABLE_RECOVERY",
    "REVOCATION_STALE_DENIAL",
    "INDEPENDENT_VERIFIER_PROBE",
    "AMBIGUITY_CLASSIFICATION",
    "TIMELINE_CONSOLE_READ",
    "BOUNDED_ADVISOR",
)
CORE_EXPECTED_RESULTS: Final = {
    "TARGET_RESET": "RESET_VERIFIED",
    "HEALTHY_PROMOTION": "PROMOTED",
    "UNHEALTHY_STABLE_RECOVERY": "RECOVERED",
    "REVOCATION_STALE_DENIAL": "DENIED",
    "INDEPENDENT_VERIFIER_PROBE": "VERIFIED",
    "AMBIGUITY_CLASSIFICATION": "AMBIGUOUS",
    "TIMELINE_CONSOLE_READ": "READABLE",
    "BOUNDED_ADVISOR": "ADVISORY_ONLY",
}
CORE_REQUIRED_EVIDENCE: Final = {
    "TARGET_RESET": frozenset({"CLOUD_RUN_CONFIGURATION", "DATA_PATH_PROBE"}),
    "HEALTHY_PROMOTION": frozenset(
        {
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "VERIFIED_CAPABILITY_METADATA",
            "EXECUTOR_EPOCH_CHECK",
            "EXECUTION_RECEIPT",
            "HEALTH_DECISION",
            "TIMELINE",
        }
    ),
    "UNHEALTHY_STABLE_RECOVERY": frozenset(
        {
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "VERIFIED_CAPABILITY_METADATA",
            "EXECUTOR_EPOCH_CHECK",
            "EXECUTION_RECEIPT",
            "HEALTH_DECISION",
            "RECOVERY_SERVICE_IDENTITY_BINDING",
            "TIMELINE",
        }
    ),
    "REVOCATION_STALE_DENIAL": frozenset(
        {
            "AUTHORITY_TRANSITION",
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "VERIFIED_CAPABILITY_METADATA",
            "EXECUTOR_EPOCH_CHECK",
            "STALE_DENIAL",
            "EXECUTION_RECEIPT",
            "TIMELINE",
        }
    ),
    "INDEPENDENT_VERIFIER_PROBE": frozenset(
        {
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "INDEPENDENT_VERIFICATION",
            "TIMELINE",
        }
    ),
    "AMBIGUITY_CLASSIFICATION": frozenset(
        {
            "CLOUD_RUN_CONFIGURATION",
            "EXECUTION_RECEIPT",
            "AMBIGUITY_CLASSIFICATION",
            "TIMELINE",
        }
    ),
    "TIMELINE_CONSOLE_READ": frozenset(
        {"CLOUD_RUN_CONFIGURATION", "TIMELINE", "CONSOLE_READ"}
    ),
    "BOUNDED_ADVISOR": frozenset(
        {"CLOUD_RUN_CONFIGURATION", "COORDINATOR", "MODEL_AUDIT", "TIMELINE"}
    ),
}
MAX_CORE_CASE_DURATION_MS: Final = 60 * 60 * 1_000
MAX_CORE_DURATION_MS: Final = 4 * 60 * 60 * 1_000
MAX_CORE_COST_MICROUSD: Final = 10_000_000

CLAIM_CATEGORIES: Final = frozenset(
    {
        "architecture",
        "security",
        "determinism",
        "latency",
        "reliability",
        "cost",
        "comparison",
        "demo",
    }
)
FAULT_ORDER: Final = (
    "DELAYED_TASK",
    "DUPLICATE_DELIVERY",
    "REVOCATION_RACE",
    "MONITORING_GAP",
    "API_TIMEOUT",
    "CONFIGURATION_DRIFT",
    "PROBE_FAILURE",
)
FAULT_INVARIANTS: Final = {
    "DELAYED_TASK": frozenset({"STALE_DENIAL"}),
    "DUPLICATE_DELIVERY": frozenset({"ONE_RECOVERY_INTENT"}),
    "REVOCATION_RACE": frozenset({"STALE_DENIAL"}),
    "MONITORING_GAP": frozenset({"DETERMINISTIC_HEALTH"}),
    "API_TIMEOUT": frozenset({"NO_BLIND_RETRY", "AMBIGUITY_CLASSIFICATION"}),
    "CONFIGURATION_DRIFT": frozenset({"SAFE_FALLBACK"}),
    "PROBE_FAILURE": frozenset({"SAFE_FALLBACK"}),
}
BASE_REQUIRED_KINDS: Final = frozenset(
    {
        "CONTRACT_SCHEMA_INDEX",
        "TERRAFORM_PLAN",
        "RELEASE_EVIDENCE_MANIFEST",
        "RELEASE_EVIDENCE_VERIFICATION",
        "CORE_ACCEPTANCE_MANIFEST",
        "FAULT_ACCEPTANCE_MANIFEST",
        "SECURITY_ABUSE_MANIFEST",
        "PERFORMANCE_SUMMARY",
        "REQUIRED_CHECK_RESULTS",
        "ARCHITECTURE_DOCUMENT",
        "ARCHITECTURE_DIAGRAM",
        "QUICKSTART_DOCUMENT",
        "DEMO_ASSET",
        "NATIVE_COMPARISON_DOCUMENT",
        "LIMITATIONS_DOCUMENT",
        "DISCLOSURE_DOCUMENT",
        "RELEASE_REVIEW",
    }
)
FINAL_ONLY_KINDS: Final = frozenset({"PREPARED_BUNDLE", "CLEAN_ROOM_REHEARSAL"})
ALLOWED_KINDS: Final = BASE_REQUIRED_KINDS | FINAL_ONLY_KINDS
JSON_SCHEMAS: Final = {
    "CONTRACT_SCHEMA_INDEX": "controlgraph.contract-schema-index/v1",
    "RELEASE_EVIDENCE_MANIFEST": "controlgraph.release-evidence/v1",
    "RELEASE_EVIDENCE_VERIFICATION": "controlgraph.release-evidence-verification/v1",
    "CORE_ACCEPTANCE_MANIFEST": "controlgraph.core-acceptance-manifest/v1",
    "FAULT_ACCEPTANCE_MANIFEST": "controlgraph.fault-acceptance-manifest/v1",
    "SECURITY_ABUSE_MANIFEST": "controlgraph.security-abuse-manifest/v1",
    "PERFORMANCE_SUMMARY": "controlgraph.measurement-summary/v1",
    "REQUIRED_CHECK_RESULTS": "controlgraph.required-check-results/v1",
    "RELEASE_REVIEW": "controlgraph.release-review/v1",
    "PREPARED_BUNDLE": BUNDLE_SCHEMA,
    "CLEAN_ROOM_REHEARSAL": "controlgraph.clean-room-rehearsal/v1",
}
SINGLETON_KINDS: Final = ALLOWED_KINDS - {"DEMO_ASSET"}
REQUIRED_CHECKS: Final = frozenset({"PYTHON", "WEB", "TERRAFORM", "SECURITY"})
RELEASE_CHECKS: Final = frozenset(
    {
        "LEAST_PRIVILEGE",
        "EMBEDDED_SECRETS_ABSENT",
        "TRUSTED_KEY_VERSIONS_CURRENT",
        "EVIDENCE_REDACTED",
        "RESIDUAL_RISKS_DOCUMENTED",
        "UNSUPPORTED_CLAIMS_ABSENT",
    }
)
CLEAN_ROOM_STEPS: Final = frozenset(
    {
        "VERIFY_CHECKSUMS",
        "DEPLOY_FROZEN_ARTIFACTS",
        "RUN_ACCEPTANCE",
        "VALIDATE_EVIDENCE_LINKS",
        "FINAL_SIGN_OFF",
    }
)


class BundleError(ValueError):
    """The bundle specification or a referenced artifact is invalid."""


def _object(value: Any, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError(message)
    return value


def _load_json_bytes(payload: bytes, message: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BundleError(message)
            result[key] = value
        return result

    try:
        return json.loads(payload, object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(message) from error


def _read_json(path: Path, message: str) -> tuple[dict[str, Any], bytes]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise BundleError(message) from error
    return _object(_load_json_bytes(payload, message), message), payload


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise BundleError("ARTIFACT_READ_FAILED") from error
    return digest.hexdigest()


def _git(repo: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=repo, check=True, capture_output=True, text=True
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise BundleError("SOURCE_GIT_CHECK_FAILED") from error
    return completed.stdout.strip()


def _relative_path(root: Path, value: Any) -> Path:
    if not isinstance(value, str):
        raise BundleError("ARTIFACT_PATH_INVALID")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise BundleError("ARTIFACT_PATH_INVALID")
    root = root.resolve()
    candidate = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise BundleError("ARTIFACT_PATH_INVALID")
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as error:
        raise BundleError("ARTIFACT_PATH_INVALID") from error
    if not resolved.is_relative_to(root):
        raise BundleError("ARTIFACT_PATH_INVALID")
    return resolved


def _validate_source(repo: Path, source: Any) -> tuple[dict[str, Any], list[str]]:
    item = _object(source, "SOURCE_INVALID")
    if set(item) != {"repository", "revision", "tag", "tag_status", "tag_object_sha"}:
        raise BundleError("SOURCE_INVALID")
    revision = item.get("revision")
    tag = item.get("tag")
    status = item.get("tag_status")
    if (
        item.get("repository") != REPOSITORY
        or not isinstance(revision, str)
        or COMMIT_RE.fullmatch(revision) is None
    ):
        raise BundleError("SOURCE_INVALID")
    if not isinstance(tag, str) or not tag or status not in {"PENDING", "VERIFIED"}:
        raise BundleError("SOURCE_TAG_INVALID")
    _git(repo, "check-ref-format", f"refs/tags/{tag}")
    if _git(repo, "rev-parse", "HEAD") != revision or _git(
        repo, "status", "--porcelain=v1", "--untracked-files=no"
    ):
        raise BundleError("SOURCE_NOT_EXACT_CLEAN_HEAD")
    origin = _git(repo, "remote", "get-url", "origin")
    if origin not in {
        f"{REPOSITORY}.git",
        REPOSITORY,
        "git@github.com:OCHOLA-EDDYPHIL/controlgraph.git",
    }:
        raise BundleError("SOURCE_REPOSITORY_MISMATCH")
    pending: list[str] = []
    tag_object = item.get("tag_object_sha")
    if status == "PENDING":
        if tag_object is not None:
            raise BundleError("SOURCE_TAG_INVALID")
        pending.append("SOURCE_TAG")
    else:
        if not isinstance(tag_object, str) or COMMIT_RE.fullmatch(tag_object) is None:
            raise BundleError("SOURCE_TAG_INVALID")
        if _git(repo, "cat-file", "-t", f"refs/tags/{tag}") != "tag":
            raise BundleError("SOURCE_TAG_NOT_ANNOTATED")
        if _git(repo, "rev-parse", f"refs/tags/{tag}") != tag_object:
            raise BundleError("SOURCE_TAG_OBJECT_MISMATCH")
        if _git(repo, "rev-parse", f"refs/tags/{tag}^{{commit}}") != revision:
            raise BundleError("SOURCE_TAG_COMMIT_MISMATCH")
        remote_refs = {
            ref: sha
            for line in _git(
                repo,
                "ls-remote",
                "--tags",
                "origin",
                f"refs/tags/{tag}",
                f"refs/tags/{tag}^{{}}",
            ).splitlines()
            for sha, ref in (line.split("\t", maxsplit=1),)
        }
        if (
            remote_refs.get(f"refs/tags/{tag}") != tag_object
            or remote_refs.get(f"refs/tags/{tag}^{{}}") != revision
        ):
            raise BundleError("SOURCE_TAG_REMOTE_MISMATCH")
    return item, pending


def _validate_artifact_entry(value: Any) -> dict[str, Any]:
    item = _object(value, "ARTIFACT_INVALID")
    allowed = {"id", "kind", "location", "path", "sha256", "status", "schema_version"}
    if not set(item).issubset(allowed) or not {
        "id",
        "kind",
        "location",
        "path",
        "sha256",
        "status",
    }.issubset(item):
        raise BundleError("ARTIFACT_INVALID")
    artifact_id = item.get("id")
    kind = item.get("kind")
    if (
        not isinstance(artifact_id, str)
        or ID_RE.fullmatch(artifact_id) is None
        or kind not in ALLOWED_KINDS
    ):
        raise BundleError("ARTIFACT_INVALID")
    if item.get("location") not in {"REPOSITORY", "BUNDLE"} or item.get(
        "status"
    ) not in {"PENDING", "VERIFIED"}:
        raise BundleError("ARTIFACT_INVALID")
    expected_schema = JSON_SCHEMAS.get(kind)
    declared_schema = item.get("schema_version")
    if expected_schema is not None and declared_schema != expected_schema:
        raise BundleError("ARTIFACT_SCHEMA_INVALID")
    if item["status"] == "PENDING" and item.get("sha256") is not None:
        raise BundleError("PENDING_ARTIFACT_HAS_DIGEST")
    if item["status"] == "VERIFIED" and (
        not isinstance(item.get("sha256"), str)
        or SHA_RE.fullmatch(item["sha256"]) is None
    ):
        raise BundleError("VERIFIED_ARTIFACT_DIGEST_INVALID")
    return item


def _bind_artifacts(
    repo: Path, artifact_root: Path, values: Any, stage: str
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    list[str],
]:
    if not isinstance(values, list) or not values:
        raise BundleError("ARTIFACTS_INVALID")
    records: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    payloads: dict[str, dict[str, Any]] = {}
    pending: list[str] = []
    kinds: Counter[str] = Counter()
    for raw in values:
        item = _validate_artifact_entry(raw)
        artifact_id = item["id"]
        kind = item["kind"]
        if artifact_id in by_id:
            raise BundleError("ARTIFACT_ID_DUPLICATE")
        kinds[kind] += 1
        root = repo if item["location"] == "REPOSITORY" else artifact_root
        path = _relative_path(root, item["path"])
        record = dict(item)
        record["bytes"] = None
        if item["status"] == "PENDING":
            pending.append(f"ARTIFACT:{artifact_id}")
        else:
            if not path.is_file():
                raise BundleError("ARTIFACT_MISSING")
            if item["location"] == "REPOSITORY":
                relative = path.relative_to(repo.resolve()).as_posix()
                _git(repo, "ls-files", "--error-unmatch", "--", relative)
            if _file_sha(path) != item["sha256"]:
                raise BundleError("ARTIFACT_DIGEST_MISMATCH")
            record["bytes"] = path.stat().st_size
            declared_schema = item.get("schema_version")
            if declared_schema is not None:
                payload, _ = _read_json(path, "ARTIFACT_JSON_INVALID")
                if payload.get("schema_version") != declared_schema:
                    raise BundleError("ARTIFACT_SCHEMA_MISMATCH")
                payloads[artifact_id] = payload
            elif kind == "TERRAFORM_PLAN":
                payload, _ = _read_json(path, "TERRAFORM_PLAN_INVALID")
                if not isinstance(payload.get("format_version"), str):
                    raise BundleError("TERRAFORM_PLAN_INVALID")
                payloads[artifact_id] = payload
        records.append(record)
        by_id[artifact_id] = item
    required = BASE_REQUIRED_KINDS | (FINAL_ONLY_KINDS if stage == "FINAL" else set())
    if not required.issubset(kinds):
        raise BundleError("REQUIRED_ARTIFACT_KIND_MISSING")
    if stage == "PREPARED" and any(kinds[kind] for kind in FINAL_ONLY_KINDS):
        raise BundleError("PREPARED_BUNDLE_HAS_FINAL_ARTIFACT")
    if any(kinds[kind] != 1 for kind in SINGLETON_KINDS if kind in required):
        raise BundleError("SINGLETON_ARTIFACT_KIND_INVALID")
    if kinds["DEMO_ASSET"] < 1:
        raise BundleError("ARTIFACT_KIND_COUNT_INVALID")
    return records, by_id, payloads, pending


def _require_source_commit(payload: Mapping[str, Any], revision: str) -> None:
    if payload.get("source_commit") != revision:
        raise BundleError("ARTIFACT_SOURCE_MISMATCH")


def _validate_contract_index(payload: Mapping[str, Any], revision: str) -> None:
    _require_source_commit(payload, revision)
    schemas = payload.get("schemas")
    if not isinstance(schemas, list) or not schemas:
        raise BundleError("CONTRACT_SCHEMA_INDEX_INVALID")
    identities: set[str] = set()
    for value in schemas:
        item = _object(value, "CONTRACT_SCHEMA_INDEX_INVALID")
        identifier, version = item.get("id"), item.get("version")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identities
            or not isinstance(version, str)
            or not version
        ):
            raise BundleError("CONTRACT_SCHEMA_INDEX_INVALID")
        identities.add(identifier)


def _core_artifact(value: Any) -> dict[str, Any]:
    artifact = _object(value, "CORE_ACCEPTANCE_ARTIFACT_INVALID")
    if (
        set(artifact) != {"artifact_id", "byte_count", "media_type", "sha256"}
        or not isinstance(artifact.get("artifact_id"), str)
        or CORE_ID_RE.fullmatch(artifact["artifact_id"]) is None
        or type(artifact.get("byte_count")) is not int
        or not 0 < artifact["byte_count"] <= 8 * 1024 * 1024
        or artifact.get("media_type")
        not in {"application/json", "text/plain", "application/octet-stream"}
        or not isinstance(artifact.get("sha256"), str)
        or SHA_RE.fullmatch(artifact["sha256"]) is None
    ):
        raise BundleError("CORE_ACCEPTANCE_ARTIFACT_INVALID")
    return artifact


def _clean_room_output(root: Path, value: Any) -> tuple[dict[str, Any], Path]:
    reference = _object(value, "CLEAN_ROOM_OUTPUT_INVALID")
    artifact_id = reference.get("artifact_id")
    relative_path = reference.get("path")
    sha256 = reference.get("sha256")
    if (
        set(reference) != {"artifact_id", "path", "sha256"}
        or not isinstance(artifact_id, str)
        or CORE_ID_RE.fullmatch(artifact_id) is None
        or not isinstance(relative_path, str)
        or PurePosixPath(relative_path).parts[:1] != ("clean-room",)
        or not isinstance(sha256, str)
        or SHA_RE.fullmatch(sha256) is None
    ):
        raise BundleError("CLEAN_ROOM_OUTPUT_INVALID")
    path = _relative_path(root, reference.get("path"))
    try:
        size = path.stat().st_size
    except OSError as error:
        raise BundleError("CLEAN_ROOM_OUTPUT_INVALID") from error
    if (
        not path.is_file()
        or not 0 < size <= 8 * 1024 * 1024
        or _file_sha(path) != sha256
    ):
        raise BundleError("CLEAN_ROOM_OUTPUT_INVALID")
    return {"bytes": size, "id": artifact_id, "sha256": sha256}, path


def _validate_core_acceptance(
    payload: Mapping[str, Any],
    revision: str,
    release_images: Mapping[str, str] | None,
    terraform_plan: Mapping[str, Any],
) -> None:
    inputs = _object(payload.get("inputs"), "CORE_ACCEPTANCE_MANIFEST_INVALID")
    target = _object(inputs.get("target"), "CORE_ACCEPTANCE_TARGET_INVALID")
    spec_sha256 = payload.get("spec_sha256")
    run_inputs_sha256 = inputs.get("run_inputs_sha256")
    if (
        payload.get("schema_version") != "controlgraph.core-acceptance-manifest/v1"
        or payload.get("status") != "PASSED"
        or payload.get("evidence_binding_complete") is not True
        or payload.get("runner_mode") != "EXPLICIT_HOSTED_EVIDENCE_BINDING"
        or inputs.get("source_commit") != revision
        or not isinstance(spec_sha256, str)
        or SHA_RE.fullmatch(spec_sha256) is None
        or payload.get("run_id") != f"cgacceptance:{spec_sha256}"
        or not isinstance(run_inputs_sha256, str)
        or SHA_RE.fullmatch(run_inputs_sha256) is None
        or type(inputs.get("random_seed")) is not int
        or not 0 <= inputs["random_seed"] <= 9_007_199_254_740_991
    ):
        raise BundleError("CORE_ACCEPTANCE_MANIFEST_INVALID")
    if (
        target.get("schema_version") != "controlgraph.acceptance-target/v1"
        or target.get("environment") != "nonprod"
        or target.get("region") != "us-central1"
        or target.get("service_name") != "controlgraph-reference-target"
        or not isinstance(target.get("project_id"), str)
        or PROJECT_RE.fullmatch(target["project_id"]) is None
        or not isinstance(target.get("stable_revision"), str)
        or CLOUD_RUN_NAME_RE.fullmatch(target["stable_revision"]) is None
        or not isinstance(target.get("candidate_revision"), str)
        or CLOUD_RUN_NAME_RE.fullmatch(target["candidate_revision"]) is None
        or target["stable_revision"] == target["candidate_revision"]
    ):
        raise BundleError("CORE_ACCEPTANCE_TARGET_INVALID")
    values = inputs.get("images")
    if not isinstance(values, list) or len(values) != len(IMAGE_COMPONENTS):
        raise BundleError("CORE_ACCEPTANCE_IMAGES_INVALID")
    images: dict[str, str] = {}
    digests: set[str] = set()
    for value in values:
        image = _object(value, "CORE_ACCEPTANCE_IMAGES_INVALID")
        component = image.get("component")
        reference = image.get("reference")
        if not isinstance(component, str) or not isinstance(reference, str):
            raise BundleError("CORE_ACCEPTANCE_IMAGES_INVALID")
        match = IMAGE_RE.fullmatch(reference)
        if (
            image.get("schema_version") != "controlgraph.acceptance-image/v1"
            or component not in IMAGE_COMPONENTS
            or component in images
            or match is None
            or match.group("image") != component
            or match.group("project") != target["project_id"]
            or match.group("region") != target["region"]
            or match.group("digest") in digests
        ):
            raise BundleError("CORE_ACCEPTANCE_IMAGES_INVALID")
        images[component] = reference
        digests.add(match.group("digest"))
    if set(images) != IMAGE_COMPONENTS or (
        release_images is not None and images != release_images
    ):
        raise BundleError("CORE_RELEASE_IMAGE_MISMATCH")

    plan = _core_artifact(inputs.get("terraform_plan"))
    if (
        plan["artifact_id"] != terraform_plan.get("id")
        or plan["sha256"] != terraform_plan.get("sha256")
        or plan["byte_count"] != terraform_plan.get("bytes")
        or plan["media_type"] != "application/json"
    ):
        raise BundleError("CORE_ACCEPTANCE_PLAN_MISMATCH")
    policies = inputs.get("policies")
    if not isinstance(policies, list) or not 1 <= len(policies) <= 8:
        raise BundleError("CORE_ACCEPTANCE_POLICY_INVALID")
    artifact_ids = {plan["artifact_id"]}
    for raw in policies:
        policy = _object(raw, "CORE_ACCEPTANCE_POLICY_INVALID")
        schema_version = policy.get("policy_schema_version")
        artifact = _core_artifact(policy.get("artifact"))
        if (
            set(policy) != {"artifact", "policy_schema_version"}
            or not isinstance(schema_version, str)
            or SCHEMA_RE.fullmatch(schema_version) is None
            or artifact["media_type"] != "application/json"
            or artifact["artifact_id"] in artifact_ids
        ):
            raise BundleError("CORE_ACCEPTANCE_POLICY_INVALID")
        artifact_ids.add(artifact["artifact_id"])

    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or len(raw_cases) != len(CORE_CASE_ORDER):
        raise BundleError("CORE_ACCEPTANCE_CASES_INVALID")
    cases = [_object(value, "CORE_ACCEPTANCE_CASES_INVALID") for value in raw_cases]
    if tuple(case.get("kind") for case in cases) != CORE_CASE_ORDER:
        raise BundleError("CORE_ACCEPTANCE_CASES_INVALID")
    case_ids: set[str] = set()
    evidence_ids: set[str] = set()
    total_duration = 0
    maximum_duration = 0
    reported_cost = 0
    maximum_cost = 0
    for sequence, case in enumerate(cases, start=1):
        kind = CORE_CASE_ORDER[sequence - 1]
        case_id = case.get("case_id")
        duration = case.get("duration_ms")
        duration_bound = case.get("maximum_duration_ms")
        cost = _object(case.get("cost"), "CORE_ACCEPTANCE_CASES_INVALID")
        cost_reported = cost.get("reported_microusd")
        cost_bound = cost.get("maximum_microusd")
        entry_points = case.get("entry_points")
        evidence = case.get("evidence")
        steps = case.get("steps")
        if (
            case.get("sequence") != sequence
            or not isinstance(case_id, str)
            or CORE_ID_RE.fullmatch(case_id) is None
            or case_id in case_ids
            or case.get("status") != "PASSED"
            or case.get("execution_mode") != "HOSTED_GOOGLE_CLOUD"
            or case.get("expected_result") != CORE_EXPECTED_RESULTS[kind]
            or case.get("observed_result") != CORE_EXPECTED_RESULTS[kind]
            or type(duration) is not int
            or type(duration_bound) is not int
            or not 0 <= duration <= duration_bound <= MAX_CORE_CASE_DURATION_MS
            or cost.get("basis") not in {"MEASURED", "UPPER_BOUND"}
            or type(cost_reported) is not int
            or type(cost_bound) is not int
            or not 0 <= cost_reported <= cost_bound <= MAX_CORE_COST_MICROUSD
            or not isinstance(entry_points, list)
            or not entry_points
            or any(not isinstance(value, str) or not value for value in entry_points)
            or not isinstance(evidence, list)
            or not evidence
            or not isinstance(steps, list)
            or not steps
            or len(steps) != len(entry_points)
        ):
            raise BundleError("CORE_ACCEPTANCE_CASES_INVALID")
        result_artifact = _core_artifact(case.get("result_artifact"))
        if (
            result_artifact["media_type"] != "application/json"
            or result_artifact["artifact_id"] in artifact_ids
        ):
            raise BundleError("CORE_ACCEPTANCE_CASES_INVALID")
        artifact_ids.add(result_artifact["artifact_id"])
        case_ids.add(case_id)
        total_duration += duration
        maximum_duration += duration_bound
        reported_cost += cost_reported
        maximum_cost += cost_bound

        case_evidence_ids: set[str] = set()
        evidence_kinds: set[str] = set()
        for raw_evidence in evidence:
            item = _object(raw_evidence, "CORE_ACCEPTANCE_EVIDENCE_INVALID")
            evidence_id = item.get("evidence_id")
            kind_value = item.get("kind")
            artifact = _core_artifact(item.get("artifact"))
            if (
                not isinstance(evidence_id, str)
                or CORE_ID_RE.fullmatch(evidence_id) is None
                or evidence_id in evidence_ids
                or not isinstance(kind_value, str)
                or item.get("projection")
                not in {"PUBLIC_REDACTED", "PRIVATE_DIGEST_ONLY"}
                or artifact["artifact_id"] in artifact_ids
            ):
                raise BundleError("CORE_ACCEPTANCE_EVIDENCE_INVALID")
            evidence_ids.add(evidence_id)
            case_evidence_ids.add(evidence_id)
            evidence_kinds.add(kind_value)
            artifact_ids.add(artifact["artifact_id"])
        if not CORE_REQUIRED_EVIDENCE[kind].issubset(evidence_kinds):
            raise BundleError("CORE_ACCEPTANCE_EVIDENCE_INVALID")

        referenced: set[str] = set()
        step_duration = 0
        for step_sequence, raw_step in enumerate(steps, start=1):
            step = _object(raw_step, "CORE_ACCEPTANCE_EVIDENCE_INVALID")
            references = step.get("evidence_ids")
            step_ms = step.get("duration_ms")
            if (
                step.get("schema_version")
                != "controlgraph.core-acceptance-step-result/v1"
                or step.get("sequence") != step_sequence
                or step.get("status") != "PASSED"
                or step.get("operation") != entry_points[step_sequence - 1]
                or type(step_ms) is not int
                or not 0 <= step_ms <= MAX_CORE_CASE_DURATION_MS
                or not isinstance(references, list)
                or not references
                or any(not isinstance(value, str) for value in references)
                or len(set(references)) != len(references)
            ):
                raise BundleError("CORE_ACCEPTANCE_EVIDENCE_INVALID")
            referenced.update(references)
            step_duration += step_ms
        if referenced != case_evidence_ids or step_duration > duration:
            raise BundleError("CORE_ACCEPTANCE_EVIDENCE_INVALID")

    manifest_duration = payload.get("duration_ms")
    duration_bound = payload.get("maximum_duration_ms")
    cost = _object(payload.get("cost"), "CORE_ACCEPTANCE_MANIFEST_INVALID")
    manifest_cost_bound = cost.get("maximum_microusd")
    if (
        type(manifest_duration) is not int
        or type(duration_bound) is not int
        or manifest_duration != total_duration
        or not 0 <= manifest_duration <= duration_bound <= MAX_CORE_DURATION_MS
        or maximum_duration > duration_bound
        or cost.get("basis") not in {"MEASURED", "UPPER_BOUND"}
        or cost.get("currency") != "USD"
        or cost.get("reported_microusd") != reported_cost
        or type(manifest_cost_bound) is not int
        or not maximum_cost <= manifest_cost_bound <= MAX_CORE_COST_MICROUSD
    ):
        raise BundleError("CORE_ACCEPTANCE_BOUNDS_INVALID")


def _validate_release_evidence(
    repo: Path,
    artifact_root: Path,
    manifest_entry: Mapping[str, Any],
    manifest: Mapping[str, Any],
    marker: Mapping[str, Any],
    revision: str,
) -> dict[str, Any]:
    if (
        manifest.get("source") != {"repository": REPOSITORY, "revision": revision}
        or manifest.get("runtime_security_claim") is not False
    ):
        raise BundleError("RELEASE_EVIDENCE_SOURCE_INVALID")
    if (
        marker.get("source_sha") != revision
        or marker.get("verified") is not True
        or marker.get("runtime_security_claim") is not False
        or marker.get("manifest_sha256") != manifest_entry.get("sha256")
    ):
        raise BundleError("RELEASE_EVIDENCE_MARKER_INVALID")
    root = _relative_path(artifact_root, manifest_entry["path"]).parent
    files: dict[str, str] = {}

    def bind(relative: Any, expected: Any | None = None) -> str:
        path = _relative_path(root, relative)
        if not path.is_file():
            raise BundleError("RELEASE_EVIDENCE_FILE_MISSING")
        digest = _file_sha(path)
        if expected is not None and digest != expected:
            raise BundleError("RELEASE_EVIDENCE_DIGEST_MISMATCH")
        files[str(relative)] = digest
        return digest

    materials = manifest.get("materials")
    if not isinstance(materials, list) or not materials:
        raise BundleError("RELEASE_EVIDENCE_MATERIALS_INVALID")
    for value in materials:
        item = _object(value, "RELEASE_EVIDENCE_MATERIALS_INVALID")
        bind_repo = _relative_path(repo, item.get("path"))
        if not bind_repo.is_file() or _file_sha(bind_repo) != item.get("sha256"):
            raise BundleError("RELEASE_EVIDENCE_MATERIALS_INVALID")
    subjects = _object(manifest.get("subjects"), "RELEASE_EVIDENCE_SUBJECTS_INVALID")
    expected_subjects = {"backend", "cli", "console", "terraform", "release"} | {
        f"image-{name}" for name in IMAGE_COMPONENTS
    }
    if set(subjects) != expected_subjects:
        raise BundleError("RELEASE_EVIDENCE_SUBJECTS_INVALID")
    images: dict[str, str] = {}
    for name, raw in subjects.items():
        subject = _object(raw, "RELEASE_EVIDENCE_SUBJECTS_INVALID")
        for evidence_name in ("sbom", "vulnerability_and_secret_scan"):
            evidence = _object(
                subject.get(evidence_name), "RELEASE_EVIDENCE_SUBJECTS_INVALID"
            )
            bind(evidence.get("path"), evidence.get("sha256"))
        if name.startswith("image-"):
            reference = subject.get("immutable_reference")
            if not isinstance(reference, str):
                raise BundleError("RELEASE_IMAGE_REFERENCE_INVALID")
            match = IMAGE_RE.fullmatch(reference)
            component = name.removeprefix("image-")
            if match is None or match.group("image") != component:
                raise BundleError("RELEASE_IMAGE_REFERENCE_INVALID")
            images[component] = reference
    if len({reference.rsplit("@", 1)[1] for reference in images.values()}) != len(
        IMAGE_COMPONENTS
    ):
        raise BundleError("RELEASE_IMAGE_REFERENCE_INVALID")
    tool = _object(
        _object(manifest.get("tooling"), "RELEASE_EVIDENCE_TOOL_INVALID").get("trivy"),
        "RELEASE_EVIDENCE_TOOL_INVALID",
    )
    database = _object(tool.get("database"), "RELEASE_EVIDENCE_TOOL_INVALID")
    bind(database.get("path"), database.get("sha256"))
    attestations = _object(
        manifest.get("attestations"), "RELEASE_EVIDENCE_ATTESTATIONS_INVALID"
    )
    if not attestations:
        raise BundleError("RELEASE_EVIDENCE_ATTESTATIONS_INVALID")
    for relative in attestations.values():
        bind(relative)
    provenance_path = root / "provenance.intoto.jsonl"
    provenance, _ = _read_json(provenance_path, "RELEASE_PROVENANCE_INVALID")
    if provenance.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise BundleError("RELEASE_PROVENANCE_INVALID")
    files["provenance.intoto.jsonl"] = _file_sha(provenance_path)
    return {
        "files": [{"path": key, "sha256": files[key]} for key in sorted(files)],
        "images": dict(sorted(images.items())),
    }


def _validate_fault_acceptance(
    payload: Mapping[str, Any], core: Mapping[str, Any], revision: str
) -> None:
    core_inputs = _object(core.get("inputs"), "FAULT_ACCEPTANCE_RUN_MISMATCH")
    target = _object(core_inputs.get("target"), "FAULT_ACCEPTANCE_RUN_MISMATCH")
    if (
        payload.get("source_commit") != revision
        or payload.get("project_id") != target.get("project_id")
        or payload.get("region") != target.get("region")
        or payload.get("environment") != target.get("environment")
        or payload.get("service_name") != target.get("service_name")
        or payload.get("stable_revision") != target.get("stable_revision")
        or payload.get("candidate_revision") != target.get("candidate_revision")
        or payload.get("run_seed") != core_inputs.get("random_seed")
    ):
        raise BundleError("FAULT_ACCEPTANCE_RUN_MISMATCH")
    cases = payload.get("cases")
    principal_sha256 = payload.get("acceptance_principal_sha256")
    if (
        payload.get("schema_version") != "controlgraph.fault-acceptance-manifest/v1"
        or payload.get("environment") != "nonprod"
        or payload.get("purpose") != "PRODUCT_VALIDATION"
        or payload.get("result") != "PASSED"
        or not isinstance(principal_sha256, str)
        or SHA_RE.fullmatch(principal_sha256) is None
        or payload.get("allowlisted_faults") != list(FAULT_ORDER)
        or type(payload.get("run_seed")) is not int
        or not 0 <= payload["run_seed"] <= 9_007_199_254_740_991
        or not isinstance(cases, list)
        or len(cases) != len(FAULT_ORDER)
        or tuple(case.get("fault") for case in cases if isinstance(case, dict))
        != FAULT_ORDER
    ):
        raise BundleError("FAULT_ACCEPTANCE_MANIFEST_INVALID")
    run_seed = payload["run_seed"]
    root_ids: set[str] = set()
    for raw, fault in zip(cases, FAULT_ORDER, strict=True):
        case = _object(raw, "FAULT_ACCEPTANCE_MANIFEST_INVALID")
        digest = hashlib.sha256(
            b"controlgraph.fault-acceptance-seed/v1\0"
            + str(run_seed).encode("ascii")
            + b"\0"
            + fault.encode("ascii")
        ).digest()
        expected_id = f"fault-{fault.lower().replace('_', '-')}-{digest.hex()[:16]}"
        artifacts = case.get("artifacts")
        invariants = case.get("observed_invariants")
        root_id = case.get("root_id")
        if (
            case.get("scenario_id") != expected_id
            or case.get("random_seed") != int.from_bytes(digest[:6], "big")
            or case.get("result") != "PASSED"
            or not isinstance(case.get("boundary"), str)
            or not case["boundary"]
            or not isinstance(case.get("injection"), str)
            or not case["injection"]
            or not isinstance(root_id, str)
            or not root_id
            or root_id in root_ids
            or not isinstance(artifacts, list)
            or not artifacts
            or not isinstance(invariants, list)
            or len(invariants) != len(FAULT_INVARIANTS[fault])
            or any(not isinstance(value, str) for value in invariants)
            or set(invariants) != FAULT_INVARIANTS[fault]
        ):
            raise BundleError("FAULT_ACCEPTANCE_MANIFEST_INVALID")
        root_ids.add(root_id)
        artifact_names: set[str] = set()
        for raw_artifact in artifacts:
            artifact = _object(raw_artifact, "FAULT_ACCEPTANCE_MANIFEST_INVALID")
            name = artifact.get("name")
            sha256 = artifact.get("sha256")
            if (
                not isinstance(name, str)
                or not name
                or name in artifact_names
                or not isinstance(sha256, str)
                or SHA_RE.fullmatch(sha256) is None
            ):
                raise BundleError("FAULT_ACCEPTANCE_MANIFEST_INVALID")
            artifact_names.add(name)


def _validate_known_payloads(
    repo: Path,
    artifact_root: Path,
    artifacts: Mapping[str, dict[str, Any]],
    payloads: Mapping[str, dict[str, Any]],
    revision: str,
    source_tag: str,
    source_tag_object: str | None,
    artifact_records: Sequence[dict[str, Any]],
    claims: Sequence[dict[str, Any]],
    stage: str,
) -> dict[str, Any] | None:
    by_kind: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for artifact_id, item in artifacts.items():
        if artifact_id in payloads:
            by_kind.setdefault(item["kind"], []).append(
                (artifact_id, payloads[artifact_id])
            )
    supply_chain: dict[str, Any] | None = None
    release = by_kind.get("RELEASE_EVIDENCE_MANIFEST", [])
    marker = by_kind.get("RELEASE_EVIDENCE_VERIFICATION", [])
    if release and marker:
        release_id, manifest = release[0]
        supply_chain = _validate_release_evidence(
            repo, artifact_root, artifacts[release_id], manifest, marker[0][1], revision
        )
    for _, payload in by_kind.get("CONTRACT_SCHEMA_INDEX", []):
        _validate_contract_index(payload, revision)
    core = by_kind.get("CORE_ACCEPTANCE_MANIFEST", [])
    terraform_plan = next(
        item for item in artifact_records if item["kind"] == "TERRAFORM_PLAN"
    )
    release_images = supply_chain["images"] if supply_chain is not None else None
    for _, payload in core:
        _validate_core_acceptance(payload, revision, release_images, terraform_plan)
    faults = by_kind.get("FAULT_ACCEPTANCE_MANIFEST", [])
    if core and faults:
        _validate_fault_acceptance(faults[0][1], core[0][1], revision)
    for _, payload in by_kind.get("SECURITY_ABUSE_MANIFEST", []):
        _require_source_commit(payload, revision)
        if (
            payload.get("status") != "PASSED"
            or payload.get("target_unchanged_for_every_case") is not True
            or payload.get("no_temporary_iam") is not True
            or payload.get("no_controls_disabled") is not True
        ):
            raise BundleError("SECURITY_ABUSE_MANIFEST_INVALID")
    for _, payload in by_kind.get("PERFORMANCE_SUMMARY", []):
        source_run = payload.get("source_run", {})
        measurements = payload.get("measurements", {})
        run_cost = (
            measurements.get("run_cost", {}) if isinstance(measurements, dict) else {}
        )
        digests = payload.get("artifact_digests", {})
        core_digest = next(
            item["sha256"]
            for item in artifacts.values()
            if item["kind"] == "CORE_ACCEPTANCE_MANIFEST"
        )
        plan_digest = next(
            item["sha256"]
            for item in artifacts.values()
            if item["kind"] == "TERRAFORM_PLAN"
        )
        if (
            payload.get("environment", {}).get("source_commit") != revision
            or payload.get("measurement_result") != "OBSERVED"
            or payload.get("failures") != []
            or source_run.get("status") != "PASSED"
            or source_run.get("evidence_binding_complete") is not True
            or source_run.get("within_duration_bound") is not True
            or run_cost.get("within_bound") is not True
            or not isinstance(payload.get("measurement_set_sha256"), str)
            or SHA_RE.fullmatch(payload["measurement_set_sha256"]) is None
            or digests.get("acceptance_manifest_sha256") != core_digest
            or digests.get("terraform_plan_sha256") != plan_digest
            or not payload.get("known_limitations")
        ):
            raise BundleError("PERFORMANCE_SUMMARY_INVALID")
        scope = payload.get("claim_scope", {})
        if any(
            scope.get(key) is not False
            for key in (
                "internet_scale_claim",
                "production_reliability_claim",
                "production_slo_claim",
            )
        ):
            raise BundleError("PERFORMANCE_CLAIM_SCOPE_INVALID")
    for _, payload in by_kind.get("REQUIRED_CHECK_RESULTS", []):
        _require_source_commit(payload, revision)
        workflow_run_id = payload.get("workflow_run_id")
        if (
            payload.get("status") != "PASSED"
            or payload.get("checks")
            != {key: "PASSED" for key in sorted(REQUIRED_CHECKS)}
            or payload.get("head_sha") != revision
            or type(workflow_run_id) is not int
            or workflow_run_id <= 0
            or payload.get("event") != "push"
            or payload.get("run_url")
            != (
                "https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/"
                f"{workflow_run_id}"
            )
        ):
            raise BundleError("REQUIRED_CHECK_RESULTS_INVALID")
    for _, payload in by_kind.get("RELEASE_REVIEW", []):
        _require_source_commit(payload, revision)
        if (
            payload.get("status") != "PASSED"
            or payload.get("checks")
            != {key: "PASSED" for key in sorted(RELEASE_CHECKS)}
            or set(payload.get("claim_ids", [])) != {claim["id"] for claim in claims}
            or not payload.get("residual_risks")
        ):
            raise BundleError("RELEASE_REVIEW_INVALID")
    prepared = by_kind.get("PREPARED_BUNDLE", [])
    clean_room = by_kind.get("CLEAN_ROOM_REHEARSAL", [])
    if stage == "FINAL" and prepared and clean_room:
        _, prepared_payload = prepared[0]
        expected_artifacts = sorted(
            (item for item in artifact_records if item["kind"] not in FINAL_ONLY_KINDS),
            key=lambda item: item["id"],
        )
        if (
            prepared_payload.get("stage") != "PREPARED"
            or prepared_payload.get("status") != "PENDING"
            or prepared_payload.get("pending") != ["CLEAN_ROOM_REHEARSAL"]
            or prepared_payload.get("source")
            != {
                "repository": REPOSITORY,
                "revision": revision,
                "tag": source_tag,
                "tag_status": "VERIFIED",
                "tag_object_sha": source_tag_object,
            }
            or prepared_payload.get("artifacts") != expected_artifacts
            or prepared_payload.get("claims")
            != sorted(claims, key=lambda item: item["id"])
        ):
            raise BundleError("PREPARED_BUNDLE_INVALID")
    for _, payload in clean_room:
        _require_source_commit(payload, revision)
        sign_off = payload.get("sign_off")
        prepared_digest = artifacts[prepared[0][0]]["sha256"] if prepared else None
        outputs = _object(payload.get("outputs"), "CLEAN_ROOM_REHEARSAL_INVALID")
        if (
            payload.get("source_tag") != source_tag
            or payload.get("prepared_bundle_sha256") != prepared_digest
            or payload.get("status") != "PASSED"
            or payload.get("steps")
            != {key: "PASSED" for key in sorted(CLEAN_ROOM_STEPS)}
            or not isinstance(sign_off, dict)
            or not sign_off.get("reviewer_id")
            or not sign_off.get("recorded_at")
            or set(outputs)
            != {
                "terraform_plan",
                "core_acceptance_manifest",
                "evidence_link_validation",
            }
        ):
            raise BundleError("CLEAN_ROOM_REHEARSAL_INVALID")
        bound_outputs: dict[str, dict[str, Any]] = {}
        output_paths: dict[str, Path] = {}
        for name, value in outputs.items():
            bound_outputs[name], output_paths[name] = _clean_room_output(
                artifact_root, value
            )
        if (
            len({item["id"] for item in bound_outputs.values()}) != len(bound_outputs)
            or len(set(output_paths.values())) != len(output_paths)
            or output_paths["terraform_plan"]
            == _relative_path(artifact_root, terraform_plan["path"])
            or bound_outputs["terraform_plan"]["sha256"] == terraform_plan["sha256"]
        ):
            raise BundleError("CLEAN_ROOM_OUTPUT_INVALID")
        plan_payload, _ = _read_json(
            output_paths["terraform_plan"], "CLEAN_ROOM_TERRAFORM_PLAN_INVALID"
        )
        if not isinstance(plan_payload.get("format_version"), str):
            raise BundleError("CLEAN_ROOM_TERRAFORM_PLAN_INVALID")
        clean_core, _ = _read_json(
            output_paths["core_acceptance_manifest"],
            "CLEAN_ROOM_CORE_ACCEPTANCE_INVALID",
        )
        if not core:
            raise BundleError("CLEAN_ROOM_CORE_ACCEPTANCE_INVALID")
        primary_core_id, primary_core = core[0]
        clean_inputs = _object(
            clean_core.get("inputs"), "CLEAN_ROOM_CORE_ACCEPTANCE_INVALID"
        )
        primary_inputs = _object(
            primary_core.get("inputs"), "CLEAN_ROOM_CORE_ACCEPTANCE_INVALID"
        )
        if (
            bound_outputs["core_acceptance_manifest"]["sha256"]
            == artifacts[primary_core_id]["sha256"]
            or clean_core.get("run_id") == primary_core.get("run_id")
            or clean_inputs.get("source_commit") != primary_inputs.get("source_commit")
            or clean_inputs.get("target") != primary_inputs.get("target")
            or clean_inputs.get("images") != primary_inputs.get("images")
        ):
            raise BundleError("CLEAN_ROOM_CORE_ACCEPTANCE_INVALID")
        _validate_core_acceptance(
            clean_core,
            revision,
            release_images,
            bound_outputs["terraform_plan"],
        )
        links, _ = _read_json(
            output_paths["evidence_link_validation"],
            "CLEAN_ROOM_EVIDENCE_LINKS_INVALID",
        )
        if (
            links.get("schema_version") != "controlgraph.evidence-link-validation/v1"
            or links.get("status") != "PASSED"
            or links.get("source_commit") != revision
            or links.get("prepared_bundle_sha256") != prepared_digest
            or links.get("terraform_plan_sha256")
            != bound_outputs["terraform_plan"]["sha256"]
            or links.get("core_acceptance_manifest_sha256")
            != bound_outputs["core_acceptance_manifest"]["sha256"]
            or links.get("validated_claim_ids")
            != sorted(claim["id"] for claim in claims)
        ):
            raise BundleError("CLEAN_ROOM_EVIDENCE_LINKS_INVALID")
    return supply_chain


def _validate_claims(
    values: Any, artifacts: Mapping[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str], set[str]]:
    if not isinstance(values, list) or not values:
        raise BundleError("CLAIMS_INVALID")
    records: list[dict[str, Any]] = []
    pending: list[str] = []
    identifiers: set[str] = set()
    categories: set[str] = set()
    for value in values:
        item = _object(value, "CLAIM_INVALID")
        if set(item) != {
            "id",
            "category",
            "statement",
            "statement_sha256",
            "source_ids",
            "evidence_ids",
            "status",
        }:
            raise BundleError("CLAIM_INVALID")
        claim_id = item.get("id")
        statement = item.get("statement")
        source_ids = item.get("source_ids")
        evidence_ids = item.get("evidence_ids")
        if (
            not isinstance(claim_id, str)
            or ID_RE.fullmatch(claim_id) is None
            or claim_id in identifiers
            or item.get("category") not in CLAIM_CATEGORIES
            or not isinstance(statement, str)
            or not statement.strip()
            or len(statement) > 1000
            or item.get("statement_sha256")
            != hashlib.sha256(statement.encode()).hexdigest()
            or not isinstance(source_ids, list)
            or not source_ids
            or any(not isinstance(source_id, str) for source_id in source_ids)
            or len(set(source_ids)) != len(source_ids)
            or any(source_id not in artifacts for source_id in source_ids)
            or any(
                artifacts[source_id]["location"] != "REPOSITORY"
                or artifacts[source_id]["status"] != "VERIFIED"
                for source_id in source_ids
            )
            or not isinstance(evidence_ids, list)
            or not evidence_ids
            or any(not isinstance(evidence_id, str) for evidence_id in evidence_ids)
            or len(set(evidence_ids)) != len(evidence_ids)
            or any(value not in artifacts for value in evidence_ids)
            or item.get("status") not in {"PENDING", "SUPPORTED"}
        ):
            raise BundleError("CLAIM_INVALID")
        if item["status"] == "SUPPORTED":
            if any(
                artifacts[evidence_id]["status"] != "VERIFIED"
                for evidence_id in evidence_ids
            ):
                raise BundleError("SUPPORTED_CLAIM_HAS_PENDING_EVIDENCE")
        else:
            pending.append(f"CLAIM:{claim_id}")
        identifiers.add(claim_id)
        categories.add(item["category"])
        records.append(dict(item))
    if categories != CLAIM_CATEGORIES:
        raise BundleError("CLAIM_CATEGORY_COVERAGE_INVALID")
    return records, pending, identifiers


def verify_bundle(
    repo: Path, spec_path: Path, artifact_root: Path
) -> tuple[dict[str, Any], bool]:
    """Return the immutable bundle inventory and whether every gate is ready."""

    repo = repo.resolve(strict=True)
    spec, spec_bytes = _read_json(spec_path, "SPEC_INVALID")
    stage = spec.get("stage")
    if (
        spec.get("schema_version") != SPEC_SCHEMA
        or stage not in {"PREPARED", "FINAL"}
        or set(spec) != {"schema_version", "stage", "source", "artifacts", "claims"}
    ):
        raise BundleError("SPEC_INVALID")
    source, pending = _validate_source(repo, spec["source"])
    artifact_records, artifacts, payloads, artifact_pending = _bind_artifacts(
        repo, artifact_root.resolve(), spec["artifacts"], stage
    )
    claims, claim_pending, _ = _validate_claims(spec["claims"], artifacts)
    supply_chain = _validate_known_payloads(
        repo,
        artifact_root.resolve(),
        artifacts,
        payloads,
        source["revision"],
        source["tag"],
        source["tag_object_sha"],
        artifact_records,
        claims,
        stage,
    )
    pending.extend(artifact_pending)
    pending.extend(claim_pending)
    if stage == "PREPARED":
        pending.append("CLEAN_ROOM_REHEARSAL")
    elif pending:
        raise BundleError("FINAL_BUNDLE_INCOMPLETE")
    result: dict[str, Any] = {
        "artifacts": sorted(artifact_records, key=lambda value: value["id"]),
        "claims": sorted(claims, key=lambda value: value["id"]),
        "pending": sorted(pending),
        "schema_version": BUNDLE_SCHEMA,
        "source": source,
        "spec_sha256": hashlib.sha256(spec_bytes).hexdigest(),
        "stage": stage,
        "status": "READY" if stage == "FINAL" else "PENDING",
    }
    if supply_chain is not None:
        result["supply_chain"] = supply_chain
    return result, stage == "FINAL"


def _write_once(path: Path, value: Mapping[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(payload)
    except OSError as error:
        raise BundleError("OUTPUT_WRITE_FAILED") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a frozen ControlGraph claim/evidence bundle."
    )
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result, ready = verify_bundle(args.repo, args.spec, args.artifact_root)
        _write_once(args.output, result)
    except (BundleError, OSError) as error:
        print(f"frozen bundle verification failed: {error}", file=sys.stderr)
        return 2
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
