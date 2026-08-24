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
PROJECT_RE = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
IMAGE_RE = re.compile(
    r"^us-central1-docker\.pkg\.dev/controlgraph-canary-[a-z0-9]{6,10}/"
    r"controlgraph-canary/[a-z-]+@sha256:[0-9a-f]{64}$"
)

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
FAULT_KINDS: Final = frozenset(
    {
        "DELAYED_TASK",
        "DUPLICATE_DELIVERY",
        "REVOCATION_RACE",
        "MONITORING_GAP",
        "API_TIMEOUT",
        "CONFIGURATION_DRIFT",
        "PROBE_FAILURE",
    }
)
REQUIRED_KINDS: Final = frozenset(
    {
        "CONTRACT_SCHEMA_INDEX",
        "TERRAFORM_PLAN",
        "RELEASE_EVIDENCE_MANIFEST",
        "RELEASE_EVIDENCE_VERIFICATION",
        "CORE_ACCEPTANCE_MANIFEST",
        "FAULT_SCENARIO_SET",
        "FAULT_APPLICATION_EVIDENCE",
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
        "CLEAN_ROOM_REHEARSAL",
    }
)
ALLOWED_KINDS: Final = REQUIRED_KINDS | {"DEMO_MANIFEST"}
JSON_SCHEMAS: Final = {
    "CONTRACT_SCHEMA_INDEX": "controlgraph.contract-schema-index/v1",
    "RELEASE_EVIDENCE_MANIFEST": "controlgraph.release-evidence/v1",
    "RELEASE_EVIDENCE_VERIFICATION": "controlgraph.release-evidence-verification/v1",
    "CORE_ACCEPTANCE_MANIFEST": "controlgraph.core-acceptance-manifest/v1",
    "FAULT_SCENARIO_SET": "controlgraph.fault-scenario-set/v1",
    "FAULT_APPLICATION_EVIDENCE": "controlgraph.fault-application-evidence/v1",
    "SECURITY_ABUSE_MANIFEST": "controlgraph.security-abuse-manifest/v1",
    "PERFORMANCE_SUMMARY": "controlgraph.measurement-summary/v1",
    "REQUIRED_CHECK_RESULTS": "controlgraph.required-check-results/v1",
    "RELEASE_REVIEW": "controlgraph.release-review/v1",
    "CLEAN_ROOM_REHEARSAL": "controlgraph.clean-room-rehearsal/v1",
}
SINGLETON_KINDS: Final = REQUIRED_KINDS - {"FAULT_APPLICATION_EVIDENCE", "DEMO_ASSET"}
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


def _canonical_sha(value: Any) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


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
    if kind == "DEMO_MANIFEST" and (
        not isinstance(declared_schema, str) or not declared_schema
    ):
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
    repo: Path, artifact_root: Path, values: Any
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
    if not REQUIRED_KINDS.issubset(kinds):
        raise BundleError("REQUIRED_ARTIFACT_KIND_MISSING")
    if any(kinds[kind] != 1 for kind in SINGLETON_KINDS):
        raise BundleError("SINGLETON_ARTIFACT_KIND_INVALID")
    if (
        kinds["FAULT_APPLICATION_EVIDENCE"] != 7
        or kinds["DEMO_ASSET"] < 1
        or kinds["DEMO_MANIFEST"] > 1
    ):
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
        f"image-{name}"
        for name in (
            "controller",
            "console",
            "advisor",
            "reference-stable",
            "reference-candidate",
        )
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
            if not isinstance(reference, str) or IMAGE_RE.fullmatch(reference) is None:
                raise BundleError("RELEASE_IMAGE_REFERENCE_INVALID")
            images[name.removeprefix("image-")] = reference
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


def _validate_faults(
    payloads: Mapping[str, dict[str, Any]], artifacts: Mapping[str, dict[str, Any]]
) -> None:
    scenario_ids = [
        key for key, value in artifacts.items() if value["kind"] == "FAULT_SCENARIO_SET"
    ]
    evidence_ids = [
        key
        for key, value in artifacts.items()
        if value["kind"] == "FAULT_APPLICATION_EVIDENCE"
    ]
    if not scenario_ids or any(
        key not in payloads for key in [*scenario_ids, *evidence_ids]
    ):
        return
    scenarios = payloads[scenario_ids[0]].get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 7:
        raise BundleError("FAULT_SCENARIO_SET_INVALID")
    by_fault: dict[str, dict[str, Any]] = {}
    for value in scenarios:
        scenario = _object(value, "FAULT_SCENARIO_SET_INVALID")
        fault = scenario.get("fault")
        target = _object(scenario.get("target"), "FAULT_TARGET_INVALID")
        if (
            fault not in FAULT_KINDS
            or fault in by_fault
            or scenario.get("schema_version") != "controlgraph.fault-scenario/v1"
            or scenario.get("purpose") != "PRODUCT_VALIDATION"
        ):
            raise BundleError("FAULT_SCENARIO_SET_INVALID")
        if (
            target.get("schema_version") != "controlgraph.acceptance-fault-target/v1"
            or target.get("environment") != "acceptance"
            or target.get("region") != "us-central1"
            or target.get("service_name") != "controlgraph-reference-target"
            or not isinstance(target.get("project_id"), str)
            or PROJECT_RE.fullmatch(target["project_id"]) is None
        ):
            raise BundleError("FAULT_TARGET_INVALID")
        by_fault[fault] = scenario
    if set(by_fault) != FAULT_KINDS:
        raise BundleError("FAULT_SCENARIO_SET_INVALID")
    seen: set[str] = set()
    for evidence_id in evidence_ids:
        evidence = payloads[evidence_id]
        fault = evidence.get("fault")
        evidence_scenario = by_fault.get(str(fault))
        if (
            evidence_scenario is None
            or str(fault) in seen
            or evidence.get("result") != "PASSED"
            or evidence.get("purpose") != "PRODUCT_VALIDATION"
        ):
            raise BundleError("FAULT_APPLICATION_EVIDENCE_INVALID")
        if (
            evidence.get("scenario_id") != evidence_scenario.get("scenario_id")
            or evidence.get("scenario_sha256") != _canonical_sha(evidence_scenario)
            or evidence.get("target") != evidence_scenario.get("target")
            or evidence.get("boundary") != evidence_scenario.get("boundary")
            or evidence.get("random_seed") != evidence_scenario.get("random_seed")
            or evidence.get("activation_identity_sha256")
            != evidence_scenario.get("activation", {}).get("identity_sha256")
        ):
            raise BundleError("FAULT_APPLICATION_EVIDENCE_INVALID")
        required = evidence_scenario.get("required_invariants")
        observed = evidence.get("observed_invariants")
        if (
            not isinstance(required, list)
            or not isinstance(observed, list)
            or not set(required).issubset(observed)
        ):
            raise BundleError("FAULT_APPLICATION_EVIDENCE_INVALID")
        seen.add(str(fault))
    if seen != FAULT_KINDS:
        raise BundleError("FAULT_APPLICATION_EVIDENCE_INVALID")


def _validate_known_payloads(
    repo: Path,
    artifact_root: Path,
    artifacts: Mapping[str, dict[str, Any]],
    payloads: Mapping[str, dict[str, Any]],
    revision: str,
    source_tag: str,
    claim_ids: set[str],
) -> dict[str, Any] | None:
    by_kind: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for artifact_id, item in artifacts.items():
        if artifact_id in payloads:
            by_kind.setdefault(item["kind"], []).append(
                (artifact_id, payloads[artifact_id])
            )
    for _, payload in by_kind.get("CONTRACT_SCHEMA_INDEX", []):
        _validate_contract_index(payload, revision)
    for _, payload in by_kind.get("CORE_ACCEPTANCE_MANIFEST", []):
        if (
            payload.get("status") != "PASSED"
            or payload.get("evidence_binding_complete") is not True
            or payload.get("inputs", {}).get("source_commit") != revision
        ):
            raise BundleError("CORE_ACCEPTANCE_MANIFEST_INVALID")
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
        if payload.get("status") != "PASSED" or payload.get("checks") != {
            key: "PASSED" for key in sorted(REQUIRED_CHECKS)
        }:
            raise BundleError("REQUIRED_CHECK_RESULTS_INVALID")
    for _, payload in by_kind.get("RELEASE_REVIEW", []):
        _require_source_commit(payload, revision)
        if (
            payload.get("status") != "PASSED"
            or payload.get("checks")
            != {key: "PASSED" for key in sorted(RELEASE_CHECKS)}
            or set(payload.get("claim_ids", [])) != claim_ids
            or not payload.get("residual_risks")
        ):
            raise BundleError("RELEASE_REVIEW_INVALID")
    for _, payload in by_kind.get("CLEAN_ROOM_REHEARSAL", []):
        _require_source_commit(payload, revision)
        sign_off = payload.get("sign_off")
        if (
            payload.get("source_tag") != source_tag
            or payload.get("status") != "PASSED"
            or payload.get("steps")
            != {key: "PASSED" for key in sorted(CLEAN_ROOM_STEPS)}
            or not isinstance(sign_off, dict)
            or not sign_off.get("reviewer_id")
            or not sign_off.get("recorded_at")
        ):
            raise BundleError("CLEAN_ROOM_REHEARSAL_INVALID")
    _validate_faults(payloads, artifacts)
    release = by_kind.get("RELEASE_EVIDENCE_MANIFEST", [])
    marker = by_kind.get("RELEASE_EVIDENCE_VERIFICATION", [])
    if release and marker:
        release_id, manifest = release[0]
        return _validate_release_evidence(
            repo, artifact_root, artifacts[release_id], manifest, marker[0][1], revision
        )
    return None


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
            or item.get("source_ids") != ["source"]
            or not isinstance(evidence_ids, list)
            or not evidence_ids
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
            if item["category"] == "demo" and not any(
                artifacts[evidence_id]["kind"] == "DEMO_MANIFEST"
                for evidence_id in evidence_ids
            ):
                raise BundleError("DEMO_CLAIM_HAS_NO_FINAL_MANIFEST")
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
    if spec.get("schema_version") != SPEC_SCHEMA or set(spec) != {
        "schema_version",
        "source",
        "artifacts",
        "claims",
    }:
        raise BundleError("SPEC_INVALID")
    source, pending = _validate_source(repo, spec["source"])
    artifact_records, artifacts, payloads, artifact_pending = _bind_artifacts(
        repo, artifact_root.resolve(), spec["artifacts"]
    )
    claims, claim_pending, claim_ids = _validate_claims(spec["claims"], artifacts)
    supply_chain = _validate_known_payloads(
        repo,
        artifact_root.resolve(),
        artifacts,
        payloads,
        source["revision"],
        source["tag"],
        claim_ids,
    )
    pending.extend(artifact_pending)
    pending.extend(claim_pending)
    result: dict[str, Any] = {
        "artifacts": sorted(artifact_records, key=lambda value: value["id"]),
        "claims": sorted(claims, key=lambda value: value["id"]),
        "pending": sorted(pending),
        "schema_version": BUNDLE_SCHEMA,
        "source": source,
        "spec_sha256": hashlib.sha256(spec_bytes).hexdigest(),
        "status": "READY" if not pending else "PENDING",
    }
    if supply_chain is not None:
        result["supply_chain"] = supply_chain
    return result, not pending


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
