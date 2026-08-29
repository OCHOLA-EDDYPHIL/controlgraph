from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import sys
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

SCRIPT = Path(__file__).parents[2] / "scripts" / "core_acceptance.py"
SOURCE_ROOT = SCRIPT.parents[1]

CASES = (
    ("TARGET_RESET", ("CLOUD_RUN_CONFIGURATION", "DATA_PATH_PROBE")),
    (
        "HEALTHY_PROMOTION",
        (
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "VERIFIED_CAPABILITY_METADATA",
            "EXECUTOR_EPOCH_CHECK",
            "EXECUTION_RECEIPT",
            "HEALTH_DECISION",
            "TIMELINE",
        ),
    ),
    (
        "UNHEALTHY_STABLE_RECOVERY",
        (
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "VERIFIED_CAPABILITY_METADATA",
            "EXECUTOR_EPOCH_CHECK",
            "EXECUTION_RECEIPT",
            "HEALTH_DECISION",
            "RECOVERY_SERVICE_IDENTITY_BINDING",
            "TIMELINE",
        ),
    ),
    (
        "REVOCATION_STALE_DENIAL",
        (
            "AUTHORITY_TRANSITION",
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "VERIFIED_CAPABILITY_METADATA",
            "EXECUTOR_EPOCH_CHECK",
            "STALE_DENIAL",
            "EXECUTION_RECEIPT",
            "COORDINATOR",
            "MODEL_AUDIT",
            "TIMELINE",
        ),
    ),
    (
        "INDEPENDENT_VERIFIER_PROBE",
        (
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "INDEPENDENT_VERIFICATION",
            "TIMELINE",
        ),
    ),
    (
        "AMBIGUITY_CLASSIFICATION",
        (
            "CLOUD_RUN_CONFIGURATION",
            "EXECUTION_RECEIPT",
            "AMBIGUITY_CLASSIFICATION",
            "TIMELINE",
        ),
    ),
    (
        "TIMELINE_CONSOLE_READ",
        ("CLOUD_RUN_CONFIGURATION", "TIMELINE", "CONSOLE_READ"),
    ),
    (
        "BOUNDED_ADVISOR",
        (
            "CLOUD_RUN_CONFIGURATION",
            "COORDINATOR",
            "MODEL_AUDIT",
            "PUBLIC_REPLAY_SEED",
            "TIMELINE",
        ),
    ),
)


class _StrictTupleResponse(BaseModel):
    model_config = ConfigDict(strict=True)

    values: tuple[str, ...]


EXPECTED_RESULTS = {
    "TARGET_RESET": "RESET_VERIFIED",
    "HEALTHY_PROMOTION": "PROMOTED",
    "UNHEALTHY_STABLE_RECOVERY": "RECOVERED",
    "REVOCATION_STALE_DENIAL": "DENIED",
    "INDEPENDENT_VERIFIER_PROBE": "VERIFIED",
    "AMBIGUITY_CLASSIFICATION": "AMBIGUOUS",
    "TIMELINE_CONSOLE_READ": "READABLE",
    "BOUNDED_ADVISOR": "ADVISORY_ONLY",
}

ENTRY_POINTS = {
    "TARGET_RESET": (
        "runner:reset-reference-target",
        "runner:verify-stable-data-path",
    ),
    "HEALTHY_PROMOTION": (
        "runner:reset-reference-target",
        "runner:observe-healthy-promotion",
    ),
    "UNHEALTHY_STABLE_RECOVERY": (
        "runner:reset-reference-target",
        "runner:observe-unhealthy-stable-recovery",
    ),
    "REVOCATION_STALE_DENIAL": (
        "runner:reset-reference-target",
        "runner:observe-revocation-stale-denial",
    ),
    "INDEPENDENT_VERIFIER_PROBE": (
        "runner:reset-reference-target",
        "runner:observe-independent-verification",
    ),
    "AMBIGUITY_CLASSIFICATION": (
        "runner:reset-reference-target",
        "runner:observe-ambiguity-classification",
    ),
    "TIMELINE_CONSOLE_READ": (
        "runner:reset-reference-target",
        "runner:observe-timeline-console",
    ),
    "BOUNDED_ADVISOR": (
        "runner:reset-reference-target",
        "runner:observe-bounded-advisor",
    ),
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _test_identity_token(*, audience: str, email: str) -> str:
    now = int(datetime.now(tz=UTC).timestamp())
    encoded_claims = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "aud": audience,
                    "email": email,
                    "exp": now + 300,
                    "iat": now,
                    "iss": "https://accounts.google.com",
                }
            ).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"e30.{encoded_claims}.signature"


def _write(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical(value)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _artifact(artifact_id: str, relative_path: str, digest: str) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "media_type": "application/json",
        "relative_path": relative_path,
        "schema_version": "controlgraph.acceptance-artifact-binding/v1",
        "sha256": digest,
    }


def _run_inputs_sha256(spec: dict[str, Any]) -> str:
    projection = {
        "cases": [
            {key: value for key, value in item.items() if key != "result"} for item in spec["cases"]
        ],
        "images": spec["images"],
        "maximum_total_cost_microusd": spec["maximum_total_cost_microusd"],
        "maximum_total_duration_ms": spec["maximum_total_duration_ms"],
        "policies": spec["policies"],
        "random_seed": spec["random_seed"],
        "schema_version": "controlgraph.core-acceptance-run-inputs/v1",
        "source_commit": spec["source_commit"],
        "target": spec["target"],
        "terraform_plan": spec["terraform_plan"],
        "test_clock": spec["test_clock"],
    }
    return hashlib.sha256(_canonical(projection)).hexdigest()


def _git_repo(path: Path) -> str:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "scripts").mkdir()
    (path / "scripts" / "core_acceptance.py").write_bytes(SCRIPT.read_bytes())
    package = path / "backend" / "src" / "controlgraph_canary"
    (package / "contracts").mkdir(parents=True)
    for relative_path in (
        "__init__.py",
        "contracts/base.py",
        "contracts/codec.py",
    ):
        source = SOURCE_ROOT / "backend" / "src" / "controlgraph_canary" / relative_path
        destination = package / relative_path
        shutil.copy2(source, destination)
    (package / "contracts" / "__init__.py").write_text(
        '"""Acceptance runner test package."""\n',
        encoding="utf-8",
    )
    (path / "source.txt").write_text("synthetic\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Acceptance Test",
            "-c",
            "user.email=acceptance@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    repo = tmp_path / "repo"
    source_commit = _git_repo(repo)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    target = {
        "candidate_revision": "controlgraph-reference-target-candidate-v18",
        "environment": "nonprod",
        "project_id": "controlgraph-canary-abc123",
        "region": "us-central1",
        "schema_version": "controlgraph.acceptance-target/v1",
        "service_name": "controlgraph-reference-target",
        "stable_revision": "controlgraph-reference-target-stable-v18",
    }
    plan_sha = _write(artifacts / "inputs" / "plan.json", {"resource_changes": []})
    policy_sha = _write(artifacts / "inputs" / "policy.json", {"minimum_requests": 10})
    cases: list[dict[str, Any]] = []
    clock_ticks: list[dict[str, object]] = []
    for sequence, (kind, _) in enumerate(CASES, start=1):
        slug = kind.lower().replace("_", "-")
        case_id = f"core-case-{sequence}"
        clock_key = f"case-{sequence}-start"
        started_second = (sequence - 1) * 2
        clock_ticks.append(
            {
                "at": f"2026-08-24T00:00:{started_second:02d}Z",
                "name": clock_key,
                "schema_version": "controlgraph.acceptance-test-clock-tick/v1",
            }
        )
        cases.append(
            {
                "case_id": case_id,
                "kind": kind,
                "maximum_cost_microusd": 10,
                "maximum_duration_ms": 500,
                "random_seed": sequence,
                "schema_version": "controlgraph.core-acceptance-case-binding/v1",
                "sequence": sequence,
                "test_clock_keys": [clock_key],
            }
        )
    images = []
    for index, component in enumerate(
        ("controller", "advisor", "console", "reference-stable", "reference-candidate"),
        start=1,
    ):
        images.append(
            {
                "component": component,
                "reference": (
                    "us-central1-docker.pkg.dev/controlgraph-canary-abc123/"
                    f"controlgraph-canary/{component}@sha256:{index:064x}"
                ),
                "schema_version": "controlgraph.acceptance-image/v1",
            }
        )
    spec: dict[str, Any] = {
        "cases": cases,
        "images": images,
        "maximum_total_cost_microusd": 100,
        "maximum_total_duration_ms": 10_000,
        "policies": [
            {
                "artifact": _artifact("rollout-policy", "inputs/policy.json", policy_sha),
                "policy_schema_version": "controlgraph.rollout-health-policy/v1",
                "schema_version": "controlgraph.acceptance-policy-binding/v1",
            }
        ],
        "random_seed": 17,
        "schema_version": "controlgraph.core-acceptance-run-spec/v1",
        "source_commit": source_commit,
        "target": target,
        "terraform_plan": _artifact("terraform-plan", "inputs/plan.json", plan_sha),
        "test_clock": {
            "schema_version": "controlgraph.acceptance-test-clock/v1",
            "ticks": clock_ticks,
        },
    }
    run_inputs_sha256 = _run_inputs_sha256(spec)
    for sequence, ((kind, evidence_kinds), binding) in enumerate(
        zip(CASES, cases, strict=True),
        start=1,
    ):
        slug = kind.lower().replace("_", "-")
        started_second = (sequence - 1) * 2
        completed_second = started_second + 1
        evidence: list[dict[str, object]] = []
        evidence_ids: list[str] = []
        for evidence_sequence, evidence_kind in enumerate(evidence_kinds, start=1):
            evidence_id = f"{slug}-{evidence_sequence}"
            relative_path = f"evidence/{evidence_id}.json"
            digest = _write(
                artifacts / relative_path,
                {
                    "case_id": binding["case_id"],
                    "evidence_id": evidence_id,
                    "kind": evidence_kind,
                    "observed_at": f"2026-08-24T00:00:{completed_second:02d}Z",
                    "ordinal": evidence_sequence,
                    "run_inputs_sha256": run_inputs_sha256,
                    "schema_version": "controlgraph.hosted-acceptance-observation/v1",
                    "source": {
                        "observation": {
                            "private_marker": "not-copied-to-manifest",
                            "synthetic": True,
                        },
                        "schema_version": (
                            "controlgraph.hosted-evidence-"
                            f"{evidence_kind.lower().replace('_', '-')}/v1"
                        ),
                    },
                },
            )
            evidence.append(
                {
                    "artifact": _artifact(f"artifact-{evidence_id}", relative_path, digest),
                    "evidence_id": evidence_id,
                    "kind": evidence_kind,
                    "observed_at": f"2026-08-24T00:00:{completed_second:02d}Z",
                    "projection": "PRIVATE_DIGEST_ONLY",
                    "run_inputs_sha256": run_inputs_sha256,
                    "schema_version": "controlgraph.acceptance-evidence-binding/v1",
                }
            )
            evidence_ids.append(evidence_id)
        entry_points = ENTRY_POINTS[kind]
        result = {
            "case_id": binding["case_id"],
            "completed_at": f"2026-08-24T00:00:{completed_second:02d}Z",
            "cost_basis": "UPPER_BOUND",
            "cost_microusd": 1,
            "duration_ms": 100,
            "evidence": evidence,
            "execution_mode": "HOSTED_GOOGLE_CLOUD",
            "kind": kind,
            "observed_result": EXPECTED_RESULTS[kind],
            "random_seed": sequence,
            "run_inputs_sha256": run_inputs_sha256,
            "schema_version": "controlgraph.core-acceptance-case-result/v1",
            "source_commit": source_commit,
            "started_at": f"2026-08-24T00:00:{started_second:02d}Z",
            "status": "PASSED",
            "steps": [
                {
                    "duration_ms": 1,
                    "evidence_ids": (
                        [
                            evidence_ids[index % len(evidence_ids)],
                            *evidence_ids[len(entry_points) :],
                        ]
                        if index == 0
                        else [evidence_ids[index % len(evidence_ids)]]
                    ),
                    "operation": operation,
                    "schema_version": "controlgraph.core-acceptance-step-result/v1",
                    "sequence": index + 1,
                    "status": "PASSED",
                }
                for index, operation in enumerate(entry_points)
            ],
            "target": target,
            "test_clock_keys": binding["test_clock_keys"],
        }
        result_path = f"results/{slug}.json"
        result_sha = _write(artifacts / result_path, result)
        binding["result"] = _artifact(f"result-{slug}", result_path, result_sha)
    spec_path = tmp_path / "run-spec.json"
    _write(spec_path, spec)
    return repo, artifacts, spec_path, spec


def _run(
    repo: Path,
    artifacts: Path,
    spec_path: Path,
    output: Path,
    *,
    bound_package: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if bound_package:
        environment["PYTHONPATH"] = str(repo / "backend" / "src")
    else:
        environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [
            sys.executable,
            str(repo / "scripts" / "core_acceptance.py"),
            "--spec",
            str(spec_path),
            "--artifact-root",
            str(artifacts),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )


def test_binds_complete_core_run_without_copying_private_evidence(tmp_path: Path) -> None:
    repo, artifacts, spec_path, _ = _fixture(tmp_path)
    output = tmp_path / "manifest.json"

    completed = _run(repo, artifacts, spec_path, output)

    assert completed.returncode == 0
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "controlgraph.core-acceptance-manifest/v1"
    assert manifest["status"] == "PASSED"
    assert manifest["evidence_binding_complete"] is True
    assert [item["kind"] for item in manifest["cases"]] == [item[0] for item in CASES]
    assert (
        manifest["inputs"]["source_commit"]
        == subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    encoded = output.read_text(encoding="utf-8")
    assert "relative_path" not in encoded
    assert "private_marker" not in encoded
    assert "not-copied-to-manifest" not in encoded


def test_rejects_incomplete_core_case_set(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["cases"].pop()
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_SPEC_INVALID"}'
    assert not (tmp_path / "manifest.json").exists()


def test_rejects_target_outside_isolated_project(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["target"]["project_id"] = "production-control-plane"
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_SPEC_INVALID"}'


def test_rejects_missing_advisor_image(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["images"].pop(1)
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_SPEC_INVALID"}'


def test_rejects_changed_evidence_artifact(tmp_path: Path) -> None:
    repo, artifacts, spec_path, _ = _fixture(tmp_path)
    evidence = next((artifacts / "evidence").iterdir())
    evidence.write_text("changed", encoding="utf-8")

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_ARTIFACT_DIGEST_MISMATCH"}'


def test_rejects_digest_bound_evidence_without_the_typed_observation_envelope(
    tmp_path: Path,
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    binding = spec["cases"][0]
    result_path = artifacts / binding["result"]["relative_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    evidence = result["evidence"][0]
    evidence_path = artifacts / evidence["artifact"]["relative_path"]
    observation = json.loads(evidence_path.read_text(encoding="utf-8"))
    observation["source"]["schema_version"] = "controlgraph.hosted-evidence-wrong/v1"
    evidence["artifact"]["sha256"] = _write(evidence_path, observation)
    binding["result"]["sha256"] = _write(result_path, result)
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_EVIDENCE_INVALID"}'


def test_rejects_case_not_bound_to_fixed_product_entry_points(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    binding = spec["cases"][0]
    result_path = artifacts / binding["result"]["relative_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["steps"][0]["operation"] = "custom:acceptance-driver"
    binding["result"]["sha256"] = _write(result_path, result)
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_CASE_BINDING_MISMATCH"}'


def test_rejects_caller_defined_success_outcome(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    binding = spec["cases"][1]
    result_path = artifacts / binding["result"]["relative_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["observed_result"] = "EXPECTED"
    binding["result"]["sha256"] = _write(result_path, result)
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_CASE_RESULT_INVALID"}'


def test_rejects_result_from_different_run_inputs(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["random_seed"] = 18
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_CASE_BINDING_MISMATCH"}'


def test_rejects_overlapping_case_intervals(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    binding = spec["cases"][1]
    result_path = artifacts / binding["result"]["relative_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["started_at"] = "2026-08-24T00:00:00Z"
    result["completed_at"] = "2026-08-24T00:00:01Z"
    for evidence in result["evidence"]:
        evidence["observed_at"] = "2026-08-24T00:00:01Z"
        evidence_path = artifacts / evidence["artifact"]["relative_path"]
        observation = json.loads(evidence_path.read_text(encoding="utf-8"))
        observation["observed_at"] = "2026-08-24T00:00:01Z"
        evidence["artifact"]["sha256"] = _write(evidence_path, observation)
    binding["result"]["sha256"] = _write(result_path, result)
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_CASE_SEQUENCE_INVALID"}'


def test_emits_failed_manifest_for_a_terminal_case_failure(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    binding = spec["cases"][1]
    result_path = artifacts / binding["result"]["relative_path"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["observed_result"] = "FAILED_SAFE"
    result["status"] = "FAILED"
    result["steps"][0]["status"] = "FAILED"
    binding["result"]["sha256"] = _write(result_path, result)
    _write(spec_path, spec)
    output = tmp_path / "manifest.json"

    completed = _run(repo, artifacts, spec_path, output)

    assert completed.returncode == 1
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["status"] == "FAILED"
    assert manifest["evidence_binding_complete"] is False
    assert manifest["cases"][1]["observed_result"] == "FAILED_SAFE"


def test_rejects_dirty_source_checkout(tmp_path: Path) -> None:
    repo, artifacts, spec_path, _ = _fixture(tmp_path)
    (repo / "source.txt").write_text("changed\n", encoding="utf-8")

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_SOURCE_DIRTY"}'


def test_rejects_package_loaded_from_another_checkout(tmp_path: Path) -> None:
    repo, artifacts, spec_path, _ = _fixture(tmp_path)

    completed = _run(
        repo,
        artifacts,
        spec_path,
        tmp_path / "manifest.json",
        bound_package=False,
    )

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"ACCEPTANCE_SOURCE_MISMATCH"}'


def test_hosted_execute_requires_matching_double_confirmation(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(SOURCE_ROOT / "backend" / "src")
    environment.pop("CONTROLGRAPH_CORE_ACCEPTANCE_CONFIRM", None)

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "execute",
            "--spec",
            str(tmp_path / "missing-spec.json"),
            "--artifact-root",
            str(tmp_path),
            "--output-spec",
            str(tmp_path / "bound-spec.json"),
            "--output",
            str(tmp_path / "manifest.json"),
            "--project-number",
            "123456789",
            "--network-resource",
            "projects/controlgraph-canary-abc123/global/networks/test",
            "--subnetwork-resource",
            "projects/controlgraph-canary-abc123/regions/us-central1/subnetworks/test",
            "--verifier-service-account",
            "controlgraph-verifier@controlgraph-canary-abc123.iam.gserviceaccount.com",
            "--restricted-exporter-service-account",
            "cg-restricted-exporter@controlgraph-canary-abc123.iam.gserviceaccount.com",
            "--acceptance-identity",
            "acceptance@example.invalid",
            "--confirm",
            "RUN_CONTROLGRAPH_CORE_ACCEPTANCE",
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 2
    assert completed.stderr.strip() == ('{"code":"ACCEPTANCE_HOSTED_CONFIRMATION_REQUIRED"}')
    assert not (tmp_path / "manifest.json").exists()


def test_generate_spec_emits_a_deterministic_operable_template(tmp_path: Path) -> None:
    repo, artifacts, _spec_path, spec = _fixture(tmp_path)
    first = tmp_path / "generated-first.json"
    second = tmp_path / "generated-second.json"
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(SOURCE_ROOT / "backend" / "src")
    base = [
        sys.executable,
        str(SCRIPT),
        "generate-spec",
        "--artifact-root",
        str(artifacts),
        "--project-id",
        spec["target"]["project_id"],
        "--source-commit",
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "--stable-revision",
        spec["target"]["stable_revision"],
        "--candidate-revision",
        spec["target"]["candidate_revision"],
    ]
    for option, image in zip(
        (
            "--controller-image",
            "--advisor-image",
            "--console-image",
            "--reference-stable-image",
            "--reference-candidate-image",
        ),
        spec["images"],
        strict=True,
    ):
        base.extend((option, image["reference"]))
    base.extend(
        (
            "--terraform-plan",
            "inputs/plan.json",
            "--policy-schema-version",
            "controlgraph.rollout-health-policy/v1",
            "--policy-artifact",
            "inputs/policy.json",
            "--clock-start",
            "2026-08-24T00:00:00Z",
            "--random-seed",
            "17",
        )
    )

    for output in (first, second):
        completed = subprocess.run(
            [*base, "--output", str(output)],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )
        assert completed.returncode == 0

    generated = json.loads(first.read_text(encoding="utf-8"))
    assert first.read_bytes() == second.read_bytes()
    assert generated["target"]["environment"] == "nonprod"
    assert [case["kind"] for case in generated["cases"]] == [kind for kind, _ in CASES]
    assert {case["result"]["sha256"] for case in generated["cases"]} == {"0" * 64}


def test_hosted_execute_resets_before_all_eight_fixed_cases(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _repo, artifacts, _spec_path, spec_value = _fixture(tmp_path)
    shutil.rmtree(artifacts / "evidence")
    shutil.rmtree(artifacts / "results")
    for case in spec_value["cases"]:
        case["result"]["sha256"] = "0" * 64
    template = tmp_path / "template.json"
    _write(template, spec_value)
    module_spec = importlib.util.spec_from_file_location("core_acceptance_execute_test", SCRIPT)
    assert module_spec is not None and module_spec.loader is not None
    runner = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = runner
    module_spec.loader.exec_module(runner)
    reset_cases: list[str] = []

    monkeypatch.setenv(
        "CONTROLGRAPH_CORE_ACCEPTANCE_CONFIRM",
        "RUN_CONTROLGRAPH_CORE_ACCEPTANCE",
    )
    monkeypatch.setattr(runner, "_verify_source", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner, "_verify_exact_remote_main", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner, "_verify_hosted_bindings", lambda *_args, **_kwargs: None)

    def reset(_run: Any, case: Any) -> dict[str, str]:
        reset_cases.append(case.kind.value)
        return {"schema_version": "test.reset/v1"}

    def observations(_run: Any, case: Any, *_args: Any) -> Any:
        return runner._CaseOutcome(
            observations={
                kind: {"schema_version": f"test.{kind.value.lower()}/v1"}
                for kind in runner.REQUIRED_EVIDENCE[case.kind]
            },
            terminal_result=runner.EXPECTED_RESULTS[case.kind],
        )

    monkeypatch.setattr(runner, "_reset_target", reset)
    monkeypatch.setattr(
        runner,
        "_probe_stable",
        lambda *_args: {"schema_version": "test.probe/v1", "status": "COMPLETE"},
    )
    monkeypatch.setattr(runner, "_run_healthy_case", observations)
    monkeypatch.setattr(runner, "_run_unhealthy_case", observations)
    monkeypatch.setattr(runner, "_run_revocation_case", observations)
    monkeypatch.setattr(runner, "_run_verifier_case", observations)
    monkeypatch.setattr(runner, "_run_ambiguity_case", observations)
    monkeypatch.setattr(runner, "_run_timeline_console_case", observations)
    monkeypatch.setattr(runner, "_run_advisor_case", observations)

    output_spec = tmp_path / "bound-spec.json"
    output_manifest = tmp_path / "manifest.json"
    _payload, _run_id, status = runner.execute_hosted(
        spec_path=template,
        artifact_root=artifacts,
        output_spec=output_spec,
        output_manifest=output_manifest,
        project_number="123456789",
        network_resource="projects/controlgraph-canary-abc123/global/networks/test",
        subnetwork_resource=(
            "projects/controlgraph-canary-abc123/regions/us-central1/subnetworks/test"
        ),
        verifier_service_account=(
            "controlgraph-verifier@controlgraph-canary-abc123.iam.gserviceaccount.com"
        ),
        restricted_exporter_service_account=(
            "cg-restricted-exporter@controlgraph-canary-abc123.iam.gserviceaccount.com"
        ),
        acceptance_identity="acceptance@example.invalid",
        confirmation="RUN_CONTROLGRAPH_CORE_ACCEPTANCE",
    )

    assert reset_cases == [kind for kind, _evidence in CASES]
    assert status.value == "PASSED"
    assert output_spec.is_file()
    assert output_manifest.is_file()


def test_hosted_cli_decodes_json_arrays_for_strict_tuple_contracts(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    module_spec = importlib.util.spec_from_file_location(
        "core_acceptance_hosted_response_test", SCRIPT
    )
    assert module_spec is not None and module_spec.loader is not None
    runner = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = runner
    module_spec.loader.exec_module(runner)
    monkeypatch.setattr(
        runner,
        "_capture_process",
        lambda *_args, **_kwargs: (0, b'{"values":["one","two"]}\n'),
    )

    _status, decoded, model = runner._run_cli(
        repo=tmp_path,
        entry_point="controlgraph-canary",
        arguments=(),
        model_type=_StrictTupleResponse,
    )

    assert decoded == {"values": ["one", "two"]}
    assert model is not None and model.values == ("one", "two")


def test_service_account_identity_token_uses_direct_iam_credentials_request(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    audience = "https://controlgraph-api-123456789.us-central1.run.app"
    service_account = "cg-restricted-exporter@controlgraph-canary-abc123.iam.gserviceaccount.com"
    expected_token = _test_identity_token(audience=audience, email=service_account)
    process_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    request_calls: list[tuple[Any, int]] = []

    def capture_process(
        argv: tuple[str, ...],
        **kwargs: Any,
    ) -> tuple[int, bytes]:
        process_calls.append((argv, kwargs))
        return 0, b"opaque-source-credential\n"

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def read(self, maximum_bytes: int) -> bytes:
            assert maximum_bytes == runner.MAX_ARTIFACT_BYTES + 1
            return json.dumps({"token": expected_token}).encode("utf-8")

    class Opener:
        def open(self, request: Any, *, timeout: int) -> Response:
            request_calls.append((request, timeout))
            return Response()

    monkeypatch.setattr(runner, "_capture_process", capture_process)
    monkeypatch.setattr(runner, "_HTTP_OPENER", Opener())
    run = SimpleNamespace(
        repo=tmp_path,
        api_origin=audience,
        acceptance_identity="acceptance@example.invalid",
        spec=SimpleNamespace(target=SimpleNamespace(project_id="controlgraph-canary-abc123")),
    )

    assert runner._identity_token(run, service_account) == expected_token

    assert process_calls == [
        (
            ("gcloud", "auth", "print-access-token", "acceptance@example.invalid"),
            {"repo": tmp_path, "timeout": 60},
        )
    ]
    request, timeout = request_calls[0]
    assert len(request_calls) == 1
    assert timeout == 30
    assert request.full_url == (
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
        "cg-restricted-exporter%40controlgraph-canary-abc123.iam.gserviceaccount.com:"
        "generateIdToken"
    )
    assert request.get_method() == "POST"
    assert request.data == (
        b'{"audience":"https://controlgraph-api-123456789.us-central1.run.app","includeEmail":true}'
    )
    assert dict(request.header_items()) == {
        "Accept": "application/json",
        "Authorization": "Bearer opaque-source-credential",
        "Content-type": "application/json",
        "User-agent": "controlgraph-m8-core/1",
        "X-goog-user-project": "controlgraph-canary-abc123",
    }
    assert "impersonate" not in " ".join(process_calls[0][0]).lower()
    assert "generateAccessToken" not in request.full_url


@pytest.mark.parametrize(
    ("status", "payload"),
    (
        (403, b'{"error":{"message":"provider-private-detail"}}'),
        (200, b"not-json"),
        (200, b"{}"),
        (200, b'{"token":""}'),
    ),
)
def test_service_account_identity_token_sanitizes_provider_failures(
    tmp_path: Path,
    monkeypatch: Any,
    status: int,
    payload: bytes,
) -> None:
    runner = _hosted_module(tmp_path)

    class Response:
        def __init__(self) -> None:
            self.status = status

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def read(self, _maximum_bytes: int) -> bytes:
            return payload

    monkeypatch.setattr(
        runner,
        "_capture_process",
        lambda *_args, **_kwargs: (0, b"opaque-source-credential\n"),
    )
    monkeypatch.setattr(
        runner,
        "_HTTP_OPENER",
        SimpleNamespace(open=lambda *_args, **_kwargs: Response()),
    )
    run = SimpleNamespace(
        repo=tmp_path,
        acceptance_identity="acceptance@example.invalid",
        spec=SimpleNamespace(target=SimpleNamespace(project_id="controlgraph-canary-abc123")),
    )

    with pytest.raises(runner.AcceptanceError) as captured:
        runner._service_account_identity_token(
            run,
            service_account=(
                "cg-restricted-exporter@controlgraph-canary-abc123.iam.gserviceaccount.com"
            ),
            audience="https://controlgraph-api-123456789.us-central1.run.app",
        )

    assert captured.value.code == "ACCEPTANCE_HOSTED_IDENTITY_INVALID"
    assert str(captured.value) == "ACCEPTANCE_HOSTED_IDENTITY_INVALID"
    assert "provider-private-detail" not in str(captured.value)


@pytest.mark.parametrize(
    ("token_audience", "token_email"),
    (
        ("https://wrong.example.invalid", "restricted@example.invalid"),
        ("https://api.example.invalid", "wrong@example.invalid"),
    ),
)
def test_service_account_identity_token_requires_exact_claims(
    tmp_path: Path,
    monkeypatch: Any,
    token_audience: str,
    token_email: str,
) -> None:
    runner = _hosted_module(tmp_path)
    audience = "https://api.example.invalid"
    service_account = "restricted@example.invalid"
    token = _test_identity_token(audience=token_audience, email=token_email)
    monkeypatch.setattr(
        runner,
        "_service_account_identity_token",
        lambda *_args, **_kwargs: token,
    )
    run = SimpleNamespace(repo=tmp_path, api_origin=audience)

    with pytest.raises(runner.AcceptanceError) as captured:
        runner._identity_token(run, service_account)

    assert captured.value.code == "ACCEPTANCE_HOSTED_IDENTITY_INVALID"


def test_operator_identity_token_path_is_unchanged(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    token = _test_identity_token(
        audience="https://api.example.invalid",
        email="acceptance@example.invalid",
    )
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def capture_process(
        argv: tuple[str, ...],
        **kwargs: Any,
    ) -> tuple[int, bytes]:
        calls.append((argv, kwargs))
        return 0, f"{token}\n".encode("ascii")

    class NoHttp:
        def open(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("operator identity must not call IAM Credentials")

    monkeypatch.setattr(runner, "_capture_process", capture_process)
    monkeypatch.setattr(runner, "_HTTP_OPENER", NoHttp())
    run = SimpleNamespace(repo=tmp_path, api_origin="https://api.example.invalid")

    assert runner._identity_token(run) == token
    assert calls == [
        (("gcloud", "auth", "print-identity-token"), {"repo": tmp_path, "timeout": 60})
    ]


def test_hosted_root_creation_retries_exact_unknown_with_same_command(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    run = SimpleNamespace(repo=tmp_path, project_number="123456789")
    command_path = tmp_path / "root.json"
    adopted = SimpleNamespace(outcome="ADOPTED")
    responses = [
        (4, {"code": "ROOT_CREATION_OUTCOME_UNKNOWN"}, None),
        (0, {}, adopted),
    ]
    invocations: list[dict[str, Any]] = []
    sleeps: list[int] = []

    def run_cli(**kwargs: Any) -> tuple[int, dict[str, Any], Any]:
        invocations.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(runner, "_run_cli", run_cli)
    monkeypatch.setattr(runner.time, "sleep", sleeps.append)

    result = runner._submit_root_creation(run, command_path)

    assert result is adopted
    assert len(invocations) == 2
    assert invocations[0]["arguments"] == invocations[1]["arguments"]
    assert invocations[0]["allowed_statuses"] == frozenset({0, 4})
    assert invocations[1]["allowed_statuses"] == frozenset({0, 4})
    assert sleeps == [1]


def test_hosted_root_creation_rejects_adoption_without_ambiguity(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    monkeypatch.setattr(
        runner,
        "_run_cli",
        lambda **_kwargs: (0, {}, SimpleNamespace(outcome="ADOPTED")),
    )

    try:
        runner._submit_root_creation(
            SimpleNamespace(repo=tmp_path, project_number="123456789"),
            tmp_path / "root.json",
        )
    except runner.AcceptanceError as error:
        assert error.code == "ACCEPTANCE_HOSTED_ROOT_INVALID"
    else:
        raise AssertionError("an unambiguous root adoption was unexpectedly accepted")


def test_hosted_root_creation_unknown_outcome_retry_is_bounded(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    calls = {"count": 0}
    sleeps: list[int] = []

    def run_cli(**_kwargs: Any) -> tuple[int, dict[str, str], None]:
        calls["count"] += 1
        return 4, {"code": "ROOT_CREATION_OUTCOME_UNKNOWN"}, None

    monkeypatch.setattr(runner, "_run_cli", run_cli)
    monkeypatch.setattr(runner.time, "sleep", sleeps.append)

    try:
        runner._submit_root_creation(
            SimpleNamespace(repo=tmp_path, project_number="123456789"),
            tmp_path / "root.json",
        )
    except runner.AcceptanceError as error:
        assert error.code == "ACCEPTANCE_HOSTED_ROOT_AMBIGUOUS"
    else:
        raise AssertionError("three ambiguous root attempts unexpectedly succeeded")

    assert calls["count"] == 3
    assert sleeps == [1, 1]


def test_hosted_root_creation_does_not_retry_other_status_four_payloads(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    calls = {"count": 0}

    def run_cli(**_kwargs: Any) -> tuple[int, dict[str, str], None]:
        calls["count"] += 1
        return 4, {"code": "ROOT_CREATION_OUTCOME_UNKNOWN", "detail": "extra"}, None

    monkeypatch.setattr(runner, "_run_cli", run_cli)

    try:
        runner._submit_root_creation(
            SimpleNamespace(repo=tmp_path, project_number="123456789"),
            tmp_path / "root.json",
        )
    except runner.AcceptanceError as error:
        assert error.code == "ACCEPTANCE_HOSTED_ROOT_INVALID"
    else:
        raise AssertionError("a non-exact ambiguity payload was unexpectedly retried")

    assert calls["count"] == 1


def test_hosted_health_evaluation_adopts_after_delayed_unknown(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    result = SimpleNamespace(terminal_status="unhealthy")
    responses = [
        (4, {"code": "HEALTH_EVALUATION_OUTCOME_UNKNOWN"}, None),
    ] * 4 + [(0, {}, result)]
    invocations: list[dict[str, Any]] = []
    sleeps: list[int] = []

    def run_cli(**kwargs: Any) -> tuple[int, dict[str, Any], Any]:
        invocations.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(runner, "_run_cli", run_cli)
    monkeypatch.setattr(runner, "_write_command", lambda *_args: None)
    monkeypatch.setattr(runner.time, "sleep", sleeps.append)
    run = SimpleNamespace(
        repo=tmp_path,
        project_number="123456789",
        command_path=lambda _case, _label: tmp_path / "health.json",
    )

    observed = runner._evaluate_health(
        run,
        SimpleNamespace(),
        command=SimpleNamespace(),
        label="second",
    )

    assert observed is result
    assert len(invocations) == 5
    assert all(call["allowed_statuses"] == frozenset({0, 4}) for call in invocations)
    assert sleeps == [1, 1, 1, 1]


def test_hosted_binding_uses_the_deployed_evidence_writer_identity(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _repo, _artifacts, spec_path, _spec_value = _fixture(tmp_path)
    module_spec = importlib.util.spec_from_file_location(
        "core_acceptance_hosted_binding_test", SCRIPT
    )
    assert module_spec is not None and module_spec.loader is not None
    runner = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = runner
    module_spec.loader.exec_module(runner)
    _payload, spec = runner._load_contract(
        spec_path,
        runner.CoreAcceptanceRunSpecV1,
        error_code="ACCEPTANCE_SPEC_INVALID",
    )
    project_id = spec.target.project_id
    active_identity = "acceptance@example.invalid"

    def gcloud_json(arguments: tuple[str, ...], **_kwargs: Any) -> object:
        if arguments[:2] == ("auth", "list"):
            return [{"account": active_identity}]
        if arguments[:2] == ("projects", "describe"):
            return {"projectNumber": "123456789"}
        role = arguments[3].removeprefix("controlgraph-")
        component = (
            runner.ImageComponent.ADVISOR
            if role == "advisor"
            else runner.ImageComponent.CONSOLE
            if role == "console"
            else runner.ImageComponent.CONTROLLER
        )
        account_id = "cg-evidence-writer" if role == "evidence-writer" else f"controlgraph-{role}"
        return {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"image": runner._image(spec, component)}],
                        "serviceAccountName": (
                            f"{account_id}@{project_id}.iam.gserviceaccount.com"
                        ),
                    }
                }
            }
        }

    monkeypatch.setattr(runner, "_gcloud_json", gcloud_json)
    run = runner._HostedExecution(
        repo=tmp_path,
        artifact_root=tmp_path,
        spec=spec,
        run_inputs_sha256="1" * 64,
        project_number="123456789",
        network_resource=f"projects/{project_id}/global/networks/test",
        subnetwork_resource=(f"projects/{project_id}/regions/us-central1/subnetworks/test"),
        verifier_service_account=(f"controlgraph-verifier@{project_id}.iam.gserviceaccount.com"),
        restricted_exporter_service_account=(
            f"cg-restricted-exporter@{project_id}.iam.gserviceaccount.com"
        ),
        acceptance_identity=active_identity,
    )

    runner._verify_hosted_bindings(run)

    assert run.service_bindings["evidence-writer"]["service_account"] == (
        f"cg-evidence-writer@{project_id}.iam.gserviceaccount.com"
    )


def test_uncertain_revocation_leaves_held_queue_for_explicit_cleanup(
    monkeypatch: Any,
) -> None:
    module_spec = importlib.util.spec_from_file_location(
        "core_acceptance_queue_safety_test", SCRIPT
    )
    assert module_spec is not None and module_spec.loader is not None
    runner = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = runner
    module_spec.loader.exec_module(runner)
    root = SimpleNamespace(root_id="cgroot:test")
    run = SimpleNamespace(
        execution_queue_cleanup_required=False,
        root_ids=set(),
        unreleased_root_ids=set(),
    )
    queue_actions: list[str] = []

    monkeypatch.setattr(runner, "_create_root", lambda *_args: SimpleNamespace(root=root))

    def health_load(*_args: Any, **kwargs: Any) -> tuple[object, ...]:
        kwargs["before_terminal"]()
        return object(), object(), object(), object()

    monkeypatch.setattr(runner, "_health_load", health_load)
    monkeypatch.setattr(
        runner,
        "_queue_control",
        lambda _run, action: queue_actions.append(action),
    )
    monkeypatch.setattr(runner, "_promote", lambda *_args, **_kwargs: (object(), object()))

    def uncertain_revoke(*_args: Any, **_kwargs: Any) -> None:
        raise runner.AcceptanceError("ACCEPTANCE_HOSTED_REVOCATION_INVALID")

    monkeypatch.setattr(runner, "_revoke", uncertain_revoke)

    try:
        runner._run_revocation_case(run, object())
    except runner.AcceptanceError as error:
        assert error.code == "ACCEPTANCE_HOSTED_REVOCATION_INVALID"
    else:
        raise AssertionError("uncertain revocation unexpectedly succeeded")

    assert queue_actions == ["hold"]
    assert run.execution_queue_cleanup_required is True
    failure = runner._runner_failure_observation(
        run,
        code="ACCEPTANCE_HOSTED_REVOCATION_INVALID",
        disposition="FAILED",
        reset_completed=True,
    )
    assert failure["execution_queue_cleanup_required"] is True


def test_revocation_fetches_proof_after_stale_receipt() -> None:
    runner = _hosted_module(Path(__file__).parent)
    source = inspect.getsource(runner._run_revocation_case)

    release = source.index('_queue_control(run, "release")')
    receipt = source.index("stale_receipt = _poll_receipt(")
    proof = source.index("proof = _revocation_proof(")

    assert release < receipt < proof


def test_revocation_invokes_fresh_advisor_before_recovery() -> None:
    runner = _hosted_module(Path(__file__).parent)
    source = inspect.getsource(runner._run_revocation_case)

    receipt = source.index("stale_receipt = _poll_receipt(")
    proof = source.index("proof = _revocation_proof(")
    unchanged = source.index('"after-stale-denial"')
    readiness = source.index("_wait_for_stale_denial_completion(")
    advisor_command = source.index("advisor_command = _advisor_command(")
    advisor_invocation = source.index("advisor_result = _invoke_advisor(")
    causal_clause = source.index("advisor_causal_path_clause =")
    causal_validation = source.index("expected_causal_path_clause=advisor_causal_path_clause")
    recovery = source.index("recovery_dispatch, recovery_receipt = _recover_revoked(")

    assert (
        receipt
        < proof
        < unchanged
        < readiness
        < advisor_command
        < advisor_invocation
        < causal_clause
        < causal_validation
        < recovery
    )
    assert "revocation.result.new_epoch" in source


def _advisor_result_with_causal_statement(statement: str) -> tuple[Any, Any]:
    from controlgraph_canary.contracts.codec import canonical_sha256
    from controlgraph_canary.contracts.model_assistance import (
        ADVISOR_OPERATOR_COMMAND_V1,
        AdvisorOperatorCommandV1,
        DiagnosticEvidenceKind,
        DiagnosticToolId,
    )
    from controlgraph_canary.contracts.models import TargetBinding

    root_sha256 = "1" * 64
    command = AdvisorOperatorCommandV1(
        schema_version=ADVISOR_OPERATOR_COMMAND_V1,
        request_id="advisor-request",
        idempotency_key="advisor-idempotency",
        target=TargetBinding(
            schema_version="controlgraph.target-binding/v1",
            project_id="controlgraph-canary-abc123",
            region="us-central1",
            environment="nonprod",
            service_name="controlgraph-reference-target",
        ),
        root_id=f"cgroot:{root_sha256}",
        expected_root_sha256=root_sha256,
        expected_epoch=2,
        requested_at="2026-08-28T00:00:00Z",
    )
    citations = tuple(
        SimpleNamespace(evidence_kind=kind)
        for kind in (
            DiagnosticEvidenceKind.RECEIPT,
            DiagnosticEvidenceKind.TIMELINE,
            DiagnosticEvidenceKind.TARGET,
        )
    )
    recommendation = SimpleNamespace(
        findings=(SimpleNamespace(statement=statement, citations=citations),),
        authority_effect="none",
        deterministic_health_override=False,
        operator_review_required=True,
    )
    audit = SimpleNamespace(
        validation=SimpleNamespace(
            accepted=True,
            codes=(SimpleNamespace(value="accepted"),),
        ),
        prompt_version="controlgraph.rollout-advisor-prompt/v2",
        tool_calls=tuple(
            SimpleNamespace(
                sequence=sequence,
                tool_id=tool_id,
                status=SimpleNamespace(value="succeeded"),
                output_sha256="2" * 64,
            )
            for sequence, tool_id in enumerate(DiagnosticToolId, start=1)
        ),
    )
    result = SimpleNamespace(
        replayed=False,
        command_sha256=canonical_sha256(command),
        root_id=command.root_id,
        root_sha256=command.expected_root_sha256,
        epoch=command.expected_epoch,
        response=SimpleNamespace(audit=audit, recommendation=recommendation),
    )
    return command, result


def test_core_advisor_validation_requires_exact_causal_path_clause(tmp_path: Path) -> None:
    from controlgraph_canary.application.model_assistance import (
        stale_denial_causal_path_clause,
    )

    runner = _hosted_module(tmp_path)
    expected = stale_denial_causal_path_clause(
        work_epoch=1,
        current_authority_epoch=2,
        target_configuration_sha256="3" * 64,
    )
    command, accepted = _advisor_result_with_causal_statement(expected)
    runner._validate_advisor_result(
        command,
        accepted,
        replayed=False,
        expected_causal_path_clause=expected,
    )
    _, rejected = _advisor_result_with_causal_statement(
        expected.replace("target=90/10", "target=100/0")
    )

    with pytest.raises(runner.AcceptanceError) as raised:
        runner._validate_advisor_result(
            command,
            rejected,
            replayed=False,
            expected_causal_path_clause=expected,
        )

    assert raised.value.code == "ACCEPTANCE_HOSTED_ADVISOR_INVALID"


def _stale_completion_readiness_fixture(*, verification_id: str) -> tuple[Any, ...]:
    root_sha256 = "1" * 64
    receipt_sha256 = "2" * 64
    target_sha256 = "3" * 64
    root = SimpleNamespace(root_id=f"cgroot:{root_sha256}", root_sha256=root_sha256)
    revocation = SimpleNamespace(
        result=SimpleNamespace(
            new_epoch=2,
            committed_at="2026-08-28T00:00:00Z",
            operator_identity="operator@example.com",
            evidence_id="cgevidence:revocation",
            request_id="revocation-request",
        )
    )
    receipt = SimpleNamespace(
        receipt=SimpleNamespace(
            epoch=1,
            updated_at="2026-08-28T00:00:01Z",
            receipt_id="cgreceipt:stale",
            request_id="promotion-request",
        ),
        receipt_sha256=receipt_sha256,
    )

    def correlation(kind: str, value: str) -> Any:
        return SimpleNamespace(kind=kind, correlation_id=value)

    def field(name: str, value: str) -> Any:
        return SimpleNamespace(name=name, value=value)

    def entry(
        sequence: int,
        event_type: str,
        occurred_at: str,
        *,
        epoch: int,
        correlations: tuple[Any, ...],
        fields: tuple[Any, ...],
        signature_purpose: str | None,
        verification_status: str,
        terminal_classification: str = "NONE",
        actor_id: str = "actor:test",
        payload_sha256: str = "4" * 64,
    ) -> Any:
        return SimpleNamespace(
            root_id=root.root_id,
            root_sha256=root.root_sha256,
            sequence=sequence,
            event_type=event_type,
            epoch=epoch,
            occurred_at=occurred_at,
            actor_id=actor_id,
            signature=(
                None if signature_purpose is None else SimpleNamespace(purpose=signature_purpose)
            ),
            verification_status=verification_status,
            terminal_classification=terminal_classification,
            payload_sha256=payload_sha256,
            correlations=correlations,
            display_fields=fields,
        )

    actor_id = (
        "actor:" + hashlib.sha256(revocation.result.operator_identity.encode("utf-8")).hexdigest()
    )
    common_verification_correlations = (
        correlation("REQUEST", receipt.receipt.request_id),
        correlation("VERIFICATION", verification_id),
    )
    entries = (
        entry(
            1,
            "AUTHORITY_EPOCH_ADVANCED",
            revocation.result.committed_at,
            epoch=2,
            correlations=(
                correlation("EVIDENCE", revocation.result.evidence_id),
                correlation("REQUEST", revocation.result.request_id),
            ),
            fields=(field("SUMMARY", "Epoch Advanced"),),
            signature_purpose="EVIDENCE",
            verification_status="VERIFIED",
            actor_id=actor_id,
        ),
        entry(
            2,
            "MUTATION_DENIED",
            receipt.receipt.updated_at,
            epoch=1,
            correlations=(
                correlation("RECEIPT", receipt.receipt.receipt_id),
                correlation("REQUEST", receipt.receipt.request_id),
            ),
            fields=(field("OUTCOME", "DENIED"), field("REASON_CODE", "EPOCH_MISMATCH")),
            signature_purpose=None,
            verification_status="NOT_APPLICABLE",
            payload_sha256=receipt.receipt_sha256,
        ),
        entry(
            3,
            "VERIFICATION_RECORDED",
            "2026-08-28T00:00:02Z",
            epoch=1,
            correlations=common_verification_correlations,
            fields=(
                field("ACTION", "APPLY_CANARY_V1"),
                field("OBSERVATION", "CONFIGURATION"),
                field("OUTCOME", "MATCH"),
                field(
                    "STATE",
                    "stable_percent=90;candidate_percent=10;"
                    f"target_configuration_sha256={target_sha256}",
                ),
            ),
            signature_purpose="INDEPENDENT_VERIFICATION",
            verification_status="VERIFIED",
        ),
        entry(
            4,
            "VERIFICATION_RECORDED",
            "2026-08-28T00:00:03Z",
            epoch=1,
            correlations=common_verification_correlations,
            fields=(
                field("ACTION", "APPLY_CANARY_V1"),
                field("OBSERVATION", "PROBE"),
                field("OUTCOME", "MATCH"),
            ),
            signature_purpose="INDEPENDENT_VERIFICATION",
            verification_status="VERIFIED",
        ),
        entry(
            5,
            "TERMINAL_CLASSIFIED",
            "2026-08-28T00:00:04Z",
            epoch=1,
            correlations=common_verification_correlations,
            fields=(
                field("ACTION", "STALE_CAPABILITY_DENIAL"),
                field("OUTCOME", "COMPLETE"),
                field("REASON_CODE", "STALE_CAPABILITY_DENIAL_COMPLETE"),
            ),
            signature_purpose=None,
            verification_status="VERIFIED",
            terminal_classification="DENIED",
        ),
    )
    return (
        root,
        revocation,
        receipt,
        target_sha256,
        (SimpleNamespace(entries=entries),),
    )


def test_stale_completion_readiness_waits_for_exact_correlated_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = _hosted_module(tmp_path)
    receipt_sha256 = "2" * 64
    expected_verification = f"stale-denial:{receipt_sha256[:32]}"
    root, revocation, receipt, target_sha256, ready = _stale_completion_readiness_fixture(
        verification_id=expected_verification
    )
    _, _, _, _, substituted = _stale_completion_readiness_fixture(
        verification_id=f"stale-denial:{'9' * 32}"
    )
    observations = iter((substituted, ready))
    reads: list[object] = []
    sleeps: list[float] = []

    def read_timeline(run: object) -> tuple[Any, ...]:
        reads.append(run)
        return next(observations)

    monkeypatch.setattr(runner, "_read_operator_timeline", read_timeline)
    monkeypatch.setattr(runner.time, "sleep", sleeps.append)
    monkeypatch.setattr(runner, "_STALE_COMPLETION_READINESS_ATTEMPTS", 3)
    run = object()

    observed = runner._wait_for_stale_denial_completion(
        run,
        root=root,
        revocation=revocation,
        stale_receipt=receipt,
        target_configuration_sha256=target_sha256,
    )

    assert observed is ready
    assert reads == [run, run]
    assert sleeps == [runner._STALE_COMPLETION_READINESS_DELAY_SECONDS]


def test_stale_completion_readiness_fails_boundedly_when_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = _hosted_module(tmp_path)
    root, revocation, receipt, target_sha256, substituted = _stale_completion_readiness_fixture(
        verification_id=f"stale-denial:{'9' * 32}"
    )
    reads: list[object] = []
    sleeps: list[float] = []

    def read_timeline(run: object) -> tuple[Any, ...]:
        reads.append(run)
        return substituted

    monkeypatch.setattr(runner, "_read_operator_timeline", read_timeline)
    monkeypatch.setattr(runner.time, "sleep", sleeps.append)
    monkeypatch.setattr(runner, "_STALE_COMPLETION_READINESS_ATTEMPTS", 3)
    run = object()

    with pytest.raises(runner.AcceptanceError) as raised:
        runner._wait_for_stale_denial_completion(
            run,
            root=root,
            revocation=revocation,
            stale_receipt=receipt,
            target_configuration_sha256=target_sha256,
        )

    assert raised.value.code == "ACCEPTANCE_HOSTED_STALE_COMPLETION_TIMEOUT"
    assert reads == [run, run, run]
    assert sleeps == [
        runner._STALE_COMPLETION_READINESS_DELAY_SECONDS,
        runner._STALE_COMPLETION_READINESS_DELAY_SECONDS,
    ]


def _hosted_module(tmp_path: Path) -> Any:
    module_spec = importlib.util.spec_from_file_location(
        f"core_acceptance_hosted_{_next_module_index()}", SCRIPT
    )
    assert module_spec is not None and module_spec.loader is not None
    runner = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = runner
    module_spec.loader.exec_module(runner)
    return runner


_MODULE_INDEX = {"value": 0}


def _next_module_index() -> int:
    _MODULE_INDEX["value"] += 1
    return _MODULE_INDEX["value"]


def _provider_job_document(
    image: str,
    service_account: str,
    labels: dict[str, Any],
) -> dict[str, Any]:
    return {
        "apiVersion": "run.googleapis.com/v1",
        "kind": "Job",
        "metadata": {
            "generation": 1,
            "labels": dict(labels),
            "name": "cg-m8-core-p-abc",
            "uid": "uid-1",
        },
        "spec": {
            "template": {
                "metadata": {"labels": dict(labels), "name": "cg-m8-core-p-abc"},
                "spec": {
                    "parallelism": 1,
                    "taskCount": 1,
                    "template": {
                        "spec": {
                            "containers": [{"image": image}],
                            "maxRetries": 0,
                            "serviceAccountName": service_account,
                            "timeoutSeconds": "600s",
                        }
                    },
                },
            }
        },
        "status": {"conditions": []},
    }


def test_hosted_load_job_verification_accepts_provider_json_envelope(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    _repo, _artifacts, spec_path, _spec_value = _fixture(tmp_path)
    _payload, spec = runner._load_contract(
        spec_path,
        runner.CoreAcceptanceRunSpecV1,
        error_code="ACCEPTANCE_SPEC_INVALID",
    )
    controller_image = next(
        item.reference for item in spec.images if item.component is runner.ImageComponent.CONTROLLER
    )
    verifier = "controlgraph-verifier@controlgraph-canary-abc123.iam.gserviceaccount.com"
    run = SimpleNamespace(
        repo=SOURCE_ROOT,
        artifact_root=tmp_path,
        spec=spec,
        run_inputs_sha256="a" * 64,
        project_number="123456789",
        network_resource="projects/controlgraph-canary-abc123/global/networks/test",
        subnetwork_resource=(
            "projects/controlgraph-canary-abc123/regions/us-central1/subnetworks/test"
        ),
        verifier_service_account=verifier,
    )
    case = spec.cases[0]
    described = _provider_job_document(
        controller_image,
        verifier,
        {runner._LOAD_JOB_LABEL_KEY: runner._LOAD_JOB_LABEL},
    )
    monkeypatch.setattr(runner, "_capture_process", lambda *_args, **_kwargs: (0, b""))
    monkeypatch.setattr(runner, "_load_job_names", lambda *_args, **_kwargs: frozenset())
    monkeypatch.setattr(
        runner,
        "_gcloud_json",
        lambda *_args, **_kwargs: described,
    )

    job_name = runner._create_load_job(
        run,
        case,
        mode="probe-stable",
        destination="https://controlgraph-reference-target.example/v1/probe",
        audience="https://controlgraph-reference-target.example",
        expected_revision=spec.target.stable_revision,
    )

    assert job_name.startswith(runner._LOAD_JOB_PREFIX)


def test_hosted_load_job_verification_rejects_provider_drift(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    _repo, _artifacts, spec_path, _spec_value = _fixture(tmp_path)
    _payload, spec = runner._load_contract(
        spec_path,
        runner.CoreAcceptanceRunSpecV1,
        error_code="ACCEPTANCE_SPEC_INVALID",
    )
    controller_image = next(
        item.reference for item in spec.images if item.component is runner.ImageComponent.CONTROLLER
    )
    verifier = "controlgraph-verifier@controlgraph-canary-abc123.iam.gserviceaccount.com"
    run = SimpleNamespace(
        repo=SOURCE_ROOT,
        artifact_root=tmp_path,
        spec=spec,
        run_inputs_sha256="a" * 64,
        project_number="123456789",
        network_resource="projects/controlgraph-canary-abc123/global/networks/test",
        subnetwork_resource=(
            "projects/controlgraph-canary-abc123/regions/us-central1/subnetworks/test"
        ),
        verifier_service_account=verifier,
    )
    case = spec.cases[0]
    monkeypatch.setattr(runner, "_capture_process", lambda *_args, **_kwargs: (0, b""))
    monkeypatch.setattr(runner, "_load_job_names", lambda *_args, **_kwargs: frozenset())

    def without_template_labels(document: dict[str, Any]) -> dict[str, Any]:
        drifted = json.loads(json.dumps(document))
        drifted["spec"]["template"]["metadata"]["labels"] = {}
        return drifted

    def without_resource_labels(document: dict[str, Any]) -> dict[str, Any]:
        drifted = json.loads(json.dumps(document))
        drifted["metadata"]["labels"] = {}
        return drifted

    drifted_documents = (
        _provider_job_document(
            controller_image[:-1] + ("0" if controller_image[-1] != "0" else "1"),
            verifier,
            {runner._LOAD_JOB_LABEL_KEY: runner._LOAD_JOB_LABEL},
        ),
        _provider_job_document(
            controller_image,
            "other@controlgraph-canary-abc123.iam.gserviceaccount.com",
            {runner._LOAD_JOB_LABEL_KEY: runner._LOAD_JOB_LABEL},
        ),
        _provider_job_document(controller_image, verifier, {}),
        without_template_labels(
            _provider_job_document(
                controller_image,
                verifier,
                {runner._LOAD_JOB_LABEL_KEY: runner._LOAD_JOB_LABEL},
            )
        ),
        without_resource_labels(
            _provider_job_document(
                controller_image,
                verifier,
                {runner._LOAD_JOB_LABEL_KEY: runner._LOAD_JOB_LABEL},
            )
        ),
    )
    for described in drifted_documents:

        def make_gcloud_json(document: dict[str, Any]) -> Any:
            return lambda _arguments, **_kwargs: document

        monkeypatch.setattr(runner, "_gcloud_json", make_gcloud_json(described))
        try:
            runner._create_load_job(
                run,
                case,
                mode="probe-stable",
                destination="https://controlgraph-reference-target.example/v1/probe",
                audience="https://controlgraph-reference-target.example",
                expected_revision=spec.target.stable_revision,
            )
        except runner.AcceptanceError as error:
            assert error.code == "ACCEPTANCE_HOSTED_LOAD_INVALID"
        else:
            raise AssertionError("drifted load job document unexpectedly accepted")


def test_hosted_probe_records_stay_within_restricted_canonical_json() -> None:
    runner = _hosted_module(Path(__file__).parent)
    record = {
        "accepted": True,
        "mode": "probe-stable",
        "request_count": 1,
        "response_codes": [{"code": 200, "count": 1}],
        "schema_version": runner._LOAD_RESULT_SCHEMA,
        "started_at": "2026-08-24T00:00:00Z",
        "status": "COMPLETE",
        "token_persisted": False,
        "windows": [
            {
                "accepted": 120,
                "response_codes": [{"code": 200, "count": 118}, {"code": 404, "count": 2}],
                "submitted": 120,
                "window_index": 1,
            }
        ],
    }

    encoded = runner._canonical_object(runner._json_value(record))

    assert b'"status":"COMPLETE"' in encoded


def test_hosted_timeline_evidence_compacts_large_pages_with_complete_bindings() -> None:
    runner = _hosted_module(Path(__file__).parent)
    digests = tuple(character * 64 for character in ("a", "b", "c"))
    audience = SimpleNamespace(value="OPERATOR")
    pages = []
    after_sequence = 0
    after_entry_sha256 = None
    for index, digest in enumerate(digests, start=1):
        command = SimpleNamespace(
            audience=audience,
            after_sequence=after_sequence,
            after_entry_sha256=after_entry_sha256,
        )
        document = {
            "command": {
                "audience": audience.value,
                "after_entry_sha256": after_entry_sha256,
                "after_sequence": after_sequence,
            },
            "entries": [
                {
                    "entry_sha256": digest,
                    "payload": "x" * 24_000,
                    "previous_entry_sha256": after_entry_sha256,
                    "sequence": index,
                }
            ],
            "has_more": index < len(digests),
            "head_entry_sha256": digests[-1],
            "head_sequence": len(digests),
            "next_after_entry_sha256": digest,
            "next_after_sequence": index,
            "schema_version": "controlgraph.timeline-page/v1",
        }

        def model_dump(*, mode: str, value: dict[str, Any] = document) -> dict[str, Any]:
            assert mode == "json"
            return value

        pages.append(
            SimpleNamespace(
                command=command,
                entries=(
                    SimpleNamespace(
                        entry_sha256=digest,
                        previous_entry_sha256=after_entry_sha256,
                        sequence=index,
                    ),
                ),
                has_more=index < len(digests),
                head_entry_sha256=digests[-1],
                head_sequence=len(digests),
                model_dump=model_dump,
                next_after_entry_sha256=digest,
                next_after_sequence=index,
            )
        )
        after_sequence = index
        after_entry_sha256 = digest

    with pytest.raises(runner.ContractError):
        runner.canonical_json_value_bytes([page.model_dump(mode="json") for page in pages])

    release_document = {
        "root_id": "cgroot:" + "d" * 64,
        "schema_version": "controlgraph.service-claim-release-result/v1",
    }

    def release_dump(*, mode: str) -> dict[str, Any]:
        assert mode == "json"
        return release_document

    evidence = runner._timeline_evidence(
        tuple(pages),
        release=SimpleNamespace(model_dump=release_dump),
    )
    summary = evidence["summary"]
    page_sha256s = [
        hashlib.sha256(runner.canonical_json_value_bytes(page.model_dump(mode="json"))).hexdigest()
        for page in pages
    ]

    assert summary["audience"] == "OPERATOR"
    assert summary["page_count"] == 3
    assert summary["entry_count"] == 3
    assert summary["head_sequence"] == 3
    assert summary["head_entry_sha256"] == digests[-1]
    assert [item["page_sha256"] for item in summary["page_bindings"]] == page_sha256s
    assert (
        summary["page_set_sha256"]
        == hashlib.sha256(
            runner._TIMELINE_PAGE_SET_DOMAIN + runner.canonical_json_value_bytes(page_sha256s)
        ).hexdigest()
    )
    assert (
        summary["page_set_sha256"]
        != hashlib.sha256(
            runner._TIMELINE_PAGE_SET_DOMAIN
            + runner.canonical_json_value_bytes(list(reversed(page_sha256s)))
        ).hexdigest()
    )
    assert evidence["release"] == release_document
    assert (
        runner._timeline_evidence(
            tuple(pages),
            release=SimpleNamespace(model_dump=release_dump),
        )
        == evidence
    )
    encoded = runner._canonical_object(evidence)
    assert len(encoded) < runner.MAX_CONTRACT_BYTES
    assert b'"payload"' not in encoded


def test_hosted_timeline_evidence_rejects_cursor_gaps() -> None:
    runner = _hosted_module(Path(__file__).parent)
    digest = "a" * 64
    page = SimpleNamespace(
        command=SimpleNamespace(
            audience=SimpleNamespace(value="OPERATOR"),
            after_sequence=1,
            after_entry_sha256=digest,
        ),
        entries=(),
        has_more=False,
        head_entry_sha256=digest,
        head_sequence=1,
        next_after_entry_sha256=digest,
        next_after_sequence=1,
    )

    for pages in ((), (page,)):
        with pytest.raises(runner.AcceptanceError) as raised:
            runner._timeline_evidence(pages)

        assert raised.value.code == "ACCEPTANCE_HOSTED_TIMELINE_INVALID"


def test_hosted_policy_binding_compares_plain_artifact_digest() -> None:
    """The spec artifact digest is plain SHA-256 of canonical policy bytes.

    The hosted root check must compare it with the same plain digest of the
    returned root policy, never with the domain-separated ``canonical_sha256``.
    """

    from controlgraph_canary.contracts.codec import (
        canonical_json_bytes,
        canonical_sha256,
    )
    from controlgraph_canary.contracts.health import create_rollout_health_policy_v2

    policy = create_rollout_health_policy_v2()
    artifact_sha256 = hashlib.sha256(canonical_json_bytes(policy)).hexdigest()

    assert artifact_sha256 != canonical_sha256(policy)
    vector = json.loads(
        (SOURCE_ROOT / "contract-fixtures" / "health-v1" / "golden.json").read_text()
    )
    canonical = next(
        item["canonical"] for item in vector["vectors"] if item["model"] == "RolloutHealthPolicyV2"
    )
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == artifact_sha256


def test_hosted_receipt_poll_tolerates_transient_read_codes(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(tmp_path)
    case = SimpleNamespace(case_id="core-case-1")
    root = SimpleNamespace(root_id="cgroot:" + "b" * 64, root_sha256="b" * 64)

    class _Outcome:
        value = "VERIFIED"

    class _Receipt:
        outcome = _Outcome()

    class _Model:
        receipt = _Receipt()

    reads: list[tuple[int, bytes]] = [
        (4, b'{"code":"RECEIPT_READ_OUTCOME_UNKNOWN"}'),
        (4, b'{"code":"RECEIPT_READ_AUTH_UNAVAILABLE"}'),
        (0, b"{}"),
    ]

    def fake_run_cli(*_args: Any, **_kwargs: Any) -> tuple[int, Any, Any]:
        status, raw = reads.pop(0)
        return status, json.loads(raw), _Model() if status == 0 else None

    monkeypatch.setattr(runner, "_run_cli", fake_run_cli)
    monkeypatch.setattr(runner.time, "sleep", lambda *_a: None)

    model = runner._poll_receipt(
        run=SimpleNamespace(repo=SOURCE_ROOT, project_number="123456789"),
        case=case,
        root=root,
        epoch=1,
        request_id="req",
        idempotency_key="idem",
        action="APPLY_CANARY_V1",
        capability_sha256="c" * 64,
        label="apply",
    )

    assert isinstance(model, _Model)

    def fatal_run_cli(*_args: Any, **_kwargs: Any) -> tuple[int, Any, Any]:
        return (
            5,
            json.loads(b'{"code":"RECEIPT_READ_COMMAND_INVALID"}'),
            None,
        )

    monkeypatch.setattr(runner, "_run_cli", fatal_run_cli)
    try:
        runner._poll_receipt(
            run=SimpleNamespace(repo=SOURCE_ROOT, project_number="123456789"),
            case=case,
            root=root,
            epoch=1,
            request_id="req",
            idempotency_key="idem",
            action="APPLY_CANARY_V1",
            capability_sha256="c" * 64,
            label="apply",
        )
    except runner.AcceptanceError as error:
        assert error.code == "ACCEPTANCE_HOSTED_RECEIPT_INVALID"
    else:
        raise AssertionError("fatal receipt-read code was unexpectedly tolerated")


def test_hosted_candidate_prewarm_returns_on_first_answer(
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(Path(__file__).parent)
    calls = {"count": 0}

    class _Response:
        def __enter__(self) -> object:
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

    def answering(*_args: Any, **_kwargs: Any):
        calls["count"] += 1
        return _Response()

    monkeypatch.setattr(runner.urllib.request, "urlopen", answering)
    runner._prewarm_candidate(
        candidate_url="https://candidate.example",
        deadline=datetime.now(UTC),
    )
    assert calls["count"] == 1


def test_hosted_candidate_prewarm_fails_closed_when_never_ready(
    monkeypatch: Any,
) -> None:
    runner = _hosted_module(Path(__file__).parent)

    def timing_out(*_args: Any, **_kwargs: Any):
        raise TimeoutError("cold start")

    monkeypatch.setattr(runner.urllib.request, "urlopen", timing_out)
    try:
        runner._prewarm_candidate(
            candidate_url="https://candidate.example",
            deadline=datetime.now(UTC),
        )
    except runner.AcceptanceError as error:
        assert error.code == "ACCEPTANCE_HOSTED_CANDIDATE_UNREADY"
    else:
        raise AssertionError("unready candidate was unexpectedly accepted")


def test_hosted_health_load_projects_fast_and_slow_receipt_windows() -> None:
    runner = _hosted_module(Path(__file__).parent)
    load_start = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    raw_load = {
        "anchor": runner._utc(load_start),
        "mode": "healthy",
        "request_count": 360,
        "schema_version": runner._LOAD_RESULT_SCHEMA,
        "status": "COMPLETE",
        "token_persisted": False,
        "windows": [
            {
                "accepted": 120,
                "started_at": runner._utc(load_start + timedelta(minutes=index)),
                "submitted": 120,
                "window_index": index + 1,
            }
            for index in range(3)
        ],
    }

    cases = (
        ("2026-08-26T11:59:45Z", load_start, (1, 2)),
        ("2026-08-26T12:00:15Z", load_start + timedelta(minutes=1), (2, 3)),
    )
    for receipt_updated_at, expected_anchor, expected_indices in cases:
        health_anchor = runner._derive_health_anchor(
            load_start=load_start,
            receipt_updated_at=receipt_updated_at,
        )
        projected = runner._project_health_load(
            raw_load,
            load_start=load_start,
            health_anchor=health_anchor,
        )

        assert health_anchor == expected_anchor
        assert projected["anchor"] == runner._utc(expected_anchor)
        assert projected["request_count"] == 240
        assert len(projected["windows"]) == 2
        assert tuple(window["window_index"] for window in projected["windows"]) == (
            expected_indices
        )


def test_hosted_health_load_rejects_receipt_outside_overlap() -> None:
    runner = _hosted_module(Path(__file__).parent)

    try:
        runner._derive_health_anchor(
            load_start=datetime(2026, 8, 26, 12, 0, tzinfo=UTC),
            receipt_updated_at="2026-08-26T12:01:15Z",
        )
    except runner.AcceptanceError as error:
        assert error.code == "ACCEPTANCE_HOSTED_LOAD_ALIGNMENT_INVALID"
    else:
        raise AssertionError("an out-of-range apply receipt was unexpectedly aligned")


@pytest.mark.parametrize(
    ("disposition", "accepted"),
    (("CREATED", True), ("ADOPTED", True), ("DUPLICATE", False)),
)
def test_hosted_health_append_disposition_validation(
    disposition: str,
    accepted: bool,
) -> None:
    runner = _hosted_module(Path(__file__).parent)

    assert runner._accepted_health_append_disposition(disposition) is accepted


def test_hosted_health_load_retries_at_the_declared_boundary() -> None:
    from controlgraph_canary.application.receipt_execution import (
        RECEIPT_NEW_CLAIM_RECOVERY_WINDOW_SECONDS,
    )
    from controlgraph_canary.contracts.health import create_rollout_health_policy_v2

    runner = _hosted_module(Path(__file__).parent)
    source = inspect.getsource(runner._health_load)
    policy = create_rollout_health_policy_v2()
    promotion_schedule_lead_seconds = 5
    proof_margin_seconds = (
        policy.maximum_observation_delay_seconds
        - policy.observation_delay_seconds
        - promotion_schedule_lead_seconds
    )

    assert "while datetime.now(UTC) < next_evaluation:" in source
    assert "next_evaluation + timedelta" not in source
    assert source.index("before_terminal()") < source.index(
        "while datetime.now(UTC) < next_evaluation:"
    )
    assert proof_margin_seconds == 115
    assert proof_margin_seconds > RECEIPT_NEW_CLAIM_RECOVERY_WINDOW_SECONDS


def test_hosted_health_load_preserves_cold_start_token_margin() -> None:
    runner = _hosted_module(Path(__file__).parent)
    source = inspect.getsource(runner._health_load)
    submitted_at = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    token_acquired_at = submitted_at + timedelta(seconds=159)
    earliest = submitted_at + timedelta(seconds=300)
    planned_anchor = earliest.replace(second=0, microsecond=0)
    load_start = planned_anchor - timedelta(minutes=1)

    assert "datetime.now(UTC) + timedelta(seconds=300)" in source
    assert token_acquired_at <= load_start - timedelta(seconds=60)


def test_hosted_promotion_uses_five_second_schedule_lead(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    from controlgraph_canary.contracts.promotion_execution import (
        PROMOTION_HEALTH_CHAIN_LOCATOR_V1,
        VERIFIED_APPLY_RECEIPT_LOCATOR_V1,
        PromotionHealthChainLocatorV1,
        VerifiedApplyReceiptLocatorV1,
    )

    runner = _hosted_module(tmp_path)
    fixed_now = datetime(2026, 8, 25, 13, 6, 19, tzinfo=UTC)

    class _FixedDateTime(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:
            assert tz is UTC
            return fixed_now

    root_sha256 = "a" * 64
    root = SimpleNamespace(
        root_id=f"cgroot:{root_sha256}",
        root_sha256=root_sha256,
    )
    receipt = VerifiedApplyReceiptLocatorV1(
        schema_version=VERIFIED_APPLY_RECEIPT_LOCATOR_V1,
        receipt_id="receipt-apply-001",
        request_id="request-apply-001",
        idempotency_key="idempotency-apply-001",
        capability_sha256="b" * 64,
        mutation_sha256="c" * 64,
        expected_poststate_sha256="d" * 64,
        provider_operation="operations/apply-001",
        receipt_sha256="e" * 64,
    )
    health_chain = PromotionHealthChainLocatorV1(
        schema_version=PROMOTION_HEALTH_CHAIN_LOCATOR_V1,
        anchor_id="cghealthanchor:healthy-001",
        anchor_sha256="f" * 64,
        chain_id=f"cghealthchain:{'1' * 64}",
        health_chain_sha256="1" * 64,
        chain_head_sha256="2" * 64,
        ordered_proof_chain_sha256="3" * 64,
        terminal_sequence=2,
    )
    terminal = SimpleNamespace(
        terminal_status=SimpleNamespace(value="healthy"),
        promotion_health_chain=health_chain,
    )
    run = SimpleNamespace(
        repo=SOURCE_ROOT,
        project_number="123456789",
        run_inputs_sha256="4" * 64,
        command_path=lambda _case, _label: tmp_path / "promotion.json",
    )
    case = SimpleNamespace(case_id="core-case-02")
    commands: list[Any] = []

    monkeypatch.setattr(runner, "datetime", _FixedDateTime)
    monkeypatch.setattr(
        runner,
        "_write_command",
        lambda _path, command: commands.append(command),
    )

    def run_cli(*_args: Any, **_kwargs: Any) -> tuple[int, dict[str, Any], Any]:
        dispatch = SimpleNamespace(
            root_id=root.root_id,
            epoch=1,
            health_chain_locator=health_chain,
            enqueue_disposition="CREATED",
        )
        return 0, {}, dispatch

    monkeypatch.setattr(runner, "_run_cli", run_cli)

    runner._promote(
        run,
        case,
        root_result=SimpleNamespace(root=root),
        apply_receipt=SimpleNamespace(verified_apply_receipt=receipt),
        terminal=terminal,
    )

    assert len(commands) == 1
    assert commands[0].scheduled_at == "2026-08-25T13:06:24Z"


def test_hosted_load_script_retries_transport_failures() -> None:
    runner = _hosted_module(Path(__file__).parent)
    source = runner._REMOTE_LOAD_SCRIPT
    namespace: dict[str, Any] = {"__name__": "load-script"}
    with contextlib.suppress(SystemExit):
        exec(compile(source, "<load-script>", "exec"), namespace)

    class _FlakyOpener:
        def __init__(self) -> None:
            self.calls = 0

        def open(self, *_args: Any, **_kwargs: Any):
            self.calls += 1
            if self.calls < 3:
                raise urllib.error.URLError(TimeoutError("cold start"))

            class _Response:
                status = 200

                def read(self, *_a: Any) -> bytes:
                    return json.dumps(
                        {
                            "marker": "controlgraph-candidate-v1",
                            "revision": "controlgraph-reference-target-candidate-v18",
                            "schema_version": "controlgraph.reference-probe/v1",
                        }
                    ).encode()

                def __enter__(self):
                    return self

                def __exit__(self, *_a: Any) -> None:
                    return None

            return _Response()

    namespace["time.sleep"] = lambda *_a: None
    flaky = _FlakyOpener()
    namespace["OPENER"] = flaky

    code, accepted = namespace["one"](
        "https://candidate.example/v1/probe",
        "token",
        "healthy",
        "controlgraph-reference-target-candidate-v18",
    )

    assert flaky.calls == 3
    assert code == 200 and accepted is True
