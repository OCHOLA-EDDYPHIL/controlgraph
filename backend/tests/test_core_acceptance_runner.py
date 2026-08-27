from __future__ import annotations

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
        ("CLOUD_RUN_CONFIGURATION", "COORDINATOR", "MODEL_AUDIT", "TIMELINE"),
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
        "candidate_revision": "controlgraph-reference-target-candidate-v10",
        "environment": "nonprod",
        "project_id": "controlgraph-canary-abc123",
        "region": "us-central1",
        "schema_version": "controlgraph.acceptance-target/v1",
        "service_name": "controlgraph-reference-target",
        "stable_revision": "controlgraph-reference-target-stable-v10",
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
        subnetwork_resource=(
            f"projects/{project_id}/regions/us-central1/subnetworks/test"
        ),
        verifier_service_account=(
            f"controlgraph-verifier@{project_id}.iam.gserviceaccount.com"
        ),
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
    monkeypatch.setattr(
        runner,
        "_health_load",
        lambda *_args, **_kwargs: (object(), object(), object(), object()),
    )
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
        item.reference
        for item in spec.images
        if item.component is runner.ImageComponent.CONTROLLER
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
        item.reference
        for item in spec.images
        if item.component is runner.ImageComponent.CONTROLLER
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
        item["canonical"]
        for item in vector["vectors"]
        if item["model"] == "RolloutHealthPolicyV2"
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
        deadline=datetime.now(UTC) + timedelta(seconds=30),
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
                            "revision": "controlgraph-reference-target-candidate-v10",
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
        "controlgraph-reference-target-candidate-v10",
    )

    assert flaky.calls == 3
    assert code == 200 and accepted is True
