from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).parents[2] / "scripts" / "core_acceptance.py"
SOURCE_ROOT = SCRIPT.parents[1]

CASES = (
    ("TARGET_RESET", ("CLOUD_RUN_CONFIGURATION", "DATA_PATH_PROBE")),
    (
        "HEALTHY_PROMOTION",
        (
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "SIGNED_CAPABILITY",
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
            "SIGNED_CAPABILITY",
            "EXECUTOR_EPOCH_CHECK",
            "EXECUTION_RECEIPT",
            "HEALTH_DECISION",
            "RECOVERY_IDENTITY",
            "TIMELINE",
        ),
    ),
    (
        "REVOCATION_STALE_DENIAL",
        (
            "AUTHORITY_TRANSITION",
            "CLOUD_RUN_CONFIGURATION",
            "DATA_PATH_PROBE",
            "SIGNED_CAPABILITY",
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
    ("TIMELINE_CONSOLE_READ", ("TIMELINE", "CONSOLE_READ")),
    ("BOUNDED_ADVISOR", ("COORDINATOR", "MODEL_AUDIT", "TIMELINE")),
)

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

RESET_AND_READ = (
    "cli:controlgraph-reference-target-reset",
    "cli:controlgraph-canary:read-target-traffic",
)

ENTRY_POINTS = {
    "TARGET_RESET": RESET_AND_READ,
    "HEALTHY_PROMOTION": (
        *RESET_AND_READ,
        "cli:controlgraph-canary:capture-stable-snapshot",
        "cli:controlgraph-canary:create-rollout-root",
        "cli:controlgraph-canary:apply-canary",
        "cli:controlgraph-canary:evaluate-health",
        "cli:controlgraph-canary:promote-candidate",
        "cli:controlgraph-canary:read-execution-receipt",
        "cli:controlgraph-canary:read-target-traffic",
        "cli:controlgraph-canary:release-service-claim",
    ),
    "UNHEALTHY_STABLE_RECOVERY": (
        *RESET_AND_READ,
        "cli:controlgraph-canary:capture-stable-snapshot",
        "cli:controlgraph-canary:create-rollout-root",
        "cli:controlgraph-canary:apply-canary",
        "cli:controlgraph-canary:evaluate-health",
        "service:recovery",
        "cli:controlgraph-canary:read-execution-receipt",
        "cli:controlgraph-canary:read-target-traffic",
        "cli:controlgraph-canary:release-service-claim",
    ),
    "REVOCATION_STALE_DENIAL": (
        *RESET_AND_READ,
        "cli:controlgraph-canary:capture-stable-snapshot",
        "cli:controlgraph-canary:create-rollout-root",
        "cli:controlgraph-canary:apply-canary",
        "cli:controlgraph-canary:evaluate-health",
        "cli:controlgraph-canary:execution-queue:hold",
        "cli:controlgraph-canary:promote-candidate",
        "cli:controlgraph-canary:revoke-epoch",
        "cli:controlgraph-canary:execution-queue:release",
        "cli:controlgraph-canary:read-execution-receipt",
        "cli:controlgraph-canary:read-target-traffic",
        "cli:controlgraph-canary:recover-captured-stable",
        "cli:controlgraph-canary:release-service-claim",
    ),
    "INDEPENDENT_VERIFIER_PROBE": (
        *RESET_AND_READ,
        "service:verifier:independent-verification",
        "endpoint:reference-target:probe",
    ),
    "AMBIGUITY_CLASSIFICATION": (
        *RESET_AND_READ,
        "cli:controlgraph-canary:classify-completion",
    ),
    "TIMELINE_CONSOLE_READ": (
        *RESET_AND_READ,
        "endpoint:api:timeline-read",
        "web:operator-console",
    ),
    "BOUNDED_ADVISOR": (
        *RESET_AND_READ,
        "endpoint:api:advisor-command",
        "service:coordinator:advisor",
        "service:advisor",
        "cli:controlgraph-canary:read-target-traffic",
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
        "candidate_revision": "controlgraph-reference-target-candidate-v4",
        "environment": "acceptance",
        "project_id": "controlgraph-canary-abc123",
        "region": "us-central1",
        "schema_version": "controlgraph.acceptance-target/v1",
        "service_name": "controlgraph-reference-target",
        "stable_revision": "controlgraph-reference-target-stable-v4",
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
                    "evidence_id": evidence_id,
                    "private_marker": "not-copied-to-manifest",
                    "synthetic": True,
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

    def observations(_run: Any, case: Any, *_args: Any) -> dict[Any, object]:
        return {
            kind: {"schema_version": f"test.{kind.value.lower()}/v1"}
            for kind in runner.REQUIRED_EVIDENCE[case.kind]
        }

    monkeypatch.setattr(runner, "_reset_target", reset)
    monkeypatch.setattr(
        runner,
        "_probe_stable",
        lambda *_args: {"schema_version": "test.probe/v1"},
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
        confirmation="RUN_CONTROLGRAPH_CORE_ACCEPTANCE",
    )

    assert reset_cases == [kind for kind, _evidence in CASES]
    assert status.value == "PASSED"
    assert output_spec.is_file()
    assert output_manifest.is_file()
