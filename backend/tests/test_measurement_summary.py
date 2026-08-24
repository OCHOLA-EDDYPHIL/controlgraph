from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "measurement_summary.py"
SOURCE_ROOT = SCRIPT.parents[1]

PHASES = (
    "ISSUANCE",
    "QUEUEING",
    "EXECUTOR_EPOCH_DENIAL",
    "TRAFFIC_MUTATION",
    "MONITORING",
    "RECOVERY",
    "VERIFICATION",
    "TIMELINE_DELIVERY",
    "MODEL_ASSISTANCE",
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _write(path: Path, value: object) -> str:
    payload = _canonical(value)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _artifact(artifact_id: str, digest: str) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "byte_count": 10,
        "media_type": "application/json",
        "sha256": digest,
    }


def _fixture(tmp_path: Path) -> tuple[Path, Path, dict[str, Any], dict[str, Any]]:
    evidence = []
    for index, phase in enumerate(PHASES, start=1):
        evidence_id = f"evidence-{index}"
        evidence.append(
            {
                "artifact": _artifact(evidence_id, f"{index:064x}"),
                "evidence_id": evidence_id,
                "kind": phase,
                "observed_at": "2026-08-24T00:00:01Z",
                "projection": "PRIVATE_DIGEST_ONLY",
            }
        )
    manifest: dict[str, Any] = {
        "cases": [
            {
                "case_id": "case-one",
                "evidence": evidence,
                "execution_mode": "HOSTED_GOOGLE_CLOUD",
                "status": "PASSED",
            }
        ],
        "cost": {
            "basis": "UPPER_BOUND",
            "currency": "USD",
            "maximum_microusd": 1_000_000,
            "reported_microusd": 120_000,
        },
        "duration_ms": 9_000,
        "evidence_binding_complete": True,
        "inputs": {
            "images": [
                {
                    "component": "controller",
                    "reference": "registry.example/controller@sha256:" + "a" * 64,
                },
                {
                    "component": "advisor",
                    "reference": "registry.example/advisor@sha256:" + "b" * 64,
                },
                {
                    "component": "console",
                    "reference": "registry.example/console@sha256:" + "c" * 64,
                },
                {
                    "component": "reference-stable",
                    "reference": "registry.example/reference-stable@sha256:" + "d" * 64,
                },
                {
                    "component": "reference-candidate",
                    "reference": "registry.example/reference-candidate@sha256:" + "e" * 64,
                },
            ],
            "policies": [
                {
                    "artifact": _artifact("health-policy", "c" * 64),
                    "policy_schema_version": "controlgraph.rollout-health-policy/v1",
                }
            ],
            "source_commit": "d" * 40,
            "target": {
                "environment": "acceptance",
                "candidate_revision": "controlgraph-reference-target-candidate-v4",
                "project_id": "controlgraph-canary-abc123",
                "region": "us-central1",
                "service_name": "controlgraph-reference-target",
                "stable_revision": "controlgraph-reference-target-stable-v4",
            },
            "terraform_plan": _artifact("terraform-plan", "e" * 64),
        },
        "maximum_duration_ms": 10_000,
        "run_id": "cgacceptance:" + "f" * 64,
        "runner_mode": "EXPLICIT_HOSTED_EVIDENCE_BINDING",
        "schema_version": "controlgraph.core-acceptance-manifest/v1",
        "status": "PASSED",
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_sha256 = _write(manifest_path, manifest)

    samples = []
    sequence = 1
    for phase_index, phase in enumerate(PHASES, start=1):
        for repetition in range(2):
            samples.append(
                {
                    "case_id": "case-one",
                    "duplicate_protected_effect": sequence in {2, 4},
                    "duration_ms": phase_index * 10 + repetition,
                    "evidence_id": f"evidence-{phase_index}",
                    "evidence_sha256": f"{phase_index:064x}",
                    "phase": phase,
                    "sample_id": f"sample-{sequence}",
                    "schema_version": "controlgraph.measurement-sample/v1",
                    "sequence": sequence,
                    "status": "FAILED" if sequence == 1 else "PASSED",
                    "verifier_agreement": (
                        "AGREED"
                        if phase == "VERIFICATION" and repetition == 0
                        else "DISAGREED"
                        if phase == "VERIFICATION"
                        else "NOT_APPLICABLE"
                    ),
                }
            )
            sequence += 1
    sample_set: dict[str, Any] = {
        "bounds": {
            "maximum_cloud_run_instances": 4,
            "maximum_model_calls_per_request": 4,
            "maximum_model_duration_ms": 20_000,
            "maximum_model_output_tokens": 2048,
            "maximum_parallel_runs": 1,
            "maximum_samples": 18,
            "maximum_task_concurrent_dispatches": 1,
            "maximum_task_dispatches_per_second": 1,
            "schema_version": "controlgraph.measurement-bounds/v1",
        },
        "samples": samples,
        "schema_version": "controlgraph.measurement-sample-set/v1",
        "source_manifest_sha256": manifest_sha256,
    }
    sample_path = tmp_path / "samples.json"
    _write(sample_path, sample_set)
    return manifest_path, sample_path, manifest, sample_set


def _run(
    manifest_path: Path,
    sample_path: Path,
    output: Path,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(SOURCE_ROOT / "backend" / "src")
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source-manifest",
            str(manifest_path),
            "--sample-set",
            str(sample_path),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )


def test_summary_reports_bounded_measurements_without_scaling_claims(tmp_path: Path) -> None:
    manifest_path, sample_path, _, _ = _fixture(tmp_path)
    output = tmp_path / "summary.json"

    result = _run(manifest_path, sample_path, output)

    assert result.returncode == 0, result.stderr
    summary = json.loads(output.read_bytes())
    assert summary["schema_version"] == "controlgraph.measurement-summary/v1"
    assert summary["sample_count"] == 18
    assert summary["measurement_result"] == "OBSERVED_WITH_FAILURES"
    assert summary["measurements"]["queue_age_ms"] == {
        "maximum_ms": 21,
        "minimum_ms": 20,
        "p50_ms": 20,
        "p95_ms": 21,
        "p99_ms": 21,
        "sample_count": 2,
    }
    assert summary["measurements"]["revocation_to_denial_ms"]["p95_ms"] == 31
    assert summary["measurements"]["recovery_time_ms"]["p95_ms"] == 61
    assert summary["measurements"]["error_rate"]["count"] == 1
    assert summary["measurements"]["duplicate_rate"]["count"] == 2
    agreement = summary["measurements"]["verifier_agreement_rate"]
    assert agreement["count"] == 1
    assert agreement["sample_count"] == 2
    assert agreement["lower_basis_points"] < agreement["rate_basis_points"]
    assert agreement["rate_basis_points"] < agreement["upper_basis_points"]
    assert summary["measurements"]["run_cost"] == {
        "basis": "UPPER_BOUND",
        "currency": "USD",
        "maximum_microusd_per_run": 1_000_000,
        "reported_microusd_per_run": 120_000,
        "run_count": 1,
        "within_bound": True,
    }
    assert summary["source_run"]["status"] == "PASSED"
    assert summary["source_run"]["within_duration_bound"] is True
    assert [item["phase"] for item in summary["measurements"]["latency_by_phase"]] == list(PHASES)
    assert summary["claim_scope"] == {
        "internet_scale_claim": False,
        "production_reliability_claim": False,
        "production_slo_claim": False,
        "scope": "ISOLATED_ACCEPTANCE_ONLY",
    }
    assert len(summary["artifact_digests"]["evidence"]) == 9
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(result.stdout)["report_id"] == summary["report_id"]


def test_summary_is_byte_deterministic(tmp_path: Path) -> None:
    manifest_path, sample_path, _, _ = _fixture(tmp_path)
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    assert _run(manifest_path, sample_path, first).returncode == 0
    assert _run(manifest_path, sample_path, second).returncode == 0

    assert first.read_bytes() == second.read_bytes()


def test_failed_hosted_run_is_summarized_instead_of_discarded(tmp_path: Path) -> None:
    manifest_path, sample_path, manifest, sample_set = _fixture(tmp_path)
    manifest["status"] = "FAILED"
    manifest["evidence_binding_complete"] = False
    manifest["cases"][0]["status"] = "FAILED"
    sample_set["source_manifest_sha256"] = _write(manifest_path, manifest)
    for sample in sample_set["samples"]:
        sample["status"] = "PASSED"
    _write(sample_path, sample_set)

    output = tmp_path / "summary.json"
    result = _run(manifest_path, sample_path, output)

    assert result.returncode == 0, result.stderr
    summary = json.loads(output.read_bytes())
    assert summary["measurement_result"] == "OBSERVED_WITH_FAILURES"
    assert summary["source_run"]["status"] == "FAILED"
    assert summary["source_run"]["evidence_binding_complete"] is False
    assert summary["source_run"]["failed_case_ids"] == ["case-one"]


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ("missing_phase", "MEASUREMENT_SAMPLE_SET_INVALID"),
        ("unknown_field", "MEASUREMENT_SAMPLE_SET_INVALID"),
        ("unsafe_parallelism", "MEASUREMENT_SAMPLE_SET_INVALID"),
        ("wrong_source_digest", "MEASUREMENT_SOURCE_DIGEST_MISMATCH"),
        ("wrong_evidence_digest", "MEASUREMENT_EVIDENCE_BINDING_MISMATCH"),
    ),
)
def test_invalid_samples_fail_closed(
    tmp_path: Path,
    mutation: str,
    expected_code: str,
) -> None:
    manifest_path, sample_path, _, sample_set = _fixture(tmp_path)
    if mutation == "missing_phase":
        sample_set["samples"] = sample_set["samples"][:-2]
        sample_set["bounds"]["maximum_samples"] = 16
    elif mutation == "unknown_field":
        sample_set["unexpected"] = True
    elif mutation == "unsafe_parallelism":
        sample_set["bounds"]["maximum_parallel_runs"] = 2
    elif mutation == "wrong_source_digest":
        sample_set["source_manifest_sha256"] = "f" * 64
    else:
        sample_set["samples"][0]["evidence_sha256"] = "f" * 64
    _write(sample_path, sample_set)

    result = _run(manifest_path, sample_path, tmp_path / "summary.json")

    assert result.returncode == 2
    assert json.loads(result.stderr) == {"code": expected_code}


def test_noncanonical_or_nonisolated_source_fails_closed(tmp_path: Path) -> None:
    manifest_path, sample_path, manifest, _ = _fixture(tmp_path)
    manifest["inputs"]["target"]["environment"] = "production"
    manifest_path.write_bytes(_canonical(manifest))

    result = _run(manifest_path, sample_path, tmp_path / "summary.json")

    assert result.returncode == 2
    assert json.loads(result.stderr) == {"code": "MEASUREMENT_SOURCE_INVALID"}


def test_output_is_create_only(tmp_path: Path) -> None:
    manifest_path, sample_path, _, _ = _fixture(tmp_path)
    output = tmp_path / "summary.json"
    output.write_text("retained", encoding="utf-8")

    result = _run(manifest_path, sample_path, output)

    assert result.returncode == 2
    assert output.read_text(encoding="utf-8") == "retained"
    assert json.loads(result.stderr) == {"code": "MEASUREMENT_OUTPUT_INVALID"}
