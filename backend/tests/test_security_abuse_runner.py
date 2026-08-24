from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).parents[2] / "scripts" / "security_abuse.py"
SOURCE_ROOT = SCRIPT.parents[1]

CASES = (
    (
        "CROSS_IDENTITY_INVOCATION",
        "cloud-run:cross-identity-invocation",
        "AUTHENTICATED_HTTP",
        "CLOUD_IAM",
        "IDENTITY_DENIED",
        4,
    ),
    (
        "CROSS_PROJECT_TARGET",
        "controlgraph:cross-project-target",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "TARGET_DENIED",
        1,
    ),
    (
        "CROSS_SERVICE_TARGET",
        "controlgraph:cross-service-target",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "TARGET_DENIED",
        1,
    ),
    (
        "CAPABILITY_TAMPER",
        "controlgraph:tampered-capability",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "SIGNATURE_DENIED",
        1,
    ),
    (
        "CAPABILITY_REPLAY",
        "controlgraph:cross-request-capability-replay",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "REPLAY_DENIED",
        1,
    ),
    (
        "STALE_EPOCH",
        "controlgraph:stale-epoch-execution",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "EPOCH_DENIED",
        1,
    ),
    (
        "SCOPE_AMPLIFICATION",
        "controlgraph:widened-capability-scope",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "SCOPE_DENIED",
        1,
    ),
    (
        "RECEIPT_COLLISION",
        "controlgraph:receipt-key-collision",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "RECEIPT_DENIED",
        1,
    ),
    (
        "RECOVERY_PROMOTION",
        "controlgraph:recovery-promote-candidate",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "RECOVERY_LIMIT_DENIED",
        1,
    ),
    (
        "RECOVERY_REVISION_SELECTION",
        "controlgraph:recovery-select-revision",
        "PROTECTED_APPLICATION_ROUTE",
        "APPLICATION",
        "RECOVERY_LIMIT_DENIED",
        1,
    ),
    (
        "VERIFIER_MUTATION",
        "iam:verifier-update-target",
        "IAM_POLICY_TROUBLESHOOTER",
        "CLOUD_IAM",
        "MUTATION_AUTHORITY_DENIED",
        1,
    ),
    (
        "ISSUER_MUTATION",
        "iam:issuer-update-target",
        "IAM_POLICY_TROUBLESHOOTER",
        "CLOUD_IAM",
        "MUTATION_AUTHORITY_DENIED",
        1,
    ),
    (
        "UNAUTHORIZED_EVIDENCE_READ",
        "controlgraph:restricted-evidence-read",
        "AUTHENTICATED_HTTP",
        "APPLICATION",
        "EVIDENCE_ACCESS_DENIED",
        1,
    ),
    (
        "MODEL_TOOL_MUTATION",
        "adk:unregistered-mutation-tool",
        "ADK_TOOL_REGISTRY",
        "APPLICATION",
        "TOOL_DENIED",
        1,
    ),
    (
        "ADVISOR_MUTATION",
        "iam:advisor-update-target",
        "IAM_POLICY_TROUBLESHOOTER",
        "CLOUD_IAM",
        "MUTATION_AUTHORITY_DENIED",
        1,
    ),
)

REASONS = {
    "CROSS_IDENTITY_INVOCATION": "IAM_PERMISSION_DENIED",
    "CROSS_PROJECT_TARGET": "TARGET_BINDING_MISMATCH",
    "CROSS_SERVICE_TARGET": "TARGET_BINDING_MISMATCH",
    "CAPABILITY_TAMPER": "SIGNATURE_INVALID",
    "CAPABILITY_REPLAY": "CLAIM_BINDING_MISMATCH",
    "STALE_EPOCH": "EPOCH_MISMATCH",
    "SCOPE_AMPLIFICATION": "SCOPE_AMPLIFICATION",
    "RECEIPT_COLLISION": "IDEMPOTENCY_CONFLICT",
    "RECOVERY_PROMOTION": "RECOVERY_COMMAND_DENIED",
    "RECOVERY_REVISION_SELECTION": "RECOVERY_COMMAND_DENIED",
    "VERIFIER_MUTATION": "IAM_PERMISSION_DENIED",
    "ISSUER_MUTATION": "IAM_PERMISSION_DENIED",
    "UNAUTHORIZED_EVIDENCE_READ": "TIMELINE_RAW_EXPORT_ACCESS_DENIED",
    "MODEL_TOOL_MUTATION": "DIAGNOSTIC_TOOL_DENIED",
    "ADVISOR_MUTATION": "IAM_PERMISSION_DENIED",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _write(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical(value)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _repository(path: Path) -> str:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "scripts").mkdir()
    shutil.copy2(SCRIPT, path / "scripts" / "security_abuse.py")
    package = path / "backend" / "src" / "controlgraph_canary"
    (package / "contracts").mkdir(parents=True)
    for relative_path in ("__init__.py", "contracts/base.py", "contracts/codec.py"):
        source = SOURCE_ROOT / "backend" / "src" / "controlgraph_canary" / relative_path
        shutil.copy2(source, package / relative_path)
    (package / "contracts" / "__init__.py").write_text(
        '"""Security abuse runner test package."""\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Security Test",
            "-c",
            "user.email=security@example.invalid",
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


def _artifact(artifact_id: str, relative_path: str, digest: str) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "media_type": "application/json",
        "relative_path": relative_path,
        "schema_version": "controlgraph.security-abuse-artifact/v1",
        "sha256": digest,
    }


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    repo = tmp_path / "repo"
    source_commit = _repository(repo)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    target = {
        "project_id": "controlgraph-canary-abc123",
        "region": "us-central1",
        "schema_version": "controlgraph.security-abuse-target/v1",
        "service_name": "controlgraph-reference-target",
    }
    bindings: list[dict[str, object]] = []
    for sequence, (kind, operation, method, layer, denial_class, attempts) in enumerate(
        CASES, start=1
    ):
        case_id = f"security-abuse-{sequence:02d}"
        evidence = {
            "attempt_count": attempts,
            "attempted_at": "2026-08-24T00:00:01Z",
            "case_id": case_id,
            "denial_class": denial_class,
            "denial_layer": layer,
            "kind": kind,
            "observed_reason_code": REASONS[kind],
            "operation": operation,
            "probe_method": method,
            "provider_mutation_calls": 0,
            "readback_after_at": "2026-08-24T00:00:02Z",
            "readback_before_at": "2026-08-24T00:00:00Z",
            "schema_version": "controlgraph.security-abuse-case-evidence/v1",
            "sequence": sequence,
            "source_commit": source_commit,
            "status": "DENIED",
            "target": target,
            "target_after_sha256": "1" * 64,
            "target_before_sha256": "1" * 64,
            "unauthorized_target_change": False,
        }
        relative_path = f"cases/{sequence:02d}.json"
        digest = _write(artifacts / relative_path, evidence)
        bindings.append(
            {
                "case_id": case_id,
                "evidence": _artifact(f"case-{sequence:02d}", relative_path, digest),
                "kind": kind,
                "schema_version": "controlgraph.security-abuse-case-binding/v1",
                "sequence": sequence,
            }
        )
    spec: dict[str, Any] = {
        "cases": bindings,
        "completed_at": "2026-08-24T00:00:03Z",
        "controls_disabled": [],
        "core_acceptance_manifest_sha256": "2" * 64,
        "execution_mode": "HOSTED_GOOGLE_CLOUD",
        "fixture_cleanup_status": "NOT_REQUIRED",
        "identity_mode": "EXISTING_IDENTITIES_ONLY",
        "schema_version": "controlgraph.security-abuse-run/v1",
        "source_commit": source_commit,
        "started_at": "2026-08-24T00:00:00Z",
        "target": target,
        "temporary_iam_bindings_created": 0,
        "temporary_service_accounts_created": 0,
    }
    spec_path = tmp_path / "run.json"
    _write(spec_path, spec)
    return repo, artifacts, spec_path, spec


def _run(
    repo: Path,
    artifacts: Path,
    spec_path: Path,
    output: Path,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(repo / "backend" / "src")
    return subprocess.run(
        [
            sys.executable,
            str(repo / "scripts" / "security_abuse.py"),
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


def _rewrite_case(
    artifacts: Path,
    spec_path: Path,
    spec: dict[str, Any],
    index: int,
    **changes: object,
) -> None:
    binding = spec["cases"][index]
    evidence_path = artifacts / binding["evidence"]["relative_path"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence.update(changes)
    binding["evidence"]["sha256"] = _write(evidence_path, evidence)
    _write(spec_path, spec)


def test_binds_complete_denial_run_without_copying_private_evidence(tmp_path: Path) -> None:
    repo, artifacts, spec_path, _ = _fixture(tmp_path)
    output = tmp_path / "manifest.json"

    completed = _run(repo, artifacts, spec_path, output)

    assert completed.returncode == 0
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "controlgraph.security-abuse-manifest/v1"
    assert manifest["status"] == "PASSED"
    assert manifest["target_unchanged_for_every_case"] is True
    assert [item["kind"] for item in manifest["cases"]] == [item[0] for item in CASES]
    encoded = output.read_text(encoding="utf-8")
    assert "relative_path" not in encoded


def test_rejects_incomplete_or_reordered_case_set(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["cases"].pop()
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"SECURITY_ABUSE_SPEC_INVALID"}'


def test_rejects_target_outside_isolated_project(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["target"]["project_id"] = "production-control-plane"
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"SECURITY_ABUSE_SPEC_INVALID"}'


def test_rejects_changed_evidence_artifact(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    evidence = artifacts / spec["cases"][0]["evidence"]["relative_path"]
    evidence.write_text("changed", encoding="utf-8")

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"SECURITY_ABUSE_ARTIFACT_DIGEST_MISMATCH"}'


def test_rejects_caller_selected_operation(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    _rewrite_case(artifacts, spec_path, spec, 0, operation="custom:security-probe")

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"SECURITY_ABUSE_CASE_BINDING_MISMATCH"}'


def test_reports_failed_run_when_target_changes(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    _rewrite_case(artifacts, spec_path, spec, 3, target_after_sha256="3" * 64)
    output = tmp_path / "manifest.json"

    completed = _run(repo, artifacts, spec_path, output)

    assert completed.returncode == 1
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["status"] == "FAILED"
    assert manifest["target_unchanged_for_every_case"] is False
    assert manifest["cases"][3]["status"] == "FAILED"


def test_reports_failed_run_when_denial_reaches_provider_mutation(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    _rewrite_case(artifacts, spec_path, spec, 8, provider_mutation_calls=1)
    output = tmp_path / "manifest.json"

    completed = _run(repo, artifacts, spec_path, output)

    assert completed.returncode == 1
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "FAILED"


def test_reports_failed_run_for_unexpected_permission(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    _rewrite_case(
        artifacts,
        spec_path,
        spec,
        10,
        observed_reason_code="UNEXPECTED_ALLOW",
        status="PERMITTED",
    )
    output = tmp_path / "manifest.json"

    completed = _run(repo, artifacts, spec_path, output)

    assert completed.returncode == 1
    assert json.loads(output.read_text(encoding="utf-8"))["cases"][10]["status"] == "FAILED"


def test_rejects_temporary_iam_or_disabled_controls(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["temporary_iam_bindings_created"] = 1
    spec["controls_disabled"] = ["cloud-run-authentication"]
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"SECURITY_ABUSE_SPEC_INVALID"}'


def test_rejects_source_commit_mismatch(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["source_commit"] = "f" * 40
    _write(spec_path, spec)

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"SECURITY_ABUSE_SOURCE_MISMATCH"}'


def test_rejects_noncanonical_reason_code(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    _rewrite_case(artifacts, spec_path, spec, 0, observed_reason_code="permission denied")

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"SECURITY_ABUSE_CASE_EVIDENCE_INVALID"}'


def test_rejects_unrecognized_claimed_denial(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    _rewrite_case(artifacts, spec_path, spec, 0, observed_reason_code="EXPECTED_DENIAL")

    completed = _run(repo, artifacts, spec_path, tmp_path / "manifest.json")

    assert completed.returncode == 2
    assert completed.stderr.strip() == '{"code":"SECURITY_ABUSE_CASE_BINDING_MISMATCH"}'


def test_console_iam_check_compares_the_provider_resource_name_by_service() -> None:
    iam = (SOURCE_ROOT / "infra" / "runtime" / "iam.tf").read_text(encoding="utf-8")

    assert (
        'trimprefix(google_cloud_run_v2_service_iam_member.operator_console_public.name, '
        '"projects/${var.project_id}/locations/${var.region}/services/") '
        "== module.console.service.name"
    ) in iam
