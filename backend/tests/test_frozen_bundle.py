from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "frozen_bundle.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("frozen_bundle", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bundle = _load_script()


def _run(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _write_json(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_text(path: Path, value: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    repo = tmp_path / "repo"
    artifacts = tmp_path / "artifacts"
    repo.mkdir()
    artifacts.mkdir()
    _run(repo, "init", "-q")
    _run(repo, "config", "user.email", "acceptance@example.test")
    _run(repo, "config", "user.name", "Acceptance")
    _run(
        repo,
        "remote",
        "add",
        "origin",
        "git@github.com:OCHOLA-EDDYPHIL/controlgraph.git",
    )

    repository_files = {
        "architecture": ("ARCHITECTURE_DOCUMENT", "docs/architecture.md"),
        "architecture-diagram": ("ARCHITECTURE_DIAGRAM", "docs/assets/architecture.svg"),
        "quickstart": ("QUICKSTART_DOCUMENT", "docs/quickstart.md"),
        "demo-asset": ("DEMO_ASSET", "docs/assets/demo.txt"),
        "comparison": ("NATIVE_COMPARISON_DOCUMENT", "docs/comparison.md"),
        "limitations": ("LIMITATIONS_DOCUMENT", "docs/limitations.md"),
        "disclosures": ("DISCLOSURE_DOCUMENT", "docs/disclosures.md"),
    }
    for artifact_id, (_, relative) in repository_files.items():
        _write_text(repo / relative, f"{artifact_id}\n")
    _run(repo, "add", ".")
    _run(repo, "commit", "-qm", "fixture")
    revision = _run(repo, "rev-parse", "HEAD")
    _run(repo, "tag", "-a", "v0.1.0", "-m", "fixture release")
    tag_object = _run(repo, "rev-parse", "refs/tags/v0.1.0")

    entries: list[dict[str, Any]] = []

    def add_repo(artifact_id: str, kind: str, relative: str) -> None:
        entries.append(
            {
                "id": artifact_id,
                "kind": kind,
                "location": "REPOSITORY",
                "path": relative,
                "sha256": hashlib.sha256((repo / relative).read_bytes()).hexdigest(),
                "status": "VERIFIED",
            }
        )

    def add_json(
        artifact_id: str,
        kind: str,
        value: dict[str, Any],
        *,
        relative: str | None = None,
        schema: str | None = None,
    ) -> None:
        relative = relative or f"{artifact_id}.json"
        entries.append(
            {
                "id": artifact_id,
                "kind": kind,
                "location": "BUNDLE",
                "path": relative,
                "schema_version": schema or bundle.JSON_SCHEMAS[kind],
                "sha256": _write_json(artifacts / relative, value),
                "status": "VERIFIED",
            }
        )

    for artifact_id, (kind, relative) in repository_files.items():
        add_repo(artifact_id, kind, relative)

    add_json(
        "contracts",
        "CONTRACT_SCHEMA_INDEX",
        {
            "schema_version": "controlgraph.contract-schema-index/v1",
            "source_commit": revision,
            "schemas": [{"id": "promotion-command", "version": "v2"}],
        },
    )
    plan_path = artifacts / "terraform-plan.json"
    entries.append(
        {
            "id": "terraform-plan",
            "kind": "TERRAFORM_PLAN",
            "location": "BUNDLE",
            "path": "terraform-plan.json",
            "sha256": _write_json(plan_path, {"format_version": "1.2"}),
            "status": "VERIFIED",
        }
    )
    add_json(
        "core-acceptance",
        "CORE_ACCEPTANCE_MANIFEST",
        {
            "schema_version": "controlgraph.core-acceptance-manifest/v1",
            "status": "PASSED",
            "evidence_binding_complete": True,
            "inputs": {"source_commit": revision},
        },
    )
    scenarios: list[dict[str, Any]] = []
    fault_evidence: list[str] = []
    for index, fault in enumerate(sorted(bundle.FAULT_KINDS)):
        scenario = {
            "activation": {
                "identity_sha256": "a" * 64,
                "schema_version": "controlgraph.fault-activation/v1",
            },
            "boundary": f"boundary.{index}",
            "fault": fault,
            "purpose": "PRODUCT_VALIDATION",
            "random_seed": index + 1,
            "required_invariants": ["SAFE_FALLBACK"],
            "scenario_id": f"fault-{index}",
            "schema_version": "controlgraph.fault-scenario/v1",
            "target": {
                "environment": "acceptance",
                "project_id": "controlgraph-canary-abc123",
                "region": "us-central1",
                "schema_version": "controlgraph.acceptance-fault-target/v1",
                "service_name": "controlgraph-reference-target",
            },
        }
        scenarios.append(scenario)
        evidence_id = f"fault-{index}"
        fault_evidence.append(evidence_id)
        add_json(
            evidence_id,
            "FAULT_APPLICATION_EVIDENCE",
            {
                "activation_identity_sha256": "a" * 64,
                "boundary": scenario["boundary"],
                "fault": fault,
                "observed_invariants": ["SAFE_FALLBACK"],
                "purpose": "PRODUCT_VALIDATION",
                "random_seed": index + 1,
                "result": "PASSED",
                "scenario_id": scenario["scenario_id"],
                "scenario_sha256": bundle._canonical_sha(scenario),
                "schema_version": "controlgraph.fault-application-evidence/v1",
                "target": scenario["target"],
            },
        )
    add_json(
        "fault-scenarios",
        "FAULT_SCENARIO_SET",
        {
            "schema_version": "controlgraph.fault-scenario-set/v1",
            "scenarios": scenarios,
        },
    )
    add_json(
        "security-abuse",
        "SECURITY_ABUSE_MANIFEST",
        {
            "schema_version": "controlgraph.security-abuse-manifest/v1",
            "source_commit": revision,
            "status": "PASSED",
            "target_unchanged_for_every_case": True,
            "no_temporary_iam": True,
            "no_controls_disabled": True,
        },
    )
    add_json(
        "performance",
        "PERFORMANCE_SUMMARY",
        {
            "schema_version": "controlgraph.measurement-summary/v1",
            "environment": {"source_commit": revision},
            "measurement_result": "OBSERVED",
            "measurement_set_sha256": "b" * 64,
            "failures": [],
            "artifact_digests": {
                "acceptance_manifest_sha256": next(
                    item["sha256"] for item in entries if item["id"] == "core-acceptance"
                ),
                "terraform_plan_sha256": next(
                    item["sha256"] for item in entries if item["id"] == "terraform-plan"
                ),
            },
            "measurements": {"run_cost": {"within_bound": True}},
            "source_run": {
                "status": "PASSED",
                "evidence_binding_complete": True,
                "within_duration_bound": True,
            },
            "known_limitations": ["ISOLATED_SINGLE_PROJECT_AND_REGION"],
            "claim_scope": {
                "internet_scale_claim": False,
                "production_reliability_claim": False,
                "production_slo_claim": False,
            },
        },
    )
    add_json(
        "checks",
        "REQUIRED_CHECK_RESULTS",
        {
            "schema_version": "controlgraph.required-check-results/v1",
            "source_commit": revision,
            "status": "PASSED",
            "checks": {key: "PASSED" for key in sorted(bundle.REQUIRED_CHECKS)},
        },
    )

    release_root = artifacts / "release"
    nested_files: dict[str, str] = {}
    for name in ["backend", "cli", "console", "terraform", "release"] + [
        f"image-{name}"
        for name in ["controller", "console", "advisor", "reference-stable", "reference-candidate"]
    ]:
        nested_files[f"sboms/{name}.json"] = _write_json(
            release_root / f"sboms/{name}.json", {"name": name}
        )
        nested_files[f"scans/{name}.json"] = _write_json(
            release_root / f"scans/{name}.json", {"name": name}
        )
    nested_files["tooling/database.json"] = _write_json(
        release_root / "tooling/database.json", {"updated": "fixture"}
    )
    _write_json(release_root / "attestations/provenance.json", {"fixture": True})
    _write_json(
        release_root / "provenance.intoto.jsonl",
        {"predicateType": "https://slsa.dev/provenance/v1"},
    )
    subjects: dict[str, Any] = {}
    for name in ["backend", "cli", "console", "terraform", "release"]:
        subjects[name] = {
            "sbom": {"path": f"sboms/{name}.json", "sha256": nested_files[f"sboms/{name}.json"]},
            "vulnerability_and_secret_scan": {
                "path": f"scans/{name}.json",
                "sha256": nested_files[f"scans/{name}.json"],
            },
        }
    for name in ["controller", "console", "advisor", "reference-stable", "reference-candidate"]:
        subject = f"image-{name}"
        subjects[subject] = {
            "immutable_reference": (
                "us-central1-docker.pkg.dev/controlgraph-canary-abc123/"
                f"controlgraph-canary/{name}@sha256:{index + 1:064x}"
            ),
            "sbom": {
                "path": f"sboms/{subject}.json",
                "sha256": nested_files[f"sboms/{subject}.json"],
            },
            "vulnerability_and_secret_scan": {
                "path": f"scans/{subject}.json",
                "sha256": nested_files[f"scans/{subject}.json"],
            },
        }
    material_path = "docs/architecture.md"
    release_manifest = {
        "schema_version": "controlgraph.release-evidence/v1",
        "source": {"repository": bundle.REPOSITORY, "revision": revision},
        "runtime_security_claim": False,
        "materials": [
            {
                "path": material_path,
                "sha256": hashlib.sha256((repo / material_path).read_bytes()).hexdigest(),
            }
        ],
        "subjects": subjects,
        "tooling": {
            "trivy": {
                "database": {
                    "path": "tooling/database.json",
                    "sha256": nested_files["tooling/database.json"],
                }
            }
        },
        "attestations": {"image-provenance": "attestations/provenance.json"},
    }
    release_sha = _write_json(release_root / "manifest.json", release_manifest)
    add_json(
        "release-evidence",
        "RELEASE_EVIDENCE_MANIFEST",
        release_manifest,
        relative="release/manifest.json",
    )
    add_json(
        "release-verification",
        "RELEASE_EVIDENCE_VERIFICATION",
        {
            "schema_version": "controlgraph.release-evidence-verification/v1",
            "source_sha": revision,
            "manifest_sha256": release_sha,
            "verified": True,
            "runtime_security_claim": False,
        },
        relative="release/VERIFIED.json",
    )
    add_json(
        "demo-manifest",
        "DEMO_MANIFEST",
        {"schema_version": "controlgraph.demo-manifest/v1", "status": "PASSED"},
        schema="controlgraph.demo-manifest/v1",
    )

    claim_evidence = {
        "architecture": ["architecture", "architecture-diagram"],
        "security": ["security-abuse", "release-evidence"],
        "determinism": ["fault-scenarios", *fault_evidence],
        "latency": ["performance"],
        "reliability": ["core-acceptance", "performance"],
        "cost": ["performance"],
        "comparison": ["comparison"],
        "demo": ["demo-asset", "demo-manifest"],
    }
    claims = []
    for category, evidence_ids in claim_evidence.items():
        statement = f"Fixture {category} claim"
        claims.append(
            {
                "id": f"claim-{category}",
                "category": category,
                "statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "source_ids": ["source"],
                "evidence_ids": evidence_ids,
                "status": "SUPPORTED",
            }
        )
    claim_ids = {claim["id"] for claim in claims}
    add_json(
        "release-review",
        "RELEASE_REVIEW",
        {
            "schema_version": "controlgraph.release-review/v1",
            "source_commit": revision,
            "status": "PASSED",
            "checks": {key: "PASSED" for key in sorted(bundle.RELEASE_CHECKS)},
            "claim_ids": sorted(claim_ids),
            "residual_risks": ["ISOLATED_ACCEPTANCE_ONLY"],
        },
    )
    add_json(
        "clean-room",
        "CLEAN_ROOM_REHEARSAL",
        {
            "schema_version": "controlgraph.clean-room-rehearsal/v1",
            "source_commit": revision,
            "source_tag": "v0.1.0",
            "status": "PASSED",
            "steps": {key: "PASSED" for key in sorted(bundle.CLEAN_ROOM_STEPS)},
            "sign_off": {"reviewer_id": "fixture-reviewer", "recorded_at": "2026-08-24T00:00:00Z"},
        },
    )
    spec = {
        "schema_version": "controlgraph.frozen-bundle-spec/v1",
        "source": {
            "repository": bundle.REPOSITORY,
            "revision": revision,
            "tag": "v0.1.0",
            "tag_status": "VERIFIED",
            "tag_object_sha": tag_object,
        },
        "artifacts": entries,
        "claims": claims,
    }
    spec_path = tmp_path / "spec.json"
    _write_json(spec_path, spec)
    return repo, artifacts, spec_path, spec


def test_ready_bundle_binds_claims_faults_and_supply_chain(tmp_path: Path) -> None:
    repo, artifacts, spec_path, _ = _fixture(tmp_path)

    result, ready = bundle.verify_bundle(repo, spec_path, artifacts)

    assert ready is True
    assert result["status"] == "READY"
    assert result["pending"] == []
    assert set(result["supply_chain"]["images"]) == {
        "advisor",
        "console",
        "controller",
        "reference-candidate",
        "reference-stable",
    }


def test_pending_entries_remain_fail_closed_without_artifacts(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["source"]["tag_status"] = "PENDING"
    spec["source"]["tag_object_sha"] = None
    for artifact in spec["artifacts"]:
        artifact["status"] = "PENDING"
        artifact["sha256"] = None
    for claim in spec["claims"]:
        claim["status"] = "PENDING"
    _write_json(spec_path, spec)

    result, ready = bundle.verify_bundle(repo, spec_path, artifacts)

    assert ready is False
    assert result["status"] == "PENDING"
    assert "SOURCE_TAG" in result["pending"]
    assert "CLAIM:claim-demo" in result["pending"]


def test_fault_evidence_must_bind_the_canonical_scenario_digest(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    entry = next(item for item in spec["artifacts"] if item["id"] == "fault-0")
    payload = json.loads((artifacts / entry["path"]).read_text())
    payload["scenario_sha256"] = "f" * 64
    entry["sha256"] = _write_json(artifacts / entry["path"], payload)
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match="FAULT_APPLICATION_EVIDENCE_INVALID"):
        bundle.verify_bundle(repo, spec_path, artifacts)


def test_demo_claim_cannot_be_supported_before_final_manifest_exists(tmp_path: Path) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path)
    spec["artifacts"] = [item for item in spec["artifacts"] if item["kind"] != "DEMO_MANIFEST"]
    demo_claim = next(item for item in spec["claims"] if item["category"] == "demo")
    demo_claim["evidence_ids"] = ["demo-asset"]
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match="DEMO_CLAIM_HAS_NO_FINAL_MANIFEST"):
        bundle.verify_bundle(repo, spec_path, artifacts)
