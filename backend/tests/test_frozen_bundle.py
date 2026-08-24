from __future__ import annotations

import copy
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


def _core_artifact(artifact_id: str, sha256: str, byte_count: int = 64) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "byte_count": byte_count,
        "media_type": "application/json",
        "sha256": sha256,
    }


def _core_manifest(
    *,
    revision: str,
    image_references: dict[str, str],
    plan_id: str,
    plan_sha256: str,
    plan_bytes: int,
    digest_digit: str,
) -> dict[str, Any]:
    run_inputs_sha256 = digest_digit * 64
    spec_sha256 = chr(ord(digest_digit) + 1) * 64
    cases: list[dict[str, Any]] = []
    artifact_index = 16
    for sequence, kind in enumerate(bundle.CORE_CASE_ORDER, start=1):
        evidence: list[dict[str, Any]] = []
        for evidence_kind in sorted(bundle.CORE_REQUIRED_EVIDENCE[kind]):
            slug = evidence_kind.lower().replace("_", "-")
            evidence_id = f"case-{sequence}-{slug}"
            evidence.append(
                {
                    "artifact": _core_artifact(f"artifact-{evidence_id}", f"{artifact_index:064x}"),
                    "evidence_id": evidence_id,
                    "kind": evidence_kind,
                    "observed_at": f"2026-08-24T00:{sequence:02d}:00Z",
                    "projection": "PUBLIC_REDACTED",
                }
            )
            artifact_index += 1
        evidence_ids = [item["evidence_id"] for item in evidence]
        split = len(evidence_ids) // 2
        entry_points = [f"runner:reset-case-{sequence}", f"runner:run-case-{sequence}"]
        cases.append(
            {
                "case_id": f"case-{sequence}",
                "completed_at": f"2026-08-24T00:{sequence:02d}:01Z",
                "cost": {
                    "basis": "UPPER_BOUND",
                    "maximum_microusd": 100,
                    "reported_microusd": 10,
                },
                "duration_ms": 10,
                "entry_points": entry_points,
                "evidence": evidence,
                "execution_mode": "HOSTED_GOOGLE_CLOUD",
                "expected_result": bundle.CORE_EXPECTED_RESULTS[kind],
                "kind": kind,
                "maximum_duration_ms": 1_000,
                "observed_result": bundle.CORE_EXPECTED_RESULTS[kind],
                "random_seed": sequence,
                "result_artifact": _core_artifact(
                    f"case-{sequence}-result", f"{artifact_index:064x}"
                ),
                "sequence": sequence,
                "started_at": f"2026-08-24T00:{sequence:02d}:00Z",
                "status": "PASSED",
                "steps": [
                    {
                        "duration_ms": 5,
                        "evidence_ids": evidence_ids[:split],
                        "operation": entry_points[0],
                        "schema_version": "controlgraph.core-acceptance-step-result/v1",
                        "sequence": 1,
                        "status": "PASSED",
                    },
                    {
                        "duration_ms": 5,
                        "evidence_ids": evidence_ids[split:],
                        "operation": entry_points[1],
                        "schema_version": "controlgraph.core-acceptance-step-result/v1",
                        "sequence": 2,
                        "status": "PASSED",
                    },
                ],
                "test_clock_keys": [f"case-{sequence}-start"],
            }
        )
        artifact_index += 1
    return {
        "cases": cases,
        "completed_at": "2026-08-24T00:09:01Z",
        "cost": {
            "basis": "UPPER_BOUND",
            "currency": "USD",
            "maximum_microusd": 800,
            "reported_microusd": 80,
        },
        "duration_ms": 80,
        "evidence_binding_complete": True,
        "inputs": {
            "images": [
                {
                    "schema_version": "controlgraph.acceptance-image/v1",
                    "component": name,
                    "reference": image_references[name],
                }
                for name in (
                    "controller",
                    "advisor",
                    "console",
                    "reference-stable",
                    "reference-candidate",
                )
            ],
            "policies": [
                {
                    "artifact": _core_artifact("rollout-policy", "b" * 64),
                    "policy_schema_version": "controlgraph.rollout-health-policy/v1",
                }
            ],
            "random_seed": 17,
            "run_inputs_sha256": run_inputs_sha256,
            "source_commit": revision,
            "target": {
                "schema_version": "controlgraph.acceptance-target/v1",
                "project_id": "controlgraph-canary-abc123",
                "region": "us-central1",
                "environment": "nonprod",
                "service_name": "controlgraph-reference-target",
                "stable_revision": "reference-stable-00001-aaa",
                "candidate_revision": "reference-candidate-00002-bbb",
            },
            "terraform_plan": _core_artifact(plan_id, plan_sha256, plan_bytes),
            "test_clock": {
                "schema_version": "controlgraph.acceptance-test-clock/v1",
                "ticks": [
                    {
                        "at": f"2026-08-24T00:{sequence:02d}:00Z",
                        "name": f"case-{sequence}-start",
                        "schema_version": "controlgraph.acceptance-test-clock-tick/v1",
                    }
                    for sequence in range(1, 9)
                ],
            },
        },
        "maximum_duration_ms": 8_000,
        "run_id": f"cgacceptance:{spec_sha256}",
        "runner_mode": "EXPLICIT_HOSTED_EVIDENCE_BINDING",
        "schema_version": "controlgraph.core-acceptance-manifest/v1",
        "spec_sha256": spec_sha256,
        "started_at": "2026-08-24T00:01:00Z",
        "status": "PASSED",
    }


def _fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, dict[str, Any]]:
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
    original_git = bundle._git

    def git_with_remote_tag(repository: Path, *args: str) -> str:
        if args[:3] == ("ls-remote", "--tags", "origin"):
            return f"{tag_object}\trefs/tags/v0.1.0\n{revision}\trefs/tags/v0.1.0^{{}}"
        return str(original_git(repository, *args))

    monkeypatch.setattr(bundle, "_git", git_with_remote_tag)
    image_components = (
        "controller",
        "advisor",
        "console",
        "reference-stable",
        "reference-candidate",
    )
    image_references = {
        name: (
            "us-central1-docker.pkg.dev/controlgraph-canary-abc123/"
            f"controlgraph-canary/{name}@sha256:{index:064x}"
        )
        for index, name in enumerate(image_components, start=1)
    }

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
    plan_sha256 = _write_json(plan_path, {"format_version": "1.2"})
    entries.append(
        {
            "id": "terraform-plan",
            "kind": "TERRAFORM_PLAN",
            "location": "BUNDLE",
            "path": "terraform-plan.json",
            "sha256": plan_sha256,
            "status": "VERIFIED",
        }
    )
    add_json(
        "core-acceptance",
        "CORE_ACCEPTANCE_MANIFEST",
        _core_manifest(
            revision=revision,
            image_references=image_references,
            plan_id="terraform-plan",
            plan_sha256=plan_sha256,
            plan_bytes=plan_path.stat().st_size,
            digest_digit="c",
        ),
    )
    fault_cases: list[dict[str, Any]] = []
    for index, fault in enumerate(bundle.FAULT_ORDER):
        digest = hashlib.sha256(
            b"controlgraph.fault-acceptance-seed/v1\0" + b"17\0" + fault.encode("ascii")
        ).digest()
        fault_cases.append(
            {
                "artifacts": [{"name": "evidence.json", "sha256": f"{index + 1:064x}"}],
                "boundary": f"boundary.{index}",
                "fault": fault,
                "injection": f"INJECT_{fault}",
                "observed_invariants": sorted(bundle.FAULT_INVARIANTS[fault]),
                "observation": {},
                "random_seed": int.from_bytes(digest[:6], "big"),
                "result": "PASSED",
                "root_id": f"cgroot:{index}",
                "scenario_id": (f"fault-{fault.lower().replace('_', '-')}-{digest.hex()[:16]}"),
            }
        )
    add_json(
        "fault-acceptance",
        "FAULT_ACCEPTANCE_MANIFEST",
        {
            "acceptance_principal_sha256": "a" * 64,
            "allowlisted_faults": list(bundle.FAULT_ORDER),
            "candidate_revision": "reference-candidate-00002-bbb",
            "cases": fault_cases,
            "environment": "nonprod",
            "project_id": "controlgraph-canary-abc123",
            "purpose": "PRODUCT_VALIDATION",
            "region": "us-central1",
            "result": "PASSED",
            "run_seed": 17,
            "schema_version": "controlgraph.fault-acceptance-manifest/v1",
            "service_name": "controlgraph-reference-target",
            "source_commit": revision,
            "stable_revision": "reference-stable-00001-aaa",
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
            "head_sha": revision,
            "workflow_run_id": 123456789,
            "event": "push",
            "run_url": ("https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/123456789"),
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
    for name in image_components:
        subject = f"image-{name}"
        subjects[subject] = {
            "immutable_reference": image_references[name],
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
    claim_evidence = {
        "architecture": ["architecture", "architecture-diagram"],
        "security": ["security-abuse", "release-evidence"],
        "determinism": ["fault-acceptance"],
        "latency": ["performance"],
        "reliability": ["core-acceptance", "performance"],
        "cost": ["performance"],
        "comparison": ["comparison"],
        "demo": ["demo-asset", "core-acceptance"],
    }
    claim_sources = {
        "architecture": ["architecture", "architecture-diagram"],
        "security": ["architecture"],
        "determinism": ["architecture"],
        "latency": ["limitations"],
        "reliability": ["architecture"],
        "cost": ["limitations"],
        "comparison": ["comparison"],
        "demo": ["quickstart", "demo-asset"],
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
                "source_ids": claim_sources[category],
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
    source = {
        "repository": bundle.REPOSITORY,
        "revision": revision,
        "tag": "v0.1.0",
        "tag_status": "VERIFIED",
        "tag_object_sha": tag_object,
    }
    prepared_spec = {
        "schema_version": "controlgraph.frozen-bundle-spec/v1",
        "stage": "PREPARED",
        "source": source,
        "artifacts": copy.deepcopy(entries),
        "claims": copy.deepcopy(claims),
    }
    prepared_spec_path = tmp_path / "prepared-spec.json"
    _write_json(prepared_spec_path, prepared_spec)
    prepared_bundle, ready = bundle.verify_bundle(repo, prepared_spec_path, artifacts)
    assert ready is False
    assert prepared_bundle["pending"] == ["CLEAN_ROOM_REHEARSAL"]
    add_json(
        "prepared-bundle",
        "PREPARED_BUNDLE",
        prepared_bundle,
        relative="prepared-bundle.json",
    )
    prepared_digest = next(item["sha256"] for item in entries if item["id"] == "prepared-bundle")
    clean_plan_path = artifacts / "clean-room" / "terraform-plan.json"
    clean_plan_sha256 = _write_json(
        clean_plan_path, {"format_version": "1.2", "resource_changes": []}
    )
    clean_core_path = artifacts / "clean-room" / "core-acceptance-manifest.json"
    clean_core_sha256 = _write_json(
        clean_core_path,
        _core_manifest(
            revision=revision,
            image_references=image_references,
            plan_id="clean-room-terraform-plan",
            plan_sha256=clean_plan_sha256,
            plan_bytes=clean_plan_path.stat().st_size,
            digest_digit="d",
        ),
    )
    link_validation_path = artifacts / "clean-room" / "evidence-links.json"
    link_validation_sha256 = _write_json(
        link_validation_path,
        {
            "core_acceptance_manifest_sha256": clean_core_sha256,
            "prepared_bundle_sha256": prepared_digest,
            "schema_version": "controlgraph.evidence-link-validation/v1",
            "source_commit": revision,
            "status": "PASSED",
            "terraform_plan_sha256": clean_plan_sha256,
            "validated_claim_ids": sorted(claim_ids),
        },
    )
    add_json(
        "clean-room",
        "CLEAN_ROOM_REHEARSAL",
        {
            "schema_version": "controlgraph.clean-room-rehearsal/v1",
            "source_commit": revision,
            "source_tag": "v0.1.0",
            "prepared_bundle_sha256": prepared_digest,
            "status": "PASSED",
            "steps": {key: "PASSED" for key in sorted(bundle.CLEAN_ROOM_STEPS)},
            "outputs": {
                "terraform_plan": {
                    "artifact_id": "clean-room-terraform-plan",
                    "path": "clean-room/terraform-plan.json",
                    "sha256": clean_plan_sha256,
                },
                "core_acceptance_manifest": {
                    "artifact_id": "clean-room-core-acceptance",
                    "path": "clean-room/core-acceptance-manifest.json",
                    "sha256": clean_core_sha256,
                },
                "evidence_link_validation": {
                    "artifact_id": "clean-room-evidence-links",
                    "path": "clean-room/evidence-links.json",
                    "sha256": link_validation_sha256,
                },
            },
            "sign_off": {
                "reviewer_id": "fixture-reviewer",
                "recorded_at": "2026-08-24T00:00:00Z",
            },
        },
    )
    spec = {
        "schema_version": "controlgraph.frozen-bundle-spec/v1",
        "stage": "FINAL",
        "source": source,
        "artifacts": entries,
        "claims": claims,
    }
    spec_path = tmp_path / "spec.json"
    _write_json(spec_path, spec)
    return repo, artifacts, spec_path, spec


def test_ready_bundle_binds_claims_faults_and_supply_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, artifacts, spec_path, _ = _fixture(tmp_path, monkeypatch)

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


def test_prepared_bundle_has_only_clean_room_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    spec["stage"] = "PREPARED"
    spec["artifacts"] = [
        item for item in spec["artifacts"] if item["kind"] not in bundle.FINAL_ONLY_KINDS
    ]
    _write_json(spec_path, spec)

    result, ready = bundle.verify_bundle(repo, spec_path, artifacts)

    assert ready is False
    assert result["status"] == "PENDING"
    assert result["stage"] == "PREPARED"
    assert result["pending"] == ["CLEAN_ROOM_REHEARSAL"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_commit", "f" * 40),
        ("environment", "acceptance"),
        ("stable_revision", "controlgraph-reference-target-other"),
        ("run_seed", 18),
    ],
)
def test_fault_manifest_must_bind_the_core_acceptance_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: Any
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    entry = next(item for item in spec["artifacts"] if item["id"] == "fault-acceptance")
    payload = json.loads((artifacts / entry["path"]).read_text())
    payload[field] = value
    entry["sha256"] = _write_json(artifacts / entry["path"], payload)
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match="FAULT_ACCEPTANCE_RUN_MISMATCH"):
        bundle.verify_bundle(repo, spec_path, artifacts)


def test_fault_manifest_rejects_the_superseded_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    entry = next(item for item in spec["artifacts"] if item["id"] == "fault-acceptance")
    entry["schema_version"] = "controlgraph.fault-scenario-set/v1"
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match="ARTIFACT_SCHEMA_INVALID"):
        bundle.verify_bundle(repo, spec_path, artifacts)


@pytest.mark.parametrize("tamper", ["principal", "root", "artifact", "invariant"])
def test_fault_manifest_rejects_unbound_passed_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    entry = next(item for item in spec["artifacts"] if item["id"] == "fault-acceptance")
    payload = json.loads((artifacts / entry["path"]).read_text())
    if tamper == "principal":
        payload["acceptance_principal_sha256"] = "invalid"
    elif tamper == "root":
        payload["cases"][1]["root_id"] = payload["cases"][0]["root_id"]
    elif tamper == "artifact":
        payload["cases"][0]["artifacts"].append(payload["cases"][0]["artifacts"][0])
    else:
        payload["cases"][0]["observed_invariants"] = ["SAFE_FALLBACK"]
    entry["sha256"] = _write_json(artifacts / entry["path"], payload)
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match="FAULT_ACCEPTANCE_MANIFEST_INVALID"):
        bundle.verify_bundle(repo, spec_path, artifacts)


def test_claim_source_must_be_a_verified_repository_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    demo_claim = next(item for item in spec["claims"] if item["category"] == "demo")
    demo_claim["source_ids"] = ["core-acceptance"]
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match="CLAIM_INVALID"):
        bundle.verify_bundle(repo, spec_path, artifacts)


def test_required_checks_bind_the_exact_main_workflow_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    entry = next(item for item in spec["artifacts"] if item["id"] == "checks")
    payload = json.loads((artifacts / entry["path"]).read_text())
    payload["run_url"] = "https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/987654321"
    entry["sha256"] = _write_json(artifacts / entry["path"], payload)
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match="REQUIRED_CHECK_RESULTS_INVALID"):
        bundle.verify_bundle(repo, spec_path, artifacts)


def test_core_images_must_match_release_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    entry = next(item for item in spec["artifacts"] if item["id"] == "core-acceptance")
    payload = json.loads((artifacts / entry["path"]).read_text())
    payload["inputs"]["images"][0]["reference"] = payload["inputs"]["images"][0][
        "reference"
    ].replace("@sha256:0", "@sha256:f", 1)
    entry["sha256"] = _write_json(artifacts / entry["path"], payload)
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match="CORE_RELEASE_IMAGE_MISMATCH"):
        bundle.verify_bundle(repo, spec_path, artifacts)


@pytest.mark.parametrize(
    ("tamper", "error"),
    [
        ("spec", "CORE_ACCEPTANCE_MANIFEST_INVALID"),
        ("run", "CORE_ACCEPTANCE_MANIFEST_INVALID"),
        ("input", "CORE_ACCEPTANCE_MANIFEST_INVALID"),
        ("cases", "CORE_ACCEPTANCE_CASES_INVALID"),
        ("plan", "CORE_ACCEPTANCE_PLAN_MISMATCH"),
        ("policy", "CORE_ACCEPTANCE_ARTIFACT_INVALID"),
        ("evidence", "CORE_ACCEPTANCE_EVIDENCE_INVALID"),
        ("bounds", "CORE_ACCEPTANCE_BOUNDS_INVALID"),
    ],
)
def test_core_manifest_rejects_incomplete_or_unbound_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
    error: str,
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    entry = next(item for item in spec["artifacts"] if item["id"] == "core-acceptance")
    payload = json.loads((artifacts / entry["path"]).read_text())
    if tamper == "spec":
        payload["spec_sha256"] = "invalid"
    elif tamper == "run":
        payload["run_id"] = f"cgacceptance:{'f' * 64}"
    elif tamper == "input":
        payload["inputs"]["run_inputs_sha256"] = "invalid"
    elif tamper == "cases":
        payload["cases"].pop()
    elif tamper == "plan":
        payload["inputs"]["terraform_plan"]["sha256"] = "f" * 64
    elif tamper == "policy":
        payload["inputs"]["policies"][0]["artifact"]["sha256"] = "invalid"
    elif tamper == "evidence":
        payload["cases"][0]["evidence"].pop()
    else:
        payload["duration_ms"] += 1
    entry["sha256"] = _write_json(artifacts / entry["path"], payload)
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match=error):
        bundle.verify_bundle(repo, spec_path, artifacts)


@pytest.mark.parametrize(
    ("tamper", "error"),
    [
        ("terraform_plan", "CLEAN_ROOM_TERRAFORM_PLAN_INVALID"),
        ("core_acceptance_manifest", "CORE_ACCEPTANCE_CASES_INVALID"),
        ("evidence_link_validation", "CLEAN_ROOM_EVIDENCE_LINKS_INVALID"),
    ],
)
def test_clean_room_validates_cited_output_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
    error: str,
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    entry = next(item for item in spec["artifacts"] if item["id"] == "clean-room")
    record = json.loads((artifacts / entry["path"]).read_text())
    reference = record["outputs"][tamper]
    output_path = artifacts / reference["path"]
    output = json.loads(output_path.read_text())
    if tamper == "terraform_plan":
        output.pop("format_version")
    elif tamper == "core_acceptance_manifest":
        output["cases"].pop()
    else:
        output["validated_claim_ids"] = []
    reference["sha256"] = _write_json(output_path, output)
    if tamper == "core_acceptance_manifest":
        links_reference = record["outputs"]["evidence_link_validation"]
        links_path = artifacts / links_reference["path"]
        links = json.loads(links_path.read_text())
        links["core_acceptance_manifest_sha256"] = reference["sha256"]
        links_reference["sha256"] = _write_json(links_path, links)
    entry["sha256"] = _write_json(artifacts / entry["path"], record)
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match=error):
        bundle.verify_bundle(repo, spec_path, artifacts)


@pytest.mark.parametrize(
    ("reuse", "error"),
    [
        ("path", "CLEAN_ROOM_OUTPUT_INVALID"),
        ("plan", "CLEAN_ROOM_OUTPUT_INVALID"),
        ("run", "CLEAN_ROOM_CORE_ACCEPTANCE_INVALID"),
    ],
)
def test_clean_room_outputs_are_distinct_from_primary_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reuse: str,
    error: str,
) -> None:
    repo, artifacts, spec_path, spec = _fixture(tmp_path, monkeypatch)
    entry = next(item for item in spec["artifacts"] if item["id"] == "clean-room")
    record = json.loads((artifacts / entry["path"]).read_text())
    if reuse == "path":
        record["outputs"]["evidence_link_validation"]["path"] = "evidence-links.json"
    elif reuse == "plan":
        plan = next(item for item in spec["artifacts"] if item["id"] == "terraform-plan")
        clean_plan = record["outputs"]["terraform_plan"]
        clean_plan["sha256"] = plan["sha256"]
        (artifacts / clean_plan["path"]).write_bytes((artifacts / plan["path"]).read_bytes())
    else:
        clean_core_reference = record["outputs"]["core_acceptance_manifest"]
        clean_core_path = artifacts / clean_core_reference["path"]
        clean_core = json.loads(clean_core_path.read_text())
        primary_entry = next(item for item in spec["artifacts"] if item["id"] == "core-acceptance")
        primary_core = json.loads((artifacts / primary_entry["path"]).read_text())
        clean_core["run_id"] = primary_core["run_id"]
        clean_core_reference["sha256"] = _write_json(clean_core_path, clean_core)
    entry["sha256"] = _write_json(artifacts / entry["path"], record)
    _write_json(spec_path, spec)

    with pytest.raises(bundle.BundleError, match=error):
        bundle.verify_bundle(repo, spec_path, artifacts)


def test_verified_tag_must_exist_on_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, artifacts, spec_path, _ = _fixture(tmp_path, monkeypatch)
    current_git = bundle._git

    def git_without_remote_tag(repository: Path, *args: str) -> str:
        if args[:3] == ("ls-remote", "--tags", "origin"):
            return ""
        return str(current_git(repository, *args))

    monkeypatch.setattr(bundle, "_git", git_without_remote_tag)

    with pytest.raises(bundle.BundleError, match="SOURCE_TAG_REMOTE_MISMATCH"):
        bundle.verify_bundle(repo, spec_path, artifacts)
