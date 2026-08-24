from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load_module() -> ModuleType:
    path = REPO / "scripts/release_evidence.py"
    spec = importlib.util.spec_from_file_location("release_evidence", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_evidence = _load_module()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _bundle(
    predicate_type: str,
    subjects: list[tuple[str, str]],
    predicate: dict[str, Any],
) -> dict[str, Any]:
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": predicate_type,
        "subject": [
            {"name": name, "digest": {"sha256": digest.removeprefix("sha256:")}}
            for name, digest in subjects
        ],
        "predicate": predicate,
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "dsseEnvelope": {"payload": payload, "signatures": [{"sig": "c2ln"}]},
    }


def test_source_inventories_cover_every_required_surface() -> None:
    policy = release_evidence._policy(REPO)
    inventories = release_evidence._source_packages(REPO, policy)

    assert set(inventories) == set(policy["source_subjects"])
    assert inventories["backend"] == inventories["cli"]
    assert any(item["name"] == "controlgraph-canary" for item in inventories["backend"])
    assert any(item["name"] == "react" for item in inventories["console"])
    assert {item["name"] for item in inventories["terraform"]} == {
        "registry.terraform.io/hashicorp/google",
        "registry.terraform.io/hashicorp/google-beta",
    }
    assert any(item["name"] == "cosign" for item in inventories["release"])
    assert all(
        item.get("licenseDeclared") and item.get("externalRefs")
        for packages in inventories.values()
        for item in packages
    )
    for packages in inventories.values():
        assert len({item["SPDXID"] for item in packages}) == len(packages)
    assert all(item.get("checksums") for item in inventories["terraform"])


def test_release_inventory_requires_pinned_actions_and_base_images(tmp_path: Path) -> None:
    policy = release_evidence._policy(REPO)
    repo = tmp_path
    (repo / ".github/workflows").mkdir(parents=True)
    (repo / "backend").mkdir()
    (repo / "web").mkdir()
    (repo / ".github/workflows/build.yml").write_text(
        "steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8"
    )
    (repo / "backend/Dockerfile").write_text(
        "FROM python:3.12@sha256:" + "1" * 64 + "\n", encoding="utf-8"
    )
    (repo / "web/Dockerfile").write_text("FROM runtime\n", encoding="utf-8")

    with pytest.raises(release_evidence.EvidenceError, match="action is not commit-pinned"):
        release_evidence._release_packages(repo, policy)

    (repo / ".github/workflows/build.yml").write_text(
        "steps:\n  - uses: actions/checkout@" + "1" * 40 + "\n", encoding="utf-8"
    )
    (repo / "backend/Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    with pytest.raises(release_evidence.EvidenceError, match="not digest-pinned"):
        release_evidence._release_packages(repo, policy)


def test_image_bindings_require_exact_subjects_and_unique_digests() -> None:
    policy = release_evidence._policy(REPO)
    names = policy["image_subjects"]
    registry = "us-central1-docker.pkg.dev/controlgraph-canary-abcdef/controlgraph-canary"
    images = [
        f"{name}={registry}/{name}@sha256:{index:064x}" for index, name in enumerate(names, 1)
    ]

    assert set(release_evidence._parse_images(images, policy)) == set(names)
    with pytest.raises(release_evidence.EvidenceError, match="subjects"):
        release_evidence._parse_images(images[:-1], policy)
    with pytest.raises(release_evidence.EvidenceError, match="distinct"):
        duplicate = images[-1].rsplit(":", 1)[0] + ":" + f"{1:064x}"
        release_evidence._parse_images([*images[:-1], duplicate], policy)


def test_prepare_accepts_an_exact_clean_git_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_sha = "a" * 40
    registry = "us-central1-docker.pkg.dev/controlgraph-canary-abcdef/controlgraph-canary"
    policy = release_evidence._policy(REPO)
    images = [
        f"{name}={registry}/{name}@sha256:{index:064x}"
        for index, name in enumerate(policy["image_subjects"], 1)
    ]

    def fake_git(_repo: Path, *args: str) -> str:
        if args == ("rev-parse", "HEAD"):
            return source_sha
        if args == ("status", "--porcelain=v1"):
            return ""
        return "2026-08-24T05:00:00+00:00"

    monkeypatch.setattr(release_evidence, "_git", fake_git)

    release_evidence.prepare(
        REPO,
        tmp_path / "evidence",
        source_sha,
        images,
        "https://github.com/OCHOLA-EDDYPHIL/controlgraph/.github/workflows/deploy.yml@refs/heads/main",
        "https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/1/attempts/1",
    )

    inputs = json.loads((tmp_path / "evidence/inputs.json").read_text())
    assert inputs["source_sha"] == source_sha


@pytest.mark.parametrize(
    ("finding_key", "finding"),
    [
        ("Vulnerabilities", {"VulnerabilityID": "CVE-SYNTHETIC", "Severity": "CRITICAL"}),
        ("Misconfigurations", {"ID": "CFG-SYNTHETIC", "Severity": "CRITICAL"}),
        ("Licenses", {"Name": "LicenseRef-Synthetic", "Severity": "CRITICAL"}),
        ("Secrets", {"RuleID": "synthetic"}),
    ],
)
def test_trivy_policy_rejects_critical_or_secret_findings(
    tmp_path: Path, finding_key: str, finding: dict[str, str]
) -> None:
    report = tmp_path / "scan.json"
    _write_json(report, {"SchemaVersion": 2, "Results": [{finding_key: [finding]}]})

    with pytest.raises(release_evidence.EvidenceError):
        release_evidence._validate_trivy(report, {"CRITICAL"})


def test_trivy_policy_accepts_noncritical_findings(tmp_path: Path) -> None:
    report = tmp_path / "scan.json"
    _write_json(
        report,
        {
            "SchemaVersion": 2,
            "Results": [
                {"Vulnerabilities": [{"VulnerabilityID": "CVE-SYNTHETIC", "Severity": "HIGH"}]}
            ],
        },
    )

    release_evidence._validate_trivy(report, {"CRITICAL"})


def test_attestations_bind_all_five_immutable_images(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    names = ["controller", "console", "advisor", "reference-stable", "reference-candidate"]
    registry = "us-central1-docker.pkg.dev/controlgraph-canary-abcdef/controlgraph-canary"
    images = {name: f"{registry}/{name}@sha256:{index:064x}" for index, name in enumerate(names, 1)}
    policy = release_evidence._policy(REPO)
    provenance_predicate = {
        "buildDefinition": {"buildType": "https://github.com/actions/workflow"},
        "runDetails": {"builder": {"id": "synthetic"}},
    }
    _write_json(tmp_path / "provenance.predicate.json", provenance_predicate)
    monkeypatch.setattr(
        release_evidence,
        "_verify_sigstore_bundle",
        lambda **_kwargs: None,
    )
    for name, reference in images.items():
        subject = [(reference.rsplit("@", 1)[0], reference.rsplit("@", 1)[1])]
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": name, "licenseDeclared": "NOASSERTION"}],
        }
        _write_json(tmp_path / f"sboms/image-{name}.spdx.json", sbom)
        _write_json(
            tmp_path / f"attestations/{name}.sbom.sigstore.json",
            _bundle(
                "https://spdx.dev/Document",
                subject,
                sbom,
            ),
        )
        _write_json(
            tmp_path / f"attestations/{name}.provenance.sigstore.json",
            _bundle(
                "https://slsa.dev/provenance/v1",
                subject,
                provenance_predicate,
            ),
        )

    paths = release_evidence._validate_attestations(
        output=tmp_path,
        images=images,
        policy=policy,
        source_sha="a" * 40,
        cosign=Path("/pinned/cosign"),
        trusted_root=REPO / ".github/sigstore-trusted-root.json",
    )

    assert set(paths) == {
        *(f"{name}-provenance" for name in names),
        *(f"{name}-sbom" for name in names),
    }

    _write_json(
        tmp_path / "sboms/image-controller.spdx.json",
        {"spdxVersion": "SPDX-2.3", "packages": [{"name": "tampered"}]},
    )
    with pytest.raises(release_evidence.EvidenceError, match="retained SPDX"):
        release_evidence._validate_attestations(
            output=tmp_path,
            images=images,
            policy=policy,
            source_sha="a" * 40,
            cosign=Path("/pinned/cosign"),
            trusted_root=REPO / ".github/sigstore-trusted-root.json",
        )


def test_fake_attestation_signature_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "fake.sigstore.json"
    _write_json(bundle, _bundle("https://spdx.dev/Document", [], {}))
    policy = release_evidence._policy(REPO)
    captured: list[str] = []

    def reject(command: list[str], **_kwargs: Any) -> None:
        captured.extend(command)
        raise release_evidence.subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(release_evidence.subprocess, "run", reject)

    with pytest.raises(release_evidence.EvidenceError, match="cryptographic"):
        release_evidence._verify_sigstore_bundle(
            cosign=Path("/pinned/cosign"),
            bundle=bundle,
            digest="sha256:" + "1" * 64,
            predicate_type="spdxjson",
            policy=policy,
            source_sha="a" * 40,
            trusted_root=REPO / ".github/sigstore-trusted-root.json",
        )

    assert "--certificate-identity" in captured
    assert "--certificate-oidc-issuer" in captured
    assert "--certificate-github-workflow-repository" in captured
    assert "--certificate-github-workflow-ref" in captured
    assert "--certificate-github-workflow-sha" in captured
    assert "--use-signed-timestamps" in captured
    assert "--insecure-ignore-tlog" in captured


def test_material_inventory_is_complete_and_unique() -> None:
    policy = release_evidence._policy(REPO)
    paths = release_evidence._material_paths(REPO, policy)

    assert len(paths) == len(set(paths))
    assert REPO / "backend/uv.lock" in paths
    assert REPO / "web/package-lock.json" in paths
    assert REPO / "infra/runtime/.terraform.lock.hcl" in paths
    assert REPO / ".github/workflows/deploy.yml" in paths
