#!/usr/bin/env python3
"""Build and verify the private release supply-chain evidence bundle."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import subprocess
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import tomllib

POLICY_PATH = Path(".github/release-evidence-policy.json")
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
PUBLISHED_IMAGE_RE = re.compile(
    r"us-central1-docker\.pkg\.dev/controlgraph-canary-[a-z0-9]{6,10}/"
    r"controlgraph-canary/(?P<image>[a-z-]+)@sha256:(?P<digest>[0-9a-f]{64})"
)
ACTION_RE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*([^\s#]+)@([^\s#]+)(?:\s|#|$)", re.MULTILINE
)
FROM_RE = re.compile(r"^FROM\s+([^\s]+)", re.MULTILINE)
PROVIDER_RE = re.compile(r'provider\s+"([^"]+)"\s*\{(.*?)\n\}', re.DOTALL)
VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"', re.MULTILINE)
HASH_RE = re.compile(r'"(h1:[A-Za-z0-9+/=]+|zh:[0-9a-f]{64})"')
SPDX_LICENSE_RE = re.compile(r"^[A-Za-z0-9.+-]+$")
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_MAIN_REF = "refs/heads/main"
GITHUB_WORKFLOW_TRIGGER = "workflow_dispatch"


class EvidenceError(ValueError):
    """Release evidence is missing, malformed, or violates policy."""


def _load_json(path: Path) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read JSON evidence {path}: {error}") from error


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _policy(repo: Path) -> dict[str, Any]:
    value = _load_json(repo / POLICY_PATH)
    if not isinstance(value, dict) or value.get("schema_version") != (
        "controlgraph.release-evidence-policy/v1"
    ):
        raise EvidenceError("unsupported release evidence policy")
    return value


def _created_at(repo: Path, source_sha: str) -> str:
    value = _git(repo, "show", "-s", "--format=%cI", source_sha)
    parsed = dt.datetime.fromisoformat(value).astimezone(dt.UTC).replace(microsecond=0)
    return parsed.isoformat().replace("+00:00", "Z")


def _spdx_id(value: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", value).strip("-.")


def _purl(package_type: str, name: str, version: str) -> str:
    encoded = urllib.parse.quote(name, safe="@/._-")
    encoded_version = urllib.parse.quote(version, safe="._-+")
    return f"pkg:{package_type}/{encoded}@{encoded_version}"


def _checksum(value: str) -> dict[str, str] | None:
    for prefix in ("sha256:", "zh:"):
        if value.startswith(prefix) and SHA256_RE.fullmatch(value.removeprefix(prefix)):
            return {"algorithm": "SHA256", "checksumValue": value.removeprefix(prefix)}
    if value.startswith("sha512-"):
        try:
            decoded = base64.b64decode(
                value.removeprefix("sha512-"), validate=True
            ).hex()
        except ValueError:
            return None
        return {"algorithm": "SHA512", "checksumValue": decoded}
    return None


def _package(
    *,
    name: str,
    version: str,
    download: str,
    license_name: str,
    purl: str,
    checksum: dict[str, str] | None = None,
) -> dict[str, Any]:
    package: dict[str, Any] = {
        "SPDXID": _spdx_id(f"Package-{name}-{version}"),
        "name": name,
        "versionInfo": version,
        "downloadLocation": download or "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": (
            license_name if SPDX_LICENSE_RE.fullmatch(license_name) else "NOASSERTION"
        ),
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
    }
    if checksum is not None:
        package["checksums"] = [checksum]
    return package


def _python_packages(repo: Path) -> list[dict[str, Any]]:
    lock = tomllib.loads((repo / "backend/uv.lock").read_text(encoding="utf-8"))
    packages: list[dict[str, Any]] = []
    for item in lock.get("package", []):
        name = item.get("name")
        version = item.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise EvidenceError("uv.lock contains an unversioned package")
        source = item.get("source", {})
        download = (
            source.get("registry", "NOASSERTION")
            if isinstance(source, dict)
            else "NOASSERTION"
        )
        artifact = item.get("sdist")
        checksum = (
            _checksum(artifact.get("hash", "")) if isinstance(artifact, dict) else None
        )
        packages.append(
            _package(
                name=name,
                version=version,
                download=download,
                license_name="NOASSERTION",
                purl=_purl("pypi", name, version),
                checksum=checksum,
            )
        )
    if not packages:
        raise EvidenceError("uv.lock contains no packages")
    return packages


def _npm_packages(repo: Path) -> list[dict[str, Any]]:
    lock = _load_json(repo / "web/package-lock.json")
    if not isinstance(lock, dict) or lock.get("lockfileVersion") != 3:
        raise EvidenceError("package-lock.json must use lockfile version 3")
    packages: dict[tuple[str, str, str], dict[str, Any]] = {}
    for path, item in sorted(lock.get("packages", {}).items()):
        if not path or not isinstance(item, dict):
            continue
        name = path.rsplit("node_modules/", maxsplit=1)[-1]
        version = item.get("version")
        if not isinstance(version, str):
            raise EvidenceError(f"package-lock entry has no version: {path}")
        license_name = item.get("license", "NOASSERTION")
        integrity = str(item.get("integrity", ""))
        packages[(name, version, integrity)] = _package(
            name=name,
            version=version,
            download=str(item.get("resolved", "NOASSERTION")),
            license_name=(
                license_name if isinstance(license_name, str) else "NOASSERTION"
            ),
            purl=_purl("npm", name, version),
            checksum=_checksum(integrity),
        )
    if not packages:
        raise EvidenceError("package-lock.json contains no packages")
    return [packages[key] for key in sorted(packages)]


def _terraform_packages(repo: Path, policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    licenses = policy.get("licenses", {})
    for lock_path in sorted((repo / "infra").glob("**/.terraform.lock.hcl")):
        text = lock_path.read_text(encoding="utf-8")
        for provider, body in PROVIDER_RE.findall(text):
            version_match = VERSION_RE.search(body)
            if version_match is None:
                raise EvidenceError(
                    f"provider has no exact version in {lock_path}: {provider}"
                )
            version = version_match.group(1)
            hashes = HASH_RE.findall(body)
            checksum = next(
                (_checksum(value) for value in hashes if value.startswith("zh:")), None
            )
            license_name = licenses.get(provider, "NOASSERTION")
            found[(provider, version)] = _package(
                name=provider,
                version=version,
                download=f"https://{provider}",
                license_name=str(license_name),
                purl=_purl(
                    "terraform",
                    provider.removeprefix("registry.terraform.io/"),
                    version,
                ),
                checksum=checksum,
            )
    if not found:
        raise EvidenceError("Terraform locks contain no providers")
    return [found[key] for key in sorted(found)]


def _release_packages(repo: Path, policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    licenses = policy.get("licenses", {})
    packages: dict[tuple[str, str], dict[str, Any]] = {}
    for workflow in sorted((repo / ".github/workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for name, revision in ACTION_RE.findall(text):
            if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
                raise EvidenceError(
                    f"workflow action is not commit-pinned: {name}@{revision}"
                )
            packages[(name, revision)] = _package(
                name=name,
                version=revision,
                download=f"https://github.com/{name}",
                license_name=str(licenses.get(name, "NOASSERTION")),
                purl=_purl("github", name, revision),
                checksum={"algorithm": "SHA1", "checksumValue": revision},
            )
    for dockerfile in (repo / "backend/Dockerfile", repo / "web/Dockerfile"):
        for reference in FROM_RE.findall(dockerfile.read_text(encoding="utf-8")):
            if "@sha256:" not in reference:
                if "/" in reference or ":" in reference:
                    raise EvidenceError(
                        f"external base image is not digest-pinned: {reference}"
                    )
                continue
            name, digest = reference.split("@sha256:", maxsplit=1)
            if not SHA256_RE.fullmatch(digest):
                raise EvidenceError(f"invalid base image digest: {reference}")
            packages[(name, digest)] = _package(
                name=name,
                version=f"sha256:{digest}",
                download=f"https://hub.docker.com/_/{name.split(':', maxsplit=1)[0]}",
                license_name="NOASSERTION",
                purl=f"pkg:oci/{urllib.parse.quote(name, safe='._-')}@sha256:{digest}",
                checksum={"algorithm": "SHA256", "checksumValue": digest},
            )
    tools = policy.get("tools", {})
    for name, item in sorted(tools.items()):
        if not isinstance(item, dict):
            raise EvidenceError(f"invalid tool policy: {name}")
        version = str(item["version"])
        repository = str(item["repository"])
        packages[(name, version)] = _package(
            name=name,
            version=version,
            download=f"https://github.com/{repository}",
            license_name=str(item["license"]),
            purl=_purl("github", repository, version),
            checksum={"algorithm": "SHA256", "checksumValue": str(item["sha256"])},
        )
    if not packages:
        raise EvidenceError("release inputs contain no pinned packages")
    return [packages[key] for key in sorted(packages)]


def _source_packages(
    repo: Path, policy: Mapping[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    python = _python_packages(repo)
    return {
        "backend": python,
        "cli": python,
        "console": _npm_packages(repo),
        "terraform": _terraform_packages(repo, policy),
        "release": _release_packages(repo, policy),
    }


def _spdx_document(
    *, repo: Path, source_sha: str, subject: str, packages: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    namespace = (
        f"https://github.com/OCHOLA-EDDYPHIL/controlgraph/sbom/{source_sha}/{subject}"
    )
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        }
        for package in packages
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"controlgraph-{subject}-{source_sha[:12]}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": _created_at(repo, source_sha),
            "creators": ["Tool: controlgraph-release-evidence/1"],
        },
        "packages": list(packages),
        "relationships": relationships,
    }


def _material_paths(repo: Path, policy: Mapping[str, Any]) -> list[Path]:
    paths: set[Path] = set()
    for pattern in policy.get("material_globs", []):
        matches = [path for path in repo.glob(str(pattern)) if path.is_file()]
        if not matches:
            raise EvidenceError(f"material pattern matched no files: {pattern}")
        paths.update(matches)
    return sorted(paths)


def _validate_builder_identity(
    policy: Mapping[str, Any], builder_id: str, invocation_id: str
) -> None:
    if builder_id != f"https://github.com/{policy['workflow_ref']}":
        raise EvidenceError(
            "builder identity is outside the pinned publication workflow"
        )
    invocation_pattern = re.compile(
        rf"https://github\.com/{re.escape(str(policy['repository']))}/actions/runs/"
        r"[1-9][0-9]*/attempts/[1-9][0-9]*"
    )
    if invocation_pattern.fullmatch(invocation_id) is None:
        raise EvidenceError("invocation identity is outside the repository")


def _provenance_predicate(
    *,
    repo: Path,
    policy: Mapping[str, Any],
    source_sha: str,
    builder_id: str,
    invocation_id: str,
) -> dict[str, Any]:
    _validate_builder_identity(policy, builder_id, invocation_id)
    return {
        "buildDefinition": {
            "buildType": "https://github.com/actions/workflow",
            "externalParameters": {"sourceRevision": source_sha},
            "internalParameters": {},
            "resolvedDependencies": [
                {
                    "uri": str(path.relative_to(repo)),
                    "digest": {"sha256": _sha256(path)},
                }
                for path in _material_paths(repo, policy)
            ],
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": {"invocationId": invocation_id},
        },
    }


def _parse_images(values: Iterable[str], policy: Mapping[str, Any]) -> dict[str, str]:
    images: dict[str, str] = {}
    for value in values:
        name, separator, reference = value.partition("=")
        match = PUBLISHED_IMAGE_RE.fullmatch(reference)
        if (
            not separator
            or name in images
            or match is None
            or match.group("image") != name
        ):
            raise EvidenceError(f"invalid image binding: {value}")
        images[name] = reference
    expected = set(policy.get("image_subjects", []))
    if set(images) != expected:
        raise EvidenceError(f"image subjects must equal {sorted(expected)}")
    digests = [reference.rsplit("@", maxsplit=1)[1] for reference in images.values()]
    if len(digests) != len(set(digests)):
        raise EvidenceError("deployed image digests must be distinct")
    return dict(sorted(images.items()))


def prepare(
    repo: Path,
    output: Path,
    source_sha: str,
    image_values: Sequence[str],
    builder_id: str,
    invocation_id: str,
) -> None:
    policy = _policy(repo)
    _sigstore_paths(repo, policy)
    if (
        not GIT_SHA_RE.fullmatch(source_sha)
        or _git(repo, "rev-parse", "HEAD") != source_sha
    ):
        raise EvidenceError("source revision does not match the checked-out commit")
    if _git(repo, "status", "--porcelain=v1"):
        raise EvidenceError("source checkout is not clean")
    images = _parse_images(image_values, policy)
    output.mkdir(parents=True, exist_ok=False)
    for subject, packages in _source_packages(repo, policy).items():
        _write_json(
            output / "sboms" / f"{subject}.spdx.json",
            _spdx_document(
                repo=repo, source_sha=source_sha, subject=subject, packages=packages
            ),
        )
    _write_json(
        output / "inputs.json",
        {
            "schema_version": "controlgraph.release-inputs/v1",
            "source_sha": source_sha,
            "images": images,
        },
    )
    _write_json(
        output / "provenance.predicate.json",
        _provenance_predicate(
            repo=repo,
            policy=policy,
            source_sha=source_sha,
            builder_id=builder_id,
            invocation_id=invocation_id,
        ),
    )


def _validate_spdx(path: Path, *, expected: Mapping[str, Any] | None = None) -> None:
    value = _load_json(path)
    if not isinstance(value, dict) or value.get("spdxVersion") != "SPDX-2.3":
        raise EvidenceError(f"not an SPDX 2.3 JSON document: {path}")
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages:
        raise EvidenceError(f"SBOM has no packages: {path}")
    for package in packages:
        if not isinstance(package, dict) or not any(
            key in package for key in ("licenseDeclared", "licenseConcluded")
        ):
            raise EvidenceError(f"SBOM package has no license data: {path}")
    if expected is not None and value != expected:
        raise EvidenceError(f"source SBOM does not match current lock inputs: {path}")


def _validate_trivy(path: Path, critical: set[str]) -> None:
    value = _load_json(path)
    if not isinstance(value, dict) or not isinstance(value.get("SchemaVersion"), int):
        raise EvidenceError(f"not a Trivy JSON report: {path}")
    results = value.get("Results") or []
    if not isinstance(results, list):
        raise EvidenceError(f"invalid Trivy results: {path}")
    blocked: list[str] = []
    secret_count = 0
    for result in results:
        if not isinstance(result, dict):
            raise EvidenceError(f"invalid Trivy result entry: {path}")
        secrets = result.get("Secrets") or []
        if not isinstance(secrets, list):
            raise EvidenceError(f"invalid Trivy secret result: {path}")
        secret_count += len(secrets)
        for field in ("Vulnerabilities", "Misconfigurations", "Licenses"):
            findings = result.get(field) or []
            if not isinstance(findings, list):
                raise EvidenceError(f"invalid Trivy finding list: {path}")
            for finding in findings:
                if not isinstance(finding, dict):
                    raise EvidenceError(f"invalid Trivy finding: {path}")
                if str(finding.get("Severity", "UNKNOWN")).upper() in critical:
                    blocked.append(
                        str(
                            finding.get("VulnerabilityID")
                            or finding.get("ID")
                            or finding.get("Name")
                            or "unknown"
                        )
                    )
    if secret_count:
        raise EvidenceError(f"embedded secrets detected in {path}: {secret_count}")
    if blocked:
        raise EvidenceError(
            f"policy-critical findings in {path}: {', '.join(sorted(blocked))}"
        )


def _validate_cosign_binary(cosign: Path, policy: Mapping[str, Any]) -> None:
    tool = policy.get("tools", {}).get("cosign", {})
    if (
        not cosign.is_file()
        or not isinstance(tool, dict)
        or _sha256(cosign) != tool.get("sha256")
    ):
        raise EvidenceError("cosign verifier does not match the pinned tool digest")


def _sigstore_paths(repo: Path, policy: Mapping[str, Any]) -> tuple[Path, Path]:
    config = policy.get("sigstore", {})
    if not isinstance(config, dict):
        raise EvidenceError("Sigstore policy is malformed")
    signing_config = repo / str(config.get("signing_config", ""))
    trusted_root = repo / str(config.get("trusted_root", ""))
    if (
        not signing_config.is_file()
        or _sha256(signing_config) != config.get("signing_config_sha256")
        or not trusted_root.is_file()
        or _sha256(trusted_root) != config.get("trusted_root_sha256")
    ):
        raise EvidenceError("Sigstore trust configuration digest drift detected")
    signing = _load_json(signing_config)
    trust = _load_json(trusted_root)
    if (
        not isinstance(signing, dict)
        or signing.get("rekorTlogConfig") != {}
        or not signing.get("tsaUrls")
        or not isinstance(trust, dict)
        or trust.get("tlogs")
        or not trust.get("certificateAuthorities")
        or not trust.get("ctlogs")
        or not trust.get("timestampAuthorities")
    ):
        raise EvidenceError("Sigstore policy must use Fulcio, CT, and TSA without Rekor")
    return signing_config, trusted_root


def _verify_sigstore_bundle(
    *,
    cosign: Path,
    bundle: Path,
    digest: str,
    predicate_type: str,
    policy: Mapping[str, Any],
    source_sha: str,
    trusted_root: Path,
) -> None:
    command = [
        str(cosign),
        "verify-blob-attestation",
        "--bundle",
        str(bundle),
        "--digest",
        digest.removeprefix("sha256:"),
        "--digestAlg",
        "sha256",
        "--type",
        predicate_type,
        "--trusted-root",
        str(trusted_root),
        "--use-signed-timestamps",
        "--insecure-ignore-tlog",
        "--certificate-identity",
        f"https://github.com/{policy['workflow_ref']}",
        "--certificate-oidc-issuer",
        GITHUB_OIDC_ISSUER,
        "--certificate-github-workflow-repository",
        str(policy["repository"]),
        "--certificate-github-workflow-ref",
        GITHUB_MAIN_REF,
        "--certificate-github-workflow-sha",
        source_sha,
        "--certificate-github-workflow-trigger",
        GITHUB_WORKFLOW_TRIGGER,
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise EvidenceError(
            f"cryptographic Sigstore verification failed: {bundle.name}"
        ) from error


def _attestation_payload(path: Path) -> dict[str, Any]:
    bundle = _load_json(path)
    if not isinstance(bundle, dict):
        raise EvidenceError(f"invalid Sigstore bundle: {path}")
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
        raise EvidenceError(f"Sigstore bundle has no DSSE payload: {path}")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise EvidenceError(f"Sigstore bundle has no signature: {path}")
    try:
        payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
    except (ValueError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid DSSE payload in {path}") from error
    if not isinstance(payload, dict):
        raise EvidenceError(f"invalid attestation statement in {path}")
    return payload


def _attestation_subjects(payload: Mapping[str, Any]) -> set[tuple[str, str]]:
    subjects: set[tuple[str, str]] = set()
    for subject in payload.get("subject", []):
        if not isinstance(subject, dict) or not isinstance(subject.get("digest"), dict):
            continue
        name = subject.get("name")
        digest = subject["digest"].get("sha256")
        if isinstance(name, str) and isinstance(digest, str):
            subjects.add((name, f"sha256:{digest}"))
    return subjects


def _validate_attestations(
    *,
    output: Path,
    images: Mapping[str, str],
    policy: Mapping[str, Any],
    source_sha: str,
    cosign: Path,
    trusted_root: Path,
) -> dict[str, str]:
    attestation_paths: dict[str, str] = {}
    provenance_predicate = _load_json(output / "provenance.predicate.json")
    if not isinstance(provenance_predicate, dict):
        raise EvidenceError("release provenance predicate is malformed")
    for name, reference in images.items():
        image_name, digest = reference.rsplit("@", maxsplit=1)
        subject = {(image_name, digest)}
        sbom_path = output / f"attestations/{name}.sbom.sigstore.json"
        _verify_sigstore_bundle(
            cosign=cosign,
            bundle=sbom_path,
            digest=digest,
            predicate_type="spdxjson",
            policy=policy,
            source_sha=source_sha,
            trusted_root=trusted_root,
        )
        sbom_payload = _attestation_payload(sbom_path)
        if sbom_payload.get("predicateType") != "https://spdx.dev/Document":
            raise EvidenceError(
                f"SBOM attestation has the wrong predicate type: {name}"
            )
        if _attestation_subjects(sbom_payload) != subject:
            raise EvidenceError(f"SBOM attestation does not bind image: {name}")
        local_sbom = _load_json(output / f"sboms/image-{name}.spdx.json")
        if sbom_payload.get("predicate") != local_sbom:
            raise EvidenceError(
                f"SBOM attestation does not bind the retained SPDX document: {name}"
            )
        attestation_paths[f"{name}-sbom"] = str(sbom_path.relative_to(output))

        provenance_path = output / f"attestations/{name}.provenance.sigstore.json"
        _verify_sigstore_bundle(
            cosign=cosign,
            bundle=provenance_path,
            digest=digest,
            predicate_type="slsaprovenance1",
            policy=policy,
            source_sha=source_sha,
            trusted_root=trusted_root,
        )
        provenance_payload = _attestation_payload(provenance_path)
        if provenance_payload.get("predicateType") != "https://slsa.dev/provenance/v1":
            raise EvidenceError(
                f"image provenance has the wrong predicate type: {name}"
            )
        if _attestation_subjects(provenance_payload) != subject:
            raise EvidenceError(f"provenance attestation does not bind image: {name}")
        if provenance_payload.get("predicate") != provenance_predicate:
            raise EvidenceError(
                f"provenance attestation does not bind release inputs: {name}"
            )
        attestation_paths[f"{name}-provenance"] = str(
            provenance_path.relative_to(output)
        )
    return dict(sorted(attestation_paths.items()))


def _file_record(output: Path, path: Path) -> dict[str, str]:
    return {"path": str(path.relative_to(output)), "sha256": _sha256(path)}


def finalize(
    repo: Path,
    output: Path,
    source_sha: str,
    builder_id: str,
    invocation_id: str,
    cosign: Path,
) -> None:
    policy = _policy(repo)
    _validate_cosign_binary(cosign, policy)
    _, trusted_root = _sigstore_paths(repo, policy)
    inputs = _load_json(output / "inputs.json")
    if not isinstance(inputs, dict) or inputs.get("source_sha") != source_sha:
        raise EvidenceError("release input revision is missing or stale")
    images = inputs.get("images")
    if not isinstance(images, dict):
        raise EvidenceError("release image inputs are missing")
    images = _parse_images(
        [f"{name}={value}" for name, value in images.items()], policy
    )
    expected_provenance_predicate = _provenance_predicate(
        repo=repo,
        policy=policy,
        source_sha=source_sha,
        builder_id=builder_id,
        invocation_id=invocation_id,
    )
    if _load_json(output / "provenance.predicate.json") != (
        expected_provenance_predicate
    ):
        raise EvidenceError("release provenance predicate drift detected")

    expected_sboms = _source_packages(repo, policy)
    subjects: dict[str, dict[str, Any]] = {}
    source_scan = output / "scans/source.trivy.json"
    _validate_trivy(source_scan, set(policy["critical_severities"]))
    for name, packages in expected_sboms.items():
        path = output / f"sboms/{name}.spdx.json"
        expected = _spdx_document(
            repo=repo, source_sha=source_sha, subject=name, packages=packages
        )
        _validate_spdx(path, expected=expected)
        subjects[name] = {
            "kind": "source",
            "sbom": _file_record(output, path),
            "vulnerability_and_secret_scan": _file_record(output, source_scan),
        }
    for name, reference in images.items():
        sbom = output / f"sboms/image-{name}.spdx.json"
        scan = output / f"scans/image-{name}.trivy.json"
        _validate_spdx(sbom)
        _validate_trivy(scan, set(policy["critical_severities"]))
        subjects[f"image-{name}"] = {
            "kind": "container-image",
            "immutable_reference": reference,
            "digest": reference.rsplit("@", maxsplit=1)[1],
            "sbom": _file_record(output, sbom),
            "vulnerability_and_secret_scan": _file_record(output, scan),
        }
    attestations = _validate_attestations(
        output=output,
        images=images,
        policy=policy,
        source_sha=source_sha,
        cosign=cosign,
        trusted_root=trusted_root,
    )
    materials = [
        {
            "path": str(path.relative_to(repo)),
            "sha256": _sha256(path),
        }
        for path in _material_paths(repo, policy)
    ]
    db_metadata = output / "tooling/trivy-db.json"
    if not isinstance(_load_json(db_metadata), dict):
        raise EvidenceError("Trivy database metadata is missing")
    manifest = {
        "schema_version": "controlgraph.release-evidence/v1",
        "source": {
            "repository": f"https://github.com/{policy['repository']}",
            "revision": source_sha,
        },
        "builder": {"id": builder_id, "invocation_id": invocation_id},
        "policy": {
            "path": str(POLICY_PATH),
            "sha256": _sha256(repo / POLICY_PATH),
            "critical_severities": policy["critical_severities"],
        },
        "materials": materials,
        "tooling": {
            "cosign": policy["tools"]["cosign"],
            "trivy": {
                **policy["tools"]["trivy"],
                "database": _file_record(output, db_metadata),
            }
        },
        "subjects": dict(sorted(subjects.items())),
        "attestations": attestations,
        "runtime_security_claim": False,
    }
    _write_json(output / "manifest.json", manifest)
    _write_json(
        output / "provenance.intoto.jsonl",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": name, "digest": {"sha256": record["sbom"]["sha256"]}}
                for name, record in sorted(subjects.items())
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": expected_provenance_predicate,
        },
    )
    verify(repo, output, source_sha, cosign)


def verify(repo: Path, output: Path, source_sha: str, cosign: Path) -> None:
    policy = _policy(repo)
    _validate_cosign_binary(cosign, policy)
    _, trusted_root = _sigstore_paths(repo, policy)
    if _git(repo, "rev-parse", "HEAD") != source_sha:
        raise EvidenceError("verification source revision does not match HEAD")
    manifest = _load_json(output / "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != (
        "controlgraph.release-evidence/v1"
    ):
        raise EvidenceError("release evidence manifest is missing or unsupported")
    if manifest.get("runtime_security_claim") is not False:
        raise EvidenceError("release inventory must not claim runtime security")
    source = manifest.get("source", {})
    if source != {
        "repository": f"https://github.com/{policy['repository']}",
        "revision": source_sha,
    }:
        raise EvidenceError("release manifest source revision is stale")
    builder = manifest.get("builder", {})
    _validate_builder_identity(
        policy,
        str(builder.get("id", "")),
        str(builder.get("invocation_id", "")),
    )
    expected_provenance_predicate = _provenance_predicate(
        repo=repo,
        policy=policy,
        source_sha=source_sha,
        builder_id=str(builder["id"]),
        invocation_id=str(builder["invocation_id"]),
    )
    if _load_json(output / "provenance.predicate.json") != (
        expected_provenance_predicate
    ):
        raise EvidenceError("release provenance predicate drift detected")
    if manifest.get("policy", {}).get("sha256") != _sha256(repo / POLICY_PATH):
        raise EvidenceError("release evidence policy digest drifted")
    expected_materials = {
        str(path.relative_to(repo)): _sha256(path)
        for path in _material_paths(repo, policy)
    }
    try:
        actual_materials = {
            item["path"]: item["sha256"] for item in manifest.get("materials", [])
        }
    except (KeyError, TypeError) as error:
        raise EvidenceError("release material records are malformed") from error
    if actual_materials != expected_materials:
        raise EvidenceError("release material digest drift detected")
    subjects = manifest.get("subjects", {})
    required = set(policy["source_subjects"]) | {
        f"image-{name}" for name in policy["image_subjects"]
    }
    if not isinstance(subjects, dict) or set(subjects) != required:
        raise EvidenceError("release evidence subjects are incomplete")
    inputs = _load_json(output / "inputs.json")
    if not isinstance(inputs, dict) or inputs.get("source_sha") != source_sha:
        raise EvidenceError("release inputs are missing or stale")
    image_values = {
        name.removeprefix("image-"): record.get("immutable_reference")
        for name, record in subjects.items()
        if name.startswith("image-") and isinstance(record, dict)
    }
    images = _parse_images(
        [f"{name}={reference}" for name, reference in image_values.items()], policy
    )
    if inputs.get("images") != images:
        raise EvidenceError("release image input drift detected")
    source_scan = output / "scans/source.trivy.json"
    _validate_trivy(source_scan, set(policy["critical_severities"]))
    expected_source_sboms = _source_packages(repo, policy)
    for name, packages in expected_source_sboms.items():
        _validate_spdx(
            output / f"sboms/{name}.spdx.json",
            expected=_spdx_document(
                repo=repo,
                source_sha=source_sha,
                subject=name,
                packages=packages,
            ),
        )
    for name in images:
        _validate_spdx(output / f"sboms/image-{name}.spdx.json")
        _validate_trivy(
            output / f"scans/image-{name}.trivy.json",
            set(policy["critical_severities"]),
        )
    if manifest.get("attestations") != _validate_attestations(
        output=output,
        images=images,
        policy=policy,
        source_sha=source_sha,
        cosign=cosign,
        trusted_root=trusted_root,
    ):
        raise EvidenceError("release attestation inventory drift detected")
    for record in subjects.values():
        for evidence_name in ("sbom", "vulnerability_and_secret_scan"):
            evidence = record.get(evidence_name, {})
            path = output / str(evidence.get("path", ""))
            if not path.is_file() or evidence.get("sha256") != _sha256(path):
                raise EvidenceError(f"release evidence digest drift: {evidence_name}")
    tool = manifest.get("tooling", {}).get("trivy", {})
    expected_tool = policy["tools"]["trivy"]
    if any(tool.get(key) != value for key, value in expected_tool.items()):
        raise EvidenceError("release scanner identity drift detected")
    database = tool.get("database", {})
    database_path = output / str(database.get("path", ""))
    if not database_path.is_file() or database.get("sha256") != _sha256(database_path):
        raise EvidenceError("release scanner database evidence drift detected")
    if not isinstance(_load_json(database_path), dict):
        raise EvidenceError("release scanner database metadata is malformed")
    if manifest.get("tooling", {}).get("cosign") != policy["tools"]["cosign"]:
        raise EvidenceError("release attestation verifier identity drift detected")
    provenance = _load_json(output / "provenance.intoto.jsonl")
    if not isinstance(provenance, dict) or provenance.get("predicateType") != (
        "https://slsa.dev/provenance/v1"
    ):
        raise EvidenceError("local provenance statement is missing")
    if provenance.get("predicate") != expected_provenance_predicate:
        raise EvidenceError("local provenance statement drift detected")
    _write_json(
        output / "VERIFIED.json",
        {
            "schema_version": "controlgraph.release-evidence-verification/v1",
            "source_sha": source_sha,
            "manifest_sha256": _sha256(output / "manifest.json"),
            "verified": True,
            "runtime_security_claim": False,
        },
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--repo", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--source-sha", required=True)
    prepare_parser.add_argument("--image", action="append", default=[])
    prepare_parser.add_argument("--builder-id", required=True)
    prepare_parser.add_argument("--invocation-id", required=True)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--repo", type=Path, required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)
    finalize_parser.add_argument("--source-sha", required=True)
    finalize_parser.add_argument("--builder-id", required=True)
    finalize_parser.add_argument("--invocation-id", required=True)
    finalize_parser.add_argument("--cosign", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--repo", type=Path, required=True)
    verify_parser.add_argument("--output", type=Path, required=True)
    verify_parser.add_argument("--source-sha", required=True)
    verify_parser.add_argument("--cosign", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo = args.repo.resolve()
    output = args.output.resolve()
    try:
        if args.command == "prepare":
            prepare(
                repo,
                output,
                args.source_sha,
                args.image,
                args.builder_id,
                args.invocation_id,
            )
        elif args.command == "finalize":
            finalize(
                repo,
                output,
                args.source_sha,
                args.builder_id,
                args.invocation_id,
                args.cosign.resolve(),
            )
        else:
            verify(repo, output, args.source_sha, args.cosign.resolve())
    except (EvidenceError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"release evidence verification failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
