#!/usr/bin/env python3
"""Export one bounded public replay from exact hosted acceptance evidence."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Final, cast
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import core_acceptance
from pydantic import ValidationError

from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.codec import (
    ContractError,
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.public_replay import (
    MAX_PUBLIC_REPLAY_BASE64_BYTES,
    MAX_PUBLIC_REPLAY_GZIP_BYTES,
    MAX_PUBLIC_REPLAY_JSON_BYTES,
    PUBLIC_REPLAY_CASE_V1,
    PUBLIC_REPLAY_IMAGE_V1,
    PublicReplayCaseKind,
    PublicReplayCaseV1,
    PublicReplayEnvelopeV1,
    PublicReplayImageComponent,
    PublicReplayImageV1,
    PublicReplaySeedV1,
    create_public_replay_envelope,
    create_public_replay_payload,
)

CORE_MANIFEST_SCHEMA: Final = "controlgraph.core-acceptance-manifest/v1"
PUBLIC_REPLAY_EVIDENCE_KIND: Final = "PUBLIC_REPLAY_SEED"
CORE_CASE_ORDER: Final = (
    "TARGET_RESET",
    "HEALTHY_PROMOTION",
    "UNHEALTHY_STABLE_RECOVERY",
    "REVOCATION_STALE_DENIAL",
    "INDEPENDENT_VERIFIER_PROBE",
    "AMBIGUITY_CLASSIFICATION",
    "TIMELINE_CONSOLE_READ",
    "BOUNDED_ADVISOR",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CONSOLE_ORIGIN = re.compile(
    r"^https://controlgraph-console-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)
_STATIC_ASSET = re.compile(r"^/assets/[A-Za-z0-9._-]+\.(?:css|js)$")
_STATIC_IMPORT = re.compile(
    rb'''["'](?P<path>(?:/assets/|\./)[A-Za-z0-9._-]+\.(?:css|js))["']'''
)
_PUBLIC_REPLAY_CONFIG = re.compile(
    rb'^window\.controlGraphPublicReplayConfig=Object\.freeze\('
    rb'\{"available":true,"sha256":"(?P<sha256>[0-9a-f]{64})"\}'
    rb'\);\n$'
)
_PUBLIC_REPLAY_CSP: Final = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'none'",
        "connect-src 'self'",
        "font-src 'self'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    )
)
_FORBIDDEN_STATIC_MARKERS: Final = (
    b"/v1/operator/",
    b"/operator-config.js",
    b"controlgraphoperatorconfig",
    b"x-controlgraph-authorization",
    b"x-serverless-authorization",
    b"controlgraph-api-",
    b"accounts.google.com",
)
MAX_HOSTED_REPLAY_PAGE_BYTES: Final = 16_384
MAX_HOSTED_REPLAY_CONFIG_BYTES: Final = 1_024
MAX_HOSTED_REPLAY_ASSET_BYTES: Final = 262_144
MAX_HOSTED_REPLAY_ASSET_COUNT: Final = 16
MAX_HOSTED_REPLAY_ASSET_TOTAL_BYTES: Final = 524_288
_PUBLIC_REPLAY_EVIDENCE_ORDINAL: Final = 1 + tuple(
    sorted(
        core_acceptance.REQUIRED_EVIDENCE[core_acceptance.CaseKind.BOUNDED_ADVISOR],
        key=lambda item: item.value,
    )
).index(core_acceptance.EvidenceKind.PUBLIC_REPLAY_SEED)


class PublicReplayExportError(ValueError):
    """Stable exporter failure that does not include untrusted input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class HostedReplayHttpResponse:
    """One bounded, redirect-free HTTP response used by hosted verification."""

    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class HostedReplayVerification:
    """Non-secret summary of a successfully verified hosted replay."""

    origin: str
    replay_sha256: str
    source_commit: str
    case_count: int
    event_count: int
    static_asset_count: int


type HostedReplayFetcher = Callable[
    [str, Mapping[str, str], int],
    HostedReplayHttpResponse,
]


class _DenyRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Any,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


class _ReplayHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.asset_paths: list[str] = []
        self.invalid = False
        self.replay_root = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        names = tuple(name for name, _value in attrs)
        if len(names) != len(set(names)):
            self.invalid = True
            return
        values = dict(attrs)
        if values.get("id") == "replay-root":
            self.replay_root = True
        if tag == "script":
            source = values.get("src")
            if source is None:
                self.invalid = True
            else:
                self.asset_paths.append(source)
        elif tag == "link" and values.get("rel") in {
            "modulepreload",
            "preload",
            "stylesheet",
        }:
            reference = values.get("href")
            if reference is None:
                self.invalid = True
            else:
                self.asset_paths.append(reference)
        elif tag in {"base", "form", "iframe"}:
            self.invalid = True


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _reject_float(_value: str) -> None:
    raise ValueError("float denied")


def _canonical_object(payload: bytes, *, code: str) -> dict[str, Any]:
    if not payload or len(payload) > MAX_PUBLIC_REPLAY_JSON_BYTES:
        raise PublicReplayExportError(code)
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
        if type(value) is not dict or canonical_json_value_bytes(
            cast(RestrictedJson, value)
        ) != payload:
            raise ValueError("not canonical")
    except (ContractError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise PublicReplayExportError(code) from error
    return cast(dict[str, Any], value)


def _read_regular_file(path: Path, *, maximum: int, code: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PublicReplayExportError(code) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise PublicReplayExportError(code)
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, min(65_536, maximum + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise PublicReplayExportError(code)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or size != before.st_size
        ):
            raise PublicReplayExportError(code)
        return b"".join(chunks)
    except OSError as error:
        raise PublicReplayExportError(code) from error
    finally:
        os.close(descriptor)


def _object(value: object, code: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise PublicReplayExportError(code)
    return cast(dict[str, Any], value)


def _validate_manifest(payload: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _canonical_object(payload, code="PUBLIC_REPLAY_MANIFEST_INVALID")
    inputs = _object(manifest.get("inputs"), "PUBLIC_REPLAY_MANIFEST_INVALID")
    source_commit = inputs.get("source_commit")
    spec_sha256 = manifest.get("spec_sha256")
    run_id = manifest.get("run_id")
    if (
        manifest.get("schema_version") != CORE_MANIFEST_SCHEMA
        or manifest.get("status") != "PASSED"
        or manifest.get("evidence_binding_complete") is not True
        or manifest.get("runner_mode") != "EXPLICIT_HOSTED_EVIDENCE_BINDING"
        or not isinstance(source_commit, str)
        or _COMMIT.fullmatch(source_commit) is None
        or not isinstance(spec_sha256, str)
        or _SHA256.fullmatch(spec_sha256) is None
        or run_id != f"cgacceptance:{spec_sha256}"
        or not isinstance(manifest.get("completed_at"), str)
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_MANIFEST_INVALID")

    cases = manifest.get("cases")
    if (
        not isinstance(cases, list)
        or len(cases) != len(CORE_CASE_ORDER)
        or tuple(
            item.get("kind") if isinstance(item, dict) else None for item in cases
        )
        != CORE_CASE_ORDER
        or any(
            not isinstance(item, dict)
            or item.get("sequence") != sequence
            or item.get("status") != "PASSED"
            for sequence, item in enumerate(cases, start=1)
        )
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_MANIFEST_INVALID")

    images = inputs.get("images")
    if not isinstance(images, list) or len(images) != len(PublicReplayImageComponent):
        raise PublicReplayExportError("PUBLIC_REPLAY_MANIFEST_INVALID")
    expected_components = tuple(item.value for item in PublicReplayImageComponent)
    if tuple(
        item.get("component") if isinstance(item, dict) else None for item in images
    ) != expected_components:
        raise PublicReplayExportError("PUBLIC_REPLAY_MANIFEST_INVALID")

    advisor_case = cast(dict[str, Any], cases[-1])
    evidence = advisor_case.get("evidence")
    if not isinstance(evidence, list):
        raise PublicReplayExportError("PUBLIC_REPLAY_MANIFEST_INVALID")
    candidates = [
        item
        for item in evidence
        if isinstance(item, dict) and item.get("kind") == PUBLIC_REPLAY_EVIDENCE_KIND
    ]
    if len(candidates) != 1:
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID")
    binding = cast(dict[str, Any], candidates[0])
    artifact = _object(binding.get("artifact"), "PUBLIC_REPLAY_SEED_BINDING_INVALID")
    if (
        binding.get("projection") != "PUBLIC_REDACTED"
        or artifact.get("media_type") != "application/json"
        or not isinstance(artifact.get("sha256"), str)
        or _SHA256.fullmatch(artifact["sha256"]) is None
        or type(artifact.get("byte_count")) is not int
        or not 0 < artifact["byte_count"] <= MAX_PUBLIC_REPLAY_JSON_BYTES
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID")
    return manifest, binding


def _decode_bound_seed(
    *,
    manifest: dict[str, Any],
    binding: dict[str, Any],
    seed_payload: bytes,
) -> PublicReplaySeedV1:
    """Validate the hosted observation wrapper before decoding its public projection."""

    artifact = _object(binding.get("artifact"), "PUBLIC_REPLAY_SEED_BINDING_INVALID")
    if (
        len(seed_payload) != artifact["byte_count"]
        or hashlib.sha256(seed_payload).hexdigest() != artifact["sha256"]
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID")
    observation = _canonical_object(
        seed_payload,
        code="PUBLIC_REPLAY_SEED_BINDING_INVALID",
    )
    inputs = _object(manifest.get("inputs"), "PUBLIC_REPLAY_MANIFEST_INVALID")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases or not isinstance(cases[-1], dict):
        raise PublicReplayExportError("PUBLIC_REPLAY_MANIFEST_INVALID")
    advisor_case = cast(dict[str, Any], cases[-1])
    if (
        set(observation)
        != {
            "case_id",
            "evidence_id",
            "kind",
            "observed_at",
            "ordinal",
            "run_inputs_sha256",
            "schema_version",
            "source",
        }
        or observation.get("schema_version")
        != "controlgraph.hosted-acceptance-observation/v1"
        or observation.get("case_id") != advisor_case.get("case_id")
        or observation.get("evidence_id") != binding.get("evidence_id")
        or observation.get("kind") != PUBLIC_REPLAY_EVIDENCE_KIND
        or observation.get("observed_at") != binding.get("observed_at")
        or observation.get("run_inputs_sha256") != inputs.get("run_inputs_sha256")
        or observation.get("ordinal") != _PUBLIC_REPLAY_EVIDENCE_ORDINAL
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID")
    source = _object(
        observation.get("source"),
        "PUBLIC_REPLAY_SEED_BINDING_INVALID",
    )
    if (
        set(source) != {"observation", "schema_version"}
        or source.get("schema_version")
        != "controlgraph.hosted-evidence-public-replay-seed/v1"
        or type(source.get("observation")) is not dict
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID")
    try:
        projected = canonical_json_value_bytes(
            cast(RestrictedJson, source["observation"])
        )
        return decode_contract(projected, PublicReplaySeedV1)
    except (ContractError, TypeError, ValueError, ValidationError) as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_INVALID") from error


def rebuild_manifest_and_read_seed(
    *,
    manifest_payload: bytes,
    spec_path: Path,
    artifact_root: Path,
) -> bytes:
    """Rebuild the canonical core manifest and resolve its one bound public seed."""

    try:
        rebuilt, _run_id, status = core_acceptance.build_manifest(
            spec_path=spec_path,
            artifact_root=artifact_root,
        )
    except core_acceptance.AcceptanceError as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_MANIFEST_REBUILD_FAILED") from error
    if status is not core_acceptance.ResultStatus.PASSED or rebuilt != manifest_payload:
        raise PublicReplayExportError("PUBLIC_REPLAY_MANIFEST_REBUILD_MISMATCH")
    _manifest, expected_binding = _validate_manifest(rebuilt)
    expected_seed = _object(
        expected_binding.get("artifact"),
        "PUBLIC_REPLAY_SEED_BINDING_INVALID",
    )
    try:
        _spec_payload, spec = core_acceptance._load_contract(
            spec_path,
            core_acceptance.CoreAcceptanceRunSpecV1,
            error_code="PUBLIC_REPLAY_SPEC_INVALID",
        )
        if spec.cases[-1].kind is not core_acceptance.CaseKind.BOUNDED_ADVISOR:
            raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID")
        result_payload, _result_artifact = core_acceptance._bind_artifact(
            spec.cases[-1].result,
            artifact_root=artifact_root.resolve(strict=True),
            maximum_bytes=MAX_CONTRACT_BYTES,
        )
        result = decode_contract(result_payload, core_acceptance.CoreAcceptanceCaseResultV1)
        seeds = [
            item
            for item in result.evidence
            if item.kind is core_acceptance.EvidenceKind.PUBLIC_REPLAY_SEED
        ]
        if (
            len(seeds) != 1
            or seeds[0].projection
            is not core_acceptance.EvidenceProjection.PUBLIC_REDACTED
        ):
            raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID")
        seed_payload, seed_artifact = core_acceptance._bind_artifact(
            seeds[0].artifact,
            artifact_root=artifact_root.resolve(strict=True),
            maximum_bytes=MAX_PUBLIC_REPLAY_JSON_BYTES,
        )
    except (
        core_acceptance.AcceptanceError,
        ContractError,
        OSError,
        TypeError,
        ValueError,
        ValidationError,
    ) as error:
        if isinstance(error, PublicReplayExportError):
            raise
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID") from error
    if seed_artifact != expected_seed:
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_BINDING_INVALID")
    return seed_payload


def build_public_replay(
    *,
    manifest_payload: bytes,
    seed_payload: bytes,
) -> tuple[bytes, bytes, str]:
    """Validate accepted inputs and return canonical JSON, deterministic gzip, and SHA-256."""

    manifest, seed_binding = _validate_manifest(manifest_payload)
    try:
        seed = _decode_bound_seed(
            manifest=manifest,
            binding=seed_binding,
            seed_payload=seed_payload,
        )
        inputs = _object(manifest["inputs"], "PUBLIC_REPLAY_MANIFEST_INVALID")
        raw_images = cast(list[dict[str, Any]], inputs["images"])
        images = tuple(
            PublicReplayImageV1(
                schema_version=PUBLIC_REPLAY_IMAGE_V1,
                component=PublicReplayImageComponent(item["component"]),
                reference=item["reference"],
            )
            for item in raw_images
        )
        raw_cases = cast(list[dict[str, Any]], manifest["cases"])
        cases = tuple(
            PublicReplayCaseV1(
                schema_version=PUBLIC_REPLAY_CASE_V1,
                sequence=cast(int, item["sequence"]),
                kind=PublicReplayCaseKind(cast(str, item["kind"])),
                case_sha256=hashlib.sha256(
                    canonical_json_value_bytes(cast(RestrictedJson, item))
                ).hexdigest(),
            )
            for item in raw_cases
        )
        payload = create_public_replay_payload(
            source_commit=cast(str, inputs["source_commit"]),
            acceptance_manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
            acceptance_run_id=cast(str, manifest["run_id"]),
            accepted_at=cast(str, manifest["completed_at"]),
            images=images,
            cases=cases,
            seed=seed,
        )
        replay_payload = canonical_json_bytes(create_public_replay_envelope(payload))
    except (ContractError, KeyError, TypeError, ValueError, ValidationError) as error:
        if isinstance(error, PublicReplayExportError):
            raise
        raise PublicReplayExportError("PUBLIC_REPLAY_SEED_INVALID") from error
    if len(replay_payload) > MAX_PUBLIC_REPLAY_JSON_BYTES:
        raise PublicReplayExportError("PUBLIC_REPLAY_JSON_TOO_LARGE")
    compressed = gzip.compress(replay_payload, compresslevel=9, mtime=0)
    if not compressed or len(compressed) > MAX_PUBLIC_REPLAY_GZIP_BYTES:
        raise PublicReplayExportError("PUBLIC_REPLAY_GZIP_TOO_LARGE")
    encoded = base64.b64encode(compressed)
    if len(encoded) > MAX_PUBLIC_REPLAY_BASE64_BYTES:
        raise PublicReplayExportError("PUBLIC_REPLAY_BASE64_TOO_LARGE")
    return replay_payload, compressed, hashlib.sha256(replay_payload).hexdigest()


def _git(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_SOURCE_INVALID") from error
    if result.returncode != 0:
        raise PublicReplayExportError("PUBLIC_REPLAY_SOURCE_INVALID")
    return result.stdout.strip()


def verify_exact_source(repo: Path, source_commit: str) -> None:
    """Require the manifest source to be the exact clean exporter checkout."""

    try:
        root = repo.resolve(strict=True)
    except OSError as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_SOURCE_INVALID") from error
    if (
        not root.is_dir()
        or Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root
        or _git(root, "rev-parse", "HEAD") != source_commit
        or _git(root, "status", "--porcelain=v1")
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_SOURCE_MISMATCH")


def terraform_values(compressed: bytes, replay_sha256: str) -> bytes:
    """Render the two paired, non-secret runtime values as deterministic HCL."""

    encoded = base64.b64encode(compressed).decode("ascii")
    if (
        not compressed
        or len(compressed) > MAX_PUBLIC_REPLAY_GZIP_BYTES
        or len(encoded) > MAX_PUBLIC_REPLAY_BASE64_BYTES
        or _SHA256.fullmatch(replay_sha256) is None
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_TFVARS_INVALID")
    return (
        f"public_replay_gzip_base64 = {json.dumps(encoded)}\n"
        f"public_replay_sha256 = {json.dumps(replay_sha256)}\n"
    ).encode("ascii")


def _outside_repo(path: Path, repo: Path) -> Path:
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_OUTPUT_INVALID") from error
    candidate = parent / path.name
    if (
        not parent.is_dir()
        or parent.is_relative_to(repo)
        or candidate.exists()
        or candidate.is_symlink()
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_OUTPUT_INVALID")
    return candidate


def _write_once(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        with suppress(OSError):
            path.unlink(missing_ok=True)
        raise PublicReplayExportError("PUBLIC_REPLAY_OUTPUT_INVALID") from error


def export_public_replay(
    *,
    repo: Path,
    manifest_path: Path,
    spec_path: Path,
    artifact_root: Path,
    output_directory: Path,
    tfvars_output: Path,
) -> tuple[Path, str]:
    """Verify exact source and write only untracked deployment inputs outside the repository."""

    manifest_payload = _read_regular_file(
        manifest_path,
        maximum=MAX_PUBLIC_REPLAY_JSON_BYTES,
        code="PUBLIC_REPLAY_MANIFEST_INVALID",
    )
    manifest, _artifact = _validate_manifest(manifest_payload)
    inputs = _object(manifest["inputs"], "PUBLIC_REPLAY_MANIFEST_INVALID")
    verify_exact_source(repo, cast(str, inputs["source_commit"]))
    seed_payload = rebuild_manifest_and_read_seed(
        manifest_payload=manifest_payload,
        spec_path=spec_path,
        artifact_root=artifact_root,
    )
    replay, compressed, replay_sha256 = build_public_replay(
        manifest_payload=manifest_payload,
        seed_payload=seed_payload,
    )
    try:
        output_root = output_directory.resolve(strict=True)
    except OSError as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_OUTPUT_INVALID") from error
    exact_repo = repo.resolve(strict=True)
    if not output_root.is_dir() or output_root.is_relative_to(exact_repo):
        raise PublicReplayExportError("PUBLIC_REPLAY_OUTPUT_INVALID")
    output = _outside_repo(output_root / f"{replay_sha256}.json", exact_repo)
    tfvars = _outside_repo(tfvars_output, exact_repo)
    if output == tfvars:
        raise PublicReplayExportError("PUBLIC_REPLAY_OUTPUT_INVALID")
    _write_once(output, replay)
    try:
        _write_once(tfvars, terraform_values(compressed, replay_sha256))
    except PublicReplayExportError:
        with suppress(OSError):
            output.unlink(missing_ok=True)
        raise
    return output, replay_sha256


def _hosted_request_headers(accept: str) -> Mapping[str, str]:
    return {
        "Accept": accept,
        "User-Agent": "controlgraph-public-replay-verifier/1",
    }


def _fetch_hosted_replay(
    url: str,
    headers: Mapping[str, str],
    maximum_bytes: int,
) -> HostedReplayHttpResponse:
    """Fetch once over HTTPS without redirects, ambient credentials, or unbounded reads."""

    if (
        not url.startswith("https://")
        or set(headers) != {"Accept", "User-Agent"}
        or not 0 < maximum_bytes <= MAX_HOSTED_REPLAY_ASSET_BYTES
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_REQUEST_INVALID")
    request = Request(url, headers=dict(headers), method="GET")
    try:
        with build_opener(ProxyHandler({}), _DenyRedirects).open(
            request,
            timeout=10,
        ) as response:
            content_lengths = response.headers.get_all("Content-Length", [])
            content_length: int | None = None
            if len(content_lengths) > 1:
                raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_RESPONSE_INVALID")
            if content_lengths:
                try:
                    content_length = int(content_lengths[0], 10)
                except ValueError as error:
                    raise PublicReplayExportError(
                        "PUBLIC_REPLAY_HOSTED_RESPONSE_INVALID"
                    ) from error
                if content_length < 1 or content_length > maximum_bytes:
                    raise PublicReplayExportError(
                        "PUBLIC_REPLAY_HOSTED_RESPONSE_INVALID"
                    )
            body = response.read(maximum_bytes + 1)
            selected_headers: dict[str, str] = {}
            for name in (
                "Cache-Control",
                "Content-Encoding",
                "Content-Security-Policy",
                "Content-Type",
                "Cross-Origin-Resource-Policy",
                "X-Content-Type-Options",
            ):
                values = response.headers.get_all(name, [])
                if len(values) > 1:
                    raise PublicReplayExportError(
                        "PUBLIC_REPLAY_HOSTED_RESPONSE_INVALID"
                    )
                if values:
                    selected_headers[name.lower()] = values[0]
            if content_length is not None and len(body) != content_length:
                raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_RESPONSE_INVALID")
            return HostedReplayHttpResponse(
                url=response.geturl(),
                status=response.status,
                headers=selected_headers,
                body=body,
            )
    except PublicReplayExportError:
        raise
    except (HTTPError, OSError, TimeoutError, URLError, ValueError) as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_REQUEST_FAILED") from error


def _response_header(response: HostedReplayHttpResponse, name: str) -> str:
    value = response.headers.get(name.lower())
    if type(value) is not str:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_RESPONSE_INVALID")
    return value


def _validate_hosted_response(
    response: HostedReplayHttpResponse,
    *,
    expected_url: str,
    expected_media_type: str,
    maximum_bytes: int,
) -> None:
    if (
        response.url != expected_url
        or response.status != 200
        or type(response.body) is not bytes
        or not 0 < len(response.body) <= maximum_bytes
        or _response_header(response, "content-type").split(";", 1)[0].strip().lower()
        != expected_media_type
        or response.headers.get("content-encoding", "identity").lower() != "identity"
        or _response_header(response, "x-content-type-options").lower() != "nosniff"
        or _response_header(response, "cross-origin-resource-policy").lower()
        != "same-origin"
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_RESPONSE_INVALID")


def _validate_public_headers(
    response: HostedReplayHttpResponse,
    *,
    immutable: bool,
) -> None:
    expected_cache = "public, max-age=31536000, immutable" if immutable else "no-store"
    if (
        _response_header(response, "content-security-policy") != _PUBLIC_REPLAY_CSP
        or _response_header(response, "cache-control") != expected_cache
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_HEADERS_INVALID")


def _safe_static_path(value: str) -> str:
    if value == "/replay-config.js" or _STATIC_ASSET.fullmatch(value) is not None:
        return value
    raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_ASSET_INVALID")


def _static_import_path(owner: str, reference: bytes) -> str:
    try:
        decoded = reference.decode("ascii")
    except UnicodeDecodeError as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_ASSET_INVALID") from error
    if decoded.startswith("./") and owner.startswith("/assets/"):
        decoded = f"/assets/{decoded[2:]}"
    return _safe_static_path(decoded)


def _validate_static_body(payload: bytes) -> None:
    lowered = payload.lower()
    if any(marker in lowered for marker in _FORBIDDEN_STATIC_MARKERS):
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_PROTECTED_DEPENDENCY")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_ASSET_INVALID") from error
    if text.startswith("\ufeff") or "\x00" in text:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_ASSET_INVALID")


def _replay_asset_paths(page: bytes) -> tuple[str, ...]:
    _validate_static_body(page)
    try:
        parser = _ReplayHtmlParser()
        parser.feed(page.decode("utf-8"))
        parser.close()
    except (UnicodeError, ValueError) as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_PAGE_INVALID") from error
    if parser.invalid or not parser.replay_root:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_PAGE_INVALID")
    try:
        paths = tuple(_safe_static_path(item) for item in parser.asset_paths)
    except PublicReplayExportError as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_PAGE_INVALID") from error
    if (
        paths.count("/replay-config.js") != 1
        or not any(path.endswith(".js") and path != "/replay-config.js" for path in paths)
        or len(paths) != len(set(paths))
        or len(paths) > MAX_HOSTED_REPLAY_ASSET_COUNT
    ):
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_PAGE_INVALID")
    return paths


def verify_hosted_public_replay(
    *,
    origin: str,
    expected_sha256: str,
    fetcher: HostedReplayFetcher = _fetch_hosted_replay,
) -> HostedReplayVerification:
    """Verify the deployed credential-free replay without calling a protected API."""

    if _CONSOLE_ORIGIN.fullmatch(origin) is None or _SHA256.fullmatch(expected_sha256) is None:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_INPUT_INVALID")

    page_url = f"{origin}/replay"
    page = fetcher(
        page_url,
        _hosted_request_headers("text/html"),
        MAX_HOSTED_REPLAY_PAGE_BYTES,
    )
    _validate_hosted_response(
        page,
        expected_url=page_url,
        expected_media_type="text/html",
        maximum_bytes=MAX_HOSTED_REPLAY_PAGE_BYTES,
    )
    _validate_public_headers(page, immutable=False)
    asset_paths = _replay_asset_paths(page.body)

    config_url = f"{origin}/replay-config.js"
    config = fetcher(
        config_url,
        _hosted_request_headers("text/javascript"),
        MAX_HOSTED_REPLAY_CONFIG_BYTES,
    )
    _validate_hosted_response(
        config,
        expected_url=config_url,
        expected_media_type="text/javascript",
        maximum_bytes=MAX_HOSTED_REPLAY_CONFIG_BYTES,
    )
    _validate_public_headers(config, immutable=False)
    _validate_static_body(config.body)
    match = _PUBLIC_REPLAY_CONFIG.fullmatch(config.body)
    if match is None or match.group("sha256").decode("ascii") != expected_sha256:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_CONFIG_INVALID")

    pending = [path for path in asset_paths if path != "/replay-config.js"]
    observed: set[str] = set()
    total_bytes = 0
    while pending:
        path = pending.pop(0)
        if path in observed:
            continue
        if len(observed) >= MAX_HOSTED_REPLAY_ASSET_COUNT:
            raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_ASSET_INVALID")
        media_type = "text/javascript" if path.endswith(".js") else "text/css"
        url = f"{origin}{path}"
        asset = fetcher(
            url,
            _hosted_request_headers(media_type),
            MAX_HOSTED_REPLAY_ASSET_BYTES,
        )
        _validate_hosted_response(
            asset,
            expected_url=url,
            expected_media_type=media_type,
            maximum_bytes=MAX_HOSTED_REPLAY_ASSET_BYTES,
        )
        _validate_static_body(asset.body)
        total_bytes += len(asset.body)
        if total_bytes > MAX_HOSTED_REPLAY_ASSET_TOTAL_BYTES:
            raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_ASSET_INVALID")
        observed.add(path)
        for nested in _STATIC_IMPORT.finditer(asset.body):
            nested_path = _static_import_path(path, nested.group("path"))
            if nested_path != "/replay-config.js" and nested_path not in observed:
                pending.append(nested_path)

    artifact_url = f"{origin}/replays/{expected_sha256}.json"
    artifact = fetcher(
        artifact_url,
        _hosted_request_headers("application/json"),
        MAX_PUBLIC_REPLAY_JSON_BYTES,
    )
    _validate_hosted_response(
        artifact,
        expected_url=artifact_url,
        expected_media_type="application/json",
        maximum_bytes=MAX_PUBLIC_REPLAY_JSON_BYTES,
    )
    _validate_public_headers(artifact, immutable=True)
    if hashlib.sha256(artifact.body).hexdigest() != expected_sha256:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_DIGEST_MISMATCH")
    try:
        envelope = decode_contract(artifact.body, PublicReplayEnvelopeV1)
    except (ContractError, TypeError, ValueError, ValidationError) as error:
        raise PublicReplayExportError("PUBLIC_REPLAY_HOSTED_REPLAY_INVALID") from error
    return HostedReplayVerification(
        origin=origin,
        replay_sha256=expected_sha256,
        source_commit=envelope.payload.source_commit,
        case_count=len(envelope.payload.cases),
        event_count=len(envelope.payload.events),
        static_asset_count=len(observed),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build or verify one public replay.")
    commands = parser.add_subparsers(dest="command", required=True)
    export_parser = commands.add_parser(
        "export",
        help="export from exact hosted acceptance evidence",
    )
    export_parser.add_argument("--repo", required=True, type=Path)
    export_parser.add_argument("--manifest", required=True, type=Path)
    export_parser.add_argument("--spec", required=True, type=Path)
    export_parser.add_argument("--artifact-root", required=True, type=Path)
    export_parser.add_argument("--output-directory", required=True, type=Path)
    export_parser.add_argument("--tfvars-output", required=True, type=Path)
    verify_parser = commands.add_parser(
        "verify-hosted",
        help="verify the deployed credential-free replay surface",
    )
    verify_parser.add_argument("--origin", required=True)
    verify_parser.add_argument("--expected-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0].startswith("-") and arguments[0] not in {"-h", "--help"}:
        arguments.insert(0, "export")
    args = _parser().parse_args(arguments)
    try:
        if args.command == "verify-hosted":
            verification = verify_hosted_public_replay(
                origin=cast(str, args.origin),
                expected_sha256=cast(str, args.expected_sha256),
            )
        else:
            output, replay_sha256 = export_public_replay(
                repo=args.repo,
                manifest_path=args.manifest,
                spec_path=args.spec,
                artifact_root=args.artifact_root,
                output_directory=args.output_directory,
                tfvars_output=args.tfvars_output,
            )
    except PublicReplayExportError as error:
        print(json.dumps({"code": error.code}, separators=(",", ":")), file=sys.stderr)
        return 2
    if args.command == "verify-hosted":
        print(
            json.dumps(
                {
                    "case_count": verification.case_count,
                    "event_count": verification.event_count,
                    "origin": verification.origin,
                    "replay_sha256": verification.replay_sha256,
                    "source_commit": verification.source_commit,
                    "static_asset_count": verification.static_asset_count,
                    "status": "VERIFIED",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    print(
        json.dumps(
            {
                "path": output.name,
                "replay_sha256": replay_sha256,
                "status": "EXPORTED",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
