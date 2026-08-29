from __future__ import annotations

import gzip
import hashlib
import importlib
import json
import subprocess
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from controlgraph_canary.contracts.codec import (
    RestrictedJson,
    canonical_json_value_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.public_replay import (
    MAX_PUBLIC_REPLAY_BASE64_BYTES,
    MAX_PUBLIC_REPLAY_GZIP_BYTES,
    MAX_PUBLIC_REPLAY_JSON_BYTES,
    PublicReplayEnvelopeV1,
    PublicReplaySeedV1,
)

SCRIPTS = Path(__file__).parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
public_replay = importlib.import_module("public_replay")

CASE_KINDS = (
    "TARGET_RESET",
    "HEALTHY_PROMOTION",
    "UNHEALTHY_STABLE_RECOVERY",
    "REVOCATION_STALE_DENIAL",
    "INDEPENDENT_VERIFIER_PROBE",
    "AMBIGUITY_CLASSIFICATION",
    "TIMELINE_CONSOLE_READ",
    "BOUNDED_ADVISOR",
)
IMAGE_COMPONENTS = (
    "controller",
    "advisor",
    "console",
    "reference-stable",
    "reference-candidate",
)
TOOL_IDS = (
    "read_root_summary",
    "read_target_summary",
    "read_health_summary",
    "read_receipt_summary",
    "read_timeline_summary",
    "read_verifier_summary",
)
HOSTED_ORIGIN = "https://controlgraph-console-123456789012.us-central1.run.app"
PUBLIC_CSP = "; ".join(
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


def _sha(value: int) -> str:
    return f"{value:02x}" * 32


def _traffic(*, stable: int, candidate: int, digest: str) -> dict[str, object]:
    return {
        "candidate_percent": candidate,
        "schema_version": "controlgraph.public-replay-traffic/v1",
        "stable_percent": stable,
        "target_configuration_sha256": digest,
    }


def _seed() -> PublicReplaySeedV1:
    traffic_90 = _traffic(stable=90, candidate=10, digest=_sha(20))
    return PublicReplaySeedV1.model_validate_json(
        canonical_json_value_bytes(
            cast(
                RestrictedJson,
                {
                    "advisor": {
                        "advisor": {
                            "audit_sha256": _sha(21),
                            "authority_effect": "none",
                            "confidence_basis_points": 8500,
                            "deterministic_health_override": False,
                            "findings": (
                                {
                                    "citations": tuple(
                                        {
                                            "evidence_id": f"evidence-{kind}",
                                            "evidence_kind": kind,
                                            "schema_version": (
                                                "controlgraph.public-replay-citation/v1"
                                            ),
                                            "source_sha256": _sha(30 + index),
                                        }
                                        for index, kind in enumerate(
                                            ("receipt", "timeline", "target")
                                        )
                                    ),
                                    "schema_version": "controlgraph.public-replay-finding/v1",
                                    "statement": (
                                        "Stale work was denied and the target remained unchanged."
                                    ),
                                },
                            ),
                            "model_id": "gemini-3.5-flash",
                            "model_location": "global",
                            "operator_review_required": True,
                            "prompt_version": "controlgraph.rollout-advisor-prompt/v2",
                            "registry_sha256": _sha(22),
                            "replayed_without_model_call": True,
                            "requested_operator_action": "wait",
                            "response_sha256": _sha(23),
                            "schema_version": "controlgraph.public-replay-advisor/v1",
                            "snapshot_sha256": _sha(24),
                            "structured_output_sha256": _sha(25),
                            "tool_calls": tuple(
                                {
                                    "input_sha256": _sha(40 + index),
                                    "output_sha256": _sha(50 + index),
                                    "schema_version": ("controlgraph.public-replay-tool-call/v1"),
                                    "sequence": index + 1,
                                    "status": "succeeded",
                                    "tool_id": tool_id,
                                }
                                for index, tool_id in enumerate(TOOL_IDS)
                            ),
                            "validation": "accepted",
                        },
                        "schema_version": "controlgraph.public-replay-advisor-validated/v1",
                    },
                    "advisor_requested_at": "2026-08-24T00:00:03Z",
                    "authority": {
                        "cause": "OPERATOR_REVOCATION",
                        "new_epoch": 2,
                        "previous_epoch": 1,
                        "schema_version": "controlgraph.public-replay-authority-advanced/v1",
                        "transition_sha256": _sha(26),
                    },
                    "authority_occurred_at": "2026-08-24T00:00:00Z",
                    "denial": {
                        "current_authority_epoch": 2,
                        "outcome": "DENIED",
                        "reason_code": "EPOCH_MISMATCH",
                        "receipt_sha256": _sha(27),
                        "schema_version": "controlgraph.public-replay-stale-denial/v1",
                        "work_epoch": 1,
                    },
                    "denial_occurred_at": "2026-08-24T00:00:01Z",
                    "recovery": {
                        "outcome": "VERIFIED",
                        "receipt_sha256": _sha(28),
                        "schema_version": "controlgraph.public-replay-recovery-verified/v1",
                        "traffic": _traffic(stable=100, candidate=0, digest=_sha(29)),
                    },
                    "recovery_occurred_at": "2026-08-24T00:00:04Z",
                    "schema_version": "controlgraph.public-replay-seed/v1",
                    "timeline": {
                        "schema_version": "controlgraph.public-replay-timeline-committed/v1",
                        "timeline": {
                            "entries": tuple(
                                {
                                    "entry_sha256": _sha(60 + index),
                                    "event_type": event_type,
                                    "occurred_at": f"2026-08-24T00:00:0{index}Z",
                                    "schema_version": (
                                        "controlgraph.public-replay-timeline-entry/v1"
                                    ),
                                    "sequence": index + 1,
                                    "verification_status": (
                                        "NOT_APPLICABLE" if index == 0 else "VERIFIED"
                                    ),
                                }
                                for index, event_type in enumerate(
                                    (
                                        "AUTHORITY_EPOCH_ADVANCED",
                                        "MUTATION_DENIED",
                                        "MUTATION_APPLIED",
                                        "MODEL_ASSISTANCE_RECORDED",
                                    )
                                )
                            ),
                            "entry_count": 4,
                            "head_entry_sha256": _sha(63),
                            "head_sequence": 4,
                            "page_count": 1,
                            "page_set_sha256": _sha(64),
                            "schema_version": "controlgraph.public-replay-timeline/v1",
                        },
                    },
                    "timeline_observed_at": "2026-08-24T00:00:05Z",
                    "unchanged": {
                        "after_denial": traffic_90,
                        "before_denial": traffic_90,
                        "schema_version": "controlgraph.public-replay-target-unchanged/v1",
                    },
                    "unchanged_observed_at": "2026-08-24T00:00:02Z",
                },
            )
        )
    )


def _fixture() -> tuple[bytes, bytes]:
    run_inputs_sha256 = _sha(70)
    seed = _seed()
    seed_wrapper: dict[str, Any] = {
        "case_id": "core-case-08",
        "evidence_id": "public-replay-seed",
        "kind": "PUBLIC_REPLAY_SEED",
        "observed_at": "2026-08-24T00:00:06Z",
        "ordinal": 4,
        "run_inputs_sha256": run_inputs_sha256,
        "schema_version": "controlgraph.hosted-acceptance-observation/v1",
        "source": {
            "observation": seed.model_dump(mode="json"),
            "schema_version": ("controlgraph.hosted-evidence-public-replay-seed/v1"),
        },
    }
    seed_payload = canonical_json_value_bytes(seed_wrapper)
    cases: list[dict[str, Any]] = [
        {
            "case_id": f"core-case-{index:02d}",
            "evidence": [],
            "kind": kind,
            "sequence": index,
            "status": "PASSED",
        }
        for index, kind in enumerate(CASE_KINDS, start=1)
    ]
    cases[-1]["evidence"] = [
        {
            "artifact": {
                "artifact_id": "artifact-public-replay-seed",
                "byte_count": len(seed_payload),
                "media_type": "application/json",
                "sha256": hashlib.sha256(seed_payload).hexdigest(),
            },
            "evidence_id": "public-replay-seed",
            "kind": "PUBLIC_REPLAY_SEED",
            "observed_at": "2026-08-24T00:00:06Z",
            "projection": "PUBLIC_REDACTED",
        }
    ]
    manifest: dict[str, Any] = {
        "cases": cases,
        "completed_at": "2026-08-24T00:00:07Z",
        "evidence_binding_complete": True,
        "inputs": {
            "images": [
                {
                    "component": component,
                    "reference": (
                        "us-central1-docker.pkg.dev/controlgraph-canary-abc123/"
                        f"controlgraph-canary/{component}@sha256:{_sha(80 + index)}"
                    ),
                    "schema_version": "controlgraph.acceptance-image/v1",
                }
                for index, component in enumerate(IMAGE_COMPONENTS)
            ],
            "run_inputs_sha256": run_inputs_sha256,
            "source_commit": "a" * 40,
        },
        "run_id": f"cgacceptance:{_sha(71)}",
        "runner_mode": "EXPLICIT_HOSTED_EVIDENCE_BINDING",
        "schema_version": "controlgraph.core-acceptance-manifest/v1",
        "spec_sha256": _sha(71),
        "status": "PASSED",
    }
    return canonical_json_value_bytes(manifest), seed_payload


def _hosted_fixture() -> tuple[
    str,
    dict[str, public_replay.HostedReplayHttpResponse],
]:
    manifest, seed = _fixture()
    replay, _compressed, replay_sha256 = public_replay.build_public_replay(
        manifest_payload=manifest,
        seed_payload=seed,
    )
    page = (
        b'<!doctype html><html><head><script type="module" '
        b'src="/assets/replay-abc123.js"></script>'
        b'<link rel="modulepreload" href="/assets/jsx-runtime-def456.js">'
        b'<link rel="stylesheet" href="/assets/replay-abc123.css"></head>'
        b'<body><div id="replay-root"></div>'
        b'<script src="/replay-config.js"></script></body></html>'
    )
    common = {
        "cache-control": "no-store",
        "cross-origin-resource-policy": "same-origin",
        "x-content-type-options": "nosniff",
    }

    def response(
        path: str,
        body: bytes,
        media_type: str,
        *,
        public: bool = False,
        immutable: bool = False,
    ) -> public_replay.HostedReplayHttpResponse:
        headers = {**common, "content-type": media_type}
        if public:
            headers["content-security-policy"] = PUBLIC_CSP
        if immutable:
            headers["cache-control"] = "public, max-age=31536000, immutable"
        return public_replay.HostedReplayHttpResponse(
            url=f"{HOSTED_ORIGIN}{path}",
            status=200,
            headers=headers,
            body=body,
        )

    config = (
        "window.controlGraphPublicReplayConfig=Object.freeze("
        f'{{"available":true,"sha256":"{replay_sha256}"}});\n'
    ).encode("ascii")
    artifact_path = f"/replays/{replay_sha256}.json"
    return replay_sha256, {
        f"{HOSTED_ORIGIN}/replay": response(
            "/replay",
            page,
            "text/html; charset=utf-8",
            public=True,
        ),
        f"{HOSTED_ORIGIN}/replay-config.js": response(
            "/replay-config.js",
            config,
            "text/javascript; charset=utf-8",
            public=True,
        ),
        f"{HOSTED_ORIGIN}/assets/replay-abc123.js": response(
            "/assets/replay-abc123.js",
            b'import{j}from"./jsx-runtime-def456.js";fetch("/replays/value.json",'
            b'{credentials:"omit"});',
            "text/javascript; charset=utf-8",
        ),
        f"{HOSTED_ORIGIN}/assets/jsx-runtime-def456.js": response(
            "/assets/jsx-runtime-def456.js",
            b"export const j={};",
            "text/javascript; charset=utf-8",
        ),
        f"{HOSTED_ORIGIN}/assets/replay-abc123.css": response(
            "/assets/replay-abc123.css",
            b"body{color:#123}",
            "text/css; charset=utf-8",
        ),
        f"{HOSTED_ORIGIN}{artifact_path}": response(
            artifact_path,
            replay,
            "application/json",
            public=True,
            immutable=True,
        ),
    }


def test_builds_deterministic_bounded_replay_from_bound_observation() -> None:
    manifest, seed = _fixture()

    first = public_replay.build_public_replay(
        manifest_payload=manifest,
        seed_payload=seed,
    )
    second = public_replay.build_public_replay(
        manifest_payload=manifest,
        seed_payload=seed,
    )

    assert first == second
    replay, compressed, replay_sha256 = first
    assert gzip.decompress(compressed) == replay
    assert replay_sha256 == hashlib.sha256(replay).hexdigest()
    assert len(replay) <= MAX_PUBLIC_REPLAY_JSON_BYTES
    assert len(compressed) <= MAX_PUBLIC_REPLAY_GZIP_BYTES
    assert len(public_replay.terraform_values(compressed, replay_sha256)) > 0
    assert len(public_replay.base64.b64encode(compressed)) <= MAX_PUBLIC_REPLAY_BASE64_BYTES
    envelope = decode_contract(replay, PublicReplayEnvelopeV1)
    assert tuple(item.kind.value for item in envelope.payload.cases) == CASE_KINDS
    assert len(envelope.payload.events) == 6


def test_rejects_bare_seed_and_tampered_hosted_wrapper() -> None:
    manifest_payload, seed_payload = _fixture()
    manifest = public_replay._canonical_object(
        manifest_payload,
        code="PUBLIC_REPLAY_MANIFEST_INVALID",
    )
    bare_seed = canonical_json_value_bytes(_seed().model_dump(mode="json"))
    binding = manifest["cases"][-1]["evidence"][0]["artifact"]
    binding["byte_count"] = len(bare_seed)
    binding["sha256"] = hashlib.sha256(bare_seed).hexdigest()
    rebound_manifest = canonical_json_value_bytes(manifest)

    with pytest.raises(public_replay.PublicReplayExportError) as bare_error:
        public_replay.build_public_replay(
            manifest_payload=rebound_manifest,
            seed_payload=bare_seed,
        )
    assert bare_error.value.code == "PUBLIC_REPLAY_SEED_BINDING_INVALID"

    wrapper = public_replay._canonical_object(
        seed_payload,
        code="PUBLIC_REPLAY_SEED_BINDING_INVALID",
    )
    wrapper["ordinal"] = 3
    wrong_ordinal_seed = canonical_json_value_bytes(wrapper)
    binding["byte_count"] = len(wrong_ordinal_seed)
    binding["sha256"] = hashlib.sha256(wrong_ordinal_seed).hexdigest()
    rebound_manifest = canonical_json_value_bytes(manifest)
    with pytest.raises(public_replay.PublicReplayExportError) as ordinal_error:
        public_replay.build_public_replay(
            manifest_payload=rebound_manifest,
            seed_payload=wrong_ordinal_seed,
        )
    assert ordinal_error.value.code == "PUBLIC_REPLAY_SEED_BINDING_INVALID"

    wrapper["ordinal"] = 4
    wrapper["source"]["schema_version"] = "controlgraph.hosted-evidence-private/v1"
    tampered_seed = canonical_json_value_bytes(wrapper)
    binding["byte_count"] = len(tampered_seed)
    binding["sha256"] = hashlib.sha256(tampered_seed).hexdigest()
    rebound_manifest = canonical_json_value_bytes(manifest)
    with pytest.raises(public_replay.PublicReplayExportError) as wrapper_error:
        public_replay.build_public_replay(
            manifest_payload=rebound_manifest,
            seed_payload=tampered_seed,
        )
    assert wrapper_error.value.code == "PUBLIC_REPLAY_SEED_BINDING_INVALID"


def test_manifest_rebuild_must_match_exact_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, _seed_payload = _fixture()
    monkeypatch.setattr(
        public_replay.core_acceptance,
        "build_manifest",
        lambda **_arguments: (
            manifest + b" ",
            "cgacceptance:test",
            public_replay.core_acceptance.ResultStatus.PASSED,
        ),
    )

    with pytest.raises(public_replay.PublicReplayExportError) as caught:
        public_replay.rebuild_manifest_and_read_seed(
            manifest_payload=manifest,
            spec_path=Path("unused-spec.json"),
            artifact_root=Path("unused-artifacts"),
        )

    assert caught.value.code == "PUBLIC_REPLAY_MANIFEST_REBUILD_MISMATCH"


def test_manifest_rebuild_resolves_the_exact_bound_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_payload, seed_payload = _fixture()
    manifest = public_replay._canonical_object(
        manifest_payload,
        code="PUBLIC_REPLAY_MANIFEST_INVALID",
    )
    expected_artifact = manifest["cases"][-1]["evidence"][0]["artifact"]
    seed_binding = SimpleNamespace(
        artifact=object(),
        kind=public_replay.core_acceptance.EvidenceKind.PUBLIC_REPLAY_SEED,
        projection=public_replay.core_acceptance.EvidenceProjection.PUBLIC_REDACTED,
    )
    result = SimpleNamespace(evidence=[seed_binding])
    spec = SimpleNamespace(
        cases=[
            SimpleNamespace(
                kind=public_replay.core_acceptance.CaseKind.BOUNDED_ADVISOR,
                result=object(),
            )
        ]
    )
    calls: Iterator[tuple[bytes, dict[str, Any]]] = iter(
        ((b"case-result", {}), (seed_payload, expected_artifact))
    )
    monkeypatch.setattr(
        public_replay.core_acceptance,
        "build_manifest",
        lambda **_arguments: (
            manifest_payload,
            manifest["run_id"],
            public_replay.core_acceptance.ResultStatus.PASSED,
        ),
    )
    monkeypatch.setattr(
        public_replay.core_acceptance,
        "_load_contract",
        lambda *_arguments, **_keywords: (b"spec", spec),
    )
    monkeypatch.setattr(
        public_replay.core_acceptance,
        "_bind_artifact",
        lambda *_arguments, **_keywords: next(calls),
    )
    monkeypatch.setattr(public_replay, "decode_contract", lambda *_arguments: result)

    observed = public_replay.rebuild_manifest_and_read_seed(
        manifest_payload=manifest_payload,
        spec_path=tmp_path / "run-spec.json",
        artifact_root=tmp_path,
    )

    assert observed == seed_payload


def test_exact_source_rejects_wrong_head_and_dirty_checkout(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Replay Test"],
        check=True,
    )
    source = tmp_path / "source.txt"
    source.write_text("accepted\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "source.txt"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "accepted source",
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    public_replay.verify_exact_source(tmp_path, head)
    with pytest.raises(public_replay.PublicReplayExportError) as wrong_head:
        public_replay.verify_exact_source(tmp_path, "0" * 40)
    assert wrong_head.value.code == "PUBLIC_REPLAY_SOURCE_MISMATCH"

    source.write_text("dirty\n", encoding="utf-8")
    with pytest.raises(public_replay.PublicReplayExportError) as dirty:
        public_replay.verify_exact_source(tmp_path, head)
    assert dirty.value.code == "PUBLIC_REPLAY_SOURCE_MISMATCH"


def test_verify_hosted_replay_checks_only_bounded_credential_free_surface() -> None:
    replay_sha256, responses = _hosted_fixture()
    calls: list[tuple[str, dict[str, str], int]] = []

    def fetcher(
        url: str,
        headers: Mapping[str, str],
        maximum_bytes: int,
    ) -> public_replay.HostedReplayHttpResponse:
        calls.append((url, dict(headers), maximum_bytes))
        return responses[url]

    result = public_replay.verify_hosted_public_replay(
        origin=HOSTED_ORIGIN,
        expected_sha256=replay_sha256,
        fetcher=fetcher,
    )

    assert result.replay_sha256 == replay_sha256
    assert result.case_count == 8
    assert result.event_count == 6
    assert result.static_asset_count == 3
    assert len(calls) == 6
    assert all(url.startswith(HOSTED_ORIGIN) for url, _headers, _maximum in calls)
    assert not any("/v1/operator/" in url for url, _headers, _maximum in calls)
    assert all(
        set(headers) == {"Accept", "User-Agent"}
        and "Authorization" not in headers
        and "Cookie" not in headers
        for _url, headers, _maximum in calls
    )


@pytest.mark.parametrize(
    ("target", "replacement", "expected_code"),
    [
        (
            "/replay-config.js",
            b'window.controlGraphPublicReplayConfig=Object.freeze('
            b'{"available":true,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"});\n',
            "PUBLIC_REPLAY_HOSTED_CONFIG_INVALID",
        ),
        (
            "/assets/replay-abc123.js",
            b'fetch("/v1/operator/timeline")',
            "PUBLIC_REPLAY_HOSTED_PROTECTED_DEPENDENCY",
        ),
    ],
)
def test_verify_hosted_replay_rejects_wrong_config_or_protected_dependency(
    target: str,
    replacement: bytes,
    expected_code: str,
) -> None:
    replay_sha256, responses = _hosted_fixture()
    url = f"{HOSTED_ORIGIN}{target}"
    original = responses[url]
    responses[url] = public_replay.HostedReplayHttpResponse(
        url=original.url,
        status=original.status,
        headers=original.headers,
        body=replacement,
    )

    with pytest.raises(public_replay.PublicReplayExportError) as caught:
        public_replay.verify_hosted_public_replay(
            origin=HOSTED_ORIGIN,
            expected_sha256=replay_sha256,
            fetcher=lambda request_url, _headers, _maximum: responses[request_url],
        )

    assert caught.value.code == expected_code


def test_verify_hosted_replay_rejects_noncanonical_artifact_and_weak_headers() -> None:
    replay_sha256, responses = _hosted_fixture()
    artifact_url = f"{HOSTED_ORIGIN}/replays/{replay_sha256}.json"
    artifact = responses[artifact_url]
    malformed = artifact.body.replace(b"EPOCH_MISMATCH", b"EPOCH_MISMATCX")
    malformed_sha256 = hashlib.sha256(malformed).hexdigest()
    malformed_url = f"{HOSTED_ORIGIN}/replays/{malformed_sha256}.json"
    config_url = f"{HOSTED_ORIGIN}/replay-config.js"
    config = responses[config_url]
    responses[config_url] = public_replay.HostedReplayHttpResponse(
        url=config.url,
        status=config.status,
        headers=config.headers,
        body=(
            "window.controlGraphPublicReplayConfig=Object.freeze("
            f'{{"available":true,"sha256":"{malformed_sha256}"}});\n'
        ).encode("ascii"),
    )
    responses[malformed_url] = public_replay.HostedReplayHttpResponse(
        url=malformed_url,
        status=200,
        headers=artifact.headers,
        body=malformed,
    )

    with pytest.raises(public_replay.PublicReplayExportError) as malformed_error:
        public_replay.verify_hosted_public_replay(
            origin=HOSTED_ORIGIN,
            expected_sha256=malformed_sha256,
            fetcher=lambda request_url, _headers, _maximum: responses[request_url],
        )
    assert malformed_error.value.code == "PUBLIC_REPLAY_HOSTED_REPLAY_INVALID"

    replay_sha256, responses = _hosted_fixture()
    artifact_url = f"{HOSTED_ORIGIN}/replays/{replay_sha256}.json"
    artifact = responses[artifact_url]
    responses[artifact_url] = public_replay.HostedReplayHttpResponse(
        url=artifact.url,
        status=artifact.status,
        headers={**artifact.headers, "cache-control": "no-store"},
        body=artifact.body,
    )
    with pytest.raises(public_replay.PublicReplayExportError) as header_error:
        public_replay.verify_hosted_public_replay(
            origin=HOSTED_ORIGIN,
            expected_sha256=replay_sha256,
            fetcher=lambda request_url, _headers, _maximum: responses[request_url],
        )
    assert header_error.value.code == "PUBLIC_REPLAY_HOSTED_HEADERS_INVALID"


def test_verify_hosted_cli_emits_only_the_bounded_public_summary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    replay_sha256 = _sha(99)
    monkeypatch.setattr(
        public_replay,
        "verify_hosted_public_replay",
        lambda **_arguments: public_replay.HostedReplayVerification(
            origin=HOSTED_ORIGIN,
            replay_sha256=replay_sha256,
            source_commit="a" * 40,
            case_count=8,
            event_count=6,
            static_asset_count=3,
        ),
    )

    status = public_replay.main(
        (
            "verify-hosted",
            "--origin",
            HOSTED_ORIGIN,
            "--expected-sha256",
            replay_sha256,
        )
    )

    assert status == 0
    assert json.loads(capsys.readouterr().out) == {
        "case_count": 8,
        "event_count": 6,
        "origin": HOSTED_ORIGIN,
        "replay_sha256": replay_sha256,
        "source_commit": "a" * 40,
        "static_asset_count": 3,
        "status": "VERIFIED",
    }
