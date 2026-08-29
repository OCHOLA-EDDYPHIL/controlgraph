from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]


def _text(path: str) -> str:
    return (REPOSITORY_ROOT / path).read_text(encoding="utf-8")


def test_public_replay_uses_only_paired_bounded_console_environment_values() -> None:
    variables = _text("infra/runtime/variables.tf")
    services = _text("infra/runtime/services.tf")

    assert 'variable "public_replay_gzip_base64"' in variables
    assert 'length(var.public_replay_gzip_base64) <= 24576' in variables
    assert 'length(var.public_replay_gzip_base64) % 4 == 0' in variables
    assert 'variable "public_replay_sha256"' in variables
    assert (
        '(var.public_replay_gzip_base64 == "") == '
        '(var.public_replay_sha256 == "")'
    ) in variables
    assert 'var.public_replay_sha256 == "" ? {} : {' in services
    assert services.count("CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64") == 1
    assert services.count("CONTROLGRAPH_PUBLIC_REPLAY_SHA256") == 1
    assert "public_replay" not in _text("infra/runtime/iam.tf")


def test_public_replay_does_not_add_a_service_or_secret_binding() -> None:
    services = _text("infra/runtime/services.tf")
    console = re.search(
        r'module "console" \{(?P<body>.*?)\n\}',
        services,
        flags=re.DOTALL,
    )

    assert console is not None
    body = console.group("body")
    assert "CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64" in body
    assert "CONTROLGRAPH_PUBLIC_REPLAY_SHA256" in body
    assert "secret" not in body.lower()
    assert 'module "public_replay"' not in services


def test_console_image_build_includes_the_separate_replay_entry() -> None:
    dockerfile = _text("web/Dockerfile")
    vite = _text("web/vite.config.ts")
    replay_html = _text("web/replay.html")

    assert "COPY index.html replay.html" in dockerfile
    assert 'replay: resolve(import.meta.dirname, "replay.html")' in vite
    assert 'src="/replay-config.js"' in replay_html
    assert "operator-config" not in replay_html
    assert "accounts.google.com" not in replay_html
