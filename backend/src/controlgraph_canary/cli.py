"""Command-line entry point for local validation and service startup."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections.abc import Sequence
from typing import Any, Protocol

from controlgraph_canary.authority import EpochFence, EpochMismatchError
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_COMMAND_V1,
    EpochRevocationCommandV1,
    EpochRevocationResultV1,
)
from controlgraph_canary.integrations.google.internal_transport import (
    InternalHttpResponse,
    OneShotHttpPoster,
    UrllibOneShotHttpPoster,
)
from controlgraph_canary.settings import ControllerSettings, required_environment_keys

_PROJECT_NUMBER = re.compile(r"^[1-9][0-9]{5,31}$")
_IDENTITY_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{16,16384}$")
_HTTP_TIMEOUT_SECONDS = 10.0


class IdentityTokenCommandRunner(Protocol):
    """Run one fixed shell-free identity-token command."""

    def __call__(
        self,
        argv: Sequence[str],
        *,
        capture_output: bool,
        text: bool,
        check: bool,
        timeout: float,
        shell: bool,
    ) -> subprocess.CompletedProcess[str]: ...


def _doctor_report(environment: dict[str, str]) -> dict[str, Any]:
    missing = [
        key
        for key in required_environment_keys(environment)
        if not environment.get(key, "").strip()
    ]
    return {
        "configured": not missing,
        "missing": missing,
        "cloud_calls_performed": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlgraph-canary",
        description="Local tools for the ControlGraph Canary scaffold.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("doctor", help="validate required environment variables")

    fence_parser = subparsers.add_parser("fence-check", help="validate an epoch token")
    fence_parser.add_argument("--token-epoch", type=int, required=True)
    fence_parser.add_argument("--current-epoch", type=int, required=True)
    fence_parser.add_argument("--controller-id", required=True)

    revoke_parser = subparsers.add_parser(
        "revoke-epoch",
        help="advance one exact rollout epoch through the authenticated API",
    )
    revoke_parser.add_argument("--project-number", required=True)
    revoke_parser.add_argument("--root-id", required=True)
    revoke_parser.add_argument("--expected-root-sha256", required=True)
    revoke_parser.add_argument("--expected-epoch", type=int, required=True)
    revoke_parser.add_argument("--reason", required=True)
    revoke_parser.add_argument("--request-id", required=True)
    revoke_parser.add_argument("--idempotency-key", required=True)
    revoke_parser.add_argument("--confirm", required=True, choices=("REVOKE",))

    serve_parser = subparsers.add_parser("serve", help="serve the read-only HTTP surface")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    for variant in ("stable", "candidate"):
        reference_parser = subparsers.add_parser(
            f"serve-reference-{variant}",
            help=f"serve the fixed {variant} reference marker",
        )
        reference_parser.add_argument("--host", default="0.0.0.0")
        reference_parser.add_argument(
            "--port",
            type=int,
            default=int(os.environ.get("PORT", "8080")),
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute a CLI command and return its process status."""

    args = _build_parser().parse_args(argv)

    if args.command == "doctor":
        report = _doctor_report(dict(os.environ))
        print(json.dumps(report, sort_keys=True))
        return 0 if report["configured"] else 2

    if args.command == "fence-check":
        try:
            fence = EpochFence(epoch=args.token_epoch, controller_id=args.controller_id)
            fence.require_current(args.current_epoch)
        except (EpochMismatchError, ValueError) as error:
            print(json.dumps({"authorized": False, "reason": str(error)}, sort_keys=True))
            return 3
        print(
            json.dumps(
                {
                    "authorized": True,
                    "controller_id": fence.controller_id,
                    "epoch": fence.epoch,
                },
                sort_keys=True,
            )
        )
        return 0

    if args.command == "revoke-epoch":
        return _run_epoch_revocation(args)

    if args.command == "serve":
        import uvicorn

        settings = ControllerSettings.from_environment()
        app_path = f"controlgraph_canary.services.{settings.role}.app:app"
        uvicorn.run(app_path, host=args.host, port=args.port, access_log=False)
        return 0

    if args.command in {"serve-reference-stable", "serve-reference-candidate"}:
        import uvicorn

        from controlgraph_canary.reference_target import ReferenceVariant, create_reference_app

        variant = ReferenceVariant(args.command.removeprefix("serve-reference-"))
        app = create_reference_app(variant)
        uvicorn.run(app, host=args.host, port=args.port, access_log=False)
        return 0

    raise AssertionError(f"unhandled command: {args.command}")


def _run_epoch_revocation(
    args: argparse.Namespace,
    *,
    command_runner: IdentityTokenCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Make exactly one authenticated API request without exposing its credential."""

    try:
        origin = _sealed_api_origin(args.project_number)
        command = EpochRevocationCommandV1(
            schema_version=EPOCH_REVOCATION_COMMAND_V1,
            root_id=args.root_id,
            expected_root_sha256=args.expected_root_sha256,
            expected_epoch=args.expected_epoch,
            reason=args.reason,
            request_id=args.request_id,
            idempotency_key=args.idempotency_key,
            confirmation=args.confirm,
        )
    except (TypeError, ValueError):
        _print_cli_error("REVOCATION_COMMAND_INVALID")
        return 2
    try:
        runner = command_runner or _run_identity_token_command
        completed = runner(
            (
                "gcloud",
                "auth",
                "print-identity-token",
                f"--audiences={origin}",
            ),
            capture_output=True,
            text=True,
            check=False,
            timeout=_HTTP_TIMEOUT_SECONDS,
            shell=False,
        )
    except Exception:
        _print_cli_error("REVOCATION_AUTH_UNAVAILABLE")
        return 3
    token = completed.stdout.strip() if completed.returncode == 0 else ""
    if _IDENTITY_TOKEN.fullmatch(token) is None:
        _print_cli_error("REVOCATION_AUTH_UNAVAILABLE")
        return 3
    poster = http_poster or UrllibOneShotHttpPoster()
    try:
        response = poster.post(
            url=f"{origin}/v1/operator/commands",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            body=canonical_json_bytes(command),
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
    except Exception:
        _print_cli_error("REVOCATION_OUTCOME_UNKNOWN")
        return 4
    if type(response) is not InternalHttpResponse:
        _print_cli_error("REVOCATION_OUTCOME_UNKNOWN")
        return 4
    if response.status_code != 200:
        code = (
            "REVOCATION_OUTCOME_UNKNOWN"
            if type(response.status_code) is int
            and 500 <= response.status_code <= 599
            else "REVOCATION_API_DENIED"
        )
        _print_cli_error(code)
        return 4 if code == "REVOCATION_OUTCOME_UNKNOWN" else 5
    if response.content_type not in {
        "application/json",
        "application/json; charset=utf-8",
    }:
        _print_cli_error("REVOCATION_API_DENIED")
        return 5
    try:
        result = decode_contract(response.body, EpochRevocationResultV1)
    except ContractError:
        _print_cli_error("REVOCATION_RESPONSE_INVALID")
        return 6
    if (
        result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.root_id != command.root_id
        or result.root_sha256 != command.expected_root_sha256
        or result.reason != command.reason
        or result.previous_epoch != command.expected_epoch
        or result.new_epoch != command.expected_epoch + 1
    ):
        _print_cli_error("REVOCATION_RESPONSE_INVALID")
        return 6
    print(canonical_json_bytes(result).decode("utf-8"))
    return 0


def _sealed_api_origin(project_number: str) -> str:
    if type(project_number) is not str or _PROJECT_NUMBER.fullmatch(project_number) is None:
        raise ValueError("project number is invalid")
    return f"https://controlgraph-api-{project_number}.us-central1.run.app"


def _run_identity_token_command(
    argv: Sequence[str],
    *,
    capture_output: bool,
    text: bool,
    check: bool,
    timeout: float,
    shell: bool,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=capture_output,
        text=text,
        check=check,
        timeout=timeout,
        shell=shell,
    )


def _print_cli_error(code: str) -> None:
    print(json.dumps({"code": code}, sort_keys=True))
