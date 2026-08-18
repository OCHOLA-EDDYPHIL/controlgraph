"""Command-line entry point for local validation and service startup."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from typing import Any

from controlgraph_canary.authority import EpochFence, EpochMismatchError
from controlgraph_canary.settings import REQUIRED_ENVIRONMENT_KEYS, ControllerSettings


def _doctor_report(environment: dict[str, str]) -> dict[str, Any]:
    missing = [key for key in REQUIRED_ENVIRONMENT_KEYS if not environment.get(key, "").strip()]
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

    serve_parser = subparsers.add_parser("serve", help="serve the read-only HTTP surface")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
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

    if args.command == "serve":
        import uvicorn

        ControllerSettings.from_environment()
        uvicorn.run("controlgraph_canary.api:app", host=args.host, port=args.port)
        return 0

    raise AssertionError(f"unhandled command: {args.command}")
