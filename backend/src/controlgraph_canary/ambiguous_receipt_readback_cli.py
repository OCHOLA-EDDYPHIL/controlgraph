"""One-shot executor CLI for readback-only ambiguous receipt resolution."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

from controlgraph_canary.application.ambiguous_receipt_readback import (
    AmbiguousReceiptReadbackError,
    AmbiguousReceiptReadbackResolver,
)
from controlgraph_canary.contracts.ambiguous_receipt_readback import (
    AmbiguousReceiptReadbackCommandV1,
)
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.models import CapabilityAction
from controlgraph_canary.services.ambiguous_receipt_readback import (
    create_ambiguous_receipt_readback_resolver,
)

AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV = (
    "CONTROLGRAPH_AMBIGUOUS_RECEIPT_READBACK_COMMAND"
)


class ResolverFactory(Protocol):
    """Compose one executor-bound resolver from validated runtime settings."""

    def __call__(
        self,
        *,
        action: CapabilityAction,
        environment: Mapping[str, str] | None = None,
    ) -> AmbiguousReceiptReadbackResolver: ...


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
    resolver_factory: ResolverFactory | None = None,
) -> int:
    """Resolve one exact receipt and return a stable process status."""

    parser = argparse.ArgumentParser(
        prog="controlgraph-ambiguous-receipt-readback",
        description="Resolve one stored ambiguous receipt by independent readback only.",
    )
    command_source = parser.add_mutually_exclusive_group(required=True)
    command_source.add_argument(
        "--command-file",
        help="canonical readback command path, or '-' for stdin",
    )
    command_source.add_argument(
        "--command-environment",
        action="store_true",
        help=(
            "read canonical JSON from "
            f"{AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV}"
        ),
    )
    args = parser.parse_args(argv)
    source = os.environ if environment is None else environment
    try:
        command = decode_contract(
            _read_bounded_command(
                file_source=args.command_file,
                use_environment=args.command_environment,
                environment=source,
            ),
            AmbiguousReceiptReadbackCommandV1,
        )
    except (ContractError, OSError, TypeError, ValueError):
        _print_error("AMBIGUOUS_RECEIPT_READBACK_COMMAND_INVALID")
        return 2
    try:
        factory = resolver_factory or create_ambiguous_receipt_readback_resolver
        resolver = factory(action=command.action, environment=environment)
    except Exception:
        _print_error("AMBIGUOUS_RECEIPT_READBACK_CONFIGURATION_INVALID")
        return 3
    try:
        result = asyncio.run(resolver.resolve(command))
    except AmbiguousReceiptReadbackError as error:
        _print_error(error.code.value)
        return 4
    except Exception:
        _print_error("AMBIGUOUS_RECEIPT_READBACK_UNAVAILABLE")
        return 5
    print(canonical_json_bytes(result).decode("utf-8"))
    return 0


def _read_bounded_command(
    *,
    file_source: str | None,
    use_environment: bool,
    environment: Mapping[str, str],
) -> bytes:
    if type(use_environment) is not bool:
        raise TypeError("command environment selector is invalid")
    if use_environment:
        if file_source is not None:
            raise ValueError("command sources are mutually exclusive")
        raw = environment.get(AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV)
        if type(raw) is not str:
            raise ValueError("command environment source is missing")
        try:
            payload = raw.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("command environment source is invalid") from error
    elif type(file_source) is not str or not file_source:
        raise ValueError("command file source is invalid")
    elif file_source == "-":
        payload = sys.stdin.buffer.read(MAX_CONTRACT_BYTES + 1)
    else:
        with Path(file_source).open("rb") as command_file:
            payload = command_file.read(MAX_CONTRACT_BYTES + 1)
    if type(payload) is not bytes or not payload or len(payload) > MAX_CONTRACT_BYTES:
        raise ValueError("command source is outside its byte bounds")
    return payload


def _print_error(code: str) -> None:
    print(json.dumps({"code": code}, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["AMBIGUOUS_RECEIPT_READBACK_COMMAND_ENV", "main"]
