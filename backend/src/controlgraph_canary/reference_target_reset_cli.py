"""Deployment-only command for the explicit reference-target baseline reset."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Callable, Sequence

from controlgraph_canary.application.reference_target_reset import (
    REFERENCE_TARGET_CANDIDATE_REVISION,
    REFERENCE_TARGET_REGION,
    REFERENCE_TARGET_RESET_CONFIRMATION,
    REFERENCE_TARGET_SERVICE,
    REFERENCE_TARGET_STABLE_REVISION,
    ReferenceTargetResetConfiguration,
    ReferenceTargetResetError,
    ReferenceTargetResetErrorCode,
    ReferenceTargetResetRequest,
    ReferenceTargetResetResult,
    ReferenceTargetResetter,
)

type ReferenceTargetResetterFactory = Callable[
    [ReferenceTargetResetConfiguration], ReferenceTargetResetter
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controlgraph-reference-target-reset",
        description="Explicitly restore the deployed reference target to 100 percent stable.",
    )
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--stable-image", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--network-resource", required=True)
    parser.add_argument("--subnetwork-resource", required=True)
    parser.add_argument("--expected-etag", required=True)
    parser.add_argument(
        "--confirm",
        required=True,
        choices=(REFERENCE_TARGET_RESET_CONFIRMATION,),
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    resetter_factory: ReferenceTargetResetterFactory | None = None,
) -> int:
    """Run one explicit deployment-time reset with conditional provider readback."""

    args = _build_parser().parse_args(argv)
    try:
        configuration = ReferenceTargetResetConfiguration(
            project_id=args.project_id,
            stable_image=args.stable_image,
            candidate_image=args.candidate_image,
            network_resource=args.network_resource,
            subnetwork_resource=args.subnetwork_resource,
        )
        request = ReferenceTargetResetRequest(
            expected_etag=args.expected_etag,
            confirmation=args.confirm,
        )
    except (AttributeError, TypeError, ValueError):
        _print_error("REFERENCE_TARGET_RESET_COMMAND_INVALID")
        return 2
    try:
        factory = resetter_factory or _default_reference_target_resetter
        resetter = factory(configuration)
        if (
            not isinstance(resetter, ReferenceTargetResetter)
            or resetter.configuration != configuration
        ):
            raise TypeError("reference-target resetter is not configuration-bound")
        result = asyncio.run(resetter.reset(request))
    except ReferenceTargetResetError as error:
        status = {
            ReferenceTargetResetErrorCode.TARGET_STATE_DENIED: 3,
            ReferenceTargetResetErrorCode.PRECONDITION_FAILED: 4,
            ReferenceTargetResetErrorCode.PROVIDER_REJECTED: 5,
            ReferenceTargetResetErrorCode.OUTCOME_UNKNOWN: 6,
        }[error.code]
        _print_error(f"REFERENCE_TARGET_RESET_{error.code.value}")
        return status
    except Exception:
        _print_error("REFERENCE_TARGET_RESET_OUTCOME_UNKNOWN")
        return 6
    if (
        type(result) is not ReferenceTargetResetResult
        or result.configuration != configuration
        or result.request != request
    ):
        _print_error("REFERENCE_TARGET_RESET_RESPONSE_INVALID")
        return 6
    output = {
        "action": "reset-reference-target-baseline",
        "candidate_image": configuration.candidate_image,
        "candidate_percent": 0,
        "candidate_revision": REFERENCE_TARGET_CANDIDATE_REVISION,
        "observed_etag": result.observed_etag,
        "observed_generation": result.observed_generation,
        "operation_name": result.operation_name,
        "outcome": result.outcome.value,
        "previous_etag": request.expected_etag,
        "previous_generation": result.previous_generation,
        "project_id": configuration.project_id,
        "region": REFERENCE_TARGET_REGION,
        "service_name": REFERENCE_TARGET_SERVICE,
        "stable_image": configuration.stable_image,
        "stable_percent": 100,
        "stable_revision": REFERENCE_TARGET_STABLE_REVISION,
    }
    print(json.dumps(output, sort_keys=True))
    return 0


def _default_reference_target_resetter(
    configuration: ReferenceTargetResetConfiguration,
) -> ReferenceTargetResetter:
    from controlgraph_canary.integrations.google.cloud_run import (
        CloudRunV2ReferenceTargetResetter,
    )

    return CloudRunV2ReferenceTargetResetter(configuration=configuration)


def _print_error(code: str) -> None:
    print(json.dumps({"code": code}, sort_keys=True))


__all__ = ["main"]
