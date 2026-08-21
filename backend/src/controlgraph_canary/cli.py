"""Command-line entry point for local validation and service startup."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from controlgraph_canary.application.queue_control import (
    EXECUTION_QUEUE_ID,
    EXECUTION_QUEUE_REGION,
    ExecutionQueueController,
    ExecutionQueueObservation,
    ExecutionQueueState,
    ExecutionQueueTarget,
)
from controlgraph_canary.authority import EpochFence, EpochMismatchError
from controlgraph_canary.contracts.base import MAX_CONTRACT_BYTES
from controlgraph_canary.contracts.canary_execution import (
    APPLY_CANARY_COMMAND_V1,
    ApplyCanaryCommandV1,
    CanaryDispatchResultV1,
)
from controlgraph_canary.contracts.codec import (
    ContractError,
    ContractErrorCode,
    canonical_json_bytes,
    decode_contract,
)
from controlgraph_canary.contracts.health_pipeline import (
    HealthEvaluationCommandV1,
    HealthEvaluationResultV1,
    HealthEvaluationResultV2,
    health_evaluation_command_sha256,
)
from controlgraph_canary.contracts.models import CapabilityAction
from controlgraph_canary.contracts.operator_observability import (
    EXECUTION_RECEIPT_READ_COMMAND_V1,
    STABLE_SNAPSHOT_CAPTURE_COMMAND_V1,
    TARGET_TRAFFIC_READ_COMMAND_V1,
    ExecutionReceiptReadCommandV1,
    ExecutionReceiptReadResultV1,
    StableSnapshotCaptureCommandV1,
    StableSnapshotCaptureResultV1,
    TargetTrafficReadCommandV1,
    TargetTrafficReadResultV1,
)
from controlgraph_canary.contracts.promotion_execution import (
    PromotionCommandV2,
    PromotionDispatchResultV2,
)
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryCommandV2,
    RecoveryDispatchResultV2,
    RevokedV2RecoverySourceV1,
    recovery_trigger_proof_sha256,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_COMMAND_V1,
    EPOCH_REVOCATION_PROOF_COMMAND_V1,
    EpochRevocationCallOutcomeV1,
    EpochRevocationCommandV1,
    EpochRevocationProofCommandV1,
    EpochRevocationProofV1,
    epoch_revocation_proof_matches_command,
)
from controlgraph_canary.contracts.root_creation import (
    RootCreationCommandV1,
    RootCreationResultV1,
    RootCreationResultV2,
    decode_root_creation_result,
)
from controlgraph_canary.contracts.root_trust import stable_snapshots_match
from controlgraph_canary.contracts.service_claim_release import (
    ServiceClaimReleaseCommandV1,
    ServiceClaimReleaseResultV1,
)
from controlgraph_canary.contracts.storage import execution_receipt_logical_id
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.integrations.google.internal_transport import (
    InternalHttpResponse,
    OneShotHttpPoster,
    UrllibOneShotHttpPoster,
)
from controlgraph_canary.settings import ControllerSettings, required_environment_keys

_PROJECT_NUMBER = re.compile(r"^[1-9][0-9]{5,31}$")
_IDENTITY_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{16,16384}$")
_IDENTITY_TOKEN_COMMAND_TIMEOUT_SECONDS = 10.0
# The API may wait on the complete internal authorization chain. Match the
# bounded Cloud Run request deadline so callers can observe its response.
_OPERATOR_HTTP_TIMEOUT_SECONDS = 60.0

type OperatorApiCommand = (
    StableSnapshotCaptureCommandV1
    | RootCreationCommandV1
    | ApplyCanaryCommandV1
    | ExecutionReceiptReadCommandV1
    | TargetTrafficReadCommandV1
    | HealthEvaluationCommandV1
    | PromotionCommandV2
    | RecoveryCommandV2
    | EpochRevocationCommandV1
    | EpochRevocationProofCommandV1
    | ServiceClaimReleaseCommandV1
)
type OperatorApiResult = (
    StableSnapshotCaptureResultV1
    | RootCreationResultV1
    | RootCreationResultV2
    | CanaryDispatchResultV1
    | ExecutionReceiptReadResultV1
    | TargetTrafficReadResultV1
    | HealthEvaluationResultV1
    | HealthEvaluationResultV2
    | PromotionDispatchResultV2
    | RecoveryDispatchResultV2
    | ServiceClaimReleaseResultV1
)

_OPERATOR_API_COMMAND_TYPES = (
    StableSnapshotCaptureCommandV1,
    RootCreationCommandV1,
    ApplyCanaryCommandV1,
    ExecutionReceiptReadCommandV1,
    TargetTrafficReadCommandV1,
    HealthEvaluationCommandV1,
    PromotionCommandV2,
    RecoveryCommandV2,
    EpochRevocationCommandV1,
    EpochRevocationProofCommandV1,
    ServiceClaimReleaseCommandV1,
)

type ExecutionQueueControllerFactory = Callable[[ExecutionQueueTarget], ExecutionQueueController]


class GcloudCommandRunner(Protocol):
    """Run one fixed shell-free gcloud command."""

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


class _OperatorApiFailure(StrEnum):
    AUTH_UNAVAILABLE = "AUTH_UNAVAILABLE"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    API_DENIED = "API_DENIED"


class _OperatorApiError(RuntimeError):
    def __init__(self, failure: _OperatorApiFailure) -> None:
        self.failure = failure
        super().__init__(failure.value)


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

    proof_parser = subparsers.add_parser(
        "revocation-proof",
        help="retrieve one exact verified revocation proof through the authenticated API",
    )
    proof_parser.add_argument("--project-number", required=True)
    proof_parser.add_argument("--root-id", required=True)
    proof_parser.add_argument("--root-sha256", required=True)
    proof_parser.add_argument("--previous-epoch", type=int, required=True)
    proof_parser.add_argument("--new-epoch", type=int, required=True)
    proof_parser.add_argument("--reason", required=True)
    proof_parser.add_argument("--request-sha256", required=True)
    proof_parser.add_argument("--request-id", required=True)
    proof_parser.add_argument("--idempotency-key", required=True)
    proof_parser.add_argument("--result-id", required=True)
    proof_parser.add_argument("--evidence-id", required=True)
    proof_parser.add_argument("--evidence-sha256", required=True)
    proof_parser.add_argument("--attempt-id", required=True)
    proof_parser.add_argument("--audit-id", required=True)

    snapshot_parser = subparsers.add_parser(
        "capture-stable-snapshot",
        help="capture the configured target's stable snapshot through the operator API",
    )
    snapshot_parser.add_argument("--project-number", required=True)
    snapshot_parser.add_argument("--request-id", required=True)

    root_parser = subparsers.add_parser(
        "create-rollout-root",
        help="create one rollout root from an exact canonical command",
    )
    root_parser.add_argument("--project-number", required=True)
    root_parser.add_argument(
        "--command-file",
        required=True,
        help="canonical root-creation command path, or '-' for stdin",
    )

    canary_parser = subparsers.add_parser(
        "apply-canary",
        help="dispatch one 90/10 canary through the operator API",
    )
    _add_authority_arguments(canary_parser)

    receipt_parser = subparsers.add_parser(
        "read-execution-receipt",
        help="read one exact execution receipt through the operator API",
    )
    _add_authority_arguments(receipt_parser)
    receipt_parser.add_argument(
        "--action",
        type=CapabilityAction,
        choices=(
            CapabilityAction.APPLY_CANARY,
            CapabilityAction.PROMOTE_CANDIDATE,
            CapabilityAction.RECOVER_STABLE,
        ),
        required=True,
    )
    receipt_parser.add_argument("--capability-sha256", required=True)

    traffic_parser = subparsers.add_parser(
        "read-target-traffic",
        help="read the configured target's exact traffic through the operator API",
    )
    traffic_parser.add_argument("--project-number", required=True)
    traffic_parser.add_argument("--request-id", required=True)

    promotion_parser = subparsers.add_parser(
        "promote-candidate",
        help="dispatch one promotion from an exact canonical command",
    )
    promotion_parser.add_argument("--project-number", required=True)
    promotion_parser.add_argument(
        "--command-file",
        required=True,
        help="canonical promotion command path, or '-' for stdin",
    )

    health_parser = subparsers.add_parser(
        "evaluate-health",
        help="evaluate one exact post-apply health window through the operator API",
    )
    health_parser.add_argument("--project-number", required=True)
    health_parser.add_argument(
        "--command-file",
        required=True,
        help="canonical health-evaluation command path, or '-' for stdin",
    )

    recovery_parser = subparsers.add_parser(
        "recover-captured-stable",
        help="dispatch one explicitly confirmed revoked-V2 stable recovery",
    )
    recovery_parser.add_argument("--project-number", required=True)
    recovery_parser.add_argument(
        "--command-file",
        required=True,
        help="canonical recovery command path, or '-' for stdin",
    )

    release_claim_parser = subparsers.add_parser(
        "release-service-claim",
        help="release one terminal rollout's service claim through the authenticated API",
    )
    release_claim_parser.add_argument("--project-number", required=True)
    release_claim_parser.add_argument(
        "--command-file",
        required=True,
        help="canonical service-claim release command path, or '-' for stdin",
    )

    queue_parser = subparsers.add_parser(
        "execution-queue",
        help="inspect, hold, or release the fixed execution queue",
    )
    queue_subparsers = queue_parser.add_subparsers(dest="queue_action", required=True)
    describe_queue_parser = queue_subparsers.add_parser(
        "describe",
        help="read the fixed execution queue state",
    )
    describe_queue_parser.add_argument("--project-id", required=True)
    hold_queue_parser = queue_subparsers.add_parser(
        "hold",
        help="pause dispatch from the fixed execution queue",
    )
    hold_queue_parser.add_argument("--project-id", required=True)
    hold_queue_parser.add_argument(
        "--confirm",
        required=True,
        choices=("HOLD_EXECUTION_QUEUE",),
    )
    release_queue_parser = queue_subparsers.add_parser(
        "release",
        help="resume dispatch from the fixed execution queue",
    )
    release_queue_parser.add_argument("--project-id", required=True)
    release_queue_parser.add_argument(
        "--confirm",
        required=True,
        choices=("RELEASE_EXECUTION_QUEUE",),
    )

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


def _add_authority_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-number", required=True)
    parser.add_argument("--root-id", required=True)
    parser.add_argument("--expected-root-sha256", required=True)
    parser.add_argument("--expected-epoch", type=int, required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--idempotency-key", required=True)


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

    if args.command == "revocation-proof":
        return _run_revocation_proof(args)

    if args.command == "capture-stable-snapshot":
        return _run_stable_snapshot_capture(args)

    if args.command == "create-rollout-root":
        return _run_root_creation(args)

    if args.command == "apply-canary":
        return _run_apply_canary(args)

    if args.command == "read-execution-receipt":
        return _run_execution_receipt_read(args)

    if args.command == "read-target-traffic":
        return _run_target_traffic_read(args)

    if args.command == "promote-candidate":
        return _run_promotion(args)

    if args.command == "evaluate-health":
        return _run_health_evaluation(args)

    if args.command == "recover-captured-stable":
        return _run_recovery(args)

    if args.command == "release-service-claim":
        return _run_service_claim_release(args)

    if args.command == "execution-queue":
        return _run_execution_queue_command(args)

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
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Make exactly one authenticated API request without exposing its credential."""

    try:
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
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, TypeError, ValueError):
        _print_cli_error("REVOCATION_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("REVOCATION", error)
    try:
        outcome = decode_contract(response_body, EpochRevocationCallOutcomeV1)
    except ContractError:
        _print_cli_error("REVOCATION_RESPONSE_INVALID")
        return 6
    result = outcome.result
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
    print(canonical_json_bytes(outcome).decode("utf-8"))
    return 0


def _run_revocation_proof(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Retrieve one exact proof without direct authority-store or KMS access."""

    try:
        command = EpochRevocationProofCommandV1(
            schema_version=EPOCH_REVOCATION_PROOF_COMMAND_V1,
            root_id=args.root_id,
            root_sha256=args.root_sha256,
            previous_epoch=args.previous_epoch,
            new_epoch=args.new_epoch,
            reason=args.reason,
            request_sha256=args.request_sha256,
            request_id=args.request_id,
            idempotency_key=args.idempotency_key,
            result_id=args.result_id,
            evidence_id=args.evidence_id,
            evidence_sha256=args.evidence_sha256,
            attempt_id=args.attempt_id,
            audit_id=args.audit_id,
        )
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, TypeError, ValueError):
        _print_cli_error("REVOCATION_PROOF_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        if error.failure is _OperatorApiFailure.AUTH_UNAVAILABLE:
            _print_cli_error("REVOCATION_AUTH_UNAVAILABLE")
            return 3
        _print_cli_error("REVOCATION_PROOF_DENIED")
        return 5 if error.failure is _OperatorApiFailure.API_DENIED else 4
    try:
        proof = decode_contract(response_body, EpochRevocationProofV1)
    except ContractError:
        _print_cli_error("REVOCATION_PROOF_RESPONSE_INVALID")
        return 6
    if not epoch_revocation_proof_matches_command(proof, command):
        _print_cli_error("REVOCATION_PROOF_RESPONSE_INVALID")
        return 6
    print(canonical_json_bytes(proof).decode("utf-8"))
    return 0


def _run_stable_snapshot_capture(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Capture only the API-configured target's stable snapshot."""

    try:
        command = StableSnapshotCaptureCommandV1(
            schema_version=STABLE_SNAPSHOT_CAPTURE_COMMAND_V1,
            request_id=args.request_id,
        )
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, TypeError, ValueError):
        _print_cli_error("SNAPSHOT_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("SNAPSHOT", error)
    try:
        result = decode_contract(response_body, StableSnapshotCaptureResultV1)
    except ContractError:
        _print_cli_error("SNAPSHOT_RESPONSE_INVALID")
        return 6
    if result.request.request_id != command.request_id:
        _print_cli_error("SNAPSHOT_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_root_creation(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Create one root from a pre-decoded exact root-creation command."""

    try:
        command = _read_root_creation_command(args.command_file)
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, OSError, TypeError, ValueError):
        _print_cli_error("ROOT_CREATION_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("ROOT_CREATION", error)
    try:
        result = decode_root_creation_result(response_body)
    except ContractError:
        _print_cli_error("ROOT_CREATION_RESPONSE_INVALID")
        return 6
    root_snapshot = result.root.content.stable_snapshot
    if (
        result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or not stable_snapshots_match(
            root_snapshot,
            command.expected_stable_snapshot,
        )
        or root_snapshot.captured_at < command.expected_stable_snapshot.captured_at
    ):
        _print_cli_error("ROOT_CREATION_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_apply_canary(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Dispatch one command bound to exact root authority."""

    try:
        command = ApplyCanaryCommandV1(
            schema_version=APPLY_CANARY_COMMAND_V1,
            root_id=args.root_id,
            expected_root_sha256=args.expected_root_sha256,
            expected_epoch=args.expected_epoch,
            request_id=args.request_id,
            idempotency_key=args.idempotency_key,
        )
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, TypeError, ValueError):
        _print_cli_error("CANARY_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("CANARY", error)
    try:
        result = decode_contract(response_body, CanaryDispatchResultV1)
    except ContractError:
        _print_cli_error("CANARY_RESPONSE_INVALID")
        return 6
    if (
        result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.root_id != command.root_id
        or result.root_sha256 != command.expected_root_sha256
        or result.epoch != command.expected_epoch
    ):
        _print_cli_error("CANARY_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_execution_receipt_read(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Read only the receipt named by its complete dispatch identity."""

    try:
        command = ExecutionReceiptReadCommandV1(
            schema_version=EXECUTION_RECEIPT_READ_COMMAND_V1,
            root_id=args.root_id,
            expected_root_sha256=args.expected_root_sha256,
            expected_epoch=args.expected_epoch,
            action=args.action,
            request_id=args.request_id,
            idempotency_key=args.idempotency_key,
            capability_sha256=args.capability_sha256,
        )
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, TypeError, ValueError):
        _print_cli_error("RECEIPT_READ_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("RECEIPT_READ", error)
    try:
        result = decode_contract(response_body, ExecutionReceiptReadResultV1)
    except ContractError:
        _print_cli_error("RECEIPT_READ_RESPONSE_INVALID")
        return 6
    if result.command != command:
        _print_cli_error("RECEIPT_READ_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_target_traffic_read(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Read only the API-configured target's traffic state."""

    try:
        command = TargetTrafficReadCommandV1(
            schema_version=TARGET_TRAFFIC_READ_COMMAND_V1,
            request_id=args.request_id,
        )
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, TypeError, ValueError):
        _print_cli_error("TRAFFIC_READ_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("TRAFFIC_READ", error)
    try:
        result = decode_contract(response_body, TargetTrafficReadResultV1)
    except ContractError:
        _print_cli_error("TRAFFIC_READ_RESPONSE_INVALID")
        return 6
    if result.request.request_id != command.request_id:
        _print_cli_error("TRAFFIC_READ_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_promotion(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Dispatch one promotion from a pre-decoded exact promotion command."""

    try:
        command = _read_promotion_command(args.command_file)
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, OSError, TypeError, ValueError):
        _print_cli_error("PROMOTION_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("PROMOTION", error)
    try:
        result = decode_contract(response_body, PromotionDispatchResultV2)
    except ContractError:
        _print_cli_error("PROMOTION_RESPONSE_INVALID")
        return 6
    if (
        result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.root_id != command.root_id
        or result.root_sha256 != command.expected_root_sha256
        or result.epoch != command.expected_epoch
        or result.scheduled_at != command.scheduled_at
        or result.verified_apply_receipt != command.verified_apply_receipt
    ):
        _print_cli_error("PROMOTION_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_health_evaluation(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Evaluate one root-, receipt-, and predecessor-bound health window."""

    try:
        command = _read_health_evaluation_command(args.command_file)
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, OSError, TypeError, ValueError):
        _print_cli_error("HEALTH_EVALUATION_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("HEALTH_EVALUATION", error)
    try:
        result = _decode_health_evaluation_result(response_body)
    except ContractError:
        _print_cli_error("HEALTH_EVALUATION_RESPONSE_INVALID")
        return 6
    if (
        result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.command_sha256 != health_evaluation_command_sha256(command)
        or result.target != command.target
        or result.root_id != command.root_id
        or result.root_sha256 != command.expected_root_sha256
        or result.epoch != command.expected_epoch
        or result.verified_apply_receipt != command.verified_apply_receipt
        or result.expected_sequence != command.expected_sequence
        or result.expected_chain_head_sha256
        != command.expected_chain_head_sha256
    ):
        _print_cli_error("HEALTH_EVALUATION_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_recovery(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Dispatch only the explicit revoked-V2 captured-stable command."""

    try:
        command = _read_recovery_command(args.command_file)
        if type(command.source) is not RevokedV2RecoverySourceV1:
            raise ValueError("operator recovery requires the revoked-V2 source")
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, OSError, TypeError, ValueError):
        _print_cli_error("RECOVERY_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("RECOVERY", error)
    try:
        result = decode_contract(response_body, RecoveryDispatchResultV2)
    except ContractError:
        _print_cli_error("RECOVERY_RESPONSE_INVALID")
        return 6
    if (
        result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.target != command.source.target
        or result.root_id != command.root_id
        or result.root_sha256 != command.expected_root_sha256
        or result.epoch != command.expected_epoch
        or result.scheduled_at != command.scheduled_at
        or result.verified_apply_receipt != command.verified_apply_receipt
        or result.source_receipt_sha256
        != command.verified_apply_receipt.receipt_sha256
        or result.trigger_basis is not command.source.basis
        or result.trigger_proof_sha256
        != recovery_trigger_proof_sha256(command.source)
        or result.stable_percent != 100
        or result.candidate_percent != 0
    ):
        _print_cli_error("RECOVERY_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_service_claim_release(
    args: argparse.Namespace,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> int:
    """Release one terminal rollout claim through the sealed operator API."""

    try:
        command = _read_service_claim_release_command(args.command_file)
        response_body = _post_operator_command(
            args.project_number,
            command,
            command_runner=command_runner,
            http_poster=http_poster,
        )
    except (ContractError, OSError, TypeError, ValueError):
        _print_cli_error("SERVICE_CLAIM_RELEASE_COMMAND_INVALID")
        return 2
    except _OperatorApiError as error:
        return _report_operator_api_failure("SERVICE_CLAIM_RELEASE", error)
    try:
        result = decode_contract(response_body, ServiceClaimReleaseResultV1)
    except ContractError:
        _print_cli_error("SERVICE_CLAIM_RELEASE_RESPONSE_INVALID")
        return 6
    if (
        result.request_id != command.request_id
        or result.idempotency_key != command.idempotency_key
        or result.root_id != command.root_id
        or result.root_sha256 != command.expected_root_sha256
        or result.fenced_epoch != command.expected_epoch + 1
        or result.fenced_authority_revision != command.expected_epoch
        or result.terminal_receipt_id
        != execution_receipt_logical_id(
            result.target,
            command.terminal_receipt_idempotency_key,
        )
    ):
        _print_cli_error("SERVICE_CLAIM_RELEASE_RESPONSE_INVALID")
        return 6
    _print_contract_result(result)
    return 0


def _run_execution_queue_command(
    args: argparse.Namespace,
    *,
    controller_factory: ExecutionQueueControllerFactory | None = None,
) -> int:
    """Inspect or control only the fixed execution queue with one provider RPC."""

    action = getattr(args, "queue_action", None)
    project_id = getattr(args, "project_id", None)
    confirmation = getattr(args, "confirm", None)
    if type(action) is not str or type(project_id) is not str:
        _print_cli_error("QUEUE_CONTROL_COMMAND_INVALID")
        return 2
    try:
        target = ExecutionQueueTarget(project_id=project_id)
    except (TypeError, ValueError):
        _print_cli_error("QUEUE_CONTROL_COMMAND_INVALID")
        return 2
    if not _valid_queue_confirmation(action, confirmation):
        _print_cli_error("QUEUE_CONTROL_COMMAND_INVALID")
        return 2

    try:
        factory = controller_factory or _default_execution_queue_controller
        controller = factory(target)
        if action == "describe":
            observation = controller.describe()
        elif action == "hold":
            observation = controller.hold()
        else:
            observation = controller.release()
    except Exception:
        code = (
            "QUEUE_CONTROL_PROVIDER_UNAVAILABLE"
            if action == "describe"
            else "QUEUE_CONTROL_OUTCOME_UNKNOWN"
        )
        _print_cli_error(code)
        return 3 if action == "describe" else 4

    expected_state = {
        "hold": ExecutionQueueState.PAUSED,
        "release": ExecutionQueueState.RUNNING,
    }.get(action)
    if (
        type(observation) is not ExecutionQueueObservation
        or observation.resource_name != target.resource_name
        or type(observation.state) is not ExecutionQueueState
        or (expected_state is not None and observation.state is not expected_state)
    ):
        code = (
            "QUEUE_CONTROL_RESPONSE_INVALID"
            if action == "describe"
            else "QUEUE_CONTROL_OUTCOME_UNKNOWN"
        )
        _print_cli_error(code)
        return 5 if action == "describe" else 4
    output = {
        "action": action,
        "location": EXECUTION_QUEUE_REGION,
        "project_id": target.project_id,
        "queue_id": EXECUTION_QUEUE_ID,
        "state": observation.state.value,
    }
    print(json.dumps(output, sort_keys=True))
    return 0


def _valid_queue_confirmation(action: object, confirmation: object) -> bool:
    if action == "describe":
        return confirmation is None
    if action == "hold":
        return confirmation == "HOLD_EXECUTION_QUEUE"
    if action == "release":
        return confirmation == "RELEASE_EXECUTION_QUEUE"
    return False


def _default_execution_queue_controller(
    target: ExecutionQueueTarget,
) -> ExecutionQueueController:
    from controlgraph_canary.integrations.google.queue_control import (
        GoogleCloudTasksExecutionQueueController,
    )

    return GoogleCloudTasksExecutionQueueController.from_default_credentials(target)


def _read_root_creation_command(source: str) -> RootCreationCommandV1:
    return decode_contract(_read_bounded_command_bytes(source), RootCreationCommandV1)


def _read_promotion_command(source: str) -> PromotionCommandV2:
    return decode_contract(_read_bounded_command_bytes(source), PromotionCommandV2)


def _read_health_evaluation_command(source: str) -> HealthEvaluationCommandV1:
    return decode_contract(
        _read_bounded_command_bytes(source),
        HealthEvaluationCommandV1,
    )


def _read_recovery_command(source: str) -> RecoveryCommandV2:
    return decode_contract(
        _read_bounded_command_bytes(source),
        RecoveryCommandV2,
    )


def _decode_health_evaluation_result(
    payload: bytes,
) -> HealthEvaluationResultV1 | HealthEvaluationResultV2:
    try:
        return decode_contract(payload, HealthEvaluationResultV2)
    except ContractError as error:
        if error.code is not ContractErrorCode.VERSION_UNSUPPORTED:
            raise
    return decode_contract(payload, HealthEvaluationResultV1)


def _read_service_claim_release_command(source: str) -> ServiceClaimReleaseCommandV1:
    return decode_contract(
        _read_bounded_command_bytes(source),
        ServiceClaimReleaseCommandV1,
    )


def _read_bounded_command_bytes(source: str) -> bytes:
    if type(source) is not str or not source:
        raise ValueError("command source is invalid")
    if source == "-":
        payload = sys.stdin.buffer.read(MAX_CONTRACT_BYTES + 1)
    else:
        with Path(source).open("rb") as command_file:
            payload = command_file.read(MAX_CONTRACT_BYTES + 1)
    if type(payload) is not bytes or not payload or len(payload) > MAX_CONTRACT_BYTES:
        raise ValueError("command source is outside its byte bounds")
    return payload


def _post_operator_command(
    project_number: str,
    command: OperatorApiCommand,
    *,
    command_runner: GcloudCommandRunner | None = None,
    http_poster: OneShotHttpPoster | None = None,
) -> bytes:
    """Send one exact admitted command to the sealed operator API route."""

    origin = _sealed_api_origin(project_number)
    if type(command) not in _OPERATOR_API_COMMAND_TYPES:
        raise TypeError("operator API command type is not admitted")
    body = canonical_json_bytes(command)
    try:
        runner = command_runner or _run_gcloud_command
        completed = runner(
            (
                "gcloud",
                "auth",
                "print-identity-token",
            ),
            capture_output=True,
            text=True,
            check=False,
            timeout=_IDENTITY_TOKEN_COMMAND_TIMEOUT_SECONDS,
            shell=False,
        )
        token = (
            completed.stdout.strip()
            if completed.returncode == 0 and type(completed.stdout) is str
            else ""
        )
    except Exception as error:
        raise _OperatorApiError(_OperatorApiFailure.AUTH_UNAVAILABLE) from error
    if _IDENTITY_TOKEN.fullmatch(token) is None:
        raise _OperatorApiError(_OperatorApiFailure.AUTH_UNAVAILABLE)

    try:
        poster = http_poster or UrllibOneShotHttpPoster()
        response = poster.post(
            url=f"{origin}/v1/operator/commands",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                CONTROLGRAPH_AUTHORIZATION_HEADER: f"Bearer {token}",
                SERVERLESS_AUTHORIZATION_HEADER: f"Bearer {token}",
            },
            body=body,
            timeout=_OPERATOR_HTTP_TIMEOUT_SECONDS,
        )
    except Exception as error:
        raise _OperatorApiError(_OperatorApiFailure.OUTCOME_UNKNOWN) from error
    if type(response) is not InternalHttpResponse:
        raise _OperatorApiError(_OperatorApiFailure.OUTCOME_UNKNOWN)
    if (
        type(response.status_code) is not int
        or not 100 <= response.status_code <= 599
        or (response.content_type is not None and type(response.content_type) is not str)
        or type(response.body) is not bytes
    ):
        raise _OperatorApiError(_OperatorApiFailure.OUTCOME_UNKNOWN)
    if response.status_code != 200:
        if 400 <= response.status_code <= 499:
            raise _OperatorApiError(_OperatorApiFailure.API_DENIED)
        raise _OperatorApiError(_OperatorApiFailure.OUTCOME_UNKNOWN)
    if response.content_type not in {
        "application/json",
        "application/json; charset=utf-8",
    }:
        raise _OperatorApiError(_OperatorApiFailure.OUTCOME_UNKNOWN)
    if not response.body or len(response.body) > MAX_CONTRACT_BYTES:
        raise _OperatorApiError(_OperatorApiFailure.OUTCOME_UNKNOWN)
    return response.body


def _report_operator_api_failure(prefix: str, error: _OperatorApiError) -> int:
    status = {
        _OperatorApiFailure.AUTH_UNAVAILABLE: 3,
        _OperatorApiFailure.OUTCOME_UNKNOWN: 4,
        _OperatorApiFailure.API_DENIED: 5,
    }[error.failure]
    _print_cli_error(f"{prefix}_{error.failure.value}")
    return status


def _print_contract_result(result: OperatorApiResult) -> None:
    if type(result) not in (
        StableSnapshotCaptureResultV1,
        RootCreationResultV1,
        RootCreationResultV2,
        CanaryDispatchResultV1,
        ExecutionReceiptReadResultV1,
        TargetTrafficReadResultV1,
        HealthEvaluationResultV1,
        HealthEvaluationResultV2,
        PromotionDispatchResultV2,
        RecoveryDispatchResultV2,
        ServiceClaimReleaseResultV1,
    ):
        raise TypeError("operator API result type is not admitted")
    print(canonical_json_bytes(result).decode("utf-8"))


def _sealed_api_origin(project_number: str) -> str:
    if type(project_number) is not str or _PROJECT_NUMBER.fullmatch(project_number) is None:
        raise ValueError("project number is invalid")
    return f"https://controlgraph-api-{project_number}.us-central1.run.app"


def _run_gcloud_command(
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
