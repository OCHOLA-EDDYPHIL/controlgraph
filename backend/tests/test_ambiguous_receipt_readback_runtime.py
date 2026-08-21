from __future__ import annotations

import inspect

from root_v2_support import root_bundle, target_binding

import controlgraph_canary.application.ambiguous_receipt_readback as resolver_module
import controlgraph_canary.services.ambiguous_receipt_readback as composition_module
from controlgraph_canary.application.ambiguous_receipt_readback import (
    AmbiguousReceiptReadbackResolver,
)
from controlgraph_canary.application.receipt_execution import ReceiptReadbackResult
from controlgraph_canary.services.ambiguous_receipt_readback import (
    create_ambiguous_receipt_readback_resolver,
)

PROJECT_ID = "controlgraph-canary-abc123"
PROJECT_NUMBER = "123456789012"


def _environment() -> dict[str, str]:
    return {
        "CONTROLGRAPH_PROJECT_ID": PROJECT_ID,
        "CONTROLGRAPH_PROJECT_NUMBER": PROJECT_NUMBER,
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_SERVICE_NAME": "controlgraph-executor",
        "CONTROLGRAPH_CONTROLLER_ID": f"{PROJECT_ID}:us-central1:executor",
        "CONTROLGRAPH_ROLE": "executor",
        "CONTROLGRAPH_BUILD_DIGEST": f"sha256:{'a' * 64}",
        "CONTROLGRAPH_CONTRACT_VERSION": "controlgraph.contract/v1",
        "CONTROLGRAPH_FIRESTORE_DATABASE": "controlgraph-authority",
        "CONTROLGRAPH_MUTATIONS_ENABLED": "true",
        "CONTROLGRAPH_ENVIRONMENT": "nonprod",
        "CONTROLGRAPH_AUTH_AUDIENCE": (
            f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "CONTROLGRAPH_AUTH_CALLER_ROLE": "execution_task_caller",
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
            f"cg-execution-task-caller@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": "123456789012345678901",
        "CONTROLGRAPH_CAPABILITY_KEY_VERSION": (
            f"projects/{PROJECT_ID}/locations/us-central1/keyRings/controlgraph-signing/"
            "cryptoKeys/capability-signing/cryptoKeyVersions/1"
        ),
        "CONTROLGRAPH_COORDINATOR_URL": (
            f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        "CONTROLGRAPH_TARGET_NETWORK_RESOURCE": (
            f"projects/{PROJECT_ID}/global/networks/controlgraph-network"
        ),
        "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE": (
            f"projects/{PROJECT_ID}/regions/us-central1/subnetworks/controlgraph-runtime"
        ),
    }


class _RootReader:
    target = target_binding()

    async def read_root_creation_bundle(self, root_id: str) -> object:
        del root_id
        return root_bundle()


class _ReceiptStore:
    target = target_binding()

    async def read_receipt(self, idempotency_key: str) -> None:
        del idempotency_key
        return None

    async def resolve_ambiguous_receipt(
        self,
        expected: object,
        replacement: object,
        expected_authority: object,
        expected_service_claim: object,
    ) -> None:
        del expected, replacement, expected_authority, expected_service_claim
        return None


class _OperationReadback:
    target = target_binding()

    async def terminal_success(self, operation_name: str) -> bool:
        del operation_name
        return False


class _TargetReadback:
    target = target_binding()

    async def readback(self, expected: object) -> ReceiptReadbackResult:
        del expected
        return ReceiptReadbackResult(state=None, observed_etag=None)


def test_one_shot_composition_is_executor_only_and_uses_injected_read_dependencies() -> None:
    resolver = create_ambiguous_receipt_readback_resolver(
        environment=_environment(),
        root_reader=_RootReader(),
        receipt_store=_ReceiptStore(),
        operation_readback=_OperationReadback(),
        target_readback=_TargetReadback(),
    )

    assert type(resolver) is AmbiguousReceiptReadbackResolver
    assert resolver.target == target_binding()


def test_one_shot_composition_rejects_disabled_executor() -> None:
    environment = _environment()
    environment["CONTROLGRAPH_MUTATIONS_ENABLED"] = "false"

    try:
        create_ambiguous_receipt_readback_resolver(
            environment=environment,
            root_reader=_RootReader(),
            receipt_store=_ReceiptStore(),
            operation_readback=_OperationReadback(),
            target_readback=_TargetReadback(),
        )
    except ValueError as error:
        assert "enabled executor" in str(error)
    else:
        raise AssertionError("disabled executor was admitted")


def test_readback_composition_has_no_provider_mutation_or_dispatch_import_surface() -> None:
    source = "\n".join(
        (
            inspect.getsource(resolver_module),
            inspect.getsource(composition_module),
        )
    )

    for forbidden in (
        "CloudRunV2Adapter",
        "MutationPermit",
        "FinalMutationGate",
        ".update(",
        ".mutate(",
    ):
        assert forbidden not in source
