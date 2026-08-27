"""Executor-only composition for the one-shot ambiguous receipt resolver."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime

from controlgraph_canary.application.ambiguous_receipt_readback import (
    AmbiguousReceiptReadbackResolver,
    AmbiguousReceiptResolutionStore,
    TargetBoundProviderOperationReadback,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunMutationPurpose,
    CloudRunTargetConfiguration,
)
from controlgraph_canary.application.identity import (
    RECEIPT_AUTHORITY_PATH,
    RECOVERY_RECEIPT_AUTHORITY_PATH,
    CallerRole,
    ServiceRole,
)
from controlgraph_canary.application.receipt_authority import ReceiptAuthorityClient
from controlgraph_canary.application.receipt_execution import (
    TargetBoundReceiptReadback,
)
from controlgraph_canary.application.root_authority import RootAuthorityBundleReader
from controlgraph_canary.application.root_trust import (
    CanonicalInternalTransport,
    CoordinatorInternalRoute,
)
from controlgraph_canary.contracts.models import CapabilityAction, TargetBinding
from controlgraph_canary.integrations.google.cloud_run import (
    CloudRunV2OperationReadback,
    CloudRunV2ReceiptReadback,
    ReadOnlyOperationsClientFactory,
    ReadOnlyServicesClientFactory,
)
from controlgraph_canary.integrations.google.firestore import FirestoreAuthorityStore
from controlgraph_canary.integrations.google.internal_transport import (
    GoogleOneShotOidcTransport,
)
from controlgraph_canary.settings import ControllerSettings


def create_ambiguous_receipt_readback_resolver(
    *,
    action: CapabilityAction,
    environment: Mapping[str, str] | None = None,
    root_reader: RootAuthorityBundleReader | None = None,
    receipt_store: AmbiguousReceiptResolutionStore | None = None,
    operation_readback: TargetBoundProviderOperationReadback | None = None,
    target_readback: TargetBoundReceiptReadback | None = None,
    internal_transport: CanonicalInternalTransport | None = None,
    operations_client_factory: ReadOnlyOperationsClientFactory | None = None,
    services_client_factory: ReadOnlyServicesClientFactory | None = None,
    clock: Callable[[], datetime] | None = None,
) -> AmbiguousReceiptReadbackResolver:
    """Compose only the read/CAS dependencies available to the executor identity."""

    if type(action) is not CapabilityAction or action not in {
        CapabilityAction.APPLY_CANARY,
        CapabilityAction.RECOVER_STABLE,
    }:
        raise ValueError("ambiguous receipt readback action is not supported")
    settings = ControllerSettings.from_environment(environment)
    if settings.role != ServiceRole.EXECUTOR.value or not settings.mutations_enabled:
        raise ValueError("ambiguous receipt readback requires the enabled executor role")
    if (
        settings.coordinator_url is None
        or settings.target_network_resource is None
        or settings.target_subnetwork_resource is None
    ):
        raise ValueError("ambiguous receipt readback executor configuration is incomplete")
    target = _reference_target(settings)
    cloud_run_configuration = CloudRunTargetConfiguration(
        target=target,
        stable_revision="controlgraph-reference-target-stable-v15",
        candidate_revision="controlgraph-reference-target-candidate-v15",
        stable_concurrency=8,
        candidate_concurrency=8,
        network_resource=settings.target_network_resource,
        subnetwork_resource=settings.target_subnetwork_resource,
    )
    selected_root_reader = root_reader
    if selected_root_reader is None:
        selected_root_reader = FirestoreAuthorityStore(
            target=target,
            configured_project_id=settings.project_id,
        )
    selected_receipt_store = receipt_store
    if selected_receipt_store is None:
        receipt_authority_path = (
            RECOVERY_RECEIPT_AUTHORITY_PATH
            if action is CapabilityAction.RECOVER_STABLE
            else RECEIPT_AUTHORITY_PATH
        )
        selected_transport = internal_transport or GoogleOneShotOidcTransport(
            project_id=settings.project_id,
            caller_role=CallerRole.EXECUTOR,
        )
        selected_receipt_store = ReceiptAuthorityClient(
            target=target,
            route=CoordinatorInternalRoute(
                project_id=settings.project_id,
                project_number=settings.project_number,
                caller_role=CallerRole.EXECUTOR,
                service_role=ServiceRole.COORDINATOR,
                audience=settings.coordinator_url,
                override_path=receipt_authority_path,
            ),
            transport=selected_transport,
        )
    selected_operation_readback = operation_readback or CloudRunV2OperationReadback(
        target=target,
        configured_project_id=settings.project_id,
        operations_client_factory=operations_client_factory,
    )
    selected_target_readback = target_readback or CloudRunV2ReceiptReadback(
        configuration=cloud_run_configuration,
        configured_project_id=settings.project_id,
        mutation_purpose=(
            CloudRunMutationPurpose.STABLE_RECOVERY
            if action is CapabilityAction.RECOVER_STABLE
            else CloudRunMutationPurpose.STANDARD_EXECUTION
        ),
        services_client_factory=services_client_factory,
    )
    return AmbiguousReceiptReadbackResolver(
        root_reader=selected_root_reader,
        receipt_store=selected_receipt_store,
        operation_readback=selected_operation_readback,
        target_readback=selected_target_readback,
        clock=clock,
    )


def _reference_target(settings: ControllerSettings) -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=settings.project_id,
        region=settings.region,
        environment=settings.environment,
        service_name="controlgraph-reference-target",
    )


__all__ = ["create_ambiguous_receipt_readback_resolver"]
