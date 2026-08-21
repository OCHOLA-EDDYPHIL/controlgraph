from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from functools import cache

import pytest
from recovery_v2_test_data import (
    RecoveryV2Bundle,
    make_revoked_v2_recovery_bundle,
    make_unhealthy_v3_recovery_bundle,
)
from test_candidate_revision import _revision_configuration

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreOutcomeUnknown,
    StoredRecord,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunReadyState,
    CloudRunRevisionState,
    CloudRunServiceState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
    cloud_run_revision_configuration_sha256,
)
from controlgraph_canary.application.recovery_execution import (
    RecoveryExecutionError,
    RecoveryExecutionErrorCode,
    RecoveryRolloutCoordinator,
    _prestate_matches,
)
from controlgraph_canary.application.recovery_store import (
    DirectRecoveryEnqueueStart,
    RecoveryEnqueuePermit,
)
from controlgraph_canary.application.tasks import (
    AddressedTask,
    TaskEnqueueDisposition,
    TaskEnqueueResult,
    TaskRoute,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryAuthorizationV1,
    RecoveryCapabilityIssuanceResultV2,
    RecoveryCommandV2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchState,
    RecoveryIntentV1,
    RecoveryTaskRequestV2,
    create_recovery_intent,
    recovery_command_sha256,
)


@cache
def _recovery_bundle() -> RecoveryV2Bundle:
    return make_revoked_v2_recovery_bundle()


class _Resolver:
    def __init__(self, authorization: RecoveryAuthorizationV1) -> None:
        self.authorization = authorization
        self.calls = 0

    async def resolve(
        self,
        command: RecoveryCommandV2,
        *,
        now: datetime,
    ) -> RecoveryAuthorizationV1:
        assert command == self.authorization.prestate_attestation.result.request.command
        assert now.tzinfo is UTC
        self.calls += 1
        return self.authorization


class _CapabilityClient:
    def __init__(self, result: RecoveryCapabilityIssuanceResultV2) -> None:
        self.result = result
        self.calls = 0

    async def issue(
        self,
        command: RecoveryCommandV2,
        authorization: RecoveryAuthorizationV1,
    ) -> RecoveryCapabilityIssuanceResultV2:
        expected = (
            self.result.issuance_command.authorization.prestate_attestation.result.request.command
        )
        assert command == expected
        assert authorization == self.result.issuance_command.authorization
        self.calls += 1
        return self.result


class _DispatchStore:
    def __init__(self, bundle: RecoveryV2Bundle, *, ambiguous_start: bool = False) -> None:
        self.target = bundle.root.content.target
        self.intent: StoredRecord[RecoveryIntentV1] | None = None
        self.dispatch_record: StoredRecord[RecoveryDispatchRecordV2] | None = None
        self.ambiguous_start = ambiguous_start
        self.begin_calls = 0

    async def read_recovery_intent(
        self,
        root_sha256: str,
    ) -> StoredRecord[RecoveryIntentV1] | None:
        if self.intent is None or self.intent.value.root_sha256 != root_sha256:
            return None
        return self.intent

    async def create_or_adopt_recovery_intent(
        self,
        intent: RecoveryIntentV1,
    ) -> StoredRecord[RecoveryIntentV1]:
        proposed = StoredRecord(intent, 0)
        if self.intent is None:
            self.intent = proposed
        elif self.intent != proposed:
            raise AuthorityStoreConflict
        return self.intent

    async def read_recovery_dispatch(
        self,
        command: RecoveryCommandV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2] | None:
        if self.dispatch_record is None:
            return None
        if self.dispatch_record.value.command_sha256 != recovery_command_sha256(command):
            raise AuthorityStoreConflict
        return self.dispatch_record

    async def prepare_or_adopt_recovery_dispatch(
        self,
        intent: StoredRecord[RecoveryIntentV1],
        prepared: RecoveryDispatchRecordV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2]:
        assert intent == self.intent
        proposed = StoredRecord(prepared, 0)
        if self.dispatch_record is None:
            self.dispatch_record = proposed
        elif self.dispatch_record != proposed:
            raise AuthorityStoreConflict
        return self.dispatch_record

    async def compare_and_set_recovery_dispatch(
        self,
        expected: StoredRecord[RecoveryDispatchRecordV2],
        replacement: RecoveryDispatchRecordV2,
    ) -> StoredRecord[RecoveryDispatchRecordV2]:
        if self.dispatch_record != expected:
            raise AuthorityStoreConflict
        self.dispatch_record = StoredRecord(replacement, expected.revision + 1)
        return self.dispatch_record

    async def begin_recovery_enqueue(
        self,
        expected: StoredRecord[RecoveryDispatchRecordV2],
        replacement: RecoveryDispatchRecordV2,
    ) -> DirectRecoveryEnqueueStart:
        self.begin_calls += 1
        if self.dispatch_record != expected:
            raise AuthorityStoreConflict
        self.dispatch_record = StoredRecord(replacement, 1)
        if self.ambiguous_start:
            raise AuthorityStoreOutcomeUnknown
        return DirectRecoveryEnqueueStart(
            dispatch=self.dispatch_record,
            permit=RecoveryEnqueuePermit._from_direct_store_start(self.dispatch_record),
        )


class _TaskDispatcher:
    def __init__(self, bundle: RecoveryV2Bundle) -> None:
        self.bundle = bundle
        self.dispatch_calls = 0

    def prepare(
        self,
        request: RecoveryTaskRequestV2,
        *,
        now: datetime,
    ) -> AddressedTask:
        task_sha256 = canonical_sha256(request)
        parent = (
            f"projects/{request.intent.target.project_id}/locations/us-central1/"
            "queues/controlgraph-recovery"
        )
        return AddressedTask(
            route=TaskRoute.RECOVERY,
            parent=parent,
            name=f"{parent}/tasks/cg-{task_sha256}",
            handler_url=f"{request.handler_audience}/v1/internal/tasks/recover",
            audience=request.handler_audience,
            oidc_service_account=(
                "cg-recovery-task-caller@"
                f"{request.intent.target.project_id}.iam.gserviceaccount.com"
            ),
            scheduled_for=datetime.strptime(
                request.scheduled_at,
                "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=UTC),
            expires_at=datetime.strptime(
                request.expires_at,
                "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=UTC),
            body=b"sealed-recovery-task",
        )

    def dispatch_prepared_recovery(
        self,
        task: AddressedTask,
        *,
        permit: RecoveryEnqueuePermit,
        now: datetime,
    ) -> TaskEnqueueResult:
        permit._take(
            task_name=task.name,
            task_sha256=canonical_sha256(self.bundle.task),
        )
        self.dispatch_calls += 1
        return TaskEnqueueResult(
            task_name=task.name,
            disposition=TaskEnqueueDisposition.CREATED,
        )


def _coordinator(
    store: _DispatchStore,
    bundle: RecoveryV2Bundle | None = None,
) -> tuple[RecoveryRolloutCoordinator, _Resolver, _CapabilityClient, _TaskDispatcher]:
    selected_bundle = bundle or _recovery_bundle()
    resolver = _Resolver(selected_bundle.authorization)
    capability = _CapabilityClient(selected_bundle.issuance_result)
    dispatcher = _TaskDispatcher(selected_bundle)
    coordinator = RecoveryRolloutCoordinator(
        target=selected_bundle.root.content.target,
        authorization_resolver=resolver,
        capability_client=capability,
        dispatch_store=store,
        task_dispatcher=dispatcher,
        clock=lambda: datetime(2026, 8, 19, 12, 5, 11, tzinfo=UTC),
    )
    return coordinator, resolver, capability, dispatcher


def test_recovery_prestate_accepts_only_exact_hosted_tagged_traffic() -> None:
    bundle = make_revoked_v2_recovery_bundle()
    original = bundle.prestate_request
    target = original.target
    stable_configuration = _revision_configuration(
        target=target,
        concurrency=original.concurrency,
        image_digest="1" * 64,
    )
    candidate_configuration = _revision_configuration(
        target=target,
        concurrency=original.concurrency,
        image_digest="2" * 64,
    )
    request = original.model_copy(
        update={
            "stable_revision_configuration_sha256": (
                cloud_run_revision_configuration_sha256(stable_configuration)
            ),
            "candidate_revision_configuration_sha256": (
                cloud_run_revision_configuration_sha256(candidate_configuration)
            ),
        }
    )
    service_resource = (
        f"projects/{target.project_id}/locations/{target.region}/services/{target.service_name}"
    )
    service = CloudRunServiceState(
        target=target,
        resource_name=service_resource,
        uid="recovery-prestate-service-uid",
        etag="recovery-prestate-etag",
        generation=9,
        observed_generation=9,
        reconciling=False,
        ready_state=CloudRunReadyState.READY,
        latest_ready_revision=request.candidate_revision,
        latest_created_revision=request.candidate_revision,
        template_revision=request.candidate_revision,
        template_concurrency=request.concurrency,
        traffic=(
            CloudRunTrafficAllocation(
                revision=request.stable_revision,
                percent=90,
                tag="stable",
            ),
            CloudRunTrafficAllocation(
                revision=request.candidate_revision,
                percent=10,
                tag="candidate",
            ),
        ),
        traffic_statuses=(
            CloudRunTrafficStatus(
                revision=request.stable_revision,
                percent=90,
                tag="stable",
                uri=("https://stable---controlgraph-reference-target-abc-uc.a.run.app"),
            ),
            CloudRunTrafficStatus(
                revision=request.candidate_revision,
                percent=10,
                tag="candidate",
                uri=("https://candidate---controlgraph-reference-target-abc-uc.a.run.app"),
            ),
        ),
        uri="https://controlgraph-reference-target-abc-uc.a.run.app",
    )

    def revision(
        name: str,
        configuration: object,
    ) -> CloudRunRevisionState:
        return CloudRunRevisionState(
            target=target,
            revision=name,
            resource_name=f"{service_resource}/revisions/{name}",
            service_resource=service_resource,
            uid=f"{name}-uid",
            etag=f"{name}-etag",
            generation=1,
            observed_generation=1,
            reconciling=False,
            ready_state=CloudRunReadyState.READY,
            concurrency=request.concurrency,
            configuration=configuration,  # type: ignore[arg-type]
        )

    stable = revision(request.stable_revision, stable_configuration)
    candidate = revision(request.candidate_revision, candidate_configuration)
    assert _prestate_matches(request, service, stable, candidate)

    wrong_tag = replace(
        service,
        traffic=(
            replace(service.traffic[0], tag="candidate"),
            service.traffic[1],
        ),
    )
    assert not _prestate_matches(request, wrong_tag, stable, candidate)

    unsafe_uri = replace(
        service,
        traffic_statuses=(
            replace(
                service.traffic_statuses[0],
                uri="https://attacker.example.test",
            ),
            service.traffic_statuses[1],
        ),
    )
    assert not _prestate_matches(request, unsafe_uri, stable, candidate)


def test_recovery_coordinator_dispatches_once_and_adopts_terminal_result() -> None:
    async def scenario() -> None:
        bundle = _recovery_bundle()
        store = _DispatchStore(bundle)
        coordinator, resolver, capability, dispatcher = _coordinator(store)

        created = await coordinator.dispatch(bundle.command)
        replay = await coordinator.dispatch(bundle.command)

        assert created == replay
        assert created.enqueue_disposition == "CREATED"
        assert resolver.calls == 1
        assert capability.calls == 1
        assert dispatcher.dispatch_calls == 1
        assert store.begin_calls == 1
        assert store.dispatch_record is not None
        assert store.dispatch_record.revision == 2
        assert store.dispatch_record.value.state is RecoveryDispatchState.CREATED

    asyncio.run(scenario())


def test_unhealthy_v3_coordinator_adopts_atomic_intent_and_dispatches_once() -> None:
    async def scenario() -> None:
        bundle = make_unhealthy_v3_recovery_bundle()
        store = _DispatchStore(bundle)
        store.intent = StoredRecord(
            create_recovery_intent(
                bundle.command,
                created_at=bundle.command.source.triggered_at,
            ),
            0,
        )
        coordinator, resolver, capability, dispatcher = _coordinator(store, bundle)

        created = await coordinator.dispatch(bundle.command)
        replay = await coordinator.dispatch(bundle.command)

        assert created == replay
        assert created.root_schema_version == "controlgraph.rollout-root/v3"
        assert created.enqueue_disposition == "CREATED"
        assert resolver.calls == capability.calls == dispatcher.dispatch_calls == 1
        assert store.begin_calls == 1
        assert store.intent.value.command == bundle.command
        assert store.dispatch_record is not None
        assert store.dispatch_record.value.task == bundle.task

    asyncio.run(scenario())


def test_ambiguous_enqueue_start_is_never_retried_or_given_a_new_permit() -> None:
    async def scenario() -> None:
        bundle = _recovery_bundle()
        store = _DispatchStore(bundle, ambiguous_start=True)
        coordinator, _, _, dispatcher = _coordinator(store)

        with pytest.raises(RecoveryExecutionError) as first:
            await coordinator.dispatch(bundle.command)
        assert first.value.code is RecoveryExecutionErrorCode.OUTCOME_UNKNOWN
        assert dispatcher.dispatch_calls == 0
        assert store.begin_calls == 1
        assert store.dispatch_record is not None
        assert store.dispatch_record.value.state is RecoveryDispatchState.ENQUEUE_STARTED

        with pytest.raises(RecoveryExecutionError) as replay:
            await coordinator.dispatch(bundle.command)
        assert replay.value.code is RecoveryExecutionErrorCode.OUTCOME_UNKNOWN
        assert dispatcher.dispatch_calls == 0
        assert store.begin_calls == 1

    asyncio.run(scenario())


def test_root_owned_recovery_intent_denies_a_conflicting_command() -> None:
    async def scenario() -> None:
        bundle = _recovery_bundle()
        store = _DispatchStore(bundle)
        alternate = RecoveryCommandV2.model_validate(
            {
                **bundle.command.model_dump(mode="python"),
                "request_id": "conflicting-recovery-request",
                "idempotency_key": "conflicting-recovery-key",
            }
        )
        store.intent = StoredRecord(
            create_recovery_intent(
                alternate,
                created_at=alternate.source.triggered_at,
            ),
            0,
        )
        coordinator, resolver, capability, dispatcher = _coordinator(store)

        with pytest.raises(RecoveryExecutionError) as denied:
            await coordinator.dispatch(bundle.command)
        assert denied.value.code is RecoveryExecutionErrorCode.IDENTITY_CONFLICT
        assert resolver.calls == 0
        assert capability.calls == 0
        assert dispatcher.dispatch_calls == 0

    asyncio.run(scenario())
