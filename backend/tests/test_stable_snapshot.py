from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import replace
from datetime import UTC, datetime
from functools import wraps
from typing import Any

import pytest

from controlgraph_canary.application.cloud_run import (
    CloudRunExecutionEnvironment,
    CloudRunHttpProbe,
    CloudRunNetworkInterface,
    CloudRunReadError,
    CloudRunReadErrorCode,
    CloudRunReadyState,
    CloudRunRevisionConfiguration,
    CloudRunRevisionState,
    CloudRunServiceState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
    CloudRunVpcEgress,
    cloud_run_revision_configuration_sha256,
)
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.application.stable_snapshot import (
    MAX_STABLE_CAPTURE_ATTEMPTS,
    STABLE_CONFIGURATION_DOMAIN,
    STABLE_CONFIGURATION_V1,
    StableCaptureError,
    StableCaptureReason,
    StableSnapshotCaptureConfiguration,
    StableSnapshotCapturer,
    StableSnapshotReader,
    stable_configuration_sha256,
)
from controlgraph_canary.contracts.models import TargetBinding, TrafficAllocation

PROJECT_ID = "controlgraph-canary-a1b2c3"
SERVICE = "controlgraph-reference-target"
STABLE = f"{SERVICE}-stable-v14"
CANDIDATE = f"{SERVICE}-candidate-v14"
SERVICE_RESOURCE = f"projects/{PROJECT_ID}/locations/us-central1/services/{SERVICE}"
READER_IDENTITY = f"controlgraph-verifier@{PROJECT_ID}.iam.gserviceaccount.com"
NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
IMAGE = (
    f"us-central1-docker.pkg.dev/{PROJECT_ID}/controlgraph-images/reference-target"
    f"@sha256:{'1' * 64}"
)


def _async_test[**P](
    function: Callable[P, Coroutine[Any, Any, None]],
) -> Callable[P, None]:
    @wraps(function)
    def run(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(function(*args, **kwargs))

    return run


def _target(**changes: str) -> TargetBinding:
    values = {
        "schema_version": "controlgraph.target-binding/v1",
        "project_id": PROJECT_ID,
        "region": "us-central1",
        "environment": "acceptance",
        "service_name": SERVICE,
    }
    values.update(changes)
    return TargetBinding(**values)  # type: ignore[arg-type]


def _revision_configuration(**changes: object) -> CloudRunRevisionConfiguration:
    values: dict[str, object] = {
        "image": IMAGE,
        "service_account": (
            f"controlgraph-reference@{PROJECT_ID}.iam.gserviceaccount.com"
        ),
        "execution_environment": CloudRunExecutionEnvironment.GEN2,
        "timeout_seconds": 5,
        "concurrency": 8,
        "min_instance_count": 0,
        "max_instance_count": 1,
        "container_name": "reference-target",
        "command": (),
        "args": (),
        "working_dir": None,
        "port_name": "http1",
        "container_port": 8080,
        "cpu_limit": "1",
        "memory_limit": "512Mi",
        "cpu_idle": True,
        "startup_cpu_boost": False,
        "startup_probe": CloudRunHttpProbe(
            path="/healthz",
            port=8080,
            initial_delay_seconds=0,
            timeout_seconds=2,
            period_seconds=5,
            failure_threshold=12,
        ),
        "liveness_probe": CloudRunHttpProbe(
            path="/healthz",
            port=8080,
            initial_delay_seconds=5,
            timeout_seconds=2,
            period_seconds=10,
            failure_threshold=3,
        ),
        "vpc_connector": None,
        "vpc_egress": CloudRunVpcEgress.ALL_TRAFFIC,
        "network_interfaces": (
            CloudRunNetworkInterface(
                network="projects/controlgraph-canary-a1b2c3/global/networks/controlgraph",
                subnetwork=(
                    "projects/controlgraph-canary-a1b2c3/regions/us-central1/"
                    "subnetworks/controlgraph"
                ),
                tags=(),
            ),
        ),
    }
    values.update(changes)
    return CloudRunRevisionConfiguration(**values)  # type: ignore[arg-type]


def _service(
    *,
    target: TargetBinding | None = None,
    generation: int = 7,
    observed_generation: int | None = None,
    etag: str | None = None,
    uid: str = "service-uid-001",
    reconciling: bool = False,
    ready_state: CloudRunReadyState = CloudRunReadyState.READY,
    traffic: tuple[tuple[str, int], ...] = ((STABLE, 100),),
    status_traffic: tuple[tuple[str, int], ...] | None = None,
    tags: tuple[str | None, ...] | None = None,
    status_tags: tuple[str | None, ...] | None = None,
    latest_ready_revision: str = CANDIDATE,
    latest_created_revision: str = CANDIDATE,
    template_revision: str = CANDIDATE,
    uri: str = "https://reference-target.example.test",
) -> CloudRunServiceState:
    selected_target = target or _target()
    selected_status = traffic if status_traffic is None else status_traffic
    selected_tags = (
        tuple(f"route-{index}" for index in range(len(traffic)))
        if tags is None
        else tags
    )
    selected_status_tags = selected_tags if status_tags is None else status_tags
    return CloudRunServiceState(
        target=selected_target,
        resource_name=(
            f"projects/{selected_target.project_id}/locations/{selected_target.region}/services/"
            f"{selected_target.service_name}"
        ),
        uid=uid,
        etag=etag or f"service-etag-{generation}",
        generation=generation,
        observed_generation=(
            generation if observed_generation is None else observed_generation
        ),
        reconciling=reconciling,
        ready_state=ready_state,
        latest_ready_revision=latest_ready_revision,
        latest_created_revision=latest_created_revision,
        template_revision=template_revision,
        template_concurrency=8,
        traffic=tuple(
            CloudRunTrafficAllocation(revision=revision, percent=percent, tag=tag)
            for (revision, percent), tag in zip(traffic, selected_tags, strict=True)
        ),
        traffic_statuses=tuple(
            CloudRunTrafficStatus(
                revision=revision,
                percent=percent,
                tag=tag,
                uri=None if tag is None else f"https://{tag}.example.test",
            )
            for (revision, percent), tag in zip(
                selected_status,
                selected_status_tags,
                strict=True,
            )
        ),
        uri=uri,
    )


def _revision(
    *,
    target: TargetBinding | None = None,
    revision: str = STABLE,
    generation: int = 1,
    observed_generation: int | None = None,
    etag: str = "stable-revision-etag-1",
    uid: str = "stable-revision-uid-001",
    reconciling: bool = False,
    ready_state: CloudRunReadyState = CloudRunReadyState.READY,
    concurrency: int = 8,
    configuration: CloudRunRevisionConfiguration | None = None,
) -> CloudRunRevisionState:
    selected_target = target or _target()
    selected_configuration = configuration or _revision_configuration(
        image=IMAGE.replace(PROJECT_ID, selected_target.project_id),
        service_account=(
            f"controlgraph-reference@{selected_target.project_id}.iam.gserviceaccount.com"
        ),
        concurrency=concurrency,
    )
    service_resource = (
        f"projects/{selected_target.project_id}/locations/{selected_target.region}/services/"
        f"{selected_target.service_name}"
    )
    return CloudRunRevisionState(
        target=selected_target,
        revision=revision,
        resource_name=f"{service_resource}/revisions/{revision}",
        service_resource=service_resource,
        uid=uid,
        etag=etag,
        generation=generation,
        observed_generation=(
            generation if observed_generation is None else observed_generation
        ),
        reconciling=reconciling,
        ready_state=ready_state,
        concurrency=concurrency,
        configuration=selected_configuration,
    )


class _FakeReader:
    def __init__(
        self,
        services: list[object],
        revisions: list[object],
        *,
        target: TargetBinding | None = None,
        service_role: ServiceRole = ServiceRole.VERIFIER,
    ) -> None:
        self._target = target or _target()
        self._service_role = service_role
        self.services = list(services)
        self.revisions = list(revisions)
        self.calls: list[str] = []
        self.mutation_calls = 0

    @property
    def target(self) -> TargetBinding:
        return self._target

    @property
    def service_role(self) -> ServiceRole:
        return self._service_role

    @property
    def reader_identity(self) -> str:
        return f"controlgraph-verifier@{self.target.project_id}.iam.gserviceaccount.com"

    async def read_service(self) -> CloudRunServiceState:
        self.calls.append("service")
        value = self.services.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value  # type: ignore[return-value]

    async def read_revision(self, revision_name: str) -> CloudRunRevisionState:
        self.calls.append(f"revision:{revision_name}")
        value = self.revisions.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value  # type: ignore[return-value]

    async def mutate(self, _value: object) -> None:
        self.mutation_calls += 1
        raise AssertionError("stable snapshot capture cannot mutate the provider")


def _capturer(
    reader: _FakeReader,
    *,
    configuration: StableSnapshotCaptureConfiguration | None = None,
    clock: Callable[[], datetime] | None = None,
) -> StableSnapshotCapturer:
    return StableSnapshotCapturer(
        reader=reader,
        configuration=configuration
        or StableSnapshotCaptureConfiguration(
            target=_target(),
            reader_identity=READER_IDENTITY,
        ),
        clock=clock or (lambda: NOW),
    )


@_async_test
async def test_capture_uses_two_matching_reads_and_ignores_mutable_aliases() -> None:
    first = _service(
        tags=(None,),
        status_tags=("old-stable-alias",),
        latest_ready_revision=CANDIDATE,
        template_revision=CANDIDATE,
    )
    second = _service(
        tags=("new-stable-alias",),
        status_tags=(None,),
        latest_ready_revision=STABLE,
        latest_created_revision=STABLE,
        template_revision=STABLE,
        uri="https://changed-display.example.test",
    )
    reader = _FakeReader([first, second], [_revision()])

    snapshot = await _capturer(reader).capture()

    assert snapshot.target == _target()
    assert snapshot.stable_revision == STABLE
    assert snapshot.traffic == (TrafficAllocation(revision=STABLE, percent=100),)
    assert snapshot.concurrency == 8
    assert snapshot.service_generation == 7
    assert snapshot.provider_etag == "service-etag-7"
    assert snapshot.configuration_sha256 == (
            "3694b28654b6159e735f5932a313168042b617d8bb2f87d6efc797fdbf228442"
    )
    assert snapshot.stable_revision_configuration_sha256 == (
        cloud_run_revision_configuration_sha256(_revision_configuration())
    )
    assert snapshot.captured_at == "2026-08-19T12:00:00Z"
    assert snapshot.captured_by == READER_IDENTITY
    assert reader.calls == ["service", f"revision:{STABLE}", "service"]
    assert reader.mutation_calls == 0


@_async_test
async def test_capture_reads_the_single_positive_revision_name_not_a_declared_alias() -> None:
    service = _service(traffic=((CANDIDATE, 100),), template_revision=STABLE)
    reader = _FakeReader(
        [service, service],
        [
            _revision(
                revision=CANDIDATE,
                etag="candidate-revision-etag-1",
                uid="candidate-revision-uid-001",
            )
        ],
    )

    snapshot = await _capturer(reader).capture()

    assert snapshot.stable_revision == CANDIDATE
    assert snapshot.traffic == (TrafficAllocation(revision=CANDIDATE, percent=100),)
    assert reader.calls == ["service", f"revision:{CANDIDATE}", "service"]
    assert reader.mutation_calls == 0


@_async_test
async def test_capture_preserves_optional_zero_percent_candidate() -> None:
    service = _service(
        traffic=((STABLE, 100), (CANDIDATE, 0)),
        tags=("stable", "candidate"),
    )
    reader = _FakeReader([service, service], [_revision()])

    snapshot = await _capturer(reader).capture()

    assert snapshot.traffic == (
        TrafficAllocation(revision=STABLE, percent=100),
        TrafficAllocation(revision=CANDIDATE, percent=0),
    )
    assert snapshot.configuration_sha256 != (
        "7382be29340b9a7b0703bec0e2f589010ce61c81ccae9735dc41dc2e5ced70fe"
    )
    assert reader.mutation_calls == 0


@_async_test
async def test_generation_change_restarts_the_complete_capture() -> None:
    generation_seven = _service(generation=7)
    generation_eight = _service(generation=8)
    reader = _FakeReader(
        [generation_seven, generation_eight, generation_eight, generation_eight],
        [_revision(), _revision()],
    )

    snapshot = await _capturer(reader).capture()

    assert snapshot.service_generation == 8
    assert snapshot.provider_etag == "service-etag-8"
    assert reader.calls == [
        "service",
        f"revision:{STABLE}",
        "service",
        "service",
        f"revision:{STABLE}",
        "service",
    ]
    assert reader.mutation_calls == 0


@pytest.mark.parametrize(
    "changed",
    [
        _service(etag="service-etag-other"),
        _service(uid="service-uid-other"),
        _service(traffic=((STABLE, 90), (CANDIDATE, 10))),
        _service(reconciling=True),
    ],
)
@_async_test
async def test_any_source_version_or_baseline_change_restarts_capture(
    changed: CloudRunServiceState,
) -> None:
    stable = _service()
    reader = _FakeReader(
        [stable, changed, stable, stable],
        [_revision(), _revision()],
    )

    snapshot = await _capturer(reader).capture()

    assert snapshot.service_generation == stable.generation
    assert snapshot.provider_etag == stable.etag
    assert reader.calls == [
        "service",
        f"revision:{STABLE}",
        "service",
        "service",
        f"revision:{STABLE}",
        "service",
    ]
    assert reader.mutation_calls == 0


@_async_test
async def test_source_change_restarts_are_bounded_without_mutation() -> None:
    services: list[object] = []
    revisions: list[object] = []
    for generation in range(1, MAX_STABLE_CAPTURE_ATTEMPTS + 1):
        services.extend(
            [
                _service(generation=generation),
                _service(generation=generation + 1),
            ]
        )
        revisions.append(_revision())
    reader = _FakeReader(services, revisions)

    with pytest.raises(StableCaptureError) as failure:
        await _capturer(reader).capture()

    assert failure.value.reason is StableCaptureReason.SOURCE_CHANGED
    assert reader.calls.count("service") == MAX_STABLE_CAPTURE_ATTEMPTS * 2
    assert reader.calls.count(f"revision:{STABLE}") == MAX_STABLE_CAPTURE_ATTEMPTS
    assert reader.mutation_calls == 0


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (
            CloudRunReadError(CloudRunReadErrorCode.NOT_FOUND),
            StableCaptureReason.SERVICE_MISSING,
        ),
        (
            CloudRunReadError(CloudRunReadErrorCode.UNAVAILABLE),
            StableCaptureReason.SOURCE_UNAVAILABLE,
        ),
        (
            CloudRunReadError(CloudRunReadErrorCode.CORRUPT_RESPONSE),
            StableCaptureReason.SOURCE_INVALID,
        ),
        (RuntimeError("synthetic provider detail"), StableCaptureReason.SOURCE_UNAVAILABLE),
        (object(), StableCaptureReason.SOURCE_INVALID),
    ],
)
@_async_test
async def test_service_read_failures_have_closed_sanitized_reasons(
    source: object,
    reason: StableCaptureReason,
) -> None:
    reader = _FakeReader([source], [])

    with pytest.raises(StableCaptureError) as failure:
        await _capturer(reader).capture()

    assert failure.value.reason is reason
    assert str(failure.value) == reason.value
    assert failure.value.__cause__ is None
    assert "synthetic provider detail" not in str(failure.value)
    assert reader.mutation_calls == 0


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (
            CloudRunReadError(CloudRunReadErrorCode.NOT_FOUND),
            StableCaptureReason.REVISION_MISSING,
        ),
        (
            CloudRunReadError(CloudRunReadErrorCode.UNAVAILABLE),
            StableCaptureReason.SOURCE_UNAVAILABLE,
        ),
        (
            CloudRunReadError(CloudRunReadErrorCode.CORRUPT_RESPONSE),
            StableCaptureReason.SOURCE_INVALID,
        ),
        (RuntimeError("synthetic revision detail"), StableCaptureReason.SOURCE_UNAVAILABLE),
        (object(), StableCaptureReason.SOURCE_INVALID),
    ],
)
@_async_test
async def test_revision_read_failures_have_closed_sanitized_reasons(
    source: object,
    reason: StableCaptureReason,
) -> None:
    reader = _FakeReader([_service()], [source])

    with pytest.raises(StableCaptureError) as failure:
        await _capturer(reader).capture()

    assert failure.value.reason is reason
    assert str(failure.value) == reason.value
    assert failure.value.__cause__ is None
    assert "synthetic revision detail" not in str(failure.value)
    assert reader.mutation_calls == 0


@pytest.mark.parametrize(
    ("service", "reason"),
    [
        (_service(reconciling=True), StableCaptureReason.SERVICE_NOT_READY),
        (
            _service(generation=7, observed_generation=6),
            StableCaptureReason.SERVICE_NOT_READY,
        ),
        (
            _service(ready_state=CloudRunReadyState.NOT_READY),
            StableCaptureReason.SERVICE_NOT_READY,
        ),
        (
            _service(ready_state=CloudRunReadyState.FAILED),
            StableCaptureReason.SERVICE_NOT_READY,
        ),
        (
            _service(
                traffic=((STABLE, 100), (CANDIDATE, 0)),
                status_traffic=((STABLE, 0), (CANDIDATE, 100)),
            ),
            StableCaptureReason.TRAFFIC_UNRESOLVED,
        ),
        (
            _service(traffic=((STABLE, 90), (CANDIDATE, 10))),
            StableCaptureReason.BASELINE_NOT_STABLE,
        ),
        (
            _service(traffic=(("unrelated-service-stable-v1", 100),)),
            StableCaptureReason.TRAFFIC_UNSUPPORTED,
        ),
    ],
)
@_async_test
async def test_ineligible_service_baselines_are_rejected(
    service: CloudRunServiceState,
    reason: StableCaptureReason,
) -> None:
    reader = _FakeReader([service], [_revision()])

    with pytest.raises(StableCaptureError) as failure:
        await _capturer(reader).capture()

    assert failure.value.reason is reason
    assert reader.calls == ["service"]
    assert reader.mutation_calls == 0


@pytest.mark.parametrize(
    ("revision", "reason"),
    [
        (
            _revision(revision=CANDIDATE),
            StableCaptureReason.TRAFFIC_UNRESOLVED,
        ),
        (
            _revision(target=_target(project_id="controlgraph-canary-b2c3d4")),
            StableCaptureReason.TARGET_MISMATCH,
        ),
        (
            _revision(reconciling=True),
            StableCaptureReason.REVISION_NOT_READY,
        ),
        (
            _revision(generation=2, observed_generation=1),
            StableCaptureReason.REVISION_NOT_READY,
        ),
        (
            _revision(ready_state=CloudRunReadyState.NOT_READY),
            StableCaptureReason.REVISION_NOT_READY,
        ),
        (
            _revision(ready_state=CloudRunReadyState.FAILED),
            StableCaptureReason.REVISION_NOT_READY,
        ),
    ],
)
@_async_test
async def test_unresolved_or_unready_stable_revision_is_rejected(
    revision: CloudRunRevisionState,
    reason: StableCaptureReason,
) -> None:
    reader = _FakeReader([_service()], [revision])

    with pytest.raises(StableCaptureError) as failure:
        await _capturer(reader).capture()

    assert failure.value.reason is reason
    assert reader.mutation_calls == 0


@_async_test
async def test_provider_target_substitution_is_rejected() -> None:
    other_target = _target(project_id="controlgraph-canary-b2c3d4")
    reader = _FakeReader([_service(target=other_target)], [_revision()])

    with pytest.raises(StableCaptureError) as failure:
        await _capturer(reader).capture()

    assert failure.value.reason is StableCaptureReason.TARGET_MISMATCH
    assert reader.mutation_calls == 0


@_async_test
async def test_second_read_target_substitution_is_not_retried() -> None:
    other_target = _target(project_id="controlgraph-canary-b2c3d4")
    reader = _FakeReader(
        [_service(), _service(target=other_target)],
        [_revision()],
    )

    with pytest.raises(StableCaptureError) as failure:
        await _capturer(reader).capture()

    assert failure.value.reason is StableCaptureReason.TARGET_MISMATCH
    assert reader.calls == ["service", f"revision:{STABLE}", "service"]


@_async_test
async def test_cancellation_propagates_without_mutation() -> None:
    reader = _FakeReader([asyncio.CancelledError()], [])

    with pytest.raises(asyncio.CancelledError):
        await _capturer(reader).capture()

    assert reader.mutation_calls == 0


def test_configuration_digest_binds_immutable_revision_and_serving_state() -> None:
    service = _service()
    revision = _revision()
    traffic = (TrafficAllocation(revision=STABLE, percent=100),)
    baseline = stable_configuration_sha256(service, revision, traffic)

    changes = (
        (_service(uid="service-uid-002"), revision, traffic),
        (service, replace(revision, uid="stable-revision-uid-002"), traffic),
        (service, replace(revision, etag="stable-revision-etag-2"), traffic),
        (
            service,
            replace(revision, generation=2, observed_generation=2),
            traffic,
        ),
        (
            service,
            replace(
                revision,
                concurrency=9,
                configuration=replace(revision.configuration, concurrency=9),
            ),
            traffic,
        ),
        (
            service,
            replace(
                revision,
                configuration=replace(
                    revision.configuration,
                    image=revision.configuration.image.replace("1" * 64, "2" * 64),
                ),
            ),
            traffic,
        ),
        (
            _service(traffic=((STABLE, 100), (CANDIDATE, 0))),
            revision,
            (
                TrafficAllocation(revision=STABLE, percent=100),
                TrafficAllocation(revision=CANDIDATE, percent=0),
            ),
        ),
    )

    assert STABLE_CONFIGURATION_V1 == "controlgraph.stable-configuration/v1"
    assert STABLE_CONFIGURATION_DOMAIN == b"controlgraph.stable-configuration-sha256/v1\0"
    assert baseline == "3694b28654b6159e735f5932a313168042b617d8bb2f87d6efc797fdbf228442"
    assert all(
        stable_configuration_sha256(changed_service, changed_revision, changed_traffic)
        != baseline
        for changed_service, changed_revision, changed_traffic in changes
    )


@pytest.mark.parametrize(
    "changed",
    [
        _revision_configuration(image=IMAGE.replace("1" * 64, "2" * 64)),
        _revision_configuration(
            service_account=(
                "controlgraph-reference@controlgraph-canary-b2c3d4.iam.gserviceaccount.com"
            )
        ),
        _revision_configuration(execution_environment=CloudRunExecutionEnvironment.GEN1),
        _revision_configuration(timeout_seconds=6),
        _revision_configuration(concurrency=9),
        _revision_configuration(min_instance_count=1),
        _revision_configuration(max_instance_count=2),
        _revision_configuration(container_name="reference-target-v2"),
        _revision_configuration(command=("/app/reference-target",)),
        _revision_configuration(args=("--synthetic",)),
        _revision_configuration(working_dir="/app"),
        _revision_configuration(port_name="http2"),
        _revision_configuration(
            container_port=8081,
            startup_probe=CloudRunHttpProbe(
                path="/healthz",
                port=8081,
                initial_delay_seconds=0,
                timeout_seconds=2,
                period_seconds=5,
                failure_threshold=12,
            ),
            liveness_probe=CloudRunHttpProbe(
                path="/healthz",
                port=8081,
                initial_delay_seconds=5,
                timeout_seconds=2,
                period_seconds=10,
                failure_threshold=3,
            ),
        ),
        _revision_configuration(cpu_limit="2"),
        _revision_configuration(memory_limit="1Gi"),
        _revision_configuration(cpu_idle=False),
        _revision_configuration(startup_cpu_boost=True),
        _revision_configuration(
            startup_probe=CloudRunHttpProbe(
                path="/ready",
                port=8080,
                initial_delay_seconds=0,
                timeout_seconds=2,
                period_seconds=5,
                failure_threshold=12,
            )
        ),
        _revision_configuration(
            startup_probe=replace(
                _revision_configuration().startup_probe,
                initial_delay_seconds=1,
            )
        ),
        _revision_configuration(
            startup_probe=replace(
                _revision_configuration().startup_probe,
                timeout_seconds=3,
            )
        ),
        _revision_configuration(
            startup_probe=replace(
                _revision_configuration().startup_probe,
                period_seconds=6,
            )
        ),
        _revision_configuration(
            startup_probe=replace(
                _revision_configuration().startup_probe,
                failure_threshold=13,
            )
        ),
        _revision_configuration(
            liveness_probe=CloudRunHttpProbe(
                path="/live",
                port=8080,
                initial_delay_seconds=5,
                timeout_seconds=2,
                period_seconds=10,
                failure_threshold=3,
            )
        ),
        _revision_configuration(
            liveness_probe=replace(
                _revision_configuration().liveness_probe,
                initial_delay_seconds=6,
            )
        ),
        _revision_configuration(
            liveness_probe=replace(
                _revision_configuration().liveness_probe,
                timeout_seconds=3,
            )
        ),
        _revision_configuration(
            liveness_probe=replace(
                _revision_configuration().liveness_probe,
                period_seconds=11,
            )
        ),
        _revision_configuration(
            liveness_probe=replace(
                _revision_configuration().liveness_probe,
                failure_threshold=4,
            )
        ),
        _revision_configuration(
            vpc_connector=(
                "projects/controlgraph-canary-a1b2c3/locations/us-central1/"
                "connectors/controlgraph"
            ),
            network_interfaces=(),
        ),
        _revision_configuration(vpc_egress=CloudRunVpcEgress.PRIVATE_RANGES_ONLY),
        _revision_configuration(
            network_interfaces=(
                CloudRunNetworkInterface(
                    network="projects/controlgraph-canary-a1b2c3/global/networks/other",
                    subnetwork=(
                        "projects/controlgraph-canary-a1b2c3/regions/us-central1/"
                        "subnetworks/controlgraph"
                    ),
                    tags=(),
                ),
            )
        ),
        _revision_configuration(
            network_interfaces=(
                replace(
                    _revision_configuration().network_interfaces[0],
                    subnetwork=(
                        "projects/controlgraph-canary-a1b2c3/regions/us-central1/"
                        "subnetworks/other"
                    ),
                ),
            )
        ),
        _revision_configuration(
            network_interfaces=(
                replace(
                    _revision_configuration().network_interfaces[0],
                    tags=("egress",),
                ),
            )
        ),
    ],
)
def test_immutable_revision_configuration_digest_binds_every_admitted_field(
    changed: CloudRunRevisionConfiguration,
) -> None:
    baseline = _revision_configuration()

    assert cloud_run_revision_configuration_sha256(changed) != (
        cloud_run_revision_configuration_sha256(baseline)
    )


def test_configuration_digest_excludes_mutable_display_and_alias_fields() -> None:
    service = _service(tags=("stable",), status_tags=("stable",))
    display_changed = _service(
        tags=("renamed",),
        status_tags=("renamed",),
        latest_ready_revision=STABLE,
        latest_created_revision=STABLE,
        template_revision=STABLE,
        uri="https://different-display.example.test",
    )
    traffic = (TrafficAllocation(revision=STABLE, percent=100),)

    assert stable_configuration_sha256(service, _revision(), traffic) == (
        stable_configuration_sha256(display_changed, _revision(), traffic)
    )


def test_configuration_digest_rejects_unbound_or_nonstable_state() -> None:
    service = _service()
    revision = _revision()

    with pytest.raises(ValueError, match="exact baseline"):
        stable_configuration_sha256(
            service,
            revision,
            (TrafficAllocation(revision=CANDIDATE, percent=100),),
        )
    with pytest.raises(ValueError, match="exact baseline"):
        stable_configuration_sha256(
            _service(traffic=((STABLE, 90), (CANDIDATE, 10))),
            revision,
            (TrafficAllocation(revision=STABLE, percent=100),),
        )
    with pytest.raises(ValueError, match="exact baseline"):
        stable_configuration_sha256(
            service,
            _revision(target=_target(project_id="controlgraph-canary-b2c3d4")),
            (TrafficAllocation(revision=STABLE, percent=100),),
        )


@pytest.mark.parametrize(
    "target",
    [
        _target(project_id="shared-project-a1b2c3"),
        _target(region="europe-west1"),
        _target(service_name="another-service"),
        _target(environment="reconcile.production"),
    ],
)
def test_capture_configuration_rejects_out_of_boundary_targets(target: TargetBinding) -> None:
    with pytest.raises(ValueError, match="outside the ControlGraph boundary"):
        StableSnapshotCaptureConfiguration(
            target=target,
            reader_identity=f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com",
        )


def test_capture_configuration_requires_exact_authenticated_verifier() -> None:
    for identity in (
        f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com",
        "controlgraph-verifier@controlgraph-canary-b2c3d4.iam.gserviceaccount.com",
        "controlgraph.verifier/v1",
    ):
        with pytest.raises(ValueError, match="configured verifier"):
            StableSnapshotCaptureConfiguration(
                target=_target(),
                reader_identity=identity,
            )


def test_capturer_requires_reader_bound_to_the_same_target() -> None:
    other_target = _target(project_id="controlgraph-canary-b2c3d4")
    reader = _FakeReader([], [], target=other_target)

    with pytest.raises(ValueError, match="configured target"):
        _capturer(reader)


@pytest.mark.parametrize("role", [ServiceRole.EXECUTOR, ServiceRole.RECOVERY])
def test_capturer_rejects_mutation_capable_reader_roles(role: ServiceRole) -> None:
    reader = _FakeReader([], [], service_role=role)

    with pytest.raises(ValueError, match="configured target"):
        _capturer(reader)


@_async_test
async def test_invalid_clock_is_rejected_after_matching_reads() -> None:
    service = _service()
    reader = _FakeReader([service, service], [_revision()])

    with pytest.raises(ValueError, match="exact aware second"):
        await _capturer(
            reader,
            clock=lambda: NOW.replace(microsecond=1),
        ).capture()

    assert reader.calls == ["service", f"revision:{STABLE}", "service"]
    assert reader.mutation_calls == 0


def test_fake_reader_satisfies_only_the_read_port_needed_by_capture() -> None:
    reader = _FakeReader([], [])

    assert isinstance(reader, StableSnapshotReader)
    public_capture_callables = {
        name
        for name in dir(_capturer(reader))
        if not name.startswith("_") and callable(getattr(_capturer(reader), name))
    }
    assert public_capture_callables == {"capture"}
