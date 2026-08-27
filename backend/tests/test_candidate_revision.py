from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import replace
from datetime import UTC, datetime
from functools import wraps
from typing import Any

import pytest

from controlgraph_canary.application.candidate_revision import (
    CandidateRevisionAttestation,
    CandidateRevisionValidationConfiguration,
    CandidateRevisionValidator,
    CandidateValidationError,
    CandidateValidationReason,
)
from controlgraph_canary.application.cloud_run import (
    CloudRunExecutionEnvironment,
    CloudRunHttpProbe,
    CloudRunNetworkInterface,
    CloudRunReadError,
    CloudRunReadErrorCode,
    CloudRunReadyState,
    CloudRunRevisionConfiguration,
    CloudRunRevisionState,
    CloudRunVpcEgress,
    cloud_run_revision_configuration_sha256,
)
from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.contracts.models import TargetBinding

PROJECT_ID = "controlgraph-canary-a1b2c3"
SERVICE = "controlgraph-reference-target"
CANDIDATE = f"{SERVICE}-candidate-v12"
READER_IDENTITY = f"controlgraph-verifier@{PROJECT_ID}.iam.gserviceaccount.com"
NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)


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
        "environment": "nonprod",
        "service_name": SERVICE,
    }
    values.update(changes)
    return TargetBinding(**values)  # type: ignore[arg-type]


def _revision_configuration(
    *,
    target: TargetBinding | None = None,
    concurrency: int = 8,
    image_digest: str = "1" * 64,
) -> CloudRunRevisionConfiguration:
    selected_target = target or _target()
    return CloudRunRevisionConfiguration(
        image=(
            f"{selected_target.region}-docker.pkg.dev/{selected_target.project_id}/"
            f"controlgraph-images/reference-target@sha256:{image_digest}"
        ),
        service_account=(
            f"controlgraph-reference@{selected_target.project_id}.iam.gserviceaccount.com"
        ),
        execution_environment=CloudRunExecutionEnvironment.GEN2,
        timeout_seconds=5,
        concurrency=concurrency,
        min_instance_count=0,
        max_instance_count=1,
        container_name="reference-target",
        command=(),
        args=(),
        working_dir=None,
        port_name="http1",
        container_port=8080,
        cpu_limit="1",
        memory_limit="512Mi",
        cpu_idle=True,
        startup_cpu_boost=False,
        startup_probe=CloudRunHttpProbe(
            path="/healthz",
            port=8080,
            initial_delay_seconds=0,
            timeout_seconds=2,
            period_seconds=5,
            failure_threshold=12,
        ),
        liveness_probe=CloudRunHttpProbe(
            path="/healthz",
            port=8080,
            initial_delay_seconds=5,
            timeout_seconds=2,
            period_seconds=10,
            failure_threshold=3,
        ),
        vpc_connector=None,
        vpc_egress=CloudRunVpcEgress.ALL_TRAFFIC,
        network_interfaces=(
            CloudRunNetworkInterface(
                network=(
                    f"projects/{selected_target.project_id}/global/networks/controlgraph"
                ),
                subnetwork=(
                    f"projects/{selected_target.project_id}/regions/"
                    f"{selected_target.region}/subnetworks/controlgraph"
                ),
                tags=(),
            ),
        ),
    )


def _revision(
    *,
    target: TargetBinding | None = None,
    revision: str = CANDIDATE,
    generation: int = 3,
    observed_generation: int | None = None,
    reconciling: bool = False,
    ready_state: CloudRunReadyState = CloudRunReadyState.READY,
    concurrency: int = 8,
    configuration: CloudRunRevisionConfiguration | None = None,
) -> CloudRunRevisionState:
    selected_target = target or _target()
    service_resource = (
        f"projects/{selected_target.project_id}/locations/{selected_target.region}/services/"
        f"{selected_target.service_name}"
    )
    return CloudRunRevisionState(
        target=selected_target,
        revision=revision,
        resource_name=f"{service_resource}/revisions/{revision}",
        service_resource=service_resource,
        uid="candidate-revision-uid-003",
        etag="candidate-revision-etag-3",
        generation=generation,
        observed_generation=(
            generation if observed_generation is None else observed_generation
        ),
        reconciling=reconciling,
        ready_state=ready_state,
        concurrency=concurrency,
        configuration=configuration
        or _revision_configuration(target=selected_target, concurrency=concurrency),
    )


class _FakeReader:
    def __init__(
        self,
        value: object,
        *,
        target: TargetBinding | None = None,
        service_role: ServiceRole = ServiceRole.VERIFIER,
        reader_identity: str = READER_IDENTITY,
    ) -> None:
        self._target = target or _target()
        self._service_role = service_role
        self._reader_identity = reader_identity
        self.value = value
        self.calls: list[str] = []

    @property
    def target(self) -> TargetBinding:
        return self._target

    @property
    def service_role(self) -> ServiceRole:
        return self._service_role

    @property
    def reader_identity(self) -> str:
        return self._reader_identity

    async def read_revision(self, revision_name: str) -> CloudRunRevisionState:
        self.calls.append(revision_name)
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value  # type: ignore[return-value]


def _configuration(
    *,
    target: TargetBinding | None = None,
    candidate_revision: str = CANDIDATE,
    expected_configuration_sha256: str | None = None,
    expected_concurrency: int = 8,
    reader_identity: str = READER_IDENTITY,
) -> CandidateRevisionValidationConfiguration:
    selected_target = target or _target()
    return CandidateRevisionValidationConfiguration(
        target=selected_target,
        candidate_revision=candidate_revision,
        expected_configuration_sha256=(
            expected_configuration_sha256
            or cloud_run_revision_configuration_sha256(
                _revision_configuration(target=selected_target)
            )
        ),
        expected_concurrency=expected_concurrency,
        reader_identity=reader_identity,
    )


def _validator(
    reader: _FakeReader,
    *,
    configuration: CandidateRevisionValidationConfiguration | None = None,
    clock: Callable[[], datetime] = lambda: NOW,
) -> CandidateRevisionValidator:
    return CandidateRevisionValidator(
        reader=reader,
        configuration=configuration or _configuration(),
        clock=clock,
    )


@_async_test
async def test_exact_candidate_read_returns_frozen_attestation() -> None:
    reader = _FakeReader(_revision())

    attestation = await _validator(reader).validate()

    assert reader.calls == [CANDIDATE]
    assert attestation == CandidateRevisionAttestation(
        target=_target(),
        candidate_revision=CANDIDATE,
        configuration_sha256=cloud_run_revision_configuration_sha256(
            _revision_configuration()
        ),
        generation=3,
        etag="candidate-revision-etag-3",
        concurrency=8,
        reader_identity=READER_IDENTITY,
        captured_at="2026-08-19T12:00:00Z",
    )
    with pytest.raises(AttributeError):
        attestation.generation = 4  # type: ignore[misc]


@pytest.mark.parametrize(
    "target",
    [
        _target(project_id="other-project-a1b2c3"),
        _target(project_id="controlgraph-canary-reconcile"),
        _target(region="europe-west1"),
        _target(environment="acceptance"),
        _target(service_name="other-reference-target"),
    ],
)
def test_configuration_rejects_targets_outside_exact_controlgraph_boundary(
    target: TargetBinding,
) -> None:
    with pytest.raises(ValueError, match="outside the ControlGraph boundary"):
        _configuration(target=target)


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"candidate_revision": "other-service-candidate-v1"}, "configured service"),
        ({"expected_configuration_sha256": "A" * 64}, "SHA-256"),
        ({"expected_concurrency": 0}, "approved bound"),
        (
            {"reader_identity": f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"},
            "verifier identity",
        ),
    ],
)
def test_configuration_rejects_each_untrusted_binding(
    change: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        _configuration(**change)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "reader",
    [
        _FakeReader(_revision(), target=_target(environment="alternate")),
        _FakeReader(_revision(), service_role=ServiceRole.EXECUTOR),
        _FakeReader(
            _revision(),
            reader_identity=(
                f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"
            ),
        ),
    ],
)
def test_reader_target_role_and_identity_mismatch_deny_before_read(
    reader: _FakeReader,
) -> None:
    with pytest.raises(CandidateValidationError) as failure:
        _validator(reader)

    assert failure.value.reason is CandidateValidationReason.MISMATCH
    assert reader.calls == []


@pytest.mark.parametrize(
    "revision",
    [
        _revision(target=_target(project_id="controlgraph-canary-b2c3d4")),
        _revision(revision=f"{SERVICE}-stable-v12"),
    ],
)
@_async_test
async def test_cross_target_or_wrong_revision_is_denied(
    revision: CloudRunRevisionState,
) -> None:
    with pytest.raises(CandidateValidationError) as failure:
        await _validator(_FakeReader(revision)).validate()

    assert failure.value.reason is CandidateValidationReason.MISMATCH


@pytest.mark.parametrize("field", ["resource_name", "service_resource"])
@_async_test
async def test_exact_resource_and_service_binding_is_rechecked(field: str) -> None:
    revision = _revision()
    object.__setattr__(revision, field, "projects/invalid/locations/us-central1/services/invalid")

    with pytest.raises(CandidateValidationError) as failure:
        await _validator(_FakeReader(revision)).validate()

    assert failure.value.reason is CandidateValidationReason.MISMATCH


@pytest.mark.parametrize(
    ("revision", "reason"),
    [
        (
            _revision(ready_state=CloudRunReadyState.NOT_READY),
            CandidateValidationReason.NOT_READY,
        ),
        (
            _revision(ready_state=CloudRunReadyState.FAILED),
            CandidateValidationReason.NOT_READY,
        ),
        (
            _revision(reconciling=True),
            CandidateValidationReason.RECONCILING,
        ),
        (
            _revision(generation=3, observed_generation=2),
            CandidateValidationReason.STALE_GENERATION,
        ),
        (
            _revision(concurrency=9),
            CandidateValidationReason.MISMATCH,
        ),
        (
            _revision(
                configuration=_revision_configuration(image_digest="2" * 64)
            ),
            CandidateValidationReason.MISMATCH,
        ),
    ],
)
@_async_test
async def test_one_field_state_changes_fail_closed(
    revision: CloudRunRevisionState,
    reason: CandidateValidationReason,
) -> None:
    with pytest.raises(CandidateValidationError) as failure:
        await _validator(_FakeReader(revision)).validate()

    assert failure.value.reason is reason


@pytest.mark.parametrize(
    ("provider_value", "reason"),
    [
        (
            CloudRunReadError(CloudRunReadErrorCode.NOT_FOUND),
            CandidateValidationReason.NOT_FOUND,
        ),
        (
            CloudRunReadError(CloudRunReadErrorCode.UNAVAILABLE),
            CandidateValidationReason.UNAVAILABLE,
        ),
        (
            CloudRunReadError(CloudRunReadErrorCode.CORRUPT_RESPONSE),
            CandidateValidationReason.CORRUPT,
        ),
        (RuntimeError("synthetic raw provider detail"), CandidateValidationReason.UNAVAILABLE),
        (object(), CandidateValidationReason.CORRUPT),
    ],
)
@_async_test
async def test_provider_failures_are_sanitized(
    provider_value: object,
    reason: CandidateValidationReason,
) -> None:
    with pytest.raises(CandidateValidationError) as failure:
        await _validator(_FakeReader(provider_value)).validate()

    assert failure.value.reason is reason
    assert "synthetic raw provider detail" not in str(failure.value)


@_async_test
async def test_cancellation_propagates_without_reclassification() -> None:
    with pytest.raises(asyncio.CancelledError):
        await _validator(_FakeReader(asyncio.CancelledError())).validate()


@pytest.mark.parametrize(
    "clock_value",
    [
        datetime(2026, 8, 19, 12, 0),
        datetime(2026, 8, 19, 12, 0, 0, 1, tzinfo=UTC),
    ],
)
@_async_test
async def test_clock_must_return_an_aware_utc_second(clock_value: datetime) -> None:
    with pytest.raises(ValueError, match="exact aware second"):
        await _validator(_FakeReader(_revision()), clock=lambda: clock_value).validate()


@pytest.mark.parametrize(
    "change",
    [
        {"candidate_revision": "other-service-candidate-v1"},
        {"configuration_sha256": "A" * 64},
        {"generation": 0},
        {"etag": "not an etag with spaces"},
        {"concurrency": 0},
        {
            "reader_identity": (
                f"controlgraph-executor@{PROJECT_ID}.iam.gserviceaccount.com"
            )
        },
        {"captured_at": "2026-08-19T12:00:00+00:00"},
    ],
)
def test_attestation_revalidates_each_trusted_field(change: dict[str, object]) -> None:
    valid = CandidateRevisionAttestation(
        target=_target(),
        candidate_revision=CANDIDATE,
        configuration_sha256=cloud_run_revision_configuration_sha256(
            _revision_configuration()
        ),
        generation=3,
        etag="candidate-revision-etag-3",
        concurrency=8,
        reader_identity=READER_IDENTITY,
        captured_at="2026-08-19T12:00:00Z",
    )

    with pytest.raises((TypeError, ValueError)):
        replace(valid, **change)
