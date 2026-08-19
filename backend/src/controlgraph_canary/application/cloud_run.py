"""Provider-neutral state and outcomes for the bound Cloud Run target."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from controlgraph_canary.contracts.base import MAX_SAFE_INTEGER
from controlgraph_canary.contracts.codec import RestrictedJson, canonical_json_value_bytes
from controlgraph_canary.contracts.models import MutationIntent, TargetBinding

TARGET_CONFIGURATION_DOMAIN: Final = b"controlgraph.target-configuration-sha256/v1\0"
TARGET_CONFIGURATION_V1: Final = "controlgraph.target-configuration/v1"
CLOUD_RUN_REVISION_CONFIGURATION_DOMAIN: Final = (
    b"controlgraph.cloud-run-revision-configuration-sha256/v1\0"
)
CLOUD_RUN_REVISION_CONFIGURATION_V1: Final = (
    "controlgraph.cloud-run-revision-configuration/v1"
)
_CLOUD_RUN_NAME: Final = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_OPAQUE_TOKEN: Final = re.compile(r"^[A-Za-z0-9._~:/+=-]+$")
_IMMUTABLE_IMAGE: Final = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_SERVICE_ACCOUNT: Final = re.compile(
    r"^[a-z0-9][a-z0-9-]{0,62}@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$"
)


def _require_name(name: str, value: object) -> None:
    if type(value) is not str or _CLOUD_RUN_NAME.fullmatch(value) is None:
        raise ValueError(f"{name} is not an exact Cloud Run name")


def _require_bounded_text(name: str, value: object, *, maximum: int = 2_048) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} is not bounded text")


def _require_token(name: str, value: object) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or _OPAQUE_TOKEN.fullmatch(value) is None
    ):
        raise ValueError(f"{name} is not an opaque provider token")


def _require_generation(name: str, value: object) -> None:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"{name} is not a positive safe integer")


def _service_resource(target: TargetBinding) -> str:
    return f"projects/{target.project_id}/locations/{target.region}/services/{target.service_name}"


def _revision_resource(target: TargetBinding, revision: str) -> str:
    return f"{_service_resource(target)}/revisions/{revision}"


class DeclaredRevision(StrEnum):
    """Closed selector for the two revisions admitted by one rollout root."""

    STABLE = "STABLE"
    CANDIDATE = "CANDIDATE"


class CloudRunReadyState(StrEnum):
    """Closed provider-neutral state of the authoritative Ready condition."""

    READY = "READY"
    NOT_READY = "NOT_READY"
    FAILED = "FAILED"


class CloudRunExecutionEnvironment(StrEnum):
    """Supported immutable Cloud Run execution environments."""

    GEN1 = "EXECUTION_ENVIRONMENT_GEN1"
    GEN2 = "EXECUTION_ENVIRONMENT_GEN2"


class CloudRunVpcEgress(StrEnum):
    """Supported immutable Cloud Run VPC egress modes."""

    ALL_TRAFFIC = "ALL_TRAFFIC"
    PRIVATE_RANGES_ONLY = "PRIVATE_RANGES_ONLY"


@dataclass(frozen=True, slots=True)
class CloudRunNetworkInterface:
    """Canonical direct-VPC interface configuration for one revision."""

    network: str
    subnetwork: str
    tags: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_bounded_text("VPC network", self.network, maximum=512)
        _require_bounded_text("VPC subnetwork", self.subnetwork, maximum=512)
        if (
            len(self.tags) > 64
            or tuple(sorted(set(self.tags))) != self.tags
            or any(
                type(tag) is not str or _CLOUD_RUN_NAME.fullmatch(tag) is None
                for tag in self.tags
            )
        ):
            raise ValueError("VPC network tags are not canonical")


@dataclass(frozen=True, slots=True)
class CloudRunHttpProbe:
    """Canonical supported HTTP probe configuration."""

    path: str
    port: int
    initial_delay_seconds: int
    timeout_seconds: int
    period_seconds: int
    failure_threshold: int

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not self.path.startswith("/")
            or len(self.path) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in self.path)
        ):
            raise ValueError("HTTP probe path is invalid")
        for name, value, minimum, maximum in (
            ("port", self.port, 1, 65_535),
            ("initial delay", self.initial_delay_seconds, 0, 240),
            ("timeout", self.timeout_seconds, 1, 240),
            ("period", self.period_seconds, 1, 240),
            ("failure threshold", self.failure_threshold, 1, 240),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"HTTP probe {name} is outside the supported bound")


@dataclass(frozen=True, slots=True)
class CloudRunRevisionConfiguration:
    """Closed immutable execution configuration for one Cloud Run revision."""

    image: str
    service_account: str
    execution_environment: CloudRunExecutionEnvironment
    timeout_seconds: int
    concurrency: int
    min_instance_count: int
    max_instance_count: int
    container_name: str
    command: tuple[str, ...]
    args: tuple[str, ...]
    working_dir: str | None
    port_name: str
    container_port: int
    cpu_limit: str
    memory_limit: str
    cpu_idle: bool
    startup_cpu_boost: bool
    startup_probe: CloudRunHttpProbe
    liveness_probe: CloudRunHttpProbe
    vpc_connector: str | None
    vpc_egress: CloudRunVpcEgress
    network_interfaces: tuple[CloudRunNetworkInterface, ...]

    def __post_init__(self) -> None:
        if type(self.image) is not str or _IMMUTABLE_IMAGE.fullmatch(self.image) is None:
            raise ValueError("revision image is not pinned by an immutable sha256 digest")
        if (
            type(self.service_account) is not str
            or _SERVICE_ACCOUNT.fullmatch(self.service_account) is None
        ):
            raise ValueError("revision service account is invalid")
        if type(self.execution_environment) is not CloudRunExecutionEnvironment:
            raise TypeError("revision execution environment must be closed")
        for name, value, minimum, maximum in (
            ("timeout", self.timeout_seconds, 1, 3_600),
            ("concurrency", self.concurrency, 1, 1_000),
            ("minimum instances", self.min_instance_count, 0, 1_000),
            ("maximum instances", self.max_instance_count, 1, 1_000),
            ("container port", self.container_port, 1, 65_535),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"revision {name} is outside the supported bound")
        if self.min_instance_count > self.max_instance_count:
            raise ValueError("revision scaling bounds are inverted")
        _require_name("container name", self.container_name)
        _require_name("container port name", self.port_name)
        for name, values in (("command", self.command), ("arguments", self.args)):
            if len(values) > 64 or any(
                type(value) is not str
                or not value
                or len(value) > 2_048
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
                for value in values
            ):
                raise ValueError(f"revision container {name} is not bounded")
        if self.working_dir is not None:
            _require_bounded_text("container working directory", self.working_dir, maximum=512)
        for resource_name, resource_value in (
            ("CPU limit", self.cpu_limit),
            ("memory limit", self.memory_limit),
        ):
            _require_bounded_text(resource_name, resource_value, maximum=64)
        if type(self.cpu_idle) is not bool or type(self.startup_cpu_boost) is not bool:
            raise ValueError("revision resource flags are invalid")
        if (
            type(self.startup_probe) is not CloudRunHttpProbe
            or type(self.liveness_probe) is not CloudRunHttpProbe
        ):
            raise TypeError("revision probes must use the supported HTTP shape")
        if self.startup_probe.port != self.container_port:
            raise ValueError("startup probe does not address the declared container port")
        if self.liveness_probe.port != self.container_port:
            raise ValueError("liveness probe does not address the declared container port")
        if self.vpc_connector is not None:
            _require_bounded_text("VPC connector", self.vpc_connector, maximum=512)
        if type(self.vpc_egress) is not CloudRunVpcEgress:
            raise TypeError("revision VPC egress must be closed")
        if not 0 <= len(self.network_interfaces) <= 1 or any(
            type(item) is not CloudRunNetworkInterface for item in self.network_interfaces
        ):
            raise ValueError("revision VPC interfaces are not bounded")
        if (self.vpc_connector is None) == (not self.network_interfaces):
            raise ValueError("revision must use exactly one supported VPC attachment")


@dataclass(frozen=True, slots=True)
class CloudRunTargetConfiguration:
    """Trusted constructor binding for one service and two immutable revisions."""

    target: TargetBinding
    stable_revision: str
    candidate_revision: str
    stable_concurrency: int
    candidate_concurrency: int
    network_resource: str
    subnetwork_resource: str

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("Cloud Run target configuration requires an exact target")
        _require_name("stable_revision", self.stable_revision)
        _require_name("candidate_revision", self.candidate_revision)
        if self.stable_revision == self.candidate_revision:
            raise ValueError("declared Cloud Run revisions must differ")
        prefix = f"{self.target.service_name}-"
        if not self.stable_revision.startswith(prefix) or not self.candidate_revision.startswith(
            prefix
        ):
            raise ValueError("declared revisions do not belong to the configured service")
        for name, value in (
            ("stable_concurrency", self.stable_concurrency),
            ("candidate_concurrency", self.candidate_concurrency),
        ):
            if type(value) is not int or not 1 <= value <= 1_000:
                raise ValueError(f"{name} is outside the approved bound")
        for coordinate_name, coordinate_value, prefix in (
            (
                "network resource",
                self.network_resource,
                f"projects/{self.target.project_id}/global/networks/",
            ),
            (
                "subnetwork resource",
                self.subnetwork_resource,
                (
                    f"projects/{self.target.project_id}/regions/"
                    f"{self.target.region}/subnetworks/"
                ),
            ),
        ):
            if type(coordinate_value) is not str or not coordinate_value.startswith(prefix):
                raise ValueError(
                    f"Cloud Run {coordinate_name} is outside the configured target"
                )
            _require_name(coordinate_name, coordinate_value.removeprefix(prefix))
            if "reconcile" in coordinate_value.lower():
                raise ValueError(
                    f"Cloud Run {coordinate_name} is outside the ControlGraph boundary"
                )

    @property
    def service_resource(self) -> str:
        return _service_resource(self.target)

    def revision(self, declared: DeclaredRevision) -> str:
        if type(declared) is not DeclaredRevision:
            raise TypeError("an exact declared revision selector is required")
        if declared is DeclaredRevision.STABLE:
            return self.stable_revision
        return self.candidate_revision

    def revision_resource(self, declared: DeclaredRevision) -> str:
        return self.revision_resource_name(self.revision(declared))

    def revision_resource_name(self, revision: str) -> str:
        """Bind one exact service-owned revision name to its provider resource."""

        _require_name("revision", revision)
        if not revision.startswith(f"{self.target.service_name}-"):
            raise ValueError("revision does not belong to the configured service")
        return _revision_resource(self.target, revision)

    def validate_revision_configuration(
        self,
        configuration: CloudRunRevisionConfiguration,
    ) -> None:
        """Reject revision execution state outside the fixed target boundary."""

        if type(configuration) is not CloudRunRevisionConfiguration:
            raise TypeError("an exact Cloud Run revision configuration is required")
        expected_service_account = (
            f"controlgraph-reference@{self.target.project_id}.iam.gserviceaccount.com"
        )
        expected_image_prefix = (
            f"{self.target.region}-docker.pkg.dev/{self.target.project_id}/"
        )
        if configuration.service_account != expected_service_account:
            raise ValueError("revision service account is outside the reference target")
        if not configuration.image.startswith(expected_image_prefix):
            raise ValueError("revision image is outside the target project and region")
        if configuration.vpc_connector is not None or len(configuration.network_interfaces) != 1:
            raise ValueError("revision VPC attachment is outside the reference target")
        interface = configuration.network_interfaces[0]
        if (
            interface.network != self.network_resource
            or interface.subnetwork != self.subnetwork_resource
        ):
            raise ValueError("revision VPC coordinates are outside the reference target")


@dataclass(frozen=True, slots=True)
class TargetConfigurationProjection:
    """Provider-neutral canonical poststate admitted by one mutation intent."""

    target: TargetBinding
    stable_revision: str
    candidate_revision: str
    stable_percent: int
    candidate_percent: int
    concurrency: int

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("target configuration requires an exact target")
        _require_name("stable_revision", self.stable_revision)
        _require_name("candidate_revision", self.candidate_revision)
        if self.stable_revision == self.candidate_revision:
            raise ValueError("target configuration revisions must differ")
        prefix = f"{self.target.service_name}-"
        if not self.stable_revision.startswith(prefix) or not self.candidate_revision.startswith(
            prefix
        ):
            raise ValueError("target configuration revisions do not belong to the target service")
        if (
            type(self.stable_percent) is not int
            or type(self.candidate_percent) is not int
            or not 0 <= self.stable_percent <= 100
            or not 0 <= self.candidate_percent <= 100
            or self.stable_percent + self.candidate_percent != 100
        ):
            raise ValueError("target configuration traffic is invalid")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 1_000:
            raise ValueError("target configuration concurrency is invalid")


def target_configuration_projection(
    intent: MutationIntent,
    *,
    expected_concurrency: int,
) -> TargetConfigurationProjection:
    """Project only the exact poststate fields shared by receipts and readback."""

    if type(intent) is not MutationIntent:
        raise TypeError("an exact mutation intent is required")
    if intent.concurrency is not None and intent.concurrency != expected_concurrency:
        raise ValueError("mutation intent concurrency does not match the expected concurrency")
    return TargetConfigurationProjection(
        target=intent.target,
        stable_revision=intent.stable_revision,
        candidate_revision=intent.candidate_revision,
        stable_percent=intent.stable_percent,
        candidate_percent=intent.candidate_percent,
        concurrency=expected_concurrency,
    )


def target_configuration_sha256(
    intent: MutationIntent,
    *,
    expected_concurrency: int,
) -> str:
    """Hash the provider-neutral target poststate under one explicit domain."""

    projected = target_configuration_projection(
        intent,
        expected_concurrency=expected_concurrency,
    )
    value: RestrictedJson = {
        "candidate_percent": projected.candidate_percent,
        "candidate_revision": projected.candidate_revision,
        "concurrency": projected.concurrency,
        "schema_version": TARGET_CONFIGURATION_V1,
        "stable_percent": projected.stable_percent,
        "stable_revision": projected.stable_revision,
        "target": projected.target.model_dump(mode="json"),
    }
    return hashlib.sha256(
        TARGET_CONFIGURATION_DOMAIN + canonical_json_value_bytes(value)
    ).hexdigest()


def cloud_run_revision_configuration_sha256(
    configuration: CloudRunRevisionConfiguration,
) -> str:
    """Hash every admitted immutable execution field under one explicit domain."""

    if type(configuration) is not CloudRunRevisionConfiguration:
        raise TypeError("an exact Cloud Run revision configuration is required")
    value: RestrictedJson = {
        "args": list(configuration.args),
        "command": list(configuration.command),
        "container_name": configuration.container_name,
        "container_port": configuration.container_port,
        "cpu_idle": configuration.cpu_idle,
        "cpu_limit": configuration.cpu_limit,
        "execution_environment": configuration.execution_environment.value,
        "image": configuration.image,
        "liveness_probe": _probe_value(configuration.liveness_probe),
        "max_instance_count": configuration.max_instance_count,
        "memory_limit": configuration.memory_limit,
        "min_instance_count": configuration.min_instance_count,
        "network_interfaces": [
            {
                "network": interface.network,
                "subnetwork": interface.subnetwork,
                "tags": list(interface.tags),
            }
            for interface in configuration.network_interfaces
        ],
        "port_name": configuration.port_name,
        "schema_version": CLOUD_RUN_REVISION_CONFIGURATION_V1,
        "service_account": configuration.service_account,
        "startup_cpu_boost": configuration.startup_cpu_boost,
        "startup_probe": _probe_value(configuration.startup_probe),
        "timeout_seconds": configuration.timeout_seconds,
        "traffic_concurrency": configuration.concurrency,
        "vpc_connector": configuration.vpc_connector,
        "vpc_egress": configuration.vpc_egress.value,
        "working_dir": configuration.working_dir,
    }
    return hashlib.sha256(
        CLOUD_RUN_REVISION_CONFIGURATION_DOMAIN + canonical_json_value_bytes(value)
    ).hexdigest()


def _probe_value(probe: CloudRunHttpProbe) -> RestrictedJson:
    return {
        "failure_threshold": probe.failure_threshold,
        "initial_delay_seconds": probe.initial_delay_seconds,
        "path": probe.path,
        "period_seconds": probe.period_seconds,
        "port": probe.port,
        "timeout_seconds": probe.timeout_seconds,
    }


@dataclass(frozen=True, slots=True)
class CloudRunTrafficAllocation:
    """Exact desired traffic mapping for one declared revision."""

    revision: str
    percent: int
    tag: str | None

    def __post_init__(self) -> None:
        _require_name("traffic revision", self.revision)
        if type(self.percent) is not int or not 0 <= self.percent <= 100:
            raise ValueError("traffic percent is outside zero to one hundred")
        if self.tag is not None:
            _require_name("traffic tag", self.tag)


@dataclass(frozen=True, slots=True)
class CloudRunTrafficStatus:
    """Provider-observed URL mapping for one traffic target."""

    revision: str
    percent: int
    tag: str | None
    uri: str | None

    def __post_init__(self) -> None:
        _require_name("traffic status revision", self.revision)
        if type(self.percent) is not int or not 0 <= self.percent <= 100:
            raise ValueError("traffic status percent is outside zero to one hundred")
        if self.tag is not None:
            _require_name("traffic status tag", self.tag)
        if self.uri is not None:
            _require_bounded_text("traffic status URI", self.uri)


@dataclass(frozen=True, slots=True)
class CloudRunServiceState:
    """Bounded provider state returned by one exact service read or operation."""

    target: TargetBinding
    resource_name: str
    uid: str
    etag: str
    generation: int
    observed_generation: int
    reconciling: bool
    ready_state: CloudRunReadyState
    latest_ready_revision: str
    latest_created_revision: str
    template_revision: str
    template_concurrency: int
    traffic: tuple[CloudRunTrafficAllocation, ...]
    traffic_statuses: tuple[CloudRunTrafficStatus, ...]
    uri: str

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("Cloud Run service state requires an exact target")
        if self.resource_name != _service_resource(self.target):
            raise ValueError("Cloud Run service state does not match its target")
        _require_bounded_text("service uid", self.uid, maximum=128)
        _require_token("service etag", self.etag)
        _require_generation("service generation", self.generation)
        _require_generation("service observed generation", self.observed_generation)
        if type(self.reconciling) is not bool:
            raise ValueError("service reconciling flag is invalid")
        if type(self.ready_state) is not CloudRunReadyState:
            raise TypeError("service readiness state must be closed")
        for name, value in (
            ("latest_ready_revision", self.latest_ready_revision),
            ("latest_created_revision", self.latest_created_revision),
            ("template_revision", self.template_revision),
        ):
            _require_name(name, value)
        if (
            type(self.template_concurrency) is not int
            or not 1 <= self.template_concurrency <= 1_000
        ):
            raise ValueError("service template concurrency is outside the approved bound")
        if not 1 <= len(self.traffic) <= 2:
            raise ValueError("service traffic mapping is not bounded")
        if len({item.revision for item in self.traffic}) != len(self.traffic):
            raise ValueError("service traffic contains a duplicate revision")
        if sum(item.percent for item in self.traffic) != 100:
            raise ValueError("service traffic does not total one hundred percent")
        if not 1 <= len(self.traffic_statuses) <= 2:
            raise ValueError("service traffic status mapping is not bounded")
        if len({item.revision for item in self.traffic_statuses}) != len(self.traffic_statuses):
            raise ValueError("service traffic status contains a duplicate revision")
        if sum(item.percent for item in self.traffic_statuses) != 100:
            raise ValueError("service traffic statuses do not total one hundred percent")
        _require_bounded_text("service URI", self.uri)


@dataclass(frozen=True, slots=True)
class CloudRunRevisionState:
    """Exact immutable state for one declared Cloud Run revision."""

    target: TargetBinding
    revision: str
    resource_name: str
    service_resource: str
    uid: str
    etag: str
    generation: int
    observed_generation: int
    reconciling: bool
    ready_state: CloudRunReadyState
    concurrency: int
    configuration: CloudRunRevisionConfiguration

    def __post_init__(self) -> None:
        if type(self.target) is not TargetBinding:
            raise TypeError("Cloud Run revision state requires an exact target")
        _require_name("revision", self.revision)
        if self.resource_name != _revision_resource(self.target, self.revision):
            raise ValueError("Cloud Run revision state does not match its target")
        if self.service_resource != _service_resource(self.target):
            raise ValueError("Cloud Run revision service does not match its target")
        _require_bounded_text("revision uid", self.uid, maximum=128)
        _require_token("revision etag", self.etag)
        _require_generation("revision generation", self.generation)
        _require_generation("revision observed generation", self.observed_generation)
        if type(self.reconciling) is not bool:
            raise ValueError("revision reconciling flag is invalid")
        if type(self.ready_state) is not CloudRunReadyState:
            raise TypeError("revision readiness state must be closed")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 1_000:
            raise ValueError("revision concurrency is outside the approved bound")
        if type(self.configuration) is not CloudRunRevisionConfiguration:
            raise TypeError("revision immutable configuration must be exact")
        if self.configuration.concurrency != self.concurrency:
            raise ValueError("revision concurrency does not match its immutable configuration")
        expected_service_account = (
            f"controlgraph-reference@{self.target.project_id}.iam.gserviceaccount.com"
        )
        if self.configuration.service_account != expected_service_account:
            raise ValueError("revision service account is outside the reference target")
        expected_image_prefix = (
            f"{self.target.region}-docker.pkg.dev/{self.target.project_id}/"
        )
        if not self.configuration.image.startswith(expected_image_prefix):
            raise ValueError("revision image is outside the target project and region")


@dataclass(frozen=True, slots=True)
class CloudRunTargetState:
    """One bounded service view plus both exact declared revision reads."""

    service: CloudRunServiceState
    stable_revision: CloudRunRevisionState
    candidate_revision: CloudRunRevisionState

    def __post_init__(self) -> None:
        target = self.service.target
        if (
            self.stable_revision.target != target
            or self.candidate_revision.target != target
            or self.stable_revision.revision == self.candidate_revision.revision
        ):
            raise ValueError("Cloud Run target state is not one exact declared target")


class CloudRunMutationOutcome(StrEnum):
    """Closed provider classifications after one admitted mutation call."""

    APPLIED = "APPLIED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"


class CloudRunMutationReason(StrEnum):
    """Sanitized reason retained without raw provider response material."""

    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    DECLARATION_MISMATCH = "DECLARATION_MISMATCH"
    PROVIDER_REJECTED = "PROVIDER_REJECTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


@dataclass(frozen=True, slots=True)
class CloudRunMutationResult:
    """One mutation attempt with its request mapping and bounded provider result."""

    outcome: CloudRunMutationOutcome
    requested_traffic: tuple[CloudRunTrafficAllocation, ...]
    expected_concurrency: int
    operation_name: str | None
    service: CloudRunServiceState | None
    reason: CloudRunMutationReason | None

    def __post_init__(self) -> None:
        if type(self.outcome) is not CloudRunMutationOutcome:
            raise TypeError("an exact Cloud Run mutation outcome is required")
        if len(self.requested_traffic) != 2:
            raise ValueError("a mutation must bind both declared revisions")
        if len({item.revision for item in self.requested_traffic}) != 2:
            raise ValueError("mutation traffic revisions must be distinct")
        if sum(item.percent for item in self.requested_traffic) != 100:
            raise ValueError("mutation traffic does not total one hundred percent")
        if (
            type(self.expected_concurrency) is not int
            or not 1 <= self.expected_concurrency <= 1_000
        ):
            raise ValueError("mutation concurrency is outside the approved bound")
        if self.operation_name is not None:
            _require_bounded_text("operation name", self.operation_name, maximum=512)
        if self.outcome is CloudRunMutationOutcome.APPLIED:
            if self.operation_name is None or self.service is None or self.reason is not None:
                raise ValueError("applied mutation result shape is invalid")
            return
        if self.service is not None or type(self.reason) is not CloudRunMutationReason:
            raise ValueError("non-applied mutation result shape is invalid")
        if (
            self.outcome is CloudRunMutationOutcome.AMBIGUOUS
            and self.reason is not CloudRunMutationReason.OUTCOME_UNKNOWN
        ):
            raise ValueError("ambiguous mutation requires an unknown-outcome reason")
        if (
            self.outcome is CloudRunMutationOutcome.FAILED_SAFE
            and (
                self.reason is CloudRunMutationReason.OUTCOME_UNKNOWN
                or self.operation_name is not None
            )
        ):
            raise ValueError("failed-safe mutation result shape is invalid")


class CloudRunReadErrorCode(StrEnum):
    """Stable failure classes for exact target reads."""

    NOT_FOUND = "CLOUD_RUN_NOT_FOUND"
    UNAVAILABLE = "CLOUD_RUN_UNAVAILABLE"
    CORRUPT_RESPONSE = "CLOUD_RUN_CORRUPT_RESPONSE"


class CloudRunReadError(RuntimeError):
    """Sanitized read failure that retains no raw provider response material."""

    def __init__(self, code: CloudRunReadErrorCode) -> None:
        if type(code) is not CloudRunReadErrorCode:
            raise TypeError("an exact Cloud Run read error code is required")
        self.code = code
        super().__init__(code.value)


__all__ = [
    "CLOUD_RUN_REVISION_CONFIGURATION_DOMAIN",
    "CLOUD_RUN_REVISION_CONFIGURATION_V1",
    "TARGET_CONFIGURATION_DOMAIN",
    "TARGET_CONFIGURATION_V1",
    "CloudRunExecutionEnvironment",
    "CloudRunHttpProbe",
    "CloudRunMutationOutcome",
    "CloudRunMutationReason",
    "CloudRunMutationResult",
    "CloudRunNetworkInterface",
    "CloudRunReadError",
    "CloudRunReadErrorCode",
    "CloudRunReadyState",
    "CloudRunRevisionConfiguration",
    "CloudRunRevisionState",
    "CloudRunServiceState",
    "CloudRunTargetConfiguration",
    "CloudRunTargetState",
    "CloudRunTrafficAllocation",
    "CloudRunTrafficStatus",
    "CloudRunVpcEgress",
    "DeclaredRevision",
    "TargetConfigurationProjection",
    "cloud_run_revision_configuration_sha256",
    "target_configuration_projection",
    "target_configuration_sha256",
]
