"""Environment-backed settings for local validation and service startup."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from controlgraph_canary.application.identity import ServiceRole, runtime_service_name
from controlgraph_canary.application.signing import SIGNING_ALGORITHM

REQUIRED_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_PROJECT_ID",
    "CONTROLGRAPH_PROJECT_NUMBER",
    "CONTROLGRAPH_REGION",
    "CONTROLGRAPH_SERVICE_NAME",
    "CONTROLGRAPH_CONTROLLER_ID",
    "CONTROLGRAPH_ROLE",
    "CONTROLGRAPH_BUILD_DIGEST",
    "CONTROLGRAPH_CONTRACT_VERSION",
    "CONTROLGRAPH_FIRESTORE_DATABASE",
    "CONTROLGRAPH_MUTATIONS_ENABLED",
    "CONTROLGRAPH_ENVIRONMENT",
    "CONTROLGRAPH_AUTH_AUDIENCE",
    "CONTROLGRAPH_AUTH_CALLER_EMAIL",
    "CONTROLGRAPH_AUTH_CALLER_ROLE",
    "CONTROLGRAPH_AUTH_CALLER_SUBJECT",
)

EVIDENCE_WRITER_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
    "CONTROLGRAPH_SIGNING_ALGORITHM",
)

COORDINATOR_TRUST_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_VERIFIER_URL",
    "CONTROLGRAPH_EVIDENCE_WRITER_URL",
    "CONTROLGRAPH_CAPABILITY_KEY_VERSION",
    "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
    "CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256",
    "CONTROLGRAPH_OPERATOR_EMAIL",
    "CONTROLGRAPH_OPERATOR_SUBJECT",
)

API_ROOT_ENVIRONMENT_KEYS = ("CONTROLGRAPH_COORDINATOR_URL",)

VERIFIER_PREFLIGHT_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_TARGET_NETWORK_RESOURCE",
    "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE",
)

RUNTIME_ROLES = frozenset(role.value for role in ServiceRole)
_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_PROJECT_NUMBER = re.compile(r"^[1-9][0-9]{5,31}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def required_environment_keys(environment: Mapping[str, str]) -> tuple[str, ...]:
    """Return the exact startup key set required by the selected role."""

    role = environment.get("CONTROLGRAPH_ROLE")
    if type(role) is str and role.strip() == ServiceRole.EVIDENCE_WRITER.value:
        return REQUIRED_ENVIRONMENT_KEYS + EVIDENCE_WRITER_ENVIRONMENT_KEYS
    if type(role) is str and role.strip() == ServiceRole.API.value:
        return REQUIRED_ENVIRONMENT_KEYS + API_ROOT_ENVIRONMENT_KEYS
    if type(role) is str and role.strip() == ServiceRole.COORDINATOR.value:
        return REQUIRED_ENVIRONMENT_KEYS + COORDINATOR_TRUST_ENVIRONMENT_KEYS
    if type(role) is str and role.strip() == ServiceRole.VERIFIER.value:
        return REQUIRED_ENVIRONMENT_KEYS + VERIFIER_PREFLIGHT_ENVIRONMENT_KEYS
    return REQUIRED_ENVIRONMENT_KEYS


@dataclass(frozen=True, slots=True)
class ControllerSettings:
    """Validated common settings shared by every private service shell."""

    project_id: str
    project_number: str
    region: str
    service_name: str
    controller_id: str
    role: str
    build_digest: str
    contract_version: str
    firestore_database: str
    mutations_enabled: bool
    environment: str
    capability_key_version: str | None
    evidence_key_version: str | None
    signing_algorithm: str | None
    verifier_url: str | None
    evidence_writer_url: str | None
    target_network_resource: str | None
    target_subnetwork_resource: str | None
    coordinator_url: str | None
    candidate_revision_configuration_sha256: str | None
    operator_identity: str | None
    operator_subject: str | None

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> ControllerSettings:
        source = os.environ if environment is None else environment
        missing = [
            key
            for key in required_environment_keys(source)
            if type(source.get(key)) is not str or not source[key].strip()
        ]
        if missing:
            raise ValueError(f"missing environment variables: {', '.join(missing)}")
        project_id = source["CONTROLGRAPH_PROJECT_ID"].strip()
        project_number = source["CONTROLGRAPH_PROJECT_NUMBER"].strip()
        region = source["CONTROLGRAPH_REGION"].strip()
        service_name = source["CONTROLGRAPH_SERVICE_NAME"].strip()
        controller_id = source["CONTROLGRAPH_CONTROLLER_ID"].strip()
        role = source["CONTROLGRAPH_ROLE"].strip()
        build_digest = source["CONTROLGRAPH_BUILD_DIGEST"].strip()
        contract_version = source["CONTROLGRAPH_CONTRACT_VERSION"].strip()
        firestore_database = source["CONTROLGRAPH_FIRESTORE_DATABASE"].strip()
        mutation_flag = source["CONTROLGRAPH_MUTATIONS_ENABLED"].strip().lower()
        environment_name = source["CONTROLGRAPH_ENVIRONMENT"].strip()

        if _PROJECT_ID.fullmatch(project_id) is None:
            raise ValueError("CONTROLGRAPH_PROJECT_ID is not a dedicated ControlGraph project")
        if _PROJECT_NUMBER.fullmatch(project_number) is None:
            raise ValueError("CONTROLGRAPH_PROJECT_NUMBER is invalid")
        if region != "us-central1":
            raise ValueError("CONTROLGRAPH_REGION must be us-central1")
        try:
            service_role = ServiceRole(role)
        except ValueError:
            raise ValueError("CONTROLGRAPH_ROLE is not a closed runtime role") from None
        if service_name != runtime_service_name(service_role):
            raise ValueError("CONTROLGRAPH_SERVICE_NAME does not match its runtime role")
        if controller_id != f"{project_id}:{region}:{role}":
            raise ValueError("CONTROLGRAPH_CONTROLLER_ID does not match its bound coordinates")
        if _DIGEST.fullmatch(build_digest) is None:
            raise ValueError("CONTROLGRAPH_BUILD_DIGEST must be an immutable sha256 digest")
        if contract_version != "controlgraph.contract/v1":
            raise ValueError("CONTROLGRAPH_CONTRACT_VERSION is unsupported")
        if firestore_database != "controlgraph-authority":
            raise ValueError("CONTROLGRAPH_FIRESTORE_DATABASE must be controlgraph-authority")
        if mutation_flag not in {"true", "false"}:
            raise ValueError("CONTROLGRAPH_MUTATIONS_ENABLED must be true or false")
        if mutation_flag != "false":
            raise ValueError("M2 service shells must keep mutations disabled")
        if environment_name != "nonprod":
            raise ValueError("CONTROLGRAPH_ENVIRONMENT must be nonprod")

        capability_key_version: str | None = None
        evidence_key_version: str | None = None
        signing_algorithm: str | None = None
        verifier_url: str | None = None
        evidence_writer_url: str | None = None
        target_network_resource: str | None = None
        target_subnetwork_resource: str | None = None
        coordinator_url: str | None = None
        candidate_revision_configuration_sha256: str | None = None
        operator_identity: str | None = None
        operator_subject: str | None = None
        if service_role is ServiceRole.API:
            coordinator_url = source["CONTROLGRAPH_COORDINATOR_URL"].strip()
            _validate_service_url(
                coordinator_url,
                ServiceRole.COORDINATOR,
                project_number,
            )
        if service_role in {ServiceRole.EVIDENCE_WRITER, ServiceRole.COORDINATOR}:
            evidence_key_version = source["CONTROLGRAPH_EVIDENCE_KEY_VERSION"].strip()
            expected_key_version = re.compile(
                rf"^projects/{re.escape(project_id)}/locations/us-central1/"
                r"keyRings/controlgraph-signing/cryptoKeys/evidence-signing/"
                r"cryptoKeyVersions/[1-9][0-9]*$"
            )
            if expected_key_version.fullmatch(evidence_key_version) is None:
                raise ValueError("CONTROLGRAPH_EVIDENCE_KEY_VERSION is outside its purpose")
        if service_role is ServiceRole.EVIDENCE_WRITER:
            signing_algorithm = source["CONTROLGRAPH_SIGNING_ALGORITHM"].strip()
            if signing_algorithm != SIGNING_ALGORITHM:
                raise ValueError("CONTROLGRAPH_SIGNING_ALGORITHM is unsupported")
        if service_role is ServiceRole.COORDINATOR:
            capability_key_version = source[
                "CONTROLGRAPH_CAPABILITY_KEY_VERSION"
            ].strip()
            expected_capability_key_version = re.compile(
                rf"^projects/{re.escape(project_id)}/locations/us-central1/"
                r"keyRings/controlgraph-signing/cryptoKeys/capability-signing/"
                r"cryptoKeyVersions/[1-9][0-9]*$"
            )
            if (
                expected_capability_key_version.fullmatch(capability_key_version)
                is None
            ):
                raise ValueError(
                    "CONTROLGRAPH_CAPABILITY_KEY_VERSION is outside its purpose"
                )
            verifier_url = source["CONTROLGRAPH_VERIFIER_URL"].strip()
            evidence_writer_url = source["CONTROLGRAPH_EVIDENCE_WRITER_URL"].strip()
            _validate_service_url(verifier_url, ServiceRole.VERIFIER, project_number)
            _validate_service_url(
                evidence_writer_url,
                ServiceRole.EVIDENCE_WRITER,
                project_number,
            )
            candidate_revision_configuration_sha256 = source[
                "CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256"
            ].strip()
            if (
                _DIGEST.fullmatch(
                    f"sha256:{candidate_revision_configuration_sha256}"
                )
                is None
            ):
                raise ValueError(
                    "CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256 is invalid"
                )
            operator_identity = source["CONTROLGRAPH_OPERATOR_EMAIL"].strip()
            operator_subject = source["CONTROLGRAPH_OPERATOR_SUBJECT"].strip()
            _validate_operator_identity(operator_identity)
            if _PROJECT_NUMBER.fullmatch(operator_subject) is None:
                raise ValueError("CONTROLGRAPH_OPERATOR_SUBJECT is invalid")
        if service_role is ServiceRole.VERIFIER:
            target_network_resource = source[
                "CONTROLGRAPH_TARGET_NETWORK_RESOURCE"
            ].strip()
            target_subnetwork_resource = source[
                "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE"
            ].strip()
            _validate_target_resource(
                target_network_resource,
                prefix=f"projects/{project_id}/global/networks/",
            )
            _validate_target_resource(
                target_subnetwork_resource,
                prefix=f"projects/{project_id}/regions/us-central1/subnetworks/",
            )

        return cls(
            project_id=project_id,
            project_number=project_number,
            region=region,
            service_name=service_name,
            controller_id=controller_id,
            role=role,
            build_digest=build_digest,
            contract_version=contract_version,
            firestore_database=firestore_database,
            mutations_enabled=False,
            environment=environment_name,
            capability_key_version=capability_key_version,
            evidence_key_version=evidence_key_version,
            signing_algorithm=signing_algorithm,
            verifier_url=verifier_url,
            evidence_writer_url=evidence_writer_url,
            target_network_resource=target_network_resource,
            target_subnetwork_resource=target_subnetwork_resource,
            coordinator_url=coordinator_url,
            candidate_revision_configuration_sha256=(
                candidate_revision_configuration_sha256
            ),
            operator_identity=operator_identity,
            operator_subject=operator_subject,
        )


def _validate_service_url(value: str, role: ServiceRole, project_number: str) -> None:
    expected = (
        f"https://{runtime_service_name(role)}-{project_number}.us-central1.run.app"
    )
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("internal service URL is invalid") from None
    if (
        value != expected
        or parsed.scheme != "https"
        or parsed.netloc != parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is not None
        or value.endswith("/")
    ):
        raise ValueError("internal service URL is invalid")


def _validate_target_resource(value: str, *, prefix: str) -> None:
    suffix = value.removeprefix(prefix)
    if (
        not value.startswith(prefix)
        or not suffix
        or len(suffix) > 63
        or re.fullmatch(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", suffix) is None
        or "reconcile" in value.lower()
    ):
        raise ValueError("verifier target network resource is invalid")


def _validate_operator_identity(value: str) -> None:
    if (
        re.fullmatch(
            r"[a-z0-9][a-z0-9._%+\-]{0,63}@"
            r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?",
            value,
        )
        is None
        or value.endswith(".iam.gserviceaccount.com")
    ):
        raise ValueError("CONTROLGRAPH_OPERATOR_EMAIL is invalid")
