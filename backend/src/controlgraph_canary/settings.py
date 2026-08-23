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
    "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_EMAIL",
    "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_SUBJECT",
)

COORDINATOR_TRUST_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_ISSUER_URL",
    "CONTROLGRAPH_VERIFIER_URL",
    "CONTROLGRAPH_EVIDENCE_WRITER_URL",
    "CONTROLGRAPH_CAPABILITY_KEY_VERSION",
    "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
    "CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256",
    "CONTROLGRAPH_OPERATOR_EMAIL",
    "CONTROLGRAPH_OPERATOR_SUBJECT",
    "CONTROLGRAPH_SECURITY_AUDITOR_EMAIL",
    "CONTROLGRAPH_SECURITY_AUDITOR_SUBJECT",
    "CONTROLGRAPH_RESTRICTED_EXPORTER_EMAIL",
    "CONTROLGRAPH_RESTRICTED_EXPORTER_SUBJECT",
    "CONTROLGRAPH_EXECUTOR_URL",
    "CONTROLGRAPH_RECOVERY_URL",
    "CONTROLGRAPH_EXECUTION_QUEUE",
    "CONTROLGRAPH_RECOVERY_QUEUE",
    "CONTROLGRAPH_EXECUTION_TASK_CALLER",
    "CONTROLGRAPH_RECOVERY_TASK_CALLER",
    "CONTROLGRAPH_RECEIPT_AUTH_CALLER_EMAIL",
    "CONTROLGRAPH_RECEIPT_AUTH_CALLER_SUBJECT",
    "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_EMAIL",
    "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_SUBJECT",
    "CONTROLGRAPH_TIMELINE_RETENTION_CALLER_EMAIL",
    "CONTROLGRAPH_TIMELINE_RETENTION_CALLER_SUBJECT",
)

API_ROOT_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_COORDINATOR_URL",
    "CONTROLGRAPH_OPERATOR_CONSOLE_ORIGIN",
    "CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE",
    "CONTROLGRAPH_SECURITY_AUDITOR_EMAIL",
    "CONTROLGRAPH_SECURITY_AUDITOR_SUBJECT",
    "CONTROLGRAPH_RESTRICTED_EXPORTER_EMAIL",
    "CONTROLGRAPH_RESTRICTED_EXPORTER_SUBJECT",
)

ISSUER_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_CAPABILITY_KEY_VERSION",
    "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
    "CONTROLGRAPH_SIGNING_ALGORITHM",
    "CONTROLGRAPH_RECOVERY_URL",
)

EXECUTOR_MUTATION_WORKER_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_CAPABILITY_KEY_VERSION",
    "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
    "CONTROLGRAPH_COORDINATOR_URL",
    "CONTROLGRAPH_TARGET_NETWORK_RESOURCE",
    "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE",
    "CONTROLGRAPH_RECOVERY_FACADE_CALLER_EMAIL",
    "CONTROLGRAPH_RECOVERY_FACADE_CALLER_SUBJECT",
)

RECOVERY_WORKER_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_CAPABILITY_KEY_VERSION",
    "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
    "CONTROLGRAPH_EXECUTOR_URL",
)

VERIFIER_PREFLIGHT_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_TARGET_NETWORK_RESOURCE",
    "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE",
    "CONTROLGRAPH_EVIDENCE_WRITER_URL",
    "CONTROLGRAPH_EVIDENCE_KEY_VERSION",
    "CONTROLGRAPH_REFERENCE_TARGET_URL",
)

RUNTIME_ROLES = frozenset(role.value for role in ServiceRole)
_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_PROJECT_NUMBER = re.compile(r"^[1-9][0-9]{5,31}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GOOGLE_OAUTH_CLIENT_AUDIENCE = re.compile(
    r"^[0-9]{6,32}(?:-[a-z0-9]{6,128})?\.apps\.googleusercontent\.com$"
)


def required_environment_keys(environment: Mapping[str, str]) -> tuple[str, ...]:
    """Return the exact startup key set required by the selected role."""

    role = environment.get("CONTROLGRAPH_ROLE")
    if type(role) is str and role.strip() == ServiceRole.EVIDENCE_WRITER.value:
        return REQUIRED_ENVIRONMENT_KEYS + EVIDENCE_WRITER_ENVIRONMENT_KEYS
    if type(role) is str and role.strip() == ServiceRole.API.value:
        return REQUIRED_ENVIRONMENT_KEYS + API_ROOT_ENVIRONMENT_KEYS
    if type(role) is str and role.strip() == ServiceRole.ISSUER.value:
        return REQUIRED_ENVIRONMENT_KEYS + ISSUER_ENVIRONMENT_KEYS
    mutations_enabled = environment.get("CONTROLGRAPH_MUTATIONS_ENABLED")
    if type(role) is str and type(mutations_enabled) is str:
        selected_role = role.strip()
        enabled = mutations_enabled.strip().lower() == "true"
        if selected_role == ServiceRole.EXECUTOR.value and enabled:
            return REQUIRED_ENVIRONMENT_KEYS + EXECUTOR_MUTATION_WORKER_ENVIRONMENT_KEYS
        if selected_role == ServiceRole.RECOVERY.value and enabled:
            return REQUIRED_ENVIRONMENT_KEYS + RECOVERY_WORKER_ENVIRONMENT_KEYS
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
    issuer_url: str | None
    executor_url: str | None
    recovery_url: str | None
    execution_queue: str | None
    recovery_queue: str | None
    execution_task_caller: str | None
    recovery_task_caller: str | None
    receipt_authority_caller_identity: str | None
    receipt_authority_caller_subject: str | None
    recovery_receipt_authority_caller_identity: str | None
    recovery_receipt_authority_caller_subject: str | None
    recovery_facade_caller_identity: str | None
    recovery_facade_caller_subject: str | None
    classification_evidence_caller_identity: str | None
    classification_evidence_caller_subject: str | None
    target_network_resource: str | None
    target_subnetwork_resource: str | None
    reference_target_url: str | None
    coordinator_url: str | None
    candidate_revision_configuration_sha256: str | None
    operator_identity: str | None
    operator_subject: str | None
    operator_console_origin: str | None
    operator_oauth_client_audience: str | None
    security_auditor_identity: str | None
    security_auditor_subject: str | None
    restricted_exporter_identity: str | None
    restricted_exporter_subject: str | None
    timeline_retention_caller_identity: str | None
    timeline_retention_caller_subject: str | None

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
        mutations_enabled = mutation_flag == "true"
        if mutations_enabled and service_role not in {
            ServiceRole.EXECUTOR,
            ServiceRole.RECOVERY,
        }:
            raise ValueError("only an execution worker may enable controlled mutations")
        if environment_name != "nonprod":
            raise ValueError("CONTROLGRAPH_ENVIRONMENT must be nonprod")

        capability_key_version: str | None = None
        evidence_key_version: str | None = None
        signing_algorithm: str | None = None
        verifier_url: str | None = None
        evidence_writer_url: str | None = None
        issuer_url: str | None = None
        executor_url: str | None = None
        recovery_url: str | None = None
        execution_queue: str | None = None
        recovery_queue: str | None = None
        execution_task_caller: str | None = None
        recovery_task_caller: str | None = None
        receipt_authority_caller_identity: str | None = None
        receipt_authority_caller_subject: str | None = None
        recovery_receipt_authority_caller_identity: str | None = None
        recovery_receipt_authority_caller_subject: str | None = None
        recovery_facade_caller_identity: str | None = None
        recovery_facade_caller_subject: str | None = None
        classification_evidence_caller_identity: str | None = None
        classification_evidence_caller_subject: str | None = None
        target_network_resource: str | None = None
        target_subnetwork_resource: str | None = None
        reference_target_url: str | None = None
        coordinator_url: str | None = None
        candidate_revision_configuration_sha256: str | None = None
        operator_identity: str | None = None
        operator_subject: str | None = None
        operator_console_origin: str | None = None
        operator_oauth_client_audience: str | None = None
        security_auditor_identity: str | None = None
        security_auditor_subject: str | None = None
        restricted_exporter_identity: str | None = None
        restricted_exporter_subject: str | None = None
        timeline_retention_caller_identity: str | None = None
        timeline_retention_caller_subject: str | None = None
        executor_enabled = service_role is ServiceRole.EXECUTOR and mutations_enabled
        recovery_enabled = service_role is ServiceRole.RECOVERY and mutations_enabled
        if service_role is ServiceRole.API or executor_enabled:
            coordinator_url = source["CONTROLGRAPH_COORDINATOR_URL"].strip()
            _validate_service_url(
                coordinator_url,
                ServiceRole.COORDINATOR,
                project_number,
            )
        if service_role is ServiceRole.API:
            raw_operator_console_origin = source["CONTROLGRAPH_OPERATOR_CONSOLE_ORIGIN"]
            expected_console_origin = (
                f"https://controlgraph-console-{project_number}.us-central1.run.app"
            )
            if raw_operator_console_origin != expected_console_origin:
                raise ValueError("CONTROLGRAPH_OPERATOR_CONSOLE_ORIGIN is invalid")
            operator_console_origin = raw_operator_console_origin
            raw_operator_oauth_client_audience = source[
                "CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE"
            ]
            if (
                raw_operator_oauth_client_audience != raw_operator_oauth_client_audience.strip()
                or _GOOGLE_OAUTH_CLIENT_AUDIENCE.fullmatch(raw_operator_oauth_client_audience)
                is None
            ):
                raise ValueError("CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE is invalid")
            operator_oauth_client_audience = raw_operator_oauth_client_audience
        if service_role in {ServiceRole.API, ServiceRole.COORDINATOR}:
            security_auditor_identity = source[
                "CONTROLGRAPH_SECURITY_AUDITOR_EMAIL"
            ].strip()
            security_auditor_subject = source[
                "CONTROLGRAPH_SECURITY_AUDITOR_SUBJECT"
            ].strip()
            restricted_exporter_identity = source[
                "CONTROLGRAPH_RESTRICTED_EXPORTER_EMAIL"
            ].strip()
            restricted_exporter_subject = source[
                "CONTROLGRAPH_RESTRICTED_EXPORTER_SUBJECT"
            ].strip()
            _validate_timeline_reader_identity(
                security_auditor_identity,
                project_id=project_id,
                account_id="cg-security-auditor",
            )
            _validate_timeline_reader_identity(
                restricted_exporter_identity,
                project_id=project_id,
                account_id="cg-restricted-exporter",
            )
            if (
                _PROJECT_NUMBER.fullmatch(security_auditor_subject) is None
                or _PROJECT_NUMBER.fullmatch(restricted_exporter_subject) is None
            ):
                raise ValueError("timeline privileged reader subject is invalid")
            ordinary_identity = (
                source["CONTROLGRAPH_AUTH_CALLER_EMAIL"].strip()
                if service_role is ServiceRole.API
                else source["CONTROLGRAPH_OPERATOR_EMAIL"].strip()
            )
            ordinary_subject = (
                source["CONTROLGRAPH_AUTH_CALLER_SUBJECT"].strip()
                if service_role is ServiceRole.API
                else source["CONTROLGRAPH_OPERATOR_SUBJECT"].strip()
            )
            if len(
                {
                    (ordinary_identity, ordinary_subject),
                    (security_auditor_identity, security_auditor_subject),
                    (restricted_exporter_identity, restricted_exporter_subject),
                }
            ) != 3:
                raise ValueError("timeline privileged reader identities must be distinct")
        if (
            service_role
            in {
                ServiceRole.EVIDENCE_WRITER,
                ServiceRole.COORDINATOR,
                ServiceRole.VERIFIER,
                ServiceRole.ISSUER,
            }
            or executor_enabled
            or recovery_enabled
        ):
            evidence_key_version = source["CONTROLGRAPH_EVIDENCE_KEY_VERSION"].strip()
            expected_key_version = re.compile(
                rf"^projects/{re.escape(project_id)}/locations/us-central1/"
                r"keyRings/controlgraph-signing/cryptoKeys/evidence-signing/"
                r"cryptoKeyVersions/[1-9][0-9]*$"
            )
            if expected_key_version.fullmatch(evidence_key_version) is None:
                raise ValueError("CONTROLGRAPH_EVIDENCE_KEY_VERSION is outside its purpose")
        if service_role in {ServiceRole.EVIDENCE_WRITER, ServiceRole.ISSUER}:
            signing_algorithm = source["CONTROLGRAPH_SIGNING_ALGORITHM"].strip()
            if signing_algorithm != SIGNING_ALGORITHM:
                raise ValueError("CONTROLGRAPH_SIGNING_ALGORITHM is unsupported")
        if (
            service_role
            in {
                ServiceRole.COORDINATOR,
                ServiceRole.ISSUER,
            }
            or executor_enabled
            or recovery_enabled
        ):
            capability_key_version = source["CONTROLGRAPH_CAPABILITY_KEY_VERSION"].strip()
            expected_capability_key_version = re.compile(
                rf"^projects/{re.escape(project_id)}/locations/us-central1/"
                r"keyRings/controlgraph-signing/cryptoKeys/capability-signing/"
                r"cryptoKeyVersions/[1-9][0-9]*$"
            )
            if expected_capability_key_version.fullmatch(capability_key_version) is None:
                raise ValueError("CONTROLGRAPH_CAPABILITY_KEY_VERSION is outside its purpose")
        if service_role is ServiceRole.COORDINATOR:
            issuer_url = source["CONTROLGRAPH_ISSUER_URL"].strip()
            verifier_url = source["CONTROLGRAPH_VERIFIER_URL"].strip()
            evidence_writer_url = source["CONTROLGRAPH_EVIDENCE_WRITER_URL"].strip()
            _validate_service_url(issuer_url, ServiceRole.ISSUER, project_number)
            _validate_service_url(verifier_url, ServiceRole.VERIFIER, project_number)
            _validate_service_url(
                evidence_writer_url,
                ServiceRole.EVIDENCE_WRITER,
                project_number,
            )
            candidate_revision_configuration_sha256 = source[
                "CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256"
            ].strip()
            if _DIGEST.fullmatch(f"sha256:{candidate_revision_configuration_sha256}") is None:
                raise ValueError("CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256 is invalid")
            operator_identity = source["CONTROLGRAPH_OPERATOR_EMAIL"].strip()
            operator_subject = source["CONTROLGRAPH_OPERATOR_SUBJECT"].strip()
            _validate_operator_identity(operator_identity)
            if _PROJECT_NUMBER.fullmatch(operator_subject) is None:
                raise ValueError("CONTROLGRAPH_OPERATOR_SUBJECT is invalid")
            executor_url = source["CONTROLGRAPH_EXECUTOR_URL"].strip()
            recovery_url = source["CONTROLGRAPH_RECOVERY_URL"].strip()
            _validate_service_url(executor_url, ServiceRole.EXECUTOR, project_number)
            _validate_service_url(recovery_url, ServiceRole.RECOVERY, project_number)
            execution_queue = source["CONTROLGRAPH_EXECUTION_QUEUE"].strip()
            recovery_queue = source["CONTROLGRAPH_RECOVERY_QUEUE"].strip()
            if execution_queue != "controlgraph-execution":
                raise ValueError("CONTROLGRAPH_EXECUTION_QUEUE is invalid")
            if recovery_queue != "controlgraph-recovery":
                raise ValueError("CONTROLGRAPH_RECOVERY_QUEUE is invalid")
            execution_task_caller = source["CONTROLGRAPH_EXECUTION_TASK_CALLER"].strip()
            recovery_task_caller = source["CONTROLGRAPH_RECOVERY_TASK_CALLER"].strip()
            _validate_task_caller(
                execution_task_caller,
                project_id=project_id,
                account_id="cg-execution-task-caller",
            )
            _validate_task_caller(
                recovery_task_caller,
                project_id=project_id,
                account_id="cg-recovery-task-caller",
            )
            receipt_authority_caller_identity = source[
                "CONTROLGRAPH_RECEIPT_AUTH_CALLER_EMAIL"
            ].strip()
            if receipt_authority_caller_identity != (
                f"controlgraph-executor@{project_id}.iam.gserviceaccount.com"
            ):
                raise ValueError("receipt authority caller identity is invalid")
            receipt_authority_caller_subject = source[
                "CONTROLGRAPH_RECEIPT_AUTH_CALLER_SUBJECT"
            ].strip()
            if _PROJECT_NUMBER.fullmatch(receipt_authority_caller_subject) is None:
                raise ValueError("receipt authority caller subject is invalid")
            recovery_receipt_authority_caller_identity = source[
                "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_EMAIL"
            ].strip()
            if recovery_receipt_authority_caller_identity != (
                f"controlgraph-executor@{project_id}.iam.gserviceaccount.com"
            ):
                raise ValueError("recovery receipt authority caller identity is invalid")
            recovery_receipt_authority_caller_subject = source[
                "CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_SUBJECT"
            ].strip()
            if _PROJECT_NUMBER.fullmatch(recovery_receipt_authority_caller_subject) is None:
                raise ValueError("recovery receipt authority caller subject is invalid")
            timeline_retention_caller_identity = source[
                "CONTROLGRAPH_TIMELINE_RETENTION_CALLER_EMAIL"
            ].strip()
            if timeline_retention_caller_identity != (
                f"cg-retention-sweeper@{project_id}.iam.gserviceaccount.com"
            ):
                raise ValueError("timeline retention caller identity is invalid")
            timeline_retention_caller_subject = source[
                "CONTROLGRAPH_TIMELINE_RETENTION_CALLER_SUBJECT"
            ].strip()
            if _PROJECT_NUMBER.fullmatch(timeline_retention_caller_subject) is None:
                raise ValueError("timeline retention caller subject is invalid")
        if service_role is ServiceRole.ISSUER:
            recovery_url = source["CONTROLGRAPH_RECOVERY_URL"].strip()
            _validate_service_url(recovery_url, ServiceRole.RECOVERY, project_number)
        if recovery_enabled:
            executor_url = source["CONTROLGRAPH_EXECUTOR_URL"].strip()
            _validate_service_url(executor_url, ServiceRole.EXECUTOR, project_number)
        if executor_enabled:
            recovery_facade_caller_identity = source[
                "CONTROLGRAPH_RECOVERY_FACADE_CALLER_EMAIL"
            ].strip()
            if recovery_facade_caller_identity != (
                f"controlgraph-recovery@{project_id}.iam.gserviceaccount.com"
            ):
                raise ValueError("recovery facade caller identity is invalid")
            recovery_facade_caller_subject = source[
                "CONTROLGRAPH_RECOVERY_FACADE_CALLER_SUBJECT"
            ].strip()
            if _PROJECT_NUMBER.fullmatch(recovery_facade_caller_subject) is None:
                raise ValueError("recovery facade caller subject is invalid")
        if service_role is ServiceRole.EVIDENCE_WRITER:
            classification_evidence_caller_identity = source[
                "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_EMAIL"
            ].strip()
            if classification_evidence_caller_identity != (
                f"controlgraph-verifier@{project_id}.iam.gserviceaccount.com"
            ):
                raise ValueError("classification evidence caller identity is invalid")
            classification_evidence_caller_subject = source[
                "CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_SUBJECT"
            ].strip()
            if _PROJECT_NUMBER.fullmatch(classification_evidence_caller_subject) is None:
                raise ValueError("classification evidence caller subject is invalid")
        if service_role is ServiceRole.VERIFIER:
            evidence_writer_url = source["CONTROLGRAPH_EVIDENCE_WRITER_URL"].strip()
            _validate_service_url(
                evidence_writer_url,
                ServiceRole.EVIDENCE_WRITER,
                project_number,
            )
            reference_target_url = source["CONTROLGRAPH_REFERENCE_TARGET_URL"].strip()
            _validate_reference_target_url(reference_target_url, project_number)
        if service_role is ServiceRole.VERIFIER or executor_enabled:
            target_network_resource = source["CONTROLGRAPH_TARGET_NETWORK_RESOURCE"].strip()
            target_subnetwork_resource = source["CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE"].strip()
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
            mutations_enabled=mutations_enabled,
            environment=environment_name,
            capability_key_version=capability_key_version,
            evidence_key_version=evidence_key_version,
            signing_algorithm=signing_algorithm,
            verifier_url=verifier_url,
            evidence_writer_url=evidence_writer_url,
            issuer_url=issuer_url,
            executor_url=executor_url,
            recovery_url=recovery_url,
            execution_queue=execution_queue,
            recovery_queue=recovery_queue,
            execution_task_caller=execution_task_caller,
            recovery_task_caller=recovery_task_caller,
            receipt_authority_caller_identity=receipt_authority_caller_identity,
            receipt_authority_caller_subject=receipt_authority_caller_subject,
            recovery_receipt_authority_caller_identity=(recovery_receipt_authority_caller_identity),
            recovery_receipt_authority_caller_subject=(recovery_receipt_authority_caller_subject),
            recovery_facade_caller_identity=recovery_facade_caller_identity,
            recovery_facade_caller_subject=recovery_facade_caller_subject,
            classification_evidence_caller_identity=(classification_evidence_caller_identity),
            classification_evidence_caller_subject=(classification_evidence_caller_subject),
            target_network_resource=target_network_resource,
            target_subnetwork_resource=target_subnetwork_resource,
            reference_target_url=reference_target_url,
            coordinator_url=coordinator_url,
            candidate_revision_configuration_sha256=(candidate_revision_configuration_sha256),
            operator_identity=operator_identity,
            operator_subject=operator_subject,
            operator_console_origin=operator_console_origin,
            operator_oauth_client_audience=operator_oauth_client_audience,
            security_auditor_identity=security_auditor_identity,
            security_auditor_subject=security_auditor_subject,
            restricted_exporter_identity=restricted_exporter_identity,
            restricted_exporter_subject=restricted_exporter_subject,
            timeline_retention_caller_identity=timeline_retention_caller_identity,
            timeline_retention_caller_subject=timeline_retention_caller_subject,
        )


def _validate_service_url(value: str, role: ServiceRole, project_number: str) -> None:
    expected = f"https://{runtime_service_name(role)}-{project_number}.us-central1.run.app"
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


def _validate_reference_target_url(value: str, project_number: str) -> None:
    expected = (
        f"https://controlgraph-reference-target-{project_number}"
        ".us-central1.run.app"
    )
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("reference target URL is invalid") from None
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
        raise ValueError("reference target URL is invalid")


def _validate_task_caller(
    value: str,
    *,
    project_id: str,
    account_id: str,
) -> None:
    if value != f"{account_id}@{project_id}.iam.gserviceaccount.com":
        raise ValueError("task caller identity is invalid")


def _validate_operator_identity(value: str) -> None:
    if re.fullmatch(
        r"[a-z0-9][a-z0-9._%+\-]{0,63}@"
        r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?",
        value,
    ) is None or value.endswith(".iam.gserviceaccount.com"):
        raise ValueError("CONTROLGRAPH_OPERATOR_EMAIL is invalid")


def _validate_timeline_reader_identity(
    value: str,
    *,
    project_id: str,
    account_id: str,
) -> None:
    if value != f"{account_id}@{project_id}.iam.gserviceaccount.com":
        raise ValueError("timeline privileged reader identity is invalid")
