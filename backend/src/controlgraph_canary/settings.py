"""Environment-backed settings for local validation and service startup."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

REQUIRED_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_PROJECT_ID",
    "CONTROLGRAPH_REGION",
    "CONTROLGRAPH_SERVICE_NAME",
    "CONTROLGRAPH_CONTROLLER_ID",
    "CONTROLGRAPH_ROLE",
    "CONTROLGRAPH_BUILD_DIGEST",
    "CONTROLGRAPH_CONTRACT_VERSION",
    "CONTROLGRAPH_FIRESTORE_DATABASE",
    "CONTROLGRAPH_MUTATIONS_ENABLED",
    "CONTROLGRAPH_ENVIRONMENT",
)

RUNTIME_ROLES = frozenset({"api", "coordinator", "issuer", "executor", "recovery", "verifier"})
_PROJECT_ID = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ControllerSettings:
    """Validated common settings shared by every private service shell."""

    project_id: str
    region: str
    service_name: str
    controller_id: str
    role: str
    build_digest: str
    contract_version: str
    firestore_database: str
    mutations_enabled: bool
    environment: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> ControllerSettings:
        source = os.environ if environment is None else environment
        missing = [key for key in REQUIRED_ENVIRONMENT_KEYS if not source.get(key, "").strip()]
        if missing:
            raise ValueError(f"missing environment variables: {', '.join(missing)}")
        project_id = source["CONTROLGRAPH_PROJECT_ID"].strip()
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
        if region != "us-central1":
            raise ValueError("CONTROLGRAPH_REGION must be us-central1")
        if role not in RUNTIME_ROLES:
            raise ValueError("CONTROLGRAPH_ROLE is not a closed runtime role")
        if service_name != f"controlgraph-{role}":
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

        return cls(
            project_id=project_id,
            region=region,
            service_name=service_name,
            controller_id=controller_id,
            role=role,
            build_digest=build_digest,
            contract_version=contract_version,
            firestore_database=firestore_database,
            mutations_enabled=False,
            environment=environment_name,
        )
