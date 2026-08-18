"""Environment-backed settings for local validation and service startup."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

REQUIRED_ENVIRONMENT_KEYS = (
    "CONTROLGRAPH_PROJECT_ID",
    "CONTROLGRAPH_REGION",
    "CONTROLGRAPH_SERVICE_NAME",
    "CONTROLGRAPH_CONTROLLER_ID",
)


@dataclass(frozen=True, slots=True)
class ControllerSettings:
    """Validated identifiers needed by future cloud adapters."""

    project_id: str
    region: str
    service_name: str
    controller_id: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> ControllerSettings:
        source = os.environ if environment is None else environment
        missing = [key for key in REQUIRED_ENVIRONMENT_KEYS if not source.get(key, "").strip()]
        if missing:
            raise ValueError(f"missing environment variables: {', '.join(missing)}")
        return cls(
            project_id=source["CONTROLGRAPH_PROJECT_ID"].strip(),
            region=source["CONTROLGRAPH_REGION"].strip(),
            service_name=source["CONTROLGRAPH_SERVICE_NAME"].strip(),
            controller_id=source["CONTROLGRAPH_CONTROLLER_ID"].strip(),
        )
