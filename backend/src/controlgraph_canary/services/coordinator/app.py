"""Coordinator service composition root."""

from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.services.runtime import create_runtime_service_app

app = create_runtime_service_app(ServiceRole.COORDINATOR)
