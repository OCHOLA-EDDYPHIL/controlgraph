"""Verifier service composition root."""

from controlgraph_canary.http.service import ServiceRole, create_service_app

app = create_service_app(ServiceRole.VERIFIER)
