"""Advisor service composition root."""

from controlgraph_canary.services.advisor.runtime import create_advisor_runtime_app

app = create_advisor_runtime_app()
