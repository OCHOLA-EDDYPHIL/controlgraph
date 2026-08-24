"""Composition root for the isolated advisor runtime."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from datetime import datetime

from fastapi import FastAPI

from controlgraph_canary.application.identity import ServiceRole, runtime_route_policy
from controlgraph_canary.application.model_assistance import (
    AdvisorModel,
    ReadOnlyAdvisorService,
    VerifiedDiagnosticEvidenceReader,
)
from controlgraph_canary.http.advisor import create_advisor_app
from controlgraph_canary.integrations.google.identity import (
    GoogleIdentityVerifier,
    IdentityTokenVerifier,
)
from controlgraph_canary.settings import ControllerSettings


def create_advisor_runtime_app(
    *,
    environment: Mapping[str, str] | None = None,
    token_verifier: IdentityTokenVerifier | None = None,
    identity_clock: Callable[[], float] | None = None,
    validation_clock: Callable[[], datetime] | None = None,
    model: AdvisorModel | None = None,
    evidence_reader: VerifiedDiagnosticEvidenceReader | None = None,
) -> FastAPI:
    """Compose the advisor without importing ADK into controller runtimes."""

    source = os.environ if environment is None else environment
    settings = ControllerSettings.from_environment(source)
    if settings.role != ServiceRole.ADVISOR.value:
        raise ValueError("advisor runtime role is invalid")
    policy = runtime_route_policy(ServiceRole.ADVISOR, source)
    authenticator = GoogleIdentityVerifier(
        verifier=token_verifier,
        clock=identity_clock,
    )
    selected_model = model
    if selected_model is None:
        from controlgraph_canary.integrations.adk.rollout_advisor import (
            GoogleAdkRolloutAdvisor,
        )

        if (
            settings.advisor_model is None
            or settings.advisor_model_location is None
            or settings.advisor_api_version is None
            or settings.advisor_max_llm_calls is None
            or settings.advisor_max_output_tokens is None
            or settings.advisor_timeout_seconds is None
        ):
            raise ValueError("advisor model settings are incomplete")
        selected_model = GoogleAdkRolloutAdvisor(
            project_id=settings.project_id,
            model_id=settings.advisor_model,
            model_location=settings.advisor_model_location,
            api_version=settings.advisor_api_version,
            max_llm_calls=settings.advisor_max_llm_calls,
            max_output_tokens=settings.advisor_max_output_tokens,
        )
    if settings.advisor_timeout_seconds is None:
        raise ValueError("advisor timeout setting is incomplete")
    service = ReadOnlyAdvisorService(
        authentication_policy=policy,
        model=selected_model,
        evidence_reader=evidence_reader,
        timeout_seconds=settings.advisor_timeout_seconds,
        clock=validation_clock,
    )
    return create_advisor_app(
        authenticator=authenticator,
        authentication_policy=policy,
        advisor_service=service,
        build_digest=settings.build_digest,
    )


__all__ = ["create_advisor_runtime_app"]
