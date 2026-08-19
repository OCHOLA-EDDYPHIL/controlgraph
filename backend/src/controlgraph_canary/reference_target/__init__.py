"""Harmless stable and candidate probe service."""

from __future__ import annotations

import os
from enum import StrEnum
from typing import Final, Literal

from fastapi import FastAPI, Response
from pydantic import BaseModel, ConfigDict

REFERENCE_PROBE_VERSION: Final = "controlgraph.reference-probe/v1"
REFERENCE_SERVICE_NAME: Final = "controlgraph-reference-target"
STABLE_REVISION: Final = f"{REFERENCE_SERVICE_NAME}-stable-v1"
CANDIDATE_REVISION: Final = f"{REFERENCE_SERVICE_NAME}-candidate-v1"
STABLE_MARKER: Final = "controlgraph-stable-v1"
CANDIDATE_MARKER: Final = "controlgraph-candidate-v1"


class ReferenceVariant(StrEnum):
    """Closed behavior variants built as separate immutable images."""

    STABLE = "stable"
    CANDIDATE = "candidate"


class ReferenceHealth(BaseModel):
    """Minimal liveness response with no deployment metadata."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok"]


class ReferenceProbe(BaseModel):
    """Synthetic revision behavior returned to an authenticated reader."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["controlgraph.reference-probe/v1"]
    revision: str
    marker: str


def expected_revision(variant: ReferenceVariant) -> str:
    """Return the one immutable revision name allowed for a behavior variant."""

    if variant is ReferenceVariant.STABLE:
        return STABLE_REVISION
    if variant is ReferenceVariant.CANDIDATE:
        return CANDIDATE_REVISION
    raise ValueError("unsupported reference variant")


def behavior_marker(variant: ReferenceVariant) -> str:
    """Return the fixed synthetic marker compiled into a behavior variant."""

    if variant is ReferenceVariant.STABLE:
        return STABLE_MARKER
    if variant is ReferenceVariant.CANDIDATE:
        return CANDIDATE_MARKER
    raise ValueError("unsupported reference variant")


def create_reference_app(
    variant: ReferenceVariant,
    *,
    revision: str | None = None,
) -> FastAPI:
    """Create a marker-only app sealed to one exact Cloud Run revision name."""

    if not isinstance(variant, ReferenceVariant):
        raise ValueError("variant must be a ReferenceVariant")
    configured_revision = os.environ.get("K_REVISION") if revision is None else revision
    required_revision = expected_revision(variant)
    if configured_revision != required_revision:
        raise ValueError("K_REVISION does not match the immutable reference variant")

    marker = behavior_marker(variant)
    app = FastAPI(
        title="ControlGraph reference target",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz", response_model=ReferenceHealth)
    def healthz(response: Response) -> ReferenceHealth:
        _set_read_only_headers(response)
        return ReferenceHealth(status="ok")

    @app.get("/v1/probe", response_model=ReferenceProbe)
    def probe(response: Response) -> ReferenceProbe:
        _set_read_only_headers(response)
        return ReferenceProbe(
            schema_version=REFERENCE_PROBE_VERSION,
            revision=required_revision,
            marker=marker,
        )

    return app


def _set_read_only_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


__all__ = [
    "CANDIDATE_MARKER",
    "CANDIDATE_REVISION",
    "REFERENCE_PROBE_VERSION",
    "REFERENCE_SERVICE_NAME",
    "STABLE_MARKER",
    "STABLE_REVISION",
    "ReferenceHealth",
    "ReferenceProbe",
    "ReferenceVariant",
    "behavior_marker",
    "create_reference_app",
    "expected_revision",
]
