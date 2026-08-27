"""Harmless stable and candidate probe service."""

from __future__ import annotations

import os
import re
from enum import StrEnum
from typing import Final, Literal

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, ConfigDict

from controlgraph_canary.contracts.codec import canonical_json_bytes
from controlgraph_canary.contracts.independent_verification import (
    SEALED_REFERENCE_PROBE_V1,
    SealedReferenceProbeV1,
)

REFERENCE_PROBE_VERSION: Final = "controlgraph.reference-probe/v1"
REFERENCE_SERVICE_NAME: Final = "controlgraph-reference-target"
STABLE_REVISION: Final = f"{REFERENCE_SERVICE_NAME}-stable-v10"
CANDIDATE_REVISION: Final = f"{REFERENCE_SERVICE_NAME}-candidate-v10"
STABLE_MARKER: Final = "controlgraph-stable-v1"
CANDIDATE_MARKER: Final = "controlgraph-candidate-v1"
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_CORRELATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


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

    @app.get("/v1/probe", response_model=None)
    def probe(
        nonce: str | None = None,
        correlation_id: str | None = None,
    ) -> Response:
        body: bytes | str
        if nonce is None and correlation_id is None:
            body = ReferenceProbe(
                schema_version=REFERENCE_PROBE_VERSION,
                revision=required_revision,
                marker=marker,
            ).model_dump_json()
        elif (
            nonce is None
            or correlation_id is None
            or _NONCE.fullmatch(nonce) is None
            or _CORRELATION.fullmatch(correlation_id) is None
        ):
            raise HTTPException(status_code=400, detail="probe seal invalid")
        else:
            body = canonical_json_bytes(
                SealedReferenceProbeV1(
                    schema_version=SEALED_REFERENCE_PROBE_V1,
                    revision=required_revision,
                    marker=marker,
                    nonce=nonce,
                    correlation_id=correlation_id,
                )
            )
        response = Response(
            content=body,
            media_type="application/json",
        )
        _set_read_only_headers(response)
        return response

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
