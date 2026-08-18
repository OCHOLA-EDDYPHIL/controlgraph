"""Read-only HTTP surface for the controller scaffold."""

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from controlgraph_canary import __version__


class HealthResponse(BaseModel):
    """Service health response."""

    model_config = ConfigDict(frozen=True)

    status: str
    version: str


class CapabilitiesResponse(BaseModel):
    """Safe, static declaration of implemented capabilities."""

    model_config = ConfigDict(frozen=True)

    epoch_fence_validation: bool
    cloud_run_mutations: bool
    infrastructure_resources: bool


app = FastAPI(
    title="ControlGraph Canary",
    version=__version__,
    description="Read-only service scaffold for an epoch-fenced Cloud Run canary controller.",
)


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    """Report process health without consulting cloud services."""

    return HealthResponse(status="ok", version=__version__)


@app.get("/v1/capabilities", response_model=CapabilitiesResponse)
def capabilities() -> CapabilitiesResponse:
    """Report which safety-relevant features are present in this scaffold."""

    return CapabilitiesResponse(
        epoch_fence_validation=True,
        cloud_run_mutations=False,
        infrastructure_resources=False,
    )
