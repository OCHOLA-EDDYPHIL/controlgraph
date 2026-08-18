from fastapi.testclient import TestClient

from controlgraph_canary.api import app


def test_health_endpoint() -> None:
    response = TestClient(app).get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_capabilities_are_safe_by_default() -> None:
    response = TestClient(app).get("/v1/capabilities")

    assert response.status_code == 200
    assert response.json() == {
        "epoch_fence_validation": True,
        "cloud_run_mutations": False,
        "infrastructure_resources": False,
    }
