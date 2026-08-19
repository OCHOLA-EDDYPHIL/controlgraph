from __future__ import annotations

import importlib
import json
import re

import pytest
from fastapi.testclient import TestClient

from controlgraph_canary.http.service import (
    PRODUCT_CONTRACT_VERSION,
    SERVICE_SHELL_VERSION,
    ServiceRole,
    create_service_app,
    protected_paths,
)

ROLE_MODULES = (
    (ServiceRole.API, "controlgraph_canary.services.api.app"),
    (ServiceRole.COORDINATOR, "controlgraph_canary.services.coordinator.app"),
    (ServiceRole.ISSUER, "controlgraph_canary.services.issuer.app"),
    (ServiceRole.EXECUTOR, "controlgraph_canary.services.executor.app"),
    (ServiceRole.RECOVERY, "controlgraph_canary.services.recovery.app"),
    (ServiceRole.VERIFIER, "controlgraph_canary.services.verifier.app"),
)


@pytest.mark.parametrize(("role", "module_name"), ROLE_MODULES)
def test_each_service_role_has_identity_safe_health_and_metadata(
    role: ServiceRole,
    module_name: str,
) -> None:
    module = importlib.import_module(module_name)
    client = TestClient(module.app)

    health = client.get("/healthz")
    metadata = client.get("/v1/metadata")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["service_role"] == role.value
    assert re.fullmatch(r"[0-9a-f]{32}", health.json()["correlation_id"])
    assert health.headers["x-controlgraph-correlation-id"] == health.json()["correlation_id"]
    assert metadata.status_code == 200
    assert metadata.json()["contract_version"] == PRODUCT_CONTRACT_VERSION
    assert metadata.json()["service_shell_version"] == SERVICE_SHELL_VERSION
    assert metadata.json()["service_role"] == role.value
    assert metadata.json()["mutation_enabled"] is False
    assert metadata.json()["build_digest"] is None
    assert re.fullmatch(r"[0-9a-f]{32}", metadata.json()["correlation_id"])
    assert metadata.headers["x-controlgraph-correlation-id"] == metadata.json()["correlation_id"]
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@pytest.mark.parametrize("role", tuple(ServiceRole))
def test_every_protected_route_remains_disabled_without_reading_sensitive_body(
    role: ServiceRole,
    caplog: pytest.LogCaptureFixture,
) -> None:
    digest = f"sha256:{'c' * 64}"
    client = TestClient(create_service_app(role, build_digest=digest))
    sensitive_marker = "unmistakably-synthetic-capability-and-token"

    for path in protected_paths(role):
        response = client.post(
            path,
            content=f'{{"capability":"{sensitive_marker}"}}',
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {sensitive_marker}",
            },
        )
        assert response.status_code == 503
        assert response.json()["code"] == "MUTATION_DISABLED"
        assert re.fullmatch(r"[0-9a-f]{32}", response.json()["correlation_id"])
        assert (
            response.headers["x-controlgraph-correlation-id"] == response.json()["correlation_id"]
        )
        assert sensitive_marker not in response.text

        duplicate = client.post(path, content=f'{{"capability":"{sensitive_marker}"}}')
        assert duplicate.status_code == 503
        assert duplicate.json()["code"] == "MUTATION_DISABLED"

    metadata = client.get("/v1/metadata")
    assert metadata.json()["build_digest"] == digest
    assert metadata.json()["mutation_enabled"] is False
    assert sensitive_marker not in caplog.text


@pytest.mark.parametrize(
    "digest",
    ["latest", "sha256:abc", f"sha256:{'A' * 64}", f"md5:{'0' * 64}"],
)
def test_service_shell_rejects_mutable_or_malformed_build_identifiers(digest: str) -> None:
    with pytest.raises(ValueError, match="immutable sha256"):
        create_service_app(ServiceRole.EXECUTOR, build_digest=digest)


def test_service_shell_rejects_an_unsupported_configured_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROLGRAPH_CONTRACT_VERSION", "controlgraph.contract/v2")

    with pytest.raises(ValueError, match="CONTRACT_VERSION"):
        create_service_app(ServiceRole.EXECUTOR, build_digest=f"sha256:{'d' * 64}")


def test_service_shell_emits_payload_free_structured_correlation_event(
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = TestClient(create_service_app(ServiceRole.EXECUTOR))
    sensitive_marker = "unmistakably-synthetic-capability-and-token"

    response = client.post(
        protected_paths(ServiceRole.EXECUTOR)[0],
        content=f'{{"capability":"{sensitive_marker}"}}',
        headers={"Authorization": f"Bearer {sensitive_marker}"},
    )

    emitted = capsys.readouterr().err.strip().splitlines()
    event = json.loads(emitted[-1])
    assert event == {
        "correlation_id": response.headers["x-controlgraph-correlation-id"],
        "event": "controlgraph.service.request",
        "service_role": "executor",
        "status_code": 503,
    }
    assert sensitive_marker not in "\n".join(emitted)
