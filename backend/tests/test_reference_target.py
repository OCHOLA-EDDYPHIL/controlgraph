from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from controlgraph_canary.reference_target import (
    CANDIDATE_MARKER,
    CANDIDATE_REVISION,
    STABLE_MARKER,
    STABLE_REVISION,
    ReferenceVariant,
    create_reference_app,
)


@pytest.mark.parametrize(
    ("variant", "revision", "marker"),
    [
        (ReferenceVariant.STABLE, STABLE_REVISION, STABLE_MARKER),
        (ReferenceVariant.CANDIDATE, CANDIDATE_REVISION, CANDIDATE_MARKER),
    ],
)
def test_probe_returns_only_fixed_synthetic_revision_behavior(
    variant: ReferenceVariant,
    revision: str,
    marker: str,
) -> None:
    client = TestClient(create_reference_app(variant, revision=revision))

    health = client.get("/healthz")
    probe = client.get("/v1/probe")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert probe.status_code == 200
    assert probe.json() == {
        "schema_version": "controlgraph.reference-probe/v1",
        "revision": revision,
        "marker": marker,
    }
    assert health.headers["cache-control"] == "no-store"
    assert probe.headers["cache-control"] == "no-store"
    assert probe.headers["x-content-type-options"] == "nosniff"
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.post("/v1/probe").status_code == 405


def test_stable_and_candidate_behavior_is_distinct() -> None:
    stable = TestClient(
        create_reference_app(ReferenceVariant.STABLE, revision=STABLE_REVISION)
    ).get("/v1/probe")
    candidate = TestClient(
        create_reference_app(ReferenceVariant.CANDIDATE, revision=CANDIDATE_REVISION)
    ).get("/v1/probe")

    assert stable.json()["revision"] != candidate.json()["revision"]
    assert stable.json()["marker"] != candidate.json()["marker"]


@pytest.mark.parametrize(
    ("variant", "revision"),
    [
        (ReferenceVariant.STABLE, CANDIDATE_REVISION),
        (ReferenceVariant.CANDIDATE, STABLE_REVISION),
        (ReferenceVariant.STABLE, "reference-target-stable"),
        (ReferenceVariant.CANDIDATE, ""),
    ],
)
def test_reference_app_rejects_revision_substitution(
    variant: ReferenceVariant,
    revision: str,
) -> None:
    with pytest.raises(ValueError, match="K_REVISION"):
        create_reference_app(variant, revision=revision)


def test_reference_app_reads_only_the_platform_revision_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("K_REVISION", STABLE_REVISION)
    monkeypatch.setenv("SYNTHETIC_SECRET", "unmistakably-synthetic-secret")

    response = TestClient(create_reference_app(ReferenceVariant.STABLE)).get("/v1/probe")

    assert response.json()["revision"] == STABLE_REVISION
    assert "unmistakably-synthetic-secret" not in response.text
