from __future__ import annotations

import json

import pytest

from controlgraph_canary.application.reference_target_reset import (
    ReferenceTargetResetConfiguration,
    ReferenceTargetResetOutcome,
    ReferenceTargetResetRequest,
    ReferenceTargetResetResult,
)
from controlgraph_canary.reference_target_reset_cli import main

PROJECT_ID = "controlgraph-canary-a1b2c3"
STABLE_IMAGE = (
    f"us-central1-docker.pkg.dev/{PROJECT_ID}/controlgraph-canary/reference-stable"
    f"@sha256:{'4' * 64}"
)
CANDIDATE_IMAGE = (
    f"us-central1-docker.pkg.dev/{PROJECT_ID}/controlgraph-canary/reference-candidate"
    f"@sha256:{'5' * 64}"
)


def _arguments(*, project_id: str = PROJECT_ID) -> list[str]:
    return [
        "--project-id",
        project_id,
        "--stable-image",
        STABLE_IMAGE,
        "--candidate-image",
        CANDIDATE_IMAGE,
        "--network-resource",
        f"projects/{project_id}/global/networks/controlgraph-canary",
        "--subnetwork-resource",
        (
            f"projects/{project_id}/regions/us-central1/"
            "subnetworks/controlgraph-canary-us-central1"
        ),
        "--expected-etag",
        "etag-before-reset",
        "--confirm",
        "RESET_REFERENCE_TARGET_BASELINE",
    ]


def test_reference_target_reset_command_emits_exact_readback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Resetter:
        def __init__(self, configuration: ReferenceTargetResetConfiguration) -> None:
            self.configuration = configuration

        async def reset(
            self,
            request: ReferenceTargetResetRequest,
        ) -> ReferenceTargetResetResult:
            return ReferenceTargetResetResult(
                configuration=self.configuration,
                request=request,
                outcome=ReferenceTargetResetOutcome.RESET_APPLIED,
                previous_generation=8,
                observed_generation=9,
                observed_etag="etag-after-reset",
                operation_name="operations/reference-target-reset-1",
            )

    assert main(_arguments(), resetter_factory=Resetter) == 0
    assert json.loads(capsys.readouterr().out) == {
        "action": "reset-reference-target-baseline",
        "candidate_image": CANDIDATE_IMAGE,
        "candidate_percent": 0,
        "candidate_revision": "controlgraph-reference-target-candidate-v15",
        "observed_etag": "etag-after-reset",
        "observed_generation": 9,
        "operation_name": "operations/reference-target-reset-1",
        "outcome": "RESET_APPLIED",
        "previous_etag": "etag-before-reset",
        "previous_generation": 8,
        "project_id": PROJECT_ID,
        "region": "us-central1",
        "service_name": "controlgraph-reference-target",
        "stable_image": STABLE_IMAGE,
        "stable_percent": 100,
        "stable_revision": "controlgraph-reference-target-stable-v15",
    }


def test_reference_target_reset_command_rejects_an_unbound_project_before_cloud(
    capsys: pytest.CaptureFixture[str],
) -> None:
    called = False

    def fail_factory(_configuration: ReferenceTargetResetConfiguration) -> object:
        nonlocal called
        called = True
        raise AssertionError("invalid reset must not construct a provider client")

    assert main(_arguments(project_id="shared-project"), resetter_factory=fail_factory) == 2
    assert called is False
    assert json.loads(capsys.readouterr().out) == {
        "code": "REFERENCE_TARGET_RESET_COMMAND_INVALID"
    }


def test_reference_target_reset_request_preserves_a_provider_quoted_etag() -> None:
    request = ReferenceTargetResetRequest(
        expected_etag='"provider-etag=="',
        confirmation="RESET_REFERENCE_TARGET_BASELINE",
    )

    assert request.expected_etag == '"provider-etag=="'


@pytest.mark.parametrize("expected_etag", ['""', '"unclosed', 'embedded"quote'])
def test_reference_target_reset_request_rejects_malformed_quoted_etags(
    expected_etag: str,
) -> None:
    with pytest.raises(ValueError, match="expected etag"):
        ReferenceTargetResetRequest(
            expected_etag=expected_etag,
            confirmation="RESET_REFERENCE_TARGET_BASELINE",
        )
