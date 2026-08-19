from importlib import import_module

import pytest


@pytest.mark.parametrize(
    "module_name",
    [
        "controlgraph_canary.application",
        "controlgraph_canary.authority",
        "controlgraph_canary.contracts",
        "controlgraph_canary.http",
        "controlgraph_canary.integrations.google",
        "controlgraph_canary.reference_target",
        "controlgraph_canary.services.coordinator",
        "controlgraph_canary.services.executor",
        "controlgraph_canary.services.issuer",
        "controlgraph_canary.services.recovery",
        "controlgraph_canary.services.verifier",
    ],
)
def test_required_package_boundary_exists(module_name: str) -> None:
    assert import_module(module_name).__name__ == module_name
