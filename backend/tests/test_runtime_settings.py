import pytest

from controlgraph_canary.settings import ControllerSettings


def _environment() -> dict[str, str]:
    return {
        "CONTROLGRAPH_PROJECT_ID": "controlgraph-canary-abc123",
        "CONTROLGRAPH_PROJECT_NUMBER": "123456789012",
        "CONTROLGRAPH_REGION": "us-central1",
        "CONTROLGRAPH_SERVICE_NAME": "controlgraph-executor",
        "CONTROLGRAPH_CONTROLLER_ID": "controlgraph-canary-abc123:us-central1:executor",
        "CONTROLGRAPH_ROLE": "executor",
        "CONTROLGRAPH_BUILD_DIGEST": f"sha256:{'a' * 64}",
        "CONTROLGRAPH_CONTRACT_VERSION": "controlgraph.contract/v1",
        "CONTROLGRAPH_FIRESTORE_DATABASE": "controlgraph-authority",
        "CONTROLGRAPH_MUTATIONS_ENABLED": "false",
        "CONTROLGRAPH_ENVIRONMENT": "nonprod",
        "CONTROLGRAPH_AUTH_AUDIENCE": (
            "https://controlgraph-executor-123456789012.us-central1.run.app"
        ),
        "CONTROLGRAPH_AUTH_CALLER_ROLE": "execution_task_caller",
        "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
            "cg-execution-task-caller@controlgraph-canary-abc123.iam.gserviceaccount.com"
        ),
        "CONTROLGRAPH_AUTH_CALLER_SUBJECT": "123456789012345678901",
    }


def test_runtime_settings_bind_role_and_environment() -> None:
    settings = ControllerSettings.from_environment(_environment())

    assert settings.project_number == "123456789012"
    assert settings.role == "executor"
    assert settings.service_name == "controlgraph-executor"
    assert settings.mutations_enabled is False


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("CONTROLGRAPH_PROJECT_ID", "shared-project"),
        ("CONTROLGRAPH_PROJECT_NUMBER", "project-number"),
        ("CONTROLGRAPH_REGION", "europe-west1"),
        ("CONTROLGRAPH_SERVICE_NAME", "controlgraph-recovery"),
        ("CONTROLGRAPH_CONTROLLER_ID", "wrong"),
        ("CONTROLGRAPH_ROLE", "planner"),
        ("CONTROLGRAPH_BUILD_DIGEST", "latest"),
        ("CONTROLGRAPH_CONTRACT_VERSION", "controlgraph.contract/v2"),
        ("CONTROLGRAPH_FIRESTORE_DATABASE", "(default)"),
        ("CONTROLGRAPH_MUTATIONS_ENABLED", "true"),
        ("CONTROLGRAPH_ENVIRONMENT", "prod"),
    ],
)
def test_runtime_settings_fail_closed_on_substitution(key: str, value: str) -> None:
    environment = _environment()
    environment[key] = value

    with pytest.raises(ValueError):
        ControllerSettings.from_environment(environment)
