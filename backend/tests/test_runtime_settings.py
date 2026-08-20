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


def _api_environment() -> dict[str, str]:
    environment = _environment()
    environment.update(
        {
            "CONTROLGRAPH_SERVICE_NAME": "controlgraph-api",
            "CONTROLGRAPH_CONTROLLER_ID": "controlgraph-canary-abc123:us-central1:api",
            "CONTROLGRAPH_ROLE": "api",
            "CONTROLGRAPH_AUTH_AUDIENCE": (
                "https://controlgraph-api-123456789012.us-central1.run.app"
            ),
            "CONTROLGRAPH_AUTH_CALLER_ROLE": "operator",
            "CONTROLGRAPH_AUTH_CALLER_EMAIL": "operator@example.com",
            "CONTROLGRAPH_COORDINATOR_URL": (
                "https://controlgraph-coordinator-123456789012."
                "us-central1.run.app"
            ),
            "CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE": (
                "32555940559.apps.googleusercontent.com"
            ),
        }
    )
    return environment


def test_runtime_settings_bind_role_and_environment() -> None:
    settings = ControllerSettings.from_environment(_environment())

    assert settings.project_number == "123456789012"
    assert settings.role == "executor"
    assert settings.service_name == "controlgraph-executor"
    assert settings.mutations_enabled is False
    assert settings.evidence_key_version is None
    assert settings.signing_algorithm is None


def test_enabled_executor_requires_and_binds_exact_mutation_configuration() -> None:
    environment = _environment()
    environment.update(
        {
            "CONTROLGRAPH_MUTATIONS_ENABLED": "true",
            "CONTROLGRAPH_CAPABILITY_KEY_VERSION": (
                "projects/controlgraph-canary-abc123/locations/us-central1/"
                "keyRings/controlgraph-signing/cryptoKeys/capability-signing/"
                "cryptoKeyVersions/1"
            ),
            "CONTROLGRAPH_COORDINATOR_URL": (
                "https://controlgraph-coordinator-123456789012."
                "us-central1.run.app"
            ),
            "CONTROLGRAPH_TARGET_NETWORK_RESOURCE": (
                "projects/controlgraph-canary-abc123/global/networks/"
                "controlgraph-network"
            ),
            "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE": (
                "projects/controlgraph-canary-abc123/regions/us-central1/"
                "subnetworks/controlgraph-runtime"
            ),
        }
    )

    settings = ControllerSettings.from_environment(environment)

    assert settings.mutations_enabled is True
    assert settings.coordinator_url == environment["CONTROLGRAPH_COORDINATOR_URL"]
    assert settings.capability_key_version == environment[
        "CONTROLGRAPH_CAPABILITY_KEY_VERSION"
    ]
    assert settings.target_network_resource == environment[
        "CONTROLGRAPH_TARGET_NETWORK_RESOURCE"
    ]
    assert settings.target_subnetwork_resource == environment[
        "CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE"
    ]


def test_api_requires_and_binds_exact_operator_oauth_client_audience() -> None:
    environment = _api_environment()

    settings = ControllerSettings.from_environment(environment)

    assert settings.operator_oauth_client_audience == environment[
        "CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE"
    ]


@pytest.mark.parametrize(
    "audience",
    [
        "",
        "https://controlgraph-api-123456789012.us-central1.run.app",
        "client.apps.googleusercontent.com",
        "32555940559.apps.googleusercontent.com ",
    ],
)
def test_api_rejects_missing_or_malformed_operator_oauth_client_audience(
    audience: str,
) -> None:
    environment = _api_environment()
    environment["CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE"] = audience

    with pytest.raises(ValueError):
        ControllerSettings.from_environment(environment)


def test_api_rejects_absent_operator_oauth_client_audience() -> None:
    environment = _api_environment()
    del environment["CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE"]

    with pytest.raises(ValueError, match="missing environment variables"):
        ControllerSettings.from_environment(environment)


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
        ("CONTROLGRAPH_MUTATIONS_ENABLED", "enabled"),
        ("CONTROLGRAPH_ENVIRONMENT", "prod"),
    ],
)
def test_runtime_settings_fail_closed_on_substitution(key: str, value: str) -> None:
    environment = _environment()
    environment[key] = value

    with pytest.raises(ValueError):
        ControllerSettings.from_environment(environment)
