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
            "CONTROLGRAPH_OPERATOR_CONSOLE_ORIGIN": (
                "https://controlgraph-console-123456789012.us-central1.run.app"
            ),
            "CONTROLGRAPH_SECURITY_AUDITOR_EMAIL": (
                "cg-security-auditor@controlgraph-canary-abc123."
                "iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_SECURITY_AUDITOR_SUBJECT": "223456789012345678901",
            "CONTROLGRAPH_RESTRICTED_EXPORTER_EMAIL": (
                "cg-restricted-exporter@controlgraph-canary-abc123."
                "iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_RESTRICTED_EXPORTER_SUBJECT": "323456789012345678901",
        }
    )
    return environment


def _advisor_environment() -> dict[str, str]:
    environment = _environment()
    environment.update(
        {
            "CONTROLGRAPH_SERVICE_NAME": "controlgraph-advisor",
            "CONTROLGRAPH_CONTROLLER_ID": (
                "controlgraph-canary-abc123:us-central1:advisor"
            ),
            "CONTROLGRAPH_ROLE": "advisor",
            "CONTROLGRAPH_AUTH_AUDIENCE": (
                "https://controlgraph-advisor-123456789012.us-central1.run.app"
            ),
            "CONTROLGRAPH_AUTH_CALLER_ROLE": "coordinator",
            "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
                "controlgraph-coordinator@controlgraph-canary-abc123."
                "iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_ADVISOR_MODEL": "gemini-3.5-flash",
            "CONTROLGRAPH_ADVISOR_MODEL_LOCATION": "global",
            "CONTROLGRAPH_ADVISOR_API_VERSION": "v1",
            "CONTROLGRAPH_ADVISOR_PROMPT_VERSION": (
                "controlgraph.rollout-advisor-prompt/v1"
            ),
            "CONTROLGRAPH_ADVISOR_TIMEOUT_SECONDS": "20",
            "CONTROLGRAPH_ADVISOR_MAX_LLM_CALLS": "4",
            "CONTROLGRAPH_ADVISOR_MAX_OUTPUT_TOKENS": "2048",
            "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS": "false",
            "GOOGLE_GENAI_USE_ENTERPRISE": "true",
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
            "CONTROLGRAPH_EVIDENCE_KEY_VERSION": (
                "projects/controlgraph-canary-abc123/locations/us-central1/"
                "keyRings/controlgraph-signing/cryptoKeys/evidence-signing/"
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
            "CONTROLGRAPH_RECOVERY_FACADE_CALLER_EMAIL": (
                "controlgraph-recovery@controlgraph-canary-abc123."
                "iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_RECOVERY_FACADE_CALLER_SUBJECT": "123456789012345678902",
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


def test_enabled_recovery_requires_the_sealed_executor_facade() -> None:
    environment = _environment()
    environment.update(
        {
            "CONTROLGRAPH_SERVICE_NAME": "controlgraph-recovery",
            "CONTROLGRAPH_CONTROLLER_ID": (
                "controlgraph-canary-abc123:us-central1:recovery"
            ),
            "CONTROLGRAPH_ROLE": "recovery",
            "CONTROLGRAPH_MUTATIONS_ENABLED": "true",
            "CONTROLGRAPH_AUTH_AUDIENCE": (
                "https://controlgraph-recovery-123456789012.us-central1.run.app"
            ),
            "CONTROLGRAPH_AUTH_CALLER_ROLE": "recovery_task_caller",
            "CONTROLGRAPH_AUTH_CALLER_EMAIL": (
                "cg-recovery-task-caller@controlgraph-canary-abc123."
                "iam.gserviceaccount.com"
            ),
            "CONTROLGRAPH_CAPABILITY_KEY_VERSION": (
                "projects/controlgraph-canary-abc123/locations/us-central1/"
                "keyRings/controlgraph-signing/cryptoKeys/capability-signing/"
                "cryptoKeyVersions/1"
            ),
            "CONTROLGRAPH_EVIDENCE_KEY_VERSION": (
                "projects/controlgraph-canary-abc123/locations/us-central1/"
                "keyRings/controlgraph-signing/cryptoKeys/evidence-signing/"
                "cryptoKeyVersions/1"
            ),
            "CONTROLGRAPH_EXECUTOR_URL": (
                "https://controlgraph-executor-123456789012."
                "us-central1.run.app"
            ),
        }
    )

    settings = ControllerSettings.from_environment(environment)

    assert settings.role == "recovery"
    assert settings.mutations_enabled is True
    assert settings.coordinator_url is None
    assert settings.executor_url == environment["CONTROLGRAPH_EXECUTOR_URL"]
    assert settings.target_network_resource is None
    assert settings.target_subnetwork_resource is None
    assert settings.capability_key_version == environment[
        "CONTROLGRAPH_CAPABILITY_KEY_VERSION"
    ]


def test_api_requires_and_binds_exact_operator_oauth_client_audience() -> None:
    environment = _api_environment()

    settings = ControllerSettings.from_environment(environment)

    assert settings.operator_oauth_client_audience == environment[
        "CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE"
    ]
    assert (
        settings.operator_console_origin
        == environment["CONTROLGRAPH_OPERATOR_CONSOLE_ORIGIN"]
    )
    assert settings.security_auditor_identity == (
        "cg-security-auditor@controlgraph-canary-abc123.iam.gserviceaccount.com"
    )
    assert settings.restricted_exporter_identity == (
        "cg-restricted-exporter@controlgraph-canary-abc123.iam.gserviceaccount.com"
    )


def test_api_rejects_human_privileged_timeline_identity() -> None:
    environment = _api_environment()
    environment["CONTROLGRAPH_SECURITY_AUDITOR_EMAIL"] = environment[
        "CONTROLGRAPH_AUTH_CALLER_EMAIL"
    ]
    with pytest.raises(ValueError, match="privileged reader identity"):
        ControllerSettings.from_environment(environment)


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


def test_advisor_settings_are_exact_and_mutation_disabled() -> None:
    settings = ControllerSettings.from_environment(_advisor_environment())

    assert settings.role == "advisor"
    assert settings.mutations_enabled is False
    assert settings.advisor_model == "gemini-3.5-flash"
    assert settings.advisor_model_location == "global"
    assert settings.advisor_api_version == "v1"
    assert settings.advisor_timeout_seconds == 20
    assert settings.advisor_max_llm_calls == 4
    assert settings.advisor_max_output_tokens == 2048
    assert settings.capability_key_version is None
    assert settings.evidence_key_version is None


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("CONTROLGRAPH_ADVISOR_MODEL", "gemini-flash-latest"),
        ("CONTROLGRAPH_ADVISOR_MODEL_LOCATION", "us-central1"),
        ("CONTROLGRAPH_ADVISOR_API_VERSION", "v1beta1"),
        ("CONTROLGRAPH_ADVISOR_PROMPT_VERSION", "unversioned"),
        ("CONTROLGRAPH_ADVISOR_TIMEOUT_SECONDS", "31"),
        ("CONTROLGRAPH_ADVISOR_MAX_LLM_CALLS", "5"),
        ("CONTROLGRAPH_ADVISOR_MAX_OUTPUT_TOKENS", "4096"),
        ("ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS", "true"),
        ("GOOGLE_GENAI_USE_ENTERPRISE", "false"),
    ],
)
def test_advisor_rejects_substituted_model_configuration(key: str, value: str) -> None:
    environment = _advisor_environment()
    environment[key] = value

    with pytest.raises(ValueError, match="advisor model configuration"):
        ControllerSettings.from_environment(environment)


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "http://controlgraph-console-123456789012.us-central1.run.app",
        "https://controlgraph-api-123456789012.us-central1.run.app",
        "https://controlgraph-console-123456789012.us-central1.run.app/",
        "https://controlgraph-console-999999999999.us-central1.run.app",
    ],
)
def test_api_rejects_noncanonical_operator_console_origin(origin: str) -> None:
    environment = _api_environment()
    environment["CONTROLGRAPH_OPERATOR_CONSOLE_ORIGIN"] = origin

    with pytest.raises(ValueError, match="CONTROLGRAPH_OPERATOR_CONSOLE_ORIGIN"):
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
