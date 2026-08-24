from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]


def _text(path: str) -> str:
    return (REPOSITORY_ROOT / path).read_text(encoding="utf-8")


def test_foundation_enables_vertex_and_grants_advisor_only_prediction() -> None:
    apis = _text("infra/foundation/apis.tf")
    roles = _text("infra/foundation/iam_roles.tf")
    bindings = _text("infra/foundation/iam_bindings.tf")

    assert '"aiplatform.googleapis.com"' in apis
    role = re.search(
        r"vertex_advisor\s*=\s*\{(?P<body>.*?)\n\s*\}",
        roles,
        flags=re.DOTALL,
    )
    assert role is not None
    assert '"aiplatform.endpoints.predict"' in role.group("body")
    assert "aiplatform." not in role.group("body").replace(
        "aiplatform.endpoints.predict", ""
    )
    assert 'workloads["advisor"].member' in bindings
    assert 'controlgraph["vertex_advisor"].name' in bindings


def test_advisor_has_no_firestore_or_mutation_identity_grant() -> None:
    matrix = _text("infra/foundation/iam_matrix.tf")
    firestore = _text("infra/foundation/firestore.tf")

    expected_rows = re.findall(
        r"advisor\s*=\s*toset\(\[(?P<body>.*?)\]\)",
        matrix,
        flags=re.DOTALL,
    )
    assert len(expected_rows) == 2
    assert all(re.findall(r'"([^\"]+)"', row) == ["vertex_model_predict"] for row in expected_rows)
    reader_block = re.search(
        r"firestore_readers\s*=\s*toset\(\[(?P<body>.*?)\]\)",
        firestore,
        flags=re.DOTALL,
    )
    assert reader_block is not None
    assert '"advisor"' not in reader_block.group("body")
    assert 'firestore_writers = toset(["coordinator"])' in firestore


def test_runtime_binds_one_private_advisor_to_the_coordinator() -> None:
    services = _text("infra/runtime/services.tf")
    iam = _text("infra/runtime/iam.tf")

    advisor_module = re.search(
        r'module "advisor" \{(?P<body>.*?)\n\}',
        services,
        flags=re.DOTALL,
    )
    assert advisor_module is not None
    body = advisor_module.group("body")
    assert "container_image   = var.advisor_image" in body
    assert "service_account   = local.service_accounts.advisor" in body
    assert 'ingress           = "INGRESS_TRAFFIC_INTERNAL_ONLY"' in body
    assert "maximum_instances = 1" in body
    assert "concurrency       = 1" in body
    assert re.search(r'CONTROLGRAPH_ADVISOR_MODEL\s*=\s*"gemini-3\.5-flash"', body)
    assert re.search(r'CONTROLGRAPH_ADVISOR_MODEL_LOCATION\s*=\s*"global"', body)
    assert re.search(r'ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS\s*=\s*"false"', body)
    assert re.search(r'GOOGLE_GENAI_USE_ENTERPRISE\s*=\s*"true"', body)
    assert "local.run_invokers.advisor.member ==" in iam
    assert '"serviceAccount:${local.service_accounts.coordinator}"' in iam
