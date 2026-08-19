import json
from pathlib import Path


def test_shared_contract_fixture_manifest_is_versioned() -> None:
    manifest_path = Path(__file__).parents[2] / "contract-fixtures" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest == {
        "canonical_encoding": "controlgraph.canonical-json/v1",
        "fixture_version": "controlgraph.contract-fixtures/v1",
        "fixtures": [],
    }
