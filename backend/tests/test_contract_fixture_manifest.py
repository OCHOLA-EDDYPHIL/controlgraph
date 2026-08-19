import json
from pathlib import Path


def test_shared_contract_fixture_manifest_is_versioned() -> None:
    manifest_path = Path(__file__).parents[2] / "contract-fixtures" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest == {
        "canonical_encoding": "controlgraph.canonical-json/v1",
        "fixture_version": "controlgraph.contract-fixtures/v1",
        "fixture_sets": [{"manifest": "v1/manifest.json", "name": "v1"}],
    }

    for fixture_set in manifest["fixture_sets"]:
        assert (manifest_path.parent / fixture_set["manifest"]).is_file()
