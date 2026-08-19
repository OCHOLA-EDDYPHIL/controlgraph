import json
from pathlib import Path

import pytest

from controlgraph_canary.contracts import (
    ContractError,
    EvidenceEvent,
    ExecutionReceipt,
    RolloutRoot,
    TargetBinding,
    TaskRequest,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.base import StrictContractModel

FIXTURE_ROOT = Path(__file__).parents[2] / "contract-fixtures" / "v1"
MODEL_TYPES: dict[str, type[StrictContractModel]] = {
    "EvidenceEvent": EvidenceEvent,
    "ExecutionReceipt": ExecutionReceipt,
    "RolloutRoot": RolloutRoot,
    "TargetBinding": TargetBinding,
    "TaskRequest": TaskRequest,
}


def load_fixture(name: str) -> object:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def test_fixture_manifest_names_the_shared_vectors() -> None:
    assert load_fixture("manifest.json") == {
        "canonical_encoding": "controlgraph.canonical-json/v1",
        "fixture_version": "controlgraph.contract-fixtures/v1",
        "golden": "golden.json",
        "malformed": "malformed.json",
    }


def test_python_matches_every_golden_byte_and_digest() -> None:
    fixture = load_fixture("golden.json")
    assert isinstance(fixture, dict)
    vectors = fixture["vectors"]
    assert isinstance(vectors, list)

    for vector in vectors:
        assert isinstance(vector, dict)
        model_type = MODEL_TYPES[vector["model"]]
        model = decode_contract(vector["canonical"], model_type)
        assert canonical_json_bytes(model).decode("utf-8") == vector["canonical"]
        assert canonical_sha256(model) == vector["sha256"]
        assert model.schema_version == vector["schema_version"]


def test_shared_malformed_vectors_fail_with_stable_codes() -> None:
    fixture = load_fixture("malformed.json")
    assert isinstance(fixture, dict)
    cases = fixture["cases"]
    assert isinstance(cases, list)

    for case in cases:
        assert isinstance(case, dict)
        with pytest.raises(ContractError) as error:
            decode_contract(case["text"], TargetBinding)
        assert error.value.code.value == case["code"], case["name"]
