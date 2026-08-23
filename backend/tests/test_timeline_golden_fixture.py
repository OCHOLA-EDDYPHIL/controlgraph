from pathlib import Path

from timeline_golden_data import operator_timeline_page

from controlgraph_canary.contracts.codec import canonical_json_bytes, decode_contract
from controlgraph_canary.contracts.timeline import (
    TimelineEventType,
    TimelinePageV1,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "timeline" / "operator_timeline_page_v1.json"


def test_operator_timeline_fixture_is_canonical_and_contract_valid() -> None:
    fixture = _FIXTURE.read_bytes()
    expected = operator_timeline_page()

    assert fixture == canonical_json_bytes(expected) + b"\n"
    assert decode_contract(fixture.removesuffix(b"\n"), TimelinePageV1) == expected
    assert {entry.event_type for entry in expected.entries} == {
        TimelineEventType.TASK_CREATED,
        TimelineEventType.MUTATION_APPLIED,
        TimelineEventType.HEALTH_OBSERVED,
        TimelineEventType.HEALTH_DECIDED,
        TimelineEventType.TERMINAL_CLASSIFIED,
        TimelineEventType.RECOVERY_TASK_CREATED,
        TimelineEventType.VERIFICATION_RECORDED,
        TimelineEventType.MODEL_ASSISTANCE_RECORDED,
        TimelineEventType.OPERATOR_ACTION_RECORDED,
    }
    assert b"canonical_record" not in fixture
    assert b"raw_source_id" not in fixture
