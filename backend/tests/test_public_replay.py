from __future__ import annotations

from collections.abc import Callable
from typing import Literal

import pytest
from pydantic import ValidationError
from recovery_v2_test_data import make_unhealthy_v3_recovery_bundle
from test_recovery_facade_runtime import _recovery_receipt

from controlgraph_canary.application.timeline_projectors import project_execution_receipt
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import CapabilityAction
from controlgraph_canary.contracts.public_replay import (
    PublicReplayAdvisorV1,
    PublicReplayAdvisorValidatedV1,
    PublicReplayAuthorityAdvancedV1,
    PublicReplayCaseKind,
    PublicReplayCaseV1,
    PublicReplayCitationV1,
    PublicReplayEnvelopeV1,
    PublicReplayEventEnvelopeV1,
    PublicReplayEventV1,
    PublicReplayFindingV1,
    PublicReplayImageComponent,
    PublicReplayImageV1,
    PublicReplayPayloadV1,
    PublicReplayRecoveryVerifiedV1,
    PublicReplaySeedV1,
    PublicReplayStaleDenialV1,
    PublicReplayTargetUnchangedV1,
    PublicReplayTimelineCommittedV1,
    PublicReplayTimelineEntryV1,
    PublicReplayTimelineEventType,
    PublicReplayTimelineV1,
    PublicReplayToolCallV1,
    PublicReplayTrafficV1,
    create_public_replay_envelope,
    create_public_replay_payload,
)
from controlgraph_canary.contracts.timeline import (
    TimelineEventType,
    standard_timeline_evidence_policy_set,
)

type CitationKind = Literal["receipt", "timeline", "target"]
type ToolId = Literal[
    "read_root_summary",
    "read_target_summary",
    "read_health_summary",
    "read_receipt_summary",
    "read_timeline_summary",
    "read_verifier_summary",
]


def _digest(value: int) -> str:
    return f"{value:064x}"


def _traffic(*, stable: int, candidate: int, digest: int) -> PublicReplayTrafficV1:
    return PublicReplayTrafficV1(
        schema_version="controlgraph.public-replay-traffic/v1",
        stable_percent=stable,
        candidate_percent=candidate,
        target_configuration_sha256=_digest(digest),
    )


def _advisor() -> PublicReplayAdvisorV1:
    citation_kinds: tuple[CitationKind, ...] = ("receipt", "timeline", "target")
    citations = tuple(
        PublicReplayCitationV1(
            schema_version="controlgraph.public-replay-citation/v1",
            evidence_kind=kind,
            evidence_id=f"evidence-{kind}",
            source_sha256=_digest(20 + index),
        )
        for index, kind in enumerate(citation_kinds, start=1)
    )
    tool_ids: tuple[ToolId, ...] = (
        "read_root_summary",
        "read_target_summary",
        "read_health_summary",
        "read_receipt_summary",
        "read_timeline_summary",
        "read_verifier_summary",
    )
    return PublicReplayAdvisorV1(
        schema_version="controlgraph.public-replay-advisor/v1",
        model_id="gemini-3.5-flash",
        model_location="global",
        prompt_version="controlgraph.rollout-advisor-prompt/v2",
        response_sha256=_digest(30),
        audit_sha256=_digest(31),
        registry_sha256=_digest(32),
        snapshot_sha256=_digest(33),
        structured_output_sha256=_digest(34),
        validation="accepted",
        authority_effect="none",
        deterministic_health_override=False,
        operator_review_required=True,
        requested_operator_action="manual_review",
        confidence_basis_points=8_400,
        findings=(
            PublicReplayFindingV1(
                schema_version="controlgraph.public-replay-finding/v1",
                statement="Stale work was denied after the authority epoch advanced.",
                citations=citations,
            ),
        ),
        tool_calls=tuple(
            PublicReplayToolCallV1(
                schema_version="controlgraph.public-replay-tool-call/v1",
                sequence=index,
                tool_id=tool_id,
                input_sha256=_digest(40 + index),
                output_sha256=_digest(50 + index),
                status="succeeded",
            )
            for index, tool_id in enumerate(tool_ids, start=1)
        ),
        replayed_without_model_call=True,
    )


def _timeline() -> PublicReplayTimelineV1:
    entries = tuple(
        PublicReplayTimelineEntryV1(
            schema_version="controlgraph.public-replay-timeline-entry/v1",
            sequence=100 + index,
            entry_sha256=_digest(60 + index),
            event_type=event_type,
            occurred_at=f"2026-08-24T00:00:0{index - 1}Z",
            verification_status=(
                "VERIFIED"
                if event_type is PublicReplayTimelineEventType.MUTATION_APPLIED
                else "NOT_APPLICABLE"
            ),
        )
        for index, event_type in enumerate(PublicReplayTimelineEventType, start=1)
    )
    return PublicReplayTimelineV1(
        schema_version="controlgraph.public-replay-timeline/v1",
        head_sequence=104,
        head_entry_sha256=entries[-1].entry_sha256,
        entry_count=104,
        page_count=3,
        page_set_sha256=_digest(70),
        entries=entries,
    )


def _seed() -> PublicReplaySeedV1:
    canary = _traffic(stable=90, candidate=10, digest=80)
    return PublicReplaySeedV1(
        schema_version="controlgraph.public-replay-seed/v1",
        authority_occurred_at="2026-08-24T00:00:00Z",
        denial_occurred_at="2026-08-24T00:00:01Z",
        unchanged_observed_at="2026-08-24T00:00:02Z",
        advisor_requested_at="2026-08-24T00:00:03Z",
        recovery_occurred_at="2026-08-24T00:00:04Z",
        timeline_observed_at="2026-08-24T00:00:05Z",
        authority=PublicReplayAuthorityAdvancedV1(
            schema_version="controlgraph.public-replay-authority-advanced/v1",
            previous_epoch=7,
            new_epoch=8,
            cause="OPERATOR_REVOCATION",
            transition_sha256=_digest(81),
        ),
        denial=PublicReplayStaleDenialV1(
            schema_version="controlgraph.public-replay-stale-denial/v1",
            work_epoch=7,
            current_authority_epoch=8,
            outcome="DENIED",
            reason_code="EPOCH_MISMATCH",
            receipt_sha256=_digest(82),
        ),
        unchanged=PublicReplayTargetUnchangedV1(
            schema_version="controlgraph.public-replay-target-unchanged/v1",
            before_denial=canary,
            after_denial=canary,
        ),
        advisor=PublicReplayAdvisorValidatedV1(
            schema_version="controlgraph.public-replay-advisor-validated/v1",
            advisor=_advisor(),
        ),
        recovery=PublicReplayRecoveryVerifiedV1(
            schema_version="controlgraph.public-replay-recovery-verified/v1",
            outcome="VERIFIED",
            receipt_sha256=_digest(83),
            traffic=_traffic(stable=100, candidate=0, digest=84),
        ),
        timeline=PublicReplayTimelineCommittedV1(
            schema_version="controlgraph.public-replay-timeline-committed/v1",
            timeline=_timeline(),
        ),
    )


def _images() -> tuple[PublicReplayImageV1, ...]:
    return tuple(
        PublicReplayImageV1(
            schema_version="controlgraph.public-replay-image/v1",
            component=component,
            reference=(
                "us-central1-docker.pkg.dev/controlgraph-canary-abc123/"
                f"controlgraph-canary/{component.value}@sha256:{_digest(90 + index)}"
            ),
        )
        for index, component in enumerate(PublicReplayImageComponent, start=1)
    )


def _cases() -> tuple[PublicReplayCaseV1, ...]:
    return tuple(
        PublicReplayCaseV1(
            schema_version="controlgraph.public-replay-case/v1",
            sequence=index,
            kind=kind,
            case_sha256=_digest(100 + index),
        )
        for index, kind in enumerate(PublicReplayCaseKind, start=1)
    )


def _payload() -> PublicReplayPayloadV1:
    return create_public_replay_payload(
        source_commit="a" * 40,
        acceptance_manifest_sha256=_digest(120),
        acceptance_run_id=f"cgacceptance:{_digest(121)}",
        accepted_at="2026-08-24T00:00:06Z",
        images=_images(),
        cases=_cases(),
        seed=_seed(),
    )


def _rehash_events(
    payload: PublicReplayPayloadV1,
    mutate: Callable[[int, dict[str, object]], None],
) -> tuple[tuple[PublicReplayEventEnvelopeV1, ...], str]:
    predecessor: str | None = None
    rebuilt: list[PublicReplayEventEnvelopeV1] = []
    for index, envelope in enumerate(payload.events):
        event_value = envelope.event.model_dump(mode="python")
        mutate(index, event_value)
        event_value["previous_event_sha256"] = predecessor
        event = PublicReplayEventV1.model_validate(event_value)
        predecessor = canonical_sha256(event)
        rebuilt.append(
            PublicReplayEventEnvelopeV1(
                schema_version="controlgraph.public-replay-event-envelope/v1",
                event=event,
                event_sha256=predecessor,
            )
        )
    assert predecessor is not None
    return tuple(rebuilt), predecessor


def test_public_replay_round_trip_binds_complete_surface() -> None:
    envelope = create_public_replay_envelope(_payload())
    encoded = canonical_json_bytes(envelope)
    advisor = envelope.payload.events[3].event.details
    timeline = envelope.payload.events[-1].event.details

    assert decode_contract(encoded, PublicReplayEnvelopeV1) == envelope
    assert len(envelope.payload.images) == 5
    assert tuple(item.kind for item in envelope.payload.cases) == tuple(PublicReplayCaseKind)
    assert isinstance(advisor, PublicReplayAdvisorValidatedV1)
    assert len(advisor.advisor.tool_calls) == 6
    assert isinstance(timeline, PublicReplayTimelineCommittedV1)
    assert {item.event_type for item in timeline.timeline.entries} == set(
        PublicReplayTimelineEventType
    )


def test_public_replay_rejects_duplicate_advisor_tool() -> None:
    value = _advisor().model_dump(mode="python")
    calls = list(value["tool_calls"])
    calls[1] = {**calls[1], "tool_id": calls[0]["tool_id"]}
    value["tool_calls"] = tuple(calls)

    with pytest.raises(ValidationError, match="tool calls"):
        PublicReplayAdvisorV1.model_validate(value)


@pytest.mark.parametrize("tamper", ["reordered", "duplicate"])
def test_public_replay_rejects_noncanonical_cases(tamper: str) -> None:
    value = _payload().model_dump(mode="python")
    cases = list(value["cases"])
    if tamper == "reordered":
        cases[0], cases[1] = cases[1], cases[0]
    else:
        cases[1] = cases[0]
    value["cases"] = tuple(cases)

    with pytest.raises(ValidationError, match="case commitments"):
        PublicReplayPayloadV1.model_validate(value)


def test_public_replay_rejects_broken_event_chain() -> None:
    payload = _payload()
    value = payload.model_dump(mode="python")
    events = list(value["events"])
    event_value = payload.events[1].event.model_dump(mode="python")
    event_value["previous_event_sha256"] = "0" * 64
    event = PublicReplayEventV1.model_validate(event_value)
    events[1] = PublicReplayEventEnvelopeV1(
        schema_version="controlgraph.public-replay-event-envelope/v1",
        event=event,
        event_sha256=canonical_sha256(event),
    ).model_dump(mode="python")
    value["events"] = tuple(events)

    with pytest.raises(ValidationError, match="event chain"):
        PublicReplayPayloadV1.model_validate(value)


def test_public_replay_rejects_cross_event_epoch_mismatch() -> None:
    payload = _payload()

    def change_denial(index: int, event: dict[str, object]) -> None:
        if index == 1:
            details = event["details"]
            assert isinstance(details, dict)
            details["work_epoch"] = 9
            details["current_authority_epoch"] = 10

    events, head = _rehash_events(payload, change_denial)
    value = payload.model_dump(mode="python")
    value["events"] = tuple(item.model_dump(mode="python") for item in events)
    value["event_chain_head_sha256"] = head

    with pytest.raises(ValidationError, match="authority and denial"):
        PublicReplayPayloadV1.model_validate(value)


def test_public_replay_rejects_duplicate_timeline_sequence() -> None:
    value = _timeline().model_dump(mode="python")
    entries = list(value["entries"])
    entries[1] = {**entries[1], "sequence": entries[0]["sequence"]}
    value["entries"] = tuple(entries)

    with pytest.raises(ValidationError, match="timeline commitments"):
        PublicReplayTimelineV1.model_validate(value)


def test_public_replay_timeline_allows_replayed_earlier_timestamp() -> None:
    value = _timeline().model_dump(mode="python")
    entries = list(value["entries"])
    entries.extend(
        (
            {
                **entries[1],
                "sequence": 105,
                "entry_sha256": _digest(75),
                "occurred_at": "2026-08-24T00:00:04Z",
            },
            {
                **entries[3],
                "sequence": 106,
                "entry_sha256": _digest(76),
                "occurred_at": "2026-08-24T00:00:03Z",
            },
        )
    )
    value.update(
        entries=tuple(entries),
        entry_count=106,
        head_sequence=106,
        head_entry_sha256=_digest(76),
    )

    timeline = PublicReplayTimelineV1.model_validate(value)

    assert len(timeline.entries) == 6
    assert timeline.entries[-1].occurred_at < timeline.entries[-2].occurred_at


def test_public_replay_recovery_event_matches_real_receipt_projector() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    receipt = _recovery_receipt(bundle.task)
    projection = project_execution_receipt(
        receipt,
        policy_set=standard_timeline_evidence_policy_set(receipt.target),
    )

    assert receipt.action is CapabilityAction.RECOVER_STABLE
    assert projection.event.event_type is TimelineEventType.MUTATION_APPLIED
    assert (
        PublicReplayTimelineEventType(projection.event.event_type.value)
        is PublicReplayTimelineEventType.MUTATION_APPLIED
    )
