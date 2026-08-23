"""Small adapter from durable M6 records to one bounded advisor snapshot."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from controlgraph_canary.application.authority_store import RootCreationBundle
from controlgraph_canary.application.timeline import TimelineReadSlice
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.model_assistance import (
    ADVISOR_INVOCATION_REQUEST_V1,
    DIAGNOSTIC_EVIDENCE_SUMMARY_V1,
    DIAGNOSTIC_SNAPSHOT_V1,
    AdvisorInvocationRequestV1,
    AdvisorOperatorCommandV1,
    AdvisoryHealth,
    DiagnosticEvidenceKind,
    DiagnosticEvidenceSummaryCode,
    DiagnosticEvidenceSummaryV1,
    DiagnosticSnapshotV1,
    EvidenceConsistency,
    RolloutPhase,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.root_creation import RolloutRootV3
from controlgraph_canary.contracts.timeline import (
    TIMELINE_PAGE_COMMAND_V1,
    TimelineAudience,
    TimelineEntryV1,
    TimelineEventType,
    TimelinePageCommandV1,
    TimelineTerminalClassification,
    TimelineVerificationStatus,
)

_MAX_TIMELINE_ENTRIES = 100
_SNAPSHOT_LIFETIME_SECONDS = 240


@runtime_checkable
class M6AuthorityReader(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootCreationBundle | None: ...


@runtime_checkable
class M6TimelineReader(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def read_page(self, command: TimelinePageCommandV1) -> TimelineReadSlice: ...


class M6DiagnosticSnapshotAssembler:
    """Project one current root from the M6 authority and chained timeline stores."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        authority: M6AuthorityReader,
        timeline: M6TimelineReader,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or not isinstance(authority, M6AuthorityReader)
            or authority.target != target
            or not isinstance(timeline, M6TimelineReader)
            or timeline.target != target
        ):
            raise ValueError("M6 diagnostic snapshot configuration is invalid")
        self._target = target
        self._authority = authority
        self._timeline = timeline

    async def assemble(
        self,
        command: AdvisorOperatorCommandV1,
    ) -> AdvisorInvocationRequestV1:
        if type(command) is not AdvisorOperatorCommandV1 or command.target != self._target:
            raise ValueError("advisor command target is invalid")
        bundle = await self._authority.read_root_creation_bundle(command.root_id)
        if bundle is None or type(bundle.root.value) is not RolloutRootV3:
            raise ValueError("advisor root evidence is unavailable")
        root = bundle.root.value
        authority = bundle.authority.value
        if (
            root.root_sha256 != command.expected_root_sha256
            or authority.root_id != root.root_id
            or authority.root_sha256 != root.root_sha256
            or authority.current_epoch != command.expected_epoch
            or authority.target != self._target
        ):
            raise ValueError("advisor authority evidence is stale")

        page = await self._timeline.read_page(
            TimelinePageCommandV1(
                schema_version=TIMELINE_PAGE_COMMAND_V1,
                target=self._target,
                after_sequence=0,
                after_entry_sha256=None,
                limit=_MAX_TIMELINE_ENTRIES,
                audience=TimelineAudience.OPERATOR,
            )
        )
        if (
            page.head is None
            or page.head.sequence != len(page.entries)
            or page.head.sequence > _MAX_TIMELINE_ENTRIES
            or page.head.entry_sha256 != page.entries[-1].entry_sha256
        ):
            raise ValueError("advisor timeline evidence is unavailable")
        entries = tuple(
            entry
            for entry in page.entries
            if entry.content.event.root_id == root.root_id
            and entry.content.event.root_sha256 == root.root_sha256
        )
        if not entries or any(
            entry.content.event.epoch > authority.current_epoch for entry in entries
        ):
            raise ValueError("advisor timeline evidence is inconsistent")

        root_entries = _verified_entries(entries, TimelineEventType.AUTHORITY_ROOT_CREATED)
        health_entries = _verified_entries(entries, TimelineEventType.HEALTH_DECIDED)
        verifier_entries = _verified_entries(entries, TimelineEventType.VERIFICATION_RECORDED)
        receipt_entries = tuple(
            entry
            for entry in entries
            if entry.content.event.event_type
            in {
                TimelineEventType.MUTATION_APPLIED,
                TimelineEventType.MUTATION_DENIED,
                TimelineEventType.MUTATION_AMBIGUOUS,
            }
            and entry.content.event.verification_status
            in {
                TimelineVerificationStatus.VERIFIED,
                TimelineVerificationStatus.AMBIGUOUS,
            }
        )
        if not root_entries or not health_entries or not verifier_entries or not receipt_entries:
            raise ValueError("advisor evidence set is incomplete")

        plan = root.content.rollout_plan
        health_entry = health_entries[-1]
        health_value = _display_value(health_entry, "OUTCOME")
        health = {
            "healthy": AdvisoryHealth.HEALTHY,
            "unhealthy": AdvisoryHealth.UNHEALTHY,
            "wait": AdvisoryHealth.UNKNOWN,
            "insufficient-evidence": AdvisoryHealth.AMBIGUOUS,
        }.get(health_value or "", AdvisoryHealth.UNKNOWN)
        terminal_health = health in {AdvisoryHealth.HEALTHY, AdvisoryHealth.UNHEALTHY}
        phase, stable_percent, candidate_percent = _rollout_state(
            entries,
            authority_revoked=authority.current_epoch > plan.initial_epoch,
            health=health,
        )
        observed_at = command.requested_at
        fresh_until = _utc_text(_utc(observed_at) + timedelta(seconds=_SNAPSHOT_LIFETIME_SECONDS))
        target_entries = verifier_entries[-2:]
        receipt_entry = receipt_entries[-1]
        snapshot = DiagnosticSnapshotV1(
            schema_version=DIAGNOSTIC_SNAPSHOT_V1,
            snapshot_id=_snapshot_id(
                root.root_sha256,
                authority.current_epoch,
                page.head.entry_sha256,
                command.request_id,
            ),
            target=self._target,
            root_id=root.root_id,
            root_sha256=root.root_sha256,
            current_epoch=authority.current_epoch,
            stable_revision=plan.stable_revision,
            candidate_revision=plan.candidate_revision,
            recovery_revision=plan.stable_revision,
            stable_percent=stable_percent,
            candidate_percent=candidate_percent,
            rollout_phase=phase,
            authority_revoked=authority.current_epoch > plan.initial_epoch,
            health=health,
            terminal_health=terminal_health,
            health_policy_sha256=plan.health_policy_sha256,
            evidence_consistency=EvidenceConsistency.CONSISTENT,
            assembled_at=observed_at,
            expires_at=fresh_until,
            root_summary=_summary(
                DiagnosticEvidenceKind.ROOT,
                root_entries[-1:],
                source_sha256=root.root_sha256,
                observed_at=observed_at,
                fresh_until=fresh_until,
            ),
            target_summary=_summary(
                DiagnosticEvidenceKind.TARGET,
                target_entries,
                source_sha256=_entry_set_sha256(target_entries),
                observed_at=observed_at,
                fresh_until=fresh_until,
            ),
            health_summary=_summary(
                DiagnosticEvidenceKind.HEALTH,
                health_entries[-1:],
                source_sha256=health_entry.content.event.payload_sha256,
                observed_at=observed_at,
                fresh_until=fresh_until,
            ),
            receipt_summary=_summary(
                DiagnosticEvidenceKind.RECEIPT,
                receipt_entries[-1:],
                source_sha256=receipt_entry.content.event.payload_sha256,
                observed_at=observed_at,
                fresh_until=fresh_until,
            ),
            timeline_summary=_summary(
                DiagnosticEvidenceKind.TIMELINE,
                entries[-1:],
                source_sha256=page.head.entry_sha256,
                observed_at=observed_at,
                fresh_until=fresh_until,
            ),
            verifier_summary=_summary(
                DiagnosticEvidenceKind.VERIFIER,
                verifier_entries[-2:],
                source_sha256=_entry_set_sha256(verifier_entries[-2:]),
                observed_at=observed_at,
                fresh_until=fresh_until,
            ),
        )
        return AdvisorInvocationRequestV1(
            schema_version=ADVISOR_INVOCATION_REQUEST_V1,
            correlation_id=command.request_id,
            requested_at=command.requested_at,
            snapshot=snapshot,
            snapshot_sha256=canonical_sha256(snapshot),
        )


def _verified_entries(
    entries: tuple[TimelineEntryV1, ...],
    event_type: TimelineEventType,
) -> tuple[TimelineEntryV1, ...]:
    return tuple(
        entry
        for entry in entries
        if entry.content.event.event_type is event_type
        and entry.content.event.signature is not None
        and entry.content.event.verification_status is TimelineVerificationStatus.VERIFIED
    )


def _rollout_state(
    entries: tuple[TimelineEntryV1, ...],
    *,
    authority_revoked: bool,
    health: AdvisoryHealth,
) -> tuple[RolloutPhase, int, int]:
    terminal = next(
        (
            entry.content.event.terminal_classification
            for entry in reversed(entries)
            if entry.content.event.event_type is TimelineEventType.TERMINAL_CLASSIFIED
        ),
        TimelineTerminalClassification.NONE,
    )
    if terminal is TimelineTerminalClassification.PROMOTED:
        return RolloutPhase.PROMOTED, 0, 100
    if terminal is TimelineTerminalClassification.RECOVERED:
        return RolloutPhase.STABLE, 100, 0
    if authority_revoked:
        return RolloutPhase.REVOKED, 90, 10
    if health is AdvisoryHealth.UNHEALTHY:
        return RolloutPhase.RECOVERY_PENDING, 90, 10
    return RolloutPhase.CANARY, 90, 10


def _summary(
    kind: DiagnosticEvidenceKind,
    entries: tuple[TimelineEntryV1, ...],
    *,
    source_sha256: str,
    observed_at: str,
    fresh_until: str,
) -> DiagnosticEvidenceSummaryV1:
    if not entries:
        raise ValueError("diagnostic summary source is empty")
    summary_code = dict(
        zip(
            tuple(DiagnosticEvidenceKind),
            tuple(DiagnosticEvidenceSummaryCode),
            strict=True,
        )
    )[kind]
    return DiagnosticEvidenceSummaryV1(
        schema_version=DIAGNOSTIC_EVIDENCE_SUMMARY_V1,
        evidence_kind=kind,
        evidence_ids=tuple(
            f"cgdiag:{kind.value}:{entry.entry_sha256[:24]}" for entry in entries
        ),
        source_sha256=source_sha256,
        observed_at=observed_at,
        fresh_until=fresh_until,
        summary_code=summary_code,
        redacted=True,
        untrusted_model_context=True,
    )


def _entry_set_sha256(entries: tuple[TimelineEntryV1, ...]) -> str:
    digest = hashlib.sha256(b"controlgraph.diagnostic-entry-set/v1\0")
    for entry in entries:
        digest.update(bytes.fromhex(entry.entry_sha256))
    return digest.hexdigest()


def _snapshot_id(root_sha256: str, epoch: int, head_sha256: str, request_id: str) -> str:
    digest = hashlib.sha256(
        b"controlgraph.diagnostic-snapshot-id/v1\0"
        + bytes.fromhex(root_sha256)
        + b"\0"
        + str(epoch).encode("ascii")
        + b"\0"
        + bytes.fromhex(head_sha256)
        + b"\0"
        + request_id.encode("utf-8")
    ).hexdigest()
    return f"cgsnapshot:{digest}"


def _display_value(entry: TimelineEntryV1, name: str) -> str | None:
    return next(
        (
            field.value
            for field in entry.content.event.display_fields
            if field.name.value == name
        ),
        None,
    )


def _utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def _utc_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = ["M6DiagnosticSnapshotAssembler"]
