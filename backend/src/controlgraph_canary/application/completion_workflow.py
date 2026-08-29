"""Coordinator orchestration for root-bound independent completion evidence."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast, runtime_checkable

from controlgraph_canary.application.authority_store import StoredRecord
from controlgraph_canary.application.cloud_run import (
    rollout_root_v2_target_configuration_sha256,
    rollout_root_v3_target_configuration_sha256,
)
from controlgraph_canary.application.root_authority import (
    RootAuthorityBundle,
    capability_claims_match_root_authority,
    inspect_root_authority_bundle,
    service_claim_matches_content_addressed_root,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.independent_verification import (
    AUTHORITY_COMPLETION_EVIDENCE_V1,
    COMPLETION_ASSESSMENT_REQUEST_V1,
    COMPLETION_EVIDENCE_BUNDLE_V1,
    EXECUTION_COMPLETION_EVIDENCE_V1,
    INDEPENDENT_VERIFICATION_INVOCATION_V1,
    VERIFICATION_REQUEST_V1,
    AuthorityCompletionEvidenceV1,
    AuthorityCompletionKind,
    CompletionAssessmentRequestV1,
    CompletionClassificationV1,
    CompletionEvidenceBundleV1,
    CompletionKind,
    ConfigurationAttestationStatus,
    ExecutionCompletionEvidenceV1,
    IndependentVerificationInvocationV1,
    IndependentVerificationKind,
    ProbeAttestationStatus,
    VerificationRequestV1,
    VerifiedIndependentVerificationEvidenceV1,
    fixed_probe_policy,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EvidenceKind,
    ExecutionReceipt,
    ReasonCode,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
)
from controlgraph_canary.contracts.revocation import EpochRevocationResultV1
from controlgraph_canary.contracts.root_creation import (
    RolloutRootV2,
    RolloutRootV3,
    SignedEvidenceEventV1,
    capability_lineage_anchor,
)
from controlgraph_canary.contracts.storage import (
    ServiceClaimRecord,
    ServiceClaimRecordV3,
    ServiceClaimRecordValue,
    execution_receipt_logical_id,
)

_OBSERVATION_WINDOW_SECONDS = 300


class CompletionWorkflowErrorCode(StrEnum):
    CONFIGURATION_INVALID = "COMPLETION_WORKFLOW_CONFIGURATION_INVALID"
    INPUT_INVALID = "COMPLETION_WORKFLOW_INPUT_INVALID"
    CLASSIFICATION_UNAVAILABLE = "COMPLETION_WORKFLOW_CLASSIFICATION_UNAVAILABLE"
    TIMELINE_UNAVAILABLE = "COMPLETION_WORKFLOW_TIMELINE_UNAVAILABLE"


class CompletionWorkflowError(RuntimeError):
    """Payload-free failure at the coordinator completion boundary."""

    def __init__(self, code: CompletionWorkflowErrorCode) -> None:
        if type(code) is not CompletionWorkflowErrorCode:
            raise TypeError("an exact completion workflow error code is required")
        self.code = code
        super().__init__(code.value)


@runtime_checkable
class CompletionVerificationClient(Protocol):
    async def attest(
        self,
        invocation: IndependentVerificationInvocationV1,
    ) -> VerifiedIndependentVerificationEvidenceV1: ...


@runtime_checkable
class CompletionClassifier(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def classify(
        self,
        bundle: CompletionEvidenceBundleV1,
    ) -> CompletionClassificationV1: ...


@runtime_checkable
class CompletionAuthorityReader(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootAuthorityBundle | None: ...

    async def read_signed_evidence_event(
        self,
        evidence_id: str,
    ) -> StoredRecord[SignedEvidenceEventV1] | None: ...

    async def read_signed_epoch_evidence(
        self,
        root_id: str,
        epoch: int,
    ) -> StoredRecord[SignedEvidenceEventV1] | None: ...


@runtime_checkable
class CompletionAuthorityEvidenceVerifier(Protocol):
    async def verify(self, signed: SignedEvidenceEventV1) -> None: ...


@runtime_checkable
class CompletionSignedIntentReader(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def read_signed_intent(
        self,
        capability_sha256: str,
    ) -> SignedCapability | None: ...


@runtime_checkable
class CompletionSignedIntentVerifier(Protocol):
    def verify(self, capability: SignedCapability) -> None: ...


@runtime_checkable
class CompletionWorkflowTimelineRecorder(Protocol):
    @property
    def target(self) -> TargetBinding: ...

    async def record_verification_bundle(
        self,
        *verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None: ...

    async def record_completion_bundle(
        self,
        classification: CompletionClassificationV1,
        *verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None: ...

    async def record_stale_denial_completion(
        self,
        receipt: ExecutionReceipt,
        signed_authority: SignedEvidenceEventV1 | None,
        classification: CompletionClassificationV1,
        *verified: VerifiedIndependentVerificationEvidenceV1,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class VerifiedTargetObservation:
    """The independent signals obtained for one exact verification request."""

    request: VerificationRequestV1
    configuration: VerifiedIndependentVerificationEvidenceV1 | None
    probe: VerifiedIndependentVerificationEvidenceV1 | None

    @property
    def matched(self) -> bool:
        configuration = self.configuration
        probe = self.probe
        return (
            configuration is not None
            and probe is not None
            and configuration.signing_request.configuration is not None
            and configuration.signing_request.configuration.request == self.request
            and configuration.signing_request.configuration.status
            is ConfigurationAttestationStatus.MATCH
            and probe.signing_request.probe is not None
            and probe.signing_request.probe.request.verification == self.request
            and probe.signing_request.probe.status is ProbeAttestationStatus.MATCH
        )

    @property
    def evidence(self) -> tuple[VerifiedIndependentVerificationEvidenceV1, ...]:
        return tuple(
            item for item in (self.configuration, self.probe) if item is not None
        )


class CoordinatorCompletionWorkflow:
    """Collect independent observations and classify terminal target outcomes."""

    def __init__(
        self,
        *,
        target: TargetBinding,
        verifier: CompletionVerificationClient,
        classifier: CompletionClassifier,
        timeline_recorder: CompletionWorkflowTimelineRecorder | None = None,
        authority_reader: CompletionAuthorityReader | None = None,
        authority_evidence_verifier: CompletionAuthorityEvidenceVerifier | None = None,
        signed_intent_reader: CompletionSignedIntentReader | None = None,
        signed_intent_verifier: CompletionSignedIntentVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            type(target) is not TargetBinding
            or not isinstance(verifier, CompletionVerificationClient)
            or not isinstance(classifier, CompletionClassifier)
            or classifier.target != target
            or (authority_reader is None) != (authority_evidence_verifier is None)
            or (signed_intent_reader is None) != (signed_intent_verifier is None)
            or (
                authority_reader is not None
                and (
                    not isinstance(authority_reader, CompletionAuthorityReader)
                    or authority_reader.target != target
                )
            )
            or (
                authority_evidence_verifier is not None
                and not isinstance(
                    authority_evidence_verifier,
                    CompletionAuthorityEvidenceVerifier,
                )
            )
            or (
                signed_intent_reader is not None
                and (
                    not isinstance(signed_intent_reader, CompletionSignedIntentReader)
                    or signed_intent_reader.target != target
                )
            )
            or (
                signed_intent_verifier is not None
                and not isinstance(
                    signed_intent_verifier,
                    CompletionSignedIntentVerifier,
                )
            )
            or (
                timeline_recorder is not None
                and (
                    not isinstance(
                        timeline_recorder,
                        CompletionWorkflowTimelineRecorder,
                    )
                    or timeline_recorder.target != target
                )
            )
            or (clock is not None and not callable(clock))
        ):
            raise CompletionWorkflowError(
                CompletionWorkflowErrorCode.CONFIGURATION_INVALID
            )
        self._target = target
        self._verifier = verifier
        self._classifier = classifier
        self._timeline_recorder = timeline_recorder
        self._authority_reader = authority_reader
        self._authority_evidence_verifier = authority_evidence_verifier
        self._signed_intent_reader = signed_intent_reader
        self._signed_intent_verifier = signed_intent_verifier
        self._clock = clock or _system_utc_second

    @property
    def target(self) -> TargetBinding:
        return self._target

    async def verify_target(
        self,
        *,
        root: RolloutRootV2 | RolloutRootV3,
        service_claim: ServiceClaimRecord,
        receipt: ExecutionReceipt,
    ) -> VerifiedTargetObservation:
        """Verify configuration and serving revision before health evaluation."""

        observation = await self._observe(
            root=root,
            service_claim=service_claim,
            receipt=receipt,
            started_at=self._timestamp(),
        )
        recorder = self._timeline_recorder
        if recorder is not None and observation.evidence:
            try:
                await recorder.record_verification_bundle(*observation.evidence)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise CompletionWorkflowError(
                    CompletionWorkflowErrorCode.TIMELINE_UNAVAILABLE
                ) from None
        return observation

    async def classify_completion(
        self,
        *,
        root: RolloutRootV2 | RolloutRootV3,
        service_claim: ServiceClaimRecord,
        receipt: ExecutionReceipt,
    ) -> CompletionClassificationV1:
        """Use the shared classifier for a persisted promotion or recovery receipt."""

        verification_started_at = self._timestamp()
        observation = await self._observe(
            root=root,
            service_claim=service_claim,
            receipt=receipt,
            started_at=verification_started_at,
        )
        kind = {
            CapabilityAction.PROMOTE_CANDIDATE: CompletionKind.PROMOTION,
            CapabilityAction.RECOVER_STABLE: CompletionKind.RECOVERY,
        }.get(receipt.action)
        if kind is None:
            raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID)
        assessed_at = self._timestamp()
        request = CompletionAssessmentRequestV1(
            schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
            kind=kind,
            verification=observation.request,
            assessed_at=assessed_at,
        )
        execution = (
            _execution_evidence(observation.request, receipt)
            if await self._signed_intent_is_verified(root=root, receipt=receipt)
            else None
        )
        bundle = CompletionEvidenceBundleV1(
            schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
            request=request,
            execution=execution,
            configuration=observation.configuration,
            probe=observation.probe,
        )
        try:
            classification = await self._classifier.classify(bundle)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CompletionWorkflowError(
                CompletionWorkflowErrorCode.CLASSIFICATION_UNAVAILABLE
            ) from None
        recorder = self._timeline_recorder
        if recorder is not None:
            try:
                await recorder.record_completion_bundle(
                    classification,
                    *observation.evidence,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise CompletionWorkflowError(
                    CompletionWorkflowErrorCode.TIMELINE_UNAVAILABLE
                ) from None
        return classification

    async def classify_revocation(
        self,
        *,
        root: RolloutRootV2 | RolloutRootV3,
        service_claim: ServiceClaimRecord,
        result: EpochRevocationResultV1,
        signed_evidence: SignedEvidenceEventV1,
    ) -> CompletionClassificationV1:
        """Classify one signature-verified, durably committed authority transition."""

        try:
            verification = create_authority_verification_request(
                root=root,
                service_claim=service_claim,
                result=result,
            )
            authority = AuthorityCompletionEvidenceV1(
                schema_version=AUTHORITY_COMPLETION_EVIDENCE_V1,
                kind=AuthorityCompletionKind.REVOCATION,
                root_id=result.root_id,
                root_sha256=result.root_sha256,
                epoch=result.new_epoch,
                target=result.target,
                plan_sha256=verification.plan_sha256,
                request_id=result.request_id,
                correlation_id=verification.correlation_id,
                observation_window_started_at=(
                    verification.observation_window_started_at
                ),
                observation_window_ends_at=verification.observation_window_ends_at,
                authority_evidence_sha256=canonical_sha256(signed_evidence),
                signature_verified=True,
                occurred_at=result.committed_at,
            )
            assessment = CompletionAssessmentRequestV1(
                schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
                kind=CompletionKind.REVOCATION,
                verification=verification,
                assessed_at=result.committed_at,
            )
            bundle = CompletionEvidenceBundleV1(
                schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
                request=assessment,
                authority=authority,
            )
            return await self._classifier.classify(bundle)
        except asyncio.CancelledError:
            raise
        except CompletionWorkflowError:
            raise
        except Exception:
            raise CompletionWorkflowError(
                CompletionWorkflowErrorCode.CLASSIFICATION_UNAVAILABLE
            ) from None

    async def classify_stale_denial(
        self,
        receipt: ExecutionReceipt,
    ) -> CompletionClassificationV1:
        """Classify one durable stale denial against the current signed epoch fence."""

        if (
            type(receipt) is not ExecutionReceipt
            or receipt.outcome is not ReceiptOutcome.DENIED
            or receipt.reason_code is not ReasonCode.EPOCH_MISMATCH
            or receipt.observed_authority_epoch is None
            or receipt.observed_authority_epoch <= receipt.epoch
        ):
            raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID)
        reader = self._authority_reader
        verifier = self._authority_evidence_verifier
        if reader is None or verifier is None:
            raise CompletionWorkflowError(
                CompletionWorkflowErrorCode.CONFIGURATION_INVALID
            )
        try:
            root_bundle = await reader.read_root_creation_bundle(receipt.root_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CompletionWorkflowError(
                CompletionWorkflowErrorCode.CLASSIFICATION_UNAVAILABLE
            ) from None
        trusted = inspect_root_authority_bundle(root_bundle, target=self._target)
        if (
            trusted is None
            or type(trusted.service_claim)
            not in {ServiceClaimRecord, ServiceClaimRecordV3}
        ):
            raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID)
        signed_evidence: SignedEvidenceEventV1 | None = None
        current_authority = trusted.authority
        if current_authority.current_epoch >= receipt.observed_authority_epoch:
            try:
                current_is_observed = (
                    current_authority.current_epoch
                    == receipt.observed_authority_epoch
                )
                stored_evidence = (
                    await reader.read_signed_evidence_event(
                        current_authority.evidence_id
                    )
                    if current_is_observed
                    else await reader.read_signed_epoch_evidence(
                        receipt.root_id,
                        receipt.observed_authority_epoch,
                    )
                )
                if (
                    type(stored_evidence) is StoredRecord
                    and stored_evidence.revision == 0
                    and type(stored_evidence.value) is SignedEvidenceEventV1
                ):
                    candidate = stored_evidence.value
                    event = candidate.event
                    if (
                        event.kind is EvidenceKind.EPOCH_ADVANCED
                        and event.root_id == receipt.root_id
                        and event.root_sha256 == receipt.root_sha256
                        and event.target == receipt.target
                        and event.epoch == receipt.observed_authority_epoch
                        and event.occurred_at <= receipt.updated_at
                        and candidate.signing_key_version
                        == trusted.root.content.evidence_signing_key_version
                        and (
                            not current_is_observed
                            or (
                                event.evidence_id == current_authority.evidence_id
                                and event.actor == current_authority.changed_by
                                and event.request_id
                                == current_authority.request_id
                                and event.occurred_at
                                == current_authority.changed_at
                            )
                        )
                    ):
                        await verifier.verify(candidate)
                        signed_evidence = candidate
            except asyncio.CancelledError:
                raise
            except Exception:
                signed_evidence = None

        started_at = (
            signed_evidence.event.occurred_at
            if signed_evidence is not None
            else (
                current_authority.changed_at
                if current_authority.changed_at <= receipt.updated_at
                else receipt.created_at
            )
        )
        try:
            verification = create_stale_denial_verification_request(
                root=trusted.root,
                service_claim=trusted.service_claim,
                receipt=receipt,
                started_at=started_at,
            )
        except CompletionWorkflowError:
            raise
        except Exception:
            raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID) from None

        configuration = await self._attest(
            IndependentVerificationKind.CONFIGURATION,
            verification,
        )
        probe = await self._attest(
            IndependentVerificationKind.PROBE,
            verification,
        )
        observation = VerifiedTargetObservation(
            request=verification,
            configuration=_post_denial_evidence(configuration, receipt),
            probe=_post_denial_evidence(probe, receipt),
        )

        authority = (
            AuthorityCompletionEvidenceV1(
                schema_version=AUTHORITY_COMPLETION_EVIDENCE_V1,
                kind=AuthorityCompletionKind.EPOCH_ADVANCEMENT,
                root_id=receipt.root_id,
                root_sha256=receipt.root_sha256,
                epoch=signed_evidence.event.epoch,
                target=receipt.target,
                plan_sha256=receipt.plan_sha256,
                request_id=receipt.request_id,
                correlation_id=verification.correlation_id,
                observation_window_started_at=(
                    verification.observation_window_started_at
                ),
                observation_window_ends_at=verification.observation_window_ends_at,
                authority_evidence_sha256=canonical_sha256(signed_evidence),
                signature_verified=True,
                occurred_at=signed_evidence.event.occurred_at,
            )
            if signed_evidence is not None
            else None
        )
        try:
            assessed_at = max(
                (
                    self._timestamp(),
                    receipt.updated_at,
                    *(item.verified_at for item in observation.evidence),
                ),
                key=_parse_utc,
            )
            assessment = CompletionAssessmentRequestV1(
                schema_version=COMPLETION_ASSESSMENT_REQUEST_V1,
                kind=CompletionKind.STALE_CAPABILITY_DENIAL,
                verification=verification,
                assessed_at=assessed_at,
            )
            bundle = CompletionEvidenceBundleV1(
                schema_version=COMPLETION_EVIDENCE_BUNDLE_V1,
                request=assessment,
                execution=(
                    _execution_evidence(verification, receipt)
                    if await self._signed_intent_is_verified(
                        root=trusted.root,
                        receipt=receipt,
                    )
                    else None
                ),
                configuration=observation.configuration,
                probe=observation.probe,
                authority=authority,
            )
        except Exception:
            raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID) from None
        try:
            classification = await self._classifier.classify(bundle)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise CompletionWorkflowError(
                CompletionWorkflowErrorCode.CLASSIFICATION_UNAVAILABLE
            ) from None
        recorder = self._timeline_recorder
        if recorder is not None:
            try:
                await recorder.record_stale_denial_completion(
                    receipt,
                    signed_evidence,
                    classification,
                    *observation.evidence,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise CompletionWorkflowError(
                    CompletionWorkflowErrorCode.TIMELINE_UNAVAILABLE
                ) from None
        return classification

    async def _observe(
        self,
        *,
        root: RolloutRootV2 | RolloutRootV3,
        service_claim: ServiceClaimRecord,
        receipt: ExecutionReceipt,
        started_at: str,
    ) -> VerifiedTargetObservation:
        try:
            request = create_verification_request(
                root=root,
                service_claim=service_claim,
                receipt=receipt,
                started_at=started_at,
            )
        except CompletionWorkflowError:
            raise
        except Exception:
            raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID) from None
        configuration = await self._attest(
            IndependentVerificationKind.CONFIGURATION,
            request,
        )
        probe = await self._attest(IndependentVerificationKind.PROBE, request)
        return VerifiedTargetObservation(
            request=request,
            configuration=configuration,
            probe=probe,
        )

    async def _signed_intent_is_verified(
        self,
        *,
        root: RolloutRootV2 | RolloutRootV3,
        receipt: ExecutionReceipt,
    ) -> bool:
        reader = self._signed_intent_reader
        verifier = self._signed_intent_verifier
        if reader is None or verifier is None:
            return False
        try:
            signed = await reader.read_signed_intent(receipt.capability_sha256)
            if (
                type(signed) is not SignedCapability
                or not _signed_intent_matches_receipt(signed, root, receipt)
            ):
                return False
            verifier.verify(signed)
            return True
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def _attest(
        self,
        kind: IndependentVerificationKind,
        request: VerificationRequestV1,
    ) -> VerifiedIndependentVerificationEvidenceV1 | None:
        try:
            return await self._verifier.attest(
                IndependentVerificationInvocationV1(
                    schema_version=INDEPENDENT_VERIFICATION_INVOCATION_V1,
                    kind=kind,
                    verification=request,
                )
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    def _timestamp(self) -> str:
        try:
            value = self._clock()
        except Exception:
            raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID) from None
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID)
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_verification_request(
    *,
    root: RolloutRootV2 | RolloutRootV3,
    service_claim: ServiceClaimRecordValue,
    receipt: ExecutionReceipt,
    started_at: str,
) -> VerificationRequestV1:
    """Derive one verification request only from trusted root, claim, and receipt state."""

    if (
        type(root) not in {RolloutRootV2, RolloutRootV3}
        or type(service_claim) not in {ServiceClaimRecord, ServiceClaimRecordV3}
        or type(receipt) is not ExecutionReceipt
        or not service_claim_matches_content_addressed_root(service_claim, root)
        or receipt.target != root.content.target
        or receipt.root_id != root.root_id
        or receipt.root_sha256 != root.root_sha256
        or receipt.plan_sha256 != canonical_sha256(root.content.rollout_plan)
        or receipt.receipt_id
        != execution_receipt_logical_id(receipt.target, receipt.idempotency_key)
        or receipt.action
        not in {
            CapabilityAction.APPLY_CANARY,
            CapabilityAction.PROMOTE_CANDIDATE,
            CapabilityAction.RECOVER_STABLE,
        }
    ):
        raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID)
    traffic = {
        CapabilityAction.APPLY_CANARY: (90, 10),
        CapabilityAction.PROMOTE_CANDIDATE: (0, 100),
        CapabilityAction.RECOVER_STABLE: (100, 0),
    }[receipt.action]
    target_sha256 = (
        rollout_root_v2_target_configuration_sha256(
            root,
            stable_percent=traffic[0],
            candidate_percent=traffic[1],
        )
        if type(root) is RolloutRootV2
        else rollout_root_v3_target_configuration_sha256(
            cast(RolloutRootV3, root),
            stable_percent=traffic[0],
            candidate_percent=traffic[1],
        )
    )
    if receipt.expected_poststate_sha256 != target_sha256:
        raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID)
    start = _parse_utc(started_at)
    plan = root.content.rollout_plan
    policy = fixed_probe_policy(*traffic)
    receipt_sha256 = canonical_sha256(receipt)
    return VerificationRequestV1(
        schema_version=VERIFICATION_REQUEST_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=receipt.epoch,
        target=root.content.target,
        plan_sha256=canonical_sha256(plan),
        service_claim_sha256=canonical_sha256(service_claim),
        probe_policy_sha256=canonical_sha256(policy),
        signed_intent_sha256=receipt.capability_sha256,
        action=receipt.action,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=traffic[0],
        candidate_percent=traffic[1],
        concurrency=plan.concurrency,
        expected_stable_revision_configuration_sha256=(
            plan.stable_revision_configuration_sha256
        ),
        expected_candidate_revision_configuration_sha256=(
            plan.candidate_revision_configuration_sha256
        ),
        expected_target_configuration_sha256=target_sha256,
        observation_window_started_at=started_at,
        observation_window_ends_at=_utc_second(
            start + timedelta(seconds=_OBSERVATION_WINDOW_SECONDS)
        ),
        request_id=receipt.request_id,
        correlation_id=f"verify:{receipt_sha256[:32]}",
    )


def create_authority_verification_request(
    *,
    root: RolloutRootV2 | RolloutRootV3,
    service_claim: ServiceClaimRecord,
    result: EpochRevocationResultV1,
) -> VerificationRequestV1:
    """Bind an authority-only assessment to the same immutable rollout contract."""

    if (
        type(root) not in {RolloutRootV2, RolloutRootV3}
        or type(service_claim) is not ServiceClaimRecord
        or type(result) is not EpochRevocationResultV1
        or not service_claim_matches_content_addressed_root(service_claim, root)
        or result.root_id != root.root_id
        or result.root_sha256 != root.root_sha256
        or result.target != root.content.target
    ):
        raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID)
    traffic = (90, 10)
    plan = root.content.rollout_plan
    target_sha256 = (
        rollout_root_v2_target_configuration_sha256(
            root,
            stable_percent=traffic[0],
            candidate_percent=traffic[1],
        )
        if type(root) is RolloutRootV2
        else rollout_root_v3_target_configuration_sha256(
            cast(RolloutRootV3, root),
            stable_percent=traffic[0],
            candidate_percent=traffic[1],
        )
    )
    start = _parse_utc(result.committed_at)
    return VerificationRequestV1(
        schema_version=VERIFICATION_REQUEST_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=result.new_epoch,
        target=root.content.target,
        plan_sha256=canonical_sha256(plan),
        service_claim_sha256=canonical_sha256(service_claim),
        probe_policy_sha256=canonical_sha256(fixed_probe_policy(*traffic)),
        signed_intent_sha256=result.request_sha256,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=traffic[0],
        candidate_percent=traffic[1],
        concurrency=plan.concurrency,
        expected_stable_revision_configuration_sha256=(
            plan.stable_revision_configuration_sha256
        ),
        expected_candidate_revision_configuration_sha256=(
            plan.candidate_revision_configuration_sha256
        ),
        expected_target_configuration_sha256=target_sha256,
        observation_window_started_at=result.committed_at,
        observation_window_ends_at=_utc_second(
            start + timedelta(seconds=_OBSERVATION_WINDOW_SECONDS)
        ),
        request_id=result.request_id,
        correlation_id=f"revocation:{result.evidence_sha256[:32]}",
    )


def create_stale_denial_verification_request(
    *,
    root: RolloutRootV2 | RolloutRootV3,
    service_claim: ServiceClaimRecordValue,
    receipt: ExecutionReceipt,
    started_at: str,
) -> VerificationRequestV1:
    """Bind a fresh unchanged-canary observation to one durable stale denial."""

    if (
        type(root) not in {RolloutRootV2, RolloutRootV3}
        or type(service_claim) not in {ServiceClaimRecord, ServiceClaimRecordV3}
        or type(receipt) is not ExecutionReceipt
        or not service_claim_matches_content_addressed_root(service_claim, root)
        or receipt.target != root.content.target
        or receipt.root_id != root.root_id
        or receipt.root_sha256 != root.root_sha256
        or receipt.plan_sha256 != canonical_sha256(root.content.rollout_plan)
        or receipt.receipt_id
        != execution_receipt_logical_id(receipt.target, receipt.idempotency_key)
        or receipt.outcome is not ReceiptOutcome.DENIED
        or receipt.reason_code is not ReasonCode.EPOCH_MISMATCH
        or receipt.observed_authority_epoch is None
        or receipt.observed_authority_epoch <= receipt.epoch
    ):
        raise CompletionWorkflowError(CompletionWorkflowErrorCode.INPUT_INVALID)
    traffic = (90, 10)
    plan = root.content.rollout_plan
    target_sha256 = (
        rollout_root_v2_target_configuration_sha256(
            root,
            stable_percent=traffic[0],
            candidate_percent=traffic[1],
        )
        if type(root) is RolloutRootV2
        else rollout_root_v3_target_configuration_sha256(
            cast(RolloutRootV3, root),
            stable_percent=traffic[0],
            candidate_percent=traffic[1],
        )
    )
    start = _parse_utc(started_at)
    receipt_sha256 = canonical_sha256(receipt)
    return VerificationRequestV1(
        schema_version=VERIFICATION_REQUEST_V1,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=receipt.epoch,
        target=root.content.target,
        plan_sha256=canonical_sha256(plan),
        service_claim_sha256=canonical_sha256(service_claim),
        probe_policy_sha256=canonical_sha256(fixed_probe_policy(*traffic)),
        signed_intent_sha256=receipt.capability_sha256,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=traffic[0],
        candidate_percent=traffic[1],
        concurrency=plan.concurrency,
        expected_stable_revision_configuration_sha256=(
            plan.stable_revision_configuration_sha256
        ),
        expected_candidate_revision_configuration_sha256=(
            plan.candidate_revision_configuration_sha256
        ),
        expected_target_configuration_sha256=target_sha256,
        observation_window_started_at=started_at,
        observation_window_ends_at=_utc_second(
            start + timedelta(seconds=_OBSERVATION_WINDOW_SECONDS)
        ),
        request_id=receipt.request_id,
        correlation_id=f"stale-denial:{receipt_sha256[:32]}",
    )


def _post_denial_evidence(
    evidence: VerifiedIndependentVerificationEvidenceV1 | None,
    receipt: ExecutionReceipt,
) -> VerifiedIndependentVerificationEvidenceV1 | None:
    if evidence is None:
        return None
    occurred_at = evidence.signed_evidence.evidence.occurred_at
    if _parse_utc(occurred_at) < _parse_utc(receipt.updated_at):
        return None
    return evidence


def _execution_evidence(
    request: VerificationRequestV1,
    receipt: ExecutionReceipt,
) -> ExecutionCompletionEvidenceV1:
    return ExecutionCompletionEvidenceV1(
        schema_version=EXECUTION_COMPLETION_EVIDENCE_V1,
        root_id=receipt.root_id,
        root_sha256=receipt.root_sha256,
        epoch=receipt.epoch,
        target=receipt.target,
        plan_sha256=receipt.plan_sha256,
        service_claim_sha256=request.service_claim_sha256,
        probe_policy_sha256=request.probe_policy_sha256,
        signed_intent_sha256=receipt.capability_sha256,
        intent_signature_verified=True,
        request_id=receipt.request_id,
        correlation_id=request.correlation_id,
        observation_window_started_at=request.observation_window_started_at,
        observation_window_ends_at=request.observation_window_ends_at,
        action=receipt.action,
        outcome=receipt.outcome,
        reason_code=receipt.reason_code,
        observed_authority_epoch=receipt.observed_authority_epoch,
        receipt_sha256=canonical_sha256(receipt),
        receipt_persisted=True,
        write_outcome_known=receipt.outcome is not ReceiptOutcome.AMBIGUOUS,
    )


def _signed_intent_matches_receipt(
    signed: SignedCapability,
    root: RolloutRootV2 | RolloutRootV3,
    receipt: ExecutionReceipt,
) -> bool:
    claims = signed.claims
    try:
        root_match = capability_claims_match_root_authority(
            claims,
            root,
            capability_lineage_anchor(root),
        )
    except Exception:
        return False
    return (
        root_match
        and canonical_sha256(signed) == receipt.capability_sha256
        and claims.target == receipt.target
        and claims.root_id == receipt.root_id
        and claims.root_sha256 == receipt.root_sha256
        and claims.epoch == receipt.epoch
        and claims.action is receipt.action
        and claims.plan_sha256 == receipt.plan_sha256
        and claims.provider_etag == receipt.provider_etag
        and claims.request_id == receipt.request_id
        and claims.idempotency_key == receipt.idempotency_key
        and claims.not_before <= receipt.created_at
        and receipt.dispatch_not_after <= claims.expires_at
    )


def _parse_utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _utc_second(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _system_utc_second() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


__all__ = [
    "CompletionAuthorityEvidenceVerifier",
    "CompletionAuthorityReader",
    "CompletionClassifier",
    "CompletionSignedIntentReader",
    "CompletionSignedIntentVerifier",
    "CompletionVerificationClient",
    "CompletionWorkflowError",
    "CompletionWorkflowErrorCode",
    "CompletionWorkflowTimelineRecorder",
    "CoordinatorCompletionWorkflow",
    "VerifiedTargetObservation",
    "create_authority_verification_request",
    "create_stale_denial_verification_request",
    "create_verification_request",
]
