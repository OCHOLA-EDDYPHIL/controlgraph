"""Canonical post-apply health anchors and signed decision chains."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, model_validator

from controlgraph_canary.contracts.base import (
    Base64Url,
    CloudRunName,
    Identifier,
    KeyVersionResource,
    OpaqueToken,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import (
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    canonical_sha256,
    decode_base64url,
    encode_base64url,
)
from controlgraph_canary.contracts.health import (
    HealthDecisionStatus,
    HealthDecisionV1,
    HealthEvaluationStateV1,
    HealthReasonCode,
    MonitoringObservationTiming,
    MonitoringWindowObservationV1,
    RolloutHealthPolicyV2,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    ExecutionReceipt,
    ReceiptOutcome,
    TargetBinding,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV3

POST_APPLY_HEALTH_ANCHOR_V1: Final = "controlgraph.post-apply-health-anchor/v1"
HEALTH_DECISION_PROOF_V1: Final = "controlgraph.health-decision-proof/v1"
SIGNED_HEALTH_DECISION_PROOF_V1: Final = "controlgraph.signed-health-decision-proof/v1"
HEALTH_ATTESTATION_SIGNATURE_INPUT_V1: Final = (
    "controlgraph.health-attestation-signature-input/v1"
)
HEALTHY_PROMOTION_PROOF_V1: Final = "controlgraph.healthy-promotion-proof/v1"
SIGNED_HEALTH_DECISION_CHAIN_V1: Final = "controlgraph.signed-health-decision-chain/v1"
HEALTH_ATTESTATION_SIGNING_REQUEST_V1: Final = (
    "controlgraph.health-attestation-signing-request/v1"
)
HEALTH_ATTESTATION_PURPOSE: Final = "HEALTH_ATTESTATION"
P256_SIGNING_ALGORITHM: Final = "EC_SIGN_P256_SHA256"

_ANCHOR_ID_DOMAIN = b"controlgraph.post-apply-health-anchor-id/v1\0"
_PROOF_ID_DOMAIN = b"controlgraph.health-decision-proof-id/v1\0"
_PROMOTION_PROOF_ID_DOMAIN = b"controlgraph.healthy-promotion-proof-id/v1\0"
_CHAIN_MANIFEST_DOMAIN = b"controlgraph.signed-health-decision-chain-sha256/v1\0"
_SIGNED_PROOF_CHAIN_DOMAIN = b"controlgraph.signed-health-proof-chain/v1\0"
_ATTESTATION_REQUEST_ID_DOMAIN = b"controlgraph.health-attestation-request-id/v1\0"
_ATTESTATION_INPUT_DOMAIN = b"controlgraph.health-attestation-signature-input/v1\0"
_TARGET_CONFIGURATION_DOMAIN = b"controlgraph.target-configuration-sha256/v1\0"
_TARGET_CONFIGURATION_V1 = "controlgraph.target-configuration/v1"
_MAX_PROOFS_PER_WINDOW = 2
_RETRYABLE_REASONS: Final = frozenset(
    {
        HealthReasonCode.SAMPLE_MISSING,
        HealthReasonCode.SAMPLE_PARTIAL,
        HealthReasonCode.MINIMUM_REQUESTS_NOT_MET,
    }
)
_FORBIDDEN_ORCHESTRATION_REASONS: Final = frozenset(
    {
        HealthReasonCode.WINDOW_NOT_READY,
        HealthReasonCode.SAMPLE_EARLY,
        HealthReasonCode.WINDOW_DUPLICATE,
        HealthReasonCode.WINDOW_OUT_OF_ORDER,
    }
)
_EVIDENCE_KEY = re.compile(
    r"^projects/(?P<project>controlgraph-canary-[a-z0-9]{6,10})/"
    r"locations/us-central1/keyRings/controlgraph-signing/"
    r"cryptoKeys/evidence-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _seconds(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _utc_second(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_utc_minute_strictly_after(value: str) -> str:
    """Return the next whole UTC minute, even when value is minute aligned."""

    parsed = _seconds(value)
    try:
        result = parsed.replace(second=0, microsecond=0) + timedelta(minutes=1)
    except OverflowError as error:
        raise ValueError("health anchor interval exceeds the UTC calendar range") from error
    return _utc_second(result)


def _content_id(
    value: StrictContractModel,
    *,
    id_field: str,
    prefix: str,
    domain: bytes,
) -> str:
    projection = cast(
        RestrictedJson,
        value.model_dump(mode="json", exclude={id_field}),
    )
    return f"{prefix}{hashlib.sha256(domain + canonical_json_value_bytes(projection)).hexdigest()}"


def _target_configuration_sha256(
    *,
    target: TargetBinding,
    stable_revision: str,
    candidate_revision: str,
    stable_percent: int,
    candidate_percent: int,
    concurrency: int,
) -> str:
    value: RestrictedJson = {
        "candidate_percent": candidate_percent,
        "candidate_revision": candidate_revision,
        "concurrency": concurrency,
        "schema_version": _TARGET_CONFIGURATION_V1,
        "stable_percent": stable_percent,
        "stable_revision": stable_revision,
        "target": target.model_dump(mode="json"),
    }
    return hashlib.sha256(
        _TARGET_CONFIGURATION_DOMAIN + canonical_json_value_bytes(value)
    ).hexdigest()


class PostApplyHealthAnchorV1(StrictContractModel):
    """Root-derived health interval anchored to one exact verified 90/10 receipt."""

    schema_version: Literal["controlgraph.post-apply-health-anchor/v1"]
    anchor_id: Identifier
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    plan_sha256: Sha256Digest
    policy: RolloutHealthPolicyV2
    policy_sha256: Sha256Digest
    stable_snapshot_sha256: Sha256Digest
    stable_revision: CloudRunName
    stable_revision_configuration_sha256: Sha256Digest
    candidate_revision: CloudRunName
    candidate_revision_configuration_sha256: Sha256Digest
    concurrency: Annotated[int, Field(ge=1, le=1_000)]
    stable_percent: Literal[90]
    candidate_percent: Literal[10]
    expected_prestate_sha256: Sha256Digest
    provider_etag: OpaqueToken
    evidence_signing_key_version: KeyVersionResource
    apply_receipt: ExecutionReceipt
    source_receipt_sha256: Sha256Digest
    observation_started_at: UtcSecond

    @model_validator(mode="after")
    def validate_anchor(self) -> Self:
        plan_prefix = f"{self.target.service_name}-"
        receipt = self.apply_receipt
        expected_prestate = _target_configuration_sha256(
            target=self.target,
            stable_revision=self.stable_revision,
            candidate_revision=self.candidate_revision,
            stable_percent=90,
            candidate_percent=10,
            concurrency=self.concurrency,
        )
        key_match = _EVIDENCE_KEY.fullmatch(self.evidence_signing_key_version)
        if self.root_id != f"cgroot:{self.root_sha256}":
            raise ValueError("health anchor root binding is invalid")
        if (
            self.stable_revision == self.candidate_revision
            or not self.stable_revision.startswith(plan_prefix)
            or not self.candidate_revision.startswith(plan_prefix)
        ):
            raise ValueError("health anchor revisions are outside the exact target")
        if self.policy_sha256 != canonical_sha256(self.policy):
            raise ValueError("health anchor policy digest is invalid")
        if self.expected_prestate_sha256 != expected_prestate:
            raise ValueError("health anchor 90/10 prestate digest is invalid")
        if key_match is None or key_match.group("project") != self.target.project_id:
            raise ValueError("health anchor signing key is outside the evidence purpose")
        if (
            type(receipt) is not ExecutionReceipt
            or receipt.action is not CapabilityAction.APPLY_CANARY
            or receipt.outcome is not ReceiptOutcome.VERIFIED
            or receipt.reason_code is not None
            or receipt.provider_operation is None
            or receipt.target != self.target
            or receipt.root_id != self.root_id
            or receipt.root_sha256 != self.root_sha256
            or receipt.epoch != self.epoch
            or receipt.plan_sha256 != self.plan_sha256
            or receipt.expected_poststate_sha256 != self.expected_prestate_sha256
            or receipt.observed_etag != self.provider_etag
            or receipt.observed_authority_epoch != self.epoch
            or self.source_receipt_sha256 != canonical_sha256(receipt)
        ):
            raise ValueError("health anchor receipt is not the exact verified 90/10 result")
        if self.observation_started_at != next_utc_minute_strictly_after(receipt.updated_at):
            raise ValueError("health anchor interval is not derived from the receipt")
        if self.anchor_id != _content_id(
            self,
            id_field="anchor_id",
            prefix="cghealthanchor:",
            domain=_ANCHOR_ID_DOMAIN,
        ):
            raise ValueError("health anchor identifier is not canonical")
        return self


class HealthDecisionProofV1(StrictContractModel):
    """One verifier-owned observation, prior state, and deterministic decision."""

    schema_version: Literal["controlgraph.health-decision-proof/v1"]
    proof_id: Identifier
    anchor_id: Identifier
    anchor_sha256: Sha256Digest
    sequence: Annotated[int, Field(ge=1, le=20)]
    previous_signed_proof_sha256: Sha256Digest | None
    verifier_identity: Annotated[str, Field(min_length=1, max_length=320)]
    prior_state: HealthEvaluationStateV1
    observation: MonitoringWindowObservationV1
    observation_sha256: Sha256Digest
    decision: HealthDecisionV1
    decision_sha256: Sha256Digest
    produced_at: UtcSecond

    @model_validator(mode="after")
    def validate_proof(self) -> Self:
        decision = self.decision
        observation = self.observation
        expected_verifier = (
            f"controlgraph-verifier@{decision.target.project_id}.iam.gserviceaccount.com"
        )
        if (self.sequence == 1) != (self.previous_signed_proof_sha256 is None):
            raise ValueError("health proof predecessor shape is invalid")
        if self.verifier_identity != expected_verifier:
            raise ValueError("health proof verifier identity is not target-bound")
        if self.observation_sha256 != canonical_sha256(observation):
            raise ValueError("health proof observation digest is invalid")
        if self.decision_sha256 != canonical_sha256(decision):
            raise ValueError("health proof decision digest is invalid")
        if decision.prior_state_sha256 != canonical_sha256(self.prior_state):
            raise ValueError("health proof prior state digest is invalid")
        if (
            decision.observation_sha256 != self.observation_sha256
            or decision.query_sha256s != observation.query_sha256s
            or decision.sample_sha256s != observation.sample_sha256s
            or decision.window_started_at != observation.window_started_at
            or decision.window_ended_at != observation.window_ended_at
            or decision.policy_sha256 != observation.policy_sha256
            or decision.target != observation.target
            or decision.root_id != observation.root_id
            or decision.root_sha256 != observation.root_sha256
            or decision.epoch != observation.epoch
            or decision.candidate_revision != observation.candidate_revision
            or self.prior_state.target != observation.target
            or self.prior_state.root_id != observation.root_id
            or self.prior_state.root_sha256 != observation.root_sha256
            or self.prior_state.epoch != observation.epoch
            or self.prior_state.candidate_revision != observation.candidate_revision
            or self.produced_at != decision.evaluated_at
            or observation.observed_at != decision.evaluated_at
        ):
            raise ValueError("health proof evidence and decision scope is inconsistent")
        if any(reason in _FORBIDDEN_ORCHESTRATION_REASONS for reason in decision.reason_codes):
            raise ValueError("health proof records a noncanonical orchestration attempt")
        if observation.timing is MonitoringObservationTiming.EARLY:
            raise ValueError("health proof cannot attest an early observation")
        if self.proof_id != _content_id(
            self,
            id_field="proof_id",
            prefix="cghealthproof:",
            domain=_PROOF_ID_DOMAIN,
        ):
            raise ValueError("health proof identifier is not canonical")
        return self


class SignedHealthDecisionProofV1(StrictContractModel):
    """A health proof signed only under the evidence key's health purpose."""

    schema_version: Literal["controlgraph.signed-health-decision-proof/v1"]
    proof: HealthDecisionProofV1
    purpose: Literal["HEALTH_ATTESTATION"]
    signing_key_version: KeyVersionResource
    signing_algorithm: Literal["EC_SIGN_P256_SHA256"]
    payload_sha256: Sha256Digest
    signing_input_sha256: Sha256Digest
    signature: Base64Url

    @model_validator(mode="after")
    def validate_signature_bindings(self) -> Self:
        project_id = self.proof.decision.target.project_id
        matched = _EVIDENCE_KEY.fullmatch(self.signing_key_version)
        try:
            raw_signature = decode_base64url(self.signature)
        except Exception:
            raise ValueError("health attestation signature encoding is invalid") from None
        if (
            matched is None
            or matched.group("project") != project_id
            or self.payload_sha256 != canonical_sha256(self.proof)
            or self.signing_input_sha256
            != health_attestation_signing_input_sha256(
                self.proof,
                self.signing_key_version,
            )
            or not raw_signature
            or len(raw_signature) > 256
            or encode_base64url(raw_signature) != self.signature
        ):
            raise ValueError("health attestation signature bindings are invalid")
        return self


class HealthyPromotionProofV1(StrictContractModel):
    """Compact healthy-chain projection carried into promotion authorization."""

    schema_version: Literal["controlgraph.healthy-promotion-proof/v1"]
    proof_id: Identifier
    anchor_id: Identifier
    anchor_sha256: Sha256Digest
    root_id: Identifier
    root_sha256: Sha256Digest
    target: TargetBinding
    epoch: PositiveSafeInteger
    policy_sha256: Sha256Digest
    candidate_revision: CloudRunName
    terminal_sequence: Annotated[int, Field(ge=1, le=20)]
    source_receipt_sha256: Sha256Digest
    expected_prestate_sha256: Sha256Digest
    terminal_health_decision_sha256: Sha256Digest
    signed_health_chain_sha256: Sha256Digest
    stable_percent: Literal[0]
    candidate_percent: Literal[100]
    desired_poststate_sha256: Sha256Digest
    issued_at: UtcSecond
    valid_until: UtcSecond

    @model_validator(mode="after")
    def validate_promotion_proof(self) -> Self:
        if self.root_id != f"cgroot:{self.root_sha256}":
            raise ValueError("healthy promotion proof root binding is invalid")
        if self.issued_at >= self.valid_until:
            raise ValueError("healthy promotion proof validity interval is invalid")
        if self.proof_id != _content_id(
            self,
            id_field="proof_id",
            prefix="cghealthpromotion:",
            domain=_PROMOTION_PROOF_ID_DOMAIN,
        ):
            raise ValueError("healthy promotion proof identifier is not canonical")
        return self


class SignedHealthDecisionChainV1(StrictContractModel):
    """Bounded, predecessor-linked signed health history for one post-apply anchor."""

    schema_version: Literal["controlgraph.signed-health-decision-chain/v1"]
    chain_id: Identifier
    anchor: PostApplyHealthAnchorV1
    anchor_sha256: Sha256Digest
    signed_proofs: Annotated[
        tuple[SignedHealthDecisionProofV1, ...],
        Field(min_length=1, max_length=20),
    ]
    chain_head_sha256: Sha256Digest
    healthy_promotion_proof: HealthyPromotionProofV1 | None

    @model_validator(mode="after")
    def validate_chain(self) -> Self:
        anchor = self.anchor
        if self.anchor_sha256 != canonical_sha256(anchor):
            raise ValueError("health chain anchor digest is invalid")
        if len(self.signed_proofs) > anchor.policy.maximum_windows * _MAX_PROOFS_PER_WINDOW:
            raise ValueError("health chain exceeds the policy evaluation bound")
        if self.chain_head_sha256 != canonical_sha256(self.signed_proofs[-1]):
            raise ValueError("health chain head digest is invalid")
        seen_signed: set[str] = set()
        window_counts: dict[int, int] = {}
        previous: SignedHealthDecisionProofV1 | None = None
        for expected_sequence, signed in enumerate(self.signed_proofs, start=1):
            signed_sha256 = canonical_sha256(signed)
            proof = signed.proof
            if signed_sha256 in seen_signed:
                raise ValueError("health chain contains a repeated signed proof")
            seen_signed.add(signed_sha256)
            if (
                proof.sequence != expected_sequence
                or proof.anchor_id != anchor.anchor_id
                or proof.anchor_sha256 != self.anchor_sha256
                or proof.decision.policy_sha256 != anchor.policy_sha256
                or proof.decision.target != anchor.target
                or proof.decision.root_id != anchor.root_id
                or proof.decision.root_sha256 != anchor.root_sha256
                or proof.decision.epoch != anchor.epoch
                or proof.decision.candidate_revision != anchor.candidate_revision
                or proof.observation.observation_started_at
                != anchor.observation_started_at
                or signed.signing_key_version != anchor.evidence_signing_key_version
            ):
                raise ValueError("health chain proof is outside its exact anchor")
            expected_previous = canonical_sha256(previous) if previous is not None else None
            if proof.previous_signed_proof_sha256 != expected_previous:
                raise ValueError("health chain predecessor digest is invalid")
            self._validate_state_transition(previous, proof)
            self._validate_window_attempt(previous, proof, window_counts)
            previous = signed

        terminal = self.signed_proofs[-1]
        if terminal.proof.decision.status is HealthDecisionStatus.HEALTHY:
            if self.healthy_promotion_proof is None:
                raise ValueError("healthy chain requires its compact promotion proof")
            self._validate_healthy_promotion_proof(terminal)
        elif self.healthy_promotion_proof is not None:
            raise ValueError("non-healthy chain cannot authorize promotion")
        if self.chain_id != f"cghealthchain:{signed_health_decision_chain_sha256(self)}":
            raise ValueError("health chain identifier is not canonical")
        return self

    def _validate_state_transition(
        self,
        previous: SignedHealthDecisionProofV1 | None,
        proof: HealthDecisionProofV1,
    ) -> None:
        if previous is None:
            expected = HealthEvaluationStateV1(
                schema_version="controlgraph.health-evaluation-state/v1",
                policy_schema_version=self.anchor.policy.schema_version,
                policy_sha256=self.anchor.policy_sha256,
                target=self.anchor.target,
                root_id=self.anchor.root_id,
                root_sha256=self.anchor.root_sha256,
                epoch=self.anchor.epoch,
                candidate_revision=self.anchor.candidate_revision,
                observation_started_at=self.anchor.observation_started_at,
                last_window_ended_at=None,
                consecutive_healthy_windows=0,
                consecutive_unhealthy_windows=0,
                evaluated_windows=0,
                last_observation_sha256=None,
                consumed_sample_set_sha256s=(),
                prior_decision_sha256=None,
            )
        else:
            predecessor = previous.proof.decision
            if predecessor.next_evaluation_at is None:
                raise ValueError("health chain continues after a terminal decision")
            next_values = predecessor.next_state.model_dump(mode="python")
            next_values["prior_decision_sha256"] = canonical_sha256(predecessor)
            expected = HealthEvaluationStateV1.model_validate(next_values)
        if proof.prior_state != expected:
            raise ValueError("health chain state is not derived from its predecessor")

    def _validate_window_attempt(
        self,
        previous: SignedHealthDecisionProofV1 | None,
        proof: HealthDecisionProofV1,
        window_counts: dict[int, int],
    ) -> None:
        policy = self.anchor.policy
        observation = proof.observation
        window_index = observation.window_index
        count = window_counts.get(window_index, 0) + 1
        if count > _MAX_PROOFS_PER_WINDOW:
            raise ValueError("health chain exceeds the per-window attempt bound")
        window_counts[window_index] = count
        ready_at = _seconds(observation.window_ended_at) + timedelta(
            seconds=policy.observation_delay_seconds
        )
        deadline = _seconds(observation.window_ended_at) + timedelta(
            seconds=policy.maximum_observation_delay_seconds
        )
        evaluated_at = _seconds(proof.decision.evaluated_at)
        if evaluated_at < ready_at:
            raise ValueError("health chain contains an evaluation before readiness")
        if count == 1:
            return
        if previous is None:
            raise ValueError("health chain retry lacks its predecessor")
        predecessor = previous.proof
        if (
            predecessor.observation.window_index != window_index
            or len(predecessor.decision.reason_codes) != 1
            or predecessor.decision.reason_codes[0] not in _RETRYABLE_REASONS
            or predecessor.decision.next_evaluation_at != _utc_second(deadline)
            or _seconds(predecessor.decision.evaluated_at) >= deadline
            or evaluated_at < deadline
        ):
            raise ValueError("health chain retry is not the one policy-declared deadline retry")

    def _validate_healthy_promotion_proof(
        self,
        terminal: SignedHealthDecisionProofV1,
    ) -> None:
        compact = self.healthy_promotion_proof
        assert compact is not None
        anchor = self.anchor
        desired = _target_configuration_sha256(
            target=anchor.target,
            stable_revision=anchor.stable_revision,
            candidate_revision=anchor.candidate_revision,
            stable_percent=0,
            candidate_percent=100,
            concurrency=anchor.concurrency,
        )
        if (
            compact.anchor_id != anchor.anchor_id
            or compact.anchor_sha256 != self.anchor_sha256
            or compact.root_id != anchor.root_id
            or compact.root_sha256 != anchor.root_sha256
            or compact.target != anchor.target
            or compact.epoch != anchor.epoch
            or compact.policy_sha256 != anchor.policy_sha256
            or compact.candidate_revision != anchor.candidate_revision
            or compact.terminal_sequence != terminal.proof.sequence
            or compact.source_receipt_sha256 != anchor.source_receipt_sha256
            or compact.expected_prestate_sha256 != anchor.expected_prestate_sha256
            or compact.terminal_health_decision_sha256
            != terminal.proof.decision_sha256
            or compact.signed_health_chain_sha256
            != signed_health_proof_chain_sha256(self.signed_proofs)
            or compact.desired_poststate_sha256 != desired
            or compact.issued_at != terminal.proof.decision.evaluated_at
            or compact.valid_until
            != _utc_second(
                _seconds(terminal.proof.observation.window_ended_at)
                + timedelta(seconds=anchor.policy.maximum_observation_delay_seconds)
            )
        ):
            raise ValueError("healthy promotion proof does not match its signed chain")


class HealthAttestationSigningRequestV1(StrictContractModel):
    """Exact anchor, signed predecessor, and pending proof sent to the evidence writer."""

    schema_version: Literal["controlgraph.health-attestation-signing-request/v1"]
    request_id: Identifier
    anchor: PostApplyHealthAnchorV1
    anchor_sha256: Sha256Digest
    prior_signed_proof: SignedHealthDecisionProofV1 | None
    pending_proof: HealthDecisionProofV1

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        anchor_sha256 = canonical_sha256(self.anchor)
        proof = self.pending_proof
        predecessor = self.prior_signed_proof
        if self.anchor_sha256 != anchor_sha256:
            raise ValueError("health attestation request anchor digest is invalid")
        if (
            proof.anchor_id != self.anchor.anchor_id
            or proof.anchor_sha256 != anchor_sha256
        ):
            raise ValueError("health attestation request proof is outside its anchor")
        if predecessor is None:
            if proof.sequence != 1 or proof.previous_signed_proof_sha256 is not None:
                raise ValueError("initial health attestation request predecessor is invalid")
            expected_state = HealthEvaluationStateV1(
                schema_version="controlgraph.health-evaluation-state/v1",
                policy_schema_version=self.anchor.policy.schema_version,
                policy_sha256=self.anchor.policy_sha256,
                target=self.anchor.target,
                root_id=self.anchor.root_id,
                root_sha256=self.anchor.root_sha256,
                epoch=self.anchor.epoch,
                candidate_revision=self.anchor.candidate_revision,
                observation_started_at=self.anchor.observation_started_at,
                last_window_ended_at=None,
                consecutive_healthy_windows=0,
                consecutive_unhealthy_windows=0,
                evaluated_windows=0,
                last_observation_sha256=None,
                consumed_sample_set_sha256s=(),
                prior_decision_sha256=None,
            )
        else:
            predecessor_proof = predecessor.proof
            predecessor_decision = predecessor_proof.decision
            if (
                predecessor_proof.anchor_id != self.anchor.anchor_id
                or predecessor_proof.anchor_sha256 != anchor_sha256
                or predecessor.signing_key_version
                != self.anchor.evidence_signing_key_version
                or proof.sequence != predecessor_proof.sequence + 1
                or proof.previous_signed_proof_sha256 != canonical_sha256(predecessor)
                or predecessor_decision.next_evaluation_at is None
            ):
                raise ValueError("health attestation request predecessor is invalid")
            state_values = predecessor_decision.next_state.model_dump(mode="python")
            state_values["prior_decision_sha256"] = canonical_sha256(
                predecessor_decision
            )
            expected_state = HealthEvaluationStateV1.model_validate(state_values)
        if proof.prior_state != expected_state:
            raise ValueError("health attestation request state is not predecessor-derived")
        if self.request_id != _content_id(
            self,
            id_field="request_id",
            prefix="cghealthattest:",
            domain=_ATTESTATION_REQUEST_ID_DOMAIN,
        ):
            raise ValueError("health attestation request identifier is not canonical")
        return self


def create_post_apply_health_anchor(
    *,
    root: RolloutRootV3,
    apply_receipt: ExecutionReceipt,
) -> PostApplyHealthAnchorV1:
    """Derive the sole health interval admitted by an exact V3 root and receipt."""

    if type(root) is not RolloutRootV3:
        raise TypeError("health anchoring requires an exact RolloutRootV3")
    if type(apply_receipt) is not ExecutionReceipt:
        raise TypeError("health anchoring requires an exact execution receipt")
    validated_root = RolloutRootV3.model_validate(root)
    validated_receipt = ExecutionReceipt.model_validate(apply_receipt)
    content = validated_root.content
    plan = content.rollout_plan
    if validated_receipt.provider_etag != content.stable_snapshot.provider_etag:
        raise ValueError("health anchor receipt does not use the root's stable precondition")
    values: dict[str, object] = {
        "schema_version": POST_APPLY_HEALTH_ANCHOR_V1,
        "anchor_id": "pending",
        "root_id": validated_root.root_id,
        "root_sha256": validated_root.root_sha256,
        "target": content.target,
        "epoch": validated_receipt.epoch,
        "plan_sha256": canonical_sha256(plan),
        "policy": content.health_policy,
        "policy_sha256": canonical_sha256(content.health_policy),
        "stable_snapshot_sha256": canonical_sha256(content.stable_snapshot),
        "stable_revision": plan.stable_revision,
        "stable_revision_configuration_sha256": (
            plan.stable_revision_configuration_sha256
        ),
        "candidate_revision": plan.candidate_revision,
        "candidate_revision_configuration_sha256": (
            plan.candidate_revision_configuration_sha256
        ),
        "concurrency": plan.concurrency,
        "stable_percent": 90,
        "candidate_percent": 10,
        "expected_prestate_sha256": _target_configuration_sha256(
            target=content.target,
            stable_revision=plan.stable_revision,
            candidate_revision=plan.candidate_revision,
            stable_percent=90,
            candidate_percent=10,
            concurrency=plan.concurrency,
        ),
        "provider_etag": validated_receipt.observed_etag,
        "evidence_signing_key_version": content.evidence_signing_key_version,
        "apply_receipt": validated_receipt,
        "source_receipt_sha256": canonical_sha256(validated_receipt),
        "observation_started_at": next_utc_minute_strictly_after(
            validated_receipt.updated_at
        ),
    }
    draft = PostApplyHealthAnchorV1.model_construct(_fields_set=None, **values)
    values["anchor_id"] = _content_id(
        draft,
        id_field="anchor_id",
        prefix="cghealthanchor:",
        domain=_ANCHOR_ID_DOMAIN,
    )
    return PostApplyHealthAnchorV1.model_validate(values)


def create_health_decision_proof(
    *,
    anchor: PostApplyHealthAnchorV1,
    sequence: int,
    previous_signed_proof_sha256: str | None,
    prior_state: HealthEvaluationStateV1,
    observation: MonitoringWindowObservationV1,
    decision: HealthDecisionV1,
) -> HealthDecisionProofV1:
    """Create one content-addressed proof from verifier-owned evaluator inputs."""

    if type(anchor) is not PostApplyHealthAnchorV1:
        raise TypeError("health proof creation requires an exact anchor")
    values: dict[str, object] = {
        "schema_version": HEALTH_DECISION_PROOF_V1,
        "proof_id": "pending",
        "anchor_id": anchor.anchor_id,
        "anchor_sha256": canonical_sha256(anchor),
        "sequence": sequence,
        "previous_signed_proof_sha256": previous_signed_proof_sha256,
        "verifier_identity": (
            f"controlgraph-verifier@{anchor.target.project_id}.iam.gserviceaccount.com"
        ),
        "prior_state": prior_state,
        "observation": observation,
        "observation_sha256": canonical_sha256(observation),
        "decision": decision,
        "decision_sha256": canonical_sha256(decision),
        "produced_at": decision.evaluated_at,
    }
    draft = HealthDecisionProofV1.model_construct(_fields_set=None, **values)
    values["proof_id"] = _content_id(
        draft,
        id_field="proof_id",
        prefix="cghealthproof:",
        domain=_PROOF_ID_DOMAIN,
    )
    return HealthDecisionProofV1.model_validate(values)


def health_attestation_signing_input_sha256(
    proof: HealthDecisionProofV1,
    signing_key_version: str,
) -> str:
    """Hash a health proof under its fixed purpose, key, and algorithm."""

    if type(proof) is not HealthDecisionProofV1:
        raise TypeError("health attestation requires an exact health proof")
    if type(signing_key_version) is not str or _EVIDENCE_KEY.fullmatch(
        signing_key_version
    ) is None:
        raise ValueError("health attestation key version is invalid")
    header: RestrictedJson = {
        "algorithm": P256_SIGNING_ALGORITHM,
        "key_version": signing_key_version,
        "payload_version": proof.schema_version,
        "purpose": HEALTH_ATTESTATION_PURPOSE,
        "schema_version": HEALTH_ATTESTATION_SIGNATURE_INPUT_V1,
    }
    return hashlib.sha256(
        _ATTESTATION_INPUT_DOMAIN
        + canonical_json_value_bytes(header)
        + b"\0"
        + canonical_json_bytes(proof)
    ).hexdigest()


def signed_health_proof_chain_sha256(
    signed_proofs: tuple[SignedHealthDecisionProofV1, ...],
) -> str:
    """Hash the complete ordered signed-proof sequence under a fixed domain."""

    if (
        type(signed_proofs) is not tuple
        or not signed_proofs
        or len(signed_proofs) > 20
        or any(type(value) is not SignedHealthDecisionProofV1 for value in signed_proofs)
    ):
        raise ValueError("signed health proof sequence is invalid")
    digest = hashlib.sha256()
    digest.update(_SIGNED_PROOF_CHAIN_DOMAIN)
    digest.update(len(signed_proofs).to_bytes(2, "big"))
    for signed in signed_proofs:
        digest.update(bytes.fromhex(canonical_sha256(signed)))
    return digest.hexdigest()


def signed_health_decision_chain_sha256(
    chain: SignedHealthDecisionChainV1,
) -> str:
    """Hash the chain manifest without encoding its potentially large proof aggregate."""

    if type(chain) is not SignedHealthDecisionChainV1:
        raise TypeError("health chain hashing requires an exact signed chain")
    compact_sha256 = (
        canonical_sha256(chain.healthy_promotion_proof)
        if chain.healthy_promotion_proof is not None
        else None
    )
    return health_chain_manifest_sha256(
        anchor_sha256=chain.anchor_sha256,
        ordered_proof_chain_sha256=signed_health_proof_chain_sha256(
            chain.signed_proofs
        ),
        chain_head_sha256=chain.chain_head_sha256,
        healthy_promotion_proof_sha256=compact_sha256,
    )


def health_chain_manifest_sha256(
    *,
    anchor_sha256: str,
    ordered_proof_chain_sha256: str,
    chain_head_sha256: str,
    healthy_promotion_proof_sha256: str | None,
) -> str:
    """Hash exact chain-manifest components without requiring the full proof chain."""

    required = (
        anchor_sha256,
        ordered_proof_chain_sha256,
        chain_head_sha256,
    )
    if any(
        type(component) is not str or _SHA256.fullmatch(component) is None
        for component in required
    ):
        raise ValueError("health chain manifest digest is invalid")
    if healthy_promotion_proof_sha256 is not None and (
        type(healthy_promotion_proof_sha256) is not str
        or _SHA256.fullmatch(healthy_promotion_proof_sha256) is None
    ):
        raise ValueError("health chain manifest promotion-proof digest is invalid")
    components = (
        bytes.fromhex(anchor_sha256),
        bytes.fromhex(ordered_proof_chain_sha256),
        bytes.fromhex(chain_head_sha256),
        (
            bytes.fromhex(healthy_promotion_proof_sha256)
            if healthy_promotion_proof_sha256 is not None
            else b""
        ),
    )
    digest = hashlib.sha256()
    digest.update(_CHAIN_MANIFEST_DOMAIN)
    for component in components:
        digest.update(len(component).to_bytes(2, "big"))
        digest.update(component)
    return digest.hexdigest()


def create_healthy_promotion_proof(
    *,
    anchor: PostApplyHealthAnchorV1,
    signed_proofs: tuple[SignedHealthDecisionProofV1, ...],
) -> HealthyPromotionProofV1:
    """Project a terminal healthy attestation into a compact promotion input."""

    if type(anchor) is not PostApplyHealthAnchorV1:
        raise TypeError("healthy promotion proof requires an exact anchor")
    if (
        type(signed_proofs) is not tuple
        or not signed_proofs
        or any(type(value) is not SignedHealthDecisionProofV1 for value in signed_proofs)
    ):
        raise TypeError("healthy promotion proof requires exact signed proofs")
    signed_terminal_proof = signed_proofs[-1]
    proof = signed_terminal_proof.proof
    if proof.decision.status is not HealthDecisionStatus.HEALTHY:
        raise ValueError("only a terminal healthy decision can authorize promotion")
    issued = _seconds(proof.decision.evaluated_at)
    valid_until = _seconds(proof.observation.window_ended_at) + timedelta(
        seconds=anchor.policy.maximum_observation_delay_seconds
    )
    if issued >= valid_until:
        raise ValueError("terminal healthy decision is outside the policy evidence lifetime")
    values: dict[str, object] = {
        "schema_version": HEALTHY_PROMOTION_PROOF_V1,
        "proof_id": "pending",
        "anchor_id": anchor.anchor_id,
        "anchor_sha256": canonical_sha256(anchor),
        "root_id": anchor.root_id,
        "root_sha256": anchor.root_sha256,
        "target": anchor.target,
        "epoch": anchor.epoch,
        "policy_sha256": anchor.policy_sha256,
        "candidate_revision": anchor.candidate_revision,
        "terminal_sequence": proof.sequence,
        "source_receipt_sha256": anchor.source_receipt_sha256,
        "expected_prestate_sha256": anchor.expected_prestate_sha256,
        "terminal_health_decision_sha256": proof.decision_sha256,
        "signed_health_chain_sha256": signed_health_proof_chain_sha256(signed_proofs),
        "stable_percent": 0,
        "candidate_percent": 100,
        "desired_poststate_sha256": _target_configuration_sha256(
            target=anchor.target,
            stable_revision=anchor.stable_revision,
            candidate_revision=anchor.candidate_revision,
            stable_percent=0,
            candidate_percent=100,
            concurrency=anchor.concurrency,
        ),
        "issued_at": _utc_second(issued),
        "valid_until": _utc_second(valid_until),
    }
    draft = HealthyPromotionProofV1.model_construct(_fields_set=None, **values)
    values["proof_id"] = _content_id(
        draft,
        id_field="proof_id",
        prefix="cghealthpromotion:",
        domain=_PROMOTION_PROOF_ID_DOMAIN,
    )
    return HealthyPromotionProofV1.model_validate(values)


def create_signed_health_decision_chain(
    *,
    anchor: PostApplyHealthAnchorV1,
    signed_proofs: tuple[SignedHealthDecisionProofV1, ...],
) -> SignedHealthDecisionChainV1:
    """Create and fully validate one bounded signed health chain."""

    if type(anchor) is not PostApplyHealthAnchorV1:
        raise TypeError("health chain creation requires an exact anchor")
    if type(signed_proofs) is not tuple or any(
        type(value) is not SignedHealthDecisionProofV1 for value in signed_proofs
    ):
        raise TypeError("health chain creation requires exact signed proofs")
    if not signed_proofs:
        raise ValueError("health chain requires at least one signed proof")
    healthy = signed_proofs[-1].proof.decision.status is HealthDecisionStatus.HEALTHY
    values: dict[str, object] = {
        "schema_version": SIGNED_HEALTH_DECISION_CHAIN_V1,
        "chain_id": "pending",
        "anchor": anchor,
        "anchor_sha256": canonical_sha256(anchor),
        "signed_proofs": signed_proofs,
        "chain_head_sha256": canonical_sha256(signed_proofs[-1]),
        "healthy_promotion_proof": (
            create_healthy_promotion_proof(
                anchor=anchor,
                signed_proofs=signed_proofs,
            )
            if healthy
            else None
        ),
    }
    draft = SignedHealthDecisionChainV1.model_construct(_fields_set=None, **values)
    values["chain_id"] = f"cghealthchain:{signed_health_decision_chain_sha256(draft)}"
    return SignedHealthDecisionChainV1.model_validate(values)


def create_health_attestation_signing_request(
    *,
    anchor: PostApplyHealthAnchorV1,
    prior_signed_proof: SignedHealthDecisionProofV1 | None,
    pending_proof: HealthDecisionProofV1,
) -> HealthAttestationSigningRequestV1:
    """Create the complete bounded request required before health-proof signing."""

    if type(anchor) is not PostApplyHealthAnchorV1:
        raise TypeError("health attestation request requires an exact anchor")
    if prior_signed_proof is not None and type(
        prior_signed_proof
    ) is not SignedHealthDecisionProofV1:
        raise TypeError("health attestation request requires an exact prior signed proof")
    if type(pending_proof) is not HealthDecisionProofV1:
        raise TypeError("health attestation request requires an exact pending proof")
    values: dict[str, object] = {
        "schema_version": HEALTH_ATTESTATION_SIGNING_REQUEST_V1,
        "request_id": "pending",
        "anchor": anchor,
        "anchor_sha256": canonical_sha256(anchor),
        "prior_signed_proof": prior_signed_proof,
        "pending_proof": pending_proof,
    }
    draft = HealthAttestationSigningRequestV1.model_construct(
        _fields_set=None,
        **values,
    )
    values["request_id"] = _content_id(
        draft,
        id_field="request_id",
        prefix="cghealthattest:",
        domain=_ATTESTATION_REQUEST_ID_DOMAIN,
    )
    return HealthAttestationSigningRequestV1.model_validate(values)


__all__ = [
    "HEALTHY_PROMOTION_PROOF_V1",
    "HEALTH_ATTESTATION_PURPOSE",
    "HEALTH_ATTESTATION_SIGNATURE_INPUT_V1",
    "HEALTH_ATTESTATION_SIGNING_REQUEST_V1",
    "HEALTH_DECISION_PROOF_V1",
    "POST_APPLY_HEALTH_ANCHOR_V1",
    "SIGNED_HEALTH_DECISION_CHAIN_V1",
    "SIGNED_HEALTH_DECISION_PROOF_V1",
    "HealthAttestationSigningRequestV1",
    "HealthDecisionProofV1",
    "HealthyPromotionProofV1",
    "PostApplyHealthAnchorV1",
    "SignedHealthDecisionChainV1",
    "SignedHealthDecisionProofV1",
    "create_health_attestation_signing_request",
    "create_health_decision_proof",
    "create_healthy_promotion_proof",
    "create_post_apply_health_anchor",
    "create_signed_health_decision_chain",
    "health_attestation_signing_input_sha256",
    "health_chain_manifest_sha256",
    "next_utc_minute_strictly_after",
    "signed_health_decision_chain_sha256",
    "signed_health_proof_chain_sha256",
]
