"""Bounded wire contracts for one post-apply health evaluation attempt."""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    Identifier,
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
)
from controlgraph_canary.contracts.health import HealthDecisionStatus
from controlgraph_canary.contracts.health_execution import (
    PostApplyHealthAnchorV1,
    SignedHealthDecisionProofV1,
    create_post_apply_health_anchor,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.promotion_execution import (
    PromotionHealthChainLocatorV1,
    VerifiedApplyReceiptLocatorV1,
    create_verified_apply_receipt_locator,
)
from controlgraph_canary.contracts.root_creation import RolloutRootV3

HEALTH_EVALUATION_COMMAND_V1: Final = "controlgraph.health-evaluation-command/v1"
HEALTH_EVALUATION_INVOCATION_V1: Final = "controlgraph.health-evaluation-invocation/v1"
VERIFIER_HEALTH_EVALUATION_REQUEST_V1: Final = (
    "controlgraph.verifier-health-evaluation-request/v1"
)
VERIFIER_HEALTH_EVALUATION_RESULT_V1: Final = (
    "controlgraph.verifier-health-evaluation-result/v1"
)
HEALTH_EVALUATION_RESULT_V1: Final = "controlgraph.health-evaluation-result/v1"

_COMMAND_DIGEST_DOMAIN: Final = b"controlgraph.health-evaluation-command-sha256/v1\0"
_VERIFIER_REQUEST_DIGEST_DOMAIN: Final = (
    b"controlgraph.verifier-health-evaluation-request-sha256/v1\0"
)
_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(
    r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
_MAX_ID_TOKEN_LIFETIME_SECONDS: Final = 3_660

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


def _target_is_exact(target: TargetBinding) -> bool:
    return (
        type(target) is TargetBinding
        and _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is not None
        and "reconcile" not in target.project_id
        and target.region == "us-central1"
        and target.environment == "nonprod"
        and target.service_name == _REFERENCE_SERVICE
    )


class HealthEvaluationCommandV1(StrictContractModel):
    """Operator-selected root, epoch, and exact verified apply receipt."""

    schema_version: Literal["controlgraph.health-evaluation-command/v1"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1
    expected_sequence: Annotated[int, Field(ge=0, le=19)]
    expected_chain_head_sha256: Sha256Digest | None

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        if (
            not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.expected_root_sha256}"
            or (self.expected_sequence == 0)
            != (self.expected_chain_head_sha256 is None)
        ):
            raise ValueError("health evaluation command bindings are invalid")
        return self


class HealthEvaluationInvocationV1(StrictContractModel):
    """Health command plus operator identity facts authenticated by the API."""

    schema_version: Literal["controlgraph.health-evaluation-invocation/v1"]
    command: HealthEvaluationCommandV1
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        if (
            _HUMAN_EMAIL.fullmatch(self.operator_identity) is None
            or self.operator_identity.endswith(".iam.gserviceaccount.com")
            or _API_AUDIENCE.fullmatch(self.operator_audience) is None
            or self.operator_issued_at >= self.operator_expires_at
            or self.operator_expires_at - self.operator_issued_at
            > _MAX_ID_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError("health evaluation invocation bindings are invalid")
        return self


class VerifierHealthEvaluationRequestV1(StrictContractModel):
    """One root-bound anchor and only its immediate signed predecessor."""

    schema_version: Literal["controlgraph.verifier-health-evaluation-request/v1"]
    request_sha256: Sha256Digest
    command: HealthEvaluationCommandV1
    command_sha256: Sha256Digest
    root: RolloutRootV3
    anchor: PostApplyHealthAnchorV1
    anchor_sha256: Sha256Digest
    prior_signed_proof: SignedHealthDecisionProofV1 | None

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        command = self.command
        root = self.root
        anchor = self.anchor
        predecessor = self.prior_signed_proof
        try:
            expected_anchor = create_post_apply_health_anchor(
                root=root,
                apply_receipt=anchor.apply_receipt,
            )
            expected_receipt = create_verified_apply_receipt_locator(
                anchor.apply_receipt
            )
        except (TypeError, ValueError):
            raise ValueError("verifier health request anchor is invalid") from None
        if (
            command.target != root.content.target
            or command.root_id != root.root_id
            or command.expected_root_sha256 != root.root_sha256
            or command.expected_epoch != anchor.epoch
            or command.verified_apply_receipt != expected_receipt
            or anchor != expected_anchor
            or self.anchor_sha256 != canonical_sha256(anchor)
            or self.command_sha256 != health_evaluation_command_sha256(command)
        ):
            raise ValueError("verifier health request bindings are invalid")
        if predecessor is None:
            if (
                command.expected_sequence != 0
                or command.expected_chain_head_sha256 is not None
            ):
                raise ValueError("verifier health request predecessor is invalid")
        else:
            proof = predecessor.proof
            if (
                proof.anchor_id != anchor.anchor_id
                or proof.anchor_sha256 != self.anchor_sha256
                or proof.sequence != command.expected_sequence
                or canonical_sha256(predecessor)
                != command.expected_chain_head_sha256
                or predecessor.signing_key_version
                != anchor.evidence_signing_key_version
                or proof.decision.next_evaluation_at is None
            ):
                raise ValueError("verifier health request predecessor is invalid")
        if self.request_sha256 != verifier_health_evaluation_request_sha256(self):
            raise ValueError("verifier health request digest is invalid")
        canonical_json_value_bytes(
            cast(RestrictedJson, self.model_dump(mode="json"))
        )
        return self


class VerifierHealthEvaluationResultV1(StrictContractModel):
    """One signed proof bound to the exact verifier request that produced it."""

    schema_version: Literal["controlgraph.verifier-health-evaluation-result/v1"]
    request_sha256: Sha256Digest
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    anchor_id: Identifier
    anchor_sha256: Sha256Digest
    prior_signed_proof_sha256: Sha256Digest | None
    signed_proof: SignedHealthDecisionProofV1
    signed_proof_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        proof = self.signed_proof.proof
        if (
            not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.root_sha256}"
            or proof.decision.target != self.target
            or proof.decision.root_id != self.root_id
            or proof.decision.root_sha256 != self.root_sha256
            or proof.decision.epoch != self.epoch
            or proof.anchor_id != self.anchor_id
            or proof.anchor_sha256 != self.anchor_sha256
            or proof.previous_signed_proof_sha256
            != self.prior_signed_proof_sha256
            or canonical_sha256(self.signed_proof) != self.signed_proof_sha256
        ):
            raise ValueError("verifier health result bindings are invalid")
        canonical_json_value_bytes(
            cast(RestrictedJson, self.model_dump(mode="json"))
        )
        return self


class HealthEvaluationResultV1(StrictContractModel):
    """Compact durable chain progress returned without transporting the full chain."""

    schema_version: Literal["controlgraph.health-evaluation-result/v1"]
    request_id: Identifier
    idempotency_key: Identifier
    command_sha256: Sha256Digest
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    verified_apply_receipt: VerifiedApplyReceiptLocatorV1
    expected_sequence: Annotated[int, Field(ge=0, le=19)]
    expected_chain_head_sha256: Sha256Digest | None
    anchor_id: Identifier
    anchor_sha256: Sha256Digest
    chain_id: Identifier
    health_chain_sha256: Sha256Digest
    chain_head_sha256: Sha256Digest
    ordered_proof_chain_sha256: Sha256Digest
    terminal_sequence: Annotated[int, Field(ge=1, le=20)]
    terminal_status: HealthDecisionStatus
    terminal_health_decision_sha256: Sha256Digest
    next_evaluation_at: UtcSecond | None
    append_disposition: Literal["CREATED", "ADOPTED"]
    promotion_health_chain: PromotionHealthChainLocatorV1 | None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        locator = self.promotion_health_chain
        if (
            not _target_is_exact(self.target)
            or self.root_id != f"cgroot:{self.root_sha256}"
            or self.chain_id != f"cghealthchain:{self.health_chain_sha256}"
            or (self.expected_sequence == 0)
            != (self.expected_chain_head_sha256 is None)
            or self.terminal_sequence != self.expected_sequence + 1
        ):
            raise ValueError("health evaluation result bindings are invalid")
        if self.terminal_status is HealthDecisionStatus.HEALTHY:
            if (
                self.next_evaluation_at is not None
                or locator is None
                or locator.anchor_id != self.anchor_id
                or locator.anchor_sha256 != self.anchor_sha256
                or locator.chain_id != self.chain_id
                or locator.health_chain_sha256 != self.health_chain_sha256
                or locator.chain_head_sha256 != self.chain_head_sha256
                or locator.ordered_proof_chain_sha256
                != self.ordered_proof_chain_sha256
                or locator.terminal_sequence != self.terminal_sequence
            ):
                raise ValueError("healthy evaluation result lacks its exact chain locator")
        elif locator is not None:
            raise ValueError("non-healthy evaluation result cannot authorize promotion")
        canonical_json_value_bytes(
            cast(RestrictedJson, self.model_dump(mode="json"))
        )
        return self


def health_evaluation_command_sha256(command: HealthEvaluationCommandV1) -> str:
    """Hash every operator-selected health-evaluation binding."""

    if type(command) is not HealthEvaluationCommandV1:
        raise TypeError("health evaluation hashing requires an exact command")
    return hashlib.sha256(
        _COMMAND_DIGEST_DOMAIN + canonical_json_bytes(command)
    ).hexdigest()


def verifier_health_evaluation_request_sha256(
    request: VerifierHealthEvaluationRequestV1,
) -> str:
    """Hash a verifier request without its self-identifying digest field."""

    if type(request) is not VerifierHealthEvaluationRequestV1:
        raise TypeError("verifier health hashing requires an exact request")
    projection = cast(
        RestrictedJson,
        request.model_dump(mode="json", exclude={"request_sha256"}),
    )
    return hashlib.sha256(
        _VERIFIER_REQUEST_DIGEST_DOMAIN + canonical_json_value_bytes(projection)
    ).hexdigest()


def create_verifier_health_evaluation_request(
    *,
    command: HealthEvaluationCommandV1,
    root: RolloutRootV3,
    anchor: PostApplyHealthAnchorV1,
    prior_signed_proof: SignedHealthDecisionProofV1 | None,
) -> VerifierHealthEvaluationRequestV1:
    """Construct the sole bounded request admitted by the verifier service."""

    if (
        type(command) is not HealthEvaluationCommandV1
        or type(root) is not RolloutRootV3
        or type(anchor) is not PostApplyHealthAnchorV1
        or (
            prior_signed_proof is not None
            and type(prior_signed_proof) is not SignedHealthDecisionProofV1
        )
    ):
        raise TypeError("verifier health request inputs must be exact")
    values: dict[str, object] = {
        "schema_version": VERIFIER_HEALTH_EVALUATION_REQUEST_V1,
        "request_sha256": "0" * 64,
        "command": command,
        "command_sha256": health_evaluation_command_sha256(command),
        "root": root,
        "anchor": anchor,
        "anchor_sha256": canonical_sha256(anchor),
        "prior_signed_proof": prior_signed_proof,
    }
    draft = VerifierHealthEvaluationRequestV1.model_construct(
        _fields_set=None,
        **values,
    )
    values["request_sha256"] = verifier_health_evaluation_request_sha256(draft)
    return VerifierHealthEvaluationRequestV1.model_validate(values)


__all__ = [
    "HEALTH_EVALUATION_COMMAND_V1",
    "HEALTH_EVALUATION_INVOCATION_V1",
    "HEALTH_EVALUATION_RESULT_V1",
    "VERIFIER_HEALTH_EVALUATION_REQUEST_V1",
    "VERIFIER_HEALTH_EVALUATION_RESULT_V1",
    "HealthEvaluationCommandV1",
    "HealthEvaluationInvocationV1",
    "HealthEvaluationResultV1",
    "VerifierHealthEvaluationRequestV1",
    "VerifierHealthEvaluationResultV1",
    "create_verifier_health_evaluation_request",
    "health_evaluation_command_sha256",
    "verifier_health_evaluation_request_sha256",
]
