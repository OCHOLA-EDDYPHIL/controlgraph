"""Canonical contracts for issuing and dispatching the first 90/10 canary."""

from __future__ import annotations

import re
from typing import Annotated, Final, Literal, Self

from pydantic import StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    CloudRunName,
    Identifier,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.models import TargetBinding

APPLY_CANARY_COMMAND_V1: Final = "controlgraph.apply-canary-command/v1"
APPLY_CANARY_INVOCATION_V1: Final = "controlgraph.apply-canary-invocation/v1"
CAPABILITY_ISSUANCE_COMMAND_V1: Final = (
    "controlgraph.capability-issuance-command/v1"
)
CANARY_DISPATCH_RESULT_V1: Final = "controlgraph.canary-dispatch-result/v1"

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_HUMAN_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_API_AUDIENCE = re.compile(
    r"^https://controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$"
)
_TASK_NAME = re.compile(
    r"^projects/(controlgraph-canary-[a-z0-9]{6,10})/locations/us-central1/"
    r"queues/controlgraph-execution/tasks/cg-[0-9a-f]{64}$"
)
_REFERENCE_SERVICE: Final = "controlgraph-reference-target"
_MAX_ID_TOKEN_LIFETIME_SECONDS: Final = 3_660

GoogleSubject = Annotated[
    str,
    StringConstraints(min_length=6, max_length=32, pattern=r"^[1-9][0-9]{5,31}$"),
]


class ApplyCanaryCommandV1(StrictContractModel):
    """Operator-selected identities and expected authority, never target coordinates."""

    schema_version: Literal["controlgraph.apply-canary-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier


class ApplyCanaryInvocationV1(StrictContractModel):
    """One apply command plus identity facts authenticated by the operator API."""

    schema_version: Literal["controlgraph.apply-canary-invocation/v1"]
    command: ApplyCanaryCommandV1
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
            raise ValueError("apply-canary invocation bindings are invalid")
        return self


class CapabilityIssuanceCommandV1(StrictContractModel):
    """Coordinator preconditions for one root-derived apply-canary capability."""

    schema_version: Literal["controlgraph.capability-issuance-command/v1"]
    root_id: Identifier
    expected_root_sha256: Sha256Digest
    expected_epoch: PositiveSafeInteger
    request_id: Identifier
    idempotency_key: Identifier


class CanaryDispatchResultV1(StrictContractModel):
    """Bounded result of issuing and addressing one canary task."""

    schema_version: Literal["controlgraph.canary-dispatch-result/v1"]
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    stable_revision: CloudRunName
    candidate_revision: CloudRunName
    stable_percent: Literal[90]
    candidate_percent: Literal[10]
    capability_id: Identifier
    capability_sha256: Sha256Digest
    task_id: Identifier
    task_name: BoundedText
    enqueue_disposition: Literal["CREATED", "DUPLICATE", "AMBIGUOUS"]
    scheduled_at: UtcSecond
    expires_at: UtcSecond

    @model_validator(mode="after")
    def validate_dispatch(self) -> Self:
        task_match = _TASK_NAME.fullmatch(self.task_name)
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(self.target.project_id) is None
            or "reconcile" in self.target.project_id.lower()
            or self.target.region != "us-central1"
            or self.target.environment != "nonprod"
            or self.target.service_name != _REFERENCE_SERVICE
            or task_match is None
            or task_match.group(1) != self.target.project_id
            or self.scheduled_at >= self.expires_at
        ):
            raise ValueError("canary dispatch result bindings are invalid")
        return self


__all__ = [
    "APPLY_CANARY_COMMAND_V1",
    "APPLY_CANARY_INVOCATION_V1",
    "CANARY_DISPATCH_RESULT_V1",
    "CAPABILITY_ISSUANCE_COMMAND_V1",
    "ApplyCanaryCommandV1",
    "ApplyCanaryInvocationV1",
    "CanaryDispatchResultV1",
    "CapabilityIssuanceCommandV1",
]
