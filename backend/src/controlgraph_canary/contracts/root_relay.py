"""Canonical API-to-coordinator invocation for rollout-root creation."""

from __future__ import annotations

import re
from typing import Annotated, Final, Literal, Self

from pydantic import StringConstraints, model_validator

from controlgraph_canary.contracts.base import (
    Audience,
    BoundedText,
    PositiveSafeInteger,
    StrictContractModel,
)
from controlgraph_canary.contracts.root_creation import RootCreationCommandV1

ROOT_CREATION_INVOCATION_V1: Final = "controlgraph.root-creation-invocation/v1"

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


class RootCreationInvocationV1(StrictContractModel):
    """An exact command plus identity facts already verified by the operator API."""

    schema_version: Literal["controlgraph.root-creation-invocation/v1"]
    command: RootCreationCommandV1
    operator_identity: BoundedText
    operator_subject: GoogleSubject
    operator_issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    operator_audience: Audience
    operator_issued_at: PositiveSafeInteger
    operator_expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_invocation(self) -> Self:
        target = self.command.expected_stable_snapshot.target
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is None
            or "reconcile" in target.project_id
            or target.region != "us-central1"
            or target.environment != "nonprod"
            or target.service_name != _REFERENCE_SERVICE
            or _HUMAN_EMAIL.fullmatch(self.operator_identity) is None
            or self.operator_identity.endswith(".iam.gserviceaccount.com")
            or _API_AUDIENCE.fullmatch(self.operator_audience) is None
            or self.operator_issued_at >= self.operator_expires_at
            or self.operator_expires_at - self.operator_issued_at
            > _MAX_ID_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError("root creation invocation bindings are invalid")
        return self


__all__ = [
    "ROOT_CREATION_INVOCATION_V1",
    "RootCreationInvocationV1",
]
