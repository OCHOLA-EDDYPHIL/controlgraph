"""Canonical API-to-coordinator invocations for timeline projections."""

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
from controlgraph_canary.contracts.timeline import (
    TimelinePageCommandV1,
    TimelineRawExportCommandV1,
)

TIMELINE_READ_INVOCATION_V1: Final = "controlgraph.timeline-read-invocation/v1"
TIMELINE_RAW_EXPORT_INVOCATION_V1: Final = (
    "controlgraph.timeline-raw-export-invocation/v1"
)

_CONTROLGRAPH_PROJECT = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")
_TIMELINE_READER_EMAIL = re.compile(
    r"^[a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9.\-]{0,251}[a-z0-9])?$"
)
_TIMELINE_READER_SERVICE_ACCOUNT = re.compile(
    r"^cg-(?:security-auditor|restricted-exporter)@"
    r"(?P<project>controlgraph-canary-[a-z0-9]{6,10})\.iam\.gserviceaccount\.com$"
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


class TimelineReaderIdentityV1(StrictContractModel):
    """Identity facts verified by the API and re-authorized by the coordinator."""

    email: BoundedText
    subject: GoogleSubject
    issuer: Literal["accounts.google.com", "https://accounts.google.com"]
    audience: Audience
    issued_at: PositiveSafeInteger
    expires_at: PositiveSafeInteger

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if (
            _TIMELINE_READER_EMAIL.fullmatch(self.email) is None
            or (
                self.email.endswith(".iam.gserviceaccount.com")
                and _TIMELINE_READER_SERVICE_ACCOUNT.fullmatch(self.email) is None
            )
            or _API_AUDIENCE.fullmatch(self.audience) is None
            or self.issued_at >= self.expires_at
            or self.expires_at - self.issued_at > _MAX_ID_TOKEN_LIFETIME_SECONDS
        ):
            raise ValueError("timeline reader identity bindings are invalid")
        return self


class TimelineReadInvocationV1(StrictContractModel):
    schema_version: Literal["controlgraph.timeline-read-invocation/v1"]
    command: TimelinePageCommandV1
    reader: TimelineReaderIdentityV1

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        target = self.command.target
        reader_service_account = _TIMELINE_READER_SERVICE_ACCOUNT.fullmatch(
            self.reader.email
        )
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is None
            or "reconcile" in target.project_id
            or target.region != "us-central1"
            or target.environment != "nonprod"
            or target.service_name != _REFERENCE_SERVICE
            or (
                reader_service_account is not None
                and reader_service_account.group("project") != target.project_id
            )
        ):
            raise ValueError("timeline read invocation target is invalid")
        return self


class TimelineRawExportInvocationV1(StrictContractModel):
    schema_version: Literal["controlgraph.timeline-raw-export-invocation/v1"]
    command: TimelineRawExportCommandV1
    reader: TimelineReaderIdentityV1

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        target = self.command.target
        reader_service_account = _TIMELINE_READER_SERVICE_ACCOUNT.fullmatch(
            self.reader.email
        )
        if (
            _CONTROLGRAPH_PROJECT.fullmatch(target.project_id) is None
            or "reconcile" in target.project_id
            or target.region != "us-central1"
            or target.environment != "nonprod"
            or target.service_name != _REFERENCE_SERVICE
            or (
                reader_service_account is not None
                and reader_service_account.group("project") != target.project_id
            )
        ):
            raise ValueError("timeline raw export invocation target is invalid")
        return self


__all__ = [
    "TIMELINE_RAW_EXPORT_INVOCATION_V1",
    "TIMELINE_READ_INVOCATION_V1",
    "TimelineRawExportInvocationV1",
    "TimelineReadInvocationV1",
    "TimelineReaderIdentityV1",
]
