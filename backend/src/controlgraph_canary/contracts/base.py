"""Strict primitives shared by ControlGraph wire contracts."""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_CONTRACT_BYTES = 65_536
MAX_JSON_DEPTH = 12
MAX_JSON_ITEMS = 64

_UTC_SECOND = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})Z$"
)


def validate_nfc_text(value: str) -> str:
    """Require bounded contract text to be Unicode scalar NFC text."""

    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("text must contain Unicode scalar values") from error
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("text must use NFC normalization")
    return value


def validate_safe_text(value: str) -> str:
    """Reject rendering controls from human-readable boundary text."""

    validate_nfc_text(value)
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        raise ValueError("text contains a rendering control")
    return value


def validate_utc_second(value: str) -> str:
    """Require one exact UTC timestamp encoding with whole-second precision."""

    validate_nfc_text(value)
    if _UTC_SECOND.fullmatch(value) is None:
        raise ValueError("timestamp must use YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("timestamp is not a valid UTC calendar second") from error
    return value


def validate_audience(value: str) -> str:
    """Require an exact HTTPS service audience without userinfo or fragments."""

    validate_nfc_text(value)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("audience is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError("audience must be one exact HTTPS origin or path")
    return value


class StrictContractModel(BaseModel):
    """Immutable, strict, unknown-field-rejecting contract base."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


Identifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
    AfterValidator(validate_nfc_text),
]
ProjectId = Annotated[
    str,
    StringConstraints(
        min_length=6,
        max_length=30,
        pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$",
    ),
]
Region = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=32,
        pattern=r"^[a-z]+-[a-z]+[0-9]+$",
    ),
]
CloudRunName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=63,
        pattern=r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Base64Url = Annotated[
    str,
    StringConstraints(min_length=1, max_length=16_384, pattern=r"^[A-Za-z0-9_-]+$"),
]
OpaqueToken = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=512,
        pattern=r'^(?:[A-Za-z0-9._~:/+=-]+|"[A-Za-z0-9._~:/+=-]+")$',
    ),
]
KeyVersionResource = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=512,
        pattern=(
            r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/"
            r"keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/"
            r"cryptoKeyVersions/[1-9][0-9]*$"
        ),
    ),
]
ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512),
    AfterValidator(validate_safe_text),
]
BoundedText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2_048),
    AfterValidator(validate_safe_text),
]
UtcSecond = Annotated[
    str,
    StringConstraints(min_length=20, max_length=20),
    AfterValidator(validate_utc_second),
]
Audience = Annotated[
    str,
    StringConstraints(min_length=9, max_length=2_048),
    AfterValidator(validate_audience),
]
SafeInteger = Annotated[int, Field(ge=-MAX_SAFE_INTEGER, le=MAX_SAFE_INTEGER)]
NonNegativeSafeInteger = Annotated[int, Field(ge=0, le=MAX_SAFE_INTEGER)]
PositiveSafeInteger = Annotated[int, Field(ge=1, le=MAX_SAFE_INTEGER)]
Percent = Annotated[int, Field(ge=0, le=100)]


__all__ = [
    "MAX_CONTRACT_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_ITEMS",
    "MAX_SAFE_INTEGER",
    "Audience",
    "Base64Url",
    "BoundedText",
    "CloudRunName",
    "Identifier",
    "KeyVersionResource",
    "NonNegativeSafeInteger",
    "OpaqueToken",
    "Percent",
    "PositiveSafeInteger",
    "ProjectId",
    "Region",
    "SafeInteger",
    "Sha256Digest",
    "ShortText",
    "StrictContractModel",
    "UtcSecond",
    "validate_nfc_text",
    "validate_utc_second",
]
