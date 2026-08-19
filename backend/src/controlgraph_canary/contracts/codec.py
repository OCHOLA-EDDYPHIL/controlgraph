"""Restricted canonical JSON and version-aware contract decoding."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from enum import StrEnum
from typing import Any, Literal, cast, get_args, get_origin

from pydantic import ValidationError

from controlgraph_canary.contracts.base import (
    MAX_CONTRACT_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_ITEMS,
    MAX_SAFE_INTEGER,
    StrictContractModel,
    validate_nfc_text,
)

CANONICAL_ENCODING = "controlgraph.canonical-json/v1"
DIGEST_DOMAIN = b"controlgraph.contract-sha256/v1\0"
_OBJECT_KEY = re.compile(r"^[a-z][a-z0-9_]*$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]*$")

type RestrictedJson = (
    bool | int | str | list["RestrictedJson"] | dict[str, "RestrictedJson"] | None
)
type ContractType = type[StrictContractModel]


class ContractErrorCode(StrEnum):
    """Stable public codec failures."""

    INVALID = "CONTRACT_INVALID"
    VERSION_UNSUPPORTED = "CONTRACT_VERSION_UNSUPPORTED"


class ContractError(ValueError):
    """A bounded contract failure that never includes untrusted payload text."""

    def __init__(self, code: ContractErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _invalid(message: str) -> ContractError:
    return ContractError(ContractErrorCode.INVALID, message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _reject_float(_value: str) -> None:
    raise ValueError("floating-point numbers are not permitted")


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite numbers are not permitted")


def _validate_restricted(value: object, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting is too deep")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("integer is outside the cross-language safe range")
        return
    if type(value) is str:
        validate_nfc_text(value)
        return
    if type(value) in {list, tuple}:
        sequence = cast(list[object] | tuple[object, ...], value)
        if len(sequence) > MAX_JSON_ITEMS:
            raise ValueError("JSON array has too many items")
        for item in sequence:
            _validate_restricted(item, depth=depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_JSON_ITEMS:
            raise ValueError("JSON object has too many fields")
        for key, item in value.items():
            if type(key) is not str or _OBJECT_KEY.fullmatch(key) is None:
                raise ValueError("JSON object key is not canonical")
            _validate_restricted(item, depth=depth + 1)
        return
    raise ValueError("value is not part of restricted JSON")


def canonical_json_value_bytes(value: RestrictedJson) -> bytes:
    """Encode a restricted JSON value with one cross-language representation."""

    try:
        _validate_restricted(value)
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as error:
        raise _invalid("canonical JSON encoding failed") from error
    if not encoded or len(encoded) > MAX_CONTRACT_BYTES:
        raise _invalid("canonical JSON is outside its byte bounds")
    return encoded


def canonical_json_bytes(model: StrictContractModel) -> bytes:
    """Return canonical bytes for one fully validated contract instance."""

    if not isinstance(model, StrictContractModel):
        raise TypeError("a strict contract model is required")
    try:
        validated = type(model).model_validate(model)
        value = validated.model_dump(mode="json")
    except (TypeError, ValueError, ValidationError) as error:
        raise _invalid("contract validation failed") from error
    return canonical_json_value_bytes(value)


def _expected_version(model_type: ContractType) -> str:
    if not isinstance(model_type, type) or not issubclass(model_type, StrictContractModel):
        raise TypeError("model_type must be a strict contract model type")
    field = model_type.model_fields.get("schema_version")
    if field is None or get_origin(field.annotation) is not Literal:
        raise TypeError("contract model must declare one literal schema_version")
    values = get_args(field.annotation)
    if len(values) != 1 or type(values[0]) is not str:
        raise TypeError("contract model must declare one literal schema_version")
    return values[0]


def decode_contract[ModelT: StrictContractModel](
    payload: bytes | str,
    model_type: type[ModelT],
) -> ModelT:
    """Decode one exact canonical object and reject parser ambiguity."""

    if type(payload) is bytes:
        encoded = payload
        try:
            text = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise _invalid("contract is not valid UTF-8") from error
    elif type(payload) is str:
        text = payload
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError as error:
            raise _invalid("contract is not valid UTF-8") from error
    else:
        raise TypeError("payload must be exact bytes or text")

    if not encoded or len(encoded) > MAX_CONTRACT_BYTES or encoded.startswith(b"\xef\xbb\xbf"):
        raise _invalid("contract is outside its byte bounds")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        _validate_restricted(value)
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise _invalid("contract is not restricted JSON") from error
    if type(value) is not dict:
        raise _invalid("contract must be a JSON object")

    expected_version = _expected_version(model_type)
    version = value.get("schema_version")
    if type(version) is not str:
        raise _invalid("schema_version is required")
    if version != expected_version:
        raise ContractError(
            ContractErrorCode.VERSION_UNSUPPORTED,
            "contract schema_version is unsupported",
        )

    try:
        normalized = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        model = model_type.model_validate_json(normalized)
    except ValidationError as error:
        if any(
            item["type"] == "literal_error"
            and item["loc"]
            and item["loc"][-1] == "schema_version"
            and type(item["input"]) is str
            for item in error.errors()
        ):
            raise ContractError(
                ContractErrorCode.VERSION_UNSUPPORTED,
                "nested contract schema_version is unsupported",
            ) from error
        raise _invalid("contract validation failed") from error
    except (TypeError, ValueError) as error:
        raise _invalid("contract validation failed") from error

    if canonical_json_bytes(model) != encoded:
        raise _invalid("contract is not in canonical form")
    return model


def canonical_sha256(model: StrictContractModel) -> str:
    """Hash canonical bytes under an explicit version and schema domain."""

    version = _expected_version(type(model))
    material = DIGEST_DOMAIN + version.encode("ascii") + b"\0" + canonical_json_bytes(model)
    return hashlib.sha256(material).hexdigest()


def encode_base64url(value: bytes) -> str:
    """Encode bytes as unpadded canonical base64url."""

    if type(value) is not bytes:
        raise TypeError("base64url input must be bytes")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_base64url(value: str, *, maximum_bytes: int = 16_384) -> bytes:
    """Decode only the unpadded canonical base64url spelling."""

    if (
        type(value) is not str
        or len(value) > maximum_bytes * 2
        or _BASE64URL.fullmatch(value) is None
    ):
        raise _invalid("base64url value is invalid")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise _invalid("base64url value is invalid") from error
    if len(decoded) > maximum_bytes or encode_base64url(decoded) != value:
        raise _invalid("base64url value is not canonical")
    return decoded


__all__ = [
    "CANONICAL_ENCODING",
    "DIGEST_DOMAIN",
    "ContractError",
    "ContractErrorCode",
    "canonical_json_bytes",
    "canonical_json_value_bytes",
    "canonical_sha256",
    "decode_base64url",
    "decode_contract",
    "encode_base64url",
]
