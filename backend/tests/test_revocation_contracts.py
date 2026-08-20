from __future__ import annotations

import pytest
from pydantic import ValidationError

from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_COMMAND_V1,
    EPOCH_REVOCATION_INVOCATION_V1,
    EpochRevocationCommandV1,
    EpochRevocationInvocationV1,
    epoch_revocation_request_sha256,
)

ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64


def _command_values() -> dict[str, object]:
    return {
        "schema_version": EPOCH_REVOCATION_COMMAND_V1,
        "root_id": f"cgroot:{ZERO_DIGEST}",
        "expected_root_sha256": ZERO_DIGEST,
        "expected_epoch": 1,
        "reason": "Stop delayed work before it executes.",
        "request_id": "request-revoke-001",
        "idempotency_key": "revoke-001",
        "confirmation": "REVOKE",
    }


def _invocation_values() -> dict[str, object]:
    return {
        "schema_version": EPOCH_REVOCATION_INVOCATION_V1,
        "command": _command_values(),
        "attempt_id": "cgrevoke-attempt-001",
        "operator_identity": "operator@example.test",
        "operator_subject": "123456789012345678901",
        "operator_issuer": "https://accounts.google.com",
        "operator_audience": (
            "https://controlgraph-api-123456789012.us-central1.run.app"
        ),
        "operator_issued_at": 1_787_137_440,
        "operator_expires_at": 1_787_138_100,
    }


@pytest.mark.parametrize(
    "changed",
    [
        {"confirmation": "revoke"},
        {"reason": " Stop delayed work before it executes."},
        {"root_id": f"cgroot:{ONE_DIGEST}"},
        {"unexpected": "field"},
    ],
)
def test_revocation_command_rejects_noncanonical_input(
    changed: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        EpochRevocationCommandV1.model_validate({**_command_values(), **changed})


def test_revocation_invocation_rejects_unknown_and_service_account_operators() -> None:
    for changed in (
        {"unexpected": "field"},
        {
            "operator_identity": (
                "controlgraph-api@example.iam.gserviceaccount.com"
            )
        },
    ):
        with pytest.raises(ValidationError):
            EpochRevocationInvocationV1.model_validate(
                {**_invocation_values(), **changed}
            )


def test_request_digest_binds_every_security_relevant_request_field() -> None:
    original_values = _invocation_values()
    original = EpochRevocationInvocationV1.model_validate(original_values)
    original_digest = epoch_revocation_request_sha256(original)
    changed_commands = (
        {
            "root_id": f"cgroot:{ONE_DIGEST}",
            "expected_root_sha256": ONE_DIGEST,
        },
        {"expected_epoch": 2},
        {"reason": "Stop all delayed work before it executes."},
        {"request_id": "request-revoke-002"},
        {"idempotency_key": "revoke-002"},
    )
    changed_invocations = (
        {"operator_identity": "second-operator@example.test"},
        {"operator_subject": "223456789012345678901"},
    )

    digests = {
        epoch_revocation_request_sha256(
            EpochRevocationInvocationV1.model_validate(
                {
                    **original_values,
                    "command": {**_command_values(), **changed},
                }
            )
        )
        for changed in changed_commands
    }
    digests.update(
        epoch_revocation_request_sha256(
            EpochRevocationInvocationV1.model_validate(
                {**original_values, **changed}
            )
        )
        for changed in changed_invocations
    )

    assert original_digest not in digests
    assert len(digests) == len(changed_commands) + len(changed_invocations)


def test_attempt_identity_does_not_change_the_canonical_request_digest() -> None:
    first_values = _invocation_values()
    second_values = {**first_values, "attempt_id": "cgrevoke-attempt-002"}

    assert epoch_revocation_request_sha256(
        EpochRevocationInvocationV1.model_validate(first_values)
    ) == epoch_revocation_request_sha256(
        EpochRevocationInvocationV1.model_validate(second_values)
    )
