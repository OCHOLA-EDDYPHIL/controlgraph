from __future__ import annotations

import asyncio
from types import SimpleNamespace

import google_crc32c
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from test_independent_verification import (
    EVIDENCE_KEY_VERSION,
    PROJECT,
    _caller,
    _request,
    _service_with,
    _state,
)

from controlgraph_canary.application.identity import ServiceRole
from controlgraph_canary.application.signing import SigningError
from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.independent_verification import (
    INDEPENDENT_VERIFICATION_PURPOSE,
    P256_SIGNING_ALGORITHM,
    SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
    IndependentVerificationAttestationV1,
    SignedIndependentVerificationEvidenceV1,
    independent_verification_signing_input_sha256,
)
from controlgraph_canary.integrations.google.kms import (
    GoogleKmsIndependentVerificationEvidenceVerifier,
)


class _KmsClient:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self.pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.version_calls = 0
        self.public_calls = 0

    async def get_crypto_key_version(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object:
        self.version_calls += 1
        assert request == {"name": EVIDENCE_KEY_VERSION}
        assert retry is None
        assert timeout == 5.0
        return SimpleNamespace(
            name=EVIDENCE_KEY_VERSION,
            state="ENABLED",
            algorithm="EC_SIGN_P256_SHA256",
        )

    async def get_public_key(
        self,
        request: dict[str, object],
        *,
        retry: object,
        timeout: float,
    ) -> object:
        self.public_calls += 1
        assert request == {"name": EVIDENCE_KEY_VERSION}
        assert retry is None
        assert timeout == 5.0
        return SimpleNamespace(
            name=EVIDENCE_KEY_VERSION,
            algorithm="EC_SIGN_P256_SHA256",
            pem=self.pem,
            pem_crc32c=google_crc32c.value(self.pem.encode("ascii")),
        )


def _signed(
    private_key: ec.EllipticCurvePrivateKey,
) -> SignedIndependentVerificationEvidenceV1:
    service, _, _, _ = _service_with(_state())
    attestation = asyncio.run(service.attest_configuration(_request(), _caller()))
    assert isinstance(attestation, IndependentVerificationAttestationV1)
    evidence = attestation.signing_request.evidence
    signing_input = independent_verification_signing_input_sha256(
        evidence,
        EVIDENCE_KEY_VERSION,
    )
    signature = private_key.sign(
        bytes.fromhex(signing_input),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    return SignedIndependentVerificationEvidenceV1(
        schema_version=SIGNED_INDEPENDENT_VERIFICATION_EVIDENCE_V1,
        evidence=evidence,
        purpose=INDEPENDENT_VERIFICATION_PURPOSE,
        signing_key_version=EVIDENCE_KEY_VERSION,
        signing_algorithm=P256_SIGNING_ALGORITHM,
        payload_sha256=canonical_sha256(evidence),
        signing_input_sha256=signing_input,
        signature=encode_base64url(signature),
    )


def test_kms_verifier_uses_read_only_public_material_for_exact_digest() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    client = _KmsClient(private_key)
    verifier = GoogleKmsIndependentVerificationEvidenceVerifier(
        project_id=PROJECT,
        service_role=ServiceRole.COORDINATOR,
        key_version=EVIDENCE_KEY_VERSION,
        client=client,
    )

    asyncio.run(verifier.verify(_signed(private_key)))

    assert client.version_calls == 1
    assert client.public_calls == 1


def test_kms_verifier_rejects_signature_substitution() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    signed = _signed(private_key)
    other_key = ec.generate_private_key(ec.SECP256R1())
    invalid_signature = other_key.sign(
        bytes.fromhex(signed.signing_input_sha256),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    substituted = signed.model_copy(
        update={"signature": encode_base64url(invalid_signature)}
    )
    verifier = GoogleKmsIndependentVerificationEvidenceVerifier(
        project_id=PROJECT,
        service_role=ServiceRole.COORDINATOR,
        key_version=EVIDENCE_KEY_VERSION,
        client=_KmsClient(private_key),
    )

    with pytest.raises(SigningError):
        asyncio.run(verifier.verify(substituted))


def test_kms_verifier_rejects_payload_digest_substitution() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    signed = _signed(private_key)
    substituted = signed.model_copy(update={"payload_sha256": "0" * 64})
    verifier = GoogleKmsIndependentVerificationEvidenceVerifier(
        project_id=PROJECT,
        service_role=ServiceRole.COORDINATOR,
        key_version=EVIDENCE_KEY_VERSION,
        client=_KmsClient(private_key),
    )

    with pytest.raises(SigningError):
        asyncio.run(verifier.verify(substituted))
