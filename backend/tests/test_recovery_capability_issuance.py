from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from functools import cache
from typing import cast

from recovery_v2_test_data import (
    RecoveryV2Bundle,
    make_revoked_v2_recovery_bundle,
    make_unhealthy_recovery_chain,
    make_unhealthy_v3_recovery_bundle,
    make_v2_verified_apply_receipt,
)
from root_v2_support import RootBundle
from root_v2_test_data import make_root_v2_records, make_root_v3_records

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.application.capability_issuance import (
    AuthenticatedIssuancePrincipal,
    CapabilityIssuer,
    CapabilityIssuerConfiguration,
)
from controlgraph_canary.application.signing import (
    PurposeSealedSigner,
    SigningProfile,
)
from controlgraph_canary.contracts.codec import canonical_sha256
from controlgraph_canary.contracts.health_execution import (
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
)
from controlgraph_canary.contracts.models import CapabilityAction, ExecutionReceipt
from controlgraph_canary.contracts.promotion_execution import PromotionHealthChainLocatorV1
from controlgraph_canary.contracts.recovery_execution import (
    RecoveryHealthChainLocatorV1,
    RecoveryIntentV1,
    RecoveryPrestateAttestationV1,
    RevokedV2RecoverySourceV1,
    UnhealthyRecoverySourceV1,
    create_recovery_intent,
)
from controlgraph_canary.contracts.root_creation import (
    RolloutRootV2,
    RolloutRootV3,
    SignedEvidenceEventV1,
)


@cache
def _bundle() -> RecoveryV2Bundle:
    return make_revoked_v2_recovery_bundle()


class _SigningBackend:
    def __init__(self, profile: SigningProfile) -> None:
        self._profile = profile
        self.digests: list[bytes] = []

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    def sign_digest(self, digest: bytes) -> bytes:
        self.digests.append(digest)
        return b"recovery-capability-signature"


class _AuthorityStore:
    def __init__(self, bundle: RecoveryV2Bundle) -> None:
        records = make_root_v2_records()
        assert records.root == bundle.root
        source = cast(RevokedV2RecoverySourceV1, bundle.command.source)
        authority = source.revocation_proof.authority
        self.target = records.root.content.target
        self._bundle = RootBundle(
            root=StoredRecord(records.root, 0),
            service_claim=StoredRecord(records.service_claim, 0),
            authority=StoredRecord(authority, authority.revision),
            lineage_anchor=StoredRecord(records.lineage_anchor, 0),
        )
        self.reads = 0

    async def read_root_creation_bundle(self, root_id: str) -> RootBundle | None:
        self.reads += 1
        if root_id != self._bundle.root.value.root_id:
            return None
        return self._bundle


class _RecoveryRecords:
    def __init__(self, bundle: RecoveryV2Bundle) -> None:
        self.target = bundle.root.content.target
        self._command = bundle.command
        self._intent = StoredRecord(
            create_recovery_intent(
                bundle.command,
                created_at=bundle.authorization.issued_at,
            ),
            0,
        )
        self._receipt = StoredRecord(
            make_v2_verified_apply_receipt(cast(RolloutRootV2, bundle.root)),
            bundle.command.verified_apply_receipt.storage_revision,
        )
        self.intent_reads = 0
        self.receipt_reads = 0
        self.chain_reads = 0

    async def read_recovery_intent(
        self,
        root_sha256: str,
    ) -> StoredRecord[RecoveryIntentV1] | None:
        self.intent_reads += 1
        if root_sha256 != self._command.expected_root_sha256:
            return None
        return self._intent

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        self.receipt_reads += 1
        if idempotency_key != self._command.verified_apply_receipt.idempotency_key:
            return None
        return self._receipt

    async def read_recovery_health_chain(
        self,
        locator: RecoveryHealthChainLocatorV1,
    ) -> None:
        del locator
        self.chain_reads += 1
        return None


class _PrestateVerifier:
    def __init__(self, attestation: RecoveryPrestateAttestationV1) -> None:
        self._attestation = attestation
        self.calls = 0

    @property
    def project_id(self) -> str:
        return self._attestation.result.request.target.project_id

    @property
    def key_version(self) -> str:
        return self._attestation.signing_key_version

    async def verify(self, attestation: RecoveryPrestateAttestationV1) -> None:
        assert attestation == self._attestation
        self.calls += 1


class _RevocationEvidenceVerifier:
    def __init__(self, signed: SignedEvidenceEventV1) -> None:
        self._signed = signed
        self.calls = 0

    @property
    def evidence_key_version(self) -> str:
        return self._signed.signing_key_version

    async def verify(self, signed: SignedEvidenceEventV1) -> None:
        assert signed == self._signed
        self.calls += 1


class _V3AuthorityStore:
    def __init__(self, bundle: RecoveryV2Bundle) -> None:
        records = make_root_v3_records()
        assert records.root == bundle.root
        self.target = records.root.content.target
        self._bundle = RootCreationBundle(
            root=StoredRecord(records.root, 0),
            service_claim=StoredRecord(records.service_claim, 0),
            authority=StoredRecord(records.authority, records.authority.revision),
            lineage_anchor=StoredRecord(records.lineage_anchor, 0),
            signed_evidence=StoredRecord(records.signed_evidence, 0),
            creation_result=StoredRecord(records.creation_result, 0),
        )
        self.reads = 0

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootCreationBundle | None:
        self.reads += 1
        if root_id != self._bundle.root.value.root_id:
            return None
        return self._bundle


class _V3RecoveryRecords:
    def __init__(self, bundle: RecoveryV2Bundle) -> None:
        self.target = bundle.root.content.target
        self._command = bundle.command
        self._chain = make_unhealthy_recovery_chain(cast(RolloutRootV3, bundle.root))
        self._intent = StoredRecord(
            create_recovery_intent(
                bundle.command,
                created_at=bundle.command.source.triggered_at,
            ),
            0,
        )
        self._receipt = StoredRecord(
            self._chain.anchor.apply_receipt,
            bundle.command.verified_apply_receipt.storage_revision,
        )
        self.intent_reads = 0
        self.receipt_reads = 0
        self.chain_reads = 0

    async def read_recovery_intent(
        self,
        root_sha256: str,
    ) -> StoredRecord[RecoveryIntentV1] | None:
        self.intent_reads += 1
        if root_sha256 != self._command.expected_root_sha256:
            return None
        return self._intent

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        self.receipt_reads += 1
        if idempotency_key != self._command.verified_apply_receipt.idempotency_key:
            return None
        return self._receipt

    async def read_recovery_health_chain(
        self,
        locator: RecoveryHealthChainLocatorV1,
    ) -> SignedHealthDecisionChainV1 | None:
        self.chain_reads += 1
        source = cast(UnhealthyRecoverySourceV1, self._command.source)
        if locator != source.health_chain_locator:
            return None
        return self._chain

    async def read_promotion_health_chain(
        self,
        locator: PromotionHealthChainLocatorV1,
    ) -> SignedHealthDecisionChainV1 | None:
        del locator
        return None


class _HealthVerifier:
    def __init__(self, bundle: RecoveryV2Bundle) -> None:
        self._chain = make_unhealthy_recovery_chain(cast(RolloutRootV3, bundle.root))
        self.calls: list[SignedHealthDecisionProofV1] = []

    async def verify(self, signed: SignedHealthDecisionProofV1) -> None:
        assert signed in self._chain.signed_proofs
        self.calls.append(signed)


class _UnusedRevocationEvidenceVerifier:
    def __init__(self, key_version: str) -> None:
        self.evidence_key_version = key_version
        self.calls = 0

    async def verify(self, signed: SignedEvidenceEventV1) -> None:
        del signed
        self.calls += 1
        raise AssertionError("unhealthy V3 recovery cannot use revocation evidence")


def test_recovery_issuance_rereads_all_authority_and_targets_only_recovery() -> None:
    bundle = _bundle()
    authority_store = _AuthorityStore(bundle)
    records = _RecoveryRecords(bundle)
    prestate_verifier = _PrestateVerifier(bundle.prestate_attestation)
    evidence_verifier = _RevocationEvidenceVerifier(
        cast(
            RevokedV2RecoverySourceV1,
            bundle.command.source,
        ).revocation_proof.signed_evidence
    )
    signing_backend = _SigningBackend(
        SigningProfile.capability(
            bundle.root.content.target.project_id,
            bundle.authorization.capability_signing_key_version,
        )
    )
    issuer = CapabilityIssuer(
        store=authority_store,
        signer=PurposeSealedSigner(signing_backend),
        configuration=CapabilityIssuerConfiguration(
            target=bundle.root.content.target,
            handler_audience=bundle.root.content.authority_bounds.executor_audience,
            recovery_handler_audience=bundle.authorization.recovery_audience,
            lifetime_seconds=300,
        ),
        receipt_reader=records,
        recovery_intent_reader=records,
        recovery_health_chain_reader=records,
        recovery_prestate_verifier=prestate_verifier,
        revocation_evidence_verifier=evidence_verifier,
    )

    result = asyncio.run(
        issuer.issue_recovery(
            bundle.issuance_command,
            principal=AuthenticatedIssuancePrincipal(
                identity=(
                    "controlgraph-coordinator@"
                    f"{bundle.root.content.target.project_id}.iam.gserviceaccount.com"
                )
            ),
            now=datetime(2026, 8, 19, 12, 5, 20, tzinfo=UTC),
        )
    )

    claims = result.capability.claims
    assert claims.action is CapabilityAction.RECOVER_STABLE
    assert claims.subject == bundle.authorization.recovery_identity
    assert claims.audience == bundle.authorization.recovery_audience
    assert (claims.stable_percent, claims.candidate_percent) == (100, 0)
    assert claims.concurrency == bundle.authorization.concurrency
    assert claims.provider_etag == bundle.authorization.current_provider_etag
    assert claims.parent_capability_sha256 is None
    assert claims.issued_at == bundle.authorization.issued_at
    assert claims.not_before == bundle.authorization.scheduled_at
    assert claims.expires_at == bundle.authorization.proof_valid_until
    assert result.capability_sha256 == canonical_sha256(result.capability)
    assert len(signing_backend.digests) == 1
    assert authority_store.reads == 2
    assert records.intent_reads == records.receipt_reads == 2
    assert records.chain_reads == 0
    assert prestate_verifier.calls == evidence_verifier.calls == 2


def test_unhealthy_v3_recovery_issuance_replays_chain_and_signs_once() -> None:
    bundle = make_unhealthy_v3_recovery_bundle()
    authority_store = _V3AuthorityStore(bundle)
    records = _V3RecoveryRecords(bundle)
    prestate_verifier = _PrestateVerifier(bundle.prestate_attestation)
    health_verifier = _HealthVerifier(bundle)
    revocation_verifier = _UnusedRevocationEvidenceVerifier(
        bundle.authorization.evidence_signing_key_version
    )
    signing_backend = _SigningBackend(
        SigningProfile.capability(
            bundle.root.content.target.project_id,
            bundle.authorization.capability_signing_key_version,
        )
    )
    issuer = CapabilityIssuer(
        store=authority_store,
        signer=PurposeSealedSigner(signing_backend),
        configuration=CapabilityIssuerConfiguration(
            target=bundle.root.content.target,
            handler_audience=bundle.root.content.authority_bounds.executor_audience,
            recovery_handler_audience=bundle.authorization.recovery_audience,
            lifetime_seconds=300,
        ),
        receipt_reader=records,
        promotion_health_chain_reader=records,
        health_signature_verifier=health_verifier,
        recovery_intent_reader=records,
        recovery_health_chain_reader=records,
        recovery_prestate_verifier=prestate_verifier,
        revocation_evidence_verifier=revocation_verifier,
    )

    result = asyncio.run(
        issuer.issue_recovery(
            bundle.issuance_command,
            principal=AuthenticatedIssuancePrincipal(
                identity=(
                    "controlgraph-coordinator@"
                    f"{bundle.root.content.target.project_id}.iam.gserviceaccount.com"
                )
            ),
            now=datetime(2026, 8, 21, 12, 9, 20, tzinfo=UTC),
        )
    )

    claims = result.capability.claims
    assert claims.action is CapabilityAction.RECOVER_STABLE
    assert claims.subject == bundle.authorization.recovery_identity
    assert claims.audience == bundle.authorization.recovery_audience
    assert (claims.stable_percent, claims.candidate_percent) == (100, 0)
    assert claims.concurrency == bundle.authorization.concurrency
    assert claims.provider_etag == bundle.authorization.current_provider_etag
    assert claims.parent_capability_sha256 is None
    assert result.capability_sha256 == canonical_sha256(result.capability)
    assert len(signing_backend.digests) == 1
    assert authority_store.reads == 2
    assert records.intent_reads == records.receipt_reads == records.chain_reads == 2
    assert health_verifier.calls == [
        *records._chain.signed_proofs,
        *records._chain.signed_proofs,
    ]
    assert prestate_verifier.calls == 2
    assert revocation_verifier.calls == 0
