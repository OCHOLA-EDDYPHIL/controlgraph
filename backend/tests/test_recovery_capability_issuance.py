from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from functools import cache
from typing import cast

import pytest
from health_execution_test_data import make_verified_apply_receipt
from recovery_v2_test_data import (
    RecoveryV2Bundle,
    make_revoked_v2_recovery_bundle,
    make_revoked_v3_recovery_bundle,
    make_unhealthy_recovery_chain,
    make_unhealthy_v3_recovery_bundle,
    make_v2_verified_apply_receipt,
)
from root_v2_support import RootBundle
from root_v2_test_data import make_root_v2_records, make_root_v3_records

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.application.capability_issuance import (
    AuthenticatedIssuancePrincipal,
    CapabilityIssuanceError,
    CapabilityIssuanceErrorCode,
    CapabilityIssuer,
    CapabilityIssuerConfiguration,
)
from controlgraph_canary.application.recovery_execution import (
    RecoveryExecutionError,
    RecoveryExecutionErrorCode,
    StoredRecoveryAuthorizationResolver,
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
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EpochAuthorityRecord,
    ExecutionReceipt,
)
from controlgraph_canary.contracts.promotion_execution import PromotionHealthChainLocatorV1
from controlgraph_canary.contracts.recovery_execution import (
    RECOVER_CAPTURED_STABLE,
    RecoveryHealthChainLocatorV1,
    RecoveryIntentV1,
    RecoveryPrestateAttestationV1,
    RevokedV2RecoverySourceV1,
    RevokedV3RecoverySourceV1,
    UnhealthyRecoverySourceV1,
    create_recovery_apply_receipt_locator,
    create_recovery_intent,
    create_revoked_v3_recovery_command,
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
    def __init__(
        self,
        signed: SignedEvidenceEventV1,
        *,
        evidence_key_version: str | None = None,
        fail: bool = False,
    ) -> None:
        self._signed = signed
        self._evidence_key_version = evidence_key_version or signed.signing_key_version
        self._fail = fail
        self.calls = 0

    @property
    def evidence_key_version(self) -> str:
        return self._evidence_key_version

    async def verify(self, signed: SignedEvidenceEventV1) -> None:
        assert signed == self._signed
        self.calls += 1
        if self._fail:
            raise ValueError("synthetic revocation signature failure")


class _V3AuthorityStore:
    def __init__(
        self,
        bundle: RecoveryV2Bundle,
        *,
        authority: EpochAuthorityRecord | None = None,
        second_authority: EpochAuthorityRecord | None = None,
    ) -> None:
        records = make_root_v3_records()
        assert records.root == bundle.root
        self.target = records.root.content.target
        selected_authority = authority or (
            bundle.command.source.revocation_proof.authority
            if type(bundle.command.source) is RevokedV3RecoverySourceV1
            else records.authority
        )
        self._bundle = RootCreationBundle(
            root=StoredRecord(records.root, 0),
            service_claim=StoredRecord(records.service_claim, 0),
            authority=StoredRecord(selected_authority, selected_authority.revision),
            lineage_anchor=StoredRecord(records.lineage_anchor, 0),
            signed_evidence=StoredRecord(records.signed_evidence, 0),
            creation_result=StoredRecord(records.creation_result, 0),
        )
        self._second_authority = second_authority
        self.reads = 0

    async def read_root_creation_bundle(
        self,
        root_id: str,
    ) -> RootCreationBundle | None:
        self.reads += 1
        if root_id != self._bundle.root.value.root_id:
            return None
        if self.reads > 1 and self._second_authority is not None:
            authority = self._second_authority
            return RootCreationBundle(
                root=self._bundle.root,
                service_claim=self._bundle.service_claim,
                authority=StoredRecord(authority, authority.revision),
                lineage_anchor=self._bundle.lineage_anchor,
                signed_evidence=self._bundle.signed_evidence,
                creation_result=self._bundle.creation_result,
            )
        return self._bundle


class _V3RecoveryRecords:
    def __init__(
        self,
        bundle: RecoveryV2Bundle,
        *,
        source_receipt: ExecutionReceipt | None = None,
    ) -> None:
        self.target = bundle.root.content.target
        self._command = bundle.command
        self._chain = (
            None
            if type(bundle.command.source) is RevokedV3RecoverySourceV1
            else make_unhealthy_recovery_chain(cast(RolloutRootV3, bundle.root))
        )
        self._intent = StoredRecord(
            create_recovery_intent(
                bundle.command,
                created_at=bundle.command.source.triggered_at,
            ),
            0,
        )
        selected_receipt = source_receipt or (
            make_verified_apply_receipt(cast(RolloutRootV3, bundle.root))
            if self._chain is None
            else self._chain.anchor.apply_receipt
        )
        self._receipt = StoredRecord(
            selected_receipt,
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
        if self._chain is None:
            return None
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


class _UnusedHealthVerifier:
    def __init__(self, project_id: str) -> None:
        self.project_id = project_id
        self.calls = 0

    async def verify(self, signed: SignedHealthDecisionProofV1) -> None:
        del signed
        self.calls += 1
        raise AssertionError("revoked V3 recovery cannot use health evidence")


class _PrestateEvaluator:
    def __init__(self, attestation: RecoveryPrestateAttestationV1) -> None:
        self._attestation = attestation
        self.calls = 0

    async def evaluate(self, request: object) -> RecoveryPrestateAttestationV1:
        assert request == self._attestation.result.request
        self.calls += 1
        return self._attestation


def _later_authority(bundle: RecoveryV2Bundle) -> EpochAuthorityRecord:
    source = cast(RevokedV3RecoverySourceV1, bundle.command.source)
    values = source.revocation_proof.authority.model_dump(mode="python")
    values.update(
        current_epoch=source.epoch + 1,
        previous_epoch=source.epoch,
        revision=source.epoch,
        changed_at="2026-08-21T12:08:00Z",
    )
    return EpochAuthorityRecord.model_validate(values)


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


def test_revoked_v3_recovery_issuance_replays_operator_proof_and_signs_once() -> None:
    bundle = make_revoked_v3_recovery_bundle()
    authority_store = _V3AuthorityStore(bundle)
    records = _V3RecoveryRecords(bundle)
    prestate_verifier = _PrestateVerifier(bundle.prestate_attestation)
    source = cast(RevokedV3RecoverySourceV1, bundle.command.source)
    evidence_verifier = _RevocationEvidenceVerifier(source.revocation_proof.signed_evidence)
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
            now=datetime(2026, 8, 21, 12, 9, 20, tzinfo=UTC),
        )
    )

    claims = result.capability.claims
    assert claims.action is CapabilityAction.RECOVER_STABLE
    assert claims.subject == bundle.authorization.recovery_identity
    assert (claims.stable_percent, claims.candidate_percent) == (100, 0)
    assert claims.stable_revision == bundle.root.content.stable_snapshot.stable_revision
    assert claims.concurrency == bundle.root.content.stable_snapshot.concurrency
    assert len(signing_backend.digests) == 1
    assert authority_store.reads == 2
    assert records.intent_reads == records.receipt_reads == 2
    assert records.chain_reads == 0
    assert prestate_verifier.calls == evidence_verifier.calls == 2


def _stored_v3_resolver(
    bundle: RecoveryV2Bundle,
    *,
    authority_store: _V3AuthorityStore | None = None,
    records: _V3RecoveryRecords | None = None,
    evidence_verifier: _RevocationEvidenceVerifier | None = None,
) -> tuple[
    StoredRecoveryAuthorizationResolver,
    _V3AuthorityStore,
    _V3RecoveryRecords,
    _PrestateEvaluator,
    _PrestateVerifier,
    _RevocationEvidenceVerifier,
]:
    source = cast(RevokedV3RecoverySourceV1, bundle.command.source)
    selected_authority_store = authority_store or _V3AuthorityStore(bundle)
    selected_records = records or _V3RecoveryRecords(bundle)
    selected_evidence_verifier = evidence_verifier or _RevocationEvidenceVerifier(
        source.revocation_proof.signed_evidence
    )
    evaluator = _PrestateEvaluator(bundle.prestate_attestation)
    prestate_verifier = _PrestateVerifier(bundle.prestate_attestation)
    resolver = StoredRecoveryAuthorizationResolver(
        target=bundle.root.content.target,
        root_reader=selected_authority_store,
        receipt_reader=selected_records,
        intent_reader=selected_records,
        health_chain_reader=selected_records,
        health_signature_verifier=_UnusedHealthVerifier(
            bundle.root.content.target.project_id
        ),
        revocation_evidence_verifier=selected_evidence_verifier,
        prestate_evaluator=evaluator,
        prestate_signature_verifier=prestate_verifier,
    )
    return (
        resolver,
        selected_authority_store,
        selected_records,
        evaluator,
        prestate_verifier,
        selected_evidence_verifier,
    )


def test_revoked_v3_resolver_replays_proof_and_fresh_prestate_twice() -> None:
    bundle = make_revoked_v3_recovery_bundle()
    resolver, authority_store, records, evaluator, prestate_verifier, evidence_verifier = (
        _stored_v3_resolver(bundle)
    )

    authorization = asyncio.run(
        resolver.resolve(
            bundle.command,
            now=datetime(2026, 8, 21, 12, 9, 10, tzinfo=UTC),
        )
    )

    assert authorization == bundle.authorization
    assert authority_store.reads == 2
    assert records.intent_reads == records.receipt_reads == 2
    assert records.chain_reads == 0
    assert evaluator.calls == prestate_verifier.calls == 1
    assert evidence_verifier.calls == 2


def test_revoked_v3_resolver_denies_noncurrent_proof_before_prestate() -> None:
    bundle = make_revoked_v3_recovery_bundle()
    source = cast(RevokedV3RecoverySourceV1, bundle.command.source)
    values = source.revocation_proof.authority.model_dump(mode="python")
    values["changed_by"] = "other-operator@example.test"
    mismatched = EpochAuthorityRecord.model_validate(values)
    resolver, _, _, evaluator, _, evidence_verifier = _stored_v3_resolver(
        bundle,
        authority_store=_V3AuthorityStore(bundle, authority=mismatched),
    )

    with pytest.raises(RecoveryExecutionError) as denied:
        asyncio.run(
            resolver.resolve(
                bundle.command,
                now=datetime(2026, 8, 21, 12, 9, 10, tzinfo=UTC),
            )
        )

    assert denied.value.code is RecoveryExecutionErrorCode.TRIGGER_INVALID
    assert evaluator.calls == evidence_verifier.calls == 0


def test_revoked_v3_resolver_denies_later_authority_before_prestate() -> None:
    bundle = make_revoked_v3_recovery_bundle()
    resolver, _, _, evaluator, _, evidence_verifier = _stored_v3_resolver(
        bundle,
        authority_store=_V3AuthorityStore(
            bundle,
            authority=_later_authority(bundle),
        ),
    )

    with pytest.raises(RecoveryExecutionError) as denied:
        asyncio.run(
            resolver.resolve(
                bundle.command,
                now=datetime(2026, 8, 21, 12, 9, 10, tzinfo=UTC),
            )
        )

    assert denied.value.code is RecoveryExecutionErrorCode.TRUSTED_STATE_INVALID
    assert evaluator.calls == evidence_verifier.calls == 0


def test_revoked_v3_resolver_denies_apply_receipt_after_revocation() -> None:
    bundle = make_revoked_v3_recovery_bundle()
    source = cast(RevokedV3RecoverySourceV1, bundle.command.source)
    late_receipt = make_verified_apply_receipt(
        cast(RolloutRootV3, bundle.root),
        updated_at="2026-08-21T12:05:01Z",
    )
    late_command = create_revoked_v3_recovery_command(
        root=cast(RolloutRootV3, bundle.root),
        revocation_proof=source.revocation_proof,
        verified_apply_receipt=create_recovery_apply_receipt_locator(
            late_receipt,
            storage_revision=2,
        ),
        request_id=bundle.command.request_id,
        idempotency_key=bundle.command.idempotency_key,
        scheduled_at=bundle.command.scheduled_at,
        confirmation=RECOVER_CAPTURED_STABLE,
    )
    late_bundle = replace(bundle, command=late_command)
    resolver, _, _, evaluator, _, evidence_verifier = _stored_v3_resolver(
        late_bundle,
        records=_V3RecoveryRecords(late_bundle, source_receipt=late_receipt),
    )

    with pytest.raises(RecoveryExecutionError) as denied:
        asyncio.run(
            resolver.resolve(
                late_command,
                now=datetime(2026, 8, 21, 12, 9, 10, tzinfo=UTC),
            )
        )

    assert denied.value.code is RecoveryExecutionErrorCode.TRIGGER_INVALID
    assert evaluator.calls == 0
    assert evidence_verifier.calls == 0


@pytest.mark.parametrize("failure", ["key", "signature"])
def test_revoked_v3_resolver_denies_untrusted_revocation_evidence(
    failure: str,
) -> None:
    bundle = make_revoked_v3_recovery_bundle()
    source = cast(RevokedV3RecoverySourceV1, bundle.command.source)
    verifier = _RevocationEvidenceVerifier(
        source.revocation_proof.signed_evidence,
        evidence_key_version=(
            bundle.root.content.authority_bounds.capability_signing_key_version
            if failure == "key"
            else None
        ),
        fail=failure == "signature",
    )
    resolver, _, _, evaluator, _, selected_verifier = _stored_v3_resolver(
        bundle,
        evidence_verifier=verifier,
    )

    with pytest.raises(RecoveryExecutionError) as denied:
        asyncio.run(
            resolver.resolve(
                bundle.command,
                now=datetime(2026, 8, 21, 12, 9, 10, tzinfo=UTC),
            )
        )

    assert denied.value.code is RecoveryExecutionErrorCode.TRIGGER_INVALID
    assert evaluator.calls == 0
    assert selected_verifier.calls == (0 if failure == "key" else 1)


def test_revoked_v3_issuance_denies_authority_change_on_second_read() -> None:
    bundle = make_revoked_v3_recovery_bundle()
    source = cast(RevokedV3RecoverySourceV1, bundle.command.source)
    authority_store = _V3AuthorityStore(
        bundle,
        second_authority=_later_authority(bundle),
    )
    records = _V3RecoveryRecords(bundle)
    prestate_verifier = _PrestateVerifier(bundle.prestate_attestation)
    evidence_verifier = _RevocationEvidenceVerifier(source.revocation_proof.signed_evidence)
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

    with pytest.raises(CapabilityIssuanceError) as denied:
        asyncio.run(
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

    assert denied.value.code is CapabilityIssuanceErrorCode.EXPECTED_STATE_MISMATCH
    assert authority_store.reads == 2
    assert len(signing_backend.digests) == 1


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
    assert records._chain is not None
    assert health_verifier.calls == [
        *records._chain.signed_proofs,
        *records._chain.signed_proofs,
    ]
    assert prestate_verifier.calls == 2
    assert revocation_verifier.calls == 0
