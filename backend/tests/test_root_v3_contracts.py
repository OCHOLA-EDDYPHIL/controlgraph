from __future__ import annotations

import pytest
from pydantic import ValidationError
from root_v2_test_data import make_root_v2_records, make_root_v3_records

from controlgraph_canary.application.authority_store import RootCreationBundle, StoredRecord
from controlgraph_canary.application.root_authority import (
    capability_claims_match_root_authority,
    capability_scope_from_claims,
    inspect_root_authority_bundle,
)
from controlgraph_canary.contracts.base import StrictContractModel
from controlgraph_canary.contracts.codec import (
    ContractError,
    ContractErrorCode,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.models import CapabilityAction, CapabilityClaims
from controlgraph_canary.contracts.root_creation import (
    RolloutRootContentV3,
    RolloutRootV2,
    RolloutRootV3,
    RootCreationResultV1,
    RootCreationResultV2,
    decode_root_creation_result,
)
from controlgraph_canary.contracts.storage import (
    AUTHORITY_STORAGE_DOCUMENT_V1,
    AuthorityStorageDocument,
    AuthorityStorageKind,
)


def test_v3_root_and_result_round_trip_without_changing_historical_decoding() -> None:
    current = make_root_v3_records()
    historical = make_root_v2_records()

    assert decode_contract(canonical_json_bytes(current.root), RolloutRootV3) == current.root
    assert (
        decode_contract(canonical_json_bytes(current.creation_result), RootCreationResultV2)
        == current.creation_result
    )
    assert decode_root_creation_result(
        canonical_json_bytes(current.creation_result)
    ) == current.creation_result
    assert decode_contract(canonical_json_bytes(historical.root), RolloutRootV2) == historical.root
    assert (
        decode_contract(
            canonical_json_bytes(historical.creation_result),
            RootCreationResultV1,
        )
        == historical.creation_result
    )
    assert decode_root_creation_result(
        canonical_json_bytes(historical.creation_result)
    ) == historical.creation_result


@pytest.mark.parametrize(
    ("value", "wrong_type"),
    [
        (make_root_v3_records().root, RolloutRootV2),
        (make_root_v2_records().root, RolloutRootV3),
        (make_root_v3_records().creation_result, RootCreationResultV1),
        (make_root_v2_records().creation_result, RootCreationResultV2),
    ],
)
def test_root_versions_do_not_decode_as_each_other(
    value: StrictContractModel,
    wrong_type: type[StrictContractModel],
) -> None:
    with pytest.raises(ContractError) as error:
        decode_contract(canonical_json_bytes(value), wrong_type)

    assert error.value.code is ContractErrorCode.VERSION_UNSUPPORTED


def test_v3_content_binds_the_exact_v2_health_policy_and_plan_digest() -> None:
    current = make_root_v3_records()
    historical = make_root_v2_records()
    values = current.root.content.model_dump(mode="python")

    with pytest.raises(ValidationError):
        RolloutRootContentV3.model_validate(
            {**values, "health_policy": historical.root.content.health_policy}
        )

    altered_plan = current.root.content.rollout_plan.model_copy(
        update={"health_policy_sha256": "0" * 64}
    )
    with pytest.raises(ValidationError, match="canonical health policy"):
        RolloutRootContentV3.model_validate({**values, "rollout_plan": altered_plan})


def test_result_version_rejects_a_root_from_the_other_family() -> None:
    current = make_root_v3_records()
    historical = make_root_v2_records()

    with pytest.raises(ValidationError):
        RootCreationResultV2.model_validate(
            {
                **current.creation_result.model_dump(mode="python"),
                "root": historical.root,
            }
        )
    with pytest.raises(ValidationError):
        RootCreationResultV1.model_validate(
            {
                **historical.creation_result.model_dump(mode="python"),
                "root": current.root,
            }
        )


def test_internal_bundle_accepts_only_the_two_closed_version_pairs() -> None:
    current = make_root_v3_records()
    historical = make_root_v2_records()

    with pytest.raises(TypeError, match="versions do not match"):
        RootCreationBundle(
            root=StoredRecord(current.root, 0),
            service_claim=StoredRecord(current.service_claim, 0),
            authority=StoredRecord(current.authority, 0),
            lineage_anchor=StoredRecord(current.lineage_anchor, 0),
            signed_evidence=StoredRecord(current.signed_evidence, 0),
            creation_result=StoredRecord(historical.creation_result, 0),
        )


def test_storage_kinds_keep_v3_payloads_out_of_historical_collections() -> None:
    current = make_root_v3_records()
    payload = canonical_json_bytes(current.root).decode("utf-8")
    values = {
        "schema_version": AUTHORITY_STORAGE_DOCUMENT_V1,
        "record_kind": AuthorityStorageKind.ROLLOUT_ROOT_V3,
        "logical_id": current.root.root_id,
        "revision": 0,
        "mutation_id": "mutation-root-v3-001",
        "canonical_payload": payload,
        "payload_sha256": canonical_sha256(current.root),
    }

    assert AuthorityStorageDocument.model_validate(values).record_kind is (
        AuthorityStorageKind.ROLLOUT_ROOT_V3
    )
    with pytest.raises(ValidationError, match="payload is invalid"):
        AuthorityStorageDocument.model_validate(
            {**values, "record_kind": AuthorityStorageKind.ROLLOUT_ROOT_V2}
        )


def test_downstream_authority_accepts_v3_without_widening_the_closed_root_types() -> None:
    current = make_root_v3_records()
    bundle = RootCreationBundle(
        root=StoredRecord(current.root, 0),
        service_claim=StoredRecord(current.service_claim, 0),
        authority=StoredRecord(current.authority, 0),
        lineage_anchor=StoredRecord(current.lineage_anchor, 0),
        signed_evidence=StoredRecord(current.signed_evidence, 0),
        creation_result=StoredRecord(current.creation_result, 0),
    )
    trusted = inspect_root_authority_bundle(
        bundle,
        target=current.root.content.target,
    )

    assert trusted is not None
    assert type(trusted.root) is RolloutRootV3
    root = trusted.root
    plan = root.content.rollout_plan
    bounds = root.content.authority_bounds
    grant = bounds.apply_canary
    claims = CapabilityClaims(
        schema_version="controlgraph.capability-claims/v1",
        capability_id="capability-v3-apply-001",
        issuer=bounds.issuer_identity,
        subject=grant.subject_identity,
        audience=grant.audience,
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        stable_revision=plan.stable_revision,
        candidate_revision=plan.candidate_revision,
        stable_percent=90,
        candidate_percent=10,
        concurrency=None,
        plan_sha256=canonical_sha256(plan),
        provider_etag=root.content.stable_snapshot.provider_etag,
        request_id="request-v3-apply-001",
        idempotency_key="intent-v3-apply-001",
        parent_capability_sha256=None,
        issued_at="2026-08-19T12:02:00Z",
        not_before="2026-08-19T12:02:00Z",
        expires_at="2026-08-19T12:07:00Z",
        signing_algorithm="EC_SIGN_P256_SHA256",
        signing_key_version=bounds.capability_signing_key_version,
    )

    assert capability_claims_match_root_authority(
        claims,
        root,
        trusted.lineage_anchor,
    )
    scope = capability_scope_from_claims(claims, root)
    assert scope.root_sha256 == root.root_sha256
    assert scope.traffic_percent.minimum == scope.traffic_percent.maximum == 10
