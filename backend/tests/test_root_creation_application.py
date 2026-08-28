from dataclasses import replace

import pytest
from pydantic import ValidationError

from controlgraph_canary.application.candidate_revision import (
    CandidateRevisionAttestation,
)
from controlgraph_canary.application.root_creation import (
    RootCreationConfiguration,
    build_unsigned_root_creation,
    complete_root_creation,
)
from controlgraph_canary.contracts.codec import (
    canonical_sha256,
    encode_base64url,
)
from controlgraph_canary.contracts.health import (
    RolloutHealthPolicyV2,
    create_rollout_health_policy_v2,
)
from controlgraph_canary.contracts.models import (
    StableSnapshot,
    TargetBinding,
    TrafficAllocation,
)
from controlgraph_canary.contracts.root_creation import (
    ROOT_CREATION_COMMAND_V1,
    SIGNED_EVIDENCE_EVENT_V1,
    RolloutRootV3,
    RootCreationCommandV1,
    SignedEvidenceEventV1,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)

PROJECT = "controlgraph-canary-a1b2c3"
PROJECT_NUMBER = "123456789012"
SERVICE = "controlgraph-reference-target"
STABLE = f"{SERVICE}-stable-v18"
CANDIDATE = f"{SERVICE}-candidate-v18"
CAPABILITY_KEY = (
    f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)
EVIDENCE_KEY = (
    f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/evidence-signing/cryptoKeyVersions/1"
)
STABLE_DIGEST = "1" * 64
CANDIDATE_DIGEST = "2" * 64


def _target() -> TargetBinding:
    return TargetBinding(
        schema_version="controlgraph.target-binding/v1",
        project_id=PROJECT,
        region="us-central1",
        environment="nonprod",
        service_name=SERVICE,
    )


def _policy() -> RolloutHealthPolicyV2:
    return create_rollout_health_policy_v2()


def _configuration() -> RootCreationConfiguration:
    target = _target()
    return RootCreationConfiguration(
        target=target,
        verifier_identity=(
            f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"
        ),
        candidate_revision=CANDIDATE,
        candidate_revision_configuration_sha256=CANDIDATE_DIGEST,
        concurrency=8,
        health_policy=_policy(),
        capability_signing_key_version=CAPABILITY_KEY,
        evidence_signing_key_version=EVIDENCE_KEY,
        issuer_identity=f"controlgraph-issuer@{PROJECT}.iam.gserviceaccount.com",
        executor_identity=f"controlgraph-executor@{PROJECT}.iam.gserviceaccount.com",
        recovery_identity=f"controlgraph-recovery@{PROJECT}.iam.gserviceaccount.com",
        executor_audience=(
            f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        recovery_audience=(
            f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        maximum_capability_lifetime_seconds=600,
        operator_identity="operator@example.test",
        operator_subject="123456789012345678901",
    )


def _snapshot(*, captured_at: str = "2026-08-19T12:04:59Z") -> StableSnapshot:
    target = _target()
    return StableSnapshot(
        schema_version="controlgraph.stable-snapshot/v1",
        target=target,
        stable_revision=STABLE,
        traffic=(TrafficAllocation(revision=STABLE, percent=100),),
        concurrency=8,
        service_generation=7,
        provider_etag="stable-etag-7",
        configuration_sha256="0" * 64,
        stable_revision_configuration_sha256=STABLE_DIGEST,
        captured_at=captured_at,
        captured_by=(
            f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"
        ),
    )


def _candidate(
    *,
    captured_at: str = "2026-08-19T12:04:58Z",
) -> CandidateRevisionAttestation:
    target = _target()
    return CandidateRevisionAttestation(
        target=target,
        candidate_revision=CANDIDATE,
        configuration_sha256=CANDIDATE_DIGEST,
        generation=9,
        etag="candidate-etag-9",
        concurrency=8,
        reader_identity=(
            f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"
        ),
        captured_at=captured_at,
    )


def _command(*, request_id: str = "request-root-001") -> RootCreationCommandV1:
    return RootCreationCommandV1(
        schema_version=ROOT_CREATION_COMMAND_V1,
        request_id=request_id,
        idempotency_key="root-create-001",
        expected_stable_snapshot=_snapshot(captured_at="2026-08-19T12:04:57Z"),
    )


def _unsigned(
    *,
    command: RootCreationCommandV1 | None = None,
    stable_snapshot: StableSnapshot | None = None,
    candidate_revision: CandidateRevisionAttestation | None = None,
):
    return build_unsigned_root_creation(
        command=command or _command(),
        operator_identity="operator@example.test",
        operator_subject="123456789012345678901",
        stable_snapshot=stable_snapshot or _snapshot(),
        candidate_revision=candidate_revision or _candidate(),
        configuration=_configuration(),
        created_at="2026-08-19T12:05:00Z",
    )


def _signed(unsigned=None) -> SignedEvidenceEventV1:
    value = unsigned or _unsigned()
    event = value.evidence_event
    return SignedEvidenceEventV1(
        schema_version=SIGNED_EVIDENCE_EVENT_V1,
        event=event,
        purpose="EVIDENCE",
        signing_key_version=EVIDENCE_KEY,
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=evidence_payload_sha256(event),
        signing_input_sha256=evidence_signing_input_sha256(event, EVIDENCE_KEY),
        signature=encode_base64url(b"synthetic-p256-signature"),
    )


def test_builds_one_complete_content_addressed_root_bundle() -> None:
    unsigned = _unsigned()
    artifacts = complete_root_creation(unsigned, _signed(unsigned))

    root = artifacts.root
    plan = root.content.rollout_plan
    assert type(root) is RolloutRootV3
    assert type(root.content.health_policy) is RolloutHealthPolicyV2
    assert root.root_sha256 == canonical_sha256(root.content)
    assert root.root_id == f"cgroot:{root.root_sha256}"
    assert plan.stable_revision == STABLE
    assert plan.candidate_revision == CANDIDATE
    assert (plan.stable_percent, plan.candidate_percent) == (90, 10)
    assert plan.candidate_revision_configuration_sha256 == CANDIDATE_DIGEST
    assert artifacts.service_claim.root_sha256 == root.root_sha256
    assert artifacts.service_claim.operator_owner == "operator@example.test"
    assert artifacts.initial_authority.current_epoch == 1
    assert artifacts.initial_authority.changed_by == "operator@example.test"
    assert artifacts.lineage_anchor.root_sha256 == root.root_sha256
    assert artifacts.creation_result.outcome == "CREATED"
    assert artifacts.creation_result.signed_evidence == artifacts.signed_evidence


@pytest.mark.parametrize(
    ("snapshot_time", "candidate_time"),
    [
        ("2026-08-19T11:59:59Z", "2026-08-19T11:59:58Z"),
        ("2026-08-19T12:04:57Z", "2026-08-19T12:04:58Z"),
        ("2026-08-19T12:05:01Z", "2026-08-19T12:04:58Z"),
    ],
)
def test_rejects_stale_reordered_or_future_verifier_state(
    snapshot_time: str,
    candidate_time: str,
) -> None:
    with pytest.raises(ValueError, match="fresh state"):
        _unsigned(
            stable_snapshot=_snapshot(captured_at=snapshot_time),
            candidate_revision=_candidate(captured_at=candidate_time),
        )


def test_rejects_operator_and_candidate_substitution() -> None:
    with pytest.raises(ValueError, match="operator"):
        build_unsigned_root_creation(
            command=_command(),
            operator_identity="other.operator@example.test",
            operator_subject="123456789012345678901",
            stable_snapshot=_snapshot(),
            candidate_revision=_candidate(),
            configuration=_configuration(),
            created_at="2026-08-19T12:05:00Z",
        )

    changed_candidate = replace(
        _candidate(),
        configuration_sha256="3" * 64,
    )
    with pytest.raises(ValueError, match="fresh state"):
        _unsigned(candidate_revision=changed_candidate)


def test_rejects_signed_evidence_for_another_event() -> None:
    unsigned = _unsigned()
    other = _unsigned(command=_command(request_id="request-root-002"))

    with pytest.raises(ValueError, match="does not match"):
        complete_root_creation(unsigned, _signed(other))


def test_configuration_and_command_fail_closed_before_construction() -> None:
    with pytest.raises(ValueError, match="purpose boundary"):
        replace(
            _configuration(),
            evidence_signing_key_version=CAPABILITY_KEY,
        )
    with pytest.raises(ValueError, match="operator"):
        replace(
            _configuration(),
            operator_identity=f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com",
        )
    with pytest.raises(ValidationError):
        RootCreationCommandV1.model_validate(
            {
                "schema_version": ROOT_CREATION_COMMAND_V1,
                "request_id": "request-root-001",
                "idempotency_key": "root-create-001",
                "expected_stable_snapshot": _snapshot(),
                "operator_identity": "other.operator@example.test",
            }
        )
