from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from root_v2_test_data import PROJECT_NUMBER, make_root_v2_records, root_v2_target

from controlgraph_canary.application.cloud_run import (
    CloudRunReadyState,
    CloudRunServiceState,
    CloudRunTrafficAllocation,
    CloudRunTrafficStatus,
)
from controlgraph_canary.application.identity import (
    CLASSIFICATION_EVIDENCE_PATH,
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.service_claim_classification import (
    ServiceClaimClassificationError,
    ServiceClaimClassificationErrorCode,
    ServiceClaimClassificationService,
)
from controlgraph_canary.application.service_claim_classification_signing import (
    ClassificationEvidenceSigningService,
)
from controlgraph_canary.application.signing import (
    AsyncPurposeSealedSigner,
    SigningProfile,
)
from controlgraph_canary.contracts.codec import canonical_sha256, encode_base64url
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    SignedEvidenceEventV1,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)
from controlgraph_canary.contracts.service_claim_release import (
    SERVICE_CLAIM_CLASSIFICATION_REQUEST_V1,
    ServiceClaimClassificationRequestV1,
    ServiceClaimClassificationSigningRequestV1,
    service_claim_release_evidence_id,
)
from controlgraph_canary.contracts.storage import ServiceClaimTargetClassification

NOW = datetime(2026, 8, 20, 14, 0, tzinfo=UTC)
COORDINATOR_SUBJECT = "123456789012345678901"
VERIFIER_SUBJECT = "223456789012345678901"


def _audience(role: ServiceRole) -> str:
    return (
        f"https://controlgraph-{role.value.replace('_', '-')}-{PROJECT_NUMBER}"
        ".us-central1.run.app"
    )


def _coordinator_policy() -> RouteAuthenticationPolicy:
    target = root_v2_target()
    return RouteAuthenticationPolicy(
        project_id=target.project_id,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.VERIFIER,
        path=protected_path(ServiceRole.VERIFIER),
        audience=_audience(ServiceRole.VERIFIER),
        caller=CallerBinding(
            role=CallerRole.COORDINATOR,
            email=(
                f"controlgraph-coordinator@{target.project_id}.iam.gserviceaccount.com"
            ),
            subject=COORDINATOR_SUBJECT,
        ),
    )


def _classification_policy() -> RouteAuthenticationPolicy:
    target = root_v2_target()
    return RouteAuthenticationPolicy(
        project_id=target.project_id,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EVIDENCE_WRITER,
        path=CLASSIFICATION_EVIDENCE_PATH,
        audience=_audience(ServiceRole.EVIDENCE_WRITER),
        caller=CallerBinding(
            role=CallerRole.VERIFIER,
            email=(
                f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com"
            ),
            subject=VERIFIER_SUBJECT,
        ),
    )


def _context(role: CallerRole) -> AuthenticationContext:
    target = root_v2_target()
    email, subject, audience = {
        CallerRole.COORDINATOR: (
            f"controlgraph-coordinator@{target.project_id}.iam.gserviceaccount.com",
            COORDINATOR_SUBJECT,
            _audience(ServiceRole.VERIFIER),
        ),
        CallerRole.VERIFIER: (
            f"controlgraph-verifier@{target.project_id}.iam.gserviceaccount.com",
            VERIFIER_SUBJECT,
            _audience(ServiceRole.EVIDENCE_WRITER),
        ),
    }[role]
    return AuthenticationContext(
        role=role,
        email=email,
        subject=subject,
        issuer="https://accounts.google.com",
        audience=audience,
        issued_at=int(NOW.timestamp()) - 60,
        expires_at=int(NOW.timestamp()) + 600,
    )


def _request() -> ServiceClaimClassificationRequestV1:
    records = make_root_v2_records()
    claim = records.service_claim
    request_sha256 = "a" * 64
    return ServiceClaimClassificationRequestV1(
        schema_version=SERVICE_CLAIM_CLASSIFICATION_REQUEST_V1,
        root_id=records.root.root_id,
        root_sha256=records.root.root_sha256,
        target=claim.target,
        release_request_sha256=request_sha256,
        classification_evidence_id=service_claim_release_evidence_id(
            request_sha256,
            "classification",
        ),
        previous_evidence_sequence=2,
        previous_event_sha256="b" * 64,
        stable_revision=claim.stable_revision,
        candidate_revision=claim.candidate_revision,
        concurrency=records.root.content.authority_bounds.concurrency,
        expected_classification=(
            ServiceClaimTargetClassification.CANDIDATE_PROMOTED
        ),
        expected_target_configuration_sha256=(
            claim.candidate_target_configuration_sha256
        ),
        minimum_service_generation_exclusive=claim.baseline_service_generation,
        fenced_epoch=2,
        fenced_authority_revision=1,
        request_id="request-release-001",
    )


def _service_state(
    request: ServiceClaimClassificationRequestV1,
    **changes: object,
) -> CloudRunServiceState:
    values: dict[str, object] = {
        "target": request.target,
        "resource_name": (
            f"projects/{request.target.project_id}/locations/{request.target.region}/"
            f"services/{request.target.service_name}"
        ),
        "uid": "service-uid-001",
        "etag": "provider-etag-22",
        "generation": request.minimum_service_generation_exclusive + 1,
        "observed_generation": request.minimum_service_generation_exclusive + 1,
        "reconciling": False,
        "ready_state": CloudRunReadyState.READY,
        "latest_ready_revision": request.candidate_revision,
        "latest_created_revision": request.candidate_revision,
        "template_revision": request.candidate_revision,
        "template_concurrency": request.concurrency,
        "traffic": (
            CloudRunTrafficAllocation(
                revision=request.stable_revision,
                percent=0,
                tag="stable",
            ),
            CloudRunTrafficAllocation(
                revision=request.candidate_revision,
                percent=100,
                tag="candidate",
            ),
        ),
        "traffic_statuses": (
            CloudRunTrafficStatus(
                revision=request.stable_revision,
                percent=0,
                tag="stable",
                uri=None,
            ),
            CloudRunTrafficStatus(
                revision=request.candidate_revision,
                percent=100,
                tag="candidate",
                uri="https://candidate.example.test",
            ),
        ),
        "uri": "https://service.example.test",
    }
    values.update(changes)
    return CloudRunServiceState(**values)  # type: ignore[arg-type]


class _Reader:
    def __init__(self, request: ServiceClaimClassificationRequestV1) -> None:
        self.target = request.target
        self.reader_identity = (
            f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
        )
        self.state = _service_state(request)
        self.calls = 0

    async def read_service(self) -> CloudRunServiceState:
        self.calls += 1
        return self.state


def _signed(request: ServiceClaimClassificationSigningRequestV1) -> SignedEvidenceEventV1:
    key = make_root_v2_records().root.content.evidence_signing_key_version
    return SignedEvidenceEventV1(
        schema_version=SIGNED_EVIDENCE_EVENT_V1,
        event=request.event,
        purpose="EVIDENCE",
        signing_key_version=key,
        signing_algorithm="EC_SIGN_P256_SHA256",
        payload_sha256=evidence_payload_sha256(request.event),
        signing_input_sha256=evidence_signing_input_sha256(request.event, key),
        signature=encode_base64url(b"verifier-authenticated-classification"),
    )


class _EvidenceClient:
    def __init__(self) -> None:
        self.requests: list[ServiceClaimClassificationSigningRequestV1] = []

    async def sign(
        self,
        request: ServiceClaimClassificationSigningRequestV1,
    ) -> SignedEvidenceEventV1:
        self.requests.append(request)
        return _signed(request)


def test_verifier_fresh_read_builds_exact_actor_and_chain_bound_attestation() -> None:
    request = _request()
    reader = _Reader(request)
    evidence = _EvidenceClient()
    service = ServiceClaimClassificationService(
        authentication_policy=_coordinator_policy(),
        reader_factory=lambda _: reader,
        evidence_client=evidence,
        clock=lambda: NOW,
    )

    attestation = asyncio.run(
        service.classify(request, _context(CallerRole.COORDINATOR))
    )

    assert reader.calls == 1
    assert evidence.requests == [attestation.signing_request]
    signing_request = attestation.signing_request
    assert signing_request.result.request == request
    assert signing_request.event.actor == (
        f"controlgraph-verifier@{request.target.project_id}.iam.gserviceaccount.com"
    )
    assert signing_request.event.sequence == request.previous_evidence_sequence + 1
    assert signing_request.event.previous_event_sha256 == request.previous_event_sha256
    assert signing_request.event.subject_sha256 == canonical_sha256(
        signing_request.subject
    )
    assert attestation.signed_evidence.event == signing_request.event


@pytest.mark.parametrize(
    "change",
    [
        {"reconciling": True},
        {"observed_generation": 7},
        {"template_concurrency": 9},
        {
            "traffic": (
                CloudRunTrafficAllocation(
                    revision=make_root_v2_records().service_claim.stable_revision,
                    percent=100,
                    tag="stable",
                ),
            )
        },
    ],
)
def test_verifier_rejects_nonexact_or_stale_provider_state(
    change: dict[str, object],
) -> None:
    request = _request()
    reader = _Reader(request)
    reader.state = _service_state(request, **change)
    evidence = _EvidenceClient()
    service = ServiceClaimClassificationService(
        authentication_policy=_coordinator_policy(),
        reader_factory=lambda _: reader,
        evidence_client=evidence,
        clock=lambda: NOW,
    )

    with pytest.raises(ServiceClaimClassificationError) as failure:
        asyncio.run(service.classify(request, _context(CallerRole.COORDINATOR)))

    assert failure.value.code is ServiceClaimClassificationErrorCode.TARGET_MISMATCH
    assert evidence.requests == []


class _DigestBackend:
    def __init__(self) -> None:
        self.profile = SigningProfile.evidence(
            root_v2_target().project_id,
            make_root_v2_records().root.content.evidence_signing_key_version,
        )
        self.calls: list[bytes] = []

    async def sign_digest(self, digest: bytes) -> bytes:
        self.calls.append(digest)
        return b"classification-only-signature"


def _classification_signing_request() -> ServiceClaimClassificationSigningRequestV1:
    request = _request()
    reader = _Reader(request)
    evidence = _EvidenceClient()
    service = ServiceClaimClassificationService(
        authentication_policy=_coordinator_policy(),
        reader_factory=lambda _: reader,
        evidence_client=evidence,
        clock=lambda: NOW,
    )
    asyncio.run(service.classify(request, _context(CallerRole.COORDINATOR)))
    return evidence.requests[0]


def test_classification_signer_requires_verifier_identity_equal_to_event_actor() -> None:
    backend = _DigestBackend()
    service = ClassificationEvidenceSigningService(
        project_id=root_v2_target().project_id,
        authentication_policy=_classification_policy(),
        signer=AsyncPurposeSealedSigner(backend),
    )
    request = _classification_signing_request()

    signed = asyncio.run(service.sign(request, _context(CallerRole.VERIFIER)))

    assert signed.event == request.event
    assert len(backend.calls) == 1

    with pytest.raises(ServiceClaimClassificationError) as failure:
        asyncio.run(service.sign(request, _context(CallerRole.COORDINATOR)))
    assert failure.value.code is ServiceClaimClassificationErrorCode.CALLER_DENIED
    assert len(backend.calls) == 1


def test_classification_signer_rejects_actor_substitution_before_kms() -> None:
    backend = _DigestBackend()
    service = ClassificationEvidenceSigningService(
        project_id=root_v2_target().project_id,
        authentication_policy=_classification_policy(),
        signer=AsyncPurposeSealedSigner(backend),
    )
    request = _classification_signing_request().model_copy(
        update={
            "event": _classification_signing_request().event.model_copy(
                update={"actor": "controlgraph.coordinator/v1"}
            )
        }
    )

    with pytest.raises(ServiceClaimClassificationError) as failure:
        asyncio.run(service.sign(request, _context(CallerRole.VERIFIER)))

    assert failure.value.code is ServiceClaimClassificationErrorCode.CALLER_DENIED
    assert backend.calls == []
