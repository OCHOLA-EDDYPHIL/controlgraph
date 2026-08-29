from __future__ import annotations

import asyncio
import gc
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi.testclient import TestClient
from health_execution_test_data import make_observation, make_signed_proof
from pydantic import ValidationError
from root_v2_test_data import PROJECT, PROJECT_NUMBER, RootV3Records, make_root_v3_records
from test_m2_firestore_authority_store import _FakeClient, _FakeTransactionRunner

from controlgraph_canary.application.authority_store import (
    AuthorityStoreConflict,
    AuthorityStoreCorruptRecord,
    AuthorityStoreOutcomeUnknown,
    AuthorityStoreUnavailable,
    ReceiptClaimCreated,
    StoredRecord,
)
from controlgraph_canary.application.canary_execution import (
    CanaryExecutionError,
    CanaryExecutionErrorCode,
    CapabilityIssuanceService,
)
from controlgraph_canary.application.capability_issuance import (
    MIN_PROMOTION_EXECUTION_MARGIN_SECONDS,
    AuthenticatedIssuancePrincipal,
    CapabilityIssuanceError,
    CapabilityIssuanceErrorCode,
    CapabilityIssuer,
    CapabilityIssuerConfiguration,
    PromotionCapabilityIssuanceRequestV2,
)
from controlgraph_canary.application.capability_verification import (
    CapabilityVerifier,
    CapabilityVerifierConfiguration,
)
from controlgraph_canary.application.cloud_run import (
    rollout_root_v3_target_configuration_sha256,
)
from controlgraph_canary.application.execution import (
    FinalMutationGate,
    MutationPermit,
)
from controlgraph_canary.application.health_evaluation import (
    derive_next_health_evaluation_state,
    evaluate_health_observation,
    initial_health_evaluation_state,
)
from controlgraph_canary.application.identity import (
    AuthenticationContext,
    CallerBinding,
    CallerRole,
    RouteAuthenticationPolicy,
    ServiceRole,
    protected_path,
)
from controlgraph_canary.application.promotion_execution import (
    ApiPromotionClient,
    CoordinatorPromotionCapabilityClient,
    CoordinatorPromotionRelay,
    PromotionRolloutCoordinator,
    StoredPromotionAuthorizationResolver,
)
from controlgraph_canary.application.promotion_store import DirectPromotionEnqueueStartV2
from controlgraph_canary.application.receipt_execution import (
    ReceiptExecutionCoordinator,
    ReceiptExecutionStored,
    ReceiptMutationResult,
    ReceiptMutationStatus,
    ReceiptReadbackResult,
)
from controlgraph_canary.application.revocation import EpochRevoker
from controlgraph_canary.application.root_trust import CoordinatorInternalRoute
from controlgraph_canary.application.signing import (
    DigestSigningBackend,
    PurposeSealedSigner,
    SigningKeyState,
    SigningProfile,
    TrustBundle,
    TrustBundleVerifier,
    VerificationProfile,
    make_trust_bundle_entry,
)
from controlgraph_canary.application.tasks import (
    AddressedTask,
    TaskAddressingError,
    TaskAddressor,
    TaskDeliverySettings,
    TaskDispatcher,
    TaskEnqueueDisposition,
    TaskEnqueueResult,
)
from controlgraph_canary.authority.replay import (
    MutationAction,
    MutationBinding,
    MutationTargetKey,
    mutation_identity,
)
from controlgraph_canary.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
    encode_base64url,
)
from controlgraph_canary.contracts.health_execution import (
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    create_health_decision_proof,
    create_post_apply_health_anchor,
    create_signed_health_decision_chain,
)
from controlgraph_canary.contracts.models import (
    CapabilityAction,
    EvidenceEvent,
    ExecutionReceipt,
    MutationIntent,
    ReasonCode,
    ReceiptOutcome,
    SignedCapability,
    TargetBinding,
)
from controlgraph_canary.contracts.promotion_execution import (
    PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V2,
    PROMOTION_COMMAND_V2,
    VERIFIED_APPLY_RECEIPT_LOCATOR_V1,
    PromotionAuthorizationV1,
    PromotionCapabilityIssuanceCommandV2,
    PromotionCommandV2,
    PromotionDispatchRecordV2,
    PromotionDispatchState,
    PromotionInvocationV2,
    PromotionMutationIntentV2,
    PromotionTaskRequestV2,
    VerifiedApplyReceiptLocatorV1,
    create_promotion_authorization,
    create_promotion_health_chain_locator,
    promotion_command_v2_sha256,
    promotion_dispatch_v2_id,
)
from controlgraph_canary.contracts.revocation import (
    EPOCH_REVOCATION_COMMAND_V1,
    EPOCH_REVOCATION_INVOCATION_V1,
    EpochRevocationCommandV1,
    EpochRevocationInvocationV1,
)
from controlgraph_canary.contracts.root_creation import (
    SIGNED_EVIDENCE_EVENT_V1,
    SignedEvidenceEventV1,
    evidence_payload_sha256,
    evidence_signing_input_sha256,
)
from controlgraph_canary.contracts.storage import (
    AuthorityStorageKind,
    execution_receipt_logical_id,
    promotion_dispatch_v2_document_id,
)
from controlgraph_canary.http.identity_headers import (
    CONTROLGRAPH_AUTHORIZATION_HEADER,
    SERVERLESS_AUTHORIZATION_HEADER,
)
from controlgraph_canary.http.service import create_service_app
from controlgraph_canary.integrations.google.firestore import FirestoreAuthorityStore

ISSUE_TIME = datetime(2026, 8, 19, 12, 9, tzinfo=UTC)
REVOKE_TIME = datetime(2026, 8, 19, 12, 9, 10, tzinfo=UTC)
EXECUTE_TIME = datetime(2026, 8, 19, 12, 9, 20, tzinfo=UTC)
OPERATOR = "operator@example.test"
OPERATOR_SUBJECT = "123456789012345678901"
API_AUDIENCE = f"https://controlgraph-api-{PROJECT_NUMBER}.us-central1.run.app"
EXECUTOR_AUDIENCE = f"https://controlgraph-executor-{PROJECT_NUMBER}.us-central1.run.app"
CAPABILITY_KEY_VERSION = (
    f"projects/{PROJECT}/locations/us-central1/keyRings/controlgraph-signing/"
    "cryptoKeys/capability-signing/cryptoKeyVersions/1"
)

_HEALTH_CHAINS: dict[str, SignedHealthDecisionChainV1] = {}
_HEALTH_CHAINS_BY_RECEIPT: dict[str, SignedHealthDecisionChainV1] = {}


@pytest.fixture(autouse=True)
def _collect_integration_objects() -> object:
    yield
    gc.collect()


class _P256SigningBackend:
    def __init__(
        self,
        profile: SigningProfile,
        private_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        self._profile = profile
        self._private_key = private_key

    @property
    def profile(self) -> SigningProfile:
        return self._profile

    def sign_digest(self, digest: bytes) -> bytes:
        return self._private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )


class _EvidenceClient:
    def __init__(self, key_version: str) -> None:
        self._key_version = key_version
        self.calls: list[EvidenceEvent] = []

    async def sign(self, event: EvidenceEvent) -> SignedEvidenceEventV1:
        self.calls.append(event)
        return SignedEvidenceEventV1(
            schema_version=SIGNED_EVIDENCE_EVENT_V1,
            event=event,
            purpose="EVIDENCE",
            signing_key_version=self._key_version,
            signing_algorithm="EC_SIGN_P256_SHA256",
            payload_sha256=evidence_payload_sha256(event),
            signing_input_sha256=evidence_signing_input_sha256(
                event,
                self._key_version,
            ),
            signature=encode_base64url(b"synthetic-revocation-signature"),
        )


class _AcceptHealthVerifier:
    async def verify(self, signed_proof: SignedHealthDecisionProofV1) -> None:
        if type(signed_proof) is not SignedHealthDecisionProofV1:
            raise ValueError("health proof is not exact")


class _HealthReader:
    def __init__(self, records: RootV3Records) -> None:
        self.target = records.root.content.target

    async def read_promotion_health_chain(
        self,
        locator: object,
    ) -> SignedHealthDecisionChainV1 | None:
        digest = getattr(locator, "health_chain_sha256", None)
        if type(digest) is not str:
            return None
        return _HEALTH_CHAINS.get(digest)


class _DirectPromotionCapabilityClient:
    def __init__(
        self,
        service: CapabilityIssuanceService,
        context: AuthenticationContext,
    ) -> None:
        self._service = service
        self._context = context
        self.calls: list[PromotionCommandV2] = []
        self.after_issue: Callable[[], None] | None = None

    async def issue(
        self,
        command: PromotionCommandV2,
        authorization: PromotionAuthorizationV1,
    ) -> object:
        self.calls.append(command)
        issued = await self._service.issue(
            PromotionCapabilityIssuanceCommandV2(
                schema_version=PROMOTION_CAPABILITY_ISSUANCE_COMMAND_V2,
                root_id=command.root_id,
                expected_root_sha256=command.expected_root_sha256,
                expected_epoch=command.expected_epoch,
                request_id=command.request_id,
                idempotency_key=command.idempotency_key,
                scheduled_at=command.scheduled_at,
                verified_apply_receipt=command.verified_apply_receipt,
                authorization=authorization,
            ),
            self._context,
        )
        if self.after_issue is not None:
            self.after_issue()
        return issued


class _HoldingEnqueuer:
    def __init__(self) -> None:
        self.tasks: dict[str, AddressedTask] = {}
        self.attempts: list[AddressedTask] = []

    async def enqueue(
        self,
        task: AddressedTask,
        *,
        now: datetime,
    ) -> TaskEnqueueResult:
        del now
        self.attempts.append(task)
        if task.name in self.tasks:
            return TaskEnqueueResult(
                task_name=task.name,
                disposition=TaskEnqueueDisposition.DUPLICATE,
            )
        self.tasks[task.name] = task
        return TaskEnqueueResult(
            task_name=task.name,
            disposition=TaskEnqueueDisposition.CREATED,
        )


class _CapabilityEnvelopeVerifier:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.calls: list[SignedCapability] = []

    def verify(self, capability: SignedCapability) -> None:
        self.calls.append(capability)
        if self.error is not None:
            raise self.error


class _TimelineRecorder:
    def __init__(self, target: TargetBinding) -> None:
        self.target = target
        self.calls: list[tuple[SignedCapability, bool]] = []

    async def record_signed_capability(
        self,
        signed: SignedCapability,
        *,
        signature_verified: bool,
    ) -> None:
        self.calls.append((signed, signature_verified))


class _AmbiguousEnqueuer(_HoldingEnqueuer):
    async def enqueue(
        self,
        task: AddressedTask,
        *,
        now: datetime,
    ) -> TaskEnqueueResult:
        del now
        self.attempts.append(task)
        self.tasks[task.name] = task
        return TaskEnqueueResult(
            task_name=task.name,
            disposition=TaskEnqueueDisposition.AMBIGUOUS,
        )


class _NoMutationAdapter:
    def __init__(self, records: RootV3Records) -> None:
        self.target = records.root.content.target
        self.service_role = ServiceRole.EXECUTOR
        self.calls: list[MutationPermit] = []
        self._prepared_intent: MutationIntent | PromotionMutationIntentV2 | None = None

    @property
    def intent(self) -> MutationIntent | PromotionMutationIntentV2:
        if self._prepared_intent is None:
            raise RuntimeError("mutation adapter has not been prepared")
        return self._prepared_intent

    async def prepare(
        self,
        intent: MutationIntent | PromotionMutationIntentV2,
    ) -> _NoMutationAdapter:
        self._prepared_intent = intent
        return self

    async def mutate(self, permit: MutationPermit) -> ReceiptMutationResult:
        self.calls.append(permit)
        return ReceiptMutationResult(
            status=ReceiptMutationStatus.APPLIED,
            provider_operation="operations/unexpected",
            reason_code=None,
        )


class _NoReadback:
    def __init__(self, records: RootV3Records) -> None:
        self.target = records.root.content.target
        self.calls = 0

    async def readback(self, expected: object) -> ReceiptReadbackResult:
        del expected
        self.calls += 1
        raise AssertionError("stale promotion must not reach provider readback")


class _ReceiptReader:
    def __init__(
        self,
        records: RootV3Records,
        stored: StoredRecord[ExecutionReceipt] | None,
    ) -> None:
        self.target = records.root.content.target
        self.stored = stored

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        if self.stored is None or self.stored.value.idempotency_key != idempotency_key:
            return None
        return self.stored


class _SequencedReceiptReader:
    def __init__(
        self,
        records: RootV3Records,
        reads: list[StoredRecord[ExecutionReceipt] | BaseException],
    ) -> None:
        self.target = records.root.content.target
        self._reads = reads
        self.calls = 0

    async def read_receipt(
        self,
        idempotency_key: str,
    ) -> StoredRecord[ExecutionReceipt] | None:
        del idempotency_key
        selected = self._reads[min(self.calls, len(self._reads) - 1)]
        self.calls += 1
        if isinstance(selected, BaseException):
            raise selected
        return selected


class _NeverTransport:
    def __init__(self) -> None:
        self.calls = 0

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        del route, body
        self.calls += 1
        raise AssertionError("malformed promotion must not reach internal transport")


class _StaticTransport:
    def __init__(self, response: bytes) -> None:
        self._response = response
        self.calls: list[tuple[CoordinatorInternalRoute, bytes]] = []

    async def post(self, route: CoordinatorInternalRoute, body: bytes) -> bytes:
        self.calls.append((route, body))
        return self._response


class _StaticAuthenticator:
    def authenticate(
        self,
        authorization_header: str | None,
        policy: RouteAuthenticationPolicy,
    ) -> AuthenticationContext:
        if authorization_header != "Bearer exact.test.credential":
            raise AssertionError("test credential is not exact")
        return AuthenticationContext(
            role=policy.caller.role,
            email=policy.caller.email,
            subject=policy.caller.subject,
            issuer="https://accounts.google.com",
            audience=policy.audience,
            issued_at=1_776_236_340,
            expires_at=1_776_239_400,
        )


class _NeverPromotionCoordinator:
    def __init__(self) -> None:
        self.calls = 0

    async def dispatch(self, command: PromotionCommandV2) -> object:
        del command
        self.calls += 1
        raise AssertionError("malformed invocation must not reach promotion coordinator")


def _target_key(records: RootV3Records) -> MutationTargetKey:
    target = records.root.content.target
    return MutationTargetKey(
        project_id=target.project_id,
        region=target.region,
        environment=target.environment,
        service_name=target.service_name,
    )


def _source_binding(
    records: RootV3Records,
    *,
    source_idempotency_key: str,
    suffix: str,
) -> MutationBinding:
    root = records.root
    return MutationBinding(
        idempotency_key=source_idempotency_key,
        request_id=f"request-apply-{suffix}",
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=MutationAction.APPLY_CANARY,
        target=_target_key(records),
        provider_precondition=root.content.stable_snapshot.provider_etag,
        plan_sha256=canonical_sha256(root.content.rollout_plan),
        capability_sha256=("a" if suffix == "001" else "b") * 64,
        payload_sha256=("c" if suffix == "001" else "d") * 64,
        expected_poststate_sha256=rollout_root_v3_target_configuration_sha256(
            root,
            stable_percent=90,
            candidate_percent=10,
        ),
    )


async def _write_verified_apply_receipt(
    store: FirestoreAuthorityStore,
    records: RootV3Records,
    *,
    source_idempotency_key: str = "intent-apply-001",
    suffix: str = "001",
    observed_etag: str = "etag-canary-8",
) -> StoredRecord[ExecutionReceipt]:
    binding = _source_binding(
        records,
        source_idempotency_key=source_idempotency_key,
        suffix=suffix,
    )
    root = records.root
    claimed = ExecutionReceipt(
        schema_version="controlgraph.execution-receipt/v1",
        receipt_id=execution_receipt_logical_id(
            root.content.target,
            source_idempotency_key,
        ),
        request_id=binding.request_id,
        idempotency_key=source_idempotency_key,
        capability_sha256=binding.capability_sha256,
        mutation_sha256=mutation_identity(binding),
        plan_sha256=binding.plan_sha256,
        expected_poststate_sha256=binding.expected_poststate_sha256,
        target=root.content.target,
        root_id=root.root_id,
        root_sha256=root.root_sha256,
        epoch=1,
        action=CapabilityAction.APPLY_CANARY,
        provider_etag=binding.provider_precondition,
        dispatch_not_after="2026-08-19T12:10:00Z",
        outcome=ReceiptOutcome.CLAIMED,
        reason_code=None,
        provider_operation=None,
        observed_etag=None,
        observed_authority_epoch=None,
        created_at="2026-08-19T12:02:00Z",
        updated_at="2026-08-19T12:02:00Z",
        evidence_ids=(),
    )
    created = await store.claim_or_adopt_receipt(claimed, binding)
    assert type(created) is ReceiptClaimCreated
    applied = ExecutionReceipt(
        **{
            **claimed.model_dump(mode="python"),
            "outcome": ReceiptOutcome.APPLIED,
            "provider_operation": f"operations/apply-{suffix}",
            "observed_authority_epoch": 1,
            "updated_at": "2026-08-19T12:02:30Z",
        }
    )
    applied_record = await store.compare_and_set_receipt(created.receipt, applied)
    verified = ExecutionReceipt(
        **{
            **applied.model_dump(mode="python"),
            "outcome": ReceiptOutcome.VERIFIED,
            "observed_etag": observed_etag,
            "updated_at": "2026-08-19T12:03:00Z",
        }
    )
    return await store.compare_and_set_receipt(applied_record, verified)


def _locator(receipt: ExecutionReceipt) -> VerifiedApplyReceiptLocatorV1:
    if receipt.provider_operation is None:
        raise AssertionError("verified source receipt requires one provider operation")
    return VerifiedApplyReceiptLocatorV1(
        schema_version=VERIFIED_APPLY_RECEIPT_LOCATOR_V1,
        receipt_id=receipt.receipt_id,
        request_id=receipt.request_id,
        idempotency_key=receipt.idempotency_key,
        capability_sha256=receipt.capability_sha256,
        mutation_sha256=receipt.mutation_sha256,
        expected_poststate_sha256=receipt.expected_poststate_sha256,
        provider_operation=receipt.provider_operation,
        receipt_sha256=canonical_sha256(receipt),
    )


def _healthy_chain(
    records: RootV3Records,
    receipt: ExecutionReceipt,
) -> SignedHealthDecisionChainV1:
    anchor = create_post_apply_health_anchor(
        root=records.root,
        apply_receipt=receipt,
    )
    state = initial_health_evaluation_state(
        policy=anchor.policy,
        target=anchor.target,
        root_id=anchor.root_id,
        root_sha256=anchor.root_sha256,
        epoch=anchor.epoch,
        candidate_revision=anchor.candidate_revision,
        observation_started_at=anchor.observation_started_at,
    )
    first_observation = make_observation(anchor, window_index=1)
    first_decision = evaluate_health_observation(
        policy=anchor.policy,
        prior_state=state,
        observation=first_observation,
        evaluated_at=first_observation.observed_at,
    )
    first_proof = create_health_decision_proof(
        anchor=anchor,
        sequence=1,
        previous_signed_proof_sha256=None,
        prior_state=state,
        observation=first_observation,
        decision=first_decision,
    )
    first_signed = make_signed_proof(first_proof, anchor, marker=b"promotion-first")
    second_state = derive_next_health_evaluation_state(
        policy=anchor.policy,
        predecessor_decision=first_decision,
    )
    second_observation = make_observation(anchor, window_index=2)
    second_decision = evaluate_health_observation(
        policy=anchor.policy,
        prior_state=second_state,
        predecessor_decision=first_decision,
        observation=second_observation,
        evaluated_at=second_observation.observed_at,
    )
    second_proof = create_health_decision_proof(
        anchor=anchor,
        sequence=2,
        previous_signed_proof_sha256=canonical_sha256(first_signed),
        prior_state=second_state,
        observation=second_observation,
        decision=second_decision,
    )
    second_signed = make_signed_proof(second_proof, anchor, marker=b"promotion-second")
    return create_signed_health_decision_chain(
        anchor=anchor,
        signed_proofs=(first_signed, second_signed),
    )


def _promotion_command(
    records: RootV3Records,
    receipt: ExecutionReceipt,
    **changes: object,
) -> PromotionCommandV2:
    receipt_sha256 = canonical_sha256(receipt)
    chain = _HEALTH_CHAINS_BY_RECEIPT.get(receipt_sha256)
    if chain is None:
        chain = _healthy_chain(records, receipt)
        _HEALTH_CHAINS_BY_RECEIPT[receipt_sha256] = chain
    locator = create_promotion_health_chain_locator(chain)
    _HEALTH_CHAINS[locator.health_chain_sha256] = chain
    proof = chain.healthy_promotion_proof
    assert proof is not None
    values: dict[str, object] = {
        "schema_version": PROMOTION_COMMAND_V2,
        "root_id": records.root.root_id,
        "expected_root_sha256": records.root.root_sha256,
        "expected_epoch": 1,
        "request_id": "request-promote-001",
        "idempotency_key": "intent-promote-001",
        "scheduled_at": proof.issued_at,
        "verified_apply_receipt": _locator(receipt),
        "health_chain_locator": locator,
    }
    values.update(changes)
    return PromotionCommandV2.model_validate(values)


def _coordinator_context() -> AuthenticationContext:
    now = int(ISSUE_TIME.timestamp())
    return AuthenticationContext(
        role=CallerRole.COORDINATOR,
        email=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com",
        subject="345678901234567890123",
        issuer="https://accounts.google.com",
        audience=f"https://controlgraph-issuer-{PROJECT_NUMBER}.us-central1.run.app",
        issued_at=now - 60,
        expires_at=now + 600,
    )


def _issuer_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.ISSUER,
        path=protected_path(ServiceRole.ISSUER),
        audience=f"https://controlgraph-issuer-{PROJECT_NUMBER}.us-central1.run.app",
        caller=CallerBinding(
            role=CallerRole.COORDINATOR,
            email=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com",
            subject="345678901234567890123",
        ),
    )


def _operator_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.API,
        path=protected_path(ServiceRole.API),
        audience=API_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.OPERATOR,
            email=OPERATOR,
            subject=OPERATOR_SUBJECT,
        ),
    )


def _coordinator_policy() -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.COORDINATOR,
        path=protected_path(ServiceRole.COORDINATOR),
        audience=(f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"),
        caller=CallerBinding(
            role=CallerRole.API,
            email=f"controlgraph-api@{PROJECT}.iam.gserviceaccount.com",
            subject="234567890123456789012",
        ),
    )


def _operator_context() -> AuthenticationContext:
    now = int(REVOKE_TIME.timestamp())
    return AuthenticationContext(
        role=CallerRole.OPERATOR,
        email=OPERATOR,
        subject=OPERATOR_SUBJECT,
        issuer="https://accounts.google.com",
        audience=API_AUDIENCE,
        issued_at=now - 60,
        expires_at=now + 600,
    )


def _executor_policy(records: RootV3Records) -> RouteAuthenticationPolicy:
    return RouteAuthenticationPolicy(
        project_id=PROJECT,
        project_number=PROJECT_NUMBER,
        service_role=ServiceRole.EXECUTOR,
        path=protected_path(ServiceRole.EXECUTOR),
        audience=EXECUTOR_AUDIENCE,
        caller=CallerBinding(
            role=CallerRole.EXECUTION_TASK_CALLER,
            email=f"cg-execution-task-caller@{PROJECT}.iam.gserviceaccount.com",
            subject="456789012345678901234",
        ),
    )


def _task_caller(records: RootV3Records) -> AuthenticationContext:
    policy = _executor_policy(records)
    now = int(EXECUTE_TIME.timestamp())
    return AuthenticationContext(
        role=CallerRole.EXECUTION_TASK_CALLER,
        email=policy.caller.email,
        subject=policy.caller.subject,
        issuer="https://accounts.google.com",
        audience=policy.audience,
        issued_at=now - 60,
        expires_at=now + 600,
    )


def _delivery_settings() -> TaskDeliverySettings:
    return TaskDeliverySettings(
        project_id=PROJECT,
        execution_queue_id="controlgraph-execution",
        recovery_queue_id="controlgraph-recovery",
        executor_service_url=EXECUTOR_AUDIENCE,
        recovery_service_url=(
            f"https://controlgraph-recovery-{PROJECT_NUMBER}.us-central1.run.app"
        ),
        execution_oidc_service_account=(
            f"cg-execution-task-caller@{PROJECT}.iam.gserviceaccount.com"
        ),
        recovery_oidc_service_account=(
            f"cg-recovery-task-caller@{PROJECT}.iam.gserviceaccount.com"
        ),
    )


def _trust_verifier(
    private_key: ec.EllipticCurvePrivateKey,
) -> TrustBundleVerifier:
    profile = SigningProfile.capability(PROJECT, CAPABILITY_KEY_VERSION)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return TrustBundleVerifier(
        VerificationProfile.capability(PROJECT, profile.key_resource),
        TrustBundle(
            entries=(
                make_trust_bundle_entry(
                    profile=profile,
                    state=SigningKeyState.ENABLED,
                    public_key_pem=public_key_pem,
                ),
            )
        ),
    )


async def _created_store() -> tuple[
    FirestoreAuthorityStore,
    RootV3Records,
]:
    store, records, _, _ = await _created_store_components()
    return store, records


async def _created_store_components() -> tuple[
    FirestoreAuthorityStore,
    RootV3Records,
    _FakeClient,
    _FakeTransactionRunner,
]:
    records = make_root_v3_records()
    client = _FakeClient()
    runner = _FakeTransactionRunner()
    store = FirestoreAuthorityStore.for_test(
        target=records.root.content.target,
        configured_project_id=PROJECT,
        client_factory=lambda: client,  # type: ignore[arg-type,return-value]
        transaction_runner=runner,  # type: ignore[arg-type]
    )
    await store.create_or_adopt_root_creation_bundle(
        records.root,
        records.service_claim,
        records.authority,
        records.lineage_anchor,
        records.signed_evidence,
        records.creation_result,
    )
    return store, records, client, runner


def _issuer(
    store: FirestoreAuthorityStore,
    records: RootV3Records,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    receipt_reader: object | None = None,
) -> CapabilityIssuer:
    backend = _P256SigningBackend(
        SigningProfile.capability(PROJECT, CAPABILITY_KEY_VERSION),
        private_key,
    )
    return CapabilityIssuer(
        store=store,
        signer=PurposeSealedSigner(cast(DigestSigningBackend, backend)),
        configuration=CapabilityIssuerConfiguration(
            target=records.root.content.target,
            handler_audience=EXECUTOR_AUDIENCE,
            lifetime_seconds=300,
        ),
        receipt_reader=receipt_reader or store,  # type: ignore[arg-type]
        promotion_health_chain_reader=_HealthReader(records),
        health_signature_verifier=_AcceptHealthVerifier(),
    )


def _rollout_coordinator(
    store: FirestoreAuthorityStore,
    issuer: CapabilityIssuer,
    records: RootV3Records,
    enqueuer: _HoldingEnqueuer,
    *,
    clock: Callable[[], datetime] = lambda: ISSUE_TIME,
    client_capture: list[_DirectPromotionCapabilityClient] | None = None,
    capability_verifier: _CapabilityEnvelopeVerifier | None = None,
    timeline_recorder: _TimelineRecorder | None = None,
) -> PromotionRolloutCoordinator:
    service = CapabilityIssuanceService(
        issuer=issuer,
        authentication_policy=_issuer_policy(),
        clock=lambda: ISSUE_TIME,
    )
    client = _DirectPromotionCapabilityClient(service, _coordinator_context())
    if client_capture is not None:
        client_capture.append(client)
    return PromotionRolloutCoordinator(
        target=records.root.content.target,
        authorization_resolver=StoredPromotionAuthorizationResolver(
            target=records.root.content.target,
            root_reader=store,
            health_chain_reader=_HealthReader(records),
            health_signature_verifier=_AcceptHealthVerifier(),
        ),
        capability_client=cast(object, client),  # type: ignore[arg-type]
        dispatch_store=store,
        task_dispatcher=TaskDispatcher(
            TaskAddressor(_delivery_settings()),
            enqueuer,
        ),
        clock=clock,
        capability_verifier=capability_verifier,
        timeline_recorder=timeline_recorder,
    )


def test_promotion_records_capability_after_signature_verification() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        verifier = _CapabilityEnvelopeVerifier()
        recorder = _TimelineRecorder(records.root.content.target)
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, ec.generate_private_key(ec.SECP256R1())),
            records,
            enqueuer,
            capability_verifier=verifier,
            timeline_recorder=recorder,
        )

        await coordinator.dispatch(_promotion_command(records, source.value))

        assert len(verifier.calls) == 1
        assert recorder.calls == [(verifier.calls[0], True)]
        assert len(enqueuer.attempts) == 1

    asyncio.run(scenario())


def test_promotion_fails_closed_when_capability_verification_fails() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        marker = "synthetic-promotion-verification-detail"
        verifier = _CapabilityEnvelopeVerifier(RuntimeError(marker))
        recorder = _TimelineRecorder(records.root.content.target)
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, ec.generate_private_key(ec.SECP256R1())),
            records,
            enqueuer,
            capability_verifier=verifier,
            timeline_recorder=recorder,
        )
        command = _promotion_command(records, source.value)

        with pytest.raises(CanaryExecutionError) as denied:
            await coordinator.dispatch(command)

        assert denied.value.code is CanaryExecutionErrorCode.ISSUANCE_DENIED
        assert marker not in str(denied.value)
        assert len(verifier.calls) == 1
        assert recorder.calls == []
        assert enqueuer.attempts == []
        assert await store.read_promotion_dispatch_v2(command) is None

    asyncio.run(scenario())


def _promotion_request(command: PromotionCommandV2) -> PromotionCapabilityIssuanceRequestV2:
    chain = _HEALTH_CHAINS[command.health_chain_locator.health_chain_sha256]
    authorization = create_promotion_authorization(
        root=make_root_v3_records().root,
        signed_health_chain=chain,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        scheduled_at=command.scheduled_at,
    )
    return PromotionCapabilityIssuanceRequestV2(
        root_id=command.root_id,
        expected_root_sha256=command.expected_root_sha256,
        expected_epoch=command.expected_epoch,
        request_id=command.request_id,
        idempotency_key=command.idempotency_key,
        scheduled_at=command.scheduled_at,
        verified_apply_receipt=command.verified_apply_receipt,
        authorization=authorization,
    )


def test_promotion_command_binds_only_authority_and_exact_verified_receipt() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        receipt = await _write_verified_apply_receipt(store, records)
        command = _promotion_command(records, receipt.value)

        assert tuple(PromotionCommandV2.model_fields) == (
            "schema_version",
            "root_id",
            "expected_root_sha256",
            "expected_epoch",
            "request_id",
            "idempotency_key",
            "scheduled_at",
            "verified_apply_receipt",
            "health_chain_locator",
        )
        assert (
            decode_contract(
                canonical_json_bytes(command),
                PromotionCommandV2,
            )
            == command
        )
        missing_schedule = command.model_dump(mode="python")
        del missing_schedule["scheduled_at"]
        with pytest.raises(ValidationError):
            PromotionCommandV2.model_validate(missing_schedule)
        with pytest.raises(ValidationError):
            PromotionCommandV2.model_validate(
                {
                    **command.model_dump(mode="python"),
                    "scheduled_at": "2026-08-19T12:06:00.000Z",
                }
            )
        for injected in (
            {"target": records.root.content.target.model_dump(mode="json")},
            {"action": CapabilityAction.PROMOTE_CANDIDATE.value},
            {"stable_percent": 0, "candidate_percent": 100},
            {"provider_etag": "caller-selected-etag"},
        ):
            with pytest.raises(ValidationError):
                PromotionCommandV2.model_validate({
                    **command.model_dump(mode="python"),
                    **injected,
                })

    asyncio.run(scenario())


def test_issuer_derives_root_scoped_promotion_from_verified_canary_receipt() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        issuer = _issuer(store, records, private_key)
        command = _promotion_command(records, source.value)

        capability = await issuer.issue_promotion(
            _promotion_request(command),
            principal=AuthenticatedIssuancePrincipal(
                identity=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com"
            ),
            now=ISSUE_TIME,
        )

        claims = capability.claims
        assert claims.target == records.root.content.target
        assert claims.root_id == records.root.root_id
        assert claims.root_sha256 == records.root.root_sha256
        assert claims.epoch == 1
        assert claims.action is CapabilityAction.PROMOTE_CANDIDATE
        assert (claims.stable_percent, claims.candidate_percent) == (0, 100)
        assert claims.concurrency is None
        assert claims.provider_etag == source.value.observed_etag
        assert claims.request_id == command.request_id
        assert claims.idempotency_key == command.idempotency_key
        assert claims.not_before == command.scheduled_at
        assert claims.expires_at == "2026-08-19T12:12:00Z"
        assert claims.parent_capability_sha256 is None
        assert claims.plan_sha256 == canonical_sha256(records.root.content.rollout_plan)
        assert claims.stable_revision == records.root.content.rollout_plan.stable_revision
        assert claims.candidate_revision == records.root.content.rollout_plan.candidate_revision

    asyncio.run(scenario())


def test_promotion_schedule_binds_capability_identity_and_exact_margin_boundary() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        issuer = _issuer(store, records, private_key)
        first_command = _promotion_command(records, source.value)
        boundary_schedule = (
            ISSUE_TIME
            + timedelta(seconds=180 - MIN_PROMOTION_EXECUTION_MARGIN_SECONDS)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        boundary_command = first_command.model_copy(
            update={"scheduled_at": boundary_schedule}
        )
        principal = AuthenticatedIssuancePrincipal(
            identity=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com"
        )

        first = await issuer.issue_promotion(
            _promotion_request(first_command),
            principal=principal,
            now=ISSUE_TIME,
        )
        boundary = await issuer.issue_promotion(
            _promotion_request(boundary_command),
            principal=principal,
            now=ISSUE_TIME,
        )

        assert MIN_PROMOTION_EXECUTION_MARGIN_SECONDS == 30
        assert first.claims.not_before == first_command.scheduled_at
        assert boundary.claims.not_before == boundary_schedule
        assert boundary.claims.expires_at == "2026-08-19T12:12:00Z"
        assert first.claims.capability_id != boundary.claims.capability_id

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("scheduled_at", "issue_time"),
    [
        ("2026-08-19T12:09:00Z", ISSUE_TIME + timedelta(seconds=1)),
        ("2026-08-19T12:11:31Z", ISSUE_TIME),
    ],
)
def test_issuer_rejects_past_or_insufficient_margin_promotion_schedule(
    scheduled_at: str,
    issue_time: datetime,
) -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        issuer = _issuer(
            store,
            records,
            ec.generate_private_key(ec.SECP256R1()),
        )
        command = _promotion_command(
            records,
            source.value,
            scheduled_at=scheduled_at,
        )

        with pytest.raises(CapabilityIssuanceError) as denied:
            await issuer.issue_promotion(
                _promotion_request(command),
                principal=AuthenticatedIssuancePrincipal(
                    identity=(
                        f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com"
                    )
                ),
                now=issue_time,
            )

        assert denied.value.code is CapabilityIssuanceErrorCode.VALIDITY_EXHAUSTED

    asyncio.run(scenario())


def test_internal_client_rejects_signed_schedule_substitution() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        issuer = _issuer(
            store,
            records,
            ec.generate_private_key(ec.SECP256R1()),
        )
        command = _promotion_command(records, source.value)
        substituted = command.model_copy(
            update={"scheduled_at": "2026-08-19T12:10:00Z"}
        )
        capability = await issuer.issue_promotion(
            _promotion_request(substituted),
            principal=AuthenticatedIssuancePrincipal(
                identity=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com"
            ),
            now=ISSUE_TIME,
        )
        transport = _StaticTransport(canonical_json_bytes(capability))
        client = CoordinatorPromotionCapabilityClient(
            route=CoordinatorInternalRoute(
                project_id=PROJECT,
                project_number=PROJECT_NUMBER,
                caller_role=CallerRole.COORDINATOR,
                service_role=ServiceRole.ISSUER,
                audience=(
                    f"https://controlgraph-issuer-{PROJECT_NUMBER}.us-central1.run.app"
                ),
            ),
            transport=transport,
        )

        with pytest.raises(CanaryExecutionError) as denied:
            await client.issue(command, _promotion_request(command).authorization)

        assert denied.value.code is CanaryExecutionErrorCode.RESPONSE_INVALID
        assert len(transport.calls) == 1
        issuance = decode_contract(
            transport.calls[0][1],
            PromotionCapabilityIssuanceCommandV2,
        )
        assert issuance.scheduled_at == command.scheduled_at

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "alter",
    [
        "locator_digest",
        "locator_operation",
        "poststate",
        "root",
        "epoch",
        "operation",
        "missing_operation",
        "missing_etag",
        "premature_revision",
    ],
)
def test_issuer_rejects_forged_or_incoherent_source_receipts(alter: str) -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        receipt = source.value
        locator = _locator(receipt)
        selected = receipt
        selected_revision = source.revision
        if alter == "locator_digest":
            locator = VerifiedApplyReceiptLocatorV1(
                **{
                    **locator.model_dump(mode="python"),
                    "receipt_sha256": "f" * 64,
                }
            )
        elif alter == "locator_operation":
            locator = VerifiedApplyReceiptLocatorV1(
                **{
                    **locator.model_dump(mode="python"),
                    "provider_operation": "operations/forged",
                }
            )
        elif alter == "poststate":
            selected = ExecutionReceipt(
                **{
                    **receipt.model_dump(mode="python"),
                    "expected_poststate_sha256": "f" * 64,
                }
            )
            locator = _locator(selected)
        elif alter == "root":
            selected = ExecutionReceipt(
                **{
                    **receipt.model_dump(mode="python"),
                    "root_id": "cgroot:substituted",
                }
            )
            locator = _locator(selected)
        elif alter == "epoch":
            selected = ExecutionReceipt(
                **{
                    **receipt.model_dump(mode="python"),
                    "epoch": 2,
                    "observed_authority_epoch": 2,
                }
            )
            locator = _locator(selected)
        elif alter == "operation":
            selected = ExecutionReceipt(
                **{
                    **receipt.model_dump(mode="python"),
                    "action": CapabilityAction.PROMOTE_CANDIDATE,
                }
            )
            locator = _locator(selected)
        elif alter == "missing_operation":
            selected = ExecutionReceipt(
                **{
                    **receipt.model_dump(mode="python"),
                    "provider_operation": None,
                }
            )
        elif alter == "missing_etag":
            selected = ExecutionReceipt.model_construct(
                **{
                    **receipt.model_dump(mode="python"),
                    "observed_etag": None,
                }
            )
        elif alter == "premature_revision":
            selected_revision = 1
        reader = _ReceiptReader(records, StoredRecord(selected, selected_revision))
        private_key = ec.generate_private_key(ec.SECP256R1())
        issuer = _issuer(
            store,
            records,
            private_key,
            receipt_reader=reader,
        )
        command = _promotion_command(records, receipt)
        request = _promotion_request(command)
        object.__setattr__(request, "verified_apply_receipt", locator)

        with pytest.raises(CapabilityIssuanceError) as denied:
            await issuer.issue_promotion(
                request,
                principal=AuthenticatedIssuancePrincipal(
                    identity=(f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com")
                ),
                now=ISSUE_TIME,
            )
        assert denied.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID

    asyncio.run(scenario())


def test_receipt_read_failure_and_between_read_change_fail_closed() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        command = _promotion_command(records, source.value)
        private_key = ec.generate_private_key(ec.SECP256R1())
        principal = AuthenticatedIssuancePrincipal(
            identity=f"controlgraph-coordinator@{PROJECT}.iam.gserviceaccount.com"
        )

        unavailable_reader = _SequencedReceiptReader(
            records,
            [AuthorityStoreUnavailable()],
        )
        unavailable_issuer = _issuer(
            store,
            records,
            private_key,
            receipt_reader=unavailable_reader,
        )
        with pytest.raises(CapabilityIssuanceError) as unavailable:
            await unavailable_issuer.issue_promotion(
                _promotion_request(command),
                principal=principal,
                now=ISSUE_TIME,
            )
        assert unavailable.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_UNAVAILABLE

        corrupt_reader = _SequencedReceiptReader(
            records,
            [AuthorityStoreCorruptRecord()],
        )
        corrupt_issuer = _issuer(
            store,
            records,
            private_key,
            receipt_reader=corrupt_reader,
        )
        with pytest.raises(CapabilityIssuanceError) as corrupt:
            await corrupt_issuer.issue_promotion(
                _promotion_request(command),
                principal=principal,
                now=ISSUE_TIME,
            )
        assert corrupt.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID

        changed = ExecutionReceipt(
            **{
                **source.value.model_dump(mode="python"),
                "observed_etag": "etag-canary-substituted",
            }
        )
        changing_reader = _SequencedReceiptReader(
            records,
            [source, StoredRecord(changed, source.revision)],
        )
        changing_issuer = _issuer(
            store,
            records,
            private_key,
            receipt_reader=changing_reader,
        )
        with pytest.raises(CapabilityIssuanceError) as changed_between_reads:
            await changing_issuer.issue_promotion(
                _promotion_request(command),
                principal=principal,
                now=ISSUE_TIME,
            )
        assert changed_between_reads.value.code is CapabilityIssuanceErrorCode.TRUSTED_STATE_INVALID
        assert changing_reader.calls == 2

    asyncio.run(scenario())


def test_cross_instance_exact_replay_adopts_original_result_without_reissuing() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        first_clients: list[_DirectPromotionCapabilityClient] = []
        replay_clients: list[_DirectPromotionCapabilityClient] = []
        first_coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
            client_capture=first_clients,
        )
        replay_coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
            clock=lambda: ISSUE_TIME + timedelta(seconds=30),
            client_capture=replay_clients,
        )
        command = _promotion_command(records, source.value)

        first = await first_coordinator.dispatch(command)
        replay = await replay_coordinator.dispatch(command)

        assert first.enqueue_disposition == TaskEnqueueDisposition.CREATED.value
        assert replay == first
        assert len(enqueuer.tasks) == 1
        assert len(enqueuer.attempts) == 1
        assert len(first_clients) == len(replay_clients) == 1
        assert first_clients[0].calls == [command]
        assert replay_clients[0].calls == []
        first_request = decode_contract(enqueuer.attempts[0].body, PromotionTaskRequestV2)
        assert first_request.capability.claims.capability_id == first.capability_id
        assert first_request.capability.claims.not_before == command.scheduled_at
        assert first_request.scheduled_at == command.scheduled_at
        assert enqueuer.attempts[0].scheduled_for == ISSUE_TIME

    asyncio.run(scenario())


def test_changed_schedule_under_same_identities_conflicts_without_reissue() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        clients: list[_DirectPromotionCapabilityClient] = []
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
            client_capture=clients,
        )
        first_command = _promotion_command(records, source.value)
        conflicting_command = first_command.model_copy(
            update={"scheduled_at": "2026-08-19T12:10:00Z"}
        )

        first = await coordinator.dispatch(first_command)
        with pytest.raises(CanaryExecutionError) as conflicting:
            await coordinator.dispatch(conflicting_command)

        assert first.scheduled_at == first_command.scheduled_at
        assert promotion_command_v2_sha256(first_command) != promotion_command_v2_sha256(
            conflicting_command
        )
        assert conflicting.value.code is CanaryExecutionErrorCode.IDENTITY_CONFLICT
        assert clients[0].calls == [first_command]
        assert len(enqueuer.attempts) == 1

    asyncio.run(scenario())


def test_api_client_rejects_dispatch_result_schedule_substitution() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        coordinator = _rollout_coordinator(
            store,
            _issuer(
                store,
                records,
                ec.generate_private_key(ec.SECP256R1()),
            ),
            records,
            _HoldingEnqueuer(),
        )
        command = _promotion_command(records, source.value)
        result = await coordinator.dispatch(command)
        substituted = result.model_copy(
            update={"scheduled_at": "2026-08-19T12:06:01Z"}
        )
        transport = _StaticTransport(canonical_json_bytes(substituted))
        client = ApiPromotionClient(
            route=CoordinatorInternalRoute(
                project_id=PROJECT,
                project_number=PROJECT_NUMBER,
                caller_role=CallerRole.API,
                service_role=ServiceRole.COORDINATOR,
                audience=(
                    f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"
                ),
            ),
            authentication_policy=_operator_policy(),
            transport=transport,
        )

        with pytest.raises(CanaryExecutionError) as denied:
            await client.dispatch(command, _operator_context())

        assert denied.value.code is CanaryExecutionErrorCode.RESPONSE_INVALID
        assert len(transport.calls) == 1
        invocation = decode_contract(transport.calls[0][1], PromotionInvocationV2)
        assert invocation.command.scheduled_at == command.scheduled_at

    asyncio.run(scenario())


def test_changed_source_under_same_promotion_idempotency_cannot_enqueue_twice() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        first_source = await _write_verified_apply_receipt(store, records)
        second_source = await _write_verified_apply_receipt(
            store,
            records,
            source_idempotency_key="intent-apply-002",
            suffix="002",
        )
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        first_command = _promotion_command(records, first_source.value)
        conflicting_command = _promotion_command(records, second_source.value)

        first = await coordinator.dispatch(first_command)
        with pytest.raises(CanaryExecutionError) as conflicting:
            await coordinator.dispatch(conflicting_command)

        assert first.enqueue_disposition == TaskEnqueueDisposition.CREATED.value
        assert conflicting.value.code is CanaryExecutionErrorCode.IDENTITY_CONFLICT
        assert len(enqueuer.tasks) == 1
        assert len(enqueuer.attempts) == 1
        held = decode_contract(
            next(iter(enqueuer.tasks.values())).body,
            PromotionTaskRequestV2,
        )
        assert held.capability.claims.provider_etag == first_source.value.observed_etag

    asyncio.run(scenario())


def test_ambiguous_enqueue_is_terminal_and_exact_replay_never_retries() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _AmbiguousEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        replay = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
            clock=lambda: ISSUE_TIME + timedelta(seconds=45),
        )
        command = _promotion_command(records, source.value)

        first = await coordinator.dispatch(command)
        adopted = await replay.dispatch(command)

        assert first.enqueue_disposition == TaskEnqueueDisposition.AMBIGUOUS.value
        assert adopted == first
        assert len(enqueuer.attempts) == 1

    asyncio.run(scenario())


def test_maximum_length_request_identities_remain_durable_and_replayable() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        command = _promotion_command(
            records,
            source.value,
            request_id="r" * 128,
            idempotency_key="i" * 128,
        )

        dispatched = await coordinator.dispatch(command)
        replay = await coordinator.dispatch(command)

        assert replay == dispatched
        assert dispatched.request_id == command.request_id
        assert dispatched.idempotency_key == command.idempotency_key
        assert len(enqueuer.attempts) == 1

    asyncio.run(scenario())


def test_cross_instance_prepare_race_adopts_one_exact_signed_task() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        first_clients: list[_DirectPromotionCapabilityClient] = []
        second_clients: list[_DirectPromotionCapabilityClient] = []
        first = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
            client_capture=first_clients,
        )
        second = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
            clock=lambda: ISSUE_TIME + timedelta(seconds=1),
            client_capture=second_clients,
        )
        command = _promotion_command(records, source.value)

        first_prepared, second_prepared = await asyncio.gather(
            first._prepare(command),
            second._prepare(command),
        )

        assert first_prepared == second_prepared
        assert first_prepared.value.task_sha256 == canonical_sha256(first_prepared.value.task)
        assert first_clients[0].calls == second_clients[0].calls == [command]
        dispatched = await first.dispatch(command)
        replay = await second.dispatch(command)
        assert replay == dispatched
        assert len(enqueuer.attempts) == 1

    asyncio.run(scenario())


def test_ambiguous_prepare_commit_is_adopted_without_a_second_task() -> None:
    async def scenario() -> None:
        store, records, _, runner = await _created_store_components()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        clients: list[_DirectPromotionCapabilityClient] = []
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
            client_capture=clients,
        )
        command = _promotion_command(records, source.value)
        clients[0].after_issue = lambda: setattr(runner, "mode", "commit-then-timeout")

        prepared = await coordinator._prepare(command)
        readback = await store.read_promotion_dispatch_v2(command)

        assert prepared == readback
        assert prepared.value.state is PromotionDispatchState.PREPARED
        dispatched = await coordinator.dispatch(command)
        replay = await coordinator.dispatch(command)
        assert replay == dispatched
        assert len(enqueuer.attempts) == 1

    asyncio.run(scenario())


def test_same_second_start_cas_yields_one_one_use_enqueue_permit() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        command = _promotion_command(records, source.value)
        prepared = await coordinator._prepare(command)
        started = PromotionDispatchRecordV2.model_validate(
            {
                **prepared.value.model_dump(mode="python"),
                "state": PromotionDispatchState.ENQUEUE_STARTED,
                "enqueue_started_at": "2026-08-19T12:09:00Z",
            }
        )

        contenders = await asyncio.gather(
            store.begin_promotion_enqueue_v2(prepared, started),
            store.begin_promotion_enqueue_v2(prepared, started),
            return_exceptions=True,
        )

        direct = [value for value in contenders if type(value) is DirectPromotionEnqueueStartV2]
        conflicts = [value for value in contenders if type(value) is AuthorityStoreConflict]
        assert len(direct) == len(conflicts) == 1
        dispatcher = TaskDispatcher(TaskAddressor(_delivery_settings()), enqueuer)
        addressed = dispatcher.prepare(prepared.value.task, now=ISSUE_TIME)
        dispatched = await dispatcher.dispatch_prepared_v2(
            addressed,
            permit=direct[0].permit,
            now=ISSUE_TIME,
        )
        with pytest.raises(TaskAddressingError):
            await dispatcher.dispatch_prepared_v2(
                addressed,
                permit=direct[0].permit,
                now=ISSUE_TIME,
            )
        assert dispatched.disposition is TaskEnqueueDisposition.CREATED
        assert len(enqueuer.attempts) == 1

    asyncio.run(scenario())


def test_start_commit_response_loss_never_grants_enqueue_authority() -> None:
    async def scenario() -> None:
        store, records, _, runner = await _created_store_components()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        command = _promotion_command(records, source.value)
        prepared = await coordinator._prepare(command)
        started = PromotionDispatchRecordV2.model_validate(
            {
                **prepared.value.model_dump(mode="python"),
                "state": PromotionDispatchState.ENQUEUE_STARTED,
                "enqueue_started_at": "2026-08-19T12:09:00Z",
            }
        )
        runner.mode = "commit-then-timeout"

        with pytest.raises(AuthorityStoreOutcomeUnknown):
            await store.begin_promotion_enqueue_v2(prepared, started)
        with pytest.raises(CanaryExecutionError) as replay:
            await coordinator.dispatch(command)

        assert replay.value.code is CanaryExecutionErrorCode.OUTCOME_UNKNOWN
        assert (await store.read_promotion_dispatch_v2(command)) == StoredRecord(started, 1)
        assert enqueuer.attempts == []

    asyncio.run(scenario())


def test_legacy_dispatch_cannot_bypass_promotion_enqueue_permit() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        command = _promotion_command(records, source.value)
        prepared = await coordinator._prepare(command)
        dispatcher = TaskDispatcher(TaskAddressor(_delivery_settings()), enqueuer)

        with pytest.raises(TaskAddressingError):
            await dispatcher.dispatch(  # type: ignore[arg-type]
                prepared.value.task,
                now=ISSUE_TIME,
            )

        assert enqueuer.attempts == []

    asyncio.run(scenario())


@pytest.mark.parametrize("corruption", ["task_name", "task_sha256", "scheduled_at"])
def test_dispatch_record_rejects_non_deterministic_task_identity(corruption: str) -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            _HoldingEnqueuer(),
        )
        prepared = await coordinator._prepare(_promotion_command(records, source.value))
        changed = {
            "task_name": (
                f"projects/{PROJECT}/locations/us-central1/queues/"
                f"controlgraph-execution/tasks/cg-{'0' * 64}"
            ),
            "task_sha256": "f" * 64,
            "scheduled_at": "2026-08-19T12:07:00Z",
        }

        with pytest.raises(ValidationError):
            PromotionDispatchRecordV2.model_validate(
                {
                    **prepared.value.model_dump(mode="python"),
                    corruption: changed[corruption],
                }
            )

    asyncio.run(scenario())


def test_task_contract_rejects_promotion_schedule_substitution() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        coordinator = _rollout_coordinator(
            store,
            _issuer(
                store,
                records,
                ec.generate_private_key(ec.SECP256R1()),
            ),
            records,
            _HoldingEnqueuer(),
        )
        prepared = await coordinator._prepare(
            _promotion_command(records, source.value)
        )

        with pytest.raises(ValidationError):
            PromotionTaskRequestV2.model_validate(
                {
                    **prepared.value.task.model_dump(mode="python"),
                    "scheduled_at": "2026-08-19T12:06:01Z",
                }
            )

    asyncio.run(scenario())


def test_partial_prepare_ambiguity_never_enqueues_and_becomes_trusted_state_failure() -> None:
    async def scenario() -> None:
        store, records, _, runner = await _created_store_components()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        clients: list[_DirectPromotionCapabilityClient] = []
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
            client_capture=clients,
        )
        command = _promotion_command(records, source.value)
        clients[0].after_issue = lambda: setattr(
            runner,
            "mode",
            "commit-first-only-then-timeout",
        )

        with pytest.raises(CanaryExecutionError) as ambiguous:
            await coordinator._prepare(command)
        with pytest.raises(CanaryExecutionError) as corrupt:
            await coordinator.dispatch(command)

        assert ambiguous.value.code is CanaryExecutionErrorCode.OUTCOME_UNKNOWN
        assert corrupt.value.code is CanaryExecutionErrorCode.TRUSTED_STATE_INVALID
        assert enqueuer.attempts == []

    asyncio.run(scenario())


def test_started_without_terminal_result_is_outcome_unknown_without_retry() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        command = _promotion_command(records, source.value)
        prepared = await coordinator._prepare(command)
        started = PromotionDispatchRecordV2.model_validate(
            {
                **prepared.value.model_dump(mode="python"),
                "state": PromotionDispatchState.ENQUEUE_STARTED,
                "enqueue_started_at": "2026-08-19T12:09:00Z",
            }
        )
        await store.begin_promotion_enqueue_v2(prepared, started)

        with pytest.raises(CanaryExecutionError) as denied:
            await coordinator.dispatch(command)

        assert denied.value.code is CanaryExecutionErrorCode.OUTCOME_UNKNOWN
        assert enqueuer.attempts == []

    asyncio.run(scenario())


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_missing_or_corrupt_prepared_record_after_ownership_fails_closed(
    damage: str,
) -> None:
    async def scenario() -> None:
        store, records, client, _ = await _created_store_components()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        command = _promotion_command(records, source.value)
        await coordinator._prepare(command)
        command_sha256 = promotion_command_v2_sha256(command)
        document_id = promotion_dispatch_v2_document_id(
            promotion_dispatch_v2_id(command_sha256)
        )
        path = f"{AuthorityStorageKind.PROMOTION_DISPATCH_V2.value}/{document_id}"
        if damage == "missing":
            del client.documents[path]
        else:
            client.documents[path].data["payload_sha256"] = "0" * 64

        with pytest.raises(CanaryExecutionError) as denied:
            await coordinator.dispatch(command)

        assert denied.value.code is CanaryExecutionErrorCode.TRUSTED_STATE_INVALID
        assert enqueuer.attempts == []

    asyncio.run(scenario())


def test_revoked_held_promotion_passes_signature_then_fails_final_fresh_epoch() -> None:
    async def scenario() -> None:
        store, records = await _created_store()
        source = await _write_verified_apply_receipt(store, records)
        private_key = ec.generate_private_key(ec.SECP256R1())
        enqueuer = _HoldingEnqueuer()
        coordinator = _rollout_coordinator(
            store,
            _issuer(store, records, private_key),
            records,
            enqueuer,
        )
        command = _promotion_command(records, source.value)

        dispatched = await coordinator.dispatch(command)
        assert dispatched.enqueue_disposition == TaskEnqueueDisposition.CREATED.value
        assert len(enqueuer.tasks) == 1
        held = next(iter(enqueuer.tasks.values()))

        verifier = CapabilityVerifier(
            root_reader=store,
            trust_verifier=_trust_verifier(private_key),
            configuration=CapabilityVerifierConfiguration(
                target=records.root.content.target,
                route_policy=_executor_policy(records),
            ),
            clock=lambda: REVOKE_TIME,
        )
        verified = await verifier.verify(held.body, _task_caller(records))
        assert verified.request.intent.action is CapabilityAction.PROMOTE_CANDIDATE
        assert verified.request.intent.epoch == 1

        evidence = _EvidenceClient(records.root.content.evidence_signing_key_version)
        revoker = EpochRevoker(
            store=store,
            evidence_client=evidence,
            operator_policy=_operator_policy(),
            clock=lambda: REVOKE_TIME,
        )
        operator = _operator_context()
        revocation = EpochRevocationInvocationV1(
            schema_version=EPOCH_REVOCATION_INVOCATION_V1,
            command=EpochRevocationCommandV1(
                schema_version=EPOCH_REVOCATION_COMMAND_V1,
                root_id=records.root.root_id,
                expected_root_sha256=records.root.root_sha256,
                expected_epoch=1,
                reason="Stop the canary before delayed promotion executes.",
                request_id="request-revoke-promotion-001",
                idempotency_key="revoke-promotion-001",
                confirmation="REVOKE",
            ),
            attempt_id="cgrevoke-attempt-promotion-001",
            operator_identity=operator.email,
            operator_subject=operator.subject,
            operator_issuer="https://accounts.google.com",
            operator_audience=operator.audience,
            operator_issued_at=operator.issued_at,
            operator_expires_at=operator.expires_at,
        )
        revoked = await revoker.revoke(revocation, principal=operator)
        assert revoked.previous_epoch == 1
        assert revoked.new_epoch == 2
        assert len(evidence.calls) == 1

        adapter = _NoMutationAdapter(records)
        readback = _NoReadback(records)
        execution = ReceiptExecutionCoordinator(
            store=store,
            final_gate=FinalMutationGate(
                authority_reader=store,
                adapter=adapter,
                route_policy=_executor_policy(records),
                source_receipt_reader=store,
                clock=lambda: EXECUTE_TIME,
            ),
            readback=readback,
            clock=lambda: EXECUTE_TIME,
        )
        response = await execution.execute(verified)

        assert type(response) is ReceiptExecutionStored
        assert response.receipt.value.outcome is ReceiptOutcome.DENIED
        assert response.receipt.value.reason_code is ReasonCode.EPOCH_MISMATCH
        assert response.receipt.value.observed_authority_epoch == 2
        assert adapter.calls == []
        assert readback.calls == 0
        source_after = await store.read_receipt(source.value.idempotency_key)
        assert source_after == source

    asyncio.run(scenario())


def test_malformed_promotion_command_stops_at_api_decoder() -> None:
    transport = _NeverTransport()
    client = ApiPromotionClient(
        route=CoordinatorInternalRoute(
            project_id=PROJECT,
            project_number=PROJECT_NUMBER,
            caller_role=CallerRole.API,
            service_role=ServiceRole.COORDINATOR,
            audience=(f"https://controlgraph-coordinator-{PROJECT_NUMBER}.us-central1.run.app"),
        ),
        authentication_policy=_operator_policy(),
        transport=transport,
    )
    app = create_service_app(
        ServiceRole.API,
        authenticator=_StaticAuthenticator(),
        authentication_policy=_operator_policy(),
        api_promotion_client=client,
    )

    response = TestClient(app).post(
        protected_path(ServiceRole.API),
        content=b'{"schema_version":"controlgraph.promotion-command/v1"}',
        headers={
            CONTROLGRAPH_AUTHORIZATION_HEADER: "Bearer exact.test.credential",
            SERVERLESS_AUTHORIZATION_HEADER: (
                "bearer exact.test.SIGNATURE_REMOVED_BY_GOOGLE"
            ),
        },
    )

    assert response.status_code == 400
    assert response.json()["code"] == "CONTRACT_VERSION_UNSUPPORTED"
    assert transport.calls == 0


def test_malformed_promotion_invocation_stops_at_coordinator_decoder() -> None:
    coordinator = _NeverPromotionCoordinator()
    relay = CoordinatorPromotionRelay(
        authentication_policy=_coordinator_policy(),
        operator_policy=_operator_policy(),
        coordinator=cast(object, coordinator),  # type: ignore[arg-type]
    )
    app = create_service_app(
        ServiceRole.COORDINATOR,
        authenticator=_StaticAuthenticator(),
        authentication_policy=_coordinator_policy(),
        coordinator_promotion_relay=relay,
    )

    response = TestClient(app).post(
        protected_path(ServiceRole.COORDINATOR),
        content=b'{"schema_version":"controlgraph.promotion-invocation/v1"}',
        headers={"Authorization": "Bearer exact.test.credential"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "CONTRACT_VERSION_UNSUPPORTED"
    assert coordinator.calls == 0


def test_malformed_promotion_issuance_stops_at_issuer_decoder() -> None:
    store, records = asyncio.run(_created_store())
    private_key = ec.generate_private_key(ec.SECP256R1())
    service = CapabilityIssuanceService(
        issuer=_issuer(store, records, private_key),
        authentication_policy=_issuer_policy(),
        clock=lambda: ISSUE_TIME,
    )
    app = create_service_app(
        ServiceRole.ISSUER,
        authenticator=_StaticAuthenticator(),
        authentication_policy=_issuer_policy(),
        capability_issuance_service=service,
    )

    response = TestClient(app).post(
        protected_path(ServiceRole.ISSUER),
        content=(b'{"schema_version":"controlgraph.promotion-capability-issuance-command/v1"}'),
        headers={"Authorization": "Bearer exact.test.credential"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "CONTRACT_VERSION_UNSUPPORTED"
