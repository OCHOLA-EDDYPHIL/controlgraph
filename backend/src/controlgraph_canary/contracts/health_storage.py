"""Compact normalized persistence contracts for signed health chains."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, ValidationError, model_validator

from controlgraph_canary.contracts.base import (
    MAX_CONTRACT_BYTES,
    BoundedText,
    Identifier,
    PositiveSafeInteger,
    Sha256Digest,
    StrictContractModel,
    UtcSecond,
)
from controlgraph_canary.contracts.codec import (
    DIGEST_DOMAIN,
    ContractError,
    RestrictedJson,
    canonical_json_bytes,
    canonical_json_value_bytes,
    canonical_sha256,
    decode_contract,
)
from controlgraph_canary.contracts.health import HealthDecisionStatus
from controlgraph_canary.contracts.health_execution import (
    HealthyPromotionProofV1,
    PostApplyHealthAnchorV1,
    SignedHealthDecisionChainV1,
    SignedHealthDecisionProofV1,
    health_chain_manifest_sha256,
    signed_health_decision_chain_sha256,
    signed_health_proof_chain_sha256,
)
from controlgraph_canary.contracts.models import TargetBinding
from controlgraph_canary.contracts.recovery_execution import (
    RECOVERY_TASK_REQUEST_V2,
    RecoveryDispatchIdentityV2,
    RecoveryDispatchRecordV2,
    RecoveryDispatchResultV2,
    RecoveryDispatchState,
    RecoveryIntentV1,
    RecoveryTaskRequestV2,
    recovery_dispatch_id,
)

HEALTH_PROOF_DOCUMENT_REFERENCE_V1: Final = (
    "controlgraph.health-proof-document-reference/v1"
)
HEALTH_CHAIN_MANIFEST_V1: Final = "controlgraph.health-chain-manifest/v1"
HEALTH_STORAGE_DOCUMENT_V1: Final = "controlgraph.health-storage-document/v1"
RECOVERY_DISPATCH_STORAGE_RECORD_V2: Final = (
    "controlgraph.recovery-dispatch-storage-record/v2"
)

HEALTH_FIRESTORE_DOCUMENT_ID_DOMAIN: Final = (
    b"controlgraph.health-firestore-document-id/v1\0"
)
_SIGNED_PROOF_CHAIN_DOMAIN: Final = b"controlgraph.signed-health-proof-chain/v1\0"
_CONTROLGRAPH_PROJECT_ID: Final = re.compile(r"^controlgraph-canary-[a-z0-9]{6,10}$")


class HealthStorageKind(StrEnum):
    """Closed, versioned Firestore collections for normalized health evidence."""

    POST_APPLY_HEALTH_ANCHOR = "controlgraph-post-apply-health-anchors-v1"
    SIGNED_HEALTH_DECISION_PROOF = "controlgraph-signed-health-decision-proofs-v1"
    HEALTH_CHAIN_HEAD = "controlgraph-health-chain-heads-v1"
    HEALTH_CHAIN_MANIFEST = "controlgraph-health-chain-manifests-v1"
    RECOVERY_INTENT = "controlgraph-recovery-intents-v1"
    RECOVERY_DISPATCH_IDENTITY = "controlgraph-recovery-dispatch-identities-v2"
    RECOVERY_DISPATCH = "controlgraph-recovery-dispatches-v2"


def _require_health_target(target: TargetBinding) -> None:
    if type(target) is not TargetBinding:
        raise TypeError("health storage target must be exact")
    if (
        _CONTROLGRAPH_PROJECT_ID.fullmatch(target.project_id) is None
        or "reconcile" in target.project_id
        or target.region != "us-central1"
        or target.environment != "nonprod"
        or target.service_name != "controlgraph-reference-target"
    ):
        raise ValueError("health storage target is outside the ControlGraph boundary")


class _LogicalIdentity(StrictContractModel):
    value: Identifier


def _validated_identifier(value: str) -> str:
    try:
        return _LogicalIdentity(value=value).value
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("health storage logical identifier is invalid") from error


def _validated_digest(value: str) -> str:
    class _Digest(StrictContractModel):
        value: Sha256Digest

    try:
        return _Digest(value=value).value
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("health storage digest is invalid") from error


def _document_id(
    kind: HealthStorageKind,
    target: TargetBinding,
    *components: str,
) -> str:
    if type(kind) is not HealthStorageKind:
        raise TypeError("health storage kind must be exact")
    _require_health_target(target)
    if not components or any(
        type(component) is not str or not component for component in components
    ):
        raise ValueError("health storage document identity is invalid")
    digest = hashlib.sha256()
    digest.update(HEALTH_FIRESTORE_DOCUMENT_ID_DOMAIN)
    for component in (
        kind.value,
        canonical_sha256(target),
        *components,
    ):
        encoded = component.encode("ascii")
        digest.update(len(encoded).to_bytes(2, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def health_anchor_document_id(target: TargetBinding, anchor_id: str) -> str:
    """Return the target-scoped immutable document ID for one health anchor."""

    return _document_id(
        HealthStorageKind.POST_APPLY_HEALTH_ANCHOR,
        target,
        _validated_identifier(anchor_id),
    )


def signed_health_proof_logical_id(signed_proof_sha256: str) -> str:
    """Return the content identity for one exact signed proof wrapper."""

    return f"cgsignedhealthproof:{_validated_digest(signed_proof_sha256)}"


def signed_health_proof_document_id(
    target: TargetBinding,
    anchor_id: str,
    signed_proof_sha256: str,
) -> str:
    """Return one target- and anchor-scoped signed-proof document ID."""

    return _document_id(
        HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF,
        target,
        _validated_identifier(anchor_id),
        _validated_digest(signed_proof_sha256),
    )


def health_chain_head_document_id(target: TargetBinding, anchor_id: str) -> str:
    """Return the target-scoped CAS head document ID for one health anchor."""

    return _document_id(
        HealthStorageKind.HEALTH_CHAIN_HEAD,
        target,
        _validated_identifier(anchor_id),
    )


def health_chain_manifest_document_id(
    target: TargetBinding,
    manifest_sha256: str,
) -> str:
    """Return the target-scoped immutable lookup ID for one chain manifest."""

    return _document_id(
        HealthStorageKind.HEALTH_CHAIN_MANIFEST,
        target,
        _validated_digest(manifest_sha256),
    )


def recovery_intent_document_id(target: TargetBinding, root_sha256: str) -> str:
    """Return the root-scoped identity shared by every recovery epoch."""

    return _document_id(
        HealthStorageKind.RECOVERY_INTENT,
        target,
        _validated_digest(root_sha256),
    )


def recovery_dispatch_identity_logical_id(
    identity_kind: str,
    identity_value: str,
) -> str:
    """Return a bounded content identity for one recovery request key."""

    kind = _validated_identifier(identity_kind)
    value = _validated_identifier(identity_value)
    digest = hashlib.sha256()
    digest.update(b"controlgraph.recovery-dispatch-identity-logical-id/v2\0")
    for component in (kind, value):
        encoded = component.encode("ascii")
        digest.update(len(encoded).to_bytes(2, "big"))
        digest.update(encoded)
    return f"cgrecoveryidentity:{digest.hexdigest()}"


def recovery_dispatch_identity_document_id(
    target: TargetBinding,
    identity_kind: str,
    identity_value: str,
) -> str:
    """Return one target-sealed recovery request-ownership document ID."""

    return _document_id(
        HealthStorageKind.RECOVERY_DISPATCH_IDENTITY,
        target,
        _validated_identifier(identity_kind),
        _validated_identifier(identity_value),
    )


def recovery_dispatch_document_id(target: TargetBinding, dispatch_id: str) -> str:
    """Return the target-sealed document ID for one recovery dispatch."""

    return _document_id(
        HealthStorageKind.RECOVERY_DISPATCH,
        target,
        _validated_identifier(dispatch_id),
    )


def ordered_health_proof_digests_sha256(
    signed_proof_sha256s: tuple[str, ...],
) -> str:
    """Hash an ordered sequence of signed-proof digests without an aggregate payload."""

    if (
        type(signed_proof_sha256s) is not tuple
        or not signed_proof_sha256s
        or len(signed_proof_sha256s) > 20
    ):
        raise ValueError("ordered signed-proof digest sequence is invalid")
    validated = tuple(_validated_digest(value) for value in signed_proof_sha256s)
    digest = hashlib.sha256()
    digest.update(_SIGNED_PROOF_CHAIN_DOMAIN)
    digest.update(len(validated).to_bytes(2, "big"))
    for value in validated:
        digest.update(bytes.fromhex(value))
    return digest.hexdigest()


def health_chain_manifest_components_sha256(
    *,
    anchor_sha256: str,
    ordered_proof_chain_sha256: str,
    chain_head_sha256: str,
    healthy_promotion_proof_sha256: str | None,
) -> str:
    """Recompute the health-chain helper digest from compact manifest components."""

    return health_chain_manifest_sha256(
        anchor_sha256=_validated_digest(anchor_sha256),
        ordered_proof_chain_sha256=_validated_digest(
            ordered_proof_chain_sha256
        ),
        chain_head_sha256=_validated_digest(chain_head_sha256),
        healthy_promotion_proof_sha256=(
            _validated_digest(healthy_promotion_proof_sha256)
            if healthy_promotion_proof_sha256 is not None
            else None
        ),
    )


class HealthProofDocumentReferenceV1(StrictContractModel):
    """Ordered immutable document and digest binding for one signed proof."""

    schema_version: Literal["controlgraph.health-proof-document-reference/v1"]
    sequence: Annotated[int, Field(ge=1, le=20)]
    proof_id: Identifier
    document_id: Sha256Digest
    signed_proof_sha256: Sha256Digest
    decision_sha256: Sha256Digest


class HealthChainManifestV1(StrictContractModel):
    """Compact durable chain state that never embeds the full signed proof sequence."""

    schema_version: Literal["controlgraph.health-chain-manifest/v1"]
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    anchor_id: Identifier
    anchor_sha256: Sha256Digest
    chain_id: Identifier
    manifest_sha256: Sha256Digest
    ordered_proof_chain_sha256: Sha256Digest
    chain_head_sha256: Sha256Digest
    terminal_sequence: Annotated[int, Field(ge=1, le=20)]
    terminal_status: HealthDecisionStatus
    proof_documents: Annotated[
        tuple[HealthProofDocumentReferenceV1, ...],
        Field(min_length=1, max_length=20),
    ]
    healthy_promotion_proof: HealthyPromotionProofV1 | None
    healthy_promotion_proof_sha256: Sha256Digest | None

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        _require_health_target(self.target)
        if self.root_id != f"cgroot:{self.root_sha256}":
            raise ValueError("health manifest root binding is invalid")
        if len(self.proof_documents) != self.terminal_sequence:
            raise ValueError("health manifest proof count is invalid")
        signed_digests: list[str] = []
        seen_document_ids: set[str] = set()
        seen_signed_digests: set[str] = set()
        for expected_sequence, reference in enumerate(self.proof_documents, start=1):
            expected_document_id = signed_health_proof_document_id(
                self.target,
                self.anchor_id,
                reference.signed_proof_sha256,
            )
            if (
                reference.sequence != expected_sequence
                or reference.document_id != expected_document_id
                or reference.document_id in seen_document_ids
                or reference.signed_proof_sha256 in seen_signed_digests
            ):
                raise ValueError("health manifest proof reference is invalid")
            seen_document_ids.add(reference.document_id)
            seen_signed_digests.add(reference.signed_proof_sha256)
            signed_digests.append(reference.signed_proof_sha256)
        expected_ordered_digest = ordered_health_proof_digests_sha256(
            tuple(signed_digests)
        )
        compact = self.healthy_promotion_proof
        compact_sha256 = (
            canonical_sha256(compact) if compact is not None else None
        )
        if (
            self.ordered_proof_chain_sha256 != expected_ordered_digest
            or self.chain_head_sha256 != self.proof_documents[-1].signed_proof_sha256
            or self.healthy_promotion_proof_sha256 != compact_sha256
        ):
            raise ValueError("health manifest digest bindings are invalid")
        if self.terminal_status is HealthDecisionStatus.HEALTHY:
            terminal = self.proof_documents[-1]
            if (
                compact is None
                or compact.anchor_id != self.anchor_id
                or compact.anchor_sha256 != self.anchor_sha256
                or compact.root_id != self.root_id
                or compact.root_sha256 != self.root_sha256
                or compact.target != self.target
                or compact.epoch != self.epoch
                or compact.terminal_sequence != self.terminal_sequence
                or compact.terminal_health_decision_sha256
                != terminal.decision_sha256
                or compact.signed_health_chain_sha256
                != self.ordered_proof_chain_sha256
            ):
                raise ValueError("healthy manifest compact proof is invalid")
        elif compact is not None:
            raise ValueError("non-healthy manifest cannot carry a promotion proof")
        expected_manifest_sha256 = health_chain_manifest_components_sha256(
            anchor_sha256=self.anchor_sha256,
            ordered_proof_chain_sha256=self.ordered_proof_chain_sha256,
            chain_head_sha256=self.chain_head_sha256,
            healthy_promotion_proof_sha256=self.healthy_promotion_proof_sha256,
        )
        if (
            self.manifest_sha256 != expected_manifest_sha256
            or self.chain_id != f"cghealthchain:{self.manifest_sha256}"
        ):
            raise ValueError("health manifest identity is invalid")
        return self


def create_health_chain_manifest(
    chain: SignedHealthDecisionChainV1,
) -> HealthChainManifestV1:
    """Project an in-process chain into its bounded normalized manifest."""

    if type(chain) is not SignedHealthDecisionChainV1:
        raise TypeError("health manifest creation requires an exact signed chain")
    signed_digests = tuple(canonical_sha256(proof) for proof in chain.signed_proofs)
    proof_documents = tuple(
        HealthProofDocumentReferenceV1(
            schema_version=HEALTH_PROOF_DOCUMENT_REFERENCE_V1,
            sequence=signed.proof.sequence,
            proof_id=signed.proof.proof_id,
            document_id=signed_health_proof_document_id(
                chain.anchor.target,
                chain.anchor.anchor_id,
                signed_sha256,
            ),
            signed_proof_sha256=signed_sha256,
            decision_sha256=signed.proof.decision_sha256,
        )
        for signed, signed_sha256 in zip(chain.signed_proofs, signed_digests, strict=True)
    )
    compact = chain.healthy_promotion_proof
    manifest_sha256 = signed_health_decision_chain_sha256(chain)
    manifest = HealthChainManifestV1(
        schema_version=HEALTH_CHAIN_MANIFEST_V1,
        target=chain.anchor.target,
        root_id=chain.anchor.root_id,
        root_sha256=chain.anchor.root_sha256,
        epoch=chain.anchor.epoch,
        anchor_id=chain.anchor.anchor_id,
        anchor_sha256=chain.anchor_sha256,
        chain_id=chain.chain_id,
        manifest_sha256=manifest_sha256,
        ordered_proof_chain_sha256=signed_health_proof_chain_sha256(
            chain.signed_proofs
        ),
        chain_head_sha256=chain.chain_head_sha256,
        terminal_sequence=chain.signed_proofs[-1].proof.sequence,
        terminal_status=chain.signed_proofs[-1].proof.decision.status,
        proof_documents=proof_documents,
        healthy_promotion_proof=compact,
        healthy_promotion_proof_sha256=(
            canonical_sha256(compact) if compact is not None else None
        ),
    )
    if manifest.manifest_sha256 != signed_health_decision_chain_sha256(chain):
        raise ValueError("health manifest does not match the chain helper digest")
    return manifest


def _canonical_embedded_contract_sha256(value: dict[str, object]) -> str:
    schema_version = value.get("schema_version")
    if type(schema_version) is not str:
        raise ValueError("embedded contract schema version is invalid")
    payload = canonical_json_value_bytes(cast(RestrictedJson, value))
    return hashlib.sha256(
        DIGEST_DOMAIN + schema_version.encode("ascii") + b"\0" + payload
    ).hexdigest()


def _canonical_recovery_task_payload(
    payload: str,
) -> tuple[dict[str, object], bytes]:
    try:
        value = json.loads(payload)
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("recovery dispatch task payload is invalid") from error
    if type(value) is not dict or value.get("schema_version") != RECOVERY_TASK_REQUEST_V2:
        raise ValueError("recovery dispatch task schema is invalid")
    encoded = canonical_json_value_bytes(cast(RestrictedJson, value))
    if encoded.decode("utf-8") != payload:
        raise ValueError("recovery dispatch task payload is not canonical")
    return cast(dict[str, object], value), encoded


def _object_field(value: dict[str, object], field: str) -> dict[str, object]:
    nested = value.get(field)
    if type(nested) is not dict:
        raise ValueError("recovery dispatch task structure is invalid")
    return cast(dict[str, object], nested)


class RecoveryDispatchStorageRecordV2(StrictContractModel):
    """Shallow durable projection of a dispatch with its task as canonical text."""

    schema_version: Literal["controlgraph.recovery-dispatch-storage-record/v2"]
    dispatch_id: Identifier
    command_sha256: Sha256Digest
    recovery_authorization_sha256: Sha256Digest
    capability_id: Identifier
    request_id: Identifier
    idempotency_key: Identifier
    target: TargetBinding
    root_id: Identifier
    root_sha256: Sha256Digest
    epoch: PositiveSafeInteger
    scheduled_at: UtcSecond
    source_receipt_sha256: Sha256Digest
    trigger_proof_sha256: Sha256Digest
    prestate_attestation_sha256: Sha256Digest
    task_sha256: Sha256Digest
    task_name: BoundedText
    task_canonical_payload: Annotated[
        str,
        Field(min_length=2, max_length=MAX_CONTRACT_BYTES),
    ]
    state: RecoveryDispatchState
    prepared_at: UtcSecond
    enqueue_started_at: UtcSecond | None
    terminal_at: UtcSecond | None
    result: RecoveryDispatchResultV2 | None

    @model_validator(mode="after")
    def validate_storage_record(self) -> Self:
        try:
            task, task_payload = _canonical_recovery_task_payload(
                self.task_canonical_payload
            )
            intent = _object_field(task, "intent")
            authorization = _object_field(intent, "authorization")
            attestation = _object_field(authorization, "prestate_attestation")
            prestate_result = _object_field(attestation, "result")
            prestate_request = _object_field(prestate_result, "request")
            command = _object_field(prestate_request, "command")
            source = _object_field(authorization, "source")
            apply_receipt = _object_field(authorization, "verified_apply_receipt")
            capability = _object_field(task, "capability")
            claims = _object_field(capability, "claims")
        except (ContractError, TypeError, ValueError) as error:
            raise ValueError("recovery dispatch storage payload is invalid") from error
        target = self.target.model_dump(mode="json")
        task_sha256 = hashlib.sha256(
            DIGEST_DOMAIN
            + RECOVERY_TASK_REQUEST_V2.encode("ascii")
            + b"\0"
            + task_payload
        ).hexdigest()
        expected_task_name = (
            f"projects/{self.target.project_id}/locations/us-central1/queues/"
            f"controlgraph-recovery/tasks/cg-{self.task_sha256}"
        )
        terminal = self.state in {
            RecoveryDispatchState.CREATED,
            RecoveryDispatchState.DUPLICATE,
            RecoveryDispatchState.AMBIGUOUS,
        }
        if (
            self.task_sha256 != task_sha256
            or self.task_name != expected_task_name
            or self.command_sha256 != prestate_request.get("command_sha256")
            or self.dispatch_id != recovery_dispatch_id(self.command_sha256)
            or self.recovery_authorization_sha256
            != _canonical_embedded_contract_sha256(authorization)
            or self.recovery_authorization_sha256
            != intent.get("recovery_authorization_sha256")
            or self.capability_id != intent.get("capability_id")
            or self.capability_id != authorization.get("capability_id")
            or self.capability_id != claims.get("capability_id")
            or self.request_id != command.get("request_id")
            or self.request_id != authorization.get("request_id")
            or self.request_id != intent.get("request_id")
            or self.idempotency_key != command.get("idempotency_key")
            or self.idempotency_key != authorization.get("idempotency_key")
            or self.idempotency_key != intent.get("idempotency_key")
            or target != source.get("target")
            or target != authorization.get("target")
            or target != intent.get("target")
            or target != claims.get("target")
            or self.root_id != command.get("root_id")
            or self.root_id != authorization.get("root_id")
            or self.root_id != intent.get("root_id")
            or self.root_id != claims.get("root_id")
            or self.root_sha256 != command.get("expected_root_sha256")
            or self.root_sha256 != authorization.get("root_sha256")
            or self.root_sha256 != intent.get("root_sha256")
            or self.root_sha256 != claims.get("root_sha256")
            or self.epoch != command.get("expected_epoch")
            or self.epoch != authorization.get("epoch")
            or self.epoch != intent.get("epoch")
            or self.epoch != claims.get("epoch")
            or self.scheduled_at != command.get("scheduled_at")
            or self.scheduled_at != authorization.get("scheduled_at")
            or self.scheduled_at != task.get("scheduled_at")
            or self.source_receipt_sha256 != apply_receipt.get("receipt_sha256")
            or self.source_receipt_sha256
            != authorization.get("source_receipt_sha256")
            or self.source_receipt_sha256 != intent.get("source_receipt_sha256")
            or self.trigger_proof_sha256 != authorization.get("trigger_proof_sha256")
            or self.trigger_proof_sha256 != intent.get("trigger_proof_sha256")
            or self.prestate_attestation_sha256
            != _canonical_embedded_contract_sha256(attestation)
            or self.prestate_attestation_sha256
            != authorization.get("prestate_attestation_sha256")
            or self.prestate_attestation_sha256
            != intent.get("prestate_attestation_sha256")
        ):
            raise ValueError("recovery dispatch storage bindings are invalid")
        if self.state is RecoveryDispatchState.PREPARED:
            if any(
                value is not None
                for value in (self.enqueue_started_at, self.terminal_at, self.result)
            ):
                raise ValueError("prepared recovery dispatch storage shape is invalid")
            return self
        if self.enqueue_started_at is None or self.enqueue_started_at < self.prepared_at:
            raise ValueError("recovery dispatch enqueue start is invalid")
        if self.state is RecoveryDispatchState.ENQUEUE_STARTED:
            if self.terminal_at is not None or self.result is not None:
                raise ValueError("started recovery dispatch storage shape is invalid")
            return self
        result = self.result
        if (
            not terminal
            or self.terminal_at is None
            or self.terminal_at < self.enqueue_started_at
            or result is None
            or result.enqueue_disposition != self.state.value
            or result.request_id != self.request_id
            or result.idempotency_key != self.idempotency_key
            or result.target != self.target
            or result.root_schema_version != authorization.get("root_schema_version")
            or result.root_id != self.root_id
            or result.root_sha256 != self.root_sha256
            or result.epoch != self.epoch
            or result.stable_revision != authorization.get("stable_revision")
            or result.stable_revision_configuration_sha256
            != authorization.get("stable_revision_configuration_sha256")
            or result.candidate_revision != authorization.get("candidate_revision")
            or result.candidate_revision_configuration_sha256
            != authorization.get("candidate_revision_configuration_sha256")
            or result.concurrency != authorization.get("concurrency")
            or result.provider_etag != authorization.get("current_provider_etag")
            or result.verified_apply_receipt.model_dump(mode="json")
            != apply_receipt
            or result.source_receipt_sha256 != self.source_receipt_sha256
            or result.trigger_basis.value != source.get("basis")
            or result.trigger_proof_sha256 != self.trigger_proof_sha256
            or result.prestate_attestation_sha256
            != self.prestate_attestation_sha256
            or result.expected_prestate_sha256
            != authorization.get("expected_prestate_sha256")
            or result.desired_poststate_sha256
            != authorization.get("desired_poststate_sha256")
            or result.proof_valid_until != authorization.get("proof_valid_until")
            or result.recovery_authorization_sha256
            != self.recovery_authorization_sha256
            or result.capability_id != self.capability_id
            or result.capability_sha256
            != _canonical_embedded_contract_sha256(capability)
            or result.task_id != task.get("task_id")
            or result.task_name != self.task_name
            or result.scheduled_at != self.scheduled_at
            or result.expires_at != task.get("expires_at")
        ):
            raise ValueError("terminal recovery dispatch storage shape is invalid")
        return self


def _recovery_dispatch_domain_record(
    stored: RecoveryDispatchStorageRecordV2,
    task: RecoveryTaskRequestV2,
) -> RecoveryDispatchRecordV2:
    return RecoveryDispatchRecordV2(
        schema_version="controlgraph.recovery-dispatch-record/v2",
        dispatch_id=stored.dispatch_id,
        command_sha256=stored.command_sha256,
        recovery_authorization_sha256=stored.recovery_authorization_sha256,
        capability_id=stored.capability_id,
        request_id=stored.request_id,
        idempotency_key=stored.idempotency_key,
        target=stored.target,
        root_id=stored.root_id,
        root_sha256=stored.root_sha256,
        epoch=stored.epoch,
        scheduled_at=stored.scheduled_at,
        source_receipt_sha256=stored.source_receipt_sha256,
        trigger_proof_sha256=stored.trigger_proof_sha256,
        prestate_attestation_sha256=stored.prestate_attestation_sha256,
        task_sha256=stored.task_sha256,
        task_name=stored.task_name,
        task=task,
        state=stored.state,
        prepared_at=stored.prepared_at,
        enqueue_started_at=stored.enqueue_started_at,
        terminal_at=stored.terminal_at,
        result=stored.result,
    )


def create_recovery_dispatch_storage_record(
    record: RecoveryDispatchRecordV2,
) -> RecoveryDispatchStorageRecordV2:
    """Project a validated domain dispatch into its bounded durable shape."""

    if type(record) is not RecoveryDispatchRecordV2:
        raise TypeError("recovery dispatch storage requires an exact record")
    task_payload = canonical_json_value_bytes(
        cast(RestrictedJson, record.task.model_dump(mode="json"))
    ).decode("utf-8")
    return RecoveryDispatchStorageRecordV2(
        schema_version=RECOVERY_DISPATCH_STORAGE_RECORD_V2,
        dispatch_id=record.dispatch_id,
        command_sha256=record.command_sha256,
        recovery_authorization_sha256=record.recovery_authorization_sha256,
        capability_id=record.capability_id,
        request_id=record.request_id,
        idempotency_key=record.idempotency_key,
        target=record.target,
        root_id=record.root_id,
        root_sha256=record.root_sha256,
        epoch=record.epoch,
        scheduled_at=record.scheduled_at,
        source_receipt_sha256=record.source_receipt_sha256,
        trigger_proof_sha256=record.trigger_proof_sha256,
        prestate_attestation_sha256=record.prestate_attestation_sha256,
        task_sha256=record.task_sha256,
        task_name=record.task_name,
        task_canonical_payload=task_payload,
        state=record.state,
        prepared_at=record.prepared_at,
        enqueue_started_at=record.enqueue_started_at,
        terminal_at=record.terminal_at,
        result=record.result,
    )


def recovery_dispatch_storage_record_value(
    stored: RecoveryDispatchStorageRecordV2,
) -> RecoveryDispatchRecordV2:
    """Reconstruct and revalidate the full recovery dispatch aggregate."""

    if type(stored) is not RecoveryDispatchStorageRecordV2:
        raise TypeError("an exact recovery dispatch storage record is required")
    _canonical_recovery_task_payload(stored.task_canonical_payload)
    task = RecoveryTaskRequestV2.model_validate_json(stored.task_canonical_payload)
    return _recovery_dispatch_domain_record(stored, task)


class HealthStorageDocumentV1(StrictContractModel):
    """Exact canonical payload wrapper for one normalized health document."""

    schema_version: Literal["controlgraph.health-storage-document/v1"]
    record_kind: HealthStorageKind
    target: TargetBinding
    logical_id: Identifier
    revision: Annotated[int, Field(ge=0, le=20)]
    mutation_id: Identifier
    canonical_payload: Annotated[str, Field(min_length=2, max_length=MAX_CONTRACT_BYTES)]
    payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        _require_health_target(self.target)
        model_type: type[StrictContractModel]
        if self.record_kind is HealthStorageKind.POST_APPLY_HEALTH_ANCHOR:
            model_type = PostApplyHealthAnchorV1
        elif self.record_kind is HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF:
            model_type = SignedHealthDecisionProofV1
        elif self.record_kind is HealthStorageKind.RECOVERY_INTENT:
            model_type = RecoveryIntentV1
        elif self.record_kind is HealthStorageKind.RECOVERY_DISPATCH_IDENTITY:
            model_type = RecoveryDispatchIdentityV2
        elif self.record_kind is HealthStorageKind.RECOVERY_DISPATCH:
            model_type = RecoveryDispatchStorageRecordV2
        else:
            model_type = HealthChainManifestV1
        try:
            payload = decode_contract(self.canonical_payload, model_type)
        except ContractError as error:
            raise ValueError("health storage payload is invalid") from error
        if canonical_sha256(payload) != self.payload_sha256:
            raise ValueError("health storage payload digest does not match")
        if self.record_kind is HealthStorageKind.POST_APPLY_HEALTH_ANCHOR:
            anchor = cast(PostApplyHealthAnchorV1, payload)
            expected_logical_id = anchor.anchor_id
            expected_target = anchor.target
            expected_revision = 0
        elif self.record_kind is HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF:
            proof = cast(SignedHealthDecisionProofV1, payload)
            expected_logical_id = signed_health_proof_logical_id(
                canonical_sha256(proof)
            )
            expected_target = proof.proof.decision.target
            expected_revision = 0
        elif self.record_kind in {
            HealthStorageKind.HEALTH_CHAIN_HEAD,
            HealthStorageKind.HEALTH_CHAIN_MANIFEST,
        }:
            manifest = cast(HealthChainManifestV1, payload)
            expected_logical_id = (
                manifest.anchor_id
                if self.record_kind is HealthStorageKind.HEALTH_CHAIN_HEAD
                else manifest.chain_id
            )
            expected_target = manifest.target
            expected_revision = manifest.terminal_sequence
        elif self.record_kind is HealthStorageKind.RECOVERY_INTENT:
            intent = cast(RecoveryIntentV1, payload)
            expected_logical_id = intent.intent_id
            expected_target = intent.command.source.target
            expected_revision = 0
        elif self.record_kind is HealthStorageKind.RECOVERY_DISPATCH_IDENTITY:
            identity = cast(RecoveryDispatchIdentityV2, payload)
            expected_logical_id = recovery_dispatch_identity_logical_id(
                identity.identity_kind.value,
                identity.identity_value,
            )
            expected_target = identity.target
            expected_revision = 0
        else:
            dispatch = cast(RecoveryDispatchStorageRecordV2, payload)
            expected_logical_id = dispatch.dispatch_id
            expected_target = dispatch.target
            expected_revision = {
                RecoveryDispatchState.PREPARED: 0,
                RecoveryDispatchState.ENQUEUE_STARTED: 1,
                RecoveryDispatchState.CREATED: 2,
                RecoveryDispatchState.DUPLICATE: 2,
                RecoveryDispatchState.AMBIGUOUS: 2,
            }[dispatch.state]
        if (
            self.logical_id != expected_logical_id
            or self.target != expected_target
            or self.revision != expected_revision
        ):
            raise ValueError("health storage wrapper binding is invalid")
        return self


def health_storage_document_payload(
    document: HealthStorageDocumentV1,
) -> StrictContractModel:
    """Decode one exact health storage wrapper without aggregate-chain decoding."""

    if type(document) is not HealthStorageDocumentV1:
        raise TypeError("health storage wrapper must be exact")
    model_type: type[StrictContractModel]
    if document.record_kind is HealthStorageKind.POST_APPLY_HEALTH_ANCHOR:
        model_type = PostApplyHealthAnchorV1
    elif document.record_kind is HealthStorageKind.SIGNED_HEALTH_DECISION_PROOF:
        model_type = SignedHealthDecisionProofV1
    elif document.record_kind is HealthStorageKind.RECOVERY_INTENT:
        model_type = RecoveryIntentV1
    elif document.record_kind is HealthStorageKind.RECOVERY_DISPATCH_IDENTITY:
        model_type = RecoveryDispatchIdentityV2
    elif document.record_kind is HealthStorageKind.RECOVERY_DISPATCH:
        model_type = RecoveryDispatchStorageRecordV2
    else:
        model_type = HealthChainManifestV1
    return decode_contract(document.canonical_payload, model_type)


def health_storage_payload_fits(value: StrictContractModel) -> bool:
    """Return whether one normalized payload fits the canonical contract bound."""

    try:
        canonical_json_bytes(value)
    except (ContractError, TypeError, ValueError):
        return False
    return True


__all__ = [
    "HEALTH_CHAIN_MANIFEST_V1",
    "HEALTH_FIRESTORE_DOCUMENT_ID_DOMAIN",
    "HEALTH_PROOF_DOCUMENT_REFERENCE_V1",
    "HEALTH_STORAGE_DOCUMENT_V1",
    "RECOVERY_DISPATCH_STORAGE_RECORD_V2",
    "HealthChainManifestV1",
    "HealthProofDocumentReferenceV1",
    "HealthStorageDocumentV1",
    "HealthStorageKind",
    "RecoveryDispatchStorageRecordV2",
    "create_health_chain_manifest",
    "create_recovery_dispatch_storage_record",
    "health_anchor_document_id",
    "health_chain_head_document_id",
    "health_chain_manifest_components_sha256",
    "health_chain_manifest_document_id",
    "health_storage_document_payload",
    "health_storage_payload_fits",
    "ordered_health_proof_digests_sha256",
    "recovery_dispatch_document_id",
    "recovery_dispatch_identity_document_id",
    "recovery_dispatch_identity_logical_id",
    "recovery_dispatch_storage_record_value",
    "recovery_intent_document_id",
    "signed_health_proof_document_id",
    "signed_health_proof_logical_id",
]
