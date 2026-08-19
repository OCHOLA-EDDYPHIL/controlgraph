# ControlGraph Canary product contract

## Status and scope

This document freezes the version 1 product vocabulary and acceptance boundary for
ControlGraph Canary. It is a contract for implementation, not a statement that every
described component is already deployed. The current repository provides strict versioned
contracts, cross-language canonical fixtures, a pure reducer, root-scoped exact-match epoch
transitions, a local service and CLI, a console shell, and Terraform input contracts. Hosted
authority persistence, signing, task delivery, Cloud Run mutation, deterministic health
evaluation, promotion, recovery, and rendered evidence views require later implementation and
acceptance.

Version 1 controls one canary rollout for one Cloud Run service in one Google Cloud project and
region. It is not a general deployment system, workflow engine, graph engine, or authorization
platform.

## Product invariant

A Cloud Run mutation is admissible only when all of the following facts are proven:

1. the workload caller is authenticated for the protected handler;
2. the request carries a canonical, correctly signed, unexpired capability;
3. every capability binding exactly matches the environment, service, rollout root, action,
   plan, target revision, request identity, and provider precondition;
4. any child authority is equal to or narrower than its parent and terminates at the approved
   rollout root;
5. a fresh authoritative read immediately before mutation reports the exact epoch signed into
   the capability; and
6. the execution receipt permits this exact canonical request to proceed.

A stale or future epoch never grants authority. Missing, malformed, uncertain, or mismatched
authority fails closed. Authentication, a valid signature, queue admission, and IAM permission
are necessary controls, but none is sufficient mutation authority by itself.

## Versioned actors

The actor identifiers below are stable vocabulary. Runtime identity and IAM bindings are
separate implementation concerns.

| Actor identifier | Responsibility | Forbidden authority |
|---|---|---|
| `controlgraph.operator/v1` | Approve a root, request a rollout action, and explicitly revoke an epoch. | Cannot bypass capability validation or choose an arbitrary executor target. |
| `controlgraph.api/v1` | Authenticate operator requests, validate public contracts, and expose narrow application operations. | Cannot mutate Cloud Run or sign capabilities. |
| `controlgraph.cli/v1` | Submit explicit operator requests to the authenticated API and render machine-readable results. | Cannot write authority storage or call the Cloud Run Admin API directly. |
| `controlgraph.console/v1` | Present read-only operator information obtained from the API. | Cannot hold cloud credentials, sign authority, or invoke cloud control-plane APIs. |
| `controlgraph.coordinator/v1` | Reduce accepted events into deterministic next commands and request bounded issuance or delivery. | Cannot approve authority, mutate Cloud Run, or reinterpret model output as a decision. |
| `controlgraph.issuer/v1` | Construct canonical, attenuated capability claims and request signatures from the configured KMS key version. | Cannot mutate Cloud Run or use a caller-selected key. |
| `controlgraph.executor/v1` | Validate an execution request, recheck authority, claim a receipt, and invoke the narrow canary adapter once. | Cannot deploy images, retarget another service, or retry an ambiguous mutation blindly. |
| `controlgraph.recovery/v1` | Restore only the captured stable configuration under separately scoped recovery authority. | Cannot promote a candidate or select an arbitrary revision. |
| `controlgraph.verifier/v1` | Read the target independently and classify an observed postcondition. | Cannot mutate the target or grant authority. |
| `controlgraph.target/v1` | Provide the disposable Cloud Run service and immutable revisions used by acceptance. | Has no ControlGraph authority. |
| `controlgraph.advisor/v1` | Optionally summarize already recorded facts through an integration boundary. | Cannot decide health, safety, authority, rollout, promotion, recovery, or revocation. |

## Versioned records

Every record crossing a process, trust, persistence, or language boundary carries one exact
schema version. The first implementation uses these logical record families:

| Record | Required meaning |
|---|---|
| `controlgraph.target-binding/v1` | Exact project, region, service, and environment identity. |
| `controlgraph.stable-snapshot/v1` | Captured stable revision, traffic, concurrency, provider resource version, and canonical configuration digest. |
| `controlgraph.rollout-root/v1` | Immutable approved snapshot, candidate, plan, policies, recovery bounds, and maximum authority. |
| `controlgraph.epoch-authority/v1` | Current epoch and monotonic transition metadata for one root. |
| `controlgraph.capability-claims/v1` | Narrow action authority, identity bindings, lineage, times, request identity, plan digest, and provider precondition. |
| `controlgraph.signed-capability/v1` | Claims plus the configured algorithm, exact KMS key version, and signature. |
| `controlgraph.mutation-intent/v1` | One exact target change derived from the immutable root. |
| `controlgraph.task-request/v1` | Addressed delivery of one signed mutation intent. |
| `controlgraph.execution-receipt/v1` | Durable request binding and execution classification. |
| `controlgraph.health-input/v1` | Bounded observations supplied to deterministic health policy. |
| `controlgraph.recovery-plan/v1` | Restore-only plan bound to the captured stable snapshot. |
| `controlgraph.evidence-event/v1` | Ordered, immutable statement about an authority or execution fact. |

Canonical encodings and digests are version-bound. Unknown critical fields, duplicate keys,
ambiguous numbers or timestamps, noncanonical input, and cross-field inconsistencies are
rejected before trust is established.

## Versioned commands

Commands are closed canary-domain operations. An implementation must not accept a cloud API
method, URL, resource path, or arbitrary field mask in place of one of these commands.

| Command | Meaning |
|---|---|
| `CAPTURE_STABLE_V1` | Read and confirm an eligible 100 percent stable baseline. |
| `CREATE_ROLLOUT_ROOT_V1` | Atomically create an immutable root, initial authority, and service claim. |
| `APPLY_CANARY_V1` | Set the approved stable/candidate revisions to the exact 90/10 plan. |
| `EVALUATE_HEALTH_V1` | Apply deterministic policy to bounded, versioned health inputs. |
| `PROMOTE_CANDIDATE_V1` | Set 100 percent traffic to the approved candidate. |
| `RECOVER_STABLE_V1` | Restore only the captured stable traffic and approved concurrency. |
| `REVOKE_EPOCH_V1` | Compare and advance the root epoch with an operator reason and request identity. |
| `VERIFY_TARGET_V1` | Independently read and classify the target configuration. |

## Rollout states and transitions

The reducer consumes an explicit prior state and ordered event. It performs no clock, model,
network, storage, queue, or cloud operation.

| State | Meaning | Permitted next direction |
|---|---|---|
| `ROOT_PENDING` | Snapshot and approval inputs are being validated. | `ROOT_ACTIVE`, `DENIED`, or `FAILED_SAFE`. |
| `ROOT_ACTIVE` | Immutable root and current authority exist; no canary mutation is pending. | `CANARY_PENDING` or `REVOKED`. |
| `CANARY_PENDING` | An approved 90/10 intent may be issued and executed. | `CANARY_OBSERVING`, `DENIED`, `AMBIGUOUS`, `FAILED_SAFE`, or `REVOKED`. |
| `CANARY_OBSERVING` | Independent readback has confirmed 90/10 and health inputs may be evaluated. | `PROMOTION_PENDING`, `RECOVERY_PENDING`, or `REVOKED`. |
| `PROMOTION_PENDING` | An approved candidate-promotion intent may be executed. | `PROMOTED`, `DENIED`, `AMBIGUOUS`, `FAILED_SAFE`, or `REVOKED`. |
| `RECOVERY_PENDING` | A restore-only intent for the captured stable snapshot may be executed. | `RECOVERED`, `DENIED`, `AMBIGUOUS`, `FAILED_SAFE`, or `REVOKED`. |
| `PROMOTED` | Independent readback proves the approved candidate receives 100 percent traffic. | Terminal after service-claim release requirements are met. |
| `RECOVERED` | Independent readback proves the captured stable configuration was restored. | Terminal after service-claim release requirements are met. |
| `REVOKED` | The root epoch advanced and capabilities at the prior epoch are stale. | No further mutation at the revoked epoch; recovery requires separately current authority. |
| `DENIED` | A command was rejected before its protected side effect. | Terminal for that command. |
| `FAILED_SAFE` | A known failure occurred without an admitted target mutation. | Terminal for that command unless an explicit new command is approved. |
| `AMBIGUOUS` | A provider request may have taken effect and exact readback is required. | `PROMOTED`, `RECOVERED`, `CANARY_OBSERVING`, or an explicit unresolved terminal classification after readback. |

Invalid transitions return `TRANSITION_INVALID` and emit no mutation command. Missing
authorization or epoch facts return a denial rather than being inferred.

## Receipt outcomes

An execution receipt is bound to the capability digest, rollout root, epoch, action, target,
provider precondition, plan digest, canonical mutation digest, and idempotency key.

| Outcome | Completion rule |
|---|---|
| `CLAIMED` | One exact request owns the right to attempt its next safe phase. It is not success. |
| `DENIED` | Validation or authority failed and the mutation adapter was not called. |
| `APPLIED` | The provider returned a known accepted result; independent verification is still required. |
| `VERIFIED` | Independent readback matches the exact approved postcondition. |
| `FAILED_SAFE` | The operation is known not to have produced the protected effect. |
| `AMBIGUOUS` | The provider outcome is unknown; no blind retry is permitted. |

An exact duplicate may return the existing receipt. Reuse of an idempotency key with a different
canonical request is denied. An ambiguous receipt is never converted to success merely because a
request was accepted or timed out.

## Stable reason codes

Public failures return a stable code and a bounded, non-sensitive explanation. The initial code
families are:

| Code | Meaning |
|---|---|
| `CONTRACT_INVALID` | The record is malformed, oversized, ambiguous, or noncanonical. |
| `CONTRACT_VERSION_UNSUPPORTED` | A schema version is not supported. |
| `CALLER_UNAUTHENTICATED` | Workload identity could not be verified. |
| `CALLER_UNAUTHORIZED` | The verified identity is not permitted for this route or role. |
| `SIGNATURE_INVALID` | The configured key version did not verify the canonical claims. |
| `KEY_VERSION_UNTRUSTED` | The claimed algorithm or key version is not in the configured trust set. |
| `CAPABILITY_EXPIRED` | The capability lifetime ended. |
| `CAPABILITY_NOT_YET_VALID` | The capability is not valid at the supplied evaluation time. |
| `CLAIM_BINDING_MISMATCH` | A caller, audience, plan, request, or handler binding differs. |
| `TARGET_BINDING_MISMATCH` | Project, region, environment, service, revision, or provider precondition differs. |
| `LINEAGE_INVALID` | Capability ancestry is missing, cyclic, unknown, or inconsistent. |
| `SCOPE_AMPLIFICATION` | A child attempts to widen its parent's authority. |
| `AUTHORITY_UNAVAILABLE` | Current authority cannot be read or validated. |
| `EPOCH_MISMATCH` | The signed epoch is not exactly current. |
| `IDEMPOTENCY_CONFLICT` | A request identity or key was reused for different canonical work. |
| `RECEIPT_IN_PROGRESS` | Another exact delivery already owns the safe execution phase. |
| `PROVIDER_PRECONDITION_FAILED` | The target changed from the approved snapshot. |
| `PROVIDER_OUTCOME_AMBIGUOUS` | A provider response cannot prove whether the mutation committed. |
| `TRANSITION_INVALID` | The requested state transition is not legal. |
| `POLICY_UNHEALTHY` | Deterministic health policy selected restore-only recovery. |

More specific subcodes may be added only under a new compatible contract version; existing code
meanings must not be repurposed.

## Journey branches

All branches start by capturing an exact stable configuration, confirming the same provider
resource version on a second read, claiming the service, and creating an immutable rollout root
at epoch 1. Later steps refer to its then-current value as epoch N.

### Healthy branch

The system issues an `APPLY_CANARY_V1` capability at epoch N, validates it at execution, rechecks
epoch N immediately before the mutation, conditionally applies 90/10, and independently verifies
the split. Versioned health inputs may then select `PROMOTE_CANDIDATE_V1`; completion requires an
independent read proving 100 percent traffic on the approved candidate.

### Unhealthy branch

Deterministic health policy may select `RECOVER_STABLE_V1`. Recovery authority is limited to the
captured stable revision and configuration. Completion requires an independent read proving that
the captured stable state was restored. No model or recovery worker may select a different
revision or promote the candidate.

### Revocation branch

An authenticated operator submits `REVOKE_EPOCH_V1` with the root, expected epoch, reason,
request identity, and explicit confirmation. A successful compare-and-advance records N+1. A
delayed capability issued at N may still pass caller and signature checks, but it must receive
`EPOCH_MISMATCH` at the fresh authority check and produce a `DENIED` receipt without calling the
Cloud Run mutation adapter.

These branches define acceptance targets. They do not claim that hosted health, promotion,
recovery, or revocation is present in the current scaffold.

## Non-goals

Version 1 does not provide arbitrary deployments, image selection, multi-cloud control,
multi-region authority, a general graph abstraction, Pub/Sub orchestration, an external policy
engine, autonomous model decisions, or direct cloud control from the console. Product-submission
workflow state and temporary delivery status do not belong in the product contract.

The architecture, threat model, native-cloud comparison, and acceptance cases refine this
contract without widening it.
