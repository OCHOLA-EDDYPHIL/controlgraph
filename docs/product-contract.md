# ControlGraph Canary product contract

## Status and scope

This document freezes the version 1 product vocabulary and acceptance boundary for
ControlGraph Canary. It is a contract for implemented behavior, not evidence that any particular
revision has passed hosted acceptance. The repository implements canonical contracts,
root-scoped epoch authority, authenticated role composition, KMS signing, Firestore claims and
receipts, addressed Cloud Tasks delivery, target-bound Cloud Run execution and readback,
deterministic Monitoring health evaluation, healthy promotion, and captured-stable recovery.
The current console remains read-only and static; a rendered operator evidence timeline is
outside this implementation boundary.

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
| `controlgraph.executor/v1` | Independently validate normal execution or recovery-facade work, recheck authority, claim the matching receipt, and invoke the purpose-bound adapter once. | Cannot deploy images, retarget another service, or retry an ambiguous mutation blindly. |
| `controlgraph.recovery/v1` | Validate a recovery delivery and forward its unchanged canonical task once to the executor's recovery-only facade. | Has no direct target update, target service-account impersonation, operation-read, or promotion authority. |
| `controlgraph.verifier/v1` | Read Monitoring and target state independently, evaluate health, and produce signed health or recovery-prestate evidence through the evidence writer. | Cannot mutate the target or grant authority. |
| `controlgraph.target/v1` | Provide the disposable Cloud Run service and immutable revisions used by acceptance. | Has no ControlGraph authority. |
| `controlgraph.advisor/v1` | Optionally summarize already recorded facts through an integration boundary. | Cannot decide health, safety, authority, rollout, promotion, recovery, or revocation. |

## Versioned records

Every record crossing a process, trust, persistence, or language boundary carries one exact
schema version. The implementation uses these logical record families:

| Record | Required meaning |
|---|---|
| `controlgraph.target-binding/v1` | Exact project, region, service, and environment identity. |
| `controlgraph.stable-snapshot/v1` | Captured stable revision, traffic, concurrency, provider resource version, and canonical configuration digest. |
| `controlgraph.rollout-root/v2` and `/v3` | Immutable approved snapshot, candidate, plan, policies, recovery bounds, and maximum authority; V3 includes the frozen Monitoring health policy. |
| `controlgraph.epoch-authority/v1` | Current epoch and monotonic transition metadata for one root. |
| `controlgraph.capability-claims/v1` | Narrow action authority, identity bindings, lineage, times, request identity, plan digest, and provider precondition. |
| `controlgraph.signed-capability/v1` | Claims plus the configured algorithm, exact KMS key version, and signature. |
| `controlgraph.mutation-intent/v1`, `controlgraph.promotion-mutation-intent/v2`, and `controlgraph.recovery-mutation-intent/v2` | One exact target change derived from the immutable root. |
| `controlgraph.task-request/v1`, `controlgraph.promotion-task-request/v2`, and `controlgraph.recovery-task-request/v2` | Addressed delivery of one signed mutation intent. |
| `controlgraph.execution-receipt/v1` | Durable request binding and execution classification. |
| `controlgraph.monitoring-metric-query/v1` and related sample/observation records | Exact candidate-revision Monitoring queries and canonical one-minute observations. |
| `controlgraph.health-decision/v1` and signed proof records | Deterministic decision, complete input citations, prior state, and signed chain linkage. |
| `controlgraph.unhealthy-recovery-source/v1`, `controlgraph.revoked-v2-recovery-source/v1`, and `controlgraph.revoked-v3-recovery-source/v1` | Disjoint recovery triggers for automatic terminal-unhealthy V3 recovery and explicitly confirmed recovery of revoked V2 or V3 roots. |
| Recovery intent, authorization, prestate, task, and dispatch records | Root-owned restore-only work bound to the captured stable snapshot, source receipt, trigger proof, current epoch, and addressed task. |
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
| `RECOVER_STABLE_V1` | Route 100 percent of traffic only to the captured stable revision while requiring approved concurrency to remain unchanged. |
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

An execution receipt is bound to the request identity, capability digest, rollout root, epoch,
action, target, provider precondition, plan digest, canonical mutation digest, expected canonical
post-state digest, and idempotency key.

| Outcome | Completion rule |
|---|---|
| `CLAIMED` | A directly confirmed fresh create may carry one process-local dispatch lease. The stored record alone grants no later dispatch authority and is not success. |
| `DENIED` | Validation or authority failed and the mutation adapter was not called. |
| `APPLIED` | The provider returned a known accepted result; independent verification is still required. |
| `VERIFIED` | Independent readback matches the exact approved postcondition. |
| `FAILED_SAFE` | The operation is known not to have produced the protected effect. |
| `AMBIGUOUS` | The provider outcome is unknown; no blind retry is permitted. |

An exact duplicate may return the existing receipt. Reuse of an idempotency key with a different
canonical request is denied. An ambiguous receipt is never converted to success merely because a
request was accepted or timed out. A persisted claim is never replayed as a mutation attempt;
after its dispatch deadline, recovery is readback-only.

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
| `TRANSPORT_UNAVAILABLE` | Bounded delivery attempts ended before provider dispatch was possible. |
| `PROVIDER_PRECONDITION_FAILED` | The target changed from the approved snapshot. |
| `PROVIDER_REQUEST_REJECTED` | The provider rejected the bounded request before producing the protected effect. |
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
the split. The verifier derives exact one-minute candidate-revision Monitoring queries from the
root, canonicalizes their samples, and applies the frozen thresholds and consecutive-window
rules. A signed terminal healthy proof may authorize `PROMOTE_CANDIDATE_V1`; completion requires
an independent read proving 100 percent traffic on the approved candidate.

### Unhealthy branch

A signed terminal unhealthy proof is appended atomically with the root-owned recovery intent.
The coordinator derives one deterministic dispatch identity, obtains a KMS-signed recovery
capability and signed verifier prestate, and addresses `RECOVER_STABLE_V1` to the recovery queue.
The recovery service verifies and forwards the unchanged task once; it never mutates Cloud Run.
The executor's separate recovery-only facade independently reverifies the task and uses a
separate recovery receipt route before one conditional traffic-only update naming the captured
stable revision at 100 percent. Completion requires exact independent readback, including
unchanged approved concurrency. A model, recovery worker, or caller cannot select another revision
or promote the candidate.

A revoked V3 root has a separate, operator-only recovery source; the health pipeline never emits
it automatically. It is admissible only when the current authority exactly equals a signed
operator-revocation proof for N to N+1, an exact verified `APPLY_CANARY_V1` receipt is at the
direct predecessor epoch N and is no later than the revocation commit, and a fresh signed prestate
proves the exact root-derived 90/10 configuration at N+1. The operator must explicitly confirm
`RECOVER_CAPTURED_STABLE` but cannot choose the recovery revision. The current N+1 authority is
used to issue a new stable-only recovery capability; no capability from N is revived. After a
verified recovery, service-claim release remains a separate authenticated operation.

### Revocation branch

An authenticated operator submits `REVOKE_EPOCH_V1` with the root, expected epoch, reason,
request identity, and explicit confirmation. A successful compare-and-advance records N+1. A
delayed capability issued at N may still pass caller and signature checks, but it must receive
`EPOCH_MISMATCH` at the fresh authority check and produce a `DENIED` receipt without calling the
Cloud Run mutation adapter.

These branches define acceptance targets. Their implementation in a source revision does not by
itself claim that the same revision has passed hosted acceptance.

## Non-goals

Version 1 does not provide arbitrary deployments, image selection, multi-cloud control,
multi-region authority, a general graph abstraction, Pub/Sub orchestration, an external policy
engine, autonomous model decisions, or direct cloud control from the console. Product-submission
workflow state and temporary delivery status do not belong in the product contract.

The architecture, threat model, native-cloud comparison, and acceptance cases refine this
contract without widening it.
