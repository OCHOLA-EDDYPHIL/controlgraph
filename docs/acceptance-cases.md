# Build acceptance cases

## Status and evidence rule

These cases define the reproducible outcomes against which the built product is evaluated. They
are specifications, not records of completed hosted runs. The current scaffold does not satisfy
the hosted cases.

Local fakes and contract tests are required development evidence, but they do not replace a case
that explicitly calls for Cloud Run, Cloud KMS, Firestore, Cloud Tasks, or Google-issued identity.
A hosted result is attributable only to the exact accepted source revision and isolated
environment that produced it.

Every case records, without credentials or raw tokens:

- source revision and contract versions;
- bound project, region, environment, and service identifiers in an appropriately sanitized
  evidence location;
- rollout-root digest, issue epoch, current epoch, action, request identity, and capability digest;
- ordered authority, receipt, provider-operation, and verification events;
- target configuration before and after the attempted action; and
- one terminal classification from the product contract.

Rendered UI output is not required evidence for these cases. Ordered records, API or CLI output,
and independent provider readback are sufficient when their identities and digests agree.

## Common initial conditions

Hosted cases use one disposable, non-production Cloud Run target in one explicit project and
region. It has immutable stable and candidate revisions with harmless, distinguishable probe
markers. The stable revision initially receives 100 percent traffic. Neither revision contains
customer data or an external side effect.

The environment uses distinct service identities, private protected handlers, a dedicated
Firestore authority boundary, explicit KMS key versions, and a regional Cloud Tasks queue. All
container references are immutable digests. The target is reset and independently read before
each case.

## Case A: healthy canary and promotion

This is the normative positive journey for deterministic health and promotion. It does not claim
that hosted health evaluation or promotion exists in the current scaffold.

### Initial state

- Stable revision S is ready and receives 100 percent traffic.
- Candidate revision C is ready and receives 0 percent traffic.
- Two exact service reads agree on the provider resource version.
- No active rollout claim exists for the target.

### Operator action

The operator approves an immutable root containing the stable snapshot, candidate C, exact 90/10
plan, deterministic health policy, promotion bound, recovery bound, and initial epoch N.

### Expected data path

1. Root, service claim, and epoch-N authority are created atomically.
2. The issuer signs an `APPLY_CANARY_V1` capability bound to S, C, 90/10, the captured provider
   precondition, root digest, request identity, and epoch N.
3. Cloud Tasks delivers the command under the expected OIDC caller.
4. The executor verifies caller, signature, claims, lineage, scope, target, plan, and request.
5. The executor claims the exact receipt, freshly confirms epoch N, and submits one conditional
   traffic update.
6. Independent readback observes exactly 90 percent S and 10 percent C before health observation
   begins.
7. Bounded health inputs satisfy deterministic policy.
8. A separately scoped `PROMOTE_CANDIDATE_V1` command passes the same gates and independent
   readback observes 100 percent C.

### Expected evidence

- immutable root and initial epoch records;
- canary capability digest, receipt, provider operation, and verified 90/10 readback;
- versioned health inputs and deterministic healthy classification;
- promotion capability digest, receipt, provider operation, and verified 100 percent C readback;
- no unexpected target field or revision change.

### Terminal classification

`PROMOTED` with a `VERIFIED` promotion receipt. A request acceptance response without independent
readback does not satisfy the case.

### Native and added guarantees

Cloud Run supplies immutable revisions, conditional traffic update, and exact readback. IAM,
OIDC, KMS, Firestore, and Cloud Tasks provide their native identity, signing, transaction, and
delivery controls. ControlGraph adds the immutable approval boundary, attenuated capability,
execution-time epoch check, exact receipt, and deterministic state transition.

## Case B: unhealthy canary and stable recovery

This is the normative recovery journey. It remains an acceptance specification until hosted
deterministic health and recovery behavior is implemented and exercised.

### Initial state

- A root at epoch N has a verified 90/10 split between captured stable revision S and candidate C.
- The root fixes the health policy and a recovery plan that can restore only the captured stable
  traffic and approved concurrency.
- The recovery identity has no candidate-promotion authority.

### Operator action

The operator permits the approved health window to be evaluated. No model response or free-form
operator text can select the outcome.

### Expected data path

1. Bounded, versioned observations fail the deterministic health policy.
2. The reducer emits `RECOVER_STABLE_V1` and no promotion command.
3. The issuer creates a recovery capability bound to S, the captured configuration, root, current
   epoch N, request identity, and provider precondition.
4. The recovery handler verifies the dedicated caller and complete capability, claims its receipt,
   and freshly confirms epoch N.
5. The restore-only adapter performs one conditional update.
6. Independent readback observes 100 percent traffic on S and the captured approved concurrency.

### Expected evidence

- exact health inputs and `POLICY_UNHEALTHY` decision;
- absence of any promotion capability or command;
- restore-only capability, receipt, provider operation, and verified stable readback;
- attempts to substitute C or another revision are separately denied with zero mutation.

### Terminal classification

`RECOVERED` with a `VERIFIED` recovery receipt. If the provider result is uncertain, the terminal
classification remains `AMBIGUOUS` until exact independent readback resolves it; the mutation is
not retried merely because the response was lost.

### Native and added guarantees

Cloud Run provides conditional update and configuration readback. ControlGraph adds deterministic
health-to-command reduction, a recovery-only authority scope, binding to the captured stable
revision, execution-time epoch validation, and explicit ambiguity handling.

## Case C: delayed stale task after manual revocation

This is the signature revocation case. The delayed action must be one that would visibly change
the current target if it executed; a duplicate request for an already-applied 90/10 split is not
sufficient evidence.

### Initial state

- S and C have a verified 90/10 traffic split under an active immutable root at epoch N.
- A valid `PROMOTE_CANDIDATE_V1` capability is signed at epoch N and bound to an exact request,
  target, plan, and current provider precondition.
- The addressed Cloud Tasks delivery is held before the protected handler executes.

### Operator action

The authenticated operator uses the CLI, which calls the authenticated API, to submit the root,
expected epoch N, reason, request identity, and explicit confirmation. The authority transaction
advances the root to N+1. The held task is then released.

### Expected data path

1. The task reaches the executor under the expected Cloud Tasks OIDC caller.
2. Caller authentication succeeds.
3. Canonical decoding, configured KMS signature verification, time, lineage, scope, action,
   target, plan, and request checks succeed.
4. The fresh authoritative read returns N+1 rather than signed epoch N.
5. Execution returns `EPOCH_MISMATCH`, records a `DENIED` receipt, and does not call the Cloud Run
   adapter.
6. Independent Cloud Run readback still observes exactly 90 percent S and 10 percent C.

### Expected evidence

- issuance event at N and exact capability digest;
- operator revocation request, N-to-N+1 transition, and revocation evidence identifier;
- successful caller and signature stages without credential material;
- stale-epoch receipt containing issue epoch N, current epoch N+1, and `EPOCH_MISMATCH`;
- no provider mutation operation for the delayed request; and
- before-and-after target reads with the same 90/10 traffic allocation.

### Terminal classification

The delayed command is `DENIED`; the rollout root is `REVOKED` for epoch-N work. The case must not
depend on task deletion, task expiry, capability expiry, invalid signature, queue failure, a test
bypass, or a mocked Cloud Run mutation.

### Native and added guarantees

Cloud Tasks and OIDC prove addressed delivery by the configured caller, KMS proves signature
integrity, and Cloud Run provides target readback. ControlGraph adds the separate current-authority
decision that makes otherwise valid delayed work harmless.

## Negative-authority conformance

The built enforcement path also exercises at least these single-variable failures:

- malformed or noncanonical claims;
- tampered payload or invalid signature;
- untrusted key version or algorithm;
- wrong issuer, subject, audience, caller, or handler;
- expired or not-yet-valid capability;
- cross-project, cross-region, cross-environment, or cross-service substitution;
- widened child authority or invalid lineage;
- arbitrary revision, URL, resource path, method, or field-mask injection;
- wrong provider precondition;
- duplicate exact delivery;
- one idempotency key with different canonical content; and
- missing, corrupt, or unavailable authority storage.

Each denial asserts the stable reason, durable receipt where applicable, zero target-adapter
invocations, and unchanged target configuration. These cases verify the product contract; they
are not product-kill, falsification, or ablation gates.
