# Acceptance cases

## Status and evidence rule

These cases define the reproducible outcomes used to evaluate ControlGraph. They are
specifications. Accepted-run records are separate, and implementation alone does not prove a
hosted result.

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

This is the normative positive journey for deterministic health and promotion.

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
7. The verifier derives the root's exact candidate-revision request-count and latency queries,
   canonicalizes bounded Monitoring results, and evaluates the frozen one-minute-window policy.
8. Two consecutive healthy windows produce a signed terminal proof whose complete chain
   authorizes a separately scoped `PROMOTE_CANDIDATE_V1` command.
9. The normal executor applies the promotion through its receipt path, and independent readback
   observes 100 percent C.

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

This is the normative recovery journey.

### Initial state

- A root at epoch N has a verified 90/10 split between captured stable revision S and candidate C.
- The root fixes the health policy and a recovery plan that can route traffic only to the captured
  stable revision while requiring approved concurrency to remain unchanged.
- The recovery identity has no target update, reference-target `actAs`, operation-read, receipt
  write, or candidate-promotion authority.

### Operator action

The operator permits the approved health window to be evaluated. No model response or free-form
operator text can select the outcome.

### Expected data path

1. Exact candidate-revision Monitoring observations produce two consecutive deterministic
   unhealthy decisions, ending in a signed terminal proof.
2. One Firestore transaction appends that terminal proof and creates one root-owned recovery
   intent. Concurrent evaluators adopt the same intent rather than creating another command.
3. The coordinator advances the deterministic recovery dispatch record, obtains a signed verifier
   prestate and a KMS-signed capability bound to S, and addresses one canonical recovery task.
4. The recovery handler verifies the dedicated task caller, capability, root, epoch, source
   receipt binding, signed prestate, and exact target, then forwards the unchanged task once to
   the executor's recovery-only facade.
5. The executor facade independently reverifies those bindings and claims through the separate
   recovery receipt route. Its final gate then rereads the exact durable source receipt, freshly
   confirms root and epoch N, and permits one conditional traffic update containing only S at
   100 percent.
6. Independent readback observes only S at 100 percent traffic and confirms that the captured
   approved concurrency is unchanged.

### Expected evidence

- exact health inputs and `POLICY_UNHEALTHY` decision;
- absence of any promotion capability or command;
- atomic health-proof and recovery-intent ownership, deterministic dispatch identity, and signed
  recovery prestate;
- restore-only capability, separate recovery receipt, provider operation, and verified stable
  readback;
- attempts to substitute C or another revision are separately denied with zero mutation.

### Terminal classification

`RECOVERED` with a `VERIFIED` recovery receipt. If the provider result is uncertain, the terminal
classification remains `AMBIGUOUS` until exact independent readback resolves it; the mutation is
not retried merely because the response was lost.

### Native and added guarantees

Cloud Run provides conditional update and configuration readback. ControlGraph adds deterministic
health-to-command reduction, transactional single-intent ownership, recovery-to-executor privilege
separation, binding to the captured stable revision, execution-time epoch validation, and explicit
ambiguity handling.

## Case B2: explicitly recover a revoked V3 canary

This is the bounded recovery path for a V3 rollout that an operator revoked while its exact 90/10
canary remained deployed. It is not an automatic consequence of revocation.

### Initial state

- The immutable V3 root captured stable revision S and candidate C, and an exact
  `APPLY_CANARY_V1` receipt is `VERIFIED` at epoch N for the exact 90/10 configuration.
- A signed operator-revocation proof records the direct N-to-N+1 transition and exactly matches the
  current authority record.
- Fresh verifier readback still observes the root-derived S/C revisions, approved concurrency, and
  exact 90/10 traffic split.

### Operator action

The authenticated operator submits the root-bound recovery command and explicitly confirms
`RECOVER_CAPTURED_STABLE`. The command contains no selectable recovery revision.

### Expected data path and evidence

1. The API admits only the explicit revoked-V3 source and preserves the operator identity bound by
   the revocation proof; an automatic unhealthy command cannot enter this route.
2. The coordinator claims or adopts one root-unique intent. The resolver and issuer each reread
   current authority, require equality with the signed N-to-N+1 proof, verify its exact evidence
   key and signature, and require the exact verified APPLY receipt at direct predecessor N to be
   no later than the revocation commit.
3. A fresh signed prestate attests the exact root-derived 90/10 configuration at N+1. The normal
   stable-only recovery task, facade, separate receipt route, final authority read, conditional
   target update, and independent readback then apply unchanged.
4. Only captured stable revision S receives 100 percent traffic. The recovery receipt is
   `VERIFIED`; the operator may then invoke the separate authenticated service-claim release flow.

Stale or later authority, a non-predecessor or post-revocation receipt, wrong proof key or
signature, missing confirmation, cross-root source, or any selected revision is denied before
mutation. Epoch-N capability authority remains revoked throughout.

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

## Authority-boundary conformance

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
