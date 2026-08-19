# Threat model

## Status

This threat model defines the required security boundary for ControlGraph Canary. Controls named
as requirements are not claims that the current scaffold has deployed them. The implemented
scaffold currently provides only local exact-match epoch validation, read-only HTTP endpoints,
and configuration contracts; it has no durable authority store, signing path, task delivery, or
Cloud Run mutation capability.

## Protected assets and safety outcomes

The protected assets are:

- the traffic and approved concurrency configuration of one bound Cloud Run service;
- immutable rollout roots and stable snapshots;
- the current epoch for each rollout root;
- KMS signing authority and public trust material;
- execution receipts and evidence records; and
- workload and operator identity bindings.

The primary safety outcome is that delayed, replayed, tampered, expired, misbound, overbroad, or
revoked work cannot reach the Cloud Run mutation adapter. When a provider response is uncertain,
the outcome remains explicit and no blind retry is performed.

ControlGraph protects control-plane mutation authorization. It does not claim to secure arbitrary
application code, eliminate all Google Cloud compromise, or make a Firestore epoch read and a
Cloud Run update one atomic transaction.

## Trust boundaries and data flow

```text
Operator identity
      |
      | authenticated, versioned API request
      v
API boundary -----> deterministic application facade and reducer
                          |
                          | bounded issuance request
                          v
                    Issuer identity -----> Cloud KMS boundary
                          |
                          | canonical signed capability
                          v
                    Coordinator boundary
                          |
                          | addressed task + dedicated OIDC caller
                          v
Cloud Tasks boundary ---> Executor or recovery ingress boundary
                                |
                                | caller, signature, lineage, scope,
                                | binding, time, request checks
                                v
                         Firestore authority boundary
                                |
                                | fresh exact-epoch result and receipt claim
                                v
                         Narrow Cloud Run Admin API adapter
                                |
                                | conditional provider update
                                v
                         Bound Cloud Run target

Verifier identity ------ independent read ------> Bound Cloud Run target
Cloud Monitoring ------- bounded observations --> Deterministic policy input
Evidence writer -------- append facts ----------> Evidence boundary
Console ---------------- read-only API ----------> Operator information
Optional Gemini/ADK advisor -- bounded read-only facade; never enters the authority path
```

### Identity boundary

Operator, API, coordinator, issuer, executor, recovery, verifier, and task-caller identities are
distinct. Cloud Run IAM determines who may invoke a service; application OIDC verification then
checks exact issuer, audience, expiry, subject, and allowed service-account or operator identity.
A verified caller still requires a valid capability.

### Network boundary

Internal services admit only intended authenticated callers. The operator API may be reachable
through an authenticated endpoint, but it has no public unauthenticated business route. The
console never invokes Google Cloud control-plane APIs directly.

### Firestore authority boundary

Rollout roots are immutable. Service claims, current epochs, and receipts use fixed canonical
document identities and transactional compare-and-set operations. Reads used to authorize a
mutation are strongly consistent and never fall back to a cache. An unavailable or corrupt record
denies mutation.

### KMS boundary

Private signing material remains inside Cloud KMS. Capability and evidence signing use separate
keys and explicit key versions. The issuer can request a signature for configured canonical
payloads but cannot administer keys or mutate Cloud Run. Executors trust only configured key
versions and algorithms; capabilities cannot supply a new public key or key URL.

### Task-delivery boundary

Cloud Tasks authenticates delivery with a dedicated OIDC identity and fixed audience. Queue
admission identifies an addressed delivery, not authority to perform its requested action.
Capabilities remain independently validated after delivery, including duplicate and delayed
delivery.

### Cloud Run mutation boundary

The adapter is constructed for one configured project, region, and service. Its public operations
cover exact reads and the narrow traffic or approved concurrency updates required by the canary
contract. It accepts no arbitrary resource coordinate, image, environment variable, cloud API
method, or field mask. Every update carries the approved provider precondition.

### Evidence boundary

Receipts and evidence identify canonical requests and authority transitions without storing
credentials or raw tokens. Evidence integrity does not itself grant authority. Independent
readback, immutable request bindings, and signed evidence make omission or alteration detectable.

## Authority by actor

| Actor | Narrow authority | Explicit denial |
|---|---|---|
| Operator | Approve a root and explicitly compare-and-advance its epoch. | No direct target mutation or KMS use. |
| API | Authenticate requests and invoke narrow application use cases. | No signing or target mutation. |
| Coordinator | Select deterministic next commands already permitted by state and policy. | No authority approval or cloud mutation. |
| Issuer | Read approved authority and request capability signatures. | No Cloud Run permission. |
| Executor | Apply approved canary or promotion traffic after all gates. | No deploy, retarget, or arbitrary service update. |
| Recovery | Restore only the captured stable configuration. | Cannot promote, choose a revision, or widen recovery bounds. |
| Verifier | Read exact target configuration and classify it. | No mutation or authority write. |
| Task caller | Invoke one protected handler with the configured audience. | No mutation authority by identity alone. |
| Optional Gemini/ADK advisor | Summarize bounded, already recorded facts. | No health, authority, safety, rollout, recovery, or execution decision. |

## Threats, controls, and decisive tests

| Threat | Required controls | Decisive acceptance |
|---|---|---|
| Delayed work after revocation | Root-scoped epochs; fresh authoritative read immediately before mutation; no cache fallback. | Pause a valid epoch-N task, advance to N+1, release it, observe `EPOCH_MISMATCH`, zero adapter calls, and unchanged traffic. |
| Replay or duplicate delivery | Deterministic request identity; transactional receipt claim; exact canonical receipt binding. | Concurrent exact duplicates yield at most one mutation; later duplicates return the same terminal result. |
| Same key, different payload | Receipt binds capability, target, plan, precondition, and mutation digests. | Reuse with one changed field yields `IDEMPOTENCY_CONFLICT` and zero mutation. |
| Capability tampering | Canonical bytes, KMS signature verification, configured key version and algorithm. | Change every signed field in turn; each request is denied before handler logic. |
| Expired or not-yet-valid authority | Bounded lifetime and explicit supplied evaluation time with skew policy. | Boundary-time cases return the stable time reason and zero mutation. |
| Scope amplification | Closed action set; complete lineage; child must be equal or narrower across every bound. | Widen project, region, service, revision, action, traffic, concurrency, or expiry and observe `SCOPE_AMPLIFICATION`. |
| Cross-service, project, region, or environment substitution | Exact target binding in root, capability, request, route configuration, receipt, and adapter constructor. | Substitute each coordinate independently; observe a target-binding denial and zero provider calls. |
| Target-coordinate injection | Adapter exposes no unbound target parameter or general update method. | Unknown fields, resource names, URLs, methods, and field masks are rejected at contract decode. |
| Caller impersonation or confused deputy | Cloud Run IAM plus in-application OIDC checks; exact role-to-route map; capability subject and audience binding. | Missing token, wrong audience, wrong issuer, unexpected service account, and valid caller with wrong capability are all denied. |
| Stolen valid delivery token | Short token lifetime and separate capability authorization. | A valid task-caller token without the exact capability cannot enter protected execution. |
| Stale provider configuration | Immutable snapshot, second-read confirmation, canonical digest, and Cloud Run etag or equivalent precondition. | Modify the service after capture; conditional mutation fails without overwriting the new configuration. |
| Ambiguous Cloud Run write | One provider attempt; durable `AMBIGUOUS` receipt; exact independent readback; no blind retry. | Inject timeout after possible commit and prove only exact readback can classify the result. |
| Ambiguous Firestore write | Mutation identity, canonical wrapper, exact readback, and explicit unknown outcome. | Lose the commit response; adopt only the exact stored poststate, otherwise return unknown. |
| Concurrent root creation | Canonical service-claim key and transactional root/claim/authority creation. | Racing creates for one service produce exactly one active root. |
| Recovery abuse | Separate recovery identity and action; root-bound captured stable revision; restore-only adapter operation. | Attempt promotion or arbitrary revision recovery and observe denial before mutation. |
| Evidence tampering or omission | Canonical event identity, append-only records, signed evidence where required, and independent target readback. | Alter or remove a record and detect a digest, signature, or sequence discontinuity. |
| Prompt injection or unsafe model output | Models remain outside authority packages and call only a read-only application facade. | Adversarial text cannot produce a capability, authority transition, task enqueue, or adapter call. |
| Credential disclosure | Never log or persist authorization headers, tokens, signatures as secrets, private keys, or raw provider errors. | Secret-shaped fixtures are rejected or redacted and error chains expose no credential material. |
| Dependency or source confusion | Immutable dependency locks, pinned actions and images, disclosed adaptation source, and no sibling-repository runtime path. | Clean checkout and provenance checks detect symlinks, forbidden source paths, generated output, and credential material. |

## Fail-closed ordering

Protected execution follows this order:

1. authenticate the caller;
2. decode and verify canonical capability content;
3. validate all claims, lineage, scope, target, and request bindings;
4. strongly read current authority;
5. transactionally claim the exact receipt;
6. strongly read current authority again immediately before mutation;
7. invoke the narrow conditional adapter once; and
8. record the result and require independent readback before verified success.

The second authority read prevents the receipt transaction from becoming a substitute for the
last-mile check. A revocation can still race in the interval between the final Firestore read and
the Cloud Run API call because the two providers do not share an atomic transaction. The product
does not conceal that residual interval. Exact provider preconditions prevent overwriting a
changed service, while the required delayed-task demonstration proves revocation for work held
before the fresh read.

## Assumptions and non-goals

Google Cloud IAM, KMS, Firestore, Cloud Tasks, and Cloud Run are trusted to enforce their
documented cryptographic, identity, transactional, and provider-precondition behavior. Their
configuration is still treated as reviewable product input rather than an implicit default.

Denial of service, a fully compromised Google Cloud control plane, malicious code already running
under an executor identity, and vulnerabilities in the target application are outside the first
control-plane contract. Those risks do not justify widening authority or converting uncertainty
into success.
