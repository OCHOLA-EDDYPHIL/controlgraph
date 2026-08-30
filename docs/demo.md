# Evidence-backed demo

This is the evidence order for one hosted acceptance run of the disposable reference target.
Present a claim only when all four evidence columns below are bound to the same source commit,
target, root, epoch, request, and run. Examples and fixture identifiers are synthetic; published
evidence is redacted.

Use the [reproducible quickstart](quickstart.md) to provision and run the sequence. The
[product contract](product-contract.md) defines the allowed outcomes, and the
[threat model](threat-model.md) defines what the demonstration does not prove.

## Shortest complete proof

The clearest single path starts from verified 90/10 traffic. Enqueue signed promotion work at
epoch N, pause delivery, revoke to N+1, and release the queue. The executor returns
`DENIED / EPOCH_MISMATCH`; configuration readback before and after denial proves the target stayed
90/10. Gemini 3.5 Flash then uses the Google ADK runner's six read-only tools to derive one
receipt/timeline/target-cited causal path with no authority effect. Fresh current-epoch,
stable-only recovery finishes at verified 100/0.

The immutable, credential-free version of that path is available at the
[public replay](https://controlgraph-console-936681471311.us-central1.run.app/replay).

## Demo sequence

### 1. Establish the boundary

Show the exact source SHA, five immutable image references, reviewed Terraform plan digest,
dedicated project and region, fixed reference target, two task queues, separate service identities,
and cost and duration bounds. Show only synthetic resource names and digests in a public recording.

Narrate: "This run controls one disposable Cloud Run service in one isolated project. The browser
and CLI reach the authenticated API; neither can call the target control plane directly."

### 2. Apply the 90/10 canary

Reset and probe the stable 100/0 baseline. Capture it twice, create the immutable rollout root,
and dispatch `APPLY_CANARY`. Read the exact execution receipt and target configuration before
showing 90 percent stable and 10 percent candidate traffic.

Narrate only after the evidence gate passes: "The executor accepted one target-bound capability,
reread the root's current Firestore epoch immediately before its conditional Cloud Run update,
and independent readback and probing agree on the 90/10 state."

### 3. Show both deterministic health outcomes

For the healthy case, submit the bounded Monitoring windows, show their signed deterministic
health chain, dispatch promotion, and verify 0/100 traffic plus the candidate probe marker. For a
separate reset root, submit the fixed unhealthy inputs; show the atomic recovery intent, separately
addressed recovery task, executor recovery-facade receipt, and restored 100/0 traffic plus stable
probe marker.

Narrate: "Monitoring inputs and the frozen policy determine the branch. A model does not choose
promotion or recovery, and the recovery identity cannot mutate Cloud Run itself."

### 4. Revoke delayed work

Reset, create a fresh root, establish its verified 90/10 prestate, hold the execution queue, and
enqueue otherwise-valid work at epoch N. Revoke to N+1, release the queue, and show that the delayed
work receives `EPOCH_MISMATCH` without a protected target change. Then use the separately confirmed,
current-epoch recovery path and verify the captured stable state. Before recovery, invoke the
bounded advisor against that exact stale-denial snapshot. Show all six successful read-only tool
calls, the receipt/timeline/target citations, `authority_effect=none`, and the identical replayed
result that causes no second model call.

Narrate: "Authentication, signature validity, and queue admission are insufficient. Stale authority
is denied at execution time. Gemini explains the evidence-backed causal path but cannot change the
decision; recovery is new, stable-only authority rather than revival of epoch N."

### 5. Review the operator surfaces and clean up

In the authenticated console, page through the ordered timeline and correlate root, epoch,
request, receipt, health, recovery, and terminal events. The deterministic denial must appear
before the `ADVISORY_ONLY` analysis, and the advisor has no apply action. Then open `/replay`
without credentials and show its artifact-hash, schema, payload-digest, and event-chain checks.
The browser does not independently verify KMS signatures.

Finish by resetting to 100/0, verifying configuration and the stable data-path marker, releasing
the terminal service claim, and ensuring the execution queue is running. Infrastructure teardown
is outside this demonstration and requires separate authorization.

## Claim-to-evidence gate

Each row is one admissible demo claim. If any cell is missing, contradictory, from another root,
or outside the run interval, say that the result is unverified and do not make the claim.

| Demo claim | Configuration readback | Data-path proof | Signed timeline evidence | Acceptance manifest |
|---|---|---|---|---|
| Canary applied at 90/10 | `controlgraph.target-traffic-read-result/v1`: exact revisions, 90/10 traffic, concurrency, etag, and configuration digests | `controlgraph.probe-attestation/v1`: root-bound 20-sample observation and matching revision markers | `MUTATION_APPLIED` and `VERIFICATION_RECORDED`, with matching root, epoch, receipt, and payload digests | `HEALTHY_PROMOTION` or `UNHEALTHY_STABLE_RECOVERY` case binds the readback, probe, capability, executor check, receipt, and timeline artifacts |
| Healthy candidate promoted to 100 percent | Final target readback: stable 0, candidate 100, expected candidate configuration digest | Signed independent-verification evidence cites a matching candidate probe attestation | `HEALTH_DECIDED` followed by `TERMINAL_CLASSIFIED=PROMOTED` on one verified chain | `HEALTHY_PROMOTION` is `PASSED` with observed result `PROMOTED` |
| Unhealthy candidate recovered to captured stable | Final target readback: stable 100, candidate 0, captured configuration and concurrency | Signed independent-verification evidence cites a matching stable probe attestation | `HEALTH_DECIDED`, `RECOVERY_INTENT_CREATED`, `RECOVERY_APPLIED`, then `TERMINAL_CLASSIFIED=RECOVERED` | `UNHEALTHY_STABLE_RECOVERY` is `PASSED` with observed result `RECOVERED` and recovery-identity evidence |
| Revocation denied delayed epoch-N work and recovery used N+1 | Readbacks before and after delayed delivery show no stale mutation; final readback shows captured stable | Root-bound probe attestations agree with both observed configurations | `AUTHORITY_EPOCH_ADVANCED`, `MUTATION_DENIED` with `EPOCH_MISMATCH`, and the distinct current-epoch recovery sequence | `REVOCATION_STALE_DENIAL` is `PASSED` with authority-transition, executor-check, stale-denial, receipt, timeline, readback, and probe artifacts |
| Gemini explained the stale denial without authority effect | The cited target summary records the same 90/10 configuration at or after denial | The cited target or verifier record binds the observed configuration | `MODEL_ASSISTANCE_RECORDED` follows the deterministic denial; the structured finding cites receipt, timeline, and target or verifier evidence | `BOUNDED_ADVISOR` is `PASSED` with `ADVISORY_ONLY`, six successful read-only tool calls, accepted non-fallback output, and idempotent replay |

The source contracts behind those evidence types are:

- [target configuration readback](../backend/src/controlgraph_canary/contracts/operator_observability.py);
- [probe and independent-verification evidence](../backend/src/controlgraph_canary/contracts/independent_verification.py);
- [signed evidence events](../backend/src/controlgraph_canary/contracts/root_creation.py);
- [timeline entries and pages](../backend/src/controlgraph_canary/contracts/timeline.py); and
- [completion classification](../backend/src/controlgraph_canary/application/completion_classification.py).

The console renders the server-produced projection in
[`web/src/timelinePresentation.ts`](../web/src/timelinePresentation.ts). The advisor receives six
read-only diagnostic tools through
[`application/model_assistance_m6.py`](../backend/src/controlgraph_canary/application/model_assistance_m6.py);
it has no mutation facade, and its result is always non-authoritative.

## Accepted manifest and replay binding

The published replay records one accepted hosted run:

- source: `dcc2192dade08d3fdfd27daded0ccfdd13193fd1`;
- run: `cgacceptance:380d6733e6caa85a17df5da6c193680bfa7e03b00009ac30a40fa068849b14b9`;
- manifest SHA-256:
  `7b5c2e362b702bd675acc8b1fff18a4ece232cd530013967d6ed11122fcea700`;
- public replay SHA-256:
  `13782bc3b1d6f711c39494118a3df783de61b9ac20f0defeca108ec473fcf8cc`; and
- result: all eight fixed cases passed with complete evidence binding and five immutable image
  references.

The replay's six-event chain records the epoch advance, stale denial, unchanged 90/10 target,
validated cited advisor result, verified 100/0 recovery, and committed timeline. The acceptance
manifest remains the run's authoritative full evidence; the replay is its bounded redacted
projection.

## Publication boundary

Publish only the public-redacted artifact projections and their digests. Do not publish OAuth or
OIDC tokens, Terraform state, provider responses containing sensitive metadata, raw restricted
events, account subjects, local paths, or reusable credentials. A successful demo proves only the
closed reference-target cases at the recorded revision and measured bounds; it does not establish
general deployment support, production suitability, or autonomous model authority.
