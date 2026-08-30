# Decision 0002: check revocable authority at execution time

- Status: Accepted
- Scope: every protected Cloud Run traffic mutation

## Context

A capability can be valid when issued and stale when queued work reaches an executor. Signature
verification, task admission, short lifetimes, and queue cancellation cannot prove that approval
is still current at the moment of change.

## Decision

Each rollout has two authority records:

- an immutable root that defines the approved target, revisions, plan, policy, and maximum scope;
  and
- a separate monotonically increasing epoch that records current authority for that root.

Every capability binds the root and one exact epoch. After the executor claims the request receipt,
it performs a strongly consistent authority read as the final authorization operation before the
target-bound adapter call. The signed epoch must equal the current epoch. A mismatch, missing
record, invalid record, or read failure denies the action.

Revocation advances the epoch with an expected-current comparison. It does not rewrite the root,
delete queued tasks, or change target traffic.

## Consequences

- Work that waits in a queue loses authority as soon as its epoch is no longer current.
- Current work still passes through identity, signature, lineage, scope, receipt, target, plan,
  and provider-precondition checks.
- The executor needs a strongly consistent authority read on every protected mutation path.
- Firestore and Cloud Run do not share a transaction. A small interval remains between the final
  authority read and the provider call; target preconditions and independent readback limit and
  expose that interval.

Validating only at issuance or enqueue time, relying on expiry, and deleting queued tasks were
rejected because they do not close the execution-time race.
