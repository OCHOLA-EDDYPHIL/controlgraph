# Decision 0001: selectively reuse owner-authored RECONCILE patterns

- Status: Accepted
- Scope: contract, persistence, identity, and transport foundations

## Context

ControlGraph needs strict boundary contracts, deterministic encoding, conservative provider-write
handling, workload identity verification, and one-shot authenticated transport. The project owner
already implemented relevant patterns in RECONCILE. Reusing those patterns is faster and clearer
than recreating them without acknowledging their origin.

ControlGraph must still remain an independent product and runtime.

## Decision

The sole initial adaptation source is the owner-authored RECONCILE repository at immutable commit
`ea1607a7782bc73c729407618d8c8a4ccfb4778b`. Review is limited to:

- `reconcile/contracts/base.py`;
- `reconcile/contracts/codec.py`;
- selected bounded-value patterns from `reconcile/contracts/common.py`;
- `reconcile/hosted/firestore_cas.py`;
- `reconcile/hosted/identity.py`; and
- `reconcile/hosted/transport.py`.

Accepted patterns include strict immutable records, canonical JSON and digests, stable contract
errors, compare-and-set storage, exact readback after uncertain writes, bounded Google OIDC
verification, and one-shot authenticated transport.

Each pattern is rewritten for ControlGraph's closed Cloud Run canary domain, terminology, limits,
package boundaries, and tests. ControlGraph does not import these files, depend on a sibling
working tree, share runtime state, or preserve RECONCILE-specific contracts.

The [provenance register](../provenance.md) owns the source-to-destination mapping, material
changes, rights holder, and verification record.

## Consequences

- ControlGraph can use proven boundary and failure-handling patterns while keeping an independent
  codebase and deployment.
- Every adaptation remains traceable and receives ControlGraph-specific tests.
- Unlisted RECONCILE source and unrelated third-party material remain outside the accepted set.
- A later source revision requires an explicit amendment before inspection or adaptation.

The source repository has no general license that can be assumed for unrelated material. Owner
authorization applies only to the identified owner-authored patterns and does not change any
third-party license obligation.
