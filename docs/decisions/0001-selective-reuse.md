# Decision 0001: selective owner-authorized RECONCILE reuse

- Status: Accepted
- Scope: ControlGraph contract, persistence, identity, and transport foundations

## Context

ControlGraph needs strict boundary contracts, deterministic canonical encodings, conservative
provider-write handling, workload identity verification, and bounded authenticated transport.
The project owner has already implemented and audited relevant patterns in RECONCILE. Repeating
those patterns without acknowledging their origin would be slower and less accurate than a
narrow, disclosed adaptation.

The earlier blanket exclusion of all RECONCILE work is therefore replaced by this decision. The
replacement does not turn ControlGraph into a RECONCILE integration and does not admit the
RECONCILE runtime as a dependency.

## Decision

ControlGraph accepts the immutable RECONCILE source commit
`ea1607a7782bc73c729407618d8c8a4ccfb4778b` as its sole initial adaptation source. Only
owner-authored patterns from these repository-relative paths are in scope:

- `reconcile/contracts/base.py`
- `reconcile/contracts/codec.py`
- selected bounded value patterns from `reconcile/contracts/common.py`
- `reconcile/hosted/firestore_cas.py`
- `reconcile/hosted/identity.py`
- `reconcile/hosted/transport.py`

The accepted patterns are limited to:

- immutable, strict, unknown-field-rejecting contracts;
- bounded values and deterministic canonical JSON and digest construction;
- version-aware decoding and stable public contract errors;
- fixed Firestore identities, compare-and-swap preconditions, exact readback, and explicit
  unknown outcomes after ambiguous writes;
- bounded Google OIDC verification against an exact audience and caller policy; and
- one-shot authenticated HTTP transport without redirects, forwarded inbound credentials, or
  blind retries.

Adaptation means rewriting these patterns for ControlGraph's closed Cloud Run canary domain,
terminology, limits, package boundaries, and tests. It does not mean copying the source files as
modules or preserving RECONCILE-specific contracts.

Source inspection and adaptation use the immutable Git object. The current working tree of the
source repository is not an accepted input. ControlGraph must contain every adapted artifact it
uses and must have no runtime import, source-path reference, symlink, generated-code link, or
deployment dependency on the source repository.

Each adaptation records its accepted source path, local destination, material changes, rights
holder, and relevant third-party dependencies in the provenance record before release.

## Implementation path

The product stack remains:

- Python 3.12 for the authority kernel, application services, adapters, and CLI;
- React with TypeScript for the read-only operator console;
- Terraform for infrastructure definitions;
- Firestore for durable authority and receipts;
- Cloud KMS for asymmetric signing;
- Cloud Tasks with OIDC for addressed delivery;
- Cloud Run for private services and the disposable canary target; and
- Cloud Monitoring and structured evidence for bounded observations.

The authority package remains independent of HTTP frameworks, cloud SDKs, model SDKs, and agent
frameworks. Google-specific implementations live outside it and depend inward through narrow
application ports.

## Explicit exclusions

This decision does not authorize importing or adapting:

- the complete RECONCILE runtime or a compatibility layer for it;
- qualification, falsification, scenario, Lazarus, Phase 5, or operator workflows;
- planner qualification or read-only observation capabilities as mutation authority;
- RECONCILE-specific product language or terminal interface;
- RECONCILE Terraform, cloud state, queues, databases, KMS keys, credentials, evidence, or
  generated output;
- third-party source merely because it is present in RECONCILE;
- Go, Rust, or another service implementation language;
- Pub/Sub or another event bus;
- OpenFGA or another external authorization system;
- a general-purpose topology or graph engine; or
- product-kill, falsification, or ablation gates.

No placeholders, generic hooks, or compensating controls are added for these exclusions.

## Licensing and ownership

The accepted source is owner-authored by OCHOLA-EDDYPHIL. RECONCILE does not provide a repository
license that can be assumed for unrelated material. Owner authorization covers adaptation of the
identified owner-authored patterns for ControlGraph; it does not relicense third-party work or
remove third-party notice obligations. Any third-party dependency used by an adaptation retains
its own license and must appear in the project's notices and release evidence.

## Consequences

ControlGraph can reuse proven failure handling while preserving an independent product and
runtime. Review must compare adapted behavior with both this product contract and the disclosed
source, and ControlGraph-specific tests must establish the resulting behavior. The project must
not describe adapted work as greenfield.

If a later source commit is needed, a new decision or explicit amendment must record its full
commit identifier, the reason for selecting it, and the additional paths reviewed before any
adaptation occurs.
