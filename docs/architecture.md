# Architecture

## Purpose and implementation posture

ControlGraph Canary addresses stale authority at execution time. A request can be correctly
authenticated, correctly signed, and intact yet no longer be authorized because it was queued
before an operator revoked its rollout epoch.

The current repository implements strict versioned contracts, cross-language canonical fixtures,
a pure rollout reducer, root-scoped exact-match epochs, read-only HTTP routes, a CLI diagnostic,
a static React shell, Terraform input contracts, and local tests. It does not currently persist
authoritative epochs, sign capabilities, deliver authenticated tasks, mutate Cloud Run, evaluate
hosted health, recover a service, or render a hosted evidence timeline.

The architecture below fixes the boundary that later numbered implementation work must satisfy.
It must not be read as evidence that the hosted path has already been deployed or accepted.

## Control path

```text
API or CLI
    |
    v
authenticated application facade
    |
    v
deterministic reducer and closed canary policy
    |
    v
KMS capability issuer
    |
    v
addressed Cloud Tasks delivery with dedicated OIDC caller
    |
    v
caller, signature, time, lineage, scope, binding, and request validation
    |
    v
transactional receipt claim
    |
    v
fresh authoritative epoch read immediately before mutation
    |
    v
target-bound Cloud Run adapter with provider precondition
    |
    v
idempotent receipt, independent readback, and evidence
```

No model appears in this path. An optional Gemini or ADK advisory integration may consume a
narrow, read-only application view, but its output cannot approve authority, classify health,
select a rollout or recovery action, enqueue protected work, or call a mutation adapter.

## Layering and dependency direction

The Python implementation is divided by authority rather than by cloud product:

```text
HTTP services / CLI / composition roots
             |                  |
             |                  v
             |          Google integrations
             |          Firestore, KMS, OIDC,
             |          Cloud Tasks, Cloud Run
             |                  |
             +---------> application facade and ports
                                      |
                         +------------+------------+
                         v                         v
                  versioned contracts       authority kernel
                                            reducer, epoch,
                                            policy, replay rules
```

The authority kernel is pure Python and imports no HTTP framework, Google Cloud SDK, model SDK,
ADK, or agent framework. Boundary contracts may use narrowly selected validation dependencies,
but cloud and transport types do not enter domain decisions. Integrations depend inward through
application ports; the authority and application layers never import an integration.

Optional agent integrations belong under `integrations/` and receive no mutation-capable facade.

## Domain records

The first contract contains exact, versioned records for:

- project, region, environment, and service target binding;
- stable service snapshot and provider precondition;
- immutable rollout root and content digest;
- root-scoped epoch authority and monotonic transitions;
- capability claims, signatures, lineage, and attenuation;
- mutation intent and addressed task request;
- execution receipt and ambiguity classification;
- deterministic health input and restore-only recovery plan; and
- ordered evidence events.

The complete vocabulary and terminal semantics are defined in `product-contract.md`.

## Canonical wire boundary

Every object crossing a language, process, persistence, or trust boundary has one exact schema
version and bounded canonical representation. Signed and hashed content uses deterministic UTF-8
JSON, duplicate-key rejection, explicit timestamp and number rules, unknown-field rejection, and
domain-separated digests. Parsing untrusted input never chooses a key, algorithm, URL, resource,
or method.

Python and TypeScript may share golden fixtures for representation and display, but TypeScript
never becomes an authority implementation. The server remains the source of mutation decisions.

## Epoch authority

Each immutable rollout root begins at epoch 1 and has an independent, monotonically increasing
epoch.
Authority changes compare an expected current epoch and advance it exactly once while recording
the actor, cause, request identity, prior epoch, new epoch, and evidence identity.

Exact equality is required:

- signed epoch lower than current: the work is stale;
- signed epoch higher than current: the authority view or request is inconsistent;
- exact match: epoch validation succeeds, subject to every other gate.

Epochs are never inferred from time, shared between roots, decremented, or reused. Queue admission,
issuance, and an earlier process check cannot substitute for a strongly consistent authority read
immediately before mutation. Failure to read or validate current authority denies the operation.

## Immutable roots and attenuation

A rollout begins with two matching reads of an eligible 100 percent stable target. The snapshot
records exact immutable revisions, traffic, approved concurrency, service generation or etag, and
a canonical configuration digest. A canonical service claim permits at most one active root for
the project, region, environment, and service.

Root creation atomically binds the stable snapshot, candidate, 90/10 plan, deterministic policy,
recovery limits, initial epoch, operator approval, and maximum authority. Root content is
content-addressed and immutable; revocation updates a separate authority record.

Child capabilities must be equal to or narrower than their parent across caller, audience,
project, region, environment, service, root, epoch, action, revision, traffic, concurrency,
provider precondition, lifetime, plan, and request identity. Lineage ends at the approved root and
rejects missing, cyclic, unknown, or widened ancestry.

## Identity and signing

Operator, API, coordinator, issuer, executor, recovery, verifier, and task-caller identities are
separate. Service invocation uses Cloud Run IAM, and protected application routes independently
verify Google-issued identity claims against an exact audience and caller policy. A valid identity
does not authorize mutation without the capability.

Cloud KMS holds asymmetric private keys. Capabilities bind the configured signing algorithm and
exact key version into their canonical claims. Callers cannot select a key, algorithm, trust
bundle, or public-key URL. Capability and evidence signing use separate permissions. The issuer
can sign approved canonical claims but cannot mutate Cloud Run.

## Delivery and execution

Cloud Tasks carries addressed commands to fixed private handler URLs with a dedicated OIDC caller,
audience, regional queue, bounded age, rate, concurrency, retry, and backoff. Cloud Tasks is not an
event bus and its delivery identity is separate from action authority.

Protected execution performs these gates in order:

1. caller verification;
2. canonical contract and signature verification;
3. issuer, subject, audience, time, lineage, scope, target, plan, precondition, and request checks;
4. strong authority read;
5. transactional claim of the exact execution receipt;
6. a second strong authority read immediately before mutation;
7. one conditional adapter call; and
8. durable result recording followed by independent readback.

The adapter accepts an internal mutation permit produced only after the final authority check. It
does not accept an arbitrary project, region, service, image, revision, URL, API method, or field
mask from a capability holder.

## Receipts, replay, and uncertain outcomes

The deterministic idempotency identity binds root, epoch, action, target, provider precondition,
plan, and canonical payload. A Firestore transaction gives one exact request ownership of its safe
execution phase.

An exact duplicate returns or adopts the existing result. Reuse with different canonical content
is an attack and is denied. A timeout, connection loss, malformed operation result, or other
unknown provider response becomes `AMBIGUOUS`. The adapter does not retry the mutation merely
because delivery or HTTP failed. Exact readback may adopt only the expected canonical poststate;
otherwise uncertainty remains explicit.

## Cloud boundary

The planned deployment is one isolated Google Cloud project and one compatible region. Terraform
defines required APIs, immutable-image Artifact Registry inputs, Firestore, KMS, Cloud Tasks,
private Cloud Run services, distinct identities, bounded resources, audit configuration, and a
disposable reference target. Minimum instances remain zero where safe, and no long-lived service
account key is used.

The operator API may use an authenticated ingress suitable for the CLI. Issuer, executor,
recovery, and verifier handlers admit only intended internal authenticated callers. The reference
target is disposable, contains no customer data, and exposes only a harmless probe marker to its
authorized reader.

Cloud Run IAM cannot constrain a service update to individual traffic fields. The executor's
narrow application contract and target-bound adapter therefore remain necessary even under
least-privilege IAM. Firestore and Cloud Run also do not share an atomic transaction; the threat
model records the residual interval between the final authority read and provider call rather
than overstating the guarantee.

## Operator surfaces

The API is the authority-preserving operator boundary. A CLI mutation command calls that API with
an authenticated identity, versioned request, expected epoch, request identity, reason, and
explicit confirmation; it does not write Firestore or invoke Cloud Run directly.

The current console is static and read-only. Any later evidence presentation must obtain bounded
data through the API and must not hold provider credentials or become a mutation surface. This
architecture makes no claim that such hosted console behavior is currently implemented.

## Selective reuse and provenance

Owner-authored patterns may be adapted only from the accepted immutable RECONCILE source and paths
recorded in `decisions/0001-selective-reuse.md` and `provenance.md`. ControlGraph has no runtime,
source-path, symlink, state, credential, or deployment dependency on RECONCILE. Adapted behavior
uses ControlGraph terminology, closed contracts, and ControlGraph-specific tests.

## Explicit non-goals

- arbitrary service deployment or container selection;
- a general graph, topology, workflow, or policy engine;
- Go, Rust, or another backend implementation language;
- Pub/Sub or another event bus;
- OpenFGA or another external authorization system;
- multi-project or multi-region authority paths;
- autonomous model authority;
- direct cloud mutation from a browser console;
- RECONCILE runtime, state, credentials, Terraform, or product workflows; and
- product-submission or temporary project-tracking state.
