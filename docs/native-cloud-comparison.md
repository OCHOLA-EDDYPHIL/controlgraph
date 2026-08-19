# Native-cloud comparison

## Purpose

ControlGraph composes Google Cloud controls rather than replacing them. This comparison states
which guarantee each native mechanism supplies, which question it does not answer, and the narrow
additional decision ControlGraph is designed to make.

The comparison is architectural. The current scaffold does not yet deploy or exercise the hosted
mechanisms listed here. Provider parameters, regional availability, IAM permissions, quotas, and
failure behavior must be confirmed against official Google Cloud documentation before a live
configuration is accepted.

## Comparison

| Mechanism | Native guarantee used by ControlGraph | What it does not establish | ControlGraph addition |
|---|---|---|---|
| Google Cloud IAM | A principal may call a permitted API on a permitted resource under the configured policy. | That a queued request remains authorized by its rollout root when it eventually executes; field-level canary intent; immutable lineage. | Root-scoped capabilities, exact target and action bindings, and a fresh epoch decision immediately before mutation. |
| Cloud Run IAM | Only allowed principals can invoke a protected Cloud Run service. | That an authenticated caller is entitled to request a particular traffic mutation. | In-application caller policy plus a separate signed capability and current-epoch check. |
| Cloud Tasks OIDC | A task is delivered with a Google-signed identity token for a configured service account and audience. | The business authority, scope, freshness, target, or idempotency of the task payload. | Canonical capability verification, lineage and target checks, receipts, and stale-epoch denial. |
| Cloud Tasks delivery and retries | Addressed, delayed, and retried HTTP delivery under queue limits. | Exactly-once execution or a safe retry after an uncertain mutation response. | A deterministic request identity and durable receipt ensure duplicates cannot authorize a second mutation; ambiguity requires readback. |
| Cloud KMS asymmetric signing | A configured key version signs a supplied digest without exporting private key material. | Whether the signed request was appropriately scoped, remains current, or matches the executing caller and target. | Canonical bounded claims, explicit key-version trust, attenuation, expiry, and execution-time epoch validation. |
| Firestore transactions and write preconditions | Atomic document transactions and conditional writes within Firestore. | Atomicity with a later Cloud Run Admin API call or correctness of application-level document identities. | Immutable root records, canonical document keys, monotonic epoch transitions, exact receipt claims, and explicit unknown-write handling. |
| Cloud Run service etag or equivalent precondition | A conditional update can reject a service that changed since the approved read. | The authorization epoch, capability lineage, or whether the requested fields form the approved canary plan. | The immutable root binds the captured version and exact plan; the sealed adapter permits only the approved fields and revisions. |
| Immutable Cloud Run revisions | A named revision identifies a fixed deployed revision configuration. | Which revision was approved as stable or candidate for this rollout. | Stable capture and root creation bind exact immutable revision names and reject mutable aliases as authority. |
| Cloud Logging and Monitoring | Provider telemetry and metric observations can be collected under configured access. | A deterministic authority decision, complete evidence sequence, or permission to promote or recover. | Versioned evidence references and deterministic policy inputs; observations remain non-authoritative until evaluated by the kernel. |
| Artifact Registry digests | A digest identifies immutable container bytes. | That the image is authorized for an arbitrary deployment or that a rollout may change service configuration. | Terraform and service configuration accept reviewed digest references; the rollout adapter cannot deploy images. |

## Why signatures and IAM are not enough

A signature answers whether named bytes were signed by a trusted key. IAM and OIDC answer whether
a caller may reach an API or handler. A provider precondition answers whether the target changed
since a prior observation. None answers whether authority granted at epoch N remains current after
an operator advances the rollout root to N+1.

ControlGraph therefore treats the authoritative epoch read as a separate, last-mile decision.
The request may be authentic, correctly signed, unexpired, and delivered by the expected task
caller and still be denied because its root epoch is no longer current.

## Why ControlGraph still relies on native controls

The epoch check is not a substitute for IAM, OIDC, KMS, Firestore transactions, or provider
preconditions. Removing any of those controls would create a different vulnerability:

- without IAM or OIDC, an unexpected caller could reach protected code;
- without KMS, capability integrity and issuer provenance would be weaker;
- without transactions, concurrent authority and receipt claims would be indecisive;
- without a provider precondition, a valid plan could overwrite intervening service changes; and
- without immutable revisions and image digests, the approved target would be ambiguous.

The intended system is defense in depth with distinct questions and independently testable
failures, not a claim that epoch fencing replaces native cloud security.

## Provider-native optimistic concurrency limitation

Cloud Run concurrency control protects the service document, while the rollout epoch lives in
Firestore. No native transaction spans those two resources. ControlGraph performs a strong epoch
read immediately before a conditional Cloud Run update and keeps the interval explicit in the
threat model. The delayed-task acceptance case proves stale work held before that read is denied;
it does not claim a cross-provider atomic revocation primitive.

## Acceptance relationship

Native configuration is accepted only when both positive and negative behavior is observed:

- intended identities can invoke only their expected services;
- unintended identities and audiences are denied;
- KMS signs only under configured key-version permissions;
- Firestore races produce one deterministic winner;
- Cloud Tasks duplicates do not produce duplicate mutation;
- Cloud Run rejects stale provider preconditions; and
- advancing an epoch makes an otherwise valid delayed task harmless before mutation.

The reproducible cases are defined in `acceptance-cases.md`.
