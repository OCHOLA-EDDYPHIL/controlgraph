# Provenance and disclosure policy

## Purpose

ControlGraph combines project-specific implementation, disclosed adaptation of owner-authored
patterns, third-party dependencies, generated artifacts, and native cloud services. This record
keeps those categories distinct. The project must not describe the complete implementation as
greenfield once adapted work is present.

This file records durable source facts. Credentials, customer data, private prompts, provider
state, local paths, transient evidence, and development-machine details do not belong here.

## Ownership categories

| Category | Meaning | Required disclosure |
|---|---|---|
| ControlGraph-original | Material authored specifically for this repository without adapting another implementation. | Local artifact and author or rights holder. |
| Owner-authorized adaptation | ControlGraph-specific work derived from identified owner-authored source patterns. | Immutable source commit, source paths, rights holder, local destinations, and material changes. |
| Third-party dependency | Library, action, provider, tool, image, or vendored material owned by another party. | Name, version or immutable reference, use, license, and required notices. |
| Generated artifact | Output produced by a named tool from recorded inputs. | Tool and version, source inputs, reproducibility rule, and whether the artifact is tracked. |
| Native cloud service | Provider capability used through configuration or an API without copying its source. | Service, purpose, and configuration or acceptance boundary. |
| Synthetic test material | Invented identifiers, payloads, observations, and target behavior used for tests. | Generation rule and assurance that it contains no customer or operational data. |

## Accepted owner-authored source

The initial accepted adaptation source is the owner-authored RECONCILE repository at immutable
commit `ea1607a7782bc73c729407618d8c8a4ccfb4778b`, accepted for review on 2026-08-19.

| Source path | Rights holder | Intended ControlGraph use | Material adaptation required |
|---|---|---|---|
| `reconcile/contracts/base.py` | OCHOLA-EDDYPHIL | Strict immutable boundary models and bounded primitive validation. | Remove RECONCILE security and contract dependencies; use ControlGraph limits, terminology, packages, and tests. |
| `reconcile/contracts/codec.py` | OCHOLA-EDDYPHIL | Version-aware decoding, duplicate-key rejection, canonical bytes, and stable contract errors. | Define ControlGraph canonical number, timestamp, size, digest-domain, and cross-language rules. |
| Selected patterns from `reconcile/contracts/common.py` | OCHOLA-EDDYPHIL | Bounded digests, target bindings, ambiguity values, and freshness concepts where the canary contract needs them. | Admit only closed Cloud Run canary fields; exclude generic observation and RECONCILE workflow vocabulary. |
| `reconcile/hosted/firestore_cas.py` | OCHOLA-EDDYPHIL | Fixed logical identities, CAS preconditions, mutation identity, exact readback, and explicit unknown outcomes. | Replace RECONCILE collections and payloads with rollout roots, authority, service claims, receipts, and evidence; preserve no source database or path. |
| `reconcile/hosted/identity.py` | OCHOLA-EDDYPHIL | Bounded Google OIDC verification against an exact audience and caller set. | Define ControlGraph roles, route policies, stable denial codes, and tests; retain no RECONCILE identity configuration. |
| `reconcile/hosted/transport.py` | OCHOLA-EDDYPHIL | Bounded one-shot authenticated transport without redirects or blind retries. | Seal destinations to configured ControlGraph services and audiences; use ControlGraph request and error contracts. |

This source set is authorization to adapt identified owner-authored patterns, not a runtime
dependency and not permission to copy unrelated material. Source inspection uses the immutable Git
object, never an uncommitted source working tree. ControlGraph must not contain a sibling-repository
import, source-path dependency, symlink, copied cloud state, credential, database, queue, key,
evidence artifact, generated output, or deployment dependency.

The accepted source repository does not provide an explicit repository license that may be
assumed for unrelated material. Owner authorization covers the identified owner-authored patterns
for this project. It does not relicense third-party work or remove third-party notice obligations.

No ControlGraph runtime adaptation is asserted merely by listing an accepted source here. As code
is adapted, the adaptation register below must name its actual local destination and material
changes before a release claim is made.

## Adaptation register

| Local artifact | Accepted source | Material changes | Verification |
|---|---|---|---|
| `backend/src/controlgraph_canary/contracts/base.py` | `reconcile/contracts/base.py` at `ea1607a7782bc73c729407618d8c8a4ccfb4778b` | Retains strict frozen models and bounded primitive validation; replaces RECONCILE security dependencies with ControlGraph NFC, safe-integer, UTC-second, audience, and domain limits. | Contract model, Unicode, timestamp, bound, and import-boundary tests. |
| `backend/src/controlgraph_canary/contracts/codec.py` | `reconcile/contracts/codec.py` at `ea1607a7782bc73c729407618d8c8a4ccfb4778b` | Retains duplicate-key rejection, version-aware decoding, canonical bytes, and stable errors; adds a no-float cross-language subset, canonical-input enforcement, domain-separated hashes, byte/depth bounds, and canonical base64url. | Python malformed/canonical tests and byte-identical TypeScript golden vectors. |
| `backend/src/controlgraph_canary/contracts/models.py` | Selected bounded-value and ambiguity patterns from `reconcile/contracts/common.py` at `ea1607a7782bc73c729407618d8c8a4ccfb4778b` | Replaces provider-neutral RECONCILE records with closed ControlGraph target, root, authority, capability, task, receipt, health, recovery, and evidence schemas. | ControlGraph cross-field, round-trip, fixture, and rejection tests. |
| `backend/src/controlgraph_canary/authority/replay.py` | Mutation-identity, exact-readback, and explicit unknown-outcome patterns from `reconcile/hosted/firestore_cas.py`, plus one-shot transport behavior from `reconcile/hosted/transport.py`, at `ea1607a7782bc73c729407618d8c8a4ccfb4778b` | Recasts the selected patterns as a dependency-free canary mutation binding and receipt-state kernel. It binds request, capability, payload, plan, root, provider precondition, target, epoch, and expected post-state digests; removes durable pre-dispatch retry authority; and requires exact readback after any possible provider attempt. | Canonical fixture identity, altered-binding replay, provider ambiguity, readback-only recovery, and generated invariant tests. |
| `backend/src/controlgraph_canary/contracts/storage.py`, `backend/src/controlgraph_canary/application/authority_store.py`, `backend/src/controlgraph_canary/application/receipt_execution.py`, and `backend/src/controlgraph_canary/integrations/google/firestore.py` | Fixed logical identity, transaction, compare-and-swap, exact-readback, and ambiguous-write patterns from `reconcile/hosted/firestore_cas.py` at `ea1607a7782bc73c729407618d8c8a4ccfb4778b` | Replaces every RECONCILE collection, record, and path with fixed ControlGraph authority record families in the named `controlgraph-authority` database. Adds target-sealed document identities, atomic root/claim/authority creation, direct-confirmed one-use receipt dispatch, monotonic authority and receipt revisions, explicit service-claim release, bounded transactions, sanitized provider errors, and exact wrapper-plus-payload readback after an uncertain commit. | Contract tests, fake-provider contention and ambiguity tests, and real Firestore-emulator races for root creation, epoch revocation, execution claims, and recovery claims. |
| `backend/src/controlgraph_canary/application/tasks.py` and `backend/src/controlgraph_canary/integrations/google/tasks.py` | Destination sealing and one-shot delivery behavior from `reconcile/hosted/transport.py` at `ea1607a7782bc73c729407618d8c8a4ccfb4778b` | Recasts transport as two addressed Cloud Tasks routes derived only from startup configuration. Adds canonical task identities, exact regional queues, handler origins and paths, distinct OIDC callers, schedule and age bounds, one create attempt, and exact duplicate adoption without treating delivery identity as mutation authority. | Route substitution, time-bound, duplicate, provider-request, and no-application-retry tests. |
| `backend/src/controlgraph_canary/application/identity.py` and `backend/src/controlgraph_canary/integrations/google/identity.py` | Bounded Google OIDC verification against exact audience and caller sets from `reconcile/hosted/identity.py` at `ea1607a7782bc73c729407618d8c8a4ccfb4778b` | Replaces RECONCILE identity configuration with a closed ControlGraph service, route, caller-role, email, subject, and audience map. Adds stable credential-free denial codes, exact token time bounds, startup coordinate cross-checks, task-caller separation, and authentication context that retains no bearer token or mutation authority. | Caller-map, route-replay, claim substitution, bounded-token, credential-nondisclosure, startup-composition, and protected-route tests. |

A broad entry such as "backend" is insufficient: each coherent adapted module or tightly related
module group must remain traceable as later work is added.

## Repository-origin material

The initial ControlGraph scaffold, product text, Python package, React and TypeScript console,
CSS, Terraform input contracts, and tests were authored specifically for ControlGraph by the
project owner. This fact does not make later adaptations original work and does not supersede the
adaptation register.

The root `LICENSE` is the Apache License 2.0 text published by the Apache Software Foundation.
Direct dependencies and development tools are disclosed in `THIRD_PARTY_NOTICES.md`; their own
license texts and distributions remain authoritative. Package and action references do not imply
that their source is vendored.

The current UI uses system fonts and CSS-drawn presentation. No external image, font, icon, or
generated media is recorded in the scaffold.

## Native cloud services

Terraform and application code may configure or call Firestore, Cloud KMS, Cloud Tasks, Cloud Run,
Cloud Monitoring, Artifact Registry, IAM, and related Google Cloud control APIs. These are native
services, not copied implementation. Their use must be causally necessary to an accepted product
case and configured with explicit identity, region, bounds, and teardown behavior.

Provider documentation and API schemas are external references. Copying example source from them
requires a separate license and provenance review; merely using a documented API does not.

## Synthetic data

Tests use invented project IDs, regions, service names, revision names, epochs, timestamps,
digests, traffic allocations, health samples, identities, provider responses, and probe markers.
Fixtures must contain no customer data, production identifier, live credential, private prompt,
or copied provider state. Secret-shaped cases use unmistakably synthetic placeholders and are
never valid credentials.

The disposable reference target must return only a fixed synthetic behavior marker and immutable
revision identity. It must not contain customer workloads, persistent business data, or an
external side effect.

## Generated artifacts

Dependency locks and the Terraform provider lock are generated by their package tools and may be
tracked for reproducibility. Build output, coverage, caches, Terraform plans and state, provider
credentials, runtime logs, and transient acceptance evidence remain untracked.

The tracked `.github/sigstore-signing-config.json` and
`.github/sigstore-trusted-root.json` files are generated by Cosign 3.1.3 from the Sigstore
public-good service defaults. They exclude Rekor and retain the Fulcio, certificate-transparency,
and RFC3161 timestamp-authority material used by release verification. Regenerate them with the
pinned Cosign binary using `cosign signing-config create --with-default-services
--no-default-rekor` and `cosign trusted-root create --with-default-services
--no-default-rekor`, respectively. Do not hand-edit them; review regenerated trust changes and
update their SHA-256 digests in `.github/release-evidence-policy.json`. Cosign and the Sigstore
root-signing material are Apache-2.0 licensed.

If a generated schema, software bill of materials, trust bundle, or other release artifact is
tracked later, its entry must record:

1. generator and exact version;
2. immutable or digestible inputs;
3. output path and whether hand editing is forbidden;
4. applicable licenses and notices; and
5. the command or workflow that reproduces it without a secret.

## Update procedure

Before adapting or importing material:

1. identify an immutable source revision and exact repository-relative paths;
2. confirm ownership and applicable license or explicit authorization;
3. reject unrelated third-party or operational material;
4. record intended local destinations and material changes;
5. implement through ControlGraph package boundaries with no source-repository dependency;
6. add ControlGraph-specific tests for the adapted behavior; and
7. update notices when a new third-party obligation is introduced.

A newer RECONCILE commit is not implicitly accepted. It requires an explicit amendment recording
the full commit identifier, reason for selection, paths reviewed, and impact on existing
adaptations.

Material with unclear provenance, incompatible rights, hidden operational state, or an unreviewed
source path must not enter the repository.
