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
| None recorded by this documentation-only foundation change. | Not applicable. | The accepted source set and rules are established; runtime code remains to be implemented through its numbered roadmap work. | Current repository checks describe only the scaffold. |

Future entries replace the empty row with concrete local files. A broad entry such as "backend"
is insufficient: each coherent adapted module or tightly related module group must be traceable.

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
