# Architecture

## Purpose

ControlGraph Canary is intended to coordinate canary revisions on Cloud Run while preventing two controller instances from exercising authority at the same time. This revision establishes the safety boundary and repository shape; it does not mutate cloud resources.

## Component boundary

```text
Operator browser
      |
      v
React console ---- read-only status ----> Python HTTP surface
                                             |
                                             v
                                      application facade
                                             |
                                             v
                                      epoch authority core

Terraform contract modules ---- future deployment wiring (no resources today)
```

The product name describes a control relationship, not a reusable graph-processing framework. Domain behavior should remain explicit and small.

## Epoch-fencing invariant

An authority grant contains a non-negative integer epoch and a controller identity. A durable authority mechanism will monotonically advance the current epoch whenever ownership changes. Immediately before an eventual control-plane mutation, the actor must prove that its token epoch exactly equals the current epoch.

Equality is intentional:

- token epoch lower than current: the controller was superseded;
- token epoch higher than current: the token is not yet authoritative or the read is inconsistent;
- exact match: epoch validation succeeds, subject to all other authorization checks.

Any inability to read or validate current authority must fail closed. Epoch validation is necessary but not sufficient: production wiring must also authenticate callers, bind the epoch to the intended controller and operation, protect storage integrity, and emit an audit record.

## Python dependency policy

`controlgraph_canary.authority` is authority-bearing. It may import only Python's standard library and other dependency-free domain primitives. It must not import HTTP frameworks, cloud SDKs, agent frameworks, or ADK packages. A test inspects its imports to preserve this boundary.

If an ADK-based operator assistant is added later, place it outside the authority and service packages (for example, under a top-level `integrations/adk/` tree). The integration may call a narrow, non-authoritative application facade. Dependency direction must never point from the authority core or mutation-capable service package toward ADK.

## HTTP and console posture

The current HTTP routes expose health and static capability information only. The React console is a local operator shell with no credential handling and no direct cloud API calls. A future write surface requires a separate threat model, authenticated operator identity, CSRF/replay protections where applicable, authorization tests, and an explicit human confirmation flow.

## Infrastructure posture

Terraform currently validates configuration contracts and immutable image references but creates no resources. Future modules should separate:

1. Cloud Run runtime identity and service;
2. durable epoch authority storage;
3. least-privilege access to a narrowly scoped target service; and
4. audit/observability sinks.

Avoid implicit provider credentials in CI. Plans and applies require an intentionally configured environment and human-reviewed workflow outside the checks included here.

## Explicit non-goals for this scaffold

- rollout or control-plane mutation logic;
- a general graph engine;
- multi-language service implementations;
- event-bus orchestration;
- external policy-engine integration;
- hackathon or submission workflow state; and
- autonomous deployment.
