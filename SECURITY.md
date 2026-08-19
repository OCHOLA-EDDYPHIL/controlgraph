# Security policy

## Supported versions

ControlGraph Canary is pre-release software. Security fixes are made on the latest revision
only.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it privately to the repository maintainers with:

- the affected revision and component;
- a minimal reproduction;
- expected and observed behavior;
- potential impact; and
- any suggested mitigation.

Do not include production credentials, customer data, or live project identifiers. Maintainers should acknowledge a complete report within five business days and coordinate disclosure after a fix is available.

## Security invariants

- A stale or future epoch never grants authority.
- Caller identity, signatures, claims, scope, target bindings, epochs, and preconditions are
  untrusted until independently validated.
- Every mutating executor performs a fresh authoritative epoch read immediately before the
  target-bound mutation adapter is invoked.
- Authority code remains independent of HTTP frameworks, cloud SDKs, model SDKs, agent
  frameworks, and optional integrations.
- Scope attenuation can preserve or narrow authority but cannot expand it.
- Duplicate delivery is safe only for an identical canonical request; an ambiguous provider
  outcome requires readback and never permits a blind retry.
- CI has read-only repository permissions by default and uses no long-lived cloud key.
- The web console does not directly invoke cloud control-plane APIs.

This project is not production-ready. Deployment evidence applies only to the isolated
acceptance environment and exact tested revision; it is not a claim of general security,
availability, or production suitability.
