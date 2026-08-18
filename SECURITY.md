# Security policy

## Supported versions

ControlGraph Canary is currently a pre-release scaffold. Security fixes are made on the latest revision only.

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
- Controller identity and epoch are treated as untrusted inputs until validated.
- Authority code remains independent of agent frameworks and optional integrations.
- CI has read-only repository permissions and no cloud identity.
- The web console does not directly invoke cloud control-plane APIs.

This scaffold is not production-ready. Before deployment, add authenticated operator access, durable epoch storage, auditable authority acquisition, least-privilege Cloud Run permissions, request integrity controls, and failure-injection tests.
