# ControlGraph Canary

ControlGraph Canary is a narrow authority and execution control plane for Cloud Run
canaries. It addresses work that was valid when queued but no longer has authority when it
reaches the mutation boundary. Every mutating executor must re-read the rollout root's
current epoch immediately before invoking its target-bound adapter. A capability from any
other epoch fails closed even when its caller and signature are valid.

The repository contains a Python 3.12 backend and CLI, a read-only React and TypeScript
console, Terraform, shared contract fixtures, and CI checks. The first vertical is a 90/10
Cloud Run canary followed by manual epoch revocation and denial of a delayed stale task.

## Repository layout

```text
backend/  Authority kernel, application services, Google adapters, API, CLI, and tests
web/      Read-only React/Vite operator console and contract-fixture checks
infra/    Isolated Google Cloud environment and service modules
docs/     Product contract, architecture, threat model, acceptance, and provenance
```

## Quick start

### Backend

```bash
cd backend
uv sync --all-extras --dev
uv run pytest
uv run controlgraph-canary doctor
uv run controlgraph-canary serve
```

During the foundation milestone, the HTTP process exposes only read-only endpoints:

- `GET /healthz`
- `GET /v1/capabilities`

### Web console

```bash
cd web
npm install
npm test
npm run dev
```

### Terraform

```bash
cd infra
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

Terraform must receive immutable container references in the form `...@sha256:...`. Plans
and applies are intentional operator actions and are never run by the local console.

## Safety model

- Epochs are root-scoped, monotonically increasing authority versions.
- A capability is valid only for an exact current-epoch match.
- Authority-bearing Python code has an enforced import boundary and cannot depend on HTTP,
  cloud, model, or agent-framework packages.
- Mutation adapters are configured for one target and cannot accept arbitrary coordinates.
- The console remains read-only and never invokes a cloud control plane directly.
- Unknown or ambiguous mutation outcomes remain explicit and are never blindly retried.

See [docs/architecture.md](docs/architecture.md) for the boundary and threat model.

## Development

Run the same checks as CI:

```bash
cd backend && uv sync --all-extras --dev && uv run ruff check . && uv run mypy src && uv run pytest
cd web && npm run typecheck && npm test -- --run && npm run build
cd infra && terraform fmt -check -recursive && terraform validate
python scripts/check_clean_room.py
```

The source-boundary check keeps credentials, host paths, symlinks, unrecorded adaptations,
and runtime dependencies on sibling repositories out of the project.

## License

Apache License 2.0. See [LICENSE](LICENSE).
