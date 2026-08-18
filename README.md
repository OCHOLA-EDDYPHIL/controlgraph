# ControlGraph Canary

ControlGraph Canary is a safety-first scaffold for a Cloud Run canary controller. Its core invariant is epoch fencing: a controller may act only while the epoch in its authority token exactly matches the current authoritative epoch. A superseded controller must fail closed.

This repository is deliberately pre-integration. It contains a typed Python 3.12 service and CLI, a React and TypeScript operator console, Terraform contract modules, and local CI checks. It does **not** contain Cloud Run mutation code, rollout orchestration, or cloud credentials.

## Repository layout

```text
backend/  Python service, CLI, and epoch-fence authority primitive
web/      React/Vite operator console
infra/    Terraform inputs and placeholder module contracts
docs/     Architecture and provenance records
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

The HTTP process exposes only read-only scaffold endpoints:

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

The Terraform module is a contract placeholder and intentionally creates no cloud resources. Supply immutable container references in the form `...@sha256:...` when planning future wiring.

## Safety model

- Epochs are non-negative, monotonically increasing authority versions.
- A token is valid only for an exact epoch match.
- Authority-bearing Python code has an enforced import boundary and cannot depend on agent/ADK packages.
- No workflow authenticates to a cloud provider or deploys resources.
- No application or infrastructure command is run automatically by the console.

See [docs/architecture.md](docs/architecture.md) for the boundary and threat model.

## Development

Run the same checks as CI:

```bash
cd backend && uv sync --all-extras --dev && uv run ruff check . && uv run mypy src && uv run pytest
cd web && npm run typecheck && npm test -- --run && npm run build
cd infra && terraform fmt -check -recursive && terraform validate
python scripts/check_clean_room.py
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
