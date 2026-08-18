# Agent instructions

These instructions apply to the entire repository.

## Scope

ControlGraph Canary is a Python 3.12 Cloud Run canary-controller scaffold with a React/TypeScript console and Terraform. Keep changes narrowly aligned with epoch fencing and safe operator visibility.

## Hard boundaries

- Never perform a cloud deployment, submission, or live mutation without explicit user approval. Local adapters, fakes, and tests may be implemented under their roadmap issue without touching a provider.
- Keep `backend/src/controlgraph_canary/authority/` free of ADK, agent-framework, HTTP, and cloud SDK imports.
- Optional agent integrations belong under `integrations/` and may depend inward on a narrow application facade; authority packages must never depend outward on them.
- Do not add another implementation language, event bus, external authorization system, product-submission state, or a general-purpose graph abstraction.
- Implement rollout behavior only through the numbered roadmap issues, preserving the authority boundaries and acceptance criteria recorded there.
- Use immutable image digests in infrastructure examples.
- Never commit credentials, Terraform state, environment files, or generated build output.

## Verification

Before handing off a change, run the relevant checks:

```bash
cd backend && uv sync --all-extras --dev && uv run ruff check . && uv run mypy src && uv run pytest
cd web && npm run typecheck && npm test -- --run && npm run build
cd infra && terraform fmt -check -recursive && terraform init -backend=false && terraform validate
```

If a tool is unavailable, report that plainly. Do not replace missing verification with a cloud operation.
