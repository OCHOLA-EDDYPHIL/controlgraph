# ControlGraph Canary

**A valid signature proves what was approved. It does not prove that approval still exists when
queued work finally executes.**

ControlGraph Canary is last-mile authority for agentic Cloud Run changes. It turns real provider
observations into deterministic execution decisions, narrow KMS-signed capabilities, durable
one-use receipt claims, and an evidence-backed causal path that an operator can inspect. Every
mutating executor rereads the rollout root's current Firestore epoch immediately before invoking
its target-bound adapter. A capability from any other epoch fails closed even when its caller and
signature are valid.

The repository contains a Python 3.12 backend and CLI, a static React and TypeScript operator
console, Terraform, shared contract fixtures, and CI checks. The implemented rollout vertical
captures a stable Cloud Run revision, applies a 90/10 canary, deterministically evaluates its
Cloud Monitoring signals, then either promotes the approved candidate or restores the captured
stable revision. Manual epoch revocation makes delayed otherwise-valid work fail closed.

## The proof protocol

The strongest end-to-end path is deliberately small and visible:

1. Establish a verified 90/10 canary and enqueue signed promotion work at epoch N.
2. Hold delivery, revoke authority to N+1, and release the delayed work.
3. Classify it as `DENIED / EPOCH_MISMATCH` while independent readback proves the target stayed
   exactly 90/10.
4. Invoke Gemini 3.5 Flash through Google ADK with six read-only tools. The accepted structured
   finding cites the receipt, timeline, and target evidence that form the stale-authority causal
   path; it has `authority_effect=none` and offers no apply action.
5. Issue fresh, stable-only recovery authority at the current epoch and verify 100/0.

If a provider mutation might have happened but readback cannot distinguish the outcome,
ControlGraph records `AMBIGUOUS`; it does not wrap uncertainty in a success-shaped certificate or
blindly retry. Selected authority, health, and independent-verification evidence and capabilities
are signed with purpose-separated Cloud KMS keys. The ordered timeline is hash-linked.

## Verify the published run

The credential-free [public replay](https://controlgraph-console-936681471311.us-central1.run.app/replay)
is bound to:

- source `dcc2192dade08d3fdfd27daded0ccfdd13193fd1`;
- accepted run `cgacceptance:380d6733e6caa85a17df5da6c193680bfa7e03b00009ac30a40fa068849b14b9`;
- acceptance manifest SHA-256
  `7b5c2e362b702bd675acc8b1fff18a4ece232cd530013967d6ed11122fcea700`; and
- replay SHA-256 `13782bc3b1d6f711c39494118a3df783de61b9ac20f0defeca108ec473fcf8cc`.

The browser fails closed unless the artifact hash, closed schema, payload digest, eight-case
binding, and six-event hash chain validate. It renders recorded, redacted evidence and makes no
protected API call. It does not independently verify Cloud KMS signatures; those are checked in
the authenticated verifier path and represented by bounded metadata in the replay.

## Repository layout

```text
backend/  Authority kernel, application services, Google adapters, API, CLI, and tests
web/      Read-only React/Vite operator console and contract-fixture checks
infra/    Isolated Google Cloud environment and service modules
docs/     Product contract, architecture, threat model, acceptance, and provenance
```

## Quick start

The commands below are the local development path. For the isolated hosted setup, exact 90/10
walkthrough, revocation and recovery sequence, evidence review, and cleanup, use the
[reproducible canary quickstart](docs/quickstart.md) and
[evidence-backed demo](docs/demo.md).

### Backend

```bash
cd backend
uv sync --all-extras --dev
uv run pytest
uv run controlgraph-canary doctor
uv run controlgraph-canary serve
```

Each controller exposes identity-safe read endpoints:

- `GET /healthz`
- `GET /v1/metadata`

Role-specific protected routes compose the authenticated API, coordinator, issuer, executor,
recovery, verifier, and evidence-writer boundaries. Mutation routes require the complete
role-specific environment and exact caller, capability, root, epoch, receipt, and target
bindings; an ordinary local start does not bypass those gates.

### Web console

```bash
cd web
npm install
npm test
npm run dev
```

### Terraform

```bash
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra/bootstrap init -backend=false
terraform -chdir=infra/bootstrap validate
terraform -chdir=infra/foundation init -backend=false
terraform -chdir=infra/foundation validate
terraform -chdir=infra/runtime init -backend=false
terraform -chdir=infra/runtime validate
```

Terraform must receive immutable container references in the form `...@sha256:...`. Plans
and applies are intentional operator actions and are never run by the local console.

## Safety model

- Epochs are root-scoped, monotonically increasing authority versions.
- A capability is valid only for an exact current-epoch match.
- Authority-bearing Python code has an enforced import boundary and cannot depend on HTTP,
  cloud, model, or agent-framework packages.
- Mutation adapters are configured for one target and cannot accept arbitrary coordinates.
- Cloud Monitoring health decisions are deterministic, root-bound, and signed; no model chooses
  promotion or recovery.
- The recovery identity can only verify and forward stable-only work to the executor's separate
  recovery facade. It has no direct target-update, target service-account impersonation
  (`actAs`), or operation-read authority.
- The static console never invokes a cloud control plane directly. It reads the timeline and can
  submit only an authenticated, explicitly confirmed epoch revocation through the API.
- ADK/Gemini assistance is bounded and read-only; model output is never mutation authority.
- Unknown or ambiguous mutation outcomes remain explicit and are never blindly retried.

See [docs/architecture.md](docs/architecture.md) and
[docs/threat-model.md](docs/threat-model.md) for the security boundary.

## Development

Run the same checks as CI:

```bash
cd backend && uv sync --all-extras --dev && uv run ruff check . && uv run mypy src && uv run pytest
cd web && npm run typecheck && npm test -- --run && npm run build
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra/bootstrap init -backend=false && terraform -chdir=infra/bootstrap validate
terraform -chdir=infra/foundation init -backend=false && terraform -chdir=infra/foundation validate
terraform -chdir=infra/runtime init -backend=false && terraform -chdir=infra/runtime validate
python scripts/check_clean_room.py
```

The source-boundary check keeps credentials, host paths, symlinks, unrecorded adaptations,
and runtime dependencies on sibling repositories out of the project.

## License

Apache License 2.0. See [LICENSE](LICENSE).
