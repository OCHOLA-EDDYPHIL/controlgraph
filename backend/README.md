# ControlGraph Canary backend

The backend is a Python 3.12 package divided by authority:

- `authority/` contains dependency-free domain primitives and policy;
- `contracts/` contains strict versioned wire models and canonical encodings;
- `application/` contains use cases and narrow provider protocols;
- `integrations/google/` contains Google Cloud implementations;
- `http/` and `cli.py` expose authenticated operator and task interfaces;
- `services/` contains role-specific composition roots; and
- `reference_target/` contains the harmless stable/candidate probe service.

Dependencies point inward toward `application`, `contracts`, and `authority`. In particular,
`authority/` cannot import HTTP, Google Cloud, model, or agent-framework packages. The CLI
uses the authenticated API and never writes authority state or mutates Cloud Run directly.

## M2 cloud boundaries

The Google adapters are deliberately narrower than the underlying APIs:

- Firestore is fixed to the `controlgraph-authority` database in `us-central1`, four versioned
  record families, deterministic document identities, strong reads, and transactional
  compare-and-set operations.
- KMS signing is fixed to P-256/SHA-256, an explicit key version, and either the capability or
  evidence purpose. Private key material never enters application configuration. Capability and
  evidence signing use distinct identities; the verifier has no signing or authority-write grant.
- Cloud Tasks derives its queue, handler origin and path, audience, and OIDC caller from startup
  configuration. It performs one create call and treats an exact deterministic task name as the
  duplicate boundary.
- Terraform wires the `api`, `coordinator`, `issuer`, `executor`, `recovery`, and `verifier`
  composition roots to separate Cloud Run identities. Their M2 protected routes return
  `MUTATION_DISABLED`.

Every service exposes identity-safe `GET /healthz` and `GET /v1/metadata` responses. Starting a
role requires the complete validated environment shown in `.env.example`; `controlgraph-canary
serve` refuses another project family, region, database, role, contract version, mutable build
reference, or enabled M2 mutation flag.

## Firestore emulator acceptance

Start the installed Google Cloud Firestore emulator in one terminal:

```bash
gcloud beta emulators firestore start \
  --host-port=127.0.0.1:8787 \
  --database-mode=firestore-native \
  --project=controlgraph-canary-emulator
```

Then exercise the real asynchronous SDK and transaction retry path:

```bash
FIRESTORE_EMULATOR_HOST=127.0.0.1:8787 \
  uv run pytest tests/test_m2_firestore_emulator.py
```

The ordinary test suite skips those three emulator cases when the endpoint is absent. Fake
provider tests still cover commit ambiguity, exact readback, corruption, and sanitized failure
classes on every run.
