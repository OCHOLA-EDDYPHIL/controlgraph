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

## Cloud boundaries

The Google adapters are deliberately narrower than the underlying APIs:

- Firestore is fixed to the `controlgraph-authority` database in `us-central1`, canonical
  authority, receipt, health-chain, and recovery records, deterministic document identities,
  strong reads, and transactional compare-and-set operations.
- KMS signing is fixed to P-256/SHA-256, an explicit key version, and either the capability or
  evidence purpose. Private key material never enters application configuration. Capability and
  evidence signing use distinct identities; the verifier has no signing or authority-write grant.
- Cloud Tasks derives its queue, handler origin and path, audience, and OIDC caller from startup
  configuration. It performs one create call and treats an exact deterministic task name as the
  duplicate boundary.
- Terraform wires the `api`, `coordinator`, `issuer`, `executor`, `recovery`, `verifier`, and
  `evidence_writer` composition roots to separate Cloud Run identities and exact authenticated
  routes.

The verifier derives fixed candidate-revision Cloud Monitoring queries from the immutable root,
canonicalizes the returned request-count and latency samples, applies the frozen health policy,
and obtains a signed decision proof. A terminal healthy proof can authorize a 100 percent
candidate promotion through the normal executor. A terminal unhealthy proof is appended in the
same transaction that creates the root-owned recovery intent; the coordinator then owns its
deterministic dispatch record and addressed recovery task.

The recovery service validates the task caller and signed stable-only capability, then forwards
the same canonical task once to a recovery-only executor facade. The executor independently
reverifies the task, signed verifier prestate, root, epoch, and captured stable revision before
claiming through the separate recovery receipt route. Its final gate then rereads the durable
source receipt and current root and epoch before issuing one conditional traffic-only update
naming only the captured stable revision at 100 percent. Provider uncertainty remains
`AMBIGUOUS` and can advance only through exact readback, never a blind mutation retry.

Every service exposes identity-safe `GET /healthz` and `GET /v1/metadata` responses. The
`.env.example` file shows a non-mutating API baseline; each deployed role receives its complete
validated configuration from Terraform. `controlgraph-canary serve` refuses another project
family, region, database, role, contract version, mutable build reference, or inconsistent
role-specific authority configuration.

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

The ordinary test suite skips those emulator cases when the endpoint is absent. Fake
provider tests still cover commit ambiguity, exact readback, corruption, and sanitized failure
classes on every run.
