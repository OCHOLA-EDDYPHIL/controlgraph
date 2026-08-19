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
