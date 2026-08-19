# Third-party notices

ControlGraph Canary is licensed under Apache-2.0. The project depends on or uses development tooling from the following projects. Their own license texts and distributions remain authoritative.

| Project | Use | License |
|---|---|---|
| FastAPI | Python HTTP API | MIT |
| Pydantic | API response models | MIT |
| Uvicorn | ASGI server | BSD-3-Clause |
| pytest | Python tests | MIT |
| mypy | Python type checking | MIT |
| Ruff | Python linting | MIT |
| React / React DOM | Web console | MIT |
| Vite | Web build tooling | MIT |
| TypeScript | Type checking and compilation | Apache-2.0 |
| Vitest | Web tests | MIT |
| Testing Library | Component tests | MIT |
| jsdom | Test DOM implementation | MIT |
| Hypothesis | Property-based Python tests | MPL-2.0 |
| Terraform | Infrastructure tooling | BUSL-1.1 for current upstream releases; verify the installed version |
| Google Terraform provider | Future Cloud Run resource provider | MPL-2.0 |
| GitHub checkout/setup actions | CI bootstrap | MIT |
| HashiCorp setup-terraform action | CI bootstrap | MPL-2.0 |

Container base images and transitive packages may carry additional notices. Produce a dependency lock and software bill of materials for every release, then ship the corresponding source/license obligations with that release.

Selected implementation patterns are adapted from owner-authored RECONCILE sources under
explicit owner authorization. They are not third-party code and do not create a runtime or
source-path dependency. The immutable source revision, source paths, ownership, and material
modifications are recorded in `docs/provenance.md`.
