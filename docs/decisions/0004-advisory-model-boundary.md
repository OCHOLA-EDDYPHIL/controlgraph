# Decision 0004: keep model assistance outside authority

- Status: Accepted
- Scope: Google ADK and Gemini integration

## Context

Model assistance can help an operator connect receipts, timeline events, health evidence, and
target observations. Model output is probabilistic and may be unavailable, malformed, stale, or
influenced by untrusted text. It cannot safely decide whether a rollout action is authorized.

## Decision

Deterministic code owns authority, health classification, task dispatch, promotion, recovery, and
provider mutation. The optional advisor receives only typed, read-only summaries through a fixed
application facade. Its structured output must cite recorded evidence and pass validation before
it can appear in the timeline.

Advisor output is always `ADVISORY_ONLY`. It cannot issue or sign a capability, advance an epoch,
enqueue work, choose an arbitrary revision, override a health result, or call a mutation adapter.
An operator reviews any suggested next step through the existing deterministic control surface.

## Consequences

- Operators can use model-assisted explanation without moving the model into the trust boundary.
- Advisor failure does not block deterministic inspection or authority controls.
- Model and prompt changes can alter explanations but cannot alter mutation authority.
- The integration needs citation validation, bounded read-only tools, redaction, and an audit record.

Allowing the model to orchestrate rollout actions or treating its rationale as proof was rejected
because either choice would make probabilistic output authority-bearing.
