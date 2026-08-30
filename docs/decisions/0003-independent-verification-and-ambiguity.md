# Decision 0003: verify effects independently and preserve ambiguity

- Status: Accepted
- Scope: mutation receipts and terminal rollout outcomes

## Context

A provider can accept a request and lose the response. A worker can time out after the effect. A
successful HTTP response can also disagree with later target state. Retrying in these conditions
can duplicate a mutation, while trusting the executor alone can report success without proof.

## Decision

ControlGraph permits one provider attempt for a directly confirmed fresh receipt claim. The
receipt binds the complete canonical request. Exact duplicates can adopt the same result; altered
reuse is denied.

A separate read-only verifier observes target configuration and required data-path evidence.
ControlGraph reports a verified outcome only when intent, receipt, configuration, and observation
agree. If a provider response cannot prove whether the effect occurred, the receipt remains
`AMBIGUOUS`. Exact readback can resolve it. Delivery or HTTP failure never creates permission for a
blind mutation retry.

## Consequences

- The component that requests a change is not the sole source of completion evidence.
- Unknown outcomes stay visible instead of becoming success-shaped records.
- Some outcomes take longer to resolve because the system waits for decisive readback.
- Operators can distinguish a proven safe failure, a verified effect, and unresolved provider
  uncertainty.

Automatic retry after a possible provider effect and completion based only on an executor response
were rejected because both can hide or duplicate a change.
