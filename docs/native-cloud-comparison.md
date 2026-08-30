# Native-cloud comparison

ControlGraph builds on Google Cloud rather than replacing it. Cloud Run still serves revisions and
changes traffic. IAM authenticates callers. Cloud Tasks delivers work. Cloud KMS signs digests for
capabilities and selected evidence. Cloud Monitoring supplies health observations. Cloud Audit Logs
record provider activity.

ControlGraph adds a narrow authority and evidence layer around those services. Its main addition is
an execution-time decision: after claiming the exact receipt, the executor performs a fresh
authoritative epoch read immediately before the target-bound mutation adapter. Queued work can
proceed only when its signed epoch exactly matches current authority; stale, future, missing, or
unreadable authority stops before the adapter is called.

## What ControlGraph adds

| Concern | Native Google Cloud foundation | ControlGraph addition |
|---|---|---|
| Traffic changes | Cloud Run splits traffic between immutable revisions and supports rollback. Cloud Deploy can coordinate phased canaries. | A signed capability binds one approved target, plan, action, precondition, and authority epoch. After the exact receipt claim, the executor performs the fresh authoritative epoch read immediately before its fixed traffic adapter and requires an exact match. |
| Approval lifecycle | IAM and Cloud Deploy approvals control who can start or advance delivery. | A root-scoped epoch lets an operator revoke queued work without changing its signature or deleting its task. |
| Task delivery | Cloud Tasks provides authenticated, rate-limited delivery and may deliver a task more than once. | An exact receipt binds one canonical request. Duplicate delivery can adopt the same result but cannot create new mutation authority. |
| Health decisions | Cloud Monitoring exposes metrics. Cloud Deploy can run configured verification steps. | The rollout root fixes the admitted queries, windows, thresholds, and transition rules. A pure evaluator selects promotion or captured-stable recovery. |
| Recovery | Cloud Run can route traffic back to an earlier revision. Cloud Deploy can create a rollback rollout. | Recovery is restricted to the stable revision captured by the rollout root and uses a separate delivery and execution boundary. |
| Completion | Cloud Run exposes service state and Monitoring exposes serving signals. | A separate read-only verifier compares intent, receipt, configuration, and data-path evidence before ControlGraph reports a verified outcome. |
| Investigation | Cloud Audit Logs record supported provider operations. | A target-scoped timeline connects authority, execution, verification, and recovery without replacing provider logs. |
| Advisory explanation | Vertex AI supplies model inference, and Google ADK coordinates the bounded model-and-tool interaction. Neither becomes rollout authority. | Only after the deterministic outcome, Gemini 3.5 Flash on Vertex AI is coordinated by Google ADK through exactly six fixed read-only tools: Rollout root, Target state, Health evidence, Execution receipt, Evidence timeline, and Independent verifier. The cited result is `ADVISORY_ONLY` and never participates in authority, health, dispatch, recovery, or mutation decisions. |

## Demonstrated boundary

The repository and the **Accepted stale-authority run** demonstrate these additions:

- a fresh, authoritative exact-match epoch check immediately before the mutation adapter that
  stops delayed stale work without calling that adapter;
- capability scope that can stay equal or become narrower, but cannot widen;
- deterministic health evaluation followed by promotion or captured-stable recovery;
- independent configuration and data-path verification;
- explicit `AMBIGUOUS` outcomes when provider evidence cannot prove completion; and
- an ordered evidence timeline with a bounded public projection.

The [acceptance cases](acceptance-cases.md) define each expected result. The credential-free
[Live-hosted demo — Verified Replay](https://controlgraph-console-936681471311.us-central1.run.app/replay)
shows recorded evidence for one accepted stale-authority sequence, not a live control surface. Its
accepted artifact's source revision is `dcc2192dade08d3fdfd27daded0ccfdd13193fd1`; the separately
deployed viewer may run a newer revision without changing that source identity. Native identity,
signing, delivery, mutation, metrics, and audit controls remain part of the solution.

## Provider references

- [Cloud Run traffic management](https://docs.cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration)
- [Cloud Run access control](https://docs.cloud.google.com/run/docs/securing/managing-access)
- [Cloud Run monitoring](https://docs.cloud.google.com/run/docs/monitoring)
- [Cloud Run audit logging](https://docs.cloud.google.com/run/docs/audit-logging)
- [Cloud Run service read API](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/get)
- [Cloud Deploy overview](https://docs.cloud.google.com/deploy/docs/overview)
- [Cloud Deploy canary strategy](https://docs.cloud.google.com/deploy/docs/deployment-strategies/canary)
- [Cloud Deploy promotion and approvals](https://docs.cloud.google.com/deploy/docs/promote-release)
- [Cloud Deploy rollback](https://docs.cloud.google.com/deploy/docs/roll-back)
- [Cloud Deploy verification](https://docs.cloud.google.com/deploy/docs/verify-deployment)
- [Cloud Tasks queue behavior](https://docs.cloud.google.com/tasks/docs/configuring-queues)
- [Cloud Tasks duplicate execution](https://docs.cloud.google.com/tasks/docs/common-pitfalls#duplicate_execution)
- [Cloud KMS digital signatures](https://docs.cloud.google.com/kms/docs/create-validate-signatures)
- [Cloud Audit Logs](https://docs.cloud.google.com/logging/docs/audit)

This comparison covers the documented single-project, single-region reference boundary. See the
[threat model](threat-model.md) for assumptions and residual risks.
