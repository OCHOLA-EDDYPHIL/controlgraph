# Native-cloud comparison

## Scope

ControlGraph composes Google Cloud controls rather than replacing them. [Cloud Run](https://docs.cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration)
remains the traffic and serving control plane; IAM, Cloud Tasks, Cloud KMS, Cloud Monitoring, and
Cloud Audit Logs retain their native responsibilities. [Cloud Deploy](https://docs.cloud.google.com/deploy/docs/overview)
is included solely as the provider's native release-orchestration comparison.

In this page, **inherited** means enforced by a Google Cloud service, **enforced** means a
ControlGraph request is admitted or denied by its closed application boundary, and **observed**
means a separate read-only ControlGraph path records or classifies provider state. The comparison
does not claim production readiness, exactly-once provider mutation, or a transaction spanning
Firestore and Cloud Run.

## Comparison

| Concern | Native Google Cloud capability | ControlGraph boundary and demonstrated delta |
|---|---|---|
| Traffic management | Cloud Run can split traffic between revisions, migrate traffic gradually, and route traffic back to an earlier revision. Cloud Deploy can drive phased canary rollouts to Cloud Run. See [Cloud Run traffic management](https://docs.cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration) and [Cloud Deploy canary strategy](https://docs.cloud.google.com/deploy/docs/deployment-strategies/canary). | ControlGraph relies on Cloud Run for the actual traffic update. Its demonstrated addition is a root-, target-, plan-, and epoch-bound capability followed by independent configuration and data-path observation: [Case A](acceptance-cases.md#case-a-healthy-canary-and-promotion), [traffic-path verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32441418993), and [independent-verification artifact](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32670679730). |
| Rollout controls | Cloud Deploy models releases and rollouts, supports canary phases, and provides promotion and approval workflows. See [canary strategy](https://docs.cloud.google.com/deploy/docs/deployment-strategies/canary) and [promotion and approvals](https://docs.cloud.google.com/deploy/docs/promote-release). | ControlGraph does not take credit for those controls. Its narrower enforcement is an immutable rollout root, KMS-signed attenuated capabilities, and an exact-match epoch fence: [Case A](acceptance-cases.md#case-a-healthy-canary-and-promotion), [negative-authority conformance](acceptance-cases.md#negative-authority-conformance), and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32441418993). |
| IAM and signatures | Cloud Run IAM controls who may invoke or administer services; Cloud Deploy IAM controls access to delivery resources; Cloud KMS signs supplied digests with a configured asymmetric key version. See [Cloud Run IAM](https://docs.cloud.google.com/run/docs/securing/managing-access), [Cloud Deploy IAM](https://docs.cloud.google.com/deploy/docs/iam-roles-permissions), and [Cloud KMS signatures](https://docs.cloud.google.com/kms/docs/create-validate-signatures). | These inherited controls remain necessary. ControlGraph additionally validates closed capability claims and prevents a child capability from widening its root, target, action, plan, caller, lifetime, or epoch scope: [negative-authority conformance](acceptance-cases.md#negative-authority-conformance) and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32441418993). |
| Retries and uncertain delivery | Cloud Tasks applies configured dispatch limits and retry policy, and its documentation states that duplicate executions can occur. See [queue retries](https://docs.cloud.google.com/tasks/docs/configuring-queues) and [duplicate execution](https://docs.cloud.google.com/tasks/docs/common-pitfalls#duplicate_execution). | ControlGraph does not restate native delivery as exactly-once mutation. Its demonstrated guarantees here are a fresh executor-time epoch decision and completion only after independent evidence agrees: [Case C](acceptance-cases.md#case-c-delayed-stale-task-after-manual-revocation), [stale-denial verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32441418993), and [completion-classifier artifact](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32670679730). |
| Rollback and recovery | Cloud Run can shift traffic back to an earlier revision. Cloud Deploy rollback creates a new rollout based on an earlier release. See [Cloud Run rollback](https://docs.cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration#rollback) and [Cloud Deploy rollback](https://docs.cloud.google.com/deploy/docs/roll-back). | ControlGraph's demonstrated recovery is deliberately narrower: deterministic unhealthy evidence may authorize only 100% traffic to the stable revision captured by that rollout root, followed by independent readback. See [Case B](acceptance-cases.md#case-b-unhealthy-canary-and-stable-recovery) and [exact-main recovery verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32635228713). |
| Health signals | Cloud Run exposes metrics and integrates with Cloud Monitoring. Cloud Deploy can run configured verification tasks after deployment and fail the rollout when verification fails. See [Cloud Run monitoring](https://docs.cloud.google.com/run/docs/monitoring) and [Cloud Deploy verification](https://docs.cloud.google.com/deploy/docs/verify-deployment). | ControlGraph fixes the admitted Monitoring queries, windows, thresholds, and transition rules in the rollout root, then evaluates them deterministically; the signals do not grant authority by themselves. See [Case A](acceptance-cases.md#case-a-healthy-canary-and-promotion), [Case B](acceptance-cases.md#case-b-unhealthy-canary-and-stable-recovery), and [exact-main health verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32635228713). |
| Audit evidence | Cloud Audit Logs records provider administrative and data-access activity according to each service's audit-log support and configuration. See [Cloud Audit Logs](https://docs.cloud.google.com/logging/docs/audit) and [Cloud Run audit logging](https://docs.cloud.google.com/run/docs/audit-logging). | ControlGraph supplements provider logs with an ordered, target-scoped evidence timeline and separately authorized redacted projections; it does not present that timeline as a replacement for provider audit logs. See the [acceptance evidence rule](acceptance-cases.md#status-and-evidence-rule) and [exact-main timeline verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32670679730). |
| Operator workflow | Cloud Run exposes revision traffic operations. Cloud Deploy provides release promotion, approval, verification, and rollback workflows. See [Cloud Run traffic management](https://docs.cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration), [Cloud Deploy promotion and approvals](https://docs.cloud.google.com/deploy/docs/promote-release), and [Cloud Deploy rollback](https://docs.cloud.google.com/deploy/docs/roll-back). | ControlGraph's demonstrated operator-specific addition is a root-bound manual epoch advance that causes otherwise valid delayed work to fail closed; the evidence timeline makes that decision reviewable. See [Case C](acceptance-cases.md#case-c-delayed-stale-task-after-manual-revocation), [stale-denial verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32441418993), and [timeline verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32670679730). |
| Independent observation | Cloud Run exposes [service state](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/get), while Cloud Monitoring exposes serving signals. These are provider facts, not an application-level conclusion that a rollout completed. | A separate read-only verifier canonicalizes configuration, performs a bounded harmless revision probe, and classifies completion only when intent, receipt, configuration, and data-path evidence agree: [Case A](acceptance-cases.md#case-a-healthy-canary-and-promotion), [Case B](acceptance-cases.md#case-b-unhealthy-canary-and-stable-recovery), and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32670679730). |

## Exact ControlGraph claim boundary

The accepted evidence supports only these ControlGraph additions:

- exact-match epoch fencing and executor-time denial of stale work — [Case C](acceptance-cases.md#case-c-delayed-stale-task-after-manual-revocation) and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32441418993);
- KMS-signed capability attenuation within a fixed rollout root — [Case A](acceptance-cases.md#case-a-healthy-canary-and-promotion), [negative-authority conformance](acceptance-cases.md#negative-authority-conformance), and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32441418993);
- deterministic health evaluation and healthy promotion — [Case A](acceptance-cases.md#case-a-healthy-canary-and-promotion) and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32635228713);
- deterministic captured-stable recovery — [Case B](acceptance-cases.md#case-b-unhealthy-canary-and-stable-recovery) and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32635228713);
- independent configuration and data-path verification — [Case A](acceptance-cases.md#case-a-healthy-canary-and-promotion), [Case B](acceptance-cases.md#case-b-unhealthy-canary-and-stable-recovery), and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32670679730); and
- an ordered evidence timeline with bounded, redacted projections — the [acceptance evidence rule](acceptance-cases.md#status-and-evidence-rule) and [exact-main verification](https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/32670679730).

Authentication, signing, task delivery, traffic mutation, provider metrics, deployment workflows,
and cloud audit logging remain inherited native controls. ControlGraph neither replaces nor
weakens them.

## Dated primary references

The comparison was reviewed on 2026-08-24 against these first-party Google Cloud pages. The dates
shown are the pages' own “Last updated” dates at review time.

- [Cloud Run: Rollbacks, gradual rollouts, and traffic migration](https://docs.cloud.google.com/run/docs/rollouts-rollbacks-traffic-migration) — 2026-08-19 UTC.
- [Cloud Run: Access control with IAM](https://docs.cloud.google.com/run/docs/securing/managing-access) — 2026-08-19 UTC.
- [Cloud Run: Monitor health and performance](https://docs.cloud.google.com/run/docs/monitoring) — 2026-08-19 UTC.
- [Cloud Run audit logging](https://docs.cloud.google.com/run/docs/audit-logging) — 2026-08-19 UTC.
- [Cloud Run API: Get a service](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/get) — 2025-07-09 UTC.
- [Cloud Deploy overview](https://docs.cloud.google.com/deploy/docs/overview) — 2026-08-11 UTC.
- [Cloud Deploy: Use a canary deployment strategy](https://docs.cloud.google.com/deploy/docs/deployment-strategies/canary) — 2026-08-11 UTC.
- [Cloud Deploy: Promote your release and manage approvals](https://docs.cloud.google.com/deploy/docs/promote-release) — 2026-08-11 UTC.
- [Cloud Deploy: Roll back a target](https://docs.cloud.google.com/deploy/docs/roll-back) — 2026-08-11 UTC.
- [Cloud Deploy: Verify your deployment](https://docs.cloud.google.com/deploy/docs/verify-deployment) — 2026-08-11 UTC.
- [Cloud Deploy: IAM roles and permissions](https://docs.cloud.google.com/deploy/docs/iam-roles-permissions) — 2026-08-11 UTC.
- [Cloud Tasks: Configure queue routing, limits, and retries](https://docs.cloud.google.com/tasks/docs/configuring-queues) — 2026-08-13 UTC.
- [Cloud Tasks: Common issues, including duplicate execution](https://docs.cloud.google.com/tasks/docs/common-pitfalls#duplicate_execution) — 2026-08-11 UTC.
- [Cloud KMS: Creating and validating digital signatures](https://docs.cloud.google.com/kms/docs/create-validate-signatures) — 2026-08-11 UTC.
- [Cloud Audit Logs overview](https://docs.cloud.google.com/logging/docs/audit) — 2026-08-21 UTC.
