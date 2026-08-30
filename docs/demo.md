# Evidence-backed demo

This demo shows the problem ControlGraph solves: queued work can keep valid credentials after its
approval is no longer current. The recorded sequence connects the authority change, executor
decision, target readback, recovery, and optional advisory explanation.

Open the credential-free
[Live-hosted demo — Verified Replay](https://controlgraph-console-936681471311.us-central1.run.app/replay)
for recorded evidence from the **Accepted stale-authority run**. It is not a live control surface.
Use the [canary quickstart](quickstart.md) to reproduce the full workflow in an isolated project.

## The recorded sequence at a glance

![A promotion queued at epoch N reaches the executor after authority advances to N+1, so ControlGraph blocks it, verifies unchanged traffic, and restores stable traffic with new authority.](assets/stale-authority-flow.svg)

[Open the editable Draw.io source](assets/stale-authority-flow.drawio).

The important point is the timing. The promotion is authentic, signed, and correctly addressed.
It stops because the executor checks the current epoch immediately before the traffic operation.

## Walk through the result

### 1. Start from a known canary

Capture the stable revision, create the rollout root, and apply the approved 90/10 split. Show the
execution receipt, configuration readback, and probe evidence together. They must name the same
target, root, epoch, request, and traffic plan.

The result is a canary whose starting state is independently confirmed.

### 2. Show deterministic outcomes

Run the fixed Monitoring policy against the approved observation windows. Healthy evidence can
authorize promotion to the candidate. Terminal unhealthy evidence can authorize recovery only to
the stable revision captured by the root.

The policy selects the branch. The model does not choose promotion or recovery.

### 3. Revoke queued work

Return to a verified 90/10 state and queue promotion work under epoch N. Hold delivery, then let
the operator advance authority to N+1. Release the queued task.

The task can pass caller, signature, lineage, target, and plan checks. After claiming its exact
receipt, the executor performs a fresh authoritative read of the root's current epoch immediately
before the target-bound mutation adapter. The signed epoch N does not equal current epoch N+1, so
the executor returns `DENIED / EPOCH_MISMATCH` without calling the adapter. Missing, unreadable, or
otherwise nonmatching authority also fails closed. No traffic update is admitted.

### 4. Verify the target and explain the evidence

Compare configuration and probe evidence from before and after the denial. Both observations must
show the same 90/10 target state.

Only after the deterministic denial and unchanged-target readback, Gemini 3.5 Flash on Vertex AI
is coordinated by Google ADK through exactly six fixed read-only tools: Rollout root, Target state,
Health evidence, Execution receipt, Evidence timeline, and Independent verifier. The tools expose
bounded recorded summaries, and the accepted structured result cites its evidence. The result is
`ADVISORY_ONLY`; it has no apply action and never participates in authority, health, dispatch,
recovery, or mutation decisions.

### 5. Recover with current authority

Create new stable-only recovery authority at N+1. The recovery service validates and forwards the
task to the executor's recovery-only path. Independent readback must confirm 100 percent traffic
on the captured stable revision.

The old epoch stays revoked. Recovery succeeds because it uses new authority, not because stale
authority becomes valid again.

## Verification gates

| Claim | Required evidence |
|---|---|
| The canary reached 90/10 | Matching execution receipt, target readback, revision probe, and timeline event |
| A healthy candidate was promoted | Terminal healthy proof followed by verified 100 percent candidate traffic |
| An unhealthy candidate recovered | Terminal unhealthy proof, root-owned recovery intent, recovery receipt, and verified stable traffic |
| Revocation stopped delayed work | N-to-N+1 authority transition, `EPOCH_MISMATCH` receipt, and unchanged before-and-after target reads |
| The advisor explained rather than acted | Gemini 3.5 Flash on Vertex AI coordinated by Google ADK; all six fixed read-only tool calls; cited receipt, timeline, and target or verifier records; `ADVISORY_ONLY`; no authority, health, dispatch, recovery, or mutation effect |

If the records disagree, belong to different roots, or fall outside the accepted interval, the
claim is not verified. ControlGraph keeps that uncertainty visible.

The underlying evidence contracts are available in:

- [target observation](../backend/src/controlgraph_canary/contracts/operator_observability.py);
- [probe and independent verification](../backend/src/controlgraph_canary/contracts/independent_verification.py);
- [signed evidence](../backend/src/controlgraph_canary/contracts/root_creation.py);
- [timeline records](../backend/src/controlgraph_canary/contracts/timeline.py); and
- [completion classification](../backend/src/controlgraph_canary/application/completion_classification.py).

## What the public replay validates

Before it renders, the browser validates the published artifact, closed schemas, payload digest,
acceptance-case bindings, immutable image references, and event chain. The visible sequence covers
the authority advance, stale denial, unchanged target, cited advisor result, verified recovery,
and committed timeline.

Full artifact source, manifest, event, and image identifiers remain available under
**Verification gates** in the replay. The displayed source commit is the accepted artifact source,
`dcc2192dade08d3fdfd27daded0ccfdd13193fd1`, not necessarily the revision of the separately
deployed viewer. The accepted manifest is the complete evidence record; the replay is its bounded,
redacted projection.

## Demonstration scope

The demo uses one disposable Cloud Run target in one isolated Google Cloud project and region. It
contains synthetic identifiers and no customer workload. The result supports the documented
reference cases for the recorded run. It does not establish general production suitability.

Finish by confirming 100 percent stable traffic, the stable probe marker, a released service
claim, and an empty running execution queue. Infrastructure teardown is a separate operator
action.
