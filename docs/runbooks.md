# Operations runbooks

These procedures apply only to the isolated ControlGraph environment and its fixed reference
target. They do not grant authority: every mutation still requires the normal authenticated API,
root binding, exact epoch, purpose-specific identity, capability, provider precondition, receipt,
and readback gates.

## Alert contract

Each alert counts one fixed log signal with no extracted metric labels. The source resource set is
limited to the ControlGraph coordinator, two fixed task queues, or the signing key ring. Every
policy sends an opening notification and a recovery notification to the explicit operator email
channel. The alert includes links to this runbook and project Logs Explorer.

| Signal | Opens when | Severity | Incident owner | Correlate with |
|---|---|---|---|---|
| Stale denial | One terminal stale-capability denial is recorded in 60 seconds | Warning | Operator | Timeline root digest and epoch |
| Ambiguous mutation | One ambiguous mutation receipt is recorded in 60 seconds | Error | Operator | Timeline root digest and epoch; receipt evidence |
| Stuck task | A fixed-queue response is non-OK or reaches dispatch attempt 3 | Error | Operator | Queue, task activity log, and addressed receipt |
| Unhealthy rollout | One deterministic terminal-unhealthy health decision is recorded | Warning | Operator | Signed health proof and root digest |
| Failed recovery | One recovery completion remains ambiguous | Critical | Operator | Recovery receipt, target readback, root digest, and epoch |
| Key problem | A signing-key call fails or a key version is updated or destroyed | Critical | Security audit | KMS audit method, key version, and affected signature purpose |
| Verifier disagreement | Configuration verification disagrees or execution evidence contradicts | Error | Security audit | Signed configuration/probe evidence and root digest |
| Evidence failure | Required evidence is absent, stale, unavailable, inconclusive, or misbound | Error | Security audit | Timeline reason, evidence digest, and signing-key version |

The root digest and epoch in an application signal are correlation fields, not metric labels.
Provider alerts correlate by their fixed queue or key resource. After matching samples stop,
Monitoring can close the incident on a subsequent evaluation; the 30-minute auto-close is the
absent-data fallback. A closure sends the recovery notification, but the owner must still record
the independently verified recovery evidence before resolving the incident record.

## Incident rules

1. Record the alert policy, opening time, exact source revision, deployed image digest, root digest,
   epoch, and fixed resource named by the alert.
2. Stop new operator work for the affected root. Do not retry an ambiguous mutation, edit
   Firestore, impersonate a workload, or call Cloud Run traffic APIs directly.
3. Keep duties separate: the operator coordinates and confirms operator commands; the executor is
   the only target mutator; recovery can only forward stable-only work; signers sign only their
   purpose; the verifier and security auditor remain read-only.
4. Use the timeline and signed evidence to select an existing root-bound procedure. Never type a
   replacement service, revision, image, target, key, queue, or epoch into a mutation path.
5. Close the incident only after the triggering state has cleared, the alert has sent its recovery
   notification, and independent readback agrees with durable evidence.

## Deploy

1. Review immutable controller, advisor, console, stable, and candidate image digests and saved
   foundation and runtime plans for the dedicated project. Reject mutable tags and unrelated IAM,
   service, target, or region changes.
2. The infrastructure operator applies the reviewed foundation plan before the runtime plan. A
   runtime workload never receives infrastructure administration.
3. Read each service's authenticated metadata and confirm its build digest and role. Confirm the
   reference target still matches the pre-deploy snapshot; deployment does not select rollout
   traffic.
4. Exercise one read-only timeline query and verify that alert policies and the operator
   notification channel are enabled and verified. Product acceptance remains a separate
   root-bound workflow.

## Rollback

1. Stop new operator requests and identify the last accepted source revision and immutable image
   digests from retained deployment evidence.
2. If rollout authority may still be active, advance its epoch through the manual revocation
   procedure before changing controller images.
3. Review a Terraform plan that changes only the affected controller image digest or configuration
   back to the accepted values. Apply it as the infrastructure operator.
4. Verify service metadata, queue state, authority reads, and target traffic independently. A
   controller rollback never rewrites receipts, chooses target traffic, or revives an old epoch.

## Stale denial and manual epoch revocation

1. Read the exact root, root digest, current epoch, active service claim, and timeline evidence
   through the authenticated operator surface.
2. Submit `controlgraph-canary revoke-epoch` with those exact values, a unique request and
   idempotency key, a recorded reason, and `--confirm REVOKE`.
3. Retrieve the matching `revocation-proof`; verify the evidence signature, previous epoch, new
   epoch, request digest, and audit identity.
4. Deliver any already-addressed task only through its fixed queue. Its stale capability must be
   denied at the executor's fresh authority read; never alter the task or mint replacement
   authority for the old epoch.

## Key rotation or disablement

1. The security auditor identifies the exact purpose, key version, audit method, and affected
   signatures without reading private key material. A planned version update also opens this alert
   and must use the same review.
2. Stop new work for affected roots and revoke active epochs if signing trust is uncertain. Drain or
   contain addressed work before changing the configured version.
3. The infrastructure operator creates or enables a purpose-matched version through reviewed
   Terraform, then deploys the exact trust and signer configuration. Capability and evidence keys
   remain separate; signer identities receive no key administration.
4. Verify new signatures and retained old signatures independently before disabling an old
   version. Do not destroy a key version during incident response. Destruction requires a separate
   retention and evidence review.

## Queue drain

1. Stop new operator admissions for the affected root and observe both fixed queue depths and task
   activity logs. Let healthy addressed deliveries finish until depth is zero.
2. For containment, revoke the root epoch first, then use `controlgraph-canary execution-queue
   hold --confirm HOLD_EXECUTION_QUEUE` on the fixed execution queue. Do not purge, delete, edit,
   retarget, or replay tasks.
3. The recovery queue remains separate and stable-only. Its identity cannot mutate the target; it
   may only forward the unchanged task to the executor recovery facade.
4. After authority and downstream health are independently restored, use the fixed execution-queue
   release command. Confirm delayed work is either exactly adopted or denied by the current epoch,
   and keep observing until both depths are zero.

## Authority read failure

1. Treat every failed or uncertain authority read as a denial. Stop new work and contain the
   execution queue; do not use cached epochs or issue a capability from an earlier read.
2. The security auditor checks Firestore availability and audit logs while the operator checks the
   root through the API. Neither identity edits authority documents.
3. Restore only provider availability or reviewed configuration. Then perform fresh authoritative
   reads through the normal service boundary and verify the same root digest and current epoch.
4. Resume the queue only after reads succeed and any delayed task is expected to pass or fail using
   that exact epoch.

## Ambiguous mutation readback

1. Stop new work for the root and preserve the ambiguous receipt, expected post-state digest, and
   provider precondition. Never dispatch the mutation again.
2. Run the executor-bound `controlgraph-ambiguous-receipt-readback` once with the canonical command
   for that stored receipt. The command can only read the configured target and adopt an exact
   expected post-state.
3. If readback verifies the expected state, record the updated receipt and independent completion
   evidence. If it does not, keep the outcome ambiguous.
4. After the recorded dispatch deadline, an operator may use the authenticated
   `abandon-ambiguous-recovery` workflow. It fences authority and may require a separately audited
   reset; it never grants another mutation attempt.

## Stable recovery

1. Confirm the trigger is either a signed terminal-unhealthy V3 chain or an explicitly revoked root
   and that its recovery source binds the exact captured stable revision.
2. For revoked-root recovery, submit `recover-captured-stable` with the canonical root-derived
   command. The operator confirms recovery but does not choose a service, revision, traffic split,
   or concurrency.
3. Recovery verifies and forwards the unchanged task once. The executor recovery facade repeats
   capability, source-receipt, root, epoch, prestate, and target checks before one conditional
   stable-only update.
4. Require exact target readback, signed configuration and probe evidence, a verified recovery
   receipt, and terminal classification before releasing the service claim. Any mismatch remains
   ambiguous and follows the readback procedure.

## Verifier disagreement or evidence failure

1. The security auditor compares the signed configuration and probe records with the immutable
   root, expected action, target, epoch, evidence key version, and freshness bounds.
2. Missing, unavailable, stale, inconclusive, contradictory, or misbound evidence cannot be
   replaced with a manual assertion. The verifier remains read-only and cannot repair the target.
3. Restore the failing read or signing dependency, then request fresh evidence through the normal
   coordinator-to-verifier and evidence-writer routes. Do not weaken a threshold or signature
   check to clear the alert.
4. Reclassify only the complete fresh bundle. Close the incident when the new signed evidence and
   independent target readback agree.

## Incident evidence export

1. A distinct restricted-export identity requests the fixed target's bounded raw timeline export;
   the operator and browser console are not substitutes for that identity.
2. Export at most the contract page limit, follow the signed cursor, and preserve entry, payload,
   signature, policy, and deletion-receipt digests. Never export bearer tokens, cookies,
   capabilities, credentials, or provider state.
3. Store the incident bundle in the approved restricted evidence location with the source revision,
   deployed image digests, alert and recovery times, and the verifier result. Public summaries use
   only the redacted timeline projection.

## Release evidence verification

Release attestations use the pinned Sigstore Fulcio and RFC3161 timestamp-authority trust material.
The signing configuration intentionally excludes Rekor because its public log can disclose private
SBOM and provenance predicates. Cosign's `--insecure-ignore-tlog` switch is permitted only together
with the pinned trusted root and `--use-signed-timestamps`; verification still requires the
signature, certificate and SCT chain, signed timestamp, exact GitHub workflow identity, subject
digest, and retained predicate content. The resulting limitation is no public transparency-log
inclusion, so retain the private bundles with the release archive and verify OCI-referrer support in
the hosted Artifact Registry acceptance run.

## Rehearsal protocol

Rehearse each critical procedure against the isolated reference target before relying on it. Use a
fresh root, exact main revision and image digests, bounded task and model calls, and a recorded
before/after target hash. Capture alert opening and recovery delivery, role-denial checks, final
queue depth, target traffic, evidence signatures, and cleanup. A rehearsal is accepted only when
the reference target returns to its independently verified baseline and no temporary privilege or
fixture remains.
