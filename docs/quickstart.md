# Reproducible canary quickstart

This runbook reproduces the closed ControlGraph Canary story in one dedicated,
non-production Google Cloud project: establish a 100/0 stable baseline, stage an immutable
candidate, apply 90/10 traffic, evaluate deterministic health, promote or recover, revoke an
epoch, prove stale work is denied, review the timeline, and reset the target. It does not claim
production readiness or support for arbitrary services.

Run hosted acceptance only with explicit owner authorization. The commands below mutate the
disposable reference target and incur bounded Google Cloud cost. They do not create or save a
service-account key; `gcloud` uses the active human identity and the runtime uses workload
identities.

## Pinned prerequisites

| Tool or boundary | Required value |
|---|---|
| Source | one clean, reviewed commit on `main` |
| Python | 3.12 |
| `uv` | lockfile-respecting install with `--frozen` |
| Node.js | 22; dependencies from `web/package-lock.json` with `npm ci` |
| Terraform | 1.10.3; checked-in provider lock files |
| Google Cloud | one project named `controlgraph-canary-*`, `us-central1`, billing and organization access |
| Operator | one approved human principal and subject; Application Default Credentials and `gcloud` login |
| Utilities | Git, Google Cloud CLI, GitHub CLI, and `jq` 1.7 |

The pinned CI definitions are in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
Terraform's isolation, budget, retention, and least-privilege boundaries are detailed in
[`infra/README.md`](../infra/README.md).

Pin the run before doing anything else:

```bash
git switch main
git pull --ff-only
test -z "$(git status --porcelain=v1)"
CG_SOURCE_SHA="$(git rev-parse HEAD)"
test "$(git branch --show-current)" = main
CG_RUN_DIR="$(mktemp -d)"
```

Keep the run directory outside the repository. It contains only synthetic test evidence, but it
must still be access-controlled and retained or deleted according to the acceptance decision.

## Verify the exact source

Run the same local gates as CI:

```bash
(cd backend && uv sync --frozen --all-extras --dev)
(cd backend && uv run ruff check .)
(cd backend && uv run mypy src)
(cd backend && uv run pytest)
(cd web && npm ci)
(cd web && npm run typecheck)
(cd web && npm run test:ci)
(cd web && npm run build)
terraform -chdir=infra fmt -check -recursive
uv run --project backend --frozen python scripts/check_clean_room.py
test "$(git rev-parse HEAD)" = "$CG_SOURCE_SHA"
test -z "$(git status --porcelain=v1)"
```

Local checks are necessary, but they are not hosted acceptance evidence.

## Provision the isolated environment

Use reviewed, untracked copies of each `terraform.tfvars.example`. Replace every synthetic value,
review each saved plan, and apply the stacks in order. Bootstrap starts with local state because
its bucket does not yet exist:

```bash
cp infra/bootstrap/terraform.tfvars.example infra/bootstrap/terraform.tfvars
terraform -chdir=infra/bootstrap init -backend=false
terraform -chdir=infra/bootstrap validate
terraform -chdir=infra/bootstrap plan -out=bootstrap.tfplan
terraform -chdir=infra/bootstrap apply bootstrap.tfplan
```

Migrate bootstrap state and initialize the later stacks exactly as described in
[`infra/README.md`](../infra/README.md#bootstrap-and-state-migration), using separate
`bootstrap`, `foundation`, and `runtime` prefixes. Then apply foundation:

```bash
CG_STATE_BUCKET="$(terraform -chdir=infra/bootstrap output -raw state_bucket_name)"
cp infra/foundation/terraform.tfvars.example infra/foundation/terraform.tfvars
terraform -chdir=infra/foundation init -lockfile=readonly \
  -backend-config="bucket=$CG_STATE_BUCKET" -backend-config="prefix=foundation"
terraform -chdir=infra/foundation validate
terraform -chdir=infra/foundation plan -out=foundation.tfplan
terraform -chdir=infra/foundation apply foundation.tfplan
```

Publish all five images from the pinned `main` commit. The workflow rejects other refs and emits
immutable `@sha256:` references:

```bash
gh workflow run deploy.yml --ref main
gh run list --workflow deploy.yml --branch main --event workflow_dispatch \
  --limit 20 --json databaseId,headSha,status > "$CG_RUN_DIR/publish-runs.json"
CG_PUBLISH_RUN_ID="$(jq -r --arg sha "$CG_SOURCE_SHA" \
  'map(select(.headSha == $sha))[0].databaseId // empty' "$CG_RUN_DIR/publish-runs.json")"
test -n "$CG_PUBLISH_RUN_ID"
gh run watch "$CG_PUBLISH_RUN_ID" --exit-status
test "$(gh run view "$CG_PUBLISH_RUN_ID" --json headSha --jq .headSha)" = "$CG_SOURCE_SHA"
```

Confirm the completed workflow's `headSha` equals `$CG_SOURCE_SHA`. Copy its five immutable image
outputs into the untracked runtime variables. First create the stable revision, then change only
`reference_target_deployment_phase` to `candidate` and apply again; the second apply stages the
candidate at zero percent traffic.

```bash
cp infra/runtime/terraform.tfvars.example infra/runtime/terraform.tfvars
terraform -chdir=infra/runtime init -lockfile=readonly \
  -backend-config="bucket=$CG_STATE_BUCKET" -backend-config="prefix=runtime"
terraform -chdir=infra/runtime validate
terraform -chdir=infra/runtime plan -out=runtime-stable.tfplan
terraform -chdir=infra/runtime apply runtime-stable.tfplan

terraform -chdir=infra/runtime plan -out=runtime-candidate.tfplan
terraform -chdir=infra/runtime apply runtime-candidate.tfplan
mkdir -p "$CG_RUN_DIR/artifacts"
terraform -chdir=infra/runtime show -json runtime-candidate.tfplan \
  > "$CG_RUN_DIR/artifacts/runtime-candidate-plan.json"
terraform -chdir=infra/runtime output -json reference_target > "$CG_RUN_DIR/reference-target.json"
terraform -chdir=infra/runtime output -json controller_services > "$CG_RUN_DIR/controllers.json"
terraform -chdir=infra/runtime output -json task_queues > "$CG_RUN_DIR/task-queues.json"
terraform -chdir=infra/runtime output -json operator_console > "$CG_RUN_DIR/operator-console.json"
```

The two runtime plans must show the exact dedicated project and service, bounded scaling, private
target ingress, separate execution and recovery queues, and only immutable images. The checked-in
[runtime output contract](../infra/runtime/outputs.tf) is the configuration evidence source.

## Run the closed acceptance sequence

Set coordinates from Terraform output rather than retyping them:

```bash
CG_PROJECT_ID="$(jq -r '.project_id' "$CG_RUN_DIR/reference-target.json")"
CG_PROJECT_NUMBER="$(terraform -chdir=infra/foundation output -raw project_number)"
CG_ACCEPTANCE_IDENTITY="$(gcloud config get-value account)"
CG_CLI=(uv run --project backend --frozen controlgraph-canary)
```

Place the exact reviewed canonical health-policy JSON under the external artifact directory, then
generate the closed eight-case specification rather than hand-authoring it. The generator binds
the source commit, five images, `nonprod` target and revisions, Terraform plan, policy, seed, test
clock, case order, duration bounds, and cost bounds:

```bash
CG_POLICY_ARTIFACT="inputs/rollout-health-policy.json"
CG_POLICY_SCHEMA_VERSION="$(jq -r '.schema_version' \
  "$CG_RUN_DIR/artifacts/$CG_POLICY_ARTIFACT")"
uv run --project backend --frozen python scripts/core_acceptance.py generate-spec \
  --artifact-root "$CG_RUN_DIR/artifacts" \
  --output "$CG_RUN_DIR/core-acceptance-spec.json" \
  --project-id "$CG_PROJECT_ID" \
  --source-commit "$CG_SOURCE_SHA" \
  --stable-revision "$(jq -r '.stable_revision' "$CG_RUN_DIR/reference-target.json")" \
  --candidate-revision "$(jq -r '.candidate_revision' "$CG_RUN_DIR/reference-target.json")" \
  --controller-image "$(terraform -chdir=infra/runtime output -raw runtime_image)" \
  --advisor-image "$(terraform -chdir=infra/runtime output -raw advisor_image)" \
  --console-image "$(jq -r '.image' "$CG_RUN_DIR/operator-console.json")" \
  --reference-stable-image "$(jq -r '.stable_image' "$CG_RUN_DIR/reference-target.json")" \
  --reference-candidate-image "$(jq -r '.candidate_image' "$CG_RUN_DIR/reference-target.json")" \
  --terraform-plan runtime-candidate-plan.json \
  --policy-schema-version "$CG_POLICY_SCHEMA_VERSION" \
  --policy-artifact "$CG_POLICY_ARTIFACT" \
  --clock-start "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --random-seed 17
```

Review the generated specification before execution. The hosted runner writes canonical command
files under the external artifact directory and binds their evidence into one manifest. Both
confirmations below are intentional because the command changes the disposable target:

```bash
CONTROLGRAPH_CORE_ACCEPTANCE_CONFIRM=RUN_CONTROLGRAPH_CORE_ACCEPTANCE \
uv run --project backend --frozen python scripts/core_acceptance.py execute \
  --spec "$CG_RUN_DIR/core-acceptance-spec.json" \
  --artifact-root "$CG_RUN_DIR/artifacts" \
  --output-spec "$CG_RUN_DIR/executed-spec.json" \
  --output "$CG_RUN_DIR/manifest.json" \
  --project-number "$CG_PROJECT_NUMBER" \
  --network-resource "$(jq -r '.baseline_reset.network_resource' "$CG_RUN_DIR/reference-target.json")" \
  --subnetwork-resource "$(jq -r '.baseline_reset.subnetwork_resource' "$CG_RUN_DIR/reference-target.json")" \
  --verifier-service-account "$(terraform -chdir=infra/foundation output -json service_account_emails | jq -r '.verifier')" \
  --restricted-exporter-service-account "$(terraform -chdir=infra/foundation output -json service_account_emails | jq -r '.restricted_exporter')" \
  --acceptance-identity "$CG_ACCEPTANCE_IDENTITY" \
  --confirm RUN_CONTROLGRAPH_CORE_ACCEPTANCE
```

The reviewed run specification pins the source commit, five image digests, target and revisions,
Terraform plan digest, policy artifacts, deterministic seed and clock, maximum duration, maximum
cost, and the eight fixed cases. Do not hand-edit a generated command, signed record, result, or
manifest.

For audit and recovery, these are the exact operator entry points exercised by the runner:

| Step | Pinned entry point |
|---|---|
| Reset to 100/0 | `controlgraph-reference-target-reset` with `RESET_REFERENCE_TARGET_BASELINE` |
| Capture stable | `controlgraph-canary capture-stable-snapshot --project-number "$CG_PROJECT_NUMBER" --request-id demo-capture-001` |
| Create root | `controlgraph-canary create-rollout-root` with its generated canonical command |
| Apply 90/10 | `controlgraph-canary apply-canary` with the generated root, epoch, request, and idempotency bindings |
| Read receipt | `controlgraph-canary read-execution-receipt` with the exact dispatch identity |
| Read target | `controlgraph-canary read-target-traffic --project-number "$CG_PROJECT_NUMBER" --request-id demo-read-001` |
| Evaluate health | `controlgraph-canary evaluate-health` with the generated canonical health command |
| Promote healthy candidate | `controlgraph-canary promote-candidate` with the signed healthy-chain locator |
| Hold delayed work | `controlgraph-canary execution-queue hold --project-id "$CG_PROJECT_ID" --confirm HOLD_EXECUTION_QUEUE` |
| Revoke epoch | `controlgraph-canary revoke-epoch` with `--confirm REVOKE` and the generated root and epoch bindings |
| Release delayed work | `controlgraph-canary execution-queue release --project-id "$CG_PROJECT_ID" --confirm RELEASE_EXECUTION_QUEUE` |
| Recover revoked root | `controlgraph-canary recover-captured-stable` with the generated revocation proof and recovery command |
| Release service claim | `controlgraph-canary release-service-claim` with the generated terminal evidence command |

Generated commands preserve all root, receipt, health-chain, prestate, revocation-proof, and
provider-precondition bindings; these are not operator-chosen values. The CLI contract and
argument definitions are in
[`backend/src/controlgraph_canary/cli.py`](../backend/src/controlgraph_canary/cli.py).

An unhealthy terminal health decision dispatches the separate stable-only recovery path
automatically. `recover-captured-stable` is reserved for an explicitly confirmed revoked-root
recovery; it does not turn stale authority back on.

## Review and verify

Open the console URI from `operator-console.json` while authenticated as the configured operator.
The console reads `/v1/operator/timeline` through the API; it does not call Firestore or a cloud
control plane. Check ordered root and epoch bindings, signature metadata, terminal classification,
and the `ADVISORY_ONLY` model-assistance event. Advisor text is explanatory only.

Independently verify the final traffic state:

```bash
"${CG_CLI[@]}" read-target-traffic \
  --project-number "$CG_PROJECT_NUMBER" \
  --request-id demo-final-read-001 \
  > "$CG_RUN_DIR/final-traffic.json"
jq -e '.schema_version == "controlgraph.target-traffic-read-result/v1"' \
  "$CG_RUN_DIR/final-traffic.json"
```

The verifier's `controlgraph.probe-attestation/v1`, its signed
`controlgraph.independent-verification-evidence/v1`, the signed timeline source evidence, and the
configuration readback must agree. The evidence-to-claim map is in [the demo](demo.md).

## Prepare, rehearse, and finalize the bundle

After the owner has published an annotated source tag for `$CG_SOURCE_SHA`, fetch it and verify its
peeled commit before preparing the bundle. Build the external `PREPARED` specification only from
the real artifacts and tracked source files produced above. Do not create a rehearsal file or a
placeholder for one; a prepared specification omits both `PREPARED_BUNDLE` and
`CLEAN_ROOM_REHEARSAL`.

```bash
CG_SOURCE_TAG="${CG_SOURCE_TAG:?set CG_SOURCE_TAG to the owner-published annotated tag}"
git fetch --tags origin
test "$(git cat-file -t "refs/tags/$CG_SOURCE_TAG")" = "tag"
test "$(git rev-parse "refs/tags/$CG_SOURCE_TAG^{commit}")" = "$CG_SOURCE_SHA"
set +e
uv run --project backend --frozen python scripts/frozen_bundle.py \
  --repo . \
  --spec "$CG_RUN_DIR/frozen-bundle-prepared-spec.json" \
  --artifact-root "$CG_RUN_DIR/artifacts" \
  --output "$CG_RUN_DIR/artifacts/prepared-bundle.json"
CG_PREPARED_STATUS=$?
set -e
test "$CG_PREPARED_STATUS" -eq 1
jq -e '.stage == "PREPARED" and .status == "PENDING" and
  .pending == ["CLEAN_ROOM_REHEARSAL"]' \
  "$CG_RUN_DIR/artifacts/prepared-bundle.json"
```

Transfer the source tag, prepared bundle, specification, and checksum-bound artifact directory to
a fresh environment. There, rerun the prepared verification, deploy only its frozen image and
Terraform inputs, execute the same acceptance flow, validate every evidence link, and record the
actual `controlgraph.clean-room-rehearsal/v1` sign-off. That record must cite the SHA-256 of
`prepared-bundle.json`; it is created only after those steps pass.

Create the external `FINAL` specification by preserving every prepared source, artifact, and claim
binding and adding the real `PREPARED_BUNDLE` and `CLEAN_ROOM_REHEARSAL` artifacts with their
digests. Finalization succeeds only when the prepared content is unchanged and the sign-off binds
that prepared bundle:

```bash
uv run --project backend --frozen python scripts/frozen_bundle.py \
  --repo . \
  --spec "$CG_RUN_DIR/frozen-bundle-final-spec.json" \
  --artifact-root "$CG_RUN_DIR/artifacts" \
  --output "$CG_RUN_DIR/frozen-bundle.json"
jq -e '.stage == "FINAL" and .status == "READY" and .pending == []' \
  "$CG_RUN_DIR/frozen-bundle.json"
```

## Cleanup

Cleanup means restoring the disposable target and releasing application state, not destroying
retained infrastructure:

1. Release the execution queue if a revocation case left it paused.
2. Run `controlgraph-reference-target-reset` with the current etag and the exact
   `baseline_reset` values from `reference-target.json`.
3. Read target traffic and require stable 100, candidate 0, approved concurrency, and the expected
   stable probe marker.
4. Release the terminal service claim with its generated canonical command.
5. Preserve the redacted evidence bundle and record the retention decision for the external run
   directory.

Do not run Terraform destroy as routine cleanup. Infrastructure and signing-key retirement need
separate authorization and the ordered procedure in
[`infra/README.md`](../infra/README.md#separately-authorized-teardown).
