# Frozen release rehearsal

This companion to the [reproducible canary quickstart](quickstart.md) turns completed,
source-bound acceptance outputs into a `PREPARED` bundle, repeats deployment and acceptance
from a clean checkout, verifies every evidence link, and creates the `FINAL` bundle. Continue
in the same shell after the quickstart's acceptance and artifact-producing runs. Never create
placeholder evidence or hand-edit generated records.

## Prepare the frozen bundle

The frozen-bundle specification has four top-level fields: `schema_version`, `stage`, `source`,
and the `artifacts` and `claims` arrays. An artifact entry contains `id`, `kind`, `location`,
`path`, `sha256`, `status`, and `schema_version` when the artifact is a typed JSON record. A claim
entry contains `id`, `category`, the exact `statement` and its SHA-256, `source_ids`,
`evidence_ids`, and `status`. Paths with location `REPOSITORY` are relative to the checkout; paths
with location `BUNDLE` are relative to `$CG_RUN_DIR/artifacts`.

Use only real completed outputs. In addition to the core manifest and Terraform plan created
above, place the successful fault, abuse, measurement, and supply-chain outputs at these stable
bundle-relative paths:

```text
fault-acceptance-manifest.json
security-abuse-manifest.json
measurement-summary.json
release/manifest.json
release/VERIFIED.json
```

Generate the schema index from the exact tracked source. Then select the completed `CI` workflow
run triggered by the exact source commit's push to `main`, inspect that run with `gh run view`,
and derive the required-check record from its four successful jobs. Local checks do not replace
this hosted evidence:

```bash
git grep -h -o -E 'controlgraph\.[a-z0-9.-]+/v[0-9]+' \
  -- backend/src web/src contract-fixtures \
  | sort -u \
  | jq -R 'capture("^(?<id>.+)/(?<version>v[0-9]+)$")' \
  | jq -s --arg source "$CG_SOURCE_SHA" \
      '{schema_version:"controlgraph.contract-schema-index/v1",
        source_commit:$source,schemas:.}' \
  > "$CG_RUN_DIR/artifacts/contract-schema-index.json"

CG_CI_RUN_ID="$(gh run list --workflow ci.yml --branch main --event push \
  --commit "$CG_SOURCE_SHA" --limit 20 \
  --json databaseId,headSha,event,status,conclusion \
  --jq 'map(select(.event == "push" and .status == "completed" and
    .conclusion == "success")) | .[0].databaseId // empty')"
test -n "$CG_CI_RUN_ID"
gh run view "$CG_CI_RUN_ID" \
  --json databaseId,url,headSha,event,status,conclusion,jobs \
  > "$CG_RUN_DIR/ci-run.json"
jq -e --arg source "$CG_SOURCE_SHA" '
  .databaseId > 0 and .headSha == $source and .event == "push" and
  .status == "completed" and .conclusion == "success" and
  .url == ("https://github.com/OCHOLA-EDDYPHIL/controlgraph/actions/runs/" +
    (.databaseId | tostring)) and
  ([.jobs[] | select(
      .name as $name |
      (["Python","Web","Terraform","Security"] | index($name)) != null and
      .status == "completed" and .conclusion == "success") | .name] | sort | unique) ==
    (["Python","Web","Terraform","Security"] | sort)' \
  "$CG_RUN_DIR/ci-run.json"
jq --arg source "$CG_SOURCE_SHA" '
  {schema_version:"controlgraph.required-check-results/v1",
    source_commit:$source,status:"PASSED",workflow_run_id:.databaseId,
    run_url:.url,head_sha:.headSha,event:.event,
    checks:(reduce .jobs[] as $job ({};
      if (["Python","Web","Terraform","Security"] | index($job.name)) != null
      then . + {($job.name | ascii_upcase):
        (if $job.conclusion == "success" then "PASSED" else "FAILED" end)}
      else . end))}' "$CG_RUN_DIR/ci-run.json" \
  > "$CG_RUN_DIR/artifacts/required-check-results.json"
```

Create the claim ledger from exact, bounded statements. The following entries cover the claims in
this quickstart and demo; add a separate entry before preparation for every additional published
claim. The helper calculates each statement digest rather than embedding a sample digest:

```bash
cg_claim() {
  local claim_id="$1" category="$2" statement="$3" source_csv="$4" evidence_csv="$5"
  local statement_sha source_ids evidence_ids
  statement_sha="$(printf '%s' "$statement" | sha256sum | awk '{print $1}')"
  source_ids="$(jq -cn --arg value "$source_csv" '$value | split(",")')"
  evidence_ids="$(jq -cn --arg value "$evidence_csv" '$value | split(",")')"
  jq -cn \
    --arg id "$claim_id" --arg category "$category" --arg statement "$statement" \
    --arg statement_sha256 "$statement_sha" --argjson source_ids "$source_ids" \
    --argjson evidence_ids "$evidence_ids" \
    '{id:$id,category:$category,statement:$statement,
      statement_sha256:$statement_sha256,source_ids:$source_ids,
      evidence_ids:$evidence_ids,status:"SUPPORTED"}'
}

while IFS='|' read -r claim_id category statement source_ids evidence_ids; do
  cg_claim "$claim_id" "$category" "$statement" "$source_ids" "$evidence_ids"
done <<'EOF' | jq -s '.' > "$CG_RUN_DIR/frozen-claims.json"
architecture-boundaries|architecture|The isolated reference deployment separates authority, execution, recovery, verification, presentation, and advisory boundaries.|architecture,architecture-diagram|architecture-diagram,core-acceptance
executor-time-fencing|security|The recorded reference run enforces exact epoch authority at the executor mutation boundary.|architecture|security-abuse,core-acceptance
seeded-faults|determinism|The recorded fault run covers the seven allowlisted scenarios with deterministic seeds.|architecture|fault-acceptance
bounded-latency|latency|Latency statements apply only to the recorded isolated acceptance run.|quickstart|performance
bounded-reliability|reliability|Reliability statements apply only to the recorded isolated acceptance cases.|architecture|core-acceptance,performance
bounded-cost|cost|Cost statements apply only to the recorded bounded acceptance run.|quickstart|performance
native-comparison|comparison|The comparison separates inherited Google Cloud controls from ControlGraph behavior.|comparison|comparison
evidence-backed-demo|demo|The demo is supported only by its recorded configuration, probe, timeline, and acceptance evidence.|quickstart,demo-asset|demo-asset,core-acceptance
EOF
```

After reviewing the claim ledger, least privilege, current trusted key versions, redaction,
secret-scan results, disclosures, and residual risks, record that review. Add every additional
observed residual risk to the array before continuing:

```bash
jq -n --arg source "$CG_SOURCE_SHA" \
  --slurpfile claims "$CG_RUN_DIR/frozen-claims.json" \
  '{schema_version:"controlgraph.release-review/v1",source_commit:$source,status:"PASSED",
    checks:{EMBEDDED_SECRETS_ABSENT:"PASSED",EVIDENCE_REDACTED:"PASSED",
      LEAST_PRIVILEGE:"PASSED",RESIDUAL_RISKS_DOCUMENTED:"PASSED",
      TRUSTED_KEY_VERSIONS_CURRENT:"PASSED",UNSUPPORTED_CLAIMS_ABSENT:"PASSED"},
    claim_ids:($claims[0] | map(.id) | sort),
    residual_risks:["ISOLATED_ACCEPTANCE_ONLY"]}' \
  > "$CG_RUN_DIR/artifacts/release-review.json"
```

Build the artifact inventory by hashing the files that actually exist. The architecture document
contains the rendered Mermaid trust-boundary diagram, the threat model is the limitations source,
and `SECURITY.md` is the disclosure source:

```bash
cg_artifact() {
  local artifact_id="$1" kind="$2" location="$3" relative="$4" schema="${5:-}"
  local root absolute digest
  if test "$location" = REPOSITORY; then root=.; else root="$CG_RUN_DIR/artifacts"; fi
  absolute="$root/$relative"
  test -f "$absolute"
  digest="$(sha256sum "$absolute" | awk '{print $1}')"
  if test -n "$schema"; then
    test "$(jq -r '.schema_version // empty' "$absolute")" = "$schema"
    jq -cn --arg id "$artifact_id" --arg kind "$kind" --arg location "$location" \
      --arg path "$relative" --arg sha256 "$digest" --arg schema_version "$schema" \
      '{id:$id,kind:$kind,location:$location,path:$path,sha256:$sha256,
        schema_version:$schema_version,status:"VERIFIED"}'
  else
    jq -cn --arg id "$artifact_id" --arg kind "$kind" --arg location "$location" \
      --arg path "$relative" --arg sha256 "$digest" \
      '{id:$id,kind:$kind,location:$location,path:$path,sha256:$sha256,status:"VERIFIED"}'
  fi
}

while IFS='|' read -r artifact_id kind location relative schema; do
  cg_artifact "$artifact_id" "$kind" "$location" "$relative" "$schema"
done <<'EOF' | jq -s '.' > "$CG_RUN_DIR/frozen-artifacts.json"
contracts|CONTRACT_SCHEMA_INDEX|BUNDLE|contract-schema-index.json|controlgraph.contract-schema-index/v1
terraform-plan|TERRAFORM_PLAN|BUNDLE|runtime-candidate-plan.json|
release-evidence|RELEASE_EVIDENCE_MANIFEST|BUNDLE|release/manifest.json|controlgraph.release-evidence/v1
release-verification|RELEASE_EVIDENCE_VERIFICATION|BUNDLE|release/VERIFIED.json|controlgraph.release-evidence-verification/v1
core-acceptance|CORE_ACCEPTANCE_MANIFEST|BUNDLE|core-acceptance-manifest.json|controlgraph.core-acceptance-manifest/v1
fault-acceptance|FAULT_ACCEPTANCE_MANIFEST|BUNDLE|fault-acceptance-manifest.json|controlgraph.fault-acceptance-manifest/v1
security-abuse|SECURITY_ABUSE_MANIFEST|BUNDLE|security-abuse-manifest.json|controlgraph.security-abuse-manifest/v1
performance|PERFORMANCE_SUMMARY|BUNDLE|measurement-summary.json|controlgraph.measurement-summary/v1
checks|REQUIRED_CHECK_RESULTS|BUNDLE|required-check-results.json|controlgraph.required-check-results/v1
release-review|RELEASE_REVIEW|BUNDLE|release-review.json|controlgraph.release-review/v1
architecture|ARCHITECTURE_DOCUMENT|REPOSITORY|docs/architecture.md|
architecture-diagram|ARCHITECTURE_DIAGRAM|REPOSITORY|docs/architecture.md|
quickstart|QUICKSTART_DOCUMENT|REPOSITORY|docs/quickstart.md|
demo-asset|DEMO_ASSET|REPOSITORY|docs/demo.md|
comparison|NATIVE_COMPARISON_DOCUMENT|REPOSITORY|docs/native-cloud-comparison.md|
limitations|LIMITATIONS_DOCUMENT|REPOSITORY|docs/threat-model.md|
disclosures|DISCLOSURE_DOCUMENT|REPOSITORY|SECURITY.md|
EOF
```

After the owner has published an annotated source tag for `$CG_SOURCE_SHA`, verify both its local
object and the exact tag and peeled commit advertised by `origin`. Then construct the `PREPARED`
specification directly from the two generated arrays:

```bash
CG_SOURCE_TAG="${CG_SOURCE_TAG:?set CG_SOURCE_TAG to the owner-published annotated tag}"
git check-ref-format "refs/tags/$CG_SOURCE_TAG"
git fetch --force origin "refs/tags/$CG_SOURCE_TAG:refs/tags/$CG_SOURCE_TAG"
test "$(git cat-file -t "refs/tags/$CG_SOURCE_TAG")" = tag
CG_SOURCE_TAG_OBJECT="$(git rev-parse "refs/tags/$CG_SOURCE_TAG")"
test "$(git rev-parse "refs/tags/$CG_SOURCE_TAG^{commit}")" = "$CG_SOURCE_SHA"
test "$(git ls-remote --tags origin "refs/tags/$CG_SOURCE_TAG" | awk '{print $1}')" \
  = "$CG_SOURCE_TAG_OBJECT"
test "$(git ls-remote --tags origin "refs/tags/$CG_SOURCE_TAG^{}" | awk '{print $1}')" \
  = "$CG_SOURCE_SHA"

jq -n --arg revision "$CG_SOURCE_SHA" --arg tag "$CG_SOURCE_TAG" \
  --arg tag_object "$CG_SOURCE_TAG_OBJECT" \
  --slurpfile artifacts "$CG_RUN_DIR/frozen-artifacts.json" \
  --slurpfile claims "$CG_RUN_DIR/frozen-claims.json" \
  '{schema_version:"controlgraph.frozen-bundle-spec/v1",stage:"PREPARED",
    source:{repository:"https://github.com/OCHOLA-EDDYPHIL/controlgraph",
      revision:$revision,tag:$tag,tag_status:"VERIFIED",tag_object_sha:$tag_object},
    artifacts:$artifacts[0],claims:$claims[0]}' \
  > "$CG_RUN_DIR/frozen-bundle-prepared-spec.json"

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

## Run the clean-room rehearsal

Use a fresh clone or an equivalently isolated disposable worktree. This local-clone form preserves
the separately reviewed, ignored Terraform variables without putting them in the bundle. It checks
out the remote annotated tag, reruns the source gates, and byte-compares a second prepared-bundle
verification with the original:

```bash
CG_SOURCE_DIR="$(pwd -P)"
CG_ORIGINAL_RUN_DIR="$CG_RUN_DIR"
CG_REHEARSAL_ROOT="$(mktemp -d)"
CG_CLEAN_SOURCE="$CG_REHEARSAL_ROOT/source"
CG_CLEAN_FROZEN_ARTIFACTS="$CG_REHEARSAL_ROOT/frozen-artifacts"
CG_CLEAN_RUN_ARTIFACTS="$CG_REHEARSAL_ROOT/run-artifacts"

git clone --no-checkout https://github.com/OCHOLA-EDDYPHIL/controlgraph "$CG_CLEAN_SOURCE"
git -C "$CG_CLEAN_SOURCE" fetch --force origin \
  "refs/tags/$CG_SOURCE_TAG:refs/tags/$CG_SOURCE_TAG"
git -C "$CG_CLEAN_SOURCE" checkout --detach "$CG_SOURCE_SHA"
test "$(git -C "$CG_CLEAN_SOURCE" cat-file -t "refs/tags/$CG_SOURCE_TAG")" = tag
test "$(git -C "$CG_CLEAN_SOURCE" rev-parse "refs/tags/$CG_SOURCE_TAG^{commit}")" \
  = "$CG_SOURCE_SHA"
test -z "$(git -C "$CG_CLEAN_SOURCE" status --porcelain=v1)"

cp -a "$CG_ORIGINAL_RUN_DIR/artifacts" "$CG_CLEAN_FROZEN_ARTIFACTS"
install -m 600 "$CG_ORIGINAL_RUN_DIR/frozen-bundle-prepared-spec.json" \
  "$CG_REHEARSAL_ROOT/frozen-bundle-prepared-spec.json"
mkdir -p "$CG_CLEAN_RUN_ARTIFACTS/inputs"

(cd "$CG_CLEAN_SOURCE/backend" && uv sync --frozen --all-extras --dev)
(cd "$CG_CLEAN_SOURCE/backend" && uv run ruff check . && uv run mypy src && uv run pytest)
(cd "$CG_CLEAN_SOURCE/web" && npm ci && npm run typecheck && npm run test:ci && npm run build)
terraform -chdir="$CG_CLEAN_SOURCE/infra" fmt -check -recursive
uv run --project "$CG_CLEAN_SOURCE/backend" --frozen python \
  "$CG_CLEAN_SOURCE/scripts/check_clean_room.py"

set +e
uv run --project "$CG_CLEAN_SOURCE/backend" --frozen python \
  "$CG_CLEAN_SOURCE/scripts/frozen_bundle.py" \
  --repo "$CG_CLEAN_SOURCE" \
  --spec "$CG_REHEARSAL_ROOT/frozen-bundle-prepared-spec.json" \
  --artifact-root "$CG_CLEAN_FROZEN_ARTIFACTS" \
  --output "$CG_REHEARSAL_ROOT/prepared-bundle.reverified.json"
CG_REVERIFY_STATUS=$?
set -e
test "$CG_REVERIFY_STATUS" -eq 1
cmp "$CG_CLEAN_FROZEN_ARTIFACTS/prepared-bundle.json" \
  "$CG_REHEARSAL_ROOT/prepared-bundle.reverified.json"
```

Copy only the reviewed ignored Terraform inputs into the clean checkout, initialize all three
remote states, and save fresh plans. Inspect the three text plans before applying; stop if any
plan names another project or contains a delete action:

```bash
install -m 600 "$CG_SOURCE_DIR/infra/bootstrap/terraform.tfvars" \
  "$CG_CLEAN_SOURCE/infra/bootstrap/terraform.tfvars"
install -m 600 "$CG_SOURCE_DIR/infra/bootstrap/backend.tf" \
  "$CG_CLEAN_SOURCE/infra/bootstrap/backend.tf"
install -m 600 "$CG_SOURCE_DIR/infra/foundation/terraform.tfvars" \
  "$CG_CLEAN_SOURCE/infra/foundation/terraform.tfvars"
install -m 600 "$CG_SOURCE_DIR/infra/runtime/terraform.tfvars" \
  "$CG_CLEAN_SOURCE/infra/runtime/terraform.tfvars"

terraform -chdir="$CG_CLEAN_SOURCE/infra/bootstrap" init -lockfile=readonly -reconfigure \
  -backend-config="bucket=$CG_STATE_BUCKET" -backend-config="prefix=bootstrap"
terraform -chdir="$CG_CLEAN_SOURCE/infra/foundation" init -lockfile=readonly -reconfigure \
  -backend-config="bucket=$CG_STATE_BUCKET" -backend-config="prefix=foundation"
terraform -chdir="$CG_CLEAN_SOURCE/infra/runtime" init -lockfile=readonly -reconfigure \
  -backend-config="bucket=$CG_STATE_BUCKET" -backend-config="prefix=runtime"

mkdir -p "$CG_CLEAN_RUN_ARTIFACTS/plans"
for stack in bootstrap foundation runtime; do
  terraform -chdir="$CG_CLEAN_SOURCE/infra/$stack" validate
  terraform -chdir="$CG_CLEAN_SOURCE/infra/$stack" plan \
    -out="$CG_CLEAN_RUN_ARTIFACTS/plans/$stack.tfplan"
  terraform -chdir="$CG_CLEAN_SOURCE/infra/$stack" show -json \
    "$CG_CLEAN_RUN_ARTIFACTS/plans/$stack.tfplan" \
    > "$CG_CLEAN_RUN_ARTIFACTS/plans/$stack.json"
  jq -e 'all(.resource_changes[]?; (.change.actions | index("delete") | not))' \
    "$CG_CLEAN_RUN_ARTIFACTS/plans/$stack.json"
  terraform -chdir="$CG_CLEAN_SOURCE/infra/$stack" show -no-color \
    "$CG_CLEAN_RUN_ARTIFACTS/plans/$stack.tfplan" \
    > "$CG_CLEAN_RUN_ARTIFACTS/plans/$stack.txt"
done
```

After reviewing those three text plans and confirming the authorized isolated project, apply the
saved plans in order:

```bash
terraform -chdir="$CG_CLEAN_SOURCE/infra/bootstrap" apply \
  "$CG_CLEAN_RUN_ARTIFACTS/plans/bootstrap.tfplan"
terraform -chdir="$CG_CLEAN_SOURCE/infra/foundation" apply \
  "$CG_CLEAN_RUN_ARTIFACTS/plans/foundation.tfplan"
terraform -chdir="$CG_CLEAN_SOURCE/infra/runtime" apply \
  "$CG_CLEAN_RUN_ARTIFACTS/plans/runtime.tfplan"
```

Regenerate the acceptance template with the fresh runtime plan and test clock while preserving
the prepared source, target, image, policy, and seed bindings. The hosted executor verifies the
deployed service images before running the eight cases:

```bash
CG_PREPARED_CORE="$CG_CLEAN_FROZEN_ARTIFACTS/core-acceptance-manifest.json"
install -m 600 "$CG_CLEAN_FROZEN_ARTIFACTS/inputs/rollout-health-policy.json" \
  "$CG_CLEAN_RUN_ARTIFACTS/inputs/rollout-health-policy.json"

cg_prepared_image() {
  jq -er --arg component "$1" \
    '.inputs.images[] | select(.component == $component) | .reference' \
    "$CG_PREPARED_CORE"
}

uv run --project "$CG_CLEAN_SOURCE/backend" --frozen python \
  "$CG_CLEAN_SOURCE/scripts/core_acceptance.py" generate-spec \
  --artifact-root "$CG_CLEAN_RUN_ARTIFACTS" \
  --output "$CG_REHEARSAL_ROOT/core-acceptance-spec.json" \
  --project-id "$(jq -er '.inputs.target.project_id' "$CG_PREPARED_CORE")" \
  --source-commit "$CG_SOURCE_SHA" \
  --stable-revision "$(jq -er '.inputs.target.stable_revision' "$CG_PREPARED_CORE")" \
  --candidate-revision "$(jq -er '.inputs.target.candidate_revision' "$CG_PREPARED_CORE")" \
  --controller-image "$(cg_prepared_image controller)" \
  --advisor-image "$(cg_prepared_image advisor)" \
  --console-image "$(cg_prepared_image console)" \
  --reference-stable-image "$(cg_prepared_image reference-stable)" \
  --reference-candidate-image "$(cg_prepared_image reference-candidate)" \
  --terraform-plan plans/runtime.json \
  --policy-schema-version "$(jq -er '.schema_version' \
    "$CG_CLEAN_RUN_ARTIFACTS/inputs/rollout-health-policy.json")" \
  --policy-artifact inputs/rollout-health-policy.json \
  --clock-start "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --random-seed "$(jq -er '.inputs.random_seed' "$CG_PREPARED_CORE")"

CG_CLEAN_PROJECT_NUMBER="$(terraform -chdir="$CG_CLEAN_SOURCE/infra/foundation" \
  output -raw project_number)"
CG_CLEAN_ACCEPTANCE_IDENTITY="$(gcloud config get-value account)"
CONTROLGRAPH_CORE_ACCEPTANCE_CONFIRM=RUN_CONTROLGRAPH_CORE_ACCEPTANCE \
uv run --project "$CG_CLEAN_SOURCE/backend" --frozen python \
  "$CG_CLEAN_SOURCE/scripts/core_acceptance.py" execute \
  --spec "$CG_REHEARSAL_ROOT/core-acceptance-spec.json" \
  --artifact-root "$CG_CLEAN_RUN_ARTIFACTS" \
  --output-spec "$CG_REHEARSAL_ROOT/executed-spec.json" \
  --output "$CG_CLEAN_RUN_ARTIFACTS/core-acceptance-manifest.json" \
  --project-number "$CG_CLEAN_PROJECT_NUMBER" \
  --network-resource "$(terraform -chdir="$CG_CLEAN_SOURCE/infra/runtime" \
    output -json reference_target | jq -er '.baseline_reset.network_resource')" \
  --subnetwork-resource "$(terraform -chdir="$CG_CLEAN_SOURCE/infra/runtime" \
    output -json reference_target | jq -er '.baseline_reset.subnetwork_resource')" \
  --verifier-service-account "$(terraform -chdir="$CG_CLEAN_SOURCE/infra/foundation" \
    output -json service_account_emails | jq -er '.verifier')" \
  --restricted-exporter-service-account "$(terraform -chdir="$CG_CLEAN_SOURCE/infra/foundation" \
    output -json service_account_emails | jq -er '.restricted_exporter')" \
  --acceptance-identity "$CG_CLEAN_ACCEPTANCE_IDENTITY" \
  --confirm RUN_CONTROLGRAPH_CORE_ACCEPTANCE
```

Rebind every case result from disk, compare the reconstructed manifest byte-for-byte, compare all
immutable inputs with the prepared run, and reverify the release evidence:

```bash
uv run --project "$CG_CLEAN_SOURCE/backend" --frozen python \
  "$CG_CLEAN_SOURCE/scripts/core_acceptance.py" bind \
  --spec "$CG_REHEARSAL_ROOT/executed-spec.json" \
  --artifact-root "$CG_CLEAN_RUN_ARTIFACTS" \
  --output "$CG_REHEARSAL_ROOT/core-acceptance-manifest.rebound.json"
cmp "$CG_CLEAN_RUN_ARTIFACTS/core-acceptance-manifest.json" \
  "$CG_REHEARSAL_ROOT/core-acceptance-manifest.rebound.json"
jq -e '.status == "PASSED" and .evidence_binding_complete == true and
  (.cases | length == 8) and all(.cases[]; .status == "PASSED")' \
  "$CG_CLEAN_RUN_ARTIFACTS/core-acceptance-manifest.json"
jq -S '.inputs | {source_commit,target,images,policies,random_seed}' \
  "$CG_PREPARED_CORE" > "$CG_REHEARSAL_ROOT/prepared-inputs.json"
jq -S '.inputs | {source_commit,target,images,policies,random_seed}' \
  "$CG_CLEAN_RUN_ARTIFACTS/core-acceptance-manifest.json" \
  > "$CG_REHEARSAL_ROOT/rehearsed-inputs.json"
cmp "$CG_REHEARSAL_ROOT/prepared-inputs.json" "$CG_REHEARSAL_ROOT/rehearsed-inputs.json"
test "$(jq -er '.run_id' "$CG_CLEAN_RUN_ARTIFACTS/core-acceptance-manifest.json")" \
  != "$(jq -er '.run_id' "$CG_PREPARED_CORE")"
CG_COSIGN="${CG_COSIGN:?set CG_COSIGN to the pinned executable Cosign path}"
test -x "$CG_COSIGN"
uv run --project "$CG_CLEAN_SOURCE/backend" --frozen python \
  "$CG_CLEAN_SOURCE/scripts/release_evidence.py" verify \
  --repo "$CG_CLEAN_SOURCE" \
  --output "$CG_CLEAN_FROZEN_ARTIFACTS/release" \
  --source-sha "$CG_SOURCE_SHA" \
  --cosign "$CG_COSIGN"
```

Only after those commands pass, create an evidence-link validation record from the actual fresh
runtime plan, acceptance manifest, prepared-bundle digest, and complete sorted claim list. Copy
those exact outputs under the frozen artifact root, then write the sign-off. Use a non-secret,
publishable reviewer identifier rather than an email address:

```bash
CG_REVIEWER_ID="${CG_REVIEWER_ID:?set a publishable reviewer identifier}"
CG_PREPARED_SHA="$(sha256sum "$CG_CLEAN_FROZEN_ARTIFACTS/prepared-bundle.json" | awk '{print $1}')"
CG_REHEARSED_SHA="$(sha256sum "$CG_CLEAN_RUN_ARTIFACTS/core-acceptance-manifest.json" | awk '{print $1}')"
CG_RUNTIME_PLAN_SHA="$(sha256sum "$CG_CLEAN_RUN_ARTIFACTS/plans/runtime.json" | awk '{print $1}')"
test "$CG_RUNTIME_PLAN_SHA" \
  != "$(sha256sum "$CG_CLEAN_FROZEN_ARTIFACTS/runtime-candidate-plan.json" | awk '{print $1}')"
test "$(jq -er '.inputs.terraform_plan.sha256' \
  "$CG_CLEAN_RUN_ARTIFACTS/core-acceptance-manifest.json")" = "$CG_RUNTIME_PLAN_SHA"
CG_VALIDATED_CLAIMS="$(jq -c '.claims | map(.id) | sort' \
  "$CG_REHEARSAL_ROOT/frozen-bundle-prepared-spec.json")"

jq -n --arg source "$CG_SOURCE_SHA" --arg prepared "$CG_PREPARED_SHA" \
  --arg runtime_plan "$CG_RUNTIME_PLAN_SHA" --arg rehearsed "$CG_REHEARSED_SHA" \
  --argjson claim_ids "$CG_VALIDATED_CLAIMS" \
  '{schema_version:"controlgraph.evidence-link-validation/v1",source_commit:$source,
    prepared_bundle_sha256:$prepared,terraform_plan_sha256:$runtime_plan,
    core_acceptance_manifest_sha256:$rehearsed,validated_claim_ids:$claim_ids,
    status:"PASSED"}' \
  > "$CG_REHEARSAL_ROOT/evidence-links.json"
CG_EVIDENCE_LINKS_SHA="$(sha256sum "$CG_REHEARSAL_ROOT/evidence-links.json" | awk '{print $1}')"

jq -n --arg source "$CG_SOURCE_SHA" --arg tag "$CG_SOURCE_TAG" \
  --arg prepared "$CG_PREPARED_SHA" --arg reviewer "$CG_REVIEWER_ID" \
  --arg recorded_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg rehearsed "$CG_REHEARSED_SHA" --arg runtime_plan "$CG_RUNTIME_PLAN_SHA" \
  --arg evidence_links "$CG_EVIDENCE_LINKS_SHA" \
  '{schema_version:"controlgraph.clean-room-rehearsal/v1",source_commit:$source,
    source_tag:$tag,prepared_bundle_sha256:$prepared,status:"PASSED",
    steps:{DEPLOY_FROZEN_ARTIFACTS:"PASSED",FINAL_SIGN_OFF:"PASSED",
      RUN_ACCEPTANCE:"PASSED",VALIDATE_EVIDENCE_LINKS:"PASSED",VERIFY_CHECKSUMS:"PASSED"},
    outputs:{
      terraform_plan:{artifact_id:"clean-room-terraform-plan",
        path:"clean-room/terraform-plan.json",sha256:$runtime_plan},
      core_acceptance_manifest:{artifact_id:"clean-room-core-acceptance",
        path:"clean-room/core-acceptance-manifest.json",sha256:$rehearsed},
      evidence_link_validation:{artifact_id:"clean-room-evidence-links",
        path:"clean-room/evidence-links.json",sha256:$evidence_links}},
    sign_off:{reviewer_id:$reviewer,recorded_at:$recorded_at}}' \
  > "$CG_REHEARSAL_ROOT/clean-room-rehearsal.json"

mkdir -p "$CG_ORIGINAL_RUN_DIR/artifacts/clean-room"
install -m 600 "$CG_CLEAN_RUN_ARTIFACTS/plans/runtime.json" \
  "$CG_ORIGINAL_RUN_DIR/artifacts/clean-room/terraform-plan.json"
install -m 600 "$CG_CLEAN_RUN_ARTIFACTS/core-acceptance-manifest.json" \
  "$CG_ORIGINAL_RUN_DIR/artifacts/clean-room/core-acceptance-manifest.json"
install -m 600 "$CG_REHEARSAL_ROOT/evidence-links.json" \
  "$CG_ORIGINAL_RUN_DIR/artifacts/clean-room/evidence-links.json"
install -m 600 "$CG_REHEARSAL_ROOT/clean-room-rehearsal.json" \
  "$CG_ORIGINAL_RUN_DIR/artifacts/clean-room-rehearsal.json"
```

## Finalize the bundle

Create the `FINAL` specification by preserving the prepared source, artifact, and claim arrays and
adding only the real prepared bundle and clean-room record with their calculated digests:

```bash
CG_PREPARED_SHA="$(sha256sum "$CG_RUN_DIR/artifacts/prepared-bundle.json" | awk '{print $1}')"
CG_CLEAN_ROOM_SHA="$(sha256sum "$CG_RUN_DIR/artifacts/clean-room-rehearsal.json" | awk '{print $1}')"
jq --arg prepared_sha "$CG_PREPARED_SHA" --arg clean_room_sha "$CG_CLEAN_ROOM_SHA" '
  .stage = "FINAL"
  | .artifacts += [
      {id:"prepared-bundle",kind:"PREPARED_BUNDLE",location:"BUNDLE",
       path:"prepared-bundle.json",sha256:$prepared_sha,
       schema_version:"controlgraph.frozen-bundle/v1",status:"VERIFIED"},
      {id:"clean-room",kind:"CLEAN_ROOM_REHEARSAL",location:"BUNDLE",
       path:"clean-room-rehearsal.json",sha256:$clean_room_sha,
       schema_version:"controlgraph.clean-room-rehearsal/v1",status:"VERIFIED"}
    ]' "$CG_RUN_DIR/frozen-bundle-prepared-spec.json" \
  > "$CG_RUN_DIR/frozen-bundle-final-spec.json"

uv run --project backend --frozen python scripts/frozen_bundle.py \
  --repo . \
  --spec "$CG_RUN_DIR/frozen-bundle-final-spec.json" \
  --artifact-root "$CG_RUN_DIR/artifacts" \
  --output "$CG_RUN_DIR/frozen-bundle.json"
jq -e '.stage == "FINAL" and .status == "READY" and .pending == []' \
  "$CG_RUN_DIR/frozen-bundle.json"
```
