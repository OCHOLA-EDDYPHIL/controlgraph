# Infrastructure

ControlGraph uses independent Terraform states for project bootstrap, shared foundation, and
runtime services. Every stack targets one dedicated non-production project in `us-central1` and
rejects project identifiers containing `reconcile`.

```text
bootstrap/   Dedicated project and retained Terraform state bucket
foundation/  APIs, budget, audit policy, network, registry, identities, and IAM
runtime/     Private services, fixed task queues, and the disposable reference target
```

The runtime stack is added by the service deployment roadmap issues. No stack may use a shared
project, a sibling repository state bucket, or credentials stored in this repository.

## Bootstrap and state migration

Copy only the example for the stack being operated and keep the resulting `.tfvars` file
untracked. The bootstrap state begins locally because its own bucket does not exist yet:

```bash
cd infra/bootstrap
cp terraform.tfvars.example terraform.tfvars
terraform init -backend=false
terraform fmt -check
terraform validate
terraform plan -out=bootstrap.tfplan
terraform apply bootstrap.tfplan
```

After reading the new bucket name from the bootstrap output, migrate the local state into that
bucket. Materialize the ignored backend file from its reviewed template, then use the exact new
bucket and a ControlGraph-only prefix:

```bash
cp backend.gcs.tf.example backend.tf
terraform init -migrate-state \
  -backend-config="bucket=CONTROLGRAPH_STATE_BUCKET" \
  -backend-config="prefix=bootstrap"
```

Initialize later stacks with separate prefixes in the same retained bucket:

```bash
terraform -chdir=../foundation init \
  -backend-config="bucket=CONTROLGRAPH_STATE_BUCKET" \
  -backend-config="prefix=foundation"
```

Always review the saved plan before applying. Confirm the exact project ID, organization,
`us-central1` region, resource names, labels, IAM members, budget filter, and lifecycle settings.
An apply is never inferred from a successful validation.

The Google IAM, Workload Identity Federation, Billing, and Logging `_Required` control planes are
provider-managed global services. They carry no rollout authority data path. The project
`_Default` sink is explicitly routed to the dedicated `us-central1` log bucket; Firestore, KMS,
Tasks, Artifact Registry, networking, Cloud Run, and workload log storage remain regional.

## Cost and retention

The foundation configures a project-filtered USD 10 monthly budget with current-spend alerts at
50, 90, and 100 percent and a forecast alert at 100 percent. A budget is visibility, not a hard
spending cap. Cloud Run services use bounded scaling in the runtime stack, logs retain 30 days,
and Artifact Registry cleanup is limited to old untagged artifacts.

The project, state bucket, authority database, signing keys, network, registry, log bucket,
runtime services, and acceptance evidence remain retained after M4. Deletion protection and
`prevent_destroy` are deliberate. Bootstrap and foundation applies use an authenticated human;
the keyless CI Terraform identity is currently limited to its exact state bucket. Resource
provisioning permissions are added only with the resource-specific deployment workflow.

## Separately authorized teardown

Teardown requires a new explicit authorization. The reviewed order is:

1. stop new operator requests, preserve the final acceptance evidence, and inspect plans for the
   exact dedicated project;
2. use a reviewed teardown change to remove `prevent_destroy` only from authorized runtime and
   foundation resources, then destroy runtime before foundation;
3. verify both child states contain no managed resources, while retaining their state objects for
   the final audit;
4. move the ignored bootstrap backend configuration out of the stack and migrate bootstrap state
   from GCS to a protected local backend; verify that local state before touching bucket objects;
5. remove only the reviewed `runtime`, `foundation`, and `bootstrap` state prefixes, including
   noncurrent versions, and account for the bucket's seven-day soft-delete retention;
6. in a second reviewed change, remove bootstrap `prevent_destroy`, change the project deletion
   policy, and delete the now-empty state bucket and project from the migrated local state; and
7. verify that no shared, RECONCILE, billing-account, organization, or unrelated resource changed.

Do not disable protections or run teardown commands as part of M2–M4 acceptance.
