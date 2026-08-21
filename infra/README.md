# Infrastructure

ControlGraph uses independent Terraform states for project bootstrap, shared foundation, and
runtime services. Every stack targets one dedicated non-production project in `us-central1` and
rejects project identifiers containing `reconcile`.

```text
bootstrap/   Dedicated project and retained Terraform state bucket
foundation/  APIs, budget, audit policy, network, registry, authority data, keys, identities, IAM
runtime/     Private controller services and fixed authenticated task queues
```

The runtime stack includes the disposable reference target used by the closed canary contract.
No stack may use a shared project, a sibling repository state bucket, or credentials stored in
this repository.

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
terraform -chdir=../runtime init \
  -backend-config="bucket=CONTROLGRAPH_STATE_BUCKET" \
  -backend-config="prefix=runtime"
```

Always review the saved plan before applying. Confirm the exact project ID, organization,
`us-central1` region, resource names, labels, IAM members, budget filter, and lifecycle settings.
An apply is never inferred from a successful validation.

The Google IAM, Workload Identity Federation, Billing, and Logging `_Required` control planes are
provider-managed global services. They carry no rollout authority data path. The project
`_Default` sink is explicitly routed to the dedicated `us-central1` log bucket; Firestore, KMS,
Tasks, Artifact Registry, networking, Cloud Run, and workload log storage remain regional.

## Defined cost and retention

The foundation configuration defines a project-filtered USD 10 monthly budget with current-spend
alerts at 50, 90, and 100 percent and a forecast alert at 100 percent. A budget is visibility, not
a hard spending cap. The runtime definitions bound Cloud Run scaling, retain workload logs for 30
days, and limit Artifact Registry cleanup to old untagged artifacts when the stacks are applied.

The definitions retain the project, state bucket, authority database, signing keys, network,
registry, log bucket, runtime services, and evidence. Deletion protection and
`prevent_destroy` are deliberate. An authorized bootstrap or foundation apply uses an
authenticated human; the defined keyless CI Terraform identity is limited to its exact state
bucket and dedicated signing key ring. Resource provisioning permissions are added only with a
resource-specific deployment workflow.

The foundation declares one Firestore Native database named `controlgraph-authority` and one
regional KMS key ring containing exactly two asymmetric signing keys: capability and evidence.
The runtime stack declares seven Python controller services and the disposable reference target
from dedicated-registry image digests. Each controller has its own runtime identity, bounded
scaling and resources, Direct VPC egress, and authenticated invocation. The API binding admits
only the explicit operator principal; all other controller definitions use internal ingress.
Execution and recovery queues are separate, region-pinned, limited to one dispatch per second
and one concurrent dispatch, and force their exact HTTPS path, OIDC caller, and audience.

Only the executor receives service-scoped target traffic-update, reference-target `actAs`, and
project operation-read grants. Cloud Run IAM lets the recovery identity invoke the executor
service, but application caller policy admits that identity only at the recovery facade and
rejects it at the normal execution route. Recovery receives none of the direct target permissions.
Only the verifier receives Monitoring time-series access, and its target-snapshot role is scoped
to the reference service. The executor uses separate authenticated coordinator routes for
standard and recovery receipt transitions.

The IAM graph keeps the capability issuer and evidence writer as distinct identities with signer
access to only their respective keys. It grants the evidence writer no Firestore authority write,
keeps the verifier read-only, and permits the API identity to read the two public keys and version
metadata for trust-bundle publication without signing or key administration.

Firestore server-client IAM is database-granular. The coordinator authority facade is the only
defined database writer. The executor receives read access and must use narrow authenticated
coordinator operations for receipt claim and compare-and-set writes; the recovery identity can
read the authority needed to validate forwarding but receives no receipt-write path. Collection
names are application contract boundaries, not claimed IAM boundaries.

The keyless CI Terraform identity can administer objects in its exact state bucket and signing
keys in the dedicated key ring; it is intentionally not granted general runtime provisioning
authority. Bootstrap, foundation, and runtime applies therefore remain authenticated human
operations until a reviewed resource-specific deployment workflow grants narrower provisioning
permissions.

## Retained authority data and keys

The authority database uses delete protection, an `ABANDON` deletion policy, and
`prevent_destroy`. A separately authorized teardown must first decide whether the synthetic
authority and receipt records require a Firestore managed export, record the export location and
retention boundary, then review a change that disables database deletion protection. Removing the
Terraform resource alone must not be represented as deleting the retained database.

KMS private key material is never exportable. Separately authorized retirement disables a key
version before scheduling destruction, preserves public verification material for retained
evidence, and observes the configured 30-day destruction delay. Acceptance must not disable or
schedule destruction of either initial signing version.

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

Do not disable protections or run teardown commands as part of normal acceptance.
