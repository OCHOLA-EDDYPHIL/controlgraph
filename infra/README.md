# Infrastructure

This directory starts with validated deployment contracts and evolves through the numbered
roadmap issues into the isolated ControlGraph acceptance environment. Infrastructure changes
use Terraform, immutable image digests, one explicit project, and one explicit region.

```bash
cp terraform.tfvars.example terraform.tfvars
terraform init -backend=false
terraform validate
terraform plan
```

The example digest is a syntax placeholder, not a deployable image. Replace it with the digest
of a reviewed build. Never plan or apply against a shared or RECONCILE project. Review every
saved plan for exact project, region, resource names, scaling bounds, budget, and teardown
behavior before applying it.
