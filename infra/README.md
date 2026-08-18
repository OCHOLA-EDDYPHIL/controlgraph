# Infrastructure contracts

This directory captures validated inputs for a future Cloud Run deployment. The child module creates no resources and makes no API calls. It exists so service names, scaling bounds, and immutable image references can be reviewed before deployment wiring is designed.

```bash
cp terraform.tfvars.example terraform.tfvars
terraform init -backend=false
terraform validate
terraform plan
```

The example digest is a syntax placeholder, not a deployable image. Replace it with the digest of a reviewed build.
