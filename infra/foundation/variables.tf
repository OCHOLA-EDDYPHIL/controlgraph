variable "project_id" {
  description = "Dedicated Google Cloud project for ControlGraph Canary."
  type        = string

  validation {
    condition     = can(regex("^controlgraph-canary-[a-z0-9]{6,10}$", var.project_id))
    error_message = "project_id must use controlgraph-canary- followed by 6 to 10 lowercase letters or digits."
  }
}

variable "project_number" {
  description = "Numeric identifier of the dedicated Google Cloud project."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{6,20}$", var.project_number))
    error_message = "project_number must contain only the numeric Google Cloud project identifier."
  }
}

variable "organization_id" {
  description = "Numeric Google Cloud organization identifier recorded by bootstrap."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{6,20}$", var.organization_id))
    error_message = "organization_id must contain only the numeric Google Cloud organization identifier."
  }
}

variable "region" {
  description = "Sole Google Cloud region for ControlGraph Canary resources."
  type        = string

  validation {
    condition     = var.region == "us-central1"
    error_message = "region must be exactly us-central1."
  }
}

variable "state_bucket_name" {
  description = "ControlGraph-only GCS bucket containing bootstrap and foundation state."
  type        = string

  validation {
    condition = (
      can(regex("^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", var.state_bucket_name)) &&
      !strcontains(lower(var.state_bucket_name), "reconcile")
    )
    error_message = "state_bucket_name must be a valid ControlGraph-only bucket name without a RECONCILE identifier."
  }
}

variable "bootstrap_state_prefix" {
  description = "Fixed GCS state prefix produced by the bootstrap stack."
  type        = string
  default     = "bootstrap"

  validation {
    condition     = var.bootstrap_state_prefix == "bootstrap"
    error_message = "bootstrap_state_prefix must be exactly bootstrap."
  }
}

variable "billing_account_id" {
  description = "Billing account that owns the project-scoped monthly visibility budget."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", var.billing_account_id))
    error_message = "billing_account_id must use the six-six-six uppercase billing account format."
  }
}

variable "network_name" {
  description = "Name of the dedicated custom VPC."
  type        = string
  default     = "controlgraph-canary"

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", var.network_name)) &&
      !strcontains(lower(var.network_name), "reconcile")
    )
    error_message = "network_name must be a valid dedicated VPC name without a RECONCILE identifier."
  }
}

variable "subnetwork_name" {
  description = "Name of the sole regional subnetwork."
  type        = string
  default     = "controlgraph-canary-us-central1"

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", var.subnetwork_name)) &&
      !strcontains(lower(var.subnetwork_name), "reconcile")
    )
    error_message = "subnetwork_name must be a valid dedicated subnetwork name without a RECONCILE identifier."
  }
}

variable "subnetwork_cidr" {
  description = "IPv4 CIDR reserved for the sole regional subnetwork."
  type        = string
  default     = "10.42.0.0/24"

  validation {
    condition     = var.subnetwork_cidr == "10.42.0.0/24"
    error_message = "subnetwork_cidr must be exactly 10.42.0.0/24."
  }
}

variable "artifact_repository_id" {
  description = "Regional Docker repository identifier."
  type        = string
  default     = "controlgraph-canary"

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", var.artifact_repository_id)) &&
      !strcontains(lower(var.artifact_repository_id), "reconcile")
    )
    error_message = "artifact_repository_id must be a valid dedicated repository ID without a RECONCILE identifier."
  }
}

variable "github_repository" {
  description = "Exact GitHub owner and repository allowed to exchange an OIDC token."
  type        = string

  validation {
    condition     = var.github_repository == "OCHOLA-EDDYPHIL/controlgraph"
    error_message = "github_repository must identify the ControlGraph repository exactly."
  }
}

variable "github_repository_id" {
  description = "Immutable numeric GitHub repository identifier allowed by workload identity federation."
  type        = string

  validation {
    condition     = var.github_repository_id == "1338673889"
    error_message = "github_repository_id must match the immutable ControlGraph repository identifier."
  }
}

variable "github_owner_id" {
  description = "Immutable numeric GitHub owner identifier allowed by workload identity federation."
  type        = string

  validation {
    condition     = var.github_owner_id == "154631735"
    error_message = "github_owner_id must match the immutable ControlGraph owner identifier."
  }
}

variable "github_ref" {
  description = "Exact GitHub ref allowed by workload identity federation."
  type        = string

  validation {
    condition     = var.github_ref == "refs/heads/main"
    error_message = "github_ref must be exactly refs/heads/main."
  }
}

variable "github_workflow_ref" {
  description = "Exact GitHub workflow ref allowed by workload identity federation."
  type        = string

  validation {
    condition = (
      startswith(var.github_workflow_ref, "OCHOLA-EDDYPHIL/controlgraph/.github/workflows/") &&
      endswith(var.github_workflow_ref, "@refs/heads/main")
    )
    error_message = "github_workflow_ref must bind a ControlGraph workflow to refs/heads/main."
  }
}

variable "operator_principal" {
  description = "Exact human operator principal granted the bounded operator role."
  type        = string

  validation {
    condition     = can(regex("^user:[^@[:space:]]+@[^@[:space:]]+$", var.operator_principal))
    error_message = "operator_principal must be one explicit user email principal."
  }
}

variable "operator_subject" {
  description = "Exact Google identity subject for the human operator."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]{5,31}$", var.operator_subject))
    error_message = "operator_subject must be one explicit numeric Google identity subject."
  }
}
