variable "project_id" {
  description = "Immutable identifier for the dedicated ControlGraph Canary project."
  type        = string

  validation {
    condition     = can(regex("^controlgraph-canary-[a-z0-9]{6,10}$", var.project_id))
    error_message = "project_id must use controlgraph-canary- followed by 6 to 10 lowercase letters or digits."
  }

  validation {
    condition     = !strcontains(lower(var.project_id), "reconcile")
    error_message = "project_id must not reference RECONCILE."
  }
}

variable "organization_id" {
  description = "Numeric Google Cloud organization that will own the dedicated project."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{6,32}$", var.organization_id))
    error_message = "organization_id must be a numeric Google Cloud organization identifier."
  }
}

variable "billing_account_id" {
  description = "Existing billing account attached to the dedicated project."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", var.billing_account_id))
    error_message = "billing_account_id must use the Google Cloud billing-account identifier format."
  }
}

variable "region" {
  description = "Immutable region for every regional ControlGraph resource."
  type        = string

  validation {
    condition     = var.region == "us-central1"
    error_message = "region must be exactly us-central1."
  }
}
