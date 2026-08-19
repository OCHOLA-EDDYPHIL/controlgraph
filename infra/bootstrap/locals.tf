locals {
  bootstrap_services = toset([
    "cloudresourcemanager.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
  ])

  labels = {
    application = "controlgraph"
    component   = "canary"
    environment = "nonprod"
    lifecycle   = "retained"
    managed_by  = "terraform"
  }

  state_bucket_name = "${var.project_id}-tfstate"
}

check "isolated_controlgraph_environment" {
  assert {
    condition     = !strcontains(lower(var.project_id), "reconcile")
    error_message = "The bootstrap stack refuses any project identifier that references RECONCILE."
  }

  assert {
    condition     = var.region == "us-central1"
    error_message = "The bootstrap stack is restricted to us-central1."
  }
}
