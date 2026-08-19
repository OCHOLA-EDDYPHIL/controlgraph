data "terraform_remote_state" "bootstrap" {
  backend = "gcs"

  config = {
    bucket = var.state_bucket_name
    prefix = var.bootstrap_state_prefix
  }
}

check "state_bucket_is_project_bound" {
  assert {
    condition     = var.state_bucket_name == "${var.project_id}-tfstate"
    error_message = "Foundation state must use the retained bucket derived from the dedicated project ID."
  }
}

check "bootstrap_project_id_matches" {
  assert {
    condition     = data.terraform_remote_state.bootstrap.outputs.project_id == var.project_id
    error_message = "Foundation project_id must match the bootstrap state output."
  }
}

check "bootstrap_project_number_matches" {
  assert {
    condition     = tostring(data.terraform_remote_state.bootstrap.outputs.project_number) == var.project_number
    error_message = "Foundation project_number must match the bootstrap state output."
  }
}

check "bootstrap_region_matches" {
  assert {
    condition     = data.terraform_remote_state.bootstrap.outputs.region == var.region
    error_message = "Foundation region must match the bootstrap state output."
  }
}

check "bootstrap_state_bucket_matches" {
  assert {
    condition     = data.terraform_remote_state.bootstrap.outputs.state_bucket_name == var.state_bucket_name
    error_message = "Foundation state bucket must match the bootstrap state output."
  }
}

check "bootstrap_organization_matches" {
  assert {
    condition     = tostring(data.terraform_remote_state.bootstrap.outputs.organization_id) == var.organization_id
    error_message = "Foundation organization_id must match the bootstrap state output."
  }
}
