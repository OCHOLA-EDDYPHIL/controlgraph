resource "google_billing_budget" "project_monthly" {
  billing_account = var.billing_account_id
  display_name    = "ControlGraph Canary monthly project budget"

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "10"
    }
  }

  budget_filter {
    projects               = ["projects/${var.project_number}"]
    calendar_period        = "MONTH"
    credit_types_treatment = "INCLUDE_ALL_CREDITS"
  }

  threshold_rules {
    threshold_percent = 0.50
    spend_basis       = "CURRENT_SPEND"
  }

  threshold_rules {
    threshold_percent = 0.80
    spend_basis       = "CURRENT_SPEND"
  }

  threshold_rules {
    threshold_percent = 1.00
    spend_basis       = "CURRENT_SPEND"
  }

  threshold_rules {
    threshold_percent = 1.00
    spend_basis       = "FORECASTED_SPEND"
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required["billingbudgets.googleapis.com"]]
}
