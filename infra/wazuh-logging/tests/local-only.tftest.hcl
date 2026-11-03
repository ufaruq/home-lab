run "unreviewed_deployment_is_refused" {
  command         = plan
  expect_failures = [terraform_data.logging]
}

run "existing_local_manager_and_selected_guest" {
  command = plan
  variables {
    deployment_reviewed = true
    agents              = ["portainer"]
    phase               = "logging"
  }
  assert {
    condition     = terraform_data.logging.input.manager == "wazuh" && terraform_data.logging.input.retention_days == 7
    error_message = "Only the existing local manager and seven-day alert retention are permitted."
  }
  assert {
    condition     = terraform_data.logging.input.agents == tolist(["portainer"])
    error_message = "Guest selection must be exact."
  }
}

run "parrot_is_refused" {
  command = plan
  variables {
    deployment_reviewed = true
    agents              = ["parrot_htb"]
  }
  expect_failures = [var.agents]
}
