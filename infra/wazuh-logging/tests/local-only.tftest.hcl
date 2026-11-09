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

run "native_repair_is_explicit_in_local_plan" {
  command = plan
  variables {
    deployment_reviewed  = true
    phase                = "truenas"
    agents               = []
    truenas_template_fix = true
  }
  assert {
    condition     = terraform_data.logging.input.native_template_fix == true && terraform_data.logging.input.phase == "truenas" && length(terraform_data.logging.input.agents) == 0
    error_message = "Native repair must be explicit and target only the existing manager/appliance workflow."
  }
}

run "native_repair_cannot_enter_other_phases" {
  command = plan
  variables {
    deployment_reviewed  = true
    phase                = "logging"
    truenas_template_fix = true
  }
  expect_failures = [terraform_data.logging]
}

run "truenas_cannot_install_guest_agents" {
  command = plan
  variables {
    deployment_reviewed = true
    phase               = "truenas"
    agents              = ["portainer"]
  }
  expect_failures = [terraform_data.logging]
}
