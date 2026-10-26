mock_provider "grafana" {}

variables {
  free_plan_verified        = true
  prometheus_datasource_uid = "existing-prometheus"
  loki_datasource_uid       = "existing-loki"
}

run "empty_selection_never_runs_host_configuration" {
  command = plan
  assert {
    condition     = length(terraform_data.fleet) == 0 && alltrue([for names in values(output.selected_targets) : length(names) == 0])
    error_message = "The default must perform no guest configuration."
  }
  assert {
    condition     = length(output.public_configuration_sha256) == 64
    error_message = "Public configuration must have a deterministic SHA-256 digest."
  }
}

run "unbilled_trial_does_not_allow_guest_convergence" {
  command = plan
  variables {
    free_plan_verified                     = false
    unbilled_trial_dashboard_only_verified = true
    collector_targets                      = ["maps"]
    deployment_reviewed                    = true
  }
  expect_failures = [terraform_data.fleet[0]]
}

run "trial_blocks_selected_host_deployment" {
  command = plan
  variables {
    collector_targets   = ["debian_server"]
    deployment_reviewed = true
  }
  expect_failures = [terraform_data.fleet[0]]
}

run "review_is_required_for_nonempty_selection" {
  command = plan
  variables {
    collector_targets = ["debian_server"]
  }
  expect_failures = [terraform_data.fleet[0]]
}

run "unknown_host_is_blocked" {
  command = plan
  variables {
    collector_targets = ["invented_host"]
  }
  expect_failures = [var.collector_targets]
}

run "dom0_never_receives_collectors" {
  command = plan
  variables {
    collector_targets = ["datacenter1"]
  }
  expect_failures = [var.collector_targets]
}

run "diskless_host_is_blocked" {
  command = plan
  variables {
    collector_targets = ["deb_node_db"]
  }
  expect_failures = [var.collector_targets]
}

run "appliance_collectors_are_blocked" {
  command = plan
  variables {
    collector_targets = ["truenas"]
  }
  expect_failures = [var.collector_targets]
}

run "manager_has_only_one_authorized_host" {
  command = plan
  variables {
    wazuh_manager_targets = ["debian_server"]
  }
  expect_failures = [var.wazuh_manager_targets]
}

run "opnsense_requires_manifest_firewall" {
  command = plan
  variables {
    opnsense_targets = ["wazuh"]
  }
  expect_failures = [var.opnsense_targets]
}
