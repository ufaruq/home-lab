mock_provider "grafana" {}

variables {
  free_plan_verified        = true
  prometheus_datasource_uid = "existing-prometheus"
  loki_datasource_uid       = "existing-loki"
  expected_linux_hosts      = ["linux-a", "linux-b"]
  expected_windows_hosts    = ["windows-a"]
}

run "trial_or_unverified_plan_is_blocked" {
  command = plan
  variables {
    free_plan_verified = false
  }
  expect_failures = [grafana_folder.homelab]
}

run "verified_unbilled_trial_allows_only_empty_host_dashboards" {
  command = plan
  variables {
    free_plan_verified                     = false
    unbilled_trial_dashboard_only_verified = true
    expected_linux_hosts                   = []
    expected_windows_hosts                 = []
    usage_datasource_uid                   = "existing-usage"
  }
  assert {
    condition     = length(grafana_dashboard.homelab) == 2 && length(grafana_rule_group.fleet) == 0
    error_message = "An unbilled trial may publish fleet/usage dashboards without alert rules."
  }
}

run "trial_exception_cannot_enable_host_rules" {
  command = plan
  variables {
    free_plan_verified                     = false
    unbilled_trial_dashboard_only_verified = true
  }
  expect_failures = [grafana_folder.homelab]
}

run "baseline_existing_stack_scope" {
  command = plan
  assert {
    condition     = length(grafana_dashboard.homelab) == 1 && length(grafana_rule_group.fleet) == 1
    error_message = "Only the baseline fleet dashboard and one host-health group should be planned."
  }
  assert {
    condition     = length(grafana_rule_group.fleet[0].rule) == 7 && alltrue([for rule in grafana_rule_group.fleet[0].rule : rule.is_paused])
    error_message = "Three per-host presence rules and four platform disk/memory rules must start paused."
  }
  assert {
    condition = alltrue([for rule in grafana_rule_group.fleet[0].rule :
      length(rule.data) == 3 && rule.condition == "C" &&
      jsondecode(rule.data[1].model).type == "reduce" &&
      jsondecode(rule.data[2].model).type == "threshold" &&
      length(jsondecode(rule.data[2].model).conditions) == 1
    ])
    error_message = "Rules must use native reduce and threshold expressions with exactly one threshold condition."
  }
  assert {
    condition = alltrue([for host in ["linux-a", "linux-b", "windows-a"] : length([
      for rule in grafana_rule_group.fleet[0].rule : rule if
      rule.name == "Host telemetry missing: ${host}" &&
      strcontains(jsondecode(rule.data[0].model).expr, "host=\"${host}\"") &&
      strcontains(jsondecode(rule.data[0].model).expr, "or vector(0)")
    ]) == 1])
    error_message = "Every expected host needs its own zero-filled absence check, including partial fleet loss."
  }
  assert {
    condition = alltrue([for panel in jsondecode(grafana_dashboard.homelab["fleet"].config_json).panels :
      contains(["existing-prometheus", "existing-loki"], panel.datasource.uid)
    ])
    error_message = "Dashboard panels must bind only existing supplied datasource UIDs."
  }
  assert {
    condition = length([
      for rule in grafana_rule_group.fleet[0].rule : rule if
      rule.name == "Windows memory pressure critical" &&
      strcontains(jsondecode(rule.data[0].model).expr, "windows_memory_physical_total_bytes") &&
      !strcontains(jsondecode(rule.data[0].model).expr, "windows_cs_")
    ]) == 1 && strcontains(grafana_dashboard.homelab["fleet"].config_json, "windows_memory_physical_total_bytes")
    error_message = "Windows memory queries must use the memory collector metric; the cs collector was removed from the bundled exporter."
  }
}

run "halted_fleet_has_no_uptime_rules" {
  command = plan
  variables {
    expected_linux_hosts   = []
    expected_windows_hosts = []
  }
  assert {
    condition     = length(grafana_rule_group.fleet) == 0 && length(output.expected_hosts) == 0
    error_message = "An undeployed or halted fleet must not create host-health rules."
  }
}

run "active_rules_require_owner_contact_point" {
  command = plan
  variables {
    alerts_enabled = true
  }
  expect_failures = [grafana_folder.homelab]
}

run "activate_only_existing_contact_point" {
  command = plan
  variables {
    alerts_enabled              = true
    existing_contact_point_name = "owner-chosen-existing"
  }
  assert {
    condition = alltrue([for rule in grafana_rule_group.fleet[0].rule :
      !rule.is_paused && rule.notification_settings[0].contact_point == "owner-chosen-existing"
    ])
    error_message = "Every active rule must route directly to the owner-selected existing contact point."
  }
}

run "no_ambiguous_platform" {
  command = plan
  variables {
    expected_windows_hosts = ["linux-a"]
  }
  expect_failures = [grafana_folder.homelab]
}

run "host_names_cannot_inject_promql" {
  command = plan
  variables {
    expected_linux_hosts = ["bad\"} or vector(1)"]
  }
  expect_failures = [var.expected_linux_hosts]
}

run "data_source_is_uid_not_url" {
  command = plan
  variables {
    prometheus_datasource_uid = "https://example.invalid/token"
  }
  expect_failures = [var.prometheus_datasource_uid]
}

run "optional_dashboards_use_explicit_existing_sources" {
  command = plan
  variables {
    usage_datasource_uid      = "existing-usage"
    enable_security_dashboard = true
  }
  assert {
    condition     = length(grafana_dashboard.homelab) == 3 && jsondecode(grafana_dashboard.homelab["usage"].config_json).panels[0].datasource.uid == "existing-usage"
    error_message = "Usage/security views must be opt-in and bind the supplied existing usage source."
  }
}
