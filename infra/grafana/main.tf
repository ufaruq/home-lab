locals {
  expected_hosts = setunion(var.expected_linux_hosts, var.expected_windows_hosts)
  linux_hosts    = join("|", sort(tolist(var.expected_linux_hosts)))
  windows_hosts  = join("|", sort(tolist(var.expected_windows_hosts)))
  dashboard_sources = merge({
    fleet = "fleet.json.tftpl"
    }, var.enable_security_dashboard ? {
    security = "security.json.tftpl"
    } : {}, var.usage_datasource_uid != null ? {
    usage = "usage.json.tftpl"
  } : {})
}

resource "grafana_folder" "homelab" {
  uid   = "homelab-monitoring"
  title = "Home lab monitoring"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.free_plan_verified || (var.unbilled_trial_dashboard_only_verified && length(local.expected_hosts) == 0 && !var.alerts_enabled)
      error_message = "Verify actual Free status, or explicitly verify an unbilled Cloud Trial for dashboard-only deployment with no expected hosts or alerts."
    }
    precondition {
      condition     = length(setintersection(var.expected_linux_hosts, var.expected_windows_hosts)) == 0
      error_message = "A host cannot be both Linux and Windows."
    }
    precondition {
      condition     = !var.alerts_enabled || (var.existing_contact_point_name != null && length(local.expected_hosts) > 0)
      error_message = "Activating alerts requires an owner-selected existing contact point and at least one expected deployed host."
    }
  }
}

resource "grafana_dashboard" "homelab" {
  for_each = local.dashboard_sources
  folder   = grafana_folder.homelab.uid
  config_json = templatefile("${path.module}/../../monitoring/grafana/dashboards/${each.value}", {
    prometheus_uid = var.prometheus_datasource_uid
    loki_uid       = var.loki_datasource_uid
    usage_uid      = coalesce(var.usage_datasource_uid, "unused")
  })
}
