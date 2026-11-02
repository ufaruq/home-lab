locals {
  # A separate zero-filled query for every expected host detects partial fleet
  # loss as well as complete telemetry loss. Halted hosts must not be expected.
  missing_host_rules = {
    for host in local.expected_hosts : "missing-${host}" => {
      name      = "Host telemetry missing: ${host}"
      expr      = "1 - (max(max_over_time(up{job=\"homelab\",host=\"${host}\"}[5m])) or vector(0))"
      threshold = 0
      host      = host
      summary   = "No successful collector scrape from ${host} for at least five minutes. Verify intended power state, Alloy and remote write."
    }
  }
  linux_rules = length(var.expected_linux_hosts) == 0 ? {} : {
    linux-disk = {
      name      = "Linux disk space critical"
      expr      = "100 * (1 - node_filesystem_avail_bytes{job=\"homelab\",host=~\"${local.linux_hosts}\",fstype!~\"tmpfs|devtmpfs|overlay|squashfs\"} / node_filesystem_size_bytes{job=\"homelab\",host=~\"${local.linux_hosts}\",fstype!~\"tmpfs|devtmpfs|overlay|squashfs\"}) and on(host,device,mountpoint) (node_filesystem_readonly{job=\"homelab\"} == 0)"
      threshold = 90
      host      = null
      summary   = "Writable filesystem has less than 10% available space for ten minutes."
    }
    linux-memory = {
      name      = "Linux memory pressure critical"
      expr      = "100 * (1 - node_memory_MemAvailable_bytes{job=\"homelab\",host=~\"${local.linux_hosts}\"} / node_memory_MemTotal_bytes{job=\"homelab\",host=~\"${local.linux_hosts}\"})"
      threshold = 90
      host      = null
      summary   = "Available host memory has stayed below 10% for ten minutes."
    }
  }
  windows_rules = length(var.expected_windows_hosts) == 0 ? {} : {
    windows-disk = {
      name      = "Windows disk space critical"
      expr      = "100 * (1 - windows_logical_disk_free_bytes{job=\"homelab\",host=~\"${local.windows_hosts}\",volume!~\"HarddiskVolume.*\"} / windows_logical_disk_size_bytes{job=\"homelab\",host=~\"${local.windows_hosts}\",volume!~\"HarddiskVolume.*\"})"
      threshold = 90
      host      = null
      summary   = "Windows volume has less than 10% free space for ten minutes."
    }
    windows-memory = {
      name      = "Windows memory pressure critical"
      expr      = "100 * (1 - windows_memory_available_bytes{job=\"homelab\",host=~\"${local.windows_hosts}\"} / windows_memory_physical_total_bytes{job=\"homelab\",host=~\"${local.windows_hosts}\"})"
      threshold = 90
      host      = null
      summary   = "Available Windows memory has stayed below 10% for ten minutes."
    }
  }
  alert_rules = merge(local.missing_host_rules, local.linux_rules, local.windows_rules)
}

resource "grafana_rule_group" "fleet" {
  count            = length(local.expected_hosts) == 0 ? 0 : 1
  name             = "Home lab host health"
  folder_uid       = grafana_folder.homelab.uid
  interval_seconds = 60

  dynamic "rule" {
    for_each = local.alert_rules
    content {
      name           = rule.value.name
      condition      = "C"
      for            = startswith(rule.key, "missing-") ? "5m" : "10m"
      no_data_state  = "OK"
      exec_err_state = "Error"
      is_paused      = !var.alerts_enabled
      labels = merge({
        managed_by = "terraform-homelab"
        scope      = "homelab"
        severity   = "critical"
      }, rule.value.host == null ? {} : { host = rule.value.host })
      annotations = {
        summary     = rule.value.summary
        description = "Host {{ $labels.host }}; value {{ $values.B.Value }}. See the Home lab fleet dashboard. Missing data on disk/memory is handled by the individual host telemetry rule."
      }

      data {
        ref_id         = "A"
        datasource_uid = var.prometheus_datasource_uid
        relative_time_range {
          from = 600
          to   = 0
        }
        model = jsonencode({
          datasource    = { type = "prometheus", uid = var.prometheus_datasource_uid }
          editorMode    = "code"
          expr          = rule.value.expr
          instant       = false
          range         = true
          intervalMs    = 60000
          maxDataPoints = 600
          refId         = "A"
        })
      }

      data {
        ref_id         = "B"
        datasource_uid = "__expr__"
        relative_time_range {
          from = 0
          to   = 0
        }
        model = jsonencode({
          datasource = { type = "__expr__", uid = "__expr__" }
          expression = "A"
          reducer    = "last"
          refId      = "B"
          type       = "reduce"
        })
      }

      data {
        ref_id         = "C"
        datasource_uid = "__expr__"
        relative_time_range {
          from = 0
          to   = 0
        }
        model = jsonencode({
          datasource = { type = "__expr__", uid = "__expr__" }
          expression = "B"
          refId      = "C"
          type       = "threshold"
          conditions = [{
            evaluator = { params = [rule.value.threshold], type = "gt" }
            operator  = { type = "and" }
            query     = { params = ["C"] }
            reducer   = { params = [], type = "last" }
            type      = "query"
          }]
        })
      }

      dynamic "notification_settings" {
        for_each = var.existing_contact_point_name == null ? [] : [var.existing_contact_point_name]
        content {
          contact_point   = notification_settings.value
          group_by        = ["alertname", "grafana_folder", "host"]
          repeat_interval = "4h"
        }
      }
    }
  }
}
