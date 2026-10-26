terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  backend "local" {}
  required_providers {
    grafana = {
      source  = "grafana/grafana"
      version = "= 4.45.2"
    }
  }
}

provider "grafana" {
  insecure_skip_verify = false
}

variable "zero_cost_verified" {
  type    = bool
  default = false
}

variable "collector_enabled" {
  type    = bool
  default = true
}

locals {
  repository = abspath("${path.module}/../..")
  vm_policy  = jsondecode(file("${local.repository}/monitoring/xcp/vm-targets.json"))
  sources = setunion(
    fileset(local.repository, "monitoring/xcp/*.cjs"),
    fileset(local.repository, "monitoring/xcp/*.json"),
    fileset(local.repository, "ansible/roles/monitoring_xcp/**/*.yml"),
    toset(["ansible/playbooks/monitoring-xcp.yml", "scripts/monitoring/xcp.py"])
  )
}

data "grafana_folder" "homelab" {
  uid = "homelab-monitoring"
}

resource "grafana_dashboard" "xcp_host" {
  folder = data.grafana_folder.homelab.uid
  config_json = templatefile("${local.repository}/monitoring/grafana/dashboards/xcp-host.json.tftpl", {
    prometheus_uid = "grafanacloud-prom"
  })
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.zero_cost_verified
      error_message = "Use the controller to verify the existing unbilled Trial/Free stack and the saved plan."
    }
  }
}

resource "terraform_data" "collector" {
  input = {
    host_name  = "datacenter1"
    enabled    = var.collector_enabled
    vm_targets = local.vm_policy.targets
  }
  triggers_replace = {
    enabled       = var.collector_enabled
    source_digest = sha256(jsonencode({ for name in local.sources : name => filesha256("${local.repository}/${name}") }))
  }
  lifecycle {
    precondition {
      condition     = var.zero_cost_verified
      error_message = "Use the controller's live zero-cost verification before deploying."
    }
  }
  provisioner "local-exec" {
    command = "exec python3 \"$XCP_CONTROLLER\" deploy --enabled \"$XCP_ENABLED\""
    environment = {
      XCP_CONTROLLER = "${local.repository}/scripts/monitoring/xcp.py"
      XCP_ENABLED    = tostring(var.collector_enabled)
    }
    quiet = true
  }
}

output "dashboard_url" {
  value = grafana_dashboard.xcp_host.url
}

resource "grafana_dashboard" "xcp_vms" {
  folder = data.grafana_folder.homelab.uid
  config_json = templatefile("${local.repository}/monitoring/grafana/dashboards/xcp-vms.json.tftpl", {
    prometheus_uid = "grafanacloud-prom"
  })
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.zero_cost_verified
      error_message = "Use the controller to verify the existing unbilled Trial/Free stack and the saved plan."
    }
  }
}

output "vm_dashboard_url" {
  value = grafana_dashboard.xcp_vms.url
}
