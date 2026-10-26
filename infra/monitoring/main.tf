locals {
  repository_root = abspath("${path.module}/../..")
  fleet           = jsondecode(file("${local.repository_root}/monitoring/fleet.json"))
  selection = {
    collectors = sort(tolist(var.collector_targets))
    manager    = sort(tolist(var.wazuh_manager_targets))
    opnsense   = sort(tolist(var.opnsense_targets))
  }
  selection_count = length(var.collector_targets) + length(var.wazuh_manager_targets) + length(var.opnsense_targets)

  # Include public desired configuration only. Private credentials/inventory and
  # private vars are deliberately never read into Terraform values or state.
  deployment_files = sort(tolist(setunion(
    fileset(local.repository_root, "ansible/roles/monitoring_*/**"),
    fileset(local.repository_root, "ansible/playbooks/monitoring*.yml"),
    fileset(local.repository_root, "monitoring/wazuh/**"),
    fileset(local.repository_root, "monitoring/opnsense/**"),
    fileset(local.repository_root, "scripts/monitoring/*.py"),
    toset(["monitoring/fleet.json"])
  )))
  deployment_digest = sha256(jsonencode({
    selection = local.selection
    sources   = { for name in local.deployment_files : name => filesha256("${local.repository_root}/${name}") if !strcontains(name, "__pycache__/") && !endswith(name, ".pyc") }
  }))
}

# Static child module: its provider authenticates externally via GRAFANA_URL/AUTH.
# No cloud-account provider or billing privileges are used by this composition.
module "grafana" {
  source = "../grafana"

  free_plan_verified                     = var.free_plan_verified
  unbilled_trial_dashboard_only_verified = var.unbilled_trial_dashboard_only_verified || var.unbilled_trial_collection_verified
  prometheus_datasource_uid              = var.prometheus_datasource_uid
  loki_datasource_uid                    = var.loki_datasource_uid
  usage_datasource_uid                   = var.usage_datasource_uid
  expected_linux_hosts                   = var.expected_linux_hosts
  expected_windows_hosts                 = var.expected_windows_hosts
  alerts_enabled                         = var.alerts_enabled
  existing_contact_point_name            = var.existing_contact_point_name
  enable_security_dashboard              = var.enable_security_dashboard
}

resource "terraform_data" "fleet" {
  count = local.selection_count == 0 ? 0 : 1

  input = local.selection
  triggers_replace = {
    public_configuration_sha256 = local.deployment_digest
  }

  lifecycle {
    precondition {
      condition     = var.deployment_reviewed
      error_message = "Review the exact selected hosts and private deployment settings, then explicitly set deployment_reviewed=true."
    }
    precondition {
      condition = (var.free_plan_verified && local.fleet.grafana.observed_plan == "free" && local.fleet.grafana.live_apply_enabled == true) || (
        var.unbilled_trial_collection_verified && local.fleet.grafana.observed_plan == "trial" &&
        local.fleet.grafana.trial_collector_apply_enabled == true &&
        length(var.wazuh_manager_targets) == 0 && length(var.opnsense_targets) == 0
      )
      error_message = "Collector deployment requires verified Free or unbilled Trial; the Trial path permits only Alloy collectors, not Wazuh manager or OPNsense changes."
    }
  }

  # Creation/replacement re-runs idempotent Ansible through the reviewed safe
  # controller. There is no destroy provisioner and no credential-bearing state.
  provisioner "local-exec" {
    command = <<-EOT
      set -eu
      exec python3 "$MONITORING_CONTROLLER" deploy-fleet --selection-json "$MONITORING_SELECTION" --private-inventory "$MONITORING_PRIVATE_INVENTORY" --private-vars "$MONITORING_PRIVATE_VARS"
    EOT
    environment = {
      MONITORING_CONTROLLER = "${local.repository_root}/scripts/monitoring/manage.py"
      MONITORING_SELECTION  = jsonencode(local.selection)
    }
    quiet = true
  }
}
