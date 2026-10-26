output "selected_targets" {
  description = "Exact public deployment selection; empty selection performs no host configuration."
  value       = local.selection
}

output "public_configuration_sha256" {
  description = "Digest of selected names and versioned public deployment configuration; excludes private inputs."
  value       = local.deployment_digest
}

output "grafana_folder_uid" {
  value = module.grafana.folder_uid
}

output "grafana_dashboard_uids" {
  value = module.grafana.dashboard_uids
}
