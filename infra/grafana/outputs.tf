output "folder_uid" {
  value = grafana_folder.homelab.uid
}

output "expected_hosts" {
  description = "Hosts whose missing telemetry is monitored; review before enabling alerts."
  value       = sort(tolist(local.expected_hosts))
}

output "dashboard_uids" {
  value = { for name, dashboard in grafana_dashboard.homelab : name => dashboard.uid }
}
