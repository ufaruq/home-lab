# Existing Grafana stack configuration

The primary deployment entrypoint is [`infra/monitoring`](../monitoring/README.md),
which composes this static child module with Terraform-managed fleet convergence.
Use its guarded workflow for deployment. This directory remains independently
validatable for focused local tests; do not apply both roots with separate states
against the same existing Grafana objects.

This root manages only a folder, sourced dashboards and Grafana-managed alert rules in
the existing `https://cordialbike2680.grafana.net` stack. It creates no cloud stack,
subscription, data source, service account, integration, contact point or global
notification policy. It does not install a Grafana server.

The live stack reports Cloud Trial. This child root permits only folders and
dashboards, with empty expected-host sets and alerts disabled. It requires
`unbilled_trial_dashboard_only_verified=true`, the public trial-dashboard declaration,
and the controller's fresh live edition check before plan and apply. The primary
`infra/monitoring` composition separately permits selected Alloy collectors during
the verified Trial. Grafana states that trial usage is never billed and automatically moves to Free
([official documentation](https://grafana.com/docs/grafana-cloud/platform/cost-management-and-billing/manage-invoices/understand-your-invoice/)).
This dashboard-only exception enables no ingestion, host deployment, alert rules or billing changes.
`free_plan_verified` remains false until actual Free status is verified. These gates
are not universal spending caps; review combined usage before enabling collectors.

## Inputs and credentials

Supply `GRAFANA_URL=https://cordialbike2680.grafana.net` and `GRAFANA_AUTH` through the
environment from your private credential manager. Use an existing stack service
account with only the folder/dashboard/alert permissions needed here. Do not use an
organization-wide Grafana Cloud access-policy token or billing credentials. TLS
verification is explicitly enabled. Never put tokens in command arguments, tfvars,
source files or outputs. Do not enable provider debug logs.

The service account needs folder read/write and dashboard create/read/write access
to **Home lab monitoring**, not just the bundled GrafanaCloud folder. A token can
have `folders:create` while lacking access to the newly created folder. During
bootstrap an administrator can grant that service account **Edit** on this folder
through Dashboards → Home lab monitoring → Folder actions → Manage permissions.
This narrow grant does not require an administrator token or billing access.
Do not assume a successful data-source lookup proves folder permissions.

If folder creation succeeds but its read-back fails with HTTP 403, keep the state
and fix that folder permission first. Terraform may mark the created folder tainted.
After independently reading it and confirming UID `homelab-monitoring`, clear only
that taint with `terraform -chdir=infra/monitoring untaint
module.grafana.grafana_folder.homelab`, then generate and inspect a new saved plan.
Do not delete the folder, remove lifecycle protection or reuse the failed plan.

Copy `terraform.tfvars.example` to a mode-0600 file outside this checkout. Required
inputs are the **existing** Prometheus and Loki data source UIDs. Find UIDs in the
existing stack's data source settings; this root never provisions backends. Optional
`usage_datasource_uid` must identify the existing `grafanacloud-usage` source.

`expected_linux_hosts` and `expected_windows_hosts` contain only enabled, deployed
inventory names that should currently be online. Their empty defaults intentionally
create no alert group. Exclude halted guests, diskless definitions, appliances and
dom0. Remove a host before planned long shutdown; add it only after deploying its
collector. The controller/manifest remain the authoritative deployment selection;
these sets are the explicit alerting expectation, and must be reviewed together.

Rules are paused by default. To activate, verify each query and supply both
`alerts_enabled=true` and the owner's `existing_contact_point_name`. All active rules
route directly to that existing contact point; recipients and transport secrets stay
private in Grafana. Direct routing needs Grafana 10.4+ with simplified routing enabled.
If unavailable, leave alerts paused until the owner provides a compatible routing
arrangement. This root never takes over the global notification policy tree.

## Local checks and deployment

```sh
terraform -chdir=infra/grafana init -backend=false
terraform -chdir=infra/grafana fmt -check -recursive
terraform -chdir=infra/grafana validate
terraform -chdir=infra/grafana test
```

These checks use mock providers and need no live credentials. `init` downloads the
pinned provider; validate/test may need permission for the provider's local Unix
socket. Tests do not verify live PromQL evaluation or contact-point delivery.

Use the repository monitoring controller for a saved plan and guarded apply once
its private-input and applicable Free/Trial checks pass. Review the actual plan: the
only allowed managed resource types in Free mode are `grafana_folder`,
`grafana_dashboard` and `grafana_rule_group`; the trial exception excludes rule groups.

Terraform state, saved plans and private inputs contain operational details. Keep
them owner-only and outside Git. The controller places plans and logs in the
private runtime directory, but this standalone root's local state defaults to the
Git-ignored `infra/grafana/terraform.tfstate` (and adjacent backup). Protect those
files and keep owner-only backups outside the checkout. `TF_DATA_DIR` relocates
Terraform working data, not state. Provider authentication and collector ingestion
tokens are supplied externally and are not Terraform inputs or resource state.
Do not upload state to a paid backend, run an unguarded `terraform apply`, or copy
shell history containing secrets.

The folder has `prevent_destroy=true`. Existing resources with these UIDs must be
imported and reviewed before adoption; do not overwrite an unrelated dashboard.
To import an existing owned folder: `terraform -chdir=infra/grafana import
grafana_folder.homelab homelab-monitoring` with the same private inputs and state
location. Dashboard UIDs are `homelab-fleet`, `homelab-security` and
`homelab-free-usage`. Restore desired source, review a saved plan and reapply to
redeploy. Decommission intentionally requires a separate review of lifecycle
protection and the saved plan.

## Metrics, logs and alert semantics

Collectors use stable labels `job=homelab`, `host=<inventory_name>`,
`environment=homelab|lab` and `role=<manifest role>`. Fleet panels query Linux
`node_cpu_seconds_total`, `node_memory_MemAvailable_bytes`,
`node_memory_MemTotal_bytes`, `node_filesystem_avail_bytes`,
`node_filesystem_size_bytes`, and Windows `windows_cpu_time_total`,
`windows_memory_available_bytes`, `windows_memory_physical_total_bytes`,
`windows_logical_disk_free_bytes`, `windows_logical_disk_size_bytes`.
Disk alerts also need `node_filesystem_readonly`. Presence uses scrape `up`.

Each expected host has an independent missing-telemetry rule using a zero fallback;
one missing host is detected while others remain healthy. It observes successful
scrapes over five minutes then requires five additional minutes before firing.
Disk usage above 90% and memory usage above 90% require ten minutes. Disk/memory
No Data is OK because presence rules cover collector loss; query failures remain
Error. This does not detect an exporter that is reachable but silently stops
emitting one metric family. Native reduce/threshold expressions preserve instance
labels so the alert identifies host and filesystem. No service probes or remote
commands are implied by `up`.

The optional security dashboard is reserved for a **separately implemented and
reviewed security-log export**. Current supported Alloy collectors intentionally
reject Wazuh `alerts.json` and do not feed this dashboard. Leave
`enable_security_dashboard=false`; enabling the view does not configure an export
or grant log access. Its future-export selector is
`{job="homelab",filename="/var/ossec/logs/alerts/alerts.json"}`. Implement and review
the export's privacy, permissions, labels and Free-tier usage separately before
using that view. No log permissions are widened by this configuration.
The optional usage dashboard reads official active-series and samples-per-second
metrics from the existing usage source. Its Loki daily log-byte panel measures only
retained `job=homelab` logs, so it is **not** tenant-wide billing ingestion; consult
Grafana's Usage screen for the full tenant, all other jobs, logs, and retention.
7,000 active series and 500 MB/day logs are operational targets, not hard caps.

## Verified primary references

- [Pinned provider 4.45.2](https://registry.terraform.io/providers/grafana/grafana/4.45.2)
- [Provider environment authentication](https://github.com/grafana/terraform-provider-grafana/blob/v4.45.2/docs/index.md)
- [Rule group and direct notification schema](https://github.com/grafana/terraform-provider-grafana/blob/v4.45.2/docs/resources/rule_group.md)
- [Grafana's native reduce/threshold provisioning example](https://github.com/grafana/provisioning-alerting-examples/blob/main/config-files/grafana/provisioning/alerting/alert_rules.yaml)
- [Official usage metrics](https://grafana.com/docs/grafana-cloud/platform/cost-management-and-billing/understand-usage-cost/metrics/)
