# XCP-ng host metrics

The owner confirmed `datacenter1`, the XCP-ng hypervisor, as the target. The
earlier Maps pilot is a separate guest and does not satisfy this objective.

Use XOA's existing JSON-RPC `host.stats` and inventory APIs. A collector runs
once per minute as the existing unprivileged XOA automation user. Ansible owns
its files, private configuration and cron entry; a dedicated Terraform root
owns that deployment and the Grafana host dashboard. No package or agent is
installed in dom0, and VM power/network state is outside this deployment.

The collector uses a dedicated XOA user with a viewer ACL on the existing pool.
Administrator API credentials are used only by the idempotent account setup
task, never stored in the scheduled collector's configuration. Existing pinned
SSH configuration is preserved, including its ban on port forwarding. API
requests execute on XOA against loopback. Metrics leave over verified HTTPS to
the existing Grafana Cloud Metrics endpoint using its supported Influx line
ingestion API. This creates no cloud stack, subscription, integration, storage
or paid resource.

Collect CPU utilization, RAM, load, uptime, physical network throughput and
selected storage capacity/I/O. Emit only allowlisted numeric measurements and
static host/environment/role labels, plus bounded interface/storage identifiers.
Reject stale/future source data, invalid values, payloads over 64 KiB, and more
than 128 series per run. One run per minute and an overlap lock bound ingestion.
Publish collection health and source freshness; write a private local status
file when cloud delivery fails. Raw API errors, credentials, VM/application
payloads and logs are never exported.

The dashboard has a freshness/collection health overview, CPU/RAM/load/uptime,
network and storage panels. It is a distinct Terraform-owned dashboard in the
existing Home lab monitoring folder. The existing guest dashboard remains
available. No notifications are activated without an existing contact point.

Private credentials/inventory, state and plans stay outside the checkout with
owner-only permissions. The deployment controller checks the actual unbilled
Grafana Trial/Free mode and the saved Terraform plan before apply, and repeats
the cloud check before Ansible mutates the collector. Only the exact dashboard
and local deployment record are allowed. Explicit `collector_enabled=false`
removes the scheduled job; destroying Terraform state does not uninstall it.

Completion requires live source statistics from datacenter1, a successful
scheduled upload, queried Cloud metrics with current timestamps, and the live
dashboard containing the deployed queries. XOA's current upgrade/SSH outage
may delay that final deployment, but does not change the target or acceptance.
