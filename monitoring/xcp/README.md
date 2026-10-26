# datacenter1 and VM resource monitoring

**Current VM rollout:** dashboard and configuration are prepared; the collector
update awaits XOA returning online after the owner's lab upgrade. See
[deployment status](DEPLOYMENT.md). VM series are not verified live yet.

This pipeline collects **XCP-ng host and selected VM** metrics through XOA. A scheduled Node
collector runs as the existing unprivileged `lab-automation` user on XOA. No
agent, package or service is installed in dom0. Ansible manages the collector
files, private config, viewer account and cron; `infra/xcp-monitoring` Terraform
owns the deployment record and both Grafana dashboards.

## Architecture and security

The collector uses XOA's existing loopback JSON-RPC API and installed `ws`
dependency. The pinned `xoa-management` SSH alias is used for deployment. Its
ban on port forwarding stays in place. Node, cron and flock must already exist;
the role stops if prerequisites are missing instead of changing appliance
packages. It rejects root, dom0 and an unexpected XOA hostname.

The account setup task uses administrator API credentials through hidden stdin
over SSH. It creates a dedicated user with global permission `none` and a single
`viewer` ACL on the existing pool. The scheduled job stores only that viewer
password and the Grafana metrics write token. Existing administrator or broader
ACL assignments fail closed; existing passwords are never overwritten. All
credential files/directories are owner-only (0600/0700). No raw API error,
credential, application payload or log is exported.

Metrics go over verified HTTPS to the existing Grafana Cloud Metrics instance.
The [supported direct Influx endpoint](https://grafana.com/docs/grafana-cloud/send-data/metrics/metrics-influxdb/push-from-telegraf/)
converts fields to Prometheus series; no Influx database or server is created.
Only allowlisted numeric CPU, RAM, load, uptime, physical NIC throughput and
selected SR capacity/I/O, plus selected VM resource metrics are sent. Host data
is capped at 128 series; each VM at 48, with up to 16 selected VMs. The combined
payload is capped at 1024 series and 64 KiB per run. One scheduled run per minute
means at most 1024 samples/minute from this collector. Monitor total
tenant usage in the existing Free usage dashboard as other collectors are added.

The live account check requires the approved unbilled Cloud Trial or verified
Free plan before plan, apply and host deployment. No paid fallback, retention
upgrade, cloud stack, infrastructure or subscription is provisioned. After Trial
automatically transitions to Free, verify the portal's Free status, update
`monitoring/fleet.json` to verified Free/live apply and set private
`xcp_metrics_free_plan_verified: true`. A changed/unverified plan stops apply.

## Private inputs

Keep JSON/token files outside the checkout in an owner-only directory. The
existing dashboard service token manages only Grafana metadata. A separate
Cloud Access Policy token with `metrics:write` sends metrics.

Inventory JSON:

```json
{"all":{"hosts":{"xoa_metrics":{"ansible_host":"xoa-management","ansible_user":"lab-automation","ansible_python_interpreter":"/usr/bin/python3"}}}}
```

Deployment JSON:

```json
{
  "xcp_collector_expected_hostname": "xoa",
  "xcp_admin_email": "EXISTING_PRIVATE_XOA_ADMIN_EMAIL",
  "xcp_admin_password": "EXISTING_PRIVATE_XOA_ADMIN_PASSWORD",
  "xcp_metrics_config": {
    "host_name": "datacenter1",
    "host_id": "VERIFIED_EXISTING_HOST_UUID",
    "pool_id": "VERIFIED_EXISTING_POOL_UUID",
    "storage_ids": ["VERIFIED_EXISTING_STORAGE_UUID"],
    "vm_targets": [{"name":"wazuh","id":"VERIFIED_LIVE_VM_UUID","expected_name":"Wazuh","environment":"homelab","role":"security"}],
    "excluded_vm_ids": ["VERIFIED_PARROT_UUID"],
    "xoa_email": "home-lab-xcp-metrics-UNIQUE@localhost",
    "xoa_password": "GENERATE_A_RANDOM_PASSWORD_OF_AT_LEAST_32_CHARACTERS",
    "metrics_url": "https://prometheus-YOUR_EXISTING_HOST.grafana.net/api/v1/push/influx/write",
    "metrics_username": "EXISTING_METRICS_INSTANCE_ID",
    "metrics_token": "PRIVATE_METRICS_WRITE_TOKEN"
  }
}
```

The single VM entry above illustrates the entry format; deployment requires all
13 entries in the exact order in [vm-targets.json](vm-targets.json). Do not copy
that abbreviated selection into a live deployment.

Select actual UUIDs from the private Xen inventory and verify through the live
API. Exclude ISO/udev passthrough SRs. The host UUID/name/pool must match and the
upload endpoint/username must match the existing Grafana datasource. Use a unique
reader email; the generated password remains private. For rotation, create a new
uniquely named reader, redeploy, verify it and revoke the old identity using the
XOA identity workflow. Administrator credentials are retained only in the
operator's private deployment file for future reconciliation.

## Deploy, redeploy and disable

The deployed Mac controller has durable owner-only inputs, state and its pinned
Python/Ansible runtime under `~/.config/home-lab/monitoring`. To use that setup:

```sh
source "$HOME/.config/home-lab/monitoring/xcp.env"
make monitoring-xcp-plan
make monitoring-xcp-up
make monitoring-xcp-status
```

Keep this private directory when moving/rebuilding the controller. The live
collector on XOA continues independently of the Mac. See the point-in-time
[deployment verification](DEPLOYMENT.md) for the installed scope and evidence.
For a new controller, build the pinned Ansible runtime using the dependency
instructions in the [main monitoring guide](../README.md), then restore the
private inputs/state and adjust these paths.

Export paths, never secret values in shell history:

```sh
export GRAFANA_URL=https://cordialbike2680.grafana.net
export MONITORING_GRAFANA_AUTH_FILE=/PRIVATE/PATH/dashboard-token
export XCP_METRICS_PRIVATE_INVENTORY=/PRIVATE/PATH/xcp-inventory.json
export XCP_METRICS_PRIVATE_VARS=/PRIVATE/PATH/xcp-deployment.json
export ANSIBLE_PLAYBOOK_BIN=/PRIVATE/PATH/ansible-venv/bin/ansible-playbook
export MONITORING_RUN_DIR=/PRIVATE/PATH/runtime
python3 scripts/monitoring/xcp.py plan
python3 scripts/monitoring/xcp.py apply
```

Review the actual printed plan. The controller accepts only the exact host
host/VM dashboards and datacenter1 deployment record; credentials never enter Terraform
values/state. Provider data, saved plans and state live under
`$MONITORING_RUN_DIR/xcp`. Preserve that state for redeployment.

Source changes rerun idempotent Ansible. For drift repair, credential rotation or
recovery after XOA rebuild, run `plan --redeploy` then `apply`. To stop collection,
run `plan --disabled` then `apply`; Ansible removes the cron entry and stored
collector credentials. The dashboard and XOA viewer remain. Destroying/deleting
Terraform state performs no remote uninstall; explicit disable is required.

## Reporting and verification

The dashboard is
`https://cordialbike2680.grafana.net/d/homelab-xcp-host`.
It shows collection health/source age, CPU, RAM, load, uptime, network and storage.
Missing/unsupported measurements stay absent. Source samples older than three
minutes or more than 30 seconds in the future are rejected; original source
timestamps are preserved. No stale metric is relabeled as a current observation.

Verify actual Cloud results and increasing timestamps across at least two
scheduled runs, rather than relying on one manual upload:

```promql
homelab_xcp_collector_success{host="datacenter1"}
time() - homelab_xcp_collector_source_timestamp_seconds{host="datacenter1"}
homelab_xcp_cpu_used_percent{host="datacenter1"}
homelab_xcp_memory_used_bytes{host="datacenter1"}
homelab_xcp_network_receive_bytes_per_second{host="datacenter1"}
homelab_xcp_storage_used_bytes{host="datacenter1"}
```

The job runs once per minute with `flock` overlap protection. Read installation
and delivery status with:

```sh
python3 scripts/monitoring/xcp.py status
ssh -o BatchMode=yes xoa-management crontab -l
```

`~/.config/home-lab-xcp-metrics/status.json` records attempt/source timestamps,
collection/delivery booleans, sample count, HTTP status and sanitized error code.
It contains no credentials or response bodies. Source failure sends health `0`
when Cloud delivery works. Upload failure can only be recorded locally; absence
of Cloud health data does not establish health. No email/webhook notification is
activated by this root. Wazuh detection events, guest filesystem usage and application telemetry need separate guest instrumentation.

If XOA is offline/upgrading, restore it through the existing infrastructure
workflow, then redeploy and verify scheduled data. If an update moves/removes
Node or XOA's `ws` dependency, review the runtime path in code and revalidate;
the role never installs replacements automatically. No durable sample queue or
historical replay is provided, so network/Cloud outages leave gaps.

Local checks:

```sh
node --test scripts/monitoring/tests/xcp_metrics.test.cjs scripts/monitoring/tests/xcp_runtime.test.cjs scripts/monitoring/tests/xcp_vms.test.cjs
python3 -m unittest discover -s scripts/monitoring/tests -p test_xcp.py
terraform -chdir=infra/xcp-monitoring fmt -check
```

## VM selection and collector setup

[Open VM resources](https://cordialbike2680.grafana.net/d/homelab-xcp-vms).
Use the **VM** selector to choose Wazuh or any included guest. The public
`vm-targets.json` policy covers every current inventory VM except `parrot_htb`.
The private deployment file maps these aliases to live UUIDs and expected names,
with role/environment labels from `monitoring/fleet.json`. The controller rejects
missing targets, unexpected labels, or a missing Parrot UUID denylist. Runtime
checks the actual UUID, name and pool before requesting `vm.stats`; it also rejects
Parrot names. Parrot has no Alloy component in the guest deployment policy.
New inventory VMs require an explicit reviewed policy and private mapping update;
collection never automatically enrolls an unknown guest.

There is **one collector on XOA**, shared with the hypervisor pipeline. No agents
are installed on these VMs, including Wazuh, Windows, TrueNAS and the firewall.
No guest SSH account or Tailscale installation is needed. For a rebuild:

1. Restore XOA access and the private controller directory described above.
2. Verify live VM identities through the XOA API using its viewer account. Match
   names against `ansible/inventory/host_vars/<alias>.yml`; fail on duplicate names.
3. In private `xcp_metrics_config.vm_targets`, provide all aliases in policy order,
   each with `name`, `id`, `expected_name`, `environment` and `role`. Preserve the
   verified current Parrot UUID(s) in `excluded_vm_ids`. Never select Parrot.
4. Keep the private deployment file mode 0600 in a mode-0700 directory. Run
   `make monitoring-xcp-plan MONITORING_ARGS=--redeploy`, inspect the exact two
   dashboard/local record plan, then `make monitoring-xcp-up`.
5. Check `make monitoring-xcp-status`: `collection_ok` and `delivery_ok` should be
   true, each running VM should have `stats_available: true`, and halted VMs
   should have no failure. Confirm increasing source timestamps in Grafana.

Running VMs export mean vCPU usage, assigned RAM, guest free/used RAM **only if
reported by guest tools**, uptime, virtual NIC bytes/sec, virtual disk bytes/sec
and IOPS. Disk capacity/allocation describes XOA VDI backing, **not filesystem
free/used space**. Guest load averages and Wazuh application/detection health are
not supplied by this API. Unsupported values remain absent.

Halted VMs export power state and statistics availability only. They are never
booted by monitoring, and their resource charts start automatically after boot.
The dashboard gates resource charts on running state and available statistics.
A VM source failure marks it unavailable and collector health unhealthy while
preserving healthy VM/host samples. Two bounded API workers and a deadline limit
collection work; `flock` prevents overlap. `status.json.vm_statuses` reports
per-VM sanitized outcomes, while `homelab_xcp_collector_vm_failures` exposes the
failure count in Cloud. No notifications are activated.

Useful live queries:

```promql
homelab_xcp_vm_power_state{host="datacenter1"}
homelab_xcp_vm_cpu_used_percent{vm="wazuh"}
homelab_xcp_vm_stats_available{vm="wazuh"}
time() - homelab_xcp_vm_source_timestamp_seconds{vm="wazuh"}
count({__name__=~"homelab_xcp_vm_.*", vm="parrot_htb"})
```

The last query must return no series. `power_state` values are running=1,
halted=0, paused=2, suspended=3, missing/unknown=-1. No resource zeros are invented
for stopped or unsupported guests. These series share the existing Free stack;
check total fleet usage through the existing usage dashboard as scope grows.
