# datacenter1 deployment verification

Verified **2026-10-26 20:12:19 UTC**. This records observed deployment evidence at that time;
future upgrades/outages can change runtime status.

[Open the live host dashboard](https://cordialbike2680.grafana.net/d/homelab-xcp-host).

## Deployed scope

- The XCP-ng hypervisor **datacenter1** is monitored through XOA's live API.
- Terraform owns the dashboard and external collector deployment record.
  Ansible installs the collector/configuration/cron as the existing unprivileged
  XOA account. No dom0 package, agent, power or network change was made.
- The dashboard has 13 panels, including one explanation panel. All 15 actual
  metric expressions returned successful, populated results through Grafana's
  existing Prometheus datasource. CPU, RAM, load, uptime, two physical NICs and
  three storage repositories returned real values.
- The collector sent **33 series** with HTTPS **204** delivery success. Cron is
  active with one once-per-minute entry and overlap protection. Range readback
  returned **11 distinct source timestamps** across the observed window, and
  subsequent cron status confirmed continuing collection/delivery success.
- Source age was within the three-minute freshness bound. Stale or missing
  source data is never represented as a fresh successful observation.

## Security and cost evidence

- The dedicated XOA collector user has global permission `none`, exactly one
  `viewer` ACL on the existing pool and no group memberships. Scheduled
  collection refuses administrator credentials.
- The remote configuration is mode 0600 in a mode-0700 directory. Pinned SSH,
  the SSH key's no-forwarding restriction and verified HTTPS remain enforced.
  Only a viewer password and Cloud write token are stored on the collector.
- Actual Terraform plans contained only the host dashboard and local deployment
  record. The live unbilled Grafana Cloud Trial was checked before plan, apply
  and Ansible deployment. No paid resource/subscription/stack/datasource or
  Oracle resource was created. The collector caps itself at 128 series/run,
  64 KiB/run and one scheduled run/minute.
- Source and Terraform state/plan checks found no credential values in public
  sources or Terraform values. Private inputs/state/token files are mode 0600.

## Reproducibility and reporting

- 13 collector tests and three saved-plan guard tests passed. Terraform
  validation/formatting and Ansible syntax checks passed.
- An explicit re-convergence completed with **Ansible changed=0, failed=0**.
  The final Terraform plan from the durable private backend showed **no-op** for
  both managed resources.
- Private state, inputs and a pinned Python 3.13.17 / Ansible 2.21.5 controller
  are preserved under `~/.config/home-lab/monitoring`, outside Git. The relocated
  runtime passed syntax validation and the copied state produced no changes.
- Use `source "$HOME/.config/home-lab/monitoring/xcp.env"`, then the
  `monitoring-xcp-plan`, `monitoring-xcp-up` and `monitoring-xcp-status` Make
  targets. See [the full setup/recovery guide](README.md).
- Health and freshness are reported in Grafana; sanitized collection/upload
  status is retained on XOA in `~/.config/home-lab-xcp-metrics/status.json`.
  Email/webhook notifications are not activated. Wazuh security events and
  guest/Maps collection remain separate deployment work.

## VM extension status — 2026-10-26

The Terraform-managed [VM dashboard](https://cordialbike2680.grafana.net/d/homelab-xcp-vms)
was created in the existing folder. All 15 actual Prometheus expressions were
accepted by the live datasource; none returned VM series yet. **The VM collector
update is pending**, so the older host-only verification above does not establish
VM collection success.

The reviewed plan contained only: host dashboard no-op, VM dashboard create,
and local collector deployment record replacement. Ansible could not reach XOA
at its initial fact-gathering task, before changing any remote files. XOA was
offline in Tailscale; its recorded LAN address and the hypervisor's direct
management address also timed out. The owner confirmed the lab was offline or
upgrading. No guest was started and no networking/security setting was changed.

Public policy and the private configuration select 13 VMs, including local
Wazuh, with Parrot explicitly excluded. At the last live inventory capture,
four included guests were running and nine halted. Those counts are historical,
not current runtime assertions. The private deployment file was backed up before
adding the verified UUID/name mappings and remains mode 0600.

23 Node collector tests, 23 Python controller/policy tests, the existing guest
role tests (with seven environment-dependent skips), Terraform validation/fmt
and Ansible syntax passed using the pinned controller runtime. VM selection,
Parrot denylisting, missing guest RAM, stale samples, cardinality limits and
partial source failure are covered. The combined collector cap is now 1024
series and 64 KiB per run, with one scheduled run per minute. No billable cloud
resource was provisioned.

Once the lab is online, resume from the durable state (do not reuse the already
applied plan):

```sh
source "$HOME/.config/home-lab/monitoring/xcp.env"
make monitoring-xcp-plan
make monitoring-xcp-up
make monitoring-xcp-status
```

The failed provisioner leaves the local Terraform deployment record marked for
replacement; a fresh plan retries its idempotent Ansible work. The dashboard
already exists and should remain a no-op. Confirm per-VM status, Cloud delivery,
all selected power states, absence of Parrot series and increasing resource
source timestamps across at least two scheduled runs before declaring VM
collection operational. Powered-off guests need not be started for monitoring.

## Connection recovery and live VM verification — 2026-11-01 20:03:14 UTC

The connection and VM collection are operational as of this check, superseding
the pending rollout status above. XOA is reachable through its existing pinned
Tailscale SSH alias. Its original hypervisor entry had a stale management
address; the other entry initially returned an authentication failure. The
existing `xoaclient` entry became connected while diagnostics were running.
No password reset or credential replacement was performed by this repair.

Trusted recovery SSH verified datacenter1's host/pool UUIDs, current management
address and public TLS certificate fingerprint. The Terraform-invoked Ansible
role preserved the recovered working connection and disabled only the explicitly
declared stale failed entry. No saved entry was deleted and no VM or host network
setting was changed. The optional `reconcile-host.cjs` helper checks the independent
certificate pin before any repair and verifies the host name/UUID and pool.
Its deployment-only admin input remains hidden; scheduled collection still uses
the dedicated viewer. Existing XOA host TLS settings are preserved; the repair
probe does not add ongoing certificate pinning to XOA's own host client.

Live evidence:

- Both dashboards' **30 metric expressions** returned populated results.
- Exactly **13 selected VM power-state series** were present; Parrot had **zero**
  VM metric series. Wazuh, Portainer, TrueNAS and XOA supplied CPU/resource data;
  nine halted guests supplied power/statistics-availability status only.
- The collector reported **130 samples**, successful collection and HTTPS **204**
  delivery. Grafana returned **130 active collector series**, below the local
  1024-series cap. Cron was active with one once-per-minute entry and the private
  remote configuration was mode 0600.
- Wazuh range readback contained **11 distinct source timestamps** in the checked
  ten-minute window. Latest status was fresh, all selected VM outcomes had no
  failure, and every running selected VM had available statistics.
- The final guarded Terraform plan showed **no-op** for both dashboards and the
  local collector deployment record. No new cloud infrastructure or paid
  subscription was created, and no guest was started for monitoring.
- Nine synthetic connection-repair tests cover preserved credentials/settings,
  no-op reconciliation, pin mismatch, wrong identity, rollback, strict ownership,
  stale-entry cleanup and preserving a healthy primary on cleanup failure.

[Open VM metrics](https://cordialbike2680.grafana.net/d/homelab-xcp-vms).
Actual addresses, server/host/pool UUIDs, certificate pins, credentials and detailed
verification reports remain in private owner-only controller files outside Git.
