# Terraform-managed monitoring deployment

`infra/monitoring` is the primary entrypoint for Grafana configuration, Alloy
collectors, Wazuh manager/agents and OPNsense syslog. Terraform calls the versioned
deployment controller, which runs the repository's Ansible playbooks against exact
selected inventory names. The existing Oracle/Xen provisioning roots are separate;
this root creates no VM, disk, network, paid backend or Grafana subscription.

**The observed Grafana stack is Cloud Trial. Grafana states Trial usage is never
billed and that the account automatically moves to its always-free $0 plan**
([official billing terms](https://grafana.com/docs/grafana-cloud/platform/cost-management-and-billing/manage-invoices/understand-your-invoice/),
[Free plan](https://grafana.com/pricing/)). Terraform may therefore deploy the
folder and dashboards and the selected Alloy collectors now. The controller checks
the live Cloud Trial edition before both plan and apply. The Trial path permits
only Alloy collectors; Wazuh manager and OPNsense mutation stay disabled. The
remaining inputs are the actual write token and verified host access. Alerts remain
disabled. No billing settings or paid subscriptions are changed.

`unbilled_trial_collection_verified=true` is the private declaration for this
zero-cost Trial mode; `trial_collector_apply_enabled=true` in `monitoring/fleet.json`
allows the exact collector-only path. This records Grafana's published terms and
the deployment choice; it is not a usage budget or billing control. Keep collection
within the Free plan's limits and never enable a paid plan.

## What Terraform owns

| Address | Effect |
| --- | --- |
| `module.grafana.grafana_folder.homelab` | Owns the Home lab monitoring folder in the existing stack; deletion is protected. |
| `module.grafana.grafana_dashboard.homelab[...]` | Applies sourced fleet and optional security/usage dashboards to that folder. |
| `module.grafana.grafana_rule_group.fleet[0]` | Applies paused-by-default host-health rules when an expected-host set is nonempty. |
| `terraform_data.fleet[0]` | On creation/replacement, calls the safe controller once with explicit public host selections. Exists only for nonempty deployment selection. |

The Grafana child module is static and authenticates from the environment. Only the
Grafana provider and Terraform's built-in `terraform_data` resource are needed.
There are no cloud-account, billing, subscription, datasource, contact-point,
notification-tree, SSH-provider or generic remote-exec resources.

The `terraform_data` creation provisioner runs the reviewed command
`python3 scripts/monitoring/manage.py deploy-fleet` with the selected names. The
controller validates **all selected groups before any guest mutation**, then
configures manager, OPNsense and collectors in that order. Ansible limits each
operation to the explicit inventory names. It does not automatically boot a VM,
replace a disk, recover captured secret archives or install software in dom0.

The public source/selection digest causes replacement when relevant versioned
roles, playbooks, Wazuh/OPNsense policies, controller Python or `fleet.json` change.
Replacement reruns idempotent configuration. **There is no destroy provisioner:**
removing targets or Terraform state does not uninstall agents, stop services or
remove guest configuration. Decommissioning is a separate explicit operation.

Terraform does not read remote guest configuration during refresh and cannot
detect arbitrary drift in Alloy, Wazuh or OPNsense. A successful previous apply
does not prove current reachability, retention execution, collector ingestion,
dashboard query results or alert delivery. Grafana resources have their provider's
normal read/plan behavior; guest configuration has the explicit re-convergence
workflow below.

## Prerequisites and private files

Use Terraform 1.9 or newer, Python 3, Ansible and the documented collections/tools.
Run from a trusted local operator machine with verified SSH host keys, Windows
WinRM TLS verification and OPNsense HTTPS verification. See
[`monitoring/README.md`](../../monitoring/README.md),
[`monitoring/alloy/README.md`](../../monitoring/alloy/README.md),
[`monitoring/wazuh/README.md`](../../monitoring/wazuh/README.md) and
[`monitoring/opnsense/README.md`](../../monitoring/opnsense/README.md) for private
role settings, pinned package versions and deployment modes.

Keep these outside the checkout, owned by the operator, mode 0400 or 0600:

- A private inventory override with real reachable addresses, logins and trusted
  transport settings. Preserve the captured inventory/host_vars in this repository.
- Private Ansible JSON variables, containing explicitly reviewed access/deployment
  flags and the component-specific credentials/settings.
- Terraform JSON variables copied from `inputs.tfvars.json.example`. The HCL
  `terraform.tfvars.example` is an alternative reference; the controller's `--vars`
  interface reads JSON.

The controller rejects private files inside this checkout and unsafe permissions.
Set a private mode-0700 `MONITORING_RUN_DIR` outside the checkout for logs and saved
plans. Terraform state remains local by default at the Git-ignored
`infra/monitoring/terraform.tfstate` (and adjacent backup); the controller does not
relocate it. Protect state files with owner-only permissions and retain owner-only
backups outside the checkout. `TF_DATA_DIR` relocates working data, not state.
Never copy state, saved plans, logs, real tfvars or credential-bearing generated
files into Git; plans/state contain operational metadata even when no password is
supplied as a Terraform input. Grafana authentication and collector ingestion
tokens stay external and are not resource-state inputs.

Supply environment variables through your private credential manager:

| Variable | Purpose |
| --- | --- |
| `GRAFANA_URL` | Exactly `https://cordialbike2680.grafana.net`; the controller rejects another stack. |
| `GRAFANA_AUTH` | Existing stack service-account token with only required folder/dashboard/alert permissions. |
| `MONITORING_GRAFANA_AUTH_FILE` | Alternative to `GRAFANA_AUTH`: owner-only token file outside the checkout; its contents are read privately. |
| `MONITORING_PRIVATE_INVENTORY` | Absolute path to the owner-only private inventory override inherited by the creation provisioner. |
| `MONITORING_PRIVATE_VARS` | Absolute path to owner-only Ansible JSON variables inherited by the creation provisioner. |
| `MONITORING_RUN_DIR` | Owner-only directory outside the checkout for controller runtime artifacts. |

No Terraform variable reads private paths or file contents. The provisioner receives
only its public controller path and selection through Terraform's environment map;
private path variables and Grafana authentication are inherited at execution time.
Secrets never become `terraform_data.input`, replacement triggers or outputs. Do
not set provider debug logs or include secrets in command arguments.

## Select hosts and expected telemetry

All target sets default empty. Do not select the entire inventory as a shortcut.
Select only reachable, reviewed hosts intended for this operation:

| Input | Allowed selection |
| --- | --- |
| `collector_targets` | Planned Linux/Windows `alloy` members in `monitoring/fleet.json`. Unknown, blocked, agentless, appliance and XCP-ng/dom0 hosts fail before deployment. |
| `wazuh_manager_targets` | Empty or `["oracle_wazuh"]`, after the separate Oracle root and private access are verified. The captured local manager is preserved. |
| `opnsense_targets` | Empty or `["firewall"]`, with compatible OPNsense manifest membership and independently verified native API. |
| `deployment_reviewed` | Must be true for nonempty selection after reviewing exact names and private component settings. It cannot bypass controller or role checks. |

The selected manager target is now `oracle_wazuh`; see the separate
[Oracle root](../oracle/wazuh/README.md). Its explicit fresh mode and ARM small-lab
approval do not authorize migration of captured local identities or agents.
The generic role defaults to adoption, while the Oracle inventory selects fresh.
Review backups and operational
impact first. Collector selection handles the corresponding endpoint agent policy;
it is not a fleet power-management or OS-upgrade command.

`expected_linux_hosts` and `expected_windows_hosts` are the separate alerting
expectation. Include deployed collectors that should currently be online, including
already deployed hosts omitted from this particular convergence. Exclude halted
guests and all undeployed or diskless definitions. Presence is checked separately
for every name so one missing host is caught while the remainder is healthy.

Grafana requires the existing `prometheus_datasource_uid` and `loki_datasource_uid`.
`usage_datasource_uid` is optional. Leave `enable_security_dashboard=false`: the
current collectors intentionally reject Wazuh `alerts.json`, and the reserved
security view requires a separately implemented and reviewed export. Enabling the
dashboard alone does not configure that export or expand log access. Start with
`alerts_enabled=false`; verify actual query results and the owner's existing
contact point before activating notifications. Active alerts require
`existing_contact_point_name`; no recipient or delivery secret is stored here.
See [`infra/grafana/README.md`](../grafana/README.md) for queries, latency, supported
metrics and the distinction between usage targets and billing protection.

## Validate, review and deploy

Offline checks need no live Grafana or host credentials and execute no provisioner:

```sh
python3 scripts/monitoring/manage.py validate
terraform -chdir=infra/monitoring init -backend=false
terraform -chdir=infra/monitoring fmt -check -recursive
terraform -chdir=infra/monitoring validate
terraform -chdir=infra/monitoring test
terraform -chdir=infra/grafana test
```

`init` downloads the pinned provider. Some local sandboxes require approval for
provider Unix sockets during validation/tests. The tests use mocked Grafana and
plan-only runs; they do not establish live connectivity or Free-plan eligibility.
The tests include the Trial path and still require private explicit verification;
they do not make any hosted changes.

Populate the owner-only private Terraform JSON inputs, export the private
environment above and use the guarded saved-plan flow. For this Trial, set
`free_plan_verified=false`, `unbilled_trial_collection_verified=true`, the selected
Alloy `collector_targets`, and leave Wazuh manager/OPNsense targets, alerts and
security dashboard disabled. Mark `deployment_reviewed=true` only after reviewing
the exact private inventory and collector settings. The controller fetches and
checks the live Trial edition before plan/apply. Read existing source UIDs with
`python3 scripts/monitoring/manage.py grafana-info` using the same private
credentials. The `stack-plan` and `stack-apply` commands target this root:

```sh
python3 scripts/monitoring/manage.py stack-plan --vars /absolute/private/monitoring.tfvars.json
python3 scripts/monitoring/manage.py stack-apply --vars /absolute/private/monitoring.tfvars.json
```

Read the generated plan and exact selected targets before applying. Use the
controller's retained private log path when an operation fails. Do not bypass a
failed gate with direct Terraform apply, generic shell hooks, insecure transport,
unrestricted inventory limits or broader provider permissions.

The saved-plan resource guard permits Grafana folder/dashboard/rule-group
create/update/no-op actions under `module.grafana` only; cloud-resource deletions
or replacements are rejected. The one approved built-in address is
`terraform_data.fleet[0]`: its replacement reruns host configuration and does not
delete cloud or guest resources. No other provider/resource/address is a deployment
extension point. A `terraform_data` deletion simply removes bookkeeping and does
not uninstall anything. Changed configuration/private inputs invalidate old plan
reviews; generate and inspect a new plan rather than reusing a stale one.

## Re-convergence, token rotation and recovery

Private file changes and guest-side drift do not affect the public replacement
digest. For deliberate re-convergence or private-token rotation, keep the exact
desired selection, update private inputs through the credential manager and create
a fresh reviewed plan with:

```sh
python3 scripts/monitoring/manage.py stack-plan --replace-fleet --vars /absolute/private/monitoring.tfvars.json
python3 scripts/monitoring/manage.py stack-apply --vars /absolute/private/monitoring.tfvars.json
```

The controller adds Terraform's exact `-replace='terraform_data.fleet[0]'` flag
and keeps the operation within the saved-plan review/guard workflow. Inspect the
replacement plan before `stack-apply`. No automatic token rotation is inferred
from a private-file timestamp. The secondary `grafana-plan`/`grafana-apply` commands
target only the original child root and are not the composed deployment workflow.

If an Ansible stage fails, Terraform reports failure and leaves the resource
unconverged/tainted; inspect its private stage log, resolve the issue, then review a
new plan and rerun. Earlier idempotent stages may already have completed; the
controller's preflight reduces avoidable partial deployment but cannot make
multiple remote services transactional. No success claim should replace readback
of the affected guest service and Grafana telemetry.

Do not independently apply `infra/grafana` against the same objects with separate
state after adopting this composition. For an earlier standalone Grafana state,
back up state privately and review a Terraform state-move/import migration to the
`module.grafana.*` addresses before any apply; otherwise Terraform may propose
creating colliding UIDs. The child root remains useful for focused offline tests.
The protected folder prevents accidental destruction; decommissioning or migration
requires an explicit reviewed state/resource plan.
