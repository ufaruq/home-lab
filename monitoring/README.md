# Monitoring deployment and collector setup

This is the start-to-finish guide for the repository's monitoring stack. The
deployment entry point for guests/Wazuh is **Terraform in `infra/monitoring`**.
The XCP-ng hypervisor and its selected VMs (excluding Parrot) have a dedicated [agentless resource workflow](xcp/README.md)
through **Terraform in `infra/xcp-monitoring`**. Terraform
manages Grafana resources directly and runs the versioned Ansible roles to
configure Wazuh and collectors. No manual SSH provisioning commands are hidden
in a cloud dashboard.

The absolute cloud budget is **$0**. No Oracle resources, hosted subscriptions,
paid plugins, new Grafana stacks, or paid backends are provisioned here.

## 1. What is managed

| Configuration | Owner | Detailed guide |
| --- | --- | --- |
| Selected deployment targets and change fingerprints | Terraform composition root | [infra/monitoring](../infra/monitoring/README.md) |
| Grafana folder, dashboards and paused-by-default alerts | Grafana Terraform provider | [infra/grafana](../infra/grafana/README.md) |
| Linux/Windows metrics and log collectors | Terraform-invoked Alloy role | [Alloy setup](alloy/README.md) |
| datacenter1 hypervisor metrics | Terraform-invoked external XOA collector | [XCP host setup](xcp/README.md) |
| Docker application log forwarding definition | Versioned Compose logging overlay; explicitly deployed with the application's stack | [Alloy application logs](alloy/README.md), [overlay](alloy/examples/compose.logging.yaml) |
| Wazuh manager policy, agent groups, custom rules and retention | Terraform-invoked Wazuh roles | [Wazuh setup](wazuh/README.md) |
| Linux/Windows Wazuh agents and retained enrollment identities | Terraform-invoked agent role | [Wazuh agents](wazuh/README.md) |
| OPNsense's dedicated remote logging destination | Terraform-invoked native HTTPS API helper | [OPNsense setup](opnsense/README.md) |

The owner selected an **Oracle-hosted Wazuh server** to separate security records
from the monitored hypervisor. Start with the [Oracle Wazuh guide](../infra/oracle/wazuh/README.md).
The root is prepared but free ARM host capacity was unavailable at the last check.
No Oracle workload has been created by it. The captured local manager is retained
for recovery and is no longer the selected manager deployment target.

The fleet map is [fleet.json](fleet.json). It includes the existing 14 guest
definitions, `datacenter1`, and the explicit external `oracle_wazuh` target from
[inventory/oracle.yml](inventory/oracle.yml). Planned does not mean reachable, running, or
approved for deployment. The two diskless definitions are blocked. TrueNAS and
the hypervisor remain agentless. datacenter1 uses the dedicated XOA host-metrics
workflow above; TrueNAS/native appliance interfaces still need verification.
The code never installs an agent in dom0 or boots a guest.

The application overlay does not restore application data or reconstruct private
Compose projects. Keep each reviewed application definition in its existing
deployment workflow and merge the logging fragment there. Recreating a container
is an application deployment decision; this monitoring code does not do it
automatically. Unknown small devices can send approved syslog over a protected
path; native SNMP/exporter deployment depends on their actual model/capabilities.

## 2. Free plan and collection budgets

The live account reports **Cloud Trial**. Grafana says Trial use is never billed,
then the account automatically moves to its always-free plan ([billing terms](https://grafana.com/docs/grafana-cloud/platform/cost-management-and-billing/manage-invoices/understand-your-invoice/),
[Free plan](https://grafana.com/pricing/)). The controller can configure the
selected Alloy collectors during Trial after it rechecks the live edition. Wazuh
manager and OPNsense changes remain a separate deployment. This does not add a paid
subscription. Collection rates and quotas are service limits, not billing controls.

When the account finishes Trial and the portal reports Free, review and change
only these public facts in `fleet.json`:

```json
"observed_plan": "free",
"live_apply_enabled": true
```

Set `free_plan_verified=true` in private Terraform inputs after that check. The
Alloy role's private `monitoring_grafana_zero_cost_mode_verified` applies to both
Trial and Free; during Trial, the controller instead checks the live Cloud Trial
edition before each plan/apply. Never upgrade a subscription to make a failed
deploy work. Never add payment details for this project.

Current Free allowances are 10,000 active metric series, 50 GB/month logs, and
14-day cloud retention. Our operational targets are 7,000 series and 500 MB/day
total logs. Alloy has a smaller per-host sample limit and bounded line ingestion;
these are collection controls, not billing caps. Watch actual Cloud usage.
Shorter local retention does **not** reduce monthly hosted ingestion.

Wazuh starts with a narrowly scoped seven-day alert-index retention policy. Read
the Wazuh guide before explicitly enabling its application to existing indices:
aged alert indices can be deleted. Raw archive-all collection is not enabled.
Lab activity from Parrot and the malware-analysis VM has separate labels/policy.

## 3. Prepare the controller

Use a supported Python for Ansible (the existing controller setup uses Python
3.13), Terraform >=1.9, and the pinned Ansible dependencies:

```sh
python3.13 -m venv .venv-monitoring
.venv-monitoring/bin/pip install -r ansible/requirements.txt
export ANSIBLE_PLAYBOOK_BIN="$PWD/.venv-monitoring/bin/ansible-playbook"
export ANSIBLE_INVENTORY_BIN="$PWD/.venv-monitoring/bin/ansible-inventory"
export ANSIBLE_COLLECTIONS_PATH="$PWD/.local/monitoring/collections"
.venv-monitoring/bin/ansible-galaxy collection install \
  -r ansible/monitoring-requirements.yml -p "$ANSIBLE_COLLECTIONS_PATH"
```

The Windows collection is pinned. No extra software is installed in XCP-ng's
control domain. `.venv-monitoring` must remain out of Git. On this Mac, the
already-existing private controller at `/private/tmp/xen-ansible-venv313` can be
used for validation; it is temporary and is not a durable deployment dependency.

```sh
make monitoring-inventory
make monitoring-check PYTHON=.venv-monitoring/bin/python
make monitoring-syntax
```

Syntax/test commands do not contact the fleet. Native Alloy validation tests use
`ALLOY_BINARY` when an official, checksum-verified validator is available; see the
Alloy guide. Terraform mock checks require `terraform init` to download providers
but do not need hosted credentials and do not create cloud resources.

## 4. Create private inputs outside the repository

```sh
umask 077
export MONITORING_PRIVATE_DIR="$HOME/.config/home-lab-monitoring"
mkdir -p "$MONITORING_PRIVATE_DIR"
chmod 700 "$MONITORING_PRIVATE_DIR"
cp monitoring/examples/private-inventory.json.example "$MONITORING_PRIVATE_DIR/inventory.json"
cp monitoring/examples/deployment.json.example "$MONITORING_PRIVATE_DIR/deployment.json"
cp infra/monitoring/inputs.tfvars.json.example "$MONITORING_PRIVATE_DIR/terraform.json"
chmod 600 "$MONITORING_PRIVATE_DIR"/*.json
export MONITORING_PRIVATE_INVENTORY="$MONITORING_PRIVATE_DIR/inventory.json"
export MONITORING_PRIVATE_VARS="$MONITORING_PRIVATE_DIR/deployment.json"
```

Replace all `REPLACE_...` entries with verified current values. Do not copy cached
guest addresses from snapshots without checking them. Keep this directory and
its backups encrypted and private. JSON is used so the controller can validate
inputs without loading arbitrary YAML tags or requiring a secrets library.

Private inventory contains actual addresses/logins, per-host version declarations
and any SSH/WinRM authentication configuration. Use SSH keys/agent or private
secret storage for Linux; Windows management uses HTTPS WinRM with certificate
verification. Do not disable host-key checks or trust self-signed certificates
without installing the correct CA. Linux deployment needs reviewed sudo/root
privileges; the running Alloy service itself is unprivileged.

Both `monitoring_access_verified` and `monitoring_deployment_approved` start false.
Set them to actual JSON booleans `true` only after checking the selected hosts and
reviewing the proposed monitoring configuration. String `"true"` is rejected.
Fresh software installation, Wazuh response-policy edits, retention changes and
firewall forwarding have additional separate approval flags described below.

## 5. Configure Grafana credentials and connection details

There are two different credentials:

1. A **Grafana service-account token** for Terraform to manage this stack's
   dashboards/alerts. Give it the permissions required for those resources; do
   not use an organization/billing administrator credential.
2. A **Grafana Cloud access-policy token** scoped to metrics write and logs write
   for Alloy ingestion. This does not need dashboard-edit or billing access.

For this repository's combined Alloy client, create one stack-scoped access
policy named `home-lab-alloy-write` with only the `metrics:write` and `logs:write`
scopes, then create a token. Grafana requires the Cloud Portal Admin role to
generate these write credentials ([official steps](https://grafana.com/docs/grafana-cloud/platform/security-and-account-management/security-and-access/authentication-and-permissions/access-policies/manage-cloud-data-source-credentials/)).
The token is shown once. Add it to the private `monitoring_grafana_write_token`
field in `deployment.json`; never put it in Terraform vars or chat. The service
account token in `grafanakey` manages dashboards and cannot ingest telemetry.

Create/rotate credentials directly with Grafana. Never paste them into chat,
repository files, Terraform variable files, shell command literals or examples.
An owner-only file can supply the management token without retaining it in shell
history:

```sh
read -r -s GRAFANA_AUTH
printf '%s' "$GRAFANA_AUTH" > "$MONITORING_PRIVATE_DIR/grafana-auth"
chmod 600 "$MONITORING_PRIVATE_DIR/grafana-auth"
unset GRAFANA_AUTH
export MONITORING_GRAFANA_AUTH_FILE="$MONITORING_PRIVATE_DIR/grafana-auth"
export GRAFANA_URL="https://cordialbike2680.grafana.net"
make monitoring-info
```

`monitoring-info` is read-only and prints only data-source UID/name/type, never
secure settings. It can be used during Trial. Copy the existing Prometheus and
Loki UIDs into `terraform.json`; do not provision replacement paid backends.

From Grafana's Metrics and Logs connection instructions, copy each ingestion URL
and instance username into `deployment.json`, along with the separate write-only
token. Do not derive ingestion URLs from the dashboard hostname. They normally
use separate regional `*.grafana.net` endpoints. The role requires HTTPS and
does not allow disabling certificate verification.

Choose an **existing contact point** for alerts and test its delivery manually to
your own destination. This code does not create recipients or take over global
notification routes. Keep `alerts_enabled=false` until collectors and expected
hosts are verified. Include only intentionally online hosts in expected-host
sets; otherwise a deliberately halted lab VM will produce an outage alert.

## 6. Set up collectors and Wazuh

First establish `oracle_wazuh` through the [Oracle root](../infra/oracle/wazuh/README.md),
verified private access and a deliberate 4.7.x-to-4.14.9 agent migration. Then use
one Linux pilot, followed by Windows and OPNsense. Keep deployment selections small.

- **Wazuh manager:** the selected `oracle_wazuh` target uses explicitly approved
  fresh 4.14.9 ARM installation. Use its separate private manager example, reviewed
  checksum and small-ARM approval. Do not reuse the old adoption variables for this
  new server. The local 4.7.5 installation and identities remain intact. The generic
  role still defaults to adoption; the Oracle inventory explicitly selects fresh
  without inventing authorization. The [Wazuh guide](wazuh/README.md) covers backups
  and historical adoption behavior.
- **Linux collector:** set the verified manager address and the host's exact
  installed agent version in private inputs. Maps was captured with 4.7.4, while
  some other endpoints had 4.7.5. Do not apply one guessed version to every host.
  Allow a missing agent/Alloy install only with its explicit installation flag.
- **Windows collector:** verify WinRM HTTPS/login/CA and follow the Windows
  instructions in [Alloy](alloy/README.md) and [Wazuh](wazuh/README.md). Installer
  hashes are mandatory where packages are downloaded. Keep credentials out of
  PowerShell command literals and WinRM debug output.
- **Application logs:** Alloy starts with conservative file/channel selection.
  Follow [the application logging setup](alloy/README.md) to enable the bounded
  loopback Docker syslog receiver and merge the versioned Compose fragment into
  reviewed application stacks. This needs no Docker socket or Docker-group access.
- **OPNsense:** first establish the encrypted logging path, then provide verified
  API TLS credentials and the dedicated destination. Native Wazuh syslog is
  plaintext; it is blocked unless an encrypted VPN path is explicitly verified.
  TLS forwarding requires an actual pre-existing TLS syslog relay and its trust
  configuration. A private LAN address alone is not encryption. See
  [OPNsense setup](opnsense/README.md).
- **TrueNAS/extra devices:** keep native syslog/SNMP/exporter configuration scoped
  to the actual appliance version. They are not ordinary Linux agent targets.
  Verify capabilities and declare their collection configuration before adding
  them to a rollout. Dom0 is always agentless.

New Wazuh enrollment needs CA-verified TLS. Adopted `client.keys` and certificate
files are preserved; that preservation does not prove their historical trust
setup is correct. Audit it before use. Lab endpoints must have local active
response disabled or explicitly approve the narrow local change. Central group
configuration alone cannot disable the local response process.

## 7. Plan and deploy through Terraform

For the current Trial, deploy Alloy collectors only after the private write token,
host addresses/logins, trusted SSH/WinRM transport and exact selection are ready.
The controller verifies the live Cloud Trial edition. Wazuh manager and OPNsense
changes remain separate. After Trial transitions to Free, update the manifest and
Terraform Free verification values as above.

```sh
make monitoring-plan MONITORING_ARGS="--vars $MONITORING_PRIVATE_DIR/terraform.json"
```

The controller downloads the pinned provider, creates an owner-only saved plan
outside the checkout, checks its resource types/actions, and records hashes of
the plan, public configuration and private Terraform inputs. Inspect the plan
and private log paths printed by the command. Only the existing-stack folder,
dashboards, alert groups and the exact built-in fleet orchestration resource are
allowed. No hosted subscription, VM, network, paid integration or access grant
is allowed by the plan guard.

```sh
make monitoring-up MONITORING_ARGS="--vars $MONITORING_PRIVATE_DIR/terraform.json"
```

Terraform applies the saved plan. Its creation-only fleet provisioner validates
every selected host's declared access first, then invokes manager, OPNsense and
collector plays in order. Plays are serial and stop on failure. Runtime failures
can leave an earlier target configured; this is not a transactional deployment.
Roles are designed for safe reruns, with staged config validation and rollback
where configuration is replaced. Always inspect a failed private log and verify
service state before repeating a deployment.

Saved reviews expire after 24 hours and are invalid if public configuration or
Terraform inputs change. Regenerate and inspect the plan after any change. Keep
the native `terraform apply` command for trusted local operations only; the
guarded Make workflow is the recommended path. Never apply an unreviewed plan.

## 8. Verify real operation

Before enabling Grafana alerts, check all of the following on the actual hosts:

- Alloy service is running and its loopback readiness endpoint is healthy.
- Grafana Explore shows `up{job="homelab",host="<inventory_name>"}` and the expected
  Linux/Windows metrics. Verify one selected log message, correct labels and
  timestamp. A green service does not prove successful remote writes.
- Wazuh reports the agent connected and its intended group configuration synced.
  Generate a harmless test event and confirm it reaches the correct manager.
- OPNsense sends a harmless test log over the verified encrypted path and the
  receiver parses it correctly. Do not assume successful API configuration proves
  encrypted delivery or correct decoding.
- Expected-host alerts cover each intentionally online host individually. Test
  loss of telemetry and recovery notifications without turning off the whole lab.
- Actual Cloud ingestion stays comfortably below the permanent Free allowance.

Only after those checks set `alerts_enabled=true`, choose the existing contact
point and apply another reviewed Terraform plan. End-to-end delivery is not
claimed by local syntax tests or Terraform mocks.

## 9. Redeploy, rotate and recover

Public role/template/dashboard changes are fingerprinted by Terraform. They
cause the selected fleet's idempotent configuration to run again. Credentials
and private deployment inputs are intentionally absent from Terraform state and
the public change fingerprint. After rotating a telemetry token or changing a
private collector option, explicitly re-converge:

```sh
make monitoring-plan MONITORING_ARGS="--vars $MONITORING_PRIVATE_DIR/terraform.json --replace-fleet"
make monitoring-up MONITORING_ARGS="--vars $MONITORING_PRIVATE_DIR/terraform.json"
```

The replacement is only Terraform's local orchestration record. There is no
destroy provisioner and no automatic uninstall. Terraform does not natively
observe arbitrary guest drift through that record; deliberate re-convergence
and live verification are necessary. Preserve Alloy's data/positions directory
to avoid replaying logs. Never delete it merely to restart a collector.

Back up Terraform state privately, existing Wazuh identities/certificates and any
data you need to retain. Restoring public policy is not restoring indexed logs,
Docker volumes, enrollment keys or private application databases. A fresh Wazuh
server rebuild needs the deliberate identity/backup plan in its guide. Existing
4.7.5 upgrades remain a separate reviewed migration, not a side effect of rollout.

## 10. Connection and credential security

For the network exposure policy, per-service source restrictions, remote access
and DDoS limitations, read [Private access and network security](network/README.md).
These network controls require separate verification; this stack currently
configures neither a VPN nor firewall/NAT rules.

- Grafana uses CA-validated HTTPS and scoped tokens. Public collector management
  ports are not opened. The deployment controller will not follow authentication
  redirects or disable transport checks.
- Alloy runs unprivileged on Linux, with a protected token file; Windows token
  ACLs restrict access to SYSTEM/Administrators. Local application syslog listens
  on loopback only. Redaction is conservative and cannot guarantee every secret
  is recognized; select sources deliberately.
- Wazuh uses its native encrypted agent transport with retained per-agent keys;
  fresh enrollment verifies the manager CA over TLS. Indexer management and
  OPNsense APIs verify HTTPS certificates, including private CAs where needed.
- Native device syslog is not assumed encrypted. Use an actually verified VPN
  transport or TLS relay before enabling it. The code does not create that VPN
  or make the existing recovery network magically trusted.
- The controller refuses world/group-readable private inputs, implicit targets,
  unverified access, paid plan states, unsafe plan resource types and certificate
  verification bypasses. These are safeguards, not proof that an uninspected
  machine or pre-existing network is secure.

The dashboards are live, but no host telemetry is arriving yet. The remaining
collector inputs are the Grafana Cloud write token and verified private host
addresses/logins. Wazuh remains dependent on an available $0 Oracle host and its
private access. OPNsense forwarding still needs a private VPN path or TLS relay.

Official references: [Grafana billing/trial FAQ](https://grafana.com/docs/grafana-cloud/platform/cost-management-and-billing/manage-invoices/understand-your-invoice/),
[Grafana Free limits](https://grafana.com/pricing/),
[Alloy documentation](https://grafana.com/docs/alloy/latest/),
[Wazuh centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html),
[OPNsense API](https://docs.opnsense.org/development/api/core/syslog.html),
[XCP-ng external metrics](https://docs.xcp-ng.org/management/monitoring/).
