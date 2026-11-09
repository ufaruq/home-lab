# Existing local Wazuh deployment

This Terraform root configures an **existing** Wazuh VM through Ansible. It
creates one built-in `terraform_data.logging` resource and no cloud instances,
networking, volumes, subscriptions, public DNS, or paid service. Oracle and
Grafana billing are independent of this local deployment. The repository's
absolute $0 policy still applies, including Tailscale's current Free allowances.
Do not use promotional credits as evidence of free eligibility.

The supported adoption target is Ubuntu 24.04 with manager, indexer and dashboard
already installed at `4.7.5-1`. There is no reinstall or automatic upgrade. Plan a
separate reviewed upgrade for this older release. All changes flow through
[`wazuh_logging.py`](../../scripts/monitoring/wazuh_logging.py), Terraform's
saved plan, and [`wazuh-logging.yml`](../../ansible/playbooks/wazuh-logging.yml).
The controller rejects cloud providers, extra resources, destruction, altered
targets, failed checks and changed private inputs between plan and apply.

## What gets configured

- Manager rules, decoders and agent groups come from `monitoring/wazuh/`.
  Unrelated manager configuration and existing agent identities are retained.
- Alert indices matching only `wazuh-alerts-4.x-*` get the seven-day ISM policy.
  Existing alert indices with another policy require separate review. The
  manager authenticates locally with its existing indexer admin certificate;
  the key stays on the manager, and indexer TLS verifies `127.0.0.1`.
- Internal logs rotate, and approved cleanup removes only old generated
  compressed alert archives. See [storage details](../../monitoring/wazuh/STORAGE.md).
  Retention is **not a hard disk quota**; monitor usage and ingestion rate.
- The separate explicit `truenas` phase configures the owned appliance's native
  mutual TLS syslog path through the [TrueNAS workflow](../../monitoring/truenas/README.md).
  It requires an empty agent selection and manager-only inventory. TrueNAS stays
  agentless; its events use manager agent ID `000` and retain source hostname/program.
  Bootstrap and PKI preparation precede saved-plan review; service configuration
  still converges through Terraform and Ansible. Delivery is verified separately.
- Selected guests use Wazuh agents. Existing agents are adopted at an explicitly
  declared compatible version. Fresh installation/enrollment has separate
  package, TLS and credential inputs in the existing agent role.
- The optional [private dashboard role](../../monitoring/wazuh/TAILNET.md) installs
  a pinned signed Tailscale package, joins an existing Free tailnet and serves
  trusted HTTPS. Dashboard HTTP binds only to `127.0.0.1:5601`; Tailscale Serve
  proxies to it over loopback. Dashboard-to-indexer TLS stays enabled. Wazuh's
  own login is still required. Funnel, subnet routing and Tailscale SSH are not
  enabled. Access is limited by the tailnet's existing ACLs/grants; review those
  if other people or shared devices belong to the tailnet.

## Prerequisites and private inputs

Use Terraform 1.9–1.x and the repository's pinned Ansible Python environment.
The controller needs Python 3.9+; use the same Python executable consistently.
Enable Tailscale on the operator's computer to reach existing private SSH hops.
Verify every SSH host key independently before saving it. Keep strict checking
enabled; do not use `StrictHostKeyChecking=no` or accept an unverified host key.
The guest account must have approved sudo access; a read-only XOA collector
account cannot install an agent.

Create a directory outside the checkout with mode `0700`. Store inventories,
passwords, auth-key files, variables, plans and state there with mode `0600`.
Examples below use `$HOME/.config/home-lab/monitoring/wazuh-logging`; replace
placeholder values privately. Do not commit completed files.

`deployment-inventory.json` contains only `wazuh` and explicitly selected guests:

```json
{"all":{"hosts":{
  "wazuh":{
    "ansible_host":"homelab-logs-wazuh",
    "ansible_user":"EXISTING_ADMIN",
    "ansible_python_interpreter":"/usr/bin/python3",
    "monitoring_access_verified":true,
    "monitoring_expected_vm_uuid":"VERIFIED-XEN-VM-UUID"
  },
  "portainer":{
    "ansible_host":"homelab-logs-portainer",
    "ansible_user":"EXISTING_ADMIN",
    "ansible_python_interpreter":"/usr/bin/python3",
    "monitoring_access_verified":true,
    "monitoring_expected_vm_uuid":"VERIFIED-XEN-VM-UUID",
    "monitoring_wazuh_agent_version":"4.7.5",
    "monitoring_wazuh_agent_group":"homelab-linux"
  }
}}}
```

SSH aliases must resolve through an existing verified private path, with pinned
known-hosts files and strict checking. Add password/sudo inputs privately if
needed; SSH keys or Ansible Vault are preferable for ongoing operation. Do not
put passwords in a command line, Terraform variable or shell history. The
playbook verifies `/sys/hypervisor/uuid` over SSH immediately before mutation;
this local deployment currently supports Linux guests only. Windows agents
remain available through the general monitoring stack and require their own
verified access and identity workflow.

`deployment.json` example for logging without dashboard enrollment:

```json
{
  "monitoring_wazuh_selected_agents":["portainer"],
  "monitoring_wazuh_mode":"adopt",
  "monitoring_wazuh_manager_version":"4.7.5",
  "monitoring_wazuh_manager_address":"VERIFIED_PRIVATE_MANAGER_IP",
  "monitoring_wazuh_storage_cleanup_approved":true,
  "monitoring_wazuh_group_assignments":[{"id":"003","group":"homelab-linux"}]
}
```

Group IDs must come from the verified manager registry, not this example.
Cleanup approval implements the requested seven-day deletion policy; deleted
events cannot be recovered by changing the flag. Raw full-event archiving is
not enabled by this deployment. The manager already collects its own local
security logs and does not need a second agent installed beside it.

### Recover an indexer already at its shard limit

An indexer with years of daily indices can reach its shard limit before an ISM
configuration index exists. The first policy creation then fails, for example:
`would add [2] total shards ... [999]/[1000] maximum shards open`. Do not raise
the shard limit or add storage as a shortcut. Independently inspect the exact
expired alert candidate via the trusted indexer API and record its actual
index UUID and `creation.date` from `_cat/indices` in the private variables:

```json
{
  "monitoring_wazuh_shard_bootstrap_cleanup_approved":true,
  "monitoring_wazuh_shard_bootstrap":{
    "index":"wazuh-alerts-4.x-YYYY.MM.DD",
    "uuid":"VERIFIED_INDEX_UUID",
    "creation_date":"VERIFIED_CREATION_EPOCH_MILLISECONDS"
  }
}
```

This explicitly permits deletion of **one** reviewed, already expired alert
index, only when initial policy creation receives the exact shard-limit error.
Immediately before deletion, the helper requires both daily date and actual
creation time to be older than seven days, rereads its UUID/creation settings,
rejects aliases/wildcards and existing policy ownership, and uses an exact
index-name DELETE. It retries policy creation once and never picks another
candidate automatically. The identity check assumes no other administrator is
concurrently replacing that old index; OpenSearch does not provide an atomic
UUID-conditional index DELETE. Default operation performs no bootstrap delete.
After recovery, ordinary ISM retention handles the other expired alert indices
asynchronously. Remove the private bootstrap inputs after successful recovery.

For an existing agent pointing at an old address, independently read the agent
ID and SHA256 of its shared key on **both** manager and agent via verified SSH.
Only when they match, add these host-specific private inventory fields:

```json
{
  "monitoring_wazuh_previous_manager_address":"VERIFIED_OLD_ADDRESS",
  "monitoring_wazuh_agent_connection_migration_approved":true,
  "monitoring_wazuh_expected_agent_id":"003",
  "monitoring_wazuh_existing_key_sha256":"VERIFIED_64_HEX_DIGEST"
}
```

The migration changes only the existing TCP manager address, validates with the
installed Wazuh binary, keeps the shared key/enrollment policy, and rolls back
from a private backup if activation fails. It refuses multiple server blocks,
unexpected transport/ports, an unexpected old address or a different key.

## Plan, deploy and redeploy

Set these variables in your local shell. They contain file paths, not tokens:

```sh
export WAZUH_LOGGING_INVENTORY="$HOME/.config/home-lab/monitoring/wazuh-logging/deployment-inventory.json"
export WAZUH_LOGGING_VARS="$HOME/.config/home-lab/monitoring/wazuh-logging/deployment.json"
export WAZUH_LOGGING_RUN_DIR="$HOME/.config/home-lab/monitoring/wazuh-logging/terraform"
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
export ANSIBLE_PLAYBOOK_BIN="$HOME/.config/home-lab/monitoring/venv/bin/ansible-playbook"
export ANSIBLE_SSH_ARGS="-F $HOME/.config/home-lab/monitoring/wazuh-logging/ssh_config"

"$HOME/.config/home-lab/monitoring/venv/bin/python" scripts/monitoring/wazuh_logging.py plan --phase logging
"$HOME/.config/home-lab/monitoring/venv/bin/python" scripts/monitoring/wazuh_logging.py apply --phase logging
```

`plan` saves `deployment.tfplan` and a private input-digest review receipt beside
the local state. `apply` rechecks the exact plan and inputs before invoking
Ansible. Private values never enter the Terraform resource. Logs can reveal
operational aliases; keep deployment output private. Do not enable `TF_LOG`,
Ansible debug verbosity or `--diff` when using real credentials.

Use `--phase tailnet` after preparing the private Tailscale variables documented
in [TAILNET.md](../../monitoring/wazuh/TAILNET.md), or `--phase all` for both.
`all` does not enable TrueNAS. Use `--phase truenas` with its reviewed private
profile and receiver variables as documented in the linked guide. The same
phase must be used in plan and apply. Tailscale HTTPS approval, if
needed, is an owner action in the admin console's DNS settings. Failure leaves
the existing website configuration intact. A successful migration replaces its
LAN-wide dashboard listener with the tailnet HTTPS endpoint.

Reconciliation runs when source or selection changes. To rerun the same inputs
for drift repair, use `plan --phase all --redeploy`, review, then
`apply --phase all`. Terraform stores deployment intent and triggers, while
Ansible checks/reconciles host configuration during a run; Terraform refresh
alone does not inspect every remote file. Do not use `terraform destroy` to
remove monitoring: it would remove bookkeeping, not reverse host changes.
Changes to private role settings alone also require `--redeploy`; secret inputs
are deliberately absent from Terraform triggers and state.

## Add collectors safely

1. Confirm the VM is running and reachable. Do not boot a VM just for telemetry.
2. Verify SSH and sudo, the host key and Xen VM UUID. Copy only verified entries
   into the private deployment inventory. Never select Parrot.
3. Add the guest alias to `monitoring_wazuh_selected_agents` and set its exact
   agent version/group. For fresh agents, follow the existing
   [Wazuh agent instructions](../../monitoring/wazuh/README.md), including pinned
   package checksums and verified enrollment TLS. Do not reuse a different
   guest's agent ID/key or enable unauthenticated enrollment as a shortcut.
4. Add its verified manager registry ID to the manager group mapping after
   enrollment. Existing group memberships are retained.
5. Plan/apply, confirm the agent is active at the manager, and send a unique
   `HOMELAB_MONITORING_TEST: <nonce>` event with
   `logger -p auth.notice -t homelab-monitoring 'HOMELAB_MONITORING_TEST: <nonce>'`
   from that guest. The exact program tag selects the custom syslog decoder.
   Confirm rule `100100`, the correct agent name and a fresh timestamp in Wazuh.
   This checks collection and transport rather than merely service status.

TrueNAS uses the [native TLS bootstrap and forwarding workflow](../../monitoring/truenas/README.md).
OPNsense needs its native syslog integration and verified appliance administration. Do not install this Linux agent on them. Syslog must use a
verified encrypted private path; LAN reachability alone is not transport
encryption. XCP-ng remains agentless. Nine halted guests and any guest without
verified administrator access remain pending until reachable; their existing
hypervisor metrics/power-state monitoring is separate.

## Verify and troubleshoot

Run offline tests before deployment:

```sh
"$HOME/.config/home-lab/monitoring/venv/bin/python" -m unittest discover -s scripts/monitoring/tests -p 'test_wazuh_logging.py'
"$HOME/.config/home-lab/monitoring/venv/bin/python" -m unittest discover -s ansible/tests -p 'test_*.py'
terraform -chdir=infra/wazuh-logging validate
```

After deployment verify manager/indexer/dashboard/Filebeat health, the agent
list, ISM policy attachment, disk usage and the cleanup timer. From an authorized
tailnet client, open the printed private HTTPS URL and confirm trusted TLS and
the Wazuh login. Check that the dashboard's backend listener is loopback-only
and that no Funnel configuration exists. Do not bypass certificate warnings.

An SSH `Permission denied` after the pinned host answers indicates an account,
key or password issue. The existing XOA `lab-automation` account can collect
metrics but lacks permission to install Wazuh. Use an approved real admin
account or add an automation key through the VM console; do not reset passwords
or disable verification automatically. A failed Ansible task stops the apply;
review its sanitized output, correct the cause, regenerate the plan and retry.
