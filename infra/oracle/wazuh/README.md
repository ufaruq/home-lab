# Oracle Always Free Wazuh

The owner selected Oracle to separate Wazuh from the monitored hypervisor. This
root prepares one ARM server in the existing `home-lab` compartment and leaves
the captured local Wazuh VM unchanged. The absolute cloud budget is **$0**; follow
[AGENTS.md](../../../AGENTS.md). There is no paid fallback or account upgrade.

**Live status, 2026-10-25 Pacific:** the verified account has subscription tier
`FREE`, an expired trial, home region San Jose and available entitlement for
2 A1 OCPUs/12 GB RAM. Existing resources include one E2 micro VM and a 60 GB boot
disk. Oracle reports `OUT_OF_HOST_CAPACITY` for A1 with 2 OCPUs and 12, 10 or 8 GB
RAM. No resource-changing Terraform apply has been performed for this root.
Do not fabricate capacity flags, bypass the controller or upgrade to obtain a VM.

## What this root owns

- One `VM.Standard.A1.Flex`: fixed 2 OCPUs, 12 GB RAM, official pinned Ubuntu
  22.04 ARM image, one 100 GB boot disk at 10 VPUs/GB. With the currently existing
  disk this is 160 GB combined, within the current published 200 GB allowance.
- Its own VCN, subnet, route table, internet gateway, empty custom security list,
  NSG and narrow outbound rules. No public application ingress and no IPv6.
- An optional, temporary bootstrap SSH exception from exactly one verified
  public IPv4 `/32`. Default `null` means no public SSH. Remove it after private
  administration works. The unassociated VCN default security list is never used
  by this subnet; NSG and custom-list rules are additive, so attaching a permissive
  security list would defeat the intended restriction.
- Resource-specific tenancy quotas: A1 cores 2, A1 RAM 12 GB and combined disk
  200 GB in the home region; no automatic backups in `home-lab`. These do not cap
  every cloud service or transfer charge. The Free account restriction, complete
  usage checks and saved-plan resource guard are additional requirements.
- Optional `terraform_data.manager[0]` runs the versioned Wazuh role after
  explicit `deploy_manager=true` and verified private host access. Creation or
  source changes reconverge policy; removing the record does not uninstall Wazuh.

It creates no load balancer, NAT gateway, Marketplace subscription, image, snapshot,
replica, paid backend, instance-principal permissions or operator write access.
Public addressing is for outbound connectivity and optional narrow bootstrap,
not public Wazuh access. Cloud-init contains SSH hardening and a public key only.
Passwords, private keys, Wazuh enrollment credentials and VPN tokens must never
enter Terraform variables, cloud-init, state, plans or command arguments.

The existing operator stays read-only. Use a temporary administrator CLI session
only for these reviewed changes; do not grant broad provisioning permissions to
the operator. The existing micro VM does not consume the A1 CPU allowance, so
stopping it does not resolve ARM physical-capacity shortages. Its removal is not
necessary for this deployment's current storage budget.

### Why the existing micro VM cannot replace this server

Live readback confirms `instance-20260126-1712` is running on
`VM.Standard.E2.1.Micro` with **1 GB RAM**. Oracle explicitly excludes that shape
from in-place resizing. A full Wazuh server/indexer/dashboard installation is
unsuitable for this allocation: the quickstart recommends 8 GiB RAM for 1–25
agents, and even a manager-only installation lists a 2 GB RAM minimum. Extra disk
or swap does not increase its CPU/RAM allocation or change its architecture.
Do not overwrite it or bypass installer hardware checks to work around A1 capacity.

It could later be repurposed as a lightweight private-access gateway or bounded
log relay after guest/SSH inspection and a reviewed Terraform adoption plan.
That would still require a larger Wazuh analysis/storage host. The latest reuse
assessment changed no VM, package, disk, network or IAM settings; a fresh guarded
A1 audit still returned OUT_OF_HOST_CAPACITY.

References: [Oracle resize restrictions](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/resizinginstances.htm),
[Wazuh server requirements](https://documentation.wazuh.com/current/installation-guide/wazuh-server/index.html),
[full-stack sizing](https://documentation.wazuh.com/current/quickstart.html).

## 1. Local checks

```sh
python3 -m unittest discover -s scripts/oracle/tests -v
terraform -chdir=infra/oracle/wazuh init -backend=false
terraform -chdir=infra/oracle/wazuh fmt -check -recursive
terraform -chdir=infra/oracle/wazuh validate
terraform -chdir=infra/oracle/wazuh test
```

Mock tests create no Oracle resources. Use the checked-in provider lock file.
Local provider execution may require permission for its Unix socket. These checks
do not establish actual capacity, Wazuh performance, PKI trust or VPN operation.

## 2. Authenticate and check capacity safely

Authenticate the original administrator with MFA, not `home-lab-operator`:

```sh
oci session authenticate --region us-sanjose-1 --profile-name home-lab-bootstrap
python3 scripts/oracle/wazuh.py audit
```

Use a separate browser profile when an existing browser session silently selects
the operator. `audit` reads subscription details, subscribed regions, all active
compartments, instances, boot/data disks, backups, actual A1 usage/limits, the
official image and a capacity report. A capacity report creates no VM and reserves
no capacity. The workflow currently supports the verified single-region,
single-availability-domain tenancy; additional regions/ADs stop for expanded audit.
CLI errors fail closed, never become zero usage.

The raw normalized audit is owner-only at
`$MONITORING_RUN_DIR/oracle-wazuh-audit.json`. The default runtime directory is
`/private/tmp/home-lab-monitoring-<uid>` (0700). Error details are retained privately.
`OUT_OF_HOST_CAPACITY` exits without initializing a deployment, changing quotas,
creating a VCN or launching an instance. Retry this read-only command deliberately
later; no continuous launch loop or background retry has been installed.

## 3. Prepare private inputs when capacity is available

Use the [main private-file setup](../../../monitoring/README.md). Copy
`inputs.tfvars.json.example` to an owner-only JSON file outside this checkout.
The audit supplies verified identifiers; replace example fields with its actual
tenancy, compartment, AD and official image values. Keep the selected image pinned
for later plans; selecting a newer image can propose replacement, which the guard
rejects. An image upgrade is a separate migration.

Use a dedicated Ed25519 deployment key. Store the private key in your encrypted
credential location/SSH agent; only its public `.pub` line belongs in Terraform
inputs. Set `bootstrap_ssh_cidr` to your verified current public IPv4 `/32` only
if needed for initial access. A dynamic address requires a reviewed update; never
substitute `0.0.0.0/0`. The guard also rejects private/reserved addresses. Keep
`deploy_manager` omitted or false for the infrastructure stage.

```sh
python3 scripts/oracle/wazuh.py plan --vars /absolute/private/oracle-wazuh.json
python3 scripts/oracle/wazuh.py apply --vars /absolute/private/oracle-wazuh.json
```

Read the saved plan summary and private Terraform log before apply. The controller
repeats live eligibility/usage/capacity checks for each command. Plans, generated
inputs and review receipts are 0600 outside the checkout. Source, original input,
generated-input and binary-plan hashes must match; a review expires after 15 minutes.
The guard rejects other providers/resources, extra compute/storage, VM replacement,
destruction, public application ports and broad SSH. Removing the temporary SSH
rule is allowed. An API can still lose capacity between the report and creation;
a failed launch is not permission for another shape/region or an automatic retry.

Terraform state stays in this root's Git-ignored local `terraform.tfstate` and
backup. The controller uses umask 077; protect existing state and encrypted backups
as well. It contains infrastructure metadata/public keys but must not be published.
Do not independently apply an unguarded plan or run with Terraform debug logging.

## 4. Establish private access before installing Wazuh

Verify the new server's SSH host key against independently trusted console/serial
output before adding it to known_hosts. Do not use unchecked `ssh-keyscan` as proof
of identity, `StrictHostKeyChecking=no` or a `/dev/null` known-hosts file.

The intended private design is Tailscale on the Oracle host plus one existing
trusted home subnet router. Advertise only required hosts/routes and grant exact
admin and endpoint access; review the full existing tailnet policy, including any
default allow-all rule. This root currently **does not install/enroll Tailscale or
replace tailnet rules**. That network configuration needs the actual home routes,
chosen gateway and private tailnet credentials/policy, and must be added through
Terraform-managed configuration before remote deployment is claimed complete.
Do not open Wazuh ports publicly as a temporary workaround.

Read the [network guide](../../../monitoring/network/README.md) for source/port
restrictions, SNAT, final-hop encryption and DDoS limits. Keep HTTPS certificate
verification and host firewall restrictions. A tailnet connection does not make
the hosted Grafana URL private. Verify the cloud VM's DNS resolution, time sync,
HTTPS relay connectivity and protected routes before any application rollout.

## 5. Configure the manager through Terraform

`oracle_wazuh` is an explicit external inventory entry in
[`monitoring/inventory/oracle.yml`](../../../monitoring/inventory/oracle.yml).
It has no invented address and starts with closed access/deployment gates.
The captured local `wazuh` entry is preserved and no longer a manager target.
Use a mode-0600 private inventory override to set `oracle_wazuh.ansible_host` to
the verified reachable private/VPN address and retain `ansible_user=ubuntu`.

Copy [`oracle-wazuh.json.example`](../../../monitoring/examples/oracle-wazuh.json.example)
outside the checkout for manager variables. Review the exact official 4.14.9
installer and independently verify its SHA-256; put that checksum in the private
file. Set actual boolean access, deployment, fresh-install and
`monitoring_wazuh_arm_small_approved` flags only after completing their checks.
The two-core ARM exception is deliberate small-lab sizing; it does not use the
assistant's OS/hardware bypass flags. Start with a few endpoints and measure CPU,
RAM, indexing latency and disk growth. Short retention reduces disk, not ingest CPU.

Export `MONITORING_PRIVATE_INVENTORY` and `MONITORING_PRIVATE_VARS` as private file
paths, set `deploy_manager=true` in private Terraform JSON, then generate and review
a new `plan` and `apply` through the controller. Host credentials are inherited by
the creation provisioner, not stored in Terraform. Wazuh policy source changes
reconverge the selected server. Private-input/token changes do not alter the public
digest. For deliberate re-convergence or credential rotation, keep
`deploy_manager=true`, update private inputs and run:

```sh
python3 scripts/oracle/wazuh.py plan --reconfigure-manager --vars /absolute/private/oracle-wazuh.json
python3 scripts/oracle/wazuh.py apply --vars /absolute/private/oracle-wazuh.json
```

Only the creation-only manager record is replaced; the VM is preserved. When
manager deployment is enabled, the private inventory/role-file paths and hashes
also belong to the private plan receipt. Changes invalidate the reviewed plan
without putting their contents into Terraform state.

## 6. Migrate agents and verify service

The current local manager/agents are captured at 4.7.x. This fresh cloud server is
4.14.9; the existing role's same-minor compatibility policy rejects an automatic
migration. Preserve original `client.keys`, CA material and backups. Plan agent
package upgrades, manager trust, enrollment and group mappings explicitly; do not
silently overwrite or reenroll adopted agents. Until that migration is implemented
and verified, prepared cloud infrastructure is not fleet security coverage.

Validate dashboard/API/indexer health privately, enrollment CA/name/expiry and
password settings, then test one endpoint end to end. Apply seven-day alert-index
retention only with explicit approval and a reviewed backup plan. The Grafana
collector rollout remains independently blocked while the hosted plan is Trial.
See the [Wazuh guide](../../../monitoring/wazuh/README.md) and
[collector guide](../../../monitoring/alloy/README.md).

## Recovery and cost boundaries

Both the VM and quota resource prevent Terraform destruction. VM replacement is
also rejected by the controller. Preserve the boot disk and private state; a later
decommission requires an explicit reviewed plan, including retained disks. Do not
launch a second replacement alongside the first within a full A1 free allocation.
No automatic paid backup/storage expansion is configured. Oracle may reclaim idle
free instances, so configuration-as-code is not a substitute for private backups
of identities and data you need to retain. No free-tier availability guarantee is
made. If resource eligibility or cost protection changes, stop and reassess.

References: [Oracle Always Free](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm),
[compute quotas](https://docs.oracle.com/en-us/iaas/Content/Quotas/Concepts/resourcequotas_topic-Compute_Quotas.htm),
[volume quotas](https://docs.oracle.com/en-us/iaas/Content/Quotas/Concepts/resourcequotas_topic-Block_Volume_Quotas.htm),
[Wazuh sizing/platforms](https://documentation.wazuh.com/current/quickstart.html).
