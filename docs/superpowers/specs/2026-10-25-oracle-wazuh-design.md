# Oracle Wazuh deployment

The owner selected Oracle for Wazuh after comparing local shared-host placement,
separate hardware and other SIEMs. Preserve the absolute $0 limit, manage desired
configuration through Terraform, retain the existing local VM as recovery evidence,
and keep Grafana Cloud as the operational telemetry service. No paid fallback,
region switch or account upgrade is authorized.

Use one VM.Standard.A1.Flex in the existing home-lab compartment in us-sanjose-1:
2 ARM OCPUs, 12 GB RAM, an official Ubuntu 22.04 ARM image and a 100 GB balanced
boot disk. These are conservative limits against the current published and actual
account allowances (2 A1 OCPUs, 12 GB RAM, 200 GB combined disk). Existing storage
is 60 GB, so proposed combined storage is 160 GB. The official reviewed Wazuh
4.14.9 assistant supports aarch64 and accepts two cores without hardware-check
bypasses. The quickstart recommends four cores; performance must be measured at
small scope before fleet rollout. Preserve the legacy local manager and its keys;
new-manager agent migration must be explicit and cannot silently replace them.

The separate infra/oracle/wazuh root creates its own VCN/subnet/NSG/route/Internet
gateway, a closed subnet security list and the VM. No Wazuh application ports are
public. Optional bootstrap SSH permits one verified public IPv4 /32 and is removed
after VPN access works. IPv6 is disabled. Only necessary outbound bootstrap/VPN
traffic is allowed. No NAT gateway, load balancer, paid Marketplace image, backups,
replicas or instance-principal permissions are created. Cloud-init contains only
public SSH material and SSH hardening, never enrollment keys or passwords.

Add tenancy A1 and disk quotas without changing the existing micro VM. The
operator stays read-only and cannot alter quotas or IAM. Quotas cover particular
resources, not every possible charge; actual Free account status, resource scope,
usage checks and plan guards remain necessary. Never call budgets a spending cap.

A guarded controller checks current subscription details, all subscribed regions
and compartments, existing compute and disk usage, free service limits and exact
shape capacity before producing a plan, then repeats those checks before applying
the hashed saved plan. Any unavailable capacity stops before any resource mutation.
The actual capacity report on 2026-10-26 UTC is OUT_OF_HOST_CAPACITY. Prepare and
test code; no cloud-changing apply is permitted while that remains true.

Tailscale provides private administration and agent routes when configured. One
trusted home subnet router plus Tailscale on the cloud VM avoids a VPN client on
each home VM. Route/grant rules need actual home topology and tailnet policy before
changes. Tailnet rules must restrict exact sources/services, with no broad default
allow-all path. Grafana ingestion remains outbound and blocked until actual Free
status is verified. Wazuh/Alloy credentials stay external to Terraform values/state.

Implementation now prepares the Oracle root, its guarded audit/plan/apply workflow,
ARM bootstrap compatibility, and precise README instructions. Physical capacity,
verified SSH identity, Tailscale enrollment/policy, current private host addresses,
trusted PKI and actual manager/agent migration remain live rollout requirements.
