# XCP-ng host and VM metrics as code

This Terraform root manages the `homelab-xcp-host` and `homelab-xcp-vms` dashboards in the existing
Grafana folder and invokes Ansible for the external collector on XOA. The
monitored host is **datacenter1**; all 13 declared local VMs except Parrot are
selected through `monitoring/xcp/vm-targets.json`. Powered-off guests report only
status until boot. No per-guest agents are installed.

Use the [complete collector guide](../../monitoring/xcp/README.md) and the guarded
`scripts/monitoring/xcp.py plan` / `apply` workflow. State, plans and private
inputs stay outside the checkout. The only managed resources permitted by the
controller are these two dashboards and their local Terraform deployment record.
No cloud infrastructure, stack, subscription, datasource or paid plugin is
created. Public source changes replace the deployment record and rerun
idempotent Ansible. Terraform refresh cannot detect arbitrary remote file drift;
use `plan --redeploy` to deliberately reconcile it.
