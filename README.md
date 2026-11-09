# Home lab as code

This repository records the XCP-ng fleet and its recovery evidence, manages
declared VM/guest configuration, and contains a Terraform-driven monitoring stack.
The absolute cloud budget is **$0**; read [AGENTS.md](AGENTS.md) before changing
cloud resources or subscriptions.

- **Monitoring setup, collectors, and redeployment:** [monitoring/README.md](monitoring/README.md)
- **Primary monitoring Terraform root:** [infra/monitoring](infra/monitoring/README.md)
- **Grafana resources:** [infra/grafana](infra/grafana/README.md)
- **datacenter1 and VM resource dashboards, excluding Parrot:** [monitoring/xcp](monitoring/xcp/README.md), [Terraform root](infra/xcp-monitoring/README.md)
- **Alloy Linux/Windows and application collectors:** [monitoring/alloy](monitoring/alloy/README.md)
- **Wazuh adoption, agents, fresh deployment and retention:** [monitoring/wazuh](monitoring/wazuh/README.md)
- **TrueNAS native TLS syslog and repeatable bootstrap:** [monitoring/truenas](monitoring/truenas/README.md)
- **OPNsense encrypted-path syslog forwarding:** [monitoring/opnsense](monitoring/opnsense/README.md)
- **Private access, network restrictions and DDoS limits:** [monitoring/network](monitoring/network/README.md)
- **Xen inventory and recovery:** [xen-server](xen-server/README.md)
- **Existing VM infrastructure:** [infra/xen/vms](infra/xen/vms/README.md)
- **Existing guest convergence:** [ansible](ansible/README.md)
- **Oracle access bootstrap:** [infra/oracle/bootstrap](infra/oracle/bootstrap/README.md)
- **Optional unprovisioned Oracle Wazuh infrastructure:** [infra/oracle/wazuh](infra/oracle/wazuh/README.md)

Monitoring deploys through Terraform. The selected Wazuh deployment uses the
existing local manager through [infra/wazuh-logging](infra/wazuh-logging/README.md).
The optional Oracle root remains unprovisioned and subject to separate Always
Free eligibility and capacity checks.
The monitoring roots manage Grafana resources and invoke versioned Ansible roles.
They do not upgrade subscriptions, boot existing guests or restore application data.

Start with `make monitoring-inventory` and the monitoring setup guide. Current
defaults permit dashboards and selected Alloy collectors on Grafana's verified
unbilled Trial; private write credentials and verified host access are required.
Local Wazuh and native TrueNAS forwarding use their separate private deployment
inputs; OPNsense retains its encrypted-path prerequisites.
The existing Xen commands remain separate and retain their own guards.
