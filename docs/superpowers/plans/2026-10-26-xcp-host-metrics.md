# XCP-ng host metrics implementation

1. [x] Implement and test bounded, freshness-aware XOA-to-metrics conversion.
2. [x] Add the loopback JSON-RPC client, viewer-account reconciliation and HTTPS
   writer with private local status reporting.
3. [x] Add an Ansible role/playbook for the unprivileged XOA collector and cron.
4. [x] Add a dedicated Terraform root, saved-plan guard and deployment controller.
5. [x] Add the host dashboard and deployment/collector/troubleshooting README.
6. [x] Verify local tests and configuration; query live XOA after its upgrade.
7. [x] Review/apply the exact Terraform plan, deploy via Ansible, verify multiple
   scheduled uploads and query the actual dashboard's metric expressions.

Evidence: [deployment verification](../../../monitoring/xcp/DEPLOYMENT.md).
