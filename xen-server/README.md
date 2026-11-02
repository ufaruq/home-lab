# Xen automation scope

This directory documents a reusable controller workflow for existing Xen infrastructure. It deliberately excludes a real deployment's hardware inventory, addresses, identities, evidence and recovery history.

| State | Owner |
| --- | --- |
| Supported VM and network declarations | Terraform and its guarded plan |
| Selected verified Linux configuration | Ansible guest roles |
| Narrow native host policies | Reviewed Ansible/XenAPI helpers |
| Disks, application data and secrets | Separately defined private backup/recovery procedures |
| Unsupported attributes and appliances | Explicit observation and operator review |

Each setting needs one owner. Captured state is evidence, not automatic permission to enforce it. A no-op plan does not prove health, successful reboot, data consistency or complete recovery.

Start with the [workflow](automation-workflow.md), [desired policy](desired-state.md), [debugging runbook](debugging-runbook.md) and [backup guide](backups.md). Implementation details are in the [Terraform](../infra/xen/vms/README.md) and [Ansible](../ansible/README.md) guides.

[XOA remote access](remote-access.md) documents the Tailscale endpoint, dedicated
SSH identity, `make xoa-up` convergence, and connection/debugging instructions.
[Guest startup and recovery](vm-resilience.md) covers the exact autostart set,
native crash/reboot policy, graceful shutdown protection and verification.
[XO source updates](xo-source-updates.md) documents the free source build, weekly
GitHub/Node maintenance, Debian security updates, rollback and debugging commands.

Private deployment material belongs in ignored `inventory/`, `guest-inventory/`, `evidence/`, local policy files and private notes. Credentials and authoritative SSH host keys belong outside the checkout. Commit only deliberately synthetic fixtures and generic documentation.

Recovery requires compatible host software, known-good storage, network access, verified images, private state and any required application data. Record the actual recovery test privately. Do not claim that creating a definition restores its contents.
