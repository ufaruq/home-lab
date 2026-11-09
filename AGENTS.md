# Home lab agent instructions

## Resilience and configuration as code

Keep this home lab resilient, recoverable, and reproducible using the existing
Terraform, Ansible, native XCP-ng recovery, and monitoring setup. Treat these
requirements as part of every infrastructure change, including incident repairs.
This guidance does not authorize unrelated live changes or disruptive tests.

### Use the existing sources of truth

- Read [the repository overview](README.md), [the Xen controller workflow](xen-server/automation-workflow.md),
  [VM resilience](xen-server/vm-resilience.md), and the relevant component guide
  before changing that component.
- Use `infra/xen/vms/` and the selected private inventory/desired-state inputs
  for supported VM hardware, power state, autostart, and protection settings.
  Use the guarded controller commands rather than bypassing plan safeguards.
- Use existing Ansible roles/playbooks for host and guest configuration,
  services, networking, access, and recovery. Native startup declarations and
  lifecycle metadata belong in the existing private `native_recovery_policy`;
  see [the recovery guide](ansible/recovery/README.md).
- Use the existing monitoring Terraform roots and versioned Ansible roles for
  monitoring changes; follow [the monitoring guide](monitoring/README.md).
  Extend existing modules and roles before introducing another management tool,
  parallel source of truth, or custom recovery daemon.
- Inspect live state before making decisions. Historical inventory, fixtures,
  documentation, and a VM's current power state do not establish desired policy.
  Preserve stable VM, host, pool, NIC, and disk identities and existing ownership.

### Save every persistent change as configuration

- Update the owning declaration before applying a persistent infrastructure or
  service change. UI, SSH, API, and console changes must not become the only
  record of intended configuration. Use idempotent, repeatable automation.
- If an urgent authorized repair requires a direct live change, capture the
  private before-state, reconcile the repair into the existing configuration
  during the same task, and check that later convergence preserves it. Report
  any remaining drift or blocker explicitly; do not call the task complete while
  an undocumented persistent repair remains.
- Keep reusable code, nonsecret configuration, and recovery instructions in the
  repository. Keep actual deployment inventory, private desired-state inputs,
  credentials, state, saved plans, and sensitive evidence in the existing
  protected private locations. Never publish secrets to satisfy this rule.
- Update the relevant runbook when prerequisites, dependencies, recovery steps,
  or verification change. Describe what was saved, applied, and verified,
  including any unapplied configuration or untested recovery assumptions.

### Preserve automatic recovery

- Maintain the explicitly approved automatic-start VM set and management VM
  identity across Terraform and native recovery policy. Preserve intentionally
  halted guests; do not enable autostart or restart every VM by default.
- Preserve recovery order: physical power and storage, host networking/XAPI,
  native guest startup, management access, then dependent applications. Restore
  declared storage aliases and mounts before starting dependent guests. Use
  permanent disk identities and preserve passthrough/data disks.
- Keep approved boot services enabled and native crash/reboot recovery metadata
  consistent with policy. Preserve intentional shutdown behavior. Prefer the
  existing native mechanisms and declared service restart policies; avoid restart
  loops, blanket force restarts, and changes that mask a storage or network fault.
- Recovery must work after the controller disconnects. Do not make unattended
  startup depend on an interactive login, an agent session, or a manual `make up`.
  Native autostart/crash recovery does not establish hung-guest detection or
  application recovery; the current setup has no continuous polling watchdog.
- Preserve independent access and private off-host recovery material before
  risky maintenance. Configuration as code does not replace backups of VM disks,
  application data, pool metadata, or private state. Verify restore prerequisites
  and document gaps without claiming untested recovery guarantees.

### Verify without disrupting the lab

- Run the relevant local validation and tests for changed automation. For live
  Xen changes, use `make plan`, inspect the actual plan, and use `make up` only
  within the authorized scope; then run `make recovery-check` and another
  `make plan` to check for unexpected drift. Follow component-specific checks
  for other stacks. Never apply a plan with unreviewed destruction, replacement,
  resizing, or unrelated topology changes.
- Verify the exact intended guest states, management access, storage availability,
  and affected application health. A successful apply, enabled service, running
  VM, or reachable login page alone is insufficient evidence of full recovery.
- Host reboots, power-loss exercises, destructive restore tests, and disruptive
  failover tests need an explicitly authorized maintenance scope and a working
  recovery path. Use read-only checks otherwise and state what remains untested.

## Absolute cloud cost limit: $0

The owner cannot afford cloud charges. Under no circumstances may this
infrastructure incur charges or exceed Oracle Cloud's applicable Always Free
allowances. This is a hard requirement for all work in this repository.

- Never upgrade the Oracle account to Pay As You Go, enable paid subscriptions,
  accept paid Marketplace terms, or provision billable resources.
- Free trial credits, promotional credits, estimates, and budget alerts do not
  satisfy the $0 requirement. Budget alerts are not a hard spending cap.
- Before any cloud-changing apply, verify the account's billing status, the
  current official Always Free terms, the home region, and existing usage across
  the entire tenancy. Verify the exact proposed resources are eligible and the
  combined usage remains within every applicable free allowance.
- Review the actual Terraform plan before applying. Do not create an unplanned
  resource, choose a paid fallback shape, add chargeable storage or networking,
  or provision resources in another region when free capacity is unavailable.
- Use enforceable quotas and restricted permissions where supported. The
  day-to-day operator must not be able to change billing settings, increase
  quotas, or remove cost safeguards. Do not represent partial quotas or IAM
  restrictions as a universal spending cap.
- If free eligibility or effective cost protection cannot be established, stop
  before provisioning and explain the blocker. Do not proceed on the assumption
  that a small charge is acceptable.
- Apply this rule to the complete lifecycle: installation, operation, backups,
  logs, snapshots, retained disks, data transfer, upgrades, and replacement
  resources that may temporarily coexist.
- Keep passwords, private keys, session tokens, Terraform state, local variable
  files, and saved plans out of version control.
