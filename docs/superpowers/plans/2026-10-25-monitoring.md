# Monitoring Implementation Plan

> **For agentic workers:** Implement independent subsystems in parallel, then integrate and independently review.

**Goal:** Reproducible Grafana Cloud Free and local Wazuh monitoring for the inventoried fleet.
**Architecture:** The infra/monitoring Terraform composition owns existing-stack visualization/alerts and creation-only selected-fleet convergence. Versioned Ansible roles implement guest configuration. A controller validates fleet policy, private inputs and saved plans before deployment. Guest drift requires deliberate re-convergence.
**Tech Stack:** Terraform, Grafana provider, Ansible, Python controller/tests, Alloy, Wazuh.
**Spec:** docs/superpowers/specs/2026-10-25-monitoring-design.md

## Global Constraints

- Absolute cost ceiling $0; no cloud provisioning, paid features, stack upgrades, or trial-credit reliance.
- Existing Grafana URL https://cordialbike2680.grafana.net; stack is Trial. Trial collector deployments use the live-verified, unbilled Trial path and Free transition described below.
- Preserve captured Wazuh 4.7.5 installation by default; distinct explicitly pinned fresh install.
- Credentials outside Git; private inputs mode 0600; no secret diffs or TLS/SSH bypasses.
- Exact target selection; never automatically start guests or install agents in dom0/appliances.

## Review Focus

- Partial host selection or unknown targets must fail before contacting or mutating guests.
- Log/metric fanout must stay bounded and include missing-host detection.
- Existing Wazuh identities, enrollment, TLS, and unrelated configuration must survive adoption.
- Provider plans must contain only existing-stack dashboard/folder/alert resources plus the exact built-in terraform_data.fleet[0] orchestration address.
- Rendered collector configuration must validate before service restart; failed changes must not report success.

### Task 1: Fleet policy and deployment controller

- [x] Validate existing inventory references and platform/role boundaries with failing unit tests first.
- [x] Implement monitoring policy, private-file checks, explicit-target controller, and Make commands.
- [x] Write guide and integrate playbooks using existing Ansible conventions.

### Task 2: Grafana configuration

- [x] Implement existing-stack Terraform root, sourced dashboards and alert rules.
- [x] Verify provider schema, mock tests, and no billable resource types.

### Task 3: Collector deployment

- [x] Implement Alloy Linux/Windows role with secure tokens, pinned official packages, bounded pipelines, and validation/restart handling.
- [x] Add role tests, rendering/validator evidence and platform playbooks.

### Task 4: Wazuh and network security configuration

- [x] Implement safe manager adoption, fresh installation, Linux/Windows agents, centralized policy/rules and scoped retention.
- [x] Implement OPNsense remote syslog configuration with verified TLS and idempotent native API updates.
- [x] Verify tests and syntax; document backup/recovery and appliance constraints.

### Task 5: Integration and verification

- [x] Run combined local validation, existing regressions, fresh independent review and fix important findings.
- [x] Prepare concrete private credential setup and deployment commands.
- [x] Perform only live operations whose prerequisites and free eligibility are verified; otherwise report the exact remaining inputs.

## Verification recorded 2026-10-25

- Controller: 14 tests passed; existing Xen scripts: 56 tests passed.
- Combined Ansible inventory/guest/monitoring suite: 53 tests passed, including native Alloy validation and actual local Ansible gate/fresh-fact execution. The first sandboxed attempt could not create Ansible RPC sockets; the complete outside-sandbox rerun passed.
- Terraform: both roots validated; 9 Grafana + 9 composition mock tests passed; format checks passed.
- All three monitoring playbooks passed syntax checks. Eight monitoring README link sets resolve; private JSON examples parse; whitespace checks passed.
- Independent review found manager status handling, missing fresh facts, an incorrect example path, unsupported optional Wazuh export documentation and inaccurate state placement documentation. Fixed all five; the optional export remains explicitly unsupported and disabled rather than widening log access.
- No live monitoring deployment, ingestion, alert delivery, firewall/VPN change or new Oracle workload was performed. Actual Grafana Free status, private inputs, current verified hosts and protected device-syslog transport remain required.
- Follow-up network discussion: owner has a Tailscale account and is considering one subnet router and possibly home-to-Oracle connectivity. Network guide records source/port isolation, final-hop encryption, DDoS limitations and options; actual Wazuh placement and network topology need clarification before a network Terraform extension.

## 2026-10-26 live deployment ruling

The instance API confirms Cloud Trial. Official Grafana terms state Trial use is never billed, the Free plan is always $0, and Trial automatically transitions to Free. Permit folder/dashboard metadata and selected Alloy collectors after a fresh live Trial check before plan and apply. The Trial collection path excludes Wazuh-manager/OPNsense mutation and alerts; it creates no paid cloud resources or subscriptions. Host credentials and target access remain explicit private prerequisites. This supersedes the earlier blanket Trial block without declaring the stack already Free.
