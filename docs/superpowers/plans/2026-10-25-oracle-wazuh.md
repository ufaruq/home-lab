# Oracle Wazuh Implementation Plan

> For agentic workers: use superpowers:executing-plans in the current session.

**Goal:** Prepare and, only when verified free capacity exists, deploy Wazuh separately in Oracle.
**Architecture:** A separate OCI Terraform root creates fixed free resources and quota controls. A stdlib controller performs read-only live audits, reviews a saved plan and rechecks before apply. Existing versioned Ansible roles remain the application configuration layer.
**Tech Stack:** Terraform 1.9+, Oracle provider 8.29.0, OCI CLI, Python, Ansible, Wazuh 4.14.9.
**Spec:** docs/superpowers/specs/2026-10-25-oracle-wazuh-design.md

## Global constraints

- Absolute $0, no upgrade, trial credits, paid fallback or other region.
- Existing operator remains read-only; existing root micro VM/local Wazuh stay untouched.
- No public Wazuh ports or secrets in Terraform state/cloud-init.
- Current physical capacity is unavailable; no cloud-changing apply until it becomes available.

## Review focus

- Paid subscriptions, stale audits, unexpected existing resources or quota/capacity failures stop before mutation.
- Combined storage and A1 usage include all compartments, retained boot volumes and the existing micro VM.
- Saved plans reject deletion/replacement, extra providers/resources, larger shapes/disks, unsafe ingress and image changes.
- ARM support must not bypass installer OS/hardware checks or silently migrate legacy identities.
- Private VPN/host trust and cloud capacity are separate prerequisites; prepared configuration is not a live deployment.

## Tasks

- [x] Add failing tests for audit assessment, resource scope, unsafe plans, quota limits and network ingress.
- [x] Implement scripts/oracle/wazuh.py audit/plan/apply and infra/oracle/wazuh with mock Terraform tests.
- [x] Add explicit constrained ARM fresh-bootstrap support and offline regression checks.
- [x] Update monitoring target documentation, Oracle setup/redeployment README and private examples.
- [x] Run local verification and fresh independent review; fix important findings.
- [ ] Recheck live prerequisites and deploy only if all pass; otherwise leave no new cloud resources and report the exact blocker.

## Verified outcome

No cloud-changing apply occurred. Last live capacity report at 2026-10-26
04:23 UTC reports OUT_OF_HOST_CAPACITY for A1 2 OCPUs with 12/10/8 GB RAM.
Subscription details verified FREE/expired FREE_TRIAL; A1 entitlement 2 OCPUs,
12 GB; existing root micro VM and 60 GB boot disk; no existing A1 usage.
The user authorized stopping the unused micro if necessary, but doing so would
not create ARM capacity and is unnecessary for the 160 GB proposed disk total.
No existing instance was stopped, modified or deleted.

Independent review found terminating resources excluded too early and incomplete
saved-plan source hashing. Reproduced both with failing tests, fixed both, and
passed the complete 9-test Oracle controller suite. Quota-relaxation guard also
reproduced/fixed. Source, private inputs and plans now have matching receipts.
Monitoring controller14/14, Ansible58/58 (including actual ARM-gate execution),
Oracle Terraform8/8 and monitoring composition9/9 passed; Oracle validation and
all three monitoring syntax checks passed. Documentation links/examples checked.

The last attempt to run the new audit controller against live Oracle stopped on
expired CLI credentials before reaching capacity checks. No mutation was attempted.
Its full API-response normalization/capacity-stop path is covered offline with
actual CLI response formats. Refresh the administrator session before a later
read-only retry. Never call this prepared root an actual deployment.

Remaining rollout requirements after capacity: verified SSH identity, private
Tailscale topology/enrollment/policy, manager install/readback, explicit legacy
agent migration, and actual Grafana Free status/credentials before hosted ingestion.
