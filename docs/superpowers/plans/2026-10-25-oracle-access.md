# Oracle Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the approved restricted Oracle operator account through reusable Terraform.

**Architecture:** A bootstrap root module uses the temporary administrator session to manage identities, a compartment, and scoped policies. Future workload roots use the operator session; credentials remain outside Terraform.

**Tech Stack:** Terraform 1.17, oracle/oci provider, OCI CLI security-token authentication.

**Spec:** docs/superpowers/specs/2026-10-25-oracle-access-design.md

## Global Constraints

- Absolute cloud cost limit: $0, as required by AGENTS.md. Verify billing status, actual Always Free eligibility, and tenancy-wide usage before any cloud changes. No account upgrades, paid resources, paid fallbacks, or reliance on trial credits or budget alerts.
- Home region: us-sanjose-1; preserve existing administrator and Default domain.
- Initially read compute, volumes, and networking only in home-lab; root grants are read-only discovery. No workload creation rights before enforceable Always Free safeguards.
- No passwords, MFA material, permanent API credentials, or session tokens in Terraform.
- Ignore and protect local inputs, plans, and state; commit the dependency lockfile.
- Preserve unrelated docs/README.md changes and the xen-server directory.

## Review Focus

- A future policy edit must not grant tenancy-wide writes or IAM administration.
- Identity Domain group members must reference SCIM user IDs; IAM policies must reference group OCIDs.
- Enrollment must not cause passwords or authentication tokens to enter state.
- A destroy or rename must not remove access foundations accidentally.
- Console MFA enforcement must cover this non-administrator rather than administrators alone.

### Task 1: Implement and verify the bootstrap module

**Files:** infra/oracle/bootstrap/{versions,variables,main,outputs}.tf; tests/access.tftest.hcl; terraform.tfvars.example; README.md; .gitignore.

**Interfaces:** Consumes tenancy/domain OCIDs and operator email as ignored local inputs. Produces operator/group/compartment identifiers and restricted policies, authenticated through an external OCI profile.

- [x] Write mock-provider security tests before the module: scoped access, read-only root grants, dedicated membership, credential-free enrollment.
- [x] Implement the minimal module, local input example, and operating instructions.
- [x] Run terraform fmt -check, init, validate, and test; inspect all results.
- [x] Obtain an independent security review and address important findings.

### Task 2: Apply and verify the approved account

**Files:** Ignored local terraform.tfvars, saved plan, and state; module README for enrollment instructions.

**Interfaces:** Consumes the verified module and temporary bootstrap session. Produces live identities and policies plus an enrollment handoff.

- [x] Inspect console sign-on rules; confirm whether the operator inherits required MFA.
- [x] Verify billing status and that all planned identity resources remain within existing free identity-domain entitlements; stop if $0 eligibility cannot be established.
- [x] Create owner-only local inputs and generate a live Terraform plan.
- [x] Verify the plan creates only the approved user, group, compartment, and policies.
- [x] Apply that saved plan using the user's existing authorization; do not touch other resources.
- [x] Verify cloud membership/policies and run a subsequent no-change plan.
- [x] Give the owner enrollment instructions; authenticate as the operator and verify denied IAM access after enrollment.
