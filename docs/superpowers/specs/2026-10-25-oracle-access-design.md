# Oracle home lab access

The user approved a separate, MFA-protected account restricted to a home-lab compartment and requested Terraform so the setup is reproducible.

## Approach

Use Oracle's Terraform provider with the existing Default identity domain. Manage the operator user, its group membership, a home-lab compartment, and IAM policies in a dedicated bootstrap root module. Authenticate with the existing temporary administrator profile. Future workloads use a separate Terraform root and the operator's temporary profile.

Manual console creation would work but would not record infrastructure changes. CLI scripts would also work but would require custom reconciliation. Terraform is the user's chosen approach because it tracks resources and can preview changes.

## Boundaries

- Absolute cloud cost limit: $0. The owner cannot afford charges. Never upgrade the account or rely on trial credits or budget alerts as a spending cap. Verify free eligibility, billing status, and tenancy-wide usage before applying; stop if effective cost protection cannot be established. AGENTS.md is authoritative for this constraint.
- Region: us-sanjose-1, verified as this tenancy's home region.
- User: home-lab-operator, using the owner's existing email for activation.
- Group: HomeLabOperators, containing only the new user.
- Initial permissions: read-only instance-family, volume-family, and virtual-network-family inside home-lab only. The user's later absolute $0 constraint takes precedence over the original management-access proposal. Provisioning permissions require a separate change after enforceable Always Free controls have been verified.
- Root-level permissions: compartment discovery and image reading only, as required for console navigation and selecting platform images.
- No IAM, billing, tenancy administration, or permissions to change the bootstrap stack for the operator.
- Preserve the existing administrator and the Default identity domain.
- Do not manage passwords, MFA seeds, API keys, or CLI session tokens in Terraform.
- Keep state, saved plans, local inputs, and provider binaries out of Git; protect local state with owner-only access.
- Prevent accidental destruction of the bootstrap identity and compartment through Terraform lifecycle protection.

## Enrollment and validation

Oracle handles account activation, password selection, and MFA enrollment. Verify the applicable console sign-on rules before claiming MFA enforcement. Validate Terraform formatting and schema, test security boundaries with mock-provider plans, review a live plan, apply only the authorized bootstrap resources, and verify cloud resources and a subsequent no-change plan. Operator authentication and live denial checks require the owner to finish enrollment.

## Scope

This change establishes access only. It does not provision the Wazuh VM, networking, chargeable resources, a state bucket, or new identity domains. Local Terraform state is an initial single-operator choice; a locked, encrypted remote backend can be added deliberately later.
