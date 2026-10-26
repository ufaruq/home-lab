# Home lab agent instructions

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
