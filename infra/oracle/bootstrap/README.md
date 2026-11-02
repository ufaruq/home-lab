# Oracle home lab access

This bootstrap configuration creates a `home-lab` compartment, a
`home-lab-operator` user in the existing Free identity domain, a dedicated
`HomeLabOperators` group, and two access policies. It does not create a new cloud
account, identity domain, VM, network, storage volume, or subscription.

The absolute cloud cost limit is **$0**. Follow the root [AGENTS.md](../../../AGENTS.md)
before any apply. Never upgrade the account, use trial credits to justify a paid
resource, or treat a budget alert as a spending cap.

## Permissions

The operator starts with **read-only** access to compute, volumes, and networking
inside `home-lab`. It can inspect compartment metadata and read platform images
across the tenancy for console navigation. It cannot create workloads, administer
IAM, change quotas, or manage billing. Account-wide read access to compartment
names and images does not allow changing other compartments.

Provisioning permissions must be a separate, reviewed change after enforceable
Always Free controls have been verified. This configuration intentionally offers
no switch that enables broad management permissions.

The existing administrator remains responsible for this bootstrap root. Future
Wazuh infrastructure belongs in a separate root with separate state and a
restricted operator profile. The operator must not be able to modify its own
permissions or the cost safeguards.

## Authentication and initialization

Install Terraform and Oracle's OCI CLI from their official distributions. Use a
temporary browser-authenticated administrator session; do not create a permanent
API key for this task.

```sh
oci session authenticate --region us-sanjose-1 --profile-name home-lab-bootstrap
cd infra/oracle/bootstrap
umask 077
cp terraform.tfvars.example terraform.tfvars
```

Fill in the existing tenancy and identity domain OCIDs and your email address in
the ignored local `terraform.tfvars`. Identifiers are not passwords, but the local
file contains personal account metadata and should remain private.

```sh
terraform init
terraform fmt -check -recursive
terraform validate
terraform test
terraform plan -out=bootstrap.tfplan
terraform show bootstrap.tfplan
```

Before applying, verify the tenancy's current subscription/payment model and
Free identity-domain entitlement, including existing user counts. The plan must
create only the compartment, operator, group, and two policies. Do not accept a
replacement, deletion, identity-domain upgrade, or any billable resource.

```sh
terraform apply bootstrap.tfplan
terraform plan -detailed-exitcode
```

The final command should exit 0 with no changes. If the session expires, refresh
it with `oci session refresh --profile home-lab-bootstrap --auth security_token`
or sign in again. Generate and review a fresh plan if configuration changes.

## Account activation and MFA

Oracle sends the owner the new user's activation email. Complete activation,
password selection, and MFA enrollment directly with Oracle. The username is
`home-lab-operator`; it differs from the original administrator's email-based
username even though both use the owner's mailbox.

If an activation email does not arrive, use the administrator console to locate
this exact user and resend its activation invitation. Do not reset the original
administrator's password. Verify the applicable console sign-on rule requires
MFA for non-administrators before using this account.

The module reads the existing console policy, its two security-default rules,
and the catch-all login condition. It checks the rules' order, required MFA,
mandatory enrollment, and that the non-admin rule matches all logins. Oracle's
built-in rules omit their individual `active` field, so the guard uses membership
in the active policy rather than treating that missing field as proof of an
enabled rule. Actual MFA enforcement must also be confirmed during the operator's
first login. No sign-on settings are modified. Mock tests cover missing MFA,
an extra preceding rule, an unrelated condition, and a paid domain type.

After enrollment, authenticate the operator separately:

```sh
oci session authenticate --region us-sanjose-1 --profile-name home-lab-operator
```

Select the new operator in the browser login. Its CLI commands must include
`--profile home-lab-operator --auth security_token`. Verify it can read the lab
and cannot list IAM policies or manage identities before treating the access
setup as fully verified. Never run this bootstrap configuration with the operator
profile.

## State and lifecycle

Keep `.terraform.lock.hcl` in Git. Local inputs, provider binaries, saved plans,
and state are ignored. Credentials stay in `~/.oci/`, outside Terraform. No
password, MFA seed, permanent API key, or session token is a Terraform resource
or input.

The local state still contains email addresses and identity metadata. Use
owner-only file permissions, encrypted local storage, and a secure backup outside
Git. Keep saved plans private too. This is a single-operator local backend; a
remote backend and its costs/security must be reviewed separately before use.

Lifecycle protection prevents Terraform from accidentally deleting the user,
group, compartment, or policies. Intentional removal requires an administrator
and an explicit configuration change. Keep this state: deleting it does not
delete the cloud resources and makes subsequent reconciliation harder.

Oracle automatically adds and changes SCIM schema namespace metadata as it
populates extensions. Only the user/group `schemas` metadata is ignored during
reconciliation; membership, account attributes, and access policies remain
managed. Group members are explicitly requested from Oracle so membership drift
is visible.

References: [OCI provider authentication](https://docs.oracle.com/en-us/iaas/Content/dev/terraform/configuring.htm),
[Free identity domains](https://docs.oracle.com/en-us/iaas/Content/Identity/sku/overview.htm).
