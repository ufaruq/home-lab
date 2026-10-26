# Automation choices and boundaries

Terraform is useful for declarative resource ownership, private state and reviewable plans. The Xen Orchestra provider covers a subset of Xen configuration; native XenAPI helpers handle narrowly reviewed gaps. Ansible configures selected verified guests and host policy. Avoid giving multiple tools ownership of the same setting.

A central controller keeps dependencies out of the hypervisor control domain and allows one reviewed workflow. It also needs protected credentials, pinned host identities, recoverable state, serialized writes and access independent of the management appliance.

Read-only inventory and offline captures help discover current configuration. They do not establish intended policy, repository availability, image suitability, runtime health or full application recoverability. Unsupported platforms should remain observed-only until their own policy and tests exist.

## Scheduling

Begin with explicit manual checks. If recurring checks are needed, schedule read-only discovery/plans and define where private results go and how failures are surfaced. A failed check must not become a clean status. Unattended correction requires separate authorization, review and recovery design; no scheduler is implied by the presence of a command.

An agent inside every guest is unnecessary for this workflow. Pull-based configuration or an orchestration service can be evaluated later when its trust, reachability and lifecycle costs are understood. Neither solves missing backups or a physical storage fault.

## Recovery

Distinguish adoption, drift repair, missing-resource recovery and full rebuild. Existing-template names are not verified recovery images. A successful import/no-op says nothing about whether guest data can be recovered. Use explicit recipes and isolated restore tests, preserving unsupported raw storage and passthrough boundaries.

The [workflow](automation-workflow.md) implements these limits. Real research notes, deployment observations, logs and inventory remain private and ignored. Public tests use invented fixtures only. No paid service or new cloud resource is required by the local workflow.
