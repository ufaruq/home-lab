# Make the home lab reproducible before upgrading or migrating

## Goal and sequence

The goal is to understand the running host and VMs, capture applications and configuration in version control, and establish a repeatable rebuild path before changing the platform.

A useful sequence is:

1. Inventory the current system without changing it.
2. Identify configuration and state that must survive.
3. Build configuration-management recipes and VM definitions.
4. Import supported existing infrastructure and reconcile the code with reality.
5. Test a representative rebuild and recovery path.
6. Upgrade XCP-ng or carry out a separately planned migration to another platform.

For a single host, operations requiring a host reboot or replacement need a downtime plan. Configuration code reduces uncertainty but does not remove the need for installation media, storage access, credentials, or any required copies of data.

## Divide responsibilities between tools

| Tool | Responsibility | Limits |
| --- | --- | --- |
| Terraform or OpenTofu | Supported infrastructure resources: VM definitions and provider-supported networking/storage objects | Does not automatically discover every setting, configure every application, or copy guest disks |
| Cloud-init | Initial guest identity, users, access, and supported first-boot configuration | Requires suitable guest images and integration; it is not continuous management of every service |
| Ansible | Packages, application configuration, users, services, and other explicit OS-level settings | Requires access and appropriate modules/roles; it does not automatically infer how a server was configured |
| Packer, where useful | Repeatable base-image creation | Optional; useful once a stable image-building requirement exists |
| Backups, images, or secret storage | Irreplaceable state that recipes cannot regenerate | Keep secrets and sensitive Terraform state out of a public Git repository |

Use the provider for the actual platform. Xen Orchestra has an official Terraform provider; Proxmox has community providers including bpg/proxmox. Their schemas and supported resources differ. Moving between hypervisors generally means adapting infrastructure definitions, even when the guest application playbooks can be reused.

Sources: [XO Terraform provider](https://docs.xen-orchestra.com/automation/terraform-provider), [Proxmox provider](https://registry.terraform.io/providers/bpg/proxmox/latest/docs), [XCP-ng infrastructure as code](https://docs.xcp-ng.org/management/infrastructure-as-code/).

## Inventory before writing desired-state code

Capture, with secrets redacted:

- Host product/version, firmware boot mode, and relevant hardware details.
- Boot device, storage controller mode, physical disks, storage repositories/pools, and virtual disk formats.
- Management network settings, bridges or bonds, VLANs, and storage networks.
- VM names, operating systems, CPU/RAM, disk attachments, NIC attachments, startup behavior, and installation templates.
- GPU/controller passthrough assignments and the boot or device settings they depend on.
- Applications and versions, services, configuration locations, scheduled jobs, certificates, and external dependencies.
- Existing management and backup tooling.

A filename copied from a server is not necessarily a portable configuration recipe. Record why it exists, what generates it, and what it depends on. Keep private values in a suitable secret store or encrypted configuration system rather than committing them as plain text.

## Adopt existing infrastructure rather than accidentally replace it

Write resource configuration, import supported existing resources into Terraform state, and inspect the plan. Reconcile differences until it proposes no unintended changes. A no-change plan is evidence of alignment only for the settings and resources that provider actually models.

Review replacement actions particularly carefully: a mismatch in an immutable field can propose rebuilding a VM rather than merely documenting it. Importing a VM does not back up its disks or establish that its applications are reproducible.

Store Terraform state appropriately; it can contain secrets even when input variables are marked sensitive. A public configuration repository is not a suitable default destination for raw state, credentials, private keys, or unredacted host inventory.

Source: [Terraform import documentation](https://developer.hashicorp.com/terraform/language/import).

## Test the rebuild recipe

Use a representative disposable VM to test the intended image, initial access, configuration management, application startup, network reachability, and any required settings restore. Compare the result with the current VM.

This tests more than generating plausible configuration files. Unrecorded manual installation steps, licenses, private repositories, downloaded artifacts, and secrets are common reasons a configuration-only rebuild is incomplete.

If guest data is deliberately expendable, document that decision and identify the smaller set of configuration or state that remains important.

## XCP-ng upgrade context

As checked on October 25, 2026:

- XCP-ng 8.2 and 8.2.1 reached end-of-life on September 16, 2025.
- XCP-ng 8.3 LTS is supported until November 30, 2028.
- Upgrading to 8.3 requires the supported installation-ISO procedure. An in-place yum version upgrade to 8.3 is not supported.

A high-level upgrade sequence is to verify backups and configuration capture, apply available source-release updates, read the target release notes, shut down or move VMs as appropriate, boot the verified ISO in the original BIOS/UEFI mode, and choose the upgrade option for the existing installation. Afterward, apply target-release updates and verify storage, networking, guests, and passthrough.

The ISO upgrade retains XCP-ng's VM/storage configuration, but custom changes in the host system can be lost. Preserve and review boot parameters, users, packages, local files, and other custom configuration. Pools, HA, alternate drivers, and XOSTOR have additional requirements; use the official procedure for the actual deployment rather than treating this paragraph as an executable runbook.

End-of-life status establishes a support/security-maintenance concern. It does not, on its own, identify the exact missing security patches or prove exploitation on a particular host.

Sources: [8.2 lifecycle](https://docs.xcp-ng.org/releases/release-8-2/), [8.3 lifecycle and release notes](https://docs.xcp-ng.org/releases/release-8-3/), [upgrade procedure](https://docs.xcp-ng.org/installation/upgrade/).

## Where Codex fits

Codex can help inspect authorized logs and configuration, explain dependencies, draft infrastructure/configuration code, and run validation. It does not automatically convert an arbitrary host into a complete, correct Terraform/Ansible repository. Inventory, explicit assumptions, review, and rebuild testing remain necessary.

Running Codex temporarily on a host can support a local investigation, but hypervisor control domains have platform-specific support and compatibility constraints. XCP-ng documents restrictions on third-party host software. Record that tradeoff rather than assuming a general Linux installation guide implies supported installation on every hypervisor.

For an older Linux host, check the release, architecture, and system library first:

~~~sh
cat /etc/os-release
uname -m
getconf GNU_LIBC_VERSION
~~~

A glibc version such as 2.17 is a library version, not the XCP-ng release number. Do not replace the host's system glibc merely to run a CLI. OpenAI publishes standalone Linux musl builds, but a successful version command is only the first compatibility test; authentication, command execution, and sandbox support also need verification on the actual kernel.

Use the current upstream installation and authentication instructions rather than treating an old copied command as a permanent support guarantee. Remote Control is distinct from signing in: it requires supported functionality and pairing, and enabling it does not automatically move an existing conversation to that host.

Sources: [XCP-ng host requirements](https://docs.xcp-ng.org/installation/requirements/), [Codex installation](https://learn.chatgpt.com/docs/codex/cli), [standalone binaries](https://github.com/openai/codex), [authentication](https://learn.chatgpt.com/docs/auth), [remote connections](https://learn.chatgpt.com/docs/remote-connections).

## Current decision remains open

Capture the existing application setup first. Then choose between upgrading XCP-ng and migrating to Proxmox based on actual management, storage, hardware, and availability requirements.

An XCP-ng upgrade and an XCP-ng-to-Proxmox migration are different projects. Neither has been performed by writing these notes. Hardware layout and provider coverage still need inventory before either can become a concrete runbook.
