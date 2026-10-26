# Desired-state contract

Keep the real policy in an ignored local file selected with `XEN_POLICY_FILE`. The public policy fixtures are invented test data, not deployment recommendations.

A policy has `schema_version: 1`, a `vms` map keyed by original logical VM identity, a `networks` map and an explicit `guest_targets` list. Supported VM overrides are:

| Field | Meaning |
| --- | --- |
| `cpus` | Positive desired vCPU count |
| `memory_min`, `memory_max` | Positive byte counts with minimum not greater than maximum |
| `power_state` | Explicit desired `Halted` or `Running` |
| `auto_poweron` | Strict Boolean automatic-start policy |
| `recovery` | Operator-verified existing recovery-template identity and verification declaration |

Automatic startup must agree with the desired Running state. An actual autostart toggle requires an explicit policy declaration. Starting a halted VM may attach its unchanged disks/NICs; this does not authorize changing their identities, sizes, order or networks.

Omitted supported values preserve the reviewed observed baseline. Original logical identities remain stable after recovery, while private discovery binds them to current remote identities. Imports must use those current bindings.

Recovery must be genuinely necessary and must use a verified available image. An OS-install placeholder, historical template label or existing definition is not proof of application/data recoverability. Protected raw storage and unsupported passthrough devices must not be reconstructed implicitly. Physical-network changes, disk removal/resizing and replacement remain outside the guard's permitted boundary.

`guest_targets` contains reviewed inventory aliases, not guesses from VM labels. Private guest policy must separately establish access, configuration verification and intended state. Captured accounts, packages and file checksums are evidence; they are not permission to replay an entire operating system or configuration archive.

See [workflow](automation-workflow.md), [Terraform](../infra/xen/vms/README.md) and [Ansible](../ansible/README.md). Store actual identities, addresses, images, credentials and observations only in private ignored inputs.
