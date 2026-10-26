# Xen configuration workflow

Terraform describes supported Xen Orchestra resources. Ansible handles selected guest configuration and narrowly scoped native host policies. A plan guard rejects destructive or unsupported changes before an apply.

This public tree contains reusable code, documentation and invented test fixtures. It contains no deployment inventory, desired operating policy, credentials, host keys, recovery history or backup images. Supply those privately; an offline test does not establish that a real deployment or restore works.

## Controller setup

Run tools on a separate controller, not the hypervisor control domain. Use a supported Python environment and the pinned dependencies:

```sh
python3.13 -m venv .local/controller
. .local/controller/bin/activate
python -m pip install -r ansible/requirements.txt
export ANSIBLE_PLAYBOOK_BIN="$(command -v ansible-playbook)"
make check
```

Tests use explicitly synthetic fixtures under `tests/fixtures/xen/`. They must never become a fallback for live discovery or apply.

## Supply private inputs

Keep connection credentials and pinned host keys in owner-only files outside the checkout. Keep local deployment inputs in ignored paths, or select private paths explicitly:

- `XEN_CONNECTION_FILE`: private connection/authentication settings.
- `XEN_INVENTORY_FILE`: reviewed XenAPI inventory; default `xen-server/inventory/local.json`.
- `XEN_POLICY_FILE`: reviewed desired policy; default `xen-server/desired-state.json`.
- `XEN_ANSIBLE_INVENTORY`: generated private Ansible inventory.
- `XEN_HOST_VARS_FILE`: optional private control-host variables.

The [workflow](xen-server/automation-workflow.md) explains connection settings and native policy requirements. Generate an example inventory without connecting to a server:

```sh
python ansible/files/generate_inventory.py \
  --inventory tests/fixtures/xen/inventory.json \
  --captures tests/fixtures/xen/guest-inventory \
  --output .local/example-inventory
```

After supplying and reviewing real private inputs:

```sh
make readiness
make plan
# Review the exact guarded plan and intended guest selection before applying.
make up
```

`make up` can change explicitly authorized settings and start a management appliance declared Running. It does not install the hypervisor, manufacture missing recovery images, format storage or restore arbitrary application data. Keep recoverable private state and backups before using it.

## Documentation

- [Scope and ownership](xen-server/README.md)
- [Controller workflow](xen-server/automation-workflow.md) and [desired policy](xen-server/desired-state.md)
- [Debugging](xen-server/debugging-runbook.md) and [backups](xen-server/backups.md)
- [Terraform](infra/xen/vms/README.md) and [Ansible](ansible/README.md)
- [Tool and scheduling choices](xen-server/automation-research.md)
- [Reference guides](docs/README.md)

Private inventory, captures, logs and investigation notes remain local in ignored paths. Do not stage them to make a command work. The repository's [zero cloud-cost requirement](AGENTS.md) applies throughout; these Xen workflows target existing local infrastructure.
