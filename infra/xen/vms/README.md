# Guarded Xen Terraform configuration

This root manages supported existing VM/network declarations through Xen Orchestra. It creates no cloud resources, storage repositories or disk-image uploads and does not format storage. Unsupported raw storage, passthrough and host topology remain explicitly protected.

Supply `inventory_file` and `desired_state_file` as explicit private inputs. No real inventory or operating policy is committed. Invented fixtures under `tests/fixtures/xen/` exist only for tests; they must not become live fallback configuration.

Private discovery maps bind original logical IDs to current remote IDs. Imports use current discovered identities, while ownership outputs retain stable original logical identities. Restore the appropriate private state before recovery/bootstrap and reject ambiguous or stale bindings.

The [desired policy](../../../xen-server/desired-state.md) defines supported CPU/RAM/power/autostart overrides and verified recovery recipes. Existing disk/NIC identity, size, order and unsupported settings must remain unchanged. A missing ordinary VM needs an available verified recovery image; a historical OS-template label is not such a recipe. Protected devices cannot be recreated implicitly.

Use the [controller workflow](../../../xen-server/automation-workflow.md) for guarded live operations. Direct Terraform validation/planning alone does not authorize apply. The convergence guard checks complete ownership, current imports, exact desired values, permitted attachment transitions and unsupported actions. Deletion, replacement, unknown resources and unreviewed recovery are rejected.

The strict adoption path permits identity-checked state import with no remote changes. Convergence is a different path that can perform explicitly reviewed bounded changes. Review the exact saved plan in either case.

Keep `.terraform/`, state, variable files, plans, tokens, actual discovery bindings and run evidence private and ignored. A clean import/no-op plan does not prove guest health, application recoverability or a tested full restore.
