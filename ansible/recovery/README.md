# Native startup policy

This helper reviews stock host startup/shutdown wiring against a private policy. It does not create a management appliance, restore disks, install a custom agent or change VM automatic-start flags; Terraform owns those declarations.

Supply `native_recovery_policy` in private control-host variables with expected host/pool identities, the exact approved automatic-management VM set and reviewed stock-file SHA-256 values. The helper must refuse missing/placeholder identities, unknown replacements/drop-ins or changed stock content. No deployment identity or digest is a public default.

The automatic set may contain multiple explicitly approved guests. In that case,
declare `management_vm_id` separately within that set so management bootstrap still
starts only the management VM. Terraform owns each guest's desired Running state
and `auto_poweron` flag; native recovery verifies the exact set and the stock host
boot/shutdown service. It refuses an undeclared automatic guest or an active boot
service with an approved guest still halted. A legacy single-VM policy remains valid.

An optional `guest_lifecycle` map is keyed only by approved automatic guest IDs.
It can declare `actions_after_crash: restart`, `actions_after_reboot: restart`,
and `actions_after_shutdown: destroy`. The helper verifies or restores this native
metadata without starting/stopping guests. Core dumps and forced restart after an
intentional guest shutdown are outside this policy. This catches drift in native
fields that the Terraform provider does not expose; a hung OS or failed storage
still requires a separate recovery path.

An optional private `host_storage_links` map preserves custom raw-disk aliases.
Keys must use `/passthrough-drives/<name>/<name>` and values must name a permanent
whole disk under `/dev/disk/by-id/`. The Ansible recovery playbook verifies the host
identity and block device before reconciling a symlink. It refuses regular files,
redirected parent directories, partition identifiers and any live alias that would
change the physical disk. It never formats, partitions or attaches storage.

The installer helper [upgrade_restore.py](../../scripts/xen/upgrade_restore.py)
can restore these aliases and the explicitly allowlisted network/logging assets
into a matching offline XCP-ng 8.3 target. This is separate from normal convergence;
it refuses the live root filesystem. Keep its generated bundle, public-key
authorization and expected host identity private. Rehearse against the signed
installer's service units before arming an upgrade.

`resolver_config()` validates numeric IPv4 resolvers for a generated installer-only
network hook. This avoids relying on a broken DHCP-advertised DNS service during
a network installation. The hook runs before repository verification; it must
refuse execution against an installed host. Never disable package or repository
signature checks as a DNS workaround.

```sh
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
ansible-playbook -i .local/xen/ansible/hosts.yml \
  ansible/recovery/native-boot.yml --check
```

Review the exact automatic-start set before an authorized apply. Starting stock startup wiring may start an already-approved halted management VM; unrelated guest states must remain unchanged. Preserve original private before-state and both stock shutdown actions. Do not stop/restart an active unit as casual rollback because shutdown hooks can affect guests.

A recovered VM identity can differ from its original logical identity. Bootstrap/state binding does not authorize silently changing the native startup policy: review it explicitly. Refusal is preferable to starting an ambiguous appliance.

An enabled unit or successful apply is not a full reboot, power-loss or bare-metal recovery test. Those need separate review, known-good storage, independent access and a tested backup/restore procedure.
