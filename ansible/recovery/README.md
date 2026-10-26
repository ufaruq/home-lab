# Native startup policy

This helper reviews stock host startup/shutdown wiring against a private policy. It does not create a management appliance, restore disks, install a custom agent or change VM automatic-start flags; Terraform owns those declarations.

Supply `native_recovery_policy` in private control-host variables with expected host/pool identities, the exact approved automatic-management VM set and reviewed stock-file SHA-256 values. The helper must refuse missing/placeholder identities, unknown replacements/drop-ins or changed stock content. No deployment identity or digest is a public default.

```sh
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
ansible-playbook -i .local/xen/ansible/hosts.yml \
  ansible/recovery/native-boot.yml --check
```

Review the exact automatic-start set before an authorized apply. Starting stock startup wiring may start an already-approved halted management VM; unrelated guest states must remain unchanged. Preserve original private before-state and both stock shutdown actions. Do not stop/restart an active unit as casual rollback because shutdown hooks can affect guests.

A recovered VM identity can differ from its original logical identity. Bootstrap/state binding does not authorize silently changing the native startup policy: review it explicitly. Refusal is preferable to starting an ambiguous appliance.

An enabled unit or successful apply is not a full reboot, power-loss or bare-metal recovery test. Those need separate review, known-good storage, independent access and a tested backup/restore procedure.
