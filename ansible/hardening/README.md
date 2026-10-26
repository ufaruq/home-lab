# Narrow logging hardening

This helper validates and optionally wraps an existing reviewed log-rotation policy with shared locking and bounded execution. A read-only health helper reports filesystem byte/inode use and logging-service status. It is not continuous monitoring or proof that storage hardware is healthy.

Check is the default. Apply requires both explicit hardening and verified-workflow gates. Preflight validates existing files, ownership, policy and parser behavior before any write; unexpected state stops the operation. Retention, paths and package compatibility must be reviewed for the target instead of copied from a real deployment's notes.

```sh
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
ansible-playbook -i .local/xen/ansible/hosts.yml \
  ansible/hardening/apply.yml --check --diff
ansible-playbook -i .local/xen/ansible/hosts.yml \
  ansible/hardening/health.yml
```

Health reads may produce private controller artifacts. Keep them outside public paths. A warning, query failure or inactive required service must remain visible; do not report an unreachable host as healthy.

Before an authorized apply, preserve the helper's private original-file/metadata backup. Writes are atomic per file, not a transaction across the entire operation. Rollback must use the exact reviewed private backup and refuse destinations changed since deployment. Never publish backup manifests, actual digests, host output or investigation history.

More frequent normal checks do not guarantee bounded space during bursts, rotation failures or I/O faults. This code does not repair disks, change storage, reboot hosts or authorize changes to guest configuration.
