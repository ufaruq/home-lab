# Reviewed native host networking

The helper compares a private network profile with existing XenAPI host/PIF state. The actual `profile.json` is ignored and must be supplied by the operator. It is not a public example or a source of live defaults.

Review expected host/pool identities, each PIF UUID/MAC/network/management role, address mode, static settings and route/DNS preferences. DHCP lease observations must not be mistaken for desired static values. Keep an independent recovery path and detect duplicate guest/host addresses before changing networking.

Check is the default. Identity, topology, attachment, management-role or unreviewed preference mismatches must stop processing. Apply requires its explicit gate, a reviewed profile and verified recovery prerequisites. Do not use this helper to unplug interfaces, reassign management ownership or reconstruct physical topology.

```sh
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
ansible-playbook -i .local/xen/ansible/hosts.yml \
  ansible/networking/apply.yml --check
```

A deployment may require a root-private `/etc/home-lab/direct-cable-network.conf` containing reviewed `RECOVERY_PORT_MAC` and `RECOVERY_ADDRESSES` values. The recovery script has no saved deployment address/MAC fallback. Keep the real profile, host keys, before-state and diagnostic output private.

After an authorized change, verify live routes, DNS source selection and the recovery path. A successful local profile comparison is not a reboot, outage or end-to-end reachability test. The helper does not authorize VM power changes or guest NIC mutation.
