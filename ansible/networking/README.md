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

The optional private `host_network_recovery` policy supplies the expected host UUID,
four reviewed assets and accepted prior hashes to `recovery-service.yml`. Assets are
limited to the recovery script, private profile, service and timer. Unknown content,
redirected paths and service overrides stop processing before changes. Apply makes
a private original-state backup and installs the declared files atomically.

The oneshot does not remain active after exit. Its enabled systemd timer retries
30 seconds after completion, starting 45 seconds after boot. XCP-ng can reconcile
native PIF addresses after `xapi.service` has started and remove an extra recovery
alias; a successful early oneshot alone therefore does not prove enduring access.
This timer restores only declared aliases on the MAC-selected port/bridge. It does
not restart networking, change native management ownership or restart VMs.

The controller's owner-only connection profile may set `XEN_SSH_BIND_INTERFACE`
to its USB Ethernet interface. OpenSSH then uses `-B` for the cached host transport,
avoiding an overlapping link-local route through Wi-Fi. This needs no global route
change or Mac administrator authorization. Verify the actual interface on each
controller; its name is private deployment data, not a public default.

Verify repair by removing only the extra recovery alias while connected through an
independent management path. Confirm the timer restores it, an interface-bound fresh
SSH login succeeds, native addresses and all guest power states stay unchanged, and
the subsequent Ansible check is clean. Then verify the complete cold-boot path.

After an authorized change, verify live routes, DNS source selection and the recovery path. A successful local profile comparison is not a reboot, outage or end-to-end reachability test. The helper does not authorize VM power changes or guest NIC mutation.
