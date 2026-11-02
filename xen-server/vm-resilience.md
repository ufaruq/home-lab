# Guest startup and recovery

The private desired policy identifies each approved guest by its logical UUID and
declares `power_state: Running` and `auto_poweron: true`. Other guests retain their
own explicit policy. Terraform manages these settings, VM protection flags and the
reviewed NIC/disk bindings. Private deployment values and before/after evidence
remain ignored; public source contains only the reusable implementation.

The private `native_recovery_policy` declares the same exact automatic VM set, a
separate `management_vm_id`, expected host/pool identities and reviewed stock-file
hashes. Ansible verifies the pool autostart flag and enabled, unmasked stock host
boot/shutdown service. Management bootstrap starts only the management VM, even when
several application guests are automatic.

Native `guest_lifecycle` declarations can require restart after a hypervisor-observed
crash or guest reboot while preserving a stopped state after intentional guest
shutdown. The recovery helper verifies or restores these metadata settings without
rebooting a guest or producing a memory core dump. It does not diagnose a hung OS
or recover failed storage. Autostart runs on host boot; `make up` restores desired
Running states on demand. No continuous polling watchdog is installed.

## Host upgrade acceptance

The recovery chain is physical power, boot storage, host networking and XAPI,
native guest autostart, then the management guest's networking, Tailscale and XO.
It must work without a connected controller or a manual `make up`. Ansible
declares and repairs the configuration; the host and guest services execute it at
boot. Tailscale remains in the management guest, so it cannot provide access while
the hypervisor or that guest is unavailable.

Before a major host upgrade, preserve an off-host control-domain backup and pool
database, the private configuration/state and independent management-guest disk
copies. Verify the installer signature, upgrade mode and existing installation
identity. Custom root-filesystem paths may be discarded by the installer: include
network recovery, log rotation, SSH access and any raw-disk aliases in a reviewed
offline recovery bundle. Use permanent disk identities rather than `/dev/sdX`.
Recheck stock service/script hashes against the new release's signed packages.
If the upgrade uses the official network-install source, verify its metadata and
boot-file hashes against the signed ISO and test the host's uplink first. An
installer-only DNS override can use the private reviewed resolver list when DHCP
advertises a broken resolver. Keep it separate from persistent host configuration;
the recovery hook restores that configuration into the upgraded system. Do not
disable TLS or RPM/repository signature checks to work around connectivity errors.

After patching, reboot the physical host and observe all of the following:

- Host SSH, management networking, public DNS, logging and storage return.
- The exact approved VM set starts; intentionally halted VMs remain halted.
- Management guest SSH, Tailscale enrollment and the authenticated XO inventory
  return without reauthorization or a manual service start.
- Application endpoints become reachable and a subsequent recovery check/plan
  reports no unexpected changes. Endpoint reachability alone is not an application
  or storage-integrity check.

Record timings, package/kernel versions, failures and remediation privately.
Reboot success does not prove recovery from a failed disk or a sudden power cut.
For recovery when electricity returns, firmware must also have its AC-recovery
policy set to power on; inspect that setting separately. Check the management
device's Tailscale node-key expiry in the tailnet admin console. A server with an
expiring key will eventually require reauthorization; disabling expiry is an
explicit device-level admin choice, separate from starting `tailscaled` at boot.

## Reviewed remediations

- A guest using DHCP must attach its NIC to the intended DHCP-enabled network.
  Preserve MAC, interface device number, disk bindings and an original private
  capture when relocating a reviewed NIC. Record the new binding in the private
  Terraform hardware declaration so future recreation uses the same topology.
- Use the explicit `allow_graceful_shutdown` override to remove only reviewed
  `clean_shutdown` and `clean_reboot` blocks. This allows orderly host maintenance
  while retaining forced-power, deletion and other unrelated protections.
- Keep guest network/DNS configuration in reviewed Ansible declarations when an
  OS change is necessary. The optional XOA network declaration is documented in
  [remote access](remote-access.md); its non-root role verifies network drift and
  privileged bootstrap can restore the reviewed files. It grants no arbitrary
  network-edit sudo permission.
- Test DNS separately from LAN connectivity. A DHCP lease and a reachable web UI
  do not prove the advertised resolver can resolve public names. Router DNS repair
  requires authenticated router access; record its eventual intended settings in
  that device's configuration workflow.

## Verify changes

```sh
make plan
make up
make recovery-check
make plan
```

Review the plan before apply. For autostart/protection remediation, ensure only the
approved flags change, with no VM recreation, disk replacement, resizing or unrelated
NIC change. The second plan should report no changes. Keep state/backups outside Git.

A guest-only maintenance exercise can gracefully stop the approved application
subset, leave the management VM running, and invoke the unchanged stock autostart
script after checking the pool flag and exact VM allowlist. Verify that all approved
guests return, all unselected power states remain unchanged, and application endpoints
are ready. The stock script is best effort and can suppress startup errors, so its
exit code alone is insufficient. Restarting the entire host boot/shutdown unit would
run its whole-host shutdown preparation; it is not a guest-only test.

Use current guest-agent timestamps, DHCP/ARP evidence tied to the expected VM NIC
MAC, guest consoles and application probes as appropriate. Desktop login readiness,
an HTTP login redirect, certificate trust, application internals and storage-pool
integrity are separate observations. An anonymous probe against a self-signed
certificate must not be described as certificate-trust verification.

If startup fails, inspect the VM's allowed/blocked operations, current tasks, disk
availability and storage PBD attachments, host free memory, `xapi-domains.service`,
`/var/log/xensource.log`, Xen logs and kernel storage messages. Preserve the original
state and use graceful shutdown; full physical-host reboot/power-loss testing needs
its own maintenance window and a working recovery path.
