# XOA remote access

XOA can be reached through its own Tailscale endpoint. The travelling administrator's
Mac and XOA must be in the same permitted tailnet. Xen Orchestra's existing web
authentication still applies. The direct endpoint provides access to XOA; it does
not advertise the home LAN or configure an exit node.

Actual addresses, guest UUID, public key, private-key path and verified SSH host pin
are supplied in an owner-only inventory outside Git. The private SSH key stays on
the controller. The root-owned Tailscale node state remains in the guest. Neither
credential belongs in Terraform state, saved plans, source code or diagnostic posts.

## Configuration ownership

Terraform owns the XOA VM and its virtual hardware. The
[XOA access playbook](../ansible/playbooks/xoa-access.yml) owns the dedicated guest
account/public key and signed Tailscale package source during an explicitly
authenticated root bootstrap. It installs a sudo rule allowing the non-root account
only these exact commands: `apt-get update`, installation of the `tailscale` package,
and enabling/starting `tailscaled.service`. It provides no general sudo or shell.
The separate [source-update workflow](xo-source-updates.md) adds only its fixed
root-owned `--apply` and `--status` entrypoints after provisioning.

Ordinary Ansible runs ensure the package is present and the service is active and
enabled. They verify that enrollment is Running. A missing node identity requires
owner enrollment; the playbook does not invent credentials or restore node secrets
from Terraform state. Installed packages are not automatically upgraded on every run.

```sh
make xoa-syntax
make xoa-status  # Read-only checks
make xoa-up      # Repair the declared package/service state
```

`make up` invokes this convergence after the existing Xen workflow when an owner-only
`.local/xen/xoa-access-inventory` pointer or `XOA_ANSIBLE_INVENTORY` selects a private
inventory. Without that explicit configuration, the optional stage is skipped.
These commands run on demand; no Ansible schedule or persistent controller agent is
installed. Tailscale's daemon runs at boot and handles its own network reconnection.

The private inventory may also declare the reviewed XOA network files in
`xoa_network_files` (the three allowed persistent files, with `dest` and
`content_b64`), plus `xoa_network_gateway`, `xoa_network_interface` and
`xoa_network_resolvers`. Privileged bootstrap can restore those files and the
reviewed route/DNS. Ordinary non-root runs verify their contents and runtime
route/resolvers; they report drift without granting arbitrary network-edit sudo.
The pre-change backups and working configuration are private. This captures the
recovery-interface default-route/DNS remediation as a repeatable declaration.

The private JSON inventory must contain exactly one host under
`all.children.xoa_remote_access.hosts`. Declare its `ansible_host`, `ansible_user`,
`ansible_ssh_private_key_file`, strict `ansible_ssh_common_args`,
`xoa_expected_vm_uuid`, `xoa_access_user`, and `xoa_access_public_key`. The inventory
and pointer must be owner-only. The guest UUID is checked before mutation.

Initial bootstrap requires an existing, verified guest root login:

```sh
python3 scripts/xen/xoa_access.py apply --bootstrap
```

This is separate from hypervisor root and the Xen Orchestra web/API account. The
command never stops a VM, mounts a guest disk, resets a password or seeds its own
initial access. Emergency offline key installation requires an approved XOA outage,
a rollback snapshot, complete filesystem unmount and native disk detach before the
VM starts. Remove temporary root authorization after verifying the permanent login.

## Enrollment and access

With an authenticated guest administrator shell, enroll through the normal owner
browser flow, selecting the same tailnet as the travelling Mac. Keep the CLI request
running until approval completes. A short CLI timeout can leave a stale pending
login URL. Keep DNS preferences explicit; the current setup preserves the guest's
reviewed DNS and does not accept tailnet DNS into its resolver configuration.

Use the endpoint recorded in the private inventory/evidence. Existing validated HTTPS
can be used, or the XOA HTTP service can be reached directly over the encrypted
Tailscale connection. Avoid a public SSH/admin port forward. The dedicated SSH key
must use the saved verified XOA SSH host-key pin even when its transport address changes.

Review the complete tailnet policy to restrict approved administrator devices to the
required XOA web/SSH ports. A new narrow rule does not override an existing broad
allow rule. No tailnet-wide access policy has been replaced by this playbook.

## Debugging

1. Confirm Tailscale is connected on the travelling device, then use `tailscale ping`
   against the private XOA endpoint. A relay connection can work even when a direct
   connection is unavailable.
2. Run `make xoa-status`. A guest UUID mismatch is a hard stop. A missing package or
   inactive service can be repaired only through an existing reachable SSH path.
3. With guest administrator access, inspect `systemctl status tailscaled.service`
   and `journalctl -u tailscaled.service`. Verify `systemctl is-enabled tailscaled.service`.
4. Inspect `ip route show default`, `/etc/network/interfaces`, the DHCP interface
   declaration, and `/etc/resolv.conf`. A default route through an isolated recovery
   interface prevents outbound Tailscale traffic. Check `getent hosts pkgs.tailscale.com`
   and verified HTTPS to the official package server. Current network configuration
   and pre-change backups are private; this package/service playbook does not grant
   its non-root account arbitrary network-repair privileges.
5. If SSH authentication fails, verify the selected private key, account and host
   fingerprint. The public key belongs in that guest account's `authorized_keys`;
   an XO web/API login does not authenticate a Linux SSH session.

Test from a phone hotspot or another external network before travelling. If XOA,
the XCP-ng host, home internet or home power is down, this endpoint cannot provide
its own recovery path. A physical OPNsense or separate always-on management gateway
is a future independent recovery route. Its installation is separate from this setup.

References: [Tailscale Linux packages](https://pkgs.tailscale.com/stable/),
[Tailscale access controls](https://tailscale.com/docs/features/access-control),
[XOA administration](https://docs.xen-orchestra.com/updater/).
