# Private Wazuh dashboard

`monitoring_wazuh_tailnet` configures the existing Ubuntu24.04 Noble amd64
Wazuh4.7.5-1 manager. It creates no cloud resources, disks, public ingress,
subscription, domain registration or paid service. Existing infrastructure must
already satisfy the repository's $0 policy. A verified Tailscale Free account
and sufficient remaining free device/user capacity are required before joining;
trial credits and billing alerts are not substitutes. The role cannot inspect
the tailnet's billing settings: its verification flag records an owner's current
check and is not a spending cap.

The browser opens `https://homelab-wazuh.<private-suffix>.ts.net/` while connected
to the authorized tailnet. Tailscale Serve terminates trusted HTTPS443 and
proxies only to `http://127.0.0.1:5601`. The dashboard binds to IPv4 loopback,
uses secure cookies, and retains its Wazuh login. Plaintext stays inside the
manager; indexer TLS, manager configuration and dashboard-to-indexer credentials
are preserved. Serve does not configure public Funnel, subnet routes, an exit
node or Tailscale SSH. Existing exit-node/subnet-router settings or unrelated
Serve configuration cause a stop for separate review.

## Role inputs

All approval/verification values must be actual YAML booleans. Every run
requires `monitoring_access_verified: true` and
`monitoring_deployment_approved: true`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `monitoring_wazuh_tailnet_install_approved` | `false` | Permit installation when Tailscale is absent. |
| `monitoring_wazuh_tailnet_dns_repair_approved` | `false` | After confirming DHCP DNS fails while direct public DNS and HTTPS work, permit the DNS-only repair below. |
| `monitoring_wazuh_tailnet_join_approved` | `false` | Permit enrollment of a new, unregistered node. |
| `monitoring_wazuh_tailnet_dashboard_approved` | `false` | Permit the dashboard listener/Serve transaction. |
| `monitoring_wazuh_tailnet_free_plan_verified` | `false` | Owner verified the current Free plan and remaining allowances. Required for join or dashboard work. |
| `monitoring_wazuh_tailnet_auth_key_file` | empty | Absolute controller path to fresh single-use auth key; only used for new enrollment. |
| `monitoring_wazuh_tailnet_dns_suffix` | empty | Exact private MagicDNS suffix, for example `example.ts.net`, without a trailing dot. |
| `monitoring_wazuh_tailnet_hostname` | `homelab-wazuh` | Exact node hostname; one lowercase DNS label, maximum63 characters. |
| `monitoring_wazuh_tailnet_version` | `1.104.4` | Exact reviewed package release; other versions are rejected. |
| `monitoring_wazuh_tailnet_os_version` | `24.04` | Exact supported platform; other versions are rejected. |
| `monitoring_wazuh_tailnet_wazuh_version` | `4.7.5-1` | All three central Wazuh packages must match; no Wazuh package changes. |

The caller supplies an existing manager inventory entry, gathers facts and uses
approved sudo access. This role deliberately refuses Ansible check mode;
syntax checks and offline tests are available without host access.

## Three explicit phases

1. Install: set only installation approval plus the two global gates. The role
   installs the exact signed package, enables `tailscaled`, and holds its package
   version. Join and dashboard flags remain false: it does not read a key,
   authenticate a node or change the dashboard. Existing package versions must
   match; automatic upgrade/downgrade is refused.
2. Enroll: verify Free plan/capacity in the owner's Tailscale console, confirm the
   exact MagicDNS suffix and create a fresh single-use key. A key ever pasted
   into chat or a terminal command must first be revoked. Save the fresh key
   privately outside the repository as a regular file owned by the controller
   user with mode0400 or0600. Set the controller **path**, free verification and
   join approval. Do not put key contents in Terraform variables/state/plans,
   environment variables, command arguments, logs or version control. A
   root-only temporary `/run` file is copied to the manager; `tailscale up`
   receives `--auth-key=file:/...`, and Ansible always removes this remote copy.
   Existing online nodes are validated against the exact expected hostname and
   suffix; no existing identity is forcibly logged out, reset or reauthenticated.
   Any pending device approval must be completed in the console.
3. Website: the tailnet owner first enables HTTPS certificates in the console's
   DNS settings. Enabling certificates publishes the device's DNS name in
   certificate transparency logs; it does not make the website public. Set
   dashboard approval and Free verification. A private certificate readiness
   check must succeed **before** changing dashboard settings. Missing HTTPS
   approval stops with a sanitized message and leaves the current website
   intact. A successful migration intentionally replaces the previous
   network-wide dashboard listener with the private tailnet URL.

Keep the key file private and remove it after successful one-time enrollment.
Restrict the tailnet ACL/grants to intended administrators; Serve follows
tailnet access control, including device sharing. Do not enable Funnel for
this device. This role does not modify global ACLs or billing controls.

## Confirmed DNS failure

If downloads fail with `Temporary failure in name resolution`, inspect
`resolvectl status`, DHCP DNS and routes before changing anything. Test the
actual DNS response: an upstream `SERVFAIL` differs from a blocked network.
Only after independently confirming working public DNS responses and outbound
HTTPS may the owner-approved DNS repair flag be enabled in private variables.

The optional `dns.yml` tasks install only the owned
`/etc/systemd/resolved.conf.d/60-homelab-wazuh.conf`, with `DNS=1.1.1.1 9.9.9.9`
and the route-only DNS domain `~.`. They restart only `systemd-resolved`, verify
normal resolution of the package and login hostnames, and restore/remove the
owned drop-in if verification fails. The VM's DHCP address, interfaces, IP
routes and Netplan files remain intact. More-specific per-link DNS domains keep
their normal precedence. Disabling the flag skips repair; it does not remove an
already installed configuration. Remove the owned file and restart the resolver
explicitly if returning to a repaired DHCP resolver. Do not enable this flag
as a substitute for diagnosing failed routing or an intentional DNS policy.

Upstream references: [systemd resolver configuration](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html),
[Cloudflare resolver addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/),
[Quad9's free DNS services](https://docs.quad9.net/services/). The repair uses
standard DNS; package HTTPS verification, signed APT metadata and the signing-key
digest remain enforced independently.

## Validation and recovery

The editor preserves unrelated YAML text, comments, indexer TLS and secrets,
and rejects duplicate managed keys or ambiguous managed layouts. The native
dashboard Node.js YAML loader validates the staged file and confirms every
unrelated parsed value is unchanged. Existing config ownership/mode is retained
for service readability. Backups and staging live in the root-only
`/var/lib/homelab-wazuh-tailnet/` directory with mode0600 files:

- `original-dashboard.yml` is preserved once for operator recovery.
- `previous-dashboard.yml` is replaced with the pre-transaction config each run.
- `staged-dashboard.yml` contains the validated desired config.

Activation restarts the dashboard only when its config changed, checks its
loopback HTTP health, and verifies the resulting Serve mapping. Failure removes
only a newly attempted managed HTTPS443 listener and restores/restarts the
previous dashboard config. An existing exact managed mapping is retained.
The daemon enrollment is intentionally retained after a dashboard rollback.
Service restart success does not prove the browser can reach the service:
finally open the private HTTPS URL from an authorized connected client and
confirm trusted TLS plus the normal Wazuh login. No certificate-warning bypass
is part of this workflow.

Run offline verification from the repository root with the existing Ansible
Python environment:

```sh
/Users/umarfaruq/.config/home-lab/monitoring/venv/bin/python -m unittest discover -s ansible/tests -p 'test_*.py'
```

## Reviewed upstream inputs

Reviewed2026-11-02:

- [Official stable package repository](https://pkgs.tailscale.com/stable/):
  Noble amd64 package metadata lists version`1.104.4`, SHA256
  `8768973def76dd530b53a0fe74ca396252fff050f955aeebfabd33c77960625d`.
  Installation uses authenticated APT metadata and a `signed-by` restricted key.
- [Official Noble signing key](https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg):
  downloaded over verified HTTPS and SHA256 pinned as
  `3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39`.
  The repository advertises `.sha256` for package artifacts; this signing-key
  `.sha256` endpoint returned404, so its digest was computed locally from the
  official HTTPS download. Key rotation requires a new reviewed digest.
- [Serve and HTTPS approval](https://tailscale.com/docs/features/tailscale-serve).
- [Auth-key file support](https://tailscale.com/docs/reference/tailscale-cli/up).
- [Client settings](https://tailscale.com/docs/reference/tailscale-cli).

No live package installation, enrollment or dashboard mutation is performed by
the offline tests.
