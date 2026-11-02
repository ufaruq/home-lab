# Local Wazuh configuration

**Placement update:** the owner selected Oracle for the new central server. Use
the [Oracle deployment guide](../../infra/oracle/wazuh/README.md) and explicit
`oracle_wazuh` target. The captured local 4.7.5 manager remains recovery evidence;
the adoption instructions below describe role behavior, not the current manager
deployment target. No cloud server or agent migration has been deployed.

These roles manage the existing local Wazuh VM and explicitly selected endpoints. They create no cloud resources. The captured manager/indexer/dashboard versions are **4.7.5**; captured agents include **4.7.4** and **4.7.5**. Offline package evidence does not establish live health. Preserve this installation through `monitoring_wazuh_mode: adopt` (default). An upgrade is a separate backup, compatibility and migration review.

Both `monitoring_access_verified` and `monitoring_deployment_approved` must be actual YAML booleans `true`. Use the repository deployment controller, an exact host limit, verified SSH/WinRM identity and a mode-0600 private inventory/vars file outside the checkout. Never disable host or TLS verification. Ansible requires Linux root privilege through the existing verified account; Windows uses the `ansible.windows` collection and the existing WinRM HTTPS configuration.

## Adopt central components

Declare `monitoring_wazuh_manager_version: '4.7.5'`. The manager role reads package versions and requires the manager, indexer and dashboard to match that exact release. It never invokes a package manager installation in adoption mode. Existing `ossec.conf`, auth/enrollment settings, TLS certificates, API credentials, agent identities and unrelated custom rules remain in place.

Repository-owned files are `etc/rules/homelab_rules.xml`, `etc/decoders/homelab_decoders.xml` and `etc/shared/homelab-{linux,windows,lab}/agent.conf`. The role stages the existing custom rules/decoders with the new files and validates the complete staged set with the **installed** `wazuh-analysisd -t -c` before installing them. Group configurations are checked with `verify-agent-conf -f` before installation. Live manager configuration is not rewritten. Changed owned files receive mode-0640 backups beside the originals. Failed activation restores previous owned files and reports failure; preserve these private backups for recovery.

Linux policies collect authentication/audit logs, limited `/etc` FIM and inventory. Audit collection consumes an existing auditd log; the role does not install auditd or change kernel auditing. Windows collects selected Security events, inventory and bounded FIM. Existing endpoint log settings are preserved, so review total volume before assigning these groups. Assign `homelab-lab` to Parrot and malware lab Linux endpoints; Windows uses `homelab-windows`. Wazuh 4.7.5's execution daemon reads active-response disablement from **local** `ossec.conf`; centralized group policy cannot reliably disable execution. Adoption preserves that local policy by default. For adopted endpoints, explicitly set `monitoring_wazuh_disable_active_response_approved: true` to authorize the narrow `disabled=yes` edit. An adopted lab endpoint fails closed if active response is enabled and that scoped edit has not been approved. Newly installed agents default to disabled response as part of their approved fresh installation. Linux checks the staged edit with `wazuh-execd -t -c` before installation; Windows parses the resulting XML and restores the backup if service restart fails. Backups remain private beside the original config. Multiple active-response sections or unrecognized values fail for manual review.

Existing enrollment/group membership is preserved by default. To activate the central policy for adopted agents, provide explicit manager-side IDs (never infer IDs from cached hostnames):

```yaml
monitoring_wazuh_group_assignments:
  - id: '003'                    # verified live agent ID; example only
    group: homelab-lab
    active_response_disabled_verified: true # only after endpoint role/readback confirms local disabled=yes
```

The official `agent_groups` CLI adds only the requested group; it does not replace other memberships. Lab assignments additionally require per-entry `active_response_disabled_verified: true` after verified endpoint readback; creating a central lab policy alone does not disable response. Review precedence if an agent belongs to other groups. Read `agent_groups -S -i ID` and manager/agent status after deployment to confirm synchronization and connectivity; local service start is not proof of manager connection.

## Adopt or install endpoints

Declare `monitoring_wazuh_agent_version`, `monitoring_wazuh_manager_version`, `monitoring_wazuh_manager_address` and optionally `monitoring_wazuh_manager_port` (1514). This implementation conservatively requires the same minor release and an agent patch no newer than its manager. Existing packages must match the declared version; the role fails on drift instead of upgrading. It checks the existing manager connection, validates Linux configuration, enforces reviewed active-response intent as described above, starts the service and confirms a nonempty existing `client.keys`. It never replaces that identity. A mismatched connection or broken enrollment needs a separate reviewed migration.

An absent agent requires `monitoring_wazuh_agent_install_approved: true`, a SHA-256 pin in `monitoring_wazuh_agent_package_sha256`, a private `monitoring_wazuh_enrollment_password`, `monitoring_wazuh_manager_ca_source` pointing to the reviewed manager CA PEM on the controller, and `monitoring_wazuh_enrollment_tls_verified: true` after the enrollment trust checks below. Declare `monitoring_wazuh_agent_group` (`homelab-linux`, `homelab-lab`, or `homelab-windows`). Supported installation targets are x86_64 Debian-family DEB, RedHat-family RPM and Windows MSI. The role derives the exact official package URL from the declared version; it does not use `latest` or enable a broad package repository. RPM signature verification remains enabled and needs the approved Wazuh signing key already installed on the guest. Download the release checksum from the [official package list](https://documentation.wazuh.com/current/installation-guide/packages-list.html) and independently review it before setting the private input. The controller never invents a checksum.

Fresh installation refuses retained `/var/ossec` or Windows agent directories. This prevents accidental reenrollment of a damaged existing endpoint. New enrollment uses the manager CA and password, with secrets suppressed in Ansible output. The manager's enrollment listener and auth settings must already be configured and reachable through the private network; adoption never weakens or replaces them. The role does not report a successful enrollment until `client.keys` exists and is nonempty. Agent-to-manager reachability and central group synchronization still require live readback.

### Enrollment trust and credential transport

Enrollment on port 1515 is a separate connection from normal keyed agent events on port 1514. The official installers receive both `WAZUH_REGISTRATION_CA` and `WAZUH_REGISTRATION_PASSWORD`: the password is sent inside the CA-authenticated TLS enrollment channel and stored in the agent's private `authd.pass` file. An encrypted channel without manager identity verification is insufficient. Before setting `monitoring_wazuh_enrollment_tls_verified: true`, verify the existing enrollment listener's certificate chain, validity dates and manager name/IP against the reviewed CA and the exact declared manager address; verify password authentication is enabled on that existing listener. No role creates PKI or weakens manager authentication. Missing CA, an unverified/default enrollment certificate or a missing/nonboolean TLS-verification gate blocks a fresh agent before installation.

The role rejects a supplied PEM containing a private key. After installation, it checks that the actual client configuration points to the reviewed CA and private password path before the role starts or restarts the service. Linux requires a nonempty root-owned mode-0600/0640 password file; Windows rejects broad Everyone/Authenticated Users/Users ACL grants. If package behavior differs, deployment fails for review rather than silently using default unverified enrollment. The official package may perform its own installation-time actions; only reviewed pinned official artifacts should be approved. Keep enrollment passwords in Ansible Vault or the mode-0600 external private input file, never command-line `-e` values, shell history or Git. `no_log` prevents Ansible output exposure; it does not encrypt the password file at rest.

**Adoption is not a trust audit.** Retaining existing `client.keys` preserves agent identity; it does not prove those keys were originally issued by an authenticated manager or that the existing CA/certificate is correct. Before using adopted agents, audit the existing enrollment CA path, manager certificate chain/name/expiry, auth settings, key provenance and current manager identity through independently trusted access. The role does not reenroll adopted endpoints or replace their certificates to hide missing evidence. If that trust cannot be established, stop deployment and review a separate key/PKI migration. See the [official manager identity verification instructions](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/manager-identity-verification.html) and [client enrollment settings](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html).

## Fresh all-in-one deployment

This is a distinct operation on a **clean existing local VM**, not an upgrade of the captured installation. Set all of:

```yaml
monitoring_wazuh_mode: fresh
monitoring_wazuh_fresh_approved: true
monitoring_wazuh_fresh_version: '4.14.9'
monitoring_wazuh_manager_version: '4.14.9'
monitoring_wazuh_installer_sha256: '<reviewed 64-character SHA-256>'
```

The implemented fresh path supports Ubuntu 22.04/24.04 x86_64/aarch64 with roughly
8 GiB RAM and at least 4 vCPUs normally. A two-core **aarch64-only** lab deployment
additionally requires actual boolean `monitoring_wazuh_arm_small_approved: true`;
the reviewed official 4.14.9 assistant supports this without hardware-check bypass
flags. This is smaller than the quickstart recommendation, so start with a few
endpoints and measure CPU, memory and indexing latency before expanding. Review
100 GiB disk capacity/free space before approval; the role provisions no storage.
[Wazuh sizing and supported platforms](https://documentation.wazuh.com/current/quickstart.html);
[reviewed 4.14.9 release](https://documentation.wazuh.com/current/release-notes/release-4-14-9.html).

Download `https://packages.wazuh.com/4.14/wazuh-install.sh` to a private review location, inspect it and check its `readonly wazuh_version` declaration is exactly 4.14.9. Record its independently reviewed SHA-256 in the private inputs. The minor-version download URL can change upstream; a checksum mismatch stops deployment. The role checks the release declaration without executing installer code, then runs that checksum-verified official assistant with `--all-in-one`, without overwrite, uninstall, OS-check bypass or ignored hardware checks. Generated credentials stay in the root-only `/root/homelab-wazuh-bootstrap` directory; the upstream assistant writes its root-only `/var/log/wazuh-install.log` separately. Keep the generated installation archive in an owner-controlled encrypted backup outside Git.

Rerunning a completed fresh deployment uses the existing matching components without reinstalling. An interrupted or partial install fails closed if any central package/configuration remains; inspect logs and restore the approved VM backup or follow official recovery before retrying. This avoids automatic destructive cleanup. Existing 4.7.x agents are **not** silently upgraded to 4.14.9; plan explicit agent migration before using the fresh manager with this same-minor policy.

## Private OPNsense syslog receiver

To add a receiver, explicitly set `monitoring_wazuh_syslog_enabled: true`, **`monitoring_wazuh_syslog_vpn_verified: true`**, `monitoring_wazuh_syslog_bind_address` to the manager's RFC1918 IPv4 address, `monitoring_wazuh_syslog_source_address` to the firewall's exact RFC1918 IPv4 address, and optionally `monitoring_wazuh_syslog_port` (514). The VPN gate must be an actual YAML boolean and is checked before guest contact or other manager policy changes. Set it only after verifying an existing end-to-end **WireGuard or IPsec** path, authenticated peers, routes and firewall policy that prevents unencrypted fallback. A private subnet or VLAN alone does not encrypt traffic; a VPN that leaves an unencrypted final network hop does not satisfy the gate. The role does not create or configure a VPN and the flag records operator verification rather than automatically proving network protection.

Native Wazuh syslog is **plaintext TCP**, even with `protocol=tcp`; this role does not turn it into a TLS listener. The role adds one marked TCP `<remote>` stanza and validates it with `wazuh-remoted -t -c` before replacing the file. It retains a private backup and restores it on restart failure. This opt-in operation is the only edit to manager `ossec.conf`; auth, archive settings and other listener stanzas stay intact. The source allowlist and private bind constrain this receiver, while existing listeners and firewall/NAT exposure need independent review. No host firewall or NAT rules are opened, and public syslog is never authorized.

Match the private receiver address/port with [OPNsense forwarding](../opnsense/README.md), which separately requires `monitoring_opnsense_syslog_vpn_verified: true` for TCP. A TLS sender requires an **existing verified TLS syslog relay**, a reviewed CA already trusted by OPNsense, its fingerprint record and an existing client-certificate UUID; do not configure `tls4` directly to this plaintext receiver. The relay's final hop to Wazuh must also stay protected through same-host loopback or an existing verified encrypted transport. The relay path and its exact gates are documented in the OPNsense guide. Neither path creates PKI, a VPN, a relay or public ports.

## Seven-day alerts retention

`retention.json` is an OpenSearch ISM policy scoped only to `wazuh-alerts-4.x-*`. It deletes alert **indices** whose creation age exceeds seven days, so retention is approximately seven days at daily-index resolution. It does not enable `logall`/archive-all, delete arbitrary indices, modify snapshots or manage archive retention.

Applying requires `monitoring_wazuh_retention_approved: true`, a verified HTTPS `monitoring_wazuh_indexer_url`, private `monitoring_wazuh_indexer_username`/`monitoring_wazuh_indexer_password`, and optionally `monitoring_wazuh_indexer_ca_path` (controller CA file; otherwise normal system trust). Redirects and TLS verification bypasses are rejected. The helper creates/updates only `homelab-wazuh-alerts-7d`, attaches it only to unmanaged matching alert indices, and refuses to take over indices with another policy. Its template covers future matching indices. Review retention and backups before enabling: deleting old alerts is irreversible. Existing snapshots/archives are not touched or automatically backed up.

The ISM protocol follows [OpenSearch policy APIs](https://docs.opensearch.org/docs/latest/im-plugin/ism/api/) and [Wazuh index lifecycle guidance](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html). Private credentials need only the reviewed policy/index privileges, not account billing permissions.

Offline checks: `python3 -m unittest discover -s ansible/tests -p test_monitoring_wazuh.py`. Live Wazuh binary validation, package availability, trusted enrollment, indexer API behavior and actual fleet connectivity remain deployment prerequisites; offline XML tests cannot establish them.
