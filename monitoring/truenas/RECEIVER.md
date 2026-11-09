# Owned TrueNAS TLS receiver

`monitoring_wazuh_truenas` adds an isolated, unprivileged rsyslog instance on the
existing Ubuntu 24.04 amd64 Wazuh 4.7.5-1 VM. It preserves the default rsyslog
configuration, socket inputs and service. No cloud, public listener, firewall
rule, route, Tailscale Funnel, native Wazuh TCP syslog input or package upgrade
is declared by this role. Invoke it only through the selected Terraform-driven
Ansible deployment after current identity/access verification.

Supply these values in the protected private deployment inputs outside Git:

| Variable | Required value |
| --- | --- |
| `monitoring_access_verified` | actual boolean `true` after trusted access verification |
| `monitoring_deployment_approved` | actual boolean `true` after reviewing selected deployment |
| `monitoring_truenas_receiver_address` | verified exact Wazuh RFC1918 IPv4 address |
| `monitoring_truenas_source_address` | verified exact TrueNAS RFC1918 IPv4 source address |
| `monitoring_truenas_ca_file` | controller CA PEM file, mode 0600 |
| `monitoring_truenas_server_cert_file` | controller server certificate PEM file, mode 0600 |
| `monitoring_truenas_server_key_file` | controller server private key PEM file, mode 0600 |
| `monitoring_truenas_receiver_install_approved` | actual boolean `true` only if missing `rsyslog-gnutls` installation is reviewed |

The base `rsyslog` and `logrotate` packages must already exist. Installing the
missing plugin uses existing signed apt repositories; it does not add a key,
repository or signature bypass. Review those repositories and their trust before
approving package installation. Package installation and the dedicated account,
directories and empty current log persist if later activation fails.

The listener binds only the declared address on TCP 6514. GnuTLS requires a
trusted client certificate, the permitted peer name `homelab-truenas`, and TLS
1.2 or 1.3. Its dedicated ruleset discards any other source IP before writing the
owned file. Source filtering happens after TLS authentication, so an unapproved
source can still attempt a handshake; an existing host/network firewall can
restrict connections earlier. This role opens no firewall rule. Plaintext has
no receiver or fallback in this instance. Inspect other existing listeners and
network exposure independently.

**Certificate identity:** rsyslog `x509/name` checks certificate CN/SAN names,
not exclusively the subject CN. Issue the appliance certificate with exact
CN `homelab-truenas`; use a dedicated private issuing CA and do not issue another
client certificate with that CN or SAN. A different CN with a matching SAN can
also satisfy rsyslog's name check. This role cannot claim a CN-only policy.
Verify the sender's exact CN, validity, client-auth purpose and key matching in
the PKI/sender workflow. The receiver certificate must match the exact address
or DNS identity the appliance verifies. Neither PKI nor certificate expiry
renewal is created by this role. Keep CA signing keys and client private keys
outside the receiver; back them up privately off-host.

Certificates and server key are copied to `/etc/homelab-truenas` as mode 0600,
owned by dedicated `homelab-syslog`. The service has no Linux capabilities and
no supplementary Wazuh membership. `/var/log/homelab-truenas` is
`homelab-syslog:wazuh` mode 2750; current/rotated logs are mode 0640 with that
owner/group. Setgid inheritance keeps newly reopened files in the Wazuh group.
Wazuh 4.7.5's native logcollector retains root access; verify its actual runtime
identity/readability on the selected host. Its only managed `ossec.conf` edit is
the marked `homelab-truenas-localfile` stanza pointing at `events.log` with
`log_format=syslog`. Unrelated XML is preserved; an unowned duplicate target
localfile or ambiguous owned markers fails before deployment.

The receiver uses `RSYSLOG_TraditionalFileFormat` to preserve parsed hostname,
program/tag and message for the older Wazuh syslog parser. The authenticated
sender still controls its reported hostname/program/message; transport trust
does not make payload fields trustworthy. Maximum messages are 8 KiB, queue
capacity is 10,000 messages in memory, and connections are limited to eight.
There is no unbounded disk spool. MemoryMax is 192 MiB; pressure, daemon restart,
full queues, write failure and oversize messages can lose events. This is best
effort collection, not a durable audit archive.

A dedicated systemd timer checks rotation hourly, including a persistent timer
catch-up after downtime. Rotation is daily or above 64 MiB, retains at most seven
archives, and removes archives older than seven days when rotation runs.
Compression is delayed one rotation to support logcollector rollover. A rough
steady-state envelope is eight 64 MiB files (about 512 MiB before compression),
plus writes between hourly checks. This is **not a universal disk hard cap**:
high volume, timer failure or delayed rotation can exceed it, while frequent
size rotations can reduce the retained time below seven days. Wazuh indexed
alerts/archives, system journal and sender buffers have their own retention;
this role does not configure those. Observe actual disk/ingestion growth.

Ubuntu 24.04's existing `rsyslogd` AppArmor profile remains enforced. The role
requires its reviewed `include if exists <rsyslog.d>` mechanism and owns only
`/etc/apparmor.d/rsyslog.d/homelab-truenas`. That snippet grants read access to
the four dedicated receiver config/certificate/key paths, owner-only access to
the dedicated runtime directory and PID files, and owner-only access to the
dedicated work directory and its immediate entries. It adds no capabilities,
global filesystem access or profile bypass. The installed vendor profile already
permits logging under `/var/log`; its other rules and snippets are preserved.
Before native rsyslog validation, the role compiles the complete retained profile
using `apparmor_parser --skip-kernel-load --skip-cache`, then reloads it with
`--replace --skip-cache` and checks that `rsyslogd` is still enforced. This policy
reload does not restart the default rsyslog service. A failure restores or removes
only the owned snippet, reloads the prior complete profile and verifies enforcement
before restoring prior receiver service state. An unknown include or absent
existing enforced profile stops deployment. This addresses the verified AppArmor
`open` denial on the custom config path without weakening ordinary file modes.
See the [Ubuntu 24.04 parser options](https://manpages.ubuntu.com/manpages/noble/man8/apparmor_parser.8.html)
and [Ubuntu packaging's snippet mechanism](https://lists.ubuntu.com/archives/lunar-changes/2023-February/009743.html).

Before restarting, Ansible validates the isolated config with
`rsyslogd -N1 -f /etc/homelab-truenas/rsyslog.conf` as the receiver user, checks
logrotate in debug mode and validates staged Wazuh XML with the installed
`wazuh-logcollector -t -c`. Failed activation restores prior owned TLS/config/unit
files and Wazuh backup, removes newly added owned configuration and restores
prior owned service/timer state. The default rsyslog service is never restarted.
Inspect failures and private journal output before retrying. Ansible check mode
is not a substitute for this validation/transaction or the guarded Terraform
plan. Existing Wazuh backup files remain private beside `ossec.conf`.

For a rebuild, restore private inventory, exact addresses and trusted SSH
identity first; restore retained Wazuh configuration/identity/data separately,
then reconverge this role using the same private certificate sources. Systemd
starts the approved receiver and rotation timer without an agent session.
Configuration recreation does not restore historical logs or indexed data.

Offline checks:

```sh
python3 -m unittest discover -s ansible/tests -p test_truenas_receiver.py
```

Before claiming delivery, verify native config validation and services, actual
6514 bind and log permissions, then send a harmless unique event from the owned
appliance and confirm hostname/program parsing and the expected Wazuh result.
A generic syslog event may be collected without producing an alert; verify with
a matching rule/test event rather than enabling archive-all. Verify no writes
from plaintext, no-client-certificate, untrusted CA, wrong peer identity,
expired certificate, TLS 1.0/1.1 and wrong source cases using isolated test
clients. Verify log reopening after normal scheduled rotation and subsequent
convergence does not change policy. Tests must use the existing authorized
private path; do not expose a port publicly to test it. Reboot/power-loss tests
remain separate maintenance work. Offline tests and successful service startup
do not establish those live checks.

References: [rsyslog imtcp](https://docs.rsyslog.com/doc/configuration/modules/imtcp.html),
[GnuTLS driver authentication](https://docs.rsyslog.com/doc/concepts/ns_gtls.html),
[CN/SAN matching](https://docs.rsyslog.com/doc/reference/parameters/imtcp-streamdriver-prioritizesan.html),
[Wazuh 4.7.5 native config CLI](https://github.com/wazuh/wazuh/blob/v4.7.5/src/logcollector/main.c).
