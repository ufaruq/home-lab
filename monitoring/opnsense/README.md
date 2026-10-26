# OPNsense native syslog

`monitoring_opnsense` reconciles one destination through the native Syslog settings API; it does not install an appliance agent or modify firewall/NAT rules. Metrics/SNMP collection is optional future work and is not enabled here.

Run the role with a local controller connection and an exact `firewall` host limit through the repository controller. Both shared deployment gates must be actual boolean `true`. Private inputs outside Git are:

```yaml
monitoring_opnsense_url: https://firewall.example.internal
monitoring_opnsense_api_key: '<private restricted API key>'
monitoring_opnsense_api_secret: '<private API secret>'
monitoring_opnsense_ca_file: /absolute/controller/path/firewall-ca.pem # optional with system-trusted HTTPS
monitoring_opnsense_syslog_address: 10.2.0.3 # replace with verified private receiver
monitoring_opnsense_syslog_port: 514
monitoring_opnsense_syslog_transport: tcp4
monitoring_opnsense_syslog_vpn_verified: false # set true only after verifying the existing encrypted path below
```

The destination must be a literal RFC1918 IPv4 or ULA IPv6 address. Public, loopback, link-local and hostname destinations are rejected. **Private addresses and VLANs do not encrypt syslog.** Both transport paths below fail closed until their explicit verification prerequisites are supplied. Flags must be actual YAML booleans; the string `'true'` is rejected.

## Path 1: existing encrypted VPN to the native Wazuh receiver

`tcp4`/`tcp6` sends plaintext syslog inside TCP. It is allowed only with `monitoring_opnsense_syslog_vpn_verified: true`, after the operator has verified an **existing end-to-end WireGuard or IPsec tunnel** protects the complete route from OPNsense to the receiving host. Verify peer authentication, current tunnel/route state, source/destination addresses and firewall policy. Firewall policy must prevent a direct unencrypted route or fallback when the tunnel is unavailable. A VPN that terminates at a separate gateway with an unencrypted final network segment does not satisfy this requirement.

For the managed native Wazuh receiver, independently set `monitoring_wazuh_syslog_vpn_verified: true` along with its private bind/source addresses. The manager gate is checked before guest contact or any policy changes. The supplied receiver is **plaintext TCP IPv4**, not a TLS server; use `tcp4` only over the verified encrypted VPN. No role installs or reconfigures the VPN, adds NAT rules, opens public ports or treats the operator flag as automatic proof that a tunnel exists. The flag records the operator's completed verification; deployment cannot establish actual network protection from a private IP alone.

## Path 2: existing TLS syslog relay

Use `tls4`/`tls6` only to an **existing independently verified TLS syslog relay**, not directly to the native receiver created by `monitoring_wazuh_manager`. Required private inputs are:

```yaml
monitoring_opnsense_syslog_transport: tls4
monitoring_opnsense_syslog_port: 6514
monitoring_opnsense_syslog_tls_relay_verified: false # true only after the checks below
monitoring_opnsense_syslog_tls_ca_sha256: '<64-hex SHA-256 fingerprint of the existing trusted relay CA certificate>'
monitoring_opnsense_syslog_certificate: '<existing native client-certificate UUID>'
```

Verify that the relay presents a valid, unexpired server certificate matching the configured literal destination IP, its issuing CA is already in OPNsense's trusted CA store, native syslog-ng validates that chain and identity, and the selected native client certificate/key exists and is approved for that relay. The CA fingerprint is an audit record supplied by the operator; this helper does not download/import CAs or independently compare the appliance trust store to that record. Set `monitoring_opnsense_syslog_tls_relay_verified: true` only after those checks. The role does not create a relay, VPN, CA, certificate, private key or public listener.

The relay-to-Wazuh leg also needs protection: use an existing same-host loopback connection or an independently verified end-to-end encrypted transport. Sending TLS to a relay and then ordinary TCP across a separate LAN does not protect the complete path. The manager role's optional receiver supports RFC1918 bind addresses rather than loopback, so enabling it for a remote relay still requires its own verified VPN gate. A loopback receiver/relay setup is an existing prerequisite outside this role.

## Management API and rollout

Management HTTPS is a separate connection from syslog delivery. `monitoring_opnsense_ca_file` verifies the **firewall management API**, while the native appliance trust store and `monitoring_opnsense_syslog_tls_ca_sha256` concern the **syslog relay**. The API always verifies the firewall certificate using normal system trust or the explicit CA file; redirects are rejected. Encrypting the API does not encrypt a TCP syslog destination. All API keys, payloads and responses are `no_log` in Ansible. Use a restricted firewall API account allowed to read/update Syslog destinations and reconfigure that service.

The code searches all destinations and owns only the exact description `homelab-monitoring`. It reads the complete matching destination, normalizes native selection fields, and adds or updates it only on drift. Duplicate matching descriptions fail for manual review. Unrelated destinations and general local logging settings remain intact. A changed destination is reconfigured and read back before reporting success. The selected programs are `filterlog,sshd` at notice and higher severity; the API validates those installed application names. Review program availability for the installed OPNsense version before applying. Filterlog may emit events below notice; adjust this reviewed bounded policy explicitly if those firewall traffic logs are needed.

Back up the firewall configuration through its supported facilities before rollout. Removing or changing the owned destination can be done in native Logging / Settings; rerunning restores repository policy. If a prior apply saved settings but reconfiguration failed, resolve that service failure and reconfigure through OPNsense before rerunning; successful settings readback alone does not prove message delivery. Verify a selected event reaches Wazuh after deployment.

Schema and endpoints were checked against the [official Syslog API reference](https://docs.opnsense.org/development/api/core/syslog.html), [native destination model](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Syslog/Syslog.xml) and [settings controller](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Syslog/Api/SettingsController.php). The tested operations are searchDestinations, getDestination, addDestination, setDestination, then service/reconfigure. The installed appliance must expose those endpoints; unsupported schema or rejected fields fail without a fallback to GUI scraping or full configuration replacement.
