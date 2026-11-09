# Local Wazuh deployment evidence

Verified on **2026-11-03 UTC**. This is point-in-time evidence, not a substitute
for ongoing health checks. Private addresses, VM/index UUIDs, credentials,
certificate material, exact tailnet URL, plans and Terraform state remain
outside Git.

## Deployed and verified

- The existing Ubuntu 24.04 manager, indexer and dashboard remain at `4.7.5-1`;
  Filebeat is running. No Wazuh package was reinstalled or upgraded.
- Portainer's existing `4.7.5-1` agent was pointing at an old manager address.
  Independently verified matching shared-key evidence allowed a scoped address
  migration. Its agent ID/key were retained. The manager reports it active and
  synchronized with the Linux group policy.
- At **04:02:53 UTC**, a fresh synthetic syslog event from Portainer triggered
  rule `100100` and was confirmed in the alert index through trusted local
  indexer certificate authentication. The manager, indexer, dashboard, Filebeat
  and local cleanup timer were all active in that verification.
- Native `wazuh-logtest` initially reported no decoder for that syslog event.
  The health decoder now explicitly selects the `homelab-monitoring` program
  tag; the same native test then matched the decoder and rule `100100`.
- Seven-day ISM retention is attached to alert indices. Initially 302 historical
  alert indices and 999 open shards blocked creation of the retention index.
  Recovery deleted one individually reviewed expired alert index after checking
  its exact UUID, creation age and lack of policy ownership, then created the
  policy. Asynchronous ISM cleanup subsequently left **seven alert indices**.
  No shard limit was raised and no unrelated index family was deleted.
- Internal log rotation and conservative dated compressed-alert cleanup are
  deployed with an enabled daily systemd timer. Full-event archive-all remains
  disabled. Time-based retention is not a hard disk quota; other files/index
  families remain outside this cleanup scope.
- Tailscale `1.104.4` was installed from signed, pinned official package inputs.
  The owner confirmed Free status, approved the device and enabled HTTPS.
  Only a replacement key supplied privately was used; the chat-exposed key was
  not used. Global Tailscale approvals are one-time owner actions, while the
  node and service configuration are managed through Terraform and Ansible.
- The private HTTPS URL returned the Wazuh login page with status **200** and
  normal certificate validation. Dashboard HTTP binds only to `127.0.0.1:5601`
  behind Tailscale Serve. A separate LAN client confirmed ports 443 and 5601
  closed while the existing agent receiver on 1514 remained reachable. Serve
  configuration contains no public Funnel, subnet route or exit node.
- DHCP-provided DNS returned `SERVFAIL` even though outbound HTTPS and direct
  public DNS worked. The optional owned systemd-resolved drop-in corrected DNS
  on this VM; its IP, routes, interfaces and Netplan configuration were retained.
- The existing dashboard `admin` account was verified without reading or
  printing its password/hash. No account password was changed or reset.

All deployment mutations used the guarded local-only Terraform root and
Ansible. Read-only inspections and the synthetic event test were separate
verification actions. No Oracle/Grafana resources, public ingress, paid service,
extra disk or VM were provisioned, and no halted guest was started.

## Remaining fleet work

This deployment confirms **Portainer and the manager's own local logs**, not
every guest. XOA's metrics account remains intentionally unprivileged; its
administrator SSH credential has not been verified, so no Wazuh agent was
installed there. TrueNAS's management address was discovered through a
read-only console capture, but native syslog configuration still needs verified
appliance administrator access and encrypted transport. Halted guests remain
pending. Parrot is explicitly excluded. Existing agentless hypervisor/VM metrics
are a separate deployment documented under `monitoring/xcp/`.

The older Wazuh release, retained enrollment/API settings and future appliance
transport still require their own reviewed maintenance work. This deployment
does not claim that all existing settings have been hardened or that private
access guarantees protection against every denial-of-service attack.

## Reproduce verification

Use the [deployment guide](../../infra/wazuh-logging/README.md) for private input
setup, guarded plan/apply, redeployment, collector additions and recovery.
Native validation is run before activation. Confirm agent activity and shared
group synchronization, emit a unique tagged health event, then verify both its
manager alert and indexed copy. Check TLS from an authorized tailnet client and
confirm the former LAN dashboard listener is closed.

The public snapshot passed 75 Ansible/Python tests (nine environment-dependent
skips), 28 monitoring-controller tests and three local-only Terraform plan tests.
Terraform validation/formatting and the deployment playbook syntax checks also
passed. Offline tests do not prove live connectivity; the checks above supply
that separate evidence.
