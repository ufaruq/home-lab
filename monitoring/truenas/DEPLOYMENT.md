# Verified deployment: 2026-11-09 UTC

The selected existing TrueNAS SCALE 24.04.2.5 appliance forwards native syslog over
mutual TLS to the existing local Ubuntu 24.04 Wazuh 4.7.5 manager. This records a
point-in-time verification, not a guarantee of future service or disk capacity.

- A native `logger` event from the verified appliance reached the dedicated
  receiver file, matched Wazuh rule `100100`, and appeared in the alert index at
  **2026-11-09T06:44:59.159Z**. Its source hostname was preserved. Agent ID is
  **`000`**, because the appliance uses an agentless manager-localfile receiver.
- The approved TLS client stayed connected; absent and incorrect client
  certificates were rejected. A valid-client test sent through the hypervisor
  was excluded by the exact source-IP filter.
- Receiver, rotation timer, Wazuh manager/indexer/dashboard, Filebeat and the
  existing system rsyslog were active. Portainer remained connected. The private
  dashboard returned HTTP 200 with ordinary HTTPS verification. The manager had
  81.7% disk space free at the check.
- The owned receiver log was rotated and reloaded. A second native event was
  confirmed in the reopened file and alert index at **2026-11-09T06:48:05.363Z**;
  log permissions remained 0640 and all affected services stayed healthy.
- Native API settings reconciled without further changes. A fresh guarded
  Terraform plan showed only `terraform_data.logging` with action **`no-op`**.
  All infrastructure/service changes used the versioned local deployment path;
  no cloud resources were provisioned.
- Both exact-release TLS template defects were reproduced: missing `os` omitted
  the destination, and an unpadded CA hash filename caused native OpenSSL issuer
  lookup failure. The combined hash-pinned repair validated native generation
  and the selected CA link. The helper verified that the exact prior `/usr`
  read-only mount, dataset identity and property provenance were restored.
  Private original/actual-before backups and repair evidence remain outside Git.

Public snapshot checks: 159 Ansible/Python tests ran (150 passed, nine
environment-dependent skips), 15 controller tests passed, and six local-only
Terraform safety tests passed. Playbook syntax, Terraform formatting/validation
and scoped known-secret/private-identifier scans passed.

Routine syslog records do not necessarily create Wazuh alerts. Raw records stay
in the bounded receiver log; alerts use the existing seven-day alert-index
policy. This does not enable SMB/file-access auditing, change TrueNAS's existing
`syslog_audit` selection, import IOC feeds, configure notifications, or enable
active response. Those remain separately declared detection/telemetry work.

A full TrueNAS OS/pool rebuild, power-loss recovery and destructive restore were
not tested. Fresh-state reconciliation, version/identity/digest guards and
rollback are covered by offline tests. Restore protected inputs and verify a
replacement identity before replaying [the setup/rebuild workflow](README.md).
