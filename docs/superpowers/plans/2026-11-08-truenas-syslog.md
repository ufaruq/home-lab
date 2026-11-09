# TrueNAS native encrypted log forwarding

Extend the existing local Wazuh Terraform → Ansible deployment. No cloud resources,
NAS agents, guest package installs, VM power changes or storage changes are needed.

1. Verify the selected TrueNAS VM through the existing authenticated hypervisor
   connection and native console. Pin the supported TrueNAS 24.04.2.5 version.
   Bootstrap a method-restricted native API key using that root console; transfer
   only controller-public-key-encrypted key material through a nonce-scoped Xenstore
   reply. Never reset a password or record the plaintext key in console history.
2. Preserve the verified HTTPS certificate and key in private controller storage.
   Generate dedicated syslog CA/server/client certificates there; verify the API
   server certificate before transmitting any API credential.
3. Use the existing guarded Terraform root with a separate `truenas` phase.
   Ansible configures an isolated unprivileged rsyslog TLS receiver with client
   certificate and source restrictions, bounded queues/rotation, and a managed
   Wazuh localfile stanza. Native API reconciliation imports owned certificates
   and changes only the five syslog settings, preserving unrelated configuration.
4. Save private before-state; reject unexpected certificate ownership, destination,
   VM identity or version. Roll back owned syslog settings after failed updates.
   Validate staged receiver/Wazuh configuration before restarting affected services.
5. Test bad TLS clients, authenticated delivery, Wazuh event/index visibility and
   a second convergence. Test an empty/rebuilt appliance with mocks; do not destroy
   or reboot the live NAS to test recovery. Publish only scoped code/docs/tests.

Recreation requires restored controller private inputs and verified console access
for the explicitly selected replacement VM. Rerunning bootstrap and the reviewed
Terraform deployment restores logging configuration. This is not a full NAS/data
restore, automatic VM discovery or a claim of tested destructive disaster recovery.

The installed release matches the official template with two observed TLS bugs:
the CA path uses `os` without importing it, and the CA subject-hash filename uses
`%x.0` instead of OpenSSL's required eight-digit `%08x.0`. The renderer can omit
the remote destination, and a leading-zero subject hash can fail native
`openssl verify -CApath` issuer lookup even with the selected CA. Native API
readback alone therefore cannot prove forwarding. Extend the explicit `truenas`
plan with `native_template_fix=true`. Its versioned helper accepts only the
pinned original, known owned import-only, or combined repaired digest, and makes
only those two small edits in the one vendor template. The combined SHA256 is
`54590db0c9bbc2e90a597acdf65071e588e0b3b40405e11bd9a03211bdd2f4c1`.
It preserves the original backup and first repair receipt, captures the actual
before-file and a separate versioned receipt for the combined repair, validates
native generation and restarts through middleware. Failed activation restores
the actual before-file, including an import-only file when that was the starting
state. Both defects remain recorded in repeatable rebuild automation without
additional flags; live combined-repair delivery is not yet established here.
The private remount gate permits only a temporary
`/usr` mount override bound to native boot metadata and dataset GUID. The guest
restores and verifies its exact prior read-only state in `finally`; no stored ZFS
property, developer mode, package protection or data dataset changes are permitted.
Unknown versions/content/identities and failed restoration stop deployment.
