# Owned TrueNAS logs to the existing Wazuh manager

This integration uses the owned TrueNAS SCALE 24.04.2.5 appliance's native TLS
syslog forwarding and an isolated TLS receiver on the existing local Ubuntu
24.04 amd64 Wazuh 4.7.5-1 manager. Terraform invokes the versioned Ansible role,
then the pinned controller interpreter reconciles the native appliance API.
No Wazuh/Linux agent is installed on TrueNAS, and no cloud resource, public
route, ingress rule, Funnel or subscription is created. The absolute cost is $0.

See [point-in-time deployment evidence](DEPLOYMENT.md).
Read [receiver behavior and recovery](RECEIVER.md), [native API scope](API.md)
and the [existing local deployment guide](../../infra/wazuh-logging/README.md).
The existing `all` phase remains logging plus tailnet; appliance forwarding
requires the separate explicit `truenas` phase. This phase requires
`monitoring_wazuh_selected_agents: []` and a manager-only private inventory.
It does not rerun fleet agents, general manager policy, retention or tailnet.

Keep the deployment inventory, variables, profile, API key, trust material,
PKI, before-state records, saved plan and Terraform state outside this checkout.
Private files must be mode 0600 and private directories mode 0700, owned by the
controller user. Use canonical absolute paths without symlinks for appliance
materials. Do not put credentials in a Terraform input, command argument,
public example, debug output or shell history.

Prepare the existing authenticated management path first. Independently verify
the hypervisor SSH identity, the exact appliance VM UUID/version and native
console administrative identity. Bootstrap uses the existing pinned
`home-lab-host` SSH alias to reach the hypervisor's native VM console. It requires
the appliance's existing console administration capability; it does not reset a
web password, enable guest SSH or create an alternative login path. No automatic
appliance discovery or guessed VM identity is used.

Save this declaration outside the repository as a controller-owned mode-0600
JSON file. Create its private parent/output directories with mode 0700 first.
Use distinct output filenames and an otherwise unused dedicated PKI directory:

```json
{
  "console_administration_enabled": true,
  "expected_vm_uuid": "VERIFIED_LOWERCASE_XEN_VM_UUID",
  "expected_version": "TrueNAS-SCALE-24.04.2.5",
  "address": "VERIFIED_TRUENAS_RFC1918_IPV4",
  "syslogserver": "VERIFIED_WAZUH_RFC1918_IPV4:6514",
  "ssh_alias": "home-lab-host",
  "profile_file": "/PRIVATE_DIRECTORY/truenas-profile.json",
  "api_key_file": "/PRIVATE_DIRECTORY/truenas-api-key",
  "server_certificate_file": "/PRIVATE_DIRECTORY/truenas-https.pem",
  "pki_directory": "/PRIVATE_DIRECTORY/truenas-syslog-pki"
}
```

Run the versioned bootstrap with the pinned controller interpreter:

```sh
"$HOME/.config/home-lab/monitoring/venv/bin/python" monitoring/truenas/bootstrap.py --declaration /PRIVATE_DIRECTORY/truenas-bootstrap.json
```

The bootstrap checks the selected guest's root console identity, Xen UUID and
exact version before creating its owned restricted API key. The key allowlist
is the exact HTTP verb/resource list in `client.REST_ALLOWLIST`. It retrieves the
public management certificate through that authenticated console path, records
its SHA256 pin, creates/validates dedicated syslog PKI, saves the profile and
verifies the resulting credential over pinned HTTPS through the existing SSH
route. This credential setup is separate from the forwarding plan and does not
enable syslog. Existing complete bootstrap inputs are verified on rerun without
automatic key rotation. A partial bootstrap or existing owned key without its
controller credential stops for recovery.

Retain `bootstrap-pending.json`, `bootstrap-recovery-key.pem` and
`bootstrap-encrypted-reply.json` privately with the declaration, API key, HTTPS
certificate, profile and all six PKI files. The recovery private key and encrypted
reply together can recover the created credential after interruption; protect
and encrypt the off-host backup as credential material. Pending output may
remain even after a successful bootstrap and is not an instruction to create
another key. If interrupted, inspect the existing private artifacts and appliance
key identity through the verified management path before any retry. Never delete
recovery artifacts or create a replacement key merely to get past the guard.
The CA signing key stays on the private controller and its encrypted off-host
backup; it is not copied to TrueNAS or the receiver.

Restore complete private inputs when possible. For a replacement appliance,
independently verify the new Xen UUID, version and management identity before
updating the private declaration and replaying bootstrap. Then review and apply
a new forwarding plan. Reusing an old address is not identity verification. A
full appliance/manager OS rebuild and recovery from power loss have not been
tested by this workflow; native declaration replay is not a backup restore test.

This workflow is pinned to `TrueNAS-SCALE-24.04.2.5` and fails closed after an
upgrade. Newer TrueNAS releases revoke restricted legacy API keys during
migration; do not assume this credential survives or replace it with an
unrestricted key. Review the new version's API/authentication and native syslog
schema before changing the pin and rebuilding the narrowly scoped credential.

Prepare a dedicated persistent syslog PKI before planning with the pinned
controller interpreter:

```sh
"$HOME/.config/home-lab/monitoring/venv/bin/python" monitoring/truenas/pki.py --directory /PRIVATE_DIRECTORY/truenas-syslog-pki --receiver-ipv4 VERIFIED_WAZUH_RFC1918_IPV4
```

This invokes `ensure_materials` from [pki.py](pki.py), an explicit local
preparation step: it creates private files only on the controller, never sends
keys over the network, and validates existing material without rotating it.
The six required files are `ca.pem`, `ca-key.pem`, `server.pem`, `server-key.pem`,
`client.pem` and `client-key.pem`. Back up all six privately off-host. A partial,
expired or mismatched PKI stops reconciliation for a reviewed restore/rotation.
Do not issue other clients from this dedicated CA. The client certificate has
exact CN `homelab-truenas` and no SAN; the server certificate identifies the
reviewed receiver IPv4. Receiver name authentication follows rsyslog CN/SAN
semantics, as documented in [RECEIVER.md](RECEIVER.md).

The bootstrap-generated private appliance profile has this shape; retain the
verified `expected_vm_uuid` recorded from the declaration:

```json
{
  "enabled": true,
  "expected_version": "TrueNAS-SCALE-24.04.2.5",
  "expected_vm_uuid": "VERIFIED_LOWERCASE_XEN_VM_UUID",
  "address": "VERIFIED_TRUENAS_RFC1918_IPV4",
  "ssh_alias": "home-lab-host",
  "syslogserver": "VERIFIED_WAZUH_RFC1918_IPV4:6514",
  "sysloglevel": "F_INFO",
  "server_cert_sha256": "VERIFIED_TRUENAS_HTTPS_DER_SHA256",
  "server_certificate_file": "/PRIVATE_DIRECTORY/truenas-https.pem",
  "api_key_file": "/PRIVATE_DIRECTORY/truenas-api-key",
  "pki_directory": "/PRIVATE_DIRECTORY/truenas-syslog-pki"
}
```

The certificate pin identifies the appliance's management HTTPS service,
separate from the dedicated syslog CA. The pinned client creates a verified SSH
forward through `home-lab-host` and requires trusted HTTPS and the exact pin
before sending its API key. See [API.md](API.md) for the narrow middleware API
allowlist and the explicit previous-destination declaration needed when
migrating an existing nonempty syslog destination.

In the selected private Wazuh deployment JSON, retain the existing adoption
version settings, set the agent selection to `[]`, and add:

```json
{
  "monitoring_truenas_receiver_address": "VERIFIED_WAZUH_RFC1918_IPV4",
  "monitoring_truenas_source_address": "VERIFIED_TRUENAS_RFC1918_IPV4",
  "monitoring_truenas_ca_file": "/PRIVATE_DIRECTORY/truenas-syslog-pki/ca.pem",
  "monitoring_truenas_server_cert_file": "/PRIVATE_DIRECTORY/truenas-syslog-pki/server.pem",
  "monitoring_truenas_server_key_file": "/PRIVATE_DIRECTORY/truenas-syslog-pki/server-key.pem",
  "monitoring_truenas_receiver_install_approved": false
}
```

The receiver certificate paths must select those exact files from the profile's
PKI directory. The destination/source must agree across the profile and receiver
variables. Missing `rsyslog-gnutls` needs separate actual boolean `true` package
approval; installation pins its version to the installed base rsyslog and uses
existing signed apt sources. The role does not upgrade Wazuh or base rsyslog.
The manager inventory retains verified SSH access, the expected Xen guest UUID
and actual boolean `monitoring_access_verified: true`. The controller passes
actual boolean deployment approval only within the selected deployment.

Use the same private environment and pinned Python/Ansible paths as the existing
local Wazuh deployment, additionally exporting the profile path:

```sh
export WAZUH_TRUENAS_PROFILE="/PRIVATE_DIRECTORY/truenas-profile.json"
"$HOME/.config/home-lab/monitoring/venv/bin/python" scripts/monitoring/wazuh_logging.py plan --phase truenas --redeploy
"$HOME/.config/home-lab/monitoring/venv/bin/python" scripts/monitoring/wazuh_logging.py apply --phase truenas
```

Inspect the saved plan between those commands. Only the existing
`terraform_data.logging` orchestration record may change; its normal input is the
exact manager/agents/phase/seven-day-retention schema. The optional native template
repair below adds only `native_template_fix: true` when explicitly selected.
The protected review
receipt also fingerprints the profile, all six PKI files, the HTTPS trust
certificate and API key, in addition to the inventory, deployment variables,
source and saved plan. Changes to any reviewed material require a fresh plan.
The plan requires all PKI/credential files to exist, validates certificate
chains, keys, names and validity, and performs no preparation or network calls.
Changes to private inputs need `--redeploy` because secrets
are intentionally excluded from Terraform state/triggers. Public native Python
and receiver role/template changes are included in source triggers.

During apply, the exact guest UUID guard runs before Ansible changes. Ansible
validates and activates the TLS receiver and the owned Wazuh localfile stanza;
only after success does the same pinned interpreter invoke
`client.py configure --profile` to reconcile native forwarding. Receiver failure
stops appliance changes. Native API failure can leave the successfully configured
receiver installed; the scoped native before-state is saved privately before
appliance mutation, with rollback/readback behavior described in [API.md](API.md).
A rerun converges existing owned PKI/objects and native settings. Neither
Terraform rollback nor deleting its orchestration record undoes appliance edits.

The exact 24.04.2.5 native syslog template has two observed TLS defects: it
references `os` without importing it, and formats a CA subject-hash filename
without the leading-zero padding OpenSSL requires. The first defect prevents
rendering the remote destination. The second can leave a seven-digit CA filename
where OpenSSL's hashed trust directory requires eight digits, causing issuer
lookup failure despite selecting the correct CA. Installed-template/error evidence
and a native `openssl verify -CApath` failure established these defects.

The optional versioned [native repair](native_fix.py) makes two small edits in
that exact vendor file: add `import os` and change `%x.0` to `%08x.0`. It accepts
only the pinned original, the known owned import-only version, or the combined
repaired content. The combined SHA256 is
`54590db0c9bbc2e90a597acdf65071e588e0b3b40405e11bd9a03211bdd2f4c1`.
Unknown content/version fails closed. Both edits are declared in the same
reviewed automation and replay on a verified rebuild; no additional repair flag
is needed. This does not authorize a blanket vendor patch, package replacement
or appliance upgrade. The combined repair's live delivery still requires the
verification below.

To declare this repair, add actual boolean
`"monitoring_truenas_native_template_fix_enabled": true` to the private deployment
variables, and actual boolean `"native_syslog_template_fix_enabled": true` to the
same private bootstrap declaration whose console gate is already true.

The appliance OS may mount `/usr` read-only. To permit the helper's narrowly
scoped temporary OS remount when that exact unpatched state requires it, also
add actual boolean `"native_syslog_usr_remount_enabled": true` to the private
bootstrap declaration. This flag is optional and defaults false; a nonboolean
value fails controller review. Without explicit approval, the helper refuses
to modify a read-only mount. The saved review receipt hashes the whole declaration,
including this flag; changing it requires another plan.

This permission covers only a temporary `/usr` remount around the one-file
vendor repair. The helper binds the mounted OS dataset to root-owned native
`/conf/truenas_root_ds.json` metadata, verifies its ZFS source/GUID and records
private before-mount evidence before remounting. It restores the original
read-only mount in a `finally` path and verifies the resulting mount flags and
property source. It does not change stored ZFS properties, enable developer
mode or remount appliance data datasets. No live GUID belongs in public inputs;
the native metadata supplies the binding after the declared VM identity check,
including on a verified replacement installation. Preserve the separate private
mount receipt alongside template backups and inspect any failed restoration
before retrying.

Export the declaration path before a new saved-plan review:

```sh
export WAZUH_TRUENAS_BOOTSTRAP="/PRIVATE_DIRECTORY/truenas-bootstrap.json"
"$HOME/.config/home-lab/monitoring/venv/bin/python" scripts/monitoring/wazuh_logging.py plan --phase truenas --redeploy
"$HOME/.config/home-lab/monitoring/venv/bin/python" scripts/monitoring/wazuh_logging.py apply --phase truenas
```

The controller binds this declaration to the exact reviewed profile, guest UUID,
release, addresses, SSH alias, credential/trust files and PKI directory. Its hash
is included in the protected review receipt. The repair flag defaults false and
is rejected outside `truenas`; the plan explicitly records the selected boolean.
When enabled, deployment order is receiver Ansible, native template repair, then
native API reconciliation. Existing `all` deployments do not select this repair.

The repair accepts an empty native destination on a fresh appliance or the
already-declared exact intended TLS destination; it preserves unrelated settings
and refuses another destination. This allows the same repair-before-reconciliation
order on a fresh installation. That fresh-state ordering is checked with offline
mocks; a full appliance OS rebuild has not been performed. A rebuild still
requires verified replacement identity and restored private inputs, without
automatic discovery or an implied backup restore guarantee.

Before replacement, the helper captures the actual current template and a
versioned exact-digest receipt in a private root-owned appliance recovery
directory. It preserves the original vendor backup and import-only repair
receipt when extending an earlier repair, with separate before-state/evidence
for the combined repair. It preserves the vendor file's owner/group/mode,
validates the template and generated configuration
with native tooling, restarts only native syslog, and checks the resulting TLS
destination/service. Failure attempts to restore the exact file present before
that repair attempt, including an already import-only file, and regenerate/restart
native logging, recording rollback verification privately.
Keep those guest backups and controller-side repair evidence with the encrypted
off-host recovery material. Template/service validation still does not establish
that an appliance event reached Wazuh; repeat the delivery checks below.

TrueNAS stays agentless. Its events appear under Wazuh manager agent ID `000`,
with the source hostname/program retained from native syslog, rather than as a
separately enrolled appliance agent. The payload hostname is sender-supplied;
the TLS certificate and exact source-IP filter provide the transport identity.

Verify a unique harmless event from the actual appliance reaches
`/var/log/homelab-truenas/events.log` with its intended hostname/program and then
the expected Wazuh decoder/rule. Ordinary collected logs need not create alerts;
use a known matching test event. Verify native TLS rejection cases, exact source
filtering, file permissions, healthy services, log reopening/rotation and a second
convergence. See the receiver runbook for precise checks and storage limitations.
An enabled forwarding setting, reachable dashboard or successful apply alone
cannot establish delivery. No host reboot, power-loss exercise or disruptive
failover test is part of this integration.

After the reviewed deployment, use a fresh lowercase nonce containing only
letters, digits and hyphens for these targeted verification commands:

```sh
"$HOME/.config/home-lab/monitoring/venv/bin/python" monitoring/truenas/verify.py --declaration /PRIVATE_DIRECTORY/truenas-bootstrap.json --event unique-test-nonce
"$HOME/.config/home-lab/monitoring/venv/bin/python" monitoring/truenas/verify.py --tls-check --profile /PRIVATE_DIRECTORY/truenas-profile.json --event unique-test-nonce
```

The native-console check verifies the declared root guest identity/version before
emitting `HOMELAB_MONITORING_TEST: truenas-unique-test-nonce` with the native
`logger` command. It needs the verified console route, without an API credential.
The TLS check uses a temporary strict SSH forward through `home-lab-host`,
verifies the receiver certificate against the dedicated CA and exact receiver
IPv4, and uses TLS 1.2 for comparable probes. Rsyslog's GnuTLS driver checks
peer authorization after the cryptographic handshake, so the helper sends a
harmless line and observes the subsequent read boundary. It requires the
approved connection to remain open during a bounded read before and after both
negative probes, while an absent certificate and the same-CA server certificate
with wrong client identity/purpose must produce EOF or a peer TLS rejection.
Connection failures and generic network timeouts do not establish rejection.
Only after those controls pass does it send
`HOMELAB_MONITORING_TEST: source-filter-unique-test-nonce` through the tunnel,
whose source is the hypervisor. Output contains sanitized booleans only.

Independently inspect the manager log through the verified Ansible path: the
native `truenas-unique-test-nonce` event must appear and the tunneled
`source-filter-unique-test-nonce` event must be absent. Then inspect the expected
Wazuh event under manager ID `000`. The helper's emission/sending booleans alone
do not establish either log result or Wazuh ingestion. These narrow tests do not
replace expired/untrusted-certificate, old TLS version or reboot checks described
in the receiver runbook.

A rebuild restores the independently verified management/guest identity and
private inputs first, replays the bootstrap when needed, then uses the same
`truenas` plan/apply flow. Native appliance configuration and receiver systemd
units operate without a connected controller. Restore historical events,
Wazuh identity/index data and appliance configuration backups separately;
configuration convergence cannot recreate lost data or prove untested recovery.

Offline checks:

```sh
python3 -m unittest discover -s scripts/monitoring/tests -p test_wazuh_logging.py
python3 -m unittest discover -s ansible/tests -p 'test_truenas*.py'
terraform -chdir=infra/wazuh-logging validate
```

For a newly installed replacement rather than a restored appliance backup:

1. Verify its exact VM UUID, root console route, address and supported OS version.
   Create a new private mode-0700 bootstrap directory and a declaration selecting
   that identity; choose fresh profile, API-key and HTTPS-trust filenames there.
   Preserve the old private directory for recovery; do not overwrite its profile
   or delete a key merely because the new instance has the same IP address.
2. Point `pki_directory` at the original restored dedicated syslog PKI when the
   receiver address is unchanged and its certificates remain valid. The fresh
   appliance imports those existing client/CA objects. Retaining that PKI avoids
   changing the receiver's trust unnecessarily. Lost/expired PKI requires a
   deliberate replacement and a fresh receiver plan.
3. Run the bootstrap CLI. It verifies the replacement through the hypervisor,
   captures its HTTPS identity and creates its scoped credential. A restored
   appliance already containing the owned key needs its original controller key
   restored as well; bootstrap refuses blind credential rotation.
4. Select the new private profile, update the receiver source address if needed,
   and run the `truenas` plan/apply with `--redeploy` as above. Check native event
   delivery and the final no-change plan. This replay is the automatic
   configuration step; the repository does not watch for or trust arbitrary new
   VMs, install the TrueNAS OS, restore pools or recover lost application data.
