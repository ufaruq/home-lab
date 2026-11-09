# Native TrueNAS TLS syslog API

`api.py` provides `reconcile(request, config, materials)` for the verified
`TrueNAS-SCALE-24.04.2.5` appliance. It has no CLI, credentials, HTTP implementation,
cloud operation, shell execution or remote agent installation. Python
`cryptography` >=42 is required on the controller (not on TrueNAS).

The 24.04 [official API schema](https://www.truenas.com/docs/scale/24.04/api/scale_websocket_api.html)
defines `system.advanced.config/update` with `syslogserver`, `syslog_transport`,
`syslog_tls_certificate`, `syslog_tls_certificate_authority` and `sysloglevel`.
It defines `certificateauthority.create` with `CA_CREATE_IMPORTED` and
`certificate.create` with `CERTIFICATE_CREATE_IMPORTED`; the latter is a job.
The [24.04 advanced settings reference](https://www.truenas.com/docs/scale/24.04/scaleuireference/systemsettings/advancedsettingsscreen/)
describes selecting both TLS certificate and CA. These are the 24.04 native
fields; the helper does not use the 25.04+ versioned JSON-RPC schema.

The injected transport accepts `request(method, path, body=None)` and returns
decoded JSON. Paths are relative to the trusted `/api/v2.0` base. The transport
must enforce authenticated, certificate-verified HTTPS, the exact trusted target,
bounded timeouts and response sizes, no redirects, and sanitized errors. A
verified SSH tunnel may carry the HTTPS connection without weakening certificate
verification. Never log authorization headers, API response bodies, request bodies,
certificate private keys or full advanced settings. List endpoints can return
private keys and other sensitive fields.

Before its first mutation, the caller must durably capture the first
`GET /system/advanced` response's five owned fields in an owner-only private
before-state file. A request wrapper can perform that capture as the GET returns;
this remains necessary when a later import or update fails. The helper returns
that scope as `before` and `after` upon success. `ReconcileError.before` also holds
the scope for update/import/migration failures. There is no filesystem side effect
inside this helper. The caller owns protected persistence and recovery records.

Required private configuration:

```python
config = {
    'enabled': True,  # An actual boolean; absent/false/string/integer refuses calls.
    'expected_version': 'TrueNAS-SCALE-24.04.2.5',
    'syslogserver': '<verified RFC1918 receiver IPv4>:6514',
    'sysloglevel': 'F_INFO',
}
materials = {
    'ca_certificate': '<single PEM certificate for the selected syslog CA>',
    'client_certificate': '<single PEM client certificate signed by that CA>',
    'client_privatekey': '<matching unencrypted PEM client private key>',
}
```

The helper requires current certificates, a CA BasicConstraints extension, a
non-CA client with CLIENT_AUTH EKU, a matching client key and a valid direct client
signature from the provided CA. SHA1/MD5 signatures are rejected. Intermediate
chains are deliberately unsupported: select the issuing CA as the explicit trust
source. The relay's server certificate must also chain to that CA and identify
its configured receiver IPv4; receiver/server verification belongs to the PKI and
end-to-end checks. No CA private key is imported or needed.

An existing nonempty destination different from `syslogserver` is preserved unless
private `reviewed_previous_syslogserver` equals that exact observed string. This
is a migration declaration for an existing destination, not a request for renewed
approval of the already authorized empty-destination setup.

Only additive objects named `homelab_truenas_syslog_ca` and
`homelab_truenas_syslog_client` may be created. Both names are checked before any
import, including collisions across certificate/CA namespaces. Existing names
must have exactly the same SHA256 certificate fingerprint; the client must also
have a readable matching private key. Conflicts require a separately reviewed
rotation. The CA is not added to the global trusted store. No certificate,
unrelated object or prior configuration is deleted.

The middleware/REST mapping used by this helper is:

| Middleware method | REST operation |
| --- | --- |
| `system.version` | `GET /system/version` |
| `system.advanced.config` | `GET /system/advanced` |
| `system.advanced.update` | `PUT /system/advanced` |
| `certificateauthority.query` | `GET /certificateauthority` |
| `certificateauthority.create` | `POST /certificateauthority` |
| `certificate.query` | `GET /certificate` |
| `certificate.create` | `POST /certificate` |
| `core.get_jobs` | `GET /core/get_jobs?id=<created job id>` |

TrueNAS 24.04 REST API-key authorization uses HTTP verbs and resource paths,
**not** middleware `CALL` names. The bootstrap must use `client.REST_ALLOWLIST`,
which contains these exact eight entries with trailing slashes:

```json
[
  {"method": "GET", "resource": "/system/version/"},
  {"method": "GET", "resource": "/system/advanced/"},
  {"method": "PUT", "resource": "/system/advanced/"},
  {"method": "GET", "resource": "/certificateauthority/"},
  {"method": "POST", "resource": "/certificateauthority/"},
  {"method": "GET", "resource": "/certificate/"},
  {"method": "POST", "resource": "/certificate/"},
  {"method": "GET", "resource": "/core/get_jobs/"}
]
```

The [installed-release REST implementation](https://github.com/truenas/middleware/blob/TS-24.04.2.5/src/middlewared/middlewared/restful.py)
constructs authorization from the request method and generated path. The transport
always appends the trailing slash locally; job query filters are not part of the
allowlist resource. No wildcard, key-management, shell, delete, reboot or storage
permissions are needed. The transport may require trailing slashes according to the appliance's
REST router; it must normalize them locally instead of following redirects.
`core.get_jobs` is polled for up to 60 seconds, inspecting only the created job's
state. Job errors/results may contain secrets and are never exposed.

An update sends exactly the five owned fields. It rechecks the before-state just
before writing and reads back afterward. Matching desired state produces no
writes. Failed PUT/readback triggers a PUT of only the previous five fields,
followed by verification. `ReconcileError.rollback_verified` reports whether that
readback matched. If rollback cannot be verified, stop and inspect privately;
never claim full recovery. An additive import may remain after any subsequent
failure; retain it for a safe rerun rather than deleting an object that could now
be referenced. The caller should serialize appliance writes during reconciliation.

Offline verification:

```sh
python3 -m unittest ansible.tests.test_truenas_api -v
```

These tests do not establish encrypted delivery. After guarded deployment,
confirm the relay sees the intended TrueNAS client certificate and a harmless
TrueNAS log reaches the correct Wazuh manager with the intended source and decoder.
Native TLS setup alone does not prove successful ingestion or reboot recovery.

## Private controller transport and PKI

`client.py` provides `validate_profile(path, require_key=False)` (read-only) and
`configure(path)`. The guarded controller uses:

```sh
python3 monitoring/truenas/client.py configure --profile /absolute/private/profile.json
python3 monitoring/truenas/client.py validate --profile /absolute/private/profile.json
```

The private JSON profile contains the config fields above, plus `ssh_alias`
(exactly `home-lab-host`), `address` (the verified TrueNAS private IPv4),
`server_cert_sha256` (the exact DER SHA256 of its HTTPS certificate),
`server_certificate_file`, `api_key_file` and `pki_directory`.
`sysloglevel` defaults to `F_INFO`. File paths must be absolute, nonsymlink paths
outside the checkout; files must be owned by the controller user with mode 0600
inside an owned mode-0700 directory. Use the canonical `/private/tmp` path when
working on macOS rather than the `/tmp` symlink. Validation with
`require_key=False` permits a key file that has not yet been bootstrapped; it
still verifies the local HTTPS trust certificate and exact recorded pin.

The transport uses a fresh foreground SSH process with `-S none`, disabled
multiplexing, strict host-key checking and an ephemeral loopback forward to the
verified TrueNAS IPv4 on port 443 through the existing `home-lab-host` alias.
It cleans up that process on exit. Each API connection uses CERT_REQUIRED,
`server_hostname='localhost'` and the independently verified bootstrap certificate
as its explicit trust source, then checks the exact DER SHA256 pin before sending
Bearer authentication. Therefore that actual bootstrap certificate must identify
`localhost`. No redirects are followed. Paths/methods are restricted to the table
above; replies and timeouts are bounded. Only sanitized success summaries or
sanitized errors reach stdout/stderr.

Prepare the persistent private PKI offline before generating a saved plan:

```sh
python3 monitoring/truenas/pki.py --directory /absolute/private/syslog-pki \
  --receiver-ipv4 '<verified Wazuh private IPv4>'
```

The existing parent directory must be private; the final PKI directory can be
created as mode 0700. This creates `ca.pem`, `ca-key.pem`, `server.pem`,
`server-key.pem`, `client.pem` and `client-key.pem`, all mode 0600. The CA is
`homelab-truenas-syslog-ca`; the client is `homelab-truenas`, has CLIENT_AUTH EKU
and no SAN; the server has SERVER_AUTH EKU and exactly the receiver's IPv4 SAN.
CA validity is ten years and leaf validity 825 days. Track expiry and plan a
reviewed rotation before it expires. No existing file is overwritten; partial,
expired or conflicting sets fail closed. Keep the CA private key on the protected
controller; the receiver needs only the CA certificate and server pair.

`pki.validate_existing(directory, receiver_ipv4)` and the PKI CLI's
`--validate-only` are strictly read-only and validate the complete existing set.
The plan review should require and fingerprint these files; generation is a
separate explicit preparation step. Back up all six files privately before
redeployment. Configuration creates an owner-only `before-<random>.json` in the
PKI directory containing only the five owned syslog fields, flushes it to disk
before the first API mutation, and retains it for recovery. Neither private
artifact paths nor contents are printed.

Additional controller tests:

```sh
python3 -m unittest ansible.tests.test_truenas_client ansible.tests.test_truenas_api -v
```

## Exact 24.04.2.5 native TLS template repair (v2)

The installed release's [official syslog-ng template](https://github.com/truenas/middleware/blob/TS-24.04.2.5/src/middlewared/middlewared/etc_files/syslog-ng/syslog-ng.conf.mako)
uses `os.listdir` and symlink operations without importing `os`. The native
renderer can therefore log `Error symlinking syslog CA` with
`AttributeError: 'Undefined' object has no attribute 'listdir'`, omit the remote
destination, and still restart successfully. Correct API readback alone does not
prove that this release rendered its TLS destination.

`native_fix.py` declares two narrow corrections: add `import os` to the existing
opening Python block and format the CA hash symlink with `%08x.0` instead of
`%x.0`. OpenSSL requires eight hexadecimal digits in a
[CA-directory hash filename](https://docs.openssl.org/3.1/man1/openssl-rehash/).
A leading-zero subject hash otherwise creates a seven-digit link that native
certificate verification cannot find. It permits only version
`TrueNAS-SCALE-24.04.2.5` and the exact original SHA256
`042d13cb429f3ca9e50b65860f21e74ae13985b2d8f7ce1f840d815db92fba88`, the earlier os-only repair SHA256
`9622877fd7889d7d0141afe0f6c051dc1d0228e8392bd3203cedbaf310dfe053`, or the
fully repaired v2 SHA256
`54590db0c9bbc2e90a597acdf65071e588e0b3b40405e11bd9a03211bdd2f4c1`.
The template path is pinned to
`/usr/lib/python3/dist-packages/middlewared/etc_files/syslog-ng/syslog-ng.conf.mako`.
An unknown digest or release stops before changing anything; upgrades require a
new review instead of reapplying this patch blindly.

The protected repair declaration requires actual booleans
`console_administration_enabled: true` and
`native_syslog_template_fix_enabled: true`, plus `expected_vm_uuid`,
`expected_version`, `ssh_alias: home-lab-host` and the exact desired
`syslogserver` private IPv4 destination on port 6514. The existing authenticated
console verifies root UID, guest UUID and exact release before any write. The
repair accepts an empty native destination for fresh deployment, or the exact
already-declared destination with TLS. It refuses every other existing destination
and writes no advanced settings itself. The native client subsequently configures
fresh TLS forwarding through the normal reviewed API path.

Before replacing the template, the helper compiles the candidate with the native
Mako library and saves mode-0600 recovery files under root-owned mode-0700
`/root/.config/homelab-truenas`, flushing files and directory metadata. The vendor
`.original` backup and existing v1 receipt remain untouched. A separate
`syslog-ng.conf.mako.before-v2-<actual-before-sha256>` file preserves the actual
current template, and `syslog-ng-template-repair-v2.json` records before/target
hashes. Thus upgrading the os-only repair rolls back to that precise os-only
before-state if needed, while fresh deployment rolls back to the vendor original. Replacement is atomic and preserves original
ownership and mode; symlinks and writable-by-other template/recovery paths are
refused. It invokes native `etc.generate('syslogd')`, validates the generated file
with `syslog-ng -s`, and uses native `service.restart('syslogd')`. When the desired
TLS destination already exists in advanced settings, its rendered destination is
required before restart and again afterward. The selected CA must also have the
correct eight-digit hash symlink pointing exactly to its native certificate path;
only the native template generator creates that link. Native service health is
checked.
On failure after replacement it restores the exact actual saved before-template, regenerates,
validates and restarts native logging, and records whether rollback was verified.
An already repaired healthy template is verified without another write or restart.

The controller saves the sanitized result and console nonce recovery path privately
before acknowledging the guest reply. The function `repair(declaration_path)`
returns `changed`, `native_template_verified` and
`remote_destination_verified`; the latter is false for an intentionally empty
fresh destination. The CLI is:

```sh
python3 monitoring/truenas/native_fix.py --declaration /absolute/private/repair.json
python3 -m unittest ansible.tests.test_truenas_native_fix -v
```

Keep the declaration and guest backup in private recovery material. Replay this
versioned repair during rebuilding the same exact release, before the native API
client configures TLS forwarding. No guest packages, SSH service, network or
storage configuration are changed. Successful template repair and generated TLS
configuration still require a harmless end-to-end event check at the receiver
and Wazuh before claiming delivery.

The protected `/usr` mount additionally requires the actual boolean declaration
`native_syslog_usr_remount_enabled: true` when the original template needs repair.
The helper binds `/usr`'s mounted ZFS source to the root-owned native
`/conf/truenas_root_ds.json` `usr` entry and dataset GUID, requires the native RO
option, `/usr` mountpoint, `canmount=noauto`, and baseline `readonly=on` with source
`local`. It saves a separate mode-0600 `usr-remount-before.json` under the private
root recovery directory before any remount. Only `/usr` is temporarily remounted
with `mount -o remount,rw /usr`; a guest-side `finally` remounts it read-only and
checks the exact original options, source, GUID and dataset-property values and
sources. These [temporary OpenZFS mount overrides](https://openzfs.github.io/openzfs-docs/man/v2.2/7/zfsprops.7.html#Temporary_Mount_Point_Properties)
do not change stored dataset properties. No `zfs set`, developer mode, package
permission or other dataset change is used. The guest cleanup continues if the
controller disconnects. A restoration failure is an explicit failed outcome;
`usr_readonly_verified` must be true before completion. An already patched
appliance verifies its original read-only protection without remounting it.
