# Backup and recovery

Configuration code, Terraform state, pool metadata, management configuration, guest disks and application data protect different layers. Define which are needed, keep private copies outside the host, and test recovery in isolation.

Keep backup images, manifests, keys, credentials and actual recovery mappings out of Git. Use owner-only directories/files. Keep encryption keys separately recoverable from ciphertext. A copy on another disk in the same host is useful preservation but does not protect against whole-host loss.

## Preservation and verification

Use supported native export/copy operations. For a halted guest, copy its reviewed disk head. For a running guest, use the supported snapshot/backup consistency mechanism and describe whether it is crash-consistent or application-consistent. Preserve sources until a separately authorized recovery decision.

Record source/destination identities, scope, native task results, destination metadata and the checks actually performed in a private manifest. Native copy success or a readable image header is not a bytewise readback, restore boot or application-consistency test. Stop on copy/read errors rather than repeatedly stressing failing storage.

Raw guest configuration archives may contain passwords, hashes and private keys. Discovery archives and temporary controller files are not durable backups. Do not publish them or treat them as blanket restoration instructions.

## Authenticated backup containers

If using the controller's AES-GCM pool-export format, keep its versioned header, nonce and ciphertext/tag together, and verify against the private manifest. The following generic example decrypts and validates in memory; it never prints a key or plaintext:

```python
from pathlib import Path
import hashlib
import json
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

base = Path("/secure/controller/backups")
manifest = json.loads((base / "pool.manifest.json").read_text())
key = (base / "pool.key").read_bytes()
blob = (base / "pool.encrypted").read_bytes()
header = b"HOME-LAB-POOL-AES256GCM-v1\x00"
assert blob.startswith(header)
assert hashlib.sha256(blob).hexdigest() == manifest["encrypted_sha256"]
offset = len(header)
plaintext = AESGCM(key).decrypt(blob[offset:offset + 12], blob[offset + 12:], header)
assert hashlib.sha256(plaintext).hexdigest() == manifest["sha256"]
ET.fromstring(plaintext)
print("Backup integrity verified")
```

Use the header/version recorded by the actual exporter; do not guess offsets or silently change a format. A decryption check is not a restore test. Keep any temporary plaintext in an owner-only temporary filesystem and remove it after authorized use.

## Restore order

1. Preserve old storage and isolate the suspected fault before maintenance.
2. Prepare compatible host software, known-good storage and independent recovery access.
3. Rehearse pool metadata recovery on an isolated replacement with the intended storage available.
4. Recover required guest disks and management configuration; metadata alone does not contain disk contents.
5. Restore appropriate private Terraform state, rediscover identities and review every binding before apply.
6. Reconcile supported configuration only after its gates pass; restore application data from separately tested backups.

Native startup policy can pin reviewed identities independently of bootstrap/state. A changed recovered identity needs an explicit review of that policy. Do not bypass a refusal or equate a no-op plan with complete disaster recovery.
