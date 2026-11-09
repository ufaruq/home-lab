#!/usr/bin/env python3
"""Repeatable native-console credential bootstrap for a selected TrueNAS VM.

The private declaration must explicitly authorize console administration and bind
the VM identity. No web password is reset, and no guest SSH service is enabled.
"""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sibling(name):
    spec = importlib.util.spec_from_file_location('truenas_bootstrap_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


console = sibling('console')
client = sibling('client')
pki = client.pki
KEY_NAME = 'homelab_truenas_syslog'


def key_program(expected_uuid, public_key):
    # All interpolated values are public. The credential remains guest-memory-only
    # until RSA-OAEP encryption. Native midclt output is captured, never displayed.
    public = base64.b64encode(public_key).decode()
    return console.GUEST + '''
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding
if identity != %r:raise ValueError('Identity changed')
pub=serialization.load_pem_public_key(base64.b64decode(%r))
if pub.key_size!=2048:raise ValueError('Bootstrap encryption key differs')
existing=mid('api_key.query', [['name','=',%r]])
if existing:raise ValueError('Owned key exists; restore controller credential instead of rotating')
created=mid('api_key.create',{'name':%r,'allowlist':%r})
cipher=pub.encrypt(created['key'].encode(),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
identity.update({'encrypted_key':base64.b64encode(cipher).decode(),'key_id':created['id']})
reply(identity)
''' % ({'uid': 0, 'uuid': expected_uuid, 'version': console.VERSION}, public,
       KEY_NAME, KEY_NAME, client.REST_ALLOWLIST)


def bootstrap(declaration_path):
    declaration = json.loads(pki.read_private(declaration_path))
    if declaration.get('console_administration_enabled') is not True or declaration.get('expected_version') != console.VERSION:
        raise ValueError('Explicit supported console bootstrap declaration required')
    vm = declaration.get('expected_vm_uuid', '')
    if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', vm):
        raise ValueError('Expected VM identity required')
    if declaration.get('ssh_alias') != 'home-lab-host':
        raise ValueError('Use the existing pinned management route')
    profile_path = pki.private_path(declaration['profile_file'])
    key_path = pki.private_path(declaration['api_key_file'])
    cert_path = pki.private_path(declaration['server_certificate_file'])
    pending_path = key_path.with_name('bootstrap-pending.json')
    encryption_path = key_path.with_name('bootstrap-recovery-key.pem')
    ciphertext_path = key_path.with_name('bootstrap-encrypted-reply.json')
    outputs = (profile_path, key_path, cert_path, pending_path, encryption_path, ciphertext_path)
    if len(set(outputs)) != len(outputs):
        raise ValueError('Bootstrap output paths must be distinct')
    pki.private_directory(key_path.parent)
    for output in (profile_path, cert_path):
        pki.private_directory(output.parent)
    client._private_ipv4(declaration['address'])
    receiver, port = declaration['syslogserver'].rsplit(':', 1)
    if port != '6514' or client._private_ipv4(receiver) != receiver or receiver == declaration['address']:
        raise ValueError('Distinct private appliance/receiver addresses and TLS6514 required')
    if profile_path.exists():
        profile = client.validate_profile(profile_path, require_key=True)
        if profile.get('expected_vm_uuid') != vm or profile['address'] != declaration['address']:
            raise ValueError('Existing bootstrap profile belongs to another VM')
        with client.tunnel(profile) as port:
            if client.RestTransport(profile, port)('GET', '/system/version') != console.VERSION:
                raise ValueError('Existing API credential/version did not verify')
        pki.validate_existing(profile['pki_directory'], profile['syslogserver'].split(':')[0])
        return {'changed': False, 'credential_verified': True}
    if any(path.exists() or path.is_symlink() for path in (key_path, cert_path, pending_path, encryption_path, ciphertext_path)):
        raise ValueError('Partial bootstrap exists; recover privately before retrying')
    pki.ensure_materials(declaration['pki_directory'], receiver)
    identity = console.discover(declaration['ssh_alias'], vm)
    pki.write_new(cert_path, identity['certificate'].encode())
    profile = {name: declaration[name] for name in ('address', 'ssh_alias', 'api_key_file',
        'server_certificate_file', 'pki_directory', 'syslogserver', 'expected_version', 'expected_vm_uuid')}
    profile.update(enabled=True, server_cert_sha256=identity['sha256'], sysloglevel='F_INFO')
    client.validate_profile(profile, require_key=False)
    # Preserve the asymmetric recovery key BEFORE creating the appliance credential.
    # Interrupted creation can be recovered with this key + encrypted reply; never
    # create another credential blindly after a partially completed bootstrap.
    encryption_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pki.write_new(encryption_path, encryption_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pki.write_new(pending_path, json.dumps({'vm_uuid': vm, 'key_name': KEY_NAME,
        'status': 'creation_may_be_pending'}).encode())
    public_key = encryption_key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    reply = console.execute(declaration['ssh_alias'], vm, key_program(vm, public_key))
    pki.write_new(ciphertext_path, json.dumps(reply).encode())
    if '_console_reply_path' in reply:
        console.acknowledge(declaration['ssh_alias'], vm, reply['_console_reply_path'])
    secret = encryption_key.decrypt(base64.b64decode(reply['encrypted_key'], validate=True),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    if not secret or len(secret) > 1024 or any(c <= 32 or c >= 127 for c in secret):
        raise ValueError('Invalid bootstrap credential')
    pki.write_new(key_path, secret + b'\n')
    pki.write_new(profile_path, json.dumps(profile, indent=2).encode())
    verified = client.validate_profile(profile_path, require_key=True)
    with client.tunnel(verified) as port:
        if client.RestTransport(verified, port)('GET', '/system/version') != console.VERSION:
            raise ValueError('Created API credential did not verify')
    # Retain encrypted recovery artifacts privately; they also prove the key ID
    # and exact guest identity without publishing credentials.
    return {'changed': True, 'credential_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--declaration', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(bootstrap(args.declaration), sort_keys=True))
    except Exception:
        print('TrueNAS bootstrap stopped; inspect private declaration, console and recovery artifacts. No password reset or automatic key rotation was attempted.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
