#!/usr/bin/env python3
"""Private controller transport for native TrueNAS API reconciliation."""
import argparse
import contextlib
import hashlib
import http.client
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit


def _sibling(name):
    spec = importlib.util.spec_from_file_location('homelab_truenas_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = _sibling('api')
pki = _sibling('pki')


# TrueNAS 24.04 REST authorization matches the HTTP verb and generated resource
# path, including the trailing slash. Query filters are not part of resource.
REST_ALLOWLIST = [
    {'method': method, 'resource': resource}
    for method, resource in (
        ('GET', '/system/version/'),
        ('GET', '/system/advanced/'), ('PUT', '/system/advanced/'),
        ('GET', '/certificateauthority/'), ('POST', '/certificateauthority/'),
        ('GET', '/certificate/'), ('POST', '/certificate/'),
        ('GET', '/core/get_jobs/'),
    )
]


class ClientError(ValueError):
    pass


def _private_ipv4(value):
    ip = ipaddress.IPv4Address(value)
    if not any(ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError()
    return str(ip)


def validate_profile(profile_path, *, require_key=False):
    """Read-only private profile validation; return normalized configuration dict."""
    try:
        if isinstance(profile_path, dict):
            profile = dict(profile_path)
        else:
            profile = json.loads(pki.read_private(profile_path))
        if not isinstance(profile, dict) or profile.get('enabled') is not True:
            raise ValueError()
        if profile.get('expected_version') != api.VERSION or profile.get('ssh_alias') != 'home-lab-host':
            raise ValueError()
        profile['address'] = _private_ipv4(profile['address'])
        receiver, port = profile['syslogserver'].rsplit(':', 1)
        if port != '6514' or _private_ipv4(receiver) != receiver:
            raise ValueError()
        if profile.get('sysloglevel', 'F_INFO') != 'F_INFO':
            raise ValueError()
        profile['sysloglevel'] = 'F_INFO'
        pin = profile['server_cert_sha256'].lower()
        if not re.fullmatch('[0-9a-f]{64}', pin):
            raise ValueError()
        profile['server_cert_sha256'] = pin
        cert_path = pki.private_path(profile['server_certificate_file'])
        pem = pki.read_private(cert_path).decode('ascii')
        if pem.count('-----BEGIN CERTIFICATE-----') != 1 or 'PRIVATE KEY' in pem:
            raise ValueError()
        der = ssl.PEM_cert_to_DER_cert(pem)
        if hashlib.sha256(der).hexdigest() != pin:
            raise ValueError()
        # Validate its parse/trust-file suitability, never disable verification.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=pem)
        profile['server_certificate_file'] = str(cert_path)
        profile['pki_directory'] = str(pki.private_directory(profile['pki_directory']))
        key_path = pki.private_path(profile['api_key_file'])
        if require_key:
            _read_key(key_path)
        profile['api_key_file'] = str(key_path)
        if 'reviewed_previous_syslogserver' in profile and not isinstance(profile['reviewed_previous_syslogserver'], str):
            raise ValueError()
        return profile
    except Exception:
        raise ClientError('Invalid private TrueNAS profile, trust pin, file ownership or permissions') from None


def _read_key(path):
    try:
        key = pki.read_private(path, limit=16384).decode('ascii').strip()
        if not key or any(ord(char) <= 32 or ord(char) >= 127 for char in key):
            raise ValueError()
        return key
    except Exception:
        raise ClientError('Invalid private API key file') from None


class _PinnedConnection(http.client.HTTPConnection):
    def __init__(self, port, context, pin):
        super().__init__('127.0.0.1', port, timeout=15)
        self._context, self._pin = context, pin

    def connect(self):
        raw = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        try:
            wrapped = self._context.wrap_socket(raw, server_hostname='localhost')
            if hashlib.sha256(wrapped.getpeercert(binary_form=True)).hexdigest() != self._pin:
                wrapped.close()
                raise ClientError('TrueNAS HTTPS certificate pin mismatch')
            self.sock = wrapped
        except Exception:
            raw.close()
            raise ClientError('TrueNAS HTTPS identity verification failed') from None


class RestTransport:
    """Fresh TLS verification and exact pin check precede reading/sending any key."""
    def __init__(self, profile, port):
        self.profile = profile
        self.port = port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(cadata=pki.read_private(profile['server_certificate_file']).decode('ascii'))

    def __call__(self, method, path, body=None):
        conn = None
        try:
            parsed = urlsplit(path)
            allowed = {(entry['method'], entry['resource']) for entry in REST_ALLOWLIST}
            if (method, parsed.path + '/') not in allowed or parsed.scheme or parsed.netloc or parsed.fragment:
                raise ValueError()
            if parsed.path == '/core/get_jobs':
                if not re.fullmatch('id=[1-9][0-9]*', parsed.query):
                    raise ValueError()
            elif parsed.query:
                raise ValueError()
            conn = _PinnedConnection(self.port, self.context, self.profile['server_cert_sha256'])
            conn.connect()  # Authentication must never precede this verified handshake.
            key = _read_key(self.profile['api_key_file'])
            target = '/api/v2.0' + parsed.path + '/' + ('?' + parsed.query if parsed.query else '')
            encoded = None if body is None else json.dumps(body, separators=(',', ':')).encode()
            conn.request(method, target, body=encoded,
                         headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json', 'Accept': 'application/json'})
            response = conn.getresponse()
            if not 200 <= response.status < 300:
                raise ValueError()  # Includes every redirect. Never read/print error bodies.
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError()
            return json.loads(data)
        except Exception:
            raise ClientError('TrueNAS verified API request failed') from None
        finally:
            if conn is not None:
                conn.close()


@contextlib.contextmanager
def tunnel(profile):
    process = None
    try:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        args = ['ssh', '-N', '-T', '-S', 'none', '-o', 'ControlMaster=no', '-o', 'ControlPersist=no',
                '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ExitOnForwardFailure=yes',
                '-o', 'ConnectTimeout=15', '-L', f'127.0.0.1:{port}:{profile["address"]}:443', profile['ssh_alias']]
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 20
        while True:
            if process.poll() is not None:
                raise ClientError('Verified SSH tunnel could not be established')
            try:
                # Verify actual remote TLS/pin, not merely a locally listening port.
                probe = _PinnedConnection(port, _trust_context(profile), profile['server_cert_sha256'])
                try:
                    probe.connect()
                finally:
                    probe.close()
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise ClientError('Verified SSH tunnel readiness failed') from None
                time.sleep(0.2)
        yield port
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def _trust_context(profile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=pki.read_private(profile['server_certificate_file']).decode('ascii'))
    return context


def configure(profile_path):
    profile = validate_profile(profile_path, require_key=True)
    directory = pki.private_directory(profile['pki_directory'])
    files = pki.ensure_materials(directory, profile['syslogserver'].rsplit(':', 1)[0])
    materials = dict(ca_certificate=pki.read_private(files['ca.pem']).decode(),
                     client_certificate=pki.read_private(files['client.pem']).decode(),
                     client_privatekey=pki.read_private(files['client-key.pem']).decode())
    backup = directory / ('before-' + uuid.uuid4().hex + '.json')
    captured = False
    with tunnel(profile) as port:
        transport = RestTransport(profile, port)
        def request(method, path, body=None):
            nonlocal captured
            if method != 'GET' and not captured:
                raise ClientError('Private before-state has not been saved')
            response = transport(method, path, body)
            if method == 'GET' and path == '/system/advanced' and not captured:
                scope = api._scope(response)
                pki.write_new(backup, json.dumps(scope, sort_keys=True).encode())
                captured = True
            return response
        result = api.reconcile(request, profile, materials)
    # Do not expose private addresses, paths, certificates or full API state.
    return {'changed': result['changed'], 'before_state_saved': captured,
            'imported': result['imported']}


def main():
    parser = argparse.ArgumentParser(description='Configure reviewed native TrueNAS TLS syslog')
    parser.add_argument('command', nargs='?', choices=['configure', 'validate'], default='configure')
    parser.add_argument('--profile', required=True)
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.validate_only or args.command == 'validate':
            validate_profile(args.profile, require_key=True)
            print(json.dumps({'valid': True}))
        else:
            print(json.dumps(configure(args.profile), sort_keys=True))
    except Exception:
        print('TrueNAS operation failed; inspect private trust, profile and scoped recovery evidence.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
