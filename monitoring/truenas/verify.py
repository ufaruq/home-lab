#!/usr/bin/env python3
"""Emit a native appliance event or check the private receiver's TLS boundary."""
import argparse
import contextlib
import datetime as dt
import importlib.util
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time


def _sibling(name):
    spec = importlib.util.spec_from_file_location('truenas_verify_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


console = _sibling('console')
client = _sibling('client')
pki = client.pki


def validate_event(event):
    if not isinstance(event, str) or not re.fullmatch('[a-z0-9-]{1,96}', event):
        raise ValueError('Invalid test nonce')
    return event


def event_program(expected_uuid, event):
    event = validate_event(event)
    if not re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', expected_uuid):
        raise ValueError('Invalid expected guest identity')
    return console.GUEST + '''
if identity != %r:raise ValueError('Identity changed')
subprocess.run(['logger','-p','auth.notice','-t','homelab-monitoring',%r],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
identity.update({'event_emitted':True})
reply(identity)
''' % ({'uid': 0, 'uuid': expected_uuid, 'version': console.VERSION},
       'HOMELAB_MONITORING_TEST: truenas-' + event)


def emit_event(declaration_path, event):
    declaration = json.loads(pki.read_private(declaration_path))
    if (declaration.get('console_administration_enabled') is not True
            or declaration.get('expected_version') != console.VERSION
            or declaration.get('ssh_alias') != 'home-lab-host'):
        raise ValueError('Reviewed console declaration required')
    expected = declaration['expected_vm_uuid']
    program = event_program(expected, event)
    reply = console.execute(declaration['ssh_alias'], expected, program)
    console.verify_identity(reply, expected)
    if reply.get('event_emitted') is not True:
        raise ValueError('Event emission did not verify')
    console.acknowledge(declaration['ssh_alias'], expected, reply['_console_reply_path'])
    return {'event_emitted': True, 'guest_identity_verified': True}


@contextlib.contextmanager
def receiver_tunnel(profile):
    """Temporary forwarding only; no SSH multiplex reuse or persistent state."""
    receiver = profile['syslogserver'].rsplit(':', 1)[0]
    process = None
    try:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen([
            'ssh', '-N', '-T', '-S', 'none', '-o', 'ControlMaster=no',
            '-o', 'ControlPersist=no', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ConnectTimeout=10', '-L', f'127.0.0.1:{port}:{receiver}:6514',
            profile['ssh_alias']], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                raise ValueError('SSH receiver forwarding failed')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    pass
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise ValueError('SSH receiver forwarding timed out') from None
                time.sleep(0.1)
        yield port
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def tls_context(files, certificate=None, key=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Pin protocol for comparable probes. GnuTLS authorizes peers after the
    # cryptographic handshake even under TLS 1.2, so observe the read boundary.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=files['ca.pem'])
    if certificate is not None:
        context.load_cert_chain(certfile=files[certificate], keyfile=files[key])
    return context


def observe_connection(context, port, receiver, message):
    """Observe rsyslog's post-handshake authorization, without claiming an ACK.

    gtls requests a certificate, completes the TLS handshake, then checks peer
    authorization and closes rejected sessions. Syslog sends no response on an
    approved idle connection. Only a completed, verified TLS session surviving
    the bounded read timeout is the positive control.
    """
    with socket.create_connection(('127.0.0.1', port), timeout=8) as raw:
        try:
            with context.wrap_socket(raw, server_hostname=receiver) as connection:
                if connection.version() != 'TLSv1.2':
                    raise ValueError('Unexpected TLS protocol')
                connection.sendall(message)
                connection.settimeout(3)
                try:
                    response = connection.recv(1)
                except TimeoutError:
                    return 'open'
                if response == b'':
                    return 'closed'
                raise ValueError('Unexpected syslog server response')
        except ssl.SSLCertVerificationError:
            # A failure to authenticate the server is not client-auth rejection.
            raise
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
            return 'closed'
        except ssl.SSLError as error:
            # Accept explicit peer fatal TLS alerts, never generic local TLS errors.
            reason = getattr(error, 'reason', '') or ''
            if '_ALERT_' in reason and any(word in reason for word in
                    ('CERTIFICATE', 'UNKNOWN_CA', 'ACCESS_DENIED', 'HANDSHAKE_FAILURE')):
                return 'closed'
            raise


def tls_check(profile_path, event):
    event = validate_event(event)
    profile = client.validate_profile(profile_path, require_key=False)
    receiver = profile['syslogserver'].rsplit(':', 1)[0]
    files = pki.validate_existing(profile['pki_directory'], receiver)
    trusted = tls_context(files, 'client.pem', 'client-key.pem')
    missing = tls_context(files)
    # Same issuing CA, different CN and SERVER_AUTH-only EKU. This specifically
    # exercises client identity/purpose enforcement, not an untrusted-CA failure.
    wrong = tls_context(files, 'server.pem', 'server-key.pem')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%b %d %H:%M:%S')
    # Nonces on authentication probes are distinct from the final source probe.
    probe = (f'<85>{stamp} truenas-tls-probe homelab-monitoring: '
             'HOMELAB_TLS_AUTH_PROBE: ' + event + '\n').encode('ascii')
    with receiver_tunnel(profile) as port:
        if observe_connection(trusted, port, receiver, probe) != 'open':
            raise ValueError('Approved TLS positive control failed')
        no_client_rejected = observe_connection(missing, port, receiver, probe) == 'closed'
        wrong_client_rejected = observe_connection(wrong, port, receiver, probe) == 'closed'
        if not no_client_rejected or not wrong_client_rejected:
            raise ValueError('Receiver client authentication boundary failed')
        # Bracket the negative checks with the same approved control to reject
        # whole-service failures as evidence of client authentication.
        if observe_connection(trusted, port, receiver, probe) != 'open':
            raise ValueError('Approved TLS follow-up control failed')
        message = (f'<85>{stamp} truenas-tls-probe homelab-monitoring: '
                   'HOMELAB_MONITORING_TEST: source-filter-' + event + '\n').encode('ascii')
        if observe_connection(trusted, port, receiver, message) != 'open':
            raise ValueError('Source-filter probe connection did not remain open')
    # The tunnel originates from the hypervisor. This proves sending only;
    # independently check the manager log excludes the source-filter marker.
    return {'trusted_client_accepted': True, 'missing_client_rejected': True,
            'wrong_client_rejected': True, 'source_filter_probe_sent': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--declaration')
    parser.add_argument('--event')
    parser.add_argument('--tls-check', action='store_true')
    parser.add_argument('--profile')
    args = parser.parse_args()
    if args.tls_check:
        if not args.profile or args.declaration:
            parser.error('--tls-check requires --profile and no --declaration')
    elif not args.declaration or not args.event or args.profile:
        parser.error('native event requires --declaration and --event')
    try:
        result = (tls_check(args.profile, args.event or secrets.token_hex(16)) if args.tls_check
                  else emit_event(args.declaration, args.event))
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({'verified': False}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
