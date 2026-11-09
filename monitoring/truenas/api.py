"""Narrow TrueNAS SCALE 24.04.2.5 native TLS syslog reconciliation.

The injected request transport owns authentication, verified HTTPS, timeouts and
private before-state persistence. Never log request/response bodies.
"""
import datetime as dt
import ipaddress
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

VERSION = 'TrueNAS-SCALE-24.04.2.5'
CA_NAME = 'homelab_truenas_syslog_ca'
CLIENT_NAME = 'homelab_truenas_syslog_client'
OWNED_FIELDS = ('syslogserver', 'syslog_transport', 'syslog_tls_certificate',
                'syslog_tls_certificate_authority', 'sysloglevel')


class ReconcileError(ValueError):
    """Sanitized failure. before contains only scoped syslog settings, if read."""
    def __init__(self, message, *, before=None, rollback_verified=False):
        super().__init__(message)
        self.before = before
        self.rollback_verified = rollback_verified


def _public_key(key):
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def _cert(pem):
    # Single certificates only: the selected CA is the explicit trust source.
    if not isinstance(pem, str) or pem.count('-----BEGIN CERTIFICATE-----') != 1:
        raise ReconcileError('Expected exactly one PEM certificate per material')
    return x509.load_pem_x509_certificate(pem.encode())


def _materials(materials):
    try:
        ca = _cert(materials['ca_certificate'])
        client = _cert(materials['client_certificate'])
        key = serialization.load_pem_private_key(materials['client_privatekey'].encode(), password=None)
        now = dt.datetime.now(dt.timezone.utc)
        for cert in (ca, client):
            if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
                raise ValueError('validity')
            if cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.name in ('sha1', 'md5'):
                raise ValueError('weak signature')
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('not a CA')
        if client.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('client is CA')
        if ExtendedKeyUsageOID.CLIENT_AUTH not in client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise ValueError('missing client authentication')
        client.verify_directly_issued_by(ca)
        if _public_key(client.public_key()) != _public_key(key.public_key()):
            raise ValueError('key mismatch')
        return ca, client
    except Exception:
        raise ReconcileError('Invalid, expired, untrusted or mismatched TLS certificate material') from None


def _call(request, method, path, body=None):
    try:
        return request(method, path, body) if body is not None else request(method, path)
    except Exception:
        # Transport exceptions may contain bodies, headers or private keys.
        raise ReconcileError('TrueNAS API request failed') from None


def _scope(response):
    if not isinstance(response, dict) or any(k not in response for k in OWNED_FIELDS):
        raise ReconcileError('TrueNAS advanced settings lack the expected 24.04 syslog schema')
    scope = {k: response[k] for k in OWNED_FIELDS}
    if not isinstance(scope['syslogserver'], str):
        raise ReconcileError('Unexpected syslog destination schema')
    for field in ('syslog_tls_certificate', 'syslog_tls_certificate_authority'):
        if scope[field] is not None and type(scope[field]) is not int:
            raise ReconcileError('Unexpected syslog certificate reference schema')
    return scope


def _find(rows, name, cert, *, client=False):
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReconcileError('Unexpected certificate query schema')
    matches = [row for row in rows if row.get('name') == name]
    if len(matches) > 1:
        raise ReconcileError('Ambiguous managed certificate name')
    if not matches:
        return None
    row = matches[0]
    try:
        if _cert(row['certificate']).fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256()):
            raise ValueError('different certificate')
        if type(row['id']) is not int or row['id'] <= 0:
            raise ValueError('invalid identity')
        if client:
            key = serialization.load_pem_private_key(row['privatekey'].encode(), password=None)
            if _public_key(key.public_key()) != _public_key(cert.public_key()):
                raise ValueError('different key')
        return row['id']
    except Exception:
        raise ReconcileError('Managed certificate name conflicts with existing material') from None


def _wait_job(request, job_id):
    if type(job_id) is not int or job_id <= 0:
        raise ReconcileError('Unexpected certificate import job response')
    deadline = time.monotonic() + 60
    while True:
        rows = _call(request, 'GET', f'/core/get_jobs?id={job_id}')
        if not isinstance(rows, list) or len(rows) != 1 or rows[0].get('id') != job_id:
            raise ReconcileError('Certificate import job was not found')
        state = rows[0].get('state')
        if state == 'SUCCESS':
            return
        if state not in ('WAITING', 'RUNNING'):
            raise ReconcileError('Certificate import job failed')
        if time.monotonic() >= deadline:
            raise ReconcileError('Certificate import job timed out; inspect privately before retrying')
        time.sleep(0.5)


def reconcile(request, config, materials):
    """Return {changed, before, after, imported}; never return PEM/key/API bodies.

    Only enabled=True permits calls. Existing destinations can migrate only if
    reviewed_previous_syslogserver exactly names the current destination. The
    caller must persist the scoped GET before the first mutation (see API.md).
    """
    if config.get('enabled') is not True:
        raise ReconcileError('Native TrueNAS syslog requires enabled=true')
    if config.get('expected_version') != VERSION:
        raise ReconcileError('Only the reviewed exact TrueNAS release is supported')
    server = config.get('syslogserver', '')
    try:
        host, port = server.rsplit(':', 1)
        ip = ipaddress.IPv4Address(host)
        allowed = any(ip in ipaddress.IPv4Network(network) for network in
                      ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
        if port != '6514' or not allowed or str(ip) != host:
            raise ValueError('destination')
    except Exception:
        raise ReconcileError('Syslog requires an RFC1918 IPv4 address and TLS port 6514') from None
    if config.get('sysloglevel') != 'F_INFO':
        raise ReconcileError('Only the reviewed F_INFO syslog level is supported')
    ca, client = _materials(materials)
    if _call(request, 'GET', '/system/version') != VERSION:
        raise ReconcileError('Live TrueNAS version differs from the reviewed exact version')
    before = _scope(_call(request, 'GET', '/system/advanced'))
    previous = before['syslogserver']
    if previous and previous != server and config.get('reviewed_previous_syslogserver') != previous:
        raise ReconcileError('Existing syslog destination requires a reviewed exact migration', before=before)
    # Preflight both names before creating either, including cross-type conflicts.
    cas = _call(request, 'GET', '/certificateauthority')
    clients = _call(request, 'GET', '/certificate')
    ca_id = _find(cas, CA_NAME, ca)
    client_id = _find(clients, CLIENT_NAME, client, client=True)
    if any(row.get('name') == CLIENT_NAME for row in cas) or any(row.get('name') == CA_NAME for row in clients):
        raise ReconcileError('Managed certificate name belongs to the wrong object type', before=before)
    imported = []
    try:
        if ca_id is None:
            _call(request, 'POST', '/certificateauthority', {
                'name': CA_NAME, 'create_type': 'CA_CREATE_IMPORTED',
                'certificate': materials['ca_certificate'], 'add_to_trusted_store': False})
            ca_id = _find(_call(request, 'GET', '/certificateauthority'), CA_NAME, ca)
            if ca_id is None:
                raise ReconcileError('Imported CA did not appear in readback')
            imported.append(CA_NAME)
        if client_id is None:
            job = _call(request, 'POST', '/certificate', {
                'name': CLIENT_NAME, 'create_type': 'CERTIFICATE_CREATE_IMPORTED',
                'certificate': materials['client_certificate'],
                'privatekey': materials['client_privatekey']})
            _wait_job(request, job)
            client_id = _find(_call(request, 'GET', '/certificate'), CLIENT_NAME, client, client=True)
            if client_id is None:
                raise ReconcileError('Imported client certificate did not appear in readback')
            imported.append(CLIENT_NAME)
    except Exception:
        raise ReconcileError('Certificate import failed; inspect additive objects privately before retrying', before=before) from None
    desired = dict(syslogserver=server, syslog_transport='TLS',
                   syslog_tls_certificate=client_id, syslog_tls_certificate_authority=ca_id,
                   sysloglevel='F_INFO')
    if desired == before:
        return dict(changed=bool(imported), before=before, after=desired, imported=imported)
    # Re-read immediately before writing to avoid overwriting a concurrent edit.
    if _scope(_call(request, 'GET', '/system/advanced')) != before:
        raise ReconcileError('Syslog changed concurrently; no settings were written', before=before)
    try:
        _call(request, 'PUT', '/system/advanced', desired)
        if _scope(_call(request, 'GET', '/system/advanced')) != desired:
            raise ReconcileError('Syslog readback mismatch')
    except Exception:
        verified = False
        try:
            _call(request, 'PUT', '/system/advanced', before)
            verified = _scope(_call(request, 'GET', '/system/advanced')) == before
        except Exception:
            pass
        raise ReconcileError('Syslog update failed; rollback ' + ('verified' if verified else 'could not be verified'),
                             before=before, rollback_verified=verified) from None
    return dict(changed=True, before=before, after=desired, imported=imported)
