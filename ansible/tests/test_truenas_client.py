"""Offline controller trust, credential ordering, private input and PKI checks."""
import contextlib
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SPEC = importlib.util.spec_from_file_location('truenas_client', Path(__file__).resolve().parents[2] / 'monitoring/truenas/client.py')
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class ControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = dt.datetime.now(dt.timezone.utc)
        cls.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(1).not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                    .sign(key, hashes.SHA256()))
        cls.pem = cls.cert.public_bytes(serialization.Encoding.PEM)
        cls.der = cls.cert.public_bytes(serialization.Encoding.DER)
        cls.pin = hashlib.sha256(cls.der).hexdigest()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        os.chmod(self.directory, 0o700)
        self.trust = self.directory / 'trust.pem'
        self.key = self.directory / 'key'
        client.pki.write_new(self.trust, self.pem)
        client.pki.write_new(self.key, b'EXAMPLE-SECRET-KEY')
        self.profile = dict(enabled=True, expected_version=client.api.VERSION, ssh_alias='home-lab-host',
                            address='192.168.1.9', syslogserver='192.168.1.10:6514', server_cert_sha256=self.pin,
                            server_certificate_file=str(self.trust), api_key_file=str(self.key),
                            pki_directory=str(self.directory))
        self.profile_file = self.directory / 'profile.json'
        client.pki.write_new(self.profile_file, json.dumps(self.profile).encode())

    def test_validation_has_no_network_or_write_side_effects(self):
        with patch.object(client.subprocess, 'Popen', side_effect=AssertionError()), patch.object(client.pki, 'write_new', side_effect=AssertionError()):
            result = client.validate_profile(self.profile_file, require_key=True)
        self.assertEqual(result['sysloglevel'], 'F_INFO')

    def test_private_modes_symlinks_and_repository_rejected(self):
        os.chmod(self.key, 0o644)
        with self.assertRaises(client.ClientError):
            client.validate_profile(self.profile_file, require_key=True)
        os.chmod(self.key, 0o600)
        alias = self.directory / 'alias'
        alias.symlink_to(self.key)
        self.profile['api_key_file'] = str(alias)
        with self.assertRaises(client.ClientError):
            client.validate_profile(self.profile, require_key=True)
        with self.assertRaises(client.pki.PrivateInputError):
            client.pki.private_path(Path(__file__).resolve())
        os.chmod(self.directory, 0o755)
        with self.assertRaises(client.ClientError):
            client.validate_profile(self.profile_file, require_key=True)
        os.chmod(self.directory, 0o700)

    def test_bootstrap_validation_does_not_require_key_yet(self):
        self.key.unlink()
        self.assertTrue(client.validate_profile(self.profile_file, require_key=False)['enabled'])
        with self.assertRaises(client.ClientError):
            client.validate_profile(self.profile_file, require_key=True)

    def test_pin_must_match_local_trust_certificate(self):
        self.profile['server_cert_sha256'] = '0' * 64
        with self.assertRaises(client.ClientError) as caught:
            client.validate_profile(self.profile)
        self.assertNotIn(str(self.directory), str(caught.exception))

    def test_connection_checks_hostname_chain_and_pin(self):
        events = []
        class Wrapped:
            def getpeercert(inner, binary_form=False):
                events.append('cert')
                return self.der
            def close(inner):
                events.append('wrapped-close')
        class Raw:
            def close(inner):
                events.append('raw-close')
        class Context:
            def wrap_socket(inner, raw, server_hostname):
                self.assertEqual(server_hostname, 'localhost')
                events.append('tls')
                return Wrapped()
        with patch.object(client.socket, 'create_connection', return_value=Raw()):
            good = client._PinnedConnection(1234, Context(), self.pin)
            good.connect()
            bad = client._PinnedConnection(1234, Context(), '0' * 64)
            with self.assertRaises(client.ClientError):
                bad.connect()
        self.assertEqual(events[:2], ['tls', 'cert'])
        self.assertIn('wrapped-close', events)
        context = client._trust_context(self.profile)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_bootstrap_allowlist_exactly_matches_transport_routes(self):
        expected = {
            ('GET', '/system/version/'), ('GET', '/system/advanced/'), ('PUT', '/system/advanced/'),
            ('GET', '/certificateauthority/'), ('POST', '/certificateauthority/'),
            ('GET', '/certificate/'), ('POST', '/certificate/'), ('GET', '/core/get_jobs/')}
        self.assertEqual({(e['method'], e['resource']) for e in client.REST_ALLOWLIST}, expected)
        sent = []
        class Response:
            status = 200
            def read(inner, limit): return b'{}'
        class Connection:
            def __init__(inner, *args): pass
            def connect(inner): pass
            def request(inner, method, path, **kwargs): sent.append((method, path))
            def getresponse(inner): return Response()
            def close(inner): pass
        transport = client.RestTransport(self.profile, 1234)
        with patch.object(client, '_PinnedConnection', Connection):
            for method, resource in expected:
                path = resource.rstrip('/')
                if path == '/core/get_jobs':
                    path += '?id=99'
                transport(method, path)
        self.assertEqual({(method, path.split('?')[0].removeprefix('/api/v2.0')) for method, path in sent}, expected)
        self.assertIn(('GET', '/api/v2.0/core/get_jobs/?id=99'), sent)

    def test_key_is_read_and_sent_only_after_verified_connect(self):
        events = []
        class Response:
            status = 200
            def read(inner, limit):
                return b'"version"'
        class Connection:
            def __init__(inner, *args):
                pass
            def connect(inner):
                events.append('verified')
            def request(inner, method, path, **kwargs):
                self.assertEqual(path, '/api/v2.0/system/version/')
                self.assertEqual(kwargs['headers']['Authorization'], 'Bearer EXAMPLE-SECRET-KEY')
                events.append('send')
            def getresponse(inner):
                return Response()
            def close(inner):
                pass
        def key(path):
            events.append('key-read')
            return 'EXAMPLE-SECRET-KEY'
        transport = client.RestTransport(self.profile, 1234)
        with patch.object(client, '_PinnedConnection', Connection), patch.object(client, '_read_key', key):
            self.assertEqual(transport('GET', '/system/version'), 'version')
        self.assertEqual(events, ['verified', 'key-read', 'send'])

    def test_failed_tls_never_reads_or_sends_credentials(self):
        class Connection:
            def __init__(inner, *args):
                pass
            def connect(inner):
                raise ValueError('SECRET remote detail')
            def close(inner):
                pass
        transport = client.RestTransport(self.profile, 1234)
        with patch.object(client, '_PinnedConnection', Connection), patch.object(client, '_read_key', side_effect=AssertionError('read too early')):
            with self.assertRaises(client.ClientError) as caught:
                transport('GET', '/system/version')
        self.assertNotIn('SECRET', str(caught.exception))

    def test_redirect_and_non_allowlisted_requests_are_rejected(self):
        transport = client.RestTransport(self.profile, 1234)
        with patch.object(client, '_PinnedConnection', side_effect=AssertionError('must reject first')):
            for method, path in [('DELETE', '/certificate'), ('GET', 'https://evil/system/version'), ('GET', '/system/version?x=1')]:
                with self.assertRaises(client.ClientError):
                    transport(method, path)
        class Response:
            status = 302
        class Connection:
            def __init__(inner, *args): pass
            def connect(inner): pass
            def request(inner, *args, **kwargs): pass
            def getresponse(inner): return Response()
            def close(inner): pass
        with patch.object(client, '_PinnedConnection', Connection):
            with self.assertRaises(client.ClientError):
                transport('GET', '/system/version')

    def test_pki_is_persistent_correctly_scoped_and_never_rotated(self):
        directory = self.directory / 'pki'
        files = client.pki.ensure_materials(directory, '192.168.1.10')
        before = {name: Path(path).read_bytes() for name, path in files.items()}
        self.assertEqual(files, client.pki.ensure_materials(directory, '192.168.1.10'))
        self.assertEqual(before, {name: Path(path).read_bytes() for name, path in files.items()})
        server = x509.load_pem_x509_certificate(before['server.pem'])
        self.assertEqual(str(server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value[0].value), '192.168.1.10')
        with self.assertRaises(client.pki.PrivateInputError):
            client.pki.ensure_materials(directory, '192.168.1.11')
        (directory / 'client.pem').unlink()
        with self.assertRaises(client.pki.PrivateInputError):
            client.pki.ensure_materials(directory, '192.168.1.10')
        self.assertEqual((directory / 'ca.pem').read_bytes(), before['ca.pem'])

    def test_before_state_saved_before_mutations(self):
        # Mock PKI loading; this test verifies integration ordering, not keygen.
        scope = dict(syslogserver='', syslog_transport='UDP', syslog_tls_certificate=None,
                     syslog_tls_certificate_authority=None, sysloglevel='F_ERR')
        calls = []
        def reconcile(request, profile, materials):
            request('GET', '/system/advanced')
            self.assertEqual(len(list(self.directory.glob('before-*.json'))), 1)
            request('PUT', '/system/advanced', scope)
            return dict(changed=True, imported=[])
        def transport(method, path, body=None):
            calls.append(method)
            return dict(scope, secret='NEVER SAVE')
        files = {'ca.pem': str(self.trust), 'client.pem': str(self.trust), 'client-key.pem': str(self.key)}
        with patch.object(client.pki, 'ensure_materials', return_value=files), patch.object(client, 'tunnel', return_value=contextlib.nullcontext(1234)), patch.object(client, 'RestTransport', return_value=transport), patch.object(client.api, 'reconcile', reconcile):
            result = client.configure(self.profile_file)
        self.assertTrue(result['before_state_saved'])
        backup = next(self.directory.glob('before-*.json'))
        self.assertEqual(json.loads(backup.read_text()), scope)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(calls, ['GET', 'PUT'])


if __name__ == '__main__':
    unittest.main()
