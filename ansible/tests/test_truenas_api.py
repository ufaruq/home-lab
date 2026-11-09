"""Offline native TrueNAS reconciliation tests: no appliance or network access."""
import copy
import datetime as dt
import importlib.util
from pathlib import Path
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

SPEC = importlib.util.spec_from_file_location('truenas_api', Path(__file__).resolve().parents[2] / 'monitoring/truenas/api.py')
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)


def material():
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'offline fixture')])
    def builder(public, ca):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(public).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    ca = builder(ca_key.public_key(), True).sign(ca_key, hashes.SHA256())
    client = builder(key.public_key(), False).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False).sign(ca_key, hashes.SHA256())
    return dict(ca_certificate=ca.public_bytes(serialization.Encoding.PEM).decode(),
                client_certificate=client.public_bytes(serialization.Encoding.PEM).decode(),
                client_privatekey=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()).decode())


class Appliance:
    def __init__(self):
        self.advanced = dict(syslogserver='', syslog_transport='UDP', syslog_tls_certificate=None,
                             syslog_tls_certificate_authority=None, sysloglevel='F_ERR',
                             motd='keep', anonstats_token='NEVER OUTPUT', syslog_audit=True)
        self.cas, self.certs, self.calls = [], [], []
        self.version = api.VERSION
        self.bad_readback = False
        self.fail_rollback = False
        self.puts = 0

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == '/system/version':
            return self.version
        if path == '/system/advanced':
            if method == 'GET':
                row = copy.deepcopy(self.advanced)
                if self.bad_readback and self.puts == 1:
                    row['sysloglevel'] = 'F_DEBUG'
                return row
            self.puts += 1
            if self.fail_rollback and self.puts == 2:
                raise RuntimeError('SECRET transport detail')
            self.advanced.update(body)
            return copy.deepcopy(self.advanced)
        if path.startswith('/core/get_jobs'):
            return [{'id': 99, 'state': 'SUCCESS', 'result': 'SECRET'}]
        rows = self.cas if path == '/certificateauthority' else self.certs
        if method == 'GET':
            return copy.deepcopy(rows)
        rows.append(dict(body, id=len(rows) + 1))
        return 99 if path == '/certificate' else copy.deepcopy(rows[-1])


class NativeApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.materials = material()

    def setUp(self):
        self.device = Appliance()
        self.config = dict(enabled=True, expected_version=api.VERSION,
                           syslogserver='192.168.50.7:6514', sysloglevel='F_INFO')

    def reconcile(self):
        return api.reconcile(self.device, self.config, self.materials)

    def test_missing_or_nonboolean_gate_never_calls_api(self):
        for enabled in (None, False, 'true', 1):
            self.config['enabled'] = enabled
            with self.assertRaises(api.ReconcileError):
                self.reconcile()
        self.assertEqual(self.device.calls, [])

    def test_wrong_declared_or_live_version_prevents_writes(self):
        self.config['expected_version'] = '25.10'
        with self.assertRaises(api.ReconcileError):
            self.reconcile()
        self.assertEqual(self.device.calls, [])
        self.config['expected_version'] = api.VERSION
        self.device.version = 'TrueNAS-SCALE-24.04.2.4'
        with self.assertRaises(api.ReconcileError):
            self.reconcile()
        self.assertEqual([c[0] for c in self.device.calls], ['GET'])

    def test_invalid_destination_and_level_prevent_calls(self):
        for server in ('8.8.8.8:6514', '127.0.0.1:6514', '192.168.1.1:514', 'host:6514', '192.168.1.1:6514,192.168.1.2:6514'):
            self.config['syslogserver'] = server
            with self.assertRaises(api.ReconcileError):
                self.reconcile()
        self.assertEqual(self.device.calls, [])

    def test_updates_only_owned_fields_and_second_convergence_is_noop(self):
        before = copy.deepcopy(self.device.advanced)
        result = self.reconcile()
        self.assertTrue(result['changed'])
        self.assertEqual(set(result['before']), set(api.OWNED_FIELDS))
        self.assertNotIn('anonstats_token', repr(result))
        writes = [c for c in self.device.calls if c[0] == 'PUT']
        self.assertEqual(set(writes[0][2]), set(api.OWNED_FIELDS))
        for key in set(before) - set(api.OWNED_FIELDS):
            self.assertEqual(before[key], self.device.advanced[key])
        self.device.calls.clear()
        self.assertFalse(self.reconcile()['changed'])
        self.assertTrue(all(call[0] == 'GET' for call in self.device.calls))

    def test_existing_unrelated_destination_requires_exact_review(self):
        self.device.advanced['syslogserver'] = '192.168.50.4:514'
        for review in (None, True, '192.168.50.3:514'):
            self.config['reviewed_previous_syslogserver'] = review
            with self.assertRaises(api.ReconcileError):
                self.reconcile()
        self.assertTrue(all(call[0] == 'GET' for call in self.device.calls))
        self.config['reviewed_previous_syslogserver'] = '192.168.50.4:514'
        self.assertTrue(self.reconcile()['changed'])

    def test_name_conflict_preflight_prevents_all_writes(self):
        self.device.certs.append(dict(id=8, name=api.CLIENT_NAME,
                                      certificate=self.materials['ca_certificate'], privatekey='SECRET'))
        with self.assertRaises(api.ReconcileError) as caught:
            self.reconcile()
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertTrue(all(call[0] == 'GET' for call in self.device.calls))

    def test_wrong_object_type_prevents_writes(self):
        self.device.cas.append(dict(id=8, name=api.CLIENT_NAME))
        with self.assertRaises(api.ReconcileError):
            self.reconcile()
        self.assertTrue(all(call[0] == 'GET' for call in self.device.calls))

    def test_invalid_material_prevents_calls(self):
        invalid = dict(self.materials, client_privatekey='SECRET')
        with self.assertRaises(api.ReconcileError) as caught:
            api.reconcile(self.device, self.config, invalid)
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertEqual(self.device.calls, [])

    def test_failed_readback_restores_owned_before_scope(self):
        before = copy.deepcopy(self.device.advanced)
        self.device.bad_readback = True
        with self.assertRaises(api.ReconcileError) as caught:
            self.reconcile()
        self.assertTrue(caught.exception.rollback_verified)
        self.assertEqual(before, self.device.advanced)
        self.assertEqual(len(self.device.cas), 1)  # Additive objects retained, never deleted.
        self.assertEqual(len(self.device.certs), 1)
        self.assertFalse(any(call[0] == 'DELETE' for call in self.device.calls))

    def test_failed_rollback_is_reported_without_transport_secrets(self):
        self.device.bad_readback = self.device.fail_rollback = True
        with self.assertRaises(api.ReconcileError) as caught:
            self.reconcile()
        self.assertFalse(caught.exception.rollback_verified)
        self.assertIn('could not be verified', str(caught.exception))
        self.assertNotIn('SECRET', str(caught.exception))

    def test_failed_import_job_never_updates_syslog(self):
        def failed_job(method, path, body=None):
            if path.startswith('/core/get_jobs'):
                return [{'id': 99, 'state': 'FAILED', 'error': 'SECRET'}]
            return self.device(method, path, body)
        with self.assertRaises(api.ReconcileError) as caught:
            api.reconcile(failed_job, self.config, self.materials)
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertEqual(self.device.puts, 0)

    def test_concurrent_settings_edit_is_preserved(self):
        reads = 0
        def concurrent(method, path, body=None):
            nonlocal reads
            if method == 'GET' and path == '/system/advanced':
                reads += 1
                if reads == 2:
                    self.device.advanced['sysloglevel'] = 'F_WARNING'
            return self.device(method, path, body)
        with self.assertRaisesRegex(api.ReconcileError, 'concurrently'):
            api.reconcile(concurrent, self.config, self.materials)
        self.assertEqual(self.device.puts, 0)
        self.assertEqual(self.device.advanced['sysloglevel'], 'F_WARNING')

    def test_unrelated_certificates_are_preserved(self):
        unrelated_ca = dict(id=90, name='unrelated_ca', certificate='opaque')
        unrelated_cert = dict(id=91, name='web_ui_certificate', privatekey='SECRET')
        self.device.cas.append(unrelated_ca.copy())
        self.device.certs.append(unrelated_cert.copy())
        result = self.reconcile()
        self.assertTrue(result['changed'])
        self.assertEqual(self.device.cas[0], unrelated_ca)
        self.assertEqual(self.device.certs[0], unrelated_cert)
        self.assertNotIn('SECRET', repr(result))

    def test_transport_failure_redacts_details(self):
        def failing(*args):
            raise RuntimeError('password=SECRET')
        with self.assertRaises(api.ReconcileError) as caught:
            api.reconcile(failing, self.config, self.materials)
        self.assertEqual(str(caught.exception), 'TrueNAS API request failed')
        self.assertIsNone(caught.exception.__cause__)


if __name__ == '__main__':
    unittest.main()
