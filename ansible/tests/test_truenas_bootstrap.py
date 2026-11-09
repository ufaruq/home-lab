"""Offline bootstrap gates, encrypted key handling and recovery semantics."""
import ast
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import struct
import zlib
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SPEC = importlib.util.spec_from_file_location('truenas_bootstrap', Path(__file__).resolve().parents[2] / 'monitoring/truenas/bootstrap.py')
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)
UUID = '11111111-2222-3333-4444-555555555555'
SECRET = 'OFFLINE-API-KEY-NEVER-PRINT'


def identity():
    return {'uid': 0, 'uuid': UUID, 'version': bootstrap.console.VERSION}


def run_key_program(program, *, existing=None, observed=None):
    calls, replies = [], []
    def mid(method, *args):
        calls.append((method, args))
        if method == 'api_key.query':
            return [] if existing is None else existing
        if method == 'api_key.create':
            return {'key': SECRET, 'id': 77}
        raise AssertionError('Unexpected method')
    namespace = {'identity': identity() if observed is None else observed,
                 'mid': mid, 'reply': replies.append, 'base64': base64}
    exec(program[len(bootstrap.console.GUEST):], namespace)
    return calls, replies[0]


class KeyProgramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def test_guest_encrypts_secret_and_creates_only_exact_scoped_key(self):
        program = bootstrap.key_program(UUID, self.public)
        self.assertLessEqual(len(bootstrap.console.console_command(program)), 3900)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            calls, reply = run_key_program(program)
        self.assertEqual(stdout.getvalue(), '')
        self.assertNotIn(SECRET, program)
        self.assertNotIn(SECRET, json.dumps(reply))
        self.assertEqual(reply['key_id'], 77)
        decrypted = self.key.decrypt(base64.b64decode(reply['encrypted_key'], validate=True),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.assertEqual(decrypted.decode(), SECRET)
        self.assertEqual(calls, [
            ('api_key.query', ([['name', '=', bootstrap.KEY_NAME]],)),
            ('api_key.create', ({'name': bootstrap.KEY_NAME, 'allowlist': bootstrap.client.REST_ALLOWLIST},))])
        self.assertNotIn('api_key.delete', program)

    def test_decode_reply_bounds_compression_and_rejects_trailing_or_truncated_data(self):
        compressed = zlib.compress(json.dumps(identity()).encode(), 9)
        encoded = base64.b64encode(compressed).decode()
        self.assertEqual(bootstrap.console.decode_reply(encoded), identity())
        bad = [None, 'A' * 2801, 'not base64!',
               base64.b64encode(compressed[:-1]).decode(),
               base64.b64encode(compressed + b'extra').decode(),
               base64.b64encode(compressed + compressed).decode(),
               base64.b64encode(zlib.compress(json.dumps('x' * 9000).encode(), 9)).decode()]
        for value in bad:
            with self.subTest(case=type(value).__name__), self.assertRaises((ValueError, zlib.error)):
                bootstrap.console.decode_reply(value)

    def test_ciphertext_reply_fits_xenstore_quota_and_roundtrips_without_escapes(self):
        _, reply = run_key_program(bootstrap.key_program(UUID, self.public))
        program = bootstrap.console.GUEST.replace('XENSTORE_REPLY_PATH', '/local/domain/123/data/homelab-' + 'a' * 32)
        tree = ast.parse(program)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'reply')
        packets = []
        class Bus:
            def __enter__(inner): return inner
            def __exit__(inner, *args): pass
            def write(inner, packet): packets.append(packet)
            def read(inner, count):
                return struct.pack('<IIII', 11, 1, 0, 0) if count == 16 else b''
        namespace = dict(base64=base64, zlib=zlib, json=json, struct=struct, open=lambda *args, **kwargs: Bus())
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<offline-reply>', 'exec'), namespace)
        namespace['reply'](reply)
        packet = packets[0]
        kind, req, tx, size = struct.unpack('<IIII', packet[:16])
        self.assertEqual((kind, req, tx), (11, 1, 0))
        self.assertEqual(size, len(packet) - 16)
        self.assertLessEqual(size, 2048)
        path, encoded = packet[16:].split(b'\0', 1)
        self.assertNotIn(b'\\', encoded)
        self.assertNotIn(SECRET.encode(), encoded)
        self.assertEqual(json.loads(zlib.decompress(base64.b64decode(encoded, validate=True))), reply)

    def test_existing_named_key_is_never_rotated_or_deleted(self):
        program = bootstrap.key_program(UUID, self.public)
        with self.assertRaisesRegex(ValueError, 'Owned key exists'):
            run_key_program(program, existing=[{'id': 11}])

    def test_wrong_identity_blocks_key_creation(self):
        program = bootstrap.key_program(UUID, self.public)
        for changes in ({'uid': 1000}, {'uuid': 'ffffffff-2222-3333-4444-555555555555'}, {'version': 'TrueNAS-SCALE-25.10'}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'Identity changed'):
                run_key_program(program, observed=dict(identity(), **changes))


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        os.chmod(self.directory, 0o700)
        self.declaration_path = self.directory / 'declaration.json'
        self.profile_path = self.directory / 'profile.json'
        self.key_path = self.directory / 'api-key'
        self.cert_path = self.directory / 'server-trust.pem'
        self.pki_directory = self.directory / 'pki'
        self.declaration = dict(console_administration_enabled=True, expected_version=bootstrap.console.VERSION,
            expected_vm_uuid=UUID, ssh_alias='home-lab-host', address='192.168.1.9',
            syslogserver='192.168.1.10:6514', profile_file=str(self.profile_path),
            api_key_file=str(self.key_path), server_certificate_file=str(self.cert_path),
            pki_directory=str(self.pki_directory))
        self.save_declaration()
        self.profile = dict(self.declaration, enabled=True, server_cert_sha256='a' * 64)
        self.discovered = dict(identity(), certificate='OFFLINE-PUBLIC-CERTIFICATE', sha256='a' * 64)

    def save_declaration(self):
        self.declaration_path.write_text(json.dumps(self.declaration))
        os.chmod(self.declaration_path, 0o600)

    def patches(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        discover = stack.enter_context(patch.object(bootstrap.console, 'discover', return_value=self.discovered))
        execute = stack.enter_context(patch.object(bootstrap.console, 'execute', side_effect=lambda alias, vm, program: dict(run_key_program(program)[1], _console_reply_path='/local/domain/7/data/homelab-' + 'a' * 32)))
        stack.enter_context(patch.object(bootstrap.console, 'acknowledge'))
        stack.enter_context(patch.object(bootstrap.pki, 'ensure_materials', return_value={}))
        stack.enter_context(patch.object(bootstrap.pki, 'validate_existing', return_value={}))
        stack.enter_context(patch.object(bootstrap.client, 'validate_profile', return_value=self.profile))
        stack.enter_context(patch.object(bootstrap.client, 'tunnel', return_value=contextlib.nullcontext(1234)))
        stack.enter_context(patch.object(bootstrap.client, 'RestTransport', return_value=lambda method, path: bootstrap.console.VERSION))
        return discover, execute

    def test_explicit_boolean_version_vm_and_route_gates_precede_console(self):
        for field, values in [('console_administration_enabled', (False, 'true', 1, None)),
                              ('expected_version', ('25.10', None)),
                              ('expected_vm_uuid', ('', UUID.replace('1', 'A', 1))),
                              ('ssh_alias', ('other-host', '-oProxyCommand=anything'))]:
            for value in values:
                declaration = dict(self.declaration, **{field: value})
                self.declaration_path.write_text(json.dumps(declaration))
                with self.subTest(field=field, value=value), patch.object(bootstrap.console, 'discover') as discover:
                    with self.assertRaises(ValueError):
                        bootstrap.bootstrap(self.declaration_path)
                    discover.assert_not_called()
        self.assertFalse(self.key_path.exists())

    def test_malformed_destination_and_unsafe_output_parents_prevent_console(self):
        variants = [dict(address='8.8.8.8'), dict(address='127.0.0.1'),
                    dict(syslogserver='192.168.1.10:514'), dict(syslogserver='8.8.8.8:6514'),
                    dict(syslogserver='host.example:6514'), dict(syslogserver='192.168.1.9:6514')]
        unsafe = self.directory / 'unsafe'
        unsafe.mkdir(mode=0o755)
        variants.extend([{field: str(unsafe / 'output')} for field in
                         ('profile_file', 'api_key_file', 'server_certificate_file')])
        for changes in variants:
            self.declaration_path.write_text(json.dumps(dict(self.declaration, **changes)))
            with self.subTest(changes=changes), patch.object(bootstrap.console, 'discover') as discover, patch.object(bootstrap.console, 'execute') as execute:
                with self.assertRaises(ValueError):
                    bootstrap.bootstrap(self.declaration_path)
                discover.assert_not_called(); execute.assert_not_called()
        self.assertFalse(self.key_path.exists())

    def test_colliding_output_and_recovery_paths_prevent_console(self):
        collisions = [dict(profile_file=str(self.key_path)), dict(server_certificate_file=str(self.key_path)),
                      dict(profile_file=str(self.cert_path))]
        collisions.extend([{field: str(self.directory / name)}
                           for field in ('profile_file', 'server_certificate_file')
                           for name in ('bootstrap-pending.json', 'bootstrap-recovery-key.pem', 'bootstrap-encrypted-reply.json')])
        # Naming the key itself after any reserved artifact is also refused.
        collisions.extend([dict(api_key_file=str(self.directory / name))
                           for name in ('bootstrap-pending.json', 'bootstrap-recovery-key.pem', 'bootstrap-encrypted-reply.json')])
        for changes in collisions:
            self.declaration_path.write_text(json.dumps(dict(self.declaration, **changes)))
            with self.subTest(changes=changes), patch.object(bootstrap.console, 'discover') as discover, patch.object(bootstrap.console, 'execute') as execute:
                with self.assertRaisesRegex(ValueError, 'distinct'):
                    bootstrap.bootstrap(self.declaration_path)
                discover.assert_not_called(); execute.assert_not_called()
        self.assertFalse(self.key_path.exists())

    def test_invalid_pki_prevents_console_and_key_creation(self):
        with patch.object(bootstrap.pki, 'ensure_materials', side_effect=ValueError('Invalid existing PKI')), patch.object(bootstrap.console, 'discover') as discover, patch.object(bootstrap.console, 'execute') as execute:
            with self.assertRaises(ValueError):
                bootstrap.bootstrap(self.declaration_path)
            discover.assert_not_called(); execute.assert_not_called()
        self.assertFalse((self.directory / 'bootstrap-recovery-key.pem').exists())

    def test_acknowledgement_follows_fsynced_ciphertext_persistence(self):
        self.patches()
        original_write = bootstrap.pki.write_new
        events = []
        def write(path, content):
            original_write(path, content)
            events.append(('saved', Path(path).name))
        def acknowledge(alias, vm, path):
            self.assertEqual((alias, vm), ('home-lab-host', UUID))
            artifact = self.directory / 'bootstrap-encrypted-reply.json'
            self.assertTrue(artifact.exists())
            self.assertEqual(json.loads(artifact.read_text())['_console_reply_path'], path)
            self.assertIn(('saved', artifact.name), events)
            events.append(('acknowledged', path))
        with patch.object(bootstrap.pki, 'write_new', side_effect=write), patch.object(bootstrap.pki.os, 'fsync', wraps=os.fsync) as fsync, patch.object(bootstrap.console, 'acknowledge', side_effect=acknowledge) as ack:
            bootstrap.bootstrap(self.declaration_path)
        ack.assert_called_once()
        # Every saved artifact flushes both its file and containing directory.
        self.assertGreaterEqual(fsync.call_count, 2 * sum(event[0] == 'saved' for event in events))
        self.assertLess(events.index(('saved', 'bootstrap-encrypted-reply.json')),
                        next(i for i, event in enumerate(events) if event[0] == 'acknowledged'))

    def test_failed_ciphertext_persistence_never_acknowledges_guest_reply(self):
        self.patches()
        original_write = bootstrap.pki.write_new
        def write(path, content):
            if Path(path).name == 'bootstrap-encrypted-reply.json':
                raise ValueError('Disk full')
            original_write(path, content)
        with patch.object(bootstrap.pki, 'write_new', side_effect=write), patch.object(bootstrap.console, 'acknowledge') as acknowledge:
            with self.assertRaisesRegex(ValueError, 'Disk full'):
                bootstrap.bootstrap(self.declaration_path)
            acknowledge.assert_not_called()
        self.assertFalse(self.key_path.exists())
        self.assertTrue((self.directory / 'bootstrap-recovery-key.pem').exists())

    def test_console_retains_reply_and_returns_recovery_path(self):
        path = '/local/domain/7/data/homelab-' + 'a' * 32
        data = base64.b64encode(zlib.compress(json.dumps(identity()).encode(), 9)).decode()
        result = type('Result', (), {'returncode': 0, 'stdout': json.dumps(dict(data=data, path=path)).encode()})()
        with patch.object(bootstrap.console.subprocess, 'run', return_value=result) as run:
            reply = bootstrap.console.execute('home-lab-host', UUID, 'print("offline public program")')
        self.assertEqual(reply['_console_reply_path'], path)
        self.assertEqual(reply['uuid'], UUID)
        remote_source = run.call_args.kwargs['input'].decode()
        self.assertNotIn("['xenstore-rm'", remote_source)

    def test_encrypting_key_and_pending_are_persisted_before_guest_creation(self):
        discover, execute = self.patches()
        original = execute.side_effect
        def inspect(alias, vm, program):
            for filename in ('bootstrap-recovery-key.pem', 'bootstrap-pending.json'):
                artifact = self.directory / filename
                self.assertTrue(artifact.exists())
                self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
            self.assertFalse(self.key_path.exists())
            return original(alias, vm, program)
        execute.side_effect = inspect
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = bootstrap.bootstrap(self.declaration_path)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(result, {'changed': True, 'credential_verified': True})
        self.assertEqual(self.key_path.read_text().strip(), SECRET)
        ciphertext = self.directory / 'bootstrap-encrypted-reply.json'
        self.assertNotIn(SECRET, ciphertext.read_text())
        self.assertNotIn(SECRET, self.profile_path.read_text())
        self.assertNotIn('BEGIN PRIVATE KEY', self.profile_path.read_text())
        for path in (self.key_path, self.profile_path, self.cert_path, ciphertext):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        discover.assert_called_once()
        execute.assert_called_once()

    def test_completed_bootstrap_verifies_existing_credential_without_console_or_rotation(self):
        discover, execute = self.patches()
        bootstrap.bootstrap(self.declaration_path)
        saved = self.key_path.read_bytes()
        discover.reset_mock(); execute.reset_mock()
        result = bootstrap.bootstrap(self.declaration_path)
        self.assertEqual(result, {'changed': False, 'credential_verified': True})
        self.assertEqual(self.key_path.read_bytes(), saved)
        discover.assert_not_called(); execute.assert_not_called()

    def test_interrupted_bootstrap_retains_private_recovery_key_and_blocks_blind_retry(self):
        discover, execute = self.patches()
        execute.side_effect = ValueError('Channel interrupted')
        with self.assertRaises(ValueError):
            bootstrap.bootstrap(self.declaration_path)
        self.assertTrue((self.directory / 'bootstrap-recovery-key.pem').exists())
        self.assertTrue((self.directory / 'bootstrap-pending.json').exists())
        self.assertFalse(self.key_path.exists())
        execute.reset_mock(); discover.reset_mock()
        with self.assertRaisesRegex(ValueError, 'Partial bootstrap'):
            bootstrap.bootstrap(self.declaration_path)
        discover.assert_not_called(); execute.assert_not_called()

    def test_decryption_failure_preserves_ciphertext_for_manual_recovery(self):
        discover, execute = self.patches()
        execute.side_effect = lambda *args: dict(identity(), encrypted_key='AA==', key_id=77)
        with self.assertRaises(ValueError):
            bootstrap.bootstrap(self.declaration_path)
        self.assertTrue((self.directory / 'bootstrap-encrypted-reply.json').exists())
        self.assertFalse(self.key_path.exists())
        self.assertFalse(self.profile_path.exists())

    def test_existing_profile_identity_mismatch_never_rewrites_profile_or_key(self):
        discover, execute = self.patches()
        self.profile_path.write_text('PRIVATE-PROFILE')
        os.chmod(self.profile_path, 0o600)
        self.profile['address'] = '192.168.1.99'
        with self.assertRaisesRegex(ValueError, 'another VM'):
            bootstrap.bootstrap(self.declaration_path)
        self.assertEqual(self.profile_path.read_text(), 'PRIVATE-PROFILE')
        discover.assert_not_called(); execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
