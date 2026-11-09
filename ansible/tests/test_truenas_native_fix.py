"""Offline exact-release vendor repair gates, transactions and rollback tests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('truenas_native_fix', Path(__file__).resolve().parents[2] / 'monitoring/truenas/native_fix.py')
fix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fix)
UUID = '11111111-2222-3333-4444-555555555555'
SERVER = '192.168.1.10:6514'
ORIGINAL = b'<%\nlogger = middleware.logger\n%>\nfixture public template \"%x.0\" % certificate_authority[\"subject_name_hash\"]\n'
OS_ONLY = ORIGINAL.replace(b'<%\n', b'<%\nimport os\n', 1)
PATCHED = OS_ONLY.replace(b'"%x.0"', b'"%08x.0"', 1)


class GuestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        os.chmod(self.root, 0o700)
        self.template = self.root / 'vendor.mako'
        self.template.write_bytes(ORIGINAL)
        os.chmod(self.template, 0o644)
        self.rendered = self.root / 'syslog-ng.conf'
        self.rendered.write_text('syslog("192.168.1.10" port(6514) transport("tls")); destination(loghost);')
        self.ca_directory = self.root / 'ca-directory'
        self.ca_directory.mkdir()
        self.ca_certificate = self.ca_directory / 'owned-ca.crt'
        self.ca_certificate.write_text('PUBLIC FIXTURE CA')
        self.ca_link = self.ca_directory / '0286b6bc.0'
        self.ca_link.symlink_to(self.ca_certificate)
        self.calls = []
        self.results = []

    def run_guest(self, *, uid=0, version=None, fail_generate=False, server=SERVER, transport='TLS', fail_replace=False, remount_enabled=True, fail_restore=False, bad_native_guid=False, baseline_rw=False):
        owner_os = os
        mounted_rw = baseline_rw
        metadata = self.root / 'native-root.json'
        metadata.write_text(json.dumps([{'ds': 'fixture-boot/ROOT/24.04.2.5/usr', 'guid': '9999000011112222333' if not bad_native_guid else 'wrong', 'fhs_entry': {'name': 'usr', 'options': ['RO']}}]))
        class GuestOS:
            def __getattr__(inner, name):
                return getattr(owner_os, name)
            def lstat(inner, path):
                info = owner_os.lstat(path)
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=info.st_gid)
            def fchown(inner, *args): pass
        class Commands:
            DEVNULL = -3
            def check_output(inner, args, **kwargs):
                self.calls.append(tuple(args))
                if args[0] == 'findmnt':
                    return json.dumps({'filesystems': [dict(target='/usr',source='fixture-boot/ROOT/24.04.2.5/usr',fstype='zfs',options=('rw' if mounted_rw else 'ro')+',relatime,xattr,noacl,casesensitive')]}).encode()
                if args[0] == 'zfs':
                    return ('readonly\t'+('off\ttemporary' if mounted_rw else 'on\tlocal')+'\nguid\t9999000011112222333\t-\nmountpoint\t/usr\tlocal\ncanmount\tnoauto\tlocal\n').encode()
                return b'active\n'
            def check_call(inner, args, **kwargs):
                nonlocal mounted_rw
                self.calls.append(tuple(args))
                if args[0] == 'mount':
                    if args[2] == 'remount,rw':
                        receipt = self.root / 'root/.config/homelab-truenas/usr-remount-before.json'
                        self.assertTrue(receipt.exists(), 'protection before-state must precede remount')
                    if args[2] == 'remount,ro' and fail_restore:
                        raise OSError(16, 'private restoration detail')
                    mounted_rw = args[2] == 'remount,rw'
                return 0
        failed = False
        def mid(method, *args):
            nonlocal failed
            self.calls.append((method, *args))
            if method == 'system.advanced.config':
                return dict(syslogserver=server, syslog_transport=transport, syslog_tls_certificate_authority=7)
            if method == 'certificateauthority.query':
                return dict(subject_name_hash=42383036, revoked=False, certificate_path=str(self.ca_certificate))
            if fail_generate and method == 'etc.generate' and not failed:
                failed = True
                raise ValueError('fixture native render failure')
            return True
        with patch.object(fix, 'ORIGINAL_SHA256', hashlib.sha256(ORIGINAL).hexdigest()), patch.object(fix, 'OS_ONLY_SHA256', hashlib.sha256(OS_ONLY).hexdigest()), patch.object(fix, 'PATCHED_SHA256', hashlib.sha256(PATCHED).hexdigest()), patch.object(fix, 'TEMPLATE_PATH', str(self.template)):
            program = fix.program(UUID, SERVER, remount_enabled)[len(fix.console.GUEST):]
        program = program.replace("'/root'", repr(str(self.root / 'root'))).replace("'/root/.config'", repr(str(self.root / 'root/.config')))
        program = program.replace("'/root/.config/homelab-truenas'", repr(str(self.root / 'root/.config/homelab-truenas')))
        program = program.replace("'/etc/syslog-ng/syslog-ng.conf'", repr(str(self.rendered)))
        program = program.replace("'/conf/truenas_root_ds.json'", repr(str(metadata)))
        program = program.replace("'/etc/certificates/CA/'", repr(str(self.ca_directory) + '/'))
        module = types.ModuleType('mako.template')
        module.Template = lambda **kwargs: self.calls.append(('mako-compile', kwargs['text']))
        namespace = dict(os=GuestOS(), hashlib=hashlib, json=json, subprocess=Commands(), mid=mid,
            identity=dict(uid=uid, uuid=UUID, version=version or fix.console.VERSION), reply=self.results.append)
        with patch.dict(sys.modules, {'mako': types.ModuleType('mako'), 'mako.template': module}):
            if fail_replace:
                with patch('tempfile.mkstemp', side_effect=OSError(30, 'PRIVATE PATH must not appear')):
                    exec(program, namespace)
            else:
                exec(program, namespace)
        return self.results[-1]

    def test_exact_public_digest_pins_and_console_command_bound(self):
        self.assertEqual(fix.ORIGINAL_SHA256, '042d13cb429f3ca9e50b65860f21e74ae13985b2d8f7ce1f840d815db92fba88')
        self.assertEqual(fix.OS_ONLY_SHA256, '9622877fd7889d7d0141afe0f6c051dc1d0228e8392bd3203cedbaf310dfe053')
        self.assertEqual(fix.PATCHED_SHA256, '54590db0c9bbc2e90a597acdf65071e588e0b3b40405e11bd9a03211bdd2f4c1')
        program = fix.program(UUID, SERVER, True)
        command = fix.console.console_command(program)
        self.assertLess(max(map(len, command.splitlines())), 3900)
        self.assertLessEqual(len(command), 16000)
        compile(program, '<guest>', 'exec')
        with self.assertRaises(ValueError):
            fix.patch_template(b'unknown release')

    def test_only_known_import_patch_is_atomic_preserving_mode_with_private_backup(self):
        result = self.run_guest()
        self.assertTrue(result['ok'])
        self.assertTrue(result['changed'])
        self.assertEqual(self.template.read_bytes(), PATCHED)
        self.assertEqual(stat.S_IMODE(self.template.stat().st_mode), 0o644)
        directory = self.root / 'root/.config/homelab-truenas'
        backup = directory / 'syslog-ng.conf.mako.original'
        receipt = directory / 'syslog-ng-template-repair-v2.json'
        self.assertEqual(backup.read_bytes(), ORIGINAL)
        for path in (backup, receipt):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertFalse(list(self.root.glob('.homelab-syslog-*')))
        methods = [c[0] for c in self.calls]
        self.assertLess(methods.index('mako-compile'), methods.index('etc.generate'))
        self.assertLess(methods.index('etc.generate'), methods.index('service.restart'))
        self.assertEqual(methods.count('service.restart'), 1)

    def seed_v1(self):
        self.template.write_bytes(OS_ONLY)
        directory = self.root / 'root/.config/homelab-truenas'
        directory.mkdir(parents=True, mode=0o700)
        for path, data in [(directory / 'syslog-ng.conf.mako.original', ORIGINAL),
                           (directory / 'syslog-ng-template-repair.json', b'PRIVATE V1 RECEIPT')]:
            path.write_bytes(data); os.chmod(path, 0o600)
        return directory

    def test_os_only_upgrade_preserves_history_and_saves_actual_before(self):
        directory = self.seed_v1()
        result = self.run_guest()
        self.assertTrue(result['ok'])
        self.assertEqual(self.template.read_bytes(), PATCHED)
        self.assertEqual((directory / 'syslog-ng.conf.mako.original').read_bytes(), ORIGINAL)
        self.assertEqual((directory / 'syslog-ng-template-repair.json').read_bytes(), b'PRIVATE V1 RECEIPT')
        digest = hashlib.sha256(OS_ONLY).hexdigest()
        self.assertEqual((directory / ('syslog-ng.conf.mako.before-v2-' + digest)).read_bytes(), OS_ONLY)
        self.assertEqual(json.loads((directory / 'syslog-ng-template-repair-v2.json').read_text())['before_sha256'], digest)
        self.assertTrue(result['usr_readonly_verified'])

    def test_upgrade_failure_rolls_back_actual_os_only_before_not_vendor_original(self):
        directory = self.seed_v1()
        result = self.run_guest(fail_generate=True)
        self.assertFalse(result['ok'])
        self.assertTrue(result['rollback_verified'])
        self.assertTrue(result['usr_readonly_verified'])
        self.assertEqual(self.template.read_bytes(), OS_ONLY)
        self.assertEqual((directory / 'syslog-ng.conf.mako.original').read_bytes(), ORIGINAL)
        self.assertEqual((directory / 'syslog-ng-template-repair.json').read_bytes(), b'PRIVATE V1 RECEIPT')

    def test_selected_ca_link_requires_eight_digits_and_exact_certificate_target(self):
        self.ca_link.unlink()
        (self.ca_directory / '286b6bc.0').symlink_to(self.ca_certificate)
        result = self.run_guest()
        self.assertFalse(result['ok'])
        self.assertTrue(result['rollback_verified'])
        self.assertEqual(self.template.read_bytes(), ORIGINAL)
        other = self.ca_directory / 'unrelated.crt'
        other.write_text('UNRELATED CA')
        self.ca_link.symlink_to(other)
        result = self.run_guest()
        self.assertFalse(result['ok'])
        self.assertTrue(result['rollback_verified'])
        self.assertEqual(self.template.read_bytes(), ORIGINAL)

    def test_pure_patch_supports_original_os_only_and_combined_without_extra_changes(self):
        with patch.object(fix, 'ORIGINAL_SHA256', hashlib.sha256(ORIGINAL).hexdigest()), patch.object(fix, 'OS_ONLY_SHA256', hashlib.sha256(OS_ONLY).hexdigest()), patch.object(fix, 'PATCHED_SHA256', hashlib.sha256(PATCHED).hexdigest()):
            for before in (ORIGINAL, OS_ONLY, PATCHED):
                self.assertEqual(fix.patch_template(before), PATCHED)
        self.assertEqual(format(42383036, '08x') + '.0', '0286b6bc.0')

    def test_fresh_empty_destination_can_repair_before_native_client_configuration(self):
        self.rendered.write_text('local logging only')
        result = self.run_guest(server='', transport='UDP')
        self.assertTrue(result['ok'])
        self.assertTrue(result['changed'])
        self.assertFalse(result['remote_destination_verified'])
        self.assertEqual(self.template.read_bytes(), PATCHED)
        self.assertFalse(any(c[0] == 'system.advanced.update' for c in self.calls))
        self.calls.clear()
        second = self.run_guest(server='', transport='UDP')
        self.assertTrue(second['ok'])
        self.assertFalse(second['changed'])
        self.assertFalse(second['remote_destination_verified'])
        self.assertFalse(any(c[0] in ('etc.generate', 'service.restart') for c in self.calls))

    def test_unrelated_existing_destination_or_plaintext_policy_is_preserved(self):
        for server, transport in [('192.168.1.11:6514', 'TLS'), (SERVER, 'UDP')]:
            result = self.run_guest(server=server, transport=transport)
            self.assertFalse(result['ok'])
            self.assertFalse(result['changed'])
            self.assertEqual(self.template.read_bytes(), ORIGINAL)
        self.assertFalse((self.root / 'root').exists())

    def test_root_owned_readable_ancestors_are_allowed_but_backup_stays_private(self):
        parent = self.root / 'root/.config'
        parent.mkdir(parents=True, mode=0o755)
        os.chmod(parent.parent, 0o755)
        os.chmod(parent, 0o755)
        result = self.run_guest()
        self.assertTrue(result['ok'])
        self.assertEqual(stat.S_IMODE((parent / 'homelab-truenas').stat().st_mode), 0o700)

    def test_known_patch_is_idempotent_without_regeneration_or_restart(self):
        self.template.write_bytes(PATCHED)
        result = self.run_guest()
        self.assertTrue(result['ok'])
        self.assertFalse(result['changed'])
        self.assertFalse(any(c[0] in ('etc.generate', 'service.restart') for c in self.calls))

    def test_unknown_digest_and_wrong_identity_never_modify_template(self):
        for uid, version, content in [(1000, None, ORIGINAL), (0, 'TrueNAS-SCALE-25.10', ORIGINAL), (0, None, b'unrelated template')]:
            self.template.write_bytes(content)
            result = self.run_guest(uid=uid, version=version)
            self.assertFalse(result['ok'])
            self.assertFalse(result['changed'])
            self.assertEqual(self.template.read_bytes(), content)
        self.assertFalse((self.root / 'root').exists())

    def test_symlink_vendor_path_is_refused(self):
        target = self.root / 'unrelated'
        target.write_bytes(ORIGINAL)
        self.template.unlink(); self.template.symlink_to(target)
        result = self.run_guest()
        self.assertFalse(result['ok'])
        self.assertFalse(result['changed'])
        self.assertEqual(target.read_bytes(), ORIGINAL)

    def test_readonly_replace_failure_reports_errno_without_false_mutation_or_write_retry(self):
        result = self.run_guest(fail_replace=True)
        self.assertFalse(result['ok'])
        self.assertFalse(result['changed'])
        self.assertTrue(result['rollback_verified'])
        self.assertEqual(result['stage'], 'replace')
        self.assertEqual(result['failure_type'], 'OSError')
        self.assertEqual(result['failure_errno'], 30)
        self.assertNotIn('PRIVATE PATH', json.dumps(result))
        self.assertEqual(self.template.read_bytes(), ORIGINAL)
        self.assertFalse(any(c[0] in ('etc.generate', 'service.restart') for c in self.calls))

    def test_temporary_remount_requires_boolean_gate_and_binds_native_dataset_guid(self):
        for args in (dict(remount_enabled=False), dict(remount_enabled='true'), dict(bad_native_guid=True), dict(baseline_rw=True)):
            self.calls.clear()
            result = self.run_guest(**args)
            self.assertFalse(result['ok'])
            self.assertFalse(result['changed'])
            self.assertEqual(self.template.read_bytes(), ORIGINAL)
            self.assertFalse(any(c[0] == 'mount' for c in self.calls))

    def test_remount_is_temporary_receipted_and_readonly_restored(self):
        result = self.run_guest()
        self.assertTrue(result['ok'])
        self.assertTrue(result['usr_readonly_verified'])
        mounts = [c for c in self.calls if c[0] == 'mount']
        self.assertEqual(mounts, [('mount', '-o', 'remount,rw', '/usr'), ('mount', '-o', 'remount,ro', '/usr')])
        self.assertFalse(any(c[0] == 'zfs' and c[1] in ('set', 'inherit') for c in self.calls))
        receipt = self.root / 'root/.config/homelab-truenas/usr-remount-before.json'
        saved = json.loads(receipt.read_text())
        self.assertEqual(saved['properties']['readonly'], ['on', 'local'])
        self.assertEqual(saved['properties']['guid'][0], '9999000011112222333')
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
        self.calls.clear()
        second = self.run_guest()
        self.assertTrue(second['ok'])
        self.assertTrue(second['usr_readonly_verified'])
        self.assertFalse(any(c[0] == 'mount' for c in self.calls))

    def test_protection_restore_failure_never_reports_success(self):
        result = self.run_guest(fail_restore=True)
        self.assertFalse(result['ok'])
        self.assertTrue(result['protection_restore_failed'])
        self.assertFalse(result['usr_readonly_verified'])
        self.assertEqual(result['protection_failure_type'], 'OSError')
        self.assertNotIn('private restoration detail', json.dumps(result))
        self.assertEqual(self.calls[-1], ('mount', '-o', 'remount,ro', '/usr'))

    def test_generation_failure_restores_original_and_reports_verified_rollback(self):
        result = self.run_guest(fail_generate=True)
        self.assertFalse(result['ok'])
        self.assertTrue(result['changed'])
        self.assertTrue(result['rollback_verified'])
        self.assertEqual(self.template.read_bytes(), ORIGINAL)
        self.assertEqual(result['stage'], 'generate')
        self.assertTrue(result['usr_readonly_verified'])
        self.assertIn(('mount', '-o', 'remount,ro', '/usr'), self.calls)

    def test_missing_generated_tls_destination_rolls_back_before_restart(self):
        self.rendered.write_text('local logging only')
        result = self.run_guest()
        self.assertFalse(result['ok'])
        self.assertTrue(result['rollback_verified'])
        self.assertEqual(self.template.read_bytes(), ORIGINAL)
        self.assertEqual(sum(c[0] == 'service.restart' for c in self.calls), 1)  # rollback only


class DeclarationTests(unittest.TestCase):
    def test_explicit_boolean_and_exact_identity_gates_precede_console(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp).resolve(); os.chmod(directory, 0o700)
            declaration = directory / 'repair.json'
            base = dict(console_administration_enabled=True, native_syslog_template_fix_enabled=True,
                expected_version=fix.console.VERSION, ssh_alias='home-lab-host', expected_vm_uuid=UUID, syslogserver=SERVER)
            for changes in ({'console_administration_enabled': 'true'}, {'native_syslog_template_fix_enabled': 1},
                            {'expected_version': '25.10'}, {'expected_vm_uuid': ''}, {'ssh_alias': 'other'},
                            {'syslogserver': '8.8.8.8:6514'}, {'syslogserver': '192.168.1.10:514'}):
                declaration.write_text(json.dumps(dict(base, **changes))); os.chmod(declaration, 0o600)
                with patch.object(fix.console, 'execute') as execute:
                    with self.assertRaises(ValueError):fix.repair(declaration)
                    execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
