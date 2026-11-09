import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location('wazuh_logging', Path(__file__).parents[1] / 'wazuh_logging.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

class LoggingScopeTests(unittest.TestCase):
    def plan(self):
        return {'resource_changes': [{'mode': 'managed', 'address': 'terraform_data.logging',
            'type': 'terraform_data', 'provider_name': 'terraform.io/builtin/terraform',
            'change': {'actions': ['create'], 'after': {'input': {
                'manager': 'wazuh', 'agents': ['portainer'], 'phase': 'all', 'retention_days': 7}}}}]}

    def test_exact_local_plan(self):
        m.guard_plan(self.plan(), ['portainer'], 'all')

    def test_rejects_cloud_or_expanded_targets(self):
        for field, value in [('address', 'oci_core_instance.bad'), ('provider_name', 'registry.terraform.io/oracle/oci')]:
            p = self.plan(); p['resource_changes'][0][field] = value
            with self.assertRaises(ValueError): m.guard_plan(p, ['portainer'], 'all')
        p = self.plan(); p['resource_changes'][0]['change']['after']['input']['agents'].append('parrot_htb')
        with self.assertRaises(ValueError): m.guard_plan(p, ['portainer'], 'all')

    def test_destroy_and_failed_checks_rejected(self):
        p = self.plan(); p['resource_changes'][0]['change']['actions'] = ['delete']
        with self.assertRaises(ValueError): m.guard_plan(p, ['portainer'], 'all')
        p = self.plan(); p['checks'] = [{'status': 'fail'}]
        with self.assertRaises(ValueError): m.guard_plan(p, ['portainer'], 'all')

    def test_appliances_and_parrot_are_never_agent_targets(self):
        for alias in ['parrot_htb', 'truenas', 'datacenter1', 'wazuh', 'opnsense']:
            with self.assertRaises(ValueError): m.validate_agents([alias])

    def test_truenas_phase_requires_empty_agents_and_exact_local_input(self):
        p = self.plan()
        p['resource_changes'][0]['change']['after']['input'].update(agents=[], phase='truenas')
        m.guard_plan(p, [], 'truenas')
        with self.assertRaises(ValueError): m.guard_plan(p, ['portainer'], 'truenas')
        for phase in ['logging', 'tailnet', 'all']:
            m.validate_phase(phase, ['portainer'])

    def private_fixture(self, directory):
        private = directory/'private'; private.mkdir(mode=0o700)
        pki = private/'pki'; pki.mkdir(mode=0o700)
        for name in ['ca.pem', 'ca-key.pem', 'server.pem', 'server-key.pem', 'client.pem', 'client-key.pem', 'https.pem', 'api-key']:
            path = pki/name; path.write_text('synthetic '+name); path.chmod(0o600)
        profile = {'enabled': True, 'expected_version': 'TrueNAS-SCALE-24.04.2.5',
                   'expected_vm_uuid': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'ssh_alias': 'home-lab-host',
                   'syslogserver': '10.23.1.2:6514', 'address': '10.23.1.3',
                   'pki_directory': str(pki), 'server_certificate_file': str(pki/'https.pem'),
                   'api_key_file': str(pki/'api-key')}
        profile_path = private/'profile.json'; profile_path.write_text(json.dumps(profile)); profile_path.chmod(0o600)
        config = {'monitoring_truenas_receiver_address': '10.23.1.2',
                  'monitoring_truenas_source_address': '10.23.1.3',
                  'monitoring_truenas_ca_file': str(pki/'ca.pem'),
                  'monitoring_truenas_server_cert_file': str(pki/'server.pem'),
                  'monitoring_truenas_server_key_file': str(pki/'server-key.pem')}
        repo = directory/'repo'; (repo/'monitoring/truenas').mkdir(parents=True)
        (repo/'monitoring/truenas/client.py').write_text('from types import SimpleNamespace\npki=SimpleNamespace(validate_existing=lambda directory, address: None)\ndef validate_profile(path, require_key=False):\n assert require_key is True\n')
        return repo, profile_path, pki, config

    def test_private_receipt_covers_profile_and_every_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, profile, pki, config = self.private_fixture(Path(temporary))
            with mock.patch.object(m, 'ROOT', repo):
                env = {'WAZUH_TRUENAS_PROFILE': str(profile)}
                first = m.truenas_review(env, config)
                self.assertEqual(len(first['materials']), 8)
                for path in pki.iterdir():
                    original = path.read_text(); path.write_text(original+' changed')
                    self.assertNotEqual(first, m.truenas_review(env, config))
                    path.write_text(original)
                profile.write_text(profile.read_text()+'\n')
                self.assertNotEqual(first, m.truenas_review(env, config))
                self.assertNotIn('synthetic', json.dumps(first))

    def test_private_review_rejects_missing_public_or_mismatched_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, profile, pki, config = self.private_fixture(Path(temporary))
            with mock.patch.object(m, 'ROOT', repo):
                env = {'WAZUH_TRUENAS_PROFILE': str(profile)}
                for field, value in [('monitoring_truenas_receiver_address', '0.0.0.0'),
                                     ('monitoring_truenas_source_address', '10.23.1.4'),
                                     ('monitoring_truenas_server_key_file', str(pki/'client-key.pem')),
                                     ('monitoring_truenas_receiver_install_approved', 'true')]:
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        m.truenas_review(env, dict(config, **{field: value}))
                (pki/'client-key.pem').chmod(0o644)
                with self.assertRaises(ValueError): m.truenas_review(env, config)
                (pki/'client-key.pem').unlink()
                with self.assertRaises(FileNotFoundError): m.truenas_review(env, config)

    def test_truenas_deploy_orders_receiver_before_pinned_native_client(self):
        env = {'WAZUH_TRUENAS_PROFILE': '/private/profile.json', 'ANSIBLE_PLAYBOOK_BIN': '/pinned/ansible-playbook'}
        with mock.patch.object(m, 'inputs', return_value=(Path('/private/inventory'), Path('/private/vars'), {})), \
             mock.patch.object(m, 'truenas_review'), mock.patch.object(m, 'private_file', side_effect=Path), \
             mock.patch.object(m.subprocess, 'run') as run:
            m.deploy(env, 'truenas')
        first, second = [call.args[0] for call in run.call_args_list]
        self.assertEqual(first[0], '/pinned/ansible-playbook')
        self.assertEqual(first[-2:], ['--tags', 'truenas'])
        self.assertEqual(second, [m.sys.executable, str(m.ROOT/'monitoring/truenas/client.py'), 'configure', '--profile', '/private/profile.json'])

    def test_all_phase_does_not_implicitly_configure_appliance(self):
        with mock.patch.object(m, 'inputs', return_value=(Path('/private/inventory'), Path('/private/vars'), {})), \
             mock.patch.object(m, 'truenas_review') as review, mock.patch.object(m.subprocess, 'run') as run:
            m.deploy({}, 'all')
        review.assert_not_called()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][-2:], ['--tags', 'logging,tailnet'])

    def test_source_receipt_fingerprints_receiver_templates_and_native_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            template = repo/'ansible/roles/monitoring_wazuh_truenas/templates/receiver.service.j2'
            helper = repo/'monitoring/truenas/client.py'
            for path in [template, helper]:
                path.parent.mkdir(parents=True, exist_ok=True); path.write_text('before')
            with mock.patch.object(m, 'ROOT', repo):
                original = m.source_digest()
                for path in [template, helper]:
                    path.write_text('after')
                    self.assertNotEqual(original, m.source_digest())
                    path.write_text('before')

    def test_template_fix_flag_is_strict_and_true_only_in_truenas(self):
        name = 'monitoring_truenas_native_template_fix_enabled'
        for phase in m.PHASES:
            self.assertFalse(m.template_fix_enabled({}, phase))
            self.assertFalse(m.template_fix_enabled({name: False}, phase))
            for bad in ['true', 'false', 1, None]:
                with self.subTest(phase=phase, bad=bad), self.assertRaises(ValueError):
                    m.template_fix_enabled({name: bad}, phase)
            if phase == 'truenas': self.assertTrue(m.template_fix_enabled({name: True}, phase))
            else:
                with self.assertRaises(ValueError): m.template_fix_enabled({name: True}, phase)

    def test_guard_includes_native_repair_only_for_exact_approved_input(self):
        p = self.plan()
        expected = p['resource_changes'][0]['change']['after']['input']
        expected.update(agents=[], phase='truenas', native_template_fix=True)
        m.guard_plan(p, [], 'truenas', True)
        for enabled in [False, 'true', 1]:
            with self.assertRaises(ValueError): m.guard_plan(p, [], 'truenas', enabled)
        expected['native_template_fix'] = False
        with self.assertRaises(ValueError): m.guard_plan(p, [], 'truenas', True)
        with self.assertRaises(ValueError): m.guard_plan(p, [], 'truenas', False)
        expected['native_template_fix'] = 1
        with self.assertRaises(ValueError): m.guard_plan(p, [], 'truenas', True)
        for phase in ['all', 'logging', 'tailnet']:
            expected['phase'] = phase
            with self.assertRaises(ValueError): m.guard_plan(p, [], phase, True)

    def bootstrap_fixture(self, profile_path):
        profile = json.loads(profile_path.read_text())
        declaration = {key: profile[key] for key in
                       ('expected_vm_uuid', 'expected_version', 'address', 'ssh_alias',
                        'syslogserver', 'api_key_file', 'server_certificate_file', 'pki_directory')}
        declaration.update(console_administration_enabled=True, native_syslog_template_fix_enabled=True,
                           profile_file=str(profile_path))
        path = profile_path.with_name('bootstrap.json')
        path.write_text(json.dumps(declaration)); path.chmod(0o600)
        return path, declaration

    def test_repair_review_binds_declaration_identity_paths_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, profile, pki, config = self.private_fixture(Path(temporary))
            declaration, values = self.bootstrap_fixture(profile)
            config['monitoring_truenas_native_template_fix_enabled'] = True
            env = {'WAZUH_TRUENAS_PROFILE': str(profile), 'WAZUH_TRUENAS_BOOTSTRAP': str(declaration)}
            with mock.patch.object(m, 'ROOT', repo):
                original = m.truenas_review(env, config)
                self.assertEqual(original['bootstrap'], m.digest(declaration))
                self.assertTrue(original['native_template_fix'])
                declaration.write_text(declaration.read_text()+'\n')
                self.assertNotEqual(original, m.truenas_review(env, config))
                mismatches = {
                    'console_administration_enabled': 'true', 'native_syslog_template_fix_enabled': False,
                    'expected_vm_uuid': 'different', 'expected_version': 'new-version', 'address': '10.23.1.9',
                    'ssh_alias': 'other-host', 'syslogserver': '10.23.1.8:6514',
                    'profile_file': str(pki/'ca.pem'), 'api_key_file': str(pki/'client-key.pem'),
                    'server_certificate_file': str(pki/'ca.pem'), 'pki_directory': str(pki.parent)}
                for key, value in mismatches.items():
                    declaration.write_text(json.dumps(dict(values, **{key: value})))
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        m.truenas_review(env, config)
                declaration.write_text(json.dumps(values)); declaration.chmod(0o644)
                with self.assertRaises(ValueError): m.truenas_review(env, config)

    def test_repair_disabled_does_not_need_bootstrap_and_deploy_order_is_exact(self):
        config = {'monitoring_truenas_native_template_fix_enabled': True}
        env = {'WAZUH_TRUENAS_PROFILE': '/private/profile', 'WAZUH_TRUENAS_BOOTSTRAP': '/private/bootstrap'}
        with mock.patch.object(m, 'inputs', return_value=(Path('/private/inventory'), Path('/private/vars'), config)), \
             mock.patch.object(m, 'truenas_review'), mock.patch.object(m, 'private_file', side_effect=Path), \
             mock.patch.object(m.subprocess, 'run') as run:
            m.deploy(env, 'truenas')
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 3)
        self.assertEqual(commands[0][-2:], ['--tags', 'truenas'])
        self.assertEqual(commands[1], [m.sys.executable, str(m.ROOT/'monitoring/truenas/native_fix.py'), '--declaration', '/private/bootstrap'])
        self.assertEqual(commands[2], [m.sys.executable, str(m.ROOT/'monitoring/truenas/client.py'), 'configure', '--profile', '/private/profile'])
        with tempfile.TemporaryDirectory() as temporary:
            repo, profile, pki, config = self.private_fixture(Path(temporary))
            config['monitoring_truenas_native_template_fix_enabled'] = False
            with mock.patch.object(m, 'ROOT', repo):
                review = m.truenas_review({'WAZUH_TRUENAS_PROFILE':str(profile)}, config)
            self.assertNotIn('bootstrap', review)

    def test_optional_usr_remount_approval_requires_an_actual_boolean(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, profile, pki, config = self.private_fixture(Path(temporary))
            declaration, values = self.bootstrap_fixture(profile)
            config['monitoring_truenas_native_template_fix_enabled'] = True
            env = {'WAZUH_TRUENAS_PROFILE': str(profile), 'WAZUH_TRUENAS_BOOTSTRAP': str(declaration)}
            with mock.patch.object(m, 'ROOT', repo):
                baseline = m.truenas_review(env, config)
                for value in [False, True]:
                    declaration.write_text(json.dumps(dict(values, native_syslog_usr_remount_enabled=value)))
                    self.assertNotEqual(baseline, m.truenas_review(env, config))
                for value in ['true', 'false', 0, 1, None]:
                    declaration.write_text(json.dumps(dict(values, native_syslog_usr_remount_enabled=value)))
                    with self.subTest(value=value), self.assertRaises(ValueError):
                        m.truenas_review(env, config)

if __name__ == '__main__': unittest.main()
