"""Offline behavioral checks for security policy and native appliance reconciliation."""
import importlib.util
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SecurityPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load('policy', 'monitoring/wazuh/policy.py')

    def test_adoption_accepts_older_agent_but_rejects_newer_or_missing_versions(self):
        self.policy.validate_versions('4.7.5', '4.7.4')
        for version in ('4.7.6', '4.8.0', '', 'latest'):
            with self.assertRaises(ValueError):
                self.policy.validate_versions('4.7.5', version)

    def test_gate_requires_actual_booleans(self):
        self.policy.require_approval(True, True)
        for access, approved in ((False, True), (True, 'true'), ('true', True)):
            with self.assertRaises(ValueError):
                self.policy.require_approval(access, approved)

    def test_manager_status_accepts_healthy_standalone_with_optional_daemons_stopped(self):
        health = load('manager_status', 'ansible/roles/monitoring_wazuh_manager/files/validate_status.py')
        status = self.standalone_status()
        health.validate_status(status, 1)
        for optional in ('wazuh-authd', 'wazuh-execd'):
            next(item for item in status['data'] if item['daemon'] == optional)['status'] = 'stopped'
        configuration = '<ossec_config><auth><disabled>yes</disabled></auth><active-response><disabled>yes</disabled></active-response></ossec_config>'
        disabled = health.disabled_from_config(configuration)
        self.assertEqual(disabled, {'wazuh-authd', 'wazuh-execd'})
        health.validate_status(status, 1, disabled)
        with self.assertRaisesRegex(ValueError, 'wazuh-authd'):
            health.validate_status(status, 1)

    @staticmethod
    def standalone_status():
        running = ('wazuh-apid', 'wazuh-authd', 'wazuh-db', 'wazuh-execd', 'wazuh-analysisd',
                   'wazuh-syscheckd', 'wazuh-remoted', 'wazuh-logcollector', 'wazuh-monitord', 'wazuh-modulesd')
        stopped = ('wazuh-clusterd', 'wazuh-maild', 'wazuh-agentlessd', 'wazuh-integratord', 'wazuh-dbd', 'wazuh-csyslogd')
        return {'error': 0, 'data': [{'daemon': name, 'status': 'running'} for name in running]
                + [{'daemon': name, 'status': 'stopped'} for name in stopped]}

    def test_manager_status_rejects_missing_or_stopped_analysisd_and_remoted(self):
        health = load('manager_status', 'ansible/roles/monitoring_wazuh_manager/files/validate_status.py')
        for daemon in ('wazuh-analysisd', 'wazuh-remoted'):
            for missing in (False, True):
                status = self.standalone_status()
                if missing:
                    status['data'] = [row for row in status['data'] if row['daemon'] != daemon]
                else:
                    next(item for item in status['data'] if item['daemon'] == daemon)['status'] = 'stopped'
                with self.assertRaisesRegex(ValueError, daemon):
                    health.validate_status(status, 1)

    def test_retention_is_only_seven_day_alert_indices(self):
        policy = json.loads((ROOT / 'monitoring/wazuh/retention.json').read_text())
        self.policy.validate_retention(policy)
        policy['policy']['ism_template'][0]['index_patterns'] = ['*']
        with self.assertRaises(ValueError):
            self.policy.validate_retention(policy)

    def test_group_configuration_has_supported_linux_windows_fim_and_inventory(self):
        groups = ROOT / 'monitoring/wazuh/groups'
        for name in ('homelab-linux', 'homelab-windows', 'homelab-lab'):
            root = ET.parse(groups / name / 'agent.conf').getroot()
            self.assertIsNone(root.find('active-response'))
            self.assertIsNotNone(root.find('syscheck/directories'))
            self.assertIsNotNone(root.find("wodle[@name='syscollector']"))
            self.assertIsNotNone(root.find('localfile'))

    def test_response_disable_edits_only_local_disabled_value_and_is_repeatable(self):
        response = load('disable_response', 'monitoring/wazuh/disable_response.py')
        original = '<ossec_config><!--keep--><client><server><address>10.2.0.3</address></server><enrollment><password>private</password></enrollment></client><active-response><disabled>no</disabled><ca_store>etc/wpk_root.pem</ca_store></active-response></ossec_config>'
        expected = original.replace('<disabled>no</disabled>', '<disabled>yes</disabled>')
        self.assertEqual(response.disable(original), expected)
        self.assertEqual(response.disable(expected), expected)
        absent = '<ossec_config><syscheck><disabled>no</disabled></syscheck></ossec_config>'
        self.assertIn('<syscheck><disabled>no</disabled></syscheck>', response.disable(absent))
        self.assertIn('<active-response><disabled>yes</disabled></active-response>', response.disable(absent))

    def test_staging_preserves_manager_local_policy_keys_and_live_rules(self):
        staging = load('stage_policy', 'monitoring/wazuh/stage_policy.py')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            manager = base / 'manager'
            workspace = manager / 'etc/.workspace'
            for relative in ('etc/rules', 'etc/decoders'):
                (manager / relative).mkdir(parents=True)
            (workspace / 'source/rules').mkdir(parents=True)
            (workspace / 'source/decoders').mkdir(parents=True)
            original = '<ossec_config><!--keep--><auth><password>private</password></auth><ruleset><rule_dir>etc/rules</rule_dir><decoder_dir>etc/decoders</decoder_dir></ruleset></ossec_config>'
            (manager / 'etc/ossec.conf').write_text(original)
            (manager / 'etc/client.keys').write_text('private-identity')
            (manager / 'etc/rules/local_rules.xml').write_text('<group name="existing"/>')
            for kind in ('rules', 'decoders'):
                (workspace / f'source/{kind}/homelab_{kind}.xml').write_text('<group/>' if kind == 'rules' else '<decoder name="test"/>')
            staging.stage(manager, workspace)
            self.assertEqual((manager / 'etc/ossec.conf').read_text(), original)
            self.assertEqual((manager / 'etc/client.keys').read_text(), 'private-identity')
            self.assertFalse((manager / 'etc/rules/homelab_rules.xml').exists())
            self.assertEqual((workspace / 'staged-rules/local_rules.xml').read_text(), '<group name="existing"/>')
            self.assertIn('<auth><password>private</password></auth>', (workspace / 'ossec-validation.conf').read_text())
            self.assertIn('<rule_dir>etc/.workspace/staged-rules</rule_dir>', (workspace / 'ossec-validation.conf').read_text())

    def test_retention_attaches_only_unmanaged_alerts_and_is_repeatable(self):
        retention = load('retention', 'monitoring/wazuh/retention.py')
        body = json.loads((ROOT / 'monitoring/wazuh/retention.json').read_text())
        saved = None
        assigned = False
        writes = []
        def request(method, path, data=None, missing_ok=False):
            nonlocal saved, assigned
            if method == 'GET' and '/policies/' in path:
                if saved is None:
                    return None
                native = copy.deepcopy(saved['policy'])
                native['states'][1]['actions'][0]['retry'] = {'count': 3, 'backoff': 'exponential', 'delay': '1m'}
                native['ism_template'][0]['last_updated_time'] = 123456
                return {'policy': native, '_seq_no': 1, '_primary_term': 1}
            if method == 'PUT':
                writes.append(path)
                saved = data
                return {'_id': retention.POLICY_ID}
            if '/explain/' in path:
                return {'wazuh-alerts-4.x-2026.10.25': {'policy_id': retention.POLICY_ID if assigned else None}, 'total_managed_indices': 1}
            if '/add/' in path:
                writes.append(path)
                assigned = True
                return {'updated_indices': 1, 'failures': False, 'failed_indices': []}
            raise AssertionError((method, path))
        self.assertTrue(retention.reconcile(request, body))
        self.assertFalse(retention.reconcile(request, body))
        self.assertEqual(len(writes), 2)
        self.assertTrue(writes[1].endswith('wazuh-alerts-4.x-2026.10.25'))


class ApplianceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load('opnsense_syslog', 'monitoring/opnsense/syslog.py')

    def test_public_loopback_and_link_local_destinations_fail(self):
        for address in ('8.8.8.8', '127.0.0.1', '169.254.1.1', 'example.com', '::1', 'fe80::1'):
            with self.assertRaises(ValueError):
                self.api.destination(address, 514, 'tcp4')
        self.assertEqual(self.api.destination('10.2.0.3', 514, 'tcp4')['hostname'], '10.2.0.3')
        with self.assertRaises(ValueError):
            self.api.destination('10.2.0.3', 6514, 'tls4')
        self.assertEqual(self.api.destination('10.2.0.3', 6514, 'tls4', '00000000-0000-0000-0000-000000000001')['transport'], 'tls4')

    def test_plaintext_requires_verified_encrypted_vpn_before_any_api_call(self):
        config = {'access_verified': True, 'deployment_approved': True, 'destination': '10.2.0.3', 'port': 514, 'transport': 'tcp4'}
        calls = []
        for flag in (None, False, 'true'):
            candidate = dict(config, vpn_verified=flag)
            with self.assertRaises(ValueError):
                self.api.configure(candidate, lambda *args: calls.append(args))
        self.assertEqual(calls, [])
        self.api.validate_transport(dict(config, vpn_verified=True))

    def test_tls_requires_existing_verified_relay_and_ca_before_any_api_call(self):
        config = {'access_verified': True, 'deployment_approved': True, 'destination': '10.2.0.3', 'port': 6514, 'transport': 'tls4',
                  'certificate': '00000000-0000-0000-0000-000000000001'}
        calls = []
        for extras in ({}, {'tls_relay_verified': 'true', 'tls_ca_sha256': 'a' * 64}, {'tls_relay_verified': True},
                       {'tls_relay_verified': True, 'tls_ca_sha256': 'invalid'}):
            with self.assertRaises(ValueError):
                self.api.configure(dict(config, **extras), lambda *args: calls.append(args))
        self.assertEqual(calls, [])
        self.api.validate_transport(dict(config, tls_relay_verified=True, tls_ca_sha256='a' * 64))

    def test_reconcile_add_then_noop_then_update_with_readback(self):
        state = {}
        writes = []

        def request(method, path, body=None):
            if path.endswith('searchDestinations'):
                return {'rows': [{'uuid': key, 'description': value['description']} for key, value in state.items()]}
            if '/getDestination/' in path:
                return {'destination': state[path.rsplit('/', 1)[1]]}
            if path.endswith('addDestination'):
                state['abc'] = body['destination'].copy()
                writes.append('add')
                return {'result': 'saved', 'uuid': 'abc'}
            if '/setDestination/' in path:
                state['abc'].update(body['destination'])
                writes.append('set')
                return {'result': 'saved'}
            if path.endswith('reconfigure'):
                writes.append('reload')
                return {'status': 'ok'}
            raise AssertionError(path)

        desired = self.api.destination('10.2.0.3', 514, 'tcp4')
        self.assertTrue(self.api.reconcile(request, desired))
        self.assertFalse(self.api.reconcile(request, desired))
        desired['port'] = '5514'
        self.assertTrue(self.api.reconcile(request, desired))
        self.assertEqual(writes, ['add', 'reload', 'set', 'reload'])

    def test_duplicate_owned_destinations_fail_without_mutation(self):
        def request(method, path, body=None):
            self.assertEqual(method, 'POST')
            self.assertTrue(path.endswith('searchDestinations'))
            return {'rows': [{'uuid': 'a', 'description': 'homelab-monitoring'}, {'uuid': 'b', 'description': 'homelab-monitoring'}]}
        with self.assertRaises(ValueError):
            self.api.reconcile(request, self.api.destination('10.2.0.3', 514, 'tcp4'))

    def test_selection_normalization_matches_native_get_destination(self):
        desired = self.api.destination('10.2.0.3', 514, 'tcp4')
        actual = desired.copy()
        actual['transport'] = {'tcp4': {'selected': 1, 'value': 'TCP(4)'}, 'udp4': {'selected': 0}}
        actual['program'] = {'sshd': {'selected': 1}, 'filterlog': {'selected': 1}, 'ntpd': {'selected': 0}}
        self.assertTrue(self.api.equal(actual, desired))
        actual['program']['ntpd']['selected'] = 1
        self.assertFalse(self.api.equal(actual, desired))


class DeploymentGateTests(unittest.TestCase):
    def test_two_core_arm_requires_explicit_small_lab_approval_and_memory(self):
        binary = os.environ.get('ANSIBLE_PLAYBOOK') or shutil.which('ansible-playbook')
        if not binary:
            self.skipTest('Set ANSIBLE_PLAYBOOK to run real Ansible checks')
        with tempfile.TemporaryDirectory() as directory:
            base = {'monitoring_wazuh_fresh_approved': True, 'monitoring_wazuh_manager_version': '4.14.9',
                    'monitoring_wazuh_fresh_version': '4.14.9', 'monitoring_wazuh_installer_sha256': 'a' * 64,
                    'monitoring_wazuh_arm_small_approved': True,
                    'ansible_facts': {'distribution': 'Ubuntu', 'distribution_version': '22.04', 'architecture': 'aarch64', 'memtotal_mb': 12000, 'processor_vcpus': 2}}
            task = [{'ansible.builtin.include_tasks': str(ROOT / 'ansible/roles/monitoring_wazuh_manager/tasks/fresh-platform.yml')}]
            result = self.run_play(binary, directory, task, base)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for change in ('approval', 'string', 'architecture', 'memory', 'cores'):
                variables = copy.deepcopy(base)
                if change == 'approval': variables['monitoring_wazuh_arm_small_approved'] = False
                if change == 'string': variables['monitoring_wazuh_arm_small_approved'] = 'true'
                if change == 'architecture': variables['ansible_facts']['architecture'] = 'x86_64'
                if change == 'memory': variables['ansible_facts']['memtotal_mb'] = 4096
                if change == 'cores': variables['ansible_facts']['processor_vcpus'] = 1
                result = self.run_play(binary, directory, task, variables)
                self.assertNotEqual(result.returncode, 0, change)
                self.assertIn('changed=0', result.stdout)

    def run_play(self, binary, directory, tasks, variables):
        path = Path(directory) / 'gate.json'
        path.write_text(json.dumps([{'hosts': 'localhost', 'gather_facts': False, 'connection': 'local',
                                     'vars': variables, 'tasks': tasks}]))
        environment = os.environ.copy()
        environment['ANSIBLE_LOCAL_TEMP'] = str(Path(directory) / 'tmp')
        return subprocess.run([binary, '-i', 'localhost,', str(path)], env=environment,
                              capture_output=True, text=True, timeout=30)

    def test_native_syslog_receiver_rejects_missing_vpn_gate_before_guest_contact(self):
        binary = os.environ.get('ANSIBLE_PLAYBOOK') or shutil.which('ansible-playbook')
        if not binary:
            self.skipTest('Set ANSIBLE_PLAYBOOK to run real Ansible gate checks')
        with tempfile.TemporaryDirectory() as directory:
            for flag in (False, 'true'):
                role = str(ROOT / 'ansible/roles/monitoring_wazuh_manager')
                result = self.run_play(binary, directory, [{'ansible.builtin.include_role': {'name': role}}],
                    {'monitoring_access_verified': True, 'monitoring_deployment_approved': True,
                     'monitoring_wazuh_syslog_enabled': True, 'monitoring_wazuh_syslog_vpn_verified': flag})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('changed=0', result.stdout)
                self.assertNotIn('Detect existing manager identity', result.stdout)

    def test_fresh_flow_gathers_real_hardware_facts_with_automatic_gathering_disabled(self):
        binary = os.environ.get('ANSIBLE_PLAYBOOK') or shutil.which('ansible-playbook')
        if not binary:
            self.skipTest('Set ANSIBLE_PLAYBOOK to run real Ansible fact collection')
        role = str(ROOT / 'ansible/roles/monitoring_wazuh_manager')
        with tempfile.TemporaryDirectory() as directory:
            tasks = [
                {'block': [{'ansible.builtin.include_role': {'name': role, 'tasks_from': 'fresh'}}],
                 'rescue': [
                     {'ansible.builtin.assert': {'that': ["ansible_failed_task.name == 'Refuse implicit fresh installation or unsupported OS'"]}},
                     {'ansible.builtin.set_fact': {'fresh_refusal_observed': True}},
                 ]},
                {'ansible.builtin.assert': {'that': ['fresh_refusal_observed is sameas true'] +
                    [f'ansible_facts.{name} is defined' for name in
                     ('distribution', 'distribution_version', 'architecture', 'memtotal_mb', 'processor_vcpus')]}},
            ]
            variables = {'monitoring_access_verified': True, 'monitoring_deployment_approved': True,
                         'monitoring_wazuh_fresh_approved': True, 'monitoring_wazuh_installer_sha256': 'a' * 64,
                         # Deliberate release mismatch stops the real fresh flow before package inspection/install.
                         'monitoring_wazuh_manager_version': '4.7.5', 'monitoring_wazuh_fresh_version': '4.14.9'}
            result = self.run_play(binary, directory, tasks, variables)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('changed=0', result.stdout)
            self.assertNotIn('Check all central component packages', result.stdout)
            variables['monitoring_access_verified'] = False
            rejected = self.run_play(binary, directory, tasks, variables)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertNotIn('Gather fresh bootstrap', rejected.stdout)

    def test_sender_and_fresh_agents_reject_unverified_transport_before_mutation(self):
        binary = os.environ.get('ANSIBLE_PLAYBOOK') or shutil.which('ansible-playbook')
        if not binary:
            self.skipTest('Set ANSIBLE_PLAYBOOK to run real Ansible gate checks')
        with tempfile.TemporaryDirectory() as directory:
            for flag in (False, 'true'):
                sender = self.run_play(binary, directory,
                    [{'ansible.builtin.include_role': {'name': str(ROOT / 'ansible/roles/monitoring_opnsense')}}],
                    {'monitoring_access_verified': True, 'monitoring_deployment_approved': True,
                     'monitoring_opnsense_url': 'https://firewall.invalid', 'monitoring_opnsense_api_key': 'fixture',
                     'monitoring_opnsense_api_secret': 'fixture', 'monitoring_opnsense_syslog_vpn_verified': flag})
                self.assertNotEqual(sender.returncode, 0)
                self.assertIn('changed=0', sender.stdout)
                self.assertNotIn('Reconcile and read back', sender.stdout)
                for platform in ('linux', 'windows'):
                    result = self.run_play(binary, directory,
                        [{'ansible.builtin.include_tasks': str(ROOT / f'ansible/roles/monitoring_wazuh_agent/tasks/{platform}-install.yml')}],
                        {'monitoring_wazuh_agent_install_approved': True, 'monitoring_agent_directory': {'stat': {'exists': False}},
                         'ansible_facts': {'architecture': 'x86_64'}, 'monitoring_wazuh_agent_package_sha256': 'a' * 64,
                         'monitoring_wazuh_enrollment_password': 'fixture-private', 'monitoring_wazuh_manager_ca_source': '/nonexistent-reviewed-ca.pem',
                         'monitoring_wazuh_enrollment_tls_verified': flag, 'monitoring_wazuh_agent_group': 'homelab-windows'})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('changed=0', result.stdout)
                    self.assertNotIn('Place reviewed', result.stdout)
                    self.assertNotIn('Copy reviewed', result.stdout)

    def test_roles_stop_before_contact_or_mutation_with_closed_gates(self):
        binary = os.environ.get('ANSIBLE_PLAYBOOK') or shutil.which('ansible-playbook')
        if not binary:
            self.skipTest('Set ANSIBLE_PLAYBOOK to run real Ansible gate checks')
        with tempfile.TemporaryDirectory() as directory:
            environment = os.environ.copy()
            environment['ANSIBLE_LOCAL_TEMP'] = str(Path(directory) / 'tmp')
            for role in ('monitoring_wazuh_manager', 'monitoring_wazuh_agent', 'monitoring_opnsense'):
                for gate in (False, 'true'):
                    playbook = [{'hosts': 'localhost', 'gather_facts': False, 'connection': 'local',
                                 'vars': {'monitoring_access_verified': gate, 'monitoring_deployment_approved': True},
                                 'roles': [{'role': str(ROOT / 'ansible/roles' / role)}]}]
                    path = Path(directory) / 'gate.json'
                    path.write_text(json.dumps(playbook))
                    result = subprocess.run([binary, '-i', 'localhost,', str(path)], env=environment,
                                            capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(result.returncode, 0, role)
                    self.assertIn('changed=0', result.stdout)
                    self.assertEqual(result.stdout.count('TASK ['), 1)
                    self.assertNotIn('TASK [' + role + ' : Detect', result.stdout)


if __name__ == '__main__':
    unittest.main()
