import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab
from test_plan_guard import fixture


FIXTURE=Path(__file__).resolve().parents[3]/'tests/fixtures/xen'

class ConvergenceRunnerTests(unittest.TestCase):
    def setUp(self):
        self.environment=patch.dict(os.environ,{'XEN_ANSIBLE_INVENTORY':str(FIXTURE/'ansible/hosts.yml'),'XEN_HOST_VARS_FILE':str(FIXTURE/'ansible/host_vars/example_control.yml')})
        self.environment.start();self.addCleanup(self.environment.stop)

    def exercise(self, reject=False, guests=None):
        inventory, plan = fixture()
        policy = {'schema_version': 1, 'vms': {}, 'networks': {}, 'guest_targets': guests or []}
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            saved = root / 'convergence.tfplan'
            saved.write_text('saved exact plan')
            saved.chmod(0o600)
            private_vars = root / 'private.yml'
            private_vars.write_text('{}')
            private_vars.chmod(0o600)
            def terraform(*args, **kwargs):
                calls.append(('terraform', args))
                if args[:2] == ('show', '-json'):
                    return json.dumps(plan) if len(args) == 3 else '{}'
                return ''
            def ansible(playbook, **kwargs):
                calls.append(('ansible', playbook, kwargs))
            with patch.dict(os.environ, {'XEN_RUN_DIR': str(root), 'XOA_URL': 'wss://xo.invalid',
                                          'XOA_TOKEN': 'private-test-token', 'XEN_PRIVATE_VARS': str(private_vars)}, clear=False), \
                 patch.object(lab, 'terraform', side_effect=terraform), \
                 patch.object(lab, 'ansible', side_effect=ansible), \
                 patch.object(lab, 'query_live', return_value={}), \
                 patch.object(lab, 'bootstrap_management', side_effect=lambda inventory, policy, state: calls.append(('bootstrap', state))), \
                 patch.object(lab, 'resolve_bindings', return_value={'schema_version':1,'existing_vm_ids':{},'existing_network_ids':{},'available_template_ids':[]}), \
                 patch.object(lab, 'verify_convergence', side_effect=ValueError('disk replacement') if reject else None, return_value=2):
                if reject:
                    with self.assertRaisesRegex(ValueError, 'disk replacement'):
                        lab.converge(inventory, policy, saved)
                else:
                    lab.converge(inventory, policy, saved)
        return calls

    def test_up_plans_checks_applies_then_runs_native_and_guest_convergence(self):
        calls = self.exercise(guests=['example_linux'])
        kinds = [(c[0], c[1][0] if c[0] == 'terraform' else c[1]) for c in calls]
        self.assertIn(('terraform', 'plan'), kinds)
        apply = kinds.index(('terraform', 'apply'))
        self.assertGreater(kinds.index(('ansible', 'xcp-definitions.yml')), apply)
        self.assertGreater(kinds.index(('ansible', '../recovery/native-boot.yml')), apply)
        self.assertGreater(kinds.index(('ansible', '../hardening/apply.yml')), apply)
        self.assertGreater(kinds.index(('ansible', '../networking/apply.yml')), apply)
        self.assertLess(kinds.index(('ansible', 'converge-guests.yml')), apply)
        self.assertEqual(kinds[-1], ('ansible', 'converge-guests.yml'))
        self.assertTrue(any(c[0] == 'ansible' and c[2].get('extra_vars', {}).get('xcp_definition_apply') is True for c in calls))

    def test_convergence_loads_local_state_before_bootstrap(self):
        calls=self.exercise()
        initial=next(index for index,call in enumerate(calls) if call[:2]==('terraform',('init','-input=false')))
        state=next(index for index,call in enumerate(calls) if call[:2]==('terraform',('show','-json')))
        bootstrap=next(index for index,call in enumerate(calls) if call[0]=='bootstrap')
        self.assertLess(initial,state)
        self.assertLess(state,bootstrap)
        self.assertEqual(calls[bootstrap][1],{})

    def test_rejected_plan_never_applies_or_configures(self):
        calls = self.exercise(reject=True)
        self.assertFalse(any(c[0] == 'ansible' or (c[0] == 'terraform' and c[1][0] == 'apply') for c in calls))

    def test_empty_guest_selection_is_reported_and_not_run_with_all_hosts(self):
        calls = self.exercise()
        self.assertFalse(any(c[0] == 'ansible' and c[1] == 'converge-guests.yml' for c in calls))

    def test_unknown_guest_cannot_silently_match_zero_hosts(self):
        with self.assertRaisesRegex(ValueError, 'unknown|Linux'):
            lab.validate_policy({'schema_version':1,'vms':{},'networks':{},'guest_targets':['typo']}, fixture()[0])

    def test_explicit_autostart_policy_is_boolean(self):
        inventory,_ = fixture()
        logical = next(iter(inventory['vms']))
        lab.validate_policy({'schema_version':1,'vms':{logical:{'auto_poweron':False}},'networks':{},'guest_targets':[]}, inventory)
        with self.assertRaisesRegex(ValueError, 'boolean'):
            lab.validate_policy({'schema_version':1,'vms':{logical:{'auto_poweron':'false'}},'networks':{},'guest_targets':[]}, inventory)

    def test_diskless_overrides_reach_native_definitions(self):
        host = json.loads((FIXTURE / 'ansible/host_vars/example_control.yml').read_text())
        logical = host['xcp_native_definitions'][0]['uuid']
        definitions = lab.native_definitions({'vms': {logical: {'cpus': 3, 'memory_min': 2147483648,
                                                               'memory_max': 4294967296}}}, {'existing_network_ids': {}})
        changed = next(item for item in definitions if item['uuid'] == logical)
        self.assertEqual(changed['VCPUs_at_startup'], '3')
        self.assertEqual(changed['VCPUs_max'], '3')
        self.assertEqual(changed['memory_dynamic_max'], '4294967296')
        self.assertEqual(changed['memory_static_max'], '4294967296')

    def test_diskless_guest_cannot_be_started_without_an_os_disk(self):
        host = json.loads((FIXTURE / 'ansible/host_vars/example_control.yml').read_text())
        logical = host['xcp_native_definitions'][0]['uuid']
        with self.assertRaisesRegex(ValueError, 'diskless'):
            lab.native_definitions({'vms': {logical: {'power_state': 'Running'}}}, {'existing_network_ids': {}})

    def test_management_bootstrap_requires_declared_running_and_only_targets_xoa(self):
        inventory = json.loads((FIXTURE/'inventory.json').read_text())
        logical = next(key for key, vm in inventory['vms'].items() if vm['uuid'] == json.loads((FIXTURE/'recovery-policy.json').read_text())['automatic_vm_ids'][0])
        with patch.object(lab, 'remote_json', return_value={'power_state': 'Running', 'changed': True}) as remote:
            lab.bootstrap_management(inventory, {'vms': {}}, {})
            remote.assert_not_called()
            lab.bootstrap_management(inventory, {'vms': {logical: {'power_state': 'Running'}}}, {})
            self.assertEqual(remote.call_count, 1)
            self.assertIn(logical, remote.call_args.args[0])
            self.assertNotIn('database', remote.call_args.args[0])

    def test_private_connection_loads_without_overriding_operator_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'connection.json'
            path.write_text(json.dumps({'XOA_URL': 'ws://127.0.0.1:1234', 'XOA_TOKEN': 'fixture-only'}))
            path.chmod(0o600)
            with patch.dict(os.environ, {'XEN_CONNECTION_FILE': str(path), 'XOA_URL': 'wss://operator.test'}, clear=True):
                lab.load_connection()
                self.assertEqual(os.environ['XOA_TOKEN'], 'fixture-only')
                self.assertEqual(os.environ['XOA_URL'], 'wss://operator.test')

    def test_public_connection_file_is_rejected_before_loading_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'connection.json'
            path.write_text('{"XOA_TOKEN":"fixture-only"}')
            path.chmod(0o644)
            with patch.dict(os.environ, {'XEN_CONNECTION_FILE': str(path)}, clear=True):
                with self.assertRaisesRegex(ValueError, 'owner-only'):
                    lab.load_connection()
                self.assertNotIn('XOA_TOKEN', os.environ)

    def test_saved_token_and_recovery_password_use_only_one_provider_auth_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'connection.json'
            path.write_text(json.dumps({'XOA_TOKEN': 'fixture-token', 'XOA_USER': 'automation', 'XOA_PASSWORD': 'fixture-password'}))
            path.chmod(0o600)
            with patch.dict(os.environ, {'XEN_CONNECTION_FILE': str(path)}, clear=True):
                lab.load_connection()
                self.assertEqual(os.environ['XOA_TOKEN'], 'fixture-token')
                self.assertNotIn('XOA_USER', os.environ)
                self.assertNotIn('XOA_PASSWORD', os.environ)

    def test_expired_saved_token_uses_private_automation_account_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'connection.json'
            path.write_text(json.dumps({'XOA_TOKEN': 'expired-fixture', 'expires_at': '2000-01-01T00:00:00Z',
                                         'XOA_USER': 'automation', 'XOA_PASSWORD': 'fixture-password'}))
            path.chmod(0o600)
            with patch.dict(os.environ, {'XEN_CONNECTION_FILE': str(path)}, clear=True):
                lab.load_connection()
                self.assertNotIn('XOA_TOKEN', os.environ)
                self.assertEqual(os.environ['XOA_USER'], 'automation')

    def test_host_control_socket_is_never_reused_for_guest_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'XEN_RUN_DIR':directory,'XEN_SSH_CONTROL':'/private/tmp/host-only-control'}, clear=True), \
                 patch.object(lab, 'run', return_value='') as runner:
                lab.ansible('converge-guests.yml',check=False,limit='example_linux')
                self.assertNotIn('--ssh-common-args',runner.call_args.args[0])
                lab.ansible('xcp-definitions.yml',check=True,limit='example_control')
                self.assertIn('--ssh-common-args',runner.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
