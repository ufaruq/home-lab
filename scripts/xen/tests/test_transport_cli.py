"""Check that real CLI dispatch owns transport lifetime, including failures."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab


FIXTURE=Path(__file__).resolve().parents[3]/'tests/fixtures/xen'
FIXTURE_ENV={'XEN_INVENTORY_FILE':str(FIXTURE/'inventory.json'),'XEN_POLICY_FILE':str(FIXTURE/'policy.json'),'XEN_ANSIBLE_INVENTORY':str(FIXTURE/'ansible/hosts.yml'),'XEN_HOST_VARS_FILE':str(FIXTURE/'ansible/host_vars/example_control.yml')}

class TransportCLITests(unittest.TestCase):
    def exercise(self, command, failure=False):
        opened = Mock()
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, dict(FIXTURE_ENV,XEN_RUN_DIR=directory), clear=True), \
                patch.object(sys, 'argv', ['lab.py', command]), \
                patch.object(lab, 'load_connection'), \
                patch.object(lab, 'open_transport', return_value=opened) as connect, \
                patch.object(lab, 'bootstrap_management'), \
                patch.object(lab, 'terraform', return_value='{}'), \
                patch.object(lab, 'converge', side_effect=ValueError('fixture failure') if failure else None):
            result = lab.main()
        return result, connect, opened

    def test_bootstrap_connects_without_api_and_closes(self):
        result, connect, opened = self.exercise('bootstrap')
        self.assertEqual(result, 0)
        connect.assert_called_once_with(api=False)
        opened.close.assert_called_once_with()

    def test_standalone_bootstrap_loads_local_state_before_host_bootstrap(self):
        events=[]
        state={'values':{'root_module':{'resources':[]}}}
        def terraform(*args,**kwargs):
            events.append(('terraform',args))
            return __import__('json').dumps(state) if args==('show','-json') else ''
        def bootstrap(inventory,policy,observed):
            events.append(('bootstrap',observed))
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ,dict(FIXTURE_ENV,XEN_RUN_DIR=directory),clear=True), \
                patch.object(sys,'argv',['lab.py','bootstrap']), \
                patch.object(lab,'load_connection'), \
                patch.object(lab,'open_transport',return_value=Mock()), \
                patch.object(lab,'terraform',side_effect=terraform), \
                patch.object(lab,'bootstrap_management',side_effect=bootstrap):
            self.assertEqual(lab.main(),0)
        self.assertEqual(events,[('terraform',('init','-input=false')),('terraform',('show','-json')),('bootstrap',state)])

    def test_inventory_does_not_connect_or_prompt(self):
        result, connect, opened = self.exercise('inventory')
        self.assertEqual(result, 0)
        connect.assert_not_called()
        opened.close.assert_not_called()

    def test_rejected_convergence_still_closes_its_api_forward(self):
        result, connect, opened = self.exercise('converge', failure=True)
        self.assertEqual(result, 2)
        connect.assert_called_once_with(api=True)
        opened.close.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
