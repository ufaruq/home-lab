import importlib.util
import unittest
from pathlib import Path

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

if __name__ == '__main__': unittest.main()
