import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from discovery import resolve_bindings
from test_plan_guard import fixture


class DiscoveryTests(unittest.TestCase):
    def source(self):
        inventory, _ = fixture()
        live = {'vms': {key: {'name_label': value.get('name_label', key)} for key, value in inventory['vms'].items()},
                'networks': {key: {} for key in inventory['networks']}, 'templates': {'template-1': {}}}
        return inventory, live

    def test_missing_vm_is_not_imported(self):
        inventory, live = self.source()
        missing = next(iter(inventory['vms']))
        del live['vms'][missing]
        bindings = resolve_bindings(inventory, live, {})
        self.assertNotIn(missing, bindings['existing_vm_ids'])
        self.assertIn('template-1', bindings['available_template_ids'])

    def test_recovered_state_identity_is_reused(self):
        inventory, live = self.source()
        logical = next(iter(inventory['vms']))
        live['vms']['recovered-id'] = live['vms'].pop(logical)
        address = f'xenorchestra_vm.existing["{logical}"]'
        state = {'values': {'root_module': {'resources': [{'address': address, 'values': {'id': 'recovered-id'}}]}}}
        self.assertEqual(resolve_bindings(inventory, live, state)['existing_vm_ids'][logical], 'recovered-id')

    def test_untracked_same_name_vm_blocks_duplicate_creation(self):
        inventory, live = self.source()
        logical = next(iter(inventory['vms']))
        inventory['vms'][logical]['name_label'] = 'important'
        live['vms']['untracked'] = {'name_label': 'important'}
        del live['vms'][logical]
        with self.assertRaisesRegex(ValueError, 'untracked'):
            resolve_bindings(inventory, live, {})

    def test_stale_state_cannot_rebind_a_different_live_object(self):
        inventory, live = self.source()
        logical = next(iter(inventory['vms']))
        state = {'values': {'root_module': {'resources': [{'address': f'xenorchestra_vm.existing["{logical}"]', 'values': {'id': 'different'}}]}}}
        with self.assertRaisesRegex(ValueError, 'identity'):
            resolve_bindings(inventory, live, state)


if __name__ == '__main__':
    unittest.main()
