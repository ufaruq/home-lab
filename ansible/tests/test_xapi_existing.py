import copy
import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location('xapi_existing', pathlib.Path(__file__).parents[1] / 'files/xapi_existing.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
UUID = '20000000-0000-4000-8000-000000000001'
ALLOWED = {UUID: 'example-diskless'}


def state():
    return {'uuid': UUID, 'name_label': 'example-diskless', 'VCPUs_max': '4', 'VCPUs_at_startup': '4',
            'memory_static_min': '536870912', 'memory_static_max': '8589934592',
            'memory_dynamic_min': '8589934592', 'memory_dynamic_max': '8589934592',
            'power_state': 'Halted', 'disks': [], 'vifs': [{'uuid': 'vif1', 'device': '0', 'MAC': 'aa:bb:cc:dd:ee:ff', 'network_uuid': 'net1'}]}


class FakeAPI:
    """Stateful fake backend; writes actually change subsequent reads."""
    def __init__(self, observed):
        self.observed = copy.deepcopy(observed)
        self.writes = []
    def get_vm(self, uuid):
        if uuid != self.observed['uuid']:
            raise ValueError('unknown VM')
        return copy.deepcopy(self.observed)
    def set_cpu(self, uuid, maximum, startup):
        self.writes.append(('cpu', uuid, maximum, startup))
        self.observed.update(VCPUs_max=maximum, VCPUs_at_startup=startup)
    def set_memory(self, uuid, values):
        self.writes.append(('memory', uuid, values))
        self.observed.update(values)
    def move_vif(self, uuid, network):
        self.writes.append(('vif', uuid, network))
        next(v for v in self.observed['vifs'] if v['uuid'] == uuid)['network_uuid'] = network


class ExistingVMTests(unittest.TestCase):
    def test_check_reports_cpu_memory_network_drift_without_writes(self):
        desired = state()
        desired.update(VCPUs_max='6', VCPUs_at_startup='6', memory_dynamic_min='4294967296')
        desired['vifs'][0]['network_uuid'] = 'net2'
        api = FakeAPI(state())
        before = copy.deepcopy(api.observed)
        result = m.reconcile(api, [desired], ALLOWED, apply=False)
        self.assertTrue(result['changed'])
        self.assertIn('VCPUs_max', result['vms'][0]['diff'])
        self.assertIn('memory_dynamic_min', result['vms'][0]['diff'])
        self.assertIn('vifs', result['vms'][0]['diff'])
        self.assertEqual(api.writes, [])
        self.assertEqual(api.observed, before)
    def test_explicit_apply_reconciles_existing_definition_and_is_idempotent(self):
        desired = state()
        desired.update(VCPUs_max='6', VCPUs_at_startup='6', memory_dynamic_min='4294967296')
        desired['vifs'][0]['network_uuid'] = 'net2'
        api = FakeAPI(state())
        self.assertTrue(m.reconcile(api, [desired], ALLOWED, apply=True)['changed'])
        self.assertFalse(m.reconcile(api, [desired], ALLOWED, apply=True)['changed'])
        self.assertEqual([w[0] for w in api.writes], ['cpu', 'memory', 'vif'])
    def test_refuses_disk_power_identity_and_vif_identity_changes_before_writes(self):
        for mutation in ('disk', 'power', 'identity', 'vif'):
            desired = state()
            desired['VCPUs_max'] = '6'
            if mutation == 'disk': desired['disks'] = [{'uuid': 'newdisk'}]
            if mutation == 'power': desired['power_state'] = 'Running'
            if mutation == 'identity': desired['uuid'] = 'not-allowlisted'
            if mutation == 'vif': desired['vifs'][0]['MAC'] = '00:00:00:00:00:00'
            api = FakeAPI(state())
            with self.assertRaises(ValueError): m.reconcile(api, [desired], ALLOWED, apply=True)
            self.assertEqual(api.writes, [])
    def test_native_adapter_refuses_control_domains_templates_and_snapshots(self):
        from types import SimpleNamespace
        for flag in ('is_control_domain', 'is_a_template', 'is_a_snapshot'):
            vm = SimpleNamespace(get_by_uuid=lambda identity: 'ref', get_record=lambda ref: {flag: True})
            api = m.NativeAPI(SimpleNamespace(xenapi=SimpleNamespace(VM=vm)))
            with self.assertRaises(ValueError):
                api.get_vm(UUID)

    def test_missing_or_malformed_private_allowlist_refuses_every_write(self):
        for allowed in (None, {}, {"not-a-uuid": "example-diskless"}, {UUID: ""}):
            api = FakeAPI(state())
            with self.assertRaises(ValueError):
                m.reconcile(api, [state()], allowed, apply=True)
            self.assertEqual(api.writes, [])

    def test_observed_running_vm_refuses_apply_and_check_has_blocker(self):
        observed = state(); observed['power_state'] = 'Running'
        api = FakeAPI(observed)
        self.assertTrue(m.reconcile(api, [state()], ALLOWED, apply=False)['blocked'])
        with self.assertRaises(ValueError): m.reconcile(api, [state()], ALLOWED, apply=True)
        self.assertEqual(api.writes, [])


if __name__ == '__main__': unittest.main()
