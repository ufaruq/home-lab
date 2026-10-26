import copy
import importlib.util
import pathlib
import json
import unittest
SPEC=importlib.util.spec_from_file_location('native_boot',pathlib.Path(__file__).parents[1]/'native_boot.py')
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)

POLICY=json.loads((pathlib.Path(__file__).resolve().parents[3]/'tests/fixtures/xen/recovery-policy.json').read_text())
HOST=POLICY['expected_host_uuid'];POOL=POLICY['expected_pool_uuid'];MANAGER=POLICY['automatic_vm_ids'][0]

class FakeAPI:
    def __init__(self):
        self.data={'host_uuids':[HOST],'pool_uuid':POOL,'pool_auto_poweron':'true','vms':{MANAGER:{'name':'XOA','auto_poweron':'true','power_state':'Running'},'other':{'name':'other','auto_poweron':'false','power_state':'Halted'}}}
        self.writes=[]
    def snapshot(self):return copy.deepcopy(self.data)
    def enable_pool(self,pool_uuid):self.writes.append('pool');self.data['pool_auto_poweron']='true'

class FakeSystem:
    def __init__(self):
        self.data={'runtime_mask':True,'persistent_override':False,'unexpected_dropins':False,'stock_hashes_valid':True,'enabled':True,'active':False,'active_state':'inactive'}
        self.calls=[]
    def snapshot(self):return copy.deepcopy(self.data)
    def backup(self,before):self.calls.append('backup');return {'path':'/private-fixture/before.json','sha256':'fixture-sha'}
    def unmask_runtime(self):self.calls.append('unmask_runtime');self.data['runtime_mask']=False
    def reload(self):self.calls.append('reload')
    def enable(self):self.calls.append('enable');self.data['enabled']=True
    def start(self):self.calls.append('start');self.data['active']=True;self.data['active_state']='active'

class BootTests(unittest.TestCase):
    def test_check_has_no_writes_apply_is_idempotent(self):
        api=FakeAPI();system=FakeSystem()
        self.assertTrue(m.reconcile(api,system,POLICY,False)['changed'])
        self.assertEqual(system.calls,[]);self.assertEqual(api.writes,[])
        self.assertTrue(m.reconcile(api,system,POLICY,True)['changed'])
        self.assertEqual(system.calls,['backup','unmask_runtime','reload','start'])
        before=list(system.calls)
        self.assertFalse(m.reconcile(api,system,POLICY,True)['changed'])
        self.assertEqual(system.calls,before)
    def test_every_preflight_blocker_refuses_before_first_write(self):
        for failure in ['extra_flag','wrong_pool','invalid_other_state','persistent_mask','dropins','modified_stock']:
            api=FakeAPI();system=FakeSystem()
            if failure=='extra_flag':api.data['vms']['other']['auto_poweron']='true'
            if failure=='wrong_pool':api.data['pool_uuid']='wrong'
            if failure=='invalid_other_state':api.data['vms']['other']['power_state']='Broken'
            if failure=='persistent_mask':system.data['persistent_override']=True
            if failure=='dropins':system.data['unexpected_dropins']=True
            if failure=='modified_stock':system.data['stock_hashes_valid']=False
            with self.assertRaises(ValueError):m.reconcile(api,system,POLICY,True)
            self.assertEqual(api.writes,[]);self.assertEqual(system.calls,[])
    def test_active_stock_unit_is_never_stopped_or_restarted(self):
        api=FakeAPI();system=FakeSystem();system.data.update(runtime_mask=False,active=True,active_state='active')
        self.assertFalse(m.reconcile(api,system,POLICY,True)['changed'])
        self.assertNotIn('start',system.calls);self.assertNotIn('stop',system.calls);self.assertNotIn('restart',system.calls)
    def test_manually_running_nonautomatic_guest_is_unchanged(self):
        api=FakeAPI();api.data['vms']['other']['power_state']='Running';system=FakeSystem()
        result=m.reconcile(api,system,POLICY,True)
        self.assertEqual(result['after']['api']['vms']['other']['power_state'],'Running')
        self.assertEqual(api.writes,[])
        self.assertNotIn('stop',system.calls);self.assertNotIn('restart',system.calls)
    def test_unexpected_nonautomatic_guest_state_transition_is_refused(self):
        api=FakeAPI()
        class TransitioningSystem(FakeSystem):
            def start(self):
                super().start()
                api.data['vms']['other']['power_state']='Running'
        system=TransitioningSystem()
        with self.assertRaisesRegex(ValueError,'nonautomatic guest power state changed'):
            m.reconcile(api,system,POLICY,True)
        self.assertEqual(api.writes,[])
        self.assertNotIn('stop',system.calls);self.assertNotIn('restart',system.calls)

    def test_pool_enable_preserves_adapter_ownership_and_never_changes_guest_flags(self):
        api=FakeAPI();api.data['pool_auto_poweron']='false';system=FakeSystem()
        before=copy.deepcopy(api.data['vms'])
        result=m.reconcile(api,system,POLICY,True)
        self.assertEqual(api.writes,['pool']);self.assertEqual(api.data['vms'],before)
        self.assertTrue(result['after']['system']['active'])

if __name__=='__main__':unittest.main()
