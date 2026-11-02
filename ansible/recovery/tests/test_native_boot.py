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
    def set_guest_lifecycle(self,identity,settings):self.writes.append(('lifecycle',identity));self.data['vms'][identity].update(settings)

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
    def lifecycle_case(self):
        policy=copy.deepcopy(POLICY);policy['guest_lifecycle']={MANAGER:{'actions_after_crash':'restart','actions_after_reboot':'restart','actions_after_shutdown':'destroy'}}
        api=FakeAPI();api.data['vms'][MANAGER].update(actions_after_crash='destroy',actions_after_reboot='destroy',actions_after_shutdown='destroy')
        system=FakeSystem();system.data.update(runtime_mask=False,active=True,active_state='active')
        return policy,api,system
    def test_lifecycle_check_is_readonly_and_apply_changes_only_metadata(self):
        policy,api,system=self.lifecycle_case();before=api.data['vms'][MANAGER]['power_state']
        self.assertEqual(m.reconcile(api,system,policy,False)['operations'],['restore_guest_lifecycle']);self.assertEqual(api.writes,[])
        self.assertTrue(m.reconcile(api,system,policy,True)['changed']);self.assertEqual(api.data['vms'][MANAGER]['power_state'],before)
        self.assertEqual(api.data['vms'][MANAGER]['actions_after_shutdown'],'destroy');self.assertFalse(m.reconcile(api,system,policy,True)['changed'])
    def test_lifecycle_cannot_target_unapproved_guest_or_request_dumps_or_shutdown_loop(self):
        for kind in ('unapproved','dump','shutdown_restart'):
            policy,api,system=self.lifecycle_case()
            if kind=='unapproved':policy['guest_lifecycle'][HOST]=policy['guest_lifecycle'].pop(MANAGER)
            elif kind=='dump':policy['guest_lifecycle'][MANAGER]['actions_after_crash']='coredump_and_restart'
            else:policy['guest_lifecycle'][MANAGER]['actions_after_shutdown']='restart'
            with self.assertRaises(ValueError):m.reconcile(api,system,policy,True)
            self.assertEqual(api.writes,[]);self.assertEqual(system.calls,[])
    def multiple(self):
        policy=copy.deepcopy(POLICY)
        extra='00000000-0000-4000-8000-000000000099'
        policy['automatic_vm_ids']=[extra,MANAGER]
        policy['management_vm_id']=MANAGER
        api=FakeAPI();api.data['vms'][extra]={'name':'selected application','auto_poweron':'true','power_state':'Running'}
        return policy,api,extra
    def test_exact_multiple_automatic_guests_are_supported(self):
        policy,api,extra=self.multiple();system=FakeSystem()
        result=m.reconcile(api,system,policy,True)
        self.assertEqual(result['after']['api']['vms'][extra]['power_state'],'Running')
        self.assertEqual(result['after']['api']['vms']['other']['power_state'],'Halted')
    def test_multiple_policy_requires_explicit_manager_and_unique_selection(self):
        for kind in ('missing_manager','outside_manager','duplicate'):
            policy,api,extra=self.multiple()
            if kind=='missing_manager':policy.pop('management_vm_id')
            elif kind=='outside_manager':policy['management_vm_id']=HOST
            else:policy['automatic_vm_ids'].append(extra)
            with self.assertRaises(ValueError):m.reconcile(api,FakeSystem(),policy,True)
            self.assertEqual(api.writes,[])
    def test_active_unit_refuses_any_selected_halted_guest_before_writes(self):
        policy,api,extra=self.multiple();api.data['vms'][extra]['power_state']='Halted'
        system=FakeSystem();system.data.update(runtime_mask=False,active=True,active_state='active')
        with self.assertRaisesRegex(ValueError,'automatic guest is halted'):m.reconcile(api,system,policy,True)
        self.assertEqual(system.calls,[]);self.assertEqual(api.writes,[])
    def test_start_checks_every_selected_guest(self):
        policy,api,extra=self.multiple();api.data['vms'][extra]['power_state']='Halted'
        with self.assertRaisesRegex(ValueError,'every approved automatic guest'):m.reconcile(api,FakeSystem(),policy,True)

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
