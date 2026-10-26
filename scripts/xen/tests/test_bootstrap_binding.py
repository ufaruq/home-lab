"""Execute bootstrap's generated native code against an in-memory XenAPI only."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import lab

FIXTURE=Path(__file__).resolve().parents[3]/'tests/fixtures/xen'
SNAPSHOT=json.loads((FIXTURE/'inventory.json').read_text())
BOOT_POLICY=json.loads((FIXTURE/'recovery-policy.json').read_text())
ORIGINAL=BOOT_POLICY['automatic_vm_ids'][0]
RESTORED=next(iter(SNAPSHOT['templates']))
HOST=next(iter(SNAPSHOT['hosts']))
POOL=next(iter(SNAPSHOT['pools']))
SR=next(key for key,value in SNAPSHOT['storage_repositories'].items() if value['type']=='ext')
MANAGER_NAME=SNAPSHOT['vms'][ORIGINAL]['name_label']
ADDRESS='xenorchestra_vm.existing["'+ORIGINAL+'"]'


def record(identity):
    return {'uuid':identity,'name_label':MANAGER_NAME,'power_state':'Halted',
            'is_a_template':False,'is_a_snapshot':False,'is_control_domain':False}


class FakeAPI:
    def __init__(self,ids):
        self.records={key:record(key) for key in ids};self.starts=[]
        self.host_ids=[HOST];self.pool_ids=[POOL]
        self.host=types.SimpleNamespace(get_all_records=lambda:{key:{'uuid':key} for key in self.host_ids})
        self.pool=types.SimpleNamespace(get_all_records=lambda:{key:{'uuid':key} for key in self.pool_ids})
        self.VM=self;self.session=types.SimpleNamespace(logout=lambda:None)
    def login_with_password(self,*args):pass
    def get_all_records(self):return copy.deepcopy(self.records)
    def get_by_uuid(self,key):
        if key not in self.records:raise RuntimeError('missing VM '+key)
        return key
    def get_record(self,key):return copy.deepcopy(self.records[key])
    def get_power_state(self,key):return self.records[key]['power_state']
    def start(self,key,*args):self.starts.append(key);self.records[key]['power_state']='Running'


class BootstrapBindingTests(unittest.TestCase):
    def setUp(self):
        self.inventory={'schema_version':1,'hosts':{HOST:{}},'pools':{POOL:{}},'networks':{},
                        'storage_repositories':{SR:{'type':'ext'}},
                        'vms':{ORIGINAL:{'uuid':ORIGINAL,'name_label':MANAGER_NAME,'disks':[{'vdi':{'name_label':'root','sr_uuid':SR}}]}}}
        self.policy={'vms':{ORIGINAL:{'power_state':'Running'}}}
    def state(self,current):return {'values':{'root_module':{'resources':[{'address':ADDRESS,'mode':'managed','values':{'id':current}}]}}}
    def bootstrap(self,api,state):
        def remote(source):
            fake=types.SimpleNamespace(xapi_local=lambda:types.SimpleNamespace(xenapi=api))
            output=io.StringIO()
            with patch.dict(sys.modules,{'XenAPI':fake}),contextlib.redirect_stdout(output):
                exec(compile(source,'<offline-bootstrap>','exec'),{})
            return json.loads(output.getvalue())
        with patch.object(lab,'remote_json',side_effect=remote),patch.object(lab,'control_host_vars',return_value={'native_recovery_policy':BOOT_POLICY}):
            return lab.bootstrap_management(self.inventory,self.policy,state)
    def test_restored_xoa_uses_managed_current_uuid(self):
        api=FakeAPI([RESTORED]);self.bootstrap(api,self.state(RESTORED))
        self.assertEqual(api.starts,[RESTORED])
    def test_initial_bootstrap_without_state_uses_original_uuid(self):
        api=FakeAPI([ORIGINAL]);self.bootstrap(api,{})
        self.assertEqual(api.starts,[ORIGINAL])
    def test_wrong_host_and_pool_refused_before_start(self):
        for kind in ['host_ids','pool_ids']:
            with self.subTest(kind=kind):
                api=FakeAPI([RESTORED]);setattr(api,kind,['wrong'])
                with self.assertRaisesRegex(RuntimeError,'host|pool|identity'):self.bootstrap(api,self.state(RESTORED))
                self.assertEqual(api.starts,[])
    def test_original_and_recovered_ids_are_ambiguous(self):
        api=FakeAPI([ORIGINAL,RESTORED])
        with self.assertRaisesRegex(RuntimeError,'ambiguous|Ambiguous'):self.bootstrap(api,self.state(RESTORED))
        self.assertEqual(api.starts,[])
    def test_untracked_same_name_and_wrong_vm_type_refused(self):
        for kind in ['same_name','is_a_template','is_a_snapshot','is_control_domain','wrong_name']:
            with self.subTest(kind=kind):
                api=FakeAPI([RESTORED])
                if kind=='same_name':api.records['untracked']=record('untracked')
                elif kind=='wrong_name':api.records[RESTORED]['name_label']='other'
                else:api.records[RESTORED][kind]=True
                with self.assertRaises(RuntimeError):self.bootstrap(api,self.state(RESTORED))
                self.assertEqual(api.starts,[])
    def test_stale_state_never_falls_back_to_starting_original(self):
        api=FakeAPI([ORIGINAL])
        with self.assertRaisesRegex(RuntimeError,'missing|ambiguous'):self.bootstrap(api,self.state(RESTORED))
        self.assertEqual(api.starts,[])
    def test_duplicate_state_binding_refused_before_remote_call(self):
        state=self.state(RESTORED)
        state['values']['root_module']['resources']*=2
        with patch.object(lab,'remote_json') as remote,patch.object(lab,'control_host_vars',return_value={'native_recovery_policy':BOOT_POLICY}):
            with self.assertRaisesRegex(ValueError,'Ambiguous'):lab.bootstrap_management(self.inventory,self.policy,state)
            remote.assert_not_called()

    def test_already_running_restored_xoa_is_not_started_again(self):
        api=FakeAPI([RESTORED]);api.records[RESTORED]['power_state']='Running'
        self.bootstrap(api,self.state(RESTORED));self.assertEqual(api.starts,[])

if __name__=='__main__':unittest.main()
