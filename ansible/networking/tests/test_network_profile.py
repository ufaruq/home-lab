import copy
import importlib.util
import json
import hashlib
import stat
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import unittest
ROOT=Path(__file__).parents[1]
SPEC=importlib.util.spec_from_file_location('network_profile',ROOT/'network_profile.py')
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
FIXTURE=Path(__file__).resolve().parents[3]/'tests/fixtures/xen'
PROFILE=json.loads((FIXTURE/'network-profile.json').read_text())
RECOVERY=next(key for key,value in PROFILE['pifs'].items() if value['role']=='recovery')
UPLINK=next(key for key,value in PROFILE['pifs'].items() if value['role']=='uplink')
LEASE=json.loads((FIXTURE/'inventory.json').read_text())['pifs'][UPLINK]

class FakeAPI:
    def __init__(self):
        self.data={'host_uuids':[PROFILE['expected_host_uuid']],'pool_uuid':PROFILE['expected_pool_uuid'],'pifs':{}}
        for key,value in PROFILE['pifs'].items():
            self.data['pifs'][key]=dict(uuid=key,host_uuid=PROFILE['expected_host_uuid'],physical=True,currently_attached=True,MAC=value['mac'],network_uuid=value['network_uuid'],management=value['management'],ip_configuration_mode=value['mode'],IP=value.get('IP',LEASE['IP']),netmask=value.get('netmask',LEASE['netmask']),gateway=value.get('gateway',LEASE['gateway']),DNS=value.get('DNS',LEASE['DNS']),other_config=dict(value['other_config'],preserve='yes'))
        self.data['pifs'][RECOVERY]['ip_configuration_mode']='DHCP'
        self.data['pifs'][UPLINK]['other_config']['peerdns']='true'
        self.writes=[];self.fail_reconfigure=False
    def snapshot(self):return copy.deepcopy(self.data)
    def set_flags(self,key,flags):self.writes.append(('flags',key));self.data['pifs'][key]['other_config'].update(flags)
    def reconfigure(self,key,desired):
        self.writes.append(('reconfigure',key))
        if self.fail_reconfigure:raise ValueError('fixture reconfigure failure')
        record=self.data['pifs'][key];record['ip_configuration_mode']=desired['mode']
        if desired['mode']=='Static':
            for field in ['IP','netmask','gateway','DNS']:record[field]=desired[field]

class FakeSystem:
    def __init__(self):self.calls=[]
    def preflight(self,profile):pass
    def backup(self,stage,state,backup=None):self.calls.append(stage);return '/private-fixture'
    def start_guard(self):self.calls.append('guard');return 'fixture-guard'
    def restore_recovery(self):self.calls.append('restore')
    def stop_guard(self,unit):self.calls.append('stop_guard')

class NetworkTests(unittest.TestCase):
    def test_preflight_only_invokes_check_for_reviewed_script_supporting_it(self):
        for private_policy in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                script=Path(directory)/'recovery'
                body=b'#!/bin/sh\n'
                if private_policy:body+=b'# home-lab: private-recovery-policy-v1\n'
                script.write_bytes(body)
                profile=copy.deepcopy(PROFILE)
                profile['recovery_script_sha256']=hashlib.sha256(body).hexdigest()
                system=m.NativeSystem()
                with patch.object(m,'SCRIPT',str(script)), \
                        patch.object(m.os,'stat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o755,st_uid=0)), \
                        patch.object(m.os,'access',return_value=True), \
                        patch.object(system,'run') as run:
                    system.preflight(profile)
                    if private_policy:
                        run.assert_called_once_with([str(script),'--check','--expect-mac',PROFILE['pifs'][RECOVERY]['mac']],40)
                    else:run.assert_not_called()

    def test_check_is_readonly_apply_is_idempotent(self):
        api=FakeAPI();system=FakeSystem()
        self.assertTrue(m.reconcile(api,system,PROFILE,False)['changed'])
        self.assertEqual(api.writes,[]);self.assertEqual(system.calls,[])
        self.assertTrue(m.reconcile(api,system,PROFILE,True)['changed'])
        self.assertEqual(api.writes,[('flags',UPLINK),('reconfigure',UPLINK),('reconfigure',RECOVERY)])
        self.assertEqual(system.calls,['before','guard','restore','stop_guard','after'])
        self.assertEqual(api.data['pifs'][UPLINK]['other_config']['preserve'],'yes')
        writes=list(api.writes);calls=list(system.calls)
        self.assertFalse(m.reconcile(api,system,PROFILE,True)['changed'])
        self.assertEqual(api.writes,writes);self.assertEqual(system.calls,calls)
    def test_flag_change_refreshes_runtime_without_comparing_dhcp_lease(self):
        api=FakeAPI();system=FakeSystem();api.data['pifs'][RECOVERY]['ip_configuration_mode']='Static'
        m.reconcile(api,system,PROFILE,True)
        self.assertEqual(api.writes,[('flags',UPLINK),('reconfigure',UPLINK)])
        self.assertEqual(api.data['pifs'][UPLINK]['IP'],LEASE['IP'])
    def test_all_flags_precede_interface_reconfiguration(self):
        api=FakeAPI();system=FakeSystem();api.data['pifs'][RECOVERY]['other_config']['defaultroute']='true'
        m.reconcile(api,system,PROFILE,True)
        self.assertEqual(api.writes[:2],[('flags',UPLINK),('flags',RECOVERY)])
    def test_finally_restores_aliases_after_failed_reconfigure(self):
        api=FakeAPI();api.fail_reconfigure=True;system=FakeSystem()
        with self.assertRaises(ValueError):m.reconcile(api,system,PROFILE,True)
        self.assertEqual(system.calls,['before','guard','restore','stop_guard','after'])
    def test_identity_and_unreviewed_pif_fail_before_writes(self):
        for fault in ['host','mac','role','extra_default','profile_target']:
            api=FakeAPI();system=FakeSystem();policy=copy.deepcopy(PROFILE)
            if fault=='host':api.data['host_uuids']=['wrong']
            if fault=='mac':api.data['pifs'][UPLINK]['MAC']='wrong'
            if fault=='role':api.data['pifs'][RECOVERY]['management']=False
            if fault=='extra_default':api.data['pifs']['other']={'other_config':{'defaultroute':'true'}}
            if fault=='profile_target':policy['pifs']['other']=policy['pifs'].pop(UPLINK)
            with self.assertRaises(ValueError):m.reconcile(api,system,policy,True)
            self.assertEqual(api.writes,[]);self.assertEqual(system.calls,[])
    def test_public_result_does_not_expose_private_records(self):
        api=FakeAPI();system=FakeSystem();result=m.reconcile(api,system,PROFILE,True)
        self.assertNotIn('before',result);self.assertNotIn('after',result)
        self.assertNotIn('preserve',json.dumps(result))

if __name__=='__main__':unittest.main()
