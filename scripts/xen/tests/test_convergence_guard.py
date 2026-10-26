import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_plan_guard import fixture, VM, NETWORK, SR, VM_ADDRESS, NETWORK_ADDRESS

NEW_ID = '00000000-0000-0000-0000-000000000099'
TEMPLATE = '00000000-0000-0000-0000-000000000088'


def setup_case():
    inventory, plan = fixture()
    inventory['vms'][VM].update(name_label='server', VCPUs_at_startup='2', memory_dynamic_min='1024', memory_dynamic_max='2048', power_state='Halted')
    inventory['vms'][VM]['disks'][0].update(userdevice='0', currently_attached=False)
    inventory['vms'][VM]['disks'][0]['vdi'].update(uuid='disk-original', virtual_size='8192', name_description='')
    inventory['vms'][VM]['vifs'] = [{'device':'0','MAC':'aa:bb:cc:dd:ee:ff','network_uuid':NETWORK,'currently_attached':False}]
    inventory['networks'][NETWORK].update(name_label='isolated', name_description='', MTU='1500', pif_uuids=[], other_config={})
    values={'id':VM,'cpus':2,'memory_min':1024,'memory_max':2048,'power_state':'Halted','name_label':'server','template':TEMPLATE,'disk':[{'name_label':'root','name_description':'','sr_id':SR,'size':8192,'attached':False,'vdi_id':'disk-original','vbd_id':'vbd-original','position':'0'}],'network':[{'network_id':NETWORK,'mac_address':'aa:bb:cc:dd:ee:ff','attached':False,'device':'0'}]}
    for item in plan['resource_changes']:
        value=values if item['address']==VM_ADDRESS else {'id':NETWORK,'name_label':'isolated','mtu':1500,'source_pif_device':None,'vlan':None}
        item['change'].update(before=copy.deepcopy(value),after=copy.deepcopy(value))
    for item in plan['planned_values']['root_module']['resources']:
        item['values']=copy.deepcopy(next(c['change']['after'] for c in plan['resource_changes'] if c['address']==item['address']))
    policy={'schema_version':1,'vms':{},'networks':{},'guest_targets':[]}
    bindings={'schema_version':1,'existing_vm_ids':{VM:VM},'existing_network_ids':{NETWORK:NETWORK},'available_template_ids':[TEMPLATE]}
    return inventory,plan,policy,bindings


class ConvergenceGuardTests(unittest.TestCase):
    def verify(self, case):
        file=ROOT/'convergence_guard.py'
        if not file.exists():self.fail('Convergence verification is not implemented')
        spec=importlib.util.spec_from_file_location('convergence_guard',file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        inventory,plan,policy,bindings=case
        return m.verify(plan,inventory,policy,bindings)

    def sync(self,case):
        for item in case[1]['planned_values']['root_module']['resources']:
            item['values']=copy.deepcopy(next(c['change']['after'] for c in case[1]['resource_changes'] if c['address']==item['address']))

    def test_existing_imports_match_current_bindings(self):
        self.assertEqual(self.verify(setup_case()),2)

    def test_recovered_identity_is_used_for_next_import_and_noop(self):
        c=setup_case();c[3]['existing_vm_ids'][VM]=NEW_ID
        ch=c[1]['resource_changes'][0]['change']
        for key in ['before','after']:ch[key]['id']=NEW_ID
        ch['importing']['id']=NEW_ID;self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_policy_cpu_memory_update_is_allowed(self):
        c=setup_case();c[2]['vms'][VM]={'cpus':4,'memory_min':2048,'memory_max':4096};ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['after'].update(cpus=4,memory_min=2048,memory_max=4096);self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_explicit_auto_poweron_enable_requires_running_target(self):
        c=setup_case();c[0]['vms'][VM]['other_config']={'auto_poweron':'false'}
        c[2]['vms'][VM]={'auto_poweron':True,'power_state':'Running'}
        ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['before']['auto_poweron']=False;ch['after'].update(auto_poweron=True,power_state='Running');self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_explicit_auto_poweron_disable_is_allowed(self):
        c=setup_case();c[0]['vms'][VM]['other_config']={'auto_poweron':'true'};c[2]['vms'][VM]={'auto_poweron':False}
        ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['before']['auto_poweron']=True;ch['after']['auto_poweron']=False;self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_undeclared_auto_poweron_toggle_is_rejected(self):
        for baseline in [None,'false']:
            c=setup_case()
            if baseline is not None:c[0]['vms'][VM]['other_config']={'auto_poweron':baseline}
            ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['before']['auto_poweron']=False;ch['after']['auto_poweron']=True;self.sync(c)
            with self.subTest(baseline=baseline),self.assertRaises(ValueError):self.verify(c)

    def test_auto_poweron_without_observed_baseline_can_stay_unchanged(self):
        c=setup_case();ch=c[1]['resource_changes'][0]['change'];ch['before']['auto_poweron']=False;ch['after']['auto_poweron']=False;self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_auto_poweron_policy_rejects_non_booleans(self):
        for value in [0,1,'true','false',None]:
            c=setup_case();c[2]['vms'][VM]={'auto_poweron':value}
            with self.subTest(value=value),self.assertRaises(ValueError):self.verify(c)

    def test_auto_poweron_true_with_halted_target_is_rejected(self):
        c=setup_case();c[2]['vms'][VM]={'auto_poweron':True}
        with self.assertRaises(ValueError):self.verify(c)

    def test_undeclared_true_auto_poweron_cannot_fight_halted_target(self):
        c=setup_case();ch=c[1]['resource_changes'][0]['change'];ch['before']['auto_poweron']=True;ch['after']['auto_poweron']=True;self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def test_numeric_auto_poweron_plan_cannot_masquerade_as_false(self):
        c=setup_case();c[2]['vms'][VM]={'auto_poweron':False};ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['before']['auto_poweron']=True;ch['after']['auto_poweron']=0;self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def test_auto_poweron_baseline_is_preserved_during_other_update(self):
        c=setup_case();c[0]['vms'][VM]['other_config']={'auto_poweron':'false'};ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['before'].update(cpus=1,auto_poweron=False);ch['after']['auto_poweron']=False;self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_cpu_drift_can_return_to_observed_baseline(self):
        c=setup_case();ch=c[1]['resource_changes'][0]['change'];ch['before']['cpus']=1;ch['actions']=['update'];self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_explicit_start_can_attach_same_disks_and_nics(self):
        c=setup_case();c[2]['vms'][VM]={'power_state':'Running'};ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['after']['power_state']='Running'
        for key in ['disk','network']:ch['after'][key][0]['attached']=True
        self.sync(c);self.assertEqual(self.verify(c),2)

    def test_mutation_disguised_as_noop_is_rejected(self):
        c=setup_case();c[1]['resource_changes'][0]['change']['after']['disk'][0]['size']=4096;self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def test_unapproved_mutations_are_rejected(self):
        for field,value in [('name_label','changed'),('template',NEW_ID),('cpus',3),('power_state','Running'),('cloud_config','secret'),('unknown_setting',True)]:
            with self.subTest(field=field):
                c=setup_case();ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['after'][field]=value;self.sync(c)
                with self.assertRaises(ValueError):self.verify(c)

    def test_nested_mutations_and_detachment_are_rejected(self):
        for key,field,value in [('disk','vdi_id','another'),('disk','size',1),('network','mac_address','changed'),('network','network_id',NEW_ID),('disk','attached',False)]:
            with self.subTest(key=key,field=field):
                c=setup_case();ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update']
                if field=='attached':ch['before'][key][0]['attached']=True
                ch['after'][key][0][field]=value;self.sync(c)
                with self.assertRaises(ValueError):self.verify(c)

    def test_unrequested_attachment_is_rejected(self):
        c=setup_case();ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['after']['network'][0]['attached']=True;self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def test_unsafe_actions_are_rejected(self):
        for actions in [['delete'],['delete','create'],['create','delete'],['forget']]:
            with self.subTest(actions=actions):
                c=setup_case();c[1]['resource_changes'][0]['change']['actions']=actions
                with self.assertRaises(ValueError):self.verify(c)

    def test_unknown_configured_values_are_rejected(self):
        c=setup_case();c[1]['resource_changes'][0]['change']['after_unknown']={'disk':[{'size':True}]}
        with self.assertRaises(ValueError):self.verify(c)

    def test_computed_address_unknowns_do_not_block_safe_update(self):
        c=setup_case();ch=c[1]['resource_changes'][0]['change'];ch['actions']=['update'];ch['before']['cpus']=1;ch['after_unknown']={'ipv4_addresses':True,'network':[{'ipv6_addresses':True}]}
        self.assertEqual(self.verify(c),2)

    def test_wrong_binding_or_import_is_rejected(self):
        for patch in ['binding','import','after']:
            c=setup_case();ch=c[1]['resource_changes'][0]['change']
            if patch=='binding':c[3]['existing_vm_ids'][VM]=NEW_ID
            elif patch=='import':ch['importing']['id']=NEW_ID
            else:ch['after']['id']=NEW_ID;self.sync(c)
            with self.subTest(patch=patch),self.assertRaises(ValueError):self.verify(c)

    def test_missing_coverage_or_external_resource_is_rejected(self):
        for patch in ['coverage','foreign','duplicate','missing_change']:
            c=setup_case()
            if patch=='coverage':del c[1]['planned_values']['outputs']['adoption_targets']['value'][VM_ADDRESS]
            elif patch=='foreign':c[1]['resource_changes'].append({'address':'oci_core_instance.billable','change':{'actions':['create']}})
            elif patch=='duplicate':c[1]['resource_changes'].append(copy.deepcopy(c[1]['resource_changes'][0]))
            else:c[1]['resource_changes'].pop()
            with self.subTest(patch=patch),self.assertRaises(ValueError):self.verify(c)

    def test_network_updates_are_rejected(self):
        c=setup_case();ch=c[1]['resource_changes'][1]['change'];ch['actions']=['update'];ch['after']['mtu']=9000;self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def recovery(self):
        c=setup_case();del c[3]['existing_vm_ids'][VM];c[2]['vms'][VM]={'recovery':{'template_id':TEMPLATE,'verified':True}}
        ch=c[1]['resource_changes'][0]['change'];ch.update(actions=['create'],before=None,after_unknown={'id':True});ch.pop('importing');ch['after']['id']=None
        for key in ['vdi_id','vbd_id','position']:ch['after']['disk'][0].pop(key)
        ch['after']['network'][0].pop('device');self.sync(c);return c

    def test_verified_missing_vm_can_be_recovered(self):
        self.assertEqual(self.verify(self.recovery()),2)

    def test_vm_recovery_rejects_missing_or_unavailable_recipe(self):
        for patch in ['unverified','unavailable','wrong_template','already_exists','known_id','import','raw','cloudconfig','disk_change','running']:
            c=self.recovery();ch=c[1]['resource_changes'][0]['change']
            if patch=='unverified':c[2]['vms'][VM]['recovery']['verified']=False
            elif patch=='unavailable':c[3]['available_template_ids']=[]
            elif patch=='wrong_template':ch['after']['template']=NEW_ID
            elif patch=='already_exists':c[3]['existing_vm_ids'][VM]=VM
            elif patch=='known_id':ch['after']['id']=VM
            elif patch=='import':ch['importing']={'id':VM}
            elif patch=='raw':c[0]['storage_repositories'][SR]['type']='udev'
            elif patch=='cloudconfig':ch['after']['cloud_config']='anything'
            elif patch=='disk_change':ch['after']['disk'][0]['size']=1
            else:ch['after']['power_state']='Running'
            self.sync(c)
            with self.subTest(patch=patch),self.assertRaises(ValueError):self.verify(c)

    def test_vm_recovery_rejects_unrestorable_passthrough_devices(self):
        for field in ['attached_pci_uuids', 'vgpu_uuids', 'vusb_uuids', 'other_config.pci']:
            c=self.recovery()
            if field=='other_config.pci':c[0]['vms'][VM]['other_config']={'pci':'0/0000:01:00.0'}
            else:c[0]['vms'][VM][field]=['device-identity']
            with self.subTest(field=field),self.assertRaises(ValueError):self.verify(c)

    def test_missing_isolated_network_can_be_created(self):
        c=setup_case();del c[3]['existing_network_ids'][NETWORK];ch=c[1]['resource_changes'][1]['change'];ch.update(actions=['create'],before=None,after_unknown={'id':True});ch.pop('importing');ch['after']['id']=None;self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_generated_isolated_vlan_zero_and_guest_alias_are_allowed(self):
        c=setup_case();c[2]['guest_targets']=['maps'];del c[3]['existing_network_ids'][NETWORK]
        ch=c[1]['resource_changes'][1]['change'];ch.update(actions=['create'],before=None,after_unknown={'id':True});ch.pop('importing');ch['after'].update(id=None,vlan=0,source_pif_device='');self.sync(c)
        self.assertEqual(self.verify(c),2)

    def test_new_network_cannot_enable_unobserved_nbd(self):
        c=setup_case();del c[3]['existing_network_ids'][NETWORK];ch=c[1]['resource_changes'][1]['change'];ch.update(actions=['create'],before=None,after_unknown={'id':True});ch.pop('importing');ch['after'].update(id=None,nbd=True);self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def test_creation_with_unknown_provider_setting_is_rejected(self):
        c=self.recovery();c[1]['resource_changes'][0]['change']['after']['new_dangerous_option']=True;self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def test_network_creation_requires_pif_inventory_evidence(self):
        c=setup_case();c[0]['networks'][NETWORK].pop('pif_uuids');del c[3]['existing_network_ids'][NETWORK]
        ch=c[1]['resource_changes'][1]['change'];ch.update(actions=['create'],before=None,after_unknown={'id':True});ch.pop('importing');ch['after']['id']=None;self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def test_pif_backed_network_cannot_be_recreated(self):
        c=setup_case();del c[3]['existing_network_ids'][NETWORK];c[0]['networks'][NETWORK]['pif_uuids']=['pif'];ch=c[1]['resource_changes'][1]['change'];ch.update(actions=['create'],before=None);ch.pop('importing');ch['after']['id']=None;self.sync(c)
        with self.assertRaises(ValueError):self.verify(c)

    def test_invalid_memory_or_unknown_policy_is_rejected(self):
        for settings in [{'memory_min':4096},{'cpus':False},{'cpus':0},{'mystery':1}]:
            c=setup_case();c[2]['vms'][VM]=settings
            with self.subTest(settings=settings),self.assertRaises(ValueError):self.verify(c)

    def test_read_only_xen_data_lookup_is_allowed(self):
        c=setup_case();c[1]['resource_changes'].append({'address':'data.xenorchestra_pool.pool','mode':'data','change':{'actions':['read']}})
        self.assertEqual(self.verify(c),2)

    def test_incomplete_plan_is_rejected(self):
        for patch in [{'complete':False},{'errored':True},{'deferred_changes':[{}]}]:
            c=setup_case();c[1].update(patch)
            with self.subTest(patch=patch),self.assertRaises(ValueError):self.verify(c)


if __name__=='__main__':unittest.main()
