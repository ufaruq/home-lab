import copy
import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'xcp.py'

class XcpPlanTests(unittest.TestCase):
    def module(self):
        self.assertTrue(SOURCE.exists(), 'XCP Terraform controller is not implemented')
        spec = importlib.util.spec_from_file_location('xcp_controller', SOURCE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def plan(self):
        plan = {'resource_changes': [
            {'address':'grafana_dashboard.xcp_host','mode':'managed','type':'grafana_dashboard','provider_name':'registry.terraform.io/grafana/grafana','change':{'actions':['create'],'after':{'folder':'homelab-monitoring','config_json':json.dumps({'uid':'homelab-xcp-host'})}}},
            {'address':'terraform_data.collector','mode':'managed','type':'terraform_data','provider_name':'terraform.io/builtin/terraform','change':{'actions':['create'],'after':{'input':{'enabled':True,'host_name':'datacenter1'}}}},
        ]}
        plan['resource_changes'][1]['change']['after']['input']['vm_targets']=json.loads((SOURCE.parents[2]/'monitoring/xcp/vm-targets.json').read_text())['targets']
        return plan

    def test_exact_dashboard_and_host_deployment_are_allowed(self):
        self.module().guard_plan(self.plan())

    def test_cloud_resources_deletion_and_wrong_identity_are_rejected(self):
        module = self.module()
        for change in ('paid','delete','host','folder'):
            plan=copy.deepcopy(self.plan())
            if change=='paid': plan['resource_changes'][0]['type']='grafana_cloud_stack'
            if change=='delete': plan['resource_changes'][0]['change']['actions']=['delete']
            if change=='host': plan['resource_changes'][1]['change']['after']['input']['host_name']='wrong'
            if change=='folder': plan['resource_changes'][0]['change']['after']['folder']='another'
            with self.subTest(change=change), self.assertRaises(ValueError): module.guard_plan(plan)

    def test_failed_or_unknown_plan_checks_block_apply(self):
        module=self.module()
        for status in ('fail','unknown'):
            plan=self.plan();plan['checks']=[{'status':status}]
            with self.assertRaises(ValueError):module.guard_plan(plan)

    def test_vm_dashboard_has_an_exact_identity_and_selection_excludes_parrot(self):
        module=self.module();plan=self.plan()
        plan['resource_changes'][0]['address']='grafana_dashboard.xcp_vms'
        plan['resource_changes'][0]['change']['after']['config_json']=json.dumps({'uid':'homelab-xcp-vms'})
        plan['resource_changes'][1]['change']['after']['input']['vm_targets']=json.loads((SOURCE.parents[2]/'monitoring/xcp/vm-targets.json').read_text())['targets']
        module.guard_plan(plan)
        plan['resource_changes'][1]['change']['after']['input']['vm_targets'].append('parrot_htb')
        with self.assertRaises(ValueError):module.guard_plan(plan)

    def test_public_vm_policy_covers_every_inventory_vm_except_parrot(self):
        root=SOURCE.parents[2];policy=json.loads((root/'monitoring/xcp/vm-targets.json').read_text())
        inventory=json.loads((root/'tests/fixtures/monitoring/hosts.json').read_text())
        names=set()
        for name,group in inventory['all']['children'].items():
            if name!='xcp_control':names.update(group.get('hosts',{}))
        self.assertEqual(set(policy['targets']),names-{'parrot_htb'})
        self.assertEqual(policy['excluded'],['parrot_htb'])

    def test_private_vm_mapping_must_match_public_selection_and_inventory(self):
        module=self.module();root=SOURCE.parents[2]
        policy=json.loads((root/'monitoring/xcp/vm-targets.json').read_text())
        fleet=json.loads((root/'monitoring/fleet.json').read_text())['hosts']
        observed={name:{'vm_name':name} for name in policy['targets']}
        observed['parrot_htb']={'vm_name':'Parrot','vm_uuid':'excluded'}
        config={'vm_targets':[{'name':name,'expected_name':name,'role':fleet[name]['role'],'environment':fleet[name]['environment']} for name in policy['targets']],'excluded_vm_ids':['excluded']}
        module.validate_vm_policy(config,policy,fleet,observed)
        config['excluded_vm_ids']=[]
        with self.assertRaises(ValueError):module.validate_vm_policy(config,policy,fleet,observed)

if __name__ == '__main__': unittest.main()
