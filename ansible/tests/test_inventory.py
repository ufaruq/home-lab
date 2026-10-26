"""Exercise explicitly supplied, wholly invented inventory and offline evidence."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=ROOT/'tests/fixtures/xen'
sys.path.insert(0,str(ROOT/'ansible/files'))
from generate_inventory import generate
from integrate_offline import integrate


def load(path):return json.loads(Path(path).read_text())


class InventoryTests(unittest.TestCase):
    def generate_fixture(self,output):
        generate(FIXTURE/'inventory.json',output,'example_control',load(FIXTURE/'recovery-policy.json'),load(FIXTURE/'network-profile.json'),FIXTURE/'guest-inventory')
    def test_synthetic_fleet_preserves_devices_and_no_access_is_granted(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp);self.generate_fixture(output)
            source=load(FIXTURE/'inventory.json')
            guests=[load(p) for p in (output/'host_vars').glob('*.yml') if p.stem!='example_control']
            self.assertEqual({v['vm_uuid'] for v in guests},set(source['vms']))
            for guest in guests:
                observed=source['vms'][guest['vm_uuid']]
                self.assertEqual(guest['xcp_observed']['disks'],observed['disks'])
                self.assertEqual(guest['xcp_observed']['vifs'],observed['vifs'])
                self.assertNotIn('ansible_host',guest)
                self.assertFalse(guest.get('guest_access_verified',False))
                self.assertFalse(guest.get('guest_desired_state_declared',False))
                self.assertTrue(guest['discovery_gaps'])
            control=load(output/'host_vars/example_control.yml')
            self.assertEqual(len(control['xcp_native_definitions']),1)
            self.assertEqual(control['xcp_native_definitions'][0]['disks'],[])
            self.assertEqual(control['native_recovery_policy']['automatic_vm_ids'],['00000000-0000-4000-8000-000000000001'])
    def test_explicit_evidence_produces_pinned_baseline_with_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp);self.generate_fixture(output)
            guest=load(output/'host_vars/example_linux.yml')
            self.assertTrue(guest['offline_capture']['linux_baseline_available'])
            path=ROOT/guest['offline_capture']['manifest']
            self.assertEqual(guest['offline_capture']['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(guest['guest_desired_packages'],['example-tool=1.0'])
            self.assertEqual([u['name'] for u in guest['guest_desired_users']],['root','example_user'])
            self.assertEqual(guest['guest_desired_services'],[{'name':'example.service','enabled':True}])
            coverage=load(output/'guest-coverage.json')
            self.assertEqual(coverage['captured_vm_count'],4)
            self.assertEqual(coverage['blocked_vm_count'],3)
    def test_bsd_stays_observed_only_and_detects_same_network_address_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp);self.generate_fixture(output)
            guest=load(output/'host_vars/example_bsd.yml')
            self.assertEqual(guest['guest_observed_os']['type'],'freebsd')
            self.assertEqual(guest['guest_desired_packages'],[])
            self.assertFalse(guest['offline_capture']['linux_baseline_available'])
            self.assertEqual(guest['guest_network_conflicts'][0]['address'],'198.51.100.1')
            self.assertEqual(guest['guest_network_conflicts'][0]['vlan'],'42')
            groups=load(output/'hosts.yml')['all']['children']
            self.assertIn('example_bsd',groups['bsd_guests']['hosts'])
            self.assertNotIn('example_bsd',groups['linux_guests']['hosts'])
    def test_different_network_same_address_does_not_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'out';self.generate_fixture(output)
            source=load(FIXTURE/'inventory.json')
            for pif in source['pifs'].values():
                if pif.get('IP')=='198.51.100.1':pif['network_uuid']='10000000-0000-4000-8000-000000000002'
            path=Path(temp)/'source.json';path.write_text(json.dumps(source))
            integrate(path,FIXTURE/'guest-inventory',output)
            self.assertEqual(load(output/'host_vars/example_bsd.yml')['guest_network_conflicts'],[])
    def test_windows_has_no_invented_unix_login(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp);self.generate_fixture(output)
            for alias in ['example_legacy_desktop','example_uefi_desktop']:
                self.assertNotIn('ansible_user',load(output/'host_vars'/(alias+'.yml')))
    def test_cli_requires_explicit_input_and_output(self):
        result=subprocess.run([sys.executable,str(ROOT/'ansible/files/generate_inventory.py')],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('--inventory',result.stderr)
        self.assertIn('--output',result.stderr)
    def test_private_inline_policy_overrides_generated_access_defaults(self):
        executable=os.environ.get('ANSIBLE_INVENTORY_BIN') or shutil.which('ansible-inventory')
        if not executable:self.skipTest('Set ANSIBLE_INVENTORY_BIN for effective inventory validation')
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'out';self.generate_fixture(output)
            private=Path(temp)/'private.json';private.write_text(json.dumps({'all':{'hosts':{'example_linux':{'ansible_host':'203.0.113.90','ansible_user':'example_operator','guest_access_verified':True,'guest_configuration_verified':True,'guest_desired_state_declared':True}}}}))
            private.chmod(0o600)
            env=dict(os.environ,ANSIBLE_CONFIG=str(ROOT/'ansible/ansible.cfg'),ANSIBLE_HOME=str(Path(temp)/'ansible-home'))
            result=subprocess.run([executable,'-i',str(output/'hosts.yml'),'-i',str(private),'--host','example_linux'],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            actual=json.loads(result.stdout)
            self.assertEqual(actual['ansible_host'],'203.0.113.90')
            self.assertEqual(actual['ansible_user'],'example_operator')
            self.assertIs(actual['guest_access_verified'],True)

if __name__=='__main__':unittest.main()
