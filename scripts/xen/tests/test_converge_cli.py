"""Exercise the actual CLI and guards; external systems are disposable executables."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_convergence_guard import setup_case

SCRIPT = Path(__file__).resolve().parents[1] / 'lab.py'


class ConvergenceCLITests(unittest.TestCase):
    def exercise(self, unsafe=False):
        inventory, plan, policy, bindings = setup_case()
        if unsafe:
            plan['resource_changes'][0]['change']['actions'] = ['delete', 'create']
        live = {'vms': {k: {'name_label': v.get('name_label', k)} for k,v in inventory['vms'].items()},
                'networks': {k: {} for k in inventory['networks']},
                'templates': {key: {} for key in bindings['available_template_ids']}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = {'inventory': inventory, 'policy': policy, 'live': live, 'plan': plan}
            for name, value in sources.items():
                (root / (name + '.json')).write_text(json.dumps(value))
            program = root / 'external'
            program.write_text('#!' + sys.executable + '''
import json, os, pathlib, sys
root=pathlib.Path(os.environ['TEST_ROOT'])
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with (root/'calls.jsonl').open('a') as out: out.write(json.dumps([name,args])+'\\n')
if name=='ssh': print((root/'live.json').read_text())
if name=='terraform':
    if 'plan' in args:
        output=next(a[5:] for a in args if a.startswith('-out='))
        pathlib.Path(output).write_text((root/'plan.json').read_text())
    if 'show' in args:
        print(pathlib.Path(args[-1]).read_text() if args[-1]!='-json' else '{}')
''')
            program.chmod(0o700)
            for name in ['terraform','ssh','ansible']:
                (root/name).symlink_to(program)
            pin=root/'known_hosts';pin.write_text('example_control ssh-ed25519 synthetic-fixture\n');pin.chmod(0o600)
            fixture=SCRIPT.parents[2]/'tests/fixtures/xen'
            hostvars=json.loads((fixture/'ansible/host_vars/example_control.yml').read_text())
            management=next(iter(inventory['vms']))
            inventory['vms'][management]['name_label']='example-management'
            (root/'inventory.json').write_text(json.dumps(inventory))
            hostvars['native_recovery_policy']['automatic_vm_ids']=[management]
            (root/'host-vars.json').write_text(json.dumps(hostvars))
            env = dict(os.environ, XEN_ANSIBLE_INVENTORY=str(fixture/'ansible/hosts.yml'),XEN_HOST_VARS_FILE=str(root/'host-vars.json'),XEN_HOST=hostvars['ansible_user']+'@'+hostvars['ansible_host'],XEN_SSH_HOST_ALIAS='example_control',XEN_KNOWN_HOSTS_FILE=str(pin), TEST_ROOT=str(root), TERRAFORM_BIN=str(root/'terraform'),
                       XEN_SSH_BIN=str(root/'ssh'), ANSIBLE_PLAYBOOK_BIN=str(root/'ansible'),
                       XEN_RUN_DIR=str(root/'run'), XOA_URL='wss://xo.test', XOA_TOKEN='test-only')
            env.pop('XEN_PRIVATE_VARS', None)
            env.pop('XEN_PRIVATE_INVENTORY', None)
            result=subprocess.run([sys.executable, str(SCRIPT), '--inventory', str(root/'inventory.json'),
                                   '--policy', str(root/'policy.json'), 'converge'],
                                  env=env,text=True,capture_output=True)
            calls=[json.loads(line) for line in (root/'calls.jsonl').read_text().splitlines()]
            return result,calls

    def test_actual_cli_discovers_imports_checks_and_applies_exact_plan(self):
        result,calls=self.exercise()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(any(name=='ssh' for name,_ in calls))
        applies=[args for name,args in calls if name=='terraform' and 'apply' in args]
        self.assertEqual(len(applies),1)
        self.assertTrue(applies[0][-1].endswith('/convergence.tfplan'))
        self.assertTrue(any(name=='ansible' and any('xcp-definitions.yml' in arg for arg in args) for name,args in calls))

    def test_actual_cli_replacement_rejected_before_apply_or_ansible(self):
        result,calls=self.exercise(unsafe=True)
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertFalse(any(name=='ansible' or (name=='terraform' and 'apply' in args) for name,args in calls))


if __name__ == '__main__': unittest.main()
