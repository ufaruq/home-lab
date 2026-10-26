#!/usr/bin/env python3
"""Run inside a disposable root Linux Docker container only, never on the controller."""
import json
import os
import pathlib
import platform
import re
import subprocess

if platform.system() != 'Linux' or not pathlib.Path('/.dockerenv').exists() or os.geteuid() != 0:
    raise SystemExit('Refusing: fixture requires a disposable root Linux Docker container')

inventory = {'all': {'children': {'guests': {'children': {'linux_guests': {'hosts': {
    'fixture': {'ansible_connection':'local', 'ansible_host':'127.0.0.1','ansible_user':'root',
                'ansible_python_interpreter':'/usr/bin/python3', 'guest_access_verified':True,
                'guest_configuration_verified':True, 'guest_desired_state_declared':True,
                'guest_desired_groups':[{'name':'hl_fixture','gid':50001}],
                'guest_desired_users':[{'name':'hl_fixture','uid':50001,'group':'hl_fixture','groups':[],
                                       'shell':'/bin/sh','home':'/nonexistent','create_home':False}],
                'guest_desired_packages':[], 'guest_desired_services':[]}}}}}}}}
pathlib.Path('/tmp/fixture-inventory.json').write_text(json.dumps(inventory))
env = dict(os.environ, ANSIBLE_HOME='/tmp/ansible-home', ANSIBLE_CONFIG='/work/ansible/ansible.cfg',
           PYTHONPATH='/tmp/ansible')
command = ['/tmp/ansible/bin/ansible-playbook', '-i', '/tmp/fixture-inventory.json',
           '/work/ansible/playbooks/converge-guests.yml', '--limit', 'fixture',
           '-e', '{"guest_targets":["fixture"]}']
changes = []
for attempt in range(2):
    result = subprocess.run(command, env=env, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, result.stderr)
        raise SystemExit(result.returncode)
    recap = re.search(r'fixture\s*:\s*ok=\d+\s+changed=(\d+)', result.stdout)
    if not recap or 'declared managed settings verified' not in result.stdout:
        print(result.stdout, result.stderr)
        raise SystemExit('Fixture did not prove convergence verification')
    changes.append(int(recap.group(1)))
assert changes[0] > 0 and changes[1] == 0, changes
print('Real container user/group convergence verified: first_changed=%s second_changed=%s' % tuple(changes))
