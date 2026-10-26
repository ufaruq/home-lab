#!/usr/bin/env python3
"""Exercise the real guest_state identity guard in disposable root Linux Docker only."""
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import uuid

if platform.system()!='Linux' or not pathlib.Path('/.dockerenv').exists() or os.geteuid()!=0:
    raise SystemExit('Refusing: requires disposable root Linux Docker container')

play=pathlib.Path('/tmp/guest-target-guard-play.yml')
play.write_text('''---
- hosts: linux_guests
  gather_facts: false
  roles:
    - guest_state
''')
env=dict(os.environ,ANSIBLE_HOME='/tmp/ansible-home',ANSIBLE_CONFIG='/work/ansible/ansible.cfg',PYTHONPATH='/tmp/ansible')

def fingerprint():
    return {p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in ['/etc/passwd','/etc/group','/etc/shadow','/tmp/guest-guard-marker']}

pathlib.Path('/tmp/guest-guard-marker').write_text('must remain unchanged\n')
for label,uname_output,expected in [('linux','Linux',0),('darwin','Darwin',2),('control_domain','Linux\ncontrol_d',2)]:
    name='hl_guard_'+uuid.uuid4().hex[:8]
    policy={'ansible_connection':'local','ansible_host':'127.0.0.1','ansible_user':'root',
            'ansible_python_interpreter':'/usr/bin/python3','guest_access_verified':True,
            'guest_configuration_verified':True,'guest_desired_state_declared':True,
            'guest_desired_groups':[{'name':name}],
            'guest_desired_users':[{'name':name,'group':name,'groups':[],'home':'/nonexistent','shell':'/bin/sh','create_home':False}],
            'guest_desired_packages':[],'guest_desired_services':[]}
    inventory=pathlib.Path('/tmp/guest-target-guard-inventory.json')
    inventory.write_text(json.dumps({'all':{'children':{'linux_guests':{'hosts':{'fixture':policy}}}}}))
    fake=pathlib.Path('/tmp/guest-target-guard-bin');fake.mkdir(exist_ok=True)
    (fake/'uname').write_text('#!/bin/sh\nprintf \'%s\\n\' '+"'"+uname_output+"'"+'\n')
    (fake/'uname').chmod(0o755)
    run_env=dict(env,PATH=str(fake)+':'+os.environ.get('PATH','/usr/bin:/bin'))
    before=fingerprint()
    result=subprocess.run(['/tmp/ansible/bin/ansible-playbook','-i',str(inventory),str(play)],env=run_env,text=True,capture_output=True)
    if result.returncode!=expected:
        print(result.stdout,result.stderr)
        raise SystemExit('%s: expected rc=%s got=%s'%(label,expected,result.returncode))
    if expected:
        if 'target must be Linux and must not be a Xen control domain' not in result.stdout:
            print(result.stdout,result.stderr);raise SystemExit('Failure was not the expected target guard')
        assert fingerprint()==before,'Rejected target changed account files or marker'
    else:
        assert name in pathlib.Path('/etc/passwd').read_text(),'Normal Linux target did not converge'
    print('%s: expected rc=%s, identity guard verified%s'%(label,expected,', account/marker hashes unchanged' if expected else ''))
