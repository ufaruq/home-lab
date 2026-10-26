#!/usr/bin/env python3
"""Check real flock/timeout and exit propagation inside a disposable Linux Docker container only."""
import importlib.util
import os
import pathlib
import platform
import subprocess

if platform.system()!='Linux' or not pathlib.Path('/.dockerenv').exists() or os.geteuid()!=0:
    raise SystemExit('Refusing: requires disposable root Linux Docker container')
spec=importlib.util.spec_from_file_location('rotation',pathlib.Path(__file__).parents[1]/'log_rotation.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
pathlib.Path('/run/lock').mkdir(parents=True,exist_ok=True)
pathlib.Path('/tmp/reviewed-wrapper').write_text(m.WRAPPER)
pathlib.Path('/usr/sbin/logrotate').write_text('''#!/bin/sh
printf '%s\\n' "$@" >> /tmp/rotation-args
if ! mkdir /tmp/rotation-critical-section 2>/dev/null; then exit 88; fi
trap 'rmdir /tmp/rotation-critical-section' EXIT
sleep 0.2
exit "${FIXTURE_EXIT:-0}"
''')
pathlib.Path('/usr/sbin/logrotate').chmod(0o755)
for code in (0,23):
    result=subprocess.run(['/bin/sh','/tmp/reviewed-wrapper'],env=dict(os.environ,FIXTURE_EXIT=str(code)))
    assert result.returncode==code,(code,result.returncode)
first=subprocess.Popen(['/bin/sh','/tmp/reviewed-wrapper'])
second=subprocess.Popen(['/bin/sh','/tmp/reviewed-wrapper'])
assert first.wait()==0 and second.wait()==0,'shared lock failed'
arguments=pathlib.Path('/tmp/rotation-args').read_text().splitlines()
assert arguments==['-s','/var/lib/logrotate/logrotate.status','/etc/logrotate.conf']*4,arguments
print('Runtime fixture passed: normal args; success=0; runtime error=23 propagated; concurrent checks serialized')
