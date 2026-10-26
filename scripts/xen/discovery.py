"""Read-only discovery and identity resolution before Terraform reconciliation."""

import base64
import json
import os
import re
import shlex
import subprocess

from plan_guard import expected_targets, resources


# Python 2-compatible: use the installed XenAPI bindings without installing Dom0 software.
REMOTE_QUERY = r'''
import json
import XenAPI
s = XenAPI.xapi_local()
s.xenapi.login_with_password('', '')
try:
    vms = {}
    templates = {}
    for ref, vm in s.xenapi.VM.get_all_records().items():
        if vm['is_control_domain'] or vm['is_a_snapshot']:
            continue
        entry = {'name_label': vm['name_label'], 'power_state': vm['power_state']}
        (templates if vm['is_a_template'] else vms)[vm['uuid']] = entry
    networks = dict((n['uuid'], {'name_label': n['name_label']}) for n in s.xenapi.network.get_all_records().values())
    print(json.dumps({'vms': vms, 'templates': templates, 'networks': networks,
                      'host_ids': [h['uuid'] for h in s.xenapi.host.get_all_records().values()],
                      'pool_ids': [p['uuid'] for p in s.xenapi.pool.get_all_records().values()]}))
finally:
    s.xenapi.session.logout()
'''


def remote_json(source):
    host = os.environ.get('XEN_HOST')
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9_.@:\[\]-]+', host) or host.startswith('-'):
        raise ValueError('XEN_HOST must be an SSH hostname, optionally with a username')
    binary = os.environ.get('XEN_SSH_BIN', 'ssh')
    command = [binary, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
               '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2']
    if os.environ.get('XEN_SSH_CONTROL'):
        command.extend(['-S', os.environ['XEN_SSH_CONTROL']])
    payload = base64.b64encode(source.encode()).decode()
    remote = "python -c " + shlex.quote("import base64; exec(compile(base64.b64decode(" + repr(payload) + "), '<discovery>', 'exec'))")
    result = subprocess.run(command + [host, remote], text=True, capture_output=True, check=True, timeout=45)
    return json.loads(result.stdout)


def query_live():
    return remote_json(REMOTE_QUERY)


def resolve_bindings(inventory, live, state):
    for section in ('vms', 'networks', 'templates'):
        if not isinstance(live.get(section), dict):
            raise ValueError('live discovery is incomplete: ' + section)
    for section, observed in [('host_ids', 'hosts'), ('pool_ids', 'pools')]:
        if observed in inventory and not set(inventory[observed]).issubset(set(live.get(section, []))):
            raise ValueError('live host/pool identity does not match the captured lab')
    state_ids = {r['address']: r.get('values', {}).get('id') for r in
                 resources(state.get('values', {}).get('root_module', {})) if r.get('mode', 'managed') == 'managed'}
    result = {'schema_version': 1, 'existing_vm_ids': {}, 'existing_network_ids': {},
              'available_template_ids': sorted(live['templates'])}
    for address, logical in expected_targets(inventory).items():
        kind = 'vms' if address.startswith('xenorchestra_vm.') else 'networks'
        previous = state_ids.get(address)
        current = previous or logical
        if current in live[kind]:
            if previous and previous != logical and logical in live[kind]:
                raise ValueError('ambiguous live identity for ' + logical)
            result['existing_vm_ids' if kind == 'vms' else 'existing_network_ids'][logical] = current
        elif previous and logical in live[kind]:
            raise ValueError('stale state identity conflicts with live original ' + logical)
        else:
            name = inventory[kind][logical].get('name_label')
            if name and any(value.get('name_label') == name for value in live[kind].values()):
                raise ValueError('untracked same-name resource blocks duplicate creation: ' + name)
    return result
