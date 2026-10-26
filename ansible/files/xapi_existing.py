#!/usr/bin/env python
"""Existing diskless VM definition reconciliation. Python 2.7/3; no guest/disk/power operations."""
from __future__ import print_function
import argparse
import base64
import copy
import json
import sys
import uuid as uuid_module

try:
    STRING_TYPES = (basestring,)
except NameError:
    STRING_TYPES = (str,)


def validate_allowlist(allowed):
    if not isinstance(allowed, dict) or not allowed:
        raise ValueError('An explicit nonempty private VM UUID/name allowlist is required')
    for identity, name in allowed.items():
        try:
            valid = (isinstance(identity, STRING_TYPES) and isinstance(name, STRING_TYPES)
                     and bool(name.strip()) and str(uuid_module.UUID(identity)) == identity)
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError('Private allowlist requires canonical VM UUIDs and nonempty names')
CPU = ('VCPUs_max', 'VCPUs_at_startup')
MEMORY = ('memory_static_min', 'memory_static_max', 'memory_dynamic_min', 'memory_dynamic_max')


def normalized(v):
    result = dict((k, str(v[k])) for k in CPU + MEMORY)
    result.update(uuid=v['uuid'], name_label=v['name_label'], power_state=v['power_state'],
                  disks=copy.deepcopy(v['disks']),
                  vifs=sorted([dict((k, x[k]) for k in ('uuid', 'device', 'MAC', 'network_uuid'))
                               for x in v['vifs']], key=lambda x: x['uuid']))
    return result


def reconcile(api, desired_vms, allowed_vms, apply=False):
    validate_allowlist(allowed_vms)
    result = {'changed': False, 'mode': 'apply' if apply else 'check', 'blocked': [], 'vms': []}
    prepared = []
    seen = set()
    for supplied in desired_vms:
        wanted = normalized(supplied)
        uuid = wanted['uuid']
        if uuid not in allowed_vms or uuid in seen or wanted['name_label'] != allowed_vms[uuid]:
            raise ValueError('Only exact allowlisted existing diskless VM identities are supported')
        seen.add(uuid)
        if wanted['power_state'] != 'Halted' or wanted['disks']:
            raise ValueError('Desired definition must remain Halted with zero disk attachments')
        maximum, startup = [int(wanted[k]) for k in CPU]
        smin, smax, dmin, dmax = [int(wanted[k]) for k in MEMORY]
        if not (0 < startup <= maximum and 0 <= smin <= dmin <= dmax <= smax):
            raise ValueError('Invalid CPU/memory bounds')
        observed = normalized(api.get_vm(uuid))
        diff = dict((k, {'before': observed[k], 'after': wanted[k]})
                    for k in wanted if observed[k] != wanted[k])
        blockers = []
        if observed['name_label'] != wanted['name_label']: blockers.append('VM name identity drift')
        if observed['power_state'] != 'Halted': blockers.append('VM is not halted; no power operations supported')
        if observed['disks']: blockers.append('Unexpected disk attachments; no disk operations supported')
        ov = dict((x['uuid'], x) for x in observed['vifs'])
        wv = dict((x['uuid'], x) for x in wanted['vifs'])
        if len(ov) != len(observed['vifs']) or len(wv) != len(wanted['vifs']) or set(ov) != set(wv):
            blockers.append('VIF create/delete/replacement is unsupported')
        else:
            for key in ov:
                if any(ov[key][f] != wv[key][f] for f in ('MAC', 'device')):
                    blockers.append('VIF MAC/device identity change is unsupported')
        result['blocked'].extend([uuid + ': ' + b for b in blockers])
        result['vms'].append({'uuid': uuid, 'name_label': wanted['name_label'], 'diff': diff, 'blocked': blockers})
        result['changed'] = result['changed'] or bool(diff)
        prepared.append((observed, wanted, diff))
    if apply and result['blocked']:
        raise ValueError('; '.join(result['blocked']))
    if apply:
        # Validate every VM before the first setter. No create/destroy, disk, start, stop, or reboot calls.
        for observed, wanted, diff in prepared:
            uuid = wanted['uuid']
            if any(k in diff for k in CPU): api.set_cpu(uuid, wanted[CPU[0]], wanted[CPU[1]])
            if any(k in diff for k in MEMORY): api.set_memory(uuid, dict((k, wanted[k]) for k in MEMORY))
            previous = dict((x['uuid'], x) for x in observed['vifs'])
            for vif in wanted['vifs']:
                if previous[vif['uuid']]['network_uuid'] != vif['network_uuid']:
                    api.move_vif(vif['uuid'], vif['network_uuid'])
    return result


class NativeAPI(object):
    def __init__(self, session): self.x = session.xenapi
    def get_vm(self, uuid):
        ref = self.x.VM.get_by_uuid(uuid)
        v = self.x.VM.get_record(ref)
        if any(v.get(flag, False) for flag in ('is_control_domain', 'is_a_template', 'is_a_snapshot')):
            raise ValueError('Control domains, templates and snapshots cannot be reconciled as diskless guests')
        result = dict((k, v[k]) for k in CPU + MEMORY + ('uuid', 'name_label', 'power_state'))
        result['disks'] = []
        for r in v['VBDs']:
            b = self.x.VBD.get_record(r)
            if b['type'] == 'Disk': result['disks'].append({'uuid': b['uuid']})
        result['vifs'] = []
        for r in v['VIFs']:
            f = self.x.VIF.get_record(r)
            result['vifs'].append(dict(uuid=f['uuid'], device=f['device'], MAC=f['MAC'],
                                      network_uuid=self.x.network.get_uuid(f['network'])))
        return result
    def set_cpu(self, uuid, maximum, startup):
        ref = self.x.VM.get_by_uuid(uuid)
        current = int(self.x.VM.get_VCPUs_max(ref))
        if int(maximum) < current:
            self.x.VM.set_VCPUs_at_startup(ref, startup)
            self.x.VM.set_VCPUs_max(ref, maximum)
        else:
            self.x.VM.set_VCPUs_max(ref, maximum)
            self.x.VM.set_VCPUs_at_startup(ref, startup)
    def set_memory(self, uuid, values):
        self.x.VM.set_memory_limits(self.x.VM.get_by_uuid(uuid), *[values[k] for k in MEMORY])
    def move_vif(self, uuid, network):
        self.x.VIF.move(self.x.VIF.get_by_uuid(uuid), self.x.network.get_by_uuid(network))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--desired-base64', required=True)
    parser.add_argument('--allowed-base64', required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--check', action='store_true')
    args = parser.parse_args()
    import XenAPI  # Native Dom0 binding; no pip package installed on host.
    session = XenAPI.xapi_local()
    session.xenapi.login_with_password('root', '', '1.0', 'ansible-existing-diskless-vms')
    try:
        desired = json.loads(base64.b64decode(args.desired_base64).decode('utf-8'))
        allowed = json.loads(base64.b64decode(args.allowed_base64).decode('utf-8'))
        print(json.dumps(reconcile(NativeAPI(session), desired, allowed, apply=args.apply), sort_keys=True))
    finally:
        session.xenapi.session.logout()


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print(json.dumps({'failed': True, 'error_type': type(exc).__name__, 'message': str(exc)}))
        sys.exit(1)
