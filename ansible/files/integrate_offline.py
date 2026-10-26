#!/usr/bin/env python3
"""Generate review-gated desired baselines from sanitized offline guest evidence."""
import argparse
import hashlib
import json
import pathlib
import posixpath

ROOT = pathlib.Path(__file__).resolve().parents[2]


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')



def guest_host_address_conflicts(source, vm_uuid, evidence):
    """Flag observed Xen PV interface addresses duplicated on the same host network."""
    vifs = {v['device']: v for v in source['vms'][vm_uuid].get('vifs', [])}
    interfaces = evidence.get('application_configuration_observed', {}).get('interfaces', {})
    conflicts = []
    for settings in interfaces.values():
        device = settings.get('if', '')
        if not isinstance(device, str) or not device.startswith('xn') or not device[2:].isdigit():
            continue
        vif = vifs.get(device[2:])
        address = settings.get('ipaddr')
        if not vif or not isinstance(address, str):
            continue
        for pif in source.get('pifs', {}).values():
            if pif['network_uuid'] == vif['network_uuid'] and pif.get('IP') == address:
                conflicts.append({'kind': 'guest_host_duplicate_ipv4', 'address': address,
                                  'guest_interface': device, 'network_uuid': vif['network_uuid'],
                                  'host_uuid': pif['host_uuid'], 'pif_uuid': pif['uuid'], 'vlan': pif['VLAN'],
                                  'note': 'Guest and recorded Dom0 PIF share this IPv4 address on the same network. Resolve before firewall boot or network changes; no address/route change is authorized by this observation.'})
    return conflicts


def integrate(source_path, capture_dir, inventory_dir):
    source_path=pathlib.Path(source_path).resolve()
    capture_dir=pathlib.Path(capture_dir).resolve()
    inventory_dir=pathlib.Path(inventory_dir).resolve()
    source = json.loads(source_path.read_text())
    inventory = json.loads((inventory_dir/'hosts.yml').read_text())
    coverage = []
    for path in sorted((inventory_dir/'host_vars').glob('*.yml')):
        hv = json.loads(path.read_text())
        if 'vm_uuid' not in hv:
            continue
        uuid = hv['vm_uuid']
        manifest_path = capture_dir / (uuid + '.json')
        if not manifest_path.exists():
            continue
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw)
        revisit = manifest.get('current_readonly_revisit', {})
        bsd = [d for d in manifest['disks'] if d.get('os', {}).get('type') in ('freebsd', 'openbsd', 'netbsd') and d.get('users') and d.get('packages')]
        if revisit.get('os', {}).get('type') in ('freebsd', 'openbsd', 'netbsd') and revisit.get('users') and revisit.get('packages'):
            bsd = [revisit]
        linux = [d for d in manifest['disks'] if d.get('os', {}).get('type') == 'linux' and d.get('users') and d.get('packages')]
        windows = [d for d in manifest['disks'] if d.get('os', {}).get('type') == 'windows']
        if bsd:
            linux, windows = [], []
        blockers = list(manifest.get('blockers', []))
        if revisit.get('blocker'):
            blockers.append(revisit['blocker'])
        hv['offline_capture'] = {'manifest': str(manifest_path.relative_to(ROOT)) if manifest_path.is_relative_to(ROOT) else str(manifest_path), 'sha256': hashlib.sha256(raw).hexdigest(),
                                 'captured_at': manifest['captured_at'], 'status': manifest['coverage_status'],
                                 'source': 'offline guest files presented read-only; not cached guest metrics',
                                 'linux_baseline_available': bool(linux), 'bsd_observed_only': bool(bsd), 'blockers': blockers,
                                 'revisit_captured_at': revisit.get('captured_at'),
                                 'historical_disk_observations': [{k: d.get(k) for k in ['vdi_uuid','status','errors']} for d in manifest['disks']],
                                 'limitations': manifest.get('capture_limitations', [])}
        # Preserve the complete exported VM definition, including unsupported child-device attributes.
        hv['xcp_snapshot_definition'] = source['vms'][uuid]
        hv['xcp_overlay_unenforced_fields'] = sorted(k for k in source['vms'][uuid] if k not in {
            'uuid','name_label','VCPUs_max','VCPUs_at_startup','memory_dynamic_min','memory_dynamic_max',
            'memory_static_min','memory_static_max','disks','vifs','power_state'})
        hv['xcp_overlay_note'] = 'Preserved evidence only; no extra metadata setters. Nested VBD/VIF attributes may also be unsupported by Terraform; review before adoption.'
        hv['guest_observed_readonly_revisit'] = revisit
        hv['guest_network_conflicts'] = guest_host_address_conflicts(source, uuid, bsd[0] if bsd else revisit)
        hv['guest_private_config_files'] = []
        hv['guest_private_config_deploy_declared'] = False
        supplemental = manifest.get('supplemental_application_capture', {})
        hv['guest_observed_application_capture'] = supplemental
        hv['guest_observed_separate_data_disk_capture'] = manifest.get('separate_data_disk_capture', {})
        if linux:
            # Single detected OS root is the reproducible baseline; data disks remain separate evidence.
            if len(linux) != 1:
                raise ValueError('Multiple Linux root baselines require explicit selection: ' + uuid)
            disk = linux[0]
            hv['guest_observed_os'] = disk['os']
            for key in ['users','groups','packages','service_enablement','network_config_files','network_config_observed','structured_network_config','configuration_files','containers','app_locations']:
                hv['guest_observed_' + key] = disk.get(key, [])
            groups = disk['groups']
            gid_names = {}
            for g in groups:
                gid_names.setdefault(g['gid'], g['name'])
            hv['guest_desired_groups'] = [{'name': g['name'], 'gid': g['gid']} for g in groups]
            users = []
            for u in disk['users']:
                desired = {k: u[k] for k in ['name','uid','home','shell']}
                desired['create_home'] = False
                if u['gid'] in gid_names:
                    desired['group'] = gid_names[u['gid']]
                desired['groups'] = [g['name'] for g in groups if u['name'] in g['members']]
                users.append(desired)
            hv['guest_desired_users'] = users
            hv['guest_desired_packages'] = [p['package'] + ((':' + p['architecture']) if p.get('architecture') not in (None, '', 'all') and ':' not in p['package'] else '') + '=' + p['version'] for p in disk['packages']]
            enabled = sorted(set(posixpath.basename(e['path']) for e in disk.get('service_enablement', [])
                                 if ('.wants/' in e['path'] or '.requires/' in e['path']) and e['path'].endswith('.service') and e.get('target') != '/dev/null'))
            hv['guest_desired_services'] = [{'name': name, 'enabled': True} for name in enabled]
            hv['guest_desired_baseline_note'] = 'Observed reconstruction baseline, not reviewed connection/enforcement policy. Offline symlinks prove enablement only; no running state inferred. Historical package versions require matching repositories/artifacts.'
            app_prefixes = ('/etc/apache2/', '/etc/nginx/', '/etc/redis/', '/etc/docker/', '/etc/wazuh', '/etc/xo-server/', '/var/ossec/etc/')
            candidates = [f for f in disk.get('configuration_files', []) if f.get('type') == 'file' and f.get('sha256') and f['path'].startswith(app_prefixes)]
            hv['guest_observed_app_config_candidates'] = candidates
            hv['discovery_gaps'] = ['Guest login, routes, SSH host identity and access policy not verified',
                                    'Desired baseline requires review before any enforcement',
                                    'Historical package repository availability and installer artifacts unverified',
                                    'Private configuration files require explicit per-file selection; archives are not blanket restoration instructions',
                                    'Application data, secrets, workload restoration, runtime service state and full rebuild validation remain incomplete']
            inventory['all']['children']['linux_guests']['hosts'][path.stem] = {}
            # Preserve appliance grouping while adding actual verified Linux applicability.
            inventory['all']['children']['unknown_guests']['hosts'].pop(path.stem, None)
        if bsd:
            if len(bsd) != 1:
                raise ValueError('Multiple BSD root observations require explicit selection: ' + uuid)
            evidence = bsd[0]
            hv['guest_observed_os'] = evidence['os']
            for key in ['users','groups','packages','configuration_files','app_locations','readonly_service_config_directives']:
                hv['guest_observed_' + key] = evidence.get(key, [])
            hv['guest_observed_application_configuration'] = evidence.get('application_configuration_observed', {})
            for key in ['users','groups','packages','services']:
                hv['guest_desired_' + key] = []
            hv['guest_desired_baseline_note'] = 'BSD/OPNsense observed evidence only. No Linux package/account/service desired baseline is generated; BSD mutation and rebuild policy remain unsupported.'
            hv['discovery_gaps'] = ['Guest SSH identity, access and routes remain unverified',
                                    'BSD/OPNsense mutation and full rebuild policy are not implemented; excluded from Linux convergence',
                                    'Private appliance configuration contains secrets and requires separately reviewed restoration policy',
                                    'Kernel build, runtime health, application data and full restore verification remain incomplete']
            if hv['guest_network_conflicts']:
                hv['discovery_gaps'].append('Observed guest IPv4 address duplicates a control-host interface on the same network; resolve before boot or network changes')
            inventory['all']['children']['bsd_guests']['hosts'][path.stem] = {}
            inventory['all']['children']['linux_guests']['hosts'].pop(path.stem, None)
            inventory['all']['children']['unknown_guests']['hosts'].pop(path.stem, None)
        if windows:
            disk = windows[0]
            hv['guest_observed_os'] = disk['os']
            for key in ['installed_applications','windows_services','windows_network_interfaces','user_profile_directories','windows_identity_limit','configuration_files']:
                hv['guest_observed_' + key] = disk.get(key, [])
            hv['windows_enforcement_gap'] = 'Observed only: installer sources, licenses, account identities and intended service/network policy unavailable. No installer URLs invented.'
        # Fact capture never grants access or apply permission.
        for flag in ['guest_access_verified', 'guest_configuration_verified', 'guest_desired_state_declared']:
            if bsd:
                hv[flag] = False
            else:
                hv.pop(flag, None)
        hv['guest_access_status'] = ('Offline BSD evidence only; access/desired gates false and Linux convergence excluded' if bsd else 'Offline evidence captured; connection and apply gates still default false in group_vars')
        write(path, hv)
        coverage.append({'inventory_name': path.stem, 'vm_uuid': uuid, 'vm_name': hv['vm_name'],
                         'status': manifest['coverage_status'], 'linux_baseline': bool(linux),
                         'windows_observed_only': bool(windows), 'bsd_observed_only': bool(bsd), 'blockers': blockers,
                         'manifest': hv['offline_capture']['manifest'], 'manifest_sha256': hv['offline_capture']['sha256']})
    write(inventory_dir/'hosts.yml', inventory)
    write(inventory_dir/'guest-coverage.json', {'vms': coverage, 'captured_vm_count': sum(v['status'] == 'partial_configuration_captured' for v in coverage),
                                         'blocked_vm_count': sum(v['status'] == 'blocked' for v in coverage),
                                         'scope': 'Partial offline configuration evidence, not full rebuild or verified guest access'})


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',type=pathlib.Path,required=True)
    parser.add_argument('--captures',type=pathlib.Path,required=True)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    args=parser.parse_args()
    integrate(args.inventory,args.captures,args.output)
