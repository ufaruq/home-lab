#!/usr/bin/env python3
"""Generate a local Ansible inventory from explicitly supplied private or synthetic data."""
import argparse
import json
from pathlib import Path
import re

GROUPS=('xcp_control','linux_guests','windows_guests','bsd_guests','appliance_guests','unknown_guests')
HARDWARE=('uuid','name_label','VCPUs_max','VCPUs_at_startup','memory_static_min','memory_static_max',
          'memory_dynamic_min','memory_dynamic_max','power_state','disks','cdroms','vifs','domain_type',
          'HVM_boot_policy','HVM_boot_params','PV_bootloader','PV_args','platform','other_config',
          'attached_pci_uuids','vgpu_uuids','vusb_uuids')


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def alias(name):
    value=re.sub(r'[^a-z0-9_]+','_',name.lower()).strip('_')
    if not value or value[0].isdigit():value='guest_'+value
    return value


def generate(source_path,output,control_alias='control_host',recovery_policy=None,network_profile=None,captures=None):
    source_path=Path(source_path).resolve();output=Path(output).resolve()
    source=json.loads(source_path.read_text())
    if len(source['hosts'])!=1:raise ValueError('Explicit single-host source inventory required')
    inventory={'all':{'children':{group:{'hosts':{}} for group in GROUPS}}}
    definitions=[];seen={control_alias}
    for uuid,vm in source['vms'].items():
        name=alias(vm['name_label'])
        if name in seen:raise ValueError('Duplicate inventory alias; rename source entries explicitly: '+name)
        seen.add(name)
        metrics=vm.get('last_known_guest_metrics') or {};os_version=metrics.get('os_version',{})
        distro=os_version.get('distro','').lower()
        group=('windows_guests' if distro=='windows' else 'bsd_guests' if distro in ('freebsd','openbsd','netbsd')
               else 'linux_guests' if distro in ('debian','ubuntu','linux','pop','rhel','centos','alpine','arch','parrot') else 'unknown_guests')
        inventory['all']['children'][group]['hosts'][name]={}
        addresses=sorted(set(ip for key,ip in metrics.get('networks',{}).items() if '/ipv4/' in key or key.endswith('/ip')))
        variables={'vm_uuid':uuid,'vm_name':vm['name_label'],'xcp_observed':{key:vm.get(key) for key in HARDWARE},
                   'cached_guest_hints':{'source':'Unverified cached metrics, not current reachability or guest inspection','last_updated':metrics.get('last_updated'),'os_version':os_version,'ipv4_candidates':addresses},
                   'guest_access_status':'Unverified; access and apply gates default false in group_vars',
                   'guest_desired_users':[],'guest_desired_groups':[],'guest_desired_packages':[],'guest_desired_services':[],
                   'discovery_gaps':['Guest access is unverified','Guest and application configuration require explicit inspection'],
                   'configuration_owner':'ansible native XenAPI' if not vm['disks'] else 'terraform hardware; ansible guest state'}
        if addresses:variables['guest_cached_address_candidate']=addresses[0]
        if not vm['disks']:
            definition={key:vm[key] for key in ('uuid','name_label','VCPUs_max','VCPUs_at_startup','memory_static_min','memory_static_max','memory_dynamic_min','memory_dynamic_max','power_state')}
            definition.update(disks=[],vifs=[{key:vif[key] for key in ('uuid','device','MAC','network_uuid')} for vif in vm['vifs']])
            variables['xcp_desired_definition']=definition;definitions.append(definition)
            variables['discovery_gaps'].append('No observed disk: boot/recovery storage policy is unresolved')
        write(output/'host_vars'/(name+'.yml'),variables)
    inventory['all']['children']['guests']={'children':{g:{} for g in GROUPS if g!='xcp_control'}}
    inventory['all']['children']['xcp_control']['hosts'][control_alias]={}
    host=next(iter(source['hosts'].values()))
    variables={'ansible_host':host['address'],'ansible_user':'root','ansible_python_interpreter':'/usr/bin/python',
               'xcp_host_uuid':host['uuid'],'xcp_native_definitions':definitions,'xcp_definition_allowlist':{d['uuid']:d['name_label'] for d in definitions},'xcp_definition_apply':False,'control_host_only':True}
    if recovery_policy is not None:variables['native_recovery_policy']=recovery_policy
    if network_profile is not None:variables['network_profile']=network_profile
    write(output/'hosts.yml',inventory);write(output/'host_vars'/(control_alias+'.yml'),variables)
    defaults={'guest_access_verified':False,'guest_configuration_verified':False,'guest_desired_state_declared':False}
    write(output/'group_vars/all.yml',defaults)
    for group in ('linux_guests','bsd_guests','appliance_guests','unknown_guests'):write(output/'group_vars'/(group+'.yml'),{'ansible_user':'root'})
    write(output/'group_vars/windows_guests.yml',{'ansible_connection':'winrm','ansible_winrm_transport':'ntlm','ansible_winrm_server_cert_validation':'validate','ansible_port':5986})
    if captures is not None:
        from integrate_offline import integrate
        integrate(source_path,Path(captures),output)
    return inventory


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--captures',type=Path);parser.add_argument('--control-alias',default='control_host')
    parser.add_argument('--recovery-policy',type=Path);parser.add_argument('--network-profile',type=Path)
    args=parser.parse_args()
    load=lambda path:json.loads(path.read_text()) if path else None
    generate(args.inventory,args.output,args.control_alias,load(args.recovery_policy),load(args.network_profile),args.captures)

if __name__=='__main__':main()
