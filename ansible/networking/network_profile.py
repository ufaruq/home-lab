#!/usr/bin/env python
"""Persistent reviewed XenAPI PIF profile. Python 2.7/3; read-only check by default."""
from __future__ import print_function
import argparse,base64,hashlib,json,os,socket,stat,subprocess,sys,tempfile,time
SCRIPT='/usr/local/sbin/direct-cable-network'


def ordered_ids(profile):
    return [key for role in ['uplink','recovery'] for key,desired in profile['pifs'].items() if desired['role']==role]


def valid_uuid(value):
    import uuid
    try:return str(uuid.UUID(value))==value
    except (ValueError,TypeError,AttributeError):return False


def valid_ipv4(value):
    try:
        socket.inet_pton(socket.AF_INET,value)
        return True
    except (socket.error,TypeError):return False


def validate(state,profile):
    import re
    required=set(['schema_version','expected_host_uuid','expected_pool_uuid','recovery_script','recovery_script_sha256','pifs'])
    if not isinstance(profile,dict) or set(profile)!=required or profile['schema_version']!=1:
        raise ValueError('Required private network profile is incomplete or has unsupported fields')
    if not valid_uuid(profile['expected_host_uuid']) or not valid_uuid(profile['expected_pool_uuid']):
        raise ValueError('Private profile requires canonical host/pool UUIDs')
    if profile.get('recovery_script')!=SCRIPT or not re.match(r'^[0-9a-f]{64}$',profile.get('recovery_script_sha256','')):
        raise ValueError('Private reviewed recovery script SHA256 is required')
    if state['host_uuids']!=[profile['expected_host_uuid']] or state['pool_uuid']!=profile['expected_pool_uuid']:
        raise ValueError('Live host/pool differs from private reviewed identities')
    targets=profile['pifs']
    if not isinstance(targets,dict) or len(targets)!=2 or sorted(d.get('role','') for d in targets.values())!=['recovery','uplink']:
        raise ValueError('Private profile must select exactly one recovery and one uplink PIF')
    for key in ordered_ids(profile):
        desired=targets[key];record=state['pifs'].get(key,{})
        if not valid_uuid(key) or not valid_uuid(desired.get('network_uuid')) or not re.match(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$',desired.get('mac','')) or type(desired.get('management')) is not bool:
            raise ValueError('Private PIF UUID/MAC/network/management identity is invalid')
        if record.get('host_uuid')!=profile['expected_host_uuid'] or record.get('MAC','').lower()!=desired['mac'] or record.get('network_uuid')!=desired['network_uuid'] or record.get('management')!=desired['management'] or not record.get('physical') or not record.get('currently_attached'):
            raise ValueError('Live PIF identity, role or attachment mismatch')
        expected_flags={'defaultroute':'true','peerdns':'false'} if desired['role']=='uplink' else {'defaultroute':'false','peerdns':'true'}
        if desired.get('other_config')!=expected_flags:raise ValueError('Only reviewed role-specific route/DNS preference flags are supported')
        identity_fields=set(['role','mac','network_uuid','management','mode','other_config'])
        if desired['role']=='uplink':
            if desired.get('mode')!='DHCP' or set(desired)!=identity_fields:raise ValueError('Uplink must use DHCP without static lease overrides')
        else:
            if set(desired)!=identity_fields|set(['IP','netmask','gateway','DNS']) or desired['mode']!='Static' or desired['gateway']!='':raise ValueError('Recovery PIF requires an explicit static address and no gateway')
            if not valid_ipv4(desired['IP']) or not valid_ipv4(desired['netmask']) or not desired['DNS'] or not all(valid_ipv4(value) for value in desired['DNS'].split(',')):
                raise ValueError('Private recovery address, netmask and DNS must be explicit IPv4 values')
    for key,record in state['pifs'].items():
        if key not in targets and any(record.get('other_config',{}).get(flag)=='true' for flag in ['defaultroute','peerdns']):
            raise ValueError('Unreviewed PIF claims default-route or peer-DNS preference')


def plan(state,profile):
    changes=[]
    for key in ordered_ids(profile):
        record=state['pifs'][key];desired=profile['pifs'][key]
        flags=any(record['other_config'].get(k)!=v for k,v in desired['other_config'].items())
        parameters=record['ip_configuration_mode']!=desired['mode']
        if desired['mode']=='Static':parameters=parameters or any(record.get(k,'')!=desired[k] for k in ['IP','netmask','gateway','DNS'])
        if flags or parameters:changes.append({'pif_uuid':key,'flags':flags,'reconfigure':True})
    return changes


def reconcile(api,system,profile,apply=False):
    before=api.snapshot();validate(before,profile);system.preflight(profile)
    changes=plan(before,profile)
    result={'mode':'apply' if apply else 'check','changed':bool(changes),'operations':changes}
    if not apply or not changes:return result
    backup=system.backup('before',before);result['private_backup']=backup;guard=None;restored=False
    try:
        # Publish both preference maps before either native DHCP/static projection.
        for item in changes:
            if item['flags']:api.set_flags(item['pif_uuid'],profile['pifs'][item['pif_uuid']]['other_config'])
        guard=system.start_guard()
        for item in changes:api.reconfigure(item['pif_uuid'],profile['pifs'][item['pif_uuid']])
    finally:
        try:
            system.restore_recovery();restored=True
        finally:
            try:
                # A failed restore leaves the bounded guardian retrying independently.
                if guard and restored:system.stop_guard(guard)
            finally:system.backup('after',api.snapshot(),backup)
    after=api.snapshot();validate(after,profile)
    if plan(after,profile):raise ValueError('Native PIF metadata did not converge; inspect private backups')
    for key,record in before['pifs'].items():
        if key not in profile['pifs'] and after['pifs'].get(key)!=record:raise ValueError('Unreviewed PIF changed during reconciliation')
    result['verified']=True
    return result


class NativeAPI(object):
    def __init__(self,session):self.x=session.xenapi
    def snapshot(self):
        hosts=self.x.host.get_all_records();pools=self.x.pool.get_all_records()
        if len(pools)!=1:raise ValueError('Expected one existing pool')
        networks=self.x.network.get_all_records();pifs={}
        for record in self.x.PIF.get_all_records().values():
            pifs[record['uuid']]={field:record.get(field) for field in ['uuid','MAC','physical','management','currently_attached','ip_configuration_mode','IP','netmask','gateway','DNS','other_config']}
            pifs[record['uuid']]['host_uuid']=hosts[record['host']]['uuid']
            pifs[record['uuid']]['network_uuid']=networks[record['network']]['uuid']
        return {'host_uuids':sorted(v['uuid'] for v in hosts.values()),'pool_uuid':next(iter(pools.values()))['uuid'],'pifs':pifs}
    def set_flags(self,key,flags):
        ref=self.x.PIF.get_by_uuid(key);config=self.x.PIF.get_other_config(ref);config.update(flags);self.x.PIF.set_other_config(ref,config)
    def reconfigure(self,key,desired):
        values=[desired.get(k,'') for k in ['IP','netmask','gateway','DNS']]
        self.x.PIF.reconfigure_ip(self.x.PIF.get_by_uuid(key),desired['mode'],*values)


class NativeSystem(object):
    def run(self,args,seconds=15):
        process=subprocess.Popen(['/usr/bin/timeout',str(seconds)]+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=process.communicate()
        if process.returncode:raise ValueError('Native command failed: '+args[0]+' exit='+str(process.returncode))
        return out
    def preflight(self,profile):
        if os.path.islink(SCRIPT):raise ValueError('Recovery script cannot be a symlink')
        info=os.stat(SCRIPT)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or not os.access(SCRIPT,os.X_OK):raise ValueError('Recovery script must be root-owned, executable and not writable by group/others')
        with open(SCRIPT,'rb') as stream:script_body=stream.read()
        digest=hashlib.sha256(script_body).hexdigest()
        if digest!=profile['recovery_script_sha256']:raise ValueError('Recovery script differs from reviewed source')
        recovery=next(desired for desired in profile['pifs'].values() if desired['role']=='recovery')
        # Only the reviewed version advertising this interface accepts --check.
        # Legacy reviewed scripts may ignore arguments and apply addresses.
        if b'# home-lab: private-recovery-policy-v1' in script_body:
            self.run([SCRIPT,'--check','--expect-mac',recovery['mac']],40)
        for path in ['/usr/bin/systemd-run','/bin/systemctl','/usr/bin/timeout']:
            if not os.access(path,os.X_OK):raise ValueError('Missing native safeguard tool: '+path)
    def backup(self,stage,state,backup=None):
        base='/root/home-lab-network-backups'
        if not os.path.isdir(base):os.makedirs(base,0o700)
        info=os.lstat(base)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('Private network backup directory ownership/mode is unsafe')
        directory=backup or tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%SZ-',time.gmtime()),dir=base)
        body=(json.dumps({'captured_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'pif_state':state},sort_keys=True,indent=2)+'\n').encode('utf-8')
        target=os.path.join(directory,stage+'.json');fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        with open(target,'rb') as stream:
            if stream.read()!=body:raise ValueError('Private network metadata backup verification failed')
        return directory
    def start_guard(self):
        unit='home-lab-network-guard-'+str(os.getpid())
        script='attempt=0; while [ "$attempt" -lt 12 ]; do /usr/bin/timeout 8 '+SCRIPT+' >/dev/null 2>&1; attempt=$((attempt+1)); sleep 5; done'
        self.run(['/usr/bin/systemd-run','--quiet','--unit='+unit,'/usr/bin/timeout','90','/bin/sh','-c',script])
        self.run(['/bin/systemctl','is-active','--quiet',unit+'.service'])
        return unit
    def restore_recovery(self):self.run([SCRIPT],40)
    def stop_guard(self,unit):self.run(['/bin/systemctl','stop',unit+'.service'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--profile-base64',required=True)
    mode=parser.add_mutually_exclusive_group();mode.add_argument('--apply',action='store_true');mode.add_argument('--check',action='store_true')
    args=parser.parse_args();profile=json.loads(base64.b64decode(args.profile_base64).decode('utf-8'))
    if args.apply and os.geteuid()!=0:raise ValueError('Apply requires root')
    socket.setdefaulttimeout(30)
    import XenAPI
    session=XenAPI.xapi_local();session.xenapi.login_with_password('root','','1.0','ansible-reviewed-network-profile')
    try:print(json.dumps(reconcile(NativeAPI(session),NativeSystem(),profile,args.apply),sort_keys=True))
    finally:session.xenapi.session.logout()

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'failed':True,'error_type':type(exc).__name__,'message':str(exc) if isinstance(exc,ValueError) else 'Native API operation failed; inspect private metadata backups and native logs'},sort_keys=True));sys.exit(1)
