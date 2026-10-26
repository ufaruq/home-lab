#!/usr/bin/env python
"""Restore reviewed native XOA-only boot/shutdown wiring. Python 2.7/3; check by default."""
from __future__ import print_function
import argparse,base64,copy,hashlib,json,os,subprocess,sys,tempfile,time
UNIT='xapi-domains.service'
STOCK='/usr/lib/systemd/system/'+UNIT
SCRIPT='/opt/xensource/bin/xapi-autostart-vms'


def validate_policy(policy):
    import re
    import uuid
    required=set(['expected_host_uuid','expected_pool_uuid','automatic_vm_ids','stock_sha256'])
    if not isinstance(policy,dict) or set(policy)!=required:
        raise ValueError('Required private boot policy is incomplete or has unsupported fields')
    identities=[policy['expected_host_uuid'],policy['expected_pool_uuid']]
    if not isinstance(policy['automatic_vm_ids'],list) or len(policy['automatic_vm_ids'])!=1:
        raise ValueError('Private boot policy must select exactly one automatic management VM')
    identities+=policy['automatic_vm_ids']
    for identity in identities:
        try:
            if str(uuid.UUID(identity))!=identity:raise ValueError()
        except (ValueError,TypeError,AttributeError):raise ValueError('Boot policy requires canonical UUID identities')
    hashes=policy['stock_sha256']
    if not isinstance(hashes,dict) or set(hashes)!=set([STOCK,SCRIPT]) or any(not isinstance(value,type('')) and not isinstance(value,type(u'')) or not re.match(r'^[0-9a-f]{64}$',value) for value in hashes.values()):
        raise ValueError('Private boot policy must contain reviewed stock unit/script SHA256 values')


def validate_api(state,policy):
    validate_policy(policy)
    if state['host_uuids'] != [policy['expected_host_uuid']] or state['pool_uuid'] != policy['expected_pool_uuid']:
        raise ValueError('Host/pool identity differs from reviewed single-host policy')
    expected=set(policy['automatic_vm_ids'])
    actual=set(uuid for uuid,v in state['vms'].items() if v['auto_poweron']=='true')
    if actual != expected:raise ValueError('VM auto_poweron flags do not match exact XOA-only policy; Terraform must reconcile them first')
    for uuid,v in state['vms'].items():
        if v['auto_poweron'] not in ('','false','true'):raise ValueError('Unexpected guest auto_poweron value')
        if uuid in expected and v['power_state'] not in ('Running','Halted'):raise ValueError('XOA power state is not Running/Halted')
        if uuid not in expected and v['power_state'] not in ('Halted','Running','Paused','Suspended'):raise ValueError('Unrecognized nonautomatic guest power state: '+uuid)


def reconcile(api,system,policy,apply=False):
    before={'api':api.snapshot(),'system':system.snapshot()}
    validate_api(before['api'],policy)
    unit=before['system']
    if unit['persistent_override'] or unit['unexpected_dropins'] or not unit['stock_hashes_valid']:
        raise ValueError('Persistent mask/override, drop-in or modified stock boot/shutdown unit/script requires review')
    if unit['active_state'] not in ('active','inactive'):raise ValueError('Unexpected/transitional stock unit state; refusing lifecycle changes')
    if unit['active'] and before['api']['vms'][policy['automatic_vm_ids'][0]]['power_state']=='Halted':
        raise ValueError('Stock unit is active while XOA is halted; no restart or direct VM start is allowed by this helper')
    operations=[]
    if before['api']['pool_auto_poweron']!='true':operations.append('enable_pool_auto_poweron')
    if unit['runtime_mask']:operations.extend(['unmask_runtime','daemon_reload'])
    if not unit['enabled']:operations.append('enable_stock_unit')
    if not unit['active']:operations.append('start_stock_unit')
    result={'mode':'apply' if apply else 'check','changed':bool(operations),'operations':operations,'before':before,
            'scope':'Native XOA-only autostart and stock graceful shutdown wiring; no custom agent, VM flag edits, direct VM lifecycle calls, stop/restart or reboot'}
    if apply and operations:
        result['private_backup']=system.backup(before)
        if 'enable_pool_auto_poweron' in operations:api.enable_pool(policy['expected_pool_uuid'])
        if unit['runtime_mask']:system.unmask_runtime();system.reload()
        if not unit['enabled']:system.enable()
        if not unit['active']:system.start()
    if apply:
        after={'api':api.snapshot(),'system':system.snapshot()}
        validate_api(after['api'],policy)
        if set(after['api']['vms'])!=set(before['api']['vms']):raise ValueError('Guest inventory changed during recovery wiring; inspect without lifecycle operations')
        for uuid,vm in before['api']['vms'].items():
            if uuid not in policy['automatic_vm_ids'] and after['api']['vms'][uuid]['power_state']!=vm['power_state']:
                raise ValueError('A nonautomatic guest power state changed during native boot wiring: '+uuid)
        if after['api']['pool_auto_poweron']!='true' or after['system']['runtime_mask'] or not after['system']['enabled'] or not after['system']['active'] or after['system']['persistent_override'] or after['system']['unexpected_dropins'] or not after['system']['stock_hashes_valid']:
            raise ValueError('Native boot wiring did not reach enabled/unmasked/active state; preserve backup and inspect without stop/restart')
        if 'start_stock_unit' in operations and after['api']['vms'][policy['automatic_vm_ids'][0]]['power_state']!='Running':
            raise ValueError('Stock best-effort autostart did not leave XOA Running')
        result['after']=after
    return result


class NativeAPI(object):
    def __init__(self,session):self.x=session.xenapi
    def snapshot(self):
        hosts=sorted(v['uuid'] for v in self.x.host.get_all_records().values())
        pools=self.x.pool.get_all_records()
        if len(pools)!=1:raise ValueError('Expected exactly one pool')
        pool=next(iter(pools.values()));vms={}
        for v in self.x.VM.get_all_records().values():
            if v['is_a_template'] or v['is_a_snapshot'] or v['is_control_domain']:continue
            vms[v['uuid']]={'name':v['name_label'],'power_state':v['power_state'],'auto_poweron':v['other_config'].get('auto_poweron','')}
        return {'host_uuids':hosts,'pool_uuid':pool['uuid'],'pool_auto_poweron':pool['other_config'].get('auto_poweron',''),'vms':vms}
    def enable_pool(self,pool_uuid):
        ref=self.x.pool.get_by_uuid(pool_uuid)
        config=self.x.pool.get_other_config(ref);config['auto_poweron']='true'
        self.x.pool.set_other_config(ref,config)


class NativeSystem(object):
    def __init__(self,policy):
        validate_policy(policy)
        self.expected_hashes=policy['stock_sha256']
    def run(self,args):
        process=subprocess.Popen(['/usr/bin/timeout','120','/bin/systemctl']+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=process.communicate()
        if process.returncode:raise ValueError('systemctl command failed: '+str(args)+' exit='+str(process.returncode))
        return out.decode('utf-8','replace')
    def snapshot(self):
        paths={};valid=True
        for path,expected in self.expected_hashes.items():
            if os.path.islink(path) or not os.path.isfile(path):valid=False;paths[path]='unexpected-type';continue
            with open(path,'rb') as stream:actual=hashlib.sha256(stream.read()).hexdigest()
            paths[path]=actual;valid=valid and actual==expected
        runtime='/run/systemd/system/'+UNIT;persistent='/etc/systemd/system/'+UNIT
        runtime_mask=os.path.islink(runtime) and os.readlink(runtime)=='/dev/null'
        persistent_override=os.path.lexists(persistent) or (os.path.lexists(runtime) and not runtime_mask)
        dropins=False
        for directory in ['/etc/systemd/system/'+UNIT+'.d','/run/systemd/system/'+UNIT+'.d','/usr/lib/systemd/system/'+UNIT+'.d']:
            if os.path.lexists(directory) and (not os.path.isdir(directory) or os.listdir(directory)):dropins=True
        link='/etc/systemd/system/multi-user.target.wants/'+UNIT
        enabled=os.path.islink(link) and os.path.realpath(link)==os.path.realpath(STOCK)
        if os.path.lexists(link) and not enabled:persistent_override=True
        show=self.run(['show',UNIT,'-p','ActiveState','-p','SubState','-p','UnitFileState','-p','FragmentPath','-p','DropInPaths'])
        values=dict(line.split('=',1) for line in show.splitlines() if '=' in line)
        if values.get('DropInPaths'):dropins=True
        expected_fragment='/dev/null' if runtime_mask else STOCK
        if values.get('FragmentPath')!=expected_fragment:persistent_override=True
        return {'runtime_mask':runtime_mask,'persistent_override':persistent_override,'unexpected_dropins':dropins,'stock_hashes_valid':valid,
                'stock_sha256':paths,'enabled':enabled,'active':values.get('ActiveState')=='active','active_state':values.get('ActiveState'),
                'unit_properties':values,'runtime_mask_target':os.readlink(runtime) if os.path.islink(runtime) else None,'enabled_link_target':os.readlink(link) if os.path.islink(link) else None}
    def backup(self,before):
        base='/root/home-lab-recovery-backups'
        if not os.path.isdir(base):os.makedirs(base,0o700)
        directory=tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%SZ-',time.gmtime()),dir=base)
        body=json.dumps({'captured_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'before':before},sort_keys=True,indent=2)+'\n'
        target=directory+'/before.json';fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(body.encode('utf-8'));stream.flush();os.fsync(stream.fileno())
        with open(target,'rb') as stream:digest=hashlib.sha256(stream.read()).hexdigest()
        if digest!=hashlib.sha256(body.encode('utf-8')).hexdigest():raise ValueError('Fresh boot metadata backup verification failed')
        return {'path':target,'sha256':digest}
    def unmask_runtime(self):self.run(['unmask','--runtime',UNIT])
    def reload(self):self.run(['daemon-reload'])
    def enable(self):self.run(['enable',UNIT])
    def start(self):self.run(['start',UNIT])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--policy-base64',required=True)
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--apply',action='store_true');modes.add_argument('--check',action='store_true')
    args=parser.parse_args();policy=json.loads(base64.b64decode(args.policy_base64).decode('utf-8'));validate_policy(policy)
    if args.apply and os.geteuid()!=0:raise ValueError('Apply requires root')
    import XenAPI
    session=XenAPI.xapi_local();session.xenapi.login_with_password('root','','1.0','ansible-native-xoa-boot')
    try:print(json.dumps(reconcile(NativeAPI(session),NativeSystem(policy),policy,args.apply),sort_keys=True))
    finally:session.xenapi.session.logout()

if __name__=='__main__':
    try:main()
    except Exception as exc:print(json.dumps({'failed':True,'error_type':type(exc).__name__,'message':str(exc)},sort_keys=True));sys.exit(1)
