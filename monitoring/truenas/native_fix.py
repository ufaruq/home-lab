#!/usr/bin/env python3
"""Exact-release repair for TrueNAS native syslog TLS template defects."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

SOURCE_URL = 'https://raw.githubusercontent.com/truenas/middleware/TS-24.04.2.5/src/middlewared/middlewared/etc_files/syslog-ng/syslog-ng.conf.mako'
ORIGINAL_SHA256 = '042d13cb429f3ca9e50b65860f21e74ae13985b2d8f7ce1f840d815db92fba88'
OS_ONLY_SHA256 = '9622877fd7889d7d0141afe0f6c051dc1d0228e8392bd3203cedbaf310dfe053'
PATCHED_SHA256 = '54590db0c9bbc2e90a597acdf65071e588e0b3b40405e11bd9a03211bdd2f4c1'
TEMPLATE_PATH = '/usr/lib/python3/dist-packages/middlewared/etc_files/syslog-ng/syslog-ng.conf.mako'


def _sibling(name):
    spec = importlib.util.spec_from_file_location('truenas_native_fix_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


client = _sibling('client')
console = _sibling('console')


def patch_template(content):
    digest = hashlib.sha256(content).hexdigest()
    if digest == PATCHED_SHA256:
        return content
    if digest not in (ORIGINAL_SHA256, OS_ONLY_SHA256):
        raise ValueError('Unknown native template; no repair permitted')
    patched = content.replace(b'<%\nlogger = middleware.logger', b'<%\nimport os\nlogger = middleware.logger', 1)
    patched = patched.replace(b'"%x.0" % certificate_authority["subject_name_hash"]', b'"%08x.0" % certificate_authority["subject_name_hash"]', 1)
    if hashlib.sha256(patched).hexdigest() != PATCHED_SHA256:
        raise ValueError('Native template patch did not match the reviewed digest')
    return patched


GUEST_REPAIR = r'''
import stat,tempfile
from mako.template import Template
changed=False
rollback_verified=False
stage='preflight'
remount_attempted=False
usr_readonly_verified=False
path=TEMPLATE_PATH
backup_dir='/root/.config/homelab-truenas'
backup=backup_dir+'/syslog-ng.conf.mako.original'
receipt=backup_dir+'/syslog-ng-template-repair-v2.json'
def digest(data):return hashlib.sha256(data).hexdigest()
def read_regular(path):
 st=os.lstat(path)
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:raise ValueError('Guard')
 with open(path,'rb') as f:return f.read(),st
def syncdir(directory):
 fd=os.open(directory,os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)
def save_new(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 syncdir(os.path.dirname(path))
def replace(data,st):
 global changed
 directory=os.path.dirname(path)
 fd,tmp=tempfile.mkstemp(prefix='.homelab-syslog-',dir=directory)
 try:
  with os.fdopen(fd,'wb') as f:
   os.fchmod(f.fileno(),stat.S_IMODE(st.st_mode));os.fchown(f.fileno(),st.st_uid,st.st_gid)
   f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path);changed=True;syncdir(directory)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
def active():
 return subprocess.check_output(['systemctl','is-active','syslog-ng'],stderr=subprocess.DEVNULL).decode().strip()=='active'
def mount_state():
 m=json.loads(subprocess.check_output(['findmnt','-J','-M','/usr','-o','TARGET,SOURCE,FSTYPE,OPTIONS']))['filesystems']
 if len(m)!=1:raise ValueError('Guard')
 m=m[0]
 if m['target']!='/usr' or m['fstype']!='zfs':raise ValueError('Guard')
 data,_=read_regular('/conf/truenas_root_ds.json')
 entries=[e for e in json.loads(data) if e['fhs_entry']['name']=='usr']
 if len(entries)!=1 or entries[0]['ds']!=m['source'] or 'RO' not in entries[0]['fhs_entry']['options']:raise ValueError('Guard')
 props=dict((x[0],x[1:]) for x in (line.split('\t') for line in subprocess.check_output(['zfs','get','-Hp','-o','property,value,source','readonly,guid,mountpoint,canmount',m['source']]).decode().splitlines()))
 if props['guid'][0]!=str(entries[0]['guid']) or props['mountpoint'][0]!='/usr' or props['canmount'][0]!='noauto':raise ValueError('Guard')
 m['options']=sorted(m['options'].split(','))
 return {'mount':m,'properties':props}
def same_mount(a,b):
 return a['mount']['source']==b['mount']['source'] and a['properties']['guid']==b['properties']['guid'] and set(a['mount']['options'])-{'ro','rw'}==set(b['mount']['options'])-{'ro','rw'}
def validate_remote():
 subprocess.check_call(['syslog-ng','-s','-f','/etc/syslog-ng/syslog-ng.conf'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 with open('/etc/syslog-ng/syslog-ng.conf') as f:rendered=f.read()
 host,port=SERVER.rsplit(':',1)
 if require_remote and (('syslog("'+host+'" port('+port+') transport("tls")') not in rendered or 'destination(loghost)' not in rendered):raise ValueError('Guard')
 if require_remote:
  ca=mid('certificateauthority.query',[['id','=',advanced['syslog_tls_certificate_authority']]],{'get':True})
  value=ca['subject_name_hash']
  if type(value) is not int or not 0<=value<=0xffffffff or ca['revoked']:raise ValueError('Guard')
  link='/etc/certificates/CA/'+('%08x.0'%value)
  if not os.path.islink(link) or os.readlink(link)!=ca['certificate_path'] or not os.path.isfile(link) or os.path.realpath(link)!=os.path.realpath(ca['certificate_path']):raise ValueError('Guard')
try:
 if identity!={'uid':0,'uuid':UUID,'version':VERSION}:raise ValueError('Guard')
 advanced=mid('system.advanced.config')
 require_remote=bool(advanced['syslogserver'])
 if require_remote and (advanced['syslogserver']!=SERVER or advanced['syslog_transport']!='TLS'):raise ValueError('Guard')
 if not active():raise ValueError('Guard')
 original,st=read_regular(path)
 initial_hash=digest(original)
 current=initial_hash
 if current not in (ORIGINAL,OS_ONLY,PATCHED):raise ValueError('Guard')
 before_mount=mount_state()
 if 'ro' not in before_mount['mount']['options'] or before_mount['properties']['readonly']!=['on','local']:raise ValueError('Guard')
 usr_readonly_verified=True
 if current==PATCHED:
  validate_remote()
 else:
  patched=original.replace(b'<%\nlogger = middleware.logger',b'<%\nimport os\nlogger = middleware.logger',1)
  patched=patched.replace(b'"%x.0" % certificate_authority["subject_name_hash"]',b'"%08x.0" % certificate_authority["subject_name_hash"]',1)
  if digest(patched)!=PATCHED:raise ValueError('Guard')
  Template(text=patched.decode())
  for directory in ('/root','/root/.config',backup_dir):
   if not os.path.exists(directory):os.mkdir(directory,0o700)
   info=os.lstat(directory)
   forbidden=0o077 if directory==backup_dir else 0o022
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & forbidden:raise ValueError('Guard')
  if os.path.lexists(backup):
   saved,bstat=read_regular(backup)
   if digest(saved)!=ORIGINAL or stat.S_IMODE(bstat.st_mode)!=0o600:raise ValueError('Guard')
  else:
   vendor=original if current==ORIGINAL else original.replace(b'<%\nimport os\n',b'<%\n',1)
   if digest(vendor)!=ORIGINAL:raise ValueError('Guard')
   save_new(backup,vendor)
  before_backup=backup_dir+'/syslog-ng.conf.mako.before-v2-'+initial_hash
  if os.path.lexists(before_backup):
   saved,bstat=read_regular(before_backup)
   if digest(saved)!=initial_hash or stat.S_IMODE(bstat.st_mode)!=0o600:raise ValueError('Guard')
  else:save_new(before_backup,original)
  evidence=json.dumps({'version':VERSION,'template':path,'before_sha256':initial_hash,'original_sha256':ORIGINAL,'patched_sha256':PATCHED},sort_keys=True).encode()
  if os.path.lexists(receipt):
   saved,rstat=read_regular(receipt)
   if saved!=evidence or stat.S_IMODE(rstat.st_mode)!=0o600:raise ValueError('Guard')
  else:save_new(receipt,evidence)
  if not REMOUNT:raise ValueError('Guard')
  mount_receipt=backup_dir+'/usr-remount-before.json'
  evidence=json.dumps(before_mount,sort_keys=True).encode()
  if os.path.lexists(mount_receipt):
   saved,rstat=read_regular(mount_receipt)
   if saved!=evidence or stat.S_IMODE(rstat.st_mode)!=0o600:raise ValueError('Guard')
  else:save_new(mount_receipt,evidence)
  stage='remount';remount_attempted=True;usr_readonly_verified=False
  subprocess.check_call(['mount','-o','remount,rw','/usr'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  writable=mount_state()
  if 'rw' not in writable['mount']['options'] or not same_mount(before_mount,writable):raise ValueError('Guard')
  stage='replace';replace(patched,st)
  stage='generate';mid('etc.generate','syslogd');validate_remote()
  stage='restart';mid('service.restart','syslogd')
  if not active():raise ValueError('Guard')
  validate_remote()
 outcome=dict(identity,ok=True,changed=changed,template_sha256=PATCHED,remote_destination_verified=require_remote)
except Exception as error:
 failure_type=type(error).__name__
 failure_errno=getattr(error,'errno',None)
 if type(failure_errno) is not int:failure_errno=None
 if stage!='preflight':
  try:
   current=digest(read_regular(path)[0])
   if current==initial_hash and active():rollback_verified=True
   elif changed:
    saved,_=read_regular(before_backup)
    if digest(saved)!=initial_hash:raise ValueError('Guard')
    replace(saved,st);mid('etc.generate','syslogd')
    subprocess.check_call(['syslog-ng','-s','-f','/etc/syslog-ng/syslog-ng.conf'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    mid('service.restart','syslogd')
    rollback_verified=digest(read_regular(path)[0])==initial_hash and active()
  except Exception:pass
 outcome=dict(identity,ok=False,changed=changed,stage=stage,rollback_verified=rollback_verified,failure_type=failure_type,failure_errno=failure_errno)
finally:
 if remount_attempted:
  try:
   subprocess.check_call(['mount','-o','remount,ro','/usr'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   after_mount=mount_state()
   usr_readonly_verified=after_mount==before_mount
   if not usr_readonly_verified:raise ValueError('Guard')
  except Exception as error:
   outcome.update(ok=False,protection_restore_failed=True,protection_failure_type=type(error).__name__,protection_failure_errno=getattr(error,'errno',None))
 outcome['usr_readonly_verified']=usr_readonly_verified
reply(outcome)
'''


def program(expected_uuid, syslogserver, remount_enabled=False):
    constants = ('\nTEMPLATE_PATH=%r\nORIGINAL=%r\nOS_ONLY=%r\nPATCHED=%r\nUUID=%r\nVERSION=%r\nSERVER=%r\nREMOUNT=%r\n' %
                 (TEMPLATE_PATH, ORIGINAL_SHA256, OS_ONLY_SHA256, PATCHED_SHA256, expected_uuid, console.VERSION, syslogserver, remount_enabled is True))
    return console.GUEST + constants + GUEST_REPAIR


def repair(declaration_path):
    declaration = json.loads(client.pki.read_private(declaration_path))
    if (declaration.get('console_administration_enabled') is not True
            or declaration.get('native_syslog_template_fix_enabled') is not True
            or declaration.get('expected_version') != console.VERSION
            or declaration.get('ssh_alias') != 'home-lab-host'):
        raise ValueError('Exact native template repair declaration is required')
    vm = declaration.get('expected_vm_uuid', '')
    if not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', vm):
        raise ValueError('Expected native VM identity is required')
    server = declaration.get('syslogserver', '')
    try:
        host, port = server.rsplit(':', 1)
        if client._private_ipv4(host) != host or port != '6514':raise ValueError()
    except Exception:
        raise ValueError('Exact private TLS syslog receiver is required') from None
    result = console.execute(declaration['ssh_alias'], vm, program(vm, server, declaration.get('native_syslog_usr_remount_enabled') is True))
    evidence_dir = client.pki.private_directory(Path(declaration_path).resolve().parent)
    # Preserve diagnostic outcome and nonce before acknowledging the guest reply.
    import uuid
    client.pki.write_new(evidence_dir / ('native-template-repair-' + uuid.uuid4().hex + '.json'),
                         json.dumps(result, sort_keys=True).encode())
    if '_console_reply_path' in result:
        console.acknowledge(declaration['ssh_alias'], vm, result['_console_reply_path'])
    if result.get('ok') is not True:
        raise ValueError('Native template repair failed; inspect private evidence and rollback status')
    return {'changed': result['changed'], 'native_template_verified': True,
            'remote_destination_verified': result['remote_destination_verified'],
            'usr_readonly_verified': result['usr_readonly_verified']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--declaration', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(repair(args.declaration), sort_keys=True))
        return 0
    except Exception:
        print('Native TrueNAS template repair stopped; inspect private identity, digest and recovery evidence.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
