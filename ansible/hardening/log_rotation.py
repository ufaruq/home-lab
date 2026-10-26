#!/usr/bin/env python
"""Reviewed XCP-ng logging hardening; Python 2.7/3, check by default."""
from __future__ import print_function
import argparse
import time
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile

ORIGINAL_ROTATE_COMMAND = '/usr/sbin/logrotate -s /var/lib/logrotate/logrotate.status /etc/logrotate.conf'
WRAPPER_PATH = '/usr/local/sbin/home-lab-logrotate'
ORIGINAL_DAILY = '''#!/bin/sh

/usr/sbin/logrotate -s /var/lib/logrotate/logrotate.status /etc/logrotate.conf
EXITVALUE=$?
if [ $EXITVALUE != 0 ]; then
    /usr/bin/logger -t logrotate "ALERT exited abnormally with [$EXITVALUE]"
fi
exit 0
'''
ORIGINAL_POLICY = '''# see "man logrotate" for details
# rotate log files daily
daily

# keep one months worth of backlogs
rotate 31

# create new (empty) log files after rotating old ones
create

# rotate if log reaches 100 MiB
maxsize 104857600

# compress log files
compress
delaycompress

# RPM packages drop log rotation information into this directory
include /etc/logrotate.d

# no packages own wtmp and btmp -- we'll rotate them here
/var/log/wtmp {
    monthly
    create 0664 root utmp
\tminsize 1M
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    rotate 1
}

# system-specific logs may be also be configured here.
'''
DAILY = ORIGINAL_DAILY.replace(ORIGINAL_ROTATE_COMMAND, WRAPPER_PATH)
WRAPPER = '''#!/bin/sh
# Owned by home-lab logging hardening. Normal rotation only: never force/delete.
# Daily and 15-minute checks share this lock and the existing state file.
exec /usr/bin/flock -w 60 /run/lock/home-lab-logrotate.lock /usr/bin/timeout -k 10 240 /usr/sbin/logrotate -s /var/lib/logrotate/logrotate.status /etc/logrotate.conf
'''
CRON = '''# Owned by home-lab logging hardening; preserve normal daily/size/retention policy.
SHELL=/bin/sh
MAILTO=""
PATH=/sbin:/bin:/usr/sbin:/usr/bin
*/15 * * * * root /usr/local/sbin/home-lab-logrotate >/dev/null 2>&1 || /usr/bin/logger -t home-lab-logrotate "normal rotation check failed"
'''
HEALTH_SCRIPT = '''#!/usr/bin/python
from __future__ import print_function
import argparse,json,os,subprocess,sys,time

def classify(usage, services, warning=80, critical=90):
    messages=[];level=0
    for field in ['bytes_percent','inodes_percent']:
        percent=usage[field]
        if percent >= critical:level=max(level,2);messages.append(field+' >= critical threshold')
        elif percent >= warning:level=max(level,1);messages.append(field+' >= warning threshold')
    for unit,state in services.items():
        if state != 'active':level=max(level,2);messages.append(unit+' is '+state)
    return level,messages

def collect(warning=80,critical=90):
    if not 0 < warning < critical <= 100:raise ValueError('require 0 < warning < critical <= 100')
    fs=os.statvfs('/var/log');used=fs.f_blocks-fs.f_bfree
    denominator=used+fs.f_bavail
    if denominator <= 0 or fs.f_files <= 0:raise ValueError('filesystem counters unavailable')
    usage={'path':'/var/log','bytes_percent':round(100.0*used/denominator,2),'inodes_percent':round(100.0*(fs.f_files-fs.f_ffree)/fs.f_files,2)}
    services={};query_errors=[]
    for unit in ['rsyslog','crond']:
        process=subprocess.Popen(['/usr/bin/timeout','10','/bin/systemctl','is-active',unit],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=process.communicate();services[unit]=out.decode('utf-8','replace').strip() or ('query-failed-'+str(process.returncode))
        if process.returncode not in (0,3):query_errors.append(unit+' service query exit='+str(process.returncode))
    code,messages=classify(usage,services,warning,critical)
    if query_errors:code=3;messages.extend(query_errors)
    return {'captured_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'status':['ok','warning','critical','unknown'][code],'exit_code':code,'usage':usage,'services':services,'warning_percent':warning,'critical_percent':critical,'warnings':messages,'scope':'Point-in-time host health; no alert delivery or continuous monitoring pipeline'},code

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description='Read-only /var/log space/inode and logging/cron service health')
    parser.add_argument('--warning',type=int,default=80);parser.add_argument('--critical',type=int,default=90);args=parser.parse_args()
    try:report,code=collect(args.warning,args.critical)
    except Exception as exc:report,code={'status':'unknown','exit_code':3,'error_type':type(exc).__name__,'message':str(exc)},3
    print(json.dumps(report,sort_keys=True));sys.exit(code)
'''
OWNED = {WRAPPER_PATH: (WRAPPER, 0o755), '/etc/cron.daily/logrotate': (DAILY, 0o755),
         '/etc/cron.d/home-lab-logrotate': (CRON, 0o644), '/usr/local/sbin/home-lab-log-health': (HEALTH_SCRIPT, 0o755)}
REQUIRED_BINARIES = ['/usr/bin/flock','/usr/bin/timeout','/usr/sbin/logrotate','/bin/sh','/bin/systemctl','/usr/bin/logger']
BACKUP_BASE = '/root/home-lab-hardening-backups'


def digest(value):
    if not isinstance(value, bytes): value = value.encode('utf-8')
    return hashlib.sha256(value).hexdigest()


def read(path):
    with open(path, 'rb') as stream: return stream.read().decode('utf-8')


def command(args, stdin=None):
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate(stdin.encode('utf-8') if stdin is not None else None)
    return process.returncode, out.decode('utf-8','replace'), err.decode('utf-8','replace')


def write_atomic(path, value, mode, uid=None, gid=None):
    directory = os.path.dirname(path)
    if not os.path.isdir(directory): os.makedirs(directory, 0o755)
    fd, temporary = tempfile.mkstemp(prefix='.home-lab-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value.encode('utf-8'));stream.flush();os.fsync(stream.fileno())
            os.fchmod(stream.fileno(),mode)
            if uid is not None and os.geteuid() == 0:os.fchown(stream.fileno(),uid,gid)
        os.rename(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def reconcile(root='/', apply=False, runner=command):
    root = root.rstrip('/')
    path = lambda name: root + name
    for binary in REQUIRED_BINARIES:
        if not os.path.isfile(path(binary)) or not os.access(path(binary),os.X_OK):
            raise ValueError('Required installed executable unavailable: '+binary)
    if read(path('/etc/logrotate.conf')) != ORIGINAL_POLICY:
        raise ValueError('Global logrotate policy differs from reviewed daily/31/100MiB/compression policy; refusing overwrite')
    if read(path('/etc/cron.daily/logrotate')) not in (ORIGINAL_DAILY,DAILY):
        raise ValueError('Existing packaged daily script differs from reviewed exact content; refusing overwrite')
    for name,(content,mode) in OWNED.items():
        if name != '/etc/cron.daily/logrotate' and os.path.lexists(path(name)):
            if os.path.islink(path(name)) or read(path(name)) != content:
                raise ValueError('Owned destination already has unexpected content/type: '+name)
    if os.path.islink(path('/etc/cron.daily/logrotate')):
        raise ValueError('Daily script is unexpectedly a symlink')
    checks = [('configuration_parse_debug_empty_state',[path('/usr/sbin/logrotate'),'-d','-s','/dev/null',path('/etc/logrotate.conf')],None),
              ('cron_service',[path('/bin/systemctl'),'is-active','crond'],None),
              ('wrapper_shell_syntax',[path('/bin/sh'),'-n'],WRAPPER),
              ('daily_shell_syntax',[path('/bin/sh'),'-n'],DAILY),
              ('cron_command_syntax',[path('/bin/sh'),'-n'],CRON.split('root ',1)[1])]
    validated=[]
    for label,args,stdin in checks:
        rc,out,err=runner(args,stdin)
        if rc != 0:raise ValueError('Validation failed: '+label+' exit='+str(rc))
        validated.append(label)
    compile(HEALTH_SCRIPT,'<health-script>','exec')
    # Empty-state debug validates parsing without simulating due rotations. Inspect real state separately.
    real_rc,real_out,real_err=runner([path('/usr/sbin/logrotate'),'-d','-s',path('/var/lib/logrotate/logrotate.status'),path('/etc/logrotate.conf')],None)
    warnings=[]
    if real_rc:
        output=real_out+'\n'+real_err
        errors=[line.strip() for line in output.splitlines() if line.strip().startswith('error:')]
        version_rc,version_out,version_err=runner([path('/usr/sbin/logrotate'),'--version'],None)
        previous=path('/var/log/boot.log.7.gz');future=path('/var/log/boot.log.8.gz')
        known=(real_rc==1 and version_rc==0 and 'logrotate 3.8.6' in [line.strip() for line in (version_out+'\n'+version_err).splitlines()]
               and errors==['error: error opening /var/log/boot.log.8.gz: No such file or directory']
               and 'renaming /var/log/boot.log.7.gz to /var/log/boot.log.8.gz' in output
               and 'removing old log /var/log/boot.log.8.gz' in output
               and os.path.isfile(previous) and not os.path.islink(previous) and not os.path.lexists(future))
        if not known:raise ValueError('Real-state debug failed with an unrecognized error; refusing apply')
        warnings.append('logrotate 3.8.6 real-state debug cannot open future boot.log.8.gz after a simulated rename; config parsing passed; normal runtime rotation is still required to exit zero')
    validated.append('real_state_debug_inspected')
    changes=[]
    for name,(content,mode) in sorted(OWNED.items()):
        current=os.stat(path(name)) if os.path.exists(path(name)) else None
        if current is None or read(path(name)) != content or stat.S_IMODE(current.st_mode) != mode or current.st_uid != os.geteuid() or current.st_gid != os.getegid():
            changes.append(name)
    result={'mode':'apply' if apply else 'check','changed':bool(changes),'changed_files':changes,'validated':validated,
            'real_state_debug_exit':real_rc,'warnings':warnings,'preserved_policy_sha256':digest(ORIGINAL_POLICY),'desired_sha256':dict((n,digest(v[0])) for n,v in OWNED.items()),
            'rotation':'normal only, shared lock; 15-minute check and existing daily schedule; unchanged daily/31/100MiB/compression policy'}
    if apply and changes:
        if not os.path.isdir(path(BACKUP_BASE)):os.makedirs(path(BACKUP_BASE),0o700)
        backup=tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%SZ-',time.gmtime()),dir=path(BACKUP_BASE))
        write_atomic(backup+'/logrotate.conf.original',read(path('/etc/logrotate.conf')),0o600)
        manifest={'schema_version':1,'preserved_policy_sha256':digest(ORIGINAL_POLICY),'files':[]}
        for index,name in enumerate(changes):
            entry={'path':name,'installed_sha256':digest(OWNED[name][0]),'original_exists':os.path.exists(path(name))}
            if entry['original_exists']:
                metadata=os.stat(path(name));body=read(path(name));filename=str(index)+'.original'
                write_atomic(backup+'/'+filename,body,0o600)
                entry.update(backup_file=filename,sha256=digest(body),mode=stat.S_IMODE(metadata.st_mode),uid=metadata.st_uid,gid=metadata.st_gid)
            manifest['files'].append(entry)
        write_atomic(backup+'/manifest.json',json.dumps(manifest,sort_keys=True,indent=2)+'\n',0o600)
        for entry in manifest['files']:
            if entry['original_exists'] and digest(read(backup+'/'+entry['backup_file'])) != entry['sha256']:raise ValueError('Fresh original backup verification failed')
        if digest(read(backup+'/logrotate.conf.original')) != digest(ORIGINAL_POLICY):raise ValueError('Fresh policy backup verification failed')
        result['backup_manifest_sha256']=digest(read(backup+'/manifest.json'))
        result['backed_up_original_sha256']=dict((e['path'],e['sha256']) for e in manifest['files'] if e['original_exists'])
        activation_order=[WRAPPER_PATH,'/usr/local/sbin/home-lab-log-health','/etc/cron.daily/logrotate','/etc/cron.d/home-lab-logrotate']
        for name in activation_order:
            if name in changes:write_atomic(path(name),OWNED[name][0],OWNED[name][1],os.geteuid(),os.getegid())
        result['backup_directory']=backup
    return result


def rollback(root, backup, apply=False):
    root=root.rstrip('/')
    base=os.path.realpath(root+BACKUP_BASE)+'/'
    if not os.path.realpath(backup).startswith(base):raise ValueError('Rollback backup must be under the owned private backup directory')
    manifest=json.loads(read(backup+'/manifest.json'))
    for entry in manifest['files']:
        if entry['path'] not in OWNED:raise ValueError('Unexpected rollback destination')
        target=root+entry['path']
        if os.path.lexists(target) and (os.path.islink(target) or digest(read(target)) != entry['installed_sha256']):
            raise ValueError('Current file changed since installation; refusing rollback overwrite: '+entry['path'])
        if entry['original_exists']:
            if '/' in entry['backup_file'] or digest(read(backup+'/'+entry['backup_file'])) != entry['sha256']:
                raise ValueError('Original backup checksum failed')
    if apply:
        for entry in manifest['files']:
            target=root+entry['path']
            if entry['original_exists']:write_atomic(target,read(backup+'/'+entry['backup_file']),entry['mode'],entry['uid'],entry['gid'])
            elif os.path.exists(target):os.unlink(target)
    return {'mode':'rollback-apply' if apply else 'rollback-check','changed':bool(manifest['files']),'files':[e['path'] for e in manifest['files']]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--apply',action='store_true');modes.add_argument('--check',action='store_true')
    parser.add_argument('--rollback',metavar='PRIVATE_BACKUP_DIRECTORY')
    parser.add_argument('--health',action='store_true')
    args=parser.parse_args()
    if args.health:
        code,out,err=command(['/usr/bin/python','-c',HEALTH_SCRIPT]);print(out.strip());return code
    if args.apply and os.geteuid()!=0:raise ValueError('Apply requires root')
    report=rollback('/',args.rollback,args.apply) if args.rollback else reconcile('/',args.apply)
    print(json.dumps(report,sort_keys=True));return 0


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:
        print(json.dumps({'failed':True,'error_type':type(exc).__name__,'message':str(exc)},sort_keys=True));sys.exit(1)
