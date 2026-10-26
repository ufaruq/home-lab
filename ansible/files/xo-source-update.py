#!/usr/bin/python3
"""Build official XO master before activation; back up Redis and roll back failed health checks."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import selectors
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import urllib.error

BASE=Path('/opt/home-lab/xo')
STATE=Path('/var/lib/home-lab-xo')
CONFIG=Path('/etc/home-lab/xo-source.json')
OVERRIDE=Path('/etc/systemd/system/xo-server.service.d/90-home-lab-source.conf')
REPOSITORY='https://github.com/vatesfr/xen-orchestra.git'
YARN_INTEGRITY='prL3kGtyG7o9Z9Sv8IPfBNrWTDmXB4Qbes8A9rEzt6wkJV8mUvoirjU0Mp3GGAU06Y0XQyA3/2/RQFVuK7MTfg=='

def select_node(rows,major):
    candidates=[r['version'] for r in rows if r.get('lts') and 'linux-x64' in r.get('files',[]) and re.fullmatch(r'v'+str(major)+r'\.\d+\.\d+',r.get('version',''))]
    if not candidates:raise ValueError('No supported Linux x64 LTS runtime in the configured major line')
    return max(candidates,key=lambda v:tuple(map(int,v[1:].split('.'))))

def parse_head(text):
    rows=[line.split() for line in text.splitlines() if line.strip()]
    if len(rows)!=1 or len(rows[0])!=2 or rows[0][1]!='refs/heads/master' or not re.fullmatch('[0-9a-f]{40}',rows[0][0]):
        raise ValueError('Official master must resolve to exactly one Git commit')
    return rows[0][0]

def archive_checksum(text,filename):
    matches=[row[0] for line in text.splitlines() if len(row:=line.split())==2 and row[1].lstrip('*')==filename and re.fullmatch('[0-9a-f]{64}',row[0])]
    if len(matches)!=1:raise ValueError('Expected one exact upstream archive checksum')
    return matches[0]

def verify_build(source):
    for name in ['packages/xo-server/dist/cli.mjs','packages/xo-web/dist/index.html','@xen-orchestra/web/dist/index.html']:
        if not (source/name).is_file():raise ValueError('Incomplete XO build: '+name)

def activate_with_rollback(stop,backup,switch,start,health,stop_candidate,restore,switch_old,start_old):
    stop()
    try:backup()
    except BaseException:
        start_old();raise
    try:
        switch();start();health()
    except BaseException:
        stop_candidate();restore();switch_old();start_old();raise

def copy_state_tree(source,destination):
    def transient(directory,names):
        return [name for name in names if stat.S_ISSOCK(os.lstat(Path(directory)/name).st_mode) or stat.S_ISFIFO(os.lstat(Path(directory)/name).st_mode)]
    shutil.copytree(source,destination,symlinks=True,ignore=transient)

def run(args,**kw):
    return subprocess.run([str(a) for a in args],check=True,text=True,**kw)

def fetch(url,limit=20*1024*1024):
    with urllib.request.urlopen(url,timeout=60) as response:
        data=response.read(limit+1)
    if len(data)>limit:raise ValueError('Upstream response exceeded its size limit')
    return data

def atomic(path,data,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    descriptor,name=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    temporary=Path(name)
    try:
        with os.fdopen(descriptor,'w') as output:output.write(data);output.flush();os.fsync(output.fileno())
        temporary.chmod(mode);temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)

def freeze_release(root,uid=0,gid=0):
    root=root.resolve()
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in [Path(directory),*[Path(directory)/f for f in dirs+files]]:
            if name.is_symlink():
                if not name.resolve().is_relative_to(root):raise ValueError('Build symlink escapes the release')
                os.chown(name,uid,gid,follow_symlinks=False)
            else:
                info=name.stat()
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):raise ValueError('Unexpected special file in build')
                if stat.S_ISREG(info.st_mode) and info.st_nlink>1:
                    descriptor,temporary=tempfile.mkstemp(prefix='.promote-',dir=name.parent)
                    try:
                        with name.open('rb') as source,os.fdopen(descriptor,'wb') as target:shutil.copyfileobj(source,target)
                        os.replace(temporary,name)
                    finally:Path(temporary).unlink(missing_ok=True)
                os.chown(name,uid,gid,follow_symlinks=False)
                name.chmod(0o755 if name.is_dir() or info.st_mode&0o111 else 0o644)

def prune(base,state,current,previous):
    keep={p.resolve() for p in (current,previous) if p is not None}
    for release in (base/'releases').iterdir():
        if release.is_dir() and not release.is_symlink() and re.fullmatch(r'[0-9a-f]{40}-v24\.\d+\.\d+',release.name) and release.resolve() not in keep:
            shutil.rmtree(release)
    backups=sorted(p for p in (state/'backups').iterdir() if p.is_dir() and not p.is_symlink() and re.fullmatch(r'\d{8}T\d{6}Z',p.name))
    for backup in backups[:-7]:shutil.rmtree(backup)
    logs=sorted(state.glob('build-*.log'),key=lambda p:p.stat().st_mtime,reverse=True)
    for log in logs[7:]:log.unlink()
    runtimes={str((p/'node').resolve()) for p in keep if (p/'node').is_symlink()}
    if (base/'runtimes').exists():
        for node in (base/'runtimes').iterdir():
            if node.is_dir() and not node.is_symlink() and re.fullmatch(r'v24\.\d+\.\d+',node.name) and str(node.resolve()) not in runtimes:shutil.rmtree(node)

def extract(archive,destination):
    destination.mkdir(parents=True,exist_ok=True)
    root=destination.resolve()
    with tarfile.open(archive) as tar:
        members=tar.getmembers();links={PurePosixPath(m.name) for m in members if m.issym() or m.islnk()};seen=set()
        for member in members:
            path=PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or path in seen or any(p in links for p in path.parents):raise ValueError('Unsafe archive member path')
            seen.add(path)
            if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):raise ValueError('Special archive member refused')
            if member.issym() or member.islnk():
                target=(root/path).parent/member.linkname if member.issym() else root/member.linkname
                if not target.resolve().is_relative_to(root):raise ValueError('Archive link escapes its destination')
                relative=PurePosixPath(target.resolve().relative_to(root))
                if relative in links or any(p in links for p in relative.parents):raise ValueError('Archive link chains require review')
        # Extract ordinary files before links; refuse members beneath a link, including later ones.
        for member in sorted(members,key=lambda m:m.issym() or m.islnk()):
            tar.extract(member,path=root,set_attrs=False)
            path=root/member.name
            if not path.is_symlink():path.chmod(0o755 if member.isdir() or member.mode&0o111 else 0o644)
    for directory,dirs,_ in os.walk(root,followlinks=False):Path(directory).chmod(0o755)

def runtime(major):
    version=select_node(json.loads(fetch('https://nodejs.org/dist/index.json')),major)
    target=BASE/'runtimes'/version
    if (target/'bin/node').is_file():return target,version
    if shutil.disk_usage(BASE).free<1024**3:raise ValueError('Runtime download requires a 1 GiB reserve')
    filename='node-'+version+'-linux-x64.tar.xz'
    url='https://nodejs.org/dist/'+version+'/'
    digest=archive_checksum(fetch(url+'SHASUMS256.txt').decode(),filename)
    archive=fetch(url+filename,100*1024*1024)
    if hashlib.sha256(archive).hexdigest()!=digest:raise ValueError('Node archive digest mismatch')
    with tempfile.TemporaryDirectory(dir=BASE) as temporary:
        tmp=Path(temporary);(tmp/filename).write_bytes(archive);extract(tmp/filename,tmp/'unpacked')
        source=tmp/'unpacked'/filename.removesuffix('.tar.xz')
        target.parent.mkdir(exist_ok=True);source.rename(target)
    return target,version

PROBE=r'''
const input=JSON.parse(require('fs').readFileSync(0,'utf8'));
const ws=new WebSocket('ws://127.0.0.1/api/');let id=0;const pending=new Map();
const timer=setTimeout(()=>{process.exit(2)},12000);
function call(method,params){return new Promise((resolve,reject)=>{const key=++id;pending.set(key,{resolve,reject});ws.send(JSON.stringify({jsonrpc:'2.0',id:key,method,params}));});}
ws.addEventListener('message',event=>{let d;try{d=JSON.parse(event.data)}catch{return};const p=pending.get(d.id);if(!p)return;pending.delete(d.id);d.error?p.reject(new Error('XO API rejected request')):p.resolve(d.result);});
ws.addEventListener('error',()=>process.exit(2));
ws.addEventListener('open',async()=>{try{
 await call('session.signIn',{email:input.email,password:input.password});
 const objects=Object.values(await call('xo.getAllObjects',{}));
 const methods=await call('system.getMethodsInfo',{});let configuredJobs=0,activeJobs=0;
 for(const method of ['backupNg.getAllJobs','job.getAll','metadataBackup.getAllJobs','mirrorBackup.getAllJobs']){
   if(methods[method]===undefined){if(['backupNg.getAllJobs','job.getAll'].includes(method))throw new Error('Missing job inspection API');continue;}
   const result=await call(method,{});if(result===null||typeof result!=='object')throw new Error('Invalid job list');
   const jobs=Object.values(result);configuredJobs+=jobs.length;activeJobs+=jobs.filter(j=>j.runId!==undefined&&j.runId!==null).length;
 }
 const ids=type=>objects.filter(x=>x.type===type).map(x=>x.id).sort();
 const tasks=objects.filter(x=>x.type==='task' && !['success','failure','cancelled'].includes(x.status));
 console.log(JSON.stringify({vms:ids('VM'),hosts:ids('host'),pools:ids('pool'),active_tasks:tasks.length,configured_jobs:configuredJobs,active_jobs:activeJobs}));
 clearTimeout(timer);ws.close();
}catch{process.exit(2)}});
'''

def probe(node,config):
    result=run([node/'bin/node','-e',PROBE],input=json.dumps(config['health_login']),capture_output=True,timeout=20)
    return json.loads(result.stdout)

def pending_rest_tasks(config,allow_legacy=False):
    login=config['health_login'];encoded=base64.b64encode((login['email']+':'+login['password']).encode()).decode()
    request=urllib.request.Request('http://127.0.0.1/rest/v0/tasks?filter=status%3Apending&limit=1',headers={'Authorization':'Basic '+encoded,'Accept':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=15) as response:
            if 'application/json' not in response.headers.get('Content-Type',''):return None
            result=json.loads(response.read(1048576))
    except urllib.error.HTTPError as error:
        if error.code==404 or allow_legacy and error.code in (401,403):return None
        raise ValueError('Could not authenticate/read XO task status') from None
    if not isinstance(result,list):raise ValueError('Unexpected XO task status response')
    return len(result)

def require_idle(baseline,pending,initial=False):
    if baseline['active_tasks'] or baseline['active_jobs'] or pending:raise ValueError('XO has active tasks/jobs; maintenance postponed')
    if pending is None and not (initial and baseline['configured_jobs']==0):raise ValueError('Cannot verify XO application task status; automatic cutover refused')

def bounded_log(output,data,limit=16*1024*1024):
    if output.tell()+len(data)>limit:output.seek(0);output.truncate()
    output.write(data[-limit:]);output.flush()

def build_command(arguments,cwd,output):
    process=subprocess.Popen([str(x) for x in arguments],cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        deadline=time.monotonic()+1800
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic()>deadline:raise RuntimeError('Build exceeded its 30 minute deadline')
                if shutil.disk_usage(BASE).free<2*1024**3:raise RuntimeError('Build stopped to preserve 2 GiB filesystem reserve')
                for key,_ in selector.select(timeout=0.5):
                    chunk=os.read(key.fd,65536)
                    if chunk:bounded_log(output,chunk)
                    else:selector.unregister(key.fileobj)
        if process.wait()!=0:raise RuntimeError('Build command failed; see bounded private build log')
    except BaseException:
        with contextlib.suppress(ProcessLookupError):os.killpg(process.pid,signal.SIGKILL)
        process.wait();raise
    finally:process.stdout.close()

def source_build(commit,node,version):
    release=BASE/'releases'/(commit+'-'+version)
    if (release/'ready.json').is_file():verify_build(release/'source');return release
    if release.exists():
        if (BASE/'current').is_symlink() and (BASE/'current').resolve()==release:raise ValueError('Current release is incomplete; preserve it for recovery')
        subprocess.run(['pkill','-KILL','-u','xo-build'],check=False)
        shutil.rmtree(release)
    if shutil.disk_usage(BASE).free<5*1024**3:raise ValueError('At least 5 GiB free space is needed before staging an XO build')
    release.mkdir(parents=True)
    shutil.chown(release,user='xo-build',group='xo-build')
    yarn=BASE/'yarn-1.22.22'
    if not (yarn/'bin/yarn.js').is_file():
        blob=fetch('https://registry.npmjs.org/yarn/-/yarn-1.22.22.tgz')
        if base64.b64encode(hashlib.sha512(blob).digest()).decode()!=YARN_INTEGRITY:raise ValueError('Yarn digest mismatch')
        with tempfile.TemporaryDirectory(dir=BASE) as directory:
            temp=Path(directory);(temp/'yarn.tgz').write_bytes(blob);extract(temp/'yarn.tgz',temp/'unpacked');(temp/'unpacked/package').rename(yarn)
    source=release/'source'
    environment=['env','HOME=/var/lib/home-lab-xo-build','XDG_CACHE_HOME=/var/lib/home-lab-xo-build/.cache','YARN_CACHE_FOLDER=/var/lib/home-lab-xo-build/.cache/yarn','npm_config_cache=/var/lib/home-lab-xo-build/.cache/npm','PATH='+str(node/'bin')+':/usr/bin:/bin','NODE_OPTIONS=--max-old-space-size=2048','TURBO_TELEMETRY_DISABLED=1','HUSKY=0']
    prefix=['systemd-run','--wait','--collect','--pipe','--quiet','--uid=xo-build',
            '--property=NoNewPrivileges=yes','--property=PrivateTmp=yes','--property=ProtectSystem=strict',
            '--property=ProtectHome=yes','--property=RuntimeMaxSec=30min',
            '--property=ReadWritePaths='+str(release)+' /var/lib/home-lab-xo-build',
            '--property=IPAddressDeny=127.0.0.0/8 ::1/128 169.254.0.0/16 fe80::/10 fc00::/7 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10']
    log=STATE/('build-'+commit+'.log')
    print('Building XO',commit,'with Node',version,flush=True)
    try:
        with log.open('wb') as output:
            def build(*args,cwd=None):build_command([*prefix,'--working-directory='+str(cwd or BASE),'--',*environment,*args],cwd,output)
            build('git','init',str(source));build('git','remote','add','origin',REPOSITORY,cwd=source)
            build('git','fetch','--depth=1','origin',commit,cwd=source);build('git','checkout','--detach',commit,cwd=source)
            build(node/'bin/node',yarn/'bin/yarn.js','install','--frozen-lockfile','--non-interactive',cwd=source)
            build(node/'bin/node',yarn/'bin/yarn.js','turbo','run','build','--concurrency=2','--filter=xo-server','--filter=xo-server-*','--filter=xo-web','--filter=@xen-orchestra/web','--filter=@xen-orchestra/backup-archive',cwd=source)
            build(node/'bin/node',yarn/'bin/yarn.js','build:doc',cwd=source)
        # No build-account process may keep writable descriptors open into promoted code.
        subprocess.run(['pkill','-KILL','-u','xo-build'],check=False)
        verify_build(source);freeze_release(release)
        (release/'node').symlink_to(node)
        atomic(release/'ready.json',json.dumps({'commit':commit,'node':version}),0o644)
    except BaseException:
        subprocess.run(['pkill','-KILL','-u','xo-build'],check=False)
        shutil.rmtree(release)
        raise
    finally:
        # Yarn caches can be recreated and must not grow with weekly dependency changes.
        shutil.rmtree('/var/lib/home-lab-xo-build/.cache',ignore_errors=True)
    return release

def switch_link(target):
    link=BASE/'current';temp=BASE/'current.new'
    temp.unlink(missing_ok=True);temp.symlink_to(target);temp.replace(link)

def activate(release,node,config,baseline):
    old=(BASE/'current').resolve() if (BASE/'current').is_symlink() else None
    previous=OVERRIDE.read_text() if OVERRIDE.exists() else None
    stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime());backup=STATE/'backups'/stamp;backup.mkdir(parents=True,mode=0o700)
    def stop():run(['systemctl','stop','xo-server.service'])
    def snapshot():
        database=Path(config['redis_directory'])/config['redis_filename']
        if shutil.disk_usage(STATE).free<max(database.stat().st_size*3,1024**3):raise ValueError('Insufficient reserve for safe Redis backup/restore')
        if run(['redis-cli','--raw','CONFIG','GET','appendonly'],capture_output=True).stdout.splitlines()[-1]!='no':
            raise ValueError('Redis AOF is enabled; a reviewed AOF-aware backup/restore is required')
        run(['redis-cli','--rdb',backup/'redis.rdb'],capture_output=True,timeout=60)
        if not (backup/'redis.rdb').is_file() or (backup/'redis.rdb').stat().st_size<10:raise ValueError('Redis backup is missing/empty')
        if Path('/etc/xo-server').exists():copy_state_tree('/etc/xo-server',backup/'xo-server')
        if Path('/var/lib/xo-server/data').exists():copy_state_tree('/var/lib/xo-server/data',backup/'xo-data')
        atomic(backup/'previous.json',json.dumps({'release':str(old) if old else None,'override':previous}))
    def switch():
        switch_link(release)
        atomic(OVERRIDE,'[Service]\nExecStart=\nExecStart=/opt/home-lab/xo/current/node/bin/node /opt/home-lab/xo/current/source/packages/xo-server/dist/cli.mjs\n',0o644)
        run(['systemctl','daemon-reload'])
    def start():run(['systemctl','start','xo-server.service'])
    def health():
        last=None
        for _ in range(24):
            try:
                result=probe(node,config)
                if any(result[k]!=baseline[k] for k in ['vms','hosts','pools']):raise ValueError('XO inventory differs after activation')
                if pending_rest_tasks(config) is None:raise ValueError('New source does not expose the required application task API')
                for path in ['/','/v5/','/v6/']:
                    with urllib.request.urlopen('http://127.0.0.1'+path,timeout=10) as response:
                        if b'<html' not in response.read(8192).lower():raise ValueError('XO web interface did not return HTML')
                run(['systemctl','is-active','--quiet','xo-server.service']);return
            except Exception as e:last=e;time.sleep(5)
        raise RuntimeError('Candidate failed authenticated XO API/inventory health check') from last
    def restore():
        # Stop Redis before replacing its RDB; never restore while the candidate is writing.
        run(['systemctl','stop','redis-server.service'])
        target_dir=Path(config['redis_directory']);filename=config['redis_filename']
        temporary=target_dir/(filename+'.home-lab-restore')
        shutil.copyfile(backup/'redis.rdb',temporary);shutil.chown(temporary,user='redis',group='redis');temporary.chmod(0o640);temporary.replace(target_dir/filename)
        for original,saved in [(Path('/etc/xo-server'),backup/'xo-server'),(Path('/var/lib/xo-server/data'),backup/'xo-data')]:
            if saved.exists():
                if original.exists():original.rename(backup/('failed-'+saved.name))
                copy_state_tree(saved,original)
        run(['systemctl','start','redis-server.service'])
    def old_switch():
        if old:switch_link(old)
        else:(BASE/'current').unlink(missing_ok=True)
        if previous is None:OVERRIDE.unlink(missing_ok=True)
        else:atomic(OVERRIDE,previous,0o644)
        run(['systemctl','daemon-reload'])
    activate_with_rollback(stop,snapshot,switch,start,health,stop,restore,old_switch,start)
    atomic(STATE/'status.json',json.dumps({'commit':release.name[:40],'node':node.name,'activated_at':stamp,'backup':str(backup),'authenticated_inventory_health':True},indent=2))
    prune(BASE,STATE,release,old)

def main():
    parser=argparse.ArgumentParser(description=__doc__);mode=parser.add_mutually_exclusive_group();mode.add_argument('--apply',action='store_true');mode.add_argument('--build-only',action='store_true');mode.add_argument('--status',action='store_true');parser.add_argument('--initial-migration',action='store_true');args=parser.parse_args()
    if os.geteuid()!=0:raise ValueError('Maintenance requires existing root authorization')
    metadata=CONFIG.stat()
    if metadata.st_uid!=0 or not stat.S_ISREG(metadata.st_mode) or metadata.st_mode&0o077:raise ValueError('Private update configuration must be root-owned and owner-only')
    config=json.loads(CONFIG.read_text())
    if config.get('repository')!=REPOSITORY or config.get('branch')!='master' or config.get('node_major')!=24:raise ValueError('Unreviewed update source/runtime policy')
    if config.get('guest_uuid','').lower()!=Path('/sys/hypervisor/uuid').read_text().strip().lower():raise ValueError('Wrong guest identity')
    if args.status:
        record=json.loads((STATE/'status.json').read_text())
        print(json.dumps({key:record[key] for key in ['commit','node','activated_at','authenticated_inventory_health']},indent=2));return
    STATE.mkdir(mode=0o700,exist_ok=True);STATE.chmod(0o700);BASE.mkdir(parents=True,exist_ok=True)
    with (STATE/'update.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        commit=parse_head(run(['git','ls-remote',REPOSITORY,'refs/heads/master'],capture_output=True,timeout=60).stdout)
        if not args.apply and not args.build_only:print(json.dumps({'available_commit':commit,'scope':'check only'}));return
        node,version=runtime(24);release=source_build(commit,node,version)
        if args.build_only:print('Source candidate built and verified without changing the running service');return
        if (BASE/'current').is_symlink() and (BASE/'current').resolve()==release:
            probe(node,config);print('XO source/runtime already current; authenticated API verified');return
        baseline=probe(node,config)
        if args.initial_migration and (STATE/'status.json').exists():raise ValueError('Initial migration exception cannot be reused')
        require_idle(baseline,pending_rest_tasks(config,allow_legacy=args.initial_migration),args.initial_migration)
        activate(release,node,config,baseline)
        print('XO source update activated; authenticated inventory verified')

if __name__=='__main__':
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(RuntimeError('Maintenance interrupted')))
    main()
