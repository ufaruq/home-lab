#!/usr/bin/env python
"""Install reviewed recovery aliases and retry wiring; Python 2.7/3 compatible."""
from __future__ import print_function
import argparse,base64,hashlib,json,os,stat,subprocess,tempfile,time

UNIT='direct-cable-network.service'
TIMER='direct-cable-network.timer'
ALLOWED={'/usr/local/sbin/direct-cable-network':0o755,
 '/etc/home-lab/direct-cable-network.conf':0o600,
 '/etc/systemd/system/'+UNIT:0o644,'/etc/systemd/system/'+TIMER:0o644}

def file_plan(root,assets,accepted):
 root=os.path.realpath(root);changes=[]
 if not isinstance(assets,dict) or not assets:raise ValueError('Recovery assets are required')
 for name,entry in sorted(assets.items()):
  if name not in ALLOWED or entry.get('mode')!=ALLOWED[name]:raise ValueError('Unreviewed recovery path or permissions')
  path=os.path.join(root,name.lstrip('/'))
  if os.path.realpath(path)!=path or os.path.islink(path):raise ValueError('Recovery asset path is redirected')
  body=base64.b64decode(entry['content'])
  if hashlib.sha256(body).hexdigest()!=entry['sha256']:raise ValueError('Recovery asset digest mismatch')
  if os.path.lexists(path):
   info=os.lstat(path)
   if not stat.S_ISREG(info.st_mode):raise ValueError('Recovery asset is not a regular file')
   with open(path,'rb') as stream:digest=hashlib.sha256(stream.read()).hexdigest()
   if digest not in [entry['sha256']]+accepted.get(name,[]):raise ValueError('Existing recovery asset differs from reviewed versions: '+name)
   if digest==entry['sha256'] and stat.S_IMODE(info.st_mode)==entry['mode'] and info.st_uid==0:continue
  changes.append(name)
 return changes

def run(args):
 process=subprocess.Popen(['/usr/bin/timeout','50']+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 out,err=process.communicate()
 if process.returncode:raise ValueError('Recovery service command failed: '+repr(args)+' '+err.decode('utf-8','replace')[-500:])
 return out.decode('utf-8','replace').strip()

def write(path,body,mode):
 parent=os.path.dirname(path)
 if not os.path.isdir(parent):os.makedirs(parent,0o755)
 fd,temporary=tempfile.mkstemp(prefix='.home-lab-recovery-',dir=parent)
 try:
  with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
  os.chmod(temporary,mode);os.chown(temporary,0,0);os.rename(temporary,path)
 finally:
  if os.path.exists(temporary):os.unlink(temporary)

def reconcile(policy,apply=False):
 inventory={}
 for line in open('/etc/xensource-inventory'):
  if '=' in line:
   key,value=line.strip().split('=',1);inventory[key]=value.strip("'\"")
 if inventory.get('INSTALLATION_UUID')!=policy['expected_host_uuid']:raise ValueError('Recovery host identity mismatch')
 if set(policy['assets'])!=set(ALLOWED):raise ValueError('Complete recovery asset set is required')
 changes=file_plan('/',policy['assets'],policy.get('accepted_sha256',{}))
 units={}
 for unit in [UNIT,TIMER]:
  values=dict(line.split('=',1) for line in run(['/bin/systemctl','show',unit,'-p','UnitFileState','-p','ActiveState','-p','DropInPaths','-p','FragmentPath']).splitlines() if '=' in line)
  if values.get('DropInPaths'):raise ValueError('Unexpected recovery service/timer drop-in requires review')
  if values.get('FragmentPath') not in ('','/etc/systemd/system/'+unit):raise ValueError('Unexpected recovery service/timer override requires review')
  units[unit]=values
 wiring=any(v.get('UnitFileState')!='enabled' for v in units.values()) or units[TIMER].get('ActiveState')!='active'
 result={'changed':bool(changes or wiring),'files':changes,'timer_interval_seconds':30,'mode':'apply' if apply else 'check'}
 if not apply:return result
 if os.geteuid()!=0:raise ValueError('Recovery apply requires root')
 if changes:
  parent='/root/home-lab-network-backups'
  if not os.path.isdir(parent):os.makedirs(parent,0o700)
  if os.path.islink(parent) or os.stat(parent).st_uid!=0 or stat.S_IMODE(os.stat(parent).st_mode)&0o077:raise ValueError('Unsafe private backup directory')
  folder=tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%SZ-',time.gmtime()),dir=parent)
  before={name:{'content':base64.b64encode(open(name,'rb').read()).decode('ascii'),'mode':stat.S_IMODE(os.stat(name).st_mode)} if os.path.isfile(name) else None for name in changes}
  write(folder+'/recovery-assets.json',json.dumps(before,indent=2).encode('utf-8'),0o600)
  result['private_backup']=folder
  for name in changes:
   entry=policy['assets'][name];write(name,base64.b64decode(entry['content']),entry['mode'])
  os.chmod('/etc/home-lab',0o700);os.chown('/etc/home-lab',0,0)
  run(['/bin/systemctl','daemon-reload'])
  # The reviewed old oneshot has no ExecStop and owns addresses only. Clearing its
  # RemainAfterExit state permits the timer to invoke the new oneshot repeatedly.
  run(['/bin/systemctl','stop',UNIT])
 for unit in [UNIT,TIMER]:
  if units[unit].get('UnitFileState')!='enabled':run(['/bin/systemctl','enable',unit])
 if changes or wiring:run(['/bin/systemctl','start',UNIT]);run(['/bin/systemctl','start',TIMER])
 if file_plan('/',policy['assets'],{}):raise ValueError('Recovery file verification failed')
 if run(['/bin/systemctl','is-active',TIMER])!='active':raise ValueError('Recovery timer is not active')
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--policy-base64',required=True);parser.add_argument('--apply',action='store_true');args=parser.parse_args()
 print(json.dumps(reconcile(json.loads(base64.b64decode(args.policy_base64)),args.apply)))

if __name__=='__main__':main()
