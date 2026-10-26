#!/usr/bin/env python
"""Restore only reviewed local recovery assets into an XCP-ng 8.3 installer target."""
from __future__ import print_function
import argparse,base64,hashlib,json,os,re,socket,stat,subprocess,tempfile

ALLOWED={
 '/usr/local/sbin/direct-cable-network':0o755,
 '/etc/home-lab/direct-cable-network.conf':0o600,
 '/etc/systemd/system/direct-cable-network.service':0o644,
 '/etc/systemd/system/direct-cable-network.timer':0o644,
 '/usr/local/sbin/home-lab-logrotate':0o755,
 '/usr/local/sbin/home-lab-log-health':0o755,
 '/etc/cron.daily/logrotate':0o755,
 '/etc/cron.d/home-lab-logrotate':0o644,
}

def resolver_config(servers):
 if not isinstance(servers,list) or not servers:raise ValueError('Installer resolvers must be a nonempty list')
 for server in servers:
  try:
   if not re.match(r'^[0-9.]+\Z',server):raise ValueError('Expected a numeric IPv4 resolver')
   socket.inet_pton(socket.AF_INET,server)
  except (TypeError,socket.error):raise ValueError('Expected a numeric IPv4 resolver')
 return ''.join('nameserver '+server+'\n' for server in servers).encode('ascii')

def verify_device(device):
 if not stat.S_ISBLK(os.stat(device).st_mode):raise ValueError('Permanent storage identity is not an available block device')

def restore_links(target,links,apply=False):
 """Reconcile legacy aliases only; never partition, format, mount or attach disks."""
 root=os.path.realpath(target);pending=[]
 if not isinstance(links,dict):raise ValueError('Storage mappings must be a dictionary')
 for name,device in sorted(links.items()):
  if not re.match(r'^/passthrough-drives/([A-Za-z0-9_-]+)/\1\Z',name):raise ValueError('Unreviewed raw-disk alias path')
  if not re.match(r'^/dev/disk/by-id/(?:ata-|wwn-|nvme-)[A-Za-z0-9_.:-]+\Z',device) or re.search(r'-part[0-9]+$',device):raise ValueError('Raw-disk mappings require permanent whole-device identities')
  path=os.path.join(root,name.lstrip('/'));parent=os.path.realpath(os.path.dirname(path))
  if root!='/' and not parent.startswith(root+os.sep):raise ValueError('Storage mapping escapes installer target')
  if root=='/' and parent!=os.path.dirname(path):raise ValueError('Storage mapping parent is redirected')
  verify_device(device)
  if os.path.lexists(path) and not os.path.islink(path):raise ValueError('Refusing to overwrite a non-symlink storage mapping')
  if os.path.islink(path) and os.readlink(path)==device:continue
  if root=='/' and os.path.islink(path) and os.path.realpath(path)!=os.path.realpath(device):raise ValueError('Refusing to redirect an existing alias to a different physical disk')
  pending.append((path,device,name))
 if apply:
  for path,device,name in pending:
   parent=os.path.dirname(path)
   if not os.path.isdir(parent):os.makedirs(parent,0o755)
   fd,temporary=tempfile.mkstemp(prefix='.home-lab-link-',dir=parent);os.close(fd);os.unlink(temporary)
   try:os.symlink(device,temporary);os.rename(temporary,path)
   finally:
    if os.path.lexists(temporary):os.unlink(temporary)
 return [name for path,device,name in pending]

def validate(target,bundle):
 root=os.path.realpath(target)
 if root=='/' or not os.path.isdir(root):raise ValueError('Only an existing offline installer target is allowed')
 inventory={}
 try:
  with open(os.path.join(root,'etc/xensource-inventory')) as stream:
   for line in stream:
    if '=' in line:
     k,v=line.strip().split('=',1);inventory[k]=v.strip("'\"")
 except IOError:raise ValueError('Installer target identity is unavailable')
 if not inventory.get('PRODUCT_VERSION','').startswith('8.3.') or inventory.get('INSTALLATION_UUID')!=bundle.get('host_uuid'):
  raise ValueError('Installer release or host identity differs from the reviewed upgrade')
 if not re.match(r'^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?\Z',bundle.get('public_key','')):raise ValueError('Expected one owner public key')
 files=bundle.get('files',{})
 if not isinstance(files,dict) or not files:raise ValueError('Recovery asset bundle is empty')
 for name,entry in files.items():
  if name not in ALLOWED or entry.get('mode')!=ALLOWED[name]:raise ValueError('Unreviewed recovery asset path or permissions')
  path=os.path.realpath(os.path.join(root,name.lstrip('/')))
  if not path.startswith(root+os.sep):raise ValueError('Recovery path escapes the target')
  body=base64.b64decode(entry['content'])
  if hashlib.sha256(body).hexdigest()!=entry['sha256']:raise ValueError('Recovery asset digest differs')
 for name in ['root/.ssh','root/.ssh/authorized_keys','var/lib/home-lab']:
  path=os.path.realpath(os.path.join(root,name))
  if not path.startswith(root+os.sep):raise ValueError('Private recovery path escapes the target')
 restore_links(root,bundle.get('storage_links',{}),False)
 return root

def write(path,body,mode):
 directory=os.path.dirname(path)
 if not os.path.isdir(directory):os.makedirs(directory,0o755)
 descriptor,temporary=tempfile.mkstemp(prefix='.home-lab-upgrade-',dir=directory)
 try:
  with os.fdopen(descriptor,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
  os.chmod(temporary,mode);os.chown(temporary,0,0);os.rename(temporary,path)
 finally:
  if os.path.exists(temporary):os.unlink(temporary)

def reboot_ready(installer_exit,marker,host_uuid,bundle_sha256):
 return str(installer_exit)=='0' and isinstance(marker,dict) and marker.get('host_uuid')==host_uuid and marker.get('bundle_sha256')==bundle_sha256

def restore(target,bundle):
 root=validate(target,bundle)
 for name,entry in sorted(bundle['files'].items()):write(root+name,base64.b64decode(entry['content']),entry['mode'])
 restore_links(root,bundle.get('storage_links',{}),True)
 private=root+'/etc/home-lab';os.chmod(private,0o700);os.chown(private,0,0)
 directory=root+'/root/.ssh'
 if not os.path.isdir(directory):os.makedirs(directory,0o700)
 os.chmod(directory,0o700);os.chown(directory,0,0)
 path=directory+'/authorized_keys'
 old=open(path,'rb').read() if os.path.isfile(path) else b''
 key=bundle['public_key'].encode('utf-8');words=key.split();present=False
 for line in old.splitlines():
  parts=line.split()
  if b'ssh-ed25519' in parts:
   i=parts.index(b'ssh-ed25519')
   if len(parts)>i+1 and parts[i+1]==words[1]:present=True
 content=old if present else old+(b'' if not old or old.endswith(b'\n') else b'\n')+b'no-agent-forwarding,no-X11-forwarding '+key+b'\n'
 write(path,content,0o600)
 for unit in ['sshd.service','rsyslog.service','chronyd.service','crond.service','xapi-domains.service','direct-cable-network.service','direct-cable-network.timer']:
  subprocess.check_call(['systemctl','--root='+root,'enable',unit])
 result={'restored_files':sorted(bundle['files']),'storage_links':bundle.get('storage_links',{}),'owner_public_key_present':True,'native_guest_autostart_enabled':True,'mode':'offline XCP-ng 8.3 upgrade target; no disk or VM definitions created/deleted'}
 directory=root+'/var/lib/home-lab'
 if not os.path.isdir(directory):os.makedirs(directory,0o700)
 write(directory+'/upgrade-recovery.json',(json.dumps(result,indent=2)+'\n').encode('utf-8'),0o600)
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('target');parser.add_argument('--bundle-base64',required=True);args=parser.parse_args()
 if os.geteuid()!=0:raise ValueError('Installer restoration requires existing root authorization')
 bundle=json.loads(base64.b64decode(args.bundle_base64).decode('utf-8'))
 print(json.dumps(restore(args.target,bundle)))

if __name__=='__main__':main()
