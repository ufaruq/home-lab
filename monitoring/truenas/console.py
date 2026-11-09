"""Bounded native console bootstrap over an already authenticated XCP-ng SSH route.

Only public bootstrap programs may be typed. Secrets return as ciphertext through
the selected guest's nonce-scoped Xenstore entry, never through the screen.
"""
import base64
import json
import re
import secrets
import subprocess
import zlib
from pathlib import Path

VERSION = 'TrueNAS-SCALE-24.04.2.5'
SHIFT = dict(zip('~!@#$%^&*()_+{}|:"<>?', '`1234567890-=[]\\;\',./'))


def key_events(char):
    if char == '\n':
        return [(0xff0d, 1), (0xff0d, 0)]
    if len(char) != 1 or not 32 <= ord(char) < 127:
        raise ValueError('Only printable ASCII and Enter may be typed')
    shifted = char in SHIFT or char.isupper()
    key = ord(char)
    return ([(0xffe1, 1)] if shifted else []) + [(key, 1), (key, 0)] + ([(0xffe1, 0)] if shifted else [])


def console_command(public_script):
    encoded = base64.b64encode(zlib.compress(public_script.encode(), 9)).decode()
    command = "python3 -c 'import sys,zlib,base64;exec(zlib.decompress(base64.b64decode(sys.stdin.buffer.read())))' <<'HOMELAB_BOOTSTRAP'\n"
    command += '\n'.join(encoded[i:i+120] for i in range(0, len(encoded), 120))
    command += '\nHOMELAB_BOOTSTRAP\n'
    if len(command) > 16000 or max(map(len, command.splitlines())) > 3900:
        raise ValueError('Bootstrap program exceeds bounded console transport')
    return command


def verify_identity(reply, expected_uuid):
    if reply.get('uid') != 0 or reply.get('uuid', '').lower() != expected_uuid.lower() or reply.get('version') != VERSION:
        raise ValueError('Authenticated console guest identity/version did not match')


def decode_reply(data):
    if not isinstance(data, str) or len(data) > 2800:
        raise ValueError('Console reply exceeds native quota')
    compressed = base64.b64decode(data, validate=True)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, 8193)
    if len(raw) > 8192 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('Invalid bounded console reply')
    return json.loads(raw)


# Python 2 compatible: XCP-ng dom0 needs no additional packages or persistent files.
REMOTE = r'''
import socket,struct,time,json,subprocess,sys
cfg=CONFIGURATION
def xe(*args):
 return subprocess.check_output(['xe']+list(args)).decode().strip()
uuid=cfg['uuid']
if xe('vm-param-get','uuid='+uuid,'param-name=power-state')!='running':raise ValueError('Guest not running')
domid=xe('vm-param-get','uuid='+uuid,'param-name=dom-id')
if not domid.isdigit() or int(domid)<1:raise ValueError('Invalid guest domain')
path='/local/domain/'+domid+'/data/homelab-'+cfg['nonce']
try:
 subprocess.check_output(['xenstore-read',path],stderr=subprocess.STDOUT)
 raise ValueError('Reply path already exists')
except subprocess.CalledProcessError:pass
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect('/var/run/xen/vnc-'+domid)
def read(n):
 b=b''
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c:raise ValueError('Console closed')
  b+=c
 return b
if not read(12).startswith(b'RFB 003.'):raise ValueError('Unknown console protocol')
s.sendall(b'RFB 003.008\n');n=ord(read(1));types=read(n)
if b'\x01' not in types:raise ValueError('Native console security differs')
s.sendall(b'\x01')
if struct.unpack('>I',read(4))[0]!=0:raise ValueError('Console handshake failed')
s.sendall(b'\x01');init=read(24);read(struct.unpack('>I',init[20:])[0])
if xe('vm-param-get','uuid='+uuid,'param-name=dom-id')!=domid:raise ValueError('Guest domain changed')
def key(k,down):
 s.sendall(struct.pack('>BBHI',4,down,0,k));time.sleep(.01)
# Clear a partial shell line; option 7 opens the native Linux shell from the
# console menu and is a harmless missing command when the shell is already open.
for k,d in [(0xffe1,0),(0xffe2,0),(0xffe3,1),(ord('c'),1),(ord('c'),0),(0xffe3,0)]:key(k,d)
time.sleep(.2)
for k,d in [(ord('7'),1),(ord('7'),0),(0xff0d,1),(0xff0d,0)]:key(k,d)
time.sleep(.5)
script=cfg['script'].replace('XENSTORE_REPLY_PATH',path)
shift=dict(zip('~!@#$%^&*()_+{}|:"<>?', '`1234567890-=[]\\;\',./'))
import base64,zlib
encoded=base64.b64encode(zlib.compress(script.encode(),9)).decode()
line="python3 -c 'import sys,zlib,base64;exec(zlib.decompress(base64.b64decode(sys.stdin.buffer.read())))' <<'HOMELAB_BOOTSTRAP'\n"
line+='\n'.join(encoded[i:i+120] for i in range(0,len(encoded),120))+'\nHOMELAB_BOOTSTRAP\n'
if len(line)>16000 or max(map(len,line.splitlines()))>3900:raise ValueError('Console program too long')
try:
 for c in line:
  if c=='\n':key(0xff0d,1);key(0xff0d,0)
  else:
   shifted=c in shift or c.isupper();k=ord(c)
   if shifted:key(0xffe1,1)
   key(k,1);key(k,0)
   if shifted:key(0xffe1,0)
  time.sleep(.012)
 end=time.time()+45
 while time.time()<end:
  try:
   reply=subprocess.check_output(['xenstore-read',path],stderr=subprocess.STDOUT)
   if len(reply)>4096:raise ValueError('Reply too large')
   sys.stdout.write(json.dumps({'data':reply.decode().strip(),'path':path}));break
  except subprocess.CalledProcessError:time.sleep(.3)
 else:raise ValueError('Native console reply timed out')
finally:
 s.close()
 # Reply is deliberately retained until the controller has durably saved it.
 pass
'''

GUEST = r'''
import os,struct,json,subprocess,socket,ssl,base64,hashlib,zlib
def mid(method,*args):
 data=subprocess.check_output(['midclt','call',method]+[json.dumps(x) for x in args],stderr=subprocess.DEVNULL).decode().strip()
 try:return json.loads(data)
 except json.JSONDecodeError:return data
identity={'uid':os.getuid(),'uuid':open('/sys/hypervisor/uuid').read().strip(),'version':mid('system.version')}
def reply(value):
 payload=b'XENSTORE_REPLY_PATH\0'+base64.b64encode(zlib.compress(json.dumps(value).encode(),9))
 if len(payload)>2048:raise ValueError('Reply too large')
 with open('/dev/xen/xenbus','r+b',buffering=0) as bus:
  bus.write(struct.pack('<IIII',11,1,0,len(payload))+payload)
  h=bus.read(16)
  if len(h)!=16:raise ValueError('Xenstore reply missing')
  kind,req,tx,n=struct.unpack('<IIII',h);result=bus.read(n)
  if kind!=11:raise ValueError('Xenstore write refused: '+result.decode())
'''


def execute(ssh_alias, expected_uuid, public_program):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', ssh_alias) or not re.fullmatch(r'[0-9a-fA-F-]{36}', expected_uuid):
        raise ValueError('Select a verified SSH alias and VM UUID')
    console_command(public_program)
    cfg = {'uuid': expected_uuid, 'nonce': secrets.token_hex(16), 'script': public_program}
    source = REMOTE.replace('CONFIGURATION', repr(cfg), 1)
    result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ConnectTimeout=10', ssh_alias, 'python', '-'], input=source.encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    if result.returncode:
        raise ValueError('Native console bootstrap failed; inspect console privately')
    try:
        envelope = json.loads(result.stdout)
        reply = decode_reply(envelope['data'])
        verify_identity(reply, expected_uuid)
        reply['_console_reply_path'] = envelope['path']
        return reply
    except (ValueError, KeyError, TypeError):
        raise ValueError('Native console identity/reply verification failed') from None


def discover(ssh_alias, expected_uuid):
    # The public certificate is read from inside the already authenticated guest.
    # No HTTP credential is sent on this local metadata-only connection.
    program = GUEST + '''
context=ssl._create_unverified_context()
with socket.create_connection(('127.0.0.1',443),timeout=10) as raw:
 with context.wrap_socket(raw,server_hostname='localhost') as tls:
  cert=tls.getpeercert(binary_form=True)
identity.update({'certificate':ssl.DER_cert_to_PEM_cert(cert),'sha256':hashlib.sha256(cert).hexdigest()})
reply(identity)
'''
    reply = execute(ssh_alias, expected_uuid, program)
    acknowledge(ssh_alias, expected_uuid, reply['_console_reply_path'])
    return reply


def acknowledge(ssh_alias, expected_uuid, reply_path):
    if not re.fullmatch(r'/local/domain/[1-9][0-9]*/data/homelab-[a-f0-9]{32}', reply_path):
        raise ValueError('Invalid owned console reply path')
    program = "import subprocess\n" + "domid=subprocess.check_output(['xe','vm-param-get','uuid='+%r,'param-name=dom-id']).decode().strip()\n" % expected_uuid
    program += "assert %r.startswith('/local/domain/'+domid+'/data/homelab-')\n" % reply_path
    program += "subprocess.check_call(['xenstore-rm',%r])\n" % reply_path
    subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',ssh_alias,'python','-'],
        input=program.encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=True)
