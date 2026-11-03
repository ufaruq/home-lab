#!/usr/bin/env python3
"""Stage only an approved address change for an independently verified agent key."""
import hashlib,hmac,json,os,re,stat,sys
import pwd
from pathlib import Path
import xml.etree.ElementTree as ET

def update(text,previous,manager,port):
    for value in (previous,manager):
        if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}',value):
            raise ValueError('Manager address must be an exact hostname/IP')
    if type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid manager port')
    root=ET.fromstring('<root>'+text+'</root>');clients=root.findall('./ossec_config/client')
    if len(clients)!=1 or len(clients[0].findall('server'))!=1:raise ValueError('Exactly one existing manager connection is required')
    server=clients[0].find('server')
    if server.findtext('address') not in (previous,manager) or server.findtext('protocol','tcp')!='tcp' or server.findtext('port','1514')!=str(port):
        raise ValueError('Current manager/transport differs from reviewed migration')
    blocks=list(re.finditer(r'<client(?:\s[^>]*)?>.*?</client\s*>',text,re.S))
    if len(blocks)!=1:raise ValueError('Ambiguous client block')
    client=blocks[0];servers=list(re.finditer(r'<server(?:\s[^>]*)?>.*?</server\s*>',client.group(),re.S))
    if len(servers)!=1:raise ValueError('Ambiguous server block')
    s=servers[0];addresses=list(re.finditer(r'<address\s*>([^<]*)</address\s*>',s.group(),re.S))
    if len(addresses)!=1 or addresses[0].group(1).strip()!=server.findtext('address'):raise ValueError('Ambiguous address field')
    a=addresses[0];start=client.start()+s.start()+a.start(1);end=client.start()+s.start()+a.end(1)
    return text[:start]+manager+text[end:]

def validate_private_file(info, owners):
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o007:
        raise ValueError('Private package-owned agent files required')

def main():
    if os.geteuid()!=0:raise ValueError('Root required')
    c=json.load(sys.stdin)
    if c.get('migration_approved') is not True or not re.fullmatch(r'[0-9]{3,8}',c.get('agent_id','')) or not re.fullmatch(r'[0-9a-f]{64}',c.get('key_sha256','')):raise ValueError('Explicit migration and trusted key proof required')
    keys=Path('/var/ossec/etc/client.keys');source=Path('/var/ossec/etc/ossec.conf')
    owners={0,pwd.getpwnam('wazuh').pw_uid}
    for p in (keys,source):
        validate_private_file(p.lstat(),owners)
    rows=[x.split() for x in keys.read_text().splitlines() if x.strip() and not x.startswith('#')]
    if len(rows)!=1 or len(rows[0])!=4 or rows[0][0]!=c['agent_id'] or not hmac.compare_digest(hashlib.sha256(rows[0][3].encode()).hexdigest(),c['key_sha256']):raise ValueError('Existing agent key differs from trusted manager proof')
    out=Path(c['output']);parent=out.parent
    if parent.parent!=Path('/var/ossec/etc') or not parent.name.startswith('.homelab-agent-connection-') or parent.is_symlink() or parent.stat().st_uid!=0 or parent.stat().st_mode&0o077 or out.name!='ossec.conf':raise ValueError('Private staging directory required')
    old=source.read_text();new=update(old,c['previous'],c['manager'],c['port'])
    descriptor=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as stream:stream.write(new)
    print(json.dumps({'changed':new!=old}))
if __name__=='__main__':
    try:main()
    except Exception:
        print('Scoped Wazuh agent connection migration failed; inspect verified identity and private inputs.',file=sys.stderr);sys.exit(1)
