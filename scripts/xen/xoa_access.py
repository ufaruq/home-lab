#!/usr/bin/env python3
"""Converge one explicitly configured private XOA endpoint through Ansible."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'status', 'syntax', 'source-update', 'source-status', 'source-syntax'))
    parser.add_argument('--if-configured', action='store_true')
    parser.add_argument('--bootstrap', action='store_true')
    args = parser.parse_args()
    pointer = ROOT/'.local/xen/xoa-access-inventory'
    value = os.environ.get('XOA_ANSIBLE_INVENTORY')
    if not value and pointer.is_file():
        if stat.S_IMODE(pointer.stat().st_mode) & 0o077:
            raise ValueError('XOA inventory pointer must be owner-only')
        value = pointer.read_text().strip()
    if not value:
        if args.if_configured:
            print('XOA guest access: no private configuration selected; skipped')
            return
        raise ValueError('Set XOA_ANSIBLE_INVENTORY or the owner-only private inventory pointer')
    path = Path(value).expanduser().resolve()
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError('XOA inventory must be an owner-only regular file')
    data = json.loads(path.read_text())
    hosts = data.get('all', {}).get('children', {}).get('xoa_remote_access', {}).get('hosts', {})
    if len(hosts) != 1:
        raise ValueError('Private XOA inventory must identify exactly one endpoint')
    from lab import load_connection
    load_connection()
    binary = os.environ.get('ANSIBLE_PLAYBOOK_BIN', 'ansible-playbook')
    source_action=args.action.startswith('source-')
    playbook='xo-source-action.yml' if source_action else 'xoa-access.yml'
    command = [binary, '-i', str(path), str(ROOT/'ansible/playbooks'/playbook)]
    if args.bootstrap:
        if args.action != 'apply':
            raise ValueError('Bootstrap requires apply')
        command += ['-e', 'xoa_access_bootstrap=true', '-e', 'ansible_user=root']
    if args.action == 'status':
        command += ['-e', 'xoa_access_check_only=true']
    if source_action:
        command += ['-e', 'xo_source_operation='+('update' if args.action=='source-update' else 'status')]
    if args.action in ('syntax','source-syntax'):
        command += ['--syntax-check']
    environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT/'ansible/ansible.cfg'))
    # Shell credentials are not needed by the guest playbook or its child SSH processes.
    for key in ('XOA_TOKEN', 'XOA_PASSWORD', 'XOA_USER', 'XOA_URL'):
        environment.pop(key, None)
    subprocess.run(command, env=environment, cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
