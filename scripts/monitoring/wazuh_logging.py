#!/usr/bin/env python3
"""Terraform -> Ansible for an existing local Wazuh manager; no cloud resources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TF_ROOT = ROOT / 'infra/wazuh-logging'
PHASES = ('logging', 'tailnet', 'all')

def private_file(value):
    path = Path(value).expanduser().absolute()
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or path.resolve().is_relative_to(ROOT):
        raise ValueError('Inputs/state must be private controller-owned files outside the repository')
    return path

def validate_agents(agents):
    fleet = json.loads((ROOT / 'monitoring/fleet.json').read_text())['hosts']
    if not isinstance(agents, list) or len(agents) != len(set(agents)):
        raise ValueError('Select distinct agent aliases')
    for alias in agents:
        target = fleet.get(alias, {})
        if alias in ('parrot_htb', 'wazuh') or target.get('platform') != 'linux' or 'wazuh-agent' not in target.get('components', []):
            raise ValueError('Only selected guest agents are allowed; Parrot, manager and appliances are excluded')

def guard_plan(plan, agents, phase):
    validate_agents(agents)
    if phase not in PHASES or plan.get('errored') or any(c.get('status') != 'pass' for c in plan.get('checks', [])):
        raise ValueError('Plan checks or phase failed')
    resources = plan.get('resource_changes', [])
    if len(resources) != 1:
        raise ValueError('Exactly one local Terraform deployment resource is permitted')
    item = resources[0]
    change = item.get('change', {})
    expected = {'manager': 'wazuh', 'agents': agents, 'phase': phase, 'retention_days': 7}
    if (item.get('mode') != 'managed' or item.get('address') != 'terraform_data.logging' or item.get('type') != 'terraform_data'
        or item.get('provider_name') != 'terraform.io/builtin/terraform'
        or change.get('actions') not in (['create'], ['no-op'], ['update'], ['delete', 'create'])
        or (change.get('after') or {}).get('input') != expected):
        raise ValueError('Only the exact existing local Wazuh deployment may change; cloud provisioning is forbidden')

def inputs(env):
    invpath = private_file(env['WAZUH_LOGGING_INVENTORY'])
    varpath = private_file(env['WAZUH_LOGGING_VARS'])
    inv = json.loads(invpath.read_text()); config = json.loads(varpath.read_text())
    agents = config['monitoring_wazuh_selected_agents']; validate_agents(agents)
    hosts = inv.get('all', {}).get('hosts', {})
    if set(hosts) != {'wazuh', *agents} or set(inv) != {'all'} or set(inv['all']) != {'hosts'}:
        raise ValueError('Inventory must contain only the exact manager and selected agents')
    for alias, host in hosts.items():
        if host.get('monitoring_access_verified') is not True or not host.get('monitoring_expected_vm_uuid') or not host.get('ansible_host') or not host.get('ansible_user'):
            raise ValueError('Every selected guest requires verified access and expected VM identity')
    if config.get('monitoring_wazuh_mode') != 'adopt' or config.get('monitoring_wazuh_manager_version') != '4.7.5':
        raise ValueError('Only adoption of the existing 4.7.5 manager is supported')
    return invpath, varpath, config

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_digest():
    paths = set()
    for pattern in ('monitoring/wazuh/**/*', 'ansible/roles/monitoring_wazuh_*/**/*',
                    'ansible/playbooks/wazuh-logging*.yml', 'scripts/monitoring/wazuh_logging.py',
                    'infra/wazuh-logging/*.tf'):
        paths.update(p for p in ROOT.glob(pattern) if p.is_file() and p.suffix in ('.py', '.json', '.xml', '.conf', '.yml', '.tf'))
    return hashlib.sha256(json.dumps({str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}, sort_keys=True).encode()).hexdigest()

def tf(env, *args, capture=False):
    return subprocess.run(['terraform', '-chdir='+str(TF_ROOT), *args], cwd=ROOT, env=env,
        check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout

def deploy(env, phase):
    invpath, varpath, config = inputs(env)
    if phase not in PHASES: raise ValueError('Invalid deployment phase')
    command = [env.get('ANSIBLE_PLAYBOOK_BIN', 'ansible-playbook'), '-i', str(invpath),
        str(ROOT/'ansible/playbooks/wazuh-logging.yml'), '-e', '@'+str(varpath),
        '-e', json.dumps({'monitoring_deployment_approved': True}),
        '--tags', 'logging,tailnet' if phase == 'all' else phase]
    subprocess.run(command, cwd=ROOT, env=env, check=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'deploy'))
    parser.add_argument('--phase', choices=PHASES, default='all')
    parser.add_argument('--redeploy', action='store_true')
    args = parser.parse_args(); os.umask(0o077)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(('TF_VAR_', 'TF_LOG', 'TF_CLI_ARGS')):
            env.pop(key)
    invpath, varpath, config = inputs(env)
    env['WAZUH_LOGGING_PYTHON'] = sys.executable
    if args.action == 'deploy': deploy(env, args.phase); return
    directory = Path(env['WAZUH_LOGGING_RUN_DIR']).expanduser().absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if directory.is_symlink() or directory.resolve().is_relative_to(ROOT) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Runtime directory must be controller-owned mode0700 outside the checkout')
    env['TF_DATA_DIR'] = str(directory/'tfdata')
    plan = directory/'deployment.tfplan'; receipt = directory/'review.json'
    tf(env, 'init', '-input=false', '-reconfigure', '-backend-config=path='+str(directory/'terraform.tfstate'), capture=True)
    if args.action == 'plan':
        command = ['plan', '-input=false', '-var=deployment_reviewed=true', '-var=phase='+args.phase,
            '-var=agents='+json.dumps(config['monitoring_wazuh_selected_agents']), '-out='+str(plan)]
        if args.redeploy: command.append('-replace=terraform_data.logging')
        tf(env, *command, capture=True); plan.chmod(0o600)
    private_file(plan)
    data = json.loads(tf(env, 'show', '-json', str(plan), capture=True))
    guard_plan(data, config['monitoring_wazuh_selected_agents'], args.phase)
    review = {'plan': digest(plan), 'inventory': digest(invpath), 'variables': digest(varpath), 'phase': args.phase, 'source': source_digest()}
    print('Reviewed local Wazuh plan: existing manager, agents '+json.dumps(config['monitoring_wazuh_selected_agents'])+', phase '+args.phase+'; no cloud resources.', flush=True)
    if args.action == 'plan':
        receipt.write_text(json.dumps(review)); receipt.chmod(0o600)
    else:
        if json.loads(private_file(receipt).read_text()) != review:
            raise ValueError('Inputs or saved plan changed after review; generate a new plan')
        tf(env, 'apply', '-input=false', str(plan))

if __name__ == '__main__':
    try: main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError):
        print('Local Wazuh deployment stopped; inspect private access, approved inputs and saved plan. No cloud fallback is allowed.', file=sys.stderr)
        sys.exit(2)
