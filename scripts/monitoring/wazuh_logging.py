#!/usr/bin/env python3
"""Terraform -> Ansible for an existing local Wazuh manager; no cloud resources."""
import argparse
import hashlib
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TF_ROOT = ROOT / 'infra/wazuh-logging'
PHASES = ('logging', 'tailnet', 'all', 'truenas')

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

def guard_plan(plan, agents, phase, template_fix=False):
    validate_agents(agents)
    validate_phase(phase, agents)
    if type(template_fix) is not bool or (template_fix and phase != 'truenas'):
        raise ValueError('Native template repair is an explicit TrueNAS-only boolean')
    if phase not in PHASES or plan.get('errored') or any(c.get('status') != 'pass' for c in plan.get('checks', [])):
        raise ValueError('Plan checks or phase failed')
    resources = plan.get('resource_changes', [])
    if len(resources) != 1:
        raise ValueError('Exactly one local Terraform deployment resource is permitted')
    item = resources[0]
    change = item.get('change', {})
    expected = {'manager': 'wazuh', 'agents': agents, 'phase': phase, 'retention_days': 7}
    if template_fix:
        expected['native_template_fix'] = True
        if (change.get('after') or {}).get('input', {}).get('native_template_fix') is not True:
            raise ValueError('Plan must explicitly declare boolean native_template_fix=true')
    if (item.get('mode') != 'managed' or item.get('address') != 'terraform_data.logging' or item.get('type') != 'terraform_data'
        or item.get('provider_name') != 'terraform.io/builtin/terraform'
        or change.get('actions') not in (['create'], ['no-op'], ['update'], ['delete', 'create'])
        or (change.get('after') or {}).get('input') != expected):
        raise ValueError('Only the exact existing local Wazuh deployment may change; cloud provisioning is forbidden')

def validate_phase(phase, agents):
    if phase not in PHASES or (phase == 'truenas' and agents != []):
        raise ValueError('TrueNAS phase requires an empty agent selection and manager-only inventory')

def template_fix_enabled(config, phase):
    value = config.get('monitoring_truenas_native_template_fix_enabled', False)
    if type(value) is not bool or (value and phase != 'truenas'):
        raise ValueError('Native template repair requires an actual boolean and the explicit TrueNAS phase')
    return value

def inputs(env, phase=None):
    invpath = private_file(env['WAZUH_LOGGING_INVENTORY'])
    varpath = private_file(env['WAZUH_LOGGING_VARS'])
    inv = json.loads(invpath.read_text()); config = json.loads(varpath.read_text())
    agents = config['monitoring_wazuh_selected_agents']; validate_agents(agents)
    if phase is not None:
        validate_phase(phase, agents)
        template_fix_enabled(config, phase)
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

def truenas_review(env, config):
    """Validate and fingerprint private appliance inputs without modifying them."""
    profile_path = private_file(env['WAZUH_TRUENAS_PROFILE'])
    if stat.S_IMODE(profile_path.stat().st_mode) != 0o600:
        raise ValueError('TrueNAS profile must be mode0600')
    profile = json.loads(profile_path.read_text())
    networks = tuple(ipaddress.ip_network(n) for n in
                     ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    addresses = []
    for name in ('monitoring_truenas_receiver_address', 'monitoring_truenas_source_address'):
        address = ipaddress.ip_address(config[name])
        if address.version != 4 or not any(address in n for n in networks):
            raise ValueError('TrueNAS receiver/source require exact RFC1918 IPv4 literals')
        addresses.append(str(address))
    if addresses[0] == addresses[1]:
        raise ValueError('TrueNAS and receiver must be distinct')
    if profile.get('syslogserver') != addresses[0] + ':6514' or profile.get('address') != addresses[1]:
        raise ValueError('Native appliance destination/source differs from receiver policy')
    if 'monitoring_truenas_receiver_install_approved' in config and type(config['monitoring_truenas_receiver_install_approved']) is not bool:
        raise ValueError('Receiver package approval must be an actual boolean')
    directory = Path(profile['pki_directory']).expanduser().absolute()
    info = directory.lstat()
    if (directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
            or directory.resolve().is_relative_to(ROOT)):
        raise ValueError('TrueNAS PKI directory must be owner-only mode0700 outside the repository')
    material_paths = {name: private_file(directory/name) for name in
                      ('ca.pem', 'ca-key.pem', 'server.pem', 'server-key.pem', 'client.pem', 'client-key.pem')}
    for variable, filename in [('monitoring_truenas_ca_file', 'ca.pem'),
                               ('monitoring_truenas_server_cert_file', 'server.pem'),
                               ('monitoring_truenas_server_key_file', 'server-key.pem')]:
        if private_file(config[variable]).resolve() != material_paths[filename].resolve():
            raise ValueError('Receiver material must use the exact reviewed appliance PKI')
    for name in ('server_certificate_file', 'api_key_file'):
        material_paths[name] = private_file(profile[name])
    if any(stat.S_IMODE(path.stat().st_mode) != 0o600 for path in material_paths.values()):
        raise ValueError('Every reviewed TrueNAS material must be mode0600')
    spec = importlib.util.spec_from_file_location('homelab_truenas_client', ROOT/'monitoring/truenas/client.py')
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    client.validate_profile(profile_path, require_key=True)
    client.pki.validate_existing(directory, addresses[0])
    review = {'profile': digest(profile_path),
              'materials': {name: digest(path) for name, path in sorted(material_paths.items())}}
    if template_fix_enabled(config, 'truenas'):
        declaration_path = private_file(env['WAZUH_TRUENAS_BOOTSTRAP'])
        if stat.S_IMODE(declaration_path.stat().st_mode) != 0o600:
            raise ValueError('Native repair declaration must be mode0600')
        declaration = json.loads(declaration_path.read_text())
        if ('native_syslog_usr_remount_enabled' in declaration
                and type(declaration['native_syslog_usr_remount_enabled']) is not bool):
            raise ValueError('Temporary native OS mount approval must be an actual boolean')
        if (declaration.get('console_administration_enabled') is not True
                or declaration.get('native_syslog_template_fix_enabled') is not True):
            raise ValueError('Native repair requires exact console and template-repair declaration booleans')
        for key in ('expected_vm_uuid', 'expected_version', 'address', 'ssh_alias', 'syslogserver'):
            if not profile.get(key) or declaration.get(key) != profile[key]:
                raise ValueError('Native repair declaration differs from the reviewed appliance identity/policy')
        if private_file(declaration['profile_file']).resolve() != profile_path.resolve():
            raise ValueError('Native repair declaration must select the exact reviewed profile')
        for key in ('api_key_file', 'server_certificate_file'):
            if private_file(declaration[key]).resolve() != material_paths[key].resolve():
                raise ValueError('Native repair declaration credential/trust paths differ from the profile')
        if Path(declaration['pki_directory']).expanduser().absolute() != directory:
            raise ValueError('Native repair declaration PKI differs from the profile')
        review.update(native_template_fix=True, bootstrap=digest(declaration_path))
    return review

def source_digest():
    paths = set()
    for pattern in ('monitoring/wazuh/**/*', 'monitoring/truenas/**/*.py', 'ansible/roles/monitoring_wazuh_*/**/*',
                    'ansible/playbooks/wazuh-logging*.yml', 'scripts/monitoring/wazuh_logging.py',
                    'infra/wazuh-logging/*.tf'):
        paths.update(p for p in ROOT.glob(pattern) if p.is_file() and p.suffix in ('.py', '.json', '.xml', '.conf', '.yml', '.tf', '.j2'))
    return hashlib.sha256(json.dumps({str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}, sort_keys=True).encode()).hexdigest()

def tf(env, *args, capture=False):
    return subprocess.run(['terraform', '-chdir='+str(TF_ROOT), *args], cwd=ROOT, env=env,
        check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout

def deploy(env, phase):
    invpath, varpath, config = inputs(env, phase)
    template_fix = template_fix_enabled(config, phase)
    if phase not in PHASES: raise ValueError('Invalid deployment phase')
    if phase == 'truenas':
        truenas_review(env, config)
    command = [env.get('ANSIBLE_PLAYBOOK_BIN', 'ansible-playbook'), '-i', str(invpath),
        str(ROOT/'ansible/playbooks/wazuh-logging.yml'), '-e', '@'+str(varpath),
        '-e', json.dumps({'monitoring_deployment_approved': True}),
        '--tags', 'logging,tailnet' if phase == 'all' else phase]
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    if phase == 'truenas':
        if template_fix:
            subprocess.run([sys.executable, str(ROOT/'monitoring/truenas/native_fix.py'),
                            '--declaration', str(private_file(env['WAZUH_TRUENAS_BOOTSTRAP']))],
                           cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, str(ROOT/'monitoring/truenas/client.py'),
                        'configure', '--profile', str(private_file(env['WAZUH_TRUENAS_PROFILE']))],
                       cwd=ROOT, env=env, check=True)

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
    invpath, varpath, config = inputs(env, args.phase)
    template_fix = template_fix_enabled(config, args.phase)
    truenas = truenas_review(env, config) if args.phase == 'truenas' else None
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
            '-var=truenas_template_fix='+str(template_fix).lower(),
            '-var=agents='+json.dumps(config['monitoring_wazuh_selected_agents']), '-out='+str(plan)]
        if args.redeploy: command.append('-replace=terraform_data.logging')
        tf(env, *command, capture=True); plan.chmod(0o600)
    private_file(plan)
    data = json.loads(tf(env, 'show', '-json', str(plan), capture=True))
    guard_plan(data, config['monitoring_wazuh_selected_agents'], args.phase, template_fix)
    review = {'plan': digest(plan), 'inventory': digest(invpath), 'variables': digest(varpath), 'phase': args.phase, 'source': source_digest()}
    if truenas is not None:
        review['truenas'] = truenas
    print('Reviewed local Wazuh plan: existing manager, agents '+json.dumps(config['monitoring_wazuh_selected_agents'])+', phase '+args.phase+', native template repair '+str(template_fix).lower()+'; no cloud resources.', flush=True)
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
