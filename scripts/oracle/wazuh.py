#!/usr/bin/env python3
"""Audit, plan and apply only the reviewed Oracle Always Free Wazuh root."""
import argparse
import concurrent.futures
import configparser
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
TF_ROOT = ROOT / 'infra/oracle/wazuh'
REGION = 'us-sanjose-1'
SPEC = importlib.util.spec_from_file_location('monitoring_helpers', ROOT / 'scripts/monitoring/manage.py')
helpers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helpers)
ALLOWED = {
    'oci_limits_quota.free_bounds': 'oci_limits_quota',
    'oci_core_vcn.wazuh': 'oci_core_vcn',
    'oci_core_internet_gateway.wazuh': 'oci_core_internet_gateway',
    'oci_core_route_table.wazuh': 'oci_core_route_table',
    'oci_core_security_list.closed': 'oci_core_security_list',
    'oci_core_subnet.wazuh': 'oci_core_subnet',
    'oci_core_network_security_group.wazuh': 'oci_core_network_security_group',
    'oci_core_instance.wazuh': 'oci_core_instance',
    'oci_core_network_security_group_security_rule.bootstrap_ssh[0]': 'oci_core_network_security_group_security_rule',
    **{f'oci_core_network_security_group_security_rule.outbound_tcp["{port}"]': 'oci_core_network_security_group_security_rule' for port in (80, 443)},
    **{f'oci_core_network_security_group_security_rule.outbound_udp["{port}"]': 'oci_core_network_security_group_security_rule' for port in (123, 3478)},
}


def active(items):
    # A requested deletion is still an allocation until the service confirms
    # its terminal state; counting the overlap is essential for the $0 rule.
    return [item for item in items if item.get('lifecycle-state') not in ('TERMINATED', 'DELETED')]


def assess(snapshot):
    """Reject uncertain eligibility; recommendations and credits are not caps."""
    sub = snapshot['subscription']
    end = dt.datetime.fromisoformat(sub.get('end-date', '').replace('Z', '+00:00'))
    if sub.get('subscription-tier') != 'FREE' or sub.get('payment-model') != 'FREE_TRIAL' or sub.get('lifecycle-state') != 'ACTIVE' or end >= dt.datetime.now(dt.timezone.utc):
        raise ValueError('An actual Free account with expired trial and no paid subscription is required')
    regions = snapshot['regions']
    if len(regions) != 1 or regions[0].get('region-name') != REGION or regions[0].get('is-home-region') is not True or regions[0].get('status') != 'READY' or len(snapshot['ads']) != 1:
        raise ValueError('Only the fully audited single-region San Jose tenancy is supported')
    limits = snapshot['limits']
    if limits['cores'] < 2 or limits['memory'] < 12 or limits['storage'] < 200:
        raise ValueError('Actual free service limits are insufficient')
    instances = active(snapshot['instances'])
    if any(item['shape'] not in ('VM.Standard.E2.1.Micro', 'VM.Standard.A1.Flex') for item in instances) or sum(item['shape'] == 'VM.Standard.E2.1.Micro' for item in instances) > 2:
        raise ValueError('Unexpected existing compute requires a separate cost review')
    own_id = snapshot.get('managed_instance_id')
    own = next((item for item in instances if item['id'] == own_id), None)
    own_cores = own['shape-config']['ocpus'] if own else 0
    own_memory = own['shape-config']['memory-in-gbs'] if own else 0
    if own and (own['shape'] != 'VM.Standard.A1.Flex' or own_cores != 2 or own_memory != 12):
        raise ValueError('Managed instance differs from the fixed free configuration')
    other_cores = snapshot['a1_usage']['cores'] - own_cores
    other_memory = snapshot['a1_usage']['memory'] - own_memory
    if other_cores != 0 or other_memory != 0:
        raise ValueError('Other A1/container usage would exceed the free allocation')
    volumes = active(snapshot['volumes'])
    own_boot = snapshot.get('managed_boot_volume_id') if own else None
    storage = sum(item['size-in-gbs'] for item in volumes if item['id'] != own_boot)
    own_volumes = [item for item in volumes if item['id'] == own_boot]
    if own and (len(own_volumes) != 1 or own_volumes[0]['size-in-gbs'] != 100 or own_volumes[0]['vpus-per-gb'] != 10):
        raise ValueError('Managed boot disk does not match the reviewed size/performance')
    if storage < 0 or storage + 100 > 200 or len(active(snapshot['backups'])) > 5:
        raise ValueError('Combined volumes/backups exceed the reviewed Always Free allowance')
    capacity = snapshot['capacity']
    if capacity != 'AVAILABLE' and not (own and capacity == 'EXISTING_ALLOCATION'):
        raise ValueError('Free ARM provisioning stopped: ' + capacity)
    return {'combined_storage_gb': storage + 100, 'existing_storage_gb': storage, 'other_a1_cores': other_cores, 'other_a1_memory_gb': other_memory}


def guard_plan(plan, image):
    summary = {}
    for item in plan.get('resource_changes', []):
        if item.get('mode') != 'managed':
            continue
        address, kind = item['address'], item['type']
        actions = item['change']['actions']
        if address == 'terraform_data.manager[0]' and kind == 'terraform_data' and item.get('provider_name') == 'terraform.io/builtin/terraform':
            if actions not in (['create'], ['update'], ['no-op'], ['delete', 'create'], ['delete']):
                raise ValueError('Unexpected manager orchestration action')
            summary[address] = actions
            continue
        closing_ssh = address == 'oci_core_network_security_group_security_rule.bootstrap_ssh[0]' and actions == ['delete']
        if ALLOWED.get(address) != kind or item.get('provider_name') != 'registry.terraform.io/oracle/oci' or (actions not in (['create'], ['update'], ['no-op']) and not closing_ssh):
            raise ValueError('Unapproved provider/resource/destructive action: ' + address)
        after = item['change'].get('after') or {}
        if kind == 'oci_limits_quota':
            expected = {
                "set compute-core quota standard-a1-core-count to 2 in tenancy where request.region = 'us-sanjose-1'",
                "set compute-memory quota standard-a1-memory-count to 12 in tenancy where request.region = 'us-sanjose-1'",
                "set block-storage quota total-storage-gb to 200 in tenancy where request.region = 'us-sanjose-1'",
                "zero block-storage quota backup-count in compartment home-lab",
            }
            if set(after.get('statements', [])) != expected or len(after.get('statements', [])) != len(expected):
                raise ValueError('Quota statements differ from reviewed free bounds')
        if kind == 'oci_core_instance':
            shape = after['shape_config'][0]; source = after['source_details'][0]
            if after.get('shape') != 'VM.Standard.A1.Flex' or shape.get('ocpus') != 2 or shape.get('memory_in_gbs') != 12 or source.get('source_id') != image or float(source.get('boot_volume_size_in_gbs', 0)) != 100 or float(source.get('boot_volume_vpus_per_gb', 0)) != 10:
                raise ValueError('Instance/image/storage differs from reviewed free bounds')
        if kind == 'oci_core_security_list' and (after.get('ingress_security_rules') or after.get('egress_security_rules')):
            raise ValueError('Subnet security list must stay closed; only reviewed NSG rules may allow traffic')
        if kind == 'oci_core_network_security_group_security_rule' and not closing_ssh:
            ingress = after.get('direction') == 'INGRESS'
            protocol = after.get('protocol')
            options = after.get('tcp_options' if protocol == '6' else 'udp_options', [])
            port = options[0].get('destination_port_range', [{}])[0] if options else {}
            if ingress:
                source = ipaddress.ip_network(after.get('source', ''), strict=True)
                if address != 'oci_core_network_security_group_security_rule.bootstrap_ssh[0]' or source.version != 4 or source.prefixlen != 32 or not source.network_address.is_global or protocol != '6' or port != {'min': 22, 'max': 22}:
                    raise ValueError('Only temporary SSH from one verified public operator IPv4 is permitted')
            elif after.get('direction') != 'EGRESS' or after.get('destination') != '0.0.0.0/0' or protocol not in ('6', '17') or port.get('min') != port.get('max') or port.get('min') not in ({80, 443} if protocol == '6' else {123, 3478}):
                raise ValueError('Unexpected egress rule')
        summary[address] = actions
    if any(check.get('status') not in ('pass',) for check in plan.get('checks', [])):
        raise ValueError('Terraform checks must all pass before apply')
    return summary


def private_write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def managed_identity():
    state = TF_ROOT / 'terraform.tfstate'
    if not state.exists():
        return {}
    if state.stat().st_uid != os.getuid() or state.stat().st_mode & 0o077:
        raise ValueError('Existing Terraform state must be owner-only')
    identities = [resource['instances'][0]['attributes'] for resource in json.loads(state.read_text()).get('resources', []) if resource.get('mode') == 'managed' and resource.get('type') == 'oci_core_instance' and resource.get('name') == 'wazuh' and not resource.get('module')]
    if len(identities) > 1:
        raise ValueError('Unexpected instance state')
    return identities[0] if identities else {}


def live_audit(profile, image=None):
    config = configparser.ConfigParser()
    config.read(Path.home() / '.oci/config')
    tenancy = config[profile]['tenancy']
    directory = helpers.run_directory()
    base = ['oci', '--profile', profile, '--auth', 'security_token', '--region', REGION]
    def call(args):
        result = subprocess.run(base + args, capture_output=True, text=True, timeout=120)
        if result.returncode:
            logfile = directory / 'oracle-audit-error.log'
            logfile.write_text(result.stdout + result.stderr); logfile.chmod(0o600)
            raise ValueError('Oracle audit failed; inspect private log ' + str(logfile))
        body = json.loads(result.stdout) if result.stdout.strip() else {'data': []}
        return body['data']
    def batch(commands):
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            return dict(zip(commands, pool.map(call, commands.values())))
    discovery = batch({
        'subscriptions': ['organizations', 'subscription', 'list', '--compartment-id', tenancy, '--all'],
        'regions': ['iam', 'region-subscription', 'list', '--tenancy-id', tenancy, '--all'],
        'compartments': ['iam', 'compartment', 'list', '--compartment-id', tenancy, '--compartment-id-in-subtree', 'true', '--access-level', 'ANY', '--all'],
        'ads': ['iam', 'availability-domain', 'list', '--compartment-id', tenancy, '--all'],
    })
    if len(discovery['regions']) != 1 or len(discovery['ads']) != 1:
        raise ValueError('Additional regions/ADs require an expanded audit; no provisioning authorized')
    subs = [s for s in discovery['subscriptions']['items'] if s['lifecycle-state'] == 'ACTIVE']
    if len(subs) != 1:
        raise ValueError('Exactly one active Free subscription must be established')
    compartments = [c for c in discovery['compartments'] if c['lifecycle-state'] == 'ACTIVE']
    labs = [c for c in compartments if c['name'] == 'home-lab' and c['compartment-id'] == tenancy]
    if len(labs) != 1:
        raise ValueError('Existing root-owned home-lab compartment is required')
    lab, ad = labs[0]['id'], discovery['ads'][0]['name']
    commands = {
        'subscription': ['organizations', 'subscription', 'get', '--subscription-id', subs[0]['id']],
        'compute_limits': ['limits', 'value', 'list', '--compartment-id', tenancy, '--service-name', 'compute', '--all'],
        'storage_limits': ['limits', 'value', 'list', '--compartment-id', tenancy, '--service-name', 'block-storage', '--all'],
        'core_usage': ['limits', 'resource-availability', 'get', '--compartment-id', tenancy, '--service-name', 'compute', '--limit-name', 'standard-a1-core-count', '--availability-domain', ad],
        'memory_usage': ['limits', 'resource-availability', 'get', '--compartment-id', tenancy, '--service-name', 'compute', '--limit-name', 'standard-a1-memory-count', '--availability-domain', ad],
    }
    for comp in [tenancy] + [c['id'] for c in compartments]:
        for name, args in {'instances': ['compute', 'instance', 'list'], 'volumes': ['bv', 'volume', 'list'], 'boots': ['bv', 'boot-volume', 'list', '--availability-domain', ad], 'backups': ['bv', 'backup', 'list'], 'bootbackups': ['bv', 'boot-volume-backup', 'list']}.items():
            commands[name + ':' + comp] = args + ['--compartment-id', comp, '--all']
    own = managed_identity()
    selected_image = image or (own.get('source_details') or [{}])[0].get('source_id')
    commands['image'] = ['compute', 'image', 'get', '--image-id', selected_image] if selected_image else ['compute', 'image', 'list', '--compartment-id', lab, '--operating-system', 'Canonical Ubuntu', '--operating-system-version', '22.04', '--shape', 'VM.Standard.A1.Flex', '--sort-by', 'TIMECREATED', '--sort-order', 'DESC', '--limit', '1']
    raw = batch(commands)
    images = raw['image'] if isinstance(raw['image'], list) else [raw['image']]
    if not images or images[0]['operating-system'] != 'Canonical Ubuntu' or images[0]['operating-system-version'] != '22.04' or 'aarch64' not in images[0]['display-name'] or images[0]['lifecycle-state'] != 'AVAILABLE':
        raise ValueError('An available official ARM Ubuntu 22.04 image is required')
    report = call(['compute', 'compute-capacity-report', 'create', '--compartment-id', tenancy, '--availability-domain', ad, '--shape-availabilities', json.dumps([{'instanceShape': 'VM.Standard.A1.Flex', 'instanceShapeConfig': {'ocpus': 2, 'memoryInGBs': 12}}])])
    def limit(key, name):
        values = [item['value'] for item in raw[key] if item['name'] == name and item.get('availability-domain') == ad]
        if len(values) != 1:
            raise ValueError('Could not verify the exact AD service limit: ' + name)
        return values[0]
    snapshot = {'subscription': raw['subscription'], 'regions': discovery['regions'], 'ads': [ad],
                'instances': sum((value for key, value in raw.items() if key.startswith('instances:')), []),
                'volumes': sum((value for key, value in raw.items() if key.startswith(('volumes:', 'boots:'))), []),
                'backups': sum((value for key, value in raw.items() if key.startswith(('backups:', 'bootbackups:'))), []),
                'limits': {'cores': limit('compute_limits', 'standard-a1-core-count'), 'memory': limit('compute_limits', 'standard-a1-memory-count'), 'storage': limit('storage_limits', 'total-free-storage-gb')},
                'a1_usage': {'cores': raw['core_usage']['used'], 'memory': raw['memory_usage']['used']},
                'capacity': report['shape-availabilities'][0]['availability-status'], 'managed_instance_id': own.get('id'), 'managed_boot_volume_id': own.get('boot_volume_id'),
                'tenancy_ocid': tenancy, 'compartment_ocid': lab, 'image_ocid': images[0]['id'], 'availability_domain': ad}
    if any(item['id'] == own.get('id') for item in active(snapshot['instances'])):
        snapshot['capacity'] = 'EXISTING_ALLOCATION'
    private_write(directory / 'oracle-wazuh-audit.json', snapshot)
    return snapshot


def configuration_hash():
    files = [*TF_ROOT.glob('*.tf'), TF_ROOT / '.terraform.lock.hcl', TF_ROOT / 'cloud-init.yaml', Path(__file__),
             ROOT / 'ansible/ansible.cfg', ROOT / 'ansible/inventory/hosts.yml', ROOT / 'monitoring/fleet.json',
             ROOT / 'monitoring/inventory/oracle.yml', ROOT / 'ansible/playbooks/monitoring-wazuh.yml', ROOT / 'ansible/playbooks/monitoring-preflight.yml']
    for directory in ('ansible/roles/monitoring_wazuh_manager', 'monitoring/wazuh', 'scripts/monitoring', 'ansible/filter_plugins', 'ansible/inventory/group_vars'):
        files.extend(p for p in (ROOT / directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
    files = sorted(set(files))
    return hashlib.sha256(''.join(str(p.relative_to(ROOT)) + ':' + hashlib.sha256(p.read_bytes()).hexdigest() for p in files).encode()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('audit', 'plan', 'apply'))
    parser.add_argument('--vars', help='Owner-only JSON inputs outside the repository')
    parser.add_argument('--profile', default='home-lab-bootstrap')
    parser.add_argument('--reconfigure-manager', action='store_true', help='With plan and deploy_manager=true, deliberately replace the creation-only manager record')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        original = helpers.private_json(args.vars) if args.vars else {}
        allowed_inputs = {'tenancy_ocid', 'compartment_ocid', 'availability_domain', 'image_ocid', 'ssh_public_key', 'bootstrap_ssh_cidr', 'oci_profile', 'deploy_manager'}
        if original.keys() - allowed_inputs:
            raise ValueError('Unexpected private Terraform inputs; audit verification cannot be supplied manually')
        if type(original.get('deploy_manager', False)) is not bool:
            raise ValueError('deploy_manager must be an actual JSON boolean')
        if args.reconfigure_manager and (args.command != 'plan' or original.get('deploy_manager') is not True):
            raise ValueError('--reconfigure-manager requires plan with deploy_manager=true')
        profile = original.get('oci_profile', args.profile)
        snapshot = live_audit(profile, original.get('image_ocid'))
        summary = assess(snapshot)
        if args.command == 'audit':
            print(json.dumps({'free_account': True, 'region': REGION, 'capacity': snapshot['capacity'], **summary}, indent=2))
            return 0
        if not args.vars:
            raise ValueError('--vars is required for plan/apply')
        variables = dict(original)
        for key in ('tenancy_ocid', 'compartment_ocid', 'availability_domain', 'image_ocid'):
            if key in variables and variables[key] != snapshot[key]:
                raise ValueError('Private input differs from audited account/image: ' + key)
            variables[key] = snapshot[key]
        variables['oci_profile'] = profile
        variables['audit'] = {'free_account_verified': True, 'capacity_available': True, 'audited_at': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), **{key: summary[key] for key in ('existing_storage_gb', 'other_a1_cores', 'other_a1_memory_gb')}}
        env = helpers.environment()
        if any(key.startswith('TF_CLI_ARGS') for key in env) or env.get('TF_LOG') or env.get('TF_LOG_PROVIDER') or env.get('TF_WORKSPACE', 'default') != 'default':
            raise ValueError('Terraform CLI overrides and debug logs are forbidden for the guarded workflow')
        env['TF_IN_AUTOMATION'] = '1'
        application_inputs = {}
        if original.get('deploy_manager') is True:
            for name in ('MONITORING_PRIVATE_INVENTORY', 'MONITORING_PRIVATE_VARS'):
                path = helpers.private_file(os.environ.get(name, ''))
                application_inputs[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            preflight = helpers.main(['preflight', '--component', 'manager', '--targets', 'oracle_wazuh', '--private-inventory', application_inputs['MONITORING_PRIVATE_INVENTORY']['path'], '--private-vars', application_inputs['MONITORING_PRIVATE_VARS']['path']])
            if preflight:
                raise ValueError('Private manager access/configuration preflight failed')
        run = helpers.run_directory(); plan = run / 'oracle-wazuh.tfplan'; receipt = run / 'oracle-wazuh.review.json'; generated = run / 'oracle-wazuh.inputs.json'
        binary = os.environ.get('TERRAFORM_BIN', 'terraform'); base = [binary, '-chdir=' + str(TF_ROOT)]
        def show():
            result = subprocess.run(base + ['show', '-json', str(plan)], env=env, capture_output=True, text=True)
            if result.returncode:
                raise ValueError('Could not read the saved plan')
            return guard_plan(json.loads(result.stdout), snapshot['image_ocid'])
        def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
        inputs_digest = digest(helpers.private_file(args.vars))
        if args.command == 'plan':
            private_write(generated, variables)
            helpers.logged_run(base + ['init', '-input=false'], 'oracle-init', env)
            replace = ['-replace=terraform_data.manager[0]'] if args.reconfigure_manager else []
            helpers.logged_run(base + ['plan', '-input=false', '-var-file=' + str(generated), '-out=' + str(plan)] + replace, 'oracle-plan', env)
            actions = show()
            private_write(receipt, {'configuration': configuration_hash(), 'inputs': inputs_digest, 'generated': digest(generated), 'plan': digest(plan), 'application_inputs': application_inputs, 'created': time.time()})
            print(json.dumps({'actions': actions, 'plan': str(plan), 'review': str(receipt)}, indent=2))
        else:
            reviewed = helpers.private_json(receipt)
            for path in (generated, plan): helpers.private_file(path)
            expected = {'configuration': configuration_hash(), 'inputs': inputs_digest, 'generated': digest(generated), 'plan': digest(plan), 'application_inputs': application_inputs}
            if any(reviewed.get(key) != value for key, value in expected.items()) or not 0 <= time.time() - reviewed.get('created', 0) <= 900:
                raise ValueError('Saved plan/input/source changed or 15-minute review expired; make a new plan')
            show()
            helpers.logged_run(base + ['apply', '-input=false', str(plan)], 'oracle-apply', env)
            print('Oracle infrastructure apply completed. VPN, Wazuh installation and telemetry still require separate verified rollout.')
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print('Oracle Wazuh stopped: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
