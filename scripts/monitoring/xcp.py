#!/usr/bin/env python3
"""Guarded Terraform/Ansible deployment for datacenter1 and its selected VMs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manage

ROOT = Path(__file__).resolve().parents[2]
TF_ROOT = ROOT / 'infra/xcp-monitoring'

def vm_policy():
    return json.loads((ROOT/'monitoring/xcp/vm-targets.json').read_text())

def validate_vm_policy(config, policy, fleet, observed):
    targets = policy['targets']
    if policy.get('excluded') != ['parrot_htb'] or set(targets) != set(observed)-{'parrot_htb'} or len(targets) != len(set(targets)):
        raise ValueError('VM policy must cover the inventory except Parrot')
    selected = config.get('vm_targets', [])
    if [x['name'] for x in selected] != targets:
        raise ValueError('Private VM selection must match the public policy exactly')
    if observed['parrot_htb']['vm_uuid'] not in config.get('excluded_vm_ids', []):
        raise ValueError('Parrot UUID must be explicitly excluded')
    for target in selected:
        name = target['name']
        if target['expected_name'] != observed[name]['vm_name'] or any(target[k] != fleet[name][k] for k in ('role', 'environment')):
            raise ValueError('VM labels/identity differ from inventory')

def guard_plan(plan):
    if plan.get('errored') or any(x.get('status') != 'pass' for x in plan.get('checks', [])):
        raise ValueError('Terraform checks must all pass')
    for item in plan.get('resource_changes', []):
        if item.get('mode') != 'managed':
            if item.get('address') != 'data.grafana_folder.homelab':
                raise ValueError('Unexpected data resource')
            continue
        actions = item['change']['actions']
        after = item['change'].get('after') or {}
        dashboards = {'grafana_dashboard.xcp_host':'homelab-xcp-host', 'grafana_dashboard.xcp_vms':'homelab-xcp-vms'}
        if item.get('address') in dashboards and item.get('type') == 'grafana_dashboard' and item.get('provider_name') == 'registry.terraform.io/grafana/grafana':
            config = json.loads(after.get('config_json', '{}'))
            if actions not in (['create'], ['update'], ['no-op']) or after.get('folder') != 'homelab-monitoring' or config.get('uid') != dashboards[item['address']]:
                raise ValueError('Only the exact XCP dashboard may be created/updated')
        elif item.get('address') == 'terraform_data.collector' and item.get('type') == 'terraform_data' and item.get('provider_name') == 'terraform.io/builtin/terraform':
            selection = after.get('input') or {}
            if actions not in (['create'], ['update'], ['no-op'], ['delete', 'create']) or selection.get('host_name') != 'datacenter1' or type(selection.get('enabled')) is not bool:
                raise ValueError('Only the exact datacenter1 collector may be reconciled')
            if selection.get('vm_targets') != vm_policy()['targets']:
                raise ValueError('Terraform VM selection must exactly match policy and exclude Parrot')
        else:
            raise ValueError('Unexpected resource; no cloud provisioning is allowed')

def request_json(env, path):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError('Authenticated redirects are refused')
    req = urllib.request.Request(env['GRAFANA_URL'] + path, headers={'Authorization':'Bearer '+env['GRAFANA_AUTH']})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as response:
        return json.load(response)

def verify_zero_cost(env, private):
    policy = json.loads((ROOT / 'monitoring/fleet.json').read_text())['grafana']
    if env['GRAFANA_URL'] != policy['url'].rstrip('/'):
        raise ValueError('Use the existing approved Grafana stack')
    if policy['observed_plan'] == 'trial' and policy.get('trial_collector_apply_enabled') is True:
        manage.verify_unbilled_trial(env)
    elif policy['observed_plan'] == 'free' and policy.get('live_apply_enabled') is True and private.get('xcp_metrics_free_plan_verified') is True:
        settings = request_json(env, '/api/frontend/settings')
        edition = settings.get('licenseInfo', {}).get('edition', '')
        if edition not in ('Cloud', 'Cloud Free', 'Free'):
            raise ValueError('Live account edition differs from verified Free status')
    else:
        raise ValueError('Actual unbilled Trial/Free status must be established before deployment')

def inputs(env):
    inventory = manage.private_file(env['XCP_METRICS_PRIVATE_INVENTORY'])
    variables = manage.private_file(env['XCP_METRICS_PRIVATE_VARS'])
    inv = json.loads(inventory.read_text())
    private = json.loads(variables.read_text())
    hosts = inv.get('all', {}).get('hosts', {})
    if set(hosts) != {'xoa_metrics'} or inv.get('all', {}).get('children'):
        raise ValueError('Private inventory must select exactly xoa_metrics')
    host = hosts['xoa_metrics']
    if set(host) - {'ansible_host', 'ansible_user', 'ansible_python_interpreter'} or host.get('ansible_host') != 'xoa-management' or host.get('ansible_user') != 'lab-automation':
        raise ValueError('Use the existing pinned xoa-management SSH alias/account')
    config = private['xcp_metrics_config']
    observed = json.loads((ROOT / 'ansible/inventory/host_vars/datacenter1.yml').read_text())
    snapshot = json.loads((ROOT / 'xen-server/inventory/local.json').read_text())
    if config['host_name'] != 'datacenter1' or config['host_id'] != observed['xcp_host_uuid'] or config['pool_id'] not in snapshot['pools']:
        raise ValueError('Collector host/pool identity differs from the private inventory')
    if not set(config['storage_ids']).issubset(snapshot['storage_repositories']):
        raise ValueError('Storage selection differs from captured inventory')
    vm_inventory = {name:json.loads((ROOT/f'ansible/inventory/host_vars/{name}.yml').read_text()) for name in vm_policy()['targets'] + vm_policy()['excluded']}
    validate_vm_policy(config, vm_policy(), json.loads((ROOT/'monitoring/fleet.json').read_text())['hosts'], vm_inventory)
    validator = 'const fs=require("fs");require(process.argv[1]).validateConfig(JSON.parse(fs.readFileSync(0,"utf8")));'
    result = subprocess.run(['node', '-e', validator, str(ROOT/'monitoring/xcp/metrics.cjs')], input=json.dumps(config), text=True, capture_output=True)
    if result.returncode:
        raise ValueError('Collector private config failed local validation')
    return inventory, variables, private

def deploy(env, enabled):
    inventory, variables, private = inputs(env)
    verify_zero_cost(env, private)
    source = request_json(env, '/api/datasources/uid/grafanacloud-prom')
    config = private['xcp_metrics_config']
    if urllib.parse.urlsplit(config['metrics_url']).hostname != urllib.parse.urlsplit(source['url']).hostname or config['metrics_username'] != source['basicAuthUser']:
        raise ValueError('Upload destination must match the existing metrics datasource')
    child = dict(env)
    for key in ('GRAFANA_AUTH', 'XOA_USER', 'XOA_PASSWORD', 'XOA_TOKEN', 'XOA_URL'):
        child.pop(key, None)
    command = [env.get('ANSIBLE_PLAYBOOK_BIN', 'ansible-playbook'), '-i', str(inventory), str(ROOT/'ansible/playbooks/monitoring-xcp.yml'), '--limit', 'xoa_metrics', '-e', '@'+str(variables), '-e', json.dumps({'xcp_metrics_enabled':enabled,'xcp_metrics_deployment_approved':True,'xcp_metrics_zero_cost_verified':True})]
    subprocess.run(command, cwd=ROOT, env=child, check=True)

def tf(env, *args, capture=False):
    return subprocess.run(['terraform', '-chdir='+str(TF_ROOT), *args], env=env, cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan','apply','deploy','status'))
    parser.add_argument('--plan')
    parser.add_argument('--disabled', action='store_true')
    parser.add_argument('--redeploy', action='store_true')
    parser.add_argument('--enabled', choices=('true','false'), default='true')
    args=parser.parse_args()
    os.umask(0o077)
    if args.action == 'status':
        command=['ssh','-o','BatchMode=yes','xoa-management','cat','.config/home-lab-xcp-metrics/status.json']
        subprocess.run(command, check=True)
        return
    env=manage.environment(include_grafana=True)
    env.setdefault('GRAFANA_URL', json.loads((ROOT/'monitoring/fleet.json').read_text())['grafana']['url'])
    env['GRAFANA_URL']=env['GRAFANA_URL'].rstrip('/')
    for key in ('TF_LOG','TF_LOG_PROVIDER','TF_LOG_PATH','TF_LOG_CORE'):
        env.pop(key,None)
    if args.action == 'deploy':
        deploy(env,args.enabled=='true');return
    _,_,private=inputs(env)
    verify_zero_cost(env,private)
    directory=manage.run_directory()/'xcp'
    directory.mkdir(mode=0o700,exist_ok=True)
    if directory.stat().st_mode & 0o077:
        raise ValueError('XCP runtime directory must be mode 0700')
    env['TF_DATA_DIR']=str(directory/'tfdata')
    plan=Path(args.plan).expanduser().resolve() if args.plan else directory/'deployment.tfplan'
    if plan.is_relative_to(ROOT):raise ValueError('Saved plan must be outside checkout')
    tf(env,'init','-input=false','-reconfigure','-backend-config=path='+str(directory/'terraform.tfstate'))
    if args.action=='plan':
        arguments=['plan','-input=false','-var=zero_cost_verified=true','-var=collector_enabled='+str(not args.disabled).lower(),'-out='+str(plan)]
        if args.redeploy:arguments.append('-replace=terraform_data.collector')
        tf(env,*arguments,capture=True)
        plan.chmod(0o600)
    manage.private_file(plan)
    digest=hashlib.sha256(plan.read_bytes()).hexdigest()
    data=json.loads(tf(env,'show','-json',str(plan),capture=True))
    guard_plan(data)
    print('Plan scope:', json.dumps([{'address':x['address'],'actions':x['change']['actions']} for x in data.get('resource_changes',[]) if x.get('mode')=='managed']), flush=True)
    print('Reviewed exact datacenter1 dashboard/collector plan:', plan, flush=True)
    if args.action=='apply':
        verify_zero_cost(env,private)
        if hashlib.sha256(plan.read_bytes()).hexdigest()!=digest:raise ValueError('Saved plan changed')
        tf(env,'apply','-input=false',str(plan))

if __name__=='__main__':
    try:main()
    except (ValueError,KeyError,OSError,subprocess.CalledProcessError) as error:
        print('XCP monitoring operation failed: '+str(error),file=sys.stderr)
        sys.exit(2)
