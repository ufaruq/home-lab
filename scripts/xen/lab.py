#!/usr/bin/env python3
"""Validate, adopt and nondestructively reconcile the declared Xen fleet."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import uuid

from plan_guard import expected_targets, resources, verify
from discovery import query_live, resolve_bindings, remote_json
from transport import open_transport


ROOT = Path(__file__).resolve().parents[2]
TF_ROOT = ROOT / "infra/xen/vms"
DEFAULT_INVENTORY = ROOT / "xen-server/inventory/local.json"
DEFAULT_POLICY = ROOT / "xen-server/desired-state.json"


def ansible_inventory_path():
    return Path(os.environ.get('XEN_ANSIBLE_INVENTORY', ROOT / 'ansible/inventory/hosts.yml')).expanduser().resolve()


def inventory_graph():
    path = ansible_inventory_path()
    if not path.is_file():
        raise ValueError('Required private Ansible inventory is missing')
    return json.loads(path.read_text())


def control_host():
    hosts = inventory_graph().get('all', {}).get('children', {}).get('xcp_control', {}).get('hosts', {})
    if not isinstance(hosts, dict) or len(hosts) != 1:
        raise ValueError('Private inventory must contain exactly one xcp_control host')
    alias = next(iter(hosts))
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', alias):
        raise ValueError('Private control-host alias is invalid')
    return alias


def control_host_vars():
    alias = control_host()
    path = Path(os.environ.get('XEN_HOST_VARS_FILE', ansible_inventory_path().parent / 'host_vars' / (alias + '.yml'))).expanduser()
    inline = inventory_graph()['all']['children']['xcp_control']['hosts'][alias] or {}
    result = dict(inline)
    if path.is_file():
        result.update(json.loads(path.read_text()))
    if not result:
        raise ValueError('Required private control host variables are missing')
    return result


def bootstrap_management(inventory, policy, state):
    profile = control_host_vars().get('native_recovery_policy')
    if not isinstance(profile, dict) or len(profile.get('automatic_vm_ids', [])) != 1:
        raise ValueError('Required private native_recovery_policy must identify one management VM')
    logical = profile['automatic_vm_ids'][0]
    if logical not in inventory['vms']:
        raise ValueError('Private management VM identity is absent from the captured inventory')
    expected_name = inventory['vms'][logical].get('name_label')
    if not isinstance(expected_name, str) or not expected_name:
        raise ValueError('Captured management VM name is required')
    if policy.get('vms', {}).get(logical, {}).get('power_state') != 'Running':
        return
    addresses = [address for address, identity in expected_targets(inventory).items()
                 if identity == logical and address.startswith('xenorchestra_vm.')]
    if len(addresses) != 1 or not inventory.get('hosts') or not inventory.get('pools'):
        raise ValueError('Management bootstrap requires an exact managed VM and captured host/pool identities')
    bindings = [item.get('values', {}).get('id') for item in
                resources(state.get('values', {}).get('root_module', {}))
                if item.get('mode', 'managed') == 'managed' and item.get('address') == addresses[0]]
    if len(bindings) > 1:
        raise ValueError('Ambiguous management VM binding in local Terraform state')
    current = bindings[0] if bindings else logical
    try:
        if not isinstance(current, str) or str(uuid.UUID(current)) != current:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ValueError('Invalid management VM identity in local Terraform state') from None
    source = """
import json
import XenAPI
s = XenAPI.xapi_local()
s.xenapi.login_with_password('', '')
try:
    host_ids = sorted(h['uuid'] for h in s.xenapi.host.get_all_records().values())
    pool_ids = sorted(p['uuid'] for p in s.xenapi.pool.get_all_records().values())
    if host_ids != %r or pool_ids != %r:
        raise RuntimeError('Management bootstrap host/pool identity mismatch')
    current, logical, expected_name = %r, %r, %r
    records = s.xenapi.VM.get_all_records()
    matches = [(ref, vm) for ref, vm in records.items() if vm['uuid'] == current]
    if len(matches) != 1:
        raise RuntimeError('Management VM binding is missing or ambiguous')
    ref, vm = matches[0]
    if vm['name_label'] != expected_name or vm['is_a_template'] or vm['is_a_snapshot'] or vm['is_control_domain']:
        raise RuntimeError('Unexpected management VM identity')
    for other in records.values():
        if other['uuid'] == current:
            continue
        if other['uuid'] == logical or (other['name_label'] == expected_name and not
                (other['is_a_template'] or other['is_a_snapshot'] or other['is_control_domain'])):
            raise RuntimeError('Ambiguous original/recovered or same-name management VM identity')
    changed = False
    if vm['power_state'] == 'Halted':
        s.xenapi.VM.start(ref, False, False)
        changed = True
    elif vm['power_state'] != 'Running':
        raise RuntimeError('Management VM requires manual power-state recovery')
    print(json.dumps({'power_state': s.xenapi.VM.get_power_state(ref), 'changed': changed}))
finally:
    s.xenapi.session.logout()
""" % (sorted(inventory['hosts']), sorted(inventory['pools']), current, logical, expected_name)
    result = remote_json(source)
    if result.get('power_state') != 'Running':
        raise ValueError('Management bootstrap did not reach the declared Running state')
    print('Management bootstrap:', 'started' if result.get('changed') else 'already running')


def verify_convergence(plan, inventory, policy, bindings):
    from convergence_guard import verify as guard
    return guard(plan, inventory, policy, bindings)


def native_definitions(policy, bindings):
    host = control_host_vars()
    definitions = host['xcp_native_definitions']
    for vm in definitions:
        settings = policy.get('vms', {}).get(vm['uuid'], {})
        if settings.get('power_state', 'Halted') != 'Halted' or settings.get('recovery'):
            raise ValueError('diskless definitions cannot boot or recover an OS without an OS disk')
        if 'cpus' in settings:
            vm['VCPUs_at_startup'] = vm['VCPUs_max'] = str(settings['cpus'])
        if 'memory_min' in settings:
            vm['memory_dynamic_min'] = str(settings['memory_min'])
        if 'memory_max' in settings:
            vm['memory_dynamic_max'] = vm['memory_static_max'] = str(settings['memory_max'])
        if not 0 <= int(vm['memory_static_min']) <= int(vm['memory_dynamic_min']) <= int(vm['memory_dynamic_max']) <= int(vm['memory_static_max']):
            raise ValueError('invalid diskless memory bounds')
        for vif in vm['vifs']:
            vif['network_uuid'] = bindings['existing_network_ids'].get(vif['network_uuid'], vif['network_uuid'])
    return definitions


def validate_policy(policy, inventory):
    if policy.get("schema_version") != 1 or set(policy) - {"schema_version", "vms", "networks", "guest_targets"}:
        raise ValueError("unsupported desired-state policy schema")
    for section in ("vms", "networks"):
        if not isinstance(policy.get(section, {}), dict) or set(policy.get(section, {})) - set(inventory[section]):
            raise ValueError("unknown resource in desired-state " + section)
    for logical, values in policy.get("vms", {}).items():
        if not isinstance(values, dict) or set(values) - {"cpus", "memory_min", "memory_max", "power_state", "recovery", "auto_poweron"}:
            raise ValueError("unsupported VM desired settings for " + logical)
        for key in ("cpus", "memory_min", "memory_max"):
            if key in values and (type(values[key]) is not int or values[key] <= 0):
                raise ValueError(key + " must be a positive integer")
        if "power_state" in values and values["power_state"] not in ("Running", "Halted"):
            raise ValueError("power_state must be Running or Halted")
        if "auto_poweron" in values and type(values['auto_poweron']) is not bool:
            raise ValueError('auto_poweron must be boolean')
    graph = inventory_graph()
    linux = graph["all"]["children"]["linux_guests"]["hosts"]
    targets = policy.get("guest_targets", [])
    if not isinstance(targets, list) or any(not isinstance(t, str) or t not in linux for t in targets) or len(targets) != len(set(targets)):
        raise ValueError("unknown, duplicate or non-Linux guest target")


def private_input(value, name):
    path = Path(value).resolve()
    if ROOT == path or ROOT in path.parents:
        raise ValueError(name + " must be outside the checkout")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(name + " must be an owner-only regular file (chmod 600)")
    return path


def load_connection():
    value = os.environ.get('XEN_CONNECTION_FILE')
    if not value:
        pointer = Path(os.environ.get('XEN_RUN_DIR', str(ROOT / '.local/xen'))) / 'connection-path'
        if not pointer.exists():
            return
        info = pointer.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('connection-path must be owner-only')
        value = pointer.read_text().strip()
    path = private_input(value, 'XEN_CONNECTION_FILE')
    connection = json.loads(path.read_text())
    allowed = {'XOA_URL', 'XOA_TOKEN', 'XOA_USER', 'XOA_PASSWORD', 'XEN_HOST',
               'XEN_SSH_CONTROL', 'XEN_PRIVATE_VARS', 'XEN_PRIVATE_INVENTORY', 'ANSIBLE_PLAYBOOK_BIN',
               'XEN_SSH_HOST_ALIAS', 'XEN_KNOWN_HOSTS_FILE', 'XEN_FORWARD_TARGET',
               'XEN_ANSIBLE_INVENTORY', 'XEN_HOST_VARS_FILE', 'XEN_INVENTORY_FILE', 'XEN_POLICY_FILE'}
    metadata = {'created_at', 'expires_at'}
    if not isinstance(connection, dict) or set(connection) - allowed - metadata:
        raise ValueError('unknown private connection setting')
    for key, item in connection.items():
        if key in allowed and (not isinstance(item, str) or not item):
            raise ValueError('private connection settings must be nonempty strings')
    selected = allowed & set(connection)
    if connection.get('XOA_TOKEN') and connection.get('expires_at'):
        expiry = datetime.fromisoformat(connection['expires_at'].replace('Z', '+00:00'))
        if expiry.tzinfo is None:
            raise ValueError('private token expiry must include a timezone')
        if expiry <= datetime.now(timezone.utc):
            selected.discard('XOA_TOKEN')
    if os.environ.get('XOA_TOKEN'):
        selected -= {'XOA_USER', 'XOA_PASSWORD'}
    elif os.environ.get('XOA_USER') or os.environ.get('XOA_PASSWORD'):
        selected -= {'XOA_TOKEN'}
    elif 'XOA_TOKEN' in selected:
        selected -= {'XOA_USER', 'XOA_PASSWORD'}
    for key in selected:
        os.environ.setdefault(key, connection[key])


@contextmanager
def controller_lock():
    with (private_directory() / "controller.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("another Xen controller operation is already running")
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def converge(inventory, policy, path, plan_only=False):
    if not os.environ.get("XOA_URL") or not (os.environ.get("XOA_TOKEN") or
            (os.environ.get("XOA_USER") and os.environ.get("XOA_PASSWORD"))):
        raise ValueError("Xen Orchestra endpoint/authentication missing: set XOA_URL and private XOA_TOKEN (or XOA_USER/XOA_PASSWORD)")
    targets = policy.get("guest_targets", [])
    if targets:
        if not os.environ.get("XEN_PRIVATE_VARS"):
            raise ValueError("selected guests require verified policy/access in XEN_PRIVATE_VARS")
        private_input(os.environ["XEN_PRIVATE_VARS"], "XEN_PRIVATE_VARS")
        ansible("converge-guests.yml", check=False, limit=",".join(targets),
                extra_vars={"guest_targets": targets, "convergence_preflight_only": True})
    # Local state can be loaded before XO is reachable; it binds recovered XOA IDs.
    terraform("init", "-input=false")
    state = json.loads(terraform("show", "-json", capture=True))
    if not plan_only:
        bootstrap_management(inventory, policy, state)
    bindings = resolve_bindings(inventory, query_live(), state)
    definitions = native_definitions(policy, bindings)
    directory = private_directory()
    variables = directory / "live.tfvars.json"
    variables.write_text(json.dumps({key: bindings[key] for key in ("existing_vm_ids", "existing_network_ids")}))
    variables.chmod(0o600)
    frozen_inventory = directory / "inventory.json"
    frozen_inventory.write_text(json.dumps(inventory))
    frozen_inventory.chmod(0o600)
    frozen_policy = directory / "desired-state.json"
    frozen_policy.write_text(json.dumps(policy))
    frozen_policy.chmod(0o600)
    (directory / "discovery.json").write_text(json.dumps(bindings, indent=2))
    path = path.resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    terraform("plan", "-input=false", "-var-file=" + str(variables),
              "-var=desired_state_file=" + str(frozen_policy),
              "-var=inventory_file=" + str(frozen_inventory), "-out=" + str(path))
    path.chmod(0o600)
    plan, digest = show_plan(path)
    count = verify_convergence(plan, inventory, policy, bindings)
    print(f"Verified nondestructive convergence for {count} resource bindings.", flush=True)
    if plan_only:
        print("Convergence plan:", path)
        return
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("saved plan changed after verification")
    terraform("apply", "-input=false", path)
    ansible("xcp-definitions.yml", check=False,
            extra_vars={"xcp_definition_apply": True, "xcp_native_definitions": definitions}, limit=control_host())
    ansible('../recovery/native-boot.yml', check=False,
            extra_vars={'native_recovery_apply': True}, limit=control_host())
    ansible('../hardening/apply.yml', check=False,
            extra_vars={'logging_hardening_apply': True, 'logging_hardening_workflow_verified': True}, limit=control_host())
    ansible('../networking/apply.yml', check=False,
            extra_vars={'network_profile_apply': True}, limit=control_host())
    if targets:
        ansible("converge-guests.yml", check=False, limit=",".join(targets),
                extra_vars={"guest_targets": targets, "convergence_preflight_only": False})
    else:
        print("Guest configuration not selected: guest_targets is empty; no guest convergence claimed.")
    print("Convergence completed for the declared scope; existing disks were preserved.")


def private_directory():
    path = Path(os.environ.get("XEN_RUN_DIR", str(ROOT / ".local/xen"))).resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("XEN_RUN_DIR must be owned by you with permissions 0700")
    return path


def run(command, capture=False, environment=None):
    return subprocess.run(
        [str(item) for item in command], cwd=ROOT, env=environment,
        text=True, check=True, stdout=subprocess.PIPE if capture else None,
    ).stdout


def terraform(*arguments, capture=False):
    binary = os.environ.get("TERRAFORM_BIN", "terraform")
    return run([binary, "-chdir=" + str(TF_ROOT), *arguments], capture=capture)


def ansible(playbook, check=True, limit=None, extra_vars=None):
    environment = dict(os.environ)
    environment.setdefault("ANSIBLE_CONFIG", str(ROOT / "ansible/ansible.cfg"))
    environment.setdefault("ANSIBLE_HOME", str(private_directory() / "ansible-home"))
    command = [os.environ.get("ANSIBLE_PLAYBOOK_BIN", "ansible-playbook"),
               "-i", str(ansible_inventory_path()),
               str(ROOT / "ansible/playbooks" / playbook)]
    if os.environ.get("XEN_PRIVATE_INVENTORY"):
        command.extend(["-i", str(private_input(os.environ["XEN_PRIVATE_INVENTORY"], "XEN_PRIVATE_INVENTORY"))])
    if check:
        command.extend(["--check", "--diff"])
    selected = limit or os.environ.get("XEN_LIMIT")
    if selected:
        command.extend(["--limit", selected])
    if os.environ.get("XEN_PRIVATE_VARS"):
        private_vars = private_input(os.environ["XEN_PRIVATE_VARS"], "XEN_PRIVATE_VARS")
        command.extend(["-e", "@" + str(private_vars)])
    if extra_vars:
        command.extend(["-e", json.dumps(extra_vars)])
    host_playbooks = {'xcp-definitions.yml', '../recovery/native-boot.yml',
                      '../hardening/apply.yml', '../hardening/health.yml', '../networking/apply.yml'}
    if os.environ.get("XEN_SSH_CONTROL") and playbook in host_playbooks:
        import shlex
        command.extend(["--ssh-common-args", "-o ControlPath=" +
                        shlex.quote(os.environ["XEN_SSH_CONTROL"]) + " -o BatchMode=yes"])
    return run(command, environment=environment)


def show_plan(path):
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("saved plan permissions must be owner-only (chmod 600)")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    plan = json.loads(terraform("show", "-json", path, capture=True))
    return plan, before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=None)
    parser.add_argument("--policy", type=Path, default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("inventory")
    sub.add_parser("validate")
    for name in ["plan", "adopt", "adoption-plan", "converge"]:
        child = sub.add_parser(name)
        child.add_argument("--plan", type=Path)
    sub.add_parser("audit")
    sub.add_parser("definitions-check")
    sub.add_parser("configure-check")
    sub.add_parser("readiness")
    sub.add_parser("bootstrap")
    sub.add_parser('health')
    sub.add_parser('hardening-check')
    sub.add_parser('recovery-check')
    sub.add_parser('network-check')
    args = parser.parse_args()
    os.umask(0o077)
    opened = None
    exit_code = 0
    try:
        if args.command not in ('inventory', 'validate'):
            load_connection()
        api_commands = {'plan', 'converge', 'readiness'}
        host_commands = {'bootstrap', 'health', 'hardening-check', 'recovery-check',
                         'network-check', 'definitions-check'}
        if args.command in api_commands | host_commands:
            opened = open_transport(api=args.command in api_commands)
        if args.command == 'validate':
            fixture = ROOT / 'tests/fixtures/xen'
            args.inventory = fixture / 'inventory.json'
            args.policy = fixture / 'policy.json'
            os.environ.update(XEN_INVENTORY_FILE=str(args.inventory), XEN_POLICY_FILE=str(args.policy),
                              XEN_ANSIBLE_INVENTORY=str(fixture / 'ansible/hosts.yml'),
                              XEN_HOST_VARS_FILE=str(fixture / 'ansible/host_vars/example_control.yml'))
        else:
            args.inventory = args.inventory or Path(os.environ.get('XEN_INVENTORY_FILE', DEFAULT_INVENTORY))
            args.policy = args.policy or Path(os.environ.get('XEN_POLICY_FILE', DEFAULT_POLICY))
        inventory = json.loads(args.inventory.read_text())
        policy = json.loads(args.policy.read_text())
        if args.command == "inventory":
            targets = expected_targets(inventory)
            print("Observed snapshot:", inventory.get("captured_at", "unknown capture time"))
            print(f"{len(inventory['vms'])} VMs; {len(inventory['networks'])} networks; "
                  f"{len(inventory['storage_repositories'])} storage repositories.")
            print(f"{len(targets)} Terraform bindings; diskless definitions have Ansible/XenAPI ownership.")
            print("Guest audit and offline capture status are documented separately; this command does not refresh desired state.")
        elif args.command == "validate":
            terraform("init", "-backend=false", "-input=false")
            terraform("fmt", "-check", "-recursive")
            terraform("validate")
            terraform("test")
            test_environment = dict(os.environ)
            if os.environ.get("ANSIBLE_PLAYBOOK_BIN"):
                inventory_binary = Path(os.environ["ANSIBLE_PLAYBOOK_BIN"]).with_name("ansible-inventory")
                if inventory_binary.is_file():
                    test_environment.setdefault("ANSIBLE_INVENTORY_BIN", str(inventory_binary))
            for directory in ["scripts/xen/tests", "ansible/tests", 'ansible/hardening/tests', 'ansible/recovery/tests', 'ansible/networking/tests']:
                run([sys.executable, "-m", "unittest", "discover", "-s", directory, "-v"], environment=test_environment)
            run(["sh", "-n", "ansible/files/audit-unix.sh"])
            environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"))
            environment.setdefault("ANSIBLE_HOME", str(private_directory() / "ansible-home"))
            binary = os.environ.get("ANSIBLE_PLAYBOOK_BIN", "ansible-playbook")
            for playbook in ["audit-guests.yml", "enforce-guests.yml", "xcp-definitions.yml", "converge-guests.yml",
                             '../hardening/apply.yml', '../hardening/health.yml', '../recovery/native-boot.yml', '../networking/apply.yml']:
                run([binary, "-i", ansible_inventory_path(),
                     ROOT / "ansible/playbooks" / playbook, "--syntax-check"], environment=environment)
        elif args.command == "bootstrap":
            validate_policy(policy, inventory)
            with controller_lock():
                terraform("init", "-input=false")
                state = json.loads(terraform("show", "-json", capture=True))
                bootstrap_management(inventory, policy, state)
        elif args.command == 'health':
            ansible('../hardening/health.yml', check=True, limit=control_host())
        elif args.command == 'hardening-check':
            ansible('../hardening/apply.yml', check=True, limit=control_host())
        elif args.command == 'recovery-check':
            ansible('../recovery/native-boot.yml', check=True, limit=control_host())
        elif args.command == 'network-check':
            ansible('../networking/apply.yml', check=True, limit=control_host())
        elif args.command in ("plan", "converge"):
            validate_policy(policy, inventory)
            path = args.plan or Path(os.environ.get("XEN_PLAN_FILE", str(private_directory() / "convergence.tfplan")))
            with controller_lock():
                converge(inventory, policy, path, plan_only=args.command == "plan")
        elif args.command == "readiness":
            validate_policy(policy, inventory)
            live = query_live()
            with controller_lock():
                terraform("init", "-input=false")
                state = json.loads(terraform("show", "-json", capture=True))
                bindings = resolve_bindings(inventory, live, state)
            print(f"Live discovery: {len(live['vms'])} VMs, {len(live['templates'])} templates, {len(live['networks'])} networks.")
            print(f"Existing Terraform targets: {len(bindings['existing_vm_ids'])} VMs, {len(bindings['existing_network_ids'])} networks.")
            print("XO endpoint:", "configured" if os.environ.get("XOA_URL") else "missing XOA_URL")
            print("XO authentication:", "configured" if os.environ.get("XOA_TOKEN") or (os.environ.get("XOA_USER") and os.environ.get("XOA_PASSWORD")) else "missing")
            print("Guest targets:", ", ".join(policy.get("guest_targets", [])) or "none selected")
            for logical, vm in inventory['vms'].items():
                print(vm['name_label'] + ": " + live['vms'].get(bindings['existing_vm_ids'].get(logical, logical), {}).get('power_state', 'missing/unmanaged'))
        elif args.command in ("adoption-plan", "adopt"):
            path = (args.plan or Path(os.environ.get("XEN_PLAN_FILE", str(private_directory() / "adoption.tfplan"))))
            path = path.resolve()
            if args.command == "adoption-plan":
                if not os.environ.get("XOA_URL"):
                    raise ValueError("set XOA_URL and private XO authentication; the Xen Orchestra service must be reachable")
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                terraform("init", "-input=false")
                terraform("plan", "-input=false", "-var=inventory_file=" + str(args.inventory.resolve()),
                          "-var=desired_state_file=" + str(args.policy.resolve()), "-out=" + str(path))
                path.chmod(0o600)
            plan, digest = show_plan(path)
            count = verify(plan, inventory)
            print(f"Verified {count} existing bindings with no infrastructure writes.", flush=True)
            if args.command == "adoption-plan":
                print("Reviewed adoption plan:", path)
            else:
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError("saved plan changed after verification")
                with controller_lock():
                    terraform("apply", "-input=false", path)
                print("Existing resources adopted into local Terraform state; guest configuration was not applied.")
        elif args.command == "definitions-check":
            ansible("xcp-definitions.yml")
        elif args.command == "audit":
            ansible("audit-guests.yml")
        elif args.command == "configure-check":
            if not os.environ.get("XEN_LIMIT") or not os.environ.get("XEN_PRIVATE_VARS"):
                raise ValueError("set XEN_LIMIT and XEN_PRIVATE_VARS to select verified guest policy")
            ansible("enforce-guests.yml")
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print("Xen command rejected: " + str(error), file=sys.stderr)
        return 2
    finally:
        if opened is not None:
            try:
                opened.close()
            except RuntimeError as error:
                print('Xen transport cleanup failed: ' + str(error), file=sys.stderr)
                exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
