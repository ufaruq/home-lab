#!/usr/bin/env python3
"""Validate and deploy the lab's monitoring configuration without implicit targets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = ROOT / "monitoring/fleet.json"
INVENTORY = ROOT / "ansible/inventory/hosts.yml"
EXTERNAL_INVENTORY = ROOT / "monitoring/inventory/oracle.yml"
TF_ROOT = ROOT / "infra/grafana"
STACK_ROOT = ROOT / "infra/monitoring"
PLAYBOOKS = {
    "collectors": "monitoring-collectors.yml",
    "manager": "monitoring-wazuh.yml",
    "opnsense": "monitoring-opnsense.yml",
}
RESOURCE_TYPES = {"grafana_folder", "grafana_dashboard", "grafana_rule_group"}


def inventory_names(tree):
    names = set()
    def visit(value):
        if not isinstance(value, dict):
            return
        names.update(value.get("hosts", {}))
        for child in value.get("children", {}).values():
            visit(child)
    visit(tree.get("all", {}))
    return names


def validate_policy(policy, inventory):
    if policy.get("schema_version") != 1:
        raise ValueError("Unsupported monitoring policy version")
    grafana = policy.get("grafana", {})
    if grafana.get("url") != "https://cordialbike2680.grafana.net" or grafana.get("required_plan") != "free":
        raise ValueError("Monitoring must target the declared existing Grafana Free stack")
    if type(grafana.get("live_apply_enabled")) is not bool:
        raise ValueError("Grafana live_apply_enabled must be a boolean")
    if type(grafana.get("trial_dashboard_apply_enabled", False)) is not bool:
        raise ValueError("trial_dashboard_apply_enabled must be a boolean")
    if type(grafana.get("trial_collector_apply_enabled", False)) is not bool:
        raise ValueError("trial_collector_apply_enabled must be a boolean")
    if grafana.get("observed_plan") not in {"free", "trial", "unknown"}:
        raise ValueError("Paid Grafana plans are outside the zero-cost deployment policy")
    if grafana["live_apply_enabled"] and grafana.get("observed_plan") != "free":
        raise ValueError("Grafana live apply cannot be enabled while the stack is Trial or unverified")
    bounds = {"active_series": (1, 7000), "daily_log_mb": (1, 500), "scrape_interval_seconds": (60, 3600), "wazuh_alert_retention_days": (7, 7)}
    for key, (low, high) in bounds.items():
        value = policy.get("budgets", {}).get(key)
        if type(value) is not int or not low <= value <= high:
            raise ValueError("Monitoring budget outside approved bounds: " + key)
    expected = inventory_names(inventory) | inventory_names(json.loads(EXTERNAL_INVENTORY.read_text()))
    if set(policy.get("hosts", {})) != expected:
        raise ValueError("Monitoring policy must explicitly map every existing inventory host")
    components = {"alloy", "wazuh-agent", "wazuh-manager", "opnsense-syslog", "xapi", "syslog", "snmp"}
    for name, host in policy["hosts"].items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            raise ValueError("Unsafe inventory name: " + name)
        if host.get("status") not in {"planned", "blocked", "agentless"}:
            raise ValueError("Host must declare deployment readiness: " + name)
        if host.get("environment") not in {"homelab", "lab"} or not re.fullmatch(r"[a-z][a-z0-9-]*", host.get("role", "")):
            raise ValueError("Host labels must be bounded stable identifiers: " + name)
        chosen = host.get("components", [])
        if not isinstance(chosen, list) or len(chosen) != len(set(chosen)) or set(chosen) - components:
            raise ValueError("Unsupported or duplicate monitoring component: " + name)
        if host.get("platform") not in {"linux", "windows"} and set(chosen) & {"alloy", "wazuh-agent", "wazuh-manager"}:
            raise ValueError("Agents cannot be installed on dom0, appliances, or unknown guests: " + name)
        if host.get("status") == "blocked" and chosen:
            raise ValueError("Blocked definitions must have no deployment components: " + name)
        if "wazuh-manager" in chosen and name != "oracle_wazuh":
            raise ValueError("Central components belong only on the selected Oracle Wazuh host")
        if "opnsense-syslog" in chosen and host.get("platform") != "opnsense":
            raise ValueError("OPNsense API automation requires an OPNsense target")


def select_targets(policy, names, component):
    if not names or len(names) != len(set(names)):
        raise ValueError("Provide a nonempty list of unique explicit inventory names")
    required = {"collectors": "alloy", "manager": "wazuh-manager", "opnsense": "opnsense-syslog"}
    if component not in required:
        raise ValueError("Unknown monitoring deployment component")
    for name in names:
        host = policy["hosts"].get(name)
        if not host or host["status"] != "planned" or required[component] not in host["components"]:
            raise ValueError("Target is unknown, blocked, agentless, or incompatible: " + name)
    return list(names)


def private_file(value):
    path = Path(value).expanduser().resolve(strict=True)
    if path.is_relative_to(ROOT):
        raise ValueError("Private inputs and plans must be outside the checkout")
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) not in (0o400, 0o600):
        raise ValueError("Private file must be owned by you and mode 0400 or 0600")
    return path


def private_json(value):
    data = json.loads(private_file(value).read_text())
    if not isinstance(data, dict):
        raise ValueError("Private variables must be a JSON object")
    return data


def run_directory():
    path = Path(os.environ.get("MONITORING_RUN_DIR", f"/private/tmp/home-lab-monitoring-{os.getuid()}")).expanduser().resolve()
    if path.is_relative_to(ROOT):
        raise ValueError("Monitoring runtime artifacts must remain outside the checkout")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.stat()
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) != 0o700:
        raise ValueError("Monitoring runtime directory must be owner-only (0700)")
    return path


def environment(include_grafana=False):
    env = dict(os.environ)
    directory = run_directory()
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible/ansible.cfg")
    env.setdefault("ANSIBLE_HOME", str(directory / "ansible-home"))
    env.setdefault("ANSIBLE_LOCAL_TEMP", str(directory / "ansible-tmp"))
    env.setdefault("ANSIBLE_COLLECTIONS_PATH", str(ROOT / ".local/monitoring/collections"))
    # Refuse caller overrides that disable the repository's transport checks.
    if env.get("ANSIBLE_HOST_KEY_CHECKING", "true").lower() not in ("true", "1", "yes"):
        raise ValueError("SSH host-key verification must remain enabled")
    for key in ("ANSIBLE_SSH_ARGS", "ANSIBLE_SSH_COMMON_ARGS", "ANSIBLE_SSH_EXTRA_ARGS"):
        if re.search(r"stricthostkeychecking[=\s]+(?:no|false|off)|userknownhostsfile[=\s]+/dev/null", env.get(key, ""), re.I):
            raise ValueError("SSH transport overrides cannot disable identity verification")
    for key in ("GRAFANA_INSECURE_SKIP_VERIFY", "GRAFANA_TLS_SKIP_VERIFY"):
        if env.get(key, "false").lower() not in ("false", "0", "no", ""):
            raise ValueError("Grafana TLS certificate verification must remain enabled")
    env["ANSIBLE_HOST_KEY_CHECKING"] = "True"
    if include_grafana and not env.get("GRAFANA_AUTH") and env.get("MONITORING_GRAFANA_AUTH_FILE"):
        env["GRAFANA_AUTH"] = private_file(env["MONITORING_GRAFANA_AUTH_FILE"]).read_text().strip()
    if not include_grafana:
        env.pop("GRAFANA_AUTH", None)
    return env


def logged_run(command, label, env=None):
    logfile = run_directory() / (label + ".log")
    with logfile.open("w") as stream:
        os.chmod(logfile, 0o600)
        result = subprocess.run([str(part) for part in command], cwd=ROOT, env=env or environment(), stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise ValueError(f"{label} failed (exit {result.returncode}); inspect private log {logfile}")
    return logfile


def target_variables(policy, selected, preflight_only=False):
    return {
        "monitoring_targets": selected,
        "monitoring_host_policies": {name: policy["hosts"][name] for name in selected},
        "monitoring_scrape_interval_seconds": policy["budgets"]["scrape_interval_seconds"],
        "monitoring_wazuh_retention_days": policy["budgets"]["wazuh_alert_retention_days"],
        "monitoring_preflight_only": preflight_only,
        "monitoring_trial_alloy_only": policy["grafana"].get("observed_plan") == "trial",
    }


def validate_access(selected, effective, overrides, component):
    for name in selected:
        values = dict(effective.get(name, {}), **overrides)
        if values.get("monitoring_access_verified") is not True or values.get("monitoring_deployment_approved") is not True:
            raise ValueError("Verified access and reviewed monitoring configuration are required for " + name)
        if component != "opnsense" and (not values.get("ansible_host") or not values.get("ansible_user")):
            raise ValueError("Actual host address and login are required for " + name)
        if str(values.get("ansible_host", "")).startswith("{{"):
            raise ValueError("Host addresses must be resolved private inventory values")
        if values.get("ansible_ssh_common_args") or values.get("ansible_ssh_extra_args") or values.get("ansible_ssh_args"):
            raise ValueError("Custom SSH arguments need a separate reviewed transport policy")
        if values.get("ansible_winrm_server_cert_validation", "validate") != "validate":
            raise ValueError("Windows certificate validation must remain enabled")
        if values.get("ansible_connection") == "winrm" and (values.get("ansible_port", 5986) != 5986 or values.get("ansible_winrm_scheme", "https") != "https"):
            raise ValueError("Windows management requires verified WinRM HTTPS on port 5986")
        if any("REPLACE" in str(values.get(key, "")) for key in ("ansible_host", "ansible_user")):
            raise ValueError("Replace example addresses/logins with verified private inventory values")


def ansible_command(component, selected, private_inventory, private_vars, policy, apply=False, preflight_only=False):
    command = [os.environ.get("ANSIBLE_PLAYBOOK_BIN", "ansible-playbook"), "-i", str(INVENTORY), "-i", str(EXTERNAL_INVENTORY), "-i", str(private_inventory), str(ROOT / "ansible/playbooks" / PLAYBOOKS[component]), "--limit", ",".join(selected), "-e", "@" + str(private_vars)]
    if not apply:
        command.append("--check")
    command.extend(["-e", json.dumps(target_variables(policy, selected, preflight_only))])
    return command


def effective_hosts(private_inventory, env):
    binary = os.environ.get("ANSIBLE_INVENTORY_BIN")
    if not binary:
        binary = str(Path(os.environ["ANSIBLE_PLAYBOOK_BIN"]).with_name("ansible-inventory")) if os.environ.get("ANSIBLE_PLAYBOOK_BIN") else "ansible-inventory"
    result = subprocess.run([binary, "-i", str(INVENTORY), "-i", str(EXTERNAL_INVENTORY), "-i", str(private_inventory), "--list"], cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode:
        raise ValueError("Private inventory could not be loaded; no targets were contacted")
    return json.loads(result.stdout).get("_meta", {}).get("hostvars", {})


def grafana_gate(policy, variables, env, dashboard_only=False):
    grafana = policy["grafana"]
    free = grafana.get("observed_plan") == "free" and grafana.get("live_apply_enabled") is True and variables.get("free_plan_verified") is True
    no_targets_or_alerts = not any(variables.get(key) for key in ("collector_targets", "wazuh_manager_targets", "opnsense_targets", "expected_linux_hosts", "expected_windows_hosts", "alerts_enabled"))
    trial_dashboard = (dashboard_only and grafana.get("observed_plan") == "trial" and grafana.get("trial_dashboard_apply_enabled") is True
                       and variables.get("unbilled_trial_dashboard_only_verified") is True and no_targets_or_alerts)
    trial_collectors = (grafana.get("observed_plan") == "trial" and grafana.get("trial_collector_apply_enabled") is True
                        and variables.get("unbilled_trial_collection_verified") is True
                        and bool(variables.get("collector_targets")) and not variables.get("wazuh_manager_targets")
                        and not variables.get("opnsense_targets") and not variables.get("expected_linux_hosts")
                        and not variables.get("expected_windows_hosts") and not variables.get("alerts_enabled")
                        and variables.get("deployment_reviewed") is True)
    trial = trial_dashboard or trial_collectors
    if not free and not trial:
        raise ValueError("Use the verified Free stack, or select only Alloy collectors under the verified unbilled Trial path; Trial deployment cannot change Wazuh, OPNsense or alerts")
    if env.get("GRAFANA_URL", "").rstrip("/") != grafana["url"] or not env.get("GRAFANA_AUTH"):
        raise ValueError("Set GRAFANA_URL to the declared existing stack and supply GRAFANA_AUTH privately")


def guard_grafana_plan(plan):
    summary = {"create": 0, "update": 0, "no-op": 0}
    for resource in plan.get("resource_changes", []):
        if resource.get("mode") != "managed":
            continue
        actions = resource["change"]["actions"]
        if resource.get("type") not in RESOURCE_TYPES or resource.get("provider_name") != "registry.terraform.io/grafana/grafana" or len(actions) != 1 or actions[0] not in summary:
            raise ValueError("Plan contains unapproved resource, provider, deletion, or replacement: " + resource.get("address", "unknown"))
        summary[actions[0]] += 1
    if any(check.get("status") != "pass" for check in plan.get("checks", [])):
        raise ValueError("Grafana security checks did not all pass")
    return summary


def guard_stack_plan(plan):
    filtered = dict(plan)
    filtered["resource_changes"] = []
    orchestration = 0
    for resource in plan.get("resource_changes", []):
        if resource.get("mode") == "managed" and resource.get("type") == "terraform_data":
            if resource.get("address") != "terraform_data.fleet[0]" or resource.get("provider_name") != "terraform.io/builtin/terraform" or resource["change"]["actions"] not in (["create"], ["update"], ["no-op"], ["delete", "create"], ["delete"]):
                raise ValueError("Unexpected deployment orchestration resource/action")
            orchestration += resource["change"]["actions"] != ["no-op"]
        else:
            filtered["resource_changes"].append(resource)
    return dict(guard_grafana_plan(filtered), orchestration=orchestration)


def guard_trial_dashboard_plan(plan):
    for resource in plan.get('resource_changes', []):
        if resource.get('mode') == 'managed' and resource.get('type') not in {'grafana_folder', 'grafana_dashboard'}:
            raise ValueError('Unbilled trial deployment permits only folders and dashboards')
    return guard_grafana_plan(plan)


def guard_trial_stack_plan(plan):
    filtered = dict(plan)
    filtered["resource_changes"] = []
    orchestration = 0
    for resource in plan.get("resource_changes", []):
        if resource.get("mode") == "managed" and resource.get("type") == "terraform_data":
            actions = resource["change"]["actions"]
            if (resource.get("address") != "terraform_data.fleet[0]"
                    or resource.get("provider_name") != "terraform.io/builtin/terraform"
                    or actions not in (["create"], ["update"], ["no-op"], ["delete", "create"])):
                raise ValueError("Trial collection permits only creation or re-convergence of the exact Alloy fleet selection")
            orchestration += actions != ["no-op"]
        else:
            if resource.get("mode") == "managed" and resource.get("type") not in {"grafana_folder", "grafana_dashboard"}:
                raise ValueError("Unbilled Trial deployment permits only dashboards and selected Alloy guest configuration")
            filtered["resource_changes"].append(resource)
    return dict(guard_grafana_plan(filtered), orchestration=orchestration)


def verify_unbilled_trial(env):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError('Refusing authenticated Grafana redirect')
    request = urllib.request.Request(env['GRAFANA_URL'].rstrip('/') + '/api/frontend/settings', headers={'Authorization': 'Bearer ' + env['GRAFANA_AUTH']})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
        settings = json.load(response)
    if settings.get('licenseInfo', {}).get('edition') != 'Cloud Trial' or settings.get('buildInfo', {}).get('edition') != 'Cloud Trial':
        raise ValueError('Live Grafana edition changed; recheck the Trial-to-Free transition before the next deployment')


def fleet_selection(policy, selection):
    if not isinstance(selection, dict) or set(selection) != set(PLAYBOOKS):
        raise ValueError("Selection must contain only collectors, manager, and opnsense arrays")
    for component, names in selection.items():
        if not isinstance(names, list):
            raise ValueError("Each component selection must be a list")
        if names:
            select_targets(policy, names, component)
    if not any(selection.values()):
        raise ValueError("No monitoring targets selected")
    return selection


def deploy_fleet(args, policy):
    selection = fleet_selection(policy, json.loads(args.selection_json))
    private_inventory, private_vars = private_file(args.private_inventory), private_file(args.private_vars)
    overrides, env = private_json(private_vars), environment(include_grafana=bool(selection["collectors"]))
    if policy["grafana"]["observed_plan"] == "trial":
        if selection["manager"] or selection["opnsense"]:
            raise ValueError("The unbilled Trial path allows Alloy collectors only")
        if selection["collectors"]:
            if policy["grafana"].get("trial_collector_apply_enabled") is not True or overrides.get("monitoring_grafana_zero_cost_mode_verified") is not True:
                raise ValueError("Explicitly verify the zero-cost Grafana Trial/Free deployment mode in private deployment inputs")
            verify_unbilled_trial(env)
    if selection["collectors"] and overrides.get("monitoring_grafana_zero_cost_mode_verified") is not True:
        raise ValueError("Set monitoring_grafana_zero_cost_mode_verified=true in private deployment inputs")
    effective = effective_hosts(private_inventory, env)
    # Validate every selected platform's declared access before the first play.
    for component, selected in selection.items():
        if selected:
            validate_access(selected, effective, overrides, component)
    if selection["collectors"] and policy["grafana"]["observed_plan"] == "free" and (policy["grafana"]["live_apply_enabled"] is not True or overrides.get("monitoring_grafana_zero_cost_mode_verified") is not True):
        raise ValueError("Verify the Grafana Free plan and zero-cost mode before deploying collectors")
    for component in ("manager", "opnsense", "collectors"):
        selected = selection[component]
        if selected:
            logfile = logged_run(ansible_command(component, selected, private_inventory, private_vars, policy, apply=True), "fleet-" + component, env)
            print("Verified play completed: " + component + "; private log: " + str(logfile))


def configuration_hash():
    digest = hashlib.sha256()
    paths = [DEFAULT_POLICY, *TF_ROOT.glob("*.tf"), *STACK_ROOT.glob("*.tf")]
    for directory in (ROOT / "monitoring", ROOT / "scripts/monitoring", ROOT / "ansible/roles", ROOT / "ansible/playbooks"):
        paths.extend(p for p in directory.rglob("*") if p.is_file() and p.suffix in {".json", ".tftpl", ".j2", ".xml", ".conf", ".py", ".yml"} and "__pycache__" not in p.parts)
    for path in sorted(set(paths)):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def show_plan(path, env, root=TF_ROOT):
    command = [os.environ.get("TERRAFORM_BIN", "terraform"), "-chdir=" + str(root), "show", "-json", str(path)]
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode:
        raise ValueError("Could not read saved Terraform plan; no changes applied")
    return json.loads(result.stdout)


def grafana_operation(args, policy):
    composed = args.command.startswith("stack-")
    root = STACK_ROOT if composed else TF_ROOT
    guard = guard_stack_plan if composed else guard_grafana_plan
    variables_path = private_file(args.vars)
    variables = private_json(variables_path)
    env = environment(include_grafana=True)
    trial = policy['grafana'].get('observed_plan') == 'trial'
    grafana_gate(policy, variables, env, dashboard_only=trial)
    if trial:
        verify_unbilled_trial(env)
        guard = guard_trial_stack_plan if composed and variables.get("collector_targets") else guard_trial_dashboard_plan
    binary = os.environ.get("TERRAFORM_BIN", "terraform")
    base = [binary, "-chdir=" + str(root)]
    path = Path(args.plan or run_directory() / ("monitoring.tfplan" if composed else "grafana.tfplan")).expanduser().resolve()
    if path.parent != run_directory():
        raise ValueError("Saved plans must be in MONITORING_RUN_DIR")
    receipt = path.with_suffix(".review.json")
    if args.command.endswith("-plan"):
        logged_run(base + ["init", "-input=false"], "grafana-init", env)
        replace = ["-replace=terraform_data.fleet[0]"] if composed and getattr(args, "replace_fleet", False) else []
        logged_run(base + ["plan", "-input=false", "-out=" + str(path), "-var-file=" + str(variables_path)] + replace, "grafana-plan", env)
        summary = guard(show_plan(path, env, root))
        receipt.write_text(json.dumps({"plan_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "configuration_sha256": configuration_hash(), "variables_sha256": hashlib.sha256(variables_path.read_bytes()).hexdigest(), "stack": policy["grafana"]["url"], "root": str(root.relative_to(ROOT)), "reviewed_at": time.time()}))
        receipt.chmod(0o600)
        print(json.dumps({"actions": summary, "saved_plan": str(path), "review": str(receipt)}, indent=2))
    else:
        review = private_json(receipt)
        private_file(path)
        expected = {"plan_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "configuration_sha256": configuration_hash(), "variables_sha256": hashlib.sha256(variables_path.read_bytes()).hexdigest(), "stack": policy["grafana"]["url"], "root": str(root.relative_to(ROOT))}
        if any(review.get(key) != value for key, value in expected.items()) or not 0 <= time.time() - review.get("reviewed_at", 0) <= 86400:
            raise ValueError("Plan/configuration/inputs changed or review expired; generate and inspect a new plan")
        guard(show_plan(path, env, root))
        logfile = logged_run(base + ["apply", "-input=false", str(path)], "grafana-apply", env)
        print("Grafana saved-plan apply completed; private log: " + str(logfile))


def grafana_info(policy):
    env = environment(include_grafana=True)
    if env.get("GRAFANA_URL", "").rstrip("/") != policy["grafana"]["url"] or not env.get("GRAFANA_AUTH"):
        raise ValueError("Set the exact GRAFANA_URL and a private service-account token or MONITORING_GRAFANA_AUTH_FILE")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            raise ValueError("Refusing to forward Grafana authentication through a redirect")
    request = urllib.request.Request(policy["grafana"]["url"] + "/api/datasources", headers={"Authorization": "Bearer " + env["GRAFANA_AUTH"]})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
            sources = json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError(f"Grafana read-only data-source lookup returned HTTP {error.code}; check token scope") from None
    print(json.dumps([{key: source.get(key) for key in ("uid", "name", "type")} for source in sources], indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("inventory", "validate", "syntax", "grafana-info"):
        child = sub.add_parser(name)
        if name == "validate":
            child.add_argument("--inventory", type=Path, default=INVENTORY, help="Inventory for read-only policy validation; deployment always requires the private inventory")
    for name in ("preflight", "plan", "deploy"):
        child = sub.add_parser(name)
        child.add_argument("--component", choices=PLAYBOOKS, default="collectors")
        child.add_argument("--targets", required=True, help="Exact comma-separated inventory names; no patterns")
        child.add_argument("--private-inventory", required=True)
        child.add_argument("--private-vars", required=True)
    child = sub.add_parser("deploy-fleet", help="Terraform's creation-only fleet provisioner; no implicit targets")
    child.add_argument("--selection-json", required=True)
    child.add_argument("--private-inventory", required=True)
    child.add_argument("--private-vars", required=True)
    for name in ("grafana-plan", "grafana-apply", "stack-plan", "stack-apply"):
        child = sub.add_parser(name)
        child.add_argument("--vars", required=True, help="Owner-only Terraform JSON inputs outside checkout")
        child.add_argument("--plan", help="Saved plan in MONITORING_RUN_DIR")
        if name == "stack-plan":
            child.add_argument("--replace-fleet", action="store_true", help="Explicitly re-converge selected guests, for remote drift or private token rotation")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        policy = json.loads(DEFAULT_POLICY.read_text())
        validate_policy(policy, json.loads((args.inventory if args.command == "validate" else INVENTORY).read_text()))
        if args.command == "inventory":
            print(json.dumps({name: {key: value[key] for key in ("platform", "role", "environment", "components", "status")} for name, value in policy["hosts"].items()}, indent=2))
        elif args.command == "validate":
            mode = "Free path enabled" if policy["grafana"]["live_apply_enabled"] else ("Trial collector path configured; live edition check runs on plan/apply" if policy["grafana"].get("trial_collector_apply_enabled") else "no live collection")
            print(f"Monitoring policy valid: {len(policy['hosts'])} inventoried targets; live mode: {mode}. Budgets are collection targets, not billing caps.")
        elif args.command == "syntax":
            for playbook in PLAYBOOKS.values():
                log = logged_run([os.environ.get("ANSIBLE_PLAYBOOK_BIN", "ansible-playbook"), "-i", str(INVENTORY), "-i", str(EXTERNAL_INVENTORY), str(ROOT / "ansible/playbooks" / playbook), "--syntax-check"], "syntax-" + playbook)
                print("Syntax passed: " + playbook + "; private log: " + str(log))
        elif args.command == "grafana-info":
            grafana_info(policy)
        elif args.command == "deploy-fleet":
            deploy_fleet(args, policy)
        elif args.command in {"preflight", "plan", "deploy"}:
            selected = select_targets(policy, args.targets.split(","), args.component)
            private_inventory = private_file(args.private_inventory)
            private_vars = private_file(args.private_vars)
            env = environment()
            validate_access(selected, effective_hosts(private_inventory, env), private_json(private_vars), args.component)
            if args.command == "deploy" and args.component == "collectors":
                deployment = private_json(private_vars)
                if deployment.get("monitoring_grafana_zero_cost_mode_verified") is not True:
                    raise ValueError("Set monitoring_grafana_zero_cost_mode_verified=true in private deployment inputs")
                if policy["grafana"]["observed_plan"] == "trial":
                    if policy["grafana"].get("trial_collector_apply_enabled") is not True:
                        raise ValueError("Trial collector deployment is not enabled in monitoring/fleet.json")
                    verify_unbilled_trial(environment(include_grafana=True))
                elif policy["grafana"]["observed_plan"] != "free" or policy["grafana"]["live_apply_enabled"] is not True:
                    raise ValueError("Verify the zero-cost Grafana plan before collector deployment")
            log = logged_run(ansible_command(args.component, selected, private_inventory, private_vars, policy, apply=args.command == "deploy", preflight_only=args.command == "preflight"), "ansible-" + args.command + "-" + args.component, env)
            print("Selected monitoring operation completed: " + ",".join(selected) + "; private log: " + str(log))
        else:
            grafana_operation(args, policy)
    except (ValueError, OSError, KeyError) as error:
        print("Monitoring stopped: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
