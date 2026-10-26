import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("monitoring_manage", ROOT / "scripts/monitoring/manage.py")
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)


class MonitoringPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "monitoring/fleet.json").read_text())
        self.inventory = json.loads((ROOT / "tests/fixtures/monitoring/hosts.json").read_text())

    def test_live_trial_check_requires_both_editions_and_refuses_redirects(self):
        env = {"GRAFANA_URL": "https://cordialbike2680.grafana.net", "GRAFANA_AUTH": "fixture"}
        for license_edition, build_edition in (("Cloud Trial", "Cloud Trial"), ("Cloud", "Cloud Trial"), ("Cloud Trial", "Cloud"), (None, None)):
            settings = {"licenseInfo": {"edition": license_edition}, "buildInfo": {"edition": build_edition}}
            opener = mock.Mock()
            opener.open.return_value.__enter__ = mock.Mock(return_value=io.StringIO(json.dumps(settings)))
            opener.open.return_value.__exit__ = mock.Mock(return_value=False)
            with self.subTest(editions=(license_edition, build_edition)), mock.patch.object(manage.urllib.request, "build_opener", return_value=opener) as factory:
                if license_edition == build_edition == "Cloud Trial":
                    manage.verify_unbilled_trial(env)
                else:
                    with self.assertRaises(ValueError):
                        manage.verify_unbilled_trial(env)
                with self.assertRaises(ValueError):
                    factory.call_args.args[0]().redirect_request(None, None, 302, "redirect", {}, "https://other.example")

    def test_inventory_covers_the_existing_fleet_without_assuming_runtime_health(self):
        manage.validate_policy(self.policy, self.inventory)
        self.assertEqual(len(self.policy["hosts"]), 16)
        self.assertEqual({n for n, h in self.policy["hosts"].items() if h["status"] == "blocked"}, {"deb_node_db", "deb_node_slim"})
        self.assertFalse(self.policy["grafana"]["live_apply_enabled"])

    def test_free_limits_are_hard_local_configuration_bounds(self):
        for field, bad_value in (("active_series", 10001), ("daily_log_mb", 2000), ("scrape_interval_seconds", 1), ("wazuh_alert_retention_days", 365), ("wazuh_alert_retention_days", 1)):
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                policy["budgets"][field] = bad_value
                with self.assertRaises(ValueError):
                    manage.validate_policy(policy, self.inventory)

    def test_environment_refuses_identity_bypasses_and_limits_management_credentials(self):
        for overrides in ({"ANSIBLE_HOST_KEY_CHECKING": "False"},
                          {"ANSIBLE_SSH_ARGS": "-o StrictHostKeyChecking=no"},
                          {"ANSIBLE_SSH_COMMON_ARGS": "-o UserKnownHostsFile=/dev/null"},
                          {"GRAFANA_INSECURE_SKIP_VERIFY": "true"}):
            with self.subTest(overrides=overrides), mock.patch.dict(os.environ, overrides, clear=True), mock.patch.object(manage, "run_directory", return_value=Path("/private/runtime")):
                with self.assertRaises(ValueError):
                    manage.environment()
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("fixture-private-token\n")
            token.chmod(0o600)
            with mock.patch.dict(os.environ, {"MONITORING_GRAFANA_AUTH_FILE": str(token)}, clear=True), mock.patch.object(manage, "run_directory", return_value=Path(directory)):
                self.assertNotIn("GRAFANA_AUTH", manage.environment())
                self.assertEqual(manage.environment(include_grafana=True)["GRAFANA_AUTH"], "fixture-private-token")
                token.chmod(0o644)
                with self.assertRaises(ValueError):
                    manage.environment(include_grafana=True)

    def test_unknown_inventory_entries_and_hypervisor_agents_are_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy["hosts"]["invented"] = policy["hosts"].pop("maps")
        with self.assertRaises(ValueError):
            manage.validate_policy(policy, self.inventory)
        policy = copy.deepcopy(self.policy)
        policy["hosts"]["datacenter1"]["components"] = ["alloy"]
        with self.assertRaises(ValueError):
            manage.validate_policy(policy, self.inventory)

    def test_exact_selection_rejects_patterns_duplicates_and_blocked_hosts(self):
        for names in ([], ["maps", "maps"], ["all"], ["maps:*"], ["deb_node_db"], ["datacenter1"], ["truenas"]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                manage.select_targets(self.policy, names, "collectors")
        self.assertEqual(manage.select_targets(self.policy, ["maps", "windows_10"], "collectors"), ["maps", "windows_10"])
        self.assertEqual(manage.select_targets(self.policy, ["oracle_wazuh"], "manager"), ["oracle_wazuh"])
        self.assertEqual(manage.select_targets(self.policy, ["firewall"], "opnsense"), ["firewall"])

    def test_group_policy_stays_alert_only_for_test_labs(self):
        selected = manage.target_variables(self.policy, ["parrot_htb", "ubuntu_malware_lab", "maps"])
        self.assertEqual(selected["monitoring_host_policies"]["parrot_htb"]["environment"], "lab")
        self.assertEqual(selected["monitoring_host_policies"]["maps"]["environment"], "homelab")
        self.assertNotIn("monitoring_deployment_approved", selected)
        self.assertNotIn("monitoring_access_verified", selected)

    def test_private_inputs_reject_repo_paths_and_readable_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secrets.json"
            path.write_text('{"monitoring_access_verified":true}')
            path.chmod(0o600)
            self.assertEqual(manage.private_file(path), path.resolve())
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                manage.private_file(path)
        with self.assertRaises(ValueError):
            manage.private_file(ROOT / "monitoring/fleet.json")

    def test_preflight_checks_all_targets_before_any_deployment(self):
        effective = {"maps": {"ansible_host": "192.168.1.10", "ansible_user": "operator", "monitoring_access_verified": True, "monitoring_deployment_approved": True}, "windows_10": {"ansible_host": "192.168.1.11", "ansible_user": "Administrator", "monitoring_access_verified": False, "monitoring_deployment_approved": True}}
        with self.assertRaises(ValueError):
            manage.validate_access(["maps", "windows_10"], effective, {}, "collectors")
        effective["windows_10"]["monitoring_access_verified"] = True
        manage.validate_access(["maps", "windows_10"], effective, {}, "collectors")
        effective["maps"]["monitoring_access_verified"] = "true"
        with self.assertRaises(ValueError):
            manage.validate_access(["maps"], effective, {}, "collectors")

    def test_ansible_command_is_argv_scoped_and_check_mode_by_default(self):
        command = manage.ansible_command("collectors", ["maps"], Path("/private/inventory.json"), Path("/private/vars.json"), self.policy, apply=False)
        self.assertIn("--check", command)
        self.assertNotIn("--diff", command)
        self.assertEqual(command[command.index("--limit") + 1], "maps")
        values = json.loads(command[-1])
        self.assertEqual(values["monitoring_targets"], ["maps"])
        self.assertNotIn("monitoring_deployment_approved", values)

    def test_saved_plan_scope_refuses_billing_permissions_deletion_and_wrong_provider(self):
        good = {"resource_changes": [{"mode": "managed", "address": "grafana_dashboard.fleet", "type": "grafana_dashboard", "provider_name": "registry.terraform.io/grafana/grafana", "change": {"actions": ["create"]}}]}
        self.assertEqual(manage.guard_grafana_plan(good), {"create": 1, "update": 0, "no-op": 0})
        for kind, actions, provider in (("grafana_cloud_stack", ["create"], "registry.terraform.io/grafana/grafana"), ("grafana_dashboard", ["delete", "create"], "registry.terraform.io/grafana/grafana"), ("grafana_service_account", ["create"], "registry.terraform.io/grafana/grafana"), ("grafana_dashboard", ["create"], "untrusted/provider")):
            plan = copy.deepcopy(good)
            plan["resource_changes"][0].update(type=kind, provider_name=provider)
            plan["resource_changes"][0]["change"]["actions"] = actions
            with self.subTest(kind=kind, actions=actions), self.assertRaises(ValueError):
                manage.guard_grafana_plan(plan)

    def test_grafana_apply_requires_actual_free_mode_and_exact_stack(self):
        with self.assertRaises(ValueError):
            manage.grafana_gate(self.policy, {"free_plan_verified": True}, {"GRAFANA_URL": self.policy["grafana"]["url"], "GRAFANA_AUTH": "private-token"})
        policy = copy.deepcopy(self.policy)
        policy["grafana"].update(observed_plan="free", live_apply_enabled=True)
        env = {"GRAFANA_URL": policy["grafana"]["url"], "GRAFANA_AUTH": "private-token"}
        manage.grafana_gate(policy, {"free_plan_verified": True}, env)
        env["GRAFANA_URL"] = "https://other.grafana.net"
        with self.assertRaises(ValueError):
            manage.grafana_gate(policy, {"free_plan_verified": True}, env)

    def test_unbilled_trial_allows_only_explicit_dashboard_configuration(self):
        policy = copy.deepcopy(self.policy)
        policy['grafana']['trial_dashboard_apply_enabled'] = True
        variables = {'free_plan_verified': False, 'unbilled_trial_dashboard_only_verified': True}
        env = {'GRAFANA_URL': policy['grafana']['url'], 'GRAFANA_AUTH': 'fixture-token'}
        manage.grafana_gate(policy, variables, env, dashboard_only=True)
        for override in ({'collector_targets': ['maps']}, {'wazuh_manager_targets': ['oracle_wazuh']},
                         {'opnsense_targets': ['firewall']}, {'expected_linux_hosts': ['maps']},
                         {'alerts_enabled': True}, {'unbilled_trial_dashboard_only_verified': 'true'}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                manage.grafana_gate(policy, dict(variables, **override), env, dashboard_only=True)
        with self.assertRaises(ValueError):
            manage.grafana_gate(policy, variables, env)

    def test_trial_resource_guard_rejects_alerts_and_guest_orchestration(self):
        base = {'mode': 'managed', 'address': 'module.grafana.grafana_dashboard.homelab["fleet"]', 'type': 'grafana_dashboard', 'provider_name': 'registry.terraform.io/grafana/grafana', 'change': {'actions': ['create']}}
        manage.guard_trial_dashboard_plan({'resource_changes': [base]})
        for kind, address in [('grafana_rule_group', 'module.grafana.grafana_rule_group.fleet[0]'), ('terraform_data', 'terraform_data.fleet[0]')]:
            resource = dict(base, type=kind, address=address)
            if kind == 'terraform_data': resource['provider_name'] = 'terraform.io/builtin/terraform'
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                manage.guard_trial_dashboard_plan({'resource_changes': [resource]})

    def test_composition_allows_only_declared_local_orchestration(self):
        base = {"mode": "managed", "address": "terraform_data.fleet[0]", "type": "terraform_data", "provider_name": "terraform.io/builtin/terraform", "change": {"actions": ["delete", "create"]}}
        self.assertEqual(manage.guard_stack_plan({"resource_changes": [base]})["orchestration"], 1)
        base["address"] = "terraform_data.unreviewed"
        with self.assertRaises(ValueError):
            manage.guard_stack_plan({"resource_changes": [base]})

    def test_fleet_selection_has_no_implicit_or_unknown_components(self):
        selected = {"collectors": ["maps"], "manager": ["oracle_wazuh"], "opnsense": ["firewall"]}
        self.assertEqual(manage.fleet_selection(self.policy, selected), selected)
        for invalid in ({}, {"collectors": [], "manager": [], "opnsense": []}, dict(selected, arbitrary=["datacenter1"]), dict(selected, collectors="all")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                manage.fleet_selection(self.policy, invalid)

    def test_fleet_validates_every_target_before_first_play(self):
        from types import SimpleNamespace
        args = SimpleNamespace(selection_json=json.dumps({"collectors": ["maps"], "manager": ["oracle_wazuh"], "opnsense": []}), private_inventory="/private/inventory.json", private_vars="/private/vars.json")
        effective = {"oracle_wazuh": {"ansible_host": "192.168.1.2", "ansible_user": "operator", "monitoring_access_verified": True, "monitoring_deployment_approved": True}, "maps": {"monitoring_access_verified": False}}
        with mock.patch.object(manage, "private_file", side_effect=lambda p: Path(p)), mock.patch.object(manage, "private_json", return_value={}), mock.patch.object(manage, "environment", return_value={}), mock.patch.object(manage, "effective_hosts", return_value=effective), mock.patch.object(manage, "logged_run") as run:
            with self.assertRaises(ValueError):
                manage.deploy_fleet(args, self.policy)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
