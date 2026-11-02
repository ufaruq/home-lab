"""Local-only collector policy, rendered pipeline and Ansible preflight tests.

Use the controller Ansible environment. ALLOY_BINARY enables the official native
validator; no tests start Alloy or contact any remote write endpoint or guest.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

import jinja2
import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible/roles/monitoring_alloy"
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
MAIN = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
SENTINEL = "TEST_TOKEN_MUST_NEVER_APPEAR_123456"


def inputs(**overrides):
    values = dict(DEFAULTS, monitoring_access_verified=True,
                  monitoring_deployment_approved=True, monitoring_grafana_zero_cost_mode_verified=True,
                  monitoring_role="server",
                  monitoring_grafana_metrics_url="https://metrics.example.net/api/prom/push",
                  monitoring_grafana_metrics_username="12345",
                  monitoring_grafana_logs_url="https://logs.example.net/loki/api/v1/push",
                  monitoring_grafana_logs_username="67890",
                  monitoring_grafana_write_token=SENTINEL)
    values.update(overrides)
    return values


def render(platform="linux", **overrides):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROLE / "templates"),
                             undefined=jinja2.StrictUndefined)
    env.filters["to_json"] = json.dumps
    values = inputs(inventory_hostname="debian_server", monitoring_alloy_platform=platform,
                    monitoring_alloy_token_path="/private/token",
                    monitoring_alloy_storage_path="/private/data")
    values.update(overrides)
    return env.get_template("config.alloy.j2").render(values)


def tasks(platform):
    return yaml.safe_load((ROLE / f"tasks/{platform}.yml").read_text())


def walk(items):
    for task in items:
        yield task
        for key in ("block", "always", "rescue"):
            yield from walk(task.get(key, []))


class AlloyPipelineTests(unittest.TestCase):
    def test_tokens_are_runtime_secrets_and_never_rendered(self):
        for platform in ("linux", "windows"):
            config = render(platform)
            self.assertNotIn(SENTINEL, config)
            self.assertIn('is_secret = true', config)
            self.assertEqual(config.count('password = local.file.grafana_token.content'), 2)
            self.assertNotIn("insecure_skip_verify", config)
            self.assertNotIn("bearer_token =", config)

    def test_fixed_allowlist_sends_required_health_metrics_and_scrape_presence(self):
        config = render()
        regex = re.search(r'regex = "([^"]+)"\n    action = "keep"', config)[1]
        for metric in ("up", "node_filesystem_readonly", "node_filesystem_avail_bytes",
                       "node_filesystem_size_bytes", "node_memory_MemAvailable_bytes",
                       "windows_memory_available_bytes", "windows_memory_physical_total_bytes",
                       "windows_system_boot_time_timestamp"):
            self.assertIsNotNone(re.fullmatch(regex, metric), metric)
        for metric in ("container_memory_usage_bytes", "kube_pod_info", "node_systemd_unit_state",
                       "node_textfile_scrape_error", "windows_process_cpu_time_total"):
            self.assertIsNone(re.fullmatch(regex, metric), metric)
        self.assertIn('set_collectors = ["cpu", "meminfo", "filesystem", "netdev", "stat", "time"]', config)
        self.assertIn('sample_limit = 450', config)
        self.assertIn('max_shards = 1', config)
        self.assertNotIn('prometheus.exporter.cadvisor', config)
        self.assertNotIn('discovery.docker', config)
        for label, value in (("job", "homelab"), ("host", "debian_server"),
                             ("environment", "homelab"), ("role", "server")):
            self.assertIn(f'target_label = "{label}"\n    replacement = "{value}"', config)
        self.assertIn('job_name = "homelab"', config)

    def test_log_selection_history_and_volume_guards(self):
        config = render()
        self.assertIn('__path__ = "/var/log/dpkg.log"', config)
        for path in ("/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "*.log", "docker.sock"):
            self.assertNotIn(path, config)
        for guard in ('tail_from_end = true', 'on_positions_file_error = "restart_from_end"',
                      'longer_than = "4KB"', 'older_than = "1h"', 'rate = 0.2', 'drop = true'):
            self.assertIn(guard, config)
        windows = render("windows")
        self.assertIn('eventlog_name = "System"', windows)
        self.assertIn('eventlog_name = "Application"', windows)
        self.assertNotIn('eventlog_name = "Security"', windows)
        self.assertIn('Level=1 or Level=2 or Level=3', windows)
        self.assertIn('exclude_user_data = true', windows)

    def test_container_syslog_is_default_off_loopback_and_reuses_one_bounded_pipeline(self):
        self.assertIs(DEFAULTS['monitoring_alloy_container_syslog_enabled'], False)
        self.assertNotIn('loki.source.syslog', render())
        self.assertNotIn('loki.source.syslog', render('windows'))
        config = render(monitoring_alloy_container_syslog_enabled=True)
        self.assertIn('loki.source.syslog "containers"', config)
        self.assertIn('address = "127.0.0.1:1515"', config)
        self.assertIn('protocol = "tcp"', config)
        self.assertIn('syslog_format = "rfc5424"', config)
        self.assertIn('max_message_length = 8192', config)
        self.assertIn('label_structured_data = false', config)
        self.assertIn('relabel_rules = loki.relabel.container_apps.rules', config)
        self.assertEqual(config.count('loki.process "bounded"'), 1)
        self.assertEqual(config.count('stage.limit {'), 1)
        self.assertEqual(config.count('forward_to = [loki.process.bounded.receiver]'), 2)
        self.assertIn('"app"]', config)
        for forbidden in ('0.0.0.0', 'docker.sock', 'discovery.docker', 'labelmap', 'container_id'):
            self.assertNotIn(forbidden, config)

    def test_container_tags_are_allowlisted_and_not_used_as_host_identity(self):
        config = render(monitoring_alloy_container_syslog_enabled=True,
                        monitoring_alloy_container_syslog_apps=['maps', 'openwebui'])
        self.assertIn('source_labels = ["__syslog_message_app_name"]', config)
        self.assertIn('action = "keep"', config)
        regex = json.loads(re.search(r'regex = ("[^\n]+")\n    action = "keep"',
                                     config[config.index('loki.relabel "container_apps"'):])[1])
        for tag in ('homelab.maps', 'homelab.openwebui'):
            self.assertIsNotNone(re.fullmatch(regex, tag))
        for tag in ('maps', 'homelab.portainer', 'homelab.maps-123', 'homelab.maps|secret',
                    'homelab.openwebui-12345', '1a2b3c4d5e6f'):
            self.assertIsNone(re.fullmatch(regex, tag), tag)
        self.assertNotIn('__syslog_message_hostname', config)
        self.assertNotIn('__syslog_message_proc_id', config)
        self.assertIn('host = "debian_server"', config)
        self.assertIn('role = "server"', config)

    def test_sensitive_app_content_is_whole_line_redacted_before_delivery(self):
        config = render(monitoring_alloy_container_syslog_enabled=True)
        regex = re.search(r'expression = `([^`]+)`\n    replace = "\[REDACTED sensitive log entry\]"', config)[1]
        marker = '[REDACTED sensitive log entry]'
        for line in ('Authorization: Bearer abc123', '{"password":"abc123"}',
                     'GET /api?token=abc123', 'access_token: abc123',
                     '{"messages":[{"content":"private chat"}]}',
                     'latitude=37.7 longitude=-122.4', '-----BEGIN RSA PRIVATE KEY-----'):
            pattern = re.compile(regex)
            match = pattern.search(line)
            self.assertIsNotNone(match, line)
            self.assertEqual(line[:match.start(1)] + marker + line[match.end(1):], marker)
        for line in ('server started on port 8080', 'request failed: database unavailable'):
            self.assertIsNone(re.search(regex, line), line)
        self.assertLess(config.index('stage.replace {'), config.index('stage.limit {'))

    def test_compose_logging_example_preserves_fixed_tags_and_nonblocking_limits(self):
        fragment = yaml.safe_load((ROOT / 'monitoring/alloy/examples/compose.logging.yaml').read_text())
        expected = {'maps': 'homelab.maps', 'open-webui': 'homelab.openwebui', 'portainer': 'homelab.portainer'}
        self.assertEqual(set(fragment['services']), set(expected))
        for service, tag in expected.items():
            service_options = fragment['services'][service]
            self.assertEqual(set(service_options), {'logging'})
            self.assertEqual(service_options['logging']['driver'], 'syslog')
            options = service_options['logging']['options']
            self.assertEqual(options['syslog-address'], 'tcp://127.0.0.1:1515')
            self.assertEqual(options['syslog-format'], 'rfc5424')
            self.assertEqual(options['tag'], tag)
            self.assertEqual(options['mode'], 'non-blocking')
            self.assertEqual(options['max-buffer-size'], '1m')
            self.assertEqual(options['cache-max-size'], '5m')
            self.assertEqual(options['cache-max-file'], '2')
            self.assertEqual(options['cache-compress'], 'true')
            self.assertNotIn('env', options)
            self.assertNotIn('env-regex', options)

    def test_linux_service_has_minimal_privileges_and_local_management(self):
        unit = (ROLE / "templates/alloy.service.j2").read_text()
        for required in ('User=alloy', 'Group=alloy', 'NoNewPrivileges=true',
                         'CapabilityBoundingSet=\n', 'ProtectSystem=strict',
                         'ReadWritePaths=/var/lib/alloy', '127.0.0.1:12345', '--disable-reporting'):
            self.assertIn(required, unit)
        self.assertNotIn('SupplementaryGroups=adm', unit)
        account = next(t['ansible.builtin.user'] for t in tasks('linux') if 'ansible.builtin.user' in t)
        self.assertEqual(account['groups'], '')
        token = next(t for t in tasks('linux') if t.get('ansible.builtin.copy', {}).get('dest') == '/etc/alloy/grafana-write-token')
        self.assertEqual(token['ansible.builtin.copy']['mode'], '0640')
        self.assertTrue(token['no_log'])
        self.assertFalse(token['diff'])

    def test_native_validation_precedes_activation_and_staging_is_cleaned(self):
        linux = next(t for t in tasks('linux') if t.get('ansible.builtin.template', {}).get('dest') == '/etc/alloy/config.alloy')
        self.assertEqual(linux['ansible.builtin.template']['validate'], '/usr/bin/alloy validate %s')
        windows = list(walk(tasks('windows')))
        names = [t['name'] for t in windows]
        self.assertLess(names.index('Run native Windows Alloy validator without starting telemetry'),
                        names.index('Activate validated Windows configuration'))
        self.assertLess(names.index('Activate validated Windows configuration'),
                        names.index('Apply validated Windows collector changes'))
        self.assertIn('Remove Windows staging configuration', names)
        source = (ROLE / 'tasks/windows.yml').read_text()
        self.assertIn("'S-1-5-18', 'S-1-5-32-544'", source)
        self.assertIn('$acl.SetAccessRuleProtection($true, $false)', source)
        self.assertIn('if (-not (Test-Path -LiteralPath $path))', source)
        self.assertIn('Bookmark.BookmarkXml', source)
        self.assertNotIn('Remove-Item', source)

    def test_all_credential_material_tasks_hide_output_and_diffs(self):
        for task in walk(tasks('linux') + tasks('windows')):
            if any(key in task for key in ('block', 'always', 'rescue')):
                continue
            serialized = json.dumps(task)
            if 'monitoring_grafana_write_token' in serialized or 'config.alloy.j2' in serialized:
                self.assertIs(task.get('no_log'), True, task['name'])
                self.assertIs(task.get('diff'), False, task['name'])

    def test_downloads_require_explicit_install_and_checksum_validation(self):
        for platform, key in (('linux', 'ansible.builtin.get_url'), ('windows', 'ansible.windows.win_get_url')):
            tree = tasks(platform)
            blocks = [t for t in tree if 'block' in t and any(key in sub for sub in t['block'])]
            self.assertEqual(len(blocks), 1)
            self.assertEqual(blocks[0]['when'], 'not monitoring_alloy_binary.stat.exists')
            download = next(t[key] for t in blocks[0]['block'] if key in t)
            self.assertIn('https://github.com/grafana/alloy/releases/download/v', download['url'])
            self.assertIn('checksum', download)
            self.assertIs(download['validate_certs'], True)
        apt = next(t['ansible.builtin.apt'] for t in walk(tasks('linux')) if 'ansible.builtin.apt' in t)
        self.assertEqual(apt['policy_rc_d'], 101)
        self.assertFalse(apt['update_cache'])
        self.assertNotIn('upgrade', apt)

    @unittest.skipUnless(os.environ.get('ALLOY_BINARY'), 'set ALLOY_BINARY to pinned official native binary')
    def test_rendered_configs_pass_native_offline_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / 'config.alloy'
            for platform, overrides in (('linux', {}), ('linux', {'monitoring_alloy_container_syslog_enabled': True}),
                                        ('windows', {})):
                with self.subTest(platform=platform, options=overrides):
                    config.write_text(render(platform, **overrides))
                    result = subprocess.run([os.environ['ALLOY_BINARY'], 'validate', str(config)],
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            config.write_text('prometheus.invalid_component "broken" {}\n')
            result = subprocess.run([os.environ['ALLOY_BINARY'], 'validate', str(config)],
                                    capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)


class AlloyAnsiblePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playbook = os.environ.get('ANSIBLE_PLAYBOOK') or shutil.which('ansible-playbook')
        if not cls.playbook:
            raise unittest.SkipTest('ansible-playbook unavailable')

    def preflight(self, overrides=None, group='linux_guests', os_facts=None):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)
            # Exactly the four declarative preflight tasks, with no setup or mutations.
            values = inputs(**(overrides or {}))
            checks = list(MAIN[:4])
            if os_facts is not None:
                values['ansible_facts'] = os_facts
                checks.append(tasks('linux')[1])
            play = [{'hosts': 'all', 'gather_facts': False, 'vars': values, 'tasks': checks}]
            (path / 'play.yml').write_text(yaml.safe_dump(play))
            (path / 'inventory.yml').write_text(yaml.safe_dump({'all': {'children': {group: {'hosts': {'fixture': {'ansible_connection': 'local'}}}}}}))
            env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(path / 'local'), ANSIBLE_NOCOLOR='1',
                       ANSIBLE_HOST_KEY_CHECKING='True')
            result = subprocess.run([self.playbook, '-i', str(path / 'inventory.yml'), str(path / 'play.yml')],
                                    capture_output=True, text=True, env=env, timeout=30, cwd=ROOT)
            self.assertNotIn(SENTINEL, result.stdout + result.stderr)
            return result

    def test_authorized_preflight_accepts_both_platform_groups(self):
        for group in ('linux_guests', 'windows_guests'):
            result = self.preflight(group=group)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_gate_rejects_strings_and_missing_approval_before_private_inputs(self):
        for value in (False, 'true', 1):
            result = self.preflight({'monitoring_access_verified': value})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Alloy requires verified access', result.stdout)
            self.assertNotIn('TASK [Validate private', result.stdout)
        result = self.preflight({'monitoring_deployment_approved': False})
        self.assertNotEqual(result.returncode, 0)

    def test_unverified_zero_cost_mode_blocks_before_private_inputs(self):
        for value in (False, 'true', 1):
            result = self.preflight({'monitoring_grafana_zero_cost_mode_verified': value})
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('TASK [Validate private', result.stdout)

    def test_debian_derivatives_are_supported_without_broadening_os_or_service_manager(self):
        for distribution in ('Debian', 'Ubuntu', 'Pop!_OS', 'Parrot'):
            result = self.preflight(os_facts={'distribution': distribution, 'os_family': 'Debian',
                                              'architecture': 'x86_64', 'service_mgr': 'systemd'})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for facts in ({'os_family': 'RedHat', 'architecture': 'x86_64', 'service_mgr': 'systemd'},
                      {'os_family': 'Debian', 'architecture': 'armv7l', 'service_mgr': 'systemd'},
                      {'os_family': 'Debian', 'architecture': 'x86_64', 'service_mgr': 'sysvinit'}):
            self.assertNotEqual(self.preflight(os_facts=facts).returncode, 0)

    def test_insecure_endpoints_and_url_credentials_fail_closed(self):
        for url in ('http://metrics.example.net/api/prom/push',
                    'https://user:password@metrics.example.net/api/prom/push',
                    'https://metrics.example.net/api/prom/push?token=secret'):
            result = self.preflight({'monitoring_grafana_metrics_url': url})
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('TASK [Validate labels', result.stdout)

    def test_unbounded_or_sensitive_collections_and_pin_changes_rejected(self):
        for override in ({'monitoring_alloy_sample_limit': 0}, {'monitoring_alloy_sample_limit': 451},
                         {'monitoring_alloy_log_rate': 1}, {'monitoring_alloy_log_burst': 11},
                         {'monitoring_alloy_linux_log_files': ['/var/log/auth.log']},
                         {'monitoring_alloy_linux_log_files': ['/var/log/*.log']},
                         {'monitoring_alloy_windows_event_channels': ['Security']},
                         {'monitoring_alloy_version': 'latest'}):
            result = self.preflight(override)
            self.assertNotEqual(result.returncode, 0, override)

    def test_container_options_reject_nonbooleans_unknown_apps_and_windows_receiver(self):
        for override in ({'monitoring_alloy_container_syslog_enabled': 'true'},
                         {'monitoring_alloy_container_syslog_enabled': 1},
                         {'monitoring_alloy_container_syslog_apps': ['unknown']},
                         {'monitoring_alloy_container_syslog_apps': ['maps|.*']},
                         {'monitoring_alloy_container_syslog_apps': 'maps'},
                         {'monitoring_alloy_container_syslog_enabled': True,
                          'monitoring_alloy_container_syslog_apps': []}):
            self.assertNotEqual(self.preflight(override).returncode, 0, override)
        enabled = {'monitoring_alloy_container_syslog_enabled': True,
                   'monitoring_alloy_container_syslog_apps': ['maps', 'openwebui']}
        linux = self.preflight(enabled)
        self.assertEqual(linux.returncode, 0, linux.stdout + linux.stderr)
        self.assertNotEqual(self.preflight(enabled, group='windows_guests').returncode, 0)

    def test_dom0_and_appliance_groups_are_rejected(self):
        for group in ('xen_hosts', 'appliance_guests', 'bsd_guests'):
            self.assertNotEqual(self.preflight(group=group).returncode, 0)


if __name__ == '__main__':
    unittest.main()
