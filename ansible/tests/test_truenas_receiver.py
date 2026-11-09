"""Offline security boundaries; native daemons/end-to-end TLS require target checks."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / 'ansible/roles/monitoring_wazuh_truenas'


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROLE / 'files' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TrueNASReceiverTests(unittest.TestCase):
    def test_accepts_only_distinct_rfc1918_literals(self):
        validate = load('validate_inputs').validate
        validate('10.23.1.2', '192.168.33.8')
        validate('172.31.0.8', '172.16.0.8')
        for bad in ['0.0.0.0', '127.0.0.1', '169.254.0.1', '100.64.0.2',
                    '192.0.2.4', '8.8.8.8', '172.32.0.1', '::1',
                    '10.0.0.1/24', '10.0.0.1\nstop', 'truenas.lan',
                    '10.0.0.1" then { stop }', '010.0.0.1']:
            for args in [(bad, '10.23.1.2'), ('10.23.1.2', bad)]:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    validate(*args)
        with self.assertRaises(ValueError):
            validate('10.0.0.1', '10.0.0.1')

    def test_remote_address_validator_cli_fails_closed(self):
        result = subprocess.run([sys.executable, str(ROLE / 'files/validate_inputs.py'),
                                 '0.0.0.0', '10.0.0.1'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_existing_localfiles_and_unrelated_policy_survive_preflight(self):
        m = load('validate_wazuh')
        text = '<ossec_config>\n<auth><disabled>no</disabled></auth>\n</ossec_config>\n'
        m.validate(text)
        block = (m.BEGIN + '\n<localfile><log_format>syslog</log_format>'
                 '<location>' + m.LOCATION + '</location></localfile>\n' + m.END)
        existing = text.replace('</ossec_config>', block + '\n</ossec_config>')
        m.validate(existing)
        m.validate(existing + text)
        for invalid in [existing + existing, existing.replace(m.END, ''),
                        existing.replace(m.BEGIN, ''),
                        existing.replace('syslog', 'command'),
                        existing.replace(m.BEGIN, '').replace(m.END, ''),
                        existing.replace('</localfile>', '</localfile><remote/>')]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                m.validate(invalid)

    def test_receiver_has_no_plaintext_or_default_config_input(self):
        config = (ROLE / 'templates/rsyslog.conf.j2').read_text()
        for required in ['StreamDriver.Name="gtls"', 'StreamDriver.Mode="1"',
                         'StreamDriver.AuthMode="x509/name"',
                         'StreamDriver.PermitExpiredCerts="off"',
                         'StreamDriver.CheckExtendedKeyPurpose="on"',
                         'PermittedPeer="homelab-truenas"',
                         '-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2',
                         '$fromhost-ip != "{{ monitoring_truenas_source_address }}"',
                         'address="{{ monitoring_truenas_receiver_address }}"',
                         'port="6514"', 'RSYSLOG_TraditionalFileFormat',
                         'queue.size="10000"', 'maxMessageSize="8k"', 'dirCreateMode="02750"']:
            self.assertIn(required, config)
        self.assertEqual(config.count('input(type='), 1)
        self.assertNotIn('module(load="imudp"', config)
        self.assertNotIn('include(', config)
        self.assertNotIn('queue.filename', config)
        self.assertNotIn('omfwd', config)

    def test_service_cannot_read_wazuh_or_write_arbitrary_system_paths(self):
        unit = (ROLE / 'templates/receiver.service.j2').read_text()
        for required in ['User=homelab-syslog', 'Group=homelab-syslog',
                         'CapabilityBoundingSet=\n', 'NoNewPrivileges=true',
                         'ProtectSystem=strict', 'ProtectHome=true', 'MemoryMax=192M']:
            self.assertIn(required, unit)
        self.assertNotIn('SupplementaryGroups=wazuh', unit)
        self.assertNotIn('User=root', unit)
        self.assertNotIn('ReadWritePaths=/var/ossec', unit)

    def test_approval_validation_rollback_and_no_upgrade_contract(self):
        tasks = (ROLE / 'tasks/main.yml').read_text()
        for flag in ['monitoring_access_verified', 'monitoring_deployment_approved']:
            self.assertIn(flag + ' is sameas true', tasks)
        self.assertIn('monitoring_truenas_receiver_install_approved is sameas true', tasks)
        self.assertIn('allow_unauthenticated: false', tasks)
        self.assertIn("item.stat.mode == '0600'", tasks)
        self.assertIn('/var/ossec/bin/wazuh-logcollector -t -c %s', tasks)
        self.assertIn('rescue:', tasks)
        self.assertIn('truenas_wazuh_config.backup_file', tasks)
        self.assertLess(tasks.index('Validate isolated rsyslog configuration'),
                        tasks.index('Activate isolated receiver after'))
        self.assertNotIn('name: wazuh-manager\n    state: present', tasks)

    def test_apparmor_extension_is_narrow_and_keeps_vendor_profile_enforced(self):
        snippet = (ROLE / 'templates/apparmor.j2').read_text()
        rules = {line.strip() for line in snippet.splitlines() if line and not line.startswith('#')}
        self.assertEqual(rules, {
            '/etc/homelab-truenas/rsyslog.conf r,', '/etc/homelab-truenas/ca.pem r,',
            '/etc/homelab-truenas/server.pem r,', '/etc/homelab-truenas/server.key r,',
            'owner /run/homelab-truenas/ rw,', 'owner /run/homelab-truenas/rsyslog.pid{,.tmp} rwk,',
            'owner /var/lib/homelab-truenas/ rw,', 'owner /var/lib/homelab-truenas/* rwk,'})
        self.assertNotIn('/**', snippet)
        self.assertNotIn('capability', snippet)
        self.assertNotIn('/var/ossec', snippet)
        tasks = (ROLE / 'tasks/main.yml').read_text()
        self.assertIn('include if exists <rsyslog', tasks)
        self.assertIn("'rsyslogd (enforce)' in truenas_apparmor_loaded.stdout_lines", tasks)
        self.assertIn("'rsyslogd (enforce)' in truenas_apparmor_reloaded.stdout_lines", tasks)
        self.assertIn("'rsyslogd (enforce)' in truenas_apparmor_restored.stdout_lines", tasks)
        self.assertIn('--skip-kernel-load, --skip-cache, /etc/apparmor.d/usr.sbin.rsyslogd', tasks)
        self.assertIn('--replace, --skip-cache, /etc/apparmor.d/usr.sbin.rsyslogd', tasks)
        self.assertLess(tasks.index('Compile retained AppArmor profile'), tasks.index('Reload enforced rsyslog AppArmor'))
        self.assertLess(tasks.index('Reload enforced rsyslog AppArmor'), tasks.index('Validate isolated rsyslog configuration'))
        snapshot = tasks[tasks.index('truenas_owned_files:'):tasks.index('- name: Record prior service state')]
        self.assertIn('/etc/apparmor.d/rsyslog.d/homelab-truenas', snapshot)
        rescue = tasks[tasks.index('  rescue:'):]
        self.assertLess(rescue.index('Remove only newly introduced owned configuration'),
                        rescue.index('Reload prior enforced AppArmor'))
        self.assertLess(rescue.index('Reload prior enforced AppArmor'), rescue.index('Restore prior owned service state'))
        for bypass in ('--Complain', '--remove', 'aa-complain', 'aa-disable', 'apparmor=0'):
            self.assertNotIn(bypass, tasks)

    def test_rotation_has_finite_retention_and_native_periodic_execution(self):
        config = (ROLE / 'templates/logrotate.j2').read_text()
        for required in ['maxsize 64M', 'rotate 7', 'maxage 7',
                         'create 0640 homelab-syslog wazuh', 'delaycompress']:
            self.assertIn(required, config)
        self.assertIn('OnCalendar=hourly', (ROLE / 'templates/rotate.timer.j2').read_text())


if __name__ == '__main__':
    unittest.main()
