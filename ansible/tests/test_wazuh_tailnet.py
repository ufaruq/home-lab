"""Offline behavior checks for private dashboard edits and tailnet boundaries."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class TailnetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'monitoring/wazuh/dashboard_config.py'
        cls.assert_helper_exists = path.exists()
        if path.exists():
            spec = importlib.util.spec_from_file_location('dashboard_config', path)
            cls.helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.helper)

    def helper_module(self):
        self.assertTrue(self.assert_helper_exists, 'Dashboard safety helper has not been implemented')
        return self.helper

    def test_private_edit_preserves_secrets_comments_and_indexer_tls(self):
        helper = self.helper_module()
        import yaml
        original = ('# operator comment\nserver.host: "0.0.0.0" # old bind\n'
                    'server.port: 443\nserver.ssl.enabled: true\n'
                    'opensearch.password: "private:#value"\n'
                    'opensearch.ssl.verificationMode: certificate\n'
                    'opensearch.hosts: ["https://127.0.0.1:9200"]\n'
                    'unrelated: |\n  preserve this text\n')
        result = helper.render_config(original)
        self.assertIn('# operator comment\n', result)
        self.assertIn('# old bind\n', result)
        self.assertIn('opensearch.password: "private:#value"\n', result)
        self.assertIn('unrelated: |\n  preserve this text\n', result)
        data = yaml.safe_load(result)
        self.assertEqual(data['server.host'], '127.0.0.1')
        self.assertEqual(data['server.port'], 5601)
        self.assertIs(data['server.ssl.enabled'], False)
        self.assertIs(data['opensearch_security.cookie.secure'], True)
        self.assertEqual(data['opensearch.ssl.verificationMode'], 'certificate')
        self.assertEqual(data['opensearch.hosts'], ['https://127.0.0.1:9200'])
        self.assertEqual(helper.render_config(result), result)

    def test_quoted_owned_keys_are_replaced_and_duplicate_keys_fail_closed(self):
        helper = self.helper_module()
        import yaml
        result = yaml.safe_load(helper.render_config('"server.host": "::"\n'))
        self.assertEqual(result['server.host'], '127.0.0.1')
        for source in ('server.host: localhost\n"server.host": "::"\n',
                       'server:\n  host: 0.0.0.0\n',
                       'server.host: |\n  0.0.0.0\n',
                       '<<: *defaults\nserver.host: localhost\n',
                       '---\nserver.host: localhost\n---\nserver.host: other\n'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                helper.render_config(source)

    def test_expected_running_identity_and_hostname_bounds(self):
        helper = self.helper_module()
        state = {'BackendState': 'Running', 'Self': {'Online': True, 'DNSName': 'homelab-wazuh.example.ts.net.'}}
        self.assertEqual(helper.validate_identity(state, 'example.ts.net', 'homelab-wazuh'), 'homelab-wazuh.example.ts.net')
        for hostname in ('', '-bad', 'bad-', 'a' * 64, 'a.b', 'bad/host'):
            with self.subTest(hostname=hostname), self.assertRaises(ValueError):
                helper.validate_identity(state, 'example.ts.net', hostname)
        for field, value in (('BackendState', 'NeedsLogin'), ('Self', {'Online': True, 'DNSName': 'homelab-wazuh.other.ts.net.'})):
            invalid = dict(state, **{field: value})
            with self.assertRaises(ValueError):
                helper.validate_identity(invalid, 'example.ts.net', 'homelab-wazuh')

    def test_serve_refuses_public_or_unrelated_existing_configuration(self):
        helper = self.helper_module()
        fqdn = 'homelab-wazuh.example.ts.net'
        managed = {'TCP': {'443': {'HTTPS': True}}, 'Web': {fqdn + ':443': {'Handlers': {'/': {'Proxy': 'http://127.0.0.1:5601'}}}}}
        helper.validate_serve({}, fqdn)
        helper.validate_serve(managed, fqdn)
        for alteration in ({'AllowFunnel': {fqdn + ':443': True}}, {'TCP': {'80': {'HTTP': True}}},
                           {'Web': {'other.example.ts.net:443': {'Handlers': {'/': {'Proxy': 'http://127.0.0.1:5601'}}}}},
                           {'Foreground': {'session': {}}}):
            invalid = copy.deepcopy(managed)
            invalid.update(alteration)
            with self.subTest(alteration=alteration), self.assertRaises(ValueError):
                helper.validate_serve(invalid, fqdn)

    def test_existing_exit_nodes_and_advertised_routes_are_rejected(self):
        helper = self.helper_module()
        safe = {'AdvertiseRoutes': [], 'ExitNodeID': '', 'ExitNodeIP': '', 'AdvertiseTags': []}
        helper.validate_network_preferences(safe)
        for key, value in (('AdvertiseRoutes', ['10.0.0.0/8']), ('ExitNodeID', 'node-id'),
                           ('ExitNodeIP', '100.100.0.1'), ('AdvertiseRoutes', ['0.0.0.0/0'])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                helper.validate_network_preferences(dict(safe, **{key: value}))

    def test_cli_stages_private_file_and_censors_secret_bearing_invalid_input(self):
        self.helper_module()
        command = [sys.executable, str(ROOT / 'monitoring/wazuh/dashboard_config.py'), 'render']
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / 'source.yml', Path(directory) / 'staged.yml'
            source.write_bytes(b'# retain CRLF\r\nopensearch.password: "private-value"\r\nserver.host: "::"\r\n')
            result = subprocess.run(command + ['--source', str(source), '--destination', str(destination)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn(b'# retain CRLF\r\nopensearch.password: "private-value"\r\n', destination.read_bytes())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result.stdout, '')
            source.write_text('server.host: private-value\nserver.host: private-value\n')
            result = subprocess.run(command + ['--source', str(source), '--destination', str(destination)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('private-value', result.stderr + result.stdout)


if __name__ == '__main__':
    unittest.main()
