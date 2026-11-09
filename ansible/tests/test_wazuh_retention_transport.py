"""Certificate mode cannot send an admin certificate to a remote indexer."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

DIRECTORY = Path(__file__).resolve().parents[2] / 'monitoring/wazuh'
sys.path.insert(0, str(DIRECTORY))
spec = importlib.util.spec_from_file_location('retention_transport', DIRECTORY/'retention.py')
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)

class CertificateTransportTests(unittest.TestCase):
    def test_legacy_policy_ownership_is_preserved(self):
        body = json.loads((DIRECTORY/'retention.json').read_text())
        methods = []
        def request(method, path, *args):
            methods.append(method)
            if '/policies/' in path:
                return {'policy': body['policy']}
            return {'wazuh-alerts-4.x-2026.01.01': {
                'index.opendistro.index_state_management.policy_id': 'existing-other-policy'}}
        with self.assertRaises(ValueError): retention.reconcile(request, body)
        self.assertEqual(methods, ['GET', 'GET'])

    def test_remote_and_nonroot_certificate_requests_stop_before_network(self):
        for uid, url in [(501, 'https://127.0.0.1:9200'), (0, 'https://example.invalid:9200')]:
            data = {'access_verified': True, 'deployment_approved': True,
                'retention_approved': True, 'local_admin_certificate': True, 'url': url}
            with patch.object(sys, 'stdin', io.StringIO(json.dumps(data))), patch.object(retention.os, 'geteuid', return_value=uid), patch.object(retention.ssl, 'create_default_context') as context:
                with self.assertRaises(ValueError): retention.main()
                context.assert_not_called()

    def test_certificate_mode_uses_fixed_existing_paths_and_no_basic_auth(self):
        data = {'access_verified': True, 'deployment_approved': True,
            'retention_approved': True, 'local_admin_certificate': True, 'url': 'https://127.0.0.1:9200'}
        with patch.object(sys, 'stdin', io.StringIO(json.dumps(data))), patch.object(retention.os, 'geteuid', return_value=0), patch.object(retention.ssl, 'create_default_context') as context, patch.object(retention.urllib.request, 'build_opener') as opener, patch.object(retention, 'reconcile') as reconcile, patch.object(sys, 'stdout', io.StringIO()):
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = '{}'
            def inspect(request, body, bootstrap=None):
                request('GET', '/_cluster/health')
                req = opener.return_value.open.call_args.args[0]
                self.assertNotIn('Authorization', req.headers)
                return False
            reconcile.side_effect = inspect
            retention.main()
            context.assert_called_once_with(cafile='/etc/wazuh-indexer/certs/root-ca.pem')
            context.return_value.load_cert_chain.assert_called_once_with('/etc/wazuh-indexer/certs/admin.pem', '/etc/wazuh-indexer/certs/admin-key.pem')

if __name__ == '__main__': unittest.main()
