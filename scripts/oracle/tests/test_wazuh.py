import copy
import contextlib
import configparser
import io
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('oracle_wazuh', ROOT / 'scripts/oracle/wazuh.py')
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


def snapshot():
    return {'subscription': {'subscription-tier': 'FREE', 'payment-model': 'FREE_TRIAL', 'lifecycle-state': 'ACTIVE', 'end-date': '2026-02-25T23:59:59+00:00'},
            'regions': [{'region-name': 'us-sanjose-1', 'is-home-region': True, 'status': 'READY'}],
            'ads': ['TEST:US-SANJOSE-1-AD-1'], 'instances': [{'id': 'old-micro', 'shape': 'VM.Standard.E2.1.Micro', 'lifecycle-state': 'RUNNING'}],
            'volumes': [{'id': 'old-boot', 'size-in-gbs': 60, 'lifecycle-state': 'AVAILABLE'}], 'backups': [],
            'limits': {'cores': 2, 'memory': 12, 'storage': 200},
            'a1_usage': {'cores': 0, 'memory': 0}, 'capacity': 'AVAILABLE'}


class OracleWazuhTests(unittest.TestCase):
    def test_cli_audit_handles_actual_response_shapes_and_stops_on_capacity(self):
        configuration = configparser.ConfigParser()
        configuration.read_dict({'fixture': {'tenancy': 'test-tenancy'}})
        ad = 'TEST:US-SANJOSE-1-AD-1'
        issued = []
        def response(command, **kwargs):
            issued.append(command)
            self.assertEqual(command[0], 'oci')
            args = command[7:]
            if args[:3] == ['organizations', 'subscription', 'list']: data = {'items': [{'id': 'sub', 'lifecycle-state': 'ACTIVE'}]}
            elif args[:3] == ['organizations', 'subscription', 'get']: data = snapshot()['subscription']
            elif args[:3] == ['iam', 'region-subscription', 'list']: data = snapshot()['regions']
            elif args[:3] == ['iam', 'availability-domain', 'list']: data = [{'name': ad}]
            elif args[:3] == ['iam', 'compartment', 'list']: data = [{'id': 'lab', 'name': 'home-lab', 'compartment-id': 'test-tenancy', 'lifecycle-state': 'ACTIVE'}]
            elif args[:3] == ['limits', 'value', 'list']:
                data = [{'name': n, 'availability-domain': ad, 'value': value} for n, value in [('standard-a1-core-count', 2), ('standard-a1-memory-count', 12), ('total-free-storage-gb', 200)]]
            elif args[:3] == ['limits', 'resource-availability', 'get']: data = {'used': 0}
            elif args[:3] == ['compute', 'image', 'list']: data = [{'id': 'image', 'operating-system': 'Canonical Ubuntu', 'operating-system-version': '22.04', 'display-name': 'Canonical-Ubuntu-22.04-aarch64-fixture', 'lifecycle-state': 'AVAILABLE'}]
            elif args[:3] == ['compute', 'compute-capacity-report', 'create']: data = {'shape-availabilities': [{'availability-status': 'OUT_OF_HOST_CAPACITY'}]}
            elif args[:3] == ['compute', 'instance', 'list']: data = snapshot()['instances'] if args[args.index('--compartment-id') + 1] == 'test-tenancy' else []
            elif args[:3] == ['bv', 'boot-volume', 'list']: data = snapshot()['volumes'] if args[args.index('--compartment-id') + 1] == 'test-tenancy' else []
            elif args[0] == 'bv': data = []
            else: raise AssertionError(args)
            # OCI returns empty stdout, not a data wrapper, for some empty lists.
            return SimpleNamespace(returncode=0, stdout=json.dumps({'data': data}) if data else '', stderr='')
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(configuration, 'read', return_value=[]), mock.patch.object(controller.configparser, 'ConfigParser', return_value=configuration), mock.patch.object(controller.helpers, 'run_directory', return_value=Path(directory)), mock.patch.object(controller, 'managed_identity', return_value={}), mock.patch.object(controller.subprocess, 'run', side_effect=response), contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(controller.main(['audit', '--profile', 'fixture']), 1)
            self.assertIn('OUT_OF_HOST_CAPACITY', errors.getvalue())
            result = json.loads((Path(directory) / 'oracle-wazuh-audit.json').read_text())
            self.assertEqual(result['volumes'][0]['size-in-gbs'], 60)
        self.assertTrue(issued)

    def test_combined_storage_includes_existing_micro_disk(self):
        self.assertEqual(controller.assess(snapshot())['combined_storage_gb'], 160)

    def test_paid_trial_and_unverified_subscription_fail(self):
        for field, value in [('subscription-tier', 'PAID'), ('payment-model', 'PAY_AS_YOU_GO'), ('end-date', '2099-01-01T00:00:00Z')]:
            data = snapshot(); data['subscription'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): controller.assess(data)

    def test_capacity_failure_never_authorizes_provisioning(self):
        data = snapshot(); data['capacity'] = 'OUT_OF_HOST_CAPACITY'
        with self.assertRaisesRegex(ValueError, 'OUT_OF_HOST_CAPACITY'): controller.assess(data)

    def test_terminating_disks_still_count_toward_overlap(self):
        data = snapshot()
        data['volumes'].append({'id': 'deleting-boot', 'size-in-gbs': 100, 'lifecycle-state': 'TERMINATING'})
        with self.assertRaisesRegex(ValueError, 'Combined volumes'): controller.assess(data)

    def test_review_hash_includes_executed_application_sources(self):
        target = ROOT / 'ansible/roles/monitoring_wazuh_manager/tasks/fresh.yml'
        original = Path.read_bytes
        inventory = ROOT / 'ansible/inventory/hosts.yml'
        def baseline(path):
            if path == inventory:
                return (ROOT / 'tests/fixtures/monitoring/hosts.json').read_bytes()
            return original(path)
        def altered(path):
            value = baseline(path)
            return value + b'\n# changed after plan\n' if path == target else value
        with mock.patch.object(Path, 'read_bytes', baseline):
            before = controller.configuration_hash()
        with mock.patch.object(Path, 'read_bytes', altered):
            self.assertNotEqual(controller.configuration_hash(), before)

    def test_extra_regions_unknown_shapes_or_unaccounted_usage_fail(self):
        for change in ('regions', 'shape', 'storage', 'cores', 'limit'):
            data = snapshot()
            if change == 'regions': data['regions'].append({'region-name': 'us-phoenix-1'})
            if change == 'shape': data['instances'][0]['shape'] = 'VM.Standard.E5.Flex'
            if change == 'storage': data['volumes'][0]['size-in-gbs'] = 150
            if change == 'cores': data['a1_usage']['cores'] = 1
            if change == 'limit': data['limits']['cores'] = 0
            with self.subTest(change=change), self.assertRaises(ValueError): controller.assess(data)

    def test_plan_guard_rejects_paid_shapes_replacements_and_public_apps(self):
        instance = {'mode': 'managed', 'address': 'oci_core_instance.wazuh', 'type': 'oci_core_instance', 'provider_name': 'registry.terraform.io/oracle/oci', 'change': {'actions': ['create'], 'after': {'shape': 'VM.Standard.A1.Flex', 'shape_config': [{'ocpus': 2, 'memory_in_gbs': 12}], 'source_details': [{'boot_volume_size_in_gbs': '100', 'boot_volume_vpus_per_gb': '10', 'source_id': 'approved-image'}]}}}
        controller.guard_plan({'resource_changes': [instance]}, 'approved-image')
        for change in ('shape', 'replace', 'extra', 'disk', 'image', 'ingress'):
            plan = {'resource_changes': [copy.deepcopy(instance)]}; r = plan['resource_changes'][0]
            if change == 'shape': r['change']['after']['shape'] = 'VM.Standard.E5.Flex'
            if change == 'replace': r['change']['actions'] = ['delete', 'create']
            if change == 'extra': r['type'] = 'oci_core_nat_gateway'
            if change == 'disk': r['change']['after']['source_details'][0]['boot_volume_size_in_gbs'] = '201'
            if change == 'image': r['change']['after']['source_details'][0]['source_id'] = 'marketplace'
            if change == 'ingress': plan['resource_changes'].append({'mode': 'managed', 'address': 'oci_core_network_security_group_security_rule.bootstrap_ssh[0]', 'type': 'oci_core_network_security_group_security_rule', 'provider_name': 'registry.terraform.io/oracle/oci', 'change': {'actions': ['create'], 'after': {'direction': 'INGRESS', 'protocol': '6', 'source': '0.0.0.0/0', 'tcp_options': [{'destination_port_range': [{'min': 443, 'max': 443}]}]}}})
            with self.subTest(change=change), self.assertRaises(ValueError): controller.guard_plan(plan, 'approved-image')

    def test_quota_relaxation_and_unknown_orchestration_are_rejected(self):
        for resource in (
            {'address': 'oci_limits_quota.free_bounds', 'type': 'oci_limits_quota', 'provider_name': 'registry.terraform.io/oracle/oci', 'change': {'actions': ['update'], 'after': {'statements': ["set compute-core quota standard-a1-core-count to 100 in tenancy"]}}},
            {'address': 'terraform_data.shell', 'type': 'terraform_data', 'provider_name': 'terraform.io/builtin/terraform', 'change': {'actions': ['create'], 'after': {}}},
        ):
            with self.subTest(resource=resource['address']), self.assertRaises(ValueError):
                controller.guard_plan({'resource_changes': [dict(resource, mode='managed')]}, 'approved-image')


if __name__ == '__main__': unittest.main()
