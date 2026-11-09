"""Offline storage safety checks; fixtures never touch a Wazuh installation."""
import datetime as dt
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('wazuh_storage', ROOT / 'monitoring/wazuh/storage.py')


class StorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.storage)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.manager = Path(self.temporary.name).resolve() / 'ossec'
        self.alerts = self.manager / 'logs/alerts'
        self.alerts.mkdir(parents=True)
        self.today = dt.date(2026, 11, 2)

    def artifact(self, relative, recent=False):
        path = self.alerts / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('fixture')
        timestamp = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc).timestamp() if recent else 1
        os.utime(path, (timestamp, timestamp))
        return path

    def plan(self):
        return self.storage.plan_cleanup(self.manager, today=self.today)

    def test_plan_keeps_active_plain_recent_and_boundary_date_files(self):
        old = self.artifact('2026/Oct/ossec-alerts-25.json.gz')
        self.artifact('2026/Oct/ossec-alerts-25-001.log.gz')
        self.artifact('2026/Oct/ossec-alerts-25.json.sum')
        protected = ['alerts.json', 'alerts.log', '2026/Oct/ossec-alerts-25.json',
                     '2026/Oct/ossec-alerts-26.log.gz', '2026/Nov/ossec-alerts-01.json.gz',
                     '2026/Oct/ossec-alerts-25.json.gz.key', '2026/Oct/ossec-alerts-25-000.log.gz',
                     '2026/Oct/ossec-alerts-25-001.json.sum', '2026/Oct/ossec-alerts-25-0001.json.gz',
                     '2026/Oct/client.keys',
                     '2026/Feb/ossec-alerts-31.json.gz', '2026/11/ossec-alerts-01.json.gz']
        for name in protected:
            self.artifact(name)
        self.artifact('2026/Oct/ossec-alerts-24.json.gz', recent=True)
        plan = self.plan()
        self.assertEqual([row['path'] for row in plan], [
            '2026/Oct/ossec-alerts-25-001.log.gz', '2026/Oct/ossec-alerts-25.json.gz',
            '2026/Oct/ossec-alerts-25.json.sum'])
        self.assertTrue(old.exists(), 'planning must never delete')

    def test_apply_requires_boolean_gate_and_revalidates_identity(self):
        old = self.artifact('2026/Oct/ossec-alerts-25.json.gz')
        plan = self.plan()
        for approval in (False, 'true', 1, None):
            with self.assertRaises(ValueError):
                self.storage.apply_cleanup(self.manager, plan, approved=approval, today=self.today)
        old.unlink()
        old.write_text('replacement')
        self.assertEqual(self.storage.apply_cleanup(self.manager, plan, approved=True, today=self.today), [])
        os.utime(old, (1, 1))
        fresh = self.plan()
        self.assertEqual(self.storage.apply_cleanup(self.manager, fresh, approved=True, today=self.today),
                         ['2026/Oct/ossec-alerts-25.json.gz'])
        self.assertFalse(old.exists())
        self.assertEqual(self.plan(), [])

    def test_new_hardlink_after_plan_prevents_deletion(self):
        old = self.artifact('2026/Oct/ossec-alerts-25.json.gz')
        plan = self.plan()
        os.link(old, self.manager / 'keep')
        self.assertEqual(self.storage.apply_cleanup(self.manager, plan, approved=True, today=self.today), [])
        self.assertTrue(old.exists())

    def test_symlinks_and_hardlinks_are_never_candidates(self):
        external = self.manager.parent / 'private'
        external.mkdir()
        target = external / 'ossec-alerts-25.json.gz'
        target.write_text('keep')
        (self.alerts / '2025').symlink_to(external, target_is_directory=True)
        (self.alerts / '2026').mkdir()
        (self.alerts / '2026/Oct').symlink_to(external, target_is_directory=True)
        november = self.alerts / '2026/Nov'
        november.mkdir()
        (november / 'ossec-alerts-01.json.gz').symlink_to(target)
        hardlink = self.artifact('2024/Oct/ossec-alerts-25.log.gz')
        os.link(hardlink, external / 'hardlink')
        self.assertEqual(self.plan(), [])
        self.assertEqual(target.read_text(), 'keep')

    def test_root_symlink_and_traversal_plan_are_rejected_without_deletion(self):
        old = self.artifact('2026/Oct/ossec-alerts-25.json.gz')
        plan = self.plan()
        invalid = dict(plan[0], path='../etc/client.keys')
        with self.assertRaises(ValueError):
            self.storage.apply_cleanup(self.manager, [invalid], approved=True, today=self.today)
        self.assertTrue(old.exists())
        self.alerts.rename(self.manager / 'logs/original')
        self.alerts.symlink_to(self.manager / 'logs/original', target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.plan()

    def test_apply_does_not_follow_replaced_directory_or_file_symlink(self):
        old = self.artifact('2026/Oct/ossec-alerts-25.json.gz')
        plan = self.plan()
        old.unlink()
        target = self.manager / 'private'
        target.write_text('keep')
        old.symlink_to(target)
        self.assertEqual(self.storage.apply_cleanup(self.manager, plan, approved=True, today=self.today), [])
        self.assertEqual(target.read_text(), 'keep')
        october = old.parent
        october.rename(october.with_name('original'))
        october.symlink_to(october.with_name('original'), target_is_directory=True)
        self.assertEqual(self.storage.apply_cleanup(self.manager, plan, approved=True, today=self.today), [])

    def test_internal_settings_preserve_unrelated_content_and_collapse_duplicates(self):
        original = '# existing\nanalysisd.debug=0\nmonitord.keep_log_days=31\nmonitord.keep_log_days=90\nremoted.pass_empty_keyfile=1\n'
        result = self.storage.internal_options(original)
        self.assertIn('# existing\nanalysisd.debug=0\n', result)
        self.assertIn('remoted.pass_empty_keyfile=1\n', result)
        self.assertEqual(result.count('monitord.keep_log_days='), 1)
        self.assertIn('monitord.keep_log_days=7\n', result)
        self.assertIn('monitord.size_rotate=64\n', result)
        self.assertIn('monitord.daily_rotations=4\n', result)
        self.assertEqual(self.storage.internal_options(result), result)

    def test_cleanup_cli_rejects_path_override_and_apply_without_review(self):
        for args in (['cleanup', '--root', str(self.manager)], ['cleanup', '--apply']):
            result = subprocess.run([os.sys.executable, str(ROOT / 'monitoring/wazuh/storage.py'), *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'fixture', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
