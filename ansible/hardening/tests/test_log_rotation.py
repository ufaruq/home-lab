import importlib.util
import pathlib
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('log_rotation', pathlib.Path(__file__).parents[1]/'log_rotation.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class RotationTests(unittest.TestCase):
    def fixture(self, root):
        for name, body in [('/etc/cron.daily/logrotate', m.ORIGINAL_DAILY), ('/etc/logrotate.conf', m.ORIGINAL_POLICY)]:
            path=pathlib.Path(root+name);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body);path.chmod(0o755 if 'cron.daily' in name else 0o644)
        for name in m.REQUIRED_BINARIES:
            path=pathlib.Path(root+name);path.parent.mkdir(parents=True,exist_ok=True);path.write_text('#!/bin/sh\nexit 0\n');path.chmod(0o755)
    def runner(self, args, stdin=None):
        if 'is-active' in args:return 0,'active\n',''
        return 0,'',''
    def test_check_does_not_mutate_and_two_apply_runs_are_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixture(root)
            before=sorted(str(p.relative_to(root)) for p in pathlib.Path(root).rglob('*'))
            check=m.reconcile(root,False,self.runner)
            self.assertTrue(check['changed'])
            self.assertEqual(before,sorted(str(p.relative_to(root)) for p in pathlib.Path(root).rglob('*')))
            applied=m.reconcile(root,True,self.runner)
            self.assertTrue(applied['changed'])
            self.assertFalse(m.reconcile(root,True,self.runner)['changed'])
            self.assertEqual(pathlib.Path(root+'/etc/logrotate.conf').read_text(),m.ORIGINAL_POLICY)
            self.assertTrue(pathlib.Path(applied['backup_directory']+'/manifest.json').exists())
            for name in ['/etc/cron.daily/logrotate','/etc/cron.d/home-lab-logrotate']:
                self.assertIn('/usr/local/sbin/home-lab-logrotate',pathlib.Path(root+name).read_text())
    def test_unexpected_daily_or_policy_refuses_before_creating_files(self):
        for target in ['/etc/cron.daily/logrotate','/etc/logrotate.conf']:
            with tempfile.TemporaryDirectory() as root:
                self.fixture(root);pathlib.Path(root+target).write_text('unexpected\n')
                with self.assertRaises(ValueError):m.reconcile(root,True,self.runner)
                self.assertFalse(pathlib.Path(root+'/usr/local/sbin/home-lab-logrotate').exists())
                self.assertFalse(pathlib.Path(root+'/root/home-lab-hardening-backups').exists())
    def test_failed_dry_run_refuses_every_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixture(root)
            def failed(args,stdin=None):return (1,'','config error') if '-d' in args else self.runner(args,stdin)
            with self.assertRaises(ValueError):m.reconcile(root,True,failed)
            self.assertFalse(pathlib.Path(root+'/etc/cron.d/home-lab-logrotate').exists())
    def test_only_exact_legacy_future_archive_artifact_is_reported_as_warning(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixture(root)
            previous=pathlib.Path(root+'/var/log/boot.log.7.gz');previous.parent.mkdir(parents=True);previous.write_bytes(b'fixture')
            def artifact(args,stdin=None):
                if '--version' in args:return 0,'logrotate 3.8.6',''
                if '-d' in args and '/dev/null' not in args:
                    return 1,'','renaming /var/log/boot.log.7.gz to /var/log/boot.log.8.gz\nremoving old log /var/log/boot.log.8.gz\nerror: error opening /var/log/boot.log.8.gz: No such file or directory\n'
                return self.runner(args,stdin)
            result=m.reconcile(root,False,artifact)
            self.assertEqual(result['real_state_debug_exit'],1)
            self.assertEqual(len(result['warnings']),1)
            def other_error(args,stdin=None):
                if '-d' in args and '/dev/null' not in args:return 1,'','error: permission denied on current log\n'
                return artifact(args,stdin)
            with self.assertRaises(ValueError):m.reconcile(root,True,other_error)
            self.assertFalse(pathlib.Path(root+'/etc/cron.d/home-lab-logrotate').exists())

    def test_rollback_restores_original_and_removes_only_new_owned_files(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixture(root);result=m.reconcile(root,True,self.runner)
            m.rollback(root,result['backup_directory'],True)
            self.assertEqual(pathlib.Path(root+'/etc/cron.daily/logrotate').read_text(),m.ORIGINAL_DAILY)
            self.assertFalse(pathlib.Path(root+'/etc/cron.d/home-lab-logrotate').exists())
    def test_health_thresholds_and_service_failures_are_explicit(self):
        namespace={'__name__':'health_fixture'}
        exec(compile(m.HEALTH_SCRIPT,'<health>','exec'),namespace)
        classify=namespace['classify']
        active={'rsyslog':'active','crond':'active'}
        self.assertEqual(classify({'bytes_percent':79.9,'inodes_percent':10},active)[0],0)
        self.assertEqual(classify({'bytes_percent':80,'inodes_percent':10},active)[0],1)
        self.assertEqual(classify({'bytes_percent':20,'inodes_percent':90},active)[0],2)
        self.assertEqual(classify({'bytes_percent':20,'inodes_percent':10},{'rsyslog':'failed','crond':'active'})[0],2)

    def test_wrapper_is_bounded_normal_rotation_and_retains_original_policy(self):
        self.assertIn('flock -w 60',m.WRAPPER)
        self.assertIn('timeout -k 10 240',m.WRAPPER)
        self.assertNotIn(' -f ',m.WRAPPER)
        self.assertEqual(m.DAILY,m.ORIGINAL_DAILY.replace(m.ORIGINAL_ROTATE_COMMAND,m.WRAPPER_PATH))

if __name__=='__main__':unittest.main()
