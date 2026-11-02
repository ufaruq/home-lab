import importlib.util
from pathlib import Path
import tempfile
import unittest
import os
import stat
import tarfile
import io

SOURCE=Path(__file__).resolve().parents[3]/'ansible/files/xo-source-update.py'

class SourceUpdateTests(unittest.TestCase):
    def module(self):
        self.assertTrue(SOURCE.exists(), 'The guarded source updater must exist')
        spec=importlib.util.spec_from_file_location('xo_source_update',SOURCE)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_only_lts_patch_line_and_linux_x64_is_selected(self):
        m=self.module()
        rows=[{'version':'v26.1.0','lts':False,'files':['linux-x64']},
              {'version':'v24.10.0','lts':'Krypton','files':['linux-x64']},
              {'version':'v24.9.0','lts':'Krypton','files':['linux-x64']},
              {'version':'v24.20.0','lts':'Krypton','files':['linux-arm64']}]
        self.assertEqual(m.select_node(rows,24),'v24.10.0')

    def test_wrong_branch_or_malformed_git_head_is_refused(self):
        m=self.module();sha='a'*40
        self.assertEqual(m.parse_head(sha+'\trefs/heads/master\n'),sha)
        for raw in ['',sha+'\trefs/heads/develop\n','--upload-pack=bad refs/heads/master',sha+'\trefs/heads/master\n'+sha+'\trefs/heads/master\n']:
            with self.subTest(raw=raw),self.assertRaises(ValueError):m.parse_head(raw)

    def test_only_exact_node_archive_checksum_is_accepted(self):
        m=self.module();digest='b'*64
        self.assertEqual(m.archive_checksum(digest+'  node-v24.10.0-linux-x64.tar.xz\n','node-v24.10.0-linux-x64.tar.xz'),digest)
        for data in [digest+' node-v24.10.0-linux-arm64.tar.xz', 'bad node-v24.10.0-linux-x64.tar.xz']:
            with self.assertRaises(ValueError):m.archive_checksum(data,'node-v24.10.0-linux-x64.tar.xz')

    def test_no_activation_without_server_and_both_web_builds(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'packages/xo-server/dist').mkdir(parents=True)
            (root/'packages/xo-server/dist/cli.mjs').write_text('')
            with self.assertRaises(ValueError):m.verify_build(root)
            for directory in ['packages/xo-web/dist','@xen-orchestra/web/dist']:
                (root/directory).mkdir(parents=True);(root/directory/'index.html').write_text('ok')
            m.verify_build(root)

    def test_failed_activation_stops_candidate_before_restoring_state(self):
        m=self.module();events=[]
        def call(name):
            def execute():events.append(name)
            return execute
        def failed_health():events.append('health');raise RuntimeError('unhealthy')
        with self.assertRaisesRegex(RuntimeError,'unhealthy'):
            m.activate_with_rollback(call('stop_old'),call('snapshot'),call('switch_new'),call('start_new'),failed_health,call('stop_candidate'),call('restore_state'),call('switch_old'),call('start_old'))
        self.assertEqual(events,['stop_old','snapshot','switch_new','start_new','health','stop_candidate','restore_state','switch_old','start_old'])

    def test_failed_backup_does_not_switch_or_restore_database(self):
        m=self.module();events=[]
        def event(name):return lambda:events.append(name)
        def failed_backup():events.append('backup');raise RuntimeError('backup failed')
        with self.assertRaisesRegex(RuntimeError,'backup failed'):
            m.activate_with_rollback(event('stop'),failed_backup,event('switch'),event('start_new'),event('health'),event('stop_new'),event('restore'),event('old'),event('start_old'))
        self.assertEqual(events,['stop','backup','start_old'])

    def test_atomic_write_does_not_follow_builder_created_temporary_symlink(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);outside=root/'outside';outside.write_text('preserve')
            target=root/'ready.json';(root/'ready.json.new').symlink_to(outside)
            m.atomic(target,'safe')
            self.assertEqual(outside.read_text(),'preserve')
            self.assertFalse(target.is_symlink())
            self.assertEqual(target.read_text(),'safe')

    def test_release_freeze_removes_builder_write_permissions_and_rejects_escape(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'release';root.mkdir();f=root/'app';f.write_text('app');f.chmod(0o777)
            m.freeze_release(root,os.getuid(),os.getgid())
            self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o755)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o755)
            (root/'escape').symlink_to(Path(d)/'outside')
            with self.assertRaises(ValueError):m.freeze_release(root,os.getuid(),os.getgid())

    def test_retention_keeps_current_and_previous_releases_and_bounded_backups(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);base=root/'xo';state=root/'state';(base/'releases').mkdir(parents=True);(state/'backups').mkdir(parents=True)
            for n in range(4):
                p=base/'releases'/((str(n)*40)+'-v24.10.0');p.mkdir();(p/'ready.json').write_text('{}')
            current=base/'releases'/('3'*40+'-v24.10.0');previous=base/'releases'/('2'*40+'-v24.10.0')
            for n in range(10):(state/'backups'/f'202610{n+1:02}T030000Z').mkdir()
            m.prune(base,state,current,previous)
            self.assertEqual(set((base/'releases').iterdir()),{current,previous})
            self.assertEqual(len(list((state/'backups').iterdir())),7)

    def test_archive_extraction_rejects_parent_escape_and_supports_internal_links(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'a.tar'
            with tarfile.open(archive,'w') as tar:
                item=tarfile.TarInfo('package/bin/app');item.size=2;item.mode=0o755;tar.addfile(item,io.BytesIO(b'ok'))
                link=tarfile.TarInfo('package/bin/alias');link.type=tarfile.SYMTYPE;link.linkname='app';tar.addfile(link)
            m.extract(archive,root/'out');self.assertEqual((root/'out/package/bin/alias').read_bytes(),b'ok')
            with tarfile.open(archive,'w') as tar:
                link=tarfile.TarInfo('package/escape');link.type=tarfile.SYMTYPE;link.linkname='../../outside';tar.addfile(link)
            with self.assertRaises(ValueError):m.extract(archive,root/'bad')

    def test_unsupported_task_api_never_means_idle_for_automatic_updates(self):
        m=self.module();baseline={'active_tasks':0,'active_jobs':0,'configured_jobs':0}
        with self.assertRaises(ValueError):m.require_idle(baseline,None,False)
        m.require_idle(baseline,None,True)
        for busy in [{'active_tasks':1,'active_jobs':0,'configured_jobs':0},{'active_tasks':0,'active_jobs':1,'configured_jobs':1}]:
            with self.assertRaises(ValueError):m.require_idle(busy,0,False)
        with self.assertRaises(ValueError):m.require_idle(baseline,1,False)
        with self.assertRaises(ValueError):m.require_idle(dict(baseline,configured_jobs=1),None,True)

    def test_compiler_log_is_bounded_and_keeps_recent_output(self):
        m=self.module()
        with tempfile.TemporaryFile() as output:
            for _ in range(20):m.bounded_log(output,b'x'*5,limit=16)
            m.bounded_log(output,b'latest',limit=16);output.seek(0);data=output.read()
            self.assertLessEqual(len(data),16);self.assertTrue(data.endswith(b'latest'))

    def test_promoted_build_breaks_hardlinks_without_changing_external_file(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d);root=parent/'release';root.mkdir();outside=parent/'cache';outside.write_text('preserve')
            inside=root/'artifact';os.link(outside,inside)
            m.freeze_release(root,os.getuid(),os.getgid())
            self.assertNotEqual(inside.stat().st_ino,outside.stat().st_ino)
            inside.write_text('updated');self.assertEqual(outside.read_text(),'preserve')

    def test_state_backup_preserves_data_but_excludes_ephemeral_pipes(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';source.mkdir();(source/'db').write_text('database');os.mkfifo(source/'runtime.pipe')
            m.copy_state_tree(source,root/'backup')
            self.assertEqual((root/'backup/db').read_text(),'database')
            self.assertFalse((root/'backup/runtime.pipe').exists())

if __name__=='__main__':unittest.main()
