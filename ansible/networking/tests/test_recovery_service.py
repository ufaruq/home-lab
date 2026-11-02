import importlib.util
from pathlib import Path
import tempfile
import unittest
import base64
import hashlib

SOURCE=Path(__file__).parents[1]/'recovery_service.py'

class RecoveryServiceTests(unittest.TestCase):
    def module(self):
        self.assertTrue(SOURCE.exists(),'Recovery service must validate declared assets before installing them')
        spec=importlib.util.spec_from_file_location('recovery_service',SOURCE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def asset(self,body=b'reviewed'):
        return {'content':base64.b64encode(body).decode(),'sha256':hashlib.sha256(body).hexdigest(),'mode':0o644}
    def test_unknown_content_is_not_overwritten_and_all_paths_are_preflighted(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/'etc/systemd/system/direct-cable-network.timer';path.parent.mkdir(parents=True);path.write_bytes(b'unreviewed')
            assets={'/etc/systemd/system/direct-cable-network.timer':self.asset()}
            with self.assertRaises(ValueError):m.file_plan(folder,assets,{})
            self.assertEqual(path.read_bytes(),b'unreviewed')
            self.assertTrue(m.file_plan(folder,assets,{next(iter(assets)):[hashlib.sha256(b'unreviewed').hexdigest()]}))
    def test_arbitrary_paths_symlinks_and_wrong_modes_are_rejected(self):
        m=self.module()
        for kind in ['path','symlink','mode','digest']:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);name='/etc/systemd/system/direct-cable-network.timer';asset=self.asset()
                if kind=='path':name='/etc/sudoers'
                if kind=='mode':asset['mode']=0o777
                if kind=='digest':asset['sha256']='0'*64
                if kind=='symlink':(root/'etc').symlink_to('/tmp')
                with self.assertRaises(ValueError):m.file_plan(folder,{name:asset},{})

if __name__=='__main__':unittest.main()
