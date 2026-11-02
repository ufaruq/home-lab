import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'upgrade_restore.py'
HOST='00000000-0000-4000-8000-000000000001'

class UpgradeRestoreTests(unittest.TestCase):
    def module(self):
        self.assertTrue(SOURCE.exists(),'Installer recovery helper must exist')
        spec=importlib.util.spec_from_file_location('upgrade_restore',SOURCE)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
    def fixture(self,root):
        (root/'etc').mkdir();(root/'etc/xensource-inventory').write_text("PRODUCT_VERSION='8.3.0'\nINSTALLATION_UUID='"+HOST+"'\n")
        body=b'#!/bin/sh\nexit 0\n'
        return {'host_uuid':HOST,'public_key':'ssh-ed25519 AAAATEST owner', 'files':{'/usr/local/sbin/direct-cable-network':{'content':base64.b64encode(body).decode(),'sha256':hashlib.sha256(body).hexdigest(),'mode':0o755}}}
    def test_wrong_host_version_path_or_hash_refused_before_file_writes(self):
        m=self.module()
        for kind in ['host','version','path','hash']:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                root=Path(d);bundle=self.fixture(root)
                if kind=='host':bundle['host_uuid']='00000000-0000-4000-8000-000000000002'
                if kind=='version':(root/'etc/xensource-inventory').write_text("PRODUCT_VERSION='8.2.1'\nINSTALLATION_UUID='"+HOST+"'\n")
                if kind=='path':bundle['files']['/../../outside']=bundle['files'].pop('/usr/local/sbin/direct-cable-network')
                if kind=='hash':bundle['files']['/usr/local/sbin/direct-cable-network']['sha256']='0'*64
                with self.assertRaises(ValueError):m.validate(str(root),bundle)
                self.assertFalse((root/'usr').exists())
    def test_live_root_and_escaping_symlink_are_refused(self):
        m=self.module()
        with self.assertRaises(ValueError):m.validate('/',{})
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'target';root.mkdir();bundle=self.fixture(root);(root/'usr').symlink_to(Path(d)/'outside')
            with self.assertRaises(ValueError):m.validate(str(root),bundle)
    def test_only_reviewed_asset_modes_are_allowed(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);bundle=self.fixture(root);bundle['files']['/usr/local/sbin/direct-cable-network']['mode']=0o777
            with self.assertRaises(ValueError):m.validate(str(root),bundle)

    def test_reboot_requires_successful_installer_and_matching_recovery_marker(self):
        m=self.module();marker={'host_uuid':HOST,'bundle_sha256':'a'*64}
        self.assertTrue(m.reboot_ready('0',marker,HOST,'a'*64))
        for code,report in [('1',marker),('0',None),('0',dict(marker,host_uuid='wrong')),('0',dict(marker,bundle_sha256='b'*64))]:
            with self.subTest(code=code,report=report):self.assertFalse(m.reboot_ready(code,report,HOST,'a'*64))

    def test_storage_alias_uses_permanent_device_and_is_idempotent(self):
        m=self.module();alias='/passthrough-drives/sdb/sdb';device='/dev/disk/by-id/wwn-0x5000000000000001'
        self.assertTrue(hasattr(m,'restore_links'),'Upgrade must preserve custom raw-disk mappings')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);links={alias:device}
            with patch.object(m,'verify_device'):
                self.assertEqual(m.restore_links(d,links,False),[alias]);self.assertFalse((root/'passthrough-drives').exists())
                self.assertEqual(m.restore_links(d,links,True),[alias])
                self.assertEqual((root/alias.lstrip('/')).readlink(),Path(device))
                self.assertEqual(m.restore_links(d,links,True),[])

    def test_storage_mapping_refuses_unstable_devices_or_escape(self):
        m=self.module();self.assertTrue(hasattr(m,'restore_links'),'Storage mappings must be validated')
        for alias,device in [('/passthrough-drives/sdb/sdb','/dev/sdb'),('/root/disk','/dev/disk/by-id/wwn-0x5000000000000001'),('/passthrough-drives/sdb/sdb','/dev/disk/by-id/wwn-0x5000000000000001-part1')]:
            with tempfile.TemporaryDirectory() as d,self.assertRaises(ValueError):m.restore_links(d,{alias:device},True)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'passthrough-drives').symlink_to('/tmp')
            with self.assertRaises(ValueError):m.restore_links(d,{'/passthrough-drives/sdb/sdb':'/dev/disk/by-id/wwn-0x5000000000000001'},True)

    def test_installer_dns_requires_numeric_resolvers_without_shell_input(self):
        m=self.module();self.assertTrue(hasattr(m,'resolver_config'),'Installer must survive a broken DHCP-advertised resolver')
        self.assertEqual(m.resolver_config(['1.1.1.1','9.9.9.9']),b'nameserver 1.1.1.1\nnameserver 9.9.9.9\n')
        for servers in [[],['example.com'],['1.1.1.1\nsearch attacker'],['999.1.1.1'],'1.1.1.1']:
            with self.subTest(servers=servers),self.assertRaises(ValueError):m.resolver_config(servers)

if __name__=='__main__':unittest.main()
