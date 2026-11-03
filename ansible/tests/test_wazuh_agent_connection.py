import importlib.util
from pathlib import Path
import unittest
import stat
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[2]
def module():
 p=ROOT/'monitoring/wazuh/agent_connection.py';assert p.exists(),'Scoped agent connection migration is not implemented'
 s=importlib.util.spec_from_file_location('agent_connection',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class AgentConnectionTests(unittest.TestCase):
 def test_native_wazuh_owner_is_allowed_but_foreign_or_public_files_are_rejected(self):
  m=module()
  for uid in [0,110]:m.validate_private_file(SimpleNamespace(st_mode=stat.S_IFREG|0o640,st_uid=uid),{0,110})
  for uid,mode in [(501,stat.S_IFREG|0o640),(110,stat.S_IFREG|0o644),(0,stat.S_IFLNK|0o600)]:
   with self.assertRaises(ValueError):m.validate_private_file(SimpleNamespace(st_mode=mode,st_uid=uid),{0,110})
 def configuration(self):return '<ossec_config><!--keep--><client><server><address>192.0.2.10</address><port>1514</port><protocol>tcp</protocol></server><enrollment><password>private</password></enrollment></client><localfile><location>/var/log/syslog</location></localfile></ossec_config>'
 def test_changes_only_reviewed_server_address(self):
  old=self.configuration();new=module().update(old,'192.0.2.10','198.51.100.10',1514)
  self.assertEqual(new,old.replace('192.0.2.10','198.51.100.10'));self.assertEqual(module().update(new,'192.0.2.10','198.51.100.10',1514),new)
 def test_refuses_unreviewed_current_address_multiple_servers_and_transport(self):
  m=module();old=self.configuration()
  for text in [old.replace('192.0.2.10','203.0.113.30'),old.replace('</client>','<server><address>192.0.2.10</address></server></client>'),old.replace('tcp','udp'),old.replace('1514','1515')]:
   with self.subTest(text=text),self.assertRaises(ValueError):m.update(text,'192.0.2.10','198.51.100.10',1514)
 def test_rejects_markup_addresses_and_ambiguous_commented_blocks(self):
  m=module()
  for target in ['evil</address>','x\n<address>y']:
   with self.assertRaises(ValueError):m.update(self.configuration(),'192.0.2.10',target,1514)
  with self.assertRaises(ValueError):m.update(self.configuration().replace('<!--keep-->','<!--<client></client>-->'),'192.0.2.10','198.51.100.10',1514)
if __name__=='__main__':unittest.main()
