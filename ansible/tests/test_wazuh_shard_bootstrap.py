"""Bootstrap deletion is restricted to one independently reviewed expired alert index."""
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
import urllib.error
from unittest.mock import patch

DIR = Path(__file__).resolve().parents[2]/'monitoring/wazuh'
sys.path.insert(0, str(DIR))
spec = importlib.util.spec_from_file_location('retention_bootstrap', DIR/'retention.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.row = {'index':'wazuh-alerts-4.x-2024.06.06', 'uuid':'synthetic00000000000001', 'creation_date':'1717657200000'}
        self.now = dt.datetime(2026,11,3,tzinfo=dt.timezone.utc)
        self.calls=[]; self.assigned=None
    def request(self, method, path, body=None, missing_ok=False):
        self.calls.append((method,path))
        if path.endswith('/_settings'):
            return {self.row['index']:{'settings':{'index':{'uuid':self.row['uuid'],'creation_date':self.row['creation_date']}}}}
        if '/_ism/explain/' in path:
            return {self.row['index']:{'policy_id':self.assigned}}
        if method=='DELETE':return {'acknowledged':True}
        raise AssertionError('Unexpected API request')
    def test_only_the_exact_expired_index_can_be_deleted(self):
        self.assertTrue(m.bootstrap_capacity(self.request, dict(self.row), now=self.now))
        self.assertEqual([p for method,p in self.calls if method=='DELETE'], ['/'+self.row['index']])
    def test_changed_identity_new_creation_or_other_policy_prevents_delete(self):
        for change in ({'uuid':'different0000000000001'}, {'creation_date':str(int(self.now.timestamp()*1000))}, {'index':'wazuh-alerts-4.x-2026.11.03'}, {'index':'other-index-*'}):
            candidate=dict(self.row,**change); self.calls=[]
            with self.assertRaises(ValueError):m.bootstrap_capacity(self.request,candidate,now=self.now)
            self.assertFalse(any(method=='DELETE' for method,_ in self.calls))
        self.assigned='existing-policy';self.calls=[]
        with self.assertRaises(ValueError):m.bootstrap_capacity(self.request,self.row,now=self.now)
        self.assertFalse(any(method=='DELETE' for method,_ in self.calls))

    def test_bootstrap_is_used_only_for_the_exact_shard_limit_rejection(self):
        body=json.loads((DIR/'retention.json').read_text())
        for code,reason,expected in [(400,'Validation Failed: this action would add [2] total shards, but this cluster currently has [999]/[1000] maximum shards open',True),(403,'access denied',False),(400,'unrelated validation error',False)]:
            puts=[]
            def request(method,path,*args):
                if method=='GET' and '/policies/' in path:return None
                if method=='PUT':
                    puts.append(path)
                    if len(puts)==1:raise urllib.error.HTTPError('https://127.0.0.1:9200',code,'test',{},io.BytesIO(json.dumps({'error':{'reason':reason}}).encode()))
                    return {}
                if '/explain/' in path:return {}
                raise AssertionError('Unexpected request')
            with patch.object(m,'bootstrap_capacity') as cleanup:
                if expected:self.assertTrue(m.reconcile(request,body,self.row))
                else:
                    with self.assertRaises(urllib.error.HTTPError):m.reconcile(request,body,self.row)
                self.assertEqual(cleanup.called,expected)

if __name__=='__main__':unittest.main()
