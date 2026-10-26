import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location('guest_state_verify', pathlib.Path(__file__).parents[1]/'filter_plugins/guest_state_verify.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def observed():
    return {'passwd': {'app': ['x','1001','1001','','/home/app','/bin/bash']},
            'group': {'app': ['x','1001',''], 'docker': ['x','999','app']},
            'packages': {'docker-ce': [{'version': '5:27.1.1-1', 'arch': 'amd64'}]},
            'services': {'docker.service': {'status':'enabled','state':'running'}},
            'files': {'/etc/docker/daemon.json': {'isreg':True,'checksum':'a'*64, 'mode':'0600'}}}


def desired():
    return {'users':[{'name':'app','uid':1001,'group':'app','groups':['docker'],'home':'/home/app','shell':'/bin/bash'}],
            'groups':[{'name':'app','gid':1001}], 'packages':['docker-ce:amd64=5:27.1.1-1'],
            'services':[{'name':'docker.service','enabled':True}],
            'files':[{'path':'/etc/docker/daemon.json','checksum_sha256':'a'*64,'mode':'0600'}]}


class GuestVerificationTests(unittest.TestCase):
    def test_matching_state_succeeds_without_requiring_running_state(self):
        actual=observed(); actual['services']['docker.service']['state']='stopped'
        self.assertEqual(m.guest_state_errors(desired(), actual), [])
    def test_detects_real_user_group_package_service_and_file_drift(self):
        actual=observed()
        actual['passwd']['app'][1]='1002'
        actual['group']['app'][1]='1002'
        actual['group']['docker'][2]=''
        actual['packages']['docker-ce'][0]['version']='5:27.0.0-1'
        actual['services']['docker.service']['status']='disabled'
        actual['files']['/etc/docker/daemon.json']['checksum']='b'*64
        errors=m.guest_state_errors(desired(), actual)
        for needle in ['uid','gid','membership','package','enabled','checksum']:
            self.assertTrue(any(needle in e for e in errors), (needle,errors))
    def test_declared_runtime_state_is_verified_when_present(self):
        wanted=desired(); wanted['services'][0]['state']='stopped'
        self.assertTrue(any('runtime' in e for e in m.guest_state_errors(wanted, observed())))
    def test_package_facts_can_use_architecture_qualified_keys(self):
        actual=observed()
        actual['packages']={'docker-ce:amd64':[{'version':'5:27.1.1-1','arch':'amd64'}]}
        self.assertEqual(m.guest_state_errors(desired(),actual),[])

    def test_missing_objects_and_wrong_architecture_fail(self):
        wanted=desired(); actual=observed();actual['packages']['docker-ce'][0]['arch']='i386'
        self.assertTrue(any('package' in e for e in m.guest_state_errors(wanted, actual)))
        errors=m.guest_state_errors(wanted,{})
        self.assertGreaterEqual(len(errors),5)

if __name__ == '__main__': unittest.main()
