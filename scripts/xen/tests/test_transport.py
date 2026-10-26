import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import transport


class TransportTests(unittest.TestCase):
    def setup_context(self,directory,extra=None):
        pin=Path(directory)/'known_hosts';pin.write_text('example-host ssh-ed25519 public-fixture\n');pin.chmod(0o600)
        env={'XEN_RUN_DIR':directory,'XEN_HOST':'root@192.0.2.10','XEN_SSH_HOST_ALIAS':'example-host','XEN_KNOWN_HOSTS_FILE':str(pin),'XEN_FORWARD_TARGET':'192.0.2.20:80','XEN_SSH_CONTROL':'/old/master','XOA_URL':'ws://127.0.0.1:54618','XOA_TOKEN':'never-in-argv'}
        env.update(extra or {})
        return env,pin
    def test_missing_private_transport_inputs_fail_before_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            values,_=self.setup_context(directory)
            for key in ['XEN_HOST','XEN_SSH_HOST_ALIAS','XEN_KNOWN_HOSTS_FILE','XEN_FORWARD_TARGET']:
                environment=dict(values);environment.pop(key,None)
                with self.subTest(key=key),patch.dict(os.environ,environment,clear=True),patch.object(transport.subprocess,'run') as runner:
                    with self.assertRaises(ValueError):transport.open_transport()
                    runner.assert_not_called()

    def test_warm_master_reused_without_askpass_and_only_owned_forward_cancelled(self):
        with tempfile.TemporaryDirectory() as directory:
            env,pin=self.setup_context(directory)
            with patch.dict(os.environ,env,clear=True),patch.object(transport,'free_port',return_value=45678),patch.object(transport.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
                opened=transport.open_transport()
                self.assertEqual(os.environ['XOA_URL'],'ws://127.0.0.1:45678')
                opened.close();opened.close()
                self.assertEqual(os.environ['XOA_URL'],env['XOA_URL'])
                commands=[c.args[0] for c in run.call_args_list]
                self.assertFalse(any('-M' in c for c in commands))
                self.assertEqual(sum('cancel' in c for c in commands),1)
                self.assertFalse(any('exit' in c for c in commands))
                self.assertTrue(any('127.0.0.1:45678:192.0.2.20:80' in c for c in commands))
                self.assertFalse(any('SSH_ASKPASS_REQUIRE' in c.kwargs.get('env',{}) for c in run.call_args_list))
    def test_cold_master_is_pinned_password_capable_and_password_not_in_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            env,pin=self.setup_context(directory,{'XEN_SSH_BIND_INTERFACE':'en7'})
            results=[1,1,0,0]
            def result(*args,**kwargs):return subprocess.CompletedProcess(args[0],results.pop(0),'','')
            with patch.dict(os.environ,env,clear=True),patch.object(transport.subprocess,'run',side_effect=result) as run:
                opened=transport.open_transport(api=False)
                master=next(c for c in run.call_args_list if '-M' in c.args[0])
                args=master.args[0]
                for expected in ['StrictHostKeyChecking=yes','HostKeyAlias=example-host','UserKnownHostsFile='+str(pin.resolve()),'ControlPersist=7200','NumberOfPasswordPrompts=1','ConnectTimeout=5','GlobalKnownHostsFile=/dev/null','UpdateHostKeys=no']:
                    self.assertIn(expected,args)
                self.assertIn('-fNT',args)
                self.assertEqual(args[args.index('-B')+1],'en7')
                self.assertEqual(master.kwargs['env']['SSH_ASKPASS_REQUIRE'],'force')
                self.assertNotIn('XOA_TOKEN',master.kwargs['env'])
                self.assertNotIn('XOA_URL',master.kwargs['env'])
                self.assertTrue(master.kwargs['env']['SSH_ASKPASS'].endswith('ssh_askpass.sh'))
                self.assertNotIn('SSH_ASKPASS',os.environ)
                self.assertNotIn('never-in-argv',' '.join(args))
                self.assertNotEqual(os.environ['XEN_SSH_CONTROL'],'/old/master')
                opened.close()
    def test_unsafe_bind_interface_rejected_before_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            for interface in ['-oProxyCommand=bad','en7; touch /tmp/bad','en7\nother','en 7']:
                env,_=self.setup_context(directory,{'XEN_SSH_BIND_INTERFACE':interface})
                with self.subTest(interface=interface),patch.dict(os.environ,env,clear=True),patch.object(transport.subprocess,'run') as runner:
                    with self.assertRaises(ValueError):transport.open_transport(api=False)
                    runner.assert_not_called()
    def test_interface_binding_never_reuses_a_legacy_or_other_interface_master(self):
        controls=[]
        with tempfile.TemporaryDirectory() as directory:
            for interface in ['en7','en8']:
                env,_=self.setup_context(directory,{'XEN_SSH_BIND_INTERFACE':interface})
                with patch.dict(os.environ,env,clear=True),patch.object(transport.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as runner:
                    opened=transport.open_transport(api=False);controls.append(opened.control);opened.close()
                    self.assertFalse(any('/old/master' in call.args[0] for call in runner.call_args_list))
            self.assertNotEqual(*controls)
    def test_forward_failure_is_closed_and_does_not_replace_url_or_cancel_unowned_forward(self):
        with tempfile.TemporaryDirectory() as directory:
            env,pin=self.setup_context(directory)
            with patch.dict(os.environ,env,clear=True),patch.object(transport,'free_port',return_value=45678),patch.object(transport.subprocess,'run',side_effect=[subprocess.CompletedProcess([],0,'',''),subprocess.CompletedProcess([],1,'','denied')]) as run:
                with self.assertRaisesRegex(RuntimeError,'forward'):transport.open_transport()
                self.assertEqual(os.environ['XOA_URL'],env['XOA_URL'])
                self.assertFalse(any('cancel' in c.args[0] for c in run.call_args_list))
    def test_unsafe_host_rejected_before_subprocess(self):
        for host in ['-oProxyCommand=bad','root@host;touch /tmp/bad','root@host\nother','root@','root@host:22','user@@host']:
            with patch.dict(os.environ,{'XEN_HOST':host,'XOA_URL':'wss://operator.example'},clear=True),patch.object(transport.subprocess,'run') as run:
                with self.assertRaises(ValueError):transport.open_transport()
                run.assert_not_called()
    def test_nonloopback_url_respected_without_forwarding(self):
        with tempfile.TemporaryDirectory() as directory:
            env,pin=self.setup_context(directory,{'XOA_URL':'wss://operator.example/api'})
            with patch.dict(os.environ,env,clear=True),patch.object(transport.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
                opened=transport.open_transport();opened.close()
                self.assertEqual(os.environ['XOA_URL'],env['XOA_URL'])
                self.assertEqual(len(run.call_args_list),1)
    def test_cancellation_failure_still_restores_original_url(self):
        with tempfile.TemporaryDirectory() as directory:
            env,pin=self.setup_context(directory)
            with patch.dict(os.environ,env,clear=True),patch.object(transport,'free_port',return_value=45678),patch.object(transport.subprocess,'run',side_effect=[subprocess.CompletedProcess([],0,'',''),subprocess.CompletedProcess([],0,'',''),subprocess.CompletedProcess([],1,'','')]):
                opened=transport.open_transport()
                with self.assertRaises(RuntimeError):opened.close()
                self.assertEqual(os.environ['XOA_URL'],env['XOA_URL'])

if __name__=='__main__':unittest.main()
