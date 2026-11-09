"""Offline verification-helper boundaries; no console/SSH/appliance calls."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import ssl
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('truenas_verify', ROOT/'monitoring/truenas/verify.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
UUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


class VerifyTests(unittest.TestCase):
    def test_nonce_is_bounded_and_cannot_inject_console_or_logs(self):
        m.validate_event('test-123')
        for invalid in ['', 'a'*97, 'upperA', 'two words', 'x\nnext', "x';bad()", 'é', '../x']:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                m.validate_event(invalid)

    def test_native_program_checks_exact_identity_before_logger(self):
        for identity in [dict(uid=0, uuid=UUID, version=m.console.VERSION),
                         dict(uid=1, uuid=UUID, version=m.console.VERSION),
                         dict(uid=0, uuid='other', version=m.console.VERSION),
                         dict(uid=0, uuid=UUID, version='new-version')]:
            run = mock.Mock()
            namespace = {'identity': identity, 'subprocess': SimpleNamespace(run=run, DEVNULL=-3), 'reply': mock.Mock()}
            with mock.patch.object(m.console, 'GUEST', ''):
                program = m.event_program(UUID, 'safe-nonce')
            if identity == dict(uid=0, uuid=UUID, version=m.console.VERSION):
                exec(program, namespace)
                command = run.call_args.args[0]
                self.assertEqual(command, ['logger', '-p', 'auth.notice', '-t', 'homelab-monitoring',
                                           'HOMELAB_MONITORING_TEST: truenas-safe-nonce'])
                self.assertTrue(run.call_args.kwargs['check'])
            else:
                with self.assertRaises(ValueError): exec(program, namespace)
                run.assert_not_called()

    def test_emit_uses_private_declaration_no_credentials_and_acknowledges(self):
        declaration = dict(console_administration_enabled=True, expected_version=m.console.VERSION,
                           ssh_alias='home-lab-host', expected_vm_uuid=UUID)
        reply = dict(uid=0, uuid=UUID, version=m.console.VERSION, event_emitted=True,
                     _console_reply_path='/owned/reply')
        with mock.patch.object(m.pki, 'read_private', return_value=json.dumps(declaration)), \
             mock.patch.object(m.console, 'execute', return_value=reply) as execute, \
             mock.patch.object(m.console, 'acknowledge') as acknowledge:
            result = m.emit_event('/private/declaration', 'safe-nonce')
        self.assertEqual(execute.call_count, 1)
        acknowledge.assert_called_once_with('home-lab-host', UUID, '/owned/reply')
        self.assertTrue(all(type(value) is bool for value in result.values()))
        for field in ['console_administration_enabled', 'expected_version', 'ssh_alias']:
            bad = dict(declaration, **{field: 'unapproved'})
            with mock.patch.object(m.pki, 'read_private', return_value=json.dumps(bad)), \
                 mock.patch.object(m.console, 'execute') as execute, self.assertRaises(ValueError):
                m.emit_event('/private/declaration', 'safe-nonce')
            execute.assert_not_called()

    def test_tls_context_verifies_server_identity_and_forces_tls12(self):
        files = {'ca.pem': '/private/ca', 'client.pem': '/private/cert', 'client-key.pem': '/private/key'}
        with mock.patch.object(m.ssl, 'SSLContext') as constructor:
            context = m.tls_context(files, 'client.pem', 'client-key.pem')
        constructor.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        context.load_verify_locations.assert_called_once_with(cafile='/private/ca')
        context.load_cert_chain.assert_called_once_with(certfile='/private/cert', keyfile='/private/key')

    def connection_fixture(self):
        raw = mock.MagicMock()
        context = mock.MagicMock()
        connection = context.wrap_socket.return_value.__enter__.return_value
        connection.version.return_value = 'TLSv1.2'
        return raw, context, connection

    def test_post_handshake_open_timeout_and_eof_have_distinct_results(self):
        for outcome, expected in [(TimeoutError(), 'open'), (b'', 'closed'),
                                  (ssl.SSLEOFError(), 'closed')]:
            raw, context, connection = self.connection_fixture()
            if isinstance(outcome, BaseException): connection.recv.side_effect = outcome
            else: connection.recv.return_value = outcome
            with mock.patch.object(m.socket, 'create_connection', return_value=raw):
                self.assertEqual(m.observe_connection(context, 1234, '10.23.1.2', b'probe\n'), expected)
            context.wrap_socket.assert_called_once_with(raw.__enter__.return_value, server_hostname='10.23.1.2')
            connection.sendall.assert_called_once_with(b'probe\n')
            connection.settimeout.assert_called_once_with(3)

    def test_early_peer_tls_alert_counts_but_local_tls_and_network_errors_do_not(self):
        raw, context, connection = self.connection_fixture()
        alert = ssl.SSLError('peer rejected'); alert.reason = 'SSLV3_ALERT_BAD_CERTIFICATE'
        context.wrap_socket.side_effect = alert
        with mock.patch.object(m.socket, 'create_connection', return_value=raw):
            self.assertEqual(m.observe_connection(context, 1234, '10.23.1.2', b'probe'), 'closed')
        for failure in [TimeoutError(), ConnectionRefusedError()]:
            with mock.patch.object(m.socket, 'create_connection', side_effect=failure), self.assertRaises(type(failure)):
                m.observe_connection(context, 1234, '10.23.1.2', b'probe')
        for failure in [ssl.SSLCertVerificationError('server identity failed'), ssl.SSLError('local TLS error'), TimeoutError()]:
            context.wrap_socket.side_effect = failure
            with mock.patch.object(m.socket, 'create_connection', return_value=raw), self.assertRaises(type(failure)):
                m.observe_connection(context, 1234, '10.23.1.2', b'probe')
        context.wrap_socket.side_effect = None
        connection.sendall.side_effect = TimeoutError()
        with mock.patch.object(m.socket, 'create_connection', return_value=raw), self.assertRaises(TimeoutError):
            m.observe_connection(context, 1234, '10.23.1.2', b'probe')

    def tls_fixture(self, observations):
        profile = {'syslogserver': '10.23.1.2:6514', 'pki_directory': '/private/pki', 'ssh_alias': 'home-lab-host'}
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(m.client, 'validate_profile', return_value=profile))
        stack.enter_context(mock.patch.object(m.pki, 'validate_existing', return_value={}))
        stack.enter_context(mock.patch.object(m, 'tls_context', side_effect=['trusted', 'missing', 'wrong']))
        stack.enter_context(mock.patch.object(m, 'receiver_tunnel', return_value=contextlib.nullcontext(2345)))
        observe = stack.enter_context(mock.patch.object(m, 'observe_connection', side_effect=observations))
        return stack, observe

    def test_tls_check_requires_bracketed_controls_before_final_source_probe(self):
        stack, observe = self.tls_fixture(['open', 'closed', 'closed', 'open', 'open'])
        with stack:
            result = m.tls_check('/private/profile', 'safe-nonce')
        self.assertEqual([call.args[0] for call in observe.call_args_list],
                         ['trusted', 'missing', 'wrong', 'trusted', 'trusted'])
        for call in observe.call_args_list[:4]:
            self.assertNotIn(b'source-filter-', call.args[3])
        self.assertIn(b'HOMELAB_MONITORING_TEST: source-filter-safe-nonce\n', observe.call_args.args[3])
        self.assertTrue(all(value is True for value in result.values()))

    def test_tls_check_fails_for_whole_service_closure_or_open_negative_control(self):
        cases = [(['closed'], 1), (['open', 'open', 'closed'], 3),
                 (['open', 'closed', 'open'], 3),
                 (['open', 'closed', 'closed', 'closed'], 4)]
        for observations, count in cases:
            with self.subTest(observations=observations):
                stack, observe = self.tls_fixture(observations)
                with stack, self.assertRaises(ValueError):
                    m.tls_check('/private/profile', 'safe-nonce')
                self.assertEqual(observe.call_count, count)
                self.assertFalse(any(b'source-filter-' in call.args[3] for call in observe.call_args_list))

    def test_tunnel_is_foreground_strict_temporary_and_stopped(self):
        reservation = mock.MagicMock()
        reservation.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 2345)
        process = mock.Mock(); process.poll.return_value = None
        with mock.patch.object(m.socket, 'socket', return_value=reservation), \
             mock.patch.object(m.socket, 'create_connection'), \
             mock.patch.object(m.subprocess, 'Popen', return_value=process) as popen:
            with m.receiver_tunnel({'syslogserver':'10.23.1.2:6514','ssh_alias':'home-lab-host'}) as port:
                self.assertEqual(port, 2345)
        args = popen.call_args.args[0]
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertIn('ExitOnForwardFailure=yes', args)
        self.assertIn('ControlMaster=no', args)
        self.assertIn('127.0.0.1:2345:10.23.1.2:6514', args)
        self.assertIn('-N', args)
        self.assertNotIn('-f', args)
        process.terminate.assert_called_once()

    def test_cli_outputs_only_sanitized_booleans_on_error(self):
        output = io.StringIO()
        with mock.patch.object(m.sys, 'argv', ['verify.py', '--declaration', '/private/path', '--event', 'safe']), \
             mock.patch.object(m, 'emit_event', side_effect=ValueError('secret material')), contextlib.redirect_stdout(output):
            code = m.main()
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue()), {'verified': False})


if __name__ == '__main__':
    unittest.main()
