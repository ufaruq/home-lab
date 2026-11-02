"""Process-scoped SSH access and owned XO forwarding; no credential-file reads."""

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]
ASKPASS = Path(__file__).with_name('ssh_askpass.sh')


def validate_host(host):
    pattern = r'(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?(?:[A-Za-z0-9_][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:]+\])'
    if not isinstance(host, str) or len(host) > 320 or not re.fullmatch(pattern, host):
        raise ValueError('XEN_HOST must be a safe SSH hostname, optionally with a username; no options, port suffix or shell syntax')
    return host


def private_known_hosts():
    value = os.environ.get('XEN_KNOWN_HOSTS_FILE')
    if not value:
        raise ValueError('XEN_KNOWN_HOSTS_FILE is required')
    path = Path(value).expanduser().resolve()
    if ROOT == path or ROOT in path.parents:
        raise ValueError('Private known_hosts must be outside the checkout')
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError('Private known_hosts must be an owner-only regular file')
    return path


def forward_target():
    value = os.environ.get('XEN_FORWARD_TARGET', '')
    match = re.fullmatch(r'([A-Za-z0-9_][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:]+\]):([0-9]+)', value)
    if not match or not 1 <= int(match.group(2)) <= 65535:
        raise ValueError('XEN_FORWARD_TARGET must explicitly specify a safe host:port')
    return value


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


def ssh_environment():
    environment = dict(os.environ)
    for name in ('XOA_TOKEN', 'XOA_PASSWORD', 'XOA_USER', 'XOA_URL'):
        environment.pop(name, None)
    return environment


def run_ssh(binary, arguments, environment=None, timeout=15):
    try:
        return subprocess.run([binary, *arguments], stdin=subprocess.DEVNULL,
                              text=True, capture_output=True, timeout=timeout,
                              env=environment if environment is not None else ssh_environment())
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('SSH transport command could not complete') from None


def master_alive(binary, host, control):
    try:
        result = run_ssh(binary, ['-S', control, '-O', 'check', '-o', 'BatchMode=yes', host])
        return result.returncode == 0
    except RuntimeError:
        return False


def private_directory():
    path = Path(os.environ.get('XEN_RUN_DIR', str(Path.home() / '.config/home-lab/xen'))).expanduser()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError('SSH transport directory must be owned by you with permissions 0700')
    return path.resolve()


def loopback_endpoint(url):
    if not url:
        raise ValueError('XOA_URL is required for API transport')
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('ws', 'wss') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        host = parsed.hostname
        loopback = host.lower() == 'localhost'
        if not loopback:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
        return parsed, loopback
    except ValueError:
        raise ValueError('XOA_URL must be a websocket endpoint without embedded credentials') from None


class Transport:
    def __init__(self, binary, host, control):
        self.binary, self.host, self.control = binary, host, control
        self._forward = None
        self._original_url = None
        self._url_changed = False
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        failure = False
        try:
            if self._forward is not None:
                result = run_ssh(self.binary, ['-S', self.control, '-O', 'cancel',
                                              '-L', self._forward, self.host])
                failure = result.returncode != 0
        finally:
            if self._url_changed:
                os.environ['XOA_URL'] = self._original_url
        if failure:
            raise RuntimeError('Could not cancel the owned SSH forward; process URL was restored')

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        try:
            self.close()
        except RuntimeError:
            if kind is None:
                raise
        return False


def open_transport(api=True):
    """Reuse/authenticate host SSH, and optionally own a fresh localhost XO forward.

    XEN_SSH_CONTROL is updated to the usable cached master. close() preserves that
    master, cancels only this object's forward and restores its previous XOA_URL.
    No function is invoked automatically at module import.
    """
    host = validate_host(os.environ.get('XEN_HOST'))
    alias = os.environ.get('XEN_SSH_HOST_ALIAS', '')
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', alias):
        raise ValueError('XEN_SSH_HOST_ALIAS is required and must be a safe host-key alias')
    pin_file = private_known_hosts()
    bind_interface = os.environ.get('XEN_SSH_BIND_INTERFACE', '')
    if bind_interface and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,31}', bind_interface):
        raise ValueError('XEN_SSH_BIND_INTERFACE must name one safe local network interface')
    endpoint, loopback = loopback_endpoint(os.environ.get('XOA_URL')) if api else (None, False)
    target = forward_target() if loopback else None
    binary = os.environ.get('XEN_SSH_BIN', 'ssh')
    control = os.environ.get('XEN_SSH_CONTROL')
    binding_identity = host + ('\0' + bind_interface if bind_interface else '')
    if bind_interface:
        # An old live master may use another interface; never silently reuse it.
        control = str(private_directory() / ('ssh-' + hashlib.sha256(binding_identity.encode()).hexdigest()[:12]))
    if not control or not master_alive(binary, host, control):
        directory = private_directory()
        control = str(directory / ('ssh-' + hashlib.sha256(binding_identity.encode()).hexdigest()[:12]))
        if len(os.fsencode(control)) > 100:
            raise ValueError('SSH transport directory path is too long for a control socket')
        if not master_alive(binary, host, control):
            if not ASKPASS.is_file() or not os.access(ASKPASS, os.X_OK):
                raise ValueError('Versioned SSH askpass helper is unavailable or not executable')
            environment = ssh_environment()
            environment.update(SSH_ASKPASS=str(ASKPASS), SSH_ASKPASS_REQUIRE='force')
            environment.setdefault('DISPLAY', ':0')
            arguments = ['-M', '-S', control, '-fNT', '-o', 'ControlPersist=7200',
                         '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=yes',
                         '-o', 'HostKeyAlias=' + alias, '-o', 'UserKnownHostsFile=' + str(pin_file),
                         '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UpdateHostKeys=no',
                         '-o', 'NumberOfPasswordPrompts=1', '-o', 'BatchMode=no',
                         '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2', host]
            if bind_interface:
                arguments[-1:-1] = ['-B', bind_interface]
            result = run_ssh(binary, arguments, environment=environment, timeout=180)
            if result.returncode or not master_alive(binary, host, control):
                raise RuntimeError('XCP-ng SSH authentication failed; no usable cached master was established')
    os.environ['XEN_SSH_CONTROL'] = control
    opened = Transport(binary, host, control)
    if loopback:
        port = free_port()
        forward = '127.0.0.1:%s:%s' % (port, target)
        result = run_ssh(binary, ['-S', control, '-O', 'forward', '-o', 'ExitOnForwardFailure=yes',
                                 '-L', forward, host])
        if result.returncode:
            raise RuntimeError('Could not establish the owned XOA SSH forward; endpoint was not changed')
        opened._forward = forward
        opened._original_url = os.environ['XOA_URL']
        opened._url_changed = True
        os.environ['XOA_URL'] = urlunsplit((endpoint.scheme, '127.0.0.1:' + str(port),
                                          endpoint.path, endpoint.query, endpoint.fragment))
    return opened
