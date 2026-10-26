#!/usr/bin/env python3
"""Reconcile one native OPNsense syslog destination. Input JSON arrives on stdin."""
import base64
import ipaddress
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request

NETWORKS = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))


def destination(address, port, transport, certificate=''):
    ip = ipaddress.ip_address(address)
    if not any(ip.version == net.version and ip in net for net in NETWORKS):
        raise ValueError('Syslog receiver must be a literal RFC1918 or ULA private address')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid syslog port')
    if transport not in (f'tcp{ip.version}', f'tls{ip.version}'):
        raise ValueError('Use TCP or TLS matching the receiver address family')
    if transport.startswith('tls') and not re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}', certificate):
        raise ValueError('Native TLS syslog requires an existing reviewed client certificate UUID')
    return {'enabled': '1', 'transport': transport, 'hostname': str(ip), 'port': str(port),
            'program': 'filterlog,sshd', 'level': 'notice,warn,err,crit,alert,emerg',
            'facility': '', 'certificate': certificate, 'rfc5424': '0', 'description': 'homelab-monitoring'}


def normalize(value):
    # Native API returns selection fields as {option: {selected: 0|1, value: ...}}.
    if isinstance(value, dict):
        return ','.join(sorted(k for k, v in value.items() if str(v.get('selected', 0)) == '1'))
    return '' if value is None else str(value)


def equal(actual, desired):
    for key, value in desired.items():
        observed = normalize(actual.get(key))
        if key in ('program', 'level', 'facility'):
            if sorted(filter(None, observed.split(','))) != sorted(filter(None, value.split(','))):
                return False
        elif observed != value:
            return False
    return True


def validate_transport(config):
    transport = config.get('transport', '')
    if transport in ('tcp4', 'tcp6'):
        if config.get('vpn_verified') is not True:
            raise ValueError('Plaintext syslog requires operator-verified end-to-end WireGuard/IPsec protection; private addressing or VLANs are insufficient')
    elif transport in ('tls4', 'tls6'):
        if config.get('tls_relay_verified') is not True:
            raise ValueError('TLS syslog requires an existing verified TLS relay; the native Wazuh listener is not TLS')
        if not re.fullmatch(r'[a-fA-F0-9]{64}', config.get('tls_ca_sha256', '')):
            raise ValueError('Record the verified relay CA fingerprint already trusted by OPNsense')
    else:
        raise ValueError('Only verified VPN/TCP or verified TLS relay syslog is supported')
    return destination(config['destination'], config['port'], transport, config.get('certificate', ''))


def configure(config, request):
    if config.get('access_verified') is not True or config.get('deployment_approved') is not True:
        raise ValueError('Verified access and deployment approval required')
    return reconcile(request, validate_transport(config))


def reconcile(request, desired):
    base = '/api/syslog/settings/'
    rows = request('POST', base + 'searchDestinations', {'current': 1, 'rowCount': -1})['rows']
    owned = [r for r in rows if r.get('description') == desired['description']]
    if len(owned) > 1:
        raise ValueError('Duplicate owned destinations require manual review')
    if owned:
        uuid = owned[0]['uuid']
        actual = request('GET', base + 'getDestination/' + uuid)['destination']
        if equal(actual, desired):
            return False
        result = request('POST', base + 'setDestination/' + uuid, {'destination': desired})
    else:
        result = request('POST', base + 'addDestination', {'destination': desired})
        uuid = result.get('uuid')
    if result.get('result') != 'saved' or not uuid:
        raise ValueError('OPNsense rejected syslog destination; review native field validation')
    result = request('POST', '/api/syslog/service/reconfigure', {})
    if result.get('status') not in ('ok', 'OK'):
        raise ValueError('OPNsense syslog reconfigure failed')
    actual = request('GET', base + 'getDestination/' + uuid)['destination']
    if not equal(actual, desired):
        raise ValueError('OPNsense syslog readback differs from requested configuration')
    return True


def main():
    config = json.load(sys.stdin)
    if config.get('access_verified') is not True or config.get('deployment_approved') is not True:
        raise ValueError('Verified access and deployment approval required')
    validate_transport(config)
    parsed = urllib.parse.urlsplit(config['url'])
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('A clean HTTPS OPNsense origin is required')
    context = ssl.create_default_context(cafile=config.get('ca_file') or None)
    token = base64.b64encode((config['key'] + ':' + config['secret']).encode()).decode()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('API redirects are forbidden')
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
    def request(method, path, body=None):
        req = urllib.request.Request(config['url'].rstrip('/') + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={'Authorization': 'Basic ' + token, 'Content-Type': 'application/json'})
        with opener.open(req, timeout=30) as response:
            return json.load(response)
    print(json.dumps({'changed': configure(config, request)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Do not echo responses, URLs, request headers or credentials.
        print('OPNsense syslog reconciliation failed; check private inputs, TLS trust and native API access.', file=sys.stderr)
        sys.exit(1)
