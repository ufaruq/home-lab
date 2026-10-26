#!/usr/bin/env python3
"""Validate Wazuh manager JSON status without treating disabled features as failures.

The daemon list/status schema follows wazuh/wazuh v4.7.5
src/init/wazuh-server.sh (DAEMONS, OP_DAEMONS and status()).
"""
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

REQUIRED = frozenset({
    'wazuh-analysisd', 'wazuh-remoted', 'wazuh-db', 'wazuh-modulesd',
    'wazuh-logcollector', 'wazuh-syscheckd', 'wazuh-monitord',
    'wazuh-apid', 'wazuh-execd', 'wazuh-authd',
})
CONFIGURABLE = frozenset({'wazuh-authd', 'wazuh-execd'})


def disabled_from_config(configuration):
    root = ET.fromstring('<root>' + configuration + '</root>')
    disabled = set()
    auth = root.find('./ossec_config/auth')
    if auth is None or (auth.findtext('disabled') or '').strip() == 'yes':
        disabled.add('wazuh-authd')
    if (root.findtext('./ossec_config/active-response/disabled') or '').strip() == 'yes':
        disabled.add('wazuh-execd')
    return disabled


def validate_status(payload, returncode, disabled=()):
    # Upstream sets rc=1 for *any* stopped process, including optional daemons.
    if returncode not in (0, 1) or payload.get('error') != 0 or not isinstance(payload.get('data'), list):
        raise ValueError('Wazuh manager status command failed or returned invalid JSON status')
    disabled = set(disabled)
    if disabled - CONFIGURABLE:
        raise ValueError('Core manager daemons cannot be exempted from health validation')
    statuses = {}
    for entry in payload['data']:
        name, status = entry.get('daemon'), entry.get('status')
        if not isinstance(name, str) or name in statuses or status not in ('running', 'stopped'):
            raise ValueError('Malformed or duplicate manager daemon status')
        statuses[name] = status
    failed = sorted(name for name in REQUIRED - disabled if statuses.get(name) != 'running')
    if failed:
        raise ValueError('Required manager daemons are missing or stopped: ' + ', '.join(failed))


if __name__ == '__main__':
    try:
        disabled = disabled_from_config(Path(sys.argv[2]).read_text())
        validate_status(json.load(sys.stdin), int(sys.argv[1]), disabled)
        print('Required Wazuh manager daemons are running')
    except (ValueError, OSError, ET.ParseError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
