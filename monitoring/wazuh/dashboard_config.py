#!/usr/bin/env python3
"""Narrow, text-preserving dashboard edit and sanitized Tailscale preflights.

The caller must additionally parse staged YAML with the dashboard's native YAML
loader before activation. This editor intentionally rejects ambiguous layouts.
No input/configuration values are emitted in diagnostics.
"""
import argparse
import json
from pathlib import Path
import re
import sys

OWNED = {
    'server.host': '"127.0.0.1"',
    'server.port': '5601',
    'server.ssl.enabled': 'false',
    'opensearch_security.cookie.secure': 'true',
}
KEY = re.compile(r'''^(?P<key>"[^"\\]+"|'[^']+'|[A-Za-z0-9_.<>-]+):[ \t]*(?P<value>.*?)(?P<end>\r?\n)?$''')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def render_config(text):
    """Replace only owned, unambiguous scalar keys; preserve all other bytes."""
    lines = text.splitlines(keepends=True)
    seen = set()
    output = []
    for index, line in enumerate(lines):
        if line.startswith(('---', '...', '%', '{', '[', '<<:')):
            raise ValueError('Ambiguous dashboard YAML layout; review manually')
        match = KEY.match(line)
        if not match:
            output.append(line)
            continue
        key = match['key'].strip('"\'')
        if key in ('server', 'opensearch_security', '<<'):
            raise ValueError('Nested or merged dashboard settings require manual review')
        if key not in OWNED:
            output.append(line)
            continue
        if key in seen:
            raise ValueError('Duplicate managed dashboard setting')
        seen.add(key)
        value = match['value']
        if value.startswith(('|', '>', '&', '*', '!', '{', '[')):
            raise ValueError('Managed dashboard setting is not a simple scalar')
        for following in lines[index + 1:]:
            if not following.strip() or following.lstrip().startswith('#'):
                continue
            if following[0].isspace():
                raise ValueError('Managed dashboard setting has an ambiguous continuation')
            break
        # A comment begins only outside a quoted scalar and after whitespace.
        comment = ''
        quote = None
        escaped = False
        for position, char in enumerate(value):
            if escaped:
                escaped = False
            elif char == '\\' and quote == '"':
                escaped = True
            elif char in ('"', "'"):
                quote = None if quote == char else char if quote is None else quote
            elif char == '#' and quote is None and (position == 0 or value[position - 1].isspace()):
                comment = ' ' + value[position:]
                break
        output.append(f'{match["key"]}: {OWNED[key]}{comment}{match["end"] or ""}')
    newline = '\r\n' if '\r\n' in text else '\n'
    result = ''.join(output)
    for key, value in OWNED.items():
        if key not in seen:
            if result and not result.endswith('\n'):
                result += newline
            result += f'{key}: {value}{newline}'
    return result


def validate_identity(state, suffix, hostname):
    if not LABEL.fullmatch(hostname):
        raise ValueError('Expected hostname must be a single DNS label of 1 to 63 characters')
    labels = suffix.split('.')
    if len(labels) < 3 or labels[-2:] != ['ts', 'net'] or not all(LABEL.fullmatch(part) for part in labels):
        raise ValueError('Expected private MagicDNS suffix must end in .ts.net')
    fqdn = f'{hostname}.{suffix}'
    if len(fqdn) > 253:
        raise ValueError('Expected private hostname exceeds DNS bounds')
    identity = state.get('Self') or {}
    if (state.get('BackendState') != 'Running' or identity.get('Online') is not True
            or identity.get('DNSName', '').rstrip('.') != fqdn):
        raise ValueError('Node is not online with the expected private tailnet identity; dashboard left unchanged')
    return fqdn


def validate_serve(config, fqdn):
    if config is None or config == {}:
        return
    expected = {'TCP': {'443': {'HTTPS': True}},
                'Web': {fqdn + ':443': {'Handlers': {'/': {'Proxy': 'http://127.0.0.1:5601'}}}}}
    candidate = dict(config)
    funnel = candidate.pop('AllowFunnel', {})
    if not isinstance(funnel, dict) or any(value is not False for value in funnel.values()):
        raise ValueError('Public Funnel configuration is forbidden')
    if candidate != expected:
        raise ValueError('Existing Serve configuration is unrelated; refusing to replace it')


def validate_network_preferences(preferences):
    if any(preferences.get(key) for key in ('AdvertiseRoutes', 'ExitNodeID', 'ExitNodeIP')):
        raise ValueError('Existing subnet routes or exit node require separate review')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['render', 'identity', 'serve', 'preferences'])
    parser.add_argument('--source', type=Path)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--suffix')
    parser.add_argument('--hostname')
    parser.add_argument('--fqdn')
    args = parser.parse_args()
    try:
        if args.operation == 'render':
            with args.source.open(encoding='utf-8', newline='') as source:
                result = render_config(source.read())
            with args.destination.open('w', encoding='utf-8', newline='') as destination:
                destination.write(result)
            args.destination.chmod(0o600)
        elif args.operation == 'identity':
            print(validate_identity(json.load(sys.stdin), args.suffix, args.hostname))
        elif args.operation == 'serve':
            validate_serve(json.load(sys.stdin), args.fqdn)
        else:
            validate_network_preferences(json.load(sys.stdin))
    except (ValueError, TypeError, KeyError, OSError, AttributeError):
        print('Private dashboard safety validation failed; inspect configuration privately.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
