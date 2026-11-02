#!/usr/bin/env python3
"""Apply one reviewed ISM policy and attach only unmanaged Wazuh alert indices."""
import base64
import copy
import json
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from policy import require_approval, validate_retention

POLICY_ID = 'homelab-wazuh-alerts-7d'
PATTERN = 'wazuh-alerts-4.x-*'


def reconcile(request, body):
    validate_retention(body)
    path = '/_plugins/_ism/policies/' + POLICY_ID
    current = request('GET', path, None, True)
    changed = False
    if current is None:
        request('PUT', path, body)
        changed = True
    else:
        actual = copy.deepcopy({key: current['policy'].get(key) for key in body['policy']})
        # ISM adds retry defaults and template timestamps when returning policies.
        for state in actual.get('states', []):
            for action in state.get('actions', []):
                if action.get('retry') == {'count': 3, 'backoff': 'exponential', 'delay': '1m'}:
                    action.pop('retry')
        for template in actual.get('ism_template', []) or []:
            template.pop('last_updated_time', None)
        if actual != body['policy']:
            request('PUT', path + '?if_seq_no=' + str(current['_seq_no']) + '&if_primary_term=' + str(current['_primary_term']), body)
            changed = True
    explained = request('GET', '/_plugins/_ism/explain/' + PATTERN, None, True) or {}
    for index, status in explained.items():
        if index == 'total_managed_indices':
            continue
        if not index.startswith('wazuh-alerts-4.x-'):
            raise ValueError('Indexer returned an index outside the approved alert pattern')
        assigned = status.get('policy_id') or status.get('index.plugins.index_state_management.policy_id')
        if assigned and assigned != POLICY_ID:
            raise ValueError('An alert index has another retention policy; review migration separately')
        if not assigned:
            result = request('POST', '/_plugins/_ism/add/' + urllib.parse.quote(index, safe=''), {'policy_id': POLICY_ID})
            if result.get('failures') or result.get('failed_indices', 0) or result.get('updated_indices') != 1:
                raise ValueError('Indexer rejected policy attachment')
            changed = True
    return changed


def main():
    config = json.load(sys.stdin)
    require_approval(config.get('access_verified'), config.get('deployment_approved'))
    if config.get('retention_approved') is not True:
        raise ValueError('Explicit retention approval required')
    parsed = urllib.parse.urlsplit(config['url'])
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('A clean HTTPS indexer origin is required')
    context = ssl.create_default_context(cafile=config.get('ca_file') or None)
    token = base64.b64encode((config['username'] + ':' + config['password']).encode()).decode()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('Indexer redirects are forbidden')
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
    def request(method, path, body=None, missing_ok=False):
        req = urllib.request.Request(config['url'].rstrip('/') + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={'Authorization': 'Basic ' + token, 'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            raise
    body = json.loads(Path(__file__).with_name('retention.json').read_text())
    print(json.dumps({'changed': reconcile(request, body)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Wazuh retention reconciliation failed; inspect trusted indexer access and existing policy ownership.', file=sys.stderr)
        sys.exit(1)
