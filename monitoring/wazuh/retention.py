#!/usr/bin/env python3
"""Apply one reviewed ISM policy and attach only unmanaged Wazuh alert indices."""
import base64
import copy
import datetime as dt
import json
import os
import re
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from policy import require_approval, validate_retention

POLICY_ID = 'homelab-wazuh-alerts-7d'
PATTERN = 'wazuh-alerts-4.x-*'


def bootstrap_capacity(request, candidate, now=None):
    """Delete one exact reviewed expired index; never expand a wildcard or alias."""
    now = now or dt.datetime.now(dt.timezone.utc)
    if not isinstance(candidate, dict) or set(candidate) != {'index', 'uuid', 'creation_date'}:
        raise ValueError('An exact reviewed index identity and creation timestamp are required')
    name = candidate['index']
    match = re.fullmatch(r'wazuh-alerts-4\.x-(\d{4})\.(\d{2})\.(\d{2})', name)
    if not match or not re.fullmatch(r'[A-Za-z0-9_-]{20,24}', candidate['uuid']):
        raise ValueError('Only an exact Wazuh daily alert index is eligible')
    date = dt.date(*(int(x) for x in match.groups()))
    created = dt.datetime.fromtimestamp(int(candidate['creation_date'])/1000, dt.timezone.utc)
    cutoff = now - dt.timedelta(days=7)
    if date >= cutoff.date() or created >= cutoff:
        raise ValueError('Both the daily date and actual index creation must be older than seven days')
    path = '/' + urllib.parse.quote(name, safe='')
    actual = request('GET', path+'/_settings', None, True)
    if actual is None:
        return False
    if set(actual) != {name}:
        raise ValueError('Index aliases and expanded selections are forbidden')
    settings = actual[name]['settings']['index']
    if settings.get('uuid') != candidate['uuid'] or settings.get('creation_date') != candidate['creation_date']:
        raise ValueError('Reviewed index identity changed; no deletion permitted')
    explained = request('GET', '/_plugins/_ism/explain/'+urllib.parse.quote(name, safe=''))
    status = explained[name]
    if any(status.get(k) for k in ('policy_id', 'index.plugins.index_state_management.policy_id', 'index.opendistro.index_state_management.policy_id')):
        raise ValueError('An existing policy owns the candidate; no bootstrap deletion permitted')
    result = request('DELETE', path)
    if result.get('acknowledged') is not True:
        raise ValueError('Indexer did not acknowledge the exact expired alert deletion')
    return True


def reconcile(request, body, bootstrap=None):
    validate_retention(body)
    path = '/_plugins/_ism/policies/' + POLICY_ID
    current = request('GET', path, None, True)
    changed = False
    if current is None:
        try:
            request('PUT', path, body)
        except urllib.error.HTTPError as error:
            if error.code != 400 or bootstrap is None:
                raise
            details = json.loads(error.read()).get('error', {})
            reason = details.get('reason', '') if isinstance(details, dict) else ''
            if not re.search(r'would add \[\d+\] total shards, but this cluster currently has \[\d+\]/\[\d+\] maximum shards open', reason):
                raise
            bootstrap_capacity(request, bootstrap)
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
        assigned = (status.get('policy_id') or status.get('index.plugins.index_state_management.policy_id')
                    or status.get('index.opendistro.index_state_management.policy_id'))
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
    bootstrap = config.get('shard_bootstrap')
    if bootstrap is not None and config.get('shard_bootstrap_cleanup_approved') is not True:
        raise ValueError('Reviewed expired-index bootstrap requires explicit cleanup approval')
    parsed = urllib.parse.urlsplit(config['url'])
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('A clean HTTPS indexer origin is required')
    headers = {'Content-Type': 'application/json'}
    if config.get('local_admin_certificate') is True:
        if os.geteuid() != 0 or config['url'] != 'https://127.0.0.1:9200':
            raise ValueError('Local certificate authentication requires root and the fixed loopback indexer')
        certs = Path('/etc/wazuh-indexer/certs')
        context = ssl.create_default_context(cafile=str(certs/'root-ca.pem'))
        context.load_cert_chain(str(certs/'admin.pem'), str(certs/'admin-key.pem'))
    else:
        context = ssl.create_default_context(cafile=config.get('ca_file') or None)
        token = base64.b64encode((config['username'] + ':' + config['password']).encode()).decode()
        headers['Authorization'] = 'Basic ' + token
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('Indexer redirects are forbidden')
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
    def request(method, path, body=None, missing_ok=False):
        req = urllib.request.Request(config['url'].rstrip('/') + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers=headers)
        try:
            with opener.open(req, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            raise
    body = json.loads(Path(__file__).with_name('retention.json').read_text())
    print(json.dumps({'changed': reconcile(request, body, bootstrap)}))


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        try:
            details = json.loads(error.read()).get('error', {})
            reason = details.get('reason', '') if isinstance(details, dict) else ''
        except (ValueError, UnicodeError):
            reason = ''
        print('Wazuh retention API failed: HTTP ' + str(error.code) + '; ' + str(reason)[:300], file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Wazuh retention reconciliation failed; inspect trusted indexer access and existing policy ownership.', file=sys.stderr)
        sys.exit(1)
