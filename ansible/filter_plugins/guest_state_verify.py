"""Read-only comparison of declared guest state with freshly collected facts."""

def guest_state_errors(desired, observed):
    errors = []
    passwd = observed.get('passwd', {})
    groups = observed.get('group', {})
    for wanted in desired.get('groups', []):
        actual = groups.get(wanted['name'])
        if not actual:
            errors.append('missing group ' + wanted['name'])
        elif 'gid' in wanted and str(actual[1]) != str(wanted['gid']):
            errors.append('group gid differs: ' + wanted['name'])
    for wanted in desired.get('users', []):
        name = wanted['name']
        actual = passwd.get(name)
        if not actual:
            errors.append('missing user ' + name)
            continue
        for field, position in [('uid', 1), ('home', 4), ('shell', 5)]:
            if field in wanted and str(actual[position]) != str(wanted[field]):
                errors.append('user ' + field + ' differs: ' + name)
        if 'group' in wanted:
            primary = groups.get(str(wanted['group']))
            expected_gid = str(primary[1]) if primary else str(wanted['group'])
            if str(actual[2]) != expected_gid:
                errors.append('user primary gid differs: ' + name)
        for group in wanted.get('groups', []):
            record = groups.get(group)
            if not record or name not in str(record[2]).split(','):
                errors.append('user group membership missing: ' + name + ' -> ' + group)
    for wanted in desired.get('packages', []):
        package, separator, version = wanted.partition('=')
        name, colon, arch = package.partition(':')
        matches = observed.get('packages', {}).get(name, [])
        if colon:
            matches = matches + observed.get('packages', {}).get(package, [])
            matches = [p for p in matches if p.get('arch') == arch]
        if separator:
            matches = [p for p in matches if p.get('version') == version]
        if not matches:
            errors.append('package absent or version/architecture differs: ' + wanted)
    for wanted in desired.get('services', []):
        name = wanted['name']
        actual = observed.get('services', {}).get(name) or observed.get('services', {}).get(name + '.service')
        if not actual:
            errors.append('missing service ' + name)
            continue
        if wanted.get('enabled') is True and actual.get('status') != 'enabled':
            errors.append('service enabled state differs: ' + name)
        elif wanted.get('enabled') is False and actual.get('status') not in ('disabled', 'masked'):
            errors.append('service disabled state differs: ' + name)
        if 'state' in wanted:
            expected = 'running' if wanted['state'] == 'started' else 'stopped'
            if actual.get('state') != expected:
                errors.append('service runtime state differs: ' + name)
    for wanted in desired.get('files', []):
        actual = observed.get('files', {}).get(wanted['path'], {})
        if not actual.get('isreg'):
            errors.append('missing regular configuration file ' + wanted['path'])
            continue
        if actual.get('checksum') != wanted['checksum_sha256']:
            errors.append('configuration checksum differs: ' + wanted['path'])
        if str(actual.get('mode', '')).lstrip('0') != str(wanted['mode']).lstrip('0'):
            errors.append('configuration mode differs: ' + wanted['path'])
        for field in ('owner', 'group'):
            if field in wanted:
                observed_name = actual.get('pw_name' if field == 'owner' else 'gr_name')
                observed_id = actual.get('uid' if field == 'owner' else 'gid')
                if str(wanted[field]) not in (str(observed_name), str(observed_id)):
                    errors.append('configuration ' + field + ' differs: ' + wanted['path'])
    return errors


class FilterModule:
    def filters(self):
        return {'guest_state_errors': guest_state_errors}
