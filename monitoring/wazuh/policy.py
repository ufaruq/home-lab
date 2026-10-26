"""Small shared, offline policy checks; no credentials or host contact."""
import re


def require_approval(access, approved):
    if access is not True or approved is not True:
        raise ValueError('Verified access and explicit deployment approval must both be boolean true')


def validate_versions(manager, agent):
    def version(value):
        if not isinstance(value, str) or not re.fullmatch(r'4\.\d+\.\d+', value):
            raise ValueError('Explicit Wazuh 4.x.y release required')
        return tuple(map(int, value.split('.')))
    server, endpoint = version(manager), version(agent)
    if endpoint > server or endpoint[:2] != server[:2]:
        raise ValueError('Use an agent from the same minor release, no newer than its manager')


def validate_retention(value):
    policy = value['policy']
    if policy['ism_template'] != [{'index_patterns': ['wazuh-alerts-4.x-*'], 'priority': 100}]:
        raise ValueError('Retention may target only Wazuh alert indices')
    if policy['default_state'] != 'retain' or policy['states'] != [
        {'name': 'retain', 'actions': [], 'transitions': [{'state_name': 'delete', 'conditions': {'min_index_age': '7d'}}]},
        {'name': 'delete', 'actions': [{'delete': {}}], 'transitions': []},
    ]:
        raise ValueError('Only reviewed seven-day retention is supported')
