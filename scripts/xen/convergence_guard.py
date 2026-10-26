#!/usr/bin/env python3
"""Verify a bounded, non-destructive Xen Terraform convergence plan."""
import argparse
import copy
import json
from pathlib import Path
import sys
import uuid

from plan_guard import expected_targets, resources

VM_MUTABLE = {'cpus', 'memory_min', 'memory_max', 'power_state'}
READ_FIELDS = {'ipv4_addresses', 'ipv6_addresses', 'sockets'}
NESTED_READ_FIELDS = {'network': {'ipv4_addresses', 'ipv6_addresses'}}
VM_FIELDS = set('affinity_host auto_poweron blocked_operations clone_type cloud_config cloud_network_config core_os cores_per_socket cpu_cap cpu_weight cpus destroy_cloud_config_vdi_after_boot exp_nested_hvm high_availability host hvm_boot_firmware id installation_method ipv4_addresses ipv6_addresses memory_max memory_min name_description name_label power_state resource_set secure_boot share sockets start_delay tags template vga videoram xenstore cdrom disk network timeouts'.split())
NETWORK_FIELDS = set('automatic default_is_locked id mtu name_description name_label nbd pool_id source_pif_device vlan'.split())
CREATE_COMPUTED = {'disk': {'position', 'vbd_id', 'vdi_id'}, 'network': {'device', 'ipv4_addresses', 'ipv6_addresses'}}


def fail(message):
    raise ValueError(message)


def identifier(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def integer(value, label):
    if type(value) is not int or value <= 0:
        fail(f'{label} must be a positive integer')
    return value


def desired(vm, settings):
    result = {}
    for key, observed in [('cpus', 'VCPUs_at_startup'), ('memory_min', 'memory_dynamic_min'), ('memory_max', 'memory_dynamic_max')]:
        if key in settings:
            result[key] = integer(settings[key], key)
        elif observed in vm:
            result[key] = integer(int(vm[observed]), key)
    result['power_state'] = settings.get('power_state', vm.get('power_state', 'Halted'))
    if result['power_state'] not in ('Halted', 'Running'):
        fail('power_state must be Halted or Running')
    if result['power_state'] == 'Running' and settings.get('power_state') != 'Running':
        fail('Running requires explicit policy authorization')
    if 'auto_poweron' in settings:
        if type(settings['auto_poweron']) is not bool:
            fail('auto_poweron must be a boolean')
        result['auto_poweron'] = settings['auto_poweron']
    elif 'auto_poweron' in vm.get('other_config', {}):
        observed = vm['other_config']['auto_poweron']
        if type(observed) is bool:
            result['auto_poweron'] = observed
        elif isinstance(observed, str) and observed.lower() in ('true', 'false'):
            result['auto_poweron'] = observed.lower() == 'true'
        else:
            fail('unsupported observed auto_poweron value')
    if result.get('auto_poweron') is True and result['power_state'] != 'Running':
        fail('auto_poweron true requires desired Running state')
    if result.get('memory_min', 0) > result.get('memory_max', float('inf')):
        fail('memory_min exceeds memory_max')
    return result


def validate_inputs(inventory, policy, bindings):
    if policy.get('schema_version') != 1 or bindings.get('schema_version') != 1:
        fail('unsupported policy or bindings schema')
    if set(policy) - {'schema_version', 'vms', 'networks', 'guest_targets'}:
        fail('unknown policy setting')
    for kind in ('vms', 'networks'):
        if not isinstance(policy.get(kind, {}), dict):
            fail(f'{kind} policy must be an object')
        if set(policy.get(kind, {})) - set(inventory[kind]):
            fail(f'unknown {kind} policy identity')
    for logical, settings in policy.get('vms', {}).items():
        if not isinstance(settings, dict) or set(settings) - (VM_MUTABLE | {'auto_poweron', 'recovery'}):
            fail('unknown VM policy setting')
        desired(inventory['vms'][logical], settings)
        if 'recovery' in settings:
            recipe = settings['recovery']
            if not isinstance(recipe, dict) or set(recipe) != {'template_id', 'verified'} or not identifier(recipe['template_id']) or type(recipe['verified']) is not bool:
                fail('invalid VM recovery recipe')
    if any(settings != {} for settings in policy.get('networks', {}).values()):
        fail('network policy updates are unsupported')
    guest_targets = policy.get('guest_targets', [])
    if not isinstance(guest_targets, list) or any(not isinstance(v, str) or not v for v in guest_targets) or len(guest_targets) != len(set(guest_targets)):
        fail('unknown guest target')
    for key, kind in [('existing_vm_ids', 'vms'), ('existing_network_ids', 'networks')]:
        mapping = bindings.get(key)
        if not isinstance(mapping, dict) or set(mapping) - set(inventory[kind]):
            fail('invalid current identity bindings')
        if not all(identifier(v) for v in mapping.values()) or len(set(mapping.values())) != len(mapping):
            fail('invalid or duplicate current resource identity')
    templates = bindings.get('available_template_ids')
    if not isinstance(templates, list) or not all(identifier(v) for v in templates):
        fail('invalid available template identities')


def check_unknown(tree, vm, creating, path=()):
    if tree is True:
        top = path[0] if path else None
        if (vm and top in READ_FIELDS) or (top == 'id' and creating):
            return
        if vm and len(path) == 3 and path[2] in NESTED_READ_FIELDS.get(top, set()):
            return
        if vm and creating and len(path) == 3 and path[2] in CREATE_COMPUTED.get(top, set()):
            return
        fail(f'unknown configured value at {path}')
    if isinstance(tree, dict):
        for key, value in tree.items():
            check_unknown(value, vm, creating, path + (key,))
    elif isinstance(tree, list):
        for index, value in enumerate(tree):
            check_unknown(value, vm, creating, path + (index,))
    elif tree not in (None, False):
        fail('invalid after_unknown structure')


def normalized(value, creating=False):
    result = copy.deepcopy(value)
    for key in READ_FIELDS:
        result.pop(key, None)
    for block, fields in NESTED_READ_FIELDS.items():
        for item in result.get(block) or []:
            for field in fields:
                item.pop(field, None)
    if creating:
        result.pop('id', None)
        for block, fields in CREATE_COMPUTED.items():
            for item in result.get(block) or []:
                for field in fields:
                    item.pop(field, None)
    return result


def check_existing(change, after, current, is_vm, target, settings):
    importing = change.get('importing')
    if importing and importing.get('id') != current:
        fail('import identity does not match current binding')
    if after.get('id') != current:
        fail('result identity does not match current binding')
    before = change.get('before')
    if before is None:
        if not importing or change['actions'] != ['no-op']:
            fail('before state required for existing resource')
    else:
        if before.get('id') != current:
            fail('before identity does not match current binding')
        left, right = normalized(before), normalized(after)
        if is_vm:
            if 'auto_poweron' in settings and after.get('auto_poweron') is target['auto_poweron']:
                left.pop('auto_poweron', None); right.pop('auto_poweron', None)
            for field in VM_MUTABLE:
                left.pop(field, None); right.pop(field, None)
            if settings.get('power_state') == 'Running' and after.get('power_state') == 'Running':
                for block in ('disk', 'network'):
                    old, new = left.get(block) or [], right.get(block) or []
                    if len(old) != len(new):
                        fail('attachment resource count changed')
                    for old_item, new_item in zip(old, new):
                        if old_item.get('attached') is False and new_item.get('attached') is True:
                            old_item['attached'] = True
        if left != right:
            fail('change outside CPU/RAM/power/authorized attachment boundary')
        if change['actions'] == ['no-op'] and normalized(before) != normalized(after):
            fail('mutation disguised as no-op')
    if not is_vm and change['actions'] != ['no-op']:
        fail('network updates are forbidden')
    if is_vm:
        for field, value in target.items():
            if (field == 'auto_poweron' and after.get(field) is not value) or after.get(field) != value:
                fail(f'{field} does not match desired policy/baseline')


def check_vm_shape(after, vm, inventory, bindings):
    if after.get('name_label') != vm.get('name_label'):
        fail('recovery VM name differs from original ownership target')
    for field in ('cloud_config', 'cloud_network_config'):
        if after.get(field) not in (None, ''):
            fail('cloudconfig is forbidden in VM recovery')
    expected = [d for d in vm['disks'] if d['vdi'].get('name_label') != 'XO CloudConfigDrive']
    disks = after.get('disk') or []
    if len(disks) != len(expected):
        fail('recovery disk coverage differs')
    for disk, original in zip(disks, sorted(expected, key=lambda d: int(d.get('userdevice', 0)))):
        vdi = original['vdi']; sr = vdi['sr_uuid']
        if inventory['storage_repositories'][sr]['type'] not in ('ext', 'lvm'):
            fail('raw or unsupported SR cannot be provisioned')
        for field, wanted in [('sr_id', sr), ('size', int(vdi['virtual_size'])), ('name_label', vdi['name_label'])]:
            if disk.get(field) != wanted:
                fail(f'recovery disk {field} differs from inventory')
        if disk.get('name_label') == 'XO CloudConfigDrive':
            fail('cloudconfig disk creation is forbidden')
    interfaces = after.get('network') or []
    expected_nics = sorted(vm.get('vifs', []), key=lambda n: int(n['device']))
    if len(interfaces) != len(expected_nics):
        fail('recovery NIC coverage differs')
    for nic, original in zip(interfaces, expected_nics):
        current = bindings['existing_network_ids'].get(original['network_uuid'])
        if not current or nic.get('network_id') != current or nic.get('mac_address') != original['MAC']:
            fail('recovery NIC identity differs or network is unavailable')


def check_network_create(after, network_id, inventory):
    network = inventory['networks'][network_id]
    if 'pifs' not in inventory and 'pif_uuids' not in network:
        fail('PIF inventory evidence required for isolated network creation')
    if network.get('pif_uuids') or any(p.get('network_uuid') == network_id for p in inventory.get('pifs', {}).values()):
        fail('PIF-backed network cannot be recreated')
    if after.get('source_pif_device') not in (None, '') or after.get('vlan') not in (None, -1, 0):
        fail('only isolated network creation is permitted')
    for field, original in [('name_label', network.get('name_label')), ('name_description', network.get('name_description', '')), ('mtu', int(network.get('MTU', 1500)))]:
        if original is not None and after.get(field, '' if field == 'name_description' else None) != original:
            fail(f'new network {field} differs from inventory')
    booleans = {'automatic': str(network.get('other_config', {}).get('automatic', 'false')).lower() == 'true', 'default_is_locked': network.get('default_locking_mode') == 'locked', 'nbd': any(p in ('nbd', 'insecure_nbd') for p in network.get('purpose', []))}
    for key, expected in booleans.items():
        if after.get(key, expected) is not expected:
            fail(f'new network {key} differs from inventory')
    pools = inventory.get('pools', {})
    if len(pools) == 1 and after.get('pool_id') != next(iter(pools)):
        fail('network pool differs from inventory')


def verify(plan, inventory, policy, bindings):
    if not str(plan.get('format_version', '')).startswith('1.') or plan.get('errored') or plan.get('complete') is False or plan.get('deferred_changes'):
        fail('unsupported, incomplete or errored plan')
    expected = expected_targets(inventory)
    validate_inputs(inventory, policy, bindings)
    values = plan.get('planned_values', {})
    if values.get('outputs', {}).get('adoption_targets', {}).get('value') != expected:
        fail('ownership coverage does not match original fleet')
    changes = {}
    for item in plan.get('resource_changes', []):
        address = item['address']; change = copy.deepcopy(item['change'])
        actions = change.get('actions')
        if item.get('mode', 'managed') == 'data':
            if not address.startswith('data.xenorchestra_') or actions not in (['read'], ['no-op']):
                fail('external or mutating data resource rejected')
            continue
        if address not in expected or address in changes:
            fail('resource outside ownership boundary or duplicate resource')
        if actions not in (['no-op'], ['update'], ['create']):
            fail('delete, replace, forget or unknown action forbidden')
        if item.get('importing'):
            if change.get('importing') and change['importing'] != item['importing']:
                fail('conflicting import identity')
            change['importing'] = item['importing']
        changes[address] = change
    actual = {}
    for item in resources(values.get('root_module', {})):
        if item.get('mode', 'managed') == 'data':
            if not item['address'].startswith('data.xenorchestra_'):
                fail('external data resource rejected')
            continue
        address = item['address']
        if address not in expected or address in actual:
            fail('unexpected or duplicate planned resource')
        actual[address] = item.get('values', {})
    if set(actual) != set(expected) or set(changes) != set(expected):
        fail('managed resource coverage incomplete')
    for address, logical in expected.items():
        vm = address.startswith('xenorchestra_vm.'); change = changes[address]; creating = change['actions'] == ['create']; after = change.get('after')
        if not isinstance(after, dict):
            fail('known resource result required')
        check_unknown(change.get('after_unknown', {}), vm, creating)
        if normalized(actual[address], creating=creating) != normalized(after, creating=creating):
            fail('planned values differ from change result')
        if vm and 'auto_poweron' in after and type(after['auto_poweron']) is not bool:
            fail('planned auto_poweron must be a boolean')
        mapping = bindings['existing_vm_ids' if vm else 'existing_network_ids']; current = mapping.get(logical)
        settings = policy.get('vms', {}).get(logical, {}) if vm else {}
        target = desired(inventory['vms'][logical], settings) if vm else {}
        if vm and after.get('auto_poweron') is True and target['power_state'] != 'Running':
            fail('auto_poweron true requires desired Running state')
        if not creating:
            if current is None:
                fail('missing resource cannot be treated as existing')
            check_existing(change, after, current, vm, target, settings)
            continue
        if current is not None or change.get('before') is not None or change.get('importing') or after.get('id') is not None or actual[address].get('id') is not None:
            fail('creation requires genuinely missing, unbound identity and no import')
        if set(after) - (VM_FIELDS if vm else NETWORK_FIELDS):
            fail('unknown provider setting in resource creation')
        if change.get('after_unknown', {}).get('id') is not True:
            fail('new resource identity must be unknown until creation')
        if vm:
            if address.startswith('xenorchestra_vm.protected[') or any(inventory['storage_repositories'][d['vdi']['sr_uuid']]['type'] == 'udev' for d in inventory['vms'][logical]['disks']):
                fail('protected/raw VM recovery forbidden')
            original_vm = inventory['vms'][logical]
            if any(original_vm.get(field) for field in ('attached_pci_uuids', 'vgpu_uuids', 'vusb_uuids')) or original_vm.get('other_config', {}).get('pci'):
                fail('VM recovery cannot restore PCI/vGPU/USB passthrough devices')
            recipe = settings.get('recovery', {})
            if recipe.get('verified') is not True or recipe.get('template_id') not in bindings['available_template_ids'] or after.get('template') != recipe.get('template_id'):
                fail('VM recovery requires verified, available, exact template')
            for field, value in target.items():
                if (field == 'auto_poweron' and after.get(field) is not value) or after.get(field) != value:
                    fail(f'recovered {field} differs from desired policy/baseline')
            check_vm_shape(after, inventory['vms'][logical], inventory, bindings)
        else:
            check_network_create(after, logical, inventory)
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'policy', 'bindings'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('plan_json', type=Path)
    args = parser.parse_args()
    try:
        count = verify(json.loads(args.plan_json.read_text()), json.loads(args.inventory.read_text()), json.loads(args.policy.read_text()), json.loads(args.bindings.read_text()))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'Convergence rejected: {error}', file=sys.stderr)
        return 2
    print(f'Convergence plan verified: {count} ownership targets; no deletion or replacement.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
