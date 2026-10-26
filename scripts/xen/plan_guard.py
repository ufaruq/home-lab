#!/usr/bin/env python3
"""Allow only identity-checked state adoption of the observed Xen fleet.

This gate deliberately permits no infrastructure writes. In particular, VM
prevent_destroy does not protect nested disk updates; this gate rejects those
updates as well as creation, replacement, and deletion.
"""

import argparse
import json
from pathlib import Path
import sys


def expected_targets(inventory):
    if inventory.get("schema_version") != 1 or not inventory.get("vms"):
        raise ValueError("unsupported or empty inventory")
    targets = {}
    repositories = inventory["storage_repositories"]
    for vm_id, vm in inventory["vms"].items():
        if vm.get("uuid") != vm_id:
            raise ValueError("inventory VM identity does not match its key")
        disks = [d for d in vm["disks"] if d["vdi"].get("name_label") != "XO CloudConfigDrive"]
        if not disks:
            continue  # These definitions have explicit Ansible/XenAPI ownership.
        protected = any(repositories[d["vdi"]["sr_uuid"]]["type"] == "udev" for d in disks)
        resource = "protected" if protected else "existing"
        targets[f'xenorchestra_vm.{resource}[{json.dumps(vm_id)}]'] = vm_id
    for network_id, network in inventory["networks"].items():
        if network.get("uuid") != network_id:
            raise ValueError("inventory network identity does not match its key")
        internal = network.get("other_config", {}).get("is_host_internal_management_network")
        if str(internal).lower() == "true":
            continue  # Platform-owned internal network, retained in coverage.
        targets[f'xenorchestra_network.existing[{json.dumps(network_id)}]'] = network_id
    return targets


def resources(module):
    result = list(module.get("resources", []))
    for child in module.get("child_modules", []):
        result.extend(resources(child))
    return result


def verify(plan, inventory):
    if not str(plan.get("format_version", "")).startswith("1."):
        raise ValueError("unsupported Terraform plan JSON format")
    if plan.get("errored") or plan.get("complete") is False or plan.get("deferred_changes"):
        raise ValueError("incomplete or errored plan cannot be adopted")
    expected = expected_targets(inventory)
    values = plan.get("planned_values", {})
    declared = values.get("outputs", {}).get("adoption_targets", {}).get("value")
    if declared != expected:
        raise ValueError("adoption coverage does not match the complete observed fleet")

    changes = {}
    for item in plan.get("resource_changes", []):
        address = item["address"]
        change = item["change"]
        actions = change.get("actions", [])
        if not actions or any(action not in ("no-op", "read") for action in actions):
            raise ValueError(f"write action {actions} rejected for {address}")
        if item.get("mode", "managed") == "data":
            continue
        if address not in expected:
            raise ValueError(f"resource outside the Xen adoption boundary: {address}")
        if actions != ["no-op"]:
            raise ValueError(f"managed resource has an invalid adoption action: {address}")
        importing = change.get("importing") or item.get("importing")
        if importing and importing.get("id") != expected[address]:
            raise ValueError(f"import identity mismatch for {address}")
        changes[address] = change

    actual = {}
    for item in resources(values.get("root_module", {})):
        if item.get("mode", "managed") == "data":
            continue
        address = item["address"]
        if address not in expected:
            raise ValueError(f"planned resource outside the Xen adoption boundary: {address}")
        if address in actual:
            raise ValueError(f"duplicate resource identity: {address}")
        actual[address] = item.get("values", {})
    if set(actual) != set(expected):
        raise ValueError("planned resource coverage is incomplete")
    for address, resource_id in expected.items():
        observed_id = actual[address].get("id")
        change = changes.get(address, {})
        importing = change.get("importing", {})
        after_id = (change.get("after") or {}).get("id")
        if observed_id is not None and observed_id != resource_id:
            raise ValueError(f"planned resource identity mismatch for {address}")
        if after_id is not None and after_id != resource_id:
            raise ValueError(f"resulting resource identity mismatch for {address}")
        if observed_id is None and importing.get("id") != resource_id:
            raise ValueError(f"existing resource identity is not established for {address}")
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("plan_json", type=Path)
    args = parser.parse_args()
    try:
        count = verify(json.loads(args.plan_json.read_text()), json.loads(args.inventory.read_text()))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"Adoption rejected: {error}", file=sys.stderr)
        return 2
    print(f"Adoption plan verified: {count} existing resource bindings; no infrastructure writes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
