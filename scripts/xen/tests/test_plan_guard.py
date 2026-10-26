import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "plan_guard.py"
VM = "00000000-0000-0000-0000-000000000001"
DISKLESS = "00000000-0000-0000-0000-000000000002"
NETWORK = "00000000-0000-0000-0000-000000000003"
SR = "00000000-0000-0000-0000-000000000004"
VM_ADDRESS = f'xenorchestra_vm.existing["{VM}"]'
NETWORK_ADDRESS = f'xenorchestra_network.existing["{NETWORK}"]'


def fixture():
    inventory = {
        "schema_version": 1,
        "vms": {
            VM: {"uuid": VM, "disks": [{"vdi": {"name_label": "root", "sr_uuid": SR}}]},
            DISKLESS: {"uuid": DISKLESS, "disks": []},
        },
        "networks": {NETWORK: {"uuid": NETWORK, "other_config": {}}},
        "storage_repositories": {SR: {"type": "ext"}},
    }
    targets = {VM_ADDRESS: VM, NETWORK_ADDRESS: NETWORK}
    plan = {
        "format_version": "1.2",
        "errored": False,
        "planned_values": {
            "outputs": {"adoption_targets": {"value": targets}},
            "root_module": {
                "resources": [
                    {"address": address, "mode": "managed", "values": {"id": resource_id}}
                    for address, resource_id in targets.items()
                ]
            },
        },
        "resource_changes": [
            {"address": address, "mode": "managed", "change": {
                "actions": ["no-op"], "after": {"id": resource_id},
                "importing": {"id": resource_id},
            }}
            for address, resource_id in targets.items()
        ],
    }
    return inventory, plan


class AdoptionPlanGuardTests(unittest.TestCase):
    def run_guard(self, inventory, plan):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "inventory.json").write_text(json.dumps(inventory))
            (root / "plan.json").write_text(json.dumps(plan))
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--inventory", str(root / "inventory.json"), str(root / "plan.json")],
                text=True, capture_output=True,
            )

    def test_import_only_plan_matches_existing_identifiers(self):
        inventory, plan = fixture()
        result = self.run_guard(inventory, plan)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 existing resource bindings", result.stdout)

    def test_nested_disk_update_cannot_pass_adoption_gate(self):
        inventory, plan = fixture()
        plan["resource_changes"][0]["change"].update(
            actions=["update"], before={"disk": [{"size": 100}]}, after={"disk": [{"size": 50}]},
        )
        result = self.run_guard(inventory, plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("write action", result.stderr)
        self.assertIn("write action", result.stderr)

    def test_missing_vm_is_not_implicitly_recreated(self):
        inventory, plan = fixture()
        plan["resource_changes"][0]["change"] = {"actions": ["create"], "after": {"name_label": "replacement"}}
        result = self.run_guard(inventory, plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("write action", result.stderr)

    def test_replacement_is_rejected_even_with_import_metadata(self):
        inventory, plan = fixture()
        plan["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        result = self.run_guard(inventory, plan)
        self.assertNotEqual(result.returncode, 0)

    def test_import_cannot_bind_the_wrong_existing_vm(self):
        inventory, plan = fixture()
        plan["resource_changes"][0]["change"]["importing"]["id"] = DISKLESS
        result = self.run_guard(inventory, plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity", result.stderr)

    def test_missing_managed_binding_is_rejected(self):
        inventory, plan = fixture()
        del plan["planned_values"]["outputs"]["adoption_targets"]["value"][VM_ADDRESS]
        result = self.run_guard(inventory, plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coverage", result.stderr)

    def test_unrelated_cloud_resource_is_rejected(self):
        inventory, plan = fixture()
        plan["resource_changes"].append({
            "address": "oci_core_instance.unrelated", "mode": "managed",
            "change": {"actions": ["no-op"], "after": {"id": "cloud-instance"}},
        })
        result = self.run_guard(inventory, plan)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside", result.stderr)

    def test_read_only_data_lookup_is_allowed(self):
        inventory, plan = fixture()
        plan["resource_changes"].append({
            "address": "data.xenorchestra_pool.current", "mode": "data",
            "change": {"actions": ["read"]},
        })
        result = self.run_guard(inventory, plan)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_incomplete_or_errored_plan_is_rejected(self):
        for patch in ({"errored": True}, {"complete": False}, {"deferred_changes": [{"reason": "unknown"}]}):
            with self.subTest(patch=patch):
                inventory, plan = fixture()
                plan.update(patch)
                result = self.run_guard(inventory, plan)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Adoption rejected:", result.stderr)


if __name__ == "__main__":
    unittest.main()
