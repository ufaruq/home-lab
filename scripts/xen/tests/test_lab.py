import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_plan_guard import fixture


SCRIPT = Path(__file__).resolve().parents[1] / "lab.py"


class AdoptionRunnerTests(unittest.TestCase):
    def exercise(self, write_action=False, public_plan=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, plan = fixture()
            if write_action:
                plan["resource_changes"][0]["change"]["actions"] = ["update"]
            source = root / "inventory.json"
            source.write_text(json.dumps(inventory))
            saved = root / "reviewed.tfplan"
            saved.write_text(json.dumps(plan))
            saved.chmod(0o644 if public_plan else 0o600)
            log = root / "calls.jsonl"
            terraform = root / "terraform"
            terraform.write_text(
                "#!" + sys.executable + "\n"
                "import json,os,pathlib,sys\n"
                "with open(os.environ['TEST_TERRAFORM_LOG'],'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "if 'show' in sys.argv: print(pathlib.Path(sys.argv[-1]).read_text())\n"
            )
            terraform.chmod(0o700)
            env = dict(os.environ, TERRAFORM_BIN=str(terraform), TEST_TERRAFORM_LOG=str(log))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--inventory", str(source), "--policy", str(SCRIPT.parents[2]/"tests/fixtures/xen/policy.json"), "adopt", "--plan", str(saved)],
                env=env, text=True, capture_output=True,
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls, str(saved)

    def test_rejected_plan_never_reaches_terraform_apply(self):
        result, calls, _ = self.exercise(write_action=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("write action", result.stderr)
        self.assertFalse(any("apply" in call for call in calls))

    def test_verified_import_plan_applies_only_the_reviewed_file(self):
        result, calls, saved = self.exercise()
        self.assertEqual(result.returncode, 0, result.stderr)
        apply_calls = [call for call in calls if "apply" in call]
        self.assertEqual(len(apply_calls), 1)
        self.assertEqual(Path(apply_calls[0][-1]).resolve(), Path(saved).resolve())
        self.assertNotIn("-auto-approve", apply_calls[0])
        self.assertTrue(apply_calls[0][0].endswith("/infra/xen/vms"))

    def test_publicly_readable_plan_is_rejected_before_reading(self):
        result, calls, _ = self.exercise(public_plan=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("permissions", result.stderr)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
