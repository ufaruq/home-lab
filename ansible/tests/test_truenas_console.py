import importlib.util
from pathlib import Path
import unittest
import subprocess
import sys
import random

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('truenas_console', ROOT/'monitoring/truenas/console.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ConsoleTests(unittest.TestCase):
    def test_shift_uppercase_and_punctuation(self):
        self.assertEqual(module.key_events('A'), [(0xffe1,1),(ord('A'),1),(ord('A'),0),(0xffe1,0)])
        self.assertEqual(module.key_events('|')[1][0], ord('|'))
        self.assertEqual(module.key_events('+')[1][0], ord('+'))
    def test_rejects_control_and_unicode(self):
        for c in ('\x00','\x1b','é'):
            with self.assertRaises(ValueError): module.key_events(c)
    def test_command_bounded_public_script(self):
        command = module.console_command('print("ok")')
        self.assertLess(len(command), 4000)
        self.assertNotIn('print', command)
    def test_long_public_program_uses_quoted_bounded_lines_and_roundtrips(self):
        data = ''.join(random.Random(9).choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6000))
        command = module.console_command('print(' + repr(data) + ')')
        self.assertIn("<<'HOMELAB_BOOTSTRAP'", command)
        self.assertLess(max(map(len, command.splitlines())), 3900)
        self.assertLessEqual(len(command), 16000)
        # Running the generated local shell decoder has no network or mutation.
        result = subprocess.run(['/bin/sh'], input=command, text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout.strip(), data)
    def test_reply_identity_fail_closed(self):
        expected = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        reply={'uid':0,'uuid':expected,'version':module.VERSION}
        module.verify_identity(reply, expected)
        for key, value in [('uid',1),('uuid','other'),('version','TrueNAS-SCALE-25.10')]:
            bad=dict(reply);bad[key]=value
            with self.assertRaises(ValueError): module.verify_identity(bad,expected)

if __name__ == '__main__': unittest.main()
