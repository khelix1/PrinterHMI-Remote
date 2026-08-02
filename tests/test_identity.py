import unittest
from pathlib import Path

from printerhmi_agent.identity import instance_identity


class IdentityTests(unittest.TestCase):
    def test_identity_is_stable_and_instance_specific(self):
        first = instance_identity(Path("/tmp/one.sock"), "host-a")
        self.assertEqual(first, instance_identity(Path("/tmp/one.sock"), "host-a"))
        self.assertNotEqual(first, instance_identity(Path("/tmp/two.sock"), "host-a"))
        self.assertNotEqual(first, instance_identity(Path("/tmp/one.sock"), "host-b"))


if __name__ == "__main__":
    unittest.main()
