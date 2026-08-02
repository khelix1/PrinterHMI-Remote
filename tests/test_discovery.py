import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from printerhmi_agent.discovery import discover_socket_paths


class DiscoveryTests(unittest.TestCase):
    def test_explicit_socket_is_discovered_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "moonraker.sock"
            with patch(
                "printerhmi_agent.discovery._is_socket",
                return_value=True,
            ):
                found = discover_socket_paths(explicit=[path, path])
                self.assertEqual(found, [path.resolve()])

    def test_environment_paths_are_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "moonraker.sock"
            with patch.dict(
                os.environ,
                {"PRINTERHMI_MOONRAKER_SOCKETS": str(path)},
                clear=False,
            ), patch(
                "printerhmi_agent.discovery._is_socket",
                return_value=True,
            ):
                    self.assertEqual(
                        discover_socket_paths(home=Path(directory)),
                        [path.resolve()],
                    )


if __name__ == "__main__":
    unittest.main()
