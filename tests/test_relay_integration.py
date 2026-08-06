import asyncio
import tempfile
import unittest
from pathlib import Path

from printerhmi_agent.relay_integration import (
    RelayIntegrationError,
    _assert_disposable_workspace,
    run_relay_integration,
)


ROOT = Path(__file__).resolve().parents[1]


class RelayIntegrationTests(unittest.TestCase):
    def test_complete_loopback_pipeline_without_stale_delay(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "integration"
            try:
                result = asyncio.run(
                    run_relay_integration(workspace, verify_stale=False)
                )
            except PermissionError:
                self.skipTest("Unix sockets are denied by this test sandbox")
            self.assertTrue(result["passed"])
            self.assertTrue(result["loopback_only"])
            self.assertTrue(result["outage_observed"])
            self.assertTrue(result["reconnect_observed"])
            self.assertTrue(result["privacy_filter_verified"])
            self.assertTrue(result["control_surface_absent"])
            self.assertEqual(result["enrolled_device_count"], 2)
            self.assertEqual(result["published_device_count"], 1)
            self.assertGreaterEqual(result["worker_success_count"], 3)
            self.assertGreaterEqual(result["worker_failure_count"], 1)

    def test_production_state_directory_is_rejected(self):
        production = Path.home() / ".local/state/printerhmi-remote/integration"
        with self.assertRaisesRegex(RelayIntegrationError, "production"):
            _assert_disposable_workspace(production)

    def test_harness_has_no_service_or_moonraker_authority(self):
        source = (
            ROOT / "src/printerhmi_agent/relay_integration.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("systemctl", source)
        self.assertNotIn("discover_socket_paths", source)
        self.assertNotIn("run_service", source)
        self.assertNotIn("0.0.0.0", source)


if __name__ == "__main__":
    unittest.main()
