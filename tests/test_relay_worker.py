import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from printerhmi_agent.relay_transport import RelayConfig, RelayTransportError
from printerhmi_agent.relay_worker import RelayWorker


ROOT = Path(__file__).resolve().parents[1]


class FakeConnector:
    def __init__(self):
        self.snapshots = []

    async def send_with_retries(self, snapshot, attempts=3):
        self.snapshots.append(snapshot)
        return {"relay_id": "relay-test", "sequence": 1, "session_id": "session"}


class RelayWorkerTests(unittest.TestCase):
    def config(self, ca_file: Path, enabled=True):
        return RelayConfig(
            enabled=enabled,
            relay_id="relay-test",
            host="relay.invalid",
            port=443,
            server_name="relay.invalid",
            ca_file=ca_file,
        )

    def test_worker_consumes_only_local_api_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connector = FakeConnector()
            worker = RelayWorker(
                self.config(root / "ca.pem"),
                root / "agent.sock",
                root / "relay-worker.json",
                connector,
            )
            snapshot = {"schema_version": 1, "generated_at": "now", "instances": {}}
            response = {"ok": True, "result": snapshot}
            with patch(
                "printerhmi_agent.relay_worker.api_request",
                new=AsyncMock(return_value=response),
            ) as request:
                asyncio.run(worker.run_once())
            request.assert_awaited_once_with(root / "agent.sock", "snapshot")
            self.assertEqual(connector.snapshots, [snapshot])

    def test_state_is_private_and_contains_no_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = RelayWorker(
                self.config(root / "ca.pem"),
                root / "agent.sock",
                root / "relay-worker.json",
                FakeConnector(),
            )
            worker.success_count = 1
            worker.write_state("connected", {"sequence": 1})
            document = json.loads(worker.state_path.read_text())
            self.assertEqual(os.stat(worker.state_path).st_mode & 0o777, 0o600)
            self.assertNotIn("snapshot", document)
            self.assertNotIn("instances", document)
            self.assertEqual(document["last_sequence"], 1)

    def test_disabled_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RelayTransportError, "disabled"):
                RelayWorker(
                    self.config(root / "ca.pem", enabled=False),
                    root / "agent.sock",
                    root / "state.json",
                    FakeConnector(),
                )

    def test_service_boundaries_and_explicit_install(self):
        monitor = (ROOT / "packaging/systemd/printerhmi-remote.service.in").read_text()
        relay = (ROOT / "packaging/systemd/printerhmi-remote-relay.service.in").read_text()
        installer = (ROOT / "install-relay-service.sh").read_text()
        base_installer = (ROOT / "install-service.sh").read_text()
        self.assertIn("PrivateNetwork=true", monitor)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", monitor)
        self.assertNotIn("PrivateNetwork=true", relay)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", relay)
        self.assertIn("--enable-network", installer)
        self.assertIn("--config", installer)
        self.assertNotIn("install-relay-service", base_installer)
        self.assertNotIn("moonraker.sock", relay)


if __name__ == "__main__":
    unittest.main()
