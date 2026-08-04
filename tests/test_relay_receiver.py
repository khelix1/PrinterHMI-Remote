import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from printerhmi_agent.enrollment import EnrollmentStore
from printerhmi_agent.relay_receiver import (
    RelayReceiver,
    RelayReceiverConfig,
    RelayReceiverError,
    receiver_api_request,
)
from printerhmi_agent.relay_registry import RelaySnapshotRegistry
from printerhmi_agent.relay_transport import RelayConfig, RelayConnector
from test_relay_transport import make_certificates, snapshot_document


ROOT = Path(__file__).resolve().parents[1]


class RelayReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def receiver_config(self, cert, key, store, port=0):
        identity = store.identity()
        return RelayReceiverConfig(
            enabled=True,
            relay_id="local-relay",
            listen_host="127.0.0.1",
            listen_port=port,
            api_socket=self.directory / "receiver.sock",
            state_file=self.directory / "receiver-state.json",
            cert_file=cert,
            key_file=key,
            stale_after=30.0,
            devices={identity["device_id"]: identity["public_key"]},
        )

    def connector_config(self, ca, port):
        return RelayConfig(
            enabled=True,
            relay_id="local-relay",
            host="127.0.0.1",
            port=port,
            server_name="localhost",
            ca_file=ca,
            connect_timeout=2.0,
        )

    def test_end_to_end_receiver_stores_latest_sanitized_snapshot(self):
        async def exercise():
            ca, cert, key = make_certificates(self.directory)
            enrollment = EnrollmentStore(self.directory / "enrollment")
            receiver = RelayReceiver(
                self.receiver_config(cert, key, enrollment), start_api=False
            )
            await receiver.start()
            try:
                port = receiver.server.sockets[0].getsockname()[1]
                result = await RelayConnector(
                    self.connector_config(ca, port), enrollment
                ).send_snapshot(snapshot_document())
                self.assertEqual(result["sequence"], 1)
                stored = await receiver.registry.snapshot(
                    enrollment.identity()["device_id"]
                )
                serialized = json.dumps(stored)
                self.assertNotIn("socket_path", serialized)
                self.assertNotIn("filename", serialized)
                self.assertIn('"progress": 0.5', serialized)
                self.assertEqual(receiver.errors, 0)
                self.assertEqual(
                    os.stat(receiver.config.state_file).st_mode & 0o777,
                    0o600,
                )
            finally:
                await receiver.close()
        asyncio.run(exercise())

    def test_receiver_rejects_unenrolled_device(self):
        async def exercise():
            ca, cert, key = make_certificates(self.directory)
            enrolled = EnrollmentStore(self.directory / "enrolled")
            unknown = EnrollmentStore(self.directory / "unknown")
            receiver = RelayReceiver(
                self.receiver_config(cert, key, enrolled), start_api=False
            )
            await receiver.start()
            try:
                port = receiver.server.sockets[0].getsockname()[1]
                with self.assertRaises(Exception):
                    await RelayConnector(
                        self.connector_config(ca, port), unknown
                    ).send_snapshot(snapshot_document())
                self.assertIsNone(
                    await receiver.registry.snapshot(unknown.identity()["device_id"])
                )
                self.assertGreaterEqual(receiver.errors, 1)
            finally:
                await receiver.close()
        asyncio.run(exercise())

    def test_private_api_exposes_health_and_selected_snapshot(self):
        async def exercise():
            _ca, cert, key = make_certificates(self.directory)
            enrollment = EnrollmentStore(self.directory / "enrollment")
            receiver = RelayReceiver(
                self.receiver_config(cert, key, enrollment), start_api=False
            )
            health = await receiver.api.dispatch(
                {"protocol_version": 1, "method": "health"}
            )
            self.assertTrue(health["ok"])
            self.assertEqual(health["result"]["device_count"], 1)
            missing = await receiver.api.dispatch(
                {
                    "protocol_version": 1,
                    "method": "snapshot",
                    "params": {"device_id": enrollment.identity()["device_id"]},
                }
            )
            self.assertFalse(missing["ok"])

            source = (
                ROOT / "src/printerhmi_agent/relay_receiver.py"
            ).read_text()
            self.assertIn("os.chmod(self.socket_path, 0o600)", source)
            self.assertIn("SO_PEERCRED", source)
        asyncio.run(exercise())

    def test_private_api_socket_is_mode_600_when_supported(self):
        async def exercise():
            _ca, cert, key = make_certificates(self.directory)
            enrollment = EnrollmentStore(self.directory / "enrollment")
            receiver = RelayReceiver(
                self.receiver_config(cert, key, enrollment), start_api=False
            )
            try:
                try:
                    await receiver.api.start()
                except PermissionError:
                    self.skipTest("Unix sockets are denied by this test sandbox")
                self.assertEqual(
                    os.stat(receiver.config.api_socket).st_mode & 0o777,
                    0o600,
                )
                health = await receiver_api_request(
                    receiver.config.api_socket, "health"
                )
                self.assertTrue(health["ok"])
                self.assertEqual(health["result"]["device_count"], 1)
            finally:
                await receiver.api.close()

        asyncio.run(exercise())

    def test_registry_replaces_instead_of_accumulating_history(self):
        async def exercise():
            registry = RelaySnapshotRegistry(
                ["device"], self.directory / "state.json"
            )
            await registry.publish("device", 1, {"value": 1})
            await registry.publish("device", 2, {"value": 2})
            stored = await registry.snapshot("device")
            self.assertEqual(stored["sequence"], 2)
            self.assertEqual(stored["snapshot"], {"value": 2})
            document = json.loads((self.directory / "state.json").read_text())
            self.assertEqual(list(document["records"]), ["device"])
            self.assertNotIn('"value":1', json.dumps(document, separators=(",", ":")))
        asyncio.run(exercise())

    def test_example_and_installer_are_disabled_by_default(self):
        example = json.loads(
            (ROOT / "config/relay-receiver.example.json").read_text()
        )
        self.assertFalse(example["enabled"])
        self.assertEqual(example["listen_host"], "127.0.0.1")
        installer = (ROOT / "install-relay-receiver-service.sh").read_text()
        self.assertIn("--enable-listener", installer)
        self.assertIn("--validate-config", installer)
        self.assertNotIn("install-relay-receiver-service", (ROOT / "install.sh").read_text())
        self.assertNotIn(
            "install-relay-receiver-service",
            (ROOT / "install-service.sh").read_text(),
        )

    def test_config_rejects_public_bind_and_mismatched_enrollment(self):
        _ca, cert, key = make_certificates(self.directory)
        enrollment = EnrollmentStore(self.directory / "enrollment").identity()

        def write_config(host, device_id):
            path = self.directory / "receiver-config.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "enabled": True,
                        "relay_id": "local-relay",
                        "listen_host": host,
                        "listen_port": 8443,
                        "api_socket": str(self.directory / "receiver.sock"),
                        "state_file": str(self.directory / "state.json"),
                        "cert_file": str(cert),
                        "key_file": str(key),
                        "stale_after": 30,
                        "devices": [
                            {
                                "device_id": device_id,
                                "public_key": enrollment["public_key"],
                            }
                        ],
                    }
                )
            )
            return path

        with self.assertRaisesRegex(RelayReceiverError, "loopback"):
            RelayReceiverConfig.load(
                write_config("0.0.0.0", enrollment["device_id"])
            )
        with self.assertRaisesRegex(RelayReceiverError, "invalid or duplicate"):
            RelayReceiverConfig.load(
                write_config("127.0.0.1", "phm_aaaaaaaaaaaaaaaaaaaaaaaaaa")
            )

    def test_receiver_unit_has_no_public_api_and_monitor_stays_isolated(self):
        unit = (
            ROOT / "packaging/systemd/printerhmi-relay-receiver.service.in"
        ).read_text()
        monitor = (
            ROOT / "packaging/systemd/printerhmi-remote.service.in"
        ).read_text()
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", unit)
        self.assertNotIn("PrivateNetwork=true", unit)
        self.assertIn("PrivateNetwork=true", monitor)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", monitor)


if __name__ == "__main__":
    unittest.main()
