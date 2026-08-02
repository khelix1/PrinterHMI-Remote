import tempfile
import unittest
from pathlib import Path
from unittest import mock

from printerhmi_agent.api import LocalAgentApi, LocalApiError
from printerhmi_agent.service import SnapshotStore


class LocalAgentApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.store = SnapshotStore(root / "status.json")
        await self.store.update(
            "printer-one",
            {"instance_id": "printer-one", "connected": True},
        )
        self.socket_path = root / "agent.sock"
        self.api = LocalAgentApi(
            self.socket_path,
            self.store,
            [{"instance_id": "printer-one", "hostname": "test-printer"}],
        )

    async def asyncTearDown(self):
        await self.store.flush()
        self.temporary.cleanup()

    async def test_socket_is_private(self):
        fake_server = mock.Mock()
        with mock.patch(
            "printerhmi_agent.api.asyncio.start_unix_server",
            new=mock.AsyncMock(return_value=fake_server),
        ) as start_server, mock.patch(
            "printerhmi_agent.api.os.chmod"
        ) as chmod:
            await self.api.start()
        start_server.assert_awaited_once()
        chmod.assert_called_once_with(self.socket_path, 0o600)

    async def test_health_reports_connected_instance(self):
        response = await self.api.dispatch(
            {"protocol_version": 1, "method": "health"}
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["protocol_version"], 1)
        self.assertEqual(response["result"]["instance_count"], 1)
        self.assertEqual(response["result"]["connected_count"], 1)

    async def test_health_retains_catalog_count_before_telemetry(self):
        empty_store = SnapshotStore(Path(self.temporary.name) / "empty.json")
        api = LocalAgentApi(
            Path(self.temporary.name) / "empty.sock",
            empty_store,
            [{"instance_id": "printer-one", "hostname": "test-printer"}],
        )
        response = await api.dispatch(
            {"protocol_version": 1, "method": "health"}
        )
        self.assertEqual(response["result"]["instance_count"], 1)
        self.assertEqual(response["result"]["telemetry_ready_count"], 0)
        self.assertEqual(response["result"]["connected_count"], 0)

    async def test_catalog_is_read_only_normalized_data(self):
        response = await self.api.dispatch(
            {"protocol_version": 1, "method": "catalog"}
        )
        self.assertEqual(
            response["result"]["instances"][0]["hostname"],
            "test-printer",
        )

    async def test_snapshot_and_instance_lookup(self):
        snapshot = await self.api.dispatch(
            {"protocol_version": 1, "method": "snapshot"}
        )
        self.assertTrue(snapshot["result"]["instances"]["printer-one"]["connected"])
        instance = await self.api.dispatch(
            {
                "protocol_version": 1,
                "method": "instance.get",
                "params": {"instance_id": "printer-one"},
            }
        )
        self.assertEqual(instance["result"]["instance_id"], "printer-one")

    async def test_unknown_method_is_rejected(self):
        with self.assertRaises(LocalApiError) as raised:
            await self.api.dispatch(
                {"protocol_version": 1, "method": "printer.restart"}
            )
        self.assertEqual(raised.exception.code, "method_not_found")

    async def test_protocol_version_is_required(self):
        with self.assertRaises(LocalApiError) as raised:
            await self.api.dispatch({"method": "health"})
        self.assertEqual(raised.exception.code, "unsupported_version")


if __name__ == "__main__":
    unittest.main()
