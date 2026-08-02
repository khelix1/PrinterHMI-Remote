import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from printerhmi_agent.catalog import inspect_instance


class CatalogTests(unittest.IsolatedAsyncioTestCase):
    async def test_hostname_comes_from_printer_info(self):
        socket_path = Path("/home/biqu/printer_data/comms/moonraker.sock")
        responses = [
            {"moonraker_version": "v0.10.0", "klippy_state": "ready"},
            {"hostname": "SUNLU-S9"},
        ]
        with patch(
            "printerhmi_agent.catalog.request",
            new=AsyncMock(side_effect=responses),
        ) as request:
            instance = await inspect_instance(socket_path)

        self.assertTrue(instance.reachable)
        self.assertEqual(instance.hostname, "SUNLU-S9")
        self.assertEqual(
            [call.args[1] for call in request.await_args_list],
            ["server.info", "printer.info"],
        )

    async def test_optional_printer_info_failure_preserves_reachability(self):
        socket_path = Path("/home/biqu/printer_data/comms/moonraker.sock")
        responses = [
            {
                "hostname": "server-fallback",
                "moonraker_version": "v0.10.0",
                "klippy_state": "ready",
            },
            RuntimeError("printer metadata unavailable"),
        ]
        with patch(
            "printerhmi_agent.catalog.request",
            new=AsyncMock(side_effect=responses),
        ):
            instance = await inspect_instance(socket_path)

        self.assertTrue(instance.reachable)
        self.assertEqual(instance.hostname, "server-fallback")
        self.assertIsNone(instance.error)


if __name__ == "__main__":
    unittest.main()
