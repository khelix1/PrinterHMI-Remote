import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from printerhmi_agent.moonraker import request


class FakeReader:
    async def readuntil(self, separator):
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "hostname": "printer-one",
                "klippy_state": "ready",
            },
        }
        return json.dumps(response).encode() + separator


class FakeWriter:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class MoonrakerClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_unix_json_rpc_request(self):
        socket_path = Path("/tmp/moonraker.sock")
        reader = FakeReader()
        writer = FakeWriter()
        with patch(
            "asyncio.open_unix_connection",
            new=AsyncMock(return_value=(reader, writer)),
        ):
                result = await request(socket_path, "server.info")
                self.assertEqual(result["hostname"], "printer-one")
                self.assertEqual(result["klippy_state"], "ready")
                request_payload = json.loads(writer.data[:-1])
                self.assertEqual(request_payload["method"], "server.info")
                self.assertTrue(writer.closed)


if __name__ == "__main__":
    unittest.main()
