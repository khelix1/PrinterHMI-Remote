import asyncio
import json
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional

from .moonraker import FRAME_END, MoonrakerProtocolError
from .telemetry import merge_status, normalized_status, subscription_for, utc_now


class MoonrakerMonitor:
    def __init__(self, socket_path: Path, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self.reader = None
        self.writer = None
        self._request_id = 0

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_unix_connection(str(self.socket_path)),
            timeout=self.timeout,
        )

    async def close(self) -> None:
        if self.writer is None:
            return
        self.writer.close()
        await self.writer.wait_closed()
        self.reader = None
        self.writer = None

    async def request(self, method: str, params: Optional[Dict[str, Any]] = None):
        if self.reader is None or self.writer is None:
            raise RuntimeError("monitor is not connected")
        self._request_id += 1
        request_id = self._request_id
        payload = {"jsonrpc": "2.0", "method": method, "id": request_id}
        if params is not None:
            payload["params"] = params
        self.writer.write(
            json.dumps(payload, separators=(",", ":")).encode("utf-8") + FRAME_END
        )
        await asyncio.wait_for(self.writer.drain(), timeout=self.timeout)

        while True:
            message = await self.read_message()
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise MoonrakerProtocolError(str(message["error"]))
            result = message.get("result")
            if not isinstance(result, dict):
                raise MoonrakerProtocolError("JSON-RPC result is not an object")
            return result

    async def read_message(self) -> Dict[str, Any]:
        if self.reader is None:
            raise RuntimeError("monitor is not connected")
        frame = await self.reader.readuntil(FRAME_END)
        try:
            message = json.loads(frame[:-1].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MoonrakerProtocolError("invalid JSON-RPC message") from exc
        if not isinstance(message, dict):
            raise MoonrakerProtocolError("JSON-RPC message is not an object")
        return message


async def snapshots(socket_path: Path) -> AsyncIterator[Dict[str, Any]]:
    monitor = MoonrakerMonitor(socket_path)
    await monitor.connect()
    status = {}
    try:
        object_result = await monitor.request("printer.objects.list")
        objects = object_result.get("objects", [])
        if not isinstance(objects, list):
            raise MoonrakerProtocolError("printer.objects.list returned invalid objects")

        subscription = subscription_for(
            name for name in objects if isinstance(name, str)
        )
        initial = await monitor.request(
            "printer.objects.subscribe",
            {"objects": subscription},
        )
        initial_status = initial.get("status", {})
        if isinstance(initial_status, dict):
            merge_status(status, initial_status)
        yield _snapshot(status, initial.get("eventtime"))

        while True:
            message = await monitor.read_message()
            if message.get("method") != "notify_status_update":
                continue
            params = message.get("params", [])
            if not isinstance(params, list) or not params or not isinstance(params[0], dict):
                continue
            merge_status(status, params[0])
            eventtime = params[1] if len(params) > 1 else None
            yield _snapshot(status, eventtime)
    finally:
        await monitor.close()


def _snapshot(status: Dict[str, Any], eventtime: object) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "captured_at": utc_now(),
        "eventtime": eventtime,
        "status": normalized_status(status),
    }
