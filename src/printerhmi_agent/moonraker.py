import asyncio
import json
from pathlib import Path
from typing import Any, Dict


FRAME_END = b"\x03"


class MoonrakerProtocolError(RuntimeError):
    pass


async def request(
    socket_path: Path,
    method: str,
    params: Dict[str, Any] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(socket_path)),
        timeout=timeout,
    )
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "id": 1,
    }
    if params:
        payload["params"] = params

    try:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        writer.write(encoded + FRAME_END)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        frame = await asyncio.wait_for(reader.readuntil(FRAME_END), timeout=timeout)
    finally:
        writer.close()
        await writer.wait_closed()

    try:
        response = json.loads(frame[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MoonrakerProtocolError("invalid JSON-RPC response") from exc

    if response.get("id") != 1:
        raise MoonrakerProtocolError("unexpected JSON-RPC response id")
    if "error" in response:
        raise MoonrakerProtocolError(str(response["error"]))
    result = response.get("result")
    if not isinstance(result, dict):
        raise MoonrakerProtocolError("JSON-RPC result is not an object")
    return result
