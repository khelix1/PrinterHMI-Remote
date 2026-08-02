import asyncio
import json
import os
import socket
import struct
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from . import __version__


PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 16 * 1024


class LocalApiError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def default_api_socket_path(state_path: Optional[Path] = None) -> Path:
    configured = os.environ.get("PRINTERHMI_API_SOCKET")
    if configured:
        return Path(configured).expanduser()
    if state_path is not None:
        return state_path.parent / "agent.sock"
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local/state"
    return base / "printerhmi-remote/agent.sock"


class LocalAgentApi:
    def __init__(self, socket_path: Path, store: Any, catalog: Iterable[dict]):
        self.socket_path = socket_path
        self.store = store
        self.catalog = list(catalog)
        self.started_monotonic = time.monotonic()
        self.server = None

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_socket():
            self.socket_path.unlink()
        self.server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.socket_path),
        )
        os.chmod(self.socket_path, 0o600)

    async def serve_forever(self) -> None:
        if self.server is None:
            await self.start()
        async with self.server:
            await self.server.serve_forever()

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            self._require_same_user(writer)
            raw = await reader.readline()
            if not raw:
                raise LocalApiError("invalid_request", "request is empty")
            if len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
                raise LocalApiError("request_too_large", "request exceeds limit")
            request = json.loads(raw.decode("utf-8"))
            response = await self.dispatch(request)
        except LocalApiError as exc:
            response = self._error(exc.code, str(exc))
        except (UnicodeDecodeError, json.JSONDecodeError):
            response = self._error("invalid_json", "request is not valid JSON")
        except Exception:
            response = self._error("internal_error", "request failed")

        writer.write(
            json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n"
        )
        try:
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    def _require_same_user(self, writer: asyncio.StreamWriter) -> None:
        peer_socket = writer.get_extra_info("socket")
        if peer_socket is None or not hasattr(socket, "SO_PEERCRED"):
            raise LocalApiError("peer_unavailable", "peer credentials unavailable")
        credentials = peer_socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _pid, uid, _gid = struct.unpack("3i", credentials)
        if uid != os.getuid():
            raise LocalApiError("forbidden", "peer user is not authorized")

    async def dispatch(self, request: object) -> Dict[str, Any]:
        if not isinstance(request, dict):
            raise LocalApiError("invalid_request", "request must be an object")
        if request.get("protocol_version") != PROTOCOL_VERSION:
            raise LocalApiError("unsupported_version", "protocol_version must be 1")
        method = request.get("method")
        if method == "health":
            document = await self.store.document()
            instances = document["instances"]
            return self._result(
                {
                    "agent_version": __version__,
                    "uptime_seconds": round(
                        time.monotonic() - self.started_monotonic, 3
                    ),
                    # Catalog membership exists before the first telemetry
                    # event, so do not make the printer count blink to zero at
                    # service startup.
                    "instance_count": len(self.catalog),
                    "telemetry_ready_count": len(instances),
                    "connected_count": sum(
                        1 for item in instances.values() if item.get("connected")
                    ),
                    "generated_at": document["generated_at"],
                }
            )
        if method == "catalog":
            return self._result({"instances": self.catalog})
        if method == "snapshot":
            return self._result(await self.store.document())
        if method == "instance.get":
            params = request.get("params")
            instance_id = params.get("instance_id") if isinstance(params, dict) else None
            if not isinstance(instance_id, str) or not instance_id:
                raise LocalApiError("invalid_params", "instance_id is required")
            document = await self.store.document()
            instance = document["instances"].get(instance_id)
            if instance is None:
                raise LocalApiError("not_found", "instance was not found")
            return self._result(instance)
        raise LocalApiError("method_not_found", "unknown read-only method")

    @staticmethod
    def _result(result: object) -> Dict[str, Any]:
        return {"protocol_version": PROTOCOL_VERSION, "ok": True, "result": result}

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "ok": False,
            "error": {"code": code, "message": message},
        }


async def api_request(
    socket_path: Path,
    method: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(socket_path)), timeout=timeout
    )
    request: Dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "method": method,
    }
    if params is not None:
        request["params"] = params
    writer.write(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
    await writer.drain()
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
    finally:
        writer.close()
        await writer.wait_closed()
    response = json.loads(raw.decode("utf-8"))
    if not isinstance(response, dict):
        raise RuntimeError("local API response is not an object")
    return response
