import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence

from .relay_registry import RelaySnapshotRegistry
from .relay_transport import (
    MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
    RelayTransportError,
    create_session_challenge,
    read_frame,
    sanitize_snapshot,
    validate_agent_hello,
    verify_session_auth,
    write_frame,
)


DEVICE_ID_PATTERN = re.compile(r"^phm_[a-z2-7]{26}$")
PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
RELAY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_API_REQUEST_BYTES = 16 * 1024


class RelayReceiverError(RuntimeError):
    pass


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _path(config_path: Path, value, label: str, must_exist=False) -> Path:
    if not isinstance(value, str) or not value:
        raise RelayReceiverError("invalid {} path".format(label))
    result = Path(value).expanduser()
    if not result.is_absolute():
        result = config_path.parent / result
    result = result.resolve()
    if must_exist and not result.is_file():
        raise RelayReceiverError("{} file was not found".format(label))
    return result


@dataclass(frozen=True)
class RelayReceiverConfig:
    enabled: bool
    relay_id: str
    listen_host: str
    listen_port: int
    api_socket: Path
    state_file: Path
    cert_file: Path
    key_file: Path
    stale_after: float
    devices: Dict[str, str]

    @classmethod
    def load(cls, path: Path) -> "RelayReceiverConfig":
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RelayReceiverError("receiver configuration could not be read") from exc
        expected = {
            "schema_version", "enabled", "relay_id", "listen_host",
            "listen_port", "api_socket", "state_file", "cert_file",
            "key_file", "stale_after", "devices",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise RelayReceiverError("invalid receiver configuration")
        if document.get("schema_version") != 1:
            raise RelayReceiverError("unsupported receiver configuration version")
        enabled = document.get("enabled")
        relay_id = document.get("relay_id")
        host = document.get("listen_host")
        port = document.get("listen_port")
        stale_after = document.get("stale_after")
        if not isinstance(enabled, bool):
            raise RelayReceiverError("invalid receiver enabled flag")
        if not isinstance(relay_id, str) or not RELAY_ID_PATTERN.fullmatch(relay_id):
            raise RelayReceiverError("invalid relay identifier")
        if not isinstance(host, str):
            raise RelayReceiverError("invalid receiver host")
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise RelayReceiverError(
                    "receiver foundation is restricted to loopback"
                )
        except ValueError as exc:
            raise RelayReceiverError("receiver host must be a loopback IP") from exc
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise RelayReceiverError("invalid receiver port")
        if (
            not isinstance(stale_after, (int, float))
            or isinstance(stale_after, bool)
            or not 5 <= float(stale_after) <= 3600
        ):
            raise RelayReceiverError("invalid receiver stale interval")
        raw_devices = document.get("devices")
        if not isinstance(raw_devices, list) or len(raw_devices) > 10000:
            raise RelayReceiverError("receiver requires enrolled devices")
        if enabled and not raw_devices:
            raise RelayReceiverError("enabled receiver requires enrolled devices")
        devices = {}
        for item in raw_devices:
            if not isinstance(item, dict) or set(item) != {"device_id", "public_key"}:
                raise RelayReceiverError("invalid receiver device entry")
            device_id = item.get("device_id")
            public_key = item.get("public_key")
            if not isinstance(device_id, str) or not DEVICE_ID_PATTERN.fullmatch(device_id):
                raise RelayReceiverError("invalid enrolled device identifier")
            if not isinstance(public_key, str) or not PUBLIC_KEY_PATTERN.fullmatch(public_key):
                raise RelayReceiverError("invalid enrolled device public key")
            try:
                decoded = base64.urlsafe_b64decode(public_key + "=")
            except (ValueError, TypeError) as exc:
                raise RelayReceiverError("invalid enrolled device public key") from exc
            token = base64.b32encode(hashlib.sha256(decoded).digest()).decode(
                "ascii"
            ).rstrip("=").lower()
            derived_device_id = "phm_{}".format(token[:26])
            if (
                len(decoded) != 32
                or device_id != derived_device_id
                or device_id in devices
            ):
                raise RelayReceiverError("invalid or duplicate enrolled device")
            devices[device_id] = public_key
        return cls(
            enabled=enabled,
            relay_id=relay_id,
            listen_host=host,
            listen_port=port,
            api_socket=_path(path, document["api_socket"], "API socket"),
            state_file=_path(path, document["state_file"], "state file"),
            cert_file=_path(path, document["cert_file"], "certificate", True),
            key_file=_path(path, document["key_file"], "private key", True),
            stale_after=float(stale_after),
            devices=devices,
        )

    def tls_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_file), str(self.key_file))
        return context


class RelayReceiverApi:
    def __init__(self, socket_path: Path, registry: RelaySnapshotRegistry):
        self.socket_path = socket_path
        self.registry = registry
        self.server = None

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.socket_path.exists() or self.socket_path.is_socket():
            self.socket_path.unlink()
        self.server = await asyncio.start_unix_server(
            self._handle, path=str(self.socket_path)
        )
        os.chmod(self.socket_path, 0o600)

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    async def _handle(self, reader, writer) -> None:
        try:
            self._require_same_user(writer)
            raw = await reader.readline()
            if not raw or len(raw) > MAX_API_REQUEST_BYTES or not raw.endswith(b"\n"):
                raise RelayReceiverError("invalid API request")
            request = json.loads(raw.decode("utf-8"))
            response = await self.dispatch(request)
        except Exception:
            response = {
                "protocol_version": 1,
                "ok": False,
                "error": {"code": "invalid_request", "message": "request rejected"},
            }
        writer.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")
        try:
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    def _require_same_user(self, writer) -> None:
        peer = writer.get_extra_info("socket")
        if peer is None or not hasattr(socket, "SO_PEERCRED"):
            raise RelayReceiverError("peer credentials unavailable")
        raw = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        if uid != os.getuid():
            raise RelayReceiverError("peer is not authorized")

    async def dispatch(self, request) -> dict:
        if not isinstance(request, dict) or request.get("protocol_version") != 1:
            raise RelayReceiverError("invalid API request")
        method = request.get("method")
        if method == "health":
            document = await self.registry.document()
            return {
                "protocol_version": 1,
                "ok": True,
                "result": {
                    "generated_at": document["generated_at"],
                    "device_count": len(document["devices"]),
                    "online_count": sum(
                        1 for item in document["devices"].values() if item["online"]
                    ),
                },
            }
        if method == "devices":
            return {"protocol_version": 1, "ok": True, "result": await self.registry.document()}
        if method == "snapshot":
            params = request.get("params")
            device_id = params.get("device_id") if isinstance(params, dict) else None
            if not isinstance(device_id, str):
                raise RelayReceiverError("device_id is required")
            snapshot = await self.registry.snapshot(device_id)
            if snapshot is None:
                return {
                    "protocol_version": 1,
                    "ok": False,
                    "error": {"code": "not_found", "message": "snapshot unavailable"},
                }
            return {"protocol_version": 1, "ok": True, "result": snapshot}
        raise RelayReceiverError("unknown API method")


class RelayReceiver:
    def __init__(self, config: RelayReceiverConfig, start_api: bool = True):
        if not config.enabled:
            raise RelayReceiverError("relay receiver is disabled")
        self.config = config
        self.registry = RelaySnapshotRegistry(
            config.devices, config.state_file, config.stale_after
        )
        self.api = RelayReceiverApi(config.api_socket, self.registry)
        self.start_api = start_api
        self.server = None
        self.errors = 0

    async def start(self) -> None:
        if self.start_api:
            await self.api.start()
        try:
            self.server = await asyncio.start_server(
                self._handle_agent,
                self.config.listen_host,
                self.config.listen_port,
                ssl=self.config.tls_context(),
                limit=MAX_FRAME_BYTES + 1,
            )
        except Exception:
            if self.start_api:
                await self.api.close()
            raise

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        if self.start_api:
            await self.api.close()

    async def serve_forever(self) -> None:
        if self.server is None:
            await self.start()
        async with self.server:
            await self.server.serve_forever()

    async def _handle_agent(self, reader, writer) -> None:
        device_id = None
        session_open = False
        try:
            hello = await read_frame(reader)
            device_id = validate_agent_hello(hello)
            enrolled_key = self.config.devices.get(device_id)
            if enrolled_key is None:
                raise RelayReceiverError("agent is not enrolled")
            challenge = create_session_challenge(device_id, self.config.relay_id)
            await write_frame(writer, challenge)
            authentication = await read_frame(reader)
            if authentication.get("device_public_key") != enrolled_key:
                raise RelayReceiverError("agent key is not enrolled")
            verify_session_auth(authentication, challenge)
            await self.registry.session_opened(device_id)
            session_open = True
            await write_frame(
                writer,
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "type": "relay.session-ready",
                    "session_id": challenge["session_id"],
                    "challenge_id": challenge["session_id"],
                    "relay_id": self.config.relay_id,
                    "accepted_at": _timestamp(),
                },
            )
            envelope = await read_frame(reader)
            if (
                set(envelope) != {
                    "protocol_version", "type", "session_id", "sequence", "snapshot"
                }
                or envelope.get("protocol_version") != PROTOCOL_VERSION
                or envelope.get("type") != "agent.telemetry"
                or envelope.get("session_id") != challenge["session_id"]
                or envelope.get("sequence") != 1
            ):
                raise RelayReceiverError("invalid telemetry envelope")
            snapshot = sanitize_snapshot(envelope.get("snapshot"))
            if snapshot != envelope.get("snapshot"):
                raise RelayReceiverError("telemetry was not privacy filtered")
            await self.registry.publish(device_id, 1, snapshot)
            await write_frame(
                writer,
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "type": "relay.telemetry-ack",
                    "session_id": challenge["session_id"],
                    "sequence": 1,
                },
            )
        except Exception:
            self.errors += 1
        finally:
            if session_open and device_id is not None:
                await self.registry.session_closed(device_id)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass


async def receiver_api_request(socket_path: Path, method: str, device_id=None) -> dict:
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    request = {"protocol_version": 1, "method": method}
    if device_id is not None:
        request["params"] = {"device_id": device_id}
    writer.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
    await writer.drain()
    raw = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return json.loads(raw.decode("utf-8"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="printerhmi-relay-receiver")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument("--api", choices=("health", "devices", "snapshot"))
    parser.add_argument("--device-id")
    args = parser.parse_args(argv)
    try:
        config = RelayReceiverConfig.load(args.config)
        if not config.enabled:
            raise RelayReceiverError("relay receiver is disabled")
        if args.validate_config:
            print("PASS: enabled loopback relay receiver configuration is valid")
            return 0
        if args.api:
            response = asyncio.run(
                receiver_api_request(config.api_socket, args.api, args.device_id)
            )
            print(json.dumps(response, indent=2, sort_keys=True))
            return 0 if response.get("ok") else 1
        receiver = RelayReceiver(config)
        asyncio.run(receiver.serve_forever())
        return 0
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, RelayReceiverError, RelayTransportError) as exc:
        print("ERROR: relay receiver unavailable: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
