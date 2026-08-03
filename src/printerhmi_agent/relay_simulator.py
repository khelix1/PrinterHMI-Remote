import argparse
import asyncio
import json
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from .relay_transport import (
    MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
    RelayTransportError,
    create_session_challenge,
    read_frame,
    validate_agent_hello,
    verify_session_auth,
    write_frame,
)


class RelaySimulator:
    def __init__(
        self,
        cert_file: Path,
        key_file: Path,
        device_id: str,
        relay_id: str = "local-relay",
        host: str = "127.0.0.1",
        port: int = 0,
    ):
        self.cert_file = cert_file
        self.key_file = key_file
        self.device_id = device_id
        self.relay_id = relay_id
        self.host = host
        self.port = port
        self.server = None
        self.received = []
        self.errors = []
        self._issued_sessions = set()

    async def start(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_file), str(self.key_file))
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            ssl=context,
            limit=MAX_FRAME_BYTES + 1,
        )

    @property
    def address(self):
        if self.server is None or not self.server.sockets:
            raise RuntimeError("relay simulator has not started")
        return self.server.sockets[0].getsockname()[:2]

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def serve_forever(self) -> None:
        if self.server is None:
            await self.start()
        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            hello = await read_frame(reader)
            validate_agent_hello(hello, self.device_id)
            challenge = create_session_challenge(self.device_id, self.relay_id)
            session_id = challenge["session_id"]
            if session_id in self._issued_sessions:
                raise RelayTransportError("relay generated a duplicate session")
            self._issued_sessions.add(session_id)
            await write_frame(writer, challenge)
            authentication = await read_frame(reader)
            verify_session_auth(authentication, challenge)
            ready = {
                "protocol_version": PROTOCOL_VERSION,
                "type": "relay.session-ready",
                "session_id": session_id,
                "challenge_id": session_id,
                "relay_id": self.relay_id,
                "accepted_at": datetime.fromtimestamp(
                    time.time(), timezone.utc
                ).isoformat().replace("+00:00", "Z"),
            }
            await write_frame(writer, ready)
            envelope = await read_frame(reader)
            expected = {
                "protocol_version", "type", "session_id", "sequence", "snapshot"
            }
            if (
                set(envelope) != expected
                or envelope.get("protocol_version") != PROTOCOL_VERSION
                or envelope.get("type") != "agent.telemetry"
                or envelope.get("session_id") != session_id
                or envelope.get("sequence") != 1
            ):
                raise RelayTransportError("invalid telemetry envelope")
            serialized = json.dumps(envelope["snapshot"], sort_keys=True)
            if "socket_path" in serialized or '"filename"' in serialized:
                raise RelayTransportError("private local fields reached relay")
            self.received.append(envelope)
            await write_frame(
                writer,
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "type": "relay.telemetry-ack",
                    "session_id": session_id,
                    "sequence": 1,
                },
            )
        except Exception as exc:
            self.errors.append("{}: {}".format(type(exc).__name__, exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass


async def _run(args) -> None:
    simulator = RelaySimulator(
        args.cert,
        args.key,
        args.device_id,
        args.relay_id,
        args.host,
        args.port,
    )
    await simulator.start()
    host, port = simulator.address
    print("PrinterHMI local TLS relay simulator: {}:{}".format(host, port), flush=True)
    try:
        await simulator.serve_forever()
    finally:
        await simulator.close()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="printerhmi-relay-sim")
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--relay-id", default="local-relay")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args(argv)
    try:
        asyncio.run(_run(args))
    except (OSError, RelayTransportError) as exc:
        print("ERROR: relay simulator: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
