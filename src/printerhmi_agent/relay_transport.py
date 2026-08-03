import asyncio
import base64
import hashlib
import json
import re
import secrets
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .enrollment import EnrollmentStore


PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 256 * 1024
MAX_SESSION_LIFETIME = 120
CLOCK_SKEW_SECONDS = 30
SESSION_SIGNATURE_DOMAIN = b"PrinterHMI Remote relay session authentication v1\x00"
RELAY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
DEVICE_ID_PATTERN = re.compile(r"^phm_[a-z2-7]{26}$")
PRIVATE_SNAPSHOT_KEYS = {
    "address",
    "api_key",
    "filename",
    "host",
    "hostname",
    "ip",
    "message",
    "socket_path",
    "url",
}


class RelayTransportError(RuntimeError):
    pass


def _canonical(document: dict) -> bytes:
    return json.dumps(
        document,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    ).encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _device_id(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).digest()
    token = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    return "phm_{}".format(token[:26])


def _decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise RelayTransportError("invalid encoded value")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise RelayTransportError("invalid encoded value") from exc


def _timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: str) -> float:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RelayTransportError("invalid session timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").timestamp()
    except ValueError as exc:
        raise RelayTransportError("invalid session timestamp") from exc


@dataclass(frozen=True)
class RelayConfig:
    enabled: bool
    relay_id: str
    host: str
    port: int
    server_name: str
    ca_file: Path
    queue_capacity: int = 8
    connect_timeout: float = 5.0

    @classmethod
    def load(cls, path: Path) -> "RelayConfig":
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RelayTransportError("relay configuration could not be read") from exc
        expected = {
            "schema_version",
            "enabled",
            "relay_id",
            "host",
            "port",
            "server_name",
            "ca_file",
            "queue_capacity",
            "connect_timeout",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise RelayTransportError("invalid relay configuration")
        if document.get("schema_version") != PROTOCOL_VERSION:
            raise RelayTransportError("unsupported relay configuration version")
        enabled = document.get("enabled")
        relay_id = document.get("relay_id")
        host = document.get("host")
        port = document.get("port")
        server_name = document.get("server_name")
        queue_capacity = document.get("queue_capacity")
        connect_timeout = document.get("connect_timeout")
        ca_value = document.get("ca_file")
        if not isinstance(enabled, bool):
            raise RelayTransportError("invalid relay enabled flag")
        if not isinstance(relay_id, str) or not RELAY_ID_PATTERN.fullmatch(relay_id):
            raise RelayTransportError("invalid relay identifier")
        if not isinstance(host, str) or not host or len(host) > 253:
            raise RelayTransportError("invalid relay host")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise RelayTransportError("invalid relay port")
        if not isinstance(server_name, str) or not server_name or len(server_name) > 253:
            raise RelayTransportError("invalid relay server name")
        if (
            not isinstance(queue_capacity, int)
            or isinstance(queue_capacity, bool)
            or not 1 <= queue_capacity <= 64
        ):
            raise RelayTransportError("invalid relay queue capacity")
        if (
            not isinstance(connect_timeout, (int, float))
            or isinstance(connect_timeout, bool)
            or not 0.5 <= float(connect_timeout) <= 30.0
        ):
            raise RelayTransportError("invalid relay connection timeout")
        if not isinstance(ca_value, str) or not ca_value:
            raise RelayTransportError("invalid relay CA path")
        ca_file = Path(ca_value).expanduser()
        if not ca_file.is_absolute():
            ca_file = path.parent / ca_file
        ca_file = ca_file.resolve()
        if not ca_file.is_file():
            raise RelayTransportError("relay CA file was not found")
        return cls(
            enabled=enabled,
            relay_id=relay_id,
            host=host,
            port=port,
            server_name=server_name,
            ca_file=ca_file,
            queue_capacity=queue_capacity,
            connect_timeout=float(connect_timeout),
        )

    def tls_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=str(self.ca_file),
        )
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


class BoundedSnapshotQueue:
    def __init__(self, capacity: int = 8):
        if not 1 <= capacity <= 64:
            raise ValueError("capacity must be between 1 and 64")
        self.capacity = capacity
        self._queue = asyncio.Queue(maxsize=capacity)
        self.dropped_count = 0

    def put_latest(self, snapshot: dict) -> None:
        while self._queue.full():
            self._queue.get_nowait()
            self.dropped_count += 1
        self._queue.put_nowait(snapshot)

    async def get(self) -> dict:
        return await self._queue.get()

    def qsize(self) -> int:
        return self._queue.qsize()


def retry_delays(attempts: int, base: float = 1.0, maximum: float = 30.0) -> List[float]:
    if attempts < 0 or base <= 0 or maximum <= 0:
        raise ValueError("invalid retry policy")
    return [min(maximum, base * (2 ** attempt)) for attempt in range(attempts)]


def create_session_challenge(
    device_id: str,
    relay_id: str,
    lifetime: int = 60,
    clock: Callable[[], float] = time.time,
) -> dict:
    if not isinstance(device_id, str) or not DEVICE_ID_PATTERN.fullmatch(device_id):
        raise RelayTransportError("invalid session audience")
    if not isinstance(relay_id, str) or not RELAY_ID_PATTERN.fullmatch(relay_id):
        raise RelayTransportError("invalid relay identifier")
    if not isinstance(lifetime, int) or not 1 <= lifetime <= MAX_SESSION_LIFETIME:
        raise RelayTransportError("invalid session lifetime")
    now = clock()
    return {
        "protocol_version": PROTOCOL_VERSION,
        "type": "relay.session-challenge",
        "session_id": str(uuid.uuid4()),
        "relay_id": relay_id,
        "nonce": _encode(secrets.token_bytes(32)),
        "audience": device_id,
        "issued_at": _timestamp(now),
        "expires_at": _timestamp(now + lifetime),
    }


def _validate_session_challenge(
    challenge: dict,
    device_id: str,
    relay_id: str,
    now: float,
) -> dict:
    expected = {
        "protocol_version",
        "type",
        "session_id",
        "relay_id",
        "nonce",
        "audience",
        "issued_at",
        "expires_at",
    }
    if not isinstance(challenge, dict) or set(challenge) != expected:
        raise RelayTransportError("invalid relay session challenge")
    if challenge.get("protocol_version") != PROTOCOL_VERSION:
        raise RelayTransportError("unsupported relay session version")
    if challenge.get("type") != "relay.session-challenge":
        raise RelayTransportError("invalid relay session challenge type")
    session_id = challenge.get("session_id")
    try:
        parsed = uuid.UUID(session_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise RelayTransportError("invalid relay session identifier") from exc
    if str(parsed) != session_id:
        raise RelayTransportError("invalid relay session identifier")
    if challenge.get("relay_id") != relay_id:
        raise RelayTransportError("relay identity does not match configuration")
    if challenge.get("audience") != device_id:
        raise RelayTransportError("relay session has the wrong audience")
    nonce = _decode(challenge.get("nonce"))
    if len(nonce) != 32:
        raise RelayTransportError("invalid relay session nonce")
    issued = _parse_timestamp(challenge.get("issued_at"))
    expires = _parse_timestamp(challenge.get("expires_at"))
    if expires <= issued or expires - issued > MAX_SESSION_LIFETIME:
        raise RelayTransportError("invalid relay session lifetime")
    if issued > now + CLOCK_SKEW_SECONDS:
        raise RelayTransportError("relay session is not yet valid")
    if expires <= now:
        raise RelayTransportError("relay session has expired")
    return json.loads(json.dumps(challenge))


def sign_session_challenge(
    store: EnrollmentStore,
    challenge: dict,
    relay_id: str,
    clock: Callable[[], float] = time.time,
) -> dict:
    identity = store.identity()
    now = clock()
    normalized = _validate_session_challenge(
        challenge,
        identity["device_id"],
        relay_id,
        now,
    )
    response = {
        "protocol_version": PROTOCOL_VERSION,
        "type": "agent.session-auth",
        "challenge": normalized,
        "device_id": identity["device_id"],
        "device_public_key": identity["public_key"],
        "signed_at": _timestamp(now),
    }
    response["signature"] = _encode(
        store.sign(SESSION_SIGNATURE_DOMAIN + _canonical(response))
    )
    return response


def verify_session_auth(
    response: dict,
    expected_challenge: dict,
    clock: Callable[[], float] = time.time,
) -> dict:
    expected = {
        "protocol_version",
        "type",
        "challenge",
        "device_id",
        "device_public_key",
        "signed_at",
        "signature",
    }
    if not isinstance(response, dict) or set(response) != expected:
        raise RelayTransportError("invalid agent session authentication")
    if response.get("protocol_version") != PROTOCOL_VERSION:
        raise RelayTransportError("unsupported agent session version")
    if response.get("type") != "agent.session-auth":
        raise RelayTransportError("invalid agent session authentication type")
    if response.get("challenge") != expected_challenge:
        raise RelayTransportError("agent session challenge does not match")
    public_key = _decode(response.get("device_public_key"))
    signature = _decode(response.get("signature"))
    if len(public_key) != 32 or len(signature) != 64:
        raise RelayTransportError("invalid agent session signature")
    if _device_id(public_key) != response.get("device_id"):
        raise RelayTransportError("invalid agent session identity")
    now = clock()
    challenge = _validate_session_challenge(
        expected_challenge,
        response["device_id"],
        expected_challenge["relay_id"],
        now,
    )
    signed_at = _parse_timestamp(response.get("signed_at"))
    if not (
        _parse_timestamp(challenge["issued_at"]) - CLOCK_SKEW_SECONDS
        <= signed_at
        < _parse_timestamp(challenge["expires_at"])
    ):
        raise RelayTransportError("invalid agent session authentication time")
    signed = dict(response)
    signed.pop("signature")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            SESSION_SIGNATURE_DOMAIN + _canonical(signed),
        )
    except InvalidSignature as exc:
        raise RelayTransportError("invalid agent session signature") from exc
    return signed


def sanitize_snapshot(document: dict) -> dict:
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise RelayTransportError("invalid snapshot document")
    instances = document.get("instances")
    if not isinstance(instances, dict):
        raise RelayTransportError("invalid snapshot instances")
    sanitized: Dict[str, dict] = {}
    for instance_id, source in instances.items():
        if not isinstance(instance_id, str) or not isinstance(source, dict):
            raise RelayTransportError("invalid snapshot instance")
        target = {
            key: _sanitize_snapshot_value(source[key])
            for key in ("instance_id", "connected", "captured_at", "eventtime", "status")
            if key in source
        }
        if source.get("error"):
            target["error"] = "unavailable"
        sanitized[instance_id] = target
    result = {
        "schema_version": PROTOCOL_VERSION,
        "generated_at": document.get("generated_at"),
        "instances": sanitized,
    }
    if len(_canonical(result)) > MAX_FRAME_BYTES // 2:
        raise RelayTransportError("snapshot exceeds relay payload limit")
    return result


def _sanitize_snapshot_value(value):
    if isinstance(value, dict):
        return {
            key: _sanitize_snapshot_value(item)
            for key, item in value.items()
            if isinstance(key, str) and key.lower() not in PRIVATE_SNAPSHOT_KEYS
        }
    if isinstance(value, list):
        return [_sanitize_snapshot_value(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise RelayTransportError("snapshot contains an unsupported value")


async def read_frame(reader: asyncio.StreamReader, timeout: float = 5.0) -> dict:
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise RelayTransportError("relay frame timed out") from exc
    except ValueError as exc:
        raise RelayTransportError("relay frame exceeds limit") from exc
    if not raw:
        raise RelayTransportError("relay closed the connection")
    if len(raw) > MAX_FRAME_BYTES or not raw.endswith(b"\n"):
        raise RelayTransportError("relay frame exceeds limit")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RelayTransportError("relay frame is not valid JSON") from exc
    if not isinstance(document, dict):
        raise RelayTransportError("relay frame must be an object")
    return document


async def write_frame(writer: asyncio.StreamWriter, document: dict) -> None:
    payload = _canonical(document) + b"\n"
    if len(payload) > MAX_FRAME_BYTES:
        raise RelayTransportError("relay frame exceeds limit")
    writer.write(payload)
    await writer.drain()


class RelayConnector:
    def __init__(
        self,
        config: RelayConfig,
        enrollment_store: Optional[EnrollmentStore] = None,
    ):
        if not config.enabled:
            raise RelayTransportError("relay transport is disabled")
        self.config = config
        self.enrollment_store = enrollment_store or EnrollmentStore()

    async def send_snapshot(self, snapshot: dict) -> dict:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config.host,
                    self.config.port,
                    ssl=self.config.tls_context(),
                    server_hostname=self.config.server_name,
                    limit=MAX_FRAME_BYTES + 1,
                ),
                timeout=self.config.connect_timeout,
            )
            challenge = await read_frame(reader, self.config.connect_timeout)
            authentication = sign_session_challenge(
                self.enrollment_store,
                challenge,
                self.config.relay_id,
            )
            await write_frame(writer, authentication)
            ready = await read_frame(reader, self.config.connect_timeout)
            expected_ready = {
                "protocol_version",
                "type",
                "session_id",
                "challenge_id",
                "relay_id",
                "accepted_at",
            }
            if (
                set(ready) != expected_ready
                or ready.get("protocol_version") != PROTOCOL_VERSION
                or ready.get("type") != "relay.session-ready"
                or ready.get("session_id") != challenge["session_id"]
                or ready.get("challenge_id") != challenge["session_id"]
                or ready.get("relay_id") != self.config.relay_id
            ):
                raise RelayTransportError("invalid relay session confirmation")
            envelope = {
                "protocol_version": PROTOCOL_VERSION,
                "type": "agent.telemetry",
                "session_id": challenge["session_id"],
                "sequence": 1,
                "snapshot": sanitize_snapshot(snapshot),
            }
            await write_frame(writer, envelope)
            acknowledgement = await read_frame(reader, self.config.connect_timeout)
            if (
                set(acknowledgement)
                != {"protocol_version", "type", "session_id", "sequence"}
                or acknowledgement.get("protocol_version") != PROTOCOL_VERSION
                or acknowledgement.get("type") != "relay.telemetry-ack"
                or acknowledgement.get("session_id") != challenge["session_id"]
                or acknowledgement.get("sequence") != 1
            ):
                raise RelayTransportError("invalid relay telemetry acknowledgement")
            return {
                "session_id": challenge["session_id"],
                "relay_id": self.config.relay_id,
                "sequence": 1,
            }
        except RelayTransportError:
            raise
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            raise RelayTransportError("secure relay connection failed") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ssl.SSLError):
                    pass

    async def send_with_retries(
        self,
        snapshot: dict,
        attempts: int = 3,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> dict:
        if attempts < 1:
            raise ValueError("attempts must be positive")
        delays = retry_delays(max(0, attempts - 1))
        last_error = None
        for attempt in range(attempts):
            try:
                return await self.send_snapshot(snapshot)
            except RelayTransportError as exc:
                last_error = exc
                if attempt < len(delays):
                    await sleep(delays[attempt])
        raise RelayTransportError("relay retry budget exhausted") from last_error
