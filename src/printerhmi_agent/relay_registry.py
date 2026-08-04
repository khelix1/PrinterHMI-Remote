import asyncio
import copy
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional


SCHEMA_VERSION = 1


def _timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


class RelaySnapshotRegistry:
    """Owns only the latest privacy-filtered snapshot for each enrolled device."""

    def __init__(
        self,
        device_ids: Iterable[str],
        state_path: Path,
        stale_after: float = 30.0,
        clock=time.time,
    ):
        self.device_ids = tuple(sorted(set(device_ids)))
        self.state_path = state_path
        self.stale_after = stale_after
        self.clock = clock
        self.records: Dict[str, dict] = {}
        self.active_sessions: Dict[str, int] = {}
        self.lock = asyncio.Lock()

    async def session_opened(self, device_id: str) -> None:
        async with self.lock:
            self.active_sessions[device_id] = (
                self.active_sessions.get(device_id, 0) + 1
            )

    async def session_closed(self, device_id: str) -> None:
        async with self.lock:
            self.active_sessions[device_id] = max(
                0, self.active_sessions.get(device_id, 0) - 1
            )

    async def publish(
        self,
        device_id: str,
        sequence: int,
        snapshot: dict,
    ) -> None:
        if device_id not in self.device_ids:
            raise ValueError("device is not enrolled")
        now = self.clock()
        async with self.lock:
            self.records[device_id] = {
                "device_id": device_id,
                "sequence": sequence,
                "received_at": _timestamp(now),
                "received_epoch": now,
                "snapshot": copy.deepcopy(snapshot),
            }
            self._write_locked()

    async def document(self) -> dict:
        now = self.clock()
        async with self.lock:
            devices = {}
            for device_id in self.device_ids:
                record = self.records.get(device_id)
                devices[device_id] = {
                    "device_id": device_id,
                    "online": bool(
                        record
                        and now - record["received_epoch"] <= self.stale_after
                    ),
                    "active_sessions": self.active_sessions.get(device_id, 0),
                    "last_seen": record["received_at"] if record else None,
                    "sequence": record["sequence"] if record else None,
                }
            return {
                "schema_version": SCHEMA_VERSION,
                "generated_at": _timestamp(now),
                "devices": devices,
            }

    async def snapshot(self, device_id: str) -> Optional[dict]:
        async with self.lock:
            record = self.records.get(device_id)
            if record is None:
                return None
            return {
                "device_id": device_id,
                "sequence": record["sequence"],
                "received_at": record["received_at"],
                "snapshot": copy.deepcopy(record["snapshot"]),
            }

    def _write_locked(self) -> None:
        document = {
            "schema_version": SCHEMA_VERSION,
            "records": {
                device_id: {
                    key: copy.deepcopy(value)
                    for key, value in record.items()
                    if key != "received_epoch"
                }
                for device_id, record in self.records.items()
            },
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_path.parent, 0o700)
        temporary = self.state_path.with_name(self.state_path.name + ".tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(document, output, separators=(",", ":"), sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.state_path)
            os.chmod(self.state_path, 0o600)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
