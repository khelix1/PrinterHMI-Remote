import asyncio
import json
import os
from pathlib import Path
from typing import Dict, Iterable, Optional

from .identity import instance_identity, machine_identity
from .monitor import snapshots
from .telemetry import utc_now


def default_state_path() -> Path:
    configured = os.environ.get("PRINTERHMI_STATE_FILE")
    if configured:
        return Path(configured).expanduser()
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local/state"
    return base / "printerhmi-remote/status.json"


class SnapshotStore:
    def __init__(self, path: Path, minimum_write_interval: float = 1.0):
        self.path = path
        self.minimum_write_interval = minimum_write_interval
        self.instances: Dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self._dirty = False
        self._last_write_time = 0.0
        self._flush_task = None

    async def update(self, instance_id: str, payload: dict) -> None:
        async with self._lock:
            self.instances[instance_id] = payload
            self._dirty = True
            loop = asyncio.get_running_loop()
            elapsed = loop.time() - self._last_write_time

            if self._last_write_time == 0.0 or elapsed >= self.minimum_write_interval:
                self._write_locked(loop.time())
            elif self._flush_task is None or self._flush_task.done():
                self._flush_task = asyncio.create_task(
                    self._flush_after(self.minimum_write_interval - elapsed)
                )

    async def flush(self) -> None:
        task = self._flush_task
        self._flush_task = None
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        async with self._lock:
            if self._dirty:
                self._write_locked(asyncio.get_running_loop().time())

    async def _flush_after(self, delay: float) -> None:
        try:
            await asyncio.sleep(max(0.0, delay))
            async with self._lock:
                if self._dirty:
                    self._write_locked(asyncio.get_running_loop().time())
        finally:
            if self._flush_task is asyncio.current_task():
                self._flush_task = None

    def _write_locked(self, now: float) -> None:
        document = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "instances": self.instances,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self.path)
        self._dirty = False
        self._last_write_time = now


async def monitor_forever(
    socket_path: Path,
    store: SnapshotStore,
    retry_seconds: float = 2.0,
) -> None:
    instance_id = instance_identity(socket_path, machine_identity())
    while True:
        try:
            async for snapshot in snapshots(socket_path):
                await store.update(
                    instance_id,
                    {
                        "instance_id": instance_id,
                        "socket_path": str(socket_path),
                        "connected": True,
                        "error": None,
                        **snapshot,
                    },
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await store.update(
                instance_id,
                {
                    "instance_id": instance_id,
                    "socket_path": str(socket_path),
                    "connected": False,
                    "captured_at": utc_now(),
                    "error": "{}: {}".format(type(exc).__name__, exc),
                },
            )
            await asyncio.sleep(retry_seconds)


async def run_service(paths: Iterable[Path], state_path: Optional[Path] = None) -> None:
    sockets = list(paths)
    if not sockets:
        raise RuntimeError("no local Moonraker Unix sockets found")
    store = SnapshotStore(state_path or default_state_path())
    await asyncio.gather(*(monitor_forever(path, store) for path in sockets))
