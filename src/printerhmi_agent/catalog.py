import asyncio
from pathlib import Path
from typing import Iterable, List

from .identity import instance_identity, machine_identity
from .model import MoonrakerInstance
from .moonraker import request


async def inspect_instance(socket_path: Path) -> MoonrakerInstance:
    host_id = machine_identity()
    identifier = instance_identity(socket_path, host_id)
    data_path = str(socket_path.parent.parent)
    try:
        info = await request(socket_path, "server.info")
    except Exception as exc:
        return MoonrakerInstance(
            instance_id=identifier,
            socket_path=str(socket_path),
            data_path=data_path,
            reachable=False,
            error="{}: {}".format(type(exc).__name__, exc),
        )

    return MoonrakerInstance(
        instance_id=identifier,
        socket_path=str(socket_path),
        data_path=data_path,
        hostname=_optional_text(info.get("hostname")),
        moonraker_version=_optional_text(info.get("moonraker_version")),
        klippy_state=_optional_text(info.get("klippy_state")),
        reachable=True,
    )


async def build_catalog(paths: Iterable[Path]) -> List[MoonrakerInstance]:
    return list(await asyncio.gather(*(inspect_instance(path) for path in paths)))


def _optional_text(value: object):
    return value if isinstance(value, str) and value else None
