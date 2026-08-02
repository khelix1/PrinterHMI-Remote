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

    # server.info owns reachability and version/state. Moonraker exposes the
    # actual Klipper host name through printer.info, so enrich the catalog without
    # allowing an optional metadata failure to mark a healthy instance offline.
    printer_info = {}
    try:
        printer_info = await request(socket_path, "printer.info")
    except Exception:
        pass

    hostname = (
        _optional_text(printer_info.get("hostname"))
        or _optional_text(info.get("hostname"))
        or socket_path.parent.parent.name
    )

    return MoonrakerInstance(
        instance_id=identifier,
        socket_path=str(socket_path),
        data_path=data_path,
        hostname=hostname,
        moonraker_version=_optional_text(info.get("moonraker_version")),
        klippy_state=_optional_text(info.get("klippy_state")),
        reachable=True,
    )


async def build_catalog(paths: Iterable[Path]) -> List[MoonrakerInstance]:
    return list(await asyncio.gather(*(inspect_instance(path) for path in paths)))


def _optional_text(value: object):
    return value if isinstance(value, str) and value else None
