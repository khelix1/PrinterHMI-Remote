import uuid
from pathlib import Path


def machine_identity() -> str:
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return "machine-id-unavailable"


def instance_identity(socket_path: Path, host_identity: str) -> str:
    canonical = str(socket_path.expanduser().resolve(strict=False))
    seed = "printerhmi-moonraker://{}/{}".format(host_identity, canonical)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
