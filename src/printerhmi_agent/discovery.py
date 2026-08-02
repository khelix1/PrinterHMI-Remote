import os
import stat
from pathlib import Path
from typing import Iterable, List, Optional, Sequence


ENV_SOCKET_PATHS = "PRINTERHMI_MOONRAKER_SOCKETS"


def _is_socket(path: Path) -> bool:
    try:
        return stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        return False


def candidate_socket_paths(
    home: Optional[Path] = None,
    explicit: Optional[Sequence[Path]] = None,
) -> Iterable[Path]:
    if explicit is not None:
        for path in explicit:
            yield path.expanduser()
        return

    configured = os.environ.get(ENV_SOCKET_PATHS, "")
    for raw in configured.split(os.pathsep):
        if raw.strip():
            yield Path(raw.strip()).expanduser()

    base = (home or Path.home()).expanduser()
    patterns = (
        "printer_data/comms/moonraker.sock",
        "printer_*_data/comms/moonraker.sock",
        "*_data/comms/moonraker.sock",
    )
    for pattern in patterns:
        yield from base.glob(pattern)


def discover_socket_paths(
    home: Optional[Path] = None,
    explicit: Optional[Sequence[Path]] = None,
) -> List[Path]:
    unique = {}
    for candidate in candidate_socket_paths(home=home, explicit=explicit):
        canonical = candidate.resolve(strict=False)
        if _is_socket(canonical):
            unique[str(canonical)] = canonical
    return [unique[key] for key in sorted(unique)]
