from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class MoonrakerInstance:
    instance_id: str
    socket_path: str
    data_path: str
    hostname: Optional[str] = None
    moonraker_version: Optional[str] = None
    klippy_state: Optional[str] = None
    reachable: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
