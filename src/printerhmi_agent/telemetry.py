from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Iterable


CORE_OBJECTS = {
    "display_status": ["progress", "message"],
    "print_stats": [
        "state",
        "filename",
        "message",
        "total_duration",
        "print_duration",
        "filament_used",
    ],
    "toolhead": ["homed_axes", "position", "status"],
    "virtual_sdcard": ["progress", "file_position", "file_size"],
}

TEMPERATURE_PREFIXES = (
    "extruder",
    "heater_bed",
    "heater_generic ",
    "temperature_sensor ",
    "temperature_fan ",
)
FAN_PREFIXES = (
    "fan",
    "fan_generic ",
    "controller_fan ",
    "temperature_fan ",
)


def subscription_for(objects: Iterable[str]) -> Dict[str, object]:
    available = set(objects)
    subscription = {
        name: fields for name, fields in CORE_OBJECTS.items() if name in available
    }
    for name in sorted(available):
        if name.startswith(TEMPERATURE_PREFIXES):
            # Custom Klipper sensors may expose humidity or other useful
            # read-only fields. Subscribe to the complete object rather than
            # assuming every sensor has the same schema.
            subscription[name] = None
        elif name.startswith(FAN_PREFIXES):
            subscription[name] = None
    return subscription


def merge_status(current: Dict[str, Any], update: Dict[str, Any]) -> None:
    for object_name, fields in update.items():
        if isinstance(fields, dict) and isinstance(current.get(object_name), dict):
            current[object_name].update(deepcopy(fields))
        else:
            current[object_name] = deepcopy(fields)


def normalized_status(status: Dict[str, Any]) -> Dict[str, Any]:
    print_stats = status.get("print_stats", {})
    virtual_sdcard = status.get("virtual_sdcard", {})
    display_status = status.get("display_status", {})

    progress = virtual_sdcard.get("progress")
    if not isinstance(progress, (int, float)):
        progress = display_status.get("progress")

    temperatures = {}
    fans = {}
    for name, fields in status.items():
        if not isinstance(fields, dict):
            continue
        if name.startswith(TEMPERATURE_PREFIXES):
            temperatures[name] = {
                key: fields.get(key)
                for key in ("temperature", "target", "power", "humidity")
                if key in fields
            }
        if name.startswith(FAN_PREFIXES):
            fans[name] = {
                key: fields.get(key) for key in ("speed", "rpm") if key in fields
            }

    return {
        "print": {
            "state": print_stats.get("state"),
            "filename": print_stats.get("filename"),
            "message": print_stats.get("message") or display_status.get("message"),
            "progress": progress,
            "total_duration": print_stats.get("total_duration"),
            "print_duration": print_stats.get("print_duration"),
            "filament_used": print_stats.get("filament_used"),
        },
        "toolhead": deepcopy(status.get("toolhead", {})),
        "temperatures": temperatures,
        "fans": fans,
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
