import asyncio
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Sequence, Tuple

from . import __version__
from .api import api_request
from .telemetry import utc_now


SERVICE_NAME = "printerhmi-remote.service"
MAX_ERROR_LINES = 20
MAX_ERROR_LENGTH = 500


def sanitize_text(value: object, sensitive_values: Iterable[object] = ()) -> str:
    text = str(value)
    for sensitive in sorted(
        (str(item) for item in sensitive_values if item),
        key=len,
        reverse=True,
    ):
        text = text.replace(sensitive, "<REDACTED>")
    home = str(Path.home())
    if home and home != "/":
        text = text.replace(home, "<HOME>")
    substitutions = (
        (r"https?://[^\s\"']+", "<URL>"),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>"),
        (r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+", r"\1=<REDACTED>"),
        (r"(?i)\b(filename|file|path)\s*[:=]\s*[^\s,;]+", r"\1=<REDACTED>"),
        (r"(?:/[A-Za-z0-9_.@+-]+){2,}", "<PATH>"),
    )
    for pattern, replacement in substitutions:
        text = re.sub(pattern, replacement, text)
    return text[:MAX_ERROR_LENGTH]


def _command(args: Sequence[str]) -> Tuple[int, str]:
    executable = shutil.which(args[0])
    if executable is None:
        return 127, ""
    try:
        completed = subprocess.run(
            [executable, *args[1:]],
            check=False,
            capture_output=True,
            text=True,
            timeout=4.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    return completed.returncode, completed.stdout


def _service_summary(command: Callable[[Sequence[str]], Tuple[int, str]]) -> dict:
    properties = ("ActiveState", "SubState", "UnitFileState", "NRestarts", "Result")
    code, output = command(
        ["systemctl", "show", SERVICE_NAME, *(
            "--property={}".format(item) for item in properties
        )]
    )
    parsed = {}
    if code == 0:
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in properties:
                parsed[key] = sanitize_text(value)
    return {
        "available": code == 0,
        "active_state": parsed.get("ActiveState"),
        "sub_state": parsed.get("SubState"),
        "unit_file_state": parsed.get("UnitFileState"),
        "restart_count": parsed.get("NRestarts"),
        "result": parsed.get("Result"),
    }


def _recent_errors(
    command: Callable[[Sequence[str]], Tuple[int, str]],
    sensitive_values: Iterable[object] = (),
) -> list:
    code, output = command(
        ["journalctl", "-u", SERVICE_NAME, "-n", "100", "--no-pager", "-o", "cat"]
    )
    if code != 0:
        return []
    interesting = re.compile(
        r"(?i)\b(error|warning|failed|exception|traceback|denied|timeout)\b"
    )
    lines = []
    for line in output.splitlines():
        if interesting.search(line):
            lines.append(sanitize_text(line, sensitive_values))
    return lines[-MAX_ERROR_LINES:]


def _file_metadata(path: Path, require_socket: bool = False) -> dict:
    try:
        details = path.stat()
    except OSError:
        return {"exists": False}
    return {
        "exists": True,
        "expected_type": stat.S_ISSOCK(details.st_mode) if require_socket else stat.S_ISREG(details.st_mode),
        "mode": "{:04o}".format(stat.S_IMODE(details.st_mode)),
        "owned_by_current_user": details.st_uid == os.getuid(),
        "size_bytes": details.st_size if not require_socket else None,
    }


async def _read_api(
    requester: Callable[..., Awaitable[Dict[str, Any]]],
    socket_path: Path,
    method: str,
) -> dict:
    try:
        response = await requester(socket_path, method)
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        return {"ok": False, "error": sanitize_text(exc)}
    if not isinstance(response, dict) or not response.get("ok"):
        return {"ok": False, "error": "API request was rejected"}
    result = response.get("result")
    return {"ok": True, "result": result if isinstance(result, dict) else {}}


def _safe_health(payload: dict) -> dict:
    allowed = (
        "agent_version",
        "uptime_seconds",
        "instance_count",
        "telemetry_ready_count",
        "connected_count",
        "generated_at",
    )
    return {key: payload.get(key) for key in allowed}


def _device_summary(instance: dict) -> dict:
    status = instance.get("status")
    status = status if isinstance(status, dict) else {}
    print_status = status.get("print")
    print_status = print_status if isinstance(print_status, dict) else {}
    temperatures = status.get("temperatures")
    fans = status.get("fans")
    return {
        "connected": bool(instance.get("connected")),
        "captured_at": instance.get("captured_at"),
        "error": sanitize_text(instance["error"]) if instance.get("error") else None,
        "print_state": print_status.get("state"),
        "temperature_device_count": len(temperatures) if isinstance(temperatures, dict) else 0,
        "fan_device_count": len(fans) if isinstance(fans, dict) else 0,
    }


async def collect_diagnostics(
    api_socket: Path,
    state_path: Path,
    requester: Callable[..., Awaitable[Dict[str, Any]]] = api_request,
    command: Callable[[Sequence[str]], Tuple[int, str]] = _command,
) -> dict:
    health_response, catalog_response, snapshot_response = await asyncio.gather(
        _read_api(requester, api_socket, "health"),
        _read_api(requester, api_socket, "catalog"),
        _read_api(requester, api_socket, "snapshot"),
    )

    catalog_items = []
    if catalog_response.get("ok"):
        candidate = catalog_response["result"].get("instances")
        if isinstance(candidate, list):
            catalog_items = [item for item in candidate if isinstance(item, dict)]

    snapshots = {}
    if snapshot_response.get("ok"):
        candidate = snapshot_response["result"].get("instances")
        if isinstance(candidate, dict):
            snapshots = candidate

    aliases = {}
    sensitive_values = []
    printers = []
    for index, item in enumerate(catalog_items, 1):
        sensitive_values.extend(
            item.get(key)
            for key in ("instance_id", "hostname", "socket_path", "data_path")
            if item.get(key)
        )
        identifier = item.get("instance_id")
        alias = "printer-{}".format(index)
        if isinstance(identifier, str):
            aliases[identifier] = alias
        telemetry = snapshots.get(identifier, {}) if isinstance(identifier, str) else {}
        telemetry = telemetry if isinstance(telemetry, dict) else {}
        printers.append(
            {
                "alias": alias,
                "reachable": bool(item.get("reachable")),
                "moonraker_version": sanitize_text(item.get("moonraker_version")) if item.get("moonraker_version") else None,
                "klippy_state": sanitize_text(item.get("klippy_state")) if item.get("klippy_state") else None,
                **_device_summary(telemetry),
            }
        )

    for identifier, telemetry in snapshots.items():
        if identifier in aliases or not isinstance(telemetry, dict):
            continue
        printers.append(
            {
                "alias": "printer-{}".format(len(printers) + 1),
                "reachable": None,
                "moonraker_version": None,
                "klippy_state": None,
                **_device_summary(telemetry),
            }
        )

    return {
        "diagnostics_schema_version": 1,
        "generated_at": utc_now(),
        "agent": {
            "version": __version__,
            "python": "{}.{}.{}".format(*sys.version_info[:3]),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "service": _service_summary(command),
        "local_api": {
            "available": bool(health_response.get("ok")),
            "socket": _file_metadata(api_socket, require_socket=True),
            "health": _safe_health(health_response.get("result", {}))
            if health_response.get("ok") else None,
            "error": health_response.get("error"),
        },
        "state_file": _file_metadata(state_path),
        "printers": printers,
        "recent_sanitized_errors": _recent_errors(command, sensitive_values),
        "privacy": {
            "raw_state_included": False,
            "hostnames_included": False,
            "instance_ids_included": False,
            "socket_paths_included": False,
            "print_filenames_included": False,
        },
    }


def default_bundle_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path.cwd() / "PrinterHMI-Remote-diagnostics-{}.zip".format(stamp)


def write_support_bundle(report: dict, output: Optional[Path] = None) -> Path:
    destination = (output or default_bundle_path()).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    note = (
        "PrinterHMI Remote sanitized diagnostics bundle\n\n"
        "This archive intentionally excludes raw telemetry, printer names, "
        "instance identifiers, socket paths, print filenames and credentials.\n"
    )
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "diagnostics.json",
            json.dumps(report, indent=2, sort_keys=True) + "\n",
        )
        archive.writestr("README.txt", note)
    os.chmod(destination, 0o600)
    return destination
