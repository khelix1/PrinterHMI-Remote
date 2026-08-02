import argparse
import asyncio
import json
from pathlib import Path
from typing import Sequence

from .catalog import build_catalog
from .discovery import discover_socket_paths
from .monitor import snapshots
from .service import default_state_path, run_service


def main(argv: Sequence[str] = None) -> int:
    parser = argparse.ArgumentParser(prog="printerhmi-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    discover = subparsers.add_parser(
        "discover",
        help="discover and inspect local Moonraker instances",
    )
    discover.add_argument("--json", action="store_true")
    discover.add_argument(
        "--socket",
        action="append",
        type=Path,
        default=None,
        help="explicit Moonraker Unix socket; may be repeated",
    )
    monitor = subparsers.add_parser(
        "monitor",
        help="stream normalized read-only telemetry for one local instance",
    )
    monitor.add_argument("--socket", type=Path, required=True)
    service = subparsers.add_parser(
        "run",
        help="monitor every local instance and atomically maintain a state file",
    )
    service.add_argument("--socket", action="append", type=Path, default=None)
    service.add_argument("--state-file", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.command == "discover":
        paths = discover_socket_paths(explicit=args.socket)
        catalog = asyncio.run(build_catalog(paths))
        if args.json:
            print(json.dumps([item.to_dict() for item in catalog], indent=2))
        elif not catalog:
            print("No local Moonraker Unix sockets found.")
        else:
            for item in catalog:
                state = item.klippy_state or "unknown"
                host = item.hostname or Path(item.data_path).name
                reachability = "online" if item.reachable else "unreachable"
                print("{}  {}  {}  {}".format(host, state, reachability, item.socket_path))
        return 0

    if args.command == "monitor":
        async def print_snapshots():
            async for snapshot in snapshots(args.socket):
                print(json.dumps(snapshot, separators=(",", ":")), flush=True)
        asyncio.run(print_snapshots())
        return 0

    if args.command == "run":
        paths = discover_socket_paths(explicit=args.socket)
        state_path = args.state_file or default_state_path()
        print("PrinterHMI Remote state: {}".format(state_path), flush=True)
        asyncio.run(run_service(paths, state_path))
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
