import argparse
import asyncio
import json
from pathlib import Path
from typing import Sequence

from .catalog import build_catalog
from .discovery import discover_socket_paths


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

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
