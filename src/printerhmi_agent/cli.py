import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Sequence

from .api import api_request, default_api_socket_path
from .catalog import build_catalog
from .diagnostics import collect_diagnostics, write_support_bundle
from .discovery import discover_socket_paths
from .enrollment import DEFAULT_PAIRING_TTL, EnrollmentError, EnrollmentStore
from .monitor import snapshots
from .relay_transport import RelayConfig, RelayConnector, RelayTransportError
from .service import default_state_path, run_service


def main(argv: Sequence[str] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)

    # This launcher exists on every managed installation. Moonraker's git_repo
    # updater refreshes source and requirements, but it does not regenerate
    # newly added editable-install console-script wrappers. Keep every role
    # reachable through this stable launcher so managed updates are complete.
    component_commands = {
        "relay-config": "printerhmi_agent.relay_configuration",
        "relay-receiver": "printerhmi_agent.relay_receiver",
        "relay-worker": "printerhmi_agent.relay_worker",
        "relay-sim": "printerhmi_agent.relay_simulator",
    }
    if arguments and arguments[0] in component_commands:
        from importlib import import_module

        component = import_module(component_commands[arguments[0]])
        return component.main(arguments[1:])

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
    service.add_argument("--api-socket", type=Path, default=None)
    api = subparsers.add_parser(
        "api",
        help="inspect the versioned read-only local agent API",
    )
    api.add_argument("method", choices=("health", "catalog", "snapshot", "instance.get"))
    api.add_argument("--api-socket", type=Path, default=None)
    api.add_argument("--instance-id")
    diagnose = subparsers.add_parser(
        "diagnose",
        help="report agent health and create a sanitized support bundle",
    )
    diagnose.add_argument("--api-socket", type=Path, default=None)
    diagnose.add_argument("--state-file", type=Path, default=None)
    diagnose.add_argument("--output", type=Path, default=None)
    diagnose.add_argument("--json", action="store_true")
    diagnose.add_argument("--no-bundle", action="store_true")
    enrollment = subparsers.add_parser(
        "enrollment",
        help="manage local cryptographic identity and one-time pairing",
    )
    enrollment.add_argument(
        "action",
        choices=(
            "identity", "pair-create", "pair-consume", "peers",
            "revoke", "rotate", "challenge-sign", "relay-complete",
        ),
    )
    enrollment.add_argument("--ttl", type=int, default=DEFAULT_PAIRING_TTL)
    enrollment.add_argument("--pairing-id")
    enrollment.add_argument("--code")
    enrollment.add_argument("--peer-id")
    enrollment.add_argument("--peer-public-key")
    enrollment.add_argument(
        "--request",
        type=Path,
        help="JSON request path, or - to read standard input",
    )
    enrollment.add_argument("--confirm", action="store_true")
    enrollment.add_argument("--json", action="store_true")
    relay_test = subparsers.add_parser(
        "relay-test",
        help="send one snapshot through the isolated outbound TLS connector",
    )
    relay_test.add_argument("--config", type=Path, required=True)
    relay_test.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args(arguments)

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
        asyncio.run(run_service(paths, state_path, args.api_socket))
        return 0

    if args.command == "api":
        params = None
        if args.method == "instance.get":
            if not args.instance_id:
                parser.error("api instance.get requires --instance-id")
            params = {"instance_id": args.instance_id}
        try:
            response = asyncio.run(
                api_request(
                    args.api_socket or default_api_socket_path(),
                    args.method,
                    params,
                )
            )
        except (OSError, asyncio.TimeoutError, ValueError) as exc:
            print("ERROR: local agent API unavailable: {}".format(exc), file=sys.stderr)
            return 1
        print(json.dumps(response, indent=2, sort_keys=True))
        return 0 if response.get("ok") else 1

    if args.command == "enrollment":
        store = EnrollmentStore()
        try:
            if args.action == "identity":
                result = store.identity()
            elif args.action == "pair-create":
                result = store.create_pairing(args.ttl)
            elif args.action == "pair-consume":
                required = (
                    args.pairing_id,
                    args.code,
                    args.peer_id,
                    args.peer_public_key,
                )
                if not all(required):
                    parser.error(
                        "enrollment pair-consume requires --pairing-id, "
                        "--code, --peer-id and --peer-public-key"
                    )
                result = store.consume_pairing(
                    args.pairing_id,
                    args.code,
                    args.peer_id,
                    args.peer_public_key,
                )
            elif args.action == "peers":
                result = {"schema_version": 1, "peers": store.list_peers()}
            elif args.action == "revoke":
                if not args.peer_id:
                    parser.error("enrollment revoke requires --peer-id")
                result = store.revoke_peer(args.peer_id)
            elif args.action in ("challenge-sign", "relay-complete"):
                if args.request is None:
                    parser.error(
                        "enrollment {} requires --request PATH or --request -".format(
                            args.action
                        )
                    )
                if str(args.request) == "-":
                    request_document = json.load(sys.stdin)
                else:
                    with args.request.open("r", encoding="utf-8") as request_file:
                        request_document = json.load(request_file)
                if args.action == "challenge-sign":
                    result = store.sign_relay_challenge(request_document)
                else:
                    result = store.complete_relay_enrollment(request_document)
            else:
                result = store.rotate_identity(confirmed=args.confirm)
        except (EnrollmentError, OSError, json.JSONDecodeError) as exc:
            print("ERROR: enrollment: {}".format(exc), file=sys.stderr)
            return 1

        if args.action == "pair-create" and not args.json:
            print("PrinterHMI Remote one-time pairing")
            print("  Code: {}".format(result["code"]))
            print("  Expires: {}".format(result["expires_at"]))
            print("  Device: {}".format(result["device_id"]))
            print("  Pairing ID: {}".format(result["pairing_id"]))
            print("Share this code only with the intended client.")
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "diagnose":
        state_path = args.state_file or default_state_path()
        report = asyncio.run(
            collect_diagnostics(
                args.api_socket or default_api_socket_path(state_path),
                state_path,
            )
        )
        bundle = None if args.no_bundle else write_support_bundle(report, args.output)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            health = report["local_api"].get("health") or {}
            service = report["service"]
            print("PrinterHMI Remote diagnostics")
            print("  Service: {} / {}".format(
                service.get("active_state") or "unavailable",
                service.get("sub_state") or "unknown",
            ))
            print("  Local API: {}".format(
                "ready" if report["local_api"]["available"] else "unavailable"
            ))
            print("  Printers: {} discovered, {} connected".format(
                health.get("instance_count", len(report["printers"])),
                health.get("connected_count", 0),
            ))
            print("  Sanitized errors: {}".format(
                len(report["recent_sanitized_errors"])
            ))
        if bundle is not None:
            print("Support bundle: {}".format(bundle))
        return 0 if report["local_api"]["available"] else 1

    if args.command == "relay-test":
        try:
            config = RelayConfig.load(args.config)
            with args.snapshot.open("r", encoding="utf-8") as snapshot_file:
                snapshot = json.load(snapshot_file)
            result = asyncio.run(RelayConnector(config).send_with_retries(snapshot))
        except (RelayTransportError, OSError, json.JSONDecodeError) as exc:
            print("ERROR: relay test: {}".format(exc), file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
