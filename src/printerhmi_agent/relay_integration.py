import argparse
import asyncio
import json
import os
import socket
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from .api import LocalAgentApi
from .enrollment import EnrollmentStore
from .relay_configuration import CA_NAME, RelayConfigurationManager
from .relay_receiver import RelayReceiver, RelayReceiverConfig
from .relay_transport import RelayConfig, RelayConnector, RelayTransportError
from .relay_worker import RelayWorker
from .service import SnapshotStore


class RelayIntegrationError(RuntimeError):
    pass


def _select_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _write_private_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(document, output, indent=2, sort_keys=True)
        output.write("\n")
    os.chmod(path, 0o600)


def _enroll(manager: RelayConfigurationManager, store: EnrollmentStore, root: Path) -> str:
    offer = store.create_pairing(300)
    offer_path = root / "pairing-offer.json"
    request_path = root / "enrollment-request.json"
    receipt_path = root / "enrollment-receipt.json"
    _write_private_json(offer_path, offer)
    manager.create_enrollment_request(offer_path, request_path)
    request = json.loads(request_path.read_text(encoding="utf-8"))
    _write_private_json(receipt_path, store.complete_relay_enrollment(request))
    manager.add_receipt(receipt_path)
    return offer["device_id"]


def _assert_disposable_workspace(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    production = (Path.home() / ".local/state/printerhmi-remote").resolve()
    if resolved == production or production in resolved.parents:
        raise RelayIntegrationError("refusing production state directory")
    if resolved.exists() and any(resolved.iterdir()):
        raise RelayIntegrationError("integration workspace must be empty")
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(resolved, 0o700)
    return resolved


def _snapshot(progress: float) -> dict:
    return {
        "instance_id": "integration-printer",
        "socket_path": "/private/moonraker.sock",
        "hostname": "private-printer",
        "connected": True,
        "captured_at": "2026-01-01T00:00:00Z",
        "status": {
            "print": {
                "state": "printing",
                "progress": progress,
                "filename": "private-job.gcode",
            },
            "temperatures": {
                "extruder": {"temperature": 205.0, "target": 210.0},
                "heater_bed": {"temperature": 59.5, "target": 60.0},
            },
        },
    }


async def run_relay_integration(workspace: Path, verify_stale: bool = True) -> dict:
    root = _assert_disposable_workspace(workspace)
    relay_dir = root / "relay"
    port = _select_loopback_port()
    manager = RelayConfigurationManager(relay_dir)
    manager.initialize("integration-relay", listen_port=port)

    primary_store = EnrollmentStore(root / "primary-enrollment")
    secondary_store = EnrollmentStore(root / "secondary-enrollment")
    primary_id = _enroll(manager, primary_store, root / "primary-transcript")
    secondary_id = _enroll(manager, secondary_store, root / "secondary-transcript")
    manager.set_enabled(True, confirmed=True)

    receiver_config = RelayReceiverConfig.load(manager.config_path)
    local_store = SnapshotStore(root / "local-state.json", minimum_write_interval=0)
    await local_store.update("integration-printer", _snapshot(0.25))
    local_api = LocalAgentApi(
        root / "agent.sock",
        local_store,
        [{"instance_id": "integration-printer", "reachable": True}],
    )
    await local_api.start()

    connector_config = RelayConfig(
        enabled=True,
        relay_id="integration-relay",
        host="127.0.0.1",
        port=port,
        server_name="localhost",
        ca_file=relay_dir / CA_NAME,
        connect_timeout=1.0,
    )
    worker = RelayWorker(
        connector_config,
        local_api.socket_path,
        root / "worker-state.json",
        RelayConnector(connector_config, primary_store),
    )
    receiver = None
    failure_observed = False
    reconnect_observed = False
    stale_observed = False
    try:
        receiver = RelayReceiver(receiver_config)
        await receiver.start()
        await worker.run_once()
        await local_store.update("integration-printer", _snapshot(0.75))
        await worker.run_once()
        stored = await receiver.registry.snapshot(primary_id)
        if stored is None:
            raise RelayIntegrationError("receiver did not retain primary snapshot")
        serialized = json.dumps(stored, sort_keys=True)
        for private_value in (
            "socket_path",
            "private-job.gcode",
            "private-printer",
            "/private/moonraker.sock",
        ):
            if private_value in serialized:
                raise RelayIntegrationError("private data reached relay state")
        if stored["snapshot"]["instances"]["integration-printer"]["status"]["print"]["progress"] != 0.75:
            raise RelayIntegrationError("latest snapshot did not replace prior state")
        if await receiver.registry.snapshot(secondary_id) is not None:
            raise RelayIntegrationError("device snapshots were not isolated")
        try:
            await receiver.api.dispatch({"protocol_version": 1, "method": "control"})
        except Exception:
            pass
        else:
            raise RelayIntegrationError("receiver exposed an unexpected control method")

        await receiver.close()
        try:
            await worker.run_once()
        except RelayTransportError:
            failure_observed = True
        if not failure_observed or worker.failure_count < 1:
            raise RelayIntegrationError("worker did not report receiver outage")

        receiver = RelayReceiver(receiver_config)
        await receiver.start()
        await worker.run_once()
        reconnect_observed = worker.success_count >= 3
        if not reconnect_observed:
            raise RelayIntegrationError("worker did not reconnect")

        if verify_stale:
            await asyncio.sleep(receiver_config.stale_after + 0.1)
            registry = await receiver.registry.document()
            stale_observed = not registry["devices"][primary_id]["online"]
            if not stale_observed:
                raise RelayIntegrationError("receiver did not mark snapshot stale")
    finally:
        if receiver is not None:
            await receiver.close()
        await local_api.close()
        await local_store.flush()

    worker_state = json.loads((root / "worker-state.json").read_text(encoding="utf-8"))
    receiver_state = json.loads(receiver_config.state_file.read_text(encoding="utf-8"))
    if "snapshot" in worker_state or "instances" in worker_state:
        raise RelayIntegrationError("worker health state retained telemetry")
    if len(receiver_state.get("records", {})) != 1:
        raise RelayIntegrationError("receiver retained unexpected device history")

    return {
        "schema_version": 1,
        "passed": True,
        "loopback_only": receiver_config.listen_host == "127.0.0.1",
        "enrolled_device_count": len(receiver_config.devices),
        "published_device_count": len(receiver_state["records"]),
        "worker_success_count": worker.success_count,
        "worker_failure_count": worker.failure_count,
        "outage_observed": failure_observed,
        "reconnect_observed": reconnect_observed,
        "stale_observed": stale_observed if verify_stale else None,
        "privacy_filter_verified": True,
        "control_surface_absent": True,
        "workspace": str(root),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="printerhmi-agent relay-integration")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--skip-stale-wait", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    temporary = None
    try:
        if args.workspace is None:
            temporary = tempfile.TemporaryDirectory(
                prefix="printerhmi-relay-integration-"
            )
            workspace = Path(temporary.name)
        else:
            workspace = args.workspace
        result = asyncio.run(
            run_relay_integration(workspace, verify_stale=not args.skip_stale_wait)
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("PASS: authenticated loopback relay integration")
            print("PASS: outage, reconnect, privacy and isolation checks")
            if result["stale_observed"] is not None:
                print("PASS: stale snapshot detection")
            print("Workspace: {}".format(result["workspace"]))
        return 0
    except (OSError, ValueError, RelayIntegrationError, RelayTransportError) as exc:
        print("ERROR: relay integration: {}".format(exc), file=sys.stderr)
        return 1
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
