import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from .api import api_request, default_api_socket_path
from .enrollment import EnrollmentStore
from .relay_transport import RelayConfig, RelayConnector, RelayTransportError


SCHEMA_VERSION = 1


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def default_worker_state_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local/state"
    return base / "printerhmi-remote/relay-worker.json"


class RelayWorker:
    def __init__(
        self,
        config: RelayConfig,
        api_socket: Path,
        state_path: Path,
        connector: Optional[RelayConnector] = None,
    ):
        if not config.enabled:
            raise RelayTransportError("relay transport is disabled")
        self.config = config
        self.api_socket = api_socket
        self.state_path = state_path
        self.connector = connector or RelayConnector(config, EnrollmentStore())
        self.success_count = 0
        self.failure_count = 0

    async def fetch_snapshot(self) -> dict:
        response = await api_request(self.api_socket, "snapshot")
        if not response.get("ok") or not isinstance(response.get("result"), dict):
            raise RelayTransportError("local agent snapshot is unavailable")
        return response["result"]

    def write_state(self, status: str, result: Optional[dict] = None) -> None:
        document = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": _timestamp(),
            "status": status,
            "relay_id": self.config.relay_id,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "last_sequence": result.get("sequence") if result else None,
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_path.parent, 0o700)
        temporary = self.state_path.with_name(self.state_path.name + ".tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(document, output, separators=(",", ":"), sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.state_path)
            os.chmod(self.state_path, 0o600)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    async def run_once(self) -> dict:
        try:
            snapshot = await self.fetch_snapshot()
            result = await self.connector.send_with_retries(snapshot, attempts=3)
        except (OSError, ValueError, RelayTransportError, asyncio.TimeoutError):
            self.failure_count += 1
            self.write_state("unavailable")
            raise
        self.success_count += 1
        self.write_state("connected", result)
        return result

    async def run(self, interval: float = 2.0) -> None:
        if interval < 0.5 or interval > 300:
            raise ValueError("interval must be between 0.5 and 300 seconds")
        while True:
            try:
                await self.run_once()
            except (OSError, ValueError, RelayTransportError, asyncio.TimeoutError):
                pass
            await asyncio.sleep(interval)


def main(argv: Sequence[str] = None) -> int:
    parser = argparse.ArgumentParser(prog="printerhmi-relay-worker")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--api-socket", type=Path, default=None)
    parser.add_argument("--state-file", type=Path, default=None)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--validate-config", action="store_true")
    args = parser.parse_args(argv)

    try:
        config = RelayConfig.load(args.config)
        if not config.enabled:
            raise RelayTransportError("relay transport is disabled")
        if args.validate_config:
            print("PASS: enabled relay configuration is valid")
            return 0
        worker = RelayWorker(
            config,
            args.api_socket or default_api_socket_path(),
            args.state_file or default_worker_state_path(),
        )
        if args.once:
            result = asyncio.run(worker.run_once())
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            asyncio.run(worker.run(args.interval))
        return 0
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, RelayTransportError, asyncio.TimeoutError) as exc:
        print("ERROR: relay worker unavailable: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
