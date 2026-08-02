# PrinterHMI Remote

PrinterHMI Remote is the local-first foundation for secure remote monitoring of
Klipper printers through Moonraker. It is designed to work with any compatible
Klipper installation; PrinterHMI hardware is optional.

## Current milestone

The repository currently provides a **read-only local agent foundation**:

- automatic discovery of local Moonraker Unix sockets;
- support for common single- and multi-instance data paths;
- stable instance identities that do not depend on DHCP addresses;
- a minimal Moonraker JSON-RPC Unix-socket client;
- normalized discovery output for future P4, relay and web consumers;
- no inbound LAN listener, cloud connection or printer-control surface.

Remote access is intentionally not implemented until the pairing protocol and
threat model are reviewed.

## Quick start

```bash
./install.sh
.venv/bin/printerhmi-agent discover
.venv/bin/printerhmi-agent discover --json
```

For development deployment to a Klipper host, apply the tracked exclusions:

```bash
rsync -av --filter="merge .rsync-filter" ./ user@printer:~/PrinterHMI-Remote/
```

Stream normalized live telemetry from one local instance:

```bash
.venv/bin/printerhmi-agent monitor \
  --socket "$HOME/printer_data/comms/moonraker.sock"
```

Run every discovered instance as a boot-persistent system service:

```bash
./install-service.sh
sudo systemctl status printerhmi-remote.service
```

The installer runs the service with the invoking Klipper account rather than as
root. Uninstalling the service retains its last normalized state document:

```bash
./uninstall-service.sh
```

The service opens no TCP listener. Its atomically replaced read-only snapshot is stored
at `~/.local/state/printerhmi-remote/status.json` by default. Rapid Moonraker events
are coalesced so persistent storage is updated at most once per second.

The service also exposes a versioned, read-only API at
`~/.local/state/printerhmi-remote/agent.sock`. The socket is mode `0600`, verifies
same-user peer credentials and accepts no printer-control methods:

```bash
.venv/bin/printerhmi-agent api health
.venv/bin/printerhmi-agent api catalog
.venv/bin/printerhmi-agent api snapshot
```

Health reports catalog membership separately from telemetry readiness, so a
newly started service does not temporarily claim that discovered printers vanished.

Create a private, sanitized support bundle with one command:

```bash
.venv/bin/printerhmi-agent diagnose
```

The bundle excludes raw telemetry and identifying printer, network and job data.
See [Diagnostics](docs/DIAGNOSTICS.md) for its exact disclosure boundary.

Register a pristine Git installation with Moonraker Update Manager:

```bash
./install-update-manager.sh
```

See [Update Manager](docs/UPDATE_MANAGER.md) for multi-instance selection,
the development-channel policy and removal instructions.

Explicit socket paths may be supplied when an installation uses a custom layout:

```bash
PRINTERHMI_MOONRAKER_SOCKETS=/path/one.sock:/path/two.sock \
  .venv/bin/printerhmi-agent discover --json
```

## Product principles

- Local printing and PrinterHMI operation never depend on the internet.
- Moonraker is never exposed directly to the public internet.
- Monitoring ships before remote control.
- LAN and cloud interfaces default to deny.
- Every printer, host and account has a stable identity.
- Multi-instance Klipper installations are first-class.
- Hosted and self-hosted relay implementations use the same documented protocol.

See [Architecture](docs/ARCHITECTURE.md), [Security](SECURITY.md), and the
[Roadmap](docs/ROADMAP.md).

## License

Apache License 2.0.
