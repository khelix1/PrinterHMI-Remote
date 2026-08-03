# PrinterHMI Remote

The normal monitor remains local-only with `PrivateNetwork=true`. An operator
may separately install the outbound TLS relay worker with an enabled relay
configuration and the explicit `--enable-network` acknowledgement. The worker
reads normalized state only through the private local API; it does not open a
listener or connect to Moonraker. See
[`docs/RELAY_WORKER.md`](docs/RELAY_WORKER.md).

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

Remote access remains disabled in the production service. The repository now
includes an isolated TLS connector and loopback relay simulator so certificate,
session-authentication, privacy and resource limits can be tested before that
boundary is opened.

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

Create and inspect the host's protected Ed25519 device identity, then issue an
expiring one-time pairing offer:

```bash
.venv/bin/printerhmi-agent enrollment identity
.venv/bin/printerhmi-agent enrollment pair-create
.venv/bin/printerhmi-agent enrollment peers
```

Phase 2 also defines signed, replay-resistant relay enrollment as an offline
JSON transcript. It does not enable cloud connectivity or expose Moonraker:

```bash
.venv/bin/printerhmi-agent enrollment challenge-sign --request challenge.json
.venv/bin/printerhmi-agent enrollment relay-complete --request enrollment-request.json
```

See the [relay enrollment protocol](docs/RELAY_ENROLLMENT_PROTOCOL.md) and
[secure enrollment threat model](docs/THREAT_MODEL.md).

The next transport layer is also testable without modifying the production
service. Its example configuration is disabled by default, TLS validates an
explicit CA and hostname, the agent signs every new session challenge, and
privacy filtering removes local paths and print identity before transmission.
See the [TLS transport foundation](docs/TLS_TRANSPORT_FOUNDATION.md) and
[outbound transport threat model](docs/TRANSPORT_THREAT_MODEL.md).

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
