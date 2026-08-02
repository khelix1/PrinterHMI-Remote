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
