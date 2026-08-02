# Changelog

## [Unreleased]

### Added

- Established the standalone PrinterHMI Remote repository.
- Added read-only discovery of local Moonraker Unix sockets.
- Added stable per-instance identities and normalized catalog output.
- Added a minimal JSON-RPC Unix-socket client, protocol schema and tests.
- Documented architecture, security boundaries and the staged product roadmap.
- Enriched discovered instances with the hostname reported by `printer.info`.
- Added reusable deployment exclusions for generated development artifacts.
- Added dynamic, read-only Moonraker object subscriptions over the local Unix socket.
- Added normalized telemetry snapshots, reconnecting multi-instance service operation,
  atomic state-file publication and a hardened systemd user-service template.
- Coalesced high-frequency telemetry writes and retained humidity and temperature-fan
  fields from dynamically discovered sensor objects.
- Replaced the development user unit with a boot-persistent, least-privilege system
  service that runs as the Klipper account and requires only Unix-socket access.
