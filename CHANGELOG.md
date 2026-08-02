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
- Added a versioned, same-user, read-only local Unix-socket API for agent health,
  catalog discovery, complete snapshots and individual instance state.
- Made service upgrades restart deterministically and verify the new API with an
  end-to-end request instead of trusting a possibly stale socket pathname.
- Added one-command operator diagnostics and mode-0600 support bundles with strict
  exclusion of raw telemetry, identities, network endpoints and print filenames.
- Added idempotent Moonraker Update Manager registration for pristine `main` checkouts,
  canonical-origin validation and least-privilege service restart authorization.
- Made Update Manager installation wait for Moonraker to validate the exact clean
  `main` revision over its local Unix socket before reporting success.
- Added the offline secure-enrollment foundation with Ed25519 device identity,
  expiring attempt-limited pairing, peer revocation, key rotation and audit events.
- Added a formal Phase 2 threat model and versioned pairing-offer schema while
  retaining the no-network service sandbox.
